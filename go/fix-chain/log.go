package fixchain

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/certificate-transparency/go/x509"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Stringify a chain in PEM format (FIXME: move all dumpers/printers
// to one file?)
func DumpChainPEM(chain []*x509.Certificate) string {
	var p string
	for _, cert := range chain {
		p += DumpPEM(cert.Raw)
	}
	return p
}

// Stringify some bytes to PEM format
func DumpPEM(cert []byte) string {
	b := pem.Block{Type: "CERTIFICATE", Bytes: cert}
	return string(pem.EncodeToMemory(&b))
}

type toLog struct {
	chain   []*x509.Certificate
	retries uint16
}

// A certificate transparency log
type Log struct {
	url    string
	roots  *x509.CertPool
	posts  chan *toLog
	active uint32
	// these counters are not atomically updated, so may not be quite right
	posted        int
	reposted      int
	lateReposted  int
	chainReposted int

	// Note that this counts the number of active requests, not
	// active servers, because we can't close it to signal the
	// end, because of retries.
	wg sync.WaitGroup
	
	postCache      map[[HashSize]byte]bool
	postChainCache map[[HashSize]byte]bool
	pcMutex        sync.Mutex
	errors         chan *FixError
}

func (s *Log) isPosted(cert *x509.Certificate) bool {
	return s.postCache[Hash(cert)]
}

// The list of root certificates the log accepts
func (s *Log) rootCerts() *x509.CertPool {
	if s.roots == nil {
		s.roots = s.getRoots()
	}
	return s.roots
}

func (s *Log) getRoots() *x509.CertPool {
	rootsJSON, err := http.Get(s.url + "/ct/v1/get-roots")
	if err != nil {
		log.Fatalf("can't get roots from %s: %s", s.url, err)
	}
	defer rootsJSON.Body.Close()
	if rootsJSON.StatusCode != 200 {
		log.Fatalf("can't deal with status other than 200: %d",
			rootsJSON.StatusCode)
	}
	j, err := ioutil.ReadAll(rootsJSON.Body)
	if err != nil {
		log.Fatalf("can't read roots: %s", err)
	}
	type Certificates struct {
		Certificates [][]byte
	}
	var certs Certificates
	err = json.Unmarshal(j, &certs)
	if err != nil {
		log.Fatalf("can't parse json (%s): %s", err, j)
	}
	ret := x509.NewCertPool()
	for i := 0; i < len(certs.Certificates); i++ {
		r, err := x509.ParseCertificate(certs.Certificates[i])
		switch err.(type) {
		case nil, x509.NonFatalErrors:
			// ignore
		default:
			log.Fatalf("can't parse certificate: %s %#v", err,
				certs.Certificates[i])
		}
		ret.AddCert(r)
		log.Printf("Root %d: %s", i, r.Subject.CommonName)
	}
	return ret
}

func (s *Log) postChain(l *toLog) {
	h := Hash(l.chain[0])
	if s.postCache[h] {
		s.lateReposted++
		return
	}
	type Chain struct {
		Chain [][]byte `json:"chain"`
	}
	var m Chain
	for _, c := range l.chain {
		m.Chain = append(m.Chain, c.Raw)
	}
	j, err := json.Marshal(m)
	if err != nil {
		log.Fatalf("Can't marshal: %s", err)
	}
	//log.Printf("post: %s", j)

	resp, err := http.Post(s.url+"/ct/v1/add-chain", "application/json",
		bytes.NewReader(j))
	if err != nil {
		// FIXME: can we figure out what the error was? So far
		// I've only ever seen EOF, but its just text...
		if l.retries == 0 {
			log.Fatalf("Can't post: %s", err)
		}
		log.Printf("Can't post: %s", err)
		l.retries--
		s.postToLog(l)
		return
	}
	defer resp.Body.Close()
	jo, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode == 502 {
		log.Printf("Retry 502: %d", l.retries)
		if l.retries == 0 {
			return
		}
		l.retries--
		s.postToLog(l)
		return
	}
	if resp.StatusCode != 200 {
		//log.Printf("Can't handle response %d: %s\nchain: %s", resp.StatusCode, jo, DumpChainPEM(l.chain))
		s.errors <- &FixError{
			Type:  LogPostFailed,
			Chain: l.chain,
			Error: errors.New(
				fmt.Sprintf("Can't handle response %d: %s",
					resp.StatusCode, jo)),
		}
		return
	}
	if err != nil {
		log.Fatalf("Can't read response: %s", err)
	}
	s.postCache[h] = true
	//log.Printf("Log returned: %s", jo)
}

func (s *Log) postServer() {
	for {
		c := <-s.posts
		atomic.AddUint32(&s.active, 1)
		s.postChain(c)
		atomic.AddUint32(&s.active, ^uint32(0))
		s.wg.Done()
	}
}

func (s *Log) postToLog(l *toLog) {
	s.wg.Add(1)
	s.posts <- l
}

func (s *Log) postOneChain(chain []*x509.Certificate) {
	s.posted++
	h := Hash(chain[0])
	if s.postCache[h] {
		s.reposted++
		return
	}
	// if we assume all chains for the same cert are equally
	// likely to succeed, then we could mark the cert as posted
	// here. However, bugs might cause a log to refuse one chain
	// and accept another, so try each unique chain.
	//s.postCache[h] = true
	h = HashChain(chain)
	s.pcMutex.Lock()
	if s.postChainCache[h] {
		s.pcMutex.Unlock()
		s.chainReposted++
		return
	}
	s.postChainCache[h] = true
	s.pcMutex.Unlock()
	l := &toLog{chain: chain, retries: 5}
	s.postToLog(l)
}

func (s *Log) postChains(chains [][]*x509.Certificate) {
	for _, chain := range chains {
		s.postOneChain(chain)
	}
}

func (s *Log) wait() {
	s.wg.Wait()
}

func newLog(url string, errors chan *FixError) *Log {
	s := &Log{url: url, posts: make(chan *toLog),
		postCache:      make(map[[HashSize]byte]bool),
		postChainCache: make(map[[HashSize]byte]bool), errors: errors}
	for i := 0; i < 100; i++ {
		go s.postServer()
	}
	t := time.NewTicker(time.Second)
	go func() {
		for _ = range t.C {
			log.Printf("posters: %d active, %d posted, "+
				"%d reposted, %d reposted (late), "+
				"%d chains reposted", s.active, s.posted,
				s.reposted, s.lateReposted, s.chainReposted)
		}
	}()

	return s
}

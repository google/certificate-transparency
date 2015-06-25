package fix_chain

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"github.com/google/certificate-transparency/go/x509"
	"log"
	"net/http"
	"sync"
)

func DumpChainPEM(chain []*x509.Certificate) string {
	var p string
	for _, cert := range chain {
		b := pem.Block { Type: "CERTIFICATE", Bytes: cert.Raw }
		p += string(pem.EncodeToMemory(&b))
	}
	return p
}

type toLog struct {
	chain []*x509.Certificate
	retries uint16
}

type Log struct {
	url string
	roots *x509.CertPool
	posts chan *toLog
	active uint16
	wg sync.WaitGroup  // Note that this counts the number of active requests, not active servers, because we can't close it to signal the end, because of retries.
	postCache map[[HashSize]byte]bool
	postChainCache map[[HashSize]byte]bool
	pcMutex sync.Mutex
}

func NewLog(url string) *Log {
	s := &Log{url: url, posts: make(chan *toLog), postCache: make(map[[HashSize]byte]bool), postChainCache: make(map[[HashSize]byte]bool)}
	for i := 0 ; i < 100 ; i++ {
		go s.postServer()
	}
	return s
}

func (s *Log) Roots() *x509.CertPool {
	if s.roots == nil {
		s.roots = s.getRoots()
	}
	return s.roots
}

func (s *Log) getRoots() *x509.CertPool {
	rootsjson, err := http.Get(s.url + "/ct/v1/get-roots")
	if err != nil {
		log.Fatalf("can't get roots from %s: %s", s.url, err)
	}
	defer rootsjson.Body.Close()
	if rootsjson.StatusCode != 200 {
		log.Fatalf("can't deal with status other than 200: %d", rootsjson.StatusCode)
	}
	j, err := ioutil.ReadAll(rootsjson.Body)
	//log.Printf("roots: %s", j)
	type Certificates struct {
		Certificates [][]byte
	}
	var certs Certificates
	err = json.Unmarshal(j, &certs)
	if err != nil {
		log.Fatalf("can't parse json (%s): %s", err, j)
	}
	//log.Printf("certs: %#v", certs)
	ret := x509.NewCertPool()
	for i := 0 ; i < len(certs.Certificates) ; i++ {
		r, err := x509.ParseCertificate(certs.Certificates[i])
		switch err.(type) {
		case nil:
		case x509.NonFatalErrors:
		default:
			log.Fatalf("can't parse certificate: %s %#v", err, certs.Certificates[i])
		}
		ret.AddCert(r)
		log.Printf("Root %d: %s", i, r.Subject.CommonName)
	}
	return ret
}

func (s *Log) postChain(l *toLog) {
	h := Hash(l.chain[0])
	if s.postCache[h] {
		log.Printf("Already posted (late)")
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
	
	resp, err := http.Post(s.url + "/ct/v1/add-chain", "application/json", bytes.NewReader(j))
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
		log.Printf("Can't handle response %d: %s\nchain: %s", resp.StatusCode, jo, DumpChainPEM(l.chain))
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
		s.active++
		log.Printf("%d active posts", s.active)
		s.postChain(c)
		s.active--
		log.Printf("%d active posts", s.active)
		s.wg.Done()
	}
}

func (s *Log) postToLog(l *toLog) {
	s.wg.Add(1)
	s.posts <- l
}

func (s *Log) PostChain(chain []*x509.Certificate) {
	h := Hash(chain[0])
	if s.postCache[h] {
		log.Printf("Already posted")
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
		log.Printf("Chain already posted")
		return
	}
	s.postChainCache[h] = true
	s.pcMutex.Unlock()
	l := &toLog{ chain: chain, retries: 5 }
	s.postToLog(l)
}

func (s *Log) PostChains(chains [][]*x509.Certificate) {
	for i, chain := range chains {
		log.Printf("post %d", i)
		s.PostChain(chain)
	}
}

func (s *Log) Wait() {
	s.wg.Wait()
}

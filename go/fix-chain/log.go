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

func DumpChainPEM(chain []*x509.Certificate) (string) {
	var p string
	for _, cert := range chain {
		b := pem.Block { Type: "CERTIFICATE", Bytes: cert.Raw }
		p += string(pem.EncodeToMemory(&b))
	}
	return p
}

type Log struct {
	url string
	roots *x509.CertPool
	poster chan []*x509.Certificate
	active uint16
	wg sync.WaitGroup
}

func NewLog(url string) (*Log) {
	s := &Log{ url: url, poster: make(chan []*x509.Certificate) }
	for i := 0 ; i < 100 ; i++ {
		go s.postServer()
	}
	return s
}

func (s *Log) Roots() (*x509.CertPool) {
	if s.roots == nil {
		s.roots = s.getRoots()
	}
	return s.roots
}

func (s *Log) getRoots() (*x509.CertPool) {
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

func (s *Log) postChain(chain []*x509.Certificate) {
	type Chain struct {
		Chain [][]byte `json:"chain"`
	}
	var m Chain
	for _, c := range chain {
		m.Chain = append(m.Chain, c.Raw)
	}
	j, err := json.Marshal(m)
	if err != nil {
		log.Fatalf("Can't marshal: %s", err)
	}
	//log.Printf("post: %s", j)
	resp, err := http.Post(s.url + "/ct/v1/add-chain", "application/json", bytes.NewReader(j))
	if err != nil {
		log.Fatalf("Can't post: %s", err)
	}
	defer resp.Body.Close()
	jo, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		// FIXME: retry 500s.
		log.Printf("Can't handle response %d: %s\nchain: %s", resp.StatusCode, jo, DumpChainPEM(chain))
		return
	}
	if err != nil {
		log.Fatalf("Can't read response: %s", err)
	}
	//log.Printf("Log returned: %s", jo)
}

func (s *Log) postServer() {
	for {
		c := <-s.poster
		s.active++
		log.Printf("%d active posters", s.active)
		s.postChain(c)
		s.active--
		log.Printf("%d active posters", s.active)
		s.wg.Done()
	}
}

func (s *Log) PostChain(chain []*x509.Certificate) {
	s.wg.Add(1)
	s.poster <- chain
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

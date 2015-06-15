package fix_chain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/certificate-transparency/go/x509"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
)

func Hash(s *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(s.Raw)
}

func HexHash(s *x509.Certificate) string {
	h := Hash(s)
	return hex.EncodeToString(h[:])
}

func dumpChain(name string, certs []*x509.Certificate) {
	for i, cert := range certs {
		log.Printf("%s %d: %s %s", name, i, HexHash(cert), cert.Subject.CommonName)
	}
}

func dumpChains(name string, chains [][]*x509.Certificate) {
	for i, chain := range chains {
		n := fmt.Sprintf("%s %d", name, i)
		dumpChain(n, chain)
	}
}

var knownBadCerts = map[string]bool {
	"http://gca.nat.gov.tw/repository/Certs/IssuedToThisCA.p7b":  true,
	"http://grca.nat.gov.tw/repository/Certs/IssuedToThisCA.p7b": true,
	"http://crt.trust-provider.com/AddTrustExternalCARoot.p7c":   true,
	"http://crt.usertrust.com/AddTrustExternalCARoot.p7c":        true,
}

func knownBad(name string) bool {
	return knownBadCerts[name]
}

var urlCache = make(map[string][]byte)

func getURL(url string) ([]byte, error) {
	r, ok := urlCache[url]
	if ok {
		log.Printf("HIT! %s", url)
		return r, nil
	}
	c, err := http.Get(url)
	// FIXME: cache errors
	if err != nil {
		return nil, err
	}
	defer c.Body.Close()
	if c.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("can't deal with status %d", c.StatusCode))
	}
	r, err = ioutil.ReadAll(c.Body)
	if err != nil {
		return nil, err
	}
	urlCache[url] = r
	return r, nil
}

type DedupedChain struct {
	certs []*x509.Certificate
}

func (d *DedupedChain) AddCert(cert *x509.Certificate) {
	// Check that the certificate isn't being added twice.
	for _, c := range d.certs {
		if c.Equal(cert) {
			return
		}
	}
	d.certs = append(d.certs, cert)
}

func (d *DedupedChain) Dump(name string) {
	dumpChain(name, d.certs)
}

type Fix struct {
	cert *x509.Certificate
	chain *DedupedChain
	opts *x509.VerifyOptions
}

func fixChain(fix *Fix, l *Log) {
	d2 := *fix.chain
	d2.AddCert(fix.cert)
	for _, c := range d2.certs {
		urls := c.IssuingCertificateURL
		for i, url := range urls {
			log.Printf("fetch issuer %d from %s", i, url)
			body, err := getURL(url)
			if err != nil {
				log.Printf("can't get URL body from %s: %s", url, err)
				continue
			}
			//log.Print(body)
			icert, err := x509.ParseCertificate(body)
			if err != nil {
				s, _ := pem.Decode(body)
				if s != nil {
					icert, err = x509.ParseCertificate(s.Bytes)
				}
			}
			if err != nil {
				if knownBad(url) {
					log.Printf("(ignored) failed to parse certificate: %s", err)
					continue
				} else {
					log.Fatalf("failed to parse certificate: %s", err)
				}
			}
			//log.Printf("%+v", icert)
			fix.opts.Intermediates.AddCert(icert)
			chain, err := fix.cert.Verify(*fix.opts)
			if err == nil {
				dumpChains("fixed", chain)
				l.PostChains(chain)
				return
			}
		}
	}
	log.Printf("failed to fix certificate for %s", fix.cert.Subject.CommonName)
}

type Fixer struct {
	fix chan *Fix
	active int
	wg sync.WaitGroup
	log *Log
}

func (f *Fixer) fixChain(cert *x509.Certificate, d *DedupedChain, intermediates *x509.CertPool, l *Log) {
	opts := x509.VerifyOptions{ Intermediates: intermediates, Roots: l.Roots(), DisableTimeChecks: true, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }
	chain, err := cert.Verify(opts)
	if err == nil {
		dumpChains("verified", chain)
		l.PostChains(chain)
		return
	}
	log.Printf("failed to verify certificate for %s: %s", cert.Subject.CommonName, err)
	f.deferFixChain(cert, d, &opts)
}

func (f *Fixer) FixAll(d *DedupedChain) {
	intermediates := x509.NewCertPool()
	for _, c := range d.certs {
		intermediates.AddCert(c)
	}
	for _, c := range d.certs {
		f.fixChain(c, d, intermediates, f.log)
	}
}

func (f *Fixer) deferFixChain(cert *x509.Certificate, chain *DedupedChain, opts *x509.VerifyOptions) {
	f.fix <- &Fix{ cert: cert, chain: chain, opts: opts }
}

func (f *Fixer) fixServer() {
	defer f.wg.Done()

	for fix := range f.fix {
		f.active++
		log.Printf("%d active fixers", f.active)
		fixChain(fix, f.log)
		f.active--
		log.Printf("%d active fixers", f.active)
	}
}

func (f *Fixer) Wait() {
	close(f.fix)
	
	// Must wait for fixers first, in case they log something.
	f.wg.Wait()
	f.log.Wait()
}

func NewFixer(logurl string) *Fixer {
	f := &Fixer{fix: make(chan *Fix), log: NewLog(logurl)}
	for i := 0 ; i < 100 ; i++ {
		f.wg.Add(1)
		go f.fixServer()
	}
	return f
}

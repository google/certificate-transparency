package fixchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/google/certificate-transparency/go/x509"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// The number of bytes Hash() returns
const HashSize = sha256.Size

// Hash the raw bytes of the certificate
func Hash(s *x509.Certificate) [HashSize]byte {
	return sha256.Sum256(s.Raw)
}

// Hex representation of Hash(s)
func HexHash(s *x509.Certificate) string {
	h := Hash(s)
	return hex.EncodeToString(h[:])
}

// Hash a chain of certificates (in fact, the hash of the
// concatenation of the certificate hashes)
func HashChain(ch []*x509.Certificate) (r [HashSize]byte) {
	h := sha256.New()
	for _, c := range ch {
		// FIXME: surely there's an easier way?
		h2 := make([]byte, HashSize)
		h3 := Hash(c)
		copy(h2, h3[:])
		h.Write(h2)
	}
	h2 := h.Sum([]byte{})
	copy(r[:], h2)
	return
}

// An unordered bag of certs
// FIXME: does Go have sets?
type Bag struct {
	certs []*x509.Certificate
}

// Implement sort.Interface for Bag
func (b Bag) Len() int { return len(b.certs) }
func (b Bag) Less(i, j int) bool {
	ci := b.certs[i].Raw
	cj := b.certs[j].Raw
	if len(ci) != len(cj) {
		return len(ci) < len(cj)
	}
	for n, _ := range ci {
		if ci[n] < cj[n] {
			return true
		}
		if ci[n] > cj[n] {
			return false
		}
	}
	return false
}
func (b Bag) Swap(i, j int) {
	t := b.certs[i]
	b.certs[i] = b.certs[j]
	b.certs[j] = t
}

// The hash of the bag (two bags with the same certificates have the same hash)
func HashBag(bag []*x509.Certificate) [HashSize]byte {
	b := Bag{certs: bag}
	sort.Sort(b)
	return HashChain(b.certs)
}

func dumpChain(name string, certs []*x509.Certificate) {
	for i, cert := range certs {
		log.Printf("%s %d: %s %s", name, i, HexHash(cert),
			cert.Subject.CommonName)
	}
}

func dumpChains(name string, chains [][]*x509.Certificate) {
	for i, chain := range chains {
		n := fmt.Sprintf("%s %d", name, i)
		dumpChain(n, chain)
	}
}

// a chain of certificates with any dupes dropped
type DedupedChain struct {
	certs []*x509.Certificate
}

// add a new certificate to the end of the chain if the cert is not already present (anywhere)
func (d *DedupedChain) AddCert(cert *x509.Certificate) {
	// Check that the certificate isn't being added twice.
	for _, c := range d.certs {
		if c.Equal(cert) {
			return
		}
	}
	d.certs = append(d.certs, cert)
}

// Dump the contents of d to the log.
func (d *DedupedChain) Dump(name string) {
	dumpChain(name, d.certs)
}

type fix struct {
	cert  *x509.Certificate
	chain *DedupedChain
	opts  *x509.VerifyOptions
	fixer *Fixer
}

// Returns a partially filled FixError on error
func augmentIntermediates(pool *x509.CertPool, url string,
	u *URLCache) *FixError {
	r := urlReplacement(url)
	if r != nil {
		log.Printf("Replaced %s: %+v", url, r)
		for _, c := range r {
			pool.AddCert(c)
		}
		return nil
	}
	body, err := u.getURL(url)
	if err != nil {
		//log.Printf("can't get URL body from %s: %s", url, err)
		return &FixError{Type: CannotFetchURL, URL: url, Error: err}
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
		//log.Fatalf("failed to parse certificate from %s: %s", url, err)
		return &FixError{Type: ParseFailure, URL: url, Bad: body,
			Error: err}
	}
	pool.AddCert(icert)
	return nil
}

func fixChain(fix *fix) {
	d2 := *fix.chain
	d2.AddCert(fix.cert)
	for _, c := range d2.certs {
		urls := c.IssuingCertificateURL
		for _, url := range urls {
			//log.Printf("fetch issuer %d from %s", i, url)
			ferr := augmentIntermediates(fix.opts.Intermediates,
				url, fix.fixer.cache)
			if ferr != nil {
				ferr.Cert = fix.cert
				ferr.Chain = fix.chain.certs
				fix.fixer.errors <- ferr
			}
			chain, err := fix.cert.Verify(*fix.opts)
			if err == nil {
				//dumpChains("fixed", chain)
				fix.fixer.fixed++
				fix.fixer.log.postChains(chain)
				return
			}
		}
	}
	//log.Printf("failed to fix certificate for %s", fix.cert.Subject.CommonName)
	fix.fixer.notfixed++
	fix.fixer.errors <- &FixError{Type: FixFailed, Cert: fix.cert,
		Chain: fix.chain.certs}
}

type Fixer struct {
	fix    chan *fix
	active uint32
	// Counters may not be entirely accurate due to non-atomicity
	skipped          uint
	reconstructed    uint
	notreconstructed uint
	fixed            uint
	notfixed         uint
	alreadydone      uint

	wg     sync.WaitGroup
	log    *Log
	errors chan *FixError
	cache  *URLCache
	done   map[[HashSize]byte]bool
}

func (f *Fixer) fixChain(cert *x509.Certificate, d *DedupedChain, intermediates *x509.CertPool, l *Log) {
	if l.isPosted(cert) {
		//log.Printf("Skip already posted cert")
		f.skipped++
		return
	}
	opts := x509.VerifyOptions{Intermediates: intermediates,
		Roots: l.rootCerts(), DisableTimeChecks: true,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	chain, err := cert.Verify(opts)
	if err == nil {
		//dumpChains("verified", chain)
		f.reconstructed++
		l.postChains(chain)
		return
	}
	//log.Printf("failed to verify certificate for %s: %s", cert.Subject.CommonName, err)
	f.errors <- &FixError{Type: VerifyFailed, Cert: cert, Chain: d.certs,
		Error: err}
	f.notreconstructed++
	f.deferFixChain(cert, d, &opts)
}

// Given a deduped chain, try to fix and submit each cert in the chain, using the rest of the chain to certify it
func (f *Fixer) FixAll(d *DedupedChain) {
	h := HashBag(d.certs)
	if f.done[h] {
		f.alreadydone++
		return
	}
	f.done[h] = true
	intermediates := x509.NewCertPool()
	for _, c := range d.certs {
		intermediates.AddCert(c)
	}
	for _, c := range d.certs {
		f.fixChain(c, d, intermediates, f.log)
	}
}

func (f *Fixer) deferFixChain(cert *x509.Certificate, chain *DedupedChain,
	opts *x509.VerifyOptions) {
	f.fix <- &fix{cert: cert, chain: chain, opts: opts, fixer: f}
}

func (f *Fixer) fixServer() {
	defer f.wg.Done()

	for fix := range f.fix {
		atomic.AddUint32(&f.active, 1)
		fixChain(fix)
		atomic.AddUint32(&f.active, ^uint32(0))
	}
}

// Wait for all the fixers (and loggers) to finish
func (f *Fixer) Wait() {
	close(f.fix)

	// Must wait for fixers first, in case they log something.
	f.wg.Wait()
	f.log.wait()
}

// Create a new fixer for a particular log
func NewFixer(logurl string, errors chan *FixError) *Fixer {
	f := &Fixer{fix: make(chan *fix), log: newLog(logurl, errors),
		errors: errors, cache: NewURLCache(),
		done: make(map[[HashSize]byte]bool)}

	for i := 0; i < 100; i++ {
		f.wg.Add(1)
		go f.fixServer()
	}

	t := time.NewTicker(time.Second)
	go func() {
		for _ = range t.C {
			log.Printf("fixers: %d active, %d skipped, " +
				"%d reconstructed, %d not reconstructed, " +
				"%d fixed, %d not fixed, %d already done",
				f.active, f.skipped, f.reconstructed,
				f.notreconstructed, f.fixed, f.notfixed,
				f.alreadydone)
		}
	}()

	return f
}

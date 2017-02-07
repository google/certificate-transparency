package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/google/certificate-transparency/go/fix-chain"
	"github.com/google/certificate-transparency/go/x509"
	"io"
	"log"
	"os"
	"sync"
)

func processChains(file string, fixer *fixchain.Fixer) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("Can't open %s: %s", f, err)
	}
	defer f.Close()

	type Chain struct {
		Chain [][]byte
	}

	dec := json.NewDecoder(f)
	for {
		var m Chain
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		var c fixchain.DedupedChain
		for _, derBytes := range m.Chain {
			cert, err := x509.ParseCertificate(derBytes)
			switch err.(type) {
			case nil, x509.NonFatalErrors:
				// ignore
			default:
				log.Fatalf("can't parse certificate: %s %#v",
					err, derBytes)
			}

			c.AddCert(cert)
		}
		fixer.FixAll(&c)
	}
}

func ContentStore(base string, sub string, c []byte) {
	r := sha256.Sum256(c)
	h := base64.URLEncoding.EncodeToString(r[:])
	d := base + "/" + sub
	os.MkdirAll(d, 0777)
	fn := d + "/" + h
	f, err := os.Create(fn)
	if err != nil {
		log.Fatalf("Can't create %s: %s", fn, err)
	}
	defer f.Close()
	f.Write(c)
}

func logJSONErrors(wg *sync.WaitGroup, errors chan *fixchain.FixError, base string) {
	defer wg.Done()

	for err := range errors {
		var b bytes.Buffer
		j := json.NewEncoder(&b)
		err2 := j.Encode(err)
		if err2 != nil {
			log.Fatalf("JSON encode failed: %s", err2)
		}
		ContentStore(base, err.TypeString(), b.Bytes())
	}
}

func logStringErrors(wg *sync.WaitGroup, errors chan *fixchain.FixError,
	base string) {
	defer wg.Done()

	for err := range errors {
		ContentStore(base, err.TypeString(), []byte(err.String()))
	}
}

func main() {
	logURL := os.Args[1]
	chains := os.Args[2]
	errDir := os.Args[3]

	var wg sync.WaitGroup
	wg.Add(1)

	errors := make(chan *fixchain.FixError)
	go logStringErrors(&wg, errors, errDir)

	f := fixchain.NewFixer(logURL, errors)

	processChains(chains, f)

	log.Printf("Wait for fixers")
	f.Wait()
	close(errors)
	log.Printf("Wait for errors")
	wg.Wait()
}

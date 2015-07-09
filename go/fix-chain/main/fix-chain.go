package main

import (
	"encoding/json"
	"io"
	"github.com/google/certificate-transparency/go/fix-chain"
	"log"
	"os"
	"sync"
	"github.com/google/certificate-transparency/go/x509"
)

func processChains(file string, fixer *fix_chain.Fixer) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("Can't open %s: %s", err)
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
		//log.Printf("%#v\n", m.Chain)
		//c := x509.NewCertPool()
		var c fix_chain.DedupedChain
		for _, derBytes := range m.Chain {
			cert, err := x509.ParseCertificate(derBytes)
			switch err.(type) {
			case nil:
			case x509.NonFatalErrors:
			default:
				log.Fatalf("can't parse certificate: %s %#v", err, derBytes)
			}

			c.AddCert(cert)
		}
		//log.Printf("%d in chain", len(m.Chain))
		//c.Dump("input")
		fixer.FixAll(&c)
	}
}

func logErrors(wg *sync.WaitGroup, errors chan *fix_chain.FixError) {
	defer wg.Done()
	
	for err := range errors {
		log.Printf("Error! %s", err.String())
	}
}

func main() {
	logurl := "https://ct.googleapis.com/rocketeer"
	//logurl := "https://ct.googleapis.com/aviator"
	
	var wg sync.WaitGroup
	wg.Add(1)
	
	errors := make(chan *fix_chain.FixError)
	go logErrors(&wg, errors)
	
	f := fix_chain.NewFixer(logurl, errors)
	
	processChains("/usr/home/ben/tmp/failed.json", f)
	
	log.Printf("Wait for fixers")
	f.Wait()
	close(errors)
	log.Printf("Wait for errors")
	wg.Wait()
}

package main

import (
	"encoding/json"
	"io"
	"github.com/google/certificate-transparency/go/fix-chain"
	"github.com/google/certificate-transparency/go/x509"
	"log"
	"os"
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
		log.Printf("%d in chain", len(m.Chain))
		c.Dump("input")
		fixer.FixAll(&c)
	}
}

func main() {
	logurl := "https://ct.googleapis.com/rocketeer"
	//logurl := "https://ct.googleapis.com/aviator"
	f := fix_chain.NewFixer(logurl)
	processChains("/usr/home/ben/tmp/failed.json", f)
	log.Printf("Wait for fixers")
	f.Wait()
}

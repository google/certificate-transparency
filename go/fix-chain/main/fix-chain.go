package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"github.com/google/certificate-transparency/go/fix-chain"
	"github.com/google/certificate-transparency/go/x509"
	"log"
	"net/http"
	"os"
)

var pemText = `
-----BEGIN CERTIFICATE-----
MIICDjCCAbUCCQDF6SfN0nsnrjAJBgcqhkjOPQQBMIGPMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMG
A1UECgwMR29vZ2xlLCBJbmMuMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIwMjAyMDUw
WhcNMjIwNTE4MjAyMDUwWjCBjzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwg
SW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAhBgkqhkiG9w0BCQEWFGdv
bGFuZy1kZXZAZ21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/Wgn
WQDo5+bz71T0327ERgd5SDDXFbXLpzIZDXTkjpe8QTEbsF+ezsQfrekrpDPC4Cd3
P9LY0tG+aI8IyVKdUjAJBgcqhkjOPQQBA0gAMEUCIGlsqMcRqWVIWTD6wXwe6Jk2
DKxL46r/FLgJYnzBEH99AiEA3fBouObsvV1R3oVkb4BQYnD4/4LeId6lAT43YvyV
a/A=
-----END CERTIFICATE-----
`

var cafbankPem = `-----BEGIN CERTIFICATE-----
MIIFAzCCA+ugAwIBAgIQA7NYsI6Ap9JvnLLI3Ut7izANBgkqhkiG9w0BAQUFADBI
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSIwIAYDVQQDExlE
aWdpQ2VydCBTZWN1cmUgU2VydmVyIENBMB4XDTE0MDMxMTAwMDAwMFoXDTE1MDcw
OTEyMDAwMFowZjELMAkGA1UEBhMCR0IxDTALBgNVBAgTBEtlbnQxFTATBgNVBAcT
DFdlc3QgTWFsbGluZzEZMBcGA1UEChMQQ0FGIEJBTksgTElNSVRFRDEWMBQGA1UE
AwwNKi5jYWZiYW5rLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALBfcK8NSruS0xnOhctUAmL9ViL2votMVCCv5v52My7IhsWP1pFMbVZrC6LjfP14
zKJQ4717sqExX0N7mG1tzArKOCHmWs8uszYRskt6e5ETMKPRURL241b0CcCdr/e4
cfYAujKwV9i9cQzifHgyQDhTzjbthEiYVOBXIfAvM4t7NlhbhVTodflQRM+erGBa
F+/N4iHbGq3BfmVnfyQrndN6hD96VtcDWyY5AHnr0vPqRVsW1+YJeAFfLUyjNkki
PM3EFlrLK/5Gr2RLEIsB53OxnwcJAipydq+gYru6yQhrlNpZPuX4dyW/brVy4pzV
QfUBkOP8fs5rFMCSAyY2zPsCAwEAAaOCAckwggHFMB8GA1UdIwQYMBaAFJBx2zfr
c8jv3NUeErY0uitaoKaSMB0GA1UdDgQWBBSUtx2r0u8IRC+/+S8gRc7Kzv78mTAl
BgNVHREEHjAcgg0qLmNhZmJhbmsub3JnggtjYWZiYW5rLm9yZzAOBgNVHQ8BAf8E
BAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMGEGA1UdHwRaMFgw
KqAooCaGJGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zc2NhLWc1LmNybDAqoCig
JoYkaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NzY2EtZzUuY3JsMEIGA1UdIAQ7
MDkwNwYJYIZIAYb9bAEBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2lj
ZXJ0LmNvbS9DUFMweAYIKwYBBQUHAQEEbDBqMCQGCCsGAQUFBzABhhhodHRwOi8v
b2NzcC5kaWdpY2VydC5jb20wQgYIKwYBBQUHMAKGNmh0dHA6Ly9jYWNlcnRzLmRp
Z2ljZXJ0LmNvbS9EaWdpQ2VydFNlY3VyZVNlcnZlckNBLmNydDAMBgNVHRMBAf8E
AjAAMA0GCSqGSIb3DQEBBQUAA4IBAQB89Fu7C1OAwVmSwG/lIMmB359puq8J0Jcu
XyLSCTPPxVWNQTzSpRQtIDRekQ8H5cf72z2xWaI9pDKR7M7/1tx4UwwaG+NDt7M2
f41Kpsn+aFtryl6Ngzu7T8018wMBorm8b09qyjDy+UhvZ0Yy7kXJ7fUMW4mtiy8e
N0Peyeb7hUTAk0IiAtCEf71SqnuGebDsxbO8xKpyMQvF7V86GD7tBPGV/PLtIVKx
jXTh97tWdE3W4S6g93TBax2Rlah0HwGLZEezmnUPJqRRw9y+ArYjPh000gcdxcCP
CmmuVy5FyQkgingGlg2o06ZMN+XsJyD5+yGFHHFIpsYnK8+7Rd+z
-----END CERTIFICATE-----
`

func Hash(s *x509.Certificate) ([sha256.Size]byte) {
	return sha256.Sum256(s.Raw)
}

func HexHash(s *x509.Certificate) (string) {
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

func knownBad(name string) (bool) {
	return name == "http://gca.nat.gov.tw/repository/Certs/IssuedToThisCA.p7b" || name == "http://grca.nat.gov.tw/repository/Certs/IssuedToThisCA.p7b" || name == "http://crt.trust-provider.com/AddTrustExternalCARoot.p7c" || name == "http://crt.usertrust.com/AddTrustExternalCARoot.p7c"
}

var URLCache map[string][]byte

func GetURL(url string) (r []byte, err error) {
	if URLCache == nil {
		URLCache = make(map[string][]byte)
	}
	r, ok := URLCache[url]
	if ok {
		log.Printf("HIT! %s", url)
	} else {
		c, err0 := http.Get(url)
		// FIXME: cache errors
		if err0 != nil {
			err = err0
			return
		}
		defer c.Body.Close()
		if c.StatusCode != 200 {
			err = errors.New(fmt.Sprintf("can't deal with status %d", c.StatusCode))
			return
		}
		r, err = ioutil.ReadAll(c.Body)
		if err != nil {
			return
		}
		URLCache[url] = r
	}
	return
}

type DedupedChain struct {
	certs []*x509.Certificate
}

func (d *DedupedChain) fixChain(cert *x509.Certificate, intermediates *x509.CertPool, l *fix_chain.Log) {
	opts := x509.VerifyOptions{ Intermediates: intermediates, Roots: l.Roots() }
	chain, err := cert.Verify(opts)
	if err == nil {
		dumpChains("verified", chain)
		l.PostChains(chain)
		return
	}
	log.Printf("failed to verify certificate for %s: %s", cert.Subject.CommonName, err)
	d2 := *d
	d2.AddCert(cert)
	for _, c := range d2.certs {
		urls := c.IssuingCertificateURL
		for i, url := range urls {
			log.Printf("fetch issuer %d from %s", i, url)
			body, err := GetURL(url)
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
			opts.Intermediates.AddCert(icert)
			chain, err := cert.Verify(opts)
			if err == nil {
				dumpChains("fixed", chain)
				l.PostChains(chain)
				return
			}
		}
	}
	log.Printf("failed to fix certificate for %s", cert.Subject.CommonName)
}

func (d *DedupedChain) fixAll(l *fix_chain.Log) {
	intermediates := x509.NewCertPool()
	for _, c := range d.certs {
		intermediates.AddCert(c)
	}
	for _, c := range d.certs {
		d.fixChain(c, intermediates, l)
	}
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

func processChains(file string, l *fix_chain.Log) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("Can't open %s: %s", err)
	}
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
		var c DedupedChain
		for i := 0 ; i < len(m.Chain) ; i++ {
			r, err := x509.ParseCertificate(m.Chain[i])
			switch err.(type) {
			case nil:
			case x509.NonFatalErrors:
			default:
				log.Fatalf("can't parse certificate: %s %#v", err, m.Chain[i])
			}
			c.AddCert(r)
			//log.Printf("Chain %d: %s", i, r.Subject.CommonName)
		}
		log.Printf("%d in chain", len(m.Chain))
		dumpChain("input", c.certs)
		c.fixAll(l)
	}
}

func main() {
	//logurl := "https://ct.googleapis.com/aviator"
	l := fix_chain.NewLog("https://ct.googleapis.com/rocketeer")
	processChains("/usr/home/ben/tmp/failed.json", l)
	/*
	s, _ := pem.Decode([]byte(cafbankPem))
	cert, err := x509.ParseCertificate(s.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %s", err)
		return
	}
*/
}

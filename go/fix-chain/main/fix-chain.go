package main

import (
	"encoding/json"
	"io"
	"github.com/google/certificate-transparency/go/fix-chain"
	"github.com/google/certificate-transparency/go/x509"
	"log"
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

func processChains(file string, fixer *fix_chain.Fixer, l *fix_chain.Log) {
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
		var c fix_chain.DedupedChain
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
		c.Dump("input")
		fixer.FixAll(&c, l)
	}
}

func main() {
	//logurl := "https://ct.googleapis.com/aviator"
	l := fix_chain.NewLog("https://ct.googleapis.com/rocketeer")
	f := fix_chain.InitFixer()
	processChains("/usr/home/ben/tmp/failed.json", f, l)
	log.Printf("Wait for fixers")
	f.Wait()
	log.Printf("Wait for loggers")
	l.Wait()
	/*
	s, _ := pem.Decode([]byte(cafbankPem))
	cert, err := x509.ParseCertificate(s.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %s", err)
		return
	}
*/
}

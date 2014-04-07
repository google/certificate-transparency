package scanner

import (
	"container/list"
	"crypto/x509"
	"ct/client"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestScannerCertMatcherFindsCN(t *testing.T) {
	const SubjectName = "www.example.com"
	const SubjectRegEx = ".*example.com"
	var cert x509.Certificate
	cert.Subject.CommonName = SubjectName

	opts := ScannerOptions{MatchSubjectRegex: regexp.MustCompile(SubjectRegEx)}
	scanner := NewScanner(nil, opts)
	if !scanner.certMatcher(&cert) {
		t.Fatal("Scanner failed to match on Subject CommonName")
	}
}

func TestScannerCertMatcherFindsSAN(t *testing.T) {
	const SubjectName = "www.example.com"
	const SubjectRegEx = ".*example.com"
	var cert x509.Certificate
	cert.Subject.CommonName = SubjectName

	opts := ScannerOptions{MatchSubjectRegex: regexp.MustCompile(SubjectRegEx)}
	scanner := NewScanner(nil, opts)
	cert.Subject.CommonName = "Wibble"              // Doesn't match
	cert.DNSNames = append(cert.DNSNames, "Wibble") // Nor this
	cert.DNSNames = append(cert.DNSNames, SubjectName)

	if !scanner.certMatcher(&cert) {
		t.Fatal("Scanner failed to match on SubjectAlternativeName")
	}
}

func TestScannerEndToEnd(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			log.Printf("GetSTH")
			if _, err := w.Write([]byte(FourEntrySTH)); err != nil {
				t.Fatal("Failed to write get-sth response")
			}
		case "/ct/v1/get-entries":
			log.Printf("GetEntries %s", r.URL.RawQuery)
			if _, err := w.Write([]byte(FourEntries)); err != nil {
				t.Fatal("Failed to write get-sth response")
			}
		default:
			t.Fatal("Unexpected request")
		}
	}))
	defer ts.Close()

	client := client.New(ts.URL)
	opts := ScannerOptions{regexp.MustCompile(".*\\.google\\.com"), 10, 1, 1, 0}
	scanner := NewScanner(client, opts)

	var matchedCerts list.List
	var matchedPrecerts list.List

	err := scanner.Scan(func(index int64, c *x509.Certificate) {
		// Annoyingly we can't t.Fatal() in here, as this is run in another go
		// routine
		matchedCerts.PushBack(*c)
	}, func(index int64, p string) {
		matchedPrecerts.PushBack(p)
	})

	if err != nil {
		t.Fatal(err)
	}

	if matchedPrecerts.Len() != 0 {
		t.Fatal("Found unexpected Precert")
	}

	switch matchedCerts.Len() {
	case 0:
		t.Fatal("Failed to find mail.google.com cert")
	case 1:
		if matchedCerts.Front().Value.(x509.Certificate).Subject.CommonName != "mail.google.com" {
			t.Fatal("Matched unexpected cert")
		}
	default:
		t.Fatal("Found unexpected number of certs")
	}
}

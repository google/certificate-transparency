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

func CertMatchesRegex(r *regexp.Regexp, cert *x509.Certificate) bool {
	if r.FindStringIndex(cert.Subject.CommonName) != nil {
		return true
	}
	for _, alt := range cert.DNSNames {
		if r.FindStringIndex(alt) != nil {
			return true
		}
	}
	return false
}

func TestScannerMatchAll(t *testing.T) {
	var cert x509.Certificate
	m := &MatchAll{}
	if !m.CertificateMatches(&cert) {
		t.Fatal("MatchAll didn't match!")
	}
}
func TestScannerMatchNone(t *testing.T) {
	var cert x509.Certificate
	m := &MatchNone{}
	if m.CertificateMatches(&cert) {
		t.Fatal("MatchNone matched!")
	}
}

func TestScannerMatchSubjectRegexMatchesCommonName(t *testing.T) {
	const SubjectName = "www.example.com"
	const SubjectRegEx = ".*example.com"
	var cert x509.Certificate
	cert.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{regexp.MustCompile(SubjectRegEx)}
	if !m.CertificateMatches(&cert) {
		t.Fatal("MatchSubjectRegex failed to match on Subject CommonName")
	}
}

func TestScannerMatchSubjectRegexMatchesSAN(t *testing.T) {
	const SubjectName = "www.example.com"
	const SubjectRegEx = ".*example.com"
	var cert x509.Certificate
	cert.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{regexp.MustCompile(SubjectRegEx)}
	cert.Subject.CommonName = "Wibble"              // Doesn't match
	cert.DNSNames = append(cert.DNSNames, "Wibble") // Nor this
	cert.DNSNames = append(cert.DNSNames, SubjectName)

	if !m.CertificateMatches(&cert) {
		t.Fatal("MatchSubjectRegex failed to match on SubjectAlternativeName")
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
	opts := ScannerOptions{
		Matcher:       &MatchSubjectRegex{regexp.MustCompile(".*\\.google\\.com")},
		BlockSize:     10,
		NumWorkers:    1,
		ParallelFetch: 1,
		StartIndex:    0,
	}
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

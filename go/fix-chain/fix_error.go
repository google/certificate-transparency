package fix_chain

import (
	"encoding/pem"
	"fmt"
	"github.com/google/certificate-transparency/go/x509"
)

type ErrorType int

const (
	ParseFailure ErrorType = iota
	CannotFetchURL
)

type FixError struct {
	Type ErrorType
	// The supplied leaf certificate
	Cert *x509.Certificate
	// The supplied chain
	Chain *DedupedChain
	// URL, if a URL is involved
	URL string
	// And the error
	Error error
}

func (e FixError) String() (s string) {
	switch(e.Type) {
	case ParseFailure: s = "ParseFailure"
	case CannotFetchURL: s = "CannotFetchURL"
	default: s = fmt.Sprint("Type%d", e.Type)
	}
	s += "\n" + e.Error.Error() + "\n"
	if e.URL != "" {
		s += e.URL + "\n"
	}
	b := pem.Block { Type: "CERTIFICATE", Bytes: e.Cert.Raw }
	s += string(pem.EncodeToMemory(&b))
	if e.Chain != nil {
		s += DumpChainPEM(e.Chain.certs)
	}
	return
}

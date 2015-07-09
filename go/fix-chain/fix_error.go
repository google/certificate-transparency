package fix_chain

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/certificate-transparency/go/x509"
)

type ErrorType int

const (
	ParseFailure ErrorType = iota
	CannotFetchURL
	FixFailed
)

type FixError struct {
	Type ErrorType
	// The supplied leaf certificate
	Cert *x509.Certificate
	// The supplied chain
	Chain *DedupedChain
	// URL, if a URL is involved
	URL string
	// The offending bytes, if applicable
	Bad []byte
	// And the error
	Error error
}

func (e FixError) TypeString() string {
	switch(e.Type) {
	case ParseFailure: return "ParseFailure"
	case CannotFetchURL: return "CannotFetchURL"
	case FixFailed: return "FixFailed"
	default: return fmt.Sprint("Type%d", e.Type)
	}
}

func (e FixError) String() (s string) {
	s = e.TypeString()
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

func (e FixError) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	j := json.NewEncoder(&b)
	var m struct {
		Type string
		Cert []byte
		Chain [][]byte
		URL string
		Bad []byte
		Error string
	}
	m.Type = e.TypeString()
	m.Cert = e.Cert.Raw
	for _, c := range e.Chain.certs {
		m.Chain = append(m.Chain, c.Raw)
	}
	m.URL = e.URL
	m.Bad = e.Bad
	if e.Error != nil {
		m.Error = e.Error.Error()
	}
	if err := j.Encode(m); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

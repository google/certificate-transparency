package fixchain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/certificate-transparency/go/x509"
)

type ErrorType int

const (
	ParseFailure ErrorType = iota
	CannotFetchURL
	FixFailed
	LogPostFailed
	VerifyFailed
)

type FixError struct {
	Type  ErrorType
	Cert  *x509.Certificate   // The supplied leaf certificate
	Chain []*x509.Certificate // The supplied chain
	URL   string              // URL, if a URL is involved
	Bad   []byte              // The offending bytes, if applicable
	Error error               // And the error
}

func (e FixError) TypeString() string {
	switch e.Type {
	case ParseFailure:
		return "ParseFailure"
	case CannotFetchURL:
		return "CannotFetchURL"
	case FixFailed:
		return "FixFailed"
	case LogPostFailed:
		return "LogPostFailed"
	case VerifyFailed:
		return "VerifyFailed"
	default:
		return fmt.Sprintf("Type%d", e.Type)
	}
}

func (e FixError) String() (s string) {
	s = e.TypeString() + "\n"
	if e.Error != nil {
		s += "Error: " + e.Error.Error() + "\n"
	}
	if e.URL != "" {
		s += "URL: " + e.URL + "\n"
	}
	s += "Bad: " + DumpPEM(e.Bad)
	if e.Cert != nil {
		s += "Cert: " + DumpPEM(e.Cert.Raw)
	}
	if e.Chain != nil {
		s += "Chain: " + DumpChainPEM(e.Chain)
	}
	return
}

func (e FixError) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	j := json.NewEncoder(&b)
	var m struct {
		Type  string
		Cert  []byte
		Chain [][]byte
		URL   string
		Bad   []byte
		Error string
	}
	m.Type = e.TypeString()
	m.Cert = e.Cert.Raw
	for _, c := range e.Chain {
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

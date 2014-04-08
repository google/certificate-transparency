// CT log client package contains types and code for interacting with
// RFC6962-compliant CT Log instances.
// See http://tools.ietf.org/html/rfc6962 for details
package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/mreiferson/go-httpclient"
)

// URI paths for CT Log endpoints
const (
	GetSTHPath     = "/ct/v1/get-sth"
	GetEntriesPath = "/ct/v1/get-entries"
)

// Variable size structure prefix-header byte lengths
const (
	CertificateLengthBytes    = 3
	PreCertificateLengthBytes = 3
	ExtensionsLengthBytes     = 2
)

const (
	IssuerKeyHashLength = 32
)

// A LogClient represents a client for a given CT Log instance
type LogClient struct {
	uri        string       // the base URI of the log. e.g. http://ct.googleapis/pilot
	httpClient *http.Client // used to interact with the log via HTTP
}

//////////////////////////////////////////////////////////////////////////////////
// JSON structures follow.
// These represent the structures returned by the CT Log server.
//////////////////////////////////////////////////////////////////////////////////

// Represents the JSON response to the add-chain CT method.
// An SCT represents a Log's promise to integrate a [pre-]certificate into the
// log within a defined period of time.
type addChainResponse struct {
	SctVersion Version `json:"sct_version"` // SCT structure version
	Id         string  `json:"id"`          // Log Id
	Timestamp  uint64  `json:"timestamp"`   // Timestamp of issuance
	Extensions string  `json:"extensions"`  // Holder for any CT extensions
	Signature  string  `json:"signature"`   // Log signature for this SCT
}

// Respresents the JSON response to the get-sth CT method
type getSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`           // Number of certs in the current tree
	Timestamp         uint64 `json:"timestamp"`           // Time that the tree was created
	Sha256RootHash    string `json:"sha256_root_hash"`    // Root hash of the tree
	TreeHeadSignature string `json:"tree_head_signature"` // Log signature for this STH
}

// Respresents a Base64 encoded leaf entry
type base64LeafEntry struct {
	LeafInput string `json:"leaf_input"`
}

// Respresents the JSON response to the CT get-entries method
type getEntriesResponse struct {
	Entries []base64LeafEntry `json:"entries"` // the list of returned entries
}

// Represents the JSON response to the CT get-consistency-proof method
type getConsistencyProofResponse struct {
	Consistency []string `json:"consistency"`
}

// Represents the JSON response to the CT get-audit-proof method
type getAuditProofResponse struct {
	Hash     []string `json:"hash"`      // the hashes which make up the proof
	TreeSize uint64   `json:"tree_size"` // the tree size against which this proof is constructed
}

// Represents the JSON response to the CT get-roots method.
type getAcceptedRootsResponse struct {
	Certificates []string `json:"certificates"`
}

// Represents the JSON response to the CT get-entry-and-proof method
type getEntryAndProofResponse struct {
	LeafInput string   `json:"leaf_input"` // the entry itself
	ExtraData string   `json:"extra_data"` // any chain provided when the entry was added to the log
	AuditPath []string `json:"audit_path"` // the corresponding proof
}

///////////////////////////////////////////////////////////////////////////////////
// The following structures represent those outlined in the RFC6962 document:
///////////////////////////////////////////////////////////////////////////////////

// Represents the LogEntryType enum from section 3.1 of the RFC:
//   enum { x509_entry(0), precert_entry(1), (65535) } LogEntryType;
type LogEntryType uint16

const (
	X509LogEntryType    LogEntryType = 0
	PrecertLogEntryType              = 1
)

// Represents the MerkleLeafType enum from section 3.4 of the RFC:
// enum { timestamped_entry(0), (255) } MerkleLeafType;
type MerkleLeafType uint8

const (
	TimestampedEntryLeafType MerkleLeafType = 0 // Entry type for an SCT
)

// The Version enum from section 3.2 of the RFC:
// enum { v1(0), (255) } Version;
type Version uint8

const (
	V1 Version = 0
)

// Raw DER bytes of an ASN.1 Certificate (section 3.1)
type ASN1Cert []byte

// Precertificate (section 3.2)
type PreCert struct {
	IssuerKeyHash  [IssuerKeyHashLength]byte
	TBSCertificate []byte
}

// Raw bytes of any CtExtension structure (see section 3.2)
type CtExtensions []byte

// Represents an internal node in the CT tree
type MerkleTreeNode []byte

// Represents a CT consistency proof (see sections 2.1.2 and 4.4)
type ConsistencyProof []MerkleTreeNode

// Represents a CT inclusion proof (see sections 2.1.1 and 4.5)
type AuditProof []MerkleTreeNode

// Represents a serialized MerkleTreeLeaf structure
type LeafInput []byte

// Represents the structure returned by the get-sth CT method after
// base64 decoding. See sections 3.5 and 4.3 in the RFC)
type SignedTreeHead struct {
	TreeSize          uint64 // The number of entries in the new tree
	Timestamp         uint64 // The time at which the STH was created
	Sha256RootHash    []byte // The root hash of the log's Merkle tree
	TreeHeadSignature []byte // The Log's signature for this STH (see RFC section 3.5)
}

// Represents the structure returned by the add-chain and add-pre-chain methods
// after base64 decoding.  (see RFC sections 3.2 ,4.1 and 4.2)
type SignedCertificateTimestamp struct {
	SctVersion Version // The version of the protocol to which the SCT conforms
	LogId      []byte  // the SHA-256 hash of the log's public key, calculated over
	// the DER encoding of the key represented as SubjectPublicKeyInfo.
	Timestamp  uint64       // Timestamp (in ms since unix epoc) at which the SCT was issued
	Extentions CtExtensions // For future extensions to the protocol
	Signature  []byte       // The Log's signature for this SCT
}

// Part of the MerkleTreeLeaf structure.
// See RFC section 3.4
type TimestampedEntry struct {
	Timestamp    uint64
	EntryType    LogEntryType
	X509Entry    ASN1Cert
	PrecertEntry PreCert
	Extensions   CtExtensions
}

// Represents the deserialized sructure of the hash input for the leaves of a
// log's Merkle tree. See RFC section 3.4
type MerkleTreeLeaf struct {
	Version          Version          // the version of the protocol to which the MerkleTreeLeaf corresponds
	LeafType         MerkleLeafType   // The type of the leaf input, currently only TimestampedEntry can exist
	TimestampedEntry TimestampedEntry // The entry data itself
}

// Deep compares two SignedTreeHeads, returning true iff they are identical.
func (sth *SignedTreeHead) Equals(other SignedTreeHead) bool {
	return sth.TreeSize == other.TreeSize &&
		sth.Timestamp == other.Timestamp &&
		bytes.Equal(sth.Sha256RootHash, other.Sha256RootHash) &&
		bytes.Equal(sth.TreeHeadSignature, other.TreeHeadSignature)
}

// Reads a variable length array of bytes from |r|. |numLenBytes| specifies the
// number of (BigEndian) prefix-bytes which contain the length of the actual
// array data bytes that follow.
// Allocates an array to hold the contents and returns a slice view into it if
// the read was successful, or an error otherwise.
func readVarBytes(r io.Reader, numLenBytes int) ([]byte, error) {
	var l uint64
	switch {
	case numLenBytes > 8:
		return nil, errors.New("numLenBytes too large")
	case numLenBytes == 0:
		return nil, errors.New("numLenBytes should be > 0")
	}
	// Read the length header bytes
	for i := 0; i < numLenBytes; i++ {
		l <<= 8
		var t uint8
		err := binary.Read(r, binary.BigEndian, &t)
		if err != nil {
			return nil, err
		}
		l |= uint64(t)
	}
	data := make([]byte, l, l)
	n, err := r.Read(data)
	if err != nil {
		return nil, err
	}
	if n != int(l) {
		return nil, errors.New("short read: expected " + strconv.Itoa(int(l)) + " but got " + strconv.Itoa(n))
	}
	return data, nil
}

// Parses the byte-stream representation of a TimestampedEntry and populates
// the struct |t| with the data.
// See RFC section 3.4 for details on the format.
// Returns a non-nil error if there was a problem.
func (t *TimestampedEntry) parse(r io.Reader) error {
	var err error
	if err = binary.Read(r, binary.BigEndian, &t.Timestamp); err != nil {
		return err
	}
	if err = binary.Read(r, binary.BigEndian, &t.EntryType); err != nil {
		return err
	}
	switch t.EntryType {
	case X509LogEntryType:
		if t.X509Entry, err = readVarBytes(r, CertificateLengthBytes); err != nil {
			return err
		}
	case PrecertLogEntryType:
		if err := binary.Read(r, binary.BigEndian, &t.PrecertEntry.IssuerKeyHash); err != nil {
			return err
		}
		if t.PrecertEntry.TBSCertificate, err = readVarBytes(r, PreCertificateLengthBytes); err != nil {
			return err
		}
	default:
		return errors.New("unknown EntryType: " + strconv.Itoa(int(t.EntryType)))
	}
	t.Extensions, err = readVarBytes(r, ExtensionsLengthBytes)
	return err
}

// Parses the byte-stream representation of a MerkleTreeLeaf and populated the
// struct |m| with the data.
// See RFC section 3.4 for details on the format.
// Returns a pointer to a new MerkleTreeLeaf or non-nil error if there was a problem
func NewMerkleTreeLeaf(r io.Reader) (*MerkleTreeLeaf, error) {
	var m MerkleTreeLeaf
	if err := binary.Read(r, binary.BigEndian, &m.Version); err != nil {
		return nil, err
	}
	if m.Version != V1 {
		return nil, fmt.Errorf("unknown Version %d", m.Version)
	}
	if err := binary.Read(r, binary.BigEndian, &m.LeafType); err != nil {
		return nil, err
	}
	if m.LeafType != TimestampedEntryLeafType {
		return nil, fmt.Errorf("unknown LeafType %d", m.LeafType)
	}
	if err := m.TimestampedEntry.parse(r); err != nil {
		return nil, err
	}
	return &m, nil
}

// Returns the X.509 Certificate contained within the MerkleTreeLeaf.
// Returns a pointer to an x509.Certificate or a non-nil error.
func (m *MerkleTreeLeaf) X509Certificate() (cert *x509.Certificate, err error) {
	cert, err = x509.ParseCertificate(m.TimestampedEntry.X509Entry)
	return cert, err
}

// Constructs a new LogClient instance.
// |uri| is the base URI of the CT log instance to interact with, e.g.
// http://ct.googleapis.com/pilot
func New(uri string) *LogClient {
	var c LogClient
	c.uri = uri
	// TODO(alcutter): make these timeouts modifiable
	transport := &httpclient.Transport{
		ConnectTimeout:        10 * time.Second,
		RequestTimeout:        30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	c.httpClient = &http.Client{Transport: transport}
	return &c
}

// Makes a HTTP call to |uri|, and attempts to parse the response as a JSON
// representation of the structure in |res|.
// Returns a non-nil |error| if there was a problem.
func (c *LogClient) fetchAndParse(uri string, res interface{}) error {
	req, _ := http.NewRequest("GET", uri, nil)
	if resp, err := c.httpClient.Do(req); err != nil {
		return err
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err = json.Unmarshal(body, &res); err != nil {
			return err
		}
	}
	return nil
}

// Retrieves the current STH from the log.
// Returns a populated SignedTreeHead, or a non-nil error.
func (c *LogClient) GetSTH() (sth *SignedTreeHead, err error) {
	var resp getSTHResponse
	if err = c.fetchAndParse(c.uri+GetSTHPath, &resp); err != nil {
		return nil, err
	} else {
		sth = &SignedTreeHead{}
		sth.TreeSize = resp.TreeSize
		sth.Timestamp = resp.Timestamp
		if sth.Sha256RootHash, err = base64.StdEncoding.DecodeString(resp.Sha256RootHash); err != nil {
			return nil, errors.New("invalid base64 encoding in sha256_root_hash")
		}
		if len(sth.Sha256RootHash) != sha256.Size {
			return nil, errors.New("sha256_root_hash is invalid length")
		}
		sth.TreeHeadSignature, err = base64.StdEncoding.DecodeString(resp.TreeHeadSignature)
		// TODO(alcutter): Verify signature
	}
	return sth, nil
}

// Attempts to retrieve the entries in the sequence [|start|, |end|] from the CT
// log server. (see section 4.6.)
// Returns a slice of LeafInputs or a non-nil error.
func (c *LogClient) GetEntries(start, end int64) ([]LeafInput, error) {
	if end < 0 {
		return nil, errors.New("end should be >= 0")
	}
	if end < start {
		return nil, errors.New("start should be <= end")
	}
	var resp getEntriesResponse
	err := c.fetchAndParse(fmt.Sprintf("%s%s?start=%d&end=%d", c.uri, GetEntriesPath, start, end), &resp)
	if err != nil {
		return nil, err
	}
	entries := make([]LeafInput, end-start+1, end-start+1)
	for index, entry := range resp.Entries {
		entries[index], err = base64.StdEncoding.DecodeString(entry.LeafInput)
		if err != nil {
			return nil, err
		}
	}
	return entries, err
}

package client

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

const (
	PrecertEntryB64 = "AAAAAAFEvwd6LgABemrYgpjLplsXa6OnqyXuj5BgQDPaapisB5WfVm+jr" +
		"FQABdEwggXNoAMCAQICEAca4ZCK2+1RDyapBvaLcg0wDQYJKoZIhvcNAQEFBQAwZjELMAkGA" +
		"1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0L" +
		"mNvbTElMCMGA1UEAxMcRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2UgQ0EtMzAeFw0xNDAzMTAwM" +
		"DAwMDBaFw0xNTA1MTMxMjAwMDBaMIGYMQswCQYDVQQGEwJKUDERMA8GA1UECBMIa2FuYWdhd" +
		"2ExEzARBgNVBAcTClNhZ2FtaWhhcmExHDAaBgNVBAoTE0tpdGFzYXRvIFVuaXZlcnNpdHkxJ" +
		"jAkBgNVBAsTHUluZm9ybWF0aW9uIE5ldHdvcmtpbmcgQ2VudGVyMRswGQYDVQQDDBIqLmtpd" +
		"GFzYXRvLXUuYWMuanAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC41vXdZxYeN" +
		"T0R03mbtCjTAJ8pnjD6IDwvHSoMzCuaeuzhNFpLIHockWPmKglLektE6lhE3Hs7mXIW86H43" +
		"WNcYOzcpFf6PdVcJFMwBgDeTlm8sPpFTwdA1tRiIRU2T0xYM4kAESimaQJZdm3xITZwEhnBq" +
		"eWX72Tr+Yzfot0COFjpX5b9to0ahTylKsGruMHWE6NpQlk+Oj24lln4uHRjdrZn/6MrX1/J8" +
		"miru9zj6Rkjn4EM+Mo6BfgpKK15nfIuEhNXFZ6WZB/MOhPgSU4uD+AsykeLsOsSTIEteuaJW" +
		"juKqTAL4QkDvjhfrk6iZTns+UuWmNbrOnzi4jAbd3OhAgMBAAGjggNaMIIDVjAfBgNVHSMEG" +
		"DAWgBRQ6nOJ2yn7EI+e5QEg1N55mUiD9zAdBgNVHQ4EFgQUQCepkOE4RkifUlf4Sfa/cJVst" +
		"WYwLwYDVR0RBCgwJoISKi5raXRhc2F0by11LmFjLmpwghBraXRhc2F0by11LmFjLmpwMA4GA" +
		"1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwYQYDVR0fBFowW" +
		"DAqoCigJoYkaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL2NhMy1nMjcuY3JsMCqgKKAmhiRod" +
		"HRwOi8vY3JsNC5kaWdpY2VydC5jb20vY2EzLWcyNy5jcmwwggHEBgNVHSAEggG7MIIBtzCCA" +
		"bMGCWCGSAGG/WwBATCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93d3cuZGlnaWNlcnQuY29tL" +
		"3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAd" +
		"QBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4Ac" +
		"wB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAAR" +
		"ABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAe" +
		"QBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAb" +
		"ABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAb" +
		"wByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AY" +
		"wBlAC4wewYIKwYBBQUHAQEEbzBtMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vyd" +
		"C5jb20wRQYIKwYBBQUHMAKGOWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vyd" +
		"EhpZ2hBc3N1cmFuY2VDQS0zLmNydDAMBgNVHRMBAf8EAjAAAAA="
	CertEntryB64 = "AAAAAAFEwEwJngAAAAUnMIIFIzCCBAugAwIBAgIHJ6L5mPSurzANBgkqhkiG" +
		"9w0BAQsFADCBtDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj" +
		"b3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8v" +
		"Y2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3Vy" +
		"ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjAeFw0xNDAzMTIxODU0NTRaFw0xNTAzMTIx" +
		"ODU0NTRaMDkxITAfBgNVBAsTGERvbWFpbiBDb250cm9sIFZhbGlkYXRlZDEUMBIGA1UEAxML" +
		"dHJpc3VyZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQUUOZYiQ4DmtX" +
		"4k4CuCgHB4b8ZONL4CJBlFQc/nIbjgKAXMNUhsjLayR36RccSp1ZJXPwKTXCWQ6kjYTeBvFs" +
		"b6ky9ApYa/ZFecNmkzld8tilDsKH7GAdr2vUz0W8bR6YlY0cgNQ/KXrFKL5giaqUt9w5OThr" +
		"WaGEDNufSDin4AChHzPhncfjwD3DZFfjcDrR9H7xryZSWVZUYTLo7Vs/ceuWvAkuh2yZe1QS" +
		"d5XKKy52MqAwqYG4Ioi2cQfCgVEe2P8HEj1XzlYxHOD0ohNf6IRnPrGVHSTcllyeJP5uvU/e" +
		"6CiOUe0F+f98I02F18cDbDfleRc6u03idR3q4ZL9AgMBAAGjggGyMIIBrjAPBgNVHRMBAf8E" +
		"BTADAQEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAOBgNVHQ8BAf8EBAMCBaAw" +
		"NgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nb2RhZGR5LmNvbS9nZGlnMnMxLTI3LmNy" +
		"bDBTBgNVHSAETDBKMEgGC2CGSAGG/W0BBxcBMDkwNwYIKwYBBQUHAgEWK2h0dHA6Ly9jZXJ0" +
		"aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8wdgYIKwYBBQUHAQEEajBoMCQGCCsG" +
		"AQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wQAYIKwYBBQUHMAKGNGh0dHA6Ly9j" +
		"ZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS9nZGlnMi5jcnQwHwYDVR0jBBgw" +
		"FoAUQMK9J47MNIMwojPX+2yz8LQsgM4wJwYDVR0RBCAwHoILdHJpc3VyZS5jb22CD3d3dy50" +
		"cmlzdXJlLmNvbTAdBgNVHQ4EFgQUncM2IqTKpShSWBCF37hH/dDVbR8wDQYJKoZIhvcNAQEL" +
		"BQADggEBAEiIEjD9CWyDyV27csg6itq48yOF/icQ6j3Y8rmyQ1levCDGaR7tv4RjU/iuQEwR" +
		"hGOG3xQ7So+qSKm0lj6ZJJpv3nLroQKpcadyW6n/s4CokHOgxxlzhwvdeTXvul0kt3QG8l4s" +
		"HgzGqvfnjUsqljQ5U4Z2BAsRuAiilVc0/TTPbb0smbnq4GFbOCXe73xFgY4NZJ6IPzvwhTdT" +
		"Lxg0dUi5yOgjsrJ7agV1sI+Wk1C7+Y70FOHcM3vNC4HZ2KIbM/pex8IH64J9/TYEkVCtTvdB" +
		"tXjj+06auSnL+GOFJgqzSfbTWT8AJIbo0GezGpN88hwulluXnhh2vPgqSvjSBjIAAA=="
)

const (
	ValidSTHResponse = `{"tree_size":3721782,"timestamp":1396609800587,
        "sha256_root_hash":"SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo=",
        "tree_head_signature":"BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="}`
	ValidSTHResponse_TreeSize          = 3721782
	ValidSTHResponse_Timestamp         = 1396609800587
	ValidSTHResponse_Sha256RootHash    = "SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo="
	ValidSTHResponse_TreeHeadSignature = "BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="
)

// Returns a "variable-length" byte buffer containing |dataSize| data bytes
// along with an appropriate header.
// The buffer format is [header][data]
// where [header] is a bigendian representation of the size of [data].
// sizeof([header]) is the minimum number of bytes necessary to represent
// |dataSize|.
func createVarByteBuf(dataSize uint64) []byte {
	lenBytes := uint64(0)
	for x := dataSize; x > 0; x >>= 8 {
		lenBytes++
	}
	buf := make([]byte, dataSize+lenBytes)
	for t, x := dataSize, uint64(0); x < lenBytes; x++ {
		buf[lenBytes-x-1] = byte(t)
		t >>= 8
	}
	for x := uint64(0); x < dataSize; x++ {
		buf[lenBytes+x] = byte(x)
	}
	return buf
}

func TestCreateVarByteBuf(t *testing.T) {
	buf := createVarByteBuf(56)
	if len(buf) != 56+1 {
		t.Errorf("Wrong buffer size returned, expected %d", 56+1)
	}
	if buf[0] != 56 {
		t.Errorf("Buffer has incorrect size header %02x", buf[0])
	}
	buf = createVarByteBuf(256)
	if len(buf) != 256+2 {
		t.Errorf("Wrong buffer size returned, expected %d", 256+2)
	}
	if buf[0] != 0x01 || buf[1] != 0x00 {
		t.Errorf("Buffer has incorrect size header %02x,%02x", buf[0], buf[1])
	}
	buf = createVarByteBuf(65536)
	if len(buf) != 65536+3 {
		t.Errorf("Wrong buffer size returned, expected %d", 65536+3)
	}
	if buf[0] != 0x01 || buf[1] != 0x00 || buf[2] != 0x00 {
		t.Errorf("Buffer has incorrect size header %02x,%02x,%02x", buf[0], buf[1], buf[2])
	}
}

func TestReadVarBytes(t *testing.T) {
	const BufSize = 453641
	r := createVarByteBuf(BufSize)
	buf, err := readVarBytes(bytes.NewReader(r), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != BufSize {
		t.Fatalf("Incorrect size buffer returned, expected %d, got %d", BufSize, len(buf))
	}
	for i := range buf {
		if buf[i] != byte(i) {
			t.Fatalf("Buffer contents incorrect, expected %02x, got %02x.", byte(i), buf[i])
		}
	}
}

func TestReadVarBytesTooLarge(t *testing.T) {
	_, err := readVarBytes(nil, 9)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatal("readVarBytes didn't fail when trying to read too large a data size: ", err)
	}
}

func TestReadVarBytesZero(t *testing.T) {
	_, err := readVarBytes(nil, 0)
	if err == nil || !strings.Contains(err.Error(), "should be > 0") {
		t.Fatal("readVarBytes didn't fail when trying to read zero length data")
	}
}

func TestReadVarBytesShortRead(t *testing.T) {
	r := make([]byte, 2)
	r[0] = 2 // but only 1 byte available...
	_, err := readVarBytes(bytes.NewReader(r), 1)
	if err == nil || !strings.Contains(err.Error(), "Short read") {
		t.Fatal("readVarBytes didn't fail with a short read")
	}
}

func TestSignedTreeHeadEquals(t *testing.T) {
	sth1 := SignedTreeHead{4, 5, []byte("hash"), []byte("sig")}
	sth2 := SignedTreeHead{4, 5, []byte("hash"), []byte("sig")}
	if !sth1.Equals(sth2) {
		t.Fatal("Should be equal")
	}
}

func TestSignedTreeHeadAreNotEqual(t *testing.T) {
	sth1 := SignedTreeHead{4, 5, []byte("hash"), []byte("sig")}
	sth2 := SignedTreeHead{4, 5, []byte("hash"), []byte("sig")}
	{
		sth2.TreeSize++
		if sth1.Equals(sth2) {
			t.Fatal("TreeSize are different")
		}
		sth2.TreeSize--
	}
	{
		sth2.Timestamp++
		if sth1.Equals(sth2) {
			t.Fatal("Timestamp are different")
		}
		sth2.Timestamp--
	}
	{
		sth2.Sha256RootHash[2]++
		if sth1.Equals(sth2) {
			t.Fatal("Sha256RootHash are different")
		}
		sth2.Sha256RootHash[2]--
	}
	{
		sth2.TreeHeadSignature[2]++
		if sth1.Equals(sth2) {
			t.Fatal("TreeHeadSignature are different")
		}
		sth2.TreeHeadSignature[2]--
	}
}

func TestNewMerkleTreeLeafForPrecert(t *testing.T) {
	entry, err := base64.StdEncoding.DecodeString(PrecertEntryB64)
	if err != nil {
		t.Fatal(err)
	}

	m, err := NewMerkleTreeLeaf(bytes.NewReader(entry))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != V1 {
		t.Fatal("Invalid version number")
	}
	if m.LeafType != TimestampedEntryLeafType {
		t.Fatal("Invalid LeafType")
	}
	if m.TimestampedEntry.EntryType != PrecertLogEntryType {
		t.Fatal("Incorrect EntryType")
	}
}

func TestNewMerkleTreeLeafForX509Cert(t *testing.T) {
	entry, err := base64.StdEncoding.DecodeString(CertEntryB64)
	if err != nil {
		t.Fatal(err)
	}

	m, err := NewMerkleTreeLeaf(bytes.NewReader(entry))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != V1 {
		t.Fatal("Invalid version number")
	}
	if m.LeafType != TimestampedEntryLeafType {
		t.Fatal("Invalid LeafType")
	}
	if m.TimestampedEntry.EntryType != X509LogEntryType {
		t.Fatal("Incorrect EntryType")
	}
}

func TestNewMerkleTreeLeafChecksVersion(t *testing.T) {
	buffer := []byte{1}
	_, err := NewMerkleTreeLeaf(bytes.NewReader(buffer))
	if err == nil || !strings.Contains(err.Error(), "Unknown Version") {
		t.Fatal("Failed to check Version - accepted 1")
	}
}

func TestNewMerkleTreeLeafChecksLeafType(t *testing.T) {
	buffer := []byte{0, 0x12, 0x34}
	_, err := NewMerkleTreeLeaf(bytes.NewReader(buffer))
	if err == nil || !strings.Contains(err.Error(), "Unknown LeafType") {
		t.Fatal("Failed to check LeafType - accepted 0x1234")
	}
}

func TestTimestampedEntryParseChecksEntryType(t *testing.T) {
	buffer := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0x45, 0x45}
	var tse TimestampedEntry
	err := tse.parse(bytes.NewReader(buffer))
	if err == nil || !strings.Contains(err.Error(), "Unknown EntryType") {
		t.Fatal("Failed to check EntryType - accepted 0x4545")
	}
}

func TestGetEntriesWorks(t *testing.T) {
	positiveDecimalNumber := regexp.MustCompile("[0-9]+")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ct/v1/get-entries" {
			t.Fatalf("Incorrect URL path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q["start"] == nil {
			t.Fatal("Missing 'start' parameter")
		}
		if !positiveDecimalNumber.MatchString(q["start"][0]) {
			t.Fatal("Invalid 'start' parameter: " + q["start"][0])
		}
		if q["end"] == nil {
			t.Fatal("Missing 'end' parameter")
		}
		if !positiveDecimalNumber.MatchString(q["end"][0]) {
			t.Fatal("Invalid 'end' parameter: " + q["end"][0])
		}
		fmt.Fprintf(w, `{"entries":[{"leaf_input": "%s", "extra_data": ""}, {"leaf_input": "%s", "extra_data": ""}]}`, PrecertEntryB64, CertEntryB64)
	}))
	defer ts.Close()

	client := New(ts.URL)
	leaves, err := client.GetEntries(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 2 {
		t.Fatal("Incorrect number of leaves returned")
	}
}

func TestGetSTHWorks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ct/v1/get-sth" {
			t.Fatalf("Incorrect URL path: %s", r.URL.Path)
		}
		fmt.Fprintf(w, `{"tree_size": %d, "timestamp": %d, "sha256_root_hash": "%s", "tree_head_signature": "%s"}`,
			ValidSTHResponse_TreeSize, ValidSTHResponse_Timestamp, ValidSTHResponse_Sha256RootHash,
			ValidSTHResponse_TreeHeadSignature)
	}))
	defer ts.Close()

	client := New(ts.URL)
	sth, err := client.GetSTH()
	if err != nil {
		t.Fatal(err)
	}
	if sth.TreeSize != ValidSTHResponse_TreeSize {
		t.Fatal("Invalid tree size")
	}
	if sth.Timestamp != ValidSTHResponse_Timestamp {
		t.Fatal("Invalid Timestamp")
	}
	hash, err := base64.StdEncoding.DecodeString(ValidSTHResponse_Sha256RootHash)
	if err != nil {
		t.Fatal("Couldn't b64 decode 'correct' STH root hash!")
	}
	if string(sth.Sha256RootHash) != string(hash) {
		t.Fatal("Invalid Sha256RootHash")
	}
	sig, err := base64.StdEncoding.DecodeString(ValidSTHResponse_TreeHeadSignature)
	if err != nil {
		t.Fatal("Couldn't b64 decode 'correct' STH signature!")
	}
	if string(sth.TreeHeadSignature) != string(sig) {
		t.Fatal("Invalid TreeHeadSignature")
	}
}

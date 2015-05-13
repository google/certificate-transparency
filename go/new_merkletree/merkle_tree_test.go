package new_merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"log"
	"reflect"
	"testing"
)

/* DummyDAO is a NewMerkleTree DAO type which simply returns an uppercase character
 * for each leaf in the tree.  For obvious reasons, this makes it a little tricky
 * to support trees larger than 26 leaves, but for testing purposes that shouldn't
 * be a terrible burden.
 */
type DummyDAO struct {
	NewMerkleTreeDataInterface

	vals []byte
}

func NewDummyDAO(size int) *DummyDAO {
	dao := new(DummyDAO)
	dao.vals = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")[0:size]
	return dao
}

func (dao DummyDAO) EntryAt(i uint64) ([]byte, error) {
	return dao.vals[i : i+1], nil
}

func (dao DummyDAO) Size() uint64 {
	return uint64(len(dao.vals))
}

/* NullHash is a stupidly simple "hash" algorithm that simply returns its input
 * as the output.  Why is this useful?  Testing.
 */
type NullHash struct {
	hash.Hash

	s []byte
}

func (h *NullHash) Write(p []byte) (int, error) {
	h.s = bytes.Join([][]byte{h.s, p}, []byte{})
	return len(p), nil
}

func (h *NullHash) Sum(b []byte) []byte {
	return bytes.Join([][]byte{h.s, b}, []byte{})
}

func (h *NullHash) Reset() {
	h.s = []byte{}
}

func (h *NullHash) Size() int {
	return len(h.s)
}

func (h *NullHash) BlockSize() int {
	return 1
}

// Real testing methods start here.

func TestNew(t *testing.T) {
	// The explicit type declaration here is deliberate, to make absolutely
	// sure that `New` is returning a `NewMerkleTree`.
	var tree *NewMerkleTree
	if tree = New(nil, nil, sha256.New); tree == nil {
		t.Fail()
	}
}

func TestEmptyTree(t *testing.T) {
	// Let's use sha256 for this one, just to show we can
	tree := New(NewDummyDAO(0), nil, sha256.New)

	actual, err := tree.CurrentRoot()
	expect, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	if err != nil {
		t.Fatalf("CurrentRoot() returned error: %v", err)
	}

	if bytes.Compare(actual, expect) != 0 {
		t.Fatalf("Incorrect root value\nexpected:\n%v\ngot:\n%v", hex.Dump(expect), hex.Dump(actual))
	}
}

func rootForTestLeaves(numLeaves int) Hash {
	switch numLeaves {
	case 0:
		return []byte("")
	case 1:
		return []byte("\x00A")
	case 2:
		return []byte("\x01\x00A\x00B")
	case 3:
		return []byte("\x01\x01\x00A\x00B\x00C")
	case 4:
		return []byte("\x01\x01\x00A\x00B\x01\x00C\x00D")
	case 5:
		return []byte("\x01\x01\x01\x00A\x00B\x01\x00C\x00D\x00E")
	case 6:
		return []byte("\x01\x01\x01\x00A\x00B\x01\x00C\x00D\x01\x00E\x00F")
	case 7:
		return []byte("\x01\x01\x01\x00A\x00B\x01\x00C\x00D\x01\x01\x00E\x00F\x00G")
	default:
		log.Fatalf("Unexpected numLeaves: %v", numLeaves)
		return nil
	}
}

func TestAddLeaf(t *testing.T) {
	for i := 0; i < 8; i++ {
		dao := NewDummyDAO(i)
		tree := New(dao, nil, func() hash.Hash { return new(NullHash) })
		r, err := tree.CurrentRoot()

		if err != nil {
			t.Fatalf("CurrentRoot() for i=%v returned error: %v", i, err)
		}

		if bytes.Compare(r, rootForTestLeaves(i)) != 0 {
			t.Fatalf("Incorrect CurrentRoot (index=%v).\ngot:\n%v\nexpected:\n%v\n", i, hex.Dump(r), hex.Dump(rootForTestLeaves(i)))
		}
	}
}

func checkPath(t *testing.T, m *NewMerkleTree, index uint64, expectedPath []Hash) {
	path, err := m.InclusionProof(index)
	if err != nil {
		t.Fatalf("InclusionProof(%v) returned error: %v", index, err)
	}
	if !reflect.DeepEqual(path, expectedPath) {
		actual_path := []string{}
		for _, e := range path {
			actual_path = append(actual_path, hex.EncodeToString(e))
		}

		expected_path := []string{}
		for _, e := range expectedPath {
			expected_path = append(expected_path, hex.EncodeToString(e))
		}

		t.Fatalf("Incorrect path returned for leaf@%d:\n%v\nexpected:\n%v", index, actual_path, expected_path)
	}
}

func TestInclusionProof(t *testing.T) {
	// Test data as per RFC6962, s2.1.3
	m := New(NewDummyDAO(7), nil, func() hash.Hash { return new(NullHash) })

	pathToOne := []Hash{
		[]byte("\x00A"), []byte("\x01\x00C\x00D"), []byte("\x01\x01\x00E\x00F\x00G")}
	pathToSix := []Hash{
		[]byte("\x01\x00E\x00F"), []byte("\x01\x01\x00A\x00B\x01\x00C\x00D")}

	checkPath(t, m, 1, pathToOne)
	checkPath(t, m, 6, pathToSix)
}

func checkError(t *testing.T, err error, msg string) {
	if err == nil {
		t.Fatalf("No error returned.\nExpected: %v", msg)
	}

	if err.Error() != msg {
		t.Fatalf("Incorrect error message.\nExpected: %v\nGot: %v", msg, err.Error())
	}
}

func TestInclusionProofOnEmptyTree(t *testing.T) {
	m := New(NewDummyDAO(0), nil, func() hash.Hash { return new(NullHash) })

	_, err := m.InclusionProof(0)

	checkError(t, err, "NewMerkleTree: Can't calculate an inclusion proof on an empty tree")
}

func TestInclusionProofOfInvalidLeaf(t *testing.T) {
	m := New(NewDummyDAO(2), nil, func() hash.Hash { return new(NullHash) })

	_, err := m.InclusionProof(2)

	checkError(t, err, "NewMerkleTree: Invalid leaf index: 2")
}

func checkConsistency(t *testing.T, m *NewMerkleTree, from, to uint64, expectedProof []Hash) {
	proof, err := m.ConsistencyProof(from, to)
	if err != nil {
		t.Fatalf("ConsistencyProof(%v, %v) returned error: %v", from, to, err)
	}
	if !reflect.DeepEqual(proof, expectedProof) {
		t.Fatalf("Incorrect proof returned for consistency %d to %d:\n%v\nexpected:\n%v", from, to, proof, expectedProof)
	}
}

func TestConsistencyProof(t *testing.T) {
	m := New(NewDummyDAO(8), nil, func() hash.Hash { return new(NullHash) })

	zeroToSeven := []Hash{}
	sevenToSeven := []Hash{}
	threeToSeven := []Hash{Hash("\x00C"), Hash("\x00D"), Hash("\x01\x00A\x00B"), Hash("\x01\x01\x00E\x00F\x00G")}
	fourToSeven := []Hash{Hash("\x01\x01\x00E\x00F\x00G")}
	sixToSeven := []Hash{Hash("\x01\x00E\x00F"), Hash("\x00G"), Hash("\x01\x01\x00A\x00B\x01\x00C\x00D")}
	twoToFive := []Hash{Hash("\x01\x00C\x00D"), Hash("\x00E")}
	sixToEight := []Hash{Hash("\x01\x00E\x00F"), Hash("\x01\x00G\x00H"), Hash("\x01\x01\x00A\x00B\x01\x00C\x00D")}

	checkConsistency(t, m, 0, 7, zeroToSeven)
	checkConsistency(t, m, 7, 7, sevenToSeven)
	checkConsistency(t, m, 3, 7, threeToSeven)
	checkConsistency(t, m, 4, 7, fourToSeven)
	checkConsistency(t, m, 6, 7, sixToSeven)
	checkConsistency(t, m, 2, 5, twoToFive)
	checkConsistency(t, m, 6, 8, sixToEight)

	_, err := m.ConsistencyProof(1, 9)
	checkError(t, err, "NewMerkleTree.ConsistencyProof: Value for 'to' greater than tree size (to=9, tree size=8)")

	_, err = m.ConsistencyProof(2, 0)
	checkError(t, err, "NewMerkleTree.ConsistencyProof: 'to' greater than 'from'")
}

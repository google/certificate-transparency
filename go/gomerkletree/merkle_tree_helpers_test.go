package gomerkletree

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func checkCurrentRoot(t *testing.T, tree *MerkleTree, treeSize int, expected Hash) {
	r, err := tree.CurrentRoot()

	if err != nil {
		t.Fatalf("CurrentRoot() for treeSize=%v returned error: %v", treeSize, err)
	}

	if bytes.Compare(r, expected) != 0 {
		t.Fatalf("Incorrect CurrentRoot (index=%v).\ngot:\n%v\nexpected:\n%v\n", treeSize, hex.Dump(r), hex.Dump(expected))
	}
}

func checkPath(t *testing.T, m *MerkleTree, index uint64, expectedPath []Hash) {
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

func checkError(t *testing.T, err error, msg string) {
	if err == nil {
		t.Fatalf("No error returned.\nExpected: %v", msg)
	}

	if err.Error() != msg {
		t.Fatalf("Incorrect error message.\nExpected: %v\nGot: %v", msg, err.Error())
	}
}

func checkConsistency(t *testing.T, m *MerkleTree, from, to uint64, expectedProof []Hash) {
	proof, err := m.ConsistencyProof(from, to)
	if err != nil {
		t.Fatalf("ConsistencyProof(%v, %v) returned error: %v", from, to, err)
	}
	if !reflect.DeepEqual(proof, expectedProof) {
		actual_proof := []string{}
		for _, e := range proof {
			actual_proof = append(actual_proof, hex.EncodeToString(e))
		}

		expected_proof := []string{}
		for _, e := range expectedProof {
			expected_proof = append(expected_proof, hex.EncodeToString(e))
		}

		t.Fatalf("Incorrect proof returned for consistency %d to %d:\n%v\nexpected:\n%v", from, to, actual_proof, expected_proof)
	}
}


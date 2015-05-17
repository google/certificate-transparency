package gomerkletree

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"testing"
)

func TestNew(t *testing.T) {
	// The explicit type declaration here is deliberate, to make absolutely
	// sure that `New` is returning a `MerkleTree`.
	var tree *MerkleTree
	if tree = New(nil, nil, sha256.New); tree == nil {
		t.Fail()
	}
}



func TestEmptyTree(t *testing.T) {
	tree := New(newTestDAO(0), nil, sha256.New)

	expect, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	checkCurrentRoot(t, tree, 0, expect)
}

func TestInclusionProofOnEmptyTree(t *testing.T) {
	m := New(newTestDAO(0), nil, sha256.New)

	_, err := m.InclusionProof(0)

	checkError(t, err, "MerkleTree: Can't calculate an inclusion proof on an empty tree")
}

func TestInclusionProofOfInvalidLeaf(t *testing.T) {
	m := New(newTestDAO(2), nil, sha256.New)

	_, err := m.InclusionProof(2)

	checkError(t, err, "MerkleTree: Invalid leaf index: 2")
}

func TestCurrentRoot(t *testing.T) {
	for i := 1; i < 9; i++ {
		dao  := newTestDAO(i)
		tree := New(dao, nil, sha256.New)

		checkCurrentRoot(t, tree, i, rootForTestDAOLeaves(i));
	}
}

func TestInclusionProof(t *testing.T) {
	m := New(newTestDAO(8), nil, sha256.New)

	pathToZero := []Hash{
		mustDecode("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
		mustDecode("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
		mustDecode("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4")}
	pathToFive := []Hash{
		mustDecode("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
		mustDecode("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
		mustDecode("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7")}

	checkPath(t, m, 0, pathToZero)
	checkPath(t, m, 5, pathToFive)
}

func TestConsistencyProof(t *testing.T) {
	m := New(newTestDAO(8), nil, sha256.New)

	oneToEight := []Hash{
		mustDecode("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
		mustDecode("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
		mustDecode("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4")}
	sixToEight := []Hash{
		mustDecode("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a"),
		mustDecode("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
		mustDecode("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7")}
	twoToFive := []Hash{
		mustDecode("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
		mustDecode("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b")}

	checkConsistency(t, m, 1, 8, oneToEight)
	checkConsistency(t, m, 6, 8, sixToEight)
	checkConsistency(t, m, 2, 5, twoToFive)
}



// Hex decodes |s| and returns the result.
// If the decode fails logs a fatal error
func mustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// Returns the the expected root hash for a tree which has had the first
// |numLeaves| of |testDAOLeaves| added to it, in order.
// Logs a fatal error if |numLeaves| is too large.
func rootForTestDAOLeaves(numLeaves int) []byte {
	switch numLeaves {
	case 1:
		return mustDecode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
	case 2:
		return mustDecode("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125")
	case 3:
		return mustDecode("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77")
	case 4:
		return mustDecode("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7")
	case 5:
		return mustDecode("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4")
	case 6:
		return mustDecode("76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef")
	case 7:
		return mustDecode("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c")
	case 8:
		return mustDecode("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328")
	default:
		log.Fatalf("Unexpected numLeaves %d", numLeaves)
	}
	return nil
}

/* testDAO is a MerkleTree DAO type which returns known test data. */
type testDAO struct {
	MerkleTreeDataInterface

	vals [][]byte
}

var testDAOLeaves [][]byte = [][]byte {
	{},
	{0x00},
	{0x10},
	{0x20, 0x21},
	{0x30, 0x31},
	{0x40, 0x41, 0x42, 0x43},
	{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
	{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f},
}

/* Create a new testDAO instance, with the first |size| leaves of data
 * available.
 */
func newTestDAO(size int) *testDAO {
	dao := new(testDAO)
	dao.vals = testDAOLeaves[0:size]
	return dao
}

func (dao testDAO) EntryAt(i uint64) ([]byte, error) {
	return dao.vals[i], nil
}

func (dao testDAO) Size() uint64 {
	return uint64(len(dao.vals))
}

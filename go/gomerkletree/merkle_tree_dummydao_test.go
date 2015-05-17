package gomerkletree

import (
	"bytes"
	"hash"
	"log"
	"testing"
)

func rootForDummyDAOLeaves(numLeaves int) Hash {
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

func TestDummyDAOCurrentRoot(t *testing.T) {
	for i := 0; i < 8; i++ {
		dao := newDummyDAO(i)
		tree := New(dao, nil, func() hash.Hash { return new(nullHash) })

		checkCurrentRoot(t, tree, i, rootForDummyDAOLeaves(i));
	}
}

func TestDummyDAOInclusionProof(t *testing.T) {
	m := New(newDummyDAO(7), nil, func() hash.Hash { return new(nullHash) })

	pathToOne := []Hash{
		Hash("\x00A"), Hash("\x01\x00C\x00D"), Hash("\x01\x01\x00E\x00F\x00G")}
	pathToSix := []Hash{
		Hash("\x01\x00E\x00F"), Hash("\x01\x01\x00A\x00B\x01\x00C\x00D")}

	checkPath(t, m, 1, pathToOne)
	checkPath(t, m, 6, pathToSix)
}

func TestDummyDAOConsistencyProof(t *testing.T) {
	m := New(newDummyDAO(8), nil, func() hash.Hash { return new(nullHash) })

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
	checkError(t, err, "MerkleTree.ConsistencyProof: Value for 'to' greater than tree size (to=9, tree size=8)")

	_, err = m.ConsistencyProof(2, 0)
	checkError(t, err, "MerkleTree.ConsistencyProof: 'to' greater than 'from'")
}

/* dummyDAO is a MerkleTree DAO type which simply returns an uppercase character
 * for each leaf in the tree.  For obvious reasons, this makes it a little tricky
 * to support trees larger than 26 leaves, but for testing purposes that shouldn't
 * be a terrible burden.
 */
type dummyDAO struct {
	MerkleTreeDataInterface

	vals []byte
}

func newDummyDAO(size int) *dummyDAO {
	dao := new(dummyDAO)
	dao.vals = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")[0:size]
	return dao
}

func (dao dummyDAO) EntryAt(i uint64) ([]byte, error) {
	return dao.vals[i : i+1], nil
}

func (dao dummyDAO) Size() uint64 {
	return uint64(len(dao.vals))
}

/* nullHash is a stupidly simple "hash" algorithm that simply returns its input
 * as the output.  Why is this useful?  Testing.
 */
type nullHash struct {
	hash.Hash

	s []byte
}

func (h *nullHash) Write(p []byte) (int, error) {
	h.s = bytes.Join([][]byte{h.s, p}, []byte{})
	return len(p), nil
}

func (h *nullHash) Sum(b []byte) []byte {
	return bytes.Join([][]byte{h.s, b}, []byte{})
}

func (h *nullHash) Reset() {
	h.s = []byte{}
}

func (h *nullHash) Size() int {
	return len(h.s)
}

func (h *nullHash) BlockSize() int {
	return 1
}


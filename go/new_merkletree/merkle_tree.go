package new_merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"math"
)

// New creates a new merkle hash tree.  The number of "leaves" of the tree,
// as well as their contents, are retrieved through |dao|.  If you wish to
// have acceptable performance on non-trivial tree sizes, you'll want to
// provide |cache| (otherwise, pass `nil`).  The hash function used for all
// nodes in the tree is specified by |hasher|.
func New(dao NewMerkleTreeDataInterface, cache NewMerkleTreeCacheInterface, hasher hash.Hash) *NewMerkleTree {
	return &NewMerkleTree{dao: dao, cache: cache, hasher: hasher}
}

func (mt NewMerkleTree) CurrentRoot() (Hash, error) {
	if mt.dao.Size() == 0 {
		// Special case: empty trees get hashes of empty strings
		mt.hasher.Reset()
		return mt.hasher.Sum([]byte{}), nil
	} else {
		return mt.subtreeRoot(0, mt.dao.Size()-1)
	}
}

func (mt NewMerkleTree) InclusionProof(leaf uint64) ([]Hash, error) {
	if mt.dao.Size() == 0 {
		return nil, errors.New("NewMerkleTree: Can't calculate an inclusion proof on an empty tree")
	}

	if leaf >= mt.dao.Size() {
		return nil, fmt.Errorf("NewMerkleTree: Invalid leaf entry ID: %v", leaf)
	}

	return mt.inclusionSubtree(leaf, 0, mt.dao.Size()-1)
}

func (mt NewMerkleTree) ConsistencyProof(from, to uint64) ([]Hash, error) {
	if from == 0 {
		// There's no algorithmic basis for this that I know of, but it is how
		// existing implementations do it
		return []Hash{}, nil
	}

	if to > mt.dao.Size() {
		return nil, fmt.Errorf("NewMerkleTree.ConsistencyProof: Value for 'to' greater than tree size (to=%v, tree size=%v)", to, mt.dao.Size())
	}

	if from > to {
		return nil, fmt.Errorf("NewMerkleTree.ConsistencyProof: 'to' greater than 'from'")
	}

	return mt.subproof(from, 0, to-1, true)
}

func (mt NewMerkleTree) hash(s []byte) Hash {
	mt.hasher.Reset()
	mt.hasher.Write(s)
	return mt.hasher.Sum([]byte{})
}

func (mt NewMerkleTree) leafHash(s []byte) Hash {
	return mt.hash(bytes.Join([][]byte{{0x0}, s}, []byte{}))
}

func (mt NewMerkleTree) nodeHash(h1, h2 Hash) Hash {
	return mt.hash(bytes.Join([][]byte{{0x1}, h1, h2}, []byte{}))
}

func (mt NewMerkleTree) subtreeRoot(n1, n2 uint64) (Hash, error) {
	if n1 == n2 {
		l, err := mt.dao.EntryAt(n1)
		if err != nil {
			return nil, err
		}
		return mt.leafHash(l), nil
	} else {
		pivot := largestPowerOfTwoLessThan(n2 - n1 + 1)

		s1, err1 := mt.subtreeRoot(n1, n1+pivot-1)
		if err1 != nil {
			return nil, err1
		}

		s2, err2 := mt.subtreeRoot(n1+pivot, n2)
		if err2 != nil {
			return nil, err2
		}

		return mt.nodeHash(s1, s2), nil
	}
}

func (mt NewMerkleTree) inclusionSubtree(leaf, n1, n2 uint64) ([]Hash, error) {
	if n1 == n2 {
		// Inclusion proof of a single element is the empty list
		return []Hash{}, nil
	} else {
		pivot := largestPowerOfTwoLessThan(n2 - n1 + 1)

		if leaf < pivot {
			h, err := mt.subtreeRoot(n1+pivot, n2)
			if err != nil {
				return nil, err
			}

			sp, err := mt.inclusionSubtree(leaf, n1, n1+pivot-1)
			if err != nil {
				return nil, err
			}

			return append(sp, h), nil
		} else {
			h, err := mt.subtreeRoot(n1, n1+pivot-1)
			if err != nil {
				return nil, err
			}

			sp, err := mt.inclusionSubtree(n1+leaf-pivot, n1+pivot, n2)
			if err != nil {
				return nil, err
			}

			return append(sp, h), nil
		}
	}
}

func largestPowerOfTwoLessThan(n uint64) uint64 {
	if n < 2 {
		panic("Can't calculate tiny powers of two")
	} else {
		return uint64(math.Floor(math.Pow(2, math.Floor(math.Log2(float64(n)-1)))))
	}
}

func (mt NewMerkleTree) subproof(from, t1, t2 uint64, b bool) ([]Hash, error) {
	if t2 == from-1 {
		if b {
			return []Hash{}, nil
		} else {
			h, err := mt.subtreeRoot(t1, t2)

			return []Hash{h}, err
		}
	} else if t1 == t2 {
		h, err := mt.subtreeRoot(t1, t2)
		return []Hash{h}, err
	} else {
		pivot := largestPowerOfTwoLessThan(t2 - t1 + 1)
		var (
			sp            []Hash
			h             Hash
			err_sp, err_h error
		)

		if from <= pivot+t1 {
			sp, err_sp = mt.subproof(from, t1, t1+pivot-1, b)
			h, err_h = mt.subtreeRoot(t1+pivot, t2)
		} else {
			sp, err_sp = mt.subproof(from, t1+pivot, t2, false)
			h, err_h = mt.subtreeRoot(t1, t1+pivot-1)
		}

		if err_sp != nil {
			return nil, err_sp
		}
		if err_h != nil {
			return nil, err_h
		}
		return append(sp, h), nil
	}
}

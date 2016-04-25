package merkletree

import (
	"hash"
)

const (
	// LeafPrefix is the domain separation prefix for leaf hashes.
	LeafPrefix = 0

	// NodePrefix is the domain separation prefix for internal tree nodes.
	NodePrefix = 1
)

// TreeHasher performs the various hashing operations required when manipulating MerkleTrees.
type TreeHasher struct {
	hasher hash.Hash
}

// NewTreeHasher returns a new TreeHasher based on the passed in hash.
func NewTreeHasher(h hash.Hash) *TreeHasher {
	return &TreeHasher{
		hasher: h,
	}
}

// DigestSize returns the size in bytes of the underlying hash.
func (h TreeHasher) DigestSize() int {
	return h.hasher.Size()
}

// HashEmpty returns the hash of the empty string.
func (h TreeHasher) HashEmpty() []byte {
	h.hasher.Reset()
	return h.hasher.Sum([]byte{})
}

// HashLeaf returns the hash of the passed in leaf, after applying domain separation.
func (h TreeHasher) HashLeaf(leaf []byte) []byte {
	h.hasher.Reset()
	h.hasher.Write([]byte{LeafPrefix})
	return h.hasher.Sum(leaf)

}

// HashChildren returns the merkle hash of the two passed in children.
func (h TreeHasher) HashChildren(left, right []byte) []byte {
	h.hasher.Reset()
	h.hasher.Write([]byte{NodePrefix})
	h.hasher.Write(left)
	return h.hasher.Sum(right)
}

package new_merkletree

type Hash []byte

// NewMerkleTreeDataInterface defines the means by which a merkle hash tree can
// retrieve data from an arbitrary data store, without tying the tree
// implementation to any particular backend storage technology.
type NewMerkleTreeDataInterface interface {
	// EntryAt takes a (0-based) |index| into the list of leaf entries in
	// the tree, and returns the contents of the leaf.  For a given
	// |index| in a given tree, the value returned **MUST NOT** ever
	// change, or the whole point of a merkle tree is defeated.
	EntryAt(index uint64) ([]byte, error)

	// Size returns the number of entries currently in the tree.  The
	// value returned by this function must never decrease between
	// calls; it is OK for the value to increase over time.
	Size() uint64
}

// NewMerkleTreeCacheInterface provides a means for a merkle tree to cache
// hash values in the tree.  Whilst all hash values *can* be recalculated
// on the fly, it is far more efficient to be able to cache recently-used
// values, to avoid needing to rehash everything.
type NewMerkleTreeCacheInterface interface {
	GetNode([]byte) Hash
	SetNode([]byte, Hash)
}

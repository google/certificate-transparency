package new_merkletree

type Hash []byte

// NewMerkleTreeInterface is the set of methods which are required to
// manipulate the contents of a Merkle Hash Tree (that is, add new entries),
// and to query the tree for inclusion and transparency proofs.
type NewMerkleTreeInterface interface {
	// CurrentRootHash returns the hash of the entire current tree.
	CurrentRootHash() (Hash, error)

	// InclusionProof returns a list of the hashes of the "sibling"
	// nodes to the leaf entry located at the (0-based) index specified.
	// The returned list is presented in order, starting from the
	// sibling to the item itself, and ending with a hash that is an
	// immediate child of the root.
	InclusionProof(entry uint64) ([]Hash, error)

	// ConsistencyProof returns a list of the hashes that make up the
	// consistency proof between the hash trees with size |tree1| and
	// |tree2|.
	ConsistencyProof(tree1 uint64, tree2 uint64) ([]Hash, error)
}

// NewMerkleTreeDataInterface defines the means by which a merkle hash tree can
// retrieve data from an arbitrary data store, without tying the tree
// implementation to any particular backend storage technology.
type NewMerkleTreeDataInterface interface {
	// EntryAt takes a (0-based) |index| into the list of leaf entries in
	// the tree, and returns the contents of the leaf.  For a given
	// |index| in a given tree, the value returned **MUST NOT** ever
	// change, or the whole point of a merkle tree is defeated.
	EntryAt func (index uint64) []byte

	// Size returns the number of entries currently in the tree.  The
	// value returned by this function must never decrease between
	// calls; it is OK for the value to increase over time.
	Size func () uint64
}

// NewMerkleTreeCacheInterface provides a means for a merkle tree to cache
// hash values in the tree.  Whilst all hash values *can* be recalculated
// on the fly, it is far more efficient to be able to cache recently-used
// values, to avoid needing to rehash everything.
type NewMerkleTreeCacheInterface interface {
	GetNode func ([]byte) Hash
	SetNode func ([]byte, Hash)
}

type NewMerkleTree struct {
	// If a merkle tree you wish to be, you must implement these
	// functions three.
	NewMerkleTreeInterface

	dao   *NewMerkleTreeDataInterface
	cache *NewMerkleTreeCacheInterface

	hasher func ([]byte) []byte
}

// New creates a new merkle hash tree.  The number of "leaves" of the tree,
// as well as their contents, are retrieved through |dao|.  If you wish to
// have acceptable performance on non-trivial tree sizes, you'll want to
// provide |cache| (otherwise, pass `nil`).  The hash function used for all
// nodes in the tree is specified by |hasher|.
func New(dao *NewMerkleTreeDataInterface, cache *NewMerkleTreeCacheInterface, hasher func ([]byte) []byte) *NewMerkleTree {
}

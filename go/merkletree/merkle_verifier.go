package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
)

// MerkleVerifier is a class which knows how to verify merkle inclusion and consistency proofs.
type MerkleVerifier struct {
	treeHasher *TreeHasher
}

// NewMerkleVerifier returns a new MerkleVerifier for a tree based on the passed in hasher.
func NewMerkleVerifier(h hash.Hash) MerkleVerifier {
	return MerkleVerifier{
		treeHasher: NewTreeHasher(h),
	}
}

// VerifyInclusionProof verifies the correctness of the passed in proof given the passed in information about the tree and leaf.
func (m MerkleVerifier) VerifyInclusionProof(leafIndex, treeSize int64, proof [][]byte, root []byte, data []byte) error {
	calcRoot, err := m.RootFromInclusionProof(leafIndex, treeSize, proof, data)
	if err != nil {
		return err
	}
	if len(calcRoot) == 0 {
		panic(errors.New("calculated empty root"))
	}
	if bytes.Compare(calcRoot, root) != 0 {
		return fmt.Errorf("calculated root:\n%v\n does not match provided root:\n%s", calcRoot, root)
	}
	return nil
}

// RootFromInclusionProof calculates the expected tree root given the proof and leaf.
func (m MerkleVerifier) RootFromInclusionProof(leafIndex, treeSize int64, proof [][]byte, data []byte) ([]byte, error) {
	if leafIndex > treeSize {
		return nil, fmt.Errorf("leafIndex %d > treeSize %d", leafIndex, treeSize)
	}
	if leafIndex == 0 {
		return nil, errors.New("leafIndex is zero")
	}

	node := leafIndex - 1
	lastNode := treeSize - 1
	nodeHash := m.treeHasher.HashLeaf(data)
	proofIndex := 0

	for lastNode > 0 {
		if proofIndex == len(proof) {
			return nil, fmt.Errorf("insuficient number of proof components (%d) for treeSize %d", len(proof), treeSize)
		}
		if isRightChild(node) {
			nodeHash = m.treeHasher.HashChildren(proof[proofIndex], nodeHash)
			proofIndex++
		} else if node < lastNode {
			nodeHash = m.treeHasher.HashChildren(nodeHash, proof[proofIndex])
			proofIndex++
		} else {
			// the sibling does not exist and the parent is a dummy copy; do nothing.
		}
		node = parent(node)
		lastNode = parent(lastNode)
	}
	if proofIndex != len(proof) {
		return nil, fmt.Errorf("invalid proof, expected %d components, but have %d", proofIndex, len(proof))
	}
	return nodeHash, nil
}

// VerifyConsistencyProof checks that the passed in consistency proof is valid between the passed in tree snapshots.
func (m MerkleVerifier) VerifyConsistencyProof(snapshot1, snapshot2 int64, root1, root2 []byte, proof [][]byte) error {
	if snapshot1 > snapshot2 {
		return fmt.Errorf("snapshot1 (%d) > snapshot2 (%d)", snapshot1, snapshot2)
	}
	if snapshot1 == snapshot2 {
		if len(root1) == 0 {
			return errors.New("invalid empty root1")
		}
		if bytes.Compare(root1, root2) != 0 {
			return fmt.Errorf("root1:\n%v\ndoes not match root2:\n%v", root1, root2)
		}
		if len(proof) != 0 {
			return fmt.Errorf("root1 and root2 match, but proof is non-empty")
		}
		// proof ok
		return nil
	}

	if len(proof) == 0 {
		return errors.New("empty proof")
	}

	node := snapshot1 - 1
	lastNode := snapshot2 - 1
	proofIndex := 0

	for isRightChild(node) {
		node = parent(node)
		lastNode = parent(lastNode)
	}

	var node1Hash []byte
	var node2Hash []byte

	if node > 0 {
		node1Hash = proof[proofIndex]
		node2Hash = proof[proofIndex]
	} else {
		// The tree at snapshot1 was balanced, nothing to verify for root1.
		node1Hash = root1
		node2Hash = root1
	}

	for node > 0 {
		if proofIndex == len(proof) {
			return errors.New("insufficient number of proof components")
		}

		if isRightChild(node) {
			node1Hash = m.treeHasher.HashChildren(proof[proofIndex], node1Hash)
			node2Hash = m.treeHasher.HashChildren(proof[proofIndex], node2Hash)
			proofIndex++
		} else if node < lastNode {
			// The sibling only exists in the later tree. The parent in the snapshot1 tree is a dummy copy.
			node2Hash = m.treeHasher.HashChildren(node2Hash, proof[proofIndex])
		} else {
			// Else the sibling does not exist in either tree. Do nothing.
		}

		node = parent(node)
		lastNode = parent(lastNode)
	}

	// Verify the first root.
	if bytes.Compare(node1Hash, root1) != 0 {
		return fmt.Errorf("failed to verify root1:\n%v\ncalculated root of:\n%v\nfrom proof", root1, node1Hash)
	}

	for lastNode > 0 {
		if proofIndex == len(proof) {
			return errors.New("can't verify newer root; insufficient number of proof components")
		}

		node2Hash = m.treeHasher.HashChildren(node2Hash, proof[proofIndex])
		proofIndex++
		lastNode = parent(lastNode)
	}

	// Verify the second root.
	if bytes.Compare(node2Hash, root2) != 0 {
		return fmt.Errorf("failed to verify root2:\n%v\ncalculated root of:\n%v\nfrom proof", root2, node2Hash)
	}
	if proofIndex != len(proof) {
		return errors.New("proof has too many components")
	}

	// proof ok
	return nil
}

func parent(leafIndex int64) int64 {
	return leafIndex >> 1
}

func isRightChild(leafIndex int64) bool {
	return leafIndex&1 == 1
}

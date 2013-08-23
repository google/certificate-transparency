"""Merkle trees."""

import hashlib
import logging

from ct.crypto import error


class TreeHasher(object):
    """Merkle hasher with domain separation for leaves and nodes."""

    def __init__(self, hashfunc=hashlib.sha256):
        self.hashfunc = hashfunc

    def __repr__(self):
        return "%r(hash function: %r)" % (self.__class__.__name__,
                                          self.hashfunc)

    def __str__(self):
        return "%s(hash function: %s)" % (self.__class__.__name__,
                                          self.hashfunc)

    def hash_empty(self):
        hasher = self.hashfunc()
        return hasher.digest()

    def hash_leaf(self, data):
        hasher = self.hashfunc()
        hasher.update("\x00" + data)
        return hasher.digest()

    def hash_children(self, left, right):
        hasher = self.hashfunc()
        hasher.update("\x01" + left + right)
        return hasher.digest()


class MerkleVerifier(object):
    """A utility class for doing Merkle path computations."""

    def __init__(self, hasher=TreeHasher()):
        self.hasher = hasher

    def __repr__(self):
        return "%r(hasher: %r)" % (self.__class__.__name__, self.hasher)

    def __str__(self):
        return "%s(hasher: %s)" % (self.__class__.__name__, self.hasher)

    @error.returns_true_or_raises
    def verify_tree_consistency(self, old_tree_size, new_tree_size, old_root,
                                new_root, proof):
        """Verify the consistency between two root hashes.

        old_tree_size must be <= new_tree_size.

        Args:
            old_tree_size: size of the older tree.
            new_tree_size: size of the newer_tree.
            old_root: the root hash of the older tree.
            new_root: the root hash of the newer tree.
            proof: the consistency proof.

        Returns:
            True. The return value is enforced by a decorator and need not be
                checked by the caller.

        Raises:
            ConsistencyError: the proof indicates an inconsistency
                (this is usually really serious!).
            ProofError: the proof is invalid.
            ValueError: supplied tree sizes are invalid.
        """
        old_size = long(old_tree_size)
        new_size = long(new_tree_size)

        if old_size < 0 or new_size < 0:
            raise ValueError("Negative tree size")

        if old_size > new_size:
            raise ValueError("Older tree has bigger size (%d vs %d), did "
                             "you supply inputs in the wrong order?" %
                             (old_size, new_size))

        if old_size == new_size:
            if old_root == new_root:
                if proof:
                    logging.warning("Trees are identical, ignoring proof")
                return True
            else:
                raise error.ConsistencyError("Inconsistency: different root "
                                             "hashes for the same tree size")

        if old_size == 0:
            if proof:
                # A consistency proof with an empty tree is an empty proof.
                # Anything is consistent with an empty tree, so ignore whatever
                # bogus proof was supplied. Note we do not verify here that the
                # root hash is a valid hash for an empty tree.
                logging.warning("Ignoring non-empty consistency proof for "
                                "empty tree.")
            return True

        # Now 0 < old_size < new_size
        # A consistency proof is essentially an audit proof for the node with
        # index old_size - 1 in the newer tree. The sole difference is that
        # the path is already hashed together into a single hash up until the
        # first audit node that occurs in the newer tree only.
        node = old_size - 1
        last_node = new_size - 1

        # While we are the right child, everything is in both trees, so move one
        # level up.
        while node % 2:
            node //= 2
            last_node //= 2

        p = iter(proof)
        try:
            if node:
                # Compute the two root hashes in parallel.
                new_hash = old_hash = p.next()
            else:
                # The old tree was balanced (2**k nodes), so we already have
                # the first root hash.
                new_hash = old_hash = old_root

            while node:
                if node % 2:
                    # node is a right child: left sibling exists in both trees.
                    next_node = p.next()
                    old_hash = self.hasher.hash_children(next_node, old_hash)
                    new_hash = self.hasher.hash_children(next_node, new_hash)
                elif node < last_node:
                    # node is a left child: right sibling only exists in the
                    # newer tree.
                    new_hash = self.hasher.hash_children(new_hash, p.next())
                # else node == last_node: node is a left child with no sibling
                # in either tree.
                node //= 2
                last_node //= 2

            # Now old_hash is the hash of the first subtree. If the two trees
            # have different height, continue the path until the new root.
            while last_node:
                new_hash = self.hasher.hash_children(new_hash, p.next())
                last_node //= 2

            # If the second hash does not match, the proof is invalid for the
            # given pair. If, on the other hand, the newer hash matches but the
            # older one doesn't, then the proof (together with the signatures
            # on the hashes) is proof of inconsistency.
            # Continue to find out.
            if new_hash != new_root:
                raise error.ProofError("Bad Merkle proof: second root hash "
                                       "does not match. Expected hash: %s "
                                       ", computed hash: %s" %
                                       (new_root, new_hash))
            elif old_hash != old_root:
                raise error.ConsistencyError("Inconsistency: first root hash "
                                             "does not match. Expected hash: "
                                             "%s, computed hash: %s" %
                                             (old_root, old_hash))

        except StopIteration:
            raise error.ProofError("Merkle proof is too short")

        # We've already verified consistency, so accept the proof even if
        # there's garbage left over (but log a warning).
        try:
            p.next()
        except StopIteration:
            pass
        else:
            logging.warning("Proof has extra nodes")
        return True

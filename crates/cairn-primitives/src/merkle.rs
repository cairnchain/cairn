//! Binary Merkle root over an ordered list of items.
//!
//! Two properties matter for consensus.
//!
//! Leaves and internal nodes are hashed under different domains, so an internal
//! node digest can never be presented as a leaf. Without that separation a
//! proof for an internal node doubles as a proof of membership for a forged
//! item.
//!
//! A level with an odd node count promotes the last node unchanged rather than
//! pairing it with itself. Bitcoin duplicates it instead, which makes the leaf
//! lists `[a, b, c]` and `[a, b, c, c]` produce the same root (CVE-2012-2459).

use crate::hash::{hash, Domain, Hash32, Hasher};

/// Hashes one item into a leaf digest.
pub fn merkle_leaf(item: &[u8]) -> Hash32 {
    hash(Domain::MerkleLeaf, item)
}

fn merkle_node(left: Hash32, right: Hash32) -> Hash32 {
    let mut hasher = Hasher::new(Domain::MerkleNode);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

/// Root of the tree built over `leaves`, which must already be leaf digests.
///
/// The root of an empty list is a fixed digest that no non empty list can
/// produce, because it is computed under its own domain.
pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    let mut level: Vec<Hash32> = match leaves {
        [] => return hash(Domain::MerkleEmpty, &[]),
        [only] => return *only,
        _ => leaves.to_vec(),
    };

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(merkle_node(*left, *right)),
                [promoted] => next.push(*promoted),
                _ => {}
            }
        }
        level = next;
    }

    level
        .first()
        .copied()
        .unwrap_or_else(|| hash(Domain::MerkleEmpty, &[]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn leaves(count: u8) -> Vec<Hash32> {
        (0..count).map(|index| merkle_leaf(&[index])).collect()
    }

    #[test]
    fn empty_and_single_roots_are_distinct() {
        let single = leaves(1);
        assert_ne!(merkle_root(&[]), merkle_root(&single));
        assert_eq!(merkle_root(&single), single[0]);
    }

    #[test]
    fn root_depends_on_order() {
        let forward = leaves(4);
        let mut reversed = forward.clone();
        reversed.reverse();
        assert_ne!(merkle_root(&forward), merkle_root(&reversed));
    }

    #[test]
    fn duplicating_the_last_leaf_changes_the_root() {
        // Regression guard for CVE-2012-2459.
        let three = leaves(3);
        let mut four = three.clone();
        four.push(three[2]);
        assert_ne!(merkle_root(&three), merkle_root(&four));
    }

    #[test]
    fn a_leaf_cannot_be_forged_from_an_internal_node() {
        let pair = leaves(2);
        let root = merkle_root(&pair);
        assert_ne!(
            root,
            merkle_leaf(&[root.as_bytes().as_slice(), b""].concat())
        );
        assert_ne!(merkle_root(&[root]), merkle_root(&pair[..1]));
    }

    #[test]
    fn root_is_stable_across_sizes() {
        for count in 1..32u8 {
            let items = leaves(count);
            assert_eq!(merkle_root(&items), merkle_root(&items));
        }
    }
}

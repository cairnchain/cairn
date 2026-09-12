//! How deep a chosen holder's path can be driven.
//!
//! `key.rs` argues the tree stays balanced: "Callers derive keys by hashing,
//! so they are spread uniformly and the tree stays balanced. An adversary who
//! could choose keys freely could pile entries onto one path and make proofs
//! there as deep as `MAX_DEPTH`."
//!
//! Both sentences are true and neither is the one the argument needs. Callers
//! do hash, and what they hash is chosen by whoever made the note: the
//! ledger's key is `hash(NoteKey, note id)` over an identifier a transaction's
//! author settles. Nobody chooses a key, and anybody can choose a preimage,
//! which buys `d` shared bits for about `2^d` hashes. The spread is uniform
//! over one draw and an adversary takes as many draws as it likes.
//!
//! What that is worth is bounded and is measured here rather than argued. It
//! costs one note per level and the levels get twice as dear each time, so the
//! reach is a few levels past whatever the honest depth is, not `MAX_DEPTH`.
//! It also costs notes that have to stay in the held tier, which evicts by
//! age, so it is rent rather than a purchase.
//!
//! Nothing in the node carries one of these proofs: the hot tier is held, and
//! a spend out of it names the note rather than proving it. What this reaches
//! is the figure the French papers publish for what a holder carries, for one
//! holder somebody picked.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use cairn_accumulator::{Key, SparseMerkleTree};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Hash32;

/// A key derived the way the ledger derives one, over something its author
/// chose.
fn key(index: u64) -> Key {
    Key::from_hash(hash(Domain::StateEntry, &index.to_le_bytes()))
}

fn value(index: u64) -> Hash32 {
    hash(Domain::MerkleLeaf, &index.to_le_bytes())
}

/// Bits two keys agree on, from the most significant end.
fn shared_bits(left: &Key, right: &Key) -> usize {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    let mut bits = 0usize;
    for (mine, theirs) in left.iter().zip(right.iter()) {
        if mine == theirs {
            bits += 8;
        } else {
            bits += (mine ^ theirs).leading_zeros() as usize;
            break;
        }
    }
    bits
}

/// Run with `--nocapture` to see the figures.
#[test]
fn grinding_preimages_lengthens_a_chosen_holders_path() {
    const HONEST: u64 = 1_000;
    /// Where the grinding stops. Each level past the last costs twice the one
    /// before, so this is minutes rather than an unbounded claim.
    const REACH: usize = 24;

    let mut tree = SparseMerkleTree::new();
    for index in 0..HONEST {
        tree.insert(key(index), value(index));
    }
    let victim = key(0);
    let honest = tree.prove(victim);
    assert!(honest.verify_membership(tree.root(), victim, value(0)));

    let mut tried = 0u64;
    let mut counter = HONEST;
    let mut planted = 0usize;
    for want in (honest.depth() + 1)..=REACH {
        loop {
            counter += 1;
            tried += 1;
            let candidate = key(counter);
            if shared_bits(&victim, &candidate) >= want {
                tree.insert(candidate, value(counter));
                planted += 1;
                break;
            }
            assert!(tried < 1 << 28, "grinding ran away at {want} bits");
        }
    }

    let driven = tree.prove(victim);
    assert!(
        driven.verify_membership(tree.root(), victim, value(0)),
        "the path still proves what it did, which is what makes this a cost \
         rather than a break"
    );

    println!(
        "{HONEST} honestly derived keys: the holder of one of them carries {} siblings, \
         {} bytes",
        honest.depth(),
        honest.size_in_bytes()
    );
    println!(
        "{planted} notes ground over 2^{:.1} hashes take the same holder to {} siblings, \
         {} bytes",
        (tried as f64).log2(),
        driven.depth(),
        driven.size_in_bytes()
    );

    assert!(
        driven.depth() >= REACH,
        "the path was driven to {} siblings, not {REACH}",
        driven.depth()
    );
    assert!(
        driven.size_in_bytes() > honest.size_in_bytes() * 3 / 2,
        "the published figure moved from {} B to {} B",
        honest.size_in_bytes(),
        driven.size_in_bytes()
    );
}

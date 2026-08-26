//! Behaviour a node depends on when it validates without holding the ledger.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::{Change, Key, Proof, SparseMerkleTree, MAX_DEPTH};
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Hash32;

/// Deterministic stand in for a note identifier.
fn key(index: u64) -> Key {
    Key::from_hash(hash(Domain::StateEntry, &index.to_le_bytes()))
}

fn value(index: u64) -> Hash32 {
    hash(Domain::MerkleLeaf, &index.to_le_bytes())
}

fn tree_with(indices: impl IntoIterator<Item = u64>) -> SparseMerkleTree {
    let mut tree = SparseMerkleTree::new();
    for index in indices {
        tree.insert(key(index), value(index));
    }
    tree
}

#[test]
fn an_empty_tree_has_a_stable_root() {
    let first = SparseMerkleTree::new();
    let second = SparseMerkleTree::new();
    assert_eq!(first.root(), second.root());
    assert!(first.is_empty());
    assert_ne!(first.root(), Hash32::ZERO);
}

#[test]
fn entries_go_in_and_come_back_out() {
    let mut tree = SparseMerkleTree::new();
    assert_eq!(tree.insert(key(1), value(1)), None);
    assert_eq!(tree.get(key(1)), Some(value(1)));
    assert_eq!(tree.len(), 1);

    assert_eq!(tree.insert(key(1), value(2)), Some(value(1)));
    assert_eq!(tree.get(key(1)), Some(value(2)));
    assert_eq!(tree.len(), 1, "replacing an entry does not add one");

    assert_eq!(tree.remove(key(1)), Some(value(2)));
    assert_eq!(tree.get(key(1)), None);
    assert!(tree.is_empty());
    assert_eq!(tree.remove(key(1)), None);
}

#[test]
fn the_root_depends_only_on_the_contents() {
    let forward = tree_with(0..64);
    let backward = tree_with((0..64).rev());
    let shuffled = tree_with([31, 7, 0, 63, 12, 45].into_iter().chain(0..64));

    assert_eq!(forward.root(), backward.root());
    assert_eq!(forward.root(), shuffled.root());
    assert_eq!(forward.len(), shuffled.len());
}

#[test]
fn removing_an_entry_restores_the_earlier_root() {
    let mut tree = tree_with(0..40);
    let before = tree.root();

    tree.insert(key(999), value(999));
    assert_ne!(tree.root(), before);

    tree.remove(key(999));
    assert_eq!(tree.root(), before, "the tree kept no trace of the entry");
}

#[test]
fn a_membership_proof_verifies_against_the_root_alone() {
    let tree = tree_with(0..500);
    let root = tree.root();

    for index in [0u64, 1, 250, 499] {
        let proof = tree.prove(key(index));
        assert!(proof.verify_membership(root, key(index), value(index)));
    }
}

#[test]
fn a_membership_proof_is_bound_to_its_key_value_and_root() {
    let tree = tree_with(0..500);
    let root = tree.root();
    let proof = tree.prove(key(7));

    assert!(proof.verify_membership(root, key(7), value(7)));
    assert!(
        !proof.verify_membership(root, key(7), value(8)),
        "wrong value"
    );
    assert!(
        !proof.verify_membership(root, key(8), value(8)),
        "wrong key"
    );
    assert!(
        !proof.verify_membership(Hash32::ZERO, key(7), value(7)),
        "wrong root"
    );
}

#[test]
fn a_proof_stops_working_once_the_tree_moves_on() {
    let mut tree = tree_with(0..100);
    let proof = tree.prove(key(5));
    let root_then = tree.root();
    assert!(proof.verify_membership(root_then, key(5), value(5)));

    tree.insert(key(1000), value(1000));
    assert!(
        !proof.verify_membership(tree.root(), key(5), value(5)),
        "a stale proof must not verify against the new root"
    );
    assert!(
        tree.prove(key(5))
            .verify_membership(tree.root(), key(5), value(5)),
        "a refreshed proof works again"
    );
}

#[test]
fn absence_is_provable_for_a_key_that_was_never_added() {
    let tree = tree_with(0..500);
    let root = tree.root();

    let missing = key(10_000);
    let proof = tree.prove(missing);
    assert!(proof.verify_absence(root, missing));
    assert!(!proof.verify_membership(root, missing, value(10_000)));
}

#[test]
fn absence_is_provable_in_an_empty_tree() {
    let tree = SparseMerkleTree::new();
    let proof = tree.prove(key(1));
    assert_eq!(proof.depth(), 0);
    assert!(proof.verify_absence(tree.root(), key(1)));
}

#[test]
fn absence_stops_being_provable_once_the_key_is_added() {
    let mut tree = tree_with(0..200);
    let target = key(10_000);
    let proof = tree.prove(target);
    assert!(proof.verify_absence(tree.root(), target));

    tree.insert(target, value(10_000));
    assert!(!proof.verify_absence(tree.root(), target));
    assert!(!tree.prove(target).verify_absence(tree.root(), target));
}

#[test]
fn an_absence_proof_cannot_be_passed_off_as_membership() {
    let tree = tree_with(0..500);
    let root = tree.root();
    let missing = key(10_000);

    let proof = tree.prove(missing);
    assert!(proof.verify_absence(root, missing));
    for candidate in 0..8u64 {
        assert!(!proof.verify_membership(root, missing, value(candidate)));
    }
}

#[test]
fn an_absence_proof_cannot_be_replayed_for_another_key() {
    let tree = tree_with(0..500);
    let root = tree.root();

    let proof = tree.prove(key(10_000));
    assert!(proof.verify_absence(root, key(10_000)));

    // The occupant sits on the original key's path, not on any other.
    let mut replays = 0;
    for candidate in 10_001..10_200u64 {
        if proof.verify_absence(root, key(candidate)) {
            replays += 1;
        }
    }
    assert_eq!(replays, 0);
}

#[test]
fn tampering_with_a_sibling_breaks_the_proof() {
    let tree = tree_with(0..500);
    let root = tree.root();
    let proof = tree.prove(key(7));

    let mut bytes = proof.encode();
    // Flip a bit inside the first sibling, past the four byte length prefix.
    bytes[4] ^= 0x01;
    let tampered = Proof::decode(&bytes).unwrap();
    assert!(!tampered.verify_membership(root, key(7), value(7)));
}

#[test]
fn proofs_survive_the_wire_format_and_reject_malformed_input() {
    let tree = tree_with(0..500);
    let root = tree.root();

    let membership = tree.prove(key(7));
    let decoded = Proof::decode(&membership.encode()).unwrap();
    assert_eq!(decoded, membership);
    assert!(decoded.verify_membership(root, key(7), value(7)));

    let absence = tree.prove(key(10_000));
    let decoded = Proof::decode(&absence.encode()).unwrap();
    assert_eq!(decoded, absence);
    assert!(decoded.verify_absence(root, key(10_000)));

    let mut bytes = absence.encode();
    let tag = bytes.len() - 1 - 64;
    bytes[tag] = 9;
    assert!(Proof::decode(&bytes).is_err(), "unknown occupant tag");
}

#[test]
fn a_batch_matches_the_same_edits_applied_one_by_one() {
    let mut batched = tree_with(0..50);
    let mut stepwise = tree_with(0..50);

    let changes = vec![
        Change::Insert {
            key: key(100),
            value: value(100),
        },
        Change::Remove { key: key(3) },
        Change::Insert {
            key: key(101),
            value: value(101),
        },
        Change::Remove { key: key(49) },
    ];
    let batched_root = batched.apply(&changes);

    stepwise.insert(key(100), value(100));
    stepwise.remove(key(3));
    stepwise.insert(key(101), value(101));
    stepwise.remove(key(49));

    assert_eq!(batched_root, stepwise.root());
    assert_eq!(batched.len(), stepwise.len());
}

#[test]
fn proofs_stay_shallow_as_the_tree_grows() {
    let count = 10_000u64;
    let tree = tree_with(0..count);
    assert_eq!(tree.len(), count as usize);

    let mut total = 0usize;
    let mut deepest = 0usize;
    for index in 0..count {
        let depth = tree.prove(key(index)).depth();
        total += depth;
        deepest = deepest.max(depth);
    }
    let average = total / count as usize;

    // Uniform keys give a balanced tree, so depth tracks log2(n), here about 13.
    assert!((12..=16).contains(&average), "average depth was {average}");
    assert!(deepest < 40, "deepest proof was {deepest}");
    assert!(deepest <= MAX_DEPTH);
}

#[test]
fn every_entry_in_a_large_tree_proves_against_one_root() {
    let count = 5_000u64;
    let tree = tree_with(0..count);
    let root = tree.root();

    for index in 0..count {
        let proof = tree.prove(key(index));
        assert!(
            proof.verify_membership(root, key(index), value(index)),
            "entry {index} failed to prove"
        );
    }
    assert!(tree
        .prove(key(count + 1))
        .verify_absence(root, key(count + 1)));
}

#[test]
fn a_copy_evolves_without_disturbing_the_original() {
    let mut original = tree_with(0..300);
    let root_before = original.root();
    let proof_before = original.prove(key(42));

    let mut copy = original.clone();
    copy.insert(key(9_000), value(9_000));
    copy.remove(key(42));

    assert_eq!(original.root(), root_before, "the original did not move");
    assert!(proof_before.verify_membership(original.root(), key(42), value(42)));
    assert_ne!(copy.root(), root_before);
    assert!(copy.prove(key(42)).verify_absence(copy.root(), key(42)));

    original.remove(key(1));
    assert!(
        copy.get(key(1)).is_some(),
        "the copy kept what the original dropped"
    );
}

//! Removal is idempotent, and the two kinds of node agree about it.
//!
//! A place that has been emptied proves itself: the root above it is exactly
//! what folding the empty leaf gives, so a second removal of the same place
//! verifies. The roots do not move, so nothing shows it, but the count does,
//! and the count is committed to. A node that dropped it twice and one that
//! dropped it once would commit to different cold sets from the same block.
//!
//! It was reachable only through the archivist, which removed once per entry
//! where a plain node sorted and deduped first. The refusal now lives in the
//! accumulator, where both kinds pass through it.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::forest::{empty_leaf, forest_leaf};
use cairn_accumulator::{Archive, Forest};
use cairn_primitives::Hash32;

fn leaf(index: u64) -> Hash32 {
    forest_leaf(&index.to_le_bytes())
}

/// Emptying a place that is already empty changes nothing, and says so.
#[test]
fn removing_an_already_empty_position_is_refused() {
    let mut archive = Archive::new();
    let mut node = Forest::new();
    for index in 0..8u64 {
        archive.add(leaf(index)).unwrap();
        node.add(leaf(index)).unwrap();
    }

    // Legitimately empty position 3.
    let proof = archive.prove(3).unwrap();
    assert!(node.remove(3, leaf(3), &proof));
    assert!(archive.remove(3));
    assert_eq!(node.len(), 7);

    let roots_commitment_reference = node.commitment();

    // Now prove the EMPTY leaf that now sits at position 3 and "remove" it
    // again. Nothing about the roots can change: folding empty_leaf up gives
    // exactly the root that is already there.
    let empty_proof = archive.prove(3).unwrap();
    assert!(
        node.verify(3, empty_leaf(), &empty_proof),
        "the empty leaf genuinely sits at position 3 now"
    );
    let second = node.remove(3, empty_leaf(), &empty_proof);

    assert!(
        !second,
        "a place that is already empty cannot be emptied again"
    );
    assert_eq!(
        node.len(),
        7,
        "and the count the commitment carries did not move"
    );
    assert_eq!(
        node.commitment(),
        roots_commitment_reference,
        "the commitment moved even though the roots did not"
    );
}

/// The consensus-relevant shape of the same defect: a plain node (which dedups
/// positions inside `remove_batch`) and an archivist (which calls `remove`
/// once per entry, no dedup) end up with different commitments when a position
/// is listed twice. If a block could ever carry two removals of one position,
/// the two node kinds would fork.
#[test]
fn plain_node_and_archivist_agree_on_a_repeated_position() {
    let mut archive = Archive::new();
    let mut node = Forest::new();
    for index in 0..16u64 {
        archive.add(leaf(index)).unwrap();
        node.add(leaf(index)).unwrap();
    }

    let proof = archive.prove(5).unwrap();
    let removals = vec![
        (5u64, leaf(5), proof.clone()),
        (5u64, leaf(5), proof.clone()),
    ];

    // Plain node: remove_batch sorts and dedups -> one removal.
    assert!(node.remove_batch(&removals));

    // Archivist path, exactly as ColdSet::remove_batch drives it: verify all,
    // then remove once per entry with no dedup. The repeat is refused rather
    // than counted, which is what makes the two kinds agree.
    for (position, leaf_value, proof) in &removals {
        assert!(archive.forest().verify(*position, *leaf_value, proof));
    }
    let mut taken = 0usize;
    for (position, _, _) in &removals {
        if archive.remove(*position) {
            taken += 1;
        }
    }
    assert_eq!(taken, 1, "the same place is emptied once, not twice");

    assert_eq!(
        node.len(),
        archive.len(),
        "plain node kept {} live, archivist kept {}",
        node.len(),
        archive.len()
    );
    assert_eq!(
        node.commitment(),
        archive.commitment(),
        "plain node and archivist committed to different states from the same block"
    );
}

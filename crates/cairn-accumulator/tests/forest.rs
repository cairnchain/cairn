//! What a node can keep track of while holding almost nothing.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::forest::{empty_leaf, forest_leaf, MAX_HEIGHT};
use cairn_accumulator::{Archive, Forest, ForestProof};
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Hash32;

fn leaf(index: u64) -> Hash32 {
    forest_leaf(&index.to_le_bytes())
}

/// An archivist and a plain node, fed exactly the same things.
struct Pair {
    archive: Archive,
    node: Forest,
}

impl Pair {
    fn new() -> Self {
        Self {
            archive: Archive::new(),
            node: Forest::new(),
        }
    }

    fn add(&mut self, index: u64) -> u64 {
        let position = self.archive.add(leaf(index)).unwrap();
        // The node adds from the roots alone. It is handed no proof, because
        // there is none to hand it.
        assert_eq!(self.node.add(leaf(index)), Some(position));
        assert_eq!(self.node.commitment(), self.archive.commitment());
        position
    }

    fn remove(&mut self, index: u64, position: u64) {
        let proof = self.archive.prove(position).unwrap();
        assert!(
            self.node.remove(position, leaf(index), &proof),
            "the node removes on a proof"
        );
        assert!(self.archive.remove(position));
        assert_eq!(self.node.commitment(), self.archive.commitment());
    }
}

#[test]
fn an_empty_forest_holds_nothing_and_says_so() {
    let forest = Forest::new();
    assert!(forest.is_empty());
    assert_eq!(forest.len(), 0);
    assert_eq!(forest.leaves(), 0);
    assert_eq!(forest.commitment(), Forest::new().commitment());
    assert!(!forest.verify(0, leaf(0), &ForestProof::default()));
}

#[test]
fn a_node_holding_only_roots_keeps_the_same_commitment() {
    let mut pair = Pair::new();
    for index in 0..1_000u64 {
        pair.add(index);
    }
    assert_eq!(pair.node.len(), 1_000);
    assert_eq!(pair.node.leaves(), 1_000);

    // This is the whole point: the node was never given a leaf's neighbours,
    // never held a tree, and is still exactly in step.
    assert_eq!(pair.node.commitment(), pair.archive.commitment());
}

#[test]
fn a_proof_from_an_archivist_convinces_a_node_that_holds_nothing() {
    let mut pair = Pair::new();
    for index in 0..500u64 {
        pair.add(index);
    }

    for position in [0u64, 1, 255, 499] {
        let proof = pair.archive.prove(position).unwrap();
        assert!(pair.node.verify(position, leaf(position), &proof));
        assert!(
            !pair.node.verify(position, leaf(position + 1), &proof),
            "wrong leaf"
        );
        assert!(
            !pair.node.verify(position + 1, leaf(position), &proof),
            "wrong position"
        );
    }
}

#[test]
fn removing_takes_a_proof_and_nothing_else() {
    let mut pair = Pair::new();
    let positions: Vec<u64> = (0..64u64).map(|index| pair.add(index)).collect();

    pair.remove(7, positions[7]);
    assert_eq!(pair.node.len(), 63);
    assert_eq!(
        pair.node.leaves(),
        64,
        "the position is spent, not reclaimed"
    );

    // The same proof cannot work twice: what it describes is no longer there.
    let stale = ForestProof::default();
    assert!(!pair.node.remove(positions[7], leaf(7), &stale));
}

#[test]
fn a_removed_leaf_stops_being_provable() {
    let mut pair = Pair::new();
    let positions: Vec<u64> = (0..32u64).map(|index| pair.add(index)).collect();

    let proof = pair.archive.prove(positions[5]).unwrap();
    assert!(pair.node.verify(positions[5], leaf(5), &proof));

    pair.remove(5, positions[5]);
    assert!(
        !pair.node.verify(positions[5], leaf(5), &proof),
        "the old proof is dead"
    );

    let after = pair.archive.prove(positions[5]).unwrap();
    assert!(
        pair.node.verify(positions[5], empty_leaf(), &after),
        "an empty place is what is left"
    );
    assert!(!pair.node.verify(positions[5], leaf(5), &after));
}

#[test]
fn a_position_still_means_the_same_place_much_later() {
    let mut pair = Pair::new();
    let early = pair.add(1);
    for index in 100..1_100u64 {
        pair.add(index);
    }

    let proof = pair.archive.prove(early).unwrap();
    assert!(
        pair.node.verify(early, leaf(1), &proof),
        "the leaf never moved"
    );
    assert!(proof.depth() > 0);
}

#[test]
fn what_a_node_holds_does_not_grow() {
    let mut node = Forest::new();
    for index in 0..100_000u64 {
        node.add(leaf(index));
    }
    // A forest holds at most one tree per bit of its leaf count, so what a node
    // keeps is at most MAX_HEIGHT hashes and two counters, at any size at all.
    assert_eq!(MAX_HEIGHT, 64);
    assert_eq!(node.len(), 100_000);
    assert_ne!(node.commitment(), Forest::new().commitment());
}

#[test]
fn every_change_moves_the_commitment() {
    let mut pair = Pair::new();
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(pair.node.commitment());

    let positions: Vec<u64> = (0..40u64)
        .map(|index| {
            let position = pair.add(index);
            assert!(
                seen.insert(pair.node.commitment()),
                "adding leaf {index} changed nothing"
            );
            position
        })
        .collect();

    for position in [3u64, 17, 39] {
        pair.remove(position, positions[position as usize]);
        assert!(
            seen.insert(pair.node.commitment()),
            "removing {position} changed nothing"
        );
    }
    assert_eq!(seen.len(), 44);
}

#[test]
fn proofs_stay_short_as_the_forest_grows() {
    let mut archive = Archive::new();
    for index in 0..4_096u64 {
        archive.add(leaf(index));
    }
    let proof = archive.prove(0).unwrap();
    assert_eq!(proof.depth(), 12, "log2 of the forest, not its size");
    assert!(proof.size_in_bytes() < 500);
}

#[test]
fn a_proof_survives_the_wire_format() {
    let mut archive = Archive::new();
    for index in 0..300u64 {
        archive.add(leaf(index));
    }
    let proof = archive.prove(42).unwrap();
    assert_eq!(ForestProof::decode(&proof.encode()).unwrap(), proof);

    let mut oversized = Vec::new();
    vec![Hash32::ZERO; MAX_HEIGHT + 1].encode_to(&mut oversized);
    assert!(ForestProof::decode(&oversized).is_err());
}

#[test]
fn two_nodes_fed_the_same_changes_agree() {
    let mut first = Forest::new();
    let mut second = Forest::new();
    let mut archive = Archive::new();

    for index in 0..200u64 {
        archive.add(leaf(index));
        first.add(leaf(index));
        second.add(leaf(index));
    }

    for position in [3u64, 90, 199] {
        let proof = archive.prove(position).unwrap();
        assert!(first.remove(position, leaf(position), &proof));
        assert!(second.remove(position, leaf(position), &proof));
        archive.remove(position);
    }

    assert_eq!(first.commitment(), second.commitment());
    assert_eq!(first.commitment(), archive.commitment());
    assert_eq!(first.len(), 197);
}

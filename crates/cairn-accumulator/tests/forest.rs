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
        let (position, proof) = self.archive.add(leaf(index)).unwrap();
        // The node adds from the roots alone. It is handed no proof, because
        // there is none to hand it: the proof falls out of the addition.
        let (node_position, node_proof) = self.node.add(leaf(index)).unwrap();
        assert_eq!(node_position, position);
        assert_eq!(node_proof, proof);
        assert!(
            self.node.verify(position, leaf(index), &proof),
            "the addition proves itself"
        );
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
        node.add(leaf(index)).unwrap();
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
        archive.add(leaf(index)).unwrap();
    }
    let proof = archive.prove(0).unwrap();
    assert_eq!(proof.depth(), 12, "log2 of the forest, not its size");
    assert!(proof.size_in_bytes() < 500);
}

#[test]
fn a_proof_survives_the_wire_format() {
    let mut archive = Archive::new();
    for index in 0..300u64 {
        archive.add(leaf(index)).unwrap();
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
        archive.add(leaf(index)).unwrap();
        first.add(leaf(index)).unwrap();
        second.add(leaf(index)).unwrap();
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

#[test]
fn several_leaves_go_at_once_from_proofs_taken_together() {
    let mut archive = Archive::new();
    for index in 0..256u64 {
        archive.add(leaf(index)).unwrap();
    }
    let mut node = Forest::new();
    for index in 0..256u64 {
        node.add(leaf(index)).unwrap();
    }

    // Everyone proves against the same root, which is what spenders in one
    // block necessarily do.
    let targets = [5u64, 6, 90, 91, 200];
    let removals: Vec<_> = targets
        .iter()
        .map(|position| {
            (
                *position,
                leaf(*position),
                archive.prove(*position).unwrap(),
            )
        })
        .collect();

    assert!(node.remove_batch(&removals));
    for position in targets {
        assert!(archive.remove(position));
    }

    assert_eq!(node.commitment(), archive.commitment());
    assert_eq!(node.len(), 251);
}

#[test]
fn the_order_spends_appear_in_changes_nothing() {
    let build = |order: &[u64]| {
        let mut archive = Archive::new();
        for index in 0..128u64 {
            archive.add(leaf(index)).unwrap();
        }
        let mut node = Forest::new();
        for index in 0..128u64 {
            node.add(leaf(index)).unwrap();
        }
        let removals: Vec<_> = order
            .iter()
            .map(|position| {
                (
                    *position,
                    leaf(*position),
                    archive.prove(*position).unwrap(),
                )
            })
            .collect();
        assert!(node.remove_batch(&removals));
        node.commitment()
    };

    let forward = build(&[3, 4, 5, 60, 127]);
    let backward = build(&[127, 60, 5, 4, 3]);
    let shuffled = build(&[60, 3, 127, 5, 4]);
    assert_eq!(forward, backward);
    assert_eq!(forward, shuffled);
}

#[test]
fn a_batch_with_one_bad_proof_changes_nothing() {
    let mut archive = Archive::new();
    for index in 0..64u64 {
        archive.add(leaf(index)).unwrap();
    }
    let mut node = Forest::new();
    for index in 0..64u64 {
        node.add(leaf(index)).unwrap();
    }
    let before = node.commitment();

    let removals = vec![
        (10u64, leaf(10), archive.prove(10).unwrap()),
        (11u64, leaf(999), archive.prove(11).unwrap()),
    ];
    assert!(!node.remove_batch(&removals));
    assert_eq!(
        node.commitment(),
        before,
        "one bad proof and none of it happened"
    );
    assert_eq!(node.len(), 64);
}

#[test]
fn an_addition_hands_over_the_proof_of_what_it_added() {
    let mut node = Forest::new();
    for index in 0..37u64 {
        let (position, proof) = node.add(leaf(index)).unwrap();
        assert!(
            node.verify(position, leaf(index), &proof),
            "adding leaf {index} did not prove itself"
        );
    }
}

#[test]
fn a_holder_keeps_its_own_proof_current_and_asks_nobody() {
    let mut archive = Archive::new();
    let mut node = Forest::new();
    for index in 0..50u64 {
        archive.add(leaf(index)).unwrap();
        node.add(leaf(index)).unwrap();
    }

    // The holder's leaf arrives, and it keeps the proof the addition handed it.
    archive.add(leaf(999)).unwrap();
    let (mine, proof) = node.add(leaf(999)).unwrap();
    node.watch(mine, proof);
    assert_eq!(node.watched_count(), 1);

    // Then the world moves on: hundreds of arrivals, so the trees the holder
    // sits in merge and merge again.
    for index in 100..600u64 {
        archive.add(leaf(index)).unwrap();
        node.add(leaf(index)).unwrap();
    }
    // And departures, which move the siblings beside it.
    for position in [3u64, 10, 44, 51, 300] {
        let proof = archive.prove(position).unwrap();
        let held = archive.leaf_at(position).unwrap();
        assert!(node.remove(position, held, &proof));
        assert!(archive.remove(position));
    }

    let current = node.proof_of(mine).expect("still watched").clone();
    assert!(
        node.verify(mine, leaf(999), &current),
        "the holder can still spend"
    );
    assert_eq!(
        current,
        archive.prove(mine).unwrap(),
        "and its proof is exactly what an archivist would have handed it"
    );
    assert!(node.unwatch(mine).is_some());
    assert_eq!(node.watched_count(), 0);
}

#[test]
fn many_holders_are_kept_current_at_once() {
    let mut archive = Archive::new();
    let mut node = Forest::new();
    let mut mine = Vec::new();

    for index in 0..200u64 {
        archive.add(leaf(index)).unwrap();
        let (position, proof) = node.add(leaf(index)).unwrap();
        if index % 7 == 0 {
            node.watch(position, proof);
            mine.push((position, index));
        }
    }
    for index in 200..800u64 {
        archive.add(leaf(index)).unwrap();
        node.add(leaf(index)).unwrap();
    }

    let removals: Vec<_> = [5u64, 6, 99, 400]
        .iter()
        .map(|position| {
            (
                *position,
                leaf(*position),
                archive.prove(*position).unwrap(),
            )
        })
        .collect();
    assert!(node.remove_batch(&removals));
    for (position, _, _) in &removals {
        archive.remove(*position);
    }

    assert_eq!(node.watched_count(), mine.len());
    for (position, index) in mine {
        let proof = node.proof_of(position).expect("watched").clone();
        assert!(
            node.verify(position, leaf(index), &proof),
            "holder at {position} lost its proof"
        );
        assert_eq!(proof, archive.prove(position).unwrap());
    }
}

#[test]
fn watching_nothing_costs_nothing() {
    let mut plain = Forest::new();
    let mut watching = Forest::new();
    for index in 0..100u64 {
        plain.add(leaf(index)).unwrap();
        let (position, proof) = watching.add(leaf(index)).unwrap();
        watching.watch(position, proof);
    }
    // What a node commits to does not depend on what anyone is watching.
    assert_eq!(plain.commitment(), watching.commitment());
    assert_eq!(plain.watched_count(), 0);
    assert_eq!(watching.watched_count(), 100);
}

/// A forest crosses the wire and comes back the same.
#[test]
fn a_forest_survives_a_round_trip() {
    let mut forest = Forest::new();
    for index in 0..37u64 {
        forest.add(forest_leaf(&index.to_le_bytes()));
    }
    let commitment = forest.commitment();

    let bytes = forest.encode();
    let read_back = Forest::decode(&bytes).expect("a forest it wrote reads back");
    assert_eq!(read_back.commitment(), commitment);
    assert_eq!(read_back.len(), forest.len());
}

/// Roots that do not match the leaf count are not a forest anything produced.
///
/// The trees a forest holds are the set bits of its leaf count, so the two
/// check each other. Without that a sender could hand over roots of its own
/// choosing and a commitment computed from them, and the pair would agree with
/// itself while describing nothing.
#[test]
fn a_forest_whose_roots_contradict_its_count_is_refused() {
    let mut forest = Forest::new();
    for index in 0..8u64 {
        forest.add(forest_leaf(&index.to_le_bytes()));
    }
    let mut bytes = forest.encode();
    // Eight leaves is one tree of height three. Say nine instead, which would
    // take two trees, and the single root no longer accounts for it.
    bytes[0] = 9;
    assert!(Forest::decode(&bytes).is_err());

    // And a forest that says more of its leaves are live than it ever held.
    let mut bytes = forest.encode();
    bytes[8] = 99;
    assert!(Forest::decode(&bytes).is_err());
}

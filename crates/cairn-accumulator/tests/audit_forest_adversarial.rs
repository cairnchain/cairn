//! Adversarial audit of the append only forest.
//!
//! What is attacked here: whether a proof for one place can be made to check
//! out at another, whether removing really removes, whether the batch form is
//! the repeated single form, whether the roots-only holder and the archivist
//! can be driven apart, and whether the empty leaf sentinel can be made to
//! collide with a real one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::map_unwrap_or
)]

use cairn_accumulator::forest::{empty_leaf, forest_leaf, tree_of, ForestProof, MAX_HEIGHT};
use cairn_accumulator::{Archive, Forest, PathsBefore};
use cairn_primitives::Hash32;

fn leaf(index: u64) -> Hash32 {
    forest_leaf(&index.to_le_bytes())
}

/// A cheap deterministic spread, so a sweep is not a straight line.
fn scramble(seed: u64) -> u64 {
    let mut value = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value ^= value >> 29;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 32;
    value
}

/// No proof checks out anywhere but where it was taken.
///
/// The forest lays its trees out largest first, so two places can share a
/// height only by being in the same tree, and inside one tree the index
/// decides which side of every merge the leaf sat on. This walks every pair at
/// several sizes rather than arguing it.
#[test]
fn a_proof_for_one_place_checks_out_nowhere_else() {
    for count in [1u64, 2, 3, 5, 8, 13, 16, 31, 33, 64] {
        let mut archive = Archive::new();
        for index in 0..count {
            archive.add(leaf(index)).unwrap();
        }
        let forest = archive.forest();

        for taken in 0..count {
            let proof = archive.prove(taken).expect("an archivist can prove it");
            assert!(forest.verify(taken, leaf(taken), &proof));
            for offered in 0..count {
                if offered == taken {
                    continue;
                }
                assert!(
                    !forest.verify(offered, leaf(taken), &proof),
                    "a proof for {taken} was accepted at {offered}, in a forest of {count}"
                );
                assert!(
                    !forest.verify(offered, leaf(offered), &proof),
                    "the siblings of {taken} carried the leaf of {offered}, in a forest of {count}"
                );
            }
            // And past the end, where no place exists at all.
            assert!(!forest.verify(count, leaf(taken), &proof));
            assert!(!forest.verify(u64::MAX, leaf(taken), &proof));
        }
    }
}

/// A proof of the wrong length is refused before its shape is considered.
#[test]
fn a_proof_padded_or_trimmed_is_refused() {
    let mut archive = Archive::new();
    for index in 0..37u64 {
        archive.add(leaf(index)).unwrap();
    }
    let forest = archive.forest();

    for position in [0u64, 1, 31, 32, 36] {
        let good = archive.prove(position).unwrap();
        assert!(forest.verify(position, leaf(position), &good));

        let mut padded = good.clone();
        padded.siblings.push(Hash32::ZERO);
        assert!(!forest.verify(position, leaf(position), &padded));

        let mut trimmed = good.clone();
        // A place in a tree of one has no siblings to take away, and shortening
        // nothing is not an attack.
        if trimmed.siblings.pop().is_some() {
            assert!(!forest.verify(position, leaf(position), &trimmed));
        }

        let huge = ForestProof {
            siblings: vec![Hash32::ZERO; MAX_HEIGHT + 8],
        };
        assert!(!forest.verify(position, leaf(position), &huge));
    }
}

/// Removing removes, and the same proof will not do it twice.
#[test]
fn a_place_cannot_be_emptied_twice() {
    let mut archive = Archive::new();
    for index in 0..16u64 {
        archive.add(leaf(index)).unwrap();
    }
    let proof = archive.prove(5).unwrap();
    let mut forest = archive.forest().clone();

    assert!(forest.remove(5, leaf(5), &proof));
    let after = forest.commitment();
    let live = forest.len();

    // The same proof again: the leaf is no longer there, so it does not verify.
    assert!(!forest.remove(5, leaf(5), &proof));
    // And the emptied place proves itself, which is the trap the guard exists
    // for: without it this would verify and take the count down again.
    let emptied_proof = {
        let mut copy = archive.clone();
        assert!(copy.remove(5));
        copy.prove(5).unwrap()
    };
    assert!(
        forest.verify(5, empty_leaf(), &emptied_proof),
        "the empty leaf really does sit there now, which is why it must be refused"
    );
    assert!(
        !forest.remove(5, empty_leaf(), &emptied_proof),
        "and offering it is refused rather than counted"
    );
    assert_eq!(forest.commitment(), after);
    assert_eq!(forest.len(), live);
}

/// The batch form and the repeated single form agree, whatever the order and
/// whichever trees the places fall in.
#[test]
fn a_batch_is_the_same_as_removing_one_at_a_time() {
    for count in [8u64, 15, 16, 31, 45, 64, 100] {
        let mut archive = Archive::new();
        for index in 0..count {
            archive.add(leaf(index)).unwrap();
        }
        let base = archive.forest().clone();

        for round in 0..12u64 {
            let mut chosen: Vec<u64> = (0..5)
                .map(|slot| scramble(round.wrapping_mul(17).wrapping_add(slot)) % count)
                .collect();
            chosen.sort_unstable();
            chosen.dedup();

            // Every proof taken against the same roots, which is what a block
            // carries.
            let batch: Vec<(u64, Hash32, ForestProof)> = chosen
                .iter()
                .map(|at| (*at, leaf(*at), archive.prove(*at).unwrap()))
                .collect();

            let mut batched = base.clone();
            assert!(batched.remove_batch(&batch), "count {count} round {round}");

            // One at a time, each proof rebuilt against the state as it then
            // stood, which is what an archivist does.
            let mut singly = archive.clone();
            for at in &chosen {
                assert!(singly.remove(*at));
            }

            assert_eq!(
                batched.commitment(),
                singly.forest().commitment(),
                "count {count} round {round} chose {chosen:?}"
            );
            assert_eq!(batched.len(), singly.forest().len());
            assert_eq!(batched.leaves(), singly.forest().leaves());
        }
    }
}

/// The order the spends appear in changes nothing, in either holder.
#[test]
fn the_order_within_a_batch_changes_nothing() {
    let mut archive = Archive::new();
    for index in 0..50u64 {
        archive.add(leaf(index)).unwrap();
    }
    let base = archive.forest().clone();
    let chosen = [3u64, 47, 12, 33, 1, 48];

    let mut expected: Option<Hash32> = None;
    for rotation in 0..chosen.len() {
        let mut order: Vec<u64> = chosen.to_vec();
        order.rotate_left(rotation);
        let batch: Vec<(u64, Hash32, ForestProof)> = order
            .iter()
            .map(|at| (*at, leaf(*at), archive.prove(*at).unwrap()))
            .collect();

        let mut forest = base.clone();
        assert!(forest.remove_batch(&batch));
        match expected {
            None => expected = Some(forest.commitment()),
            Some(first) => assert_eq!(forest.commitment(), first, "rotation {rotation}"),
        }
    }
}

/// A batch naming the same place twice gets the same answer from both
/// holders.
///
/// It did not. `Forest::remove_batch` sorts and deduplicates, so the second
/// mention was dropped and the answer was yes; the archivist arm in
/// `cairn-ledger/src/state.rs` walked the list as given, so the second call
/// met the empty leaf and the answer was no. Nothing in a block could produce
/// that list, because a cold spend's place is pinned by the leaf, which is
/// pinned by the note identifier, and the block rules already refuse a
/// repeated identifier. What made it worth closing is what sat behind it: the
/// caller applies the batch to a state whose root it has already checked and
/// will not check again, so two arms that disagreed would have let one kind of
/// node carry on with a half emptied forest and advance its tip.
///
/// The archivist arm deduplicates now, which is what this shows from the side
/// this crate can see: the forest's answer, and the same list walked the way
/// the ledger walks it.
#[test]
fn a_repeated_place_in_one_batch_gets_one_answer_from_both_holders() {
    let mut archive = Archive::new();
    for index in 0..16u64 {
        archive.add(leaf(index)).unwrap();
    }
    let proof = archive.prove(7).unwrap();
    let doubled = [
        (7u64, leaf(7), proof.clone()),
        (7u64, leaf(7), proof.clone()),
    ];

    let mut roots = archive.forest().clone();
    assert!(
        roots.remove_batch(&doubled),
        "the roots-only holder deduplicates and says yes"
    );

    // What the archivist arm now does, spelled out: verify each against the
    // roots as they stood, then walk the places once each.
    let mut keeper = archive.clone();
    let verified = doubled
        .iter()
        .all(|(at, held, proof)| keeper.forest().verify(*at, *held, proof));
    assert!(verified, "both proofs check out against the same roots");
    let mut places: Vec<u64> = doubled.iter().map(|(at, _, _)| *at).collect();
    places.sort_unstable();
    places.dedup();
    assert!(
        places.iter().all(|at| keeper.remove(*at)),
        "and the archivist says yes to the same list"
    );

    assert_eq!(roots.commitment(), keeper.forest().commitment());
    assert_eq!(roots.len(), keeper.forest().len(), "one leaf left, not two");
}

/// A batch that cannot go through leaves the forest exactly as it was.
///
/// It did not. `remove_batch` checked every proof, then applied them one after
/// another and answered `false` the moment one did not go through, and the
/// removals before it stayed. A caller that read the `false` as "nothing
/// happened" was wrong, and the ledger's caller is exactly that caller: it
/// applies the batch to a state whose root it has already checked and will not
/// check again.
///
/// The batch is run against the roots alone first now, and the forest is only
/// touched once that has come out true. The roots are sixty four hashes, so
/// the trial is what a copy of a forest was always advertised to cost.
#[test]
fn a_batch_that_cannot_go_through_leaves_the_forest_alone() {
    let mut archive = Archive::new();
    for index in 0..16u64 {
        archive.add(leaf(index)).unwrap();
    }

    // A place that was emptied earlier proves itself: the empty leaf really
    // does sit there, so the check every proof goes through says yes, and the
    // refusal comes later, in the step that will not count a leaf that is not
    // there. That is a batch that passes its own pre-check and fails partway,
    // which is the shape the old one left half applied.
    assert!(archive.remove(9));
    let emptied = archive.prove(9).unwrap();
    let mut forest = archive.forest().clone();
    let before = forest.commitment();
    let live = forest.len();

    let batch = [
        (2u64, leaf(2), archive.prove(2).unwrap()),
        (9u64, empty_leaf(), emptied.clone()),
        (5u64, leaf(5), archive.prove(5).unwrap()),
    ];
    assert!(
        forest.verify(9, empty_leaf(), &emptied),
        "the second entry checks out, which is what makes it the awkward one"
    );
    assert!(!forest.remove_batch(&batch), "so the batch is refused");
    assert_eq!(
        forest.commitment(),
        before,
        "and nothing was emptied on the way to finding out"
    );
    assert_eq!(forest.len(), live);

    // The same batch without the awkward entry goes through, so the refusal
    // above was about that entry and not about the shape of the list.
    let good = [batch[0].clone(), batch[2].clone()];
    assert!(forest.remove_batch(&good));
    assert_ne!(forest.commitment(), before);
    assert_eq!(forest.len(), live - 2);
}

/// The roots-only holder and the archivist stay together over a long run of
/// mixed additions and removals.
#[test]
fn the_two_holders_cannot_be_driven_apart() {
    let mut archive = Archive::new();
    let mut roots = Forest::new();
    let mut standing: Vec<u64> = Vec::new();
    let mut next = 0u64;

    for step in 0..600u64 {
        let choice = scramble(step) % 4;
        if choice < 3 || standing.is_empty() {
            let value = leaf(next);
            let (position, _) = archive.add(value).unwrap();
            let (mirror, _) = roots.add(value).unwrap();
            assert_eq!(position, mirror);
            standing.push(position);
            next += 1;
        } else {
            let pick = (scramble(step ^ 0xabcd) as usize) % standing.len();
            let position = standing.swap_remove(pick);
            let held = archive.leaf_at(position).unwrap();
            let proof = archive.prove(position).unwrap();
            assert!(roots.remove(position, held, &proof));
            assert!(archive.remove(position));
        }
        assert_eq!(
            archive.forest().commitment(),
            roots.commitment(),
            "step {step}"
        );
        assert_eq!(archive.forest().leaves(), roots.leaves());
        assert_eq!(archive.len(), roots.len());
        assert_eq!(
            roots.len(),
            standing.len() as u64,
            "the count says what is standing, at step {step}"
        );
    }
}

/// Every leaf the archive says is standing is one the roots will still prove.
///
/// The structure and the leaves it holds have to agree after any sequence, or
/// a holder could be told its note is gone when it is not, or the other way
/// round.
#[test]
fn the_structure_agrees_with_the_leaves_after_any_sequence() {
    let mut archive = Archive::new();
    let mut alive: Vec<u64> = Vec::new();
    let mut next = 0u64;

    for step in 0..400u64 {
        if scramble(step) % 3 != 0 || alive.is_empty() {
            let (position, _) = archive.add(leaf(next)).unwrap();
            alive.push(position);
            next += 1;
        } else {
            let pick = (scramble(step ^ 0x5555) as usize) % alive.len();
            let position = alive.swap_remove(pick);
            assert!(archive.remove(position));
            assert_eq!(archive.leaf_at(position), Some(empty_leaf()));
        }
    }

    let forest = archive.forest();
    assert_eq!(forest.len(), alive.len() as u64);
    for position in &alive {
        let proof = archive.prove(*position).expect("still standing");
        assert!(
            forest.verify(*position, leaf(*position), &proof),
            "position {position} is standing and does not prove"
        );
    }
    for position in 0..next {
        if alive.contains(&position) {
            continue;
        }
        let proof = archive.prove(position).expect("the place still exists");
        assert!(
            !forest.verify(position, leaf(position), &proof),
            "position {position} was emptied and still proves its old leaf"
        );
    }
}

/// The empty leaf sentinel lives in the same domain as a real leaf, and the
/// only thing keeping the two apart is that nothing ever hashes nothing.
///
/// `empty_leaf()` is `hash(ForestLeaf, &[])` and `forest_leaf(item)` is
/// `hash(ForestLeaf, item)`, so `forest_leaf(&[])` is the sentinel exactly. In
/// the ledger the only producer of a cold leaf is `cold_leaf`, which hashes a
/// note identifier followed by a note and is therefore never empty. The
/// separation holds, and it holds by that one fact rather than by domain.
#[test]
fn the_empty_leaf_is_reachable_only_by_hashing_nothing() {
    assert_eq!(
        forest_leaf(&[]),
        empty_leaf(),
        "the sentinel is what hashing an empty item gives"
    );
    for length in 1..=128usize {
        let item = vec![0u8; length];
        assert_ne!(
            forest_leaf(&item),
            empty_leaf(),
            "an item of {length} zero bytes collided with the sentinel"
        );
    }

    // And if one ever were added, the place it took could never be emptied,
    // and the count of what is standing would be wrong for good. Shown rather
    // than argued, because it is the consequence that matters.
    let mut forest = Forest::new();
    let (position, proof) = forest.add(empty_leaf()).unwrap();
    assert_eq!(forest.len(), 1, "it counts as standing");
    assert!(
        forest.verify(position, empty_leaf(), &proof),
        "and it verifies like any other leaf"
    );
    assert!(
        !forest.remove(position, empty_leaf(), &proof),
        "but nothing can take it out again"
    );
    assert_eq!(forest.len(), 1, "so the count never comes back down");
}

/// Trees are laid out largest first and named by the set bits of the count, so
/// no two of them share a height. That is what makes the length of a proof
/// enough to say which tree it belongs to.
#[test]
fn no_two_trees_in_one_forest_share_a_height() {
    for leaves in [1u64, 2, 3, 7, 8, 100, 1_000, 65_535, 1 << 40] {
        let mut seen: Vec<usize> = Vec::new();
        let mut position = 0u64;
        while position < leaves.min(4_096) {
            let (height, offset) = tree_of(leaves, position).unwrap();
            if !seen.contains(&height) {
                seen.push(height);
            }
            position = offset + (1u64 << height);
        }
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), seen.len(), "a height repeated at {leaves}");
    }
    assert_eq!(tree_of(0, 0), None);
    assert_eq!(tree_of(5, 5), None);
}

/// What a record of one block's worth of change to the watched map costs,
/// measured rather than reasoned about.
///
/// A `Forest` is described as sixty four hashes, and its roots are. Its
/// watched map is not: it holds one full path per position, and a `Clone` of
/// the forest carried it, so undoing a block by assigning a clone of the
/// forest from before meant a copy of the whole map in the record of every
/// block a node could still undo. At this network's grace window, the depth a
/// mature cold set has, and the thousand and twenty four records a node keeps,
/// that was nine gigabytes.
///
/// What is kept now is the paths a block did not merely lengthen, and their
/// siblings once each rather than once per path. This measures both, against
/// what a copy of the map would have cost, and checks that every path really
/// does come back out of the record.
///
/// Run with `--nocapture` to see the figures.
#[test]
fn a_record_of_one_blocks_change_to_the_watched_map_is_kilobytes() {
    /// The ledger's `GRACE_NOTES`, restated so this crate stands alone.
    const GRACE_NOTES: usize = 8_192;
    /// Depth of a path in a cold set of about a billion notes.
    const DEPTH: usize = 30;
    /// Notes a full block pushes out of the hot set, from
    /// `cairn-ledger/examples/blocksize.rs`. They take consecutive places, and
    /// one block's worth is what ages out of the window as the next lands.
    const FALLING: u64 = 686;
    /// Undo records a node keeps, which is `cairn_chain::MAX_REORG_DEPTH`.
    const RECORDS: usize = 1_024;

    let leaves = 1u64 << DEPTH;
    let run = (leaves - FALLING)..leaves;

    // Paths whose siblings are decided by the place they cover rather than by
    // whose path they are on, which is what a real forest gives: two places
    // near each other share every step above the level where they part.
    let mut forest = Forest::new();
    for position in run.clone() {
        forest.watch(position, path_at(position, DEPTH));
    }
    let snapshot: usize = run
        .clone()
        .filter_map(|at| forest.proof_of(at))
        .map(cairn_accumulator::ForestProof::size_in_bytes)
        .sum();
    let whole_map = GRACE_NOTES * (DEPTH * 32 + 4);

    let mut before = PathsBefore::before(leaves);
    for position in run.clone() {
        forest.unwatch_keeping(position, &mut before);
    }
    assert_eq!(before.len(), FALLING as usize, "every one was written down");
    assert_eq!(forest.watched_count(), 0);

    let held = before.bytes_held();
    println!(
        "a watched map of {GRACE_NOTES} paths at depth {DEPTH} is {whole_map} B, \
         and a copy in each of {RECORDS} records was {:.1} GB",
        (whole_map * RECORDS) as f64 / 1e9
    );
    println!(
        "the {FALLING} paths one block lets go of are {snapshot} B written out one \
         by one, {held} B written down as this does it"
    );
    println!(
        "over {RECORDS} records that is {:.1} MB",
        (held * RECORDS) as f64 / 1e6
    );

    assert!(
        held.saturating_mul(6) < snapshot,
        "holding the siblings once each bought less than six times: \
         {held} B against {snapshot} B"
    );
    assert!(
        held.saturating_mul(50) < whole_map,
        "a record is {held} B against a copy of the map at {whole_map} B, and a \
         node keeps {RECORDS} records"
    );
}

/// A path whose every sibling is decided by the run of leaves it covers, which
/// is the one thing about a real path this test depends on.
fn path_at(position: u64, depth: usize) -> ForestProof {
    let siblings = (0..depth)
        .map(|level| leaf(((position >> level) ^ 1) | ((level as u64) << 40)))
        .collect();
    ForestProof { siblings }
}

/// Every path written down comes back out of the record exactly as it went in.
///
/// The siblings are held once each rather than once per path, so this is the
/// thing that has to hold: an undo puts the paths back from what was written
/// down, and a path that came back wrong would leave a node agreeing with
/// everybody about every root and quietly unable to accept a spend the rest of
/// the network accepts.
#[test]
fn a_path_written_down_comes_back_the_same_path() {
    for count in [1u64, 2, 5, 16, 17, 63, 64, 200] {
        let mut archive = Archive::new();
        for index in 0..count {
            archive.add(leaf(index)).unwrap();
        }
        let mut forest = archive.forest().clone();
        for position in 0..count {
            forest.watch(position, archive.prove(position).unwrap());
        }

        let mut before = PathsBefore::before(count);
        for position in 0..count {
            forest.unwatch_keeping(position, &mut before);
        }
        assert_eq!(before.len(), count as usize, "a forest of {count}");

        // Put back the way an undo puts them back, and every one of them still
        // proves the leaf it was taken for.
        let mut back = archive.forest().clone();
        back.rewind_to(&archive.forest().roots_only(), &before);
        assert_eq!(back.watched_count(), count as usize);
        for position in 0..count {
            let kept = back.proof_of(position).expect("it was written down");
            assert_eq!(
                kept,
                &archive.prove(position).unwrap(),
                "position {position} of {count} came back a different path"
            );
            assert!(back.verify(position, leaf(position), kept));
        }
    }
}

/// Applying a block costs what the block does, not what the node watches.
///
/// It used to cost both. `extend_watched` runs once per merge inside `add` and
/// `refresh_watched` once per `remove`, and both walked every watched position
/// from end to end, with a climb through sixty four heights inside the removal
/// one. A thousand additions took a quarter of a millisecond watching nothing
/// and a sixth of a second watching sixty five thousand places, which is seven
/// hundred times, and on a wallet's node what it watches is decided partly by
/// whoever pays notes to an address it follows.
///
/// Both ask the map for the run of places they can touch instead. A merge
/// touches the two halves it merged and a removal touches one tree, and the
/// map is sorted by position, so both runs were there to be asked for.
///
/// Timed rather than argued. Run with `--nocapture` for the figures.
#[test]
fn the_cost_of_a_block_does_not_grow_with_what_the_node_watches() {
    const DEPTH: usize = 24;
    let mut measured: Vec<(usize, u128, u128)> = Vec::new();

    for watching in [0usize, 1_024, 8_192, 65_536] {
        let mut forest = Forest::new();
        // A forest big enough that a position sits deep in a real tree.
        for index in 0..(1u64 << 16) {
            forest.add(leaf(index)).unwrap();
        }
        for index in 0..watching as u64 {
            forest.watch(
                index,
                ForestProof {
                    siblings: vec![leaf(index); DEPTH],
                },
            );
        }

        let adding = std::time::Instant::now();
        for index in 0..1_024u64 {
            forest.add(leaf(index + (1 << 20))).unwrap();
        }
        let adds = adding.elapsed().as_micros();

        // And a removal, which is the more expensive of the two.
        let mut archive = Archive::new();
        for index in 0..1_024u64 {
            archive.add(leaf(index)).unwrap();
        }
        let mut small = archive.forest().clone();
        for index in 0..watching.min(1_024) as u64 {
            small.watch(index, archive.prove(index).unwrap());
        }
        let removing = std::time::Instant::now();
        for index in 0..64u64 {
            small.remove(
                index * 8,
                leaf(index * 8),
                &archive.prove(index * 8).unwrap(),
            );
        }
        let removes = removing.elapsed().as_micros();

        println!("watching {watching:>6}: 1024 adds {adds:>8} us, 64 removes {removes:>8} us");
        measured.push((watching, adds, removes));
    }

    let (_, none, _) = measured[0];
    let (many, lots, _) = measured[measured.len() - 1];
    println!(
        "watching {many} makes an ordinary block's additions {:.1}x the cost of watching nothing",
        lots as f64 / none.max(1) as f64
    );
    // Generous, because this is a clock on a machine doing other things. What
    // it is guarding against is the seven hundredfold, not a factor of two.
    assert!(
        lots < none.saturating_mul(8),
        "watching {many} made an ordinary block's additions {lots} us against {none} us"
    );
}

//! Adversarial audit of the delta rewind: `PathsBefore`, `rewind_to`, and the
//! keeping variants of the removal and unwatch steps.
//!
//! Read only. Nothing here changes a source file.
//!
//! The claim under test is that a block's undo record no longer holds a copy
//! of the watched map and still puts every watched path back exactly. The
//! whole saving rests on that: a path the record does not hold is a path the
//! rewind has to work out, and a path it works out wrongly is one its holder
//! believes and finds out about at a spend.
//!
//! The check is the strongest one available. A `Forest` compares equal only
//! when its roots, its two counters and every watched path agree, so a rewind
//! is compared against a clone taken before the change rather than against a
//! summary of one.
//!
//! The first repair wrote down every watched path a removal brought up to
//! date, which put the copy of the map straight back in under another name.
//! What is written down now is only what a holder let go of for reasons the
//! block does not account for, so the size of a record is the second thing
//! under test here, next to the rewind itself.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use cairn_accumulator::forest::{forest_leaf, PathsBefore};
use cairn_accumulator::{Archive, Forest};
use cairn_primitives::Hash32;

fn leaf(index: u64) -> Hash32 {
    forest_leaf(&index.to_le_bytes())
}

/// A deterministic stand-in for randomness, so a failure is reproducible.
fn scramble(seed: u64) -> u64 {
    let mut value = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    value ^= value >> 30;
    value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value ^= value >> 27;
    value.wrapping_mul(0x94D0_49BB_1331_11EB) ^ (value >> 31)
}

/// A forest and an archive holding the same leaves, so any proof is available.
struct Both {
    forest: Forest,
    archive: Archive,
    /// Places whose leaf is still standing.
    live: Vec<u64>,
}

impl Both {
    fn new() -> Self {
        Self {
            forest: Forest::new(),
            archive: Archive::new(),
            live: Vec::new(),
        }
    }

    fn add(&mut self, index: u64) -> u64 {
        let (position, proof) = self.forest.add(leaf(index)).unwrap();
        self.archive.add(leaf(index)).unwrap();
        self.live.push(position);
        // Most places are watched, which is what the cold set does: a note
        // that falls is watched for as long as the window wants it, and for
        // good if somebody follows its owner. Some are not, because a block
        // may empty a place nobody was watching, and a rewind that put a path
        // back for one of those would leave a node believing it can prove a
        // place it cannot.
        if scramble(position ^ 0x0BAD) % 5 != 0 {
            self.forest.watch(position, proof);
        }
        position
    }
}

/// A rewind puts the forest back exactly, watched paths and all, after any
/// mixture of removals, unwatches and additions.
///
/// The order inside a block is the order the ledger uses: what the block
/// spends is emptied first and stops being watched, then what fell in it is
/// appended and watched, then whatever the window or the ceiling no longer
/// wants is let go of.
#[test]
fn a_rewind_puts_back_every_path_a_clone_would_have() {
    for seed in 0..300u64 {
        let mut both = Both::new();
        let opening = 3 + (scramble(seed) % 40);
        for index in 0..opening {
            both.add(index);
        }
        let mut next = opening;

        for round in 0..6u64 {
            let mixer = scramble(seed ^ (round << 40));
            // The block is played onto a copy, rewound, and compared against
            // the forest it started from, which is left untouched throughout.
            let mut trial = both.forest.clone();
            let roots = both.forest.roots_only();
            let mut before = PathsBefore::before(both.forest.leaves());

            let spends = usize::try_from(mixer % 4).unwrap();
            let mut emptied: Vec<u64> = Vec::new();
            let mut removals = Vec::new();
            for step in 0..spends {
                if both.live.is_empty() {
                    break;
                }
                let at = usize::try_from(scramble(mixer ^ (step as u64)) % both.live.len() as u64)
                    .unwrap();
                let position = both.live[at];
                if emptied.contains(&position) {
                    continue;
                }
                let held = both.archive.leaf_at(position).unwrap();
                let proof = both.archive.prove(position).unwrap();
                emptied.push(position);
                removals.push((position, held, proof));
            }
            if !removals.is_empty() {
                assert!(
                    trial.remove_batch(&removals),
                    "seed {seed}, round {round}: the batch was proved against these very roots"
                );
                for (position, _, _) in &removals {
                    trial.unwatch_spent(*position, &mut before);
                }
            }

            // What fell in this block, appended and watched.
            let landing = scramble(mixer >> 8) % 5;
            let mut landed = Vec::new();
            for step in 0..landing {
                let (position, proof) = trial.add(leaf(next + step)).unwrap();
                trial.watch(position, proof);
                landed.push(next + step);
            }

            // What the window or the ceiling no longer wants, let go of after
            // the additions have already lengthened its path.
            let released = usize::try_from(scramble(mixer >> 16) % 3).unwrap();
            for step in 0..released {
                if both.live.is_empty() {
                    break;
                }
                let at = usize::try_from(
                    scramble(mixer ^ (step as u64) ^ 0x5A5A) % both.live.len() as u64,
                )
                .unwrap();
                trial.unwatch_keeping(both.live[at], &mut before);
            }

            trial.rewind_to(&roots, &removals, &before);

            // Nothing a removal touched is in the record. The whole saving
            // rests on that, so it is asserted here rather than only measured
            // elsewhere: what is written down is what the unwatches above let
            // go of, and never a path a removal brought up to date.
            assert!(
                before.len() <= released,
                "seed {seed}, round {round}: the record holds {} paths against the {released} \
                 the block let go of",
                before.len()
            );
            assert_eq!(
                trial, both.forest,
                "seed {seed}, round {round}: the rewind did not put the forest back"
            );

            // The block is then applied for real, so the next round starts
            // from a forest that has moved.
            let mut discard = PathsBefore::default();
            if !removals.is_empty() {
                assert!(both.forest.remove_batch(&removals));
                for (position, _, _) in &removals {
                    both.forest.unwatch_spent(*position, &mut discard);
                    both.archive.remove(*position);
                    both.live.retain(|held| held != position);
                }
            }
            for index in landed {
                both.add(index);
                next = next.max(index + 1);
            }
        }
    }
}

/// A removal writes down nothing at all, and every path still comes back.
///
/// It used to write down every watched path in the emptied leaf's tree. The
/// step that brought them up to date asked the map for the run of places the
/// tree covers and kept what each one said first, so the size of a record was
/// decided by how much of the watched map happened to sit in one tree. For a
/// forest whose leaf count is a power of two that is all of it, which is the
/// shape a cold set takes every time its leaf count reaches one and repeatedly
/// on either side.
///
/// What replaced it is not a smaller record but no record. A path beside an
/// emptied leaf loses one sibling and no others, and that sibling is the
/// subtree the leaf sat in, which folds out of the leaf and the proof that
/// took it out. Both travel in the block, so the rewind is handed them.
#[test]
fn a_removal_writes_down_nothing_and_every_path_still_comes_back() {
    // A forest of exactly two to the thirteen is one perfect tree, so every
    // watched place in it is one a removal brings up to date.
    const LEAVES: u64 = 8_192;
    let mut archive = Archive::new();
    for index in 0..LEAVES {
        archive.add(leaf(index)).unwrap();
    }
    let mut forest = archive.forest().clone();
    for position in 0..LEAVES {
        forest.watch(position, archive.prove(position).unwrap());
    }

    let untouched = forest.clone();
    let roots = forest.roots_only();
    let mut before = PathsBefore::before(LEAVES);
    let emptied = vec![(4_000u64, leaf(4_000), archive.prove(4_000).unwrap())];
    assert!(forest.remove_batch(&emptied));
    forest.unwatch_spent(4_000, &mut before);

    println!(
        "one removal in a forest of {LEAVES} leaves watching {LEAVES} places wrote down \
         {} paths, {} B",
        before.len(),
        before.bytes_held()
    );
    assert_eq!(
        before.len(),
        0,
        "a removal wrote paths down, which is what made a record grow with the \
         cold set's shape rather than with the block"
    );

    forest.rewind_to(&roots, &emptied, &before);
    assert_eq!(
        forest, untouched,
        "the rewind did not put every watched path in the tree back"
    );
}

/// The same at the numbers the release states, against the figure it stated.
///
/// The stated ceiling was 79.8 MB over a thousand and twenty four records, and
/// it was the cost of letting go of one block's worth of fallen notes: 686
/// paths. What it left out was the removal, and a block that spends a note out
/// of the grace window has one. When the cold set's leaf count makes the
/// window one tree, that used to be a path for every note in the window:
/// eleven times the figure stated, from one ordinary spend.
///
/// The published figures are measured on a real chain, in
/// `cairn-ledger/tests/audit_undo_record_size.rs`. This holds the accumulator's
/// half of it down on its own: at the shipped window, in one tree, a spend
/// costs the place it emptied and nothing else.
#[test]
fn a_spend_out_of_a_full_window_costs_the_place_and_no_paths() {
    /// The ledger's `GRACE_NOTES`.
    const GRACE_NOTES: u64 = 8_192;
    /// Notes one full block pushes out, which is what ages off the window.
    const FALLING: u64 = 686;
    /// Undo records a node keeps.
    const RECORDS: usize = 1_024;

    let mut archive = Archive::new();
    for index in 0..GRACE_NOTES {
        archive.add(leaf(index)).unwrap();
    }
    let mut forest = archive.forest().clone();
    for position in 0..GRACE_NOTES {
        forest.watch(position, archive.prove(position).unwrap());
    }
    let untouched = forest.clone();
    let roots = forest.roots_only();

    // A block that spends one note out of the window and lets go of the run
    // that aged off the far end of it.
    let mut before = PathsBefore::before(GRACE_NOTES);
    let emptied = vec![(1_234u64, leaf(1_234), archive.prove(1_234).unwrap())];
    assert!(forest.remove_batch(&emptied));
    forest.unwatch_spent(1_234, &mut before);
    let spend_cost = before.bytes_held();
    for position in (GRACE_NOTES - FALLING)..GRACE_NOTES {
        forest.unwatch_keeping(position, &mut before);
    }

    let held = before.bytes_held();
    println!(
        "a spend out of a window of {GRACE_NOTES} in one tree wrote down no paths and \
         {spend_cost} B, which is the place it emptied; with the {FALLING} paths that \
         aged off alongside it, {} paths and {held} B, {:.1} MB over {RECORDS} records",
        before.len(),
        (held * RECORDS) as f64 / 1e6
    );
    assert_eq!(
        spend_cost,
        std::mem::size_of::<u64>(),
        "a spend out of a window sitting in one tree cost {spend_cost} B, and the place \
         it emptied is all it should cost"
    );
    assert_eq!(before.len(), FALLING as usize);

    forest.rewind_to(&roots, &emptied, &before);
    assert_eq!(forest, untouched);
}

/// The same again for a node that follows an owner, whose notes are scattered
/// rather than consecutive.
///
/// This is the worst shape there is. The saving a shared sibling buys comes
/// from two places near each other parting company low down and sharing every
/// step above it, and one owner's notes fell at whatever times that owner was
/// paid, so they are spread across the set and share almost nothing. A removal
/// in the tree they sit in used to write down a nearly full path for each, and
/// at the `WATCHED_NOTES` ceiling that was seven and a half megabytes for one
/// block: seven and a half gigabytes over the records a node keeps, which is
/// where the whole repair had started.
///
/// It now costs what the block let go of, and a block lets go of a followed
/// path only when the ceiling displaces one.
#[test]
fn a_removal_beside_a_followed_owners_notes_costs_nothing() {
    /// The ledger's `WATCHED_NOTES`.
    const FOLLOWED: u64 = 8_192;
    /// Undo records a node keeps.
    const RECORDS: usize = 1_024;
    /// A cold set of a million notes, which is a path of twenty hashes.
    const DEPTH: usize = 20;

    let leaves = 1u64 << DEPTH;
    let mut archive = Archive::new();
    for index in 0..leaves {
        archive.add(leaf(index)).unwrap();
    }
    let mut forest = archive.forest().clone();
    let places: Vec<u64> = (0..FOLLOWED)
        .map(|index| scramble(index) % leaves)
        .collect();
    for position in &places {
        forest.watch(*position, archive.prove(*position).unwrap());
    }
    let untouched = forest.clone();
    let roots = forest.roots_only();
    let watching = forest.watched_count();

    // One spend, in the one tree this leaf count makes, so every followed path
    // there is a path the removal brings up to date.
    let mut before = PathsBefore::before(leaves);
    let spent = places[0];
    let emptied = vec![(spent, leaf(spent), archive.prove(spent).unwrap())];
    assert!(forest.remove_batch(&emptied));
    forest.unwatch_spent(spent, &mut before);

    let held = before.bytes_held();
    println!(
        "a node following {watching} scattered notes, one spend among them: \
         {} paths written down, {held} B, {:.1} MB over {RECORDS} records",
        before.len(),
        (held * RECORDS) as f64 / 1e6
    );
    assert_eq!(
        before.len(),
        0,
        "the worst shape there is still wrote {held} B down for one spend"
    );

    forest.rewind_to(&roots, &emptied, &before);
    assert_eq!(forest, untouched);
}

/// A path a holder lets go of for its own reasons is the one thing a record
/// pays for, and it comes back exactly.
///
/// This is what is left after the three above: the grace window aged past a
/// note, or a followed owner's ceiling displaced one. Nothing in the block
/// says what those paths were, so they are written down, and a record's whole
/// size is how many of them there are.
#[test]
fn what_a_holder_lets_go_of_is_what_a_record_costs() {
    /// The ledger's `WATCHED_NOTES`, displaced one block's worth at a time.
    const FOLLOWED: u64 = 8_192;
    const DISPLACED: u64 = 686;
    const RECORDS: usize = 1_024;
    const DEPTH: usize = 20;

    let leaves = 1u64 << DEPTH;
    let mut archive = Archive::new();
    for index in 0..leaves {
        archive.add(leaf(index)).unwrap();
    }
    let mut forest = archive.forest().clone();
    let places: Vec<u64> = (0..FOLLOWED)
        .map(|index| scramble(index) % leaves)
        .collect();
    for position in &places {
        forest.watch(*position, archive.prove(*position).unwrap());
    }
    let untouched = forest.clone();
    let roots = forest.roots_only();

    let mut before = PathsBefore::before(leaves);
    for position in places.iter().take(DISPLACED as usize) {
        forest.unwatch_keeping(*position, &mut before);
    }
    let held = before.bytes_held();
    println!(
        "letting go of {DISPLACED} scattered paths at depth {DEPTH}: {} written down, \
         {held} B, {:.1} MB over {RECORDS} records",
        before.len(),
        (held * RECORDS) as f64 / 1e6
    );

    forest.rewind_to(&roots, &[], &before);
    assert_eq!(
        forest, untouched,
        "a path let go of did not come back the path it was"
    );
}

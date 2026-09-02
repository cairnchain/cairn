//! A rewind at cold set shape puts back every path a clone would have.
//!
//! `audit_rewind_delta.rs` checks the delta rewind differentially, but on
//! forests far smaller than the one a live node carries. This runs the same
//! comparison at the shape the cold set actually reaches, because a rewind
//! that is right for eight leaves and wrong for eight million is a rewind
//! nothing in the suite would have caught.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use cairn_accumulator::forest::{forest_leaf, PathsBefore};
use cairn_accumulator::{Archive, Forest};
use cairn_primitives::Hash32;

fn leaf(index: u64) -> Hash32 {
    forest_leaf(&index.to_le_bytes())
}

fn scramble(seed: u64) -> u64 {
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

struct Both {
    forest: Forest,
    archive: Archive,
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

    fn add(&mut self, index: u64, watch_one_in: u64) -> u64 {
        let (position, proof) = self.forest.add(leaf(index)).unwrap();
        self.archive.add(leaf(index)).unwrap();
        self.live.push(position);
        if scramble(position ^ 0x0BAD) % watch_one_in != 0 {
            self.forest.watch(position, proof);
        }
        position
    }
}

/// Deep trees, many watched places, several removals per block, over enough
/// rounds that the leaf count crosses powers of two in both directions.
#[test]
fn a_rewind_at_cold_set_shape_puts_back_every_path_a_clone_would_have() {
    for seed in 0..80u64 {
        let mut both = Both::new();
        // Big enough that a tree is ten deep and the forest holds several
        // trees of different heights.
        let opening = 4_000 + (scramble(seed) % 12_000);
        for index in 0..opening {
            both.add(index, 4);
        }
        let mut next = opening;

        for round in 0..60u64 {
            let mixer = scramble(seed ^ (round << 40));
            let mut trial = both.forest.clone();
            let roots = both.forest.roots_only();
            let mut before = PathsBefore::before(both.forest.leaves());

            // Up to sixteen spends in one block, which is what a busy block
            // does, and which is what puts several emptied leaves inside the
            // same tree at different depths.
            let spends = usize::try_from(mixer % 17).unwrap();
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
                assert!(trial.remove_batch(&removals), "seed {seed} round {round}");
                for (position, _, _) in &removals {
                    trial.unwatch_spent(*position, &mut before);
                }
            }

            let landing = scramble(mixer >> 8) % 40;
            let mut landed = Vec::new();
            for step in 0..landing {
                let (position, proof) = trial.add(leaf(next + step)).unwrap();
                trial.watch(position, proof);
                landed.push(next + step);
            }

            let released = usize::try_from(scramble(mixer >> 16) % 9).unwrap();
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

            assert!(
                before.len() <= released,
                "seed {seed} round {round}: record holds {} paths for {released} released",
                before.len()
            );
            assert_eq!(
                trial,
                both.forest,
                "seed {seed} round {round}: the rewind did not put the forest back \
                 ({} removals, {landing} additions, {released} released, {} leaves)",
                removals.len(),
                both.forest.leaves()
            );

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
                both.add(index, 4);
                next = next.max(index + 1);
            }
        }
    }
}

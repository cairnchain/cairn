//! AUDIT: the one property `check_the_gaps` rests on.
//!
//! `least_work_over` and `most_work_over` are written from the retarget's own
//! clamp: the difficulty may fall by at most `MAX_RETARGET_FACTOR` a block and
//! never below `MIN_DIFFICULTY`, and may rise by at most the same factor. If
//! `next_difficulty` ever steps outside that for any parent a chain could
//! actually present, the weighing refuses an honest chain, which is worse than
//! the hole it closed.
//!
//! The retarget was rewritten in the testnet-8 wave as ASERT: a fixed point
//! exponent, a floored division, a cubic, shifts both ways and saturation.
//! That is new arithmetic on a consensus path, so this walks it over the
//! parents a hostile or unlucky chain would produce, on every block time a
//! network might run, and checks the bound at every one, along with
//! determinism.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_ledger::block::HeaderSummary;
use cairn_ledger::pow::{
    next_difficulty, Origin, HALF_LIFE_IN_BLOCKS, MAX_RETARGET_FACTOR, MIN_DIFFICULTY,
    RECENT_HEADERS,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, limit: u64) -> u64 {
        if limit == 0 {
            0
        } else {
            self.next() % limit
        }
    }
}

/// What the two bounds in `sampling.rs` assume of one step.
fn within_the_clamp(previous: u64, next: u64) -> bool {
    let previous = previous.max(MIN_DIFFICULTY);
    let floor = (u128::from(previous) / MAX_RETARGET_FACTOR).max(u128::from(MIN_DIFFICULTY));
    let cap =
        u64::try_from(u128::from(previous).saturating_mul(MAX_RETARGET_FACTOR)).unwrap_or(u64::MAX);
    u128::from(next) >= floor && next <= cap
}

/// Every parent a chain could show, random and extreme, and the clamp holds at
/// each of them.
#[test]
fn the_retarget_never_leaves_the_clamp_the_weighing_assumes() {
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let targets = [0u64, 1, 5, 60, 600, 86_400, u64::MAX];

    for case in 0..50_000u64 {
        let target = targets[usize::try_from(rng.below(7)).unwrap()];
        let half_life = target.saturating_mul(HALF_LIFE_IN_BLOCKS);
        let height_shape = rng.below(4);
        let time_shape = rng.below(6);
        let difficulty_shape = rng.below(4);

        let origin = Origin {
            timestamp: match rng.below(3) {
                0 => 0,
                1 => 1_790_800_858,
                _ => rng.next(),
            },
            difficulty: match rng.below(4) {
                0 => 0,
                1 => 1,
                2 => u64::MAX,
                _ => rng.next(),
            },
        };
        let height = match height_shape {
            0 => rng.below(100),
            1 => rng.below(1 << 30),
            2 => u64::MAX - rng.below(1_000),
            _ => rng.next(),
        };
        let on_time = origin
            .timestamp
            .saturating_add(target.saturating_mul(height));
        let timestamp = match time_shape {
            // On schedule.
            0 => on_time,
            // Within a few half lives either side, where the fraction decides.
            1 => {
                let spread = half_life.saturating_mul(8).max(1);
                on_time
                    .saturating_sub(spread / 2)
                    .saturating_add(rng.below(spread))
            }
            // Far behind, a stall.
            2 => on_time.saturating_add(half_life.saturating_mul(1_000)),
            // Far ahead, or before the network opened.
            3 => rng.below(origin.timestamp.max(1)),
            // Exactly on a whole number of half lives, where the fraction is
            // nought and the shift alone answers.
            4 => on_time.saturating_add(half_life.saturating_mul(rng.below(80))),
            // At the extremes of what a u64 second holds.
            _ => {
                if rng.next() % 2 == 0 {
                    u64::MAX - rng.below(1_000)
                } else {
                    rng.below(1_000)
                }
            }
        };
        let difficulty = match difficulty_shape {
            0 => rng.below(3),
            1 => u64::MAX - rng.below(3),
            2 => 1 << 27,
            _ => rng.next(),
        };
        let parent = HeaderSummary {
            height,
            timestamp,
            difficulty,
        };

        let answer = next_difficulty(&parent, origin, target);
        assert_eq!(
            answer,
            next_difficulty(&parent, origin, target),
            "case {case} is not deterministic"
        );
        assert!(answer >= MIN_DIFFICULTY, "case {case} fell below the floor");
        assert!(
            within_the_clamp(difficulty, answer),
            "case {case}: {difficulty} -> {answer} leaves the clamp the weighing assumes \
             (target {target}, height shape {height_shape}, time shape {time_shape}, \
             difficulty shape {difficulty_shape})"
        );
    }
}

/// A young chain on schedule is asked its first block's difficulty at every
/// height, from the first block's child up past the window a node keeps.
///
/// The moving average this replaced read a window that was short on a young
/// chain, and both sides of a handover had to agree about how short. The rule
/// now reads the parent and the network's first block and nothing else, so
/// what a young chain shows it is the same question as an old one.
#[test]
fn a_young_chain_on_schedule_is_asked_what_its_first_block_carried() {
    let target = 60u64;
    let origin = Origin {
        timestamp: 1_000,
        difficulty: 4_096,
    };
    for height in 0..=RECENT_HEADERS as u64 + 10 {
        let parent = HeaderSummary {
            height,
            timestamp: 1_000 + height * target,
            difficulty: 4_096,
        };
        let answer = next_difficulty(&parent, origin, target);
        assert_eq!(answer, 4_096, "at height {height}");
        assert!(within_the_clamp(parent.difficulty, answer));
    }
}

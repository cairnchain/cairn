//! AUDIT: the one property `check_the_gaps` rests on.
//!
//! `least_work_over` and `most_work_over` are written from the retarget's own
//! clamp: the difficulty may fall by at most `MAX_RETARGET_FACTOR` a block and
//! never below `MIN_DIFFICULTY`, and may rise by at most the same factor. If
//! `next_difficulty` ever steps outside that for any window a chain could
//! actually present, the weighing refuses an honest chain, which is worse than
//! the hole it closed.
//!
//! The retarget was rewritten this morning to read solve times as signed
//! values along a timeline of its own. That is new arithmetic on a consensus
//! path, so this walks it over the windows a hostile or unlucky chain would
//! produce and checks the bound at every step, along with determinism.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_ledger::block::HeaderSummary;
use cairn_ledger::pow::{
    next_difficulty, DIFFICULTY_WINDOW, MAX_RETARGET_FACTOR, MIN_DIFFICULTY, RECENT_HEADERS,
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
    let floor = (u128::from(previous) / MAX_RETARGET_FACTOR).max(u128::from(MIN_DIFFICULTY));
    let cap =
        u64::try_from(u128::from(previous).saturating_mul(MAX_RETARGET_FACTOR)).unwrap_or(u64::MAX);
    u128::from(next) >= floor && next <= cap
}

/// Every window a chain could show, random and extreme, and the clamp holds at
/// each of them.
#[test]
fn the_retarget_never_leaves_the_clamp_the_weighing_assumes() {
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let targets = [1u64, 5, 60, 600, 86_400];

    for case in 0..20_000u64 {
        let target = targets[usize::try_from(rng.below(5)).unwrap()];
        let len = usize::try_from(rng.below(u64::try_from(RECENT_HEADERS).unwrap() + 3)).unwrap();
        let difficulty_shape = rng.below(4);
        let time_shape = rng.below(6);

        let mut window = Vec::with_capacity(len);
        let mut clock: u64 = 1_000_000;
        let mut difficulty: u64 = match difficulty_shape {
            0 => 1,
            1 => u64::MAX,
            2 => 1 << 27,
            _ => rng.next().max(1),
        };
        for height in 0..len {
            clock = match time_shape {
                // On schedule.
                0 => clock.saturating_add(target),
                // Stalled: every gap enormous.
                1 => clock.saturating_add(target.saturating_mul(1_000)),
                // Everything at one instant.
                2 => clock,
                // Backwards.
                3 => clock.saturating_sub(rng.below(target.saturating_mul(20).max(1))),
                // Wild, in both directions.
                4 => {
                    let jump = rng.below(target.saturating_mul(100).max(1));
                    if rng.next() % 2 == 0 {
                        clock.saturating_add(jump)
                    } else {
                        clock.saturating_sub(jump)
                    }
                }
                // At the extremes of what a u64 second holds.
                _ => {
                    if rng.next() % 2 == 0 {
                        u64::MAX - rng.below(1_000)
                    } else {
                        rng.below(1_000)
                    }
                }
            };
            // A difficulty run that itself moves as fast as the rule allows.
            difficulty = match rng.below(3) {
                0 => difficulty.saturating_mul(4).max(1),
                1 => (difficulty / 4).max(1),
                _ => difficulty,
            };
            window.push(HeaderSummary {
                height: height as u64,
                timestamp: clock,
                difficulty,
            });
        }

        let answer = next_difficulty(&window, target);
        assert_eq!(
            answer,
            next_difficulty(&window, target),
            "case {case} is not deterministic"
        );
        assert!(answer >= MIN_DIFFICULTY, "case {case} fell below the floor");
        if let Some(last) = window.last() {
            assert!(
                within_the_clamp(last.difficulty, answer),
                "case {case}: {} -> {answer} leaves the clamp the weighing assumes \
                 (target {target}, {} headers, difficulty shape {difficulty_shape}, \
                 time shape {time_shape})",
                last.difficulty,
                window.len()
            );
        }
    }
}

/// The window the rule actually reads is the last `DIFFICULTY_WINDOW + 1`
/// headers, and nothing longer changes the answer.
///
/// This matters because a handover supplies its own window, and `check_buried`
/// walks the run against it: if the answer depended on how many headers were
/// handed over above the minimum, two honest nodes with different amounts of
/// history would demand different difficulties of the same block.
#[test]
fn a_window_longer_than_the_rule_reads_gives_the_same_answer() {
    let target = 60u64;
    let long: Vec<HeaderSummary> = (0..300u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: 1_000 + height * target,
            difficulty: 1_000,
        })
        .collect();
    let cut = long.len() - (DIFFICULTY_WINDOW + 1);
    assert_eq!(
        next_difficulty(&long, target),
        next_difficulty(&long[cut..], target),
        "the rule reads more than the window it says it does"
    );
    // And every length in between agrees with the full one, so a sender that
    // hands over more than the minimum cannot move the demand.
    for from in 0..cut {
        assert_eq!(
            next_difficulty(&long[from..], target),
            next_difficulty(&long, target),
            "a window starting at {from} disagrees"
        );
    }
}

/// A window shorter than the rule wants is what a young chain has, and both
/// sides have to agree about it too. `check_recent` lets a sender give more
/// than the minimum, so the answer must not depend on how many.
#[test]
fn a_short_window_agrees_with_itself() {
    let target = 60u64;
    for len in 1..=RECENT_HEADERS {
        let window: Vec<HeaderSummary> = (0..len as u64)
            .map(|height| HeaderSummary {
                height,
                timestamp: 1_000 + height * target,
                difficulty: 4_096,
            })
            .collect();
        let answer = next_difficulty(&window, target);
        assert!(answer >= MIN_DIFFICULTY);
        assert!(
            within_the_clamp(window[len - 1].difficulty, answer),
            "a window of {len} left the clamp: {answer}"
        );
    }
}

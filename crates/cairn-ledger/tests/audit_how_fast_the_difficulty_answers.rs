//! AUDIT: how long the retarget really takes to answer a change in hash rate.
//!
//! The doc on `DIFFICULTY_WINDOW` said "within minutes" and the README said
//! "a handful of blocks". The window alone is ninety blocks at a minute
//! apiece, which is an hour and a half before the loop is even closed, so
//! neither could be right on any reading. Nothing in this tree had ever
//! measured it: `audit_moving_difficulty.rs` runs seventy two blocks, which
//! never fills the window, and every other retarget test asks what one
//! retarget does rather than what a run of them settles at.
//!
//! What is measured here is the closed loop. A chain warmed to a full window
//! on schedule, then a hash rate that changes and does not change back, with
//! each block taking as long as its own difficulty demands of the rate that
//! remains. Every number is a block count or a difficulty ratio, and both are
//! decided by arithmetic rather than by the machine: the chain time quoted is
//! the sum of the fixture's own solve times, not how long the test ran.
//!
//! The response is slow because the weights are what they are. They run 1 to
//! 90 and sum to 4095, so the newest gap is 90/4095 of the measurement, about
//! 2.2 percent, and one block arriving at the clamp ceiling moves the
//! difficulty by about a tenth rather than by the six times it claims. That
//! damping is what a miner's dishonest timestamp cannot get past, and it is
//! the same damping that makes an honest answer take hours.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_ledger::block::HeaderSummary;
use cairn_ledger::pow::{next_difficulty, DIFFICULTY_WINDOW, RECENT_HEADERS};
use cairn_ledger::validation::ConsensusParams;

/// The source of the prose this file guards.
const POW: &str = include_str!("../src/pow.rs");
const README: &str = include_str!("../../../README.md");

/// Seconds a network aims for between blocks.
const TARGET: u64 = 60;

/// The difficulty the warmed chain sits at.
///
/// Round, and large enough that a ratio is readable to six figures. The loop
/// is scale free: every quantity below is this number times a ratio.
const STEADY: u64 = 1_000_000;

/// A chain warmed to a full window, exactly on schedule, at one difficulty.
///
/// `next_difficulty` gives this chain back its own difficulty to the unit: the
/// weights 1 to 90 sum to 4095, and 4095 gaps of the target is exactly what
/// the retarget expects. So the loop below opens from rest, and every move it
/// makes afterwards is the answer to the change and not to the fixture.
fn warmed() -> Vec<HeaderSummary> {
    (0..RECENT_HEADERS as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: 1_000 + height * TARGET,
            difficulty: STEADY,
        })
        .collect()
}

/// How long a block of this difficulty takes once the hash rate has fallen by
/// `loss`.
///
/// Whole seconds, rounded, because a header carries whole seconds. The rate is
/// the one that made [`STEADY`] take [`TARGET`], divided by `loss`.
fn solve_seconds(difficulty: u64, loss: u64) -> u64 {
    ((difficulty * TARGET * loss + STEADY / 2) / STEADY).max(1)
}

/// What it took to bring the difficulty down to `milestone`.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    blocks: u64,
    /// Seconds of chain time, summed from the fixture's own solve times.
    seconds: u64,
}

impl Answer {
    fn minutes(&self) -> u64 {
        self.seconds / 60
    }
}

/// Runs the loop until the retarget demands `milestone` or less.
///
/// Deterministic: each block takes exactly as long as its difficulty says it
/// should, with no variance, so the curve is the mean response and the block
/// counts are reproducible anywhere.
fn answering(loss: u64, milestone: u64) -> Answer {
    let mut window = warmed();
    assert_eq!(
        next_difficulty(&window, TARGET),
        STEADY,
        "a chain on schedule has to be left alone, or the loop opens moving"
    );

    let mut height = RECENT_HEADERS as u64;
    let mut clock = window.last().unwrap().timestamp;
    let opened_at = clock;
    for blocks in 1..=10_000u64 {
        let difficulty = next_difficulty(&window, TARGET);
        clock += solve_seconds(difficulty, loss);
        window.push(HeaderSummary {
            height,
            timestamp: clock,
            difficulty,
        });
        height += 1;
        if window.len() > RECENT_HEADERS {
            window.remove(0);
        }
        if next_difficulty(&window, TARGET) <= milestone {
            return Answer {
                blocks,
                seconds: clock - opened_at,
            };
        }
    }
    panic!("the difficulty never reached {milestone}, which is the finding and worse");
}

/// The fixture's target is the one a network actually runs at, or none of the
/// minutes below mean anything.
#[test]
fn the_fixture_runs_at_the_target_a_network_uses() {
    assert_eq!(ConsensusParams::testnet().target_block_time, TARGET);
    assert_eq!(DIFFICULTY_WINDOW, 90);
    assert_eq!(RECENT_HEADERS, DIFFICULTY_WINDOW + 1);
}

/// A hash rate that halves. The correction wanted is a difficulty of 0.5x.
#[test]
fn a_halved_hash_rate_is_half_answered_in_twenty_two_blocks() {
    assert_eq!(
        answering(2, STEADY / 2 + STEADY / 4),
        Answer {
            blocks: 22,
            seconds: 2_247
        },
        "half of a doubling correction"
    );
    let ninety_percent = answering(2, 550_000);
    assert_eq!(
        ninety_percent,
        Answer {
            blocks: 90,
            seconds: 7_345
        },
        "ninety percent of a doubling correction"
    );
    assert_eq!(
        ninety_percent.minutes(),
        122,
        "which is the two hours the doc now states"
    );
}

/// A hash rate that falls tenfold. The correction wanted is 0.1x.
///
/// Ninety percent of it is a difficulty of 0.19x, and it takes an afternoon.
#[test]
fn a_tenfold_loss_is_ninety_percent_answered_in_sixty_four_blocks() {
    let ninety_percent = answering(10, 190_000);
    assert_eq!(
        ninety_percent,
        Answer {
            blocks: 64,
            seconds: 13_080
        },
        "ninety percent of a tenfold correction"
    );
    assert_eq!(ninety_percent.minutes(), 218, "three and a half hours");
}

/// The word the doc used to use, refuted at the scale it would have to mean.
///
/// Ten minutes is where "minutes" has to mean something. Ten minutes into a
/// halving, a fifth of the correction has been made; the other four fifths
/// take the two hours measured above.
#[test]
fn ten_minutes_into_a_halving_is_a_fifth_of_an_answer() {
    let a_fifth = answering(2, STEADY - (STEADY - STEADY / 2) / 5);
    assert_eq!(
        a_fifth,
        Answer {
            blocks: 6,
            seconds: 685
        },
        "a fifth of a doubling correction"
    );
    assert!(
        a_fifth.seconds > 600,
        "ten minutes of chain time does not even buy a fifth: {a_fifth:?}"
    );
}

/// Why the answer is slow, stated as the property it is.
///
/// The newest gap carries 90 of the 4095 weight, so one block arriving late
/// moves the difficulty by about a tenth however late it is. The clamp is what
/// makes "however late" true: six times the target and a hundred times it are
/// the same block to the retarget.
#[test]
fn one_late_block_moves_the_difficulty_by_about_a_tenth() {
    let weights: u64 = (1..=DIFFICULTY_WINDOW as u64).sum();
    assert_eq!(weights, 4_095);

    let mut moved = Vec::new();
    for lateness in [6u64, 100] {
        let mut window = warmed();
        let last = *window.last().unwrap();
        window.remove(0);
        window.push(HeaderSummary {
            height: last.height + 1,
            timestamp: last.timestamp + lateness * TARGET,
            difficulty: STEADY,
        });
        moved.push(next_difficulty(&window, TARGET));
    }
    assert_eq!(
        moved[0], moved[1],
        "the clamp makes six times the target and a hundred times it the same \
         block, which is the whole point of having it"
    );
    assert_eq!(
        moved[0], 900_990,
        "one late block moves the difficulty by about a tenth"
    );
}

/// The prose says what the measurement says.
///
/// This project has now shipped fifteen published figures that were wrong in
/// the instrument rather than in the thing measured, and this one is the
/// sixteenth: the doc claimed minutes for something that takes hours, and no
/// test in the tree had ever run the loop that would have said so.
#[test]
fn the_prose_says_what_the_measurement_says() {
    let half = answering(2, STEADY / 2 + STEADY / 4);
    let ninety = answering(2, 550_000);
    let tenfold = answering(10, 190_000);

    for quoted in [
        format!("half of it after {} blocks", half.blocks),
        format!("{} minutes of chain time", half.minutes()),
        format!("ninety percent after {} blocks", ninety.blocks),
        format!("after {} blocks and three and a half hours", tenfold.blocks),
    ] {
        assert!(
            POW.contains(&quoted),
            "the doc on DIFFICULTY_WINDOW no longer says `{quoted}`"
        );
    }
    assert!(
        !POW.contains("within minutes"),
        "the claim this file exists to refute is back in pow.rs"
    );
    assert!(
        !README.contains("retargets in a handful of blocks"),
        "the README is back to claiming a handful of blocks"
    );
    assert!(
        README.contains("a difficulty that answers a halving of hash rate in about two hours"),
        "the README no longer states the measured answer time"
    );
    assert_eq!(
        (ninety.seconds + 1_800) / 3_600,
        2,
        "the README says two hours and the measurement has to agree"
    );
}

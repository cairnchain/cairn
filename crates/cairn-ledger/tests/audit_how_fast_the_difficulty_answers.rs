//! AUDIT: how long the retarget really takes to answer a change in hash rate.
//!
//! The doc on the retarget's window once said "within minutes" and the README
//! said "a handful of blocks", and neither could be right on any reading of
//! the moving average it then was. Nothing in this tree had measured it until
//! this file ran the closed loop, and it is the instrument the figures in
//! `pow.rs` and the README come from.
//!
//! What is measured is the closed loop. A chain on schedule, then a hash rate
//! that changes and does not change back, with each block taking as long as
//! its own difficulty demands of the rate that remains. Every number is a
//! block count or a difficulty ratio, and both are decided by arithmetic
//! rather than by the machine: the chain time quoted is the sum of the
//! fixture's own solve times, not how long the test ran.
//!
//! The retarget is ASERT now, and the answer has a shape that can be said in
//! one line: the chain falls behind its schedule while its blocks are slow,
//! and every half life it falls behind halves the difficulty. A halving of
//! the hash rate is answered once the chain is a half life behind, which at
//! the rate that remains takes a little under two hours of chain time.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_ledger::block::HeaderSummary;
use cairn_ledger::pow::{next_difficulty, Origin, HALF_LIFE_IN_BLOCKS, RECENT_HEADERS};
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

/// Where the warmed chain's schedule starts: its first block, at [`STEADY`].
const ORIGIN: Origin = Origin {
    timestamp: 1_000,
    difficulty: STEADY,
};

/// A chain warmed to a full window, exactly on schedule, at one difficulty.
///
/// `next_difficulty` gives this chain back its own difficulty to the unit,
/// since a chain on schedule is asked what its first block carried. So the
/// loop below opens from rest, and every move it makes afterwards is the
/// answer to the change and not to the fixture.
fn warmed() -> Vec<HeaderSummary> {
    (0..RECENT_HEADERS as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: 1_000 + height * TARGET,
            difficulty: STEADY,
        })
        .collect()
}

fn asked(window: &[HeaderSummary]) -> u64 {
    next_difficulty(window.last().unwrap(), ORIGIN, TARGET)
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
        asked(&window),
        STEADY,
        "a chain on schedule has to be left alone, or the loop opens moving"
    );

    let mut height = RECENT_HEADERS as u64;
    let mut clock = window.last().unwrap().timestamp;
    let opened_at = clock;
    for blocks in 1..=10_000u64 {
        let difficulty = asked(&window);
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
        if asked(&window) <= milestone {
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
    assert_eq!(HALF_LIFE_IN_BLOCKS, 60, "an hour at this target");
}

/// A hash rate that halves. The correction wanted is a difficulty of 0.5x.
///
/// Half of it is the chain falling behind by `log2(4/3)` half lives, which at
/// blocks that take up to twice the target is exactly an hour of chain time.
/// Under the moving average it was 22 blocks and 37 minutes; the moving
/// average answered small changes faster and paid for it in noise, which is
/// the trade the half life was chosen on.
#[test]
fn a_halved_hash_rate_is_half_answered_in_thirty_five_blocks() {
    assert_eq!(
        answering(2, STEADY / 2 + STEADY / 4),
        Answer {
            blocks: 35,
            seconds: 3_601
        },
        "half of a doubling correction"
    );
    let ninety_percent = answering(2, 550_000);
    assert_eq!(
        ninety_percent,
        Answer {
            blocks: 147,
            seconds: 11_928
        },
        "ninety percent of a doubling correction"
    );
    assert_eq!(
        ninety_percent.minutes(),
        198,
        "which is the three hours and a quarter the doc states"
    );
}

/// A hash rate that falls tenfold. The correction wanted is 0.1x.
///
/// Ninety percent of it is a difficulty of 0.19x, and it takes an afternoon:
/// fewer blocks than a halving, since each one is slower and puts the chain
/// further behind. Under the moving average it was 64 blocks and 218 minutes.
#[test]
fn a_tenfold_loss_is_ninety_percent_answered_in_fifty_five_blocks() {
    let ninety_percent = answering(10, 190_000);
    assert_eq!(
        ninety_percent,
        Answer {
            blocks: 55,
            seconds: 11_960
        },
        "ninety percent of a tenfold correction"
    );
    assert_eq!(ninety_percent.minutes(), 199, "three hours and a quarter");
}

/// The word the doc once used, refuted at the scale it would have to mean.
///
/// Ten minutes is where "minutes" has to mean something. Ten minutes into a
/// halving, not even a fifth of the correction has been made.
#[test]
fn ten_minutes_into_a_halving_is_less_than_a_fifth_of_an_answer() {
    let a_fifth = answering(2, STEADY - (STEADY - STEADY / 2) / 5);
    assert_eq!(
        a_fifth,
        Answer {
            blocks: 11,
            seconds: 1_251
        },
        "a fifth of a doubling correction"
    );
    assert!(
        a_fifth.seconds > 600,
        "ten minutes of chain time does not even buy a fifth: {a_fifth:?}"
    );
}

/// What one block dated late is worth, stated as the property it is.
///
/// The moving average damped a late block to a tenth of a move however late
/// it was, which is what a miner's dishonest timestamp could not get past and
/// what made an honest answer take hours. This rule reads the parent's
/// timestamp against the schedule and nothing else, so a block dated ten
/// targets late, the most a reader takes ahead of its clock, lowers the next
/// difficulty by `2^(-10/60)`, about eleven percent, and the next honest block,
/// dated by a real clock, takes the whole of it back: nothing remembers the
/// path.
#[test]
fn one_late_block_lowers_the_next_by_its_lateness_and_an_honest_one_takes_it_back() {
    let mut window = warmed();
    let last = *window.last().unwrap();
    window.remove(0);
    window.push(HeaderSummary {
        height: last.height + 1,
        timestamp: last.timestamp + TARGET + 10 * TARGET,
        difficulty: STEADY,
    });
    let late = asked(&window);
    assert_eq!(late, 890_991, "ten targets late is 2^(-1/6)");

    let last = *window.last().unwrap();
    window.remove(0);
    window.push(HeaderSummary {
        height: last.height + 1,
        timestamp: ORIGIN.timestamp + (last.height + 1) * TARGET,
        difficulty: late,
    });
    assert_eq!(
        asked(&window),
        STEADY,
        "an honest block back on schedule asks what the schedule asks"
    );
}

/// The prose says what the measurement says.
///
/// This project has shipped more than fifteen published figures that were
/// wrong in the instrument rather than in the thing measured, and one of them
/// was here: the doc claimed minutes for something that takes hours, and no
/// test in the tree had ever run the loop that would have said so.
#[test]
fn the_prose_says_what_the_measurement_says() {
    let half = answering(2, STEADY / 2 + STEADY / 4);
    let ninety = answering(2, 550_000);
    let tenfold = answering(10, 190_000);

    for quoted in [
        format!("half of its answer after {} blocks", half.blocks),
        format!("{} minutes of chain time", half.minutes()),
        format!("ninety percent after {} blocks", ninety.blocks),
        format!(
            "after {} blocks and three hours and a quarter",
            tenfold.blocks
        ),
    ] {
        assert!(
            POW.contains(&quoted),
            "the doc on HALF_LIFE_IN_BLOCKS no longer says `{quoted}`"
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
        README.contains("a difficulty that answers a halving of hash rate in about three hours"),
        "the README no longer states the measured answer time"
    );
    assert_eq!(
        (ninety.seconds + 1_800) / 3_600,
        3,
        "the README says three hours and the measurement has to agree"
    );
}

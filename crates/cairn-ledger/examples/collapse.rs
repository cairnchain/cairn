//! How long a chain takes to recover when most of its hash rate goes away.
//!
//! A network with few miners loses a large share of its hash rate whenever
//! one of them stops, and blocks then take as much longer to find as the
//! remaining share is smaller. The difficulty comes down, but only as blocks
//! arrive, and blocks are exactly what has become scarce. That is the shape
//! of the problem: the chain has to spend the slow blocks to earn the fast
//! ones back.
//!
//! Some chains add a rule that drops the difficulty outright after a long
//! enough gap. Cairn does not, and will not: a miner who can choose the
//! timestamp can then claim the gap, and the rule meant to rescue a stalled
//! chain becomes a way to mine it cheaply. What this measures is the cost of
//! not having that rule.
//!
//! Run with `cargo run --release -p cairn-ledger --example collapse`.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use cairn_ledger::block::HeaderSummary;
use cairn_ledger::pow::{next_difficulty, DIFFICULTY_WINDOW};

/// The block time every network in this repository targets.
const TARGET: u64 = 60;

/// Shares of the hash rate left after the collapse.
const SHARES: [f64; 5] = [0.5, 0.2, 0.1, 0.05, 0.01];

/// Blocks to run before the collapse, so the window is full and the chain is
/// exactly on schedule.
const SETTLED: usize = DIFFICULTY_WINDOW * 2;

fn main() {
    println!("Recovering from a fall in hash rate");
    println!("target block time {TARGET} s, window {DIFFICULTY_WINDOW} blocks\n");

    println!(
        "{:>8}  {:>12}  {:>10}  {:>12}  {:>12}",
        "left", "first block", "blocks", "to half", "to normal"
    );
    println!("{}", "-".repeat(62));

    for share in SHARES {
        let run = recover(share);
        println!(
            "{:>7.0}%  {:>12}  {:>10}  {:>12}  {:>12}",
            share * 100.0,
            duration(run.first_block),
            run.blocks,
            duration(run.to_half),
            duration(run.to_normal),
        );
    }

    println!("\nleft         the share of the hash rate still mining");
    println!("first block  how long the block after the collapse takes");
    println!("blocks       blocks mined before the chain is back on schedule");
    println!("to half      until a block takes twice the target rather than more");
    println!("to normal    until a block takes about the target again");
}

struct Recovery {
    /// How long the first block after the collapse took.
    first_block: f64,
    /// Blocks mined before solve times came back to the target.
    blocks: usize,
    /// Seconds until a block takes no more than twice the target.
    to_half: f64,
    /// Seconds until a block takes about the target again.
    to_normal: f64,
}

/// Runs a chain at a steady rate, removes all but `share` of the hash rate,
/// and mines on until blocks take about the target time again.
///
/// Solve time is taken as its expectation rather than drawn at random. The
/// question here is how the rule behaves, not how luck does, and an average
/// answered exactly is easier to check by hand than a distribution.
fn recover(share: f64) -> Recovery {
    // The rate that produces a block per target at the starting difficulty.
    let start_difficulty = 1_000_000f64;
    let mut rate = start_difficulty / TARGET as f64;

    let mut headers: Vec<HeaderSummary> = Vec::new();
    let mut timestamp = 1_000_000u64;
    let mut difficulty = start_difficulty as u64;
    let mut height = 0u64;

    for _ in 0..SETTLED {
        headers.push(HeaderSummary {
            height,
            timestamp,
            difficulty,
        });
        trim(&mut headers);
        height += 1;
        timestamp += TARGET;
        difficulty = next_difficulty(&headers, TARGET);
    }

    rate *= share;

    let mut elapsed = 0f64;
    let mut blocks = 0usize;
    let mut first_block = 0f64;
    let mut to_half = f64::NAN;
    let mut to_normal = f64::NAN;

    // A long run, because at one per cent the early blocks are hours apart.
    while blocks < 100_000 {
        let solvetime = difficulty as f64 / rate;
        if blocks == 0 {
            first_block = solvetime;
        }
        elapsed += solvetime;
        blocks += 1;
        timestamp += solvetime.round().max(1.0) as u64;

        headers.push(HeaderSummary {
            height,
            timestamp,
            difficulty,
        });
        height += 1;
        trim(&mut headers);
        difficulty = next_difficulty(&headers, TARGET);

        if to_half.is_nan() && solvetime <= TARGET as f64 * 2.0 {
            to_half = elapsed;
        }
        if solvetime <= TARGET as f64 * 1.1 {
            to_normal = elapsed;
            break;
        }
    }

    Recovery {
        first_block,
        blocks,
        to_half,
        to_normal,
    }
}

/// Keeps only what a node keeps, so the simulation sees what a node sees.
fn trim(headers: &mut Vec<HeaderSummary>) {
    let keep = DIFFICULTY_WINDOW + 1;
    if headers.len() > keep {
        headers.drain(..headers.len() - keep);
    }
}

fn duration(seconds: f64) -> String {
    if seconds.is_nan() {
        return "never".to_owned();
    }
    if seconds < 90.0 {
        return format!("{seconds:.0} s");
    }
    if seconds < 5_400.0 {
        return format!("{:.0} min", seconds / 60.0);
    }
    if seconds < 172_800.0 {
        return format!("{:.1} h", seconds / 3_600.0);
    }
    format!("{:.1} days", seconds / 86_400.0)
}

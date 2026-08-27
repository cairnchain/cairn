//! How fast this machine searches for a block, and what difficulty that makes
//! a block take the target time.
//!
//! The answer decides the difficulty the first block of a network carries. Set
//! it too low and whoever starts a few seconds early takes hundreds of blocks
//! before anyone else has begun.
//!
//! Run with `cargo run --release -p cairn-ledger --example hashrate`.

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use std::time::Instant;

use cairn_crypto::SecretKey;
use cairn_ledger::note::Note;
use cairn_ledger::pow::meets_target;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, ConsensusParams};
use cairn_ledger::LedgerState;

const SAMPLE: u64 = 3_000_000;

fn main() {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let state = LedgerState::new();

    let coinbase = CoinbaseTransaction::new(
        0,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let mut block = assemble_block(
        &state,
        coinbase,
        Vec::<Transfer>::new(),
        &params,
        1_700_000_000,
        0,
    )
    .expect("the block is valid");

    let started = Instant::now();
    let mut found = 0u64;
    for nonce in 0..SAMPLE {
        block.header.nonce = nonce;
        if meets_target(&block.id(), 1) {
            found += 1;
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    let per_second = SAMPLE as f64 / elapsed;

    println!("one core of this machine");
    println!("  tries per second   {per_second:.0}");
    println!("  (checked {found} of {SAMPLE}, which is every one at difficulty 1)");
    println!();
    println!("{:>14}  {:>16}", "block time", "difficulty");
    println!("{}", "-".repeat(32));
    for seconds in [5u64, 30, 60, 600] {
        println!("{:>12} s  {:>16.0}", seconds, per_second * seconds as f64);
    }
    println!();
    println!("A network's first block should already take about its target time on");
    println!("one ordinary machine. Anything less and the opening seconds are a race");
    println!("nobody else has been told about yet.");
}

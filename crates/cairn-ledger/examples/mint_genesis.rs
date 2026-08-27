//! Mines the first block of a network and prints it, so it can be written into
//! the source.
//!
//! Run with `cargo run --release -p cairn-ledger --example mint_genesis -- <network> [message]`.

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cairn_ledger::block::Block;
use cairn_ledger::pow::meets_target;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer, MAX_COINBASE_EXTRA};
use cairn_ledger::validation::{assemble_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::{Decode, Encode};

fn main() {
    let mut arguments = std::env::args().skip(1);
    let network = arguments.next().unwrap_or_else(|| "devnet".to_owned());
    let message = arguments.collect::<Vec<_>>().join(" ");

    let Some(mut params) = ConsensusParams::for_network(&network) else {
        eprintln!("no rules for `{network}`");
        std::process::exit(2);
    };
    // The block being minted is the one that would be pinned, so nothing is
    // pinned while it is made.
    params.genesis = None;
    params.opens_at = 0;

    let extra = message.as_bytes().to_vec();
    if extra.len() > MAX_COINBASE_EXTRA {
        eprintln!(
            "that message is {} bytes, the limit is {MAX_COINBASE_EXTRA}",
            extra.len()
        );
        std::process::exit(2);
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);

    // A coinbase paying nobody: a network should not open with someone already
    // holding something.
    let coinbase = CoinbaseTransaction::with_extra(0, Vec::new(), extra);
    let candidate = assemble_block(
        &LedgerState::new(),
        coinbase,
        Vec::<Transfer>::new(),
        &params,
        timestamp,
        0,
    )
    .expect("a first block is valid");

    println!("network      {network}");
    println!("difficulty   {}", candidate.header.difficulty);
    println!("timestamp    {timestamp}");
    println!("message      {message:?}");
    println!("searching...");

    let started = Instant::now();
    let mut block = candidate;
    let mut nonce = 0u64;
    loop {
        block.header.nonce = nonce;
        if meets_target(&block.id(), block.header.difficulty) {
            break;
        }
        nonce = nonce.wrapping_add(1);
        if nonce == 0 {
            eprintln!("no nonce works for this block");
            std::process::exit(1);
        }
    }

    println!(
        "found        after {:.1} s at nonce {nonce}",
        started.elapsed().as_secs_f64()
    );
    println!("identifier   {}", block.id());
    println!();
    println!("{}", cairn_primitives::hex::encode(&block.encode()));
    let _ = Block::decode(&block.encode()).expect("what is printed reads back");
}

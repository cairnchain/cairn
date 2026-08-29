//! What it costs to join a chain, against what it costs to read one.
//!
//! Two exchanges, both once. First a newcomer decides which chain is heaviest
//! from a sample of its headers; then it is handed the ledger at that chain's
//! tip. Neither grows with the chain's age, which is the whole claim, so the
//! numbers below are what joining costs at any age at all.
//!
//! Run with `cargo run --release -p cairn-ledger --example joining`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::print_stdout
)]

use cairn_crypto::SecretKey;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::note::Note;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::sampling::SAMPLES;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;

const NOW: u64 = 2_000_000_000;
/// Hot sets to measure at. The last is what the rules actually allow, and
/// mining enough blocks to fill it takes a moment.
const SIZES: [usize; 4] = [1_024, 4_096, 16_384, 131_072];

fn main() {
    println!("What joining a chain costs, whatever its age\n");
    println!(
        "{:>12}  {:>12}  {:>12}  {:>12}",
        "hot notes", "ledger", "per note", "sampling"
    );
    println!("{}", "-".repeat(56));

    // A sampled start is a tip, sixty four hashes, and one opened header per
    // draw. It does not depend on the ledger, so it is the same on every row.
    let sampling = SAMPLES * (core::mem::size_of::<BlockHeader>() + 64 * 32 + 4);

    for capacity in SIZES {
        let bytes = handover_bytes(capacity);
        println!(
            "{:>12}  {:>12}  {:>12}  {:>12}",
            with_commas(capacity),
            format_bytes(bytes),
            format!("{} B", bytes / capacity.max(1)),
            format_bytes(sampling),
        );
    }

    println!(
        "\nAgainst reading the chain instead: thirty years of blocks at 128 kB\n\
         each is {}, and every byte of it has to be validated.\n\
         Joining this way is two exchanges that do not grow, and the second of\n\
         them is most of the cost.",
        format_bytes(30 * 365 * 24 * 60 * 128 * 1024),
    );

    println!(
        "\nWhat is in a handover: the hot set, which is nearly all of it; the\n\
         cold set as sixty four hashes; the grace window with a proof for each\n\
         note in it, which is the only part that could be trimmed and is worth\n\
         its size, since without it a newcomer refuses spends everyone else\n\
         takes; and the last {RECENT_HEADERS} headers, which the difficulty rule reads."
    );
}

/// A ledger filled to `capacity` notes, handed over, measured.
fn handover_bytes(capacity: usize) -> usize {
    let params = ConsensusParams::testnet().with_hot_capacity(capacity);
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::archiving();
    let mut headers = Vec::new();
    let mut clock = 1_000u64;

    // Sixteen notes a block is what a coinbase may pay out, so filling a hot
    // set of a hundred thousand takes a while and is the point.
    let per_block = params.max_coinbase_outputs;
    let each = params.initial_reward.as_pebbles() / per_block as u64;
    let first = params.initial_reward.as_pebbles() - each * (per_block as u64 - 1);

    while state.hot_len() < capacity || headers.len() <= RECENT_HEADERS {
        let height = state.next_height().unwrap();
        clock += 600;
        let outputs: Vec<Note> = (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(
                    cairn_primitives::Amount::from_pebbles(value).unwrap(),
                    miner.public_key(),
                )
            })
            .collect();
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        headers.push(block.header);
    }

    let tip = *headers.last().unwrap();
    let from = headers.len().saturating_sub(RECENT_HEADERS);
    state.handover(tip, headers[from..].to_vec()).encode().len()
}

fn with_commas(value: usize) -> String {
    let text = value.to_string();
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index > 0 && (text.len() - index) % 3 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_000_000_000 {
        return format!("{:.1} GB", bytes as f64 / 1e9);
    }
    if bytes >= 1_000_000 {
        return format!("{:.1} MB", bytes as f64 / 1e6);
    }
    format!("{} kB", bytes / 1_000)
}

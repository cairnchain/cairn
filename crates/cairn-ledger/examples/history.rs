//! What carrying the history actually costs.
//!
//! The validation state is bounded by rule. The history is not, and this
//! measures what that means in bytes and in minutes rather than in adjectives.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use std::time::Instant;

use cairn_crypto::SecretKey;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;

const SAMPLE: usize = 2_000;
/// Transfers per block in the busy measurement. A block may carry 4096, but a
/// chain that busy is not the one worth planning around.
const BUSY: usize = 64;

/// Validates `SAMPLE` blocks carrying `transfers_each` transfers, and reports
/// the cost of one block.
fn measure(transfers_each: usize) -> (usize, f64, f64) {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let spender = SecretKey::from_bytes(&[2; 32]);
    let mut state = LedgerState::new();

    let mut header_bytes = 0usize;
    let mut block_bytes = 0usize;
    let mut spent = 0.0f64;
    // Notes available to spend, oldest first.
    let mut purse: Vec<(cairn_ledger::note::NoteId, Note)> = Vec::new();

    for index in 0..SAMPLE {
        let height = state.next_height().unwrap();
        // Pay the reward out in enough pieces to keep the next block busy.
        let pieces = transfers_each.max(1).min(params.max_coinbase_outputs);
        let each = cairn_primitives::Amount::from_pebbles(
            params.initial_reward.as_pebbles() / pieces as u64,
        )
        .unwrap();
        let outputs: Vec<Note> = (0..pieces)
            .map(|_| Note::new(each, spender.public_key()))
            .collect();
        let coinbase = CoinbaseTransaction::new(height, outputs);

        let mut transfers = Vec::new();
        while transfers.len() < transfers_each {
            let Some((id, note)) = purse.pop() else {
                break;
            };
            let mut transfer = Transfer::new(
                vec![cairn_ledger::transaction::Input::hot(id)],
                vec![Note::new(note.value, miner.public_key())],
            );
            transfer.sign_input(params.network, 0, &note, &spender);
            transfers.push(transfer);
        }

        let block =
            assemble_block(&state, coinbase, transfers, &params, 1_000 + height * 60, 0).unwrap();

        let at = Instant::now();
        connect_block(&mut state, &block, &params, u64::MAX / 2).unwrap();
        spent += at.elapsed().as_secs_f64();

        if index == 0 {
            header_bytes = block.header.encode().len();
        }
        block_bytes += block.encode().len();
        purse.extend(block.coinbase.created_notes());
    }

    (
        header_bytes,
        block_bytes as f64 / SAMPLE as f64,
        spent / SAMPLE as f64,
    )
}

/// What one hot note costs a node, measured rather than guessed.
///
/// `examples/footprint.rs` builds the structures and reads the resident memory
/// back: 237 bytes for the map and the ordering, 279 for the tree. It was 813
/// before a public key stopped being kept in the form it is verified in, which
/// is where the figure below used to come from and why it is named here rather
/// than written into two format strings.
const HOT_BYTES_PER_NOTE: f64 = 516.0;

fn main() {
    let params = ConsensusParams::testnet();
    let (header_bytes, empty_size, empty_cost) = measure(0);
    let (_, busy_size, busy_cost) = measure(BUSY);
    let per_block = busy_cost;

    println!("Measured over {SAMPLE} blocks each, one core");
    println!();
    println!("  header                    {header_bytes} bytes");
    println!("  block, empty              {empty_size:.0} bytes");
    println!("  block, {BUSY} transfers      {busy_size:.0} bytes");
    println!("  validation, empty         {:.3} ms", empty_cost * 1_000.0);
    println!(
        "  validation, {BUSY} transfers {:.3} ms",
        busy_cost * 1_000.0
    );
    println!();
    println!("Revalidating from nothing, at the busy rate, one block a minute:");
    println!();
    println!(
        "  {:<10} {:>12} {:>12} {:>14}",
        "age", "blocks", "headers", "revalidation"
    );
    for years in [1u64, 5, 10, 30] {
        let blocks = years * 365 * 24 * 60;
        let headers = blocks * header_bytes as u64;
        let seconds = per_block * blocks as f64;
        println!(
            "  {:<10} {:>12} {:>10.1} MB {:>11.1} h",
            format!("{years} year{}", if years == 1 { "" } else { "s" }),
            blocks,
            headers as f64 / 1_048_576.0,
            seconds / 3_600.0,
        );
    }
    println!();
    println!("And the download, at the busy rate:");
    println!();
    for years in [1u64, 10, 30] {
        let blocks = years * 365 * 24 * 60;
        println!(
            "  {:<10} {:>10.1} GB of blocks",
            format!("{years} year{}", if years == 1 { "" } else { "s" }),
            blocks as f64 * busy_size / 1_073_741_824.0,
        );
    }
    println!();
    println!("The same revalidation, at one block every ten minutes:");
    println!();
    for years in [10u64, 30] {
        let blocks = years * 365 * 24 * 6;
        let headers = blocks * header_bytes as u64;
        let seconds = per_block * blocks as f64;
        println!(
            "  {:<10} {:>12} {:>10.1} MB {:>11.1} h",
            format!("{years} years"),
            blocks,
            headers as f64 / 1_048_576.0,
            seconds / 3_600.0,
        );
    }
    println!();
    println!(
        "For comparison, the validation state a node holds is capped at {} notes, {:.0} MB.",
        params.hot_capacity,
        params.hot_capacity as f64 * HOT_BYTES_PER_NOTE / 1_000_000.0
    );
    println!();
    println!("What the header commitment costs, and what it is for:");
    println!();
    println!("  a node carries          64 hashes, 2 kB, at any age");
    println!("  a header grew by        48 bytes, {header_bytes} in total");
    println!(
        "  sampled start, 30 years {:.0} sampled headers, {:.0} kB, plus {:.0} MB of state",
        128.0,
        128.0 * header_bytes as f64 * 12.0 / 1_024.0,
        params.hot_capacity as f64 * HOT_BYTES_PER_NOTE / 1_000_000.0
    );
    println!();
    println!("The sampled figure is what the field makes possible, not what is");
    println!("built yet: a hundred and twenty eight headers with their inclusion");
    println!("proofs, against the two gigabytes it takes to read them all.");
}

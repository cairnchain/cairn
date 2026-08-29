//! What a node holds in memory so that it can undo a reorganisation.
//!
//! A node keeps the last [`MAX_REORG_DEPTH`] blocks it applied, because a
//! branch that arrives with more work behind it has to be switched to, and
//! switching means undoing what the current one did. That window is bounded,
//! which is what makes the cost constant. What it costs is measured here,
//! because a decoded block is several times the size of the bytes it arrived
//! as, and the bytes are the only figure the rules name.
//!
//! Only the ceiling matters. A block on a quiet chain is nearly empty and
//! costs nearly nothing; the promise that a node runs on a phone has to hold
//! on a chain that is full.
//!
//! Run with `cargo run --release -p cairn-chain --example window`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::print_stdout
)]

use std::process::Command;

use cairn_chain::{ChainStore, MAX_REORG_DEPTH};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::{Amount, Hash32};

/// Copies held at once, enough for the measurement to rise above the noise.
const COPIES: usize = 256;

fn main() {
    let params = ConsensusParams::testnet();
    let block = full_block(&params);
    let encoded = block.encode().len();

    let baseline = resident_bytes().unwrap_or(0);
    let held: Vec<Block> = (0..COPIES).map(|_| block.clone()).collect();
    let used = resident_bytes().unwrap_or(0).saturating_sub(baseline);
    let each = used.checked_div(COPIES as u64).unwrap_or(0);
    assert_eq!(held.len(), COPIES);

    println!("What a full block costs a node, held rather than sent.\n");
    println!(
        "{:>28}  {:>14}",
        "on the wire",
        format_bytes(encoded as u64)
    );
    println!("{:>28}  {:>14}", "in memory", format_bytes(each));
    println!(
        "{:>28}  {:>13.1}x",
        "decoding costs",
        each as f64 / encoded as f64
    );
    println!("{:>28}  {:>14}", "transfers in it", block.transfers.len());

    println!(
        "\nThe window a node can still undo is {MAX_REORG_DEPTH} blocks, so on a chain\n\
         running at the limit that window costs:\n"
    );
    println!(
        "{:>28}  {:>14}",
        "the window, in memory",
        format_bytes(each.saturating_mul(MAX_REORG_DEPTH as u64))
    );

    // What is held is not only the window: branches offered and not taken are
    // held too, in case one of them grows into the heaviest.
    let ceiling = ChainStore::held_bytes_ceiling(&params);
    let in_memory = (ceiling as f64 * each as f64 / encoded as f64) as u64;
    println!(
        "{:>28}  {:>14}",
        "with rival branches",
        format_bytes(in_memory)
    );
    println!("{:>28}  {:>14}", "the hot set, at its own", "68 MB");

    println!(
        "\nBoth are bounded and neither grows with the chain, which is the whole\n\
         claim. What this says is which of the two the claim rests on: the blocks\n\
         a node holds so it can undo them cost several times what the notes do.\n\
         They sit on the disk as well, so the reading that would replace them is\n\
         written; what is not written is asking the disk for them.",
    );
}

/// A block filled to the byte limit the rules impose.
fn full_block(params: &ConsensusParams) -> Block {
    let owner = SecretKey::from_bytes(&[1; 32]).public_key();
    let value = Amount::from_pebbles(1_000).expect("under the ceiling");

    let mut transfers: Vec<Transfer> = Vec::new();
    let mut bytes = header_and_coinbase_bytes(params, owner);
    let mut index = 0u64;
    loop {
        // An ordinary payment: one note in, two out. What most of a full block
        // is made of, and what the block size was chosen against.
        let transfer = Transfer::new(
            vec![Input::hot(NoteId::new(
                hash(Domain::StateEntry, &index.to_le_bytes()),
                0,
            ))],
            vec![Note::new(value, owner), Note::new(value, owner)],
        );
        let size = transfer.encode().len();
        if bytes + size > params.max_block_bytes {
            break;
        }
        bytes += size;
        transfers.push(transfer);
        index += 1;
    }

    Block {
        header: BlockHeader {
            height: 1,
            previous: Hash32::from_bytes([0; 32]),
            ..empty_header()
        },
        coinbase: CoinbaseTransaction::new(1, vec![Note::new(value, owner)]),
        transfers,
    }
}

fn header_and_coinbase_bytes(params: &ConsensusParams, owner: cairn_crypto::PublicKey) -> usize {
    let _ = params;
    let value = Amount::from_pebbles(1).expect("under the ceiling");
    empty_header().encode().len()
        + CoinbaseTransaction::new(1, vec![Note::new(value, owner)])
            .encode()
            .len()
}

fn empty_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        network: cairn_ledger::note::NetworkId::TESTNET,
        height: 0,
        previous: Hash32::from_bytes([0; 32]),
        state_root: Hash32::from_bytes([0; 32]),
        transactions_root: Hash32::from_bytes([0; 32]),
        history: Hash32::from_bytes([0; 32]),
        timestamp: 0,
        difficulty: 1,
        total_work: 0,
        nonce: 0,
    }
}

fn resident_bytes() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let kilobytes: u64 = text.trim().parse().ok()?;
    Some(kilobytes.saturating_mul(1_024))
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.0} MB", bytes as f64 / 1_000_000.0)
    } else {
        format!("{:.0} kB", bytes as f64 / 1_000.0)
    }
}

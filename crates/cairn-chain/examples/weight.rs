//! What a running node holds in memory as its chain grows.
//!
//! The claim this project makes is that a full validating node costs the same
//! in thirty years as it does today. The ledger keeps that promise: the hot
//! set is capped by a consensus rule and the cold set is sixty four hashes.
//! The block tree does not. A node keeps every block it has ever applied,
//! keyed by identifier, plus the list of the branch it follows.
//!
//! This measures the gap, so the work of closing it is decided by a number
//! rather than by an intuition.
//!
//! Run with `cargo run --release -p cairn-chain --example weight`.

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use std::process::Command;

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

/// Far enough apart that the difficulty settles at its floor within a few
/// blocks, so the search below costs nothing and the measurement is of memory
/// rather than of proof of work.
const SPACING: u64 = 3_600;
const ATTEMPTS: u64 = 1 << 20;

/// Heights to measure at. The last is nine months of a sixty second chain,
/// which is short against thirty years and already enough to see the shape.
const HEIGHTS: [usize; 5] = [10_000, 50_000, 100_000, 200_000, 400_000];

fn main() {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);

    println!("What a node holds as the chain grows");
    println!("empty blocks, so this is the floor and not the cost of a busy chain\n");
    println!(
        "{:>10}  {:>12}  {:>12}  {:>14}",
        "blocks", "memory", "per block", "at 30 years"
    );
    println!("{}", "-".repeat(54));

    let mut forge = Forge::new(params);
    let mut store = ChainStore::new(params);
    let baseline = resident_bytes().unwrap_or(0);
    let mut built = 0usize;

    for target in HEIGHTS {
        while built < target {
            let block = forge.mine(&miner);
            let now = block.header.timestamp;
            store.add_block(block, now).expect("it connects");
            built += 1;
        }
        let used = resident_bytes().unwrap_or(0).saturating_sub(baseline);
        let per_block = used / built as u64;
        // A sixty second chain reaches this many blocks in thirty years.
        let thirty_years = 30 * 365 * 24 * 60;
        println!(
            "{:>10}  {:>12}  {:>12}  {:>14}",
            format_count(built),
            format_bytes(used),
            format_bytes(per_block),
            format_bytes(per_block * thirty_years),
        );
    }

    println!(
        "\nThe hot set is capped and the cold set is sixty four hashes, so\n\
         neither appears above. What grows is the block tree: every block a\n\
         node has applied, and the list of the branch it follows.\n\
         \n\
         Read the last row: the earlier ones carry the fixed cost of starting\n\
         a process spread over too few blocks. What a node actually needs to\n\
         keep is the ledger, ninety headers for the difficulty, and enough\n\
         undo records to reorganise. Everything else is already on disk."
    );
}

/// Builds valid blocks on a private copy of the ledger.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, who: &SecretKey) -> Block {
        let height = self.state.next_height().expect("the chain has room");
        self.clock += SPACING;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, who.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
            &self.params,
            self.clock,
            0,
        )
        .expect("the block is valid");
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, self.clock).expect("it connects");
        block
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

fn format_count(count: usize) -> String {
    if count >= 1_000_000 {
        format!("{} M", count / 1_000_000)
    } else if count >= 1_000 {
        format!("{} k", count / 1_000)
    } else {
        count.to_string()
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1e9)
    } else if bytes >= 1_000_000 {
        format!("{} MB", bytes / 1_000_000)
    } else if bytes >= 1_000 {
        format!("{} kB", bytes / 1_000)
    } else {
        format!("{bytes} B")
    }
}

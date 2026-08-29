//! What a running node holds in memory as its chain grows.
//!
//! The claim this project makes is that a full validating node costs the same
//! in thirty years as it does today, so the number that matters is not what a
//! node holds at a given height but what one more block adds. A cost that does
//! not grow shows up here as a marginal cost that falls towards nothing.
//!
//! What is measured is resident memory, which is what the machine actually
//! gives up. It never falls back: an allocator that hands memory back to the
//! program rather than to the kernel keeps the pages. So this reads high, and
//! reads high in the honest direction.
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

/// Heights to measure at, each roughly double the last, so the marginal cost
/// is measured over a stretch as long as everything before it.
const HEIGHTS: [usize; 5] = [25_000, 50_000, 100_000, 200_000, 400_000];

fn main() {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);

    println!("What a node holds as the chain grows");
    println!("empty blocks, so this is the floor and not the cost of a busy chain\n");
    println!(
        "{:>10}  {:>10}  {:>12}  {:>14}  {:>14}",
        "blocks", "memory", "added since", "per new block", "at 30 years"
    );
    println!("{}", "-".repeat(68));

    let mut forge = Forge::new(params);
    let mut store = ChainStore::new(params);
    let baseline = resident_bytes().unwrap_or(0);
    let mut built = 0usize;
    let mut previous = (0usize, 0u64);

    for target in HEIGHTS {
        while built < target {
            let block = forge.mine(&miner);
            let now = block.header.timestamp;
            store.add_block(block, now).expect("it connects");
            built += 1;
        }
        let used = resident_bytes().unwrap_or(0).saturating_sub(baseline);
        let added = used.saturating_sub(previous.1);
        let over = built.saturating_sub(previous.0) as u64;
        let per_block = added.checked_div(over).unwrap_or(0);
        // A sixty second chain reaches this many blocks in thirty years.
        let thirty_years = 30 * 365 * 24 * 60;
        println!(
            "{:>10}  {:>10}  {:>12}  {:>14}  {:>14}",
            format_count(built),
            format_bytes(used),
            format_bytes(added),
            format_bytes(per_block),
            format_bytes(per_block * thirty_years),
        );
        previous = (built, used);
    }

    // Resident memory stops rising well before the structures stop growing:
    // an allocator that has already asked the kernel for pages fills them
    // again rather than asking for more. What is still growing is countable,
    // so it is counted rather than measured.
    let per_id = std::mem::size_of::<cairn_primitives::Hash32>() as u64;
    let thirty_years: u64 = 30 * 365 * 24 * 60;
    // One identifier every so often, and nothing else per block.
    let milestones = thirty_years / 1_024;
    println!(
        "\nStill growing, counted rather than measured: one identifier every\n\
         1024 heights, {per_id} bytes each, so {} over thirty years.",
        format_bytes(milestones * per_id)
    );

    println!(
        "\nThe hot set is capped by a consensus rule and the cold set is sixty\n\
         four hashes, so neither appears above. A node also lets go of the body\n\
         of any block too deep to be undone, and reads it back from its log if\n\
         anyone asks. What is left growing is the list of the branch it follows\n\
         only as far back as one could still be undone, and one identifier\n\
         every 1024 heights before that. Everything else is read from the log,\n\
         where the branch sits in order of height."
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

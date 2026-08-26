//! Producing blocks.
//!
//! One thread, one nonce at a time. A real miner spreads the search across
//! cores and cards, but nothing about what makes a block valid changes with
//! how hard it is looked for.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cairn_chain::ChainStore;
use cairn_crypto::PublicKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::pow::{median_time_past, meets_target};
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, ConsensusParams};
use cairn_net::Node;
use cairn_primitives::Hash32;

/// Nonces tried before looking up to see whether the chain moved on.
///
/// Small enough that a block found elsewhere is noticed in well under a
/// second, large enough that the check costs nothing.
const NONCE_BATCH: u64 = 50_000;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default()
}

/// Mines until `running` is cleared, announcing each block it finds.
pub(crate) fn run(
    node: &Node,
    params: &ConsensusParams,
    reward_to: PublicKey,
    running: &AtomicBool,
    mut found: impl FnMut(&Block),
) {
    while running.load(Ordering::SeqCst) {
        let Some((candidate, extending)) = build(node, params, reward_to) else {
            thread::sleep(Duration::from_millis(200));
            continue;
        };
        if let Some(block) = search(node, &candidate, extending, running) {
            if node.submit_block(block.clone()).is_ok() {
                found(&block);
            }
        }
    }
}

/// Assembles the block this node would like to see next.
fn build(
    node: &Node,
    params: &ConsensusParams,
    reward_to: PublicKey,
) -> Option<(Block, Option<Hash32>)> {
    node.with_chain(|chain| {
        let extending = chain.tip();
        let state = chain.state();
        let height = state.next_height()?;

        // The timestamp has to clear the median of recent blocks. On a chain
        // whose blocks are minutes apart that is always the wall clock; on one
        // being caught up it is the median plus a second.
        let earliest =
            median_time_past(state.recent_headers()).map_or(0, |median| median.saturating_add(1));
        let timestamp = unix_now().max(earliest);

        // Whatever the pool holds that fits together, and what those transfers
        // pay to be carried.
        let (transfers, fees) = chain.selection(params.max_transfers_per_block);
        let reward = params.block_reward.checked_add(fees)?;

        let coinbase = CoinbaseTransaction::new(height, vec![Note::new(reward, reward_to)], [0; 8]);
        let block = assemble_block(state, coinbase, transfers, params, timestamp, 0).ok()?;
        Some((block, extending))
    })
}

/// Looks for a nonce, giving up as soon as the chain moves under it.
fn search(
    node: &Node,
    candidate: &Block,
    extending: Option<Hash32>,
    running: &AtomicBool,
) -> Option<Block> {
    let mut block = candidate.clone();
    let mut nonce = 0u64;
    loop {
        if !running.load(Ordering::SeqCst) {
            return None;
        }
        // Somebody else found one. Whatever this thread is holding is now built
        // on the wrong parent.
        if node.with_chain(ChainStore::tip) != extending {
            return None;
        }
        for offset in 0..NONCE_BATCH {
            block.header.nonce = nonce.wrapping_add(offset);
            if meets_target(&block.id(), block.header.difficulty) {
                return Some(block);
            }
        }
        nonce = nonce.wrapping_add(NONCE_BATCH);
        if nonce == 0 {
            // The whole nonce space came back around. A new candidate carries a
            // fresh timestamp, which is a fresh search.
            return None;
        }
    }
}

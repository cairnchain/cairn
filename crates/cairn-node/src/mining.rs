//! Producing blocks.
//!
//! The search is spread across the cores the machine has, each on its own
//! stretch of the nonce space, all stopping the moment one of them finds
//! something or the chain moves underneath them. A serious miner uses cards
//! rather than cores, but nothing about what makes a block valid changes with
//! how hard it was looked for.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
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

/// Cores left to the rest of the machine.
///
/// A node that mines is still a node: it has peers to answer, blocks to
/// validate, and a chain to write down. Taking every core would make it a
/// miner that happens to hold a chain, which is slower at both.
const CORES_SPARED: usize = 1;

/// Searchers to run at once.
///
/// One if the machine will not say how many cores it has, which is the honest
/// answer to not knowing rather than a guess that might be four times wrong.
fn searchers() -> usize {
    thread::available_parallelism()
        .map(|count| count.get().saturating_sub(CORES_SPARED).max(1))
        .unwrap_or(1)
}

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
        let now = unix_now();
        let earliest =
            median_time_past(state.recent_headers()).map_or(0, |median| median.saturating_add(1));

        // And it has to stay inside the drift every node measures against its
        // own clock. The two bounds can cross: if enough recent blocks are
        // dated near the edge of the drift, the median they carry sits past
        // what this node's own clock will accept, and every block it could
        // assemble is one it would refuse itself. There is nothing to mine
        // then, only a clock to wait for, so it says so and the caller tries
        // again in a moment.
        if earliest > now.saturating_add(params.max_timestamp_drift) {
            return None;
        }
        let timestamp = now.max(earliest);

        // Whatever the pool holds that fits together, and what those transfers
        // pay to be carried.
        let (transfers, fees) = chain.selection(params.max_transfers_per_block);
        let reward = params.reward_at(height).checked_add(fees)?;

        let coinbase = CoinbaseTransaction::new(height, vec![Note::new(reward, reward_to)]);
        let block = assemble_block(state, coinbase, transfers, params, timestamp, 0).ok()?;
        Some((block, extending))
    })
}

/// Looks for a nonce across every core, giving up as soon as the chain moves.
///
/// The nonce space is handed out in batches from one counter rather than split
/// into equal ranges up front. Equal ranges would have every searcher finish
/// its own stretch at its own pace, and a core that ran slow would leave a gap
/// nobody covered; a shared counter means no nonce is tried twice and none is
/// skipped, whatever the cores are doing.
fn search(
    node: &Node,
    candidate: &Block,
    extending: Option<Hash32>,
    running: &AtomicBool,
) -> Option<Block> {
    let count = searchers();
    if count <= 1 {
        return search_one(
            node,
            candidate,
            extending,
            running,
            &AtomicU64::new(0),
            None,
        );
    }

    let next = Arc::new(AtomicU64::new(0));
    // Cleared by whichever searcher finds something, so the others stop.
    let found = Arc::new(AtomicBool::new(false));

    thread::scope(|scope| {
        let mut hands = Vec::with_capacity(count);
        for _ in 0..count {
            let next = Arc::clone(&next);
            let found = Arc::clone(&found);
            hands.push(scope.spawn(move || {
                search_one(node, candidate, extending, running, &next, Some(&found))
            }));
        }
        hands
            .into_iter()
            .find_map(|hand| hand.join().ok().flatten())
    })
}

/// One searcher, taking batches of nonces from `next` until there are none
/// left to take or there is no longer any point.
fn search_one(
    node: &Node,
    candidate: &Block,
    extending: Option<Hash32>,
    running: &AtomicBool,
    next: &AtomicU64,
    found: Option<&AtomicBool>,
) -> Option<Block> {
    let mut block = candidate.clone();
    loop {
        if !running.load(Ordering::SeqCst) {
            return None;
        }
        if found.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
            return None;
        }
        // Somebody else found one. Whatever this thread is holding is now built
        // on the wrong parent.
        if node.with_chain(ChainStore::tip) != extending {
            return None;
        }

        // The whole nonce space came back around. A new candidate carries a
        // fresh timestamp, which is a fresh search.
        let start = next.fetch_add(NONCE_BATCH, Ordering::SeqCst);
        start.checked_add(NONCE_BATCH)?;

        for offset in 0..NONCE_BATCH {
            block.header.nonce = start.wrapping_add(offset);
            if meets_target(&block.id(), block.header.difficulty) {
                if let Some(flag) = found {
                    flag.store(true, Ordering::SeqCst);
                }
                return Some(block);
            }
        }
    }
}

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

/// Seconds a candidate may keep the timestamp it was built with.
///
/// The only thing that used to end a search, short of the chain moving, was
/// the nonce space running out, which is two to the sixty fourth hashes: about
/// fifty eight thousand years at ten megahashes a second. So the comment
/// saying a new candidate carries a fresh timestamp described a mechanism that
/// never fired, and a candidate's timestamp, its transfers and its fee total
/// were refreshed only when the tip moved.
///
/// In steady state that costs one block's worth of staleness and nothing else.
/// It bites at the one moment it matters: when the hash rate falls away and
/// the next block takes hours, that block is still dated from before the fall,
/// so it states a minute's gap the network did not take, and the retarget that
/// exists to bring the difficulty back down is shown nothing to bring it down
/// for. Only the block after it reports the stall, and there may not be one
/// for hours. Bitcoin refreshes the time during the search for exactly this.
///
/// Half a minute, against a target spacing of minutes: short enough that the
/// gap a stalled chain reports is close to the gap it took, long enough that
/// rebuilding costs nothing measurable. Nothing is lost by rebuilding, because
/// each hash is independent of the ones before it.
const CANDIDATE_PATIENCE: u64 = 30;

/// Whether a candidate has been searched long enough that what it says about
/// the clock is no longer true.
///
/// A candidate dated ahead of `now` has not aged at all: that is a chain being
/// caught up, where the timestamp is the median of recent blocks plus a second
/// rather than the wall clock, and there is nothing fresher to give it.
fn gone_stale(timestamp: u64, now: u64) -> bool {
    now.saturating_sub(timestamp) >= CANDIDATE_PATIENCE
}

/// Whether a searcher should go on with the candidate it holds.
///
/// Four reasons to stop and they are all somebody else's news, which is why
/// they are gathered here rather than left as four returns: the rule is one
/// function that can be read, and tested, without a node or a chain.
///
/// The last of them is the one that was missing. Nothing but the tip moving
/// ever ended a search, so the timestamp a candidate carried, the transfers in
/// it and the fees they paid were as old as the last block however long the
/// next one took.
fn worth_carrying_on(
    running: bool,
    found: bool,
    still_on_the_tip: bool,
    timestamp: u64,
    now: u64,
) -> bool {
    running && !found && still_on_the_tip && !gone_stale(timestamp, now)
}

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
        // Somebody else finding a block leaves whatever this thread holds
        // built on the wrong parent, and a candidate too old to still be
        // describing the clock is given back to be built again.
        if !worth_carrying_on(
            running.load(Ordering::SeqCst),
            found.is_some_and(|flag| flag.load(Ordering::SeqCst)),
            node.with_chain(ChainStore::tip) == extending,
            candidate.header.timestamp,
            unix_now(),
        ) {
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

/// AUDIT: nothing but the tip moving ever ended a search.
///
/// The comment above the nonce check said a new candidate carries a fresh
/// timestamp and named nonce exhaustion as the trigger, which is two to the
/// sixty fourth hashes: about fifty eight thousand years at ten megahashes a
/// second. So the mechanism it described had never fired once.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::{gone_stale, worth_carrying_on, CANDIDATE_PATIENCE};

    const BUILT_AT: u64 = 2_000_000_000;

    #[test]
    fn a_candidate_is_given_back_once_its_timestamp_has_aged() {
        assert!(
            worth_carrying_on(true, false, true, BUILT_AT, BUILT_AT),
            "a fresh candidate is searched"
        );
        assert!(
            worth_carrying_on(
                true,
                false,
                true,
                BUILT_AT,
                BUILT_AT + CANDIDATE_PATIENCE - 1
            ),
            "and stays worth searching up to the patience"
        );
        assert!(
            !worth_carrying_on(true, false, true, BUILT_AT, BUILT_AT + CANDIDATE_PATIENCE),
            "past it the timestamp is no longer what this node would write, so \
             the candidate goes back to be built again with the time now, the \
             transfers now and the fees they now pay"
        );
    }

    /// The case that used to be the whole of the mechanism: hours pass, and
    /// what the miner publishes still says a minute.
    #[test]
    fn a_search_lasting_hours_does_not_publish_an_hours_old_timestamp() {
        let ten_hours = 10 * 60 * 60;
        assert!(
            !worth_carrying_on(true, false, true, BUILT_AT, BUILT_AT + ten_hours),
            "a block found after a hash rate collapse must report the gap it \
             took, or the retarget it exists for is shown nothing to act on"
        );
    }

    /// A chain being caught up dates its candidates at the median of recent
    /// blocks plus a second, which can stand ahead of the wall clock. Nothing
    /// has aged there and there is nothing fresher to write.
    #[test]
    fn a_candidate_dated_ahead_of_the_clock_has_not_aged() {
        assert!(!gone_stale(BUILT_AT + 600, BUILT_AT));
    }

    /// The three conditions that were there before, which this must not have
    /// quietly dropped.
    #[test]
    fn the_older_reasons_to_stop_still_stop_a_search() {
        assert!(!worth_carrying_on(false, false, true, BUILT_AT, BUILT_AT));
        assert!(!worth_carrying_on(true, true, true, BUILT_AT, BUILT_AT));
        assert!(!worth_carrying_on(true, false, false, BUILT_AT, BUILT_AT));
    }
}

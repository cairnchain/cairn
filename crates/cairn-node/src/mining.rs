//! Producing blocks.
//!
//! The search is spread across the cores the machine has, each on its own
//! stretch of the nonce space, all stopping the moment one of them finds
//! something or the chain moves underneath them. A serious miner uses cards
//! rather than cores, but nothing about what makes a block valid changes with
//! how hard it was looked for.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cairn_chain::{Accepted, ChainStore};
use cairn_crypto::PublicKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::pow::{median_time_past, meets_target};
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, BlockError, ConsensusParams};
use cairn_net::node::Refused;
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
/// rebuilding is worth what it costs. Nothing is lost by rebuilding, because
/// each hash is independent of the ones before it.
///
/// "Nothing measurable" is what stood here, and it was measurable: a rebuild
/// asks `selection`, which asked the pool again with the signatures, at 168
/// bytes hashed and one curve verification an input for every transfer
/// waiting. At the pool's ceiling that is a hundred and twenty milliseconds,
/// twice a minute, inside `Node::with_chain` and so holding the chain lock.
/// `selection` leaves the signatures to the batch verification in
/// `evaluate_block_body` now, which is where a block is judged and where they
/// were being checked the second time.
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

/// How long the miner waits before asking again why it cannot build.
const PAUSE: Duration = Duration::from_millis(200);

/// Why the miner is not building a block, said once when it starts and not
/// again until the reason changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Waiting {
    /// The node has not validated its way past the ledger it was handed, and
    /// every block it made would be refused on the spot.
    ForProbation,
    /// Nobody to hand a block to, on a node that was given somewhere to start.
    ///
    /// A block mined with no peer starts a chain of this node's own. The chain
    /// undoes only so far, so once that chain is deeper than the undo limit
    /// the network's blocks are refused for good and the node can never rejoin
    /// it. Before this, a node started with `--mine` behind a firewall or
    /// while its seeds were down mined from its first block, printed `mined`
    /// for every block, and was a directory to be wiped a day later.
    ForAPeer,
    /// The chain is still arriving: its newest block is dated long ago and it
    /// moved a moment ago. A block built now would be built on a chain the
    /// network has already left, and would be undone as soon as the rest of
    /// the chain arrived, or, deep enough, never.
    ForTheChain,
    /// A network whose first block is written into the program, and a chain
    /// that does not hold it yet: anything built here would be a second first
    /// block, refused.
    ForAChain,
    /// The recent blocks are dated past what this node's own clock would
    /// accept, so every block it could build is one it would refuse itself.
    ForTheClock,
    /// No block can be assembled on this chain, for the reason given: a rule
    /// this build does not have is the one it meets.
    CannotAssemble(String),
}

impl fmt::Display for Waiting {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForProbation => out.write_str(
                "mining waits until this node has checked the blocks above the ledger it was \
                 handed",
            ),
            Self::ForAPeer => out.write_str(
                "mining waits until this node has a peer: a block mined with nobody to take it \
                 starts a chain of this node's own, and once that chain is deeper than a node \
                 will undo, this node can never follow the network again",
            ),
            Self::ForTheChain => out.write_str(
                "mining waits while the chain arrives: its newest block is dated long ago, and \
                 a block built on it would be built on a chain the network has left. It mines \
                 once blocks stop arriving",
            ),
            Self::ForAChain => out.write_str(
                "mining waits until this node holds its network's first block: anything built \
                 before it would be refused as a second one",
            ),
            Self::ForTheClock => out.write_str(
                "mining waits for the clock: the recent blocks are dated past what this node \
                 would accept, so every block it could build is one it would refuse",
            ),
            Self::CannotAssemble(reason) => {
                write!(
                    out,
                    "mining waits: no block can be built on this chain ({reason})"
                )
            }
        }
    }
}

/// What the miner has to tell whoever started it.
pub(crate) enum Report<'a> {
    /// A block it found, and what this node's chain did with it.
    Found(&'a Block, &'a Accepted),
    /// Everything else, in words.
    Says(Saying<'a>),
}

/// What the miner says about its own work, apart from the blocks it finds.
pub(crate) enum Saying<'a> {
    /// A block it found and this node's own chain refused, which nobody else
    /// will take either.
    ///
    /// These were dropped: `run` kept only what `submit_block` accepted, so a
    /// miner whose every block was refused hashed on every spare core and
    /// printed nothing at all.
    Refused(&'a Block, &'a Refused),
    /// It has stopped building, and why.
    Waits(&'a Waiting),
    /// It is building again after a wait.
    Resumes,
    /// The last few blocks it mined were each replaced by another at the same
    /// height.
    Replaced(u32),
}

impl fmt::Display for Saying<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(block, refused) => {
                let id = block.id().to_string();
                write!(
                    out,
                    "refused height {:<6} {}  this node's own chain turned it down: {}",
                    block.header.height,
                    id.get(..12).unwrap_or(&id),
                    all_of(*refused),
                )
            }
            Self::Waits(waiting) => write!(out, "{waiting}"),
            Self::Resumes => out.write_str("mining again"),
            Self::Replaced(count) => write!(
                out,
                "the last {count} blocks this node mined were each replaced by another block \
                 at the same height. That is what peers refusing them looks like, and the \
                 likeliest reason is this machine's clock running ahead of theirs: check it"
            ),
        }
    }
}

/// An error and every reason under it, since the one on top of a refused block
/// names the block and not what is wrong with it.
fn all_of(error: &dyn std::error::Error) -> String {
    let mut said = error.to_string();
    let mut under = error.source();
    while let Some(reason) = under {
        said.push_str(": ");
        said.push_str(&reason.to_string());
        under = reason.source();
    }
    said
}

/// Block times behind the clock past which a newest block is old.
///
/// Far past anything an ordinary chain shows: a new block may be dated as
/// early as the median of the ones before it, which is some six block times
/// back, and a gap of a few more happens. What passes this is a chain a node
/// is reading from the past, or one that stopped.
const OLD_IN_BLOCKS: u64 = 24;

/// Block times a chain has to stand still before an old newest block is taken
/// for a chain that stopped rather than one still arriving.
///
/// A node catching up is handed blocks in batches, a moment apart. A chain
/// that stopped, because its only miner went away, does not move at all, and
/// a miner that waited for it to move would wait for ever.
const STILL_IN_BLOCKS: u64 = 2;

/// Whether the chain looks like one still arriving: its newest block is dated
/// long before the clock, and it moved less than a moment ago.
///
/// Read off this node's own chain and clock and nothing a peer says: how much
/// work a peer claims to have is written by the peer, and a miner that waited
/// on it could be stopped by anybody who connected and claimed a lot.
fn still_arriving(newest: Option<u64>, now: u64, still_for: Duration, block_time: u64) -> bool {
    newest.is_some_and(|dated| {
        now.saturating_sub(dated) > block_time.saturating_mul(OLD_IN_BLOCKS)
            && still_for.as_secs() < block_time.saturating_mul(STILL_IN_BLOCKS)
    })
}

/// Whether anything stops the miner before it looks at the chain.
///
/// `alone` is a node with nowhere to start from: no seed was given and none is
/// written in for its network. That node is the whole of its network, the way
/// the throwaway network is run on one machine, and it mines alone because
/// there is nobody else to wait for. Every other node waits for a peer, and
/// then for the chain to stop arriving.
fn held_back(on_probation: bool, peers: usize, alone: bool, arriving: bool) -> Option<Waiting> {
    if on_probation {
        Some(Waiting::ForProbation)
    } else if alone {
        None
    } else if peers == 0 {
        Some(Waiting::ForAPeer)
    } else if arriving {
        Some(Waiting::ForTheChain)
    } else {
        None
    }
}

/// Blocks above one of this node's own before it counts as kept.
const SETTLED: u64 = 6;

/// Blocks of this node's own replaced in a row before the miner says so.
///
/// One lost now and then is a race, and a miner loses some. Three in a row is
/// a pattern, and the one with a cause on this side is a clock ahead of the
/// network's: every peer refuses a block dated past its own drift, at no cost
/// to anybody, and the chain moves on without it.
const REPLACED_BEFORE_SAYING: u32 = 3;

/// The blocks this node mined, until each is kept under the tip or replaced.
///
/// A miner whose clock runs ahead mines blocks only it accepts. They are
/// announced, refused by every peer, and replaced a block later, and nothing
/// on this side said so: the slow clock has a line and the fast one had none.
#[derive(Default)]
struct Mined {
    waiting: Vec<(u64, Hash32)>,
    replaced_in_a_row: u32,
    said: bool,
}

impl Mined {
    fn remember(&mut self, height: u64, id: Hash32) {
        self.waiting.push((height, id));
    }

    /// Settles every block that can be settled against the chain as it stands,
    /// and answers the run of replaced blocks the first time it is long enough
    /// to say.
    fn settle(&mut self, tip: Option<u64>, id_at: impl Fn(u64) -> Option<Hash32>) -> Option<u32> {
        let tip = tip?;
        let replaced = &mut self.replaced_in_a_row;
        let said = &mut self.said;
        self.waiting.retain(|&(height, id)| {
            if id_at(height) != Some(id) {
                *replaced = replaced.saturating_add(1);
                false
            } else if tip.saturating_sub(height) >= SETTLED {
                *replaced = 0;
                *said = false;
                false
            } else {
                true
            }
        });
        if self.replaced_in_a_row >= REPLACED_BEFORE_SAYING && !self.said {
            self.said = true;
            return Some(self.replaced_in_a_row);
        }
        None
    }
}

/// Mines until `running` is cleared, reporting each block it finds and what
/// the chain did with it, each block the chain refused, and each time it has
/// to stop and why.
///
/// Both halves of a found block, because finding a block and adding one to
/// this chain are not the same event. A block found a moment after somebody
/// else's for the same height is recorded on a branch lighter than the one
/// this node follows, and `is_ok()` cannot tell that from extending the chain.
/// Everything the caller can honestly say about the work it just spent is in
/// the variant.
pub(crate) fn run(
    node: &Node,
    params: &ConsensusParams,
    reward_to: PublicKey,
    alone: bool,
    running: &AtomicBool,
    mut report: impl FnMut(Report<'_>),
) {
    let mut waiting: Option<Waiting> = None;
    let mut mined = Mined::default();
    // The tip as last seen and when it was last seen to move. Counted from
    // the start, so a node that comes up on an old chain gives it a moment to
    // start arriving before building on it.
    let mut last_tip = None;
    let mut moved = Instant::now();
    while running.load(Ordering::SeqCst) {
        let (replaced, tip, newest) = node.with_chain(|chain| {
            let replaced = mined.settle(chain.height(), |at| chain.id_at(at));
            let newest = chain
                .state()
                .recent_headers()
                .last()
                .map(|header| header.timestamp);
            (replaced, chain.tip(), newest)
        });
        if let Some(count) = replaced {
            report(Report::Says(Saying::Replaced(count)));
        }
        if tip != last_tip {
            last_tip = tip;
            moved = Instant::now();
        }
        let arriving = still_arriving(
            newest,
            unix_now(),
            moved.elapsed(),
            params.target_block_time,
        );
        // A refusal for probation lands here on the next round, and is a wait
        // like any other rather than a reason to build again.
        let built = match held_back(
            node.probation().is_some(),
            node.peers_introduced(),
            alone,
            arriving,
        ) {
            Some(reason) => Err(reason),
            None => build(node, params, reward_to),
        };
        let (candidate, extending) = match built {
            Ok(built) => built,
            Err(reason) => {
                if waiting.as_ref() != Some(&reason) {
                    report(Report::Says(Saying::Waits(&reason)));
                    waiting = Some(reason);
                }
                thread::sleep(PAUSE);
                continue;
            }
        };
        if waiting.take().is_some() {
            report(Report::Says(Saying::Resumes));
        }
        let Some(block) = search(node, &candidate, extending, running) else {
            continue;
        };
        match node.submit_block(block.clone()) {
            Ok(landed) => {
                if matches!(landed, Accepted::Extended | Accepted::Reorganised { .. }) {
                    mined.remember(block.header.height, block.id());
                }
                report(Report::Found(&block, &landed));
            }
            Err(refused) => report(Report::Says(Saying::Refused(&block, &refused))),
        }
    }
}

/// Assembles the block this node would like to see next, or says why it
/// cannot.
///
/// Two different reasons answered the same `None` here: a clock to wait for,
/// which passes by itself, and an assembly the rules refuse, which does not.
fn build(
    node: &Node,
    params: &ConsensusParams,
    reward_to: PublicKey,
) -> Result<(Block, Option<Hash32>), Waiting> {
    node.with_chain(|chain| candidate(chain, params, reward_to, unix_now()))
}

/// The block `build` would assemble on `chain` at the time `now`.
fn candidate(
    chain: &ChainStore,
    params: &ConsensusParams,
    reward_to: PublicKey,
    now: u64,
) -> Result<(Block, Option<Hash32>), Waiting> {
    if chain.is_empty() && params.genesis.is_some() {
        return Err(Waiting::ForAChain);
    }
    let extending = chain.tip();
    let state = chain.state();
    let height = state
        .next_height()
        .ok_or_else(|| Waiting::CannotAssemble(BlockError::HeightOverflow.to_string()))?;

    // The timestamp has to clear the median of recent blocks. On a chain
    // whose blocks are minutes apart that is always the wall clock; on one
    // being caught up it is the median plus a second.
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
        return Err(Waiting::ForTheClock);
    }
    let timestamp = now.max(earliest);

    // Whatever the pool holds that fits together, and what those transfers
    // pay to be carried.
    let (transfers, fees) = chain.selection(params.max_transfers_per_block);
    let reward = params.reward_at(height).checked_add(fees).ok_or_else(|| {
        Waiting::CannotAssemble("the reward and the fees add up past what an amount holds".into())
    })?;

    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(reward, reward_to)]);
    let block = assemble_block(state, coinbase, transfers, params, timestamp, 0)
        .map_err(|error| Waiting::CannotAssemble(error.to_string()))?;
    Ok((block, extending))
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
        let mut here = None;
        for _ in 0..count {
            let shared = (Arc::clone(&next), Arc::clone(&found));
            // Asked for rather than taken, for the reason the signature
            // checker in `cairn-ledger` gives beside the same call:
            // `Scope::spawn` panics when the machine will not make a thread,
            // and under `panic = "abort"` that was the whole node gone rather
            // than a miner with fewer hands. Refused, this thread searches
            // beside the ones it was granted and asks for no more.
            let asked = thread::Builder::new()
                .name("cairn-search".to_owned())
                .spawn_scoped(scope, move || {
                    let (next, found) = shared;
                    search_one(node, candidate, extending, running, &next, Some(&found))
                });
            if let Ok(hand) = asked {
                hands.push(hand);
            } else {
                here = search_one(node, candidate, extending, running, &next, Some(&found));
                break;
            }
        }
        here.or_else(|| {
            hands
                .into_iter()
                .find_map(|hand| hand.join().ok().flatten())
        })
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

    /// What the number is, and not only where the boundary it draws falls.
    ///
    /// Every test around this one is written in terms of
    /// `CANDIDATE_PATIENCE`, so the boundary moves with it and they hold the
    /// mechanism whatever it is set to. At ten hours they all pass, and at ten
    /// hours the thing they are about is gone: the candidate is never dated
    /// again inside any stall worth reporting.
    ///
    /// What the note on the constant argues is a relation to the spacing the
    /// network aims for, and this is that relation. Its other half, that the
    /// patience is long enough for rebuilding to cost nothing measurable, is
    /// not held here and could not be: measurable is a reading of whatever
    /// machine is asked.
    #[test]
    fn the_patience_is_shorter_than_the_block_it_is_dated_within() {
        let aimed_at = cairn_ledger::validation::ConsensusParams::testnet().target_block_time;
        assert!(
            CANDIDATE_PATIENCE < aimed_at,
            "a candidate is searched {CANDIDATE_PATIENCE} seconds before it is dated again, on a \
             network aiming for a block every {aimed_at}. A stalled chain would then report a gap \
             more than a whole block short of the one it took, and the retarget that exists to \
             bring the difficulty back down is shown nothing to bring it down for"
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

/// What the miner does before and after it has somebody to mine for, and what
/// it says about the blocks and the waits in between.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod saying {
    use super::{candidate, held_back, run, Mined, Report, Saying, Waiting, PAUSE};
    use cairn_chain::{Accepted, ChainStore};
    use cairn_crypto::{PublicKey, SecretKey};
    use cairn_ledger::block::{Activation, BLOCK_VERSION};
    use cairn_ledger::pow::median_time_past;
    use cairn_ledger::validation::{mine_block, ConsensusParams};
    use cairn_net::Node;
    use cairn_primitives::Hash32;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const NOW: u64 = 2_000_000_000;

    fn reward_key() -> PublicKey {
        SecretKey::generate().unwrap().public_key()
    }

    /// What the miner reported, owned, so it can cross to the test's thread.
    #[derive(Debug, PartialEq, Eq)]
    enum Heard {
        Found(u64, bool),
        Refused(String),
        Waits(Waiting),
        Resumes,
        Replaced(u32),
    }

    fn heard(report: &Report<'_>) -> Heard {
        match report {
            Report::Found(block, landed) => Heard::Found(
                block.header.height,
                matches!(landed, Accepted::Extended | Accepted::Reorganised { .. }),
            ),
            Report::Says(saying @ Saying::Refused(..)) => Heard::Refused(saying.to_string()),
            Report::Says(Saying::Waits(waiting)) => Heard::Waits((*waiting).clone()),
            Report::Says(Saying::Resumes) => Heard::Resumes,
            Report::Says(Saying::Replaced(count)) => Heard::Replaced(*count),
        }
    }

    /// Clears `running` however the test ends, so a failed assertion ends the
    /// miner rather than leaving the scope waiting on it for ever.
    struct Stop<'a>(&'a AtomicBool);

    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    /// Runs the miner on a node of its own, hands what it reports to `test`,
    /// and stops it.
    fn mining(
        params: ConsensusParams,
        alone: bool,
        test: impl FnOnce(&Node, &mpsc::Receiver<Heard>),
    ) {
        let node = Node::bind(params, "127.0.0.1:0".parse().unwrap()).unwrap();
        let running = AtomicBool::new(true);
        let (tell, told) = mpsc::channel();
        let key = reward_key();
        thread::scope(|scope| {
            scope.spawn(|| {
                run(&node, &params, key, alone, &running, |report| {
                    let _ = tell.send(heard(&report));
                });
            });
            let _stop = Stop(&running);
            test(&node, &told);
        });
        node.shutdown();
    }

    /// The next thing the miner says. Half a minute is many times what any
    /// of these takes, and short enough that a miner saying nothing fails the
    /// test rather than outlasting whatever is timing it.
    fn next(told: &mpsc::Receiver<Heard>) -> Heard {
        told.recv_timeout(Duration::from_secs(30))
            .expect("the miner said nothing at all")
    }

    /// A node with nowhere to start from mines on its own.
    ///
    /// It is the whole of its network, which is how the throwaway network is
    /// run on one machine. The wait for a peer must not reach it, and a miner
    /// that waited for everybody would have passed every test that only asked
    /// about waiting.
    #[test]
    fn a_miner_with_nowhere_to_start_mines_alone() {
        mining(ConsensusParams::testnet(), true, |_, told| {
            assert_eq!(
                next(told),
                Heard::Found(0, true),
                "a node that is its whole network did not mine its first block"
            );
        });
    }

    /// A node that was given somewhere to start does not build a block before
    /// it has a peer, says so once, and mines once it has one.
    ///
    /// Nothing asked this, so a node started with `--mine` whose seeds did not
    /// answer mined a chain of its own from the first block, printed `mined`
    /// for every block, and past the depth a node undoes could never rejoin
    /// the network: ninety eight blocks in twelve seconds on devnet, with
    /// `peers 0` on every status line.
    #[test]
    fn a_miner_given_somewhere_to_start_waits_for_a_peer_and_says_so_once() {
        mining(ConsensusParams::testnet(), false, |node, told| {
            assert_eq!(
                next(told),
                Heard::Waits(Waiting::ForAPeer),
                "a miner with no peer built a block, or built nothing and said nothing"
            );
            // Rounds for a miner that repeated itself to be heard doing it.
            thread::sleep(PAUSE * 5);
            assert_eq!(
                node.height(),
                None,
                "and it mined with nobody to hand the block to"
            );

            let peer =
                Node::bind(ConsensusParams::testnet(), "127.0.0.1:0".parse().unwrap()).unwrap();
            node.connect(peer.address()).unwrap();
            assert_eq!(
                next(told),
                Heard::Resumes,
                "the wait was said more than once, or its end was not said at all"
            );
            assert_eq!(
                next(told),
                Heard::Found(0, true),
                "a miner that had a peer did not mine"
            );
            peer.shutdown();
        });
    }

    /// A block this node's own chain refuses is said, with the reason under
    /// it.
    ///
    /// `run` kept only what `submit_block` accepted and dropped the rest, so a
    /// miner whose every block was refused hashed on every spare core and
    /// printed nothing.
    #[test]
    fn a_block_its_own_chain_refuses_is_said_with_the_reason() {
        let before_opening = ConsensusParams {
            opens_at: u64::MAX,
            ..ConsensusParams::testnet()
        };
        mining(before_opening, true, |_, told| match next(told) {
            Heard::Refused(said) => {
                assert!(
                    said.starts_with("refused height 0 "),
                    "the refusal does not say which block: {said}"
                );
                assert!(
                    said.contains("before this network opened"),
                    "the refusal does not say why: {said}"
                );
            }
            other => panic!("a block the chain refused was not said: {other:?}"),
        });
    }

    /// A miner with a peer whose chain is old and has just moved waits for it
    /// to stop moving, says so once, and then mines on it.
    ///
    /// Nothing asked this, so a node that came up on an old chain with a peer
    /// mined on the old tip at once, while the rest of the chain was on its
    /// way.
    #[test]
    fn a_miner_on_an_old_chain_waits_for_it_to_stop_arriving() {
        let params = ConsensusParams {
            target_block_time: 1,
            ..ConsensusParams::testnet()
        };
        let long_ago = super::unix_now() - 1_000;
        let chain = grown(&params, 3, long_ago);
        let node = Node::bind(params, "127.0.0.1:0".parse().unwrap()).unwrap();
        for height in 0..3 {
            node.submit_block(chain.block_at(height).unwrap().clone())
                .unwrap();
        }
        let peer = Node::bind(params, "127.0.0.1:0".parse().unwrap()).unwrap();
        node.connect(peer.address()).unwrap();

        let running = AtomicBool::new(true);
        let (tell, told) = mpsc::channel();
        let key = reward_key();
        thread::scope(|scope| {
            scope.spawn(|| {
                run(&node, &params, key, false, &running, |report| {
                    let _ = tell.send(heard(&report));
                });
            });
            let _stop = Stop(&running);
            assert_eq!(
                next(&told),
                Heard::Waits(Waiting::ForTheChain),
                "a miner built on an old chain that had only just moved"
            );
            assert_eq!(
                next(&told),
                Heard::Resumes,
                "and never took it for a chain that stopped"
            );
            assert_eq!(next(&told), Heard::Found(3, true), "then mined on it");
        });
        node.shutdown();
        peer.shutdown();
    }

    /// A chain that goes on arriving keeps the miner waiting for as long as
    /// it does, and the wait is counted from the last block that arrived.
    ///
    /// Counted from the start instead, a miner on a node still being handed
    /// the chain in batches resumed after the first moment of it, on a tip the
    /// next batch would undo.
    #[test]
    fn a_chain_that_goes_on_arriving_keeps_the_miner_waiting() {
        let params = ConsensusParams {
            target_block_time: 2,
            ..ConsensusParams::testnet()
        };
        let long_ago = super::unix_now() - 1_000;
        let blocks = 12;
        let chain = grown(&params, blocks, long_ago);
        let node = Node::bind(params, "127.0.0.1:0".parse().unwrap()).unwrap();
        node.submit_block(chain.block_at(0).unwrap().clone())
            .unwrap();
        let peer = Node::bind(params, "127.0.0.1:0".parse().unwrap()).unwrap();
        node.connect(peer.address()).unwrap();

        let running = AtomicBool::new(true);
        let (tell, told) = mpsc::channel();
        let key = reward_key();
        thread::scope(|scope| {
            scope.spawn(|| {
                run(&node, &params, key, false, &running, |report| {
                    let _ = tell.send(heard(&report));
                });
            });
            let _stop = Stop(&running);
            assert_eq!(next(&told), Heard::Waits(Waiting::ForTheChain));
            // A block every half second, for two and a half times the moment
            // the chain has to stand still.
            for height in 1..blocks {
                thread::sleep(Duration::from_millis(500));
                node.submit_block(chain.block_at(height).unwrap().clone())
                    .unwrap();
            }
            assert!(
                told.try_recv().is_err(),
                "the miner resumed while blocks were still arriving"
            );
            assert_eq!(
                next(&told),
                Heard::Resumes,
                "and never resumed once they stopped"
            );
        });
        node.shutdown();
        peer.shutdown();
    }

    /// Every reason to hold the miner back, in the order they are asked.
    #[test]
    fn a_miner_is_held_back_by_probation_and_by_having_nobody_to_mine_for() {
        assert_eq!(held_back(true, 3, true, false), Some(Waiting::ForProbation));
        assert_eq!(held_back(true, 0, false, true), Some(Waiting::ForProbation));
        assert_eq!(held_back(false, 0, false, false), Some(Waiting::ForAPeer));
        assert_eq!(held_back(false, 0, false, true), Some(Waiting::ForAPeer));
        assert_eq!(held_back(false, 1, false, true), Some(Waiting::ForTheChain));
        assert_eq!(
            held_back(false, 0, true, true),
            None,
            "a node alone waits for nobody"
        );
        assert_eq!(held_back(false, 1, false, false), None);
    }

    /// A chain whose newest block is old and which has just moved is still
    /// arriving, and one that has stood still for a while has stopped.
    ///
    /// A node with a peer that was still reading the chain built on the old
    /// tip it held, and every block it found there was undone when the rest
    /// arrived; one that stopped for that reason alone would never restart a
    /// chain whose only miner went away.
    #[test]
    fn a_chain_still_arriving_is_told_from_one_that_stopped() {
        let block_time = 60;
        let old = NOW - block_time * super::OLD_IN_BLOCKS - 1;
        let still = |seconds: u64| Duration::from_secs(seconds);
        let moment = block_time * super::STILL_IN_BLOCKS;
        assert!(
            super::still_arriving(Some(old), NOW, still(0), block_time),
            "an old block that has just arrived is a chain still arriving"
        );
        assert!(
            super::still_arriving(Some(old), NOW, still(moment - 1), block_time),
            "and stays one until it has stood still for a moment"
        );
        assert!(
            !super::still_arriving(Some(old), NOW, still(moment), block_time),
            "a chain that has stood still for a moment has stopped, and is mined on"
        );
        assert!(
            !super::still_arriving(Some(old + 1), NOW, still(0), block_time),
            "a newest block dated inside the window is a chain that is current"
        );
        assert!(
            !super::still_arriving(None, NOW, still(0), block_time),
            "an empty chain has nothing arriving to wait for"
        );
    }

    /// A chain grown by `blocks` of this miner's own candidates, each added at
    /// the time `now`.
    fn grown(params: &ConsensusParams, blocks: u64, now: u64) -> ChainStore {
        let mut chain = ChainStore::new(*params);
        let key = reward_key();
        for _ in 0..blocks {
            let (block, _) = candidate(&chain, params, key, now).unwrap();
            chain
                .add_block(mine_block(block, 1 << 20).unwrap(), now)
                .unwrap();
        }
        chain
    }

    /// A clock to wait for and a block the rules will not let this build make
    /// are two answers, and each is the one given.
    ///
    /// Both came back as the same `None`: a wait that passes by itself and a
    /// wall that does not were one silence, and a miner meeting the second
    /// rebuilt every two hundred milliseconds for ever without a word.
    #[test]
    fn a_clock_to_wait_for_is_not_a_block_that_cannot_be_made() {
        static LATER: [Activation; 2] = [
            Activation {
                height: 0,
                version: BLOCK_VERSION,
            },
            Activation {
                height: 1,
                version: BLOCK_VERSION + 1,
            },
        ];
        let params = ConsensusParams::testnet();
        let chain = grown(&params, 3, NOW);
        let earliest = median_time_past(chain.state().recent_headers()).unwrap() + 1;
        let drift = params.max_timestamp_drift;
        assert!(
            candidate(&chain, &params, reward_key(), earliest - drift).is_ok(),
            "a clock as far behind the chain as the drift allows could not build"
        );
        assert_eq!(
            candidate(&chain, &params, reward_key(), earliest - drift - 1).err(),
            Some(Waiting::ForTheClock),
            "a clock further behind than the drift was not told to wait"
        );

        let moved_on = ConsensusParams {
            activations: &LATER,
            ..ConsensusParams::testnet()
        };
        let chain = grown(&moved_on, 1, NOW);
        match candidate(&chain, &moved_on, reward_key(), NOW) {
            Err(Waiting::CannotAssemble(reason)) => assert!(
                reason.contains("too old"),
                "the reason no block can be made is not the one the rules gave: {reason}"
            ),
            Err(other) => panic!("a rule this build lacks was answered as {other:?}"),
            Ok(_) => panic!("a block was built under a version this build does not have"),
        }
    }

    /// A network that writes its first block into the program has nothing to
    /// build on until the chain holds it.
    ///
    /// Anything built on an empty chain is a first block, and on such a
    /// network it is refused as a second one. The miner built it anyway,
    /// found it, and had it refused, over and over.
    #[test]
    fn a_network_with_its_first_block_written_in_waits_for_it() {
        let open = ConsensusParams::testnet();
        let (first, _) = candidate(&ChainStore::new(open), &open, reward_key(), NOW).unwrap();
        let pinned = ConsensusParams {
            genesis: Some(first.id()),
            ..open
        };
        assert_eq!(
            candidate(&ChainStore::new(pinned), &pinned, reward_key(), NOW).err(),
            Some(Waiting::ForAChain),
            "a miner built a first block on a network that has one written in"
        );
    }

    /// An identifier for the block at `height`, one per height and worked out
    /// rather than written down.
    fn at(height: u64) -> Hash32 {
        cairn_primitives::hash::hash(
            cairn_primitives::hash::Domain::BlockHeaderId,
            &height.to_le_bytes(),
        )
    }

    /// Blocks of this node's own replaced three times running are said once,
    /// and a block that stays under the chain starts the count again.
    ///
    /// A miner whose clock is ahead of the network's mines blocks every peer
    /// refuses, and each is replaced a block later. The slow clock had a line
    /// and the fast one had none, so an operator saw `mined` for every block
    /// and a chain that never carried one.
    #[test]
    fn its_own_blocks_replaced_three_times_running_are_said_once() {
        let mut mined = Mined::default();
        let elsewhere = |_: u64| Some(at(0));
        for height in 1..=3 {
            mined.remember(height, at(height));
        }
        assert_eq!(
            mined.settle(Some(4), elsewhere),
            Some(3),
            "three replaced, said"
        );
        mined.remember(5, at(5));
        assert_eq!(
            mined.settle(Some(6), elsewhere),
            None,
            "and not said again for a fourth"
        );

        // One kept under the tip ends the run.
        mined.remember(7, at(7));
        assert_eq!(
            mined.settle(Some(7 + super::SETTLED), |_| Some(at(7))),
            None
        );
        for height in 8..=9 {
            mined.remember(height, at(height));
        }
        assert_eq!(
            mined.settle(Some(10), elsewhere),
            None,
            "two replaced after one kept is not three running"
        );
        mined.remember(10, at(10));
        assert_eq!(
            mined.settle(Some(11), elsewhere),
            Some(3),
            "and three again after it are said again"
        );

        // A block still on the chain and not yet buried waits to be settled.
        let mut mined = Mined::default();
        mined.remember(1, at(1));
        assert_eq!(
            mined.settle(Some(1 + super::SETTLED - 1), |_| Some(at(1))),
            None
        );
        assert_eq!(mined.waiting.len(), 1, "a block not yet buried was settled");
        assert_eq!(
            mined.settle(None, elsewhere),
            None,
            "and nothing is settled without a tip"
        );
    }

    /// What each wait says is about that wait.
    #[test]
    fn each_wait_says_what_it_is_waiting_for() {
        let said = |waiting: Waiting| Saying::Waits(&waiting).to_string();
        assert!(said(Waiting::ForProbation).contains("ledger it was handed"));
        assert!(said(Waiting::ForAPeer).contains("until this node has a peer"));
        assert!(said(Waiting::ForAChain).contains("first block"));
        assert!(said(Waiting::ForTheClock).contains("waits for the clock"));
        assert!(said(Waiting::CannotAssemble("a reason".into())).contains("(a reason)"));
        assert_eq!(Saying::Resumes.to_string(), "mining again");
        assert!(Saying::Replaced(3)
            .to_string()
            .starts_with("the last 3 blocks"));
    }

    /// The miner asks the machine for its threads rather than taking them.
    ///
    /// `Scope::spawn` panics when the machine will not make a thread, and
    /// under `panic = "abort"` that ended the node, not only the miner. The
    /// signature checker in `cairn-ledger` was rewritten for exactly this and
    /// the miner beside it was not. A refusal cannot be arranged in a test on
    /// every system, so the call is read, the way this repository reads the
    /// one call site in `seeds.rs`.
    #[test]
    fn the_miner_asks_for_its_threads_rather_than_taking_them() {
        const SOURCE: &str = include_str!("mining.rs");
        let search = SOURCE
            .split_once("\nfn search(")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .expect("search is written here")
            .0;
        assert!(
            !search.contains("scope.spawn("),
            "the miner takes its threads with Scope::spawn, which panics when refused"
        );
        assert!(
            search.contains(".spawn_scoped(scope,"),
            "the miner does not ask for its threads"
        );
    }
}

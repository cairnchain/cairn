//! Withheld blocks: selfish and stubborn mining against the fork choice as it
//! is.
//!
//! Lab scenario R20 (attacks A04 and A05 of the 3 October catalogue). A miner
//! with less than half of the work keeps the blocks it finds to itself and
//! releases them to orphan honest ones. The threat model says this is
//! untreated, "as on every Nakamoto chain", and that the one lever taken is
//! the tie rule: a branch of equal work does not displace the one a node
//! already follows, and nor does a rival tip of its height carrying no more
//! than half the followed tip's difficulty in extra work. Eyal and Sirer give
//! the share a withholding miner earns as a function of its own share `alpha`
//! and of `gamma`, the part of the honest work that ends up mining on the
//! withholder's block when two blocks race at one height; it pays above
//! `alpha` once `alpha > (1 - gamma) / (3 - 2 gamma)`, a third at `gamma = 0`
//! and a quarter at `gamma = 1/2`.
//!
//! Nothing here is a model of the fork choice. Every honest node is a real
//! [`ChainStore`], every block is assembled, mined and validated, and what a
//! node follows is whatever `add_block` decided. The withholder's view of the
//! public chain is a real store as well, so it weighs branches as every node
//! does. Around them sits a small discrete event simulation: each miner finds
//! blocks as a Poisson process at a rate set by its share and by the
//! difficulty its own tip asks, blocks travel with exponential delays, and the
//! withholder follows a strategy from the papers, written by length as they
//! are.
//!
//! **What was measured.** Four honest nodes of equal share, a 60 second
//! block, honest blocks two seconds apart on average, and three ways the
//! withholder can be placed: slow (it hears honest blocks in two seconds and
//! its own reach honest nodes in six), even (one and one), and fast (a tenth
//! of a second each way). Eight thousand blocks a cell, on the eleven shares
//! of the testnet-9 study, every cell from four seeds (the control from one),
//! revenue averaged and races pooled; run with `cargo test -p cairn-chain
//! --test withheld_blocks --release -- --ignored --nocapture`, an hour and a
//! half on ten cores shared with other work.
//!
//! ```text
//! revenue share of the withholder (main chain blocks it mined), SM1
//!         slow                 even                 fast
//! alpha   gamma share  ES      gamma share  ES      gamma share  ES
//! 0.10    0.09  0.041  0.043   0.31  0.057  0.059   0.67  0.086  0.085
//! 0.15    0.09  0.079  0.085   0.33  0.109  0.107   0.67  0.138  0.139
//! 0.20    0.09  0.134  0.140   0.34  0.167  0.165   0.68  0.205  0.201
//! 0.25    0.09  0.193  0.205   0.33  0.235  0.231   0.67  0.267  0.269
//! 0.28    0.09  0.243  0.250   0.33  0.268  0.276   0.68  0.313  0.314
//! 0.30    0.09  0.269  0.283   0.33  0.306  0.309   0.67  0.344  0.345
//! 0.33    0.09  0.328  0.336   0.33  0.355  0.361   0.68  0.394  0.397
//! 0.35    0.08  0.361  0.375   0.34  0.406  0.400   0.67  0.430  0.433
//! 0.38    0.09  0.425  0.441   0.32  0.450  0.462   0.68  0.498  0.495
//! 0.40    0.10  0.482  0.492   0.33  0.509  0.511   0.67  0.534  0.539
//! 0.45    0.09  0.636  0.657   0.33  0.650  0.671   0.66  0.683  0.690
//! ```
//!
//! ```text
//! lead stubborn (never overrides, matches instead): share and deep gamma on
//! the real retarget, then with every block weighing one
//!         slow                     even                     fast
//! alpha   real        flat         real        flat         real        flat
//! 0.10    0.027 0.12  0.027 0.12   0.051 0.36  0.053 0.37   0.083 0.64  0.083 0.69
//! 0.15    0.058 0.10  0.057 0.10   0.092 0.31  0.093 0.32   0.139 0.70  0.137 0.70
//! 0.20    0.090 0.09  0.095 0.09   0.142 0.34  0.144 0.34   0.194 0.64  0.201 0.65
//! 0.25    0.141 0.09  0.141 0.09   0.209 0.33  0.208 0.34   0.266 0.66  0.266 0.69
//! 0.28    0.173 0.09  0.176 0.09   0.245 0.32  0.252 0.33   0.315 0.67  0.316 0.68
//! 0.30    0.203 0.09  0.205 0.10   0.279 0.33  0.280 0.33   0.358 0.67  0.360 0.67
//! 0.33    0.250 0.10  0.244 0.09   0.337 0.32  0.343 0.33   0.420 0.65  0.420 0.67
//! 0.35    0.292 0.11  0.290 0.09   0.381 0.33  0.383 0.33   0.466 0.67  0.455 0.67
//! 0.38    0.354 0.11  0.339 0.09   0.453 0.33  0.457 0.33   0.524 0.66  0.543 0.68
//! 0.40    0.407 0.12  0.417 0.09   0.507 0.34  0.503 0.33   0.564 0.67  0.573 0.66
//! 0.45    0.600 0.16  0.581 0.09   0.665 0.35  0.713 0.34   0.737 0.67  0.740 0.69
//! ```
//!
//! ```text
//! the share at which revenue crosses the share, linear between grid points
//!                              slow    even    fast
//! Eyal and Sirer at gamma      0.323   0.286   0.199
//! SM1                          0.333   0.294   0.186
//! lead stubborn, real          0.396   0.323   0.213
//! lead stubborn, flat          0.394   0.318   0.196
//! best of the two, real        0.333   0.294   0.186
//! best of the two, before      0.301   0.266   0.177
//! ```
//!
//! `ES` is Eyal and Sirer's formula at the gamma measured in the same run,
//! counted over races at one height only; their threshold is a third at
//! gamma 0, a quarter at gamma 1/2 and nought at gamma 1, and its first line
//! above is taken at the gamma measured here, 0.09 / 0.33 / 0.67. Deep gamma is the
//! same count over matches two or more blocks deep. The honest control
//! (`alpha` mined and published at once) earned within a hundredth of `alpha`
//! in every cell. The last line is the study's figure for the fork choice
//! before the band (`sims/q1-results.txt` of the testnet-9 study, sixteen
//! seeds), which this file measured as 0.33 / 0.30 / 0.20 from one seed on a
//! coarser grid; the study puts the band at 0.333 / 0.284 / 0.181.
//!
//! **What it says.** Selfish mining behaves here as the papers say it does on
//! any chain, and the tie rule does what the threat model claims for it and
//! no more. At one height the two blocks carry the same work, since the
//! retarget reads only the parent, so the race goes to whichever block a node
//! heard first, and gamma is set by where the withholder sits in the network,
//! not by the rule. SM1 earns within noise of the formula in every cell and
//! sets the threshold: a third for a withholder that hears and speaks late,
//! under three tenths for one as quick as the honest nodes, under a fifth for
//! one that reaches them first.
//!
//! Two branches of the same length that fork two or more blocks deep do not
//! carry the same work. Each block's difficulty follows its parent's
//! timestamp, so the branch whose blocks are dated earlier asks more of the
//! blocks above them and is heavier, by a few hundredths of a block. That is
//! inside the band, so such a match is a tie and arrival settles it, as at
//! one height: the deep gamma of lead stubbornness on the real retarget is the
//! flat lane's, a tenth, a third and two thirds by placement, and so, within
//! noise, are its revenue and its threshold. It pays from a higher share than
//! SM1 in every placement; past two fifths of the work in the fast placement
//! it earns more than SM1 does, which is the papers' own finding for a
//! withholder that wins two races in three, and owes nothing to the dates.
//!
//! Before the band the fork choice switched on any surplus. A withholder that
//! matches rather than overrides matches with blocks it found, and dated,
//! earlier, so it won those matches by work rather than by arrival: deep gamma
//! 0.87 to 1.00 in every placement, against a tenth to two thirds when every
//! block weighed one. Lead stubbornness then paid from 0.30 / 0.27 / 0.18 of
//! the work, at or below SM1 and below the papers' figure at the measured
//! gamma, and every miner gained by dating its blocks early (T8-4 of the
//! testnet-8 findings). `a_race_two_blocks_deep_goes_to_the_branch_heard_first` holds
//! the fact the band turns on; the tables measure what it is worth.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fmt::Write;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Mutex;

use cairn_chain::{ChainError, ChainStore};
use cairn_crypto::{PublicKey, SecretKey};
use cairn_fuzz::Rng;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::pow::median_time_past;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, expected_difficulty, mine_block, ConsensusParams,
};
use cairn_ledger::LedgerState;
use cairn_primitives::Hash32;

const ATTEMPTS: u64 = 1 << 32;

/// Testnet rules with an opening difficulty a test can mine thousands of
/// blocks at, and high enough that a few seconds between two timestamps
/// moves the difficulty of the block after them.
///
/// At `2^13` and a sixty second block with a sixty block half life, one
/// second of timestamp is about one and a half units of difficulty.
const TIMED: u64 = 1 << 13;

/// An opening difficulty of one, which the retarget cannot lower and, on a
/// chain that does not run ahead of its schedule, does not raise: every block
/// weighs one, so work is length and every race of equal length is a tie the
/// first block heard settles. What the fork choice would be if timestamps
/// did not move the difficulty, kept beside the real one to tell their
/// effects apart.
const FLAT: u64 = 1;

fn rules_at(opening: u64) -> ConsensusParams {
    ConsensusParams {
        genesis_difficulty: opening,
        ..ConsensusParams::testnet()
    }
}

fn rules() -> ConsensusParams {
    rules_at(TIMED)
}

fn key(seed: u8) -> PublicKey {
    SecretKey::from_bytes(&[seed; 32]).public_key()
}

fn block_on(state: &LedgerState, params: &ConsensusParams, to: PublicKey, timestamp: u64) -> Block {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, to)]);
    let block = assemble_block(
        state,
        coinbase,
        Vec::<Transfer>::new(),
        params,
        timestamp,
        0,
    )
    .unwrap();
    mine_block(block, ATTEMPTS).expect("a nonce exists")
}

/// The earliest timestamp a block on `state` may carry that is not before
/// `clock`.
fn stamp(state: &LedgerState, clock: u64) -> u64 {
    median_time_past(state.recent_headers()).map_or(clock, |median| clock.max(median + 1))
}

// ---------------------------------------------------------------------------
// The fact the measurement turns on.
// ---------------------------------------------------------------------------

/// **A race two blocks deep goes to the branch heard first, as a race at one
/// height does.**
///
/// The two branches do not carry the same work. Both first blocks sit on one
/// parent and are asked the same difficulty, but the second block of each is
/// asked a difficulty set by the first block's timestamp, and the branch
/// whose first block is dated earlier stands further ahead of the schedule,
/// is asked more, and is heavier. Under a fork choice that switched on any
/// surplus, a node that followed the later branch switched to the earlier
/// one, and a withholder matching with blocks it had found, and so dated,
/// before the honest ones won such matches by its dates wherever it sat in
/// the network (T8-4).
///
/// The two tips stand at one height and the surplus is a few hundredths of a
/// block, inside the half of the tip's difficulty that makes two tips of one
/// height a tie, so each node keeps the branch it heard first.
#[test]
fn a_race_two_blocks_deep_goes_to_the_branch_heard_first() {
    let params = rules();
    let mut state = LedgerState::new();
    let mut base = Vec::new();
    for height in 0..6u64 {
        let block = block_on(&state, &params, key(1), height * 60);
        connect_block(&mut state, &block, &params, u64::MAX / 2).unwrap();
        base.push(block);
    }
    let now = 10_000;

    // The early branch dates its first block on the schedule, the late one
    // thirty seconds after it. Their second blocks are dated alike.
    let mut early = state.clone();
    let early_first = block_on(&early, &params, key(2), 360);
    connect_block(&mut early, &early_first, &params, now).unwrap();
    let early_second = block_on(&early, &params, key(2), 420);

    let mut late = state.clone();
    let late_first = block_on(&late, &params, key(3), 390);
    connect_block(&mut late, &late_first, &params, now).unwrap();
    let late_second = block_on(&late, &params, key(3), 420);

    assert_eq!(
        early_first.header.total_work, late_first.header.total_work,
        "one block deep the two branches carry the same work"
    );
    let surplus = early_second.header.total_work - late_second.header.total_work;
    let band = u128::from(late_second.header.difficulty) / 2;
    assert!(
        surplus > 0 && surplus <= band,
        "two blocks deep the branch dated earlier is heavier, by {surplus}, and within \
         half the tip's difficulty, {band}"
    );

    // Two nodes, each hearing one branch first, block by block.
    let heard = |first: [&Block; 2], then: [&Block; 2]| {
        let mut node = ChainStore::new(params);
        for block in &base {
            node.add_block(block.clone(), now).unwrap();
        }
        for at in 0..2 {
            node.add_block(first[at].clone(), now).unwrap();
            node.add_block(then[at].clone(), now).unwrap();
            assert_eq!(
                node.tip(),
                Some(first[at].id()),
                "at depth {} the block heard first is kept",
                at + 1
            );
        }
    };
    heard([&late_first, &late_second], [&early_first, &early_second]);
    heard([&early_first, &early_second], [&late_first, &late_second]);
}

// ---------------------------------------------------------------------------
// The simulation.
// ---------------------------------------------------------------------------

/// What the withholder does with the blocks it finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Strategy {
    /// Publishes every block at once and follows the heaviest branch.
    Honest,
    /// Eyal and Sirer's SM1.
    Selfish,
    /// Nayak, Kumar, Miller and Shi's lead stubbornness: as SM1, except that
    /// when an honest block cuts its lead from two to one it publishes only
    /// enough to match the honest branch, and keeps mining on its own.
    LeadStubborn,
}

/// Mean delays, in seconds.
#[derive(Clone, Copy, Debug)]
struct Network {
    name: &'static str,
    /// From one honest node to another.
    between_honest: f64,
    /// From an honest node to the withholder.
    to_withholder: f64,
    /// From the withholder to an honest node.
    from_withholder: f64,
}

const SLOW: Network = Network {
    name: "slow",
    between_honest: 2.0,
    to_withholder: 2.0,
    from_withholder: 6.0,
};

const EVEN: Network = Network {
    name: "even",
    between_honest: 2.0,
    to_withholder: 1.0,
    from_withholder: 1.0,
};

const FAST: Network = Network {
    name: "fast",
    between_honest: 2.0,
    to_withholder: 0.1,
    from_withholder: 0.1,
};

const HONEST_NODES: usize = 4;

#[derive(Clone, Copy, Debug)]
struct Run {
    share: f64,
    strategy: Strategy,
    network: Network,
    blocks: u64,
    seed: u64,
    opening: u64,
}

/// What a run came to, read off the first honest node's branch at the end.
#[derive(Clone, Copy, Debug, Default)]
struct Outcome {
    chain: u64,
    withholder: u64,
    /// Races at one height an honest block settled, and how many of those it
    /// settled on the withholder's block.
    shallow_races: u64,
    shallow_to_withholder: u64,
    /// The same for matches two or more blocks deep.
    deep_races: u64,
    deep_to_withholder: u64,
}

impl Outcome {
    fn revenue(&self) -> f64 {
        self.withholder as f64 / self.chain as f64
    }

    fn gamma(&self) -> f64 {
        if self.shallow_races == 0 {
            return 0.0;
        }
        self.shallow_to_withholder as f64 / self.shallow_races as f64
    }

    fn deep_gamma(&self) -> Option<f64> {
        (self.deep_races > 0).then(|| self.deep_to_withholder as f64 / self.deep_races as f64)
    }
}

/// Eyal and Sirer's relative revenue for SM1.
fn eyal_sirer(alpha: f64, gamma: f64) -> f64 {
    let beta = 1.0 - alpha;
    let gained = alpha * beta * beta * (4.0 * alpha + gamma * (1.0 - 2.0 * alpha)) - alpha.powi(3);
    let normal = 1.0 - alpha * (1.0 + (2.0 - alpha) * alpha);
    gained / normal
}

fn exponential(rng: &mut Rng, mean: f64) -> f64 {
    let unit = (rng.below(1 << 53) as f64 + 0.5) / (1u64 << 53) as f64;
    -mean * unit.ln()
}

fn micros(seconds: f64) -> u64 {
    (seconds * 1e6) as u64
}

/// A real store, and the blocks that reached it before their parent did.
struct Node {
    chain: ChainStore,
    waiting: HashMap<Hash32, Vec<Block>>,
}

impl Node {
    fn new(params: ConsensusParams, genesis: &Block) -> Self {
        let mut chain = ChainStore::new(params);
        chain.add_block(genesis.clone(), 0).unwrap();
        Self {
            chain,
            waiting: HashMap::new(),
        }
    }

    /// Takes a block, and whatever was waiting on it; says whether the tip
    /// moved.
    fn take(&mut self, block: Block, now: u64) -> bool {
        let before = self.chain.tip();
        let mut queue = vec![block];
        while let Some(block) = queue.pop() {
            let id = block.id();
            let parent = block.header.previous;
            match self.chain.add_block(block.clone(), now) {
                Ok(_) => {
                    if let Some(children) = self.waiting.remove(&id) {
                        queue.extend(children);
                    }
                }
                Err(ChainError::UnknownParent(_)) => {
                    self.waiting.entry(parent).or_default().push(block);
                }
                Err(error) => panic!("an honest store refused a valid block: {error}"),
            }
        }
        self.chain.tip() != before
    }
}

/// The withholding miner: its own branch, and the public chain as it hears it.
struct Withholder {
    strategy: Strategy,
    /// The public chain as it reaches the withholder, with every block it
    /// released added the moment it released it.
    public: Node,
    /// The ledger at the head of its own branch, which is what it mines on.
    state: LedgerState,
    /// Its own branch, by height.
    ids: Vec<Hash32>,
    /// Found and not yet released, lowest first.
    withheld: Vec<Block>,
}

impl Withholder {
    /// The highest height at which its own branch and the public one agree.
    fn fork(&self) -> u64 {
        let top = self.public.chain.height().unwrap();
        let mut height = top.min(self.ids.len() as u64 - 1);
        while self.public.chain.id_at(height) != Some(self.ids[height as usize]) {
            height -= 1;
        }
        height
    }

    /// The fork, and how far each branch reaches above it.
    fn positions(&self) -> (u64, u64, u64) {
        let fork = self.fork();
        let mine = self.ids.len() as u64 - 1 - fork;
        let theirs = self.public.chain.height().unwrap() - fork;
        (fork, mine, theirs)
    }

    fn own_work(&self) -> u128 {
        self.state.total_work()
    }

    /// Gives up its own branch for the public one.
    fn adopt(&mut self) {
        let fork = self.fork();
        self.ids.truncate(fork as usize + 1);
        let top = self.public.chain.height().unwrap();
        for height in fork + 1..=top {
            self.ids.push(self.public.chain.id_at(height).unwrap());
        }
        self.state = self.public.chain.state().clone();
        self.withheld.clear();
    }
}

#[derive(Debug)]
enum Event {
    Find { miner: usize, round: u64 },
    Deliver { to: usize, block: Box<Block> },
}

#[derive(Debug)]
struct Scheduled {
    at: u64,
    seq: u64,
    event: Event,
}

impl PartialEq for Scheduled {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.seq) == (other.at, other.seq)
    }
}

impl Eq for Scheduled {}

impl PartialOrd for Scheduled {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scheduled {
    // Reversed, so the heap hands out the earliest first.
    fn cmp(&self, other: &Self) -> Ordering {
        (other.at, other.seq).cmp(&(self.at, self.seq))
    }
}

/// An open race: the height that settles it, and the two blocks below.
#[derive(Clone, Copy, Debug)]
struct Race {
    withholder: Hash32,
    honest: Hash32,
    deep: bool,
}

struct Sim {
    params: ConsensusParams,
    run: Run,
    rng: Rng,
    now: u64,
    seq: u64,
    queue: BinaryHeap<Scheduled>,
    honest: Vec<Node>,
    withholder: Withholder,
    /// Miner `HONEST_NODES` is the withholder.
    shares: Vec<f64>,
    keys: Vec<PublicKey>,
    rounds: Vec<u64>,
    /// Difficulty units the whole network hashes through a second.
    hashrate: f64,
    races: HashMap<u64, Race>,
    /// Every block the withholder found, released or not.
    found_by_withholder: HashSet<Hash32>,
    /// Every block's parent. A store keeps identifiers only inside its
    /// reorganisation window, and the tally walks the whole branch.
    parents: HashMap<Hash32, Hash32>,
    outcome: Outcome,
}

impl Sim {
    fn new(run: Run) -> Self {
        let params = rules_at(run.opening);
        let genesis = block_on(&LedgerState::new(), &params, key(100), 0);
        let mut state = LedgerState::new();
        connect_block(&mut state, &genesis, &params, 0).unwrap();
        let honest_share = (1.0 - run.share) / HONEST_NODES as f64;
        let mut shares = vec![honest_share; HONEST_NODES];
        shares.push(run.share);
        let keys = (0..=HONEST_NODES).map(|at| key(at as u8 + 1)).collect();
        let mut sim = Self {
            params,
            run,
            rng: Rng::new(run.seed),
            now: 0,
            seq: 0,
            queue: BinaryHeap::new(),
            honest: (0..HONEST_NODES)
                .map(|_| Node::new(params, &genesis))
                .collect(),
            withholder: Withholder {
                strategy: run.strategy,
                public: Node::new(params, &genesis),
                state,
                ids: vec![genesis.id()],
                withheld: Vec::new(),
            },
            shares,
            keys,
            rounds: vec![0; HONEST_NODES + 1],
            hashrate: params.genesis_difficulty as f64 / params.target_block_time as f64,
            races: HashMap::new(),
            found_by_withholder: HashSet::new(),
            parents: HashMap::new(),
            outcome: Outcome::default(),
        };
        for miner in 0..=HONEST_NODES {
            sim.restart(miner);
        }
        sim
    }

    fn seconds(&self) -> u64 {
        self.now / 1_000_000
    }

    fn schedule(&mut self, after: f64, event: Event) {
        self.seq += 1;
        self.queue.push(Scheduled {
            at: self.now + micros(after),
            seq: self.seq,
            event,
        });
    }

    /// Starts a miner's clock again on whatever it now mines on. Mining is
    /// memoryless, so throwing away the old draw changes nothing but the
    /// rate.
    fn restart(&mut self, miner: usize) {
        self.rounds[miner] += 1;
        let state = if miner == HONEST_NODES {
            &self.withholder.state
        } else {
            self.honest[miner].chain.state()
        };
        let difficulty = expected_difficulty(state, &self.params) as f64;
        let mean = difficulty / (self.shares[miner] * self.hashrate);
        let after = exponential(&mut self.rng, mean);
        let round = self.rounds[miner];
        self.schedule(after, Event::Find { miner, round });
    }

    fn run(mut self) -> Outcome {
        while self.honest[0].chain.height().unwrap() < self.run.blocks {
            let next = self.queue.pop().expect("miners never stop");
            self.now = next.at;
            match next.event {
                Event::Find { miner, round } if round == self.rounds[miner] => self.find(miner),
                Event::Find { .. } => {}
                Event::Deliver { to, block } => self.deliver(to, *block),
            }
        }
        self.tally()
    }

    fn find(&mut self, miner: usize) {
        let clock = self.seconds();
        if miner == HONEST_NODES {
            self.withholder_finds(clock);
            return;
        }
        let state = self.honest[miner].chain.state();
        let block = block_on(state, &self.params, self.keys[miner], stamp(state, clock));
        self.parents.insert(block.id(), block.header.previous);
        let height = block.header.height;
        if let Some(race) = self.races.remove(&height) {
            let (races, won) = if race.deep {
                (
                    &mut self.outcome.deep_races,
                    &mut self.outcome.deep_to_withholder,
                )
            } else {
                (
                    &mut self.outcome.shallow_races,
                    &mut self.outcome.shallow_to_withholder,
                )
            };
            if block.header.previous == race.withholder {
                *races += 1;
                *won += 1;
            } else if block.header.previous == race.honest {
                *races += 1;
            }
        }
        self.honest[miner].take(block.clone(), clock + 1);
        self.restart(miner);
        for other in 0..HONEST_NODES {
            if other != miner {
                let delay = exponential(&mut self.rng, self.run.network.between_honest);
                self.schedule(
                    delay,
                    Event::Deliver {
                        to: other,
                        block: Box::new(block.clone()),
                    },
                );
            }
        }
        let delay = exponential(&mut self.rng, self.run.network.to_withholder);
        self.schedule(
            delay,
            Event::Deliver {
                to: HONEST_NODES,
                block: Box::new(block),
            },
        );
    }

    fn deliver(&mut self, to: usize, block: Block) {
        let clock = self.seconds() + 1;
        if to == HONEST_NODES {
            self.withholder.public.take(block, clock);
            self.public_moved();
            return;
        }
        if self.honest[to].take(block, clock) {
            self.restart(to);
        }
    }

    fn withholder_finds(&mut self, clock: u64) {
        let (_, mine, theirs) = self.withholder.positions();
        let racing = self.withholder.withheld.is_empty() && mine == theirs && mine > 0;
        let w = &mut self.withholder;
        let block = block_on(
            &w.state,
            &self.params,
            self.keys[HONEST_NODES],
            stamp(&w.state, clock),
        );
        connect_block(&mut w.state, &block, &self.params, clock + 1).unwrap();
        w.ids.push(block.id());
        self.found_by_withholder.insert(block.id());
        self.parents.insert(block.id(), block.header.previous);
        let height = block.header.height;
        w.withheld.push(block);
        self.races.remove(&height);
        self.restart(HONEST_NODES);
        match self.withholder.strategy {
            Strategy::Honest => self.release(u64::MAX),
            // In a race, a block of its own settles it: both strategies take
            // the win at once.
            Strategy::Selfish | Strategy::LeadStubborn => {
                if racing {
                    self.release(u64::MAX);
                }
            }
        }
    }

    /// Something reached the withholder from the public chain.
    fn public_moved(&mut self) {
        let w = &self.withholder;
        if w.public.chain.total_work() > w.own_work() {
            self.withholder.adopt();
            self.restart(HONEST_NODES);
            return;
        }
        if w.strategy == Strategy::Honest || w.withheld.is_empty() {
            return;
        }
        let (fork, mine, theirs) = w.positions();
        if mine == theirs {
            // Its lead was one and is gone: release and race.
            self.release(u64::MAX);
        } else if mine == theirs + 1 && w.strategy == Strategy::Selfish {
            // Its lead was two: release everything and override.
            self.release(u64::MAX);
        } else {
            // Match the public branch and keep the rest.
            self.release(fork + theirs);
        }
    }

    /// Publishes what it withheld up to `height`, and opens a race where the
    /// release ends level with the public tip.
    fn release(&mut self, height: u64) {
        let w = &mut self.withholder;
        let cut = w
            .withheld
            .iter()
            .position(|block| block.header.height > height)
            .unwrap_or(w.withheld.len());
        if cut == 0 {
            return;
        }
        let released: Vec<Block> = w.withheld.drain(..cut).collect();
        let top = released.last().unwrap().header.height;
        let fork = w.fork();
        if w.public.chain.height() == Some(top) && w.public.chain.tip() != Some(w.ids[top as usize])
        {
            self.races.insert(
                top + 1,
                Race {
                    withholder: w.ids[top as usize],
                    honest: w.public.chain.tip().unwrap(),
                    deep: top > fork + 1,
                },
            );
        }
        let clock = self.now / 1_000_000 + 1;
        for block in &released {
            w.public.take(block.clone(), clock);
        }
        for block in released {
            for to in 0..HONEST_NODES {
                let delay = exponential(&mut self.rng, self.run.network.from_withholder);
                self.schedule(
                    delay,
                    Event::Deliver {
                        to,
                        block: Box::new(block.clone()),
                    },
                );
            }
        }
    }

    fn tally(mut self) -> Outcome {
        let chain = &self.honest[0].chain;
        self.outcome.chain = chain.height().unwrap();
        let mut id = chain.tip().unwrap();
        while let Some(parent) = self.parents.get(&id) {
            if self.found_by_withholder.contains(&id) {
                self.outcome.withholder += 1;
            }
            id = *parent;
        }
        self.outcome
    }
}

fn simulate(run: Run) -> Outcome {
    Sim::new(run).run()
}

/// **A withholding miner earns what the papers say, and the tie rule does no
/// more than the threat model claims.**
///
/// Short runs, so this goes with the suite: the long ones that fill the
/// tables at the top are `ignore`d. Each figure here is held with a wide
/// margin, since six hundred blocks leave a few points of noise, and every run
/// is drawn from a fixed seed, so nothing in it depends on the machine.
///
/// The control publishes at once and earns its share. SM1 with nearly half of
/// the work earns well over it, and with a tenth earns under it: the curve the
/// papers draw, crossing where they say. And the deep matches are settled by
/// arrival on the real retarget as they are when every block weighs the same,
/// so a withholder that hears late and speaks late loses most of them. Before
/// the band they were settled by work, and went its way nine times in ten.
#[test]
fn a_withholding_miner_earns_what_the_papers_say() {
    let run = |share, strategy, opening| {
        simulate(Run {
            share,
            strategy,
            network: SLOW,
            blocks: 600,
            seed: 7,
            opening,
        })
    };

    let control = run(0.3, Strategy::Honest, TIMED);
    assert!(
        (control.revenue() - 0.3).abs() < 0.08,
        "a miner publishing at once earned {:.3} with 0.3 of the work",
        control.revenue()
    );

    let large = run(0.45, Strategy::Selfish, TIMED);
    assert!(
        large.revenue() > 0.5,
        "SM1 with 0.45 of the work earned {:.3}; the papers give about {:.3} at \
         the gamma measured, {:.2}",
        large.revenue(),
        eyal_sirer(0.45, large.gamma()),
        large.gamma()
    );
    assert!(
        large.gamma() < 0.35,
        "a withholder that hears late and speaks late wins few races at one \
         height: gamma {:.2}",
        large.gamma()
    );

    let small = run(0.1, Strategy::Selfish, TIMED);
    assert!(
        small.revenue() < 0.1,
        "SM1 with a tenth of the work earned {:.3}, more than its share",
        small.revenue()
    );

    let timed = run(0.4, Strategy::LeadStubborn, TIMED);
    let flat = run(0.4, Strategy::LeadStubborn, FLAT);
    let timed_deep = timed.deep_gamma().expect("deep matches happened");
    let flat_deep = flat.deep_gamma().expect("deep matches happened");
    assert!(
        timed_deep < 0.5,
        "on the real retarget a match two or more blocks deep is a tie, the \
         blocks dated earlier being heavier by less than half a block, so \
         arrival settles it: {timed_deep:.2} of {} went the withholder's way",
        timed.deep_races
    );
    assert!(
        flat_deep < 0.5,
        "with every block weighing one a deep match is a tie and arrival \
         settles it: {flat_deep:.2} of {} went the withholder's way",
        flat.deep_races
    );
}

/// The third table of the header, slow, even and fast: the share at which
/// each lane's revenue crosses the share, as `the_tables_in_the_header`
/// computes it.
const CROSSINGS: [(&str, [f64; 3]); 4] = [
    ("SM1", [0.333, 0.294, 0.186]),
    ("lead stubborn, real", [0.396, 0.323, 0.213]),
    ("lead stubborn, flat", [0.394, 0.318, 0.196]),
    ("best of the two, real", [0.333, 0.294, 0.186]),
];

/// The same table's last line, the study's crossings for the fork choice
/// before the band, which this file no longer measures.
const BEFORE_THE_BAND: [f64; 3] = [0.301, 0.266, 0.177];

/// Deep gamma of lead stubbornness before the band, the least and the most
/// over the three placements, as the header states it.
const DEEP_GAMMA_BEFORE_THE_BAND: (f64, f64) = (0.87, 1.00);

/// How far a crossing `the_tables_in_the_header` computes may stand from the
/// one stated. The cells are seeded and come back the same on a rerun on the
/// same platform, so anything further is a change in what the rules or the
/// simulation give; and the threat model quotes these to the hundredth, so a
/// move of more than half of one can change a published figure. Then the
/// tables, this constant and the threat model are measured again together.
const CROSSING_TOLERANCE: f64 = 0.005;

/// The share at which revenue crosses the miner's own share, between the
/// two grid points either side of the last crossing from under to over.
fn crossing(points: &[(f64, f64)]) -> Option<f64> {
    points
        .windows(2)
        .filter_map(|pair| {
            let ((low, under), (high, over)) = (pair[0], pair[1]);
            (under <= 0.0 && over > 0.0).then(|| low + (high - low) * -under / (over - under))
        })
        .next_back()
}

/// The tables at the top of this file.
///
/// Every cell from `SEEDS` seeds, on a pool of one thread a core, so the
/// figures come back the same on a rerun on the same platform. The control
/// is run from the first seed alone: what it shows is that nothing in the
/// simulation pays a miner that withholds nothing.
#[test]
#[ignore = "about an hour and a half on ten cores; fills the tables in the header"]
fn the_tables_in_the_header() {
    const BLOCKS: u64 = 8_000;
    const SEEDS: u64 = 4;
    let shares = [
        0.10, 0.15, 0.20, 0.25, 0.28, 0.30, 0.33, 0.35, 0.38, 0.40, 0.45,
    ];
    let networks = [SLOW, EVEN, FAST];
    let lanes = [
        (Strategy::Selfish, TIMED),
        (Strategy::LeadStubborn, TIMED),
        (Strategy::LeadStubborn, FLAT),
        (Strategy::Honest, TIMED),
    ];
    let mut cells: Vec<Run> = Vec::new();
    for share in shares.iter().rev() {
        for network in networks {
            for (strategy, opening) in lanes {
                let seeds = if strategy == Strategy::Honest {
                    1
                } else {
                    SEEDS
                };
                for seed in 0..seeds {
                    cells.push(Run {
                        share: *share,
                        strategy,
                        network,
                        blocks: BLOCKS,
                        seed: 20 + seed,
                        opening,
                    });
                }
            }
        }
    }
    let next = AtomicUsize::new(0);
    let done: Mutex<Vec<Option<Outcome>>> = Mutex::new(vec![None; cells.len()]);
    let workers = std::thread::available_parallelism().map_or(4, usize::from);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let at = next.fetch_add(1, AtomicOrdering::Relaxed);
                let Some(run) = cells.get(at) else {
                    break;
                };
                let outcome = simulate(*run);
                done.lock().unwrap()[at] = Some(outcome);
            });
        }
    });
    let done: Vec<Outcome> = done.into_inner().unwrap().into_iter().flatten().collect();
    assert_eq!(done.len(), cells.len(), "every cell ran");

    // The seeds of one cell together: revenue averaged, races pooled.
    let find = |share: f64, strategy, network: &str, opening| {
        let runs: Vec<&Outcome> = cells
            .iter()
            .zip(&done)
            .filter(|(run, _)| {
                (run.share - share).abs() < 1e-9
                    && run.strategy == strategy
                    && run.network.name == network
                    && run.opening == opening
            })
            .map(|(_, outcome)| outcome)
            .collect();
        let revenue = runs.iter().map(|outcome| outcome.revenue()).sum::<f64>() / runs.len() as f64;
        let mut pooled = Outcome::default();
        for outcome in &runs {
            pooled.shallow_races += outcome.shallow_races;
            pooled.shallow_to_withholder += outcome.shallow_to_withholder;
            pooled.deep_races += outcome.deep_races;
            pooled.deep_to_withholder += outcome.deep_to_withholder;
        }
        (revenue, pooled)
    };

    println!("\nSM1: alpha, then per network gamma, share, Eyal-Sirer at that gamma");
    for share in shares {
        let mut line = format!("{share:<5}");
        for network in &networks {
            let (revenue, outcome) = find(share, Strategy::Selfish, network.name, TIMED);
            write!(
                line,
                "   {:.2}  {:.3}  {:.3}",
                outcome.gamma(),
                revenue,
                eyal_sirer(share, outcome.gamma())
            )
            .unwrap();
        }
        println!("{line}");
    }
    println!("\nlead stubborn: alpha, then per network share on the real retarget, deep gamma,");
    println!("share with every block weighing one, deep gamma there");
    for share in shares {
        let mut line = format!("{share:<5}");
        for network in &networks {
            let (timed, timed_races) = find(share, Strategy::LeadStubborn, network.name, TIMED);
            let (flat, flat_races) = find(share, Strategy::LeadStubborn, network.name, FLAT);
            write!(
                line,
                "   {:.3} {:.2}  {:.3} {:.2}",
                timed,
                timed_races.deep_gamma().unwrap_or(f64::NAN),
                flat,
                flat_races.deep_gamma().unwrap_or(f64::NAN)
            )
            .unwrap();
        }
        println!("{line}");
    }
    println!("\nhonest control: alpha, then share per network");
    for share in shares {
        let mut line = format!("{share:<5}");
        for network in &networks {
            let (revenue, _) = find(share, Strategy::Honest, network.name, TIMED);
            write!(line, "   {revenue:.3}").unwrap();
        }
        println!("{line}");
    }
    println!("\nthe share where revenue crosses the share, per network");
    let threshold = |strategy, network: &str, opening| {
        let points: Vec<(f64, f64)> = shares
            .iter()
            .map(|share| (*share, find(*share, strategy, network, opening).0 - share))
            .collect();
        crossing(&points).unwrap_or(f64::NAN)
    };
    let mut computed: Vec<(&str, [f64; 3])> = Vec::new();
    for (name, strategy, opening) in [
        ("SM1", Strategy::Selfish, TIMED),
        ("lead stubborn, real", Strategy::LeadStubborn, TIMED),
        ("lead stubborn, flat", Strategy::LeadStubborn, FLAT),
    ] {
        computed.push((
            name,
            networks.map(|network| threshold(strategy, network.name, opening)),
        ));
    }
    computed.push((
        "best of the two, real",
        networks.map(|network| {
            threshold(Strategy::Selfish, network.name, TIMED).min(threshold(
                Strategy::LeadStubborn,
                network.name,
                TIMED,
            ))
        }),
    ));
    for (name, crossings) in &computed {
        let mut line = format!("{name:<22}");
        for crossing in crossings {
            write!(line, "   {crossing:.3}").unwrap();
        }
        println!("{line}");
    }

    // Asserted after printing, so a run that fails still shows the tables to
    // write into the header.
    for ((name, crossings), (stated_name, stated)) in computed.iter().zip(CROSSINGS) {
        assert_eq!(*name, stated_name);
        for ((network, crossing), stated) in networks.iter().zip(crossings).zip(stated) {
            assert!(
                (crossing - stated).abs() <= CROSSING_TOLERANCE,
                "{name}, {}: the crossing is {crossing:.3} where the header states {stated:.3}; \
                 the header, `CROSSINGS` and the threat model are owed a new measurement",
                network.name
            );
        }
    }
}

/// Text with every run of whitespace made one space and the comment markers
/// of a Rust source left out, so that a phrase is found however it was
/// wrapped or aligned.
fn flat(text: &str) -> String {
    text.split_whitespace()
        .filter(|word| !matches!(*word, "///" | "//!" | "//"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// **The threat model quotes the tables in the header, and the header is the
/// table `the_tables_in_the_header` is held to.**
///
/// The selfish-mining row publishes six thresholds and a nine in ten from this
/// file. The run that produces them takes an hour and a half and is ignored,
/// so nothing that runs on a change compared the row, the header and the
/// constants with each other; the floor run's figures were in that position
/// and stood in four documents a factor of four low. Each is read here from
/// `CROSSINGS`, `BEFORE_THE_BAND` and `DEEP_GAMMA_BEFORE_THE_BAND`, so editing
/// any of the three apart from the others fails.
#[test]
fn the_threat_model_quotes_the_tables_in_the_header() {
    let header = flat(include_str!("withheld_blocks.rs"));
    for (name, [slow, even, fast]) in CROSSINGS {
        let row = format!("{name} {slow:.3} {even:.3} {fast:.3}");
        assert!(
            header.contains(&row),
            "the header's table does not hold `{row}`"
        );
    }
    let [slow, even, fast] = BEFORE_THE_BAND;
    let row = format!("best of the two, before {slow:.3} {even:.3} {fast:.3}");
    assert!(
        header.contains(&row),
        "the header's table does not hold `{row}`"
    );
    let (least, most) = DEEP_GAMMA_BEFORE_THE_BAND;
    let range = format!("deep gamma {least:.2} to {most:.2} in every placement");
    assert!(header.contains(&range), "the header does not say `{range}`");

    let threat = flat(include_str!("../../../docs/cairn-threat-model.md"));
    let quoted = |[slow, even, fast]: [f64; 3]| format!("{slow:.2}, {even:.2} and {fast:.2}");
    let best = CROSSINGS
        .iter()
        .find(|(name, _)| *name == "best of the two, real")
        .unwrap()
        .1;
    for stated in [
        format!(
            "profited from {} of the work by placement",
            quoted(BEFORE_THE_BAND)
        ),
        format!(
            "withholding pays from {}, the papers' threshold",
            quoted(best)
        ),
        "won nine in ten of them".to_owned(),
    ] {
        assert!(
            threat.contains(&stated),
            "the threat model does not say \"{stated}\""
        );
    }
    assert_eq!(
        (least * 10.0).round(),
        9.0,
        "nine in ten no longer rounds the least deep gamma the header states, {least:.2}"
    );
}

/// **The manifest names every test that uses `cairn-fuzz`, this one
/// included.**
///
/// The comment beside the dev-dependency named two of the four files that
/// use it, and gave a reason, campaigns for the nightly run, that this file
/// does not have: it takes only the seeded generator. Somebody pruning the
/// dependency on the comment's word would break two targets, one of them in
/// the nightly list.
#[test]
fn every_test_here_that_uses_the_fuzz_crate_is_named_in_the_manifest() {
    let manifest = include_str!("../Cargo.toml");
    let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut using = Vec::new();
    for entry in std::fs::read_dir(&tests).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "rs")
            && std::fs::read_to_string(&path)
                .unwrap()
                .contains("use cairn_fuzz")
        {
            using.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    assert!(using.contains(&"withheld_blocks.rs".to_owned()));
    for file in using {
        assert!(
            manifest.contains(&format!("`tests/{file}`")),
            "tests/{file} uses cairn-fuzz and the manifest does not say so"
        );
    }
}

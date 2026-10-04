//! Audit: the difficulty retarget and the timestamp rules.
//!
//! Every test states a fact about the rules as they stand, so that a claim in
//! an audit report has something that was run behind it.
//!
//! This file was written against a weighted moving average, in which a miner
//! writing its own timestamps could keep part of what it claimed: a gap read
//! unsigned was worth up to six targets forwards and one second backwards, so
//! a saw of timestamps took the difficulty to the floor from about a sixth of
//! the hash rate, a private branch reached the floor in under eight hundred
//! blocks advancing a second a block, and a minority dating its blocks at a
//! drift of two hours slowed testnet by half. Each was repaired in turn, and
//! the testnet-8 wave then replaced the rule itself with ASERT, which reads
//! the parent's timestamp against a schedule fixed at the network's first
//! block and nothing else. What the old tables compared were variants of a
//! rule no node runs any more, so they are gone; what each one protected is
//! asked here of the rule as it stands, against the same attacks.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::too_many_lines
)]

use std::fmt::Write as _;

use cairn_crypto::SecretKey;
use cairn_ledger::block::HeaderSummary;
use cairn_ledger::note::Note;
use cairn_ledger::pow::{
    median_time_past, next_difficulty, Origin, HALF_LIFE_IN_BLOCKS, MEDIAN_TIME_WINDOW,
    MIN_DIFFICULTY, RECENT_HEADERS,
};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, expected_difficulty, BlockError, ConsensusParams,
};
use cairn_ledger::LedgerState;

/// Every live network in this repository targets a minute, except devnet.
const TARGET: u64 = 60;

/// The retarget's half life at that target, in seconds.
const HALF_LIFE: u64 = HALF_LIFE_IN_BLOCKS * TARGET;

/// The most one retarget may move the difficulty, restated here and checked
/// against the code below.
const RETARGET_FACTOR: u64 = 4;

/// A gap after which the schedule asks a quarter of the difficulty, the most
/// the bound lets one block fall: two half lives past the target.
const FALL: u64 = 2 * HALF_LIFE + TARGET + 1;

/// The deepest reorganisation a node accepts, and the depth a handed over
/// ledger is buried under. Restated here because this file measures what a
/// branch that long costs in chain time.
const REORG_WINDOW: u64 = 1_024;

/// The cheapest even spacing that holds a branch of [`REORG_WINDOW`] blocks
/// at the difficulty floor, from the edge of it.
///
/// Derived rather than chosen, and pinned on both sides in
/// [`the_floor_holds_a_reorganisation_window_from_fifty_seven_seconds_and_not_from_fifty_six`].
/// At the floor's edge a chain is asked for two once it stands a half life
/// ahead of where it stood, so a thousand and twenty three gaps may fall short
/// of the target by less than an hour between them: three seconds each, and
/// not four.
const CHEAPEST_AT_THE_FLOOR: u64 = 57;

/// A block draw that does not spread the attacker's blocks evenly.
///
/// Mining is a race nobody schedules, so a miner holding a share of the hash
/// rate holds runs of consecutive blocks with the frequency that share implies.
/// Whether those runs happen decides how much a timestamp rule leaks, so the
/// draw has to be a draw. Seeded, because a test that is different every run
/// is not a test.
struct Draw(u64);

impl Draw {
    fn new() -> Self {
        Self(0x2545_F491_4F6C_DD1D)
    }

    fn next(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A window kept the way `LedgerState` keeps it, and the schedule it is
/// judged against.
struct Window {
    origin: Origin,
    recent: Vec<HeaderSummary>,
}

impl Window {
    fn new(origin: Origin) -> Self {
        Self {
            origin,
            recent: Vec::new(),
        }
    }

    fn push(&mut self, height: u64, timestamp: u64, difficulty: u64) {
        self.recent.push(HeaderSummary {
            height,
            timestamp,
            difficulty,
        });
        if self.recent.len() > RECENT_HEADERS {
            self.recent.remove(0);
        }
    }

    fn median(&self) -> Option<u64> {
        median_time_past(&self.recent)
    }

    fn next(&self, target: u64) -> u64 {
        next_difficulty(&self.last(), self.origin, target)
    }

    fn last(&self) -> HeaderSummary {
        *self.recent.last().unwrap()
    }
}

/// Fills a window with a chain that ran exactly on schedule from its first
/// block, which carried `difficulty`.
fn settled(difficulty: u64, target: u64, blocks: u64) -> (Window, u64, u64) {
    let start = 1_000_000u64;
    let mut window = Window::new(Origin {
        timestamp: start,
        difficulty,
    });
    let mut timestamp = start;
    for height in 0..blocks {
        window.push(height, timestamp, difficulty);
        timestamp += target;
    }
    (window, blocks, timestamp)
}

// ---------------------------------------------------------------------------
// 1. What the retarget reads, and the bound it applies.
// ---------------------------------------------------------------------------

/// A timestamp thrown forward lowers the next difficulty, and the block dated
/// back where it belongs takes all of it back.
///
/// The moving average this replaced read a gap that ran backwards as one
/// second, so a spike forward was worth up to its ceiling and the block that
/// undid it almost nothing, which was the whole of the exploit the rest of
/// the old file measured. The schedule has no memory to keep a discount in:
/// what a parent asks is decided by where it stands, and a parent back on
/// schedule asks what the schedule asks.
#[test]
fn a_backwards_timestamp_is_worth_the_time_it_gives_back() {
    let (mut window, height, timestamp) = settled(1_000_000, TARGET, 91);

    window.push(height, timestamp + 10_000, 1_000_000);
    let after_the_spike = window.next(TARGET);
    window.push(height + 1, timestamp + TARGET, 1_000_000);
    let after_the_return = window.next(TARGET);

    assert!(
        after_the_spike < 1_000_000,
        "the spike lowered the difficulty"
    );
    assert_eq!(
        after_the_return, 1_000_000,
        "the return gave back exactly what the spike took"
    );
}

/// The bound holds in both directions, and past two half lives a longer gap
/// buys nothing.
#[test]
fn the_bound_holds_in_both_directions() {
    let (window, _, _) = settled(1_000_000, TARGET, 91);
    let origin = window.origin;
    let at = |offset: i64| {
        let mut parent = window.last();
        parent.timestamp = parent.timestamp.saturating_add_signed(offset);
        next_difficulty(&parent, origin, TARGET)
    };
    let two = i64::try_from(2 * HALF_LIFE).unwrap();
    assert_eq!(
        at(two),
        1_000_000 / RETARGET_FACTOR,
        "two half lives behind is a quarter, exactly"
    );
    assert!(
        at(two - 1) > 1_000_000 / RETARGET_FACTOR,
        "and a second less is more"
    );
    assert_eq!(
        at(two * 1_000),
        1_000_000 / RETARGET_FACTOR,
        "past two half lives a longer gap buys nothing"
    );
    assert_eq!(
        at(-two),
        1_000_000 * RETARGET_FACTOR,
        "two half lives ahead is four times, exactly"
    );
    assert_eq!(
        at(-1_000_000),
        1_000_000 * RETARGET_FACTOR,
        "and a parent dated before the network opened is still four times"
    );
}

/// A timestamp thrown anywhere below the parent is forgotten once the parent
/// is honest.
///
/// Under the first version of the moving average the same block was worth a
/// discount that grew the nearer the tip it sat. Here where it sat changes
/// nothing at all, because only the parent's timestamp is read.
#[test]
fn a_lie_anywhere_below_the_parent_is_forgotten() {
    let (honest, _, _) = settled(1_000, TARGET, 91);
    let answer = honest.next(TARGET);
    for at in [10u64, 45, 80, 89] {
        let (mut lied, _, _) = settled(1_000, TARGET, 91);
        let index = lied
            .recent
            .iter()
            .position(|summary| summary.height == at)
            .unwrap();
        lied.recent[index].timestamp -= 2 * HALF_LIFE;
        assert_eq!(
            lied.next(TARGET),
            answer,
            "a lie at {at} changed the answer"
        );
    }
}

/// Nothing in the retarget divides by zero, wraps, or panics at the extremes.
#[test]
fn the_arithmetic_survives_every_degenerate_parent() {
    let parent = |height: u64, timestamp: u64, difficulty: u64| HeaderSummary {
        height,
        timestamp,
        difficulty,
    };
    let origin = |timestamp: u64, difficulty: u64| Origin {
        timestamp,
        difficulty,
    };
    // No block time: no schedule, the parent stands.
    assert_eq!(next_difficulty(&parent(5, 5, 7), origin(0, 9), 0), 7);
    assert_eq!(
        next_difficulty(&parent(5, 5, 0), origin(0, 9), 0),
        MIN_DIFFICULTY
    );
    // A parent stating no difficulty is read as the floor.
    assert_eq!(
        next_difficulty(&parent(0, 0, 0), origin(0, 0), TARGET),
        MIN_DIFFICULTY
    );
    // Every field at its ceiling.
    assert_eq!(
        next_difficulty(
            &parent(u64::MAX, u64::MAX, u64::MAX),
            origin(u64::MAX, u64::MAX),
            u64::MAX
        ),
        u64::MAX
    );
    // The furthest ahead a parent can stand, and the furthest behind.
    assert_eq!(
        next_difficulty(&parent(u64::MAX, 0, 1_000), origin(0, 1), u64::MAX),
        4_000
    );
    assert_eq!(
        next_difficulty(&parent(0, u64::MAX, 1_000), origin(0, u64::MAX), TARGET),
        250
    );
    // A height whose schedule is past the end of a `u64` second.
    assert_eq!(
        next_difficulty(
            &parent(u64::MAX / 2, u64::MAX, 1 << 40),
            origin(0, 1),
            TARGET
        ),
        1 << 42
    );
}

// ---------------------------------------------------------------------------
// 2. The saw, and the strongest timestamp strategy found.
// ---------------------------------------------------------------------------

/// What one run of the attack came to.
struct Run {
    /// The difficulty at the end, as a fraction of where the chain started.
    ratio: f64,
    /// Real seconds a block took over the second half of the run.
    seconds_per_block: f64,
    /// Blocks mined before the difficulty had lost nine tenths of its value,
    /// or `None` if it never did.
    to_a_tenth: Option<usize>,
}

/// How the miner that lies writes its timestamps.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lie {
    /// Every block it finds sits at the drift ceiling ahead of the wall
    /// clock, and its blocks are spread evenly through the chain. This is
    /// the saw the first audit measured, at the largest lie a reader takes.
    Saw,
    /// Every block it finds sits as far past the tip it extends as the drift
    /// allows, so a run of blocks it happens to win in a row drags the
    /// claimed timeline forward as fast as the rules let it, and its blocks
    /// are drawn rather than spread.
    Greedy,
}

/// A miner holding `share` of the hash rate dates its own blocks forward. Its
/// blocks are valid: they clear the median and sit no further ahead of the
/// wall clock than the rules allow. Every other block is dated the way
/// `cairn-node`'s miner dates one, which is the wall clock raised to the
/// median plus one.
///
/// The whole feedback loop is here: the difficulty decides the real solve
/// time, the real solve time and the lie together decide what the retarget
/// sees, and the retarget decides the next difficulty.
fn drag(lie: Lie, share: f64, blocks: usize, drift: u64) -> Run {
    let start = 1_000_000u64;
    // Total hash rate as difficulty solved per second, so at `start` a block
    // takes exactly the target.
    let rate = start as f64 / TARGET as f64;

    let (mut window, mut height, opened) = settled(start, TARGET, 91);
    let mut clock = opened as f64;
    let mut difficulty = window.next(TARGET);

    let mut draw = Draw::new();
    let mut owed = 0.0f64;
    let mut measured_from = 0.0f64;
    let mut measured_blocks = 0usize;
    let sample_from = blocks / 2;
    let mut to_a_tenth = None;

    for index in 0..blocks {
        clock += difficulty as f64 / rate;

        let attacker = if lie == Lie::Greedy {
            draw.next() < share
        } else {
            owed += share;
            let won = owed >= 1.0;
            if won {
                owed -= 1.0;
            }
            won
        };

        let earliest = window.median().map_or(0, |median| median + 1);
        let now = clock.round() as u64;
        let honest = now.max(earliest);
        let timestamp = match (attacker, lie) {
            (false, _) => honest,
            (true, Lie::Saw) => now.saturating_add(drift).max(earliest),
            (true, Lie::Greedy) => honest
                .max(window.last().timestamp.saturating_add(drift))
                .min(now.saturating_add(drift))
                .max(earliest),
        };

        if index == sample_from {
            measured_from = clock;
        }
        if index >= sample_from {
            measured_blocks += 1;
        }

        window.push(height, timestamp, difficulty);
        height += 1;
        difficulty = window.next(TARGET);

        if to_a_tenth.is_none() && difficulty as f64 <= start as f64 / 10.0 {
            to_a_tenth = Some(index + 1);
        }
    }

    Run {
        ratio: window.last().difficulty as f64 / start as f64,
        seconds_per_block: (clock - measured_from) / measured_blocks as f64,
        to_a_tenth,
    }
}

/// The shares the table is taken at.
const SHARES: [f64; 12] = [
    0.02, 0.05, 0.08, 0.10, 0.12, 0.15, 0.17, 0.20, 0.25, 0.33, 0.40, 0.45,
];

/// The saw at every share up to nearly half the hash rate.
///
/// Under the moving average as it first stood the difficulty had no
/// equilibrium past about a sixth of the hash rate: a lying block was worth
/// its ceiling to the retarget and cost the block after it one second. Here a
/// lie is worth what the parent says for one block, and the honest block after
/// it takes it back, so the chain settles where it was at every share.
#[test]
fn the_saw_does_not_pay_for_itself() {
    let drift = ConsensusParams::testnet().max_timestamp_drift;

    let honest = drag(Lie::Saw, 0.0, 3_000, drift);
    assert!(
        (0.95..=1.05).contains(&honest.ratio),
        "an honest chain drifted to {}",
        honest.ratio
    );
    assert!(
        (57.0..=63.0).contains(&honest.seconds_per_block),
        "spacing {}",
        honest.seconds_per_block
    );

    let mut out = String::from("\n  share   difficulty   block time\n");
    for share in SHARES {
        let run = drag(Lie::Saw, share, 4_000, drift);
        let _ = writeln!(
            out,
            "  {:>4.0}%   {:>10.4}   {:>8.2} s",
            share * 100.0,
            run.ratio,
            run.seconds_per_block
        );
        assert!(
            (0.85..=1.10).contains(&run.ratio),
            "share {share}: the difficulty settled at {}",
            run.ratio
        );
        assert!(
            (57.0..=63.0).contains(&run.seconds_per_block),
            "share {share}: blocks take {} s",
            run.seconds_per_block
        );
        assert!(
            run.to_a_tenth.is_none(),
            "share {share}: reached a tenth after {:?} blocks",
            run.to_a_tenth
        );
    }
    println!("{out}");
}

/// No share short of a majority takes the difficulty to a tenth, under the saw
/// or the greedy strategy, and none makes blocks come much faster than the
/// target.
///
/// The search used to stop at about a sixth of the hash rate under the first
/// moving average. It runs all the way up to a point short of a majority
/// without finding anything, and stops there because a miner that holds half
/// the blocks has no need of a timestamp trick to rewrite a chain.
#[test]
fn no_share_short_of_a_majority_takes_the_difficulty_to_the_floor() {
    let drift = ConsensusParams::testnet().max_timestamp_drift;
    let mut worst = 1.0f64;
    let mut share = 0.01f64;
    while share < 0.50 {
        for lie in [Lie::Saw, Lie::Greedy] {
            let run = drag(lie, share, 4_000, drift);
            assert!(
                run.to_a_tenth.is_none(),
                "a {share} share reached a tenth in {:?} blocks",
                run.to_a_tenth
            );
            worst = worst.min(run.seconds_per_block / TARGET as f64);
        }
        share += 0.01;
    }
    println!(
        "\n  no share below a half reaches a tenth, and the fastest any of them made\n  \
         the chain run is {:.0}% of the target block time\n",
        worst * 100.0
    );
    assert!(worst > 0.90, "blocks came {worst} of the target apart");
}

/// The lie these tables measure stays inside the drift the rules allow, and
/// the drift is a sixth of a half life on every network.
///
/// The drift was two hours on every network, which against the moving
/// average was more than its whole window on testnet and sixteen of them on
/// devnet. It is ten blocks now, and the half life is sixty, so the most a
/// timestamp the rules accept can move the next difficulty is `2^(-1/6)`.
#[test]
fn the_lie_stays_inside_the_drift_the_rules_allow() {
    for (name, params) in both_networks() {
        let half_life = HALF_LIFE_IN_BLOCKS * params.target_block_time;
        assert_eq!(
            params.max_timestamp_drift,
            10 * params.target_block_time,
            "{name}: the drift is ten of the network's blocks"
        );
        assert_eq!(
            half_life,
            6 * params.max_timestamp_drift,
            "{name}: one block's allowance is a sixth of a half life"
        );
    }
}

/// A miner that holds every block (a private branch, or a network it has
/// eclipsed) used to drive its own difficulty to the floor with timestamps
/// that advance about a second a block: five spikes in every eleven blocks,
/// the most the median rule leaves room for, took the first moving average
/// from a million to one in under eight hundred blocks.
///
/// A second a block is a chain running sixty times faster than its schedule,
/// and the schedule asks it for more at every block: a half life of claimed
/// time is an hour, and the branch gains fifty nine seconds of it a block. The
/// spikes buy each next block a discount that the low block after it takes
/// back. Every timestamp is checked against the median rule as a node would
/// apply it, so what stops the branch is the difficulty it is asked for.
#[test]
fn a_private_branch_pays_to_lie_about_its_own_solve_times() {
    let start = 1_000_000u64;
    let pattern = [
        true, false, true, false, true, false, true, false, true, false, false,
    ];
    assert_eq!(pattern.len(), MEDIAN_TIME_WINDOW);
    assert_eq!(pattern.iter().filter(|spike| **spike).count(), 5);

    let (mut window, mut height, mut low) = settled(start, TARGET, 91);
    let mut difficulty = window.next(TARGET);
    let mut refused = 0usize;
    let mut floor = false;
    let mut spent = 0u128;
    for index in 0..600 {
        let spike = pattern[index % pattern.len()];
        low += 1;
        let timestamp = if spike { low + 6 * TARGET } else { low };
        if window.median().is_some_and(|median| timestamp <= median) {
            refused += 1;
        }
        spent = spent.saturating_add(u128::from(difficulty));
        window.push(height, timestamp, difficulty);
        height += 1;
        difficulty = window.next(TARGET);
        floor |= difficulty == MIN_DIFFICULTY;
    }
    assert_eq!(refused, 0, "every block in this branch clears the median");
    assert!(!floor, "it never reaches the floor");
    println!(
        "\n  six hundred blocks a second apart ask for difficulty {difficulty} at the end,\n  \
         having spent {} blocks' work at the difficulty they started from\n",
        spent / u128::from(start)
    );
    // Six hundred blocks fifty nine seconds ahead of schedule each is nine
    // half lives and more.
    assert!(
        difficulty > start * 500,
        "six hundred blocks of the saw only reached {difficulty}"
    );
}

/// The only way to the floor: be behind the schedule, and really be behind
/// it.
///
/// With no honest miner to pull it back the difficulty still falls as far as
/// the rules allow. What it costs is time: every halving is a half life of
/// timestamps behind the schedule, whatever the spacing, and a timestamp
/// cannot outrun the wall clock by more than the drift. From 2^40 the fastest
/// walk is twenty headers, each two half lives and a target after the last,
/// and forty hours of chain time; spaced six targets apart it takes 469
/// headers and forty seven hours.
#[test]
fn the_only_way_to_the_floor_is_to_be_slow() {
    let start = 1u64 << 40;
    for (gap, headers) in [(FALL, 20usize), (6 * TARGET, 469)] {
        let (mut window, mut height, _) = settled(start, TARGET, 91);
        let opened = window.last().timestamp;
        let mut clock = opened;
        let mut difficulty = window.next(TARGET);
        let mut blocks = 0usize;
        while difficulty > MIN_DIFFICULTY && blocks < 20_000 {
            clock += gap;
            window.push(height, clock, difficulty);
            height += 1;
            difficulty = window.next(TARGET);
            blocks += 1;
        }
        assert_eq!(difficulty, MIN_DIFFICULTY);
        let spent = window.last().timestamp - opened;
        println!(
            "\n  gaps of {gap} s take the difficulty from 2^40 to the floor in {blocks} blocks\n  \
             and {spent} s of chain time, {:.1} hours that a branch cannot claim without\n  \
             the clock behind it\n",
            spent as f64 / 3_600.0
        );
        assert_eq!(blocks, headers, "at gaps of {gap} s");
        // The floor answers below two, so the walk has stood thirty nine half
        // lives behind the schedule by the parent of its last block.
        assert!(
            spent >= 39 * HALF_LIFE,
            "{spent} s is less than the half lives forty halvings need"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Determinism: the one rule that reads the node's own clock.
// ---------------------------------------------------------------------------

fn mined_at(state: &LedgerState, params: &ConsensusParams, timestamp: u64) -> cairn_ledger::Block {
    let miner = SecretKey::from_bytes(&[9u8; 32]);
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block = assemble_block(
        state,
        coinbase,
        Vec::<Transfer>::new(),
        params,
        timestamp,
        0,
    )
    .unwrap();
    cairn_ledger::validation::mine_block(block, 1 << 22).expect("a nonce exists at difficulty one")
}

/// The same block, the same chain, two nodes: one accepts it and one refuses
/// it, and the only difference between them is a second on the wall clock.
#[test]
fn one_second_of_clock_skew_decides_a_block_between_two_honest_nodes() {
    let params = ConsensusParams::testnet();
    let mut fast = LedgerState::archiving();
    let mut slow = LedgerState::archiving();

    let now = 2_000_000_000u64;
    let block = mined_at(&fast, &params, now + params.max_timestamp_drift);

    // The node whose clock says `now` takes it.
    assert!(connect_block(&mut fast, &block, &params, now).is_ok());

    // The node whose clock is one second behind refuses it.
    let refused = connect_block(&mut slow, &block, &params, now - 1).unwrap_err();
    assert!(
        matches!(refused, BlockError::TimestampTooFarAhead { .. }),
        "{refused:?}"
    );

    // And a second later the slow node would take the very same block, which
    // is what makes this refusal a delay rather than a verdict, at this
    // layer. What the layer above does with it is the finding.
    assert!(connect_block(&mut slow, &block, &params, now).is_ok());
}

/// The retarget is arithmetic on the parent and the network's first block and
/// nothing else: no clock, no floating point, no iteration over anything
/// unordered. The parents that exercise each part of it answer the same way
/// every time they are asked.
#[test]
fn the_retarget_answers_the_same_way_every_time_it_is_asked() {
    let origin = Origin {
        timestamp: 1_000_000,
        difficulty: 1_000,
    };
    let parents = [
        // On schedule, behind it by a fraction of a half life, and ahead of
        // it by more than the bound allows.
        HeaderSummary {
            height: 90,
            timestamp: 1_000_000 + 90 * TARGET,
            difficulty: 1_000,
        },
        HeaderSummary {
            height: 90,
            timestamp: 1_000_000 + 90 * TARGET + 1_234,
            difficulty: 1_000,
        },
        HeaderSummary {
            height: 90,
            timestamp: 999_000,
            difficulty: 1_000,
        },
    ];
    for parent in &parents {
        let first = next_difficulty(parent, origin, TARGET);
        for _ in 0..16 {
            assert_eq!(next_difficulty(parent, origin, TARGET), first);
        }
        let copied = *parent;
        assert_eq!(next_difficulty(&copied, origin, TARGET), first);
    }
}

/// Everything the retarget and the timestamp rules read comes from the chain
/// and the rules, so two nodes holding the same blocks demand the same
/// difficulty.
#[test]
fn the_demanded_difficulty_reads_only_the_chain() {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::archiving();
    let mut copy = LedgerState::archiving();

    let mut now = 2_000_000_000u64;
    for _ in 0..12 {
        let block = mined_at(&state, &params, now);
        // Connected on two nodes whose clocks are hours apart.
        connect_block(&mut state, &block, &params, now).unwrap();
        connect_block(&mut copy, &block, &params, now + 5_000).unwrap();
        assert_eq!(
            expected_difficulty(&state, &params),
            expected_difficulty(&copy, &params)
        );
        assert_eq!(state.recent_headers(), copy.recent_headers());
        now += TARGET;
    }
}

// ---------------------------------------------------------------------------
// 4. The lower bound on a timestamp.
// ---------------------------------------------------------------------------

/// Time cannot be moved backwards past the median, and the median is taken
/// over the last eleven headers whatever else is in the window.
#[test]
fn the_median_is_the_only_floor_and_it_is_eleven_blocks_wide() {
    let (window, _, _) = settled(1_000, TARGET, 91);
    // The last eleven are heights 80..=90. The median of eleven is the sixth,
    // at height 85.
    assert_eq!(window.median(), Some(1_000_000 + 85 * TARGET));

    // So a block may be dated five blocks into the past and still stand.
    let five_back = 1_000_000 + 86 * TARGET;
    assert!(five_back > window.median().unwrap());

    // The window the median reads never grows: putting eighty more headers in
    // front of it changes nothing.
    let mut short = Window::new(window.origin);
    for height in 80..91u64 {
        short.push(height, 1_000_000 + height * TARGET, 1_000);
    }
    assert_eq!(short.median(), window.median());
}

/// The median rule bounds a timestamp from below and nothing bounds it against
/// the parent, so a block may still be dated before the one it extends. What
/// such a block is worth to the retarget is the time it gives back: it stands
/// a little further ahead of the schedule, and asks a little more of the
/// block after it.
#[test]
fn a_block_may_be_dated_before_its_own_parent() {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::archiving();
    let now = 2_000_000_000u64;

    for index in 0..11u64 {
        let block = mined_at(&state, &params, now + index * TARGET);
        connect_block(&mut state, &block, &params, now + 100_000).unwrap();
    }

    let median = median_time_past(state.recent_headers()).unwrap();
    let parent = state.tip().unwrap().timestamp;
    assert!(median < parent, "the median lags the parent");

    let backdated = median + 1;
    assert!(backdated < parent);
    let block = mined_at(&state, &params, backdated);
    connect_block(&mut state, &block, &params, now + 100_000).unwrap();
    assert_eq!(state.tip().unwrap().timestamp, backdated);
}

// ---------------------------------------------------------------------------
// 5. Work accounting.
// ---------------------------------------------------------------------------

/// Work is the difficulty, so the work a chain accrues per second is its hash
/// rate and nothing else. Halving the difficulty doubles the blocks and buys
/// no work at all: this is why the fork choice is not what a timestamp attack
/// reaches.
#[test]
fn cheap_blocks_buy_blocks_and_never_work() {
    use cairn_ledger::pow::work_of;
    assert_eq!(work_of(1), 1);
    assert_eq!(work_of(u64::MAX), u128::from(u64::MAX));

    let full: u128 = 1_024 * work_of(1_000_000);
    let cheap: u128 = 1_024 * work_of(250_000);
    assert_eq!(full / cheap, 4);
}

/// Cumulative work cannot overflow a `u128` on any chain this software could
/// produce, and the header rule that adds to it is checked rather than
/// wrapping.
#[test]
fn cumulative_work_cannot_reach_the_end_of_a_u128() {
    use cairn_ledger::pow::work_of;
    let blocks: u128 = 1_000 * 365 * 24 * 3_600;
    let most = work_of(u64::MAX).saturating_mul(blocks);
    assert!(most < u128::MAX / 2, "a thousand years cannot fill a u128");

    let all_ones = cairn_ledger::pow::target_for(u64::MAX);
    assert_eq!(all_ones[0], 0);
}

/// A header cannot inflate the work it contributes by choosing a strange
/// difficulty: the difficulty it may state is the one the chain demands, and
/// the work it may state is that plus what stood before it.
#[test]
fn a_header_may_not_choose_the_work_it_contributes() {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::archiving();
    let now = 2_000_000_000u64;

    let honest = mined_at(&state, &params, now);
    let demanded = honest.header.difficulty;

    for claimed in [demanded + 1, demanded * 4, u64::MAX, MIN_DIFFICULTY - 1 + 2] {
        if claimed == demanded {
            continue;
        }
        let mut forged = honest.clone();
        forged.header.difficulty = claimed;
        forged.header.total_work = u128::from(claimed);
        let error = connect_block(&mut state, &forged, &params, now).unwrap_err();
        assert!(
            matches!(error, BlockError::WrongDifficulty { .. }),
            "difficulty {claimed} gave {error:?}"
        );
    }

    for claimed in [0u128, 2, u128::MAX] {
        let mut forged = honest.clone();
        forged.header.total_work = claimed;
        let error = connect_block(&mut state, &forged, &params, now).unwrap_err();
        assert!(
            matches!(error, BlockError::WrongTotalWork { .. }),
            "work {claimed} gave {error:?}"
        );
    }

    connect_block(&mut state, &honest, &params, now).unwrap();
}

// ---------------------------------------------------------------------------
// 6. What a floored difficulty does to the reorganisation window.
// ---------------------------------------------------------------------------

/// When the chains below open, and the rules that open them there: a network
/// whose first block is dated at its opening and carries the floor, so a
/// chain on schedule stands exactly at the floor's edge.
const OPENED: u64 = 2_000_000_000;

fn at_the_floors_edge() -> ConsensusParams {
    ConsensusParams {
        opens_at: OPENED,
        ..ConsensusParams::testnet()
    }
}

/// Blocks a chain keeps at the difficulty floor when its blocks are `gap`
/// seconds apart, and what the rule asks for once it stops.
///
/// Mined for real: `assemble_block` reads the difficulty off the chain and
/// `connect_block` applies every rule to what comes back. The node's clock is
/// put far ahead so that the drift is not what ends the run, since the drift
/// is a separate rule and this is about the retarget.
fn blocks_held_at_the_floor(gap: u64, most: u64) -> (u64, u64) {
    let params = at_the_floors_edge();
    let mut state = LedgerState::new();
    let mut timestamp = OPENED;
    let mut held = 0u64;
    while held < most && expected_difficulty(&state, &params) == MIN_DIFFICULTY {
        let block = mined_at(&state, &params, timestamp);
        connect_block(&mut state, &block, &params, u64::MAX / 2).unwrap();
        held += 1;
        timestamp += gap;
    }
    (held, expected_difficulty(&state, &params))
}

/// What a run of blocks at the floor actually costs in chain time.
///
/// The floor is not a spacing under this rule, it is a place behind the
/// schedule. A chain on schedule at the floor's edge is asked for two once it
/// stands a half life ahead, so every block dated closer than the target
/// spends a little of an hour of slack and none is free: a thousand and
/// twenty four blocks hold the floor evenly spaced at 57 seconds and not at
/// 56, and span 16 h 12 m against the 17 h 04 m of the target. Under the
/// moving average it was 31 seconds and 8 h 49 m.
///
/// Off a chain that is not at the floor the same spacing is a chain moving
/// ahead of its schedule, which is asked for more, not less.
#[test]
fn the_floor_holds_a_reorganisation_window_from_fifty_seven_seconds_and_not_from_fifty_six() {
    // The rule on its own: a parent at height `h` of a chain spaced `gap`
    // apart from the floor's edge stands `(target - gap) * h` ahead, and is
    // asked for the floor while that is under a half life.
    let origin = Origin {
        timestamp: OPENED,
        difficulty: MIN_DIFFICULTY,
    };
    let held = |gap: u64| {
        (0..REORG_WINDOW).all(|height| {
            let parent = HeaderSummary {
                height,
                timestamp: OPENED + height * gap,
                difficulty: MIN_DIFFICULTY,
            };
            next_difficulty(&parent, origin, TARGET) == MIN_DIFFICULTY
        })
    };
    assert!(held(CHEAPEST_AT_THE_FLOOR), "57 s a block holds the floor");
    assert!(!held(CHEAPEST_AT_THE_FLOOR - 1), "56 s a block does not");

    // And on a chain mined block by block under the real rules.
    let (fifty_six, asked) = blocks_held_at_the_floor(CHEAPEST_AT_THE_FLOOR - 1, REORG_WINDOW);
    assert!(
        fifty_six < REORG_WINDOW,
        "the floor held for {fifty_six} blocks at 56 s"
    );
    assert_eq!(asked, 2, "and the rule then asked for {asked}");
    let (fifty_seven, asked) = blocks_held_at_the_floor(CHEAPEST_AT_THE_FLOOR, REORG_WINDOW);
    assert_eq!(
        fifty_seven, REORG_WINDOW,
        "the floor held for {fifty_seven} blocks at 57 s"
    );
    assert_eq!(asked, MIN_DIFFICULTY, "and stayed there");

    let cheapest = REORG_WINDOW * CHEAPEST_AT_THE_FLOOR;
    let on_schedule = REORG_WINDOW * TARGET;
    assert_eq!(cheapest, 58_368);
    assert_eq!(on_schedule, 61_440);
    println!(
        "\n  a reorganisation window at the floor costs {} h {:02} m of chain time evenly\n  \
         spaced, against {} h {:02} m at the target\n",
        cheapest / 3_600,
        cheapest % 3_600 / 60,
        on_schedule / 3_600,
        on_schedule % 3_600 / 60,
    );

    // Off a chain that is not at the floor the same spacing moves it ahead of
    // its schedule.
    let high = 1u64 << 20;
    let (window, _, _) = settled(high, CHEAPEST_AT_THE_FLOOR, 1_025);
    assert!(
        window.next(TARGET) > high,
        "57 s a block off 2^20 asked for no more"
    );
}

/// A chain sitting at the floor, built for real and checked block by block by
/// the rules themselves.
///
/// Cumulative work is the sum of the difficulties, so a branch at difficulty
/// one adds one unit of work per block however much electricity was behind
/// it. A thousand and twenty four of them (the whole reorganisation window,
/// and the whole depth a handed over ledger is buried under) come to a
/// thousand hashes. Under the first moving average the saw bought that inside
/// twenty minutes of chain time, inside the drift of the time, so a node whose
/// clock stood at the fork took the entire branch at once.
///
/// Time is what it costs now, and more of it than under any version of the
/// moving average. The saw leaves the floor within a half life of claimed
/// time, and a branch that keeps the floor spans at least a target a block
/// less an hour. A node refuses anything more than ten blocks ahead of its own
/// clock, so the branch cannot arrive at once and the attacker sits through
/// the difference in real time while the honest chain keeps working.
#[test]
fn the_reorg_window_can_no_longer_be_had_for_a_thousand_hashes() {
    let params = at_the_floors_edge();
    assert_eq!(params.genesis_difficulty, MIN_DIFFICULTY);
    let window = 1_024usize;
    let fork_clock = OPENED;

    let pattern = [
        true, false, true, false, true, false, true, false, true, false, false,
    ];

    // First the saw, on headers alone, because it stops being mineable long
    // before the window is full and the point is exactly that.
    let mut headers = Window::new(params.origin());
    let mut low = OPENED;
    let mut demanded = MIN_DIFFICULTY;
    let mut mineable = 0usize;
    for index in 0..window {
        let median = headers.median().unwrap_or(0);
        low = low.saturating_add(1).max(median + 1);
        let timestamp = if pattern[index % pattern.len()] {
            low + 6 * TARGET
        } else {
            low
        };
        headers.push(index as u64, timestamp, demanded);
        demanded = headers.next(TARGET);
        if demanded == MIN_DIFFICULTY {
            mineable += 1;
        }
    }
    println!("\n  the saw that used to hold a chain at the floor for a whole window");
    println!("  now holds it there for {mineable} blocks, and by the end of the window");
    println!("  it is asking for difficulty {demanded}");
    assert!(
        mineable < window / 8,
        "the saw held the floor for {mineable} of {window} blocks"
    );
    assert!(demanded > 50_000, "it only reached {demanded}");

    // And a branch that does keep the floor, built for real at the cheapest
    // even spacing that keeps it. It runs out of drift long before it runs out
    // of blocks: `connect_block` refuses the rest until the clock catches up.
    let mut state = LedgerState::archiving();
    let mut timestamp = OPENED;
    let mut accepted = 0usize;
    let refusal = loop {
        if accepted == window {
            break None;
        }
        let block = mined_at(&state, &params, timestamp);
        assert_eq!(
            block.header.difficulty, MIN_DIFFICULTY,
            "a chain spaced at 57 s from the floor's edge stays at the floor"
        );
        match connect_block(&mut state, &block, &params, fork_clock) {
            Ok(_) => {
                accepted += 1;
                timestamp += CHEAPEST_AT_THE_FLOOR;
            }
            Err(error) => break Some(error),
        }
    };

    let refusal = refusal.expect("the branch outruns the drift before the window is full");
    assert!(
        matches!(refusal, BlockError::TimestampTooFarAhead { .. }),
        "{refusal:?}"
    );
    let span = window as u64 * CHEAPEST_AT_THE_FLOOR;
    println!(
        "  the cheapest even branch that keeps the floor spans {span} s, of which a node at\n  \
         the fork takes {accepted} blocks and refuses the rest until its own clock\n  \
         catches up: {:.1} hours of waiting\n",
        (span - params.max_timestamp_drift) as f64 / 3_600.0
    );
    assert!(
        accepted <= (params.max_timestamp_drift / CHEAPEST_AT_THE_FLOOR + 1) as usize,
        "it took {accepted} blocks at once"
    );
    assert!(span > params.max_timestamp_drift * 50);
}

/// A brand new network, from its opening difficulty, driven by a miner that
/// holds every block and dates them with the median-legal saw.
///
/// `testnet-8` opens at 2^28 and `devnet` at 2^23. The opening difficulty is
/// described as what makes the first seconds of a launch fair, and the saw
/// used to take either of them to the floor inside the two hour drift of the
/// first moving average: a few hundred blocks and an hour of chain time. A
/// second a block is a chain running far ahead of its schedule, so the same
/// saw walks the difficulty up on both networks: a network's opening
/// difficulty is not something the first miner can write away.
#[test]
fn an_opening_difficulty_does_not_fall_to_the_saw() {
    let pattern = [
        true, false, true, false, true, false, true, false, true, false, false,
    ];
    for (name, start, target) in [("testnet-8", 1u64 << 28, 60u64), ("devnet", 1 << 23, 5)] {
        let opened = 1_000_000u64;
        let mut window = Window::new(Origin {
            timestamp: opened,
            difficulty: start,
        });
        let mut low = opened;
        let mut difficulty = start;
        let mut refused = 0usize;
        for blocks in 0..200usize {
            let median = window.median().unwrap_or(0);
            low = low.saturating_add(1).max(median + 1);
            let timestamp = if pattern[blocks % pattern.len()] {
                low + 6 * target
            } else {
                low
            };
            if timestamp <= median {
                refused += 1;
            }
            window.push(blocks as u64, timestamp, difficulty);
            difficulty = window.next(target);
            assert!(difficulty > MIN_DIFFICULTY, "{name}: reached the floor");
        }
        assert_eq!(refused, 0, "{name}: every block clears the median");
        assert!(
            difficulty > start,
            "{name}: the saw should cost, not save: {difficulty} against {start}"
        );
        println!("\n  {name}: the saw climbs to {difficulty} over two hundred blocks");
    }
    println!();
}

// ---------------------------------------------------------------------------
// 7. Timestamps at the drift ceiling.
// ---------------------------------------------------------------------------

/// The difficulty a steady chain carries in the simulations below.
const STEADY: u64 = 1_000_000;

/// The two networks this repository runs, as the rules name them.
fn both_networks() -> [(&'static str, ConsensusParams); 2] {
    [
        ("testnet", ConsensusParams::for_network("testnet").unwrap()),
        ("devnet", ConsensusParams::for_network("devnet").unwrap()),
    ]
}

/// A draw in `0..1` that is the same on every machine.
struct Lcg(u64);

impl Lcg {
    fn unit(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Two miners. One holds `share` of the hash rate and dates its blocks at the
/// drift ceiling, never past what the rules accept and always past the
/// median, so every block it writes is valid to every node. The other dates
/// its blocks the way `cairn-node` does, the wall clock raised to the median
/// plus one. Each block takes exactly what its difficulty demands of the
/// whole hash rate.
///
/// Returns the mean block time as a multiple of the target and the highest
/// difficulty any block was asked for.
fn a_minority_at_the_ceiling(share: f64, params: &ConsensusParams, blocks: usize) -> (f64, u64) {
    let target = params.target_block_time;
    let drift = params.max_timestamp_drift;
    let mut rng = Lcg(7);
    let (mut window, mut height, _) = settled(STEADY, target, RECENT_HEADERS as u64);
    let mut real = window.last().timestamp;
    let mut solved: u128 = 0;
    let mut highest = 0u64;
    for _ in 0..blocks {
        let difficulty = window.next(target);
        let solve = ((u128::from(difficulty) * u128::from(target) + u128::from(STEADY) / 2)
            / u128::from(STEADY))
        .max(1) as u64;
        real += solve;
        let earliest = window.median().unwrap() + 1;
        let wanted = if rng.unit() < share {
            real + drift
        } else {
            real
        };
        window.push(height, wanted.max(earliest).min(real + drift), difficulty);
        height += 1;
        solved += u128::from(solve);
        highest = highest.max(difficulty);
    }
    (solved as f64 / blocks as f64 / target as f64, highest)
}

/// A minority dating its blocks at the drift ceiling leaves the chain at its
/// target and the difficulty near where it was.
///
/// The drift was two hours on every network, and against the moving average a
/// thirty percent miner at that ceiling, or an honest one whose clock was two
/// hours fast, made testnet run at 1.53 times its target with single blocks
/// asked for 115 times the steady difficulty, and devnet at fourteen times its
/// target. At ten blocks of drift and a schedule that only reads the parent,
/// each of its blocks buys the next one a sixth of a half life and the honest
/// block after takes it back.
#[test]
fn a_minority_dating_its_blocks_at_the_drift_ceiling_does_not_slow_the_chain() {
    for (name, params) in both_networks() {
        let (mean, highest) = a_minority_at_the_ceiling(0.3, &params, 4_000);
        println!(
            "\n  {name}, a 30% share at +{} s: blocks at x{mean:.3} of the target, the \
             hardest block x{:.2} of steady",
            params.max_timestamp_drift,
            highest as f64 / STEADY as f64
        );
        assert!(
            (0.90..=1.10).contains(&mean),
            "{name}: a minority writing valid timestamps made the chain run at x{mean:.3} \
             of its target block time"
        );
        assert!(
            highest <= 2 * STEADY,
            "{name}: a minority writing valid timestamps made one block ask for x{:.1} of \
             the steady difficulty",
            highest as f64 / STEADY as f64
        );
    }
}

/// A header dated at the drift ceiling lowers the next block's difficulty by
/// a sixth of a halving and nothing after it.
///
/// Under the moving average the excess a header was clamped out of came back
/// once, in full, when that header became the oldest of the window, and at a
/// drift of two hours that one retarget asked 1.36 times the steady difficulty
/// on testnet and four times on devnet. The schedule reads the parent alone:
/// the header after it, dated honestly, is asked what the schedule asks.
#[test]
fn a_header_at_the_drift_ceiling_lowers_the_next_block_by_a_ninth_and_nothing_after() {
    for (name, params) in both_networks() {
        let target = params.target_block_time;
        let (mut window, height, timestamp) = settled(STEADY, target, 100);
        window.push(height, timestamp + params.max_timestamp_drift, STEADY);
        let after_it = window.next(target);
        window.push(height + 1, timestamp + target, after_it);
        let after_that = window.next(target);
        println!(
            "\n  {name}: one header +{} s asks x{:.4} of the next, x{:.4} of the one after",
            params.max_timestamp_drift,
            after_it as f64 / STEADY as f64,
            after_that as f64 / STEADY as f64
        );
        assert_eq!(
            after_it, 890_991,
            "{name}: 2^(-1/6) of the steady difficulty"
        );
        assert_eq!(after_that, STEADY, "{name}: and nothing is left after it");
    }
}

/// The shortest a branch of the burial depth held at the floor can span, as
/// the documents publish it.
///
/// Each timestamp is taken as low as the median rule and a demand of one
/// allow, block by block, off an honest chain on schedule at the floor's edge,
/// which is the most slack any branch can start from: a branch forked off a
/// chain at a real difficulty first has to fall a half life behind for every
/// halving. Spacing need not be even, and the tightest branch spends its hour
/// of slack at once and then runs a target a block: 57 841 seconds, 16 h 04
/// m, against the 61 440 of a branch on schedule. Under the moving average
/// the same search found 30 069 seconds, 8 h 21 m.
///
/// Pinned exactly, so that a change to the retarget moving the figure either
/// way fails here and sends whoever made it to the documents that quote it.
#[test]
fn a_floor_branch_of_the_burial_depth_spans_the_figure_the_documents_publish() {
    let (mut window, mut height, _) = settled(MIN_DIFFICULTY, TARGET, 200);
    let origin = window.origin;
    let forked_at = window.last().timestamp;
    let mut highest = forked_at;
    let keeps_the_floor = |height: u64, timestamp: u64| {
        let probe = HeaderSummary {
            height,
            timestamp,
            difficulty: MIN_DIFFICULTY,
        };
        next_difficulty(&probe, origin, TARGET) == MIN_DIFFICULTY
    };
    for _ in 0..REORG_WINDOW {
        assert_eq!(window.next(TARGET), MIN_DIFFICULTY);
        let mut low = window.median().unwrap() + 1;
        let mut high = window.last().timestamp + FALL;
        while low < high {
            let middle = low + (high - low) / 2;
            if keeps_the_floor(height, middle) {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        assert!(keeps_the_floor(height, low));
        window.push(height, low, MIN_DIFFICULTY);
        highest = highest.max(low);
        height += 1;
    }
    let span = highest - forked_at;
    println!(
        "\n  1 024 blocks at the floor span {span} s, {} h {:02} m, against {} s spaced \
         evenly at {CHEAPEST_AT_THE_FLOOR} s\n",
        span / 3_600,
        span % 3_600 / 60,
        REORG_WINDOW * CHEAPEST_AT_THE_FLOOR
    );
    assert_eq!(
        span, 57_841,
        "the tightest floor branch found moved, and the specification, the whitepaper \
         and `sampling.rs` quote it"
    );
    assert!(span < REORG_WINDOW * CHEAPEST_AT_THE_FLOOR);
}

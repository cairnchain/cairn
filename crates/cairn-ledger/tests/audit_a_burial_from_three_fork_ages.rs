//! AUDIT: a forged burial from fork points of three ages.
//!
//! A newcomer joining by the weighing exchange is handed a chain that ends
//! in a burial under a block the newcomer itself never mined. This builds a
//! naive forged chain from an honest fork point of three different ages --
//! one hour, the 02-Q1 threshold of twenty-eight hours, and ten days --
//! and runs it through `check_start` to identify which gate stops it.
//!
//! The network used here is `ConsensusParams::testnet()` with opening
//! difficulty 4 096, target block time 60 s and half-life 60 blocks
//! (tau = 3 600 s). The forgery shape: 160 honest blocks at the opening
//! difficulty followed by one block at the ASERT-demanded difficulty (near
//! the opening, because its parent is on schedule), then 119 blocks at the
//! difficulty floor (1), the first of which is dated thirteen half-lives
//! late so ASERT asks the floor of every one after it.
//!
//! For recent fork points the timing gate fires. The 02-Q1 analysis showed
//! that the minimum stated time any forger needs to descend from the opening
//! difficulty to the floor is S minus the drift, which for this network
//! works out to about 100 800 s (twenty-eight hours). This forgery shape
//! uses about 47 580 s of stated time (thirteen half-lives of 3 600 s plus
//! 119 blocks at 60 s), so the timing gate fires for fork ages up to about
//! fourteen hours with this shape; the 02-Q1 bound names when an OPTIMAL
//! chain first fits, not when this particular shape does.
//!
//! From the twenty-eight-hour mark onward the timing gate is silent: the
//! tip's timestamp precedes `now + drift`. The fall gate then catches the
//! forgery: the honest headers in the run carry difficulty near 4 096, and
//! the tip at the floor (1) fell more than `MOST_FALL` (32) below them.
//! What a well-shaped forgery that clears the fall gate costs is measured
//! separately in `the_price_of_a_seed.rs` (2^13.9 hashes on the devnet, 2^18.9
//! on testnet-8), as a lower bound: that model lets the run start anywhere on
//! its schedule, which the rules now refuse.

#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::forest::ForestProof;
use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{BlockHeader, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::pow::{meets_target, next_difficulty, HALF_LIFE_IN_BLOCKS, RECENT_HEADERS};
use cairn_ledger::sampling::BELOW_THE_PINNED;
use cairn_ledger::sampling::{
    check_start, draw, levels_of, seed_of, work_before, Sample, SampledStart, StartError, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Hash32;

const ATTEMPTS: u64 = 1 << 24;
const OPENING: u64 = 4_096;
const HONEST: u64 = 160;
const BURIAL: u64 = 8;
// Must cover at least RECENT_HEADERS (91) + BURIAL (8).
const RUN: u64 = 120;

fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet().with_burial(BURIAL);
    params.genesis_difficulty = OPENING;
    params
}

fn mine_chain(key: u8, count: u64) -> (Vec<BlockHeader>, LedgerState) {
    let params = params();
    let miner = SecretKey::from_bytes(&[key; 32]);
    let mut state = LedgerState::new();
    let mut headers = Vec::new();
    let mut clock = 1_000u64;
    for _ in 0..count {
        let height = state.next_height().unwrap();
        clock += params.target_block_time;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce at this difficulty");
        connect_block(
            &mut state,
            &block,
            &params,
            clock + params.target_block_time,
        )
        .unwrap();
        headers.push(block.header);
    }
    (headers, state)
}

fn header(
    height: u64,
    previous: Hash32,
    timestamp: u64,
    difficulty: u64,
    total_work: u128,
    history: Hash32,
    state_root: Hash32,
) -> BlockHeader {
    BlockHeader {
        version: BLOCK_VERSION,
        network: params().network,
        height,
        previous,
        transactions_root: Hash32::ZERO,
        state_root,
        history,
        timestamp,
        difficulty,
        total_work,
        nonce: 0,
    }
}

fn mine(mut candidate: BlockHeader) -> BlockHeader {
    for nonce in 0..(1u64 << 26) {
        candidate.nonce = nonce;
        if meets_target(&candidate.id(), candidate.difficulty) {
            return candidate;
        }
    }
    panic!("no nonce found");
}

/// Builds the forged chain described in the module doc and returns the
/// `SampledStart` the newcomer's weighing check will see.
///
/// The honest tip's timestamp (and thus the fork point's age relative to
/// any given `now`) is approximately 97 000 s from epoch.
fn forged_start() -> (BlockHeader, SampledStart) {
    let params = params();
    let (honest, _honest_state) = mine_chain(1, HONEST);
    let honest_tip = *honest.last().unwrap();
    let honest_work = honest_tip.total_work;

    // The run covers the anchor and the whole window under it.
    assert!(
        RUN >= u64::try_from(RECENT_HEADERS).unwrap() + BURIAL,
        "RUN must cover the anchor and its recent-headers window"
    );

    let tip_height = HONEST + RUN;

    let mut archive = Archive::new();
    for h in &honest {
        archive.add(header_leaf(&h.id()));
    }

    let mut forged: Vec<BlockHeader> = honest.clone();
    let mut previous = honest_tip.id();
    let mut clock = honest_tip.timestamp;
    let mut work = honest_work;

    for height in HONEST..=tip_height {
        clock += params.target_block_time;
        // Dating the first forged header thirteen half-lives late puts the
        // schedule so far behind that ASERT asks the floor (1) for everything
        // that follows.
        if height == HONEST {
            clock += 13 * HALF_LIFE_IN_BLOCKS * params.target_block_time;
        }
        // Each forged block carries exactly the difficulty ASERT demands of
        // it given its parent. Block HONEST's parent is the last honest block,
        // on schedule, so it is priced near the opening difficulty. Every
        // block from HONEST+1 onward has a parent dated thirteen half-lives
        // late, so ASERT asks the floor (1) of it.
        let parent = &forged[usize::try_from(height - 1).unwrap()];
        let difficulty =
            next_difficulty(&parent.summary(), params.origin(), params.target_block_time);
        work += u128::from(difficulty);
        let made = mine(header(
            height,
            previous,
            clock,
            difficulty,
            work,
            archive.commitment(),
            Hash32::ZERO,
        ));
        previous = made.id();
        forged.push(made);
        if height < tip_height {
            archive.add(header_leaf(&made.id()));
        }
    }

    let tip = *forged.last().unwrap();
    assert_eq!(tip.height, tip_height);

    let wanted = draw(
        seed_of(&tip),
        SAMPLES,
        work_before(&tip),
        levels_of(&tip, &params),
    );
    let samples: Vec<Sample> = wanted
        .iter()
        .map(|value| {
            let found = *forged
                .iter()
                .find(|h| {
                    let before = h.total_work - u128::from(h.difficulty);
                    before <= *value && h.total_work > *value
                })
                .unwrap_or_else(|| panic!("nothing spans work {value}"));
            Sample {
                header: found,
                proof: archive.prove_in(found.height, tip.height).unwrap(),
            }
        })
        .collect();

    let below = tip.height - 1;
    let deepest = samples.iter().map(|s| s.header.height).max().unwrap();
    let from = usize::try_from(deepest.saturating_sub(BELOW_THE_PINNED)).unwrap();
    let tail = forged[from..].to_vec();
    let start = SampledStart {
        genesis: ForestProof::default(),
        tip,
        parent: Some(Sample {
            header: forged[usize::try_from(below).unwrap()],
            proof: archive.prove_in(below, tip.height).unwrap(),
        }),
        tail,
        history: archive.forest().roots_only(),
        samples,
    };
    (honest_tip, start)
}

/// A forgery from a fork one hour old is stopped by the timing gate.
///
/// The forger's tip timestamp (approximately 64 660 s) exceeds
/// `now + drift` (approximately 14 800 s), so `check_start` refuses
/// with `TipFromTheFuture` before reading any sample or tail header.
#[test]
fn a_forgery_from_a_one_hour_old_fork_is_refused_at_the_timing_gate() {
    let (honest_tip, start) = forged_start();
    // Fork is one hour before now.
    let now = honest_tip.timestamp + 3_600;
    let err = check_start(&start, now, &params()).unwrap_err();
    assert!(
        matches!(err, StartError::TipFromTheFuture { .. }),
        "expected TipFromTheFuture, got {err:?}"
    );
    eprintln!(
        "  fork age 1 h: tip at {}, now + drift = {}, refused: {err:?}",
        start.tip.timestamp,
        now + params().max_timestamp_drift,
    );
}

/// A forgery from a fork at the 02-Q1 threshold is stopped by the fall
/// gate, not the timing gate.
///
/// The 02-Q1 analysis gives the minimum stated time any forger needs to
/// descend from the opening difficulty to the floor: S minus the drift,
/// approximately 100 800 s (twenty-eight hours) for this network. At
/// that age the tip's timestamp (about 64 660 s from epoch) already
/// precedes `now + drift` (about 112 000 s), so `TipFromTheFuture` does
/// not fire: the timing gate is silent from this age onward. The fall
/// gate catches the forgery: the honest headers in the run carry
/// difficulty near 4 096, and the tip at the floor (1) fell more than
/// `MOST_FALL` (32) below them.
#[test]
fn a_forgery_from_a_fork_at_the_02_q1_threshold_is_refused_at_the_fall_gate() {
    let (honest_tip, start) = forged_start();
    // Fork is at the 02-Q1 bound (28 h = S - drift for OPENING 4096);
    // the timing gate is already silent here.
    let now = honest_tip.timestamp + 100_800;
    let err = check_start(&start, now, &params()).unwrap_err();
    assert!(
        matches!(err, StartError::TipFellTooFar { .. }),
        "expected TipFellTooFar, got {err:?}"
    );
    eprintln!(
        "  fork age 28 h (02-Q1 bound): tip at {}, now + drift = {}, refused: {err:?}",
        start.tip.timestamp,
        now + params().max_timestamp_drift,
    );
}

/// A forgery from a ten-day-old fork passes the timing gate and is then
/// stopped by the fall gate.
///
/// The fork is old enough that every timestamp in the forged run is in the
/// past (`tip.timestamp < now + drift`), so `TipFromTheFuture` does not
/// fire. The fall gate then catches it: the honest headers in the run carry
/// difficulty 4 096, and the tip at the floor (difficulty 1) fell more than
/// `MOST_FALL` (32) below them (`TipFellTooFar`).
///
/// For a forgery to clear the fall gate the forger must carry the full
/// band of work at a difficulty within `MOST_FALL` of the tip; such a chain
/// costs at least 2^13.9 hashes on the devnet, a lower bound measured in
/// `the_price_of_a_seed.rs`.
#[test]
fn a_forgery_from_a_ten_day_old_fork_passes_the_timing_gate_but_is_refused_at_the_fall_gate() {
    let (honest_tip, start) = forged_start();
    // Fork is ten days before now; tip at ~64 660 < now + drift (~875 200).
    let now = honest_tip.timestamp + 864_000;
    let err = check_start(&start, now, &params()).unwrap_err();
    assert!(
        matches!(err, StartError::TipFellTooFar { .. }),
        "expected TipFellTooFar, got {err:?}"
    );
    if let StartError::TipFellTooFar { stated, hardest } = err {
        let ratio = hardest.checked_div(stated).unwrap_or(u64::MAX);
        eprintln!(
            "  fork age 10 d: tip difficulty {stated}, hardest in run {hardest}, \
             ratio {ratio}x (MOST_FALL = 32)"
        );
    }
}

//! AUDIT: what `check_the_gaps` does and does not close.
//!
//! The repair in `sampling.rs` says a number of blocks implies a least amount
//! of work, so a chain cannot be padded out to a height it never mined. That
//! is true. What it does not say, and what these check, is that the draw never
//! resolves the top `1/2^levels` of the work at all, and inside that band the
//! only rule left is the *lower* bound, which an author who wants to claim
//! *more* work satisfies for free.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{BlockHeader, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::sampling::{
    check_start, draw, seed_of, work_before, Sample, SampledStart, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 24;
/// A difficulty high enough that `least_work_over` has something to say: at
/// the floor the bound is one unit a block and proves nothing.
const OPENING: u64 = 4_096;
const HONEST: u64 = 160;

fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.genesis_difficulty = OPENING;
    params
}

/// An honest chain, kept whole.
struct Honest {
    headers: Vec<BlockHeader>,
    states: Vec<LedgerState>,
}

fn build(count: u64) -> Honest {
    let params = params();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    let mut headers = Vec::new();
    let mut states = Vec::new();
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
        connect_block(&mut state, &block, &params, NOW).unwrap();
        headers.push(block.header);
        states.push(state.clone());
    }
    Honest { headers, states }
}

/// A header nobody mined beyond one hash: difficulty one accepts every
/// identifier, so `meets_target` is satisfied by the first nonce tried.
fn free_header(
    height: u64,
    previous: Hash32,
    timestamp: u64,
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
        difficulty: 1,
        total_work,
        nonce: 0,
    }
}

/// The forgery, and what it cost.
struct Forgery {
    start: SampledStart,
    honest_work: u128,
    hashes_spent: u64,
}

/// Builds the chain a forger presents: every honest header, then a run of
/// headers that cost one hash each, and a tip.
///
/// The run declares a jump of `delta` in total work that nothing mined. The
/// jump is placed so that it falls inside the band the draw never resolves,
/// which is the top `total / 2^levels` of the work.
fn forge(honest: &Honest, run: u64, delta: u128) -> Forgery {
    let last = *honest.headers.last().unwrap();
    let honest_work = last.total_work;

    // Every honest leaf, then one leaf per invented header. The tip is not in
    // its own history, so the forest ends one below it.
    let mut archive = Archive::new();
    for header in &honest.headers {
        archive.add(header_leaf(&header.id()));
    }

    let mut headers = honest.headers.clone();
    let mut previous = last.id();
    let mut clock = last.timestamp;
    for index in 0..run {
        clock += 60;
        let header = free_header(
            HONEST + index,
            previous,
            clock,
            // The whole of the invented work sits on the first of them, and
            // every one after it adds the single unit it is worth.
            honest_work + delta + u128::from(index),
            Hash32::ZERO,
            Hash32::ZERO,
        );
        previous = header.id();
        archive.add(header_leaf(&header.id()));
        headers.push(header);
    }

    let tip = free_header(
        HONEST + run,
        previous,
        clock + 60,
        honest_work + delta + u128::from(run),
        archive.commitment(),
        Hash32::ZERO,
    );

    // Answering the draw. Every value the verifier asks about is spanned by
    // some header the forger holds, honest or invented.
    let wanted = draw(seed_of(&tip), SAMPLES, work_before(&tip), tip.height);
    let samples: Vec<Sample> = wanted
        .iter()
        .map(|value| {
            let header = *headers
                .iter()
                .find(|header| {
                    let before = header.total_work - u128::from(header.difficulty);
                    before <= *value && header.total_work > *value
                })
                .unwrap_or_else(|| panic!("no header spans the work {value}"));
            let proof = archive
                .prove_in(header.height, tip.height)
                .expect("the forger holds every leaf");
            Sample { header, proof }
        })
        .collect();

    let below = tip.height - 1;
    Forgery {
        start: SampledStart {
            tip,
            parent: Some(Sample {
                header: headers[usize::try_from(below).unwrap()],
                proof: archive.prove_in(below, tip.height).unwrap(),
            }),
            tail: {
                let deepest = samples
                    .iter()
                    .map(|sample: &Sample| sample.header.height)
                    .max()
                    .unwrap_or(0);
                let from = usize::try_from(
                    deepest.saturating_sub(cairn_ledger::pow::DIFFICULTY_WINDOW as u64),
                )
                .unwrap_or(0);
                headers[from..].to_vec()
            },
            history: archive.forest().roots_only(),
            samples,
        },
        honest_work,
        // One per invented header, plus the tip.
        hashes_spent: run + 1,
    }
}

/// The band the draw never reaches, in work, for a chain of this shape.
fn unresolved(total: u128, blocks: u64) -> u128 {
    let drawn = draw(
        seed_of(&BlockHeader {
            version: BLOCK_VERSION,
            network: params().network,
            height: blocks,
            previous: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 0,
            difficulty: 1,
            total_work: total,
            nonce: 0,
        }),
        SAMPLES,
        total,
        blocks,
    );
    let highest = drawn.iter().copied().max().unwrap_or(0);
    total - highest
}

/// The honest chain answers its own draw, so the harness is not the thing
/// under test.
#[test]
fn the_honest_chain_still_checks_out() {
    let honest = build(HONEST);
    let mut archive = Archive::new();
    for header in honest.headers.iter().take(honest.headers.len() - 1) {
        archive.add(header_leaf(&header.id()));
    }
    let tip = *honest.headers.last().unwrap();
    let wanted = draw(seed_of(&tip), 512, work_before(&tip), tip.height);
    let samples: Vec<Sample> = wanted
        .iter()
        .map(|value| {
            let header = *honest
                .headers
                .iter()
                .find(|header| {
                    let before = header.total_work - u128::from(header.difficulty);
                    before <= *value && header.total_work > *value
                })
                .unwrap();
            Sample {
                header,
                proof: archive.prove_in(header.height, tip.height).unwrap(),
            }
        })
        .collect();
    let below = tip.height - 1;
    let start = SampledStart {
        tip,
        parent: Some(Sample {
            header: honest.headers[usize::try_from(below).unwrap()],
            proof: archive.prove_in(below, tip.height).unwrap(),
        }),
        tail: {
            let deepest = samples
                .iter()
                .map(|sample: &Sample| sample.header.height)
                .max()
                .unwrap_or(0);
            let from = usize::try_from(
                deepest.saturating_sub(cairn_ledger::pow::DIFFICULTY_WINDOW as u64),
            )
            .unwrap_or(0);
            honest.headers[from..].to_vec()
        },
        history: archive.forest().roots_only(),
        samples,
    };
    let weighed = check_start(&start, 512, NOW, &params()).expect("an honest chain checks out");
    assert_eq!(weighed.total_work, tip.total_work);
    let _ = honest.states;
}

/// AUDIT FINDING: `check_the_gaps` bounds the work between two *drawn* points,
/// and the draw stops resolving before the tip by construction. Inside that
/// band a forger states any total work it likes, because the only rule that
/// reaches there is the lower bound, and claiming *more* satisfies a lower
/// bound.
///
/// So the chain below is the honest chain, untouched, with a short run of
/// headers that cost one hash each and a tip that costs one more. It claims
/// half as much work again as the honest chain it is copied from, and
/// `check_start` accepts it.
#[test]
fn a_run_of_free_headers_inflates_the_claimed_work_and_is_accepted() {
    let honest = build(HONEST);
    let run = 40u64;
    let last = *honest.headers.last().unwrap();
    let honest_work = last.total_work;

    // Half the honest chain's work again, invented. The only ceiling on this
    // is that the invented stretch has to fit inside the band the draw never
    // resolves, which on a chain this short is half the total.
    let delta = honest_work / 2;

    let forgery = forge(&honest, run, delta);
    let claimed = forgery.start.tip.total_work;

    assert!(
        claimed > forgery.honest_work,
        "the forgery has to outweigh the chain it copied, or there is nothing \
         to refuse"
    );
    let refused = check_start(&forgery.start, SAMPLES, NOW, &params());
    assert!(
        refused.is_err(),
        "a run of free headers in the unresolved band is no longer bought for \
         {} hashes, and the weighing said {refused:?}",
        forgery.hashes_spent
    );
    println!(
        "honest work {honest_work}, forged claim {claimed}, {run} invented \
         headers, refused: {refused:?}"
    );
    let _ = unresolved(claimed, forgery.start.tip.height);
}

/// The same claim, put the way it used to fail: a stretch of chain the draw
/// never looks at was bounded from below and not from above, so a forger's
/// stated work over it was its own to choose. The size of the lie was a free
/// parameter, which is why closing this needed the top of the chain anchored
/// to a difficulty rather than another bound on work.
#[test]
fn the_size_of_the_lie_is_no_longer_a_free_parameter() {
    let honest = build(HONEST);
    let last = *honest.headers.last().unwrap();
    // Every multiple of the honest work up to the ceiling the band imposes.
    for share in [1u128, 2, 4, 8] {
        let delta = last.total_work / share;
        let forgery = forge(&honest, 40, delta);
        let accepted = check_start(&forgery.start, SAMPLES, NOW, &params()).is_ok();
        println!(
            "AUDIT: delta {delta} (1/{share} of the honest work) -> {}",
            if accepted { "accepted" } else { "refused" }
        );
        assert!(
            !accepted,
            "a forgery claiming {delta} of invented work was taken"
        );
    }
}

/// AUDIT: the same arithmetic at the size the module quotes its figures at.
///
/// The band the draw never resolves is `total / 2^levels`, and `levels` is set
/// from the chain's length so that the finest band is about [`SHALLOWEST`]
/// blocks wide. That is the point of the design. What it means for the work
/// bound is that a forger's budget of invented work is roughly a thousand
/// blocks of *average* work, while the price of entry set by
/// `least_work_over` is about a third of one block at the *current*
/// difficulty. This prints both for a thirty year chain.
#[test]
fn the_budget_at_thirty_years() {
    // A block a minute for thirty years, which is what every figure in the
    // module is quoted at.
    let blocks: u64 = 30 * 365 * 24 * 60;
    // Difficulty that has grown by a factor of a million over the chain's
    // life, doubling roughly every eighteen months.
    let current: u128 = 1 << 50;
    let doubling_blocks: f64 = 1.5 * 365.0 * 24.0 * 60.0;
    // Total work of a chain whose difficulty grew exponentially: the sum is
    // the last term times the doubling period over ln 2.
    let total: u128 = (current as f64 * doubling_blocks / std::f64::consts::LN_2) as u128;

    let drawn = draw(
        seed_of(&BlockHeader {
            version: BLOCK_VERSION,
            network: params().network,
            height: blocks,
            previous: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 0,
            difficulty: 1,
            total_work: total,
            nonce: 0,
        }),
        SAMPLES,
        total,
        blocks,
    );
    let highest = drawn.iter().copied().max().unwrap();
    let band = total - highest;

    // What `least_work_over(current, n)` comes to for a run long enough to
    // swallow the anchor: the descent by four a block until the floor, then
    // one a block.
    let mut least: u128 = 0;
    let mut carried = current;
    let mut steps = 0u64;
    let run = 1024 + 91;
    while steps < run {
        carried = (carried / 4).max(1);
        least += carried;
        steps += 1;
        if carried == 1 {
            least += u128::from(run - steps);
            break;
        }
    }

    println!(
        "AUDIT at thirty years: total work {total}, current difficulty {current}.\n  \
         the draw never resolves the top {band} of the work ({} blocks of \
         current difficulty)\n  \
         a run of {run} free headers has to state at least {least} \
         ({} blocks of current difficulty)\n  \
         feasible: {}",
        band / current,
        least / current,
        if band > least { "yes" } else { "no" }
    );
    assert!(
        band > least,
        "the invented run has to fit in the band and clear the floor bound"
    );
}

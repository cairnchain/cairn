//! AUDIT: the whole joining exchange, forged.
//!
//! `check_the_gaps` (sampling) and `check_buried` (handover) were added
//! together to stop a stranger handing a newcomer a chain nobody mined. This
//! builds the forgery they were meant to stop, in the shape that survives both
//! of them, and runs it through both.
//!
//! The shape is: the honest chain untouched, then a run of headers that cost
//! one hash each, long enough that the run swallows the anchor and the whole
//! difficulty window under it. Nothing in either check looks at a header below
//! the anchor except through the aggregate work bound, and that bound is a
//! lower bound, which a forger claiming *more* work satisfies for free.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{BlockHeader, HeaderSummary, BLOCK_VERSION};
use cairn_ledger::handover::accept;
use cairn_ledger::note::Note;
use cairn_ledger::pow::DIFFICULTY_WINDOW;
use cairn_ledger::pow::{meets_target, next_difficulty, RECENT_HEADERS};
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
const OPENING: u64 = 4_096;
const HONEST: u64 = 160;
const BURIAL: u64 = 8;

fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet().with_burial(BURIAL);
    params.genesis_difficulty = OPENING;
    params
}

/// A chain mined honestly, kept whole.
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
        connect_block(&mut state, &block, &params, NOW).unwrap();
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

/// Finds a nonce. At difficulty one the first is always good.
fn mine(mut candidate: BlockHeader) -> BlockHeader {
    for nonce in 0..(1u64 << 26) {
        candidate.nonce = nonce;
        if meets_target(&candidate.id(), candidate.difficulty) {
            return candidate;
        }
    }
    panic!("no nonce found");
}

fn summaries(headers: &[BlockHeader]) -> Vec<HeaderSummary> {
    headers.iter().map(BlockHeader::summary).collect()
}

/// AUDIT FINDING: both new checks pass on a chain whose last 121 headers were
/// never mined and whose ledger is one the forger wrote.
#[test]
fn a_free_run_cannot_swallow_the_anchor_any_more() {
    let params = params();
    let (honest, _honest_state) = mine_chain(1, HONEST);
    let honest_tip = *honest.last().unwrap();
    let honest_work = honest_tip.total_work;

    // The ledger the forger wants a newcomer to hold. A different chain
    // altogether, mined to the forger's own key, so every coinbase in it is
    // the forger's. Only its hot set, cold set and grace window travel, and
    // those are what the anchor's state root will be made to commit to.
    let (_donor_headers, donor) = mine_chain(9, 30);
    let donor_root = donor.state_root();

    // Long enough that the anchor and the whole difficulty window under it
    // are headers the forger made: `check_buried` reads the window out of
    // what the sender supplies, so a window of the forger's own floor-
    // difficulty headers demands the floor of every block above it.
    let run = 120u64;
    assert!(
        run >= u64::try_from(RECENT_HEADERS).unwrap() + BURIAL,
        "the run has to cover the anchor and its window"
    );
    // Invented work. Bounded only by having to fit inside the band the draw
    // never resolves, which on a chain this short is half the total.
    let delta: u128 = 300_000;

    let tip_height = HONEST + run;
    let anchor_height = tip_height - params.burial;

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
        // Below the anchor nothing checks a difficulty, so the floor it is.
        // At and above the anchor the run is checked block by block, and the
        // window it is checked against is the forger's own floor-difficulty
        // headers, which demand the floor right back.
        let difficulty = if height > anchor_height {
            let from = usize::try_from(height - u64::try_from(RECENT_HEADERS).unwrap()).unwrap();
            let to = usize::try_from(height - 1).unwrap();
            next_difficulty(&summaries(&forged[from..=to]), params.target_block_time)
        } else {
            1
        };
        work = if height == HONEST {
            honest_work + delta + 1
        } else {
            work + u128::from(difficulty)
        };
        let state_root = if height == anchor_height {
            donor_root
        } else {
            Hash32::ZERO
        };
        let made = mine(header(
            height,
            previous,
            clock,
            difficulty,
            work,
            // Commits to every header before it, which is the forest as it
            // stands right now.
            archive.commitment(),
            state_root,
        ));
        previous = made.id();
        forged.push(made);
        if height < tip_height {
            archive.add(header_leaf(&made.id()));
        }
    }

    let tip = *forged.last().unwrap();
    assert_eq!(tip.height, tip_height);
    assert_eq!(archive.forest().leaves(), tip.height, "history length");

    // ---- the weighing -------------------------------------------------
    let wanted = draw(seed_of(&tip), SAMPLES, work_before(&tip), tip.height);
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
    // The forger's best run up to the tip: the honest window under the header
    // the draw landed deepest on, then every one of its own.
    let deepest = samples
        .iter()
        .map(|sample| sample.header.height)
        .max()
        .unwrap();
    let from = usize::try_from(deepest.saturating_sub(DIFFICULTY_WINDOW as u64)).unwrap();
    let tail = forged[from..].to_vec();
    let start = SampledStart {
        tip,
        parent: Some(Sample {
            header: forged[usize::try_from(below).unwrap()],
            proof: archive.prove_in(below, tip.height).unwrap(),
        }),
        tail,
        history: archive.forest().roots_only(),
        samples,
    };
    let refused = check_start(&start, SAMPLES, NOW, &params);
    assert!(
        refused.is_err(),
        "AUDIT: the weighing took the forgery: {refused:?}"
    );
    eprintln!("  the weighing now refuses it: {refused:?}");
    let _ = honest_work;

    // ---- the handover -------------------------------------------------
    let anchor_index = usize::try_from(anchor_height).unwrap();
    let at = forged[anchor_index];
    let recent_from = anchor_index + 1 - RECENT_HEADERS;
    let recent = forged[recent_from..=anchor_index].to_vec();
    let buried = forged[anchor_index + 1..].to_vec();
    assert_eq!(u64::try_from(buried.len()).unwrap(), params.burial);

    // The forest as it stood before the anchor, which the anchor commits to.
    let mut before_at = Archive::new();
    for h in forged.iter().take(anchor_index) {
        before_at.add(header_leaf(&h.id()));
    }

    let mut handover = donor.handover(
        at,
        tip,
        archive.forest().roots_only(),
        archive.prove_in(anchor_height, tip.height).unwrap(),
        buried,
        recent,
    );
    // The ledger is the donor's; the headers under it are the forgery's.
    handover.headers = before_at.forest().roots_only();

    // The handover on its own would still take it, and that is worth being
    // explicit about rather than leaving as a gap somebody rediscovers.
    // `check_buried` seeds its retarget window from the headers the sender
    // supplies, so a run of the forger's own floor-difficulty headers demands
    // the floor right back. What stops the forgery is the weighing above,
    // which is the only gate anything from the network passes through: a node
    // asks for a ledger only from a peer whose tip it has just weighed. The
    // other caller of `accept` is a node reading its own ledger file back at
    // startup, and that file was written by this node from a chain it
    // validated itself.
    let taken = accept(&handover, &params);
    assert!(
        taken.is_ok(),
        "the handover alone does not catch it, which is why the weighing is \
         the gate and not a second opinion"
    );
    let burial_work: u128 = handover
        .buried
        .iter()
        .map(|h| u128::from(h.difficulty))
        .sum();
    assert_eq!(
        burial_work,
        u128::from(params.burial),
        "the whole burial was mined at the difficulty floor"
    );
    let _ = (donor_root, honest_work, honest_tip, anchor_height);
}

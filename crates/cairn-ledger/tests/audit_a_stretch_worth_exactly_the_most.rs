//! AUDIT: a stretch of chain worth exactly the most it could be worth.
//!
//! Between two headers whose place is established, `check_the_gaps` bounds the
//! work stated from both sides: at least what the steepest allowed descent
//! gives, at most what the steepest allowed climb does. The upper one is
//! `stated > most`, and `cargo mutants` could make it `>=` or `==` with the
//! whole suite green, which would refuse a chain stating exactly the most.
//!
//! An honest chain cannot state it. The retarget only answers the full
//! `MAX_RETARGET_FACTOR` when its window measured no time at all, and a
//! header dated at or before the median of its window is refused, so a chain
//! whose timeline stands still is not a chain. Accelerated to one second a
//! block over a hundred and eighty five blocks, the measured climb tops out
//! around one point six per block.
//!
//! A forger can. Below the run up to the tip nothing checks what the retarget
//! would have demanded: the samples are bounded and placed, and that is all.
//! So the chain here climbs by the full factor at every block, which is what
//! sits exactly on the bound, and what answers is the rule for the run at the
//! top rather than the bound underneath. Which of the two answers is the whole
//! of what this file is for.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::forest::ForestProof;
use cairn_accumulator::Archive;
use cairn_ledger::block::{BlockHeader, BLOCK_VERSION};
use cairn_ledger::pow::{meets_target, MAX_RETARGET_FACTOR, MIN_DIFFICULTY};
use cairn_ledger::sampling::{
    check_start, draw, levels_of, seed_of, work_before, Sample, SampledStart, StartError,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 24;
/// Enough that the draw has several places to land and the climb stays
/// mineable: the last block of this chain is asked for 4^9 hashes.
const BLOCKS: usize = 10;
/// Few enough that every drawn position is one this chain really spans.
const SAMPLES_ASKED: usize = 8;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// Finds a nonce for a header written by hand.
fn solve(mut candidate: BlockHeader) -> BlockHeader {
    for nonce in 0..ATTEMPTS {
        candidate.nonce = nonce;
        if meets_target(&candidate.id(), candidate.difficulty) {
            return candidate;
        }
    }
    panic!("no nonce at difficulty {}", candidate.difficulty);
}

/// A chain climbing by the full retarget factor at every block, linked and
/// committed the way a chain is, so that nothing but the numbers is wrong
/// with it.
fn climbing() -> (Vec<BlockHeader>, Archive) {
    let params = params();
    let mut headers: Vec<BlockHeader> = Vec::with_capacity(BLOCKS);
    let mut archive = Archive::new();
    let mut difficulty = MIN_DIFFICULTY;
    let mut total: u128 = 0;

    for height in 0..BLOCKS as u64 {
        if height > 0 {
            difficulty = u64::try_from(u128::from(difficulty) * MAX_RETARGET_FACTOR).unwrap();
        }
        total += u128::from(difficulty);
        let previous = headers.last().map_or(Hash32::ZERO, BlockHeader::id);
        let header = solve(BlockHeader {
            version: BLOCK_VERSION,
            network: params.network,
            height,
            previous,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::from_bytes([0xab; 32]),
            history: archive.forest().roots_only().commitment(),
            timestamp: 1_000 + height * params.target_block_time,
            difficulty,
            total_work: total,
            nonce: 0,
        });
        // Every header but the tip, which is not in its own history.
        if height + 1 < BLOCKS as u64 {
            archive.add(header_leaf(&header.id())).unwrap();
        }
        headers.push(header);
    }
    (headers, archive)
}

/// What a run of `blocks` blocks can be worth at most, starting from a header
/// of this difficulty: the climb, written out here rather than borrowed from
/// the crate, so the two are not the same arithmetic checked against itself.
fn most_over(difficulty: u64, blocks: u64) -> u128 {
    let mut most = 0u128;
    let mut carried = u128::from(difficulty);
    for _ in 0..blocks {
        carried *= MAX_RETARGET_FACTOR;
        most += carried;
    }
    most
}

#[test]
fn a_stretch_stating_exactly_the_most_is_not_refused_for_stating_too_much() {
    let (headers, archive) = climbing();
    let tip = *headers.last().unwrap();
    let last = headers.len() - 1;

    // The premise, said in numbers: every stretch of this chain states exactly
    // the most a stretch that long could be worth. A test whose chain sat
    // below the bound would pass whichever way the comparison went.
    for lower in 0..last {
        for upper in lower + 1..=last {
            assert_eq!(
                headers[upper].total_work - headers[lower].total_work,
                most_over(headers[lower].difficulty, (upper - lower) as u64),
                "the stretch from {lower} to {upper} is not on the bound"
            );
        }
    }

    let samples: Vec<Sample> = draw(
        seed_of(&tip),
        SAMPLES_ASKED,
        work_before(&tip),
        levels_of(&tip, &params()),
    )
    .into_iter()
    .map(|work| {
        let at = headers[..last]
            .iter()
            .position(|header| work_before(header) <= work && header.total_work > work)
            .unwrap_or_else(|| panic!("nothing spans work {work}"));
        Sample {
            header: headers[at],
            proof: archive.prove_in(at as u64, tip.height).unwrap(),
        }
    })
    .collect();

    let start = SampledStart {
        tip,
        tail: headers.clone(),
        parent: Some(Sample {
            header: headers[last - 1],
            proof: archive.prove_in(last as u64 - 1, tip.height).unwrap(),
        }),
        genesis: ForestProof::default(),
        history: archive.forest().roots_only(),
        samples,
    };

    // What answers is the run at the top, where every header is held to the
    // difficulty the retarget demands of it. The bound underneath has nothing
    // to say about a stretch sitting exactly on it.
    let refused = check_start(&start, SAMPLES_ASKED, NOW, &params());
    assert!(
        matches!(refused, Err(StartError::TailAtTheWrongDifficulty { .. })),
        "a chain climbing by the full factor is refused by the rule for the run \
         up to the tip, and it said {refused:?}"
    );
}

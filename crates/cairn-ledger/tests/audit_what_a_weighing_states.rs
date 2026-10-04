//! The four refusals of a weighing that no test had produced.
//!
//! `check_start` has twenty seven ways to refuse a weighing, and until this
//! file four of them were produced only by `examples/adversarial_placement.rs`,
//! which is a program and not a test: `OpeningWorthLessThanItCost`,
//! `WorkRunsBackwards` and `BlocksWorthMoreThanTheyCould`, which are the
//! stretches of chain between the headers a draw opened, and
//! `TailMissesWhatWasOpened`, which is the run up to the tip. A refusal
//! nothing produces can be deleted with every test green.
//!
//! The first three are about the totals headers state, which an honest chain
//! never gets wrong, so each is a chain made up for the purpose: headers at
//! the floor difficulty, dated on time, whose totals say what the refusal is
//! about, and a tip whose nonce is moved until the draw it seeds opens the
//! headers that show it. A total is a number the sender writes, and below the
//! highest header opened nothing but these checks reads it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use cairn_accumulator::forest::ForestProof;
use cairn_accumulator::Archive;
use cairn_ledger::block::{BlockHeader, BLOCK_VERSION};
use cairn_ledger::pow::{meets_target, MIN_DIFFICULTY};
use cairn_ledger::sampling::{
    check_start, draw, levels_of, seed_of, work_before, Sample, SampledStart, StartError, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::validation::{mine_header, ConsensusParams};
use cairn_primitives::Hash32;

const ATTEMPTS: u64 = 1 << 24;
/// How many tips are tried for one whose draw opens what a test needs.
const TIPS: u64 = 2_000;
const START: u64 = 1_000_000;
/// The spacing the retarget aims for on this network, so every header stays
/// at the floor difficulty it starts at.
const SPACING: u64 = 60;
/// Heights below the tip.
const LENGTH: u64 = 400;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// A chain of headers made up for a weighing, and the forest of everything
/// below its tip.
struct Chain {
    below: Vec<BlockHeader>,
    archive: Archive,
    tip: BlockHeader,
}

/// A chain whose header at each height states the difficulty and the total
/// `stated` gives it, linked and committed like any other.
fn made_up(stated: impl Fn(u64) -> (u64, u128)) -> Chain {
    let mut archive = Archive::new();
    let mut below: Vec<BlockHeader> = Vec::new();
    let header_at = |height: u64, archive: &Archive, below: &[BlockHeader]| {
        let (difficulty, total_work) = stated(height);
        mine_header(
            BlockHeader {
                version: BLOCK_VERSION,
                network: params().network,
                height,
                previous: below.last().map_or(Hash32::ZERO, BlockHeader::id),
                transactions_root: Hash32::ZERO,
                state_root: Hash32::ZERO,
                history: archive.forest().commitment(),
                timestamp: START + height * SPACING,
                difficulty,
                total_work,
                nonce: 0,
            },
            ATTEMPTS,
        )
        .expect("a nonce at this difficulty")
    };
    for height in 0..LENGTH {
        let header = header_at(height, &archive, &below);
        archive.add(header_leaf(&header.id())).unwrap();
        below.push(header);
    }
    let tip = header_at(LENGTH, &archive, &below);
    Chain {
        below,
        archive,
        tip,
    }
}

/// The weighing an archivist would make of `tip` on `chain`, or nothing when
/// the draw lands on work no header states.
fn weighing(chain: &Chain, tip: BlockHeader) -> Option<SampledStart> {
    let wanted = draw(
        seed_of(&tip),
        SAMPLES,
        work_before(&tip),
        levels_of(&tip, &params()),
    );
    let mut samples = Vec::with_capacity(wanted.len());
    for value in wanted {
        let found = *chain
            .below
            .iter()
            .find(|header| work_before(header) <= value && header.total_work > value)?;
        samples.push(Sample {
            header: found,
            proof: chain.archive.prove_in(found.height, tip.height).unwrap(),
        });
    }
    let pinned = samples.iter().map(|s| s.header.height).max().unwrap();
    let from =
        usize::try_from(pinned.saturating_sub(cairn_ledger::sampling::BELOW_THE_PINNED)).unwrap();
    let parent = tip.height - 1;
    let mut tail = chain.below[from..].to_vec();
    tail.push(tip);
    Some(SampledStart {
        tip,
        tail,
        parent: Some(Sample {
            header: chain.below[usize::try_from(parent).unwrap()],
            proof: chain.archive.prove_in(parent, tip.height).unwrap(),
        }),
        genesis: ForestProof::default(),
        history: chain.archive.forest().roots_only(),
        samples,
    })
}

/// The first tip, moving the nonce up, whose weighing `check_start` refuses
/// the way `named` picks out, with what it said.
fn refused_as(chain: &Chain, named: impl Fn(&StartError) -> bool) -> StartError {
    let mut tip = chain.tip;
    let now = tip.timestamp;
    let mut said = Vec::new();
    for _ in 0..TIPS {
        tip.nonce += 1;
        if !meets_target(&tip.id(), tip.difficulty) {
            continue;
        }
        let Some(start) = weighing(chain, tip) else {
            continue;
        };
        match check_start(&start, now, &params()) {
            Err(refused) if named(&refused) => return refused,
            other => said.push(other),
        }
    }
    said.dedup();
    panic!("no tip of {TIPS} had its weighing refused that way; they were answered {said:?}");
}

/// A chain whose every header states one unit less work than the blocks
/// under it are worth is refused at the lowest header opened.
///
/// Below the lowest header a draw opens, nothing is pinned but that each block
/// is a block, so a total under one unit a block is a chain claiming blocks it
/// never mined. Nothing produced the refusal, so a weighing that took such an
/// opening, or refused it for something else, passed.
#[test]
fn an_opening_that_states_less_work_than_its_blocks_is_refused() {
    let chain = made_up(|height| (MIN_DIFFICULTY, u128::from(height)));
    let refused = refused_as(&chain, |refused| {
        matches!(refused, StartError::OpeningWorthLessThanItCost { .. })
    });
    let StartError::OpeningWorthLessThanItCost { blocks, stated } = refused else {
        unreachable!()
    };
    assert_eq!(
        stated,
        blocks - 1,
        "the refusal names the wrong numbers: {refused:?}"
    );
}

/// A chain where one header states the total of a higher one, and that one
/// the total of the lower, is refused where the work runs backwards.
///
/// Two heights' totals swapped: each is still a total some header of this chain
/// states, and each still answers a draw, but between the lower one and the
/// next header opened above it the chain would have lost work. Nothing produced
/// the refusal, so a subtraction that wrapped round and was then compared
/// passed.
#[test]
fn work_that_runs_backwards_between_two_headers_opened_is_refused() {
    // Low in the chain, where the draw lands: it answers nothing from the top
    // of a chain this short. And three apart, because the retarget lets one
    // block be worth four at most, so a lower header claiming more than that
    // over its parent is refused for the climb before anything runs backwards.
    let (lower, higher) = (LENGTH / 4, LENGTH / 4 + 3);
    let chain = made_up(|height| {
        let stands_for = if height == lower {
            higher
        } else if height == higher {
            lower
        } else {
            height
        };
        (MIN_DIFFICULTY, u128::from(stands_for) + 1)
    });
    let refused = refused_as(&chain, |refused| {
        matches!(refused, StartError::WorkRunsBackwards { .. })
    });
    assert!(
        matches!(refused, StartError::WorkRunsBackwards { from, to } if from == lower && to > lower && to <= higher),
        "the refusal names the wrong heights: {refused:?}"
    );
}

/// A chain that states more work across a stretch than the retarget lets
/// that many blocks carry is refused for it.
///
/// One header at a real difficulty far above the floor, directly above headers
/// at the floor: the retarget lets a difficulty rise fourfold a block, so that
/// one block is worth more than any block there could be. Nothing produced the
/// refusal, so a weighing with no ceiling on a stretch passed.
#[test]
fn blocks_worth_more_than_the_retarget_lets_them_be_are_refused() {
    const STEEP: u64 = 4_096;
    let jump = LENGTH - 30;
    let chain = made_up(|height| {
        let honest = u128::from(height) + 1;
        match height.cmp(&jump) {
            std::cmp::Ordering::Less => (MIN_DIFFICULTY, honest),
            std::cmp::Ordering::Equal => (STEEP, honest + u128::from(STEEP) - 1),
            std::cmp::Ordering::Greater => (MIN_DIFFICULTY, honest + u128::from(STEEP) - 1),
        }
    });
    let refused = refused_as(&chain, |refused| {
        matches!(refused, StartError::BlocksWorthMoreThanTheyCould { .. })
    });
    assert!(
        matches!(refused, StartError::BlocksWorthMoreThanTheyCould { to, .. } if to == jump),
        "the refusal names the wrong stretch: {refused:?}"
    );
}

/// A run whose copy of the header the draw pinned is another header at that
/// height is refused for not carrying what was opened.
///
/// The same header with another nonce: the same parent, the same height, real
/// work at its own difficulty, and not the header the draw opened, so the run
/// up to the tip is not tied to the chain the samples were taken from. Nothing
/// produced the refusal, so a run that carried any header at that height
/// passed.
#[test]
fn a_run_that_does_not_carry_the_pinned_header_is_refused() {
    let chain = made_up(|height| (MIN_DIFFICULTY, u128::from(height) + 1));
    let start = weighing(&chain, chain.tip).expect("an honest chain answers every draw");
    let now = chain.tip.timestamp;
    check_start(&start, now, &params()).expect("an honest chain is weighed");

    let pinned = start.samples.iter().map(|s| s.header.height).max().unwrap();
    let at = start
        .tail
        .iter()
        .position(|header| header.height == pinned)
        .expect("the run carries the pinned height");
    let mut bent = start.clone();
    let original = bent.tail[at];
    let mut swapped = original;
    swapped.nonce = original.nonce + 1;
    while !meets_target(&swapped.id(), swapped.difficulty) {
        swapped.nonce += 1;
    }
    bent.tail[at] = swapped;

    assert_eq!(
        check_start(&bent, now, &params()),
        Err(StartError::TailMissesWhatWasOpened { at: pinned }),
        "a run carrying another header at the height the draw pinned was not refused \
         for it"
    );
}

/// A tip that does not carry the work its own difficulty states is refused
/// for that.
///
/// Asked before anything the tip names is read, so it is the cheapest refusal
/// a forger meets. The one test that reached it accepted it or a history of
/// the wrong length, and the two say different things, so a check that let a
/// tip without work through to the history passed.
#[test]
fn a_tip_without_the_work_it_states_is_refused_for_it() {
    let chain = made_up(|height| (MIN_DIFFICULTY, u128::from(height) + 1));
    let mut start = weighing(&chain, chain.tip).expect("an honest chain answers every draw");
    let mut tip = start.tip;
    tip.difficulty = 1 << 40;
    while meets_target(&tip.id(), tip.difficulty) {
        tip.nonce += 1;
    }
    start.tip = tip;
    assert_eq!(
        check_start(&start, tip.timestamp, &params()),
        Err(StartError::TipWithoutWork),
        "a tip that does not meet its own target was not refused for it"
    );
}

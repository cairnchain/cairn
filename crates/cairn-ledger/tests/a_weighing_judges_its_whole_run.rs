//! The run a weighing walks is judged from its second header on.
//!
//! `check_the_tail` used to apply the retarget and the work sum only above the
//! header the draw pinned. The ninety below it came along to seed the median
//! of the first header above, and the pinned header itself was judged by
//! nothing, though it is where `hardest` starts and so what `MOST_FALL` holds
//! the tip to. Since the retarget became ASERT a header's difficulty follows
//! from its parent and the network's first block alone, so every header from
//! the run's second on can be held to it, and now is.
//!
//! The chains here are headers alone, on rules whose first block carries
//! difficulty four, dated on their schedule so that the retarget asks four of
//! every header and mining one costs a few hashes. A header bent to difficulty
//! two is then a header the rules do not demand. Four and not the floor so that
//! a total one short of what it should be passes the least work a stretch can
//! carry, which at the floor is every block's own and leaves no room; what is
//! left to refuse it is the sum. Every chain is put back together above a bend
//! and the weighing drawn afresh from its new tip, so every identifier is
//! intact and the only thing wrong with the run is the one thing each test
//! bent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::{Archive, Forest};
use cairn_ledger::block::{BlockHeader, HeaderSummary};
use cairn_ledger::pow::{median_time_past, next_difficulty, work_of};
use cairn_ledger::sampling::{
    check_start, covering, draw, levels_of, open_start, seed_of, work_before, SampledStart,
    StartError, BELOW_THE_PINNED, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::validation::{mine_header, ConsensusParams};
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;

/// What the first block carries, and every header after it on schedule.
const OPENING: u64 = 4;

fn params() -> ConsensusParams {
    ConsensusParams {
        genesis_difficulty: OPENING,
        ..ConsensusParams::testnet()
    }
}

/// A chain of `count` headers, each dated where the schedule puts it, every
/// one at the difficulty the rules demand of it.
fn chain(count: u64) -> Vec<BlockHeader> {
    let params = params();
    let mut headers: Vec<BlockHeader> = Vec::new();
    let mut below = Forest::default();
    for height in 0..count {
        let header = BlockHeader {
            version: params.version_at(height),
            network: params.network,
            height,
            previous: headers.last().map_or(Hash32::ZERO, BlockHeader::id),
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: below.commitment(),
            timestamp: params.opens_at + params.target_block_time * height,
            difficulty: OPENING,
            total_work: u128::from(OPENING) * (u128::from(height) + 1),
            nonce: 0,
        };
        let header = mine_header(header, 1 << 20).unwrap();
        below.add(header_leaf(&header.id()));
        headers.push(header);
    }
    headers
}

/// Puts the chain back together from `from` up after a test changed the
/// header there: every header above names the one below, carries the
/// difficulty the rules demand of it, adds its own work to the total below,
/// and commits to the forest below it. The header at `from` keeps whatever
/// the test gave it and is only mined again.
fn rebuilt(headers: &mut [BlockHeader], from: usize) {
    let params = params();
    let mut below = Forest::default();
    for header in &headers[..from] {
        below.add(header_leaf(&header.id()));
    }
    for index in from..headers.len() {
        if index > from {
            let parent = headers[index - 1];
            let header = &mut headers[index];
            header.previous = parent.id();
            header.difficulty =
                next_difficulty(&parent.summary(), params.origin(), params.target_block_time);
            header.total_work = parent.total_work + work_of(header.difficulty);
            header.history = below.commitment();
        }
        headers[index] = mine_header(headers[index], 1 << 20).unwrap();
        below.add(header_leaf(&headers[index].id()));
    }
}

/// The deepest header the draw lands on for this chain's tip.
fn pinned(headers: &[BlockHeader]) -> u64 {
    let tip = *headers.last().unwrap();
    let ledger: Vec<(u64, u128, u64)> = headers
        .iter()
        .map(|header| (header.height, header.total_work, header.difficulty))
        .collect();
    let deepest = draw(
        seed_of(&tip),
        SAMPLES,
        work_before(&tip),
        levels_of(&tip, &params()),
    )
    .into_iter()
    .max()
    .unwrap();
    covering(&ledger, deepest).unwrap()
}

/// The weighing a peer that kept this chain would show.
fn showing(headers: &[BlockHeader]) -> SampledStart {
    let tip = *headers.last().unwrap();
    let mut archive = Archive::new();
    for header in &headers[..headers.len() - 1] {
        archive.add(header_leaf(&header.id()));
    }
    open_start(
        &tip,
        archive.forest().roots_only(),
        SAMPLES,
        &params(),
        |height| headers.get(usize::try_from(height).ok()?).copied(),
        |height| archive.prove(height),
    )
    .expect("a keeper answers its own draw")
}

/// Where a run starts: [`BELOW_THE_PINNED`] below the deepest header the
/// draw lands on, or at the first block.
fn run_starts(pinned: u64) -> u64 {
    pinned.saturating_sub(BELOW_THE_PINNED)
}

/// A chain long enough that its run starts above the first block, and one
/// short enough that its run starts at it. On chains this short the draw pins
/// about half way up, which the control below asserts rather than assumes.
const LONG: u64 = 400;
const SHORT: u64 = 100;

/// Bends one header with `bend`, puts the chain back together above it, and
/// shows the result, with every identifier in the run intact. Returns the
/// height bent and the showing.
///
/// Which header is chosen by where the draw pins, through `at`, and the draw
/// is made from the tip, which the bend changes: a bend that adds work moves
/// the pinned header by one. So the height is asked again of the bent chain
/// until the answer stops moving, and the bend sits where the test asked for
/// it against the pinned header of the chain that is actually shown.
fn bent(
    count: u64,
    at: impl Fn(u64) -> u64,
    bend: impl Fn(&mut BlockHeader, &BlockHeader),
) -> (u64, SampledStart) {
    let mut height = at(pinned(&chain(count)));
    for _ in 0..8 {
        let mut headers = chain(count);
        let index = usize::try_from(height).unwrap();
        let parent = headers[index - 1];
        bend(&mut headers[index], &parent);
        rebuilt(&mut headers, index);
        let wanted = at(pinned(&headers));
        if wanted == height {
            return (height, showing(&headers));
        }
        height = wanted;
    }
    panic!("the header to bend kept moving with the bend");
}

/// The control the refusals below are worth nothing without: both chains are
/// weighed as they stand, one with its run starting above the first block and
/// one with its run starting at it.
#[test]
fn the_chains_these_tests_bend_are_weighed_as_they_stand() {
    for (count, starts_at_the_first_block) in [(LONG, false), (SHORT, true)] {
        let headers = chain(count);
        let start = showing(&headers);
        assert_eq!(
            check_start(&start, NOW, &params()).map(|weighed| weighed.height),
            Ok(count - 1),
            "a chain of {count} headers at the difficulty its rules demand"
        );
        let first = start.tail[0].height;
        assert_eq!(first, run_starts(pinned(&headers)));
        assert_eq!(
            first == 0,
            starts_at_the_first_block,
            "a chain of {count} headers pinned at {}",
            pinned(&headers)
        );
    }
}

/// A header between the run's first and the pinned one, at a difficulty the
/// header below it does not demand, is refused by name: at the run's second
/// header, the first with a parent in the run, and further up.
///
/// Below the pinned header only the chaining and the version were asked, so a
/// run whose identifiers were intact was weighed whatever these headers said.
#[test]
fn a_header_below_the_pinned_one_at_the_wrong_difficulty_is_refused_by_name() {
    let second = |pinned: u64| run_starts(pinned) + 1;
    let between = |pinned: u64| (run_starts(pinned) + pinned) / 2;
    let just_below = |pinned: u64| pinned - 1;
    let places: [&dyn Fn(u64) -> u64; 3] = [&second, &between, &just_below];
    for (place, at) in places.into_iter().enumerate() {
        let (height, start) = bent(LONG, at, |header, parent| {
            header.difficulty = 2;
            header.total_work = parent.total_work + 2;
        });
        let pinned_at = start
            .samples
            .iter()
            .map(|sample| sample.header.height)
            .max()
            .unwrap();
        assert!(
            start.tail[0].height < height && height < pinned_at,
            "place {place}: {height} lies between the run's first header and the pinned one"
        );
        assert_eq!(
            check_start(&start, NOW, &params()),
            Err(StartError::TailAtTheWrongDifficulty {
                at: height,
                stated: 2,
                demanded: OPENING,
            }),
            "place {place}: a header at a difficulty its parent does not demand"
        );
        if place == 0 {
            assert_eq!(start.tail[1].height, height, "the run's second header");
        }
    }
}

/// The pinned header at a difficulty the header below it does not demand is
/// refused by name.
///
/// It is where `hardest` starts, the difficulty `MOST_FALL` holds the tip to,
/// and nothing judged it: the walk asked a header only when the one below it
/// stood at or above the pinned height.
#[test]
fn the_pinned_header_at_the_wrong_difficulty_is_refused_by_name() {
    let (height, start) = bent(
        LONG,
        |pinned| pinned,
        |header, parent| {
            header.difficulty = 2;
            header.total_work = parent.total_work + 2;
        },
    );
    let drawn = start
        .samples
        .iter()
        .map(|sample| sample.header.height)
        .max();
    assert_eq!(drawn, Some(height), "the bent header is the pinned one");

    assert_eq!(
        check_start(&start, NOW, &params()),
        Err(StartError::TailAtTheWrongDifficulty {
            at: height,
            stated: 2,
            demanded: OPENING,
        })
    );
}

/// A header below the pinned one whose total is not the one below it plus its
/// own work is refused by name, the chain above carrying the difference on.
#[test]
fn a_header_below_the_pinned_one_whose_work_does_not_add_up_is_refused_by_name() {
    let (height, start) = bent(
        LONG,
        |pinned| (run_starts(pinned) + pinned) / 2,
        |header, parent| header.total_work = parent.total_work + work_of(OPENING) - 1,
    );
    let pinned_at = start
        .samples
        .iter()
        .map(|sample| sample.header.height)
        .max()
        .unwrap();
    assert!(start.tail[0].height < height && height < pinned_at);

    assert_eq!(
        check_start(&start, NOW, &params()),
        Err(StartError::TailWorkDoesNotAddUp { at: height })
    );
}

/// The run's twelfth header, the first with the median's whole window below it
/// in a run that does not start at the first block, dated at that median, is
/// refused by name.
#[test]
fn a_header_below_the_pinned_one_dated_at_its_median_is_refused_where_the_run_holds_the_window() {
    let (height, start) = bent(
        LONG,
        |pinned| run_starts(pinned) + 11,
        |header, _| {
            let headers = chain(LONG);
            let below = usize::try_from(header.height).unwrap();
            let window: Vec<HeaderSummary> = headers[below - 11..below]
                .iter()
                .map(BlockHeader::summary)
                .collect();
            header.timestamp = median_time_past(&window).unwrap();
        },
    );
    assert_eq!(start.tail[11].height, height, "the run's twelfth header");
    assert_ne!(
        start.tail[0].height, 0,
        "in a run that does not start at the first block"
    );

    assert_eq!(
        check_start(&start, NOW, &params()),
        Err(StartError::TailOutOfTime { at: height })
    );
}

/// Below its twelfth header a run that does not start at the first block is
/// not judged against a median, and one that does start there is.
///
/// Below the twelfth header the run holds fewer headers than the eleven the
/// rule reads. Where it starts at the first block the shorter window is what
/// the rule read, since the chain had no more; anywhere else a median over
/// part of the window can stand above the real one and refuse an honest run.
/// Here the run's second header is dated five minutes late, inside what a
/// reader takes, and its third is back on time: under the eleven headers the
/// rule reads that third header clears the median, and over the two the run
/// holds below it, it does not.
#[test]
fn only_a_run_from_the_first_block_is_judged_before_its_twelfth_header() {
    let (_, late) = bent(
        LONG,
        |pinned| run_starts(pinned) + 1,
        |header, _| header.timestamp += 300,
    );
    assert_ne!(
        late.tail[0].height, 0,
        "a run that does not start at the first block"
    );
    assert!(
        late.tail[2].timestamp < late.tail[1].timestamp,
        "the run's timestamps do not rise below its twelfth header"
    );
    assert!(
        check_start(&late, NOW, &params()).is_ok(),
        "an honest run was judged against a median of fewer headers than the rule reads"
    );

    // From the first block the third header is judged, against the two
    // headers the chain then had.
    let (height, start) = bent(
        SHORT,
        |_| 2,
        |header, parent| header.timestamp = parent.timestamp,
    );
    assert_eq!(
        start.tail[0].height, 0,
        "this run starts at the first block"
    );
    assert_eq!(
        check_start(&start, NOW, &params()),
        Err(StartError::TailOutOfTime { at: height })
    );
}

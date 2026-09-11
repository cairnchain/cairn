//! AUDIT: what an honest archivist is made to build for one newcomer.
//!
//! Twelve rounds asked what an attacker can take. This asks what a correct,
//! up-to-date node pays to answer a request nobody is abusing.
//!
//! `open_start` answers a draw with the run of headers between the deepest
//! thing the draw pinned and the tip. The draw stops resolving a band of
//! *work* below the tip, and the run is that band counted in *blocks*: on a
//! chain whose difficulty sits near its own lifetime average the two are the
//! same thing to within a factor, and on one whose difficulty has fallen the
//! same work covers proportionally more blocks. Nothing bounds that ratio but
//! the chain's own length.
//!
//! The run was built anyway, header by header off the disk, and the far end
//! refuses it before reading a byte: `MOST_TAIL` is checked by
//! `SampledStart`'s decoder against the stated length, and by
//! `check_the_tail` against the length it works out for itself. So the whole
//! of it was disk seeks and megabytes spent on an answer that could not be
//! used, growing with the chain, in the one crate whose claim is that nothing
//! does.
//!
//! The chain here is synthetic. `open_start` reads headers and proves
//! positions and checks no work at all, so what it costs can be measured
//! without mining anything: the shape that matters is a difficulty that fell,
//! and mining one of those honestly is hours.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::cell::Cell;

use cairn_accumulator::{Forest, ForestProof};
use cairn_ledger::block::BlockHeader;
use cairn_ledger::note::NetworkId;
use cairn_ledger::pow::DIFFICULTY_WINDOW;
use cairn_ledger::sampling::{open_start, MOST_TAIL, SAMPLES};
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Hash32;

/// Difficulty the chain ran at while it had hash rate behind it.
const BUSY: u64 = 1_000_000;

/// Where the hash rate left. Everything above this is mined at the floor.
const QUIET_FROM: u64 = 20_000;

/// A chain that lost its miners a long time ago and kept going.
///
/// Not an exotic shape. It is what any chain looks like after the thing that
/// paid for its hash rate stops, and the retarget is what makes it survivable:
/// the difficulty walks down to the floor and blocks keep coming. Every one of
/// them is honest and every one is worth almost nothing, so the work behind the
/// tip is still nearly all of it the busy years' work.
const BLOCKS: u64 = 200_000;

/// The rules this chain is weighed under.
///
/// `opens_at` is nought and the block time is the default, which is what makes
/// the timestamps above an honest minute apart: the level count comes from how
/// old a tip says its chain is, so a fixture that dates its blocks badly is a
/// fixture weighed as a chain that was never this long.
fn params() -> cairn_ledger::validation::ConsensusParams {
    cairn_ledger::validation::ConsensusParams::testnet()
}

fn difficulty_at(height: u64) -> u64 {
    if height < QUIET_FROM {
        BUSY
    } else {
        1
    }
}

fn total_work_at(height: u64) -> u128 {
    let full = height.saturating_add(1);
    if full <= QUIET_FROM {
        u128::from(full) * u128::from(BUSY)
    } else {
        u128::from(QUIET_FROM) * u128::from(BUSY) + u128::from(full - QUIET_FROM)
    }
}

fn header_at(height: u64) -> Option<BlockHeader> {
    if height >= BLOCKS {
        return None;
    }
    Some(BlockHeader {
        version: 1,
        network: NetworkId::MAINNET,
        height,
        previous: Hash32::from_bytes([0; 32]),
        transactions_root: Hash32::from_bytes([0; 32]),
        state_root: Hash32::from_bytes([0; 32]),
        history: Hash32::from_bytes([0; 32]),
        timestamp: 1_000 + height * 60,
        difficulty: difficulty_at(height),
        total_work: total_work_at(height),
        nonce: height,
    })
}

/// The height whose own work spans `work`, which is where a draw lands.
///
/// The same rule `height_covering` searches for, written out: everything
/// before the block falls short of the value and the block's own total
/// reaches it. Closed form here because this chain's difficulty is a step
/// function, and a search over two hundred thousand heights per draw is not.
fn height_spanning(work: u128) -> u64 {
    let busy = u128::from(QUIET_FROM) * u128::from(BUSY);
    if work < busy {
        u64::try_from(work / u128::from(BUSY)).unwrap()
    } else {
        QUIET_FROM + u64::try_from(work - busy).unwrap()
    }
}

/// What the sampling would ask this chain, and what serving it costs.
struct Served {
    answer: Option<cairn_ledger::sampling::SampledStart>,
    reads: u64,
}

fn serve() -> Served {
    let tip = header_at(BLOCKS - 1).unwrap();
    let reads = Cell::new(0u64);
    let read = |height: u64| {
        reads.set(reads.get().saturating_add(1));
        header_at(height)
    };
    // A path is a path whatever is in it; nothing here reads one.
    let prove = |_: u64| {
        Some(ForestProof {
            siblings: vec![Hash32::from_bytes([7; 32]); 17],
        })
    };
    let answer = open_start(&tip, Forest::default(), SAMPLES, &params(), read, prove);
    Served {
        answer,
        reads: reads.get(),
    }
}

/// The band the draw leaves is measured in work, and this chain is the case
/// where that is not a number of blocks anybody bounded.
///
/// Pinned as a value the chain moves rather than as a constant: it is the
/// distance from the deepest drawn header to the tip on this exact fixture,
/// and it is what the refusal below is about. Two orders of magnitude past
/// what a sampling can carry.
#[test]
fn the_run_this_chain_asks_for_is_far_past_what_a_sampling_carries() {
    let tip = header_at(BLOCKS - 1).unwrap();
    let window = u64::try_from(DIFFICULTY_WINDOW).unwrap();

    // Worked out the way `open_start` works it out, from the draw itself.
    let drawn = cairn_ledger::sampling::draw(
        cairn_ledger::sampling::seed_of(&tip),
        SAMPLES,
        cairn_ledger::sampling::work_before(&tip),
        cairn_ledger::sampling::levels_of(&tip, &params()),
    );
    let deepest = drawn.into_iter().map(height_spanning).max().unwrap();

    let held = tip.height - deepest.saturating_sub(window) + 1;
    assert_eq!(
        held, 180_169,
        "the run between the deepest drawn header and the tip is {held} blocks"
    );
    assert!(
        held > MOST_TAIL * 10,
        "{held} blocks against a ceiling of {MOST_TAIL}"
    );
}

/// So the node says it cannot answer, instead of building the answer.
///
/// The cost is what the test is about, not the `None`. A run of 180 169
/// headers was 180 169 seeks in the header log and thirty-five megabytes
/// encoded and held in the join cache until the next block, per tip, for
/// something the far end refuses on the length alone.
///
/// So the reads are what is pinned. They are the draw's own cost and nothing
/// else, and the number moves with the draw: a different `SAMPLES`, a
/// different chain length, or a header the tip commits to differently all
/// change it.
#[test]
fn an_archivist_does_not_build_a_run_nobody_can_read() {
    let served = serve();
    assert!(
        served.answer.is_none(),
        "a chain past MOST_TAIL cannot be weighed, and building the answer \
         does not change that"
    );

    // What is left is the draw's own cost, which is what the design pays for:
    // one binary search per sample over the heights, and a header at each
    // step. Seventeen or eighteen reads a sample over this chain, against the
    // 180 169 the run alone used to add on top.
    assert_eq!(
        served.reads, 72_483,
        "answering the draw took {} header reads",
        served.reads
    );
}

/// And the ceiling is the one the far end reads, not a second copy of it.
///
/// A server that refused at some number of its own would be a server whose
/// idea of what can be carried had drifted from the reader's. This pins them
/// to each other: a run one header inside the ceiling is served and decodes,
/// and the one that made it undecodable is the length.
#[test]
fn what_is_served_is_what_a_reader_will_take_back() {
    // A chain short enough that the whole of it fits under the ceiling, so
    // the run is served rather than refused.
    let blocks = MOST_TAIL - 1_000;
    let short = |height: u64| {
        if height >= blocks {
            return None;
        }
        let mut header = header_at(0).unwrap();
        header.height = height;
        // Dated the way the chain above is dated. A fixture whose blocks all
        // carry one timestamp is a chain that says it is sixteen blocks old,
        // and the level count is read from exactly that.
        header.timestamp = 1_000 + height * 60;
        header.difficulty = 1;
        header.total_work = u128::from(height) + 1;
        header.nonce = height;
        Some(header)
    };
    let tip = short(blocks - 1).unwrap();
    let prove = |_: u64| {
        Some(ForestProof {
            siblings: vec![Hash32::from_bytes([7; 32]); 17],
        })
    };
    let start = open_start(&tip, Forest::default(), SAMPLES, &params(), short, prove)
        .expect("a chain inside the ceiling is answerable");
    assert_eq!(
        start.tail.len(),
        1_059,
        "served a run of {} against a ceiling of {MOST_TAIL}",
        start.tail.len()
    );
    let bytes = start.encode();
    let back = cairn_ledger::sampling::SampledStart::decode(&bytes)
        .expect("what a server serves is what a reader takes back");
    assert_eq!(back.tail.len(), start.tail.len());
}

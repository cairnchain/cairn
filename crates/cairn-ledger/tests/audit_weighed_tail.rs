//! AUDIT: the run up to a weighed tip, on a chain whose difficulty moves.
//!
//! `check_the_tail` applies the block rules to every header above the deepest
//! thing the draw pinned, because that is where a forger's cheap run would have
//! to live: below the pinned header there is no window to judge a difficulty
//! against, above it there is. Two of those rules had no test that reached
//! them, `TailAtTheWrongDifficulty` and `TailOutOfTime`, and the reason was the
//! same one that hid three defects elsewhere: every chain in this workspace
//! carried one difficulty from end to end, so the difficulty a header stated
//! and the difficulty its window demanded were the same number whatever a
//! fixture did to it.
//!
//! Here the chain is mined fast, then slow, then fast again, so the retarget is
//! moving on a hundred and nineteen of the tail's hundred and thirty nine
//! steps, and a header carrying the number its parent carried is a forgery the
//! rule can name. On this chain the draw pinned height 53, which leaves most of
//! the tail inside the part the rules are applied to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{BlockHeader, HeaderSummary};
use cairn_ledger::note::Note;
use cairn_ledger::pow::{median_time_past, meets_target, DIFFICULTY_WINDOW};
use cairn_ledger::sampling::{
    check_start, draw, seed_of, work_before, Sample, SampledStart, StartError, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 24;
const TARGET: u64 = 60;
const BURIAL: u64 = 8;

/// Seconds between blocks, in runs: steady, twice too fast, four times too
/// slow, twice too fast again.
///
/// The point of the runs is that the retarget is moving for almost the whole
/// chain, so the number a header states and the number its parent stated come
/// apart nearly everywhere, and a forgery that keeps its parent's is a forgery
/// the rule can see. Simulated rather than tried: this holds the difficulty
/// between about two thousand and twelve thousand, which is a chain a test can
/// mine in under half a second, where a long run at half the target climbs out
/// of reach.
const SCHEDULE: [(u64, usize); 4] = [
    (TARGET, 20),
    (TARGET / 2, 40),
    (TARGET * 4, 40),
    (TARGET / 2, 40),
];

/// The chain the whole file is built on.
const HEIGHT: usize = 140;

fn params() -> ConsensusParams {
    ConsensusParams::mineable_network(BURIAL)
}

/// One honest chain and the showing a peer would make of it.
struct Weighing {
    start: SampledStart,
    headers: Vec<BlockHeader>,
    /// The deepest header the draw landed on. Everything above it is judged in
    /// full by `check_the_tail`.
    pinned: u64,
}

fn honest() -> Weighing {
    let params = params();
    let miner = SecretKey::from_bytes(&[3; 32]);
    let mut state = LedgerState::new();
    let mut headers: Vec<BlockHeader> = Vec::new();
    let mut clock = 1_000u64;

    let spacings: Vec<u64> = SCHEDULE
        .iter()
        .flat_map(|(spacing, count)| std::iter::repeat_n(*spacing, *count))
        .collect();
    assert_eq!(spacings.len(), HEIGHT);
    for spacing in &spacings {
        let height = state.next_height().unwrap();
        clock += spacing;
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

    let tip = *headers.last().unwrap();
    let mut archive = Archive::new();
    for header in headers.iter().take(usize::try_from(tip.height).unwrap()) {
        archive.add(header_leaf(&header.id()));
    }

    let wanted = draw(seed_of(&tip), SAMPLES, work_before(&tip), tip.height);
    let samples: Vec<Sample> = wanted
        .iter()
        .map(|value| {
            let found = *headers
                .iter()
                .find(|header| {
                    let before = header.total_work - u128::from(header.difficulty);
                    before <= *value && header.total_work > *value
                })
                .unwrap_or_else(|| panic!("nothing spans work {value}"));
            Sample {
                header: found,
                proof: archive.prove_in(found.height, tip.height).unwrap(),
            }
        })
        .collect();
    let pinned = samples.iter().map(|s| s.header.height).max().unwrap();
    let from = usize::try_from(pinned.saturating_sub(DIFFICULTY_WINDOW as u64)).unwrap();
    let below = tip.height - 1;
    let start = SampledStart {
        tip,
        parent: Some(Sample {
            header: headers[usize::try_from(below).unwrap()],
            proof: archive.prove_in(below, tip.height).unwrap(),
        }),
        tail: headers[from..].to_vec(),
        history: archive.forest().roots_only(),
        samples,
    };
    Weighing {
        start,
        headers,
        pinned,
    }
}

/// Finds a nonce for a header the fixture changed.
fn solve(mut candidate: BlockHeader) -> BlockHeader {
    for nonce in 0..ATTEMPTS {
        candidate.nonce = nonce;
        if meets_target(&candidate.id(), candidate.difficulty) {
            return candidate;
        }
    }
    panic!("no nonce found at difficulty {}", candidate.difficulty);
}

/// Where in the tail a header can be changed and reach the rules in full.
///
/// Two conditions. It has to sit above the header the draw pinned, because
/// below that there is no window to judge a difficulty against and the rules
/// are deliberately not applied. And it must not be the tip, whose identifier
/// the draw itself is made from: changing that is refused for the samples
/// landing in the wrong place, long before the tail is read.
///
/// The deepest one that also carries a difficulty its parent did not, so that
/// putting the parent's number on it is a change. Where the draw lands is not
/// something a fixture chooses, so this is found rather than assumed, and the
/// assertion says what to do if a chain ever leaves nothing here.
fn changeable(weighing: &Weighing) -> usize {
    let tip = weighing.start.tip.height;
    let tail = &weighing.start.tail;
    (1..tail.len() - 1)
        .find(|index| {
            tail[*index].height > weighing.pinned
                && tail[*index].difficulty != tail[index - 1].difficulty
        })
        .unwrap_or_else(|| {
            panic!(
                "the draw pinned height {} on a chain of {tip} and nothing \
                 above it carries a difficulty its parent did not. Lengthen \
                 the runs in the schedule above",
                weighing.pinned
            )
        })
}

/// The control the refusals below are worth nothing without.
#[test]
fn the_chain_these_rules_mined_is_weighed_as_it_stands() {
    let weighing = honest();
    check_start(&weighing.start, SAMPLES, NOW, &params()).expect("its own rules weigh it");

    // And the tail really is a run of moving difficulties, or the mutations
    // below would be changing a number to itself.
    let tail = &weighing.start.tail;
    let moved = tail
        .windows(2)
        .filter(|pair| pair[0].difficulty != pair[1].difficulty)
        .count();
    println!(
        "a tail of {} headers, {moved} of them carrying a difficulty their \
         parent did not, running {}..={}; the draw pinned height {}",
        tail.len(),
        tail.iter().map(|h| h.difficulty).min().unwrap(),
        tail.iter().map(|h| h.difficulty).max().unwrap(),
        weighing.pinned
    );
    assert!(moved > tail.len() / 2);
}

/// A header of the tail carrying the difficulty its parent carried.
///
/// The whole of what a uniform chain produces, and a forgery here. It is
/// re-solved at the difficulty it claims, which is the lower of the two, so
/// what refuses it is the number and not a missing nonce.
#[test]
fn a_tail_header_that_keeps_its_parents_difficulty_is_refused() {
    let mut weighing = honest();
    let at = changeable(&weighing);
    let parent = weighing.start.tail[at - 1].difficulty;
    let stated = weighing.start.tail[at].difficulty;
    let height = weighing.start.tail[at].height;
    assert_ne!(parent, stated, "the change has to be a change");

    weighing.start.tail[at].difficulty = parent;
    weighing.start.tail[at].total_work =
        weighing.start.tail[at - 1].total_work + u128::from(parent);
    weighing.start.tail[at] = solve(weighing.start.tail[at]);

    let refused = check_start(&weighing.start, SAMPLES, NOW, &params());
    assert!(
        matches!(
            refused,
            Err(StartError::TailAtTheWrongDifficulty { at, stated: found, demanded })
                if at == height && found == parent && demanded == stated
        ),
        "a header carrying its parent's difficulty was weighed: {refused:?}"
    );
}

/// And a header of the tail dated back onto the median of its own window.
///
/// Unreachable before for the same reason: a run at the floor under a window
/// at the floor is refused for its difficulty first, wherever it is dated, so
/// nothing ever got as far as the line below it.
#[test]
fn a_tail_header_dated_before_the_median_of_its_window_is_refused() {
    let mut weighing = honest();
    let at = changeable(&weighing);
    let window: Vec<HeaderSummary> = weighing.start.tail[..at]
        .iter()
        .map(BlockHeader::summary)
        .collect();
    let median = median_time_past(&window).unwrap();
    assert!(
        weighing.start.tail[at].timestamp > median,
        "the honest header is past its own median, which is what makes moving \
         it onto the median a change"
    );

    let height = weighing.start.tail[at].height;
    weighing.start.tail[at].timestamp = median;
    weighing.start.tail[at] = solve(weighing.start.tail[at]);

    let refused = check_start(&weighing.start, SAMPLES, NOW, &params());
    assert!(
        matches!(
            refused,
            Err(StartError::TailOutOfTime { at }) if at == height
        ),
        "a header dated on the median of its own window was weighed: {refused:?}"
    );
    // The headers themselves are untouched, which is what makes this a fact
    // about the showing rather than about the chain.
    assert_eq!(weighing.headers.len(), HEIGHT);
}

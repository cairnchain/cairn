//! What a handover weighs, and the one state in which the answer is wrong.
//!
//! A handover carries the grace window and a path through the cold set for
//! every note in it. There is exactly one moment in a chain's life when that
//! part is empty: the block on which the hot set first reaches its capacity,
//! before anything has ever fallen out of it. Every block after that evicts,
//! and the window stays full for as long as the chain has traffic.
//!
//! `examples/joining.rs` measured that one moment. It filled the tier and
//! stopped, so the ledger figure it published, and the sentence beside it
//! saying the hot set is nearly all of a handover, described a state a live
//! chain is in once. The window and its paths are the larger half.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

use cairn_accumulator::forest::ForestProof;
use cairn_crypto::SecretKey;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::handover::Handover;
use cairn_ledger::note::Note;
use cairn_ledger::state::GRACE_BLOCKS;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const NOW: u64 = 4_000_000_000;
/// Small, so the tier fills and turns over inside a test.
const HOT: usize = 64;
/// What each block pays out, which is also what each block evicts once the
/// tier is full.
const PER_BLOCK: usize = 8;

/// The parts of a handover, each read off the same encoding the wire uses.
struct Parts {
    whole: usize,
    hot: usize,
    window: usize,
    paths: usize,
    notes_in_window: usize,
}

fn weigh(handover: &Handover) -> Parts {
    let whole = handover.encode().len();
    let hot = handover
        .hot
        .iter()
        .map(|(id, entry)| id.encode().len() + entry.note.encode().len() + 8)
        .sum::<usize>()
        + 4;
    let window = handover
        .grace
        .iter()
        .map(|block| {
            4 + block
                .iter()
                .map(|(id, _, note)| id.encode().len() + 8 + note.encode().len())
                .sum::<usize>()
        })
        .sum::<usize>()
        + 4;
    let paths = handover
        .grace_proofs
        .iter()
        .map(|(_, proof)| 8 + proof.size_in_bytes())
        .sum::<usize>()
        + 4;
    Parts {
        whole,
        hot,
        window,
        paths,
        notes_in_window: handover.grace.iter().flatten().count(),
    }
}

/// Mines a chain whose blocks each pay [`PER_BLOCK`] notes, keeping the ledger
/// and the headers at every height.
fn run(blocks: usize) -> (Vec<LedgerState>, Vec<BlockHeader>) {
    let params = ConsensusParams::testnet().with_hot_capacity(HOT);
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::archiving();
    let mut past = Vec::new();
    let mut headers = Vec::new();
    let mut clock = 1_000u64;

    let each = params.initial_reward.as_pebbles() / PER_BLOCK as u64;
    for _ in 0..blocks {
        let height = state.next_height().unwrap();
        clock += 600;
        let outputs: Vec<Note> = (0..PER_BLOCK)
            .map(|_| Note::new(Amount::from_pebbles(each).unwrap(), miner.public_key()))
            .collect();
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        past.push(state.clone());
        headers.push(block.header);
    }
    (past, headers)
}

fn handover_at(state: &LedgerState, headers: &[BlockHeader], height: usize) -> Handover {
    state
        .handover(
            headers[height],
            headers[height],
            state.headers_before_tip(),
            ForestProof {
                siblings: Vec::new(),
            },
            Vec::new(),
            vec![headers[height]],
        )
        .expect("every note in the window has a path")
}

/// A handover carries a path per note in the grace window, and those paths are
/// most of what it weighs.
///
/// Measured against the same hot set at two heights: the block the tier
/// filled on, where nothing has fallen, and a later one where the window holds
/// what the last sixty four blocks pushed out. The hot set is the same size in
/// both; the handover is not.
#[test]
fn the_grace_window_and_its_paths_are_most_of_a_handover() {
    let filled = HOT / PER_BLOCK;
    let later = filled + GRACE_BLOCKS;
    let (past, headers) = run(later + 1);

    let just_filled = &past[filled - 1];
    assert_eq!(just_filled.hot_len(), HOT, "the tier is full");
    assert_eq!(
        just_filled.cold_len(),
        0,
        "and nothing has fallen yet, which happens on exactly one block"
    );
    assert_eq!(just_filled.grace_len(), 0);

    let running = &past[later];
    assert_eq!(running.hot_len(), HOT, "the same tier, still full");
    assert_eq!(
        running.grace_len(),
        GRACE_BLOCKS * PER_BLOCK,
        "and a window holding what the last {GRACE_BLOCKS} blocks pushed out"
    );

    let empty = weigh(&handover_at(just_filled, &headers, filled - 1));
    let full = weigh(&handover_at(running, &headers, later));

    assert_eq!(empty.notes_in_window, 0);
    assert_eq!(full.notes_in_window, GRACE_BLOCKS * PER_BLOCK);
    assert_eq!(
        empty.hot, full.hot,
        "the hot set is the same, so the difference is the window and its paths"
    );
    println!(
        "just filled: {} B whole, {} B hot, {} B window, {} B paths",
        empty.whole, empty.hot, empty.window, empty.paths
    );
    println!(
        "running:     {} B whole, {} B hot, {} B window, {} B paths, {} notes",
        full.whole, full.hot, full.window, full.paths, full.notes_in_window
    );

    assert!(
        full.window + full.paths > full.hot,
        "the window and its paths came to {} B against {} B of hot set, so the \
         hot set really is nearly all of a handover and this test is the thing \
         that is wrong",
        full.window + full.paths,
        full.hot
    );
    assert!(
        full.whole > empty.whole * 2,
        "a handover from a running chain is {} B against {} B from one that has \
         never evicted: measuring the second publishes a figure for a state a \
         chain is in for one block",
        full.whole,
        empty.whole
    );
}

/// Every note in the window has a path, and nothing else does.
#[test]
fn a_handover_carries_exactly_one_path_per_note_in_the_window() {
    let (past, headers) = run(HOT / PER_BLOCK + GRACE_BLOCKS / 2);
    let last = past.len() - 1;
    let handover = handover_at(&past[last], &headers, last);
    assert_eq!(
        handover.grace_proofs.len(),
        handover.grace.iter().flatten().count(),
        "a note with no path is a note the receiver cannot spend the way the \
         window exists to allow"
    );
    for ((_, position, _), (at, _)) in handover
        .grace
        .iter()
        .flatten()
        .zip(handover.grace_proofs.iter())
    {
        assert_eq!(position, at, "the paths are in the window's own order");
    }
}

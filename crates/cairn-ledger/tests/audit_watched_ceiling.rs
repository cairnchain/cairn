//! Adversarial audit of the ceiling on the notes a node follows for a watched
//! owner.
//!
//! Read only. Nothing here changes a source file.
//!
//! The claims under test: a bounded amount is held however much dust is paid
//! in; the note let go of is the least valuable rather than the oldest; the
//! paths a node keeps stay bounded by the window plus the ceiling; and undoing
//! a block that trimmed puts back exactly what it took.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::{GRACE_NOTES, WATCHED_NOTES};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, disconnect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
/// Notes each block pays the followed owner.
const SPRAY: u64 = 255;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(16)
        .with_coinbase_maturity(0)
}

/// Everything the node holds for the owner it follows, as one string.
fn followed(state: &LedgerState) -> String {
    let mut out = String::new();
    for (id, position, note) in state.watched_notes() {
        let _ = writeln!(
            out,
            "{id:?} {position} {:?} {:?}",
            note.value,
            state.cold().proof_of(position)
        );
    }
    let _ = writeln!(out, "paths {}", state.watched_paths());
    out
}

/// Dust paid to a followed address buys a bounded amount of state, and what is
/// let go of when the ceiling bites is the cheapest note held.
#[test]
fn the_ceiling_holds_and_lets_go_of_the_cheapest() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(2);
    let mut state = LedgerState::new();
    state.watch_owner(alice.public_key());
    let mut source = LedgerState::archiving();

    // Every note ever paid to the followed owner, so what the node kept can be
    // compared against what it should have kept.
    let mut paid: BTreeMap<NoteId, (Amount, u64)> = BTreeMap::new();
    let mut coinbase_notes: Vec<(NoteId, Note)> = Vec::new();

    // Enough blocks that the ceiling is passed with room to spare.
    let rounds = (WATCHED_NOTES as u64 / SPRAY) + 6;
    for round in 0..rounds {
        let height = source.next_height().unwrap();
        let mut transfers = Vec::new();
        if let Some((id, note)) = coinbase_notes.pop() {
            // A spray of notes of every size, so the order the ceiling works
            // in is decided by value and not by when they arrived.
            let mut left = note.value.as_pebbles();
            let mut outputs = Vec::new();
            for index in 0..SPRAY {
                // Values that rise and fall across the block and across the
                // chain, so neither the oldest nor the newest is the cheapest.
                let value = 1 + ((index * 7919 + round * 104_729) % 4_096);
                if left <= value {
                    break;
                }
                left -= value;
                outputs.push(Note::new(
                    Amount::from_pebbles(value).unwrap(),
                    alice.public_key(),
                ));
            }
            outputs.push(Note::new(
                Amount::from_pebbles(left).unwrap(),
                alice.public_key(),
            ));
            let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
            transfer.sign_input(params.network, 0, &note, &miner);
            transfers.push(transfer);
        }

        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        let block = assemble_block(
            &source,
            coinbase,
            transfers,
            &params,
            1_000 + height * 600,
            0,
        )
        .unwrap();
        connect_block(&mut source, &block, &params, NOW).unwrap();

        let connected = connect_block(&mut state, &block, &params, NOW).unwrap();
        drop(connected);

        coinbase_notes.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(params.reward_at(height), miner.public_key()),
        ));
        for (id, position, note) in state.watched_notes() {
            paid.insert(id, (note.value, position));
        }

        assert!(
            state.watched_notes().count() <= WATCHED_NOTES,
            "block {round} left {} followed notes, past the ceiling of {WATCHED_NOTES}",
            state.watched_notes().count()
        );
        assert!(
            state.watched_paths() <= GRACE_NOTES + WATCHED_NOTES,
            "block {round} left {} paths, past the window plus the ceiling",
            state.watched_paths()
        );
    }

    let held = state.watched_notes().count();
    assert_eq!(held, WATCHED_NOTES, "the ceiling was never reached");

    // What it kept is the most valuable, by the total order the set is kept
    // in. Letting go of the cheapest one at a time keeps exactly the top of
    // that order, so this is an exact statement rather than an approximation.
    let mut ranked: Vec<(Amount, u64, NoteId)> = paid
        .iter()
        .map(|(id, (value, position))| (*value, *position, *id))
        .collect();
    ranked.sort_unstable();
    let cut = ranked.len() - WATCHED_NOTES;
    let kept: Vec<(Amount, u64, NoteId)> = {
        let mut all: Vec<(Amount, u64, NoteId)> = state
            .watched_notes()
            .map(|(id, position, note)| (note.value, position, id))
            .collect();
        all.sort_unstable();
        all
    };
    assert_eq!(
        kept,
        ranked[cut..].to_vec(),
        "the notes kept are not the most valuable ones"
    );
    println!(
        "followed {} notes in all, kept {held}, cheapest kept {:?}, dearest let go {:?}",
        ranked.len(),
        ranked[cut].0,
        ranked[cut - 1].0
    );
}

/// And undoing the block that trimmed puts back exactly what it took.
#[test]
fn an_undo_puts_back_the_notes_the_ceiling_let_go_of() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(2);
    let mut state = LedgerState::new();
    state.watch_owner(alice.public_key());
    let mut source = LedgerState::archiving();
    let mut coinbase_notes: Vec<(NoteId, Note)> = Vec::new();

    let rounds = (WATCHED_NOTES as u64 / SPRAY) + 4;
    let mut trimmed = 0usize;
    for round in 0..rounds {
        let height = source.next_height().unwrap();
        let mut transfers = Vec::new();
        if let Some((id, note)) = coinbase_notes.pop() {
            let mut left = note.value.as_pebbles();
            let mut outputs = Vec::new();
            for index in 0..SPRAY {
                let value = 1 + ((index * 7919 + round * 104_729) % 4_096);
                if left <= value {
                    break;
                }
                left -= value;
                outputs.push(Note::new(
                    Amount::from_pebbles(value).unwrap(),
                    alice.public_key(),
                ));
            }
            outputs.push(Note::new(
                Amount::from_pebbles(left).unwrap(),
                alice.public_key(),
            ));
            let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
            transfer.sign_input(params.network, 0, &note, &miner);
            transfers.push(transfer);
        }
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        let block = assemble_block(
            &source,
            coinbase,
            transfers,
            &params,
            1_000 + height * 600,
            0,
        )
        .unwrap();
        connect_block(&mut source, &block, &params, NOW).unwrap();

        let before = followed(&state);
        let root = state.state_root();
        let connected = connect_block(&mut state, &block, &params, NOW).unwrap();
        coinbase_notes.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(params.reward_at(height), miner.public_key()),
        ));

        // Undone and reapplied on every block, so the trimming one is covered
        // wherever it falls.
        disconnect_block(&mut state, &connected);
        assert_eq!(
            followed(&state),
            before,
            "block {round}: undoing left a different set of followed notes"
        );
        assert_eq!(state.state_root(), root, "block {round}: undo moved a root");
        let again = connect_block(&mut state, &block, &params, NOW).unwrap();
        drop(again);
        if state.watched_notes().count() == WATCHED_NOTES {
            trimmed += 1;
        }
    }
    assert!(trimmed > 0, "the ceiling never bit, so nothing was tested");
}

//! A node told to follow an address after the notes have already fallen.
//!
//! `watch_owner` takes up the fallen notes already sitting in the grace
//! window, because the node is holding a path for each of them anyway and
//! dropping it when the window ages past would strand the money. Those notes
//! belong to no block, so no undo record names them.
//!
//! That was read as harmless, on the grounds that the case it exists for is a
//! node handed a ledger it can undo nothing below. It is not: `watch_owner`
//! is what a wallet asks a *running* node for, and a reorganisation that
//! undoes the block one of those notes fell in reaches every one of them.
//!
//! What went wrong when it did. The note went back into the hot set and the
//! entry stayed, so the node answered "it fell at position seven" about a note
//! that was hot, and could produce no proof for a place the forest no longer
//! had. Then the branch that won landed the same note somewhere else, and the
//! order kept beside the map gained a second entry for it while the map gained
//! none. That order is what decides which followed note is let go of when the
//! ceiling bites, so the stray entry costs a note that is still followed; a
//! debug build stops on the length assertion in `commit` instead, which is a
//! node a wallet can halt by asking it to follow an address.
//!
//! So the property is the one a person would state: being told after the fact
//! lands in the same place as being told from the start, whatever the chain
//! does afterwards.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::HotEntry;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, disconnect_block, ConsensusParams};
use cairn_ledger::{Block, ConnectedBlock, LedgerState};

const NOW: u64 = 2_000_000_000;

/// Small enough that a note falls every block or two, so a run of a dozen
/// blocks fills the grace window with something worth following.
const HOT: usize = 4;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(HOT)
        .with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn candidate(
    state: &LedgerState,
    clock: &mut u64,
    miner: &SecretKey,
    transfers: Vec<Transfer>,
) -> Block {
    let params = params();
    let height = state.next_height().unwrap();
    *clock += 600;
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    assemble_block(state, coinbase, transfers, &params, *clock, 0).unwrap()
}

/// Every note the node says it follows, sorted, with where it says it fell.
fn followed(state: &LedgerState) -> Vec<(NoteId, u64)> {
    let mut held: Vec<(NoteId, u64)> = state
        .watched_notes()
        .map(|(id, position, _)| (id, position))
        .collect();
    held.sort_unstable();
    held
}

/// Notes it follows and cannot prove.
///
/// The release-visible half. A wallet asking where its note fell is answered
/// out of this map, and an answer the node cannot back with a path is an
/// answer about a note that is not there.
fn unprovable(state: &LedgerState) -> Vec<(NoteId, u64)> {
    state
        .watched_notes()
        .filter(|(id, position, note)| {
            !state.cold().proof_of(*position).is_some_and(|proof| {
                state
                    .cold()
                    .verify(*position, cairn_ledger::cold_leaf(id, note), &proof)
            })
        })
        .map(|(id, position, _)| (id, position))
        .collect()
}

#[test]
fn a_node_told_late_follows_what_a_node_told_from_the_start_follows() {
    let params = params();
    let miner = wallet(1);

    // Told after the run, so the back-fill in `watch_owner` is what puts the
    // notes in the map.
    let mut late = LedgerState::new();
    // Told before the first block, so every entry was put there by the block
    // that landed the note.
    let mut early = LedgerState::new();
    early.watch_owner(miner.public_key());

    let mut clock = 1_000u64;
    let mut late_undo: Vec<ConnectedBlock> = Vec::new();
    let mut early_undo: Vec<ConnectedBlock> = Vec::new();

    for _ in 0..12 {
        let block = candidate(&late, &mut clock, &miner, Vec::new());
        late_undo.push(connect_block(&mut late, &block, &params, NOW).unwrap());
        early_undo.push(connect_block(&mut early, &block, &params, NOW).unwrap());
    }
    late.watch_owner(miner.public_key());

    let fell = late.cold_len();
    assert!(
        fell >= 4,
        "only {fell} notes fell, so there is little to follow"
    );
    assert_eq!(
        followed(&late),
        followed(&early),
        "the two nodes do not start out following the same notes"
    );
    assert!(unprovable(&late).is_empty());
    assert!(unprovable(&early).is_empty());

    // Two blocks off both, which takes two of those notes back out of the cold
    // set and into the hot one.
    let before = late.next_cold_position();
    for _ in 0..2 {
        disconnect_block(&mut late, &late_undo.pop().unwrap());
        disconnect_block(&mut early, &early_undo.pop().unwrap());
    }
    assert!(
        late.next_cold_position() < before,
        "the undo took nothing back out of the cold set, so nothing is being tested"
    );
    assert_eq!(
        unprovable(&late),
        Vec::new(),
        "the node follows a note it cannot prove: it went back into the hot set \
         and the entry stayed behind"
    );
    assert_eq!(
        followed(&late),
        followed(&early),
        "undoing a block left the node told late following notes the node told \
         from the start does not"
    );

    // The branch that wins spends the note that would otherwise have fallen
    // first, so the eviction order shifts and the next note to fall takes a
    // place a different note had held.
    let mut by_age: Vec<(NoteId, HotEntry)> = early.hot_notes().collect();
    by_age.sort_unstable_by_key(|(id, entry)| (entry.height, *id));
    let (spend_id, spend_entry) = by_age[0];
    let mut transfer = Transfer::new(
        vec![Input::hot(spend_id)],
        vec![Note::new(spend_entry.note.value, wallet(3).public_key())],
    );
    transfer.sign_input(params.network, 0, &spend_entry.note, &miner);

    let block = candidate(&early, &mut clock, &miner, vec![transfer]);
    connect_block(&mut early, &block, &params, NOW).unwrap();
    // On the node told late this is where the map and the order beside it used
    // to come apart, which a debug build stops on.
    connect_block(&mut late, &block, &params, NOW).unwrap();

    assert_eq!(
        followed(&late),
        followed(&early),
        "the two nodes ended a reorganisation following different notes"
    );
    assert!(unprovable(&late).is_empty());
    assert!(unprovable(&early).is_empty());
    assert!(
        followed(&late).iter().any(|(_, at)| *at >= before - 2),
        "the winning branch landed nothing, so the second half of this proves nothing"
    );
}

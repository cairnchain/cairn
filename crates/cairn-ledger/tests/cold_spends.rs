//! Whether a cold note can be consumed twice.
//!
//! Validation accepts a proof taken up to `PROOF_WINDOW` blocks ago, which is
//! the whole point of that window: a spender who took one a few blocks back
//! has done nothing wrong. This asks what the application step does with it.

#![allow(
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::{cold_leaf, Block, LedgerState};
use cairn_primitives::codec::{Decode, Encode};

const NOW: u64 = 1_000_000_000;
const CAPACITY: usize = 8;

/// A reward is spendable at once here.
///
/// These tests all spend a coinbase shortly after mining it, and none of them
/// is about the wait that normally stands between the two. What the wait is
/// worth is audited in `audit_coinbase_maturity.rs`.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(CAPACITY)
        .with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn mine(
    state: &mut LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    transfers: Vec<Transfer>,
) -> Block {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block =
        assemble_block(state, coinbase, transfers, params, 1_000 + height * 600, 0).unwrap();
    connect_block(state, &block, params, NOW).unwrap();
    block
}

fn mine_empty(
    state: &mut LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    count: u64,
) -> Vec<(NoteId, Note)> {
    (0..count)
        .map(|_| {
            let block = mine(state, params, miner, Vec::new());
            (
                NoteId::new(block.coinbase.id(), 0),
                Note::new(params.initial_reward, miner.public_key()),
            )
        })
        .collect()
}

fn spend_cold(
    state: &mut LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    id: NoteId,
    note: Note,
    position: u64,
    proof: cairn_accumulator::ForestProof,
    owner: &SecretKey,
    to: &SecretKey,
) -> Result<(), String> {
    let mut transfer = Transfer::new(
        vec![Input::cold(id, note, position, proof)],
        vec![Note::new(note.value, to.public_key())],
    );
    transfer.sign_input(params.network, 0, &note, owner);
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block = assemble_block(
        state,
        coinbase,
        vec![transfer],
        params,
        1_000 + height * 600,
        0,
    )
    .map_err(|error| format!("{error:?}"))?;
    connect_block(state, &block, params, NOW)
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn a_cold_note_cannot_be_consumed_twice() {
    let params = params();
    let (miner, alice, bob) = (wallet(1), wallet(2), wallet(3));
    let mut state = LedgerState::archiving();

    let notes = mine_empty(&mut state, &params, &miner, 10);
    let (id0, note0) = notes[0];
    assert!(
        state.hot_note(&id0).is_none(),
        "notes[0] has fallen to cold"
    );

    let position = state
        .cold()
        .locate(&id0, &note0)
        .expect("it is in the cold set");
    let leaf0 = cold_leaf(&id0, &note0);
    let stale = state
        .cold()
        .prove(position)
        .expect("a proof at this moment");

    // The forest moves on, and the proof taken before it moved no longer
    // describes where the note sits.
    mine_empty(&mut state, &params, &miner, 6);
    assert!(
        !state.cold().verify(position, leaf0, &stale),
        "a proof is worth what it is worth now, and this one is not current"
    );

    // Offered anyway, it is refused rather than accepted and then quietly not
    // applied. That silence was the whole defect: the note stayed in the set
    // and paid a second person.
    let refused = spend_cold(
        &mut state, &params, &miner, id0, note0, position, stale, &miner, &alice,
    );
    assert!(refused.is_err(), "a stale proof does not buy anything");

    // Refreshed, the same spend goes through. Nothing about the transfer
    // changed but its witness, which is not part of what a transfer is.
    let before = state.cold().len();
    let fresh = state.cold().prove(position).expect("a current proof");
    spend_cold(
        &mut state, &params, &miner, id0, note0, position, fresh, &miner, &alice,
    )
    .expect("a current proof is accepted");

    // And the note is gone, which is the half that was missing.
    assert!(
        state.cold().locate(&id0, &note0).is_none(),
        "the note that was spent is out of the cold set (held {before} before)"
    );

    // So there is nothing left for Bob.
    let again = match state.cold().locate(&id0, &note0) {
        None => Err("nothing to spend".to_owned()),
        Some(position) => {
            let proof = state.cold().prove(position).expect("a current proof");
            spend_cold(
                &mut state, &params, &miner, id0, note0, position, proof, &miner, &bob,
            )
        }
    };
    assert!(again.is_err(), "one note, one spend");
}

/// A block spending a cold note reads back off the wire as it was written, and
/// the chain still takes it.
///
/// A cold input carries the note, its place and its path, and every cold spend
/// in the suite reached the next node as a value in memory. So a decoder that
/// refused every cold witness passed, which is a network where a note that has
/// fallen can be spent by nobody who has to send the spend to someone else.
#[test]
fn a_block_spending_a_cold_note_crosses_the_wire() {
    let params = params();
    let (miner, alice) = (wallet(1), wallet(2));
    let mut state = LedgerState::archiving();

    let notes = mine_empty(&mut state, &params, &miner, 10);
    let (id0, note0) = notes[0];
    let position = state
        .cold()
        .locate(&id0, &note0)
        .expect("it is in the cold set");
    let proof = state.cold().prove(position).expect("a current proof");

    let mut transfer = Transfer::new(
        vec![Input::cold(id0, note0, position, proof)],
        vec![Note::new(note0.value, alice.public_key())],
    );
    transfer.sign_input(params.network, 0, &note0, &miner);
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block = assemble_block(
        &state,
        coinbase,
        vec![transfer],
        &params,
        1_000 + height * 600,
        0,
    )
    .unwrap();

    let read = Block::decode(&block.encode()).expect("a block spending a cold note reads back");
    assert!(
        read == block,
        "a block spending a cold note read back as another block"
    );
    connect_block(&mut state, &read, &params, NOW).expect("and the chain takes it");
    assert!(
        state.cold().locate(&id0, &note0).is_none(),
        "the note it spent is out of the cold set"
    );
}

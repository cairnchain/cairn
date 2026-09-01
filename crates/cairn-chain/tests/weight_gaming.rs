//! Auditing the weight formula's claim that pushing a note out of the hot set
//! costs about what an ordinary payment costs, "however the pusher shapes the
//! transfer".
//!
//! The formula charges `max(0, outputs - inputs)` places. It credits every
//! input as if it freed a hot place. A note spent out of the grace window with
//! a plain `Witness::Hot` frees no hot place, having already fallen, yet is
//! cheap to encode and counts as an input. So a transfer that re-spends grace
//! notes and creates the same number of outputs is charged zero places while
//! evicting a note for every output.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

use cairn_chain::{fee_floor, transfer_weight};
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const NOW: u64 = 1_000_000_000;
const CAPACITY: usize = 8;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_hot_capacity(CAPACITY)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A full hot tier, with the miner's four oldest notes fallen into the grace
/// window. Returns the notes in creation order: `[0..4]` are in grace, `[4..]`
/// are still hot.
fn full_tier_with_grace(miner: &SecretKey) -> (LedgerState, ConsensusParams, Vec<(NoteId, Note)>) {
    let params = params();
    let mut state = LedgerState::archiving();
    let mut notes = Vec::new();
    for _ in 0..(CAPACITY + 4) {
        let height = state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &state,
            coinbase,
            Vec::new(),
            &params,
            1_000 + height * 600,
            0,
        )
        .unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        notes.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(params.initial_reward, miner.public_key()),
        ));
    }
    (state, params, notes)
}

/// How many hot notes a transfer of this shape pushes out of a full tier,
/// measured by the exact consensus function.
/// The inputs that resolve to notes still in the hot set, which is what the
/// node charges places against and what actually gives a place back.
fn freed_by(state: &LedgerState, transfer: &Transfer) -> BTreeSet<NoteId> {
    transfer
        .inputs
        .iter()
        .filter(|input| state.hot_note(&input.note_id).is_some())
        .map(|input| input.note_id)
        .collect()
}

fn evicted_by(state: &LedgerState, params: &ConsensusParams, transfer: &Transfer) -> usize {
    let spent_hot = freed_by(state, transfer);
    let created = transfer.created_notes();
    state
        .plan_evictions(&spent_hot, &created, params.hot_capacity)
        .len()
}

/// The claim under audit, from the doc comment on `NOTE_WEIGHT` and the commit
/// message: pushing a note out costs about what a payment costs, *however the
/// transfer is shaped* (measured discount 1.27). Two transfers, one ordinary
/// and one shaped to re-spend grace notes, are priced per note they evict. The
/// grace shape was the one door left open: its inputs cost a hundred bytes and
/// no proof, and they free nothing, so counting inputs as places charged it
/// for none of the notes it pushed out.
#[test]
fn grace_respends_pay_the_same_rate_per_eviction() {
    let miner = wallet(1);
    let payee = wallet(2);
    let (state, params, notes) = full_tier_with_grace(&miner);

    // The four oldest notes fell and are spendable without a proof.
    for (id, _) in &notes[0..4] {
        assert!(state.hot_note(id).is_none(), "it fell out of the hot set");
        assert!(state.within_grace(id).is_some(), "but is still in grace");
    }
    // The newest are still hot.
    assert!(state.hot_note(&notes[CAPACITY + 3].0).is_some());

    // An ordinary payment: one hot note in, payee and change out.
    let (hot_id, hot_note) = notes[CAPACITY + 3];
    let half = hot_note.value.as_pebbles() / 2;
    let mut ordinary = Transfer::new(
        vec![Input::hot(hot_id)],
        vec![
            Note::new(Amount::from_pebbles(half).unwrap(), payee.public_key()),
            Note::new(
                Amount::from_pebbles(hot_note.value.as_pebbles() - half - 1).unwrap(),
                miner.public_key(),
            ),
        ],
    );
    ordinary.sign_input(params.network, 0, &hot_note, &miner);

    // The grace re-spend: the four fallen notes back in, four notes out, netting
    // zero by the formula's count of inputs against outputs.
    let mut grace_inputs = Vec::new();
    let mut grace_outputs = Vec::new();
    for (id, note) in &notes[0..4] {
        grace_inputs.push(Input::hot(*id));
        grace_outputs.push(Note::new(
            Amount::from_pebbles(note.value.as_pebbles() - 1).unwrap(),
            miner.public_key(),
        ));
    }
    let mut grace = Transfer::new(grace_inputs, grace_outputs);
    for (index, (_, note)) in notes[0..4].iter().enumerate() {
        let at = u32::try_from(index).unwrap();
        grace.sign_input(params.network, at, note, &miner);
    }

    let ordinary_bytes = ordinary.encode().len();
    let grace_bytes = grace.encode().len();
    let ordinary_freed = freed_by(&state, &ordinary).len();
    let grace_freed = freed_by(&state, &grace).len();
    let ordinary_weight = transfer_weight(&ordinary, ordinary_bytes, ordinary_freed);
    let grace_weight = transfer_weight(&grace, grace_bytes, grace_freed);
    let ordinary_places = ordinary.outputs.len().saturating_sub(ordinary_freed);
    let grace_places = grace.outputs.len().saturating_sub(grace_freed);

    let ordinary_evicts = evicted_by(&state, &params, &ordinary);
    let grace_evicts = evicted_by(&state, &params, &grace);

    let ordinary_floor = fee_floor(ordinary_weight).as_pebbles();
    let grace_floor = fee_floor(grace_weight).as_pebbles();
    let ordinary_per = ordinary_floor / ordinary_evicts as u64;
    let grace_per = grace_floor / grace_evicts as u64;

    println!("ordinary: places charged {ordinary_places}, weight {ordinary_weight}, floor {ordinary_floor} pebbles, evicts {ordinary_evicts}, per-eviction {ordinary_per}");
    println!("grace   : places charged {grace_places}, weight {grace_weight}, floor {grace_floor} pebbles, evicts {grace_evicts}, per-eviction {grace_per}");

    // The grace re-spend really does push notes out of the hot set: one per
    // output, because it frees nothing.
    assert_eq!(grace_evicts, 4, "it evicts a note for every output");
    // And it is charged for every one of them, because none of its inputs was
    // still in the tier to give a place back.
    assert_eq!(grace_places, 4, "every output takes a place nothing freed");

    // The invariant the design claims: no shape is priced far below an ordinary
    // payment per note it evicts. A factor of two is already generous against
    // the measured 1.27.
    assert!(
        grace_per.saturating_mul(2) >= ordinary_per,
        "a grace re-spend evicts at {grace_per} pebbles/note against an ordinary payment's {ordinary_per}: the churn is underpriced by more than 2x, so the weight formula does not price eviction 'however the transfer is shaped'",
    );
}

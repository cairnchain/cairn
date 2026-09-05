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

/// The same door, one room along: the pool.
///
/// `accept_transfer` charges a transfer for the hot places it takes, counting
/// only the inputs that were still in the tier. That is a fact about the state
/// at the moment it arrived, and it was written down once and never asked
/// again. So the shape the test above prices correctly on arrival went on
/// being ranked at its arrival price for the whole grace window: pooled while
/// its notes were hot, and still ranked as if they were hot once they had
/// fallen and it was evicting one note per output.
///
/// A miner walks the pool from the best rate down, so the stale figure is not
/// bookkeeping: it decides what goes in the next block.
mod repricing {
    use std::sync::LazyLock;

    use cairn_chain::ChainStore;
    use cairn_crypto::SecretKey;
    use cairn_ledger::note::{Note, NoteId};
    use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
    use cairn_ledger::validation::{assemble_block, mine_block, ConsensusParams};
    use cairn_primitives::codec::Encode;
    use cairn_primitives::Amount;

    use super::{fee_floor, transfer_weight, wallet, CAPACITY, NOW};

    const ATTEMPTS: u64 = 1 << 20;

    /// Maturity off, so a coinbase note can be spent as soon as it lands and
    /// the tier can be churned in a handful of blocks.
    fn params() -> ConsensusParams {
        ConsensusParams::testnet()
            .with_hot_capacity(CAPACITY)
            .with_coinbase_maturity(0)
    }

    /// A chain with one note a block, so a fixed number of blocks pushes a
    /// known number of notes out of the tier.
    ///
    /// Mining is the slow part and the notes are the same every run, so the
    /// funded prefix is mined once for both tests.
    struct Funded {
        blocks: Vec<cairn_ledger::block::Block>,
        notes: Vec<(NoteId, Note)>,
    }

    static FUNDED: LazyLock<Funded> = LazyLock::new(|| {
        let params = params();
        let mut store = ChainStore::archiving(params);
        let mut blocks = Vec::new();
        let mut notes = Vec::new();
        let mut clock = 1_000_000u64;
        for _ in 0..CAPACITY {
            clock += 60;
            let (block, note) = mine_one(&mut store, &wallet(1), clock);
            notes.push(note);
            blocks.push(block);
        }
        Funded { blocks, notes }
    });

    fn funded() -> (ChainStore, Vec<(NoteId, Note)>, u64) {
        let mut store = ChainStore::archiving(params());
        for block in &FUNDED.blocks {
            store.add_block(block.clone(), NOW).unwrap();
        }
        (
            store,
            FUNDED.notes.clone(),
            1_000_000 + 60 * CAPACITY as u64,
        )
    }

    /// Mines one block paying `to` a single note.
    fn mine_one(
        store: &mut ChainStore,
        to: &SecretKey,
        clock: u64,
    ) -> (cairn_ledger::block::Block, (NoteId, Note)) {
        let params = *store.params();
        let height = store.state().next_height().unwrap();
        let note = Note::new(params.reward_at(height), to.public_key());
        let coinbase = CoinbaseTransaction::new(height, vec![note]);
        let block = assemble_block(
            store.state(),
            coinbase,
            Vec::<Transfer>::new(),
            &params,
            clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        let id = NoteId::new(block.coinbase.id(), 0);
        store.add_block(block.clone(), NOW).unwrap();
        (block, (id, note))
    }

    /// Spends `notes` back to their owner, leaving `fee` behind altogether.
    fn respend(
        params: &ConsensusParams,
        notes: &[(NoteId, Note)],
        owner: &SecretKey,
        fee: u64,
    ) -> Transfer {
        let each = fee / notes.len() as u64;
        let first = fee - each * (notes.len() as u64 - 1);
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for (index, (id, note)) in notes.iter().enumerate() {
            let taken = if index == 0 { first } else { each };
            inputs.push(Input::hot(*id));
            outputs.push(Note::new(
                Amount::from_pebbles(note.value.as_pebbles() - taken).unwrap(),
                owner.public_key(),
            ));
        }
        let mut transfer = Transfer::new(inputs, outputs);
        for (index, (_, note)) in notes.iter().enumerate() {
            transfer.sign_input(params.network, u32::try_from(index).unwrap(), note, owner);
        }
        transfer
    }

    /// What the same transfer weighs once its inputs have left the tier: the
    /// shape's honest price, which is what `prune_pool` has to charge it.
    fn weight_when_fallen(transfer: &Transfer) -> usize {
        transfer_weight(transfer, transfer.encode().len(), 0)
    }

    /// Pushes `count` notes out of the tier by paying somebody else.
    fn churn(store: &mut ChainStore, clock: &mut u64, count: usize) {
        for _ in 0..count {
            *clock += 60;
            mine_one(store, &wallet(9), *clock);
        }
    }

    /// A transfer paying exactly the floor for the places it took while its
    /// notes were hot pays a fifth of the floor for the places it takes once
    /// they have fallen. It used to go on waiting at the price it came in at.
    #[test]
    fn a_pooled_transfer_stops_paying_the_floor_when_its_notes_fall() {
        let miner = wallet(1);
        let (mut store, notes, mut clock) = funded();
        let params = params();

        let take = 4;
        let hot = respend(&params, &notes[0..take], &miner, 1);
        let hot_weight = transfer_weight(&hot, hot.encode().len(), take);
        let fallen_weight = weight_when_fallen(&hot);
        let fee = fee_floor(hot_weight).as_pebbles();

        let transfer = respend(&params, &notes[0..take], &miner, fee);
        let id = transfer.id();
        assert!(
            store.accept_transfer(transfer).unwrap(),
            "it pays the floor"
        );

        // Enough blocks paying somebody else to push all four out of the tier.
        churn(&mut store, &mut clock, take);

        println!(
            "weighed {hot_weight} hot and {fallen_weight} fallen; paid {fee} pebbles \
             against a floor of {} once fallen",
            fee_floor(fallen_weight).as_pebbles()
        );
        assert!(
            fee < fee_floor(fallen_weight).as_pebbles(),
            "the shape has to have become one the floor refuses"
        );
        assert!(
            store.pooled(&id).is_none(),
            "the pool went on holding, and offering to miners, a transfer that \
             pays {fee} pebbles where its shape now costs {}",
            fee_floor(fallen_weight).as_pebbles()
        );
    }

    /// And what the stale figure actually bought: a place at the front of the
    /// queue a miner walks.
    ///
    /// Two transfers, both valid, both paying the floor or better. The
    /// re-spend pays exactly what its fallen shape costs; the ordinary payment
    /// pays twice what its own shape costs. Priced honestly the payment is the
    /// better of the two and is picked first. Priced at what the re-spend was
    /// worth while its notes were hot, the re-spend wins by four to one.
    #[test]
    fn a_miner_picks_by_what_a_transfer_takes_now_rather_than_when_it_arrived() {
        let miner = wallet(1);
        let (mut store, notes, mut clock) = funded();
        let params = params();

        let take = 4;
        let probe = respend(&params, &notes[0..take], &miner, 1);
        let hot_weight = transfer_weight(&probe, probe.encode().len(), take);
        let fallen_weight = weight_when_fallen(&probe);
        let respend_fee = fee_floor(fallen_weight).as_pebbles();
        let stale = respend_fee * 65_536 / hot_weight as u64;
        let honest = respend_fee * 65_536 / fallen_weight as u64;

        let sneak = respend(&params, &notes[0..take], &miner, respend_fee);
        let sneak_id = sneak.id();
        assert!(store.accept_transfer(sneak).unwrap());

        // The four oldest fall; the newest four, including the one the
        // ordinary payment spends, stay in the tier.
        churn(&mut store, &mut clock, take);

        let (last_id, last_note) = notes[CAPACITY - 1];
        let probe = respend(&params, &[(last_id, last_note)], &miner, 1);
        let payment_weight = transfer_weight(&probe, probe.encode().len(), 1);
        let payment_fee = fee_floor(payment_weight).as_pebbles() * 2;
        let payment_rate = payment_fee * 65_536 / payment_weight as u64;
        let payment = respend(&params, &[(last_id, last_note)], &miner, payment_fee);
        let payment_id = payment.id();
        assert!(store.accept_transfer(payment).unwrap());

        println!("re-spend: {stale} stale, {honest} honest; payment: {payment_rate}");
        assert!(
            honest < payment_rate && payment_rate < stale,
            "the payment has to sit between the two prices for this to \
             distinguish them: {honest} < {payment_rate} < {stale}"
        );

        // One more block, which is what makes the pool reconsider what it
        // holds.
        churn(&mut store, &mut clock, 1);

        let (chosen, _) = store.selection(1);
        let picked = chosen.first().map(Transfer::id);
        assert_eq!(
            picked,
            Some(payment_id),
            "the miner reached for the re-spend first, at the rate it was \
             worth before its notes fell: {stale} against the payment's \
             {payment_rate}, where its honest rate is {honest}"
        );
        assert!(
            store.pooled(&sneak_id).is_some(),
            "and the re-spend is still pooled, since it does pay its fallen \
             floor: this is about the order, not about dropping it"
        );
    }
}

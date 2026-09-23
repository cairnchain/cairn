//! Transfers waiting for a block.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{
    fee_floor, must_make_room, pooled_cost, transfer_weight, ChainStore, MAX_POOLED,
    MAX_POOL_BYTES, MIN_FEE_PER_WEIGHT, NOTE_WEIGHT,
};
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer, MAX_COINBASE_EXTRA};
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, BlockError, ConsensusParams, TransferError,
};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::counting;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Comfortably past the floor of an ordinary spend, for tests about something
/// other than the floor itself.
const PLAIN_FEE: u64 = 10_000;

/// A reward is spendable at once here.
///
/// These tests all spend a coinbase shortly after mining it, and none of them
/// is about the wait that normally stands between the two. What the wait is
/// worth is audited in `cairn-ledger/tests/audit_coinbase_maturity.rs`.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// A chain of `count` blocks, and the coinbase note each one paid the miner.
fn funded(count: usize, miner: &SecretKey) -> (ChainStore, Vec<(NoteId, Note)>) {
    funded_under(params(), count, miner)
}

/// The same, under whatever rules the test needs.
fn funded_under(
    params: ConsensusParams,
    count: usize,
    miner: &SecretKey,
) -> (ChainStore, Vec<(NoteId, Note)>) {
    let mut ledger = LedgerState::new();
    let mut store = ChainStore::new(params);
    let mut clock = 1_000u64;
    let mut notes = Vec::new();

    for _ in 0..count {
        let height = ledger.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&ledger, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut ledger, &block, &params, NOW).unwrap();
        store.add_block(block.clone(), NOW).unwrap();
        notes.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(params.initial_reward, miner.public_key()),
        ));
    }
    (store, notes)
}

/// At least `count` spendable notes, paid out several to a block, so a test
/// can fill the pool without mining a block per transfer.
fn funded_widely(count: usize, miner: &SecretKey) -> (ChainStore, Vec<(NoteId, Note)>) {
    let params = params();
    let per_block = params.max_coinbase_outputs;
    let mut ledger = LedgerState::new();
    let mut store = ChainStore::new(params);
    let mut clock = 1_000u64;
    let mut notes = Vec::new();

    let each = params.initial_reward.as_pebbles() / per_block as u64;
    let first = params.initial_reward.as_pebbles() - each * (per_block as u64 - 1);

    while notes.len() < count {
        let outputs: Vec<Note> = (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(Amount::from_pebbles(value).unwrap(), miner.public_key())
            })
            .collect();

        let height = ledger.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(height, outputs.clone());
        let block =
            assemble_block(&ledger, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut ledger, &block, &params, NOW).unwrap();
        store.add_block(block.clone(), NOW).unwrap();

        for (index, note) in outputs.into_iter().enumerate() {
            let position = u32::try_from(index).unwrap();
            notes.push((NoteId::new(block.coinbase.id(), position), note));
        }
    }
    (store, notes)
}

/// Spends one note into `count` outputs, leaving `fee` behind.
fn splitting_spend(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    to: &SecretKey,
    count: usize,
    fee: Amount,
) -> Transfer {
    let shared = note.value.as_pebbles() - fee.as_pebbles();
    let each = shared / count as u64;
    let first = shared - each * (count as u64 - 1);
    let outputs: Vec<Note> = (0..count)
        .map(|index| {
            let value = if index == 0 { first } else { each };
            Note::new(Amount::from_pebbles(value).unwrap(), to.public_key())
        })
        .collect();
    let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

/// Spends one note into as many outputs as the rules allow, which is the
/// largest ordinary transfer there is.
fn wide_spend(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    to: &SecretKey,
    fee: Amount,
) -> Transfer {
    splitting_spend(
        params,
        id,
        note,
        owner,
        to,
        params.max_outputs_per_transfer,
        fee,
    )
}

/// Spends several notes into one, which is the shape that speaks for the most
/// notes per byte and so fills the pool's bookkeeping fastest.
fn gathering_spend(
    params: &ConsensusParams,
    notes: &[(NoteId, Note)],
    owner: &SecretKey,
    to: &SecretKey,
    fee: Amount,
) -> Transfer {
    let total: u64 = notes.iter().map(|(_, note)| note.value.as_pebbles()).sum();
    let paid = total - fee.as_pebbles();
    let inputs: Vec<Input> = notes.iter().map(|(id, _)| Input::hot(*id)).collect();
    let mut transfer = Transfer::new(inputs, vec![Note::new(pebbles(paid), to.public_key())]);
    for (index, (_, note)) in notes.iter().enumerate() {
        let at = u32::try_from(index).unwrap();
        transfer.sign_input(params.network, at, note, owner);
    }
    transfer
}

/// Spends one note, paying `to` and leaving the rest as a fee.
fn spend(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    to: &SecretKey,
    fee: Amount,
) -> Transfer {
    let paid = note.value.checked_sub(fee).unwrap();
    let mut transfer = Transfer::new(vec![Input::hot(id)], vec![Note::new(paid, to.public_key())]);
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

#[test]
fn a_valid_transfer_is_taken_once() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(3, &miner);

    let transfer = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        pebbles(PLAIN_FEE),
    );
    assert_eq!(store.accept_transfer(transfer.clone()), Ok(true));
    assert_eq!(store.pool_len(), 1);
    assert_eq!(
        store.accept_transfer(transfer.clone()),
        Ok(false),
        "already held"
    );
    assert_eq!(store.pool_len(), 1);
    assert_eq!(store.pooled(&transfer.id()), Some(&transfer));
}

/// A spend of a reward that has not matured never reaches the pool either.
///
/// The pool is the same rules asked one block early, so a transfer that no
/// block could carry is refused here rather than waiting for one that will
/// never come. Whoever sent it is told why, and can send it again once the
/// wait is over: a transfer's identity does not include its witness, so it is
/// the same transfer offered again.
#[test]
fn a_spend_of_a_reward_that_has_not_matured_never_reaches_the_pool() {
    let waiting = ConsensusParams::testnet().with_coinbase_maturity(8);
    let miner = wallet(1);
    let (mut store, notes) = funded_under(waiting, 3, &miner);

    let early = spend(
        &waiting,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        pebbles(PLAIN_FEE),
    );
    assert!(
        matches!(
            store.accept_transfer(early.clone()),
            Err(TransferError::ImmatureCoinbase { matures_at: 8, .. })
        ),
        "the pool held a transfer no block could carry"
    );
    assert_eq!(store.pool_len(), 0);

    // The same transfer, once the wait is over, is taken.
    let (mut store, _) = funded_under(waiting, 9, &miner);
    assert_eq!(store.accept_transfer(early), Ok(true));
    assert_eq!(store.pool_len(), 1);
}

#[test]
fn a_transfer_the_chain_would_refuse_never_reaches_the_pool() {
    let params = params();
    let miner = wallet(1);
    let thief = wallet(9);
    let (mut store, notes) = funded(3, &miner);

    let stolen = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &thief,
        &thief,
        Amount::ZERO,
    );
    assert!(matches!(
        store.accept_transfer(stolen),
        Err(TransferError::InvalidSignature { .. })
    ));

    let invented = spend(
        &params,
        NoteId::new(notes[0].0.source, 7),
        notes[0].1,
        &miner,
        &wallet(2),
        Amount::ZERO,
    );
    assert!(store.accept_transfer(invented).is_err());
    assert_eq!(store.pool_len(), 0);
}

#[test]
fn two_transfers_spending_the_same_note_cannot_both_wait() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(3, &miner);

    let first = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        pebbles(PLAIN_FEE),
    );
    let second = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(3),
        pebbles(PLAIN_FEE),
    );

    assert_eq!(store.accept_transfer(first), Ok(true));
    assert!(matches!(
        store.accept_transfer(second),
        Err(TransferError::UnknownNote(_))
    ));
    assert_eq!(store.pool_len(), 1);
}

#[test]
fn a_selection_fits_together_and_carries_its_fees() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(5, &miner);

    let fee = Amount::from_cairn("0.5").unwrap();
    for (id, note) in notes.iter().take(3) {
        let transfer = spend(&params, *id, *note, &miner, &wallet(2), fee);
        assert_eq!(store.accept_transfer(transfer), Ok(true));
    }

    let (chosen, fees) = store.selection(10);
    assert_eq!(chosen.len(), 3);
    assert_eq!(fees, Amount::from_cairn("1.5").unwrap());

    let (fewer, _) = store.selection(2);
    assert_eq!(fewer.len(), 2, "the limit is respected");
}

#[test]
fn the_selection_is_the_same_on_every_node() {
    let params = params();
    let miner = wallet(1);
    let (mut forward, notes) = funded(5, &miner);
    let (mut backward, _) = funded(5, &miner);

    let transfers: Vec<Transfer> = notes
        .iter()
        .take(4)
        .map(|(id, note)| spend(&params, *id, *note, &miner, &wallet(2), pebbles(PLAIN_FEE)))
        .collect();

    for transfer in &transfers {
        forward.accept_transfer(transfer.clone()).unwrap();
    }
    for transfer in transfers.iter().rev() {
        backward.accept_transfer(transfer.clone()).unwrap();
    }

    let (left, _) = forward.selection(10);
    let (right, _) = backward.selection(10);
    assert_eq!(
        left, right,
        "arrival order must not decide what a block holds"
    );
}

#[test]
fn a_block_clears_what_it_carried_out_of_the_pool() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(4, &miner);

    let carried = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        pebbles(PLAIN_FEE),
    );
    let left_behind = spend(
        &params,
        notes[1].0,
        notes[1].1,
        &miner,
        &wallet(3),
        pebbles(PLAIN_FEE),
    );
    store.accept_transfer(carried.clone()).unwrap();
    store.accept_transfer(left_behind.clone()).unwrap();
    assert_eq!(store.pool_len(), 2);

    // Mine a block carrying only the first of them.
    let mut ledger = store.state().clone();
    let height = ledger.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block =
        assemble_block(&ledger, coinbase, vec![carried.clone()], &params, 5_000, 0).unwrap();
    let block = mine_block(block, ATTEMPTS).unwrap();
    connect_block(&mut ledger, &block, &params, NOW).unwrap();

    store.add_block(block, NOW).unwrap();

    assert_eq!(store.pooled(&carried.id()), None, "it is in a block now");
    assert_eq!(
        store.pooled(&left_behind.id()),
        Some(&left_behind),
        "this one still waits"
    );
    assert_eq!(store.pool_len(), 1);
}

/// A full pool that refuses everything is a pool anyone can close.
///
/// Filling it costs an attacker the floor on every place: transfers spending
/// notes back to itself, paying the least the pool will carry. Everyone who
/// wants to send anything is then behind them, for as long as the attacker
/// cares to keep it up. So the ceiling holds, and a transfer paying a better
/// rate than the least the pool already carries takes that one's place.
#[test]
fn a_full_pool_makes_room_for_whoever_pays_more() {
    let params = params();
    let attacker = wallet(1);
    let (mut store, notes) = funded_widely(MAX_POOLED + 2, &attacker);

    for (id, note) in notes.iter().take(MAX_POOLED) {
        let transfer = spend(
            &params,
            *id,
            *note,
            &attacker,
            &wallet(2),
            pebbles(PLAIN_FEE),
        );
        assert!(store.accept_transfer(transfer).unwrap());
    }
    assert_eq!(store.pool_len(), MAX_POOLED, "the ceiling is reached");

    // Another paying the same rate has nothing to offer and is turned away.
    let (id, note) = notes[MAX_POOLED];
    let matching = spend(&params, id, note, &attacker, &wallet(2), pebbles(PLAIN_FEE));
    assert!(
        !store.accept_transfer(matching).unwrap(),
        "nothing to displace"
    );
    assert_eq!(store.pool_len(), MAX_POOLED);

    // One that pays more gets in, and the pool stays at its ceiling.
    let (id, note) = notes[MAX_POOLED + 1];
    let paying = spend(
        &params,
        id,
        note,
        &attacker,
        &wallet(2),
        pebbles(PLAIN_FEE * 2),
    );
    let wanted = paying.id();
    assert!(store.accept_transfer(paying).unwrap(), "it pays more");
    assert_eq!(store.pool_len(), MAX_POOLED, "and took a place, not a seat");
    assert!(store.pooled(&wanted).is_some());
}

/// A fee that buys nothing is a fee nobody pays.
#[test]
fn a_miner_takes_the_best_paying_transfers_first() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded_widely(8, &miner);

    // Fees rising with the index, admitted in the opposite order so that no
    // ordering by arrival could produce this answer by accident.
    let mut expected: Vec<(u64, cairn_primitives::Hash32)> = Vec::new();
    for (index, (id, note)) in notes.iter().take(8).enumerate().rev() {
        let fee = (index as u64 + 1) * PLAIN_FEE;
        let transfer = spend(
            &params,
            *id,
            *note,
            &miner,
            &wallet(2),
            Amount::from_pebbles(fee).unwrap(),
        );
        expected.push((fee, transfer.id()));
        assert!(store.accept_transfer(transfer).unwrap());
    }
    expected.sort_by(|left, right| right.0.cmp(&left.0));

    let (chosen, fees) = store.selection(3);
    assert_eq!(chosen.len(), 3);
    let taken: Vec<cairn_primitives::Hash32> = chosen.iter().map(Transfer::id).collect();
    let best: Vec<cairn_primitives::Hash32> = expected.iter().take(3).map(|(_, id)| *id).collect();
    assert_eq!(taken, best, "the three best paying, in that order");
    let owed: u64 = expected.iter().take(3).map(|(fee, _)| fee).sum();
    assert_eq!(fees, Amount::from_pebbles(owed).unwrap());

    // And the whole pool still fits in a block that has room for it.
    let (all, _) = store.selection(64);
    assert_eq!(all.len(), 8);
}

/// A pool is bounded by what it weighs, not only by what it counts.
///
/// One transfer spending notes out of the cold set carries a proof for each,
/// and the rules allow two hundred and fifty six of them: half a megabyte in
/// a single transfer. Four thousand of those is two gigabytes of memory handed
/// to whoever cared to send them, without a rule being broken.
#[test]
fn the_pool_is_bounded_by_weight_as_well_as_by_count() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded_widely(64, &miner);

    // Transfers as large as the rules allow, which is what an attacker sends.
    let mut taken = 0usize;
    for (id, note) in &notes {
        let transfer = wide_spend(&params, *id, *note, &miner, &wallet(2), pebbles(2_000_000));
        if store.accept_transfer(transfer).is_err() {
            break;
        }
        taken = taken.saturating_add(1);
    }

    assert!(taken > 0, "some were taken");
    assert!(
        store.pool_bytes() <= MAX_POOL_BYTES,
        "the pool holds {} bytes, over the {MAX_POOL_BYTES} it may",
        store.pool_bytes()
    );
    assert!(
        store.pool_len() < MAX_POOLED,
        "and it filled up on weight long before it filled up on count"
    );
}

/// The ceiling counts what holding a transfer costs, not what arrived.
///
/// `MAX_POOL_BYTES` is a bound on memory: its own note says four thousand
/// proof-carrying transfers is two gigabytes handed to whoever cared to send
/// them. What was counted against it was the wire form, which is not what a
/// pooled transfer takes. Three maps hold it, the pool itself and the rate
/// index and a row in `pool_spenders` for every note it speaks for, and none
/// of that was charged. It is the same mistake the block table's ceiling made
/// before `HELD_OVERHEAD`, and `audit_fee_market.rs` measures what it came to:
/// a full pool weighs a little over half the ceiling it fills.
///
/// Filled here with the shape that drags in the most bookkeeping per byte,
/// which is the one that is all inputs, since a note spoken for is a row of
/// its own.
///
/// The second half is the one that keeps the correction from going too far.
/// The pool has two questions and they have two answers: what a transfer pays
/// is asked of what it would take in a block, which is the wire form, and
/// answering it with the holding cost would price this node's own bookkeeping
/// into the rules. So the fee stays on the wire, and this holds a transfer
/// that clears the floor on the wire form and would not clear it on the
/// holding cost.
#[test]
fn the_ceiling_counts_what_holding_costs_and_not_what_arrived() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded_widely(512, &miner);

    let per_transfer = 16;
    // One note held back from the filling, for the second half below.
    let (fill, spare) = notes.split_at(notes.len() - 1);

    let mut taken = 0usize;
    for group in fill.chunks(per_transfer) {
        if group.len() < per_transfer {
            break;
        }
        // Comfortably past the floor of sixteen inputs, which is asked of
        // their bytes and so rises with the count.
        let fee = pebbles(PLAIN_FEE * per_transfer as u64 * 4);
        let transfer = gathering_spend(&params, group, &miner, &wallet(2), fee);
        match store.accept_transfer(transfer) {
            Ok(true) => taken += 1,
            other => {
                println!("stopped after {taken}: {other:?}");
                break;
            }
        }
    }
    assert!(taken > 0, "some were taken");

    // What the pool says it holds is what `pooled_cost` says of everything in
    // it. Every site that keeps this total has to agree, and each of them
    // used to read the wire form.
    let counted: usize = store
        .pooled_transfers()
        .map(|(_, transfer)| pooled_cost(transfer.encode().len(), transfer.inputs.len()))
        .sum();
    assert_eq!(
        store.pool_bytes(),
        counted,
        "the pool's total is the sum of what each one costs to hold"
    );

    // And that total is strictly above the wire forms, by at least the rows
    // the notes take. Without this the test above would still pass if
    // `pooled_cost` handed its argument straight back.
    let wire: usize = store
        .pooled_transfers()
        .map(|(_, transfer)| transfer.encode().len())
        .sum();
    let spoken_for: usize = store
        .pooled_transfers()
        .map(|(_, transfer)| transfer.inputs.len())
        .sum();
    assert!(
        store.pool_bytes() > wire + spoken_for * size_of::<NoteId>(),
        "holding {} costs more than the {wire} that arrived, by more than the \
         {spoken_for} notes it speaks for",
        store.pool_bytes()
    );

    // The fee is still asked of the wire form. This transfer clears the floor
    // on what a block would carry and does not clear it on what this node
    // pays to hold it, so it is accepted here and would be refused if the two
    // questions were answered by one number again.
    let (id, note) = spare[0];
    let wire = spend(&params, id, note, &miner, &wallet(3), pebbles(PLAIN_FEE))
        .encode()
        .len();
    let held = pooled_cost(wire, 1);
    let on_the_wire = fee_floor(transfer_weight(
        &spend(&params, id, note, &miner, &wallet(3), pebbles(PLAIN_FEE)),
        wire,
        1,
    ));
    let on_the_holding = fee_floor(transfer_weight(
        &spend(&params, id, note, &miner, &wallet(3), pebbles(PLAIN_FEE)),
        held,
        1,
    ));
    assert!(
        on_the_wire < on_the_holding,
        "the two floors differ, or this case proves nothing"
    );
    let just_enough = pebbles(on_the_wire.as_pebbles());
    let transfer = spend(&params, id, note, &miner, &wallet(3), just_enough);
    assert_eq!(
        store.accept_transfer(transfer),
        Ok(true),
        "a fee that clears the floor on the wire form is enough, and the \
         holding cost is not what the floor is asked of"
    );
}

/// Both ceilings are full at their own number, and the two differ by one.
///
/// `accept_transfer` counts the pool two ways before it decides what to drop.
/// The count is the pool without the arrival, so a pool already holding
/// `MAX_POOLED` has to drop one to take another. The bytes are the pool with
/// the arrival already added, so a pool landing exactly on `MAX_POOL_BYTES` is
/// full and not over. Two comparisons side by side, one `>=` and one `>`, and
/// the reason they differ is not visible at the line.
///
/// Held here rather than through a filled pool because four megabytes cannot
/// be landed on exactly by any pool a test can build: transfer sizes come in
/// steps of forty bytes and up, so the total steps over the ceiling rather
/// than onto it. The rule has a name so that the boundary can be asked
/// directly, which is the only way it gets asked at all.
#[test]
fn a_pool_is_full_at_its_ceiling_and_not_one_short_of_it() {
    assert!(
        !must_make_room(0, MAX_POOL_BYTES),
        "a pool landing exactly on the ceiling is full, not over: the total \
         already counts the arrival"
    );
    assert!(
        must_make_room(0, MAX_POOL_BYTES + 1),
        "and one byte past it has to make room"
    );

    assert!(
        !must_make_room(MAX_POOLED - 1, 0),
        "a pool one short of the count has room for the arrival"
    );
    assert!(
        must_make_room(MAX_POOLED, 0),
        "and a pool at the count has to drop one first, because this figure \
         does not count the arrival"
    );
}

/// A transfer no block can carry is turned away rather than kept waiting.
///
/// The pool holds what is waiting for a block. A transfer too large for any
/// block is not waiting for one, it is waiting for one that cannot be built,
/// and it would sit there until something displaced it while whoever sent it
/// believed it was on its way. The refusal is what tells them otherwise.
#[test]
fn a_transfer_too_large_for_a_block_is_refused_outright() {
    let mut params = params();
    // Small enough that an ordinary wide spend passes it, so this test builds
    // a transfer rather than a megabyte.
    params.max_block_bytes = 4096;
    let owner = wallet(1);
    let (store, notes) = funded_widely(2, &owner);

    let (id, note) = notes[0];
    let wide = wide_spend(&params, id, note, &owner, &wallet(2), pebbles(2_000_000));
    let bytes = cairn_primitives::codec::Encode::encode(&wide).len();
    assert!(
        bytes > params.max_block_bytes,
        "the transfer has to be over it"
    );

    // The store built by `funded_widely` carries the ordinary rules, so it is
    // rebuilt here with the tighter limit in force.
    let mut tight = ChainStore::new(params);
    for height in 0.. {
        match store.block_at(height) {
            Some(block) => tight.add_block(block.clone(), NOW).unwrap(),
            None => break,
        };
    }

    match tight.accept_transfer(wide) {
        Err(TransferError::TooLargeForABlock { bytes: got, limit }) => {
            assert_eq!(got, bytes);
            assert_eq!(
                limit,
                ChainStore::room_for_transfers(params.max_block_bytes),
                "the refusal has to name the room a block has, not the block"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(tight.pool_len(), 0, "and nothing was kept");

    // One that fits is taken as before.
    let (id, note) = notes[1];
    let ordinary = spend(&params, id, note, &owner, &wallet(2), pebbles(PLAIN_FEE));
    assert!(tight.accept_transfer(ordinary).unwrap());
}

/// A transfer exactly the size a block has room for is taken.
///
/// The bound refuses what no block could carry, and a transfer that fills the
/// room exactly is one a block carries. Read one place over it becomes the
/// opposite: the largest payment anyone can make turns into one nobody can
/// make, and the refusal names a limit the transfer meets.
///
/// Nothing stood on that edge. The test above builds a transfer past the
/// bound and one comfortably under it, so the comparison could be moved
/// without either of them noticing.
#[test]
fn a_transfer_exactly_the_size_a_block_has_room_for_is_taken() {
    let mut params = params();
    // Small enough that an ordinary wide spend passes it, so this test builds
    // a transfer rather than a megabyte.
    params.max_block_bytes = 4096;
    let owner = wallet(1);
    let (store, notes) = funded_widely(2, &owner);

    let (id, note) = notes[0];
    let wide = wide_spend(&params, id, note, &owner, &wallet(2), pebbles(2_000_000));
    let bytes = cairn_primitives::codec::Encode::encode(&wide).len();

    // Rules whose room for transfers is this transfer and not one byte more.
    // Taken from `room_for_transfers` rather than written down, so the two
    // cannot drift apart and leave this test standing on the wrong edge.
    let overhead = params.max_block_bytes - ChainStore::room_for_transfers(params.max_block_bytes);
    params.max_block_bytes = bytes + overhead;
    assert_eq!(
        ChainStore::room_for_transfers(params.max_block_bytes),
        bytes,
        "the rules have room for exactly this transfer"
    );

    let mut tight = ChainStore::new(params);
    for height in 0.. {
        match store.block_at(height) {
            Some(block) => tight.add_block(block.clone(), NOW).unwrap(),
            None => break,
        };
    }

    assert_eq!(
        tight.accept_transfer(wide),
        Ok(true),
        "a transfer that fills the room exactly is one a block can carry"
    );
    assert_eq!(tight.pool_len(), 1, "and it is waiting");
}

/// Nothing waits for a block for free any more.
///
/// Zero-fee transfers used to be pooled, and on a quiet chain they were also
/// mined, which made churning the hot set cost nothing exactly when notes stay
/// hot the longest. The refusal names the floor, so whoever set the fee learns
/// what to set instead.
#[test]
fn a_transfer_paying_less_than_the_floor_is_refused() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(3, &miner);

    let free = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        Amount::ZERO,
    );
    let floor = match store.accept_transfer(free) {
        Err(TransferError::FeeBelowFloor { fee, floor }) => {
            assert_eq!(fee, Amount::ZERO);
            floor
        }
        other => panic!("expected the floor to be named, got {other:?}"),
    };
    assert_eq!(store.pool_len(), 0, "and nothing was kept");

    // One pebble short is still short, and the floor itself is enough.
    let short_fee = floor.checked_sub(pebbles(1)).unwrap();
    let short = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        short_fee,
    );
    assert!(matches!(
        store.accept_transfer(short),
        Err(TransferError::FeeBelowFloor { .. })
    ));
    let exact = spend(&params, notes[1].0, notes[1].1, &miner, &wallet(2), floor);
    assert_eq!(store.accept_transfer(exact), Ok(true));
}

/// The floor charges for places in the hot set, not only for bytes.
///
/// Every note a transfer creates beyond what it spends pushes somebody's
/// oldest note out of a full tier. Charged by bytes alone, an output is forty
/// bytes against a payment's two hundred, and churning the tier was several
/// times cheaper than the traffic it displaced.
#[test]
fn a_transfer_that_creates_many_notes_pays_for_the_places_it_takes() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded_widely(2, &miner);

    let (id, note) = notes[0];
    let wide = wide_spend(&params, id, note, &miner, &wallet(2), pebbles(1));
    let bytes = wide.encode().len();
    let places = wide.outputs.len() - wide.inputs.len();

    let floor = match store.accept_transfer(wide) {
        Err(TransferError::FeeBelowFloor { floor, .. }) => floor,
        other => panic!("expected the floor to be named, got {other:?}"),
    };

    // The floor is the bytes and every place, priced at the same rate. Bytes
    // alone would ask several times less.
    let expected = (bytes + places * NOTE_WEIGHT) as u64 * MIN_FEE_PER_WEIGHT;
    assert_eq!(floor, pebbles(expected));
    assert!(
        floor.as_pebbles() > (bytes as u64) * MIN_FEE_PER_WEIGHT * 4,
        "the places outweigh the bytes for a transfer shaped like this"
    );

    // Paying for what it takes, the same shape is carried.
    let (id, note) = notes[1];
    let paid = wide_spend(&params, id, note, &miner, &wallet(2), pebbles(expected));
    assert_eq!(store.accept_transfer(paid), Ok(true));
}

/// A block is filled by what a transfer pays for what it takes, not by the
/// largest fee.
///
/// Ordered by the fee alone, one wide transfer paying a single large fee
/// outbid a block's worth of payments each paying more for their room, and
/// churning the hot set was bought at a discount.
#[test]
fn a_block_is_filled_by_rate_and_not_by_the_largest_fee() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded_widely(5, &miner);

    // Pays more than every payment below put together, and less per unit of
    // what it takes than any of them.
    let (id, note) = notes[0];
    let wide = wide_spend(&params, id, note, &miner, &wallet(2), pebbles(2_000_000));
    let wide_id = wide.id();
    assert_eq!(store.accept_transfer(wide), Ok(true));

    let mut payments = Vec::new();
    for (id, note) in notes.iter().skip(1) {
        let transfer = spend(&params, *id, *note, &miner, &wallet(2), pebbles(100_000));
        payments.push(transfer.id());
        assert_eq!(store.accept_transfer(transfer), Ok(true));
    }

    let (chosen, _) = store.selection(payments.len());
    let taken: Vec<cairn_primitives::Hash32> = chosen.iter().map(Transfer::id).collect();
    assert_eq!(taken.len(), payments.len());
    assert!(
        !taken.contains(&wide_id),
        "the largest fee lost to the better rates"
    );
    for wanted in &payments {
        assert!(taken.contains(wanted));
    }
}

/// A pooled spend is replaced by one that pays for everything it displaces,
/// and the floor again on top.
///
/// The extra floor is what bounds the churn: re-announcing a spend costs its
/// sender every time, so the network cannot be made to relay endless copies
/// of one payment for one fee.
#[test]
fn a_conflicting_transfer_replaces_what_it_pays_for() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(3, &miner);
    let (id, note) = notes[0];

    let first = spend(&params, id, note, &miner, &wallet(2), pebbles(PLAIN_FEE));
    let first_id = first.id();
    let floor = fee_floor(transfer_weight(
        &first,
        first.encode().len(),
        first.inputs.len(),
    ));
    assert_eq!(store.accept_transfer(first), Ok(true));

    // Pays more, and not enough more: what it displaces plus the floor is the
    // price of the place, and one pebble short of it changes nothing.
    let asked = PLAIN_FEE + floor.as_pebbles();
    let short = spend(&params, id, note, &miner, &wallet(3), pebbles(asked - 1));
    assert!(matches!(
        store.accept_transfer(short),
        Err(TransferError::UnknownNote(_))
    ));
    assert!(store.pooled(&first_id).is_some(), "the first still waits");

    let enough = spend(&params, id, note, &miner, &wallet(3), pebbles(asked));
    let enough_id = enough.id();
    assert_eq!(store.accept_transfer(enough), Ok(true));
    assert_eq!(store.pool_len(), 1, "a replacement, not a second spend");
    assert!(store.pooled(&first_id).is_none());
    assert!(store.pooled(&enough_id).is_some());
}

/// What a miner selects never builds a block the rules refuse for pushing too
/// many notes out of the hot set.
///
/// The cap is consensus, so a selection ignoring it would mine blocks nobody
/// accepts. What does not fit this block waits in the pool for the next one,
/// which is the queue doing exactly what it is for.
#[test]
fn a_selection_leaves_out_what_would_push_out_too_many_notes() {
    let params = params().with_hot_capacity(64).with_max_evictions(8);
    let miner = wallet(1);
    let (mut store, notes) = funded_under(params, 20, &miner);

    // Each spends one note into eight, taking seven places in the hot set.
    for (id, note) in notes.iter().take(8) {
        let transfer =
            splitting_spend(&params, *id, *note, &miner, &wallet(2), 8, pebbles(100_000));
        assert_eq!(store.accept_transfer(transfer), Ok(true));
    }
    assert_eq!(store.pool_len(), 8);

    let (chosen, _) = store.selection(100);
    assert!(
        chosen.len() < 8,
        "the selection had to leave some for a later block"
    );
    assert!(!chosen.is_empty(), "and it did not leave everything");

    // What was chosen makes a block every node accepts.
    let mut ledger = store.state().clone();
    let height = ledger.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block = assemble_block(&ledger, coinbase, chosen, &params, NOW, 0).unwrap();
    let block = mine_block(block, ATTEMPTS).unwrap();
    connect_block(&mut ledger, &block, &params, NOW).unwrap();

    // And everything at once would not have: the cap the selection respects
    // is a rule, not a preference.
    let everything: Vec<Transfer> = store
        .pooled_transfers()
        .map(|(_, transfer)| transfer.clone())
        .collect();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    assert!(matches!(
        assemble_block(
            &store.state().clone(),
            coinbase,
            everything,
            &params,
            NOW,
            0
        ),
        Err(BlockError::TooManyEvictions { .. })
    ));
}

/// AUDIT: a transfer that cannot be valid is refused before anything is hashed.
///
/// The identifier is an encoding of the whole body and a hash of it, and the
/// pool used to take it first, to see whether it already held the transfer.
/// The shape check ahead of it is a handful of comparisons and one walk over
/// the inputs, and everything already in the pool has passed it, so nothing
/// that would have been recognised is turned away by moving it up.
///
/// Counted rather than timed, and the count is nought rather than a threshold:
/// hashing anything at all before a transfer has been found capable of being
/// valid is the thing that was wrong.
#[test]
fn a_transfer_that_cannot_be_valid_is_refused_before_a_byte_is_hashed() {
    let miner = wallet(1);
    let (mut store, notes) = funded(1, &miner);

    // Two hundred and fifty six inputs, which is the most the rules allow, and
    // the same note in every one of them. Nothing about it can be valid, and
    // it is the largest thing a peer can say that of.
    let repeated = vec![Input::hot(notes[0].0); 256];
    let doomed = Transfer::new(
        repeated,
        vec![Note::new(pebbles(1), wallet(2).public_key())],
    );
    assert!(
        doomed.encode().len() > 25_000,
        "the point is that it is large"
    );

    counting::reset();
    let refused = store.accept_transfer(doomed);
    let hashed = counting::hashed();

    assert!(
        matches!(refused, Err(TransferError::DuplicateInput(_))),
        "the same note twice is not a transfer, however it is signed"
    );
    assert_eq!(
        hashed, 0,
        "refusing it hashed {hashed} bytes, and it should have hashed none"
    );
}

/// AUDIT: what the pool never holds, which is what lets a block stop asking.
///
/// `prune_pool` asks the whole pool again whenever the branch moves, and it
/// stopped asking about the signatures: a signature covers the transfer's own
/// identifier, the position of the input, and the value and owner of the note
/// being spent, and a note identifier commits to the note, so the state cannot
/// move the answer.
///
/// What that rests on is that nothing reaches the pool unchecked. There is one
/// way in, `accept_transfer`, and this is what it does with a signature that
/// does not hold. If a second way in is ever added, this test says nothing
/// about it, and the note on `prune_pool` is the thing to read before adding
/// one.
#[test]
fn a_transfer_whose_signature_does_not_hold_never_reaches_the_pool() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(2, &miner);

    // Signed by somebody who does not own the note.
    let stranger = wallet(9);
    let mut forged = Transfer::new(
        vec![Input::hot(notes[0].0)],
        vec![Note::new(
            notes[0].1.value.checked_sub(pebbles(PLAIN_FEE)).unwrap(),
            wallet(2).public_key(),
        )],
    );
    forged.sign_input(params.network, 0, &notes[0].1, &stranger);

    assert!(
        matches!(
            store.accept_transfer(forged),
            Err(TransferError::InvalidSignature { input_index: 0 })
        ),
        "a transfer signed by the wrong key was taken into the pool"
    );
    assert_eq!(store.pool_len(), 0, "and nothing was kept of it");

    // And one that does hold goes in, so this is a check and not a wall.
    let good = spend(
        &params,
        notes[1].0,
        notes[1].1,
        &miner,
        &wallet(2),
        pebbles(PLAIN_FEE),
    );
    assert_eq!(store.accept_transfer(good), Ok(true));
    assert_eq!(store.pool_len(), 1);
}

/// The largest coinbase any network's rules allow, claiming `fee` on top of
/// the reward, because that is the coinbase the pool has to leave room for.
///
/// A miner may fill its own coinbase and the pool cannot know in advance
/// whether this one will. Leaving room for a small one would put the pool back
/// where it started, promising slots in blocks that cannot be built.
fn fattest_coinbase(params: &ConsensusParams, height: u64, fee: Amount) -> CoinbaseTransaction {
    let total = params.initial_reward.as_pebbles() + fee.as_pebbles();
    let count = params.max_coinbase_outputs as u64;
    let each = total / count;
    let first = total - each * (count - 1);
    let outputs: Vec<Note> = (0..params.max_coinbase_outputs)
        .map(|index| {
            let value = if index == 0 { first } else { each };
            Note::new(pebbles(value), wallet(9).public_key())
        })
        .collect();
    CoinbaseTransaction::with_extra(height, outputs, vec![0u8; MAX_COINBASE_EXTRA])
}

/// What the pool takes is what a block can carry, measured from both sides.
///
/// The pool's job is to hold what is waiting for a block. A transfer no block
/// can carry is not waiting for one, and `a_transfer_too_large_for_a_block_is_
/// refused_outright` says so. What it did not say is where the boundary is,
/// and the boundary was in the wrong place by four kilobytes: `accept_transfer`
/// measured against `max_block_bytes` whole while `selection` packs to
/// `room_for_transfers`, so between the two lay a band the pool took and no
/// miner could ever pick.
///
/// That band is not a leak, it is a blockade, and a free one. A transfer that
/// is never mined never pays the fee it promised, so an attacker can promise
/// any fee at all; eviction drops the cheapest first, so the promise buys the
/// last place to be evicted. Four hundred and five of them fill the pool,
/// declare a hundred and twenty six billion pebbles, pay nothing, and are
/// still there after ten blocks with ordinary payments refused behind them.
///
/// So the boundary is measured here, from both sides, against the rule itself:
/// `bytes > max_block_bytes` in `connect_block`, on a block carrying the
/// largest coinbase the rules allow. Both directions matter. Too loose is the
/// blockade. Too tight is a transfer every node would have accepted, refused
/// by the pool and relayed by nobody, which is the harm
/// `room_for_transfers` was named after in the first place.
#[test]
fn what_the_pool_takes_is_what_a_block_can_carry() {
    let mut params = params();
    // Small enough that the boundary is a few dozen notes away rather than a
    // hundred and twenty kilobytes. The arithmetic is scale free.
    params.max_block_bytes = 4096;
    let owner = wallet(1);
    let (wide, notes) = funded_widely(4, &owner);

    // The same chain under the tighter limit, with a ledger beside it, so a
    // candidate block can be judged and not only measured.
    let mut tight = ChainStore::new(params);
    let mut ledger = LedgerState::new();
    for height in 0.. {
        match wide.block_at(height) {
            Some(block) => {
                connect_block(&mut ledger, block, &params, NOW).unwrap();
                tight.add_block(block.clone(), NOW).unwrap();
            }
            None => break,
        }
    }
    let height = ledger.next_height().unwrap();

    // The floor rises with the transfer, so the fee is worked out against the
    // transfer rather than picked. Changing it moves no bytes: an amount is
    // eight of them whatever it holds.
    let built = |count: usize, at: usize| -> (Transfer, Amount) {
        let (id, note) = notes[at];
        let spend =
            |fee: Amount| splitting_spend(&params, id, note, &owner, &wallet(2), count, fee);
        let draft = spend(pebbles(PLAIN_FEE));
        let floor = fee_floor(transfer_weight(&draft, draft.encode().len(), 1));
        let fee = pebbles(floor.as_pebbles() * 2);
        let paid = spend(fee);
        assert_eq!(
            paid.encode().len(),
            draft.encode().len(),
            "the fee moved bytes"
        );
        (paid, fee)
    };

    // A block carrying one such transfer and nothing else, under the largest
    // coinbase the rules allow. `bytes > max_block_bytes` is the rule, read
    // off `connect_block`.
    let candidate = |count: usize, at: usize| {
        let (transfer, fee) = built(count, at);
        let coinbase = fattest_coinbase(&params, height, fee);
        assemble_block(&ledger, coinbase, vec![transfer], &params, NOW - 600, 0).unwrap()
    };
    let carried =
        |count: usize, at: usize| candidate(count, at).encode().len() <= params.max_block_bytes;

    // The boundary, found rather than assumed.
    let widest = (1..=params.max_outputs_per_transfer)
        .take_while(|count| carried(*count, 0))
        .last()
        .expect("one note has to fit");
    assert!(
        widest < params.max_outputs_per_transfer,
        "the limit has to bite before the rules do, or this test measures nothing"
    );

    // Both sides, through the real path, so the claim is about the rule and
    // not about an encoding measured twice.
    for (count, fits) in [(widest, true), (widest + 1, false)] {
        let block = mine_block(candidate(count, 0), ATTEMPTS).unwrap();
        let verdict = connect_block(&mut ledger.clone(), &block, &params, NOW);
        assert_eq!(
            verdict.is_ok(),
            fits,
            "a block carrying {count} outputs is {} bytes against a {} limit: {verdict:?}",
            block.encode().len(),
            params.max_block_bytes
        );
        if !fits {
            assert!(
                matches!(verdict, Err(BlockError::BlockTooLarge { .. })),
                "and it has to be the size that refuses it, not something else: {verdict:?}"
            );
        }
    }

    // And the pool's answer is the same answer, on both sides.
    assert!(
        tight.accept_transfer(built(widest, 0).0).unwrap(),
        "the widest transfer a block can carry has to reach the pool"
    );
    match tight.accept_transfer(built(widest + 1, 1).0) {
        Err(TransferError::TooLargeForABlock { .. }) => {}
        other => panic!(
            "a transfer no block can carry was taken, or refused for the wrong reason: {other:?}"
        ),
    }

    // Which is the whole of it: what the pool holds, a miner can pick.
    let (chosen, _) = tight.selection(params.max_transfers_per_block);
    assert_eq!(
        chosen.len(),
        tight.pool_len(),
        "everything the pool took has to be selectable, or it is waiting for a block \
         that cannot be built"
    );
}

/// The reserve is what a block spends before its first transfer.
///
/// `room_for_transfers` subtracts a number, and the number is right only for
/// as long as it equals what the encoders produce. Both ways of being wrong
/// are live, and they are not symmetric in how they show:
///
/// Too small and the pool takes what no miner can pick, which is silent, free
/// and permanent. Too large and it refuses a transfer every node would have
/// accepted, which at least reaches whoever sent it as an error.
///
/// It was four kilobytes against a true cost of nine hundred and eight, which
/// cost nothing while only `selection` read it, because packing a block two
/// per cent loose is a miner's business. It became both kinds of wrong at once
/// the moment the pool was made to read the same number, which is why the
/// number is pinned here and not left to a comment.
///
/// A block with the largest coinbase the rules allow and no transfers in it is
/// exactly that cost, so nothing here is counted by hand.
#[test]
fn the_reserve_is_what_a_block_spends_before_its_first_transfer() {
    let params = params();
    let reserved = params.max_block_bytes - ChainStore::room_for_transfers(params.max_block_bytes);

    let ledger = LedgerState::new();
    let empty = assemble_block(
        &ledger,
        fattest_coinbase(&params, 0, Amount::ZERO),
        Vec::<Transfer>::new(),
        &params,
        1_000,
        0,
    )
    .unwrap();
    assert_eq!(
        reserved,
        empty.encode().len(),
        "the reserve and a block's own head have parted company"
    );

    // And it is the largest coinbase that has to be allowed for. A miner may
    // fill its own, and the pool answers before it knows whether this one
    // will, so reserving for a typical coinbase is reserving for a block that
    // may not be the one that gets built.
    let typical = assemble_block(
        &ledger,
        CoinbaseTransaction::new(
            0,
            vec![Note::new(params.initial_reward, wallet(9).public_key())],
        ),
        Vec::<Transfer>::new(),
        &params,
        1_000,
        0,
    )
    .unwrap();
    assert!(
        typical.encode().len() < reserved,
        "a typical block head is {} bytes and the reserve is {reserved}, so the reserve \
         is no longer the worst case",
        typical.encode().len()
    );
}

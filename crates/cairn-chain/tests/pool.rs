//! Transfers waiting for a block.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{ChainStore, MAX_POOLED};
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, ConsensusParams, TransferError,
};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain of `count` blocks, and the coinbase note each one paid the miner.
fn funded(count: usize, miner: &SecretKey) -> (ChainStore, Vec<(NoteId, Note)>) {
    let params = params();
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
        Amount::ZERO,
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
        Amount::ZERO,
    );
    let second = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(3),
        Amount::ZERO,
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
        .map(|(id, note)| spend(&params, *id, *note, &miner, &wallet(2), Amount::ZERO))
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
        Amount::ZERO,
    );
    let left_behind = spend(
        &params,
        notes[1].0,
        notes[1].1,
        &miner,
        &wallet(3),
        Amount::ZERO,
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
/// Filling it costs an attacker nothing: transfers paying no fee, spending
/// notes back to itself. Everyone who wants to send anything is then behind
/// them, for as long as the attacker cares to keep it up. So the ceiling
/// holds, and a transfer worth more than the least the pool already carries
/// takes that one's place.
#[test]
fn a_full_pool_makes_room_for_whoever_pays_more() {
    let params = params();
    let attacker = wallet(1);
    let (mut store, notes) = funded_widely(MAX_POOLED + 2, &attacker);

    for (id, note) in notes.iter().take(MAX_POOLED) {
        let transfer = spend(&params, *id, *note, &attacker, &wallet(2), Amount::ZERO);
        assert!(store.accept_transfer(transfer).unwrap());
    }
    assert_eq!(store.pool_len(), MAX_POOLED, "the ceiling is reached");

    // Another that pays nothing has nothing to offer and is turned away.
    let (id, note) = notes[MAX_POOLED];
    let free = spend(&params, id, note, &attacker, &wallet(2), Amount::ZERO);
    assert!(!store.accept_transfer(free).unwrap(), "nothing to displace");
    assert_eq!(store.pool_len(), MAX_POOLED);

    // One that pays gets in, and the pool stays at its ceiling.
    let (id, note) = notes[MAX_POOLED + 1];
    let paying = spend(
        &params,
        id,
        note,
        &attacker,
        &wallet(2),
        Amount::from_pebbles(1).unwrap(),
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
        let fee = (index as u64 + 1) * 10;
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

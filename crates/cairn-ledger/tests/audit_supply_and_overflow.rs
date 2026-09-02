//! Adversarial audit of the issued total in the state root, and of the one
//! shape the grace window says it handles and no live network reaches: a block
//! landing more notes than the window can ever hold.
//!
//! Read only. Nothing here changes a source file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::GRACE_NOTES;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, disconnect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// The total the state root carries is the money that is actually there.
///
/// Nothing else in the ledger states it, so nothing else can check it. What
/// checks it here is the test's own books: every note created and every note
/// spent, kept outside the ledger, which is exactly what anybody auditing the
/// chain had to do before this field existed.
#[test]
fn the_total_is_the_sum_of_what_is_unspent_however_the_money_moves() {
    let params = ConsensusParams::testnet()
        .with_hot_capacity(8)
        .with_coinbase_maturity(0);
    let miner = wallet(1);
    let alice = wallet(2);
    let mut state = LedgerState::archiving();
    // Every unspent note, kept beside the ledger rather than in it.
    let mut books: BTreeMap<NoteId, Amount> = BTreeMap::new();
    let mut purse: Vec<(NoteId, Note, u8)> = Vec::new();

    for round in 0..40u64 {
        let height = state.next_height().unwrap();
        let mut transfers = Vec::new();
        if let Some((id, note, owner)) = purse.pop() {
            // Every round pays a different fee, so the total moves against the
            // coinbase by a different amount each time.
            let fee = 1 + (round % 7) * 13;
            let value = note.value.as_pebbles();
            if value > fee + 2 {
                let outputs = vec![
                    Note::new(
                        Amount::from_pebbles(value - fee - 1).unwrap(),
                        alice.public_key(),
                    ),
                    Note::new(Amount::from_pebbles(1).unwrap(), alice.public_key()),
                ];
                let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
                transfer.sign_input(params.network, 0, &note, &wallet(owner));
                transfers.push(transfer);
            }
        }

        // A miner that sometimes declines part of what it is owed, which burns
        // the difference: legal, and the one thing that makes the total move
        // downward.
        let claimed = if round % 5 == 0 {
            let fees: u64 = transfers
                .iter()
                .map(|transfer: &Transfer| {
                    let spent = books
                        .get(&transfer.inputs[0].note_id)
                        .copied()
                        .unwrap_or(Amount::ZERO);
                    spent.as_pebbles() - transfer.total_output().unwrap().as_pebbles()
                })
                .sum();
            // Half the reward and none of the fees, so both directions of the
            // arithmetic are exercised.
            let _ = fees;
            params.reward_at(height).as_pebbles() / 2
        } else {
            let fees: u64 = transfers
                .iter()
                .map(|transfer: &Transfer| {
                    let spent = books
                        .get(&transfer.inputs[0].note_id)
                        .copied()
                        .unwrap_or(Amount::ZERO);
                    spent.as_pebbles() - transfer.total_output().unwrap().as_pebbles()
                })
                .sum();
            params.reward_at(height).as_pebbles() + fees
        };
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(
                Amount::from_pebbles(claimed).unwrap(),
                miner.public_key(),
            )],
        );
        let block = assemble_block(
            &state,
            coinbase,
            transfers,
            &params,
            1_000 + height * 600,
            0,
        )
        .unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();

        for transfer in &block.transfers {
            for input in &transfer.inputs {
                books.remove(&input.note_id);
                purse.retain(|(id, _, _)| *id != input.note_id);
            }
            for (id, note) in transfer.created_notes() {
                books.insert(id, note.value);
                purse.push((id, note, 2));
            }
        }
        for (id, note) in block.coinbase.created_notes() {
            books.insert(id, note.value);
            purse.push((id, note, 1));
        }

        let counted = books
            .values()
            .fold(Amount::ZERO, |sum, value| sum.checked_add(*value).unwrap());
        assert_eq!(
            state.supply(),
            counted,
            "block {round}: the ledger says {:?} and the notes add up to {counted:?}",
            state.supply()
        );
    }
    println!("supply after 40 blocks: {:?}", state.supply());
}

/// A block landing more notes than the window can ever hold.
///
/// The window drops its own front and then loses the landing as well. Nothing
/// on a live network reaches this, because a block that landed nine thousand
/// notes would be three hundred kilobytes and the limit is a hundred and
/// twenty eight. It is here because the state root, the index a node spends
/// from, and the undo all have to agree about it, and the shape they have to
/// agree about is one no chain will ever hand them.
#[test]
fn a_landing_larger_than_the_window_leaves_nothing_spendable_without_a_proof() {
    let mut params = ConsensusParams::testnet()
        .with_hot_capacity(64)
        .with_coinbase_maturity(0);
    params.max_block_bytes = 8 * 1024 * 1024;
    params.max_evictions_per_block = 1 << 20;

    let miner = wallet(1);
    let alice = wallet(2);
    let mut state = LedgerState::archiving();
    let mut mirror = LedgerState::new();
    let mut purse: Vec<(NoteId, Note)> = Vec::new();

    // Enough ordinary blocks to gather the notes the big one will spend, and
    // to put something in the window for it to lose.
    for _ in 0..40u64 {
        let height = state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
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
        connect_block(&mut mirror, &block, &params, NOW).unwrap();
        purse.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(params.reward_at(height), miner.public_key()),
        ));
    }

    // Then one block that creates more notes than the window can hold, out of
    // notes that all existed before it.
    let wanted = GRACE_NOTES + 64;
    let mut transfers = Vec::new();
    let mut made = 0usize;
    while made < wanted {
        let (id, note) = purse.pop().expect("a note for every transfer");
        let batch = (wanted - made).min(250);
        let each = note.value.as_pebbles() / (batch as u64 + 1);
        assert!(each > 0);
        let outputs: Vec<Note> = (0..batch)
            .map(|_| Note::new(Amount::from_pebbles(each).unwrap(), alice.public_key()))
            .collect();
        let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
        transfer.sign_input(params.network, 0, &note, &miner);
        made += batch;
        transfers.push(transfer);
    }

    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), miner.public_key())],
    );
    let before_root = state.state_root();
    let before_window = state.grace_window();
    let block = assemble_block(
        &state,
        coinbase,
        transfers,
        &params,
        1_000 + height * 600,
        0,
    )
    .unwrap();
    let connected = connect_block(&mut state, &block, &params, NOW).unwrap();
    let mirrored = connect_block(&mut mirror, &block, &params, NOW).unwrap();
    assert_eq!(state.state_root(), mirror.state_root());

    println!(
        "the block created {} notes; the window now holds {} blocks and {} notes",
        block
            .transfers
            .iter()
            .map(|transfer| transfer.outputs.len())
            .sum::<usize>(),
        state.grace_window().len(),
        state.grace_len()
    );

    // Whatever it did, the index a node spends from says exactly what the
    // committed window says. That is the property: they used to come apart
    // here, and two nodes agreeing on every root disagreed about which spends
    // needed a proof.
    let listed: usize = state.grace_window().iter().map(Vec::len).sum();
    assert_eq!(
        listed,
        state.grace_len(),
        "the window and the index it is read through disagree"
    );
    for block_notes in state.grace_window() {
        for (id, position, _) in block_notes {
            assert_eq!(
                state.within_grace(&id).map(|(at, _)| at),
                Some(position),
                "a note in the window is not in the index at the place the window gives"
            );
            assert!(
                state.cold().proof_of(position).is_some(),
                "a note in the window has no proof, so this ledger cannot be handed over"
            );
        }
    }

    // And it undoes exactly.
    disconnect_block(&mut state, &connected);
    disconnect_block(&mut mirror, &mirrored);
    assert_eq!(state.state_root(), before_root, "the undo moved the root");
    assert_eq!(
        mirror.state_root(),
        before_root,
        "the plain node's undo differs"
    );
    assert_eq!(
        state.grace_window(),
        before_window,
        "the window came back different"
    );
    assert_eq!(
        state.grace_len(),
        before_window.iter().map(Vec::len).sum::<usize>(),
        "the index came back holding something the window does not"
    );
}

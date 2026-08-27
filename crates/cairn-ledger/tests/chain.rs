//! End to end tests over a running chain.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, BlockError, ConsensusParams, TransferError,
};
use cairn_ledger::{Block, LedgerState};
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 1_000_000_000;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(value: u64) -> Amount {
    Amount::from_pebbles(value).unwrap()
}

fn coinbase_paying(height: u64, owner: PublicKey, value: Amount) -> CoinbaseTransaction {
    CoinbaseTransaction::new(height, vec![Note::new(value, owner)])
}

/// Builds a transfer spending `inputs` and signs every one of them.
fn signed_transfer(
    params: &ConsensusParams,
    inputs: &[(NoteId, Note, &SecretKey)],
    outputs: Vec<Note>,
) -> Transfer {
    let mut transfer = Transfer::new(
        inputs.iter().map(|(id, _, _)| Input::hot(*id)).collect(),
        outputs,
    );
    for (position, (_, note, secret)) in inputs.iter().enumerate() {
        let position = u32::try_from(position).expect("test inputs stay well under u32::MAX");
        transfer.sign_input(params.network, position, note, secret);
    }
    transfer
}

/// Chain with a single block whose coinbase pays `miner` the full reward.
fn chain_with_genesis(params: &ConsensusParams, miner: &SecretKey) -> (LedgerState, NoteId, Note) {
    let mut state = LedgerState::new();
    let note = Note::new(params.initial_reward, miner.public_key());
    let coinbase = coinbase_paying(0, miner.public_key(), params.initial_reward);
    let block = assemble_block(&state, coinbase, Vec::new(), params, 1_000, 0).unwrap();
    connect_block(&mut state, &block, params, NOW).unwrap();

    let note_id = NoteId::new(block.coinbase.id(), 0);
    assert_eq!(state.hot_note(&note_id), Some(note));
    (state, note_id, note)
}

#[test]
fn a_genesis_block_connects_and_pays_the_miner() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let (state, _, note) = chain_with_genesis(&params, &miner);

    assert_eq!(state.hot_len(), 1);
    assert_eq!(note.value, params.initial_reward);
    let tip = state.tip().unwrap();
    assert_eq!(tip.height, 0);
    assert_eq!(tip.timestamp, 1_000);
}

#[test]
fn a_transfer_moves_value_and_pays_a_fee() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let recipient = wallet(2);
    let (mut state, funded_id, funded) = chain_with_genesis(&params, &miner);

    let sent = pebbles(30 * 100_000_000);
    let change = pebbles(19 * 100_000_000);
    let fee = funded
        .value
        .checked_sub(sent)
        .unwrap()
        .checked_sub(change)
        .unwrap();

    let transfer = signed_transfer(
        &params,
        &[(funded_id, funded, &miner)],
        vec![
            Note::new(sent, recipient.public_key()),
            Note::new(change, miner.public_key()),
        ],
    );
    let transfer_id = transfer.id();

    let coinbase = coinbase_paying(
        1,
        miner.public_key(),
        params.initial_reward.checked_add(fee).unwrap(),
    );
    let block = assemble_block(&state, coinbase, vec![transfer], &params, 2_000, 0).unwrap();
    connect_block(&mut state, &block, &params, NOW).unwrap();

    assert_eq!(state.hot_note(&funded_id), None, "the spent note is gone");
    assert_eq!(
        state.hot_note(&NoteId::new(transfer_id, 0)),
        Some(Note::new(sent, recipient.public_key()))
    );
    assert_eq!(
        state.hot_note(&NoteId::new(transfer_id, 1)),
        Some(Note::new(change, miner.public_key()))
    );
    assert_eq!(
        state.hot_len(),
        3,
        "recipient, change, and the new coinbase note"
    );
}

#[test]
fn a_transfer_cannot_create_value() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let (state, funded_id, funded) = chain_with_genesis(&params, &miner);

    let too_much = funded.value.checked_add(pebbles(1)).unwrap();
    let transfer = signed_transfer(
        &params,
        &[(funded_id, funded, &miner)],
        vec![Note::new(too_much, miner.public_key())],
    );

    let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
    let outcome = assemble_block(&state, coinbase, vec![transfer], &params, 2_000, 0);
    assert!(matches!(
        outcome,
        Err(BlockError::InvalidTransfer {
            index: 0,
            source: TransferError::OutputsExceedInputs { .. }
        })
    ));
}

#[test]
fn the_same_note_cannot_be_spent_twice_in_one_block() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let (state, funded_id, funded) = chain_with_genesis(&params, &miner);

    let half = pebbles(funded.value.as_pebbles() / 2);
    let first = signed_transfer(
        &params,
        &[(funded_id, funded, &miner)],
        vec![Note::new(half, wallet(2).public_key())],
    );
    let second = signed_transfer(
        &params,
        &[(funded_id, funded, &miner)],
        vec![Note::new(half, wallet(3).public_key())],
    );

    let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
    let outcome = assemble_block(&state, coinbase, vec![first, second], &params, 2_000, 0);
    assert!(matches!(
        outcome,
        Err(BlockError::InvalidTransfer {
            index: 1,
            source: TransferError::UnknownNote(_)
        })
    ));
}

#[test]
fn a_note_spent_in_an_earlier_block_cannot_be_spent_again() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let (mut state, funded_id, funded) = chain_with_genesis(&params, &miner);

    let half = pebbles(funded.value.as_pebbles() / 2);
    let spend = signed_transfer(
        &params,
        &[(funded_id, funded, &miner)],
        vec![Note::new(half, wallet(2).public_key())],
    );

    let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
    let block = assemble_block(&state, coinbase, vec![spend.clone()], &params, 2_000, 0).unwrap();
    connect_block(&mut state, &block, &params, NOW).unwrap();

    let coinbase = coinbase_paying(2, miner.public_key(), params.initial_reward);
    let outcome = assemble_block(&state, coinbase, vec![spend], &params, 3_000, 0);
    // The note left the hot set when it was spent. A node holding only the cold
    // commitment cannot tell that from a note that fell to the cold set, so it
    // asks for a proof, and no proof exists for a note that was spent.
    assert!(matches!(
        outcome,
        Err(BlockError::InvalidTransfer {
            index: 0,
            source: TransferError::MissingProof { .. }
        })
    ));
}

#[test]
fn a_note_can_only_be_spent_by_its_owner() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let thief = wallet(9);
    let (state, funded_id, funded) = chain_with_genesis(&params, &miner);

    let transfer = signed_transfer(
        &params,
        &[(funded_id, funded, &thief)],
        vec![Note::new(pebbles(1), thief.public_key())],
    );

    let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
    let outcome = assemble_block(&state, coinbase, vec![transfer], &params, 2_000, 0);
    assert!(matches!(
        outcome,
        Err(BlockError::InvalidTransfer {
            index: 0,
            source: TransferError::InvalidSignature { input_index: 0 }
        })
    ));
}

#[test]
fn changing_an_output_after_signing_breaks_the_signature() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let attacker = wallet(9);
    let (state, funded_id, funded) = chain_with_genesis(&params, &miner);

    let mut transfer = signed_transfer(
        &params,
        &[(funded_id, funded, &miner)],
        vec![Note::new(pebbles(1), wallet(2).public_key())],
    );
    transfer.outputs[0].owner = attacker.public_key();

    let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
    let outcome = assemble_block(&state, coinbase, vec![transfer], &params, 2_000, 0);
    assert!(matches!(
        outcome,
        Err(BlockError::InvalidTransfer {
            index: 0,
            source: TransferError::InvalidSignature { .. }
        })
    ));
}

#[test]
fn a_signature_from_another_network_does_not_replay() {
    let mut params = ConsensusParams::testnet();
    let miner = wallet(1);
    let (state, funded_id, funded) = chain_with_genesis(&params, &miner);

    let mut foreign = params;
    foreign.network = NetworkId::MAINNET;
    let transfer = signed_transfer(
        &foreign,
        &[(funded_id, funded, &miner)],
        vec![Note::new(pebbles(1), miner.public_key())],
    );

    params.network = NetworkId::TESTNET;
    let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
    let outcome = assemble_block(&state, coinbase, vec![transfer], &params, 2_000, 0);
    assert!(matches!(
        outcome,
        Err(BlockError::InvalidTransfer {
            index: 0,
            source: TransferError::InvalidSignature { .. }
        })
    ));
}

#[test]
fn the_coinbase_cannot_claim_more_than_the_reward_and_fees() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let state = LedgerState::new();

    let overpaid = params.initial_reward.checked_add(pebbles(1)).unwrap();
    let coinbase = coinbase_paying(0, miner.public_key(), overpaid);
    let outcome = assemble_block(&state, coinbase, Vec::new(), &params, 1_000, 0);
    assert!(matches!(outcome, Err(BlockError::CoinbaseOverpay { .. })));
}

#[test]
fn a_tampered_state_root_is_rejected_and_leaves_the_state_untouched() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let coinbase = coinbase_paying(0, miner.public_key(), params.initial_reward);
    let mut block = assemble_block(&state, coinbase, Vec::new(), &params, 1_000, 0).unwrap();
    block.header.state_root = Hash32::ZERO;

    assert!(matches!(
        connect_block(&mut state, &block, &params, NOW),
        Err(BlockError::StateRootMismatch { .. })
    ));
    assert!(state.is_empty());
    assert_eq!(state.tip(), None);
}

#[test]
fn a_tampered_transaction_root_is_rejected() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let coinbase = coinbase_paying(0, miner.public_key(), params.initial_reward);
    let mut block = assemble_block(&state, coinbase, Vec::new(), &params, 1_000, 0).unwrap();
    block.header.transactions_root = Hash32::ZERO;

    assert!(matches!(
        connect_block(&mut state, &block, &params, NOW),
        Err(BlockError::TransactionsRootMismatch { .. })
    ));
}

#[test]
fn a_block_must_extend_the_current_tip() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let (mut state, _, _) = chain_with_genesis(&params, &miner);

    let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
    let mut block = assemble_block(&state, coinbase, Vec::new(), &params, 2_000, 0).unwrap();
    block.header.previous = Hash32::ZERO;

    assert!(matches!(
        connect_block(&mut state, &block, &params, NOW),
        Err(BlockError::WrongParent { .. })
    ));

    let coinbase = coinbase_paying(5, miner.public_key(), params.initial_reward);
    assert!(matches!(
        assemble_block(&state, coinbase, Vec::new(), &params, 2_000, 0),
        Err(BlockError::CoinbaseHeightMismatch {
            header: 1,
            coinbase: 5
        })
    ));
}

#[test]
fn a_block_from_the_far_future_is_rejected() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let coinbase = coinbase_paying(0, miner.public_key(), params.initial_reward);
    let block = assemble_block(
        &state,
        coinbase,
        Vec::new(),
        &params,
        NOW + params.max_timestamp_drift + 1,
        0,
    )
    .unwrap();

    assert!(matches!(
        connect_block(&mut state, &block, &params, NOW),
        Err(BlockError::TimestampTooFarAhead { .. })
    ));
}

#[test]
fn a_block_must_be_later_than_the_recent_median() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let (mut state, _, _) = chain_with_genesis(&params, &miner);

    let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
    let block = assemble_block(&state, coinbase, Vec::new(), &params, 1_000, 0).unwrap();

    assert!(matches!(
        connect_block(&mut state, &block, &params, NOW),
        Err(BlockError::TimestampNotAfterMedian {
            median: 1_000,
            found: 1_000
        })
    ));
}

#[test]
fn a_block_from_another_network_is_rejected() {
    let params = ConsensusParams::testnet();
    let mut foreign = params;
    foreign.network = NetworkId::MAINNET;

    let miner = wallet(1);
    let mut state = LedgerState::new();
    let coinbase = coinbase_paying(0, miner.public_key(), foreign.initial_reward);
    let block = assemble_block(&state, coinbase, Vec::new(), &foreign, 1_000, 0).unwrap();

    assert!(matches!(
        connect_block(&mut state, &block, &params, NOW),
        Err(BlockError::WrongNetwork { .. })
    ));
}

#[test]
fn identical_histories_produce_identical_state_roots() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);

    let build = || {
        let (mut state, funded_id, funded) = chain_with_genesis(&params, &miner);
        let transfer = signed_transfer(
            &params,
            &[(funded_id, funded, &miner)],
            vec![Note::new(pebbles(7), wallet(2).public_key())],
        );
        let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
        let block = assemble_block(&state, coinbase, vec![transfer], &params, 2_000, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        (state.state_root(), block.id())
    };

    assert_eq!(build(), build());
}

#[test]
fn the_state_root_notices_a_single_changed_pebble() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let (state, _, _) = chain_with_genesis(&params, &miner);

    let mut shifted = ConsensusParams::testnet();
    shifted.initial_reward = params.initial_reward.checked_sub(pebbles(1)).unwrap();
    let (other, _, _) = chain_with_genesis(&shifted, &miner);

    assert_ne!(state.state_root(), other.state_root());
}

#[test]
fn a_block_survives_a_round_trip_through_the_wire_format() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let (state, funded_id, funded) = chain_with_genesis(&params, &miner);

    let transfer = signed_transfer(
        &params,
        &[(funded_id, funded, &miner)],
        vec![Note::new(pebbles(5), wallet(2).public_key())],
    );
    let coinbase = coinbase_paying(1, miner.public_key(), params.initial_reward);
    let block = assemble_block(&state, coinbase, vec![transfer], &params, 2_000, 42).unwrap();

    let bytes = block.encode();
    let decoded = Block::decode(&bytes).unwrap();
    assert_eq!(decoded, block);
    assert_eq!(decoded.encode(), bytes);
    assert_eq!(decoded.id(), block.id());
}

#[test]
fn a_chain_of_many_blocks_stays_consistent() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let recipient = wallet(2);
    let (mut state, mut funded_id, mut funded) = chain_with_genesis(&params, &miner);

    for height in 1..=20u64 {
        let sent = pebbles(1_000);
        let change = funded.value.checked_sub(sent).unwrap();
        let transfer = signed_transfer(
            &params,
            &[(funded_id, funded, &miner)],
            vec![
                Note::new(sent, recipient.public_key()),
                Note::new(change, miner.public_key()),
            ],
        );
        let transfer_id = transfer.id();

        let coinbase = coinbase_paying(height, miner.public_key(), params.initial_reward);
        let block = assemble_block(
            &state,
            coinbase,
            vec![transfer],
            &params,
            1_000 + height * 600,
            0,
        )
        .unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();

        funded_id = NoteId::new(transfer_id, 1);
        funded = Note::new(change, miner.public_key());
    }

    let tip = state.tip().unwrap();
    assert_eq!(tip.height, 20);
    // 20 notes for the recipient, 20 coinbase notes, and the last change note.
    // The genesis coinbase note was spent by the first transfer.
    assert_eq!(state.hot_len(), 41);
}

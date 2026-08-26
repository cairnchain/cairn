//! The hot and cold tiers: what falls, when, and how it comes back.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::ForestProof;
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::GRACE_BLOCKS;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, BlockError, ConsensusParams, TransferError,
};
use cairn_ledger::{Block, LedgerState};

const NOW: u64 = 1_000_000_000;
const CAPACITY: usize = 8;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_hot_capacity(CAPACITY)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Produces the next block, paying the miner the plain reward.
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
        [0; 8],
    );
    let block =
        assemble_block(state, coinbase, transfers, params, 1_000 + height * 600, 0).unwrap();
    connect_block(state, &block, params, NOW).unwrap();
    block
}

/// Mines `count` empty blocks and returns the note each coinbase created.
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

/// Spends a note that has fallen to the cold set, paying it all to `recipient`.
fn spend_cold(
    state: &LedgerState,
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    recipient: &SecretKey,
) -> Transfer {
    // An archivist answers both questions a wallet that lost its record has:
    // where the note sits, and what proves it.
    let position = state
        .cold()
        .locate(&id, &note)
        .expect("the note is in the cold set");
    let proof = state
        .cold()
        .prove(position)
        .expect("an archivist can prove it");
    let mut transfer = Transfer::new(
        vec![Input::cold(id, note, position, proof)],
        vec![Note::new(note.value, recipient.public_key())],
    );
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

#[test]
fn notes_fall_to_the_cold_set_once_the_hot_set_is_full() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    for produced in 1..=13u64 {
        mine(&mut state, &params, &miner, Vec::new());
        let expected_hot = (produced as usize).min(CAPACITY);
        let expected_cold = produced.saturating_sub(CAPACITY as u64);
        assert_eq!(
            state.hot_len(),
            expected_hot,
            "hot set after {produced} notes"
        );
        assert_eq!(
            state.cold_len(),
            expected_cold,
            "cold set after {produced} notes"
        );
    }
}

#[test]
fn the_hot_set_never_grows_past_its_cap() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    for _ in 0..60 {
        mine(&mut state, &params, &miner, Vec::new());
        assert!(state.hot_len() <= CAPACITY);
    }
    assert_eq!(state.hot_len(), CAPACITY);
    assert_eq!(state.cold_len(), 60 - CAPACITY as u64);
}

#[test]
fn the_oldest_note_falls_first() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let notes = mine_empty(&mut state, &params, &miner, CAPACITY as u64);
    for (id, _) in &notes {
        assert!(state.hot_note(id).is_some(), "nothing has fallen yet");
    }

    mine(&mut state, &params, &miner, Vec::new());
    let (oldest, oldest_note) = notes[0];
    assert!(
        state.hot_note(&oldest).is_none(),
        "the first note produced fell first"
    );
    assert!(
        state.hot_note(&notes[1].0).is_some(),
        "the next one is still held"
    );
    let position = state.cold().locate(&oldest, &oldest_note).expect("it fell");
    let proof = state
        .cold()
        .prove(position)
        .expect("an archivist can prove it");
    assert!(state.cold().verify(
        position,
        cairn_ledger::cold_leaf(&oldest, &oldest_note),
        &proof
    ));
}

#[test]
fn a_note_that_fell_can_still_be_spent_with_a_proof() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(2);
    let mut state = LedgerState::archiving();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (fallen, note) = notes[0];
    assert!(
        state.hot_note(&fallen).is_none(),
        "the note is in the cold set"
    );
    let cold_before = state.cold_len();

    let transfer = spend_cold(&state, &params, fallen, note, &miner, &alice);
    let transfer_id = transfer.id();
    mine(&mut state, &params, &miner, vec![transfer]);

    assert!(
        state.cold().locate(&fallen, &note).is_none(),
        "the note left the cold set"
    );

    let created = NoteId::new(transfer_id, 0);
    assert_eq!(
        state.hot_note(&created),
        Some(Note::new(note.value, alice.public_key())),
        "value recovered from the cold set lands back in the hot set"
    );

    // The hot set was already full, and the block created two notes into it:
    // the payment and the coinbase. So two others took the freed note's place.
    assert_eq!(state.hot_len(), CAPACITY);
    assert_eq!(state.cold_len(), cold_before - 1 + 2);
}

#[test]
fn a_note_that_fell_moments_ago_still_spends_without_a_proof() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    // The last CAPACITY notes are still held; the one before them is the most
    // recently fallen, which is the case a transfer in flight runs into.
    let (fallen, note) = notes[notes.len() - CAPACITY - 1];
    assert!(state.hot_note(&fallen).is_none());
    assert!(state.within_grace(&fallen).is_some());

    let mut transfer = Transfer::new(
        vec![Input::hot(fallen)],
        vec![Note::new(note.value, wallet(2).public_key())],
    );
    transfer.sign_input(params.network, 0, &note, &miner);
    let transfer_id = transfer.id();
    mine(&mut state, &params, &miner, vec![transfer]);

    assert_eq!(
        state.hot_note(&NoteId::new(transfer_id, 0)),
        Some(Note::new(note.value, wallet(2).public_key()))
    );
}

#[test]
fn a_note_that_fell_long_ago_needs_a_proof() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (fallen, note) = notes[0];
    mine_empty(&mut state, &params, &miner, GRACE_BLOCKS as u64 + 2);
    assert!(
        state.within_grace(&fallen).is_none(),
        "it aged out of the window"
    );

    let mut transfer = Transfer::new(
        vec![Input::hot(fallen)],
        vec![Note::new(note.value, wallet(2).public_key())],
    );
    transfer.sign_input(params.network, 0, &note, &miner);

    let coinbase = CoinbaseTransaction::new(
        state.next_height().unwrap(),
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    assert!(matches!(
        assemble_block(&state, coinbase, vec![transfer], &params, 900_000, 0),
        Err(BlockError::InvalidTransfer {
            index: 0,
            source: TransferError::MissingProof { .. }
        })
    ));
}

#[test]
fn a_note_spent_out_of_the_grace_window_cannot_be_spent_again() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (fallen, note) = notes[notes.len() - CAPACITY - 1];
    let spend = |to: &SecretKey| {
        let mut transfer = Transfer::new(
            vec![Input::hot(fallen)],
            vec![Note::new(note.value, to.public_key())],
        );
        transfer.sign_input(params.network, 0, &note, &miner);
        transfer
    };

    mine(&mut state, &params, &miner, vec![spend(&wallet(2))]);
    // Still inside the window, which is exactly the case worth checking: the
    // window makes a fallen note spendable, and must not make a spent one so.
    assert!(state.within_grace(&fallen).is_some());

    let coinbase = CoinbaseTransaction::new(
        state.next_height().unwrap(),
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    let outcome = assemble_block(
        &state,
        coinbase,
        vec![spend(&wallet(3))],
        &params,
        900_000,
        0,
    );
    // Refused either way: the node let the proof go when the note was spent,
    // and had it kept one, the place it points at is empty now.
    assert!(
        matches!(
            outcome,
            Err(BlockError::InvalidTransfer {
                index: 0,
                source: TransferError::MissingProof { .. } | TransferError::UnknownNote(_)
            })
        ),
        "spent once already: {outcome:?}"
    );
}

#[test]
fn offering_a_proof_for_a_note_still_in_the_hot_set_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (held, note) = *notes.last().unwrap();
    assert!(state.hot_note(&held).is_some());

    // The witness is refused for what it is, not for what it contains: a note
    // the nodes still hold takes no proof at all. Refusing rather than
    // ignoring is what keeps one spend to one encoding.
    let mut transfer = Transfer::new(
        vec![Input::cold(held, note, 0, ForestProof::default())],
        vec![Note::new(note.value, wallet(2).public_key())],
    );
    transfer.sign_input(params.network, 0, &note, &miner);

    let coinbase = CoinbaseTransaction::new(
        state.next_height().unwrap(),
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    assert!(matches!(
        assemble_block(&state, coinbase, vec![transfer], &params, 9_000, 0),
        Err(BlockError::InvalidTransfer {
            index: 0,
            source: TransferError::UnexpectedProof { .. }
        })
    ));
}

#[test]
fn a_proof_taken_a_few_blocks_ago_is_still_good() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (first, first_note) = notes[0];
    let (second, second_note) = notes[1];

    // Taken now, and the cold set moves before it is used. A spender cannot
    // be expected to be exactly at the tip: on a busy chain a block lands
    // while the transfer is still being written.
    let earlier = spend_cold(&state, &params, first, first_note, &miner, &wallet(2));
    let moving = spend_cold(&state, &params, second, second_note, &miner, &wallet(3));
    mine(&mut state, &params, &miner, vec![moving]);

    mine(&mut state, &params, &miner, vec![earlier]);
}

#[test]
fn a_fallen_note_cannot_be_spent_twice() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (fallen, note) = notes[0];

    let first = spend_cold(&state, &params, fallen, note, &miner, &wallet(2));
    let second = spend_cold(&state, &params, fallen, note, &miner, &wallet(3));

    let coinbase = CoinbaseTransaction::new(
        state.next_height().unwrap(),
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    assert!(
        matches!(
            assemble_block(
                &state,
                coinbase,
                vec![first.clone(), second.clone()],
                &params,
                9_000,
                0
            ),
            Err(BlockError::InvalidTransfer {
                index: 1,
                source: TransferError::UnknownNote(_)
            })
        ),
        "twice in one block"
    );

    mine(&mut state, &params, &miner, vec![first]);
    let coinbase = CoinbaseTransaction::new(
        state.next_height().unwrap(),
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    assert!(
        matches!(
            assemble_block(&state, coinbase, vec![second], &params, 9_100, 0),
            Err(BlockError::InvalidTransfer {
                index: 0,
                source: TransferError::InvalidProof { .. }
            })
        ),
        "again in a later block"
    );
}

#[test]
fn changing_the_note_inside_a_proof_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (fallen, note) = notes[0];

    let inflated = Note::new(note.value.checked_add(note.value).unwrap(), note.owner);
    let position = state.cold().locate(&fallen, &note).expect("it fell");
    let proof = state
        .cold()
        .prove(position)
        .expect("an archivist can prove it");
    let mut transfer = Transfer::new(
        vec![Input::cold(fallen, inflated, position, proof)],
        vec![Note::new(inflated.value, wallet(2).public_key())],
    );
    transfer.sign_input(params.network, 0, &inflated, &miner);

    let coinbase = CoinbaseTransaction::new(
        state.next_height().unwrap(),
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    assert!(matches!(
        assemble_block(&state, coinbase, vec![transfer], &params, 9_000, 0),
        Err(BlockError::InvalidTransfer {
            index: 0,
            source: TransferError::InvalidProof { .. }
        })
    ));
}

#[test]
fn a_real_place_and_a_real_proof_do_not_make_a_note() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (fallen, note) = notes[0];
    let position = state.cold().locate(&fallen, &note).expect("it fell");
    let proof = state
        .cold()
        .prove(position)
        .expect("an archivist can prove it");

    // The place exists, the proof is genuine, and the identifier is one that
    // was never there. The identifier is folded into the leaf precisely so
    // that this cannot work.
    let invented = NoteId::new(fallen.source, 7);
    let mut transfer = Transfer::new(
        vec![Input::cold(invented, note, position, proof)],
        vec![Note::new(note.value, wallet(2).public_key())],
    );
    transfer.sign_input(params.network, 0, &note, &miner);

    let coinbase = CoinbaseTransaction::new(
        state.next_height().unwrap(),
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    assert!(matches!(
        assemble_block(&state, coinbase, vec![transfer], &params, 9_000, 0),
        Err(BlockError::InvalidTransfer {
            index: 0,
            source: TransferError::InvalidProof { .. }
        })
    ));
}

#[test]
fn two_nodes_replaying_the_same_blocks_agree() {
    let params = params();
    let miner = wallet(1);

    let build = || {
        let mut state = LedgerState::archiving();
        let notes = mine_empty(&mut state, &params, &miner, 14);
        let transfer = spend_cold(&state, &params, notes[1].0, notes[1].1, &miner, &wallet(2));
        mine(&mut state, &params, &miner, vec![transfer]);
        (
            state.state_root(),
            state.cold().commitment(),
            state.hot_len(),
            state.cold_len(),
        )
    };

    assert_eq!(build(), build());
}

#[test]
fn a_block_that_evicts_is_rejected_when_its_state_root_is_wrong() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    mine_empty(&mut state, &params, &miner, 9);
    let before = state.state_root();

    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    let mut block = assemble_block(
        &state,
        coinbase,
        Vec::new(),
        &params,
        1_000 + height * 600,
        0,
    )
    .unwrap();
    block.header.state_root = before;

    assert!(matches!(
        connect_block(&mut state, &block, &params, NOW),
        Err(BlockError::StateRootMismatch { .. })
    ));
    assert_eq!(
        state.state_root(),
        before,
        "the failed block changed nothing"
    );
}

#[test]
fn a_watched_owner_spends_from_the_cold_set_with_nobody_holding_it() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(2);

    // A plain node: sixty four hashes and no leaves at all.
    let mut state = LedgerState::new();
    assert!(!state.cold().is_archiving());
    state.watch_owner(miner.public_key());

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (fallen, note) = notes[0];
    assert!(state.hot_note(&fallen).is_none(), "the note fell");
    assert!(
        state.cold().locate(&fallen, &note).is_none(),
        "and nobody here holds it"
    );

    // The node was told to watch this owner, so it knows where the note went
    // and has kept the proof current on its own.
    let position = state.watched_position(&fallen).expect("it kept track");
    let proof = state
        .cold()
        .proof_of(position)
        .expect("and kept the proof current");

    let mut transfer = Transfer::new(
        vec![Input::cold(fallen, note, position, proof)],
        vec![Note::new(note.value, alice.public_key())],
    );
    transfer.sign_input(params.network, 0, &note, &miner);
    let transfer_id = transfer.id();
    mine(&mut state, &params, &miner, vec![transfer]);

    assert_eq!(
        state.hot_note(&NoteId::new(transfer_id, 0)),
        Some(Note::new(note.value, alice.public_key())),
        "spent, from a set this node has never held"
    );
    assert!(
        state.watched_position(&fallen).is_none(),
        "and it stops being tracked"
    );
}

#[test]
fn a_proof_kept_by_the_node_stays_good_while_the_cold_set_moves() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::new();
    state.watch_owner(miner.public_key());

    let notes = mine_empty(&mut state, &params, &miner, 10);
    let (mine_note, note) = notes[0];
    let position = state.watched_position(&mine_note).expect("it fell");

    // Twenty more blocks, each pushing another note down, so the trees the
    // watched note sits in merge repeatedly.
    mine_empty(&mut state, &params, &miner, 20);

    let proof = state.cold().proof_of(position).expect("still current");
    assert!(
        state
            .cold()
            .verify(position, cairn_ledger::cold_leaf(&mine_note, &note), &proof),
        "the node brought the proof along as the forest grew"
    );
}

#[test]
fn a_node_keeps_proofs_for_the_grace_window_and_nothing_more() {
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let notes = mine_empty(&mut state, &params, &miner, 12);
    let (recent, _) = notes[notes.len() - CAPACITY - 1];
    let (old, _) = notes[0];

    let (position, _) = state.within_grace(&recent).expect("it fell recently");
    assert!(
        state.cold().proof_of(position).is_some(),
        "kept while it can still be spent"
    );

    // Nobody asked about this owner, so once the window passes the node lets
    // the proof go and keeps only what it must.
    mine_empty(&mut state, &params, &miner, GRACE_BLOCKS as u64 + 2);
    assert!(state.within_grace(&old).is_none());
    assert!(state.within_grace(&recent).is_none());
    assert!(
        state.cold().proof_of(position).is_none(),
        "and then lets it go"
    );
    assert_eq!(state.watched_notes().count(), 0);
}

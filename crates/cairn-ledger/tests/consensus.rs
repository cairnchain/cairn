//! Proof of work, difficulty, timestamps, and undoing a block.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::{meets_target, RECENT_HEADERS};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, disconnect_block, mine_block, BlockError, ConnectedBlock,
    ConsensusParams,
};
use cairn_ledger::{Block, LedgerState};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const SPACING: u64 = 600;
const MINING_ATTEMPTS: u64 = 1 << 22;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn candidate(
    state: &LedgerState,
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
    assemble_block(
        state,
        coinbase,
        transfers,
        params,
        1_000 + height * SPACING,
        0,
    )
    .unwrap()
}

fn mine(
    state: &mut LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    transfers: Vec<Transfer>,
) -> (Block, ConnectedBlock) {
    let block = mine_block(candidate(state, params, miner, transfers), MINING_ATTEMPTS)
        .expect("a nonce exists at this difficulty");
    let connected = connect_block(state, &block, params, NOW).unwrap();
    (block, connected)
}

fn coinbase_note(block: &Block, params: &ConsensusParams, miner: &SecretKey) -> (NoteId, Note) {
    (
        NoteId::new(block.coinbase.id(), 0),
        Note::new(params.initial_reward, miner.public_key()),
    )
}

#[test]
fn mining_finds_a_nonce_at_a_real_difficulty() {
    let mut params = ConsensusParams::testnet();
    params.genesis_difficulty = 4_096;
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let block = candidate(&state, &params, &miner, Vec::new());
    assert_eq!(block.header.difficulty, 4_096);
    assert!(
        !meets_target(&block.id(), block.header.difficulty),
        "nonce zero is not a solution"
    );

    let solved = mine_block(block, MINING_ATTEMPTS).expect("a nonce exists");
    assert!(meets_target(&solved.id(), solved.header.difficulty));
    assert!(connect_block(&mut state, &solved, &params, NOW).is_ok());
}

#[test]
fn a_block_without_enough_work_is_refused() {
    let mut params = ConsensusParams::testnet();
    params.genesis_difficulty = 4_096;
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let solved = mine_block(
        candidate(&state, &params, &miner, Vec::new()),
        MINING_ATTEMPTS,
    )
    .expect("a nonce exists");

    let mut spoiled = solved.clone();
    for nonce in (solved.header.nonce + 1).. {
        spoiled.header.nonce = nonce;
        if !meets_target(&spoiled.id(), spoiled.header.difficulty) {
            break;
        }
    }

    assert!(matches!(
        connect_block(&mut state, &spoiled, &params, NOW),
        Err(BlockError::InsufficientWork { difficulty: 4_096 })
    ));
    assert_eq!(state.tip(), None, "the refused block changed nothing");
}

#[test]
fn a_block_cannot_choose_its_own_difficulty() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let mut block = candidate(&state, &params, &miner, Vec::new());
    block.header.difficulty = 1_000_000;
    let block = mine_block(block, MINING_ATTEMPTS).unwrap_or_else(|| {
        panic!("mining at a claimed difficulty should still be attempted");
    });

    assert!(matches!(
        connect_block(&mut state, &block, &params, NOW),
        Err(BlockError::WrongDifficulty {
            expected: 1,
            found: 1_000_000
        })
    ));
}

#[test]
fn a_block_backdated_below_the_recent_median_is_refused() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    for _ in 0..12 {
        mine(&mut state, &params, &miner, Vec::new());
    }

    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    // Well after the parent, but still behind the median of the last eleven.
    let backdated = assemble_block(
        &state,
        coinbase,
        Vec::new(),
        &params,
        1_000 + 3 * SPACING,
        0,
    )
    .unwrap();
    let backdated = mine_block(backdated, MINING_ATTEMPTS).unwrap();

    assert!(matches!(
        connect_block(&mut state, &backdated, &params, NOW),
        Err(BlockError::TimestampNotAfterMedian { .. })
    ));
}

#[test]
fn undoing_a_block_restores_the_state_exactly() {
    let params = ConsensusParams::testnet().with_hot_capacity(4);
    let miner = wallet(1);
    let alice = wallet(2);
    let mut state = LedgerState::new();

    // Fill the hot set and push some notes down to the cold set.
    let mut minted = Vec::new();
    for _ in 0..8 {
        let (block, _) = mine(&mut state, &params, &miner, Vec::new());
        minted.push(coinbase_note(&block, &params, &miner));
    }

    let before = (
        state.state_root(),
        state.hot_len(),
        state.cold_len(),
        state.tip(),
        state.recent_headers().to_vec(),
    );

    // A block that does everything at once: spends a cold note, spends a hot
    // note, creates notes, and pushes others down.
    let (cold_id, cold_note) = minted[0];
    let (hot_id, hot_note) = *minted.last().unwrap();

    let mut from_cold = Transfer::new(
        vec![Input::cold(
            cold_id,
            cold_note,
            state.cold().prove(&cold_id),
        )],
        vec![Note::new(cold_note.value, alice.public_key())],
    );
    from_cold.sign_input(params.network, 0, &cold_note, &miner);

    let mut from_hot = Transfer::new(
        vec![Input::hot(hot_id)],
        vec![Note::new(hot_note.value, alice.public_key())],
    );
    from_hot.sign_input(params.network, 0, &hot_note, &miner);

    let (_, connected) = mine(&mut state, &params, &miner, vec![from_cold, from_hot]);
    assert!(
        !connected.transition.spent_cold.is_empty(),
        "the block spent from the cold set"
    );
    assert!(
        !connected.transition.evicted.is_empty(),
        "the block pushed notes down"
    );
    assert_ne!(state.state_root(), before.0);

    disconnect_block(&mut state, &connected);

    assert_eq!(state.state_root(), before.0, "the state root came back");
    assert_eq!(state.hot_len(), before.1);
    assert_eq!(state.cold_len(), before.2);
    assert_eq!(state.tip(), before.3);
    assert_eq!(state.recent_headers(), before.4.as_slice());
    assert_eq!(
        state.hot_note(&hot_id),
        Some(hot_note),
        "the spent hot note is back"
    );
}

#[test]
fn several_blocks_undo_in_reverse_order() {
    let params = ConsensusParams::testnet().with_hot_capacity(4);
    let miner = wallet(1);
    let mut state = LedgerState::new();

    for _ in 0..6 {
        mine(&mut state, &params, &miner, Vec::new());
    }
    let checkpoint = (
        state.state_root(),
        state.hot_len(),
        state.cold_len(),
        state.tip(),
    );

    let mut applied = Vec::new();
    for _ in 0..5 {
        let (_, connected) = mine(&mut state, &params, &miner, Vec::new());
        applied.push(connected);
    }
    assert_ne!(state.state_root(), checkpoint.0);

    while let Some(connected) = applied.pop() {
        disconnect_block(&mut state, &connected);
    }

    assert_eq!(state.state_root(), checkpoint.0);
    assert_eq!(state.hot_len(), checkpoint.1);
    assert_eq!(state.cold_len(), checkpoint.2);
    assert_eq!(state.tip(), checkpoint.3);
}

#[test]
fn undoing_restores_a_header_that_had_left_the_window() {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let mut state = LedgerState::new();

    for _ in 0..RECENT_HEADERS {
        mine(&mut state, &params, &miner, Vec::new());
    }
    assert_eq!(state.recent_headers().len(), RECENT_HEADERS);
    let before = state.recent_headers().to_vec();

    let (_, connected) = mine(&mut state, &params, &miner, Vec::new());
    assert_eq!(
        state.recent_headers().len(),
        RECENT_HEADERS,
        "the window stays bounded"
    );
    assert_ne!(state.recent_headers(), before.as_slice());

    disconnect_block(&mut state, &connected);
    assert_eq!(
        state.recent_headers(),
        before.as_slice(),
        "the oldest summary came back"
    );
}

#[test]
fn a_reapplied_block_produces_the_same_state() {
    let params = ConsensusParams::testnet().with_hot_capacity(4);
    let miner = wallet(1);
    let mut state = LedgerState::new();

    for _ in 0..7 {
        mine(&mut state, &params, &miner, Vec::new());
    }

    let block = mine_block(
        candidate(&state, &params, &miner, Vec::new()),
        MINING_ATTEMPTS,
    )
    .unwrap();
    let connected = connect_block(&mut state, &block, &params, NOW).unwrap();
    let after = state.state_root();

    disconnect_block(&mut state, &connected);
    connect_block(&mut state, &block, &params, NOW).unwrap();
    assert_eq!(state.state_root(), after);
}

#[test]
fn the_reward_follows_the_schedule_rather_than_the_miner() {
    // A halving every four blocks, so the whole schedule fits in a test.
    let mut params = ConsensusParams::testnet();
    params.halving_interval = 4;
    params.tail_reward = Amount::from_cairn("3").unwrap();

    let miner = wallet(1);
    let mut state = LedgerState::new();

    let mut paid = Vec::new();
    for _ in 0..24u64 {
        let height = state.next_height().unwrap();
        let reward = params.reward_at(height);
        paid.push(reward);

        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(reward, miner.public_key())], [0; 8]);
        let block = assemble_block(
            &state,
            coinbase,
            Vec::new(),
            &params,
            1_000 + height * SPACING,
            0,
        )
        .unwrap();
        let block = mine_block(block, MINING_ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
    }

    assert_eq!(paid[0], params.initial_reward);
    assert_eq!(
        paid[3], params.initial_reward,
        "it holds through the interval"
    );
    assert_eq!(paid[4].as_pebbles(), params.initial_reward.as_pebbles() / 2);
    assert_eq!(paid[8].as_pebbles(), params.initial_reward.as_pebbles() / 4);
    assert_eq!(
        paid[23], params.tail_reward,
        "and settles on the floor it never leaves"
    );

    // A miner cannot help itself to the earlier, larger reward.
    let height = state.next_height().unwrap();
    let greedy = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
        [0; 8],
    );
    assert!(matches!(
        assemble_block(&state, greedy, Vec::new(), &params, 90_000, 0),
        Err(BlockError::CoinbaseOverpay { .. })
    ));
}

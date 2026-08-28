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
    let mut state = LedgerState::archiving();

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
    let mut state = LedgerState::archiving();

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
    let mut state = LedgerState::archiving();

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
    let mut state = LedgerState::archiving();

    for _ in 0..12 {
        mine(&mut state, &params, &miner, Vec::new());
    }

    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
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
    let mut state = LedgerState::archiving();

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

    let cold_position = state.cold().locate(&cold_id, &cold_note).expect("it fell");
    let cold_proof = state
        .cold()
        .prove(cold_position)
        .expect("an archivist can prove it");
    let mut from_cold = Transfer::new(
        vec![Input::cold(cold_id, cold_note, cold_position, cold_proof)],
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
    let mut state = LedgerState::archiving();

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
    let mut state = LedgerState::archiving();

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
    let mut state = LedgerState::archiving();

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
    let mut state = LedgerState::archiving();

    let mut paid = Vec::new();
    for _ in 0..24u64 {
        let height = state.next_height().unwrap();
        let reward = params.reward_at(height);
        paid.push(reward);

        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(reward, miner.public_key())]);
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
    );
    assert!(matches!(
        assemble_block(&state, greedy, Vec::new(), &params, 90_000, 0),
        Err(BlockError::CoinbaseOverpay { .. })
    ));
}

#[test]
fn a_pinned_network_refuses_a_chain_that_starts_elsewhere() {
    let params = ConsensusParams::for_network("devnet").expect("devnet exists");
    let miner = wallet(1);
    let mut state = LedgerState::new();

    // A first block of one's own, perfectly valid on its own terms.
    let coinbase = CoinbaseTransaction::new(
        0,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let mine_alone = assemble_block(
        &state,
        coinbase,
        Vec::new(),
        &params,
        params.opens_at + 60,
        0,
    )
    .unwrap();

    // Not even mined: where a chain starts is settled before the work behind
    // it is looked at, because a chain starting elsewhere is not this one
    // however much work it carries.
    assert!(
        matches!(
            connect_block(&mut state, &mine_alone, &params, NOW),
            Err(BlockError::WrongGenesis { .. })
        ),
        "two people starting alone must not end up on two chains without noticing"
    );

    // The one the network actually starts from is taken.
    let opening = cairn_ledger::genesis::block(params.network).expect("devnet has one");
    assert!(connect_block(&mut state, &opening, &params, NOW).is_ok());
    assert_eq!(state.tip().unwrap().id, params.genesis.unwrap());
}

#[test]
fn nothing_may_be_dated_before_the_network_opened() {
    let params = ConsensusParams::for_network("devnet").expect("devnet exists");
    let miner = wallet(1);
    let mut state = LedgerState::new();

    let opening = cairn_ledger::genesis::block(params.network).unwrap();
    connect_block(&mut state, &opening, &params, NOW).unwrap();

    let coinbase = CoinbaseTransaction::new(
        1,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let backdated = assemble_block(
        &state,
        coinbase,
        Vec::new(),
        &params,
        params.opens_at - 1,
        0,
    )
    .unwrap();

    assert!(matches!(
        connect_block(&mut state, &backdated, &params, NOW),
        Err(BlockError::BeforeTheNetworkOpened { .. })
    ));
}

#[test]
fn a_first_block_already_takes_real_work() {
    // Otherwise the opening seconds are a race the rest of the world has not
    // been told about yet.
    for name in ["testnet-2", "devnet"] {
        let params = ConsensusParams::for_network(name).expect("it exists");
        assert!(
            params.genesis_difficulty > 1_000_000,
            "{name} opens at difficulty {}",
            params.genesis_difficulty
        );
        let opening = cairn_ledger::genesis::block(params.network).unwrap();
        assert_eq!(opening.header.difficulty, params.genesis_difficulty);
    }
}

/// The two fields that make it possible to join this chain without
/// downloading all of it.
mod joining_without_the_whole_chain {
    use super::*;
    use cairn_ledger::state::header_leaf;
    use cairn_primitives::Hash32;

    /// A header states the work behind it, and cannot make that up.
    ///
    /// Without this check the field would be decoration: someone could hand a
    /// newcomer a short chain wearing a long one's numbers, and sampling it
    /// would prove nothing.
    #[test]
    fn a_header_cannot_overstate_the_work_behind_it() {
        let params = ConsensusParams::testnet();
        let miner = wallet(1);
        let mut state = LedgerState::new();
        mine(&mut state, &params, &miner, Vec::new());

        let mut lying = candidate(&state, &params, &miner, Vec::new());
        lying.header.total_work = lying.header.total_work.saturating_mul(1_000);
        let lying = mine_block(lying, MINING_ATTEMPTS).unwrap();

        match connect_block(&mut state, &lying, &params, NOW) {
            Err(BlockError::WrongTotalWork { expected, found }) => {
                assert!(found > expected, "the lie was upward");
            }
            other => panic!("expected the claim to be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_header_cannot_understate_the_work_behind_it() {
        let params = ConsensusParams::testnet();
        let miner = wallet(1);
        let mut state = LedgerState::new();
        mine(&mut state, &params, &miner, Vec::new());

        let mut lying = candidate(&state, &params, &miner, Vec::new());
        lying.header.total_work = 1;
        let lying = mine_block(lying, MINING_ATTEMPTS).unwrap();

        assert!(matches!(
            connect_block(&mut state, &lying, &params, NOW),
            Err(BlockError::WrongTotalWork { .. })
        ));
    }

    /// Work accumulates exactly, block by block.
    #[test]
    fn the_work_a_header_states_is_everything_behind_it() {
        let params = ConsensusParams::testnet();
        let miner = wallet(1);
        let mut state = LedgerState::new();

        let mut running = 0u128;
        for _ in 0..6 {
            let (block, _) = mine(&mut state, &params, &miner, Vec::new());
            running += cairn_ledger::pow::work_of(block.header.difficulty);
            assert_eq!(block.header.total_work, running);
            assert_eq!(state.total_work(), running);
        }
    }

    /// A header commits to every header before it, and cannot claim a history
    /// this chain did not produce.
    #[test]
    fn a_header_cannot_claim_a_history_it_did_not_follow() {
        let params = ConsensusParams::testnet();
        let miner = wallet(1);
        let mut state = LedgerState::new();
        mine(&mut state, &params, &miner, Vec::new());

        let mut lying = candidate(&state, &params, &miner, Vec::new());
        lying.header.history = Hash32::ZERO;
        let lying = mine_block(lying, MINING_ATTEMPTS).unwrap();

        assert!(matches!(
            connect_block(&mut state, &lying, &params, NOW),
            Err(BlockError::HistoryMismatch { .. })
        ));
    }

    /// The commitment moves with every block, and folds in the one just
    /// applied rather than lagging behind it.
    #[test]
    fn the_history_commitment_takes_in_each_block_as_it_lands() {
        let params = ConsensusParams::testnet();
        let miner = wallet(1);
        let mut state = LedgerState::new();

        let mut leaves = Vec::new();
        for height in 0..5u64 {
            let before = state.history_root();
            let (block, _) = mine(&mut state, &params, &miner, Vec::new());
            assert_eq!(
                block.header.history, before,
                "a header commits to the headers before it, not to itself"
            );
            assert_ne!(state.history_root(), before, "the commitment moved");
            assert_eq!(state.headers_committed(), height + 1);
            leaves.push(header_leaf(&block.id()));
        }

        // Every header went in once, under its own leaf, and no two are alike.
        leaves.sort_unstable();
        leaves.dedup();
        assert_eq!(leaves.len(), 5);
    }

    /// Undoing a block puts the commitment back exactly, which a reorganisation
    /// depends on.
    #[test]
    fn undoing_a_block_puts_the_history_back() {
        let params = ConsensusParams::testnet();
        let miner = wallet(1);
        let mut state = LedgerState::new();
        mine(&mut state, &params, &miner, Vec::new());

        let before = state.history_root();
        let work_before = state.total_work();
        let (_, connected) = mine(&mut state, &params, &miner, Vec::new());
        assert_ne!(state.history_root(), before);

        disconnect_block(&mut state, &connected);
        assert_eq!(state.history_root(), before);
        assert_eq!(state.total_work(), work_before);
    }

    /// Two nodes fed the same blocks agree on the commitment, which is what
    /// makes it worth putting in a header at all.
    #[test]
    fn two_nodes_given_the_same_blocks_commit_to_the_same_history() {
        let params = ConsensusParams::testnet();
        let miner = wallet(1);
        let mut ours = LedgerState::new();
        let mut blocks = Vec::new();
        for _ in 0..7 {
            let (block, _) = mine(&mut ours, &params, &miner, Vec::new());
            blocks.push(block);
        }

        let mut theirs = LedgerState::new();
        for block in &blocks {
            connect_block(&mut theirs, block, &params, NOW).unwrap();
        }
        assert_eq!(ours.history_root(), theirs.history_root());
        assert_eq!(ours.total_work(), theirs.total_work());
    }
}

/// A block is bounded by what it takes, not only by what it holds.
///
/// The counts on transfers, inputs and outputs bound the shape of a block.
/// Multiplied out they allow one of over two gigabytes, which no network
/// carries: a miner could produce a block that is valid and cannot be handed
/// to anyone, and would then be following a chain nobody else can follow. The
/// limit that matters is the one on bytes, and it is checked on the encoding a
/// node actually received.
#[test]
fn a_block_larger_than_the_rules_allow_is_refused() {
    let mut params = ConsensusParams::testnet();
    // Small enough that a handful of notes passes it, so this test builds a
    // block rather than a gigabyte.
    params.max_block_bytes = 512;
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let fat = CoinbaseTransaction::new(
        0,
        vec![
            Note::new(
                Amount::from_pebbles(params.initial_reward.as_pebbles() / 16).unwrap(),
                miner.public_key()
            );
            16
        ],
    );
    let block = assemble_block(&state, fat, Vec::new(), &params, 1_000, 0).unwrap();
    let solved = mine_block(block, MINING_ATTEMPTS).expect("a nonce exists");

    let bytes = cairn_primitives::codec::Encode::encode(&solved).len();
    assert!(
        bytes > params.max_block_bytes,
        "the block has to be over it"
    );
    assert!(
        matches!(
            connect_block(&mut state, &solved, &params, NOW),
            Err(BlockError::BlockTooLarge { .. })
        ),
        "a block of {bytes} bytes passed a limit of {}",
        params.max_block_bytes
    );

    // And the same block is fine once the rules allow its size.
    params.max_block_bytes = 4096;
    assert!(connect_block(&mut state, &solved, &params, NOW).is_ok());
}

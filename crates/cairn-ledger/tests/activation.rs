//! What a scheduled rule change does, and what it deliberately does not do.
//!
//! Renumbering the network throws the chain away, which cost nothing three
//! times over because the currency was worthless. Once it is not, a rule that
//! changes has to leave every block already mined exactly as valid as it was.
//!
//! So the rules a block is judged by are the rules of its height. A change
//! names the height it starts at, blocks before it go on being judged as they
//! always were, and nobody votes on any of it.
//!
//! The other half is what a node does when the height it has reached is
//! governed by rules it does not have. It must not treat that as a bad block:
//! every peer that had updated would be sending the same one, so refusing them
//! leaves it following whoever had not updated either, a minority chain
//! believed to be the chain. It says which version it needs, and stops.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, BlockError, ConsensusParams,
};
use cairn_ledger::{Block, LedgerState};

const NOW: u64 = 2_000_000_000;
const SPACING: u64 = 600;
const MINING_ATTEMPTS: u64 = 1 << 22;

/// A rule change scheduled at height five, written under a version this build
/// does not have. Which is the situation of every node that has not updated.
const AHEAD: &[Activation] = &[
    Activation {
        height: 0,
        version: BLOCK_VERSION,
    },
    Activation {
        height: 5,
        version: BLOCK_VERSION + 1,
    },
];

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn mine(state: &mut LedgerState, params: &ConsensusParams, miner: &SecretKey) -> Block {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let candidate = assemble_block(
        state,
        coinbase,
        Vec::new(),
        params,
        1_000 + height * SPACING,
        0,
    )
    .expect("a block this build can judge");
    let block = mine_block(candidate, MINING_ATTEMPTS).expect("a nonce exists at this difficulty");
    connect_block(state, &block, params, NOW).expect("it holds");
    block
}

#[test]
fn the_rules_of_a_height_are_the_rules_that_were_in_force_there() {
    let params = ConsensusParams {
        activations: AHEAD,
        ..ConsensusParams::testnet()
    };

    for height in 0..5 {
        assert_eq!(
            params.version_at(height),
            BLOCK_VERSION,
            "height {height} is before the change"
        );
    }
    for height in [5u64, 6, 1_000, u64::MAX] {
        assert_eq!(
            params.version_at(height),
            BLOCK_VERSION + 1,
            "height {height} is at or after it"
        );
    }
}

#[test]
fn a_network_with_nothing_scheduled_asks_for_the_version_this_build_knows() {
    let params = ConsensusParams::testnet();
    for height in [0u64, 1, 1_000_000, u64::MAX] {
        assert_eq!(params.version_at(height), BLOCK_VERSION);
    }
}

#[test]
fn what_was_mined_before_a_change_stays_valid_after_it_is_scheduled() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();

    // A chain mined while nothing was scheduled.
    let mut before = LedgerState::archiving();
    let blocks: Vec<Block> = (0..5).map(|_| mine(&mut before, &plain, &miner)).collect();

    // The same blocks, offered to a node that knows a change is coming at the
    // height just past them. Nothing about them may have changed: this is the
    // whole difference between scheduling a rule and renumbering the network.
    let announced = ConsensusParams {
        activations: AHEAD,
        ..plain
    };
    let mut after = LedgerState::archiving();
    for block in &blocks {
        connect_block(&mut after, block, &announced, NOW)
            .expect("a block keeps the validity it was mined with");
    }

    assert_eq!(
        after.state_root(),
        before.state_root(),
        "the announcement moved nothing"
    );
    assert_eq!(after.tip(), before.tip());
}

#[test]
fn a_height_this_build_has_no_rules_for_is_its_own_problem_not_the_block_s() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();

    let mut state = LedgerState::archiving();
    for _ in 0..5 {
        mine(&mut state, &plain, &miner);
    }
    // Height five, mined by a network that has the rules for it.
    let height = state.next_height().unwrap();
    assert_eq!(height, 5);
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(plain.initial_reward, miner.public_key())],
    );
    let candidate = assemble_block(
        &state,
        coinbase,
        Vec::new(),
        &plain,
        1_000 + height * SPACING,
        0,
    )
    .unwrap();
    let block = mine_block(candidate, MINING_ATTEMPTS).unwrap();

    // The same block, at a node whose schedule says height five is judged by
    // rules it does not have.
    let announced = ConsensusParams {
        activations: AHEAD,
        ..plain
    };
    let refused = connect_block(&mut state, &block, &announced, NOW).unwrap_err();

    assert_eq!(
        refused,
        BlockError::SoftwareTooOld {
            height: 5,
            required: BLOCK_VERSION + 1,
            known: BLOCK_VERSION,
        },
        "the node says it is too old, not that the block is bad"
    );
    assert!(
        !matches!(refused, BlockError::UnsupportedVersion(_)),
        "told apart from a block carrying a version that was never a rule"
    );
}

#[test]
fn a_producer_does_not_make_a_block_it_could_not_judge() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();
    let announced = ConsensusParams {
        activations: AHEAD,
        ..plain
    };

    let mut state = LedgerState::archiving();
    for _ in 0..5 {
        mine(&mut state, &plain, &miner);
    }

    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(announced.initial_reward, miner.public_key())],
    );
    let refused = assemble_block(
        &state,
        coinbase,
        Vec::new(),
        &announced,
        1_000 + height * SPACING,
        0,
    )
    .unwrap_err();

    assert_eq!(
        refused,
        BlockError::SoftwareTooOld {
            height: 5,
            required: BLOCK_VERSION + 1,
            known: BLOCK_VERSION,
        },
        "a miner on an outdated build stops rather than mining a fork of one"
    );
}

//! What a node holding only its network's pinned first block is.
//!
//! A node on a named network lays that block down the moment it starts, so it
//! knows where the story starts before it has spoken to anybody. Every chain on
//! the network begins with it, so holding it chooses none of them: such a node
//! is still free to be handed a ledger, and nothing more is.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{ChainError, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

/// A clock in 2033, past the devnet's first block and every block after it.
const NOW: u64 = 2_000_000_000;

fn devnet() -> ConsensusParams {
    ConsensusParams::for_network("devnet").expect("the devnet is a network this build ships")
}

/// `count` blocks after the first block `params` pin, or after a first block
/// of their own on rules that pin nothing.
fn blocks_after_the_first(params: ConsensusParams, count: usize) -> Vec<Block> {
    let miner = SecretKey::from_bytes(&[1; 32]).public_key();
    let mut state = LedgerState::new();
    let mut made = Vec::new();
    let mut clock = 1_000_000;
    if let Some(first) =
        cairn_ledger::genesis::block(params.network).filter(|_| params.genesis.is_some())
    {
        clock = first.header.timestamp;
        connect_block(&mut state, &first, &params, NOW).unwrap();
        made.push(first);
    }
    while made.len() <= count {
        let height = state.next_height().unwrap();
        clock += 60;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(params.reward_at(height), miner)]);
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, 1 << 28).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        made.push(block);
    }
    made
}

/// The devnet's first block and one more, mined once for the whole file: a
/// block at the devnet's opening difficulty is seconds of work.
fn on_the_devnet() -> &'static [Block] {
    static MADE: std::sync::OnceLock<Vec<Block>> = std::sync::OnceLock::new();
    MADE.get_or_init(|| blocks_after_the_first(devnet(), 1))
}

fn holding(params: ConsensusParams, blocks: &[Block]) -> ChainStore {
    let mut chain = ChainStore::new(params);
    for block in blocks {
        chain.add_block(block.clone(), NOW).unwrap();
    }
    chain
}

/// A node holding only the first block its network pins holds nothing of its
/// own, and is handed a ledger over it.
///
/// Nothing asked this, so a node that refused every ledger once it had laid
/// that block down passed, and so did every newcomer on the real networks that
/// read the whole chain instead of being handed it: every test of `adopt` ran
/// on rules that pin nothing, where a node that has not started has no block
/// at all.
#[test]
fn a_node_holding_only_the_pinned_first_block_is_handed_a_ledger_over_it() {
    let params = devnet();
    let made = on_the_devnet();
    let source = holding(params, made);
    let headers: Vec<_> = made.iter().map(|block| block.header).collect();

    let empty = ChainStore::new(params);
    assert!(
        empty.holds_nothing_of_its_own(),
        "a node with no block at all holds something of its own"
    );

    let mut newcomer = holding(params, &made[..1]);
    assert!(
        !newcomer.is_empty(),
        "the premise: it holds the first block"
    );
    assert!(
        newcomer.holds_nothing_of_its_own(),
        "a node holding only the block every chain of its network starts from was taken \
         to have chosen a chain"
    );
    assert_eq!(
        newcomer.adopt(source.state().clone(), &headers),
        Ok(()),
        "a node holding only its network's first block refused a ledger"
    );
    assert_eq!(newcomer.height(), Some(1));
    assert_eq!(newcomer.tip(), source.tip());
    assert!(
        !newcomer.holds_nothing_of_its_own(),
        "a node that has adopted a ledger still says it holds nothing of its own"
    );
}

/// One block past the pinned one is a chain, and a ledger is not adopted over
/// it; nor over a first block that the rules do not pin.
///
/// Nothing asked this, so a node that took any ledger over a chain of its own
/// passed as long as the chain had started at the right block.
#[test]
fn a_block_past_the_first_or_a_first_block_nobody_pinned_is_a_chain() {
    let params = devnet();
    let made = on_the_devnet();
    let source = holding(params, made);
    let headers: Vec<_> = made.iter().map(|block| block.header).collect();

    let mut read_one = holding(params, made);
    assert!(
        !read_one.holds_nothing_of_its_own(),
        "a node one block past its network's first block said it holds nothing of its own"
    );
    assert_eq!(
        read_one.adopt(source.state().clone(), &headers),
        Err(ChainError::AlreadyFollowing),
        "a ledger replaced a chain a node had read past the first block"
    );

    let unpinned = ConsensusParams::testnet();
    let first = blocks_after_the_first(unpinned, 0);
    let started = holding(unpinned, &first);
    assert!(
        !started.holds_nothing_of_its_own(),
        "on rules that pin nothing, a first block was taken for the one every chain shares"
    );
}

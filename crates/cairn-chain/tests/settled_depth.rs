//! A node must not undo past what its own network calls settled.
//!
//! Devnet lowers the burial to thirty two so a throwaway chain settles in
//! minutes, and lowers the coinbase maturity with it. Both say the same thing:
//! below that depth, nothing moves. A node that went on accepting a switch a
//! thousand blocks deep would be saying the opposite at the same time. It
//! would hand a newcomer a ledger anchored at a block it then orphaned, and
//! take back a reward its own rules had already called spendable.
//!
//! So the depth the switch is refused at follows the network's burial rather
//! than the constant this build could undo. What is held in memory still
//! follows the constant, which is a memory bound and is safe to overshoot.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::HashMap;
use std::sync::Arc;

use cairn_chain::{Accepted, Bodies, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The depth devnet buries at, and the fork this test puts just past it.
const SHORT_BURIAL: u64 = 32;
const FORK_AT: usize = 6;
const FOLLOWED: usize = 40;
const RIVAL: usize = 41;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Mines blocks on a private ledger, so a branch can be built off to the side.
#[derive(Clone)]
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_many(&mut self, miner: &SecretKey, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine(miner)).collect()
    }
}

/// Feeds a node the branch it follows, then a heavier rival forking
/// `FOLLOWED - FORK_AT` blocks back, and answers whether the node switched.
///
/// Both branches carry the same difficulty, so the longer one is the heavier
/// one and a node that is allowed to reach the fork will take it.
fn switches_onto_a_rival_forking_that_far_back(burial: u64) -> bool {
    let params = ConsensusParams::testnet()
        .with_burial(burial)
        .with_coinbase_maturity(burial);

    let mut base = Forge::new(params);
    let common = base.mine_many(&wallet(1), FORK_AT);
    let mut ours = base.clone();
    let mut theirs = base;

    let followed = ours.mine_many(&wallet(1), FOLLOWED - FORK_AT);
    let rival = theirs.mine_many(&wallet(9), RIVAL - FORK_AT);

    let mut store = ChainStore::new(params);
    for block in common.iter().chain(followed.iter()) {
        assert_eq!(
            store.add_block(block.clone(), NOW).unwrap(),
            Accepted::Extended,
            "the branch this node follows is its own"
        );
    }
    let tip = store.tip().unwrap();

    for block in &rival {
        // A refusal is the point on the short network, so failures here are
        // the answer rather than a reason to stop.
        let _ = store.add_block(block.clone(), NOW);
    }

    store.tip().unwrap() != tip
}

#[test]
fn a_node_will_not_undo_past_what_its_network_buries_at() {
    assert!(
        !switches_onto_a_rival_forking_that_far_back(SHORT_BURIAL),
        "a network that calls thirty two blocks settled must not undo thirty four"
    );
}

#[test]
fn the_same_fork_is_taken_where_the_network_buries_deeper() {
    assert!(
        switches_onto_a_rival_forking_that_far_back(1_024),
        "the refusal has to come from the burial, not from the shape of the test"
    );
}

/// A header outlives its body, and asking for one must not need the other.
///
/// A chain lets go of block bodies once they are on disk and far enough back,
/// which is what keeps its memory from growing with the chain. The headers
/// stay: they are what the fork choice and the branch walk read, and they are
/// a hundred and eighty two bytes against as much as a hundred and twenty
/// eight kilobytes.
///
/// Anything filling a header log has to be able to read them there. Asking for
/// the block instead is asking to be refused a header for the want of a body
/// it has no use for, and a node whose header log fell behind by more than the
/// warm window could then never fill it again.
#[test]
fn a_header_can_be_read_where_the_body_has_been_let_go_of() {
    let params = ConsensusParams::testnet();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(&wallet(1), 200);

    let mut store = ChainStore::new(params);
    // Somewhere to read a body back from, which is what lets a store part with
    // one. A node's is its block log.
    store.reads_bodies_from(Arc::new(Shelf(
        blocks
            .iter()
            .map(|block| (block.header.height, block.clone()))
            .collect(),
    )));
    for block in &blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }
    store.release_bodies(0, store.height().unwrap() + 1);

    let held = store.held_from();
    let released = blocks
        .iter()
        .map(|block| block.header.height)
        .find(|height| *height >= held && store.block_at(*height).is_none())
        .expect("some body outside the warm window was let go of");

    assert_eq!(
        store.header_at(released).map(|header| header.height),
        Some(released),
        "the header went with the body, so nothing could fill a header log"
    );
    assert!(
        store.header_at(held).is_some(),
        "and the lowest height it still answers for is one it answers for"
    );
}

/// Somewhere to read bodies back from, keyed by height, the way a node's block
/// log is.
#[derive(Debug)]
struct Shelf(HashMap<u64, Block>);

impl Bodies for Shelf {
    fn body(&self, height: u64) -> Option<Block> {
        self.0.get(&height).cloned()
    }
}

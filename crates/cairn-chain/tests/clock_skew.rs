//! A verdict the clock reverses must not be remembered against a header.
//!
//! Every other refusal a header settles is a fact about the header: a wrong
//! network, a parent that is not there, work that was not done. One is not.
//! A timestamp too far ahead is measured against the reading node's own clock,
//! so two honest nodes disagree about it, and the same node reverses it by
//! waiting. Remembering it made one second of clock skew permanent: a miner
//! publishing a block dated at the edge of the drift the rules allow, which
//! costs nothing and is valid to everybody whose clock is right, put that block
//! on the blacklist of every node running slightly slow, and those nodes then
//! refused the whole chain through it for good.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{Accepted, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// Builds the chain a node is following, and then one more block on top of it
/// dated as far ahead as the rules allow.
struct Chain {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: NOW,
        }
    }

    fn mine(&mut self, miner: &SecretKey, at: u64) -> Block {
        let height = self.state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(&self.state, coinbase, Vec::new(), &self.params, at, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, at).unwrap();
        block
    }

    fn steady(&mut self, miner: &SecretKey) -> Block {
        self.clock += 600;
        let at = self.clock;
        self.mine(miner, at)
    }
}

#[test]
fn a_block_refused_for_this_node_s_clock_is_taken_once_the_clock_catches_up() {
    let miner = wallet(1);
    let mut source = Chain::new();
    let mut store = ChainStore::new(params());

    let mut settled = NOW;
    for _ in 0..4 {
        let block = source.steady(&miner);
        settled = block.header.timestamp;
        store.add_block(block, settled).unwrap();
    }

    // Valid to everybody whose clock is right, and free to produce.
    let drift = params().max_timestamp_drift;
    let ahead = source.mine(&miner, settled + drift);
    let id = ahead.header.id();

    // This node's clock is one second slow, so for it the block is one second
    // past the edge.
    let refused = store.add_block(ahead.clone(), settled.saturating_sub(1));
    assert!(
        refused.is_err(),
        "a node running slow refuses it, which is the rule working"
    );

    // The rule is transient, so the refusal has to be too. Offered again once
    // this node's clock has reached the same reading, it is an ordinary block.
    let taken = store
        .add_block(ahead, settled + drift)
        .expect("the same block, once this node's clock has caught up");
    assert_eq!(
        taken,
        Accepted::Extended,
        "the block extends the chain rather than being condemned"
    );
    assert_eq!(store.tip(), Some(id), "the node followed it");
}

/// The consequence the finding was really about: the block above is the parent
/// of everything mined after it, so remembering it against its header did not
/// cost one block, it cost the chain. A node that refused it once went on
/// refusing every block built on it, for ever, with no way back and nothing
/// saying so.
#[test]
fn the_chain_built_on_it_is_not_lost_with_it() {
    let miner = wallet(1);
    let mut source = Chain::new();
    let mut store = ChainStore::new(params());

    let mut settled = NOW;
    for _ in 0..4 {
        let block = source.steady(&miner);
        settled = block.header.timestamp;
        store.add_block(block, settled).unwrap();
    }

    let drift = params().max_timestamp_drift;
    let ahead = source.mine(&miner, settled + drift);
    assert!(
        store
            .add_block(ahead.clone(), settled.saturating_sub(1))
            .is_err(),
        "this node's clock is one second slow, so it refuses the block"
    );

    // The network carries on. An hour later this node is offered the block it
    // refused and the three built on top of it.
    let mut carried_on = vec![ahead];
    for _ in 0..3 {
        source.clock = source.clock.max(settled + drift) + 600;
        let next = source.clock;
        carried_on.push(source.mine(&miner, next));
    }
    let tip = carried_on.last().unwrap().header.id();

    let later = settled + drift + 3_600;
    for block in carried_on {
        store
            .add_block(block, later)
            .expect("nothing here is condemned by a clock that has moved on");
    }
    assert_eq!(
        store.tip(),
        Some(tip),
        "the node caught up with the network"
    );
}

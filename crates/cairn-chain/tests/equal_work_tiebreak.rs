//! The fork choice on a tie in accumulated work.
//!
//! Two branches of exactly equal work are not ordered identically on every
//! node: each keeps the one that reached it first. That is a deliberate
//! choice. Breaking the tie on the lower identifier would settle it at once,
//! and costs more than it buys: a node catching up along a rival branch
//! passes through equal work on the way and would reorganise there, doing
//! extra rewinding to reach the same place one block later regardless.
//!
//! What this holds in place is the size of what that choice costs: the split
//! lasts one block interval, and the next block that extends either branch
//! ends it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

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

    fn fork(&self) -> Self {
        self.clone()
    }
}

/// Both branches are one block on the same parent, with the same timestamp and
/// so the same difficulty and the same work. They differ only in who mined
/// them. A node that saw A first keeps A; a node that saw B first keeps B.
/// Then one more block, and they agree again.
#[test]
fn an_equal_work_split_lasts_one_block_and_then_resolves() {
    let mut base = Forge::new(params());
    let common = base.mine_many(&wallet(1), 4);

    let mut forge_a = base.fork();
    let a = forge_a.mine(&wallet(2));
    let mut forge_b = base.fork();
    let b = forge_b.mine(&wallet(3));

    assert_ne!(a.id(), b.id(), "the two blocks must be genuinely different");
    assert_eq!(
        a.header.total_work, b.header.total_work,
        "the two branches carry exactly the same work"
    );

    // One node hears A, then B.
    let mut node_a = ChainStore::new(params());
    for block in &common {
        node_a.add_block(block.clone(), NOW).unwrap();
    }
    node_a.add_block(a.clone(), NOW).unwrap();
    node_a.add_block(b.clone(), NOW).unwrap();

    // Another hears B, then A.
    let mut node_b = ChainStore::new(params());
    for block in &common {
        node_b.add_block(block.clone(), NOW).unwrap();
    }
    node_b.add_block(b.clone(), NOW).unwrap();
    node_b.add_block(a.clone(), NOW).unwrap();

    assert_eq!(
        node_a.total_work(),
        node_b.total_work(),
        "both nodes carry the same work"
    );

    // Equal work is NOT ordered identically on every node: each keeps the
    // block that reached it first. That is a deliberate choice, not an
    // oversight, and what it costs is exactly this: for one block interval,
    // two honest nodes follow different tips.
    assert_ne!(
        node_a.tip(),
        node_b.tip(),
        "the split is the cost of keeping what arrived first"
    );

    // And what it must not cost is more than that interval. A block extending
    // either branch outweighs the other, and both nodes land on it.
    assert_eq!(node_a.tip(), Some(a.id()));
    assert_eq!(node_b.tip(), Some(b.id()));

    let after = forge_a.mine(&wallet(2));
    node_a.add_block(after.clone(), NOW).unwrap();
    node_b.add_block(after.clone(), NOW).unwrap();
    assert_eq!(
        node_a.tip(),
        node_b.tip(),
        "one more block and the two nodes agree again: a {:?} b {:?}",
        node_a.tip(),
        node_b.tip()
    );
    assert_eq!(
        node_b.tip(),
        Some(after.id()),
        "and it is the heavier branch"
    );
}

//! A failed reorganisation must restore the branch it left, including bodies
//! it released from memory and reads back from disk.
//!
//! This exercises the interaction the scoping calls invariant 3 and 4: a body
//! released by `release_bodies` and then removed from the place it is read
//! back from (which is what a node's `trim_history` does when it clears the
//! block log) is a body a failed reorganisation can no longer restore.

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

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

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

    fn fork(&self) -> Self {
        self.clone()
    }
}

/// Somewhere to read bodies back from, keyed by height, the way a node's block
/// log is. Emptying it is what a node's `trim_history` does when it clears the
/// log down to the tip.
#[derive(Debug)]
struct Shelf(HashMap<u64, Block>);

impl Shelf {
    fn holding(blocks: &[Block]) -> Self {
        Self(
            blocks
                .iter()
                .map(|block| (block.header.height, block.clone()))
                .collect(),
        )
    }

    fn empty() -> Self {
        Self(HashMap::new())
    }
}

impl Bodies for Shelf {
    fn body(&self, height: u64) -> Option<Block> {
        self.0.get(&height).cloned()
    }
}

/// The scenario both tests share: a common prefix, a good branch this node
/// follows, and a heavier bad branch whose last block cannot be applied.
///
/// The fork is deeper than `WARM_BODIES` (64), so restoring the good branch
/// after the bad one fails means re-applying blocks whose bodies were
/// released and have to be read back.
struct Scenario {
    common: Vec<Block>,
    good: Vec<Block>,
    bad: Vec<Block>,
    good_tip_height: u64,
}

fn scenario() -> Scenario {
    let miner = wallet(1);
    let rival = wallet(9);

    let mut base = Forge::new(params());
    let common = base.mine_many(&miner, 5); // heights 0..=4

    let mut good_forge = base.fork();
    let good = good_forge.mine_many(&miner, 70); // heights 5..=74

    let mut bad_forge = base.fork();
    let mut bad = bad_forge.mine_many(&rival, 71); // heights 5..=75, heavier

    // Break the last block of the heavier branch, so the switch onto it is
    // only found to be impossible once every earlier block has been applied.
    let last = bad.len() - 1;
    let mut broken = bad[last].clone();
    broken.header.state_root = cairn_primitives::Hash32::ZERO;
    bad[last] = mine_block(broken, ATTEMPTS).unwrap();

    let good_tip_height = good.last().unwrap().header.height;
    Scenario {
        common,
        good,
        bad,
        good_tip_height,
    }
}

fn feed(store: &mut ChainStore, blocks: &[Block]) {
    for block in blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }
}

/// The control: bodies are kept where they can be read back, so a failed
/// reorganisation restores the branch it left, exactly as it should.
///
/// This is the same scenario as the test below with one difference — the
/// shelf still holds the released bodies. It passing while the other fails is
/// what shows the failure is the missing bodies and nothing else.
#[test]
fn a_failed_reorg_restores_the_branch_when_bodies_can_be_read_back() {
    let s = scenario();

    let mut store = ChainStore::new(params());
    let mut on_disk = s.common.clone();
    on_disk.extend(s.good.iter().cloned());
    store.reads_bodies_from(Arc::new(Shelf::holding(&on_disk)));

    feed(&mut store, &s.common);
    feed(&mut store, &s.good);

    // Let go of the bodies of everything but the warm window, as a node does
    // once they are on disk. The shelf holds the chain from its first block.
    store.release_bodies(0, s.good_tip_height + 1);

    // The bad branch is heavier only on its last block, so nothing switches
    // until the block that cannot be applied.
    for block in &s.bad[..s.bad.len() - 1] {
        assert_eq!(
            store.add_block(block.clone(), NOW),
            Ok(Accepted::SideBranch)
        );
    }
    let outcome = store.add_block(s.bad.last().unwrap().clone(), NOW);
    assert!(outcome.is_err(), "the broken block is refused: {outcome:?}");

    assert_eq!(
        store.height(),
        Some(s.good_tip_height),
        "the node is back on the good branch it was following"
    );
    assert_eq!(store.tip(), Some(s.good.last().unwrap().id()));
}

/// The bug this closed, kept as the case that must not come back.
///
/// Bodies were let go of, and the place they are read back from was then
/// emptied — a node's upkeep dropping blocks off the front of its log. A
/// reorganisation that failed could no longer restore the branch it left, and
/// the node was stranded at the fork, on neither branch.
///
/// A body is now let go of only from where the log begins, so an operator's
/// budget trades disk against memory rather than against being able to put a
/// branch back. Here that is said as: told the shelf holds nothing, the chain
/// releases nothing, and the failed switch still restores.
#[test]
fn a_body_is_not_let_go_of_below_what_the_shelf_holds() {
    let s = scenario();

    let mut store = ChainStore::new(params());
    let mut on_disk = s.common.clone();
    on_disk.extend(s.good.iter().cloned());
    store.reads_bodies_from(Arc::new(Shelf::holding(&on_disk)));

    feed(&mut store, &s.common);
    feed(&mut store, &s.good);

    // The log holds nothing: everything below the tip was dropped. A node in
    // that state may let go of nothing, which is what the first argument says.
    store.reads_bodies_from(Arc::new(Shelf::empty()));
    store.release_bodies(s.good_tip_height + 1, s.good_tip_height + 1);

    for block in &s.bad[..s.bad.len() - 1] {
        assert_eq!(
            store.add_block(block.clone(), NOW),
            Ok(Accepted::SideBranch)
        );
    }
    let outcome = store.add_block(s.bad.last().unwrap().clone(), NOW);
    assert!(outcome.is_err(), "the broken block is refused: {outcome:?}");

    // The invariant: a failed switch leaves the node where it was, having
    // lost the whole branch it was following.
    assert_eq!(
        store.height(),
        Some(s.good_tip_height),
        "a failed reorganisation must restore the branch it left, not strand \
         the node at the fork (found height {:?}, tip {:?})",
        store.height(),
        store.tip(),
    );
    assert_eq!(store.tip(), Some(s.good.last().unwrap().id()));
}

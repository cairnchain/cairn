//! AUDIT: a clock that steps backwards must not cost a node its own branch.
//!
//! A failed switch puts back what it rolled back, and `restore` used to put
//! those blocks back through the same door a stranger's block comes in by,
//! against the clock as it reads now. Every rule that door applies is a fact
//! about the chain and answers the same way twice. One is not: the drift
//! ceiling is measured against the reading node's own clock, and a clock can
//! step backwards. An NTP correction, a restored snapshot, a dead battery, a
//! machine that dual boots.
//!
//! So a node that had applied a run of blocks, rewound them for a heavier
//! branch, and found that branch bad, refused to put its own blocks back: they
//! were now dated hours into a future its clock had retreated from. The rewind
//! stood, the refusal that came back named the wrong block, and nothing
//! re-applied the lost run until a peer happened to offer one of those blocks
//! again.
//!
//! Both tests here build the same shape and differ only in where the clock
//! stands, so what they measure is the clock and nothing else.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{Accepted, ChainError, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, BlockError, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Hash32;

/// The moment the chain below opens.
const T0: u64 = 2_000_000_000;

/// The height the followed branch and the rival part company at.
const FORK: u64 = 1;

/// Blocks the followed branch carries above the fork, and so blocks a failed
/// switch has to put back.
const ROLLED_BACK: usize = 5;

/// The first rival block is dated here, close behind the fork so that a clock
/// stepped back far enough to refuse the restored blocks still accepts it.
const RIVAL_OPENS_AT: u64 = T0 + 700;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// The chain a node follows, mined through the ordinary rules.
///
/// `testnet()` opens at the difficulty floor, where every identifier meets the
/// target, so no nonce has to be searched for and the fixture costs nothing.
/// What is measured here is the bookkeeping around a failed switch, not the
/// work behind a block.
struct Miner {
    params: ConsensusParams,
    state: LedgerState,
    key: SecretKey,
}

impl Miner {
    fn new(seed: u8) -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            key: SecretKey::from_bytes(&[seed; 32]),
        }
    }

    /// This chain as it stands, to mine a rival branch on from here.
    fn forked(&self, seed: u8) -> Self {
        Self {
            params: params(),
            state: self.state.clone(),
            key: SecretKey::from_bytes(&[seed; 32]),
        }
    }

    /// The next block, assembled and not applied.
    fn next(&self, at: u64) -> Block {
        let height = self.state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, self.key.public_key())],
        );
        assemble_block(&self.state, coinbase, Vec::new(), &self.params, at, 0).unwrap()
    }

    /// The next block, applied.
    fn mine(&mut self, at: u64) -> Block {
        let block = self.next(at);
        connect_block(&mut self.state, &block, &self.params, at).unwrap();
        block
    }
}

/// The branch this node follows: a genesis, the fork block, and five above it,
/// along with the chain as it stood at the fork.
///
/// The five sit far enough past the fork that a clock stepped back by the
/// drift refuses every one of them, which is the scenario.
fn followed() -> (Miner, Vec<Block>) {
    let mut miner = Miner::new(1);
    let mut blocks = vec![miner.mine(T0), miner.mine(T0 + 600)];
    let at_fork = miner.forked(2);
    for step in 0..ROLLED_BACK {
        blocks.push(miner.mine(T0 + 1_800 + 600 * step as u64));
    }
    (at_fork, blocks)
}

/// A heavier branch off the fork whose first block is bad.
///
/// Bad by a state root that does not match what its own body produces, which
/// is a fact about the block rather than about any clock, so the refusal it
/// earns reads the same at every hour of the day. The blocks above it are
/// never judged: they exist to make the branch outweigh the one being
/// followed, so that the node rewinds before it finds out.
fn rival(at_fork: &Miner) -> Vec<Block> {
    let mut bad = at_fork.next(RIVAL_OPENS_AT);
    assert_ne!(
        bad.header.state_root,
        Hash32::ZERO,
        "the tampering has to change the root"
    );
    bad.header.state_root = Hash32::ZERO;

    let mut branch = vec![bad];
    while branch.len() <= ROLLED_BACK {
        let previous = branch.last().unwrap();
        let mut next = previous.clone();
        next.header.previous = previous.header.id();
        next.header.height = previous.header.height + 1;
        next.header.timestamp = previous.header.timestamp + 60;
        next.header.total_work = previous.header.total_work + 1;
        branch.push(next);
    }
    branch
}

/// A node following its branch, with the rival held and one block short of
/// taking it.
fn ready() -> (ChainStore, Vec<Block>, Vec<Block>) {
    let (at_fork, branch) = followed();
    let rival = rival(&at_fork);

    let mut store = ChainStore::new(params());
    for block in &branch {
        store
            .add_block(block.clone(), block.header.timestamp)
            .expect("the branch this node follows");
    }
    assert_eq!(store.height(), Some(FORK + ROLLED_BACK as u64));

    // Every rival block but the last is only held: on its own it does not
    // outweigh the branch being followed, so nothing is switched yet.
    let last = rival.len() - 1;
    for block in &rival[..last] {
        assert_eq!(
            store.add_block(block.clone(), T0 + 4_200).unwrap(),
            Accepted::SideBranch,
            "a lighter branch is held and not followed"
        );
    }
    assert!(
        rival[last].header.total_work > store.total_work(),
        "the rival has to outweigh the branch, or nothing is rewound"
    );
    (store, branch, rival)
}

/// The ledger the branch produces, replayed from nothing.
///
/// The node under test has to end up here exactly, and a branch list that says
/// the right thing over a ledger that does not is the failure worth naming
/// separately: it is the one a height alone would not catch.
fn replayed(branch: &[Block]) -> LedgerState {
    let params = params();
    let mut state = LedgerState::new();
    for block in branch {
        connect_block(&mut state, block, &params, block.header.timestamp).unwrap();
    }
    state
}

/// What the node has to be left with either way: its own branch, whole, with
/// the ledger that belongs under it.
fn assert_branch_is_whole(store: &ChainStore, branch: &[Block], when: &str) {
    let tip = branch.last().unwrap();
    assert_eq!(
        store.height(),
        Some(FORK + ROLLED_BACK as u64),
        "{when}: the node is short by part of its own branch"
    );
    assert_eq!(store.tip(), Some(tip.header.id()), "{when}: the wrong tip");
    for block in branch {
        assert!(
            store.is_active(&block.header.id()),
            "{when}: the block at height {} is off the branch",
            block.header.height
        );
    }

    let whole = replayed(branch);
    assert_eq!(
        store.state().state_root(),
        whole.state_root(),
        "{when}: the branch came back and the ledger under it did not"
    );
    assert_eq!(
        store.state().history_root(),
        whole.history_root(),
        "{when}: the header history did not come back"
    );
    assert_eq!(
        store.state().total_work(),
        whole.total_work(),
        "{when}: the work behind the branch did not come back"
    );
    assert_eq!(
        store.state().supply(),
        whole.supply(),
        "{when}: the money did not come back"
    );
}

/// The finding. The clock has gone back most of two hours, which leaves the
/// rival's first block inside the drift and every block this node would have
/// to put back outside it.
#[test]
fn a_failed_switch_under_a_clock_that_stepped_back_leaves_the_branch_whole() {
    let (mut store, branch, rival) = ready();
    let bad = rival.first().unwrap().header.id();
    let heaviest = rival.last().unwrap().clone();

    // Placed against the drift rather than picked: far enough back that the
    // blocks being restored read as dated in the future, near enough that the
    // rival's own first block does not. So the clock decides the restoring and
    // nothing else.
    let drift = params().max_timestamp_drift;
    let stepped_back = RIVAL_OPENS_AT - drift;
    assert!(
        RIVAL_OPENS_AT <= stepped_back + drift,
        "the rival's first block has to be judged on its own merits"
    );
    let above_the_fork = usize::try_from(FORK).unwrap() + 1;
    for block in &branch[above_the_fork..] {
        assert!(
            block.header.timestamp > stepped_back + drift,
            "a restored block has to sit past the drift, or this test measures \
             nothing"
        );
    }

    let refused = store.add_block(heaviest, stepped_back);
    assert!(
        matches!(
            refused,
            Err(ChainError::InvalidBlock {
                id,
                source: BlockError::StateRootMismatch { .. }
            }) if id == bad
        ),
        "the refusal has to name the rival's bad block rather than one of this \
         node's own: {refused:?}"
    );
    assert_branch_is_whole(
        &store,
        &branch,
        "after a failed switch on a clock that went back",
    );

    // And the node is still a node. Its clock is put right, and the next
    // honest block on its own branch extends it, which only holds if the
    // ledger came back along with the branch.
    let mut miner = Miner::new(1);
    miner.state = replayed(&branch);
    let next = miner.next(T0 + 4_800);
    assert_eq!(
        store.add_block(next.clone(), T0 + 4_800).unwrap(),
        Accepted::Extended,
        "the node could not carry on from where it was left"
    );
    assert_eq!(store.tip(), Some(next.header.id()));
}

/// The same shape with a clock that never moved, which already worked.
///
/// Here so that the test above measures the clock: were this one to fail too,
/// the finding would be about the switch and not about time at all.
#[test]
fn a_failed_switch_under_a_steady_clock_leaves_the_branch_whole() {
    let (mut store, branch, rival) = ready();
    let bad = rival.first().unwrap().header.id();
    let heaviest = rival.last().unwrap().clone();

    let refused = store.add_block(heaviest, T0 + 4_200);
    assert!(
        matches!(
            refused,
            Err(ChainError::InvalidBlock {
                id,
                source: BlockError::StateRootMismatch { .. }
            }) if id == bad
        ),
        "the rival is bad whatever the clock reads: {refused:?}"
    );
    assert_branch_is_whole(&store, &branch, "after a failed switch on a steady clock");
}

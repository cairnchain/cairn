//! Choosing between branches, and rebuilding the ledger when the choice moves.

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
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
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

/// Produces blocks on a private copy of the ledger, so a branch can be built
/// without a node having to follow it.
#[derive(Clone)]
struct Branch {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Branch {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>, spacing: u64) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += spacing;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
            [0; 8],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize, spacing: u64) -> Vec<Block> {
        (0..count)
            .map(|_| self.mine(miner, Vec::new(), spacing))
            .collect()
    }
}

fn coinbase_note(block: &Block, params: &ConsensusParams, miner: &SecretKey) -> (NoteId, Note) {
    (
        NoteId::new(block.coinbase.id(), 0),
        Note::new(params.initial_reward, miner.public_key()),
    )
}

fn feed(store: &mut ChainStore, blocks: &[Block]) -> Vec<Accepted> {
    blocks
        .iter()
        .map(|block| store.add_block(block.clone(), NOW).unwrap())
        .collect()
}

#[test]
fn the_first_block_must_be_a_genesis() {
    let params = params();
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let blocks = branch.mine_empty(&miner, 2, 600);

    let mut store = ChainStore::new(params);
    assert_eq!(
        store.add_block(blocks[1].clone(), NOW),
        Err(ChainError::NotGenesis)
    );
    assert!(store.is_empty());
    assert_eq!(
        store.add_block(blocks[0].clone(), NOW),
        Ok(Accepted::Extended)
    );
}

#[test]
fn a_block_whose_parent_is_unknown_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let blocks = branch.mine_empty(&miner, 3, 600);

    let mut store = ChainStore::new(params);
    store.add_block(blocks[0].clone(), NOW).unwrap();
    assert_eq!(
        store.add_block(blocks[2].clone(), NOW),
        Err(ChainError::UnknownParent(blocks[1].id()))
    );
    assert_eq!(store.height(), Some(0));
}

#[test]
fn blocks_extend_the_chain_and_repeats_are_recognised() {
    let params = params();
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let blocks = branch.mine_empty(&miner, 5, 600);

    let mut store = ChainStore::new(params);
    assert_eq!(feed(&mut store, &blocks), vec![Accepted::Extended; 5]);
    assert_eq!(store.height(), Some(4));
    assert_eq!(store.tip(), Some(blocks[4].id()));
    assert_eq!(store.total_work(), 5);
    assert_eq!(
        store.add_block(blocks[2].clone(), NOW),
        Ok(Accepted::Duplicate)
    );
}

#[test]
fn a_block_carrying_no_work_never_reaches_memory() {
    let params = params();
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let genesis = branch.mine(&miner, Vec::new(), 600);

    let mut spoiled = genesis.clone();
    spoiled.header.difficulty = u64::MAX;

    let mut store = ChainStore::new(params);
    assert!(matches!(
        store.add_block(spoiled, NOW),
        Err(ChainError::NoWork { .. })
    ));
    assert!(
        store.is_empty(),
        "a block without work is not stored at all"
    );
}

#[test]
fn a_lighter_branch_is_recorded_without_being_followed() {
    let params = params();
    let miner = wallet(1);
    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 4, 600);

    let mut heavy = common.clone();
    let mut light = common.clone();
    let heavy_blocks = heavy.mine_empty(&miner, 3, 600);
    let light_blocks = light.mine_empty(&wallet(9), 1, 700);

    let mut store = ChainStore::new(params);
    feed(&mut store, &shared);
    feed(&mut store, &heavy_blocks);
    let tip = store.tip();

    assert_eq!(
        store.add_block(light_blocks[0].clone(), NOW),
        Ok(Accepted::SideBranch)
    );
    assert_eq!(store.tip(), tip, "the followed branch did not move");
    assert!(
        store.contains(&light_blocks[0].id()),
        "but the block is kept"
    );
    assert!(!store.is_active(&light_blocks[0].id()));
}

#[test]
fn an_equally_heavy_branch_does_not_displace_the_current_one() {
    let params = params();
    let miner = wallet(1);
    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 4, 600);

    let mut first = common.clone();
    let mut second = common.clone();
    let first_blocks = first.mine_empty(&miner, 2, 600);
    let second_blocks = second.mine_empty(&wallet(9), 2, 601);

    let mut store = ChainStore::new(params);
    feed(&mut store, &shared);
    feed(&mut store, &first_blocks);
    let tip = store.tip();

    let outcomes = feed(&mut store, &second_blocks);
    assert_eq!(outcomes, vec![Accepted::SideBranch; 2]);
    assert_eq!(
        store.tip(),
        tip,
        "equal work keeps the branch already followed"
    );
}

#[test]
fn a_heavier_branch_takes_over_and_undoes_what_the_other_did() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(2);

    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 12, 600);
    let (funded, funded_note) = coinbase_note(&shared[11], &params, &miner);

    // One branch pays alice. The other does nothing, but runs longer.
    let mut paying = common.clone();
    let mut quiet = common.clone();

    let mut payment = Transfer::new(
        vec![Input::hot(funded)],
        vec![Note::new(funded_note.value, alice.public_key())],
    );
    payment.sign_input(params.network, 0, &funded_note, &miner);
    let payment_id = payment.id();

    let mut paying_blocks = vec![paying.mine(&miner, vec![payment], 600)];
    paying_blocks.push(paying.mine(&miner, Vec::new(), 600));
    let quiet_blocks = quiet.mine_empty(&wallet(9), 4, 600);

    let mut store = ChainStore::new(params);
    feed(&mut store, &shared);
    feed(&mut store, &paying_blocks);

    let paid = NoteId::new(payment_id, 0);
    assert_eq!(
        store.state().hot_note(&paid),
        Some(Note::new(funded_note.value, alice.public_key())),
        "alice was paid on the branch the node follows"
    );
    assert_eq!(
        store.state().hot_note(&funded),
        None,
        "the source note was spent"
    );

    // The switch happens on the block that first outweighs the other branch,
    // not necessarily on the last one delivered.
    let outcomes = feed(&mut store, &quiet_blocks);
    let (removed, added) = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            Accepted::Reorganised { removed, added } => Some((removed.clone(), added.clone())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no reorganisation among {outcomes:?}"));

    assert_eq!(
        removed.len(),
        2,
        "both blocks of the abandoned branch came off"
    );
    assert_eq!(
        added.len(),
        3,
        "the branch was rebuilt up to the block that won"
    );
    assert_eq!(store.tip(), Some(quiet_blocks[3].id()));
    assert_eq!(
        store.state().hot_note(&paid),
        None,
        "the payment no longer happened"
    );
    assert_eq!(
        store.state().hot_note(&funded),
        Some(funded_note),
        "and the note it spent is unspent again"
    );
    assert!(
        store.contains(&paying_blocks[0].id()),
        "the abandoned blocks are still known"
    );
}

#[test]
fn a_branch_containing_a_bad_block_leaves_the_node_exactly_where_it_was() {
    let params = params();
    let miner = wallet(1);
    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 6, 600);

    let mut good = common.clone();
    let mut bad = common.clone();
    // The bad branch only outweighs the good one on its very last block, so
    // nothing switches until the block that cannot be applied.
    let good_blocks = good.mine_empty(&miner, 4, 600);
    let mut bad_blocks = bad.mine_empty(&wallet(9), 5, 600);

    // Break the last block of the heavier branch after it was built, so it is
    // only found out once the node tries to follow it.
    let broken = bad_blocks.last_mut().unwrap();
    broken.header.state_root = cairn_primitives::Hash32::ZERO;
    let broken = mine_block(broken.clone(), ATTEMPTS).unwrap();
    let last = bad_blocks.len() - 1;
    bad_blocks[last] = broken;

    let mut store = ChainStore::new(params);
    feed(&mut store, &shared);
    feed(&mut store, &good_blocks);

    let before = (
        store.tip(),
        store.state().state_root(),
        store.height(),
        store.total_work(),
    );

    for block in bad_blocks.iter().take(last) {
        assert_eq!(
            store.add_block(block.clone(), NOW),
            Ok(Accepted::SideBranch),
            "the lighter prefix must not displace anything"
        );
    }
    let outcome = store.add_block(bad_blocks[last].clone(), NOW);
    assert!(
        matches!(outcome, Err(ChainError::InvalidBlock { .. })),
        "got {outcome:?}"
    );

    assert_eq!(
        store.tip(),
        before.0,
        "the node is back on the branch it was following"
    );
    assert_eq!(store.state().state_root(), before.1);
    assert_eq!(store.height(), before.2);
    assert_eq!(store.total_work(), before.3);
}

#[test]
fn two_nodes_given_the_same_blocks_in_different_orders_agree() {
    let params = params();
    let miner = wallet(1);
    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 8, 600);

    let mut left = common.clone();
    let mut right = common.clone();
    let left_blocks = left.mine_empty(&miner, 2, 600);
    let right_blocks = right.mine_empty(&wallet(9), 5, 600);

    let mut first = ChainStore::new(params);
    feed(&mut first, &shared);
    feed(&mut first, &left_blocks);
    feed(&mut first, &right_blocks);

    let mut second = ChainStore::new(params);
    feed(&mut second, &shared);
    feed(&mut second, &right_blocks);
    feed(&mut second, &left_blocks);

    assert_eq!(first.tip(), second.tip(), "both settled on the same block");
    assert_eq!(first.state().state_root(), second.state().state_root());
    assert_eq!(first.total_work(), second.total_work());
    assert_eq!(
        first.len(),
        second.len(),
        "both kept every block they were given"
    );
    assert_eq!(
        first.tip(),
        Some(right_blocks[4].id()),
        "the heavier branch won"
    );
}

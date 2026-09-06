//! AUDIT: a fork choice weighing work, on chains where work is not the height.
//!
//! Every chain this crate had ever built carried one difficulty from its first
//! block to its last. `ConsensusParams::testnet()` opens on the floor and every
//! fixture spaced its blocks ten times the target apart, so the retarget only
//! ever wanted to lower a difficulty that could not be lowered. Cumulative work
//! was therefore the height, and a fork choice adding up blocks would have
//! passed every test in this file's neighbours.
//!
//! Two shapes were unreachable because of it, and each one hid a defect.
//!
//! A rival that wins with *more, easier* blocks: the switch then applies more
//! blocks than it undoes. A sweep in `forget_what_cannot_change` stopped
//! permanently when that happened at the window, because the branch's
//! beginning was taken past a cursor that then never named a block again;
//! measured at the time, a node went on holding one more block per block for
//! the rest of its life. With a uniform difficulty a heavier rival is a longer
//! one, and the fixtures all built it one block longer, so the switch applied
//! one more than it undid and the cursor stayed where it could be named.
//!
//! And a rival that wins with *fewer, harder* blocks: the node's own height
//! then goes down. Nothing in this crate had ever made a node shorter by
//! following the heaviest chain, which is the plainest statement there is that
//! work and not length is what decides.
//!
//! Both are built here on `ConsensusParams::mineable_network`, which opens
//! above the floor so the retarget has somewhere to move in either direction.
//! The spacings were chosen by simulating the retarget rather than by trying
//! numbers on a chain: a spacing under the target is a feedback loop, since
//! the difficulty rises and the fixture goes on producing blocks just as fast,
//! so a long fast run climbs out of what a test can mine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{Accepted, ChainStore, HELD_WINDOW};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, ConsensusParams, MINEABLE_DIFFICULTY,
};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 24;
const TARGET: u64 = 60;

/// Deep enough that no switch here is refused by the depth rule, and shallow
/// enough to be a chain a test can mine. The maturity follows it, which is how
/// every network sets the two and what no fixture in this workspace did.
const BURIAL: u64 = 64;

fn params() -> ConsensusParams {
    ConsensusParams::mineable_network(BURIAL)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Produces blocks on a private copy of the ledger, at whatever spacing is
/// asked for, so a branch can be built without a node having to follow it.
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

    fn mine(&mut self, miner: &SecretKey, spacing: u64) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += spacing;
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
        let block = mine_block(block, ATTEMPTS).expect("a nonce at this difficulty");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn run(&mut self, miner: &SecretKey, count: usize, spacing: u64) -> Vec<Block> {
        (0..count).map(|_| self.mine(miner, spacing)).collect()
    }

    fn fork(&self) -> Self {
        self.clone()
    }
}

fn work_of_run(blocks: &[Block]) -> u128 {
    blocks
        .iter()
        .map(|block| u128::from(block.header.difficulty))
        .sum()
}

fn difficulties(blocks: &[Block]) -> Vec<u64> {
    blocks.iter().map(|block| block.header.difficulty).collect()
}

/// A switch that applies more blocks than it undoes, and wins on work anyway.
///
/// The rival's blocks after the first are every one of them easier than every
/// block it replaces, so a fork choice counting blocks and a fork choice
/// weighing work would both take it, and only the second is right about why.
/// What this pins is the arithmetic of the switch itself: more added than
/// removed, which is the shape the sweep at the window used to freeze on and
/// which no uniform chain can produce without being built to.
#[test]
fn a_rival_of_more_and_easier_blocks_takes_the_branch_and_lengthens_it() {
    let params = params();
    let miner = wallet(1);

    let mut common = Branch::new(params);
    let shared = common.run(&miner, 20, TARGET);
    assert_eq!(
        difficulties(&shared),
        vec![MINEABLE_DIFFICULTY; 20],
        "a chain on schedule keeps the difficulty it opened at"
    );

    // Ours comes twice as fast, so the rules demand more of each block.
    let mut ours = common.fork();
    let ours_blocks = ours.run(&miner, 3, TARGET / 2);
    // The rival crawls, so the rules demand less, and it needs more blocks to
    // outweigh three of ours.
    let mut theirs = common.fork();
    let their_blocks = theirs.run(&wallet(9), 6, TARGET * 4);

    let ours_work = work_of_run(&ours_blocks);
    let their_work = work_of_run(&their_blocks);
    let easiest_of_ours = *difficulties(&ours_blocks).iter().min().unwrap();
    println!(
        "ours {:?} = {ours_work}; theirs {:?} = {their_work}",
        difficulties(&ours_blocks),
        difficulties(&their_blocks)
    );
    assert!(
        their_work > ours_work,
        "the rival has to be heavier or there is no switch to make"
    );
    assert!(
        difficulties(&their_blocks)[1..]
            .iter()
            .all(|difficulty| *difficulty < easiest_of_ours),
        "every rival block after the fork has to be easier than anything it \
         replaces, or this is not the shape being pinned"
    );

    let mut store = ChainStore::new(params);
    for block in shared.iter().chain(&ours_blocks) {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.height(), Some(22));
    let before = store.height().unwrap();

    let mut switch = None;
    for block in &their_blocks {
        let outcome = store.add_block(block.clone(), NOW).unwrap();
        if let Accepted::Reorganised { removed, added } = &outcome {
            assert!(switch.is_none(), "the branch moved twice");
            switch = Some((removed.len(), added.len()));
        }
    }
    let (removed, added) = switch.expect("the heavier branch was never taken");
    println!(
        "a switch that undid {removed} and applied {added}, height {before} -> {}",
        store.height().unwrap()
    );
    assert_eq!(removed, 3);
    assert!(
        added >= removed + 2,
        "the whole point is a switch applying at least two more than it undoes, \
         and this one applied {added} against {removed}"
    );
    assert_eq!(store.tip(), Some(their_blocks.last().unwrap().id()));
    assert_eq!(store.height(), Some(25));
    assert_eq!(
        store.total_work(),
        work_of_run(&shared) + their_work,
        "the branch is worth the sum of its difficulties"
    );

    // And the node is the node it would have been had it never seen ours.
    let mut fresh = ChainStore::new(params);
    for block in shared.iter().chain(&their_blocks) {
        fresh.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.tip(), fresh.tip());
    assert_eq!(store.state().state_root(), fresh.state().state_root());
    assert_eq!(store.total_work(), fresh.total_work());
}

/// The other direction: a node made shorter by following the heaviest chain.
///
/// This is the case round eleven built by hand once and nothing kept. Ours is
/// forty blocks that came so slowly the retarget let the difficulty fall by
/// six; the rival is sixteen that came fast enough to hold it up. Sixteen
/// outweigh forty, the node undoes forty and applies sixteen, and its own
/// height goes down by twenty four.
///
/// The slow spacing is ten times the target and worth six times it, because
/// `pow.rs` clamps a solve time into six times the target before the retarget
/// reads it. That is why a fixture cannot buy a faster collapse by dating its
/// blocks further apart, and it is why the difficulty falls over forty blocks
/// rather than over six.
#[test]
fn a_rival_of_fewer_and_harder_blocks_takes_the_branch_and_shortens_it() {
    let params = params();
    let miner = wallet(1);

    let mut common = Branch::new(params);
    let shared = common.run(&miner, 100, TARGET);

    let mut ours = common.fork();
    let ours_blocks = ours.run(&miner, 40, TARGET * 10);
    let mut theirs = common.fork();
    let their_blocks = theirs.run(&wallet(9), 16, TARGET / 2);

    let ours_work = work_of_run(&ours_blocks);
    let their_work = work_of_run(&their_blocks);
    let ours_difficulties = difficulties(&ours_blocks);
    let their_difficulties = difficulties(&their_blocks);
    println!(
        "forty blocks falling {}..{} = {ours_work}; sixteen rising {}..{} = {their_work}",
        ours_difficulties[0], ours_difficulties[39], their_difficulties[0], their_difficulties[15]
    );
    assert!(
        ours_difficulties[39] * 4 < ours_difficulties[0],
        "the slow branch has to have really lost its difficulty"
    );
    assert!(
        their_work > ours_work,
        "sixteen blocks have to outweigh forty or there is no switch"
    );

    let mut store = ChainStore::new(params);
    for block in shared.iter().chain(&ours_blocks) {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.height(), Some(139));

    let mut switch = None;
    for block in &their_blocks {
        if let Accepted::Reorganised { removed, added } =
            store.add_block(block.clone(), NOW).unwrap()
        {
            assert!(switch.is_none(), "the branch moved twice");
            switch = Some((removed.len(), added.len()));
        }
    }
    let (removed, added) = switch.expect("the heavier branch was never taken");
    println!(
        "a switch that undid {removed} and applied {added}, height 139 -> {}",
        store.height().unwrap()
    );
    // The fifteenth rival block is where the sum passes ours, so that is the
    // one the switch happens on; the sixteenth arrives afterwards and extends.
    assert_eq!((removed, added), (40, 15));
    assert_eq!(
        store.height(),
        Some(115),
        "a node that followed the heaviest chain and got shorter"
    );
    assert_eq!(store.tip(), Some(their_blocks.last().unwrap().id()));
    assert_eq!(store.total_work(), work_of_run(&shared) + their_work);

    // Consistent with a node that never saw the branch it left, which is what
    // makes the shortening a switch rather than damage.
    let mut fresh = ChainStore::new(params);
    for block in shared.iter().chain(&their_blocks) {
        fresh.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.tip(), fresh.tip());
    assert_eq!(store.state().state_root(), fresh.state().state_root());

    // And it goes on being a chain: the branch it left is still offerable and
    // still lighter, and ordinary blocks keep applying on top of the new tip.
    let carried_on = theirs.run(&wallet(9), 4, TARGET);
    for block in &carried_on {
        assert_eq!(
            store.add_block(block.clone(), NOW).unwrap(),
            Accepted::Extended
        );
    }
    assert_eq!(store.height(), Some(119));
    assert!(store.undo_records() <= HELD_WINDOW);
}

/// The same switch, at the depth where the sweeps run.
///
/// `forget_what_cannot_change` steps one block forward for each block added
/// once the branch is past [`HELD_WINDOW`], and a switch is the case where more
/// than one leaves at once. It used to stop when it could not name its own
/// height, and stopping was permanent: the cursor stayed put for the life of
/// the node and every block after it added an undo record and a block entry
/// nothing would ever remove. What made the cursor unnameable was a switch that
/// applied more blocks than it undid, because the branch's beginning was then
/// taken past it. Measured at the time: three undone against five applied froze
/// the cursor at height five, and twenty ordinary blocks afterwards took what
/// the node held from 1 029 blocks to 1 049, one per block, on a node whose
/// whole claim is that its memory does not grow with the chain.
///
/// Nothing pinned it, because no fixture could build the switch. Every chain
/// here carried one difficulty, so a heavier rival was a longer one and every
/// fixture built it one block longer, which undoes n and applies n plus one and
/// leaves the cursor exactly where it can still be named. Here the rival wins
/// on work rather than on length, so it applies fourteen against eight, and the
/// node is watched for twenty blocks afterwards to see whether what it holds
/// moves at all.
///
/// The crate's own unit test `a_switch_that_applied_more_than_it_undid_still_\
/// lets_the_window_slide` builds this shape by hand, pushing identifiers onto
/// the branch and records into the table directly, because at the time nothing
/// could reach it any other way. This arrives at the same shape through
/// `add_block` and the fork choice, on blocks that were mined: what it adds is
/// that the shape is one a network can produce, and not only one a test can
/// assemble.
///
/// A thousand and thirty three blocks at 4 096 is about four million hashes,
/// which is a couple of seconds. It is the cheapest chain that reaches the
/// window, and the window is the only place this defect lived.
#[test]
fn a_switch_at_the_window_applying_more_than_it_undid_leaves_the_node_bounded() {
    let params = params();
    let miner = wallet(1);

    let mut common = Branch::new(params);
    let shared = common.run(&miner, HELD_WINDOW + 8, TARGET);
    // A full window moves the difficulty far more slowly than the twenty block
    // chain above, because the retarget averages over ninety. So the two
    // branches are pulled further apart to reach the same shape: ours comes
    // four times too fast, and the rival is dated at six times the target,
    // which is where `pow.rs` clamps a solve time and therefore the slowest a
    // gap can be worth. Eight against sixteen is what that buys.
    let mut ours = common.fork();
    let ours_blocks = ours.run(&miner, 8, TARGET / 4);
    let mut theirs = common.fork();
    let their_blocks = theirs.run(&wallet(9), 16, TARGET * 6);

    let mut store = ChainStore::new(params);
    for block in shared.iter().chain(&ours_blocks) {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert!(
        store.height().unwrap() > u64::try_from(HELD_WINDOW).unwrap(),
        "the branch has to be past the window or the sweep never runs"
    );

    let mut switch = None;
    for block in &their_blocks {
        if let Accepted::Reorganised { removed, added } =
            store.add_block(block.clone(), NOW).unwrap()
        {
            switch = Some((removed.len(), added.len()));
        }
    }
    let (removed, added) = switch.expect("the heavier branch was never taken");
    assert_eq!(removed, 8);
    assert!(
        added >= removed + 2,
        "the shape this exists for is a switch applying at least two more than \
         it undoes, and this one applied {added} against {removed}"
    );

    // Twenty ordinary blocks, watched at both ends. A cursor that had stopped
    // walking shows up here as one more record and one more block per block.
    let carried_on = theirs.run(&wallet(9), 20, TARGET);
    let mut records = Vec::new();
    let mut held = Vec::new();
    for block in &carried_on {
        store.add_block(block.clone(), NOW).unwrap();
        records.push(store.undo_records());
        held.push(store.held_ids().len());
    }
    println!(
        "after a switch of {removed} undone and {added} applied at height {}: \
         undo records {} -> {}, blocks held {} -> {}",
        store.height().unwrap(),
        records[0],
        records[19],
        held[0],
        held[19]
    );
    assert!(
        store.undo_records() <= HELD_WINDOW,
        "{} undo records against a window of {HELD_WINDOW}",
        store.undo_records()
    );
    assert_eq!(
        records[0],
        records[19],
        "the sweep stopped walking: what the node holds grew by {} over twenty \
         ordinary blocks",
        records[19].saturating_sub(records[0])
    );
    assert_eq!(
        held[0],
        held[19],
        "the blocks held grew by {} over twenty ordinary blocks",
        held[19].saturating_sub(held[0])
    );
}

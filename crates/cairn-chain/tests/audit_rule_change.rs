//! What a scheduled rule change does to a node's block tree.
//!
//! The ledger decides the verdict on one block. This decides what the node
//! does with that verdict: what it remembers, what it throws away, what it
//! tells the layer above about the peer that sent it, and whether it can be
//! put back where it was when a branch turns out to cross the change.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{Accepted, ChainError, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, Block, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, BlockError, ConsensusParams,
};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The schedule the release that carries the change ships with.
const ANNOUNCED: &[Activation] = &[
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

/// Produces blocks on a private ledger, so a branch exists without a node
/// having to follow it.
#[derive(Clone)]
struct Miner {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Miner {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn fork(&self) -> Self {
        self.clone()
    }

    /// A block on top of what this miner holds, not applied to it.
    fn candidate(&self, miner: &SecretKey, version: Option<u16>, spacing: u64) -> Block {
        let height = self.state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
        );
        let mut block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
            &self.params,
            self.clock + spacing,
            0,
        )
        .unwrap();
        if let Some(version) = version {
            block.header.version = version;
        }
        mine_block(block, ATTEMPTS).expect("a nonce exists")
    }

    fn mine(&mut self, miner: &SecretKey, spacing: u64) -> Block {
        let block = self.candidate(miner, None, spacing);
        self.clock += spacing;
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize, spacing: u64) -> Vec<Block> {
        (0..count).map(|_| self.mine(miner, spacing)).collect()
    }
}

fn feed(store: &mut ChainStore, blocks: &[Block]) {
    for block in blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }
}

/// The release that schedules a change is the release that implements it, so
/// every node one release behind holds a schedule with nothing in it. This is
/// what such a node does when the network moves, and for a while it was the
/// opposite of what the design intended.
///
/// It did not reach `SoftwareTooOld`, so `ChainError::outdated` was `None`,
/// so `cairn-net`'s `on_block` fell through to its last arm and answered
/// `Reaction::close(DropReason::BadBlock)`, which `is_misbehaviour` reports as
/// true: the connection closed and the host refused. And because
/// `UnsupportedVersion` was in `settles_the_header`, the identifier went into
/// the `invalid` set, so the node would not judge that block again for as long
/// as the process lived, however many honest peers offered it.
///
/// The node was left following the last block before the change, calling the
/// majority chain a lie, banning everyone who had updated, and telling its
/// operator nothing at all. The population the machinery exists to protect was
/// the only population it did not cover.
///
/// The verdict is no longer remembered, because it is a judgement about the
/// reader rather than about the header, and an update reverses it. So the
/// block is kept, the messenger is not condemned, and nothing this node
/// believes about that block survives the release that would change it.
///
/// Answering "I am too old" here instead was tried and is worse: a node stops
/// itself on meeting rules it lacks, so that made stopping a node something a
/// stranger could ask for by writing a number in a field. Deciding that a run
/// of these means the chain has moved needs more than one block and more than
/// one peer, and belongs where peers are counted.
#[test]
fn a_build_without_the_schedule_does_not_condemn_the_chain_or_its_messenger() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();

    let mut chain = Miner::new(plain);
    let before = chain.mine_empty(&miner, 5, 600);
    // What the updated majority mines at the height the change governs.
    let after = chain.candidate(&miner, Some(BLOCK_VERSION + 1), 600);

    // A node still on the previous release: nothing scheduled.
    let mut store = ChainStore::new(plain);
    feed(&mut store, &before);
    assert_eq!(store.height(), Some(4));

    let refused = store.add_block(after.clone(), NOW).unwrap_err();
    assert_eq!(
        refused,
        ChainError::InvalidBlock {
            id: after.id(),
            source: BlockError::UnsupportedVersion(BLOCK_VERSION + 1),
        },
        "this build cannot judge the block, which is all it can honestly say"
    );

    // And nothing is written down against it. Offered again, it is judged
    // again and refused again, rather than answered out of a memory the next
    // release would make wrong. The cost is asking for it twice; the cost of
    // the alternative was a node refusing the real chain for the life of the
    // process, however many honest peers offered it.
    assert_eq!(
        store.add_block(after.clone(), NOW),
        Err(ChainError::InvalidBlock {
            id: after.id(),
            source: BlockError::UnsupportedVersion(BLOCK_VERSION + 1),
        }),
        "reached again rather than remembered"
    );
    assert_eq!(
        store.height(),
        Some(4),
        "and the node stands where it stopped"
    );
}

/// The same node, one release later, with the schedule and without the rules.
/// This is the behaviour the design describes, and it is reached only from
/// that earlier release.
#[test]
fn the_schedule_is_what_turns_a_bad_block_into_an_admission() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();
    let announced = ConsensusParams {
        activations: ANNOUNCED,
        ..plain
    };

    let mut chain = Miner::new(plain);
    let before = chain.mine_empty(&miner, 5, 600);
    let after = chain.candidate(&miner, Some(BLOCK_VERSION + 1), 600);

    let mut store = ChainStore::new(announced);
    feed(&mut store, &before);

    let refused = store.add_block(after.clone(), NOW).unwrap_err();
    let outdated = refused.outdated().expect("named, not blamed");
    assert_eq!(outdated.height, 5);
    assert_eq!(outdated.required, BLOCK_VERSION + 1);

    // Nothing was written down, so an update finds the block still judgeable.
    // A condemned block answers `KnownBad` and never reaches the rules again;
    // this one is judged a second time and comes back with the same admission,
    // which is the node going on saying it is out of date rather than falling
    // silent after the first peer to tell it.
    let again = store.add_block(after, NOW).unwrap_err();
    assert!(
        !matches!(again, ChainError::KnownBad { .. }),
        "held rather than condemned: {again:?}"
    );
    assert_eq!(
        again.outdated().map(|out| out.required),
        Some(BLOCK_VERSION + 1),
        "and it is still the admission and not a verdict on the block"
    );
}

/// A branch that is heavier and crosses the change.
///
/// The node rewinds onto the fork point, applies its way up, and meets the
/// change part way along. What must not happen is that it is left on half of a
/// branch it did not choose, or that the blocks it rolled back to try are
/// lost. It is put back exactly where it stood, and the refusal it reports is
/// still the one that names the node rather than the peer.
#[test]
fn a_heavier_branch_that_crosses_the_change_leaves_the_node_where_it_was() {
    let one = wallet(1);
    let two = wallet(2);
    let plain = ConsensusParams::testnet();
    let announced = ConsensusParams {
        activations: ANNOUNCED,
        ..plain
    };

    // A shared root of two blocks, then two branches from it.
    let mut root = Miner::new(plain);
    let shared = root.mine_empty(&one, 2, 600);
    let mut left = root.fork();
    let mut right = root.fork();

    let mine_side = left.mine_empty(&one, 3, 600); // heights 2, 3, 4
    let rival = right.mine_empty(&two, 3, 700); // heights 2, 3, 4
    let across = right.candidate(&two, None, 700); // height 5, the change

    let mut store = ChainStore::new(announced);
    feed(&mut store, &shared);
    feed(&mut store, &mine_side);
    let standing = store.tip().unwrap();
    let root_before = store.state().state_root();
    assert_eq!(store.height(), Some(4));

    // The rival branch, equal in work, is kept aside.
    for block in &rival {
        assert_eq!(
            store.add_block(block.clone(), NOW),
            Ok(Accepted::SideBranch)
        );
    }
    assert_eq!(store.tip(), Some(standing), "ties keep what is followed");

    // And now one block heavier, which asks for the switch.
    let refused = store.add_block(across.clone(), NOW).unwrap_err();
    assert!(
        refused.outdated().is_some(),
        "the switch stopped at the change, and said so: {refused:?}"
    );

    assert_eq!(store.tip(), Some(standing), "put back on its own branch");
    assert_eq!(store.height(), Some(4));
    assert_eq!(
        store.state().state_root(),
        root_before,
        "and the ledger with it"
    );

    // Nothing on either branch was condemned on the way through. A condemned
    // block answers `KnownBad` and no other answer does: the branch this node
    // follows says it already holds these, and the rival says it has them
    // recorded and lighter, which is the fork choice being asked again rather
    // than a verdict being remembered.
    for block in mine_side.iter().chain(rival.iter()) {
        let answer = store.add_block(block.clone(), NOW);
        assert!(
            matches!(answer, Ok(Accepted::Duplicate | Accepted::SideBranch)),
            "a block the rewind touched was written off: {answer:?}"
        );
    }
}

/// A newcomer takes a ledger from a thousand blocks below a tip, and nothing
/// on that path used to look at a block version.
///
/// The handover rebuilt the ledger and checked it against the header, checked
/// the buried run's difficulty, timestamps and work, and checked the anchor
/// against the tip's history. It never asked what version any of those headers
/// carried, and never consulted the schedule. So a node whose rules stopped at
/// height five took a ledger from height eight, adopted it, reported that
/// height, and answered balances from a chain it had no rules for, while still
/// saying it was up to date. It learned otherwise when the next block arrived,
/// and not before, and in the meantime a wallet showed a checked-looking
/// balance produced by rules the node could not check.
///
/// It is asked in both places now: where a handover is checked, and here,
/// because this is the door a ledger comes through however it was obtained.
#[test]
fn a_node_too_old_for_the_chain_will_not_take_a_ledger_from_it() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();
    let announced = ConsensusParams {
        activations: ANNOUNCED,
        ..plain
    };

    let mut chain = Miner::new(plain);
    let blocks = chain.mine_empty(&miner, 9, 600);

    let mut source = ChainStore::new(plain);
    feed(&mut source, &blocks);
    let recent: Vec<_> = blocks.iter().map(|block| block.header).collect();
    let state = source.state().clone();

    let mut joined = ChainStore::new(announced);
    let refused = joined
        .adopt(state, &recent)
        .expect_err("a ledger from rules this build lacks is not one to stand on");
    assert!(
        refused.outdated().is_some(),
        "and it says so about itself rather than about whoever offered it"
    );
    assert_eq!(joined.height(), None, "nothing was adopted");

    // The schedule is what makes this build too old: the header itself carries
    // the version this build knows, and it is the rules at that height that
    // this build does not have.
    let tip = recent.last().unwrap();
    assert_eq!(tip.version, BLOCK_VERSION);
    assert_eq!(announced.version_at(tip.height), BLOCK_VERSION + 1);

    // A node that does have the rules takes the same ledger.
    let mut current = ChainStore::new(plain);
    current
        .adopt(source.state().clone(), &recent)
        .expect("a build with the rules stands behind it");
    assert_eq!(current.height(), Some(8));
}

/// Arriving out of order across the change changes when the damage lands, not
/// whether it lands.
#[test]
fn out_of_order_across_the_change_only_delays_the_verdict() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();

    let mut chain = Miner::new(plain);
    let before = chain.mine_empty(&miner, 5, 600);
    let after = chain.candidate(&miner, Some(BLOCK_VERSION + 1), 600);

    let mut store = ChainStore::new(plain);
    feed(&mut store, &before[..4]);

    // The block from past the change, before the one below it: no parent, no
    // verdict, nothing held against anyone.
    assert_eq!(
        store.add_block(after.clone(), NOW),
        Err(ChainError::UnknownParent(after.header.previous))
    );

    // The gap closes, and the verdict lands as it would have anyway.
    store.add_block(before[4].clone(), NOW).unwrap();
    let refused = store.add_block(after.clone(), NOW).unwrap_err();
    assert!(
        matches!(
            refused,
            ChainError::InvalidBlock {
                source: BlockError::UnsupportedVersion(_),
                ..
            }
        ),
        "and it is the same verdict the block would have got in order"
    );
    assert_eq!(
        store.add_block(after.clone(), NOW).unwrap_err(),
        refused,
        "reached again rather than remembered, since a release reverses it"
    );
}

/// A node standing at the change keeps every block it is offered.
///
/// The refusal is `outdated`, so `follow` deliberately does not drop the
/// block: it becomes valid the moment the node is updated, and asking for it
/// again would be waste. But the sweep that lets go of side branches runs only
/// when a switch succeeds, and at the change no switch ever succeeds again.
/// So what is held only grows. Each block costs its sender the work for the
/// height, and the node above this one shuts down on the first of them, which
/// is what keeps this small.
#[test]
fn at_the_change_what_the_node_holds_only_grows() {
    let plain = ConsensusParams::testnet();
    let announced = ConsensusParams {
        activations: ANNOUNCED,
        ..plain
    };

    let mut chain = Miner::new(plain);
    let before = chain.mine_empty(&wallet(1), 5, 600);

    let mut store = ChainStore::new(announced);
    feed(&mut store, &before);
    let settled = store.held_bytes();

    let mut last = settled;
    for seed in 10..14u8 {
        let block = chain.candidate(&wallet(seed), None, 600);
        let refused = store.add_block(block, NOW).unwrap_err();
        assert!(refused.outdated().is_some());
        let now = store.held_bytes();
        assert!(
            now > last,
            "a block refused at the change was kept, which is intended"
        );
        last = now;
    }
    assert!(
        last > settled,
        "and nothing ever lets them go while the node stands here"
    );
}

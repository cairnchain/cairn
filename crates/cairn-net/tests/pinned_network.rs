//! Joining a chain on a network that pins its first block.
//!
//! Every other test of the handover runs on `ConsensusParams::testnet()`,
//! which pins nothing, so a newcomer there starts with no chain at all. The
//! two real networks pin theirs, and a node on either lays that block down the
//! moment it opens a directory. Its chain is then not empty, and everything
//! that decides whether a node joins asked whether it was: so on both of them
//! every newcomer read the whole chain block by block, and the handover ran
//! only in tests.
//!
//! These run the same exchanges on the devnet, from its real first block.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, expected_difficulty, mine_block, ConsensusParams,
};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, Local, PeerState, JOIN_RATHER_THAN_READ};
use cairn_net::{Joined, Node};
use cairn_primitives::Hash32;

/// A liveness bound, far past what the work takes on a loaded runner. Every
/// wait here is for something to happen.
const PATIENCE: Duration = Duration::from_secs(300);

fn params() -> ConsensusParams {
    ConsensusParams::for_network("devnet").expect("the devnet is a network this build ships")
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("waited {PATIENCE:?} for {what}");
}

/// The difficulty the forge's miner holds the devnet at: it finds a block of
/// this difficulty in the devnet's target time, a hundred and twenty eighth of
/// the rate the devnet opens for. Enough that the band of work a weighing
/// leaves unresolved lies where the chain holds rather than where it fell,
/// and no more, since every block of it is mined.
const SETTLES_AT: u64 = 1 << 16;

/// Mines on the devnet from its real first block, as one steady machine
/// slower than the one the devnet opens for: each block takes as long as its
/// difficulty asks of that machine, and the retarget falls from the first
/// block to what it can do and holds there.
///
/// It used to mine a block a minute whatever was asked, twelve times the
/// devnet's pace, which walked the difficulty down to the floor; a newcomer
/// refuses a tip that far below the run it stands on
/// (`cairn_ledger::sampling::MOST_FALL`), and read that chain rather than
/// being handed a ledger.
#[derive(Clone)]
struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new() -> Self {
        let params = params();
        let first = cairn_ledger::genesis::block(params.network).unwrap();
        let mut state = LedgerState::new();
        connect_block(&mut state, &first, &params, wall_clock()).unwrap();
        Self {
            state,
            clock: first.header.timestamp,
        }
    }

    fn mine(&mut self) -> Block {
        let params = params();
        let miner = SecretKey::from_bytes(&[1; 32]).public_key();
        let height = self.state.next_height().unwrap();
        let asked = expected_difficulty(&self.state, &params);
        self.clock += (asked * params.target_block_time).div_ceil(SETTLES_AT);
        let now = wall_clock();
        assert!(
            self.clock < now,
            "the chain would run into the future: the devnet's first block is dated \
             genesis::DEVNET_DATED_EARLY before it was minted, and this chain needs more"
        );
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, miner)]);
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, 1 << 28).unwrap();
        connect_block(&mut self.state, &block, &params, now).unwrap();
        block
    }
}

/// A chain past the length where a newcomer is handed a ledger rather than
/// reading one, mined once for the whole file, and the forge that made it.
fn a_long_chain() -> &'static (Vec<Block>, Forge) {
    static CHAIN: OnceLock<(Vec<Block>, Forge)> = OnceLock::new();
    CHAIN.get_or_init(|| {
        let mut forge = Forge::new();
        let count = usize::try_from(cairn_net::sync::JOIN_RATHER_THAN_READ).unwrap() + 40;
        let blocks = (0..count).map(|_| forge.mine()).collect();
        (blocks, forge)
    })
}

/// The chain this file mines fits in how early the devnet's first block is
/// dated.
///
/// Every block the forge mines is held behind the wall clock, and the chain
/// starts at the devnet's pinned first block, which is dated
/// `genesis::DEVNET_DATED_EARLY` before it is minted for this file's sake and
/// for nothing else: the schedule starts at that timestamp, so every second of
/// it is a second a devnet opened the day the block is minted stands behind.
/// The chain's span is the rules' and the forge's, the same whatever day it is
/// mined, so it is held here against the constant rather than against the
/// clock. A forge or a rule that lengthens it fails with the number to raise,
/// where otherwise every test in this file would pass until the morning the
/// devnet is minted again and fail then.
#[test]
fn the_chain_this_file_mines_fits_in_how_early_the_devnet_is_dated() {
    let params = params();
    let (_, forge) = a_long_chain();
    let mut forge = forge.clone();
    // The longest chain any test here mines: the long one, and a burial past
    // it.
    let mut last = forge.clock;
    for _ in 0..=params.burial {
        last = forge.mine().header.timestamp;
    }
    let span = last - cairn_ledger::genesis::opens_at(params.network);
    println!("the longest chain here spans {span} s of the devnet's schedule");
    assert!(
        span < cairn_ledger::genesis::DEVNET_DATED_EARLY,
        "the chains here span {span} s, more than the {} s the devnet's first block is dated \
         before it is minted",
        cairn_ledger::genesis::DEVNET_DATED_EARLY
    );
}

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("cairn-pinned-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    root
}

/// Whether `chain`, meeting a peer that says it has a chain long enough to be
/// final and heavier than its own, asks that peer for it at the handshake.
fn asks_at_the_handshake(chain: &mut ChainStore) -> bool {
    let network = chain.params().network;
    let theirs = Handshake {
        version: PROTOCOL_VERSION,
        network,
        genesis: Hash32::ZERO,
        height: JOIN_RATHER_THAN_READ + 40,
        total_work: chain.total_work().saturating_mul(1_000).max(1_000_000),
        listen: 0,
        nonce: 99,
        keeps: Keeps {
            headers: true,
            cold_set: false,
        },
    };
    let mut local = Local {
        chain,
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
        listen: 4242,
        nonce: 1,
    };
    on_message(
        &mut local,
        &mut PeerState::default(),
        Message::Welcome(theirs),
        wall_clock(),
    )
    .reply
    .iter()
    .any(|message| matches!(message, Message::GetChain { .. }))
}

/// A node holding only the first block its network pins leaves a long chain
/// to the choice at the handshake, and a node holding more than it can undo
/// asks for it there.
///
/// The handshake is where a node decides whether to ask a peer for its chain
/// at once or leave the choice of whom to follow to the chooser. It asked
/// whether the chain was empty, which on a named network it never is, so a
/// newcomer asked the first long chain it met for its blocks and read it.
/// Nothing asked this on a network that pins its first block, so that
/// newcomer passed.
///
/// The second half held that one block of its own was enough to ask at the
/// handshake. That was the gate a peer saying it had nought blocks went
/// through: once the node held one block from it, every long claim after it
/// was asked at once and the choice was over. A branch the node can still
/// undo is still a choice (`sync::holds_nothing_it_cannot_undo`), so the node
/// here holds one block more than its rules undo.
#[test]
fn a_node_holding_only_the_first_block_leaves_a_long_chain_to_the_choice() {
    let params = params();
    let first = cairn_ledger::genesis::block(params.network).unwrap();
    let mut newcomer = ChainStore::new(params);
    newcomer.add_block(first, wall_clock()).unwrap();
    assert!(
        !asks_at_the_handshake(&mut newcomer),
        "a node holding only its network's first block asked the first long chain it met \
         for its blocks, which reads that chain rather than choosing whom to be handed one by"
    );

    // Rules that pin nothing and undo two blocks, so a branch of the test's
    // own three blocks deep is a chain this node can no longer give up.
    let unpinned = ConsensusParams::testnet().with_burial(2);
    let miner = SecretKey::from_bytes(&[1; 32]).public_key();
    let mut state = LedgerState::new();
    let mut started = ChainStore::new(unpinned);
    for height in 0..=started.undo_limit() + 1 {
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(unpinned.reward_at(height), miner)]);
        let block = assemble_block(
            &state,
            coinbase,
            Vec::<Transfer>::new(),
            &unpinned,
            1_000 + 600 * height,
            0,
        )
        .unwrap();
        let block = mine_block(block, 1 << 20).unwrap();
        connect_block(&mut state, &block, &unpinned, wall_clock()).unwrap();
        started.add_block(block, wall_clock()).unwrap();
    }
    assert!(
        asks_at_the_handshake(&mut started),
        "a node with a chain of its own left a heavier chain to a choice it no longer has"
    );
}

/// A newcomer on a network that pins its first block is handed a ledger, and
/// carries on from it as a node that writes down what it validates.
///
/// Nothing asked this, so a node that held the pinned first block and read a
/// chain of a thousand and sixty four blocks one at a time from block one
/// passed: every test of the join ran on rules that pin nothing, where the
/// newcomer's chain really is empty.
#[test]
fn a_newcomer_on_a_network_that_pins_its_first_block_is_handed_a_ledger() {
    let params = params();
    let (blocks, _) = a_long_chain();
    let top = blocks.last().unwrap().header.height;
    let root = scratch("handed");

    let (keeper, _) = Node::open_archiving(params, loopback(), root.join("keeper")).unwrap();
    for block in blocks {
        keeper.submit_block(block.clone()).unwrap();
    }
    assert_eq!(
        keeper.height(),
        Some(top),
        "the keeper holds the whole chain"
    );

    let (joiner, _) = Node::open(params, loopback(), root.join("joiner")).unwrap();
    assert_eq!(
        joiner.height(),
        Some(0),
        "the premise: a node on this network starts holding its first block"
    );
    joiner.connect(keeper.address()).unwrap();
    // Or to say its disk would not take what it validated, which is how a node
    // that kept the first block's records behind a ledger stops.
    wait_for("the newcomer to reach the keeper's tip", || {
        joiner.height() == Some(top) || joiner.unwritten().is_some()
    });

    let how = joiner.joining();
    let read_the_first = joiner.archived_at(1).is_some();
    let wrote_the_tip = joiner.archived_at(top).is_some();
    let unwritten = joiner.unwritten().is_some();
    let same_ledger = joiner.with_chain(|chain| chain.state().state_root())
        == keeper.with_chain(|chain| chain.state().state_root());
    keeper.shutdown();
    joiner.shutdown();
    drop(joiner);

    assert_eq!(
        how,
        Joined::Done,
        "a newcomer on a network that pins its first block reached the tip without \
         being handed a ledger"
    );
    assert!(
        !read_the_first,
        "the newcomer holds block one, so it read the chain from the start"
    );
    assert!(
        same_ledger,
        "the ledger that came across is not the keeper's"
    );
    assert!(
        wrote_the_tip && !unwritten,
        "the node that was handed a ledger could not write the blocks it validated \
         after it, behind the first block it had laid down at start"
    );

    // And it comes back as it was: the ledger it was handed and the blocks
    // after it, rather than a log it cannot read.
    let (again, restored) = Node::open(params, loopback(), root.join("joiner")).unwrap();
    let height = again.height();
    again.shutdown();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        !restored.rejoining && restored.refused == 0,
        "the node that was handed a ledger set its own blocks aside at the next start"
    );
    assert_eq!(
        height,
        Some(top),
        "the node that was handed a ledger came back somewhere else"
    );
}

/// A node that joined a network that pins its first block fills in the
/// headers from before it arrived and can then hand a ledger on.
///
/// Its header log held the first block's header from the moment it opened, so
/// the headers a handover comes with had nowhere to go, and nothing else it
/// wrote could follow on from it. Nothing asked this on such a network, so a
/// node that could never take anybody in passed.
#[test]
fn a_node_that_joined_a_network_that_pins_its_first_block_can_take_someone_in() {
    let params = params();
    let (blocks, forge) = a_long_chain();
    let mut forge = forge.clone();
    let top = blocks.last().unwrap().header.height;
    let root = scratch("relay");

    let (host, _) = Node::open(params, loopback(), root.join("host")).unwrap();
    for block in blocks {
        host.submit_block(block.clone()).unwrap();
    }

    let (joined, _) = Node::open(params, loopback(), root.join("joined")).unwrap();
    joined.connect(host.address()).unwrap();
    wait_for("the node to reach the host's tip", || {
        joined.height() == Some(top) || joined.unwritten().is_some()
    });
    assert!(
        joined.unwritten().is_none(),
        "the node that was handed a ledger could not write what it validated after it"
    );
    assert_eq!(
        joined.joining(),
        Joined::Done,
        "the premise: it was handed a ledger rather than reading the chain"
    );

    wait_for("the headers from before it arrived", || {
        cairn_store::HeaderLog::open(root.join("joined"))
            .map(|log| log.first_height() == 0 && log.reaches() > top)
            .unwrap_or(false)
    });

    // It validates its way past a burial of its own before it has anything to
    // hand over.
    for _ in 0..=params.burial {
        joined.submit_block(forge.mine()).unwrap();
    }
    let top = top + params.burial + 1;
    wait_for("the node that joined to validate past a burial", || {
        joined.height() == Some(top)
    });

    host.shutdown();
    let (newcomer, _) = Node::open(params, loopback(), root.join("newcomer")).unwrap();
    newcomer.connect(joined.address()).unwrap();
    wait_for(
        "a newcomer to reach the tip through the node that joined",
        || newcomer.height() == Some(top),
    );
    let handed = newcomer.joining();
    let same_ledger = newcomer.with_chain(|chain| chain.state().state_root())
        == joined.with_chain(|chain| chain.state().state_root());
    newcomer.shutdown();
    joined.shutdown();
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(
        handed,
        Joined::Done,
        "a newcomer was not handed a ledger by a node that was handed one itself"
    );
    assert!(
        same_ledger,
        "the ledger handed on is not the one the node holds"
    );
}

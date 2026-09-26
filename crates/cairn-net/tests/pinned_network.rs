//! Joining a chain on a network that pins its first block.
//!
//! Every other test of the handover runs on `ConsensusParams::testnet()`,
//! which pins nothing, so a newcomer there starts with no chain at all. The
//! two real networks pin theirs, and a node on either lays that block down the
//! moment it opens a directory. Its chain is then not empty, and everything
//! that decides whether a node joins asked whether it was: so on testnet-6 and
//! on the devnet every newcomer read the whole chain block by block, and the
//! handover ran only in tests.
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

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::{Joined, Node};

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

/// Mines on the devnet from its real first block, a minute apart.
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
        self.clock += 60;
        let now = wall_clock();
        assert!(self.clock < now, "the chain would run into the future");
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

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("cairn-pinned-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    root
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

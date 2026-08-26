//! Real nodes on real sockets.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const PATIENCE: Duration = Duration::from_secs(15);

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// Builds blocks off to the side, so a node can be handed a ready made chain.
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

    fn mine(&mut self) -> Block {
        let miner = SecretKey::from_bytes(&[1; 32]);
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.block_reward, miner.public_key())],
            [0; 8],
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
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_many(&mut self, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine()).collect()
    }
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn a_node_starting_from_nothing_catches_up_over_tcp() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(25);

    let seeded = Node::bind(params, loopback()).unwrap();
    for block in &blocks {
        seeded.submit_block(block.clone()).unwrap();
    }
    assert_eq!(seeded.height(), Some(24));

    let fresh = Node::bind(params, loopback()).unwrap();
    assert_eq!(fresh.height(), None, "it starts with nothing at all");

    fresh.connect(seeded.address()).unwrap();
    wait_for("the fresh node to catch up", || fresh.height() == Some(24));

    let tips = (
        fresh.with_chain(ChainStore::tip),
        seeded.with_chain(ChainStore::tip),
    );
    assert_eq!(tips.0, tips.1);
    assert_eq!(
        fresh.with_chain(|chain| chain.state().state_root()),
        seeded.with_chain(|chain| chain.state().state_root()),
        "the ledger came across, not just the blocks"
    );
    assert_eq!(fresh.total_work(), seeded.total_work());
}

#[test]
fn a_new_block_reaches_a_connected_peer() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(5);

    let first = Node::bind(params, loopback()).unwrap();
    let second = Node::bind(params, loopback()).unwrap();
    for block in &blocks {
        first.submit_block(block.clone()).unwrap();
    }

    second.connect(first.address()).unwrap();
    wait_for("the peers to line up", || second.height() == Some(4));

    let fresh = forge.mine();
    first.submit_block(fresh.clone()).unwrap();

    wait_for("the new block to travel", || second.height() == Some(5));
    assert_eq!(second.with_chain(ChainStore::tip), Some(fresh.id()));
}

#[test]
fn a_block_travels_through_a_node_that_only_relays_it() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(3);

    // Wired in a line: the ends never speak to each other.
    let left = Node::bind(params, loopback()).unwrap();
    let middle = Node::bind(params, loopback()).unwrap();
    let right = Node::bind(params, loopback()).unwrap();

    for block in &blocks {
        left.submit_block(block.clone()).unwrap();
    }
    middle.connect(left.address()).unwrap();
    right.connect(middle.address()).unwrap();

    wait_for("the line to line up", || {
        middle.height() == Some(2) && right.height() == Some(2)
    });

    let fresh = forge.mine();
    left.submit_block(fresh.clone()).unwrap();

    wait_for("the block to cross the line", || right.height() == Some(3));
    assert_eq!(right.with_chain(ChainStore::tip), Some(fresh.id()));
    assert_eq!(
        right.with_chain(|chain| chain.state().state_root()),
        left.with_chain(|chain| chain.state().state_root())
    );
}

#[test]
fn a_peer_following_another_network_is_turned_away() {
    let mut theirs = params();
    theirs.network = cairn_ledger::note::NetworkId::MAINNET;

    let ours = Node::bind(params(), loopback()).unwrap();
    let stranger = Node::bind(theirs, loopback()).unwrap();

    stranger.connect(ours.address()).unwrap();

    // The connection is refused as soon as the marker is read, so neither side
    // keeps it.
    wait_for("both sides to hang up", || {
        ours.peer_count() == 0 && stranger.peer_count() == 0
    });
}

#[test]
fn a_node_shuts_down_cleanly_while_peers_are_attached() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(3);

    let first = Node::bind(params, loopback()).unwrap();
    let second = Node::bind(params, loopback()).unwrap();
    for block in &blocks {
        first.submit_block(block.clone()).unwrap();
    }
    second.connect(first.address()).unwrap();
    wait_for("the peers to line up", || second.height() == Some(2));

    first.shutdown();
    second.shutdown();
    wait_for("the connections to close", || {
        first.peer_count() == 0 && second.peer_count() == 0
    });
}

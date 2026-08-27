//! Real nodes on real sockets.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::wire::write_message;
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

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

#[test]
fn a_node_comes_back_with_the_chain_it_had() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(12);

    let directory = std::env::temp_dir().join(format!("cairn-node-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);

    let root = {
        let node = Node::open(params, loopback(), &directory).unwrap().0;
        for block in &blocks {
            node.submit_block(block.clone()).unwrap();
        }
        assert_eq!(node.height(), Some(11));
        let root = node.with_chain(|chain| chain.state().state_root());
        node.shutdown();
        root
    };

    let (revived, restored) = Node::open(params, loopback(), &directory).unwrap();
    assert_eq!(restored.blocks, 12, "every block came back");
    assert_eq!(restored.refused, 0);
    assert_eq!(restored.discarded_bytes, 0);
    assert_eq!(revived.height(), Some(11));
    assert_eq!(revived.with_chain(|chain| chain.state().state_root()), root);
}

#[test]
fn a_restarted_node_keeps_what_it_learned_from_a_peer() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(10);

    let directory = std::env::temp_dir().join(format!("cairn-node-learned-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);

    let seeded = Node::bind(params, loopback()).unwrap();
    for block in &blocks {
        seeded.submit_block(block.clone()).unwrap();
    }

    {
        let learner = Node::open(params, loopback(), &directory).unwrap().0;
        learner.connect(seeded.address()).unwrap();
        wait_for("the node to catch up", || learner.height() == Some(9));
        learner.shutdown();
    }

    let (revived, restored) = Node::open(params, loopback(), &directory).unwrap();
    assert_eq!(
        restored.blocks, 10,
        "what arrived over the wire was written down"
    );
    assert_eq!(revived.height(), Some(9));
    assert_eq!(
        revived.with_chain(|chain| chain.state().state_root()),
        seeded.with_chain(|chain| chain.state().state_root())
    );
}

#[test]
fn a_node_reaches_a_peer_it_was_never_told_about() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(4);

    // Everyone is told about the hub and nothing else.
    let hub = Node::bind(params, loopback()).unwrap();
    for block in &blocks {
        hub.submit_block(block.clone()).unwrap();
    }

    let first = Node::bind(params, loopback()).unwrap();
    let second = Node::bind(params, loopback()).unwrap();
    first.connect(hub.address()).unwrap();
    second.connect(hub.address()).unwrap();

    wait_for("both to catch up through the hub", || {
        first.height() == Some(3) && second.height() == Some(3)
    });

    wait_for("the two edges to hear about each other", || {
        first.known_addresses().contains(&second.address())
    });
    wait_for("and then to connect directly", || first.peer_count() >= 2);

    assert!(
        second.known_addresses().contains(&first.address()),
        "the hub passed each one along to the other"
    );
}

/// The failure this guards against: a peer that opens a frame and stops.
///
/// Before deadlines existed, the thread reading from it waited for as long as
/// the peer kept the socket open, and a handful of such peers was enough to
/// leave a node unable to hear anything else.
#[test]
fn a_peer_that_opens_a_frame_and_goes_quiet_is_let_go() {
    let node = Node::bind(params(), loopback()).unwrap();

    let mut stalled = TcpStream::connect(node.address()).unwrap();
    let mut header = Vec::new();
    params().network.as_u32().encode_to(&mut header);
    1_000_000u32.encode_to(&mut header);
    stalled.write_all(&header).unwrap();
    stalled.flush().unwrap();

    wait_for("the node to take the connection", || node.peer_count() == 1);
    wait_for("the stalled peer to be let go", || node.peer_count() == 0);

    // And the node is still itself: a well behaved peer still gets in.
    let other = Node::bind(params(), loopback()).unwrap();
    other.connect(node.address()).unwrap();
    wait_for("a healthy peer to be accepted", || node.peer_count() == 1);
}

/// A peer that sends a block this node rejects is disconnected.
///
/// Whether it is then turned away for a while is decided in `refusal`, which
/// exempts the loopback address and so cannot be exercised from here: several
/// nodes on one machine must not lock each other out.
#[test]
fn a_peer_that_sends_a_bad_block_is_dropped() {
    let node = Node::bind(params(), loopback()).unwrap();
    let mut forge = Forge::new(params());
    let mut block = forge.mine();
    // Claim a ledger this block does not produce.
    block.header.state_root = Hash32::ZERO;

    let mut rude = TcpStream::connect(node.address()).unwrap();
    let hello = Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen: 1,
    });
    write_message(&mut rude, params().network, &hello).unwrap();
    write_message(
        &mut rude,
        params().network,
        &Message::Block(Box::new(block)),
    )
    .unwrap();

    wait_for("the bad peer to be dropped", || node.peer_count() == 0);
}

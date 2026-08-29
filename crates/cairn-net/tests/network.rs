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
use cairn_net::{Joined, Node};
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

    /// A second forge carrying on from the same point, for building a rival
    /// branch off the one already made.
    fn fork(&self) -> Self {
        Self {
            params: self.params,
            state: self.state.clone(),
            clock: self.clock,
        }
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
        nonce: 424_242,
        archives: false,
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

/// Stopping must not depend on someone connecting.
///
/// The accept loop used to block until a connection arrived, so shutting down
/// meant opening one to wake it. On a node listening on a public address that
/// connection can fail, and the node would then never stop.
#[test]
fn a_node_stops_promptly_with_nobody_around() {
    let node = Node::bind(params(), loopback()).unwrap();
    let started = Instant::now();
    node.shutdown();
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(2),
        "shutting down took {took:?}, which means it waited on something"
    );
}

/// The address an operator gives is the one a node can always come back to.
///
/// A node keeps the addresses it learns and drops the ones that stop
/// answering, which is right until every one of them stops answering at once:
/// a closed laptop, a pulled cable, a machine that slept. The book empties,
/// and an empty book has no way back, because rejoining a network means asking
/// someone and there is nobody left to ask. Seeds are what a node is left with
/// when everything else is gone, so they survive any amount of silence, and
/// they are written down before they are dialled rather than after they answer.
#[test]
fn a_seed_that_never_answers_is_still_known() {
    let params = params();

    // An address nothing is listening on: bound to learn the port, then let go.
    let vacant = {
        let held = std::net::TcpListener::bind(loopback()).unwrap();
        held.local_addr().unwrap()
    };

    let node = Node::bind(params, loopback()).unwrap();
    node.remember_seed(vacant);
    assert!(
        node.connect(vacant).is_err(),
        "nothing is listening there, so the dial has to fail"
    );

    assert!(
        node.known_addresses().contains(&vacant),
        "a seed that was down when this node started is still worth trying later"
    );

    // Naming it again is not a second address.
    node.remember_seed(vacant);
    assert_eq!(
        node.known_addresses()
            .iter()
            .filter(|address| **address == vacant)
            .count(),
        1
    );
}

/// A node serves history it no longer holds in memory.
///
/// Past the depth a reorganisation may reach, a block is settled: it will
/// never be undone, so a node lets its body go and keeps only its place. That
/// is what stops a node's memory growing with the chain. But a newcomer asks
/// for exactly those blocks, and a network where nobody can answer for its own
/// past is not a network anybody can join. The log on disk holds the followed
/// branch in order of height, so the answer is a seek.
#[test]
fn a_node_serves_blocks_it_has_forgotten() {
    let params = params();
    let mut forge = Forge::new(params);
    // Comfortably past the window, so the early blocks are gone from memory.
    let depth = cairn_chain::MAX_REORG_DEPTH + 200;
    let blocks = forge.mine_many(depth);

    let directory = std::env::temp_dir().join(format!("cairn-forgotten-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);

    let (seeded, _) = Node::open(params, loopback(), &directory).unwrap();
    for block in &blocks {
        seeded.submit_block(block.clone()).unwrap();
    }
    let top = (depth - 1) as u64;
    assert_eq!(seeded.height(), Some(top));

    // The first block is out of memory, and so is the index that would say
    // where it was: a node holds neither for what it can no longer undo. What
    // it does hold is one identifier every so often, and height zero is one of
    // them, which is how a peer's locator finds a point both sides agree on.
    let genesis = blocks[0].id();
    seeded.with_chain(|chain| {
        assert!(
            chain.block(&genesis).is_none(),
            "a settled block should not still be held in memory"
        );
        assert_eq!(chain.height_of(&genesis), None, "nor its place");
        assert_eq!(chain.id_at(0), Some(genesis), "but the milestone is kept");
        // A height that is neither inside the window nor a milestone.
        assert!(
            chain.block_at(100).is_none(),
            "and an early height is not held either"
        );
    });

    // A node starting from nothing has to be given all of it, forgotten or not.
    let fresh = Node::bind(params, loopback()).unwrap();
    assert_eq!(fresh.height(), None);
    fresh.connect(seeded.address()).unwrap();
    wait_for("the fresh node to catch up", || fresh.height() == Some(top));

    assert_eq!(
        fresh.with_chain(|chain| chain.state().state_root()),
        seeded.with_chain(|chain| chain.state().state_root()),
        "the ledger came across, not just the blocks"
    );
    assert_eq!(fresh.total_work(), seeded.total_work());

    seeded.shutdown();
    fresh.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A reorganisation leaves the log holding the branch, not the arrivals.
///
/// The log is what a node reads a forgotten block back from, and it finds one
/// by position, because position is height. That only holds while the log is
/// the followed branch: if a reorganisation left the abandoned blocks in it,
/// every position past the fork would point at a block on a branch this node
/// gave up, and the node would serve those to anyone catching up. Wrong
/// answers, delivered confidently, which is worse than no answer.
#[test]
fn a_reorganisation_leaves_the_log_matching_the_branch() {
    let params = params();
    let mut shared = Forge::new(params);
    let common = shared.mine_many(6);

    // Two branches from the same point. The rival is longer, so it is heavier.
    let mut ours = shared.fork();
    let ours_blocks = ours.mine_many(4);
    let mut theirs = shared.fork();
    let theirs_blocks = theirs.mine_many(9);

    let directory = std::env::temp_dir().join(format!("cairn-reorg-log-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);

    {
        let (node, _) = Node::open(params, loopback(), &directory).unwrap();
        for block in common.iter().chain(&ours_blocks) {
            node.submit_block(block.clone()).unwrap();
        }
        assert_eq!(node.height(), Some(9), "six shared and four of ours");

        for block in &theirs_blocks {
            node.submit_block(block.clone()).unwrap();
        }
        assert_eq!(node.height(), Some(14), "six shared and nine of theirs");
        node.shutdown();
    }

    // Read the log back on its own, the way a node does when it starts.
    let (log, recovered) = cairn_store::BlockLog::open(&directory).unwrap();
    let expected: Vec<Block> = common.iter().chain(&theirs_blocks).cloned().collect();
    assert_eq!(recovered.blocks, expected.len(), "no abandoned blocks left");

    for (height, want) in expected.iter().enumerate() {
        let found = log.read(height).unwrap().expect("a record at every height");
        assert_eq!(
            found.id(),
            want.id(),
            "the record at position {height} is not the block at that height"
        );
        assert_eq!(found.header.height, height as u64);
    }

    // And a node opened on it comes back on the branch it was following.
    let (again, restored) = Node::open(params, loopback(), &directory).unwrap();
    assert_eq!(restored.blocks, expected.len(), "every record replayed");
    assert_eq!(again.height(), Some(14));
    assert_eq!(again.with_chain(ChainStore::tip), Some(expected[14].id()));
    again.shutdown();

    let _ = std::fs::remove_dir_all(&directory);
}

/// A node partway along catches up with one far ahead.
///
/// The case that is easy to get wrong once a node stops holding an identifier
/// for every height. The node behind names the heights it has, and the node
/// ahead no longer holds identifiers for most of them: without reading its own
/// log to answer, the only position both could agree on is the last milestone,
/// and the node behind would be told to start again from there, receive what
/// it already has, and creep forward a block at a time.
#[test]
fn a_node_partway_along_catches_up_with_one_far_ahead() {
    let params = params();
    let mut forge = Forge::new(params);
    // Comfortably past the window on both sides, so the heights the node
    // behind names are ones the node ahead has long since let go of.
    let blocks = forge.mine_many(cairn_chain::MAX_REORG_DEPTH + 400);
    let top = (blocks.len() - 1) as u64;

    let root = std::env::temp_dir().join(format!("cairn-partway-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let (ahead, _) = Node::open(params, loopback(), root.join("ahead")).unwrap();
    for block in &blocks {
        ahead.submit_block(block.clone()).unwrap();
    }
    assert_eq!(ahead.height(), Some(top));

    // Partway along, and past its own window, so it is not simply a fresh node.
    let (behind, _) = Node::open(params, loopback(), root.join("behind")).unwrap();
    for block in blocks.iter().take(cairn_chain::MAX_REORG_DEPTH + 100) {
        behind.submit_block(block.clone()).unwrap();
    }
    let started = behind.height().expect("it has a chain of its own");
    assert!(started < top, "and it is behind");

    behind.connect(ahead.address()).unwrap();
    wait_for("the node behind to catch up", || {
        behind.height() == Some(top)
    });

    assert_eq!(
        behind.with_chain(|chain| chain.state().state_root()),
        ahead.with_chain(|chain| chain.state().state_root()),
    );

    behind.shutdown();
    ahead.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

/// A node joins a chain it was never on, without reading it.
///
/// The whole point of the two exchanges. One node has a chain; another has
/// nothing and is handed, first, enough headers to see what work stands behind
/// that chain, and then the ledger at its tip. It checks both against what the
/// headers commit to, adopts the result, and carries on as a node that was
/// there all along.
#[test]
fn a_node_joins_a_chain_it_never_read() {
    let params = params();
    let mut forge = Forge::new(params);
    // Past the length where a node chooses to be handed a ledger rather than
    // read one, since being handed one is what this tests.
    let blocks =
        forge.mine_many(usize::try_from(cairn_net::sync::JOIN_RATHER_THAN_READ).unwrap() + 40);
    let top = (blocks.len() - 1) as u64;

    let directory = std::env::temp_dir().join(format!("cairn-join-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);

    // The node that answers keeps the headers, which is what proving takes.
    let (keeper, _) = Node::open_archiving(params, loopback(), &directory).unwrap();
    for block in &blocks {
        keeper.submit_block(block.clone()).unwrap();
    }
    assert_eq!(keeper.height(), Some(top));

    let newcomer = Node::bind(params, loopback()).unwrap();
    assert_eq!(newcomer.height(), None, "it starts with nothing at all");

    newcomer.connect(keeper.address()).unwrap();
    wait_for("the newcomer to join", || newcomer.height() == Some(top));
    // Reaching the height says nothing about how: reading the chain block by
    // block would reach it too, and did, back when the handover was broken and
    // the fall back to reading covered for it.
    assert_eq!(
        newcomer.joining(),
        Joined::Done,
        "the ledger was handed over rather than read"
    );

    assert_eq!(
        newcomer.with_chain(|chain| chain.state().state_root()),
        keeper.with_chain(|chain| chain.state().state_root()),
        "the ledger came across, not a copy of it"
    );
    assert_eq!(newcomer.total_work(), keeper.total_work());

    // And it is a node, not a snapshot: the next block lands on it.
    let next = forge.mine();
    keeper.submit_block(next.clone()).unwrap();
    wait_for("the next block to reach the newcomer", || {
        newcomer.height() == Some(top + 1)
    });
    assert_eq!(
        newcomer.with_chain(|chain| chain.state().state_root()),
        keeper.with_chain(|chain| chain.state().state_root()),
    );

    newcomer.shutdown();
    keeper.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A newcomer asks the node that can answer, and only that one.
///
/// Showing what work stands behind a chain takes a path through the header
/// forest, and only a node that kept the headers can build one. Everyone else
/// holds sixty four hashes, which is enough to check such a path and not
/// enough to make it. So a node with nothing asks an archivist, and reads
/// blocks one at a time from anybody else, rather than asking everyone and
/// waiting on the ones that will never answer.
#[test]
fn a_newcomer_joins_through_an_archivist_and_reads_from_the_rest() {
    let params = params();
    let mut forge = Forge::new(params);
    // Past the point where being handed a ledger beats reading one, since
    // that is the choice being tested.
    let blocks =
        forge.mine_many(usize::try_from(cairn_net::sync::JOIN_RATHER_THAN_READ).unwrap() + 40);
    let top = (blocks.len() - 1) as u64;

    let root = std::env::temp_dir().join(format!("cairn-archivist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    // One node that kept everything, and one that validated and no more.
    let (keeper, _) = Node::open_archiving(params, loopback(), root.join("keeper")).unwrap();
    let (plain, _) = Node::open(params, loopback(), root.join("plain")).unwrap();
    for block in &blocks {
        keeper.submit_block(block.clone()).unwrap();
        plain.submit_block(block.clone()).unwrap();
    }

    // Reaching only the plain node, a newcomer still gets there, the long way.
    let reader = Node::bind(params, loopback()).unwrap();
    reader.connect(plain.address()).unwrap();
    wait_for("the reader to catch up block by block", || {
        reader.height() == Some(top)
    });
    assert_eq!(
        reader.with_chain(|chain| chain.state().state_root()),
        plain.with_chain(|chain| chain.state().state_root()),
    );

    // Reaching the archivist, another newcomer is handed the whole thing.
    let joiner = Node::bind(params, loopback()).unwrap();
    assert_eq!(
        joiner.joining(),
        Joined::No,
        "a node that has asked nobody is not joining"
    );
    joiner.connect(keeper.address()).unwrap();
    wait_for("the joiner to be handed a ledger", || {
        joiner.height() == Some(top)
    });
    assert_eq!(
        joiner.joining(),
        Joined::Done,
        "and it says so, which is what an operator watching a node with no \
         height yet has to go on"
    );
    assert_eq!(
        joiner.with_chain(|chain| chain.state().state_root()),
        keeper.with_chain(|chain| chain.state().state_root()),
    );

    // Neither of them holds what happened before the window it could still
    // undo, whichever way it got there. What separates them is the role: only
    // the one that read the chain from the first block can hand it on.
    for node in [&reader, &joiner] {
        assert!(
            node.with_chain(|chain| chain.block_at(0).is_none()),
            "a node does not hold what it can no longer undo"
        );
    }
    assert!(
        !joiner.with_chain(cairn_chain::ChainStore::is_archiving),
        "and so it does not offer to hand the chain on, which is why the role \
         belongs to nodes that read it from the first block"
    );

    for node in [reader, joiner, plain, keeper] {
        node.shutdown();
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_archivist_says_so_when_it_introduces_itself() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(4);
    let root = std::env::temp_dir().join(format!("cairn-says-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let (keeper, _) = Node::open_archiving(params, loopback(), root.join("keeper")).unwrap();
    let (plain, _) = Node::open(params, loopback(), root.join("plain")).unwrap();
    for block in &blocks {
        keeper.submit_block(block.clone()).unwrap();
        plain.submit_block(block.clone()).unwrap();
    }
    assert!(keeper.with_chain(cairn_chain::ChainStore::is_archiving));
    assert!(!plain.with_chain(cairn_chain::ChainStore::is_archiving));

    keeper.shutdown();
    plain.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

/// A node handed a ledger has to become an ordinary node: one that writes what
/// it validates, serves it, and comes back after a restart.
///
/// It cannot write from the first block, because it never had one. Its log
/// starts at the height it was handed, and everything about reading a block
/// back by height has to work from there.
#[test]
fn a_node_that_joined_writes_and_serves_what_it_validates() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks =
        forge.mine_many(usize::try_from(cairn_net::sync::JOIN_RATHER_THAN_READ).unwrap() + 40);
    let top = (blocks.len() - 1) as u64;

    let root = std::env::temp_dir().join(format!("cairn-writes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let (keeper, _) = Node::open_archiving(params, loopback(), root.join("keeper")).unwrap();
    for block in &blocks {
        keeper.submit_block(block.clone()).unwrap();
    }

    let (joiner, _) = Node::open(params, loopback(), root.join("joiner")).unwrap();
    joiner.connect(keeper.address()).unwrap();
    wait_for("the joiner to be handed a ledger", || {
        joiner.height() == Some(top)
    });
    assert_eq!(joiner.joining(), Joined::Done);
    assert!(
        joiner.archived_at(top).is_none(),
        "it wrote nothing yet, having validated nothing yet"
    );

    // Blocks it validates itself, which are the ones it can vouch for.
    for _ in 0..3 {
        let next = forge.mine();
        let at = next.header.height;
        keeper.submit_block(next).unwrap();
        wait_for("the next block to reach the joiner", || {
            joiner.height() == Some(at)
        });
    }

    let written = joiner.archived_at(top + 1).expect("the first it validated");
    assert_eq!(
        written.header.height,
        top + 1,
        "at its own height, not at 0"
    );
    assert_eq!(
        joiner.archived_at(top + 3).map(|block| block.header.height),
        Some(top + 3),
    );
    assert!(
        joiner.archived_at(top).is_none(),
        "and nothing it was only handed"
    );

    // And it comes back on its own. It kept the ledger it was handed, so it
    // starts from that and replays its own blocks over it, with nobody to ask.
    joiner.shutdown();
    drop(joiner);
    let (again, restored) = Node::open(params, loopback(), root.join("joiner")).unwrap();
    assert!(
        !restored.rejoining,
        "it had the ledger it was handed, so nothing was set aside"
    );
    assert_eq!(restored.blocks, 3, "the blocks it validated came back");
    assert_eq!(restored.refused, 0);
    assert_eq!(
        again.height(),
        Some(top + 3),
        "back where it was, without asking anyone"
    );
    assert_eq!(
        again.with_chain(|chain| chain.state().state_root()),
        keeper.with_chain(|chain| chain.state().state_root()),
        "and on the same ledger, not an approximation of it"
    );
    assert_eq!(again.total_work(), keeper.total_work());

    // Losing that file is what used to be the only case: it cannot read its
    // way back, so it says so and joins again.
    again.shutdown();
    drop(again);
    std::fs::remove_file(root.join("joiner").join(cairn_store::HANDED_LEDGER)).unwrap();
    let (bare, restored) = Node::open(params, loopback(), root.join("joiner")).unwrap();
    assert!(restored.rejoining, "the log starts partway up the chain");
    assert_eq!(restored.blocks, 0);
    assert_eq!(restored.refused, 0, "set aside is not the same as refused");
    assert_eq!(bare.height(), None);

    bare.connect(keeper.address()).unwrap();
    wait_for("the joiner to be handed a ledger a second time", || {
        bare.height() == Some(top + 3)
    });

    bare.shutdown();
    keeper.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

/// A node's disk must not grow with the chain. It keeps the ledger its blocks
/// add up to and drops the blocks, which is what the sampled start made
/// possible: a newcomer no longer reads the history, so nobody has to keep it
/// for them.
#[test]
fn a_node_writes_its_ledger_down_and_stops_keeping_every_block() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(300);
    let top = (blocks.len() - 1) as u64;

    let root = std::env::temp_dir().join(format!("cairn-trim-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let (node, _) = Node::open(params, loopback(), root.join("node")).unwrap();
    for block in &blocks {
        node.submit_block(block.clone()).unwrap();
    }
    let whole = node.kept_bytes();
    assert!(whole > 0, "it wrote the blocks it validated");
    assert!(node.archived_at(0).is_some(), "including the first");

    // Told to keep almost nothing, it writes the ledger down and lets the
    // blocks go on the next round of upkeep.
    node.keep_blocks(1);
    wait_for("the node to drop what it no longer needs", || {
        node.kept_bytes() < whole
    });
    assert!(
        node.archived_at(0).is_none(),
        "the oldest blocks are gone from disk"
    );
    assert_eq!(node.height(), Some(top), "and the chain is where it was");

    // What it dropped it can no longer serve, and what it kept it still can.
    let mined = forge.mine();
    let at = mined.header.height;
    node.submit_block(mined).unwrap();
    assert_eq!(
        node.archived_at(at).map(|block| block.header.height),
        Some(at),
        "blocks it validates after the trim are written at their own height"
    );

    // And it starts again from the ledger rather than from the first block.
    node.shutdown();
    drop(node);
    let (again, restored) = Node::open(params, loopback(), root.join("node")).unwrap();
    assert!(
        !restored.rejoining,
        "it had written its own ledger down, so nothing was set aside"
    );
    assert_eq!(
        again.height(),
        Some(at),
        "back where it was, holding almost none of the chain"
    );
    assert!(again.kept_bytes() < whole);

    again.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

/// An archivist reads the headers it proves things about out of the blocks it
/// kept, so trimming those would leave it unable to answer a newcomer while
/// still telling everyone it can. It keeps them all instead.
#[test]
fn an_archivist_keeps_the_blocks_it_proves_things_from() {
    let params = params();
    let root = std::env::temp_dir().join(format!("cairn-keeps-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let (keeper, _) = Node::open_archiving(params, loopback(), root.join("keeper")).unwrap();
    let (plain, _) = Node::open(params, loopback(), root.join("plain")).unwrap();

    let mut forge = Forge::new(params);
    for block in forge.mine_many(40) {
        keeper.submit_block(block.clone()).unwrap();
        plain.submit_block(block).unwrap();
    }

    // The plain node lets blocks go once it has written its ledger down; the
    // archivist cannot, because proving where a header sits means reading it.
    plain.keep_blocks(1);
    wait_for("the plain node to drop what it no longer needs", || {
        plain.archived_at(0).is_none()
    });
    assert!(
        keeper.archived_at(0).is_some(),
        "an archivist that dropped these could not answer a newcomer, and \
         would still be saying it can"
    );

    keeper.shutdown();
    plain.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

/// Writing the ledger down and dropping the blocks below it are two steps, and
/// a machine can stop between them. What is left is a ledger and a log that
/// starts before it, which is not a fault: the blocks the ledger already
/// stands for are passed over, and the rest is replayed.
#[test]
fn a_node_stopped_between_writing_its_ledger_and_dropping_blocks_comes_back() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(60);
    let top = (blocks.len() - 1) as u64;

    let root = std::env::temp_dir().join(format!("cairn-halfway-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let directory = root.join("node");

    let (node, _) = Node::open(params, loopback(), &directory).unwrap();
    for block in &blocks {
        node.submit_block(block.clone()).unwrap();
    }
    let root_before = node.with_chain(|chain| chain.state().state_root());
    node.shutdown();
    drop(node);

    // The ledger is written and the blocks are all still there, which is
    // exactly the state a stop between the two steps leaves behind.
    let (node, _) = Node::open(params, loopback(), &directory).unwrap();
    assert!(node.write_ledger(), "the ledger went down");
    assert!(
        node.archived_at(0).is_some(),
        "and every block is still there"
    );
    node.shutdown();
    drop(node);
    assert!(directory.join(cairn_store::HANDED_LEDGER).exists());

    let (again, restored) = Node::open(params, loopback(), &directory).unwrap();
    assert!(
        !restored.rejoining,
        "a log reaching further back than the ledger is not a broken log"
    );
    assert_eq!(restored.refused, 0, "and nothing was refused");
    assert_eq!(again.height(), Some(top));
    assert_eq!(
        again.with_chain(|chain| chain.state().state_root()),
        root_before,
        "on exactly the ledger it had"
    );
    assert!(
        again.archived_at(0).is_none(),
        "and the blocks the ledger stands for are dropped rather than walked again"
    );

    again.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

/// Dropping old blocks must not cost a node its ability to change branches.
/// Undoing reads what a block did, which is held in memory, not the block; but
/// a node that trimmed and then reorganised also has to leave its log and its
/// written ledger saying the same thing as the branch it ended up on.
#[test]
fn a_node_that_dropped_blocks_can_still_change_branches() {
    let params = params();
    let mut forge = Forge::new(params);
    let common = forge.mine_many(40);

    // Two branches from the same point, the second one heavier by two blocks.
    let mut theirs = forge.clone();
    let ours = forge.mine_many(6);
    let rival = theirs.mine_many(8);

    let root = std::env::temp_dir().join(format!("cairn-reorg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let directory = root.join("node");

    let (node, _) = Node::open(params, loopback(), &directory).unwrap();
    for block in common.iter().chain(ours.iter()) {
        node.submit_block(block.clone()).unwrap();
    }
    assert_eq!(node.height(), Some(45));

    // It writes its ledger down and lets the oldest blocks go.
    node.keep_blocks(1);
    wait_for("the node to drop what it no longer needs", || {
        node.archived_at(0).is_none()
    });

    // Then the heavier branch arrives and it has to switch.
    for block in &rival {
        let _ = node.submit_block(block.clone());
    }
    assert_eq!(node.height(), Some(47), "it took the heavier branch");
    assert_eq!(
        node.with_chain(|chain| chain.tip()),
        Some(rival.last().unwrap().id()),
        "and is on it, not on a mixture of the two"
    );

    // And what it wrote down still agrees with where it ended up.
    node.shutdown();
    drop(node);
    let (again, restored) = Node::open(params, loopback(), &directory).unwrap();
    assert_eq!(
        again.height(),
        Some(47),
        "restored: {} blocks, rejoining {}",
        restored.blocks,
        restored.rejoining
    );
    assert_eq!(
        again.with_chain(|chain| chain.tip()),
        Some(rival.last().unwrap().id()),
    );

    again.shutdown();
    let _ = std::fs::remove_dir_all(&root);
}

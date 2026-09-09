//! The fallback that needs what ordinary nodes are allowed to delete.
//!
//! There are two ways onto a chain. A newcomer can be shown what work stands
//! behind a tip, weigh it, and be handed the ledger; or it can read the chain
//! block by block and check every block itself. The first is refused on a
//! chain whose difficulty has fallen far enough below what it once ran at,
//! because the run of headers it would take is longer than
//! `cairn_ledger::sampling::MOST_TAIL`, and the project says so. The answer it
//! gives is the second way in.
//!
//! The second way needs block bodies. Every node keeps every header, and no
//! node is obliged to keep a body: the default budget is
//! [`cairn_net::node::KEEP_BLOCK_BYTES`], and once a node has written its
//! ledger down the blocks below it go. Headers do not reconstruct a deleted
//! body.
//!
//! So the two ways in do not fail together, and that is what these tests fix.
//! A node that has dropped its old bodies still says it keeps the headers,
//! still hands over a ledger, and still tells a newcomer to start reading at
//! the first block, and then answers with nothing when the newcomer does. A
//! running node carries on. A newcomer, on the day the first way in is
//! refused, cannot arrive at all unless somebody kept the bodies.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Joining, Message, PROTOCOL_VERSION};
use cairn_net::wire::{read_message, write_message, Incoming};
use cairn_net::{Keeps, Node};
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Blocks the chain here carries.
///
/// Enough that a trim leaves a clear stretch of heights the node no longer
/// holds a body for, and nothing more: what is being measured is which heights
/// come back, not how many.
const BLOCKS: usize = 200;

/// Shallow burial, so a test does not mine its way through a number chosen for
/// a live network. Nothing here turns on the depth.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(8)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-needs-bodies-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// A chain built off to the side, so a node can be given a real one.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine_many(&mut self, count: usize) -> Vec<Block> {
        (0..count)
            .map(|_| {
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
            })
            .collect()
    }
}

/// A node holding the whole chain, told to keep almost none of the bodies.
///
/// The budget is a preference an operator sets and this one is extreme, which
/// is the only way to reach in a test what a live node reaches by running: the
/// default is a gigabyte, and a chain outgrows it by being a chain.
struct Trimmed {
    node: Node,
    directory: PathBuf,
    /// The lowest height it still holds a body for.
    holds_from: u64,
    top: u64,
}

fn a_node_that_dropped_its_old_bodies(name: &str) -> Trimmed {
    let directory = scratch(name);
    let mut forge = Forge::new();
    let blocks = forge.mine_many(BLOCKS);
    let top = (blocks.len() - 1) as u64;

    let (node, _) = Node::open(params(), loopback(), directory.join("node")).unwrap();
    for block in &blocks {
        node.submit_block(block.clone()).unwrap();
    }
    assert!(node.archived_at(0).is_some(), "it wrote what it validated");

    node.keep_blocks(1);
    wait_for("the node to drop the blocks below its ledger", || {
        node.archived_at(0).is_none()
    });
    let holds_from = (0..=top)
        .find(|height| node.archived_at(*height).is_some())
        .expect("it keeps the window it can still undo");
    assert!(
        holds_from > 1,
        "there has to be a stretch of heights it no longer holds, or this test \
         is measuring nothing: it holds from {holds_from}"
    );

    Trimmed {
        node,
        directory,
        holds_from,
        top,
    }
}

fn a_handshake(listen: u16, nonce: u64) -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        // A newcomer holds nothing, so it has no first block to name and no
        // work to claim. This is what one looks like on the wire.
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen,
        nonce,
        keeps: Keeps::default(),
    })
}

/// Opens a connection and gets through the introduction.
fn a_newcomer_at(address: SocketAddr, listen: u16, nonce: u64) -> TcpStream {
    let mut peer = TcpStream::connect(address).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write_message(&mut peer, params().network, &a_handshake(listen, nonce)).unwrap();
    loop {
        match read_message(&mut peer, params().network) {
            Ok(Incoming::Message(Message::Welcome(_))) => break,
            Ok(_) => {}
            Err(error) => panic!("no welcome came back: {error}"),
        }
    }
    peer
}

/// **A node says where the chain it can hand over starts, and it is not the
/// first block.**
///
/// The whole of the second way in, as it actually goes. A newcomer holds
/// nothing, so its locator is empty and it agrees with the answering node
/// about no position at all. The answer to that is where to start reading.
///
/// It used to be zero, worked out from the height the branch reaches and never
/// from the heights this node can still produce a body for. So the newcomer
/// was pointed at the first block, asked for it, and was answered with
/// silence, which from the far end is what a peer that has stopped talking
/// looks like: it waited out its patience, asked again, was pointed at the
/// first block again, and did that for the rest of its life. Nothing anywhere
/// said the blocks were not there to be had.
///
/// Now it is told where this node's own log begins. That does not get the
/// newcomer onto the chain, and this test says so: what it is offered starts
/// above the first block, so the first block of it names a parent the
/// newcomer has no way to obtain and cannot be built on. The difference is
/// that the peer is no longer claiming otherwise.
#[test]
fn a_node_says_where_the_chain_it_can_hand_over_starts() {
    let trimmed = a_node_that_dropped_its_old_bodies("where-it-starts");
    let mut peer = a_newcomer_at(trimmed.node.address(), 41_301, 0x9101);

    // What a node with nothing asks: an empty locator, which agrees with
    // nobody about anything.
    write_message(
        &mut peer,
        params().network,
        &Message::GetChain {
            locator: Vec::new(),
        },
    )
    .unwrap();
    let (from, count) = loop {
        match read_message(&mut peer, params().network) {
            Ok(Incoming::Message(Message::Chain { from, count })) => break (from, count),
            Ok(_) => {}
            Err(error) => panic!("nothing came back about where to start: {error}"),
        }
    };
    assert!(count > 0, "it has a run of blocks to offer");
    assert!(
        from > 0,
        "and it does not offer the first block, which it does not hold"
    );
    assert!(
        trimmed.node.archived_at(from).is_some(),
        "what it names is a height it can actually produce a body for"
    );

    // The newcomer takes it at its word and asks. Two heights below what it
    // was offered and two inside it, so what comes back is a count and not a
    // wait: the two inside are what says the exchange finished.
    let asked = vec![0, 1, trimmed.holds_from, trimmed.top];
    write_message(
        &mut peer,
        params().network,
        &Message::GetBlocks(asked.clone()),
    )
    .unwrap();

    let mut arrived: BTreeSet<u64> = BTreeSet::new();
    let mut lowest_offered: Option<Block> = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !arrived.contains(&trimmed.top) {
        match read_message(&mut peer, params().network) {
            Ok(Incoming::Message(Message::Block(block))) => {
                arrived.insert(block.header.height);
                if block.header.height == trimmed.holds_from {
                    lowest_offered = Some(*block);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(
        arrived.contains(&trimmed.top) && arrived.contains(&trimmed.holds_from),
        "the heights it offered came back, so the question was heard and \
         answered: {arrived:?}"
    );
    assert!(
        !arrived.contains(&0) && !arrived.contains(&1),
        "and the heights below its log did not, in the same answer: {arrived:?}"
    );

    // And the finding this leaves standing. The lowest block this peer can
    // hand over is not the first block of the chain, so it names a parent that
    // has to come from somewhere else. Reading the chain checks every block
    // against the one below it, which is what makes reading safe and what
    // makes it impossible from here: there is no block below it to be had.
    let lowest = lowest_offered.expect("the lowest offered block arrived");
    assert!(
        lowest.header.height > 0 && lowest.header.previous != Hash32::ZERO,
        "the chain this peer can serve begins in the middle of the chain"
    );

    trimmed.node.shutdown();
    let _ = std::fs::remove_dir_all(&trimmed.directory);
}

/// **The same node still keeps the headers and still hands over a ledger.**
///
/// Which is why the loss above is invisible until the day it matters. Dropping
/// bodies costs a node nothing it advertises: it says it keeps the headers,
/// because it does, and being handed a ledger needs the headers and the ledger
/// and no body at all. Every newcomer takes that route while the chain can be
/// weighed.
///
/// So a network of nodes at their default budget serves newcomers perfectly
/// well until the sampled start is refused, and then serves none at all. The
/// two ways in are not two chances at the same thing: the second one depends
/// on what nobody is obliged to keep.
#[test]
fn a_node_that_dropped_its_bodies_still_keeps_the_headers_and_the_ledger() {
    let trimmed = a_node_that_dropped_its_old_bodies("still-hands-over");
    let mut peer = a_newcomer_at(trimmed.node.address(), 41_302, 0x9102);

    // What it says about itself, which is the same as before the trim.
    write_message(
        &mut peer,
        params().network,
        &Message::GetJoin {
            what: Joining::Weight,
            part: 0,
        },
    )
    .unwrap();
    let mut carried = 0usize;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && carried == 0 {
        match read_message(&mut peer, params().network) {
            Ok(Incoming::Message(Message::JoinPart { what, bytes, .. })) => {
                assert_eq!(what, Joining::Weight);
                carried = bytes.len();
            }
            Ok(_) => {}
            Err(error) => panic!("the handover route stopped answering: {error}"),
        }
    }
    assert!(
        carried > 0,
        "a node that cannot produce one old body still shows a newcomer what \
         work stands behind its chain"
    );

    // And the claim it makes on every introduction is unchanged, so nothing a
    // newcomer can read tells it which route this peer can actually serve.
    let mut again = TcpStream::connect(trimmed.node.address()).unwrap();
    again
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write_message(&mut again, params().network, &a_handshake(41_303, 0x9103)).unwrap();
    let said = loop {
        match read_message(&mut again, params().network) {
            Ok(Incoming::Message(Message::Welcome(handshake))) => break handshake,
            Ok(_) => {}
            Err(error) => panic!("no welcome came back: {error}"),
        }
    };
    assert!(
        said.keeps.headers,
        "it keeps every header, whatever happened to the bodies"
    );
    assert_eq!(
        said.keeps,
        Keeps {
            headers: true,
            cold_set: false,
        },
        "and there is nothing in what a node says about itself that mentions \
         bodies at all, so a newcomer cannot tell this peer from one that \
         could serve it the chain: {:?}",
        said.keeps
    );

    trimmed.node.shutdown();
    let _ = std::fs::remove_dir_all(&trimmed.directory);
}

/// **A node that has written a ledger drops the bodies below it on its next
/// start, whatever its budget says.**
///
/// The budget is a preference and this is not. Once a ledger file is there,
/// the blocks it already stands for are dropped when the node opens, so
/// `--keep all` does not put them back: the only node that holds every body is
/// one that has never written a ledger down, which is one whose blocks have
/// never outgrown its budget.
///
/// Said here because it is the reason the loss is not something an operator
/// opts into. A node started with a budget it later exceeds writes a ledger
/// once, and from that start on it is a node that cannot serve the beginning
/// of the chain, whatever the budget is set to afterwards.
#[test]
fn a_written_ledger_takes_the_bodies_below_it_whatever_the_budget() {
    let directory = scratch("ledger-takes-them");
    let mut forge = Forge::new();
    let blocks = forge.mine_many(BLOCKS);

    let data = directory.join("node");
    {
        let (node, _) = Node::open(params(), loopback(), &data).unwrap();
        node.keep_blocks(u64::MAX);
        for block in &blocks {
            node.submit_block(block.clone()).unwrap();
        }
        assert!(node.archived_at(0).is_some());
        assert!(node.write_ledger(), "the ledger went down");
        assert!(
            node.archived_at(0).is_some(),
            "and writing it dropped nothing: the budget says keep everything"
        );
        node.shutdown();
    }

    let (node, _) = Node::open(params(), loopback(), &data).unwrap();
    node.keep_blocks(u64::MAX);
    assert_eq!(
        node.height(),
        Some((blocks.len() - 1) as u64),
        "it came back on the same chain"
    );
    assert!(
        node.archived_at(0).is_none(),
        "and without the first block, which the ledger it started from stands \
         for. The budget was never asked"
    );

    node.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

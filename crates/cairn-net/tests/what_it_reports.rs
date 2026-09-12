//! What this crate tells whoever is running it, held against what it did.
//!
//! Every answer here is read by a person or by a program acting for one:
//! `cairnd` prints `reached` off the first, the explorer prints the same, the
//! wallet counts seeds off it, and the wallet's `send` decides whether to tell
//! somebody their money left off the third. So each of them is a place where a
//! failure reported as success travels a long way before anybody notices.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::node::{Node, NodeError, MAX_PEERS, MOST_FROM_OUTSIDE};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-reports-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn until(patience: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    ready()
}

/// A chain built without mining: testnet's first difficulty is met by the
/// block as assembled.
struct Chain {
    state: LedgerState,
    blocks: Vec<Block>,
    clock: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            state: LedgerState::new(),
            blocks: Vec::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&self.state, coinbase, Vec::new(), &params, self.clock, 0).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        self.blocks.push(block);
    }

    /// The first note the miner was paid, as a spend can name it.
    fn first_reward(&self, miner: &SecretKey) -> (NoteId, Note) {
        let block = self.blocks.first().unwrap();
        let (id, note) = block.coinbase.created_notes().into_iter().next().unwrap();
        assert_eq!(note.owner, miner.public_key());
        (id, note)
    }
}

// ---------------------------------------------------------------------------
// `reached`.
// ---------------------------------------------------------------------------

/// The claim under `cairnd`'s `reached` line: `Ok(())` means this node holds
/// the connection.
///
/// It used to mean the three-way handshake completed. A node with no room left
/// dialled the address, shut the socket in the next statement, and answered
/// `Ok(())`; `cairnd` and the explorer printed `reached`, and the wallet
/// counted the seed among the ones it had got to. The operator's count of live
/// peers and the node's count of live peers were different numbers with the
/// same name.
#[test]
fn a_connection_this_node_let_go_of_is_not_a_peer_reached() {
    let listener = Node::bind(params(), loopback()).unwrap();
    let listening = listener.address();

    // A node with every slot taken. The connections are made from this test
    // rather than by the node, so what fills the table is exactly what a
    // crowded node's table holds.
    let crowded = Node::bind(params(), loopback()).unwrap();
    let mut held = Vec::new();
    for _ in 0..MAX_PEERS {
        held.push(TcpStream::connect(crowded.address()).unwrap());
    }
    // As full as somebody else can make it, which is `MOST_FROM_OUTSIDE`: a
    // node holds back the slots it still needs to reach peers of its own.
    assert!(
        until(Duration::from_secs(10), || crowded.peer_count()
            >= MOST_FROM_OUTSIDE),
        "the table filled: {} of {MOST_FROM_OUTSIDE}",
        crowded.peer_count()
    );
    // And those held-back slots are a way out. This used to be the point at
    // which a dial was refused, because the accept loop and the dialling round
    // asked the same question and a table somebody else filled was a table
    // this node could not leave.
    crowded
        .connect(listening)
        .expect("a table somebody else filled still leaves a node a way out of it");

    // To reach the refusal the rest of this test is about, the node has to be
    // at `MAX_PEERS` and not merely crowded, which takes its own dials as well
    // as everybody else's. A plain listener is enough: what fills a slot is a
    // connection, and loopback is exempt from `MAX_PER_HOST` so one address
    // can hold them all.
    let parking = std::net::TcpListener::bind(loopback()).unwrap();
    let parked = parking.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut taken = Vec::new();
        for stream in parking.incoming() {
            match stream {
                Ok(socket) => taken.push(socket),
                Err(_) => break,
            }
        }
    });
    for _ in crowded.peer_count()..MAX_PEERS {
        if crowded.connect(parked).is_err() {
            break;
        }
    }
    assert!(
        until(Duration::from_secs(10), || crowded.peer_count()
            >= MAX_PEERS),
        "the table has to be full for the refusal below: {} of {MAX_PEERS}",
        crowded.peer_count()
    );

    let before = crowded.peer_count();
    let refused = crowded
        .connect(listening)
        .expect_err("a full table refuses a dial");
    assert!(
        matches!(refused, NodeError::NotKept { .. }),
        "a dial this node cannot keep says so: {refused}"
    );
    assert_eq!(
        crowded.peer_count(),
        before,
        "and it kept nothing, which is the fact the answer has to match"
    );
    // The address is still written down, because it answered.
    assert!(
        crowded.known_addresses().contains(&listening),
        "an address that answered is worth dialling again"
    );

    // And a node that has stopped keeps nothing either, by a different door.
    let stopping = Node::bind(params(), loopback()).unwrap();
    stopping.shutdown();
    let refused = stopping.connect(listening).unwrap_err();
    assert!(
        matches!(refused, NodeError::NotKept { .. }),
        "a node that has stopped holds no peers: {refused}"
    );
    assert_eq!(stopping.peer_count(), 0);

    drop(held);
}

// ---------------------------------------------------------------------------
// A transfer that has left.
// ---------------------------------------------------------------------------

/// The claim behind the wallet's "Handed to the network": a peer was offered
/// it.
///
/// `submit_transaction` broadcasts once, at the instant the pool takes the
/// transfer, to whoever is connected then. Nothing gossips a pool, so a peer
/// that finishes its handshake a second later is never told. The wallet read
/// the peer count five seconds afterwards and called that "handed on", which
/// answers a different question: on a wallet that had just opened, the
/// broadcast reached an empty table, a peer arrived at second two, and the
/// person was told their money had left.
///
/// What is pinned here is the transfer arriving in the other node's pool, not
/// a field being served.
#[test]
fn a_transfer_offered_again_reaches_a_peer_that_arrived_after_the_first_broadcast() {
    let directory = scratch("offer-again");
    let key = wallet(7);
    let mut source = Chain::new();
    for _ in 0..3 {
        source.mine(&key);
    }

    let (sender, _) = Node::open(params(), loopback(), &directory).unwrap();
    for block in &source.blocks {
        sender.submit_block(block.clone()).unwrap();
    }

    // The spend is built and submitted with nobody connected, which is the
    // state a wallet is in seconds after it opens.
    assert_eq!(sender.peer_count(), 0, "nobody to broadcast to");
    let (spending, held) = source.first_reward(&key);
    let mut transfer = Transfer::new(
        vec![Input::hot(spending)],
        vec![Note::new(
            held.value
                .checked_sub(Amount::from_pebbles(10_000).unwrap())
                .unwrap(),
            wallet(9).public_key(),
        )],
    );
    transfer.sign_input(params().network, 0, &held, &key);
    let id = transfer.id();
    assert!(
        sender.submit_transaction(transfer).unwrap(),
        "the pool took it"
    );
    assert_eq!(
        sender.offer_again(&id),
        0,
        "and it was offered to nobody, because there was nobody"
    );

    // Now a peer arrives, exactly as it does while a wallet is waiting.
    let receiver = Node::bind(params(), loopback()).unwrap();
    for block in &source.blocks {
        receiver.submit_block(block.clone()).unwrap();
    }
    receiver.connect(sender.address()).unwrap();
    assert!(
        until(Duration::from_secs(10), || sender.peers_introduced() > 0),
        "the peer connected and introduced itself"
    );

    assert!(
        until(Duration::from_secs(10), || sender.offer_again(&id) > 0),
        "somebody took it into their queue"
    );
    assert!(
        until(Duration::from_secs(10), || receiver
            .with_chain(|chain| chain.pooled(&id).is_some())),
        "and the transfer reached the other node's pool, which is the fact \
         `handed_on` is a claim about"
    );

    drop(receiver);
    drop(sender);
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim under [`Peer::greeted`]: nothing is broadcast down a connection
/// this node accepted and has not yet answered.
///
/// A peer enters the table the moment its socket is accepted, and the welcome
/// is only queued once its hello has arrived. Anything sent in between reaches
/// a node that has not been introduced to this one, which refuses it as
/// `Unannounced`: the connection closes and this node's host is turned away
/// for a while. So a node's own eagerness costs it the peer that had just
/// arrived, and the peer sees a stranger that opened a connection and started
/// talking.
///
/// Held here through `offer_again`, which is the one broadcast a caller can
/// count. What must never happen is a count above nought before the peer has
/// spoken, because that is a message already gone down the wire.
#[test]
fn nothing_is_broadcast_to_a_peer_that_has_not_introduced_itself() {
    let key = wallet(11);
    let mut source = Chain::new();
    for _ in 0..3 {
        source.mine(&key);
    }

    let sender = Node::bind(params(), loopback()).unwrap();
    for block in &source.blocks {
        sender.submit_block(block.clone()).unwrap();
    }
    let (spending, held) = source.first_reward(&key);
    let mut transfer = Transfer::new(
        vec![Input::hot(spending)],
        vec![Note::new(
            held.value
                .checked_sub(Amount::from_pebbles(10_000).unwrap())
                .unwrap(),
            wallet(12).public_key(),
        )],
    );
    transfer.sign_input(params().network, 0, &held, &key);
    let id = transfer.id();
    assert!(sender.submit_transaction(transfer).unwrap());

    // A socket that connects and says nothing, which is what every peer looks
    // like for the first round trip of its life.
    let quiet = TcpStream::connect(sender.address()).unwrap();
    assert!(
        until(Duration::from_secs(10), || sender.peer_count() == 1),
        "the connection was accepted"
    );
    assert_eq!(
        sender.peer_count(),
        1,
        "one socket is held, which is what it costs this node in threads"
    );
    assert_eq!(
        sender.peers_introduced(),
        0,
        "and nought peers, which is the number worth showing a person: nothing \
         here can be asked anything. Counting the socket is what told a wallet \
         its owner it had reached the network, and told a node handed a ledger \
         it had somebody to blame for the silence"
    );
    for _ in 0..20 {
        assert_eq!(
            sender.offer_again(&id),
            0,
            "a peer that has not introduced itself is not somewhere to send a \
             transfer: sending one closes the connection and gets this host refused"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(quiet);
    drop(sender);
}

// ---------------------------------------------------------------------------
// The address book.
// ---------------------------------------------------------------------------

/// The claim: an error on a write path is reported.
///
/// The book was the one write here whose refusal was thrown away outright:
/// `let _ = book.save(directory)`. Nothing on the chain rests on that file, so
/// nothing else about the node changes while it is failing, and what it costs
/// arrives at the next start on a node that has forgotten every address it
/// learned. A directory standing in for the file is unwritable for everybody,
/// including whoever runs the tests as root.
#[test]
fn an_address_book_the_disk_refuses_is_said_rather_than_dropped() {
    let directory = scratch("unsaved-book");
    std::fs::create_dir_all(directory.join("peers.txt")).unwrap();

    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    assert!(
        node.unsaved_addresses().is_none(),
        "nothing has been written yet, so there is nothing to say"
    );
    node.remember_seed(SocketAddr::from(([10, 0, 0, 1], 9944)));
    node.shutdown();
    let because = node
        .unsaved_addresses()
        .expect("the disk refused the peers file and the node has to say so");
    eprintln!("what it said: {because}");
    assert!(!because.is_empty(), "and say what the disk said");
    drop(node);

    // And the same node on a directory that takes the write says nothing, so
    // this is a report an operator can learn to read rather than one they
    // learn to ignore.
    std::fs::remove_dir(directory.join("peers.txt")).unwrap();
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    node.remember_seed(SocketAddr::from(([10, 0, 0, 1], 9944)));
    node.shutdown();
    assert!(
        node.unsaved_addresses().is_none(),
        "a disk that took it says nothing: {:?}",
        node.unsaved_addresses()
    );
    assert!(
        std::fs::read_to_string(directory.join("peers.txt"))
            .unwrap()
            .contains("10.0.0.1:9944"),
        "and the address is on the disk"
    );

    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

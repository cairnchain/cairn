//! What a full node gives up for a visitor, and when.
//!
//! A node whose table is full lets one connection somebody else opened go, so
//! that a newcomer can still reach it: a full honest node that shut its door
//! looked like a dead one, and a crowd holding the slots of every node on a
//! network decided whom newcomers could reach. What these tests ask is what
//! the room is made for. It was made the moment a socket was accepted, before
//! the visitor had said a word, so a connection that closed at once cost the
//! node a peer for nobody, and so did every surplus dial of a node dialling
//! sixteen addresses side by side. And a dial asked for room, waited on the
//! chain to write its introduction, and went into the table without asking
//! again, taking a full table past its ceiling.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::node::{MAX_PEERS, MOST_FROM_OUTSIDE, TARGET_PEERS};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::{Keeps, Node};
use cairn_primitives::Hash32;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn hello(nonce: u64) -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen: 0,
        nonce,
        keeps: Keeps::default(),
    })
}

/// A peer that dials in, introduces itself without a port and then reads
/// whatever it is sent, and says when the node has shut the connection.
fn a_quiet_peer(node: SocketAddr, nonce: u64) -> Arc<AtomicBool> {
    let mut stream = TcpStream::connect(node).unwrap();
    write_message(&mut stream, params().network, &hello(nonce)).unwrap();
    let shut = Arc::new(AtomicBool::new(false));
    let saying = Arc::clone(&shut);
    thread::spawn(move || {
        let mut sink = [0u8; 4096];
        loop {
            match stream.read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        saying.store(true, Ordering::SeqCst);
    });
    shut
}

fn shut(peers: &[Arc<AtomicBool>]) -> usize {
    peers
        .iter()
        .filter(|shut| shut.load(Ordering::SeqCst))
        .count()
}

/// Waits for something that happens in milliseconds on a free machine, and
/// far longer than any loaded runner takes before it gives up.
fn wait_until(what: &str, ready: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

/// A node that has dialled nobody, holding every slot it keeps for
/// connections from outside with quiet peers that introduced themselves.
fn a_full_node() -> (Node, Vec<Arc<AtomicBool>>) {
    let node = Node::bind(params(), loopback()).unwrap();
    let peers: Vec<Arc<AtomicBool>> = (0..MOST_FROM_OUTSIDE)
        .map(|at| a_quiet_peer(node.address(), 10_000 + u64::try_from(at).unwrap()))
        .collect();
    wait_until("the table to fill", || {
        node.peers_introduced() == MOST_FROM_OUTSIDE
    });
    (node, peers)
}

/// Whether the node answers `visitor`'s introduction, within a patience far
/// past what answering takes.
fn answered(visitor: &mut TcpStream) -> bool {
    visitor
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    matches!(
        read_message(visitor, params().network, MAX_FRAME_BYTES),
        Ok(Incoming::Message(Message::Welcome(_)))
    )
}

/// **A visitor gone before a word costs a full node nobody.**
///
/// A full node made room when it accepted a socket, before the visitor had
/// said anything, and nothing afterwards asked whether the visitor stayed. A
/// stranger that connects and hangs up, and every surplus dial of a node
/// dialling side by side, which the dialler shuts the moment it answers, each
/// cost the node one of the peers it held: usually another node's outbound
/// connection, dialled again from that node's book for nothing. Nothing asked
/// this, so a node that let a peer go for each of five sockets that closed
/// before a byte passed.
#[test]
fn a_visitor_gone_before_a_word_costs_a_full_node_nobody() {
    let (node, mut peers) = a_full_node();
    let shut_before = shut(&peers);

    let mut let_go = Vec::new();
    for round in 0..5u64 {
        let before = shut(&peers);
        drop(TcpStream::connect(node.address()).unwrap());
        // Long enough for the node to accept it, see it gone and end it.
        thread::sleep(Duration::from_secs(1));
        let after = shut(&peers);
        let_go.push(after - before);
        // A peer let go of comes back, as the node that dialled it does on
        // its next round, so the table is full again for the next visitor.
        for back in 0..u64::try_from(after - before).unwrap() {
            peers.push(a_quiet_peer(node.address(), 20_000 + round * 100 + back));
        }
        wait_until("the table to be full again", || {
            node.peers_introduced() == MOST_FROM_OUTSIDE
        });
    }
    node.shutdown();

    assert_eq!(
        shut_before, 0,
        "fixture: a peer was shut before any visitor came"
    );
    assert_eq!(
        let_go.iter().sum::<usize>(),
        0,
        "a full node let a peer go for a visitor that never said a word and was gone \
         at once: room is made before the introduction, so a connection that closes at \
         once, a stranger's or a side by side dial's surplus, costs it a peer for nobody"
    );
}

/// **A full node still makes room for a visitor that introduces itself, and
/// lets exactly one peer go for it.**
///
/// The other half of the one above, and the reason there is room to make at
/// all: moving the choice to the introduction must not shut the door a full
/// node keeps open. Nothing asked it of a node that waits for the
/// introduction, since none did.
#[test]
fn a_full_node_makes_room_for_a_visitor_that_introduces_itself() {
    let (node, peers) = a_full_node();
    let mut visitor = TcpStream::connect(node.address()).unwrap();
    write_message(&mut visitor, params().network, &hello(30_000)).unwrap();
    let welcomed = answered(&mut visitor);
    wait_until("the peer let go of to leave", || shut(&peers) >= 1);
    thread::sleep(Duration::from_millis(500));
    let let_go = shut(&peers);
    let introduced = node.peers_introduced();
    node.shutdown();

    assert!(
        welcomed,
        "a full node turned away a visitor that introduced itself, which shuts the door \
         a full node keeps open for newcomers"
    );
    assert_eq!(
        let_go, 1,
        "room for one visitor was made by letting other than one go"
    );
    assert_eq!(
        introduced, MOST_FROM_OUTSIDE,
        "the visitor did not take the place made"
    );
}

/// **A crowd of sockets that say nothing does not shut a full node's door.**
///
/// A visitor to a full node waits for its introduction without a place of
/// its own, and only so many may wait at once. When they all say nothing, a
/// visitor that comes after them is taken as visitors always were, room made
/// the moment it arrives: a crowd that held every place to wait in would
/// otherwise decide that nobody new reaches the node at all. Nothing asked
/// it, since nothing waited before.
#[test]
fn sockets_that_say_nothing_do_not_shut_a_full_node() {
    let (node, peers) = a_full_node();
    let silent: Vec<TcpStream> = (0..TARGET_PEERS)
        .map(|_| TcpStream::connect(node.address()).unwrap())
        .collect();
    wait_until("the silent visitors to be held", || {
        node.peer_count() == MOST_FROM_OUTSIDE + TARGET_PEERS
    });
    let mut visitor = TcpStream::connect(node.address()).unwrap();
    write_message(&mut visitor, params().network, &hello(40_000)).unwrap();
    let welcomed = answered(&mut visitor);
    let let_go = shut(&peers);
    node.shutdown();
    drop(silent);

    assert!(
        welcomed,
        "a visitor that introduced itself was turned away by a full node while as many \
         sockets as may wait were holding their places without a word"
    );
    assert_eq!(
        let_go, 1,
        "room for one visitor was made by letting other than one go"
    );
}

/// Whether the node has shut `socket`, read without waiting.
fn shut_by_the_node(socket: &TcpStream) -> bool {
    socket.set_nonblocking(true).unwrap();
    let mut one = [0u8; 1];
    let shut = matches!((&*socket).read(&mut one), Ok(0));
    socket.set_nonblocking(false).unwrap();
    shut
}

/// **A visitor waiting past a full table that never says a word is let go of
/// within seconds, and a silent one that holds a place is not.**
///
/// A waiting visitor holds no slot, and what keeps a crowd of them from
/// holding the door is that each has a few seconds to say who it is, where a
/// peer holding a place is allowed ninety of silence. Nothing asked either
/// half, since nothing waited before.
#[test]
fn a_visitor_waiting_past_a_full_table_that_says_nothing_is_let_go_of() {
    let (full, _peers) = a_full_node();
    let waiting = TcpStream::connect(full.address()).unwrap();
    wait_until("the waiting visitor to be held", || {
        full.peer_count() == MOST_FROM_OUTSIDE + 1
    });
    let roomy = Node::bind(params(), loopback()).unwrap();
    let seated = TcpStream::connect(roomy.address()).unwrap();
    wait_until("the seated visitor to be held", || roomy.peer_count() == 1);

    waiting
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut one = [0u8; 1];
    let let_go = matches!((&waiting).read(&mut one), Ok(0));
    // Past the few seconds a waiting visitor has, counted from the seated
    // one's arrival, and a quiet read of the connection's own after that.
    thread::sleep(Duration::from_secs(8));
    let seated_still_held = !shut_by_the_node(&seated);
    full.shutdown();
    roomy.shutdown();

    assert!(
        let_go,
        "a visitor waiting past a full table without a word was held for a minute, when it \
         holds no slot and has a few seconds to say who it is"
    );
    assert!(
        seated_still_held,
        "a silent visitor holding a place was let go of as soon as a waiting one, when a \
         peer holding a place is allowed ninety seconds of silence"
    );
}

/// **A dial that waited on the chain does not take a full table past its
/// ceiling.**
///
/// Every dialling path asked for room and then built its introduction under
/// the chain before the connection went into the table, without asking
/// again. The accept loop filled the table in between, the dial went in on
/// top, and the table held one past its ceiling; the next visitor then cost
/// the node a peer and was turned away itself, since letting one go from a
/// table past its ceiling does not make room. Nothing asked this, so a table
/// of forty nine passed.
///
/// The chain is held here as a block being checked holds it.
#[test]
fn a_dial_that_waited_on_the_chain_does_not_take_a_full_table_past_its_ceiling() {
    let victim = Node::bind(params(), loopback()).unwrap();
    let eight: Vec<Node> = (0..TARGET_PEERS)
        .map(|_| Node::bind(params(), loopback()).unwrap())
        .collect();
    let ninth = Node::bind(params(), loopback()).unwrap();
    for node in &eight {
        victim.connect(node.address()).unwrap();
    }
    wait_until("the eight to be introduced", || {
        victim.peers_introduced() == TARGET_PEERS
    });

    // One short of the ceiling.
    let mut peers: Vec<Arc<AtomicBool>> = (0..MOST_FROM_OUTSIDE - 1)
        .map(|at| a_quiet_peer(victim.address(), 10_000 + u64::try_from(at).unwrap()))
        .collect();
    wait_until("one short of the ceiling", || {
        victim.peers_introduced() == MAX_PEERS - 1
    });

    let (most, visitor_answered, let_go) = thread::scope(|scope| {
        let (held_tx, held_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let victim = &victim;
        scope.spawn(move || {
            victim.with_chain(|_| {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        held_rx.recv().unwrap();

        // A dial with room for it when it asks, which then waits on the chain.
        let ninth_at = ninth.address();
        let dialling = scope.spawn(move || victim.connect(ninth_at));
        wait_until("the ninth to take the dial", || ninth.peer_count() == 1);

        // The last place taken while that dial waits. Its introduction waits
        // on the chain too, so the socket is what is counted.
        peers.push(a_quiet_peer(victim.address(), 20_000));
        wait_until("the table to be full", || victim.peer_count() == MAX_PEERS);

        release_tx.send(()).unwrap();
        // Refused or kept, the table is what is asked about.
        let _ = dialling.join().unwrap();
        let mut most = victim.peer_count();
        let watching = Instant::now();
        while watching.elapsed() < Duration::from_millis(300) {
            most = most.max(victim.peer_count());
            thread::sleep(Duration::from_millis(5));
        }

        let before = shut(&peers);
        let mut visitor = TcpStream::connect(victim.address()).unwrap();
        write_message(&mut visitor, params().network, &hello(30_000)).unwrap();
        let answered = answered(&mut visitor);
        thread::sleep(Duration::from_millis(500));
        (most, answered, shut(&peers) - before)
    });
    victim.shutdown();
    ninth.shutdown();
    for node in &eight {
        node.shutdown();
    }

    assert!(
        most <= MAX_PEERS,
        "a dial that asked for room at one short of the ceiling and then waited on the \
         chain went into a table the accept loop had filled meanwhile"
    );
    assert!(
        visitor_answered || let_go == 0,
        "a peer was let go of for a visitor that was then turned away itself"
    );
}

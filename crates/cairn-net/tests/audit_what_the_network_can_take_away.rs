//! What a stranger can take out of a node's address book.
//!
//! `AddressBook` says of seeds: "An address the operator gave is the one thing
//! in the book that was not learned from the network, so it is the one thing
//! the network cannot take away." That is true of everything the book does to
//! itself. `missed` never drops a seed, and `make_room` never gives one up.
//!
//! There is one other door out of the book, and it is `Shared::forget`, fed by
//! the single place in the whole protocol that removes an address: a peer whose
//! handshake carries this node's own nonce is this node reaching itself, so the
//! address the connection came from, completed by the port the handshake names,
//! is taken out. That sentence is true when the peer really is this node.
//!
//! The nonce is not a secret. A node puts it in every hello and every welcome
//! it sends, so anybody who has spoken to it once can say it back. What it then
//! names is not this node's address, it is whatever port the stranger cares to
//! write in a field, at whatever address the stranger happens to be reachable
//! from: its own on the open internet, and the one every node shares on a
//! devnet, a lab, or behind one gateway.
//!
//! Nothing is held against the speaker either. `DropReason::Ourselves` is not
//! misbehaviour, and rightly so, so the connection ends and the address earns
//! no refusal: it can be said again immediately.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::Message;
use cairn_net::wire::{read_message, write_message, Incoming};
use cairn_net::Node;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// The seed the operator names: an address nothing answers at, so that what
/// happens to it is the node's own doing and not a peer's.
fn seed() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 1))
}

fn wait_until(patience: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    ready()
}

fn hello(nonce: u64, listen: u16) -> Message {
    Message::Hello(cairn_net::message::Handshake {
        version: cairn_net::message::PROTOCOL_VERSION,
        network: params().network,
        genesis: cairn_primitives::Hash32::ZERO,
        tip: cairn_primitives::Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen,
        nonce,
        keeps: cairn_net::Keeps::default(),
    })
}

/// Says hello and reads back what the node says about itself.
fn nonce_of(at: SocketAddr) -> Option<u64> {
    let mut socket = TcpStream::connect(at).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write_message(&mut socket, params().network, &hello(0xfeed, 40_001)).ok()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match read_message(&mut socket, params().network) {
            Ok(Incoming::Message(Message::Welcome(theirs))) => {
                let _ = socket.shutdown(Shutdown::Both);
                return Some(theirs.nonce);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = socket.shutdown(Shutdown::Both);
    None
}

/// **A stranger says a node's own nonce back to it and takes the operator's
/// seed out of the book.**
///
/// The node hands its nonce to everyone it greets, so learning it costs one
/// connection. A second connection says it back, naming the seed's port, and
/// the node reads the pair as itself: it takes `<the address this connection
/// came from>:<the port named>` out of the book. On loopback, which is the
/// devnet this software is developed and demonstrated on, the address the
/// connection came from is the address every node is at.
///
/// `missed` would never have dropped it and `make_room` would never have given
/// it up; `remove` has no seed in it to notice.
///
/// What it costs depends on who started the node. An operator who typed
/// something keeps it as a name too, so `look_up_seed_names` puts the address
/// back within `NAME_LOOKUP_PERIOD`, and the stranger says it away again for
/// one more hello: a node kept without its only fallback most of the time, and
/// a name lookup on the upkeep thread forced every thirty seconds by whoever
/// cares to. A caller that only names addresses, which is what
/// `Node::remember_seed` is and what this test does, loses it for good.
///
/// And the seed is only the sharpest case. The same hello takes out any entry
/// at the address the stranger is reachable from, so on a devnet, inside one
/// office, or behind one carrier gateway it takes out the neighbours.
#[test]
fn a_seed_is_not_something_a_stranger_can_say_away() {
    let victim = Node::bind(params(), loopback()).unwrap();
    victim.remember_seed(seed());
    assert!(
        victim.known_addresses().contains(&seed()),
        "the fixture needs the seed in the book"
    );

    // Several rounds of upkeep, so that what the seed survives here is the
    // node's own dialling. It never answers, and it is still kept, which is
    // the whole of what a seed is.
    thread::sleep(Duration::from_secs(4));
    assert!(
        victim.known_addresses().contains(&seed()),
        "a seed is kept however many dials it refuses"
    );

    let nonce = nonce_of(victim.address()).expect("the node says its nonce in its welcome");
    let mut forger = TcpStream::connect(victim.address()).unwrap();
    write_message(&mut forger, params().network, &hello(nonce, seed().port())).unwrap();

    let taken = wait_until(Duration::from_secs(20), || {
        !victim.known_addresses().contains(&seed())
    });
    let left = victim.known_addresses().len();
    let _ = forger.shutdown(Shutdown::Both);
    victim.shutdown();

    assert!(
        !taken,
        "one stranger, holding nothing but a nonce the node had handed it, took the \
         operator's seed out of the book with a single hello. {left} addresses are left, \
         and they are the stranger's. A seed is the one address the book says the network \
         cannot take away, and `remove` has no seed in it to notice",
    );
}

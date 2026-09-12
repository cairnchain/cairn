//! Who decides which addresses a node spends its dials on.
//!
//! A node dials out because dialling is the half of its connections that
//! nobody else chose. What it dials is the front of its address book, and what
//! puts an address at the front is `AddressBook::answered`: "a peer that speaks
//! now is a peer that exists now". That is true of a peer this node went out
//! and reached. It is also said of a peer that dialled in, said hello, and hung
//! up, and there it answers a different question from the one the dial order
//! needed answered. Nothing has ever answered a dial at that address; the port
//! in it was named by the stranger.
//!
//! Beside it, `dial_from_book` cuts its candidate list to the number of
//! connections it wants to open before it asks whether any of them can be
//! dialled at all. A candidate that is skipped is a dial that does not happen
//! and a slot that is not refilled from further down the book.
//!
//! Together: a stranger that only ever dials in, from one address, decides the
//! whole of what a node dials out to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::Message;
use cairn_net::node::{MAX_PEERS, TARGET_PEERS};
use cairn_net::wire::{read_message, write_message, Incoming};
use cairn_net::Node;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// Ports the stranger claims to listen on, and nothing does.
///
/// Three times the number of connections a node goes out and opens, so that
/// the eight it dials in any one round are all the stranger's however the
/// rounds happen to line up. Well inside the thirty two addresses one
/// neighbourhood of the book holds.
fn claimed_ports() -> [u16; TARGET_PEERS * 3] {
    // Low, privileged and unbound: a dial to one is refused in microseconds,
    // so what this measures is the node's choice of address and not a timeout.
    std::array::from_fn(|at| u16::try_from(at).unwrap_or(u16::MAX).saturating_add(1))
}

/// `patience` is a liveness bound, not a measurement: it costs nothing when
/// the condition is met, so a short one only buys a failure that says nothing.
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

/// One greeting from one claimed port, said and then hung up on.
///
/// The welcome is queued after the book has been written, so reading one is
/// what says the greeting landed rather than what says it was sent.
fn greet_and_leave(at: SocketAddr, nonce: u64, listen: u16) -> bool {
    let Ok(mut socket) = TcpStream::connect(at) else {
        return false;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
    if write_message(&mut socket, params().network, &hello(nonce, listen)).is_err() {
        return false;
    }
    let welcomed = matches!(
        read_message(&mut socket, params().network),
        Ok(Incoming::Message(Message::Welcome(_)))
    );
    let _ = socket.shutdown(Shutdown::Both);
    welcomed
}

/// Control: with nobody greeting it, a node reaches the seed it was given.
///
/// Here so that the failure below is the flood and not the fixture.
#[test]
fn a_node_nobody_greets_reaches_the_seed_it_was_given() {
    let honest = Node::bind(params(), loopback()).unwrap();
    let victim = Node::bind(params(), loopback()).unwrap();
    victim.remember_seed(honest.address());

    let reached = wait_until(Duration::from_secs(120), || honest.peer_count() >= 1);
    victim.shutdown();
    honest.shutdown();
    assert!(
        reached,
        "a node with a seed and nothing in its way dials it"
    );
}

/// **One address that only ever dials in decides everything a node dials out
/// to.**
///
/// The stranger holds one address and never misbehaves. It opens a connection,
/// says hello naming a port, and hangs up, over and over, naming twenty four
/// ports in turn. Each greeting does two things at the node: `remember` writes
/// `<stranger's address>:<the port it named>` into the book, and `answered`
/// marks it heard from *now*, which is the front of the order the book is
/// dialled and gossiped from.
///
/// Nothing has ever answered a dial at any of those addresses. The stranger
/// dialled in; the port is a number it wrote in a field. `answered` is about
/// the host, and the dial order is about the address.
///
/// `dial_from_book` then takes `TARGET_PEERS` candidates off the front of that
/// order and stops taking. The seed the operator named sits at heard nought,
/// behind all twenty four, and is never among them. Every round the node dials
/// eight addresses that refuse it, and the one address that would have talked
/// to it is never reached for as long as the stranger keeps greeting.
#[test]
fn a_stranger_that_only_dials_in_cannot_decide_what_a_node_dials_out_to() {
    let honest = Node::bind(params(), loopback()).unwrap();
    let victim = Node::bind(params(), loopback()).unwrap();
    let victim_at = victim.address();

    let running = Arc::new(AtomicBool::new(true));
    let greeted = Arc::new(AtomicU64::new(0));
    let stop = Arc::clone(&running);
    let counting = Arc::clone(&greeted);
    let stranger = thread::spawn(move || {
        let mut nonce = 1u64;
        while stop.load(Ordering::SeqCst) {
            for port in claimed_ports() {
                if !stop.load(Ordering::SeqCst) {
                    return;
                }
                nonce = nonce.saturating_add(1);
                if greet_and_leave(victim_at, nonce, port) {
                    counting.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    });

    // Two full passes, so every claimed port is in the book and at the front of
    // it before the operator names a seed at all. A node restarting into a
    // stranger that is already there is in exactly this state.
    let filled = wait_until(Duration::from_secs(60), || {
        greeted.load(Ordering::SeqCst) >= (claimed_ports().len() as u64) * 2
    });
    assert!(
        filled,
        "the stranger could not get its greetings in: {} of {}",
        greeted.load(Ordering::SeqCst),
        claimed_ports().len() * 2,
    );

    victim.remember_seed(honest.address());
    let reached = wait_until(Duration::from_secs(120), || honest.peer_count() >= 1);

    running.store(false, Ordering::SeqCst);
    let _ = stranger.join();
    let said_hello = greeted.load(Ordering::SeqCst);
    let held = victim.peer_count();
    let known = victim.known_addresses().len();
    victim.shutdown();
    honest.shutdown();

    assert!(
        reached,
        "the victim never dialled the one address its operator gave it. One stranger said \
         hello {said_hello} times from {} claimed ports and hung up each time; every one of \
         those addresses was written down and marked heard-from, so all {} dials a round go \
         to addresses that refuse them and the seed, at heard nought, is never reached. The \
         victim was holding {held} connections and knew {known} addresses, so neither the \
         connection ceiling nor an empty book is what stopped it",
        claimed_ports().len(),
        TARGET_PEERS,
    );
}

/// **A table strangers filled leaves a node no way out of it.**
///
/// `has_room_for` answers one question: has this node room for another
/// connection. It is true, and it is the question the accept loop needed
/// answered. `dial_from_book` asks the same one, where the question it needed
/// answered was whether this node has room for a connection *it* chooses.
/// There is no third number between [`TARGET_PEERS`] and [`MAX_PEERS`]: no
/// slots are held back for dialling.
///
/// So a party that holds every slot with connections that behave perfectly
/// well decides the whole of what the node can see. Forty eight connections is
/// twenty four addresses at `MAX_PER_HOST`, which is a quarter of a `/24` or
/// twenty four addresses out of one machine's IPv6 allocation. Each greets,
/// is welcomed, and says a word every few seconds. Nothing here is
/// misbehaviour, so nothing is ever refused, and `peers_introduced` reads
/// forty eight while the node is off the network.
///
/// The comment above `dripping_peers_cannot_take_every_connection_slot` in
/// `transport_audit.rs` states this consequence in passing. What was repaired
/// there was the price of holding a slot: a frame that stalls now costs the
/// connection. Holding one by talking was never priced, and nothing tests it.
#[test]
fn a_table_strangers_filled_still_leaves_a_node_a_way_out_of_it() {
    let honest = Node::bind(params(), loopback()).unwrap();
    let victim = Node::bind(params(), loopback()).unwrap();
    let victim_at = victim.address();

    // Offered, not forced: a node that turns one of these away has done the
    // right thing, and the socket it shut is simply dropped here.
    let mut held: Vec<TcpStream> = Vec::new();
    for at in 0..MAX_PEERS {
        let Ok(mut socket) = TcpStream::connect(victim_at) else {
            continue;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_millis(50)));
        let listen = 20_000u16.saturating_add(u16::try_from(at).unwrap_or(0));
        if write_message(
            &mut socket,
            params().network,
            &hello(9_000u64.saturating_add(at as u64), listen),
        )
        .is_ok()
        {
            held.push(socket);
        }
    }
    // However many of them the node chooses to take. A node that keeps nothing
    // back for its own dialling takes all [`MAX_PEERS`]; one that keeps a few
    // back takes fewer, and this only has to establish that the stranger got
    // its crowd in either way.
    let crowd = MAX_PEERS.saturating_sub(TARGET_PEERS);
    assert!(
        wait_until(Duration::from_secs(60), || victim.peer_count() >= crowd),
        "the victim should take the connections: it took {}",
        victim.peer_count(),
    );

    // A word every few seconds, so none of them is ever dropped for silence
    // and what the test measures is the steady state rather than a lull.
    let running = Arc::new(AtomicBool::new(true));
    let stop = Arc::clone(&running);
    let keeper = thread::spawn(move || {
        let mut held = held;
        let mut tick = 0u64;
        while stop.load(Ordering::SeqCst) {
            tick = tick.saturating_add(1);
            for socket in &mut held {
                let _ = write_message(socket, params().network, &Message::Ping(tick));
                while matches!(
                    read_message(socket, params().network),
                    Ok(Incoming::Message(_))
                ) {}
            }
        }
        held
    });

    victim.remember_seed(honest.address());
    let reached = wait_until(Duration::from_secs(120), || honest.peer_count() >= 1);

    running.store(false, Ordering::SeqCst);
    let survivors = keeper.join().map(|held| held.len()).unwrap_or(0);
    let introduced = victim.peers_introduced();
    let known = victim.known_addresses().len();
    victim.shutdown();
    honest.shutdown();

    assert!(
        reached,
        "the victim never dialled the one address its operator gave it. {survivors} \
         well-behaved connections held every one of its {MAX_PEERS} slots, so the same \
         has_room_for that turns away an accepted connection turned away every dial it \
         wanted to make. It reported {introduced} peers and knew {known} addresses while \
         it was off the network",
    );
}

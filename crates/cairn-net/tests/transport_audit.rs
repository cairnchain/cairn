//! Adversarial audit of the transport: framing, the message loop, the
//! handshake, the cost accounting and the address book.
//!
//! Written in the style of `hostile_peer.rs`: each test FAILS on the code it
//! was found in and would pass once the finding is addressed.
//!
//! Every finding here has been addressed, and the tests stand as regressions,
//! in the past tense.
//!
//! A and F were the one mechanism: the deadline a socket carries is per
//! syscall and the party at the other end decides when it fires, so neither a
//! peer that dribbles nor one that sips was ever late for anything. A frame
//! now carries a deadline of its own. What the same dribble did to a node
//! that had stopped itself is in `concurrency_audit.rs`, which is where it
//! was found from the other side; it is not asserted twice.
//!
//! B, D and E were also one thing seen three times: the size of what a
//! message costs was set by the party sending it. An allowance kept on the
//! socket was refilled by hanging up; the whole address book was copied for
//! every message that arrived, under the chain; and the one message that
//! reads that book was free. The allowance belongs to the address now, the
//! book is read once the chain is let go of and only when somebody asked for
//! it, and asking costs what the answer costs.
//!
//! C and G were one thing seen twice, and it is who a node talks to rather
//! than what it spends: a stranger chose the addresses, and one address that
//! answered a dial and then said nothing kept being chosen again. The book
//! now weighs what a peer names against where that peer is and whether this
//! node went out to it, and upkeep counts the address it dialled as well as
//! the one a peer introduces itself at.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use cairn_ledger::validation::ConsensusParams;
use cairn_net::book::MAX_ADDRESSES;
use cairn_net::message::{
    Handshake, Joining, Message, PeerAddress, JOIN_PART_BYTES, MAX_SHARED_ADDRESSES,
    PROTOCOL_VERSION,
};
use cairn_net::wire::{read_message, write_message, Incoming, FRAME_PATIENCE, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn hello(nonce: u64, listen: u16) -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen,
        nonce,
        archives: false,
    })
}

fn wait_until(patience: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    ready()
}

// ---------------------------------------------------------------------------
// FINDING A, repaired: a frame kept open by a slow drip is given up on.
//
// `wire::fill` tells two silences apart, and caught a peer that opened a frame
// and STOPPED: the next deadline found `read > 0` and raised `Stalled`. What
// it did not catch was a peer that never let the deadline fire. The deadline
// was the socket's, which is per read() syscall, and every byte the SENDER
// chose to send restarted it. One byte just inside each period kept `fill`
// looping, so `read_loop` never reached the top of its `while`: PEER_SILENCE
// was never consulted, the flood counter never incremented, `PeerState::afford`
// never reached, and the frame's whole allocation held the entire time.
//
// The frame now carries FRAME_PATIENCE of its own, measured from its first
// byte, and neither side of a connection can restart that.
//
// This reader is a socket whose deadline never fires, because the peer always
// speaks first. It sleeps a tenth of the frame's patience per call, so the
// clock the repair reads is a real one: a fake that returned instantly would
// prove nothing about a deadline measured in wall time.
// ---------------------------------------------------------------------------

/// A tenth of the whole frame's patience, so a peer that means to finish has
/// ten goes at it and one that does not is caught in the eleventh.
fn drip_period() -> Duration {
    FRAME_PATIENCE / 10
}

struct Drip {
    header: Vec<u8>,
    at: usize,
    /// Periods that have passed since the frame opened.
    periods: usize,
    budget: usize,
}

impl Read for Drip {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.at < self.header.len() {
            let n = buf.len().min(self.header.len() - self.at);
            buf[..n].copy_from_slice(&self.header[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        if self.periods >= self.budget {
            // Stand-in for "the test stopped waiting", so the call returns at
            // all and the count below can be read.
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "gave up"));
        }
        self.periods += 1;
        std::thread::sleep(drip_period());
        buf[0] = 0;
        Ok(1)
    }
}

#[test]
fn a_frame_kept_open_by_a_slow_drip_is_given_up_on() {
    let mut header = Vec::new();
    params().network.as_u32().encode_to(&mut header);
    (MAX_FRAME_BYTES as u32).encode_to(&mut header);

    // Half again as many periods as the frame is given, so a reader that still
    // has no bound of its own runs past it and is caught here rather than
    // running for the fifty nine days a full frame at one byte a period takes.
    let budget = 15usize;
    let mut drip = Drip {
        header,
        at: 0,
        periods: 0,
        budget,
    };

    let outcome = read_message(&mut drip, params().network);
    assert!(
        drip.periods < budget,
        "a peer opened a {MAX_FRAME_BYTES} byte frame and sent one byte per period of \
         {:?}; the reader was still waiting on it after {} of them, and would wait \
         {} days in all. Outcome: {outcome:?}",
        drip_period(),
        drip.periods,
        (MAX_FRAME_BYTES as u64 * 5) / 86_400,
    );
}

/// The same, against a real node on a real socket.
///
/// The existing `a_peer_that_opens_a_frame_and_goes_quiet_is_let_go` covers a
/// peer that opens a frame and STOPS. This is the peer that opens a frame and
/// keeps it open: one byte every three seconds, inside the node's five second
/// read deadline. Nothing else about the connection changes.
///
/// A real node held one of these past a hundred and five seconds, for
/// thirty five bytes of drip, and would have held it for weeks: `PEER_SILENCE`
/// is checked between frames and this peer was never between frames.
#[test]
fn a_real_node_lets_go_of_a_dripping_peer() {
    let node = Node::bind(params(), loopback()).unwrap();

    let mut drip = TcpStream::connect(node.address()).unwrap();
    let mut header = Vec::new();
    params().network.as_u32().encode_to(&mut header);
    (MAX_FRAME_BYTES as u32).encode_to(&mut header);
    drip.write_all(&header).unwrap();
    drip.flush().unwrap();

    assert!(
        wait_until(Duration::from_secs(5), || node.peer_count() == 1),
        "the node should take the connection",
    );

    // Kept dribbling for as long as the node keeps listening, so what ends
    // this is the node giving up and not the test running out of patience.
    let started = Instant::now();
    let dripping = std::thread::spawn(move || {
        while started.elapsed() < Duration::from_secs(105) {
            std::thread::sleep(Duration::from_secs(3));
            if drip.write_all(&[0u8]).is_err() || drip.flush().is_err() {
                return;
            }
        }
    });
    let released = wait_until(FRAME_PATIENCE + Duration::from_secs(15), || {
        node.peer_count() == 0
    });
    let waited = started.elapsed();
    let _ = dripping.join();
    node.shutdown();
    assert!(
        released,
        "after {waited:?} of one byte every three seconds inside a single open frame, the \
         node was still holding the connection. The peer spent about a byte a second. \
         PEER_SILENCE never fires, because the read loop never gets back to the top of \
         its `while`.",
    );
}

/// What that bought an attacker: every connection slot the node had.
///
/// `has_room_for` refuses once `peers.len() >= MAX_PEERS`, and it is the same
/// check `dial_from_book` makes, so a node whose slots are full can neither
/// accept anybody nor go out and find anybody. From loopback one host filled
/// them all, because `can_be_refused` exempts it from `MAX_PER_HOST`; from
/// the internet it took `MAX_PEERS` / `MAX_PER_HOST` = 24 addresses. The whole of it
/// cost eight bytes of header each and a fifth of a byte a second after that,
/// and the node went on looking healthy while it was off the network.
#[test]
fn dripping_peers_cannot_take_every_connection_slot() {
    let node = Node::bind(params(), loopback()).unwrap();

    let mut header = Vec::new();
    params().network.as_u32().encode_to(&mut header);
    (MAX_FRAME_BYTES as u32).encode_to(&mut header);

    let drips: Vec<TcpStream> = (0..cairn_net::node::MAX_PEERS)
        .map(|_| {
            let mut socket = TcpStream::connect(node.address()).unwrap();
            socket.write_all(&header).unwrap();
            socket.flush().unwrap();
            socket
        })
        .collect();

    // One byte to every open frame every two seconds, inside the node's five
    // second read deadline, for as long as this test runs.
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let stop = std::sync::Arc::clone(&running);
    let dripper = std::thread::spawn(move || {
        let mut drips = drips;
        let mut sent = 0u64;
        while stop.load(std::sync::atomic::Ordering::SeqCst) {
            for socket in &mut drips {
                let _ = socket.write_all(&[0u8]);
                let _ = socket.flush();
                sent += 1;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        sent
    });

    assert!(
        wait_until(Duration::from_secs(10), || node.peer_count()
            >= cairn_net::node::MAX_PEERS),
        "the node should take the connections: it took {}",
        node.peer_count(),
    );
    // Past the whole frame's patience, so this is the steady state and not a
    // moment during setup: a node that judges a peer on finishing the frame it
    // opened has let all of these go by now, and one that judges it on the
    // socket's own deadline never will.
    std::thread::sleep(FRAME_PATIENCE + Duration::from_secs(5));
    let full = node.peer_count();

    // An honest peer now tries to join, and says hello properly.
    let welcomed = (|| {
        let mut honest = TcpStream::connect(node.address()).ok()?;
        honest.set_read_timeout(Some(Duration::from_secs(8))).ok()?;
        write_message(&mut honest, params().network, &hello(9_876, 4_242)).ok()?;
        match read_message(&mut honest, params().network) {
            Ok(Incoming::Message(Message::Welcome(_))) => Some(true),
            other => {
                println!("honest peer heard back: {other:?}");
                Some(false)
            }
        }
    })()
    .unwrap_or(false);

    running.store(false, std::sync::atomic::Ordering::SeqCst);
    let sent = dripper.join().unwrap();
    node.shutdown();
    assert!(
        welcomed,
        "{full} connection slots were held by peers that had each sent a {} byte header and \
         then {sent} bytes in all between them; no honest peer could get in, and the node \
         cannot dial out either, because dial_from_book asks the same has_room_for.",
        header.len(),
    );
}

// ---------------------------------------------------------------------------
// FINDING B, repaired: the allowance window was reset by hanging up.
//
// `read_loop` built a fresh `PeerState` for every connection, and `spent` and
// `window_started` lived on it, so nothing about a peer survived its socket.
// The ceiling `sync::ALLOWANCE` puts on what a peer may make a node do in ten
// seconds was therefore a ceiling per connection rather than per peer: greet,
// spend the window, hang up, dial back. `MAX_PER_HOST` allows two at a time,
// nothing rate-limits reconnection, and no refusal is ever earned, because
// asking is not misbehaviour. Measured: one address drew 5504 Chain answers
// in 5.4 seconds across six connections, 1024 apiece, where the allowance
// intends 1024 per ten seconds in all.
//
// The window belongs to the address now and is kept by the node, so what a
// peer spent on the connection before this one is already gone from it, and
// the two connections one host may hold at once share it as well.
// ---------------------------------------------------------------------------

/// `GetChain` costs `COST_CHAIN` = 8 against an `ALLOWANCE` of 8192, so one window
/// answers exactly 1024 of them and then goes quiet.
const CHAIN_PER_WINDOW: usize = 1024;

fn ask_chain_until_quiet(address: SocketAddr, nonce: u64, asks: usize) -> usize {
    let mut writing = TcpStream::connect(address).unwrap();
    let mut reading = writing.try_clone().unwrap();
    reading
        .set_read_timeout(Some(Duration::from_millis(1_500)))
        .unwrap();
    // Read while writing: the node answers as it goes, and a test that filled
    // both socket buffers before reading a byte would deadlock rather than
    // measure anything.
    let counting = std::thread::spawn(move || {
        let mut answered = 0usize;
        // The node also sends GetPeers about once a second, so "quiet" here is
        // measured on Chain answers rather than on the socket falling silent.
        let mut last = Instant::now();
        while last.elapsed() < Duration::from_millis(700) {
            match read_message(&mut reading, params().network) {
                Ok(Incoming::Message(Message::Chain { .. })) => {
                    answered += 1;
                    last = Instant::now();
                }
                Ok(Incoming::Message(_) | Incoming::Quiet) => {}
                Err(_) => break,
            }
        }
        answered
    });

    write_message(&mut writing, params().network, &hello(nonce, 4_242)).unwrap();
    for _ in 0..asks {
        if write_message(
            &mut writing,
            params().network,
            &Message::GetChain {
                locator: Vec::new(),
            },
        )
        .is_err()
        {
            break;
        }
    }
    let answered = counting.join().unwrap_or(0);
    let _ = writing.shutdown(std::net::Shutdown::Both);
    answered
}

#[test]
fn hanging_up_does_not_hand_a_peer_a_fresh_allowance() {
    let node = Node::bind(params(), loopback()).unwrap();
    let address = node.address();

    let rounds = 6usize;
    let started = Instant::now();
    let mut answered = 0usize;
    let mut each = Vec::new();
    for round in 0..rounds {
        let got = ask_chain_until_quiet(address, 1_000 + round as u64, CHAIN_PER_WINDOW + 64);
        each.push(got);
        answered += got;
    }
    let took = started.elapsed();
    node.shutdown();

    println!("{answered} Chain answers in {took:?} across {rounds} connections: {each:?}");
    // Whatever the wall clock did, one address cannot have been answered more
    // than one window's worth per ten seconds, plus one for a boundary.
    let windows = (took.as_secs() / 10) + 2;
    let ceiling = CHAIN_PER_WINDOW * windows as usize;
    assert!(
        answered <= ceiling,
        "one address drew {answered} answers in {took:?} by reconnecting {rounds} times; \
         the allowance permits about {ceiling}. The window used to live in PeerState, \
         which read_loop made fresh for every socket, so a peer that hung up and dialled \
         back had spent nothing.",
    );
}

// ---------------------------------------------------------------------------
// FINDING C, repaired: a stranger chose which addresses the node dialled, and
// private and loopback ranges were not among the ones it refused.
//
// `book::is_dialable` rejected only port zero, the unspecified address,
// broadcast and multicast. Everything else went in, including 127.0.0.0/8,
// 10/8, 172.16/12, 192.168/16 and 169.254/16, and any greeted peer could put
// sixty four addresses in the book per message for COST_TRIVIAL. The node
// then opened a TCP connection to whatever was in there and wrote its own
// handshake into it. Not a way of forging a request, since the bytes are
// fixed, but a way of making a host that is probably allowed to reach an
// internal service knock on it, and `169.254.169.254` is where the machines
// this project runs on keep their credentials.
//
// The book now knows the difference between its three doors. What the
// operator gives is taken as given: where a node runs is their business, and
// a devnet on loopback and a lab on 10/8 are somebody's real network. The
// address a live peer is reachable at is taken too, because the part of it
// that matters was observed on the socket rather than asserted by anybody.
// What a peer *names* is weighed: an address out in the world from anyone,
// and an address inside this machine or this network only from a peer this
// node went out and dialled that is itself in the same place. Out on the
// internet that holds for nobody, which is the whole point.
// ---------------------------------------------------------------------------

#[test]
fn a_stranger_cannot_point_a_node_at_private_addresses() {
    let node = Node::bind(params(), loopback()).unwrap();

    let mut socket = TcpStream::connect(node.address()).unwrap();
    write_message(&mut socket, params().network, &hello(5_555, 4_242)).unwrap();

    let named: Vec<SocketAddr> = vec![
        "127.0.0.1:22".parse().unwrap(),
        "10.0.0.5:6379".parse().unwrap(),
        "172.16.4.4:9200".parse().unwrap(),
        "192.168.1.1:80".parse().unwrap(),
        "169.254.169.254:80".parse().unwrap(),
    ];
    write_message(
        &mut socket,
        params().network,
        &Message::Peers(named.iter().copied().map(PeerAddress).collect()),
    )
    .unwrap();

    // Long enough for several rounds of upkeep, so this is what the node
    // settled on and not what it had got to.
    let taken = wait_until(Duration::from_secs(5), || {
        let book = node.known_addresses();
        named.iter().any(|address| book.contains(address))
    });
    let book = node.known_addresses();
    node.shutdown();

    assert!(
        !taken,
        "a peer that had done nothing but say hello put {named:?} into the node's address \
         book for the price of one message; the book holds {book:?}, and dial_from_book \
         opens a connection to every one of them.",
    );
    // The peer's own address is a different matter and is still written down:
    // its host came from the socket, so naming it is not a way of naming
    // somebody else.
    assert!(
        book.iter().any(|address| address.port() == 4_242),
        "the peer that spoke is still reachable at where it spoke from"
    );
}

/// And it opened them: the node was made to speak to a third party.
#[test]
fn a_stranger_cannot_make_a_node_connect_to_a_third_party() {
    // A machine that has nothing to do with Cairn, standing in for whatever
    // the attacker names: an internal service, a port worth scanning, a host
    // worth having a stranger's node knock on.
    let bystander = TcpListener::bind(loopback()).unwrap();
    // Polled rather than waited on, because the whole point of the repair is
    // that nobody knocks: a blocking accept would sit here for the life of
    // the test run instead of reporting that.
    bystander.set_nonblocking(true).expect("a listener to poll");
    let victim_of_choice = bystander.local_addr().unwrap();

    let node = Node::bind(params(), loopback()).unwrap();
    let mut socket = TcpStream::connect(node.address()).unwrap();
    write_message(&mut socket, params().network, &hello(6_666, 4_242)).unwrap();
    write_message(
        &mut socket,
        params().network,
        &Message::Peers(vec![PeerAddress(victim_of_choice)]),
    )
    .unwrap();

    // Several rounds of upkeep, which is what a node that meant to dial this
    // address would have needed rather less of.
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut delivered: Option<Vec<u8>> = None;
    while Instant::now() < deadline {
        let Ok((stream, _)) = bystander.accept() else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        let mut stream = stream;
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buffer = [0u8; 64];
        let count = stream.read(&mut buffer).unwrap_or(0);
        delivered = Some(buffer[..count].to_vec());
        break;
    }
    node.shutdown();

    assert!(
        delivered.is_none(),
        "one Peers message from a peer that had said nothing but hello made the node open a \
         TCP connection to {victim_of_choice}, a machine it had never heard of, and write \
         {} bytes into it. Whoever connected chose who the node talked to.",
        delivered.map_or(0, |bytes| bytes.len()),
    );
}

// CHECKED, DID NOT REPRODUCE: a readback oracle on top of this.
//
// `book::missed` drops an address after MAX_MISSES failed dials, so the subset
// of a named list that is still in the book after the retry schedule ought to
// be the subset whose port was open, readable with GetPeers. Run for 340
// seconds against one open and one closed port, the two were not told apart:
// the open one consumed the dialling budget (see FINDING G below), so the
// closed one was never retried often enough to be dropped. The oracle may
// still exist for a list of addresses that are all closed; it was not shown.
// Whether it survives the repair to FINDING C was not looked at either: a
// stranger no longer names the private addresses such an oracle is worth
// pointing at, which narrows it rather than closing it.

// ---------------------------------------------------------------------------
// FINDING D, repaired: every message cloned the whole address book, under the
// chain lock.
//
// `node::decide` runs for every message from every peer, and its second line
// was `let book = shared.book().clone();`, taken while `shared.chain()` is
// held. The book holds up to MAX_ADDRESSES entries in two BTreeMaps, and the
// only message that reads it is GetPeers. So the cost of serving a seventeen
// byte Ping was proportional to a number the attacker set with Peers messages
// that cost it one unit each, and it was paid inside the node's one global
// lock. The audit measured 1500 pings at 49 ms against an empty book and 103
// ms against a full one; this machine, which is slower at the copying and
// quicker at the sockets, made it 3.2 times rather than 2.1.
//
// Nothing in the layer that decides reads the book any more. A request for
// addresses is named there and answered by the node once the chain is let go
// of, which is what the blocks, the headers and the join pieces already did
// and for the same reason.
// ---------------------------------------------------------------------------

/// Addresses across enough /16 groups to get past `MAX_PER_GROUP`.
///
/// In 240/4, which is reserved and which nothing anywhere routes, because the
/// node dials what is in its book and a test has no business knocking on real
/// machines. A stranger doing this for real uses addresses that answer; what
/// matters here is only how many of them the book holds.
fn filler(count: usize) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    // MAX_PER_GROUP entries per /16, so the second octet has to move every
    // thirty two addresses or the book refuses them.
    for group in 0..=255u8 {
        for host in 0..32u8 {
            if out.len() >= count {
                return out;
            }
            out.push(SocketAddr::from((
                Ipv4Addr::new(240, group, host, 1),
                8_333,
            )));
        }
    }
    out
}

fn stuff_the_book(address: SocketAddr, nonce: u64, addresses: &[SocketAddr]) {
    let mut socket = TcpStream::connect(address).unwrap();
    write_message(&mut socket, params().network, &hello(nonce, 4_242)).unwrap();
    for chunk in addresses.chunks(MAX_SHARED_ADDRESSES) {
        write_message(
            &mut socket,
            params().network,
            &Message::Peers(chunk.iter().copied().map(PeerAddress).collect()),
        )
        .unwrap();
    }
    // Let the node take them in, and read what it says back so neither side
    // fills a socket buffer.
    let mut reading = socket.try_clone().unwrap();
    reading
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until {
        if read_message(&mut reading, params().network).is_err() {
            break;
        }
    }
    let _ = socket.shutdown(std::net::Shutdown::Both);
}

/// Pings a node as fast as it will take them, returning how long they took.
fn ping_burst(address: SocketAddr, nonce: u64, count: usize) -> Duration {
    let mut writing = TcpStream::connect(address).unwrap();
    let mut reading = writing.try_clone().unwrap();
    reading
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write_message(&mut writing, params().network, &hello(nonce, 4_242)).unwrap();

    let counting = std::thread::spawn(move || {
        let mut seen = 0usize;
        while seen < count {
            match read_message(&mut reading, params().network) {
                Ok(Incoming::Message(Message::Pong(_))) => seen += 1,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        seen
    });

    let started = Instant::now();
    for nonce in 0..count as u64 {
        write_message(&mut writing, params().network, &Message::Ping(nonce)).unwrap();
    }
    let seen = counting.join().unwrap_or(0);
    let took = started.elapsed();
    let _ = writing.shutdown(std::net::Shutdown::Both);
    assert_eq!(seen, count, "the node answered {seen} of {count} pings");
    took
}

#[test]
fn a_ping_costs_the_same_whatever_the_address_book_holds() {
    // A burst that fits inside OUTBOUND_QUEUE, so a writing thread that does
    // not get scheduled on a busy machine cannot make the node drop this peer
    // for not keeping up, which is not what is being measured. Ten of them
    // against each node, and a ping costs one unit against an allowance of
    // 8192 that the address keeps across connections.
    const PINGS: usize = 200;
    const ROUNDS: u64 = 10;

    // Best of eight each way: this is a constant factor on a path that also
    // does socket work, and one run of it is mostly scheduler noise.
    let empty = Node::bind(params(), loopback()).unwrap();
    let quick = (0..ROUNDS)
        .map(|round| ping_burst(empty.address(), 100 + round, PINGS))
        .min()
        .unwrap();
    empty.shutdown();

    let stuffed = Node::bind(params(), loopback()).unwrap();
    let addresses = filler(MAX_ADDRESSES);
    // Four connections, because one peer may only send so many messages in a
    // flood window. An attacker uses however many it needs; this is not the
    // finding, it is the setup for it.
    for (round, chunk) in addresses.chunks(1_024).enumerate() {
        stuff_the_book(stuffed.address(), 200 + round as u64, chunk);
    }
    let held = stuffed.known_addresses().len();
    let slow = (0..ROUNDS)
        .map(|round| ping_burst(stuffed.address(), 300 + round, PINGS))
        .min()
        .unwrap();
    stuffed.shutdown();

    println!("{PINGS} pings: {quick:?} with an empty book, {slow:?} with {held} addresses in it",);
    assert!(
        slow.as_secs_f64() < quick.as_secs_f64() * 1.4,
        "answering {PINGS} pings took {slow:?} with {held} addresses in the book and {quick:?} \
         with none: {:.1} times longer. decide() used to clone the whole book for every \
         message, holding the chain, and a stranger set how big it was with Peers messages \
         that cost one unit each.",
        slow.as_secs_f64() / quick.as_secs_f64().max(f64::EPSILON),
    );
}

// ---------------------------------------------------------------------------
// FINDING E, repaired: GetPeers was the cheapest message there is and drew
// the largest answer a peer can get for nothing.
//
// A 9 byte request drew a 1217 byte answer, 135 times larger, for
// COST_TRIVIAL, and the asker set the size of it by filling the book with
// IPv6 addresses first, which are 19 bytes on the wire against 7. At one unit
// an allowance window bought 8192 of those answers: ten megabytes out of a
// node for 72 kilobytes in, from one address, every ten seconds.
//
// One message being bigger than the message that asked for it is not the
// defect and could not be fixed; an answer is larger than a question. The
// defect was that it was free, so the total was set by how fast a stranger
// could ask rather than by anything the node decides. It now costs one unit
// per address it can carry, the same way a run of headers is charged for the
// reads it will do, which puts a ceiling of ALLOWANCE / COST_PEERS answers on
// a window and leaves an honest peer, which asks about once a second, eight
// times more room than it uses.
// ---------------------------------------------------------------------------

/// `COST_PEERS` is `MAX_SHARED_ADDRESSES` = 64 against an `ALLOWANCE` of 8192,
/// so
/// one window answers 128 of them and then goes quiet.
const PEERS_PER_WINDOW: usize = 128;

/// Addresses out in the world, and the ones worth naming: an IPv6 entry is
/// nineteen bytes on the wire against seven, so a book full of them is a book
/// that gives the largest answer.
///
/// An IPv6 group is the first four octets, so the second hextet moves or
/// `MAX_PER_GROUP` keeps only thirty two of them.
fn far_flung(count: usize) -> Vec<SocketAddr> {
    (1..=count)
        .map(|index| format!("[2001:{index:x}::{index:x}]:8333").parse().unwrap())
        .collect()
}

#[test]
fn getpeers_costs_what_the_answer_costs() {
    let node = Node::bind(params(), loopback()).unwrap();
    // The book is what the answer is drawn from, and a stranger fills it.
    stuff_the_book(node.address(), 400, &far_flung(MAX_SHARED_ADDRESSES * 2));

    let mut writing = TcpStream::connect(node.address()).unwrap();
    let mut reading = writing.try_clone().unwrap();
    reading
        .set_read_timeout(Some(Duration::from_millis(1_500)))
        .unwrap();

    let mut asked = Vec::new();
    Message::GetPeers.encode_to(&mut asked);
    let asked = asked.len() + 8;

    // Read while asking, so neither side fills a socket buffer and stops.
    let counting = std::thread::spawn(move || {
        let (mut answers, mut bytes) = (0usize, 0usize);
        let mut last = Instant::now();
        while last.elapsed() < Duration::from_millis(900) {
            match read_message(&mut reading, params().network) {
                Ok(Incoming::Message(Message::Peers(addresses))) => {
                    let mut encoded = Vec::new();
                    Message::Peers(addresses).encode_to(&mut encoded);
                    answers += 1;
                    bytes += encoded.len() + 8;
                    last = Instant::now();
                }
                Ok(Incoming::Message(_) | Incoming::Quiet) => {}
                Err(_) => break,
            }
        }
        (answers, bytes)
    });

    write_message(&mut writing, params().network, &hello(500, 4_242)).unwrap();
    // Under MAX_MESSAGES_PER_WINDOW, so what stops the answers is the price
    // of them and not the node closing the connection for flooding.
    let asks = 1_500usize;
    for _ in 0..asks {
        if write_message(&mut writing, params().network, &Message::GetPeers).is_err() {
            break;
        }
    }
    let (answers, bytes) = counting.join().unwrap_or((0, 0));
    let _ = writing.shutdown(std::net::Shutdown::Both);
    node.shutdown();

    let each = bytes.checked_div(answers).unwrap_or(0);
    println!(
        "{asks} asks of {asked} bytes drew {answers} answers, {bytes} bytes, {each} bytes each",
    );
    // One boundary's worth of slack: a burst that straddles two windows gets
    // what is left of the first and the whole of the second.
    let ceiling = PEERS_PER_WINDOW * 2;
    assert!(
        answers <= ceiling,
        "{asks} requests of {asked} bytes drew {answers} answers and {bytes} bytes back, where \
         one window allows {PEERS_PER_WINDOW}. GetPeers cost COST_TRIVIAL, so what a node \
         wrote in answer was set by how fast a stranger could ask: {:.0} kB/s of one peer's \
         uplink turned into {:.0} kB/s of this node's.",
        asked as f64 * 200.0 / 1024.0,
        each as f64 * 200.0 / 1024.0,
    );
    assert!(
        answers > 0,
        "an honest peer still gets an answer, and asks about once a second"
    );
}

// ---------------------------------------------------------------------------
// FINDING F, repaired: the write deadline was restartable by the receiver, the
// same way the read deadline was by the sender.
//
// `attach_peer` sets WRITE_TIMEOUT on the socket, and `write_message` called
// `write_all`, which loops over partial writes. SO_SNDTIMEO is per write()
// syscall, so a peer that accepted one byte per period kept the writer thread
// inside a single `write_all` for ever. What that retained was not just the
// thread: `read_loop` removed the peer from `shared.peers()`, freeing the
// connection slot so the same host could open another, and only then called
// `writer.join()`, so the queue of up to OUTBOUND_QUEUE answers and both
// threads outlived the peer the node had already given up on.
//
// Three things changed. The frame carries FRAME_PATIENCE in this direction as
// well as the other. Every way out of `read_loop` now reaches the socket at
// the bottom of it, where three of them used to return instead and leave the
// writer inside a write nobody was taking. And the connection slot is the last
// thing given up, so nothing the node still holds for a peer sits outside its
// own accounting.
// ---------------------------------------------------------------------------

/// The same period the drip uses, for the same reason: the deadline the repair
/// reads is a real clock, so a fake that returned instantly would prove
/// nothing about it.
struct Sip {
    periods: usize,
    budget: usize,
}

impl Write for Sip {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.periods >= self.budget {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "gave up"));
        }
        self.periods += 1;
        std::thread::sleep(drip_period());
        Ok(buf.len().min(1))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_peer_that_sips_at_one_byte_a_period_is_given_up_on() {
    let budget = 15usize;
    let mut sip = Sip { periods: 0, budget };
    // One piece of a join answer, which is what a node serving a newcomer
    // writes. A block is 128 kB by the consensus rules and behaves the same.
    let big = Message::JoinPart {
        what: Joining::Ledger,
        at: Hash32::ZERO,
        part: 0,
        parts: 1,
        bytes: vec![0u8; JOIN_PART_BYTES],
    };
    let outcome = write_message(&mut sip, params().network, &big);
    assert!(
        sip.periods < budget,
        "the writer was still inside one frame after {} periods of {:?}, for a peer \
         accepting one byte per period. It would stay there {} days for this message and \
         {} days for a 128 kB block, holding everything queued behind it. Outcome: \
         {outcome:?}",
        sip.periods,
        drip_period(),
        (JOIN_PART_BYTES as u64 * 20) / 86_400,
        (128 * 1024 * 20) / 86_400,
    );
}

/// **And the node lets go of the peer and its queue together.**
///
/// The connection slot is the last thing given up now, so `peer_count`
/// dropping is the node saying it has finished with the peer: the reading
/// thread is out, the writing thread has been joined, and the queue behind it
/// has gone with it. Before, the slot went first and all three outlived it
/// with nothing to bound them, because the path out of `read_loop` that a peer
/// which stops reading takes was the one path that did not shut the socket.
///
/// Two things cannot be asserted from out here. The answers the operating
/// system had already taken off the node's hands are one: a graceful close
/// still delivers those, and throwing them away means resetting the
/// connection, which the standard library gives no way to ask for. The
/// ordering is the other, because the only scenario that would show it needs
/// the writing thread blocked while the reading loop is still going, and
/// whether it blocks depends on socket buffer sizes no test can set. So this
/// stands as a lock on what is visible, that the node needs nothing at all
/// from the peer in order to be finished with it and writes nothing more once
/// it says so; the deadline that bounds the writer is asserted above, on a
/// writer that cannot escape it.
#[test]
fn a_node_lets_go_of_the_peer_and_its_queue_together() {
    let node = Node::bind(params(), loopback()).unwrap();
    // Something worth queueing: an address list is the largest answer a peer
    // can draw, and the book is what it is drawn from.
    stuff_the_book(node.address(), 600, &far_flung(MAX_SHARED_ADDRESSES * 2));

    let mut socket = TcpStream::connect(node.address()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write_message(&mut socket, params().network, &hello(700, 4_242)).unwrap();
    // Enough to overrun OUTBOUND_QUEUE and every socket buffer under it, and
    // not one byte of the answers is read. Spread over four windows because
    // of the repair to FINDING E: address lists are no longer free, so making
    // a node write half a megabyte now takes a peer four windows of its whole
    // allowance rather than one burst of nine byte requests.
    for _ in 0..4 {
        for _ in 0..PEERS_PER_WINDOW {
            if write_message(&mut socket, params().network, &Message::GetPeers).is_err() {
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(10));
    }

    // Not one byte is read from the socket while this waits. A node that still
    // needed the peer to take its answers before it could let go would be
    // holding both threads and the whole queue at the end of it.
    let released = wait_until(FRAME_PATIENCE + Duration::from_secs(10), || {
        node.peer_count() == 0
    });
    assert!(
        released,
        "the node should give up on a peer that stops reading, without waiting on that \
         peer to do anything",
    );

    // What the operating system already took is still there to collect, and
    // then the stream ends. Anything past that would be the node writing to a
    // peer it has said it is finished with.
    let mut collected = 0usize;
    let mut ended = false;
    for _ in 0..5_000 {
        match read_message(&mut socket, params().network) {
            Ok(Incoming::Message(Message::Peers(_))) => collected += 1,
            Ok(_) => {}
            Err(_) => {
                ended = true;
                break;
            }
        }
    }
    node.shutdown();
    println!("{collected} answers were still on the wire after the node let go");

    assert!(
        ended,
        "the node said it had finished with the peer and then went on writing to it: \
         {collected} answers and counting, out of a queue that holds OUTBOUND_QUEUE of \
         them and two threads that nobody had joined.",
    );
}

// ---------------------------------------------------------------------------
// FINDING G, repaired: one address that accepted a connection and said
// nothing consumed every outbound slot the node had.
//
// `dial_from_book` skips addresses in `connected`, which it built from
// `peer.advertised`, and `advertised` is only filled in once a peer has
// introduced itself. An address that accepts TCP and never greets therefore
// never appeared in `connected`, so it was dialled again on the next round,
// and again, until `dialled` reached TARGET_PEERS. All eight outbound
// connections then went to the one address, so what the node learned about
// the chain came only through connections a stranger had chosen; and
// `PEER_SILENCE` reaped them after ninety seconds, whereupon it began again.
// Measured: one address drew nine separate connections in about five seconds,
// against a target of eight. This is the eclipse `MAX_PER_GROUP` is written
// against, reached through a different door.
//
// The peer now carries the address this node dialled to reach it, beside the
// one it may never introduce itself at, and upkeep reads both. An address
// that takes a connection and never speaks also counts a miss against itself
// when the connection ends, the same as one that refused the dial outright,
// so the cycle does not begin again either.
//
// The two addresses are seeded rather than named in a Peers message, which is
// how they got here when this was found. Since FINDING C a stranger out on
// the internet no longer chooses loopback addresses for a node to dial, and
// on loopback there is no stranger: what a devnet is, is an operator naming
// their own machines. The finding is about what one silent address costs,
// whoever named it.
// ---------------------------------------------------------------------------

#[test]
fn one_silent_address_cannot_take_every_outbound_slot() {
    let sink = TcpListener::bind(loopback()).unwrap();
    let sink_at = sink.local_addr().unwrap();
    let taken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counting = std::sync::Arc::clone(&taken);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in sink.incoming().flatten() {
            counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            held.push(stream);
        }
    });

    let node = Node::bind(params(), loopback()).unwrap();
    // An honest peer the node ought to find, written down at the same moment
    // as the sink so neither has a head start.
    let honest = Node::bind(params(), loopback()).unwrap();
    node.remember_seed(sink_at);
    node.remember_seed(honest.address());

    let found = wait_until(Duration::from_secs(20), || honest.peer_count() >= 1);
    // Several more rounds of upkeep, so what the sink holds is what the node
    // settled on rather than what it had got to.
    std::thread::sleep(Duration::from_secs(5));
    let opened = taken.load(std::sync::atomic::Ordering::SeqCst);
    node.shutdown();
    honest.shutdown();

    println!("the sink took {opened} connections; the honest node was found: {found}");
    assert!(
        opened <= 1,
        "one silent address drew {opened} separate connections from the node, because a peer \
         that never introduces itself never got into `connected` and so was dialled again \
         every round. TARGET_PEERS is {}, so one address filled every outbound slot.",
        cairn_net::node::TARGET_PEERS,
    );
    assert!(
        found,
        "the node spent its outbound slots on an address that says nothing and never reached \
         the peer that would have talked to it",
    );
}

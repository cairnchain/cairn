//! What an address is allowed to say about the peers behind it.
//!
//! Everything a node keeps per address is a defence against one machine
//! wearing many hats, and every one of them has the same cost: the people
//! genuinely behind one address pay it too. These pin where that line sits, so
//! moving it is a decision rather than a slip.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::doc_markdown
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use cairn_ledger::validation::ConsensusParams;
use cairn_net::book::{realm_of, worth_hearing_about, Realm};
use cairn_net::message::Message;
use cairn_net::wire::{read_message, write_message};

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

// ---------------------------------------------------------------------------
// CLAIM 4: which addresses a stranger may name.
// ---------------------------------------------------------------------------

/// **Every range the address rules name, and how.**
///
/// The list a stranger's claim about an address is read against. What is not
/// on it is read as open, so a range added to the internet and not to this is
/// a range somebody can name at this node; the second half of this prints
/// those rather than asserting about them.
#[test]
fn the_ranges_the_address_rules_name() {
    let cases: [(&str, Realm); 14] = [
        ("127.0.0.1", Realm::Loopback),
        ("10.1.2.3", Realm::Private),
        ("172.16.0.1", Realm::Private),
        ("192.168.0.1", Realm::Private),
        ("100.64.0.1", Realm::Private),
        ("169.254.169.254", Realm::LinkLocal),
        ("198.51.100.4", Realm::Open),
        ("::1", Realm::Loopback),
        ("fd00::1", Realm::Private),
        ("fc00::1", Realm::Private),
        ("fe80::1", Realm::LinkLocal),
        ("::ffff:10.0.0.1", Realm::Private),
        ("::ffff:127.0.0.1", Realm::Loopback),
        ("2001:db8::1", Realm::Open),
    ];
    for (text, want) in cases {
        let ip: IpAddr = text.parse().unwrap();
        assert_eq!(realm_of(ip), want, "{text}");
    }

    // Ranges that are not named, reported rather than asserted against.
    for text in [
        "0.1.2.3",
        "192.0.0.170",
        "198.18.0.1",
        "240.0.0.1",
        "2002:c0a8:101::",
        "64:ff9b::a9fe:a9fe",
        "::ffff:0:10.0.0.1",
    ] {
        let ip: IpAddr = text.parse().unwrap();
        println!("not named: {text} -> {:?}", realm_of(ip));
    }
}

/// **A testnet run entirely on a LAN still learns its network.**
///
/// The rules refuse a private address named by a stranger out on the
/// internet. They must not refuse one named by a peer that is itself on that
/// network, or a chain run inside one building would never gossip at all.
#[test]
fn a_lan_only_deployment_still_gossips() {
    let neighbour = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)));
    let peer: SocketAddr = "192.168.1.21:9000".parse().unwrap();
    assert!(
        worth_hearing_about(&peer, neighbour, true),
        "a dialled LAN peer could not pass on another LAN peer"
    );
    // Across two private ranges, which one LAN often has.
    let other: SocketAddr = "10.9.9.9:9000".parse().unwrap();
    assert!(worth_hearing_about(&other, neighbour, true));
    // But not over a connection the LAN peer opened.
    assert!(
        !worth_hearing_about(&peer, neighbour, false),
        "an accepted LAN connection may name LAN addresses"
    );
}

// ---------------------------------------------------------------------------
// CLAIM 2, end to end through the real `Shared::allowance_for`.
// ---------------------------------------------------------------------------

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

/// **A connection that opens into a spent window waits for the next one.**
///
/// The cost the address window keeps, deliberately. A connection cannot be
/// told apart from the one that just hung up, so it starts where its address
/// left off; every connection on one machine arrives from `127.0.0.1`, so on a
/// devnet that is all of them.
///
/// One window, and no longer: the inheritance happens at a connection's first
/// question and not at every boundary after it. `shared_allowance.rs` is where
/// that is pinned; this is the same thing over a real socket.
/// Every connection on one machine arrives from `127.0.0.1`, so a devnet, a
/// test rig, and everything behind one NAT gateway share a single window.
///
/// One socket spends it with ordinary `GetPeers` messages; a second socket,
/// a different program that has spent nothing, is then answered with silence.
#[test]
fn a_connection_opening_into_a_spent_window_waits_for_the_next_one() {
    use std::net::TcpStream;
    use std::time::SystemTime;

    // Start inside a window rather than across a boundary.
    let second = || {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    while second() % 10 > 2 {
        thread::sleep(Duration::from_millis(100));
    }

    let node = cairn_net::Node::bind(params(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let at = node.address();

    let mut hog = TcpStream::connect(at).unwrap();
    hog.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut reading = hog.try_clone().unwrap();
    thread::spawn(move || while read_message(&mut reading, params().network).is_ok() {});
    write_message(&mut hog, params().network, &hello(9_001, 4_242)).unwrap();
    // 128 * COST_PER_ADDRESS_SERVED * MAX_SHARED_ADDRESSES == the whole window.
    for _ in 0..128 {
        write_message(&mut hog, params().network, &Message::GetPeers).unwrap();
    }
    thread::sleep(Duration::from_millis(300));

    let mut fresh = TcpStream::connect(at).unwrap();
    fresh
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    write_message(&mut fresh, params().network, &hello(9_002, 4_343)).unwrap();
    write_message(&mut fresh, params().network, &Message::Ping(4_242)).unwrap();

    let mut ponged = false;
    for _ in 0..12 {
        match read_message(&mut fresh, params().network) {
            Ok(cairn_net::wire::Incoming::Message(Message::Pong(4_242))) => {
                ponged = true;
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let straddled = second() % 10 < 3;
    node.shutdown();
    println!("fresh connection was answered: {ponged} (window straddled: {straddled})");
    assert!(
        !ponged,
        "the window a connection opens into is not its own, so a peer could \
         refill one by hanging up"
    );
}

/// **The control: the same second connection, on a node nobody has drained.**
///
/// Without it the test above passes on a node that answers nobody.
#[test]
fn a_fresh_node_answers_the_same_ping() {
    use std::net::TcpStream;
    let node = cairn_net::Node::bind(params(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut fresh = TcpStream::connect(node.address()).unwrap();
    fresh
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    write_message(&mut fresh, params().network, &hello(9_003, 4_444)).unwrap();
    write_message(&mut fresh, params().network, &Message::Ping(4_242)).unwrap();
    let mut ponged = false;
    for _ in 0..12 {
        match read_message(&mut fresh, params().network) {
            Ok(cairn_net::wire::Incoming::Message(Message::Pong(4_242))) => {
                ponged = true;
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    node.shutdown();
    assert!(ponged, "the control did not answer either");
}

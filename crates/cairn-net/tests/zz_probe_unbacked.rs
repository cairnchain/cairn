//! AUDIT PROBE. Not part of the shipped suite; delete after reading.
//!
//! The refused-host set is bounded, and it is keyed by `IpAddr`. A claim that
//! fails there condemns every peer at that address, including ones that never
//! made a claim of their own.

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

/// The ranges the change does name, so the report can say what is covered.
#[test]
fn zz_what_the_range_list_does_cover() {
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

/// A testnet run entirely on a LAN still learns its network.
#[test]
fn zz_a_lan_only_deployment_still_gossips() {
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

/// Every connection on one machine arrives from `127.0.0.1`, so a devnet, a
/// test rig, and everything behind one NAT gateway share a single window.
///
/// One socket spends it with ordinary `GetPeers` messages; a second socket,
/// a different program that has spent nothing, is then answered with silence.
#[test]
fn zz_one_loopback_socket_starves_every_other_one() {
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
        "the second connection was served, so the window was not shared"
    );
}

/// The control: the same second connection, on a node nobody has drained.
#[test]
fn zz_the_control_a_fresh_node_answers_the_same_ping() {
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

// ---------------------------------------------------------------------------
// CLAIM 6 and its neighbour: the refused-host set is bounded, but it is keyed
// by IpAddr, and a claim that fails there condemns every peer at that address.
// ---------------------------------------------------------------------------

/// A stranger that shares an address with an honest peer — one CGNAT pool,
/// one office, one machine running a devnet — makes that honest peer's claim
/// start life already discredited, and the chooser then follows a lighter
/// chain it can see is lighter.
#[test]
fn zz_a_failed_claim_condemns_every_peer_at_the_same_address() {
    use cairn_net::choosing::{Approach, Chooser, JoinProgress, Step};
    use cairn_net::sync::JOIN_RATHER_THAN_READ;

    let long = JOIN_RATHER_THAN_READ + 10;
    let shared_ip = IpAddr::V4(Ipv4Addr::new(100, 100, 5, 5)); // one NAT gateway
    let elsewhere = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

    let mut chooser = Chooser::new();
    // The stranger speaks first, from the shared address, and does not show.
    chooser.noted(1, Some(shared_ip), 100, long, true, 1_000);
    assert!(matches!(
        chooser.step(1_003, true, 0, JoinProgress::NothingYet, &[1]),
        Step::Ask(1, _)
    ));
    chooser.failed(1, 1_004);

    // Now the honest peer behind the same gateway, with the heavier chain,
    // and the stranger's second address with a lighter one.
    chooser.noted(2, Some(shared_ip), 1_000, long, true, 1_005);
    chooser.noted(3, Some(elsewhere), 500, long, true, 1_005);

    let step = chooser.step(1_006, true, 0, JoinProgress::NothingYet, &[1, 2, 3]);
    println!("with an honest 1000 and a stranger's 500 in front of it: {step:?}");
    assert_eq!(
        step,
        Step::Ask(3, Approach::Join),
        "the heavier honest claim was asked after all"
    );

    // And nothing about the heavier claim stops the lighter one being taken.
    assert!(
        chooser.shown(3, 500, 1_010),
        "the lighter chain was not accepted"
    );
    assert!(
        chooser.allows(3, 500, 1_010),
        "the heavier claim held the commitment back"
    );
}

/// The same thing with no attacker in it: every peer on one machine has the
/// same address, so one stalled join marks all of them.
#[test]
fn zz_on_one_machine_a_single_stall_condemns_the_whole_devnet() {
    use cairn_net::choosing::{Approach, Chooser, JoinProgress, Step};
    use cairn_net::sync::JOIN_RATHER_THAN_READ;

    let long = JOIN_RATHER_THAN_READ + 10;
    let here = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut chooser = Chooser::new();
    chooser.noted(1, Some(here), 100, long, true, 1_000);
    chooser.step(1_003, true, 0, JoinProgress::NothingYet, &[1]);
    // The join stalls — which on one machine is likely, because every peer
    // there draws on one allowance window and a join piece costs an eighth
    // of it.
    chooser.failed(1, 1_004);

    for peer in 2..6u64 {
        chooser.noted(
            peer,
            Some(here),
            1_000 + u128::from(peer),
            long,
            true,
            1_005,
        );
    }
    let step = chooser.step(1_006, true, 0, JoinProgress::NothingYet, &[1, 2, 3, 4, 5]);
    println!("every local peer, after one stall: {step:?}");
    match step {
        Step::Ask(_, Approach::Read) => {}
        other => panic!("expected the fallback read, got {other:?}"),
    }
}

//! READ-ONLY AUDIT PROBES for the 2e5ac9f transport/peer-management changes.
//!
//! These are throwaway: delete the file to remove them. Nothing here asserts
//! what the code *should* do; each test pins down what it *does* do, so a
//! finding can be quoted rather than argued.

#![allow(
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_ledger::note::NetworkId;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::book::{realm_of, worth_hearing_about, Realm};
use cairn_net::message::{Joining, Message, JOIN_PART_BYTES};
use cairn_net::sync::{on_message, Allowance, Local, PeerState, Window};
use cairn_net::wire::{read_message, write_message, MAX_FRAME_BYTES};

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn solo(chain: &mut ChainStore) -> Local<'_> {
    Local {
        keeps: cairn_net::Keeps {
            headers: true,
            cold_set: false,
        },
        nonce: 1,
        chain,
        listen: 4242,
    }
}

/// A connection from an address the node keeps a count for, already greeted.
fn behind(address: &Arc<Mutex<Window>>) -> PeerState {
    PeerState {
        greeted: true,
        height: 1_000,
        total_work: 1,
        allowance: Allowance::at(address),
        ..PeerState::default()
    }
}

/// Whether the node answered at all. `Reaction::idle()` with nothing in it is
/// what an exhausted allowance produces.
fn answered(reaction: &cairn_net::sync::Reaction) -> bool {
    !reaction.reply.is_empty()
        || reaction.share_addresses
        || reaction.join.is_some()
        || reaction.locate.is_some()
        || reaction.headers.is_some()
        || !reaction.fetch.is_empty()
}

// ---------------------------------------------------------------------------
// CLAIM 2: the allowance window is kept per ADDRESS.
// ---------------------------------------------------------------------------

/// Two nodes behind one public address — one CGNAT pool, one office, one cloud
/// NAT gateway — share a single allowance window. The one that speaks second
/// in a window inherits what the first spent and is answered with silence.
#[test]
fn zz_a_neighbour_on_the_same_address_spends_the_windows_allowance() {
    let mut chain = ChainStore::new(params());
    let now = 2_000_000_000u64; // a multiple of the ten second window
    let address = Arc::new(Mutex::new(Window::default()));

    // The noisy neighbour. Eight join requests, which is the most expensive
    // thing the protocol has and is a perfectly legitimate message.
    let mut noisy = behind(&address);
    let mut spent = 0u32;
    for part in 0..8u32 {
        let reaction = on_message(
            &mut solo(&mut chain),
            &mut noisy,
            Message::GetJoin {
                what: Joining::Ledger,
                part,
            },
            now,
        );
        if answered(&reaction) {
            spent += 1;
        }
    }
    assert_eq!(spent, 8, "eight join requests is one whole window");

    // The victim's connection opens now — or simply speaks for the first time
    // in this window. It is a different machine; it has spent nothing.
    let mut victim = behind(&address);
    let refused = (0..16)
        .filter(|_| {
            !answered(&on_message(
                &mut solo(&mut chain),
                &mut victim,
                Message::GetPeers,
                now,
            ))
        })
        .count();
    assert_eq!(
        refused,
        16,
        "the victim was answered {} times out of 16 despite having spent nothing",
        16 - refused
    );

    // And a plain Ping, the cheapest thing there is, is refused too.
    let ping = on_message(&mut solo(&mut chain), &mut victim, Message::Ping(7), now);
    assert!(
        ping.reply.is_empty(),
        "a one unit Ping still got through, so the starvation is partial"
    );
}

/// The same mechanism seen from the honest side: a peer that had a network
/// blip and dialled back gets nothing for the rest of the window it left.
#[test]
fn zz_a_reconnect_inside_the_window_comes_back_with_nothing() {
    let mut chain = ChainStore::new(params());
    let now = 2_000_000_000u64;
    let address = Arc::new(Mutex::new(Window::default()));

    let mut first = behind(&address);
    let mut served = 0u32;
    while answered(&on_message(
        &mut solo(&mut chain),
        &mut first,
        Message::GetPeers,
        now,
    )) {
        served += 1;
        assert!(served < 10_000, "the window never ran out");
    }
    assert_eq!(served, 128, "GetPeers is 64 units of an 8192 unit window");
    drop(first);

    // The socket dropped; the peer dialled straight back, same address.
    let mut again = behind(&address);
    assert!(
        !answered(&on_message(
            &mut solo(&mut chain),
            &mut again,
            Message::GetPeers,
            now
        )),
        "the reconnection was answered, so hanging up still refills"
    );

    // It comes back when the window turns, and not before.
    assert!(
        answered(&on_message(
            &mut solo(&mut chain),
            &mut again,
            Message::GetPeers,
            now + 10
        )),
        "the next window did not hand anything back"
    );
}

/// How long the victim stays starved: the neighbour only has to spend the
/// window before the victim's first message of that window, and window
/// boundaries are `unix_time / 10`, which anybody can compute.
#[test]
fn zz_the_starvation_renews_every_window_for_eight_messages() {
    let mut chain = ChainStore::new(params());
    let address = Arc::new(Mutex::new(Window::default()));
    let mut noisy = behind(&address);
    let mut victim = behind(&address);

    let mut victim_served = 0u32;
    let mut attacker_messages = 0u32;
    for window in 0..30u64 {
        let now = 2_000_000_000 + window * 10;
        // The attacker is first past the boundary.
        for part in 0..8u32 {
            attacker_messages += 1;
            on_message(
                &mut solo(&mut chain),
                &mut noisy,
                Message::GetJoin {
                    what: Joining::Ledger,
                    part,
                },
                now,
            );
        }
        // The victim asks its once-a-second questions afterwards.
        for second in 0..10u64 {
            if answered(&on_message(
                &mut solo(&mut chain),
                &mut victim,
                Message::GetPeers,
                now + second,
            )) {
                victim_served += 1;
            }
        }
    }
    assert_eq!(
        victim_served, 0,
        "the victim got {victim_served} answers over five minutes"
    );
    assert_eq!(
        attacker_messages, 240,
        "240 messages over five minutes is the whole cost of it"
    );
}

// ---------------------------------------------------------------------------
// CLAIM 1: the whole-frame deadline, and what throughput it demands.
// ---------------------------------------------------------------------------

/// A reader that hands over `rate` bytes every `tick`, like a slow link.
struct Trickle {
    rate: usize,
    tick: Duration,
    header: Vec<u8>,
    at: usize,
    delivered: usize,
}

impl Read for Trickle {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at < self.header.len() {
            let count = out.len().min(self.header.len() - self.at);
            out[..count].copy_from_slice(&self.header[self.at..self.at + count]);
            self.at += count;
            return Ok(count);
        }
        thread::sleep(self.tick);
        let count = out.len().min(self.rate);
        for byte in &mut out[..count] {
            *byte = 0;
        }
        self.delivered += count;
        Ok(count)
    }
}

/// The read side of the frame deadline, and the throughput floor it sets.
///
/// A peer sending a legitimate 512 KiB join piece over a link that delivers
/// steadily and never pauses long enough to trip the 5 s socket deadline is
/// nonetheless cut off once the frame passes 20 s.
#[test]
fn zz_the_read_deadline_sets_a_floor_on_an_honest_slow_link() {
    let network = NetworkId::new(0x0a1b_2c3d);
    let body = JOIN_PART_BYTES;
    let mut header = Vec::new();
    header.extend_from_slice(&network.as_u32().to_le_bytes());
    header.extend_from_slice(&u32::try_from(body).unwrap().to_le_bytes());

    // 20 KiB/s, delivered in 2 KiB chunks every 100 ms: below the floor.
    let mut slow = Trickle {
        rate: 2_048,
        tick: Duration::from_millis(100),
        header,
        at: 0,
        delivered: 0,
    };
    let started = Instant::now();
    let outcome = read_message(&mut slow, network);
    let took = started.elapsed();
    let delivered = slow.delivered;
    let error = outcome.expect_err("a 20 KiB/s honest sender was not cut off");
    println!(
        "read side: cut off after {:?}, {delivered} of {body} bytes delivered \
         ({:.1} KiB/s), error {error}",
        took,
        delivered as f64 / took.as_secs_f64() / 1024.0
    );
    assert!(
        took < Duration::from_secs(25),
        "the deadline did not fire inside 25 s"
    );
    // The arithmetic the floor comes from, restated against the constants.
    println!(
        "floor for a {body} byte join piece: {:.1} KiB/s; \
         floor for a {MAX_FRAME_BYTES} byte frame: {:.1} KiB/s",
        body as f64 / 20.0 / 1024.0,
        MAX_FRAME_BYTES as f64 / 20.0 / 1024.0
    );
}

/// A writer that takes `rate` bytes every `tick` and never refuses.
struct Sipping {
    rate: usize,
    tick: Duration,
    taken: usize,
}

impl Write for Sipping {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        thread::sleep(self.tick);
        let count = bytes.len().min(self.rate);
        self.taken += count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The write side. A peer that keeps taking bytes — never zero, so never a
/// `WriteZero`, and never a socket timeout — is now cut off at 20 s.
#[test]
fn zz_the_write_deadline_is_enforced_too() {
    let network = NetworkId::new(0x0a1b_2c3d);
    let message = Message::JoinPart {
        what: Joining::Ledger,
        at: cairn_primitives::hash::Hash32::from_bytes([0u8; 32]),
        part: 0,
        parts: 22,
        bytes: vec![0u8; JOIN_PART_BYTES],
    };
    let mut sipping = Sipping {
        rate: 2_048,
        tick: Duration::from_millis(100),
        taken: 0,
    };
    let started = Instant::now();
    let outcome = write_message(&mut sipping, network, &message);
    let took = started.elapsed();
    let error = outcome.expect_err("a peer taking 20 KiB/s was not cut off");
    println!(
        "write side: gave up after {:?}, {} bytes taken, error {error}",
        took, sipping.taken
    );
    assert!(
        took < Duration::from_secs(25),
        "the write deadline did not fire inside 25 s"
    );
}

/// The dribble the change was written against: one byte at a time, forever.
/// Bounded now, and the bound is the frame rather than the syscall.
#[test]
fn zz_a_dribbling_sender_no_longer_holds_the_frame_open() {
    let network = NetworkId::new(0x0a1b_2c3d);
    let mut header = Vec::new();
    header.extend_from_slice(&network.as_u32().to_le_bytes());
    header.extend_from_slice(&u32::try_from(MAX_FRAME_BYTES).unwrap().to_le_bytes());
    let mut dribble = Trickle {
        rate: 1,
        tick: Duration::from_millis(50),
        header,
        at: 0,
        delivered: 0,
    };
    let started = Instant::now();
    let outcome = read_message(&mut dribble, network);
    let took = started.elapsed();
    assert!(outcome.is_err(), "the dribbler was tolerated");
    println!(
        "dribbler: {} bytes in {:?} ({:.3} bytes/s) before it was cut off",
        dribble.delivered,
        took,
        dribble.delivered as f64 / took.as_secs_f64()
    );
    assert!(took < Duration::from_secs(25));
}

// ---------------------------------------------------------------------------
// CLAIM 4: which addresses a stranger may name.
// ---------------------------------------------------------------------------

/// RFC 6052's well known translation prefix. On an IPv6-only network with a
/// NAT64 gateway — which is what a phone on most carriers, and a good many
/// enterprise and cloud networks, actually sits on — `64:ff9b::a9fe:a9fe`
/// reaches `169.254.169.254`.
#[test]
fn zz_the_nat64_prefix_is_not_in_the_range_list() {
    let metadata: Ipv6Addr = "64:ff9b::a9fe:a9fe".parse().unwrap();
    let inside: Ipv6Addr = "64:ff9b::a00:1".parse().unwrap(); // 10.0.0.1
    let router: Ipv6Addr = "64:ff9b::c0a8:101".parse().unwrap(); // 192.168.1.1
    let here: Ipv6Addr = "64:ff9b::7f00:1".parse().unwrap(); // 127.0.0.1

    for (name, ip) in [
        ("169.254.169.254", metadata),
        ("10.0.0.1", inside),
        ("192.168.1.1", router),
        ("127.0.0.1", here),
    ] {
        assert_eq!(
            realm_of(IpAddr::V6(ip)),
            Realm::Open,
            "{name} through NAT64 was recognised"
        );
    }

    // And so it goes into the book on the word of a stranger out on the
    // internet, on a connection that stranger opened.
    let far_away = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)));
    let named = SocketAddr::new(IpAddr::V6(metadata), 80);
    assert!(
        worth_hearing_about(&named, far_away, false),
        "the NAT64 spelling of the metadata address was refused after all"
    );
}

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

/// The frame's clock starts when `read_message` is entered, not when the first
/// byte lands, so a peer whose answer takes a moment to build eats up to one
/// READ_TIMEOUT (5 s) of the 20. The real floor is therefore
/// `size / 15 s`, not `size / 20 s`.
struct LateThenSteady {
    header: Vec<u8>,
    at: usize,
    dawdle: Duration,
    rate: usize,
    tick: Duration,
    delivered: usize,
}

impl Read for LateThenSteady {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == 0 {
            // The socket blocks with nothing on it, just inside its own
            // deadline, while the peer builds the answer.
            thread::sleep(self.dawdle);
        }
        if self.at < self.header.len() {
            let count = out.len().min(self.header.len() - self.at);
            out[..count].copy_from_slice(&self.header[self.at..self.at + count]);
            self.at += count;
            return Ok(count);
        }
        thread::sleep(self.tick);
        let count = out.len().min(self.rate);
        for byte in &mut out[..count] {
            *byte = 0;
        }
        self.delivered += count;
        Ok(count)
    }
}

#[test]
fn zz_the_real_floor_is_size_over_fifteen_seconds_not_twenty() {
    let network = NetworkId::new(0x0a1b_2c3d);
    let body = JOIN_PART_BYTES;
    let mut header = Vec::new();
    header.extend_from_slice(&network.as_u32().to_le_bytes());
    header.extend_from_slice(&u32::try_from(body).unwrap().to_le_bytes());

    // 31.5 KiB/s: comfortably above the 25.6 KiB/s the doc comment computes
    // from twenty seconds, and below what fifteen seconds demands.
    let mut link = LateThenSteady {
        header,
        at: 0,
        dawdle: Duration::from_millis(4_900),
        rate: 3_226,
        tick: Duration::from_millis(100),
        delivered: 0,
    };
    let started = Instant::now();
    let outcome = read_message(&mut link, network);
    let took = started.elapsed();
    println!(
        "31.5 KiB/s with a 4.9 s wait first: {:?} after {:?}, {} of {body} bytes",
        outcome.as_ref().err().map(ToString::to_string),
        took,
        link.delivered,
    );
    println!(
        "floor at 20 s: {:.1} KiB/s; floor at 15 s: {:.1} KiB/s",
        body as f64 / 20.0 / 1024.0,
        body as f64 / 15.0 / 1024.0,
    );
    assert!(
        outcome.is_err(),
        "a link above the stated floor got through, so the dawdle costs nothing"
    );
}

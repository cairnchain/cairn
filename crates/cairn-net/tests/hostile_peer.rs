//! Findings from a network-security audit, written as tests that FAIL on the
//! code they were found in and would pass once the finding is addressed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::{ChainStore, Located};
use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::{Message, MAX_ANNOUNCED, MAX_HEADERS, MAX_REQUESTED};
use cairn_net::node::TARGET_PEERS;
use cairn_net::sync::{on_message, Local, PeerState, MAX_AWAITING};
use cairn_net::Keeps;
use cairn_net::Node;
use cairn_primitives::Hash32;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

///
/// `patience` is a liveness bound and not a measurement: it costs nothing when
/// the condition is met, so the only thing a short one buys is a failure that
/// says nothing about the code. This suite has had three of those in one day,
/// at fifteen seconds, at a minute, and at twenty milliseconds, each green on a
/// quiet machine and red on a busy one. They are set far past anything a loaded
/// runner does rather than near it.
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

// ---------------------------------------------------------------------------
// FINDING 1: GetHeaders is charged one flat unit yet serves up to MAX_HEADERS
// reads off the header log, so a peer can pull ~MAX_HEADERS times more disk
// work per allowance window than the per-block charge on GetBlocks allows.
// ---------------------------------------------------------------------------

fn solo(chain: &mut ChainStore) -> Local<'_> {
    Local {
        keeps: Keeps {
            headers: true,
            cold_set: false,
        },
        nonce: 1,
        chain,
        listen: 4242,
    }
}

fn greeted() -> PeerState {
    PeerState {
        greeted: true,
        height: 1_000,
        total_work: 1,
        ..PeerState::default()
    }
}

#[test]
fn getheaders_is_charged_far_below_the_disk_it_serves() {
    let mut chain = ChainStore::new(params());
    // A single fixed instant, so the whole loop spends one allowance window.
    let now = 2_000_000_000u64;

    // Header reads one peer can authorise in one window. Each afforded
    // GetHeaders lets the node read up to MAX_HEADERS headers off disk.
    let mut peer = greeted();
    let mut header_reads: u64 = 0;
    for _ in 0..1_000_000 {
        let reaction = on_message(
            &mut solo(&mut chain),
            &mut peer,
            Message::GetHeaders {
                from: 0,
                count: MAX_HEADERS as u64,
            },
            now,
        );
        match reaction.headers {
            Some((_, count)) => header_reads += count,
            None => break, // allowance exhausted for this window
        }
    }

    // Block reads the same peer can authorise in the same window, using the
    // largest request the protocol allows. GetBlocks is charged per block.
    let mut peer = greeted();
    let mut block_reads: u64 = 0;
    let heights: Vec<u64> = (0..MAX_REQUESTED as u64).collect();
    for _ in 0..1_000_000 {
        let reaction = on_message(
            &mut solo(&mut chain),
            &mut peer,
            Message::GetBlocks(heights.clone()),
            now,
        );
        if reaction.fetch.is_empty() {
            break; // allowance exhausted for this window
        }
        block_reads += reaction.fetch.len() as u64;
    }

    // Both come off the same disk and drain the same per-peer allowance. A peer
    // must not be able to extract far more disk work through one message kind
    // than through the other. It can: GetHeaders authorises MAX_HEADERS reads
    // for the price of one.
    assert!(
        header_reads <= block_reads,
        "one peer pulled {header_reads} header reads but only {block_reads} block reads \
         from a single allowance window: GetHeaders is under-charged by ~{}x",
        header_reads / block_reads.max(1),
    );
}

// ---------------------------------------------------------------------------
// FINDING 2: the per-peer `awaiting` set has no ceiling. A stranger sends a
// stream of cheap `Chain` messages, each naming a fresh run of heights; each
// extends `awaiting` by up to MAX_REQUESTED and resets `asked_at`, so the
// BATCH_PATIENCE clear (which reads that same `asked_at`) never fires. The set
// grows without bound: per-peer memory exhaustion charged one unit a message.
// ---------------------------------------------------------------------------

#[test]
fn a_peer_cannot_grow_the_awaiting_set_without_bound() {
    let mut chain = ChainStore::new(params());
    let mut peer = greeted();
    // One fixed instant: every message below spends from a SINGLE allowance
    // window, and 1_000 units is a fraction of it, so nothing here is even
    // rate-limited. A real attacker simply keeps going across windows.
    let now = 2_000_000_000u64;

    for i in 0..1_000u64 {
        // Distinct, non-overlapping runs of heights, so every batch is new.
        let from = 1_000_000 + i * 1_000;
        let reaction = on_message(
            &mut solo(&mut chain),
            &mut peer,
            Message::Chain { from, count: 2_000 },
            now,
        );
        assert!(
            reaction.drop_peer.is_none(),
            "a Chain message is not misbehaviour"
        );
    }

    // Four batches, and not one more, whatever the peer says. The defect was
    // that there was no ceiling at all: a thousand of these messages, a
    // fraction of one allowance window, held a hundred and twenty eight
    // thousand heights, and it grew for as long as the peer kept talking.
    assert!(
        peer.awaiting.len() <= MAX_REQUESTED * 4,
        "awaiting grew to {} heights from 1000 cheap Chain messages: a peer \
         sending these indefinitely would exhaust the node's memory",
        peer.awaiting.len(),
    );
}

// ---------------------------------------------------------------------------
// FINDING 2b: the test above drives the one path that keeps that ceiling.
//
// Two messages put heights into `awaiting`. A `Chain` goes through
// `request_range`, which counts what a batch would newly wait on and refuses
// the batch that does not fit. An `Announce` goes through `request_announced`,
// which read the room once and then admitted every new height in the
// announcement as long as there was room for a single one.
//
// So the guard above is true and demonstrates a different thing from what the
// ceiling claims. It says a `Chain` cannot push the set past 512. What
// `MAX_AWAITING` says is that the set does not go past 512.
//
// While it is over, the path that does keep the ceiling refuses everything:
// `request_range` finds no room and answers `idle`, so this node stops asking
// for the stretches it is catching up on until `BATCH_PATIENCE` empties the
// set. An announcement a peer chose to send bought a stall in this node's own
// sync, for one unit.
// ---------------------------------------------------------------------------

/// Fills `awaiting` to one place short of the ceiling, without going through
/// either path under test.
///
/// Written into the set rather than driven there by messages, because what is
/// being measured is what one announcement adds to a nearly full set, and
/// reaching that state through `request_range` would be measuring the path
/// that already holds.
fn one_place_short(peer: &mut PeerState) {
    for height in 0..(MAX_AWAITING as u64 - 1) {
        peer.awaiting.insert(height);
    }
    assert_eq!(peer.awaiting.len(), MAX_AWAITING - 1);
}

#[test]
fn an_announcement_cannot_push_the_awaiting_set_past_the_ceiling_either() {
    let mut chain = ChainStore::new(params());
    let mut peer = greeted();
    one_place_short(&mut peer);

    // Every height fresh, every identifier one this node has never held, which
    // is what an announcement from a peer ahead of it looks like.
    let announced: Vec<Located> = (0..MAX_ANNOUNCED as u64)
        .map(|step| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&step.to_le_bytes());
            Located::new(1_000_000 + step, Hash32::from_bytes(id))
        })
        .collect();
    let reaction = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Announce(announced),
        2_000_000_000,
    );
    assert!(
        reaction.drop_peer.is_none(),
        "an announcement is not misbehaviour"
    );

    assert!(
        peer.awaiting.len() <= MAX_AWAITING,
        "one announcement took the set to {} heights against a ceiling of \
         {MAX_AWAITING}. While it is over, `request_range` finds no room and \
         this node stops asking for the blocks it is catching up on.",
        peer.awaiting.len(),
    );
    // And the one place that was left was spent rather than passed over, so
    // this is the ceiling being met and not the announcement being refused.
    assert_eq!(
        peer.awaiting.len(),
        MAX_AWAITING,
        "the room that was there should have been filled"
    );
}

// ---------------------------------------------------------------------------
// FINDING 3: dial_from_book counts ALL peers (inbound included) against
// TARGET_PEERS, with no reserved outbound slots. A stranger that holds
// TARGET_PEERS inbound connections drives `wanted` to zero, so the node never
// dials out and only ever talks to whoever connected to it: an eclipse.
// ---------------------------------------------------------------------------

#[test]
fn a_node_with_no_flood_dials_its_seed() {
    // Control: with nothing holding its slots, a node dials the seed in its
    // book. This isolates the flood in the next test as the cause.
    let honest = Node::bind(params(), loopback()).unwrap();
    let victim = Node::bind(params(), loopback()).unwrap();
    victim.remember_seed(honest.address());

    let dialled = wait_until(Duration::from_secs(120), || honest.peer_count() >= 1);
    assert!(dialled, "a node with a seed and no flood should dial it");

    honest.shutdown();
    victim.shutdown();
}

#[test]
fn inbound_connections_do_not_starve_outbound_peer_discovery() {
    let honest = Node::bind(params(), loopback()).unwrap();
    let victim = Node::bind(params(), loopback()).unwrap();

    // A stranger fills the victim's peer slots with inbound connections the
    // moment it binds, before it has learned any seed. Loopback bypasses the
    // per-host cap, but any handful of addresses does the same on a real net.
    let mut flood: Vec<TcpStream> = Vec::new();
    for _ in 0..TARGET_PEERS {
        flood.push(TcpStream::connect(victim.address()).unwrap());
    }
    assert!(
        wait_until(Duration::from_secs(60), || victim.peer_count()
            >= TARGET_PEERS),
        "the victim should accept the inbound flood",
    );

    // Only now is it told where an honest node lives: a fresh laptop learns of
    // the network exactly this way, from a seed the operator gave it.
    victim.remember_seed(honest.address());

    // It should reach its seed regardless of how many strangers are attached.
    let dialled = wait_until(Duration::from_secs(120), || honest.peer_count() >= 1);
    assert!(
        dialled,
        "victim never dialled its seed while {TARGET_PEERS} inbound connections were held: \
         inbound peers count against the dial target, so a stranger holding {TARGET_PEERS} \
         connections eclipses the node from all outbound peer discovery",
    );

    drop(flood);
    honest.shutdown();
    victim.shutdown();
}

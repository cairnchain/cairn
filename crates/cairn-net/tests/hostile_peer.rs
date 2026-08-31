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

use cairn_chain::ChainStore;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::book::AddressBook;
use cairn_net::message::{Message, MAX_HEADERS, MAX_REQUESTED};
use cairn_net::node::TARGET_PEERS;
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::Node;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
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

// ---------------------------------------------------------------------------
// FINDING 1 — GetHeaders is charged one flat unit yet serves up to MAX_HEADERS
// reads off the header log, so a peer can pull ~MAX_HEADERS times more disk
// work per allowance window than the per-block charge on GetBlocks allows.
// ---------------------------------------------------------------------------

fn solo(chain: &mut ChainStore) -> Local<'_> {
    static EMPTY: std::sync::OnceLock<AddressBook> = std::sync::OnceLock::new();
    Local {
        shows_the_chain: true,
        nonce: 1,
        chain,
        book: EMPTY.get_or_init(AddressBook::new),
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
// FINDING 2 — the per-peer `awaiting` set has no ceiling. A stranger sends a
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
// FINDING 3 — dial_from_book counts ALL peers (inbound included) against
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

    let dialled = wait_until(Duration::from_secs(12), || honest.peer_count() >= 1);
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
        wait_until(Duration::from_secs(5), || victim.peer_count()
            >= TARGET_PEERS),
        "the victim should accept the inbound flood",
    );

    // Only now is it told where an honest node lives: a fresh laptop learns of
    // the network exactly this way, from a seed the operator gave it.
    victim.remember_seed(honest.address());

    // It should reach its seed regardless of how many strangers are attached.
    let dialled = wait_until(Duration::from_secs(12), || honest.peer_count() >= 1);
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

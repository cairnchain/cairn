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
///
/// Filled with heights the announcement below does not name, so that every one
/// of those is fresh and the ceiling is what stops them. A height already
/// outstanding costs nothing by design, so a set filled with the same heights
/// would measure that rule instead of this one.
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

/// What an announcement arms is written down as offered, not as sought.
///
/// The heights in an announcement are the sending peer's to choose, and the
/// ask this node sends in reply looks exactly like the ask it sends while
/// catching up. Only one of those two errands is owed the discount: catching
/// up, this node went and asked, and the peer answering is doing it a favour.
/// An announcement is the peer offering, and a block offered is a block
/// pushed. Told apart here, because told apart nowhere meant a peer that
/// announced first wrote its own price.
#[test]
fn what_an_announcement_arms_is_marked_as_offered() {
    let mut chain = ChainStore::new(params());
    let mut peer = greeted();

    let announced: Vec<Located> = (0..8u64)
        .map(|step| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&step.to_le_bytes());
            Located::new(4_000_000 + step, Hash32::from_bytes(id))
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
        "an announcement is not misbehaviour, whatever it names"
    );
    assert!(
        !peer.awaiting.is_empty(),
        "this node still has to ask about what it was told, or it never learns it is behind"
    );
    assert_eq!(
        peer.offered, peer.awaiting,
        "every height this ask covers came from the announcement, so every one of them is \
         a block offered rather than one this node went looking for. A height in the \
         waiting set and not in this one is charged as an answer, and the heights here \
         were the peer's to choose"
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

// ---------------------------------------------------------------------------
// The other door into `awaiting`.
//
// `offered` was added because an announcement's heights are the peer's to
// choose, and a block arriving at one of them was charged as an answer to
// something this node had gone looking for. The fix marked what
// `request_announced` puts into `awaiting`.
//
// `awaiting` has two fillers. The other is `request_range`, whose only caller
// is the `Chain { from, count }` arm, and both of those fields are the peer's
// to write. Nothing tracked whether this node had asked for a chain at all, so
// a `Chain` nobody asked for armed heights of the sender's choosing and every
// block pushed at one of them was charged the catching-up price. Measured
// before the repair: a discount of one thousand two hundred and eighty nine
// times, and one window of allowance buying four point nine gigabytes that way
// against three and three quarter megabytes through the door that was closed.
//
// Which is why these reach `awaiting` through a message. The test inside
// `sync.rs` sets `awaiting` and `offered` by hand, so it holds `cost_of` and
// cannot see either door.
// ---------------------------------------------------------------------------

/// A block pushed at a height a peer chose costs what a push costs.
#[test]
fn a_chain_nobody_asked_for_does_not_write_its_own_discount() {
    let mut chain = ChainStore::new(params());
    let now = 2_000_000_000u64;
    let from = 1u64;

    // Nobody asked. The peer volunteers a stretch and this node asks for the
    // blocks in it, which is right: what is under test is the price.
    let mut pushing = greeted();
    on_message(
        &mut solo(&mut chain),
        &mut pushing,
        Message::Chain { from, count: 4 },
        now,
    );
    assert!(
        pushing.awaiting.contains(&from),
        "the stretch has to have been asked for, or there is no price to compare"
    );
    assert!(
        pushing.offered.contains(&from),
        "a stretch nobody asked for is one the peer offered, and the heights in it are \
         the peer's to choose"
    );

    // And the same stretch, after this node asked for a chain of its own
    // accord. That is a catch-up, and a catch-up is what the discount is for.
    let mut catching_up = greeted();
    catching_up.chain_asked = true;
    on_message(
        &mut solo(&mut chain),
        &mut catching_up,
        Message::Chain { from, count: 4 },
        now,
    );
    assert!(catching_up.awaiting.contains(&from));
    assert!(
        !catching_up.offered.contains(&from),
        "an answer to a question this node asked is an answer, and paying a push price \
         for it would stop a node catching up at all"
    );

    // One question, one answer. A peer that sends five `Chain` messages to one
    // `GetChain` is offering four of them.
    let mut again = greeted();
    again.chain_asked = true;
    for step in 0..2u64 {
        on_message(
            &mut solo(&mut chain),
            &mut again,
            Message::Chain {
                from: 100 + step * 10,
                count: 4,
            },
            now,
        );
    }
    assert!(
        !again.offered.contains(&100),
        "the first answered the question"
    );
    assert!(
        again.offered.contains(&110),
        "and the second was nobody's question, so the mark is taken and not merely read"
    );
}

/// A peer that fills `awaiting` is asked again once the patience has run.
///
/// `BATCH_PATIENCE` is read in `follow_up` and nowhere else. `request_range`
/// answered `idle` when a batch did not fit, so it never reached it: a peer
/// that filled the set to its ceiling and then kept talking left this node
/// never asking it for a chain again, for as long as the connection lasted.
/// Its sibling `request_announced` has always ended in `follow_up`.
#[test]
fn a_peer_that_filled_the_awaiting_set_is_asked_again_once_patience_runs() {
    let mut chain = ChainStore::new(params());
    let now = 2_000_000_000u64;

    let mut peer = greeted();
    // Full, through the door that fills it.
    for step in 0..8u64 {
        on_message(
            &mut solo(&mut chain),
            &mut peer,
            Message::Chain {
                from: 1 + step * u64::try_from(MAX_REQUESTED).unwrap(),
                count: u64::try_from(MAX_REQUESTED).unwrap(),
            },
            now,
        );
    }
    assert_eq!(
        peer.awaiting.len(),
        MAX_AWAITING,
        "the set has to be at its ceiling, or this test asks nothing"
    );

    // Still full a moment later, and nothing is asked: the batch is not stale
    // yet and there is no room for another.
    let soon = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Chain {
            from: 9_000,
            count: 4,
        },
        now + 1,
    );
    assert!(
        soon.reply.is_empty(),
        "nothing is owed while the batch is fresh"
    );

    // And once the patience has run, the set is let go of and the chain is
    // asked for again.
    let later = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Chain {
            from: 9_000,
            count: 4,
        },
        now + 4_000,
    );
    assert!(
        later
            .reply
            .iter()
            .any(|said| matches!(said, Message::GetChain { .. })),
        "a peer that filled the set was never asked for a chain again: {:?}",
        later.reply
    );
}

/// A peer's own block does not re-arm its own discount.
///
/// The test above arms `chain_asked` by hand, and so never asks who arms it.
/// `follow_up` does: whenever nothing is outstanding and the peer's
/// `total_work` says it is ahead, it asks for the chain again and marks the
/// answer as one this node wanted. `total_work` is what the peer wrote in its
/// own greeting. A peer claiming the most work there is emptied `awaiting`
/// itself, a block at each height it had named, each fully decoded and none
/// applied because its parent was invented, and every such round armed the
/// catching up price for the next.
///
/// Three cases, driven through `follow_up` rather than set: a first ask is a
/// catch-up, a round that moved this node's chain earns the next one, and a
/// round that moved nothing does not. In the last the chain is still asked
/// for, because a peer that says it has more is worth asking; its answer pays
/// what a push pays.
#[test]
fn a_round_that_moved_nothing_does_not_earn_the_next_one_a_discount() {
    let mut chain = ChainStore::new(params());
    let now = 2_000_000_000u64;

    let ours = holding_work(&mut chain, now);

    // Nothing outstanding, a peer claiming everything, and a `Chain` that
    // offers nothing new, which is the shortest road into `follow_up`.
    let ahead = |work_when_asked: Option<u128>| PeerState {
        greeted: true,
        height: 1_000,
        total_work: u128::MAX,
        work_when_asked,
        ..PeerState::default()
    };
    let into_follow_up = Message::Chain { from: 0, count: 0 };

    let mut first = ahead(None);
    let reaction = on_message(
        &mut solo(&mut chain),
        &mut first,
        into_follow_up.clone(),
        now,
    );
    assert!(
        reaction
            .reply
            .iter()
            .any(|m| matches!(m, Message::GetChain { .. })),
        "a peer that says it has more is asked for it"
    );
    assert!(first.chain_asked, "and a first ask is a catch-up");

    // A round that moved this node's chain: the work recorded when it asked is
    // below the work it holds now.
    let mut moved = ahead(Some(ours - 1));
    on_message(
        &mut solo(&mut chain),
        &mut moved,
        into_follow_up.clone(),
        now,
    );
    assert!(
        moved.chain_asked,
        "a round that delivered blocks this node applied earns the next one the \
         catching up price, or an honest sync would stop getting it"
    );

    // And the same peer, one round later, having moved nothing since. This is
    // the shape an attacker would use: one round that looks honest, then
    // blocks that connect to nothing. It only fails if the work is written
    // down at each ask, and deleting that line left every case above green,
    // because each builds its peer fresh and none asks what the next round
    // compares against.
    moved.chain_asked = false;
    on_message(
        &mut solo(&mut chain),
        &mut moved,
        into_follow_up.clone(),
        now,
    );
    assert!(
        !moved.chain_asked,
        "one round that moved the chain buys one discounted round, not every \
         round after it"
    );

    // A round that moved nothing: the work is where it was when it asked.
    let mut stalled = ahead(Some(ours));
    let reaction = on_message(&mut solo(&mut chain), &mut stalled, into_follow_up, now);
    assert!(
        reaction
            .reply
            .iter()
            .any(|m| matches!(m, Message::GetChain { .. })),
        "the chain is still asked for"
    );
    assert!(
        !stalled.chain_asked,
        "and the answer is not armed as a catch-up: a round whose blocks \
         connected to nothing does not buy the next hundred and twenty eight \
         at a unit each"
    );

    // Which the price then says: the stretch it answers with is one the peer
    // offered.
    on_message(
        &mut solo(&mut chain),
        &mut stalled,
        Message::Chain { from: 1, count: 4 },
        now,
    );
    assert!(
        stalled.offered.contains(&1),
        "the blocks that follow pay what a push pays"
    );
}

/// One real block added to `chain`, so there is work to compare against, and
/// the work it now holds.
///
/// The first version of the test that uses this ran on an empty store, whose
/// work is nought, and the case that says a round which moved the chain earns
/// the next one sat behind `if ours > 0` and never ran: correct, and
/// unreachable.
fn holding_work(chain: &mut ChainStore, now: u64) -> u128 {
    let miner = cairn_crypto::SecretKey::from_bytes(&[4; 32]);
    let state = cairn_ledger::LedgerState::new();
    let coinbase = cairn_ledger::transaction::CoinbaseTransaction::new(
        0,
        vec![cairn_ledger::note::Note::new(
            params().initial_reward,
            miner.public_key(),
        )],
    );
    let block = cairn_ledger::validation::assemble_block(
        &state,
        coinbase,
        Vec::<cairn_ledger::transaction::Transfer>::new(),
        &params(),
        1_600,
        0,
    )
    .unwrap();
    let block = cairn_ledger::validation::mine_block(block, 1 << 22).expect("a nonce exists");
    chain.add_block(block, now).unwrap();
    let ours = chain.total_work();
    assert!(
        ours > 0,
        "the store holds work, or the comparisons prove nothing"
    );
    ours
}

/// The greeting that asks for the chain writes down the work it asked at.
///
/// Or the first `follow_up` after it takes itself for a first ask, and hands a
/// peer whose opening round moved nothing one more discounted round. Bounded,
/// unlike the loop the test above closes, and still a round a stranger did not
/// earn. Deleting that line left the test above green, because each of its
/// peers is built rather than greeted.
#[test]
fn the_greeting_that_asks_for_the_chain_writes_down_the_work_it_asked_at() {
    let mut chain = ChainStore::new(params());
    let now = 2_000_000_000u64;
    let ours = holding_work(&mut chain, now);
    let genesis = chain.genesis().unwrap_or(cairn_primitives::Hash32::ZERO);

    let mut greeting = PeerState::default();
    on_message(
        &mut solo(&mut chain),
        &mut greeting,
        Message::Hello(cairn_net::message::Handshake {
            version: cairn_net::message::PROTOCOL_VERSION,
            network: params().network,
            genesis,
            tip: cairn_primitives::Hash32::ZERO,
            height: 5,
            total_work: u128::MAX,
            listen: 0,
            nonce: 7,
            keeps: cairn_net::Keeps::default(),
        }),
        now,
    );
    assert!(greeting.greeted, "the greeting was taken");
    assert!(greeting.chain_asked, "and asked for the chain");
    assert_eq!(
        greeting.work_when_asked,
        Some(ours),
        "at the work this node held when it asked"
    );
}

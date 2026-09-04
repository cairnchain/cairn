//! What several threads over one node do to each other.
//!
//! AUDIT. Everything here is a probe, not a feature. A node runs a listener, a
//! read loop per peer, a writer per peer, a maintenance loop, a miner and an
//! HTTP server over one set of mutexes, and none of that had ever been pushed
//! from more than one thread at a time. These are the pushes.
//!
//! Four of these were written failing, against the behaviour the code claimed
//! rather than the behaviour it had, and each carries its own account of what
//! it found. They pass now, and they are kept so that the four defects have to
//! be reintroduced deliberately.
//!
//! The frame deadline that bounds a dripping peer is asserted in
//! `transport_audit.rs`, where it was found from the other side. What is
//! asserted here is what a dribble did to a node that had stopped itself.

#![allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::handover::Handover;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Joining, Message, PeerAddress, PROTOCOL_VERSION};
use cairn_net::node::MAX_PEERS;
use cairn_net::wire::{read_message, write_message, Incoming};
use cairn_net::Keeps;
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const BURIAL: u64 = 8;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(BURIAL)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-concurrency-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn wait_for(what: &str, patience: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("waited {patience:?} for {what} and it never happened");
}

/// Blocks built off to the side, so a node can be handed a ready made chain.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self) -> Block {
        let miner = SecretKey::from_bytes(&[1; 32]);
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_many(&mut self, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine()).collect()
    }
}

fn hello(nonce: u64) -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen: 0,
        nonce,
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
    })
}

/// The longest a caller waiting on the chain lock had to wait, sampled over
/// `over`.
///
/// `Node::height` takes the chain and does one comparison, so anything it
/// spends beyond a few microseconds is time some other thread was holding the
/// lock.
fn worst_chain_wait(node: &Node, over: Duration) -> Duration {
    let deadline = Instant::now() + over;
    let mut worst = Duration::ZERO;
    while Instant::now() < deadline {
        let at = Instant::now();
        let _ = node.height();
        worst = worst.max(at.elapsed());
    }
    worst
}

/// Every wait on the chain lock longer than `long`, sampled over `over`.
///
/// One entry per hold: a thread holding the chain blocks the call that is in
/// flight and no other, so a hold shows up as exactly one long wait. Counting
/// them is how "once a second, for ever" is told apart from "once, when the
/// tip moved".
fn long_waits_on_the_chain(node: &Node, over: Duration, long: Duration) -> Vec<Duration> {
    let deadline = Instant::now() + over;
    let mut waits = Vec::new();
    while Instant::now() < deadline {
        let at = Instant::now();
        let _ = node.height();
        let took = at.elapsed();
        if took >= long {
            waits.push(took);
        }
    }
    waits
}

/// **The ceiling on connections, under a storm rather than one at a time.**
///
/// `has_room_for` and the insertion that follows it are two separate takings
/// of the peer table, and three threads reach that pair: the accept loop, the
/// maintenance loop dialling, and any caller of `Node::connect`.
#[test]
fn a_connect_storm_does_not_push_the_peer_table_far_past_its_ceiling() {
    let node = Node::bind(params(), loopback()).unwrap();
    let address = node.address();
    let stop = Arc::new(AtomicBool::new(false));

    // Held open, silent. A silent peer keeps its slot until `PEER_SILENCE`,
    // which is far longer than this test runs.
    let mut held = Vec::new();
    let mut hands = Vec::new();
    for _ in 0..6 {
        let stop = Arc::clone(&stop);
        hands.push(thread::spawn(move || {
            let mut mine = Vec::new();
            for _ in 0..30 {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = TcpStream::connect(address) {
                    mine.push(stream);
                }
            }
            mine
        }));
    }
    for hand in hands {
        held.extend(hand.join().unwrap());
    }

    // Let the accept loop work through whatever the kernel queued.
    thread::sleep(Duration::from_millis(500));
    let peers = node.peer_count();
    println!(
        "{} connections offered, {peers} taken, ceiling {MAX_PEERS}",
        held.len()
    );
    assert!(
        peers <= MAX_PEERS,
        "the peer table reached {peers} against a ceiling of {MAX_PEERS}"
    );

    stop.store(true, Ordering::SeqCst);
    drop(held);
    wait_for(
        "the churned connections to be cleared up",
        Duration::from_secs(30),
        || node.peer_count() == 0,
    );
}

/// **Every thread that touches a node keeps making progress.**
///
/// A deadlock in a lock graph shows up as a thread that stops advancing while
/// the others carry on, so this watches counters rather than waiting for a
/// hang: a test that hangs says nothing about which pair of locks did it.
///
/// Each worker takes a different route into the shared state, chosen so that
/// every lock in the crate is reached from at least two threads: the chain,
/// the log, the peer table, the address book, the join collector, the
/// undertaking, and the thread table.
#[test]
fn many_threads_over_one_node_all_keep_moving() {
    let directory = scratch("hammer");
    let (node, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    let mut forge = Forge::new(params());
    for block in forge.mine_many(40) {
        node.submit_block(block).unwrap();
    }
    let node = Arc::new(node);
    let address = node.address();

    let names = [
        "reading the chain",
        "reading the status",
        "reading the disk",
        "writing the ledger",
        "churning connections",
        "submitting blocks",
    ];
    let ticks: Vec<Arc<AtomicU64>> = names.iter().map(|_| Arc::new(AtomicU64::new(0))).collect();
    let running = Arc::new(AtomicBool::new(true));
    let mut hands = Vec::new();

    {
        let (node, tick, running) = (
            Arc::clone(&node),
            Arc::clone(&ticks[0]),
            Arc::clone(&running),
        );
        hands.push(thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let _ = node.with_chain(ChainStore::tip);
                let _ = node.total_work();
                let _ = node.pool_len();
                let _ = node.cold_len();
                tick.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    {
        let (node, tick, running) = (
            Arc::clone(&node),
            Arc::clone(&ticks[1]),
            Arc::clone(&running),
        );
        hands.push(thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let _ = node.joining();
                let _ = node.probation();
                let _ = node.out_of_reach();
                let _ = node.peer_count();
                let _ = node.known_addresses();
                tick.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    {
        let (node, tick, running) = (
            Arc::clone(&node),
            Arc::clone(&ticks[2]),
            Arc::clone(&running),
        );
        hands.push(thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let _ = node.kept_bytes();
                let _ = node.archived_at(3);
                // The position anything reading old blocks is in: it asked the
                // chain, which no longer holds the body, and is now asking the
                // disk with the chain still held.
                node.with_chain(|_| {
                    let _ = node.archived_at(5);
                });
                tick.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    {
        let (node, tick, running) = (
            Arc::clone(&node),
            Arc::clone(&ticks[3]),
            Arc::clone(&running),
        );
        hands.push(thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let _ = node.write_ledger();
                tick.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    {
        let (tick, running) = (Arc::clone(&ticks[4]), Arc::clone(&running));
        hands.push(thread::spawn(move || {
            let mut nonce = 1u64;
            while running.load(Ordering::SeqCst) {
                if let Ok(mut stream) = TcpStream::connect(address) {
                    nonce += 1;
                    let _ = write_message(&mut stream, params().network, &hello(nonce));
                    let _ = write_message(&mut stream, params().network, &Message::GetPeers);
                }
                tick.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    {
        let (node, tick, running) = (
            Arc::clone(&node),
            Arc::clone(&ticks[5]),
            Arc::clone(&running),
        );
        hands.push(thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let block = forge.mine();
                let _ = node.submit_block(block);
                tick.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    // Nothing may go a full second without advancing while the others run.
    let mut seen: Vec<u64> = ticks
        .iter()
        .map(|tick| tick.load(Ordering::SeqCst))
        .collect();
    for round in 0..8 {
        thread::sleep(Duration::from_millis(1_000));
        for (index, tick) in ticks.iter().enumerate() {
            let now = tick.load(Ordering::SeqCst);
            assert!(
                now > seen[index],
                "round {round}: the thread {} stopped advancing at {now}, \
                 which is what a lock cycle looks like from outside",
                names[index]
            );
            seen[index] = now;
        }
    }

    running.store(false, Ordering::SeqCst);
    for hand in hands {
        let _ = hand.join();
    }
    node.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// **One stranger asking to join does not stop the whole node while it answers.**
///
/// AUDIT, repaired. `sync` set the question aside rather than answering it and
/// said so in as many words: "Both answers are megabytes, so building one runs
/// after the chain is let go of." It did not. `answer_deferred` called
/// `serve_join`, which took the join cache, then the chain, then the log, and
/// held all three for the whole build: four thousand and ninety six sampled
/// heights, each found by a binary search that read a header per step, each
/// carrying a forest proof read off the disk.
///
/// While that ran nothing else could have the chain. No block was validated,
/// no transfer taken, the miner could not assemble a candidate, and every
/// other peer's read loop waited. The cost grew with the length of the chain,
/// and it was paid again every time the tip moved, because the cache is keyed
/// on it.
///
/// What the chain is held for now is a tip, a forest of sixty four hashes and
/// nothing else. The headers and the forest paths come off the disk with the
/// chain let go of, and the log is taken one read at a time rather than for
/// the length of the build, since a thread wanting the log holds the chain
/// while it waits.
#[test]
fn a_join_request_does_not_hold_the_chain_shut() {
    // Settable so the same probe can be run against a longer chain: the
    // sample count is fixed, so what grows with the chain is the binary
    // search behind each sample and the depth of each forest proof.
    let height: usize = std::env::var("CAIRN_AUDIT_BLOCKS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(400);

    let directory = scratch("joinstall");
    let (node, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    let mut forge = Forge::new(params());
    for block in forge.mine_many(height) {
        node.submit_block(block).unwrap();
    }

    let quiet = worst_chain_wait(&node, Duration::from_millis(400));

    let mut peer = TcpStream::connect(node.address()).unwrap();
    write_message(&mut peer, params().network, &hello(987_654)).unwrap();
    write_message(
        &mut peer,
        params().network,
        &Message::GetJoin {
            what: Joining::Weight,
            part: 0,
        },
    )
    .unwrap();

    let asked = worst_chain_wait(&node, Duration::from_secs(3));
    println!(
        "chain of {height}: worst wait on the chain lock {quiet:?} with nobody asking, \
         {asked:?} while one peer asks to join"
    );

    node.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        asked < quiet + Duration::from_millis(20),
        "one peer asking to be handed the chain held the chain lock shut for {asked:?}, \
         against {quiet:?} when nobody was asking. Every other peer, the miner and the \
         HTTP server waited that long, and it grew with the chain."
    );
}

/// **A `GetJoin` naming a part that is not in the answer rebuilt the answer.**
///
/// AUDIT, repaired. `serve_join` asked `held_join` for the piece and, on
/// `None`, built the whole answer again. `held_join` ended in `piece_of`, which
/// returns `None` for two different reasons: the answer this node holds is
/// about another tip, and the answer this node holds has no such piece. The
/// first is worth a rebuild and the second is not, and they were read as one.
///
/// `GetJoin.part` is a bare `u32` off the wire with no ceiling of its own, and
/// a real answer runs to a couple of dozen pieces. So one seventeen byte
/// message, repeatable eight times an allowance window, bought the whole build:
/// four thousand and ninety six sampled heights, a binary search with a header
/// read off the disk per step, and a forest proof with every sample. Measured
/// on a chain of four hundred with the answer already built and the tip not
/// moving: five hundred and seventy milliseconds against thirty four to hand
/// over a piece that existed, and nothing went back to the asker either way.
/// The cost grows with the chain.
///
/// Asserted against what a real piece costs on the same machine rather than
/// against a number, because what is wrong is the ordering: a question this
/// node can answer out of what it is already holding must not cost more than
/// one it answers by sending half a megabyte.
#[test]
fn a_part_that_is_not_in_the_answer_does_not_rebuild_it() {
    let directory = scratch("joinpart");
    let (node, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    let mut forge = Forge::new(params());
    for block in forge.mine_many(400) {
        node.submit_block(block).unwrap();
    }

    let mut peer = TcpStream::connect(node.address()).unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    write_message(&mut peer, params().network, &hello(987_654)).unwrap();

    // The first ask builds the answer whatever happens, and is not measured.
    // Nothing mines here, so the tip does not move and the answer stays the
    // one every later question is about.
    what_it_cost(&mut peer, Joining::Weight, 0, 1);

    // A join answer is charged an eighth of an allowance window, so the asking
    // is paced to stay inside one rather than being answered with silence.
    let mut real = Vec::new();
    let mut absent = Vec::new();
    for round in 0..4u64 {
        thread::sleep(Duration::from_millis(1_600));
        real.push(what_it_cost(&mut peer, Joining::Weight, 0, 100 + round));
        thread::sleep(Duration::from_millis(1_600));
        // Inside what the wire allows and far past the end of any answer.
        absent.push(what_it_cost(
            &mut peer,
            Joining::Weight,
            50_000,
            200 + round,
        ));
    }
    let real = middle(real);
    let absent = middle(absent);

    node.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        absent < real,
        "a part that is not in the answer cost {absent:?}, where handing over a \
         part that is cost {real:?}. Asking for nothing must not cost more than \
         asking for something: the answer is built again on every one of them."
    );
}

/// What one `GetJoin` cost this node, timed from the outside.
///
/// A ping is put behind the question on the same connection. One connection is
/// read in order, so the pong cannot be written until whatever the question
/// cost has been paid, and this works for a question the node answers with
/// silence, which is what a part that is not in the answer gets.
fn what_it_cost(peer: &mut TcpStream, what: Joining, part: u32, nonce: u64) -> Duration {
    write_message(peer, params().network, &Message::GetJoin { what, part }).unwrap();
    write_message(peer, params().network, &Message::Ping(nonce)).unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(60);
    while Instant::now() < deadline {
        match read_message(peer, params().network) {
            Ok(Incoming::Message(Message::Pong(seen))) if seen == nonce => {
                return started.elapsed()
            }
            Ok(_) => {}
            Err(error) => panic!("the connection failed: {error}"),
        }
    }
    panic!("the node never answered the ping behind the question");
}

fn middle(mut of: Vec<Duration>) -> Duration {
    of.sort_unstable();
    of[of.len() / 2]
}

/// **A stranger naming addresses that do not answer stopped the round of upkeep
/// that everything else runs on.**
///
/// AUDIT, repaired. `dial_from_book` calls `TcpStream::connect_timeout`, which
/// blocks, up to `TARGET_PEERS` times, on the one thread that also drives the
/// choice a node with no chain is making, the turn to fill its old headers in,
/// the join it is waiting on and the ledger it is on probation for. An address
/// routed nowhere holds a dial for the whole of the dial timeout.
///
/// So one `Peers` message, charged a single unit of a peer's allowance, took a
/// round of upkeep from just over a second to twenty five: measured as one
/// round completed in forty seconds where an idle node completed eight in ten.
/// The addresses cost nothing to invent, and a node reaches the dead only when
/// it has not found enough live peers yet, which is exactly the node whose
/// chooser can least afford to run once every twenty five seconds.
///
/// A round now spends a bounded amount of time dialling and goes back to the
/// rest of its work.
#[test]
fn a_book_of_addresses_that_do_not_answer_does_not_stop_upkeep() {
    let directory = scratch("dialstall");
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();

    let mut peer = TcpStream::connect(node.address()).unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    write_message(&mut peer, params().network, &hello(777_777)).unwrap();

    // What an idle node's round costs, as the baseline this is measured
    // against. One `GetPeers` goes out per round, so counting them counts
    // rounds.
    let idle = rounds_seen(&mut peer, Duration::from_secs(10));

    // Everything a peer is allowed to name in one answer, twice over, all of it
    // in ranges reserved for documentation so that a dial hangs rather than
    // being refused.
    for _ in 0..2 {
        write_message(&mut peer, params().network, &Message::Peers(nowhere(64))).unwrap();
    }

    let watched = Duration::from_secs(40);
    let fed = rounds_seen(&mut peer, watched);
    let known = node.known_addresses().len();

    node.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        known >= 32,
        "only {known} of the named addresses went into the book, so this test \
         never put a full book of the dead to the node"
    );
    assert!(
        idle >= 4,
        "an idle node only completed {idle} rounds in ten seconds, so the \
         baseline this compares against is not a baseline"
    );
    assert!(
        fed >= 4,
        "with {known} addresses that do not answer in its book, the node \
         completed {fed} rounds of upkeep in {watched:?}, against {idle} in ten \
         seconds when its book was empty. Dialling blocks the one loop that \
         also drives the chooser, the header turn and the undertaking."
    );
}

/// Addresses in the ranges reserved for documentation, which nothing routes to,
/// so a dial to one hangs until it is given up on rather than being refused.
///
/// Spread across neighbourhoods, because the book keeps only `MAX_PER_GROUP`
/// from any one of them and the point here is a full book.
fn nowhere(count: usize) -> Vec<PeerAddress> {
    (0..count)
        .map(|index| {
            let group = u8::try_from(index / 24).unwrap_or(0);
            let within = u8::try_from(index % 24).unwrap_or(0) + 1;
            PeerAddress(SocketAddr::from((
                Ipv4Addr::new(198, 51 + group, 100, within),
                9_333,
            )))
        })
        .collect()
}

/// Rounds of upkeep this node completed over `over`.
///
/// Counted from the outside by the `GetPeers` it broadcasts, which is one per
/// round, so this measures the loop rather than anything this test does.
fn rounds_seen(peer: &mut TcpStream, over: Duration) -> usize {
    let mut rounds = 0usize;
    let deadline = Instant::now() + over;
    while Instant::now() < deadline {
        match read_message(peer, params().network) {
            Ok(Incoming::Message(Message::GetPeers)) => rounds += 1,
            Ok(_) => {}
            Err(_) => return rounds,
        }
    }
    rounds
}

/// **The node does not stop itself every time it writes its own ledger down.**
///
/// AUDIT, repaired. The same shape as the join answer and nobody had to ask
/// for it. Once the block log passed the operator's budget, every round of
/// upkeep called `trim_history`, which called `write_ledger`, which called
/// `own_ledger`: the chain and the log, both held, across a burial's worth of
/// headers read off the disk, a forest proof read off it as well, and several
/// megabytes encoded and written out. That was once a second, on the
/// maintenance thread, for as long as the node was over its budget, and it
/// held the chain for the whole of it.
///
/// Two things were wrong and this asserts both. The reading and the writing
/// now happen with the chain let go of, and the answer is not built again
/// while the tip it stands for has not moved: a node writes its ledger once a
/// block instead of once a second.
///
/// One hold on the chain is left and cannot be moved: `ChainStore::ledger_at`
/// unwinds the ledger a burial deep, and what undoes a block is held in the
/// chain and nowhere else. So the assertion is not that nothing ever holds the
/// chain, which would be a lie, but that writing the ledger costs one hold per
/// tip rather than one per call.
///
/// The second burst says so through the file rather than through the clock. A
/// wait on the chain lock is the wrong instrument for the second question: on
/// a loaded machine a scheduler can hold a thread off the processor for as
/// long as this build takes, and the two are not worth telling apart by
/// length. The file is not ambiguous. It is only ever written when the ledger
/// has been built, so a modification time that has not moved across two
/// seconds of writing as fast as the node can is the whole of the claim.
#[test]
fn writing_the_ledger_does_not_stop_the_node_once_a_second() {
    // The real burial rather than the shallow one the rest of these tests
    // use: what the build reads is a burial's worth of headers, so a shallow
    // one measures nothing.
    let params = ConsensusParams::testnet();
    let directory = scratch("ledgerstall");
    let (node, _) = Node::open_archiving(params, loopback(), &directory).unwrap();
    let mut forge = Forge::new(params);
    for block in forge.mine_many(params.burial as usize + 200) {
        node.submit_block(block).unwrap();
    }
    let node = Arc::new(node);

    let quiet = worst_chain_wait(&node, Duration::from_millis(400));

    let running = Arc::new(AtomicBool::new(true));
    let writer = {
        let (node, running) = (Arc::clone(&node), Arc::clone(&running));
        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let _ = node.write_ledger();
            }
        })
    };
    // Generous against a busy machine, and far above anything `Node::height`
    // costs: it takes the chain and makes one comparison.
    let long = Duration::from_millis(20);
    let ledger = directory.join(cairn_store::HANDED_LEDGER);
    let first = long_waits_on_the_chain(&node, Duration::from_secs(2), long);
    let once = written_at(&ledger);
    let again = long_waits_on_the_chain(&node, Duration::from_secs(2), long);
    let twice = written_at(&ledger);
    running.store(false, Ordering::SeqCst);
    let _ = writer.join();
    println!(
        "worst wait on the chain lock {quiet:?} idle. While the ledger is written as fast \
         as it can be: {first:?} over {long:?} in the first two seconds, {again:?} in the \
         two after that. Written at {once:?}, then {twice:?}"
    );

    node.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        once.is_some(),
        "the ledger should have been written at least once, and there is no file"
    );
    assert_eq!(
        once, twice,
        "the ledger was written again for a tip it had already been written for. That is \
         the several megabytes a second the maintenance thread used to pay for the rest \
         of the node's life."
    );
    // One is the build this tip needed. A machine busy enough can add a wait
    // of the same length that is not a build at all, which is why the count
    // has room in it and the claim above rests on the file instead.
    assert!(
        first.len() <= 2,
        "writing this node's own ledger stopped everybody else {} times in two seconds \
         ({first:?}), against {quiet:?} when it was not being written. Upkeep asks for \
         this every round on any node past its disk budget, and every round used to \
         build it again.",
        first.len(),
    );
}

/// When a file was last written, for asking whether it was written again.
fn written_at(path: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path)
        .and_then(|found| found.modified())
        .ok()
}

/// **A node that stopped itself still lets go of everything.**
///
/// AUDIT, repaired. Two things clear `running` from inside: a block from a
/// height this build has no rules for, and a handed ledger whose burial nobody
/// delivers. `shutdown` started with `running.swap(false)` and returned when
/// it was already false, so after either of those it did none of what it says
/// it does: no connection closed, no thread joined, the address book unsaved,
/// and the directory lock alive inside whatever peer thread was still blocked
/// in a read.
///
/// The reader had no way to tell. `shutdown` returned, `Drop` returned, and
/// the node looked stopped. What decides whether the winding down has already
/// happened is now a flag of its own, so clearing `running` from inside says
/// only that the node has stopped working, which is all it ever meant.
#[test]
fn a_node_that_stopped_itself_lets_go_of_its_directory() {
    // The disk a node has the instant a handover lands: the ledger it was
    // handed and not one block above it.
    let (directory, handover) = directory_holding_a_handover("selfstop");
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    node.wait_for_the_burial(0);
    assert!(node.probation().is_some(), "it is holding a handed ledger");

    // Somebody to ask, who has nothing to give, which is what turns waiting
    // into being stranded.
    let bystander = Node::bind(params(), loopback()).unwrap();
    node.connect(bystander.address()).unwrap();
    wait_for(
        "the node to say it is stranded",
        Duration::from_secs(20),
        || node.stranded().is_some(),
    );
    drop(handover);

    let started = Instant::now();
    node.shutdown();
    drop(node);
    let stopping = started.elapsed();

    // If shutdown did what it says, every thread has been joined and the last
    // `Arc<Shared>` is gone with them, so the lock is free.
    let at_once = Node::open(params(), loopback(), &directory);
    let taken = at_once.is_ok();
    drop(at_once);

    // And if it did not, how long the threads nobody joined go on holding it.
    let mut lingered = None;
    if !taken {
        let began = Instant::now();
        let deadline = began + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok((late, _)) = Node::open(params(), loopback(), &directory) {
                lingered = Some(began.elapsed());
                late.shutdown();
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
    bystander.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        taken,
        "shutdown returned in {stopping:?} and the node was dropped, and the directory \
         was still locked by threads nobody joined. It came free {lingered:?} later, \
         which was those threads reaching the end of a blocking read on their own."
    );
}

/// A peer that opens a frame and then feeds it one byte at a time, slowly
/// enough to be nearly idle and quickly enough that the read deadline never
/// passes.
///
/// `fill` carried the deadline per `read` call rather than per frame, so every
/// byte reset it. The read loop only looked at `running`, at the flood count
/// and at the silence deadline between frames, and this peer is never between
/// frames. What that did to a healthy node's connection slots is asserted in
/// `transport_audit.rs`; what it did to a node that had stopped itself is
/// below.
fn dribbler(address: SocketAddr, stop: &Arc<AtomicBool>) -> thread::JoinHandle<()> {
    let stop = Arc::clone(stop);
    thread::spawn(move || {
        let Ok(mut stream) = TcpStream::connect(address) else {
            return;
        };
        let mut header = Vec::new();
        params().network.as_u32().encode_to(&mut header);
        // A frame this node is willing to wait for, and will be waiting for
        // until the peer decides otherwise.
        900_000u32.encode_to(&mut header);
        use std::io::Write as _;
        if stream.write_all(&header).is_err() {
            return;
        }
        let _ = stream.flush();
        while !stop.load(Ordering::SeqCst) {
            if stream.write_all(&[0u8]).is_err() {
                return;
            }
            let _ = stream.flush();
            thread::sleep(Duration::from_millis(1_500));
        }
    })
}

/// **Shutting a healthy node down does not wait on a peer that will not close.**
///
/// The read loop can be deep inside one frame for as long as the peer keeps
/// feeding it, so stopping cannot depend on the loop noticing `running`. It
/// does not: `shutdown` shuts the socket under it, and the read fails at once.
#[test]
fn a_peer_that_will_not_close_does_not_hold_a_shutdown_up() {
    let node = Node::bind(params(), loopback()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let hand = dribbler(node.address(), &stop);
    wait_for(
        "the node to take the dribbling connection",
        Duration::from_secs(10),
        || node.peer_count() == 1,
    );
    // Well inside the frame, and well past one read deadline.
    thread::sleep(Duration::from_secs(6));

    let started = Instant::now();
    node.shutdown();
    let took = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    let _ = hand.join();

    assert!(
        took < Duration::from_secs(2),
        "shutting down waited {took:?} on a peer that was still feeding a frame"
    );
}

/// **A dribbling peer does not outlive a node that stopped itself.**
///
/// AUDIT, repaired. The same defect as above, at its worst. `shutdown` no-oped
/// after `running` was cleared from inside, so nobody shut the sockets, and
/// the read loop only tested `running` between frames. A peer that never
/// finished a frame therefore kept its thread, and that thread's `Arc<Shared>`
/// kept the directory lock, for as long as it cared to keep dribbling: at one
/// byte per read deadline over a frame this node will accept, that was weeks.
///
/// Two repairs stand behind this and either would show here. The shutdown does
/// its work whoever cleared `running`, and it shuts the socket under the read,
/// so the thread ends at once rather than when the peer allows. And a frame
/// now carries a deadline of its own, so even with nobody shutting anything
/// the dribble is given up on.
#[test]
fn a_dribbling_peer_does_not_outlive_a_node_that_stopped_itself() {
    let (directory, handover) = directory_holding_a_handover("dribble");
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    node.wait_for_the_burial(0);
    drop(handover);

    let stop = Arc::new(AtomicBool::new(false));
    let hand = dribbler(node.address(), &stop);
    wait_for(
        "the node to take the dribbling connection",
        Duration::from_secs(10),
        || node.peer_count() == 1,
    );
    wait_for(
        "the node to say it is stranded",
        Duration::from_secs(20),
        || node.stranded().is_some(),
    );

    node.shutdown();
    drop(node);
    // Twice the read deadline, which is what would have freed the thread if
    // the peer had merely gone quiet.
    thread::sleep(Duration::from_secs(11));
    let reopened = Node::open(params(), loopback(), &directory);
    let free = reopened.is_ok();
    drop(reopened);

    stop.store(true, Ordering::SeqCst);
    let _ = hand.join();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        free,
        "eleven seconds after the node stopped itself and was dropped, its directory \
         was still locked by a read thread a stranger was keeping alive"
    );
}

/// The disk a node has the instant a handover lands.
fn directory_holding_a_handover(name: &str) -> (PathBuf, Handover) {
    let miner = SecretKey::from_bytes(&[9; 32]);
    let params = params();
    let mut state = LedgerState::archiving();
    let mut past = Vec::new();
    let mut headers = Vec::new();
    let mut history = cairn_accumulator::Archive::new();
    let mut clock = 1_000u64;

    for _ in 0..120 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        past.push(state.clone());
        history
            .add(cairn_ledger::state::header_leaf(&block.header.id()))
            .unwrap();
        headers.push(block.header);
    }

    let tip = *headers.last().unwrap();
    let anchor_height = tip.height - BURIAL;
    let at = headers[anchor_height as usize];
    let anchor = history.prove_in(anchor_height, tip.height).unwrap();
    let from = anchor_height.saturating_sub(90) as usize;
    let recent = headers[from..=anchor_height as usize].to_vec();
    let handover = past[anchor_height as usize]
        .handover(
            at,
            tip,
            state.headers_before_tip(),
            anchor,
            headers[(anchor_height as usize + 1)..].to_vec(),
            recent,
        )
        .unwrap();

    let directory = scratch(name);
    std::fs::write(
        directory.join(cairn_store::HANDED_LEDGER),
        handover.encode(),
    )
    .unwrap();
    (directory, handover)
}

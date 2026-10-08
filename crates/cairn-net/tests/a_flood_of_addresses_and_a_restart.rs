//! A node fed addresses by a stranger, and then restarted.
//!
//! Red team scenario R9 of the testnet-8 attack catalogue (D02, D03, D04,
//! D15). Heilman's eclipse: fill a node's book with your own addresses, take
//! the outbound slots it has free, and wait for a restart, when it refills
//! all of them from the book. The catalogue passes the scenario if the victim
//! keeps at least two honest outbound connections at all times and at least
//! its anchors after a restart.
//!
//! The lab is one machine, and the loopback is one neighbourhood to the book
//! and exempt from every rule that counts by machine. So the honest nodes sit
//! on `[::1]` and the stranger on `127.0.0.1`, which are the two
//! neighbourhoods a loopback has, and the neighbourhood rules can be watched
//! at work between them. The victim introduces itself without a port, as a
//! wallet does: three honest nodes are each short of peers and would dial it
//! back, which on the real network they would not, and a connection they
//! opened would stand in for one the victim chose.
//!
//! What holds, measured: a flood of thousands of addresses through `Peers`
//! and an inbound greeting from every stranger listener take no honest
//! outbound slot, the stranger gets only the slots honest addresses left
//! free, the book keeps the stranger's neighbourhood to `MAX_PER_GROUP` and
//! every honest address it heard from, the honest chain still arrives, and a
//! clean restart dials every anchor again. Measured: four thousand four
//! hundred and eighty addresses in twelve seconds beside twelve inbound
//! connections, and the stranger's share of the book stood at thirty two.
//!
//! **What did not hold was the restart that actually happens.** Anchors were
//! written by `Node::shutdown` and nowhere else. `cairnd` installs no signal
//! handler, so a node stopped by systemd or by Ctrl-C is killed and never runs
//! it, and `deploy/cairnd.service` says as much: "a node killed outright
//! releases it as it dies". What a killed node left on disk was the book as
//! upkeep last saved it, ordered by when each address last answered a dial,
//! and the honest peers a node has held for an hour answered an hour ago.
//! Any address answered since is ahead of them: the stranger's own slots,
//! every feeler the node sends, one every two minutes into a book the
//! stranger has filled, and every redial after a stranger hangs up. Below,
//! the stranger hangs up and turns each redial away once, which takes
//! seconds. Without that, measured once while writing this, two minutes of
//! feelers did the same and the restart below came out the same; a node
//! whose eight slots were all honest would take sixteen. The node is then
//! started from a copy of what its directory holds of its peers, taken while
//! it ran, which is what a kill leaves, and of its three honest anchors it
//! dialled one: the one the neighbourhood rule puts in the first wave. With
//! the stranger spread over eight neighbourhoods the same rule would hand it
//! all eight.
//!
//! The anchors are now written to a file of their own whenever the peers a
//! node went out to change, and a start dials them before the book's order:
//! the same restart dials all three. See `node::keep_anchors`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Address, Note};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::book::{ANCHOR_FILE, MAX_PER_GROUP, PEER_FILE};
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::node::TARGET_PEERS;
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::{Keeps, Node, PeerAddress};
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A liveness bound, not a measurement: it costs nothing when the condition
/// is met, and the only thing a short one buys is a failure that says
/// nothing about the code.
const PATIENCE: Duration = Duration::from_secs(180);

/// How long the counts of who holds the victim's outbound slots must stay
/// put before they are read. Every slot is filled within a round or two of
/// upkeep, a second each, so this is several rounds with nothing moving.
const SETTLED: Duration = Duration::from_secs(3);

const HONEST: usize = 3;

/// Listeners the stranger holds. Fewer than one neighbourhood of the book
/// holds, so the book's ceiling is not what decides which are known.
const LISTENERS: usize = 24;

/// Addresses the stranger hands over in one `Peers`, the most one may carry.
const PER_ANSWER: u16 = 64;

/// Stranger addresses that must answer a dial after the honest anchors did.
/// A restart from the book can give the stranger seven slots, every one but
/// the slot the honest neighbourhood is owed; one more than that is margin.
const AHEAD_OF_THE_ANCHORS: usize = TARGET_PEERS;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn here_v4() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn here_v6() -> SocketAddr {
    SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
}

fn owner() -> Address {
    Address::from(SecretKey::from_bytes(&[9; 32]).public_key())
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-flood-and-restart-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
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

fn mine_chain(count: usize) -> Vec<Block> {
    let params = params();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            block
        })
        .collect()
}

fn handshake(listen: u16, nonce: u64) -> Handshake {
    Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen,
        nonce,
        keeps: Keeps::default(),
    }
}

/// Three honest nodes on the IPv6 loopback, each dialled to the first.
fn honest_nodes(blocks: &[Block]) -> Vec<Node> {
    let nodes: Vec<Node> = (0..HONEST)
        .map(|_| Node::bind(params(), here_v6()).unwrap())
        .collect();
    for block in blocks {
        nodes[0].submit_block(block.clone()).unwrap();
    }
    for node in &nodes[1..] {
        node.connect(nodes[0].address()).unwrap();
    }
    nodes
}

/// What the stranger's listeners share.
#[derive(Default)]
struct Lab {
    stopped: AtomicBool,
    /// Whether each listener answers one dial, hangs up, and turns every
    /// later dial away before a word.
    churning: AtomicBool,
    /// Whether a request for addresses is answered with a full list of fresh
    /// ones rather than none.
    flooding: AtomicBool,
    /// Connections the victim dialled to a listener and was answered on.
    holding: AtomicUsize,
    /// Listeners that answered a dial while churning.
    spent: Mutex<HashSet<u16>>,
    /// When a connection answered while churning last opened or closed.
    churned_at: Mutex<Option<Instant>>,
    /// Addresses handed to the victim, and the next port to name.
    flooded: AtomicU64,
    next_port: AtomicU64,
    held: Mutex<Vec<TcpStream>>,
}

struct Stranger {
    listeners: Vec<SocketAddr>,
    lab: Arc<Lab>,
}

impl Stranger {
    fn start() -> Self {
        let lab = Arc::new(Lab {
            next_port: AtomicU64::new(40_000),
            ..Lab::default()
        });
        let listeners = (0..LISTENERS)
            .map(|_| {
                let listener = TcpListener::bind(here_v4()).unwrap();
                listener.set_nonblocking(true).unwrap();
                let address = listener.local_addr().unwrap();
                let lab = Arc::clone(&lab);
                thread::spawn(move || {
                    while !lab.stopped.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((socket, _)) => {
                                let lab = Arc::clone(&lab);
                                thread::spawn(move || answer(socket, address.port(), &lab));
                            }
                            Err(_) => thread::sleep(Duration::from_millis(5)),
                        }
                    }
                });
                address
            })
            .collect();
        Self { listeners, lab }
    }

    /// Every listener dials the victim and introduces itself with its own
    /// port, which is how an address gets into a book without anybody
    /// having been asked: the socket's door. The first `leaving` hang up
    /// again; the rest stay, as inbound peers of the victim, and are not
    /// dialled while they do, since the victim counts a peer that named an
    /// address as connected at it.
    fn greet(&self, victim: SocketAddr, leaving: usize) -> Vec<TcpStream> {
        let network = params().network;
        let mut kept = Vec::new();
        for (at, listener) in self.listeners.iter().enumerate() {
            let mut socket = TcpStream::connect(victim).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let hello = Message::Hello(handshake(listener.port(), 0x5eed_0000 + at as u64));
            write_message(&mut socket, network, &hello).unwrap();
            let welcomed = matches!(
                read_message(&mut socket, network, MAX_FRAME_BYTES),
                Ok(Incoming::Message(Message::Welcome(_)))
            );
            assert!(welcomed, "the victim took listener {at}'s greeting");
            if at < leaving {
                let _ = socket.shutdown(Shutdown::Both);
            } else {
                kept.push(socket);
            }
        }
        kept
    }

    fn holding(&self) -> usize {
        self.lab.holding.load(Ordering::SeqCst)
    }

    fn hang_up(&self) {
        for socket in self.lab.held.lock().unwrap().drain(..) {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    fn spent(&self) -> usize {
        self.lab.spent.lock().unwrap().len()
    }

    /// Whether no connection answered while churning has opened or closed
    /// for long enough that the victim's count of the peers it reached
    /// holds none of them: a second covers the victim noticing a hang-up.
    fn churn_is_quiet(&self) -> bool {
        self.lab
            .churned_at
            .lock()
            .unwrap()
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
    }
}

impl Drop for Stranger {
    fn drop(&mut self) {
        self.lab.stopped.store(true, Ordering::SeqCst);
        self.hang_up();
    }
}

/// One connection the victim opened to a listener.
fn answer(mut socket: TcpStream, port: u16, lab: &Lab) {
    let network = params().network;
    socket.set_nonblocking(false).unwrap();
    let churning = lab.churning.load(Ordering::SeqCst);
    if churning && lab.spent.lock().unwrap().contains(&port) {
        // Taken and shut before a word, which the victim books as turned
        // away and leaves alone for a minute.
        let _ = socket.shutdown(Shutdown::Both);
        return;
    }
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match read_message(&mut socket, network, MAX_FRAME_BYTES) {
            Ok(Incoming::Message(Message::Hello(_))) => break,
            Ok(_) if Instant::now() < deadline => {}
            _ => return,
        }
    }
    if write_message(
        &mut socket,
        network,
        &Message::Welcome(handshake(port, u64::from(port))),
    )
    .is_err()
    {
        return;
    }
    if churning {
        // Answered, so the victim marks the address heard from now; then
        // gone, so the victim dials again.
        lab.spent.lock().unwrap().insert(port);
        *lab.churned_at.lock().unwrap() = Some(Instant::now());
        thread::sleep(Duration::from_millis(500));
        let _ = socket.shutdown(Shutdown::Both);
        *lab.churned_at.lock().unwrap() = Some(Instant::now());
        return;
    }
    lab.holding.fetch_add(1, Ordering::SeqCst);
    lab.held.lock().unwrap().push(socket.try_clone().unwrap());
    while !lab.stopped.load(Ordering::SeqCst) {
        let reply = match read_message(&mut socket, network, MAX_FRAME_BYTES) {
            Ok(Incoming::Message(Message::GetPeers)) => {
                if lab.flooding.load(Ordering::SeqCst) {
                    let first = lab
                        .next_port
                        .fetch_add(u64::from(PER_ANSWER), Ordering::SeqCst);
                    let fresh: Vec<PeerAddress> = (0..u64::from(PER_ANSWER))
                        .map(|step| {
                            let port = 10_000 + (first + step) % 50_000;
                            PeerAddress(SocketAddr::from((
                                Ipv4Addr::LOCALHOST,
                                u16::try_from(port).unwrap(),
                            )))
                        })
                        .collect();
                    lab.flooded
                        .fetch_add(u64::from(PER_ANSWER), Ordering::SeqCst);
                    Some(Message::Peers(fresh))
                } else {
                    Some(Message::Peers(Vec::new()))
                }
            }
            Ok(Incoming::Message(Message::Ping(nonce))) => Some(Message::Pong(nonce)),
            Ok(_) => None,
            Err(_) => break,
        };
        if let Some(reply) = reply {
            if write_message(&mut socket, network, &reply).is_err() {
                break;
            }
        }
    }
    lab.holding.fetch_sub(1, Ordering::SeqCst);
}

/// The counts the readings below are taken from: the victim's outbound
/// peers, the connections it dialled that the stranger holds, and every peer
/// that has introduced itself to the victim, whoever opened the connection.
fn counts(victim: &Node, stranger: &Stranger) -> (usize, usize, usize) {
    (
        victim.peers_reached(),
        stranger.holding(),
        victim.peers_introduced(),
    )
}

/// Whether no feeler of the victim's is open, given the `inbound`
/// connections the stranger holds into it.
///
/// A feeler is a connection the stranger holds and the victim does not count
/// among its outbound peers, so while one is open the stranger's count reads
/// one honest peer short. The victim counts it among the peers that
/// introduced themselves, and nothing else is there to count: the honest
/// nodes never dial the victim, which names no port.
fn no_feeler_open(counts: (usize, usize, usize), inbound: usize) -> bool {
    let (reached, _, introduced) = counts;
    introduced == reached + inbound
}

/// Who holds the victim's outbound slots: honest nodes, and the stranger.
///
/// Read once the victim holds all [`TARGET_PEERS`] of them, no feeler of its
/// is open, and none of the counts has moved for [`SETTLED`]. Every caller
/// expects all of them held, so the first two say when to read and not what
/// is read. They were not asked, and both bit on a slow runner. Windows
/// takes about two seconds to refuse a dial on the loopback, so a round of
/// dials into the dead addresses the stranger hands over held the counts
/// still for longer than `SETTLED` while the victim was still filling its
/// slots: windows-latest read three honest and two stranger before the
/// stranger had the other three. And macos-latest once read two honest and
/// six stranger after a clean restart, and three and five on the run after,
/// which is what one feeler left open looks like.
fn outbound(victim: &Node, stranger: &Stranger, inbound: usize) -> (usize, usize) {
    let mut last = (usize::MAX, usize::MAX, usize::MAX);
    let mut since = Instant::now();
    let settled = wait_until(PATIENCE, || {
        let now = counts(victim, stranger);
        if now != last {
            last = now;
            since = Instant::now();
        }
        since.elapsed() >= SETTLED
            && now.0 == TARGET_PEERS
            && no_feeler_open(now, inbound)
            && now.0 >= now.1
    });
    assert!(
        settled,
        "the victim's outbound connections never settled: {last:?} outbound, held by the \
         stranger, introduced"
    );
    (last.0 - last.1, last.1)
}

/// The honest nodes' addresses as the victim's book holds them.
fn honest_in_book(victim: &Node, honest: &[Node]) -> usize {
    let known = victim.known_addresses();
    honest
        .iter()
        .filter(|node| known.contains(&node.address()))
        .count()
}

/// The honest nodes the file of anchors in `directory` names, which is what a
/// start dials before the book's order.
fn honest_anchored(directory: &Path, honest: &[Node]) -> usize {
    let written = std::fs::read_to_string(directory.join(ANCHOR_FILE)).unwrap_or_default();
    let anchors: HashSet<SocketAddr> = written
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect();
    honest
        .iter()
        .filter(|node| anchors.contains(&node.address()))
        .count()
}

/// The victim dials the first honest node, learns the other two from it and
/// dials them, and only then does the stranger arrive: every honest address
/// in the book answered a dial before any of the stranger's.
fn victim_beside_honest_nodes(directory: &Path, honest: &[Node]) -> Node {
    let (victim, _) = Node::open_watching(params(), here_v4(), directory, &[owner()]).unwrap();
    victim.connect(honest[0].address()).unwrap();
    assert!(
        wait_until(PATIENCE, || victim.peers_reached() == HONEST),
        "the victim reached every honest node"
    );
    // The book keeps when an address answered in whole seconds, so the
    // stranger's first answer has to fall in a later one.
    thread::sleep(Duration::from_millis(1_100));
    victim
}

/// **A flood of addresses takes no honest outbound slot, and a clean restart
/// dials every anchor again.**
#[test]
fn a_flood_of_addresses_takes_no_honest_slot_and_a_clean_restart_redials_every_anchor() {
    let chain = mine_chain(3);
    let honest = honest_nodes(&chain);
    let directory = scratch("clean");
    let victim = victim_beside_honest_nodes(&directory, &honest);
    assert!(
        wait_until(PATIENCE, || victim.height() == Some(2)),
        "the victim read the honest chain"
    );

    let stranger = Stranger::start();
    stranger.lab.flooding.store(true, Ordering::SeqCst);
    let inbound = stranger.greet(victim.address(), LISTENERS / 2);
    let (honest_out, stranger_out) = outbound(&victim, &stranger, inbound.len());
    assert_eq!(
        (honest_out, stranger_out),
        (HONEST, TARGET_PEERS - HONEST),
        "the stranger took the free outbound slots and nothing else"
    );

    // The flood runs while the slots are watched. Nothing about it is
    // misbehaviour: each list answers a request and is paid for.
    // Read only once the counts have stood still for `SETTLED` with no
    // feeler open: a feeler the victim sends is a connection the stranger
    // holds and the victim does not count, and would read as an honest peer
    // lost. Standing still was the only condition, and a feeler left open
    // longer than that on a slow runner is still a feeler.
    let mut fewest_honest = HONEST;
    let mut readings = 0usize;
    let mut last = (usize::MAX, usize::MAX, usize::MAX);
    let mut since = Instant::now();
    let flooding_until = Instant::now() + Duration::from_secs(12);
    while Instant::now() < flooding_until {
        let now = counts(&victim, &stranger);
        if now != last {
            last = now;
            since = Instant::now();
        } else if since.elapsed() >= SETTLED && no_feeler_open(now, inbound.len()) {
            fewest_honest = fewest_honest.min(now.0.saturating_sub(now.1));
            readings += 1;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        readings > 0,
        "the counts never stood still during the flood"
    );
    let flooded = stranger.lab.flooded.load(Ordering::SeqCst);
    let known = victim.known_addresses();
    let in_the_strangers_neighbourhood = known
        .iter()
        .filter(|address| address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .count();
    println!(
        "flood: {flooded} addresses handed over, {} inbound held by the stranger; the victim \
         knows {} addresses, {in_the_strangers_neighbourhood} of them the stranger's; fewest \
         honest outbound seen: {fewest_honest}",
        inbound.len(),
        known.len()
    );
    assert!(flooded >= 1_000, "the fixture: the flood was a flood");
    assert!(
        fewest_honest >= HONEST,
        "an honest outbound connection was lost during the flood: {fewest_honest} left"
    );
    assert!(
        in_the_strangers_neighbourhood <= MAX_PER_GROUP,
        "the stranger's neighbourhood holds {in_the_strangers_neighbourhood} addresses of the \
         victim's book, past the {MAX_PER_GROUP} one neighbourhood may hold"
    );
    assert_eq!(
        honest_in_book(&victim, &honest),
        HONEST,
        "the flood pushed an honest address that answered out of the book"
    );

    // The honest chain still arrives, from the honest outbound peers.
    let next = {
        let mut longer = mine_chain(4);
        longer.pop().unwrap()
    };
    honest[2].submit_block(next.clone()).unwrap();
    assert!(
        wait_until(PATIENCE, || victim.id_at(3) == Some(next.id())),
        "the honest block reached the victim during the flood"
    );

    // What the restart below dials first is the file, so it is asked as well
    // as the slots: written as the outbound peers change, it names the three
    // honest peers the victim has held all along.
    assert!(
        wait_until(PATIENCE, || honest_anchored(&directory, &honest) == HONEST),
        "the anchors on the victim's disk name {} of its {HONEST} honest outbound peers",
        honest_anchored(&directory, &honest)
    );

    // A clean restart: the node is asked to stop, writes its anchors, and is
    // started again on the same directory.
    drop(inbound);
    victim.shutdown();
    drop(victim);
    assert!(
        wait_until(PATIENCE, || stranger.holding() == 0),
        "the stranger saw the victim go"
    );
    let (restarted, _) = Node::open_watching(params(), here_v4(), &directory, &[owner()]).unwrap();
    let (honest_out, stranger_out) = outbound(&restarted, &stranger, 0);
    println!("after a clean restart: {honest_out} honest and {stranger_out} stranger outbound");
    assert_eq!(
        honest_out, HONEST,
        "a clean restart did not dial every honest anchor again"
    );
    assert_eq!(
        honest_anchored(&directory, &honest),
        HONEST,
        "the restarted victim wrote over its anchors without the honest peers it holds"
    );
    assert!(
        wait_until(PATIENCE, || restarted.id_at(3) == Some(next.id())),
        "the restarted victim follows the honest chain"
    );

    restarted.shutdown();
    for node in &honest {
        node.shutdown();
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// **A restart from what a killed node leaves on disk dials every anchor
/// again.**
///
/// It did not. The victim holds its three honest peers and gives the
/// stranger the five slots left. The stranger then hangs up, answers each
/// redial of an address it has used with a connection shut before a word,
/// and answers the dial of every address it has not used yet, once, until
/// eight of its addresses have answered the victim after the honest ones
/// did. The honest connections are never touched.
///
/// The book and the anchors beside it are copied while the victim runs,
/// which is what a kill leaves of its peers, and a node is started on the
/// copy. One honest anchor was dialled, because the first wave takes one
/// address from every neighbourhood the node holds nothing in and the honest
/// nodes are a neighbourhood of their own; that much of the rule held and is
/// asserted first. The other two were not dialled at all, since the stranger
/// filled the other seven slots and a node holding eight outbound peers dials
/// nobody else but its feelers, and a feeler only goes to an address never
/// heard from.
///
/// The repair this was written beside was in `cairnd`: stop on SIGTERM and
/// SIGINT so `Node::shutdown` runs, as Bitcoin does. A crash, an out-of-memory
/// kill or a power cut would still skip it, so the anchors are written when
/// the set of outbound peers changes instead, and dialled first at a start:
/// three honest and five stranger outbound, of three honest anchors.
#[test]
fn a_restart_from_what_a_killed_node_leaves_on_disk_redials_its_anchors() {
    let honest = honest_nodes(&[]);
    let directory = scratch("killed");
    let victim = victim_beside_honest_nodes(&directory, &honest);

    let stranger = Stranger::start();
    let _ = stranger.greet(victim.address(), LISTENERS);
    let (honest_out, stranger_out) = outbound(&victim, &stranger, 0);
    assert_eq!(
        (honest_out, stranger_out),
        (HONEST, TARGET_PEERS - HONEST),
        "the fixture: the stranger took the free outbound slots"
    );

    stranger.lab.churning.store(true, Ordering::SeqCst);
    stranger.hang_up();
    // The stranger holds nothing while it churns, so between its brief
    // connections every peer the victim reached is honest.
    let mut fewest_honest = HONEST;
    let churned = wait_until(PATIENCE, || {
        if stranger.churn_is_quiet() && stranger.holding() == 0 {
            fewest_honest = fewest_honest.min(victim.peers_reached());
        }
        stranger.spent() >= AHEAD_OF_THE_ANCHORS
    });
    assert!(
        churned,
        "the victim dialled {} of the stranger's addresses",
        stranger.spent()
    );
    println!(
        "{} stranger addresses answered the victim after its honest anchors; fewest honest \
         outbound meanwhile: {fewest_honest}",
        stranger.spent()
    );
    assert!(
        fewest_honest >= HONEST,
        "an honest outbound connection was lost while the stranger churned"
    );

    // Upkeep writes the book once a round when it has changed, and the
    // anchors beside it when they have: two rounds, and the copy is what a
    // kill at this moment would leave of the node's peers.
    thread::sleep(Duration::from_millis(2_100));
    let killed = scratch("killed-copy");
    for file in [PEER_FILE, ANCHOR_FILE] {
        std::fs::copy(directory.join(file), killed.join(file)).unwrap();
    }
    victim.shutdown();
    drop(victim);
    stranger.lab.churning.store(false, Ordering::SeqCst);
    stranger.lab.spent.lock().unwrap().clear();
    assert!(
        wait_until(PATIENCE, || stranger.holding() == 0),
        "the stranger saw the victim go"
    );

    let (restarted, _) = Node::open_watching(params(), here_v4(), &killed, &[owner()]).unwrap();
    let (honest_out, stranger_out) = outbound(&restarted, &stranger, 0);
    println!(
        "after a restart from the copy: {honest_out} honest and {stranger_out} stranger \
         outbound, of {HONEST} honest anchors"
    );
    assert!(
        honest_out >= 1,
        "the first wave took nobody from the honest neighbourhood: the rule that a round \
         dials one address from every neighbourhood it holds nothing in did not hold"
    );
    assert_eq!(
        honest_out, HONEST,
        "after a restart from what a killed node leaves on disk, the victim dialled \
         {honest_out} of its {HONEST} honest anchors and gave the stranger {stranger_out} \
         of its {TARGET_PEERS} outbound slots. Anchors are written as the outbound peers \
         change and dialled first at a start, and one of the two did not happen"
    );

    restarted.shutdown();
    for node in &honest {
        node.shutdown();
    }
    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&killed);
}

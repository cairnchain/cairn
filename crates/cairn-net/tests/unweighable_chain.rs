//! A chain nobody can show, and who gets blamed for it.
//!
//! A newcomer joins by being shown what work stands behind a chain. When a
//! showing does not check out the sender loses its turn, which is right: this
//! node was handed bytes it could not use, and from one showing it cannot tell
//! a liar from an honest archivist serving a chain this build has no way to
//! weigh. Both were dropped on the floor: the decode error and the check error
//! were thrown away where they were made, and an operator watching a node take
//! hours to start saw peers being asked and dropped, with no reason anywhere.
//!
//! The second reading is not hypothetical. This build refuses a run of headers
//! longer than `cairn_ledger::sampling::MOST_TAIL`, and a chain whose
//! difficulty has fallen far below what it once ran at needs a longer one.
//! Measured over the project's own `draw` on chains a year to thirty years
//! old: a loss of twenty four to forty eight times the hash rate, depending on
//! the chain's length, makes it unweighable from about eleven days after the
//! loss until months or years after it, and every honest archivist alive then
//! fails in exactly the same words.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::Note;
use cairn_ledger::sampling::{check_start, open_start, SampledStart, StartError, SAMPLES};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Joining, Keeps, Message, JOIN_PART_BYTES, PROTOCOL_VERSION};
use cairn_net::node::{Behind, Unweighable};
use cairn_net::sync::JOIN_RATHER_THAN_READ;
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

const PATIENCE: Duration = Duration::from_secs(30);
const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Shallow burial, so the test does not mine its way through a number chosen
/// for a live network. Nothing here turns on the depth.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(8)
}

/// A chain built off to the side, so a node can be handed a real one.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine_many(&mut self, count: usize) -> Vec<Block> {
        (0..count)
            .map(|_| {
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
            })
            .collect()
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// A peer that claims a long chain, says it kept the headers, and answers the
/// weighing with bytes that are not a weighing.
///
/// Everything else it is asked is ignored, so the newcomer has no way to read
/// the chain either and keeps coming back to the showing, which is the state
/// this file is about.
struct CannotShowIt {
    address: SocketAddr,
    running: Arc<AtomicBool>,
    asked: Arc<AtomicU64>,
}

impl CannotShowIt {
    fn start(tag: u8, work: u128) -> io::Result<Self> {
        Self::start_with(tag, work, true)
    }

    /// The same, saying nothing about where it can be reached.
    ///
    /// Which is what one machine opening several connections looks like, and
    /// what nothing can tell from three peers behind one address that all
    /// decline to name a port.
    fn anonymous(tag: u8, work: u128) -> io::Result<Self> {
        Self::start_with(tag, work, false)
    }

    fn start_with(tag: u8, work: u128, name_the_port: bool) -> io::Result<Self> {
        let nonce = u64::from(tag);
        let listener = TcpListener::bind(loopback())?;
        let address = listener.local_addr()?;
        let running = Arc::new(AtomicBool::new(true));
        let asked = Arc::new(AtomicU64::new(0));
        let mine = (Arc::clone(&running), Arc::clone(&asked));
        // Named, because a peer that names no port is a peer nothing can tell
        // from the next connection off the same address, and the surface this
        // file is about counts peers. Three real ones on one loopback address
        // are three peers; three anonymous connections are one machine, and
        // that is what a fixture with `listen: 0` was modelling.
        let listen = if name_the_port { address.port() } else { 0 };
        thread::spawn(move || {
            let (running, asked) = mine;
            for stream in listener.incoming() {
                if !running.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut stream) = stream else { return };
                let network = params().network;
                stream
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .ok();
                while running.load(Ordering::SeqCst) {
                    let message = match read_message(&mut stream, network, MAX_FRAME_BYTES) {
                        Ok(Incoming::Message(message)) => message,
                        Ok(Incoming::Quiet) => continue,
                        Err(_) => break,
                    };
                    let answer = match message {
                        Message::Hello(_) => Message::Welcome(Handshake {
                            version: PROTOCOL_VERSION,
                            network,
                            genesis: Hash32::ZERO,
                            tip: Hash32::from_bytes([tag; 32]),
                            height: JOIN_RATHER_THAN_READ + 4_096,
                            total_work: work,
                            listen,
                            nonce,
                            keeps: Keeps {
                                headers: true,
                                cold_set: true,
                            },
                        }),
                        Message::GetJoin { what, .. } => {
                            asked.fetch_add(1, Ordering::SeqCst);
                            // Not a weighing, and not near being one. What a
                            // node meeting the tail ceiling gets is the same
                            // shape of answer: bytes the decoder refuses
                            // before a single check about the chain is made.
                            Message::JoinPart {
                                what,
                                at: Hash32::from_bytes([tag; 32]),
                                part: 0,
                                parts: 1,
                                bytes: vec![0xAB; 512],
                            }
                        }
                        Message::Ping(token) => Message::Pong(token),
                        _ => continue,
                    };
                    if write_message(&mut stream, network, &answer).is_err() {
                        break;
                    }
                    if matches!(answer, Message::Welcome(_)) {
                        let _ = write_message(&mut stream, network, &Message::GetPeers);
                    }
                }
            }
        });
        Ok(Self {
            address,
            running,
            asked,
        })
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.address);
    }
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("waited {PATIENCE:?} for {what}");
}

/// **A node that nobody can show a chain to now says so.**
///
/// AUDIT, repaired. `weigh_what_was_shown` read both refusals with `.ok()` and
/// threw them away, so the only thing that came of a showing that would not
/// weigh was the sender losing its turn. That is right and stays. What did not
/// exist was the other half: when several peers fail with the same words, they
/// are not what those failures have in common, and a person watching a node
/// with no chain and no explanation had nothing to go on.
#[test]
fn showings_that_all_fail_the_same_way_are_said_to_be_about_the_chain() {
    let newcomer = Node::bind(params(), loopback()).unwrap();
    assert!(
        newcomer.unweighable().is_none(),
        "a node nobody has said anything to has nothing to report"
    );

    // Three, because one peer failing is one peer and the report deliberately
    // asks for more than that. Different weights so the chooser has an order
    // to work through rather than a tie to break.
    let peers: Vec<CannotShowIt> = (0..3u8)
        .map(|index| CannotShowIt::start(70 + index, 4_000_000 - u128::from(index)).unwrap())
        .collect();
    for peer in &peers {
        newcomer.connect(peer.address).unwrap();
    }

    wait_for("the node to say nobody could show it the chain", || {
        newcomer.unweighable().is_some()
    });
    let said = newcomer.unweighable().unwrap();

    for peer in &peers {
        peer.stop();
    }
    newcomer.shutdown();

    assert!(
        said.showings >= 3,
        "three showings were needed before anything was said, and {} were counted",
        said.showings
    );
    assert!(
        said.peers >= 2,
        "one peer is one peer: {} were counted",
        said.peers
    );
    assert!(
        !said.because.is_empty(),
        "the words the refusal used are the whole point of the line"
    );
    assert!(
        peers
            .iter()
            .all(|peer| peer.asked.load(Ordering::SeqCst) > 0),
        "every one of them was asked, which is what makes this a claim about the chain"
    );
}

/// **One machine's showings are not several peers' showings.**
///
/// The line this file is about tells a person that the trouble is the chain
/// rather than a peer, and the whole of what carries that is having met it from
/// more than one peer. These were counted by connection, and a connection is
/// handed out one per socket and never reused, so one machine opening three of
/// them cleared the condition outright, for the price of three TCP handshakes
/// and no lie.
///
/// Three connections that name no port stand in for it, because that is exactly
/// what nothing can tell apart: a peer that says nothing about where it can be
/// reached is, from the outside, the same address opening another socket.
#[test]
fn showings_down_several_sockets_from_one_machine_are_one_peer() {
    let newcomer = Node::bind(params(), loopback()).unwrap();
    let peers: Vec<CannotShowIt> = (0..3u8)
        .map(|index| CannotShowIt::anonymous(90 + index, 4_000_000 - u128::from(index)).unwrap())
        .collect();
    for peer in &peers {
        newcomer.connect(peer.address).unwrap();
    }
    // Long enough that the showings have happened: the same wait the test
    // above passes in a few seconds.
    wait_for("every one of them to be asked", || {
        peers
            .iter()
            .all(|peer| peer.asked.load(Ordering::SeqCst) > 0)
    });
    thread::sleep(Duration::from_secs(2));

    let said = newcomer.unweighable();
    for peer in &peers {
        peer.stop();
    }
    newcomer.shutdown();

    assert!(
        said.is_none(),
        "one machine on three sockets was reported to a person as several peers \
         failing the same way, which is the whole of what the line claims: {said:?}"
    );
}

/// **And a chain arriving takes the line away again.**
///
/// The count is evidence about a node that has nothing, and nothing weighs a
/// showing once a chain is there, so the count is frozen from that moment.
/// Left ungated it would follow a working node for the rest of its life,
/// telling its owner to wait for something that had already happened, which is
/// the silence this line replaced wearing the other face.
#[test]
fn a_chain_arriving_ends_the_claim_that_nobody_could_show_one() {
    let mut forge = Forge::new();
    let blocks = forge.mine_many(usize::try_from(JOIN_RATHER_THAN_READ).unwrap() + 40);
    let top = (blocks.len() - 1) as u64;

    let directory = std::env::temp_dir().join(format!("cairn-unweighable-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let (keeper, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    for block in &blocks {
        keeper.submit_block(block.clone()).unwrap();
    }
    assert_eq!(keeper.height(), Some(top));

    let newcomer = Node::bind(params(), loopback()).unwrap();
    // Heavier than the real chain, so these are asked first and every one of
    // them fails before the node that can answer is reached.
    let peers: Vec<CannotShowIt> = (0..3u8)
        .map(|index| {
            CannotShowIt::start(80 + index, keeper.total_work() * 4 - u128::from(index)).unwrap()
        })
        .collect();
    for peer in &peers {
        newcomer.connect(peer.address).unwrap();
    }
    wait_for("the node to say nobody could show it the chain", || {
        newcomer.unweighable().is_some()
    });

    newcomer.connect(keeper.address()).unwrap();
    wait_for("the newcomer to be handed the chain", || {
        newcomer.height() == Some(top)
    });

    // Read after the chain is in, which is the whole of what is being asked:
    // three showings did fail, and the node is no longer one that has nothing.
    let after = newcomer.unweighable();
    for peer in &peers {
        peer.stop();
    }
    newcomer.shutdown();
    keeper.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        after.is_none(),
        "a node that weighed a chain went on saying nobody could show it one: {after:?}"
    );
}

/// This machine's clock, which is the one a running node reads.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A real showing of a short chain whose tip is dated an hour further past
/// this machine's clock than a node takes.
fn a_showing_dated_ahead() -> SampledStart {
    let params = params();
    let blocks = 40;
    let tip_at = unix_now() + params.max_timestamp_drift + 3_600;
    let mut forge = Forge {
        params,
        state: LedgerState::new(),
        clock: tip_at - 600 * blocks,
    };
    let headers: Vec<BlockHeader> = forge
        .mine_many(usize::try_from(blocks).unwrap())
        .iter()
        .map(|block| block.header)
        .collect();
    let tip = *headers.last().unwrap();
    assert_eq!(tip.timestamp, tip_at);

    let mut archive = Archive::new();
    for header in &headers {
        archive.add(header_leaf(&header.id()));
    }
    let start = open_start(
        &tip,
        forge.state.headers_before_tip(),
        SAMPLES,
        &params,
        |height| headers.get(usize::try_from(height).ok()?).copied(),
        |height| archive.prove_in(height, tip.height),
    )
    .expect("a chain this short can be shown");
    assert!(
        matches!(
            check_start(&start, unix_now(), &params),
            Err(StartError::TipFromTheFuture { .. })
        ),
        "the premise: this machine's clock refuses the tip"
    );
    assert!(
        check_start(&start, tip.timestamp, &params).is_ok(),
        "the premise: at the date its tip carries, the showing weighs"
    );
    start
}

/// Ten peers, each showing `start`, and a newcomer that has met them all.
///
/// Ten is more than the run of refusals a node counts before it names its
/// clock, and more than it counts before it names the chain.
fn a_newcomer_shown(start: &SampledStart) -> (Node, Vec<ShowsItEarly>) {
    let shown = start.encode();
    let newcomer = Node::bind(params(), loopback()).unwrap();
    let peers: Vec<ShowsItEarly> = (0..10u8)
        .map(|index| {
            ShowsItEarly::start(
                110 + index,
                4_000_000 - u128::from(index),
                start.tip.id(),
                &shown,
            )
        })
        .collect();
    for peer in &peers {
        newcomer.connect(peer.address).unwrap();
    }
    (newcomer, peers)
}

/// Waits until the newcomer says something about its clock or about the
/// chain, and returns both readings.
///
/// Counted rather than timed: either line appears once enough showings have
/// been refused, and which one it is is the question. The minute is a bound
/// for a node that says neither, several times what the ten showings take.
fn what_it_says(newcomer: &Node) -> (Option<Unweighable>, Option<Behind>) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline
        && newcomer.clock_behind().is_none()
        && newcomer.unweighable().is_none()
    {
        thread::sleep(Duration::from_millis(50));
    }
    (newcomer.unweighable(), newcomer.clock_behind())
}

/// A peer that claims a long chain, says it kept the headers, and answers the
/// weighing with `shown`, a real one, in as many pieces as it takes.
///
/// Everything else it is asked is ignored, as [`CannotShowIt`] ignores it.
struct ShowsItEarly {
    address: SocketAddr,
    running: Arc<AtomicBool>,
    shown: Arc<AtomicU64>,
}

impl ShowsItEarly {
    fn start(tag: u8, work: u128, tip: Hash32, shown: &[u8]) -> Self {
        let listener = TcpListener::bind(loopback()).unwrap();
        let address = listener.local_addr().unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let counted = Arc::new(AtomicU64::new(0));
        let mine = (Arc::clone(&running), Arc::clone(&counted));
        let pieces: Vec<Vec<u8>> = shown.chunks(JOIN_PART_BYTES).map(<[u8]>::to_vec).collect();
        let parts = u32::try_from(pieces.len()).unwrap();
        thread::spawn(move || {
            let (running, counted) = mine;
            for stream in listener.incoming() {
                if !running.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut stream) = stream else { return };
                let network = params().network;
                stream
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .ok();
                while running.load(Ordering::SeqCst) {
                    let message = match read_message(&mut stream, network, MAX_FRAME_BYTES) {
                        Ok(Incoming::Message(message)) => message,
                        Ok(Incoming::Quiet) => continue,
                        Err(_) => break,
                    };
                    let answer = match message {
                        Message::Hello(_) => Message::Welcome(Handshake {
                            version: PROTOCOL_VERSION,
                            network,
                            genesis: Hash32::ZERO,
                            tip,
                            height: JOIN_RATHER_THAN_READ + 4_096,
                            total_work: work,
                            listen: address.port(),
                            nonce: u64::from(tag),
                            keeps: Keeps {
                                headers: true,
                                cold_set: true,
                            },
                        }),
                        Message::GetJoin {
                            what: what @ Joining::Weight,
                            part,
                        } => {
                            let Some(piece) = pieces.get(usize::try_from(part).unwrap()) else {
                                continue;
                            };
                            if part + 1 == parts {
                                counted.fetch_add(1, Ordering::SeqCst);
                            }
                            Message::JoinPart {
                                what,
                                at: tip,
                                part,
                                parts,
                                bytes: piece.clone(),
                            }
                        }
                        Message::Ping(token) => Message::Pong(token),
                        _ => continue,
                    };
                    if write_message(&mut stream, network, &answer).is_err() {
                        break;
                    }
                }
            }
        });
        Self {
            address,
            running,
            shown: counted,
        }
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.address);
    }
}

/// **A showing that holds, from a tip dated past this node's clock, is held
/// against nobody and said to be about the clock.**
///
/// The one refusal in a weighing that two honest nodes can disagree about, and
/// the specification says a node MUST NOT hold it against the peer that
/// offered it. It went the way of every other refusal: the address paused for
/// a growing interval, and the showing counted towards telling a person that
/// peers are making chains up or that the chain cannot be weighed, while
/// nothing anywhere said the clock. Nothing asked this, so a node whose slow
/// clock refused every honest archivist, and blamed each of them for it,
/// passed.
#[test]
fn a_showing_dated_past_this_clock_is_said_to_be_about_the_clock() {
    let (newcomer, peers) = a_newcomer_shown(&a_showing_dated_ahead());
    let (unweighable, behind) = what_it_says(&newcomer);
    let showings: u64 = peers
        .iter()
        .map(|peer| peer.shown.load(Ordering::SeqCst))
        .sum();
    for peer in &peers {
        peer.stop();
    }
    newcomer.shutdown();

    assert!(
        unweighable.is_none(),
        "honest showings refused for this machine's clock were reported as a chain nobody \
         can show: {unweighable:?}"
    );
    assert!(
        behind.is_some(),
        "{showings} honest showings were refused for a tip dated past this machine's clock, \
         and nothing said the clock looks behind"
    );
}

/// **A showing dated past this node's clock that would not weigh at its own
/// date either is refused for what is wrong with it, and not taken for the
/// clock.**
///
/// The date is the first thing a weighing checks, before any work, so a
/// refusal for it alone costs nothing to earn. Taking every such refusal for
/// the clock would let anybody who dates a made up showing ahead come back for
/// another turn under every fresh connection, and tell the operator the clock
/// is wrong. Nothing asked this, so a node that took any tip dated ahead for
/// its own clock, whatever the showing under it, passed.
#[test]
fn a_showing_that_fails_at_its_own_date_is_not_taken_for_the_clock() {
    let mut start = a_showing_dated_ahead();
    let tip = start.tip;
    for sibling in &mut start.samples[0].proof.siblings {
        *sibling = Hash32::ZERO;
    }
    assert!(
        matches!(
            check_start(&start, tip.timestamp, &params()),
            Err(StartError::NotInHistory { .. })
        ),
        "the premise: at the date its tip carries, the showing does not weigh"
    );
    let (newcomer, peers) = a_newcomer_shown(&start);
    let (unweighable, behind) = what_it_says(&newcomer);
    for peer in &peers {
        peer.stop();
    }
    newcomer.shutdown();

    assert!(
        behind.is_none(),
        "a showing that does not weigh at any date was taken for this machine's clock"
    );
    let unweighable = unweighable
        .expect("showings that do not weigh were not reported as a chain nobody can show");
    assert!(
        !unweighable.because.starts_with("the tip is dated"),
        "a showing that does not weigh at any date was refused for its date alone: {}",
        unweighable.because
    );
}

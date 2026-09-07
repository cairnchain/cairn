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
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, PROTOCOL_VERSION};
use cairn_net::sync::JOIN_RATHER_THAN_READ;
use cairn_net::wire::{read_message, write_message, Incoming};
use cairn_net::Node;
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
                    let message = match read_message(&mut stream, network) {
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

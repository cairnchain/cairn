//! A peer that announces every block first and never sends one.
//!
//! Red team scenario R16 of the testnet-8 attack catalogue (D07). The fear is
//! a delay attack: the peer that announces a block is the peer asked for it,
//! so a stranger that always announces first and then withholds the body
//! makes a node wait on it, and the patience a node has for a batch it asked
//! for is a minute (`BATCH_PATIENCE`) against blocks every few seconds. The
//! catalogue passes the scenario if the extra delay at the victim, against a
//! control node with no such peer, has a median under five seconds.
//!
//! What stops it is that `awaiting` belongs to one peer and not to the node.
//! An announcement from the withholder puts the height in the withholder's
//! own set and nowhere else, so when an honest peer announces the same height
//! a moment later it is asked as well, at once, and the block arrives from it.
//! Nothing anywhere says "this height is already being fetched": the asking
//! is by height, so a withholder announcing a block that does not exist
//! costs the same nothing as one announcing a real one.
//!
//! Measured on loopback: the victim takes every block within milliseconds of
//! the control, and the withholder is still owed every block it was asked for
//! when the honest copy lands.

#![allow(
    clippy::cast_precision_loss,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::Located;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::sync::BATCH_PATIENCE;
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::{Keeps, Node};
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A liveness bound, not a measurement: it costs nothing when the condition
/// is met, so it is set far past anything a loaded runner takes. This suite
/// has had failures from waits set near the work rather than far past it.
const PATIENCE: Duration = Duration::from_secs(180);

/// Blocks announced and withheld. Every other one carries an identifier that
/// names no block at all, so both kinds of announcement are measured.
const ROUNDS: u64 = 6;

/// The catalogue's pass line for the median extra delay.
const MEDIAN_EXTRA: Duration = Duration::from_secs(5);

/// The line no single block may cross. A node that waited on the withholder
/// would show the whole of `BATCH_PATIENCE` here; half of it separates the two
/// outcomes without asking a loaded runner for anything close to its limit.
fn single_extra() -> Duration {
    Duration::from_secs(BATCH_PATIENCE / 2)
}

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
        thread::sleep(Duration::from_millis(2));
    }
    ready()
}

/// Builds blocks off to the side, as `tests/network.rs` does.
struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new() -> Self {
        Self {
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self) -> Block {
        let params = params();
        let miner = SecretKey::from_bytes(&[1; 32]);
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }
}

fn welcome(listen: u16) -> Message {
    Message::Welcome(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen,
        nonce: 0x5717_4401_d00d,
        keeps: Keeps::default(),
    })
}

/// The withholder: a peer that answers its introduction and every request for
/// addresses, announces what it is told to, and never sends a block.
struct Withholder {
    address: SocketAddr,
    /// Heights the victim asked it for, and when.
    asked: Arc<Mutex<Vec<(u64, Instant)>>>,
    /// The connection the victim opened to it.
    victim: Arc<Mutex<Option<TcpStream>>>,
    /// Set by the first request for addresses, which the victim sends once it
    /// has taken the withholder's introduction. Anything announced before
    /// that would be a message from a peer that has not introduced itself.
    introduced: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
}

impl Withholder {
    fn start() -> Self {
        let listener = TcpListener::bind(loopback()).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let victim = Arc::new(Mutex::new(None::<TcpStream>));
        let introduced = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        {
            let asked = Arc::clone(&asked);
            let victim = Arc::clone(&victim);
            let introduced = Arc::clone(&introduced);
            let running = Arc::clone(&running);
            thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    let Ok((socket, _)) = listener.accept() else {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    };
                    // The first connection is the victim's dial. Anybody
                    // else who learns the address is turned away, so every
                    // ask counted below is the victim's.
                    if victim.lock().unwrap().is_some() {
                        let _ = socket.shutdown(Shutdown::Both);
                        continue;
                    }
                    socket.set_nonblocking(false).unwrap();
                    *victim.lock().unwrap() = Some(socket.try_clone().unwrap());
                    let asked = Arc::clone(&asked);
                    let victim = Arc::clone(&victim);
                    let introduced = Arc::clone(&introduced);
                    let running = Arc::clone(&running);
                    thread::spawn(move || {
                        serve(
                            socket,
                            address.port(),
                            &asked,
                            &victim,
                            &introduced,
                            &running,
                        );
                    });
                }
            });
        }
        Self {
            address,
            asked,
            victim,
            introduced,
            running,
        }
    }

    fn send(&self, message: &Message) {
        let mut victim = self.victim.lock().unwrap();
        let socket = victim
            .as_mut()
            .expect("the victim has dialled the withholder");
        write_message(socket, params().network, message).unwrap();
    }

    fn was_asked_for(&self, height: u64) -> bool {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == height)
    }

    fn asks_for(&self, height: u64) -> usize {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, _)| *at == height)
            .count()
    }
}

impl Drop for Withholder {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(socket) = self.victim.lock().unwrap().as_ref() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

fn serve(
    mut socket: TcpStream,
    listen: u16,
    asked: &Mutex<Vec<(u64, Instant)>>,
    victim: &Mutex<Option<TcpStream>>,
    introduced: &AtomicBool,
    running: &AtomicBool,
) {
    let network = params().network;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    while running.load(Ordering::SeqCst) {
        let message = match read_message(&mut socket, network, MAX_FRAME_BYTES) {
            Ok(Incoming::Message(message)) => message,
            Ok(Incoming::Quiet) => continue,
            Err(_) => return,
        };
        let answer = match message {
            Message::Hello(_) => Some(welcome(listen)),
            Message::GetPeers => {
                introduced.store(true, Ordering::SeqCst);
                Some(Message::Peers(Vec::new()))
            }
            Message::Ping(nonce) => Some(Message::Pong(nonce)),
            Message::GetBlocks(heights) => {
                let now = Instant::now();
                asked
                    .lock()
                    .unwrap()
                    .extend(heights.into_iter().map(|height| (height, now)));
                None
            }
            _ => None,
        };
        if let Some(answer) = answer {
            let mut guard = victim.lock().unwrap();
            if let Some(writer) = guard.as_mut() {
                if write_message(writer, network, &answer).is_err() {
                    return;
                }
            }
        }
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        f64::midpoint(values[middle - 1], values[middle])
    } else {
        values[middle]
    }
}

/// **A block announced and withheld by one peer still arrives from the honest
/// peer that announces it next, with no wait on the first.**
///
/// The victim follows an honest miner and is also connected to the
/// withholder. A control node follows the same miner with nothing else. For
/// each block the withholder announces first, the test waits until the victim
/// has asked the withholder for it, which is the moment it would be waiting on
/// it if it were going to, and only then hands the block to the miner. The
/// victim's arrival is compared with the control's.
#[test]
fn a_block_announced_and_withheld_still_arrives_from_an_honest_peer() {
    let mut forge = Forge::new();
    let miner = Node::bind(params(), loopback()).unwrap();
    for _ in 0..3 {
        miner.submit_block(forge.mine()).unwrap();
    }
    let victim = Node::bind(params(), loopback()).unwrap();
    let control = Node::bind(params(), loopback()).unwrap();
    victim.connect(miner.address()).unwrap();
    control.connect(miner.address()).unwrap();
    assert!(
        wait_until(PATIENCE, || victim.height() == Some(2)
            && control.height() == Some(2)),
        "the victim and the control caught up with the miner"
    );

    let withholder = Withholder::start();
    victim.connect(withholder.address).unwrap();
    assert!(
        wait_until(PATIENCE, || withholder.introduced.load(Ordering::SeqCst)),
        "the victim dialled the withholder and took its introduction"
    );

    let mut extra = Vec::new();
    for round in 0..ROUNDS {
        let block = forge.mine();
        let height = block.header.height;
        let announced = if round % 2 == 0 {
            block.id()
        } else {
            // An identifier for a block that does not exist. The ask is by
            // height, so it is the same ask.
            Hash32::from_bytes([u8::try_from(round).unwrap(); 32])
        };
        withholder.send(&Message::Announce(vec![Located::new(height, announced)]));
        assert!(
            wait_until(PATIENCE, || withholder.was_asked_for(height)),
            "the victim asked the withholder for height {height}, which is what puts it \
             in a position to wait on it"
        );

        let handed = Instant::now();
        miner.submit_block(block.clone()).unwrap();
        let mut victim_at = None;
        let mut control_at = None;
        assert!(
            wait_until(PATIENCE, || {
                if victim_at.is_none() && victim.height() == Some(height) {
                    victim_at = Some(handed.elapsed());
                }
                if control_at.is_none() && control.height() == Some(height) {
                    control_at = Some(handed.elapsed());
                }
                victim_at.is_some() && control_at.is_some()
            }),
            "round {round}: the block reached both nodes"
        );
        let (victim_at, control_at) = (victim_at.unwrap(), control_at.unwrap());
        assert_eq!(victim.id_at(height), Some(block.id()));
        println!(
            "round {round} ({}): victim {:>6.1} ms, control {:>6.1} ms, withholder asked {} time(s)",
            if round % 2 == 0 { "real id" } else { "made-up id" },
            victim_at.as_secs_f64() * 1e3,
            control_at.as_secs_f64() * 1e3,
            withholder.asks_for(height),
        );
        assert!(
            victim_at < single_extra(),
            "round {round}: the victim took {victim_at:?} to get a block an honest peer \
             announced, against a batch patience of {BATCH_PATIENCE}s: it waited on the peer \
             that announced first"
        );
        assert_eq!(
            withholder.asks_for(height),
            1,
            "round {round}: the victim asked the withholder again rather than taking the \
             honest copy"
        );
        extra.push(victim_at.as_secs_f64() - control_at.as_secs_f64());
    }

    let median_extra = median(extra.clone());
    let in_ms: Vec<String> = extra
        .iter()
        .map(|seconds| format!("{:.1}", seconds * 1e3))
        .collect();
    println!(
        "extra delay at the victim per round, ms: [{}]; median {:.1} ms",
        in_ms.join(", "),
        median_extra * 1e3
    );
    assert!(
        median_extra < MEDIAN_EXTRA.as_secs_f64(),
        "the median extra delay at the victim was {median_extra:.3}s, past the catalogue's \
         {MEDIAN_EXTRA:?}"
    );

    victim.shutdown();
    control.shutdown();
    miner.shutdown();
}

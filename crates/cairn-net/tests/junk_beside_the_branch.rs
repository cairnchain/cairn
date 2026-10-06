//! A node flooded with junk beside its branch still takes an honest heavier
//! branch delivered afterwards, over real sockets.
//!
//! E05 of the testnet-8 attack catalogue: a block held beside the branch had
//! its difficulty taken as claimed, so a block claiming difficulty one cost a
//! stranger one hash, and four thousand of them hung beside the tip filled
//! the side store. Its sweep then dropped by height, so the first block of an
//! honest heavier branch went as it arrived, every later block was refused
//! for a parent the node did not have, and the node asked for the branch
//! again, was sent the same blocks, and dropped the same first one, for as
//! long as the junk sat there.
//!
//! A block beside the branch is asked at the door for the difficulty its
//! parent demands now, so the first block of the flood is refused, its sender
//! hung up on, and nothing of it is held.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::{ChainStore, MAX_SIDE_BLOCKS};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, PROTOCOL_VERSION};
use cairn_net::wire::write_message;
use cairn_net::Node;
use cairn_primitives::Hash32;

/// A liveness bound, far past what the work takes on a loaded runner. Every
/// wait here is for something to happen.
const PATIENCE: Duration = Duration::from_secs(180);

/// When the chain below opens, and when its first block is dated.
const OPENS: u64 = 1_000_000;

/// Off the floor, so that a block claiming difficulty one claims less than
/// its parent demands; at the floor every block demands one hash, and junk
/// claiming one is junk paying its way.
const OPENING: u64 = 4_096;

fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.opens_at = OPENS;
    params.genesis_difficulty = OPENING;
    params
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("waited {PATIENCE:?} for {what}");
}

/// Mines a branch on a private ledger, a block a minute, which is the
/// schedule, so every block carries the opening difficulty.
#[derive(Clone)]
struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new() -> Self {
        Self {
            state: LedgerState::new(),
            clock: OPENS,
        }
    }

    fn mine(&mut self, miner: &SecretKey) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        let block =
            assemble_block(&self.state, coinbase, Vec::new(), &params, self.clock, 0).unwrap();
        let block = mine_block(block, 1 << 24).unwrap();
        connect_block(&mut self.state, &block, &params, self.clock).unwrap();
        self.clock += params.target_block_time;
        block
    }
}

/// A block claiming difficulty one on `parent`, with a root that matches its
/// body and nothing else right about it.
fn junk(parent: &Block, nonce: u64) -> Block {
    let height = parent.header.height + 1;
    let mut block = Block {
        header: BlockHeader {
            version: BLOCK_VERSION,
            network: params().network,
            height,
            previous: parent.id(),
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: parent.header.timestamp + 1,
            difficulty: 1,
            total_work: parent.header.total_work + 1,
            nonce,
        },
        coinbase: CoinbaseTransaction::new(height, Vec::new()),
        transfers: Vec::new(),
    };
    block.header.transactions_root = block.transactions_root();
    block
}

/// One connection that introduces itself and sends every block it was given,
/// as fast as the socket takes them, unasked.
struct Flood {
    sent: Arc<AtomicU64>,
    hung_up: Arc<AtomicBool>,
}

impl Flood {
    fn start(to: SocketAddr, genesis: Hash32, blocks: Vec<Block>) -> Self {
        let sent = Arc::new(AtomicU64::new(0));
        let hung_up = Arc::new(AtomicBool::new(false));
        let (counted, noticed) = (Arc::clone(&sent), Arc::clone(&hung_up));
        let mut stream = TcpStream::connect(to).unwrap();
        let network = params().network;
        thread::spawn(move || {
            let hello = Message::Hello(Handshake {
                version: PROTOCOL_VERSION,
                network,
                genesis,
                height: 0,
                total_work: 1,
                listen: 0,
                nonce: u64::from(std::process::id()).wrapping_add(11),
                keeps: Keeps {
                    headers: false,
                    cold_set: false,
                },
            });
            if write_message(&mut stream, network, &hello).is_err() {
                noticed.store(true, Ordering::SeqCst);
                return;
            }
            for block in blocks {
                if write_message(&mut stream, network, &Message::Block(Box::new(block))).is_err() {
                    noticed.store(true, Ordering::SeqCst);
                    return;
                }
                counted.fetch_add(1, Ordering::SeqCst);
            }
            // Held open, so a node that keeps reading has nothing to hang up
            // on but what was sent.
            thread::sleep(PATIENCE);
        });
        Self { sent, hung_up }
    }
}

/// Eleven blocks everybody shares, two the victim follows, and an honest
/// branch of three off the same eleven, one block heavier.
///
/// The flood hangs off the first block the victim follows, so it ties the
/// victim's tip and sits one height above where the honest branch parts: on
/// the sweep that went by height, the honest branch's first block was the
/// lowest thing held beside the branch, and the first to go.
#[test]
fn a_node_flooded_with_junk_beside_its_branch_still_takes_a_heavier_branch_met_afterwards() {
    let params = params();
    let mut trunk = Forge::new();
    let shared: Vec<Block> = (0..11).map(|_| trunk.mine(&wallet(1))).collect();
    let mut aside = trunk.clone();
    let followed: Vec<Block> = (0..2).map(|_| trunk.mine(&wallet(1))).collect();
    let honest: Vec<Block> = (0..3).map(|_| aside.mine(&wallet(3))).collect();
    let rival = honest[2].id();

    let victim = Node::bind(params, loopback()).unwrap();
    for block in shared.iter().chain(&followed) {
        victim.submit_block(block.clone()).unwrap();
    }
    assert_eq!(victim.height(), Some(12));
    let peers: Vec<Node> = (0..2)
        .map(|_| {
            let node = Node::bind(params, loopback()).unwrap();
            for block in shared.iter().chain(&honest) {
                node.submit_block(block.clone()).unwrap();
            }
            assert_eq!(node.height(), Some(13));
            node
        })
        .collect();

    let junk: Vec<Block> = (0..=MAX_SIDE_BLOCKS as u64)
        .map(|nonce| junk(&followed[0], nonce))
        .collect();
    let ids: Vec<Hash32> = junk.iter().map(Block::id).collect();
    let flood = Flood::start(victim.address(), shared[0].id(), junk);
    wait_for("the flood to be hung up on, or to be sent in full", || {
        flood.hung_up.load(Ordering::SeqCst)
            || flood.sent.load(Ordering::SeqCst) > MAX_SIDE_BLOCKS as u64
    });

    for node in &peers {
        victim.connect(node.address()).unwrap();
    }
    wait_for(
        "the flooded node to take the heavier branch from the peers it met afterwards",
        || victim.with_chain(ChainStore::tip) == Some(rival),
    );

    let held = victim.with_chain(|chain| ids.iter().filter(|id| chain.contains(id)).count());
    assert_eq!(
        held, 0,
        "junk claiming less than its parent demands was held"
    );
    assert!(
        flood.hung_up.load(Ordering::SeqCst),
        "the sender of junk claiming less than its parent demands was left connected, \
         having written {} blocks",
        flood.sent.load(Ordering::SeqCst)
    );
    victim.shutdown();
    for node in &peers {
        node.shutdown();
    }
}

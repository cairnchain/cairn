//! Peers that say they keep the cold set, and do not.
//!
//! Lab scenario R11 (attack G08 of the 3 October catalogue). A note that has
//! fallen out of the grace window, and whose owner's node was not following
//! it, can be spent only with a path somebody kept, and the somebodies are a
//! few archivists. Whether a peer is one is a bit in its handshake. The
//! catalogue's defences: answers are folded against the asker's own roots,
//! so a lie costs a round and nothing more, and a node reaches for up to
//! `REACH_FOR_ARCHIVISTS` archivists it met before. Its pass mark: with one
//! honest archivist and six peers claiming the archive and answering every
//! place with nothing, the path is obtained within five minutes.
//!
//! The node here is in the state that question is about. It met the honest
//! archivist on an earlier connection, so the book holds its address and its
//! claim, and it holds its eight dialled connections, so the round that tops
//! peers up does not dial anybody. A real node and a real archivist on real
//! sockets; the peers that claim the archive are a few lines of protocol.
//!
//! **What was found.** A node reaches for an archivist it knows only when no
//! connected peer claims to be one. With nobody claiming, it dials the honest
//! archivist and has the path in one round. With six claimers connected, it
//! asks the six, takes six empty answers, and returns with nothing, and the
//! honest archivist is never dialled. A wallet asks again every fifteen
//! seconds and gets the same, for as long as the claimers stay connected:
//! never, against five minutes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::state::cold_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, Placed, PROTOCOL_VERSION};
use cairn_net::node::TARGET_PEERS;
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A liveness bound, far past what a loaded machine needs.
const PATIENCE: Duration = Duration::from_secs(30);

/// The peers that claim the archive, as many as the catalogue sends.
const CLAIMERS: usize = 6;

/// A small hot set, so notes fall at once, and a shallow burial.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "cairn-lying-archivists-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

/// A chain run well past the grace window, and where its first reward fell,
/// worked out on a ledger that keeps every leaf.
fn a_chain_with_a_fallen_note() -> (Vec<Block>, u64, Hash32) {
    let rules = params();
    let mut state = LedgerState::archiving();
    let paid_to = cairn_crypto::SecretKey::from_bytes(&[1; 32]).public_key();
    let mut clock = 1_000;
    let blocks: Vec<Block> = (0..cairn_ledger::state::GRACE_BLOCKS + 12)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase =
                CoinbaseTransaction::new(height, vec![Note::new(rules.initial_reward, paid_to)]);
            let block =
                assemble_block(&state, coinbase, Vec::<Transfer>::new(), &rules, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &rules, NOW).unwrap();
            block
        })
        .collect();
    let (id, note) = blocks[1].coinbase.created_notes()[0];
    let position = state.cold().locate(&id, &note).unwrap();
    (blocks, position, cold_leaf(&id, &note))
}

/// A peer that takes one connection, says in its greeting whether it keeps
/// the cold set, and answers every place it is asked about with nothing.
struct Pretender {
    address: SocketAddr,
    running: Arc<AtomicBool>,
    asked: Arc<AtomicU64>,
}

impl Pretender {
    fn start(tag: u8, claims_the_archive: bool) -> Self {
        let listener = TcpListener::bind(loopback()).unwrap();
        let address = listener.local_addr().unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let asked = Arc::new(AtomicU64::new(0));
        let mine = (Arc::clone(&running), Arc::clone(&asked));
        thread::spawn(move || {
            let (running, asked) = mine;
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let network = params().network;
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .ok();
            while running.load(Ordering::SeqCst) {
                let answer = match read_message(&mut stream, network, MAX_FRAME_BYTES) {
                    Ok(Incoming::Message(Message::Hello(_))) => Message::Welcome(Handshake {
                        version: PROTOCOL_VERSION,
                        network,
                        genesis: Hash32::ZERO,
                        height: 0,
                        total_work: 0,
                        listen: address.port(),
                        nonce: 0x5ee0 + u64::from(tag),
                        keeps: Keeps {
                            headers: true,
                            cold_set: claims_the_archive,
                        },
                    }),
                    Ok(Incoming::Message(Message::GetProofs(positions))) => {
                        asked.fetch_add(1, Ordering::SeqCst);
                        Message::Proofs(
                            positions
                                .into_iter()
                                .map(|position| Placed {
                                    position,
                                    proof: None,
                                })
                                .collect(),
                        )
                    }
                    Ok(_) => continue,
                    Err(_) => return,
                };
                if write_message(&mut stream, network, &answer).is_err() {
                    return;
                }
            }
        });
        Self {
            address,
            running,
            asked,
        }
    }

    fn asked(&self) -> u64 {
        self.asked.load(Ordering::SeqCst)
    }
}

impl Drop for Pretender {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// A node that met the honest archivist before and is now connected to
/// `claimers` peers claiming the archive and enough others to hold all its
/// dialled connections, and the honest archivist, up and not connected.
struct Scene {
    directory: std::path::PathBuf,
    keeper: Node,
    asker: Node,
    pretenders: Vec<Pretender>,
    position: u64,
    leaf: Hash32,
}

impl Scene {
    fn new(name: &str, claimers: usize) -> Self {
        let (blocks, position, leaf) = a_chain_with_a_fallen_note();
        let top = (blocks.len() - 1) as u64;
        let directory = scratch(name);
        let (keeper, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
        let at = keeper.address();
        for block in &blocks {
            keeper.submit_block(block.clone()).unwrap();
        }

        // Its chain from its own hand, and its path to the note let go of
        // once the window passed, as every node that follows nobody does.
        let asker = Node::bind(params(), loopback()).unwrap();
        for block in &blocks {
            asker.submit_block(block.clone()).unwrap();
        }
        assert_eq!(asker.height(), Some(top));
        assert!(
            asker
                .with_chain(|chain| chain.state().cold().proof_of(position))
                .is_none(),
            "fixture: the asking node still holds the path"
        );

        // The earlier connection, which is how the book learns who said it
        // keeps the archive.
        asker.connect(at).unwrap();
        wait_for("the archivist to say what it keeps", || {
            asker.archiving_peers() == 1
        });

        // Its dialled connections, all of them, so nothing tops them up.
        let pretenders: Vec<Pretender> = (0..TARGET_PEERS)
            .map(|index| Pretender::start(u8::try_from(index).unwrap(), index < claimers))
            .collect();
        for pretender in &pretenders {
            asker.connect(pretender.address).unwrap();
        }
        wait_for("every peer to introduce itself", || {
            asker.peers_introduced() == TARGET_PEERS + 1
        });

        // The archivist goes away and comes back where it was, and the asker,
        // holding its eight, does not dial it again.
        keeper.shutdown();
        drop(keeper);
        wait_for("the asker to notice the archivist went", || {
            asker.peer_count() == TARGET_PEERS
        });
        let (keeper, _) = Node::open_archiving(params(), at, &directory).unwrap();
        assert_eq!(keeper.height(), Some(top));
        assert_eq!(asker.archiving_peers(), claimers);
        assert_eq!(keeper.peer_count(), 0);

        Self {
            directory,
            keeper,
            asker,
            pretenders,
            position,
            leaf,
        }
    }

    fn finish(self) {
        self.asker.shutdown();
        self.keeper.shutdown();
        drop(self.pretenders);
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// **A node that knows an archivist, and is connected to nobody claiming to
/// be one, reaches for it and gets the path.**
///
/// The defence the catalogue counts on, on its own: the claim heard on an
/// earlier connection is followed with a dial, and the answer folds.
#[test]
fn a_node_with_no_archivist_connected_reaches_the_one_it_met() {
    let scene = Scene::new("none-claiming", 0);
    let answer = scene
        .asker
        .recover_proofs(&[(scene.position, scene.leaf)], PATIENCE);
    let dialled = scene.keeper.peer_count();
    let found = answer.proofs.contains_key(&scene.position);
    scene.finish();
    assert_eq!(dialled, 1, "the archivist it met was dialled");
    assert!(found, "and the path it handed over folded: {answer:?}");
}

/// **A node that knows an honest archivist gets the path though six
/// connected peers claim the archive and place nothing.**
///
/// R11's pass mark, asked of one round. It fails: the node reaches for an
/// archivist only when no connected peer claims to be one, so it asks the
/// six, takes their six empty answers, and stops, and the honest archivist,
/// up and in its book, is never dialled. Every later round is the same
/// round.
#[test]
fn a_node_that_knows_an_honest_archivist_gets_the_path_past_peers_that_only_claim_it() {
    let scene = Scene::new("six-claiming", CLAIMERS);
    let answer = scene
        .asker
        .recover_proofs(&[(scene.position, scene.leaf)], PATIENCE);
    let asked: u64 = scene.pretenders.iter().map(Pretender::asked).sum();
    let dialled = scene.keeper.peer_count();
    let found = answer.proofs.contains_key(&scene.position);
    scene.finish();
    assert_eq!(asked, CLAIMERS as u64, "fixture: every claimer was asked");
    assert!(
        found,
        "six peers claiming the archive kept the node from the honest archivist it \
         knows: {} asked, {} answered, nothing placed, and the archivist dialled {} \
         times",
        answer.asked, answer.answered, dialled
    );
}

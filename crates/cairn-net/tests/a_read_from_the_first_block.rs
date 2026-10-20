//! A node reading the chain from the first block, as a wallet recovering its
//! old money does, makes the newcomer's choice as any newcomer makes it.
//!
//! Such a node is never handed a ledger: every turn the choice hands out is a
//! read, and the peers that say they keep every block, archivists, are asked
//! before the others, because a peer that keeps less has let go of the first
//! blocks such a read asks for. Asking first is all an archivist's word buys.
//! What a read is held to before it ends the choice is what it is held to on
//! any newcomer (see `a_read_is_weighed.rs`): a visitor read first, claiming
//! the most work and pushing a branch from the first block mined at the lowest
//! difficulty there is, still does not end the choice, whether or not it says
//! it keeps every block.
//!
//! On a network that undoes eight blocks, with the fixture of
//! `a_read_is_weighed.rs`: nothing on the path reads that number.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::pow::MIN_DIFFICULTY;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{
    assemble_block, connect_block, expected_difficulty, mine_block, ConsensusParams,
};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, PROTOCOL_VERSION};
use cairn_net::node::{NodeError, READING_FROM_THE_FIRST};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::Hash32;

/// The depth this network undoes.
const UNDO: u64 = 8;

/// Blocks the honest chain holds, the first block among them.
const HONEST_BLOCKS: usize = 20;

/// How long the honest chain is given once the peers are reached. A liveness
/// bound on a loaded runner, not a measurement.
const PATIENCE: Duration = Duration::from_secs(90);

/// Seconds a node gives the peer its choice asked to produce something before
/// giving up on it: `choosing::FIRST_ANSWER_PATIENCE`, private to the crate.
const ANSWERING_WINDOW: u64 = 30;

fn rules() -> ConsensusParams {
    ConsensusParams::mineable_network(UNDO)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-read-from-the-first-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
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

/// Builds blocks off to the side. A copy carries on from the same blocks, so
/// the honest chain and the visitor's share their first block.
#[derive(Clone)]
struct Forge {
    state: LedgerState,
    clock: u64,
    miner: u8,
    /// How far apart the blocks are dated, in block intervals.
    spacing: u64,
}

impl Forge {
    fn mine(&mut self) -> Block {
        let params = rules();
        let height = self.state.next_height().unwrap();
        self.clock += params.target_block_time * self.spacing;
        let reward = Note::new(
            params.reward_at(height),
            SecretKey::from_bytes(&[self.miner; 32]).public_key(),
        );
        let coinbase = CoinbaseTransaction::new(height, vec![reward]);
        let block = assemble_block(&self.state, coinbase, vec![], &params, self.clock, 0).unwrap();
        let block = mine_block(block, 1 << 24).expect("a block on these rules is cheap to mine");
        connect_block(&mut self.state, &block, &params, self.clock + 1).unwrap();
        block
    }
}

/// The honest chain of `HONEST_BLOCKS`, dated a block interval apart, and the
/// visitor's: the honest first block, then `UNDO + 1` of its own dated a whole
/// half life late every time, so it walks down to the floor and stays there.
fn the_two_chains() -> (Vec<Block>, Vec<Block>) {
    let mut honest = Forge {
        state: LedgerState::new(),
        clock: rules().opens_at,
        miner: 1,
        spacing: 1,
    };
    let first = honest.mine();
    let mut visitor = honest.clone();
    visitor.miner = 3;
    visitor.spacing = 120;
    let mut honest_chain = vec![first.clone()];
    honest_chain.extend((1..HONEST_BLOCKS).map(|_| honest.mine()));
    let mut visitor_chain = vec![first];
    visitor_chain.extend((0..=UNDO).map(|_| visitor.mine()));
    assert_eq!(
        expected_difficulty(&visitor.state, &rules()),
        MIN_DIFFICULTY,
        "fixture: the visitor's branch reaches the floor"
    );
    (honest_chain, visitor_chain)
}

/// A node holding `blocks` over a directory of its own, keeping every block
/// and saying so.
fn an_archivist(name: &str, blocks: &[Block]) -> (Node, PathBuf) {
    let directory = scratch(name);
    let (node, _) = Node::open_archiving(rules(), loopback(), &directory).unwrap();
    for block in blocks {
        node.submit_block(block.clone()).unwrap();
    }
    (node, directory)
}

/// A node reading from the first block over an empty directory of its own.
fn a_recovering_node(name: &str) -> (Node, PathBuf) {
    let directory = scratch(name);
    let (node, _) = Node::open_recovering(rules(), loopback(), &directory, &[]).unwrap();
    assert!(
        node.reads_from_the_first_block(),
        "fixture: the node reads from the first block"
    );
    assert!(
        directory.join(READING_FROM_THE_FIRST).exists(),
        "fixture: and the disk says so"
    );
    (node, directory)
}

/// Dials `newcomer` as a visitor keeping no headers and saying it keeps the
/// cold set or not as `keeps_the_cold_set` says, holding `blocks` and claiming
/// `work`, and serves them like any peer, a chain asked for no oftener than
/// once a second so it is never dropped for flooding. Sets `asked` once it is
/// first asked for a block.
fn visit(
    newcomer: SocketAddr,
    work: u128,
    keeps_the_cold_set: bool,
    blocks: &[Block],
    asked: &Arc<AtomicBool>,
) -> TcpStream {
    let network = rules().network;
    let mut socket = TcpStream::connect(newcomer).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let hello = Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network,
        genesis: rules().genesis.unwrap_or(Hash32::ZERO),
        height: 10_000,
        total_work: work,
        listen: 0,
        nonce: 0x0F1F_0001,
        keeps: Keeps {
            headers: false,
            cold_set: keeps_the_cold_set,
        },
    });
    write_message(&mut socket, network, &hello).unwrap();
    let mut reading = socket.try_clone().unwrap();
    let held: Vec<Block> = blocks.to_vec();
    let asked = Arc::clone(asked);
    let mut answered: Option<Instant> = None;
    thread::spawn(move || loop {
        let message = match read_message(&mut reading, network, MAX_FRAME_BYTES) {
            Ok(Incoming::Message(message)) => message,
            Ok(Incoming::Quiet) => continue,
            Err(_) => return,
        };
        let answers = match message {
            Message::GetPeers => vec![Message::Peers(Vec::new())],
            Message::Ping(nonce) => vec![Message::Pong(nonce)],
            Message::GetChain { .. }
                if answered.is_none_or(|at| at.elapsed() >= Duration::from_secs(1)) =>
            {
                answered = Some(Instant::now());
                vec![Message::Chain {
                    from: 0,
                    count: u64::try_from(held.len()).unwrap(),
                }]
            }
            Message::GetBlocks(heights) => {
                asked.store(true, Ordering::SeqCst);
                heights
                    .iter()
                    .filter_map(|at| held.get(usize::try_from(*at).ok()?))
                    .map(|block| Message::Block(Box::new(block.clone())))
                    .collect()
            }
            _ => continue,
        };
        for answer in answers {
            if write_message(&mut reading, network, &answer).is_err() {
                return;
            }
        }
    });
    socket
}

/// A node reading from the first block, an honest archivist holding
/// `HONEST_BLOCKS`, and the visitor serving its branch one block past the
/// depth, claiming far more than the honest chain. Panics unless the node
/// ends on the honest chain, holding it from the first block.
fn a_recovery_between_an_archivist_and_a_visitor(keeps_the_cold_set: bool) {
    let (honest_chain, visitor_chain) = the_two_chains();
    let name = if keeps_the_cold_set {
        "visitor-archiving"
    } else {
        "visitor-plain"
    };
    let (seed, seed_directory) = an_archivist(&format!("{name}-seed"), &honest_chain);
    let honest_tip = seed.with_chain(ChainStore::tip).unwrap();
    let (newcomer, directory) = a_recovering_node(name);

    let asked = Arc::new(AtomicBool::new(false));
    let visitor = visit(
        newcomer.address(),
        seed.total_work().saturating_mul(1_000),
        keeps_the_cold_set,
        &visitor_chain,
        &asked,
    );
    newcomer.connect(seed.address()).unwrap();
    let took_the_honest_chain = wait_until(PATIENCE, || {
        newcomer.with_chain(ChainStore::tip) == Some(honest_tip)
    });
    let (height, on_the_visitor, first, visitor_asked) = (
        newcomer.height(),
        newcomer.id_at(1) == Some(visitor_chain[1].id()),
        newcomer.blocks_from(),
        asked.load(Ordering::SeqCst),
    );
    let _ = visitor.shutdown(Shutdown::Both);
    newcomer.shutdown();
    seed.shutdown();
    drop(newcomer);
    drop(seed);
    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&seed_directory);

    assert!(
        took_the_honest_chain,
        "a node reading from the first block, between an honest archivist and a visitor \
         claiming far more and keeping no headers (saying it keeps the cold set: \
         {keeps_the_cold_set}), was at height {height:?} after {PATIENCE:?}, on the visitor's \
         branch: {on_the_visitor}, rather than on the honest chain of {HONEST_BLOCKS} blocks"
    );
    assert_eq!(first, Some(0), "and it read the chain from the first block");
    if keeps_the_cold_set {
        assert!(
            visitor_asked,
            "fixture: a visitor saying it keeps every block and claiming the most is read first"
        );
    }
}

/// **The attack of `a_read_is_weighed.rs`, on a node reading from the first
/// block, from a visitor that says it keeps every block.**
///
/// The worst case for the order a read from the first block asks in: the
/// visitor's word that it keeps everything puts it in line with the honest
/// archivist, and its claim of more work puts it first. Its branch reaches
/// one block past the depth carrying next to no work, is held to the honest
/// archivist's claim spread over that many blocks, falls short, and the
/// honest chain is taken.
#[test]
fn a_visitor_saying_it_keeps_every_block_cannot_end_a_recovery_on_a_floor_difficulty_branch() {
    a_recovery_between_an_archivist_and_a_visitor(true);
}

/// **And from a visitor that does not say it.**
///
/// Then the honest archivist is read first, and its block past the depth is
/// held off by the visitor's claim, which is the price of a claim nobody
/// checked; the visitor's turn follows, its branch falls short of what the
/// archivist sent, and the archivist's next turn takes the honest chain.
#[test]
fn a_visitor_keeping_less_cannot_end_a_recovery_on_a_floor_difficulty_branch() {
    a_recovery_between_an_archivist_and_a_visitor(false);
}

/// **A node reading from the first block does not ask first a peer that has
/// let go of its oldest blocks.**
///
/// Two peers on the same chain, claiming the same work: an archivist, and a
/// node that keeps only what its budget affords and has trimmed its first
/// blocks. The second is reached last, so its connection number is the higher
/// and it would win the tie of work a newcomer breaks by it. Asked first, it
/// offers a chain beginning where its log begins, nothing it sends connects
/// to the first block, and the read waits out an answering window. Asked
/// first, the archivist hands the chain over at once.
#[test]
fn a_read_from_the_first_block_asks_the_archivist_before_a_peer_that_trimmed() {
    let (honest_chain, _) = the_two_chains();
    let (archivist, archivist_directory) = an_archivist("before-trimmed-archivist", &honest_chain);
    let trimmed_directory = scratch("before-trimmed-plain");
    let (trimmed, _) = Node::open(rules(), loopback(), &trimmed_directory).unwrap();
    for block in &honest_chain {
        trimmed.submit_block(block.clone()).unwrap();
    }
    trimmed.keep_blocks(1);
    assert!(
        wait_until(PATIENCE, || trimmed.blocks_from().unwrap_or(0) > 0),
        "fixture: the peer keeping less let go of its first blocks"
    );
    let honest_tip = archivist.with_chain(ChainStore::tip).unwrap();
    let (newcomer, directory) = a_recovering_node("before-trimmed");

    let started = Instant::now();
    newcomer.connect(archivist.address()).unwrap();
    newcomer.connect(trimmed.address()).unwrap();
    let took_it = wait_until(PATIENCE, || {
        newcomer.with_chain(ChainStore::tip) == Some(honest_tip)
    });
    let took = started.elapsed();
    let first = newcomer.blocks_from();
    newcomer.shutdown();
    archivist.shutdown();
    trimmed.shutdown();
    drop((newcomer, archivist, trimmed));
    for each in [directory, archivist_directory, trimmed_directory] {
        let _ = std::fs::remove_dir_all(each);
    }

    assert!(took_it, "the chain was not read in {PATIENCE:?}");
    assert_eq!(first, Some(0), "fixture: it was read from the first block");
    let bound = Duration::from_secs(ANSWERING_WINDOW / 2);
    assert!(
        took < bound,
        "reading {HONEST_BLOCKS} blocks from the first took {took:?}, past {bound:?}: the peer \
         that let go of its first blocks was asked before the archivist, and waited out"
    );
}

/// **The disk says the read is under way until the node is told it reached
/// the tip, and a start over the directory meanwhile carries it on.**
///
/// Opened as an ordinary node over a directory such a read left, a node still
/// reads from the first block; told it finished, the directory is an ordinary
/// node's, opened as one.
#[test]
fn a_read_from_the_first_block_is_remembered_until_it_is_finished() {
    let (node, directory) = a_recovering_node("remembered");
    node.shutdown();
    drop(node);

    let (again, _) = Node::open(rules(), loopback(), &directory).unwrap();
    let carried_on = again.reads_from_the_first_block();
    again.finished_reading().unwrap();
    let after = (
        again.reads_from_the_first_block(),
        directory.join(READING_FROM_THE_FIRST).exists(),
    );
    // Said twice, which is a wallet told twice, or a directory whose marker
    // something else removed: neither is an error.
    let twice = again.finished_reading();
    again.shutdown();
    drop(again);

    let (ordinary, _) = Node::open(rules(), loopback(), &directory).unwrap();
    let reads = ordinary.reads_from_the_first_block();
    ordinary.shutdown();
    drop(ordinary);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        carried_on,
        "a node opened over a directory a read from the first block left unfinished was an \
         ordinary newcomer, which on a long chain is handed a ledger"
    );
    assert_eq!(
        after,
        (false, false),
        "a node told it finished reading still reads from the first block, or left the disk \
         saying so"
    );
    assert!(twice.is_ok(), "being told twice was refused: {twice:?}");
    assert!(
        !reads,
        "a directory whose read finished was opened reading from the first block again"
    );
}

/// **A read from the first block is never started over a directory holding a
/// chain, and is carried on over one it left.**
///
/// A chain on the disk is blocks applied before anybody watched them for the
/// owner's notes, so reading on from it would not find them. An empty log is
/// no chain, and a ledger alone is one.
#[test]
fn a_read_from_the_first_block_starts_only_over_a_directory_holding_no_chain() {
    let (honest_chain, _) = the_two_chains();

    let holding = scratch("over-a-chain");
    let (node, _) = Node::open(rules(), loopback(), &holding).unwrap();
    for block in &honest_chain[..3] {
        node.submit_block(block.clone()).unwrap();
    }
    assert!(
        wait_until(PATIENCE, || node.written_through() == Some(2)),
        "fixture: the blocks reached the disk"
    );
    node.shutdown();
    drop(node);
    let refused = Node::open_recovering(rules(), loopback(), &holding, &[]).map(|(node, _)| {
        node.shutdown();
    });
    let marked = holding.join(READING_FROM_THE_FIRST).exists();

    let ledger_alone = scratch("over-a-ledger");
    std::fs::create_dir_all(&ledger_alone).unwrap();
    std::fs::write(ledger_alone.join(cairn_store::HANDED_LEDGER), b"").unwrap();
    let ledger_refused =
        Node::open_recovering(rules(), loopback(), &ledger_alone, &[]).map(|(node, _)| {
            node.shutdown();
        });
    let ledger_marked = ledger_alone.join(READING_FROM_THE_FIRST).exists();

    let empty_log = scratch("over-an-empty-log");
    let (node, _) = Node::open(rules(), loopback(), &empty_log).unwrap();
    node.shutdown();
    drop(node);
    let opened = Node::open_recovering(rules(), loopback(), &empty_log, &[]).map(|(node, _)| {
        let reads = node.reads_from_the_first_block();
        node.shutdown();
        reads
    });

    // And over a directory a read left, with a chain on it now, it carries on.
    let left = scratch("left-unfinished");
    let (node, _) = Node::open_recovering(rules(), loopback(), &left, &[]).unwrap();
    for block in &honest_chain[..3] {
        node.submit_block(block.clone()).unwrap();
    }
    assert!(
        wait_until(PATIENCE, || node.written_through() == Some(2)),
        "fixture: the blocks reached the disk"
    );
    node.shutdown();
    drop(node);
    let carried_on = Node::open_recovering(rules(), loopback(), &left, &[]).map(|(node, _)| {
        let reads = node.reads_from_the_first_block();
        node.shutdown();
        reads
    });

    for each in [holding, ledger_alone, empty_log, left] {
        let _ = std::fs::remove_dir_all(each);
    }
    assert!(
        matches!(refused, Err(NodeError::HoldsAChain { .. })),
        "a read from the first block was started over a directory holding a chain: {:?}",
        refused.err()
    );
    assert!(!marked, "and the refusal wrote the marker anyway");
    assert!(
        matches!(ledger_refused, Err(NodeError::HoldsAChain { .. })),
        "a read from the first block was started over a directory holding a ledger: {:?}",
        ledger_refused.err()
    );
    assert!(!ledger_marked, "and the refusal wrote the marker anyway");
    assert!(
        matches!(opened, Ok(true)),
        "a directory whose log holds nothing was refused: {:?}",
        opened.err()
    );
    assert!(
        matches!(carried_on, Ok(true)),
        "a read left unfinished was refused over the chain it had read: {:?}",
        carried_on.err()
    );
}

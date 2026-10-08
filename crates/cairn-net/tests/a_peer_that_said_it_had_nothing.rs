//! A newcomer, an honest seed, and a visitor that says it has nought blocks.
//!
//! A node with nothing of its own leaves a chain long enough to be final to
//! its choice of whom to follow, and asks for a short one at once, since a
//! short chain followed wrongly is undone by the fork choice. Short was the
//! height the peer wrote in its own greeting. A visitor that dials in first,
//! says it has nought blocks and claims the work of a long chain is asked for
//! its chain at the handshake, and nothing afterwards held it to what it said:
//! it pushed one block more than the network undoes, the node read them all,
//! and the honest chain, forking at the first block, was out of its reach for
//! good.
//!
//! On a network that undoes twelve blocks, once over the loopback with real
//! nodes and once on the message layer alone, where the sync layer has to
//! hold the peer to what it said without the node's chooser behind it. The
//! visitor's chain is shorter than the honest one and no harder to mine; what
//! it has is being first.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::{ChainError, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::{Keeps, Node};
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;

/// How long the honest chain is given to arrive once the seed is reached: a
/// settling, a turn and twenty blocks over the loopback take seconds, and
/// this is a liveness bound on a loaded runner rather than a measurement.
const PATIENCE: Duration = Duration::from_secs(90);

/// The depth this network undoes.
const UNDO: u64 = 12;

/// Long enough for a node to have run a round of its choice, which upkeep does
/// once a second.
const ROUND_AND_A_HALF: Duration = Duration::from_millis(1_500);

/// Blocks the honest seed holds, the first block among them.
const HONEST_BLOCKS: usize = 20;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(UNDO)
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

/// Builds blocks off to the side. A copy of one forge carries on from the
/// same blocks, so two forges can share a first block and part after it.
#[derive(Clone)]
struct Forge {
    state: LedgerState,
    clock: u64,
    miner: u8,
}

impl Forge {
    fn mine(&mut self) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(
                params.reward_at(height),
                SecretKey::from_bytes(&[self.miner; 32]).public_key(),
            )],
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
        let block = mine_block(block, 1 << 22).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }
}

/// The honest chain, and the visitor's: its own `UNDO + 1` blocks on the
/// honest first block, one more than the network undoes.
fn the_two_chains() -> (Vec<Block>, Vec<Block>) {
    let mut honest = Forge {
        state: LedgerState::new(),
        clock: 1_000,
        miner: 1,
    };
    let first = honest.mine();
    let mut visitor = honest.clone();
    visitor.miner = 4;
    visitor.clock += 7;
    let mut honest_chain = vec![first.clone()];
    honest_chain.extend((1..HONEST_BLOCKS).map(|_| honest.mine()));
    let mut visitor_chain = vec![first];
    visitor_chain.extend((0..=UNDO).map(|_| visitor.mine()));
    (honest_chain, visitor_chain)
}

/// Dials `newcomer`, introduces itself as holding nought blocks with `work`
/// behind them, and pushes the first `pushed` of `blocks` one message each, as
/// a peer may: the first block, then a pause long enough for the newcomer to
/// have run its choice since taking it, then the rest. It serves them like any
/// peer, a chain asked for offered from the block after the first and the
/// heights asked for sent, and serves the rest of `blocks` too once `all` is
/// set: until then it is a peer whose chain is as long as it pushed, so if the
/// newcomer's choice settles on it afterwards, it is given what it asks for.
fn visit(
    newcomer: SocketAddr,
    work: u128,
    blocks: &[Block],
    pushed: usize,
    all: &Arc<AtomicBool>,
) -> TcpStream {
    let network = params().network;
    let mut socket = TcpStream::connect(newcomer).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let hello = Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network,
        genesis: Hash32::ZERO,
        height: 0,
        total_work: work,
        listen: 0,
        nonce: 0x0516_0000,
        keeps: Keeps {
            headers: true,
            cold_set: false,
        },
    });
    write_message(&mut socket, network, &hello).unwrap();
    let push = |socket: &mut TcpStream, blocks: &[Block]| {
        for block in blocks {
            write_message(socket, network, &Message::Block(Box::new(block.clone()))).unwrap();
        }
    };
    push(&mut socket, &blocks[..1]);
    thread::sleep(ROUND_AND_A_HALF);
    push(&mut socket, &blocks[1..pushed]);
    let mut reading = socket.try_clone().unwrap();
    let held = blocks.to_vec();
    let all = Arc::clone(all);
    thread::spawn(move || loop {
        let serving = if all.load(Ordering::SeqCst) {
            &held[..]
        } else {
            &held[..pushed]
        };
        let message = match read_message(&mut reading, network, MAX_FRAME_BYTES) {
            Ok(Incoming::Message(message)) => message,
            Ok(Incoming::Quiet) => continue,
            Err(_) => return,
        };
        let answers = match message {
            Message::GetPeers => vec![Message::Peers(Vec::new())],
            Message::Ping(nonce) => vec![Message::Pong(nonce)],
            Message::GetChain { .. } => vec![Message::Chain {
                from: 1,
                count: u64::try_from(serving.len()).unwrap() - 1,
            }],
            Message::GetBlocks(heights) => heights
                .iter()
                .filter_map(|at| serving.get(usize::try_from(*at).ok()?))
                .map(|block| Message::Block(Box::new(block.clone())))
                .collect(),
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

/// A newcomer, an honest seed and a visitor that pushes the first `pushed` of
/// its blocks, in the order the defect needs: the visitor first, the seed once
/// the newcomer has read the visitor's chain as far as it undoes. Panics
/// unless the newcomer ends on the honest chain.
fn a_newcomer_reached_first_by_a_visitor_pushing(pushed: usize) {
    let (honest_chain, visitor_chain) = the_two_chains();
    let seed = Node::bind(params(), loopback()).unwrap();
    for block in &honest_chain {
        seed.submit_block(block.clone()).unwrap();
    }
    let honest_tip = seed.with_chain(ChainStore::tip).unwrap();
    let newcomer = Node::bind(params(), loopback()).unwrap();
    assert_eq!(
        newcomer.with_chain(ChainStore::undo_limit),
        UNDO,
        "fixture: the depth this network undoes"
    );
    assert_eq!(
        newcomer.height(),
        None,
        "fixture: the newcomer holds nothing"
    );

    // The visitor first: it is the peer that reaches a node that has just
    // started before the node's own dials are answered.
    let all = Arc::new(AtomicBool::new(false));
    let visitor = visit(
        newcomer.address(),
        seed.total_work().saturating_mul(1_000),
        &visitor_chain,
        pushed,
        &all,
    );
    assert!(
        wait_until(PATIENCE, || newcomer
            .height()
            .is_some_and(|height| height >= UNDO)),
        "fixture: the newcomer read the visitor's chain as far as it undoes, and is at {:?}",
        newcomer.height()
    );
    let after_the_push = newcomer.height();

    all.store(true, Ordering::SeqCst);
    newcomer.connect(seed.address()).unwrap();
    let took_the_honest_chain = wait_until(PATIENCE, || {
        newcomer.with_chain(ChainStore::tip) == Some(honest_tip)
    });
    let (height, on_the_visitor) = (
        newcomer.height(),
        newcomer.id_at(1) == Some(visitor_chain[1].id()),
    );
    let _ = visitor.shutdown(Shutdown::Both);
    newcomer.shutdown();
    seed.shutdown();

    assert!(
        took_the_honest_chain,
        "a newcomer that a visitor saying it had nought blocks reached first, pushing {pushed} \
         blocks, read its chain to height {after_the_push:?}, and {PATIENCE:?} after its seed \
         answered it was at height {height:?}, on the visitor's chain: {on_the_visitor}, rather \
         than on the honest chain of {HONEST_BLOCKS} blocks"
    );
}

/// **A newcomer a visitor reaches first, saying it has nought blocks and
/// pushing one more than the network undoes, still ends on the honest chain
/// once its seed answers.**
///
/// On `main` this newcomer read the visitor's chain to height thirteen and
/// stayed there, the honest chain forking below what it could undo.
#[test]
fn a_visitor_that_said_it_had_nothing_does_not_keep_a_newcomer_off_the_honest_chain() {
    a_newcomer_reached_first_by_a_visitor_pushing(visitor_blocks());
}

/// **And one pushing exactly as far as the network undoes, keeping its word
/// for the choice, is not the claim the choice asks first.**
///
/// It sends nothing the node refuses, so what it sent above the height it
/// claimed is the only thing that tells it apart from a peer with the work it
/// says. Ranked by its word it was the heaviest claim in front of the choice,
/// asked first, and handed the block that took the node past what it undoes.
#[test]
fn a_visitor_pushing_only_as_far_as_the_node_undoes_is_not_asked_first() {
    a_newcomer_reached_first_by_a_visitor_pushing(visitor_blocks() - 1);
}

/// How many blocks the visitor holds, the first block among them.
fn visitor_blocks() -> usize {
    usize::try_from(UNDO).unwrap() + 2
}

// ---------------------------------------------------------------------------
// The same visitor on the message layer, with nothing behind it.
// ---------------------------------------------------------------------------

fn local(chain: &mut ChainStore) -> Local<'_> {
    Local {
        chain,
        keeps: Keeps::default(),
        listen: 4242,
        nonce: 1,
    }
}

/// Greets a node with nothing as a peer claiming `height` and `total_work`,
/// and says whether the node asked for its chain on the spot, with the peer as
/// the greeting leaves it.
fn greeted(chain: &mut ChainStore, height: u64, total_work: u128) -> (bool, PeerState) {
    let mut peer = PeerState::default();
    let hello = Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        height,
        total_work,
        listen: 0,
        nonce: 99,
        keeps: Keeps {
            headers: true,
            cold_set: false,
        },
    };
    let reaction = on_message(&mut local(chain), &mut peer, Message::Welcome(hello), NOW);
    let asked = reaction
        .reply
        .iter()
        .any(|message| matches!(message, Message::GetChain { .. }));
    (asked, peer)
}

/// Hands `blocks` to the node from `peer`, one message each, and says what
/// the last of them was named as.
fn pushed(chain: &mut ChainStore, peer: &mut PeerState, blocks: &[Block]) -> Option<(u64, u128)> {
    let mut outgrew = None;
    for block in blocks {
        let reaction = on_message(
            &mut local(chain),
            peer,
            Message::Block(Box::new(block.clone())),
            NOW,
        );
        outgrew = reaction.outgrew;
    }
    outgrew
}

/// **A peer that says it has nought blocks is asked for its chain at the
/// handshake, and held to what it said: nothing past the depth the node
/// undoes is taken from it, and from then on it is taken to claim what it
/// sent.**
///
/// The first half is kept on purpose, and the demonstration of this defect
/// asserted the opposite: that such a peer must not be asked here at all.
/// Asking a peer that says its chain is short is how a newcomer on a young
/// network reads it at once, and the in-crate `a_newcomer` test holds that for
/// a chain one block shorter than the network undoes. What a short claim may
/// not buy is the rest: nothing held the peer to the number once it was asked,
/// and nothing here can tell nought from eleven without its blocks.
#[test]
fn a_peer_that_understates_its_height_is_held_to_it() {
    let (_, visitor_chain) = the_two_chains();
    let mut chain = ChainStore::new(params());
    assert_eq!(
        chain.undo_limit(),
        UNDO,
        "fixture: the depth this network undoes"
    );
    let (told_the_truth, _) = greeted(&mut chain, UNDO + 2, 1_000_000);
    assert!(
        !told_the_truth,
        "fixture: a claim as long as the network undoes is left to the choice"
    );

    let (asked, mut peer) = greeted(&mut chain, 0, 1_000_000);
    assert!(asked, "fixture: a short claim is asked for at once");
    let outgrew = pushed(&mut chain, &mut peer, &visitor_chain);
    assert_eq!(
        chain.height(),
        Some(UNDO),
        "a newcomer read past what it can undo from a peer that said it had nought blocks"
    );
    let held = chain.total_work();
    assert_eq!(
        outgrew,
        Some((UNDO + 1, held)),
        "the block past what the node undoes was not named as what the peer sent, with the \
         work beneath it that this node holds"
    );
    assert_eq!(
        (peer.height, peer.total_work),
        (UNDO + 1, held),
        "the peer is still taken at its word, which says nought blocks and the work of a long \
         chain, after sending more blocks than the network undoes"
    );
}

/// **And the honest chain stays within reach: the branch the visitor left is
/// one the fork choice can still leave, and does, for the chain the choice
/// settles on.**
///
/// The demonstration's own assertion first: the honest chain's block at
/// height one is not refused as too old. Then the honest chain arrives from
/// the peer the node's choice fell on, which the node says through
/// [`PeerState::chosen`], and the node ends on it.
#[test]
fn a_newcomer_reads_no_further_than_it_can_undo_from_the_peer_that_said_it_had_nothing() {
    let (honest_chain, visitor_chain) = the_two_chains();
    let mut chain = ChainStore::new(params());
    let (asked, mut visitor) = greeted(&mut chain, 0, 1_000_000);
    assert!(asked, "fixture: the understated claim is asked for");
    pushed(&mut chain, &mut visitor, &visitor_chain);

    let refused = chain.add_block(honest_chain[1].clone(), NOW);
    assert!(
        !matches!(refused, Err(ChainError::TooOld { .. })),
        "a newcomer pushed {} blocks by a peer that claimed nought is out of reach of the \
         honest chain: {refused:?}",
        visitor_chain.len()
    );

    let mut chosen = PeerState {
        greeted: true,
        chosen: true,
        ..PeerState::default()
    };
    pushed(&mut chain, &mut chosen, &honest_chain);
    assert_eq!(
        chain.tip(),
        honest_chain.last().map(Block::id),
        "the newcomer did not end on the honest chain once the choice fell on its peer"
    );
}

/// **A node holding more than it undoes takes a block from any peer at
/// once.** The hold is on a node that could still give up everything it
/// holds, and an ordinary node following the network is not one.
#[test]
fn a_node_past_what_it_undoes_takes_blocks_from_anybody() {
    let (honest_chain, _) = the_two_chains();
    let mut chain = ChainStore::new(params());
    let past = usize::try_from(UNDO).unwrap() + 2;
    for block in &honest_chain[..past] {
        chain.add_block(block.clone(), NOW).unwrap();
    }
    let mut stranger = PeerState {
        greeted: true,
        ..PeerState::default()
    };
    let outgrew = pushed(&mut chain, &mut stranger, &honest_chain[past..]);
    assert_eq!(
        (chain.tip(), outgrew),
        (honest_chain.last().map(Block::id), None),
        "a node already past what it undoes held back blocks from a peer it had not chosen"
    );
}

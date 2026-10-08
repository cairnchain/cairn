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
//! Real nodes over the loopback, on a network that undoes twelve blocks. The
//! visitor's chain is cheap and shorter than the honest one; what it has is
//! being first.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
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
/// behind them, and pushes `blocks` one message each, as a peer may. It keeps
/// the connection alive and answers nothing else.
fn visit(newcomer: SocketAddr, work: u128, blocks: &[Block]) -> TcpStream {
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
    for block in blocks {
        write_message(
            &mut socket,
            network,
            &Message::Block(Box::new(block.clone())),
        )
        .unwrap();
    }
    let mut reading = socket.try_clone().unwrap();
    thread::spawn(move || loop {
        let message = match read_message(&mut reading, network, MAX_FRAME_BYTES) {
            Ok(Incoming::Message(message)) => message,
            Ok(Incoming::Quiet) => continue,
            Err(_) => return,
        };
        let answer = match message {
            Message::GetPeers => Message::Peers(Vec::new()),
            Message::Ping(nonce) => Message::Pong(nonce),
            _ => continue,
        };
        if write_message(&mut reading, network, &answer).is_err() {
            return;
        }
    });
    socket
}

/// **A newcomer a visitor reaches first, saying it has nought blocks and
/// pushing one more than the network undoes, still ends on the honest chain
/// once its seed answers.**
#[test]
fn a_visitor_that_said_it_had_nothing_does_not_keep_a_newcomer_off_the_honest_chain() {
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
    let visitor = visit(
        newcomer.address(),
        seed.total_work().saturating_mul(1_000),
        &visitor_chain,
    );
    assert!(
        wait_until(PATIENCE, || newcomer
            .height()
            .is_some_and(|height| height >= UNDO)),
        "fixture: the newcomer read the visitor's chain as far as it undoes, and is at {:?}",
        newcomer.height()
    );
    let after_the_push = newcomer.height();

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
        "a newcomer that a visitor saying it had nought blocks reached first read its chain to \
         height {after_the_push:?}, and {PATIENCE:?} after its seed answered it was at height \
         {height:?}, on the visitor's chain: {on_the_visitor}, rather than on the honest chain \
         of {HONEST_BLOCKS} blocks, which forks below what it can undo"
    );
}

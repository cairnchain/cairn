//! What a node does about blocks it turns out not to be able to read.
//!
//! The ledger settles the verdict on one such block and the chain settles what
//! is remembered about it. This is the layer above both: what is done to the
//! peer that sent it, and what the node ends up able to say about itself.
//!
//! The verdict is deliberately not a judgement about the block. A version
//! above anything this build knows becomes readable the moment the build is
//! replaced, so it says something about the reader; it is not remembered, and
//! the messenger is not blamed. Getting that right left a hole, which is that
//! an un-updated node then refused the real chain in silence. These tests hold
//! both halves.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, ConsensusParams, TransferError,
};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::wire::write_message;
use cairn_net::Node;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Produces blocks on a private ledger, so a branch exists without a node
/// having to follow it.
struct Miner {
    state: LedgerState,
    clock: u64,
}

impl Miner {
    fn new() -> Self {
        Self {
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    /// A block for the next height, optionally claiming a version this build
    /// has no rules for.
    ///
    /// Mined, because the work is checked before anything about the version
    /// is: the identifier covers the header, so changing the version changes
    /// what has to be found.
    fn candidate(&mut self, version: Option<u16>) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, wallet(1).public_key())],
        );
        let mut block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
            &params,
            self.clock + 600,
            0,
        )
        .unwrap();
        if let Some(version) = version {
            block.header.version = version;
        }
        mine_block(block, ATTEMPTS).expect("a nonce exists")
    }

    fn mine(&mut self) -> Block {
        let block = self.candidate(None);
        self.clock += 600;
        connect_block(&mut self.state, &block, &params(), NOW).unwrap();
        block
    }
}

fn greeted() -> PeerState {
    PeerState {
        greeted: true,
        ..PeerState::new(None)
    }
}

fn solo(chain: &mut ChainStore) -> Local<'_> {
    Local {
        shows_the_chain: true,
        nonce: 1,
        chain,
        listen: 4242,
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn hello(nonce: u64) -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen: 4_242,
        nonce,
        archives: false,
    })
}

fn wait_until(patience: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    ready()
}

/// The same, through a real node over a real socket.
///
/// The arm this pins sits in the pure layer, and everything downstream of it
/// is plumbing: the reaction is read in the peer's own thread, and a
/// `drop_peer` there both ends the connection and writes the host down as one
/// to turn away for a while. This is the plumbing, since that is where the
/// cost to the network actually lands.
#[test]
fn a_real_node_keeps_the_peer_that_brought_it_a_block_it_cannot_read() {
    let mut miner = Miner::new();
    let settled: Vec<Block> = (0..5).map(|_| miner.mine()).collect();
    let unreadable = miner.candidate(Some(BLOCK_VERSION + 1));

    let node = Node::bind(params(), loopback()).unwrap();
    for block in &settled {
        node.submit_block(block.clone()).unwrap();
    }

    let mut socket = TcpStream::connect(node.address()).unwrap();
    write_message(&mut socket, params().network, &hello(4_711)).unwrap();
    assert!(
        wait_until(Duration::from_secs(5), || node.peer_count() == 1),
        "the peer never arrived, so nothing below is being tested"
    );

    write_message(
        &mut socket,
        params().network,
        &Message::Block(Box::new(unreadable)),
    )
    .unwrap();

    // Long enough that a connection being torn down would have been. The
    // question is what the node settled on, not what it had got to.
    let dropped = wait_until(Duration::from_secs(3), || node.peer_count() == 0);
    let held = node.peer_count();
    let height = node.height();
    node.shutdown();

    assert!(
        !dropped,
        "the connection was closed and the host refused, for a block this build \
         cannot read and an update would make readable: every peer that had \
         updated would be dropped, one message each"
    );
    assert_eq!(held, 1);
    assert_eq!(height, Some(4), "and the block is still not followed");
}

/// The claim, from `check_header`: "Deciding that a run of these means the
/// chain has moved rather than that somebody is talking nonsense needs
/// evidence from more than one block and more than one peer, and that belongs
/// where peers are counted."
///
/// It was written as though this layer already did that. It did not. The
/// verdict fell through to the last arm of `on_block`, which answers
/// `DropReason::BadBlock`, and `is_misbehaviour` reports that as true: the
/// connection closed and the host was refused. So the release that made the
/// chain stop condemning the block left the node condemning the messenger, and
/// the messenger is every peer that had updated.
#[test]
fn a_block_this_build_cannot_read_costs_the_peer_nothing() {
    let mut miner = Miner::new();
    let settled: Vec<Block> = (0..5).map(|_| miner.mine()).collect();
    let unreadable = miner.candidate(Some(BLOCK_VERSION + 1));

    let mut chain = ChainStore::new(params());
    for block in &settled {
        chain.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(chain.height(), Some(4));

    let mut peer = greeted();
    let reaction = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Block(Box::new(unreadable.clone())),
        NOW,
    );

    assert!(
        reaction.drop_peer.is_none(),
        "the peer was dropped for carrying what its own chain carries: {:?}",
        reaction.drop_peer
    );
    assert_eq!(
        reaction.unjudged,
        Some(BLOCK_VERSION + 1),
        "and the version is named, which is what a person needs to see"
    );
    assert!(
        reaction.applied.is_none(),
        "the block is still not followed; this build cannot judge it"
    );
    assert_eq!(chain.height(), Some(4), "and the node stands where it was");
    assert!(
        reaction.outdated.is_none(),
        "nor is this the answer that stops a node, which a stranger could then ask for"
    );
}

/// The same block, offered twice by the same peer.
///
/// Nothing is remembered against it, because an update reverses the verdict,
/// so the second offer is judged again and answered the same way. What must
/// not happen is the count of these being fed by one block sent twice looking
/// like two separate pieces of evidence: the counting is by arrival, and it is
/// the peers and the stretch of time that carry the weight. This pins the
/// layer's half, which is that the answer does not drift.
#[test]
fn the_same_unreadable_block_is_answered_the_same_way_every_time() {
    let mut miner = Miner::new();
    let settled: Vec<Block> = (0..5).map(|_| miner.mine()).collect();
    let unreadable = miner.candidate(Some(BLOCK_VERSION + 1));

    let mut chain = ChainStore::new(params());
    for block in &settled {
        chain.add_block(block.clone(), NOW).unwrap();
    }
    let mut peer = greeted();
    for round in 0..4 {
        let reaction = on_message(
            &mut solo(&mut chain),
            &mut peer,
            Message::Block(Box::new(unreadable.clone())),
            NOW,
        );
        assert!(reaction.drop_peer.is_none(), "round {round}");
        assert_eq!(reaction.unjudged, Some(BLOCK_VERSION + 1), "round {round}");
    }
}

/// And a block that is simply bad is still a bad block.
///
/// The arm above matches one verdict and no others. Without this test it could
/// widen without anybody noticing, and a node that stopped blaming peers for
/// bad blocks would be a node anybody could feed anything.
#[test]
fn a_block_that_is_merely_invalid_still_costs_the_peer_the_connection() {
    let mut miner = Miner::new();
    let settled: Vec<Block> = (0..5).map(|_| miner.mine()).collect();
    let mut broken = miner.candidate(None);
    // A coinbase paying itself more than the rules allow: a fault of the body,
    // reached after the version and settled by this build's own rules.
    broken.coinbase = CoinbaseTransaction::new(
        broken.header.height,
        vec![Note::new(
            params()
                .initial_reward
                .checked_add(params().initial_reward)
                .unwrap(),
            wallet(1).public_key(),
        )],
    );

    let mut chain = ChainStore::new(params());
    for block in &settled {
        chain.add_block(block.clone(), NOW).unwrap();
    }
    let mut peer = greeted();
    let reaction = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Block(Box::new(broken)),
        NOW,
    );
    assert!(
        reaction.drop_peer.is_some(),
        "a block this build can judge and finds bad is the peer's fault"
    );
    assert!(reaction.unjudged.is_none());
}

/// A transfer version this build does not know is a different question, and
/// this is here so the two are not confused.
///
/// A transfer is a stranger's message about a stranger's money. There is no
/// chain of them, no work behind one, and nothing a run of them says about
/// this build; whoever sent it can simply be wrong. Nothing is counted.
#[test]
fn an_unreadable_transfer_says_nothing_about_this_build() {
    let error = TransferError::UnsupportedVersion(9);
    assert_eq!(
        error.to_string(),
        "transfer version 9 is not supported",
        "named where it belongs, and nowhere near the block count"
    );
}

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

use cairn_chain::{ChainStore, Outdated};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, Block, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, ConsensusParams, TransferError,
};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::wire::write_message;
use cairn_net::Keeps;
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
        keeps: Keeps {
            headers: true,
            cold_set: false,
        },
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
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
    })
}

///
/// `patience` is a liveness bound and not a measurement: it costs nothing when
/// the condition is met, so the only thing a short one buys is a failure that
/// says nothing about the code. This suite has had three of those in one day,
/// at fifteen seconds, at a minute, and at twenty milliseconds, each green on a
/// quiet machine and red on a busy one. They are set far past anything a loaded
/// runner does rather than near it.
/// Reads everything a node sends down `socket` and answers nothing.
///
/// A test that opens a socket, says one thing and then goes quiet is modelling
/// a peer that has nothing to say. A socket nobody reads from is a different
/// thing: the node goes on sending, the receive buffer fills, a write times
/// out and the connection is closed. That is the node behaving correctly and
/// it has nothing to do with what this test is about, but it lands in the same
/// place, `peer_count` going to zero, which this reads as the node having
/// judged the peer.
///
/// How long it takes depends on how much the node happens to send and when the
/// scheduler runs it, so it is not a thing a deadline can be set around.
/// Draining the socket removes it rather than racing it. The same helper, and
/// the same reason, as `audit_clock_drift.rs`.
fn drain(socket: &TcpStream) {
    let Ok(mut reading) = socket.try_clone() else {
        return;
    };
    std::thread::spawn(move || {
        let mut scratch = [0u8; 4096];
        while let Ok(read) = std::io::Read::read(&mut reading, &mut scratch) {
            if read == 0 {
                return;
            }
        }
    });
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
    drain(&socket);
    write_message(&mut socket, params().network, &hello(4_711)).unwrap();
    assert!(
        wait_until(Duration::from_secs(60), || node.peer_count() == 1),
        "the peer never arrived, so nothing below is being tested"
    );

    write_message(
        &mut socket,
        params().network,
        &Message::Block(Box::new(unreadable)),
    )
    .unwrap();

    // Long enough that a connection being torn down would have been, and no
    // longer. This is the one shape of deadline where more is worse: what is
    // asserted is that nothing happened, so every second added is another
    // second in which something unrelated may. A drop caused by this block is
    // worked out in the peer's own thread as the message is read, which is
    // milliseconds.
    //
    // It was three seconds, and a sweep that raised fifteen liveness deadlines
    // raised it too. That sweep was right about the fourteen and exactly wrong
    // about this one.
    let dropped = wait_until(Duration::from_secs(10), || node.peer_count() == 0);
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

/// A rule change scheduled at height five, written under a version this build
/// does not have. What a node looks like once it has been told the network is
/// moving and has not been updated.
const ANNOUNCED: &[Activation] = &[
    Activation {
        height: 0,
        version: BLOCK_VERSION,
    },
    Activation {
        height: 5,
        version: BLOCK_VERSION + 1,
    },
];

/// A node whose own schedule has passed its build says so, and says it about
/// itself.
///
/// The test above is the node that has *not* been told: nothing is scheduled,
/// so the block never reaches `SoftwareTooOld`, and the answer is `unjudged`
/// with `outdated` empty. This is the other one, and it is the case the
/// machinery was built for: the schedule says height five is judged by rules
/// this build does not have, so nothing about the block is in question and
/// nothing about the peer is either.
///
/// Neither of the two things that carry it was measured. The guard that reads
/// `ChainError::outdated` can be read as false and the field can be deleted
/// from the answer, and the whole of `cairn-net` stays green. Read as false,
/// the refusal falls through to the arm that answers a bad block, so a node
/// that has been told the network moved on closes the connection and holds it
/// against every peer that has updated. With the field gone it does not close
/// anything, and simply never says why it stopped following the chain.
///
/// The three fields apart is the point. `outdated` stops the node and is the
/// one answer a stranger must not be able to ask for, which is why it is
/// reached from this node's own schedule and never from what a block claims.
#[test]
fn a_node_whose_schedule_has_passed_its_build_says_so_about_itself() {
    let mut miner = Miner::new();
    let settled: Vec<Block> = (0..5).map(|_| miner.mine()).collect();
    // Mined by a network that has the rules, at the height the change governs.
    let at_the_change = miner.candidate(None);
    assert_eq!(at_the_change.header.height, 5);

    let announced = ConsensusParams {
        activations: ANNOUNCED,
        ..params()
    };
    let mut chain = ChainStore::new(announced);
    for block in &settled {
        chain.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(
        chain.height(),
        Some(4),
        "everything under the change applies"
    );

    let mut peer = greeted();
    let reaction = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Block(Box::new(at_the_change)),
        NOW,
    );

    assert_eq!(
        reaction.drop_peer, None,
        "the peer carried what its own chain carries, and closing on it cuts \
         off everyone who has updated"
    );
    assert_eq!(
        reaction.outdated,
        Some(Outdated {
            height: 5,
            required: BLOCK_VERSION + 1,
            known: BLOCK_VERSION,
        }),
        "a node that stops following the chain here and does not say why \
         leaves its operator with a height that stopped moving and nothing to \
         read"
    );
    assert!(
        reaction.applied.is_none(),
        "the block is not followed: this build cannot judge it"
    );
    assert!(
        reaction.unreachable.is_none(),
        "and this is not a place the node cannot get back from; an update \
         gets it back"
    );
    assert_eq!(chain.height(), Some(4), "the node stands where it was");
}

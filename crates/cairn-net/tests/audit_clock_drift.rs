//! What a node does about a block dated ahead of its own clock.
//!
//! This is the one refusal in the whole rule set that two honest nodes can
//! disagree about, and that the same node reverses simply by waiting. Every
//! other verdict is a fact about the block: two nodes handed the same bytes
//! reach the same answer, today and next year. This one is measured against a
//! clock the reading machine keeps, so what it says is half about the reader.
//!
//! `cairn_chain::ChainError::settles_the_header` already knows that and leaves
//! the verdict out of what a chain remembers, with a comment ending: "those
//! nodes refused the whole chain through it and blamed every honest peer that
//! offered it." The second clause stayed true one layer up, here, where the
//! refusal fell through to `DropReason::BadBlock`: the connection closed and
//! the host was refused for ten minutes.
//!
//! The arithmetic, which is the whole of why it matters. A miner whose clock
//! is an hour and fifty eight minutes fast publishes a block that is valid to
//! everybody whose clock is right. A node two minutes slow refuses it, and
//! then refuses every peer that offers it, and `dial_from_book` will not dial
//! a refused host back either. It needed to wait a hundred and twenty seconds.
//! It bought six hundred seconds of having no peers at all and charged them to
//! peers that had done nothing wrong.

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
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::wire::write_message;
use cairn_net::Keeps;
use cairn_net::Node;
use cairn_primitives::Hash32;

const ATTEMPTS: u64 = 1 << 22;

/// This machine's own clock, which is the one a running node reads.
///
/// The blocks here are dated against it rather than against a fixed number, so
/// that a node started in this test accepts the settled ones. Nothing is
/// measured against it: what each test asserts is a difference between two
/// timestamps it computed itself.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

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
            clock: now() - 10_000,
        }
    }

    /// A block for the next height, dated `ahead` seconds past the miner's own
    /// clock.
    ///
    /// Mined, because the work behind the identifier is checked before the
    /// timestamp is looked at, and the identifier covers the timestamp.
    fn candidate(&mut self, ahead: u64) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, wallet(1).public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
            &params,
            self.clock + 600 + ahead,
            0,
        )
        .unwrap();
        mine_block(block, ATTEMPTS).expect("a nonce exists")
    }

    fn mine(&mut self) -> Block {
        let block = self.candidate(0);
        self.clock += 600;
        connect_block(&mut self.state, &block, &params(), self.clock).unwrap();
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

fn hello(nonce: u64, listen: u16) -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen,
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

/// A settled chain, and one more block dated past what a node running slightly
/// slow will accept.
fn a_chain_and_a_block_from_the_future(ahead: u64) -> (Vec<Block>, Block) {
    let mut miner = Miner::new();
    let settled: Vec<Block> = (0..5).map(|_| miner.mine()).collect();
    let future = miner.candidate(ahead);
    (settled, future)
}

/// **The refusal that a node reverses by waiting must not be charged to
/// whoever carried it.**
///
/// AUDIT, repaired. The verdict fell through to the last arm of `on_block`,
/// which answers `DropReason::BadBlock`, and `is_misbehaviour` reports that as
/// true: the connection closed and the host was refused for `REFUSAL_SECONDS`.
#[test]
fn a_block_dated_past_this_clock_costs_the_peer_nothing() {
    let drift = params().max_timestamp_drift;
    let (settled, future) = a_chain_and_a_block_from_the_future(drift + 120);

    let mut chain = ChainStore::new(params());
    for block in &settled {
        chain.add_block(block.clone(), now()).unwrap();
    }
    assert_eq!(chain.height(), Some(4));

    // The reading node's clock, which is where the block's own timestamp
    // stands 120 seconds past the drift.
    let now = future.header.timestamp - drift - 120;
    let mut peer = greeted();
    let reaction = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Block(Box::new(future.clone())),
        now,
    );

    assert!(
        reaction.drop_peer.is_none(),
        "the peer was dropped for carrying a block valid to everybody whose \
         clock is right: {:?}",
        reaction.drop_peer
    );
    assert_eq!(
        reaction.ahead_of_the_clock,
        Some(drift + 120),
        "and how far ahead of this clock it stood is named, which is the only \
         thing in this node that can say a clock is wrong"
    );
    assert!(
        reaction.applied.is_none(),
        "the block is still not taken; this node has to wait for it"
    );
    assert_eq!(chain.height(), Some(4));
    assert!(
        reaction.reply.is_empty(),
        "and nothing is asked again, which would be a loop: the same peer \
         would send the same block back at once"
    );
}

/// The whole point of the number: waiting is what fixes it.
///
/// The same block, the same peer and the same node, two minutes later.
#[test]
fn the_same_block_is_taken_once_the_clock_has_caught_up() {
    let drift = params().max_timestamp_drift;
    let (settled, future) = a_chain_and_a_block_from_the_future(drift + 120);

    let mut chain = ChainStore::new(params());
    for block in &settled {
        chain.add_block(block.clone(), now()).unwrap();
    }
    let refused_at = future.header.timestamp - drift - 120;

    let mut peer = greeted();
    let refused = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Block(Box::new(future.clone())),
        refused_at,
    );
    assert!(refused.applied.is_none());

    let taken = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Block(Box::new(future)),
        refused_at + 120,
    );
    assert!(
        taken.applied.is_some(),
        "a hundred and twenty seconds is all this ever needed, and the old \
         answer spent six hundred of them with no peers instead"
    );
    assert_eq!(chain.height(), Some(5));
}

/// The same block from the same peer, over and over, while the clock is still
/// behind.
///
/// Nothing is remembered against it, so each offer is judged again. What must
/// not happen is the answer drifting: a peer that gets a different verdict
/// each time is a peer this node will eventually drop for something it did
/// once.
#[test]
fn a_block_ahead_of_the_clock_is_answered_the_same_way_every_time() {
    let drift = params().max_timestamp_drift;
    let (settled, future) = a_chain_and_a_block_from_the_future(drift + 120);

    let mut chain = ChainStore::new(params());
    for block in &settled {
        chain.add_block(block.clone(), now()).unwrap();
    }
    let now = future.header.timestamp - drift - 120;

    let mut peer = greeted();
    for round in 0..4 {
        let reaction = on_message(
            &mut solo(&mut chain),
            &mut peer,
            Message::Block(Box::new(future.clone())),
            now,
        );
        assert!(reaction.drop_peer.is_none(), "round {round}");
        assert_eq!(
            reaction.ahead_of_the_clock,
            Some(drift + 120),
            "round {round}"
        );
    }
}

/// And a block that is simply bad is still a bad block.
///
/// The arm matches one verdict and no others. Without this it could widen
/// without anybody noticing, and a node that stopped blaming peers for bad
/// blocks would be a node anybody could feed anything.
#[test]
fn a_block_that_is_merely_invalid_still_costs_the_peer_the_connection() {
    let mut miner = Miner::new();
    let settled: Vec<Block> = (0..5).map(|_| miner.mine()).collect();
    let mut broken = miner.candidate(0);
    // A coinbase paying itself more than the rules allow: a fault of the body,
    // settled by this build's own rules and by nobody's clock.
    broken.coinbase = CoinbaseTransaction::new(
        broken.header.height,
        vec![Note::new(
            params()
                .initial_reward
                .checked_add(params().initial_reward)
                .unwrap(),
            wallet(2).public_key(),
        )],
    );
    let broken = mine_block(broken, ATTEMPTS).expect("a nonce exists");

    let mut chain = ChainStore::new(params());
    for block in &settled {
        chain.add_block(block.clone(), now()).unwrap();
    }
    let mut peer = greeted();
    let reaction = on_message(
        &mut solo(&mut chain),
        &mut peer,
        Message::Block(Box::new(broken)),
        now(),
    );
    assert!(
        reaction.drop_peer.is_some(),
        "a block whose body breaks the rules is the peer's doing and always was"
    );
    assert!(
        reaction.drop_peer.unwrap().is_misbehaviour(),
        "and it is worth turning the address away for a while"
    );
    assert!(reaction.ahead_of_the_clock.is_none());
}

/// The same, through a real node over a real socket.
///
/// The arm this pins sits in the pure layer, and everything downstream of it
/// is plumbing: the reaction is read in the peer's own thread, and a
/// `drop_peer` there both ends the connection and writes the host down as one
/// to turn away for a while. This is where the cost to the network lands, so
/// this is where it is measured.
///
/// The node's own clock is the real one, so the block is dated past it by more
/// than the drift and the node is the one running behind. That is the honest
/// shape of the scenario: nobody has to move a clock for this to happen, a
/// miner two hours fast is enough.
#[test]
fn a_real_node_keeps_the_peer_that_offered_a_block_its_clock_is_behind() {
    let mut miner = Miner::new();
    let settled: Vec<Block> = (0..5).map(|_| miner.mine()).collect();

    let node = Node::bind(params(), loopback()).unwrap();
    for block in &settled {
        node.submit_block(block.clone()).unwrap();
    }

    // Dated past the running node's own clock, which is now.
    let mut future = miner.candidate(0);
    future.header.timestamp = now() + params().max_timestamp_drift + 120;
    let future = mine_block(future, ATTEMPTS).expect("a nonce exists");

    let mut socket = TcpStream::connect(node.address()).unwrap();
    write_message(&mut socket, params().network, &hello(4_711, 4_242)).unwrap();
    assert!(
        wait_until(Duration::from_secs(60), || node.peer_count() == 1),
        "the peer never arrived, so nothing below is being tested"
    );

    write_message(
        &mut socket,
        params().network,
        &Message::Block(Box::new(future)),
    )
    .unwrap();

    // Long enough that a connection being torn down would have been. The
    // question is what the node settled on, not what it had got to.
    let dropped = wait_until(Duration::from_secs(60), || node.peer_count() == 0);
    let held = node.peer_count();
    let height = node.height();
    node.shutdown();

    assert!(
        !dropped,
        "the connection was closed over a block this node itself would accept \
         two minutes later. As `BadBlock` that also refused the host for ten \
         minutes, so the node refused its whole address book within seconds \
         and could not dial any of it back; as any other close it dials back \
         and is offered the same block again, which is a loop"
    );
    assert_eq!(held, 1);
    assert_eq!(height, Some(4), "and the block is still not followed");
}

/// **A machine refusing these from everybody is told so.**
///
/// One is a number a stranger wrote in a field and is worth nothing. A run of
/// them from more than one peer is this machine's clock, and before this
/// nothing in the node said the word clock to anybody.
#[test]
fn a_run_of_them_from_two_peers_tells_the_operator_about_the_clock() {
    let mut miner = Miner::new();
    let settled: Vec<Block> = (0..5).map(|_| miner.mine()).collect();

    let node = Node::bind(params(), loopback()).unwrap();
    for block in &settled {
        node.submit_block(block.clone()).unwrap();
    }
    assert!(
        node.clock_behind().is_none(),
        "a node that has refused nothing says nothing"
    );

    let ahead = params().max_timestamp_drift + 900;
    let mut future = miner.candidate(0);
    future.header.timestamp = now() + ahead;
    let future = mine_block(future, ATTEMPTS).expect("a nonce exists");

    // Two connections advertising two different ports, which is two peers as
    // this node counts them, offering the block four times each.
    let mut sockets = Vec::new();
    for (nonce, listen) in [(4_711u64, 4_242u16), (4_712, 4_243)] {
        let mut socket = TcpStream::connect(node.address()).unwrap();
        write_message(&mut socket, params().network, &hello(nonce, listen)).unwrap();
        sockets.push(socket);
    }
    assert!(
        wait_until(Duration::from_secs(60), || node.peer_count() == 2),
        "both peers never arrived, so nothing below is being tested"
    );
    for _ in 0..4 {
        for socket in &mut sockets {
            write_message(
                socket,
                params().network,
                &Message::Block(Box::new(future.clone())),
            )
            .unwrap();
        }
    }

    let said = wait_until(Duration::from_secs(60), || node.clock_behind().is_some());
    let behind = node.clock_behind();
    node.shutdown();

    assert!(
        said,
        "eight blocks from two peers, every one refused for standing ahead of \
         this machine's clock, and the node had nothing to say about a clock"
    );
    let behind = behind.unwrap();
    assert!(behind.blocks >= 8);
    assert_eq!(behind.peers, 2);
    assert_eq!(behind.drift, params().max_timestamp_drift);
    // The gap is the block's own timestamp against the node's own clock, and
    // the node read its clock a moment after this test read the same one, so
    // the two differ by whatever the machine was doing in between. What is
    // pinned is that the gap is the one that was actually met: no larger than
    // what was sent, and past the drift, which is the whole of what tells an
    // operator the clock rather than the block is the thing to look at.
    assert!(
        behind.seconds > behind.drift && behind.seconds <= ahead,
        "the gap reported was {} against a block sent {ahead} ahead",
        behind.seconds
    );
    assert!(
        !behind.own_first_block,
        "these came off the wire, not out of the binary"
    );
}

/// The same rule, applied to this node's own disk, which is worse.
///
/// A node replays its stored log at every start. That replay judged each block
/// against the clock, and a clock can step back: an NTP correction, a restored
/// snapshot, a dead battery, a machine that dual boots. Then the node refuses
/// its own blocks, the replay stops at the first one, and everything past it is
/// counted refused and dropped from the log.
///
/// What made it permanent rather than merely expensive is the recovery.
/// `Restored::refused` is documented as losing nothing but time, because what
/// was cut is asked for again. It is asked for again, the peers hand it back,
/// and this node refuses it again for the same reason, because the reason is
/// this machine's clock and nothing about the block. So the node stands at that
/// height for as long as the clock is wrong.
///
/// Judged against the block's own timestamp now, which is the question the
/// block already answered when this node wrote it down.
#[test]
fn a_node_whose_clock_stepped_back_still_reads_its_own_chain() {
    let mut miner = Miner::new();
    // Where this machine's clock stood when it accepted these, which is well
    // past where it stands now. Mining them is what makes them real: the work
    // covers the timestamp, so they cannot be dated after the fact.
    miner.clock = now() + params().max_timestamp_drift + 3_600;
    let chain: Vec<Block> = (0..5).map(|_| miner.mine()).collect();
    let tip = chain.last().unwrap().header.height;

    let directory = std::env::temp_dir().join(format!("cairn-clock-back-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    {
        let (mut log, _) = cairn_store::BlockLog::open(&directory).unwrap();
        for block in &chain {
            log.append(block).unwrap();
        }
        assert_eq!(log.len(), chain.len(), "the disk holds the whole chain");
    }

    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    let height = node.height();
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        height,
        Some(tip),
        "a node read its own log back against a clock that had stepped behind \
         the blocks in it, refused them for being dated ahead of a machine that \
         had written them itself, and came back short. The peers hand them back \
         and it refuses them again, so it stays there while the clock is wrong."
    );
    assert_eq!(
        restored.refused, 0,
        "and nothing was cut from the log for it"
    );
}

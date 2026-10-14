//! A peer the choice asks to read is weighed before its branch ends the choice.
//!
//! The choice falls first on the peer claiming the most work, which is a
//! number in its greeting that nothing checks, and a peer that says it keeps
//! no headers is read rather than weighed. While the choice is open, the peer
//! it fell on is the one peer a block past the depth a node undoes is taken
//! from, and taking that block is the choice made for good: a chain parting
//! from it at the first block is out of reach from then on. So a visitor that
//! claimed more than the honest chain beside it, said it kept no headers and
//! pushed a branch from the first block mined at the lowest difficulty there
//! is, one block past the depth, left a newcomer for good on a chain carrying
//! next to no work, for about a second of its own CPU.
//!
//! That block is now weighed against every other claim standing in front of
//! the choice, and a branch carrying less is not taken: the peer is ranked by
//! what it sent and the turn goes to the next claim. On the message layer,
//! with the chooser's figures handed down by hand as the node hands them down,
//! and with real nodes over the loopback, where the visitor is asked first.
//!
//! On a network that undoes eight blocks, so the visitor's branch is ten
//! blocks rather than a thousand and twenty six; nothing on the path reads
//! that number, and the ramp to the floor is in the fixture and asserted.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
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
use cairn_net::choosing::{Approach, Chooser, JoinProgress, Step};
use cairn_net::message::{Handshake, Keeps, Message, PROTOCOL_VERSION};
use cairn_net::sync::{holds_nothing_it_cannot_undo, on_message, Local, PeerState, Reaction};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;

/// The depth this network undoes.
const UNDO: u64 = 8;

/// Blocks the honest seed holds, the first block among them.
const HONEST_BLOCKS: usize = 20;

/// How long the honest chain is given once both peers are reached. A liveness
/// bound on a loaded runner, not a measurement: the last test measures.
const PATIENCE: Duration = Duration::from_secs(90);

/// Seconds a node gives the peer its choice asked to produce something before
/// giving up on it: `choosing::FIRST_ANSWER_PATIENCE`, private to the crate.
const ANSWERING_WINDOW: u64 = 30;

const NO_HEADERS: Keeps = Keeps {
    headers: false,
    cold_set: false,
};

fn rules() -> ConsensusParams {
    ConsensusParams::mineable_network(UNDO)
}

fn host(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
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
/// half life late every time, which is the most the retarget takes in one
/// step, so it walks down to the floor and stays there. Its last block is the
/// one past the depth a node undoes.
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
        "fixture: the visitor's branch reaches the floor, so the rest of it is one hash a block"
    );
    assert!(
        visitor_chain.last().unwrap().header.total_work
            < honest_chain[usize::try_from(UNDO).unwrap()]
                .header
                .total_work,
        "fixture: the visitor's branch past the depth carries less than the honest chain's \
         blocks up to it"
    );
    (honest_chain, visitor_chain)
}

/// **Half one: who the choice asks first, and what that read is held to.**
///
/// A newcomer hears two claims. Peer 1 is honest and keeps headers. Peer 2
/// says it keeps no headers and claims more work than any chain will ever
/// carry, which costs nothing to say. The first turn still goes to peer 2,
/// read: whom to ask first is a question about words, and a read checks every
/// block as it arrives. What changed is what the read is held to before it
/// can end the choice, which is the work peer 1 claims, and that once its
/// branch falls short of that the turn goes to peer 1.
///
/// The report's first half asserted that peer 2 is not handed the first turn
/// at all. Not kept: the turn costs one answering window at most, which the
/// last test measures, while refusing a read to a claim nothing has proved
/// would refuse it to every honest peer that keeps no headers, and to every
/// claim on a network where nobody has shown anything yet.
#[test]
fn the_heaviest_unchecked_claim_read_first_is_held_to_the_claims_beside_it() {
    let mut chooser = Chooser::reaching(UNDO);
    chooser.noted(1, Some(host(1)), 900_000, UNDO + 50, true, 100);
    chooser.noted(2, Some(host(2)), u128::MAX, UNDO + 50, false, 100);

    let step = chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2]);
    assert_eq!(
        step,
        Step::Ask(2, Approach::Read),
        "fixture: the first turn"
    );
    assert!(chooser.has_chosen(2), "fixture: the choice fell on peer 2");
    assert_eq!(
        chooser.must_carry(2, 200),
        900_000,
        "a read of a claim nobody checked must end the choice on at least the work the \
         honest peer beside it claims"
    );

    // Its branch reaches the depth carrying 5 467 units and no more.
    chooser.fell_short(2, Some(host(2)), UNDO + 1, 5_467, false, 201);
    assert!(
        !chooser.has_chosen(2),
        "a peer whose branch fell short is still the one blocks past the depth are taken from"
    );
    assert_eq!(
        chooser.step(202, true, 0, JoinProgress::NothingYet, &[1, 2]),
        Step::Ask(1, Approach::Read),
        "the next turn goes to the claim that held the branch off"
    );
    assert_eq!(
        chooser.must_carry(1, 202),
        5_467,
        "and that one is held to what peer 2 sent, not to what it said"
    );
}

/// The visitor's branch, a newcomer with nothing, and a peer greeted as the
/// visitor: keeping no headers and claiming `u128::MAX`.
fn a_newcomer_and_the_visitor() -> (Vec<Block>, ChainStore, PeerState) {
    let (_, branch) = the_two_chains();
    let params = rules();
    let mut chain = ChainStore::new(params);
    assert!(
        holds_nothing_it_cannot_undo(&chain),
        "fixture: the choice is open"
    );
    let mut peer = PeerState::new(Some(host(2)));
    let said = Handshake {
        version: PROTOCOL_VERSION,
        network: params.network,
        genesis: params.genesis.unwrap_or(Hash32::ZERO),
        nonce: 77,
        height: 10_000_000,
        total_work: u128::MAX,
        listen: 4242,
        keeps: NO_HEADERS,
    };
    let mut local = Local {
        keeps: NO_HEADERS,
        nonce: 1,
        chain: &mut chain,
        listen: 4242,
    };
    let met = on_message(&mut local, &mut peer, Message::Hello(said), NOW);
    assert_eq!(met.drop_peer, None, "the claim itself is never refused");
    (branch, chain, peer)
}

/// Hands `branch` to `chain` from `peer` one block at a time, the choice
/// having fallen on the peer and `must_carry` being what the chooser holds it
/// to, both written before every message as the node writes them. What the
/// last block came to.
fn pushed(
    branch: &[Block],
    chain: &mut ChainStore,
    peer: &mut PeerState,
    must_carry: u128,
) -> Reaction {
    let mut last = None;
    for (n, block) in branch.iter().enumerate() {
        peer.chosen = true;
        peer.must_carry = must_carry;
        let mut local = Local {
            keeps: NO_HEADERS,
            nonce: 1,
            chain,
            listen: 4242,
        };
        let out = on_message(
            &mut local,
            peer,
            Message::Block(Box::new(block.clone())),
            NOW,
        );
        assert_eq!(out.drop_peer, None, "block {n} was refused: {out:?}");
        last = Some(out);
    }
    last.unwrap()
}

/// **Half two: what that read can do.**
///
/// The peer the choice fell on serves its branch from the first block, mined
/// at the floor, one block past the depth this node undoes, while an honest
/// claim of 900 000 stands beside it. The last block is not taken: the node
/// is still choosing, and says what the peer's branch carries.
#[test]
fn a_read_cannot_commit_a_newcomer_to_a_floor_difficulty_branch_for_good() {
    let (branch, mut chain, mut peer) = a_newcomer_and_the_visitor();
    let last = pushed(&branch, &mut chain, &mut peer, 900_000);

    let tip = chain.height();
    let work = chain.total_work();
    assert!(
        holds_nothing_it_cannot_undo(&chain),
        "a newcomer was committed for good, on one peer's unchecked word, to a branch of {} \
         blocks carrying {work} units of work: its tip is {tip:?}, past the {UNDO} blocks it \
         undoes, while a claim of 900 000 stood beside it",
        branch.len()
    );
    assert_eq!(tip, Some(UNDO), "everything up to the depth is taken");
    assert_eq!(
        last.fell_short,
        Some((UNDO + 1, work)),
        "the block past the depth is named, with what the branch beneath it carries, for the \
         chooser to rank the peer by"
    );
}

/// **And a branch carrying as much as every other claim states does end it.**
///
/// The same branch, held to exactly the work it carries once its last block
/// is in: what the choice demands is as much as the claims beside it, not
/// more.
#[test]
fn a_branch_carrying_what_the_other_claims_state_ends_the_choice() {
    let (branch, mut chain, mut peer) = a_newcomer_and_the_visitor();
    let carries = branch.last().unwrap().header.total_work;
    let last = pushed(&branch, &mut chain, &mut peer, carries);

    assert!(
        !holds_nothing_it_cannot_undo(&chain),
        "a branch carrying {carries}, which is what the heaviest other claim states, was held off"
    );
    assert_eq!(chain.height(), Some(UNDO + 1));
    assert_eq!(last.fell_short, None);
}

/// Dials `newcomer` as a peer keeping no headers, holding `blocks` and claiming
/// `work`, and serves `blocks[..served]` like any peer: a chain asked for
/// offered from the first block, which a newcomer holding nothing needs, and
/// the heights asked for sent. It
/// answers a request for its chain no oftener than once a second, under the
/// ceiling on messages a node holds a peer to, so that a newcomer is never
/// rescued by the visitor hanging up for flooding. Sets `asked` once it is
/// first asked for a block.
fn visit(
    newcomer: SocketAddr,
    work: u128,
    blocks: &[Block],
    served: usize,
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
        nonce: 0x0F1F_0000,
        keeps: NO_HEADERS,
    });
    write_message(&mut socket, network, &hello).unwrap();
    let mut reading = socket.try_clone().unwrap();
    let held: Vec<Block> = blocks[..served].to_vec();
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

/// A newcomer, an honest seed holding `HONEST_BLOCKS`, and the visitor serving
/// the first `served` blocks of its branch, both reached at once. Panics
/// unless the newcomer ends on the honest chain, and says how long that took
/// from the moment the visitor was first asked for a block.
fn a_newcomer_between_the_seed_and_a_visitor_serving(served: usize) -> Duration {
    let (honest_chain, visitor_chain) = the_two_chains();
    let seed = Node::bind(rules(), loopback()).unwrap();
    for block in &honest_chain {
        seed.submit_block(block.clone()).unwrap();
    }
    let honest_tip = seed.with_chain(ChainStore::tip).unwrap();
    let newcomer = Node::bind(rules(), loopback()).unwrap();
    assert_eq!(
        newcomer.with_chain(ChainStore::undo_limit),
        UNDO,
        "fixture: the depth this network undoes"
    );

    // The visitor claims more than the honest chain, so it is the first claim
    // the choice asks, and the seed's is the claim standing beside it.
    let asked = Arc::new(AtomicBool::new(false));
    let visitor = visit(
        newcomer.address(),
        seed.total_work().saturating_mul(1_000),
        &visitor_chain,
        served,
        &asked,
    );
    newcomer.connect(seed.address()).unwrap();
    assert!(
        wait_until(PATIENCE, || asked.load(Ordering::SeqCst)),
        "fixture: the choice asked the visitor for its branch"
    );
    let first_asked = Instant::now();
    let took_the_honest_chain = wait_until(PATIENCE, || {
        newcomer.with_chain(ChainStore::tip) == Some(honest_tip)
    });
    let took = first_asked.elapsed();
    let (height, on_the_visitor) = (
        newcomer.height(),
        newcomer.id_at(1) == Some(visitor_chain[1].id()),
    );
    let _ = visitor.shutdown(Shutdown::Both);
    newcomer.shutdown();
    seed.shutdown();

    assert!(
        took_the_honest_chain,
        "a newcomer read a visitor claiming more than the honest chain and keeping no headers, \
         serving {served} blocks of a branch at the difficulty floor, and {PATIENCE:?} later it \
         was at height {height:?}, on the visitor's chain: {on_the_visitor}, rather than on \
         the honest chain of {HONEST_BLOCKS} blocks its seed holds"
    );
    took
}

/// **A visitor read first, pushing its branch one block past the depth, does
/// not end the newcomer's choice, and the honest chain is taken.**
///
/// On `main` the newcomer took the visitor's tenth block, held a chain of ten
/// blocks it could no longer undo, and never took the honest chain.
#[test]
fn a_visitor_read_first_cannot_end_a_newcomer_s_choice_on_a_floor_difficulty_branch() {
    a_newcomer_between_the_seed_and_a_visitor_serving(usize::try_from(UNDO).unwrap() + 2);
}

/// **How long such a visitor holds the newcomer off: one turn, ended by the
/// answering window after the last block it sends.**
///
/// The visitor serves its branch up to the depth and then nothing, so its turn
/// is not ended by a block past the depth but by its answering window. From
/// the moment it is first asked for a block, the newcomer is on the honest
/// chain within that window, a round of upkeep to hand the next turn out, and
/// the seconds the honest chain takes over the loopback. A visitor that does
/// send the block past the depth, as above, ends its turn at once. One that
/// sends its blocks a window apart renews its turn once for each height it
/// raises the branch to, which is at most the depth the node undoes.
#[test]
fn a_visitor_that_goes_quiet_at_the_depth_holds_a_newcomer_off_for_one_answering_window() {
    let took =
        a_newcomer_between_the_seed_and_a_visitor_serving(usize::try_from(UNDO).unwrap() + 1);
    let bound = Duration::from_secs(ANSWERING_WINDOW + 10);
    assert!(
        took <= bound,
        "the honest chain was taken {took:?} after the visitor was first asked, past the \
         bound of {bound:?}: one answering window, a round of upkeep and the honest read"
    );
}

/// **A young network where everybody reads still syncs at once.**
///
/// Two honest seeds holding the same chain, longer than the depth a node
/// undoes and far shorter than one it is handed: the newcomer reads it. The
/// first seed asked has its block past the depth held off by the claim of the
/// second, which states the whole chain's work; it is ranked by what it sent,
/// the second is asked, and its block past the depth carries more than that.
/// One turn more than before, a round of upkeep, and no waiting on anybody.
#[test]
fn a_newcomer_between_two_honest_seeds_that_are_read_takes_the_chain_at_once() {
    let (honest_chain, _) = the_two_chains();
    let seeds: Vec<Node> = (0..2)
        .map(|_| {
            let seed = Node::bind(rules(), loopback()).unwrap();
            for block in &honest_chain {
                seed.submit_block(block.clone()).unwrap();
            }
            seed
        })
        .collect();
    let honest_tip = seeds[0].with_chain(ChainStore::tip).unwrap();
    let newcomer = Node::bind(rules(), loopback()).unwrap();
    let started = Instant::now();
    for seed in &seeds {
        newcomer.connect(seed.address()).unwrap();
    }
    let took_it = wait_until(PATIENCE, || {
        newcomer.with_chain(ChainStore::tip) == Some(honest_tip)
    });
    let took = started.elapsed();
    let height = newcomer.height();
    newcomer.shutdown();
    for seed in &seeds {
        seed.shutdown();
    }
    assert!(
        took_it,
        "a newcomer between two honest seeds was at {height:?} after {PATIENCE:?}"
    );
    let bound = Duration::from_secs(10);
    assert!(
        took <= bound,
        "a newcomer between two honest seeds took {took:?} to read their chain, past {bound:?}: \
         a settling of two seconds, two turns a round of upkeep apart, and the read"
    );
}

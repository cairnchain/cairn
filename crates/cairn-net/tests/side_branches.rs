//! A node on the losing side of a fork, and the heavier branch it has to reach.
//!
//! Two things stood between them. A node asked a peer for its chain and then
//! asked only for the heights above its own tip, so a branch that parts from
//! it below the tip never arrived in full. And a block that loses the fork
//! choice is held without being applied, under an identifier taken over its
//! header alone, which does not commit to the signatures in the body: anybody
//! can copy the block, break a signature, and have the copy held in place of
//! the real one if it arrives first.

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

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, MAX_REQUESTED, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, tick, Local, PeerState, BATCH_PATIENCE};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;

/// A liveness bound, far past what the work takes on a loaded runner. Every
/// wait here is for something to happen.
const PATIENCE: Duration = Duration::from_secs(180);

/// A reward is spendable at once, so the rival's first block can carry a
/// payment: the one kind of block a copy can differ from in its signatures
/// alone.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
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

struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let reward = Note::new(params().initial_reward, miner.public_key());
        self.mine_paying(vec![reward], transfers)
    }

    /// The next block, its reward paid out as `outputs`.
    fn mine_paying(&mut self, outputs: Vec<Note>, transfers: Vec<Transfer>) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block =
            assemble_block(&self.state, coinbase, transfers, &params, self.clock, 0).unwrap();
        let block = mine_block(block, 1 << 22).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }

    fn fork(&self) -> Self {
        Self {
            state: self.state.clone(),
            clock: self.clock,
        }
    }
}

/// Eleven blocks everybody shares, two more the victim follows, and a heavier
/// rival of three whose first block pays somebody.
///
/// The copy is that first block with its one signature made by the wrong key:
/// the same header, so the same identifier and the same work, and a body that
/// produces the same transaction root, since a transfer's identifier leaves
/// its signatures out. Nothing short of applying it tells it from the real
/// one.
struct Fork {
    shared: Vec<Block>,
    followed: Vec<Block>,
    rival: Vec<Block>,
    copy: Block,
}

fn a_fork() -> Fork {
    let params = params();
    let miner = wallet(1);
    let mut trunk = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    let shared: Vec<Block> = (0..11).map(|_| trunk.mine(&miner, Vec::new())).collect();
    let mut aside = trunk.fork();
    let followed = (0..2).map(|_| trunk.mine(&miner, Vec::new())).collect();

    let spent = Note::new(params.initial_reward, miner.public_key());
    let mut payment = Transfer::new(
        vec![Input::hot(NoteId::new(shared[10].coinbase.id(), 0))],
        vec![Note::new(spent.value, wallet(2).public_key())],
    );
    payment.sign_input(params.network, 0, &spent, &miner);
    let mut copied = payment.clone();
    copied.sign_input(params.network, 0, &spent, &wallet(9));

    let other = wallet(3);
    let mut rival = vec![aside.mine(&other, vec![payment])];
    rival.push(aside.mine(&other, Vec::new()));
    rival.push(aside.mine(&other, Vec::new()));

    let mut copy = rival[0].clone();
    copy.transfers[0] = copied;
    assert_eq!(copy.id(), rival[0].id(), "the copy shares the identifier");
    assert_eq!(
        copy.transactions_root(),
        copy.header.transactions_root,
        "and produces the transaction root its header commits to"
    );
    assert_ne!(copy.encode(), rival[0].encode(), "yet is a different block");
    Fork {
        shared,
        followed,
        rival,
        copy,
    }
}

fn holding(blocks: &[&[Block]]) -> ChainStore {
    let mut chain = ChainStore::new(params());
    for block in blocks.iter().flat_map(|run| run.iter()) {
        chain.add_block(block.clone(), NOW).unwrap();
    }
    chain
}

fn local(chain: &mut ChainStore) -> Local<'_> {
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

fn greeted(total_work: u128, height: u64) -> PeerState {
    PeerState {
        greeted: true,
        height,
        total_work,
        ..PeerState::default()
    }
}

/// A peer's branch that parts from this node's below its tip is asked for
/// from where it parts.
///
/// A peer answers a locator with the first height past the last one it agrees
/// with, and the node asked only for what lay above its own tip, on the ground
/// that everything below was already here. On a fork it is not: the peer's
/// blocks at those heights are the other branch, and without them nothing
/// above them can be applied. Nothing asked this, so a node that could never
/// take a heavier branch it had not watched arrive passed.
#[test]
fn a_branch_that_parts_below_the_tip_is_asked_for_from_where_it_parts() {
    let fork = a_fork();
    let mut victim = holding(&[&fork.shared, &fork.followed]);
    let honest = holding(&[&fork.shared, &fork.rival]);

    // What the honest peer answers the victim's locator with.
    let locator = victim.locator();
    let agreed = locator
        .iter()
        .find(|entry| honest.agrees_with(entry))
        .map(|entry| entry.height)
        .unwrap();
    let from = agreed + 1;
    assert_eq!(from, 11, "the premise: the branches part at height eleven");

    let mut peer = greeted(honest.total_work(), 13);
    peer.chain_asked = true;
    let asked = on_message(
        &mut local(&mut victim),
        &mut peer,
        Message::Chain { from, count: 3 },
        NOW,
    );
    assert_eq!(
        asked.reply,
        vec![Message::GetBlocks(vec![11, 12, 13])],
        "a node shown a heavier branch that parts from its own below its tip did not ask \
         for the blocks where it parts, so it could never apply the ones above them"
    );
}

/// A branch that parts where the locator skips heights is taken, from the
/// height the peer names.
///
/// A locator shows every height near the tip and thins out below, so a peer
/// on a branch that parts deeper agrees with a position below where the two
/// part, and names a height the locator never showed it. The node asked from
/// that height only when its locator showed it, and otherwise only above its
/// own tip, where the peer's blocks hang on parents this node does not have:
/// the same refusal every round, for as long as it asked. Nothing asked this,
/// so a node that could take a heavier branch only when it held ten blocks or
/// fewer of its own above where the two part passed.
#[test]
fn a_branch_that_parts_where_the_locator_skips_heights_is_taken() {
    let mut trunk = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    let shared: Vec<Block> = (0..15)
        .map(|_| trunk.mine(&wallet(1), Vec::new()))
        .collect();
    let mut aside = trunk.fork();
    let own: Vec<Block> = (0..30)
        .map(|_| trunk.mine(&wallet(1), Vec::new()))
        .collect();
    let rival: Vec<Block> = (0..32)
        .map(|_| aside.mine(&wallet(3), Vec::new()))
        .collect();
    let mut victim = holding(&[&shared, &own]);
    let honest = holding(&[&shared, &rival]);

    let parts = u64::try_from(shared.len()).unwrap();
    let locator = victim.locator();
    let named = locator
        .iter()
        .find(|entry| honest.agrees_with(entry))
        .map(|entry| entry.height + 1)
        .unwrap();
    assert!(
        named < parts && locator.iter().all(|entry| entry.height != named),
        "the premise: the peer names a height below where the branches part, which the \
         locator skipped"
    );

    let mut peer = PeerState::new(None);
    let hello = Message::Welcome(cairn_net::sync::local_handshake(
        &honest,
        Keeps {
            headers: true,
            cold_set: false,
        },
        4243,
        2,
    ));
    let asks = on_message(&mut local(&mut victim), &mut peer, hello, NOW).reply;
    let rounds = answer_from(&mut victim, &mut peer, &honest, asks);
    assert_eq!(
        victim.tip(),
        Some(rival.last().unwrap().id()),
        "a heavier branch that parts where the locator skips heights was not taken after \
         {rounds} rounds of an honest peer answering everything the node asked"
    );
}

/// A peer that agrees a batch or more below this node's tip is asked only for
/// what lies above it, and one that agrees less than a batch below is asked
/// from there.
///
/// A peer that recognises nothing it was shown answers from nought, which a
/// locator always shows, and a peer that joined cannot judge the heights below
/// where it joined. Asking from what either names is a batch of blocks this
/// node already follows, the same batch every round, and the node never asks
/// past its tip. Nothing asked this, so a node that asked from any height its
/// locator showed passed, and so did one that asked only above its tip.
#[test]
fn a_peer_that_agrees_a_batch_or_more_below_the_tip_is_asked_only_past_it() {
    let batch = u64::try_from(MAX_REQUESTED).unwrap();
    let mut forge = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    let blocks: Vec<Block> = (0..MAX_REQUESTED + 20)
        .map(|_| forge.mine(&wallet(1), Vec::new()))
        .collect();
    let mut victim = holding(&[&blocks]);
    let have = u64::try_from(blocks.len()).unwrap();
    let offered = have + 20;
    let mut asked_from = |from: u64| {
        let mut peer = greeted(u128::MAX, offered);
        peer.chain_asked = true;
        on_message(
            &mut local(&mut victim),
            &mut peer,
            Message::Chain {
                from,
                count: offered - from,
            },
            NOW,
        )
        .reply
    };
    let past_the_tip = vec![Message::GetBlocks((have..offered).collect())];

    assert_eq!(
        asked_from(0),
        past_the_tip,
        "a peer that recognised nothing it was shown was asked for blocks this node holds"
    );
    let far = have - batch;
    assert_eq!(
        asked_from(far),
        past_the_tip,
        "a peer agreeing a whole batch below the tip was asked for heights this node holds"
    );
    let near = far + 1;
    assert_eq!(
        asked_from(near),
        vec![Message::GetBlocks((near..near + batch).collect())],
        "a peer agreeing less than a batch below the tip was not asked from there"
    );
}

/// Three blocks everybody shares, eight the victim follows, and a heavier
/// rival of nine, all empty: a fork that parts where the victim's locator
/// still shows every height, so a peer on the rival names where it parts.
fn a_shallow_fork() -> (Vec<Block>, Vec<Block>, Vec<Block>) {
    let mut trunk = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    let shared = (0..3).map(|_| trunk.mine(&wallet(1), Vec::new())).collect();
    let mut aside = trunk.fork();
    let own = (0..8).map(|_| trunk.mine(&wallet(1), Vec::new())).collect();
    let rival = (0..9).map(|_| aside.mine(&wallet(3), Vec::new())).collect();
    (shared, own, rival)
}

/// A branch that parts below the tip, of which one round brought only the
/// first blocks, is asked for past them the next round.
///
/// A peer serves a batch only as far as the asker's window pays for, and a
/// block of a branch this node does not follow is never handed its price
/// back, so what one window buys of a heavy branch is all that arrives in a
/// round. The node asked for the whole stretch again from where the branches
/// part every round, was sent the same first blocks every round, and never
/// took a heavier branch of full blocks weighing more than a window. Nothing
/// asked this, so that node passed: every fork here was of empty blocks,
/// which one window carries whole.
#[test]
fn a_branch_that_arrives_a_window_at_a_time_is_asked_for_past_what_arrived() {
    let (shared, own, rival) = a_shallow_fork();
    let mut victim = holding(&[&shared, &own]);
    let honest = holding(&[&shared, &rival]);

    let from = u64::try_from(shared.len()).unwrap();
    let reaches = honest.height().unwrap() + 1;
    let offer = Message::Chain {
        from,
        count: reaches - from,
    };
    let mut peer = greeted(honest.total_work(), reaches - 1);
    peer.chain_asked = true;
    let first = on_message(&mut local(&mut victim), &mut peer, offer.clone(), NOW);
    assert_eq!(
        first.reply,
        vec![Message::GetBlocks((from..reaches).collect())],
        "the premise: the branch is asked for from where it parts"
    );

    // The serving peer's window pays for the first four, and nothing more of
    // the batch comes but its newest block, sent the moment it was found,
    // which hangs on blocks this node does not hold yet.
    let arrived = 4;
    let newest = rival.last().unwrap();
    for block in rival[..arrived].iter().chain([newest]) {
        let _ = on_message(
            &mut local(&mut victim),
            &mut peer,
            Message::Block(Box::new(block.clone())),
            NOW,
        );
    }
    assert!(
        victim.block(&newest.id()).is_none(),
        "the premise: a block whose parent is missing is not held"
    );
    let patience_ran_out = tick(&victim, &mut peer, NOW + BATCH_PATIENCE);
    assert!(
        patience_ran_out
            .reply
            .iter()
            .any(|message| matches!(message, Message::GetChain { .. })),
        "the premise: the chain is asked for again once the batch's patience runs out"
    );

    let second = on_message(
        &mut local(&mut victim),
        &mut peer,
        offer,
        NOW + BATCH_PATIENCE,
    );
    let past = from + u64::try_from(arrived).unwrap();
    assert_eq!(
        second.reply,
        vec![Message::GetBlocks((past..reaches).collect())],
        "a node holding the first blocks of a peer's branch aside asked that peer for them \
         again rather than for the heights past them, so a branch weighing more than one \
         window of the peer's allowance arrives as the same first blocks every round"
    );
    for block in &rival[arrived..] {
        let _ = on_message(
            &mut local(&mut victim),
            &mut peer,
            Message::Block(Box::new(block.clone())),
            NOW + BATCH_PATIENCE,
        );
    }
    assert_eq!(
        victim.tip(),
        Some(rival.last().unwrap().id()),
        "the heavier branch was not taken once the rest of it arrived"
    );
}

/// Blocks of a branch that another peer delivered first count as arrived
/// from the peer that sends them again.
///
/// A round asked from where the branches part is sent blocks this node may
/// already hold aside, from another peer or from this one in a round before.
/// Counting only blocks new to this node as arrived would leave the peer
/// sending them asked from there again every round, and brought the same
/// blocks each time. Nothing asked this, so a node that counted only the
/// blocks it had not held before passed.
#[test]
fn blocks_another_peer_delivered_first_count_as_arrived_from_the_next() {
    let (shared, own, rival) = a_shallow_fork();
    let mut victim = holding(&[&shared, &own]);
    let honest = holding(&[&shared, &rival]);
    let from = u64::try_from(shared.len()).unwrap();
    let reaches = honest.height().unwrap() + 1;
    let offer = Message::Chain {
        from,
        count: reaches - from,
    };
    let arrived = 4;
    let delivered = |victim: &mut ChainStore, peer: &mut PeerState| {
        for block in &rival[..arrived] {
            let _ = on_message(
                &mut local(victim),
                peer,
                Message::Block(Box::new(block.clone())),
                NOW,
            );
        }
    };
    let mut first = greeted(honest.total_work(), reaches - 1);
    delivered(&mut victim, &mut first);

    let mut second = greeted(honest.total_work(), reaches - 1);
    second.chain_asked = true;
    let _ = on_message(&mut local(&mut victim), &mut second, offer.clone(), NOW);
    delivered(&mut victim, &mut second);
    let asked = on_message(&mut local(&mut victim), &mut second, offer, NOW);
    let past = from + u64::try_from(arrived).unwrap();
    assert_eq!(
        asked.reply,
        vec![Message::GetBlocks((past..reaches).collect())],
        "a peer that sent blocks this node already held aside was asked for them again \
         rather than for the heights past them"
    );
}

/// A branch held aside that has lost a block is asked for again from where
/// it parts, by the peer that delivered the blocks above the hole.
///
/// A body that fails a switch is dropped, and the blocks above it are kept.
/// Asking from past what that peer delivered would never ask for the height
/// where the real body belongs, which is the very block the switch needs.
/// Nothing asked this, so a node that trusted the last block a peer sent
/// without looking below it passed.
#[test]
fn a_branch_held_aside_with_a_hole_in_it_is_asked_for_from_where_it_parts() {
    let fork = a_fork();
    let mut victim = holding(&[&fork.shared, &fork.followed]);
    let mut forwarder = greeted(1, 12);
    let _ = on_message(
        &mut local(&mut victim),
        &mut forwarder,
        Message::Block(Box::new(fork.copy.clone())),
        NOW,
    );
    let mut honest = greeted(victim.total_work(), 12);
    for block in &fork.rival {
        let _ = on_message(
            &mut local(&mut victim),
            &mut honest,
            Message::Block(Box::new(block.clone())),
            NOW,
        );
    }
    assert_eq!(victim.height(), Some(12), "the premise: the switch failed");
    assert!(
        victim.block(&fork.rival[0].id()).is_none() && victim.block(&fork.rival[1].id()).is_some(),
        "the premise: the body that failed is gone and the one above it is held"
    );

    let asked = on_message(
        &mut local(&mut victim),
        &mut honest,
        Message::Chain { from: 11, count: 3 },
        NOW,
    );
    assert_eq!(
        asked.reply,
        vec![Message::GetBlocks(vec![11, 12, 13])],
        "a node whose switch failed on a body held aside asked the peer carrying the branch \
         only past the blocks it still held above that body, so the real one was never \
         asked for"
    );
}

/// A block a peer delivered off a branch that parts lower than the one it
/// offers now does not decide where the node asks from.
///
/// What a peer delivered of one branch says nothing about another it offers
/// afterwards, and asking past it would be asking for blocks whose parents
/// this node does not hold, round after round. Nothing asked this, so a node
/// that walked down to wherever what it held met its own branch passed.
#[test]
fn a_block_of_a_branch_parting_lower_than_the_one_offered_does_not_steer_the_ask() {
    let mut trunk = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    let shared: Vec<Block> = (0..3).map(|_| trunk.mine(&wallet(1), Vec::new())).collect();
    let mut low = trunk.fork();
    let own: Vec<Block> = (0..8).map(|_| trunk.mine(&wallet(1), Vec::new())).collect();
    let parted_low: Vec<Block> = (0..6).map(|_| low.mine(&wallet(3), Vec::new())).collect();
    let mut victim = holding(&[&shared, &own]);

    let mut peer = greeted(victim.total_work(), 10);
    for block in &parted_low {
        let _ = on_message(
            &mut local(&mut victim),
            &mut peer,
            Message::Block(Box::new(block.clone())),
            NOW,
        );
    }
    assert!(
        parted_low
            .iter()
            .all(|block| victim.block(&block.id()).is_some()),
        "the premise: the branch that parts low is held aside"
    );

    // The peer now agrees with this node up to height five and offers a
    // branch from six.
    let asked = on_message(
        &mut local(&mut victim),
        &mut peer,
        Message::Chain { from: 6, count: 6 },
        NOW,
    );
    assert_eq!(
        asked.reply,
        vec![Message::GetBlocks((6..12).collect())],
        "a node asked a peer for its branch from past a block it had delivered of another \
         branch, one that parts below where the branch it offers now does"
    );
}

/// The peer that delivers the block making a branch the heaviest is not
/// blamed when the switch fails on a body somebody else sent first, and is
/// asked again for its chain.
///
/// The copy is held without being judged, and the block above it arrives from
/// an honest peer. The switch reads the copy, fails, and the refusal names the
/// copied block rather than the one delivered. Every such refusal became
/// `BadBlock` against the peer in hand, which is misbehaviour: the honest peer
/// was disconnected and its host refused, and the sender of the copy had been
/// answered `SideBranch`. Nothing asked this, so a node that turned away the
/// peers carrying the heavier branch for a body none of them sent passed.
///
/// The honest peer is greeted at this node's own work, which is how every
/// long-lived connection of a node at the tip was greeted. This greeted it
/// with all the work there is, so a node that asked a peer greeted as an
/// equal nothing after the switch failed passed as well.
#[test]
fn the_peer_that_delivers_a_valid_block_is_not_blamed_for_a_body_another_sent() {
    let fork = a_fork();
    let mut victim = holding(&[&fork.shared, &fork.followed]);

    let mut forwarder = greeted(1, 12);
    let copied = on_message(
        &mut local(&mut victim),
        &mut forwarder,
        Message::Block(Box::new(fork.copy.clone())),
        NOW,
    );
    assert!(
        copied.drop_peer.is_none(),
        "the premise: the copy is held aside unjudged"
    );
    assert_eq!(
        copied.held_aside,
        Some(fork.copy.id()),
        "the node did not name the body it now holds aside, so nothing could say who sent it"
    );

    let mut honest = greeted(victim.total_work(), 12);
    let real = on_message(
        &mut local(&mut victim),
        &mut honest,
        Message::Block(Box::new(fork.rival[0].clone())),
        NOW,
    );
    assert_eq!(
        real.held_aside, None,
        "a body the node did not keep was named as held, against the peer that sent it"
    );
    let _ = on_message(
        &mut local(&mut victim),
        &mut honest,
        Message::Block(Box::new(fork.rival[1].clone())),
        NOW,
    );
    let delivered = on_message(
        &mut local(&mut victim),
        &mut honest,
        Message::Block(Box::new(fork.rival[2].clone())),
        NOW,
    );
    assert_eq!(victim.height(), Some(12), "the premise: the switch failed");
    assert!(
        delivered.drop_peer.is_none(),
        "the peer that delivered a valid block was disconnected for a body another peer \
         sent first"
    );
    assert!(
        delivered
            .reply
            .iter()
            .any(|message| matches!(message, Message::GetChain { .. })),
        "and it was not asked again for the branch it carries, which is where the real \
         body is: a peer greeted as an equal was not counted as ahead for the work the \
         block it delivered claims"
    );
    assert_eq!(
        delivered.failed_below,
        Some(fork.rival[0].id()),
        "the block whose held body failed was not named, so its sender could not be refused"
    );
}

/// Plays an honest peer holding `honest` through what the victim asks of it,
/// for as many rounds as it keeps asking, and says how many rounds that was.
fn answer_from(
    victim: &mut ChainStore,
    peer: &mut PeerState,
    honest: &ChainStore,
    mut asks: Vec<Message>,
) -> usize {
    let mut rounds = 0;
    while !asks.is_empty() && rounds < 16 {
        rounds += 1;
        let mut next = Vec::new();
        for ask in asks {
            let heard = match ask {
                Message::GetChain { locator } => {
                    let agreed = locator
                        .iter()
                        .find(|entry| honest.agrees_with(entry))
                        .map_or(0, |entry| entry.height + 1);
                    let reaches = honest.height().map_or(0, |tip| tip + 1);
                    vec![Message::Chain {
                        from: agreed,
                        count: reaches - agreed,
                    }]
                }
                Message::GetBlocks(heights) => heights
                    .iter()
                    .filter_map(|height| honest.block_at(*height))
                    .map(|block| Message::Block(Box::new(block.clone())))
                    .collect(),
                _ => Vec::new(),
            };
            for message in heard {
                next.extend(on_message(&mut local(victim), peer, message, NOW).reply);
            }
        }
        asks = next;
    }
    rounds
}

/// After a switch fails on a copy, the node's own asking brings the real
/// block back, with the sender of the copy gone.
///
/// The copy is dropped when it fails, and the real block it stood in for has
/// then to be asked for again. The node asked a peer for its chain and then
/// only for the heights above its own tip, so the height where the branches
/// part was never asked for again: one copy, sent once, kept a node off the
/// heavier branch for good, however many honest peers offered it afterwards.
/// Nothing asked this, so that node passed.
#[test]
fn after_a_switch_fails_on_a_copy_the_nodes_own_asking_brings_the_real_block_back() {
    let fork = a_fork();
    let mut victim = holding(&[&fork.shared, &fork.followed]);
    let honest = holding(&[&fork.shared, &fork.rival]);

    let mut forwarder = greeted(1, 12);
    let _ = on_message(
        &mut local(&mut victim),
        &mut forwarder,
        Message::Block(Box::new(fork.copy.clone())),
        NOW,
    );
    let mut first = greeted(honest.total_work(), 13);
    for block in &fork.rival[1..] {
        let _ = on_message(
            &mut local(&mut victim),
            &mut first,
            Message::Block(Box::new(block.clone())),
            NOW,
        );
    }
    assert_eq!(victim.height(), Some(12), "the premise: the switch failed");

    // Another honest peer, met afterwards, and nothing from the sender of the
    // copy from here on.
    let mut second = PeerState::new(None);
    let hello = Message::Welcome(cairn_net::sync::local_handshake(
        &honest,
        Keeps {
            headers: true,
            cold_set: false,
        },
        4243,
        2,
    ));
    let asks = on_message(&mut local(&mut victim), &mut second, hello, NOW).reply;
    let rounds = answer_from(&mut victim, &mut second, &honest, asks);
    println!("rounds {rounds}, victim height {:?}", victim.height());
    assert_eq!(
        victim.tip(),
        Some(fork.rival[2].id()),
        "after one copy failed a switch, an honest peer answering everything the node \
         asked for {rounds} rounds did not bring it onto the heavier branch"
    );
}

/// One connection that introduces itself and then sends the same copy every
/// few milliseconds, for as long as the connection lasts.
struct Forwarder {
    running: Arc<AtomicBool>,
    hung_up: Arc<AtomicBool>,
    sent: Arc<AtomicU64>,
}

impl Forwarder {
    fn start(to: SocketAddr, genesis: Hash32, copy: Block) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let hung_up = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicU64::new(0));
        let mine = (
            Arc::clone(&running),
            Arc::clone(&hung_up),
            Arc::clone(&sent),
        );
        let mut stream = TcpStream::connect(to).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let network = params().network;
        thread::spawn(move || {
            let (running, hung_up, sent) = mine;
            let hello = Message::Hello(Handshake {
                version: PROTOCOL_VERSION,
                network,
                genesis,
                tip: Hash32::ZERO,
                height: 0,
                total_work: 1,
                listen: 0,
                nonce: u64::from(std::process::id()).wrapping_add(7),
                keeps: Keeps {
                    headers: false,
                    cold_set: false,
                },
            });
            let block = Message::Block(Box::new(copy));
            let mut said = write_message(&mut stream, network, &hello).is_ok();
            while said && running.load(Ordering::SeqCst) {
                said = match read_message(&mut stream, network, MAX_FRAME_BYTES) {
                    Ok(Incoming::Message(Message::Ping(token))) => {
                        write_message(&mut stream, network, &Message::Pong(token)).is_ok()
                    }
                    Ok(_) => true,
                    Err(_) => false,
                } && write_message(&mut stream, network, &block).is_ok();
                sent.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(25));
            }
            if !said {
                hung_up.store(true, Ordering::SeqCst);
            }
        });
        Self {
            running,
            hung_up,
            sent,
        }
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// A victim on the lighter branch, and two honest nodes on the heavier one.
fn three_nodes(fork: &Fork) -> (Node, Vec<Node>) {
    let params = params();
    let victim = Node::bind(params, loopback()).unwrap();
    for block in fork.shared.iter().chain(&fork.followed) {
        victim.submit_block(block.clone()).unwrap();
    }
    assert_eq!(victim.height(), Some(12));
    let honest = (0..2)
        .map(|_| {
            let node = Node::bind(params, loopback()).unwrap();
            for block in fork.shared.iter().chain(&fork.rival) {
                node.submit_block(block.clone()).unwrap();
            }
            assert_eq!(node.height(), Some(13));
            node
        })
        .collect();
    (victim, honest)
}

/// A node on a lighter branch takes the heavier one from the peers it meets
/// afterwards, over real sockets.
///
/// Nothing asked this, so a node that was not listening while a heavier
/// branch's first blocks went round, and so could never have them, passed:
/// it stayed on its own branch with two peers offering the heavier one.
#[test]
fn a_node_on_a_lighter_branch_takes_a_heavier_one_from_peers_it_meets_afterwards() {
    let fork = a_fork();
    let (victim, honest) = three_nodes(&fork);
    for node in &honest {
        victim.connect(node.address()).unwrap();
    }
    let rival = fork.rival[2].id();
    wait_for(
        "the node on the lighter branch to take the heavier one",
        || victim.with_chain(ChainStore::tip) == Some(rival),
    );
    victim.shutdown();
    for node in &honest {
        node.shutdown();
    }
}

/// One connection sending a copy of a block ahead of every delivery does not
/// keep a node off the heavier branch, and is the one that loses its
/// connection for it.
///
/// The copy is held first, and the switch onto the heavier branch fails on it.
/// The node used to blame the honest peer that delivered the block above and
/// did nothing to the sender of the copy, which could send it again and have
/// it held again before the real block came back. Nothing asked this, so a
/// node that one connection could keep off the heavier branch for as long as
/// it cared to keep sending passed.
#[test]
fn a_copy_sent_ahead_of_every_delivery_does_not_keep_a_node_off_the_heavier_branch() {
    let fork = a_fork();
    let (victim, honest) = three_nodes(&fork);

    let forwarder = Forwarder::start(victim.address(), fork.shared[0].id(), fork.copy.clone());
    wait_for("the copy to be held ahead of the real block", || {
        victim.with_chain(|chain| {
            chain
                .block(&fork.copy.id())
                .is_some_and(|held| held.encode() == fork.copy.encode())
        })
    });

    for node in &honest {
        victim.connect(node.address()).unwrap();
    }
    let rival = fork.rival[2].id();
    wait_for("the node to take the heavier branch", || {
        victim.with_chain(ChainStore::tip) == Some(rival)
    });
    // The copy failed a switch before the node could take the branch, so its
    // sender has been hung up by now; its thread notices at its next write.
    // Counted in copies rather than waited for, so a sender left connected
    // fails this in a few seconds rather than at the patience.
    let sent = forwarder.sent.load(Ordering::SeqCst);
    wait_for(
        "the sender of the copy to notice, or to send two hundred more",
        || {
            forwarder.hung_up.load(Ordering::SeqCst)
                || forwarder.sent.load(Ordering::SeqCst) >= sent + 200
        },
    );
    assert!(
        forwarder.hung_up.load(Ordering::SeqCst),
        "the connection whose copy failed a switch was left open to send it again"
    );
    drop(forwarder);
    victim.shutdown();
    for node in &honest {
        node.shutdown();
    }
}

/// Blocks the victim follows above where a deep fork parts. The rival has one
/// more, and parts less than a batch below the victim's tip.
const DEPTH: usize = 60;
/// Transfers in a full block of the deep fork.
const LANES: usize = 5;
/// Notes each of those transfers moves on.
const WIDTH: usize = 128;

/// What one window of a peer's allowance buys of blocks served: eight
/// thousand one hundred and ninety two units of five hundred and twelve bytes.
const ONE_WINDOW: usize = 4 * 1024 * 1024;

/// `total` in `parts`, the remainder on the last, so nothing is left as fee.
fn split(total: Amount, parts: usize) -> Vec<Amount> {
    let pebbles = total.as_pebbles();
    let count = u64::try_from(parts).unwrap();
    let each = pebbles / count;
    let last = pebbles - each * (count - 1);
    (1..=count)
        .map(|part| Amount::from_pebbles(if part == count { last } else { each }).unwrap())
        .collect()
}

/// Two shared blocks, the second fanning five rewards out into 640 notes,
/// then `DEPTH` empty blocks the victim follows, and a rival of `DEPTH + 1`
/// whose blocks each move all 640 notes on when `full`, and carry nothing
/// otherwise.
struct DeepFork {
    shared: Vec<Block>,
    followed: Vec<Block>,
    rival: Vec<Block>,
}

fn a_deep_fork(full: bool) -> DeepFork {
    let params = params();
    let key = wallet(1);
    let me = key.public_key();
    let reward = || vec![Note::new(params.initial_reward, me)];
    let mut trunk = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    let seeds = split(params.initial_reward, LANES)
        .into_iter()
        .map(|value| Note::new(value, me))
        .collect();
    let first = trunk.mine_paying(seeds, Vec::new());
    let mut lanes: Vec<Vec<(NoteId, Note)>> = Vec::new();
    let mut fanned = Vec::new();
    for lane in 0..LANES {
        let seed = first.coinbase.outputs[lane];
        let outputs = split(seed.value, WIDTH)
            .into_iter()
            .map(|value| Note::new(value, me))
            .collect();
        let at = u32::try_from(lane).unwrap();
        let mut transfer = Transfer::new(
            vec![Input::hot(NoteId::new(first.coinbase.id(), at))],
            outputs,
        );
        transfer.sign_input(params.network, 0, &seed, &key);
        lanes.push(transfer.created_notes());
        fanned.push(transfer);
    }
    let second = trunk.mine_paying(reward(), fanned);
    let shared = vec![first, second];

    let mut aside = trunk.fork();
    let followed = (0..DEPTH)
        .map(|_| trunk.mine_paying(reward(), Vec::new()))
        .collect();
    let mut rival = Vec::new();
    for _ in 0..=DEPTH {
        let mut transfers = Vec::new();
        if full {
            let mut next = Vec::new();
            for lane in &lanes {
                let inputs = lane.iter().map(|(id, _)| Input::hot(*id)).collect();
                let outputs = lane.iter().map(|(_, note)| *note).collect();
                let mut transfer = Transfer::new(inputs, outputs);
                for (index, (_, note)) in lane.iter().enumerate() {
                    let index = u32::try_from(index).unwrap();
                    transfer.sign_input(params.network, index, note, &key);
                }
                next.push(transfer.created_notes());
                transfers.push(transfer);
            }
            lanes = next;
        }
        rival.push(aside.mine_paying(reward(), transfers));
    }
    DeepFork {
        shared,
        followed,
        rival,
    }
}

/// A victim on the lighter side of `fork` dials one node on the heavier side,
/// and takes the heavier branch.
fn the_victim_dials_the_heavier_side(fork: &DeepFork, what: &str) {
    let params = params();
    let victim = Node::bind(params, loopback()).unwrap();
    for block in fork.shared.iter().chain(&fork.followed) {
        victim.submit_block(block.clone()).unwrap();
    }
    let depth = u64::try_from(DEPTH).unwrap();
    assert_eq!(
        victim.height(),
        Some(depth + 1),
        "the premise: the victim's branch"
    );
    let honest = Node::bind(params, loopback()).unwrap();
    for block in fork.shared.iter().chain(&fork.rival) {
        honest.submit_block(block.clone()).unwrap();
    }
    assert_eq!(
        honest.height(),
        Some(depth + 2),
        "the premise: the heavier branch"
    );

    victim.connect(honest.address()).unwrap();
    let rival = fork.rival.last().unwrap().id();
    wait_for(what, || victim.with_chain(ChainStore::tip) == Some(rival));
    victim.shutdown();
    honest.shutdown();
}

/// A heavier branch of empty blocks that parts sixty below the tip is taken
/// over real sockets.
///
/// The same fork as the full one below with nothing in its blocks, so that a
/// failure of that one says what the weight did rather than what the depth
/// did. It passed before the full one did.
#[test]
fn a_heavier_branch_of_empty_blocks_parting_sixty_below_the_tip_is_taken() {
    let fork = a_deep_fork(false);
    the_victim_dials_the_heavier_side(
        &fork,
        "a node on a lighter branch to take a heavier one of empty blocks parting sixty \
         below its tip",
    );
}

/// A heavier branch of full blocks that parts sixty below the tip, and weighs
/// more than a window of the serving peer's allowance buys, is taken over
/// real sockets.
///
/// Each round asked for the stretch from where the branches part, the serving
/// peer stopped where the asker's window ran out, and a block of a branch
/// this node does not follow is never handed its price back, so the same
/// first forty four blocks arrived every round and the node stayed on the
/// lighter branch for good. Nothing asked this, so a node that could never
/// rejoin the network after a split of full blocks lasting between half an
/// hour and two hours passed: every fork these tests built was of empty
/// blocks.
#[test]
fn a_heavier_branch_of_full_blocks_weighing_more_than_a_window_is_taken() {
    let fork = a_deep_fork(true);
    let weights: Vec<usize> = fork
        .rival
        .iter()
        .map(|block| block.encode().len())
        .collect();
    assert!(
        weights
            .iter()
            .all(|bytes| *bytes <= params().max_block_bytes),
        "the premise: every block within the size rule"
    );
    assert!(
        weights.iter().sum::<usize>() > ONE_WINDOW,
        "the premise: the stretch above the fork weighs more than one window buys"
    );
    the_victim_dials_the_heavier_side(
        &fork,
        "a node on a lighter branch to take a heavier one of full blocks that parts sixty \
         below its tip and weighs more than one window of the serving peer's allowance",
    );
}

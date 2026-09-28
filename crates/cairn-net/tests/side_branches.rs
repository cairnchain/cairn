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
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

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
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
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

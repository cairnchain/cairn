//! The one question a wallet cannot answer for itself.
//!
//! A note that has fallen out of the set every node keeps can only be spent
//! alongside a path showing where it sits, and that path changes every time
//! another note falls. Nobody keeps one for a stranger, so a wallet whose own
//! node stopped keeping it has money it can see and cannot move. These tests
//! stand up real nodes on real sockets and put the question to them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use cairn_accumulator::ForestProof;
use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::cold_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, Placed, MAX_PROVEN, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::wire::{read_message, write_message, Incoming};
use cairn_net::Node;
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const PATIENCE: Duration = Duration::from_secs(15);

/// Blocks mined before the note under test is asked about.
///
/// Every node keeps the path to a note it watched fall for
/// `cairn_ledger::state::GRACE_BLOCKS` blocks, so that somebody who has just
/// been paid can spend without asking anybody. Past that window a node keeps
/// paths only for the owners it was told to follow, and that is the state this
/// whole exchange exists for, so the chain has to run well past the window
/// before any of these tests mean anything.
const PAST_THE_WINDOW: usize = cairn_ledger::state::GRACE_BLOCKS + 12;

/// Shallow wherever a test would otherwise have to mine its way through a
/// number chosen for a live network. What the real numbers buy is argued where
/// they are defined; what they cost a test is minutes.
///
/// The maturity rule is turned off rather than shortened: on a network this
/// shallow a reward matures where the burial is, so a number in between would
/// be saying something the design does not say.
/// Nothing here is about maturity, and every note has to be reachable.
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

fn miner() -> SecretKey {
    SecretKey::from_bytes(&[1; 32])
}

fn scratch(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("cairn-archivist-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// Builds blocks off to the side, so a node can be handed a ready made chain.
///
/// It keeps every leaf, which no node in these tests has to: what it buys is a
/// test that can say for itself where a note landed, rather than asking one of
/// the nodes it is meant to be checking.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
    paid_to: PublicKey,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::archiving(),
            clock: 1_000,
            paid_to: miner().public_key(),
        }
    }

    fn mine(&mut self) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, self.paid_to)],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_many(&mut self, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine()).collect()
    }

    /// Where a note landed, which only a holder of every leaf can say.
    fn where_it_fell(&self, id: &NoteId, note: &Note) -> u64 {
        self.state
            .cold()
            .locate(id, note)
            .expect("the note has fallen out of the hot set")
    }
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

/// A note paid by an early block, and therefore long out of the window.
fn an_old_note(blocks: &[Block]) -> (NoteId, Note) {
    blocks[1].coinbase.created_notes()[0]
}

/// A chain long enough to matter, and where one of its notes landed.
struct Ready {
    blocks: Vec<Block>,
    position: u64,
    leaf: Hash32,
    id: NoteId,
    note: Note,
}

fn a_chain_with_a_fallen_note() -> Ready {
    let mut forge = Forge::new(params());
    let blocks = forge.mine_many(PAST_THE_WINDOW);
    let (id, note) = an_old_note(&blocks);
    Ready {
        position: forge.where_it_fell(&id, &note),
        leaf: cold_leaf(&id, &note),
        id,
        note,
        blocks,
    }
}

fn a_handshake(listen: u16, nonce: u64, keeps: Keeps) -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen,
        nonce,
        keeps,
    })
}

/// **A node that cannot place its own note is told where it sits.**
///
/// The whole exchange, end to end and over a socket. One node kept every leaf
/// the cold set ever held; another followed the same chain, watched the same
/// notes fall, and let go of their paths once the window passed, which is what
/// every node does for every owner it was not told to follow. The second asks
/// the first, and what comes back is folded against the second node's own
/// commitment, worked out from blocks it validated itself.
#[test]
fn a_node_that_cannot_place_a_note_is_told_where_it_sits() {
    let ready = a_chain_with_a_fallen_note();
    let top = (ready.blocks.len() - 1) as u64;

    let directory = scratch("endtoend");
    let (keeper, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    for block in &ready.blocks {
        keeper.submit_block(block.clone()).unwrap();
    }
    assert!(keeper.is_archiving());

    let asker = Node::bind(params(), loopback()).unwrap();
    asker.connect(keeper.address()).unwrap();
    wait_for("the asking node to catch up", || {
        asker.height() == Some(top)
    });

    assert!(
        asker
            .with_chain(|chain| chain.state().cold().proof_of(ready.position))
            .is_none(),
        "a node that follows nobody lets a path go once the window passes, \
         which is the state this whole exchange exists for"
    );
    wait_for("the archivist to say what it keeps", || {
        asker.archiving_peers() == 1
    });

    let answer = asker.recover_proofs(&[(ready.position, ready.leaf)], PATIENCE);
    assert_eq!(answer.asked, 1, "there was one node worth asking");
    assert_eq!(answer.archivists, 1, "and it said it keeps the whole set");
    assert_eq!(answer.refused, 0, "nothing came back that did not fold");
    let proof = answer
        .proofs
        .get(&ready.position)
        .expect("the archivist rebuilt the path");
    assert!(
        asker.with_chain(|chain| {
            chain
                .state()
                .cold()
                .verify(ready.position, ready.leaf, proof)
        }),
        "and it folds to the commitment this node worked out for itself"
    );

    asker.shutdown();
    keeper.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// **A node that keeps the headers no longer claims to keep the cold set.**
///
/// AUDIT, repaired. The handshake carried one bit called `archives`, filled in
/// from the header log, which every node keeps. So every node on the network
/// claimed the one service almost none of them performed, and a wallet looking
/// for somebody to rebuild a path had no way to tell who could. The two claims
/// are now two, and this reads them straight off the wire from two nodes that
/// differ in exactly that.
#[test]
fn the_two_things_a_node_may_have_kept_are_told_apart_on_the_wire() {
    let plain_directory = scratch("plainclaims");
    let kept_directory = scratch("keptclaims");
    let (plain, _) = Node::open(params(), loopback(), &plain_directory).unwrap();
    let (keeper, _) = Node::open_archiving(params(), loopback(), &kept_directory).unwrap();

    for (node, expected) in [
        (
            &plain,
            Keeps {
                headers: true,
                cold_set: false,
            },
        ),
        (
            &keeper,
            Keeps {
                headers: true,
                cold_set: true,
            },
        ),
    ] {
        let mut peer = TcpStream::connect(node.address()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write_message(
            &mut peer,
            params().network,
            &a_handshake(41_100, 0x9001, Keeps::default()),
        )
        .unwrap();
        let said = loop {
            match read_message(&mut peer, params().network) {
                Ok(Incoming::Message(Message::Welcome(handshake))) => break handshake,
                Ok(_) => {}
                Err(error) => panic!("no welcome came back: {error}"),
            }
        };
        assert_eq!(
            said.keeps, expected,
            "a node that keeps the headers and a node that keeps everything \
             used to say the same thing here"
        );
    }

    plain.shutdown();
    keeper.shutdown();
    let _ = std::fs::remove_dir_all(&plain_directory);
    let _ = std::fs::remove_dir_all(&kept_directory);
}

/// **A node that cannot help says so, rather than saying nothing.**
///
/// GUARD. Silence from a peer is indistinguishable from a peer that has hung
/// up, and a wallet waiting on the one thing that would let it move its money
/// has to be able to tell those apart and go and ask somebody else. So the
/// answer names every place that was asked about, including the ones it has
/// nothing for.
///
/// The node in the middle here keeps the headers and not the cold set, which
/// is what almost every node on the network is, and which used to be a node
/// that claimed it could answer this.
#[test]
fn a_node_that_cannot_help_says_so_rather_than_nothing() {
    let ready = a_chain_with_a_fallen_note();
    let top = (ready.blocks.len() - 1) as u64;

    let directory = scratch("plainly");
    let (middle, _) = Node::open(params(), loopback(), &directory).unwrap();
    for block in &ready.blocks {
        middle.submit_block(block.clone()).unwrap();
    }

    let asker = Node::bind(params(), loopback()).unwrap();
    asker.connect(middle.address()).unwrap();
    wait_for("the asking node to catch up", || {
        asker.height() == Some(top)
    });
    assert_eq!(
        asker.archiving_peers(),
        0,
        "nothing it is connected to claims to keep the set"
    );

    let answer = asker.recover_proofs(&[(ready.position, ready.leaf)], PATIENCE);
    assert_eq!(
        answer.archivists, 0,
        "nobody claimed it, so everybody was asked"
    );
    assert_eq!(answer.asked, 1);
    assert_eq!(
        answer.answered, 1,
        "a node that cannot help still answers, or the asker cannot tell it \
         from a node that has gone away"
    );
    assert!(answer.proofs.is_empty(), "and it has nothing to give");
    assert_eq!(
        answer.refused, 0,
        "which is not the same as answering badly"
    );

    asker.shutdown();
    middle.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// **A node following the owner answers without keeping the whole set.**
///
/// An archivist is the reliable answerer and not the only one. A node told to
/// follow an owner holds the path to every one of that owner's fallen notes
/// and keeps it current for nothing, because everything that takes is already
/// passing through in the blocks. It can therefore answer for exactly those
/// places, through the same call the archivist answers through, without either
/// of them having to know which it is.
#[test]
fn a_node_following_the_owner_answers_without_keeping_the_whole_set() {
    let ready = a_chain_with_a_fallen_note();
    let top = (ready.blocks.len() - 1) as u64;

    let watching = scratch("watching");
    let (follower, _) =
        Node::open_watching(params(), loopback(), &watching, &[miner().public_key()]).unwrap();
    for block in &ready.blocks {
        follower.submit_block(block.clone()).unwrap();
    }
    assert!(
        !follower.is_archiving(),
        "it kept sixty four hashes and the paths it was asked to follow"
    );
    assert!(
        follower
            .with_chain(|chain| chain.state().cold().proof_of(ready.position))
            .is_some(),
        "and one of those paths is the one under test"
    );

    // Asks the follower and nobody else, so what comes back can only have come
    // from a node that never claimed to keep anything.
    let asker = Node::bind(params(), loopback()).unwrap();
    asker.connect(follower.address()).unwrap();
    wait_for("the asking node to catch up", || {
        asker.height() == Some(top)
    });

    let answer = asker.recover_proofs(&[(ready.position, ready.leaf)], PATIENCE);
    assert_eq!(answer.archivists, 0, "it never claimed to keep the set");
    let proof = answer
        .proofs
        .get(&ready.position)
        .expect("and it answered all the same, out of the path it already held");
    assert!(asker.with_chain(|chain| {
        chain
            .state()
            .cold()
            .verify(ready.position, ready.leaf, proof)
    }));

    asker.shutdown();
    follower.shutdown();
    let _ = std::fs::remove_dir_all(&watching);
}

/// **A path that does not fold is thrown away, and the peer that sent it is
/// not blamed.**
///
/// GUARD. Everything here rests on the asker checking, because the answer
/// comes from an anonymous stranger and nothing else stands behind it. What is
/// deliberately not done is holding it against the peer: the cold set moves
/// whenever a note falls anywhere, so an honest path built a moment before a
/// block landed fails in exactly the same way as an invented one, and a node
/// that banned peers for this would work its way through every archivist on
/// the network.
#[test]
fn a_path_that_does_not_fold_is_thrown_away_and_the_peer_is_not() {
    let ready = a_chain_with_a_fallen_note();
    let network = params().network;

    // Its chain comes from its own hand, so the only peer it has is the liar.
    let asker = Node::bind(params(), loopback()).unwrap();
    for block in &ready.blocks {
        asker.submit_block(block.clone()).unwrap();
    }

    let address = asker.address();
    let liar = thread::spawn(move || {
        let mut peer = TcpStream::connect(address).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write_message(
            &mut peer,
            network,
            // The claim that gets it asked first, and it is only a claim.
            &a_handshake(
                41_000,
                0x5157,
                Keeps {
                    headers: true,
                    cold_set: true,
                },
            ),
        )
        .unwrap();
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
            match read_message(&mut peer, network) {
                Ok(Incoming::Message(Message::GetProofs(positions))) => {
                    let answer = Message::Proofs(
                        positions
                            .into_iter()
                            .map(|position| Placed {
                                position,
                                // A path of the right shape and the wrong
                                // contents, which is what an invented one and
                                // a stale one both look like from here.
                                proof: Some(ForestProof {
                                    siblings: vec![Hash32::ZERO; 6],
                                }),
                            })
                            .collect(),
                    );
                    write_message(&mut peer, network, &answer).unwrap();
                    return peer;
                }
                Ok(_) => {}
                Err(error) => panic!("the liar lost the connection: {error}"),
            }
        }
        panic!("nobody ever asked the liar anything");
    });

    wait_for("the liar to introduce itself", || {
        asker.archiving_peers() == 1
    });
    let answer = asker.recover_proofs(&[(ready.position, ready.leaf)], PATIENCE);
    let _still_open = liar.join().unwrap();

    assert_eq!(answer.asked, 1);
    assert_eq!(answer.answered, 1, "it answered");
    assert_eq!(answer.refused, 1, "and the answer did not fold");
    assert!(
        answer.proofs.is_empty(),
        "so nothing came of it, which is the whole of what a wrong answer costs"
    );
    assert_eq!(
        asker.peer_count(),
        1,
        "and the peer is still here: a path that does not fold is also what an \
         honest peer answering a moment too early sends"
    );

    asker.shutdown();
}

/// **An answer from a peer this node did not ask is dropped.**
///
/// GUARD. The answer is taken before the chain has been anywhere near it,
/// which is only safe because one from a peer this node did not ask is dropped
/// on a lock and a lookup. Without it any stranger could hand a node sixty
/// four paths to fold, over and over, for the price of one message, and the
/// folding is done with the chain in hand.
///
/// Two peers here: one that says it keeps the set and is therefore the one
/// asked, and one that says it keeps nothing and is not. The second answers
/// anyway, over and over, for a place that is genuinely outstanding.
#[test]
fn an_answer_from_a_peer_that_was_not_asked_is_dropped() {
    let ready = a_chain_with_a_fallen_note();
    let network = params().network;

    let node = Node::bind(params(), loopback()).unwrap();
    for block in &ready.blocks {
        node.submit_block(block.clone()).unwrap();
    }
    let address = node.address();

    // The one that keeps nothing, and answers all the same.
    let position = ready.position;
    let shouting = thread::spawn(move || {
        let mut peer = TcpStream::connect(address).unwrap();
        write_message(
            &mut peer,
            network,
            &a_handshake(41_002, 0x5159, Keeps::default()),
        )
        .unwrap();
        let forged = Message::Proofs(vec![Placed {
            position,
            proof: Some(ForestProof {
                siblings: vec![Hash32::ZERO; 6],
            }),
        }]);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if write_message(&mut peer, network, &forged).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        peer
    });

    // The one that is asked, which answers honestly that it cannot help.
    let honest = thread::spawn(move || {
        let mut peer = TcpStream::connect(address).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write_message(
            &mut peer,
            network,
            &a_handshake(
                41_003,
                0x515a,
                Keeps {
                    headers: true,
                    cold_set: true,
                },
            ),
        )
        .unwrap();
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
            match read_message(&mut peer, network) {
                Ok(Incoming::Message(Message::GetProofs(positions))) => {
                    let answer = Message::Proofs(
                        positions
                            .into_iter()
                            .map(|position| Placed {
                                position,
                                proof: None,
                            })
                            .collect(),
                    );
                    write_message(&mut peer, network, &answer).unwrap();
                    return peer;
                }
                Ok(_) => {}
                Err(error) => panic!("the asked peer lost the connection: {error}"),
            }
        }
        panic!("nobody ever asked the peer that said it could help");
    });

    wait_for("both peers to introduce themselves", || {
        node.peer_count() == 2 && node.archiving_peers() == 1
    });
    let answer = node.recover_proofs(&[(ready.position, ready.leaf)], PATIENCE);
    let _held = (shouting.join().unwrap(), honest.join().unwrap());

    assert_eq!(answer.asked, 1, "only the one that said it could help");
    assert_eq!(answer.answered, 1, "and only that one was collected from");
    assert_eq!(
        answer.refused, 0,
        "the shouting peer's path never reached the chain to be folded"
    );
    assert!(answer.proofs.is_empty());

    node.shutdown();
}

/// **A request naming more places than one answer carries is refused.**
///
/// GUARD. How large an answer gets is the asker's to choose here, so it is
/// capped twice: once by the decoder, before a byte is reserved for it, and
/// once where the question is set aside, so a caller inside this process
/// cannot get past the first.
#[test]
fn a_request_past_the_cap_is_refused_before_it_is_answered() {
    let too_many: Vec<u64> = (0..=MAX_PROVEN as u64).collect();
    let bytes = Message::GetProofs(too_many.clone()).encode();
    assert!(
        Message::decode(&bytes).is_err(),
        "a request for {} places decoded, where the cap is {MAX_PROVEN}",
        too_many.len()
    );

    let mut chain = cairn_chain::ChainStore::new(params());
    let mut local = Local {
        chain: &mut chain,
        keeps: Keeps {
            headers: true,
            cold_set: true,
        },
        listen: 4242,
        nonce: 7,
    };
    let mut peer = PeerState {
        greeted: true,
        ..PeerState::default()
    };
    let reaction = on_message(&mut local, &mut peer, Message::GetProofs(too_many), NOW);
    assert_eq!(
        reaction.prove.as_ref().map(Vec::len),
        Some(MAX_PROVEN),
        "the layer that sets the question aside takes what fits and no more"
    );
}

/// **Asking is charged for, so how much a node spends answering is not the
/// asker's to decide.**
///
/// GUARD. A path is about a kilobyte on a mature chain, so a full request is a
/// block's worth of wire for a message the size of a line of text. Charged on
/// what is asked for rather than on what comes back, because a node that
/// cannot place a position still had to look.
#[test]
fn asking_for_paths_spends_the_asker_s_allowance() {
    let mut chain = cairn_chain::ChainStore::new(params());
    let mut local = Local {
        chain: &mut chain,
        keeps: Keeps {
            headers: true,
            cold_set: true,
        },
        listen: 4242,
        nonce: 7,
    };
    let mut peer = PeerState {
        greeted: true,
        ..PeerState::default()
    };
    let full: Vec<u64> = (0..MAX_PROVEN as u64).collect();

    let mut answered = 0;
    for _ in 0..64 {
        let reaction = on_message(&mut local, &mut peer, Message::GetProofs(full.clone()), NOW);
        if reaction.prove.is_some() {
            answered += 1;
        }
    }
    assert!(
        answered > 0 && answered < 64,
        "a peer asking as fast as it can was answered {answered} times out of \
         sixty four, where the window is meant to run out"
    );

    // And the window turning hands the allowance back, so an honest peer that
    // waited is not shut out for good.
    let later = on_message(&mut local, &mut peer, Message::GetProofs(full), NOW + 60);
    assert!(
        later.prove.is_some(),
        "a peer that waited for the next window is answered again"
    );
}

/// **Every place asked about is set aside, whether or not it can be found.**
///
/// GUARD, in the pure layer where the answer is decided. The shape of the
/// answer is what lets an asker tell a node that cannot help from a node that
/// has gone away, and it is settled here rather than wherever the paths are
/// built.
#[test]
fn the_question_is_set_aside_whole_and_in_order() {
    let mut chain = cairn_chain::ChainStore::new(params());
    let mut local = Local {
        chain: &mut chain,
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
        listen: 4242,
        nonce: 7,
    };
    let mut peer = PeerState {
        greeted: true,
        ..PeerState::default()
    };
    let asked = vec![9, 2, 9, 40];
    let reaction = on_message(
        &mut local,
        &mut peer,
        Message::GetProofs(asked.clone()),
        NOW,
    );
    assert_eq!(
        reaction.prove,
        Some(asked),
        "a node that keeps nothing still has the question to answer, in the \
         order it was asked and with nothing left out"
    );
}

/// **A peer that has not introduced itself is answered with nothing.**
///
/// GUARD, and the same one every other question is behind. The whole exchange
/// is one message in and a block's worth of wire out, which is the shape of
/// thing that must not be free to an anonymous socket that has said nothing.
#[test]
fn a_stranger_that_has_not_spoken_is_not_answered() {
    let mut chain = cairn_chain::ChainStore::new(params());
    let mut local = Local {
        chain: &mut chain,
        keeps: Keeps {
            headers: true,
            cold_set: true,
        },
        listen: 4242,
        nonce: 7,
    };
    let mut peer = PeerState::default();
    let reaction = on_message(&mut local, &mut peer, Message::GetProofs(vec![1, 2]), NOW);
    assert!(reaction.prove.is_none());
    assert!(
        reaction.drop_peer.is_some(),
        "asking before introducing yourself ends the connection, like every \
         other question"
    );
}

/// **The place a note landed is all that crosses the wire about it.**
///
/// Not a rule the protocol can enforce and worth pinning all the same. What an
/// asker hands over is a list of numbers, and what comes back is a list of
/// hashes: the answerer is never told whose money it is, what it is worth, or
/// which of the places it was handed matter to whom.
#[test]
fn asking_says_nothing_about_whose_money_it_is() {
    let ready = a_chain_with_a_fallen_note();
    let asked = Message::GetProofs(vec![ready.position]).encode();
    let owner = ready.note.owner.encode();
    let identifier = ready.id.encode();
    assert!(
        !asked.windows(owner.len()).any(|window| window == owner),
        "the owner travelled with the question"
    );
    assert!(
        !asked
            .windows(identifier.len())
            .any(|window| window == identifier),
        "the note travelled with the question"
    );
    assert_eq!(
        asked.len(),
        1 + 4 + 8,
        "a tag, a count and one place, which is the whole of it"
    );
}

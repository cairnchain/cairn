//! The window between adopting a handed-over ledger and being caught up.
//!
//! `accept` deliberately checks nothing about the burial blocks: it does not
//! ask that they exist, or that they carry work. The whole guarantee is the
//! newcomer's own forward validation of them, and the peer that supplied the
//! anchor is the same peer that supplies those blocks.
//!
//! So a node that has been handed one is on probation until it has validated
//! its way to the tip it was handed under. These tests are what that means:
//! what such a node will not do, what it does about a supplier that stops
//! delivering, and what it says when waiting has stopped being the answer.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use cairn_accumulator::Archive;
use cairn_chain::{ChainError, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::Note;
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::joining::Joined;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::node::{Node, Refused};
use cairn_net::sync::{local_handshake, on_message, Local, PeerState};
use cairn_net::wire::{read_message, write_message, Incoming};
use cairn_net::Keeps;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const BURIAL: u64 = 8;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(BURIAL)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// A directory of its own for one test, cleared before and after.
fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-anchor-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("waited for {what} and it never happened");
}

struct Chain {
    state: LedgerState,
    past: Vec<LedgerState>,
    blocks: Vec<Block>,
    headers: Vec<BlockHeader>,
    history: Archive,
    clock: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
            headers: Vec::new(),
            history: Archive::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&self.state, coinbase, Vec::new(), &params, self.clock, 0).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        self.past.push(self.state.clone());
        self.history.add(header_leaf(&block.header.id())).unwrap();
        self.headers.push(block.header);
        self.blocks.push(block);
    }

    fn run(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner);
        }
    }

    /// A handover from this chain, anchored `BURIAL` below its tip.
    fn handover(&self) -> (Handover, Vec<BlockHeader>) {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let anchor = self.history.prove_in(anchor_height, tip.height).unwrap();
        let from = anchor_height.saturating_sub(90) as usize;
        let recent: Vec<BlockHeader> = self.headers[from..=anchor_height as usize].to_vec();
        let handover = state
            .handover(
                at,
                tip,
                self.state.headers_before_tip(),
                anchor,
                self.headers[(anchor_height as usize + 1)..].to_vec(),
                recent.clone(),
            )
            .expect("a node can hand over what it holds");
        (handover, recent)
    }

    /// A `ChainStore` standing at this chain's tip, for building a handshake
    /// that says what this chain carries.
    fn state_as_chain(&self) -> ChainStore {
        let mut chain = ChainStore::new(params());
        for block in &self.blocks {
            chain.add_block(block.clone(), NOW).unwrap();
        }
        chain
    }
}

/// A node that has taken a handover and validated nothing above it.
fn joined() -> (ChainStore, Chain, Vec<BlockHeader>) {
    let supplier = wallet(9);
    let mut source = Chain::new();
    source.run(&supplier, 120);
    let (handover, recent) = source.handover();
    let params = params();
    let state = accept(&handover, &params).unwrap();
    let mut chain = ChainStore::new(params);
    chain.adopt(state, &recent).unwrap();
    (chain, source, recent)
}

/// The disk a node has the instant a handover lands: the ledger it was handed,
/// and not one block above it.
fn directory_holding_a_handover(name: &str) -> (PathBuf, Chain) {
    let supplier = wallet(9);
    let mut source = Chain::new();
    source.run(&supplier, 120);
    let (handover, _recent) = source.handover();

    let directory = scratch(name);
    std::fs::write(
        directory.join(cairn_store::HANDED_LEDGER),
        handover.encode(),
    )
    .unwrap();
    (directory, source)
}

/// A block this node would like to mine next, whatever it thinks of it.
fn next_block(node: &Node, source: &Chain) -> Block {
    let mine = wallet(3);
    node.with_chain(|chain| {
        let height = chain.state().next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params().initial_reward, mine.public_key())],
        );
        assemble_block(
            chain.state(),
            coinbase,
            Vec::new(),
            &params(),
            source.clock + 600,
            0,
        )
        .unwrap()
    })
}

/// **A node acted on the anchor at once, with none of the burial validated.**
///
/// Nothing between `adopt` and catching up marked the chain as provisional.
/// The moment the ledger landed the node answered about balances, took
/// transfers against it, and would extend it with a block of its own: a miner
/// pointed at it spent real work building on a ledger nobody had checked.
///
/// It now holds the anchor on probation, and says so. It still follows the
/// branch and still takes blocks, because taking them is the only way off
/// probation. What it will not do is anything that treats the anchor as
/// settled.
#[test]
fn nothing_is_manufactured_on_the_anchor_before_the_burial_is_checked() {
    let (directory, source) = directory_holding_a_handover("unchecked");
    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    let anchor_height = 120 - BURIAL - 1;
    let tip_height = 119;

    let probation = node
        .probation()
        .expect("a node handed a ledger owes the network its own check of the burial");
    assert_eq!(probation.anchor, anchor_height);
    assert_eq!(
        probation.settles_at, tip_height,
        "the burial depth above it"
    );
    assert_eq!(probation.checked(), 0, "and it has checked none of it");
    assert_eq!(probation.owed(), BURIAL);

    assert_eq!(
        node.height(),
        Some(anchor_height),
        "it still follows the branch, because taking the blocks above the \
         anchor is the only way off probation"
    );
    assert_eq!(
        node.joining(),
        Joined::Done,
        "and it no longer reports itself as a node that was never joining"
    );
    assert_eq!(restored.blocks, 0);

    // The one that matters. A block built here would be real work spent
    // extending an account of the world nobody has stood behind, announced to
    // everyone.
    let built = next_block(&node, &source);
    assert!(
        matches!(node.submit_block(built), Err(Refused::OnProbation(_))),
        "a node that cannot be trusted to know the chain does not make blocks on it"
    );

    // And a transfer is a judgement about the same ledger. The one here could
    // never be spent anywhere, which is the point: the refusal names the
    // probation rather than the transfer, so it happens before the ledger is
    // consulted at all.
    let offered = Transfer::new(Vec::new(), Vec::new());
    assert!(
        matches!(
            node.submit_transaction(offered),
            Err(Refused::OnProbation(_))
        ),
        "whether a note can be spent is a question about a ledger this node \
         has not stood behind"
    );
    assert_eq!(node.pool_len(), 0);

    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// **A heavier honest chain was refused for ever and nothing said so.**
///
/// `adopt` clears the undo records and starts the window closed, so the node
/// holds nothing it could rewind through. A heavier chain that forks below the
/// anchor cannot even be assembled: every block of it is refused for want of a
/// parent this node will never have.
///
/// The refusal is silent towards the peer by design, and that part was right:
/// dropping the messenger keeps the wrong chain and cuts off the only party
/// saying so. What was missing is that nothing anywhere recorded it either, so
/// a node in this position reported a healthy height that never moved and an
/// operator had nothing to read. The refusal is now named.
#[test]
fn a_chain_forking_below_the_anchor_is_refused_and_now_says_so() {
    let (mut chain, _source, _recent) = joined();
    let anchor_height = 120 - BURIAL - 1;

    // A different chain entirely, and a far heavier one.
    let honest_miner = wallet(1);
    let mut honest = Chain::new();
    honest.run(&honest_miner, 2_000);
    assert!(honest.state.total_work() > chain.total_work());

    let mut peer = PeerState::new(None);
    let mut local = Local {
        chain: &mut chain,
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
        listen: 9_000,
        nonce: 7,
    };
    let hello = local_handshake(
        &honest.state_as_chain(),
        Keeps {
            headers: true,
            cold_set: false,
        },
        9_100,
        11,
    );
    let greeting = on_message(&mut local, &mut peer, Message::Hello(hello), NOW);
    assert!(greeting.drop_peer.is_none());
    assert!(
        greeting
            .reply
            .iter()
            .any(|message| matches!(message, Message::GetChain { .. })),
        "the node knows it is behind and asks"
    );

    // Every block of the heavier chain, offered in order.
    let mut said = 0usize;
    for block in &honest.blocks {
        peer.awaiting.insert(block.header.height);
        let reaction = on_message(
            &mut local,
            &mut peer,
            Message::Block(Box::new(block.clone())),
            NOW,
        );
        assert!(
            reaction.drop_peer.is_none(),
            "the honest peer is still never blamed"
        );
        assert!(reaction.applied.is_none(), "and nothing is ever applied");
        if reaction.unreachable.is_some() {
            said += 1;
        }
    }
    assert!(
        said > 0,
        "a branch parting below the point this node was handed on is one it can \
         never cross to, and that is no longer indistinguishable from being early"
    );

    assert_eq!(
        local.chain.height(),
        Some(anchor_height),
        "the node never moves off the anchor"
    );

    // The chain's own answer is unchanged, and deliberately so: it is the node
    // that is in the wrong place, not the block, and the chain has no opinion
    // about which of the two it is.
    let error = local.chain.add_block(honest.blocks[500].clone(), NOW);
    assert!(
        matches!(
            error,
            Err(ChainError::UnknownParent(_) | ChainError::TooOld { .. })
        ),
        "got {error:?}"
    );
}

/// **A node stranded below its anchor had no way back and nothing saying so.**
///
/// The only cure is starting again from an empty directory, and the node could
/// not tell its operator that: there was no error meaning "I am stranded",
/// only one meaning "this block has no parent here", which reads the same as
/// being early.
///
/// It now says so the way an outdated node does. The patience is an hour by
/// default, counted from the chain last moving and only while there is
/// somebody to ask, so a node making any progress never reaches it and one
/// with no peers is never accused of a fault it does not have.
#[test]
fn a_node_that_never_gets_the_burial_says_it_is_stranded_and_stops() {
    let (directory, _source) = directory_holding_a_handover("stranded");
    let (node, _restored) = Node::open(params(), loopback(), &directory).unwrap();
    node.wait_for_the_burial(0);
    assert!(node.probation().is_some());
    assert!(node.stranded().is_none(), "nothing has gone wrong yet");

    // Somebody to ask, who has nothing to give. The node's height cannot move
    // and no amount of waiting will change that.
    let bystander = Node::bind(params(), loopback()).unwrap();
    node.connect(bystander.address()).unwrap();

    wait_for("the node to say it is stranded", || {
        node.stranded().is_some()
    });
    let stranded = node.stranded().unwrap();
    assert_eq!(stranded.anchor, 120 - BURIAL - 1);
    assert_eq!(stranded.settles_at, 119);

    bystander.shutdown();
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// **Nothing ever asked anybody else for the blocks above the anchor.**
///
/// One question went out when the ledger landed, to the peer that had supplied
/// it. The chooser was finished the moment the chain was no longer empty, so
/// every later round was quiet for ever, and a supplier that went silent with
/// the burial undelivered left the node waiting for the rest of its life.
///
/// The blocks are not that peer's to withhold: anyone on the chain has them.
/// So a node on probation asks everybody, at once and then again, and the
/// peer here is one that claims less work than the anchor does, which is
/// exactly the peer nothing else would ever have asked.
#[test]
fn a_node_on_probation_asks_somebody_other_than_its_supplier() {
    let (directory, _source) = directory_holding_a_handover("asks");
    let (node, _restored) = Node::open(params(), loopback(), &directory).unwrap();
    assert!(node.probation().is_some());

    let mut peer = TcpStream::connect(node.address()).unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let hello = Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        // Less work than the anchor claims, so nothing in the handshake gives
        // this node any reason to ask.
        height: 0,
        total_work: 0,
        listen: 1,
        nonce: 424_242,
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
    });
    write_message(&mut peer, params().network, &hello).unwrap();
    peer.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut asked = false;
    while !asked && Instant::now() < deadline {
        match read_message(&mut peer, params().network) {
            Ok(Incoming::Message(Message::GetChain { .. })) => asked = true,
            Ok(_) => {}
            Err(error) => panic!("the connection failed: {error}"),
        }
    }
    assert!(
        asked,
        "a node on probation asks whoever it can reach for the blocks above \
         its anchor, rather than waiting on the one peer that handed it over"
    );

    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// **Probation ends where it was undertaken to end, and only there.**
///
/// The other half of the rule, and the one that makes it a probation rather
/// than a permanent disability: a node that validates its way to the tip it
/// was handed under has done exactly what it undertook, and from that point
/// its own work stands behind everything it answers about. It mines, it pools
/// transfers, and nothing here says anything about it any more.
#[test]
fn probation_ends_when_the_burial_has_been_validated() {
    let (directory, source) = directory_holding_a_handover("ends");
    let host_directory = scratch("ends-host");
    let (host, _) = Node::open_archiving(params(), loopback(), &host_directory).unwrap();
    for block in &source.blocks {
        host.submit_block(block.clone()).unwrap();
    }

    let (node, _restored) = Node::open(params(), loopback(), &directory).unwrap();
    assert!(node.probation().is_some());
    let refused = next_block(&node, &source);
    assert!(matches!(
        node.submit_block(refused),
        Err(Refused::OnProbation(_))
    ));

    node.connect(host.address()).unwrap();
    wait_for("the burial to be validated", || node.height() == Some(119));
    assert!(
        node.probation().is_none(),
        "the blocks the anchor was taken on the promise of have been checked"
    );
    assert_eq!(node.joining(), Joined::No, "so it is an ordinary node now");

    let built = next_block(&node, &source);
    assert!(
        node.submit_block(built).is_ok(),
        "and it makes blocks again, which is the control on every refusal above"
    );

    node.shutdown();
    host.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&host_directory);
}

/// A raw connection that has introduced itself and claims nothing.
///
/// Claiming nothing matters: a peer that says it carries no work gives this
/// node no reason to ask it for anything, so whatever it is then sent is
/// something the node went and asked for on its own account.
fn a_bare_peer(node: &Node, nonce: u64) -> TcpStream {
    let mut peer = TcpStream::connect(node.address()).unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let hello = Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen: 0,
        nonce,
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
    });
    write_message(&mut peer, params().network, &hello).unwrap();
    peer.flush().unwrap();
    peer
}

/// Waits for one message this node sends that `wanted` recognises.
fn until_it_sends<T>(peer: &mut TcpStream, wanted: impl Fn(&Message) -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match read_message(peer, params().network) {
            Ok(Incoming::Message(message)) => {
                if let Some(found) = wanted(&message) {
                    return found;
                }
            }
            Ok(Incoming::Quiet) => {}
            Err(error) => panic!("the connection failed: {error}"),
        }
    }
    panic!("the node never sent what this was waiting for");
}

/// **A stranger's single header could stop a joined node ever filling in the
/// ones from before it arrived.**
///
/// `Message::Headers` was taken before the greeting check, before the cost
/// accounting, and with no idea who had sent it. There is one collection and
/// it is checked only at the end, so a stranger's header at height zero fixed
/// where the collection started; every honest answer after it was dropped for
/// starting somewhere else, and when the run finally reached the anchor the
/// commitment check threw the whole thing away. One message bought that, and
/// it could be sent again for ever.
///
/// A joined node that never fills those headers in can never show the chain to
/// anybody, so this is the difference between a network that grows and one
/// where only the original nodes can ever take a newcomer in. The collection
/// now belongs to the one peer this node asked, which is the same fix
/// `join_piece` carries for the other collection.
#[test]
fn a_stranger_cannot_put_a_header_into_a_collection_it_was_not_asked_for() {
    let (directory, source) = directory_holding_a_handover("headers");
    let anchor_height = 120 - BURIAL - 1;
    let oldest = anchor_height - 90;
    // The headers a handover comes with, which is what a node holds after one
    // and the only thing it can check a filled-in run against.
    {
        let mut log = cairn_store::HeaderLog::open(&directory).unwrap();
        for height in oldest..=anchor_height {
            log.append(&source.headers[height as usize]).unwrap();
        }
    }
    let (node, _restored) = Node::open(params(), loopback(), &directory).unwrap();

    // The peer the node picks, which is the first to connect. It waits until
    // it has actually been asked, so what follows is a stranger cutting in on
    // an exchange rather than a race to be first.
    let mut asked = a_bare_peer(&node, 111_111);
    until_it_sends(&mut asked, |message| {
        matches!(message, Message::GetHeaders { from: 0, .. }).then_some(())
    });

    // The stranger, with one header at the height the collection starts at.
    let mut stranger = a_bare_peer(&node, 222_222);
    let mut invented = source.headers[0];
    invented.nonce = invented.nonce.wrapping_add(1);
    write_message(
        &mut stranger,
        params().network,
        &Message::Headers {
            from: 0,
            headers: vec![invented],
        },
    )
    .unwrap();
    // One connection is read in order, so an answer to something sent after
    // the header is proof the header has already been dealt with. Without
    // this the two peers race and the test would sometimes pass by luck.
    write_message(&mut stranger, params().network, &Message::Ping(5)).unwrap();
    stranger.flush().unwrap();
    until_it_sends(&mut stranger, |message| {
        matches!(message, Message::Pong(5)).then_some(())
    });

    // The truth, from the peer that was asked for it.
    let honest: Vec<BlockHeader> = (0..oldest)
        .map(|height| source.headers[height as usize])
        .collect();
    write_message(
        &mut asked,
        params().network,
        &Message::Headers {
            from: 0,
            headers: honest,
        },
    )
    .unwrap();
    asked.flush().unwrap();

    wait_for(
        "the headers from before this node arrived to be filled in",
        || {
            cairn_store::HeaderLog::open(&directory)
                .map(|log| log.first_height() == 0)
                .unwrap_or(false)
        },
    );

    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// **One header per question held the turn to fill in a joined node's
/// headers for ever.**
///
/// The turn belongs to one peer because a run half from one peer and half from
/// another would be thrown out at the commitment check with neither of them
/// shown to be wrong. It was kept while the collection had grown inside
/// `HEADER_PATIENCE`, and it grew by one header.
///
/// So a peer that answered each question with a single header renewed the turn
/// every time. Measured on the code before this test: over seventy five seconds
/// the collection moved sixty eight places out of three hundred and one, and no
/// other peer was asked once. A node in that state never fills its old headers
/// in, so it can never show the chain to a newcomer, which is the ability this
/// whole exchange exists to keep alive. One small message per patience window
/// bought it.
///
/// Progress is now a run rather than a header, which is what `crate::wire`
/// already does with a frame: a peer that keeps delivering keeps its turn, and
/// one that only answers loses it.
#[test]
fn a_peer_that_answers_one_header_at_a_time_does_not_hold_the_turn() {
    let (directory, source) = directory_holding_a_handover("dribbled");
    let anchor_height = 120 - BURIAL - 1;
    // Few enough seeded that the run below them is longer than this test
    // watches for, so a holder feeding one header a second cannot finish it and
    // pass on its own terms.
    let oldest = anchor_height - 10;
    {
        let mut log = cairn_store::HeaderLog::open(&directory).unwrap();
        for height in oldest..=anchor_height {
            log.append(&source.headers[height as usize]).unwrap();
        }
    }
    let (node, _restored) = Node::open(params(), loopback(), &directory).unwrap();

    let mut holder = a_bare_peer(&node, 333_333);
    until_it_sends(&mut holder, |message| {
        matches!(message, Message::GetHeaders { from: 0, .. }).then_some(())
    });
    // Somebody who could answer the whole run in one message, and who is never
    // asked for as long as the holder holds the turn.
    let mut waiting = a_bare_peer(&node, 444_444);

    let started = Instant::now();
    let mut served = 0usize;
    let mut passed_on = false;
    while started.elapsed() < Duration::from_secs(90) && !passed_on {
        for from in headers_wanted(&mut holder) {
            if from < oldest {
                write_message(
                    &mut holder,
                    params().network,
                    &Message::Headers {
                        from,
                        headers: vec![source.headers[from as usize]],
                    },
                )
                .unwrap();
                holder.flush().unwrap();
                served += 1;
            }
        }
        passed_on = !headers_wanted(&mut waiting).is_empty();
    }

    assert!(
        served > 5,
        "the holder answered {served} questions, so this test never put the \
         renewal it is about to the node"
    );
    assert!(
        passed_on,
        "the holder answered {served} questions with one header each and kept \
         the turn for {:?}: a run of headers is what a turn is for, and a \
         header at a time is not one",
        started.elapsed()
    );

    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// **A peer whose run was thrown away was handed the turn straight back.**
///
/// A collection thrown away is meant to end that peer's turn: the code says
/// "the next peer is asked on the next round" and the commitment check says
/// "give somebody else the turn". Both forgot the turn outright, and forgetting
/// it is what handed it back. With nothing remembered, the round starts again
/// at the lowest connected identifier, which is the oldest connection, so
/// whoever had stayed connected longest was picked again every time.
///
/// The whole of it costs two headers that do not follow on: the first lands,
/// the second is out of order, and the collection goes. Measured on the code
/// before this test: fifty one collections spoiled in sixty seconds for
/// eighteen kilobytes from one connection, with a peer that could have answered
/// the whole run in one message never asked once. That is the same end as the
/// two defects above it, by a door neither closed: a node that never fills in
/// the headers from before it arrived can never show the chain to a newcomer.
#[test]
fn a_peer_that_spoils_the_collection_does_not_get_the_turn_back() {
    let (directory, source) = directory_holding_a_handover("spoiled");
    let anchor_height = 120 - BURIAL - 1;
    let oldest = anchor_height - 10;
    {
        let mut log = cairn_store::HeaderLog::open(&directory).unwrap();
        for height in oldest..=anchor_height {
            log.append(&source.headers[height as usize]).unwrap();
        }
    }
    let (node, _restored) = Node::open(params(), loopback(), &directory).unwrap();

    // The first connection, so the lowest identifier and the one a forgotten
    // turn goes back to.
    let mut spoiler = a_bare_peer(&node, 555_555);
    until_it_sends(&mut spoiler, |message| {
        matches!(message, Message::GetHeaders { from: 0, .. }).then_some(())
    });
    // Somebody who could answer the whole run in one message.
    let mut waiting = a_bare_peer(&node, 666_666);

    // Long enough that the half minute a turn runs for on its own would be
    // reached and passed, so a turn that ends only by running out of patience
    // is told apart from one that ends when the collection is thrown away.
    let watched = Duration::from_secs(45);
    let started = Instant::now();
    let mut thrown_away = 0usize;
    let mut passed_on: Option<Duration> = None;
    while started.elapsed() < watched && passed_on.is_none() {
        for from in headers_wanted(&mut spoiler) {
            // Two headers that do not follow on: the first lands, the second
            // is out of order, and the collection goes.
            let run = vec![
                source.headers[from as usize],
                source.headers[(from + 2) as usize],
            ];
            write_message(
                &mut spoiler,
                params().network,
                &Message::Headers { from, headers: run },
            )
            .unwrap();
            spoiler.flush().unwrap();
            thrown_away += 1;
        }
        if !headers_wanted(&mut waiting).is_empty() {
            passed_on = Some(started.elapsed());
        }
    }

    assert!(
        thrown_away > 0,
        "the spoiler was never asked, so this test never put its case to the node"
    );
    let Some(took) = passed_on else {
        panic!(
            "the spoiler had {thrown_away} collections thrown away over {:?} and was \
             asked again every time, and nobody else was asked once",
            started.elapsed()
        );
    };
    // Well inside the half minute an idle turn runs for, because a collection
    // thrown away ends the turn there and then. Anything near it would mean the
    // turn was only expiring, which costs the node that half minute for every
    // connection a stranger holds.
    assert!(
        took < Duration::from_secs(15),
        "the turn passed on after {took:?}, which is a turn running out rather \
         than a spoiled collection ending it"
    );

    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// Every `GetHeaders` waiting on this connection, by the height it starts at.
///
/// Drains rather than waits: the point is usually that nothing is there.
fn headers_wanted(peer: &mut TcpStream) -> Vec<u64> {
    let mut wanted = Vec::new();
    loop {
        match read_message(peer, params().network) {
            Ok(Incoming::Message(Message::GetHeaders { from, .. })) => wanted.push(from),
            Ok(Incoming::Message(_)) => {}
            Ok(Incoming::Quiet) | Err(_) => return wanted,
        }
    }
}

/// **`at.total_work` used never to be checked, and it is what the node
/// compares every peer against for the rest of its life.**
///
/// `accept` looked at the anchor's proof of work, its height, its place in the
/// tip's forest and its state root. It never asked whether `total_work` was
/// the number the chain behind it adds up to; nothing it held could answer
/// that. `LedgerState::rebuilt` then took the field verbatim, and
/// `ChainStore::total_work` returned it.
///
/// Every later decision about whether another chain is worth looking at runs
/// off that number: `greet` asks for a chain only when a peer claims more, and
/// `follow_up` the same. So an anchor stating an absurd figure did not merely
/// mislead an operator, it switched off the node's only remaining way out. It
/// stopped asking.
///
/// What answers it is the run of headers between the anchor and the tip, which
/// the handover now carries. The tip's own work is what the sampling
/// established, and the run is checked block by block, so the anchor's total
/// is that figure less a sum nobody chose. Probation was never going to close
/// this one: it makes such a node harmless to everyone else and gets it asking
/// again on its own schedule, but it cannot make an unchecked number checked.
#[test]
fn an_anchor_cannot_state_whatever_work_it_likes() {
    let supplier = wallet(9);
    let mut source = Chain::new();
    source.run(&supplier, 120);

    let anchor_height = (120 - BURIAL - 1) as usize;
    let tip_height = 119u64;
    let anchor_state = &source.past[anchor_height];

    // The one field nothing used to check.
    let mut forged_at = source.headers[anchor_height];
    forged_at.total_work = u128::MAX / 2;

    // Its identifier moved, so the forest that vouches for it is rebuilt with
    // the new leaf in place. The sender builds that forest anyway.
    let mut forest = Archive::new();
    for (height, header) in source.headers.iter().enumerate() {
        let leaf = if height == anchor_height {
            header_leaf(&forged_at.id())
        } else {
            header_leaf(&header.id())
        };
        forest.add(leaf).unwrap();
    }

    let mut tip = source.headers[tip_height as usize];
    tip.history = forest.commitment();
    tip.difficulty = 1;
    tip.total_work = u128::MAX / 2;

    let from = anchor_height + 1 - 91;
    let mut recent: Vec<BlockHeader> = source.headers[from..=anchor_height].to_vec();
    *recent.last_mut().unwrap() = forged_at;

    let handover = Handover {
        at: forged_at,
        tip,
        tip_history: forest.forest().roots_only(),
        anchor: forest.prove_in(anchor_height as u64, tip.height).unwrap(),
        hot: anchor_state.hot_notes().collect(),
        cold: anchor_state.cold_roots(),
        grace: anchor_state.grace_window(),
        grace_proofs: anchor_state
            .grace_window()
            .iter()
            .flatten()
            .filter_map(|(_, position, _)| {
                Some((*position, anchor_state.cold().proof_of(*position)?))
            })
            .collect(),
        headers: anchor_state.headers_before_tip(),
        maturing: anchor_state.maturing(),
        supply: anchor_state.supply(),
        buried: source.headers[anchor_height + 1..=tip_height as usize].to_vec(),
        recent: recent.clone(),
    };

    let refused = accept(&handover, &params());
    assert!(
        refused.is_err(),
        "the run above the anchor does not add up to the work it claims"
    );
}

/// **Cleared: a node that has just adopted cannot pass the anchor on.**
///
/// The one thing that would turn a single forged anchor into an epidemic is a
/// victim that can hand it to the next newcomer. It cannot, and the reason is
/// structural rather than a check that could be forgotten.
///
/// Serving a ledger goes through `ledger_at(tip - burial)`, and `adopt` sets
/// the undo window closed at the anchor, so there is nothing to undo back to
/// until the node has applied `burial` blocks of its own. Serving a weighing
/// needs a path through the header forest from before the node arrived, which
/// it does not hold.
///
/// It is worth noticing that this is the same boundary probation ends at, and
/// not by coincidence: a node becomes able to write a ledger of its own at
/// exactly the moment its own work stands behind one.
#[test]
fn a_node_that_has_just_adopted_cannot_serve_the_anchor_onward() {
    let (chain, _source, _recent) = joined();
    let anchor_height = 120 - BURIAL - 1;

    assert_eq!(chain.undo_records(), 0, "nothing was ever undoable");
    assert!(
        chain
            .ledger_at(anchor_height.saturating_sub(BURIAL))
            .is_none(),
        "so it can build no handover of its own, and `build_join` gives up here"
    );
    assert!(
        chain.ledger_at(anchor_height).is_some(),
        "only where it already stands, which is not deep enough to hand over"
    );
}

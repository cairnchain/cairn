//! Seam audit: what one crate promises and the crate on the other side reads.
//!
//! Nothing here is about the inside of a crate. Every test stands two of them
//! up together and asks whether the thing crossing between them means the same
//! on both sides.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::Note;
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Message, JOIN_PART_BYTES, MAX_JOIN_PARTS};
use cairn_net::sync::{local_handshake, on_message, DropReason, Local, PeerState};
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

/// A chain built block by block, keeping every past ledger so a handover can
/// be taken from any height.
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

    /// A handover from this chain, anchored `BURIAL` below its tip, with the
    /// run of recent headers that goes with it.
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

    /// A `ChainStore` that read this chain from its first block.
    fn read_from_the_first_block(&self) -> ChainStore {
        let mut chain = ChainStore::new(params());
        for block in &self.blocks {
            chain.add_block(block.clone(), NOW).unwrap();
        }
        chain
    }
}

/// A node that took a handover rather than reading its way to one.
fn joined() -> ChainStore {
    let supplier = wallet(9);
    let mut source = Chain::new();
    source.run(&supplier, 120);
    let (handover, recent) = source.handover();
    let state = accept(&handover, &params()).unwrap();
    let mut chain = ChainStore::new(params());
    chain.adopt(state, &recent).unwrap();
    chain
}

fn local(chain: &mut ChainStore) -> Local<'_> {
    Local {
        chain,
        keeps: Keeps {
            headers: true,
            cold_set: false,
        },
        listen: 9944,
        nonce: 7,
    }
}

/// **A node that joined by handover says it has no chain at all, for ever,
/// and never checks anybody else's.**
///
/// `ChainStore::genesis` answers out of the branch's milestone list, and
/// `Branch::from_tail` builds a branch with no milestones on purpose: a node
/// handed a ledger was not there for what came before it and says so by
/// having none. `Branch::push` then only ever fills the milestone the list is
/// actually missing, which for a branch that starts at height thirty thousand
/// is milestone twenty nine while the list holds none, so the condition
/// `index == self.milestones.len()` is false at every milestone height this
/// node will ever reach. The list stays empty for the life of the node.
///
/// `sync::local_handshake` reads that `None` and puts `Hash32::ZERO` on the
/// wire, which in `accept_handshake` is the agreed way of saying "I have no
/// chain and will take whichever one I am handed".
#[test]
fn a_joined_node_can_never_say_which_chain_it_is_on() {
    let mut chain = joined();

    assert_eq!(
        chain.height(),
        Some(120 - BURIAL - 1),
        "it is following a chain a hundred and eleven blocks long"
    );
    assert!(!chain.is_empty(), "and it knows it is following one");

    assert_eq!(
        chain.genesis(),
        None,
        "yet it holds no first block, and never will"
    );

    let said = local_handshake(
        &chain,
        Keeps {
            headers: true,
            cold_set: false,
        },
        9944,
        7,
    );
    assert_eq!(
        said.genesis,
        Hash32::ZERO,
        "so what it tells every peer is the value reserved for a node with no \
         chain at all, while it reports a height of a hundred and eleven in \
         the same message"
    );
    assert_eq!(said.height, 120 - BURIAL - 1);

    // And it stays that way however long the node runs. Fifty more blocks,
    // including a milestone boundary's worth of pushes, change nothing.
    let mut source = Chain::new();
    source.run(&wallet(9), 200);
    for block in &source.blocks {
        let _ = chain.add_block(block.clone(), NOW);
    }
    assert_eq!(
        chain.genesis(),
        None,
        "no number of blocks applied afterwards puts a milestone back"
    );
}

/// **The same node cannot refuse a peer on a different chain.**
///
/// `accept_handshake` guards the comparison with `if let Some(ours) =
/// chain.genesis()`. A joined node's is `None`, so the arm never runs: it
/// will greet a peer whose first block is nothing like its own, on the same
/// network identifier, and start syncing from it.
///
/// The control below is the same greeting offered to a node that read its
/// chain from the first block, which refuses it.
#[test]
fn a_joined_node_greets_a_peer_from_a_foreign_chain() {
    let alien = Hash32::from_bytes([0x5a; 32]);

    // A node that read its way up. It has a genesis, so it checks.
    let mut source = Chain::new();
    source.run(&wallet(9), 120);
    let mut read = source.read_from_the_first_block();
    assert!(read.genesis().is_some());

    let mut theirs = local_handshake(
        &read,
        Keeps {
            headers: true,
            cold_set: false,
        },
        9944,
        7,
    );
    theirs.genesis = alien;
    theirs.nonce = 99;

    let mut peer = PeerState::default();
    let reaction = on_message(
        &mut local(&mut read),
        &mut peer,
        Message::Hello(theirs),
        NOW,
    );
    assert!(
        matches!(
            reaction.drop_peer,
            Some(DropReason::ForeignChain { theirs: got }) if got == alien
        ),
        "a node that knows its own first block turns away a chain that is not \
         it, and this is the check the field exists for"
    );

    // The same greeting, to a node that joined.
    let mut chain = joined();
    let mut peer = PeerState::default();
    let reaction = on_message(
        &mut local(&mut chain),
        &mut peer,
        Message::Hello(theirs),
        NOW,
    );
    assert_eq!(
        reaction.drop_peer, None,
        "the joined node has nothing to compare against and lets it in, which \
         is the documented behaviour for a node with no chain; this node has \
         a chain a hundred and eleven blocks long"
    );
    assert!(peer.greeted, "and it is now a peer like any other");
}

/// **And the other side of the same coin: nobody can refuse the joined node
/// either.**
///
/// A node that did read its chain sees `Hash32::ZERO` from the joined one and
/// takes it, by the rule written for newcomers. So on a network where most
/// nodes joined rather than replayed, which is the whole claim of the design,
/// the genesis field is checked in neither direction.
#[test]
fn nobody_checks_the_genesis_a_joined_node_offers() {
    let mut source = Chain::new();
    source.run(&wallet(9), 120);
    let mut read = source.read_from_the_first_block();

    let joined_chain = joined();
    let mut theirs = local_handshake(
        &joined_chain,
        Keeps {
            headers: true,
            cold_set: false,
        },
        9945,
        8,
    );
    assert_eq!(theirs.genesis, Hash32::ZERO);
    // It is on a chain of its own, and says a height to prove it.
    theirs.total_work = 1;

    let mut peer = PeerState::default();
    let reaction = on_message(
        &mut local(&mut read),
        &mut peer,
        Message::Hello(theirs),
        NOW,
    );
    assert_eq!(
        reaction.drop_peer, None,
        "a zero genesis is read as 'I have no chain', and there is no way for \
         the reader to tell that apart from a node on a different chain that \
         has simply forgotten its own first block"
    );
}

/// **What a join answer can carry, against what the wire can deliver.**
///
/// `MAX_JOIN_PARTS` and `JOIN_PART_BYTES` live in `cairn-net` and bound what a
/// handover may take on the wire. What a handover actually takes is decided in
/// `cairn-ledger`, by `hot_capacity`, `GRACE_NOTES`, `MOST_BURIED` and the
/// depth of a cold set proof. Nothing multiplies the second set out against
/// the first.
///
/// This measures the product rather than asserting a defect: the margin is the
/// finding.
#[test]
fn a_handover_at_the_rules_ceiling_against_what_the_wire_carries() {
    let carried = (MAX_JOIN_PARTS as usize) * JOIN_PART_BYTES;

    // Measured rather than assumed: one hot note, one grace note with a proof
    // of a given depth, one buried header.
    let miner = wallet(1);
    let note = Note::new(params().initial_reward, miner.public_key());
    let note_bytes = note.encode().len();
    let id_bytes = cairn_ledger::note::NoteId::new(Hash32::ZERO, 0)
        .encode()
        .len();
    let header_bytes = {
        let mut chain = Chain::new();
        chain.run(&miner, 1);
        chain.headers[0].encode().len()
    };

    // A hot entry on the wire is the identifier, the note, and the height.
    let hot_entry = id_bytes + note_bytes + 8;
    // A grace entry is the identifier, the position, and the note.
    let grace_entry = id_bytes + 8 + note_bytes;

    let hot_capacity = params().hot_capacity;
    let grace_notes = cairn_ledger::state::GRACE_NOTES;
    let most_buried = cairn_ledger::handover::MOST_BURIED as usize;

    // A cold set proof is one hash per level of the tree the note sits in.
    // The forest allows sixty four; a chain with 2^36 notes ever spent gives
    // thirty six.
    let report = |depth: usize| -> usize {
        let proof = 8 + 4 + depth * 32;
        hot_capacity * hot_entry + grace_notes * (grace_entry + proof) + most_buried * header_bytes
    };

    let realistic = report(36);
    let ceiling = report(cairn_accumulator::forest::MAX_HEIGHT);

    println!("wire can deliver              {carried} bytes");
    println!("handover at 2^36 cold notes   {realistic} bytes");
    println!("handover at the forest's max  {ceiling} bytes");
    println!(
        "hot set alone                 {} bytes",
        hot_capacity * hot_entry
    );
    println!(
        "grace proofs alone at 2^36    {} bytes",
        grace_notes * (8 + 4 + 36 * 32)
    );

    assert!(
        realistic < carried,
        "a handover on a chain with 2^36 notes ever spent still fits, with \
         {} bytes to spare",
        carried - realistic
    );
}

/// **A `ledger.dat` the disk will not give back reads as "this node was never
/// handed a ledger", and the node then throws away every block it has.**
///
/// `read_handed_ledger` is three `.ok()?` in a row: `std::fs::read`, then
/// `Handover::decode` (a `CodecError` from `cairn-primitives`), then `accept`
/// (a `HandoverError` from `cairn-ledger`, twenty-two variants). All three
/// produce the same `None` as a directory that never held the file.
///
/// The file carries no magic and no format tag of its own — `Handover::encode`
/// begins straight at `self.at` — so a change to the `Handover` serialisation
/// lands in the second of those three, and a rule change past this build's
/// schedule lands in the third.
///
/// `None` used to mean `start = 0` to the code below it. The block log of a
/// node that joined begins above zero, so `rejoining` was true, `reached` was
/// zero, and `log.keep_below(0)` emptied it: the node came back with neither
/// the ledger nor the blocks that stood on it.
///
/// The three are told apart now. Only a file that is not there is a node that
/// never had one; a file that is there and will not be used stops the node
/// with the reason, and nothing on the disk is touched, which is what lets the
/// file be put back.
#[test]
fn a_ledger_file_the_disk_refuses_costs_the_node_nothing_it_holds() {
    let directory = std::env::temp_dir().join(format!(
        "cairn-seam-ledger-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();

    let supplier = wallet(9);
    let mut source = Chain::new();
    source.run(&supplier, 120);
    let (handover, _recent) = source.handover();
    let anchor = handover.at.height;

    std::fs::write(
        directory.join(cairn_store::HANDED_LEDGER),
        handover.encode(),
    )
    .unwrap();

    // The blocks above the anchor, which is what such a node's log holds.
    {
        let (mut log, _) = cairn_store::BlockLog::open(&directory).unwrap();
        for block in &source.blocks[(anchor as usize + 1)..] {
            log.append(block).unwrap();
        }
        assert_eq!(log.first_height(), anchor + 1);
    }

    let listen = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
    let (node, restored) = cairn_net::node::Node::open(params(), listen, &directory).unwrap();
    assert!(!restored.rejoining, "an ordinary start");
    assert_eq!(
        node.height(),
        Some(source.headers.last().unwrap().height),
        "the ledger plus the blocks above it reach the tip"
    );
    node.shutdown();
    drop(node);

    let held = {
        let (log, _) = cairn_store::BlockLog::open(&directory).unwrap();
        log.len()
    };
    assert!(held > 0, "and the blocks are still on the disk: {held}");

    // The disk gives back something that is not a handover. Any I/O failure,
    // any change to the encoding, and any rule this build has no schedule for
    // arrives here as the same `None`.
    std::fs::write(directory.join(cairn_store::HANDED_LEDGER), b"not a ledger").unwrap();

    let refused = cairn_net::node::Node::open(params(), listen, &directory);
    assert!(
        matches!(
            refused,
            Err(cairn_net::node::NodeError::UnusableLedger { .. })
        ),
        "the node read a file it could not use as a node that never had one: {:?}",
        refused.map(|_| ())
    );

    let left = {
        let (log, _) = cairn_store::BlockLog::open(&directory).unwrap();
        log.len()
    };
    assert_eq!(
        left,
        held,
        "every block it held must still be there: the log began at {} and \
         nothing may cut it over a file that can be put back",
        anchor + 1
    );

    let _ = std::fs::remove_dir_all(&directory);
}

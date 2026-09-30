//! The conversation between two nodes, without a network under it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::ForestProof;
use cairn_chain::ChainStore;
use cairn_chain::Located;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PeerAddress, Placed, MAX_CHAIN, PROTOCOL_VERSION};
use cairn_net::sync::{
    asked_for_the_chain, local_handshake, on_message, tick, DropReason, Local, PeerState,
    BATCH_PATIENCE,
};
use cairn_net::wire::{read_message, write_message, Incoming, WireError, MAX_FRAME_BYTES};
use cairn_net::Keeps;
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Hash32;
use std::net::SocketAddr;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// Builds blocks on a private ledger, so a chain can exist before any node has
/// it.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self) -> Block {
        self.mine_judged_at(NOW)
    }

    /// The next block, checked against a clock that agrees with its own date,
    /// so a block can be dated further ahead than a node at `NOW` allows.
    fn mine_by_its_own_clock(&mut self) -> Block {
        self.mine_judged_at(self.clock + 600)
    }

    fn mine_judged_at(&mut self, now: u64) -> Block {
        let miner = SecretKey::from_bytes(&[1; 32]);
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
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
        connect_block(&mut self.state, &block, &self.params, now).unwrap();
        block
    }

    fn mine_many(&mut self, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine()).collect()
    }

    /// A second miner starting from the same ledger, whose next block is
    /// dated a few seconds apart, so it is a different block at the same
    /// height.
    fn fork(&self) -> Self {
        Self {
            params: self.params,
            state: self.state.clone(),
            clock: self.clock + 7,
        }
    }
}

fn store_with(params: ConsensusParams, blocks: &[Block]) -> ChainStore {
    let mut store = ChainStore::new(params);
    for block in blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }
    store
}

/// The surroundings a test node has: a chain and an empty address book.
fn solo(chain: &mut ChainStore) -> Local<'_> {
    solo_as(chain, 1)
}

/// Everything a node would send back, including what it resolves after letting
/// go of the chain.
///
/// A node answers a locator and a request for blocks once the chain lock is
/// released, because both reach a disk for anything older than a
/// reorganisation could undo. Here there is no disk and no lock, so this
/// stands in for that step and lets a test read one answer rather than two
/// halves of one.
fn answer(
    chain: &mut ChainStore,
    peer: &mut PeerState,
    message: Message,
    now: u64,
) -> Vec<Message> {
    resolve(on_message(&mut solo(chain), peer, message, now), chain)
}

/// The same, for a node that has to be told which of the two it is.
fn exchange(
    chain: &mut ChainStore,
    peer: &mut PeerState,
    nonce: u64,
    message: Message,
) -> Vec<Message> {
    let kind = message.kind();
    let reaction = on_message(&mut solo_as(chain, nonce), peer, message, NOW);
    assert!(
        reaction.drop_peer.is_none(),
        "dropped on {kind}: {:?}",
        reaction.drop_peer
    );
    resolve(reaction, chain)
}

/// What a node would send, once it has resolved what it deferred.
fn resolve(reaction: cairn_net::sync::Reaction, chain: &ChainStore) -> Vec<Message> {
    let mut out = reaction.reply;
    if let Some(locator) = reaction.locate.as_ref() {
        let (from, count) = chain.chain_after(locator, MAX_CHAIN, 0);
        out.push(Message::Chain { from, count });
    }
    for height in &reaction.fetch {
        if let Some(block) = chain.block_at(*height) {
            out.push(Message::Block(Box::new(block.clone())));
        }
    }
    out
}

/// The same, for a test that needs two nodes to be distinguishable.
///
/// Two nodes sharing a nonce would each take the other for itself, which is
/// exactly what the nonce exists to detect.
fn solo_as(chain: &mut ChainStore, nonce: u64) -> Local<'_> {
    Local {
        keeps: Keeps {
            headers: true,
            cold_set: false,
        },
        nonce,
        chain,
        listen: 4242,
    }
}

fn greeted_peer(work: u128, height: u64) -> PeerState {
    PeerState {
        greeted: true,
        height,
        total_work: work,
        ..PeerState::default()
    }
}

/// A peer that introduced itself when it stood exactly where this node
/// stands, so the greeting asked it for nothing. It is the state every
/// long-lived connection of a node at the tip is in.
fn greeted_as_equal(chain: &ChainStore) -> PeerState {
    greeted_peer(chain.total_work(), chain.height().unwrap())
}

fn asks_for_the_chain(reply: &[Message]) -> bool {
    reply
        .iter()
        .any(|said| matches!(said, Message::GetChain { .. }))
}

#[test]
fn a_message_roundtrips_through_the_wire_format() {
    let mut forge = Forge::new(params());
    let block = forge.mine();

    let messages = vec![
        Message::Ping(42),
        Message::Pong(42),
        Message::GetChain {
            locator: vec![Located::new(0, block.id()), Located::new(9, Hash32::ZERO)],
        },
        Message::Chain { from: 7, count: 12 },
        Message::GetBlocks(vec![0, 1, 2]),
        Message::Announce(vec![Located::new(0, block.id())]),
        Message::Block(Box::new(block.clone())),
        Message::Hello(Handshake {
            version: PROTOCOL_VERSION,
            network: NetworkId::TESTNET,
            genesis: block.id(),
            height: 0,
            total_work: u128::MAX,
            listen: 4242,
            nonce: 99,
            keeps: Keeps {
                headers: true,
                cold_set: true,
            },
        }),
        Message::GetProofs(vec![0, 7, u64::MAX]),
        Message::Proofs(vec![
            Placed {
                position: 7,
                proof: Some(ForestProof {
                    siblings: vec![Hash32::ZERO, block.id()],
                }),
            },
            Placed {
                position: 9,
                proof: None,
            },
        ]),
    ];

    for message in messages {
        let bytes = message.encode();
        assert_eq!(
            Message::decode(&bytes).unwrap(),
            message,
            "{}",
            message.kind()
        );

        let mut framed = Vec::new();
        write_message(&mut framed, NetworkId::TESTNET, &message).unwrap();
        let mut cursor = framed.as_slice();
        assert_eq!(
            read_message(&mut cursor, NetworkId::TESTNET, MAX_FRAME_BYTES).unwrap(),
            Incoming::Message(message)
        );
    }
}

#[test]
fn a_frame_from_another_network_is_refused_on_its_first_bytes() {
    let mut framed = Vec::new();
    write_message(&mut framed, NetworkId::MAINNET, &Message::Ping(1)).unwrap();

    let mut cursor = framed.as_slice();
    let outcome = read_message(&mut cursor, NetworkId::TESTNET, MAX_FRAME_BYTES);
    assert!(
        matches!(outcome, Err(WireError::WrongNetwork { .. })),
        "got {outcome:?}"
    );
}

#[test]
fn an_oversized_frame_is_refused_before_anything_is_reserved() {
    let mut framed = Vec::new();
    NetworkId::TESTNET.as_u32().encode_to(&mut framed);
    u32::MAX.encode_to(&mut framed);

    let mut cursor = framed.as_slice();
    let outcome = read_message(&mut cursor, NetworkId::TESTNET, MAX_FRAME_BYTES);
    match outcome {
        Err(WireError::FrameTooLarge { declared, .. }) => {
            assert!(declared > MAX_FRAME_BYTES);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_truncated_frame_is_refused() {
    let mut framed = Vec::new();
    write_message(&mut framed, NetworkId::TESTNET, &Message::Ping(1)).unwrap();
    framed.truncate(framed.len() - 1);

    let mut cursor = framed.as_slice();
    assert!(read_message(&mut cursor, NetworkId::TESTNET, MAX_FRAME_BYTES).is_err());
}

#[test]
fn an_introduction_is_answered_and_the_shorter_chain_asks_for_more() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(5);

    let mut behind = store_with(params, &blocks[..2]);
    let ahead = store_with(params, &blocks);

    let mut peer = PeerState::default();
    let reaction = on_message(
        &mut solo(&mut behind),
        &mut peer,
        Message::Hello(local_handshake(
            &ahead,
            Keeps {
                headers: true,
                cold_set: false,
            },
            4242,
            7,
        )),
        NOW,
    );

    assert!(peer.greeted);
    assert_eq!(peer.total_work, ahead.total_work());
    assert!(reaction.drop_peer.is_none());
    assert!(matches!(reaction.reply.first(), Some(Message::Welcome(_))));
    assert!(
        matches!(reaction.reply.get(1), Some(Message::GetChain { .. })),
        "a node that is behind asks where the branches part"
    );
}

#[test]
fn the_longer_chain_does_not_ask_the_shorter_one_for_anything() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(5);

    let mut ahead = store_with(params, &blocks);
    let behind = store_with(params, &blocks[..2]);

    let mut peer = PeerState::default();
    let reaction = on_message(
        &mut solo(&mut ahead),
        &mut peer,
        Message::Hello(local_handshake(
            &behind,
            Keeps {
                headers: true,
                cold_set: false,
            },
            4242,
            7,
        )),
        NOW,
    );

    assert!(matches!(reaction.reply.first(), Some(Message::Welcome(_))));
    assert!(
        !reaction
            .reply
            .iter()
            .any(|message| matches!(message, Message::GetChain { .. })),
        "a node that is ahead asks for no blocks"
    );
}

#[test]
fn a_peer_on_another_network_or_version_or_chain_is_dropped() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(3);
    let mut store = store_with(params, &blocks);
    let sound = local_handshake(
        &store,
        Keeps {
            headers: true,
            cold_set: false,
        },
        4242,
        7,
    );

    let cases: Vec<(Handshake, DropReason)> = vec![
        (
            Handshake {
                version: PROTOCOL_VERSION + 1,
                ..sound
            },
            DropReason::WrongVersion {
                theirs: PROTOCOL_VERSION + 1,
            },
        ),
        (
            Handshake {
                network: NetworkId::MAINNET,
                ..sound
            },
            DropReason::WrongNetwork {
                theirs: NetworkId::MAINNET,
            },
        ),
        (
            Handshake {
                genesis: Hash32::from_bytes([7; 32]),
                ..sound
            },
            DropReason::ForeignChain {
                theirs: Hash32::from_bytes([7; 32]),
            },
        ),
    ];

    for (handshake, expected) in cases {
        let mut peer = PeerState::default();
        let reaction = on_message(
            &mut solo(&mut store),
            &mut peer,
            Message::Hello(handshake),
            NOW,
        );
        assert_eq!(reaction.drop_peer, Some(expected));
        assert!(!peer.greeted);
        assert!(
            reaction.reply.is_empty(),
            "nothing is answered to a peer being dropped"
        );
    }
}

/// A frame as a peer writes it: the network's marker, the length, the body.
fn framed(network: NetworkId, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    network.as_u32().encode_to(&mut out);
    u32::try_from(body.len()).unwrap().encode_to(&mut out);
    out.extend_from_slice(body);
    out
}

/// An introduction from another protocol version is refused on its version,
/// however that version lays out the rest of it.
///
/// A handshake's version is its first field, and what follows is laid out as
/// the sender's version lays it out: protocol nine's carried the tip's
/// identifier after the first block, which ten no longer has. The whole frame
/// used to be decoded with this version's layout before the version was
/// compared, so nine's introduction ran 32 bytes long, a later one of another
/// length ran short or long, and a frame that cannot be read is a broken peer
/// whose host is refused. Nothing read another version's introduction off the
/// wire, so a node refusing every node one version away from it passed.
#[test]
fn an_introduction_from_another_version_is_refused_on_its_version_whatever_its_length() {
    let params = params();
    let mut store = ChainStore::new(params);
    let ours = local_handshake(&store, Keeps::default(), 4242, 7).encode();
    let network = params.network;

    // Protocol nine's Hello: tag, version, marker and first block as ten has
    // them, then the tip's identifier, then the rest of ten's fields.
    let mut nine = vec![0u8];
    9u32.encode_to(&mut nine);
    nine.extend_from_slice(&ours[4..40]);
    nine.extend_from_slice(&[0xAB; 32]);
    nine.extend_from_slice(&ours[40..]);
    // A later version's Welcome, longer and carrying fields ten has never had.
    let mut later = vec![1u8];
    (PROTOCOL_VERSION + 1).encode_to(&mut later);
    later.extend_from_slice(&[0x5A; 200]);
    // And one whose introduction is its version and nothing else.
    let mut bare = vec![0u8];
    (PROTOCOL_VERSION + 2).encode_to(&mut bare);

    for (body, theirs) in [
        (nine, 9),
        (later, PROTOCOL_VERSION + 1),
        (bare, PROTOCOL_VERSION + 2),
    ] {
        let read = read_message(
            &mut framed(network, &body).as_slice(),
            network,
            MAX_FRAME_BYTES,
        );
        let Ok(Incoming::Message(message)) = read else {
            panic!(
                "an introduction from protocol {theirs} was not read as one, which a node \
                 holds against the host as a broken frame"
            )
        };
        assert_eq!(
            message.encode().first(),
            body.first(),
            "a Hello from protocol {theirs} was read as a Welcome, or the other way round"
        );
        let mut peer = PeerState::default();
        let reaction = on_message(&mut solo(&mut store), &mut peer, message, NOW);
        assert_eq!(
            reaction.drop_peer,
            Some(DropReason::WrongVersion { theirs }),
            "an introduction from protocol {theirs} was not refused on its version"
        );
        assert!(!peer.greeted);
        assert!(reaction.reply.is_empty());
    }

    // This version's own introduction is still read in full: one byte long is
    // a broken frame, not a version.
    let mut long = vec![0u8];
    long.extend_from_slice(&ours);
    long.push(0);
    assert!(
        matches!(
            read_message(
                &mut framed(network, &long).as_slice(),
                network,
                MAX_FRAME_BYTES
            ),
            Err(WireError::Malformed(_))
        ),
        "an introduction on this version with a byte too many was read"
    );
}

#[test]
fn nothing_is_answered_before_an_introduction() {
    let params = params();
    let mut store = ChainStore::new(params);
    let mut peer = PeerState::default();

    let reaction = on_message(&mut solo(&mut store), &mut peer, Message::Ping(1), NOW);
    assert_eq!(
        reaction.drop_peer,
        Some(DropReason::Unannounced { kind: "ping" })
    );
    assert!(reaction.reply.is_empty());
}

#[test]
fn introducing_yourself_twice_is_refused() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(2);
    let mut store = store_with(params, &blocks);
    let handshake = local_handshake(
        &store,
        Keeps {
            headers: true,
            cold_set: false,
        },
        4242,
        7,
    );

    let mut peer = PeerState::default();
    on_message(
        &mut solo(&mut store),
        &mut peer,
        Message::Hello(handshake),
        NOW,
    );
    let again = on_message(
        &mut solo(&mut store),
        &mut peer,
        Message::Hello(handshake),
        NOW,
    );
    assert_eq!(again.drop_peer, Some(DropReason::RepeatedHandshake));
}

#[test]
fn a_ping_comes_back_as_a_pong() {
    let params = params();
    let mut store = ChainStore::new(params);
    let mut peer = greeted_peer(0, 0);

    let reaction = on_message(&mut solo(&mut store), &mut peer, Message::Ping(99), NOW);
    assert_eq!(reaction.reply, vec![Message::Pong(99)]);
    assert!(reaction.drop_peer.is_none());
}

#[test]
fn a_locator_is_answered_with_what_follows_it() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(6);
    let mut ahead = store_with(params, &blocks);
    let behind = store_with(params, &blocks[..2]);

    let mut peer = greeted_peer(2, 1);
    let replies = answer(
        &mut ahead,
        &mut peer,
        Message::GetChain {
            locator: behind.locator(),
        },
        NOW,
    );

    let (from, count) = match replies.first() {
        Some(Message::Chain { from, count }) => (*from, *count),
        other => panic!("expected a chain, got {other:?}"),
    };
    assert_eq!(
        (from, count),
        (2, 4),
        "exactly the stretch the other side lacks, oldest first"
    );
}

#[test]
fn only_the_missing_blocks_are_asked_for() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(5);
    let mut behind = store_with(params, &blocks[..2]);

    let mut peer = greeted_peer(5, 4);
    let reaction = on_message(
        &mut solo(&mut behind),
        &mut peer,
        Message::Chain { from: 2, count: 3 },
        NOW,
    );

    let asked = match reaction.reply.first() {
        Some(Message::GetBlocks(heights)) => heights.clone(),
        other => panic!("expected a request, got {other:?}"),
    };
    assert_eq!(asked, vec![2, 3, 4]);
    assert_eq!(
        peer.awaiting.len(),
        3,
        "the node remembers what it is waiting for"
    );
}

#[test]
fn a_request_is_answered_with_the_blocks_that_are_held() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(3);
    let mut store = store_with(params, &blocks);

    let mut peer = greeted_peer(3, 2);
    let replies = answer(
        &mut store,
        &mut peer,
        Message::GetBlocks(vec![0, 99, 2]),
        NOW,
    );

    assert_eq!(
        replies.len(),
        2,
        "the height nothing sits at is simply not answered"
    );
    assert_eq!(replies[0], Message::Block(Box::new(blocks[0].clone())));
    assert_eq!(replies[1], Message::Block(Box::new(blocks[2].clone())));
}

#[test]
fn a_block_that_lands_is_worth_telling_everyone_about() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(3);
    let mut behind = store_with(params, &blocks[..2]);

    let mut peer = greeted_peer(3, 2);
    peer.awaiting.insert(2);
    let reaction = on_message(
        &mut solo(&mut behind),
        &mut peer,
        Message::Block(Box::new(blocks[2].clone())),
        NOW,
    );

    assert_eq!(reaction.broadcast, vec![Located::new(2, blocks[2].id())]);
    assert!(reaction.drop_peer.is_none());
    assert_eq!(behind.height(), Some(2));
    assert!(peer.awaiting.is_empty());
}

#[test]
fn a_block_whose_parent_is_missing_is_not_held_against_the_peer() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(4);
    let mut behind = store_with(params, &blocks[..1]);

    let mut peer = greeted_peer(4, 3);
    let reaction = on_message(
        &mut solo(&mut behind),
        &mut peer,
        Message::Block(Box::new(blocks[3].clone())),
        NOW,
    );

    assert!(
        reaction.drop_peer.is_none(),
        "this node is behind, the peer is not at fault"
    );
    assert!(reaction.broadcast.is_empty());
    assert!(
        matches!(reaction.reply.first(), Some(Message::GetChain { .. })),
        "it asks again from where it actually stands"
    );
}

/// A block delivered above this node's tip says the peer that delivered it
/// is ahead, whatever the peer said when it introduced itself.
///
/// The test above holds the same promise for a peer that greeted as ahead,
/// and that was the only fixture there was. Nothing asked it of a peer that
/// greeted as an equal, which is every long-lived connection of a node at
/// the tip: the work a peer wrote in its greeting was the only figure the
/// asking read, and nothing revised it, so a node that missed one
/// announcement asked nothing and stayed behind for as long as its
/// connections lived.
#[test]
fn a_block_above_the_tip_from_a_peer_greeted_as_an_equal_asks_for_the_chain() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(6);
    let mut node = store_with(params, &blocks[..3]);
    let mut peer = greeted_as_equal(&node);

    // The peer has since applied 3, 4 and 5, and this node heard only of 5.
    let announced = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Announce(vec![Located::new(5, blocks[5].id())]),
        NOW,
    );
    assert!(
        matches!(announced.reply.first(), Some(Message::GetBlocks(_))),
        "the announced block is asked for"
    );
    let arrived = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Block(Box::new(blocks[5].clone())),
        NOW + 1,
    );

    assert!(arrived.drop_peer.is_none(), "the peer did nothing wrong");
    assert_eq!(
        node.height(),
        Some(2),
        "the block hangs on a missing parent"
    );
    assert!(
        asks_for_the_chain(&arrived.reply),
        "a block three heights above this node's tip, from the peer that announced it, is \
         evidence the peer is ahead, and nothing was asked of it: the asking read only the \
         work the peer wrote in its greeting"
    );
}

/// A peer that can supply blocks only from above this node's tip is not
/// asked for them.
///
/// A node further behind than its peers keep blocks for is answered from
/// where their logs begin, above its own tip. It asked for those heights all
/// the same, took blocks whose parents it would never hold, and asked again
/// for the chain after each batch, for as long as it ran, with nothing said.
#[test]
fn a_peer_that_can_supply_only_from_above_the_tip_is_not_asked_for_those_blocks() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(3);
    let mut node = store_with(params, &blocks);
    let mut peer = greeted_peer(u128::MAX / 2, 5_000);
    peer.chain_asked = true;

    let answered = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain {
            from: 4_000,
            count: 1_000,
        },
        NOW,
    );
    assert!(
        !answered
            .reply
            .iter()
            .any(|said| matches!(said, Message::GetBlocks(_))),
        "heights no block this node holds can connect to were asked for"
    );
    assert!(peer.awaiting.is_empty(), "and are waited on for nothing");
    assert_eq!(
        answered.cannot_supply,
        Some(4_000),
        "a peer that cannot supply what is above this node's tip was not said to"
    );

    // The same answer nobody asked for is a number a peer wrote, and is not
    // passed up as evidence of anything.
    let unasked = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain {
            from: 4_000,
            count: 1_000,
        },
        NOW,
    );
    assert_eq!(unasked.cannot_supply, None);
}

/// A newcomer holding only the first block its network pins is not counted
/// as further behind than its peers keep, when a peer can supply only from
/// above its tip.
///
/// Such a node holds nothing of its own and can be handed a ledger, as a node
/// with no chain at all can, and is left to its chooser the same way. The
/// check asked whether the chain was empty, which it never is on a network
/// that pins its first block, so two such answers had the node tell its
/// operator it already follows a chain and cannot be handed one. Nothing
/// asked this on a pinned network, so that node passed.
#[test]
fn a_newcomer_holding_only_its_networks_first_block_is_not_counted_short_of_the_tip() {
    let devnet = ConsensusParams::for_network("devnet").unwrap();
    let first = cairn_ledger::genesis::block(devnet.network).unwrap();
    let mut node = store_with(devnet, &[first]);
    assert!(
        node.holds_nothing_of_its_own() && !node.is_empty(),
        "the premise: the node holds only the pinned block"
    );
    let mut peer = greeted_peer(u128::MAX / 2, 5_000);
    peer.chain_asked = true;

    let answered = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain {
            from: 4_000,
            count: 1_000,
        },
        NOW,
    );
    assert_eq!(
        answered.cannot_supply, None,
        "a newcomer holding only its network's pinned first block was counted as a node \
         further behind than its peers keep, which is said only of a node that already \
         follows a chain"
    );
}

/// A tie at one height that the network resolved the other way is followed
/// onto the branch that won.
///
/// A block that lands as a side branch is announced by nobody, so this node
/// hears of the winning branch only through the block that settles the tie,
/// and that block's parent is the side of the tie it never saw. Nothing
/// asked for the chain there from a peer greeted as an equal, so a node that
/// took the losing block first kept the branch the network had left.
#[test]
fn a_tie_resolved_the_other_way_asks_for_the_branch_that_won() {
    let params = params();
    let mut miner_a = Forge::new(params);
    let shared = miner_a.mine_many(3);
    let mut miner_b = miner_a.fork();
    let a3 = miner_a.mine();
    let b3 = miner_b.mine();
    let b4 = miner_b.mine();
    assert_ne!(a3.id(), b3.id(), "two different blocks at height 3");

    let mut node = store_with(params, &shared);
    node.add_block(a3, NOW).unwrap();
    // Greeted while both stood on the same height, before the tie resolved.
    let mut peer = greeted_as_equal(&node);

    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Announce(vec![Located::new(4, b4.id())]),
        NOW + 60,
    );
    let arrived = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Block(Box::new(b4)),
        NOW + 61,
    );

    assert!(arrived.drop_peer.is_none());
    assert_eq!(
        node.height(),
        Some(3),
        "B4 hangs on B3, which this node never saw"
    );
    assert!(
        asks_for_the_chain(&arrived.reply),
        "the network settled a tie on the other branch, and the one message that would bring \
         the block this node missed is a request for the chain, which was not sent"
    );
}

/// A block refused for being dated ahead of this node's clock is asked for
/// again once the clock allows it.
///
/// The refusal said "the block is offered again by whoever announces the
/// next one". What the next announcement offers is the next block, whose
/// parent is the refused one, and a missing parent from a peer greeted as an
/// equal asked for nothing, so the refused block was never named again.
#[test]
fn a_block_refused_for_its_timestamp_is_asked_for_again_once_the_clock_allows_it() {
    let params = params();
    let mut forge = Forge::new(params);
    let settled = forge.mine_many(3);
    forge.clock = NOW + params.max_timestamp_drift + 600;
    let ahead = forge.mine_by_its_own_clock();
    let next = forge.mine_by_its_own_clock();

    let mut node = store_with(params, &settled);
    let mut peer = greeted_as_equal(&node);
    let refused = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Block(Box::new(ahead)),
        NOW,
    );
    assert!(
        refused.ahead_of_the_clock.is_some(),
        "the fixture has to reach the timestamp refusal"
    );

    // Later, with this node's clock past the refused block's date less the
    // drift, the peer announces the block after it.
    let later = NOW + params.max_timestamp_drift + 1_800;
    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Announce(vec![Located::new(4, next.id())]),
        later,
    );
    let arrived = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Block(Box::new(next)),
        later + 1,
    );

    assert!(arrived.drop_peer.is_none());
    assert_eq!(
        node.height(),
        Some(2),
        "block 4 hangs on the refused block 3"
    );
    assert!(
        asks_for_the_chain(&arrived.reply),
        "the refused block only comes back through a request for the chain, and none was sent"
    );
}

/// A peer whose block this node's clock refused is not asked for the chain
/// again until the clock allows that block, and is asked the moment it does.
///
/// Every block above the refused one hangs on it, so each arrives with its
/// parent missing and asks for the chain, and the answer names the refused
/// block again, to be refused again: a batch a round trip for as long as
/// the clock is behind. Nothing held a peer greeted as ahead back from that,
/// and nothing asked again once the wait was over except the peer's next
/// announcement.
#[test]
fn a_peer_whose_block_the_clock_refused_is_asked_again_when_the_clock_allows_it() {
    let params = params();
    let mut forge = Forge::new(params);
    let settled = forge.mine_many(3);
    forge.clock = NOW + params.max_timestamp_drift + 600;
    let ahead = forge.mine_by_its_own_clock();
    let next = forge.mine_by_its_own_clock();
    let allowed = ahead.header.timestamp - params.max_timestamp_drift;

    let mut node = store_with(params, &settled);
    let mut peer = greeted_as_equal(&node);
    let refused = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Block(Box::new(ahead)),
        NOW,
    );
    assert!(refused.ahead_of_the_clock.is_some());
    let hanging = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Block(Box::new(next)),
        NOW + 1,
    );
    assert!(
        !asks_for_the_chain(&hanging.reply),
        "the block this one hangs on is still ahead of the clock, so asking for the chain \
         brings it back only to be refused again"
    );
    let early = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Ping(1),
        allowed - 1,
    );
    assert!(
        !asks_for_the_chain(&early.reply),
        "one second before the clock allows the refused block, the chain was asked for"
    );

    let on_time = on_message(&mut solo(&mut node), &mut peer, Message::Ping(2), allowed);
    assert!(
        asks_for_the_chain(&on_time.reply),
        "the clock allows the refused block now, and nothing asked for it again"
    );
}

/// A batch past its patience is given up on, and the chain asked for again,
/// on whatever the peer says next.
///
/// The patience was read where a `Chain`, an `Announce` or a `Block` arrived
/// and nowhere else, so a peer that had answered everything it was asked and
/// went on talking about anything else held this node mid batch until its
/// next announcement, a block interval away whatever the patience said.
#[test]
fn a_batch_past_its_patience_is_asked_again_on_the_next_word_from_the_peer() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(4);
    let mut node = store_with(params, &blocks[..1]);
    let mut peer = greeted_peer(blocks[3].header.total_work, 3);
    let asked = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain { from: 1, count: 3 },
        NOW,
    );
    assert!(matches!(asked.reply.first(), Some(Message::GetBlocks(_))));

    let inside = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Ping(1),
        NOW + BATCH_PATIENCE - 1,
    );
    assert!(
        !asks_for_the_chain(&inside.reply) && peer.awaiting.len() == 3,
        "a batch inside its patience was given up on"
    );

    let past = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Ping(2),
        NOW + BATCH_PATIENCE,
    );
    assert!(
        matches!(past.reply.first(), Some(Message::Pong(2))),
        "the ping is still answered first"
    );
    assert!(
        asks_for_the_chain(&past.reply) && peer.awaiting.is_empty(),
        "a batch past its patience is still held against a peer that keeps talking, because \
         the patience is read only when the peer speaks of its chain"
    );
}

/// The same with nothing said at all: the loop that reads a quiet
/// connection gives the batch its patience too.
///
/// Nothing ran the patience without a message to run it, so a peer that went
/// silent owing a batch held it until the connection was dropped for
/// silence, a minute and a half later, and nobody was asked meanwhile.
#[test]
fn a_batch_past_its_patience_is_asked_again_when_the_peer_says_nothing() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(4);
    let mut node = store_with(params, &blocks[..1]);
    let mut peer = greeted_peer(blocks[3].header.total_work, 3);
    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain { from: 1, count: 3 },
        NOW,
    );

    let inside = tick(&node, &mut peer, NOW + BATCH_PATIENCE - 1);
    assert!(
        inside.reply.is_empty() && peer.awaiting.len() == 3,
        "a batch inside its patience was given up on"
    );
    let past = tick(&node, &mut peer, NOW + BATCH_PATIENCE);
    assert!(
        asks_for_the_chain(&past.reply) && peer.awaiting.is_empty(),
        "a batch past its patience is held for as long as the peer says nothing"
    );
}

/// A batch whose blocks keep arriving is not given up on, however long the
/// whole of it takes.
///
/// The patience ran from the ask, so a peer delivering a long batch more
/// slowly than one batch a patience was asked for the chain again while
/// still sending, and sent everything twice. The wire's own patience renews
/// on progress for that reason, and this one now does the same.
#[test]
fn a_peer_still_delivering_its_batch_is_not_asked_for_the_chain_again() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(6);
    let mut node = store_with(params, &blocks[..1]);
    let mut peer = greeted_peer(blocks[5].header.total_work, 5);
    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain { from: 1, count: 5 },
        NOW,
    );
    assert_eq!(peer.awaiting.len(), 5, "five heights outstanding");

    // One block every fifty seconds, each well inside the patience measured
    // from the one before it.
    let mut now = NOW;
    for block in &blocks[1..5] {
        now += BATCH_PATIENCE - 10;
        let before = peer.awaiting.len();
        let landed = on_message(
            &mut solo(&mut node),
            &mut peer,
            Message::Block(Box::new(block.clone())),
            now,
        );
        assert_eq!(node.height(), Some(block.header.height), "the block landed");
        assert!(
            !asks_for_the_chain(&landed.reply) && peer.awaiting.len() == before - 1,
            "a peer delivering its batch a block every fifty seconds was given up on in the \
             middle of it: the patience ran from the ask rather than from the last block"
        );
    }
}

/// A batch owed by a quiet peer is given up on one patience after the clock
/// steps back, and not one patience after the clock climbs back past the ask.
///
/// The chooser pulls every moment it holds to the present when the clock
/// steps back, and the probation restarts its wait. The batch patience did
/// neither, so an hour's step was an hour added to the sixty seconds.
#[test]
fn a_batch_owed_by_a_quiet_peer_is_asked_again_one_patience_after_the_clock_stepped_back() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(4);
    let mut node = store_with(params, &blocks[..1]);
    let mut peer = greeted_peer(blocks[3].header.total_work, 3);
    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain { from: 1, count: 3 },
        NOW,
    );
    assert_eq!(peer.awaiting.len(), 3);

    // Any word from the peer reaches the patience (the test above), and a
    // ping asks nothing that could stand in for the batch. A `Chain` from
    // nought did, until a stretch a peer names inside one batch of the tip
    // came to be asked for as its branch.
    let nothing_new = |nonce| Message::Ping(nonce);
    let stepped_back = NOW - 3_600;
    on_message(
        &mut solo(&mut node),
        &mut peer,
        nothing_new(1),
        stepped_back,
    );
    let later = on_message(
        &mut solo(&mut node),
        &mut peer,
        nothing_new(2),
        stepped_back + BATCH_PATIENCE + 1,
    );
    assert!(
        asks_for_the_chain(&later.reply) && peer.awaiting.is_empty(),
        "sixty one seconds after the clock stepped back an hour, the quiet peer still holds \
         the batch: the wait read nought until the clock climbed back past the ask"
    );
}

/// A `Chain` nobody asked for does not renew the patience of a batch already
/// outstanding.
///
/// The patience is renewed by a block of the batch arriving, which is the
/// batch still coming. An answer to a question this node did not put renewed
/// it too, whatever heights it named, so a peer that never sent a block of
/// its batch and sent the same `Chain` again once a minute held this node mid
/// batch for as long as it cared to. Nothing sent one inside the patience.
#[test]
fn a_chain_nobody_asked_for_does_not_hold_a_batch_past_its_patience() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(4);
    let mut node = store_with(params, &blocks[..1]);
    let mut peer = greeted_peer(blocks[3].header.total_work, 3);
    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain { from: 1, count: 3 },
        NOW,
    );
    assert_eq!(peer.awaiting.len(), 3, "three heights outstanding");

    // The same stretch again, a second inside the patience, asked for by
    // nobody.
    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain { from: 1, count: 3 },
        NOW + BATCH_PATIENCE - 1,
    );
    let past = tick(&node, &mut peer, NOW + BATCH_PATIENCE);
    assert!(
        asks_for_the_chain(&past.reply) && peer.awaiting.is_empty(),
        "a batch no block of which arrived is still held a patience after it was asked for, \
         because a `Chain` nobody asked for renewed the wait"
    );
}

/// The same for an announcement of the heights already outstanding: it is
/// the peer's own doing and does not renew the patience either.
///
/// It renewed it the way the `Chain` did, so the same peer held the batch by
/// announcing its heights once a minute instead. Nothing announced inside the
/// patience of a batch already out.
#[test]
fn an_announcement_does_not_hold_a_batch_past_its_patience() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(4);
    let mut node = store_with(params, &blocks[..1]);
    let mut peer = greeted_peer(blocks[3].header.total_work, 3);
    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain { from: 1, count: 3 },
        NOW,
    );
    assert_eq!(peer.awaiting.len(), 3, "three heights outstanding");

    let announced = blocks[1..]
        .iter()
        .map(|block| Located::new(block.header.height, block.id()))
        .collect();
    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Announce(announced),
        NOW + BATCH_PATIENCE - 1,
    );
    let past = tick(&node, &mut peer, NOW + BATCH_PATIENCE);
    assert!(
        asks_for_the_chain(&past.reply) && peer.awaiting.is_empty(),
        "a batch no block of which arrived is still held a patience after it was asked for, \
         because an announcement of its heights renewed the wait"
    );
}

/// What is left of a batch that stopped arriving part way is asked for again
/// once a window of the peer's allowance has turned, long before the batch's
/// patience runs out, and once a window at most.
///
/// A peer serves a batch only as far as the asker's window pays for, which of
/// full blocks is about forty of the hundred and twenty eight asked for, and
/// stops. Nothing asked for the rest: the next question goes out only once
/// nothing is awaited, and the heights left stayed awaited until the patience
/// gave them up, a minute after the last block arrived. A node catching up on
/// full blocks moved one window a minute. Nothing asked this, since every
/// batch in the suite was served whole.
#[test]
fn the_rest_of_a_batch_cut_short_is_asked_for_again_once_a_window_has_turned() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(6);
    let mut node = store_with(params, &blocks[..1]);
    let mut peer = greeted_peer(blocks[5].header.total_work, 5);
    on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain { from: 1, count: 5 },
        NOW,
    );
    // Two of the five arrive, and then nothing: the peer's window is spent.
    let arrived = NOW + 1;
    for block in &blocks[1..3] {
        on_message(
            &mut solo(&mut node),
            &mut peer,
            Message::Block(Box::new(block.clone())),
            arrived,
        );
    }
    assert_eq!(
        node.height(),
        Some(2),
        "fixture: two blocks of the batch landed"
    );
    let rest: Vec<u64> = vec![3, 4, 5];
    assert_eq!(peer.awaiting.iter().copied().collect::<Vec<u64>>(), rest);

    let at_once = tick(&node, &mut peer, arrived);
    assert!(
        at_once.reply.is_empty(),
        "the rest was asked for in the same second the last block arrived, before any \
         window could turn"
    );
    let later = arrived + BATCH_PATIENCE / 2;
    let again = tick(&node, &mut peer, later);
    assert!(
        matches!(again.reply.as_slice(), [Message::GetBlocks(heights)] if *heights == rest),
        "half a patience after the last block of a batch cut short, the rest of it was not \
         asked for: the node waits out the whole patience for the next window of blocks"
    );
    assert_eq!(peer.awaiting.len(), 3, "asking again gave the batch up");
    let twice = tick(&node, &mut peer, later + 1);
    assert!(
        twice.reply.is_empty(),
        "the rest of a batch was asked for again a second after it was asked for"
    );
    // Asking again does not renew the patience: a peer that serves nothing
    // more is still given up on a patience after its last block.
    let past = tick(&node, &mut peer, arrived + BATCH_PATIENCE);
    assert!(
        asks_for_the_chain(&past.reply) && peer.awaiting.is_empty(),
        "asking again for the rest of a batch kept a peer that serves nothing more from \
         ever being given up on"
    );
}

#[test]
fn a_peer_sending_an_invalid_block_is_dropped() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(3);
    let mut store = store_with(params, &blocks[..2]);

    let mut spoiled = blocks[2].clone();
    spoiled.header.state_root = Hash32::ZERO;
    let spoiled = mine_block(spoiled, ATTEMPTS).unwrap();

    let mut peer = greeted_peer(3, 2);
    let reaction = on_message(
        &mut solo(&mut store),
        &mut peer,
        Message::Block(Box::new(spoiled)),
        NOW,
    );

    assert!(matches!(
        reaction.drop_peer,
        Some(DropReason::BadBlock { .. })
    ));
    assert_eq!(store.height(), Some(1), "the chain did not move");
}

#[test]
fn a_full_exchange_carries_one_chain_to_the_other_node() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(30);

    let mut behind = ChainStore::new(params);
    let mut ahead = store_with(params, &blocks);
    let mut peer = PeerState::default();
    // The welcome coming back is this side's introduction, so it starts blank.
    let mut mirror = PeerState::default();

    // Play the conversation out until nothing more is said.
    // Two nodes, two nonces, as on a real network.
    let mut pending = vec![Message::Hello(local_handshake(
        &ahead,
        Keeps {
            headers: true,
            cold_set: false,
        },
        4242,
        2,
    ))];
    let mut rounds = 0;
    while !pending.is_empty() {
        rounds += 1;
        assert!(rounds < 50, "the exchange should settle");

        let mut answers = Vec::new();
        for message in pending.drain(..) {
            answers.extend(exchange(&mut behind, &mut peer, 1, message));
        }
        for message in answers {
            pending.extend(exchange(&mut ahead, &mut mirror, 2, message));
        }
    }

    assert_eq!(behind.tip(), ahead.tip(), "both ended on the same block");
    assert_eq!(behind.state().state_root(), ahead.state().state_root());
    assert_eq!(behind.height(), Some(29));
}

#[test]
fn an_introduction_asks_the_peer_who_else_it_knows() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(2);
    let mut store = store_with(params, &blocks);
    let handshake = local_handshake(
        &store,
        Keeps {
            headers: true,
            cold_set: false,
        },
        4242,
        7,
    );

    let mut peer = PeerState::default();
    let reaction = on_message(
        &mut solo(&mut store),
        &mut peer,
        Message::Hello(handshake),
        NOW,
    );

    assert!(
        reaction.reply.contains(&Message::GetPeers),
        "a node with one connection is one cable from being alone"
    );
}

/// A request for addresses is named here and answered by the node.
///
/// Named rather than answered, like the blocks and the headers, and for the
/// same reason: the answer is drawn from the whole book, which has to be
/// ordered before any of it can be shared, and this layer runs with the chain
/// held. This layer used to be handed a copy of the book for every message
/// from every peer to serve the one message that reads it.
#[test]
fn a_request_for_peers_is_named_rather_than_answered_here() {
    let params = params();
    let mut store = ChainStore::new(params);

    let mut peer = greeted_peer(0, 0);
    let reaction = on_message(&mut solo(&mut store), &mut peer, Message::GetPeers, NOW);

    assert!(
        reaction.share_addresses,
        "the node owes this peer addresses"
    );
    assert!(
        reaction.reply.is_empty(),
        "and nothing was drawn from the book with the chain held"
    );
}

#[test]
fn addresses_received_are_passed_up_to_be_recorded() {
    use std::net::Ipv4Addr;

    let params = params();
    let mut store = ChainStore::new(params);
    let mut peer = greeted_peer(0, 0);

    let offered = vec![
        PeerAddress(SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 9000))),
        PeerAddress(SocketAddr::from((Ipv4Addr::new(198, 51, 100, 2), 9000))),
    ];
    let reaction = on_message(
        &mut solo(&mut store),
        &mut peer,
        Message::Peers(offered),
        NOW,
    );

    assert_eq!(reaction.learned.len(), 2);
    assert!(reaction.reply.is_empty(), "an address list needs no answer");
    assert!(reaction.drop_peer.is_none());
}

#[test]
fn a_peer_is_placed_at_the_address_its_connection_came_from() {
    use std::net::{IpAddr, Ipv4Addr};

    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(2);
    let mut store = store_with(params, &blocks);

    // The peer names a port. The address is taken from the socket, never from
    // anything the peer says, so one node cannot advertise another.
    let claimed = Handshake {
        listen: 5_555,
        ..local_handshake(
            &store,
            Keeps {
                headers: true,
                cold_set: false,
            },
            4242,
            7,
        )
    };
    let seen_from = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

    let mut peer = PeerState {
        remote: Some(seen_from),
        ..PeerState::default()
    };
    let reaction = on_message(
        &mut solo(&mut store),
        &mut peer,
        Message::Hello(claimed),
        NOW,
    );

    let expected = SocketAddr::new(seen_from, 5_555);
    assert_eq!(peer.advertised, Some(expected));
    assert_eq!(reaction.learned, vec![expected]);
}

#[test]
fn a_peer_that_does_not_listen_is_not_advertised() {
    use std::net::{IpAddr, Ipv4Addr};

    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(2);
    let mut store = store_with(params, &blocks);

    let quiet = Handshake {
        listen: 0,
        ..local_handshake(
            &store,
            Keeps {
                headers: true,
                cold_set: false,
            },
            4242,
            7,
        )
    };
    let mut peer = PeerState {
        remote: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        ..PeerState::default()
    };
    let reaction = on_message(&mut solo(&mut store), &mut peer, Message::Hello(quiet), NOW);

    assert_eq!(peer.advertised, None);
    assert!(
        reaction.learned.is_empty(),
        "nothing to pass on about a node nobody can reach"
    );
}

/// A reader that hands over what it holds, then behaves like a socket whose
/// deadline has passed.
struct Stalling {
    bytes: Vec<u8>,
    at: usize,
}

impl Stalling {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, at: 0 }
    }
}

impl std::io::Read for Stalling {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.at >= self.bytes.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        let take = buffer.len().min(self.bytes.len() - self.at);
        buffer[..take].copy_from_slice(&self.bytes[self.at..self.at + take]);
        self.at += take;
        Ok(take)
    }
}

#[test]
fn a_peer_with_nothing_to_say_is_not_a_failure() {
    let mut quiet = Stalling::new(Vec::new());
    assert_eq!(
        read_message(&mut quiet, NetworkId::TESTNET, MAX_FRAME_BYTES).unwrap(),
        Incoming::Quiet,
        "an idle peer must not be mistaken for a broken one"
    );
}

#[test]
fn a_peer_that_opens_a_frame_and_stops_is_refused() {
    let mut framed = Vec::new();
    NetworkId::TESTNET.as_u32().encode_to(&mut framed);
    1_000_000u32.encode_to(&mut framed);
    // The header, and then nothing at all. Without the deadline this is where
    // the reading thread would wait for as long as the peer kept the socket.
    let mut stalled = Stalling::new(framed);

    match read_message(&mut stalled, NetworkId::TESTNET, MAX_FRAME_BYTES) {
        Err(WireError::Stalled { had, wanted }) => {
            assert_eq!(had, 0);
            assert_eq!(wanted, 1_000_000);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_peer_that_stops_partway_through_a_frame_is_refused() {
    let mut framed = Vec::new();
    write_message(&mut framed, NetworkId::TESTNET, &Message::Ping(1)).unwrap();
    let full = framed.len();
    framed.truncate(full - 1);
    let mut stalled = Stalling::new(framed);

    match read_message(&mut stalled, NetworkId::TESTNET, MAX_FRAME_BYTES) {
        Err(WireError::Stalled { had, .. }) => assert!(had > 0),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_peer_that_stops_partway_through_a_header_is_refused() {
    let mut framed = Vec::new();
    NetworkId::TESTNET.as_u32().encode_to(&mut framed);
    framed.push(0);
    let mut stalled = Stalling::new(framed);

    match read_message(&mut stalled, NetworkId::TESTNET, MAX_FRAME_BYTES) {
        Err(WireError::Stalled { had, wanted }) => {
            assert_eq!(had, 5);
            assert_eq!(wanted, 8);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn belonging_elsewhere_is_not_misbehaviour() {
    assert!(!DropReason::WrongNetwork {
        theirs: NetworkId::MAINNET
    }
    .is_misbehaviour());
    assert!(!DropReason::WrongVersion { theirs: 99 }.is_misbehaviour());
    assert!(!DropReason::ForeignChain {
        theirs: Hash32::ZERO
    }
    .is_misbehaviour());
}

#[test]
fn sending_a_bad_block_or_speaking_out_of_turn_is_misbehaviour() {
    assert!(DropReason::BadBlock { id: Hash32::ZERO }.is_misbehaviour());
    assert!(DropReason::RepeatedHandshake.is_misbehaviour());
    assert!(DropReason::Unannounced { kind: "block" }.is_misbehaviour());
}

/// A node that reaches itself hangs up, rather than spending one of its few
/// connections on itself.
///
/// Found on the first contact with the real internet, not by any of these
/// tests: a node behind a router does not know the address the world reaches
/// it at, so when a peer hands that address back it looks like a stranger's.
/// Comparing addresses cannot fix that. Comparing a number the node drew for
/// itself can.
#[test]
fn a_node_that_reaches_itself_says_so_and_hangs_up() {
    let params = params();
    let mut store = ChainStore::new(params);
    let ours = 0x0BAD_C0DE_0BAD_C0DE;

    // Our own introduction, arriving back at us.
    let mine = local_handshake(
        &store,
        Keeps {
            headers: true,
            cold_set: false,
        },
        4242,
        ours,
    );
    let mut peer = PeerState {
        remote: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            203, 0, 113, 9,
        ))),
        ..PeerState::default()
    };
    let reaction = on_message(
        &mut solo_as(&mut store, ours),
        &mut peer,
        Message::Hello(mine),
        NOW,
    );

    assert_eq!(reaction.drop_peer, Some(DropReason::Ourselves));
    assert!(
        reaction.learned.is_empty(),
        "our own address must not go into the book"
    );
    assert!(reaction.reply.is_empty(), "nothing to say to ourselves");
    // And it has to come out of the book, not merely stay out of it: a peer
    // that shared it with us put it there, and it would be dialled again on
    // the next sweep.
    assert_eq!(
        reaction.forget,
        vec![SocketAddr::from((
            std::net::Ipv4Addr::new(203, 0, 113, 9),
            4242
        ))],
        "the address we reached ourselves at must be dropped from the book"
    );
}

/// And a genuine peer with a different nonce is unaffected.
#[test]
fn a_peer_that_is_not_us_is_greeted_normally() {
    let params = params();
    let mut store = ChainStore::new(params);
    let theirs = local_handshake(
        &store,
        Keeps {
            headers: true,
            cold_set: false,
        },
        5000,
        0x1111_1111_1111_1111,
    );

    let mut peer = PeerState {
        remote: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            203, 0, 113, 9,
        ))),
        ..PeerState::default()
    };
    let reaction = on_message(
        &mut solo_as(&mut store, 0x2222_2222_2222_2222),
        &mut peer,
        Message::Hello(theirs),
        NOW,
    );

    assert_eq!(reaction.drop_peer, None);
    assert_eq!(
        reaction.learned,
        vec![SocketAddr::from((
            std::net::Ipv4Addr::new(203, 0, 113, 9),
            5000
        ))]
    );
}

/// Reaching yourself is a fact about routing, not a peer behaving badly.
#[test]
fn reaching_ourselves_is_not_held_against_anyone() {
    assert!(!DropReason::Ourselves.is_misbehaviour());
}

/// How much a node spends answering must not be decided by whoever asks.
///
/// The node keeps a ceiling on how many messages a peer may send, which
/// catches a peer repeating itself. It does not catch a peer asking for a
/// great deal in each of them: two thousand messages is within that ceiling,
/// and two thousand asking for a hundred and twenty eight blocks each is a
/// quarter of a million records to read off a disk.
#[test]
fn a_peer_cannot_decide_how_much_answering_it_costs() {
    let mut forge = Forge::new(params());
    let blocks = forge.mine_many(4);
    let mut store = ChainStore::new(params());
    for block in &blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }

    let mut peer = greeted_peer(0, 0);
    let wanted: Vec<u64> = (0..blocks.len() as u64).collect();

    // Asking for everything it can, over and over, inside one window.
    let mut answered = 0usize;
    let mut refused = 0usize;
    for _ in 0..4_000 {
        let asking = Message::GetBlocks(wanted.clone());
        let reaction = on_message(&mut solo(&mut store), &mut peer, asking, NOW);
        if reaction.fetch.is_empty() {
            refused = refused.saturating_add(1);
        } else {
            answered = answered.saturating_add(1);
        }
    }
    assert!(answered > 0, "an honest peer is answered");
    assert!(
        refused > 0,
        "and a peer that keeps asking runs out of allowance"
    );

    // A refusal is not a grudge: the window turns over and it is served again.
    let later = on_message(
        &mut solo(&mut store),
        &mut peer,
        Message::GetBlocks(wanted.clone()),
        NOW + 30,
    );
    assert!(!later.fetch.is_empty(), "a fresh window answers again");
}

/// Taking delivery of what you asked for is not something to be charged for.
#[test]
fn blocks_this_node_asked_for_do_not_use_up_its_allowance() {
    let mut forge = Forge::new(params());
    let blocks = forge.mine_many(3);
    let mut store = ChainStore::new(params());

    let mut peer = greeted_peer(0, 0);
    // As though this node had just asked for all three.
    peer.asked_at = NOW;
    for height in 0..blocks.len() as u64 {
        peer.awaiting.insert(height);
    }

    for block in &blocks {
        on_message(
            &mut solo(&mut store),
            &mut peer,
            Message::Block(Box::new(block.clone())),
            NOW,
        );
    }
    assert_eq!(store.height(), Some(2), "all three landed");
    assert_eq!(peer.spent, 3, "one apiece, not the price of a stranger's");
}

/// Spends `peer`'s window down to `left` units with asks whose prices this
/// file already holds: a request for addresses and a ping.
fn spend_the_window_down_to(chain: &mut ChainStore, peer: &mut PeerState, left: u32, now: u64) {
    let target = 8_192 - left;
    while peer.spent + 64 <= target {
        on_message(&mut solo(chain), peer, Message::GetPeers, now);
    }
    while peer.spent < target {
        on_message(
            &mut solo(chain),
            peer,
            Message::Ping(peer.spent.into()),
            now,
        );
    }
    assert_eq!(
        peer.spent, target,
        "the fixture spends exactly what it says"
    );
}

/// Seven blocks answering a question this node asked, delivered against a
/// window holding seven units, and the height they took the chain to.
fn seven_blocks_against_seven_units(asked_from_outside: bool) -> Option<u64> {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(8);
    let mut node = store_with(params, &blocks[..1]);
    let mut peer = greeted_peer(u128::MAX / 2, 1_000);
    if asked_from_outside {
        asked_for_the_chain(&node, &mut peer);
    }
    let asked = on_message(
        &mut solo(&mut node),
        &mut peer,
        Message::Chain { from: 1, count: 7 },
        NOW,
    );
    assert!(matches!(asked.reply.first(), Some(Message::GetBlocks(_))));
    spend_the_window_down_to(&mut node, &mut peer, 7, NOW);
    for block in &blocks[1..] {
        on_message(
            &mut solo(&mut node),
            &mut peer,
            Message::Block(Box::new(block.clone())),
            NOW,
        );
    }
    node.height()
}

/// A batch answering a question the node put from outside this layer is
/// charged as an answer, a unit a block.
///
/// The layer marked the questions it sent itself and nothing else could mark
/// one, so the answer to the node's own questions (the choice of whom to
/// read from, the nudge after it, the probation's question for the burial,
/// the question after a handover lands) was priced as a push, and a busy
/// window refused the batch. The unmarked half here is that price, which is
/// right for a question nobody asked.
#[test]
fn a_batch_answering_a_question_the_node_asked_from_outside_is_charged_as_an_answer() {
    assert_eq!(
        seven_blocks_against_seven_units(true),
        Some(7),
        "seven blocks answering this node's own question were priced as pushes"
    );
    assert_eq!(
        seven_blocks_against_seven_units(false),
        Some(0),
        "seven blocks nobody asked for were taken at the price of an answer"
    );
}

/// A question put from outside is marked by the rule the layer keeps for its
/// own: once for a peer whose last round moved nothing, and never by undoing
/// a mark already standing.
///
/// The probation asks everyone every half minute while nothing arrives, and
/// a discount on every one of those would be a peer choosing a batch at a
/// unit a block, twice a minute, for nothing it delivered.
#[test]
fn a_question_repeated_while_nothing_arrives_buys_one_answer_at_the_discount() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(2);
    let mut node = store_with(params, &blocks[..1]);
    let mut peer = greeted_peer(u128::MAX / 2, 1_000);

    asked_for_the_chain(&node, &mut peer);
    assert!(peer.chain_asked, "the first question is marked");
    peer.chain_asked = false;
    asked_for_the_chain(&node, &mut peer);
    assert!(
        !peer.chain_asked,
        "a question repeated with nothing moved in between was given the discount again"
    );
    peer.chain_asked = true;
    asked_for_the_chain(&node, &mut peer);
    assert!(
        peer.chain_asked,
        "a question from outside took away the mark of one still outstanding"
    );

    peer.chain_asked = false;
    node.add_block(blocks[1].clone(), NOW).unwrap();
    asked_for_the_chain(&node, &mut peer);
    assert!(
        peer.chain_asked,
        "a question after the chain moved was not given the discount"
    );
}

/// The wire has to carry what the rules allow.
///
/// Two limits on the same object, written in two crates, with nothing to make
/// them agree. If the rules allowed a block this wire refused, a miner could
/// produce one that is valid and cannot be handed to anyone: it would follow a
/// chain nobody else can follow, and no attacker would be needed for the fork.
///
/// There is a third number in the chain and it is held elsewhere. A block that
/// crosses this wire is written into the block log, which refuses a body over
/// `cairn_store::MAX_RECORD_BYTES`. That half is a relation between two
/// constants and nothing else, so it is a compile time assertion beside
/// `MAX_FRAME_BYTES` rather than a test here: proving it at runtime would mean
/// building a megabyte block to compare two numbers. Named here so that a
/// reader who finds one end of the chain finds the other.
#[test]
fn the_wire_carries_the_largest_block_the_rules_allow() {
    let allowed = params().max_block_bytes;
    assert!(
        allowed < cairn_net::wire::MAX_FRAME_BYTES,
        "a block of {allowed} bytes is valid and would not fit in a frame of {}",
        cairn_net::wire::MAX_FRAME_BYTES
    );
}

//! The conversation between two nodes, without a network under it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::sync::{local_handshake, on_message, DropReason, PeerState};
use cairn_net::wire::{read_message, write_message, WireError, MAX_FRAME_BYTES};
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Hash32;

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
        let miner = SecretKey::from_bytes(&[1; 32]);
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.block_reward, miner.public_key())],
            [0; 8],
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
}

fn store_with(params: ConsensusParams, blocks: &[Block]) -> ChainStore {
    let mut store = ChainStore::new(params);
    for block in blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }
    store
}

fn greeted_peer(work: u128, height: u64) -> PeerState {
    PeerState {
        greeted: true,
        height,
        total_work: work,
        ..PeerState::default()
    }
}

#[test]
fn a_message_roundtrips_through_the_wire_format() {
    let mut forge = Forge::new(params());
    let block = forge.mine();

    let messages = vec![
        Message::Ping(42),
        Message::Pong(42),
        Message::GetChain {
            locator: vec![block.id(), Hash32::ZERO],
        },
        Message::Chain(vec![block.id()]),
        Message::GetBlocks(vec![block.id()]),
        Message::Announce(vec![block.id()]),
        Message::Block(Box::new(block.clone())),
        Message::Hello(Handshake {
            version: PROTOCOL_VERSION,
            network: NetworkId::TESTNET,
            genesis: block.id(),
            tip: block.id(),
            height: 0,
            total_work: u128::MAX,
        }),
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
            read_message(&mut cursor, NetworkId::TESTNET).unwrap(),
            message
        );
    }
}

#[test]
fn a_frame_from_another_network_is_refused_on_its_first_bytes() {
    let mut framed = Vec::new();
    write_message(&mut framed, NetworkId::MAINNET, &Message::Ping(1)).unwrap();

    let mut cursor = framed.as_slice();
    let outcome = read_message(&mut cursor, NetworkId::TESTNET);
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
    let outcome = read_message(&mut cursor, NetworkId::TESTNET);
    match outcome {
        Err(WireError::FrameTooLarge { declared }) => {
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
    assert!(read_message(&mut cursor, NetworkId::TESTNET).is_err());
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
        &mut behind,
        &mut peer,
        Message::Hello(local_handshake(&ahead)),
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
        &mut ahead,
        &mut peer,
        Message::Hello(local_handshake(&behind)),
        NOW,
    );

    assert_eq!(reaction.reply.len(), 1, "only the greeting comes back");
    assert!(matches!(reaction.reply.first(), Some(Message::Welcome(_))));
}

#[test]
fn a_peer_on_another_network_or_version_or_chain_is_dropped() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(3);
    let mut store = store_with(params, &blocks);
    let sound = local_handshake(&store);

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
        let reaction = on_message(&mut store, &mut peer, Message::Hello(handshake), NOW);
        assert_eq!(reaction.drop_peer, Some(expected));
        assert!(!peer.greeted);
        assert!(
            reaction.reply.is_empty(),
            "nothing is answered to a peer being dropped"
        );
    }
}

#[test]
fn nothing_is_answered_before_an_introduction() {
    let params = params();
    let mut store = ChainStore::new(params);
    let mut peer = PeerState::default();

    let reaction = on_message(&mut store, &mut peer, Message::Ping(1), NOW);
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
    let handshake = local_handshake(&store);

    let mut peer = PeerState::default();
    on_message(&mut store, &mut peer, Message::Hello(handshake), NOW);
    let again = on_message(&mut store, &mut peer, Message::Hello(handshake), NOW);
    assert_eq!(again.drop_peer, Some(DropReason::RepeatedHandshake));
}

#[test]
fn a_ping_comes_back_as_a_pong() {
    let params = params();
    let mut store = ChainStore::new(params);
    let mut peer = greeted_peer(0, 0);

    let reaction = on_message(&mut store, &mut peer, Message::Ping(99), NOW);
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
    let reaction = on_message(
        &mut ahead,
        &mut peer,
        Message::GetChain {
            locator: behind.locator(),
        },
        NOW,
    );

    let ids = match reaction.reply.first() {
        Some(Message::Chain(ids)) => ids.clone(),
        other => panic!("expected a chain, got {other:?}"),
    };
    let expected: Vec<_> = blocks[2..].iter().map(Block::id).collect();
    assert_eq!(
        ids, expected,
        "exactly the blocks the other side lacks, oldest first"
    );
}

#[test]
fn only_the_missing_blocks_are_asked_for() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(5);
    let mut behind = store_with(params, &blocks[..2]);

    let mut peer = greeted_peer(5, 4);
    let announced: Vec<_> = blocks.iter().map(Block::id).collect();
    let reaction = on_message(&mut behind, &mut peer, Message::Chain(announced), NOW);

    let asked = match reaction.reply.first() {
        Some(Message::GetBlocks(ids)) => ids.clone(),
        other => panic!("expected a request, got {other:?}"),
    };
    let expected: Vec<_> = blocks[2..].iter().map(Block::id).collect();
    assert_eq!(asked, expected);
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
    let asked = vec![blocks[0].id(), Hash32::from_bytes([9; 32]), blocks[2].id()];
    let reaction = on_message(&mut store, &mut peer, Message::GetBlocks(asked), NOW);

    assert_eq!(
        reaction.reply.len(),
        2,
        "the unknown identifier is simply not answered"
    );
    assert_eq!(
        reaction.reply[0],
        Message::Block(Box::new(blocks[0].clone()))
    );
    assert_eq!(
        reaction.reply[1],
        Message::Block(Box::new(blocks[2].clone()))
    );
}

#[test]
fn a_block_that_lands_is_worth_telling_everyone_about() {
    let params = params();
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(3);
    let mut behind = store_with(params, &blocks[..2]);

    let mut peer = greeted_peer(3, 2);
    peer.awaiting.insert(blocks[2].id());
    let reaction = on_message(
        &mut behind,
        &mut peer,
        Message::Block(Box::new(blocks[2].clone())),
        NOW,
    );

    assert_eq!(reaction.broadcast, vec![blocks[2].id()]);
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
        &mut behind,
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
        &mut store,
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
    let mut pending = vec![Message::Hello(local_handshake(&ahead))];
    let mut rounds = 0;
    while !pending.is_empty() {
        rounds += 1;
        assert!(rounds < 50, "the exchange should settle");

        let mut answers = Vec::new();
        for message in pending.drain(..) {
            let kind = message.kind();
            let reaction = on_message(&mut behind, &mut peer, message, NOW);
            assert!(
                reaction.drop_peer.is_none(),
                "behind dropped on {kind}: {:?}",
                reaction.drop_peer
            );
            answers.extend(reaction.reply);
        }
        for message in answers {
            let kind = message.kind();
            let reaction = on_message(&mut ahead, &mut mirror, message, NOW);
            assert!(
                reaction.drop_peer.is_none(),
                "ahead dropped on {kind}: {:?}",
                reaction.drop_peer
            );
            pending.extend(reaction.reply);
        }
    }

    assert_eq!(behind.tip(), ahead.tip(), "both ended on the same block");
    assert_eq!(behind.state().state_root(), ahead.state().state_root());
    assert_eq!(behind.height(), Some(29));
}

//! A block of the branch a node follows, sent back by a peer, does not move
//! where the next round is asked from.
//!
//! #300 made the cursor a peer's deliveries leave count a block on the branch
//! followed as well as one beside it, so a peer agreeing far below the tip
//! could be walked up a batch a round. The cursor was read at the next `Chain`
//! whatever branch that `Chain` was about, so a block of the node's own branch
//! pushed the next round to just past the tip, the shape #300 closed, and a
//! peer could put one there for nothing by sending back a block the node
//! already held. A block on the branch now counts only for a round it was
//! asked for, and only for a `Chain` answered from the same place.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{IpAddr, Ipv4Addr};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, Local, PeerState};

const NOW: u64 = 2_000_000_000;
/// Blocks on this node's own branch.
const MINE: u64 = 20;
/// Where the peer's branch parts: well below the tip, within what the node
/// undoes.
const FORK: u64 = 5;

fn host(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
}

const KEEPS: Keeps = Keeps {
    headers: false,
    cold_set: false,
};

fn rules() -> ConsensusParams {
    ConsensusParams::mineable_network(8)
}

/// A chain of `MINE` blocks, and the blocks themselves.
fn a_chain() -> (ChainStore, Vec<Block>) {
    let (chain, blocks, _) = a_chain_and_a_block_beside_it_at(MINE - 1);
    (chain, blocks)
}

/// A chain of `MINE` blocks, the blocks themselves, and a block of another
/// miner's at `beside`, on the same parent as this chain's block there and
/// carrying the same work, so it is held beside the branch and not followed.
fn a_chain_and_a_block_beside_it_at(beside: u64) -> (ChainStore, Vec<Block>, Block) {
    let params = rules();
    let miner = SecretKey::from_bytes(&[4; 32]);
    let other = SecretKey::from_bytes(&[5; 32]);
    let mut state = LedgerState::new();
    let mut chain = ChainStore::new(params);
    let mut clock = params.opens_at;
    let mut blocks = Vec::new();
    let mut side = None;
    while (blocks.len() as u64) < MINE {
        let height = state.next_height().unwrap();
        clock += params.target_block_time;
        if height == beside {
            let reward = Note::new(params.initial_reward, other.public_key());
            let coinbase = CoinbaseTransaction::new(height, vec![reward]);
            let block = assemble_block(&state, coinbase, vec![], &params, clock, 0).unwrap();
            side = Some(mine_block(block, 1 << 24).unwrap());
        }
        let reward = Note::new(params.initial_reward, miner.public_key());
        let coinbase = CoinbaseTransaction::new(height, vec![reward]);
        let block = assemble_block(&state, coinbase, vec![], &params, clock, 0).unwrap();
        let block = mine_block(block, 1 << 24).unwrap();
        connect_block(&mut state, &block, &params, clock + 1).unwrap();
        chain.add_block(block.clone(), NOW).unwrap();
        blocks.push(block);
    }
    (chain, blocks, side.unwrap())
}

fn met(chain: &mut ChainStore, peer: &mut PeerState) {
    let said = Handshake {
        version: PROTOCOL_VERSION,
        network: rules().network,
        genesis: chain.genesis().unwrap_or(cairn_primitives::Hash32::ZERO),
        nonce: 77,
        height: MINE + 500,
        total_work: u128::MAX,
        listen: 4242,
        keeps: KEEPS,
    };
    let mut local = Local {
        keeps: KEEPS,
        nonce: 1,
        chain,
        listen: 4242,
    };
    assert_eq!(
        on_message(&mut local, peer, Message::Hello(said), NOW).drop_peer,
        None
    );
}

/// The heights a reaction asks for, if it asks for any.
fn asked_for(reaction: &cairn_net::sync::Reaction) -> Option<Vec<u64>> {
    reaction.reply.iter().find_map(|message| match message {
        Message::GetBlocks(heights) => Some(heights.clone()),
        _ => None,
    })
}

/// A peer that answers a locator from where the branches part is asked from
/// there, and a block it sent of this node's own branch does not move that.
#[test]
fn a_block_of_the_branch_followed_does_not_push_the_next_round_above_the_tip() {
    let (mut chain, blocks) = a_chain();
    let mut peer = PeerState::new(Some(host(2)));
    met(&mut chain, &mut peer);
    assert_eq!(chain.height(), Some(MINE - 1), "the premise: the tip");
    assert_eq!(
        chain.branch_start(),
        Some(0),
        "the premise: every height is held, so nothing is out of reach"
    );

    // The peer sends back a block this node already holds, at its tip. It
    // costs the peer one block and buys it nothing on its face: the block is
    // a duplicate. It writes the cursor all the same.
    let tip = blocks[usize::try_from(MINE - 1).unwrap()].clone();
    let mut local = Local {
        keeps: KEEPS,
        nonce: 1,
        chain: &mut chain,
        listen: 4242,
    };
    let out = on_message(&mut local, &mut peer, Message::Block(Box::new(tip)), NOW);
    assert_eq!(out.drop_peer, None, "a duplicate is nobody's fault");

    // And now it answers a locator from where its branch parts, five blocks
    // up, fifteen below this node's tip.
    let mut local = Local {
        keeps: KEEPS,
        nonce: 1,
        chain: &mut chain,
        listen: 4242,
    };
    let out = on_message(
        &mut local,
        &mut peer,
        Message::Chain {
            from: FORK,
            count: 200,
        },
        NOW,
    );
    let heights = asked_for(&out);
    assert_eq!(
        heights
            .as_ref()
            .and_then(|heights| heights.first().copied()),
        Some(FORK),
        "the round was asked from {:?} rather than from {FORK}, where the \
         branches part. The peer had sent one block of this node's own branch, \
         at its tip, and PeerState::aside took it: past_what_arrived then \
         started the round one past the tip, which is the T8-7 F1 shape #300 \
         closed, reached through the cursor instead of through first_wanted",
        heights
            .as_ref()
            .and_then(|heights| heights.first().copied())
    );
}

/// **A block held beside the branch, lower than the round's last block on
/// the branch, does not send the next round back below that block.**
///
/// The peer answers a round on the branch this node follows, every block it
/// was asked for, and sends one block beside the branch, lower down, that
/// nobody asked for. Both were written down for the next `Chain`, and the one
/// beside the branch was taken whatever its height: the next round was asked
/// from just above it, the blocks the round had just walked asked again, so a
/// peer could keep its walk from advancing for one block a round.
#[test]
fn a_block_beside_the_branch_below_the_round_does_not_send_the_walk_back() {
    let beside = MINE - 5;
    let (mut chain, blocks, side) = a_chain_and_a_block_beside_it_at(beside);
    let mut peer = PeerState::new(Some(host(2)));
    met(&mut chain, &mut peer);
    let mut local = Local {
        keeps: KEEPS,
        nonce: 1,
        chain: &mut chain,
        listen: 4242,
    };
    let first = on_message(
        &mut local,
        &mut peer,
        Message::Chain {
            from: FORK,
            count: 200,
        },
        NOW,
    );
    let asked = asked_for(&first).expect("fixture: the first round asks for blocks");
    assert_eq!(
        asked.first().copied(),
        Some(FORK),
        "fixture: asked from {FORK}"
    );
    for at in FORK..MINE {
        assert!(asked.contains(&at), "fixture: {at} was asked for");
        let block = blocks[usize::try_from(at).unwrap()].clone();
        let mut local = Local {
            keeps: KEEPS,
            nonce: 1,
            chain: &mut chain,
            listen: 4242,
        };
        on_message(&mut local, &mut peer, Message::Block(Box::new(block)), NOW);
    }
    let mut local = Local {
        keeps: KEEPS,
        nonce: 1,
        chain: &mut chain,
        listen: 4242,
    };
    on_message(
        &mut local,
        &mut peer,
        Message::Block(Box::new(side.clone())),
        NOW,
    );
    assert!(
        chain.held_header(&side.id()).is_some() && chain.id_at(beside) != Some(side.id()),
        "fixture: the block at {beside} is held beside the branch"
    );

    let mut local = Local {
        keeps: KEEPS,
        nonce: 1,
        chain: &mut chain,
        listen: 4242,
    };
    let next = on_message(
        &mut local,
        &mut peer,
        Message::Chain {
            from: FORK,
            count: 200,
        },
        NOW,
    );
    let from = asked_for(&next).and_then(|heights| heights.first().copied());
    assert_eq!(
        from,
        Some(MINE),
        "the next round was asked from {from:?} rather than from {MINE}, past the last block \
         of the branch the round delivered: the block held beside the branch at {beside}, \
         lower and unasked, was taken over it"
    );
}

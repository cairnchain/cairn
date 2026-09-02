//! What a node says its own chain is, and who it blames when its own disk
//! cannot answer.
//!
//! Two separate holes with the same shape. A node handed a ledger has a branch
//! that starts at its anchor, so reading its first block off the branch
//! answered nothing, it introduced itself with a genesis of zeroes, and the
//! one check that refuses a peer on another chain never applied — to exactly
//! the nodes most in need of it, the ones that have just arrived and are
//! trusting a seed address.
//!
//! And when this node's own store cannot put a branch back, that was charged
//! to whichever peer had asked for the switch.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_ledger::note::NetworkId;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::{Handshake, Keeps, Message, PROTOCOL_VERSION};
use cairn_net::sync::{local_handshake, on_message, DropReason, Local, PeerState};
use cairn_primitives::Hash32;

/// A rule set that pins its first block, which is what every named network
/// does. `ConsensusParams::testnet()` pins nothing, which is what tests run on.
fn pinned() -> ConsensusParams {
    ConsensusParams {
        genesis: Some(Hash32::from_bytes([7; 32])),
        ..ConsensusParams::testnet()
    }
}

const KEEPS: Keeps = Keeps {
    headers: false,
    cold_set: false,
};

fn introduction(genesis: Hash32, network: NetworkId) -> Handshake {
    Handshake {
        version: PROTOCOL_VERSION,
        network,
        genesis,
        tip: Hash32::ZERO,
        nonce: 99,
        height: 10,
        total_work: 10,
        listen: 4242,
        keeps: KEEPS,
    }
}

/// What a peer offering `theirs` is answered with.
fn met(chain: &mut ChainStore, theirs: Handshake) -> Option<DropReason> {
    on_message(
        &mut Local {
            keeps: KEEPS,
            nonce: 1,
            chain,
            listen: 4242,
        },
        &mut PeerState::default(),
        Message::Hello(theirs),
        2_000_000_000,
    )
    .drop_peer
}

/// A node with no blocks of its own still knows which chain it is on, because
/// its rules say so before a single block arrives.
#[test]
fn a_node_with_no_blocks_still_refuses_a_peer_on_another_chain() {
    let params = pinned();
    let chain = ChainStore::new(params);
    assert_eq!(chain.genesis(), None, "it has no first block of its own");

    let mut chain = chain;
    let stranger = introduction(Hash32::from_bytes([9; 32]), params.network);
    let refused = met(&mut chain, stranger);
    assert!(
        matches!(refused, Some(DropReason::ForeignChain { .. })),
        "a node that has just arrived is the one that most needs this check, \
         and it said {refused:?}"
    );

    // And the chain it is actually on is taken.
    let ours = introduction(params.genesis.unwrap(), params.network);
    assert_eq!(met(&mut chain, ours), None);
}

/// What it says about itself is the same answer, so two such nodes recognise
/// each other rather than both claiming a chain of zeroes.
#[test]
fn a_node_with_no_blocks_introduces_itself_with_the_chain_its_rules_name() {
    let params = pinned();
    let chain = ChainStore::new(params);
    let said = local_handshake(&chain, KEEPS, 4242, 1);
    assert_eq!(
        said.genesis,
        params.genesis.unwrap(),
        "it introduced itself with a chain starting nowhere"
    );
}

/// A rule set that pins nothing falls back to the branch, which is what it did
/// before and what tests run on.
#[test]
fn a_rule_set_that_pins_nothing_still_answers_from_its_branch() {
    let chain = ChainStore::new(ConsensusParams::testnet());
    let said = local_handshake(&chain, KEEPS, 4242, 1);
    assert_eq!(said.genesis, Hash32::ZERO, "nothing to name yet");
}

/// This node's own store failing is not the peer's doing, and refusing the
/// host over it would work through every peer that offered a switch.
#[test]
fn a_store_this_node_cannot_read_is_not_held_against_the_peer() {
    assert!(
        !DropReason::OwnStore.is_misbehaviour(),
        "the peer asked for a switch and this node could not make it"
    );
}

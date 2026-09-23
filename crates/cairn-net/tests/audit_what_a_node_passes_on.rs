//! A transfer this node takes is one it passes on.
//!
//! `on_message` answers a `Transaction` the pool accepted with the identifier
//! on `Reaction::relayed`, and `node.rs` turns that list into the transfers it
//! hands to its other peers. Delete the field and the whole `cairn-net` suite
//! stays green, which is how this was found.
//!
//! What that deletion builds is a network where a payment only ever reaches
//! the nodes its sender connected to. Every node still takes the transfer,
//! still holds it, still mines it if it is the one mining; it simply never
//! tells anyone else. A wallet with one peer would watch its payment sit in
//! that peer's pool for ever, and nothing about the node would look broken.
//!
//! The tests that exist stand either side of this without standing on it.
//! `what_it_reports.rs::a_transfer_offered_again_reaches_a_peer_that_arrived_after_the_first_broadcast`
//! measures a transfer the node was handed by its own wallet, which reaches
//! the peer through `offer_again` rather than through this field;
//! `audit_what_a_signature_costs.rs` sends transfers through `on_message` but
//! sends ones no pool would take, because what it measures is the price of
//! refusing them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::Message;
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::Keeps;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A store holding a short chain, and the first reward it paid out.
fn a_chain_and_its_first_reward(miner: &SecretKey) -> (ChainStore, NoteId, Note) {
    let rules = params();
    let mut state = LedgerState::new();
    let mut store = ChainStore::new(rules);
    let mut clock = 1_000u64;
    let mut first = None;
    for _ in 0..3 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(rules.initial_reward, miner.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &rules, clock, 0).unwrap();
        connect_block(&mut state, &block, &rules, NOW).unwrap();
        if first.is_none() {
            first = block.coinbase.created_notes().into_iter().next();
        }
        store.add_block(block, NOW).unwrap();
    }
    let (id, note) = first.expect("the first block paid its miner");
    (store, id, note)
}

/// A transfer the pool takes is named as one to hand on; one it already holds
/// is not.
///
/// Both halves matter, and the second is why this is not answered by naming
/// every transfer that arrives. A node that passed on what it already held
/// would answer a flood with a flood of its own, to every peer it has.
#[test]
fn a_transfer_this_node_takes_is_one_it_passes_on() {
    let key = wallet(7);
    let (mut store, spending, held) = a_chain_and_its_first_reward(&key);

    let mut transfer = Transfer::new(
        vec![Input::hot(spending)],
        vec![Note::new(
            held.value
                .checked_sub(Amount::from_pebbles(10_000).unwrap())
                .unwrap(),
            wallet(9).public_key(),
        )],
    );
    transfer.sign_input(params().network, 0, &held, &key);
    let id = transfer.id();

    // Introduced, because a peer that has not is turned away before anything
    // here is reached.
    let mut peer = PeerState {
        greeted: true,
        ..PeerState::default()
    };
    let mut local = Local {
        chain: &mut store,
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
        listen: 9_000,
        nonce: 7,
    };

    let reaction = on_message(
        &mut local,
        &mut peer,
        Message::Transaction(Box::new(transfer.clone())),
        NOW,
    );
    assert_eq!(reaction.drop_peer, None, "the transfer was a good one");
    assert!(
        local.chain.pooled(&id).is_some(),
        "and the pool took it, or there is nothing to hand on"
    );
    assert_eq!(
        reaction.relayed,
        vec![id],
        "a transfer this node took and did not name is one that goes no \
         further than the peer that sent it, on a network where every node \
         behaves the same way"
    );

    // The same transfer again, which is what a flood is made of.
    let reaction = on_message(
        &mut local,
        &mut peer,
        Message::Transaction(Box::new(transfer)),
        NOW,
    );
    assert_eq!(
        reaction.drop_peer, None,
        "and offering it twice is not a crime"
    );
    assert!(
        reaction.relayed.is_empty(),
        "a node that hands on what it already held answers a flood with a \
         flood of its own, to every peer it has"
    );
}

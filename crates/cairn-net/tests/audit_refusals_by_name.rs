//! Four refusals a node hands its caller, produced for their cause.
//!
//! `Refused::Block`, `Refused::Transfer`, `NodeError::Io` and
//! `NodeError::Store` are made by `?` through a `From`, so no line of the node
//! names them, and no test had ever produced one. The wallet and `cairnd`
//! print each of them to a person, and the words they print are these
//! variants' own. A refusal nothing produces can change what it wraps, or
//! stop being produced, with every test green.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr, TcpListener};

use cairn_chain::ChainError;
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, ConsensusParams};
use cairn_ledger::{LedgerState, TransferError};
use cairn_net::node::Refused;
use cairn_net::{Node, NodeError};
use cairn_primitives::{Amount, Hash32};
use cairn_store::StoreError;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// A block the chain refuses comes back to the caller as the chain's refusal,
/// in the chain's words.
///
/// Nothing produced `Refused::Block`, so a node that answered a bad block
/// with another variant, or said nothing about why, passed.
#[test]
fn a_block_the_chain_refuses_is_refused_as_the_chain_said() {
    let node = Node::bind(params(), loopback()).unwrap();
    let coinbase = CoinbaseTransaction::new(
        0,
        vec![Note::new(
            params().initial_reward,
            SecretKey::from_bytes(&[1; 32]).public_key(),
        )],
    );
    let mut block = assemble_block(
        &LedgerState::new(),
        coinbase,
        Vec::new(),
        &params(),
        1_600,
        0,
    )
    .unwrap();
    block.header.state_root = Hash32::from_bytes([0x5a; 32]);

    let refused = node.submit_block(block);
    node.shutdown();
    let Err(Refused::Block(said)) = refused else {
        panic!("a block the chain cannot take was answered {refused:?}");
    };
    assert!(
        matches!(said, ChainError::InvalidBlock { .. }),
        "refused for something other than the block: {said}"
    );
    assert_eq!(
        Refused::Block(said.clone()).to_string(),
        said.to_string(),
        "the refusal a person reads is not the chain's own sentence"
    );
}

/// A transfer the rules refuse comes back to the caller as the rule it broke.
///
/// Nothing produced `Refused::Transfer`: it appeared only as a value two
/// wallet tests built by hand. A node that answered a transfer spending a
/// note it holds nowhere with `Ok(false)`, which the wallet reads as a full
/// pool, passed.
#[test]
fn a_transfer_the_rules_refuse_is_refused_as_the_rule_it_broke() {
    let node = Node::bind(params(), loopback()).unwrap();
    let owner = SecretKey::from_bytes(&[2; 32]);
    let claimed = Note::new(Amount::from_pebbles(1_000).unwrap(), owner.public_key());
    let nowhere = NoteId::new(Hash32::from_bytes([0x77; 32]), 0);
    let mut transfer = Transfer::new(
        vec![Input::hot(nowhere)],
        vec![Note::new(
            Amount::from_pebbles(900).unwrap(),
            SecretKey::from_bytes(&[3; 32]).public_key(),
        )],
    );
    transfer.sign_input(params().network, 0, &claimed, &owner);

    let refused = node.submit_transaction(transfer);
    node.shutdown();
    // Spent as a hot note the hot set does not hold, which could only be a
    // note that fell, and a note that fell is spent with the proof of where.
    assert!(
        matches!(
            refused,
            Err(Refused::Transfer(TransferError::MissingProof { note_id })) if note_id == nowhere
        ),
        "a transfer spending a note this node holds nowhere was answered {refused:?}"
    );
}

/// A node that cannot take the address it was given says the machine refused
/// it.
///
/// Nothing produced `NodeError::Io`, so a node that reported the address
/// somebody else holds as some other failure passed.
#[test]
fn a_node_that_cannot_listen_where_it_was_told_says_so() {
    let taken = TcpListener::bind(loopback()).unwrap();
    let refused = Node::bind(params(), taken.local_addr().unwrap());
    drop(taken);
    assert!(
        matches!(refused, Err(NodeError::Io(_))),
        "a node given an address somebody else holds was answered {:?}",
        refused.map(|_| ())
    );
}

/// A second node on a directory the first still holds is refused by the store,
/// and says which directory and who holds it.
///
/// Nothing produced `NodeError::Store`: `cairnd`'s exit code for it was tested
/// and its words were not read.
#[test]
fn a_directory_another_node_holds_is_refused_by_the_store() {
    let directory =
        std::env::temp_dir().join(format!("cairn-refusals-by-name-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();

    let (first, _) = Node::open(params(), loopback(), &directory).unwrap();
    let second = Node::open(params(), loopback(), &directory);
    let answered = second.as_ref().map(|_| ()).map_err(ToString::to_string);
    let refused_by_the_lock = matches!(second, Err(NodeError::Store(StoreError::Locked { .. })));
    drop(second);
    first.shutdown();
    drop(first);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        refused_by_the_lock,
        "a second node on a directory the first holds was answered {answered:?}"
    );
    let said = answered.unwrap_err();
    assert!(
        said.contains(&directory.display().to_string()),
        "the refusal does not say which directory: {said}"
    );
}

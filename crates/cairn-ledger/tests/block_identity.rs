//! A block and a copy of it with one signature changed.
//!
//! A block's identifier is the identifier of its header, so a copy that keeps
//! the header keeps the identifier, whatever its body. What a header says
//! about its body is `transactions_root`. That root used to be taken over the
//! coinbase identifier and each `Transfer::id()`, which leaves signatures and
//! witnesses out, so a copy with a signature turned to garbage produced the
//! root its header names and failed only when its signatures were checked.
//! `ChainStore` keys what it holds and what it remembers as bad by identifier,
//! and an attacker delivering that copy first could have it stand in for the
//! real block; `cairn-chain/tests/forged_twin.rs` holds what was done about
//! that in the chain.
//!
//! The root now commits to each transfer's whole encoding, so the copy still
//! shares the identifier and no longer produces the root: it is refused on
//! arrival as a body its header does not name.

#![allow(
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::{SecretKey, Signature};
use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Builds a one-transfer block whose header commits to its transactions_root,
/// exactly as a real miner would, and returns it.
fn signed_block() -> Block {
    let miner = wallet(1);
    let recipient = wallet(2);

    // A note the miner owns and is about to spend.
    let spent = Note::new(
        Amount::from_pebbles(5_000_000_000).unwrap(),
        miner.public_key(),
    );
    let spent_id = NoteId::new(Hash32::from_bytes([7u8; 32]), 0);

    let mut transfer = Transfer::new(
        vec![Input::hot(spent_id)],
        vec![Note::new(
            Amount::from_pebbles(4_000_000_000).unwrap(),
            recipient.public_key(),
        )],
    );
    transfer.sign_input(NetworkId::TESTNET, 0, &spent, &miner);

    // The signature is real and verifies against the spent note.
    let message = transfer.signature_message(NetworkId::TESTNET, 0, &spent);
    assert!(
        miner
            .public_key()
            .verify(message.as_bytes(), &transfer.inputs[0].signature)
            .is_ok(),
        "precondition: the honest block carries a valid signature"
    );

    let coinbase = CoinbaseTransaction::new(
        1,
        vec![Note::new(
            Amount::from_pebbles(1).unwrap(),
            miner.public_key(),
        )],
    );

    let mut block = Block {
        header: BlockHeader {
            version: BLOCK_VERSION,
            network: NetworkId::TESTNET,
            height: 1,
            previous: Hash32::from_bytes([1u8; 32]),
            transactions_root: Hash32::ZERO,
            state_root: Hash32::from_bytes([2u8; 32]),
            history: Hash32::ZERO,
            timestamp: 1_000,
            difficulty: 1,
            total_work: 1,
            nonce: 0,
        },
        coinbase,
        transfers: vec![transfer],
    };
    // A miner fills this in from the bodies, as connect_block re-checks.
    block.header.transactions_root = block.transactions_root();
    block
}

/// Returns `block` with input 0's signature replaced by a different 64 bytes.
fn corrupt_first_signature(mut block: Block) -> Block {
    block.transfers[0].inputs[0].signature = Signature::from_bytes(&[0xABu8; 64]);
    block
}

#[test]
fn a_block_and_its_signature_corrupted_twin_share_an_identifier() {
    let honest = signed_block();
    let twin = corrupt_first_signature(honest.clone());

    // The twin really is a different block on the wire...
    assert_ne!(
        honest.encode(),
        twin.encode(),
        "precondition: the twin differs from the honest block in its bytes"
    );
    // ...and its signature really is invalid.
    let spent = Note::new(
        Amount::from_pebbles(5_000_000_000).unwrap(),
        wallet(1).public_key(),
    );
    let message = twin.transfers[0].signature_message(NetworkId::TESTNET, 0, &spent);
    assert!(
        wallet(1)
            .public_key()
            .verify(message.as_bytes(), &twin.transfers[0].inputs[0].signature)
            .is_err(),
        "precondition: the twin's signature does not verify"
    );

    // The twin does not produce the root its header names, because the root
    // is taken over each transfer's whole encoding, signatures included. It
    // used to, since the leaf was the transfer's identifier, which leaves the
    // signature out, and a copy nothing short of applying told from the real
    // block could stand in for it.
    assert_ne!(
        twin.transactions_root(),
        twin.header.transactions_root,
        "a copy with one signature changed produces the root its header names"
    );

    // A valid block and a forged, invalid copy of it share one identifier, and
    // that is the property, not the defect.
    //
    // An identifier is taken over a header, and the header is the one thing
    // the copy did not change. What moved is the root inside the header, which
    // is what a body is checked against, so the copy is refused as a body its
    // header does not name. The transfer's own identifier still leaves out
    // signatures and proofs on purpose: refreshing a proof must not make a
    // different transfer, and anything already built on one would otherwise
    // stop being valid. The block names the version its miner carried.
    //
    // What the chain does about a shared identifier still stands, because
    // anybody can send a header with a body that is not its own: a held block
    // is a duplicate only if it is the same block, an identifier is remembered
    // as bad only for a failure the header alone settles, and a block that did
    // not apply is not kept to be handed to the next person who asks. Those
    // are held by `cairn-chain/tests/forged_twin.rs`.
    assert_eq!(
        honest.id(),
        twin.id(),
        "the identifier covers the header, and both have the same header"
    );
}

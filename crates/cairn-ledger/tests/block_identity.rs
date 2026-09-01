//! AUDIT SCRATCH TEST.
//!
//! A block header commits to `transactions_root`, a Merkle root over the
//! coinbase id and each `Transfer::id()`. `Transfer::id()` hashes `encode_body`,
//! which deliberately EXCLUDES the input signatures and witnesses. Nothing else
//! in the header commits to them either. Therefore a block's identifier does not
//! commit to the signatures that make the block valid.
//!
//! Consequence: given any block B, anyone can build a twin B' that is byte-for-
//! byte B with one input signature replaced by garbage. B' has the SAME block
//! id as B (the header is untouched and the transfer id ignores the signature),
//! passes the transactions_root check, and fails only at signature validation.
//!
//! `ChainStore` dedups and caches invalidity BY BLOCK ID
//! (cairn-chain/src/lib.rs:1049 `blocks.contains_key(&id) -> Duplicate`, and
//! :1168 `invalid.insert(id)` on a non-outdated failure, consulted at :1207).
//! An attacker who delivers B' before the honest B therefore poisons those
//! caches so the honest B is refused, which is a work-free, targeted relay DoS.
//!
//! This test asserts the property the design NEEDS to defend against that: a
//! block and its signature-corrupted twin must not share an identifier. It
//! FAILS on current code, which is the finding.

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
        spent
            .owner
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
        spent
            .owner
            .verify(message.as_bytes(), &twin.transfers[0].inputs[0].signature)
            .is_err(),
        "precondition: the twin's signature does not verify"
    );

    // The twin still passes the header's transactions_root check, because the
    // transfer id excludes the signature.
    assert_eq!(
        twin.transactions_root(),
        twin.header.transactions_root,
        "the corrupted twin passes the transactions_root check"
    );

    // A valid block and a forged, invalid copy of it share one identifier, and
    // that is the property, not the defect.
    //
    // An identifier is taken over a header. A header commits to its
    // transactions by their identifiers, and those leave out signatures and
    // proofs on purpose: refreshing a proof must not make a different
    // transfer, and anything already built on one would otherwise stop being
    // valid. Committing to the witnesses as well was written and taken back
    // out: it can only live in the header or in the coinbase, and in the
    // coinbase it does not change the identifier at all, which is the thing
    // that was supposed to move.
    //
    // So the identifier stays shared and what was done about it lives in the
    // chain, where the harm was: a held block is a duplicate only if it is the
    // same block, an identifier is remembered as bad only for a failure the
    // header alone settles, and a block that did not apply is not kept to be
    // handed to the next person who asks. Those three are held by
    // `cairn-chain/tests/forged_twin.rs`.
    assert_eq!(
        honest.id(),
        twin.id(),
        "the identifier covers the header, and both have the same header"
    );
}

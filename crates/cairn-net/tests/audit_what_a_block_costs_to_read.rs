//! What reading a block costs this node's processor, against what a peer pays
//! for it.
//!
//! A block's bytes are priced, arriving and served alike, at the rate of the
//! wire. What reading those bytes costs is another matter, and it used to run
//! with the number of owners in them rather than with the bytes: a note held
//! its owner's public key, and decoding one decompressed the point and
//! multiplied it by the group order before anything had judged the frame. A
//! note's owner is the hash of a key now, and the key is decoded only when an
//! input presents it and its hash has matched, which is at verification, where
//! a signature's price already pays for it.
//!
//! Both sides of the ratio are measured on the same machine in the same
//! process, so what it says is about the price and not about the machine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]

use std::hint::black_box;
use std::time::Instant;

use cairn_chain::ChainStore;
use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::genesis;
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::Message;
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::Keeps;
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// What one message of this shape took out of a greeted peer's window.
fn charged_for(message: Message) -> u32 {
    let mut chain = ChainStore::new(params());
    let mut peer = PeerState {
        greeted: true,
        height: 1_000,
        total_work: 1,
        ..PeerState::default()
    };
    let mut local = Local {
        keeps: Keeps {
            headers: true,
            cold_set: false,
        },
        nonce: 1,
        chain: &mut chain,
        listen: 4242,
    };
    on_message(&mut local, &mut peer, message, NOW);
    peer.spent
}

/// A real key, so that anything a decoder does with a key it does in full.
fn owner(index: usize) -> PublicKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    SecretKey::from_bytes(&seed).public_key()
}

fn a_payment(first_owner: usize) -> Transfer {
    let spending = vec![Input::hot(NoteId::new(
        Hash32::from_bytes([3; 32]),
        first_owner as u32,
    ))];
    let created = (0..2)
        .map(|index| Note::new(Amount::from_pebbles(1).unwrap(), owner(first_owner + index)))
        .collect();
    Transfer::new(spending, created)
}

/// A block filled to `max_block_bytes` with ordinary payments, every output
/// owned by a different real key.
fn a_full_block() -> Block {
    let first = genesis::block(NetworkId::DEVNET).unwrap();
    let header = BlockHeader {
        height: 1_000,
        ..first.header
    };
    let coinbase = CoinbaseTransaction::new(
        1_000,
        vec![Note::new(Amount::from_pebbles(1).unwrap(), owner(0))],
    );
    let mut block = Block {
        header,
        coinbase,
        transfers: Vec::new(),
    };
    let limit = params().max_block_bytes;
    let mut held = block.encode().len();
    let mut next = 0usize;
    loop {
        let transfer = a_payment(next * 2 + 1);
        let more = transfer.encode().len();
        if held + more > limit {
            break;
        }
        held += more;
        block.transfers.push(transfer);
        next += 1;
    }
    block
}

/// **A unit of allowance spent on a block buys about the processor a unit
/// spent on a signature does.**
///
/// A block pushed at this node is priced by its bytes, and a signature by the
/// input that presents it. Reading the block is the frame decoded into a
/// message, and it is done before anything else looks at it. With every
/// owner a key, a full block of payments was some fourteen hundred point
/// decompressions and order checks, about fifty microseconds each, for the
/// price of its bytes: a unit spent that way bought tens of times the
/// processor a unit spent on a signature did. Nothing asked, so a node that
/// decoded keys at the wire passed.
#[test]
fn a_unit_spent_on_a_block_buys_about_what_a_unit_spent_on_a_signature_does() {
    let block = a_full_block();
    let message = Message::Block(Box::new(block));
    let bytes = message.encode();
    let owners: usize = match &message {
        Message::Block(block) => {
            block
                .transfers
                .iter()
                .map(|transfer| transfer.outputs.len())
                .sum::<usize>()
                + block.coinbase.outputs.len()
        }
        _ => unreachable!(),
    };
    let block_price = charged_for(message);

    let rounds = 16u32;
    let started = Instant::now();
    for _ in 0..rounds {
        black_box(Message::decode(black_box(&bytes)).unwrap());
    }
    let per_block = started.elapsed().as_secs_f64() / f64::from(rounds);
    let per_unit_block = per_block / f64::from(block_price.max(1));

    // The yardstick: one verification, at what the table charges for the
    // smallest transfer that asks for one.
    let key = SecretKey::from_bytes(&[9; 32]);
    let signed = b"yardstick";
    let signature = key.sign(signed);
    let public = key.public_key();
    let verifications = 400u32;
    let started = Instant::now();
    for _ in 0..verifications {
        black_box(public.verify(black_box(signed), &signature)).unwrap();
    }
    let per_verify = started.elapsed().as_secs_f64() / f64::from(verifications);
    let mut smallest = a_payment(0);
    smallest.outputs.truncate(1);
    let verify_price = charged_for(Message::Transaction(Box::new(smallest)));
    let per_unit_verify = per_verify / f64::from(verify_price.max(1));

    println!(
        "a full block: {} bytes, {owners} owners, charged {block_price}, read in {:.2} ms, \
         {:.1} us a unit",
        bytes.len(),
        per_block * 1e3,
        per_unit_block * 1e6
    );
    println!(
        "one verification: {:.1} us, charged {verify_price}, {:.1} us a unit",
        per_verify * 1e6,
        per_unit_verify * 1e6
    );

    // Four is slack and not a measurement: what is refused is a price that is
    // wrong by an order of magnitude between two things a peer can send.
    assert!(
        per_unit_block <= 4.0 * per_unit_verify,
        "one unit of allowance buys {:.1} us of processor spent reading a block and {:.1} us \
         spent verifying a signature, a ratio of {:.0}: reading a block costs more than its \
         bytes are priced at",
        per_unit_block * 1e6,
        per_unit_verify * 1e6,
        per_unit_block / per_unit_verify
    );
}

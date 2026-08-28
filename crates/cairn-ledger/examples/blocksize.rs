//! How large a block the rules allow, against how large a message the network
//! carries.
//!
//! These are two limits on the same object, written in two places, and nothing
//! makes them agree. If the rules allow a block the wire refuses, a miner can
//! produce one that is valid and cannot be handed to anyone: whoever mined it
//! follows a chain nobody else can follow, which is a fork with no attacker in
//! it.
//!
//! Run with `cargo run --release -p cairn-ledger --example blocksize`.

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use cairn_accumulator::forest::ForestProof;
use cairn_crypto::{SecretKey, Signature};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, ColdWitness, Input, Transfer, Witness};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

/// What the wire carries, kept here as a plain number so this example does not
/// have to reach into the networking crate.
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// Hashes a cold proof carries. The forest commits to the whole cold set in
/// sixty four, so a path through it is at most that long.
const PROOF_HASHES: usize = 64;

fn main() {
    let params = ConsensusParams::testnet();
    let owner = SecretKey::from_bytes(&[1; 32]).public_key();

    let hot = Transfer::new(
        vec![Input::hot(NoteId::new(Hash32::ZERO, 0)); params.max_inputs_per_transfer],
        vec![Note::new(Amount::ZERO, owner); params.max_outputs_per_transfer],
    );
    let cold = Transfer::new(
        vec![cold_input(owner); params.max_inputs_per_transfer],
        vec![Note::new(Amount::ZERO, owner); params.max_outputs_per_transfer],
    );

    println!("What the rules allow, and what the wire carries\n");
    println!("{:>26}  {:>14}", "", "bytes");
    println!("{}", "-".repeat(44));
    line("one transfer, hot inputs", hot.encode().len());
    line("one transfer, cold inputs", cold.encode().len());
    println!();

    for (name, transfer) in [("hot", &hot), ("cold", &cold)] {
        let block = full_block(&params, transfer.clone());
        let size = block.encode().len();
        println!(
            "{:>26}  {:>14}  {} by the rules",
            format!("every part at its limit, {name}"),
            with_commas(size),
            if size <= params.max_block_bytes {
                "allowed"
            } else {
                "REFUSED"
            },
        );
    }
    println!();
    line("what a block may take", params.max_block_bytes);
    line("what the wire carries", MAX_FRAME_BYTES);

    println!(
        "\nThe counts allow {} transfers a block, {} inputs and {} outputs\n\
         each. Multiplied out that is a block no network would carry, which is\n\
         why the limit that decides is the one on bytes. It sits under what the\n\
         wire carries, and has to: a block the rules allow and the wire refuses\n\
         is one its miner could not hand to anyone.",
        params.max_transfers_per_block,
        params.max_inputs_per_transfer,
        params.max_outputs_per_transfer,
    );

    // An ordinary payment: one note spent, one to the payee, one back as
    // change. Everything else in this file is a worst case; this is the case.
    let ordinary = Transfer::new(
        vec![Input::hot(NoteId::new(Hash32::ZERO, 0))],
        vec![Note::new(Amount::ZERO, owner); 2],
    );
    let each = ordinary.encode().len().max(1);
    let per_block = (params.max_block_bytes / each).min(params.max_transfers_per_block);

    println!(
        "\nAn ordinary payment, one note in and two out, takes {each} bytes, so\n\
         a block holds about {} of them, or {} counting the ceiling on how\n\
         many transfers a block may carry.",
        with_commas(params.max_block_bytes / each),
        with_commas(per_block),
    );

    // Which decides something the byte limit does not say out loud: how long a
    // note stays in the hot set. Every payment nets one more note than it
    // spends, and the oldest fall out as the newest arrive.
    println!("\nHow long a note stays hot, at a given share of that:\n");
    println!(
        "{:>10}  {:>14}  {:>18}",
        "block is", "new notes", "a note stays hot"
    );
    println!("{}", "-".repeat(46));
    for share in [1.0f64, 0.5, 0.1, 0.01, 0.001] {
        let per = ((per_block as f64) * share).max(1.0);
        let blocks = params.hot_capacity as f64 / per;
        let seconds = blocks * params.target_block_time as f64;
        println!(
            "{:>9.1}%  {:>14}  {:>18}",
            share * 100.0,
            with_commas(per as usize),
            span(seconds),
        );
    }
    println!(
        "\nThe hot set holds {} notes. A note that falls out is not lost: it\n\
         is spent by presenting a proof, which its owner keeps current out of\n\
         what every block already carries. But it is the number that decides\n\
         how often that happens, and it comes from the block size rather than\n\
         from anything anyone chose on purpose.",
        with_commas(params.hot_capacity),
    );
}

fn line(name: &str, bytes: usize) {
    println!("{name:>26}  {:>14}", with_commas(bytes));
}

/// A block carrying as many copies of `transfer` as the rules allow.
fn full_block(params: &ConsensusParams, transfer: Transfer) -> Block {
    let owner = SecretKey::from_bytes(&[1; 32]).public_key();
    let coinbase = CoinbaseTransaction::new(
        0,
        vec![Note::new(Amount::ZERO, owner); params.max_coinbase_outputs],
    );
    Block {
        header: cairn_ledger::block::BlockHeader {
            version: 1,
            network: params.network,
            height: 0,
            previous: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 0,
            difficulty: 1,
            total_work: 0,
            nonce: 0,
        },
        coinbase,
        transfers: vec![transfer; params.max_transfers_per_block],
    }
}

/// An input spending a note out of the cold set, carrying the longest proof
/// the forest can produce.
fn cold_input(owner: cairn_crypto::PublicKey) -> Input {
    Input {
        note_id: NoteId::new(Hash32::ZERO, 0),
        witness: Witness::Cold(Box::new(ColdWitness {
            note: Note::new(Amount::ZERO, owner),
            position: 0,
            proof: ForestProof {
                siblings: vec![Hash32::ZERO; PROOF_HASHES],
            },
        })),
        signature: Signature::unsigned(),
    }
}

/// A duration in whatever unit reads plainly.
fn span(seconds: f64) -> String {
    if seconds < 5_400.0 {
        return format!("{:.0} min", seconds / 60.0);
    }
    if seconds < 172_800.0 {
        return format!("{:.1} h", seconds / 3_600.0);
    }
    if seconds < 63_072_000.0 {
        return format!("{:.1} days", seconds / 86_400.0);
    }
    format!("{:.1} years", seconds / 31_536_000.0)
}

fn with_commas(value: usize) -> String {
    let text = value.to_string();
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index > 0 && (text.len() - index) % 3 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

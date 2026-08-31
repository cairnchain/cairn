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
use cairn_ledger::state::{GRACE_BLOCKS, GRACE_NOTES};
use cairn_ledger::transaction::{CoinbaseTransaction, ColdWitness, Input, Transfer, Witness};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

/// What the wire carries, kept here as a plain number so this example does not
/// have to reach into the networking crate.
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Hashes a cold proof carries. The forest commits to the whole cold set in
/// sixty four, so a path through it is at most that long.
const PROOF_HASHES: usize = 64;

/// Blocks a node holds because it could still reorganise them away, kept here
/// as a plain number so this example does not reach into the chain crate.
const REORG_DEPTH: usize = 1024;

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
         a block holds about {} of them: {:.0} a second, at a block a minute.",
        with_commas(per_block),
        per_block as f64 / params.target_block_time as f64,
    );

    // The number the block size decides that nobody sees. A node holds the
    // blocks it could still reorganise away, so this is memory every node must
    // have, whatever else it is doing.
    println!(
        "\nA node holds the {} blocks it could still reorganise away, so a full\n\
         one of those is {} of memory every node must have.",
        with_commas(REORG_DEPTH),
        format_bytes(REORG_DEPTH * params.max_block_bytes),
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
        "\nThe hot set holds {} notes. A note that falls out is not lost: it is\n\
         spent by presenting a proof, which its owner keeps current out of what\n\
         every block already carries. But how often that happens follows from\n\
         the block size, which is one of the three things that number decides\n\
         and the reason it is not larger.",
        with_commas(params.hot_capacity),
    );

    grace(per_block);
    churn(&params, each, per_block);
}

/// What a transfer's fee is measured against per new note, kept here as a
/// plain number so this example does not reach into the chain crate.
const NOTE_WEIGHT: usize = 512;

/// The least a pooled transfer pays per unit of weight, in pebbles. The same
/// plain-number copy, for the same reason.
const MIN_FEE_PER_WEIGHT: u64 = 10;

/// What churning the hot set costs an attacker, before and after it was
/// priced.
///
/// The attack is a transfer that spends one note and creates as many as the
/// rules allow: every note past the first pushes somebody's oldest note out of
/// a full tier, at forty bytes each against the two hundred an ordinary
/// payment pays for its one. This measures that discount, what the fee weight
/// does to it, and where the consensus cap leaves the worst case.
fn churn(params: &ConsensusParams, ordinary_bytes: usize, per_block: usize) {
    let owner = SecretKey::from_bytes(&[1; 32]).public_key();
    let stuffed = Transfer::new(
        vec![Input::hot(NoteId::new(Hash32::ZERO, 0))],
        vec![Note::new(Amount::ZERO, owner); params.max_outputs_per_transfer],
    );
    let stuffed_bytes = stuffed.encode().len();
    let stuffed_notes = params.max_outputs_per_transfer - 1;

    let ordinary_weight = ordinary_bytes + NOTE_WEIGHT;
    let stuffed_weight = stuffed_bytes + stuffed_notes * NOTE_WEIGHT;

    println!("\nWhat pushing one note out of the hot set costs whoever does it:\n");
    println!("{:>26}  {:>10}  {:>10}", "", "by bytes", "by weight");
    println!("{}", "-".repeat(50));
    println!(
        "{:>26}  {:>10}  {:>10}",
        "an ordinary payment",
        with_commas(ordinary_bytes),
        with_commas(ordinary_weight),
    );
    println!(
        "{:>26}  {:>10}  {:>10}",
        "a transfer stuffed full",
        with_commas(stuffed_bytes / stuffed_notes),
        with_commas(stuffed_weight / stuffed_notes),
    );
    println!(
        "\nPriced by bytes, stuffing outputs churned the tier {:.1} times cheaper\n\
         than the payments it displaced. Priced by weight, the discount is\n\
         {:.2}: pushing a note out costs what a payment costs, however the\n\
         transfer is shaped.",
        ordinary_bytes as f64 / (stuffed_bytes as f64 / stuffed_notes as f64),
        ordinary_weight as f64 / (stuffed_weight as f64 / stuffed_notes as f64),
    );

    // Halving how long everyone's notes stay hot means doubling the eviction
    // rate, which at full blocks means matching the honest traffic's own note
    // creation, note for note.
    let notes_per_hour = per_block * 3600 / params.target_block_time as usize;
    let weight_per_hour = notes_per_hour * stuffed_weight / stuffed_notes;
    let floor_per_hour = weight_per_hour as u64 * MIN_FEE_PER_WEIGHT;
    println!(
        "\nHalving how long everyone's notes stay hot, at full blocks, takes\n\
         {} extra new notes an hour. That used to be free: zero-fee\n\
         transfers were pooled and mined. Priced by weight those notes cost\n\
         {} pebbles an hour ({:.2} CAIRN) at the floor, and on a contested\n\
         chain they cost outbidding an hour of everyone else's payments, at\n\
         about {} weight against their {}. On a full chain the cap below\n\
         refuses the rate outright, so the halving cannot be bought at all.",
        with_commas(notes_per_hour),
        with_commas(floor_per_hour as usize),
        floor_per_hour as f64 / 1e8,
        with_commas(weight_per_hour),
        with_commas(notes_per_hour * ordinary_weight),
    );

    // What no fee bounds: a miner stuffing its own blocks pays itself. The
    // consensus cap is what holds there.
    let stuffed_per_block = params.max_block_bytes / stuffed_bytes;
    let evictions_uncapped = stuffed_per_block * stuffed_notes;
    let uncapped_minutes = params.hot_capacity as f64 / evictions_uncapped as f64
        * params.target_block_time as f64
        / 60.0;
    let capped_minutes = params.hot_capacity as f64 / params.max_evictions_per_block as f64
        * params.target_block_time as f64
        / 60.0;
    println!(
        "\nA miner filling its own blocks pays no fee at all: {} stuffed\n\
         transfers fit a block and push out {} notes, emptying the whole\n\
         tier in {:.0} minutes. The consensus cap of {} evictions a block\n\
         makes that {:.0} minutes at any price, against the {:.0} minutes a\n\
         full chain of honest payments takes.",
        with_commas(stuffed_per_block),
        with_commas(evictions_uncapped),
        uncapped_minutes,
        with_commas(params.max_evictions_per_block),
        capped_minutes,
        params.hot_capacity as f64 / per_block as f64 * params.target_block_time as f64 / 60.0,
    );
}

fn line(name: &str, bytes: usize) {
    println!("{name:>26}  {:>14}", with_commas(bytes));
}

/// Bytes in whatever unit reads plainly.
fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_000_000_000 {
        return format!("{:.1} GB", bytes as f64 / 1e9);
    }
    if bytes >= 1_000_000 {
        return format!("{} MB", bytes / 1_000_000);
    }
    format!("{} kB", bytes / 1_000)
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

/// How long the grace on a fallen note actually lasts.
///
/// The other place the block size decides something quietly. A note that has
/// just fallen stays spendable without a proof for whichever comes first: a
/// number of blocks, or a number of notes. On a busy enough chain the second
/// arrives inside a single block, and the sixty four the first promises never
/// happen.
fn grace(per_block: usize) {
    println!("\nHow long the grace on a fallen note actually lasts:\n");
    println!(
        "{:>10}  {:>14}  {:>16}  {:>10}",
        "block is", "notes fallen", "grace lasts", "promised"
    );
    println!("{}", "-".repeat(58));
    for share in [1.0f64, 0.5, 0.1, 0.01, 0.001] {
        let per = ((per_block as f64) * share).max(1.0);
        let by_notes = (GRACE_NOTES as f64 / per).max(1.0);
        let lasts = by_notes.min(GRACE_BLOCKS as f64);
        println!(
            "{:>9.1}%  {:>14}  {:>16}  {:>10}",
            share * 100.0,
            with_commas(per as usize),
            format!("{lasts:.0} block(s)"),
            format!("{GRACE_BLOCKS} blocks"),
        );
    }
    println!(
        "\nBoth bounds are deliberate and the tighter one is meant to win. What\n\
         is worth knowing is which one that is: the grace exists so a transfer\n\
         written against the chain as it stands does not lose its race with the\n\
         next block, and on a busy chain it is spent inside that same block."
    );
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

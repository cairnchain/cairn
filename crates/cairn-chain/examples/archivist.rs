//! What each role in the network carries, over thirty years.
//!
//! Three services, and they are not the same job:
//!
//! - Following the chain. Validating blocks as they arrive and answering about
//!   the tip. Every node does this.
//! - Keeping the history. Holding every block ever accepted, so a node that
//!   reads the chain the long way has somebody to read it from.
//! - Archiving. Holding every header and every fallen note, so a newcomer can
//!   be shown which chain is heaviest and a wallet that lost a proof can be
//!   given it back.
//!
//! What this computes is what each of them costs at thirty years, from the
//! sizes the rules actually impose rather than from guesses. It exists because
//! the claim the whole design rests on is about that number.
//!
//! Run with `cargo run --release -p cairn-chain --example archivist`.

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::print_stdout
)]

use cairn_chain::ChainStore;
use cairn_ledger::validation::ConsensusParams;

/// Thirty years of a block a minute.
const BLOCKS: u64 = 30 * 365 * 24 * 60;

/// Bytes an ordinary payment takes on the wire: one note in, two out.
const PAYMENT_BYTES: u64 = 191;
/// Notes such a payment leaves behind, net of the one it spends.
const NOTES_PER_PAYMENT: u64 = 1;

/// A leaf and the inner node above it, which is what an archive holds per item.
const ARCHIVED_BYTES: u64 = 64;
/// What a header costs an archivist, which is the same bargain.
const HEADER_BYTES: u64 = 64;

fn main() {
    let params = ConsensusParams::testnet();
    let full = params.max_block_bytes as u64;

    println!("What thirty years of Cairn costs, by what a node has chosen to do.\n");
    println!("A block a minute, {BLOCKS} blocks, at three ways a chain can be used.\n");

    println!(
        "{:>14}  {:>14}  {:>14}  {:>14}  {:>14}",
        "chain is", "payments/s", "follows only", "keeps history", "archives"
    );
    println!("{}", "-".repeat(78));

    for share in [0.01f64, 0.10, 1.00] {
        let block = (full as f64 * share) as u64;
        let payments = block / PAYMENT_BYTES;
        let notes = payments * NOTES_PER_PAYMENT;

        // Following: bounded by the rules and does not grow with the chain.
        let follows = ChainStore::held_bytes_ceiling(&params) as u64;

        // Keeping the history: every block ever accepted, on disk.
        let history = BLOCKS * block;

        // Archiving: every header, and every note that ever fell out of the
        // hot set, both held so a path through them can be built.
        let fallen = (BLOCKS * notes).saturating_sub(params.hot_capacity as u64);
        let archive = BLOCKS * HEADER_BYTES + fallen * ARCHIVED_BYTES;

        println!(
            "{:>13.0}%  {:>14.1}  {:>14}  {:>14}  {:>14}",
            share * 100.0,
            payments as f64 / 60.0,
            bytes(follows),
            bytes(history),
            bytes(archive),
        );
    }

    println!(
        "\nOnly the first of the three is bounded. It is the one the design set out\n\
         to bound, and the sampled start is what lets a node do it and nothing\n\
         else: a newcomer no longer has to read the history to join, so a node no\n\
         longer has to keep it for them.\n"
    );
    println!(
        "Today every node keeps all three whether it meant to or not: nothing\n\
         trims the log, so a node's disk grows with the chain even though its\n\
         memory does not."
    );
}

fn bytes(count: u64) -> String {
    let count = count as f64;
    if count >= 1e12 {
        format!("{:.1} TB", count / 1e12)
    } else if count >= 1e9 {
        format!("{:.1} GB", count / 1e9)
    } else if count >= 1e6 {
        format!("{:.0} MB", count / 1e6)
    } else {
        format!("{:.0} kB", count / 1e3)
    }
}

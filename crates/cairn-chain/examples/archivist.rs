//! What each role in the network carries, over thirty years.
//!
//! Four services, and they are not the same job:
//!
//! - Following the chain. Validating blocks as they arrive and answering about
//!   the tip. Every node does this.
//! - Taking in newcomers. Holding every header and the forest they make, so
//!   somebody arriving can be shown which chain carries the most work. Every
//!   node does this too, which is what stops joining a chain from depending on
//!   anyone volunteering.
//! - Keeping the history. Holding every block ever accepted, so a node that
//!   reads the chain the long way has somebody to read it from.
//! - Archiving. Holding every note that ever fell out of the hot set, so a
//!   wallet that lost its proof can be given it back.
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
use cairn_ledger::block::BlockHeader;
use cairn_ledger::validation::ConsensusParams;

/// Thirty years of a block a minute.
const BLOCKS: u64 = 30 * 365 * 24 * 60;

/// Bytes an ordinary payment takes on the wire: one note in, two out.
const PAYMENT_BYTES: u64 = 191;
/// Notes such a payment leaves behind, net of the one it spends.
const NOTES_PER_PAYMENT: u64 = 1;

/// A leaf and the inner node above it, which is what a forest holds per item.
///
/// Structural, and worth saying so: a forest of `n` leaves holds `n` of them
/// and `n - 1` nodes above, at thirty two bytes each, so it costs two hashes
/// an item on disk. It is not a reading of a process, and it must not be
/// quoted as one. The whitepaper's "about 64 bytes for every note that has
/// ever fallen" is a separate number that happens to land in the same place:
/// that one is an archiving node's memory, measured with `footprint` over 3.2
/// million notes. Two numbers, two provenances, and only this one is exact.
const ARCHIVED_BYTES: u64 = 2 * 32;
/// What a header takes on disk, which is what it takes on the wire.
///
/// Taken from the type rather than written out. `cairn-store` refuses to open
/// a header log when this number moves, because its records are laid out for
/// it; an example has nothing to refuse and would go on printing the old one.
const HEADER_BYTES: u64 = BlockHeader::ENCODED_BYTES as u64;

fn main() {
    let params = ConsensusParams::testnet();
    let full = params.max_block_bytes as u64;

    println!("What thirty years of Cairn costs, by what a node has chosen to do.\n");
    println!("A block a minute, {BLOCKS} blocks, at three ways a chain can be used.\n");

    println!(
        "{:>10}  {:>11}  {:>12}  {:>12}  {:>13}  {:>10}",
        "chain is", "payments/s", "follows", "takes in", "keeps history", "archives"
    );
    println!("{}", "-".repeat(80));

    for share in [0.01f64, 0.10, 1.00] {
        let block = (full as f64 * share) as u64;
        let payments = block / PAYMENT_BYTES;
        let notes = payments * NOTES_PER_PAYMENT;

        // Following: bounded by the rules and does not grow with the chain.
        let follows = ChainStore::held_bytes_ceiling(&params) as u64;

        // Keeping the history: every block ever accepted, on disk.
        let history = BLOCKS * block;

        // Taking in newcomers: every header, and the forest they make, both
        // on disk. The same figure whatever the chain carries, since a header
        // is the same size whether its block is full or empty.
        let taking_in = BLOCKS * (HEADER_BYTES + ARCHIVED_BYTES);

        // Archiving: every note that ever fell out of the hot set, held so a
        // path through them can be built.
        let fallen = (BLOCKS * notes).saturating_sub(params.hot_capacity as u64);
        let archive = fallen * ARCHIVED_BYTES;

        println!(
            "{:>9.0}%  {:>11.1}  {:>12}  {:>12}  {:>13}  {:>10}",
            share * 100.0,
            payments as f64 / 60.0,
            bytes(follows),
            bytes(taking_in),
            bytes(history),
            bytes(archive),
        );
    }

    println!(
        "\nA node does the first two. The first is bounded by the rules and does not\n\
         grow at all; the second grows, at 129 MB a year, which is the price of\n\
         not needing anybody's permission to join. Bitcoin's equivalent promise\n\
         costs 50 GB a year and Ethereum's 200.\n"
    );
    println!(
        "The last two are chosen work, and the network runs without them. That is\n\
         the whole of what was decided here: rather than find a way to pay for a\n\
         service nobody could do without, make the service nobody can do without\n\
         small enough that everybody does it."
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

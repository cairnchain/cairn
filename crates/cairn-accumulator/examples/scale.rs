//! Measures what a node stores, and what a holder carries, as the set grows.
//!
//! Run with `cargo run --release -p cairn-accumulator --example scale`.

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use cairn_accumulator::{Key, SparseMerkleTree};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Hash32;

/// Value plus owner plus identifier, which is what a conventional node keeps
/// for every unspent note.
const BYTES_PER_NOTE: usize = 8 + 32 + 36;

fn key(index: u64) -> Key {
    Key::from_hash(hash(Domain::StateEntry, &index.to_le_bytes()))
}

fn value(index: u64) -> Hash32 {
    hash(Domain::MerkleLeaf, &index.to_le_bytes())
}

fn main() {
    println!(
        "{:>12}  {:>14}  {:>12}  {:>12}  {:>10}",
        "notes", "conventional", "cairn node", "proof avg", "proof max"
    );
    println!("{}", "-".repeat(68));

    let mut tree = SparseMerkleTree::new();
    let mut inserted = 0u64;

    for target in [1_000u64, 10_000, 100_000, 1_000_000] {
        while inserted < target {
            tree.insert(key(inserted), value(inserted));
            inserted += 1;
        }

        let sampled = 2_000u64.min(target);
        let step = target / sampled;
        let mut total = 0usize;
        let mut largest = 0usize;
        for sample in 0..sampled {
            let proof = tree.prove(key(sample * step));
            total += proof.size_in_bytes();
            largest = largest.max(proof.size_in_bytes());
        }

        println!(
            "{:>12}  {:>14}  {:>12}  {:>12}  {:>10}",
            format_count(target),
            format_bytes(target as usize * BYTES_PER_NOTE),
            "32 B",
            format_bytes(total / sampled as usize),
            format_bytes(largest),
        );
    }

    println!();
    println!("The cairn column is the accumulator root. It is 32 bytes at every size,");
    println!("and it stays 32 bytes at every size this table does not reach.");
}

fn format_count(count: u64) -> String {
    if count >= 1_000_000 {
        format!("{} M", count / 1_000_000)
    } else {
        format!("{} k", count / 1_000)
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_000_000 {
        format!("{:.0} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} kB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

//! What a node actually pays, in memory, to hold a hot set of a given size.
//!
//! The number decides the one setting still open in the protocol: how many
//! notes stay hot. It is measured rather than reasoned about, because the
//! answer is dominated by allocator behaviour and pointer overhead rather than
//! by the size of a note.
//!
//! The three structures built here are exactly the three a `LedgerState` keeps
//! for its hot set: the notes themselves, the ordering that decides what falls
//! next, and the tree that commits to them.
//!
//! Run with `cargo run --release -p cairn-ledger --example footprint`.

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use cairn_accumulator::SparseMerkleTree;
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::{cold_leaf, note_key, HotEntry};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Amount;

const SIZES: [usize; 5] = [10_000, 50_000, 100_000, 500_000, 1_000_000];

fn main() {
    let owner = SecretKey::from_bytes(&[1; 32]).public_key();
    let value = Amount::from_pebbles(5_000_000_000).expect("under the ceiling");

    println!(
        "{:>12}  {:>12}  {:>14}  {:>12}",
        "hot notes", "memory", "per note", "phone?"
    );
    println!("{}", "-".repeat(58));

    let baseline = resident_bytes().unwrap_or(0);

    for size in SIZES {
        let mut notes: BTreeMap<NoteId, HotEntry> = BTreeMap::new();
        let mut by_age: BTreeSet<(u64, NoteId)> = BTreeSet::new();
        let mut tree = SparseMerkleTree::new();

        for index in 0..size {
            let id = identifier(index);
            let height = (index / 32) as u64;
            let note = Note::new(value, owner);
            notes.insert(id, HotEntry { note, height });
            by_age.insert((height, id));
            tree.insert(note_key(&id), cold_leaf(&id, &note));
        }

        let used = resident_bytes().unwrap_or(0).saturating_sub(baseline);
        let per_note = used.checked_div(size as u64).unwrap_or(0);
        println!(
            "{:>12}  {:>12}  {:>14}  {:>12}",
            format_count(size),
            format_bytes(used),
            format!("{per_note} B"),
            if used < 512 * 1_000_000 { "yes" } else { "no" },
        );

        drop(notes);
        drop(by_age);
        drop(tree);
    }

    println!();
    println!("Measured on this machine, resident memory, release build. The root a");
    println!("node publishes is 32 bytes at every one of these sizes; what is measured");
    println!("here is only what it keeps in order to answer without a proof.");
}

fn identifier(index: usize) -> NoteId {
    let source = hash(Domain::StateEntry, &(index as u64).to_le_bytes());
    NoteId::new(source, u32::try_from(index % 256).unwrap_or(0))
}

fn resident_bytes() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let kilobytes: u64 = text.trim().parse().ok()?;
    Some(kilobytes.saturating_mul(1_024))
}

fn format_count(count: usize) -> String {
    if count >= 1_000_000 {
        format!("{} M", count / 1_000_000)
    } else {
        format!("{} k", count / 1_000)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.0} MB", bytes as f64 / 1_000_000.0)
    } else {
        format!("{:.0} kB", bytes as f64 / 1_000.0)
    }
}

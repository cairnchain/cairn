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
//! Each measurement runs in its own process, because an allocator does not
//! hand freed pages straight back: building one structure after another in a
//! single run charges the second for what the first had already asked for, and
//! that is exactly the comparison this has to get right. So the example
//! re-runs itself, once per structure and size, and each run measures a
//! process that built nothing else.
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
use cairn_ledger::validation::ConsensusParams;
use cairn_ledger::{cold_leaf, note_key, HotEntry};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Amount;

const SIZES: [usize; 5] = [10_000, 50_000, 100_000, 500_000, 1_000_000];

/// Which of the structures a run is asked to build.
const PARTS: [&str; 3] = ["all", "map", "tree"];

fn main() {
    let mut arguments = std::env::args().skip(1);
    if let (Some(part), Some(size)) = (arguments.next(), arguments.next()) {
        let size = size.parse().unwrap_or(0);
        println!("{}", build(&part, size));
        return;
    }

    println!("What a hot set costs, and where the cost goes.\n");
    println!(
        "{:>12}  {:>12}  {:>12}  {:>12}  {:>10}",
        "hot notes", "memory", "map and order", "tree", "per note"
    );
    println!("{}", "-".repeat(66));

    let mut rows = Vec::new();
    for size in SIZES {
        let mut measured = [0u64; 3];
        for (slot, part) in measured.iter_mut().zip(PARTS.iter()) {
            *slot = measure(part, size);
        }
        let [all, map, tree] = measured;
        rows.push((size, all, map, tree));
        println!(
            "{:>12}  {:>12}  {:>12}  {:>12}  {:>8} B",
            format_count(size),
            format_bytes(all),
            format_bytes(map),
            format_bytes(tree),
            all.checked_div(size as u64).unwrap_or(0),
        );
    }

    let held = core::mem::size_of::<NoteId>() + core::mem::size_of::<HotEntry>();
    println!("\nPer note, against the {held} bytes of identifier and note they hold:\n");
    println!(
        "{:>12}  {:>16}  {:>16}  {:>12}",
        "hot notes", "map and order", "tree", "overhead"
    );
    println!("{}", "-".repeat(62));
    for (size, all, map, tree) in &rows {
        let each = |bytes: u64| bytes.checked_div(*size as u64).unwrap_or(0);
        println!(
            "{:>12}  {:>14} B  {:>14} B  {:>10.0}x",
            format_count(*size),
            each(*map),
            each(*tree),
            each(*all) as f64 / held as f64,
        );
    }

    println!(
        "\nResident memory, release build, one process per measurement. The two\n\
         halves do not add up to the whole: a process that builds both reuses\n\
         pages the allocator already holds. What they compare is which structure\n\
         is worth attacking.\n"
    );
    println!("The root a node publishes is 32 bytes at every one of these sizes; what");
    println!("is measured here is only what it keeps in order to answer without a");
    println!("proof.\n");

    let ceiling = ConsensusParams::testnet().hot_capacity;
    let per_note = rows
        .last()
        .and_then(|(size, all, _, _)| all.checked_div(*size as u64))
        .unwrap_or(0);
    println!(
        "At the ceiling the rules impose, {}, that is {}. This is the number\n\
         that has to fit on a phone, and it does not grow with the chain.",
        format_count(ceiling),
        format_bytes(per_note.saturating_mul(ceiling as u64)),
    );
}

/// Runs one measurement in a process that built nothing else.
fn measure(part: &str, size: usize) -> u64 {
    let Ok(program) = std::env::current_exe() else {
        return 0;
    };
    let Ok(output) = Command::new(program)
        .args([part, &size.to_string()])
        .output()
    else {
        return 0;
    };
    String::from_utf8(output.stdout)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// Builds one of the structures and reports what the process grew by.
fn build(part: &str, size: usize) -> u64 {
    let owner = SecretKey::from_bytes(&[1; 32]).public_key();
    let value = Amount::from_pebbles(5_000_000_000).expect("under the ceiling");
    let baseline = resident_bytes().unwrap_or(0);

    let mut notes: BTreeMap<NoteId, HotEntry> = BTreeMap::new();
    let mut by_age: BTreeSet<(u64, NoteId)> = BTreeSet::new();
    let mut tree = SparseMerkleTree::new();

    for index in 0..size {
        let id = identifier(index);
        let height = (index / 32) as u64;
        let note = Note::new(value, owner);
        if part != "tree" {
            notes.insert(id, HotEntry { note, height });
            by_age.insert((height, id));
        }
        if part != "map" {
            tree.insert(note_key(&id), cold_leaf(&id, &note));
        }
    }

    let used = resident_bytes().unwrap_or(0).saturating_sub(baseline);
    // Kept alive past the measurement, so none of it is freed before it counts.
    assert!(notes.len() + by_age.len() + tree.len() > 0 || size == 0);
    used
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

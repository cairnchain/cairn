//! The forest of headers kept on disk has to be the same forest as the one
//! kept in memory. Not similar: the same, hash for hash and path for path. A
//! node whose proofs differed would be answering about a chain nobody else is
//! on, and would look to itself like it was answering correctly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use cairn_accumulator::{forest::forest_leaf, Archive};
use cairn_store::{HeaderTree, HEADER_TREE};

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-tree-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn leaf(index: u64) -> cairn_primitives::Hash32 {
    forest_leaf(&index.to_le_bytes())
}

#[test]
fn a_forest_on_disk_proves_what_one_in_memory_proves() {
    let directory = scratch("same");
    let mut disk = HeaderTree::open(&directory).unwrap();
    let mut memory = Archive::new();

    for index in 0..200u64 {
        disk.append(leaf(index)).unwrap();
        memory.add(leaf(index));

        // Checked as it grows rather than only at the end, because the shape
        // of a forest changes with every leaf and the interesting sizes are
        // the ones just before and after a power of two.
        if index % 17 == 0 || index > 190 {
            for position in [0u64, 1, index / 2, index] {
                if position > index {
                    continue;
                }
                let leaves = index + 1;
                assert_eq!(
                    disk.prove_in(position, leaves).unwrap().map(|p| p.siblings),
                    memory.prove_in(position, leaves).map(|p| p.siblings),
                    "position {position} of {leaves} differs on disk"
                );
            }
        }
    }
    assert_eq!(disk.len(), memory.len());

    // Proving against an earlier size, which is what a chain does: what a tip
    // commits to is the forest from before it.
    for leaves in [1u64, 2, 3, 64, 65, 127, 128, 199] {
        for position in [0u64, 1, leaves - 1] {
            assert_eq!(
                disk.prove_in(position, leaves).unwrap().map(|p| p.siblings),
                memory.prove_in(position, leaves).map(|p| p.siblings),
                "position {position} of {leaves}"
            );
        }
    }

    // And a proof that cannot be built is refused rather than invented.
    assert!(disk.prove_in(200, 200).unwrap().is_none());
    assert!(disk.prove_in(0, 201).unwrap().is_none());

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_forest_cut_back_is_the_forest_that_never_grew() {
    let directory = scratch("rewind");
    let mut grown = HeaderTree::open(&directory).unwrap();
    for index in 0..90u64 {
        grown.append(leaf(index)).unwrap();
    }

    let other = scratch("rewind-other");
    let mut cut = HeaderTree::open(&other).unwrap();
    for index in 0..140u64 {
        cut.append(leaf(index)).unwrap();
    }
    cut.keep_first(90).unwrap();
    assert_eq!(cut.len(), 90);

    // Grown again over the same ground, as a new branch is.
    for index in 90..100u64 {
        grown.append(leaf(index)).unwrap();
        cut.append(leaf(index)).unwrap();
    }
    for position in [0u64, 1, 63, 64, 89, 95, 99] {
        assert_eq!(
            grown.prove_in(position, 100).unwrap().map(|p| p.siblings),
            cut.prove_in(position, 100).unwrap().map(|p| p.siblings),
            "position {position} depends on how the forest got here"
        );
    }

    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&other);
}

#[test]
fn what_it_holds_survives_being_reopened() {
    let directory = scratch("reopen");
    {
        let mut tree = HeaderTree::open(&directory).unwrap();
        for index in 0..70u64 {
            tree.append(leaf(index)).unwrap();
        }
    }
    let tree = HeaderTree::open(&directory).unwrap();
    assert_eq!(tree.len(), 70);

    let mut memory = Archive::new();
    for index in 0..70u64 {
        memory.add(leaf(index));
    }
    for position in [0u64, 33, 69] {
        assert_eq!(
            tree.prove_in(position, 70).unwrap().map(|p| p.siblings),
            memory.prove_in(position, 70).map(|p| p.siblings),
        );
    }

    let _ = std::fs::remove_dir_all(&directory);
}

/// What a forest costs on disk, which is the number the whole "every node
/// takes in newcomers" claim is priced from.
///
/// A forest of `n` leaves holds `n` of them and `n - 1` nodes above, so it is
/// two nodes a leaf and not one. `header_tree.rs` used to say thirty two bytes
/// a block, which is level zero alone, in the same sentence as the gigabyte at
/// thirty years that only comes out at sixty four. Measured here rather than
/// argued, because the figure is published: `cairn-chain/examples/archivist.rs`
/// prints what taking in newcomers costs from it, and the whitepaper quotes
/// "182 bytes a header and 64 for its place in the forest".
#[test]
fn a_forest_costs_two_nodes_a_leaf_on_disk() {
    let directory = scratch("size");
    let leaves = 4_096u64;
    {
        let mut tree = HeaderTree::open(&directory).unwrap();
        for index in 0..leaves {
            tree.append(leaf(index)).unwrap();
        }
    }

    let mut held = 0u64;
    for entry in std::fs::read_dir(&directory).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with(HEADER_TREE) {
            held += entry.metadata().unwrap().len();
        }
    }
    let each = (held + leaves / 2) / leaves;
    println!("{leaves} headers cost {held} bytes of forest, {each} bytes a header");

    // A power of two is the worst case for the count and the exact one: every
    // level above the leaves is full, so the forest is 2n - 1 nodes.
    assert_eq!(held, (2 * leaves - 1) * 32);
    assert_eq!(
        each, 64,
        "the forest costs {held} bytes for {leaves} headers, and 64 a header is \
         what the paper, the archivist example and `header_tree.rs` all quote"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

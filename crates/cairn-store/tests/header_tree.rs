//! The forest of headers kept on disk has to be the same forest as the one
//! kept in memory. Not similar: the same, hash for hash and path for path. A
//! node whose proofs differed would be answering about a chain nobody else is
//! on, and would look to itself like it was answering correctly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use cairn_accumulator::{forest::forest_leaf, Archive};
use cairn_store::HeaderTree;

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

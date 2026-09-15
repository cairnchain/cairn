//! How long a forest node of the right length holding the wrong bytes costs.
//!
//! `prove_in` says: "Refusing one proof leaves the node running, following the
//! chain and serving headers, which is not the same kind of cost as refusing
//! to start." True. The question is whether it refuses one proof or every
//! proof that folds through the node, for the rest of the node's life: nothing
//! writes a node again once its level is the length the leaves account for,
//! `mend_levels` measures agreement in length, and the node's own `grow_forest`
//! compares leaves and never nodes. A node at height `k` is on the path of
//! `2^k` leaves beneath it and the sibling of the `2^k` beside it, so its
//! cost is `2^(k + 1)` leaves.
//!
//! The forest writes with no sync, and the crate says so: "under a power cut
//! any level can stop mid-write". A level whose length grew before its bytes
//! landed is exactly a node of the right length holding the wrong bytes, and
//! it is not rot. This measures what that costs across two restarts and a
//! further sixteen leaves.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cairn_primitives::Hash32;
use cairn_store::{HeaderTree, StoreError, HEADER_TREE};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-torn-node-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn leaf(n: u64) -> Hash32 {
    Hash32::from_bytes([u8::try_from(n % 251).unwrap() + 1; 32])
}

fn put(path: &Path, at: u64, value: &[u8]) {
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(value).unwrap();
}

/// Positions whose proof against `leaves` is refused, and how.
fn refused(tree: &HeaderTree, leaves: u64) -> Vec<(u64, String)> {
    (0..leaves)
        .filter_map(|at| match tree.prove_in(at, leaves) {
            Ok(_) => None,
            Err(error) => Some((at, error.to_string())),
        })
        .collect()
}

#[test]
fn a_node_torn_in_place_refuses_the_same_leaves_after_every_restart() {
    let directory = scratch("life");
    {
        let mut tree = HeaderTree::open(&directory).unwrap();
        for at in 0..16u64 {
            tree.append(leaf(at)).unwrap();
        }
    }
    // The last node of level one, covering leaves fourteen and fifteen: the
    // node an append tears when its length lands and its bytes do not.
    put(
        &directory.join(format!("{HEADER_TREE}.1")),
        7 * 32,
        &[0u8; 32],
    );

    let first = {
        let tree = HeaderTree::open(&directory).unwrap();
        assert_eq!(tree.len(), 16, "the open sees nothing");
        refused(&tree, 16)
    };
    let second = {
        let tree = HeaderTree::open(&directory).unwrap();
        refused(&tree, 16)
    };
    let grown = {
        let mut tree = HeaderTree::open(&directory).unwrap();
        for at in 16..32u64 {
            tree.append(leaf(at)).unwrap();
        }
        (refused(&tree, 16), refused(&tree, 32))
    };

    println!("PROBE: one level-one node zeroed in a forest of 16");
    println!("PROBE: refused after the first restart: {first:?}");
    println!("PROBE: refused after the second restart: {second:?}");
    println!(
        "PROBE: refused after sixteen more leaves, against 16: {:?}",
        grown.0
    );
    println!(
        "PROBE: refused after sixteen more leaves, against 32: {:?}",
        grown.1
    );

    // Four leaves, not two. The node covers fourteen and fifteen, and it is
    // also the sibling that twelve and thirteen fold with on their way up, so
    // their fold disagrees with the node above. A node at height `k` costs the
    // proofs of `2^(k + 1)` leaves: the ones beneath it and the ones beneath
    // its sibling.
    let positions = |list: &[(u64, String)]| list.iter().map(|(at, _)| *at).collect::<Vec<_>>();
    assert_eq!(
        positions(&first),
        vec![12, 13, 14, 15],
        "the leaves under it and under its sibling"
    );
    assert_eq!(
        positions(&second),
        vec![12, 13, 14, 15],
        "a restart repairs nothing"
    );
    assert_eq!(
        positions(&grown.0),
        vec![12, 13, 14, 15],
        "growing repairs nothing"
    );
    assert_eq!(
        positions(&grown.1),
        vec![12, 13, 14, 15],
        "and against the larger forest the same four are refused"
    );
    assert!(first.iter().all(|(_, why)| why.contains("folded together")));

    // What the store could have said instead, since it has the two children:
    // the node is one hash of bytes it already holds. Measured so the size of
    // the repair is on record.
    let tree = HeaderTree::open(&directory).unwrap();
    let error = tree.prove_in(14, 32).unwrap_err();
    assert!(matches!(
        error,
        StoreError::Unfolded {
            height: 1,
            start: 14
        }
    ));
    let _ = std::fs::remove_dir_all(&directory);
}

/// And what mending it costs, which is the subtree and not the chain.
///
/// The leaves are the only thing here derived from nothing, so they are what
/// settles which of a node and its sibling tore. Asking them is bounded by
/// what the node covers.
#[test]
fn a_torn_node_mended_from_the_leaves_answers_again() {
    let directory = scratch("mended");
    let leaves: Vec<Hash32> = (0..16).map(leaf).collect();
    {
        let mut tree = HeaderTree::open(&directory).unwrap();
        for one in &leaves {
            tree.append(*one).unwrap();
        }
    }

    // A node of the right length holding the wrong bytes, which is what a
    // level whose length landed before its bytes did leaves behind.
    let torn = directory.join(format!("{HEADER_TREE}.2"));
    put(&torn, 3 * 32, &[0xff; 32]);

    let mut tree = HeaderTree::open(&directory).unwrap();
    let before = refused(&tree, 16);
    assert_eq!(
        before.len(),
        8,
        "the torn node was meant to refuse the leaves beneath it and beside it: {before:?}"
    );

    let (height, start) = match tree.prove_in(12, 16) {
        Err(StoreError::Unfolded { height, start }) => (height, start),
        other => panic!("expected a node that would not fold, got {other:?}"),
    };
    tree.mend_below(height, start).unwrap();

    let after = refused(&tree, 16);
    assert!(
        after.is_empty(),
        "mending from the leaves left {} leaves still refused: {after:?}",
        after.len()
    );

    // And again after a restart, because what was mended was written down.
    drop(tree);
    let tree = HeaderTree::open(&directory).unwrap();
    let later = refused(&tree, 16);
    assert!(
        later.is_empty(),
        "the mend did not survive a restart: {later:?}"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

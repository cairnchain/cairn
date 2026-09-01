//! What the header forest is left holding when a write is interrupted.
//!
//! Level zero is the record of what the forest holds, and every level above it
//! is a function of that one. So the only thing an open has to get right is
//! putting the upper levels back into agreement with level zero, and there are
//! two ways for them to disagree: reaching too far, or falling short.
//!
//! Falling short is the dangerous one, and it used to be the silent one.
//! `set_len` extends a short file with zero bytes just as readily as it cuts a
//! long one back, so an upper level that a crash had left short came back full
//! of zeros, the leaf count came back right, every leaf read back right, and
//! the only self-heal a node has compares leaf counts. The forest then served
//! proofs with a zero where a node hash belongs, which fold to the wrong root,
//! so every newcomer handed one rejected it. Nothing reported the damage and a
//! restart did not clear it.
//!
//! These tests pin both directions, the half-written node in between, and the
//! bound: an open works out what is missing and nothing else.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cairn_accumulator::forest::node_hash;
use cairn_accumulator::Archive;
use cairn_primitives::Hash32;
use cairn_store::{HeaderTree, HEADER_TREE};

const NODE_BYTES: u64 = 32;

fn leaf(n: u64) -> Hash32 {
    Hash32::from_bytes([u8::try_from(n % 251).unwrap() + 1; 32])
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-htree-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// A forest of `leaves` of them, built the ordinary way and closed.
fn built(directory: &Path, leaves: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = HeaderTree::open(directory)?;
    for index in 0..leaves {
        tree.append(leaf(index))?;
    }
    Ok(())
}

/// The same forest in memory, which is what the disk one has to match.
fn memory(leaves: u64) -> Archive {
    let mut archive = Archive::new();
    for index in 0..leaves {
        archive.add(leaf(index));
    }
    archive
}

/// Recomputes the root a proof folds to, the way a verifier would.
fn fold(leaf: Hash32, mut index: u64, siblings: &[Hash32]) -> Hash32 {
    let mut current = leaf;
    for sibling in siblings {
        current = if index & 1 == 0 {
            node_hash(current, *sibling)
        } else {
            node_hash(*sibling, current)
        };
        index >>= 1;
    }
    current
}

/// Every leaf and every proof, against the forest kept in memory.
///
/// Every proof rather than a sample, because the node a torn append leaves
/// missing is one node of one level, and a sample is how it stays missing.
fn agrees_with_memory(disk: &HeaderTree, archive: &Archive) {
    assert_eq!(disk.len(), archive.len(), "leaf counts differ");
    for at in 0..disk.len() {
        assert_eq!(
            disk.leaf_at(at).unwrap(),
            Some(leaf(at)),
            "leaf {at} reads back wrong"
        );
    }
    let zero = Hash32::from_bytes([0; 32]);
    for leaves in 1..=disk.len() {
        for at in 0..leaves {
            let held = disk.prove_in(at, leaves).unwrap();
            assert_eq!(
                held.as_ref().map(|proof| &proof.siblings),
                archive.prove_in(at, leaves).as_ref().map(|p| &p.siblings),
                "the proof for {at} of {leaves} is not the one the forest owes"
            );
            for sibling in held.into_iter().flat_map(|proof| proof.siblings) {
                assert_ne!(sibling, zero, "a zero stands where a node hash belongs");
            }
        }
    }
}

fn level(directory: &Path, height: usize) -> PathBuf {
    directory.join(format!("{HEADER_TREE}.{height}"))
}

fn cut_to(path: &Path, bytes: u64) {
    OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(bytes)
        .unwrap();
}

fn put(path: &Path, at: u64, value: &[u8]) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(value).unwrap();
    file.flush().unwrap();
}

/// The tear that used to be silent: a leaf on disk whose parents never
/// followed it down.
///
/// `append` no longer publishes the leaf first, so this is not the state it
/// leaves any more. It is still the state a power cut can leave, because a
/// flush is not a sync and the levels reach the platter in whatever order the
/// kernel chose.
#[test]
fn an_append_torn_after_its_leaf_is_worked_out_again() {
    let directory = scratch("after-leaf");
    built(&directory, 3).unwrap();
    put(&level(&directory, 0), 3 * NODE_BYTES, leaf(3).as_bytes());

    let mut tree = HeaderTree::open(&directory).unwrap();
    agrees_with_memory(&tree, &memory(4));

    // The consequence spelled out, since it is the whole reason this matters:
    // the proof a newcomer is handed folds to the root the header commits to.
    let archive = memory(4);
    let proof = tree.prove_in(0, 4).unwrap().unwrap();
    assert_eq!(
        fold(leaf(0), 0, &proof.siblings),
        fold(leaf(0), 0, &archive.prove_in(0, 4).unwrap().siblings),
        "the mended proof folds to the wrong root"
    );

    // And the forest is usable afterwards, not merely readable: what is built
    // on top of a mended level has to be right too.
    for index in 4..9 {
        tree.append(leaf(index)).unwrap();
    }
    agrees_with_memory(&tree, &memory(9));

    let _ = std::fs::remove_dir_all(&directory);
}

/// The tear `append` leaves now: interior nodes on disk ahead of the leaf that
/// completes them.
///
/// Nothing has to be worked out here. The leaf count says those nodes stand
/// for leaves the forest does not have, so they are cut, and what is left is
/// the forest as it stood one append earlier.
#[test]
fn an_append_torn_before_its_leaf_is_cut_back() {
    let directory = scratch("before-leaf");
    built(&directory, 4).unwrap();
    cut_to(&level(&directory, 0), 3 * NODE_BYTES);

    let mut tree = HeaderTree::open(&directory).unwrap();
    agrees_with_memory(&tree, &memory(3));

    // The append that was lost, made again.
    tree.append(leaf(3)).unwrap();
    agrees_with_memory(&tree, &memory(4));

    let _ = std::fs::remove_dir_all(&directory);
}

/// Both kinds of damage in one forest, since a crash does not pick one.
///
/// A whole level gone as well, which is the far end of falling short: nothing
/// says the damage is one node, only that what is worked out again is what is
/// actually missing.
#[test]
fn a_level_reaching_too_far_under_one_falling_short() {
    let directory = scratch("both-ways");
    built(&directory, 8).unwrap();
    put(
        &level(&directory, 1),
        4 * NODE_BYTES,
        Hash32::from_bytes([0xab; 32]).as_bytes(),
    );
    std::fs::remove_file(level(&directory, 2)).unwrap();

    let tree = HeaderTree::open(&directory).unwrap();
    agrees_with_memory(&tree, &memory(8));

    let _ = std::fs::remove_dir_all(&directory);
}

/// A level that stops in the middle of a node.
///
/// Thirty two bytes or it is not a node, so the remainder is dropped before
/// anything is counted and the node is worked out again. Level zero gets the
/// same treatment, and there the dropped bytes cost one leaf.
#[test]
fn bytes_that_do_not_make_a_whole_node_are_not_one() {
    let directory = scratch("half-node");
    built(&directory, 4).unwrap();
    cut_to(&level(&directory, 1), NODE_BYTES + 17);
    let tree = HeaderTree::open(&directory).unwrap();
    agrees_with_memory(&tree, &memory(4));
    drop(tree);

    let leaves = scratch("half-leaf");
    built(&leaves, 4).unwrap();
    cut_to(&level(&leaves, 0), 3 * NODE_BYTES + 9);
    let tree = HeaderTree::open(&leaves).unwrap();
    agrees_with_memory(&tree, &memory(3));

    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&leaves);
}

/// The bound on the mending: what is there is left alone.
///
/// Only the nodes a level is short of are worked out again, so an ordinary
/// open costs nothing and a torn append costs a handful of hashes. The price
/// is that this repairs levels that cannot account for their own length, and
/// not a node that was written whole and later went bad on the disk. Checking
/// for that would mean rehashing the entire history at every start, which is
/// the cost this forest exists to avoid; it is caught instead by the proofs
/// failing against a root, where any other bad byte is caught.
#[test]
fn mending_leaves_alone_what_is_not_missing() {
    let directory = scratch("bounded");
    built(&directory, 4).unwrap();
    let marker = Hash32::from_bytes([0xcd; 32]);
    put(&level(&directory, 1), NODE_BYTES, marker.as_bytes());

    let tree = HeaderTree::open(&directory).unwrap();
    assert_eq!(tree.len(), 4);
    assert_eq!(
        tree.prove_in(0, 4).unwrap().unwrap().siblings[1],
        marker,
        "an open recomputed a node that was not missing"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

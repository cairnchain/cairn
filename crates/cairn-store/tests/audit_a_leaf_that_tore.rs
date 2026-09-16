//! What a repair does when the thing it repairs from is the damaged one.
//!
//! `mend_below` rebuilds the nodes over a subtree from the leaves beneath it,
//! and the reason written beside it was that "only the leaves are not derived
//! from anything, so only they settle it". That is true, and it answers which
//! of the nodes above to trust. It does not answer what happens when the leaf
//! is the one that tore.
//!
//! A leaf is a file on the same disk as every other level, written last by
//! `append`, so it is the likeliest of them to be in flight at a power cut.
//! Folded upward on trust, one torn leaf is written into every node over it.
//! The node written over it is then wrong too, so the next proof gets past the
//! level just mended and refuses one above it, over twice as many leaves: the
//! refusals double per pass instead of going away. After a few the forest
//! agrees with itself, `Unfolded` stops being raised, the disagreement that
//! was the only evidence is gone, and the node serves every asker a root
//! nobody else has, for positions nobody touched, across restarts.
//!
//! That is the outcome `prove_in` refuses to cause, reached through the repair
//! written to avoid it. So the leaves are not trusted either: what each one
//! should be is asked of the header log, which is the one thing in a node that
//! the forest is not derived from.

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

const LEAVES: u64 = 16;

/// The leaf that is damaged. Not the last, so there are nodes above it on both
/// sides and a sibling subtree that was never touched.
const TORN: u64 = 5;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-torn-leaf-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn leaf(n: u64) -> Hash32 {
    Hash32::from_bytes([u8::try_from(n % 251).unwrap() + 1; 32])
}

/// A forest of `LEAVES` leaves, and the directory it sits in.
fn grown(name: &str) -> (HeaderTree, PathBuf) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let mut tree = HeaderTree::open(&directory).unwrap();
    for position in 0..LEAVES {
        tree.append(leaf(position)).unwrap();
    }
    (tree, directory)
}

fn put(path: &Path, at: u64, value: &[u8]) {
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(value).unwrap();
}

/// Positions whose proof against `LEAVES` is refused.
fn refused(tree: &HeaderTree) -> Vec<u64> {
    (0..LEAVES)
        .filter(|at| tree.prove_in(*at, LEAVES).is_err())
        .collect()
}

/// Every proof this forest gives, so two forests can be compared on all of it
/// rather than on whether each is internally consistent, which is exactly the
/// thing a laundered forest is.
fn all_proofs(tree: &HeaderTree) -> Vec<Option<Vec<Hash32>>> {
    (0..LEAVES)
        .map(|at| {
            tree.prove_in(at, LEAVES)
                .ok()
                .flatten()
                .map(|proof| proof.siblings)
        })
        .collect()
}

/// The truth about a leaf, as the header log would answer it.
fn honestly(position: u64) -> Result<Option<Hash32>, StoreError> {
    Ok(Some(leaf(position)))
}

/// A mend that is handed the truth puts the forest back, and puts it back to
/// the one everybody else has.
#[test]
fn a_torn_leaf_is_put_back_rather_than_folded_upward() {
    let (honest, honest_directory) = grown("honest");
    let wanted = all_proofs(&honest);

    let (mut tree, directory) = grown("torn");
    drop(tree);
    // One bit, in the leaf itself, on the level `append` writes last.
    let leaves_file = directory.join(format!("{HEADER_TREE}.0"));
    let mut bytes = leaf(TORN).to_bytes();
    bytes[0] ^= 1;
    put(&leaves_file, TORN * 32, &bytes);
    tree = HeaderTree::open(&directory).unwrap();

    let before = refused(&tree);
    assert!(
        !before.is_empty(),
        "this test needs a forest that refuses something, and it refuses nothing"
    );

    // One pass of what the node does: take the level and start it was refused
    // at, and mend beneath them.
    let Err(StoreError::Unfolded { height, start }) = tree.prove_in(before[0], LEAVES) else {
        panic!("the refusal is meant to name the node that would not fold");
    };
    tree.mend_below(height, start, &honestly).unwrap();

    assert_eq!(
        refused(&tree),
        Vec::<u64>::new(),
        "one mend has to leave the forest whole. A mend that writes the leaf it found \
         puts a wrong node over it, and the next proof gets past the level just mended \
         and refuses one above it, over twice as many leaves"
    );
    assert_eq!(
        tree.leaf_at(TORN).unwrap(),
        Some(leaf(TORN)),
        "the leaf itself was left as it was found"
    );
    assert_eq!(
        all_proofs(&tree),
        wanted,
        "this forest now agrees with itself and does not agree with anybody else. Every \
         proof it gives folds to a root nobody has, including for positions nothing \
         touched, and the disagreement that was the only evidence of the damage is gone"
    );

    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&honest_directory);
    drop(honest);
}

/// A leaf nothing can vouch for stops the repair rather than being built upon.
#[test]
fn a_leaf_nothing_can_vouch_for_is_not_written_over() {
    let (mut tree, directory) = grown("unvouched");
    drop(tree);
    let leaves_file = directory.join(format!("{HEADER_TREE}.0"));
    let mut bytes = leaf(TORN).to_bytes();
    bytes[0] ^= 1;
    put(&leaves_file, TORN * 32, &bytes);
    tree = HeaderTree::open(&directory).unwrap();

    let before = refused(&tree);
    let Err(StoreError::Unfolded { height, start }) = tree.prove_in(before[0], LEAVES) else {
        panic!("the refusal is meant to name the node that would not fold");
    };

    let nothing = |_: u64| -> Result<Option<Hash32>, StoreError> { Ok(None) };
    assert!(
        tree.mend_below(height, start, &nothing).is_err(),
        "a forest whose leaves nothing can answer for is one this cannot repair, and \
         folding what is there upward is how a torn leaf becomes a root nobody has"
    );
    assert_eq!(
        refused(&tree),
        before,
        "and it is left exactly as refused as it was, which is the state that still \
         says something is wrong"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

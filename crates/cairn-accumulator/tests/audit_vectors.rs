//! Known answer vectors for the accumulator and the cold set forest.
//!
//! `cairn-primitives` pins its domain constants so that renaming a context
//! string fails a test rather than forking the network. Nothing pinned what
//! this crate builds out of them, and the gap is wider than it sounds: the
//! domain decides half of a digest and the bytes fed in under it decide the
//! other half. Eight changes to that second half passed the whole suite before
//! this file existed.
//!
//! - A leaf that hashes its value before its key.
//! - An accumulator node that hashes its right child before its left.
//! - The empty subtree taken under another domain.
//! - A forest node that hashes its right child before its left.
//! - A cold set commitment that hashes its live count before its leaf count.
//! - One that leaves the live count out altogether.
//! - One that leaves out the height each root sits at.
//! - That commitment taken under another domain.
//!
//! Every one of them moves every root and every commitment on the network, and
//! every one leaves both halves of the code agreeing with themselves, which is
//! why the tests that fold a proof back up to a root cannot see it: they
//! recompute with the same function they are checking. Only a number written
//! down beforehand can.
//!
//! If a vector here fails, the change that caused it is a hard fork and has to
//! be treated as one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use cairn_accumulator::forest::{empty_leaf, forest_leaf, node_hash, Forest};
use cairn_accumulator::key::KEY_LEN;
use cairn_accumulator::tree::empty_hash;
use cairn_accumulator::{Archive, Key, Proof, SparseMerkleTree};
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::hex;
use cairn_primitives::merkle::merkle_root;
use cairn_primitives::Hash32;

const PROBE: &[u8] = b"cairn audit vector";

/// Keys written out rather than derived, so these vectors say something about
/// the accumulator alone and not about whatever hashes a caller keys with.
///
/// The first two differ in their last bit and nothing else, which is the
/// deepest split the tree can be made to take: two hundred and fifty-six
/// levels. The rest part company earlier, one of them at bit eight and two at
/// bit zero, so the tree is not one long chain.
const KEYS: [&str; 5] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0080000000000000000000000000000000000000000000000000000000000000",
    "8000000000000000000000000000000000000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

/// A key none of the above leads to: its first bit is zero and its second is
/// one, so it walks off the tree rather than onto an occupied leaf.
const ABSENT: &str = "4000000000000000000000000000000000000000000000000000000000000000";

/// The root over the first however many of [`KEYS`], each entry carrying the
/// value [`value`] gives for its place in the list. The first row is the tree
/// holding nothing.
const TREE_ROOTS: [&str; 6] = [
    "655b9b83d72feef78915fb4e8ecb0848bfd823206ef920479bc26c43bed64655",
    "2717783b13206ca59115cdc00b8e4ff4e3a81e91f1a3e7735edaa63442362de9",
    "409704121cada1a90fdd18b48dd69233545f290703724321cb38b4ea893f3a92",
    "ad28c7fe4090b39894d301ae88352a699b32da8649e256d963571a24bdf96a0b",
    "5e2f909f926a9ad83ccc060faf27dbbe9f2d034e2f49e8813200625851d80be9",
    "1ae9d1b9185f5311035fcf569b0ae877c8c840c279da7a18ddde29831bfa5e30",
];

/// The cold set commitment after that many leaves have been appended and none
/// removed.
const COMMITMENTS: [&str; 9] = [
    "2b8a7f4949a18c612a530d7dc3aa53b75b7fa4163daff6c2742422bdae5a12e2",
    "3ce33e56a6a2f5a3cf21d112b418c453146ead5b4ef27f8f8c06ab2432068974",
    "eb43cd3321491a8b8c88fca72f11cc41eb62fc3d85612ae18391155f1426b173",
    "0e989f44a6996fc770e99381b7e8b2b66704692bc7a045d2c590b8a6965c9958",
    "ef8738dccd80d1513a7c361bf7ebcaeea015c2963341a079545f82fbc699334d",
    "a97551e27f207e34b3c2e7bf77df9ec7330ae3f5adae09406dc4fc3d18f0d53f",
    "977722c7dfef6f930667015924551be4062cd0e6085379319f11abd00886f111",
    "cef55d317ef57d6361caad8b96930c730009a0dfc77a7275554ed39f61bc9fd0",
    "81c49d22d4239391ccf84874e5192122f4a9817759f4c75d14e4233ad3c3ee07",
];

fn key(text: &str) -> Key {
    Key::from_bytes(hex::decode_array::<KEY_LEN>(text).expect("a key in hexadecimal"))
}

/// The value the entry at `index` carries, written from the index so the
/// tables below can be read next to the keys.
fn value(index: usize) -> Hash32 {
    Hash32::from_bytes([u8::try_from(index).unwrap_or(0).saturating_add(1); 32])
}

fn leaf(index: u64) -> Hash32 {
    forest_leaf(&index.to_le_bytes())
}

/// The tree holding the first `count` keys.
fn tree_of(count: usize) -> SparseMerkleTree {
    let mut tree = SparseMerkleTree::new();
    for (index, text) in KEYS.iter().enumerate().take(count) {
        tree.insert(key(text), value(index));
    }
    tree
}

#[test]
fn the_empty_subtree_is_still_what_it_was() {
    assert_eq!(
        empty_hash().to_string(),
        "655b9b83d72feef78915fb4e8ecb0848bfd823206ef920479bc26c43bed64655",
        "the accumulator's empty subtree changed: this is a hard fork"
    );
    // It is taken under its own domain, so nothing else in the workspace that
    // means "nothing here" can be presented as it.
    assert_ne!(empty_hash(), merkle_root(&[]));
    assert_ne!(empty_hash(), empty_leaf());
    assert_ne!(empty_hash(), Hash32::ZERO);
}

#[test]
fn a_tree_still_commits_the_way_it_did() {
    for (count, expected) in TREE_ROOTS.into_iter().enumerate() {
        assert_eq!(
            tree_of(count).root().to_string(),
            expected,
            "the root over {count} entries changed: this is a hard fork"
        );
    }
    // The first two rows are the empty subtree and one leaf standing alone,
    // which is a property rather than an accident: a tree of one entry is
    // that entry's leaf digest, so its proof carries no siblings at all.
    assert_eq!(tree_of(0).root(), empty_hash());
    let lone = tree_of(1);
    let path = lone.prove(key(KEYS[0]));
    assert_eq!(path.depth(), 0, "one entry sits at the root");
    assert!(path.verify_membership(lone.root(), key(KEYS[0]), value(0)));
}

#[test]
fn a_proof_still_folds_to_the_root_it_did() {
    let tree = tree_of(KEYS.len());
    let root = tree.root();

    // The two keys that differ in their last bit sit at the bottom of the
    // tree, so this pins the depth as well as the fold.
    let membership = tree.prove(key(KEYS[0]));
    assert_eq!(
        membership.depth(),
        256,
        "two keys differing in one bit no longer split at the last level"
    );
    assert!(membership.verify_membership(root, key(KEYS[0]), value(0)));
    assert_eq!(
        membership.size_in_bytes(),
        membership.encode().len(),
        "what a proof says it costs is not what the wire writes"
    );
    assert_eq!(Proof::decode(&membership.encode()).unwrap(), membership);

    // The absence proof is short enough to write down whole, which pins the
    // occupant tag and where it sits as well as the siblings.
    let absence = tree.prove(key(ABSENT));
    assert_eq!(absence.depth(), 2);
    assert_eq!(
        hex::encode(&absence.encode()),
        "02000000\
         207318bb1ef01c790f85ce1b235cd429ac544f84fab5ce610fed8fcca6f6affd\
         8a7b56813b701718a3cd38d131b0478971652a99c5f1f5b24701afa13f2f9c94\
         00",
        "an absence proof no longer travels the way it did"
    );
    assert!(absence.verify_absence(root, key(ABSENT)));
    assert!(!absence.verify_membership(root, key(ABSENT), value(0)));
}

#[test]
fn the_forest_still_hashes_the_way_it_did() {
    assert_eq!(
        forest_leaf(PROBE).to_string(),
        "574e819120f4ff9e742eaba13c749681b6cc0b6e1e31a464fe50d050cf817be1",
        "a cold set leaf changed: this is a hard fork"
    );
    assert_eq!(
        empty_leaf().to_string(),
        "c48b63c1e0c0918d36f51615358173206ae3f04c20ad3a958438cce4f7d09aa3",
        "the sentinel an emptied place holds changed: this is a hard fork"
    );
    assert_eq!(
        empty_leaf(),
        forest_leaf(&[]),
        "the sentinel is nothing hashed"
    );

    // Both orders, because a node that swapped its children would otherwise
    // only have to agree with itself.
    assert_eq!(
        node_hash(empty_leaf(), forest_leaf(PROBE)).to_string(),
        "d71b99128dfd63e9ba34c02a98a3f805143a9f1acb93f6dd3d2c75c05e72fefb"
    );
    assert_eq!(
        node_hash(forest_leaf(PROBE), empty_leaf()).to_string(),
        "29c52cf192e272ebbc256240284387d9a2308d878e42274f38579c0666a8f32d"
    );
}

#[test]
fn a_cold_set_commitment_is_still_what_it_was() {
    let mut forest = Forest::new();
    for (count, expected) in COMMITMENTS.into_iter().enumerate() {
        assert_eq!(
            forest.commitment().to_string(),
            expected,
            "the commitment over {count} leaves changed: this is a hard fork"
        );
        forest.add(leaf(count as u64)).unwrap();
    }

    // And one where the leaf count and the live count differ, which is the
    // only shape that says the two are hashed in the order they are: while
    // nothing has been removed they are the same number, and swapping them
    // changes nothing at all.
    let mut archive = Archive::new();
    for index in 0..5u64 {
        archive.add(leaf(index)).unwrap();
    }
    assert!(archive.remove(1));
    assert_eq!(archive.forest().leaves(), 5);
    assert_eq!(archive.forest().len(), 4);
    assert_eq!(
        archive.commitment().to_string(),
        "2d586bb3e325c55a98cf14162aedd262c5fc71dc0146b25412f2ea2d21806a9e",
        "the commitment over five places with four standing changed"
    );
}

#[test]
fn a_forest_and_its_paths_still_travel_the_way_they_did() {
    let mut archive = Archive::new();
    for index in 0..5u64 {
        archive.add(leaf(index)).unwrap();
    }

    // Five leaves are a tree of four and a tree of one, so this pins the
    // layout as well as the bytes. A line each: the leaf count, the live
    // count, how many roots follow, then a height and its root, smaller
    // height first.
    assert_eq!(
        hex::encode(&archive.forest().encode()),
        "0500000000000000\
         0500000000000000\
         02000000\
         00fdda3cad626233bccaaad87a211ac307fbecf2702d84b271000b4ff2650aa656\
         027323dd6ba35a37c865803a05eeccd52b7bc39c4d87eded457651ee4543d80bbc",
        "a forest no longer travels the way it did"
    );
    assert_eq!(
        Forest::decode(&archive.forest().encode()).unwrap(),
        archive.forest().roots_only(),
        "and what comes back is the forest that was written"
    );

    let deep = archive.prove(0).unwrap();
    assert_eq!(deep.depth(), 2);
    assert_eq!(
        hex::encode(&deep.encode()),
        "02000000\
         6d57fc6e893374a8005a29233a406d853c8b705dcd3147f5f74b5a50477ddde9\
         7b6e6885e730501bc54bce0bb4654769ddc2e29dc729e6128c288b3afcfcd1ea",
        "a path through the cold set no longer travels the way it did"
    );
    assert!(archive.forest().verify(0, leaf(0), &deep));

    // The lone leaf sits in a tree of one and its path is empty, which is the
    // shortest a proof gets and the one a length check has to let through.
    let lone = archive.prove(4).unwrap();
    assert_eq!(lone.depth(), 0);
    assert_eq!(hex::encode(&lone.encode()), "00000000");
    assert!(archive.forest().verify(4, leaf(4), &lone));
}

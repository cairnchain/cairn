//! What finding a leaf costs, and what keeping that cheap costs in exchange.
//!
//! `Archive::locate` is the question a wallet that lost its record asks an
//! archivist, and its own note says that is the reason an archivist is worth
//! paying. It answered by walking every leaf the archive has ever held, so the
//! cost of asking grew with the chain — the one thing this project says a
//! node's cost never does.
//!
//! It is not only a wallet that asks. The explorer asks it once for every note
//! on an address page and reads each page twice, with the node's chain lock
//! held throughout: two hundred passes over the whole archive for one
//! anonymous request, measured at thirteen milliseconds over eighty thousand
//! notes and rising in a straight line. Block validation waits behind that.
//!
//! Kept beside the leaves rather than derived from them, a position is a thing
//! that can be wrong, and that is what these hold. Nothing here times
//! anything: what a walk costs is arithmetic anybody can read off the code,
//! and what a kept index can do is disagree with what it stands for.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::forest::empty_leaf;
use cairn_accumulator::Archive;
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Hash32;

fn leaf(n: u64) -> Hash32 {
    hash(Domain::ForestLeaf, &n.to_le_bytes())
}

/// Every place the archive has handed out, emptied ones included, which is
/// what `locate` used to walk. `Archive::len` is the leaves still standing and
/// is a different number.
fn places(archive: &Archive) -> u64 {
    archive.forest().leaves()
}

/// What `locate` would answer if it still walked the leaves.
fn by_walking(archive: &Archive, wanted: Hash32) -> Option<u64> {
    (0..places(archive)).find(|at| archive.leaf_at(*at) == Some(wanted))
}

/// Every leaf the archive holds, asked for both ways.
#[track_caller]
fn agrees(archive: &Archive, after: &str) {
    for at in 0..places(archive) {
        let held = archive.leaf_at(at).expect("a position the archive holds");
        if held == empty_leaf() {
            assert_eq!(
                archive.locate(held),
                None,
                "after {after}: an emptied place was offered as somewhere to find a leaf. \
                 Every one of them holds the same hash, so naming one of them is naming \
                 all of them"
            );
            continue;
        }
        assert_eq!(
            archive.locate(held),
            by_walking(archive, held),
            "after {after}: the index beside the leaves disagrees with the leaves about \
             where the one at {at} is. A wallet that lost its record is told the wrong \
             place, or told there is none"
        );
    }
}

/// A leaf nobody put there is nowhere, which a walk answers by finding nothing.
#[track_caller]
fn finds_nothing_that_is_not_there(archive: &Archive, after: &str) {
    for n in 9_000..9_016u64 {
        assert_eq!(
            archive.locate(leaf(n)),
            None,
            "after {after}: a leaf this archive never held was given a place"
        );
    }
}

/// Every way an archive moves, and finding a leaf still says what the leaves
/// say.
#[test]
fn the_index_says_what_the_leaves_say_after_every_move() {
    let mut archive = Archive::new();
    agrees(&archive, "an archive with nothing in it");
    finds_nothing_that_is_not_there(&archive, "an archive with nothing in it");

    for n in 0..32u64 {
        archive.add(leaf(n)).expect("room for a leaf");
    }
    agrees(&archive, "thirty two leaves were added");
    finds_nothing_that_is_not_there(&archive, "thirty two leaves were added");
    assert_eq!(
        archive.locate(leaf(5)),
        Some(5),
        "and each is where it went"
    );

    // Emptied: the place stays and stops being anywhere to find anything.
    assert!(archive.remove(5), "the place is emptied");
    assert_eq!(
        archive.locate(leaf(5)),
        None,
        "a leaf that was taken out is not still standing somewhere"
    );
    assert_eq!(
        places(&archive),
        32,
        "and the place it held is still one the archive handed out"
    );
    assert_eq!(archive.len(), 31, "with one fewer leaf standing in it");
    agrees(&archive, "one place was emptied");

    // Dropped from the end, which is what undoing a block does.
    let before_the_last = archive.forest().clone();
    archive.add(leaf(100)).expect("room for one more");
    assert_eq!(archive.locate(leaf(100)), Some(32));
    assert!(archive.remove_last(), "the last leaf is dropped");
    assert_eq!(
        archive.locate(leaf(100)),
        None,
        "a leaf that was dropped is not still standing"
    );
    agrees(&archive, "the last leaf was dropped");
    let _ = before_the_last;

    // Rewound: leaves appended since are dropped and emptied places are put
    // back, which is what a reorganisation asks for.
    let before = archive.forest().clone();
    for n in 200..208u64 {
        archive.add(leaf(n)).expect("room for a leaf");
    }
    assert_eq!(archive.locate(leaf(203)), Some(35));
    archive.rewind(&before, 8, &[(5, leaf(5))]);

    assert_eq!(places(&archive), 32, "the appended leaves are gone");
    for n in 200..208u64 {
        assert_eq!(
            archive.locate(leaf(n)),
            None,
            "a leaf the rewind dropped is not still standing at {n}"
        );
    }
    assert_eq!(
        archive.locate(leaf(5)),
        Some(5),
        "and the place the rewind put back is somewhere to find its leaf again"
    );
    agrees(&archive, "a rewind dropped eight leaves and put one back");
    finds_nothing_that_is_not_there(&archive, "a rewind");
}

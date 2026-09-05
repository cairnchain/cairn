//! What keeping the whole cold set costs, per note that has ever fallen.
//!
//! This is the one cost in the design that grows without bound, and it is
//! nobody's but an archivist's. Two figures for it were published at once: the
//! explorer served 72 bytes a note, read off a resident set as a slope over
//! three million fallen notes, and the whitepaper said "about 64 bytes",
//! re-read structurally. Nothing said which was the quantity and which was the
//! reading of it, so a reader could take either as the other's correction.
//!
//! They are both right and they are not the same number. What an archive holds
//! is exactly 64 bytes a note and does not vary: the leaf, and the one inner
//! node that leaf completes. What a process holding it occupies is more,
//! because the vectors those hashes live in grow by doubling, so between two
//! doublings a vector carries up to its own length again in capacity nobody is
//! using. The occupancy therefore swings between 64 and about 90 bytes a note
//! as the set grows, and a slope taken at a handful of points lands wherever
//! those points fell on that swing.
//!
//! The content is what the papers should publish, because it is a property of
//! the design rather than of a `Vec`'s growth policy, and it is what
//! `cairn-chain/examples/archivist.rs` already counts with.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use cairn_accumulator::forest::forest_leaf;
use cairn_accumulator::Archive;

/// Bytes an archivist holds for every note that has ever fallen.
///
/// The figure `cairn-chain/examples/archivist.rs` counts with, and the one the
/// whitepaper publishes.
const ARCHIVED_BYTES: u64 = 64;

/// Hashes the archive holds for `leaves` leaves: one each, plus the inner
/// nodes that are complete.
///
/// A node of height `h` is complete once its whole span has arrived, so there
/// are `leaves >> h` of them, and summing over the heights gives one inner
/// node per leaf less one per tree the forest currently holds.
fn hashes_held(leaves: u64) -> u64 {
    let mut inner = 0u64;
    let mut span = 2u64;
    while span <= leaves {
        inner += leaves / span;
        span *= 2;
    }
    leaves + inner
}

/// The structural count is the one the papers publish, and it is 64 bytes.
///
/// Checked against an archive that was actually built, so the arithmetic
/// cannot drift from what `Archive::add` does.
#[test]
fn an_archivist_holds_sixty_four_bytes_for_every_note_that_ever_fell() {
    let mut archive = Archive::new();
    let count = 1u64 << 16;
    for index in 0..count {
        archive.add(forest_leaf(&index.to_le_bytes()));
    }
    assert_eq!(archive.len(), count, "nothing was removed");

    // A power of two is one tree, so there is exactly one inner node per leaf
    // less the one root that no leaf completed.
    assert_eq!(hashes_held(count), count * 2 - 1);
    // Sixty-four less the roots no leaf completed, which is at most sixty-four
    // hashes over the whole set and so vanishes into the per-note figure.
    let per_note = hashes_held(count) as f64 * 32.0 / count as f64;
    assert!(
        (per_note - ARCHIVED_BYTES as f64).abs() < 0.01,
        "an archivist holds {per_note} bytes a note, not {ARCHIVED_BYTES}"
    );

    // And it does not drift with the size, which is the whole reason it can be
    // published as one number: the count of trees is what varies, and it is at
    // most sixty-four whatever the set holds.
    for leaves in [1_000u64, 100_000, 1_000_000, 3_000_000] {
        let held = hashes_held(leaves) * 32;
        let each = held as f64 / leaves as f64;
        assert!(
            (63.0..=64.0).contains(&each),
            "{leaves} leaves come to {each} bytes each"
        );
    }
}

/// And why a resident reading of the same archive says something larger.
///
/// The hashes live in vectors that grow by doubling, so a vector holding `n`
/// items has asked for the next power of two above it. Right after a doubling
/// half of what it asked for is empty, and the occupancy per note is nearly
/// twice the content. This is the swing a five-point slope was read off, and
/// it is why the reading and the content disagree without either being wrong.
#[test]
fn a_resident_reading_of_it_swings_between_the_content_and_twice_it() {
    let asked_for = |items: u64| items.max(1).next_power_of_two();
    let occupied = |leaves: u64| {
        let mut total = asked_for(leaves);
        let mut span = 2u64;
        while span <= leaves {
            total += asked_for(leaves / span);
            span *= 2;
        }
        total * 32
    };

    // Just past a doubling, the vectors are as empty as they ever get.
    let worst = occupied(3_000_000) as f64 / 3_000_000.0;
    assert!(
        (85.0..=95.0).contains(&worst),
        "three million notes occupy {worst} bytes each"
    );

    // On a power of two they are exactly full, and the reading is the content.
    let best = occupied(1 << 22) as f64 / f64::from(1u32 << 22);
    assert!(
        (63.0..=65.0).contains(&best),
        "four million notes occupy {best} bytes each"
    );

    // The published 72 sits inside that swing, which is what it is: a reading
    // taken somewhere on it, not a second opinion about the content.
    assert!(best < 72.0 && 72.0 < worst);
}

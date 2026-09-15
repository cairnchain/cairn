//! Probes from an audit of this crate: each one holds a claim that a test
//! already named for it turned out not to hold.
//!
//! Every probe here was checked the only way a test can be: the code it is
//! about was changed, and the probe failed while the test previously named
//! for the same property went on passing. The mutation each one was checked
//! against is written above it, so the check can be repeated.
//!
//! Nothing here measures a clock or a memory reading. A counting allocator
//! would be the direct way to hold the allocation claim, and it needs
//! `unsafe impl GlobalAlloc`, which this workspace forbids; the probe for it
//! goes through the one thing the crate does control, the capacity a vector
//! is given before its first element is read.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_primitives::codec::{take_at_most, CodecError, Decode, Encode, Reader, MAX_SEQUENCE_LEN};
use cairn_primitives::merkle::{merkle_leaf, merkle_root};

// ---------------------------------------------------------------------------
// The tree.
// ---------------------------------------------------------------------------

/// `merkle::tests::a_leaf_cannot_be_forged_from_an_internal_node` compares a
/// node digest with the leaf digest of a different, shorter preimage. Those
/// differ under one domain as surely as under two, so the test passes with
/// the domain separation removed: checked by hashing `merkle_node` under
/// `Domain::MerkleLeaf`, after which the only test in the crate to fail was
/// the pinned vector, which fails on any change at all.
///
/// The forgery the separation exists to stop is an item whose bytes are two
/// leaf digests side by side. Under one domain its leaf digest *is* the node
/// over those two leaves, and the tree over `[forged, c]` has the root of the
/// tree over `[a, b, c]`: a proof of membership for an item that was never
/// in the list. This holds that, and fails under the mutation above.
///
/// It is not reachable from `cairn-ledger` today, whose leaves are thirty two
/// byte identifiers and so can never be sixty four bytes long. That is a
/// property of the caller, which is what the note on `merkle_root` says, and
/// this is the test that would notice the day it stops being one.
#[test]
fn an_item_made_of_two_leaf_digests_is_not_the_node_over_them() {
    let a = merkle_leaf(b"a");
    let b = merkle_leaf(b"b");
    let c = merkle_leaf(b"c");

    let forged_item = [a.as_bytes().as_slice(), b.as_bytes().as_slice()].concat();
    let forged = merkle_leaf(&forged_item);

    assert_ne!(
        forged,
        merkle_root(&[a, b]),
        "the same sixty four bytes hash the same as a leaf and as a node"
    );
    assert_ne!(
        merkle_root(&[forged, c]),
        merkle_root(&[a, b, c]),
        "an item that was never in the list has the root of the list"
    );
}

// ---------------------------------------------------------------------------
// The reservation.
// ---------------------------------------------------------------------------

/// A type that reads nothing and is not zero sized.
///
/// A sequence of it decodes from its count alone, so the vector that comes
/// back is one whose capacity can be read after a decode driven entirely by
/// the declared count. Nothing on the wire is shaped like this; it exists so
/// the reservation can be observed at all.
#[derive(Debug, PartialEq, Eq)]
struct Nothing(u64);

impl Encode for Nothing {
    fn encode_to(&self, _: &mut Vec<u8>) {}
}

impl Decode for Nothing {
    fn decode_from(_: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(0))
    }
}

/// `audit_canonical::a_declared_length_never_drives_an_allocation` holds its
/// claim with a five second wall clock around two thousand rejections. With
/// the decoder changed to reserve the declared count, `with_capacity(1 << 20)`
/// for `u128` and for `Hash32`, four thousand times, the test finished in
/// under ten milliseconds and passed, as did every other test in the crate:
/// the fuzz property that calls itself the observable form of this claim
/// asserts on `len()`, which the reservation does not change.
///
/// The direct measurement is a counting allocator, and that needs `unsafe`.
/// What the crate controls is the capacity handed to `with_capacity` before
/// the first element is read, and this reads it back. A count past the
/// initial reservation and not a power of two: a vector grown by doubling
/// from a fixed start cannot land on it, and one reserved at the declared
/// count lands on it exactly. So the two implementations answer with two
/// different numbers, and neither is a reading of the machine.
#[test]
fn the_reservation_made_before_the_first_element_is_not_the_declared_count() {
    let declared = 3_000u32;
    let frame = declared.encode();

    let held = Vec::<Nothing>::decode(&frame).unwrap();
    assert_eq!(held.len(), 3_000);
    assert_ne!(
        held.capacity(),
        3_000,
        "the vector was reserved at the declared count before an element was read"
    );

    let mut reader = Reader::new(&frame);
    let held = take_at_most::<Nothing>(&mut reader, 4_096, "probe").unwrap();
    assert_eq!(held.len(), 3_000);
    assert_ne!(
        held.capacity(),
        3_000,
        "take_at_most reserved at the declared count before an element was read"
    );
}

// ---------------------------------------------------------------------------
// The loop bound.
// ---------------------------------------------------------------------------

/// `fuzz_codec::reads_a_settled_prefix` says "an element costs at least one
/// byte, so a sequence cannot outrun the frame it arrived in", and asserts it
/// for thirteen types. That is the whole of what bounds `for _ in
/// 0..declared`. This crate's own `[u8; 0]` costs none, and the assertion was
/// never put to it.
///
/// Four bytes decode to a million elements, and a sequence of sequences of
/// it multiplies: thirty six bytes buy eight million pushes. No type any
/// dependant decodes is zero width, so no message reaches this today; it is
/// held here because the bound rests on a sentence that is true of the
/// types that were checked and false of one the crate ships.
#[test]
fn a_zero_width_element_lets_a_count_outrun_its_frame() {
    let ceiling = u32::try_from(MAX_SEQUENCE_LEN).unwrap();

    let held = Vec::<[u8; 0]>::decode(&ceiling.encode()).unwrap();
    assert_eq!(
        held.len(),
        MAX_SEQUENCE_LEN,
        "four bytes, a million elements"
    );

    let inner = 8u32;
    let mut frame = inner.encode();
    for _ in 0..inner {
        frame.extend_from_slice(&ceiling.encode());
    }
    assert_eq!(frame.len(), 36);
    let held = Vec::<Vec<[u8; 0]>>::decode(&frame).unwrap();
    let pushes: usize = held.iter().map(Vec::len).sum();
    assert_eq!(
        pushes,
        8 * MAX_SEQUENCE_LEN,
        "thirty six bytes, eight million pushes"
    );
}

// ---------------------------------------------------------------------------
// The encoder's own ceiling.
// ---------------------------------------------------------------------------

/// The note on `Vec::encode_to` says the disagreement past the ceiling is
/// "made loud in a debug build", and
/// `audit_canonical::the_ceiling_on_a_sequence_is_where_it_says_it_is` builds
/// its over-long frame by hand "since encoding it is what a debug build now
/// stops on". With the `debug_assert!` deleted, all fifty nine tests passed.
/// This is the one that stops passing.
#[test]
#[should_panic(expected = "past what the decoder will read back")]
fn encoding_a_sequence_past_the_ceiling_stops_a_debug_build() {
    let past: Vec<u8> = vec![0u8; MAX_SEQUENCE_LEN + 1];
    let _ = past.encode();
}

// ---------------------------------------------------------------------------
// The counter.
// ---------------------------------------------------------------------------

/// `counting::hashed` counts what is fed to `update`, and three crates hold
/// cost claims with it. A digest is a compression whether or not anything was
/// fed, so a digest over nothing is work the counter does not see: a thousand
/// of them read as nought. Every use of the counter today survives this,
/// since two compare one count against another and the one that asserts
/// nought is on a path that takes no digest at all. It is written down so
/// the next assertion of the form "hashed nothing" is read as "fed nothing".
///
/// Runs under `--features count-hashing`, which is how the crates that use
/// the counter build this one.
#[cfg(feature = "count-hashing")]
#[test]
fn a_thousand_digests_over_nothing_read_as_no_work_at_all() {
    use cairn_primitives::hash::{counting, hash, Domain, Hash32};

    counting::reset();
    let empty = merkle_root(&[]);
    assert_ne!(empty, Hash32::ZERO, "a digest was taken");
    assert_eq!(counting::hashed(), 0, "and the counter did not see it");

    for _ in 0..1_000 {
        let _ = hash(Domain::SamplingSeed, &[]);
    }
    assert_eq!(
        counting::hashed(),
        0,
        "a thousand digests, and still nought"
    );
}

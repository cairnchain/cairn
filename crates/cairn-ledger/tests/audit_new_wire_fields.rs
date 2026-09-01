//! AUDIT: the two fields that are new on the wire.
//!
//! `SampledStart.parent` and `Handover.buried` are bytes from a stranger. What
//! has to hold: the tag and the count are bounded before anything is reserved,
//! a hostile length is refused rather than turned into an allocation, and an
//! encode-decode round trip is exact in both directions (two byte strings
//! decoding to one value would give a message two identities).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::forest::{Forest, ForestProof};
use cairn_ledger::block::{BlockHeader, BLOCK_VERSION};
use cairn_ledger::handover::{Handover, MOST_BURIED};
use cairn_ledger::note::NetworkId;
use cairn_ledger::sampling::{Sample, SampledStart, SAMPLES};
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Hash32;
use std::time::Instant;

fn header(height: u64) -> BlockHeader {
    BlockHeader {
        version: BLOCK_VERSION,
        network: NetworkId::TESTNET,
        height,
        previous: Hash32::from_bytes([1; 32]),
        transactions_root: Hash32::from_bytes([2; 32]),
        state_root: Hash32::from_bytes([3; 32]),
        history: Hash32::from_bytes([4; 32]),
        timestamp: 1_700_000_000,
        difficulty: 4_096,
        total_work: 1_000_000,
        nonce: 7,
    }
}

fn sample(height: u64) -> Sample {
    Sample {
        header: header(height),
        proof: ForestProof {
            siblings: vec![Hash32::from_bytes([9; 32]); 8],
        },
    }
}

fn start(parent: Option<Sample>, samples: usize) -> SampledStart {
    SampledStart {
        tip: header(500),
        parent,
        tail: (400..=500).map(header).collect(),
        history: Forest::new(),
        samples: (0..samples as u64).map(sample).collect(),
    }
}

#[test]
fn a_sampled_start_round_trips_with_and_without_a_parent() {
    for parent in [None, Some(sample(499))] {
        for count in [0usize, 1, 17] {
            let value = start(parent.clone(), count);
            let bytes = value.encode();
            let back = SampledStart::decode(&bytes).expect("its own encoding");
            assert_eq!(back.encode(), bytes, "the encoding is not canonical");
            assert_eq!(back.parent, value.parent);
            assert_eq!(back.samples, value.samples);
            assert_eq!(back.tip, value.tip);
            assert_eq!(back.tail, value.tail);
        }
    }
}

/// The tag is one byte and only two values mean anything. A third has to be
/// refused rather than read as one of them.
#[test]
fn a_parent_tag_that_is_neither_is_refused() {
    let bytes = start(None, 1).encode();
    // The tag sits after the tip and the history, both fixed for this value.
    let tip_and_history = header(500).encode().len() + Forest::new().encode().len();
    assert_eq!(
        bytes[tip_and_history], 0,
        "the tag is where it was expected"
    );
    for tag in [2u8, 3, 0x80, 0xff] {
        let mut bent = bytes.clone();
        bent[tip_and_history] = tag;
        assert!(
            SampledStart::decode(&bent).is_err(),
            "a parent tag of {tag} was accepted"
        );
    }
}

/// A count nobody could mean is refused, and refused quickly: the point of
/// bounding before reserving is that the refusal costs nothing.
#[test]
fn a_hostile_count_is_refused_without_reserving_for_it() {
    let value = start(Some(sample(499)), 4);
    let bytes = value.encode();
    let tip_and_history = header(500).encode().len() + Forest::new().encode().len();
    let count_at = tip_and_history + 1 + sample(499).encode().len();
    assert_eq!(
        u32::from_le_bytes(bytes[count_at..count_at + 4].try_into().unwrap()),
        4,
        "the sample count is where it was expected"
    );

    for lie in [
        u32::try_from(SAMPLES).unwrap() + 1,
        1 << 20,
        1 << 28,
        u32::MAX,
    ] {
        let mut bent = bytes.clone();
        bent[count_at..count_at + 4].copy_from_slice(&lie.to_le_bytes());
        let started = Instant::now();
        assert!(
            SampledStart::decode(&bent).is_err(),
            "a sample count of {lie} was accepted"
        );
        assert!(
            started.elapsed().as_millis() < 200,
            "refusing a count of {lie} took {:?}",
            started.elapsed()
        );
    }

    // And the largest count that is allowed is still refused here, because the
    // bytes for it are not there: what must not happen is a reservation for it.
    let mut bent = bytes.clone();
    bent[count_at..count_at + 4].copy_from_slice(&u32::try_from(SAMPLES).unwrap().to_le_bytes());
    let started = Instant::now();
    assert!(SampledStart::decode(&bent).is_err());
    assert!(started.elapsed().as_millis() < 200);
}

/// The same for the buried run, whose ceiling is `MOST_BURIED`.
#[test]
fn a_hostile_buried_count_is_refused_without_reserving_for_it() {
    // A handover encoded by hand is long; the run's count is the last field,
    // so appending to a truncated encoding is not needed: the whole value is
    // built and the count bent in place.
    let handover = minimal_handover();
    let bytes = handover.encode();
    let count_at = bytes.len() - 4;
    assert_eq!(
        u32::from_le_bytes(bytes[count_at..].try_into().unwrap()),
        0,
        "an empty run is four zero bytes at the end"
    );
    for lie in [
        u32::try_from(MOST_BURIED).unwrap() + 1,
        1 << 20,
        1 << 30,
        u32::MAX,
    ] {
        let mut bent = bytes.clone();
        bent[count_at..].copy_from_slice(&lie.to_le_bytes());
        let started = Instant::now();
        assert!(
            Handover::decode(&bent).is_err(),
            "a buried count of {lie} was accepted"
        );
        assert!(
            started.elapsed().as_millis() < 200,
            "refusing a count of {lie} took {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn a_handover_round_trips_its_buried_run() {
    for run in [0usize, 1, 5] {
        let mut handover = minimal_handover();
        handover.buried = (0..run as u64).map(|index| header(600 + index)).collect();
        let bytes = handover.encode();
        let back = Handover::decode(&bytes).expect("its own encoding");
        assert_eq!(back.encode(), bytes, "the encoding is not canonical");
        assert_eq!(back.buried, handover.buried);
    }
}

fn minimal_handover() -> Handover {
    Handover {
        at: header(100),
        tip: header(500),
        tip_history: Forest::new(),
        anchor: ForestProof {
            siblings: vec![Hash32::from_bytes([5; 32]); 3],
        },
        hot: Vec::new(),
        cold: Forest::new(),
        grace: Vec::new(),
        grace_proofs: Vec::new(),
        headers: Forest::new(),
        buried: Vec::new(),
        recent: Vec::new(),
    }
}

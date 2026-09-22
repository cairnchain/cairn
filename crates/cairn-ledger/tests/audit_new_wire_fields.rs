//! AUDIT: the fields that are new on the wire.
//!
//! `SampledStart.parent`, `SampledStart.genesis` and `Handover.buried` are
//! bytes from a stranger. What has to hold: the tag and the count are bounded
//! before anything is reserved, a hostile length is refused rather than turned
//! into an allocation, and an
//! encode-decode round trip is exact in both directions (two byte strings
//! decoding to one value would give a message two identities).
//!
//! **How the middle one is held, and how it used to be.** A count refused
//! before anything is reserved and a count refused after four billion
//! elements were reserved differ in which refusal comes back, and that is
//! what is asserted. It used to be a stopwatch: the decode had to return
//! inside two hundred milliseconds.
//!
//! A stopwatch cannot see this. `Vec::with_capacity` of four billion elements
//! asks an allocator for address space, and an allocator on a host that
//! overcommits hands it back without touching a page, in microseconds. So the
//! reading the timer takes is the same whether the reservation happened or
//! not, and the one thing it does track is how loaded the machine is. It
//! could fail on a busy runner and pass on the defect, which is both ways
//! round the wrong way.
//!
//! What it is now is a fact about the code and not about the host: a count
//! past the cap comes back as the cap's own refusal, and a count the cap
//! allows with no bytes behind it comes back as the input ending. The second
//! is what keeps the first from being an assertion that a decoder refuses
//! rather than one about which refusal it was.

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
use cairn_primitives::codec::{CodecError, Decode, Encode};
use cairn_primitives::{Amount, Hash32};

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
        genesis: ForestProof {
            siblings: vec![Hash32::from_bytes([6; 32]); 5],
        },
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
            assert_eq!(back.genesis, value.genesis);
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
    let count_at = tip_and_history + 1 + sample(499).encode().len() + value.genesis.encode().len();
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
        let refused = SampledStart::decode(&bent)
            .err()
            .unwrap_or_else(|| panic!("a sample count of {lie} was accepted"));
        assert!(
            matches!(
                refused,
                CodecError::InvalidValue {
                    type_name: "SampledStart"
                }
            ),
            "a count of {lie} was refused as `{refused}`, and what has to \
             refuse it is the cap: that is the one refusal that happens before \
             a byte is read for it. Any other answer here is the answer of a \
             decoder that went on reading and was stopped by something \
             further down."
        );
    }

    // And the largest count that is allowed is still refused here, because the
    // bytes for it are not there: what must not happen is a reservation for it.
    let mut bent = bytes.clone();
    bent[count_at..count_at + 4].copy_from_slice(&u32::try_from(SAMPLES).unwrap().to_le_bytes());
    let refused = SampledStart::decode(&bent)
        .expect_err("the largest allowed count, with no bytes behind it");
    // Refused by something, and not by the cap, which is the whole of what
    // this case is for: it is what makes `InvalidValue` above mean "the cap
    // refused this count" rather than "a decoder refused these bytes".
    //
    // Not by the input ending, which is what this expected at first and is
    // worth writing down. With the count set to what the cap allows, the
    // decoder reads samples out of bytes that are not samples, and the first
    // guard the noise trips is the sequence ceiling: it comes back saying a
    // sequence declares 1 381 564 417 elements. Refused before anything is
    // reserved for that either, one layer down.
    assert!(
        !matches!(
            refused,
            CodecError::InvalidValue {
                type_name: "SampledStart"
            }
        ),
        "a count the cap allows was refused by the cap, which would mean the \
         refusal above says nothing about which guard fired: `{refused}`"
    );
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
        let refused = Handover::decode(&bent)
            .err()
            .unwrap_or_else(|| panic!("a buried count of {lie} was accepted"));
        assert!(
            matches!(
                refused,
                CodecError::InvalidValue {
                    type_name: "Handover buried run"
                }
            ),
            "a count of {lie} was refused as `{refused}`, and what has to \
             refuse it is the cap, before a byte is read for it"
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
        maturing: Vec::new(),
        supply: Amount::ZERO,
        headers: Forest::new(),
        buried: Vec::new(),
        recent: Vec::new(),
    }
}

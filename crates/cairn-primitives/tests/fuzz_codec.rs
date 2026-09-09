//! The codec under a generator that does not know what it is afraid of.
//!
//! Every `Decode` in this workspace runs through `Reader`, so what holds here
//! holds everywhere or holds nowhere. Four properties, and each one is a claim
//! the rest of the repository leans on without saying so:
//!
//! 1. **Refusal is total.** Arbitrary bytes decode to something or produce an
//!    error. Never a panic, never an abort, never a hang.
//! 2. **What is accepted is canonical.** Anything that decodes re-encodes to
//!    the bytes it came from. Two encodings of one value would give a block
//!    two identifiers, which is the one thing this module exists to deny.
//! 3. **A decode consumes a defined number of bytes.** The value depends on
//!    that prefix and on nothing after it, so a type nested inside another
//!    reads the same as one read alone.
//! 4. **A declared length does not drive an allocation.** A count past a cap
//!    is refused where the count is read, which is observable: a decoder that
//!    checked first says the cap was exceeded, and one that found out by
//!    running the loop until the bytes ran out says the input ended.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it; with none of them set it runs the same small
//! campaign on every machine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fmt::Debug;

use cairn_fuzz::{mutate, Campaign, Rng};
use cairn_primitives::codec::{take_at_most, CodecError, Decode, Encode, Reader, MAX_SEQUENCE_LEN};
use cairn_primitives::{Amount, Hash32};

/// How many of the campaign's inputs a decoder accepted.
///
/// Counted because a campaign that never gets past the first byte tests the
/// refusal path and nothing else, and would pass for ever while covering
/// nothing.
#[derive(Clone, Copy, Debug, Default)]
struct Reached {
    fed: usize,
    accepted: usize,
}

impl Reached {
    fn saw(&mut self, accepted: bool) {
        self.fed = self.fed.saturating_add(1);
        if accepted {
            self.accepted = self.accepted.saturating_add(1);
        }
    }
}

/// The three properties every type has to hold against one byte string.
///
/// Returns whether the decoder accepted it, so a campaign can say how far it
/// got.
fn holds<T: Encode + Decode + PartialEq + Debug>(bytes: &[u8], what: &str, case: usize) -> bool {
    let Ok(value) = T::decode(bytes) else {
        return false;
    };

    assert_eq!(
        value.encode(),
        bytes,
        "{what} accepted an encoding it does not itself produce (case {case}, \
         bytes {})",
        hex::encode(bytes)
    );

    // The same bytes twice give the same value. A decoder reading anything
    // outside its own frame would show up here first.
    let again = T::decode(bytes).expect("the same bytes decode the same way");
    assert_eq!(value, again, "{what} decoded the same bytes two ways");

    true
}

/// That a decode reads a settled number of bytes, and reads nothing past them.
///
/// Two halves. What it consumed has to be enough on its own, and what follows
/// has to make no difference. The second is what a type nested inside another
/// depends on, and it is the property `cairn-wallet`'s `History` deliberately
/// does not have: it asks the reader whether anything is left. Nothing in this
/// crate may, and nothing that travels between nodes may either.
fn reads_a_settled_prefix<T: Encode + Decode + PartialEq + Debug>(
    bytes: &[u8],
    what: &str,
    trailing: &[u8],
    case: usize,
) {
    let mut reader = Reader::new(bytes);
    let Ok(value) = T::decode_from(&mut reader) else {
        return;
    };
    let consumed = bytes.len().saturating_sub(reader.remaining());
    let prefix = &bytes[..consumed];

    // Nothing decodes out of nothing, which is what makes every `for _ in
    // 0..declared` in this workspace terminate: an element costs at least one
    // byte, so a sequence cannot outrun the frame it arrived in. A type that
    // consumed nothing on success would turn a declared count into a loop the
    // input cannot stop.
    assert!(
        consumed >= 1,
        "{what} decoded a value out of no bytes at all (case {case})"
    );

    let alone = T::decode(prefix).unwrap_or_else(|error| {
        panic!("{what} consumed {consumed} bytes that do not decode alone: {error} (case {case})")
    });
    assert_eq!(
        alone, value,
        "{what} read one value inside a frame and another on its own (case {case})"
    );

    let mut extended = prefix.to_vec();
    extended.extend_from_slice(trailing);
    let mut after = Reader::new(&extended);
    let with_more = T::decode_from(&mut after).unwrap_or_else(|error| {
        panic!("{what} stopped decoding because of bytes after it: {error} (case {case})")
    });
    assert_eq!(
        with_more, value,
        "{what} read a different value because of what followed it (case {case})"
    );
    assert_eq!(
        extended.len().saturating_sub(after.remaining()),
        consumed,
        "{what} consumed a different number of bytes because of what followed it (case {case})"
    );
}

/// Everything in this crate that reads bytes, fed the same input.
fn feed_every_type(bytes: &[u8], case: usize, tally: &mut [Reached; 13]) {
    tally[0].saw(holds::<u8>(bytes, "u8", case));
    tally[1].saw(holds::<u16>(bytes, "u16", case));
    tally[2].saw(holds::<u32>(bytes, "u32", case));
    tally[3].saw(holds::<u64>(bytes, "u64", case));
    tally[4].saw(holds::<u128>(bytes, "u128", case));
    tally[5].saw(holds::<[u8; 4]>(bytes, "[u8; 4]", case));
    tally[6].saw(holds::<[u8; 32]>(bytes, "[u8; 32]", case));
    tally[7].saw(holds::<Hash32>(bytes, "Hash32", case));
    tally[8].saw(holds::<Amount>(bytes, "Amount", case));
    tally[9].saw(holds::<Vec<u8>>(bytes, "Vec<u8>", case));
    tally[10].saw(holds::<Vec<u32>>(bytes, "Vec<u32>", case));
    tally[11].saw(holds::<Vec<Hash32>>(bytes, "Vec<Hash32>", case));
    tally[12].saw(holds::<Vec<Vec<u32>>>(bytes, "Vec<Vec<u32>>", case));
}

fn prefix_every_type(bytes: &[u8], case: usize, trailing: &[u8]) {
    reads_a_settled_prefix::<u8>(bytes, "u8", trailing, case);
    reads_a_settled_prefix::<u16>(bytes, "u16", trailing, case);
    reads_a_settled_prefix::<u32>(bytes, "u32", trailing, case);
    reads_a_settled_prefix::<u64>(bytes, "u64", trailing, case);
    reads_a_settled_prefix::<u128>(bytes, "u128", trailing, case);
    reads_a_settled_prefix::<[u8; 4]>(bytes, "[u8; 4]", trailing, case);
    reads_a_settled_prefix::<[u8; 32]>(bytes, "[u8; 32]", trailing, case);
    reads_a_settled_prefix::<Hash32>(bytes, "Hash32", trailing, case);
    reads_a_settled_prefix::<Amount>(bytes, "Amount", trailing, case);
    reads_a_settled_prefix::<Vec<u8>>(bytes, "Vec<u8>", trailing, case);
    reads_a_settled_prefix::<Vec<u32>>(bytes, "Vec<u32>", trailing, case);
    reads_a_settled_prefix::<Vec<Hash32>>(bytes, "Vec<Hash32>", trailing, case);
    reads_a_settled_prefix::<Vec<Vec<u32>>>(bytes, "Vec<Vec<u32>>", trailing, case);
}

/// Encodings the mutation campaign starts from, one per shape the codec knows.
fn corpus() -> Vec<Vec<u8>> {
    vec![
        7u8.encode(),
        0x0102u16.encode(),
        0x0102_0304u32.encode(),
        u64::MAX.encode(),
        u128::MAX.encode(),
        [1u8, 2, 3, 4].encode(),
        Hash32::from_bytes([9; 32]).encode(),
        Amount::MAX_MONEY.encode(),
        Amount::from_pebbles(1).unwrap().encode(),
        Vec::<u8>::new().encode(),
        vec![1u8, 2, 3].encode(),
        vec![1u32, 2, 3].encode(),
        vec![Hash32::ZERO, Hash32::from_bytes([255; 32])].encode(),
        vec![vec![1u32], Vec::<u32>::new(), vec![2, 3]].encode(),
    ]
}

#[test]
fn arbitrary_bytes_decode_or_refuse_and_never_anything_else() {
    let campaign = Campaign::named("codec: arbitrary bytes");
    let mut tally = [Reached::default(); 13];

    let ran = campaign.run(20_000, |case, rng| {
        let len = rng.between(0, 256);
        let bytes = rng.bytes(len);
        feed_every_type(&bytes, case, &mut tally);
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    // Fixed-width types take any bytes of the right length, so several of
    // these must land. None landing would mean the campaign never reached a
    // decoder at all.
    let reached = tally.iter().filter(|seen| seen.accepted > 0).count();
    assert!(
        reached >= 8,
        "only {reached} of 13 decoders were ever reached by random bytes"
    );
}

#[test]
fn a_valid_encoding_bent_out_of_shape_decodes_or_refuses() {
    let campaign = Campaign::named("codec: bent encodings");
    let corpus = corpus();
    let mut tally = [Reached::default(); 13];

    let ran = campaign.run(20_000, |case, rng| {
        let seed = rng.pick(&corpus).cloned().unwrap_or_default();
        let bent = mutate(rng, &seed, &corpus);
        feed_every_type(&bent, case, &mut tally);
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    let accepted: usize = tally.iter().map(|seen| seen.accepted).sum();
    assert!(
        accepted.saturating_mul(4) > ran.cases,
        "only {accepted} acceptances over {} bent encodings, which is a \
         campaign spending its time on the first refusal",
        ran.cases
    );
    let reached = tally.iter().filter(|seen| seen.accepted > 0).count();
    assert!(
        reached >= 10,
        "only {reached} of 13 decoders were ever reached by a bent encoding"
    );
}

#[test]
fn what_a_decode_reads_is_settled_by_the_bytes_it_consumed() {
    let campaign = Campaign::named("codec: settled prefix");
    let corpus = corpus();

    let ran = campaign.run(10_000, |case, rng| {
        let bytes = if rng.bool() {
            let len = rng.between(0, 256);
            rng.bytes(len)
        } else {
            let seed = rng.pick(&corpus).cloned().unwrap_or_default();
            mutate(rng, &seed, &corpus)
        };
        let trailing_len = rng.between(0, 40);
        let trailing = rng.bytes(trailing_len);
        prefix_every_type(&bytes, case, &trailing);
    });

    assert!(ran.cases >= 500, "the campaign ran {} cases", ran.cases);
}

/// A count past the ceiling has to be refused where the count is read.
///
/// The distinction the assertion turns on is the whole point. A decoder that
/// checked the count first answers `SequenceTooLong`. One that found out by
/// running its loop until the bytes ran out answers `UnexpectedEnd`, and would
/// have built whatever the frame could pay for before saying so.
#[test]
fn a_count_past_the_ceiling_is_refused_where_it_is_read() {
    let campaign = Campaign::named("codec: counts past the ceiling");
    let ceiling = u32::try_from(MAX_SEQUENCE_LEN).unwrap();

    let ran = campaign.run(4_000, |case, rng| {
        // Past the ceiling by anything at all.
        let declared = ceiling
            .saturating_add(1)
            .saturating_add(rng.edgy_u32() % 4096);
        let mut bytes = declared.encode();
        let body = rng.between(0, 64);
        bytes.extend_from_slice(&rng.bytes(body));

        for (what, answer) in [
            ("Vec<u8>", Vec::<u8>::decode(&bytes).err()),
            ("Vec<u32>", Vec::<u32>::decode(&bytes).err()),
            ("Vec<Hash32>", Vec::<Hash32>::decode(&bytes).err()),
            ("Vec<Vec<u32>>", Vec::<Vec<u32>>::decode(&bytes).err()),
        ] {
            assert_eq!(
                answer,
                Some(CodecError::SequenceTooLong {
                    declared: declared as usize
                }),
                "{what} did not refuse a count of {declared} where it read it (case {case})"
            );
        }
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
}

/// The same for a caller's own cap, which is what `take_at_most` is for.
#[test]
fn a_count_past_a_callers_cap_is_refused_where_it_is_read() {
    let campaign = Campaign::named("codec: counts past a caller's cap");

    let ran = campaign.run(4_000, |case, rng| {
        let most = rng.between(0, 4_096);
        let over = u32::try_from(most).unwrap_or(u32::MAX).saturating_add(1);
        let declared = over.saturating_add(rng.edgy_u32() % 1_000);
        let mut bytes = declared.encode();
        let body = rng.between(0, 64);
        bytes.extend_from_slice(&rng.bytes(body));

        let mut reader = Reader::new(&bytes);
        let answer = take_at_most::<Hash32>(&mut reader, most, "under test").err();
        assert_eq!(
            answer,
            Some(CodecError::InvalidValue {
                type_name: "under test"
            }),
            "a cap of {most} did not refuse a count of {declared} where it read it (case {case})"
        );
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
}

/// Nothing a sequence decodes to is larger than the bytes that paid for it.
///
/// This is the observable form of "no declared length drives an allocation".
/// A decoder that reserved for the count rather than for the input would come
/// back holding a vector nothing in the frame paid for.
#[test]
fn a_sequence_never_holds_more_than_its_bytes_paid_for() {
    let campaign = Campaign::named("codec: nothing is held for free");

    let ran = campaign.run(20_000, |_, rng| {
        let len = rng.between(4, 512);
        let mut bytes = rng.edgy_u32().to_le_bytes().to_vec();
        bytes.extend_from_slice(&rng.bytes(len));

        if let Ok(held) = Vec::<u8>::decode(&bytes) {
            assert!(held.len() <= bytes.len());
        }
        if let Ok(held) = Vec::<u32>::decode(&bytes) {
            assert!(held.len().saturating_mul(4) <= bytes.len());
        }
        if let Ok(held) = Vec::<Hash32>::decode(&bytes) {
            assert!(held.len().saturating_mul(32) <= bytes.len());
        }
        if let Ok(held) = Vec::<Vec<u32>>::decode(&bytes) {
            assert!(held.len().saturating_mul(4) <= bytes.len());
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
}

/// The cursor's own arithmetic, which every decoder above stands on.
#[test]
fn the_reader_never_reads_past_what_it_was_given() {
    let campaign = Campaign::named("codec: the reader");

    let ran = campaign.run(20_000, |case, rng| {
        let len = rng.between(0, 128);
        let bytes = rng.bytes(len);
        let mut reader = Reader::new(&bytes);
        let mut taken = 0usize;

        for _ in 0..rng.between(0, 8) {
            let before = reader.remaining();
            // Lengths that would overflow an offset if anything added them
            // without checking.
            let wanted = if rng.chance(4) {
                usize::MAX.saturating_sub(rng.below(4))
            } else {
                rng.between(0, 160)
            };
            match reader.take(wanted) {
                Ok(slice) => {
                    assert_eq!(slice.len(), wanted, "take returned the wrong length");
                    taken = taken.saturating_add(wanted);
                    assert_eq!(reader.remaining(), before.saturating_sub(wanted));
                }
                Err(error) => {
                    assert_eq!(error, CodecError::UnexpectedEnd);
                    assert_eq!(
                        reader.remaining(),
                        before,
                        "a refused take moved the cursor (case {case})"
                    );
                }
            }
        }

        assert!(
            taken <= bytes.len(),
            "the reader handed out bytes it had not"
        );
        let left = reader.remaining();
        let finished = reader.finish();
        assert_eq!(
            finished.is_ok(),
            left == 0,
            "finish disagreed with remaining (case {case})"
        );
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
}

/// The boundary itself, pinned rather than sampled.
#[test]
fn the_ceiling_is_where_it_says_it_is() {
    let ceiling = u32::try_from(MAX_SEQUENCE_LEN).unwrap();

    let mut at = ceiling.encode();
    at.extend_from_slice(&[0u8; 4]);
    // At the ceiling the count is allowed and the input is simply short.
    assert_eq!(Vec::<u32>::decode(&at), Err(CodecError::UnexpectedEnd));

    let mut over = ceiling.saturating_add(1).encode();
    over.extend_from_slice(&[0u8; 4]);
    assert_eq!(
        Vec::<u32>::decode(&over),
        Err(CodecError::SequenceTooLong {
            declared: MAX_SEQUENCE_LEN + 1
        })
    );
}

/// A campaign the suite does not run, kept because the engine is only worth
/// what its generator reaches.
///
/// It walks every mutation operator over the corpus and counts how many
/// distinct lengths and first bytes it produced. A generator that had quietly
/// stopped bending anything would still pass every test above, because every
/// test above is satisfied by refusing.
#[test]
fn the_generator_reaches_more_than_one_shape() {
    let corpus = corpus();
    let mut rng = Rng::new(1);
    let mut lengths = std::collections::BTreeSet::new();
    let mut leaders = std::collections::BTreeSet::new();

    for _ in 0..20_000 {
        let seed = rng.pick(&corpus).cloned().unwrap_or_default();
        let bent = mutate(&mut rng, &seed, &corpus);
        lengths.insert(bent.len());
        leaders.insert(bent.first().copied());
    }

    assert!(lengths.len() > 30, "only {} lengths", lengths.len());
    assert!(leaders.len() > 100, "only {} first bytes", leaders.len());
}

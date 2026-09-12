//! The wallet's own account of its money, read back from bytes.
//!
//! Not a stranger's bytes, in the ordinary case: this is a file the wallet
//! wrote. But a file is somewhere anybody with the disk can reach, and the
//! stamp `History::save` puts on it is an unkeyed hash over its own contents,
//! which catches a torn write and not a rewrite. So what stands between a
//! hand-edited file and a balance is the decoder, and the decoder answers to
//! the same question every other decoder in this workspace answers to.
//!
//! It is here for a second reason, which is that it is the one `Decode` in the
//! workspace that does not read a settled number of bytes and says so. A
//! history written before the wallet learned to keep the places its notes fell
//! to simply ends early, and is read rather than thrown away, because the
//! account of what a key was paid is the expensive half and the places can be
//! asked for again. So the decoder asks the reader whether anything is left.
//!
//! That exception is asserted here rather than skipped. The campaign found a
//! second one that was not documented anywhere, and it is pinned below.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_fuzz::{mutate, Campaign};
use cairn_primitives::codec::{Decode, Encode};
use cairn_wallet::history::History;

/// A history with something in it, encoded.
///
/// Built through the codec rather than through `save` and `load`, which would
/// drag a temporary directory in for nothing: what is under test is the
/// decoder, and the decoder is reachable directly.
fn corpus() -> Vec<Vec<u8>> {
    let empty = History::new().encode();
    // The same file as a wallet from before the places were kept would have
    // written it: everything up to the last list, and then nothing.
    let older = empty[..empty.len().saturating_sub(4)].to_vec();
    vec![
        empty,
        older,
        written(&[(0, 0, 0)], &[]),
        written(&[], &[(0, 0)]),
    ]
}

/// A history file built by hand, so a list can hold what no writer produces.
///
/// `held` is a note identifier's leading byte, its index, and its value.
/// `fell` is a leading byte and a place. Everything else is zero, because
/// everything else is beside the point here.
fn written(held: &[(u8, u32, u64)], fell: &[(u8, u64)]) -> Vec<u8> {
    let mut bytes = 0u64.encode();
    // No height read from yet.
    bytes.extend_from_slice(&u64::MAX.encode());
    // No movements, and no last block.
    bytes.extend_from_slice(&0u32.encode());
    bytes.extend_from_slice(&[0u8; 32]);

    bytes.extend_from_slice(&u32::try_from(held.len()).unwrap().encode());
    for (leading, index, value) in held {
        let mut source = [0u8; 32];
        source[0] = *leading;
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&index.encode());
        bytes.extend_from_slice(&value.encode());
    }

    // Nothing undone.
    bytes.extend_from_slice(&0u32.encode());

    bytes.extend_from_slice(&u32::try_from(fell.len()).unwrap().encode());
    for (leading, position) in fell {
        let mut source = [0u8; 32];
        source[0] = *leading;
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&0u32.encode());
        bytes.extend_from_slice(&position.encode());
    }
    bytes
}

#[test]
fn arbitrary_bytes_are_refused_or_read_and_settle() {
    let campaign = Campaign::named("wallet: history");
    let seeds = corpus();
    let mut accepted = 0usize;

    let ran = campaign.run(20_000, |_, rng| {
        let bytes = if rng.bool() {
            let len = rng.between(0, 300);
            rng.plausible_bytes(len)
        } else {
            let seed = rng.pick(&seeds).cloned().unwrap_or_default();
            mutate(rng, &seed, &seeds)
        };

        let Ok(history) = History::decode(&bytes) else {
            return;
        };
        accepted += 1;

        // What holds for every input, and what a wallet that loads and then
        // saves depends on: the canonical form is a fixed point. It is not
        // that a decoded history re-encodes to the bytes it came from; see the
        // two tests below for the two ways it does not.
        let canonical = history.encode();
        let again = History::decode(&canonical).expect("its own encoding reads back");
        assert_eq!(
            again.encode(),
            canonical,
            "a history has no fixed point: {} then {}",
            hex::encode(&bytes),
            hex::encode(&canonical)
        );
        assert_eq!(
            again.len(),
            history.len(),
            "a history lost movements on its way through its own encoder"
        );

        // And nothing is held that the bytes did not pay for. The smallest
        // entry of either list is forty four bytes.
        assert!(history.len() <= bytes.len());
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    assert!(accepted > 0, "not one input reached the decoder");
}

/// The documented exception, stated.
#[test]
fn a_history_from_before_the_places_reads_and_grows_by_four_bytes() {
    let full = History::new().encode();
    let older = &full[..full.len() - 4];

    let read = History::decode(older).expect("an older file is read rather than thrown away");
    assert_eq!(
        read.encode(),
        full,
        "reading an older file and writing it back does not produce the current shape"
    );
    assert_eq!(
        full.len() - older.len(),
        4,
        "the difference is one empty list and nothing else"
    );

    // Which is the whole reason this type may not be nested inside another:
    // bytes after it change what it reads. Nothing nests it, and nothing on
    // the network reads one at all.
    let mut with_more = older.to_vec();
    with_more.extend_from_slice(&1u32.encode());
    assert!(
        History::decode(&with_more).is_err(),
        "a place list of one with no place behind it has to be refused"
    );
}

/// The defect that was pinned here, and the rule that closed it.
///
/// `held` and `fell` are written out of `BTreeMap`s, in key order and never
/// twice, and were read back into `BTreeMap`s without anything asking. Two
/// entries naming the same note collapsed into one, the later silently winning,
/// and entries in any order came back sorted. So a file could say a wallet
/// holds one note at fifty and the same note at nothing, and the wallet read
/// that as holding it at nothing, without a word.
///
/// The forest had the same shape of defect and it was only malleability there,
/// because reordering roots loses nothing. This one lost an entry. A wallet
/// reading such a file reported a balance that was neither what the file said
/// nor an error, and `fell` is the list that decides whether a fallen note can
/// be spent at all: two places for one note, one of them silently kept.
///
/// The stamp never stood in the way. `History::save` appends
/// `blake3(WalletHistory, bytes)`, which anybody who can write the file can
/// recompute, because it is there to catch a write that was cut short rather
/// than a write that was meant.
///
/// Nothing on the network reads a history, so there was no fork behind this. It
/// was a local file and a wrong balance, and it is now a local file that is
/// refused.
///
/// Found by the long campaign at seed 0xca12f0221d05ca12, twenty seconds in,
/// and reduced by `cairn_fuzz::smallest` to a hundred and forty eight bytes
/// that are zero apart from one count of two.
#[test]
fn a_history_refuses_two_entries_for_one_note() {
    // The reduced case, byte for byte: a file from before the places were
    // kept, whose held list names the all-zero note twice.
    let twice = hex::decode(concat!(
        "0000000000000000",
        "0000000000000000",
        "00000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "02000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000",
        "0000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000",
        "0000000000000000",
        "00000000",
    ))
    .unwrap();
    assert_eq!(twice.len(), 148);
    assert!(
        History::decode(&twice).is_err(),
        "a history was read out of a file naming one note twice"
    );

    // Two values for one note, which is the shape that used to keep the later
    // one and throw away the one a reader would see first.
    assert!(History::decode(&written(&[(0, 0, 50), (0, 0, 7)], &[])).is_err());
    assert_eq!(
        History::decode(&written(&[(0, 0, 50)], &[]))
            .expect("one entry for one note is a file a wallet writes")
            .held()
            .count(),
        1
    );

    // The same for the places a note fell to, which is the list that decides
    // whether a fallen note can be spent.
    assert!(History::decode(&written(&[], &[(0, 11), (0, 22)])).is_err());
    assert!(History::decode(&written(&[], &[(0, 22)])).is_ok());

    // And a list out of order is refused rather than quietly sorted, which is
    // the milder half of the same rule: it was one value with two encodings.
    let descending = written(&[(2, 0, 1), (1, 0, 1)], &[]);
    let ascending = written(&[(1, 0, 1), (2, 0, 1)], &[]);
    assert_ne!(descending, ascending, "two byte strings");
    assert!(
        History::decode(&descending).is_err(),
        "and only one of them"
    );
    assert_eq!(
        History::decode(&ascending)
            .expect("the order a wallet writes")
            .encode(),
        ascending,
        "what is read back writes the bytes it came from"
    );
}

//! Bech32m against the vectors BIP 350 publishes, and the typo property an
//! address is written in it for.
//!
//! The valid and invalid strings are BIP 350's own, character for character. A
//! reader that disagrees with them about one string disagrees with every other
//! implementation about some address.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use cairn_primitives::bech32m::{
    decode, decode_groups, encode, encode_groups, Bech32mError, ALPHABET, MOST_CHARACTERS,
};

/// BIP 350's valid Bech32m strings.
const VALID: [&str; 7] = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
];

/// BIP 350's invalid Bech32m strings, each with the reason BIP 350 gives.
const INVALID: [(&str, Bech32mError); 14] = [
    ("\u{20}1xj0phk", Bech32mError::NotPrintable),
    ("\u{7f}1g6xzxy", Bech32mError::NotPrintable),
    ("\u{80}1vctc34", Bech32mError::NotPrintable),
    (
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
        Bech32mError::TooLong,
    ),
    ("qyrz8wqd2c9m", Bech32mError::NoSeparator),
    ("1qyrz8wqd2c9m", Bech32mError::EmptyPrefix),
    ("y1b0jsk6g", Bech32mError::NotInAlphabet('b')),
    ("lt1igcx5c0", Bech32mError::NotInAlphabet('i')),
    ("in1muywd", Bech32mError::TooShort),
    ("mm1crxm3i", Bech32mError::NotInAlphabet('i')),
    ("au1s5cgom", Bech32mError::NotInAlphabet('o')),
    ("M1VUXWEZ", Bech32mError::BadChecksum),
    ("16plkw9", Bech32mError::EmptyPrefix),
    ("1p2gdwpf", Bech32mError::EmptyPrefix),
];

/// BIP 173's valid Bech32 strings: right under the old constant, so wrong
/// under the new one.
const BECH32_NOT_BECH32M: [&str; 5] = [
    "A12UEL5L",
    "a12uel5l",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
];

/// **Every string BIP 350 calls valid is read, and written back the same.**
///
/// Without these a checksum computed under another constant, another
/// generator or another expansion of the prefix is only ever checked against
/// itself, and agrees with itself perfectly.
#[test]
fn every_valid_vector_of_bip_350_is_read_and_written_back() {
    for text in VALID {
        let (prefix, groups) = decode_groups(text)
            .unwrap_or_else(|why| panic!("BIP 350 calls `{text}` valid and it was refused: {why}"));
        assert_eq!(
            encode_groups(&prefix, &groups),
            text.to_ascii_lowercase(),
            "a valid string read and written again is not the string it was"
        );
    }
}

/// **Every string BIP 350 calls invalid is refused, for the reason it gives.**
///
/// A reader that takes one of these takes a string no writer produces, and
/// from then on disagrees with every other reader about what it names.
#[test]
fn every_invalid_vector_of_bip_350_is_refused_for_its_reason() {
    for (text, reason) in INVALID {
        assert_eq!(
            decode_groups(text),
            Err(reason),
            "BIP 350 calls `{}` invalid for another reason than this reader gives",
            text.escape_default()
        );
    }
}

/// **A Bech32 string is not a Bech32m string.**
///
/// The two differ in one constant. A reader that took both would take a
/// string with `q` inserted or dropped before a final `p`, which is the weakness
/// BIP 350 exists to close; one that checked under the old constant would
/// refuse every valid vector above and take every one of these.
#[test]
fn a_string_checked_under_bech32s_constant_is_refused() {
    for text in BECH32_NOT_BECH32M {
        assert_eq!(
            decode_groups(text),
            Err(Bech32mError::BadChecksum),
            "`{text}` is Bech32 and was read as Bech32m"
        );
    }
}

/// Thirty two bytes, as an address carries.
fn payload(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in (0u8..).zip(bytes.iter_mut()) {
        *byte = seed.wrapping_mul(31).wrapping_add(index).wrapping_mul(97);
    }
    bytes
}

/// **Thirty two bytes are fifty two characters, and come back as they went.**
#[test]
fn thirty_two_bytes_are_fifty_two_characters_and_come_back() {
    for seed in 0..32u8 {
        let bytes = payload(seed);
        let text = encode("tcairn", &bytes);
        assert_eq!(
            text.len(),
            "tcairn".len() + 1 + 52 + 6,
            "thirty two bytes are not written as fifty two characters and a checksum"
        );
        assert!(text.len() <= MOST_CHARACTERS);
        assert_eq!(
            decode(&text),
            Ok(("tcairn".to_owned(), bytes.to_vec())),
            "bytes written as text did not come back as the same bytes"
        );
        assert_eq!(
            decode(&text.to_ascii_uppercase()),
            Ok(("tcairn".to_owned(), bytes.to_vec())),
            "the same string in capitals, as a QR code carries it, was not read the same"
        );
    }
}

/// **A last character whose spare bits are not zero is refused.**
///
/// Fifty two groups hold 260 bits for 256, so the last character has four to
/// spare. Were they ignored, sixteen strings would name every address, each
/// with its own valid checksum, and a reader comparing text would call them
/// sixteen addresses. Nothing refused that before this test.
#[test]
fn spare_bits_that_are_not_zero_are_refused() {
    let bytes = payload(7);
    let (prefix, mut groups) = decode_groups(&encode("tcairn", &bytes)).unwrap();
    assert_eq!(groups.len(), 52);
    for spare in 1..16u8 {
        let last = groups.len() - 1;
        groups[last] = (groups[last] & 0b1_0000) | spare;
        let bent = encode_groups(&prefix, &groups);
        assert_eq!(
            decode(&bent),
            Err(Bech32mError::NonZeroPadding),
            "a string with spare bits set was read as bytes"
        );
    }

    // And a group too few, which leaves seven bits over: more than a group,
    // so the last group carries no part of any byte.
    let (prefix, mut groups) = decode_groups(&encode("tcairn", &bytes)).unwrap();
    groups.pop();
    assert_eq!(
        decode(&encode_groups(&prefix, &groups)),
        Err(Bech32mError::ExtraPadding),
        "a string whose last group carries no part of any byte was read as bytes"
    );
}

/// **Any number of bytes is written as the fewest groups that hold it, and
/// read back as it went.**
///
/// Thirty two bytes leave a last group part filled, which is the only case the
/// tests above reach. Five bytes, or any multiple of five, fill their last
/// group exactly, and a writer that added a group of padding anyway wrote a
/// string its own reader refuses; nothing encoded such a length, so that
/// passed.
#[test]
fn every_length_is_written_in_the_fewest_groups_and_read_back() {
    for length in 0..=40usize {
        let bytes: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(37))
            .collect();
        let text = encode("tcairn", &bytes);
        let (_, groups) = decode_groups(&text).unwrap();
        assert_eq!(
            groups.len(),
            (length * 8).div_ceil(5),
            "{length} bytes were not written in the fewest groups that hold them"
        );
        assert_eq!(
            decode(&text),
            Ok(("tcairn".to_owned(), bytes)),
            "{length} bytes did not come back as they went"
        );
    }
}

/// Every character a person could type in place of another.
fn printable() -> impl Iterator<Item = char> {
    (0x21u8..=0x7e).map(char::from)
}

/// **Every single-character typo and every swap of two neighbours is
/// refused.**
///
/// What the checksum is for. Bech32m detects every error of up to four
/// characters at this length, and a swap is two. Before this format an
/// address was sixty four hexadecimal characters with no checksum at all.
#[test]
fn every_typo_of_one_character_and_every_swap_of_two_is_refused() {
    for seed in 0..4u8 {
        let text = encode("tcairn", &payload(seed));
        let original: Vec<char> = text.chars().collect();
        let mut tried = 0usize;
        for position in 0..original.len() {
            for typed in printable() {
                if typed == original[position] {
                    continue;
                }
                let mut bent = original.clone();
                bent[position] = typed;
                let bent: String = bent.into_iter().collect();
                let read = decode(&bent);
                assert!(
                    !matches!(&read, Ok((prefix, _)) if prefix == "tcairn"),
                    "a string one character away from an address was read as an address \
                     under the same prefix"
                );
                tried += 1;
            }
        }
        assert_eq!(
            tried,
            original.len() * 93,
            "not every substitution was tried"
        );

        for position in 0..original.len() - 1 {
            if original[position] == original[position + 1] {
                continue;
            }
            let mut swapped = original.clone();
            swapped.swap(position, position + 1);
            let swapped: String = swapped.into_iter().collect();
            assert!(
                !matches!(decode(&swapped), Ok((prefix, _)) if prefix == "tcairn"),
                "an address with two neighbours swapped was read as an address"
            );
        }
    }
}

/// The alphabet is BIP 173's, in its order: a group's value is its position.
#[test]
fn the_alphabet_is_bip_173s() {
    assert_eq!(ALPHABET, b"qpzry9x8gf2tvdw0s3jn54khce6mua7l");
}

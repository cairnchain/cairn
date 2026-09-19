//! The hexadecimal parser, which sits behind every identifier a person types.
//!
//! It is the second thing a stranger's bytes reach, after the request reader
//! in `cairn-http`. Every `/api/tx/<hex>`, `/api/note/<hex>:<n>` and
//! `/api/address/<hex>` in the explorer is a path segment handed straight to
//! [`decode`], and the wallet's key file is read through [`decode_array`],
//! which is the one caller where being wrong costs more than a 404. An audit
//! found it had no fuzz target, which for a parser this small is less
//! surprising and no less of a gap: small is where nobody looks twice.
//!
//! Four properties:
//!
//! 1. **Refusal is total.** Any string decodes to bytes or to `None`. Never
//!    a panic.
//! 2. **What goes out comes back.** [`encode`] then [`decode`] is the
//!    identity on every byte string, in either case on the way in.
//! 3. **What comes in goes back out.** [`decode`] then [`encode`] is the
//!    identity on every accepted string, once it is folded to lower case.
//!    There is exactly one spelling of a byte string, which is what makes an
//!    identifier in a URL the same identifier everywhere else.
//! 4. **The fixed-width parser agrees with the general one.** They are
//!    deliberately separate code, so that reading a key never builds a vector
//!    holding the secret, and separate code is code that can drift.
//!
//! Two arms, counted apart: strings assembled out of a hexadecimal alphabet,
//! and valid encodings with bytes changed. A campaign that only ever fed the
//! second would never test the length check, and one that only fed the first
//! would never get past it.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_fuzz::{mutate, Arms, Built, Campaign, Rng};
use cairn_primitives::hex::{decode, decode_array, encode};

/// Everything this parser takes, in both cases.
const DIGITS: &[u8] = b"0123456789abcdefABCDEF";

/// Holds everything against one string, and says whether it was accepted.
fn holds(text: &str, case: usize) -> bool {
    // The two parsers, both directions, before anything returns.
    //
    // This used to leave the moment `decode` refused, so the fixed parser was
    // only ever asked about strings the general one had already taken. The
    // drift this file is named for is the fixed parser taking something the
    // general one refuses, and that was the half never asked. It matters more
    // than the other one, because `decode` has a single production caller in
    // this workspace, a compiled-in constant, and `decode_array` has every URL
    // the explorer answers, every key file and every command line.
    //
    // Measured: `strip_prefix("0x")` added to `decode_array` alone, three
    // lines, left all sixty tests green. One transaction then has two URLs and
    // one key file two spellings.
    let general = decode(text);
    let wide = decode_array::<32>(text).map(|array| array.to_vec());
    let narrow = decode_array::<4>(text).map(|array| array.to_vec());
    for (width, fixed) in [(32usize, &wide), (4usize, &narrow)] {
        match &general {
            Some(bytes) if bytes.len() == width => assert_eq!(
                fixed.as_ref(),
                Some(bytes),
                "the general parser read {text:?} as {width} bytes and the fixed one of \
                 that width did not (case {case})"
            ),
            _ => assert_eq!(
                fixed.as_ref(),
                None,
                "the fixed parser of {width} took {text:?}, which the general one does \
                 not read as {width} bytes (case {case})"
            ),
        }
    }

    let Some(bytes) = general else {
        return false;
    };

    // A string that decoded is exactly twice as long as what it decoded to.
    // A parser that accepted an odd length by dropping the last nibble would
    // read `0f1e2` as two bytes and answer about a different transaction than
    // the one somebody pasted.
    assert_eq!(
        bytes.len().saturating_mul(2),
        text.len(),
        "{text:?} decoded to {} bytes (case {case})",
        bytes.len()
    );

    // One spelling. Two encodings of one identifier would mean two URLs for
    // one transaction, and, where a hex string is a key in a map, two entries
    // for one thing.
    assert_eq!(
        encode(&bytes),
        text.to_ascii_lowercase(),
        "{text:?} is a second spelling of the same bytes (case {case})"
    );

    // The two parsers are separate code for a reason `decode_array`'s own doc
    // comment gives: a vector holding a secret key would be freed without
    // being wiped. Separate code is code that can drift, and the loop above is
    // what catches the drift, in both directions and at both widths. The arm
    // that stood here asked only one width and guarded it with `if other != 32`
    // inside a match arm that had already excluded 32, which is a condition
    // that cannot be false.

    true
}

/// A string assembled out of the alphabet, so the fresh arm gets past the
/// first character.
///
/// Drawn bytes reach [`decode`] and are refused at the first one that is not
/// a digit: a sixteen character string of uniform bytes is accepted about
/// once in six hundred million. `the_fresh_arm_is_worth_running` measures it.
fn a_hex_string(rng: &mut Rng) -> String {
    let len = match rng.below(8) {
        // The lengths a caller actually types: a hash or a public key twice
        // as often as the rest, then a short identifier, then nothing at all.
        0 | 1 => 64,
        2 => 8,
        3 => 0,
        _ => rng.between(0, 80),
    };
    let mut text: String = (0..len)
        .map(|_| char::from(rng.pick(DIGITS).copied().unwrap_or(b'0')))
        .collect();

    // And then, a quarter of the time, one thing that is not a digit, which
    // is how a person actually gets this wrong: a prefix, a separator, a
    // space from a copy, or an odd length.
    if rng.chance(4) {
        match rng.below(5) {
            0 => text.insert_str(0, "0x"),
            1 => text.push(' '),
            2 => text.push('g'),
            3 => text.push('é'),
            _ => {
                text.pop();
            }
        }
    }
    text
}

/// Valid encodings the bending arm starts from.
fn corpus() -> Vec<Vec<u8>> {
    [
        encode(&[]),
        encode(&[0x00]),
        encode(&[0xff]),
        encode(&[0x00, 0x0f, 0xa5, 0xff]),
        encode(&[0x12; 32]),
        encode(&(0u8..=255).collect::<Vec<u8>>()),
        "0F1E2D3C".to_owned(),
    ]
    .iter()
    .map(|text| text.as_bytes().to_vec())
    .collect()
}

#[test]
fn any_string_at_all_decodes_or_is_refused() {
    let campaign = Campaign::named("hex: any string");
    let corpus = corpus();
    let mut arms = Arms::default();

    let ran = campaign.run(20_000, |case, rng| {
        let (built, text) = if rng.bool() {
            (Built::FromNothing, a_hex_string(rng))
        } else {
            let seed = rng.pick(&corpus).cloned().unwrap_or_default();
            let bent = mutate(rng, &seed, &corpus);
            // Lossy, because the parser takes a `&str` and the mutator makes
            // bytes. What the replacement character costs is one refusal
            // where a stray byte would have been one anyway.
            (
                Built::ByBending,
                String::from_utf8_lossy(&bent).into_owned(),
            )
        };
        arms.saw(built, holds(&text, case));
    });

    arms.report("hex: any string");
    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    assert!(
        arms.from_nothing.accepted > 0,
        "not one assembled string was decoded: {:?}",
        arms.from_nothing
    );
    assert!(
        arms.by_bending.accepted > 0,
        "not one bent encoding was decoded: {:?}",
        arms.by_bending
    );
}

/// Every byte string survives being written down and read back.
#[test]
fn bytes_survive_being_written_down_and_read_back() {
    let campaign = Campaign::named("hex: round trip");

    let ran = campaign.run(20_000, |case, rng| {
        let len = rng.between(0, 96);
        let bytes = rng.bytes(len);
        let text = encode(&bytes);

        assert_eq!(
            decode(&text).as_deref(),
            Some(bytes.as_slice()),
            "bytes did not come back (case {case})"
        );
        // Either case on the way in, which is the promise the module's own
        // opening paragraph makes. A parser that took only what it writes
        // would refuse an identifier somebody copied out of a document that
        // upper-cased it.
        assert_eq!(
            decode(&text.to_ascii_uppercase()).as_deref(),
            Some(bytes.as_slice()),
            "upper case was refused (case {case})"
        );
        assert_eq!(
            text,
            text.to_ascii_lowercase(),
            "the writer used a capital (case {case})"
        );
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
}

/// The fixed-width parser takes one length and refuses every other.
///
/// This is the one that reads a wallet's key file. A parser that accepted a
/// short string by padding it, or a long one by truncating, would turn a key
/// file with a byte missing into a different wallet rather than into a
/// refusal.
#[test]
fn a_fixed_width_parser_takes_exactly_its_own_length() {
    let campaign = Campaign::named("hex: fixed width");
    let mut took = 0usize;
    let mut refused = 0usize;

    let ran = campaign.run(20_000, |case, rng| {
        let len = rng.between(0, 48);
        let bytes = rng.bytes(len);
        let text = encode(&bytes);

        let answer = decode_array::<32>(&text);
        if len == 32 {
            assert_eq!(
                answer.map(|array| array.to_vec()),
                Some(bytes),
                "32 bytes were not read back (case {case})"
            );
            took += 1;
        } else {
            assert_eq!(
                answer, None,
                "{len} bytes were accepted where 32 were wanted (case {case})"
            );
            refused += 1;
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    // Both branches, because an assertion only reached on the refusing side
    // is an assertion about a function that always returns `None`.
    assert!(took > 0, "the accepting branch was never reached");
    assert!(refused > 0, "the refusing branch was never reached");
}

/// Nothing outside the alphabet is ever a digit, wherever it sits.
///
/// The positional half matters: a parser that read the pair rather than each
/// character could take `0x` as a byte by folding the `x` into the high
/// nibble it already had.
#[test]
fn one_character_outside_the_alphabet_refuses_the_whole_string() {
    let campaign = Campaign::named("hex: one bad character");

    let ran = campaign.run(20_000, |case, rng| {
        let pairs = rng.between(1, 32);
        let mut text: String = (0..pairs.saturating_mul(2))
            .map(|_| char::from(rng.pick(DIGITS).copied().unwrap_or(b'0')))
            .collect();
        assert!(decode(&text).is_some(), "the string starts valid");

        let intruder = loop {
            let byte = rng.byte();
            if !DIGITS.contains(&byte) && byte.is_ascii() {
                break char::from(byte);
            }
        };
        let at = rng.below(text.len());
        text.replace_range(at..at.saturating_add(1), &intruder.to_string());

        assert_eq!(
            decode(&text),
            None,
            "{text:?} was accepted with {intruder:?} at {at} (case {case})"
        );
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
}

/// The measurement behind the fresh arm being assembled rather than drawn.
///
/// Kept for the reason the same test is kept in `cairn-http`: the claim that
/// an assembler is needed here is the kind that stops being true quietly, and
/// every other test in this file passes on a generator that reaches nothing.
#[test]
fn the_fresh_arm_is_worth_running() {
    let mut rng = Rng::new(13);
    let mut assembled = 0usize;
    let mut drawn = 0usize;

    for _ in 0..20_000 {
        if decode(&a_hex_string(&mut rng)).is_some() {
            assembled += 1;
        }
        let len = rng.between(0, 40);
        let text = String::from_utf8_lossy(&rng.bytes(len)).into_owned();
        if decode(&text).is_some() {
            drawn += 1;
        }
    }

    eprintln!("hex: {assembled} assembled strings decoded, {drawn} drawn ones");
    assert!(
        assembled > 10_000,
        "only {assembled} of 20000 assembled strings were decoded"
    );
    // Not zero: a drawn string of length zero decodes, and one in forty of
    // them is. The claim is that nothing longer ever gets through, which is
    // what the ratio says.
    assert!(
        drawn.saturating_mul(4) < assembled,
        "{drawn} drawn strings were decoded against {assembled} assembled ones"
    );
}

/// The boundaries, pinned rather than sampled.
#[test]
fn the_edges_of_the_alphabet_are_where_they_say_they_are() {
    assert_eq!(decode("00").as_deref(), Some(&[0x00][..]));
    assert_eq!(decode("ff").as_deref(), Some(&[0xff][..]));
    assert_eq!(decode("FF").as_deref(), Some(&[0xff][..]));
    // The characters either side of each run in the ASCII table, which is
    // where an off-by-one in a range pattern lands.
    for near in ["/0", "0:", "`a", "ag", "@A", "AG"] {
        assert_eq!(decode(near), None, "{near:?} was accepted");
    }
    assert_eq!(decode("").as_deref(), Some(&[][..]), "nothing is no bytes");
    assert_eq!(decode("0").as_deref(), None, "an odd length is not bytes");
    assert_eq!(decode_array::<0>("").map(|a| a.to_vec()), Some(Vec::new()));
}

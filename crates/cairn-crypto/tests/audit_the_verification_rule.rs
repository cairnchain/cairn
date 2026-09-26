//! The rule a node verifies a signature by, and the vectors the specification
//! publishes beside it.
//!
//! The specification said a public key is "an Ed25519 verifying key" and gave
//! each input a 64 byte signature, and said nothing about how one is checked.
//! Ed25519 verifiers differ exactly there. RFC 8032 accepts the cofactored
//! equation as well as the cofactorless one and never asks about the order of
//! `R`; this crate verifies with `verify_strict`, which refuses a small order
//! `R` and applies the cofactorless equation only. The holder of a key can
//! make a signature that falls between the two at will, so a second
//! implementation written from the document, with any RFC 8032 verifier,
//! accepted spends this one refuses and followed another chain from the first
//! block that carried one.
//!
//! So the document states the rule and publishes four vectors, and this file
//! builds the four from the RFC's own arithmetic, checks that the document
//! carries those bytes, that this crate reaches the verdict the document
//! gives for each, and that the ones it refuses are ones a verifier written to
//! the RFC alone would take. SHA-512 is written out here because no crate in
//! this build exposes one to a test; its first test pins it to the FIPS
//! vectors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names
)]

use cairn_crypto::{PublicKey, SecretKey, Signature};
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity};
use ed25519_dalek::SigningKey;

const SPECIFICATION: &str = include_str!("../../../docs/cairn-specification.md");

// ---------------------------------------------------------------------------
// SHA-512, FIPS 180-4.
// ---------------------------------------------------------------------------

const ROUND_CONSTANTS: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

const INITIAL_STATE: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

fn sha512(message: &[u8]) -> [u8; 64] {
    let mut state = INITIAL_STATE;
    let mut padded = message.to_vec();
    let bits = u128::try_from(message.len()).unwrap() * 8;
    padded.push(0x80);
    while padded.len() % 128 != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&bits.to_be_bytes());

    for block in padded.chunks(128) {
        let mut w = [0u64; 80];
        for (index, word) in block.chunks(8).enumerate() {
            w[index] = u64::from_be_bytes(<[u8; 8]>::try_from(word).unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for (constant, word) in ROUND_CONSTANTS.iter().zip(w) {
            let big_s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let choice = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(big_s1)
                .wrapping_add(choice)
                .wrapping_add(*constant)
                .wrapping_add(word);
            let big_s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = big_s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut out = [0u8; 64];
    for (index, word) in state.iter().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// The first half of SHA-512 of `text`, which is how the document derives
/// every fixed value its vectors need rather than printing one to be trusted.
fn first_half(text: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(&sha512(text)[..32]).unwrap()
}

/// The written SHA-512 is FIPS 180-4's, or every vector below is a vector of
/// something else.
///
/// Nothing else in this build computes SHA-512 where a test can reach it, so
/// this file carries its own, and a mistake in it would make the vectors agree
/// with a hash nobody uses.
#[test]
fn the_sha512_written_here_is_the_one_in_fips_180_4() {
    assert_eq!(
        cairn_primitives::hex::encode(&sha512(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "the SHA-512 written here does not give the FIPS 180-4 digest of \"abc\""
    );
    assert_eq!(
        cairn_primitives::hex::encode(&sha512(b"")),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "the SHA-512 written here does not give the FIPS 180-4 digest of nothing"
    );
}

// ---------------------------------------------------------------------------
// RFC 8032 section 5.1.7, written from the RFC and from nothing else.
// ---------------------------------------------------------------------------

/// `k = SHA-512(R || A || M) mod L`.
fn challenge(r: &[u8; 32], a: &[u8; 32], message: &[u8]) -> Scalar {
    let mut preimage = Vec::with_capacity(64 + message.len());
    preimage.extend_from_slice(r);
    preimage.extend_from_slice(a);
    preimage.extend_from_slice(message);
    Scalar::from_bytes_mod_order_wide(&sha512(&preimage))
}

/// What a verifier written to RFC 8032 alone makes of a signature: `None` when
/// `A`, `R` or `S` does not decode as the RFC says, otherwise whether the
/// cofactorless equation holds and whether the cofactored one does. The RFC
/// permits either and asks nothing about the order of `R`.
fn rfc8032(a_bytes: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Option<(bool, bool)> {
    let a = CompressedEdwardsY(*a_bytes).decompress()?;
    let r_bytes = <[u8; 32]>::try_from(&signature[..32]).unwrap();
    let r = CompressedEdwardsY(r_bytes).decompress()?;
    let s_bytes = <[u8; 32]>::try_from(&signature[32..]).unwrap();
    let s: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes).into();
    let k = challenge(&r_bytes, a_bytes, message);
    let left = s? * ED25519_BASEPOINT_POINT;
    let right = r + k * a;
    Some((
        left == right,
        (left - right).mul_by_cofactor().is_identity(),
    ))
}

// ---------------------------------------------------------------------------
// The four vectors, built.
// ---------------------------------------------------------------------------

/// A vector as the document gives it: the verdict, then `R` and `S`.
#[derive(Debug, PartialEq, Eq)]
struct Vector {
    accepted: bool,
    r: String,
    s: String,
}

/// The key, the message and the four signatures, built from the strings the
/// document names and the arithmetic RFC 8032 gives.
struct Built {
    public: PublicKey,
    message: [u8; 32],
    signatures: [[u8; 64]; 4],
}

fn joined(r: [u8; 32], s: [u8; 32]) -> [u8; 64] {
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r);
    signature[32..].copy_from_slice(&s);
    signature
}

fn built() -> Built {
    let seed = first_half(b"cairn signature vector");
    let message = first_half(b"cairn signature vector message");
    let secret = SecretKey::from_bytes(&seed);
    let public = secret.public_key();
    let a = SigningKey::from_bytes(&seed).to_scalar();
    assert_eq!(
        (a * ED25519_BASEPOINT_POINT).compress().to_bytes(),
        public.to_bytes(),
        "the scalar taken from the seed is not the one behind the public key"
    );
    let a_bytes = public.to_bytes();

    // 1: the signature the key makes.
    let honest = secret.sign(&message).to_bytes();

    // 2: the same signature with L added to S. The group order is read from
    // the scalar type, as one more than the largest scalar there is.
    let order = add_le(
        &(Scalar::ZERO - Scalar::ONE).to_bytes(),
        &Scalar::ONE.to_bytes(),
    );
    let s = <[u8; 32]>::try_from(&honest[32..]).unwrap();
    let lifted = joined(
        <[u8; 32]>::try_from(&honest[..32]).unwrap(),
        add_le(&s, &order),
    );

    // 3: R the identity, which is of small order, and S = k a.
    let identity = EdwardsPoint::identity().compress().to_bytes();
    let k = challenge(&identity, &a_bytes, &message);
    let small = joined(identity, (k * a).to_bytes());

    // 4: R = r B + T for T of order eight, and S = r + k a.
    let r = Scalar::from_bytes_mod_order_wide(&sha512(b"cairn signature vector nonce"));
    let torsion = EIGHT_TORSION[1];
    let point = (r * ED25519_BASEPOINT_POINT + torsion)
        .compress()
        .to_bytes();
    let k = challenge(&point, &a_bytes, &message);
    let twisted = joined(point, (r + k * a).to_bytes());

    Built {
        public,
        message,
        signatures: [honest, lifted, small, twisted],
    }
}

/// The sum of two 256 bit little-endian integers, which here never carries
/// out of the top byte: `S` is below `L`, and `L` is below 2^253.
fn add_le(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for (slot, (one, other)) in out.iter_mut().zip(left.iter().zip(right)) {
        let sum = u16::from(*one) + u16::from(*other) + carry;
        *slot = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "a sum of two scalars carried out of 256 bits");
    out
}

// ---------------------------------------------------------------------------
// The vectors, read.
// ---------------------------------------------------------------------------

/// The block of vectors in the document: the fenced block that opens on the
/// line naming the seed.
fn published_block() -> &'static str {
    SPECIFICATION
        .split("```")
        .map(|block| block.strip_prefix("text").unwrap_or(block).trim_start())
        .find(|block| block.starts_with("seed "))
        .expect("the specification publishes no block of signature vectors")
}

/// The value on the line that begins with `label`.
fn published(label: &str) -> &'static str {
    published_block()
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(label))
        .map_or_else(
            || panic!("the vectors have no line for `{label}`"),
            str::trim,
        )
}

/// Every numbered vector in the block, in order.
fn published_vectors() -> Vec<Vector> {
    let mut vectors: Vec<Vector> = Vec::new();
    for line in published_block().lines().map(str::trim) {
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some(number), Some(verdict)) if number.parse::<usize>().is_ok() => {
                vectors.push(Vector {
                    accepted: verdict == "accepted",
                    r: String::new(),
                    s: String::new(),
                });
            }
            (Some("R"), Some(value)) => value.clone_into(&mut vectors.last_mut().unwrap().r),
            (Some("S"), Some(value)) => value.clone_into(&mut vectors.last_mut().unwrap().s),
            _ => {}
        }
    }
    vectors
}

/// **The document's vectors are the ones the RFC's arithmetic makes, and this
/// crate gives each the verdict the document states.**
///
/// Nothing held either before. The document published no vector and no rule,
/// so a second implementer had nothing to check a verifier against, and this
/// crate could have moved from `verify_strict` to the permissive `verify` with
/// every test in the workspace passing and every node built after it taking
/// spends every node built before it refuses.
#[test]
fn the_published_vectors_are_the_ones_the_rule_decides() {
    let built = built();
    println!(
        "public key {}\nmessage    {}",
        cairn_primitives::hex::encode(&built.public.to_bytes()),
        cairn_primitives::hex::encode(&built.message)
    );
    for signature in &built.signatures {
        println!(
            "R {}\nS {}",
            cairn_primitives::hex::encode(&signature[..32]),
            cairn_primitives::hex::encode(&signature[32..])
        );
    }
    assert_eq!(
        published("public key"),
        cairn_primitives::hex::encode(&built.public.to_bytes()),
        "the document's public key is not the one its seed makes"
    );
    assert_eq!(
        published("message"),
        cairn_primitives::hex::encode(&built.message),
        "the document's message is not the one it says it derives"
    );

    let vectors = published_vectors();
    assert_eq!(
        vectors.len(),
        built.signatures.len(),
        "the document publishes a different number of signature vectors"
    );
    for (number, (vector, signature)) in vectors.iter().zip(&built.signatures).enumerate() {
        let accepted = built
            .public
            .verify(&built.message, &Signature::from_bytes(signature))
            .is_ok();
        let expected = Vector {
            accepted,
            r: cairn_primitives::hex::encode(&signature[..32]),
            s: cairn_primitives::hex::encode(&signature[32..]),
        };
        assert_eq!(
            vector,
            &expected,
            "vector {} in the document is not the signature it describes with the verdict \
             this build reaches",
            number + 1
        );
    }
}

/// **The three the rule refuses are ones a verifier written to RFC 8032
/// alone would take, so the rule is what decides them.**
///
/// The second is refused by the RFC too, but only by its range check on `S`:
/// with `S` reduced, the equation holds. The third holds under both of the
/// RFC's equations and is refused only for the order of `R`. The fourth holds
/// under the cofactored equation the RFC states first. Were any of them
/// refused by the RFC's arithmetic as well, the vector would show nothing
/// about the rule and the document would be publishing a test of nothing.
#[test]
fn every_refused_vector_is_one_the_rfc_alone_would_let_through() {
    let built = built();
    let key = built.public.to_bytes();
    let [honest, lifted, small, twisted] = built.signatures;

    assert_eq!(
        rfc8032(&key, &built.message, &honest),
        Some((true, true)),
        "the arithmetic here does not make a signature the RFC accepts, so every \
         vector below measures a mistake in this file"
    );

    assert_eq!(rfc8032(&key, &built.message, &lifted), None);
    let mut reduced = lifted;
    let s = Scalar::from_bytes_mod_order(<[u8; 32]>::try_from(&lifted[32..]).unwrap());
    reduced[32..].copy_from_slice(&s.to_bytes());
    assert_eq!(
        reduced, honest,
        "S plus L does not reduce to the first S, so the second vector is not the \
         first signature spelled a second way"
    );

    assert_eq!(
        rfc8032(&key, &built.message, &small),
        Some((true, true)),
        "a small order R with S = k a does not satisfy the RFC's equations, so the \
         third vector shows nothing about the order rule"
    );
    assert_eq!(
        rfc8032(&key, &built.message, &twisted),
        Some((false, true)),
        "a torsion R does not split the RFC's two equations, so the fourth vector \
         shows nothing about the cofactor"
    );
}

/// **The document states the rule, in the words a second implementer acts on.**
///
/// It said "Ed25519" and nothing else, which is the one sentence a second
/// implementation could not get right by reading.
#[test]
fn the_specification_states_the_verification_rule() {
    let flowing = SPECIFICATION
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for said in [
        "no prehash and no context",
        "`S`, read as a 256-bit little-endian integer, is below `L`",
        "`R` is the canonical encoding of a point on the curve",
        "that point is not of small order",
        "`[S]B = R + [k]A`",
        "without multiplying either side by the cofactor",
    ] {
        assert!(
            flowing.contains(said),
            "the specification does not say `{said}`, which is part of the rule \
             every node verifies signatures by"
        );
    }
}

/// **The whitepaper and the site name every restriction the code applies.**
///
/// Both said Ed25519 "with two restrictions beyond the standard", small order
/// keys and non-canonical encodings, after the torsion refusal had made it
/// three on keys and with the verification rule, the one a second
/// implementation could not guess, not named at all. The crate header said
/// two as well. The same claim in three places, corrected in the one a test
/// read.
#[test]
fn the_papers_name_every_restriction_the_code_applies() {
    let paper = include_str!("../../../docs/cairn-whitepaper.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let english = include_str!("../../../web/i18n/en.json");
    let french = include_str!("../../../web/i18n/fr.json");
    for (page, text) in [("whitepaper", paper.as_str()), ("English site", english)] {
        for said in [
            "canonically encoded",
            "not of small order",
            "prime order subgroup",
            "cofactorless equation",
        ] {
            assert!(
                text.contains(said),
                "the {page} does not say `{said}`, which is one of the restrictions every \
                 node applies"
            );
        }
        assert!(
            !text.contains("two restrictions"),
            "the {page} still counts two restrictions"
        );
    }
    assert!(
        french.contains("sous-groupe d'ordre premier") && french.contains("sans cofacteur"),
        "the French site does not name the subgroup rule and the cofactorless equation"
    );
    assert!(
        !french.contains("deux restrictions"),
        "the French site still counts two restrictions"
    );
}

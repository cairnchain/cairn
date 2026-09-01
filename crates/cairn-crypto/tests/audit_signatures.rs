//! Adversarial audit of key parsing, signature verification and the codec.
//!
//! Three questions: can a key be spelled two ways, can a signature be
//! transformed into a second valid signature, and can anything here be made to
//! panic or to accept on attacker chosen bytes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use cairn_crypto::{
    random_bytes, CryptoError, PublicKey, SecretKey, Signature, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
    SIGNATURE_LEN,
};
use cairn_primitives::codec::{Decode, Encode};

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for slot in &mut out {
            *slot = self.next_u64() as u8;
        }
        out
    }
}

/// 2^255 - 19, little endian. Any y at or above this is a second spelling.
const FIELD_MODULUS_LE: [u8; PUBLIC_KEY_LEN] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The order of the prime subgroup, little endian. s must be reduced modulo it.
const GROUP_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn add_256_le(left: &[u8; 32], right: &[u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        out[index] = sum as u8;
        carry = sum >> 8;
    }
    (out, carry != 0)
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; SECRET_KEY_LEN])
}

#[test]
fn every_non_canonical_y_is_refused() {
    // There are exactly nineteen values of y at or above the field modulus,
    // 2^255-19 through 2^255-1, and each has two spellings once the sign bit
    // is counted. All thirty-eight must be refused, or a key that decodes to
    // one point would have more than one identifier.
    let mut refused = 0;
    for offset in 0..19u8 {
        let mut y = FIELD_MODULUS_LE;
        y[0] += offset; // 0xed..0xff, no carry out of the low byte
        for sign in [0x00u8, 0x80] {
            let mut candidate = y;
            candidate[31] |= sign;
            assert_eq!(
                PublicKey::from_bytes(&candidate),
                Err(CryptoError::NonCanonicalPublicKey),
                "y = p + {offset}, sign {sign:#x} was not refused"
            );
            refused += 1;
        }
    }
    assert_eq!(refused, 38);

    // And the value one below the modulus is not caught by this rule, which is
    // the boundary being in the right place rather than one out.
    let mut just_below = FIELD_MODULUS_LE;
    just_below[0] -= 1;
    assert_ne!(
        PublicKey::from_bytes(&just_below),
        Err(CryptoError::NonCanonicalPublicKey),
        "p - 1 is a canonical y and must be refused for another reason"
    );
}

#[test]
fn the_remaining_non_canonical_spellings_are_refused_as_weak() {
    // The other family of non canonical encodings is x = 0 with the sign bit
    // set, which is only ever y = 1 or y = p - 1. Both are small order, so the
    // weak check is what closes the gap the canonicality check leaves open.
    let mut identity = [0u8; PUBLIC_KEY_LEN];
    identity[0] = 1;
    let mut order_two = FIELD_MODULUS_LE;
    order_two[0] -= 1; // y = p - 1

    for base in [identity, order_two] {
        for sign in [0x00u8, 0x80] {
            let mut candidate = base;
            candidate[31] |= sign;
            assert_eq!(
                PublicKey::from_bytes(&candidate),
                Err(CryptoError::WeakPublicKey),
                "x = 0 spelling {sign:#x} was accepted"
            );
        }
    }
}

#[test]
fn every_small_order_point_is_refused() {
    // The eight points of order dividing eight, in every spelling. A note
    // locked to one of these could be spent by anyone, because a signature
    // under a small order key verifies against almost any message under
    // permissive rules.
    let small_order: [[u8; PUBLIC_KEY_LEN]; 8] = [
        [0u8; PUBLIC_KEY_LEN],
        {
            let mut point = [0u8; PUBLIC_KEY_LEN];
            point[31] = 0x80;
            point
        },
        {
            let mut point = [0u8; PUBLIC_KEY_LEN];
            point[0] = 1;
            point
        },
        {
            let mut point = [0u8; PUBLIC_KEY_LEN];
            point[0] = 1;
            point[31] = 0x80;
            point
        },
        {
            let mut point = FIELD_MODULUS_LE;
            point[0] -= 1;
            point
        },
        {
            let mut point = FIELD_MODULUS_LE;
            point[0] -= 1;
            point[31] = 0xff;
            point
        },
        [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ],
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ],
    ];
    for point in small_order {
        assert_eq!(
            PublicKey::from_bytes(&point),
            Err(CryptoError::WeakPublicKey),
            "small order point accepted"
        );
    }
}

#[test]
fn a_public_key_has_exactly_one_encoding() {
    // The second direction of the round trip, over every key the parser will
    // take: whatever it accepted must come back out as the same bytes.
    let mut rng = Rng::new(0xc0ff_ee01);
    let mut accepted = 0usize;
    for _ in 0..40_000 {
        let candidate: [u8; PUBLIC_KEY_LEN] = rng.array();
        match PublicKey::from_bytes(&candidate) {
            Ok(public) => {
                assert_eq!(public.to_bytes(), candidate);
                assert_eq!(public.encode(), candidate.to_vec());
                assert_eq!(PublicKey::decode(&public.encode()).unwrap(), public);
                accepted += 1;
            }
            Err(error) => {
                assert!(PublicKey::decode(&candidate).is_err(), "{error:?}");
            }
        }
    }
    // Roughly half of random strings decompress to a point; a run that
    // accepted nothing would mean the fuzz never exercised the accepting path.
    assert!(accepted > 10_000, "only {accepted} accepted");
}

#[test]
fn adding_the_group_order_to_s_does_not_make_a_second_valid_signature() {
    // The classic Ed25519 malleability: s and s + L are congruent, so a
    // permissive verifier accepts both and the same authorisation exists under
    // two different sixty-four byte strings.
    let secret = key(11);
    let public = secret.public_key();
    let message = b"pay one cairn to bob";
    let signature = secret.sign(message);
    assert!(public.verify(message, &signature).is_ok());

    let bytes = signature.to_bytes();
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes[32..64]);
    let (malleable_s, overflowed) = add_256_le(&s, &GROUP_ORDER_LE);
    assert!(!overflowed, "s + L must still fit in 32 bytes");
    assert_ne!(malleable_s, s, "the transform must change the bytes");

    let mut malleable = [0u8; SIGNATURE_LEN];
    malleable[..32].copy_from_slice(&bytes[..32]);
    malleable[32..].copy_from_slice(&malleable_s);
    assert_ne!(malleable, bytes);

    let second = Signature::from_bytes(&malleable);
    assert_eq!(
        public.verify(message, &second),
        Err(CryptoError::BadSignature),
        "s + L was accepted: signatures are malleable"
    );

    // Two more turns of the same handle, in case one L happened to land in a
    // range the check waves through.
    let (twice, _) = add_256_le(&malleable_s, &GROUP_ORDER_LE);
    let mut third = malleable;
    third[32..].copy_from_slice(&twice);
    assert_eq!(
        public.verify(message, &Signature::from_bytes(&third)),
        Err(CryptoError::BadSignature)
    );
}

#[test]
fn the_high_bits_of_s_cannot_be_set() {
    let secret = key(12);
    let public = secret.public_key();
    let message = b"message";
    let bytes = secret.sign(message).to_bytes();
    for bit in [0x20u8, 0x40, 0x80] {
        let mut tampered = bytes;
        tampered[63] |= bit;
        assert_eq!(
            public.verify(message, &Signature::from_bytes(&tampered)),
            Err(CryptoError::BadSignature),
            "s with bit {bit:#x} set was accepted"
        );
    }
}

#[test]
fn a_tampered_r_is_refused_in_every_shape() {
    let secret = key(13);
    let public = secret.public_key();
    let message = b"message";
    let bytes = secret.sign(message).to_bytes();

    // The sign bit of R flipped names a different point.
    let mut flipped = bytes;
    flipped[31] ^= 0x80;
    assert_eq!(
        public.verify(message, &Signature::from_bytes(&flipped)),
        Err(CryptoError::BadSignature)
    );

    // R above the field modulus: a second spelling of some point, refused
    // because the recomputed R is always written canonically.
    let mut non_canonical = bytes;
    non_canonical[..32].copy_from_slice(&FIELD_MODULUS_LE);
    assert_eq!(
        public.verify(message, &Signature::from_bytes(&non_canonical)),
        Err(CryptoError::BadSignature)
    );

    // R a small order point, which is what makes a forged signature verify
    // under cofactored rules.
    let mut small_order = bytes;
    small_order[..32].copy_from_slice(&[0u8; 32]);
    assert_eq!(
        public.verify(message, &Signature::from_bytes(&small_order)),
        Err(CryptoError::BadSignature)
    );

    // Every single byte of the signature matters.
    for index in 0..SIGNATURE_LEN {
        let mut one_bit = bytes;
        one_bit[index] ^= 0x01;
        assert_eq!(
            public.verify(message, &Signature::from_bytes(&one_bit)),
            Err(CryptoError::BadSignature),
            "flipping bit 0 of byte {index} still verified"
        );
    }
}

#[test]
fn the_placeholder_signature_verifies_against_nothing() {
    // `Signature::unsigned` is a well formed value that decodes and encodes
    // like any other. The only thing between it and an unauthorised spend is
    // that verification is actually performed on every input.
    let blank = Signature::unsigned();
    assert_eq!(blank.to_bytes(), [0u8; SIGNATURE_LEN]);
    assert_eq!(Signature::decode(&blank.encode()).unwrap(), blank);

    let mut rng = Rng::new(0xc0ff_ee02);
    for _ in 0..64 {
        let secret = SecretKey::from_bytes(&rng.array());
        let public = secret.public_key();
        for message in [b"".as_slice(), b"x", &rng.array::<32>()] {
            assert_eq!(
                public.verify(message, &blank),
                Err(CryptoError::BadSignature)
            );
        }
    }
}

#[test]
fn verification_never_panics_and_never_accepts_on_arbitrary_bytes() {
    let secret = key(14);
    let public = secret.public_key();
    let mut rng = Rng::new(0xc0ff_ee03);
    for _ in 0..30_000 {
        let bytes: [u8; SIGNATURE_LEN] = rng.array();
        let signature = Signature::from_bytes(&bytes);
        assert_eq!(
            public.verify(b"message", &signature),
            Err(CryptoError::BadSignature)
        );
        // And through the codec, which is what the wire actually hands over.
        if let Ok(decoded) = Signature::decode(&bytes) {
            assert_eq!(decoded.encode(), bytes.to_vec());
            assert!(public.verify(b"message", &decoded).is_err());
        }
    }
}

#[test]
fn a_signature_survives_the_codec_byte_for_byte() {
    // The decoder takes all 2^512 strings, including scalars no signer would
    // ever produce. That is safe only because the encoder writes back exactly
    // what it read: one value, one spelling, junk included.
    let mut rng = Rng::new(0xc0ff_ee04);
    for _ in 0..20_000 {
        let bytes: [u8; SIGNATURE_LEN] = rng.array();
        let decoded = Signature::decode(&bytes).unwrap();
        assert_eq!(decoded.encode(), bytes.to_vec());
        assert_eq!(decoded.to_bytes(), bytes);
        assert_eq!(Signature::from_bytes(&bytes), decoded);
    }
    // Length is fixed: nothing shorter or longer is a signature frame.
    assert!(Signature::decode(&[0u8; SIGNATURE_LEN - 1]).is_err());
    assert!(Signature::decode(&[0u8; SIGNATURE_LEN + 1]).is_err());
}

#[test]
fn a_public_key_frame_is_refused_rather_than_carried() {
    // A non canonical or weak key must not survive decoding, or a note could
    // be locked to a key with two names or no secret.
    let mut weak = [0u8; PUBLIC_KEY_LEN];
    weak[0] = 1;
    assert!(PublicKey::decode(&weak).is_err());
    assert!(PublicKey::decode(&[0xff; PUBLIC_KEY_LEN]).is_err());
    assert!(PublicKey::decode(&FIELD_MODULUS_LE).is_err());
    assert!(PublicKey::decode(&[0u8; PUBLIC_KEY_LEN - 1]).is_err());
    assert!(PublicKey::decode(&[0u8; PUBLIC_KEY_LEN + 1]).is_err());
}

#[test]
fn a_signature_does_not_carry_to_another_message_or_key() {
    let mut rng = Rng::new(0xc0ff_ee05);
    for _ in 0..64 {
        let mine = SecretKey::from_bytes(&rng.array());
        let theirs = SecretKey::from_bytes(&rng.array());
        let message: [u8; 32] = rng.array();
        let mut other = message;
        other[0] ^= 0x01;

        let signature = mine.sign(&message);
        assert!(mine.public_key().verify(&message, &signature).is_ok());
        assert_eq!(
            mine.public_key().verify(&other, &signature),
            Err(CryptoError::BadSignature)
        );
        assert_eq!(
            theirs.public_key().verify(&message, &signature),
            Err(CryptoError::BadSignature)
        );
    }
}

#[test]
fn a_freshly_generated_key_is_always_usable() {
    // Generation must never hand back a key the parser would refuse, and the
    // entropy source must not be quietly returning the same thing twice.
    let mut seen: Vec<[u8; SECRET_KEY_LEN]> = Vec::new();
    for _ in 0..256 {
        let secret = SecretKey::generate().unwrap();
        let bytes = secret.to_bytes();
        assert!(!seen.contains(&bytes), "the entropy source repeated itself");
        seen.push(bytes);

        let public = secret.public_key();
        assert_eq!(PublicKey::from_bytes(&public.to_bytes()), Ok(public));

        let message = b"a message";
        assert!(public.verify(message, &secret.sign(message)).is_ok());
    }

    // Every clamped scalar is far from small order, including the degenerate
    // seeds a caller might supply directly.
    for seed in [[0u8; 32], [0xff; 32], [0x01; 32]] {
        let public = SecretKey::from_bytes(&seed).public_key();
        assert_eq!(PublicKey::from_bytes(&public.to_bytes()), Ok(public));
    }
}

#[test]
fn the_general_entropy_helper_does_not_repeat_itself() {
    let mut seen: Vec<[u8; 16]> = Vec::new();
    for _ in 0..512 {
        let bytes = random_bytes::<16>().unwrap();
        assert!(!seen.contains(&bytes));
        assert_ne!(bytes, [0u8; 16], "all zeroes is not entropy");
        seen.push(bytes);
    }
}

#[test]
fn the_crate_applies_no_domain_separation_of_its_own() {
    // Written down rather than assumed: `sign` puts nothing around the bytes
    // it is handed. Whatever separates one signed thing from another lives
    // entirely in the caller, so any future call site that signs something
    // other than a domain separated digest is a cross protocol replay.
    let secret = key(15);
    let public = secret.public_key();
    let digest = [0x11u8; 32];
    let signature = secret.sign(&digest);
    assert!(public.verify(&digest, &signature).is_ok());
    // The same bytes in any other role verify just as happily.
    assert!(public.verify(digest.as_slice(), &signature).is_ok());
}

#[test]
fn a_secret_key_never_prints_or_compares_its_material() {
    let secret = key(16);
    assert_eq!(format!("{secret:?}"), "SecretKey(redacted)");
    assert!(!format!("{secret:?}").contains("10"));
    // The public half is the only thing with equality and ordering on it, and
    // it is public by definition.
    let a = key(17).public_key();
    let b = key(18).public_key();
    assert_eq!(a.cmp(&b), a.to_bytes().cmp(&b.to_bytes()));
}

#[test]
fn the_scheme_still_produces_the_signature_it_used_to() {
    // Ed25519 signing is deterministic, so a fixed seed and a fixed message
    // pin the whole scheme: the curve, the hash, the clamping and the byte
    // order. Nothing in the workspace pinned any of that before. A change to
    // any of it invalidates every signature ever made on the network, and
    // without this it would show up as a fork rather than as a failing test.
    let secret = SecretKey::from_bytes(&[0x2a; SECRET_KEY_LEN]);
    let public = secret.public_key();
    assert_eq!(
        public.to_string(),
        "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61"
    );
    let signature = secret.sign(b"cairn audit vector");
    assert_eq!(
        cairn_primitives::hex::encode(&signature.to_bytes()),
        "d482cad617d9bf3b983bc800c98febdb5d24346b1bd87047cb1f5c10d9629be7d4a251f44f1919e2549b375e820ad92177ba75cb50c7087c369e83e7a06f190d"
    );
    assert!(public.verify(b"cairn audit vector", &signature).is_ok());
}

//! Addresses that decode, that nobody can spend from, and that this crate said
//! it refused.
//!
//! The crate's own header argued: "Small order public keys are refused at
//! construction, so a note can never be locked to a key that has no usable
//! secret." The refusal is real. The conclusion does not follow from it.
//!
//! Ed25519's group has a cofactor of eight, so a point can carry a torsion
//! component: `A + T` where `A` is somebody's real key and `T` is one of the
//! seven non-identity points of order dividing eight. Such a point is
//! canonically encoded, decodes cleanly, and is not of small order, so every
//! check this crate had let it through. No secret key this crate can make will
//! ever sign under it, because Ed25519 clamping clears the low three bits of
//! the scalar and a public key is therefore always eight times something,
//! which lands in the prime order subgroup.
//!
//! What that cost: a note locked to such an address is invisible to the
//! recipient's wallet, which matches on its own public key, and unspendable by
//! every program in this workspace. Seven of every eight byte strings the
//! parser accepted were addresses nobody held.
//!
//! The rule added for it is a consensus rule, so the question is not only
//! whether it is right but whether it can ever refuse an honest key. The
//! second test here holds that, over keys rather than over an argument about
//! clamping: an argument about clamping is exactly the shape of true sentence
//! this project keeps finding in front of a wrong answer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cairn_crypto::{CryptoError, PublicKey, SecretKey};
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::CompressedEdwardsY;

/// A real key, as a point that can be added to.
fn point_of(seed: u8) -> (curve25519_dalek::edwards::EdwardsPoint, [u8; 32]) {
    let bytes = SecretKey::from_bytes(&[seed; 32]).public_key().to_bytes();
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .expect("a key this crate made decompresses");
    (point, bytes)
}

/// Every point of the torsion subgroup, added to a real key.
///
/// Derived rather than pinned. One hard coded sum would be one point of eight,
/// and the claim is about the subgroup.
#[test]
fn a_key_carrying_any_torsion_at_all_is_refused() {
    for seed in [3u8, 11, 42, 200] {
        let (point, plain) = point_of(seed);

        assert_eq!(
            PublicKey::from_bytes(&plain).map(PublicKey::to_bytes),
            Ok(plain),
            "the key itself has to be taken, or this test is measuring nothing"
        );

        for (index, torsion) in EIGHT_TORSION.iter().enumerate() {
            let sum = (point + torsion).compress().to_bytes();
            if index == 0 {
                assert_eq!(sum, plain, "the identity is the identity");
                continue;
            }
            assert!(
                sum != plain,
                "adding torsion point {index} to key {seed} changed nothing, so this \
                 test is asking the same question eight times"
            );
            assert_eq!(
                PublicKey::from_bytes(&sum),
                Err(CryptoError::UnusablePublicKey),
                "key {seed} plus torsion point {index} was taken as an address. Nothing \
                 this crate can make will ever sign under it, so a note paid to it is \
                 gone."
            );
            // And the wire path agrees with the constructor, because a rule
            // enforced at one of the two is a rule with a way round it.
            assert!(
                <PublicKey as cairn_primitives::codec::Decode>::decode(sum.as_ref()).is_err(),
                "it was refused by the constructor and taken off the wire"
            );
        }
    }
}

/// Every key this crate can make is one it will take back.
///
/// The rule above is a consensus rule: a node that refuses a key its peers
/// accept follows a different chain. So what matters as much as the refusal
/// being right is that it can never fire on an honest key. Clamping says it
/// cannot. This counts.
#[test]
fn every_key_this_crate_makes_is_one_it_will_take_back() {
    let mut made = 0usize;
    for seed in 0u32..4_000 {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&seed.to_le_bytes());
        let key = SecretKey::from_bytes(&bytes).public_key().to_bytes();
        assert_eq!(
            PublicKey::from_bytes(&key).map(PublicKey::to_bytes),
            Ok(key),
            "a key this crate made was refused by the rule this crate enforces, which on \
             a chain is a node following a branch of its own"
        );
        made = made.saturating_add(1);
    }
    assert_eq!(made, 4_000);
}

/// And a key that was already refused still is, for the reason it was.
///
/// The new refusal sits after the old two, so a point that is small order or
/// not canonically encoded has to keep coming back under its own name: an
/// error that changed would send whoever reads it looking in the wrong place.
#[test]
fn the_refusals_that_were_there_still_say_what_they_said() {
    let identity = [0u8; 32];
    assert_eq!(
        PublicKey::from_bytes(&identity),
        Err(CryptoError::WeakPublicKey)
    );

    let above_the_field = [0xff; 32];
    assert_eq!(
        PublicKey::from_bytes(&above_the_field),
        Err(CryptoError::NonCanonicalPublicKey)
    );
}

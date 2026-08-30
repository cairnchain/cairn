//! Signing keys and signature verification.
//!
//! Cairn signs with Ed25519, with two restrictions over the bare scheme.
//!
//! Small order public keys are refused at construction, so a note can never be
//! locked to a key that has no usable secret. The reference implementation only
//! rejects them at verification time, which is late: by then the note exists.
//!
//! Public keys must also be canonically encoded. The reference implementation
//! keeps the bytes it was given rather than re encoding the point, so two
//! different byte strings can name the same key. That would break the one
//! representation per value rule the wire format relies on, and would give a
//! note two distinct identifiers.
//!
//! Verification uses the strict variant, which rejects non canonical signature
//! encodings. Permissive verification accepts signatures that some
//! implementations reject, and a signature that is valid on one node and
//! invalid on another splits the chain.

use std::fmt;

use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use ed25519_dalek::{Signature as DalekSignature, SigningKey, VerifyingKey};

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("public key is not a valid Ed25519 point")]
    MalformedPublicKey,
    #[error("public key has small order and no usable secret")]
    WeakPublicKey,
    #[error("public key is not canonically encoded")]
    NonCanonicalPublicKey,
    #[error("signature does not verify against this key and message")]
    BadSignature,
    #[error("the operating system refused to provide entropy")]
    NoEntropy,
}

/// A secret signing key.
///
/// The inner key zeroes its own memory on drop. `Debug` is implemented by hand
/// so the key material can never reach a log through a derived formatter.
pub struct SecretKey(SigningKey);

// Nothing here wipes the key on the way out, and it does not have to: the
// workspace builds ed25519-dalek with its `zeroize` feature, so the
// `SigningKey` inside clears itself when it is dropped. Said out loud because
// the absence of a `Drop` on a type holding a private key is the first thing
// worth asking about, and the answer is a line in a manifest.

/// Draws `N` bytes from the operating system entropy source.
///
/// For the things that are not keys and must still be unguessable: the secret
/// a wallet puts in the address of the page it serves, so that a page loaded
/// from anywhere else cannot ask it anything. Here rather than in the caller
/// because this is where entropy already comes from, and a second way of
/// asking for randomness is a second way of getting it wrong.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::NoEntropy)?;
    Ok(bytes)
}

impl SecretKey {
    /// Draws a fresh key from the operating system entropy source.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; SECRET_KEY_LEN];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::NoEntropy)?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub fn from_bytes(bytes: &[u8; SECRET_KEY_LEN]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        Signature(self.0.sign(message))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(redacted)")
    }
}

/// Little endian encoding of the curve field modulus, 2^255 - 19.
const FIELD_MODULUS_LE: [u8; PUBLIC_KEY_LEN] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Whether `bytes` is the one encoding the curve assigns to its point.
///
/// The low 255 bits hold the y coordinate and the top bit holds the sign of x,
/// so an encoding is canonical exactly when y is reduced modulo the field. The
/// remaining non canonical forms are the two points where x is zero, and those
/// have small order and are rejected separately.
fn is_canonically_encoded(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    let mut y = *bytes;
    if let Some(most_significant) = y.last_mut() {
        *most_significant &= 0x7f;
    }
    for (candidate, modulus) in y.iter().rev().zip(FIELD_MODULUS_LE.iter().rev()) {
        match candidate.cmp(modulus) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

/// A public key. Notes are locked directly to one of these.
///
/// Ed25519 public keys are 32 bytes, the same size as a digest of one, so
/// hashing the key before locking a note to it would cost a preimage step
/// without saving any state.
///
/// The 32 bytes are what is kept, not the curve point they decode to. The
/// reference type holds both, which is right for a key that verifies often and
/// wrong for a key that sits in a note: a node holds one of these per hot note
/// and touches it once, when the note is spent. Keeping the point would be 160
/// bytes of precomputation per note against 32 bytes of key, and it is the
/// difference between a hot set that costs a phone 106 MB and one that costs
/// it 37. What it costs instead is decoding the point at every verification,
/// measured in `examples/verify.rs`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, CryptoError> {
        if !is_canonically_encoded(bytes) {
            return Err(CryptoError::NonCanonicalPublicKey);
        }
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::MalformedPublicKey)?;
        if key.is_weak() {
            return Err(CryptoError::WeakPublicKey);
        }
        Ok(Self(*bytes))
    }

    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Verifies `signature` over `message` under the strict rules.
    ///
    /// The point is decoded here rather than held. A key only exists having
    /// passed the checks above, so the decoding cannot fail; treating it as a
    /// bad signature keeps that from ever becoming a panic.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::BadSignature)?;
        key.verify_strict(message, &signature.0)
            .map_err(|_| CryptoError::BadSignature)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl Encode for PublicKey {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

impl Decode for PublicKey {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let bytes = reader.take_array::<PUBLIC_KEY_LEN>()?;
        Self::from_bytes(&bytes).map_err(|_| CodecError::InvalidValue {
            type_name: "PublicKey",
        })
    }
}

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(DalekSignature);

impl Signature {
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Self {
        Self(DalekSignature::from_bytes(bytes))
    }

    /// A placeholder that verifies against nothing.
    ///
    /// Signing an input requires the transaction identifier, which requires the
    /// transaction to exist, so inputs are built with this and filled in after.
    pub fn unsigned() -> Self {
        Self::from_bytes(&[0u8; SIGNATURE_LEN])
    }

    pub fn to_bytes(self) -> [u8; SIGNATURE_LEN] {
        self.0.to_bytes()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(")?;
        for byte in self.0.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl Encode for Signature {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_bytes());
    }
}

impl Decode for Signature {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self::from_bytes(&reader.take_array::<SIGNATURE_LEN>()?))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; SECRET_KEY_LEN])
    }

    #[test]
    fn a_signature_verifies_under_its_own_key() {
        let secret = key(1);
        let signature = secret.sign(b"message");
        assert!(secret.public_key().verify(b"message", &signature).is_ok());
    }

    #[test]
    fn a_signature_fails_on_another_message_or_key() {
        let secret = key(1);
        let signature = secret.sign(b"message");
        assert_eq!(
            secret.public_key().verify(b"other", &signature),
            Err(CryptoError::BadSignature)
        );
        assert_eq!(
            key(2).public_key().verify(b"message", &signature),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn signing_is_deterministic() {
        assert_eq!(key(3).sign(b"message"), key(3).sign(b"message"));
    }

    #[test]
    fn generated_keys_differ() {
        let first = SecretKey::generate().unwrap();
        let second = SecretKey::generate().unwrap();
        assert_ne!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn keys_and_signatures_roundtrip() {
        let secret = key(4);
        let public = secret.public_key();
        assert_eq!(PublicKey::decode(&public.encode()).unwrap(), public);
        let signature = secret.sign(b"message");
        assert_eq!(Signature::decode(&signature.encode()).unwrap(), signature);
    }

    #[test]
    fn small_order_public_keys_are_rejected() {
        // These encode points of order 1, 2, 4 and 8. A signature under one of
        // them can verify against messages its holder never signed.
        let small_order: [[u8; PUBLIC_KEY_LEN]; 4] = [
            [0u8; PUBLIC_KEY_LEN],
            {
                let mut key = [0u8; PUBLIC_KEY_LEN];
                key[0] = 1;
                key
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
        for key in small_order {
            assert_eq!(PublicKey::from_bytes(&key), Err(CryptoError::WeakPublicKey));
        }
    }

    #[test]
    fn non_canonical_public_keys_are_rejected() {
        // y above the field modulus, and y exactly equal to it.
        assert_eq!(
            PublicKey::from_bytes(&[0xff; PUBLIC_KEY_LEN]),
            Err(CryptoError::NonCanonicalPublicKey)
        );
        assert_eq!(
            PublicKey::from_bytes(&FIELD_MODULUS_LE),
            Err(CryptoError::NonCanonicalPublicKey)
        );
    }

    #[test]
    fn the_sign_bit_is_not_part_of_the_canonicality_check() {
        let mut key = key(6).public_key().to_bytes();
        assert!(is_canonically_encoded(&key));
        if let Some(most_significant) = key.last_mut() {
            *most_significant |= 0x80;
        }
        assert!(is_canonically_encoded(&key));
    }

    #[test]
    fn generated_keys_are_always_accepted() {
        for seed in 0..64u8 {
            let public = key(seed).public_key();
            assert_eq!(PublicKey::from_bytes(&public.to_bytes()), Ok(public));
        }
    }

    #[test]
    fn the_secret_key_never_prints_its_material() {
        assert_eq!(format!("{:?}", key(5)), "SecretKey(redacted)");
    }
}

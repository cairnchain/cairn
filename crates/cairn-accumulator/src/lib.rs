//! The state accumulator.
//!
//! A commitment to a set of key and value pairs that fits in 32 bytes, plus
//! proofs that let a holder show their entry belongs to the set without anyone
//! holding the set. This is what lets a node validate without storing the
//! ledger.
//!
//! The construction is a compact sparse Merkle tree. Only hash functions are
//! involved, which has three consequences that decided the choice.
//!
//! There is no trusted setup. The alternatives with shorter proofs require a
//! ceremony whose secret must be destroyed, and a participant who kept it could
//! forge membership proofs forever. A forged membership proof here mints money
//! from nothing, undetectably, which is not a risk a chain can carry.
//!
//! Verification is a few dozen hashes, fast enough for a phone.
//!
//! Hash functions are not broken by quantum computers, unlike the elliptic
//! curve and hidden order groups the shorter alternatives rest on. That holds
//! for this structure and not for the money in it: notes are locked to Ed25519
//! keys, and an address is the key itself, so the key is on the chain from the
//! moment a note is made.

pub mod forest;
pub mod key;
pub mod proof;
pub mod tree;

pub use forest::{Archive, Forest, ForestProof};
pub use key::{Key, KEY_LEN, MAX_DEPTH};
pub use proof::Proof;
pub use tree::{Change, SparseMerkleTree};

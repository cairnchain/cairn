//! Domain separated hashing.

use std::fmt;
use std::sync::OnceLock;

/// Length in bytes of every digest produced by this crate.
pub const HASH_LEN: usize = 32;

/// A 32 byte BLAKE3 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32([u8; HASH_LEN]);

impl Hash32 {
    /// The all zero digest, used as the parent of the genesis block.
    pub const ZERO: Self = Self([0u8; HASH_LEN]);

    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub const fn to_bytes(self) -> [u8; HASH_LEN] {
        self.0
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({self})")
    }
}

/// The hashing context a digest is computed under.
///
/// Each variant selects an independent hash function. A preimage hashed under
/// one context can never produce the same digest under another, so a value of
/// one kind can never be reinterpreted as a value of another kind. Adding a
/// variant is safe; changing an existing context string is a hard fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Domain {
    TransferId,
    CoinbaseId,
    BlockHeaderId,
    SignatureMessage,
    MerkleLeaf,
    MerkleNode,
    MerkleEmpty,
    StateEntry,
    AccumulatorEmpty,
    AccumulatorLeaf,
    AccumulatorNode,
    NoteKey,
    HotNoteValue,
    ColdNoteValue,
    StateCommitment,
    ForestLeaf,
    ForestNode,
    ForestRoots,
    HeaderHistoryLeaf,
    SamplingSeed,
    GraceWindow,
    ProofWindow,
}

impl Domain {
    const fn context(self) -> &'static str {
        match self {
            Self::TransferId => "cairn v1 transfer id",
            Self::CoinbaseId => "cairn v1 coinbase id",
            Self::BlockHeaderId => "cairn v1 block header id",
            Self::SignatureMessage => "cairn v1 signature message",
            Self::MerkleLeaf => "cairn v1 merkle leaf",
            Self::MerkleNode => "cairn v1 merkle node",
            Self::MerkleEmpty => "cairn v1 merkle empty",
            Self::StateEntry => "cairn v1 state entry",
            Self::AccumulatorEmpty => "cairn v1 accumulator empty",
            Self::AccumulatorLeaf => "cairn v1 accumulator leaf",
            Self::AccumulatorNode => "cairn v1 accumulator node",
            Self::NoteKey => "cairn v1 note key",
            Self::HotNoteValue => "cairn v1 hot note value",
            Self::ColdNoteValue => "cairn v1 cold note value",
            Self::StateCommitment => "cairn v1 state commitment",
            Self::ForestLeaf => "cairn v1 forest leaf",
            Self::ForestNode => "cairn v1 forest node",
            Self::ForestRoots => "cairn v1 forest roots",
            Self::HeaderHistoryLeaf => "cairn v1 header history leaf",
            Self::SamplingSeed => "cairn v1 sampling seed",
            Self::GraceWindow => "cairn v1 grace window",
            Self::ProofWindow => "cairn v1 proof window",
        }
    }
}

/// Per domain BLAKE3 keys, derived once and reused.
///
/// `blake3::derive_key` is deliberately expensive, so calling it on every hash
/// would dominate the cost of building a Merkle tree.
struct DomainKeys {
    transfer_id: [u8; HASH_LEN],
    coinbase_id: [u8; HASH_LEN],
    block_header_id: [u8; HASH_LEN],
    signature_message: [u8; HASH_LEN],
    merkle_leaf: [u8; HASH_LEN],
    merkle_node: [u8; HASH_LEN],
    merkle_empty: [u8; HASH_LEN],
    state_entry: [u8; HASH_LEN],
    accumulator_empty: [u8; HASH_LEN],
    accumulator_leaf: [u8; HASH_LEN],
    accumulator_node: [u8; HASH_LEN],
    note_key: [u8; HASH_LEN],
    hot_note_value: [u8; HASH_LEN],
    cold_note_value: [u8; HASH_LEN],
    state_commitment: [u8; HASH_LEN],
    forest_leaf: [u8; HASH_LEN],
    forest_node: [u8; HASH_LEN],
    forest_roots: [u8; HASH_LEN],
    header_history_leaf: [u8; HASH_LEN],
    sampling_seed: [u8; HASH_LEN],
    grace_window: [u8; HASH_LEN],
    proof_window: [u8; HASH_LEN],
}

fn domain_keys() -> &'static DomainKeys {
    static KEYS: OnceLock<DomainKeys> = OnceLock::new();
    KEYS.get_or_init(|| DomainKeys {
        transfer_id: blake3::derive_key(Domain::TransferId.context(), &[]),
        coinbase_id: blake3::derive_key(Domain::CoinbaseId.context(), &[]),
        block_header_id: blake3::derive_key(Domain::BlockHeaderId.context(), &[]),
        signature_message: blake3::derive_key(Domain::SignatureMessage.context(), &[]),
        merkle_leaf: blake3::derive_key(Domain::MerkleLeaf.context(), &[]),
        merkle_node: blake3::derive_key(Domain::MerkleNode.context(), &[]),
        merkle_empty: blake3::derive_key(Domain::MerkleEmpty.context(), &[]),
        state_entry: blake3::derive_key(Domain::StateEntry.context(), &[]),
        accumulator_empty: blake3::derive_key(Domain::AccumulatorEmpty.context(), &[]),
        accumulator_leaf: blake3::derive_key(Domain::AccumulatorLeaf.context(), &[]),
        accumulator_node: blake3::derive_key(Domain::AccumulatorNode.context(), &[]),
        note_key: blake3::derive_key(Domain::NoteKey.context(), &[]),
        hot_note_value: blake3::derive_key(Domain::HotNoteValue.context(), &[]),
        cold_note_value: blake3::derive_key(Domain::ColdNoteValue.context(), &[]),
        state_commitment: blake3::derive_key(Domain::StateCommitment.context(), &[]),
        forest_leaf: blake3::derive_key(Domain::ForestLeaf.context(), &[]),
        forest_node: blake3::derive_key(Domain::ForestNode.context(), &[]),
        forest_roots: blake3::derive_key(Domain::ForestRoots.context(), &[]),
        header_history_leaf: blake3::derive_key(Domain::HeaderHistoryLeaf.context(), &[]),
        sampling_seed: blake3::derive_key(Domain::SamplingSeed.context(), &[]),
        grace_window: blake3::derive_key(Domain::GraceWindow.context(), &[]),
        proof_window: blake3::derive_key(Domain::ProofWindow.context(), &[]),
    })
}

fn key_for(domain: Domain) -> &'static [u8; HASH_LEN] {
    let keys = domain_keys();
    match domain {
        Domain::TransferId => &keys.transfer_id,
        Domain::CoinbaseId => &keys.coinbase_id,
        Domain::BlockHeaderId => &keys.block_header_id,
        Domain::SignatureMessage => &keys.signature_message,
        Domain::MerkleLeaf => &keys.merkle_leaf,
        Domain::MerkleNode => &keys.merkle_node,
        Domain::MerkleEmpty => &keys.merkle_empty,
        Domain::StateEntry => &keys.state_entry,
        Domain::AccumulatorEmpty => &keys.accumulator_empty,
        Domain::AccumulatorLeaf => &keys.accumulator_leaf,
        Domain::AccumulatorNode => &keys.accumulator_node,
        Domain::NoteKey => &keys.note_key,
        Domain::HotNoteValue => &keys.hot_note_value,
        Domain::ColdNoteValue => &keys.cold_note_value,
        Domain::StateCommitment => &keys.state_commitment,
        Domain::ForestLeaf => &keys.forest_leaf,
        Domain::ForestNode => &keys.forest_node,
        Domain::ForestRoots => &keys.forest_roots,
        Domain::HeaderHistoryLeaf => &keys.header_history_leaf,
        Domain::SamplingSeed => &keys.sampling_seed,
        Domain::GraceWindow => &keys.grace_window,
        Domain::ProofWindow => &keys.proof_window,
    }
}

/// An incremental hasher bound to a single domain.
#[derive(Clone, Debug)]
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Hasher {
    pub fn new(domain: Domain) -> Self {
        Self {
            inner: blake3::Hasher::new_keyed(key_for(domain)),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.inner.update(bytes);
        self
    }

    pub fn finalize(&self) -> Hash32 {
        Hash32(*self.inner.finalize().as_bytes())
    }
}

/// Hashes `bytes` under `domain` in one call.
pub fn hash(domain: Domain, bytes: &[u8]) -> Hash32 {
    let mut hasher = Hasher::new(domain);
    hasher.update(bytes);
    hasher.finalize()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_independent() {
        let message = b"same bytes";
        assert_ne!(
            hash(Domain::TransferId, message),
            hash(Domain::CoinbaseId, message)
        );
        assert_ne!(
            hash(Domain::MerkleLeaf, message),
            hash(Domain::MerkleNode, message)
        );
    }

    #[test]
    fn hashing_is_deterministic() {
        assert_eq!(
            hash(Domain::TransferId, b"abc"),
            hash(Domain::TransferId, b"abc")
        );
        assert_ne!(
            hash(Domain::TransferId, b"abc"),
            hash(Domain::TransferId, b"abd")
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut hasher = Hasher::new(Domain::StateEntry);
        hasher.update(b"ab");
        hasher.update(b"cd");
        assert_eq!(hasher.finalize(), hash(Domain::StateEntry, b"abcd"));
    }

    #[test]
    fn display_is_lowercase_hex() {
        let digest = Hash32::from_bytes([0xab; HASH_LEN]);
        assert_eq!(digest.to_string(), "ab".repeat(HASH_LEN));
    }
}

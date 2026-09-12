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

/// Declares every hashing domain once, and writes out everything that has to
/// agree with it.
///
/// There were five listings of the same twenty one names: the enum, `ALL`,
/// `context`, the key struct with its derivation, and `key_for`. Three of
/// those the compiler demanded, because an exhaustive `match` and a struct
/// literal will not build with a name missing. `ALL` it did not, and `ALL` is
/// the one the guard against an unpinned domain rests on.
///
/// So the guard did not guard. Adding a variant with the three edits the
/// compiler asks for, and leaving it out of `ALL`, left its context string
/// pinned by nothing and every test passing, which is the exact state
/// `WalletHistory` was in from the day it was added. The note beside `ALL`
/// said "Rust offers no way to walk an enum, so a table with one row per
/// domain has to be written by hand". True, and the wrong question: what
/// matters is not whether an enum can be walked but whether the compiler can
/// be made to demand a row, and a macro that emits all five from one list is
/// how. There is now nothing to leave a domain out of.
///
/// On a crate where changing a context string invalidates every digest on the
/// network, the list below is the whole of what a reader has to check.
macro_rules! domains {
    ($($variant:ident => $field:ident, $context:literal;)+) => {
        /// The hashing context a digest is computed under.
        ///
        /// Each variant selects an independent hash function. A preimage
        /// hashed under one context can never produce the same digest under
        /// another, so a value of one kind can never be reinterpreted as a
        /// value of another kind. Adding a variant is safe; changing an
        /// existing context string is a hard fork.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Domain {
            $($variant,)+
        }

        impl Domain {
            /// Every domain this crate declares, in declaration order.
            ///
            /// Emitted from the same list as the enum, so it cannot be short
            /// of it. The vectors in `tests/audit_vectors.rs` are checked
            /// against this, and a domain with no vector fails a test rather
            /// than shipping.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The string this domain's key is derived from.
            ///
            /// Published, because a second implementer cannot reproduce a
            /// single identifier in this chain without it. The specification
            /// prints the same table, and `audit_vectors.rs` holds the two
            /// against each other.
            #[must_use]
            pub const fn context(self) -> &'static str {
                match self {
                    $(Self::$variant => $context,)+
                }
            }
        }

        /// Per domain BLAKE3 keys, derived once and reused.
        ///
        /// `blake3::derive_key` is deliberately expensive, so calling it on
        /// every hash would dominate the cost of building a Merkle tree.
        struct DomainKeys {
            $($field: [u8; HASH_LEN],)+
        }

        fn domain_keys() -> &'static DomainKeys {
            static KEYS: OnceLock<DomainKeys> = OnceLock::new();
            KEYS.get_or_init(|| DomainKeys {
                $($field: blake3::derive_key(Domain::$variant.context(), &[]),)+
            })
        }

        fn key_for(domain: Domain) -> &'static [u8; HASH_LEN] {
            let keys = domain_keys();
            match domain {
                $(Domain::$variant => &keys.$field,)+
            }
        }
    };
}

domains! {
    TransferId => transfer_id, "cairn v1 transfer id";
    CoinbaseId => coinbase_id, "cairn v1 coinbase id";
    BlockHeaderId => block_header_id, "cairn v1 block header id";
    SignatureMessage => signature_message, "cairn v1 signature message";
    MerkleLeaf => merkle_leaf, "cairn v1 merkle leaf";
    MerkleNode => merkle_node, "cairn v1 merkle node";
    MerkleEmpty => merkle_empty, "cairn v1 merkle empty";
    StateEntry => state_entry, "cairn v1 state entry";
    AccumulatorEmpty => accumulator_empty, "cairn v1 accumulator empty";
    AccumulatorLeaf => accumulator_leaf, "cairn v1 accumulator leaf";
    AccumulatorNode => accumulator_node, "cairn v1 accumulator node";
    NoteKey => note_key, "cairn v1 note key";
    HotNoteValue => hot_note_value, "cairn v1 hot note value";
    StateCommitment => state_commitment, "cairn v1 state commitment";
    ForestLeaf => forest_leaf, "cairn v1 forest leaf";
    ForestNode => forest_node, "cairn v1 forest node";
    ForestRoots => forest_roots, "cairn v1 forest roots";
    HeaderHistoryLeaf => header_history_leaf, "cairn v1 header history leaf";
    SamplingSeed => sampling_seed, "cairn v1 sampling seed";
    GraceWindow => grace_window, "cairn v1 grace window";
    WalletHistory => wallet_history, "cairn v1 wallet history";
}

/// Bytes hashed on this thread, for the audits that measure what one message
/// makes a node do.
///
/// The claim those tests hold the code to is that the work a peer can ask for
/// is bounded by the length of what it sent. That is a statement about a
/// count, and a test that timed it instead would be measuring whatever else
/// the machine was doing. Every digest in this workspace passes through
/// [`Hasher::update`], so counting there counts all of it.
///
/// Per thread, because tests run beside each other in one process and a
/// counter they shared would be a counter none of them could read.
///
/// Compiled only when the `count-hashing` feature is on, which the test builds
/// of the crates that audit this turn on and a node that ships does not.
#[cfg(feature = "count-hashing")]
pub mod counting {
    use std::cell::Cell;

    thread_local! {
        static HASHED: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn took(bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        HASHED.with(|held| held.set(held.get().saturating_add(bytes)));
    }

    /// Bytes this thread has fed to a hasher since it last called [`reset`].
    pub fn hashed() -> u64 {
        HASHED.with(Cell::get)
    }

    /// Starts the count over, and answers with what it had reached.
    pub fn reset() -> u64 {
        HASHED.with(|held| held.replace(0))
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
        #[cfg(feature = "count-hashing")]
        counting::took(bytes.len());
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

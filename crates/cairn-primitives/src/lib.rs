//! Primitive types shared by every Cairn crate.
//!
//! Everything here is consensus critical: two nodes that disagree on the output
//! of any function in this crate will disagree on the chain.

pub mod amount;
pub mod codec;
pub mod hash;
pub mod merkle;

pub use amount::Amount;
pub use codec::{CodecError, Decode, Encode, Reader};
pub use hash::{Domain, Hash32, Hasher, HASH_LEN};
pub use merkle::merkle_root;

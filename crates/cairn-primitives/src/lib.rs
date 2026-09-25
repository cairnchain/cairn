//! Primitive types shared by every Cairn crate.
//!
//! Everything here is consensus critical: two nodes that disagree on the output
//! of any function in this crate will disagree on the chain.

pub mod amount;
pub mod codec;
pub mod hash;
pub mod hex;
pub mod merkle;

pub use amount::Amount;
pub use codec::{Decode, Encode};
pub use hash::Hash32;

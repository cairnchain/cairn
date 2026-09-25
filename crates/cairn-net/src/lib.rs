//! Talking to other nodes.
//!
//! The layer is split so that the part which decides anything can be tested
//! without a network. [`sync`] is pure: messages in, messages out. [`node`]
//! is the plumbing that carries them over TCP and does not decide anything.

pub mod book;
pub mod choosing;
pub mod joining;
pub mod message;
pub mod node;
mod refusal;
pub mod seeds;
pub mod sync;
pub mod wire;

pub use joining::Joined;
pub use message::{Keeps, Message, PeerAddress, MAX_PROVEN, PROTOCOL_VERSION};
pub use node::{
    Filling, Node, NodeError, Restored, Unanswered, KEEP_BLOCK_BYTES, NAME_LOOKUP_PERIOD,
};

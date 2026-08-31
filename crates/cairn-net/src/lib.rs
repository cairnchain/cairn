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
pub mod refusal;
pub mod seeds;
pub mod sync;
pub mod wire;

pub use book::AddressBook;
pub use joining::Joined;
pub use message::{Handshake, Message, PeerAddress, PROTOCOL_VERSION};
pub use node::{Node, NodeError, Restored, KEEP_BLOCK_BYTES, NAME_LOOKUP_PERIOD};
pub use seeds::start_from;
pub use sync::{on_message, DropReason, Local, PeerState, Reaction};
pub use wire::{read_message, write_message, WireError, MAX_FRAME_BYTES};

//! The Cairn ledger: notes, transactions, blocks, and the rules that connect
//! one block to the next.
//!
//! Value is held in notes rather than balances. A note is created once, spent
//! once, and never modified, which is the shape a cryptographic accumulator
//! commits to most cheaply. The design document calls them bills.

pub mod block;
pub mod emission;
pub mod genesis;
pub mod handover;
pub mod note;
pub mod pow;
pub mod sampling;
pub mod state;
pub mod transaction;
pub mod validation;

pub use block::{Block, HeaderSummary};
pub use note::NetworkId;
pub use state::{
    cold_leaf, note_key, BlockUndo, ColdSpend, HotEntry, LedgerState, StateTransition,
};
pub use transaction::Witness;
pub use validation::{
    disconnect_block, BlockError, ConnectedBlock, ConsensusParams, TransferError,
};

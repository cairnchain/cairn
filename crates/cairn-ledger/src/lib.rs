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

pub use block::{Block, BlockHeader, HeaderSummary};
pub use note::{NetworkId, Note, NoteId};
pub use state::{
    cold_leaf, note_key, BlockUndo, ColdSet, ColdSpend, HotEntry, LedgerState, StateTransition, Tip,
};
pub use transaction::{CoinbaseTransaction, ColdWitness, Input, Transfer, Witness};
pub use validation::{
    connect_block, disconnect_block, BlockError, ConnectedBlock, ConsensusParams, TransferError,
};

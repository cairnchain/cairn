//! The Cairn ledger: notes, transactions, blocks, and the rules that connect
//! one block to the next.
//!
//! Value is held in notes rather than balances. A note is created once, spent
//! once, and never modified, which is the shape a cryptographic accumulator
//! commits to most cheaply. The design document calls them bills.

pub mod block;
pub mod note;
pub mod state;
pub mod transaction;
pub mod validation;

pub use block::{Block, BlockHeader};
pub use note::{NetworkId, Note, NoteId};
pub use state::{LedgerState, NoteResolver, Tip};
pub use transaction::{CoinbaseTransaction, Input, Transfer};
pub use validation::{connect_block, BlockError, ConsensusParams, TransferError};

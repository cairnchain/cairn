//! Consensus rules.
//!
//! Every rule here decides whether a block is valid. Two nodes that evaluate
//! any of them differently follow different chains, so nothing in this module
//! may depend on wall clock time, iteration order, or locale. The current time
//! is passed in rather than read.

use std::collections::HashSet;

use cairn_primitives::amount::PEBBLES_PER_CAIRN;
use cairn_primitives::{Amount, Hash32};

use crate::block::{Block, BlockHeader, BLOCK_VERSION};
use crate::note::{NetworkId, Note, NoteId};
use crate::state::{LedgerState, NoteResolver};
use crate::transaction::{CoinbaseTransaction, Transfer, COINBASE_VERSION, TRANSFER_VERSION};

/// Reward paid to the producer of a block.
///
/// Provisional. The emission schedule is an open question, and it is tied to
/// how archivists get paid.
const INITIAL_BLOCK_REWARD: Amount = match Amount::from_pebbles(50 * PEBBLES_PER_CAIRN) {
    Some(amount) => amount,
    None => Amount::ZERO,
};

/// Rules a node applies to every block it evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusParams {
    pub network: NetworkId,
    pub block_reward: Amount,
    pub max_transfers_per_block: usize,
    pub max_inputs_per_transfer: usize,
    pub max_outputs_per_transfer: usize,
    pub max_coinbase_outputs: usize,
    /// How far ahead of the receiving node's clock a timestamp may sit.
    pub max_timestamp_drift: u64,
}

impl ConsensusParams {
    pub const fn testnet() -> Self {
        Self {
            network: NetworkId::TESTNET,
            block_reward: INITIAL_BLOCK_REWARD,
            max_transfers_per_block: 4096,
            max_inputs_per_transfer: 256,
            max_outputs_per_transfer: 256,
            max_coinbase_outputs: 16,
            max_timestamp_drift: 2 * 60 * 60,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    #[error("transfer version {0} is not supported")]
    UnsupportedVersion(u16),
    #[error("a transfer must spend at least one note")]
    NoInputs,
    #[error("a transfer must create at least one note")]
    NoOutputs,
    #[error("transfer spends {count} notes, limit is {limit}")]
    TooManyInputs { count: usize, limit: usize },
    #[error("transfer creates {count} notes, limit is {limit}")]
    TooManyOutputs { count: usize, limit: usize },
    #[error("note {0:?} is spent twice in the same transfer")]
    DuplicateInput(NoteId),
    #[error("note {0:?} is unknown or already spent")]
    UnknownNote(NoteId),
    #[error("output {index} carries no value")]
    ZeroValueOutput { index: usize },
    #[error("summing values overflowed the monetary ceiling")]
    ValueOverflow,
    #[error("transfer creates {requested} from {available}")]
    OutputsExceedInputs {
        available: Amount,
        requested: Amount,
    },
    #[error("signature on input {input_index} does not verify")]
    InvalidSignature { input_index: usize },
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("block version {0} is not supported")]
    UnsupportedVersion(u16),
    #[error("coinbase version {0} is not supported")]
    UnsupportedCoinbaseVersion(u16),
    #[error("block belongs to network {found:?}, this node follows {expected:?}")]
    WrongNetwork {
        expected: NetworkId,
        found: NetworkId,
    },
    #[error("expected height {expected}, block claims {found}")]
    WrongHeight { expected: u64, found: u64 },
    #[error("expected parent {expected}, block claims {found}")]
    WrongParent { expected: Hash32, found: Hash32 },
    #[error("the chain has reached the maximum representable height")]
    HeightOverflow,
    #[error("header is at height {header}, coinbase claims {coinbase}")]
    CoinbaseHeightMismatch { header: u64, coinbase: u64 },
    #[error("block carries {count} transfers, limit is {limit}")]
    TooManyTransfers { count: usize, limit: usize },
    #[error("coinbase creates {count} notes, limit is {limit}")]
    TooManyCoinbaseOutputs { count: usize, limit: usize },
    #[error("coinbase output {index} carries no value")]
    ZeroValueCoinbaseOutput { index: usize },
    #[error("coinbase claims {claimed}, only {allowed} is available")]
    CoinbaseOverpay { allowed: Amount, claimed: Amount },
    #[error("summing values overflowed the monetary ceiling")]
    ValueOverflow,
    #[error("timestamp {timestamp} is more than {drift} seconds ahead of this node")]
    TimestampTooFarAhead { timestamp: u64, drift: u64 },
    #[error("timestamp {found} does not advance on the parent's {previous}")]
    TimestampNotIncreasing { previous: u64, found: u64 },
    #[error("header commits to transaction root {found}, body produces {expected}")]
    TransactionsRootMismatch { expected: Hash32, found: Hash32 },
    #[error("header commits to state root {found}, the block produces {expected}")]
    StateRootMismatch { expected: Hash32, found: Hash32 },
    #[error("transfer {index} is invalid")]
    InvalidTransfer {
        index: usize,
        #[source]
        source: TransferError,
    },
}

/// Checks everything about a transfer that does not require the note set.
pub fn check_transfer_shape(
    transfer: &Transfer,
    params: &ConsensusParams,
) -> Result<(), TransferError> {
    if transfer.version != TRANSFER_VERSION {
        return Err(TransferError::UnsupportedVersion(transfer.version));
    }
    if transfer.inputs.is_empty() {
        return Err(TransferError::NoInputs);
    }
    if transfer.outputs.is_empty() {
        return Err(TransferError::NoOutputs);
    }
    if transfer.inputs.len() > params.max_inputs_per_transfer {
        return Err(TransferError::TooManyInputs {
            count: transfer.inputs.len(),
            limit: params.max_inputs_per_transfer,
        });
    }
    if transfer.outputs.len() > params.max_outputs_per_transfer {
        return Err(TransferError::TooManyOutputs {
            count: transfer.outputs.len(),
            limit: params.max_outputs_per_transfer,
        });
    }

    let mut seen = HashSet::with_capacity(transfer.inputs.len());
    for input in &transfer.inputs {
        if !seen.insert(input.note_id) {
            return Err(TransferError::DuplicateInput(input.note_id));
        }
    }

    // A note carrying no value costs permanent state and moves nothing. State
    // is the scarce resource in this design, so it is never free to consume.
    for (index, output) in transfer.outputs.iter().enumerate() {
        if output.value == Amount::ZERO {
            return Err(TransferError::ZeroValueOutput { index });
        }
    }

    transfer
        .total_output()
        .ok_or(TransferError::ValueOverflow)?;
    Ok(())
}

/// Fully validates a transfer against a view of the note set, returning its fee.
pub fn check_transfer<R: NoteResolver + ?Sized>(
    transfer: &Transfer,
    resolver: &R,
    params: &ConsensusParams,
) -> Result<Amount, TransferError> {
    check_transfer_shape(transfer, params)?;

    let mut available = Amount::ZERO;
    for (index, input) in transfer.inputs.iter().enumerate() {
        let spent = resolver
            .resolve(&input.note_id)
            .ok_or(TransferError::UnknownNote(input.note_id))?;

        let position = u32::try_from(index).unwrap_or(u32::MAX);
        let message = transfer.signature_message(params.network, position, &spent);
        spent
            .owner
            .verify(message.as_bytes(), &input.signature)
            .map_err(|_| TransferError::InvalidSignature { input_index: index })?;

        available = available
            .checked_add(spent.value)
            .ok_or(TransferError::ValueOverflow)?;
    }

    let requested = transfer
        .total_output()
        .ok_or(TransferError::ValueOverflow)?;
    available
        .checked_sub(requested)
        .ok_or(TransferError::OutputsExceedInputs {
            available,
            requested,
        })
}

/// What applying a block body does to the state, computed without mutation.
#[derive(Clone, Debug)]
pub struct BlockEffect {
    pub spent: HashSet<NoteId>,
    pub created: Vec<(NoteId, Note)>,
    pub total_fees: Amount,
    pub state_root: Hash32,
}

/// A view of the note set with the notes already spent by this block removed.
///
/// A transfer may not spend a note created earlier in the same block. Allowing
/// it would make validity depend on the order transfers appear in, which rules
/// out validating them in parallel. The restriction is provisional and costs
/// only a one block wait.
struct BlockView<'a> {
    state: &'a LedgerState,
    spent: &'a HashSet<NoteId>,
}

impl NoteResolver for BlockView<'_> {
    fn resolve(&self, id: &NoteId) -> Option<Note> {
        if self.spent.contains(id) {
            return None;
        }
        self.state.note(id)
    }
}

fn check_coinbase_shape(
    coinbase: &CoinbaseTransaction,
    params: &ConsensusParams,
) -> Result<(), BlockError> {
    if coinbase.version != COINBASE_VERSION {
        return Err(BlockError::UnsupportedCoinbaseVersion(coinbase.version));
    }
    if coinbase.outputs.len() > params.max_coinbase_outputs {
        return Err(BlockError::TooManyCoinbaseOutputs {
            count: coinbase.outputs.len(),
            limit: params.max_coinbase_outputs,
        });
    }
    for (index, output) in coinbase.outputs.iter().enumerate() {
        if output.value == Amount::ZERO {
            return Err(BlockError::ZeroValueCoinbaseOutput { index });
        }
    }
    Ok(())
}

/// Validates a block body against `state` and reports its effect.
pub fn evaluate_block_body(
    state: &LedgerState,
    coinbase: &CoinbaseTransaction,
    transfers: &[Transfer],
    params: &ConsensusParams,
) -> Result<BlockEffect, BlockError> {
    check_coinbase_shape(coinbase, params)?;

    if transfers.len() > params.max_transfers_per_block {
        return Err(BlockError::TooManyTransfers {
            count: transfers.len(),
            limit: params.max_transfers_per_block,
        });
    }

    let mut spent: HashSet<NoteId> = HashSet::new();
    let mut created: Vec<(NoteId, Note)> = Vec::new();
    let mut total_fees = Amount::ZERO;

    for (index, transfer) in transfers.iter().enumerate() {
        let view = BlockView {
            state,
            spent: &spent,
        };
        let fee = check_transfer(transfer, &view, params)
            .map_err(|source| BlockError::InvalidTransfer { index, source })?;

        for input in &transfer.inputs {
            spent.insert(input.note_id);
        }
        created.extend(transfer.created_notes());
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(BlockError::ValueOverflow)?;
    }

    let allowed = params
        .block_reward
        .checked_add(total_fees)
        .ok_or(BlockError::ValueOverflow)?;
    let claimed = coinbase.total_output().ok_or(BlockError::ValueOverflow)?;
    if claimed > allowed {
        return Err(BlockError::CoinbaseOverpay { allowed, claimed });
    }
    created.extend(coinbase.created_notes());

    let state_root = state.projected_state_root(&spent, &created);
    Ok(BlockEffect {
        spent,
        created,
        total_fees,
        state_root,
    })
}

/// Builds the block a producer would publish, with both roots filled in.
pub fn assemble_block(
    state: &LedgerState,
    coinbase: CoinbaseTransaction,
    transfers: Vec<Transfer>,
    params: &ConsensusParams,
    timestamp: u64,
    nonce: u64,
) -> Result<Block, BlockError> {
    let height = state.next_height().ok_or(BlockError::HeightOverflow)?;
    if coinbase.height != height {
        return Err(BlockError::CoinbaseHeightMismatch {
            header: height,
            coinbase: coinbase.height,
        });
    }

    let effect = evaluate_block_body(state, &coinbase, &transfers, params)?;
    let header = BlockHeader {
        version: BLOCK_VERSION,
        network: params.network,
        height,
        previous: state.expected_parent(),
        transactions_root: Hash32::ZERO,
        state_root: effect.state_root,
        timestamp,
        nonce,
    };
    let mut block = Block {
        header,
        coinbase,
        transfers,
    };
    block.header.transactions_root = block.transactions_root();
    Ok(block)
}

/// Validates `block` against `state` and, if it holds, applies it.
///
/// `now` is the receiving node's clock, in seconds since the Unix epoch. On
/// failure the state is left untouched.
pub fn connect_block(
    state: &mut LedgerState,
    block: &Block,
    params: &ConsensusParams,
    now: u64,
) -> Result<(), BlockError> {
    let header = &block.header;

    if header.version != BLOCK_VERSION {
        return Err(BlockError::UnsupportedVersion(header.version));
    }
    if header.network != params.network {
        return Err(BlockError::WrongNetwork {
            expected: params.network,
            found: header.network,
        });
    }

    let expected_height = state.next_height().ok_or(BlockError::HeightOverflow)?;
    if header.height != expected_height {
        return Err(BlockError::WrongHeight {
            expected: expected_height,
            found: header.height,
        });
    }

    let expected_parent = state.expected_parent();
    if header.previous != expected_parent {
        return Err(BlockError::WrongParent {
            expected: expected_parent,
            found: header.previous,
        });
    }

    if header.timestamp > now.saturating_add(params.max_timestamp_drift) {
        return Err(BlockError::TimestampTooFarAhead {
            timestamp: header.timestamp,
            drift: params.max_timestamp_drift,
        });
    }
    if let Some(tip) = state.tip() {
        if header.timestamp <= tip.timestamp {
            return Err(BlockError::TimestampNotIncreasing {
                previous: tip.timestamp,
                found: header.timestamp,
            });
        }
    }

    if block.coinbase.height != header.height {
        return Err(BlockError::CoinbaseHeightMismatch {
            header: header.height,
            coinbase: block.coinbase.height,
        });
    }

    let computed_transactions_root = block.transactions_root();
    if header.transactions_root != computed_transactions_root {
        return Err(BlockError::TransactionsRootMismatch {
            expected: computed_transactions_root,
            found: header.transactions_root,
        });
    }

    let effect = evaluate_block_body(state, &block.coinbase, &block.transfers, params)?;
    if header.state_root != effect.state_root {
        return Err(BlockError::StateRootMismatch {
            expected: effect.state_root,
            found: header.state_root,
        });
    }

    state.commit(header, &effect.spent, effect.created);
    Ok(())
}

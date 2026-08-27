//! Consensus rules.
//!
//! Every rule here decides whether a block is valid. Two nodes that evaluate
//! any of them differently follow different chains, so nothing in this module
//! may depend on wall clock time, iteration order, or locale. The current time
//! is passed in rather than read.

use std::collections::{BTreeMap, BTreeSet};

use cairn_primitives::{Amount, Hash32};

use crate::emission;

use crate::block::{Block, BlockHeader, BLOCK_VERSION};
use crate::note::{NetworkId, Note, NoteId};
use crate::pow::{median_time_past, meets_target, next_difficulty, work_of, MIN_DIFFICULTY};
use crate::state::{cold_leaf, BlockUndo, ColdSpend, LedgerState, StateTransition};
use crate::transaction::{
    CoinbaseTransaction, Input, Transfer, Witness, COINBASE_VERSION, MAX_COINBASE_EXTRA,
    TRANSFER_VERSION,
};

const fn amount_or_zero(pebbles: u64) -> Amount {
    match Amount::from_pebbles(pebbles) {
        Some(amount) => amount,
        None => Amount::ZERO,
    }
}

const INITIAL_REWARD: Amount = amount_or_zero(emission::INITIAL_REWARD_PEBBLES);
const TAIL_REWARD: Amount = amount_or_zero(emission::TAIL_REWARD_PEBBLES);

/// How many notes stay in the hot set.
///
/// Chosen from a measurement rather than from a round number. A hot note costs
/// about 813 bytes across the three structures a node keeps for it, most of
/// that being the tree that commits to them, so this is roughly 107 MB.
///
/// The figure is set by the promise rather than by what a server could afford:
/// a phone has to be able to hold it, because a wallet that cannot verify for
/// itself is the centralisation this design exists to remove. A leaner tree
/// representation would buy room to raise it later, and that is the single
/// most valuable optimisation left.
const DEFAULT_HOT_CAPACITY: usize = 1 << 17;

/// Seconds a block is meant to take. Provisional.
const DEFAULT_TARGET_BLOCK_TIME: u64 = 60;

/// Rules a node applies to every block it evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusParams {
    pub network: NetworkId,
    /// The block every chain on this network must start from.
    ///
    /// `None` means nothing is pinned, which is what tests and unnamed
    /// networks use. A live network always pins it: without that, a node
    /// starting fresh has to take whatever first block the peer it happens to
    /// ask hands it, which is the one piece of trust worth removing.
    pub genesis: Option<Hash32>,
    /// No block may be dated before this.
    ///
    /// Published ahead of a launch, it makes the opening moment the same for
    /// everyone. Whoever knew about the network first cannot have mined it
    /// quietly the week before, because every node refuses blocks dated
    /// earlier.
    pub opens_at: u64,
    /// What the first block pays. The schedule halves from here.
    pub initial_reward: Amount,
    /// What every block pays once halving would take it lower.
    pub tail_reward: Amount,
    /// Blocks between halvings.
    pub halving_interval: u64,
    /// Notes the hot set holds before the oldest start falling to the cold set.
    pub hot_capacity: usize,
    /// Seconds the retarget aims for between blocks.
    pub target_block_time: u64,
    /// Difficulty the first block carries, before any history exists.
    ///
    /// It should already take about the target block time on one ordinary
    /// machine. Anything less and the opening seconds are a race the rest of
    /// the world has not been told about yet.
    pub genesis_difficulty: u64,
    pub max_transfers_per_block: usize,
    pub max_inputs_per_transfer: usize,
    pub max_outputs_per_transfer: usize,
    pub max_coinbase_outputs: usize,
    /// How far ahead of the receiving node's clock a timestamp may sit.
    pub max_timestamp_drift: u64,
}

impl ConsensusParams {
    /// The rules of a named network.
    ///
    /// Every field here is consensus: two nodes that disagree on any of them
    /// build different chains while believing they are on the same one. So the
    /// rules belong to the network and are chosen by naming it, never set one
    /// at a time by whoever starts the node.
    // The mainnet arm answers like the unknown one on purpose, and saying so
    // out loud is the point: it is a name that will mean something and does
    // not yet.
    #[allow(clippy::match_same_arms)]
    pub fn for_network(name: &str) -> Option<Self> {
        match name {
            // Not yet made. A network exists once its first block does, and
            // that block will be mined in the open on the day it is announced.
            "mainnet" => None,
            "testnet" | "testnet-2" => Some(Self {
                network: NetworkId::TESTNET_2,
                genesis: crate::genesis::pinned(NetworkId::TESTNET_2),
                opens_at: crate::genesis::opens_at(NetworkId::TESTNET_2),
                genesis_difficulty: 1 << 27,
                ..Self::testnet()
            }),
            // A throwaway network, so its hot set is small enough that notes
            // reach the cold set in seconds rather than months, and its first
            // block is found in seconds. Everything else is the same, which is
            // the point of having it.
            "devnet" => Some(Self {
                network: NetworkId::DEVNET,
                genesis: crate::genesis::pinned(NetworkId::DEVNET),
                opens_at: crate::genesis::opens_at(NetworkId::DEVNET),
                genesis_difficulty: 1 << 23,
                target_block_time: 5,
                hot_capacity: 64,
                ..Self::testnet()
            }),
            _ => None,
        }
    }

    /// The name [`Self::for_network`] would take to produce these rules.
    pub fn network_name(&self) -> &'static str {
        match self.network {
            NetworkId::DEVNET => "devnet",
            NetworkId::TESTNET_2 => "testnet-2",
            // Mainnet lands here too until it has a first block, which is the
            // honest answer: it is not a network yet.
            _ => "unnamed",
        }
    }

    /// The rule set, with nothing tying it to a live network.
    ///
    /// No pinned first block and a trivial opening difficulty, which is what
    /// tests want and what no public network should ever run. Public networks
    /// come from [`Self::for_network`].
    pub const fn testnet() -> Self {
        Self {
            network: NetworkId::TESTNET,
            genesis: None,
            opens_at: 0,
            initial_reward: INITIAL_REWARD,
            tail_reward: TAIL_REWARD,
            halving_interval: emission::HALVING_INTERVAL,
            hot_capacity: DEFAULT_HOT_CAPACITY,
            target_block_time: DEFAULT_TARGET_BLOCK_TIME,
            genesis_difficulty: MIN_DIFFICULTY,
            max_transfers_per_block: 4096,
            max_inputs_per_transfer: 256,
            max_outputs_per_transfer: 256,
            max_coinbase_outputs: 16,
            max_timestamp_drift: 2 * 60 * 60,
        }
    }

    /// What a block at `height` pays whoever produced it.
    pub fn reward_at(&self, height: u64) -> Amount {
        emission::reward_at(
            height,
            self.halving_interval,
            self.initial_reward,
            self.tail_reward,
        )
    }

    /// The same rules with a hot set small enough to exercise eviction.
    #[must_use]
    pub const fn with_hot_capacity(mut self, capacity: usize) -> Self {
        self.hot_capacity = capacity;
        self
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
    #[error("note {note_id:?} is still in the hot set, so it takes no proof")]
    UnexpectedProof { note_id: NoteId },
    #[error(
        "note {note_id:?} is not in the hot set: either it fell and spending it \
         needs a proof, or it never existed. A node cannot tell the two apart, \
         because it holds neither the cold set nor a record of what was never in it"
    )]
    MissingProof { note_id: NoteId },
    #[error("the proof for note {note_id:?} does not match the cold commitment")]
    InvalidProof { note_id: NoteId },
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
    #[error("coinbase carries {size} extra bytes, limit is {MAX_COINBASE_EXTRA}")]
    CoinbaseExtraTooLarge { size: usize },
    #[error("coinbase claims {claimed}, only {allowed} is available")]
    CoinbaseOverpay { allowed: Amount, claimed: Amount },
    #[error("summing values overflowed the monetary ceiling")]
    ValueOverflow,
    #[error("timestamp {timestamp} is more than {drift} seconds ahead of this node")]
    TimestampTooFarAhead { timestamp: u64, drift: u64 },
    #[error("timestamp {found} is not past the median {median} of recent blocks")]
    TimestampNotAfterMedian { median: u64, found: u64 },
    #[error("block is dated {found}, before this network opened at {opens_at}")]
    BeforeTheNetworkOpened { opens_at: u64, found: u64 },
    #[error("this network starts at {expected}, block claims to start at {found}")]
    WrongGenesis { expected: Hash32, found: Hash32 },
    #[error("block claims difficulty {found}, the chain demands {expected}")]
    WrongDifficulty { expected: u64, found: u64 },
    #[error("block identifier does not meet the target for difficulty {difficulty}")]
    InsufficientWork { difficulty: u64 },
    #[error("header commits to transaction root {found}, body produces {expected}")]
    TransactionsRootMismatch { expected: Hash32, found: Hash32 },
    #[error("header commits to state root {found}, the block produces {expected}")]
    StateRootMismatch { expected: Hash32, found: Hash32 },
    #[error("header commits to history {found}, this chain's headers produce {expected}")]
    HistoryMismatch { expected: Hash32, found: Hash32 },
    #[error("header claims {found} total work, its parent and difficulty give {expected}")]
    WrongTotalWork { expected: u128, found: u128 },
    #[error("accumulated work would overflow")]
    WorkOverflow,
    #[error("transfer {index} is invalid")]
    InvalidTransfer {
        index: usize,
        #[source]
        source: TransferError,
    },
}

/// What a valid transfer contributes to the block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferOutcome {
    pub fee: Amount,
    pub spent_hot: Vec<NoteId>,
    pub spent_cold: Vec<ColdSpend>,
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

    let mut seen = BTreeSet::new();
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

/// Finds the note an input spends, and what it takes to put it back.
///
/// The tier is not the spender's choice: a note is cold exactly when the hot
/// set does not hold it. A witness of the wrong kind is rejected rather than
/// ignored, so one spend has one encoding.
///
/// Cold proofs are checked against the commitment as it stood before the
/// block. Checking them against one that moves as the block is applied would
/// make a transfer's validity depend on where it sits in the block.
fn resolve_input(
    state: &LedgerState,
    input: &Input,
    spent_hot: &BTreeSet<NoteId>,
    spent_cold: &BTreeMap<NoteId, ColdSpend>,
) -> Result<(Note, Option<ColdSpend>), TransferError> {
    let id = input.note_id;
    if spent_hot.contains(&id) || spent_cold.contains_key(&id) {
        return Err(TransferError::UnknownNote(id));
    }

    match (state.hot_note(&id), &input.witness) {
        (Some(note), Witness::Hot) => Ok((note, None)),
        (Some(_), Witness::Cold(_)) => Err(TransferError::UnexpectedProof { note_id: id }),
        // A note that fell moments ago is still held by every node, along with
        // its proof, so spending it takes nothing extra from whoever wrote the
        // transfer. Without this the line between the tiers would be a cliff,
        // and a transfer would lose whenever a block landed while it was being
        // written.
        (None, Witness::Hot) => match state.within_grace(&id) {
            None => Err(TransferError::MissingProof { note_id: id }),
            Some((position, note)) => {
                let proof = state
                    .cold()
                    .proof_of(position)
                    .ok_or(TransferError::MissingProof { note_id: id })?;
                // Still checked: a note that fell within the window and has
                // since been spent is no longer there to find.
                if !state.cold().verify(position, cold_leaf(&id, &note), &proof) {
                    return Err(TransferError::UnknownNote(id));
                }
                let spend = ColdSpend {
                    id,
                    position,
                    note,
                    proof,
                };
                Ok((note, Some(spend)))
            }
        },
        (None, Witness::Cold(cold)) => {
            let leaf = cold_leaf(&id, &cold.note);
            if !state.cold().verify(cold.position, leaf, &cold.proof) {
                return Err(TransferError::InvalidProof { note_id: id });
            }
            let spend = ColdSpend {
                id,
                position: cold.position,
                note: cold.note,
                proof: cold.proof.clone(),
            };
            Ok((cold.note, Some(spend)))
        }
    }
}

/// Fully validates a transfer against the note set.
pub fn check_transfer(
    transfer: &Transfer,
    state: &LedgerState,
    spent_hot: &BTreeSet<NoteId>,
    spent_cold: &BTreeMap<NoteId, ColdSpend>,
    params: &ConsensusParams,
) -> Result<TransferOutcome, TransferError> {
    check_transfer_shape(transfer, params)?;

    let mut available = Amount::ZERO;
    let mut from_hot = Vec::new();
    let mut from_cold = Vec::new();

    for (index, input) in transfer.inputs.iter().enumerate() {
        let (spent, fallen) = resolve_input(state, input, spent_hot, spent_cold)?;

        let position = u32::try_from(index).unwrap_or(u32::MAX);
        let message = transfer.signature_message(params.network, position, &spent);
        spent
            .owner
            .verify(message.as_bytes(), &input.signature)
            .map_err(|_| TransferError::InvalidSignature { input_index: index })?;

        available = available
            .checked_add(spent.value)
            .ok_or(TransferError::ValueOverflow)?;
        match fallen {
            None => from_hot.push(input.note_id),
            Some(from_the_cold_set) => from_cold.push(from_the_cold_set),
        }
    }

    let requested = transfer
        .total_output()
        .ok_or(TransferError::ValueOverflow)?;
    let fee = available
        .checked_sub(requested)
        .ok_or(TransferError::OutputsExceedInputs {
            available,
            requested,
        })?;

    Ok(TransferOutcome {
        fee,
        spent_hot: from_hot,
        spent_cold: from_cold,
    })
}

/// What applying a block body does to the state, computed without mutation.
#[derive(Clone, Debug)]
pub struct BlockEffect {
    pub transition: StateTransition,
    pub total_fees: Amount,
    pub state_root: Hash32,
}

fn check_coinbase_shape(
    coinbase: &CoinbaseTransaction,
    params: &ConsensusParams,
) -> Result<(), BlockError> {
    if coinbase.version != COINBASE_VERSION {
        return Err(BlockError::UnsupportedCoinbaseVersion(coinbase.version));
    }
    if coinbase.extra.len() > MAX_COINBASE_EXTRA {
        return Err(BlockError::CoinbaseExtraTooLarge {
            size: coinbase.extra.len(),
        });
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

    let height = state.next_height().ok_or(BlockError::HeightOverflow)?;
    let mut spent_hot: BTreeSet<NoteId> = BTreeSet::new();
    let mut spent_cold: BTreeMap<NoteId, ColdSpend> = BTreeMap::new();
    let mut created: Vec<(NoteId, Note)> = Vec::new();
    let mut total_fees = Amount::ZERO;

    for (index, transfer) in transfers.iter().enumerate() {
        let outcome = check_transfer(transfer, state, &spent_hot, &spent_cold, params)
            .map_err(|source| BlockError::InvalidTransfer { index, source })?;

        spent_hot.extend(outcome.spent_hot);
        spent_cold.extend(
            outcome
                .spent_cold
                .into_iter()
                .map(|spend| (spend.id, spend)),
        );
        created.extend(transfer.created_notes());
        total_fees = total_fees
            .checked_add(outcome.fee)
            .ok_or(BlockError::ValueOverflow)?;
    }

    // What the schedule pays at this height, plus what the transfers paid to
    // be carried.
    let allowed = params
        .reward_at(height)
        .checked_add(total_fees)
        .ok_or(BlockError::ValueOverflow)?;
    let claimed = coinbase.total_output().ok_or(BlockError::ValueOverflow)?;
    if claimed > allowed {
        return Err(BlockError::CoinbaseOverpay { allowed, claimed });
    }
    created.extend(coinbase.created_notes());

    let evicted = state.plan_evictions(&spent_hot, &created, params.hot_capacity);
    let transition = StateTransition {
        spent_hot: spent_hot.into_iter().collect(),
        spent_cold: spent_cold.into_values().collect(),
        created,
        evicted,
    };
    let state_root = state.project(&transition, height);

    Ok(BlockEffect {
        transition,
        total_fees,
        state_root,
    })
}

/// The difficulty the next block must carry.
pub fn expected_difficulty(state: &LedgerState, params: &ConsensusParams) -> u64 {
    let recent = state.recent_headers();
    if recent.is_empty() {
        params.genesis_difficulty.max(MIN_DIFFICULTY)
    } else {
        next_difficulty(recent, params.target_block_time)
    }
}

/// Searches for a nonce that satisfies the block's difficulty.
///
/// Deliberately the naive loop. A real miner runs it across cores and rolls the
/// coinbase extra nonce once the nonce space is exhausted, but neither changes
/// what makes a block valid. Returns `None` if no nonce below `attempts` works.
pub fn mine_block(mut block: Block, attempts: u64) -> Option<Block> {
    for nonce in 0..attempts {
        block.header.nonce = nonce;
        if meets_target(&block.header.id(), block.header.difficulty) {
            return Some(block);
        }
    }
    None
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
    let difficulty = expected_difficulty(state, params);
    let header = BlockHeader {
        version: BLOCK_VERSION,
        network: params.network,
        height,
        previous: state.expected_parent(),
        transactions_root: Hash32::ZERO,
        state_root: effect.state_root,
        history: state.history_root(),
        timestamp,
        difficulty,
        total_work: state
            .total_work()
            .checked_add(work_of(difficulty))
            .ok_or(BlockError::WorkOverflow)?,
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

/// A block that was applied, and what it takes to apply or undo it again.
#[derive(Clone, Debug)]
pub struct ConnectedBlock {
    pub transition: StateTransition,
    pub undo: BlockUndo,
    pub total_fees: Amount,
}

/// Checks everything about a header that does not need the block body.
///
/// Split out from [`connect_block`] so that each half stays short enough to
/// hold in one reading, which matters more here than anywhere else in the
/// codebase: every line of it is a rule two nodes must agree on exactly.
fn check_header(
    state: &LedgerState,
    header: &BlockHeader,
    params: &ConsensusParams,
) -> Result<(), BlockError> {
    if header.version != BLOCK_VERSION {
        return Err(BlockError::UnsupportedVersion(header.version));
    }
    if header.network != params.network {
        return Err(BlockError::WrongNetwork {
            expected: params.network,
            found: header.network,
        });
    }

    // Nothing may predate the moment the network opened, which is what makes
    // the opening the same for everyone rather than for whoever knew first.
    if header.timestamp < params.opens_at {
        return Err(BlockError::BeforeTheNetworkOpened {
            opens_at: params.opens_at,
            found: header.timestamp,
        });
    }

    let expected_height = state.next_height().ok_or(BlockError::HeightOverflow)?;
    if expected_height == 0 {
        if let Some(expected) = params.genesis {
            let found = header.id();
            if found != expected {
                return Err(BlockError::WrongGenesis { expected, found });
            }
        }
    }
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

    let demanded = expected_difficulty(state, params);
    if header.difficulty != demanded {
        return Err(BlockError::WrongDifficulty {
            expected: demanded,
            found: header.difficulty,
        });
    }

    check_header_commitments(state, header)
}

/// The two fields a newcomer relies on, and nothing else does.
fn check_header_commitments(state: &LedgerState, header: &BlockHeader) -> Result<(), BlockError> {
    // Both are one comparison, and both are what makes a header worth sampling
    // later. A header that misstates the work behind it, or the history it
    // follows, would let someone hand a newcomer a short chain wearing a long
    // one's numbers.
    let demanded_work = state
        .total_work()
        .checked_add(work_of(header.difficulty))
        .ok_or(BlockError::WorkOverflow)?;
    if header.total_work != demanded_work {
        return Err(BlockError::WrongTotalWork {
            expected: demanded_work,
            found: header.total_work,
        });
    }
    let demanded_history = state.history_root();
    if header.history != demanded_history {
        return Err(BlockError::HistoryMismatch {
            expected: demanded_history,
            found: header.history,
        });
    }
    Ok(())
}

/// Validates `block` against `state` and, if it holds, applies it.
///
/// `now` is the receiving node's clock, in seconds since the Unix epoch. On
/// failure the state is left untouched. Keep the returned value: undoing this
/// block later needs it.
pub fn connect_block(
    state: &mut LedgerState,
    block: &Block,
    params: &ConsensusParams,
    now: u64,
) -> Result<ConnectedBlock, BlockError> {
    let header = &block.header;
    check_header(state, header, params)?;

    // Cheap and decisive, so it runs before the body is looked at: a block
    // without work behind it costs an attacker nothing to send.
    if !meets_target(&header.id(), header.difficulty) {
        return Err(BlockError::InsufficientWork {
            difficulty: header.difficulty,
        });
    }

    if header.timestamp > now.saturating_add(params.max_timestamp_drift) {
        return Err(BlockError::TimestampTooFarAhead {
            timestamp: header.timestamp,
            drift: params.max_timestamp_drift,
        });
    }
    // Measured against the median of recent blocks rather than the parent. A
    // miner writes its own timestamp, but it holds one vote in a median, so
    // backdating a block to claim an easier difficulty stops working.
    if let Some(median) = median_time_past(state.recent_headers()) {
        if header.timestamp <= median {
            return Err(BlockError::TimestampNotAfterMedian {
                median,
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

    let undo = state.commit(header, &effect.transition);
    Ok(ConnectedBlock {
        transition: effect.transition,
        undo,
        total_fees: effect.total_fees,
    })
}

/// Takes the tip block back out of the state.
///
/// `connected` has to be what [`connect_block`] returned for the block that is
/// currently the tip. Undoing anything else corrupts the state silently, which
/// is why the two travel together.
pub fn disconnect_block(state: &mut LedgerState, connected: &ConnectedBlock) {
    state.revert(&connected.transition, &connected.undo);
}

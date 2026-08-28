//! The block tree, the fork choice, and reorganisation.
//!
//! A node does not see one chain. It sees a tree of blocks, several of which
//! may extend the same parent, and it has to choose. The rule is the branch
//! carrying the most accumulated work, which is not the same as the longest
//! branch: a longer branch of easier blocks is cheaper to produce than a
//! shorter branch of hard ones, and treating length as the measure is a
//! standing invitation to rewrite history cheaply.
//!
//! Switching branches means undoing applied blocks and applying others. That
//! has to be all or nothing. A switch that fails halfway would leave a node
//! following neither branch, with a state matching no block anyone agrees on.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use cairn_ledger::block::Block;
use cairn_ledger::note::NoteId;
use cairn_ledger::pow::{meets_target, work_of};
use cairn_ledger::transaction::Transfer;
use cairn_ledger::validation::{
    check_transfer, connect_block, disconnect_block, BlockError, ConnectedBlock, ConsensusParams,
    TransferError,
};
use cairn_ledger::ColdSpend;
use cairn_ledger::LedgerState;
use cairn_primitives::{Amount, Hash32};

/// Transfers held while they wait for a block.
///
/// Bounded, because it is filled by strangers. Once full a node simply stops
/// taking new ones rather than growing without limit.
pub const MAX_POOLED: usize = 4_096;

/// How far back the followed branch can be undone.
///
/// Every applied block records what it took to apply, so it can be undone
/// without replaying the chain. Keeping those records for every block ever
/// applied is a cost that grows with the chain, on a node whose whole claim is
/// that its cost does not, so they are kept for this many blocks and no more.
///
/// A switch that would reach deeper is refused. This is a local safety
/// policy rather than a consensus rule: two nodes with different limits still
/// build the same chain, and only ever differ after a reorganisation deeper
/// than either would accept, which on a live network means an attack or a
/// partition lasting the better part of a day.
pub const MAX_REORG_DEPTH: usize = 1_024;

/// Blocks kept off the followed branch before the unreachable ones are
/// dropped.
///
/// A branch that lost by more than [`MAX_REORG_DEPTH`] can never be switched
/// to, so holding its blocks is holding history nobody will ask for.
const MAX_SIDE_BLOCKS: usize = 4_096;

/// Identifiers of blocks known to be invalid, held before the set is cleared.
///
/// Remembering a bad block is what stops it being revalidated every time it
/// arrives. Remembering every bad block ever seen is a table an anonymous peer
/// gets to fill, so past this many the set is emptied: the cost is revalidating
/// a handful of blocks that will fail again, which is bounded, unlike the set.
const MAX_INVALID: usize = 8_192;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("block {0} builds on a parent this node has never seen")]
    UnknownParent(Hash32),
    #[error("the first block must be at height 0 with no parent")]
    NotGenesis,
    #[error("block claims height {found}, its parent sits at {parent}")]
    BrokenHeight { parent: u64, found: u64 },
    #[error("block {id} carries no work for the difficulty it claims")]
    NoWork { id: Hash32 },
    #[error("block {id} is invalid")]
    InvalidBlock {
        id: Hash32,
        #[source]
        source: BlockError,
    },
    #[error(
        "switching branches here would undo {depth} blocks, past the {MAX_REORG_DEPTH} \
         this node keeps undo records for"
    )]
    ForkTooDeep { depth: usize },
    #[error(
        "a block at height {height} is below {floor}, the oldest this node could \
         still reorganise onto"
    )]
    TooOld { height: u64, floor: u64 },
    #[error("the block tree lost a block it had recorded")]
    Corrupt,
}

/// What accepting a block did to the node's view of the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// Already known, nothing changed.
    Duplicate,
    /// Recorded on a branch lighter than the current one.
    SideBranch,
    /// Extended the current branch by one block.
    Extended,
    /// The current branch was abandoned for a heavier one.
    Reorganised {
        removed: Vec<Hash32>,
        added: Vec<Hash32>,
    },
}

#[derive(Clone, Debug)]
struct StoredBlock {
    block: Block,
    /// Work of this block plus every block behind it.
    total_work: u128,
}

/// Every block a node knows, the branch it currently follows, and the ledger
/// state that branch produces.
#[derive(Debug)]
pub struct ChainStore {
    params: ConsensusParams,
    blocks: HashMap<Hash32, StoredBlock>,
    /// Blocks that failed to apply. Kept so the same block is never retried.
    invalid: HashSet<Hash32>,
    /// The followed branch, genesis first.
    active: Vec<Hash32>,
    positions: HashMap<Hash32, usize>,
    /// What it took to apply each block on the active branch, so each can be
    /// undone without replaying the chain. Held for the most recent
    /// [`MAX_REORG_DEPTH`] blocks only.
    applied: HashMap<Hash32, ConnectedBlock>,
    /// Index in `active` of the oldest block whose undo record is still held.
    ///
    /// Kept as a cursor rather than recomputed, so trimming one block off the
    /// back costs the same whether the chain is a day or a decade old.
    undo_from: usize,
    state: LedgerState,
    /// Transfers waiting for a block, keyed by identifier so the order a miner
    /// walks them in does not depend on the order they arrived.
    pool: BTreeMap<Hash32, Transfer>,
    /// The same transfers by what they pay, cheapest first.
    ///
    /// Kept alongside rather than derived, so finding what to make room for
    /// costs a lookup and not a pass over the pool: a peer sending transfers
    /// as fast as it can would otherwise decide how much work each one causes.
    pool_by_fee: BTreeSet<(Amount, Hash32)>,
}

impl ChainStore {
    /// A node that validates and nothing more.
    ///
    /// It keeps the hot set in full and the cold set as sixty four hashes, so
    /// what it costs to run does not grow with the chain.
    pub fn new(params: ConsensusParams) -> Self {
        Self::with_state(params, LedgerState::new())
    }

    /// A node that also keeps the cold set, so it can rebuild a proof for
    /// someone who lost theirs. That is what an archivist is paid for, and
    /// what it costs is a set that grows.
    pub fn archiving(params: ConsensusParams) -> Self {
        Self::with_state(params, LedgerState::archiving())
    }

    fn with_state(params: ConsensusParams, state: LedgerState) -> Self {
        Self {
            params,
            blocks: HashMap::new(),
            invalid: HashSet::new(),
            active: Vec::new(),
            positions: HashMap::new(),
            applied: HashMap::new(),
            undo_from: 0,
            state,
            pool: BTreeMap::new(),
            pool_by_fee: BTreeSet::new(),
        }
    }

    /// Asks to be told where this owner's notes go when they fall, and to
    /// keep their proofs current.
    ///
    /// Set before any block is applied, since what is learned is learned as
    /// the notes fall.
    pub fn watch_owner(&mut self, owner: cairn_crypto::PublicKey) {
        self.state.watch_owner(owner);
    }

    /// Whether this node can answer with proofs.
    pub fn is_archiving(&self) -> bool {
        self.state.cold().is_archiving()
    }

    pub fn params(&self) -> &ConsensusParams {
        &self.params
    }

    /// The ledger as the followed branch leaves it.
    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    pub fn tip(&self) -> Option<Hash32> {
        self.active.last().copied()
    }

    pub fn height(&self) -> Option<u64> {
        self.state.tip().map(|tip| tip.height)
    }

    /// Accumulated work behind the followed branch.
    pub fn total_work(&self) -> u128 {
        self.tip()
            .and_then(|id| self.blocks.get(&id))
            .map_or(0, |stored| stored.total_work)
    }

    pub fn block(&self, id: &Hash32) -> Option<&Block> {
        self.blocks.get(id).map(|stored| &stored.block)
    }

    pub fn contains(&self, id: &Hash32) -> bool {
        self.blocks.contains_key(id)
    }

    /// Blocks held in memory, on any branch.
    ///
    /// Not how many blocks this node has ever accepted: the bodies of blocks
    /// too deep to be undone are let go of, and read back from a log when they
    /// are wanted. Use [`ChainStore::height`] for how far the chain reaches.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether this node holds no block at all, which means it has no chain.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Whether `id` is on the branch currently followed.
    pub fn is_active(&self, id: &Hash32) -> bool {
        self.positions.contains_key(id)
    }

    /// The height `id` sits at on the followed branch.
    ///
    /// A node forgets the bodies of blocks it can no longer undo but keeps
    /// knowing where they were, which is what lets it fetch one back from a
    /// log that holds the branch in order of height.
    pub fn height_of(&self, id: &Hash32) -> Option<u64> {
        self.positions
            .get(id)
            .and_then(|index| u64::try_from(*index).ok())
    }

    /// The followed branch, genesis first.
    ///
    /// Read only. Nothing outside this module decides what the branch is; an
    /// explorer or a status page only needs to walk what was decided here.
    pub fn active(&self) -> &[Hash32] {
        &self.active
    }

    /// The block the followed branch carries at `height`.
    ///
    /// Heights index the branch directly because the first block sits at
    /// height zero and every block since has added exactly one.
    pub fn block_at(&self, height: u64) -> Option<&Block> {
        let index = usize::try_from(height).ok()?;
        let id = self.active.get(index)?;
        self.block(id)
    }

    /// The first block of the followed branch.
    pub fn genesis(&self) -> Option<Hash32> {
        self.active.first().copied()
    }

    /// Which of `ids` this node has never seen.
    pub fn missing<'a>(&self, ids: impl IntoIterator<Item = &'a Hash32>) -> Vec<Hash32> {
        ids.into_iter()
            .filter(|id| !self.blocks.contains_key(id))
            .copied()
            .collect()
    }

    /// A sparse sample of the followed branch, tip first, thinning out with
    /// depth and always ending at the genesis block.
    ///
    /// Two nodes exchange these to find where their branches diverge without
    /// either sending its whole history. Recent blocks are sampled densely
    /// because that is where branches usually part; deep blocks are sampled
    /// rarely because agreement there is almost certain.
    pub fn locator(&self) -> Vec<Hash32> {
        let mut locator = Vec::new();
        let Some(mut index) = self.active.len().checked_sub(1) else {
            return locator;
        };
        let mut step = 1usize;
        let mut dense = 0usize;
        loop {
            if let Some(id) = self.active.get(index) {
                locator.push(*id);
            }
            if index == 0 {
                break;
            }
            dense = dense.saturating_add(1);
            if dense > 10 {
                step = step.saturating_mul(2);
            }
            index = index.saturating_sub(step);
        }
        locator
    }

    /// The followed branch beyond the first block of `locator` this node knows,
    /// oldest first, capped at `max`.
    ///
    /// When none of the locator is recognised the answer starts at genesis,
    /// which is what a node syncing from scratch needs.
    pub fn chain_after(&self, locator: &[Hash32], max: usize) -> Vec<Hash32> {
        let common = locator
            .iter()
            .find_map(|id| self.positions.get(id).copied());
        let from = common.map_or(0, |index| index.saturating_add(1));
        self.active
            .get(from..)
            .unwrap_or_default()
            .iter()
            .take(max)
            .copied()
            .collect()
    }

    /// Undo records held, which is bounded by [`MAX_REORG_DEPTH`].
    pub fn undo_records(&self) -> usize {
        self.applied.len()
    }

    /// Transfers waiting for a block.
    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }

    pub fn pooled(&self, id: &Hash32) -> Option<&Transfer> {
        self.pool.get(id)
    }

    /// Every transfer waiting for a block, in identifier order.
    pub fn pooled_transfers(&self) -> impl Iterator<Item = (&Hash32, &Transfer)> {
        self.pool.iter()
    }

    /// Takes a transfer that has been broadcast, returning whether it was new.
    ///
    /// A transfer is checked against the state as it stands, so a node never
    /// holds one it already knows cannot be included. A transfer spending a
    /// note another pooled transfer already spends is refused rather than
    /// replacing it: choosing between two conflicting spends is a fee policy,
    /// and the chain has no fee market yet to decide it with.
    pub fn accept_transfer(&mut self, transfer: Transfer) -> Result<bool, TransferError> {
        let id = transfer.id();
        if self.pool.contains_key(&id) {
            return Ok(false);
        }

        let spent = self.pooled_inputs();
        for input in &transfer.inputs {
            if spent.contains(&input.note_id) {
                return Err(TransferError::UnknownNote(input.note_id));
            }
        }
        let outcome = check_transfer(
            &transfer,
            &self.state,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &self.params,
        )?;

        // A full pool that refuses everything is a pool anyone can close. Four
        // thousand transfers paying nothing would hold every place, and a
        // sender who paid would be turned away behind them, for as long as the
        // attacker cared to keep it up. So a full pool makes room for whoever
        // pays more than the least it already holds, and refuses only what
        // would not improve it.
        if self.pool.len() >= MAX_POOLED {
            let Some((cheapest, victim)) = self.pool_by_fee.first().copied() else {
                return Ok(false);
            };
            if outcome.fee <= cheapest {
                return Ok(false);
            }
            self.pool.remove(&victim);
            self.pool_by_fee.remove(&(cheapest, victim));
        }

        self.pool.insert(id, transfer);
        self.pool_by_fee.insert((outcome.fee, id));
        Ok(true)
    }

    /// Transfers a miner can put in the next block, and the fees they carry.
    ///
    /// Walked from the best paying down, and within the same fee in identifier
    /// order, so two nodes holding the same pool build the same block. Order
    /// is a miner's choice and not a rule: a block is valid whatever order its
    /// transfers were picked in. But picking by identifier meant a fee bought
    /// nothing, and a fee that buys nothing is one nobody pays, which leaves a
    /// pool with no way to tell whose transfer matters when there is not room
    /// for everyone.
    pub fn selection(&self, limit: usize) -> (Vec<Transfer>, Amount) {
        let mut chosen = Vec::new();
        let mut spent_hot: BTreeSet<NoteId> = BTreeSet::new();
        let mut spent_cold: BTreeMap<NoteId, ColdSpend> = BTreeMap::new();
        let mut fees = Amount::ZERO;

        // Best paying first. The fee here is what it was worth when it was
        // admitted, which is a hint rather than a promise: what each one
        // actually pays is worked out again below, against the state as it
        // stands now.
        let ordered = self
            .pool_by_fee
            .iter()
            .rev()
            .filter_map(|(_, id)| self.pool.get(id));

        for transfer in ordered {
            if chosen.len() >= limit {
                break;
            }
            let Ok(outcome) =
                check_transfer(transfer, &self.state, &spent_hot, &spent_cold, &self.params)
            else {
                continue;
            };
            let Some(total) = fees.checked_add(outcome.fee) else {
                continue;
            };
            fees = total;
            spent_hot.extend(outcome.spent_hot);
            spent_cold.extend(
                outcome
                    .spent_cold
                    .into_iter()
                    .map(|spend| (spend.id, spend)),
            );
            chosen.push(transfer.clone());
        }
        (chosen, fees)
    }

    fn pooled_inputs(&self) -> BTreeSet<NoteId> {
        self.pool
            .values()
            .flat_map(|transfer| transfer.inputs.iter().map(|input| input.note_id))
            .collect()
    }

    /// Drops every pooled transfer the current state no longer accepts.
    ///
    /// Called whenever the followed branch moves. A reorganisation can make a
    /// transfer spendable again as easily as it can make one impossible, and
    /// nothing here assumes which.
    fn prune_pool(&mut self) {
        let params = self.params;
        let state = &self.state;
        let mut kept: BTreeSet<(Amount, Hash32)> = BTreeSet::new();
        self.pool.retain(|id, transfer| {
            match check_transfer(transfer, state, &BTreeSet::new(), &BTreeMap::new(), &params) {
                // The fee is read again rather than carried: what a transfer
                // pays depends on the state, and the state is what moved.
                Ok(outcome) => {
                    kept.insert((outcome.fee, *id));
                    true
                }
                Err(_) => false,
            }
        });
        self.pool_by_fee = kept;
    }

    /// Records a block and follows the heaviest branch it makes available.
    ///
    /// `now` is this node's clock, in seconds since the Unix epoch.
    pub fn add_block(&mut self, block: Block, now: u64) -> Result<Accepted, ChainError> {
        let id = block.id();
        if self.blocks.contains_key(&id) {
            return Ok(Accepted::Duplicate);
        }

        // Two cheap checks before the block earns a place in memory. Neither
        // decides validity, which needs the state the block builds on, but a
        // block that fails either can never become valid, and refusing it here
        // stops a peer filling this node's memory for free.
        if !meets_target(&id, block.header.difficulty) {
            return Err(ChainError::NoWork { id });
        }

        // A block this far below the tip cannot be followed whatever is built
        // on it, because reaching it would mean undoing more than this node
        // allows. Refusing it here costs one comparison; storing it costs
        // memory for a branch that ends in the same refusal, and a peer could
        // make a node hold a thousand of them by sending old history.
        if let Some(tip) = self.height() {
            let floor = tip.saturating_sub(u64::try_from(MAX_REORG_DEPTH).unwrap_or(u64::MAX));
            if block.header.height < floor {
                return Err(ChainError::TooOld {
                    height: block.header.height,
                    floor,
                });
            }
        }

        let total_work = if self.active.is_empty() {
            if block.header.height != 0 || block.header.previous != Hash32::ZERO {
                return Err(ChainError::NotGenesis);
            }
            work_of(block.header.difficulty)
        } else {
            let parent = self
                .blocks
                .get(&block.header.previous)
                .ok_or(ChainError::UnknownParent(block.header.previous))?;
            let expected_height = parent.block.header.height.saturating_add(1);
            if block.header.height != expected_height {
                return Err(ChainError::BrokenHeight {
                    parent: parent.block.header.height,
                    found: block.header.height,
                });
            }
            // The difficulty is taken as claimed here. A block claiming more
            // than its branch demands has to have done that much work to be
            // stored at all, and the switch below rejects it, so the worst it
            // buys is one wasted attempt.
            parent
                .total_work
                .saturating_add(work_of(block.header.difficulty))
        };

        self.blocks.insert(id, StoredBlock { block, total_work });

        if total_work <= self.total_work() {
            // Ties keep the block already followed. Reorganising for no gain in
            // work would let anyone churn the tip at no cost.
            return Ok(Accepted::SideBranch);
        }
        self.follow(id, now)
    }

    /// Moves the followed branch onto the one ending at `target`.
    fn follow(&mut self, target: Hash32, now: u64) -> Result<Accepted, ChainError> {
        let (fork_position, branch) = self.branch_to(target)?;

        // Refused here rather than discovered halfway through the rewind, when
        // the undo record for a block this node no longer keeps one for would
        // read as a corrupt tree.
        //
        // A branch this deep can no longer be assembled, since its first block
        // is below the floor `add_block` refuses at. This stays as the last
        // word on the rule it enforces, rather than as a check that happens to
        // be unreachable today.
        let keep = fork_position.map_or(0, |index| index.saturating_add(1));
        let depth = self.active.len().saturating_sub(keep);
        if depth > MAX_REORG_DEPTH {
            return Err(ChainError::ForkTooDeep { depth });
        }

        let rolled_back = self.rewind_to(fork_position)?;

        let mut added = Vec::new();
        for id in &branch {
            match self.apply(*id, now) {
                Ok(()) => added.push(*id),
                Err(error) => {
                    if self.invalid.len() >= MAX_INVALID {
                        self.invalid.clear();
                    }
                    self.invalid.insert(*id);
                    self.restore(&added, &rolled_back, now)?;
                    return Err(error);
                }
            }
        }

        // The state moved, so what the pool holds has to be reconsidered.
        self.prune_pool();
        self.forget_what_cannot_change();
        self.forget_unreachable_branches();

        if rolled_back.is_empty() {
            return Ok(Accepted::Extended);
        }
        Ok(Accepted::Reorganised {
            removed: rolled_back,
            added,
        })
    }

    /// The blocks between the followed branch and `target`, oldest first,
    /// along with the position on the followed branch they all descend from.
    ///
    /// `None` for that position means the branch starts from nothing, which
    /// happens only while the node has no chain at all.
    fn branch_to(&self, target: Hash32) -> Result<(Option<usize>, Vec<Hash32>), ChainError> {
        let mut branch = Vec::new();
        let mut cursor = target;
        loop {
            if let Some(position) = self.positions.get(&cursor) {
                branch.reverse();
                return Ok((Some(*position), branch));
            }
            let stored = self
                .blocks
                .get(&cursor)
                .ok_or(ChainError::UnknownParent(cursor))?;
            if self.invalid.contains(&cursor) {
                return Err(ChainError::InvalidBlock {
                    id: cursor,
                    source: BlockError::UnsupportedVersion(stored.block.header.version),
                });
            }
            branch.push(cursor);
            if stored.block.header.height == 0 {
                if self.active.is_empty() {
                    branch.reverse();
                    return Ok((None, branch));
                }
                // A second genesis shares no history with the one being
                // followed, so there is no branch point between them.
                return Err(ChainError::NotGenesis);
            }
            cursor = stored.block.header.previous;
        }
    }

    /// Undoes every applied block above `position`, newest first.
    fn rewind_to(&mut self, position: Option<usize>) -> Result<Vec<Hash32>, ChainError> {
        let keep = position.map_or(0, |index| index.saturating_add(1));
        let mut removed = Vec::new();
        while self.active.len() > keep {
            let id = self.active.pop().ok_or(ChainError::Corrupt)?;
            let connected = self.applied.remove(&id).ok_or(ChainError::Corrupt)?;
            disconnect_block(&mut self.state, &connected);
            self.positions.remove(&id);
            removed.push(id);
        }
        self.undo_from = self.undo_from.min(self.active.len());
        Ok(removed)
    }

    /// Lets go of blocks now deeper than [`MAX_REORG_DEPTH`].
    ///
    /// Past that depth a block can no longer be undone, which is a rule this
    /// store enforces rather than a hope. So what is held for it is held for
    /// nothing: the record of how to undo it, and the block itself.
    ///
    /// Dropping the block is what keeps a node's memory from growing with the
    /// chain. A node that kept every block it ever applied would be carrying
    /// its whole history in memory to answer questions it can answer from
    /// disk, where the same blocks already sit in order of height.
    ///
    /// One block leaves the window each time one is added, so this is a step
    /// rather than a sweep: what it costs does not depend on how long the
    /// chain has been running.
    fn forget_what_cannot_change(&mut self) {
        while self.active.len().saturating_sub(self.undo_from) > MAX_REORG_DEPTH {
            let Some(id) = self.active.get(self.undo_from).copied() else {
                break;
            };
            self.applied.remove(&id);
            self.blocks.remove(&id);
            self.undo_from = self.undo_from.saturating_add(1);
        }
    }

    /// Drops blocks on branches that can no longer be switched to.
    ///
    /// Only when there are enough of them to be worth the walk, because this
    /// one does have to look at every block it holds.
    fn forget_unreachable_branches(&mut self) {
        let limit = self.active.len().saturating_add(MAX_SIDE_BLOCKS);
        if self.blocks.len() <= limit {
            return;
        }
        let Some(cutoff) = self
            .height()
            .and_then(|tip| tip.checked_sub(u64::try_from(MAX_REORG_DEPTH).unwrap_or(u64::MAX)))
        else {
            return;
        };
        let positions = &self.positions;
        self.blocks.retain(|id, stored| {
            positions.contains_key(id) || stored.block.header.height >= cutoff
        });
        self.invalid.retain(|id| !positions.contains_key(id));
    }

    fn apply(&mut self, id: Hash32, now: u64) -> Result<(), ChainError> {
        let block = self
            .blocks
            .get(&id)
            .ok_or(ChainError::Corrupt)?
            .block
            .clone();
        let connected = connect_block(&mut self.state, &block, &self.params, now)
            .map_err(|source| ChainError::InvalidBlock { id, source })?;
        self.positions.insert(id, self.active.len());
        self.active.push(id);
        self.applied.insert(id, connected);
        Ok(())
    }

    /// Puts the node back on the branch it was following before a failed
    /// switch, so a bad block on a heavier branch costs nothing but the
    /// attempt.
    fn restore(
        &mut self,
        partial: &[Hash32],
        rolled_back: &[Hash32],
        now: u64,
    ) -> Result<(), ChainError> {
        for _ in partial {
            let id = self.active.pop().ok_or(ChainError::Corrupt)?;
            let connected = self.applied.remove(&id).ok_or(ChainError::Corrupt)?;
            disconnect_block(&mut self.state, &connected);
            self.positions.remove(&id);
        }
        // `rolled_back` came off the tip newest first, so it goes back on in
        // the opposite order.
        for id in rolled_back.iter().rev() {
            self.apply(*id, now)?;
        }
        Ok(())
    }
}

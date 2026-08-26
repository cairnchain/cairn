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

use std::collections::{HashMap, HashSet};

use cairn_ledger::block::Block;
use cairn_ledger::pow::{meets_target, work_of};
use cairn_ledger::validation::{
    connect_block, disconnect_block, BlockError, ConnectedBlock, ConsensusParams,
};
use cairn_ledger::LedgerState;
use cairn_primitives::Hash32;

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
    /// undone without replaying the chain.
    applied: HashMap<Hash32, ConnectedBlock>,
    state: LedgerState,
}

impl ChainStore {
    pub fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            blocks: HashMap::new(),
            invalid: HashSet::new(),
            active: Vec::new(),
            positions: HashMap::new(),
            applied: HashMap::new(),
            state: LedgerState::new(),
        }
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

    /// Blocks known, on any branch.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Whether `id` is on the branch currently followed.
    pub fn is_active(&self, id: &Hash32) -> bool {
        self.positions.contains_key(id)
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

        let total_work = if self.blocks.is_empty() {
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
        let rolled_back = self.rewind_to(fork_position)?;

        let mut added = Vec::new();
        for id in &branch {
            match self.apply(*id, now) {
                Ok(()) => added.push(*id),
                Err(error) => {
                    self.invalid.insert(*id);
                    self.restore(&added, &rolled_back, now)?;
                    return Err(error);
                }
            }
        }

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
        Ok(removed)
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

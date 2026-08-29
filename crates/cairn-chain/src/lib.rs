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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::NoteId;
use cairn_ledger::pow::{meets_target, work_of};
use cairn_ledger::transaction::Transfer;
use cairn_ledger::validation::{
    check_transfer, connect_block, disconnect_block, BlockError, ConnectedBlock, ConsensusParams,
    TransferError,
};
use cairn_ledger::ColdSpend;
use cairn_ledger::LedgerState;
use cairn_primitives::codec::{CodecError, Decode, Encode};
use cairn_primitives::{Amount, Hash32};

/// Transfers held while they wait for a block.
///
/// Bounded, because it is filled by strangers. Once full a node simply stops
/// taking new ones rather than growing without limit.
pub const MAX_POOLED: usize = 4_096;

/// What every waiting transfer may take altogether.
///
/// Four blocks' worth, which is as far ahead as a pool is any use: what waits
/// longer than that is waiting because nobody will carry it. Counting bytes as
/// well as transfers is what makes the ceiling mean something, since one
/// transfer spending notes out of the cold set carries a proof for each and
/// can run to half a megabyte on its own.
pub const MAX_POOL_BYTES: usize = 4 * 1024 * 1024;

/// A transfer waiting for a block, with what it was worth and what it takes.
///
/// Both are worked out once, when it arrives. What it is worth decides what it
/// displaces and what a miner reaches for first; what it takes decides whether
/// there is room. Reading either again from the transfer itself would mean
/// encoding it or revalidating it on every comparison.
#[derive(Clone, Debug)]
struct Pooled {
    transfer: Transfer,
    fee: Amount,
    bytes: usize,
}

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
    #[error("this node already follows a chain, and one is all it may follow")]
    AlreadyFollowing,
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

/// Positions a locator may name.
///
/// A locator thins out with depth, so this covers a chain far longer than any
/// that will exist. It lives here rather than with the wire format because
/// what fills a locator is the branch, and what a peer will accept has to be
/// at least what the branch produces.
pub const MAX_LOCATOR: usize = 64;

/// Heights between one kept identifier and the next, outside the window.
///
/// A node holds the branch it could still reorganise, in full, plus one
/// identifier every this many heights for everything older. Two nodes
/// comparing branches then agree on where to look without either holding the
/// whole of its own, and being out by up to this many blocks costs a few
/// hundred extra sent once.
///
/// A thousand and twenty four of these is thirty two kilobytes over thirty
/// years, against the gigabyte and a quarter that holding every identifier
/// would take.
const MILESTONE: u64 = 1_024;

/// A block, and where it sits on the branch that holds it.
///
/// Positions travel between nodes because holding an index from identifier
/// back to height, for the whole of a chain, is an entry per block for ever on
/// a design whose claim is that a node's cost does not grow with the chain.
///
/// A height that arrives from a peer is a claim rather than a fact. Whoever
/// receives one checks the identifier against what it holds there, so a wrong
/// height finds nothing rather than the wrong block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Located {
    pub height: u64,
    pub id: Hash32,
}

impl Located {
    pub const fn new(height: u64, id: Hash32) -> Self {
        Self { height, id }
    }
}

impl Encode for Located {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.height.encode_to(out);
        self.id.encode_to(out);
    }
}

impl Decode for Located {
    fn decode_from(reader: &mut cairn_primitives::codec::Reader<'_>) -> Result<Self, CodecError> {
        let height = u64::decode_from(reader)?;
        let id = Hash32::decode_from(reader)?;
        Ok(Self { height, id })
    }
}

/// The branch a node follows, as much of it as a node has any use for.
///
/// In full for as far back as a reorganisation may reach, since that is the
/// only part that can still change, and one identifier every [`MILESTONE`]
/// heights before that. Everything in between is on disk, in a log that holds
/// the branch in order of height, and is read from there when it is wanted.
#[derive(Clone, Debug, Default)]
struct Branch {
    /// The most recent identifiers, oldest first.
    recent: VecDeque<Hash32>,
    /// The height the first entry of `recent` sits at.
    from: u64,
    /// Identifier back to height, for what `recent` holds and nothing else.
    at: HashMap<Hash32, u64>,
    /// One identifier every [`MILESTONE`] heights, oldest first, so entry `n`
    /// is the block at height `n * MILESTONE`.
    milestones: Vec<Hash32>,
}

/// Identifiers kept in full.
///
/// One more than a reorganisation may undo, so the block a branch is rewound
/// to is always still here to be rewound onto.
const WINDOW: usize = MAX_REORG_DEPTH + 1;

impl Branch {
    /// Blocks on the branch, which is one more than the height of its tip.
    fn len(&self) -> u64 {
        self.from
            .saturating_add(u64::try_from(self.recent.len()).unwrap_or(0))
    }

    fn is_empty(&self) -> bool {
        self.recent.is_empty()
    }

    fn tip(&self) -> Option<Hash32> {
        self.recent.back().copied()
    }

    fn genesis(&self) -> Option<Hash32> {
        self.milestones.first().copied()
    }

    /// The identifier at `height`, when this node still holds it.
    ///
    /// Present for everything inside the window, and for one height in every
    /// [`MILESTONE`] before that. Absent otherwise, which is not the same as
    /// saying the branch has no block there.
    fn id_at(&self, height: u64) -> Option<Hash32> {
        if height >= self.from {
            let index = usize::try_from(height.saturating_sub(self.from)).ok()?;
            return self.recent.get(index).copied();
        }
        if height % MILESTONE != 0 {
            return None;
        }
        let index = usize::try_from(height / MILESTONE).ok()?;
        self.milestones.get(index).copied()
    }

    /// Where `id` sits, for the part of the branch held in full.
    fn height_of(&self, id: &Hash32) -> Option<u64> {
        self.at.get(id).copied()
    }

    /// A branch that begins at a run of headers taken from somewhere else.
    ///
    /// Oldest first, ending at the tip. There are no milestones: this node
    /// holds nothing older than what it was handed, so there is nothing to
    /// point at and it says so by having none.
    fn from_tail(recent: &[BlockHeader]) -> Self {
        let Some(first) = recent.first() else {
            return Self::default();
        };
        let mut branch = Self {
            from: first.height,
            ..Self::default()
        };
        for header in recent {
            let id = header.id();
            branch.recent.push_back(id);
            branch.at.insert(id, header.height);
        }
        branch
    }

    /// Adds a block to the end of the branch.
    fn push(&mut self, id: Hash32) {
        let height = self.len();
        if height % MILESTONE == 0 {
            self.milestones.push(id);
        }
        self.recent.push_back(id);
        self.at.insert(id, height);

        while self.recent.len() > WINDOW {
            if let Some(gone) = self.recent.pop_front() {
                self.at.remove(&gone);
                self.from = self.from.saturating_add(1);
            }
        }
    }

    /// Takes the last block off, returning it.
    fn pop(&mut self) -> Option<Hash32> {
        let id = self.recent.pop_back()?;
        self.at.remove(&id);
        // The height it sat at is the one after what is left.
        if self.len() % MILESTONE == 0 {
            self.milestones.pop();
        }
        Some(id)
    }
}

/// Every block a node knows, the branch it currently follows, and the ledger
/// state that branch produces.
#[derive(Debug)]
pub struct ChainStore {
    params: ConsensusParams,
    blocks: HashMap<Hash32, StoredBlock>,
    /// Blocks that failed to apply. Kept so the same block is never retried.
    invalid: HashSet<Hash32>,
    /// The branch this node follows, held as far back as it can still change
    /// and sampled before that.
    branch: Branch,
    /// What it took to apply each block on the active branch, so each can be
    /// undone without replaying the chain. Held for the most recent
    /// [`MAX_REORG_DEPTH`] blocks only.
    applied: HashMap<Hash32, ConnectedBlock>,
    /// Height of the oldest block whose undo record is still held.
    ///
    /// Kept as a cursor rather than recomputed, so trimming one block off the
    /// back costs the same whether the chain is a day or a decade old.
    undo_from: u64,
    state: LedgerState,
    /// Transfers waiting for a block, keyed by identifier so the order a miner
    /// walks them in does not depend on the order they arrived.
    pool: BTreeMap<Hash32, Pooled>,
    /// What the pool takes altogether.
    ///
    /// Counting transfers alone bounds the wrong thing. One may spend two
    /// hundred and fifty six notes out of the cold set, each carrying its own
    /// proof, which runs to half a megabyte; four thousand of those is two
    /// gigabytes of memory handed to whoever cared to send them, without a
    /// single rule being broken.
    pool_bytes: usize,
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
            branch: Branch::default(),
            applied: HashMap::new(),
            undo_from: 0,
            state,
            pool: BTreeMap::new(),
            pool_bytes: 0,
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
        self.branch.tip()
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

    /// Whether `id` is on the part of the followed branch held in full.
    ///
    /// False for a block further back than a reorganisation could reach, which
    /// is not the same as saying it is not on the branch. Ask by height for
    /// those.
    pub fn is_active(&self, id: &Hash32) -> bool {
        self.branch.height_of(id).is_some()
    }

    /// The height `id` sits at, for the part of the branch held in full.
    pub fn height_of(&self, id: &Hash32) -> Option<u64> {
        self.branch.height_of(id)
    }

    /// The identifier the followed branch carries at `height`, when this node
    /// still holds it: everything inside the reorganisation window, and one
    /// height in every [`MILESTONE`] before that.
    pub fn id_at(&self, height: u64) -> Option<Hash32> {
        self.branch.id_at(height)
    }

    /// Whether the branch carries `entry.id` at `entry.height`.
    ///
    /// The answer to a position claimed by a peer. `false` covers both a
    /// height this node holds something else at and one it no longer holds an
    /// identifier for, which is why a peer's locator names heights this node
    /// is sure to have kept.
    pub fn agrees_with(&self, entry: &Located) -> bool {
        self.branch.id_at(entry.height) == Some(entry.id)
    }

    /// The identifiers this node holds for the followed branch, oldest first.
    ///
    /// Only what it still holds: the window a reorganisation may reach, and
    /// one identifier every [`MILESTONE`] heights before that. Everything else
    /// is on disk. Callers wanting the branch in order should walk heights and
    /// read a log, which is what an explorer does.
    pub fn held_ids(&self) -> Vec<Hash32> {
        let mut ids: Vec<Hash32> = self.branch.milestones.clone();
        ids.extend(self.branch.recent.iter().copied());
        ids
    }

    /// The block the followed branch carries at `height`, when this node still
    /// holds its body.
    pub fn block_at(&self, height: u64) -> Option<&Block> {
        let id = self.branch.id_at(height)?;
        self.block(&id)
    }

    /// The first block of the followed branch.
    pub fn genesis(&self) -> Option<Hash32> {
        self.branch.genesis()
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
    ///
    /// Every height named here is one this node is sure to still hold, so a
    /// peer comparing the two is comparing like with like: inside the window
    /// any height will do, and outside it only the milestones exist, so the
    /// walk steps back to one whenever it would land between them. Both sides
    /// keep milestones at the same heights, which is what makes them meet.
    pub fn locator(&self) -> Vec<Located> {
        let mut locator = Vec::new();
        let Some(mut height) = self.height() else {
            return locator;
        };

        let mut step = 1u64;
        let mut dense = 0usize;
        loop {
            if let Some(id) = self.branch.id_at(height) {
                locator.push(Located::new(height, id));
            }
            if height == 0 || locator.len() >= MAX_LOCATOR {
                break;
            }
            dense = dense.saturating_add(1);
            if dense > 10 {
                step = step.saturating_mul(2);
            }
            height = self.step_back(height, step);
        }
        locator
    }

    /// The next height back from `height`, landing on something this node
    /// still holds and always moving.
    fn step_back(&self, height: u64, step: u64) -> u64 {
        let wanted = height.saturating_sub(step);
        if wanted >= self.branch.from || wanted == 0 {
            return wanted;
        }
        // Outside the window only the milestones are left, so round down to
        // one. Rounding can land back on `height` itself, so a step that would
        // not move goes one milestone further.
        let rounded = wanted.saturating_sub(wanted % MILESTONE);
        if rounded < height {
            return rounded;
        }
        rounded.saturating_sub(MILESTONE)
    }

    /// How far this node's branch runs past the last position in `locator` it
    /// agrees with, as a first height and how many blocks follow it.
    ///
    /// Heights rather than identifiers, because a node no longer holds an
    /// identifier for every height and reading them off a disk to answer this
    /// would be a seek per block. What a peer does with them is ask for blocks
    /// at those heights and check each one as it arrives, which it has to do
    /// regardless: a block carries what it is built on, so a chain of them
    /// proves its own order.
    ///
    /// When nothing in the locator is recognised the answer starts at zero,
    /// which is what a node syncing from scratch needs.
    pub fn chain_after(&self, locator: &[Located], max: u64) -> (u64, u64) {
        let common = locator
            .iter()
            .find(|entry| self.agrees_with(entry))
            .map(|entry| entry.height);
        let from = common.map_or(0, |height| height.saturating_add(1));
        let count = self.branch.len().saturating_sub(from).min(max);
        (from, count)
    }

    /// Undo records held, which is bounded by [`MAX_REORG_DEPTH`].
    pub fn undo_records(&self) -> usize {
        self.applied.len()
    }

    /// Transfers waiting for a block.
    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }

    /// What every transfer waiting for a block takes altogether.
    pub fn pool_bytes(&self) -> usize {
        self.pool_bytes
    }

    pub fn pooled(&self, id: &Hash32) -> Option<&Transfer> {
        self.pool.get(id).map(|held| &held.transfer)
    }

    /// Every transfer waiting for a block, in identifier order.
    pub fn pooled_transfers(&self) -> impl Iterator<Item = (&Hash32, &Transfer)> {
        self.pool.iter().map(|(id, held)| (id, &held.transfer))
    }

    /// Takes one transfer out of the pool and its indexes.
    fn drop_pooled(&mut self, id: &Hash32) {
        let Some(held) = self.pool.remove(id) else {
            return;
        };
        self.pool_by_fee.remove(&(held.fee, *id));
        self.pool_bytes = self.pool_bytes.saturating_sub(held.bytes);
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

        // A transfer larger than a block can carry would wait in the pool for
        // a block that can never be built, while whoever sent it believes it
        // is on its way. Refused here, so the refusal reaches them.
        //
        // Measured against the whole block rather than against a block minus
        // its header, because the exact margin belongs to whoever assembles
        // one; what matters here is that the impossible is turned away.
        let bytes = transfer.encode().len();
        if bytes > self.params.max_block_bytes {
            return Err(TransferError::TooLargeForABlock {
                bytes,
                limit: self.params.max_block_bytes,
            });
        }

        // A full pool that refuses everything is a pool anyone can close. Four
        // thousand transfers paying nothing would hold every place, and a
        // sender who paid would be turned away behind them, for as long as the
        // attacker cared to keep it up. So a full pool makes room for whoever
        // pays more than the least it already holds, and refuses only what
        // would not improve it.
        //
        // Full by count or full by size: one large transfer can take the room
        // of a hundred small ones, so both have to be made room for, and one
        // arrival can displace several.
        while self.pool.len() >= MAX_POOLED
            || self.pool_bytes.saturating_add(bytes) > MAX_POOL_BYTES
        {
            let Some((cheapest, victim)) = self.pool_by_fee.first().copied() else {
                return Ok(false);
            };
            if outcome.fee <= cheapest {
                return Ok(false);
            }
            self.drop_pooled(&victim);
        }

        self.pool_bytes = self.pool_bytes.saturating_add(bytes);
        self.pool.insert(
            id,
            Pooled {
                transfer,
                fee: outcome.fee,
                bytes,
            },
        );
        self.pool_by_fee.insert((outcome.fee, id));
        Ok(true)
    }

    /// Room set aside for everything in a block that is not a transfer.
    ///
    /// The header is fixed and small, and the coinbase is at most sixteen
    /// notes. Four kilobytes is several times either, which is the right
    /// margin for a number whose only job is to keep the selection below a
    /// limit checked exactly elsewhere.
    const BLOCK_OVERHEAD_BYTES: usize = 4096;

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
            .filter_map(|(_, id)| self.pool.get(id))
            .map(|held| &held.transfer);

        // What is left for transfers once the rest of the block is allowed for.
        let mut room = self
            .params
            .max_block_bytes
            .saturating_sub(Self::BLOCK_OVERHEAD_BYTES);

        for transfer in ordered {
            if chosen.len() >= limit {
                break;
            }
            // A block over the limit is refused by every node including the
            // one that made it, so a miner that filled one past it would have
            // spent the work for nothing.
            let size = transfer.encode().len();
            let Some(remaining) = room.checked_sub(size) else {
                continue;
            };
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
            room = remaining;
            chosen.push(transfer.clone());
        }
        (chosen, fees)
    }

    fn pooled_inputs(&self) -> BTreeSet<NoteId> {
        self.pool
            .values()
            .flat_map(|held| held.transfer.inputs.iter().map(|input| input.note_id))
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
        let mut bytes = 0usize;
        self.pool.retain(|id, held| {
            match check_transfer(
                &held.transfer,
                state,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &params,
            ) {
                // The fee is worked out again rather than carried over: what a
                // transfer pays depends on the state, and the state is what
                // moved. What it takes does not, so that is kept.
                Ok(outcome) => {
                    held.fee = outcome.fee;
                    kept.insert((outcome.fee, *id));
                    bytes = bytes.saturating_add(held.bytes);
                    true
                }
                Err(_) => false,
            }
        });
        self.pool_by_fee = kept;
        self.pool_bytes = bytes;
    }

    /// Takes a ledger built somewhere else, at a tip this node was not on.
    ///
    /// For a node joining a chain rather than replaying one. What it is handed
    /// has already been checked against the header that commits to it, and
    /// that header against the work behind it, so what is left here is putting
    /// it in place.
    ///
    /// Only onto a node with no chain at all. Replacing a chain a node already
    /// follows would be a reorganisation of unbounded depth, decided by
    /// whoever offered the replacement, which is the one thing the depth limit
    /// exists to refuse.
    ///
    /// The branch starts from the headers that came with the ledger, so this
    /// node knows where it is and can be reorganised as far back as those go.
    /// It holds no milestones, because it has no history to hold: it can say
    /// what it is following and cannot answer about what came before, which is
    /// the honest position for a node that was not there.
    pub fn adopt(&mut self, state: LedgerState, recent: &[BlockHeader]) -> Result<(), ChainError> {
        if !self.branch.is_empty() {
            return Err(ChainError::AlreadyFollowing);
        }
        let Some(tip) = state.tip() else {
            return Err(ChainError::Corrupt);
        };
        let Some(last) = recent.last() else {
            return Err(ChainError::Corrupt);
        };
        if last.id() != tip.id {
            return Err(ChainError::Corrupt);
        }

        self.state = state;
        self.branch = Branch::from_tail(recent);
        // Nothing here can be undone: undoing takes the record of what a block
        // did, and this node was not there when they were done. So the window
        // starts closed and opens as this node applies blocks of its own.
        self.undo_from = self.branch.len();
        self.applied.clear();
        self.blocks.clear();
        Ok(())
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

        // A block that builds straight on the tip needs no parent in memory:
        // what a parent is read for is the height and the work behind it, and
        // both of those are what the tip is. That is the ordinary case on a
        // chain being followed, and the only case at all on a node that was
        // handed its ledger rather than building it, which holds no blocks.
        if self.branch.tip() == Some(block.header.previous) {
            let expected = self.height().and_then(|tip| tip.checked_add(1));
            if Some(block.header.height) != expected {
                return Err(ChainError::BrokenHeight {
                    parent: self.height().unwrap_or(0),
                    found: block.header.height,
                });
            }
            let total_work = self
                .total_work()
                .saturating_add(work_of(block.header.difficulty));
            self.blocks.insert(id, StoredBlock { block, total_work });
            return self.follow(id, now);
        }

        let total_work = if self.branch.is_empty() {
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
        let keep = fork_position.map_or(0, |height| height.saturating_add(1));
        let depth = usize::try_from(self.branch.len().saturating_sub(keep)).unwrap_or(usize::MAX);
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
    fn branch_to(&self, target: Hash32) -> Result<(Option<u64>, Vec<Hash32>), ChainError> {
        let mut branch = Vec::new();
        let mut cursor = target;
        loop {
            if let Some(height) = self.branch.height_of(&cursor) {
                branch.reverse();
                return Ok((Some(height), branch));
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
                if self.branch.is_empty() {
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
    fn rewind_to(&mut self, position: Option<u64>) -> Result<Vec<Hash32>, ChainError> {
        let keep = position.map_or(0, |height| height.saturating_add(1));
        let mut removed = Vec::new();
        while self.branch.len() > keep {
            let id = self.branch.pop().ok_or(ChainError::Corrupt)?;
            let connected = self.applied.remove(&id).ok_or(ChainError::Corrupt)?;
            disconnect_block(&mut self.state, &connected);
            removed.push(id);
        }
        self.undo_from = self.undo_from.min(self.branch.len());
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
        let window = u64::try_from(MAX_REORG_DEPTH).unwrap_or(u64::MAX);
        while self.branch.len().saturating_sub(self.undo_from) > window {
            let Some(id) = self.branch.id_at(self.undo_from) else {
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
    ///
    /// What is held is the window a reorganisation may reach back over, plus
    /// whatever branches were offered inside it. It used to be measured
    /// against the height of the chain, which was the same number back when a
    /// node kept every block it had ever applied. It is not any more, and a
    /// ceiling that grew with the chain was one this never reached: side
    /// branches accumulated with nothing to clear them.
    fn forget_unreachable_branches(&mut self) {
        let limit = MAX_REORG_DEPTH.saturating_add(MAX_SIDE_BLOCKS);
        if self.blocks.len() <= limit {
            return;
        }
        let Some(cutoff) = self
            .height()
            .and_then(|tip| tip.checked_sub(u64::try_from(MAX_REORG_DEPTH).unwrap_or(u64::MAX)))
        else {
            return;
        };
        let branch = &self.branch;
        self.blocks.retain(|id, stored| {
            branch.height_of(id).is_some() || stored.block.header.height >= cutoff
        });
        self.invalid.retain(|id| branch.height_of(id).is_none());
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
        self.branch.push(id);
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
            let id = self.branch.pop().ok_or(ChainError::Corrupt)?;
            let connected = self.applied.remove(&id).ok_or(ChainError::Corrupt)?;
            disconnect_block(&mut self.state, &connected);
        }
        // `rolled_back` came off the tip newest first, so it goes back on in
        // the opposite order.
        for id in rolled_back.iter().rev() {
            self.apply(*id, now)?;
        }
        Ok(())
    }
}

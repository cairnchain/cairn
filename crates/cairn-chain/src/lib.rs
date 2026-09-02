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
use std::sync::Arc;

use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
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
/// Half an hour of full blocks, which is as far ahead as a pool is any use:
/// what waits longer than that is waiting because nobody will carry it.
/// Counting bytes as well as transfers is what makes the ceiling mean
/// something, since one transfer spending notes out of the cold set carries a
/// proof for each and can run to half a megabyte on its own.
pub const MAX_POOL_BYTES: usize = 4 * 1024 * 1024;

/// What one more note in the hot set adds to a transfer's weight, in bytes.
///
/// A transfer is not priced by its bytes alone, because bytes are not the
/// resource this design exists to protect. Every note a transfer creates
/// beyond what it spends takes a place in the hot set, and on a busy chain the
/// tier is full, so the place is taken from whoever holds the oldest note
/// there: their money now needs a proof to spend. Priced by bytes, a transfer
/// creating two hundred and fifty six notes churned the tier more than four
/// times cheaper than the payments it displaced, because an output is forty
/// bytes and a payment is nearly two hundred.
///
/// Five hundred and twelve is the measured cost of holding a hot note, rounded
/// down to a power of two; `cairn-ledger/examples/footprint.rs` measures it.
/// Charging a place what the place costs is a judgement rather than a theorem,
/// but it buys the property that matters: pushing a note out of the tier costs
/// about what an ordinary payment costs, however the pusher shapes the
/// transfer. `cairn-ledger/examples/blocksize.rs` works the ratio out from
/// measured sizes.
pub const NOTE_WEIGHT: usize = 512;

/// The least a transfer pays per unit of weight, in pebbles.
///
/// Zero used to be accepted, and on a quiet chain zero was also mined, since a
/// block with room takes what is offered. That made churning the hot set free
/// exactly when notes stay hot the longest and the churn does the most
/// relative harm. The floor's job is to exist, not to deter on its own: no
/// fixed number can, because nobody knows what a pebble will buy. Deterrence
/// comes from the weight above when blocks are contested, and from the
/// eviction cap in the consensus rules always.
///
/// Ten is a judgement: an ordinary payment weighs about seven hundred, so it
/// pays a few thousand pebbles, dust against anything worth a block's room,
/// while pushing the whole tier out costs whole CAIRN even on an empty chain.
/// This is local policy, not consensus: a block carrying cheaper transfers is
/// still valid, this node just will not pool or build one.
pub const MIN_FEE_PER_WEIGHT: u64 = 10;

/// Fixed point scale for fee against weight, so the pool can order transfers
/// without dividing pebbles away.
const RATE_SCALE: u128 = 1 << 16;

/// What carrying a transfer takes from the network: its bytes, plus a charge
/// for every place it takes in the hot set.
///
/// `freed` is how many of the spent notes were actually in the hot set, so
/// only those are credited with giving a place back. Counting inputs instead
/// was the obvious thing and it was wrong at one boundary: a note that has
/// just fallen may still be spent through the grace window with a plain hot
/// witness, a hundred bytes and no proof, and it frees nothing, because it
/// left the tier already. A transfer re-spending a handful of those and
/// paying them straight back to itself was charged for no places at all while
/// pushing that many notes out, which churned the tier at about a fifth of an
/// ordinary payment's price: the discount this weight exists to close, back
/// through the one door left open. A cold input carries its proof, so its
/// bytes already cover the place it does not free.
///
/// This makes the weight depend on the state, which the earlier note here
/// gave as the reason not to do it: a price that moves under the wallet
/// quoting it cannot be paid on purpose. It moves by one place, five thousand
/// one hundred and twenty pebbles, and only for a note that falls between the
/// quote and the node reading it. A wallet already asks for the number and is
/// told the number when it is short, which is the answer to a price that
/// moves, and being unable to state the price of the one shape worth gaming
/// is not.
///
/// A transfer that spends more hot notes than it creates weighs its bytes and
/// nothing more: consolidation gives the tier room back, and this is where
/// that is worth something.
#[must_use]
pub fn transfer_weight(transfer: &Transfer, bytes: usize, freed: usize) -> usize {
    let places = transfer.outputs.len().saturating_sub(freed);
    bytes.saturating_add(places.saturating_mul(NOTE_WEIGHT))
}

/// The least a transfer of this weight pays to be pooled at all.
#[must_use]
pub fn fee_floor(weight: usize) -> Amount {
    let pebbles = u64::try_from(weight)
        .unwrap_or(u64::MAX)
        .saturating_mul(MIN_FEE_PER_WEIGHT);
    Amount::from_pebbles(pebbles).unwrap_or(Amount::MAX_MONEY)
}

/// What a transfer pays for each unit of what it takes, as a fixed point
/// number every node computes identically.
fn rate(fee: Amount, weight: usize) -> u128 {
    let weight = u128::try_from(weight.max(1)).unwrap_or(1);
    u128::from(fee.as_pebbles())
        .saturating_mul(RATE_SCALE)
        .checked_div(weight)
        .unwrap_or(0)
}

/// A transfer waiting for a block, with what it pays and what it takes.
///
/// All three are worked out once, when it arrives. The fee against the weight
/// decides what it displaces and what a miner reaches for first; the bytes
/// decide whether there is room. Reading any of them again from the transfer
/// itself would mean encoding it or revalidating it on every comparison.
#[derive(Clone, Debug)]
struct Pooled {
    transfer: Transfer,
    fee: Amount,
    bytes: usize,
    /// Bytes plus the hot set places taken, which is what the fee is measured
    /// against. Fixed by the transfer's shape, so unlike the fee it never has
    /// to be worked out again.
    weight: usize,
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

/// A handover is taken from [`cairn_ledger::handover::BURIAL`] blocks below
/// the tip, and reaching that height means undoing every block above it, so
/// the undo records have to stretch at least that far.
///
/// Written down because the two numbers live in different crates and are
/// equal, which leaves no margin at all. They were once one apart in the
/// wrong direction, by an off-by-one in the guard below rather than in either
/// number, and the whole handover was quietly unreachable on any chain past a
/// thousand blocks: a newcomer was never handed a ledger and a restarting
/// node never read its own. Nothing failed, nothing was logged, and the
/// devnet tests missed it because devnet buries at thirty two. If either
/// number moves again, this stops the build rather than the network.
const _: () = assert!(cairn_ledger::handover::BURIAL <= MAX_REORG_DEPTH as u64);

/// A coinbase becomes spendable when its block can no longer be undone, and
/// this is where "can no longer be undone" is decided, so the two numbers have
/// to be the same one.
///
/// Written down for the same reason as the line above: they live in different
/// crates, and the whole claim the maturity rule makes is that a reward cannot
/// be spent while the block that paid it is still reachable by a
/// reorganisation. A maturity shorter than this depth quietly stops being that
/// claim, and nothing else would say so.
///
/// This ties the two constants. A network that lowers its own burial and
/// maturity together, as devnet does, keeps the claim through
/// [`ChainStore::undo_limit`], which is where the rule is actually applied.
const _: () = assert!(cairn_ledger::validation::COINBASE_MATURITY == MAX_REORG_DEPTH as u64);

/// Blocks kept off the followed branch before the unreachable ones are
/// dropped.
///
/// A branch that lost by more than [`MAX_REORG_DEPTH`] can never be switched
/// to, so holding its blocks is holding history nobody will ask for.
const MAX_SIDE_BLOCKS: usize = 4_096;

/// Bytes of blocks off the followed branch kept before the oldest are dropped.
///
/// A count of blocks does not bound memory, because a block is not a fixed
/// size. Counting them alone let an adversary offer four thousand blocks at
/// the largest the rules allow, which is most of a gigabyte held on the word
/// of a peer. It is the same shape of defect as a pool that counted transfers
/// rather than bytes: two limits written in two files whose product nobody had
/// worked out.
///
/// Thirty two megabytes is hundreds of full blocks and tens of thousands of
/// ordinary ones, which is far past any reorganisation a live network
/// produces. A branch cut short by this is not lost, only forgotten: it is
/// asked for again if it turns out to matter.
const MAX_SIDE_BYTES: usize = 32 * 1024 * 1024;

/// Blocks whose bodies stay in memory behind the tip.
///
/// A reorganisation reads the bodies of everything it undoes, so keeping the
/// recent ones is keeping every reorganisation a live network actually
/// produces off the disk. Beyond this a switch costs some reading, which is
/// the right trade for an event that deep: it is rare, and the alternative is
/// holding hundreds of megabytes against it.
const WARM_BODIES: u64 = 64;

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
        "switching branches here would undo {depth} blocks, past the {limit} this \
         network calls settled"
    )]
    ForkTooDeep { depth: usize, limit: u64 },
    #[error(
        "a block at height {height} is below {floor}, the oldest this node could \
         still reorganise onto"
    )]
    TooOld { height: u64, floor: u64 },
    #[error("this node already follows a chain, and one is all it may follow")]
    AlreadyFollowing,
    #[error("block {id} was refused once already, and every branch through it with it")]
    KnownBad { id: Hash32 },
    #[error("the block tree lost a block it had recorded")]
    Corrupt,
}

/// A height whose rules this software does not have.
///
/// Told apart from every other refusal on purpose. A node that reaches this
/// has not met a bad peer: it has met the network moving on without it, and
/// the two call for opposite reactions. Treating it as a bad peer would drop
/// every node that had updated and leave this one following whoever had not,
/// which is a minority chain believed to be the chain, the one outcome a
/// scheduled rule change has to avoid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outdated {
    /// Where the rules this software lacks take effect.
    pub height: u64,
    /// The block version they are written under.
    pub required: u16,
    /// The highest version this software knows.
    pub known: u16,
}

impl ChainError {
    /// The rules this node lacks, when that is why the block was refused.
    /// Whether this failure condemns the header itself.
    ///
    /// A block's identifier is taken over its header, and a header does not
    /// commit to the signatures that make its body valid. Two different blocks
    /// can therefore share an identifier, so only a failure the header alone
    /// settles may be remembered against one: a timestamp out of range, a
    /// parent that is not there, work that was not done.
    ///
    /// Anything the body decides (a signature, a root that does not match, a
    /// coinbase that overpays) says nothing about another body carrying the
    /// same identifier. Remembering that would let anyone lock the real block
    /// out of a node by sending a corrupted twin first, at the cost of copying
    /// it: the twin inherits the real block's work, so it is free.
    ///
    /// Listed rather than excluded, so a failure added later is not condemned
    /// by default. Refusing to remember costs one validation. Remembering
    /// wrongly costs a node the chain.
    ///
    /// Two verdicts look as though the header settles them and do not, which
    /// is why they are named here rather than merely absent from the list.
    ///
    /// A version this build does not accept is the second. It is measured
    /// against the schedule this node happens to be carrying, so it is a
    /// judgement about the reader and not about the header, and it changes
    /// the moment the reader is updated. Remembering it made an un-updated
    /// node condemn the real chain for good, and then refuse every honest
    /// peer that offered it. Nothing here is remembered any more, and a
    /// version above what this build knows is answered as being too old
    /// rather than as a bad block, so the node stops and says so rather than
    /// quietly mining a chain of its own.
    /// A timestamp too far ahead is measured against the reading node's own
    /// clock, so it is the one refusal in the whole set that two honest nodes
    /// can disagree about, and that the same node reverses simply by waiting.
    /// Remembering it turned a second of clock skew into a permanent exile: a
    /// miner publishing a block dated at the edge of the allowed drift, which
    /// costs nothing and is valid to everybody whose clock is right, put that
    /// block on the blacklist of every node running slightly slow, and from
    /// then on those nodes refused the whole chain through it and blamed every
    /// honest peer that offered it.
    fn settles_the_header(&self) -> bool {
        let Self::InvalidBlock { source, .. } = self else {
            return false;
        };
        matches!(
            source,
            BlockError::WrongNetwork { .. }
                | BlockError::WrongHeight { .. }
                | BlockError::WrongParent { .. }
                | BlockError::HeightOverflow
                | BlockError::TimestampNotAfterMedian { .. }
                | BlockError::BeforeTheNetworkOpened { .. }
                | BlockError::WrongGenesis { .. }
                | BlockError::WrongDifficulty { .. }
                | BlockError::InsufficientWork { .. }
                | BlockError::WrongTotalWork { .. }
                | BlockError::WrongVersion { .. }
        )
    }

    pub fn outdated(&self) -> Option<Outdated> {
        match self {
            Self::InvalidBlock {
                source:
                    BlockError::SoftwareTooOld {
                        height,
                        required,
                        known,
                    },
                ..
            } => Some(Outdated {
                height: *height,
                required: *required,
                known: *known,
            }),
            _ => None,
        }
    }
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
    /// Kept whatever happens to the body: it is what the fork choice, the
    /// branch walk and the sweeps all read, and it is 182 bytes against as
    /// much as 128 kB.
    header: BlockHeader,
    /// The body, while this node still holds it.
    ///
    /// Let go of once the block is on disk and far enough back that no
    /// ordinary reorganisation would reach it. Everything that needs one
    /// again reads it from there.
    body: Option<Block>,
    /// Work of this block plus every block behind it.
    total_work: u128,
    /// What this block takes on the wire, measured once when it arrives.
    ///
    /// Held rather than recomputed because what it bounds is checked on every
    /// block, and encoding a full one to ask its size would cost more than
    /// keeping the answer.
    bytes: usize,
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
            // Only when this is the milestone the list is actually missing.
            // A branch handed a tail holds none at all, by design, and the
            // list is read by index: appending to an empty one would file a
            // block from height five thousand where height zero is looked up,
            // and `locator` would then offer a peer a position this node
            // cannot stand behind.
            let index = usize::try_from(height / MILESTONE).unwrap_or(usize::MAX);
            if index == self.milestones.len() {
                self.milestones.push(id);
            }
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
/// Where a chain reads back the body of a block it let go of.
///
/// A node holds the bodies of the blocks it could still have to undo, which on
/// a chain running at the limit is hundreds of megabytes for something already
/// written to its disk. Handed one of these, it keeps the recent ones in
/// memory and reads the rest.
///
/// Answers by height, on the branch this node follows, because that is what a
/// log is: records in order of height. What comes back is checked against the
/// identifier it was asked for, so a log that has moved on cannot pass the
/// wrong block off as the right one.
pub trait Bodies: std::fmt::Debug + Send + Sync {
    fn body(&self, height: u64) -> Option<Block>;
}

#[derive(Debug)]
pub struct ChainStore {
    params: ConsensusParams,
    blocks: HashMap<Hash32, StoredBlock>,
    /// Wire bytes of every block held in `blocks`, so what bounds them can be
    /// checked without walking the map on each arrival.
    held_bytes: usize,
    /// Where bodies are read back from, for a node that has somewhere to read
    /// them. Without one it keeps every body it may still need, which is what
    /// a chain with no disk behind it does.
    bodies: Option<Arc<dyn Bodies>>,
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
    /// The same transfers by what they pay for what they take, cheapest first.
    ///
    /// Kept alongside rather than derived, so finding what to make room for
    /// costs a lookup and not a pass over the pool: a peer sending transfers
    /// as fast as it can would otherwise decide how much work each one causes.
    pool_by_rate: BTreeSet<(u128, Hash32)>,
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
            held_bytes: 0,
            bodies: None,
            invalid: HashSet::new(),
            branch: Branch::default(),
            applied: HashMap::new(),
            undo_from: 0,
            state,
            pool: BTreeMap::new(),
            pool_bytes: 0,
            pool_by_rate: BTreeSet::new(),
        }
    }

    /// Lets go of the bodies of blocks written down and old enough that no
    /// ordinary reorganisation would reach them.
    ///
    /// `written` is the height the caller has on disk, exclusive. Nothing
    /// above it is touched: a body let go of before it was written is a body
    /// nobody has.
    ///
    /// Only for a chain that was told where to read them back. Without that
    /// this does nothing, because it would be throwing them away.
    pub fn release_bodies(&mut self, held_from: u64, written: u64) {
        if self.bodies.is_none() {
            return;
        }
        let Some(tip) = self.height() else { return };
        let keep_from = tip.saturating_sub(WARM_BODIES);
        let below = written.min(keep_from);
        // Never below where the log begins. A body is in memory or on disk and
        // never in neither, and what the log holds at its front is whatever an
        // operator's budget left there. Letting go of a body below that leaves
        // a reorganisation that fails partway with nowhere to read back the
        // branch it was restoring, and a node on neither branch.
        //
        // So the budget trades disk against memory rather than against being
        // able to put a branch back: an operator who keeps almost nothing gets
        // a node holding its undo window in memory, which is what it did before
        // any of this was written down.
        let from = self.undo_from.max(held_from);
        for height in from..below {
            let Some(id) = self.branch.id_at(height) else {
                continue;
            };
            if let Some(stored) = self.blocks.get_mut(&id) {
                if stored.body.take().is_some() {
                    self.held_bytes = self.held_bytes.saturating_sub(stored.bytes);
                }
            }
        }
    }

    /// How many blocks this node still holds the body of.
    ///
    /// What `release_bodies` changes, and the only way to see that it did.
    #[must_use]
    pub fn bodies_held(&self) -> usize {
        self.blocks
            .values()
            .filter(|stored| stored.body.is_some())
            .count()
    }

    /// Says where bodies can be read back from.
    ///
    /// Set once, before anything is applied. Without it this chain keeps every
    /// body it might still need, which is correct and costs memory.
    pub fn reads_bodies_from(&mut self, bodies: Arc<dyn Bodies>) {
        self.bodies = Some(bodies);
    }

    /// Asks to be told where this owner's notes go when they fall, and to
    /// keep their proofs current.
    ///
    /// Set before any block is applied, since what is learned is learned as
    /// the notes fall.
    pub fn watch_owner(&mut self, owner: cairn_crypto::PublicKey) {
        self.state.watch_owner(owner);
    }

    /// Whether this node keeps the cold set, and can therefore rebuild the
    /// proof of a note whose owner lost theirs.
    ///
    /// This used to be half of a larger role, the other half being the headers
    /// a newcomer is shown. Those live on disk now and every node keeps them,
    /// so what is left here is one service and not two: a cost that grows with
    /// every note ever spent, carried by whoever offers it.
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
    ///
    /// Taken from the ledger rather than from the block held for the tip,
    /// because a node handed a ledger has no such block. It read zero there,
    /// which is the worst answer this could give: a node that believes no work
    /// stands behind it accepts any branch at all as heavier.
    ///
    /// The two agree everywhere else. A header states the work behind it and
    /// the rules refuse it unless that is what the chain actually carries, so
    /// the sum a node accumulates block by block and the figure the tip states
    /// are the same figure.
    pub fn total_work(&self) -> u128 {
        self.state.total_work()
    }

    pub fn block(&self, id: &Hash32) -> Option<&Block> {
        self.blocks.get(id).and_then(|stored| stored.body.as_ref())
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

    /// Whether this node is on no chain at all.
    ///
    /// Asked of the branch and not of the blocks held for it. A node handed a
    /// ledger holds no block and is very much on a chain, and reading this
    /// from the blocks told it otherwise: it would have asked to be handed a
    /// ledger again at every peer it met.
    pub fn is_empty(&self) -> bool {
        self.branch.is_empty()
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
    /// The lowest height this node still holds a block for.
    ///
    /// Zero for a node that read its chain from the first block, and the
    /// height it was handed for a node that joined. What a log written from
    /// what this node holds has to start at.
    /// The lowest height this chain can still answer a header for.
    ///
    /// Below [`Self::branch_start`] on a chain that has been running: the
    /// branch remembers identifiers far further back than the blocks
    /// themselves, by milestones, and what a block was is dropped entirely
    /// once it is past undoing. So a walk that wants headers has to start
    /// here, and starting at the branch's own beginning asks for blocks this
    /// chain let go of on purpose.
    ///
    /// On a node that joined a chain this is its anchor, which is the honest
    /// answer: the chain below it is one that node was never given.
    #[must_use]
    pub fn held_from(&self) -> u64 {
        self.undo_from
    }

    pub fn branch_start(&self) -> Option<u64> {
        if self.branch.is_empty() {
            return None;
        }
        Some(self.branch.from)
    }

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

    /// The header of the branch's block at `height`, body or no body.
    ///
    /// A header is kept for every block on the branch whatever happens to its
    /// body, so this answers where [`Self::block_at`] stops. Anything that
    /// wants a header and asks for the block instead is asking for a hundred
    /// and eighty two bytes and being refused for the want of a hundred and
    /// twenty eight kilobytes it has no use for.
    #[must_use]
    pub fn header_at(&self, height: u64) -> Option<BlockHeader> {
        let id = self.branch.id_at(height)?;
        self.blocks.get(&id).map(|stored| stored.header)
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
        self.pool_by_rate
            .remove(&(rate(held.fee, held.weight), *id));
        self.pool_bytes = self.pool_bytes.saturating_sub(held.bytes);
    }

    /// Takes a transfer that has been broadcast, returning whether it was new.
    ///
    /// A transfer is checked against the state as it stands, so a node never
    /// holds one it already knows cannot be included. It pays at least the
    /// floor for its weight, or it is refused with the floor named, so the
    /// refusal reaches whoever set the fee.
    ///
    /// A transfer spending a note another pooled transfer already spends can
    /// replace it, by paying for everything it displaces and then the floor
    /// again on top. An identifier excludes its witness on purpose, so a
    /// transfer offered again with a fresher proof is the same transfer and
    /// none of this applies to it: it is already here.
    pub fn accept_transfer(&mut self, transfer: Transfer) -> Result<bool, TransferError> {
        let id = transfer.id();
        if self.pool.contains_key(&id) {
            return Ok(false);
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

        let weight = transfer_weight(&transfer, bytes, outcome.spent_hot.len());
        let floor = fee_floor(weight);
        if outcome.fee < floor {
            return Err(TransferError::FeeBelowFloor {
                fee: outcome.fee,
                floor,
            });
        }
        let offered = rate(outcome.fee, weight);
        let (conflicts, conflict_bytes) =
            self.displaced_by(&transfer, outcome.fee, offered, floor)?;

        // A full pool that refuses everything is a pool anyone can close, so a
        // full one makes room for whoever pays a better rate than the least it
        // already holds, and refuses only what would not improve it. Full by
        // count or full by size: one large transfer can take the room of a
        // hundred small ones, so both have to be made room for, and one
        // arrival can displace several.
        //
        // Decided before anything is dropped. A refusal partway through would
        // otherwise have already thrown out transfers the newcomer then never
        // replaced.
        let mut victims: Vec<Hash32> = Vec::new();
        {
            let mut count = self.pool.len().saturating_sub(conflicts.len());
            let mut held = self
                .pool_bytes
                .saturating_sub(conflict_bytes)
                .saturating_add(bytes);
            let mut cheapest_first = self.pool_by_rate.iter();
            while count >= MAX_POOLED || held > MAX_POOL_BYTES {
                let Some((cheapest, victim)) = cheapest_first.next() else {
                    return Ok(false);
                };
                if conflicts.contains(victim) {
                    continue;
                }
                if offered <= *cheapest {
                    return Ok(false);
                }
                let Some(losing) = self.pool.get(victim) else {
                    return Ok(false);
                };
                victims.push(*victim);
                count = count.saturating_sub(1);
                held = held.saturating_sub(losing.bytes);
            }
        }
        for gone in &conflicts {
            self.drop_pooled(gone);
        }
        for gone in &victims {
            self.drop_pooled(gone);
        }

        self.pool_bytes = self.pool_bytes.saturating_add(bytes);
        self.pool.insert(
            id,
            Pooled {
                transfer,
                fee: outcome.fee,
                bytes,
                weight,
            },
        );
        self.pool_by_rate.insert((offered, id));
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
    /// Walked from the best rate down, and within the same rate in identifier
    /// order, so two nodes holding the same pool build the same block. Order
    /// is a miner's choice and not a rule: a block is valid whatever order its
    /// transfers were picked in. But picking by identifier meant a fee bought
    /// nothing, and picking by the fee alone let one large transfer buy a
    /// block's worth of room for the price of one payment. What is greedy here
    /// is a choice too: a cleverer packing might squeeze out more fees, but
    /// every node has to be able to predict a block, and greedy from the best
    /// rate down is the packing everyone can predict.
    pub fn selection(&self, limit: usize) -> (Vec<Transfer>, Amount) {
        let mut chosen = Vec::new();
        let mut spent_hot: BTreeSet<NoteId> = BTreeSet::new();
        let mut spent_cold: BTreeMap<NoteId, ColdSpend> = BTreeMap::new();
        let mut fees = Amount::ZERO;

        // Best rate first. The rate here is what it was worth when it was
        // admitted, which is a hint rather than a promise: what each one
        // actually pays is worked out again below, against the state as it
        // stands now.
        let ordered = self
            .pool_by_rate
            .iter()
            .rev()
            .filter_map(|(_, id)| self.pool.get(id))
            .map(|held| &held.transfer);

        // What is left for transfers once the rest of the block is allowed for.
        let mut room = self
            .params
            .max_block_bytes
            .saturating_sub(Self::BLOCK_OVERHEAD_BYTES);

        // How many notes the block may still add to the hot set before it
        // would push out more than the rules let one block push. Room the tier
        // itself still has counts, and the coinbase is allowed for as if it
        // were full, because it is not known yet.
        let mut places = self
            .params
            .hot_capacity
            .saturating_sub(self.state.hot_len())
            .saturating_add(self.params.max_evictions_per_block)
            .saturating_sub(self.params.max_coinbase_outputs);

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
            // The same refusal a full block would meet, made before the block
            // is built. Only notes spent out of the hot set give places back:
            // a cold spend puts its outputs into the tier and takes nothing
            // out of it.
            let created = transfer.outputs.len();
            let freed = outcome.spent_hot.len();
            if created > freed {
                let Some(left) = places.checked_sub(created.saturating_sub(freed)) else {
                    continue;
                };
                places = left;
            } else {
                places = places.saturating_add(freed.saturating_sub(created));
            }
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

    /// The pooled transfers a newcomer would take the place of, and what they
    /// take together, once it has paid enough to take it.
    ///
    /// Two spends of one note cannot both wait, so one of them has to go, and
    /// which one is a price and not an accident of arrival. The newcomer takes
    /// the place of everything it conflicts with if it pays what they paid
    /// together, the floor again on top, and a better rate than any of them.
    /// The extra floor is what a retry costs: without it, a sender could have
    /// the network relay endless copies of one spend for one fee.
    fn displaced_by(
        &self,
        transfer: &Transfer,
        fee: Amount,
        offered: u128,
        floor: Amount,
    ) -> Result<(BTreeSet<Hash32>, usize), TransferError> {
        let spenders = self.pooled_spenders();
        let mut conflicts: BTreeSet<Hash32> = BTreeSet::new();
        for input in &transfer.inputs {
            if let Some(holder) = spenders.get(&input.note_id) {
                conflicts.insert(*holder);
            }
        }
        if conflicts.is_empty() {
            return Ok((conflicts, 0));
        }

        let mut displaced: u128 = 0;
        let mut best: u128 = 0;
        let mut bytes = 0usize;
        for holder in &conflicts {
            let Some(held) = self.pool.get(holder) else {
                continue;
            };
            displaced = displaced.saturating_add(u128::from(held.fee.as_pebbles()));
            best = best.max(rate(held.fee, held.weight));
            bytes = bytes.saturating_add(held.bytes);
        }
        let asked = displaced.saturating_add(u128::from(floor.as_pebbles()));
        if u128::from(fee.as_pebbles()) < asked || offered <= best {
            // The first conflicting input names what is already spoken for,
            // which is what the sender has to know to try again.
            let taken = transfer
                .inputs
                .iter()
                .map(|input| input.note_id)
                .find(|note| spenders.contains_key(note))
                .unwrap_or(NoteId::new(transfer.id(), 0));
            return Err(TransferError::UnknownNote(taken));
        }
        Ok((conflicts, bytes))
    }

    /// Which pooled transfer spends each note the pool has spoken for.
    fn pooled_spenders(&self) -> BTreeMap<NoteId, Hash32> {
        let mut spenders = BTreeMap::new();
        for (id, held) in &self.pool {
            for input in &held.transfer.inputs {
                spenders.insert(input.note_id, *id);
            }
        }
        spenders
    }

    /// Drops every pooled transfer the current state no longer accepts.
    ///
    /// Called whenever the followed branch moves. A reorganisation can make a
    /// transfer spendable again as easily as it can make one impossible, and
    /// nothing here assumes which.
    fn prune_pool(&mut self) {
        let params = self.params;
        let state = &self.state;
        let mut kept: BTreeSet<(u128, Hash32)> = BTreeSet::new();
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
                    kept.insert((rate(outcome.fee, held.weight), *id));
                    bytes = bytes.saturating_add(held.bytes);
                    true
                }
                Err(_) => false,
            }
        });
        self.pool_by_rate = kept;
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

        // A ledger from a height this build has no rules for is one this node
        // cannot stand behind, and standing behind it is exactly what adopting
        // means. Nothing here used to ask: a node whose rules stopped at some
        // height took the ledger, reported that height, and answered questions
        // out of a chain it could not judge, while still saying it was up to
        // date. The next block told it, and nothing before that did.
        //
        // Asked here as well as where a handover is checked, because this is
        // the door a ledger comes through however it was obtained, and because
        // the answer belongs with every other refusal a node reports about
        // itself rather than about somebody else.
        let required = self.params.version_at(tip.height);
        if required > BLOCK_VERSION || last.version > BLOCK_VERSION {
            return Err(ChainError::InvalidBlock {
                id: tip.id,
                source: BlockError::SoftwareTooOld {
                    height: tip.height,
                    required: required.max(last.version),
                    known: BLOCK_VERSION,
                },
            });
        }

        // And the other half, which asking only about "too new" leaves open. A
        // block carries exactly the version its height demands, so a tip that
        // carries anything else is a tip no chain accepted. Without this, a
        // node running one rule set adopts, whole and without a word, a ledger
        // built under a rule set it does not run: mapped onto a real
        // activation, an updated node handed the abandoned pre-fork chain
        // takes it, reports itself up to date, and answers balances out of it.
        if last.version != required {
            return Err(ChainError::InvalidBlock {
                id: tip.id,
                source: BlockError::UnsupportedVersion(last.version),
            });
        }

        // Who this node follows is a fact about this node. It lives in the
        // ledger because that is where a falling note is seen, and a ledger
        // handed over by somebody else knows nothing about it, so assigning
        // one over the top used to forget it.
        //
        // What that cost was money. A wallet joining a live chain takes a
        // handover rather than reading thirty years of blocks, which is the
        // whole point, and its node then recorded no position for any of its
        // owner's notes as they fell. About three hours later, when the first
        // one fell, the wallet could no longer build a proof for it: the money
        // was visible, correct, and unspendable, for good, with nobody
        // attacking anything. It was the default path for a new wallet.
        let following: Vec<_> = self.state.watching().collect();
        self.state = state;
        for owner in following {
            self.state.watch_owner(owner);
        }
        self.branch = Branch::from_tail(recent);
        // Nothing here can be undone: undoing takes the record of what a block
        // did, and this node was not there when they were done. So the window
        // starts closed and opens as this node applies blocks of its own.
        self.undo_from = self.branch.len();
        self.applied.clear();
        self.blocks.clear();
        self.held_bytes = 0;
        Ok(())
    }

    /// Records a block and follows the heaviest branch it makes available.
    ///
    /// `now` is this node's clock, in seconds since the Unix epoch.
    pub fn add_block(&mut self, block: Block, now: u64) -> Result<Accepted, ChainError> {
        let id = block.id();
        // Already held, and the same block: nothing to do. Already held and a
        // *different* block is the case that matters, because an identifier is
        // taken over a header and a header does not commit to the signatures
        // in its body. Anyone can copy a block, break one signature, and send
        // the twin first; it costs them nothing, since the twin inherits the
        // work of the block it copies. Treating that as a duplicate would hand
        // them the real block's place, and the node would never follow the
        // chain past it.
        match self.blocks.get(&id) {
            Some(held) if held.body.as_ref() == Some(&block) => {
                return Ok(Accepted::Duplicate);
            }
            // Held with its body dropped, which a node does once it has been
            // applied. It was applied, so it was valid, and this is that block
            // or a twin of it; either way there is nothing to decide again.
            Some(held) if held.body.is_none() => return Ok(Accepted::Duplicate),
            _ => {}
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
            let floor = tip.saturating_sub(self.undo_limit());
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
            self.hold(id, block, total_work);
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
            let expected_height = parent.header.height.saturating_add(1);
            if block.header.height != expected_height {
                return Err(ChainError::BrokenHeight {
                    parent: parent.header.height,
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

        self.hold(id, block, total_work);

        if total_work <= self.total_work() {
            // Ties keep the block already followed, and this is a choice with
            // a cost, so it is worth writing down rather than implying.
            //
            // Two miners finding a block at the same height is ordinary. It
            // leaves two branches of exactly equal work, and two honest nodes
            // that heard them in opposite orders sit on different tips until a
            // heavier block settles it. Nothing is wrong with either node.
            //
            // Breaking the tie on the lower identifier would settle it at once
            // and was tried. It costs more than it buys: a node catching up
            // along a rival branch passes through equal work on the way and
            // reorganises there, so every sync against a competitor does extra
            // rewinding to reach the same place one block later anyway.
            //
            // So the split stands for one block interval and then resolves,
            // which is what every chain of this shape does. What must not be
            // said is that the order is total and identical everywhere: it is
            // not, it is the order the blocks arrived in, and the papers now
            // say so.
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
        let depth = self.branch.len().saturating_sub(keep);
        if depth > self.undo_limit() {
            return Err(ChainError::ForkTooDeep {
                depth: usize::try_from(depth).unwrap_or(usize::MAX),
                limit: self.undo_limit(),
            });
        }

        let rolled_back = self.rewind_to(fork_position)?;

        let mut added = Vec::new();
        for id in &branch {
            match self.apply(*id, now) {
                Ok(()) => added.push(*id),
                Err(error) => {
                    // A block whose rules this software does not have is not a
                    // block known to be bad: the same block becomes valid the
                    // moment the node is updated. Remembering it as bad would
                    // outlive the update, and would come back through
                    // `branch_to` as an ordinary refusal, with the peer blamed
                    // for this node being old, which is the one outcome the
                    // scheduled rule change exists to avoid.
                    if error.settles_the_header() {
                        if self.invalid.len() >= MAX_INVALID {
                            self.invalid.clear();
                        }
                        self.invalid.insert(*id);
                    }
                    // And the block goes, unless the only thing wrong with it
                    // is that this node is too old to judge it.
                    //
                    // An identifier is taken over a header, so what failed may
                    // be a forged copy of a real block: one signature broken,
                    // no work done, sent first. Keeping it means handing that
                    // copy to whoever next asks for the block it was copied
                    // from, and standing in the way of the real one. Nothing
                    // that did not apply is worth passing on.
                    //
                    // A block from rules this build lacks is different. It
                    // becomes valid the moment the node is updated, and
                    // throwing it away would mean asking for it again.
                    if error.outdated().is_none() && self.blocks.remove(id).is_some() {
                        self.recount();
                    }
                    self.restore(&added, &rolled_back, now)?;
                    return Err(error);
                }
            }
        }

        // A block that was undone took its transfers with it, and they were
        // paid for and are still wanted. Offering them back to the pool is
        // what keeps a reorganisation from quietly cancelling somebody's
        // payment: without it the money returns to the sender, the payment is
        // in no block and in no pool, and the only party who could notice is
        // the one who has just been told it was sent.
        //
        // Newest first, because a transfer from the block just undone is the
        // one most likely still to matter, and because that is the order a
        // rewind produces. Anything the winning branch already carries is
        // refused here for spending notes that are spent, which is the same
        // answer by a shorter road than checking for it.
        self.repool(&rolled_back);

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
                // What is remembered is that this block failed, not why: the
                // set holds identifiers and nothing else. Naming a cause here
                // would mean inventing one, and an invented cause is worse
                // than none: it is read by whoever has to tell a bad peer
                // from a node that is out of date.
                return Err(ChainError::KnownBad { id: cursor });
            }
            branch.push(cursor);
            if stored.header.height == 0 {
                if self.branch.is_empty() {
                    branch.reverse();
                    return Ok((None, branch));
                }
                // A second genesis shares no history with the one being
                // followed, so there is no branch point between them.
                return Err(ChainError::NotGenesis);
            }
            cursor = stored.header.previous;
        }
    }

    /// This node's ledger as it stood at `height`.
    ///
    /// Built by undoing blocks off a copy rather than by keeping a second
    /// ledger about, which is what makes handing over a buried one free: the
    /// records that undo a block are already held, because being able to
    /// change branches is what they are for.
    ///
    /// `None` past what can still be undone. A node that has let those records
    /// go cannot get back there, and a node that was handed its own ledger
    /// rather than reading its way to one has none at all until it has applied
    /// that many blocks itself.
    ///
    /// How deep that is takes a moment of care, and getting it wrong by one
    /// left the whole handover unreachable on a chain past a thousand blocks.
    /// Reaching height `h` means undoing the blocks above it, so what is
    /// needed is the record for every height from `h + 1` to the tip, and
    /// nothing for `h` itself. The deepest that can be reached is therefore
    /// [`Self::undo_from`] minus one, not `undo_from`: the block whose own
    /// record has just been let go is still the block a rewind lands on.
    /// A reorganisation of the full [`MAX_REORG_DEPTH`] already lands there,
    /// so refusing it here was refusing something the store does elsewhere.
    #[must_use]
    pub fn ledger_at(&self, height: u64) -> Option<LedgerState> {
        let tip = self.height()?;
        if height > tip || height.saturating_add(1) < self.undo_from {
            return None;
        }
        let mut state = self.state.clone();
        let mut at = tip;
        while at > height {
            let id = self.branch.id_at(at)?;
            disconnect_block(&mut state, self.applied.get(&id)?);
            at = at.checked_sub(1)?;
        }
        Some(state)
    }

    /// Offers the transfers of undone blocks back to the pool.
    ///
    /// Bounded by the pool's own limits rather than by the depth of the
    /// reorganisation: past them nothing more can be taken, so there is no
    /// reason to go on validating. What is dropped this way is the oldest of
    /// what was undone, which is the part most likely to have been replaced
    /// on the branch that won.
    fn repool(&mut self, undone: &[Hash32]) {
        for id in undone {
            if self.pool.len() >= MAX_POOLED || self.pool_bytes >= MAX_POOL_BYTES {
                return;
            }
            // Read through the disk, not out of memory. A body is let go of
            // once it is more than `WARM_BODIES` below the tip and written,
            // so reading only what is still in memory made this work for a
            // shallow reorganisation and quietly do nothing for a deep one.
            // The tests in this crate wire up no disk at all, which is why
            // they could not see it: without one there is nothing to let go
            // of, so every body was still in memory and the walk was right by
            // accident.
            let Some(block) = self.body_of(id) else {
                continue;
            };
            for transfer in block.transfers {
                if self.pool.len() >= MAX_POOLED || self.pool_bytes >= MAX_POOL_BYTES {
                    return;
                }
                let _ = self.accept_transfer(transfer);
            }
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
            self.release(&id);
            self.undo_from = self.undo_from.saturating_add(1);
        }
    }

    /// Wire bytes of every block this node is holding in memory.
    ///
    /// What bounds a node's memory, and what the ceiling in
    /// [`MAX_SIDE_BYTES`] is written against.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }

    /// The deepest switch this node will make on the network it is on.
    ///
    /// [`MAX_REORG_DEPTH`] is what this build can undo; the burial is what the
    /// network says is settled. A node must not undo past its own network's
    /// burial, and the reason is not the number itself: a handover is anchored
    /// there and a reward matures there. Undoing deeper would hand a newcomer
    /// a ledger anchored at a block this node went on to orphan, and would
    /// take back a reward the rules had already called spendable.
    ///
    /// Only the rule uses this. What is held in memory stays sized by the
    /// constant, because holding more of the chain than can be undone is
    /// harmless and every ceiling written against the constant stays true.
    ///
    /// On every public network the two are the same number. Devnet lowers
    /// both so a throwaway chain settles in minutes, and this is what carries
    /// the claim down with them.
    #[must_use]
    pub fn undo_limit(&self) -> u64 {
        u64::try_from(MAX_REORG_DEPTH)
            .unwrap_or(u64::MAX)
            .min(self.params.burial)
    }

    /// The most this node will ever hold in blocks.
    ///
    /// The window it may have to undo, at the largest block the rules allow,
    /// plus what it keeps of branches it is not on. Anything that raises one
    /// of the three has to be read against this.
    #[must_use]
    pub fn held_bytes_ceiling(params: &ConsensusParams) -> usize {
        MAX_REORG_DEPTH
            .saturating_mul(params.max_block_bytes)
            .saturating_add(MAX_SIDE_BYTES)
    }

    /// Takes a block into memory, keeping the byte count with it.
    fn hold(&mut self, id: Hash32, block: Block, total_work: u128) {
        let bytes = block.encode().len();
        let header = block.header;
        if let Some(replaced) = self.blocks.insert(
            id,
            StoredBlock {
                header,
                body: Some(block),
                total_work,
                bytes,
            },
        ) {
            self.held_bytes = self.held_bytes.saturating_sub(replaced.bytes);
        }
        self.held_bytes = self.held_bytes.saturating_add(bytes);
    }

    /// Drops one block, keeping the byte count with it.
    fn release(&mut self, id: &Hash32) {
        if let Some(dropped) = self
            .blocks
            .remove(id)
            .filter(|stored| stored.body.is_some())
        {
            self.held_bytes = self.held_bytes.saturating_sub(dropped.bytes);
        }
    }

    /// Recomputes the byte count after a sweep that dropped many at once.
    /// Recomputes what is held, counting only the blocks whose body is still
    /// here.
    ///
    /// One definition of what this counts, used by every path that changes it,
    /// so a body let go of and an entry dropped cannot both subtract the same
    /// bytes.
    fn recount(&mut self) {
        self.held_bytes = self
            .blocks
            .values()
            .filter(|stored| stored.body.is_some())
            .map(|stored| stored.bytes)
            .fold(0usize, usize::saturating_add);
    }

    /// Bytes of blocks that are not on the followed branch.
    fn side_bytes(&self) -> usize {
        let branch = &self.branch;
        self.blocks
            .values()
            .filter(|stored| stored.body.is_some())
            .filter(|stored| branch.height_of(&stored.header.id()).is_none())
            .map(|stored| stored.bytes)
            .fold(0usize, usize::saturating_add)
    }

    /// Drops the oldest blocks off the followed branch until what is held off
    /// it is back under [`MAX_SIDE_BYTES`].
    ///
    /// Never touches the branch being followed: those are the blocks a
    /// reorganisation has to undo, and losing one would leave the node unable
    /// to do it.
    fn forget_oldest_side_blocks(&mut self) {
        let mut over = self.side_bytes();
        if over <= MAX_SIDE_BYTES {
            return;
        }
        let branch = &self.branch;
        let mut candidates: Vec<(u64, Hash32, usize)> = self
            .blocks
            .values()
            .filter_map(|stored| {
                let id = stored.header.id();
                branch
                    .height_of(&id)
                    .is_none()
                    .then_some((stored.header.height, id, stored.bytes))
            })
            .collect();
        candidates.sort_unstable_by_key(|(height, id, _)| (*height, *id));

        for (_, id, bytes) in candidates {
            if over <= MAX_SIDE_BYTES {
                break;
            }
            self.blocks.remove(&id);
            over = over.saturating_sub(bytes);
        }
        self.recount();
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
        let by_count = self.blocks.len() > limit;
        let by_bytes = self.held_bytes > Self::held_bytes_ceiling(&self.params);
        if !by_count && !by_bytes {
            return;
        }
        let Some(cutoff) = self
            .height()
            .and_then(|tip| tip.checked_sub(u64::try_from(MAX_REORG_DEPTH).unwrap_or(u64::MAX)))
        else {
            return;
        };
        let branch = &self.branch;
        self.blocks
            .retain(|id, stored| branch.height_of(id).is_some() || stored.header.height >= cutoff);
        self.invalid.retain(|id| branch.height_of(id).is_none());
        self.recount();

        // What is left inside the window can still be more than the window is
        // worth holding, since a block inside it may be as large as the rules
        // allow. Dropping by age is what bounds that.
        self.forget_oldest_side_blocks();
    }

    fn apply(&mut self, id: Hash32, now: u64) -> Result<(), ChainError> {
        let block = self.body_of(&id).ok_or(ChainError::Corrupt)?;
        let connected = connect_block(&mut self.state, &block, &self.params, now)
            .map_err(|source| ChainError::InvalidBlock { id, source })?;
        self.branch.push(id);
        self.applied.insert(id, connected);
        Ok(())
    }

    /// The body of a block this node accepted, from memory or from wherever
    /// bodies are read back.
    ///
    /// A body read back is checked against the identifier it was asked for.
    /// Reading by height is asking the disk which block sits there now, and
    /// what sits there is not always what sat there when this was called.
    fn body_of(&self, id: &Hash32) -> Option<Block> {
        let stored = self.blocks.get(id)?;
        if let Some(body) = stored.body.as_ref() {
            return Some(body.clone());
        }
        let read = self.bodies.as_ref()?.body(stored.header.height)?;
        (read.id() == *id).then_some(read)
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use cairn_ledger::block::BLOCK_VERSION;
    use cairn_ledger::note::NetworkId;
    use cairn_ledger::transaction::CoinbaseTransaction;

    use super::*;

    fn params() -> ConsensusParams {
        ConsensusParams::testnet()
    }

    /// A count of blocks read as a height, which is how a branch counts.
    fn as_height(count: usize) -> u64 {
        u64::try_from(count).unwrap_or(u64::MAX)
    }

    /// A stand-in identifier, distinct per number and nothing else.
    fn id(n: u64) -> Hash32 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        Hash32::from_bytes(bytes)
    }

    /// An empty block, built rather than mined.
    ///
    /// Nothing reached from here weighs work or judges validity: what these
    /// tests exercise is the bookkeeping around a block, and mining one apiece
    /// would spend seconds a run proving what `tests/fork_choice.rs` already
    /// proves against real ones.
    fn block_at(height: u64, previous: Hash32, nonce: u64) -> Block {
        Block {
            header: BlockHeader {
                version: BLOCK_VERSION,
                network: NetworkId::TESTNET,
                height,
                previous,
                transactions_root: Hash32::ZERO,
                state_root: Hash32::ZERO,
                history: Hash32::ZERO,
                timestamp: 0,
                difficulty: 1,
                total_work: 0,
                nonce,
            },
            coinbase: CoinbaseTransaction::new(height, Vec::new()),
            transfers: Vec::new(),
        }
    }

    /// A run of blocks each building on the last, oldest first.
    fn run_from(previous: Hash32, heights: std::ops::Range<u64>, nonce: u64) -> Vec<Block> {
        let mut previous = previous;
        heights
            .map(|height| {
                let block = block_at(height, previous, nonce);
                previous = block.id();
                block
            })
            .collect()
    }

    /// Somewhere to read bodies back from, holding whatever a test put there.
    #[derive(Debug)]
    struct Shelf(HashMap<u64, Block>);

    impl Shelf {
        fn holding(block: Block) -> Self {
            Self(HashMap::from([(block.header.height, block)]))
        }
    }

    impl Bodies for Shelf {
        fn body(&self, height: u64) -> Option<Block> {
            self.0.get(&height).cloned()
        }
    }

    /// Records a block of a stated size, as `hold` would had it encoded one.
    ///
    /// The sizes are stated because what is under test is the accounting, and
    /// building the tens of megabytes it takes to reach the ceiling would cost
    /// a second of every run to prove something about the encoder instead.
    fn shelve(store: &mut ChainStore, height: u64, nonce: u64, bytes: usize) -> Hash32 {
        let block = block_at(height, Hash32::ZERO, nonce);
        let header = block.header;
        let id = header.id();
        store.blocks.insert(
            id,
            StoredBlock {
                header,
                body: Some(block),
                total_work: 0,
                bytes,
            },
        );
        store.held_bytes = store.held_bytes.saturating_add(bytes);
        id
    }

    /// A node holds the branch it could still reorganise in full and one
    /// identifier every [`MILESTONE`] heights before that, which is what keeps
    /// the memory it spends on history a fixed thirty two kilobytes over
    /// decades instead of a gigabyte and a quarter.
    /// A branch handed a tail never claims a height it was not handed.
    ///
    /// It holds no milestones, by design and by its own documentation, and the
    /// list they live in is read by index. Appending to an empty one would put
    /// the first block this node happened to see past a milestone boundary
    /// where height zero is looked up, and `locator` would then offer a peer
    /// `height 0, id <a block from five thousand>`, a position this node has
    /// never held and cannot defend.
    #[test]
    fn a_branch_handed_a_tail_does_not_invent_a_genesis() {
        let handed: Vec<BlockHeader> = (5_000..5_002)
            .map(|height| block_at(height, id(height - 1), 0).header)
            .collect();
        let mut branch = Branch::from_tail(&handed);

        assert_eq!(branch.genesis(), None, "it was handed no first block");
        assert_eq!(branch.id_at(0), None);

        // Past the next milestone boundary, which is where the list used to
        // gain its first entry.
        for height in 5_002..=(MILESTONE * 6) {
            branch.push(id(height));
        }
        assert!(branch.len() > MILESTONE * 5);

        assert_eq!(
            branch.genesis(),
            None,
            "crossing a boundary did not hand it a first block either"
        );
        assert_eq!(
            branch.id_at(0),
            None,
            "and height zero is still a height this node cannot answer for"
        );
        assert_eq!(branch.id_at(MILESTONE), None);
    }

    #[test]
    fn a_branch_keeps_one_identifier_every_thousand_and_twenty_four_heights() {
        let mut branch = Branch::default();
        let count = MILESTONE * 3 + 10;
        for n in 0..count {
            branch.push(id(n));
        }

        assert_eq!(branch.len(), count);
        assert_eq!(branch.tip(), Some(id(count - 1)));
        assert_eq!(branch.genesis(), Some(id(0)));
        assert_eq!(
            branch.milestones.len(),
            4,
            "one for height zero and one for each thousand and twenty four after it"
        );

        // Below the window the milestones are the whole of what is left, and
        // they answer for the heights they sit at.
        for level in 0..3 {
            let height = MILESTONE * level;
            assert_eq!(branch.id_at(height), Some(id(height)));
        }

        // Everything between two of them is gone, which is not the same as the
        // branch having no block there: a caller wanting one reads the log.
        assert_eq!(branch.id_at(1), None);
        assert_eq!(branch.id_at(MILESTONE + 1), None);
        assert_eq!(
            branch.height_of(&id(0)),
            None,
            "and a milestone is an identifier at a height, not a height for an identifier"
        );
    }

    /// What a branch holds in full is a window that slides, not a history that
    /// accumulates. A node whose memory grew with the chain would be a node
    /// whose cost grew with the chain, which is the one thing this design says
    /// it does not do.
    #[test]
    fn the_identifiers_a_branch_holds_in_full_are_a_window_and_not_a_history() {
        let mut branch = Branch::default();
        let past = 500u64;
        let count = as_height(WINDOW) + past;
        for n in 0..count {
            branch.push(id(n));
        }

        assert_eq!(branch.recent.len(), WINDOW);
        assert_eq!(
            branch.at.len(),
            WINDOW,
            "the index holds what the window does"
        );
        assert_eq!(branch.from, past);
        assert_eq!(
            branch.len(),
            count,
            "and the branch is still as long as it is"
        );

        assert_eq!(branch.height_of(&id(past)), Some(past));
        assert_eq!(branch.height_of(&id(count - 1)), Some(count - 1));
        assert_eq!(
            branch.height_of(&id(past - 1)),
            None,
            "the block below the window left the index with it"
        );
    }

    /// The window is one longer than the deepest rewind on purpose: the block
    /// a branch is rewound *onto* has to still be there to be rewound onto.
    /// One short and the deepest legal reorganisation would leave the node
    /// unable to name the branch point it had just agreed to.
    #[test]
    fn the_window_outlasts_the_deepest_rewind_the_store_will_perform() {
        assert_eq!(WINDOW, MAX_REORG_DEPTH + 1);

        let mut branch = Branch::default();
        let count = as_height(WINDOW) + 3;
        for n in 0..count {
            branch.push(id(n));
        }
        let anchor = branch.from;

        for _ in 0..MAX_REORG_DEPTH {
            assert!(
                branch.pop().is_some(),
                "the rewind ran out of identifiers before it ran out of depth"
            );
        }

        assert_eq!(branch.tip(), Some(id(anchor)));
        assert_eq!(branch.height_of(&id(anchor)), Some(anchor));
        assert_eq!(branch.len(), anchor + 1);
    }

    /// A rewind that crosses a milestone has to let go of it, or the branch
    /// would keep pointing at a block it no longer carries and tell a peer so.
    #[test]
    fn a_rewind_past_a_milestone_lets_go_of_it_and_a_push_puts_it_back() {
        let mut branch = Branch::default();
        for n in 0..=MILESTONE {
            branch.push(id(n));
        }
        assert_eq!(branch.milestones, vec![id(0), id(MILESTONE)]);

        assert_eq!(branch.pop(), Some(id(MILESTONE)));
        assert_eq!(
            branch.milestones,
            vec![id(0)],
            "the milestone went with the block it named"
        );
        assert_eq!(branch.id_at(MILESTONE), None);

        branch.push(id(MILESTONE));
        assert_eq!(branch.milestones, vec![id(0), id(MILESTONE)]);
        assert_eq!(branch.id_at(MILESTONE), Some(id(MILESTONE)));

        // And a branch rewound to nothing says so rather than pretending.
        while branch.pop().is_some() {}
        assert!(branch.is_empty());
        assert_eq!(branch.pop(), None);
        assert_eq!(branch.genesis(), None);
    }

    /// A node handed a ledger was not there for the history behind it, and the
    /// honest answer about a height it never saw is that it has none. Claiming
    /// otherwise would put a position in a locator that this node cannot stand
    /// behind.
    #[test]
    fn a_branch_taken_from_a_run_of_headers_claims_nothing_about_what_came_before() {
        let joined_at = MILESTONE * 4;
        let headers: Vec<BlockHeader> = run_from(Hash32::ZERO, joined_at..joined_at + 6, 1)
            .iter()
            .map(|block| block.header)
            .collect();

        let branch = Branch::from_tail(&headers);
        assert_eq!(branch.from, joined_at);
        assert_eq!(branch.len(), joined_at + 6);
        assert_eq!(branch.tip(), Some(headers[5].id()));
        assert_eq!(branch.height_of(&headers[0].id()), Some(joined_at));
        assert_eq!(branch.id_at(joined_at + 5), Some(headers[5].id()));

        assert_eq!(branch.id_at(joined_at - 1), None);
        assert_eq!(
            branch.id_at(MILESTONE),
            None,
            "a milestone height it never saw is still a height it never saw"
        );
        assert_eq!(
            branch.genesis(),
            None,
            "and it does not name a first block it was not there for"
        );

        assert!(Branch::from_tail(&[]).is_empty());
    }

    /// Every height a locator names has to be one this node is sure it still
    /// holds, or the peer comparing the two is handed a gap and reads it as
    /// disagreement.
    #[test]
    fn stepping_back_always_lands_on_a_height_this_node_still_holds() {
        let window_from = MILESTONE * 4;
        let headers: Vec<BlockHeader> = run_from(Hash32::ZERO, window_from..window_from + 5, 1)
            .iter()
            .map(|block| block.header)
            .collect();
        let mut store = ChainStore::new(params());
        store.branch = Branch::from_tail(&headers);

        // Inside the window every height is held, so a step lands where it aimed.
        assert_eq!(store.step_back(window_from + 400, 10), window_from + 390);
        assert_eq!(store.step_back(window_from + 4, 4), window_from);

        // Below it only the milestones exist, so a step that would land between
        // two of them rounds down to one rather than naming a height this node
        // no longer has an identifier for.
        assert_eq!(store.step_back(window_from + 4, 1_000), MILESTONE * 3);
        assert_eq!(store.step_back(3_000, 1), MILESTONE * 2);

        // A walk that stopped moving would never reach the genesis block it has
        // to end at, and a locator that never ended would be sent forever.
        let mut height = window_from + 4;
        let mut step = 1u64;
        for _ in 0..MAX_LOCATOR {
            if height == 0 {
                break;
            }
            let next = store.step_back(height, step);
            assert!(next < height, "the walk stalled at {height}");
            assert!(
                next >= store.branch.from || next % MILESTONE == 0,
                "the walk named height {next}, which this node no longer holds"
            );
            height = next;
            step = step.saturating_mul(2);
        }
        assert_eq!(height, 0, "and it reached the first block");
    }

    /// Rounding down to a milestone can land back on the height it started
    /// from, and a locator naming the same height twice is a locator asking a
    /// peer the same question until it runs out of room.
    #[test]
    fn a_step_that_would_not_move_goes_one_milestone_further() {
        let window_from = MILESTONE * 4;
        let headers: Vec<BlockHeader> = run_from(Hash32::ZERO, window_from..window_from + 2, 1)
            .iter()
            .map(|block| block.header)
            .collect();
        let mut store = ChainStore::new(params());
        store.branch = Branch::from_tail(&headers);

        assert_eq!(store.step_back(MILESTONE * 2, 0), MILESTONE);
        assert_eq!(
            store.step_back(3_000, 0),
            MILESTONE * 2,
            "a height between two milestones already moves when it rounds down"
        );
    }

    /// The walk that a switch is built from: everything between the followed
    /// branch and the block being considered, in the order it has to be
    /// applied, and the position on the branch it all hangs from.
    #[test]
    fn the_walk_to_a_block_gives_its_branch_oldest_first_and_where_it_forks() {
        let mut store = ChainStore::new(params());

        let trunk = run_from(Hash32::ZERO, 0..5, 0);
        let trunk_ids: Vec<Hash32> = trunk.iter().map(Block::id).collect();
        for block in &trunk {
            store.hold(block.id(), block.clone(), 0);
            store.branch.push(block.id());
        }

        let rival = run_from(trunk_ids[2], 3..6, 7);
        let rival_ids: Vec<Hash32> = rival.iter().map(Block::id).collect();
        for block in &rival {
            store.hold(block.id(), block.clone(), 0);
        }

        assert_eq!(
            store.branch_to(rival_ids[2]),
            Ok((Some(2), rival_ids.clone())),
            "oldest first, from the block the two branches share"
        );

        assert_eq!(
            store.branch_to(trunk_ids[4]),
            Ok((Some(4), Vec::new())),
            "a block already followed asks for nothing to be applied"
        );
    }

    /// Two chains that start from different first blocks share no history at
    /// all, so there is no branch point between them and no honest way to
    /// switch. Read as a fork it would look like a rewind to the beginning of
    /// time, which is the reorganisation the depth limit exists to refuse.
    #[test]
    fn a_second_genesis_shares_no_history_with_the_branch_being_followed() {
        let mut store = ChainStore::new(params());

        let followed = run_from(Hash32::ZERO, 0..3, 0);
        for block in &followed {
            store.hold(block.id(), block.clone(), 0);
            store.branch.push(block.id());
        }

        let stray = block_at(0, Hash32::ZERO, 99);
        let stray_id = stray.id();
        store.hold(stray_id, stray, 0);
        assert_eq!(store.branch_to(stray_id), Err(ChainError::NotGenesis));

        // The same block on a node following nothing is where a branch starts,
        // and the fork position says there is none rather than naming zero.
        let mut fresh = ChainStore::new(params());
        let first = block_at(0, Hash32::ZERO, 99);
        fresh.hold(first.id(), first, 0);
        assert_eq!(fresh.branch_to(stray_id), Ok((None, vec![stray_id])));
    }

    /// A walk that cannot be completed has to fail before anything is undone.
    /// Discovered halfway through a rewind, the same refusal would leave the
    /// node on neither branch.
    #[test]
    fn a_branch_this_node_cannot_assemble_is_refused_rather_than_half_walked() {
        let mut store = ChainStore::new(params());

        let trunk = run_from(Hash32::ZERO, 0..3, 0);
        for block in &trunk {
            store.hold(block.id(), block.clone(), 0);
            store.branch.push(block.id());
        }

        let rival = run_from(trunk[2].id(), 3..6, 7);
        let rival_ids: Vec<Hash32> = rival.iter().map(Block::id).collect();
        for block in &rival {
            store.hold(block.id(), block.clone(), 0);
        }

        // A block already known to be bad taints every branch through it, so
        // the heaviest chain in memory is worth nothing if it runs over one.
        store.invalid.insert(rival_ids[1]);
        assert!(
            matches!(
                store.branch_to(rival_ids[2]),
                Err(ChainError::KnownBad { id }) if id == rival_ids[1]
            ),
            "the walk went through a block this node had already refused"
        );

        // And a branch whose middle this node let go of names what it lost,
        // rather than reporting the tree as corrupt or walking past the hole.
        store.invalid.remove(&rival_ids[1]);
        store.release(&rival_ids[0]);
        assert_eq!(
            store.branch_to(rival_ids[2]),
            Err(ChainError::UnknownParent(rival_ids[0]))
        );
    }

    /// Bodies are read back by height, because a log is records in order of
    /// height. What sits at a height is not always what sat there when the
    /// question was asked, so the answer is checked against the identifier it
    /// was asked for: a log that has moved on returns nothing rather than the
    /// wrong block.
    #[test]
    fn a_body_read_back_is_checked_against_the_identifier_it_was_asked_for() {
        let mut store = ChainStore::new(params());
        let block = block_at(3, Hash32::ZERO, 1);
        let id = block.id();
        store.hold(id, block.clone(), 0);

        assert_eq!(store.body_of(&id), Some(block.clone()));
        assert_eq!(store.body_of(&Hash32::ZERO), None, "a block never seen");

        // A node that let go of the body and has nowhere to read it back keeps
        // the header and says it has no body, which is the truth.
        store.blocks.get_mut(&id).unwrap().body = None;
        assert_eq!(store.body_of(&id), None);

        // A log that has been reorganised under this node's feet offers the
        // block that sits at the height now, and it is refused.
        let usurper = block_at(3, Hash32::ZERO, 2);
        assert_ne!(usurper.id(), id);
        store.reads_bodies_from(Arc::new(Shelf::holding(usurper)));
        assert_eq!(
            store.body_of(&id),
            None,
            "the wrong block at the right height is still the wrong block"
        );

        store.reads_bodies_from(Arc::new(Shelf::holding(block.clone())));
        assert_eq!(store.body_of(&id), Some(block));
    }

    /// A block stops costing memory two different ways: its body is let go of,
    /// or the whole entry is dropped. Both take the same bytes off the same
    /// count, so a block that leaves by both routes must not be subtracted
    /// twice: a count that drifted below the truth is a ceiling that stops
    /// binding.
    #[test]
    fn bytes_held_come_off_the_count_once_however_a_block_leaves_memory() {
        let mut store = ChainStore::new(params());
        assert_eq!(store.held_bytes(), 0);

        let first = block_at(0, Hash32::ZERO, 1);
        let second = block_at(1, first.id(), 1);
        let first_bytes = first.encode().len();
        let second_bytes = second.encode().len();
        let (first_id, second_id) = (first.id(), second.id());

        store.hold(first_id, first.clone(), 0);
        store.hold(second_id, second, 0);
        assert_eq!(store.held_bytes(), first_bytes + second_bytes);
        assert_eq!(store.bodies_held(), 2);

        store.hold(first_id, first, 0);
        assert_eq!(
            store.held_bytes(),
            first_bytes + second_bytes,
            "the same block held twice is one block"
        );
        assert_eq!(store.len(), 2);

        // Let go of a body, as a node does once the block is on disk.
        store.blocks.get_mut(&first_id).unwrap().body = None;
        store.recount();
        assert_eq!(store.held_bytes(), second_bytes);
        assert_eq!(store.bodies_held(), 1);

        store.release(&first_id);
        assert_eq!(
            store.held_bytes(),
            second_bytes,
            "an entry without a body costs nothing, so dropping it saves nothing"
        );
        assert!(!store.contains(&first_id));

        store.release(&second_id);
        assert_eq!(store.held_bytes(), 0);
        assert_eq!(store.len(), 0);
    }

    /// A count of blocks does not bound memory, because a block is not a fixed
    /// size: four thousand rival blocks at the largest the rules allow is most
    /// of a gigabyte held on the word of a peer. So what is held off the
    /// followed branch is bounded in bytes, and the branch itself is never
    /// what pays for it: those are the blocks a reorganisation has to undo.
    #[test]
    fn blocks_off_the_followed_branch_are_dropped_oldest_first_and_it_is_never_touched() {
        const CHUNK: usize = 4 * 1024 * 1024;

        let mut store = ChainStore::new(params());

        // On the branch, and older than every rival, so a sweep going by age
        // alone would take it first.
        let anchor = shelve(&mut store, 0, 0, CHUNK);
        store.branch.push(anchor);

        let rivals: Vec<Hash32> = (1..=12u64)
            .map(|n| shelve(&mut store, n, n, CHUNK))
            .collect();
        assert_eq!(store.side_bytes(), CHUNK * 12);
        assert!(store.side_bytes() > MAX_SIDE_BYTES);

        store.forget_oldest_side_blocks();

        assert!(
            store.side_bytes() <= MAX_SIDE_BYTES,
            "holding {} bytes off the branch, the ceiling is {MAX_SIDE_BYTES}",
            store.side_bytes()
        );
        assert!(
            store.contains(&anchor),
            "the branch a reorganisation has to undo was swept away with the rest"
        );
        for gone in &rivals[..4] {
            assert!(!store.contains(gone), "the oldest rivals should have gone");
        }
        for kept in &rivals[4..] {
            assert!(store.contains(kept), "and no more than the oldest");
        }
        assert_eq!(
            store.held_bytes(),
            CHUNK * 9,
            "the count was rebuilt from what is left rather than adjusted as it went"
        );

        // Under the ceiling there is nothing to do, and it does nothing.
        let held = store.len();
        store.forget_oldest_side_blocks();
        assert_eq!(store.len(), held);
        assert_eq!(store.held_bytes(), CHUNK * 9);
    }

    /// One block leaves the window each time one is added, so this is a step
    /// and not a sweep: what it costs cannot depend on how long the chain has
    /// been running, on a node whose whole claim is that its cost does not
    /// grow with the chain.
    #[test]
    fn blocks_too_deep_to_undo_are_let_go_one_at_a_time() {
        let mut store = ChainStore::new(params());
        let past = 5usize;
        let count = as_height(MAX_REORG_DEPTH + past);

        let mut previous = Hash32::ZERO;
        let mut ids = Vec::new();
        for height in 0..count {
            let block = block_at(height, previous, 1);
            let id = block.id();
            previous = id;
            store.hold(id, block, 0);
            store.branch.push(id);
            // Exactly where `follow` calls it: once per block applied.
            store.forget_what_cannot_change();
            ids.push(id);
        }

        assert_eq!(
            store.undo_from,
            as_height(past),
            "the cursor moved one block per block, and not in a burst at the end"
        );
        assert_eq!(
            store.len(),
            MAX_REORG_DEPTH,
            "what is held is the window, whatever the chain has reached"
        );
        assert!(!store.contains(&ids[past - 1]));
        assert!(store.contains(&ids[past]));
        assert_eq!(
            store.held_bytes(),
            store
                .blocks
                .values()
                .map(|stored| stored.bytes)
                .fold(0usize, usize::saturating_add),
            "and the bytes came off with the blocks"
        );
    }
}

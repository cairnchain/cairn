//! What an explorer keeps that a node deliberately throws away.
//!
//! A Cairn node forgets on purpose: that is the whole thesis, and it is why
//! running one costs the same in ten years as today. An explorer is the
//! opposite service. It keeps every note that ever existed and an index from
//! owners to their notes, which is exactly the growing cost the protocol
//! refuses to put on validators. Keeping the two apart is not tidiness. It is
//! the claim: this file is what the chain does not make anyone carry.

use std::collections::{BTreeMap, HashMap};

use cairn_crypto::PublicKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::NoteId;
use cairn_primitives::{Amount, Hash32};

/// Where a transaction sits on the followed branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Location {
    pub(crate) height: u64,
    /// Zero for the coinbase, then one per transfer in block order.
    pub(crate) position: u32,
}

/// One note and what became of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NoteRecord {
    pub(crate) value: Amount,
    pub(crate) owner: PublicKey,
    /// Height of the block that created it.
    pub(crate) created_at: u64,
    /// Height of the block that spent it, once one has.
    pub(crate) spent_at: Option<u64>,
    /// The transfer that spent it.
    pub(crate) spent_by: Option<Hash32>,
}

impl NoteRecord {
    pub(crate) fn is_unspent(&self) -> bool {
        self.spent_at.is_none()
    }
}

/// One movement in or out of an owner's holdings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Movement {
    pub(crate) height: u64,
    /// True for a note arriving, false for one being spent.
    pub(crate) incoming: bool,
    pub(crate) transaction: Hash32,
    pub(crate) value: Amount,
}

/// Everything an owner has ever been paid.
#[derive(Clone, Debug, Default)]
pub(crate) struct OwnerRecord {
    /// Notes made out to this owner, oldest first.
    pub(crate) notes: Vec<NoteId>,
    /// Every movement, in the order the chain produced them.
    ///
    /// Recorded as it happens rather than assembled and sorted per request.
    /// A miner's address accumulates hundreds of thousands of these, and
    /// rebuilding that list to answer one page was work an anonymous caller
    /// could ask for as often as they liked.
    pub(crate) movements: Vec<Movement>,
    pub(crate) received: Amount,
    pub(crate) spent: Amount,
}

impl OwnerRecord {
    pub(crate) fn balance(&self) -> Amount {
        self.received
            .checked_sub(self.spent)
            .unwrap_or(Amount::ZERO)
    }
}

/// Totals over the followed branch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Totals {
    pub(crate) blocks: u64,
    pub(crate) transfers: u64,
    pub(crate) notes_created: u64,
    pub(crate) notes_spent: u64,
    /// Everything paid to miners, rewards and fees together.
    pub(crate) paid_to_miners: Amount,
    /// The part of that which came from senders rather than from emission.
    pub(crate) fees: Amount,
}

impl Totals {
    /// Money in existence: everything ever paid out, minus nothing, because
    /// Cairn burns nothing.
    pub(crate) fn issued(&self) -> Amount {
        self.paid_to_miners
            .checked_sub(self.fees)
            .unwrap_or(Amount::ZERO)
    }
}

/// The explorer's view of the chain.
#[derive(Debug, Default)]
pub(crate) struct Index {
    /// The stretch of the branch already read, or nothing before the first
    /// block goes in.
    span: Option<Span>,
    /// Transaction identifier to where it sits. Covers coinbases and transfers.
    ///
    /// One entry per transaction that has ever been mined, and nothing takes
    /// any of them out. That is the price of answering `/api/tx` about a
    /// transaction from years ago, and [`Index::size`] is where an operator
    /// reads what it has come to.
    at: HashMap<Hash32, Location>,
    notes: BTreeMap<NoteId, NoteRecord>,
    owners: HashMap<PublicKey, OwnerRecord>,
    totals: Totals,
    /// Movements over every owner, counted as they are recorded.
    ///
    /// Summed here rather than by walking the owners, because a page that
    /// says what this index costs should not cost a pass over it.
    movements: u64,
    /// Worked out once per refresh rather than once per request.
    richest: Vec<(PublicKey, Amount)>,
    holders: usize,
}

/// The run of blocks the index has read, and what stood at the top of it.
///
/// This used to be every identifier the walk had ever seen, oldest first:
/// thirty two bytes a block, eighty four megabytes at two and a half million
/// blocks, and exactly one of them ever compared against anything. What the
/// comparison needs is the last, so the last is what is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    /// The lowest height read. Zero on a node that still holds its first
    /// block; higher on one that dropped the oldest before the index got
    /// there, which is a shorter answer and not a wrong one, so long as it
    /// is said out loud.
    from: u64,
    /// The highest height read.
    through: u64,
    /// The identifier the branch carried at `through` when it was read. The
    /// one hash worth keeping: a branch that changed under any block below
    /// this changed under this one too.
    id: Hash32,
}

/// What the chain says about itself, read in one go.
///
/// Two questions, both answered from memory, both asked with the chain held
/// and answered before the walk begins. The walk that follows goes to a disk
/// for every block it reads, and it used to do that with the chain still in
/// its hand: one reorganisation then stopped the whole node for as long as it
/// took to read the chain back, incoming blocks included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    /// How far the followed branch reaches.
    pub(crate) tip: u64,
    /// The identifier the branch now carries at the highest height the index
    /// read, or `None` where the node no longer holds one that deep.
    pub(crate) at_last_read: Option<Hash32>,
}

/// What a node could produce for one height of the branch it follows.
///
/// Three answers and not two. A node keeps one run of blocks and drops the
/// oldest as the run grows past what its operator allows it, so a height it
/// cannot produce is either one it has let go of, which will never come back,
/// or one that has not reached its disk yet, which will. Reading the two the
/// same way is what left this index stopped at the first hole for the rest of
/// the run: an explorer past its block budget answered every question about
/// every address with nought, and called the figure exact.
#[derive(Debug)]
pub(crate) enum Held {
    /// The block, ready to read.
    Block(Box<Block>),
    /// Let go of. This node's blocks begin somewhere above this height.
    Dropped,
    /// Not on this node yet, and expected.
    Waiting,
}

/// Owners listed in the holders table.
const RICHEST: usize = 50;

/// Bytes one note that has ever existed costs the index, measured on the
/// running implementation.
///
/// Every note ever made, spent or not, with its owner, its value, the two
/// heights and the movements on both sides of it. It is the explorer's real
/// growing cost and it is seven times the one the site used to name: a node
/// that keeps the whole cold set carries seventy two bytes for each note that
/// has fallen, and a node that keeps none carries nothing at all.
pub(crate) const BYTES_PER_NOTE: u64 = 500;

/// What the index is made of, for the operator who has to pay for it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Size {
    pub(crate) notes: u64,
    pub(crate) transactions: u64,
    pub(crate) owners: u64,
    pub(crate) movements: u64,
    /// What that comes to, at [`BYTES_PER_NOTE`].
    pub(crate) bytes: u64,
}

impl Index {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Reads whatever the chain has added since the last call.
    ///
    /// A reorganisation drops the whole index and reads the branch again.
    /// Unwinding block by block would be faster and is not worth its own set
    /// of bugs here: reorganisations are short and rare, and the rebuild no
    /// longer holds anything the rest of the node needs while it runs.
    ///
    /// `block_at` reads one block of the followed branch from wherever it is.
    /// A node lets go of the bodies of blocks too deep to be undone, and an
    /// index built from the start of the chain wants exactly those, so this
    /// goes to a disk and must be called with no lock held.
    pub(crate) fn refresh(&mut self, head: &Head, block_at: impl Fn(u64) -> Held) {
        // Whether what was read last time is still on the branch. Only the
        // last block has to be checked: everything under it was checked when
        // it was read, and a branch that changed under one of them changed
        // under this one too.
        if let Some(span) = self.span {
            let agrees = match head.at_last_read {
                Some(id) => id == span.id,
                // Past what the chain still holds an identifier for. Nothing
                // that deep can have changed, so it is taken as agreeing.
                None => span.through <= head.tip,
            };
            if !agrees {
                *self = Self::new();
            }
        }

        let before = self.totals.blocks;
        let mut height = match self.span {
            Some(span) => span.through.saturating_add(1),
            // Height zero, and the walk steps over whatever of the bottom of
            // the chain this node no longer holds rather than stopping there.
            None => 0,
        };
        while height <= head.tip {
            match block_at(height) {
                Held::Block(block) => {
                    let id = block.id();
                    self.apply(&block);
                    self.span = Some(match self.span {
                        Some(span) => Span {
                            through: height,
                            id,
                            ..span
                        },
                        None => Span {
                            from: height,
                            through: height,
                            id,
                        },
                    });
                }
                Held::Dropped => {
                    // Below anything read this is only a shorter index, and
                    // the index says where it starts. Above it, the log was
                    // cut while this walk was inside it, so everything read
                    // so far has a hole under it. An index with a hole answers
                    // wrongly rather than shortly, so it starts again here.
                    if self.span.is_some() {
                        *self = Self::new();
                    }
                }
                Held::Waiting => break,
            }
            height = height.saturating_add(1);
        }
        if self.totals.blocks != before {
            self.take_stock();
        }
    }

    fn apply(&mut self, block: &Block) {
        let height = block.header.height;
        self.totals.blocks = self.totals.blocks.saturating_add(1);

        let coinbase = block.coinbase.id();
        self.at.insert(
            coinbase,
            Location {
                height,
                position: 0,
            },
        );
        for (id, note) in block.coinbase.created_notes() {
            self.credit(id, note.value, note.owner, height);
        }
        let paid = block.coinbase.total_output().unwrap_or(Amount::ZERO);
        self.totals.paid_to_miners = self
            .totals
            .paid_to_miners
            .checked_add(paid)
            .unwrap_or(self.totals.paid_to_miners);

        for (index, transfer) in block.transfers.iter().enumerate() {
            let position = u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .unwrap_or(u32::MAX);
            let id = transfer.id();
            self.at.insert(id, Location { height, position });
            self.totals.transfers = self.totals.transfers.saturating_add(1);

            let mut consumed = Amount::ZERO;
            for input in &transfer.inputs {
                if let Some(value) = self.debit(&input.note_id, height, id) {
                    consumed = consumed.checked_add(value).unwrap_or(consumed);
                }
            }
            for (note_id, note) in transfer.created_notes() {
                self.credit(note_id, note.value, note.owner, height);
            }
            let produced = transfer.total_output().unwrap_or(Amount::ZERO);
            // A transfer can never produce more than it consumes; consensus
            // refuses one that does, so the difference is the fee.
            if let Some(fee) = consumed.checked_sub(produced) {
                self.totals.fees = self
                    .totals
                    .fees
                    .checked_add(fee)
                    .unwrap_or(self.totals.fees);
            }
        }
    }

    fn credit(&mut self, id: NoteId, value: Amount, owner: PublicKey, height: u64) {
        self.notes.insert(
            id,
            NoteRecord {
                value,
                owner,
                created_at: height,
                spent_at: None,
                spent_by: None,
            },
        );
        let record = self.owners.entry(owner).or_default();
        record.notes.push(id);
        record.movements.push(Movement {
            height,
            incoming: true,
            transaction: id.source,
            value,
        });
        self.movements = self.movements.saturating_add(1);
        record.received = record
            .received
            .checked_add(value)
            .unwrap_or(record.received);
        self.totals.notes_created = self.totals.notes_created.saturating_add(1);
    }

    /// Marks a note spent and returns what it was worth.
    fn debit(&mut self, id: &NoteId, height: u64, by: Hash32) -> Option<Amount> {
        let record = self.notes.get_mut(id)?;
        record.spent_at = Some(height);
        record.spent_by = Some(by);
        let value = record.value;
        let owner = record.owner;
        if let Some(owner) = self.owners.get_mut(&owner) {
            owner.spent = owner.spent.checked_add(value).unwrap_or(owner.spent);
            owner.movements.push(Movement {
                height,
                incoming: false,
                transaction: by,
                value,
            });
            self.movements = self.movements.saturating_add(1);
        }
        self.totals.notes_spent = self.totals.notes_spent.saturating_add(1);
        Some(value)
    }

    pub(crate) fn totals(&self) -> Totals {
        self.totals
    }

    /// Blocks read so far.
    pub(crate) fn blocks_read(&self) -> usize {
        usize::try_from(self.totals.blocks).unwrap_or(usize::MAX)
    }

    /// The lowest and highest heights this index has read, if it has read any.
    pub(crate) fn covers(&self) -> Option<(u64, u64)> {
        self.span.map(|span| (span.from, span.through))
    }

    /// Whether it read the chain from its first block.
    ///
    /// The one that matters is `false`. An index that starts above zero knows
    /// nothing about what an address held before it started reading, so every
    /// balance it gives is a figure about part of the chain and not about the
    /// chain. Somebody reading a balance of nought has no way of telling that
    /// from a real balance of nought unless the page says which it is.
    pub(crate) fn reads_from_the_start(&self) -> bool {
        matches!(self.span, Some(span) if span.from == 0)
    }

    /// What this index is made of.
    pub(crate) fn size(&self) -> Size {
        let notes = u64::try_from(self.notes.len()).unwrap_or(u64::MAX);
        Size {
            notes,
            transactions: u64::try_from(self.at.len()).unwrap_or(u64::MAX),
            owners: u64::try_from(self.owners.len()).unwrap_or(u64::MAX),
            movements: self.movements,
            bytes: notes.saturating_mul(BYTES_PER_NOTE),
        }
    }

    pub(crate) fn locate(&self, transaction: &Hash32) -> Option<Location> {
        self.at.get(transaction).copied()
    }

    pub(crate) fn note(&self, id: &NoteId) -> Option<NoteRecord> {
        self.notes.get(id).copied()
    }

    pub(crate) fn owner(&self, owner: &PublicKey) -> Option<&OwnerRecord> {
        self.owners.get(owner)
    }

    /// Owners holding anything, heaviest first.
    ///
    /// Read from what the last refresh worked out. Sorting every owner in
    /// order to answer one page was work any caller could ask for at will;
    /// now it happens once per block, whether anyone is looking or not.
    pub(crate) fn richest(&self) -> &[(PublicKey, Amount)] {
        &self.richest
    }

    /// How many owners hold anything at all.
    pub(crate) fn holders(&self) -> usize {
        self.holders
    }

    /// Works out the distribution once, after the chain has moved.
    fn take_stock(&mut self) {
        let mut held: Vec<(PublicKey, Amount)> = self
            .owners
            .iter()
            .map(|(owner, record)| (*owner, record.balance()))
            .filter(|(_, balance)| *balance > Amount::ZERO)
            .collect();
        self.holders = held.len();
        held.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        held.truncate(RICHEST);
        self.richest = held;
    }
}

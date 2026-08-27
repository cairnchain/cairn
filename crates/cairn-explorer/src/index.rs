//! What an explorer keeps that a node deliberately throws away.
//!
//! A Cairn node forgets on purpose: that is the whole thesis, and it is why
//! running one costs the same in ten years as today. An explorer is the
//! opposite service. It keeps every note that ever existed and an index from
//! owners to their notes, which is exactly the growing cost the protocol
//! refuses to put on validators. Keeping the two apart is not tidiness. It is
//! the claim: this file is what the chain does not make anyone carry.

use std::collections::{BTreeMap, HashMap};

use cairn_chain::ChainStore;
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
    /// The prefix of the followed branch already read, oldest first.
    indexed: Vec<Hash32>,
    /// Transaction identifier to where it sits. Covers coinbases and transfers.
    at: HashMap<Hash32, Location>,
    notes: BTreeMap<NoteId, NoteRecord>,
    owners: HashMap<PublicKey, OwnerRecord>,
    totals: Totals,
    /// Worked out once per refresh rather than once per request.
    richest: Vec<(PublicKey, Amount)>,
    holders: usize,
}

/// Owners listed in the holders table.
const RICHEST: usize = 50;

impl Index {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Reads whatever the chain has added since the last call.
    ///
    /// A reorganisation drops the whole index and reads the branch again.
    /// Unwinding block by block would be faster and is not worth its own set
    /// of bugs here: reorganisations are short and rare, and an explorer that
    /// is briefly slow is better than one that is quietly wrong about who
    /// owns what.
    pub(crate) fn refresh(&mut self, chain: &ChainStore) {
        let active = chain.active();
        let mut shared = 0usize;
        while let (Some(known), Some(current)) = (self.indexed.get(shared), active.get(shared)) {
            if known != current {
                break;
            }
            shared = shared.saturating_add(1);
        }
        if shared < self.indexed.len() {
            *self = Self::new();
            shared = 0;
        }

        let mut position = shared;
        let before = self.indexed.len();
        while let Some(id) = active.get(position) {
            let Some(block) = chain.block(id) else {
                break;
            };
            self.apply(block);
            self.indexed.push(*id);
            position = position.saturating_add(1);
        }
        if self.indexed.len() != before {
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
        }
        self.totals.notes_spent = self.totals.notes_spent.saturating_add(1);
        Some(value)
    }

    pub(crate) fn totals(&self) -> Totals {
        self.totals
    }

    /// Blocks read so far.
    pub(crate) fn blocks_read(&self) -> usize {
        self.indexed.len()
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

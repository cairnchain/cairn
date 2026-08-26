//! The note set and its commitment.

use std::collections::{BTreeMap, HashSet};

use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{Domain, Hasher};
use cairn_primitives::merkle::merkle_root;
use cairn_primitives::Hash32;

use crate::block::BlockHeader;
use crate::note::{Note, NoteId};

/// Where a transfer looks up the notes it spends.
///
/// This is the seam the accumulator slots into. A resolver backed by the full
/// note set answers from memory; one backed by the accumulator will answer from
/// a proof carried by the transaction itself. Validation does not care which.
pub trait NoteResolver {
    fn resolve(&self, id: &NoteId) -> Option<Note>;
}

/// The block the state currently sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    pub id: Hash32,
    pub height: u64,
    pub timestamp: u64,
}

/// Hashes one note set entry.
fn state_leaf(id: &NoteId, note: &Note) -> Hash32 {
    let mut hasher = Hasher::new(Domain::StateEntry);
    hasher.update(&id.encode());
    hasher.update(&note.encode());
    hasher.finalize()
}

/// Every unspent note, and the block they were last updated by.
///
/// Notes are held in a [`BTreeMap`] rather than a hash map because the state
/// commitment is computed over them in order, and a hash map's order varies
/// between processes.
#[derive(Clone, Debug, Default)]
pub struct LedgerState {
    notes: BTreeMap<NoteId, Note>,
    tip: Option<Tip>,
}

impl LedgerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tip(&self) -> Option<Tip> {
        self.tip
    }

    /// Height the next block must carry.
    pub fn next_height(&self) -> Option<u64> {
        match self.tip {
            None => Some(0),
            Some(tip) => tip.height.checked_add(1),
        }
    }

    /// Parent identifier the next block must carry.
    pub fn expected_parent(&self) -> Hash32 {
        self.tip.map_or(Hash32::ZERO, |tip| tip.id)
    }

    pub fn note(&self, id: &NoteId) -> Option<Note> {
        self.notes.get(id).copied()
    }

    pub fn len(&self) -> usize {
        self.notes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    pub fn state_root(&self) -> Hash32 {
        self.projected_state_root(&HashSet::new(), &[])
    }

    /// The commitment the state would have once `spent` is removed and
    /// `created` is added, computed without mutating anything.
    ///
    /// A miner needs this to fill in a candidate header, and validation needs
    /// it to check that header, so it has to be available before the block is
    /// accepted.
    pub fn projected_state_root(
        &self,
        spent: &HashSet<NoteId>,
        created: &[(NoteId, Note)],
    ) -> Hash32 {
        let mut entries: Vec<(NoteId, Note)> = self
            .notes
            .iter()
            .filter(|(id, _)| !spent.contains(id))
            .map(|(id, note)| (*id, *note))
            .collect();
        entries.extend_from_slice(created);
        entries.sort_unstable_by_key(|(id, _)| *id);

        let leaves: Vec<Hash32> = entries
            .iter()
            .map(|(id, note)| state_leaf(id, note))
            .collect();
        merkle_root(&leaves)
    }

    /// Applies an already validated block.
    pub(crate) fn commit(
        &mut self,
        header: &BlockHeader,
        spent: &HashSet<NoteId>,
        created: Vec<(NoteId, Note)>,
    ) {
        for id in spent {
            self.notes.remove(id);
        }
        for (id, note) in created {
            self.notes.insert(id, note);
        }
        self.tip = Some(Tip {
            id: header.id(),
            height: header.height,
            timestamp: header.timestamp,
        });
    }
}

impl NoteResolver for LedgerState {
    fn resolve(&self, id: &NoteId) -> Option<Note> {
        self.note(id)
    }
}

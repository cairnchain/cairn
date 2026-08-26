//! The two tier note set.
//!
//! Unspent notes live in one of two places. The hot set is capped in size and
//! held in full by every node, so spending from it needs nothing but the note
//! identifier. The cold set is unbounded and exists only as a commitment, so
//! spending from it means bringing the note and a proof.
//!
//! That split is what bounds the cost of running a node. It also keeps the
//! friction where it belongs: on value that has not moved in a long time.

use std::collections::{BTreeMap, BTreeSet};

use cairn_accumulator::{Key, Proof, SparseMerkleTree};
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain, Hasher};
use cairn_primitives::Hash32;

use crate::block::BlockHeader;
use crate::note::{Note, NoteId};

/// Where a note sits in either accumulator.
///
/// The identifier is hashed rather than used directly. Every note a single
/// transaction creates shares its source identifier, so using it raw would pile
/// those notes onto one path and deepen every proof through it.
pub fn note_key(id: &NoteId) -> Key {
    Key::from_hash(hash(Domain::NoteKey, &id.encode()))
}

/// Leaf value for a note held in the hot set.
///
/// The height is committed to because it decides eviction order. Leaving it out
/// would let two nodes hold the same notes, agree on the root, and still evict
/// different ones.
fn hot_value(note: &Note, height: u64) -> Hash32 {
    let mut hasher = Hasher::new(Domain::HotNoteValue);
    hasher.update(&note.encode());
    hasher.update(&height.encode());
    hasher.finalize()
}

/// Leaf value for a note that has fallen to the cold set.
///
/// The height is dropped here: a cold note is never evicted again, and a
/// spender would otherwise have to carry it just to rebuild the leaf.
pub fn cold_value(note: &Note) -> Hash32 {
    hash(Domain::ColdNoteValue, &note.encode())
}

/// Binds the two tiers into the single root a block header carries.
///
/// Both counts are committed to, so the boundary between the tiers is itself
/// part of the commitment and a node cannot quietly hold more or fewer notes
/// hot than the rules allow.
fn compose_state_root(hot_root: Hash32, hot_len: u64, cold_root: Hash32, cold_len: u64) -> Hash32 {
    let mut hasher = Hasher::new(Domain::StateCommitment);
    hasher.update(hot_root.as_bytes());
    hasher.update(&hot_len.encode());
    hasher.update(cold_root.as_bytes());
    hasher.update(&cold_len.encode());
    hasher.finalize()
}

/// A note in the hot set, with the height that decides when it falls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotEntry {
    pub note: Note,
    pub height: u64,
}

/// The cold set.
///
/// This holds the whole tree, which is what an archivist keeps. A plain node
/// needs only the root and the count in order to validate: it cannot build
/// proofs, and it does not have to, because spenders bring their own. Carving
/// the pruned view out of this type belongs with the networking work.
#[derive(Clone, Debug, Default)]
pub struct ColdSet {
    tree: SparseMerkleTree,
}

impl ColdSet {
    pub fn root(&self) -> Hash32 {
        self.tree.root()
    }

    pub fn len(&self) -> usize {
        self.tree.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Builds the proof a spender needs. Only an archivist can answer this.
    pub fn prove(&self, id: &NoteId) -> Proof {
        self.tree.prove(note_key(id))
    }

    fn insert(&mut self, id: &NoteId, note: &Note) {
        self.tree.insert(note_key(id), cold_value(note));
    }

    fn remove(&mut self, id: &NoteId) {
        self.tree.remove(note_key(id));
    }
}

/// The block the state currently sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    pub id: Hash32,
    pub height: u64,
    pub timestamp: u64,
}

/// Everything a block does to the note set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateTransition {
    pub spent_hot: Vec<NoteId>,
    pub spent_cold: Vec<NoteId>,
    pub created: Vec<(NoteId, Note)>,
    pub evicted: Vec<(NoteId, Note)>,
}

/// Replays a transition onto a pair of trees.
///
/// Both the projection a validator computes and the commit that follows go
/// through this, so the root a block is judged against and the root the node
/// ends up with cannot drift apart.
fn replay(
    hot_tree: &mut SparseMerkleTree,
    cold: &mut ColdSet,
    transition: &StateTransition,
    height: u64,
) {
    for id in &transition.spent_hot {
        hot_tree.remove(note_key(id));
    }
    for id in &transition.spent_cold {
        cold.remove(id);
    }
    for (id, note) in &transition.created {
        hot_tree.insert(note_key(id), hot_value(note, height));
    }
    // Eviction runs last, so a note created by this very block can fall
    // straight through when the block creates more notes than the tier holds.
    for (id, note) in &transition.evicted {
        hot_tree.remove(note_key(id));
        cold.insert(id, note);
    }
}

/// The unspent notes, split across the two tiers.
#[derive(Clone, Debug, Default)]
pub struct LedgerState {
    hot: BTreeMap<NoteId, HotEntry>,
    /// Hot notes ordered by the height they were created at, then by
    /// identifier. Iterating this yields the eviction order directly.
    hot_by_age: BTreeSet<(u64, NoteId)>,
    hot_tree: SparseMerkleTree,
    cold: ColdSet,
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

    /// The note, if it is still in the hot set.
    pub fn hot_note(&self, id: &NoteId) -> Option<Note> {
        self.hot.get(id).map(|entry| entry.note)
    }

    pub fn hot_entry(&self, id: &NoteId) -> Option<HotEntry> {
        self.hot.get(id).copied()
    }

    pub fn hot_len(&self) -> usize {
        self.hot.len()
    }

    pub fn cold(&self) -> &ColdSet {
        &self.cold
    }

    pub fn cold_root(&self) -> Hash32 {
        self.cold.root()
    }

    pub fn cold_len(&self) -> usize {
        self.cold.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hot.is_empty() && self.cold.is_empty()
    }

    pub fn state_root(&self) -> Hash32 {
        compose_state_root(
            self.hot_tree.root(),
            self.hot_tree.len() as u64,
            self.cold.root(),
            self.cold.len() as u64,
        )
    }

    /// Picks the notes that fall to the cold set once this block is applied.
    ///
    /// A note is created once and never modified, so the least recently used
    /// note is simply the one created at the lowest height, with the identifier
    /// breaking ties. Both are public and identical on every node, so nothing
    /// has to track access times and no two nodes can disagree on the order.
    ///
    /// The count is bounded by the notes the block creates, because the tier
    /// was at or under its cap before the block.
    pub fn plan_evictions(
        &self,
        spent_hot: &BTreeSet<NoteId>,
        created: &[(NoteId, Note)],
        capacity: usize,
    ) -> Vec<(NoteId, Note)> {
        let surviving = self.hot.len().saturating_sub(spent_hot.len());
        let overflow = surviving
            .saturating_add(created.len())
            .saturating_sub(capacity);
        if overflow == 0 {
            return Vec::new();
        }

        let mut evicted = Vec::with_capacity(overflow);
        for (_, id) in &self.hot_by_age {
            if evicted.len() >= overflow {
                break;
            }
            if spent_hot.contains(id) {
                continue;
            }
            if let Some(entry) = self.hot.get(id) {
                evicted.push((*id, entry.note));
            }
        }

        if evicted.len() < overflow {
            // Only reachable when one block creates more notes than the tier
            // holds. Those notes all sit at the same height, so the identifier
            // is what separates them.
            let mut fresh = created.to_vec();
            fresh.sort_unstable_by_key(|(id, _)| *id);
            for entry in fresh {
                if evicted.len() >= overflow {
                    break;
                }
                evicted.push(entry);
            }
        }
        evicted
    }

    /// The state root this transition would produce, computed without touching
    /// the current state.
    ///
    /// Both trees are persistent, so the copies here are pointer copies and
    /// only the edited paths are rebuilt.
    pub fn project(&self, transition: &StateTransition, height: u64) -> Hash32 {
        let mut hot_tree = self.hot_tree.clone();
        let mut cold = self.cold.clone();
        replay(&mut hot_tree, &mut cold, transition, height);
        compose_state_root(
            hot_tree.root(),
            hot_tree.len() as u64,
            cold.root(),
            cold.len() as u64,
        )
    }

    /// Applies an already validated transition.
    pub(crate) fn commit(&mut self, header: &BlockHeader, transition: &StateTransition) {
        let height = header.height;
        replay(&mut self.hot_tree, &mut self.cold, transition, height);

        for id in &transition.spent_hot {
            self.forget_hot(id);
        }
        for (id, note) in &transition.created {
            self.remember_hot(*id, *note, height);
        }
        for (id, _) in &transition.evicted {
            self.forget_hot(id);
        }

        debug_assert_eq!(self.hot.len(), self.hot_tree.len());
        debug_assert_eq!(self.hot.len(), self.hot_by_age.len());

        self.tip = Some(Tip {
            id: header.id(),
            height,
            timestamp: header.timestamp,
        });
    }

    fn remember_hot(&mut self, id: NoteId, note: Note, height: u64) {
        if let Some(previous) = self.hot.insert(id, HotEntry { note, height }) {
            self.hot_by_age.remove(&(previous.height, id));
        }
        self.hot_by_age.insert((height, id));
    }

    fn forget_hot(&mut self, id: &NoteId) {
        if let Some(entry) = self.hot.remove(id) {
            self.hot_by_age.remove(&(entry.height, *id));
        }
    }
}

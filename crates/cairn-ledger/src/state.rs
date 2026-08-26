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

use cairn_accumulator::forest::forest_leaf;
use cairn_accumulator::{Archive, Forest, ForestProof, Key, SparseMerkleTree};
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain, Hasher};
use cairn_primitives::Hash32;

use crate::block::{BlockHeader, HeaderSummary};
use crate::note::{Note, NoteId};
use crate::pow::RECENT_HEADERS;

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

/// The leaf a fallen note takes in the forest.
///
/// The identifier is folded in because a position in the forest carries no
/// meaning of its own: without it, a proof for one note would serve for
/// another note of the same value and owner sitting elsewhere.
///
/// The height is left out: a cold note never falls again, and a spender would
/// otherwise have to carry it only to rebuild the leaf.
pub fn cold_leaf(id: &NoteId, note: &Note) -> Hash32 {
    let mut bytes = Vec::new();
    id.encode_to(&mut bytes);
    note.encode_to(&mut bytes);
    forest_leaf(&bytes)
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

/// A note that has fallen, and where it sits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdSpend {
    pub id: NoteId,
    /// Where the note sits in the forest. Positions are handed out in order
    /// and never reused, so this is stable for the life of the chain.
    pub position: u64,
    pub note: Note,
    /// What the spender presented. Kept because taking the note back out of
    /// the forest on a reorganisation needs the same siblings.
    pub proof: ForestProof,
}

/// The cold set, as whoever is holding it holds it.
///
/// A plain node keeps [`ColdSet::Roots`]: at most sixty four hashes and two
/// counters, whatever the set contains. That is the whole reason the cost of
/// running a node does not grow, and it works because folding a fallen note
/// into an append only forest needs nothing but those roots.
///
/// An archivist keeps [`ColdSet::Archive`] instead, which is every leaf the
/// forest ever held. Only an archivist can rebuild a proof for someone who
/// lost theirs, and that is the service it is paid for.
#[derive(Clone, Debug)]
pub enum ColdSet {
    Roots(Forest),
    Archive(Archive),
}

impl Default for ColdSet {
    fn default() -> Self {
        Self::Roots(Forest::new())
    }
}

impl ColdSet {
    /// What a node that only validates keeps.
    pub fn plain() -> Self {
        Self::Roots(Forest::new())
    }

    /// What a node that can answer with proofs keeps.
    pub fn archiving() -> Self {
        Self::Archive(Archive::new())
    }

    pub fn is_archiving(&self) -> bool {
        matches!(self, Self::Archive(_))
    }

    fn forest(&self) -> &Forest {
        match self {
            Self::Roots(forest) => forest,
            Self::Archive(archive) => archive.forest(),
        }
    }

    /// The thirty two bytes the state commitment folds in.
    pub fn commitment(&self) -> Hash32 {
        self.forest().commitment()
    }

    /// Notes still standing in the cold set.
    pub fn len(&self) -> u64 {
        self.forest().len()
    }

    pub fn is_empty(&self) -> bool {
        self.forest().is_empty()
    }

    /// Positions handed out so far, which is where the next one goes.
    pub fn next_position(&self) -> u64 {
        self.forest().leaves()
    }

    /// Whether the note at `position` is what the proof says it is.
    pub fn verify(&self, position: u64, leaf: Hash32, proof: &ForestProof) -> bool {
        self.forest().verify(position, leaf, proof)
    }

    /// Builds a proof. Only an archivist can answer.
    pub fn prove(&self, position: u64) -> Option<ForestProof> {
        match self {
            Self::Roots(_) => None,
            Self::Archive(archive) => archive.prove(position),
        }
    }

    /// Where a fallen note sits. Only an archivist can answer, which is
    /// exactly the service a wallet that lost its record pays for.
    pub fn locate(&self, id: &NoteId, note: &Note) -> Option<u64> {
        match self {
            Self::Roots(_) => None,
            Self::Archive(archive) => archive.locate(cold_leaf(id, note)),
        }
    }

    /// The leaf at a position, if this holder keeps leaves at all.
    pub fn leaf_at(&self, position: u64) -> Option<Hash32> {
        match self {
            Self::Roots(_) => None,
            Self::Archive(archive) => archive.leaf_at(position),
        }
    }

    /// A copy of the roots alone, which is all it takes to put the cold set
    /// back where it was.
    fn snapshot(&self) -> Forest {
        self.forest().clone()
    }

    fn add(&mut self, leaf: Hash32) -> Option<u64> {
        match self {
            Self::Roots(forest) => forest.add(leaf),
            Self::Archive(archive) => archive.add(leaf),
        }
    }

    /// Empties several notes at once, all proved against the roots as they
    /// stand before the block.
    fn remove_batch(&mut self, removals: &[(u64, Hash32, ForestProof)]) -> bool {
        match self {
            Self::Roots(forest) => forest.remove_batch(removals),
            Self::Archive(archive) => {
                for (position, leaf, proof) in removals {
                    if !archive.forest().verify(*position, *leaf, proof) {
                        return false;
                    }
                }
                // An archivist holds the leaves, so it rebuilds each proof for
                // itself and the order genuinely cannot matter.
                removals
                    .iter()
                    .all(|(position, _, _)| archive.remove(*position))
            }
        }
    }

    /// Puts the cold set back as it stood, given the roots from before and
    /// what the block did to it.
    fn rewind(&mut self, before: &Forest, appended: usize, restored: &[(u64, Hash32)]) {
        match self {
            Self::Roots(forest) => *forest = before.clone(),
            Self::Archive(archive) => archive.rewind(before, appended, restored),
        }
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
    /// Notes spent out of the cold set, with everything it takes to put them
    /// back: nobody holds the cold set, so nothing else could.
    pub spent_cold: Vec<ColdSpend>,
    pub created: Vec<(NoteId, Note)>,
    pub evicted: Vec<(NoteId, Note)>,
}

/// Everything needed to take a block back out of the state.
///
/// A node that discovers a heavier branch has to undo the blocks it already
/// applied. Replaying the chain from genesis every time would make one
/// reorganisation cost the whole history, so each block records its own
/// inverse as it is applied.
#[derive(Clone, Debug, Default)]
pub struct BlockUndo {
    /// Hot notes the block spent, with the height they were created at.
    restored_hot: Vec<(NoteId, HotEntry)>,
    /// Notes the block pushed down to the cold set, with the height they held.
    unevicted: Vec<(NoteId, HotEntry)>,
    previous_tip: Option<Tip>,
    /// The summary that fell out of the recent window when this block landed.
    dropped_summary: Option<HeaderSummary>,
    /// The cold roots from just before the block.
    ///
    /// Undoing an append to a forest means splitting a tree back into the ones
    /// it swallowed, and those are not recoverable from the roots that remain.
    /// Sixty four hashes is a small price for not having to hold the forest.
    cold_before: Forest,
}

/// Replays a transition onto a hot tree and a cold set.
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
    let removals: Vec<(u64, Hash32, ForestProof)> = transition
        .spent_cold
        .iter()
        .map(|spend| {
            (
                spend.position,
                cold_leaf(&spend.id, &spend.note),
                spend.proof.clone(),
            )
        })
        .collect();
    cold.remove_batch(&removals);
    for (id, note) in &transition.created {
        hot_tree.insert(note_key(id), hot_value(note, height));
    }
    // Eviction runs last, so a note created by this very block can fall
    // straight through when the block creates more notes than the tier holds.
    for (id, note) in &transition.evicted {
        hot_tree.remove(note_key(id));
        cold.add(cold_leaf(id, note));
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
    /// The tail of the header chain, bounded by [`RECENT_HEADERS`]. The
    /// retarget and the timestamp rules read it; nothing else does.
    recent: Vec<HeaderSummary>,
}

impl LedgerState {
    /// A node that validates and nothing more.
    pub fn new() -> Self {
        Self::default()
    }

    /// A node that also keeps the cold set, so it can rebuild a proof for
    /// someone who lost theirs.
    pub fn archiving() -> Self {
        Self {
            cold: ColdSet::archiving(),
            ..Self::default()
        }
    }

    pub fn tip(&self) -> Option<Tip> {
        self.tip
    }

    /// The tail of the header chain, oldest first.
    pub fn recent_headers(&self) -> &[HeaderSummary] {
        &self.recent
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

    /// Every note the node still holds in full, oldest first.
    ///
    /// A wallet needs this to find what it owns. Nothing answers the same
    /// question about the cold set, because nobody holds it: a wallet keeps its
    /// own record of what fell, which is the point of the proofs it carries.
    pub fn hot_notes(&self) -> impl Iterator<Item = (NoteId, HotEntry)> + '_ {
        self.hot.iter().map(|(id, entry)| (*id, *entry))
    }

    pub fn hot_len(&self) -> usize {
        self.hot.len()
    }

    pub fn cold(&self) -> &ColdSet {
        &self.cold
    }

    pub fn cold_len(&self) -> u64 {
        self.cold.len()
    }

    /// Where the next note to fall will sit.
    pub fn next_cold_position(&self) -> u64 {
        self.cold.next_position()
    }

    pub fn is_empty(&self) -> bool {
        self.hot.is_empty() && self.cold.is_empty()
    }

    pub fn state_root(&self) -> Hash32 {
        compose_state_root(
            self.hot_tree.root(),
            self.hot_tree.len() as u64,
            self.cold.commitment(),
            self.cold.len(),
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
    /// Both copies here are cheap whatever this node is: the hot tree is
    /// persistent, and the cold side only ever needs its roots, because
    /// appending takes nothing else and removing takes a proof the block
    /// already carries.
    pub fn project(&self, transition: &StateTransition, height: u64) -> Hash32 {
        let mut hot_tree = self.hot_tree.clone();
        let mut cold = ColdSet::Roots(self.cold.snapshot());
        replay(&mut hot_tree, &mut cold, transition, height);
        compose_state_root(
            hot_tree.root(),
            hot_tree.len() as u64,
            cold.commitment(),
            cold.len(),
        )
    }

    /// Applies an already validated transition, returning its inverse.
    pub(crate) fn commit(
        &mut self,
        header: &BlockHeader,
        transition: &StateTransition,
    ) -> BlockUndo {
        let height = header.height;
        let mut undo = BlockUndo {
            previous_tip: self.tip,
            cold_before: self.cold.snapshot(),
            ..BlockUndo::default()
        };

        // Read what the block is about to destroy, before it destroys it.
        for id in &transition.spent_hot {
            if let Some(entry) = self.hot.get(id) {
                undo.restored_hot.push((*id, *entry));
            }
        }
        for (id, _) in &transition.evicted {
            if let Some(entry) = self.hot.get(id) {
                undo.unevicted.push((*id, *entry));
            }
        }

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
        undo.dropped_summary = self.push_recent(header.summary());
        undo
    }

    /// Takes a block back out, restoring the state exactly as it stood before.
    ///
    /// Each step is the inverse of the matching step in [`Self::commit`], run
    /// in the opposite order.
    pub(crate) fn revert(&mut self, transition: &StateTransition, undo: &BlockUndo) {
        self.recent.pop();
        if let Some(summary) = undo.dropped_summary {
            self.recent.insert(0, summary);
        }

        let restored: Vec<(u64, Hash32)> = transition
            .spent_cold
            .iter()
            .map(|spend| (spend.position, cold_leaf(&spend.id, &spend.note)))
            .collect();
        self.cold
            .rewind(&undo.cold_before, transition.evicted.len(), &restored);

        for (id, entry) in &undo.unevicted {
            self.hot_tree
                .insert(note_key(id), hot_value(&entry.note, entry.height));
            self.remember_hot(*id, entry.note, entry.height);
        }
        for (id, _) in &transition.created {
            self.hot_tree.remove(note_key(id));
            self.forget_hot(id);
        }
        for (id, entry) in &undo.restored_hot {
            self.hot_tree
                .insert(note_key(id), hot_value(&entry.note, entry.height));
            self.remember_hot(*id, entry.note, entry.height);
        }

        debug_assert_eq!(self.hot.len(), self.hot_tree.len());
        debug_assert_eq!(self.hot.len(), self.hot_by_age.len());

        self.tip = undo.previous_tip;
    }

    /// Appends a summary, returning the one that fell out of the window.
    fn push_recent(&mut self, summary: HeaderSummary) -> Option<HeaderSummary> {
        self.recent.push(summary);
        if self.recent.len() > RECENT_HEADERS {
            self.recent.drain(..1).next()
        } else {
            None
        }
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

//! The two tier note set.
//!
//! Unspent notes live in one of two places. The hot set is capped in size and
//! held in full by every node, so spending from it needs nothing but the note
//! identifier. The cold set is unbounded and exists only as a commitment, so
//! spending from it means bringing the note and a proof.
//!
//! That split is what bounds the cost of running a node. It also keeps the
//! friction where it belongs: on value that has not moved in a long time.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cairn_accumulator::forest::forest_leaf;
use cairn_accumulator::{Archive, Forest, ForestProof, Key, SparseMerkleTree};
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain, Hasher};
use cairn_primitives::Hash32;

use crate::block::{BlockHeader, HeaderSummary};
use crate::note::{Note, NoteId};
use crate::pow::RECENT_HEADERS;
use cairn_crypto::PublicKey;

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
fn compose_state_root(
    hot_root: Hash32,
    hot_len: u64,
    cold_root: Hash32,
    cold_len: u64,
    grace_root: Hash32,
    bygone_root: Hash32,
) -> Hash32 {
    let mut hasher = Hasher::new(Domain::StateCommitment);
    hasher.update(hot_root.as_bytes());
    hasher.update(&hot_len.encode());
    hasher.update(cold_root.as_bytes());
    hasher.update(&cold_len.encode());
    hasher.update(grace_root.as_bytes());
    hasher.update(bygone_root.as_bytes());
    hasher.finalize()
}

/// The grace window, as one hash.
///
/// A block header commits to this along with the two tiers, and it has to.
/// The window decides what can be spent without a proof, so two nodes
/// disagreeing about it disagree about which blocks are valid. That matters
/// most for a node that did not build its own state but was handed one: with
/// nothing committing to the window, it would start with an empty one and
/// refuse, for the next sixty four blocks, spends the rest of the network
/// accepts. A fork with nobody at fault.
fn compose_grace_root(grace: &VecDeque<Vec<(NoteId, u64, Note)>>) -> Hash32 {
    let mut hasher = Hasher::new(Domain::GraceWindow);
    hasher.update(&u64::try_from(grace.len()).unwrap_or(u64::MAX).encode());
    for block in grace {
        hasher.update(&u64::try_from(block.len()).unwrap_or(u64::MAX).encode());
        for (id, position, note) in block {
            hasher.update(&id.encode());
            hasher.update(&position.encode());
            hasher.update(&note.encode());
        }
    }
    hasher.finalize()
}

/// The states a proof may still be checked against, as one hash.
///
/// A header commits to this for the same reason it commits to the grace
/// window: it decides which blocks are valid. A proof is written against the
/// cold set as it stood when it was taken, and a spender who took one a few
/// blocks ago has not done anything wrong, so a handful of recent states are
/// kept and a proof against any of them is accepted. A node that did not
/// build its own state and was handed one would hold none of them, and would
/// refuse every proof that was not taken at the exact tip.
fn compose_bygone_root(bygone: &VecDeque<Bygone>) -> Hash32 {
    let mut hasher = Hasher::new(Domain::ProofWindow);
    hasher.update(&u64::try_from(bygone.len()).unwrap_or(u64::MAX).encode());
    for past in bygone {
        hasher.update(past.roots.commitment().as_bytes());
        hasher.update(
            &u64::try_from(past.emptied.len())
                .unwrap_or(u64::MAX)
                .encode(),
        );
        for position in &past.emptied {
            hasher.update(&position.encode());
        }
    }
    hasher.finalize()
}

/// The proof window after a block, given the state it moves away from and the
/// places it empties.
///
/// Pure, for the same reason the grace window's is.
fn advance_bygone(bygone: &VecDeque<Bygone>, roots: Forest, emptied: Vec<u64>) -> VecDeque<Bygone> {
    let mut next = bygone.clone();
    next.push_back(Bygone { roots, emptied });
    while next.len() > PROOF_WINDOW {
        next.pop_front();
    }
    next
}

/// The grace window after a block, given what fell in it.
///
/// Pure, so that what a block is checked against and what applying it produces
/// cannot drift apart. Both bounds are here: the window holds a fixed number
/// of blocks and a fixed number of notes, whichever runs out first.
fn advance_grace(
    grace: &VecDeque<Vec<(NoteId, u64, Note)>>,
    landed: Vec<(NoteId, u64, Note)>,
) -> VecDeque<Vec<(NoteId, u64, Note)>> {
    let mut next = grace.clone();
    let mut held: usize = next.iter().map(Vec::len).sum();
    held = held.saturating_add(landed.len());
    next.push_back(landed);

    while next.len() > GRACE_BLOCKS || held > GRACE_NOTES {
        let Some(oldest) = next.pop_front() else {
            break;
        };
        held = held.saturating_sub(oldest.len());
    }
    next
}

/// The notes a block sent to the cold set, with where each one landed.
fn landing(fallen: &[(NoteId, u64)], transition: &StateTransition) -> Vec<(NoteId, u64, Note)> {
    fallen
        .iter()
        .filter_map(|(id, position)| {
            transition
                .evicted
                .iter()
                .find(|(other, _)| other == id)
                .map(|(_, note)| (*id, *position, *note))
        })
        .collect()
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

/// Notes that stay spendable without a proof after they fall.
///
/// The line between the two tiers cannot be a cliff. A transfer is written
/// against the chain as it stands, and by the time a block carries it a note
/// it spends may have fallen. Without this, a spender would have to be exactly
/// at the tip and would lose the race whenever a block landed mid transfer.
///
/// So the notes that fell most recently stay resolvable: every node keeps
/// them, and keeps their proofs current, for as long as they are in this
/// window. The count is fixed, so what it costs is fixed.
pub const GRACE_NOTES: usize = 8_192;

/// Blocks a fallen note stays spendable without a proof, whichever bound
/// bites first.
pub const GRACE_BLOCKS: usize = 64;

/// Blocks a spender's proof may lag behind by.
///
/// A proof describes the forest at the moment it was taken, and the forest
/// moves with every block. Demanding that a spender be exactly at the tip
/// would mean a transfer built while a block was being found is worthless, and
/// on a busy chain almost every transfer is built while a block is being
/// found. So a handful of recent states are kept and a proof against any of
/// them is accepted, as long as the note has not been spent since.
pub const PROOF_WINDOW: usize = 32;

/// A forest as it stood before a block, and what that block took out of it.
#[derive(Clone, Debug)]
struct Bygone {
    roots: Forest,
    emptied: Vec<u64>,
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

/// The cold set together with the recent states a proof may still be checked
/// against.
#[derive(Clone, Debug, Default)]
pub struct ColdTier {
    now: ColdSet,
    /// Oldest first, at most [`PROOF_WINDOW`] deep.
    bygone: VecDeque<Bygone>,
}

impl ColdTier {
    /// What a node that only validates keeps.
    pub fn plain() -> Self {
        Self {
            now: ColdSet::plain(),
            bygone: VecDeque::new(),
        }
    }

    /// What a node that can answer with proofs keeps.
    pub fn archiving() -> Self {
        Self {
            now: ColdSet::archiving(),
            bygone: VecDeque::new(),
        }
    }

    pub fn is_archiving(&self) -> bool {
        self.now.is_archiving()
    }

    pub fn commitment(&self) -> Hash32 {
        self.now.commitment()
    }

    pub fn len(&self) -> u64 {
        self.now.len()
    }

    pub fn is_empty(&self) -> bool {
        self.now.is_empty()
    }

    pub fn next_position(&self) -> u64 {
        self.now.next_position()
    }

    /// The proof for a position: the one being kept current, or one rebuilt
    /// from the leaves if this is an archivist.
    pub fn proof_of(&self, position: u64) -> Option<ForestProof> {
        self.now.proof_of(position)
    }

    /// Builds a proof. Only an archivist can answer.
    pub fn prove(&self, position: u64) -> Option<ForestProof> {
        self.now.prove(position)
    }

    /// Where a fallen note sits. Only an archivist can answer.
    pub fn locate(&self, id: &NoteId, note: &Note) -> Option<u64> {
        self.now.locate(id, note)
    }

    /// Whether the proof holds now, or held recently enough and the note has
    /// not been spent since.
    ///
    /// Walking backwards and gathering what each block took out is what stops
    /// an old proof from resurrecting a note that has already been spent.
    pub fn verify(&self, position: u64, leaf: Hash32, proof: &ForestProof) -> bool {
        if self.now.verify(position, leaf, proof) {
            return true;
        }
        // Walking backwards, a block that emptied this place is reached before
        // any state that still showed it. Once past that block every older
        // state describes a note that has already been spent, so the search
        // stops rather than accepting one.
        for bygone in self.bygone.iter().rev() {
            if bygone.emptied.contains(&position) {
                return false;
            }
            if bygone.roots.verify(position, leaf, proof) {
                return true;
            }
        }
        false
    }

    /// Files the current state away before a block moves it, and says what fell
    /// out of the window.
    fn remember(&mut self, emptied: Vec<u64>) -> Option<Bygone> {
        // Worked out by the same function the projection uses.
        let kept = advance_bygone(&self.bygone, self.now.snapshot().roots_only(), emptied);
        let dropped = if kept.len() <= self.bygone.len() {
            self.bygone.pop_front()
        } else {
            None
        };
        self.bygone = kept;
        dropped
    }

    /// Puts the window back as it was.
    fn forget(&mut self, dropped: Option<Bygone>) {
        self.bygone.pop_back();
        if let Some(bygone) = dropped {
            self.bygone.push_front(bygone);
        }
    }
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

    fn add(&mut self, leaf: Hash32) -> Option<(u64, ForestProof)> {
        match self {
            Self::Roots(forest) => forest.add(leaf),
            Self::Archive(archive) => archive.add(leaf),
        }
    }

    /// Starts keeping the proof for a position current, which is what lets a
    /// holder spend later without asking anyone.
    fn watch(&mut self, position: u64, proof: ForestProof) {
        if let Self::Roots(forest) = self {
            forest.watch(position, proof);
        }
    }

    fn unwatch(&mut self, position: u64) {
        if let Self::Roots(forest) = self {
            forest.unwatch(position);
        }
    }

    /// The proof for a position: the one being kept current, or one rebuilt
    /// from the leaves if this is an archivist.
    pub fn proof_of(&self, position: u64) -> Option<ForestProof> {
        match self {
            Self::Roots(forest) => forest.proof_of(position).cloned(),
            Self::Archive(archive) => archive.prove(position),
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
    /// Work behind this block and everything before it.
    pub total_work: u128,
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
    /// The state that fell out of the acceptance window when this block landed.
    dropped_bygone: Option<Bygone>,
    /// Blocks whose fallen notes stopped being spendable without a proof when
    /// this block landed.
    grace_dropped: Vec<Vec<(NoteId, u64, Note)>>,
    /// The header forest from just before the block, for the same reason the
    /// cold roots are kept: an append cannot be undone from the roots left.
    headers_before: Forest,
    /// And the one before that, which the state keeps alongside so a node can
    /// hand over a forest its own tip vouches for.
    headers_before_before_tip: Forest,
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
) -> Vec<(NoteId, u64)> {
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
    let mut fallen = Vec::with_capacity(transition.evicted.len());
    for (id, note) in &transition.evicted {
        hot_tree.remove(note_key(id));
        if let Some((position, proof)) = cold.add(cold_leaf(id, note)) {
            // Every note that falls is watched: for a while, so it stays
            // spendable without a proof, and for good if someone asked about
            // this owner. The addition hands over the proof, so this costs
            // nothing to start.
            cold.watch(position, proof);
            fallen.push((*id, position));
        }
    }
    for spend in &transition.spent_cold {
        cold.unwatch(spend.position);
    }
    fallen
}

/// The unspent notes, split across the two tiers.
/// The leaf a header takes in the history forest.
///
/// Hashed under its own domain so a header leaf can never be read as a note
/// leaf, even though both forests are built the same way.
pub fn header_leaf(id: &Hash32) -> Hash32 {
    cairn_primitives::hash::hash(Domain::HeaderHistoryLeaf, id.as_bytes())
}

#[derive(Clone, Debug, Default)]
pub struct LedgerState {
    hot: BTreeMap<NoteId, HotEntry>,
    /// Hot notes ordered by the height they were created at, then by
    /// identifier. Iterating this yields the eviction order directly.
    hot_by_age: BTreeSet<(u64, NoteId)>,
    hot_tree: SparseMerkleTree,
    cold: ColdTier,
    tip: Option<Tip>,
    /// The tail of the header chain, bounded by [`RECENT_HEADERS`]. The
    /// retarget and the timestamp rules read it; nothing else does.
    recent: Vec<HeaderSummary>,
    /// Owners whose fallen notes this node keeps track of.
    ///
    /// A wallet names itself here and gets back the two things a node cannot
    /// otherwise tell it: where its fallen notes sit, and a proof that is
    /// still current. Bounded by what the operator asked for, so a node that
    /// asked for nothing pays nothing.
    watching: BTreeSet<PublicKey>,
    /// Fallen notes belonging to a watched owner.
    watched_notes: BTreeMap<NoteId, (u64, Note)>,
    /// What fell in each of the last few blocks, oldest first. Counted in
    /// blocks so that undoing one is exact.
    grace: VecDeque<Vec<(NoteId, u64, Note)>>,
    grace_index: BTreeMap<NoteId, (u64, Note)>,
    /// The same forest as it stood before the tip was added.
    ///
    /// Sixty four more hashes, kept because nothing else commits to the forest
    /// as it stands now: a header's `history` commits to everything before it,
    /// so the forest a node currently holds is only vouched for by the block
    /// that comes next. A node handing its ledger to a newcomer sends this one
    /// instead, which the tip's own header vouches for, and the newcomer adds
    /// the tip back itself.
    headers_before_tip: Forest,
    /// Every header this chain has carried, as sixty four hashes.
    ///
    /// The same append-only forest the cold set uses, holding one leaf per
    /// header rather than one per note. Nobody stores the headers themselves;
    /// what is kept is enough to say whether a header handed over later was
    /// really at the position it claims.
    headers: Forest,
}

impl LedgerState {
    /// A node that validates and nothing more.
    pub fn new() -> Self {
        Self::default()
    }

    /// A node that also keeps the cold set, so it can rebuild a proof for
    /// someone who lost theirs.
    ///
    /// A cost that grows with the chain, carried by whoever offers the service
    /// rather than by everybody. The headers used to be kept here too, for the
    /// other half of what an archivist did; they are on disk now, held by
    /// every node, which is what stopped joining a chain from depending on
    /// somebody volunteering.
    pub fn archiving() -> Self {
        Self {
            cold: ColdTier::archiving(),
            ..Self::default()
        }
    }

    /// Asks to be told where this owner's notes go when they fall.
    ///
    /// Set before the chain is replayed, since what is learned is learned as
    /// the notes fall.
    pub fn watch_owner(&mut self, owner: PublicKey) {
        self.watching.insert(owner);
    }

    pub fn is_watching(&self, owner: &PublicKey) -> bool {
        self.watching.contains(owner)
    }

    /// Fallen notes belonging to a watched owner, with where they sit.
    pub fn watched_notes(&self) -> impl Iterator<Item = (NoteId, u64, Note)> + '_ {
        self.watched_notes
            .iter()
            .map(|(id, (position, note))| (*id, *position, *note))
    }

    /// Where a watched note fell, if it did.
    pub fn watched_position(&self, id: &NoteId) -> Option<u64> {
        self.watched_notes.get(id).map(|(position, _)| *position)
    }

    pub fn tip(&self) -> Option<Tip> {
        self.tip
    }

    /// What the next header must carry as its `history`.
    ///
    /// The commitment to every header applied so far. A node holds sixty four
    /// hashes for it, whatever the chain's age.
    pub fn history_root(&self) -> Hash32 {
        self.headers.commitment()
    }

    /// Headers folded into that commitment, which is the chain's height plus
    /// one once anything has been applied.
    pub fn headers_committed(&self) -> u64 {
        self.headers.len()
    }

    /// The header forest as it stood before the tip, which the tip commits to.
    #[must_use]
    pub fn headers_before_tip(&self) -> Forest {
        self.headers_before_tip.clone()
    }

    /// What fell in each of the last few blocks, oldest first.
    #[must_use]
    pub fn grace_window(&self) -> Vec<Vec<(NoteId, u64, Note)>> {
        self.grace.iter().cloned().collect()
    }

    /// Keeps a proof for every note the grace window holds.
    ///
    /// Only for a ledger being rebuilt from a handover. Each proof is checked
    /// against the cold commitment first, so nothing is kept on the word of
    /// whoever sent it, and every note in the window has to have one: the
    /// window exists so a note that fell moments ago can be spent without a
    /// proof from the spender, which only works if the node holds one.
    pub(crate) fn take_grace_proofs(
        &mut self,
        proofs: &[(u64, ForestProof)],
    ) -> Result<(), crate::handover::HandoverError> {
        for (position, proof) in proofs {
            let Some(leaf) = self.grace_leaf_at(*position) else {
                continue;
            };
            if !self.cold.now.verify(*position, leaf, proof) {
                return Err(crate::handover::HandoverError::BadGraceProof {
                    position: *position,
                });
            }
            self.cold.now.watch(*position, proof.clone());
        }
        for (_, position, _) in self.grace.iter().flatten() {
            if self.cold.now.proof_of(*position).is_none() {
                return Err(crate::handover::HandoverError::MissingGraceProof {
                    position: *position,
                });
            }
        }
        Ok(())
    }

    /// The cold leaf the grace window expects at `position`.
    fn grace_leaf_at(&self, position: u64) -> Option<Hash32> {
        self.grace
            .iter()
            .flatten()
            .find(|(_, at, _)| *at == position)
            .map(|(id, _, note)| cold_leaf(id, note))
    }

    /// The cold set as it stood at each of the last few blocks, with what each
    /// block emptied, oldest first.
    #[must_use]
    pub fn proof_window(&self) -> Vec<(Forest, Vec<u64>)> {
        self.cold
            .bygone
            .iter()
            .map(|past| (past.roots.clone(), past.emptied.clone()))
            .collect()
    }

    /// The cold set as this node holds it, roots only.
    #[must_use]
    pub fn cold_roots(&self) -> Forest {
        self.cold.now.snapshot()
    }

    /// A ledger built from pieces rather than from replaying a chain.
    ///
    /// Nothing here is checked. It is what [`crate::handover::accept`] builds
    /// before comparing the result against the header that commits to it,
    /// which is the only thing that makes a rebuilt ledger worth anything.
    #[must_use]
    pub(crate) fn rebuilt(
        hot: Vec<(NoteId, HotEntry)>,
        cold: Forest,
        grace: VecDeque<Vec<(NoteId, u64, Note)>>,
        bygone: Vec<(Forest, Vec<u64>)>,
        headers_before_tip: Forest,
        recent: Vec<HeaderSummary>,
        at: &BlockHeader,
    ) -> Self {
        let mut state = Self {
            cold: ColdTier {
                now: ColdSet::Roots(cold),
                bygone: bygone
                    .into_iter()
                    .map(|(roots, emptied)| Bygone { roots, emptied })
                    .collect(),
            },
            recent,
            headers_before_tip: headers_before_tip.clone(),
            headers: headers_before_tip,
            tip: Some(Tip {
                id: at.id(),
                height: at.height,
                timestamp: at.timestamp,
                total_work: at.total_work,
            }),
            ..Self::default()
        };
        // The tip belongs in the forest, and the forest handed over is the one
        // from before it, because that is the one the tip vouches for.
        state.headers.add(header_leaf(&at.id()));

        for (id, entry) in hot {
            state
                .hot_tree
                .insert(note_key(&id), hot_value(&entry.note, entry.height));
            state.hot_by_age.insert((entry.height, id));
            state.hot.insert(id, entry);
        }
        for block in &grace {
            for (id, position, note) in block {
                state.grace_index.insert(*id, (*position, *note));
            }
        }
        state.grace = grace;
        state
    }

    /// Work behind the followed branch, as the tip's own header states it.
    pub fn total_work(&self) -> u128 {
        self.tip.map_or(0, |tip| tip.total_work)
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

    /// A note that fell recently enough that every node still holds it, along
    /// with where it sits.
    ///
    /// Spending one of these takes no proof from the spender, because the node
    /// kept both the note and its proof.
    pub fn within_grace(&self, id: &NoteId) -> Option<(u64, Note)> {
        self.grace_index.get(id).copied()
    }

    /// Notes still spendable without a proof after falling.
    pub fn grace_len(&self) -> usize {
        self.grace_index.len()
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

    pub fn cold(&self) -> &ColdTier {
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
            compose_grace_root(&self.grace),
            compose_bygone_root(&self.cold.bygone),
        )
    }

    /// The window a proof may still be checked against, as one hash.
    #[must_use]
    pub fn proof_window_root(&self) -> Hash32 {
        compose_bygone_root(&self.cold.bygone)
    }

    /// The grace window as one hash, which a header commits to.
    pub fn grace_root(&self) -> Hash32 {
        compose_grace_root(&self.grace)
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
        let mut cold = ColdSet::Roots(self.cold.now.snapshot());
        let fallen = replay(&mut hot_tree, &mut cold, transition, height);
        // The same window applying this block would leave behind, worked out
        // the same way, so a block's projection and its application cannot
        // disagree about what is spendable without a proof.
        let grace = advance_grace(&self.grace, landing(&fallen, transition));
        // Filed away before the block moves it, which is the order applying
        // one uses, so the two cannot disagree about which states a proof may
        // still be checked against.
        let bygone = advance_bygone(
            &self.cold.bygone,
            self.cold.now.snapshot().roots_only(),
            transition
                .spent_cold
                .iter()
                .map(|spend| spend.position)
                .collect(),
        );
        compose_state_root(
            hot_tree.root(),
            hot_tree.len() as u64,
            cold.commitment(),
            cold.len(),
            compose_grace_root(&grace),
            compose_bygone_root(&bygone),
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
            cold_before: self.cold.now.snapshot(),
            headers_before: self.headers.clone(),
            headers_before_before_tip: self.headers_before_tip.clone(),
            ..BlockUndo::default()
        };
        // File the state away before the block moves it, so a spender whose
        // proof was taken a few blocks ago is still able to spend.
        undo.dropped_bygone = self.cold.remember(
            transition
                .spent_cold
                .iter()
                .map(|spend| spend.position)
                .collect(),
        );

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

        let fallen = replay(&mut self.hot_tree, &mut self.cold.now, transition, height);
        let recently_fallen = fallen;
        for (id, position) in &recently_fallen {
            if let Some((_, note)) = transition.evicted.iter().find(|(other, _)| other == id) {
                if self.watching.contains(&note.owner) {
                    self.watched_notes.insert(*id, (*position, *note));
                }
            }
        }
        for spend in &transition.spent_cold {
            self.watched_notes.remove(&spend.id);
        }

        let landed = landing(&recently_fallen, transition);
        undo.grace_dropped = self.remember_grace(landed);

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

        let id = header.id();
        // Appended after the block is committed, so `history` on the next
        // header commits to this one and every one before it.
        self.headers_before_tip = self.headers.clone();
        self.headers.add(header_leaf(&id));
        self.tip = Some(Tip {
            id,
            height,
            timestamp: header.timestamp,
            total_work: header.total_work,
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
            .now
            .rewind(&undo.cold_before, transition.evicted.len(), &restored);
        self.cold.forget(undo.dropped_bygone.clone());
        self.rewind_grace(&undo.grace_dropped);

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

        self.headers = undo.headers_before.clone();
        self.headers_before_tip = undo.headers_before_before_tip.clone();
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

    /// Records what fell in this block and drops whatever has aged out.
    ///
    /// Both bounds are fixed and both are checked the same way on every node,
    /// so what is spendable without a proof is not a matter of opinion.
    fn remember_grace(
        &mut self,
        landed: Vec<(NoteId, u64, Note)>,
    ) -> Vec<Vec<(NoteId, u64, Note)>> {
        for (id, position, note) in &landed {
            self.grace_index.insert(*id, (*position, *note));
        }
        // Worked out by the same function the projection uses, so the window a
        // block was checked against is the window it leaves behind.
        let kept = advance_grace(&self.grace, landed);
        let leaving = self
            .grace
            .len()
            .saturating_add(1)
            .saturating_sub(kept.len());

        // The blocks that left, so the index and the watches follow them out
        // and an undo can put them back.
        let mut dropped = Vec::new();
        for _ in 0..leaving {
            let Some(oldest) = self.grace.pop_front() else {
                break;
            };
            for (id, position, note) in &oldest {
                self.grace_index.remove(id);
                if !self.watching.contains(&note.owner) {
                    self.cold.now.unwatch(*position);
                }
            }
            dropped.push(oldest);
        }
        self.grace = kept;
        dropped
    }

    /// Puts the grace window back as it stood.
    fn rewind_grace(&mut self, dropped: &[Vec<(NoteId, u64, Note)>]) {
        if let Some(landed) = self.grace.pop_back() {
            for (id, _, _) in &landed {
                self.grace_index.remove(id);
            }
        }
        for oldest in dropped.iter().rev() {
            for (id, position, note) in oldest {
                self.grace_index.insert(*id, (*position, *note));
                let _ = position;
            }
            self.grace.push_front(oldest.clone());
        }
    }

    fn forget_hot(&mut self, id: &NoteId) {
        if let Some(entry) = self.hot.remove(id) {
            self.hot_by_age.remove(&(entry.height, *id));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use cairn_accumulator::forest::forest_leaf;

    use super::*;

    fn leaf(index: u64) -> Hash32 {
        forest_leaf(&index.to_le_bytes())
    }

    #[test]
    fn a_proof_is_accepted_while_it_is_recent_and_not_after() {
        let mut tier = ColdTier::archiving();
        for index in 0..8u64 {
            tier.now.add(leaf(index));
        }
        let proof = tier.prove(0).expect("an archivist can prove it");
        assert!(tier.verify(0, leaf(0), &proof));

        // Eight more leaves merge the tree the proof describes, so it stops
        // matching the roots as they now stand.
        tier.remember(Vec::new());
        for index in 8..16u64 {
            tier.now.add(leaf(index));
        }
        assert!(
            !tier.now.verify(0, leaf(0), &proof),
            "stale against the roots as they are"
        );
        assert!(
            tier.verify(0, leaf(0), &proof),
            "and still good, because it is recent"
        );

        // Far enough back and it is no longer worth keeping around.
        for _ in 0..PROOF_WINDOW {
            tier.remember(Vec::new());
        }
        assert!(
            !tier.verify(0, leaf(0), &proof),
            "past the window it is refused"
        );
    }

    #[test]
    fn a_recent_proof_cannot_resurrect_a_note_that_was_spent() {
        let mut tier = ColdTier::archiving();
        for index in 0..8u64 {
            tier.now.add(leaf(index));
        }
        let proof = tier.prove(3).expect("an archivist can prove it");
        assert!(tier.verify(3, leaf(3), &proof));

        // The note is spent, which is what the block records.
        tier.remember(vec![3]);
        assert!(tier.now.remove_batch(&[(3, leaf(3), proof.clone())]));

        assert!(
            !tier.verify(3, leaf(3), &proof),
            "the proof still describes a real past, and that is exactly why it is refused"
        );
    }

    #[test]
    fn the_window_stays_bounded() {
        let mut tier = ColdTier::plain();
        for index in 0..(PROOF_WINDOW as u64 * 3) {
            tier.now.add(leaf(index));
            tier.remember(Vec::new());
        }
        assert_eq!(tier.bygone.len(), PROOF_WINDOW);
    }
}

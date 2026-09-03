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

use cairn_accumulator::forest::{empty_leaf, forest_leaf};
use cairn_accumulator::{Archive, Forest, ForestProof, Key, PathsBefore, SparseMerkleTree};
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain, Hasher};
use cairn_primitives::{Amount, Hash32};

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
///
/// It stays out. The one rule that wants a note's age is the wait a coinbase
/// serves, and that is written against the coinbase that paid the note rather
/// than against the note, so it costs nothing here and nothing in a witness.
/// Putting the height back would have added eight bytes to every cold leaf,
/// every proof and every spend, to answer a question about a few thousand
/// notes out of a set with no bound on it.
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
///
/// A window of past cold sets was committed to here as well, so that a proof
/// taken a few blocks ago could still be checked. Accepting one was half a
/// rule (the step that takes the note out cannot use an old path), so the
/// rule went, and with nothing left to consult the window went too. State
/// carried inside a commitment and read by nobody is a claim about what a node
/// holds that is not true.
///
/// The maturity window and the issued total are folded in here rather than
/// each through a root of its own. Both decide what blocks are valid, so both
/// have to be committed to for the same reason the grace window is: a node
/// handed a state rather than building one would otherwise start with an empty
/// window and a supply of nothing, and disagree with the network about which
/// blocks are valid with nobody at fault. Neither is given a name of its own
/// because neither is read anywhere else, and the window is written length
/// first, so no two windows produce the same bytes.
fn compose_state_root(
    hot_root: Hash32,
    hot_len: u64,
    cold_root: Hash32,
    cold_len: u64,
    grace_root: Hash32,
    maturing: &VecDeque<Maturing>,
    supply: Amount,
) -> Hash32 {
    let mut hasher = Hasher::new(Domain::StateCommitment);
    hasher.update(hot_root.as_bytes());
    hasher.update(&hot_len.encode());
    hasher.update(cold_root.as_bytes());
    hasher.update(&cold_len.encode());
    hasher.update(grace_root.as_bytes());
    hasher.update(&u64::try_from(maturing.len()).unwrap_or(u64::MAX).encode());
    for (matures_at, coinbase) in maturing {
        hasher.update(&matures_at.encode());
        hasher.update(coinbase.as_bytes());
    }
    hasher.update(&supply.encode());
    hasher.finalize()
}

/// A coinbase whose notes cannot be spent yet, and the first height at which
/// they can.
///
/// The coinbase is named by its own identifier rather than by the notes it
/// paid, because that is what every input carries: a note it created has that
/// identifier as the source half of its own. So the rule can be asked of an
/// input without knowing where the note is held, which is the whole point of
/// writing it this way.
pub type Maturing = (u64, Hash32);

/// The maturity window after a block, given the coinbase that block paid.
///
/// Pure, for the same reason [`advance_grace`] is: what a block is checked
/// against and what applying it produces cannot be allowed to drift apart.
///
/// The window holds every coinbase that has not matured at `height`, so an
/// entry leaves on the block where its notes become spendable and never comes
/// back. That is why the window needs no length of its own and no rule of its
/// own to trim it: being in it *is* being immature.
///
/// Entries leave from the front. A block's height is one more than the last,
/// so the heights they mature at only ever increase, and the ones that have
/// matured are a prefix. Should a rule change ever make that untrue, an entry
/// stays a while longer without refusing anything, because what refuses is the
/// comparison and not the membership.
fn advance_maturing(
    maturing: &VecDeque<Maturing>,
    coinbase: Option<Maturing>,
    height: u64,
) -> Maturity {
    let mut kept = maturing.clone();
    let mut matured = Vec::new();
    while kept
        .front()
        .is_some_and(|(matures_at, _)| *matures_at <= height)
    {
        if let Some(entry) = kept.pop_front() {
            matured.push(entry);
        }
    }
    // A coinbase whose notes are spendable on the block that pays them never
    // enters the window at all, so there is nothing to take out of it later.
    let added = coinbase.filter(|(matures_at, _)| *matures_at > height);
    if let Some(entry) = added {
        kept.push_back(entry);
    }
    Maturity {
        kept,
        matured,
        added,
    }
}

/// What one block does to the maturity window.
///
/// All three come out of the same pass, so nothing that commits the change and
/// nothing that undoes it can disagree about what the change was.
struct Maturity {
    kept: VecDeque<Maturing>,
    matured: Vec<Maturing>,
    added: Option<Maturing>,
}

/// The issued total after a block, or nothing if it cannot be moved that way.
///
/// A block creates whatever its coinbase pays and destroys whatever the
/// transfers gave up as fees, and the fees are money that already existed: the
/// coinbase may re-create them, and whatever it declines to claim is gone. So
/// the supply moves by the one and against the other, and never by more than
/// the schedule pays, which the coinbase rule already holds it to.
///
/// Both directions are checked rather than saturating. Going over the ceiling
/// means a chain that has issued more than any amount can hold; going under
/// zero means a block destroyed more money than the chain ever issued, which
/// cannot happen to a sound ledger and is exactly the sort of thing that
/// should stop a block rather than be rounded away.
fn supply_after(supply: Amount, minted: Amount, fees: Amount) -> Option<Amount> {
    match minted.checked_sub(fees) {
        Some(created) => supply.checked_add(created),
        None => supply.checked_sub(fees.checked_sub(minted)?),
    }
}

/// What fell in one block: the note, where it landed, and what it was.
pub type Fallen = (NoteId, u64, Note);

/// The grace window, as one hash.
///
/// A block header commits to this along with the two tiers, and it has to.
/// The window decides what can be spent without a proof, so two nodes
/// disagreeing about it disagree about which blocks are valid. That matters
/// most for a node that did not build its own state but was handed one: with
/// nothing committing to the window, it would start with an empty one and
/// refuse, for the next sixty four blocks, spends the rest of the network
/// accepts. A fork with nobody at fault.
fn compose_grace_root(grace: &VecDeque<Vec<Fallen>>) -> Hash32 {
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

/// What one block does to the grace window.
///
/// All of it falls out of the same pass, for the same reason [`Maturity`]
/// does: what a block is checked against and what applying it produces cannot
/// be allowed to drift apart.
struct GraceStep {
    kept: VecDeque<Vec<Fallen>>,
    /// Notes this block spent, with the block and the place in it each held.
    ///
    /// Where and not merely which, because the window is committed to as a
    /// list and putting a note back in the wrong place is a different state
    /// root on a block every other node agrees with.
    lifted: Vec<(usize, usize, Fallen)>,
    /// Blocks that aged off the far end, oldest first.
    dropped: Vec<Vec<Fallen>>,
    /// Whether what fell in this block is on the window afterwards.
    landed_kept: bool,
}

/// The grace window after a block, given what it spent and what fell in it.
///
/// Pure, so that what a block is checked against and what applying it produces
/// cannot drift apart. Both bounds are here: the window holds a fixed number
/// of blocks and a fixed number of notes, whichever runs out first.
///
/// A note the block spent leaves the window on the way through. The window is
/// what fell recently and may still be spent with no proof from the spender,
/// and a note that has been spent cannot be spent again, so it has no business
/// there. Leaving it was not merely untidy: the node had emptied its leaf and
/// dropped the proof it was keeping, so the window went on naming a note
/// nothing could prove, and a ledger with one of those in it cannot be handed
/// to anybody. A receiver wants a proof for every note in the window and a
/// plain node has none to send, while an archivist sends a path to the emptied
/// place and the receiver checks it against the note as it was. Both refuse.
/// One ordinary transfer every sixty four blocks was enough to keep every
/// handover on the network broken, which is to say enough to stop anyone
/// joining without replaying the whole chain.
fn advance_grace(
    grace: &VecDeque<Vec<Fallen>>,
    spent: &BTreeSet<NoteId>,
    landed: Vec<Fallen>,
) -> GraceStep {
    let mut kept = grace.clone();
    let mut lifted = Vec::new();
    if !spent.is_empty() {
        for (block, notes) in kept.iter_mut().enumerate() {
            let mut place = 0usize;
            notes.retain(|fallen| {
                let here = place;
                place = place.saturating_add(1);
                let stays = !spent.contains(&fallen.0);
                if !stays {
                    lifted.push((block, here, *fallen));
                }
                stays
            });
        }
    }

    let blocks_before = kept.len();
    let mut held: usize = kept.iter().map(Vec::len).sum();
    held = held.saturating_add(landed.len());
    kept.push_back(landed);

    let mut dropped = Vec::new();
    while kept.len() > GRACE_BLOCKS || held > GRACE_NOTES {
        let Some(oldest) = kept.pop_front() else {
            break;
        };
        held = held.saturating_sub(oldest.len());
        dropped.push(oldest);
    }
    // A block landing more than the window can ever hold runs the front out
    // and then loses its own landing as well. What it landed was never on the
    // window, so it is not something an undo has to put back, and it is not
    // something the index may be told about either.
    let landed_kept = dropped.len() <= blocks_before;
    if !landed_kept {
        dropped.pop();
    }
    GraceStep {
        kept,
        lifted,
        dropped,
        landed_kept,
    }
}

/// The notes a block took out of the cold set.
///
/// The window has to be told, and so does the projection, so it is worked out
/// in one place rather than twice.
fn spent_cold(transition: &StateTransition) -> BTreeSet<NoteId> {
    transition.spent_cold.iter().map(|spend| spend.id).collect()
}

/// The notes a block sent to the cold set, with where each one landed.
fn landing(fallen: &[(NoteId, u64)], transition: &StateTransition) -> Vec<Fallen> {
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

/// Fallen notes a node follows on behalf of the owners it was asked to
/// follow.
///
/// The set of owners is bounded by what an operator typed. The set of notes
/// was not, and the two were treated as the same bound. An owner is a public
/// key on a public chain, so anyone could add to it: a dust note paid to a
/// followed address costs the sender a transfer and costs the node an entry
/// and a full path, for good, and a copy of that path in every undo record.
/// Measured, a run that should have held a window of a thousand held four and
/// a half thousand and was still climbing.
///
/// So there is a ceiling, and when it is reached the least valuable note held
/// is the one let go of. That is what makes the ceiling worth having rather
/// than merely true: displacing a note now costs more than the note is worth,
/// times the ceiling, where before it cost a transfer.
///
/// What a wallet does when its note is the one let go of is what it does for
/// any fallen note it cannot prove: it keeps its own record of what fell,
/// which is the point of the proofs it carries, and an archivist can say
/// where a note sits for a wallet that lost even that. The node reports the
/// note as one it cannot prove rather than as one that does not exist.
pub const WATCHED_NOTES: usize = 8_192;

/// The cold set, as whoever is holding it holds it.
///
/// A plain node keeps [`ColdSet::Roots`]: at most sixty four hashes and two
/// counters for the set itself, whatever it contains. That is the whole reason
/// the cost of running a node does not grow, and it works because folding a
/// fallen note into an append only forest needs nothing but those roots.
///
/// Beside the roots it keeps a path per note it can be asked to prove, which
/// is the grace window and whatever owners it follows. Both are bounded, so
/// this is too, but it is much the larger of the two and it is worth not
/// confusing the one figure with the other.
///
/// An archivist keeps [`ColdSet::Archive`] instead, which is every leaf the
/// forest ever held. Only an archivist can rebuild a proof for someone who
/// lost theirs. Nobody is paid for that, which every paper says and this
/// comment used to contradict: the network does not need it, and the person
/// who does is whoever lost their own proof.
#[derive(Clone, Debug)]
pub enum ColdSet {
    Roots(Forest),
    Archive(Archive),
}

/// The cold set, and nothing beside it.
///
/// A window of the last thirty two states used to sit here, so a proof taken
/// a few blocks ago could still be checked. Accepting one was half a rule: the
/// step that takes a note out folds along the path the proof carries, and an
/// old path does not reach the root that is there now, so the removal did
/// nothing and the note could be spent again. The rule went, and with nothing
/// left to consult the window went with it, including out of the state root,
/// where it was a claim about what a node holds that had stopped being true.
#[derive(Clone, Debug, Default)]
pub struct ColdTier {
    now: ColdSet,
}

impl ColdTier {
    /// What a node that only validates keeps.
    pub fn plain() -> Self {
        Self {
            now: ColdSet::plain(),
        }
    }

    /// What a node that can answer with proofs keeps.
    pub fn archiving() -> Self {
        Self {
            now: ColdSet::archiving(),
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

    /// Whether the proof holds against the set as it stands.
    ///
    /// Only as it stands. This once also accepted a proof matching any of the
    /// last thirty two states, so that a spender who took one a few blocks ago
    /// was not punished for the wait. Accepting it was half a rule: the step
    /// that takes the note out folds the empty leaf up the path the proof
    /// carries, and an old path does not reach the root that is there now, so
    /// the removal quietly did nothing and said so through a value nobody
    /// read. The note stayed, and could be spent again. Money out of nothing,
    /// agreed by every node, so nothing forked and nothing complained.
    ///
    /// The half that was missing cannot be written cheaply. Rebuilding an old
    /// path into a current one means holding what changed in between, and a
    /// node holds sixty four hashes: carrying thirty two blocks of the cold
    /// set's movements as committed state would grow the one thing this design
    /// exists to bound, to buy a convenience.
    ///
    /// And it is only a convenience. A transfer's identity leaves out its
    /// witness on purpose, precisely so a proof can be refreshed without
    /// making it a different transfer. One that waited too long is the same
    /// transfer with a newer proof, offered again, which costs whoever holds
    /// it nothing, and costs everybody else nothing to check.
    pub fn verify(&self, position: u64, leaf: Hash32, proof: &ForestProof) -> bool {
        self.now.verify(position, leaf, proof)
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

    /// A copy of the roots alone.
    ///
    /// The roots really are all of it: whether a leaf may be added or emptied,
    /// and what the commitment comes to afterwards, is decided by them. The
    /// paths a holder keeps current ride along on a `clone` and are the
    /// largest thing it holds, so anything that only wants to know what the
    /// set would look like asks for this instead.
    fn snapshot(&self) -> Forest {
        self.forest().roots_only()
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

    /// Stops keeping a path current, writing down what it was so an undo can
    /// start again.
    ///
    /// For a path let go of because the window or the ceiling stopped wanting
    /// it. Nothing else in the block says what it was, so this is the one
    /// thing an undo record pays for.
    fn unwatch(&mut self, position: u64, before: &mut PathsBefore) {
        if let Self::Roots(forest) = self {
            forest.unwatch_keeping(position, before);
        }
    }

    /// The same for a path let go of because the block spent the note under
    /// it, which costs the place and nothing more.
    ///
    /// The proof the spend was checked with is that path, and it stays in the
    /// transition for as long as the block can be undone.
    fn unwatch_spent(&mut self, position: u64, before: &mut PathsBefore) {
        if let Self::Roots(forest) = self {
            forest.unwatch_spent(position, before);
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
    ///
    /// The two arms have to be the same function. They were not: the forest
    /// sorts and deduplicates its list, so a place named twice was emptied
    /// once and the answer was yes, while the archivist walked the list as
    /// given, met the empty leaf on the second visit and answered no. Nothing
    /// in a block produces that list, because a place is pinned by the note
    /// identifier and a repeated identifier is already refused. What made it
    /// worth closing is what sits behind it: the caller applies this to a
    /// state whose root has already been checked and will not be checked
    /// again, so two arms that disagreed would have let one kind of node carry
    /// on with a half emptied forest.
    fn remove_batch(&mut self, removals: &[(u64, Hash32, ForestProof)]) -> bool {
        match self {
            Self::Roots(forest) => forest.remove_batch(removals),
            Self::Archive(archive) => {
                for (position, leaf, proof) in removals {
                    if !archive.forest().verify(*position, *leaf, proof) {
                        return false;
                    }
                }
                let mut places: Vec<u64> = removals.iter().map(|(at, _, _)| *at).collect();
                places.sort_unstable();
                places.dedup();
                // Answered before anything is emptied, so a refusal leaves the
                // archive as it was, which is what the other arm now promises
                // too.
                if places
                    .iter()
                    .any(|at| archive.leaf_at(*at).is_none_or(|held| held == empty_leaf()))
                {
                    return false;
                }
                // An archivist holds the leaves, so it rebuilds each proof for
                // itself and the order genuinely cannot matter.
                places.iter().all(|at| archive.remove(*at))
            }
        }
    }

    /// Puts the cold set back as it stood, given the roots from before and
    /// what the block did to it.
    ///
    /// A plain node mends the paths it was keeping current rather than being
    /// handed a copy of them, because a copy per block is nine gigabytes at
    /// this network's numbers. Most of the mending is worked out from
    /// `restored`, which is what the block emptied and the proofs it emptied
    /// them with. An archivist keeps no paths and rebuilds any of them from
    /// its leaves, so `disturbed` is nothing to it.
    fn rewind(
        &mut self,
        before: &Forest,
        disturbed: &PathsBefore,
        appended: usize,
        restored: &[(u64, Hash32, ForestProof)],
    ) {
        match self {
            Self::Roots(forest) => forest.rewind_to(before, restored, disturbed),
            Self::Archive(archive) => {
                let leaves: Vec<(u64, Hash32)> = restored
                    .iter()
                    .map(|(position, leaf, _)| (*position, *leaf))
                    .collect();
                archive.rewind(before, appended, &leaves);
            }
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
    /// The coinbase this block paid and the height its notes may first be
    /// spent at, or nothing when it paid nobody and so created nothing that
    /// has to wait.
    pub coinbase: Option<Maturing>,
    /// What the coinbase created.
    pub minted: Amount,
    /// What the transfers gave up as fees, which is money that existed before
    /// this block and does not after it, whether or not the coinbase took it.
    pub fees: Amount,
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
    ///
    /// Sixty four is what this now is. It used to be a whole `Forest`, which
    /// carries the paths its holder keeps current, and those are a path per
    /// note in the grace window: three hundred and twenty one megabytes at a
    /// small scale and nine gigabytes at this network's, held once per block a
    /// node could still undo, against a stated ceiling of sixty eight. What
    /// makes the roots enough is the field below and the transition this
    /// record travels beside.
    cold_before: Forest,
    /// The watched paths nothing else says how to put back.
    ///
    /// Three of the four things a block does to a path cost nothing here.
    /// Adding a leaf only ever pushes siblings onto the end of a path, and how
    /// long a path should be is decided by the leaf count, so undoing an
    /// addition is a truncation. A path beside a leaf the block emptied lost
    /// exactly one sibling, and it folds back out of the leaf and the proof
    /// that took it out, both of which sit in the transition. A path the block
    /// stopped keeping because it spent the note under it is that same proof.
    ///
    /// What is left is a path let go of because the grace window aged past it
    /// or a followed owner's ceiling displaced it. Nothing in the block
    /// accounts for those, so those are written down, and they are the whole
    /// of what a record costs.
    ///
    /// It used to be all four, and the removal was the expensive one because
    /// its size was decided by how much of the watched map sat in the emptied
    /// leaf's tree rather than by anything the block did. Measured off a real
    /// chain in `tests/audit_undo_record_size.rs`: 8133 paths and 911 kB for
    /// one ordinary block, 933.7 MB over the records a node keeps, and 1549.6
    /// MB for a node following an owner at its ceiling. Which is the order the
    /// whole repair set out to remove.
    disturbed: PathsBefore,
    /// Notes this block spent out of the grace window, with the block and the
    /// place in it each held.
    grace_lifted: Vec<(usize, usize, Fallen)>,
    /// Blocks whose fallen notes stopped being spendable without a proof when
    /// this block landed.
    grace_dropped: Vec<Vec<Fallen>>,
    /// Whether what fell in this block ended up on the window at all.
    ///
    /// It does not when the block lands more notes than the window can hold,
    /// which runs the front out and then takes the landing with it.
    grace_landed_kept: bool,
    /// Notes this block started and stopped following for a watched owner.
    ///
    /// Written down rather than worked out again from the block, because the
    /// ceiling on how many are followed means the block's own notes are not
    /// the only thing that decides: taking one on can let another go.
    watched_added: Vec<NoteId>,
    watched_removed: Vec<(NoteId, u64, Note)>,
    /// Coinbases that matured when this block landed, oldest first, and the
    /// entry this block's own coinbase added.
    ///
    /// Both are kept rather than worked out again on the way back, because
    /// undoing has to put the window back exactly: it is committed to, so a
    /// window that comes back in a different order is a different state root
    /// on a block every other node agrees with.
    matured: Vec<Maturing>,
    maturing_added: Option<Maturing>,
    /// The issued total from before the block, kept whole rather than as the
    /// step that produced it. Money is the one thing an undo may not
    /// approximate, and putting a number back is exact where undoing an
    /// addition is only as exact as the addition was.
    supply_before: Amount,
    /// The header forest from just before the block, for the same reason the
    /// cold roots are kept: an append cannot be undone from the roots left.
    headers_before: Forest,
    /// And the one before that, which the state keeps alongside so a node can
    /// hand over a forest its own tip vouches for.
    headers_before_before_tip: Forest,
}

impl BlockUndo {
    /// Watched paths this record has to carry.
    ///
    /// A node keeps one record per block it could still undo, so this times
    /// that depth is memory every node must have, next to the block bodies
    /// `examples/blocksize.rs` already accounts for. Nothing stated it and
    /// nothing measured it, and what went unstated was a full path per note in
    /// the grace window, held a thousand and twenty five times over.
    ///
    /// `tests/audit_undo_record_size.rs` measures this off a real chain rather
    /// than off a forest built by hand, which is what let a figure stand that
    /// had only ever seen one of the two ways a path gets written down.
    pub fn paths_held(&self) -> usize {
        self.disturbed.len()
    }

    /// The same in bytes.
    pub fn path_bytes(&self) -> usize {
        self.disturbed.bytes_held()
    }
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
    disturbed: &mut PathsBefore,
) -> Option<Vec<(NoteId, u64)>> {
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
    // First, and answered rather than dropped. Every proof here was checked
    // against these same roots a moment ago, so a refusal means this node's own
    // state and its own validation disagree, and going on would take the note's
    // value out of nothing. Dropping this answer is what let that happen: the
    // removal did nothing, said so, and nobody was listening.
    //
    // It is the one step here that can refuse, so it goes before anything is
    // touched, and it is all or nothing in itself. A refusal therefore leaves
    // the state exactly as it was and the caller can say no to the block.
    if !cold.remove_batch(&removals) {
        return None;
    }
    for id in &transition.spent_hot {
        hot_tree.remove(note_key(id));
    }
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
        cold.unwatch_spent(spend.position, disturbed);
    }
    Some(fallen)
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
    /// still current. A node that asked for nobody pays nothing.
    watching: BTreeSet<PublicKey>,
    /// Fallen notes belonging to a watched owner, at most [`WATCHED_NOTES`] of
    /// them.
    ///
    /// The owners are bounded by what an operator typed and their notes are
    /// not, which was read for a long time as one bound rather than two: an
    /// address is public, so anybody could pay dust to a followed one and buy
    /// the node a permanent entry and a permanent path. The ceiling is on the
    /// notes, and it is the least valuable that is let go of when it bites.
    watched_notes: BTreeMap<NoteId, (u64, Note)>,
    /// The same by what each is worth, so the least valuable is found without
    /// a walk of the whole set.
    ///
    /// The position and the identifier ride along to make the order total,
    /// which matters because two dust notes of the same value must still have
    /// one answer between them about which goes first.
    watched_by_worth: BTreeSet<(Amount, u64, NoteId)>,
    /// What fell in each of the last few blocks, oldest first, less whatever
    /// has since been spent. Counted in blocks so that undoing one is exact.
    grace: VecDeque<Vec<Fallen>>,
    /// The same by identifier. Written from the window rather than from what a
    /// block landed, so the two cannot come apart: a block landing more notes
    /// than the window can hold used to leave every one of them here, in an
    /// index whose window said nothing about them, and a node that had applied
    /// that block accepted proofless spends that a node handed the same state
    /// refused, with both agreeing on every root.
    grace_index: BTreeMap<NoteId, (u64, Note)>,
    /// Coinbases whose notes cannot be spent yet, oldest first.
    ///
    /// One entry of forty bytes for every block that can still be reorganised
    /// away, so forty kilobytes at the depth this network runs, and constant
    /// like everything else a node holds: an entry leaves on the block where
    /// its notes become spendable.
    maturing: VecDeque<Maturing>,
    /// The same by identifier, so an input costs a lookup rather than a walk
    /// of the window. Every input in every block asks this question, and a
    /// full block asks it more than a thousand times.
    maturing_index: BTreeMap<Hash32, u64>,
    /// Every pebble this branch has issued and not destroyed.
    ///
    /// Nothing else in the ledger states it. The note set is the money, but it
    /// is held as two accumulators and a plain node holds none of the cold
    /// one, so no node could add it up even if it wanted to. This is the one
    /// number that says how much money exists, and it is in the state root, so
    /// two nodes that disagree about it follow different chains instead of
    /// agreeing on a supply neither of them checked.
    supply: Amount,
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

/// The pieces a ledger is put back together from when it is handed over rather
/// than replayed.
///
/// Gathered into one value rather than handed over one after another. They all
/// come from the same handover and there are enough of them now that two put
/// in the wrong order would build a ledger that is wrong in a way nothing here
/// would notice, which is the one thing a rebuilt ledger must not be.
pub(crate) struct Pieces {
    pub hot: Vec<(NoteId, HotEntry)>,
    pub cold: Forest,
    pub grace: VecDeque<Vec<Fallen>>,
    pub maturing: VecDeque<Maturing>,
    pub supply: Amount,
    pub headers_before_tip: Forest,
    pub recent: Vec<HeaderSummary>,
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

        // And take up the ones that have already fallen and are still in the
        // grace window, which this ledger is holding a path for whether or not
        // anybody had asked for them.
        //
        // Without this the repair to `adopt` closed half its case. A node
        // handed a ledger follows its owner from that moment, so notes falling
        // afterwards are followed; the ones that fell in the sixty-four blocks
        // before the anchor arrived with a proof each, sat in the window
        // unclaimed, and were let go of when the window aged past them. The
        // handover went to the trouble of carrying a proof and the node threw
        // it away, and the money it belonged to became unspendable in exactly
        // the case the repair was written for.
        //
        // A note taken up here has no record of having fallen, so an undo
        // cannot put it back where it was. That is right for the case this
        // exists for, where the node was handed the window and can undo
        // nothing below its anchor. Where an undo could reach it, the entry
        // goes stale rather than wrong: the path stops folding to the
        // commitment, and a wallet is told the proof cannot be produced, which
        // is the safe direction and what it is already told about a note
        // nobody kept a path for.
        let taken: Vec<Fallen> = self
            .grace
            .iter()
            .flatten()
            .filter(|(_, _, note)| note.owner == owner)
            .copied()
            .collect();
        for (id, position, note) in taken {
            if self.watched_notes.insert(id, (position, note)).is_none() {
                self.watched_by_worth.insert((note.value, position, id));
            }
        }

        // The grace window can hold as many notes as the ceiling allows, so a
        // back-fill on top of a full set would put it over. The same trim
        // brings it back, cheapest first, which is the policy that makes the
        // ceiling worth having rather than a place a note is dropped at random.
        //
        // Its record of what it let go of is dropped, because none of this is
        // part of a block. Following a note is a fact about this node, not
        // about the chain, and the worst an undo that cannot reach it can do
        // is leave a cheap note unfollowed, which is where it started.
        let mut nothing_to_undo = BlockUndo::default();
        self.trim_followed(&mut nothing_to_undo);
    }

    pub fn is_watching(&self, owner: &PublicKey) -> bool {
        self.watching.contains(owner)
    }

    /// Who this ledger is following.
    ///
    /// Read when a ledger is replaced by one from somewhere else, because who
    /// a node follows is a fact about the node and not about the chain, and a
    /// ledger arriving from a stranger has no business deciding it.
    pub fn watching(&self) -> impl Iterator<Item = PublicKey> + '_ {
        self.watching.iter().copied()
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
    pub fn grace_window(&self) -> Vec<Vec<Fallen>> {
        self.grace.iter().cloned().collect()
    }

    /// Paths this node is keeping current, which is the grace window plus the
    /// notes it follows for a watched owner.
    ///
    /// Both are bounded, and this is the number the bound is about. It is much
    /// the largest thing a node holds beside the hot set, and nothing said it
    /// out loud until a path per note in the window turned out to be held once
    /// per block a node could still undo.
    pub fn watched_paths(&self) -> usize {
        self.cold.now.forest().watched_count()
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
    pub(crate) fn rebuilt(pieces: Pieces, at: &BlockHeader) -> Self {
        let Pieces {
            hot,
            cold,
            grace,
            maturing,
            supply,
            headers_before_tip,
            recent,
        } = pieces;
        let mut state = Self {
            cold: ColdTier {
                now: ColdSet::Roots(cold),
            },
            supply,
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

        // Through `remember_hot` rather than by writing the structures out
        // again here. They were written out here, and the copy was not the
        // same function: `remember_hot` takes the stale entry out of the age
        // index when it replaces one, and this did not. So a handed hot set
        // naming a note twice, at two heights, left the index holding a place
        // the map had already forgotten, and the eviction order is the one
        // structure a receiver builds from the list rather than from the
        // commitment the header carries.
        //
        // A repeated identifier is refused before this runs, in
        // `handover::accept`, which is where the reasoning and the measurement
        // are written down. So nothing reaches this with a duplicate any more
        // and no test can make it: what is left is that the structure has one
        // definition instead of two, which is worth having on its own and is
        // not a guard. `handed_hot_set.rs` checks the property either way
        // round, that a ledger taken from a handover and the same ledger
        // replayed evict in the same order.
        for (id, entry) in hot {
            state
                .hot_tree
                .insert(note_key(&id), hot_value(&entry.note, entry.height));
            state.remember_hot(id, entry.note, entry.height);
        }
        for block in &grace {
            for (id, position, note) in block {
                state.grace_index.insert(*id, (*position, *note));
            }
        }
        state.grace = grace;
        for (matures_at, coinbase) in &maturing {
            state.maturing_index.insert(*coinbase, *matures_at);
        }
        state.maturing = maturing;
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

    /// The height a coinbase's notes may first be spent at, if they may not be
    /// spent yet.
    ///
    /// Asked of the coinbase rather than of the note, and answered without
    /// consulting either tier. A note this coinbase created carries its
    /// identifier as the source half of its own, so a spender cannot get a
    /// different answer by letting the note fall to the cold set and bringing
    /// it back with a proof: the question was never about where the note is.
    pub fn coinbase_matures_at(&self, coinbase: &Hash32) -> Option<u64> {
        self.maturing_index.get(coinbase).copied()
    }

    /// Coinbases whose notes cannot be spent yet, oldest first.
    #[must_use]
    pub fn maturing(&self) -> Vec<Maturing> {
        self.maturing.iter().copied().collect()
    }

    /// Every pebble this branch has issued and not destroyed.
    ///
    /// The money that exists. A coinbase is the only thing that creates any,
    /// and a fee the coinbase declines to claim is the only thing that
    /// destroys any, so this is both what has ever been issued and what is
    /// currently unspent: transfers move money and never change how much of it
    /// there is.
    ///
    /// A node can say this out loud, which it could not before. A chain that
    /// cannot state its own supply cannot notice when it is wrong, and anyone
    /// checking that nothing was minted from nothing had to keep books outside
    /// the ledger to do it.
    pub fn supply(&self) -> Amount {
        self.supply
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
            &self.maturing,
            self.supply,
        )
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
    pub fn project(&self, transition: &StateTransition, height: u64) -> Option<Hash32> {
        let mut hot_tree = self.hot_tree.clone();
        let mut cold = ColdSet::Roots(self.cold.now.snapshot());
        let fallen = replay(
            &mut hot_tree,
            &mut cold,
            transition,
            height,
            &mut PathsBefore::default(),
        )?;
        // The same window applying this block would leave behind, worked out
        // the same way, so a block's projection and its application cannot
        // disagree about what is spendable without a proof.
        let grace = advance_grace(
            &self.grace,
            &spent_cold(transition),
            landing(&fallen, transition),
        )
        .kept;
        let maturing = advance_maturing(&self.maturing, transition.coinbase, height).kept;
        let supply = supply_after(self.supply, transition.minted, transition.fees)?;
        Some(compose_state_root(
            hot_tree.root(),
            hot_tree.len() as u64,
            cold.commitment(),
            cold.len(),
            compose_grace_root(&grace),
            &maturing,
            supply,
        ))
    }

    /// The issued total this transition would leave behind.
    ///
    /// Worked out where a refusal can be reported as what it is, rather than
    /// inside the projection where the only answer available is that the block
    /// produces no root at all.
    pub fn supply_after(&self, transition: &StateTransition) -> Option<Amount> {
        supply_after(self.supply, transition.minted, transition.fees)
    }

    /// Applies an already validated transition, returning its inverse.
    ///
    /// Nothing, or everything. Every step here was reached through the same
    /// transition projected against this same state a moment ago, so a step
    /// that refuses is this node disagreeing with itself. That used to be
    /// swallowed, on the reasoning that the root would not match the one the
    /// block claims: it is the caller that checks the root, it checked it
    /// before this ran, and it does not check again. So the refusal is
    /// reported instead, and the two things that could produce one are both
    /// worked out before anything is touched.
    pub(crate) fn commit(
        &mut self,
        header: &BlockHeader,
        transition: &StateTransition,
    ) -> Option<BlockUndo> {
        let height = header.height;
        // Asked here rather than after the fact, so that a total that cannot
        // be moved leaves the state alone.
        let supply = supply_after(self.supply, transition.minted, transition.fees)?;
        let mut undo = BlockUndo {
            previous_tip: self.tip,
            cold_before: self.cold.now.snapshot(),
            // Told the leaf count it is a record for, since a path written
            // down after this block has lengthened it has to be cut back to
            // what it was.
            disturbed: PathsBefore::before(self.cold.next_position()),
            headers_before: self.headers.clone(),
            headers_before_before_tip: self.headers_before_tip.clone(),
            supply_before: self.supply,
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

        let recently_fallen = replay(
            &mut self.hot_tree,
            &mut self.cold.now,
            transition,
            height,
            &mut undo.disturbed,
        )?;
        for (id, position) in &recently_fallen {
            if let Some((_, note)) = transition.evicted.iter().find(|(other, _)| other == id) {
                if self.watching.contains(&note.owner) {
                    self.follow_note(*id, *position, *note, &mut undo);
                }
            }
        }
        for spend in &transition.spent_cold {
            self.stop_following(&spend.id, &mut undo);
        }

        let landed = landing(&recently_fallen, transition);
        self.remember_grace(&spent_cold(transition), &landed, &mut undo);
        // After the window, because whether a path may be let go of depends on
        // whether the window still wants it, and the window is only settled
        // once the block has been applied to it.
        self.trim_followed(&mut undo);
        let (matured, added) = self.remember_maturing(transition.coinbase, height);
        undo.matured = matured;
        undo.maturing_added = added;
        self.supply = supply;

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
        debug_assert_eq!(self.watched_notes.len(), self.watched_by_worth.len());

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
        Some(undo)
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

        // The notes followed for a watched owner, undone in the opposite order
        // to `commit`: what it took out goes back first, then what it put in
        // comes out. Read off the record rather than worked out again from the
        // block, because the ceiling means a note the block landed is not the
        // only thing that can have moved. These are in no root and nothing
        // about the chain disagrees when they are wrong, which is exactly why
        // nothing would say so. What would be wrong is a wallet: after a
        // reorganisation it would still be shown a note that was undone, and
        // would have lost one that still exists, until something made it
        // resynchronise.
        for (id, position, note) in &undo.watched_removed {
            self.watched_notes.insert(*id, (*position, *note));
            self.watched_by_worth.insert((note.value, *position, *id));
        }
        for id in &undo.watched_added {
            if let Some((position, note)) = self.watched_notes.remove(id) {
                self.watched_by_worth.remove(&(note.value, position, *id));
            }
        }

        // The leaves the block emptied, and the proofs it emptied them with.
        // Those proofs were checked against the roots this is winding back to,
        // which is what makes them the paths those places had.
        let restored: Vec<(u64, Hash32, ForestProof)> = transition
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
        self.cold.now.rewind(
            &undo.cold_before,
            &undo.disturbed,
            transition.evicted.len(),
            &restored,
        );
        self.rewind_grace(undo);
        self.rewind_maturing(&undo.matured, undo.maturing_added);
        self.supply = undo.supply_before;

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
        debug_assert_eq!(self.watched_notes.len(), self.watched_by_worth.len());

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

    /// Records what fell in this block, lets go of what it spent, and drops
    /// whatever has aged out.
    ///
    /// Both bounds are fixed and both are checked the same way on every node,
    /// so what is spendable without a proof is not a matter of opinion.
    ///
    /// The index is written from the window the step produced and never from
    /// what the block landed. Those two are not the same thing when a block
    /// lands more notes than the window can ever hold: the front runs out, the
    /// landing goes with it, and what used to happen then was that every one
    /// of those notes stayed in the index for good, with no block behind them
    /// and no place in the committed window. This node would spend them with
    /// no proof and a node handed the same state would not, and both agreed on
    /// every root. Writing the index from the window is what makes that
    /// impossible rather than merely unreachable, and it stops an unrelated
    /// ratio between two constants being load bearing.
    fn remember_grace(
        &mut self,
        spent: &BTreeSet<NoteId>,
        landed: &[Fallen],
        undo: &mut BlockUndo,
    ) {
        // Worked out by the same function the projection uses, so the window a
        // block was checked against is the window it leaves behind.
        let step = advance_grace(&self.grace, spent, landed.to_vec());

        // A note the block spent is out of the forest already, so only the
        // index has to be told.
        for (_, _, (id, _, _)) in &step.lifted {
            self.grace_index.remove(id);
        }
        // Blocks that aged off the far end: the index and the paths follow
        // them out.
        for block in &step.dropped {
            for (id, position, _) in block {
                self.grace_index.remove(id);
                self.let_go_of_path(id, *position, undo);
            }
        }
        if step.landed_kept {
            for (id, position, note) in landed {
                self.grace_index.insert(*id, (*position, *note));
            }
        } else {
            for (id, position, _) in landed {
                self.let_go_of_path(id, *position, undo);
            }
        }

        undo.grace_lifted = step.lifted;
        undo.grace_dropped = step.dropped;
        undo.grace_landed_kept = step.landed_kept;
        self.grace = step.kept;
    }

    /// Stops keeping a path current, unless something else still wants it.
    ///
    /// The grace window and the owners a node follows both want paths, and a
    /// note can be in both. Whichever lets go second is the one that ends the
    /// watch.
    fn let_go_of_path(&mut self, id: &NoteId, position: u64, undo: &mut BlockUndo) {
        if self.watched_notes.contains_key(id) {
            return;
        }
        self.cold.now.unwatch(position, &mut undo.disturbed);
    }

    /// Starts following a fallen note on behalf of the owner it belongs to.
    fn follow_note(&mut self, id: NoteId, position: u64, note: Note, undo: &mut BlockUndo) {
        if self.watched_notes.insert(id, (position, note)).is_none() {
            undo.watched_added.push(id);
        }
        self.watched_by_worth.insert((note.value, position, id));
    }

    /// Stops following one, which is what a spend does.
    fn stop_following(&mut self, id: &NoteId, undo: &mut BlockUndo) {
        if let Some((position, note)) = self.watched_notes.remove(id) {
            self.watched_by_worth.remove(&(note.value, position, *id));
            undo.watched_removed.push((*id, position, note));
        }
    }

    /// Brings the followed notes back under their ceiling, letting go of the
    /// least valuable first.
    ///
    /// The ceiling is what stops a public address being a way to make somebody
    /// else's node grow for ever. Taking the cheapest first is what makes it
    /// worth having: a note is displaced only by notes worth more than it,
    /// [`WATCHED_NOTES`] of them, so dust displaces nothing.
    fn trim_followed(&mut self, undo: &mut BlockUndo) {
        while self.watched_notes.len() > WATCHED_NOTES {
            let Some(cheapest) = self.watched_by_worth.iter().next().copied() else {
                break;
            };
            let (_, position, id) = cheapest;
            self.watched_by_worth.remove(&cheapest);
            if let Some((held, note)) = self.watched_notes.remove(&id) {
                undo.watched_removed.push((id, held, note));
            }
            // The window may still want the path even though this no longer
            // does, and the window is settled by now.
            if !self.grace_index.contains_key(&id) {
                self.cold.now.unwatch(position, &mut undo.disturbed);
            }
        }
    }

    /// Records the coinbase this block paid and lets go of the ones that
    /// matured on it, reporting both so the step can be undone.
    ///
    /// The window that comes out is the one [`advance_maturing`] gives, so the
    /// window a block was checked against is the window it leaves behind. What
    /// is returned alongside is only what changed, which is what an undo needs
    /// and all it needs.
    fn remember_maturing(
        &mut self,
        coinbase: Option<Maturing>,
        height: u64,
    ) -> (Vec<Maturing>, Option<Maturing>) {
        let step = advance_maturing(&self.maturing, coinbase, height);
        for (_, id) in &step.matured {
            self.maturing_index.remove(id);
        }
        if let Some((matures_at, id)) = step.added {
            self.maturing_index.insert(id, matures_at);
        }
        self.maturing = step.kept;
        (step.matured, step.added)
    }

    /// Puts the maturity window back as it stood.
    ///
    /// The inverse of [`Self::remember_maturing`], step by step in the
    /// opposite order: what the block added comes off the back, then what
    /// matured on it goes back on the front, oldest last so the order it had
    /// is the order it gets. The window is committed to, so an order that
    /// differs is a state root that differs.
    fn rewind_maturing(&mut self, matured: &[Maturing], added: Option<Maturing>) {
        if let Some(entry) = added {
            if self.maturing.back() == Some(&entry) {
                self.maturing.pop_back();
                self.maturing_index.remove(&entry.1);
            }
        }
        for (matures_at, id) in matured.iter().rev() {
            self.maturing.push_front((*matures_at, *id));
            self.maturing_index.insert(*id, *matures_at);
        }
    }

    /// Puts the grace window back as it stood.
    ///
    /// The inverse of [`Self::remember_grace`], step by step in the opposite
    /// order: the block's own landing comes off the back, the blocks that aged
    /// out go back on the front, and the notes the block spent go back where
    /// they sat. Where and not merely back, because the window is committed to
    /// as a list, so a note that returns to a different place is a different
    /// state root on a block every other node agrees with. The places are
    /// ascending, which is what makes putting them back one at a time land
    /// each one on the index it left from.
    fn rewind_grace(&mut self, undo: &BlockUndo) {
        if undo.grace_landed_kept {
            if let Some(landed) = self.grace.pop_back() {
                for (id, _, _) in &landed {
                    self.grace_index.remove(id);
                }
            }
        }
        for oldest in undo.grace_dropped.iter().rev() {
            for (id, position, note) in oldest {
                self.grace_index.insert(*id, (*position, *note));
            }
            self.grace.push_front(oldest.clone());
        }
        for (block, place, fallen) in &undo.grace_lifted {
            let (id, position, note) = fallen;
            self.grace_index.insert(*id, (*position, *note));
            if let Some(notes) = self.grace.get_mut(*block) {
                let at = (*place).min(notes.len());
                notes.insert(at, *fallen);
            }
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
    fn a_proof_is_worth_what_it_is_worth_now() {
        let mut tier = ColdTier::archiving();
        for index in 0..8u64 {
            tier.now.add(leaf(index));
        }
        let proof = tier.prove(0).expect("an archivist can prove it");
        assert!(tier.verify(0, leaf(0), &proof));

        // Eight more leaves merge the tree the proof describes, so it stops
        // matching the roots as they now stand.
        for index in 8..16u64 {
            tier.now.add(leaf(index));
        }
        assert!(
            !tier.verify(0, leaf(0), &proof),
            "and it is refused, rather than accepted and then not applied"
        );

        // Taken again, it is good again. That is the whole cost of the rule:
        // a proof is refreshed by whoever holds it, and a transfer's identity
        // does not include its witness, so nothing else about the spend moves.
        let fresh = tier.prove(0).expect("an archivist can prove it again");
        assert!(tier.verify(0, leaf(0), &fresh));
    }

    /// Both holders answer the same on a list that names a place twice.
    ///
    /// They did not. The forest sorts and deduplicates, so the second mention
    /// was dropped and the answer was yes; the archivist arm walked the list
    /// as given, met the empty leaf on the second visit and answered no.
    /// Nothing in a block produces that list, because a place is pinned by the
    /// leaf, which is pinned by the note identifier, and the block rules
    /// already refuse a repeated identifier. It is closed because of what sits
    /// behind it: `commit` applies this to a state whose root the caller has
    /// already checked and will not check again, so two arms that disagreed
    /// would have let an archivist carry on with a half emptied forest.
    #[test]
    fn the_two_holders_answer_the_same_on_a_place_named_twice() {
        let mut plain = ColdTier::plain();
        let mut keeper = ColdTier::archiving();
        for index in 0..16u64 {
            plain.now.add(leaf(index));
            keeper.now.add(leaf(index));
        }
        let proof = keeper.prove(3).expect("an archivist can prove it");
        let doubled = [(3u64, leaf(3), proof.clone()), (3u64, leaf(3), proof)];

        assert!(plain.now.remove_batch(&doubled));
        assert!(
            keeper.now.remove_batch(&doubled),
            "the archivist used to refuse this, and the forest used to accept it"
        );
        assert_eq!(plain.commitment(), keeper.commitment());
        assert_eq!(plain.len(), keeper.len(), "one leaf gone, not two");
    }

    /// And neither of them empties anything on a batch it is going to refuse.
    #[test]
    fn a_batch_that_cannot_go_through_leaves_both_holders_alone() {
        let mut plain = ColdTier::plain();
        let mut keeper = ColdTier::archiving();
        for index in 0..16u64 {
            plain.now.add(leaf(index));
            keeper.now.add(leaf(index));
        }
        let good = keeper.prove(2).expect("an archivist can prove it");
        let wrong = keeper.prove(4).expect("an archivist can prove it");
        // The second entry offers a proof for one place against another, so it
        // is refused, and the first entry is a real removal that must not have
        // happened by the time anyone finds out.
        let batch = [(2u64, leaf(2), good), (5u64, leaf(5), wrong)];

        let commitment = plain.commitment();
        assert!(!plain.now.remove_batch(&batch));
        assert!(!keeper.now.remove_batch(&batch));
        assert_eq!(plain.commitment(), commitment);
        assert_eq!(keeper.commitment(), commitment);
        assert_eq!(plain.len(), 16);
        assert_eq!(keeper.len(), 16);
    }

    #[test]
    fn a_proof_of_a_real_past_does_not_resurrect_a_spent_note() {
        let mut tier = ColdTier::archiving();
        for index in 0..8u64 {
            tier.now.add(leaf(index));
        }
        let proof = tier.prove(3).expect("an archivist can prove it");
        assert!(tier.verify(3, leaf(3), &proof));

        // The note is spent, which is what the block records.
        assert!(tier.now.remove_batch(&[(3, leaf(3), proof.clone())]));

        assert!(
            !tier.verify(3, leaf(3), &proof),
            "the proof still describes a real past, and that is exactly why it is refused"
        );
    }
}

//! Handing a ledger to a node that does not have one.
//!
//! Once a newcomer has settled which chain is heaviest, it still cannot check
//! a single transaction: knowing what work stands behind a tip says nothing
//! about who owns what. It needs the ledger at that tip, and this is how it
//! gets one without replaying the chain that produced it.
//!
//! What makes that possible here and not elsewhere is that the ledger is
//! bounded. A chain that grows for thirty years still holds the same 68 MB of
//! hot set and the same bounded window beside it, because everything older
//! lives in a commitment rather than in a table. So it can be sent whole,
//! once, and checked against the header that commits to it.
//!
//! Sent whole is about 11 MB and not 68: what travels is the notes, where a
//! node holds them in a map, an eviction order and a tree. It reaches about
//! 19 MB when the grace window is at its own bound and its paths are as deep
//! as the forest gets, which `examples/joining.rs` measures alongside the
//! rest. Two quantities, two instruments: `examples/footprint.rs` reads the
//! 68 and `examples/joining.rs` the 11.
//!
//! This paragraph said a hundred and seven megabytes until round eleven. That
//! is what a hot set cost before a public key stopped being held as a decoded
//! curve point, and it had been corrected everywhere a test could see it: the
//! whitepaper, the site, the lesson files, and a guard in the explorer that
//! runs over the pages and not over this crate's own prose.
//!
//! Nothing here is taken on trust. Every piece is rebuilt and the result is
//! compared against what the header already said: the two tiers, the grace
//! window, the coinbases still waiting to be spendable, what the chain has
//! issued, and the headers behind it. A handover that does not reproduce the
//! header is refused, and the header itself was accepted by the sampling that
//! came before.
//!
//! All of that ends at the header, and it is worth being exact about what
//! that buys. It says a lie had to be mined for the whole burial, not that a
//! lie is impossible: whoever did mine it chose the state root and everything
//! under it. So one check here does not go by that road. The issued total at a
//! height cannot exceed what the schedule has paid by then, because a coinbase
//! claims at most the schedule plus its own block's fees and an unclaimed fee
//! is destroyed. That is a subtraction against the rules rather than against
//! anybody's commitment, and no amount of work gets past it.

use std::collections::{BTreeSet, VecDeque};

use cairn_accumulator::forest::{Forest, ForestProof};
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::{Amount, Hash32};

use crate::block::{BlockHeader, HeaderSummary, BLOCK_VERSION};
use crate::note::{NetworkId, Note, NoteId};
use crate::pow::{median_time_past, meets_target, next_difficulty, work_of, RECENT_HEADERS};
use crate::state::{
    header_leaf, HotEntry, LedgerState, Maturing, Pieces, GRACE_BLOCKS, GRACE_NOTES,
};
use crate::validation::ConsensusParams;

/// Blocks a handed over ledger must sit below the tip it belongs to.
///
/// A newcomer cannot check a ledger. It has watched no transaction go past, so
/// what it is handed is only as good as the header that commits to it, and a
/// header's state root is a field its miner chose. Proof of work says that
/// somebody spent electricity on those bytes, not that the state in them is
/// what honest transactions would have produced. One block bought an arbitrary
/// ledger.
///
/// So no ledger is taken at the tip. It is taken from here, and the newcomer
/// applies the blocks in between itself, checking every rule as any node does.
/// A lie must therefore be this deep, and to be this deep while still being
/// the heaviest chain offered, its author had to out-mine everybody else for
/// as long as it took to build them. That is the assumption the chain already
/// rests on, which is the point: the arrival stops being the weak part.
///
/// The same as the deepest reorganisation a node accepts, so a newcomer lands
/// exactly where a node that was away and came back lands, with the same
/// ability to be moved off it by a heavier chain.
pub const BURIAL: u64 = 1_024;

pub use crate::state::Fallen;

/// A ledger as it stood at one header, and everything needed to check it.
#[derive(Clone, Debug)]
pub struct Handover {
    /// The header this ledger belongs to. Its commitments are what everything
    /// else is checked against.
    ///
    /// It is not the tip. A ledger is handed over from far enough below the
    /// tip that whoever made it had to keep mining for [`BURIAL`] blocks
    /// afterwards, which is the whole of what stops a stranger writing one.
    pub at: BlockHeader,
    /// The tip of the chain this ledger belongs to, which is the one the
    /// sampling weighed.
    ///
    /// A header says what state it commits to, and proof of work says only
    /// that somebody burned electricity on those bytes. It does not say the
    /// state is what honest transactions would have produced, and nothing a
    /// newcomer can check says so either: it has watched no transaction go
    /// past. So a tip on its own buys an arbitrary ledger for the price of one
    /// block, and the answer is not to check the tip harder but to refuse to
    /// take one at all.
    pub tip: BlockHeader,
    /// The header forest as it stood before that tip, roots only.
    ///
    /// Sixty four hashes, whatever the chain's age, and the tip commits to
    /// their hash, so a sender cannot offer a forest of its own choosing
    /// without having also made the tip.
    pub tip_history: Forest,
    /// That `at` sits where it says in that forest.
    ///
    /// This is what ties the ledger to the chain that was weighed. Without it
    /// a peer could weigh one chain and hand over the ledger of another.
    pub anchor: ForestProof,
    /// Every note in the hot set, with the height that decides when it falls.
    pub hot: Vec<(NoteId, HotEntry)>,
    /// The cold set as sixty four hashes.
    pub cold: Forest,
    /// What fell in each of the last few blocks, oldest first.
    pub grace: Vec<Vec<Fallen>>,
    /// A proof for every note in that window.
    ///
    /// Spending a note that fell moments ago takes no proof from the spender,
    /// because every node holds one for it. A node handed a ledger holds none
    /// unless it is handed those too, and it cannot work them out: they are
    /// paths through a set nobody keeps. Each one is checked against the cold
    /// commitment before it is kept, so a wrong one is refused here rather
    /// than believed and used later.
    ///
    /// Every note in the window has one, and that is a property of the window
    /// rather than of a sender's diligence: a note whose leaf was emptied by a
    /// spend leaves the window with it. It did not, and a handover made after
    /// any spend inside the window was refused by every receiver, which on a
    /// chain with traffic was every handover.
    pub grace_proofs: Vec<(u64, ForestProof)>,
    /// Coinbases whose notes are not spendable yet, oldest first.
    ///
    /// A newcomer cannot work these out. They are what the last thousand
    /// blocks paid, and it has none of those blocks. Without them it would
    /// start with an empty window and accept, until it had mined its way past
    /// the depth, spends the rest of the network refuses: the same fork with
    /// nobody at fault that the grace window was found to cause. The header
    /// commits to them, so a sender cannot choose them either.
    pub maturing: Vec<Maturing>,
    /// Every pebble the chain had issued at this header.
    ///
    /// Committed to like everything else here, which is what makes it worth
    /// having: a newcomer learns the supply from the header rather than by
    /// adding up a history it was not there for.
    ///
    /// And it is the one field weighed against the rules as well as against
    /// the commitment. The schedule says the most a chain can hold at a
    /// height, and no state root a miner writes can put a ledger above it.
    pub supply: Amount,
    /// The header forest as it stood before `at`, which `at` commits to.
    pub headers: Forest,
    /// Every header between the ledger's own and the tip, oldest first, the
    /// last of them being the tip itself.
    ///
    /// This is what ties the ledger to the chain that was weighed. The forest
    /// proof above says the ledger's header sits at a position in a forest,
    /// and the forest belongs to whoever made the tip, so on its own it says
    /// nothing: a forger swapped one leaf of the honest chain's forest for a
    /// header of a private chain it had mined for nothing, and handed over the
    /// ledger that went with it. Rebuilding the forest from this run catches
    /// that wherever the swap was, because the forest is append only and the
    /// receiver holds the part below the anchor already.
    ///
    /// It also makes the burial cost something. The run is checked block by
    /// block against the rules a node applies to any other block, so the
    /// sender no longer chooses those difficulties.
    ///
    /// About a hundred and eighty kilobytes at the burial depth, against a
    /// ledger of tens of megabytes and the blocks themselves, which the
    /// receiver is about to ask for anyway.
    pub buried: Vec<BlockHeader>,
    /// The last few headers in full, oldest first, ending at `at`.
    ///
    /// The difficulty rule and the timestamp rule both read these, so a node
    /// cannot check the next block without them. They come in full rather than
    /// as summaries because a summary cannot be checked against anything: an
    /// identifier is what the header forest holds.
    pub recent: Vec<BlockHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HandoverError {
    #[error("the header at {height} belongs to network {found:?}, this node follows {expected:?}")]
    WrongNetwork {
        height: u64,
        expected: NetworkId,
        found: NetworkId,
    },
    #[error("the header at {height} is dated {found}, before this network opened at {opens_at}")]
    BeforeTheNetworkOpened {
        height: u64,
        opens_at: u64,
        found: u64,
    },
    #[error("the header this ledger claims to belong to carries no work")]
    HeaderWithoutWork,
    #[error("the hot set holds {held} notes, more than the {limit} allowed")]
    HotSetTooLarge { held: usize, limit: usize },
    #[error("the hot set names note {0:?} twice")]
    DuplicateHotNote(NoteId),
    #[error("note {0:?} is named in the hot set and in the grace window at once")]
    NoteInBothTiers(NoteId),
    #[error("the grace window names cold position {position} twice")]
    GracePositionTwice { position: u64 },
    #[error("the maturity window holds {held} coinbases, more than the {limit} allowed")]
    MaturityWindowTooLarge { held: usize, limit: u64 },
    #[error(
        "the maturity window says a coinbase matures at {matures_at}, which a ledger at \
         height {height} under a maturity of {limit} could not hold"
    )]
    MaturityOutsideTheWindow {
        matures_at: u64,
        height: u64,
        limit: u64,
    },
    #[error(
        "this ledger holds {supply} at height {height}, and the schedule has paid at most \
         {ceiling} by then"
    )]
    SupplyAboveTheSchedule {
        height: u64,
        supply: Amount,
        ceiling: Amount,
    },
    #[error(
        "the tiers that arrive in full hold {held} at height {height}, and the ledger they \
         came with declares {ceiling} issued altogether"
    )]
    TiersAboveTheSchedule {
        height: u64,
        held: Amount,
        ceiling: Amount,
    },
    #[error("the grace window holds {held} blocks, more than the {limit} allowed")]
    GraceWindowTooLarge { held: usize, limit: usize },
    #[error("the grace window holds {held} notes, more than the {limit} allowed")]
    GraceWindowHoldsTooMuch { held: usize, limit: usize },
    #[error("the ledger rebuilt from this does not produce the header's state root")]
    StateRootMismatch,
    #[error("the headers handed over are not the ones the header commits to")]
    HistoryMismatch,
    #[error("the ledger sits at {at}, not far enough below the tip at {tip}")]
    NotBuried { at: u64, tip: u64 },
    #[error("the ledger's header does not sit on the chain that was weighed")]
    NotOnTheWeighedChain,
    #[error("the recent headers do not run up to the one this ledger belongs to")]
    RecentNotEndingAtTip,
    #[error("the recent headers are not consecutive")]
    RecentNotConsecutive,
    #[error("a recent header carries no work")]
    RecentWithoutWork,
    #[error("the work at {at} in the recent run does not add up")]
    RecentWorkDoesNotAddUp { at: u64 },
    #[error("too few recent headers: {given}, and a chain at height {height} has more")]
    TooFewRecent { given: usize, height: u64 },
    #[error("the proof for the note at {position} is not one the cold set gives")]
    BadGraceProof { position: u64 },
    #[error("the note at {position} is in the grace window with no proof for it")]
    MissingGraceProof { position: u64 },
    #[error(
        "{given} headers were handed over between the ledger and the tip, and {wanted} lie there"
    )]
    BuriedRunWrongLength { given: u64, wanted: u64 },
    #[error("the header at {at} does not follow the one below it")]
    BuriedRunNotConsecutive { at: u64 },
    #[error("the header at {at} carries no work")]
    BuriedWithoutWork { at: u64 },
    #[error("the header at {at} states difficulty {stated}, and the rules demand {demanded}")]
    BuriedAtTheWrongDifficulty { at: u64, stated: u64, demanded: u64 },
    #[error("the header at {at} is not later than the median of the window before it")]
    BuriedOutOfTime { at: u64 },
    #[error("the work stated at {at} is not the work below it plus its own")]
    BuriedWorkDoesNotAddUp { at: u64 },
    #[error("the headers handed over do not run up to the tip that was weighed")]
    BuriedRunNotEndingAtTheTip,
    #[error(
        "the rules at height {height} are block version {required}, and this build knows \
         only version {known}"
    )]
    SoftwareTooOld {
        height: u64,
        required: u16,
        known: u16,
    },
    #[error(
        "the header at height {height} carries version {found}, and the rules there \
         are block version {required}"
    )]
    WrongVersion {
        height: u64,
        found: u16,
        required: u16,
    },
}

impl LedgerState {
    /// Everything another node would need to hold this ledger.
    ///
    /// The last few headers come along because the difficulty rule and the
    /// timestamp rule read them, and a node that cannot check the next block
    /// has not really been handed anything.
    ///
    /// Every note in the window needs a path, because the far end refuses a
    /// ledger that arrives without one. This used to gather them with a
    /// `filter_map`, so a note with no path was quietly left out and the
    /// receiver reported [`HandoverError::MissingGraceProof`] about a ledger
    /// the sender believed it had sent whole. Nothing produces that state:
    /// what a spend empties, it also takes off the window, and a note is only
    /// let go of once the window has stopped wanting it. The refusal is
    /// reported here anyway, because a silence that depends on an invariant
    /// holding elsewhere is the shape of the thing this crate has already had
    /// to repair once.
    pub fn handover(
        &self,
        at: BlockHeader,
        tip: BlockHeader,
        tip_history: Forest,
        anchor: ForestProof,
        buried: Vec<BlockHeader>,
        recent: Vec<BlockHeader>,
    ) -> Result<Handover, HandoverError> {
        let grace = self.grace_window();
        let mut grace_proofs = Vec::new();
        for (_, position, _) in grace.iter().flatten() {
            let proof =
                self.cold()
                    .proof_of(*position)
                    .ok_or(HandoverError::MissingGraceProof {
                        position: *position,
                    })?;
            grace_proofs.push((*position, proof));
        }
        Ok(Handover {
            at,
            tip,
            tip_history,
            anchor,
            hot: self.hot_notes().collect(),
            cold: self.cold_roots(),
            grace,
            grace_proofs,
            maturing: self.maturing(),
            supply: self.supply(),
            headers: self.headers_before_tip(),
            buried,
            recent,
        })
    }
}

/// Checks the pieces of a handover against each other.
///
/// Everything else `accept` does ends at the header: each piece is rebuilt and
/// held against a commitment the work behind that header vouches for. That is
/// a strong argument with a shape, and the shape is that a sender who did
/// out-mine the network for the burial chose every one of those commitments
/// together. What such a sender cannot choose is agreement between them,
/// because the rules that produced a ledger leave the pieces consistent and
/// nothing about writing a state root does.
///
/// So this is where a piece is asked about its neighbour, and every defect of
/// that family found so far lives here: a hot set naming a note twice, a note
/// named in both tiers at once, and a hot set worth more than the total the
/// same message declares. The grace window's own places are checked in
/// `take_grace_proofs`, where the leaves are already in hand.
/// Whether the maturity window is one this chain could have produced.
///
/// Two questions, and for a long time only the first was asked. A window
/// longer than the maturity depth is not one this network ever made, which is
/// true; what it was standing in for is whether the heights inside it are ones
/// this window could hold.
///
/// They have to be, and the reason is in `advance_maturing`: it empties the
/// window from the front and stops at the first entry that has not matured,
/// because in a window a node built from its own blocks the heights only ever
/// rise. An entry that never matures therefore never leaves, and nothing
/// behind it leaves either.
///
/// What that costs a node that took one: the window and the index beside it
/// gain an entry a block for the life of the node, `compose_state_root` walks
/// the whole of it for every candidate block, and what the note on
/// `LedgerState::maturing` calls "constant like everything else a node holds"
/// grows with the chain. Measured at three thousand blocks: three thousand and
/// four entries, and twenty times the per-block cost of a node handed an
/// honest one, still climbing. The coinbase at the head also pays notes that
/// can never be spent, because nothing will reach the height it names. And
/// once the window is longer than the depth, the first check here refuses it
/// on the far side, so the node quietly stops being able to hand its ledger to
/// anybody, which is the one exchange this file exists for.
///
/// Asked before the state root is, so that it catches a sender who recomputed
/// one. That sender is the reachable case: out-mining the network for the
/// burial buys every commitment in a handover together, and what it does not
/// buy is agreement between them and the rules that would have made them.
fn the_window_this_chain_would_have(
    handover: &Handover,
    params: &ConsensusParams,
) -> Result<(), HandoverError> {
    // Against the rule this chain runs under rather than against the ceiling
    // the wire enforces: a window holding more than
    // the maturity depth is not a window this network ever produced.
    if u64::try_from(handover.maturing.len()).unwrap_or(u64::MAX) > params.coinbase_maturity {
        return Err(HandoverError::MaturityWindowTooLarge {
            held: handover.maturing.len(),
            limit: params.coinbase_maturity,
        });
    }
    // And every height in it has to be one this window could hold, which is
    // the question the length was standing in for.
    //
    // `advance_maturing` empties this window from the front and stops at the
    // first entry that has not matured, because in a window a node built from
    // its own blocks the heights only ever rise. An entry that never matures
    // therefore never leaves, and nothing behind it leaves either: the window
    // and the index beside it gain one entry a block for the life of the node,
    // `compose_state_root` walks the whole of it for every candidate block,
    // and what the note on `LedgerState::maturing` calls "constant like
    // everything else a node holds" grows with the chain. Measured at three
    // thousand blocks: three thousand and four entries, and twenty times the
    // per-block cost of a node that was handed an honest one.
    //
    // Two more things go with it. The coinbase at the head pays notes that can
    // never be spent, because nothing will ever reach the height it names. And
    // once the window is longer than the depth, this very check refuses it on
    // the far side, so the node stops being able to hand its ledger to anybody
    // — quietly, and it is the one exchange this file exists for.
    //
    // One comparison an entry, over at most `coinbase_maturity` of them, and
    // both numbers are already here. It belongs with the others in
    // `against_each_other`: a sender that out-mined the network for the burial
    // chose this window and the state root over it together, and what it could
    // not choose is whether the two agree with the rules that would have made
    // them.
    let ceiling = handover.at.height.saturating_add(params.coinbase_maturity);
    if let Some((matures_at, _)) = handover
        .maturing
        .iter()
        .find(|(matures_at, _)| *matures_at <= handover.at.height || *matures_at > ceiling)
    {
        return Err(HandoverError::MaturityOutsideTheWindow {
            matures_at: *matures_at,
            height: handover.at.height,
            limit: params.coinbase_maturity,
        });
    }
    Ok(())
}

fn against_each_other(handover: &Handover, declared: Amount) -> Result<(), HandoverError> {
    // Each note once, which the state root cannot ask. The hot set
    // is committed to as a tree keyed by note identifier, so a list naming a
    // note twice folds to exactly the root of the list naming it once: the
    // second entry rides in free, past every check a handover has, and the
    // root matches the header.
    //
    // What it buys is not a note but a place in the eviction order, which is
    // kept by age beside the tree and is the one structure a receiver builds
    // from the list rather than from the commitment. Two entries for one note
    // at two heights are two places there and one entry in the tree.
    //
    // Measured, with fifteen notes handed over and one of them named a second
    // time at another height. A release build took the ledger, took two
    // blocks, and refused the third for a state root it did not produce, and
    // every honest block after it for the same reason: its tier had stopped
    // being the tier the network was keeping. A debug build did not get that
    // far, because the first block applied trips the assertion that the two
    // structures are the same size, so a stranger offering a ledger could
    // stop any node built that way.
    //
    // The eviction order is also written in one place now rather than two,
    // which is what makes this a second line rather than the only one: see
    // `LedgerState::rebuilt`, which `accept` hands the pieces to below.
    //
    // This said `LedgerState::from_handover`, which has never existed under
    // that name in this repository. A cross reference to a function nobody can
    // find is worse than none: it reads as though the second line has been
    // checked, and the reader who goes looking concludes the note is stale and
    // stops trusting the paragraph rather than the name.
    let mut once = BTreeSet::new();
    for (id, _) in &handover.hot {
        if !once.insert(*id) {
            return Err(HandoverError::DuplicateHotNote(*id));
        }
    }
    // And never in the other tier as well, which is the same question asked
    // across two pieces instead of within one.
    //
    // "A note may be in one tier or the other and never in both or in neither"
    // is true of a ledger a node replayed, because eviction takes the note out
    // of the hot set on the way down, and `audit_two_tier_ceiling.rs` measures
    // it over a hundred and twenty blocks. A handed ledger is the second door
    // to the same state, and the hot list and the window arrive side by side,
    // each checked against the header and neither against the other. The state
    // root cannot ask it either: the two are separate commitments, and a note
    // named in both folds correctly into each.
    //
    // What it buys is the note twice. One block spends it out of the hot set,
    // which takes it out of that tier and leaves the window naming it, since
    // `advance_grace` lifts cold spends and not hot ones. The next block
    // offers the same identifier, `hot_note` answers nothing, `within_grace`
    // answers, and the path the handover itself supplied verifies. Measured
    // with a fifty CAIRN note at cold position 82: two payees, one note.
    //
    // Free, because the receiver holds both lists. The other pieces are
    // checked against each other for the same reason below.
    for fell in &handover.grace {
        for (id, _, _) in fell {
            if once.contains(id) {
                return Err(HandoverError::NoteInBothTiers(*id));
            }
        }
    }
    // The part of it a receiver can weigh for itself.
    //
    // A note whose value is on the wire is a note this node adds up rather
    // than takes, and a ledger holding more than the chain has ever issued is
    // one nobody could have replayed.
    //
    // Two of the four pieces are like that and the note here used to name
    // one. It said the hot set arrives in full and the cold set is sixty four
    // hashes, which is true of both and partitions a ledger into two when it
    // has more parts than that. The grace window travels note by note and
    // value by value, because a receiver cannot spend out of it otherwise, so
    // it is exactly as countable as the hot set and nothing was counting it.
    //
    // A handover declaring the lawful four thousand five hundred and fifty
    // CAIRN carried a note worth five hundred million in that window, was
    // accepted, and the note was spent on the next block with `Input::hot`
    // and no proof at all, because a note in the window is the one kind that
    // needs none from the spender.
    //
    // The cold set stays what the note said it was: sixty four hashes that
    // nobody can add up without holding the set, which is the one thing this
    // design exists so a node does not have to do.
    let mut in_hand = Amount::ZERO;
    let counted = handover
        .hot
        .iter()
        .map(|(_, entry)| entry.note.value)
        .chain(
            handover
                .grace
                .iter()
                .flatten()
                .map(|(_, _, note)| note.value),
        );
    for value in counted {
        in_hand = in_hand
            .checked_add(value)
            .ok_or(HandoverError::TiersAboveTheSchedule {
                height: handover.at.height,
                held: Amount::MAX_MONEY,
                ceiling: declared,
            })?;
    }
    if in_hand > declared {
        return Err(HandoverError::TiersAboveTheSchedule {
            height: handover.at.height,
            held: in_hand,
            ceiling: declared,
        });
    }
    Ok(())
}

/// Rebuilds a ledger from a handover, or says why it cannot be believed.
///
/// The header is the authority. Everything else is rebuilt and checked against
/// what the header already committed to, so a handover proves itself: there is
/// nothing to take on the word of whoever sent it.
pub fn accept(handover: &Handover, params: &ConsensusParams) -> Result<LedgerState, HandoverError> {
    let hot_capacity = params.hot_capacity;
    let burial = params.burial;
    let at = &handover.at;
    let tip = &handover.tip;
    // Which network these belong to, and whether they predate its opening.
    // Both are read off every block by `validation::check_header` and neither
    // was read here: see `sampling::belongs_to_this_network`, which is the
    // other half of the same gap and where the reasoning is written down. A
    // node taking a ledger has no chain of its own to compare against, so
    // these are the only two things it can ask that are about *which* chain
    // this is rather than about how much work is behind it.
    belongs_to_this_network(at, params)?;
    belongs_to_this_network(tip, params)?;
    if !meets_target(&at.id(), at.difficulty) || !meets_target(&tip.id(), tip.difficulty) {
        return Err(HandoverError::HeaderWithoutWork);
    }

    // Asked before anything else is looked at, because everything else is a
    // judgement made under rules this build may not have.
    //
    // Nothing on this path used to consider a version at all. A node whose
    // rules stop at some height took a ledger anchored above it, adopted it,
    // reported that height, and answered balances out of a chain it had no
    // rules for, while still saying it was up to date. It found out at the
    // next block and not before, and in the meantime a wallet showed a
    // checked-looking balance produced by rules the node could not check.
    //
    // The reverse matters more once a rule really does change: a newcomer one
    // release behind would refuse an honest handover for carrying the wrong
    // difficulty, which reads to whoever is watching as a peer having forged
    // it. Saying "I am too old" instead is the difference between a node that
    // waits to be updated and an operator hunting an attacker who is not
    // there.
    //
    // The anchor's own version is not evidence here, and reading it was worth
    // a node. This is the one verdict that stops one: `cairn-net` keeps it and
    // `cairn-node` prints it and exits, telling the operator to update. The
    // caller pins the tip, because a ledger has to name the header the
    // weighing settled on, so a claim made out of `tip` was earned. Nothing
    // pins `at` until the forest proof further down, so a claim made out of
    // `at` was a number the sender wrote: this network, a timestamp past its
    // opening, the difficulty floor where any identifier meets the target, and
    // one hash shut any node that asked for a ledger. The same inversion the
    // block path was mended for, arriving through the other door.
    //
    // Nothing honest is lost, because versions rise with height and the anchor
    // sits below the tip: an anchor above this build's ceiling while the tip
    // is not is a combination no chain produces. An anchor claiming one falls
    // to the version rule below and is the sender's doing, which it is.
    let required = params.version_at(tip.height);
    if required > BLOCK_VERSION || tip.version > BLOCK_VERSION {
        return Err(HandoverError::SoftwareTooOld {
            height: tip.height,
            required: required.max(tip.version),
            known: BLOCK_VERSION,
        });
    }

    // Above is the half that says this build cannot judge. This is the half
    // that judges: a block carries exactly the version the rules require where
    // it sits, so a header that carries anything else is a header no chain
    // accepted. Checking only that the version was not too high let a handover
    // arrive under a version below the schedule and be taken, while the very
    // same header offered as a block would have been refused. That gap is the
    // whole of what the schedule is for: it is how a rule change is announced,
    // and a header free to understate its version is a header free to ask to
    // be judged by the rules from before the change.
    for header in [at, tip] {
        let wanted = params.version_at(header.height);
        if header.version != wanted {
            return Err(HandoverError::WrongVersion {
                height: header.height,
                found: header.version,
                required: wanted,
            });
        }
    }

    // Deep enough that whoever wrote this ledger had to go on mining for a
    // thousand blocks over it, and be the heaviest chain the whole time. That
    // is what a newcomer gets instead of the ability to check the ledger
    // itself, which it has no way to do.
    if at.height.saturating_add(burial) > tip.height {
        return Err(HandoverError::NotBuried {
            at: at.height,
            tip: tip.height,
        });
    }

    // And it is that tip's own chain. The forest is the one the tip vouches
    // for, and the header this ledger belongs to sits in it at the height it
    // claims, so a peer cannot weigh one chain and hand over another's.
    if handover.tip_history.commitment() != tip.history {
        return Err(HandoverError::HistoryMismatch);
    }
    if !handover
        .tip_history
        .verify(at.height, header_leaf(&at.id()), &handover.anchor)
    {
        return Err(HandoverError::NotOnTheWeighedChain);
    }
    // Checked before anything is built, since the size of what follows is
    // otherwise decided by whoever sent it.
    if handover.hot.len() > hot_capacity {
        return Err(HandoverError::HotSetTooLarge {
            held: handover.hot.len(),
            limit: hot_capacity,
        });
    }
    against_each_other(handover, handover.supply)?;
    // And the same for the grace window, which had this only from the wire.
    // The decoder's ceiling is what a message carries; this is what the rules
    // produce, and the two are not the same question. A window holding more
    // blocks than the window keeps is not a window this network ever made.
    if handover.grace.len() > GRACE_BLOCKS {
        return Err(HandoverError::GraceWindowTooLarge {
            held: handover.grace.len(),
            limit: GRACE_BLOCKS,
        });
    }
    // Both halves of the rule, because the rule has two. `advance_grace` runs
    // the window down while it holds more blocks than `GRACE_BLOCKS` **or**
    // more notes than `GRACE_NOTES`, and this asked only the first. A window
    // of sixty four blocks carrying eight thousand seven hundred notes is not
    // one this network ever made, and it went past every size rule here to be
    // stopped by the state root rebuild at the end, after the window had been
    // built, indexed, and its every proof taken through `take_grace_proofs`.
    // Measured on a fixture: seven point seven milliseconds against the seven
    // point eight microseconds its three siblings take, which is the whole
    // reason those three are written before anything is built.
    //
    // `decode_grace` refuses this off the wire today, so nothing reaches here
    // that this stops. That is the decoder doing the rules' work: the other
    // wire ceilings in this file are deliberately generous, under a comment
    // saying the rules a chain runs under decide the real cap and `accept`
    // checks against that. This one is now checked against that.
    let notes: usize = handover.grace.iter().map(Vec::len).sum();
    if notes > GRACE_NOTES {
        return Err(HandoverError::GraceWindowHoldsTooMuch {
            held: notes,
            limit: GRACE_NOTES,
        });
    }
    the_window_this_chain_would_have(handover, params)?;

    // The one thing in a handover that follows from the rules rather than from
    // a commitment whoever sent it wrote.
    //
    // Everything else here is checked against the header, and the header is
    // checked against the work behind it. That is a strong argument and it has
    // a shape: it says a lie had to be mined, not that a lie is impossible. A
    // sender that did out-mine the network for the burial got to choose the
    // state root, and with it the hot set, the window and this number, and no
    // check that ends at the header can tell.
    //
    // This one does not end at the header. A coinbase claims at most what the
    // schedule pays plus the fees the block's own transfers gave up, and a fee
    // the coinbase declines is destroyed, so a chain at a height holds at most
    // what the schedule has paid by then and never more.
    //
    // What it bounds is this number, and the sentence here used to go one step
    // further than that: "A ledger that holds more was not produced by these
    // rules." The ledger and the number are two fields of one state root, and
    // a sender who mined the burial chooses both. Nothing compared them. So a
    // handover declaring the lawful four thousand five hundred and fifty CAIRN
    // could carry a note worth five hundred million, be accepted, and spend it
    // on the next block.
    //
    // Two of the pieces arrive in full, so what they hold can be added up and
    // held against this, and that is done in `against_each_other`. The hot
    // set is one and the grace window is the other: the window travels note
    // by note and value by value, because a receiver cannot spend out of it
    // otherwise. This note used to name the hot set alone and partition the
    // ledger into two when it has more parts than that, which is how the
    // same five hundred million went through the window instead.
    //
    // The cold set arrives as sixty four hashes and cannot be added up by
    // anyone, because adding it up would mean holding the set, which is the
    // one thing this design exists so a node does not have to do. That half
    // no check a receiver makes can close. What this number is, exactly, is a
    // ceiling on the issued total a handover may declare, and the pieces that
    // can be counted are held to it.
    //
    // Asked before the ledger is rebuilt, because it needs nothing but the
    // height and a number that arrived on the wire.
    let ceiling = params.emitted_by(at.height);
    if handover.supply > ceiling {
        return Err(HandoverError::SupplyAboveTheSchedule {
            height: at.height,
            supply: handover.supply,
            ceiling,
        });
    }
    if handover.headers.commitment() != at.history {
        return Err(HandoverError::HistoryMismatch);
    }

    check_recent(handover, params)?;
    check_buried(
        at,
        tip,
        &handover.headers,
        &handover.buried,
        &handover.recent,
        params,
    )?;

    let mut state = LedgerState::rebuilt(
        Pieces {
            hot: handover.hot.clone(),
            cold: handover.cold.clone(),
            grace: VecDeque::from(handover.grace.clone()),
            maturing: VecDeque::from(handover.maturing.clone()),
            supply: handover.supply,
            headers_before_tip: handover.headers.clone(),
            recent: summaries(&handover.recent),
        },
        at,
    );

    // The one check that covers the hot set, the cold set and the grace window
    // at once, because the header commits to all three together.
    if state.state_root() != at.state_root {
        return Err(HandoverError::StateRootMismatch);
    }

    // Proofs last, once the cold commitment they are checked against has been
    // vouched for by the header. A note in the window without one cannot be
    // spent the way the window exists to allow, so a missing proof is refused
    // rather than discovered later by whoever tries.
    state.take_grace_proofs(&handover.grace_proofs)?;
    Ok(state)
}

/// The same question `sampling::belongs_to_this_network` asks, in the errors
/// this exchange reports.
fn belongs_to_this_network(
    header: &BlockHeader,
    params: &ConsensusParams,
) -> Result<(), HandoverError> {
    if header.network != params.network {
        return Err(HandoverError::WrongNetwork {
            height: header.height,
            expected: params.network,
            found: header.network,
        });
    }
    if header.timestamp < params.opens_at {
        return Err(HandoverError::BeforeTheNetworkOpened {
            height: header.height,
            opens_at: params.opens_at,
            found: header.timestamp,
        });
    }
    Ok(())
}

/// Checks the run of recent headers hands over what it claims.
///
/// The run is the last [`RECENT_HEADERS`] headers of the chain, ending at the
/// anchor. It is what seeds the difficulty window the buried run above it is
/// then judged against, which is why what it is allowed to say matters more
/// than its own length suggests.
///
/// **Why it cannot be forged, which is not the same as why it is checked.**
/// Every field of a header is inside its identifier, and this walks the run
/// demanding that each names the one below it. So the run is the hash
/// ancestry of the anchor, and the anchor is pinned twice before this is
/// called: it has to verify in the tip's forest at its own height, and the
/// rebuild has to put the buried run back on top of it and come out at
/// `tip.history`. Changing one field of one header means finding a second
/// preimage. On the network path the tip is not the sender's either, since
/// `take_the_ledger` refuses a handover whose tip is not the one the sampling
/// weighed.
///
/// **So the version and the work below refuse nothing the chain would not
/// already refuse, and they are here anyway.** Bending either changes the
/// identifier the header above names, so the consecutive check catches the
/// same tamper; what these buy is which sentence comes back. "The work at 812
/// does not add up" is something somebody can act on, and "not consecutive" is
/// the same fact with the reason removed. They are written before the chain
/// check for that reason and no other, and both are free of any window.
///
/// The second thing they buy is that this run carries its own argument. A
/// guard that holds only because another guard covers it becomes wrong the day
/// the other one moves, and nothing says so. This run seeds the window the
/// burial above it is judged against, which makes it the wrong place to leave
/// an argument borrowed from the forest.
///
/// **What is not checked, and why not.** The median time past reads eleven
/// headers, so it is the chain's own rule from the eleventh entry on and is
/// *not* the rule below that: `median_time_past` silently shortens its window,
/// and a shortened median over timestamps that are not monotone can exceed the
/// full one and refuse an honest handover. It belongs here with a guard and a
/// measurement, not without them.
///
/// The difficulty is worse than circular. The retarget reads ninety gaps, so
/// judging a header needs ninety one below it, and the run carries ninety
/// below the anchor. `check_buried` escapes that by starting one above the
/// anchor, where the message does hold ninety one. No header inside this run
/// can be judged however long the run is made, because each one added is
/// itself unjudgeable; the anchor could be, at the price of carrying one more
/// header on the wire. Measured, that is worth 1.38 times the cost of a
/// burial, at most 1.90, and only against a sender free to choose the anchor,
/// which the network path does not allow. A wire format is not changed for
/// that.
fn check_recent(handover: &Handover, params: &ConsensusParams) -> Result<(), HandoverError> {
    let at = &handover.at;
    let Some(last) = handover.recent.last() else {
        return Err(HandoverError::RecentNotEndingAtTip);
    };
    if last.id() != at.id() {
        return Err(HandoverError::RecentNotEndingAtTip);
    }
    // A young chain has fewer than the window wants, and that is not a fault.
    let wanted = usize::try_from(at.height.saturating_add(1))
        .unwrap_or(RECENT_HEADERS)
        .min(RECENT_HEADERS);
    if handover.recent.len() < wanted {
        return Err(HandoverError::TooFewRecent {
            given: handover.recent.len(),
            height: at.height,
        });
    }

    let mut behind: Option<&BlockHeader> = None;
    for (index, header) in handover.recent.iter().enumerate() {
        belongs_to_this_network(header, params)?;

        // A header carries exactly the version the rules require where it
        // sits, so one carrying anything else is a header no chain accepted.
        //
        // Only that half. Whether this build can judge at all is settled once
        // at the top of `accept`, against the tip, and the tip is the highest
        // header a handover carries: a schedule rises in both height and
        // version, which the build asserts, so `version_at` cannot demand more
        // of a header in this run than it demands of the tip. An arm here for
        // `SoftwareTooOld` was written and taken out again, because it could
        // not fire — found by putting `>` for `<` and watching the suite stay
        // green.
        let wanted = params.version_at(header.height);
        if header.version != wanted {
            return Err(HandoverError::WrongVersion {
                height: header.height,
                found: header.version,
                required: wanted,
            });
        }

        if !meets_target(&header.id(), header.difficulty) {
            return Err(HandoverError::RecentWithoutWork);
        }

        // The work adds up across the run, which ties `at.total_work` to the
        // headers below it where `check_buried` ties it to the tip from above.
        // The first header has nothing behind it in the message, so it is the
        // one this cannot ask about.
        //
        // Before the consecutive check on purpose. Both catch the same tamper,
        // because changing a total changes the identifier the header above it
        // names, and the one that runs first is the one that gets to say what
        // was wrong. "The work at 812 does not add up" is a sentence somebody
        // can act on; "not consecutive" is the same fact with the reason taken
        // out.
        if let Some(behind) = behind {
            if header.total_work != behind.total_work.saturating_add(work_of(header.difficulty)) {
                return Err(HandoverError::RecentWorkDoesNotAddUp { at: header.height });
            }
        }

        // Consecutive, so the run really is the tail of one chain rather than
        // headers gathered from wherever they suited. Each one names what it
        // was built on, and the last one is the header the sampling accepted,
        // so following the chain back from there is enough: nothing else needs
        // proving about them.
        if let Some(next) = handover.recent.get(index.saturating_add(1)) {
            if next.height != header.height.saturating_add(1) || next.previous != header.id() {
                return Err(HandoverError::RecentNotConsecutive);
            }
        }

        behind = Some(header);
    }
    Ok(())
}

/// The most blocks a handover may claim between its ledger and the tip.
///
/// The run is normally exactly the burial depth, since that is where a node
/// takes its anchor from. The ceiling is here because the sender chooses the
/// length and the receiver has to walk it, so without one a peer could hand
/// over a run long enough to be an afternoon's work to check.
pub const MOST_BURIED: u64 = 4 * BURIAL;

/// Ties the ledger's own header to the tip the sampling weighed, by the chain
/// of headers that runs between them.
///
/// This is the check the design was missing, and missing it cost the whole
/// argument. A forest proof says a header sits at a position in a forest. It
/// does not say the forest is a chain, and the forest belongs to whoever made
/// the tip. So a forger took the honest chain's headers, swapped one leaf for
/// a header of a private chain it had mined for nothing, and mined a tip at
/// the difficulty floor: one hash. The displaced header and the anchor sat at
/// the same height and spanned the same unit of work, so no draw could tell
/// them apart, and the ledger handed over was one the forger had written for
/// itself, paying itself every coinbase there had ever been.
///
/// Two things close it, and the first is nearly free. The header forest is
/// append only, so a newcomer does not have to take a proof's word for where
/// the anchor sits: it holds the forest as it stood before the anchor, because
/// the anchor commits to it, and it can add the anchor and then every header
/// above it and see whether it arrives at the forest the tip commits to. Under
/// a swap it does not, and it does not matter where in the chain the swap was
/// or whether any draw would ever have looked there.
///
/// The second is that the run has to have been mined. Each header names the
/// one before it, carries the difficulty the retarget demands of it, states a
/// timestamp past the median of its window, and adds its own work to the
/// total. The window starts as the headers that come with the ledger and moves
/// forward with the run, so every step is judged by the same rule a node
/// applies to a block it is handed. That is what makes the burial cost
/// something: before this, the sender chose those difficulties and could set
/// them all to the floor, so a thousand blocks of burial were a thousand
/// hashes and the phrase "buried a thousand deep" bought nothing at all.
///
/// What comes out of it is the anchor's own total work, which used to be a
/// number the sender wrote down and nobody read. It is now the tip's total
/// work, which the sampling established, less the work of a run that was
/// checked block by block.
pub fn check_buried(
    at: &BlockHeader,
    tip: &BlockHeader,
    before_at: &Forest,
    buried: &[BlockHeader],
    recent: &[BlockHeader],
    params: &ConsensusParams,
) -> Result<(), HandoverError> {
    let Some(claimed) = tip.height.checked_sub(at.height) else {
        return Err(HandoverError::NotBuried {
            at: at.height,
            tip: tip.height,
        });
    };
    let given = u64::try_from(buried.len()).unwrap_or(u64::MAX);
    if given != claimed || claimed > MOST_BURIED {
        return Err(HandoverError::BuriedRunWrongLength {
            given,
            wanted: claimed,
        });
    }

    // The forest the anchor commits to, which the caller has already checked
    // against `at.history`, plus the anchor itself. Everything above is added
    // as it is checked, and what comes out has to be the tip's own.
    let mut forest = before_at.clone();
    forest.add(header_leaf(&at.id()));

    let mut window = summaries(recent);
    let mut previous = *at;
    for header in buried {
        belongs_to_this_network(header, params)?;
        if header.height != previous.height.saturating_add(1) || header.previous != previous.id() {
            return Err(HandoverError::BuriedRunNotConsecutive { at: header.height });
        }
        if !meets_target(&header.id(), header.difficulty) {
            return Err(HandoverError::BuriedWithoutWork { at: header.height });
        }

        // Each of these is a block, so each carries exactly the version the
        // rules require where it sits. Left unchecked, the one run of headers
        // a newcomer verifies for itself was the one place a chain could be
        // built out of blocks that never had to name the rules they were mined
        // under, which is what the whole run exists to establish.
        let wanted = params.version_at(header.height);
        if wanted > BLOCK_VERSION {
            return Err(HandoverError::SoftwareTooOld {
                height: header.height,
                required: wanted,
                known: BLOCK_VERSION,
            });
        }
        if header.version != wanted {
            return Err(HandoverError::WrongVersion {
                height: header.height,
                found: header.version,
                required: wanted,
            });
        }
        let demanded = next_difficulty(&window, params.target_block_time);
        if header.difficulty != demanded {
            return Err(HandoverError::BuriedAtTheWrongDifficulty {
                at: header.height,
                stated: header.difficulty,
                demanded,
            });
        }
        if median_time_past(&window).is_some_and(|median| header.timestamp <= median) {
            return Err(HandoverError::BuriedOutOfTime { at: header.height });
        }
        if header.total_work
            != previous
                .total_work
                .saturating_add(work_of(header.difficulty))
        {
            return Err(HandoverError::BuriedWorkDoesNotAddUp { at: header.height });
        }

        // The tip is not in its own history, so its leaf is the one leaf the
        // rebuilt forest must not have.
        if header.height < tip.height {
            forest.add(header_leaf(&header.id()));
        }
        window.push(HeaderSummary {
            height: header.height,
            timestamp: header.timestamp,
            difficulty: header.difficulty,
        });
        if window.len() > RECENT_HEADERS {
            window.remove(0);
        }
        previous = *header;
    }

    if previous.id() != tip.id() {
        return Err(HandoverError::BuriedRunNotEndingAtTheTip);
    }
    // The forest the tip commits to is the one this run just rebuilt, leaf by
    // leaf, from the anchor's own. Nothing was swapped anywhere below it.
    if forest.commitment() != tip.history {
        return Err(HandoverError::NotOnTheWeighedChain);
    }
    Ok(())
}

/// What the difficulty and timestamp rules read, out of headers in full.
fn summaries(headers: &[BlockHeader]) -> Vec<HeaderSummary> {
    headers
        .iter()
        .map(|header| HeaderSummary {
            height: header.height,
            timestamp: header.timestamp,
            difficulty: header.difficulty,
        })
        .collect()
}

impl Encode for Handover {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.at.encode_to(out);
        self.tip.encode_to(out);
        self.tip_history.encode_to(out);
        self.anchor.encode_to(out);
        self.cold.encode_to(out);
        self.headers.encode_to(out);

        u32::try_from(self.hot.len())
            .unwrap_or(u32::MAX)
            .encode_to(out);
        for (id, entry) in &self.hot {
            id.encode_to(out);
            entry.note.encode_to(out);
            entry.height.encode_to(out);
        }

        u32::try_from(self.grace.len())
            .unwrap_or(u32::MAX)
            .encode_to(out);
        for block in &self.grace {
            u32::try_from(block.len())
                .unwrap_or(u32::MAX)
                .encode_to(out);
            for (id, position, note) in block {
                id.encode_to(out);
                position.encode_to(out);
                note.encode_to(out);
            }
        }

        u32::try_from(self.grace_proofs.len())
            .unwrap_or(u32::MAX)
            .encode_to(out);
        for (position, proof) in &self.grace_proofs {
            position.encode_to(out);
            proof.encode_to(out);
        }

        u32::try_from(self.maturing.len())
            .unwrap_or(u32::MAX)
            .encode_to(out);
        for (matures_at, coinbase) in &self.maturing {
            matures_at.encode_to(out);
            coinbase.encode_to(out);
        }
        self.supply.encode_to(out);

        u32::try_from(self.recent.len())
            .unwrap_or(u32::MAX)
            .encode_to(out);
        for header in &self.recent {
            header.encode_to(out);
        }

        u32::try_from(self.buried.len())
            .unwrap_or(u32::MAX)
            .encode_to(out);
        for header in &self.buried {
            header.encode_to(out);
        }
    }
}

impl Decode for Handover {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let at = BlockHeader::decode_from(reader)?;
        let tip = BlockHeader::decode_from(reader)?;
        let tip_history = Forest::decode_from(reader)?;
        let anchor = ForestProof::decode_from(reader)?;
        let cold = Forest::decode_from(reader)?;
        let headers = Forest::decode_from(reader)?;

        // Every count is checked before anything is reserved for it, because
        // all of them are chosen by whoever sent this.
        let hot = decode_hot(reader)?;
        let grace = decode_grace(reader)?;
        let grace_proofs = decode_proofs(reader)?;
        let maturing = decode_maturing(reader)?;
        let supply = Amount::decode_from(reader)?;
        let recent = decode_recent(reader)?;
        let buried = decode_buried(reader)?;

        Ok(Self {
            at,
            tip,
            tip_history,
            anchor,
            hot,
            cold,
            grace,
            grace_proofs,
            maturing,
            supply,
            headers,
            buried,
            recent,
        })
    }
}

/// The most coinbases a maturity window may hold on any network this code
/// knows.
///
/// The rules a chain runs under decide the real depth, and `accept` checks
/// against that. This is the ceiling on what will be read off a wire at all,
/// so a sender cannot make a reader reserve for a window no network allows.
pub const MAX_MATURING: usize = 1 << 16;

fn decode_maturing(reader: &mut Reader<'_>) -> Result<Vec<Maturing>, CodecError> {
    let count = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
    if count > MAX_MATURING {
        return Err(CodecError::InvalidValue {
            type_name: "Handover maturity window",
        });
    }
    let mut maturing = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let matures_at = u64::decode_from(reader)?;
        let coinbase = Hash32::decode_from(reader)?;
        maturing.push((matures_at, coinbase));
    }
    Ok(maturing)
}

/// Reads the run between the ledger and the tip, refusing a length no chain
/// asks for before a byte of it is reserved.
fn decode_buried(reader: &mut Reader<'_>) -> Result<Vec<BlockHeader>, CodecError> {
    let count = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
    if u64::try_from(count).unwrap_or(u64::MAX) > MOST_BURIED {
        return Err(CodecError::InvalidValue {
            type_name: "Handover buried run",
        });
    }
    let mut buried = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        buried.push(BlockHeader::decode_from(reader)?);
    }
    Ok(buried)
}

/// The most notes a hot set may hold on any network this code knows.
///
/// The rules a chain runs under decide the real cap, and `accept` checks
/// against that. This is the ceiling on what will be read off a wire at all,
/// so a sender cannot make a reader reserve for a hot set no network allows.
pub const MAX_HOT: usize = 1 << 20;

fn decode_hot(reader: &mut Reader<'_>) -> Result<Vec<(NoteId, HotEntry)>, CodecError> {
    let count = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
    if count > MAX_HOT {
        return Err(CodecError::InvalidValue {
            type_name: "Handover hot set",
        });
    }
    let mut hot = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let id = NoteId::decode_from(reader)?;
        let note = Note::decode_from(reader)?;
        let height = u64::decode_from(reader)?;
        hot.push((id, HotEntry { note, height }));
    }
    Ok(hot)
}

fn decode_grace(reader: &mut Reader<'_>) -> Result<Vec<Vec<Fallen>>, CodecError> {
    let blocks = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
    if blocks > GRACE_BLOCKS {
        return Err(CodecError::InvalidValue {
            type_name: "Handover grace window",
        });
    }
    let mut grace = Vec::with_capacity(blocks.min(GRACE_BLOCKS));
    let mut held = 0usize;
    for _ in 0..blocks {
        let count = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
        held = held.saturating_add(count);
        if held > GRACE_NOTES {
            return Err(CodecError::InvalidValue {
                type_name: "Handover grace window",
            });
        }
        let mut block = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let id = NoteId::decode_from(reader)?;
            let position = u64::decode_from(reader)?;
            let note = Note::decode_from(reader)?;
            block.push((id, position, note));
        }
        grace.push(block);
    }
    Ok(grace)
}

fn decode_proofs(reader: &mut Reader<'_>) -> Result<Vec<(u64, ForestProof)>, CodecError> {
    let count = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
    if count > GRACE_NOTES {
        return Err(CodecError::InvalidValue {
            type_name: "Handover grace proofs",
        });
    }
    let mut proofs = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let position = u64::decode_from(reader)?;
        let proof = ForestProof::decode_from(reader)?;
        proofs.push((position, proof));
    }
    Ok(proofs)
}

fn decode_recent(reader: &mut Reader<'_>) -> Result<Vec<BlockHeader>, CodecError> {
    let count = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
    if count > RECENT_HEADERS {
        return Err(CodecError::InvalidValue {
            type_name: "Handover recent headers",
        });
    }
    let mut recent = Vec::with_capacity(count.min(RECENT_HEADERS));
    for _ in 0..count {
        recent.push(BlockHeader::decode_from(reader)?);
    }
    Ok(recent)
}

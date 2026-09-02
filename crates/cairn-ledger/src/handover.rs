//! Handing a ledger to a node that does not have one.
//!
//! Once a newcomer has settled which chain is heaviest, it still cannot check
//! a single transaction: knowing what work stands behind a tip says nothing
//! about who owns what. It needs the ledger at that tip, and this is how it
//! gets one without replaying the chain that produced it.
//!
//! What makes that possible here and not elsewhere is that the ledger is
//! bounded. A chain that grows for thirty years still holds the same hundred
//! and seven megabytes, because everything older lives in a commitment rather
//! than in a table. So it can be sent whole, once, and checked against the
//! header that commits to it.
//!
//! Nothing here is taken on trust. Every piece is rebuilt and the result is
//! compared against what the header already said: the two tiers, the grace
//! window, the coinbases still waiting to be spendable, what the chain has
//! issued, and the headers behind it. A handover that does not reproduce the
//! header is refused, and the header itself was accepted by the sampling that
//! came before.

use std::collections::VecDeque;

use cairn_accumulator::forest::{Forest, ForestProof};
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::{Amount, Hash32};

use crate::block::{BlockHeader, HeaderSummary, BLOCK_VERSION};
use crate::note::{Note, NoteId};
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
    #[error("the header this ledger claims to belong to carries no work")]
    HeaderWithoutWork,
    #[error("the hot set holds {held} notes, more than the {limit} allowed")]
    HotSetTooLarge { held: usize, limit: usize },
    #[error("the maturity window holds {held} coinbases, more than the {limit} allowed")]
    MaturityWindowTooLarge { held: usize, limit: u64 },
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
    let required = params.version_at(tip.height);
    if required > BLOCK_VERSION || tip.version > BLOCK_VERSION || at.version > BLOCK_VERSION {
        return Err(HandoverError::SoftwareTooOld {
            height: tip.height,
            required: required.max(tip.version).max(at.version),
            known: BLOCK_VERSION,
        });
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
    // For the same reason, and against the rule this chain runs under rather
    // than against the ceiling the wire enforces: a window holding more than
    // the maturity depth is not a window this network ever produced.
    if u64::try_from(handover.maturing.len()).unwrap_or(u64::MAX) > params.coinbase_maturity {
        return Err(HandoverError::MaturityWindowTooLarge {
            held: handover.maturing.len(),
            limit: params.coinbase_maturity,
        });
    }
    if handover.headers.commitment() != at.history {
        return Err(HandoverError::HistoryMismatch);
    }

    check_recent(handover)?;
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

/// Checks the run of recent headers hands over what it claims.
fn check_recent(handover: &Handover) -> Result<(), HandoverError> {
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

    for (index, header) in handover.recent.iter().enumerate() {
        if !meets_target(&header.id(), header.difficulty) {
            return Err(HandoverError::RecentWithoutWork);
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
        if header.height != previous.height.saturating_add(1) || header.previous != previous.id() {
            return Err(HandoverError::BuriedRunNotConsecutive { at: header.height });
        }
        if !meets_target(&header.id(), header.difficulty) {
            return Err(HandoverError::BuriedWithoutWork { at: header.height });
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
const MAX_MATURING: usize = 1 << 16;

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
const MAX_HOT: usize = 1 << 20;

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

/// The identifier of the header a handover belongs to.
#[must_use]
pub fn belongs_to(handover: &Handover) -> Hash32 {
    handover.at.id()
}

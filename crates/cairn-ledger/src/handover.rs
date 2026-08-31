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
//! window, and the headers behind it. A handover that does not reproduce the
//! header is refused, and the header itself was accepted by the sampling that
//! came before.

use std::collections::VecDeque;

use cairn_accumulator::forest::{Forest, ForestProof};
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::Hash32;

use crate::block::{BlockHeader, HeaderSummary};
use crate::note::{Note, NoteId};
use crate::pow::{meets_target, RECENT_HEADERS};
use crate::state::{HotEntry, LedgerState, GRACE_BLOCKS, GRACE_NOTES};

/// What fell in one block: the note, where it landed, and what it was.
pub type Fallen = (NoteId, u64, Note);

/// A ledger as it stood at one header, and everything needed to check it.
#[derive(Clone, Debug)]
pub struct Handover {
    /// The header this ledger belongs to. Its commitments are what everything
    /// else is checked against, so a handover is only as good as the header it
    /// names, and that header is what the sampling settled.
    pub at: BlockHeader,
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
    pub grace_proofs: Vec<(u64, ForestProof)>,
    /// The header forest as it stood before `at`, which `at` commits to.
    pub headers: Forest,
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
    #[error("the ledger rebuilt from this does not produce the header's state root")]
    StateRootMismatch,
    #[error("the headers handed over are not the ones the header commits to")]
    HistoryMismatch,
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
}

impl LedgerState {
    /// Everything another node would need to hold this ledger.
    ///
    /// The last few headers come along because the difficulty rule and the
    /// timestamp rule read them, and a node that cannot check the next block
    /// has not really been handed anything.
    #[must_use]
    pub fn handover(&self, at: BlockHeader, recent: Vec<BlockHeader>) -> Handover {
        let grace = self.grace_window();
        let grace_proofs = grace
            .iter()
            .flatten()
            .filter_map(|(_, position, _)| Some((*position, self.cold().proof_of(*position)?)))
            .collect();
        Handover {
            at,
            hot: self.hot_notes().collect(),
            cold: self.cold_roots(),
            grace,
            grace_proofs,
            headers: self.headers_before_tip(),
            recent,
        }
    }
}

/// Rebuilds a ledger from a handover, or says why it cannot be believed.
///
/// The header is the authority. Everything else is rebuilt and checked against
/// what the header already committed to, so a handover proves itself: there is
/// nothing to take on the word of whoever sent it.
pub fn accept(handover: &Handover, hot_capacity: usize) -> Result<LedgerState, HandoverError> {
    let at = &handover.at;
    if !meets_target(&at.id(), at.difficulty) {
        return Err(HandoverError::HeaderWithoutWork);
    }
    // Checked before anything is built, since the size of what follows is
    // otherwise decided by whoever sent it.
    if handover.hot.len() > hot_capacity {
        return Err(HandoverError::HotSetTooLarge {
            held: handover.hot.len(),
            limit: hot_capacity,
        });
    }
    if handover.headers.commitment() != at.history {
        return Err(HandoverError::HistoryMismatch);
    }

    check_recent(handover)?;

    let mut state = LedgerState::rebuilt(
        handover.hot.clone(),
        handover.cold.clone(),
        VecDeque::from(handover.grace.clone()),
        handover.headers.clone(),
        summaries(&handover.recent),
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

        u32::try_from(self.recent.len())
            .unwrap_or(u32::MAX)
            .encode_to(out);
        for header in &self.recent {
            header.encode_to(out);
        }
    }
}

impl Decode for Handover {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let at = BlockHeader::decode_from(reader)?;
        let cold = Forest::decode_from(reader)?;
        let headers = Forest::decode_from(reader)?;

        // Every count is checked before anything is reserved for it, because
        // all of them are chosen by whoever sent this.
        let hot = decode_hot(reader)?;
        let grace = decode_grace(reader)?;
        let grace_proofs = decode_proofs(reader)?;
        let recent = decode_recent(reader)?;

        Ok(Self {
            at,
            hot,
            cold,
            grace,
            grace_proofs,
            headers,
            recent,
        })
    }
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

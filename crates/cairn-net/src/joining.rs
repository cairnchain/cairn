//! Collecting a join answer, piece by piece.
//!
//! Both halves of joining a chain are larger than one message carries, so they
//! arrive cut up and have to be put back together. Nothing about the labels on
//! the pieces is believed: what settles whether they belong together is that
//! the whole they make checks out against the header it names, and that header
//! against the work behind it.
//!
//! What this holds is one collection at a time. A node joins once, and a
//! second attempt starting while the first is unfinished is the first one
//! having failed, so it replaces it rather than running beside it.

use cairn_ledger::block::BlockHeader;
use cairn_primitives::Hash32;

use crate::message::{Joining, MAX_JOIN_PARTS};

/// Bytes a collection may reach before it is abandoned.
///
/// A ledger at the largest hot set the rules allow is eleven megabytes, and a
/// sampled weight is one. This is several times either, and it is here so that
/// a peer sending pieces that never complete anything cannot make a node hold
/// more and more of them.
pub const MAX_JOIN_BYTES: usize = 48 * 1024 * 1024;

/// Pieces of one answer, as they arrive.
#[derive(Clone, Debug)]
pub struct Collecting {
    /// What is being collected.
    pub what: Joining,
    /// The tip every piece has to name, taken from the first one to arrive.
    ///
    /// A node that mines a block partway through an exchange starts answering
    /// about a different ledger. The pieces would not go together, and this is
    /// what notices rather than finding out at the end.
    pub at: Hash32,
    /// How many pieces the answer takes, from the first one to arrive.
    pub parts: u32,
    /// The pieces held so far, in order, with gaps as `None`.
    pieces: Vec<Option<Vec<u8>>>,
}

impl Collecting {
    /// Starts a collection from the first piece to arrive.
    ///
    /// `None` when the piece is not one anything could be built from, which
    /// costs the sender the exchange rather than costing this node memory.
    #[must_use]
    pub fn started(
        what: Joining,
        at: Hash32,
        part: u32,
        parts: u32,
        bytes: Vec<u8>,
    ) -> Option<Self> {
        if parts == 0 || parts > MAX_JOIN_PARTS || part >= parts {
            return None;
        }
        let mut pieces = vec![None; usize::try_from(parts).ok()?];
        *pieces.get_mut(usize::try_from(part).ok()?)? = Some(bytes);
        Some(Self {
            what,
            at,
            parts,
            pieces,
        })
    }

    /// Takes a piece, saying whether it belonged to this collection.
    pub fn take(&mut self, what: Joining, at: Hash32, part: u32, bytes: Vec<u8>) -> bool {
        if what != self.what || at != self.at || part >= self.parts {
            return false;
        }
        let Ok(index) = usize::try_from(part) else {
            return false;
        };
        let Some(slot) = self.pieces.get_mut(index) else {
            return false;
        };
        // A piece that arrives twice is not an error and not worth a second
        // copy: a node asks again for what it thinks is missing, and an answer
        // in flight can cross the question.
        if slot.is_none() {
            *slot = Some(bytes);
        }
        self.held() <= MAX_JOIN_BYTES
    }

    /// The next piece this collection is missing, or `None` when it is whole.
    #[must_use]
    pub fn wanted(&self) -> Option<u32> {
        self.pieces
            .iter()
            .position(Option::is_none)
            .and_then(|index| u32::try_from(index).ok())
    }

    /// Bytes held across every piece so far.
    #[must_use]
    pub fn held(&self) -> usize {
        self.pieces
            .iter()
            .flatten()
            .map(Vec::len)
            .fold(0usize, usize::saturating_add)
    }

    /// The whole answer, once nothing is missing.
    #[must_use]
    pub fn whole(&self) -> Option<Vec<u8>> {
        if self.wanted().is_some() {
            return None;
        }
        let mut out = Vec::with_capacity(self.held());
        for piece in self.pieces.iter().flatten() {
            out.extend_from_slice(piece);
        }
        Some(out)
    }
}

/// How far a node is through joining a chain it was not on.
#[derive(Clone, Debug, Default)]
pub enum Progress {
    /// Nothing asked for yet.
    #[default]
    Idle,
    /// Collecting the headers that say what work stands behind a tip.
    Weighing(Collecting),
    /// That settled. Waiting on the first piece of the ledger, which is what
    /// says how many pieces there are.
    ///
    /// The tip is held because the ledger has to be the one belonging to the
    /// chain just weighed. A peer that weighed one chain and handed over the
    /// ledger of another would otherwise be believed.
    Weighed { tip: BlockHeader },
    /// Collecting that ledger.
    Fetching {
        tip: BlockHeader,
        collecting: Collecting,
    },
    /// Done, and the ledger is in the chain.
    Landed,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn tip() -> Hash32 {
        Hash32::from_bytes([7; 32])
    }

    #[test]
    fn pieces_go_back_together_in_order() {
        let mut collecting =
            Collecting::started(Joining::Ledger, tip(), 0, 3, b"one".to_vec()).unwrap();
        assert_eq!(collecting.wanted(), Some(1));
        assert!(collecting.whole().is_none());

        // Out of order, which is what a network does.
        assert!(collecting.take(Joining::Ledger, tip(), 2, b"three".to_vec()));
        assert_eq!(collecting.wanted(), Some(1));
        assert!(collecting.take(Joining::Ledger, tip(), 1, b"two".to_vec()));

        assert_eq!(collecting.wanted(), None);
        assert_eq!(collecting.whole().unwrap(), b"onetwothree".to_vec());
    }

    /// A node that mined a block partway through is answering about a different
    /// ledger, and its pieces do not belong with the ones already held.
    #[test]
    fn a_piece_about_another_tip_is_not_taken() {
        let mut collecting =
            Collecting::started(Joining::Ledger, tip(), 0, 2, b"one".to_vec()).unwrap();

        let other = Hash32::from_bytes([9; 32]);
        assert!(!collecting.take(Joining::Ledger, other, 1, b"two".to_vec()));
        assert!(!collecting.take(Joining::Weight, tip(), 1, b"two".to_vec()));
        assert_eq!(collecting.wanted(), Some(1), "and nothing was kept");
    }

    /// An answer in flight can cross the question asking for it again.
    #[test]
    fn a_piece_that_arrives_twice_is_not_held_twice() {
        let mut collecting =
            Collecting::started(Joining::Ledger, tip(), 0, 2, b"one".to_vec()).unwrap();
        assert!(collecting.take(Joining::Ledger, tip(), 1, b"two".to_vec()));
        assert!(collecting.take(Joining::Ledger, tip(), 1, b"again".to_vec()));
        assert_eq!(collecting.whole().unwrap(), b"onetwo".to_vec());
    }

    #[test]
    fn a_first_piece_that_makes_no_sense_starts_nothing() {
        assert!(Collecting::started(Joining::Ledger, tip(), 0, 0, Vec::new()).is_none());
        assert!(Collecting::started(Joining::Ledger, tip(), 3, 2, Vec::new()).is_none());
        assert!(
            Collecting::started(Joining::Ledger, tip(), 0, MAX_JOIN_PARTS + 1, Vec::new())
                .is_none()
        );
    }

    /// Pieces that never complete anything must not accumulate for ever.
    #[test]
    fn a_collection_that_grows_past_its_ceiling_is_refused() {
        let mut collecting =
            Collecting::started(Joining::Ledger, tip(), 0, 4, vec![0; MAX_JOIN_BYTES / 3]).unwrap();
        assert!(collecting.take(Joining::Ledger, tip(), 1, vec![0; MAX_JOIN_BYTES / 3]));
        assert!(
            !collecting.take(Joining::Ledger, tip(), 2, vec![0; MAX_JOIN_BYTES / 2]),
            "past the ceiling, so the exchange is given up rather than grown"
        );
    }
}

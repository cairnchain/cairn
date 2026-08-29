//! Joining a chain from a sample of its headers.
//!
//! A newcomer has to answer one question before it can do anything else: of
//! the chains being offered to it, which one has the most work behind it? The
//! obvious way is to download them all and add up, which is the cost this whole
//! design exists to avoid: at thirty years that is tens of gigabytes to answer
//! a question about one number.
//!
//! What is done instead is what `FlyClient` does (Bünz, Kiffer, Luu, Zamani,
//! IEEE S&P 2020). Every header commits to the work behind the whole chain and
//! to every header before it, so a prover can be asked to open a few of those
//! headers at positions it cannot predict. A chain whose stated work was never
//! done has to lie about some of its headers, and the positions are drawn so
//! that a lie large enough to matter is almost certain to be opened.
//!
//! Two things make the questions unanswerable in advance. The positions come
//! from hashing the tip, so choosing them means redoing the tip's work. And
//! they are drawn against work rather than height, so a chain claiming work it
//! did not do is asked about the part it claimed.
//!
//! What this settles is which chain is heaviest, and nothing else. A newcomer
//! that has settled it still needs the ledger at that tip before it can check
//! a transaction, and that is a separate exchange: the ledger is bounded and
//! every header commits to it, so it arrives whole and is checked against the
//! header this sampling just accepted.

use cairn_accumulator::forest::{Forest, ForestProof};
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Hash32;

use crate::block::BlockHeader;
use crate::pow::{meets_target, work_of};
use crate::state::header_leaf;

/// Headers opened when a newcomer is deciding between chains.
///
/// Measured rather than argued: `cargo run --release -p cairn-ledger --example
/// sampled_start` forges chains that overstate their work by a given share and
/// counts how often this many draws catch one. The number here is where that
/// measurement stops finding a forgery it misses.
pub const SAMPLES: usize = 128;

/// Halvings of the remaining work the draw spreads its samples over.
///
/// The distribution has to be denser towards the tip, because that is where an
/// adversary who cannot afford real work has to put the lie: everything behind
/// a fork is honest history it did not make. Sampling by repeated halving is
/// that density written in whole numbers. The top half of the work gets as many
/// draws as the quarter below it, and so on down, which is a density
/// proportional to one over the distance from the tip, the distribution
/// `FlyClient` proves its bound for.
///
/// Forty levels reaches a millionth of a millionth of the work, far past any
/// chain that will exist.
const LEVELS: u32 = 40;

/// One header a prover opened, and the proof that it sits where it says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub header: BlockHeader,
    pub proof: ForestProof,
}

/// Everything a newcomer is handed to decide what stands behind a tip.
#[derive(Clone, Debug)]
pub struct SampledStart {
    /// The header everything else is measured against.
    pub tip: BlockHeader,
    /// The header forest as it stood before the tip, roots only.
    ///
    /// Sixty four hashes, whatever the chain's age. The tip commits to their
    /// hash, so a prover cannot hand over a forest of its own choosing without
    /// having also made the tip.
    pub history: Forest,
    /// One header per drawn position, in the order they were drawn.
    pub samples: Vec<Sample>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StartError {
    #[error("the tip carries no work")]
    TipWithoutWork,
    #[error("the tip claims no work at all")]
    TipClaimsNothing,
    #[error("the history handed over is not the one the tip commits to")]
    HistoryMismatch,
    #[error("the history holds {held} headers, the tip sits at height {height}")]
    HistoryWrongLength { held: u64, height: u64 },
    #[error("expected {wanted} samples, got {given}")]
    WrongCount { wanted: usize, given: usize },
    #[error("the header opened at draw {index} carries no work")]
    SampleWithoutWork { index: usize },
    #[error("the header opened at draw {index} is not in the tip's history")]
    NotInHistory { index: usize },
    #[error("the header opened at draw {index} does not cover the work drawn")]
    WrongPlace { index: usize },
    #[error("the header opened at draw {index} states more work than the tip")]
    PastTheTip { index: usize },
}

/// What a chain is worth, once its sampling has been checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Weighed {
    pub tip: Hash32,
    pub height: u64,
    pub total_work: u128,
}

/// The work standing behind a header, not counting its own.
#[must_use]
pub fn work_before(header: &BlockHeader) -> u128 {
    header.total_work.saturating_sub(work_of(header.difficulty))
}

/// The seed the draw comes from.
///
/// The tip's own identifier, which a prover can only choose by finding another
/// tip, and finding a tip costs the work the tip states. This is Fiat-Shamir:
/// the questions are settled by the thing being questioned, so nobody has to
/// be trusted to ask them honestly and no round trip is needed to agree on
/// them.
#[must_use]
pub fn seed_of(tip: &BlockHeader) -> Hash32 {
    hash(Domain::SamplingSeed, &tip.id().encode())
}

/// The work values a newcomer asks about, given a tip's total.
///
/// Whole numbers throughout, because both sides have to draw exactly the same
/// list and floating point is not the same everywhere. The halving that makes
/// the distribution is done on the work itself rather than on a fraction of it.
#[must_use]
pub fn draw(seed: Hash32, count: usize, total_work: u128) -> Vec<u128> {
    if total_work == 0 || count == 0 {
        return Vec::new();
    }

    let mut drawn = Vec::with_capacity(count);
    for index in 0..count {
        // Two numbers from one hash: which halving level, and where inside it.
        let mut material = [0u8; 40];
        if let Some(head) = material.get_mut(..32) {
            head.copy_from_slice(seed.as_bytes());
        }
        let counter = u64::try_from(index).unwrap_or(u64::MAX);
        if let Some(tail) = material.get_mut(32..) {
            tail.copy_from_slice(&counter.to_le_bytes());
        }
        let bytes = hash(Domain::SamplingSeed, &material);
        let bytes = bytes.as_bytes();

        let level = u32::from(bytes.first().copied().unwrap_or(0)) % LEVELS;
        let within = u128::from_le_bytes(
            bytes
                .get(8..24)
                .and_then(|slice| <[u8; 16]>::try_from(slice).ok())
                .unwrap_or([0; 16]),
        );

        // The band this level covers: from `total - total/2^level` up to
        // `total - total/2^(level+1)`. Level zero is the top half of the work,
        // level one the quarter below it, and so on towards the tip.
        let far = total_work >> level.min(127);
        let near = total_work >> level.saturating_add(1).min(127);
        let width = far.saturating_sub(near).max(1);
        let offset = within.checked_rem(width).unwrap_or(0);
        let value = total_work.saturating_sub(far).saturating_add(offset);
        drawn.push(value.min(total_work.saturating_sub(1)));
    }
    drawn
}

/// Checks that a tip really has the work it claims, on the strength of the
/// headers opened for it.
///
/// What is checked, for each drawn value of work: the header opened carries
/// real proof of work, it sits in the tip's history at the height it states,
/// and the work it states covers the value drawn, meaning the work before it
/// falls short of the draw and its own total reaches it. That last one is what
/// ties a claimed total to blocks that were actually made: a chain claiming
/// work it did not do has nothing to open at the values inside the claim.
pub fn check_start(start: &SampledStart, count: usize) -> Result<Weighed, StartError> {
    let tip = &start.tip;
    if !meets_target(&tip.id(), tip.difficulty) {
        return Err(StartError::TipWithoutWork);
    }
    if tip.total_work == 0 {
        return Err(StartError::TipClaimsNothing);
    }
    if start.history.commitment() != tip.history {
        return Err(StartError::HistoryMismatch);
    }
    // The tip's history holds every header before it, so its length is the
    // tip's height. A prover that shrank it could put a header anywhere.
    if start.history.leaves() != tip.height {
        return Err(StartError::HistoryWrongLength {
            held: start.history.leaves(),
            height: tip.height,
        });
    }

    // Drawn against the work behind the tip rather than including it. The tip
    // is not in its own history, so there would be nothing to open for a draw
    // that landed in it, and nothing needs opening: the tip arrives whole and
    // its own work is checked directly.
    let wanted = draw(seed_of(tip), count, work_before(tip));
    if start.samples.len() != wanted.len() {
        return Err(StartError::WrongCount {
            wanted: wanted.len(),
            given: start.samples.len(),
        });
    }

    for (index, (sample, drawn)) in start.samples.iter().zip(wanted.iter()).enumerate() {
        let header = &sample.header;
        if !meets_target(&header.id(), header.difficulty) {
            return Err(StartError::SampleWithoutWork { index });
        }
        if header.total_work > tip.total_work {
            return Err(StartError::PastTheTip { index });
        }
        if !start
            .history
            .verify(header.height, header_leaf(&header.id()), &sample.proof)
        {
            return Err(StartError::NotInHistory { index });
        }

        // The work standing behind this header, before its own.
        let before = work_before(header);
        if before > *drawn || header.total_work <= *drawn {
            return Err(StartError::WrongPlace { index });
        }
    }

    Ok(Weighed {
        tip: tip.id(),
        height: tip.height,
        total_work: tip.total_work,
    })
}

/// The height whose header covers `work` on a chain, for a prover answering a
/// draw.
///
/// The block a draw lands in is the one whose own work spans it: everything
/// before it falls short, and its own total reaches it.
#[must_use]
pub fn covering(headers: &[(u64, u128, u64)], work: u128) -> Option<u64> {
    headers
        .iter()
        .find(|(_, total, difficulty)| {
            let before = total.saturating_sub(work_of(*difficulty));
            before <= work && *total > work
        })
        .map(|(height, _, _)| *height)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> Hash32 {
        Hash32::from_bytes([byte; 32])
    }

    #[test]
    fn a_draw_asks_about_work_that_exists() {
        let total = 1_000_000u128;
        for value in draw(seed(1), 256, total) {
            assert!(value < total, "drew {value}, past a total of {total}");
        }
    }

    /// The same tip has to produce the same questions on both sides, or the
    /// prover is answering a list the verifier never asked for.
    #[test]
    fn a_draw_is_the_same_every_time() {
        let first = draw(seed(7), 64, 9_999_991);
        let second = draw(seed(7), 64, 9_999_991);
        assert_eq!(first, second);
        assert_ne!(
            first,
            draw(seed(8), 64, 9_999_991),
            "and it turns on the seed"
        );
    }

    /// Denser towards the tip, which is where a chain claiming work it did not
    /// do has to put the claim.
    #[test]
    fn a_draw_leans_towards_the_tip() {
        let total = 1_000_000u128;
        let drawn = draw(seed(3), 4_096, total);
        let near = drawn.iter().filter(|value| **value > total / 2).count();
        let far = drawn.len().saturating_sub(near);
        assert!(
            near > far * 2,
            "the top half of the work drew {near} and everything below it {far}"
        );

        // And the very end is reached, which a uniform draw would need a
        // million samples to manage.
        let last_thousandth = total - total / 1_000;
        assert!(
            drawn.iter().any(|value| *value > last_thousandth),
            "nothing landed in the last thousandth of the work"
        );
    }

    #[test]
    fn nothing_is_drawn_from_a_chain_with_no_work() {
        assert!(draw(seed(1), 64, 0).is_empty());
        assert!(draw(seed(1), 0, 1_000).is_empty());
    }

    /// The block a draw lands in is the one whose own work spans it.
    #[test]
    fn a_draw_lands_in_the_block_that_spans_it() {
        // Three blocks, each of difficulty 1: work 1, 2, 3 behind them.
        let unit = work_of(1);
        let headers = vec![(2u64, unit * 3, 1u64), (1, unit * 2, 1), (0, unit, 1)];

        assert_eq!(covering(&headers, 0), Some(0));
        assert_eq!(covering(&headers, unit - 1), Some(0));
        assert_eq!(covering(&headers, unit), Some(1));
        assert_eq!(covering(&headers, unit * 2), Some(2));
        assert_eq!(covering(&headers, unit * 3), None, "past the end");
    }
}

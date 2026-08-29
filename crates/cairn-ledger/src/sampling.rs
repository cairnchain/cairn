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
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Hash32;

use crate::block::BlockHeader;
use crate::pow::{meets_target, work_of};
use crate::state::header_leaf;

/// Headers opened when a newcomer is deciding between chains.
///
/// Measured rather than argued. `cargo run --release -p cairn-ledger --example
/// sampled_start` puts the question two ways: it forges real chains and watches
/// them fail, and it asks the draw alone how often it lands in the work a
/// forger had to invent, at the size a chain reaches in thirty years. At this
/// count a chain overstating its work by one per cent is caught every time,
/// and one overstating by a tenth of a per cent is not.
///
/// A tenth of a per cent is left uncaught deliberately, because catching it
/// would cost four times the traffic to refuse a claim worth a tenth of a per
/// cent of a chain. Where that line belongs is an economic question rather
/// than a statistical one: what a forger stands to gain against the work it
/// would have to redo. Until that is answered this is a floor taken from
/// measurement, not a bound derived from a threat, and it is the last thing
/// between this and a protocol that can be relied on.
///
/// At roughly two kilobytes an opened header this is about a megabyte, which
/// is more than one message carries: a proof travels in several.
pub const SAMPLES: usize = 512;

/// Fewest halvings the draw ever spreads its samples over.
///
/// The distribution has to be denser towards the tip, because that is where an
/// adversary who cannot afford real work has to put the lie: everything behind
/// a fork is honest history it did not make. Sampling by repeated halving is
/// that density written in whole numbers. The top half of the work gets as many
/// draws as the quarter below it, and so on down, which is a density
/// proportional to one over the distance from the tip, the distribution
/// `FlyClient` proves its bound for.
///
/// How far down to go is decided by the chain rather than fixed, since halving
/// past the width of one block puts every draw at that level into the same
/// block: draws spent on a question already asked. `FlyClient` sets the same
/// bound and calls it delta, at one over the number of blocks.
const FEWEST_LEVELS: u32 = 1;

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

impl Encode for Sample {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.header.encode_to(out);
        self.proof.encode_to(out);
    }
}

impl Decode for Sample {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let header = BlockHeader::decode_from(reader)?;
        let proof = ForestProof::decode_from(reader)?;
        Ok(Self { header, proof })
    }
}

impl Encode for SampledStart {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.tip.encode_to(out);
        self.history.encode_to(out);
        u32::try_from(self.samples.len())
            .unwrap_or(u32::MAX)
            .encode_to(out);
        for sample in &self.samples {
            sample.encode_to(out);
        }
    }
}

impl Decode for SampledStart {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let tip = BlockHeader::decode_from(reader)?;
        let history = Forest::decode_from(reader)?;
        let count = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
        // Bounded before anything is reserved, since a sender picks it.
        if count > SAMPLES {
            return Err(CodecError::InvalidValue {
                type_name: "SampledStart",
            });
        }
        let mut samples = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            samples.push(Sample::decode_from(reader)?);
        }
        Ok(Self {
            tip,
            history,
            samples,
        })
    }
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

/// Halvings worth making on a chain of `blocks` blocks.
///
/// One per halving until a band is narrower than a block, since a band inside
/// one block cannot ask a question the band around it did not already ask.
fn levels_for(blocks: u64) -> u32 {
    let significant = u64::BITS.saturating_sub(blocks.max(1).leading_zeros());
    significant.max(FEWEST_LEVELS)
}

/// The work values a newcomer asks about, given a tip's total and how many
/// blocks stand behind it.
///
/// Whole numbers throughout, because both sides have to draw exactly the same
/// list and floating point is not the same everywhere. The halving that makes
/// the distribution is done on the work itself rather than on a fraction of it.
#[must_use]
pub fn draw(seed: Hash32, count: usize, total_work: u128, blocks: u64) -> Vec<u128> {
    if total_work == 0 || count == 0 {
        return Vec::new();
    }
    let levels = levels_for(blocks);

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

        let level = u32::from(bytes.first().copied().unwrap_or(0))
            .checked_rem(levels)
            .unwrap_or(0);
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
    let wanted = draw(seed_of(tip), count, work_before(tip), tip.height);
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

/// Builds the answer to a newcomer's draw, for a node that kept the headers.
///
/// `header_at` reads one header of the followed branch by height, which is a
/// seek in a log rather than anything held in memory. `prove` is what only an
/// archivist can do: a path through the header forest, which cannot be built
/// from the sixty four hashes everybody else keeps.
///
/// `None` when this node cannot answer, which is the honest reply from a node
/// that validates and nothing more.
pub fn open_start(
    tip: &BlockHeader,
    history: Forest,
    count: usize,
    header_at: impl Fn(u64) -> Option<BlockHeader>,
    prove: impl Fn(u64) -> Option<ForestProof>,
) -> Option<SampledStart> {
    let wanted = draw(seed_of(tip), count, work_before(tip), tip.height);
    let mut samples = Vec::with_capacity(wanted.len());

    // Where each draw lands, found by walking back from the tip. A chain is
    // ordered by work as well as by height, so this is a search over something
    // already sorted rather than a scan.
    for work in wanted {
        let height = height_covering(tip, work, &header_at)?;
        let header = header_at(height)?;
        let proof = prove(height)?;
        samples.push(Sample { header, proof });
    }
    Some(SampledStart {
        tip: *tip,
        history,
        samples,
    })
}

/// The height whose header spans `work`, by halving.
///
/// Work rises with height and every block adds its own, so the heights are
/// ordered by the work behind them and the block spanning a given value is
/// found the way any sorted thing is searched.
fn height_covering(
    tip: &BlockHeader,
    work: u128,
    header_at: &impl Fn(u64) -> Option<BlockHeader>,
) -> Option<u64> {
    let mut low = 0u64;
    let mut high = tip.height.checked_sub(1)?;
    while low <= high {
        let middle = low.saturating_add(high.saturating_sub(low) / 2);
        let header = header_at(middle)?;
        if header.total_work <= work {
            low = middle.checked_add(1)?;
        } else if work_before(&header) > work {
            high = middle.checked_sub(1)?;
        } else {
            return Some(middle);
        }
    }
    None
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
        for value in draw(seed(1), 256, total, 1_000) {
            assert!(value < total, "drew {value}, past a total of {total}");
        }
    }

    /// The same tip has to produce the same questions on both sides, or the
    /// prover is answering a list the verifier never asked for.
    #[test]
    fn a_draw_is_the_same_every_time() {
        let first = draw(seed(7), 64, 9_999_991, 10_000);
        let second = draw(seed(7), 64, 9_999_991, 10_000);
        assert_eq!(first, second);
        assert_ne!(
            first,
            draw(seed(8), 64, 9_999_991, 10_000),
            "and it turns on the seed"
        );
    }

    /// Denser towards the tip, which is where a chain claiming work it did not
    /// do has to put the claim.
    #[test]
    fn a_draw_leans_towards_the_tip() {
        let total = 1_000_000u128;
        let drawn = draw(seed(3), 4_096, total, 100_000);
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
        assert!(draw(seed(1), 64, 0, 100).is_empty());
        assert!(draw(seed(1), 0, 1_000, 100).is_empty());
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

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
use crate::pow::{meets_target, work_of, MAX_RETARGET_FACTOR, MIN_DIFFICULTY};
use crate::state::header_leaf;

/// Headers opened when a newcomer is deciding between chains.
///
/// Derived from the assumption the chain already makes, and then measured.
///
/// A forger cannot mine what it did not mine. To present a chain heavier than
/// the honest one while holding a share `s` of the world's work, it has to
/// invent the difference: work no block of its chain spans. It has done `s`
/// and must claim more than `1 - s`, so at least
///
/// ```text
/// lie = 1 - s / (1 - s)
/// ```
///
/// of what it presents is invented. That is a large number for every share
/// proof of work is supposed to survive: a third of the world's work still
/// means inventing half the chain. It only approaches zero as `s` approaches
/// the half at which mining the chain outright is cheaper than forging it.
///
/// The derivation stops there, and an earlier version of this did not notice.
/// It went on to say that each draw lands in invented work with probability
/// `lie`, so `count` draws miss with `(1 - lie)^count`, which at 512 reached
/// 2^-128 at 45.7%. That step assumes the draw is uniform over the chain. It
/// is not, and it is not on purpose.
///
/// The density is one over the distance from the tip, which is what makes the
/// bound indifferent to how deep a forger forks: a fork at any depth leaves a
/// gap covering the same share of its own stretch, and a `1/x` density gives
/// every stretch the same weight. Without that, a forger simply forks deep,
/// invents more of the chain in absolute terms, and puts all of it where a
/// tip-heavy draw hardly ever looks. Measured, that placement took 512 draws
/// from the claimed 2^-128 at 45.7% down to 2^-5.8.
///
/// The price of the density is a factor of `levels` on every draw: it spreads
/// the questions over every scale of depth, so each one is worth `1/levels` of
/// what a uniform draw would be worth against a fixed placement. A draw lands
/// in the gap with probability `ln(1/(1-lie)) / levels` rather than `lie`, and
/// missing that factor is the whole of the error.
///
/// So the count is set from the real thing:
///
/// ```text
/// (1 - ln(1/(1-lie))/levels)^count <= 2^-128
/// ```
///
/// At 4096 draws over a thirty year chain that holds against every forger up
/// to **43%** of the world's work, measured against this very function and
/// against forgeries built and put through [`check_start`]. The papers claim
/// **40%**, which leaves three points of margin for the difference between a
/// staircase of halvings and the smooth density it stands for.
///
/// What that costs is eight megabytes to join a chain rather than one, against
/// the forty-eight gigabytes it replaces. What it buys back is [`SHALLOWEST`]:
/// the draw stops resolving 1024 blocks from the tip, which cuts `levels` from
/// twenty-four to fourteen and the count with it.
///
/// **The guarantee is a depth, and it is worth stating as one.** A forger at
/// 40% cannot put a newcomer on a branch differing from the real one by more
/// than about 1240 blocks (twenty hours). Inside that, it can, and so can a
/// slow peer: it is where any node sits for its first blocks after connecting,
/// and it is shallower than the reorganisation this node would accept anyway.
///
/// Past 50% nothing here helps, and nothing anywhere else does either: a
/// forger at half the work has nothing left to invent and can mine the chain.
///
/// `cargo run --release -p cairn-ledger --example sampled_start` prints the
/// derivation and forges chains against it;
/// `--example adversarial_placement` is where the numbers above come from, and
/// it checks its own model against forgeries that were actually built.
pub const SAMPLES: usize = 4_096;

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

/// How close to the tip the draw stops resolving, in blocks.
///
/// Halving all the way down to a single block is what the first version did,
/// and it is what made the count so expensive. The density that survives a
/// forger choosing its fork depth is one over the distance from the tip, and
/// the price of that density is a factor of `ln(1/delta)` on the number of
/// draws, where delta is the shallowest fork it still separates. Resolving to
/// one block in thirty years means paying that factor twenty-four times over,
/// to tell apart chains that differ by one block.
///
/// Which is not worth buying, because nothing else in this node pretends to
/// tell those apart either: a node refuses to reorganise deeper than
/// `MAX_REORG_DEPTH`, the same 1024 blocks, and below that it changes its mind
/// freely. So the guarantee the sampling offers is stated to match the one the
/// fork choice already offers: a newcomer cannot be put on the wrong chain by
/// more than this, and within it, it is in the same position as any node that
/// just reconnected.
const SHALLOWEST: u64 = 1_024;

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
    /// The header the tip was built on, opened in the tip's own history.
    ///
    /// Without it the weighing said only that a tip names a forest, which is
    /// not the same as saying it stands at the end of a chain. An attacker
    /// took the honest chain's headers, which any node serves to anyone who
    /// asks, built a forest of them, and mined one header at the difficulty
    /// floor to sit on top: one hash, always successful, claiming the honest
    /// chain's whole weight and one unit more. Every draw was answered by a
    /// genuine honest header. Opening the parent costs one more header and one
    /// more path, and a tip on no chain has none to give.
    ///
    /// `None` only for a chain that is one block long, which has no parent to
    /// open.
    pub parent: Option<Sample>,
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
    #[error(
        "the {blocks} blocks between height {from} and height {to} state {stated} work, \
         and that many blocks cannot be worth less than {least}"
    )]
    BlocksWorthLessThanTheyCost {
        from: u64,
        to: u64,
        blocks: u64,
        stated: u128,
        least: u128,
    },
    #[error(
        "the {blocks} blocks between height {from} and height {to} state {stated} work, \
         and that many blocks cannot be worth more than {most}"
    )]
    BlocksWorthMoreThanTheyCould {
        from: u64,
        to: u64,
        blocks: u64,
        stated: u128,
        most: u128,
    },
    #[error("work runs backwards between height {from} and height {to}")]
    WorkRunsBackwards { from: u64, to: u64 },
    #[error("the first {blocks} blocks of the chain state only {stated} work")]
    OpeningWorthLessThanItCost { blocks: u64, stated: u128 },
    #[error("the header the tip was built on was not opened")]
    ParentNotOpened,
    #[error("the header opened for the tip's parent is not the one the tip names")]
    ParentNotTheTipsOwn,
}

/// The least work `blocks` blocks can carry, starting from a block of this
/// difficulty.
///
/// The retarget may divide the difficulty by [`MAX_RETARGET_FACTOR`] each
/// block and never takes it below [`MIN_DIFFICULTY`], so the cheapest run of
/// blocks there is falls as fast as the rule allows and then sits on the
/// floor. Bounded work: the descent reaches the floor in at most the number of
/// times the factor divides a `u64`, and everything after that is one
/// multiplication.
fn least_work_over(difficulty: u64, blocks: u64) -> u128 {
    let floor = u128::from(MIN_DIFFICULTY);
    let mut least: u128 = 0;
    let mut carried = u128::from(difficulty);
    let mut done: u64 = 0;
    while done < blocks {
        carried = carried
            .checked_div(MAX_RETARGET_FACTOR)
            .unwrap_or(floor)
            .max(floor);
        least = least.saturating_add(carried);
        done = done.saturating_add(1);
        if carried == floor {
            let rest = blocks.saturating_sub(done);
            return least.saturating_add(u128::from(rest).saturating_mul(floor));
        }
    }
    least
}

/// The most work `blocks` blocks can carry, starting from a block of this
/// difficulty. The mirror of [`least_work_over`], rising by the same factor
/// until a difficulty cannot be stated in a `u64` at all.
fn most_work_over(difficulty: u64, blocks: u64) -> u128 {
    let ceiling = u128::from(u64::MAX);
    let mut most: u128 = 0;
    let mut carried = u128::from(difficulty).max(1);
    let mut done: u64 = 0;
    while done < blocks {
        carried = carried.saturating_mul(MAX_RETARGET_FACTOR).min(ceiling);
        most = most.saturating_add(carried);
        done = done.saturating_add(1);
        if carried == ceiling {
            let rest = blocks.saturating_sub(done);
            return most.saturating_add(u128::from(rest).saturating_mul(ceiling));
        }
    }
    most
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
        match &self.parent {
            None => 0u8.encode_to(out),
            Some(parent) => {
                1u8.encode_to(out);
                parent.encode_to(out);
            }
        }
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
        let parent = match u8::decode_from(reader)? {
            0 => None,
            1 => Some(Sample::decode_from(reader)?),
            _ => {
                return Err(CodecError::InvalidValue {
                    type_name: "SampledStart",
                })
            }
        };
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
            parent,
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
/// One per halving until a band is narrower than [`SHALLOWEST`], since past
/// that the draw would be separating chains that the fork choice does not
/// separate either, at a cost paid by every draw at every level.
fn levels_for(blocks: u64) -> u32 {
    let separable = blocks / SHALLOWEST;
    let significant = u64::BITS.saturating_sub(separable.max(1).leading_zeros());
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
///
/// Then, and this is the part the first version left out, what is checked
/// between the headers opened rather than at them. The draw is over work, so a
/// stretch of chain claiming no work is a stretch the draw almost never lands
/// in, and for a while that was a door left wide open. A forger took the
/// honest chain's headers, which anybody can ask for, put them in a forest of
/// its own, appended an anchor of its invention and a thousand leaves that
/// were not headers at all, and mined a tip at the difficulty floor: one hash,
/// always successful, declaring one unit more work than the honest chain. All
/// four thousand draws landed in the honest work below and every one of them
/// was answered by a genuine honest header with a genuine proof. The forgery
/// was heavier than every honest peer's claim and could be shown, so it won on
/// the chooser's own terms without any need to isolate anybody, and the ledger
/// hung off it was whatever its author liked.
///
/// What closes it is that a number of blocks implies a least amount of work.
/// The difficulty may fall by at most [`MAX_RETARGET_FACTOR`] per block and
/// never below [`MIN_DIFFICULTY`], so between any two headers whose place is
/// established the work must have grown by at least what that descent allows,
/// and by no more than the matching climb. A thousand blocks are worth a
/// thousand hashes at the very least, and far more than that off a chain of
/// any real difficulty, because walking the difficulty down has to be mined
/// like anything else. The forgery states one.
///
/// This is what the height and the work being separate claims used to cost.
/// They are now tied to each other by the one rule that governs both.
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

    check_the_parent(start)?;
    check_the_gaps(start)?;

    Ok(Weighed {
        tip: tip.id(),
        height: tip.height,
        total_work: tip.total_work,
    })
}

/// Checks that the tip stands at the end of the chain it names.
///
/// The parent has to be in the tip's own history at the height below it, be
/// the header the tip names as its own, and carry the work the tip's total
/// leaves for it. A tip that was mined on nothing has no parent that satisfies
/// all three, and mining one that does means mining on the chain it claims,
/// which is the honest thing this whole exchange is trying to tell apart from
/// the rest.
fn check_the_parent(start: &SampledStart) -> Result<(), StartError> {
    let tip = &start.tip;
    let Some(below) = tip.height.checked_sub(1) else {
        // One block long, so there is nothing under it to open.
        return Ok(());
    };
    let Some(parent) = start.parent.as_ref() else {
        return Err(StartError::ParentNotOpened);
    };
    let header = &parent.header;
    if header.height != below || header.id() != tip.previous {
        return Err(StartError::ParentNotTheTipsOwn);
    }
    if !meets_target(&header.id(), header.difficulty) {
        return Err(StartError::ParentNotTheTipsOwn);
    }
    if !start
        .history
        .verify(below, header_leaf(&header.id()), &parent.proof)
    {
        return Err(StartError::NotInHistory { index: usize::MAX });
    }
    if header.total_work.saturating_add(work_of(tip.difficulty)) != tip.total_work {
        return Err(StartError::ParentNotTheTipsOwn);
    }
    Ok(())
}

/// Checks the stretches of chain nobody opened.
///
/// Every header whose place in the tip's history is established is a point the
/// chain is pinned at, and the tip is the last of them. Between two such
/// points there are as many blocks as their heights differ by, and those
/// blocks cannot state whatever work suits their author: the retarget bounds
/// how fast the difficulty moves, so the run has a least and a most.
///
/// The lower bound is the one that matters. It is what makes a stretch of
/// chain cost something whether or not the draw ever looked at it, and so what
/// stops a chain being padded out to a height it never mined.
fn check_the_gaps(start: &SampledStart) -> Result<(), StartError> {
    let mut points: Vec<&BlockHeader> = start
        .samples
        .iter()
        .chain(start.parent.iter())
        .map(|sample| &sample.header)
        .chain(std::iter::once(&start.tip))
        .collect();
    points.sort_unstable_by_key(|header| (header.height, header.total_work));
    points.dedup_by_key(|header| header.height);

    // Below the lowest point the chain is not pinned at all, so all that can
    // be said is that every block down there is a block: the floor is the
    // least any of them is worth.
    if let Some(first) = points.first() {
        let blocks = first.height.saturating_add(1);
        let least = u128::from(blocks).saturating_mul(u128::from(MIN_DIFFICULTY));
        if first.total_work < least {
            return Err(StartError::OpeningWorthLessThanItCost {
                blocks,
                stated: first.total_work,
            });
        }
    }

    for pair in points.windows(2) {
        let (Some(from), Some(to)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        let Some(blocks) = to.height.checked_sub(from.height) else {
            continue;
        };
        let Some(stated) = to.total_work.checked_sub(from.total_work) else {
            return Err(StartError::WorkRunsBackwards {
                from: from.height,
                to: to.height,
            });
        };
        let least = least_work_over(from.difficulty, blocks);
        if stated < least {
            return Err(StartError::BlocksWorthLessThanTheyCost {
                from: from.height,
                to: to.height,
                blocks,
                stated,
                least,
            });
        }
        let most = most_work_over(from.difficulty, blocks);
        if stated > most {
            return Err(StartError::BlocksWorthMoreThanTheyCould {
                from: from.height,
                to: to.height,
                blocks,
                stated,
                most,
            });
        }
    }
    Ok(())
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
    let parent = match tip.height.checked_sub(1) {
        None => None,
        Some(below) => Some(Sample {
            header: header_at(below)?,
            proof: prove(below)?,
        }),
    };
    Some(SampledStart {
        tip: *tip,
        parent,
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

    /// What the count is for, pinned so it cannot drift unnoticed.
    ///
    /// A forger holding share `s` of the world's work cannot mine what it did
    /// not mine, so to present a chain heavier than the honest one it has to
    /// invent `1 - s/(1-s)` of what it shows. That part is arithmetic and it
    /// holds.
    ///
    /// What does not follow, and what an earlier version of this assumed, is
    /// that a draw lands in the invented part with that same probability. It
    /// would if the draw were uniform. It is not: it is one over the distance
    /// from the tip, which is what makes it indifferent to how deep a forger
    /// forks, and the price of that indifference is a factor of the number of
    /// halvings on every draw. Missing it is what put the count at 512.
    ///
    /// So: a draw lands in the gap with probability `ln(1/(1-lie)) / levels`
    /// in nats, and `count` of them miss with `(1 - that)^count`.
    #[test]
    fn the_count_holds_to_the_share_the_papers_claim() {
        // Thirty years at a block a minute, which is the size every figure in
        // the papers is quoted at.
        let levels = f64::from(levels_for(30 * 365 * 24 * 60));
        let count = i32::try_from(SAMPLES).expect("a count that fits");
        let missed = |share: f64| {
            let lie = 1.0 - share / (1.0 - share);
            let per_draw = (1.0 / (1.0 - lie)).ln() / (levels * 2f64.ln());
            (1.0 - per_draw).powi(count)
        };

        // The share the papers claim, and everything under it.
        for share in [0.05, 0.10, 0.20, 0.30, 0.35, 0.40] {
            assert!(
                missed(share) <= 2f64.powi(-128),
                "a forger at {share} of the work gets through more often than \
                 one in 2^128"
            );
        }

        // And the claim is not idle. It stops holding a few points above what
        // is claimed, which is where the margin is: 4096 draws are measured to
        // hold to 43%, and 40% is what is said out loud.
        assert!(
            missed(0.46) > 2f64.powi(-128),
            "the count holds further than the papers say, so one of them is wrong"
        );

        // No count protects against a majority. At half the world's work there
        // is nothing left to invent.
        assert!(
            (missed(0.5) - 1.0).abs() < 1e-12,
            "at half the world's work there is no lie left to catch"
        );
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

        // And it stops resolving before the tip rather than at it. On a chain
        // of a hundred thousand blocks the finest band is a hundred and
        // twenty-eight of them wide, so the last stretch is never drawn from
        // at all. That is deliberate: see SHALLOWEST. What it costs is stated
        // as a depth rather than hidden, and what it buys is a count that is
        // eight megabytes instead of a hundred.
        let bands = levels_for(100_000);
        let unresolved = total >> bands;
        assert!(
            !drawn.iter().any(|value| *value > total - unresolved),
            "the draw resolves past where it says it stops"
        );
        assert!(
            drawn.iter().any(|value| *value > total - unresolved * 4),
            "and stops close to it, not far short"
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

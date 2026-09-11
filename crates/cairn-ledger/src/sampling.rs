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
//! Three things make the questions unanswerable in advance. The positions come
//! from hashing the tip, so choosing them means redoing the tip's work. They
//! are drawn against work rather than height, so a chain claiming work it did
//! not do is asked about the part it claimed. And how many of them there are
//! is decided by how old the chain says it is, which the reader's own clock
//! bounds: see [`levels_of`], which is where six networks' worth of this got
//! it wrong.
//!
//! What this settles is which chain is heaviest, and nothing else. A newcomer
//! that has settled it still needs the ledger at that tip before it can check
//! a transaction, and that is a separate exchange: the ledger is bounded and
//! every header commits to it, so it arrives whole and is checked against the
//! header this sampling just accepted.

use cairn_accumulator::forest::{tree_of, Forest, ForestProof};
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Hash32;

use crate::block::{BlockHeader, HeaderSummary};
use crate::note::NetworkId;
use crate::pow::{
    median_time_past, meets_target, next_difficulty, work_of, DIFFICULTY_WINDOW,
    MAX_RETARGET_FACTOR, MIN_DIFFICULTY,
};
use crate::state::header_leaf;
use crate::validation::ConsensusParams;

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
/// **`levels` is an input, and for six networks it was one a prover wrote
/// down.** It was `levels_for(tip.height)`, read off a field of the tip, and a
/// height is not work: the only rule holding the two together is
/// `check_the_gaps`, which prices a run of blocks nobody opened at
/// [`MIN_DIFFICULTY`] apiece. So a chain whose blocks averaged difficulty `d`
/// could state a height `d` times the one it had, buy `log2(d)` halvings with
/// it, and take that many slices off what every draw was worth. At a real
/// chain's numbers that is fifty-odd halvings against the fourteen the count
/// was set for, bought in work the forger was already inventing. Measured on
/// this very function, a forger at 40% went from missing all 4096 draws with
/// 2^-207 to missing them with 2^-58, against a figure published as 2^-128,
/// and the share the count held to was 31% rather than 40%.
///
/// [`levels_of`] is what closes it: the halvings are counted from how old the
/// chain says it is rather than from how tall, and the age is the one number
/// on a tip that a reader's own clock bounds. A prover cannot spread the draw
/// over more halvings than the honest chain has had time for, and the height
/// is still read, where it can only take halvings away.
///
/// What that costs is about three megabytes to weigh a thirty-year chain,
/// against the three gigabytes of headers it replaces reading. What it buys
/// back is [`SHALLOWEST`]: the draw stops resolving 1024 blocks from the tip,
/// which cuts `levels` from twenty-four to fourteen and the count with it.
///
/// The three megabytes are derived rather than guessed, in [`sample_bytes`]:
/// a header per draw plus the path beside it, and a path is as long as the
/// tree the draw lands in. The figure here used to be eight, from a count that
/// predates this derivation multiplied by a path of sixty-four hashes.
/// Sixty-four is the deepest a forest can ever hold; thirty
/// years of blocks make a forest whose largest tree is twenty-three, and the
/// draw spends most of its levels in trees smaller than that. So the old
/// figure was an upper bound on a chain nobody will live to see, quoted as the
/// cost of joining this one.
///
/// **The guarantee is a depth, and it is worth stating as one.** A forger at
/// 40% cannot put a newcomer on a branch differing from the real one by more
/// than about 1240 blocks. Inside that, it can, and so can a slow peer: it is
/// where any node sits for its first blocks after connecting.
///
/// That depth is deeper than what a node will undo. This paragraph used to end
/// by saying it was shallower than the reorganisation this node would accept,
/// which its own two numbers refute: `MAX_REORG_DEPTH` is 1024 and the
/// effective limit is the lesser of that and the network's burial. So a
/// newcomer put at the far end of the guarantee cannot be carried back onto the
/// real chain by the ordinary rule, and the whitepaper's limitations section
/// states the gap and the three ways of closing it. None is chosen here,
/// because each changes a rule.
///
/// Twenty hours at a block a minute, and the depth is the part that is
/// guaranteed. A branch sitting at the difficulty floor may state the same
/// depth in half that time, since the retarget stops asking for more once the
/// gaps pass half the target, so any argument that wants a duration has to say
/// which of the two chains it is timing.
///
/// Past 50% nothing here helps, and nothing anywhere else does either: a
/// forger at half the work has nothing left to invent and can mine the chain.
///
/// **The bound is per tip, and a forger may buy more than one.** The seed is
/// the tip's own identifier, so a forger that dislikes the questions it drew
/// finds another tip and asks again, and a forger with `g` tips faces `g`
/// times the chance of getting one through. That is a cost rather than a bar:
/// a tip costs the tip's own work, so reaching even 2^80 tips is out of the
/// question on a chain of any real difficulty, and 2^80 against 2^-128 is
/// still 2^-48. The margin absorbs it, but the figure is a per-tip figure and
/// saying so is the difference between a bound and a hope. Grinding is
/// measured against forgeries that were built, in `adversarial_placement`.
///
/// `cargo run --release -p cairn-ledger --example sampled_start` prints the
/// derivation and forges chains against it;
/// `--example adversarial_placement` is where the numbers above come from. It
/// works the depth out from the real draw, and then holds that model to the
/// shipped check: it mines chains, builds forgeries on them that a forger
/// could really present, and for every tip compares what the draw alone says
/// with what [`check_start`] did, attributing every refusal to the check that
/// made it. The two have never differed. Until this round that half of it was
/// worthless, because it left every `previous` link naming a header it had
/// just replaced and then counted the refusal for the broken link as a
/// forgery the draw had caught.
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
pub const SHALLOWEST: u64 = 1_024;

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
    /// Every header from a full retarget window below the deepest thing the
    /// draw pinned, up to the tip. Oldest first.
    ///
    /// The draw deliberately stops resolving [`SHALLOWEST`] blocks from the
    /// tip, and for a while nothing else looked up there either. That was
    /// enough on its own: a forger left the honest chain untouched, appended
    /// its own headers at the difficulty floor, one hash each, and put the
    /// work it was inventing inside the band the draw never reaches. The
    /// anchor a newcomer is then handed is one of the forger's own headers,
    /// with whatever ledger it cares to commit to. Neither the parent check
    /// nor the work between opened headers sees it, because both are about
    /// what a run of blocks is worth and this run really is worth what it
    /// says: almost nothing, honestly stated.
    ///
    /// What was missing is that the top of a chain was tied to no difficulty
    /// anybody could check. The run below fixes that by starting at a header
    /// the draw actually landed on, and walking upward under the retarget:
    /// each header carries the difficulty the window demands of it, dates
    /// after that window's median, and adds its own work to the total. The
    /// window below the pinned header comes along too, and is honest because
    /// those headers have to chain into it: a forger cannot swap them without
    /// having mined the pinned header on top of its own.
    ///
    /// Held together with the tip's timestamp being near the reader's own
    /// clock, that makes the cheap run cost the one thing a forger cannot
    /// manufacture. Blocks at the floor have to be spaced past half the
    /// target or the retarget demands more of them, so a thousand of them
    /// span eight hours and a half, and a reader
    /// refuses a tip more than two hours ahead of its own
    /// clock. Two hours is [`ConsensusParams::max_timestamp_drift`], and this
    /// used to say a day: true, and twelve times looser than the rule it
    /// stands in for, inside the one argument that rule is load-bearing for.
    ///
    /// Half the target rather than the target, and the difference is a factor
    /// of two on the waiting. At the floor the retarget answers
    /// `floor(target / gap)`, which is already one at 31 seconds a block, so a
    /// thousand cheap blocks span 8 h 49 m and not the 17 h 04 m this used to
    /// claim. The argument survives halved: the run still has to state more
    /// time than the drift lets a reader take in advance, so the forger still
    /// sits through the difference in real time. The boundary is pinned at
    /// exactly 30 and 31 seconds in
    /// `tests/retarget_timewarp.rs::the_floor_holds_from_thirty_one_seconds_and_not_from_thirty`.
    pub tail: Vec<BlockHeader>,
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
    #[error("the run up to the tip holds {given} headers, and {wanted} were wanted")]
    TailWrongLength { given: u64, wanted: u64 },
    #[error("the run up to the tip does not hold the header opened at height {at}")]
    TailMissesWhatWasOpened { at: u64 },
    #[error("the header at {at} in the run up to the tip does not follow the one below it")]
    TailNotConsecutive { at: u64 },
    #[error("the header at {at} in the run up to the tip carries no work")]
    TailWithoutWork { at: u64 },
    #[error("the header at {at} states difficulty {stated}, and the rules demand {demanded}")]
    TailAtTheWrongDifficulty { at: u64, stated: u64, demanded: u64 },
    #[error("the header at {at} is not later than the median of the window before it")]
    TailOutOfTime { at: u64 },
    #[error("the work stated at {at} is not the work below it plus its own")]
    TailWorkDoesNotAddUp { at: u64 },
    #[error("the tip is dated {timestamp}, further ahead than this node will take")]
    TipFromTheFuture { timestamp: u64 },
    #[error("nothing was opened, so there is nothing to measure the tip against")]
    NothingOpened,
}

/// The longest run this will walk between the deepest thing the draw pinned
/// and the tip.
///
/// On a chain whose difficulty is near its own lifetime average the band the
/// draw leaves unresolved is about [`SHALLOWEST`] blocks, so the run is that
/// plus a window. The ceiling is generous against that because the band is
/// measured in work: a chain whose difficulty has fallen well below what it
/// averaged over its life has more blocks inside the same band. Past this it
/// cannot be weighed and has to be read, which is a real limit and is stated
/// rather than hidden. A chain that has lost sixteen times its hash rate and
/// not recovered is the shape that reaches it.
pub const MOST_TAIL: u64 = 16 * SHALLOWEST + DIFFICULTY_WINDOW as u64;

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

        u32::try_from(self.tail.len())
            .unwrap_or(u32::MAX)
            .encode_to(out);
        for header in &self.tail {
            header.encode_to(out);
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
        let held = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
        if u64::try_from(held).unwrap_or(u64::MAX) > MOST_TAIL {
            return Err(CodecError::InvalidValue {
                type_name: "SampledStart",
            });
        }
        let mut tail = Vec::with_capacity(held.min(1024));
        for _ in 0..held {
            tail.push(BlockHeader::decode_from(reader)?);
        }

        Ok(Self {
            tip,
            tail,
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
///
/// This is the honest count for a chain of that length, and it is public
/// because it is what every published figure is computed from and what
/// [`levels_of`] holds a stranger's tip to.
#[must_use]
pub fn levels_for(blocks: u64) -> u32 {
    let separable = blocks / SHALLOWEST;
    let significant = u64::BITS.saturating_sub(separable.max(1).leading_zeros());
    significant.max(FEWEST_LEVELS)
}

/// Halvings the draw spreads itself over, for a tip a stranger is offering.
///
/// Two numbers, and the smaller of them wins.
///
/// The first is the chain's age counted in blocks: how long the tip says the
/// network has been running, over the block time the network aims at. That is
/// a ceiling a prover cannot lift, because a reader refuses a tip dated more
/// than [`ConsensusParams::max_timestamp_drift`] past its own clock and the
/// opening moment is written into the software rather than sent by a peer. So
/// the deepest a stated chain can halve is the deepest the real one can,
/// whatever else it says about itself.
///
/// The second is the tip's height, which is what this read alone for six
/// networks and what a prover could write down for one unit of work a block.
/// It is kept because it is the right answer for a chain that has stalled: ten
/// blocks mined over a year should not be halved nine times into the last of
/// them. Taken as the smaller of the two it can only take halvings away, and a
/// draw spread over fewer of them is worth more per question, not less.
///
/// So there is no side of this to lean on. Overstating either number is
/// refused or ignored; understating either widens the band nearest the tip,
/// and that band is the run of headers a prover then has to hand over in full,
/// which is refused past [`MOST_TAIL`].
///
/// On an honest chain the two agree, because the retarget is what makes them
/// agree: it holds the chain to `target_block_time` a block, so its age in
/// blocks is its height. A chain that ran fast for its whole life states fewer
/// halvings than its height would, and pays for it in a longer run up to the
/// tip rather than in a weaker draw.
///
/// **The reader's clock bounds this and does not enter it.** Nothing here reads
/// the time of day: the count is a function of the tip and of constants, so
/// every node computes the same one for the same tip and a prover answers the
/// list its reader asked for. Clamping the age against the reader's own clock
/// here instead would be a second implementation that splits the network the
/// first time two nodes disagree about the hour. What the clock does is decide
/// whether the tip is looked at at all, in [`check_start`], before this is
/// called. A node whose clock runs fast raises its own ceiling by exactly the
/// error: a year fast on a thirty year chain moves the count from fourteen to
/// fourteen, which is the scale of the dependency.
#[must_use]
pub fn levels_of(tip: &BlockHeader, params: &ConsensusParams) -> u32 {
    let since_opening = tip.timestamp.saturating_sub(params.opens_at);
    let by_the_clock = since_opening
        .checked_div(params.target_block_time.max(1))
        .unwrap_or(0);
    levels_for(by_the_clock.min(tip.height))
}

/// The work values a newcomer asks about, given a tip's total and the number
/// of halvings the questions are spread over.
///
/// Whole numbers throughout, because both sides have to draw exactly the same
/// list and floating point is not the same everywhere. The halving that makes
/// the distribution is done on the work itself rather than on a fraction of it.
///
/// **`levels` is asked for rather than worked out here.** It used to be
/// `levels_for(tip.height)`, computed inside this function off a number a
/// prover writes down, and that was the break [`SAMPLES`] describes. Naming it
/// as an argument is what makes a caller say where its count came from, and
/// makes the old mistake a type error rather than a plausible line: a height
/// is a `u64` and this wants the count itself. [`levels_of`] is what a real
/// tip goes through; [`levels_for`] is what a modelled chain of a given length
/// goes through.
///
/// **The level is drawn from eight bytes rather than one.** One byte was the
/// first shape, and 256 does not divide by 14: the four deepest levels came up
/// nineteen times in 256 and the other ten eighteen, an under-draw of 1.5625
/// percent on the ten levels nearest the tip, so 4096 draws did the work of
/// 4032. `FlyClient` assumes the choice is uniform, so that was a real loss,
/// small enough to sit inside the three points of margin [`SAMPLES`] holds
/// back and measured in `tests/audit_sampling_as_published.rs` rather than
/// argued. Eight bytes multiplied by `levels` and shifted back down spread the
/// same choice with a bias under one part in 2^64, which is below anything
/// this is quoted to. It costs one multiplication, and it is done now because
/// changing which positions a chain is asked about is a change both sides make
/// on the same day, and the level count moving is already one of those.
#[must_use]
pub fn draw(seed: Hash32, count: usize, total_work: u128, levels: u32) -> Vec<u128> {
    if total_work == 0 || count == 0 {
        return Vec::new();
    }
    let levels = levels.max(FEWEST_LEVELS);

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

        // Multiplied and shifted rather than reduced: `chosen` spans the
        // whole of a `u64`, so scaling it by `levels` and taking the high half
        // lands in `0..levels` with a bias under one part in 2^64.
        let chosen = u64::from_le_bytes(
            bytes
                .get(..8)
                .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
                .unwrap_or([0; 8]),
        );
        let level =
            u32::try_from(u128::from(chosen).saturating_mul(u128::from(levels)) >> 64).unwrap_or(0);
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

/// What one opened header and the path beside it take on the wire.
///
/// A header is fixed width, and a path is a length followed by its siblings.
/// Written from [`Sample`]'s own encoding and checked against it in this
/// module's tests, because a size derived beside a format rather than from it
/// is exactly how the published figure went wrong.
fn opened_header_bytes(depth: usize) -> u64 {
    let header = u64::try_from(BlockHeader::ENCODED_BYTES).unwrap_or(0);
    let siblings = u64::try_from(depth).unwrap_or(0).saturating_mul(32);
    header.saturating_add(4).saturating_add(siblings)
}

/// Bytes the drawn answers take on the wire, for a chain of `blocks` blocks.
///
/// The count is the draw this build makes, and each path is as long as the
/// tree the drawn position falls in, so nothing here is a bound standing in
/// for a measurement.
///
/// It lives here rather than in an example because three examples quoted this
/// figure and each derived it again, and two of the three were wrong in the
/// same two ways. A header was priced at `size_of::<BlockHeader>()`, 192,
/// because a `u128` field carries the alignment, where the wire writes
/// [`BlockHeader::ENCODED_BYTES`], 182. And a path was priced at 64 levels,
/// which is how many trees a forest can hold once it has `2^64` leaves rather
/// than how deep one path is: thirty years of blocks a minute make a deepest
/// tree of twenty-three, and most draws land in trees smaller than that.
/// Together they published 9.4 MB for something that costs 3.1.
///
/// The chain is taken as one of even difficulty, so that a work value is a
/// height. That is what makes a drawn number a position; a real chain's
/// difficulty moves and moves the mapping with it, but not the shape of the
/// forest and not the count of the draw.
///
/// `seed` is what [`seed_of`] gives for the tip being weighed. A different tip
/// draws different positions and lands on a slightly different total.
#[must_use]
pub fn sample_bytes(seed: Hash32, blocks: u64) -> u64 {
    let mut total = 0u64;
    for work in draw(seed, SAMPLES, u128::from(blocks), levels_for(blocks)) {
        let position = u64::try_from(work).unwrap_or(0);
        let depth = tree_of(blocks, position).map_or(0, |(height, _)| height);
        total = total.saturating_add(opened_header_bytes(depth));
    }
    total
}

/// Whether a header is one this network could have produced.
///
/// Two fields [`crate::validation::check_header`] puts every block through,
/// and that nothing on the joining path read at all. A node with no chain is
/// the one reader that cannot fall back on comparing what it is offered
/// against what it already has, so it is the reader these matter most to, and
/// it was the only one not asking.
///
/// The network identifier is what the whole numbering scheme rests on: a
/// network that has to change a rule starts over and takes the next number, so
/// that a node still on the old one "is told plainly that it is on another
/// network, rather than failing somewhere confusing". A newcomer could be
/// weighed onto another network's chain, take its ledger, and then refuse
/// every block that chain went on to produce, which is exactly the confusing
/// failure the number exists to prevent. It costs one comparison.
///
/// The opening moment is the sharper of the two. `opens_at` is published ahead
/// of a launch so that "whoever knew about the network first cannot have mined
/// it quietly the week before, because every node refuses blocks dated
/// earlier". Every node did not: a chain premined before the opening carries
/// the extra work that head start bought, and a newcomer weighed it, took it,
/// and sat on a chain every established node refuses. Re-dating those blocks
/// forward is not a way out, because a header's difficulty is part of its
/// identifier and the retarget would have demanded a different one for blocks
/// spaced that way, so the head start has to be worn where it was earned.
///
/// Neither check can refuse an honest chain: every honest header went through
/// `check_header` on the way in and carries both. What they cover is every
/// header this exchange actually sees, which is the tip, its parent, the run
/// up to the tip, and whatever the draw opened. A header nobody opened is
/// still unexamined, and on a young chain, where a head start is worth a large
/// share of the total, that is where the draw is looking.
fn belongs_to_this_network(
    header: &BlockHeader,
    params: &ConsensusParams,
) -> Result<(), StartError> {
    if header.network != params.network {
        return Err(StartError::WrongNetwork {
            height: header.height,
            expected: params.network,
            found: header.network,
        });
    }
    if header.timestamp < params.opens_at {
        return Err(StartError::BeforeTheNetworkOpened {
            height: header.height,
            opens_at: params.opens_at,
            found: header.timestamp,
        });
    }
    Ok(())
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
pub fn check_start(
    start: &SampledStart,
    count: usize,
    now: u64,
    params: &ConsensusParams,
) -> Result<Weighed, StartError> {
    let tip = &start.tip;
    belongs_to_this_network(tip, params)?;
    // Before the draw rather than after it, because how old the tip says the
    // chain is decides how many questions are asked, and this is what bounds
    // what it can say. See [`levels_of`].
    if tip.timestamp > now.saturating_add(params.max_timestamp_drift) {
        return Err(StartError::TipFromTheFuture {
            timestamp: tip.timestamp,
        });
    }
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
    let wanted = draw(
        seed_of(tip),
        count,
        work_before(tip),
        levels_of(tip, params),
    );
    if start.samples.len() != wanted.len() {
        return Err(StartError::WrongCount {
            wanted: wanted.len(),
            given: start.samples.len(),
        });
    }

    for (index, (sample, drawn)) in start.samples.iter().zip(wanted.iter()).enumerate() {
        let header = &sample.header;
        belongs_to_this_network(header, params)?;
        if !meets_target(&header.id(), header.difficulty) {
            return Err(StartError::SampleWithoutWork { index });
        }
        if header.total_work > tip.total_work {
            return Err(StartError::PastTheTip { index });
        }
        // Whether this header answers the question that was asked, which is
        // two comparisons on numbers already in hand. Ahead of the proof,
        // which folds up to sixty four hashes: the loop stops at the first
        // sample it refuses, so a forger who opens a real header at the wrong
        // place now buys one comparison rather than a path.
        //
        // `before` is the work standing behind this header, not counting its
        // own.
        let before = work_before(header);
        if before > *drawn || header.total_work <= *drawn {
            return Err(StartError::WrongPlace { index });
        }

        if !start
            .history
            .verify(header.height, header_leaf(&header.id()), &sample.proof)
        {
            return Err(StartError::NotInHistory { index });
        }
    }

    check_the_parent(start, params)?;
    check_the_gaps(start)?;
    check_the_tail(start, params)?;

    Ok(Weighed {
        tip: tip.id(),
        height: tip.height,
        total_work: tip.total_work,
    })
}

/// Walks the top of the chain, which the draw does not reach.
///
/// Starts a full retarget window below the deepest header the draw landed on,
/// so the window the first checked header is judged against is one a forger
/// would have had to mine that header on top of. From there every header is
/// held to the rules a node applies to any block it is handed: the difficulty
/// the window demands, a timestamp past that window's median, its own work
/// added to the total, and real work behind its own identifier.
///
/// The tip's timestamp is measured against the reader's own clock rather than
/// left to the forward validation that comes later, because this is where the
/// decision is made: without it a forger hands over a chain whose cheap blocks
/// are spaced out across days it never waited. That check has moved up to the
/// top of [`check_start`], since the same timestamp now decides how many
/// questions get asked and the bound on it has to be in force before the draw
/// rather than after the answers.
fn check_the_tail(start: &SampledStart, params: &ConsensusParams) -> Result<(), StartError> {
    let tip = &start.tip;
    // The deepest thing the draw actually landed on. The parent does not
    // count: it is required rather than drawn, so a forger chooses it.
    let Some(pinned) = start
        .samples
        .iter()
        .map(|sample| &sample.header)
        .max_by_key(|header| header.height)
    else {
        return Err(StartError::NothingOpened);
    };

    let window = u64::try_from(DIFFICULTY_WINDOW).unwrap_or(u64::MAX);
    let from = pinned.height.saturating_sub(window);
    let Some(span) = tip.height.checked_sub(from) else {
        return Err(StartError::TailWrongLength {
            given: u64::try_from(start.tail.len()).unwrap_or(u64::MAX),
            wanted: 0,
        });
    };
    let wanted = span.saturating_add(1);
    let given = u64::try_from(start.tail.len()).unwrap_or(u64::MAX);
    if given != wanted || wanted > MOST_TAIL {
        return Err(StartError::TailWrongLength { given, wanted });
    }

    // A window and one more, which is all this ever holds: it is trimmed to
    // that at the end of every step. Reserving the run's own length instead
    // sized a reader's allocation from a number the sender chose, for room
    // nothing ever puts anything in.
    let mut summaries: Vec<HeaderSummary> = Vec::with_capacity(DIFFICULTY_WINDOW.saturating_add(1));
    let mut previous: Option<&BlockHeader> = None;
    let mut carried_the_pinned = false;
    for header in &start.tail {
        belongs_to_this_network(header, params)?;
        if !meets_target(&header.id(), header.difficulty) {
            return Err(StartError::TailWithoutWork { at: header.height });
        }
        if let Some(below) = previous {
            if header.height != below.height.saturating_add(1) || header.previous != below.id() {
                return Err(StartError::TailNotConsecutive { at: header.height });
            }
            // Below the pinned header nothing can be checked but the chain
            // itself, since the window that would judge those difficulties is
            // not here. Above it the rules apply in full, and that is where a
            // forger's cheap run would have to live.
            if below.height >= pinned.height {
                let demanded = next_difficulty(&summaries, params.target_block_time);
                if header.difficulty != demanded {
                    return Err(StartError::TailAtTheWrongDifficulty {
                        at: header.height,
                        stated: header.difficulty,
                        demanded,
                    });
                }
                if median_time_past(&summaries).is_some_and(|median| header.timestamp <= median) {
                    return Err(StartError::TailOutOfTime { at: header.height });
                }
                if header.total_work != below.total_work.saturating_add(work_of(header.difficulty))
                {
                    return Err(StartError::TailWorkDoesNotAddUp { at: header.height });
                }
            }
        }
        if header.height == pinned.height {
            if header.id() != pinned.id() {
                return Err(StartError::TailMissesWhatWasOpened { at: pinned.height });
            }
            carried_the_pinned = true;
        }
        summaries.push(HeaderSummary {
            height: header.height,
            timestamp: header.timestamp,
            difficulty: header.difficulty,
        });
        if summaries.len() > DIFFICULTY_WINDOW.saturating_add(1) {
            summaries.remove(0);
        }
        previous = Some(header);
    }

    if !carried_the_pinned {
        return Err(StartError::TailMissesWhatWasOpened { at: pinned.height });
    }
    if previous.is_some_and(|last| last.id() != tip.id()) {
        return Err(StartError::TailNotConsecutive { at: tip.height });
    }
    Ok(())
}

/// Checks that the tip stands at the end of the chain it names.
///
/// The parent has to be in the tip's own history at the height below it, be
/// the header the tip names as its own, and carry the work the tip's total
/// leaves for it. A tip that was mined on nothing has no parent that satisfies
/// all three, and mining one that does means mining on the chain it claims,
/// which is the honest thing this whole exchange is trying to tell apart from
/// the rest.
fn check_the_parent(start: &SampledStart, params: &ConsensusParams) -> Result<(), StartError> {
    let tip = &start.tip;
    let Some(below) = tip.height.checked_sub(1) else {
        // One block long, so there is nothing under it to open.
        return Ok(());
    };
    let Some(parent) = start.parent.as_ref() else {
        return Err(StartError::ParentNotOpened);
    };
    let header = &parent.header;
    belongs_to_this_network(header, params)?;
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
/// `params` is read for the same reason the reader reads it: the number of
/// questions comes from the tip's age under this network's own opening moment
/// and block time, so a prover that took it from anywhere else would answer a
/// list nobody asked for.
///
/// `header_at` reads one header of the followed branch by height, which is a
/// seek in a log rather than anything held in memory. `prove` is what only an
/// archivist can do: a path through the header forest, which cannot be built
/// from the sixty four hashes everybody else keeps.
///
/// `None` when this node cannot answer, which is the honest reply from a node
/// that validates and nothing more, and also from a node whose chain has left
/// the band a sampling can reach. See the run up to the tip below.
pub fn open_start(
    tip: &BlockHeader,
    history: Forest,
    count: usize,
    params: &ConsensusParams,
    header_at: impl Fn(u64) -> Option<BlockHeader>,
    prove: impl Fn(u64) -> Option<ForestProof>,
) -> Option<SampledStart> {
    let wanted = draw(
        seed_of(tip),
        count,
        work_before(tip),
        levels_of(tip, params),
    );
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
    let deepest = samples
        .iter()
        .map(|sample: &Sample| sample.header.height)
        .max()
        .unwrap_or(tip.height);
    let window = u64::try_from(DIFFICULTY_WINDOW).unwrap_or(u64::MAX);
    let from = deepest.saturating_sub(window);

    // How long the run would be, worked out before a header is read for it.
    //
    // The draw stops resolving a band of work below the tip, and the run is
    // that band measured in blocks. On a chain whose difficulty is near its
    // own lifetime average that is about [`SHALLOWEST`] blocks; on one whose
    // difficulty has fallen far below it the same work covers proportionally
    // more, and there is no bound on the ratio but the chain's own length. A
    // chain that has lost a hundredfold over a suffix of half a million blocks
    // makes a run of half a million headers, which is what the loop below used
    // to read off the disk and encode: a hundred megabytes, and growing with
    // the chain, off a node whose whole claim is that nothing here does.
    //
    // Not one byte of which could ever be used. `check_the_tail` wants exactly
    // this many headers and refuses past [`MOST_TAIL`], and `SampledStart`'s
    // decoder refuses the same length before it reserves anything, so the far
    // end throws the answer away without reading it. Refusing here reaches the
    // same conclusion for the price of the subtraction.
    //
    // This belongs on the serving side because it is the same constant on both
    // sides of the same exchange, and it lives in this crate rather than in
    // whatever ships a server so that the two cannot drift apart: a build that
    // moved MOST_TAIL would move what it serves with it.
    let held = tip.height.checked_sub(from)?.checked_add(1)?;
    if held > MOST_TAIL {
        return None;
    }
    let mut tail = Vec::with_capacity(usize::try_from(held).unwrap_or(0));
    for height in from..=tip.height {
        tail.push(header_at(height)?);
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
        tail,
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

    fn bare_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            network: NetworkId::MAINNET,
            height: 0,
            previous: Hash32::from_bytes([0; 32]),
            transactions_root: Hash32::from_bytes([0; 32]),
            state_root: Hash32::from_bytes([0; 32]),
            history: Hash32::from_bytes([0; 32]),
            timestamp: 0,
            difficulty: 1,
            total_work: 0,
            nonce: 0,
        }
    }

    /// The price of one answer is the wire's price, not the compiler's.
    ///
    /// `size_of::<BlockHeader>()` is 192 and the encoding writes 182: the
    /// `u128` field takes the alignment with it and ten bytes of padding are
    /// counted that never travel. Every figure built on the wrong one of those
    /// was five per cent high before the path was even considered.
    #[test]
    fn one_opened_header_costs_what_the_wire_writes() {
        for depth in [0usize, 1, 7, 23, 64] {
            let sample = Sample {
                header: bare_header(),
                proof: ForestProof {
                    siblings: vec![Hash32::from_bytes([9; 32]); depth],
                },
            };
            assert_eq!(
                u64::try_from(sample.encode().len()).unwrap(),
                opened_header_bytes(depth),
                "a path of {depth} levels"
            );
        }
    }

    /// The published cost of weighing a chain, re-derived.
    ///
    /// Both halves of the old formula are pinned here. A path of 64 levels
    /// instead of the tree the draw lands in puts this over nine megabytes; a
    /// header at `size_of` instead of its encoded width puts it over 3.2. The
    /// bounds are tight enough that either alone fails.
    #[test]
    fn weighing_a_thirty_year_chain_costs_three_megabytes() {
        let blocks = 30 * 365 * 24 * 60;
        let bytes = sample_bytes(seed(7), blocks);
        assert!(
            (3_000_000..3_200_000).contains(&bytes),
            "a sampled start opens {SAMPLES} headers for {bytes} bytes"
        );

        // And no path anywhere near the depth a forest could hold. Sixty-four
        // is the count of trees at 2^64 leaves; this chain's deepest tree is
        // twenty-three, which is what the figure above is made of.
        let deepest = draw(seed(7), SAMPLES, u128::from(blocks), levels_for(blocks))
            .into_iter()
            .filter_map(|work| tree_of(blocks, u64::try_from(work).ok()?))
            .map(|(height, _)| height)
            .max()
            .expect("the draw opened something");
        assert!(
            deepest <= 23,
            "the deepest path a thirty-year draw takes is {deepest} levels"
        );
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

    /// The break, closed: a stated height buys no halvings.
    ///
    /// The chain is 2048 blocks old by its own clock, and says so. Whatever it
    /// says about its height, the count is the one those 2048 blocks earn.
    #[test]
    fn a_stated_height_no_longer_buys_halvings() {
        let params = ConsensusParams::testnet();
        let honest = 2_048u64;
        let mut tip = bare_header();
        tip.height = honest;
        tip.timestamp = params.opens_at + honest * params.target_block_time;
        assert_eq!(levels_of(&tip, &params), levels_for(honest));

        for stated in [honest * 64, honest * 1_000_000, 1 << 61, u64::MAX] {
            tip.height = stated;
            assert_eq!(
                levels_of(&tip, &params),
                levels_for(honest),
                "a stated height of {stated} moved the count"
            );
        }
    }

    /// And the height is still read, where it can only take halvings away.
    ///
    /// Ten blocks mined over a year are ten blocks. Counting the halvings from
    /// the year would spread nine of them over the last block, which is nine
    /// levels' worth of draws asking a question already answered.
    #[test]
    fn a_stalled_chain_halves_over_its_blocks_and_not_over_its_years() {
        let params = ConsensusParams::testnet();
        let mut tip = bare_header();
        tip.height = 10;
        tip.timestamp = params.opens_at + 365 * 24 * 60 * 60;
        assert_eq!(levels_of(&tip, &params), levels_for(10));
        assert_eq!(levels_of(&tip, &params), FEWEST_LEVELS);
    }

    /// A chain dated before its own network opened halves once, not forever.
    #[test]
    fn a_tip_older_than_its_network_counts_no_halvings_from_its_clock() {
        let params = ConsensusParams::testnet();
        let mut tip = bare_header();
        tip.height = 1 << 40;
        tip.timestamp = params.opens_at.saturating_sub(1);
        assert_eq!(levels_of(&tip, &params), FEWEST_LEVELS);
    }

    /// Every halving is drawn from as often as every other.
    ///
    /// The level used to come from one byte reduced by `levels`, and 256 does
    /// not divide by 14: four levels drew 19 times in 256 and ten drew 18, so
    /// the four deepest ran 3.9 percent over and the ten nearest the tip 1.6
    /// percent under. At this many draws the noise is a third of a percent, so
    /// the bound below refuses the old shape and passes the new one with room.
    #[test]
    fn every_halving_is_drawn_from_as_often_as_every_other() {
        const DRAWS: usize = 1 << 20;
        let levels = levels_for(30 * 365 * 24 * 60);
        assert_eq!(levels, 14, "the size every published figure is quoted at");

        let total = 1u128 << 100;
        let mut counts = vec![0usize; usize::try_from(levels).unwrap()];
        for value in draw(seed(5), DRAWS, total, levels) {
            // Which band the value came from, read back out of it: a band runs
            // from `total >> (level + 1)` behind the tip up to `total >> level`.
            let distance = total - value;
            let level = (0..levels)
                .find(|level| {
                    distance > total >> level.saturating_add(1) && distance <= total >> level
                })
                .expect("every drawn value sits in a band");
            counts[usize::try_from(level).unwrap()] += 1;
        }

        // Whole numbers throughout: `off * 50 < even` is a deviation under two
        // per cent, and the old shape ran four levels at nearly four.
        let even = DRAWS / usize::try_from(levels).unwrap();
        for (level, count) in counts.iter().enumerate() {
            let off = count.abs_diff(even);
            assert!(
                off * 50 < even,
                "level {level} drew {count} times against {even}, which is past two percent"
            );
        }
    }

    /// A count of nothing is still a count of one, because a draw with no
    /// levels has no band to land in.
    #[test]
    fn a_draw_over_no_levels_draws_over_one() {
        let total = 1_000_000u128;
        assert_eq!(draw(seed(2), 32, total, 0), draw(seed(2), 32, total, 1));
    }

    #[test]
    fn a_draw_asks_about_work_that_exists() {
        let total = 1_000_000u128;
        for value in draw(seed(1), 256, total, levels_for(1_000)) {
            assert!(value < total, "drew {value}, past a total of {total}");
        }
    }

    /// The same tip has to produce the same questions on both sides, or the
    /// prover is answering a list the verifier never asked for.
    #[test]
    fn a_draw_is_the_same_every_time() {
        let first = draw(seed(7), 64, 9_999_991, levels_for(10_000));
        let second = draw(seed(7), 64, 9_999_991, levels_for(10_000));
        assert_eq!(first, second);
        assert_ne!(
            first,
            draw(seed(8), 64, 9_999_991, levels_for(10_000)),
            "and it turns on the seed"
        );
    }

    /// Denser towards the tip, which is where a chain claiming work it did not
    /// do has to put the claim.
    #[test]
    fn a_draw_leans_towards_the_tip() {
        let total = 1_000_000u128;
        let drawn = draw(seed(3), 4_096, total, levels_for(100_000));
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
        // as a depth rather than hidden, and what it buys is the count: the
        // draw is worth `1/levels` per question, so resolving to one block in
        // thirty years would take twenty-four levels where this takes
        // fourteen, and the same guarantee would cost seven thousand draws
        // instead of four.
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
        assert!(draw(seed(1), 64, 0, levels_for(100)).is_empty());
        assert!(draw(seed(1), 0, 1_000, levels_for(100)).is_empty());
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

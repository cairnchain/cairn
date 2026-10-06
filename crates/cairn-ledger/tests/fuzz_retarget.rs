//! The retarget, against the specification worked by hand.
//!
//! `pow::next_difficulty` carries its arithmetic in 128 bits and saturates
//! where a value would not fit, on an argument written beside it and in the
//! specification: a value too wide to fit is past the clamp at step 10
//! whichever way it was rounded, so saturating gives the exact answer. Fifty
//! vectors from an independent reference hold that at fixed points
//! (`asert_vectors.txt`, read by `the_difficulty_follows_the_clock.rs`).
//! Nothing held it between them, so the argument was checked at the points
//! somebody thought to write down and nowhere else.
//!
//! The reference here is the specification's ten numbered steps done over
//! integers of any size, with no width chosen anywhere and nothing taken from
//! the code under test. The one number it does not write out is `r` at step 8
//! once `s` is 64 or more: `r` is then at least `2^s`, which is past any
//! `high` step 9 can produce, and writing `2^s` out for an `s` near `2^58`
//! would take that many bits. The reference is held to the published vectors
//! first, by its own test below, so a disagreement in the campaign is a
//! disagreement with that independent reference too and not a slip in this
//! one.
//!
//! The draws lean on where a fixed-width implementation goes wrong:
//!
//! - an exponent on either side of a whole number of half lives, where `s`
//!   steps and `f` wraps, and where the floor division of step 5 and a
//!   truncating one part company;
//! - a parent whose clamp lands exactly on `r`, or one either side of it;
//! - the floor, where `r` is nought or one and the clamp's low is one;
//! - saturation: difficulties near `u64::MAX`, a `4 * P` past 64 bits, and
//!   heights and timestamps at either end of `u64`;
//! - block times of 5 and 60, which are the ones the networks use, and now
//!   and then 0, 1 or anything at all.
//!
//! Each of those is counted, and the campaign fails if one was never drawn:
//! a reference that agrees with the code on cases that never reach the clamp
//! says nothing about the clamp.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::cmp::Ordering;
use std::collections::BTreeMap;

use cairn_fuzz::{Campaign, Rng};
use cairn_ledger::block::HeaderSummary;
use cairn_ledger::pow::{next_difficulty, Origin};

/// The vectors the independent reference printed.
const VECTORS: &str = include_str!("asert_vectors.txt");

/// A signed integer of any size, which is what the specification's steps are
/// written over.
///
/// Least significant limb first, with no zero limb at the top, so nought is
/// the empty vector and is never negative.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Int {
    negative: bool,
    limbs: Vec<u64>,
}

fn trimmed(mut limbs: Vec<u64>) -> Vec<u64> {
    while limbs.last() == Some(&0) {
        limbs.pop();
    }
    limbs
}

fn magnitude_cmp(a: &[u64], b: &[u64]) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

fn magnitude_add(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u128;
    for index in 0..a.len().max(b.len()) {
        let sum = u128::from(a.get(index).copied().unwrap_or(0))
            + u128::from(b.get(index).copied().unwrap_or(0))
            + carry;
        out.push(sum as u64);
        carry = sum >> 64;
    }
    out.push(carry as u64);
    trimmed(out)
}

/// `a - b`, for `a` at least `b`.
fn magnitude_sub(a: &[u64], b: &[u64]) -> Vec<u64> {
    assert!(
        magnitude_cmp(a, b) != Ordering::Less,
        "a magnitude went below nought"
    );
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = false;
    for (index, limb) in a.iter().enumerate() {
        let (step, under) = limb.overflowing_sub(b.get(index).copied().unwrap_or(0));
        let (step, under_again) = step.overflowing_sub(u64::from(borrow));
        out.push(step);
        borrow = under || under_again;
    }
    trimmed(out)
}

fn magnitude_mul(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = vec![0u64; a.len() + b.len()];
    for (i, x) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, y) in b.iter().enumerate() {
            let sum = u128::from(*x) * u128::from(*y) + u128::from(out[i + j]) + carry;
            out[i + j] = sum as u64;
            carry = sum >> 64;
        }
        out[i + b.len()] = carry as u64;
    }
    trimmed(out)
}

fn magnitude_shl(a: &[u64], bits: usize) -> Vec<u64> {
    if a.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0u64; bits / 64];
    let shift = bits % 64;
    let mut carry = 0u64;
    for limb in a {
        if shift == 0 {
            out.push(*limb);
        } else {
            out.push((limb << shift) | carry);
            carry = limb >> (64 - shift);
        }
    }
    out.push(carry);
    trimmed(out)
}

fn magnitude_shr(a: &[u64], bits: usize) -> Vec<u64> {
    let skip = bits / 64;
    if skip >= a.len() {
        return Vec::new();
    }
    let shift = bits % 64;
    let mut out = Vec::with_capacity(a.len() - skip);
    for index in skip..a.len() {
        let low = a[index] >> shift;
        let high = if shift == 0 {
            0
        } else {
            a.get(index + 1).copied().unwrap_or(0) << (64 - shift)
        };
        out.push(low | high);
    }
    trimmed(out)
}

/// Quotient and remainder of two magnitudes, one bit at a time, which is slow
/// and has nothing in it to get wrong.
fn magnitude_divrem(a: &[u64], b: &[u64]) -> (Vec<u64>, Vec<u64>) {
    assert!(!b.is_empty(), "a division by nought");
    let mut quotient = vec![0u64; a.len()];
    let mut remainder: Vec<u64> = Vec::new();
    for bit in (0..a.len() * 64).rev() {
        remainder = magnitude_shl(&remainder, 1);
        if (a[bit / 64] >> (bit % 64)) & 1 == 1 {
            remainder = magnitude_add(&remainder, &[1]);
        }
        if magnitude_cmp(&remainder, b) != Ordering::Less {
            remainder = magnitude_sub(&remainder, b);
            quotient[bit / 64] |= 1 << (bit % 64);
        }
    }
    (trimmed(quotient), remainder)
}

impl Int {
    fn signed(negative: bool, limbs: Vec<u64>) -> Self {
        let limbs = trimmed(limbs);
        Self {
            negative: negative && !limbs.is_empty(),
            limbs,
        }
    }

    fn of(value: u128) -> Self {
        Self::signed(false, vec![value as u64, (value >> 64) as u64])
    }

    fn of_signed(value: i128) -> Self {
        let magnitude = Self::of(value.unsigned_abs());
        Self::signed(value < 0, magnitude.limbs)
    }

    fn negated(&self) -> Self {
        Self::signed(!self.negative, self.limbs.clone())
    }

    fn plus(&self, other: &Self) -> Self {
        if self.negative == other.negative {
            return Self::signed(self.negative, magnitude_add(&self.limbs, &other.limbs));
        }
        match magnitude_cmp(&self.limbs, &other.limbs) {
            Ordering::Less => {
                Self::signed(other.negative, magnitude_sub(&other.limbs, &self.limbs))
            }
            _ => Self::signed(self.negative, magnitude_sub(&self.limbs, &other.limbs)),
        }
    }

    fn minus(&self, other: &Self) -> Self {
        self.plus(&other.negated())
    }

    fn times(&self, other: &Self) -> Self {
        Self::signed(
            self.negative != other.negative,
            magnitude_mul(&self.limbs, &other.limbs),
        )
    }

    /// `floor(self / divisor)` for a divisor above nought: toward negative
    /// infinity, as step 5 asks.
    fn floor_div(&self, divisor: &Self) -> Self {
        assert!(!divisor.negative && !divisor.limbs.is_empty());
        let (quotient, remainder) = magnitude_divrem(&self.limbs, &divisor.limbs);
        if !self.negative || remainder.is_empty() {
            return Self::signed(self.negative, quotient);
        }
        Self::signed(true, magnitude_add(&quotient, &[1]))
    }

    /// `self * 2^bits`, for a value not below nought.
    fn shifted_up(&self, bits: usize) -> Self {
        assert!(!self.negative);
        Self::signed(false, magnitude_shl(&self.limbs, bits))
    }

    /// `floor(self / 2^bits)`, for a value not below nought.
    fn shifted_down(&self, bits: usize) -> Self {
        assert!(!self.negative);
        Self::signed(false, magnitude_shr(&self.limbs, bits))
    }

    fn compare(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => magnitude_cmp(&self.limbs, &other.limbs),
            (true, true) => magnitude_cmp(&other.limbs, &self.limbs),
        }
    }

    fn below(&self, other: &Self) -> bool {
        self.compare(other) == Ordering::Less
    }

    /// The value, when it is a `u64`.
    fn small(&self) -> Option<u64> {
        if self.negative {
            return None;
        }
        match self.limbs.as_slice() {
            [] => Some(0),
            [only] => Some(*only),
            _ => None,
        }
    }

    /// The value, when it fits in an `i64` wide enough for a shift count.
    fn shift_count(&self) -> Option<i64> {
        let magnitude = i64::try_from(self.limbs.first().copied().unwrap_or(0)).ok()?;
        if self.limbs.len() > 1 {
            return None;
        }
        Some(if self.negative { -magnitude } else { magnitude })
    }
}

fn int(value: u64) -> Int {
    Int::of(u128::from(value))
}

/// What step 8 produced, before step 10 held it.
#[derive(Clone, Debug)]
enum Scheduled {
    /// Written out exactly.
    Exactly(Int),
    /// `s` is 64 or more, so `r` is at least `2^s` and past any `high`.
    PastAnyHigh,
}

/// Steps 3 to 8, which do not read the parent's difficulty: `r`, and the `n`,
/// `s` and `f` it came from, so the campaign can say what it reached.
#[derive(Clone, Debug)]
struct Schedule {
    n: Int,
    tau: Int,
    s: Int,
    f: u64,
    r: Scheduled,
}

/// The specification's steps 3 to 8, for a block time above nought.
///
/// The bindings carry the specification's letters, so each line can be read
/// against the step it names.
#[allow(clippy::many_single_char_names)]
fn schedule(height: u64, timestamp: u64, origin: Origin, target: u64) -> Schedule {
    assert!(target > 0, "step 2 answers a block time of nought");
    // Step 3. `Q` is read in `reference`, which is the one place it is used.
    let d = int(origin.difficulty.max(1));
    let tau = int(60).times(&int(target));
    // Step 4.
    let n = int(target)
        .times(&int(height))
        .minus(&int(timestamp).minus(&int(origin.timestamp)));
    // Step 5, toward negative infinity.
    let e = n.times(&int(65_536)).floor_div(&tau);
    // Step 6.
    let s = e.floor_div(&int(65_536));
    let f = e
        .minus(&s.times(&int(65_536)))
        .small()
        .filter(|f| *f < 65_536)
        .expect("step 6 leaves f in 0..65536");
    // Step 7.
    let fraction = int(f);
    let cubic = int(195_766_423_245_049)
        .times(&fraction)
        .plus(&int(971_821_376).times(&fraction).times(&fraction))
        .plus(
            &int(5_127)
                .times(&fraction)
                .times(&fraction)
                .times(&fraction),
        )
        .plus(&Int::of(1 << 47))
        .shifted_down(48);
    let factor = int(65_536).plus(&cubic);
    // Step 8: floor(D * factor * 2^s / 65536).
    let product = d.times(&factor);
    let r = if s.below(&int(64)) {
        match s.shift_count() {
            Some(up) if up >= 16 => {
                Scheduled::Exactly(product.shifted_up(usize::try_from(up - 16).unwrap()))
            }
            Some(down) => {
                // `16 - s` past a few hundred leaves nothing of a product
                // under 2^81, and a count that does not fit an `i64` is far
                // past that.
                let down = usize::try_from(16i64.saturating_sub(down).min(1 << 20)).unwrap();
                Scheduled::Exactly(product.shifted_down(down))
            }
            None => Scheduled::Exactly(Int::of(0)),
        }
    } else {
        Scheduled::PastAnyHigh
    };
    Schedule { n, tau, s, f, r }
}

/// Which way step 10 went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Settled {
    /// Step 2: no schedule at all.
    NoSchedule,
    /// `r` stood between `low` and `high`, inclusive.
    AsScheduled,
    /// `r` was below `low` and raised to it.
    RaisedToLow,
    /// `r` was above `high` and lowered to it.
    LoweredToHigh,
}

/// The specification's answer, and the way it got there.
#[derive(Clone, Debug)]
struct Reference {
    answer: u64,
    settled: Settled,
    low: u64,
    high: u64,
    schedule: Option<Schedule>,
}

/// The specification's ten steps. Step 1, a branch with no blocks, is not a
/// question `next_difficulty` is asked: it always has a parent.
fn reference(parent: &HeaderSummary, origin: Origin, target: u64) -> Reference {
    // Step 2.
    if target == 0 {
        let answer = parent.difficulty.max(1);
        return Reference {
            answer,
            settled: Settled::NoSchedule,
            low: answer,
            high: answer,
            schedule: None,
        };
    }
    let schedule = schedule(parent.height, parent.timestamp, origin, target);
    // Step 9.
    let q = int(parent.difficulty.max(1));
    let low = q.floor_div(&int(4)).small().unwrap().max(1);
    let high = q.times(&int(4)).small().unwrap_or(u64::MAX);
    // Step 10.
    let (answer, settled) = match &schedule.r {
        Scheduled::PastAnyHigh => (high, Settled::LoweredToHigh),
        Scheduled::Exactly(r) if r.below(&int(low)) => (low, Settled::RaisedToLow),
        Scheduled::Exactly(r) if int(high).below(r) => (high, Settled::LoweredToHigh),
        Scheduled::Exactly(r) => (r.small().unwrap(), Settled::AsScheduled),
    };
    Reference {
        answer,
        settled,
        low,
        high,
        schedule: Some(schedule),
    }
}

/// The reference reproduces every vector the independent reference printed.
///
/// What makes a disagreement in the campaign below the code's and not this
/// file's: the two references were written apart, in two languages, and
/// agree on all fifty, including the saturating ones and a block time of
/// `u64::MAX`.
#[test]
fn the_reference_reproduces_the_published_vectors() {
    let mut checked = 0usize;
    for line in VECTORS.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 8, "a vector line has eight fields: {line}");
        let number = |index: usize| -> u64 { fields[index].parse().unwrap() };
        let origin = Origin {
            timestamp: number(2),
            difficulty: number(3),
        };
        let parent = HeaderSummary {
            height: number(4),
            timestamp: number(5),
            difficulty: number(6),
        };
        assert_eq!(
            reference(&parent, origin, number(1)).answer,
            number(7),
            "the reference disagrees with vector {}",
            fields[0]
        );
        checked += 1;
    }
    assert_eq!(checked, 50, "the vectors did not all load");
}

/// A `u64` from the places a difficulty, a height or a timestamp goes wrong.
fn edgy(rng: &mut Rng) -> u64 {
    match rng.below(8) {
        0 => rng.edgy_u64(),
        1 => u64::MAX - rng.below(5) as u64,
        2 => rng.below(6) as u64,
        3 => {
            let power = 1u64 << rng.below(64);
            match rng.below(3) {
                0 => power - 1,
                1 => power,
                _ => power.saturating_add(1),
            }
        }
        4 => u64::MAX / 4 + rng.below(3) as u64 - 1,
        _ => rng.edgy_u64() >> rng.below(64),
    }
}

/// The values at the ends of a `u64`, and the few in between where a width
/// runs out.
const ENDS: [u64; 14] = [
    0,
    1,
    2,
    4,
    5,
    60,
    1 << 32,
    1 << 62,
    1 << 63,
    u64::MAX / 4,
    u64::MAX / 4 + 1,
    u64::MAX - 1,
    u64::MAX,
    1_790_800_858,
];

/// Every input at an end at once.
///
/// One field at an end is what the other draws make; several together is
/// where a product of two of them leaves 128 bits and a subtraction after it
/// leaves the sign it should have, which drawing each field on its own
/// reaches about once in a million cases.
fn all_at_the_ends(rng: &mut Rng) -> (u64, Origin, HeaderSummary) {
    let mut end = || rng.pick(&ENDS).copied().unwrap_or(0);
    let target = end();
    let origin = Origin {
        timestamp: end(),
        difficulty: end(),
    };
    let parent = HeaderSummary {
        height: end(),
        timestamp: end(),
        difficulty: end(),
    };
    (target, origin, parent)
}

/// A block time: mostly the two the networks use.
fn block_time(rng: &mut Rng) -> u64 {
    match rng.below(20) {
        0 => 0,
        1 => 1,
        2 => edgy(rng),
        3..=10 => 5,
        _ => 60,
    }
}

/// An opening moment and difficulty, sometimes the ones a network has.
fn origin(rng: &mut Rng) -> Origin {
    let timestamp = match rng.below(4) {
        0 => edgy(rng),
        1 => 0,
        _ => 1_790_800_858 + rng.below(1_000_000) as u64,
    };
    let difficulty = match rng.below(5) {
        0 => edgy(rng),
        1 => 1 + rng.below(8) as u64,
        2 => 1 << 27,
        _ => {
            let power = 1u64 << rng.below(64);
            power.saturating_add(rng.below(3) as u64).saturating_sub(1)
        }
    };
    Origin {
        timestamp,
        difficulty,
    }
}

/// A parent's height and timestamp, and from them the `n` steps 4 to 6 read.
///
/// Mostly drawn by choosing the exponent first: a whole number of half lives
/// `s`, from the clamp's two edges out to saturation, and then `n` within a
/// few seconds of `s * tau`, so that `f` is nought or about to wrap. The
/// timestamp that gives that `n` is worked out backwards, and when it would
/// not fit a `u64` the draw takes the nearest one that does, which is a
/// timestamp at an end of the range and a case worth asking anyway.
fn parent_time(rng: &mut Rng, origin: Origin, target: u64) -> (u64, u64) {
    let height = match rng.below(5) {
        0 => edgy(rng),
        1 => rng.below(4) as u64,
        _ => rng.below(20_000_000) as u64,
    };
    if target == 0 || rng.chance(5) {
        let timestamp = match rng.below(3) {
            0 => edgy(rng),
            1 => origin.timestamp,
            _ => origin
                .timestamp
                .saturating_add(target.saturating_mul(height))
                .saturating_add(rng.below(7_200) as u64)
                .saturating_sub(3_600),
        };
        return (height, timestamp);
    }
    let whole: i128 = match rng.below(6) {
        // Inside the clamp.
        0 => rng.below(9) as i128 - 4,
        // Around the floor for every opening difficulty.
        1 => -(rng.below(80) as i128),
        // Around saturation.
        2 => 40 + rng.below(40) as i128,
        // Far past either.
        3 => i128::from(rng.edgy_u64() >> rng.below(64)) * if rng.bool() { 1 } else { -1 },
        _ => rng.below(140) as i128 - 70,
    };
    let tau = 60 * i128::from(target);
    let near = rng.below(7) as i128 - 3;
    let within = if rng.chance(3) {
        rng.below(usize::try_from(tau.min(1 << 40)).unwrap()) as i128
    } else {
        near
    };
    let n = Int::of_signed(whole)
        .times(&Int::of_signed(tau))
        .plus(&Int::of_signed(within));
    // t = t0 + T * h - n.
    let timestamp = int(origin.timestamp)
        .plus(&int(target).times(&int(height)))
        .minus(&n);
    let timestamp = if timestamp.negative {
        0
    } else {
        timestamp.small().unwrap_or(u64::MAX)
    };
    (height, timestamp)
}

/// A parent difficulty, often placed so the clamp lands on `r` or next to it.
fn parent_difficulty(rng: &mut Rng, origin: Origin, scheduled: Option<&Scheduled>) -> u64 {
    let exact = match scheduled {
        Some(Scheduled::Exactly(r)) => Some(r.clone()),
        _ => None,
    };
    let nudge = rng.below(9) as i128 - 4;
    match (rng.below(6), exact) {
        // `high = 4P` within a few of `r`.
        (0 | 1, Some(r)) => {
            let quarter = r.floor_div(&int(4)).plus(&Int::of_signed(nudge / 2));
            clamped(&quarter)
        }
        // `low = floor(P / 4)` within a few of `r`.
        (2 | 3, Some(r)) => clamped(&r.times(&int(4)).plus(&Int::of_signed(nudge))),
        (4, _) => origin.difficulty,
        _ => edgy(rng),
    }
}

/// A value held to what a `u64` can say.
fn clamped(value: &Int) -> u64 {
    if value.negative {
        return 0;
    }
    value.small().unwrap_or(u64::MAX)
}

/// What the campaign reached, so the run can say it reached each kind.
#[derive(Debug, Default)]
struct Reached {
    by_way: BTreeMap<&'static str, usize>,
}

impl Reached {
    fn saw(&mut self, what: &'static str) {
        *self.by_way.entry(what).or_default() += 1;
    }

    fn count(&self, what: &str) -> usize {
        self.by_way.get(what).copied().unwrap_or(0)
    }
}

/// `next_difficulty` answers what the specification's steps answer, for any
/// parent and any origin.
///
/// Fifty vectors held the code to an independent reference at fixed points,
/// and nothing asked between them. A saturating step that gave the wrong
/// answer for some width of `n` not in the table, or a floor division read as
/// truncation for a fraction not in the table, passed.
#[test]
fn the_retarget_answers_what_the_specification_does() {
    let campaign = Campaign::named("ledger: retarget against the specification");
    let seed = campaign.seed();
    let mut reached = Reached::default();

    let ran = campaign.run(20_000, |case, rng| {
        let (target, origin, parent) = if rng.chance(16) {
            reached.saw("every input at an end");
            all_at_the_ends(rng)
        } else {
            let target = block_time(rng);
            let origin = origin(rng);
            let (height, timestamp) = parent_time(rng, origin, target);
            let scheduled = (target > 0).then(|| schedule(height, timestamp, origin, target).r);
            let difficulty = parent_difficulty(rng, origin, scheduled.as_ref());
            let parent = HeaderSummary {
                height,
                timestamp,
                difficulty,
            };
            (target, origin, parent)
        };
        let HeaderSummary {
            height,
            timestamp,
            difficulty,
        } = parent;

        let expected = reference(&parent, origin, target);
        let answered = next_difficulty(&parent, origin, target);
        assert_eq!(
            answered, expected.answer,
            "case {case} of seed {seed:#x}: the retarget answers {answered} where the \
             specification answers {}, for a parent at height {height} dated {timestamp} \
             at difficulty {difficulty}, an origin dated {} at difficulty {}, and a block \
             time of {target}; the steps: {expected:?}",
            expected.answer, origin.timestamp, origin.difficulty
        );

        match expected.settled {
            Settled::NoSchedule => reached.saw("no schedule"),
            Settled::AsScheduled => reached.saw("as scheduled"),
            Settled::RaisedToLow if expected.low == 1 => reached.saw("the floor"),
            Settled::RaisedToLow => reached.saw("clamped down"),
            Settled::LoweredToHigh if expected.high == u64::MAX => reached.saw("saturated"),
            Settled::LoweredToHigh => reached.saw("clamped up"),
        }
        if let Some(schedule) = &expected.schedule {
            match &schedule.r {
                Scheduled::PastAnyHigh => reached.saw("r past 2^64"),
                Scheduled::Exactly(r) => {
                    if r.compare(&int(expected.low)) == Ordering::Equal
                        || r.compare(&int(expected.high)) == Ordering::Equal
                    {
                        reached.saw("r exactly on the clamp");
                    }
                    if r.small().is_none() {
                        reached.saw("r written out past 64 bits");
                    }
                }
            }
            // Where `n` sits against a whole number of half lives: on it, or
            // one second either side, which is where `s` steps.
            let into = schedule
                .n
                .minus(&schedule.n.floor_div(&schedule.tau).times(&schedule.tau));
            if into.small() == Some(0) {
                reached.saw("n a whole number of half lives");
            } else if into.small() == Some(1)
                || into.plus(&int(1)).compare(&schedule.tau) == Ordering::Equal
            {
                reached.saw("n one second off a whole number");
            }
            // A negative exponent that is not a whole number is where the
            // floor of step 5 and a truncation give different answers.
            if schedule.n.negative && schedule.f != 0 {
                reached.saw("behind, between whole numbers");
            }
            if !schedule.s.below(&int(64)) {
                reached.saw("s of 64 or more");
            }
            if schedule.s.below(&Int::of_signed(-80)) {
                reached.saw("s below -80");
            }
        }
        if difficulty > u64::MAX / 4 {
            reached.saw("4P past 64 bits");
        }
        if target == 5 || target == 60 {
            reached.saw("a network block time");
        }
    });

    eprintln!("ledger: retarget reached {:?}", reached.by_way);
    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    for what in [
        "no schedule",
        "as scheduled",
        "the floor",
        "clamped down",
        "saturated",
        "clamped up",
        "r past 2^64",
        "r exactly on the clamp",
        "r written out past 64 bits",
        "n a whole number of half lives",
        "n one second off a whole number",
        "behind, between whole numbers",
        "s of 64 or more",
        "s below -80",
        "4P past 64 bits",
        "a network block time",
        "every input at an end",
    ] {
        assert!(
            reached.count(what) > 0,
            "the campaign never reached \"{what}\", so it asked nothing there: {:?}",
            reached.by_way
        );
    }
}

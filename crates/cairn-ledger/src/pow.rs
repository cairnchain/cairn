//! Proof of work: targets, difficulty, and the timestamp rules that protect it.

use cairn_primitives::Hash32;

use crate::block::HeaderSummary;

/// Difficulty 1 accepts every hash, so it is the floor a chain can fall to.
pub const MIN_DIFFICULTY: u64 = 1;

/// Blocks the median time past is taken over.
pub const MEDIAN_TIME_WINDOW: usize = 11;

/// The retarget's half life, in target block times.
///
/// A chain one half life ahead of its schedule is asked for twice the
/// difficulty its first block carried, and one half life behind for half.
/// Sixty blocks is an hour on the public networks and five minutes on the
/// devnet. Counted in blocks for the reason the drift allowance in
/// [`crate::validation`] is: what it is measured against is the block time,
/// so a figure in seconds would be right on one network and twelve times
/// wrong on the next, and [`next_difficulty`] works it out from the block time
/// it is given rather than reading a second number that could disagree.
///
/// Measured in `tests/audit_how_fast_the_difficulty_answers.rs` from a chain
/// on schedule, every block taking as long as its difficulty asks of the rate
/// that remains. A hash rate that halves has
/// half of its answer after 35 blocks, which is 60 minutes of chain time, and
/// ninety percent after 147 blocks, three hours and a quarter. A tenfold loss
/// reaches the same ninety percent
/// after 55 blocks and three hours and a quarter.
///
/// Chosen by simulation against the moving average it replaced, in the
/// testnet-8 wave's `tau.py`, `presence.py` and `clamp.py`. An hour answers a
/// genuine loss of nine tenths of the hash rate in about the time the old rule
/// did, 3.8 hours until the blocks are back near their target, and holds a
/// miner that mines a burst and leaves to a stall that grows with the
/// logarithm of what it paid rather than with what it paid. Reaching a
/// difficulty `X` times the honest one takes a branch `log2(X)` half lives
/// ahead of its schedule, about `X` times the honest rate for `tau / ln 2`;
/// the next honest block waits about `X` target times, and the honest chain
/// gives back the branch's lead, `log2(X)` half lives, in all. Measured on
/// both rules on one basis, the honest delay over the next hundred honest
/// blocks against the hours of the honest rate the burst paid
/// (`outcomes.py`, the plan's simulator and seeds, the bound included):
///
/// ```text
///                                   moving average     schedule
/// 2 October burst, 80 blocks        45 h for 51 h      1.0 h for 1.9 h
/// 1 260 times the rate for 5 min    71 h for 117 h     5.6 h for 106 h
/// 1 260 times the rate for 1 h      298 h for 1 177 h  11.3 h for 1 259 h
/// ```
///
/// For the same effort the stall is thirteen to twenty six times shorter, and
/// each further hour of it costs more than the last; a burst as small as the
/// 2 October one still costs the honest chain about half of what it paid,
/// which at that size is an hour. The schedule's figures are held in
/// `tests/the_difficulty_follows_the_clock.rs`. Two hours would halve the
/// first honest block's wait after a burst of the same cost, but add about a
/// half life to the honest chain's delay in all, 8.5 hours against 5.6 for
/// the five minute burst, and answer a real loss in 7.8 hours; half an hour is
/// noisier, and the noise is what a miner switching in and out reads.
pub const HALF_LIFE_IN_BLOCKS: u64 = 60;

/// Ceiling on how far one retarget may move the difficulty, in either
/// direction.
///
/// An honest chain rarely brings the schedule near it. The difficulty a block
/// asks for over its parent's is `2^((T - gap) / tau)`, where `gap` is the
/// parent's own stated solve time, so the bound binds only after a gap more
/// than two half lives longer than the target, or one that runs two half lives
/// backwards. On an honest chain whose hash rate falls fifty times it bound on
/// one block in eighteen thousand.
///
/// A miner that mines a burst and leaves brings it there. Past about 120
/// times the honest difficulty, the first honest block's wait is longer than
/// that, so the block after it is held to a quarter of it and the next to a
/// quarter of that, where the schedule alone would have asked less at once;
/// from a few hundred times on that adds about a third of the first wait to
/// the stall, `X / 3` target times. A miner of 1 260 times the honest rate
/// staying an hour leaves the next hundred honest blocks 11.3 hours late
/// with the bound and 9.6 without it. Past a few thousand times the stall
/// leaves the chain further behind its schedule than the floor's edge, and
/// the honest chain then mines hundreds or thousands of blocks at
/// [`MIN_DIFFICULTY`], with almost no work behind them, while it catches the
/// schedule up: a median of 874 after a departure from 4 096 times and 7 642
/// after 8 192, which the bound brings on sooner and makes longer. Both are
/// held in `tests/the_difficulty_follows_the_clock.rs`.
///
/// Public because the weighing in [`crate::sampling`] reasons from it. Two
/// headers a thousand blocks apart cannot state whatever work they like
/// between them: the difficulty may fall by at most this factor per block and
/// never below [`MIN_DIFFICULTY`], so a number of blocks implies a least
/// amount of work. Reading the constant rather than restating it is what
/// keeps the two rules from drifting apart, and it is the reason the bound
/// stayed when the rule under it changed.
pub const MAX_RETARGET_FACTOR: u128 = 4;

/// How many recent headers a node keeps, its tip included.
///
/// Two rules read them. The median time past reads the last
/// [`MEDIAN_TIME_WINDOW`], and the retarget reads the last one alone, the
/// parent, because its answer depends on where the chain stands against its
/// schedule and not on the path it took there. So ninety one is more than
/// either needs. It is what the moving average the retarget used to be read,
/// ninety gaps, and it stays because the number is on the wire: a handover
/// carries this many headers ending at its ledger, and the run a newcomer
/// weighs starts [`crate::sampling::BELOW_THE_PINNED`] below the deepest
/// header its draw pinned.
///
/// What it is for now, besides the median's eleven, is the reach of what a
/// newcomer judges. Every header of both runs from the second on is held to
/// the retarget and the work sum, so a fork point within the window is one
/// those checks see, and one below it is not. Shrinking it changes both
/// exchanges, so old and new nodes could no longer hand each other a ledger or
/// a weighing: a change for a network that restarts anyway. Its floor would
/// then be twelve and not eleven, since `sampling` asserts the median's whole
/// window below the pinned header, one more than the walk reads.
pub const RECENT_HEADERS: usize = 91;

const _: () = assert!(
    RECENT_HEADERS >= MEDIAN_TIME_WINDOW,
    "a node has to keep at least the headers the median reads"
);

/// Where the retarget's schedule starts: the network's first block.
///
/// Read from the rules a node runs and never from a peer.
/// [`crate::validation::ConsensusParams::origin`] gives the moment the network
/// opened and the difficulty its first block carries, which on every network
/// that pins a first block are that block's own timestamp and difficulty, so
/// a node that joined by handover and never held the first block still has
/// both in its binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    /// When the first block is dated, in seconds since the Unix epoch.
    pub timestamp: u64,
    /// The difficulty the first block carries.
    pub difficulty: u64,
}

/// The retarget's fixed point carries sixteen fractional bits.
const FRACTION_BITS: u32 = 16;

/// One, in that fixed point.
const ONE: i128 = 65_536;

const _: () = assert!(ONE == 1 << FRACTION_BITS);

/// The coefficients of the aserti3-2d cubic, which gives `2^(f / 65536)` in
/// the same fixed point for `0 <= f < 65536` to within 0.013 percent, never
/// decreasing, and stays below twice its value at nought. Bitcoin Cash has
/// computed its targets with these since November 2020; they are copied, not
/// derived, so that a second implementation can copy them too.
const CUBIC: [u128; 3] = [195_766_423_245_049, 971_821_376, 5_127];

/// Half of the `2^48` the cubic is divided by, so the division rounds to the
/// nearest rather than down.
const CUBIC_ROUNDING: u128 = 140_737_488_355_328;

/// The largest block identifier that still satisfies `difficulty`.
///
/// The target is the full range divided by the difficulty, so doubling the
/// difficulty halves the space of acceptable hashes.
pub fn target_for(difficulty: u64) -> [u8; 32] {
    if difficulty <= MIN_DIFFICULTY {
        return [0xff; 32];
    }
    let divisor = u128::from(difficulty);
    let mut quotient = [0u64; 4];
    let mut remainder: u128 = 0;

    for limb in &mut quotient {
        // Long division over the four limbs of an all ones 256 bit value. The
        // remainder is always below the divisor, so shifting it up by one limb
        // and adding the next cannot leave 128 bits.
        let current = remainder
            .checked_shl(64)
            .and_then(|shifted| shifted.checked_add(u128::from(u64::MAX)))
            .unwrap_or(u128::MAX);
        *limb = u64::try_from(current.checked_div(divisor).unwrap_or(0)).unwrap_or(u64::MAX);
        remainder = current.checked_rem(divisor).unwrap_or(0);
    }

    let mut bytes = [0u8; 32];
    for (chunk, limb) in bytes.chunks_mut(8).zip(quotient) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    bytes
}

/// Whether a block identifier is small enough for `difficulty`.
///
/// The identifier is read as a big endian 256 bit number, which is exactly a
/// byte by byte comparison from the front.
pub fn meets_target(id: &Hash32, difficulty: u64) -> bool {
    id.as_bytes().as_slice() <= target_for(difficulty).as_slice()
}

/// The weight a block of this difficulty carries in the fork choice.
///
/// Difficulty is the expected number of hashes, so it is the work directly.
/// Keeping the unit a `u64` lets cumulative work be a `u128` sum instead of
/// 256 bit arithmetic, and the fork choice is not where subtle bugs belong.
pub const fn work_of(difficulty: u64) -> u128 {
    difficulty as u128
}

/// The median of the timestamps of the last [`MEDIAN_TIME_WINDOW`] blocks.
///
/// A block must be later than this rather than later than its parent. A single
/// miner can put any clock it likes in its own header, but it cannot move a
/// median it holds only one vote in, so backdating a block to claim an easier
/// difficulty stops working.
pub fn median_time_past(recent: &[HeaderSummary]) -> Option<u64> {
    let window = recent.len().min(MEDIAN_TIME_WINDOW);
    let start = recent.len().saturating_sub(window);
    let mut timestamps: Vec<u64> = recent
        .get(start..)?
        .iter()
        .map(|summary| summary.timestamp)
        .collect();
    if timestamps.is_empty() {
        return None;
    }
    timestamps.sort_unstable();
    timestamps.get(timestamps.len().saturating_div(2)).copied()
}

/// The difficulty the block after `parent` must carry.
///
/// ASERT, the absolutely scheduled exponentially rising targets of Bitcoin
/// Cash's aserti3-2d, written for difficulty rather than target and anchored
/// at the network's first block. A chain whose parent at height `h` is dated
/// `t` is asked for
///
/// ```text
/// D = D0 * 2^((T * h - (t - t0)) / tau)
/// ```
///
/// where `t0` and `D0` are the first block's timestamp and difficulty, `T` the
/// target block time and `tau` [`HALF_LIFE_IN_BLOCKS`] of them. On schedule
/// the difficulty is the first block's; every half life ahead of the schedule
/// doubles it and every half life behind halves it. The answer is then held
/// within [`MAX_RETARGET_FACTOR`] of the parent's either way, and to
/// [`MIN_DIFFICULTY`] and `u64::MAX`.
///
/// It replaces a weighted moving average over ninety blocks, which rose by the
/// whole bound a block while a burst lasted and fell back only as the burst's
/// blocks left its window, ninety slow blocks later. On 2 October 2026 a
/// stranger mined eighty testnet-7 blocks in two minutes, the average asked
/// the next block for 768 times the difficulty before them, and the network
/// nearly stopped for 33 hours. Here the same eighty blocks, stamped as they
/// were, leave the chain 4 656 seconds further ahead of its schedule, which
/// asks the next block for 2.45 times the difficulty, and the honest miner
/// walks back onto the schedule on its own. What the rule answers depends on
/// where the chain stands, not on the path it took there.
///
/// A miner writing its own timestamps moves only the parent's term, and the
/// median time past and the future limit hold that term as they always did: a
/// block dated ten target times ahead, the most a reader takes, buys a
/// difficulty `2^(-10 / 60)` lower for the one block after it, and the next
/// honest timestamp takes it back, since nothing here remembers the path.
///
/// Exact integer arithmetic, the same on every machine, step by step as the
/// specification states it:
///
/// 1. `n = T * h - (t - t0)`, signed: seconds ahead of the schedule.
/// 2. `e = floor(n * 65536 / tau)`, floored rather than truncated, so that one
///    second behind is a little below `D0` and never `D0` itself.
/// 3. `s = floor(e / 65536)` and `f = e - 65536 * s`, so `0 <= f < 65536`.
/// 4. `factor = 65536 + ((195766423245049 f + 971821376 f^2 + 5127 f^3 +
///    2^47) >> 48)`.
/// 5. `r = floor(D0 * factor * 2^s / 65536)`.
/// 6. The answer is `r` held within `[max(P / 4, 1), min(4 P, 2^64 - 1)]`,
///    `P` the parent's difficulty.
///
/// `D0` and `P` are read as at least one. Intermediates are 128 bits wide and
/// saturate where an exact value would not fit, which happens only where the
/// exact answer is past the bound in step 6 anyway, so the result is the exact
/// one: `tests/asert_vectors.txt` holds the vectors an independent reference
/// computed with unbounded integers, including those.
///
/// A block time of nought is no schedule at all, and the answer is the
/// parent's difficulty. No network has one.
///
/// **The first block is not a question this answers**, since it has no parent.
/// Its difficulty is the network's opening one, and
/// [`crate::validation::expected_difficulty`] answers it. The block after it is
/// answered here like any other, and on every network that pins its first
/// block the exponent is then nought, so it carries the opening difficulty too.
pub fn next_difficulty(parent: &HeaderSummary, origin: Origin, target_block_time: u64) -> u64 {
    let previous = u128::from(parent.difficulty.max(MIN_DIFFICULTY));

    // Every product of two `u64` here fits in 128 bits but one, a height times
    // a block time past 2^127, and that one saturates far past any bound the
    // last step can apply.
    let scheduled = i128::from(target_block_time).saturating_mul(i128::from(parent.height));
    let elapsed = i128::from(parent.timestamp).saturating_sub(i128::from(origin.timestamp));
    let ahead = scheduled.saturating_sub(elapsed);
    let half_life = i128::from(target_block_time).saturating_mul(i128::from(HALF_LIFE_IN_BLOCKS));

    // Euclidean division by a positive divisor is floor division, which is the
    // rounding the specification asks for on both sides of the schedule.
    let Some(exponent) = ahead.saturating_mul(ONE).checked_div_euclid(half_life) else {
        return u64::try_from(previous).unwrap_or(u64::MAX);
    };
    let whole = exponent.div_euclid(ONE);
    let fraction = u128::try_from(exponent.rem_euclid(ONE)).unwrap_or(0);

    let [linear, square, cube] = CUBIC;
    let rise = linear
        .saturating_mul(fraction)
        .saturating_add(square.saturating_mul(fraction.saturating_pow(2)))
        .saturating_add(cube.saturating_mul(fraction.saturating_pow(3)))
        .saturating_add(CUBIC_ROUNDING)
        .checked_shr(48)
        .unwrap_or(0);
    let factor = ONE.unsigned_abs().saturating_add(rise);
    let scaled = u128::from(origin.difficulty.max(MIN_DIFFICULTY)).saturating_mul(factor);

    // `2^s / 65536` as one shift, left or right. Of the two amounts one is
    // always nought, and either one too wide for the value saturates it: to
    // the ceiling going up, to nothing going down.
    let shift = whole.saturating_sub(i128::from(FRACTION_BITS));
    let left = u32::try_from(shift.max(0)).unwrap_or(u32::MAX);
    let right = u32::try_from(shift.min(0).unsigned_abs()).unwrap_or(u32::MAX);
    let asked = 1u128
        .checked_shl(left)
        .and_then(|power| scaled.checked_mul(power))
        .unwrap_or(u128::MAX)
        .checked_shr(right)
        .unwrap_or(0);

    let floor = previous
        .checked_div(MAX_RETARGET_FACTOR)
        .unwrap_or(0)
        .max(u128::from(MIN_DIFFICULTY));
    let cap = previous
        .saturating_mul(MAX_RETARGET_FACTOR)
        .min(u128::from(u64::MAX));
    u64::try_from(asked.clamp(floor, cap)).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn summary(height: u64, timestamp: u64, difficulty: u64) -> HeaderSummary {
        HeaderSummary {
            height,
            timestamp,
            difficulty,
        }
    }

    /// A chain running exactly on schedule at a constant difficulty.
    fn steady(count: u64, spacing: u64, difficulty: u64) -> Vec<HeaderSummary> {
        (0..count)
            .map(|i| summary(i, i * spacing, difficulty))
            .collect()
    }

    #[test]
    fn difficulty_one_accepts_everything() {
        assert_eq!(target_for(1), [0xff; 32]);
        assert_eq!(target_for(0), [0xff; 32]);
        assert!(meets_target(&Hash32::from_bytes([0xff; 32]), 1));
    }

    #[test]
    fn doubling_the_difficulty_halves_the_target() {
        let mut expected = [0xffu8; 32];
        expected[0] = 0x7f;
        assert_eq!(target_for(2), expected);

        let quarter = target_for(4);
        assert_eq!(quarter[0], 0x3f);
    }

    #[test]
    fn a_higher_difficulty_rejects_more_hashes() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x40;
        let id = Hash32::from_bytes(bytes);
        assert!(meets_target(&id, 1));
        assert!(meets_target(&id, 2));
        assert!(!meets_target(&id, 4), "0x40.. is above the quarter target");
    }

    #[test]
    fn work_follows_difficulty() {
        assert_eq!(work_of(1), 1);
        assert_eq!(work_of(1000), 1000);
        assert!(work_of(u64::MAX) > work_of(u64::MAX - 1));
    }

    #[test]
    fn the_median_ignores_a_single_wild_timestamp() {
        let mut recent = steady(11, 60, 1);
        assert_eq!(median_time_past(&recent), Some(300));

        recent[10].timestamp = u64::MAX;
        assert_eq!(
            median_time_past(&recent),
            Some(300),
            "one outlier moved nothing"
        );
        assert_eq!(median_time_past(&[]), None);
    }

    /// Testnet-7's opening, a realistic place for a schedule to start.
    const OPENED: u64 = 1_790_800_858;

    fn origin(difficulty: u64) -> Origin {
        Origin {
            timestamp: OPENED,
            difficulty,
        }
    }

    /// The parent at `height`, dated `offset` seconds from where the schedule
    /// puts it: positive is late, negative is early.
    fn parent_at(height: u64, offset: i64, difficulty: u64) -> HeaderSummary {
        let on_time = OPENED + 60 * height;
        summary(height, on_time.saturating_add_signed(offset), difficulty)
    }

    #[test]
    fn the_block_after_the_first_carries_the_first_blocks_difficulty() {
        for difficulty in [1, 4_096, 1 << 23, 1 << 27, u64::MAX] {
            let first = summary(0, OPENED, difficulty);
            assert_eq!(next_difficulty(&first, origin(difficulty), 60), difficulty);
        }
    }

    #[test]
    fn a_chain_on_schedule_keeps_the_first_blocks_difficulty_at_any_height() {
        for height in [1, 90, 1_000, 525_600, 15_768_000] {
            let parent = parent_at(height, 0, 1 << 27);
            assert_eq!(next_difficulty(&parent, origin(1 << 27), 60), 1 << 27);
        }
    }

    #[test]
    fn a_half_life_ahead_doubles_and_a_half_life_behind_halves() {
        let tau = i64::try_from(60 * HALF_LIFE_IN_BLOCKS).unwrap();
        let base = 1 << 27;
        assert_eq!(
            next_difficulty(&parent_at(1_000, -tau, base), origin(base), 60),
            2 * base
        );
        assert_eq!(
            next_difficulty(&parent_at(1_000, tau, base), origin(base), 60),
            base / 2
        );
        // And the devnet's five seconds make its half life five minutes.
        let devnet = Origin {
            timestamp: OPENED,
            difficulty: 1 << 23,
        };
        let early = summary(400, OPENED + 5 * 400 - 300, 1 << 23);
        assert_eq!(next_difficulty(&early, devnet, 5), 1 << 24);
    }

    /// One second behind is a little below the first block's difficulty, not
    /// the first block's difficulty: the exponent is floored, and truncating
    /// it toward nought would have rounded both sides toward the schedule.
    #[test]
    fn a_second_either_side_of_the_schedule_moves_the_difficulty() {
        let base = 1 << 40;
        let late = next_difficulty(&parent_at(1_000, 1, base), origin(base), 60);
        let early = next_difficulty(&parent_at(1_000, -1, base), origin(base), 60);
        assert!(late < base, "{late}");
        assert!(early > base, "{early}");
    }

    #[test]
    fn a_later_parent_never_asks_for_more() {
        let base = 1 << 30;
        let mut last = u64::MAX;
        for offset in (-40_000..40_000).step_by(97) {
            let asked = next_difficulty(&parent_at(5_000, offset, base), origin(base), 60);
            assert!(asked <= last, "{offset}: {asked} after {last}");
            last = asked;
        }
        assert_eq!(last, base / 4, "and it ends on the bound");
    }

    #[test]
    fn one_retarget_moves_by_at_most_four_times_either_way() {
        let base = 1 << 27;
        let far_early = parent_at(1_000, -36_000, base);
        let far_late = parent_at(1_000, 36_000, base);
        assert_eq!(next_difficulty(&far_early, origin(base), 60), 4 * base);
        assert_eq!(next_difficulty(&far_late, origin(base), 60), base / 4);
    }

    #[test]
    fn the_difficulty_never_falls_below_the_floor() {
        let late = parent_at(100, 3_600 * 40, MIN_DIFFICULTY);
        assert_eq!(next_difficulty(&late, origin(1 << 27), 60), MIN_DIFFICULTY);
        let unstated = parent_at(100, 3_600 * 40, 0);
        assert_eq!(
            next_difficulty(&unstated, origin(1 << 27), 60),
            MIN_DIFFICULTY
        );
    }

    #[test]
    fn a_difficulty_at_the_ceiling_stays_there() {
        let early = parent_at(1_000, -3_600, u64::MAX);
        assert_eq!(next_difficulty(&early, origin(u64::MAX), 60), u64::MAX);
        let everything = summary(u64::MAX, 0, u64::MAX);
        let start = Origin {
            timestamp: 0,
            difficulty: u64::MAX,
        };
        assert_eq!(next_difficulty(&everything, start, u64::MAX), u64::MAX);
    }

    #[test]
    fn no_block_time_is_no_schedule() {
        let parent = parent_at(1_000, 0, 12_345);
        assert_eq!(next_difficulty(&parent, origin(1 << 27), 0), 12_345);
        let unstated = parent_at(1_000, 0, 0);
        assert_eq!(
            next_difficulty(&unstated, origin(1 << 27), 0),
            MIN_DIFFICULTY
        );
    }
}

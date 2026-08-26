//! Proof of work: targets, difficulty, and the timestamp rules that protect it.

use cairn_primitives::Hash32;

use crate::block::HeaderSummary;

/// Difficulty 1 accepts every hash, so it is the floor a chain can fall to.
pub const MIN_DIFFICULTY: u64 = 1;

/// Blocks considered when retargeting.
///
/// Short enough to answer a swing in hash rate within minutes. Bitcoin waits
/// two weeks, which suits a chain nobody can meaningfully swing; on a young
/// chain the same rule freezes the ledger for weeks after rented hash rate
/// leaves.
pub const DIFFICULTY_WINDOW: usize = 90;

/// Blocks the median time past is taken over.
pub const MEDIAN_TIME_WINDOW: usize = 11;

/// A solve time is clamped into this multiple of the target before it can
/// influence the retarget, so a miner cannot move the difficulty far with one
/// dishonest timestamp.
const MAX_SOLVETIME_FACTOR: u64 = 6;

/// Ceiling on how far one retarget may move the difficulty, in either
/// direction. Belt and braces on top of the clamped solve times.
const MAX_RETARGET_FACTOR: u128 = 4;

/// How many recent headers a node has to keep to apply every rule here.
pub const RECENT_HEADERS: usize = if DIFFICULTY_WINDOW > MEDIAN_TIME_WINDOW {
    DIFFICULTY_WINDOW + 1
} else {
    MEDIAN_TIME_WINDOW
};

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

/// The difficulty the next block must carry.
///
/// A linearly weighted moving average: recent solve times count for more than
/// older ones, so the chain answers a change in hash rate within a handful of
/// blocks instead of a fixed epoch.
pub fn next_difficulty(recent: &[HeaderSummary], target_block_time: u64) -> u64 {
    let last = match recent.last() {
        None => return MIN_DIFFICULTY,
        Some(summary) => *summary,
    };

    let available = recent.len().saturating_sub(1).min(DIFFICULTY_WINDOW);
    if available == 0 || target_block_time == 0 {
        return last.difficulty.max(MIN_DIFFICULTY);
    }

    let start = recent.len().saturating_sub(available.saturating_add(1));
    let window = match recent.get(start..) {
        None => return last.difficulty.max(MIN_DIFFICULTY),
        Some(window) => window,
    };

    let ceiling = target_block_time.saturating_mul(MAX_SOLVETIME_FACTOR);
    let mut weighted_solvetime: u128 = 0;
    let mut total_difficulty: u128 = 0;

    for (index, pair) in window.windows(2).enumerate() {
        let [previous, current] = pair else { continue };
        // A timestamp that runs backwards clamps to one second rather than
        // wrapping, and one that runs far ahead clamps to the ceiling.
        let solvetime = current
            .timestamp
            .saturating_sub(previous.timestamp)
            .clamp(1, ceiling);
        let weight = u128::try_from(index.saturating_add(1)).unwrap_or(u128::MAX);
        weighted_solvetime =
            weighted_solvetime.saturating_add(weight.saturating_mul(u128::from(solvetime)));
        total_difficulty = total_difficulty.saturating_add(u128::from(current.difficulty));
    }

    if weighted_solvetime == 0 {
        return last.difficulty.max(MIN_DIFFICULTY);
    }

    let previous = u128::from(last.difficulty).max(1);
    let count = u128::try_from(available).unwrap_or(1);
    // The weights 1..=n sum to n(n+1)/2, so a chain running exactly on schedule
    // produces a weighted solve time of that sum times the target, and the
    // difficulty comes back unchanged.
    let expected = count
        .saturating_mul(count.saturating_add(1))
        .saturating_div(2)
        .saturating_mul(u128::from(target_block_time));

    let average = total_difficulty
        .checked_div(count)
        .unwrap_or(previous)
        .max(1);
    let next = average
        .saturating_mul(expected)
        .checked_div(weighted_solvetime)
        .unwrap_or(previous);

    let floor = previous
        .saturating_div(MAX_RETARGET_FACTOR)
        .max(u128::from(MIN_DIFFICULTY));
    let cap = previous.saturating_mul(MAX_RETARGET_FACTOR);
    let bounded = next.clamp(floor, cap);

    u64::try_from(bounded)
        .unwrap_or(u64::MAX)
        .max(MIN_DIFFICULTY)
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

    #[test]
    fn a_chain_on_schedule_keeps_its_difficulty() {
        let recent = steady(91, 60, 1_000);
        let next = next_difficulty(&recent, 60);
        assert!(
            (950..=1_050).contains(&next),
            "difficulty drifted to {next}"
        );
    }

    #[test]
    fn difficulty_rises_when_blocks_come_too_fast() {
        let recent = steady(91, 15, 1_000);
        assert!(next_difficulty(&recent, 60) > 1_000);
    }

    #[test]
    fn difficulty_falls_when_blocks_come_too_slowly() {
        let recent = steady(91, 240, 1_000);
        assert!(next_difficulty(&recent, 60) < 1_000);
    }

    #[test]
    fn one_retarget_cannot_move_the_difficulty_more_than_fourfold() {
        let mut recent = steady(91, 60, 1_000);
        for entry in &mut recent {
            entry.timestamp = 0;
        }
        assert!(next_difficulty(&recent, 60) <= 4_000);

        let mut recent = steady(91, 60, 1_000);
        for (index, entry) in recent.iter_mut().enumerate() {
            entry.timestamp = index as u64 * 100_000;
        }
        assert!(next_difficulty(&recent, 60) >= 250);
    }

    #[test]
    fn difficulty_never_falls_below_the_floor() {
        let recent = steady(91, 1_000_000, MIN_DIFFICULTY);
        assert_eq!(next_difficulty(&recent, 60), MIN_DIFFICULTY);
    }

    #[test]
    fn a_short_history_is_handled() {
        assert_eq!(next_difficulty(&[], 60), MIN_DIFFICULTY);
        assert_eq!(next_difficulty(&[summary(0, 0, 7)], 60), 7);
        let two = vec![summary(0, 0, 7), summary(1, 60, 7)];
        assert!(next_difficulty(&two, 60) > 0);
    }
}

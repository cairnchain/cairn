//! What each block pays whoever produced it.
//!
//! The reward halves at a fixed interval until it reaches a floor, and then
//! stays at that floor for as long as the chain runs.
//!
//! The floor is the part worth arguing about. A schedule that reaches zero
//! leaves fees as the only thing paying for the work that secures the chain,
//! and nobody has shown that a fee market alone holds up: the question is open
//! on the one chain old enough to be asking it. A chain whose whole claim is
//! that it will still be verifiable in thirty years cannot rest that claim on
//! an open question, so it keeps paying.
//!
//! The floor is small enough that what it adds each year shrinks as a share of
//! what exists, without ever reaching zero.

use cairn_primitives::amount::PEBBLES_PER_CAIRN;
use cairn_primitives::Amount;

/// Blocks between halvings, roughly two years at a sixty second block.
///
/// Counted in blocks rather than in time, so the schedule is a property of the
/// chain and not of anyone's clock.
pub const HALVING_INTERVAL: u64 = 1_051_200;

/// What the first block pays.
pub const INITIAL_REWARD_PEBBLES: u64 = 50 * PEBBLES_PER_CAIRN;

/// What every block pays once halving would take it lower.
pub const TAIL_REWARD_PEBBLES: u64 = PEBBLES_PER_CAIRN / 100;

/// The reward at `height`, under a schedule starting at `initial` and never
/// falling below `tail`.
pub fn reward_at(height: u64, interval: u64, initial: Amount, tail: Amount) -> Amount {
    if interval == 0 {
        return initial;
    }
    let halvings = height.checked_div(interval).unwrap_or(0);
    let shift = u32::try_from(halvings).unwrap_or(u32::MAX);
    let halved = initial.as_pebbles().checked_shr(shift).unwrap_or(0);
    let pebbles = halved.max(tail.as_pebbles());
    Amount::from_pebbles(pebbles).unwrap_or(tail)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn initial() -> Amount {
        Amount::from_pebbles(INITIAL_REWARD_PEBBLES).unwrap()
    }

    fn tail() -> Amount {
        Amount::from_pebbles(TAIL_REWARD_PEBBLES).unwrap()
    }

    fn reward(height: u64) -> Amount {
        reward_at(height, HALVING_INTERVAL, initial(), tail())
    }

    #[test]
    fn the_reward_holds_then_halves() {
        assert_eq!(reward(0), initial());
        assert_eq!(reward(HALVING_INTERVAL - 1), initial());
        assert_eq!(
            reward(HALVING_INTERVAL).as_pebbles(),
            initial().as_pebbles() / 2
        );
        assert_eq!(
            reward(HALVING_INTERVAL * 2).as_pebbles(),
            initial().as_pebbles() / 4
        );
    }

    #[test]
    fn the_reward_never_reaches_zero() {
        assert_eq!(reward(HALVING_INTERVAL * 20), tail());
        assert_eq!(reward(HALVING_INTERVAL * 1_000), tail());
        assert_eq!(reward(u64::MAX), tail());
        assert!(
            reward(u64::MAX) > Amount::ZERO,
            "the work never stops being paid for"
        );
    }

    #[test]
    fn the_reward_only_ever_falls() {
        let mut previous = reward(0);
        for halvings in 0..24u64 {
            let now = reward(halvings * HALVING_INTERVAL);
            assert!(now <= previous, "a reward rose at halving {halvings}");
            previous = now;
        }
    }

    /// Every pebble the halvings pay out, read off the shipped schedule.
    ///
    /// An era pays one reward for the whole interval, so an era is a
    /// multiplication rather than a walk of a million heights.
    /// `tests/audit_emission.rs` sums the same schedule height by height and
    /// arrives at the same figure, which is what makes either of them worth
    /// reading.
    fn before_the_floor() -> u128 {
        let mut total: u128 = 0;
        let mut height = 0u64;
        while reward(height) > tail() {
            total = total.saturating_add(
                u128::from(reward(height).as_pebbles())
                    .saturating_mul(u128::from(HALVING_INTERVAL)),
            );
            height = height.saturating_add(HALVING_INTERVAL);
        }
        total
    }

    #[test]
    fn what_the_halvings_add_up_to() {
        // A geometric series: the whole schedule before the floor is twice what
        // one interval pays at the starting rate.
        let in_cairn = before_the_floor() / u128::from(PEBBLES_PER_CAIRN);
        assert_eq!(
            in_cairn, 105_107_167,
            "the schedule before the floor pays out {in_cairn} CAIRN"
        );
    }

    #[test]
    fn the_floor_adds_little_and_less_over_time() {
        // A year of floor rewards at a sixty second block.
        let blocks_per_year: u128 = 525_600;
        let yearly = blocks_per_year.saturating_mul(u128::from(tail().as_pebbles()))
            / u128::from(PEBBLES_PER_CAIRN);
        assert_eq!(yearly, 5_256);
        // Under a tenth of a percent a year of what the halvings pay out, and
        // the share only falls as the total grows.
        //
        // Measured against the schedule rather than against a number written
        // here. The number written here was twenty one million: Bitcoin's, in
        // the one file whose whole subject is that this schedule is not
        // Bitcoin's. It went unnoticed because the claim held either way, and
        // holds by five times the margin against the real figure.
        let whole = before_the_floor() / u128::from(PEBBLES_PER_CAIRN);
        assert!(
            yearly.saturating_mul(1_000) < whole,
            "{yearly} CAIRN a year is not a tenth of a percent of {whole}"
        );
    }
}

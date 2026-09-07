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

/// Every pebble the schedule has paid out by `height`, counting that height.
///
/// The most a chain can hold there. A block issues whatever its coinbase
/// claims and no more than the schedule allows, and a fee the coinbase
/// declines to claim is destroyed, so what a chain has at a height is at most
/// this and never more. It is the one thing about a handed over ledger that
/// can be checked against the rules rather than against a commitment whoever
/// sent it wrote.
///
/// Summed by era rather than by height, because the caller is a rule on a
/// received message and a walk of thirteen million heights is not.
///
/// The answer is clamped at the monetary ceiling. Nothing that can be weighed
/// against this sits above the ceiling, so a figure above it would bound
/// nothing the type does not already bound, and no chain reaches one: the
/// floor takes about a hundred and seventy thousand years to add the
/// difference.
pub fn emitted_by(height: u64, interval: u64, initial: Amount, tail: Amount) -> Amount {
    let blocks = u128::from(height).saturating_add(1);
    let mut paid: u128 = 0;
    let mut left = blocks;
    if interval > 0 {
        let era = u128::from(interval);
        let mut halvings: u32 = 0;
        // Ends after at most as many turns as an amount has bits, because the
        // rate reaches the floor by then whatever the floor is.
        while left > 0 {
            let rate = initial.as_pebbles().checked_shr(halvings).unwrap_or(0);
            if rate <= tail.as_pebbles() {
                break;
            }
            let here = left.min(era);
            paid = paid.saturating_add(u128::from(rate).saturating_mul(here));
            left = left.saturating_sub(here);
            halvings = halvings.saturating_add(1);
        }
    }
    // What is left pays the floor, which is what `reward_at` answers once
    // halving would take it lower. A schedule with no interval never halves,
    // so its floor is the opening rate.
    let floor = if interval == 0 { initial } else { tail };
    paid = paid.saturating_add(u128::from(floor.as_pebbles()).saturating_mul(left));
    u64::try_from(paid)
        .ok()
        .and_then(Amount::from_pebbles)
        .unwrap_or(Amount::MAX_MONEY)
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

    /// The running total against the schedule it is a total of.
    ///
    /// Two computations that share nothing but the answer: one walks every
    /// height and adds up what [`reward_at`] pays there, the other jumps era
    /// by era. A closed form that drifts from the schedule it describes is the
    /// exact shape of defect this project has shipped before, and this one is
    /// about to be a rule a node refuses a ledger on.
    #[test]
    fn the_running_total_is_the_schedule_added_up_height_by_height() {
        // A schedule small enough to walk whole, with a halving every four
        // blocks and a floor reached inside it.
        let interval = 4u64;
        let opening = Amount::from_pebbles(64).unwrap();
        let floor = Amount::from_pebbles(3).unwrap();
        let mut walked: u64 = 0;
        for height in 0..64u64 {
            walked = walked
                .checked_add(reward_at(height, interval, opening, floor).as_pebbles())
                .unwrap();
            assert_eq!(
                emitted_by(height, interval, opening, floor).as_pebbles(),
                walked,
                "the two disagree at height {height}"
            );
        }

        // And on the schedule that ships, at every boundary that matters.
        for height in [
            0,
            1,
            HALVING_INTERVAL - 1,
            HALVING_INTERVAL,
            13 * HALVING_INTERVAL - 1,
            13 * HALVING_INTERVAL,
            13 * HALVING_INTERVAL + 1,
        ] {
            let stated = emitted_by(height, HALVING_INTERVAL, initial(), tail());
            let below = emitted_by(
                height.saturating_sub(1),
                HALVING_INTERVAL,
                initial(),
                tail(),
            );
            let step = if height == 0 {
                stated
            } else {
                stated.checked_sub(below).unwrap()
            };
            assert_eq!(step, reward(height), "the step at height {height}");
        }
    }

    /// The whole schedule before the floor, stated once by the running total.
    ///
    /// The figure the project publishes, reached by the function a node uses
    /// to bound a ledger rather than by a sum written for the occasion.
    #[test]
    fn the_running_total_reaches_the_published_figure() {
        let last_paying = 13 * HALVING_INTERVAL - 1;
        let total = emitted_by(last_paying, HALVING_INTERVAL, initial(), tail());
        assert_eq!(total.as_pebbles(), 10_510_716_795_955_200);
        assert_eq!(
            u128::from(total.as_pebbles()) / u128::from(PEBBLES_PER_CAIRN),
            105_107_167
        );
        assert_eq!(
            u128::from(total.as_pebbles()),
            before_the_floor(),
            "the era walk and the running total are the same number"
        );
    }

    /// A schedule that never halves, and one asked about a height no chain
    /// reaches.
    #[test]
    fn the_running_total_holds_at_both_extremes() {
        // No interval means the opening rate for ever, which is the largest
        // number the schedule can be asked for.
        assert_eq!(
            emitted_by(9, 0, initial(), tail()).as_pebbles(),
            initial().as_pebbles().checked_mul(10).unwrap()
        );
        // Past what an amount can hold, the answer is the ceiling rather than
        // a wrap: no supply sits above it, so nothing is loosened.
        assert_eq!(
            emitted_by(u64::MAX, HALVING_INTERVAL, initial(), tail()),
            Amount::MAX_MONEY
        );
        assert_eq!(
            emitted_by(0, HALVING_INTERVAL, initial(), tail()),
            initial()
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

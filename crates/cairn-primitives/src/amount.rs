//! Monetary amounts.

use std::fmt;

/// Number of indivisible units in one CAIRN.
pub const PEBBLES_PER_CAIRN: u64 = 100_000_000;

/// A quantity of money, counted in pebbles.
///
/// Every operation is checked. The type deliberately implements no `Add` or
/// `Sub`, because silent wraparound in a monetary type is how chains mint
/// money by accident.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Self = Self(0);

    /// Hard ceiling on any single amount and on any sum of amounts.
    ///
    /// The figure is provisional, since the emission schedule is not settled.
    /// What consensus relies on is the ceiling itself: it keeps any realistic
    /// sum of validated amounts far below `u64::MAX`, so an overflow becomes a
    /// validation failure instead of a wraparound.
    pub const MAX_MONEY: Self = Self(2_100_000_000_000_000);

    /// Returns `None` if `pebbles` exceeds [`Amount::MAX_MONEY`].
    pub const fn from_pebbles(pebbles: u64) -> Option<Self> {
        if pebbles > Self::MAX_MONEY.0 {
            None
        } else {
            Some(Self(pebbles))
        }
    }

    pub const fn as_pebbles(self) -> u64 {
        self.0
    }

    /// Returns `None` on overflow or if the result exceeds [`Amount::MAX_MONEY`].
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(sum) => Self::from_pebbles(sum),
            None => None,
        }
    }

    /// Returns `None` if `other` is larger than `self`.
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        match self.0.checked_sub(other.0) {
            Some(difference) => Some(Self(difference)),
            None => None,
        }
    }

    /// Sums an iterator, failing on overflow or on breaching the ceiling.
    pub fn checked_sum<I: IntoIterator<Item = Self>>(amounts: I) -> Option<Self> {
        amounts.into_iter().try_fold(Self::ZERO, Self::checked_add)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0.checked_div(PEBBLES_PER_CAIRN).unwrap_or_default();
        let fraction = self.0.checked_rem(PEBBLES_PER_CAIRN).unwrap_or_default();
        write!(f, "{whole}.{fraction:08} CAIRN")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ceiling_is_enforced_on_construction() {
        assert!(Amount::from_pebbles(Amount::MAX_MONEY.as_pebbles()).is_some());
        assert!(Amount::from_pebbles(Amount::MAX_MONEY.as_pebbles() + 1).is_none());
        assert!(Amount::from_pebbles(u64::MAX).is_none());
    }

    #[test]
    fn addition_cannot_exceed_the_ceiling() {
        let half = Amount::from_pebbles(Amount::MAX_MONEY.as_pebbles()).unwrap();
        assert!(half.checked_add(Amount::from_pebbles(1).unwrap()).is_none());
    }

    #[test]
    fn subtraction_cannot_go_negative() {
        let one = Amount::from_pebbles(1).unwrap();
        assert!(Amount::ZERO.checked_sub(one).is_none());
        assert_eq!(one.checked_sub(one), Some(Amount::ZERO));
    }

    #[test]
    fn sum_reports_overflow() {
        let big = Amount::MAX_MONEY;
        assert!(Amount::checked_sum([big, big]).is_none());
        let one = Amount::from_pebbles(1).unwrap();
        assert_eq!(
            Amount::checked_sum([one, one, one]),
            Amount::from_pebbles(3)
        );
    }

    #[test]
    fn display_keeps_eight_decimals() {
        let amount = Amount::from_pebbles(123_456_789).unwrap();
        assert_eq!(amount.to_string(), "1.23456789 CAIRN");
        assert_eq!(Amount::ZERO.to_string(), "0.00000000 CAIRN");
    }
}

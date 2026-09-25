//! Counting a campaign's two arms apart.
//!
//! Every campaign in this repository is built the same way: some inputs are
//! assembled from nothing by the generator, and the rest are a corpus entry
//! with bytes changed. They reach different code and they fail differently,
//! and until the audit that added this module every campaign counted them
//! together under one `assert!(accepted > 0)`.
//!
//! One counter over two arms is a guard that passes while one of them is
//! dead. That was not a hypothetical: counted apart, the arm built from
//! nothing accepted zero inputs in every campaign that existed, because
//! [`crate::Rng::bytes`] draws boundary values and four boundary bytes are
//! almost never a length a decoder will act on. The campaigns went on passing
//! for as long as the other arm kept working, which is what an assertion that
//! cannot fail buys.
//!
//! So the arms are counted apart, printed apart, and guarded apart. A test
//! using this should write two assertions and not one, and each should name
//! the arm it is about, because the whole value of the split is in the
//! failure message.

/// Which of a campaign's two arms an input came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Built {
    /// Assembled by the generator with no corpus entry behind it.
    FromNothing,
    /// A corpus entry with bytes changed, through [`crate::mutate`].
    ByBending,
}

/// What one arm fed a decoder, and how much of it the decoder took.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arm {
    fed: usize,
    pub accepted: usize,
}

impl Arm {
    fn saw(&mut self, accepted: bool) {
        self.fed = self.fed.saturating_add(1);
        if accepted {
            self.accepted = self.accepted.saturating_add(1);
        }
    }

    /// What share of this arm a decoder took, in parts per thousand.
    ///
    /// Integer, because this is printed beside two counts and a percentage
    /// with a decimal point in it invites reading the number as a
    /// measurement of something rather than as the shape of the run.
    #[must_use]
    fn per_thousand(&self) -> usize {
        self.accepted
            .saturating_mul(1_000)
            .checked_div(self.fed)
            .unwrap_or(0)
    }
}

/// The two arms of one campaign, kept apart.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arms {
    pub from_nothing: Arm,
    pub by_bending: Arm,
}

impl Arms {
    /// Records one input and whether the thing under test accepted it.
    pub fn saw(&mut self, built: Built, accepted: bool) {
        match built {
            Built::FromNothing => self.from_nothing.saw(accepted),
            Built::ByBending => self.by_bending.saw(accepted),
        }
    }

    /// Writes both arms to stderr.
    ///
    /// To stderr and not into a return value, for the reason
    /// [`crate::Campaign::run`] prints its own count: a campaign that reached
    /// nothing passes every test that asserts refusal, so the counts are the
    /// only thing in the output that says the run meant anything.
    pub fn report(&self, what: &str) {
        eprintln!(
            "{what}: from nothing {}/{} accepted ({} per thousand), by bending {}/{} accepted ({} per thousand)",
            self.from_nothing.accepted,
            self.from_nothing.fed,
            self.from_nothing.per_thousand(),
            self.by_bending.accepted,
            self.by_bending.fed,
            self.by_bending.per_thousand(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_arm_counts_only_its_own() {
        let mut arms = Arms::default();
        arms.saw(Built::FromNothing, true);
        arms.saw(Built::FromNothing, false);
        arms.saw(Built::ByBending, false);

        assert_eq!(arms.from_nothing.fed, 2);
        assert_eq!(arms.from_nothing.accepted, 1);
        assert_eq!(arms.by_bending.fed, 1);
        assert_eq!(arms.by_bending.accepted, 0);
    }

    /// The failure the module exists for: one arm carrying the other.
    ///
    /// A single counter over both of these reads as two acceptances and says
    /// nothing is wrong. This is the assertion that tells them apart.
    #[test]
    fn a_dead_arm_is_visible_beside_a_live_one() {
        let mut arms = Arms::default();
        for _ in 0..1_000 {
            arms.saw(Built::FromNothing, false);
            arms.saw(Built::ByBending, true);
        }
        assert_eq!(arms.from_nothing.accepted, 0);
        assert_eq!(arms.from_nothing.per_thousand(), 0);
        assert_eq!(arms.by_bending.per_thousand(), 1_000);
    }

    #[test]
    fn an_arm_that_was_never_fed_is_a_share_of_nothing_rather_than_a_division_by_it() {
        assert_eq!(Arm::default().per_thousand(), 0);
    }
}

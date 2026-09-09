//! Running a generator for a stated number of cases, or for a stated time.
//!
//! A fuzz test in a suite has to answer to two things that pull against each
//! other. It has to run on every change, which means it has to be quick, and a
//! quick campaign finds what a quick campaign finds. So there are two of them
//! and they are the same code: a small deterministic count in `cargo test`,
//! and a budget in seconds behind an environment variable for the campaign
//! that is meant to find something.
//!
//! This follows `CAIRN_AUDIT_FULL_DIR` in `cairn-store/tests/audit_out_of_room.rs`,
//! which puts the tests that need a small filesystem behind a variable and
//! says so when they are skipped. The difference is that nothing here is
//! skipped without it: the short campaign always runs.

use std::time::{Duration, Instant};

use crate::{seed_for, Rng};

/// The run every campaign uses when nothing says otherwise.
///
/// Fixed rather than drawn from the clock, because a suite whose cases change
/// between runs is a suite where a regression that reappears on Tuesday can be
/// argued away as noise on Wednesday.
pub const DEFAULT_SEED: u64 = 0xCA12_F022_1D05_CA12;

/// What a campaign did, for the test to report and to assert a floor on.
#[derive(Clone, Copy, Debug)]
pub struct Ran {
    pub cases: usize,
    pub elapsed: Duration,
    pub seed: u64,
}

/// One named campaign, with its case count and its seed settled.
#[derive(Clone, Copy, Debug)]
pub struct Campaign {
    name: &'static str,
    seed: u64,
    cases: Option<usize>,
    budget: Option<Duration>,
}

impl Campaign {
    /// Reads the environment once and settles what this campaign will do.
    #[must_use]
    pub fn named(name: &'static str) -> Self {
        Self {
            name,
            seed: read("CAIRN_FUZZ_SEED").unwrap_or(DEFAULT_SEED),
            cases: read("CAIRN_FUZZ_CASES"),
            budget: read("CAIRN_FUZZ_SECONDS").map(Duration::from_secs),
        }
    }

    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// The generator for one case, reachable from the seed and the number
    /// alone.
    #[must_use]
    pub fn stream(&self, case: usize) -> Rng {
        Rng::new(seed_for(self.seed, case))
    }

    /// Runs `body` once per case, `quick` times unless the environment says
    /// otherwise.
    ///
    /// `body` is handed the case number and that case's own generator. It
    /// should not carry state between cases beyond counters, because a case
    /// that only fails after the ninety thousand before it is not a case
    /// anybody can reproduce.
    pub fn run<F: FnMut(usize, &mut Rng)>(&self, quick: usize, mut body: F) -> Ran {
        let started = Instant::now();
        let mut cases = 0usize;

        if let Some(budget) = self.budget {
            // Checked every case rather than every so many, because one case
            // here can involve mining and one can involve four bytes.
            while started.elapsed() < budget {
                let mut rng = self.stream(cases);
                body(cases, &mut rng);
                cases = cases.saturating_add(1);
            }
        } else {
            let wanted = self.cases.unwrap_or(quick);
            while cases < wanted {
                let mut rng = self.stream(cases);
                body(cases, &mut rng);
                cases = cases.saturating_add(1);
            }
        }

        let ran = Ran {
            cases,
            elapsed: started.elapsed(),
            seed: self.seed,
        };
        // Written to stderr rather than returned only, because the number of
        // cases is the whole of what a campaign's result means and a test that
        // passes silently could have run none.
        eprintln!(
            "{}: {} cases, seed {:#x}, {:.2?}",
            self.name, ran.cases, ran.seed, ran.elapsed
        );
        ran
    }
}

/// Reads one number out of the environment, ignoring anything unreadable.
///
/// Ignoring rather than failing, because a mistyped variable should leave the
/// suite running its usual cases rather than turning a fuzz test into a
/// configuration error.
fn read<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether the environment is steering this run.
    ///
    /// These two tests are about the default behaviour, and a long campaign
    /// replaces it. Running them anyway under `CAIRN_FUZZ_SECONDS` would spend
    /// the budget twice over on a loop that fuzzes nothing.
    fn steered() -> bool {
        std::env::var("CAIRN_FUZZ_CASES").is_ok() || std::env::var("CAIRN_FUZZ_SECONDS").is_ok()
    }

    #[test]
    fn a_campaign_runs_the_count_it_was_asked_for() {
        if steered() {
            eprintln!("skipped: the environment is steering the case count");
            return;
        }
        let campaign = Campaign::named("counting");
        let mut seen = 0usize;
        let ran = campaign.run(64, |_, rng| {
            let _ = rng.next_u64();
            seen = seen.saturating_add(1);
        });
        assert_eq!(ran.cases, 64);
        assert_eq!(seen, 64);
    }

    #[test]
    fn a_case_is_reachable_on_its_own() {
        if steered() {
            eprintln!("skipped: the environment is steering the case count");
            return;
        }
        let campaign = Campaign::named("reaching");
        let mut from_the_run = None;
        campaign.run(200, |case, rng| {
            if case == 137 {
                from_the_run = Some(rng.next_u64());
            }
        });
        assert_eq!(from_the_run, Some(campaign.stream(137).next_u64()));
    }
}

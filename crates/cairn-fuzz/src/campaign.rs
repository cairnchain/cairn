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

use std::ffi::OsString;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{seed_for, Rng};

/// The run every campaign uses when nothing says otherwise.
///
/// Fixed rather than drawn from the clock, because a suite whose cases change
/// between runs is a suite where a regression that reappears on Tuesday can be
/// argued away as noise on Wednesday.
pub(crate) const DEFAULT_SEED: u64 = 0xCA12_F022_1D05_CA12;

/// What a campaign did, for the test to report and to assert a floor on.
#[derive(Clone, Copy, Debug)]
pub struct Ran {
    pub cases: usize,
    elapsed: Duration,
    seed: u64,
}

/// One named campaign, with its case count and its seed settled.
#[derive(Clone, Debug)]
pub struct Campaign {
    name: &'static str,
    seed: u64,
    cases: Option<usize>,
    budget: Option<Duration>,
    /// Where a case that fails is written down.
    kept_in: PathBuf,
}

impl Campaign {
    /// Reads the environment once and settles what this campaign will do.
    ///
    /// # Panics
    ///
    /// When `CAIRN_FUZZ_SEED` is set to something that is not a seed. See
    /// [`replaying`].
    #[must_use]
    pub fn named(name: &'static str) -> Self {
        Self {
            name,
            seed: replaying(std::env::var_os("CAIRN_FUZZ_SEED")),
            cases: read("CAIRN_FUZZ_CASES"),
            budget: read("CAIRN_FUZZ_SECONDS").map(Duration::from_secs),
            kept_in: kept_under(Path::new(env!("CARGO_MANIFEST_DIR")), name),
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
    ///
    /// A case whose body panics is written down before the panic goes on to
    /// fail the test: see [`Campaign::keep`].
    pub fn run<F: FnMut(usize, &mut Rng)>(&self, quick: usize, mut body: F) -> Ran {
        let started = Instant::now();
        let mut cases = 0usize;

        if let Some(budget) = self.budget {
            // Checked every case rather than every so many, because one case
            // here can involve mining and one can involve four bytes.
            while started.elapsed() < budget {
                self.one(cases, &mut body);
                cases = cases.saturating_add(1);
            }
        } else {
            let wanted = self.cases.unwrap_or(quick);
            while cases < wanted {
                self.one(cases, &mut body);
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

    /// Runs one case, and writes it down if it fails.
    fn one<F: FnMut(usize, &mut Rng)>(&self, case: usize, body: &mut F) {
        let mut rng = self.stream(case);
        // Unwind safety is not a question here: the panic is not recovered
        // from, only noted on its way out.
        if let Err(failure) = panic::catch_unwind(AssertUnwindSafe(|| body(case, &mut rng))) {
            let said = failure
                .downcast_ref::<&str>()
                .map(|said| (*said).to_owned())
                .or_else(|| failure.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            self.keep(case, &said);
            panic::resume_unwind(failure);
        }
    }

    /// Writes down a case that failed, and says where.
    ///
    /// A failure used to be a message in a log and nothing else: the nightly
    /// run's seven failures in September were each a seed, a case number and a
    /// sentence in a log kept for ninety days, and several of the messages
    /// did not carry the case number at all. What is written here is enough to
    /// run that one case again with the variables and the command it names, and
    /// it is written to a file so a workflow can keep it after the log is
    /// gone. It is also printed, because the file is not always read.
    fn keep(&self, case: usize, said: &str) {
        let replay = format!(
            "CAIRN_FUZZ_SEED={:#x} CAIRN_FUZZ_CASES={} {}",
            self.seed,
            case.saturating_add(1),
            this_test()
        );
        let record = format!(
            "campaign: {}\nseed: {:#x} ({} in decimal)\ncase: {case}\nreplay: {replay}\nfailed with: {said}\n",
            self.name, self.seed, self.seed
        );
        let file = self
            .kept_in
            .join(format!("seed-{:x}-case-{case}.txt", self.seed));
        let written = std::fs::create_dir_all(&self.kept_in)
            .and_then(|()| std::fs::write(&file, &record))
            .map_or_else(
                |error| format!("and could not be written down: {error}"),
                |()| format!("kept in {}", file.display()),
            );
        eprintln!(
            "{}: case {case} of seed {:#x} failed, {written}. Replay it with {replay}",
            self.name, self.seed
        );
    }
}

/// Where the failing cases of the campaign called `name` are written, for a
/// crate whose manifest is in `manifest`.
///
/// `target/fuzz/<campaign>/` at the root of the workspace, which is the one
/// directory every checkout has and none commits. The workspace is found from
/// the crate rather than from the test's working directory, because cargo runs
/// each test from its own crate's directory.
fn kept_under(manifest: &Path, name: &str) -> PathBuf {
    let workspace = manifest
        .ancestors()
        .nth(2)
        .map_or_else(|| manifest.to_path_buf(), Path::to_path_buf);
    let folder: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    workspace.join("target").join("fuzz").join(folder)
}

/// The seed a run replays, read in either form a log shows it.
///
/// Every campaign prints its seed as `0x...`, which is where a person copies
/// it from, and the workflow's last line prints it in decimal. Both are read.
///
/// Anything else stops the run rather than being ignored, and this is the one
/// variable where that is the right answer. A case count or a budget that
/// cannot be read leaves the usual cases, which are a fine answer; a seed
/// that cannot be read is a replay asked for and not given, and falling back
/// to the default ran another campaign, which passed and was read as the
/// failure not reproducing.
fn replaying(given: Option<OsString>) -> u64 {
    let Some(given) = given else {
        return DEFAULT_SEED;
    };
    given
        .to_str()
        .and_then(seed_from)
        .unwrap_or_else(|| not_a_seed(&given))
}

/// A seed written in decimal or as `0x` and hexadecimal digits.
fn seed_from(text: &str) -> Option<u64> {
    let text = text.trim();
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(digits) => (digits, 16),
        None => (text, 10),
    };
    // Digits and nothing else: `from_str_radix` also takes a sign, which no
    // seed a campaign printed ever carried.
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

// A panic is denied across this workspace because a panic at run time is a
// node that stops. This crate ships in nothing, and here the panic fails the
// test that asked for a replay, which is the answer that test is owed.
#[allow(clippy::panic)]
fn not_a_seed(given: &OsString) -> u64 {
    panic!(
        "CAIRN_FUZZ_SEED is \"{}\", which is neither a decimal number nor 0x and \
         hexadecimal digits; a replay that ran some other seed would pass and prove nothing",
        given.display()
    )
}

/// The command that runs the one test a campaign is in, from what the running
/// test can tell about itself: the package cargo names in `CARGO_PKG_NAME`, the
/// test binary, named after the file it was built from with a hash after it,
/// and the thread the test harness runs each test on, named after the test.
///
/// A replay line gave the two variables and nothing else. They are read by
/// every campaign in the binary, so running the binary under them failed
/// every other campaign's floor on its own case count beside the one being
/// replayed. Whatever cannot be told is left out rather than guessed.
fn replay_command(package: Option<&str>, binary: Option<&str>, test: Option<&str>) -> String {
    let Some(package) = package else {
        return "cargo test".to_owned();
    };
    let mut command = format!("cargo test -p {package}");
    if let Some(binary) = binary {
        let stem = binary
            .rsplit_once('-')
            .filter(|(_, hash)| !hash.is_empty() && hash.chars().all(|c| c.is_ascii_hexdigit()))
            .map_or(binary, |(stem, _)| stem);
        if stem == package.replace('-', "_") {
            command.push_str(" --lib");
        } else {
            command.push_str(" --test ");
            command.push_str(stem);
        }
    }
    if let Some(test) = test.filter(|name| *name != "main") {
        command.push_str(" -- --exact ");
        command.push_str(test);
    }
    command
}

/// [`replay_command`] for the test running on this thread.
fn this_test() -> String {
    let package = std::env::var("CARGO_PKG_NAME").ok();
    let binary = std::env::args_os().next().and_then(|path| {
        Path::new(&path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_owned)
    });
    replay_command(
        package.as_deref(),
        binary.as_deref(),
        std::thread::current().name(),
    )
}

/// Reads one number out of the environment, ignoring anything unreadable.
///
/// Ignoring rather than failing, because a mistyped variable should leave the
/// suite running its usual cases rather than turning a fuzz test into a
/// configuration error. Not the seed: see [`replaying`].
fn read<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok()?.trim().parse().ok()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
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

    /// A campaign given a time budget runs cases for that long, and says
    /// which seed it ran from.
    ///
    /// This is how the nightly run drives every campaign, through
    /// `CAIRN_FUZZ_SECONDS`, and no test here ever set a budget: the loop
    /// that honours one was reached by nothing, so a loop that ran no case at
    /// all passed, and every nightly campaign would have reported nought cases
    /// and succeeded.
    #[test]
    fn a_campaign_with_a_budget_runs_until_it_is_spent() {
        let campaign = Campaign {
            name: "budgeted",
            seed: 0xabcd,
            cases: None,
            budget: Some(Duration::from_millis(20)),
            kept_in: std::env::temp_dir(),
        };
        assert_eq!(campaign.seed(), 0xabcd);
        let ran = campaign.run(1, |_, rng| {
            let _ = rng.next_u64();
        });
        assert!(
            ran.cases > 1,
            "a twenty millisecond budget ran {} cases",
            ran.cases
        );
        assert!(
            ran.elapsed >= Duration::from_millis(20),
            "and stopped early"
        );
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

    /// A seed is read in both forms a log shows it, and in no other.
    ///
    /// Every campaign prints `seed 0x...` and the workflow prints the same
    /// seed in decimal. Only decimal was read, and anything else was taken as
    /// no seed at all. Nothing asked this, so a seed that could not be typed
    /// back as it was printed passed.
    #[test]
    fn a_seed_is_read_in_either_form_a_log_shows_it() {
        for seed in [0, 1, 0x4d2f_3a1b, DEFAULT_SEED, u64::MAX] {
            assert_eq!(
                seed_from(&format!("{seed:#x}")),
                Some(seed),
                "a seed as a campaign prints it"
            );
            assert_eq!(
                seed_from(&format!(" {seed}\n")),
                Some(seed),
                "a seed as the workflow prints it"
            );
        }
        assert_eq!(seed_from("0XFF"), Some(255));
        for unreadable in [
            "", "0x", "seed", "0x12g", "0x+12", "+12", "-1", "1e3", "0x1_0",
        ] {
            assert_eq!(
                seed_from(unreadable),
                None,
                "a value that is not a seed was read as one"
            );
        }
        assert_eq!(seed_from("0x10000000000000000"), None, "sixty five bits");
        assert_eq!(replaying(None), DEFAULT_SEED);
        assert_eq!(replaying(Some(OsString::from("0x2a"))), 42);
    }

    /// A seed that cannot be read stops the run instead of running another.
    ///
    /// It used to be ignored, like a case count that cannot be read, and the
    /// run went on from the default seed: a replay that replayed nothing,
    /// passed, and was read as the failure not reproducing. Nothing asked
    /// this, so a mistyped seed that quietly ran the default campaign passed.
    #[test]
    #[should_panic(expected = "CAIRN_FUZZ_SEED is \"0x4d2f3a1b,\"")]
    fn a_seed_that_cannot_be_read_stops_the_run() {
        let _ = replaying(Some(OsString::from("0x4d2f3a1b,")));
    }

    /// A case that fails is written down with what replays it, and the
    /// failure still fails.
    ///
    /// A failure used to be a message in a log and nothing else, and the log
    /// is gone after ninety days. Nothing asked this, so a campaign that kept
    /// nothing of a failing case, or that swallowed the failure while keeping
    /// it, passed.
    #[test]
    fn a_failing_case_is_written_down_with_what_replays_it() {
        let directory = std::env::temp_dir().join(format!(
            "cairn-fuzz-kept-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let campaign = Campaign {
            name: "failing",
            seed: 0xabcd,
            cases: Some(10),
            budget: None,
            kept_in: directory.join("failing"),
        };
        let mut drawn_there = None;
        let failed = panic::catch_unwind(AssertUnwindSafe(|| {
            campaign.run(10, |case, rng| {
                if case == 7 {
                    drawn_there = Some(rng.next_u64());
                    panic!("the property does not hold");
                }
            })
        }));
        assert!(failed.is_err(), "the failing case was swallowed");

        let kept = directory.join("failing").join("seed-abcd-case-7.txt");
        let record = std::fs::read_to_string(&kept).expect("the failing case was not kept");
        assert!(
            record.contains("seed: 0xabcd (43981 in decimal)"),
            "{record}"
        );
        assert!(record.contains("case: 7"), "{record}");
        assert!(
            record.contains("failed with: the property does not hold"),
            "{record}"
        );
        let held = std::fs::read_dir(directory.join("failing"))
            .unwrap()
            .count();
        assert_eq!(held, 1, "cases that passed were kept too");
        let replay_line = record
            .lines()
            .find(|line| line.starts_with("replay: "))
            .unwrap_or_default();
        assert!(
            replay_line.contains("cargo test -p cairn-fuzz --lib"),
            "the replay line does not say which test binary the campaign is in: {record}"
        );
        if std::thread::current()
            .name()
            .is_some_and(|name| name != "main")
        {
            assert!(
                replay_line
                    .contains("-- --exact campaign::tests::a_failing_case_is_written_down_with_what_replays_it"),
                "the replay line does not name the one test to run, so every other campaign \
                 in the binary runs under its variables and fails its own floor: {record}"
            );
        }

        // And what it says to run does reach that case, with that stream.
        let replay = record
            .lines()
            .find_map(|line| line.strip_prefix("replay: "))
            .expect("no replay line");
        let mut seed = None;
        let mut cases = None;
        for setting in replay.split_whitespace() {
            if let Some(value) = setting.strip_prefix("CAIRN_FUZZ_SEED=") {
                seed = Some(replaying(Some(OsString::from(value))));
            }
            if let Some(value) = setting.strip_prefix("CAIRN_FUZZ_CASES=") {
                cases = value.parse::<usize>().ok();
            }
        }
        let again = Campaign {
            name: "replayed",
            seed: seed.expect("no seed in the replay line"),
            cases,
            budget: None,
            kept_in: directory.join("replayed"),
        };
        let mut drawn_again = None;
        let mut last = None;
        again.run(1, |case, rng| {
            last = Some(case);
            if case == 7 {
                drawn_again = Some(rng.next_u64());
            }
        });
        assert_eq!(
            last,
            Some(7),
            "the replay does not stop at the failing case"
        );
        assert_eq!(drawn_again, drawn_there, "the replay drew another case");
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The command a replay line gives names the package, the test binary and
    /// the one test, whichever kind of test the campaign is in.
    ///
    /// It named the two variables and nothing else, and they are read by every
    /// campaign in the binary, whose floors on their own case counts then
    /// failed beside the one being replayed. Nothing asked what the line
    /// runs.
    #[test]
    fn a_replay_line_runs_the_one_test_the_campaign_is_in() {
        assert_eq!(
            replay_command(
                Some("cairn-wallet"),
                Some("fuzz_history-2ec1b7e32afcc5a1"),
                Some("histories_hold")
            ),
            "cargo test -p cairn-wallet --test fuzz_history -- --exact histories_hold"
        );
        assert_eq!(
            replay_command(
                Some("cairn-explorer"),
                Some("cairn_explorer-0badc0de"),
                Some("api::tests::owners")
            ),
            "cargo test -p cairn-explorer --lib -- --exact api::tests::owners"
        );
        assert_eq!(
            replay_command(Some("cairn-net"), Some("fuzz_wire-00ff"), Some("main")),
            "cargo test -p cairn-net --test fuzz_wire",
            "a test run on the main thread has no name to give"
        );
        assert_eq!(
            replay_command(None, None, None),
            "cargo test",
            "what cannot be told is left out, not guessed"
        );
        assert_eq!(
            replay_command(Some("cairn-net"), Some("fuzz_wire"), None),
            "cargo test -p cairn-net --test fuzz_wire",
            "a binary name with no hash after it is taken whole"
        );
        assert_eq!(
            replay_command(Some("cairn-net"), Some("fuzz_wire-after"), None),
            "cargo test -p cairn-net --test fuzz_wire-after",
            "what follows the last hyphen was cut off as a hash when it is not one"
        );
    }

    /// Failing cases go under the workspace's own `target`, one folder a
    /// campaign.
    ///
    /// Where a workflow has to look for them, so it is held rather than left
    /// to whatever a test's working directory is: cargo runs each test from
    /// its own crate, and a folder under that would be a different place for
    /// every campaign. Nothing asked it before there was anything to keep.
    #[test]
    fn failing_cases_are_kept_under_the_workspace_target() {
        let crate_at = Path::new("/w/crates/cairn-store");
        assert_eq!(
            kept_under(crate_at, "store: block log framing"),
            Path::new("/w/target/fuzz/store--block-log-framing")
        );
        let this = Campaign::named("this crate");
        assert!(
            this.kept_in.ends_with("target/fuzz/this-crate"),
            "{}",
            this.kept_in.display()
        );
        assert!(
            this.kept_in
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .is_some_and(|root| root.join("Cargo.lock").exists()),
            "the folder is not at the root of the workspace: {}",
            this.kept_in.display()
        );
    }
}

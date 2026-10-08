//! The nightly run fits its timeout, counted from the files it runs.
//!
//! `CAIRN_FUZZ_SECONDS` is a budget per campaign, and cargo runs the test
//! binaries one after another and only the tests inside one binary at once.
//! So the job's wall clock is the seconds times the rounds each target's
//! campaigns take, and the rounds depend on how many run at once. That was
//! the runner's core count, which the workflow did not state: six campaigns
//! were added to a list whose timeout did not move, and whether it still fit
//! depended on a machine nobody had looked at. The workflow now pins the
//! threads and states the count, and this recounts it from the targets.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::Path;

const WORKFLOW: &str = include_str!("../../../.github/workflows/fuzz.yml");

/// What the run is left besides the campaigns: the checkout, the toolchain and
/// a release build of every target, which took two minutes on 8 October 2026.
/// Ten times that, so a slower runner or a larger build still fits.
const BESIDE_THE_CAMPAIGNS_MINUTES: u64 = 20;

/// The number after `key` in the workflow, up to the first character that is
/// not a digit.
fn number_after(key: &str) -> u64 {
    let at = WORKFLOW
        .find(key)
        .unwrap_or_else(|| panic!("the workflow does not say `{key}`"));
    WORKFLOW[at + key.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("no number after `{key}` in the workflow"))
}

/// Every `-p <crate> --test <target>` the campaign step names, in order.
fn targets() -> Vec<(String, String)> {
    let run = &WORKFLOW[WORKFLOW.find("cargo test --release").unwrap()..];
    let mut words = run.split_whitespace();
    let mut package = None;
    let mut named = Vec::new();
    while let Some(word) = words.next() {
        match word {
            "-p" => package = words.next(),
            "--test" => named.push((
                package
                    .expect("a target named before its package")
                    .to_owned(),
                words.next().unwrap().to_owned(),
            )),
            "--" => break,
            _ => {}
        }
    }
    named
}

#[test]
fn the_nightly_run_fits_its_timeout_whatever_the_runner() {
    let threads = number_after("--test-threads=");
    let seconds = number_after("CAIRN_FUZZ_SECONDS: ${{ github.event.inputs.seconds || '");
    assert_eq!(
        seconds,
        number_after("default: \""),
        "the scheduled run and a run by hand start from different budgets"
    );
    let timeout = number_after("timeout-minutes: ");

    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut campaigns = 0;
    let mut rounds = 0;
    let named = targets();
    for (package, target) in &named {
        let file = crates
            .join(package)
            .join("tests")
            .join(format!("{target}.rs"));
        let source = std::fs::read_to_string(&file).unwrap_or_else(|_| {
            panic!("the workflow names {}, which is not there", file.display())
        });
        let here = source.matches("Campaign::named(").count() as u64;
        assert!(
            here <= source.matches("#[test]").count() as u64,
            "{package} --test {target} opens more campaigns than it has tests, and the \
             count below takes every campaign for a test of its own"
        );
        campaigns += here;
        rounds += here.div_ceil(threads);
    }
    let minutes = rounds * seconds / 60;

    for stated in [
        format!("the {campaigns} campaigns of these {} targets", named.len()),
        format!("take {rounds} rounds"),
        format!("which at {seconds} seconds is {minutes}"),
    ] {
        assert!(
            WORKFLOW
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains(&stated),
            "the workflow's arithmetic does not say \"{stated}\", which is what its list \
             and its thread count give"
        );
    }
    assert!(
        minutes + BESIDE_THE_CAMPAIGNS_MINUTES <= timeout,
        "{rounds} rounds of {seconds} seconds is {minutes} minutes of campaigns, which with \
         {BESIDE_THE_CAMPAIGNS_MINUTES} for the build does not fit the {timeout} minute timeout"
    );
}

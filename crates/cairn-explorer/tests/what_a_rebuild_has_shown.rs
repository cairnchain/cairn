//! What `deploy/rebuild.sh` tells a person it has shown, and what the
//! archives are packed with.
//!
//! The rebuild compares the Linux archives it rebuilt, one by default, with
//! their lines in the release's SHA256SUMS. It then said that any download
//! whose hash is in SHA256SUMS was known to be the source, and offered a
//! check of every archive against every line. A SHA256SUMS published beside a
//! swapped macOS archive carries the right Linux line all the same, so the
//! macOS and Windows reader was told their download had been checked against
//! the source when it had not.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// What a rebuild that matched says, having rebuilt only `names`.
#[cfg(unix)]
fn said_after_rebuilding(names: &str) -> String {
    let output = std::process::Command::new("bash")
        .arg(repository().join("deploy/rebuild.sh"))
        .args([
            "--say-what-was-checked",
            names,
            "/tmp/cairn-rebuild.test",
            "0.14.0",
        ])
        .output()
        .expect("bash runs");
    assert!(output.status.success(), "fixture: the script answered");
    String::from_utf8(output.stdout).unwrap()
}

/// **A rebuild says it has shown the archives it rebuilt, and nothing else,
/// and offers a check of those alone.**
#[cfg(unix)]
#[test]
fn a_rebuild_says_it_checked_only_what_it_rebuilt() {
    let said = said_after_rebuilding("linux-x86_64");
    assert!(said.contains("cairn-linux-x86_64.tar.gz"), "{said}");
    for other in ["linux-arm64", "macos", "windows"] {
        assert!(
            !said.contains(other),
            "a rebuild of the x86_64 archive said something of the {other} one: {said}"
        );
    }
    assert!(
        !said.contains("--ignore-missing"),
        "a rebuild offered a check of every archive against lines it did not rebuild: {said}"
    );
    assert!(
        said.contains("gh attestation verify"),
        "a rebuild did not say what checks the archives it did not rebuild: {said}"
    );
    assert!(
        said.contains("temporary directory"),
        "a rebuild sent the reader back to a directory this machine may clear: {said}"
    );
}

/// **The Windows archive is packed by Python 3 under whichever name runs.**
///
/// Named `python`, which the Windows runner has and a Mac or most Linux
/// machines do not, so the script could not be run by hand there for that
/// archive.
#[test]
fn the_zip_is_packed_by_whichever_python_runs() {
    let script = std::fs::read_to_string(repository().join("deploy/release-build.sh")).unwrap();
    let packs = script
        .lines()
        .find(|line| line.contains("release-zip.py"))
        .expect("the script packs the zip with release-zip.py");
    assert!(
        packs.trim_start().starts_with("\"$python\""),
        "the zip is packed by a Python named once, not by the one that runs: {packs}"
    );
    assert!(
        script.contains("if python3 -c '' >/dev/null 2>&1; then"),
        "python3 is not tried by running it"
    );
}

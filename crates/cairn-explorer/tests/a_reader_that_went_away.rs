//! What `cairn-explorer` does when nobody is reading what it writes.
//!
//! The explorer prints its settings when it starts, a line for every seed, and
//! a paragraph when its node stops itself, and whatever reads those lines is
//! not its business: a `tee` that was killed, a log shipper that restarted, a
//! script that read the first line of `--check` and closed the pipe. Rust
//! ignores `SIGPIPE`, so a reader going away arrives as an error from the next
//! write, and `println!` answers that error by panicking. Under the release
//! profile's `panic = "abort"` that is the whole explorer gone, with no line
//! anywhere saying why. `cairnd` was taught this in 31-F1; the explorer wrote
//! every line with `println!`.
//!
//! The pipes below are made with their reading end already closed, so the
//! first write fails every time rather than whenever the scheduler lets the
//! test close it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Output, Stdio};

/// A pipe nobody will ever read, as something a child can write into.
fn nobody_reading() -> Stdio {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    Stdio::from(writer)
}

fn explorer(arguments: &[&str], stdout: Stdio, stderr: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cairn-explorer"))
        .args(arguments)
        .stdout(stdout)
        .stderr(stderr)
        .output()
        .expect("cairn-explorer runs")
}

/// **An explorer asked what it would do, whose answer nobody reads, stops on
/// a code of nought.**
///
/// `--check` prints the settings and stops, and a script updating a machine
/// asks it before anything else. Nothing asked what happens when the script
/// has stopped reading, so an explorer that died on its first line passed.
#[test]
fn an_explorer_nobody_is_reading_answers_check_and_exits_nought() {
    let output = explorer(
        &["--check", "--network", "devnet"],
        nobody_reading(),
        Stdio::piped(),
    );
    let complained = String::from_utf8_lossy(&output.stderr);
    assert!(
        !complained.contains("panicked"),
        "an explorer whose output nobody reads panicked on a line it could not write, which \
         in the shipped build is the whole explorer aborting: {complained}"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "an explorer asked for its settings, whose output nobody read, did not exit nought: \
         {complained}"
    );
}

/// **A command line it cannot use stops it on a code of two, whoever is
/// reading its complaint.**
///
/// The code is what a unit file reads, and two says "the command line", which
/// is the operator's to fix. The complaint went out with `eprintln!`, so an
/// explorer whose standard error was closed turned that two into the 101 of a
/// panic.
#[test]
fn a_command_line_it_cannot_use_stops_it_on_two_with_nobody_reading() {
    let output = explorer(
        &["--network", "moonnet"],
        nobody_reading(),
        nobody_reading(),
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "a command line the explorer cannot use, refused to a closed standard error, did \
         not stop it on a code of two"
    );
}

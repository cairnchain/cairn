//! What `cairn-explorer` tells the machine that started it.
//!
//! Everything else in this crate's suite drives the routes and the index from
//! inside, and nothing ran the program itself. So a `main` that did nothing at
//! all passed, and so did a `run` that answered every command line with
//! success before reading it.
//!
//! Neither case here starts a node: one is refused before it could, and the
//! other asks only for the settings.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, Output};

use cairn_ledger::validation::ConsensusParams;

fn explorer(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cairn-explorer"))
        .args(arguments)
        .output()
        .expect("cairn-explorer runs")
}

/// A command line it cannot use stops it with a code of two, a line saying
/// why, and the usage text.
///
/// Nothing ran the program, so an explorer that exited nought and said
/// nothing when asked for a network that does not exist passed: to a unit
/// file that is a clean stop, and it is never restarted with a name that
/// works.
#[test]
fn a_command_line_it_cannot_use_stops_it_with_a_code_of_two() {
    let output = explorer(&["--network", "moonnet"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a network that does not exist was not refused with a code of two"
    );
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("cairn-explorer: unknown network `moonnet`"),
        "the refusal does not say what was refused"
    );
    assert!(
        said.contains("--check"),
        "and the usage text does not follow it"
    );
}

/// `--check` prints the settings it worked out and stops there, with a code
/// of nought.
///
/// Nothing ran the program, so an explorer that printed nothing for
/// `--check` passed, which leaves a script updating a machine with no way to
/// ask what the explorer would do before it does it.
#[test]
fn check_prints_the_settings_and_stops_with_nought() {
    let output = explorer(&["--check", "--network", "devnet", "--seed", "127.0.0.1:9"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a check of settings it can use did not exit nought"
    );
    let devnet = ConsensusParams::for_network("devnet").unwrap();
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains(&format!(
            "network      devnet (0x{:08x})",
            devnet.network.as_u32()
        )),
        "the check does not say which network it would follow: {said}"
    );
    assert!(
        !said.contains("listening"),
        "and a check starts no node: {said}"
    );
}

/// An argument that is not text is a command line it cannot use, and stops it
/// with a code of two and the usage text.
///
/// Nothing asked this, so the arguments were read with `std::env::args`,
/// which panics on one that is not Unicode, and a data directory named with a
/// stray byte was answered with a Rust panic and 101.
#[cfg(unix)]
#[test]
fn an_argument_that_is_not_text_stops_it_with_a_code_of_two() {
    use std::os::unix::ffi::OsStrExt as _;

    let output = Command::new(env!("CARGO_BIN_EXE_cairn-explorer"))
        .arg("--data")
        .arg(std::ffi::OsStr::from_bytes(b"explorer-\xff"))
        .arg("--check")
        .output()
        .expect("cairn-explorer runs");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        !said.contains("panicked"),
        "an argument that is not text was answered with a panic: {said}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "an argument that is not text was not refused with a code of two: {said}"
    );
    assert!(
        said.contains("--check"),
        "and the usage text does not follow it: {said}"
    );
}

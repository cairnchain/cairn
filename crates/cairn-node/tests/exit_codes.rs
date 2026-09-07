//! What `cairnd` tells the machine that started it.
//!
//! An exit code is the one thing a node says that nobody reads by eye. A unit
//! file with `Restart=on-failure` reads it, `cairnd && ...` reads it, and every
//! shell script anybody wraps this in reads it. So a code that means the
//! opposite of what happened is a failure reported as success at the widest
//! surface this program has.
//!
//! Two of them are held here, and the third, a node that stops itself, is held
//! beside the decision that produces it in `main.rs`: putting a node in that
//! state from the outside means a disk that has filled or a chain whose rules
//! moved on, and neither is something a test can arrange without becoming a
//! worse test than the one it replaced.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairnd-exit-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn cairnd(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cairnd"))
        .args(arguments)
        .output()
        .expect("cairnd runs")
}

/// A node that ran for as long as it was asked leaves by the ordinary door.
///
/// The half that has to go on being true, or the codes carry nothing. This is
/// a node that did what it was started to do and stopped when it was told to.
#[test]
fn a_node_that_ran_for_as_long_as_it_was_asked_exits_nought() {
    let directory = scratch("ran-for");
    let output = cairnd(&[
        "--data",
        &directory.to_string_lossy(),
        "--network",
        "devnet",
        "--listen",
        "127.0.0.1:0",
        "--run-for",
        "1",
        "--status",
        "1",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.contains("stopped"), "{said}");
    assert!(
        !said.contains("stopped on the fault"),
        "nothing was wrong with it: {said}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// `--check` is a setting, so it is read off the settings.
///
/// It used to be found by looking through the words the operator typed for one
/// that read `--check`, which finds it in the one place it is not: standing
/// where another option's value belongs. `--data --check` printed the settings,
/// stopped, and exited nought, having started no node, written nothing to the
/// directory the operator meant to name, and said nothing about any of it. The
/// explorer was mended for this and the node was not.
#[test]
fn a_flag_standing_where_a_value_belongs_is_not_the_flag() {
    let directory = scratch("check");
    let output = cairnd(&[
        "--data",
        &directory.to_string_lossy(),
        "--network",
        "devnet",
        "--check",
    ]);
    assert_eq!(output.status.code(), Some(0), "asked for plainly");
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains("devnet"),
        "and it says what it would do: {said}"
    );
    assert!(
        !directory.exists(),
        "and starts nothing, so the directory is not made"
    );

    let output = cairnd(&["--data", "--check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a missing value is a refusal, not a check: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let complained = String::from_utf8_lossy(&output.stderr);
    assert!(
        complained.contains("another option"),
        "and it names what went wrong: {complained}"
    );
}

/// The floor under `--keep`, said where the figure is said.
///
/// A node keeps the blocks a reorganisation may still have to read back
/// whatever size it is given, because the chain lets go of block bodies from
/// memory on the promise that the log still holds them. Nothing stated that
/// and nothing reported it: `--keep 1MB` printed "1 MB on disk, older ones
/// dropped" and held a hundred and twenty eight times that, and the operator
/// who sized a disk off the printed figure found out from the disk.
#[test]
fn the_floor_under_what_a_node_keeps_is_printed_beside_the_figure() {
    let directory = scratch("keep");
    let output = cairnd(&[
        "--data",
        &directory.to_string_lossy(),
        "--network",
        "testnet-6",
        "--keep",
        "1MB",
        "--check",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.contains("1 MB on disk"), "the budget: {said}");
    assert!(
        said.contains("never below the last 1024 blocks"),
        "and the floor under it, in blocks: {said}"
    );
    assert!(
        said.contains("up to 134 MB"),
        "and what that floor comes to on this network: {said}"
    );

    // `all` has no floor to state, because nothing is dropped.
    let output = cairnd(&[
        "--data",
        &directory.to_string_lossy(),
        "--keep",
        "all",
        "--check",
    ]);
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.contains("every one ever accepted"), "{said}");
    assert!(!said.contains("never below"), "{said}");
}

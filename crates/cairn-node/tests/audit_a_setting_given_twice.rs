//! A setting given twice, and which of the two runs.
//!
//! `options.rs` states the rule above the list of names it knows: a setting
//! that is silently ignored is how an operator ends up running rules they did
//! not choose, which on a chain means following a different one.
//!
//! It was applied to a name the node does not know and not to a name it knows
//! given twice, where the same thing happens by the same road. And the example
//! in that sentence is the case it happens to: `--network devnet --network
//! testnet-6` ran on devnet, said devnet in its summary, and said nothing at
//! all about the testnet-6 it had also been told. Two chains, one of them
//! chosen by which argument came first.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairnd-twice-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn cairnd(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cairnd"))
        .args(arguments)
        .output()
        .expect("cairnd runs")
}

/// What it said, whichever channel it said it on.
fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn two_networks_on_one_command_line_are_refused_rather_than_settled_by_order() {
    let directory = scratch("command-line");
    let output = cairnd(&[
        "--data",
        &directory.to_string_lossy(),
        "--network",
        "devnet",
        "--network",
        "testnet-6",
        "--check",
    ]);
    let words = said(&output);

    assert_ne!(
        output.status.code(),
        Some(0),
        "it started on one of the two networks it was told and said nothing about the other: \
         {words}"
    );
    assert!(
        words.contains("devnet") && words.contains("testnet-6"),
        "the refusal names neither of the two values it is about: {words}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The file has the same rule, because it is the same failure.
#[test]
fn two_networks_in_the_file_are_refused_as_well() {
    let directory = scratch("file");
    std::fs::write(
        directory.join("cairn.conf"),
        "network = devnet\nnetwork = testnet-6\n",
    )
    .unwrap();
    let output = cairnd(&["--data", &directory.to_string_lossy(), "--check"]);
    let words = said(&output);

    assert_ne!(
        output.status.code(),
        Some(0),
        "a file naming two networks started on one of them: {words}"
    );
    assert!(
        words.contains("cairn.conf"),
        "the refusal does not say where the two values are: {words}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// And the same value twice drops nothing, so nothing is said about it.
///
/// The rule is about a value that would be ignored. Two spellings of the same
/// choice ignore nothing, and refusing them would break an invocation that
/// asks for exactly what it gets.
#[test]
fn the_same_value_twice_is_not_a_setting_given_twice() {
    let directory = scratch("same");
    let output = cairnd(&[
        "--data",
        &directory.to_string_lossy(),
        "--network",
        "devnet",
        "--network",
        "devnet",
        "--check",
    ]);
    let words = said(&output);

    assert_eq!(
        output.status.code(),
        Some(0),
        "asking twice for the same network was refused: {words}"
    );
    assert!(words.contains("devnet"), "and it is the network asked for");
    let _ = std::fs::remove_dir_all(&directory);
}

/// A seed is a list and not a setting: every one of them is dialled, so
/// naming two is naming two rather than dropping one.
#[test]
fn two_seeds_are_two_seeds() {
    let directory = scratch("seeds");
    let output = cairnd(&[
        "--data",
        &directory.to_string_lossy(),
        "--network",
        "devnet",
        "--seed",
        "127.0.0.1:1111",
        "--seed",
        "127.0.0.1:2222",
        "--check",
    ]);
    let words = said(&output);

    assert_eq!(
        output.status.code(),
        Some(0),
        "naming two seeds was read as naming one setting twice: {words}"
    );
    assert!(
        words.contains("1111") && words.contains("2222"),
        "and both of them are used: {words}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

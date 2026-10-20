//! `cairn-wallet recover` at the command line: what it refuses, and that it
//! says so before it reads anything.
//!
//! What a recovery finds and what it costs are held in
//! `audit_what_a_restore_on_a_new_machine_finds.rs`, against the library the
//! command runs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-recover-command-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn wallet(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args(arguments)
        .output()
        .expect("the wallet runs")
}

fn a_key(home: &Path) -> PathBuf {
    let key = home.join("key");
    let made = wallet(&["new", key.to_str().unwrap(), "--unsafe-skip-word-check"]);
    assert!(made.status.success(), "fixture: a key was made");
    key
}

/// **`recover` wants a directory named, and refuses one that is already a
/// wallet's, before it reaches anybody.**
///
/// The default --data is where an ordinary wallet keeps its account, which
/// is the one directory a recovery must not read into, so it is not taken as
/// a default; and a directory holding an account is refused with the file
/// named and nothing written to it.
#[test]
fn recover_names_the_directory_it_reads_into_and_refuses_one_in_use() {
    let home = scratch("refusals");
    let key = a_key(&home);

    let unnamed = wallet(&["recover", key.to_str().unwrap(), "--network", "devnet"]);
    let in_use = home.join("in-use");
    std::fs::create_dir_all(&in_use).unwrap();
    std::fs::write(in_use.join("history.dat"), b"").unwrap();
    let refused = wallet(&[
        "recover",
        key.to_str().unwrap(),
        "--network",
        "devnet",
        "--data",
        in_use.to_str().unwrap(),
    ]);
    let written: Vec<_> = std::fs::read_dir(&in_use)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let help = wallet(&["help"]);
    let _ = std::fs::remove_dir_all(&home);

    let unnamed_said = String::from_utf8_lossy(&unnamed.stderr);
    assert!(
        !unnamed.status.success() && unnamed_said.contains("--data <directory>"),
        "recover without --data did not stop and ask for one: {unnamed_said}"
    );
    let refused_said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success() && refused_said.contains("history.dat"),
        "recover over a wallet's account did not refuse it by name: {refused_said}"
    );
    assert_eq!(
        written,
        vec![std::ffi::OsString::from("history.dat")],
        "the refused directory was written to"
    );
    assert!(
        String::from_utf8_lossy(&help.stdout).contains("cairn-wallet recover <key file>"),
        "the help does not say how to recover"
    );
}

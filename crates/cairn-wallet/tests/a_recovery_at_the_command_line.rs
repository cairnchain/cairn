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

/// What a person reads, with the lines folded back into one.
fn read_as_one(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The balance and what is said beside it, from the address line to the list
/// of what happened.
fn the_balance_said(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip_while(|line| !line.starts_with("address"))
        .take_while(|line| !line.starts_with("What happened"))
        .map(str::to_owned)
        .collect()
}

/// **A recovery that reaches the tip says of the money what `balance` says,
/// every line of it, and what to do with a copy of the payments.**
///
/// It printed a balance of its own: the address, the height and the number,
/// without the notes line, without the warning that says the number may not
/// be this wallet's own answer, and without the notes that cannot move yet.
/// That was the one command a person runs having lost everything, and the one
/// that put the number bare.
#[test]
fn a_recovery_that_reaches_the_tip_says_what_balance_says() {
    use cairn_ledger::validation::ConsensusParams;
    use cairn_net::Node;

    let home = scratch("reached");
    let key = a_key(&home);
    let params = ConsensusParams::for_network("devnet").unwrap();
    let (keeper, _) =
        Node::open_archiving(params, "127.0.0.1:0".parse().unwrap(), home.join("keeper")).unwrap();
    let seed = format!("127.0.0.1:{}", keeper.address().port());
    let data = home.join("recovered");
    let both = |command: &str| {
        wallet(&[
            command,
            key.to_str().unwrap(),
            "--network",
            "devnet",
            "--seed",
            &seed,
            "--data",
            data.to_str().unwrap(),
        ])
    };
    let recovered = both("recover");
    let balance = both("balance");
    keeper.shutdown();
    let _ = std::fs::remove_dir_all(&home);

    assert!(
        recovered.status.success(),
        "fixture: the recovery reached the tip of a chain an archivist holds: {}{}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(balance.status.success(), "fixture: balance ran over it");
    let said = the_balance_said(&recovered);
    assert!(
        said.iter()
            .any(|line| line.starts_with("notes") && line.contains("that can move now")),
        "a recovery printed its balance without the lines balance prints beside it: {said:?}"
    );
    assert_eq!(
        said,
        the_balance_said(&balance),
        "a recovery and a balance over the same directory said different things of the money"
    );
    assert!(
        read_as_one(&recovered).contains(
            "If you kept a copy of pending.dat beside history.dat, put it back in the --data \
             directory as well"
        ),
        "a recovery did not say what a copy of the payments keeps: {}",
        read_as_one(&recovered)
    );
}

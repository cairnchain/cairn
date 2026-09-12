//! Settings `cairn.conf` accepted and the node never read.
//!
//! The list of names this node understands carries the reason for refusing one
//! it does not: "A setting that is silently ignored is how an operator ends up
//! running rules they did not choose, which on a chain means following a
//! different one." The rule was applied to names the node does not understand
//! and not to names it understands and then never reads, and three of the
//! eleven are of the second kind: `resolve_options` takes `data`, `help` and
//! `check` from the command line and only from there.
//!
//! So a file carrying one was validated against the list, filed, and dropped
//! without a word. An unknown name stopped the node loudly; a known name that
//! did nothing was accepted in silence; and nothing in the refusal, in the
//! startup summary or in `--check` told the two apart.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairnd-settings-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn with_config(directory: &Path, text: &str) {
    std::fs::write(directory.join("cairn.conf"), text).unwrap();
}

fn cairnd(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cairnd"))
        .args(arguments)
        .output()
        .expect("cairnd runs")
}

/// **A setting the file takes is a setting the node reads.**
///
/// Each of the three is asked for in a file and the node has to say it will
/// not take it there. Refused rather than honoured, because none of the three
/// is a setting: `data` names the directory the file itself was found in, so
/// setting it there cannot mean anything, and `help` and `check` are questions
/// put to the program and answered once.
///
/// `check` is the sharp one. `--check` exists so a script can ask what a node
/// would do without starting one, and `check = yes` in the file started a
/// node, bound a port and wrote a directory: the one outcome the flag exists
/// to avoid, reached by writing the flag down.
#[test]
fn a_name_the_file_may_carry_is_a_name_the_node_reads() {
    for (name, value) in [("data", "/mnt/chain"), ("check", "yes"), ("help", "yes")] {
        let directory = scratch(name);
        with_config(&directory, &format!("{name} = {value}\n"));
        let output = cairnd(&[
            "--data",
            &directory.to_string_lossy(),
            "--network",
            "devnet",
            "--listen",
            "127.0.0.1:0",
            "--run-for",
            "1",
        ]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_ne!(
            output.status.code(),
            Some(0),
            "`{name} = {value}` in cairn.conf was taken and dropped without a word"
        );
        assert!(
            said.contains(name),
            "the refusal has to name the setting it is about: {said}"
        );
    }
}

/// **And the names that are settings still are.**
///
/// The other half, so this cannot pass by refusing everything. A file carrying
/// only names the node reads starts a node and the node runs on them.
#[test]
fn a_file_of_settings_the_node_does_read_starts_a_node() {
    let directory = scratch("ordinary");
    with_config(
        &directory,
        "# what an operator would actually write\n\
         network = devnet\n\
         listen = 127.0.0.1:0\n\
         run-for = 1\n\
         status = 1\n",
    );
    let output = cairnd(&["--data", &directory.to_string_lossy()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.contains("stopped"), "{said}");
}

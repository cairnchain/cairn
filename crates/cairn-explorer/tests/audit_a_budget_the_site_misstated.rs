//! What `cairn-explorer` says it keeps on disk when it is given a budget.
//!
//! A node keeps the blocks a reorganisation may still have to read back
//! whatever size it is given, because the chain lets go of block bodies from
//! memory on the promise that the log still holds them. `cairnd` was mended to
//! say so beside the figure, after `--keep 1MB` printed "1 MB on disk, older
//! ones dropped" and held a hundred and twenty eight times that. The explorer
//! trims through the same node and printed the same figure without the floor.
//!
//! The line is printed after the node is started, so this runs the program,
//! reads until the line after it, and stops it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use cairn_ledger::validation::ConsensusParams;

/// Everything the explorer printed before its restore line, or before it
/// stopped, whichever came first.
fn start_up(arguments: &[&str]) -> Vec<String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cairn-explorer"))
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("cairn-explorer runs");
    let stdout = child.stdout.take().expect("its output is piped");
    let (send, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else {
                return;
            };
            if send.send(line).is_err() {
                return;
            }
        }
    });

    // A liveness bound set far past what a loaded machine needs. The line
    // arrives as soon as the node has opened its directory.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut said = Vec::new();
    while Instant::now() < deadline {
        match lines.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                let last = line.starts_with("restored");
                said.push(line);
                if last {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    said
}

fn scratch(name: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-explorer-budget-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// The floor under `--keep` is said where the explorer says what it keeps, as
/// `cairnd` says it, and `all` has none to state.
///
/// Nothing asked this, so an explorer given a megabyte printed that it kept a
/// megabyte, on a network where the blocks it cannot drop come to several.
#[test]
fn the_floor_under_what_the_site_keeps_is_said_beside_the_figure() {
    let devnet = ConsensusParams::for_network("devnet").unwrap();
    let directory = scratch("one-megabyte");
    let data = directory.to_string_lossy().into_owned();
    let common = [
        "--network",
        "devnet",
        "--data",
        data.as_str(),
        "--listen",
        "127.0.0.1:0",
        "--http",
        "127.0.0.1:0",
        "--seed",
        "127.0.0.1:9",
    ];

    let mut arguments = common.to_vec();
    arguments.extend(["--keep", "1MB"]);
    let said = start_up(&arguments).join("\n");
    assert!(
        said.contains("blocks       1 MB"),
        "the budget is not where the explorer says what it keeps"
    );
    assert!(
        said.contains(&format!("never below the last {} blocks", devnet.burial)),
        "the explorer says it keeps a megabyte, and not that it never drops the \
         blocks a reorganisation may read back, which weigh more"
    );
    assert!(
        said.contains("up to "),
        "the explorer does not say what the floor comes to on this network"
    );

    let _ = std::fs::remove_dir_all(&directory);
    let directory = scratch("all");
    let data = directory.to_string_lossy().into_owned();
    let mut arguments = common.to_vec();
    arguments[3] = data.as_str();
    let said = start_up(&arguments).join("\n");
    assert!(
        said.contains("blocks       every one ever accepted"),
        "an explorer keeping everything does not say so"
    );
    assert!(
        !said.contains("never below"),
        "an explorer that drops nothing states a floor under what it drops"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

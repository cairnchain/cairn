//! What `cairn-explorer` says it keeps on disk when it is given a budget.
//!
//! An explorer keeps the cold set, and the cold set is built by reading every
//! block from the first at every start, so an explorer keeps every block
//! whatever `--keep` says: a node that archives refuses to start over blocks
//! that do not begin at the first. The explorer used to hand its budget to
//! the node, which trimmed, and to print the budget as what it kept; the next
//! start was refused. It says what it keeps now, and why the budget is not it.
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

/// An explorer given a budget says it keeps every block, whatever the budget,
/// and one keeping everything says so plainly.
///
/// It printed the budget, with the floor under it, as what it kept. Nothing
/// asked whether that was true, and it was not: the node trimmed to it, and
/// the explorer could not start again on that directory, since an archive is
/// built from every block.
#[test]
fn an_explorer_given_a_budget_says_it_keeps_every_block() {
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
        said.contains("blocks       every one ever accepted, whatever --keep says"),
        "an explorer given a budget does not say it keeps every block: {said}"
    );
    assert!(
        !said.contains("older ones dropped") && !said.contains("never below"),
        "an explorer given a budget says it drops blocks, which it does not: {said}"
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
        !said.contains("whatever --keep says"),
        "an explorer given no budget speaks of one"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

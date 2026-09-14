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

/// **What a dropped block costs somebody else is printed where the budget is
/// chosen.**
///
/// There are two ways onto this chain and they need different things. Being
/// handed a ledger needs headers, which every node keeps for ever. Reading the
/// chain block by block needs every body, and no node is obliged to keep one:
/// past the budget they go, and a header does not rebuild a deleted body.
///
/// A node at any budget serves newcomers perfectly well while the first way
/// works, and the first way is refused on a chain whose difficulty has fallen
/// far enough below what it once ran at. On that day the second way is the
/// only way in, and whether anybody can take it depends on choices made here,
/// by people who had no way to know they were making one.
#[test]
fn what_dropping_a_block_costs_a_newcomer_is_printed_beside_the_budget() {
    let directory = scratch("keep-costs");
    let output = cairnd(&[
        "--data",
        &directory.to_string_lossy(),
        "--keep",
        "1GB",
        "--check",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains("what is dropped cannot be served"),
        "the budget says what it costs: {said}"
    );
    assert!(
        said.contains("block by block"),
        "and who pays it, which is whoever has to read the chain: {said}"
    );

    // Nothing to say to an operator who keeps everything: they are the ones
    // the sentence is about.
    let output = cairnd(&[
        "--data",
        &directory.to_string_lossy(),
        "--keep",
        "all",
        "--check",
    ]);
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(!said.contains("what is dropped"), "{said}");
}

/// **A node that could not start is not a command line that was wrong.**
///
/// Both used to print the usage text and exit 2, so whatever started this node
/// could not tell "you typed something I cannot read" from "the directory is
/// held by another node". The first is the operator's to fix and the usage
/// text is what fixes it; the second has a command line that is right, and
/// telling that operator to go and look for a mistake sends them somewhere
/// there is nothing to find.
///
/// The reasoning is the one already written on `Ending::Fault`: no usage text,
/// because nothing on the command line was wrong. It was true of that case and
/// of this one, and applied only to that one.
#[test]
fn a_node_that_could_not_start_says_so_without_the_usage_text() {
    let directory = scratch("held");

    // One node holding the directory, for as long as the second one tries.
    let mut holding = Command::new(env!("CARGO_BIN_EXE_cairnd"))
        .args([
            "--data",
            &directory.to_string_lossy(),
            "--network",
            "devnet",
            "--listen",
            "127.0.0.1:0",
            "--run-for",
            "30",
        ])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("cairnd runs");

    // Waited for, not asserted on: what is asserted is what the second node
    // says, and a first node that never took the lock makes this test fail
    // rather than pass.
    let giving_up = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut refused = None;
    while std::time::Instant::now() < giving_up {
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
        if output.status.code() != Some(0) {
            refused = Some(output);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = holding.kill();
    let _ = holding.wait();

    let output = refused.expect("a second node on a held directory is refused");
    let complained = String::from_utf8_lossy(&output.stderr);

    assert!(
        complained.contains("could not start"),
        "it did not say it could not start: {complained}"
    );
    assert!(
        !complained.contains("--data <directory>"),
        "it printed the usage text at an operator whose command line was right: {complained}"
    );
    assert_ne!(
        output.status.code(),
        Some(2),
        "a node that could not start exits on the code a wrong command line exits on, so nothing \
         that starts this node can tell the two apart"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "it stopped without running, which is the code for that"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// And a command line that really is wrong still gets the usage text and the
/// code that goes with it, which is what says the change above is a
/// distinction and not a removal.
#[test]
fn a_command_line_that_cannot_be_read_still_gets_the_usage_text() {
    let output = cairnd(&["--nonsense", "3"]);
    let complained = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{complained}");
    assert!(
        complained.contains("--data <directory>"),
        "an operator who typed something unreadable was not shown what to type: {complained}"
    );
}

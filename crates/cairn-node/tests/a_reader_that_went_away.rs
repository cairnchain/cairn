//! What `cairnd` does when nobody is reading what it writes, or when what it
//! is given to read is not text.
//!
//! A node prints a status line every few seconds for as long as it runs, and
//! whatever reads those lines is not the node's business: a `tee` that was
//! killed, a pager that was quit, a log shipper that restarted. Rust ignores
//! `SIGPIPE`, so a reader going away arrives as an error from the next write,
//! and `println!` answers that error by panicking. Under the release profile's
//! `panic = "abort"` that is the whole node gone, with no line anywhere saying
//! why, because the line that would have said it is the one that could not be
//! written.
//!
//! The pipes below are made with their reading end already closed, so the
//! first write fails every time rather than whenever the scheduler lets the
//! test close it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead as _, Read as _};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairnd-reader-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// Runs a command that is meant to stop on its own, and fails rather than
/// waiting for ever if it does not.
///
/// A command line read as nothing starts a node on the default directory that
/// runs until it is killed, so a test that waited for it would hang rather
/// than say what went wrong.
fn run_to_the_end(command: &mut Command) -> Output {
    let mut child = command.spawn().expect("cairnd runs");
    let started = Instant::now();
    while child.try_wait().expect("cairnd can be waited on").is_none() {
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cairnd was still running a minute after a command line that should stop it");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("cairnd ends")
}

/// A pipe nobody will ever read, as something a child can write into.
fn nobody_reading() -> Stdio {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    Stdio::from(writer)
}

/// A node whose standard output nobody reads runs for as long as it was asked
/// and leaves by the ordinary door.
///
/// Nothing asked this, so a node that died on its first line when its reader
/// had gone passed: every line it writes was a `println!`, and the test that
/// met it in `exit_codes.rs` kept its reader open to step around it.
#[test]
fn a_node_nobody_is_reading_runs_to_the_end_and_exits_nought() {
    let directory = scratch("stdout");
    let output = Command::new(env!("CARGO_BIN_EXE_cairnd"))
        .args([
            "--data",
            &directory.to_string_lossy(),
            "--network",
            "devnet",
            "--listen",
            "127.0.0.1:0",
            "--status",
            "1",
            "--run-for",
            "2",
        ])
        .stdout(nobody_reading())
        .stderr(Stdio::piped())
        .output()
        .expect("cairnd runs");
    let _ = std::fs::remove_dir_all(&directory);
    let complained = String::from_utf8_lossy(&output.stderr);
    assert!(
        !complained.contains("panicked"),
        "a node whose output nobody reads panicked on a line it could not write, which in \
         the shipped build is the whole node aborting: {complained}"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a node asked to run for two seconds, whose output nobody read, did not exit nought: \
         {complained}"
    );
}

/// And the same when the reader goes away while the node is running, which
/// is the way it happens: the node has printed its start and its first status
/// line, and whatever was reading them stops.
///
/// Nothing asked this either, so the status line, which is written every
/// period for as long as the node runs, took the node down on the first
/// period after its reader left.
#[test]
fn a_node_whose_reader_leaves_while_it_runs_carries_on_to_the_end() {
    let directory = scratch("leaves");
    let mut child = Command::new(env!("CARGO_BIN_EXE_cairnd"))
        .args([
            "--data",
            &directory.to_string_lossy(),
            "--network",
            "devnet",
            "--listen",
            "127.0.0.1:0",
            "--status",
            "1",
            "--run-for",
            "4",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cairnd runs");

    let mut stderr = child.stderr.take().unwrap();
    let complaints = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });

    // Up to the first status line, and then the reader goes.
    {
        let stdout = child.stdout.take().unwrap();
        let mut lines = std::io::BufReader::new(stdout).lines();
        loop {
            match lines.next() {
                Some(Ok(line)) if line.starts_with('[') => break,
                Some(Ok(_)) => {}
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the node ended before its first status line");
                }
            }
        }
    }

    let status = child.wait().expect("cairnd ends");
    let complained = complaints.join().unwrap();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        !complained.contains("panicked"),
        "a node whose reader went away panicked on its next status line: {complained}"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a node whose reader went away did not run to the end of --run-for and exit \
         nought: {complained}"
    );
}

/// A command line that cannot be read still exits on the code for one when
/// there is nowhere to say so.
///
/// Nothing asked this, so the message about a misread command line, written
/// with `eprintln!`, panicked on a closed standard error and turned the 2 a
/// supervisor reads into 101.
#[test]
fn a_misread_command_line_exits_two_with_nowhere_to_say_so() {
    let output = run_to_the_end(
        Command::new(env!("CARGO_BIN_EXE_cairnd"))
            .args(["--data", "--check"])
            .stdout(Stdio::null())
            .stderr(nobody_reading()),
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "a misread command line with a closed standard error did not exit on the code for \
         one"
    );
}

/// An argument that is not text is a command line this node cannot read, and
/// is answered as one.
///
/// Nothing asked this, so the arguments were read with `std::env::args`,
/// which panics on one that is not Unicode, and a data directory named with a
/// stray byte was answered with a Rust panic and 101 rather than the usage
/// text and 2.
#[cfg(unix)]
#[test]
fn an_argument_that_is_not_text_is_a_misread_command_line() {
    use std::os::unix::ffi::OsStrExt as _;

    let output = run_to_the_end(
        Command::new(env!("CARGO_BIN_EXE_cairnd"))
            .arg("--data")
            .arg(std::ffi::OsStr::from_bytes(b"cairn-data-\xff"))
            .arg("--check")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let complained = String::from_utf8_lossy(&output.stderr);
    assert!(
        !complained.contains("panicked"),
        "an argument that is not text was answered with a panic: {complained}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "an argument that is not text was not answered as a misread command line: \
         {complained}"
    );
    assert!(
        complained.contains("--data <directory>"),
        "and the usage text did not follow it: {complained}"
    );
}

/// The lines under a status line are written, and a state a healthy node's
/// numbers look exactly like is said in words.
///
/// Nothing ran the binary far enough to ask, so the function that writes them
/// could have written nothing at all. A list of peers that will not write is
/// the state used here: a directory standing where the file goes, which
/// disturbs nothing else about the node.
#[test]
fn a_list_of_peers_that_will_not_write_is_said_under_the_status_line() {
    let directory = scratch("book");
    std::fs::create_dir_all(directory.join("peers.txt")).unwrap();
    let output = run_to_the_end(
        Command::new(env!("CARGO_BIN_EXE_cairnd"))
            .args([
                "--data",
                &directory.to_string_lossy(),
                "--network",
                "devnet",
                "--listen",
                "127.0.0.1:0",
                "--seed",
                "127.0.0.1:9",
                "--status",
                "1",
                "--run-for",
                "6",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let _ = std::fs::remove_dir_all(&directory);
    // One run of words, since the paragraph is wrapped where it falls.
    let said = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        said.contains("is not being written"),
        "a list of peers the disk would not take was not said under the status line: {said}"
    );
}

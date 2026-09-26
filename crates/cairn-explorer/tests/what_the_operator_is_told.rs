//! What `cairn-explorer` tells whoever runs it, the code it exits on, and what
//! its site takes from a stranger.
//!
//! `cairnd` tells a start that failed apart from a command line it could not
//! read, and says every way its disk was short when it opened. The explorer
//! reads the same node through the same open and did neither: every failure
//! printed the usage text and exited two, and a start said two of the ten
//! things the open reports. These run the program.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-explorer-told-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn start(directory: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_cairn-explorer"))
        .args([
            "--data",
            &directory.to_string_lossy(),
            "--network",
            "devnet",
            "--listen",
            "127.0.0.1:0",
            "--http",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("cairn-explorer runs")
}

/// Reads what a running explorer prints up to the line that says where its
/// site is, which is the end of what a start says.
fn what_a_start_says(child: &mut Child) -> (Vec<String>, BufReader<std::process::ChildStdout>) {
    let mut lines = BufReader::new(child.stdout.take().expect("started with a pipe"));
    let mut said = Vec::new();
    loop {
        let mut line = String::new();
        match lines.read_line(&mut line) {
            Ok(0) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the explorer stopped before it opened its site: {said:?}");
            }
            Ok(_) => {
                let done = line.starts_with("open");
                said.push(line.trim_end().to_owned());
                if done {
                    return (said, lines);
                }
            }
        }
    }
}

/// **An explorer that could not start says so, without the usage text, and
/// exits one.**
///
/// A directory held by another explorer, or a port taken, is a command line
/// that was right. The explorer answered every failure with the usage text
/// and a code of two, which sends an operator looking for a typo that is not
/// there and leaves whatever started it unable to tell the two apart;
/// `cairnd` stopped doing that, and `exit_codes.rs` held only the misread
/// command line, so a start that failed any other way passed.
#[test]
fn an_explorer_that_could_not_start_says_so_without_the_usage_text() {
    let directory = scratch("held");
    let mut holding = start(&directory);
    let (_, _held_open) = what_a_start_says(&mut holding);

    let output = Command::new(env!("CARGO_BIN_EXE_cairn-explorer"))
        .args([
            "--data",
            &directory.to_string_lossy(),
            "--network",
            "devnet",
            "--listen",
            "127.0.0.1:0",
            "--http",
            "127.0.0.1:0",
        ])
        .output()
        .expect("cairn-explorer runs");
    let _ = holding.kill();
    let _ = holding.wait();
    let _ = std::fs::remove_dir_all(&directory);
    let complained = String::from_utf8_lossy(&output.stderr);

    assert!(
        complained.contains("could not start"),
        "it did not say it could not start"
    );
    assert!(
        !complained.contains("--data <directory>"),
        "it printed the usage text at an operator whose command line was right"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "an explorer that could not start exits on the code a wrong command line \
         exits on, so nothing that starts it can tell the two apart"
    );
}

/// **A start that found an unfinished write says so.**
///
/// The open reports ten things about the disk and the explorer printed two of
/// them, the blocks and the addresses. Bytes of a write that never finished,
/// cut off the end of the log, were cut without a word.
#[test]
fn a_start_that_cut_an_unfinished_write_says_so() {
    let directory = scratch("torn");
    std::fs::write(directory.join("blocks.log"), [0xAB; 5]).unwrap();

    let mut explorer = start(&directory);
    let (said, _open) = what_a_start_says(&mut explorer);
    let _ = explorer.kill();
    let _ = explorer.wait();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        said.iter().any(|line| line.contains("unfinished write")),
        "a start that dropped the bytes of an unfinished write said nothing about \
         it: {said:?}"
    );
}

/// **The site answers a POST before its body, because it takes none.**
///
/// The explorer has no POST route, and the server under it read a POST's
/// body before routing. Behind the proxy every reader arrives from the
/// loopback, which the per-address ceiling does not count, so one machine
/// sending POST heads that announce a body and never send it held every slot
/// for the whole deadline. The server can now refuse a body before reading
/// it; this holds that the explorer asks it to.
#[test]
fn the_site_answers_a_post_before_its_body() {
    use std::io::{Read, Write};

    let directory = scratch("post");
    let mut explorer = start(&directory);
    let (said, _open) = what_a_start_says(&mut explorer);
    let site = said
        .last()
        .and_then(|line| line.split("http://").nth(1))
        .map(|rest| rest.trim_end_matches('/').to_owned())
        .expect("the start says where the site is");

    let mut stream = std::net::TcpStream::connect(&site).unwrap();
    stream
        .set_read_timeout(Some(cairn_http::http::REQUEST_DEADLINE / 2))
        .unwrap();
    stream
        .write_all(b"POST /api/status HTTP/1.1\r\nhost: x\r\ncontent-length: 4096\r\n\r\n")
        .unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    let _ = explorer.kill();
    let _ = explorer.wait();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        answer.starts_with("HTTP/1.1 405"),
        "the site waited for the body of a POST it has no use for: {answer:?}"
    );
}

//! What the command line says, and when, as a person reads it.
//!
//! These run the binary and read what reaches its standard output, which is
//! the only thing a person at a terminal, or a script reading a pipe, ever
//! sees of it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-command-line-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// How long the wallet is told to wait for a chain that will never come.
const WAIT_SECONDS: u64 = 6;

/// The word that says the wallet is working reaches the screen when the
/// wait begins, not when it ends.
///
/// It was written with `print!` and nothing flushed it, and a standard output
/// is line buffered whether or not it is a terminal, so it arrived with the
/// newline after the wait. Nothing read the output while the wait ran, so a
/// wallet that showed one line and then nothing for thirty seconds, as if
/// hung, passed.
#[test]
fn catching_up_is_said_when_the_wait_begins_and_not_when_it_ends() {
    let home = scratch("catching-up");
    let key = home.join("key");
    let made = Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args(["new", key.to_str().unwrap()])
        .output()
        .expect("the wallet runs");
    assert!(made.status.success(), "fixture: a key was made");

    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args([
            "balance",
            key.to_str().unwrap(),
            "--data",
            home.join("data").to_str().unwrap(),
            "--network",
            "devnet",
            // Nowhere, so no chain ever arrives and the whole wait is spent.
            "--seed",
            "127.0.0.1:9",
            "--wait",
            &WAIT_SECONDS.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the wallet runs");

    // A byte at a time, noting when each line of interest has arrived whole.
    // The pipe only ever holds what the wallet flushed.
    let mut out = child.stdout.take().unwrap();
    let (tell, told) = mpsc::channel::<(&'static str, Duration)>();
    let reader = thread::spawn(move || {
        let mut seen: Vec<u8> = Vec::new();
        let mut byte = [0u8; 1];
        let (mut reached, mut catching) = (false, false);
        while let Ok(1) = out.read(&mut byte) {
            seen.push(byte[0]);
            if !reached && seen.ends_with(b"reached\n") {
                reached = true;
                let _ = tell.send(("reached", started.elapsed()));
            }
            if !catching && seen.ends_with(b"catching up") {
                catching = true;
                let _ = tell.send(("catching up", started.elapsed()));
            }
        }
    });

    let (mut when_reached, mut when_catching) = (None, None);
    while let Ok((what, at)) = told.recv_timeout(Duration::from_secs(WAIT_SECONDS + 30)) {
        if what == "reached" {
            when_reached = Some(at);
        } else {
            when_catching = Some(at);
        }
        if when_reached.is_some() && when_catching.is_some() {
            break;
        }
    }
    let _ = child.wait();
    let _ = reader.join();
    let _ = std::fs::remove_dir_all(&home);

    let reached = when_reached.expect("the line naming the seeds reached arrives");
    let catching = when_catching.expect("`catching up` arrives at some point");
    // The line before it arrived at once, so the pipe and the reader are not
    // what is slow: a gap here is the wallet's own buffering.
    assert!(
        catching < reached + Duration::from_secs(2),
        "`catching up` reached the screen only once the wait was over, so for the whole \
         wait the wallet showed one line and then nothing"
    );
}

/// `--yes` is an option `send` knows, so a script can say in advance what a
/// person at a terminal is now asked.
///
/// `send` asked nothing before an irreversible payment; now it asks at a
/// terminal, and a script that wants the old way says so. Without the option
/// the question would be one a script could not get past.
#[test]
fn a_script_can_answer_yes_in_advance() {
    let home = scratch("answer-yes");
    let key = home.join("key");
    let made = Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args(["new", key.to_str().unwrap()])
        .output()
        .expect("the wallet runs");
    assert!(made.status.success(), "fixture: a key was made");
    let somebody = cairn_crypto::SecretKey::generate()
        .unwrap()
        .public_key()
        .to_string();

    let sent = Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args([
            "send",
            key.to_str().unwrap(),
            "--to",
            &somebody,
            "--amount",
            "1",
            "--yes",
            "--data",
            home.join("data").to_str().unwrap(),
            "--network",
            "devnet",
            "--seed",
            "127.0.0.1:9",
            "--wait",
            "0",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("the wallet runs");
    let _ = std::fs::remove_dir_all(&home);
    let said = String::from_utf8_lossy(&sent.stderr);

    assert!(
        !said.contains("unknown option"),
        "`--yes` is refused as an option `send` does not know"
    );
    assert!(
        said.contains("more than"),
        "a wallet holding nothing was not refused for holding nothing"
    );
}

/// `open` serves a page that says which payments are waiting and which were
/// not carried, and holds nothing back when there are none.
///
/// Nothing ran `open` at all, so a command that printed nothing and served
/// nothing passed, and so did a page whose answer lacked the fields its own
/// script reads to say what became of a payment.
#[test]
fn the_page_open_serves_says_what_became_of_the_payments() {
    use std::io::{BufRead as _, Write as _};

    let home = scratch("open");
    let key = home.join("key");
    let data = home.join("data");
    let made = Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args(["new", key.to_str().unwrap()])
        .output()
        .expect("the wallet runs");
    assert!(made.status.success(), "fixture: a key was made");

    let mut child = Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args([
            "open",
            key.to_str().unwrap(),
            "--data",
            data.to_str().unwrap(),
            "--network",
            "devnet",
            "--seed",
            "127.0.0.1:9",
            "--wait",
            "0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the wallet runs");

    // Standard output is not a terminal here, so the address goes to a file
    // and the line names it.
    let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let written = lines.by_ref().map_while(Result::ok).find_map(|line| {
        line.strip_prefix("open      the address is in ")
            .map(std::path::PathBuf::from)
    });
    let answer = written.and_then(|path| {
        let link = std::fs::read_to_string(path).ok()?;
        let rest = link.trim().strip_prefix("http://")?;
        let (host, query) = rest.split_once("/?")?;
        let mut stream = std::net::TcpStream::connect(host).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok()?;
        write!(
            stream,
            "GET /api/state?{query} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n"
        )
        .ok()?;
        let mut said = String::new();
        let _ = std::io::Read::read_to_string(&mut stream, &mut said);
        Some(said)
    });
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&home);

    let answer = answer.expect("`open` did not serve a page at the address it wrote down");
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "the page did not answer"
    );
    assert!(
        answer.contains("\"payments\":[]") && answer.contains("\"notCarried\":[]"),
        "the page does not say which payments are waiting and which were not carried"
    );
}

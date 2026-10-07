//! What the public explorer does when every one of its connections is held.
//!
//! Red team scenario R14 of the testnet-8 attack catalogue (E14). The server
//! under the explorer serves [`MAX_CONNECTIONS`] at once and no more, so a
//! flood that opens that many and keeps them is how a reader is shut out from
//! a laptop. `crates/cairn-http/tests/slow_connections.rs` holds the mechanism
//! against a bare `serve`; this runs the real `cairn-explorer` binary on the
//! loopback, a devnet node with an empty chain, because the explorer wires up
//! `serve_without_bodies` itself and a change there that reintroduced the body
//! wait, or dropped the visible refusal, would pass every unit test and fail
//! a reader.
//!
//! Three things are measured, and they are what the catalogue asks for.
//!
//! An honest reader gets the page. A flood of half-open connections takes
//! every slot, and while they are held a fresh reader is turned away with a
//! 503 it can read rather than a reset or a hung socket: the repository has
//! history here, a 503 from a full server that reached the reader as a
//! transport error, and this holds that it no longer does. And the denial is
//! bounded by the asking deadline the caller cannot move: every held slot is
//! cut at [`REQUEST_DEADLINE`] whatever the holder does, so the same reader is
//! served the real page within that deadline rather than waiting on anyone to
//! intervene.
//!
//! **What this costs the attacker, and what it does not close.** A held slot
//! is given back after [`REQUEST_DEADLINE`], so holding the site down without
//! pause means redialling all [`MAX_CONNECTIONS`] every deadline: at sixty
//! four slots and a ten second deadline that is about three hundred and eighty
//! connections a minute, cheap from one machine over the loopback, where the
//! per-address ceiling does not count. That is the accepted shape for a node
//! answering a public port with nothing in front of it; the public site at
//! cairnchain.org runs behind the Caddy proxy `deploy/explorer.sh` writes,
//! whose own `read_header` timeout cuts a slow head before it reaches the
//! explorer. This scenario is about the explorer's own half of that defence,
//! which is the deadline, and the deadline is what is held here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use cairn_http::http::{MAX_CONNECTIONS, REQUEST_DEADLINE};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-explorer-held-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// Starts the explorer on a devnet chain with an empty directory, listening on
/// the loopback with the operating system choosing both ports.
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

/// Reads what the explorer prints up to the line naming its site, and returns
/// the `host:port` that line carries.
fn site_of(child: &mut Child) -> String {
    let mut lines = BufReader::new(child.stdout.take().expect("started with a pipe"));
    loop {
        let mut line = String::new();
        match lines.read_line(&mut line) {
            Ok(0) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the explorer stopped before it opened its site");
            }
            Ok(_) => {
                if let Some(rest) = line.split("http://").nth(1) {
                    return rest.trim().trim_end_matches('/').to_owned();
                }
            }
        }
    }
}

/// Asks once and reads everything back until the socket closes.
fn ask(site: &str, request: &[u8], read_timeout: Duration) -> String {
    let mut stream = TcpStream::connect(site).unwrap();
    stream.set_read_timeout(Some(read_timeout)).unwrap();
    stream.write_all(request).unwrap();
    let mut said = String::new();
    let _ = stream.read_to_string(&mut said);
    said
}

/// A reader gets the index page the explorer compiles in.
#[test]
fn an_honest_reader_gets_the_page() {
    let directory = scratch("page");
    let mut explorer = start(&directory);
    let site = site_of(&mut explorer);

    let said = ask(
        &site,
        b"GET / HTTP/1.1\r\nhost: x\r\n\r\n",
        Duration::from_secs(5),
    );

    let _ = explorer.kill();
    let _ = explorer.wait();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(said.starts_with("HTTP/1.1 200 OK"), "{said}");
    assert!(
        said.contains("content-type: text/html"),
        "the site did not answer a reader with its page: {said}"
    );
}

/// **Every slot held turns a fresh reader away in a way it can read, and the
/// deadline frees them so the same reader is served within it.**
///
/// The flood holds every slot with a half-written head, which costs nothing
/// but a socket each and which no per-read timeout ends. While it holds, a
/// reader is answered 503 rather than met with a reset or left hanging. Then
/// the flood is left alone: the asking deadline cuts every one of its slots,
/// and the reader is served the real page within that deadline, without
/// anyone lifting the flood by hand.
#[test]
fn every_slot_held_is_a_refusal_the_reader_reads_then_the_deadline_frees_it() {
    let directory = scratch("flood");
    let mut explorer = start(&directory);
    let site = site_of(&mut explorer);

    let began = Instant::now();
    let mut holding = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let Ok(mut stream) = TcpStream::connect(&site) else {
            continue;
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        // Half a head: enough to be a caller holding a slot, never enough to
        // be answered, and far short of the line and head caps so only the
        // deadline can end it.
        if stream.write_all(b"GET / HTTP/1.1\r\n").is_err() {
            continue;
        }
        let mut buffer = [0u8; 16];
        match stream.read(&mut buffer) {
            // Answered already, so it never held a slot: do not keep it.
            Ok(read) if read > 0 => {}
            _ => holding.push(stream),
        }
    }
    assert_eq!(
        holding.len(),
        MAX_CONNECTIONS,
        "the loopback is not counted per address, so the flood takes every slot"
    );

    // While the slots are held, a reader is turned away with a status line it
    // can read, not a bare close.
    let turned_away = ask(
        &site,
        b"GET / HTTP/1.1\r\nhost: x\r\n\r\n",
        Duration::from_secs(2),
    );
    assert!(
        turned_away.starts_with("HTTP/1.1 503"),
        "a reader arriving into a full site was not told it was full: {turned_away:?}"
    );
    assert!(
        turned_away.contains("too many connections"),
        "the refusal does not say why: {turned_away:?}"
    );

    // Left alone, the flood is cut at the deadline and the reader is served the
    // real page. The deadline is the bound; the margin above it is for a slow
    // machine and for the moment the just-freed slot is taken.
    let bound = REQUEST_DEADLINE + Duration::from_secs(20);
    let mut served = String::new();
    while began.elapsed() < bound {
        let said = ask(
            &site,
            b"GET / HTTP/1.1\r\nhost: x\r\n\r\n",
            Duration::from_secs(5),
        );
        if said.starts_with("HTTP/1.1 200") {
            served = said;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let freed = began.elapsed();

    // The held connections are let go of whatever they did, so the test does
    // not depend on them being closed by the client.
    drop(holding);
    let _ = explorer.kill();
    let _ = explorer.wait();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        served.starts_with("HTTP/1.1 200 OK") && served.contains("content-type: text/html"),
        "the site did not come back once the deadline cut the flood: {served:?}"
    );
    assert!(
        freed < bound,
        "the site came back after {freed:?}, past the deadline that is supposed to bound it"
    );
}

/// **A slow head is cut at the deadline, and the caller is told it was late.**
///
/// One connection, a header dribbled a byte at a time so every per-read
/// timeout is reset and only the fixed deadline from the accept can end it.
#[test]
fn a_slow_head_is_cut_at_the_deadline() {
    let directory = scratch("slow");
    let mut explorer = start(&directory);
    let site = site_of(&mut explorer);

    let mut stream = TcpStream::connect(&site).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\n").unwrap();

    let began = Instant::now();
    let patience = REQUEST_DEADLINE + Duration::from_secs(15);
    let mut let_go = None;
    let mut seen = Vec::new();
    while began.elapsed() < patience {
        // A header line that never ends, a byte at a time, well short of the
        // caps so nothing but the deadline can stop it.
        if stream.write_all(b"x").is_err() {
            let_go = Some(began.elapsed());
            break;
        }
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(read) => {
                seen.extend_from_slice(&byte[..read]);
                let_go = Some(began.elapsed());
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => {
                let_go = Some(began.elapsed());
                break;
            }
        }
    }

    let mut said = String::from_utf8_lossy(&seen).into_owned();
    let mut rest = String::new();
    let _ = stream.read_to_string(&mut rest);
    said.push_str(&rest);

    let _ = explorer.kill();
    let _ = explorer.wait();
    let _ = std::fs::remove_dir_all(&directory);

    let let_go = let_go.expect("a head that never finished was never cut off");
    assert!(
        let_go < REQUEST_DEADLINE + Duration::from_secs(10),
        "a slow head was cut after {let_go:?}, long past the deadline"
    );
    let first = said.lines().next().unwrap_or_default();
    assert!(
        first.starts_with("HTTP/1.1 408 Request Timeout"),
        "a caller cut off at the deadline was not told it was late: {first:?}"
    );
}

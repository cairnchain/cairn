//! What one machine can cost this server by saying very little, very slowly.
//!
//! A per-read timeout is no defence against a caller that keeps sending, since
//! every byte that arrives resets it. So a single host could open every slot,
//! write half a request line on each, dribble a byte now and then, and hold
//! the whole server for as long as it liked while every honest reader was met
//! with a 503. Both halves of the answer are checked here: a request that
//! never finishes is cut off at a deadline the caller cannot move, and no one
//! address may hold every slot.
//!
//! The second is counted rather than raced against a second reader, because
//! everything in a test arrives from the loopback: the only address a test has
//! is the one doing the flooding. So the flood counts what it was allowed to
//! hold, and what it was not allowed to hold is what is left for everybody
//! else.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_http::http::{MAX_CONNECTIONS, REQUEST_DEADLINE};
use cairn_http::Response;

const BODY: &str = "cairn";

/// A server on the loopback, answering everything the same way.
///
/// Nothing stops it. It blocks on accept, and the test binary ending is what
/// ends it, which is all that is wanted here.
fn start() -> SocketAddr {
    let listener = cairn_http::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let running = Arc::new(AtomicBool::new(true));
        cairn_http::serve(&listener, &running, |_| {
            Response::asset("text/plain; charset=utf-8", BODY)
        });
    });
    address
}

/// Everything the server says, read until it closes.
fn reply(stream: &mut TcpStream) -> String {
    let mut said = String::new();
    let _ = stream.read_to_string(&mut said);
    said
}

fn ask(address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    reply(&mut stream)
}

/// Whether a read found nothing yet, as opposed to finding the end.
fn still_waiting(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[test]
fn an_ordinary_request_is_answered_as_it_was() {
    let address = start();
    let said = ask(address, "GET / HTTP/1.1\r\nhost: x\r\n\r\n");
    assert!(said.starts_with("HTTP/1.1 200 OK"), "{said}");
    assert!(said.contains("connection: close"), "{said}");
    assert!(said.ends_with(BODY), "{said}");
}

/// A browser opens several connections to one origin at once, and so does
/// everyone behind one office address. A cap that did not leave room for that
/// would turn away people reading the site rather than a machine holding it.
#[test]
fn several_connections_from_one_address_are_all_served() {
    let address = start();
    let mut open = Vec::new();
    for _ in 0..6 {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n").unwrap();
        open.push(stream);
    }
    for mut stream in open {
        stream.write_all(b"\r\n").unwrap();
        let said = reply(&mut stream);
        assert!(said.starts_with("HTTP/1.1 200 OK"), "{said}");
    }
}

/// The finding as one connection: a head that never ends, kept alive by a byte
/// now and then. Every byte resets the per-read timeout, so nothing but a
/// deadline counted from the accept can end this.
#[test]
fn a_head_that_never_ends_is_cut_off_at_the_deadline() {
    let address = start();
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\n").unwrap();

    let began = Instant::now();
    let patience = REQUEST_DEADLINE + Duration::from_secs(10);
    let mut let_go = None;
    let mut seen = Vec::new();
    while began.elapsed() < patience {
        // A header line that never ends, a byte at a time, and far short of
        // the line and head caps, so nothing but the deadline can stop it.
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
            Err(error) if still_waiting(&error) => {}
            Err(_) => {
                let_go = Some(began.elapsed());
                break;
            }
        }
    }

    let let_go = let_go.expect("a request that never finished was never cut off");
    assert!(
        let_go < REQUEST_DEADLINE + Duration::from_secs(5),
        "cut off after {let_go:?}, long past the budget"
    );
    assert!(
        let_go + Duration::from_secs(1) >= REQUEST_DEADLINE,
        "cut off after {let_go:?}, before the budget an honest caller is promised"
    );

    // The caller is told rather than merely dropped, as everywhere else here.
    // What arrives can be cut short by the reset the caller's own next byte
    // provokes, so the check is that whatever did arrive was a timeout and not
    // something else.
    let mut said = String::from_utf8_lossy(&seen).into_owned();
    said.push_str(&reply(&mut stream));
    let first = said.lines().next().unwrap_or_default();
    assert!(
        "HTTP/1.1 408 Request Timeout".starts_with(first),
        "the server answered {first:?}"
    );
}

/// The loopback is exempt from the per-address ceiling, and this is what that
/// costs and what pays for it. Every reader of the public site arrives through
/// a proxy on this machine, so counting them as one address would cap the site
/// rather than the flood. What holds instead is the deadline: a flood of stuck
/// connections from here does take every slot, and gives every one of them
/// back without anybody intervening.
#[test]
fn a_flood_over_the_loopback_is_released_by_the_deadline() {
    let address = start();
    let began = Instant::now();
    let mut holding = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let Ok(mut stream) = TcpStream::connect(address) else {
            continue;
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        // Half a head: enough to be a caller, never enough to be answered.
        if stream.write_all(b"GET / HTTP/1.1\r\n").is_err() {
            continue;
        }
        let mut buffer = [0u8; 16];
        match stream.read(&mut buffer) {
            Ok(read) if read > 0 => {}
            _ => holding.push(stream),
        }
    }
    assert_eq!(
        holding.len(),
        MAX_CONNECTIONS,
        "the loopback is not counted per address, so it takes every slot"
    );

    // Nobody else can be served while they are held, which is the price.
    let mut turned_away = TcpStream::connect(address).unwrap();
    turned_away
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    turned_away.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let mut said = String::new();
    let _ = turned_away.read_to_string(&mut said);
    assert!(
        said.starts_with("HTTP/1.1 503"),
        "a reader arriving into a full server is turned away, said {said:?}"
    );

    // And the price is bounded. The held connections are cut on the deadline
    // whatever they do, so the server comes back on its own.
    for mut stuck in holding {
        stuck.set_read_timeout(Some(REQUEST_DEADLINE * 3)).unwrap();
        let mut answer = String::new();
        let _ = stuck.read_to_string(&mut answer);
    }
    let waited = began.elapsed();
    assert!(
        waited < REQUEST_DEADLINE * 3,
        "every held slot came back in {waited:?}, which the deadline bounds"
    );

    let mut served = TcpStream::connect(address).unwrap();
    served
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    served.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let mut answer = String::new();
    let _ = served.read_to_string(&mut answer);
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "the server answers again once the deadline has cut the flood, said {answer:?}"
    );
}

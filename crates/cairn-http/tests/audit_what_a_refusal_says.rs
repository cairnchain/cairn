//! What a refusal tells the person reading it, and whether the message it
//! promises arrives.
//!
//! Two things a caller has to go on when a request is not answered: the status
//! line, and the sentence under it. Every refusal made while reading a request
//! carried the same sentence, "malformed request", whatever had gone wrong. A
//! caller cut off at the deadline was told its request was malformed; so was
//! one whose header block was larger than this server takes, and one whose
//! form body was. The status was right in each case and the sentence under it
//! was about a different failure.
//!
//! And the one answer a full server gives was an incomplete message. It was
//! written with the flag that means "this was a HEAD, compute the body and do
//! not send it", on a connection whose request has not been read yet, so a GET
//! got a head declaring a length and then nothing. A body short of its own
//! `content-length` is not a short answer: the reader gets a transport error
//! rather than a 503.
//!
//! It was written with that flag, and then it was closed over bytes nobody had
//! read. Both produce the same thing at the reader, and only the first was
//! fixed. A connection closed while what it received is still unread is reset,
//! and the reset takes with it whatever the caller has not already read of the
//! answer, which for an answer this small is the whole body. The refusal is
//! the path where those bytes are always there, because it answers before
//! reading any.
//!
//! Which host it shows on is timing and not the rule. Every stack resets a
//! connection closed over bytes nobody read; what differs is whether the
//! caller has already taken the answer out of its own buffer before the reset
//! lands. That race was won on the machines this was written on and lost on
//! the Windows runner, and the fix is to take what the caller sent before
//! hanging up rather than to race it better.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cairn_http::http::MAX_CONNECTIONS;
use cairn_http::Response;

fn start() -> SocketAddr {
    let listener = cairn_http::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let running = Arc::new(AtomicBool::new(true));
        cairn_http::serve(&listener, &running, |_| {
            Response::asset("text/plain; charset=utf-8", "ok")
        });
    });
    address
}

fn ask(address: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let _ = stream.write_all(request);
    let mut said = String::new();
    let _ = stream.read_to_string(&mut said);
    said
}

/// The head and the body of an answer, split at the blank line.
fn split(said: &str) -> (&str, &str) {
    said.split_once("\r\n\r\n").unwrap_or((said, ""))
}

/// What a head says it is sending.
fn declared(head: &str) -> usize {
    head.lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(usize::MAX)
}

/// **A refusal says which refusal it is.**
///
/// Three failures, three statuses, and the sentence under each has to be about
/// the failure it sits under. The status lines are checked too, because `413`
/// had no reason phrase at all and went out as `HTTP/1.1 413 Error`.
#[test]
fn a_refusal_says_what_went_wrong_and_not_what_went_wrong_elsewhere() {
    let address = start();

    let mut endless = String::from("GET / HTTP/1.1\r\nhost: cairn\r\n");
    while endless.len() < 16 * 1024 {
        endless.push_str("x-filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    let too_large_a_head = ask(address, endless.as_bytes());
    assert!(
        too_large_a_head.starts_with("HTTP/1.1 431 Request Header Fields Too Large"),
        "{too_large_a_head}"
    );
    assert!(
        too_large_a_head.contains("the request head is larger than this server takes"),
        "a head over the cap was told its request was malformed: {too_large_a_head}"
    );

    let body = "a".repeat(64 * 1024);
    let too_large_a_body = ask(
        address,
        format!(
            "POST / HTTP/1.1\r\nhost: cairn\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    assert!(
        too_large_a_body.starts_with("HTTP/1.1 413 Content Too Large"),
        "a status with no reason phrase goes out as `413 Error`: {too_large_a_body}"
    );
    assert!(
        too_large_a_body.contains("the form body is larger than this server takes"),
        "{too_large_a_body}"
    );

    // And an actually malformed request still says so, or the sentence above
    // is just a different single answer.
    let nonsense = ask(address, b"GET http://elsewhere/ HTTP/1.1\r\n\r\n");
    assert!(
        nonsense.starts_with("HTTP/1.1 400 Bad Request"),
        "{nonsense}"
    );
    assert!(nonsense.contains("malformed request"), "{nonsense}");
}

/// **And the one answer a full server gives is a whole message.**
///
/// Every slot taken, one more caller, and what comes back has to be a message
/// a reader can finish. This is the answer that goes out exactly when the
/// server is under the most pressure, which is when a person most needs to be
/// told what happened rather than handed a network error.
#[test]
fn the_answer_a_full_server_gives_carries_the_body_it_promises() {
    let address = start();

    // Held open by never reading, so the slots stay taken while the test asks
    // for one more. Dropped at the end of the test with the sockets.
    let mut holding: Vec<TcpStream> = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let Ok(stream) = TcpStream::connect(address) else {
            break;
        };
        holding.push(stream);
    }

    let mut refused = String::new();
    for _ in 0..8 {
        let said = ask(address, b"GET / HTTP/1.1\r\nhost: cairn\r\n\r\n");
        if said.starts_with("HTTP/1.1 503") {
            refused = said;
            break;
        }
    }
    assert!(
        !refused.is_empty(),
        "the slots did not fill, so there is nothing here to measure"
    );
    assert!(
        refused.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{refused}"
    );

    let (head, body) = split(&refused);
    assert_eq!(
        body.len(),
        declared(head),
        "the head promised {} bytes and {} arrived, which reaches a reader as a \
         transport error and not as a 503",
        declared(head),
        body.len()
    );
    assert!(body.contains("too many connections"), "{body}");
}

/// **And it is still whole when the caller sent more than the refusal reads.**
///
/// The refusal answers before reading a byte, so whatever the caller sent is
/// sitting unread when the connection is closed, and a close over unread bytes
/// is a reset. This sends a request head and then a body on top of it, which
/// is the same condition the test above meets by accident and this one meets
/// on purpose: a caller with a form to post, turned away because the server is
/// full.
///
/// The assertion is the same and so is the rule. What differs between hosts is
/// only whether the caller reads the answer before the reset reaches it, which
/// is why this is worth a case of its own rather than a stronger assertion on
/// the one above: on a host that wins that race, both pass whatever the server
/// does about it.
#[test]
fn the_refusal_is_whole_for_a_caller_that_sent_more_than_it_reads() {
    let address = start();

    let mut holding: Vec<TcpStream> = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let Ok(stream) = TcpStream::connect(address) else {
            break;
        };
        holding.push(stream);
    }

    // A head and a body under the cap, so nothing here is refused for its
    // size: what is being tested is the bytes nobody read, not the length.
    let mut request = Vec::new();
    request
        .extend_from_slice(b"POST /form HTTP/1.1\r\nhost: cairn\r\ncontent-length: 2048\r\n\r\n");
    request.extend_from_slice(&[b'x'; 2048]);

    let mut refused = String::new();
    for _ in 0..8 {
        let said = ask(address, &request);
        if said.starts_with("HTTP/1.1 503") {
            refused = said;
            break;
        }
    }
    assert!(
        !refused.is_empty(),
        "the slots did not fill, so there is nothing here to measure"
    );

    let (head, body) = split(&refused);
    assert_eq!(
        body.len(),
        declared(head),
        "the head promised {} bytes and {} arrived. The caller sent a body this \
         path never reads, and closing over it reset the connection, which \
         takes the answer with it.",
        declared(head),
        body.len()
    );
    assert!(body.contains("too many connections"), "{body}");
}

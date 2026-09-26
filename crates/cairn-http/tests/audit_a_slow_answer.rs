//! An answer the application took a long time to work out.
//!
//! A connection has one budget, fixed when it is accepted: the time to ask,
//! and then what the answer is worth at the slowest link this server writes
//! for. The application's own work sat between the two halves and was charged
//! to the caller, so an answer that took longer to compute than the asking
//! deadline was computed and then thrown away unwritten: the writer found its
//! budget spent before the first byte and hung up.
//!
//! The wallet's page is where that lands on money. Sending waits several
//! seconds inside the answer for a peer to take the transfer, and a send that
//! ran past the budget left the transfer handed over and the page saying the
//! wallet had stopped answering, with the Send button back and the form still
//! filled in.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cairn_http::http::REQUEST_DEADLINE;
use cairn_http::Response;

const ANSWER: &str = "{\"sent\":true}";

/// A server whose every answer takes `thinking` to work out.
fn start(thinking: Duration) -> SocketAddr {
    let listener = cairn_http::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let running = Arc::new(AtomicBool::new(true));
        cairn_http::serve(&listener, &running, move |_| {
            thread::sleep(thinking);
            Response::json(ANSWER.to_owned())
        });
    });
    address
}

/// Asks in one write, at once, and reads everything until the server closes.
fn ask(address: SocketAddr, patience: Duration) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(patience)).unwrap();
    stream
        .write_all(b"POST /api/send HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\r\n")
        .unwrap();
    let mut said = String::new();
    let _ = stream.read_to_string(&mut said);
    said
}

/// A caller that asked properly is given the answer however long the
/// application took over it.
///
/// Nothing asked this. Every test of the deadline answered at once, so a
/// server that charged the application's time to the caller passed all of
/// them, and an answer worked out in eleven seconds reached its caller as a
/// closed connection with no status line.
#[test]
fn an_answer_computed_past_the_asking_deadline_is_still_delivered() {
    let thinking = REQUEST_DEADLINE + Duration::from_secs(1);
    let address = start(thinking);
    let said = ask(address, thinking + REQUEST_DEADLINE);
    assert!(
        said.starts_with("HTTP/1.1 200"),
        "an answer that took longer to work out than the asking deadline was worked out and \
         never written: the caller, who asked in one write, read no status line at all"
    );
    assert!(
        said.ends_with(ANSWER),
        "the answer's body did not arrive whole"
    );
}

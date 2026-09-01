//! The other half of the slow-connection case: taking the answer slowly.
//!
//! A deadline over the asking alone stopped a caller dribbling its request and
//! did nothing at all about one that asked properly and then took the answer
//! back in sips. `WRITE_TIMEOUT` is per write and every sip the caller
//! consents to take resets it, so both shapes cost the same and hold a slot
//! for as long as the caller cares to.
//!
//! It has to be sips and not single bytes, which is the one thing the audit
//! got wrong about its own finding. A caller reading a byte at a time never
//! reopens its receive window, so the writing side stops making progress and
//! the plain write timeout ends it; what holds a connection open is taking
//! enough to let the next write through and then waiting, over and over.
//!
//! What covers it now is one moment for the whole connection: the deadline for
//! asking, plus what the answer is worth at the slowest link this server
//! writes for, and never more than `ANSWER_DEADLINE`. It is settled before a
//! byte of the answer moves, so nothing the caller sends or declines to take
//! can add to it. Both halves are checked here, because a deadline that only
//! did the first would cut off the reader it exists to serve.

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
use std::time::{Duration, Instant};

use cairn_http::http::{ANSWER_DEADLINE, REQUEST_DEADLINE};
use cairn_http::Response;

/// An answer far bigger than any socket buffer pair, so the server is really
/// left blocked on the caller rather than handing the whole thing to the
/// kernel and walking away.
///
/// A loopback socket here swallows most of a megabyte before it blocks, which
/// is why this has to be so much larger than anything the server really sends.
/// What is being tested is the ceiling, and on a link with buffers this deep
/// an answer of a realistic size never touches it: it is written and gone
/// before the caller has read a byte.
const TOO_BIG_TO_BUFFER: usize = 32 * 1024 * 1024;

/// What the caller takes at a time, which has to be more than half the receive
/// buffer or the window never reopens and there is no attack to test.
const SIP: usize = 1024 * 1024;

/// And how long it waits between sips: under the write timeout, so that every
/// blocked write is let through just before it would have been given up on.
const BETWEEN_SIPS: Duration = Duration::from_secs(8);

/// The longest a connection can last: the caller's time to ask, and then the
/// most any answer can be worth.
const WHOLE_CONNECTION: Duration = REQUEST_DEADLINE.saturating_add(ANSWER_DEADLINE);

fn start(bytes: usize) -> SocketAddr {
    let listener = cairn_http::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let running = Arc::new(AtomicBool::new(true));
        cairn_http::serve(&listener, &running, move |_| Response {
            status: 200,
            content_type: "text/plain; charset=utf-8",
            cache: "no-store",
            body: vec![b'c'; bytes],
        });
    });
    address
}

fn ask(address: SocketAddr, patience: Duration) -> TcpStream {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(patience)).unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n")
        .unwrap();
    stream
}

/// Everything left on a connection, read as fast as it will come.
fn drain(stream: &mut TcpStream) -> usize {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut read = 0usize;
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return read,
            Ok(count) => read += count,
        }
    }
}

/// Reads up to `wanted` bytes, or fewer if the connection ends first.
fn sip(stream: &mut TcpStream, wanted: usize) -> usize {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut read = 0usize;
    while read < wanted {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => read += count,
        }
    }
    read
}

/// The finding, as a regression: a caller that asks properly and then takes
/// the answer in sips, each one timed to arrive just before the write it is
/// blocking would have been given up on, is let go of at the deadline instead
/// of holding its slot for as long as the answer lasts.
#[test]
fn taking_the_answer_in_sips_does_not_hold_the_connection() {
    let address = start(TOO_BIG_TO_BUFFER);
    let mut stream = ask(address, Duration::from_secs(5));

    let started = Instant::now();
    let sipping = WHOLE_CONNECTION + Duration::from_secs(2);
    let mut taken = 0usize;
    while started.elapsed() < sipping {
        let got = sip(&mut stream, SIP);
        taken += got;
        if got == 0 {
            break;
        }
        thread::sleep(BETWEEN_SIPS.min(sipping.saturating_sub(started.elapsed())));
    }

    // Then read as fast as the connection will give. A server still holding
    // the connection would finish the whole answer here.
    taken += drain(&mut stream);
    let held = started.elapsed();
    println!(
        "sipped for {sipping:?} and took {taken} bytes of a {TOO_BIG_TO_BUFFER} byte answer, \
         connection over after {held:?}"
    );
    assert!(
        taken < TOO_BIG_TO_BUFFER / 2,
        "the server wrote {taken} bytes to a caller taking it in sips, \
         so the connection outlived the {WHOLE_CONNECTION:?} it is allowed"
    );
    assert!(
        held < sipping + REQUEST_DEADLINE,
        "the connection was still going {held:?} after it was accepted"
    );
}

/// The half that would break if the deadline were made blunt. This reader is
/// slow, and honest about it: it takes the answer steadily at a small fraction
/// of what the loopback would give it, and takes longer over it than the
/// asking deadline on its own would allow. It must get every byte.
#[test]
fn an_honest_reader_on_a_slow_link_still_gets_the_whole_answer() {
    const BODY: usize = 2 * 1024 * 1024;
    const CHUNK: usize = 16 * 1024;
    const PAUSE: Duration = Duration::from_millis(125);

    let address = start(BODY);
    let mut stream = ask(address, Duration::from_secs(5));
    let started = Instant::now();

    let mut buffer = vec![0u8; CHUNK];
    let mut said = Vec::new();
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => said.extend_from_slice(&buffer[..count]),
            Err(error) => panic!("the server gave up on an honest reader: {error}"),
        }
        thread::sleep(PAUSE);
    }
    let took = started.elapsed();

    let head = said
        .windows(4)
        .position(|four| four == b"\r\n\r\n")
        .expect("no head")
        + 4;
    let body = said.len() - head;
    let rate = body as u64 / took.as_secs().max(1);
    println!(
        "an honest reader took the whole {body} byte answer in {took:?}, \
         which is {rate} bytes a second and well inside the {WHOLE_CONNECTION:?} \
         a connection is allowed"
    );
    assert!(
        took > REQUEST_DEADLINE,
        "this reader was not slow enough to be a test: {took:?}"
    );
    assert!(
        took < WHOLE_CONNECTION,
        "this reader was too slow to be honest: {took:?}"
    );
    assert_eq!(
        body, BODY,
        "an honest reader was cut off after {body} of {BODY} bytes"
    );
}

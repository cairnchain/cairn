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
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_http::http::{ANSWER_DEADLINE, REQUEST_DEADLINE};
use cairn_http::Response;

/// The smallest answer worth trying, whatever a kernel says it will hold.
const AT_LEAST: usize = 48 * 1024 * 1024;

/// And the largest, so that a kernel with very deep buffers costs this test
/// some memory rather than the machine all of it.
const AT_MOST: usize = 256 * 1024 * 1024;

/// What the caller takes at a time. Enough that the receive window reopens and
/// the server gets to write again, which is what makes this an attack rather
/// than a caller that has simply stopped reading.
const SIP: usize = 1024 * 1024;

/// And how long it waits between sips: under the write timeout, so that every
/// blocked write is let through just before it would have been given up on.
const BETWEEN_SIPS: Duration = Duration::from_secs(8);

/// The longest a connection can last: the caller's time to ask, and then the
/// most any answer can be worth.
const WHOLE_CONNECTION: Duration = REQUEST_DEADLINE.saturating_add(ANSWER_DEADLINE);

/// Between this test starting its clock and the server stamping the connection
/// it accepted. Only ever makes the deadline later than the server's own.
const SLACK: Duration = Duration::from_secs(3);

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

/// The same, counting separately what arrives after `cutoff`.
///
/// A read completing after the cutoff carries bytes the server may have handed
/// to the kernel before it: that residue is what a kernel holds, and it is
/// measured. Anything beyond it is the server still writing.
fn sip_after(stream: &mut TcpStream, wanted: usize, cutoff: Instant, late: &mut usize) -> usize {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut read = 0usize;
    while read < wanted {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                read += count;
                if Instant::now() > cutoff {
                    *late += count;
                }
            }
        }
    }
    read
}

/// Everything left, counting what arrives after `cutoff`.
fn drain_after(stream: &mut TcpStream, cutoff: Instant, late: &mut usize) -> usize {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut read = 0usize;
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return read,
            Ok(count) => {
                read += count;
                if Instant::now() > cutoff {
                    *late += count;
                }
            }
        }
    }
}

/// How much a loopback connection on this machine swallows before the writer
/// is really blocked on the reader.
///
/// The whole of the test below rests on the server being unable to write its
/// answer and walk away, and how much a kernel takes before it says no is the
/// kernel's decision. It is not a number this file can hold: a loopback socket
/// pair here swallows a couple of megabytes, and Windows CI swallowed twenty
/// seven. A thirty two megabyte answer went into the buffers whole there, the
/// server was never blocked on the caller for a moment, it closed on its
/// deadline exactly as it should, and the test read the bytes still sitting in
/// the caller's own receive buffer as a server that had held the connection.
/// So the answer is sized from this rather than pinned above it.
///
/// Read flat out first and then not at all. The reading is what makes a
/// receive window that grows with what the reader takes grow here too, and
/// reading faster than the caller below can only make this number larger,
/// which is the safe direction: what it decides is how much room there is
/// between what a kernel holds and what a server writes.
fn swallowed_by_a_loopback_pair() -> usize {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let address = listener.local_addr().unwrap();
    let consumed = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let taking = {
        let (consumed, stop) = (Arc::clone(&consumed), Arc::clone(&stop));
        thread::spawn(move || {
            let (mut side, _) = listener.accept().unwrap();
            side.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut buffer = vec![0u8; 256 * 1024];
            let until = Instant::now() + Duration::from_millis(200);
            while Instant::now() < until {
                match side.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        consumed.fetch_add(count, Ordering::Relaxed);
                    }
                    Err(_) => {}
                }
            }
            // Then hold the socket open and take nothing, which is what leaves
            // the writer to fill everything there is to fill.
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(20));
            }
        })
    };

    let mut writing = TcpStream::connect(address).unwrap();
    writing.set_nonblocking(true).unwrap();
    let block = vec![b'c'; 256 * 1024];
    let mut written = 0usize;
    let mut refused: Option<Instant> = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match writing.write(&block) {
            Ok(0) => break,
            Ok(count) => {
                written += count;
                refused = None;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let since = *refused.get_or_insert_with(Instant::now);
                if since.elapsed() > Duration::from_secs(1) {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = taking.join();
    written.saturating_sub(consumed.load(Ordering::Relaxed))
}

/// The finding, as a regression: a caller that asks properly and then takes
/// the answer in sips, each one timed to arrive just before the write it is
/// blocking would have been given up on, is let go of at the deadline instead
/// of holding its slot for as long as the answer lasts.
///
/// The sips are counted rather than clocked. The loop used to run for a fixed
/// wall-clock window and take however many sips fitted inside it, which is not
/// the same number of sips on a platform whose timer moves in fifteen
/// millisecond steps as it is here, and how far past the deadline the sipping
/// reaches is the whole of what the loop is for. A count of sips at a fixed
/// pace says that plainly on every machine.
#[test]
fn taking_the_answer_in_sips_does_not_hold_the_connection() {
    let swallowed = swallowed_by_a_loopback_pair();
    let answer = swallowed.saturating_mul(6).clamp(AT_LEAST, AT_MOST);
    // Sips enough to carry the sipping a whole pause past the deadline, so
    // that a server which lets go on time has stopped writing well before the
    // last one and a server which does not is still writing at it.
    let sips = usize::try_from(WHOLE_CONNECTION.as_secs() / BETWEEN_SIPS.as_secs() + 2).unwrap();
    let sipped_for = BETWEEN_SIPS.saturating_mul(u32::try_from(sips).unwrap());
    assert!(
        answer >= swallowed.saturating_mul(3),
        "this machine's loopback swallows {swallowed} bytes and the largest answer this \
         test will build is {answer}, so there is no room between what a kernel holds \
         and what a server writes for a deadline to show in"
    );

    let address = start(answer);
    let mut stream = ask(address, Duration::from_secs(5));

    let started = Instant::now();
    // The moment after which nothing the server writes is within its budget.
    // The server's own deadline runs from when it accepted the connection,
    // which is a little before this, so this is the later of the two and the
    // slack only makes the test kinder.
    let cutoff = started + WHOLE_CONNECTION + SLACK;
    let mut taken = 0usize;
    let mut late = 0usize;
    for _ in 0..sips {
        let got = sip_after(&mut stream, SIP, cutoff, &mut late);
        taken += got;
        if got == 0 {
            break;
        }
        thread::sleep(BETWEEN_SIPS);
    }

    // Then read as fast as the connection will give. A server still holding
    // the connection would finish the whole answer here; one that let go on
    // its deadline has nothing left to give but what the kernel is holding.
    taken += drain_after(&mut stream, cutoff, &mut late);
    let over = started.elapsed();
    println!(
        "a loopback pair here swallows {swallowed} bytes, so the answer is {answer}. \
         Took {sips} sips over {sipped_for:?} and got {taken} bytes, {late} of them \
         after the {WHOLE_CONNECTION:?} the connection is allowed; over after {over:?}"
    );
    // What arrived late rather than what arrived at all.
    //
    // The total cannot tell the two cases apart, and it took a red build on
    // one platform and not the others to see it: a server that stopped on time
    // still leaves whatever the kernel was holding, and a client sipping at a
    // megabyte every eight seconds is still draining that long after the
    // server has gone. Fifty megabytes arriving proves nothing on its own.
    // Fifty megabytes arriving *after the deadline* proves the server was
    // still writing, because nothing else can be holding them.
    assert!(
        late < answer / 4,
        "{late} bytes of a {answer} byte answer arrived after the \
         {WHOLE_CONNECTION:?} this connection is allowed, on a machine whose loopback \
         holds {swallowed}. A server that let go on time leaves what the kernel was \
         holding and no more, so this is the server still writing."
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

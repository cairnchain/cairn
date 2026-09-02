//! The throughput a frame has to keep up, and who it cuts off.
//!
//! A peer that opens a frame and dribbles never lets the socket's own deadline
//! fire, because every byte it sends starts the next one. So the frame carries
//! a deadline of its own. Bounding the whole frame with it set a floor of
//! about twenty six kilobytes a second on whoever was mid frame, and the claim
//! that no link worth having is below that was an assumption about links: a
//! phone on a weak signal delivers under it steadily, and the frames that
//! floor cut off were the large ones, which is to say the ones a node is
//! handed when it joins.
//!
//! The deadline is renewed by progress now. A link that keeps delivering keeps
//! its frame; one that stops loses it inside twenty seconds either way, and a
//! stranger holding a connection has to keep paying for it.

#![allow(
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{self, Read, Write};
use std::thread;
use std::time::{Duration, Instant};

use cairn_ledger::note::NetworkId;
use cairn_net::message::{Joining, Message, JOIN_PART_BYTES};
use cairn_net::wire::{read_message, write_message, WireError, MAX_FRAME_BYTES, PROGRESS_BYTES};

// ---------------------------------------------------------------------------
// CLAIM 2: the allowance window is kept per ADDRESS.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CLAIM 1: the whole-frame deadline, and what throughput it demands.
// ---------------------------------------------------------------------------

/// A reader that hands over `rate` bytes every `tick`, like a slow link.
struct Trickle {
    rate: usize,
    tick: Duration,
    header: Vec<u8>,
    at: usize,
    delivered: usize,
}

impl Read for Trickle {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at < self.header.len() {
            let count = out.len().min(self.header.len() - self.at);
            out[..count].copy_from_slice(&self.header[self.at..self.at + count]);
            self.at += count;
            return Ok(count);
        }
        thread::sleep(self.tick);
        let count = out.len().min(self.rate);
        for byte in &mut out[..count] {
            *byte = 0;
        }
        self.delivered += count;
        Ok(count)
    }
}

/// **An honest slow link carries a whole join piece to the end.**
///
/// Twenty kilobytes a second, which is a phone on a weak signal and is under
/// the twenty six a whole-frame deadline demanded. This is the frame a node is
/// handed when it joins, so the floor cut off exactly the people the handover
/// design exists for.
#[test]
fn an_honest_slow_link_carries_a_join_piece_to_the_end() {
    let network = NetworkId::new(0x0a1b_2c3d);
    let body = JOIN_PART_BYTES;
    let mut header = Vec::new();
    header.extend_from_slice(&network.as_u32().to_le_bytes());
    header.extend_from_slice(&u32::try_from(body).unwrap().to_le_bytes());

    // 20 KiB/s, delivered in 2 KiB chunks every 100 ms: below the floor.
    let mut slow = Trickle {
        rate: 2_048,
        tick: Duration::from_millis(100),
        header,
        at: 0,
        delivered: 0,
    };
    let started = Instant::now();
    let outcome = read_message(&mut slow, network);
    let took = started.elapsed();
    let delivered = slow.delivered;
    // The bytes are zeros rather than a message, so what comes back is a
    // decode failure. That is the point: the frame was carried to the end
    // instead of being cut off partway, which is what `Stalled` would say.
    assert!(
        matches!(outcome, Err(WireError::Malformed(_))),
        "a 20 KiB/s honest sender was cut off after {took:?} with {delivered} \
         of {body} bytes delivered: {outcome:?}"
    );
    assert_eq!(delivered, body, "the whole frame arrived");
    println!(
        "read side: {delivered} bytes in {took:?} ({:.1} KiB/s)",
        delivered as f64 / took.as_secs_f64() / 1024.0
    );
    // What the floor is now, against what a whole-frame deadline demanded.
    println!(
        "floor now: {:.1} KiB/s; whole-frame floor for a {body} byte join \
         piece was {:.1} KiB/s, and {:.1} KiB/s for a {MAX_FRAME_BYTES} byte frame",
        PROGRESS_BYTES as f64 / 20.0 / 1024.0,
        body as f64 / 20.0 / 1024.0,
        MAX_FRAME_BYTES as f64 / 20.0 / 1024.0
    );
}

/// A writer that takes `rate` bytes every `tick` and never refuses.
struct Sipping {
    rate: usize,
    tick: Duration,
    taken: usize,
}

impl Write for Sipping {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        thread::sleep(self.tick);
        let count = bytes.len().min(self.rate);
        self.taken += count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// **And the same on the write side.**
///
/// A peer that keeps taking bytes — never zero, so never a `WriteZero`, and
/// never a socket timeout — is one this node keeps writing to for as long as
/// it keeps taking them.
#[test]
fn an_honest_slow_reader_is_written_to_until_it_has_the_whole_frame() {
    let network = NetworkId::new(0x0a1b_2c3d);
    let message = Message::JoinPart {
        what: Joining::Ledger,
        at: cairn_primitives::hash::Hash32::from_bytes([0u8; 32]),
        part: 0,
        parts: 22,
        bytes: vec![0u8; JOIN_PART_BYTES],
    };
    let mut sipping = Sipping {
        rate: 2_048,
        tick: Duration::from_millis(100),
        taken: 0,
    };
    let started = Instant::now();
    let outcome = write_message(&mut sipping, network, &message);
    let took = started.elapsed();
    assert!(
        outcome.is_ok(),
        "a peer taking 20 KiB/s was given up on after {took:?} with {} bytes \
         taken",
        sipping.taken
    );
    println!("write side: {} bytes in {took:?}", sipping.taken);
}

/// **A dribbler is still cut off, which is what the deadline is for.**
///
/// One byte at a time, forever. It never lets the socket's own deadline fire,
/// so without a deadline belonging to the frame it held a thread, a connection
/// slot and up to a megabyte of buffer for as long as it cared to. Renewing by
/// progress does not help it: a byte every fifty milliseconds is twenty a
/// second, and the frame wants sixty four kilobytes.
#[test]
fn a_dribbling_sender_still_loses_the_frame() {
    let network = NetworkId::new(0x0a1b_2c3d);
    let mut header = Vec::new();
    header.extend_from_slice(&network.as_u32().to_le_bytes());
    header.extend_from_slice(&u32::try_from(MAX_FRAME_BYTES).unwrap().to_le_bytes());
    let mut dribble = Trickle {
        rate: 1,
        tick: Duration::from_millis(50),
        header,
        at: 0,
        delivered: 0,
    };
    let started = Instant::now();
    let outcome = read_message(&mut dribble, network);
    let took = started.elapsed();
    assert!(outcome.is_err(), "the dribbler was tolerated");
    println!(
        "dribbler: {} bytes in {:?} ({:.3} bytes/s) before it was cut off",
        dribble.delivered,
        took,
        dribble.delivered as f64 / took.as_secs_f64()
    );
    assert!(took < Duration::from_secs(25));
}

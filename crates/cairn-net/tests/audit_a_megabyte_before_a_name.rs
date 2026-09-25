//! What a stranger can make a node spend before it has said who it is.
//!
//! `read_message` reads a frame header, checks the network marker, checks the
//! declared length against the protocol's frame cap, allocates, and decodes.
//! The comment on that cap reasoned about the allocation: a megabyte, bounded
//! by the number of connections a node accepts at once, fine.
//!
//! The allocation is the cheap half. Decoding is the other, and decoding a
//! frame full of notes decompresses a point off the curve for every owner in
//! it and checks each one for its subgroup. A megabyte of note owners is about
//! twenty six thousand keys: a sixth of a second of somebody else's processor
//! before the subgroup check went in, and one and a third seconds after.
//!
//! The budget that would have charged for it is `held_off`, twenty lines below
//! the read, and by then the work is done. A control that exists and is
//! charged one layer too high.
//!
//! So the cap is the caller's to state now, and the caller that reads from a
//! peer states a small one until the peer has introduced itself. A handshake
//! is a fixed set of fields a few hundred bytes long, and it is the only thing
//! a node has any business sending before one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::codec::Encode;

use cairn_net::message::Message;
use cairn_net::wire::{
    most_from, read_message, WireError, FRAME_PATIENCE, MAX_FRAME_BYTES, MOST_BEFORE_A_NAME,
};

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn hello(nonce: u64, listen: u16) -> Message {
    Message::Hello(cairn_net::message::Handshake {
        version: cairn_net::message::PROTOCOL_VERSION,
        network: params().network,
        genesis: cairn_primitives::Hash32::ZERO,
        tip: cairn_primitives::Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen,
        nonce,
        keeps: cairn_net::Keeps::default(),
    })
}

/// A frame declaring `declared` bytes, with none of them.
///
/// The declared length is what the cap is checked against, so the body never
/// has to exist. What is under test is whether the reader agrees to wait for
/// it.
fn a_frame_declaring(declared: usize) -> Vec<u8> {
    // Written with the encoder the wire uses rather than by hand, so the two
    // cannot drift. Written by hand, this was big endian where the codec is
    // little, and every assertion below passed for `WrongNetwork`.
    let mut framed = Vec::new();
    params().network.as_u32().encode_to(&mut framed);
    u32::try_from(declared).unwrap().encode_to(&mut framed);
    framed
}

/// The cap the caller states is the cap that is applied.
///
/// Exact, and held at the reader rather than through a socket. Watching a
/// socket cannot answer this: the bytes a test writes are not the bytes a node
/// reads, because a kernel buffers what it has not handed over yet, and a
/// connection that is closed takes several writes to say so. The first
/// attempt at this test measured what it had written and passed with the cap
/// removed.
#[test]
fn a_reader_refuses_what_the_caller_would_not_have_it_read() {
    let over = MOST_BEFORE_A_NAME.saturating_add(1);

    let mut stranger = Cursor::new(a_frame_declaring(over));
    assert!(
        matches!(
            read_message(&mut stranger, params().network, MOST_BEFORE_A_NAME),
            Err(WireError::FrameTooLarge { declared, .. }) if declared == over
        ),
        "a caller that said {MOST_BEFORE_A_NAME} was handed a frame of {over} to read"
    );

    // And the same bytes under the protocol's own cap are not refused for
    // their size, which is what makes the line above about the cap and not
    // about the frame.
    let mut peer = Cursor::new(a_frame_declaring(over));
    assert!(
        !matches!(
            read_message(&mut peer, params().network, MAX_FRAME_BYTES),
            Err(WireError::FrameTooLarge { .. })
        ),
        "the two caps behave alike, so stating one bought nothing"
    );

    // Neither cap reaches past the protocol's, whatever a caller asks for.
    let mut absurd = Cursor::new(a_frame_declaring(MAX_FRAME_BYTES.saturating_add(1)));
    assert!(matches!(
        read_message(&mut absurd, params().network, usize::MAX),
        Err(WireError::FrameTooLarge { .. })
    ));
}

/// And a node refuses a stranger's oversized frame at its header.
///
/// The reading above is of the function; this is of the node that calls it,
/// and what it holds is that the two are joined. A node that refused at the
/// header closes at once; a node that agreed to the length waits for a body
/// that never comes, for [`FRAME_PATIENCE`]. The gap between the two is twenty
/// seconds against the two this waits, which is the margin that makes a
/// reading of a clock mean something here.
#[test]
fn a_stranger_cannot_ask_a_node_to_read_a_megabyte() {
    let node = cairn_net::Node::bind(params(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let mut stranger = TcpStream::connect(node.address()).unwrap();

    stranger.write_all(&a_frame_declaring(900 * 1024)).unwrap();
    stranger.flush().unwrap();

    stranger
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bin = [0u8; 64];
    let closed = loop {
        match stranger.read(&mut bin) {
            Ok(0) => break true,
            Ok(_) => {}
            Err(_) => break false,
        }
    };
    assert!(
        closed,
        "a socket that had not said who it was asked this node to take nine hundred \
         kilobytes and decode every key in them, and the node settled in to wait for it. \
         It has {FRAME_PATIENCE:?} of patience for a frame."
    );
}

/// And the cap admits the one thing it has to admit.
///
/// Held against an encoded handshake rather than against a number somebody
/// liked the look of. A cap on what a stranger may send is only safe if a
/// stranger can still say who it is, and the way to know that is to measure
/// the sentence, not to assert that four kilobytes sounds like plenty.
#[test]
fn the_cap_before_a_name_admits_a_name() {
    let greeting = hello(7_001, 4_242).encode();
    assert!(
        greeting.len() < MOST_BEFORE_A_NAME,
        "a handshake is {} bytes and a stranger is allowed {MOST_BEFORE_A_NAME}, so no \
         stranger could introduce itself and this node would speak to nobody",
        greeting.len()
    );
    // And with room to spare, because the handshake carries a `Keeps` that may
    // grow and nobody editing it will think to come here.
    assert!(
        greeting.len().saturating_mul(4) < MOST_BEFORE_A_NAME,
        "a handshake is {} bytes against a cap of {MOST_BEFORE_A_NAME}, which leaves no \
         room for the next field added to it",
        greeting.len()
    );
}

/// A peer that has introduced itself gets the protocol's cap, not the stranger's.
///
/// Without this the test above passes on a node that refuses everything, which
/// would break the chain rather than protect it: a block is the largest thing
/// on this wire and it travels in one frame.
#[test]
fn a_peer_that_said_who_it_was_gets_the_whole_frame() {
    assert_eq!(most_from(true), MAX_FRAME_BYTES);
    assert_eq!(most_from(false), MOST_BEFORE_A_NAME);
    assert!(
        most_from(false) < most_from(true),
        "the two are the same number, so naming them apart bought nothing"
    );
}

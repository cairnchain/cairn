//! Framing messages onto a byte stream.
//!
//! A frame is a four byte network marker, a four byte length, and the message.
//!
//! The marker means a peer speaking a different network is recognised on its
//! first four bytes rather than after a confusing decode. The length is checked
//! against a hard cap before a single byte is reserved, because it is the one
//! number an anonymous peer gets to choose about this node's memory.
//!
//! There is no checksum. TCP already carries one, and against a peer that is
//! actively hostile a checksum it computes itself proves nothing.
//!
//! A read distinguishes two silences, which is the whole reason this is not a
//! plain `read_exact`. A peer with nothing to say between frames is normal and
//! must not be disconnected. A peer that opens a frame, announces a length, and
//! then stops is not: without that distinction the reading thread waits on it
//! for as long as the socket stays open, and a handful of such peers is enough
//! to silence a node entirely.
//!
//! Neither `read_exact` nor `write_all` is used here for a second reason: the
//! deadline a socket carries is per syscall, and the party at the other end
//! decides when those fire. One byte just inside each period restarts it, so a
//! frame that never finishes never times out either. Both directions therefore
//! carry a deadline of their own, [`FRAME_PATIENCE`], which belongs to the
//! frame rather than to the syscall.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use cairn_ledger::note::NetworkId;
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};

/// Largest message this node will read or write.
///
/// Comfortably more than the consensus rules allow a block to take, a block
/// being the largest thing that legitimately crosses this wire. The two limits
/// are written in two places and have to be kept in that order: a block the
/// rules allow and the wire refuses would be one its miner could not hand to
/// anyone, and that miner would then be following a chain nobody else can
/// follow.
///
/// The margin is deliberate. Larger costs memory, since this is the one
/// allocation an anonymous peer gets to ask for and a node holds several dozen
/// connections at once. Smaller leaves no room for a block to grow into
/// without this having to move in step.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

const HEADER_BYTES: usize = 8;

/// How long one frame may take, from its first byte to its last.
///
/// The socket's own deadlines bound one syscall, and that is all they can
/// bound: a peer feeding a byte a second is never late for a `read`, and one
/// accepting a byte a second is never late for a `write`. Either of them held
/// a thread, a connection slot and up to a megabyte of buffer for as long as
/// it cared to keep dribbling, and neither ever reached the loop that judges
/// peers, because that loop only runs between frames.
///
/// So the frame is what a peer is judged on. Twenty seconds is four times the
/// read deadline and the whole of a frame rather than a call, which puts a
/// floor of about twenty six kilobytes a second on a peer that is mid frame:
/// far below any link that could follow a chain of hundred kilobyte blocks,
/// and far above what a stranger holding a megabyte of this node open is
/// entitled to spend.
///
/// The socket deadlines are still needed and are not replaced. This can only
/// be looked at between syscalls, so without them one call could block for
/// ever and never come back to be judged.
pub const FRAME_PATIENCE: Duration = Duration::from_secs(20);

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("peer speaks network {found:#010x}, this node speaks {expected:#010x}")]
    WrongNetwork { expected: u32, found: u32 },
    #[error("peer announced a {declared} byte frame, the limit is {MAX_FRAME_BYTES}")]
    FrameTooLarge { declared: usize },
    #[error("frame body is malformed: {0}")]
    Malformed(#[from] CodecError),
    #[error("this node would have sent a {size} byte frame, over its own limit")]
    OversizedSend { size: usize },
    #[error("peer opened a {wanted} byte frame, sent {had} bytes of it, and stopped")]
    Stalled { had: usize, wanted: usize },
    #[error("peer took {sent} bytes of a {size} byte frame and would take no more")]
    Unaccepted { sent: usize, size: usize },
}

/// What one read attempt found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming {
    Message(crate::message::Message),
    /// The deadline passed with no frame open. The peer is simply idle.
    Quiet,
}

/// Whether an error is the read deadline passing rather than a real failure.
///
/// Platforms disagree on which of the two kinds a socket timeout raises, so
/// both are treated as the deadline.
fn is_deadline(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Filled {
    Complete,
    /// The deadline passed before the first byte.
    Nothing,
}

/// Reads exactly `buffer.len()` bytes by `by`, or reports which silence
/// stopped it.
///
/// Two ways of never finishing, and they need different answers. A peer that
/// opens a frame and stops is caught by the socket's own deadline, on the read
/// that finds nothing. A peer that opens a frame and dribbles is caught by
/// `by`, because it never lets that deadline fire: every byte it sends starts
/// the next one, and it can go on doing that for as long as the frame is long.
fn fill<R: Read>(reader: &mut R, buffer: &mut [u8], by: Instant) -> Result<Filled, WireError> {
    let wanted = buffer.len();
    let mut read = 0usize;
    while read < wanted {
        let Some(rest) = buffer.get_mut(read..) else {
            return Ok(Filled::Complete);
        };
        match reader.read(rest) {
            Ok(0) => return Err(WireError::Io(io::Error::from(io::ErrorKind::UnexpectedEof))),
            Ok(count) => read = read.saturating_add(count),
            // A signal arrived mid read. Nothing was lost; go round again.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if is_deadline(&error) => {
                if read == 0 {
                    return Ok(Filled::Nothing);
                }
                return Err(WireError::Stalled { had: read, wanted });
            }
            Err(error) => return Err(WireError::Io(error)),
        }
        if read < wanted && Instant::now() >= by {
            return Err(WireError::Stalled { had: read, wanted });
        }
    }
    Ok(Filled::Complete)
}

/// The moment a frame started now runs out of patience.
///
/// Saturating, because a clock far enough along that adding twenty seconds
/// overflows is not a reason to stop framing messages.
fn patience_from(now: Instant) -> Instant {
    now.checked_add(FRAME_PATIENCE).unwrap_or(now)
}

/// Writes the whole of `bytes` by `by`, or gives up on the peer.
///
/// The mirror of [`fill`], and there for the mirror reason: `write_all` loops
/// over partial writes, the socket's deadline is per `write` call, and a peer
/// accepting one byte per deadline restarts it every time. What that held was
/// not only the writing thread: everything queued behind it was held with it,
/// for a peer that had already decided not to read.
fn drain<W: Write>(writer: &mut W, bytes: &[u8], by: Instant) -> Result<(), WireError> {
    let size = bytes.len();
    let mut sent = 0usize;
    while sent < size {
        let Some(rest) = bytes.get(sent..) else {
            return Ok(());
        };
        match writer.write(rest) {
            Ok(0) => return Err(WireError::Io(io::Error::from(io::ErrorKind::WriteZero))),
            Ok(count) => sent = sent.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(WireError::Io(error)),
        }
        if sent < size && Instant::now() >= by {
            return Err(WireError::Unaccepted { sent, size });
        }
    }
    Ok(())
}

/// Writes one framed message, giving the peer [`FRAME_PATIENCE`] to take it.
pub fn write_message<W: Write>(
    writer: &mut W,
    network: NetworkId,
    message: &crate::message::Message,
) -> Result<(), WireError> {
    let body = message.encode();
    if body.len() > MAX_FRAME_BYTES {
        return Err(WireError::OversizedSend { size: body.len() });
    }
    let length = u32::try_from(body.len()).unwrap_or(u32::MAX);

    let mut frame = Vec::with_capacity(body.len().saturating_add(HEADER_BYTES));
    network.as_u32().encode_to(&mut frame);
    length.encode_to(&mut frame);
    frame.extend_from_slice(&body);

    drain(writer, &frame, patience_from(Instant::now()))?;
    writer.flush()?;
    Ok(())
}

/// Reads one framed message, up to whatever deadline `reader` carries.
///
/// Returns [`Incoming::Quiet`] when the deadline passes before a frame starts,
/// so a caller can tell an idle peer from one holding a frame open.
pub fn read_message<R: Read>(reader: &mut R, network: NetworkId) -> Result<Incoming, WireError> {
    // The frame's own deadline. Started here rather than at the first byte,
    // which costs a peer that dawdles before speaking at most one read
    // deadline out of the twenty seconds; a peer with nothing to say at all
    // never reaches it, because the header read returns `Quiet` first and the
    // next call starts again.
    let by = patience_from(Instant::now());
    let mut header = [0u8; HEADER_BYTES];
    if fill(reader, &mut header, by)? == Filled::Nothing {
        return Ok(Incoming::Quiet);
    }

    let mut cursor = Reader::new(&header);
    let marker = u32::decode_from(&mut cursor)?;
    if marker != network.as_u32() {
        return Err(WireError::WrongNetwork {
            expected: network.as_u32(),
            found: marker,
        });
    }
    let declared = usize::try_from(u32::decode_from(&mut cursor)?).unwrap_or(usize::MAX);
    if declared > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge { declared });
    }

    // The one allocation an anonymous peer gets to ask for, which is why the
    // cap above is checked first and why a node accepts a bounded number of
    // connections at once.
    let mut body = vec![0u8; declared];
    if fill(reader, &mut body, by)? == Filled::Nothing {
        return Err(WireError::Stalled {
            had: 0,
            wanted: declared,
        });
    }
    Ok(Incoming::Message(crate::message::Message::decode(&body)?))
}

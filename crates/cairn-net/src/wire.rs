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

/// What a peer may send before it has introduced itself.
///
/// A handshake is a fixed set of fields, a few hundred bytes, and it is the
/// only thing a node has any business sending before one. Everything else is
/// refused as unannounced a moment later anyway, so the only question this
/// answers is how much the refusal costs.
///
/// It used to cost whatever [`MAX_FRAME_BYTES`] allowed. The comment on that
/// cap reasoned about the allocation, which is a megabyte and is bounded by
/// the number of connections a node accepts at once. Decoding what is in it is
/// the other half: a megabyte of note owners is about twenty six thousand
/// public keys, and each one is a point decompressed off the curve and checked
/// for its subgroup. A sixth of a second of somebody else's processor before
/// that subgroup check existed, and one and a third seconds after, from a
/// socket that had not said who it was.
pub const MOST_BEFORE_A_NAME: usize = 4 * 1024;

/// How much this node will read from a peer, by whether it knows who it is.
///
/// Named rather than written inline at the one call site, because it is the
/// whole of the policy and the place a reader will come looking for it.
#[must_use]
pub const fn most_from(announced: bool) -> usize {
    if announced {
        MAX_FRAME_BYTES
    } else {
        MOST_BEFORE_A_NAME
    }
}

/// A block this wire carries has to fit in the log that stores it.
///
/// The paragraph above ties this ceiling to the one end of a block's journey,
/// what the consensus rules allow it to be, and `tests/protocol.rs` holds that
/// tie. The other end is a record in the block log, which refuses a body over
/// [`cairn_store::MAX_RECORD_BYTES`] and answers `BlockTooLarge`. Three
/// numbers in three crates, in one order, and only two of them were tied to
/// each other.
///
/// What the missing tie costs is not a silent divergence: a node that
/// validated a block off this wire and could not write it down reaches the
/// state `Node::unwritten` reports and stops itself over, with its chain
/// ahead of its disk. That is the right answer to the situation and the wrong
/// situation to be in, and it would be reachable by a change to either number
/// with nothing in between to say so.
///
/// Stated as `<=` rather than as the exact relation, which is
/// `MAX_FRAME_BYTES - 1 <= MAX_RECORD_BYTES`: a frame carries a one byte tag
/// before the block, so the largest block a frame holds is one byte short of
/// the frame. The stronger statement implies the one that is needed and reads
/// as what it means, that this wire never carries more than the log will take.
///
/// Held where the numbers are written rather than where a test runs. Nothing
/// sends a block at either ceiling, and a test that did would be building a
/// megabyte block to prove an inequality between two constants.
const _: () = assert!(MAX_FRAME_BYTES <= cairn_store::MAX_RECORD_BYTES);

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
/// read deadline and belongs to the frame rather than to a call.
///
/// What it does not do any more is bound the whole frame. A fixed twenty
/// seconds for anything from eight bytes to a megabyte set a floor of about
/// twenty six kilobytes a second on whoever was mid frame, and the claim that
/// no link worth having is below that was an assumption about links rather
/// than a fact about them: a phone on a weak signal, or a rural line, delivers
/// under it steadily. On a design whose whole point is that anyone can run a
/// full node, the frames that floor cut off were the large ones, which is to
/// say the ones a node is handed when it joins.
///
/// So this is what a frame may go without getting on with it, and
/// [`PROGRESS_BYTES`] renews it. A link that keeps delivering keeps its frame;
/// one that stops loses it inside twenty seconds either way.
///
/// The socket deadlines are still needed and are not replaced. This can only
/// be looked at between syscalls, so without them one call could block for
/// ever and never come back to be judged.
pub const FRAME_PATIENCE: Duration = Duration::from_secs(20);

/// What a frame has to move to be given [`FRAME_PATIENCE`] again.
///
/// The floor this sets is sixty four kilobytes in twenty seconds, about three
/// and a quarter kilobytes a second, which is a link that can still follow a
/// chain of hundred kilobyte blocks a minute apart and is eight times below
/// what a whole-frame deadline demanded.
///
/// It is also what a stranger has to keep paying. Under the old rule a held
/// connection cost the peer almost nothing for twenty seconds; under this one
/// it costs three kilobytes a second for as long as it is held, and a frame is
/// capped at [`MAX_FRAME_BYTES`], so the longest anyone can hold one is
/// sixteen renewals.
pub const PROGRESS_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("peer speaks network {found}, this node speaks {expected}")]
    WrongNetwork {
        expected: NetworkId,
        found: NetworkId,
    },
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
fn fill<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    patience: &mut Patience,
) -> Result<Filled, WireError> {
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
        if read < wanted && !patience.holds(read, Instant::now()) {
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

/// How long a frame may go without getting on with it.
///
/// Carried across both halves of a read, so the header and the body are one
/// frame and not two deadlines.
#[derive(Debug)]
struct Patience {
    by: Instant,
    /// Bytes moved when the deadline was last renewed.
    marked: usize,
}

impl Patience {
    fn started() -> Self {
        Self {
            by: patience_from(Instant::now()),
            marked: 0,
        }
    }

    /// Whether a frame that has moved `moved` bytes by `now` may carry on.
    ///
    /// Renewed by progress rather than by time, which is the difference
    /// between judging a peer on how fast it is and judging it on whether it
    /// is still going. A link too slow to move [`PROGRESS_BYTES`] in
    /// [`FRAME_PATIENCE`] is one that cannot follow this chain at all.
    ///
    /// Handed the moment rather than reading the clock, so the second the
    /// deadline falls on can be asked: read here, it was a comparison nothing
    /// could reach, since no test can make the clock read exactly the deadline.
    fn holds(&mut self, moved: usize, now: Instant) -> bool {
        if moved.saturating_sub(self.marked) >= PROGRESS_BYTES {
            self.marked = moved;
            self.by = patience_from(now);
            return true;
        }
        now < self.by
    }
}

/// Writes the whole of `bytes` by `by`, or gives up on the peer.
///
/// The mirror of [`fill`], and there for the mirror reason: `write_all` loops
/// over partial writes, the socket's deadline is per `write` call, and a peer
/// accepting one byte per deadline restarts it every time. What that held was
/// not only the writing thread: everything queued behind it was held with it,
/// for a peer that had already decided not to read.
fn drain<W: Write>(writer: &mut W, bytes: &[u8], patience: &mut Patience) -> Result<(), WireError> {
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
        if sent < size && !patience.holds(sent, Instant::now()) {
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

    drain(writer, &frame, &mut Patience::started())?;
    writer.flush()?;
    Ok(())
}

/// Reads one framed message, up to whatever deadline `reader` carries.
///
/// Returns [`Incoming::Quiet`] when the deadline passes before a frame starts,
/// so a caller can tell an idle peer from one holding a frame open.
pub fn read_message<R: Read>(
    reader: &mut R,
    network: NetworkId,
    most: usize,
) -> Result<Incoming, WireError> {
    // The frame's own deadline. Started here rather than at the first byte,
    // which costs a peer that dawdles before speaking at most one read
    // deadline out of the twenty seconds; a peer with nothing to say at all
    // never reaches it, because the header read returns `Quiet` first and the
    // next call starts again.
    let mut patience = Patience::started();
    let mut header = [0u8; HEADER_BYTES];
    if fill(reader, &mut header, &mut patience)? == Filled::Nothing {
        return Ok(Incoming::Quiet);
    }

    let mut cursor = Reader::new(&header);
    let marker = u32::decode_from(&mut cursor)?;
    if marker != network.as_u32() {
        return Err(WireError::WrongNetwork {
            expected: network,
            found: NetworkId::new(marker),
        });
    }
    let declared = usize::try_from(u32::decode_from(&mut cursor)?).unwrap_or(usize::MAX);
    if declared > most.min(MAX_FRAME_BYTES) {
        return Err(WireError::FrameTooLarge { declared });
    }

    // What this caller will let this peer ask for, which is not the same
    // question as what the protocol allows. The cap used to be the protocol's
    // alone, and the comment here reasoned about the allocation: one megabyte,
    // bounded connections, fine. The allocation is the cheap half. The line
    // below decodes the frame, and decoding a frame full of notes decompresses
    // a point off the curve for every owner in it, so a megabyte from somebody
    // who had not yet said who they were bought a second and a third of this
    // node's processor. The cap is the caller's to state now, and the caller
    // that reads from a peer states a small one until the peer has introduced
    // itself.
    let mut body = vec![0u8; declared];
    if fill(reader, &mut body, &mut patience)? == Filled::Nothing {
        return Err(WireError::Stalled {
            had: 0,
            wanted: declared,
        });
    }
    Ok(Incoming::Message(crate::message::Message::decode(&body)?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, Read, Write};
    use std::time::Instant;

    use cairn_ledger::note::NetworkId;
    use cairn_primitives::codec::Encode;
    use cairn_primitives::Hash32;

    use super::{
        drain, fill, patience_from, read_message, write_message, Filled, Incoming, Patience,
        WireError, HEADER_BYTES, MAX_FRAME_BYTES,
    };
    use crate::message::{Joining, Message};

    const NETWORK: NetworkId = NetworkId::new(0x0a1b_2c3d);

    /// One thing a scripted socket does when asked.
    enum Turn {
        /// Hands over, or takes, at most this many bytes.
        Give(usize),
        /// Raises an error of this kind.
        Fail(io::ErrorKind),
    }

    /// A socket that does what it was told, in order, and then waits out its
    /// deadline for ever.
    struct Script {
        bytes: Vec<u8>,
        at: usize,
        turns: VecDeque<Turn>,
    }

    impl Script {
        fn new(bytes: Vec<u8>, turns: impl IntoIterator<Item = Turn>) -> Self {
            Self {
                bytes,
                at: 0,
                turns: turns.into_iter().collect(),
            }
        }
    }

    impl Read for Script {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            match self.turns.pop_front() {
                Some(Turn::Give(most)) => {
                    let rest = self.bytes.get(self.at..).unwrap_or_default();
                    let count = rest.len().min(out.len()).min(most);
                    for (slot, byte) in out.iter_mut().zip(rest).take(count) {
                        *slot = *byte;
                    }
                    self.at = self.at.saturating_add(count);
                    Ok(count)
                }
                Some(Turn::Fail(kind)) => Err(io::Error::from(kind)),
                None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        }
    }

    impl Write for Script {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            match self.turns.pop_front() {
                Some(Turn::Give(most)) => {
                    let count = bytes.len().min(most);
                    self.bytes
                        .extend_from_slice(bytes.get(..count).unwrap_or_default());
                    Ok(count)
                }
                Some(Turn::Fail(kind)) => Err(io::Error::from(kind)),
                None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn framed(message: &Message) -> Vec<u8> {
        let mut frame = Vec::new();
        write_message(&mut frame, NETWORK, message).unwrap();
        frame
    }

    /// Patience that ran out the moment it was made.
    fn spent() -> Patience {
        Patience {
            by: Instant::now(),
            marked: 0,
        }
    }

    /// A signal in the middle of a read loses nothing, and a frame that
    /// arrives a few bytes at a time is read whole.
    ///
    /// Every reader the tests handed this module either delivered what it
    /// was asked for or never finished, and none was interrupted. So a `fill`
    /// that treated an interrupted read as the connection failing passed, and
    /// so did one that gave a frame up after its first partial read.
    #[test]
    fn a_frame_read_in_pieces_and_interrupted_arrives_whole() {
        let message = Message::Ping(7);
        let frame = framed(&message);
        let mut turns = vec![Turn::Fail(io::ErrorKind::Interrupted)];
        turns.extend(frame.iter().map(|_| Turn::Give(3)));
        turns.insert(4, Turn::Fail(io::ErrorKind::Interrupted));
        let mut socket = Script::new(frame, turns);
        match read_message(&mut socket, NETWORK, MAX_FRAME_BYTES) {
            Ok(Incoming::Message(read)) => assert_eq!(read, message),
            other => panic!("a frame read in pieces, with signals, came back {other:?}"),
        }
    }

    /// A connection that fails is not a peer with nothing to say.
    ///
    /// Only the two kinds a socket's deadline raises are silence. Nothing
    /// handed this module any other error, so a `fill` that took every error
    /// for the deadline passed: a reset connection read as a quiet peer before
    /// a frame, and as a stalled one inside it, and the reading loop went
    /// round again on a socket that was already gone.
    #[test]
    fn a_connection_that_fails_is_not_a_quiet_peer() {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            let mut idle = Script::new(Vec::new(), [Turn::Fail(kind)]);
            assert!(
                matches!(
                    read_message(&mut idle, NETWORK, MAX_FRAME_BYTES),
                    Ok(Incoming::Quiet)
                ),
                "the deadline passing before a frame is not a failure"
            );
        }

        let mut reset = Script::new(Vec::new(), [Turn::Fail(io::ErrorKind::ConnectionReset)]);
        match read_message(&mut reset, NETWORK, MAX_FRAME_BYTES) {
            Err(WireError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            }
            other => panic!("a reset connection before a frame read as {other:?}"),
        }

        let frame = framed(&Message::Ping(7));
        let mut cut = Script::new(
            frame,
            [
                Turn::Give(HEADER_BYTES),
                Turn::Fail(io::ErrorKind::ConnectionReset),
            ],
        );
        match read_message(&mut cut, NETWORK, MAX_FRAME_BYTES) {
            Err(WireError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            }
            other => panic!("a connection reset inside a frame read as {other:?}"),
        }
    }

    /// A frame whose last byte arrives is taken, however late, and one that
    /// is still short when its patience is spent is not.
    ///
    /// The patience is asked between reads of a frame that is not finished
    /// yet. Nothing ran a frame to its end with the patience already spent,
    /// so a `fill` that asked it once more after the last byte passed, and
    /// threw away a whole frame for arriving at the deadline.
    #[test]
    fn a_frame_that_finishes_is_taken_and_one_that_does_not_is_not() {
        let mut buffer = [0u8; 8];
        let mut whole = Script::new(vec![1u8; 8], [Turn::Give(8)]);
        assert!(
            matches!(
                fill(&mut whole, &mut buffer, &mut spent()),
                Ok(Filled::Complete)
            ),
            "a frame that arrived whole was refused for being late"
        );

        let mut short = Script::new(vec![1u8; 8], [Turn::Give(1), Turn::Give(7)]);
        assert!(
            matches!(
                fill(&mut short, &mut buffer, &mut spent()),
                Err(WireError::Stalled { had: 1, wanted: 8 })
            ),
            "a frame still short when its patience was spent was read on"
        );
    }

    /// The same on the way out: the last byte taken is a frame sent, and a
    /// peer still short of it when the patience is spent is given up on.
    #[test]
    fn a_frame_that_is_taken_whole_is_sent_and_one_that_is_not_is_not() {
        let bytes = [1u8; 8];
        let mut whole = Script::new(Vec::new(), [Turn::Give(8)]);
        assert!(
            drain(&mut whole, &bytes, &mut spent()).is_ok(),
            "a frame the peer took whole was given up on for being late"
        );

        let mut short = Script::new(Vec::new(), [Turn::Give(1), Turn::Give(7)]);
        assert!(
            matches!(
                drain(&mut short, &bytes, &mut spent()),
                Err(WireError::Unaccepted { sent: 1, size: 8 })
            ),
            "a peer still short of the frame when its patience was spent was \
             written to on"
        );
    }

    /// A signal in the middle of a write loses nothing, and a peer that takes
    /// a frame a few bytes at a time is written the whole of it.
    ///
    /// The mirror of the first test here, and missing for the same reason:
    /// no writer the tests used was ever interrupted.
    #[test]
    fn a_frame_written_in_pieces_and_interrupted_is_sent_whole() {
        let message = Message::Ping(7);
        let frame = framed(&message);
        let mut turns = vec![Turn::Fail(io::ErrorKind::Interrupted)];
        turns.extend(frame.iter().map(|_| Turn::Give(3)));
        turns.insert(4, Turn::Fail(io::ErrorKind::Interrupted));
        let mut socket = Script::new(Vec::new(), turns);
        assert!(
            write_message(&mut socket, NETWORK, &message).is_ok(),
            "a peer taking the frame in pieces, with signals, was given up on"
        );
        assert_eq!(socket.bytes, frame, "what went out is not the frame");
    }

    /// Patience runs out at its deadline and not before, and is renewed by
    /// sixty four kilobytes and nothing less.
    ///
    /// The deadline was read off the clock inside the comparison, so the
    /// second it falls on could not be asked. And the renewal was held only
    /// by frames that moved a great deal or nothing, so a floor of about a
    /// kilobyte, which lets a dribbler hold a frame for a thousand renewals
    /// rather than sixteen, passed.
    #[test]
    fn patience_ends_at_its_deadline_and_is_renewed_by_sixty_four_kilobytes() {
        let start = Instant::now();
        let mut fresh = Patience {
            by: patience_from(start),
            marked: 0,
        };
        let by = fresh.by;
        assert!(fresh.holds(0, start), "patience ran out as it was given");
        assert!(!fresh.holds(0, by), "patience held at its own deadline");

        let mut late = Patience {
            by: start,
            marked: 0,
        };
        assert!(
            !late.holds(64 * 1024 - 1, start),
            "a frame was renewed for moving less than sixty four kilobytes"
        );
        assert!(
            late.holds(64 * 1024, start),
            "a frame that moved sixty four kilobytes was not renewed"
        );
    }

    /// A frame exactly as large as the wire takes is sent.
    ///
    /// The ceiling was asked from above only, with a frame past it, so a
    /// writer that refused the largest frame the reader accepts passed. That
    /// is the frame a block at the consensus limit comes closest to, and a
    /// node that could not send it could not hand its block to anyone.
    #[test]
    fn a_frame_exactly_at_the_ceiling_is_sent() {
        let empty = Message::JoinPart {
            what: Joining::Ledger,
            at: Hash32::ZERO,
            part: 0,
            parts: 1,
            bytes: Vec::new(),
        };
        let room = MAX_FRAME_BYTES.checked_sub(empty.encode().len()).unwrap();
        let largest = Message::JoinPart {
            what: Joining::Ledger,
            at: Hash32::ZERO,
            part: 0,
            parts: 1,
            bytes: vec![0u8; room],
        };
        assert_eq!(
            largest.encode().len(),
            MAX_FRAME_BYTES,
            "the message built is not exactly at the ceiling"
        );

        let mut written = Vec::new();
        assert!(
            write_message(&mut written, NETWORK, &largest).is_ok(),
            "a frame exactly at the ceiling was refused"
        );
        assert_eq!(
            Some(written.len()),
            MAX_FRAME_BYTES.checked_add(HEADER_BYTES),
            "the frame written is not the whole of it"
        );
    }
}

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

use std::io::{Read, Write};

use cairn_ledger::note::NetworkId;
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};

/// Largest message this node will read or write.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

const HEADER_BYTES: usize = 8;

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
}

/// Writes one framed message.
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

    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

/// Reads one framed message, blocking until it arrives.
pub fn read_message<R: Read>(
    reader: &mut R,
    network: NetworkId,
) -> Result<crate::message::Message, WireError> {
    let mut header = [0u8; HEADER_BYTES];
    reader.read_exact(&mut header)?;

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

    let mut body = vec![0u8; declared];
    reader.read_exact(&mut body)?;
    Ok(crate::message::Message::decode(&body)?)
}

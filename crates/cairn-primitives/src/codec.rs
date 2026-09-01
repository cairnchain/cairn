//! Canonical binary encoding.
//!
//! Consensus depends on two nodes producing byte identical encodings, so the
//! format admits exactly one representation of any value:
//!
//! - integers are fixed width little endian, never variable length,
//! - sequences carry a `u32` little endian element count,
//! - decoding rejects trailing bytes.
//!
//! Variable length integers are deliberately avoided. They save a few bytes and
//! introduce a class of bug where the same value has several valid encodings,
//! which lets an attacker mutate a transaction identifier without invalidating
//! its signatures.

use crate::amount::Amount;
use crate::hash::{Hash32, HASH_LEN};

/// Upper bound on the element count of any decoded sequence.
///
/// Blocks are bounded far below this by consensus rules. The limit exists so
/// that a malformed frame cannot request an unbounded allocation.
pub const MAX_SEQUENCE_LEN: usize = 1 << 20;

/// Capacity reserved up front when decoding a sequence.
///
/// The declared length is attacker controlled, so it is used to drive the loop
/// but never to size the initial allocation.
const INITIAL_SEQUENCE_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("input ended before the value was complete")]
    UnexpectedEnd,
    #[error("input has {0} unconsumed trailing bytes")]
    TrailingBytes(usize),
    #[error("sequence declares {declared} elements, limit is {MAX_SEQUENCE_LEN}")]
    SequenceTooLong { declared: usize },
    #[error("value is not a valid {type_name}")]
    InvalidValue { type_name: &'static str },
}

/// Serialises a value into its single canonical byte form.
pub trait Encode {
    fn encode_to(&self, out: &mut Vec<u8>);

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_to(&mut out);
        out
    }
}

/// Parses a value written by [`Encode`].
pub trait Decode: Sized {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError>;

    /// Decodes a complete frame, rejecting any trailing bytes.
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes);
        let value = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
}

/// A cursor over a byte frame.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    /// Succeeds only if the whole frame was consumed.
    pub fn finish(self) -> Result<(), CodecError> {
        match self.remaining() {
            0 => Ok(()),
            unconsumed => Err(CodecError::TrailingBytes(unconsumed)),
        }
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CodecError::UnexpectedEnd)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(CodecError::UnexpectedEnd)?;
        self.offset = end;
        Ok(slice)
    }

    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let slice = self.take(N)?;
        <[u8; N]>::try_from(slice).map_err(|_| CodecError::UnexpectedEnd)
    }
}

macro_rules! impl_codec_for_int {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Encode for $ty {
                fn encode_to(&self, out: &mut Vec<u8>) {
                    out.extend_from_slice(&self.to_le_bytes());
                }
            }

            impl Decode for $ty {
                fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
                    const LEN: usize = std::mem::size_of::<$ty>();
                    Ok(<$ty>::from_le_bytes(reader.take_array::<LEN>()?))
                }
            }
        )*
    };
}

impl_codec_for_int!(u8, u16, u32, u64, u128);

impl<const N: usize> Encode for [u8; N] {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        reader.take_array::<N>()
    }
}

impl Encode for Hash32 {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

impl Decode for Hash32 {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self::from_bytes(reader.take_array::<HASH_LEN>()?))
    }
}

impl Encode for Amount {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.as_pebbles().encode_to(out);
    }
}

impl Decode for Amount {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let pebbles = u64::decode_from(reader)?;
        Self::from_pebbles(pebbles).ok_or(CodecError::InvalidValue {
            type_name: "Amount",
        })
    }
}

impl<T: Encode> Encode for Vec<T> {
    /// The two sides of this pair do not agree about everything, and the part
    /// they do not agree about is unreachable rather than handled.
    ///
    /// This writes whatever length it is given; the decoder refuses anything
    /// past [`MAX_SEQUENCE_LEN`]. So a sequence longer than that encodes to a
    /// frame nothing can read back, and a node could take an identifier over a
    /// structure it cannot re-parse. Nothing on the wire comes near the
    /// ceiling, since a block is capped far below it and every sequence in a
    /// block is capped again by its own rule.
    ///
    /// Silently writing a shorter count was considered and is worse: it would
    /// give two different sequences the same encoding, which is the one
    /// property this whole module exists to deny. Refusing is not available
    /// either, since encoding cannot fail. So the disagreement is left where
    /// it is, made loud in a debug build, and written down here so that
    /// whoever adds a type that could reach it finds this note first.
    fn encode_to(&self, out: &mut Vec<u8>) {
        debug_assert!(
            self.len() <= MAX_SEQUENCE_LEN,
            "a sequence of {} is past what the decoder will read back",
            self.len()
        );
        let len = u32::try_from(self.len()).unwrap_or(u32::MAX);
        len.encode_to(out);
        for item in self {
            item.encode_to(out);
        }
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let declared = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
        if declared > MAX_SEQUENCE_LEN {
            return Err(CodecError::SequenceTooLong { declared });
        }
        let mut items = Self::with_capacity(declared.min(INITIAL_SEQUENCE_CAPACITY));
        for _ in 0..declared {
            items.push(T::decode_from(reader)?);
        }
        Ok(items)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn roundtrip<T: Encode + Decode + PartialEq + std::fmt::Debug>(value: &T) {
        let bytes = value.encode();
        let decoded = T::decode(&bytes).unwrap();
        assert_eq!(&decoded, value);
        assert_eq!(decoded.encode(), bytes, "encoding is not canonical");
    }

    #[test]
    fn integers_roundtrip_little_endian() {
        roundtrip(&0x0102_0304_u32);
        assert_eq!(0x0102_0304_u32.encode(), vec![0x04, 0x03, 0x02, 0x01]);
        roundtrip(&u64::MAX);
        roundtrip(&7u8);
    }

    #[test]
    fn wide_integers_roundtrip() {
        roundtrip(&u128::MAX);
        roundtrip(&0u128);
        assert_eq!(1u128.encode().len(), 16);
    }

    #[test]
    fn hash_and_amount_roundtrip() {
        roundtrip(&Hash32::from_bytes([9; HASH_LEN]));
        roundtrip(&Amount::from_pebbles(123_456).unwrap());
    }

    #[test]
    fn amount_above_the_ceiling_is_rejected() {
        let bytes = (Amount::MAX_MONEY.as_pebbles() + 1).encode();
        assert_eq!(
            Amount::decode(&bytes),
            Err(CodecError::InvalidValue {
                type_name: "Amount"
            })
        );
    }

    #[test]
    fn sequences_roundtrip_with_a_length_prefix() {
        let values: Vec<u32> = vec![1, 2, 3];
        roundtrip(&values);
        assert_eq!(values.encode()[..4], [3, 0, 0, 0]);
        roundtrip(&Vec::<u32>::new());
    }

    #[test]
    fn oversized_sequence_is_rejected_without_allocating() {
        let mut bytes = u32::MAX.encode();
        bytes.extend_from_slice(&[0; 8]);
        assert!(matches!(
            Vec::<u32>::decode(&bytes),
            Err(CodecError::SequenceTooLong { .. })
        ));
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert_eq!(u32::decode(&[1, 2]), Err(CodecError::UnexpectedEnd));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(
            u32::decode(&[1, 2, 3, 4, 5]),
            Err(CodecError::TrailingBytes(1))
        );
    }
}

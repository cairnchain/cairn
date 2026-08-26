//! Positions in the accumulator.

use std::fmt;

use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::Hash32;

pub const KEY_LEN: usize = 32;

/// Deepest a key can sit, one level per bit.
pub const MAX_DEPTH: usize = KEY_LEN * 8;

/// Where an entry sits in the tree.
///
/// Callers derive keys by hashing, so they are spread uniformly and the tree
/// stays balanced. An adversary who could choose keys freely could pile entries
/// onto one path and make proofs there as deep as [`MAX_DEPTH`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn from_hash(hash: Hash32) -> Self {
        Self(hash.to_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The bit that picks a side at `depth`, counting from the most significant
    /// bit of the first byte. `true` means the right child.
    pub fn bit(&self, depth: usize) -> bool {
        let byte_index = depth.checked_div(8).unwrap_or(0);
        let bit_index = u32::try_from(depth.checked_rem(8).unwrap_or(0)).unwrap_or(0);
        self.0.get(byte_index).is_some_and(|byte| {
            let shift = 7u32.saturating_sub(bit_index);
            byte.checked_shr(shift).unwrap_or(0) & 1 == 1
        })
    }

    /// Whether the two keys agree on their first `bits` bits.
    pub fn shares_prefix(&self, other: &Self, bits: usize) -> bool {
        let bits = bits.min(MAX_DEPTH);
        let whole_bytes = bits.checked_div(8).unwrap_or(0);
        let leftover_bits = u32::try_from(bits.checked_rem(8).unwrap_or(0)).unwrap_or(0);

        match (self.0.get(..whole_bytes), other.0.get(..whole_bytes)) {
            (Some(mine), Some(theirs)) if mine == theirs => {}
            _ => return false,
        }
        if leftover_bits == 0 {
            return true;
        }
        let mask = !0xffu8.checked_shr(leftover_bits).unwrap_or(0);
        match (self.0.get(whole_bytes), other.0.get(whole_bytes)) {
            (Some(mine), Some(theirs)) => (mine & mask) == (theirs & mask),
            _ => false,
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({self})")
    }
}

impl Encode for Key {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Key {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(reader.take_array::<KEY_LEN>()?))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn bits_read_from_the_most_significant_end() {
        let mut bytes = [0u8; KEY_LEN];
        bytes[0] = 0b1010_0000;
        let key = Key::from_bytes(bytes);
        assert!(key.bit(0));
        assert!(!key.bit(1));
        assert!(key.bit(2));
        assert!(!key.bit(3));
    }

    #[test]
    fn bits_past_the_key_read_as_zero() {
        assert!(!Key::from_bytes([0xff; KEY_LEN]).bit(MAX_DEPTH));
    }

    #[test]
    fn a_key_shares_every_prefix_with_itself() {
        let key = Key::from_bytes([0x5a; KEY_LEN]);
        for bits in 0..=MAX_DEPTH {
            assert!(key.shares_prefix(&key, bits));
        }
    }

    #[test]
    fn prefixes_stop_agreeing_at_the_first_differing_bit() {
        let mut other = [0u8; KEY_LEN];
        other[0] = 0b0000_1000;
        let zero = Key::from_bytes([0u8; KEY_LEN]);
        let other = Key::from_bytes(other);

        for bits in 0..=4 {
            assert!(zero.shares_prefix(&other, bits), "agree up to bit {bits}");
        }
        for bits in 5..=8 {
            assert!(!zero.shares_prefix(&other, bits), "differ from bit {bits}");
        }
    }

    #[test]
    fn keys_roundtrip() {
        let key = Key::from_bytes([7; KEY_LEN]);
        assert_eq!(Key::decode(&key.encode()).unwrap(), key);
    }
}

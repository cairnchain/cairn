//! Notes and the identifiers that address them.

use cairn_crypto::PublicKey;
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::{Amount, Hash32};

/// Identifies which chain a message belongs to.
///
/// It is committed to by every signature, so a transaction signed for one
/// network cannot be replayed on another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkId(u32);

impl NetworkId {
    pub const MAINNET: Self = Self(0x4341_524e);
    pub const TESTNET: Self = Self(0x4341_5254);

    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl Encode for NetworkId {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.0.encode_to(out);
    }
}

impl Decode for NetworkId {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(u32::decode_from(reader)?))
    }
}

/// Addresses one note by the transaction that created it.
///
/// Ordering is defined so the note set has a single canonical enumeration,
/// which the state commitment depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoteId {
    pub source: Hash32,
    pub index: u32,
}

impl NoteId {
    pub const fn new(source: Hash32, index: u32) -> Self {
        Self { source, index }
    }
}

impl Encode for NoteId {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.source.encode_to(out);
        self.index.encode_to(out);
    }
}

impl Decode for NoteId {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            source: Hash32::decode_from(reader)?,
            index: u32::decode_from(reader)?,
        })
    }
}

/// A unit of value locked to one public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub value: Amount,
    pub owner: PublicKey,
}

impl Note {
    pub const fn new(value: Amount, owner: PublicKey) -> Self {
        Self { value, owner }
    }
}

impl Encode for Note {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.value.encode_to(out);
        self.owner.encode_to(out);
    }
}

impl Decode for Note {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            value: Amount::decode_from(reader)?,
            owner: PublicKey::decode_from(reader)?,
        })
    }
}

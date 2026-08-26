//! Transactions.
//!
//! Two kinds exist and they are separate types rather than one type with a
//! special case. A [`CoinbaseTransaction`] creates value and has no inputs; a
//! [`Transfer`] moves value and always has inputs. Keeping them apart means no
//! code path can mint money by handing a transfer an empty input list.

use cairn_crypto::{SecretKey, Signature};
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::{Domain, Hasher};
use cairn_primitives::{Amount, Hash32};

use crate::note::{NetworkId, Note, NoteId};

pub const TRANSFER_VERSION: u16 = 1;
pub const COINBASE_VERSION: u16 = 1;

/// One spent note together with the signature authorising the spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub note_id: NoteId,
    pub signature: Signature,
}

impl Input {
    /// An input that still has to be signed.
    pub fn unsigned(note_id: NoteId) -> Self {
        Self {
            note_id,
            signature: Signature::unsigned(),
        }
    }
}

impl Encode for Input {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.note_id.encode_to(out);
        self.signature.encode_to(out);
    }
}

impl Decode for Input {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            note_id: NoteId::decode_from(reader)?,
            signature: Signature::decode_from(reader)?,
        })
    }
}

/// Spends existing notes and creates new ones.
///
/// The difference between the value spent and the value created is the fee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub version: u16,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Note>,
}

impl Transfer {
    pub const fn new(inputs: Vec<Input>, outputs: Vec<Note>) -> Self {
        Self {
            version: TRANSFER_VERSION,
            inputs,
            outputs,
        }
    }

    /// Encodes everything the identifier commits to, which is everything except
    /// the signatures.
    fn encode_body(&self, out: &mut Vec<u8>) {
        self.version.encode_to(out);
        let input_count = u32::try_from(self.inputs.len()).unwrap_or(u32::MAX);
        input_count.encode_to(out);
        for input in &self.inputs {
            input.note_id.encode_to(out);
        }
        self.outputs.encode_to(out);
    }

    /// The transaction identifier.
    ///
    /// Signatures are excluded. If they were included, any change to a
    /// signature would change the identifier, and every transaction already
    /// built on top of this one would silently become invalid. Excluding them
    /// also means the identifier is known before the transaction is signed.
    pub fn id(&self) -> Hash32 {
        let mut body = Vec::new();
        self.encode_body(&mut body);
        cairn_primitives::hash::hash(Domain::TransferId, &body)
    }

    /// The message the holder of `spent` signs to authorise input `input_index`.
    ///
    /// The value and owner of the spent note are committed to alongside the
    /// transaction body. Without that, a wallet shown a false input value would
    /// sign a transaction whose real fee is the difference, and the signature
    /// would be perfectly valid.
    pub fn signature_message(&self, network: NetworkId, input_index: u32, spent: &Note) -> Hash32 {
        let mut hasher = Hasher::new(Domain::SignatureMessage);
        hasher.update(&network.encode());
        hasher.update(&self.version.encode());
        hasher.update(self.id().as_bytes());
        hasher.update(&input_index.encode());
        hasher.update(&spent.value.encode());
        hasher.update(spent.owner.as_bytes());
        hasher.finalize()
    }

    /// Signs input `input_index` with `secret`, which must own `spent`.
    pub fn sign_input(
        &mut self,
        network: NetworkId,
        input_index: u32,
        spent: &Note,
        secret: &SecretKey,
    ) {
        let message = self.signature_message(network, input_index, spent);
        let signature = secret.sign(message.as_bytes());
        if let Some(input) = usize::try_from(input_index)
            .ok()
            .and_then(|i| self.inputs.get_mut(i))
        {
            input.signature = signature;
        }
    }

    /// Total value created by this transfer.
    pub fn total_output(&self) -> Option<Amount> {
        Amount::checked_sum(self.outputs.iter().map(|note| note.value))
    }

    /// The notes this transfer creates, paired with the identifiers they take.
    pub fn created_notes(&self) -> Vec<(NoteId, Note)> {
        let id = self.id();
        self.outputs
            .iter()
            .enumerate()
            .map(|(index, note)| {
                let index = u32::try_from(index).unwrap_or(u32::MAX);
                (NoteId::new(id, index), *note)
            })
            .collect()
    }
}

impl Encode for Transfer {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.version.encode_to(out);
        self.inputs.encode_to(out);
        self.outputs.encode_to(out);
    }
}

impl Decode for Transfer {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u16::decode_from(reader)?,
            inputs: Vec::decode_from(reader)?,
            outputs: Vec::decode_from(reader)?,
        })
    }
}

/// The only transaction that creates value.
///
/// It carries the height it belongs to, so two coinbases paying the same
/// outputs at different heights cannot share an identifier. `extra_nonce` gives
/// a miner search space beyond the header nonce and separates two candidate
/// blocks that are otherwise identical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseTransaction {
    pub version: u16,
    pub height: u64,
    pub outputs: Vec<Note>,
    pub extra_nonce: [u8; 8],
}

impl CoinbaseTransaction {
    pub const fn new(height: u64, outputs: Vec<Note>, extra_nonce: [u8; 8]) -> Self {
        Self {
            version: COINBASE_VERSION,
            height,
            outputs,
            extra_nonce,
        }
    }

    pub fn id(&self) -> Hash32 {
        cairn_primitives::hash::hash(Domain::CoinbaseId, &self.encode())
    }

    pub fn total_output(&self) -> Option<Amount> {
        Amount::checked_sum(self.outputs.iter().map(|note| note.value))
    }

    pub fn created_notes(&self) -> Vec<(NoteId, Note)> {
        let id = self.id();
        self.outputs
            .iter()
            .enumerate()
            .map(|(index, note)| {
                let index = u32::try_from(index).unwrap_or(u32::MAX);
                (NoteId::new(id, index), *note)
            })
            .collect()
    }
}

impl Encode for CoinbaseTransaction {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.version.encode_to(out);
        self.height.encode_to(out);
        self.outputs.encode_to(out);
        self.extra_nonce.encode_to(out);
    }
}

impl Decode for CoinbaseTransaction {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u16::decode_from(reader)?,
            height: u64::decode_from(reader)?,
            outputs: Vec::decode_from(reader)?,
            extra_nonce: <[u8; 8]>::decode_from(reader)?,
        })
    }
}

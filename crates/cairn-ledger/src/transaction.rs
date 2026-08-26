//! Transactions.
//!
//! Two kinds exist and they are separate types rather than one type with a
//! special case. A [`CoinbaseTransaction`] creates value and has no inputs; a
//! [`Transfer`] moves value and always has inputs. Keeping them apart means no
//! code path can mint money by handing a transfer an empty input list.

use cairn_accumulator::Proof;
use cairn_crypto::{SecretKey, Signature};
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::{Domain, Hasher};
use cairn_primitives::{Amount, Hash32};

use crate::note::{NetworkId, Note, NoteId};

pub const TRANSFER_VERSION: u16 = 1;
pub const COINBASE_VERSION: u16 = 1;

/// The note and the proof a spender supplies for a note in the cold set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdWitness {
    pub note: Note,
    pub proof: Proof,
}

/// How the spender makes the note being spent available to a validator.
///
/// The cold payload is boxed. Nearly every input spends from the hot set, an
/// enum is as large as its largest variant, and leaving a proof sized hole in
/// every hot input would waste memory in exactly the place this design exists
/// to save it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Witness {
    /// The note is in the hot set, so every node already holds it and the
    /// identifier is enough.
    Hot,
    /// The note has fallen to the cold set, which no node holds. The spender
    /// supplies it along with a proof that it belongs to the cold commitment.
    Cold(Box<ColdWitness>),
}

impl Encode for Witness {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::Hot => 0u8.encode_to(out),
            Self::Cold(cold) => {
                1u8.encode_to(out);
                cold.note.encode_to(out);
                cold.proof.encode_to(out);
            }
        }
    }
}

impl Decode for Witness {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode_from(reader)? {
            0 => Ok(Self::Hot),
            1 => Ok(Self::Cold(Box::new(ColdWitness {
                note: Note::decode_from(reader)?,
                proof: Proof::decode_from(reader)?,
            }))),
            _ => Err(CodecError::InvalidValue {
                type_name: "Witness",
            }),
        }
    }
}

/// One spent note, with what a validator needs to see it and the signature
/// authorising the spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub note_id: NoteId,
    pub witness: Witness,
    pub signature: Signature,
}

impl Input {
    /// Spends a note the nodes still hold. Signed afterwards.
    pub fn hot(note_id: NoteId) -> Self {
        Self {
            note_id,
            witness: Witness::Hot,
            signature: Signature::unsigned(),
        }
    }

    /// Spends a note from the cold set, carrying it and its proof. Signed
    /// afterwards.
    pub fn cold(note_id: NoteId, note: Note, proof: Proof) -> Self {
        Self {
            note_id,
            witness: Witness::Cold(Box::new(ColdWitness { note, proof })),
            signature: Signature::unsigned(),
        }
    }
}

impl Encode for Input {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.note_id.encode_to(out);
        self.witness.encode_to(out);
        self.signature.encode_to(out);
    }
}

impl Decode for Input {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            note_id: NoteId::decode_from(reader)?,
            witness: Witness::decode_from(reader)?,
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

    /// Encodes everything the identifier commits to: the version, the notes
    /// being spent, and the notes being created.
    ///
    /// Signatures and witnesses are both left out. A stale proof has to be
    /// refreshable without changing the transaction identifier, for the same
    /// reason a signature must not change it: everything already built on top
    /// of this transaction would otherwise become invalid.
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

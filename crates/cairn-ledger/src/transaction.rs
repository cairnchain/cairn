//! Transactions.
//!
//! Two kinds exist and they are separate types rather than one type with a
//! special case. A [`CoinbaseTransaction`] creates value and has no inputs; a
//! [`Transfer`] moves value and always has inputs. Keeping them apart means no
//! code path can mint money by handing a transfer an empty input list.

use cairn_accumulator::ForestProof;
use cairn_crypto::{SecretKey, Signature, PUBLIC_KEY_LEN};
use cairn_primitives::codec::{take_at_most, CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::{Domain, Hasher};
use cairn_primitives::{Amount, Hash32};

use crate::note::{NetworkId, Note, NoteId};

pub const TRANSFER_VERSION: u16 = 1;
pub const COINBASE_VERSION: u16 = 1;

/// Bytes a coinbase may carry beyond what consensus reads.
///
/// It gives a miner room to search beyond the header nonce, and it is where
/// the first block of a network says something about the day it was made. A
/// piece of public news nobody could have known in advance is what shows the
/// chain was not quietly started weeks earlier.
pub const MAX_COINBASE_EXTRA: usize = 64;

/// The most inputs a transfer's decoder will build.
///
/// Not a second consensus rule. It is the same rule read earlier: a transfer
/// past `max_inputs_per_transfer` is refused by every network this build
/// knows, and the assertion beside [`crate::validation::ConsensusParams`]
/// stops a build where that stops being true.
///
/// It is here because decoding is not free and happens before any rule has
/// looked at the frame. Without a ceiling the only bound was the frame, so a
/// megabyte of repeated inputs was built in full and then refused for its
/// shape. Reading one no longer does curve arithmetic, since a note's owner is
/// an address and an input's key is carried as bytes, but building what was
/// read still costs an allocation for each, and the rules already say how many
/// can be worth building.
pub const MOST_INPUTS: usize = 256;

/// The most outputs a transfer's decoder will build. See [`MOST_INPUTS`].
pub const MOST_OUTPUTS: usize = 256;

/// The most outputs a coinbase's decoder will build. See [`MOST_INPUTS`].
///
/// A coinbase refuses an oversized `extra` where it is read rather than where
/// it is judged, for the same reason and by the same argument.
///
/// That sentence stood here before it was true. `extra` was read as an
/// ordinary sequence, held only to [`cairn_primitives::codec::MAX_SEQUENCE_LEN`]
/// and measured against [`MAX_COINBASE_EXTRA`] once it was built, one line
/// under a field that did it the other way. What gave it away was reading the
/// two lines together rather than reading this comment.
pub const MOST_COINBASE_OUTPUTS: usize = 16;

/// The note and the proof a spender supplies for a note in the cold set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdWitness {
    pub note: Note,
    /// Where the note sits in the forest. A proof says nothing without it: the
    /// same siblings would carry a different leaf at a different place.
    pub position: u64,
    pub proof: ForestProof,
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
                cold.position.encode_to(out);
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
                position: u64::decode_from(reader)?,
                proof: ForestProof::decode_from(reader)?,
            }))),
            _ => Err(CodecError::InvalidValue {
                type_name: "Witness",
            }),
        }
    }
}

/// One spent note, with what a validator needs to see it, the key that owns
/// it and the signature authorising the spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub note_id: NoteId,
    pub witness: Witness,
    /// The Ed25519 key whose address owns the note, as its thirty two bytes.
    ///
    /// Carried as bytes and decoded nowhere on the wire. A validator hashes
    /// it and compares the hash with the note's owner first, which costs one
    /// hash, and decodes it only to verify the signature, once the hash has
    /// matched. A key of another scheme would arrive in another transfer
    /// version, which names its own encoding.
    ///
    /// Not in the transfer's identifier, for the reason the signature is not:
    /// the identifier is known before anything is signed. It cannot be swapped
    /// for another key either way, since only one key hashes to the owner.
    pub key: [u8; PUBLIC_KEY_LEN],
    pub signature: Signature,
}

impl Input {
    /// Spends a note the nodes still hold. Signed afterwards, which is also
    /// when the key is filled in.
    pub fn hot(note_id: NoteId) -> Self {
        Self {
            note_id,
            witness: Witness::Hot,
            key: [0u8; PUBLIC_KEY_LEN],
            signature: Signature::unsigned(),
        }
    }

    /// Spends a note from the cold set, carrying it, where it sits, and the
    /// proof. Signed afterwards, which is also when the key is filled in.
    pub fn cold(note_id: NoteId, note: Note, position: u64, proof: ForestProof) -> Self {
        Self {
            note_id,
            witness: Witness::Cold(Box::new(ColdWitness {
                note,
                position,
                proof,
            })),
            key: [0u8; PUBLIC_KEY_LEN],
            signature: Signature::unsigned(),
        }
    }
}

impl Encode for Input {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.note_id.encode_to(out);
        self.witness.encode_to(out);
        out.extend_from_slice(&self.key);
        self.signature.encode_to(out);
    }
}

impl Decode for Input {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            note_id: NoteId::decode_from(reader)?,
            witness: Witness::decode_from(reader)?,
            key: reader.take_array::<PUBLIC_KEY_LEN>()?,
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
    /// Signatures, keys and witnesses are all left out. A stale proof has to
    /// be refreshable without changing the transaction identifier, for the
    /// same reason a signature must not change it: everything already built
    /// on top of this transaction would otherwise become invalid. The key goes
    /// with the signature, which is made with it.
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

    /// Everything a transfer's signatures commit to that is the same for all
    /// of them, worked out once.
    ///
    /// See [`Signing`] for why this exists rather than being asked for again
    /// at each input.
    pub fn signing(&self, network: NetworkId) -> Signing {
        Signing {
            network,
            version: self.version,
            id: self.id(),
        }
    }

    /// The message the holder of `spent` signs to authorise input `input_index`.
    ///
    /// The value and owner of the spent note are committed to alongside the
    /// transaction body. Without that, a wallet shown a false input value would
    /// sign a transaction whose real fee is the difference, and the signature
    /// would be perfectly valid. The owner is the note's address, the hash of
    /// the key that signs.
    ///
    /// One input's worth. Anything asking for several should take a [`Signing`]
    /// once and derive them from it.
    pub fn signature_message(&self, network: NetworkId, input_index: u32, spent: &Note) -> Hash32 {
        self.signing(network).message(input_index, spent)
    }

    /// Signs input `input_index` with `secret`, which must own `spent`, and
    /// puts its public key in the input beside the signature.
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
            input.key = secret.public_key().to_bytes();
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

/// What every signature on one transfer commits to, held rather than redone.
///
/// The identifier is the expensive half of a signature message: it encodes the
/// whole body and hashes it. It does not depend on which input is being
/// signed, so asking for it once per input made a transfer cost the square of
/// its own size. At the two hundred and fifty six inputs the rules allow, a
/// thirty six kilobyte transfer was five megabytes encoded and five megabytes
/// hashed, all of it before the first signature was looked at, and the first
/// bad one then refused the lot for the price of one comparison. A peer could
/// send that as fast as it could upload.
///
/// Nothing about what is signed changed. The identifier deliberately excludes
/// the signatures, so that it is known before signing, which is exactly what
/// makes it one value for the whole transfer rather than one per input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signing {
    network: NetworkId,
    version: u16,
    id: Hash32,
}

impl Signing {
    pub const fn id(&self) -> Hash32 {
        self.id
    }

    /// The message the holder of `spent` signs to authorise `input_index`.
    pub fn message(&self, input_index: u32, spent: &Note) -> Hash32 {
        let mut hasher = Hasher::new(Domain::SignatureMessage);
        hasher.update(&self.network.encode());
        hasher.update(&self.version.encode());
        hasher.update(self.id.as_bytes());
        hasher.update(&input_index.encode());
        hasher.update(&spent.value.encode());
        hasher.update(spent.owner.as_bytes());
        hasher.finalize()
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
            inputs: take_at_most(reader, MOST_INPUTS, "transfer inputs")?,
            outputs: take_at_most(reader, MOST_OUTPUTS, "transfer outputs")?,
        })
    }
}

/// The only transaction that creates value.
///
/// It carries the height it belongs to, so two coinbases paying the same
/// outputs at different heights cannot share an identifier. `extra` gives
/// a miner search space beyond the header nonce and separates two candidate
/// blocks that are otherwise identical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseTransaction {
    pub version: u16,
    pub height: u64,
    pub outputs: Vec<Note>,
    pub extra: Vec<u8>,
}

impl CoinbaseTransaction {
    pub const fn new(height: u64, outputs: Vec<Note>) -> Self {
        Self {
            version: COINBASE_VERSION,
            height,
            outputs,
            extra: Vec::new(),
        }
    }

    /// The same, carrying something beyond what consensus reads.
    ///
    /// A miner could use it as search space past the header nonce; the miner
    /// in this workspace builds with [`CoinbaseTransaction::new`] and never
    /// does. The first block
    /// of a network uses it to say something about the day it was made: a
    /// piece of public news nobody could have known in advance is what shows
    /// the chain was not quietly started weeks earlier.
    pub fn with_extra(height: u64, outputs: Vec<Note>, extra: Vec<u8>) -> Self {
        Self {
            version: COINBASE_VERSION,
            height,
            outputs,
            extra,
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
        self.extra.encode_to(out);
    }
}

impl Decode for CoinbaseTransaction {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u16::decode_from(reader)?,
            height: u64::decode_from(reader)?,
            outputs: take_at_most(reader, MOST_COINBASE_OUTPUTS, "coinbase outputs")?,
            extra: take_at_most(reader, MAX_COINBASE_EXTRA, "coinbase extra")?,
        })
    }
}

//! Notes, the addresses that may spend them, and the identifiers that name
//! them.

use cairn_crypto::{PublicKey, PUBLIC_KEY_LEN};
use cairn_primitives::bech32m::{self, Bech32mError};
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::{Domain, Hasher, HASH_LEN};
use cairn_primitives::{Amount, Hash32};

/// Identifies which chain a message belongs to.
///
/// It is committed to by every signature, so a transaction signed for one
/// network cannot be replayed on another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkId(u32);

impl NetworkId {
    pub const MAINNET: Self = Self(0x4341_524e);
    /// The first public test network.
    ///
    /// Test networks are numbered because they get thrown away. A rule that
    /// has to change makes every block already mined invalid, so the network
    /// starts over, and the next one takes the next number. A node still on
    /// the old one is then told plainly that it is on another network, rather
    /// than failing somewhere confusing.
    pub const TESTNET_1: Self = Self(0x4341_5254);
    /// The second, which exists because the header gained the two fields that
    /// make it possible to join this chain without downloading all of it.
    ///
    /// That is a change to the shape of a header, so every block mined under
    /// the old shape is invalid under the new one, and the rule above applies
    /// to the letter: the network starts over and takes the next number. It
    /// cost nothing this time, and it is exactly the change that could not
    /// have been made after a network had value on it.
    pub const TESTNET_2: Self = Self(0x4341_5255);
    /// The third, which exists because the state root now commits to the grace
    /// window as well as to the two tiers.
    ///
    /// The window decides what can be spent without a proof. With nothing
    /// committing to it, a node handed a state rather than building its own
    /// would start with an empty window and refuse, for the next sixty four
    /// blocks, spends the rest of the network accepts: a fork with nobody at
    /// fault. Found while writing the exchange that hands a newcomer a state,
    /// which is the only thing that would have found it.
    ///
    /// Changing what a header commits to invalidates every block mined under
    /// the old rule, so the network starts over and takes the next number.
    pub const TESTNET_3: Self = Self(0x4341_5256);
    /// The fourth, because a cold note could be spent twice.
    ///
    /// A proof was accepted if it matched the cold set as it stood at any of
    /// the last thirty two blocks, so that a spender who took one a few blocks
    /// ago was not punished for the wait. Accepting it was half a rule: the
    /// step that takes the note out folds along the path the proof carries,
    /// and an old path does not reach the root that is there now, so the
    /// removal did nothing, said so through a value nobody read, and the note
    /// stayed to be spent again. Every node computed the same wrong state, so
    /// they all agreed and nothing forked.
    ///
    /// A proof is now worth what it is worth now, and the window that was kept
    /// for it left the state root with it. Both change what a header commits
    /// to, so every block mined under the old rule is invalid and the network
    /// starts over. The chain it replaces could mint from nothing, which is
    /// not a chain to carry forward under a schedule.
    pub const TESTNET_4: Self = Self(0x4341_5257);
    /// The fifth, because a stranger could hand a newcomer a chain nobody
    /// mined, and a miner could talk the difficulty down to nothing.
    ///
    /// Two rules changed and either one on its own would have been enough. A
    /// tip has to open the header it was built on, and the run of headers
    /// between a handed-over ledger and the tip has to travel with it and be
    /// checked block by block, so weight can no longer be borrowed from a
    /// chain somebody else mined. And the retarget, a moving average then, came
    /// to read solve times as signed values along a timeline of its own, so a
    /// miner dating its blocks ahead no longer took six minutes from the
    /// measurement and gave one second back; past a sixth of the hash rate
    /// that had had no equilibrium at all.
    ///
    /// The second of those changes what difficulty every block must carry, so
    /// every block mined under the old rule is invalid under this one and the
    /// network starts over. The first changes the shape of two exchanges, and
    /// a node still on testnet-4 is told plainly that it is on another network
    /// rather than failing somewhere confusing.
    pub const TESTNET_5: Self = Self(0x4341_5258);
    /// The sixth, because a block reward could be spent before its block was
    /// settled, a ledger could not say how much money existed, and a state
    /// with a spent note in its grace window could not be handed over at all.
    ///
    /// The last of those was the one that mattered. A newcomer takes a ledger
    /// rather than reading thirty years of blocks, and that ledger carries the
    /// window of notes that fell recently. A note spent out of that window
    /// left the window listing it while its proof had been dropped, so the
    /// handover was refused, and the window turns over in twelve blocks on a
    /// busy chain. Joining was therefore broken essentially always, which is
    /// the one thing this whole design exists to prevent.
    ///
    /// A spend now takes the note off the window, which changes what a header
    /// commits to. So do the other two: a reward that cannot move until its
    /// block is past reorganisation, and a running supply the state root
    /// carries so that money out of nothing becomes a fork rather than
    /// something every node agrees about. Every block mined under the old
    /// rules is invalid under these, so the network starts over.
    pub const TESTNET_6: Self = Self(0x4341_5259);
    /// The seventh, because a place in the hot set was free to a miner, a
    /// block did not commit to its signatures, an address showed its key, and
    /// two hash domains were told apart only by how long what they hashed
    /// happened to be.
    ///
    /// A transfer could take as many places in the hot set as it liked for
    /// the price of its bytes alone, and a miner packing its own blocks with
    /// them paid not even that: pushing every note in the tier out to a cold
    /// witness cost a stranger real money and cost the miner who did it
    /// nothing. A header named its body by a root built over every transfer's
    /// identifier, which by design leaves out witnesses and signatures, so a
    /// copy that changed only those still matched the same root: a node could
    /// hold, apply and serve a body its miner never signed. A note's owner
    /// was the public key itself, decoded straight off the chain, so every
    /// unspent note stood exposed to whatever could someday break that key,
    /// and a typo in a pasted address passed for somebody's key about one
    /// time in sixteen, since the only check was whether the bytes described
    /// a usable point at all. And two domains, the sampling draw and the
    /// empty leaf of the cold set, each hashed two kinds of value apart only
    /// because every caller so far had kept their lengths fixed and
    /// different, an argument that lived in the callers rather than in the
    /// hash.
    ///
    /// A place in the hot set now costs a price that is destroyed, asked of a
    /// miner the same as anyone; a header commits to every byte of its body,
    /// signatures and proofs included, so a copy naming another body is
    /// refused before it is held; a note is locked to the hash of a key,
    /// which appears only when the note is spent, written as an address a
    /// checksum protects; and the draw and the empty leaf hash under domains
    /// of their own. Each of these changes what a header commits to or what a
    /// note is, so every block mined under the old rules is invalid under
    /// these, and the network starts over.
    pub const TESTNET_7: Self = Self(0x4341_525A);
    /// The eighth, because a few minutes of hired hash rate could nearly stop
    /// the chain for 33 hours.
    ///
    /// The retarget was a moving average over the last ninety blocks, which
    /// rose fast and fell slowly. On 2 October 2026 a stranger mined eighty
    /// blocks in two minutes and left; the first honest block after them was
    /// asked 768 times the difficulty before them, and the honest miner,
    /// alone with it again, needed 33 hours to work it back down. Five
    /// minutes of a miner that size held the next hundred honest blocks up
    /// 71 hours, and an hour of it 298, so the cheapest way to stop the
    /// network was to rent hash rate for a few minutes and leave.
    ///
    /// The difficulty now follows a schedule fixed at the first block: what a
    /// block is asked depends on how far its parent stands ahead of or behind
    /// the time the schedule gives its height, twice as much for every hour
    /// ahead and half as much for every hour behind, and not on the path the
    /// chain took to get there. A burst that leaves holds the honest chain up
    /// for about as long as it ran ahead of the schedule, which grows with the
    /// logarithm of what it paid: 5.6 hours after the same five minutes, 11.3
    /// after the same hour. That changes the difficulty every block must
    /// carry, so every block mined under the old rule is invalid under this
    /// one, and the network starts over.
    pub const TESTNET_8: Self = Self(0x4341_525B);
    /// Kept as the name of whichever test network is current.
    pub const TESTNET: Self = Self::TESTNET_8;
    /// The original throwaway network, retired alongside testnet-6.
    ///
    /// Decided after the audit that named testnet-7: a devnet directory or
    /// peer left over from before the restart met a node that still called
    /// itself "devnet" and read the same marker, so nothing told the two
    /// apart, where every renumbered test network already says so plainly.
    /// Devnet is thrown away routinely, but this restart renumbers it too,
    /// so a node still on it is told which network that is rather than being
    /// read as the current one under its old name.
    pub const DEVNET_1: Self = Self(0x4341_5244);
    /// The second throwaway network, retired alongside testnet-7.
    ///
    /// Renumbered for the reason the first was: a devnet chain mined under the
    /// moving average is invalid under the schedule, and a directory or a peer
    /// left over from before the restart is told which network it is on
    /// rather than being read as the current one under its old name.
    pub const DEVNET_2: Self = Self(0x4341_5245);
    /// A throwaway network with the same rules but a much shorter block time,
    /// for running the software on one machine.
    ///
    /// Renumbered alongside testnet-8, as it was alongside testnet-7: a
    /// directory or a peer still on an old marker is told plainly which
    /// network it is on, the way every retired testnet already is, rather
    /// than being taken for this one.
    pub const DEVNET: Self = Self(0x4341_5246);

    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// The name this network is known by, when it has one.
    ///
    /// The retired ones are named too, and they are the reason this exists.
    /// Every constant above says a node left behind "is then told plainly that
    /// it is on another network, rather than failing somewhere confusing", and
    /// what it was told was a thirty two bit marker: `peer speaks network
    /// 0x43415258`. Five constants carried the translation and nothing read
    /// them, so the one table that could make the telling plain was the one
    /// piece of the promise nobody had wired up.
    ///
    /// `None` for a marker this build does not know, which is the honest
    /// answer and not a fallback: a number nobody named is a number this node
    /// has nothing to say about, and printing it raw is then right.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::MAINNET => Some("mainnet"),
            Self::TESTNET_1 => Some("testnet-1"),
            Self::TESTNET_2 => Some("testnet-2"),
            Self::TESTNET_3 => Some("testnet-3"),
            Self::TESTNET_4 => Some("testnet-4"),
            Self::TESTNET_5 => Some("testnet-5"),
            Self::TESTNET_6 => Some("testnet-6"),
            Self::TESTNET_7 => Some("testnet-7"),
            Self::TESTNET_8 => Some("testnet-8"),
            Self::DEVNET_1 => Some("devnet-1"),
            Self::DEVNET_2 => Some("devnet-2"),
            Self::DEVNET => Some("devnet"),
            _ => None,
        }
    }

    /// What an address on this network starts with, before its `1`.
    ///
    /// The kind of network rather than the network: every test network
    /// shares one, so an address stays the same across the restarts a test
    /// network goes through, and mainnet has one no test network can be
    /// mistaken for. A marker this build does not name is a test network
    /// here, since the one network whose money is real is named above.
    #[must_use]
    pub const fn address_prefix(self) -> &'static str {
        match self {
            Self::MAINNET => "cairn",
            Self::DEVNET | Self::DEVNET_1 | Self::DEVNET_2 => "dcairn",
            _ => "tcairn",
        }
    }
}

/// The name, or the marker when there is no name.
///
/// Three errors print a network at somebody: a frame from the wrong one, a
/// peer following another, and a block belonging elsewhere. All three printed
/// either `{:#010x}` or the derived `Debug`, so an operator on a retired build
/// read `0x43415258` or `NetworkId(1128416344)` and had nothing to look up.
impl core::fmt::Display for NetworkId {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => out.write_str(name),
            None => write!(out, "{:#010x}", self.0),
        }
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

/// The scheme byte of an Ed25519 key, hashed in front of it.
///
/// Inside the hash so that a key of another scheme with the same thirty two
/// bytes can never name the same owner: SLH-DSA-128s keys are thirty two bytes
/// too. A scheme to come arrives as a transfer version that names its own.
pub const ED25519: u8 = 0x00;

/// Who may spend a note: the hash of a key, never the key.
///
/// A note locked to a key shows that key to everybody for as long as it is
/// unspent, which is what a quantum computer would need and all of the supply
/// would offer it. Locked to the hash, the key appears on the chain once, in
/// the input that spends the note, and the owner is thirty two bytes whatever
/// guards it.
///
/// Reading one is copying thirty two bytes. A key is decoded, with the three
/// refusals `cairn_crypto::PublicKey::from_bytes` makes, only when an input
/// presents one whose hash is already known to match, which is at
/// verification, so no frame buys curve arithmetic by carrying notes.
///
/// No `Display`, on purpose. An address is written with its network's prefix
/// and a checksum, by [`Address::to_text`], and every face that prints one has
/// to say which network it is on to do it. A bare hexadecimal address cannot be
/// printed by accident, so none can be typed back in by someone who read one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; HASH_LEN]);

/// Why a string is not an address on this network.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("{0}")]
    Text(#[from] Bech32mError),
    #[error(
        "it is an address for another network: it starts {found}1, and addresses here \
         start {expected}1"
    )]
    OtherNetwork {
        found: String,
        expected: &'static str,
    },
    #[error("it carries {0} bytes, and an address carries 32")]
    WrongLength(usize),
}

impl Address {
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub const fn to_bytes(self) -> [u8; HASH_LEN] {
        self.0
    }

    /// The address of an Ed25519 key given as its thirty two bytes, decoded
    /// or not.
    ///
    /// What an input is checked against: the key it carries is hashed as it
    /// stands, before anything has asked whether it is a point, so a key that
    /// is not the owner's costs one hash to refuse and no curve arithmetic.
    #[must_use]
    pub fn of_ed25519(key: &[u8; PUBLIC_KEY_LEN]) -> Self {
        let mut hasher = Hasher::new(Domain::Address);
        hasher.update(&[ED25519]);
        hasher.update(key);
        Self(hasher.finalize().to_bytes())
    }

    /// The address written for `network`: its prefix, `1`, fifty two
    /// characters of Bech32m data and six of checksum.
    #[must_use]
    pub fn to_text(&self, network: NetworkId) -> String {
        bech32m::encode(network.address_prefix(), &self.0)
    }

    /// Reads an address written for `network`, and nothing else.
    ///
    /// Refused: anything Bech32m refuses, which is every typo of up to four
    /// characters; a prefix other than this network's; and any length but
    /// thirty two bytes. The same string in capitals throughout is read, which
    /// is how a QR code carries it. Surrounding space is not trimmed here:
    /// what a face does with what was pasted is the face's to say.
    pub fn from_text(text: &str, network: NetworkId) -> Result<Self, AddressError> {
        let (prefix, bytes) = bech32m::decode(text)?;
        let expected = network.address_prefix();
        if prefix != expected {
            return Err(AddressError::OtherNetwork {
                found: prefix,
                expected,
            });
        }
        let bytes: [u8; HASH_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| AddressError::WrongLength(bytes.len()))?;
        Ok(Self(bytes))
    }
}

impl From<PublicKey> for Address {
    fn from(key: PublicKey) -> Self {
        Self::of_ed25519(key.as_bytes())
    }
}

impl From<&PublicKey> for Address {
    fn from(key: &PublicKey) -> Self {
        Self::of_ed25519(key.as_bytes())
    }
}

impl From<&Address> for Address {
    fn from(address: &Address) -> Self {
        *address
    }
}

/// Hexadecimal, for a developer reading a derived `Debug`; a person is shown
/// [`Address::to_text`].
impl core::fmt::Debug for Address {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(out, "Address({})", Hash32::from_bytes(self.0))
    }
}

impl Encode for Address {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Address {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(reader.take_array::<HASH_LEN>()?))
    }
}

/// A unit of value locked to one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub value: Amount,
    pub owner: Address,
}

impl Note {
    /// A note paid to `owner`, an address or the key whose address it is.
    pub fn new(value: Amount, owner: impl Into<Address>) -> Self {
        Self {
            value,
            owner: owner.into(),
        }
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
            owner: Address::decode_from(reader)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{Address, Note};

    /// An owner in a note is thirty two bytes and nothing beside them, and a
    /// note is forty.
    ///
    /// What a node holds for every hot note rests on this: 68 MB at the
    /// ceiling the rules impose, as `examples/footprint.rs` reads it. It
    /// rested on a public key being thirty two bytes while a note held one,
    /// and the check stayed with the key when the owner became an address, so
    /// an address that carried anything more would have passed.
    #[test]
    fn an_owner_in_a_note_is_thirty_two_bytes_and_a_note_forty() {
        assert_eq!(std::mem::size_of::<Address>(), 32);
        assert_eq!(std::mem::size_of::<Note>(), 40);
    }
}

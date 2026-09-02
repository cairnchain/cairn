//! What nodes say to each other.
//!
//! Every list a peer can send is capped, and every cap is enforced while
//! decoding. A peer is not a trusted party: it is an anonymous stranger, and
//! the first thing a message format has to do is refuse to allocate whatever
//! that stranger asks for.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use cairn_accumulator::ForestProof;
use cairn_chain::{Located, MAX_LOCATOR};
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::NetworkId;
use cairn_ledger::transaction::Transfer;
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::Hash32;

/// Bumped when the meaning of a message changes. Peers on another version are
/// refused rather than misunderstood.
///
/// Six carries the two changes that made the archivist real. There is a
/// question a wallet can ask about where one of its fallen notes sits, and the
/// handshake now says separately whether a node kept the headers and whether
/// it kept the cold set. Those were one field before, computed from the
/// headers and named after the cold set, so every node claimed the service and
/// none of them offered it.
///
/// A node on five and a node on six turn each other away at the handshake,
/// which is the gentlest way this could have gone. The alternative was to add
/// the question without saying so: a node on five meeting it would not be able
/// to decode it, would take that for a peer that is broken or probing, and
/// would refuse the address for an hour. A wallet looking for an archivist
/// would then work its way through the network banning itself from it.
pub const PROTOCOL_VERSION: u32 = 6;

/// Identifiers one announcement may carry.
pub const MAX_ANNOUNCED: usize = 512;
/// Positions one chain answer may name.
pub const MAX_CHAIN: u64 = 2_000;
/// Blocks one request may ask for.
pub const MAX_REQUESTED: usize = 128;
/// Addresses one answer may carry.
pub const MAX_SHARED_ADDRESSES: usize = 64;

/// Headers one answer carries.
///
/// A node that joined a chain fills in the headers from before it arrived, so
/// it can take in a newcomer of its own. At 182 bytes each this is 93 kB an
/// answer, which is under what the wire carries and enough that filling in a
/// long chain is thousands of exchanges rather than millions.
pub const MAX_HEADERS: usize = 512;

/// Places one request may ask to have proved.
///
/// A wallet asking is recovering, which happens once and covers whatever it
/// has: sixty four notes is more than most wallets ever hold fallen at one
/// time, and a wallet holding more asks again. The number is small because the
/// answer is the expensive half, not the question: one path is about a
/// kilobyte on a mature chain, so a full answer is the size of a block, and
/// the asker must not be the one who decides how large that gets.
pub const MAX_PROVEN: usize = 64;

/// A peer's listening address, in a form the wire can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerAddress(pub SocketAddr);

impl Encode for PeerAddress {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self.0 {
            SocketAddr::V4(address) => {
                4u8.encode_to(out);
                address.ip().octets().encode_to(out);
                address.port().encode_to(out);
            }
            SocketAddr::V6(address) => {
                6u8.encode_to(out);
                address.ip().octets().encode_to(out);
                address.port().encode_to(out);
            }
        }
    }
}

impl Decode for PeerAddress {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode_from(reader)? {
            4 => {
                let octets = <[u8; 4]>::decode_from(reader)?;
                let port = u16::decode_from(reader)?;
                Ok(Self(SocketAddr::from((Ipv4Addr::from(octets), port))))
            }
            6 => {
                let octets = <[u8; 16]>::decode_from(reader)?;
                let port = u16::decode_from(reader)?;
                Ok(Self(SocketAddr::from((Ipv6Addr::from(octets), port))))
            }
            _ => Err(CodecError::InvalidValue {
                type_name: "PeerAddress",
            }),
        }
    }
}

/// What a node claims to have kept.
///
/// Two claims, two quite different bargains, and until now one bit. Keeping
/// the headers costs 182 bytes a block and is what lets anybody join a chain
/// at all, so almost every node does it. Keeping the cold set costs a set that
/// grows with every note ever spent, and is what lets a wallet that has lost
/// the path to one of its own fallen notes get another; almost no node does
/// it. One field answered both, filled in from the header log and named after
/// the cold set, so every node on the network offered the second service and
/// none of them performed it.
///
/// Claims and not facts, and neither is taken on trust. Everything either kind
/// of node hands over is checked against something the asker worked out for
/// itself. What the claims save is asking the wrong node and waiting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Keeps {
    /// The headers, so this node can show a newcomer what work stands behind
    /// the chain it follows.
    pub headers: bool,
    /// The whole cold set, so this node can rebuild the path to a note that
    /// fell long ago. This is the archivist.
    pub cold_set: bool,
}

impl Encode for Keeps {
    fn encode_to(&self, out: &mut Vec<u8>) {
        u8::from(self.headers).encode_to(out);
        u8::from(self.cold_set).encode_to(out);
    }
}

impl Decode for Keeps {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            headers: claimed(reader)?,
            cold_set: claimed(reader)?,
        })
    }
}

/// One claim about what a node kept.
///
/// Anything but zero or one is a peer saying something this version does not
/// understand, and reading it as true would be guessing on the peer's behalf.
fn claimed(reader: &mut Reader<'_>) -> Result<bool, CodecError> {
    match u8::decode_from(reader)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CodecError::InvalidValue { type_name: "Keeps" }),
    }
}

/// What a node tells a peer about itself when the connection opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub version: u32,
    pub network: NetworkId,
    /// The first block of the branch this node follows. Two nodes that
    /// disagree here are on unrelated chains and have nothing to exchange.
    pub genesis: Hash32,
    pub tip: Hash32,
    pub height: u64,
    /// Work behind the tip, which is what decides who is behind whom.
    pub total_work: u128,
    /// The port this node listens on. A peer already knows the address the
    /// connection came from, so this is what completes it into an address
    /// others can be pointed at.
    pub listen: u16,
    /// Drawn once when the node starts, and never reused.
    ///
    /// A node behind a router does not know the address the world reaches it
    /// at, so when a peer hands that address back it looks like a stranger's
    /// and gets dialled. Comparing addresses cannot fix this; comparing a
    /// number the node drew for itself can. Seeing your own means the
    /// connection is your own.
    pub nonce: u64,
    /// What this node kept, and therefore what it can be asked for.
    pub keeps: Keeps,
}

impl Encode for Handshake {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.version.encode_to(out);
        self.network.encode_to(out);
        self.genesis.encode_to(out);
        self.tip.encode_to(out);
        self.height.encode_to(out);
        self.total_work.encode_to(out);
        self.listen.encode_to(out);
        self.nonce.encode_to(out);
        self.keeps.encode_to(out);
    }
}

impl Decode for Handshake {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u32::decode_from(reader)?,
            network: NetworkId::decode_from(reader)?,
            genesis: Hash32::decode_from(reader)?,
            tip: Hash32::decode_from(reader)?,
            height: u64::decode_from(reader)?,
            total_work: u128::decode_from(reader)?,
            listen: u16::decode_from(reader)?,
            nonce: u64::decode_from(reader)?,
            keeps: Keeps::decode_from(reader)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Opens a connection.
    Hello(Handshake),
    /// Answers [`Message::Hello`].
    Welcome(Handshake),
    /// Liveness, and a rough measure of how slow a peer is.
    Ping(u64),
    Pong(u64),
    /// Where do our branches part? The locator runs from the sender's tip
    /// backwards, thinning out with depth.
    GetChain {
        locator: Vec<Located>,
    },
    /// How far the sender's branch runs past the last position in the locator
    /// it agreed with: a first height, and how many blocks follow it.
    ///
    /// Heights rather than identifiers. A node no longer holds an identifier
    /// for every height it has, and reading them off a disk to fill this would
    /// be a seek a block to answer a question the blocks themselves answer:
    /// each one carries what it is built on, so a run of them proves its own
    /// order as it arrives.
    Chain {
        from: u64,
        count: u64,
    },
    /// Send me the blocks at these heights, on the branch you follow.
    GetBlocks(Vec<u64>),
    /// One block. Boxed because it dwarfs every other variant, and an enum is
    /// as large as its largest one.
    Block(Box<Block>),
    /// I have these, ask if you want them.
    Announce(Vec<Located>),
    /// Who else do you know?
    GetPeers,
    /// Addresses worth trying.
    Peers(Vec<PeerAddress>),
    /// A transfer looking for a block. Boxed for the same reason a block is.
    Transaction(Box<Transfer>),
    /// Show me which chain you follow is the heaviest, or hand me the ledger
    /// at its tip.
    ///
    /// `part` is which piece of the answer is wanted. Both answers are larger
    /// than one message carries, so they arrive in pieces and the asker puts
    /// them back together; whether the pieces belong together is settled by
    /// checking the whole, not by trusting the labels on it.
    GetJoin {
        what: Joining,
        part: u32,
    },
    /// Send me the headers from this height, on the branch you follow.
    ///
    /// For a node that was handed a ledger and so has no headers from before
    /// it arrived. Without them it can follow the chain perfectly well and can
    /// take in nobody, which would make the ability to join a chain die out
    /// with the nodes that read one from the first block.
    GetHeaders {
        from: u64,
        count: u64,
    },
    /// Headers in order, starting at `from`.
    ///
    /// Nothing about them is taken on the sender's word. Each one names what
    /// it was built on, so the run proves its own order, and the forest they
    /// make has to produce the commitment the asker's own tip already carries.
    /// A sender that made any of them up is caught by that, not by being
    /// trusted less.
    Headers {
        from: u64,
        headers: Vec<BlockHeader>,
    },
    /// One piece of an answer to [`Message::GetJoin`].
    ///
    /// `at` is the tip the answer describes, so an asker can tell that every
    /// piece came from the same moment: a node that mined a block partway
    /// through is answering about a different ledger, and the pieces would not
    /// go together.
    JoinPart {
        what: Joining,
        at: Hash32,
        part: u32,
        parts: u32,
        bytes: Vec<u8>,
    },
    /// Where do these fallen notes sit? Send me the paths.
    ///
    /// The one thing a wallet cannot work out for itself. A note that has
    /// fallen out of the set every node holds can only be spent alongside a
    /// path showing where it sits, that path changes with every block that
    /// buries another note, and a wallet whose node stopped keeping it current
    /// has money it can see and cannot move.
    ///
    /// Places rather than notes, because a place is what both kinds of
    /// answerer can look up: an archivist rebuilds the path from the leaves it
    /// kept, and a node following the owner already holds it. Naming the note
    /// instead would have made the archivist the only possible answerer and
    /// would have told it whose money it was being asked about.
    GetProofs(Vec<u64>),
    /// One answer per place asked about, in the order they were asked about.
    ///
    /// Nothing here is taken on the sender's word, and nothing needs to be: a
    /// path either folds to the commitment the asker's own node already holds
    /// or it is worth nothing, and the asker checks. That is why this can be
    /// asked of a stranger at all.
    Proofs(Vec<Placed>),
}

/// What one node could say about one place in the cold set.
///
/// A node that cannot produce the path says so, with nothing where the path
/// would be, rather than leaving the place out of its answer or saying
/// nothing. Silence from a peer is indistinguishable from a peer that has hung
/// up, and a wallet waiting on the one thing that would let it spend its money
/// has to be able to tell those apart and go and ask somebody else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placed {
    pub position: u64,
    /// The path from that place up to the commitment, when this node has one.
    pub proof: Option<ForestProof>,
}

impl Encode for Placed {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.position.encode_to(out);
        match &self.proof {
            None => 0u8.encode_to(out),
            Some(proof) => {
                1u8.encode_to(out);
                proof.encode_to(out);
            }
        }
    }
}

impl Decode for Placed {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let position = u64::decode_from(reader)?;
        let proof = match u8::decode_from(reader)? {
            0 => None,
            1 => Some(ForestProof::decode_from(reader)?),
            _ => {
                return Err(CodecError::InvalidValue {
                    type_name: "Placed",
                })
            }
        };
        Ok(Self { position, proof })
    }
}

/// What a newcomer is asking to be shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Joining {
    /// The sampled headers that say what work stands behind a tip.
    Weight,
    /// The ledger at that tip.
    Ledger,
}

impl Joining {
    /// Which of the two answers this is, so a node can keep one of each.
    #[must_use]
    pub const fn slot(self) -> usize {
        match self {
            Self::Weight => 0,
            Self::Ledger => 1,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Weight => 0,
            Self::Ledger => 1,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Weight),
            1 => Some(Self::Ledger),
            _ => None,
        }
    }
}

impl Encode for Joining {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.tag().encode_to(out);
    }
}

impl Decode for Joining {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Self::from_tag(u8::decode_from(reader)?).ok_or(CodecError::InvalidValue {
            type_name: "Joining",
        })
    }
}

/// Bytes one piece of a join answer carries.
///
/// Comfortably under what the wire takes, so a piece and its labels together
/// always fit. Smaller pieces mean more round trips on an exchange that
/// happens once in a node's life; larger ones would not fit.
pub const JOIN_PART_BYTES: usize = 512 * 1024;

/// Pieces one answer may be cut into.
///
/// A ledger is eleven megabytes at the largest hot set the rules allow, and a
/// sampled weight is eight. This is several times either, and it is here so a
/// reader can refuse an answer that claims to be enormous before it starts
/// collecting one.
pub const MAX_JOIN_PARTS: u32 = 64;

impl Message {
    /// A short name for logs and errors.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::Welcome(_) => "welcome",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::GetChain { .. } => "get chain",
            Self::Chain { .. } => "chain",
            Self::GetBlocks(_) => "get blocks",
            Self::Block(_) => "block",
            Self::Announce(_) => "announce",
            Self::GetPeers => "get peers",
            Self::Peers(_) => "peers",
            Self::Transaction(_) => "transaction",
            Self::GetJoin { .. } => "get join",
            Self::JoinPart { .. } => "join part",
            Self::GetHeaders { .. } => "get headers",
            Self::Headers { .. } => "headers",
            Self::GetProofs(_) => "get proofs",
            Self::Proofs(_) => "proofs",
        }
    }

    const fn tag(&self) -> u8 {
        match self {
            Self::Hello(_) => 0,
            Self::Welcome(_) => 1,
            Self::Ping(_) => 2,
            Self::Pong(_) => 3,
            Self::GetChain { .. } => 4,
            Self::Chain { .. } => 5,
            Self::GetBlocks(_) => 6,
            Self::Block(_) => 7,
            Self::Announce(_) => 8,
            Self::GetPeers => 9,
            Self::Peers(_) => 10,
            Self::Transaction(_) => 11,
            Self::GetJoin { .. } => 12,
            Self::JoinPart { .. } => 13,
            Self::GetHeaders { .. } => 14,
            Self::Headers { .. } => 15,
            Self::GetProofs(_) => 16,
            Self::Proofs(_) => 17,
        }
    }
}

/// Decodes a list of identifiers, refusing one longer than `limit`.
/// A bounded list of heights.
fn decode_heights(reader: &mut Reader<'_>, limit: usize) -> Result<Vec<u64>, CodecError> {
    let heights = Vec::<u64>::decode_from(reader)?;
    if heights.len() > limit {
        return Err(CodecError::InvalidValue {
            type_name: "height list",
        });
    }
    Ok(heights)
}

fn decode_ids(reader: &mut Reader<'_>, limit: usize) -> Result<Vec<Located>, CodecError> {
    let ids = Vec::<Located>::decode_from(reader)?;
    if ids.len() > limit {
        return Err(CodecError::InvalidValue {
            type_name: "identifier list",
        });
    }
    Ok(ids)
}

impl Encode for Message {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.tag().encode_to(out);
        match self {
            Self::Hello(handshake) | Self::Welcome(handshake) => handshake.encode_to(out),
            Self::Ping(nonce) | Self::Pong(nonce) => nonce.encode_to(out),
            Self::GetChain { locator } => locator.encode_to(out),
            Self::Chain { from, count } | Self::GetHeaders { from, count } => {
                from.encode_to(out);
                count.encode_to(out);
            }
            Self::GetBlocks(heights) => heights.encode_to(out),
            Self::Announce(ids) => ids.encode_to(out),
            Self::Block(block) => block.encode_to(out),
            Self::GetPeers => {}
            Self::Peers(addresses) => addresses.encode_to(out),
            Self::Transaction(transfer) => transfer.encode_to(out),
            Self::GetJoin { what, part } => {
                what.encode_to(out);
                part.encode_to(out);
            }
            Self::JoinPart {
                what,
                at,
                part,
                parts,
                bytes,
            } => {
                what.encode_to(out);
                at.encode_to(out);
                part.encode_to(out);
                parts.encode_to(out);
                bytes.encode_to(out);
            }
            Self::Headers { from, headers } => {
                from.encode_to(out);
                headers.encode_to(out);
            }
            Self::GetProofs(positions) => positions.encode_to(out),
            Self::Proofs(placed) => placed.encode_to(out),
        }
    }
}

impl Decode for Message {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode_from(reader)? {
            0 => Ok(Self::Hello(Handshake::decode_from(reader)?)),
            1 => Ok(Self::Welcome(Handshake::decode_from(reader)?)),
            2 => Ok(Self::Ping(u64::decode_from(reader)?)),
            3 => Ok(Self::Pong(u64::decode_from(reader)?)),
            4 => Ok(Self::GetChain {
                locator: decode_ids(reader, MAX_LOCATOR)?,
            }),
            5 => {
                let from = u64::decode_from(reader)?;
                let count = u64::decode_from(reader)?;
                if count > MAX_CHAIN {
                    return Err(CodecError::InvalidValue {
                        type_name: "chain length",
                    });
                }
                Ok(Self::Chain { from, count })
            }
            6 => Ok(Self::GetBlocks(decode_heights(reader, MAX_REQUESTED)?)),
            7 => Ok(Self::Block(Box::new(Block::decode_from(reader)?))),
            8 => Ok(Self::Announce(decode_ids(reader, MAX_ANNOUNCED)?)),
            9 => Ok(Self::GetPeers),
            10 => {
                let addresses = Vec::<PeerAddress>::decode_from(reader)?;
                if addresses.len() > MAX_SHARED_ADDRESSES {
                    return Err(CodecError::InvalidValue {
                        type_name: "address list",
                    });
                }
                Ok(Self::Peers(addresses))
            }
            11 => Ok(Self::Transaction(Box::new(Transfer::decode_from(reader)?))),
            12 => Ok(Self::GetJoin {
                what: Joining::decode_from(reader)?,
                part: u32::decode_from(reader)?,
            }),
            13 => {
                let what = Joining::decode_from(reader)?;
                let at = Hash32::decode_from(reader)?;
                let part = u32::decode_from(reader)?;
                let parts = u32::decode_from(reader)?;
                // Checked before the bytes are read, since both are named by
                // whoever sent this and one of them decides an allocation.
                if parts > MAX_JOIN_PARTS || part >= parts {
                    return Err(CodecError::InvalidValue {
                        type_name: "JoinPart",
                    });
                }
                let bytes = Vec::<u8>::decode_from(reader)?;
                if bytes.len() > JOIN_PART_BYTES {
                    return Err(CodecError::InvalidValue {
                        type_name: "JoinPart",
                    });
                }
                Ok(Self::JoinPart {
                    what,
                    at,
                    part,
                    parts,
                    bytes,
                })
            }
            14 => Ok(Self::GetHeaders {
                from: u64::decode_from(reader)?,
                count: u64::decode_from(reader)?,
            }),
            15 => {
                let from = u64::decode_from(reader)?;
                let headers = Vec::<BlockHeader>::decode_from(reader)?;
                if headers.len() > MAX_HEADERS {
                    return Err(CodecError::InvalidValue {
                        type_name: "Headers",
                    });
                }
                Ok(Self::Headers { from, headers })
            }
            16 => Ok(Self::GetProofs(decode_heights(reader, MAX_PROVEN)?)),
            17 => {
                let placed = Vec::<Placed>::decode_from(reader)?;
                if placed.len() > MAX_PROVEN {
                    return Err(CodecError::InvalidValue {
                        type_name: "Proofs",
                    });
                }
                Ok(Self::Proofs(placed))
            }
            _ => Err(CodecError::InvalidValue {
                type_name: "Message",
            }),
        }
    }
}

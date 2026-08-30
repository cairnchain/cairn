//! What nodes say to each other.
//!
//! Every list a peer can send is capped, and every cap is enforced while
//! decoding. A peer is not a trusted party: it is an anonymous stranger, and
//! the first thing a message format has to do is refuse to allocate whatever
//! that stranger asks for.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use cairn_chain::{Located, MAX_LOCATOR};
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::NetworkId;
use cairn_ledger::transaction::Transfer;
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::Hash32;

/// Bumped when the meaning of a message changes. Peers on another version are
/// refused rather than misunderstood.
pub const PROTOCOL_VERSION: u32 = 5;

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
    /// Whether this node kept the history, and can therefore prove things
    /// about it.
    ///
    /// Only a node that kept the headers can show a newcomer what work stands
    /// behind a chain, and only one that kept the cold set can rebuild a proof
    /// for a wallet that lost one. Both are the same service and the same
    /// bargain, so they are one answer.
    ///
    /// A claim, not a fact, and it costs nothing to make. Nothing is taken on
    /// the strength of it: everything an archivist hands over is checked
    /// against what a header commits to. What it saves is asking the wrong
    /// node and waiting.
    pub archives: bool,
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
        u8::from(self.archives).encode_to(out);
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
            // Anything but zero or one is a node saying something this version
            // does not understand, and taking it for true would be guessing.
            archives: match u8::decode_from(reader)? {
                0 => false,
                1 => true,
                _ => {
                    return Err(CodecError::InvalidValue {
                        type_name: "Handshake",
                    })
                }
            },
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
            _ => Err(CodecError::InvalidValue {
                type_name: "Message",
            }),
        }
    }
}

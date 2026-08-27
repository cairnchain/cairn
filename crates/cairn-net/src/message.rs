//! What nodes say to each other.
//!
//! Every list a peer can send is capped, and every cap is enforced while
//! decoding. A peer is not a trusted party: it is an anonymous stranger, and
//! the first thing a message format has to do is refuse to allocate whatever
//! that stranger asks for.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use cairn_ledger::block::Block;
use cairn_ledger::note::NetworkId;
use cairn_ledger::transaction::Transfer;
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::Hash32;

/// Bumped when the meaning of a message changes. Peers on another version are
/// refused rather than misunderstood.
pub const PROTOCOL_VERSION: u32 = 2;

/// Identifiers one announcement may carry.
pub const MAX_ANNOUNCED: usize = 512;
/// Entries a locator may carry. A locator thins out with depth, so this covers
/// a chain far longer than any that will exist.
pub const MAX_LOCATOR: usize = 64;
/// Identifiers one chain answer may carry.
pub const MAX_CHAIN: usize = 2_000;
/// Blocks one request may ask for.
pub const MAX_REQUESTED: usize = 128;
/// Addresses one answer may carry.
pub const MAX_SHARED_ADDRESSES: usize = 64;

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
        locator: Vec<Hash32>,
    },
    /// The identifiers that follow, oldest first.
    Chain(Vec<Hash32>),
    /// Send me these blocks.
    GetBlocks(Vec<Hash32>),
    /// One block. Boxed because it dwarfs every other variant, and an enum is
    /// as large as its largest one.
    Block(Box<Block>),
    /// I have these, ask if you want them.
    Announce(Vec<Hash32>),
    /// Who else do you know?
    GetPeers,
    /// Addresses worth trying.
    Peers(Vec<PeerAddress>),
    /// A transfer looking for a block. Boxed for the same reason a block is.
    Transaction(Box<Transfer>),
}

impl Message {
    /// A short name for logs and errors.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::Welcome(_) => "welcome",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::GetChain { .. } => "get chain",
            Self::Chain(_) => "chain",
            Self::GetBlocks(_) => "get blocks",
            Self::Block(_) => "block",
            Self::Announce(_) => "announce",
            Self::GetPeers => "get peers",
            Self::Peers(_) => "peers",
            Self::Transaction(_) => "transaction",
        }
    }

    const fn tag(&self) -> u8 {
        match self {
            Self::Hello(_) => 0,
            Self::Welcome(_) => 1,
            Self::Ping(_) => 2,
            Self::Pong(_) => 3,
            Self::GetChain { .. } => 4,
            Self::Chain(_) => 5,
            Self::GetBlocks(_) => 6,
            Self::Block(_) => 7,
            Self::Announce(_) => 8,
            Self::GetPeers => 9,
            Self::Peers(_) => 10,
            Self::Transaction(_) => 11,
        }
    }
}

/// Decodes a list of identifiers, refusing one longer than `limit`.
fn decode_ids(reader: &mut Reader<'_>, limit: usize) -> Result<Vec<Hash32>, CodecError> {
    let ids = Vec::<Hash32>::decode_from(reader)?;
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
            Self::Chain(ids) | Self::GetBlocks(ids) | Self::Announce(ids) => ids.encode_to(out),
            Self::Block(block) => block.encode_to(out),
            Self::GetPeers => {}
            Self::Peers(addresses) => addresses.encode_to(out),
            Self::Transaction(transfer) => transfer.encode_to(out),
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
            5 => Ok(Self::Chain(decode_ids(reader, MAX_CHAIN)?)),
            6 => Ok(Self::GetBlocks(decode_ids(reader, MAX_REQUESTED)?)),
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
            _ => Err(CodecError::InvalidValue {
                type_name: "Message",
            }),
        }
    }
}

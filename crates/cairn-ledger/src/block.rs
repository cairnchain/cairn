//! Block headers and blocks.

use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::Domain;
use cairn_primitives::merkle::{merkle_leaf, merkle_root};
use cairn_primitives::Hash32;

use crate::note::NetworkId;
use crate::transaction::{CoinbaseTransaction, Transfer};

pub const BLOCK_VERSION: u16 = 1;

/// Everything a node needs to follow the chain without the block body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u16,
    pub network: NetworkId,
    pub height: u64,
    pub previous: Hash32,
    /// Merkle root over the coinbase identifier followed by every transfer
    /// identifier, in the order they appear in the block.
    pub transactions_root: Hash32,
    /// Commitment to the whole note set as it stands after this block.
    ///
    /// It is recomputed from scratch today, which is the one part of this
    /// design that does not scale and precisely what the accumulator replaces.
    /// The field is already at its final position and size, so making that
    /// change will not alter the header format.
    pub state_root: Hash32,
    /// Seconds since the Unix epoch.
    pub timestamp: u64,
    pub nonce: u64,
}

impl BlockHeader {
    pub fn id(&self) -> Hash32 {
        cairn_primitives::hash::hash(Domain::BlockHeaderId, &self.encode())
    }
}

impl Encode for BlockHeader {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.version.encode_to(out);
        self.network.encode_to(out);
        self.height.encode_to(out);
        self.previous.encode_to(out);
        self.transactions_root.encode_to(out);
        self.state_root.encode_to(out);
        self.timestamp.encode_to(out);
        self.nonce.encode_to(out);
    }
}

impl Decode for BlockHeader {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u16::decode_from(reader)?,
            network: NetworkId::decode_from(reader)?,
            height: u64::decode_from(reader)?,
            previous: Hash32::decode_from(reader)?,
            transactions_root: Hash32::decode_from(reader)?,
            state_root: Hash32::decode_from(reader)?,
            timestamp: u64::decode_from(reader)?,
            nonce: u64::decode_from(reader)?,
        })
    }
}

/// A header and the transactions it commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub coinbase: CoinbaseTransaction,
    pub transfers: Vec<Transfer>,
}

impl Block {
    pub fn id(&self) -> Hash32 {
        self.header.id()
    }

    /// Recomputes the root the header claims in `transactions_root`.
    pub fn transactions_root(&self) -> Hash32 {
        let mut leaves = Vec::with_capacity(self.transfers.len().saturating_add(1));
        leaves.push(merkle_leaf(self.coinbase.id().as_bytes()));
        leaves.extend(
            self.transfers
                .iter()
                .map(|t| merkle_leaf(t.id().as_bytes())),
        );
        merkle_root(&leaves)
    }
}

impl Encode for Block {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.header.encode_to(out);
        self.coinbase.encode_to(out);
        self.transfers.encode_to(out);
    }
}

impl Decode for Block {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            header: BlockHeader::decode_from(reader)?,
            coinbase: CoinbaseTransaction::decode_from(reader)?,
            transfers: Vec::decode_from(reader)?,
        })
    }
}

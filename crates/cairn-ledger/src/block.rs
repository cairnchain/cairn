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
    pub state_root: Hash32,
    /// Commitment to every header before this one.
    ///
    /// The root of an append-only forest holding the identifier of each
    /// earlier header, which a node carries as sixty four hashes exactly like
    /// the cold set. It costs one hash to check and one append to maintain.
    ///
    /// What it buys is the only way to join this chain without downloading all
    /// of it. Someone starting from nothing can be handed a handful of old
    /// headers, check that each is really where it claims to be in this
    /// commitment, and work out what stands behind the tip without seeing the
    /// millions of headers in between. Without this field that takes every
    /// header there has ever been, and it cannot be added later: changing a
    /// header's shape invalidates every block already mined.
    pub history: Hash32,
    /// Seconds since the Unix epoch.
    pub timestamp: u64,
    /// Work the block claims to carry. Validated against the value the chain
    /// history demands, so a miner cannot pick an easier one.
    pub difficulty: u64,
    /// Work behind this block and every block before it.
    ///
    /// Checked against the parent's, so a block cannot claim work it did not
    /// do. Sampling headers proves nothing unless the work each one stands for
    /// is known, and reading it here is what lets a verifier weight its sample
    /// by work rather than by how many blocks it was shown.
    pub total_work: u128,
    pub nonce: u64,
}

impl BlockHeader {
    /// The identifier, which is also what proof of work is measured against.
    pub fn id(&self) -> Hash32 {
        cairn_primitives::hash::hash(Domain::BlockHeaderId, &self.encode())
    }

    pub fn summary(&self) -> HeaderSummary {
        HeaderSummary {
            height: self.height,
            timestamp: self.timestamp,
            difficulty: self.difficulty,
        }
    }
}

/// The part of a header the retarget and the timestamp rules need.
///
/// Nodes keep a short window of these rather than whole headers, so the memory
/// a node spends on chain history is bounded like everything else here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderSummary {
    pub height: u64,
    pub timestamp: u64,
    pub difficulty: u64,
}

impl Encode for BlockHeader {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.version.encode_to(out);
        self.network.encode_to(out);
        self.height.encode_to(out);
        self.previous.encode_to(out);
        self.transactions_root.encode_to(out);
        self.state_root.encode_to(out);
        self.history.encode_to(out);
        self.timestamp.encode_to(out);
        self.difficulty.encode_to(out);
        self.total_work.encode_to(out);
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
            history: Hash32::decode_from(reader)?,
            timestamp: u64::decode_from(reader)?,
            difficulty: u64::decode_from(reader)?,
            total_work: u128::decode_from(reader)?,
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

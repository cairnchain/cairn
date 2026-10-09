//! Bodies of blocks a node holds off the branch it follows, on disk once its
//! memory has no more room for them.
//!
//! A switch onto a heavier branch is tried only once every block of that
//! branch is held, so what a node may hold beside its branch is the deepest
//! switch it can make. Held in memory alone that was thirty two megabytes, two
//! hundred and fifty six full blocks, where the rules promise a thousand and
//! twenty four. The chain keeps that much in memory still and puts the rest
//! here, by identifier, one file each.
//!
//! A cache and not a record, which is what sets it apart from every other file
//! in this crate. Nothing here is synced, because nothing here has to survive:
//! it is emptied when it is opened, since an entry for it lives only in the
//! memory of the process that wrote it, and a body the chain asks for and does
//! not get back is a body it no longer holds, as after a switch that failed.
//! What is read back is checked by the chain against the identifier and the
//! root the header names before anything uses it, so a file cut short by a
//! machine that stopped, or changed on the disk since, is a body that is not
//! here rather than one that is believed. And it is a directory of its own,
//! so nothing written here can land in the block log, the header log or the
//! ledger.

use std::io::Read;
use std::path::{Path, PathBuf};

use cairn_ledger::block::Block;
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Hash32;

use crate::{StoreError, MAX_RECORD_BYTES};

/// The name the directory takes inside a node's directory.
pub const SIDE_BODIES: &str = "side";

/// What a body is written under inside it: the block's identifier, in hex.
const SUFFIX: &str = "blk";

/// Bodies held off the followed branch, one file per block, named by the
/// block's identifier.
///
/// A file each rather than one file appended to, because what this holds is
/// let go of in any order, block by block, as the sweep beside the branch
/// decides, and a file that is removed gives its space back at once. There are
/// at most as many as the chain holds entries beside its branch, which it
/// bounds.
#[derive(Debug)]
pub struct SideBodyFiles {
    directory: PathBuf,
}

impl SideBodyFiles {
    /// Opens the directory for these inside `directory`, creating it if it is
    /// not there, and empties it.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, StoreError> {
        let directory = directory.as_ref().join(SIDE_BODIES);
        std::fs::create_dir_all(&directory)?;
        let files = Self { directory };
        files.clear();
        Ok(files)
    }

    /// Where these live.
    pub fn path(&self) -> &Path {
        &self.directory
    }

    fn file(&self, id: &Hash32) -> PathBuf {
        self.directory.join(format!("{id}.{SUFFIX}"))
    }

    /// Writes `block` down under `id`.
    ///
    /// A write the disk refuses leaves nothing behind, so a full disk is not
    /// made fuller by the attempt, and the chain keeps the body where it was.
    pub fn put(&self, id: &Hash32, block: &Block) -> Result<(), StoreError> {
        let file = self.file(id);
        let written = std::fs::write(&file, block.encode());
        if written.is_err() {
            let _ = std::fs::remove_file(&file);
        }
        Ok(written?)
    }

    /// The body written down under `id`, if there is one that reads as a
    /// block.
    ///
    /// Nothing more than that is asked here: whether it is the block `id`
    /// names is the chain's question, and it asks it.
    pub fn get(&self, id: &Hash32) -> Option<Block> {
        let file = std::fs::File::open(self.file(id)).ok()?;
        // A length on the disk is not necessarily a length this process
        // wrote, so nothing is read past what a record may hold. A longer
        // file is cut there and does not decode, unless what comes before the
        // cut is a whole block, which the chain then checks like any other.
        let limit = u64::try_from(MAX_RECORD_BYTES).unwrap_or(u64::MAX);
        let mut bytes = Vec::new();
        file.take(limit).read_to_end(&mut bytes).ok()?;
        Block::decode(&bytes).ok()
    }

    /// Lets go of whatever is written down under `id`.
    pub fn remove(&self, id: &Hash32) {
        let _ = std::fs::remove_file(self.file(id));
    }

    /// Lets go of everything written down here, and of anything else a
    /// machine that stopped left in the directory.
    pub fn clear(&self) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return;
        };
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }

    /// How many bodies are written down here.
    pub fn len(&self) -> usize {
        std::fs::read_dir(&self.directory)
            .map(|entries| entries.flatten().count())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use cairn_ledger::block::{BlockHeader, BLOCK_VERSION};
    use cairn_ledger::note::NetworkId;
    use cairn_ledger::transaction::CoinbaseTransaction;

    fn block(nonce: u64) -> Block {
        Block {
            header: BlockHeader {
                version: BLOCK_VERSION,
                network: NetworkId::TESTNET,
                height: 3,
                previous: Hash32::ZERO,
                transactions_root: Hash32::ZERO,
                state_root: Hash32::ZERO,
                history: Hash32::ZERO,
                timestamp: 0,
                difficulty: 1,
                total_work: 4,
                nonce,
            },
            coinbase: CoinbaseTransaction::new(3, Vec::new()),
            transfers: Vec::new(),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("cairn-side-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }

    /// What is written down comes back, by identifier, and goes when it is
    /// let go of.
    #[test]
    fn a_body_written_down_is_read_back_by_its_identifier_until_it_is_let_go_of() {
        let directory = scratch("round-trip");
        let files = SideBodyFiles::open(&directory).unwrap();
        let (one, two) = (block(1), block(2));
        files.put(&one.id(), &one).unwrap();
        files.put(&two.id(), &two).unwrap();
        assert_eq!(files.get(&one.id()), Some(one.clone()));
        assert_eq!(files.get(&two.id()), Some(two.clone()));
        assert_eq!(files.len(), 2);
        assert!(
            !files.is_empty(),
            "two bodies are written down and it says none are"
        );

        files.remove(&one.id());
        assert_eq!(files.get(&one.id()), None, "a body let go of is gone");
        assert_eq!(files.get(&two.id()), Some(two));
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Opening empties it: a body written before is nobody's now, because
    /// what said whose it was lived in the memory of the process that wrote
    /// it.
    #[test]
    fn opening_lets_go_of_whatever_was_written_before() {
        let directory = scratch("reopened");
        let files = SideBodyFiles::open(&directory).unwrap();
        let one = block(1);
        files.put(&one.id(), &one).unwrap();
        std::fs::write(files.path().join("left.part"), b"half a body").unwrap();
        drop(files);

        let again = SideBodyFiles::open(&directory).unwrap();
        assert!(
            again.is_empty(),
            "a restart starts with nothing beside the branch"
        );
        assert_eq!(again.get(&one.id()), None);
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A file that is not a block, or is cut short, reads as no body.
    #[test]
    fn a_file_that_does_not_read_as_a_block_is_no_body() {
        let directory = scratch("cut-short");
        let files = SideBodyFiles::open(&directory).unwrap();
        let one = block(1);
        files.put(&one.id(), &one).unwrap();
        let bytes = one.encode();
        std::fs::write(files.file(&one.id()), &bytes[..bytes.len() / 2]).unwrap();
        assert_eq!(files.get(&one.id()), None);
        let _ = std::fs::remove_dir_all(&directory);
    }
}

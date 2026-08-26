//! Keeping a chain across restarts.
//!
//! Blocks are appended to one file in the order they were accepted, and that
//! order is always replayable: a node only ever accepts a block whose parent it
//! already holds, so a parent can never appear after its child.
//!
//! There is no checksum on a record. Every block is verified cryptographically
//! when it is replayed, which catches anything a checksum would and a great
//! deal more.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cairn_ledger::block::Block;
use cairn_primitives::codec::{CodecError, Decode, Encode};

/// The name the block log takes inside a node's directory.
pub const BLOCK_LOG: &str = "blocks.log";

/// Largest record the log will read or write.
///
/// A length read from disk is not necessarily a length this process wrote, so
/// it is checked before anything is reserved for it.
pub const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("could not reach the block log: {0}")]
    Io(#[from] std::io::Error),
    #[error("record {index} declares {declared} bytes, the limit is {MAX_RECORD_BYTES}")]
    RecordTooLarge { index: usize, declared: usize },
    #[error("block would not fit in one record")]
    BlockTooLarge,
    #[error("record {index} is not a block: {source}")]
    Malformed {
        index: usize,
        #[source]
        source: CodecError,
    },
}

/// What opening a log found on disk.
#[derive(Debug, Default)]
pub struct Recovered {
    pub blocks: Vec<Block>,
    /// Bytes dropped from the end because they were incomplete or unreadable.
    ///
    /// A torn record at the end is the ordinary trace of a crash during a
    /// write, and dropping it costs one block that will simply be fetched
    /// again.
    pub discarded_bytes: u64,
}

/// An append only record of every block a node has accepted.
#[derive(Debug)]
pub struct BlockLog {
    file: File,
    path: PathBuf,
    /// Byte offset just past each record, so the file can be cut back to any
    /// record boundary.
    ends: Vec<u64>,
}

impl BlockLog {
    /// Opens the log inside `directory`, creating it if needed, and reads back
    /// everything it holds.
    pub fn open(directory: impl AsRef<Path>) -> Result<(Self, Recovered), StoreError> {
        let directory = directory.as_ref();
        std::fs::create_dir_all(directory)?;
        let path = directory.join(BLOCK_LOG);

        // Never truncating is the whole point: the file already there is the
        // chain this node spent time collecting and verifying.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let mut log = Self {
            file,
            path,
            ends: Vec::new(),
        };
        let recovered = log.scan()?;
        Ok((log, recovered))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    /// Adds one block to the end of the log.
    pub fn append(&mut self, block: &Block) -> Result<(), StoreError> {
        let body = block.encode();
        if body.len() > MAX_RECORD_BYTES {
            return Err(StoreError::BlockTooLarge);
        }
        let length = u32::try_from(body.len()).unwrap_or(u32::MAX);

        let mut record = Vec::with_capacity(body.len().saturating_add(4));
        length.encode_to(&mut record);
        record.extend_from_slice(&body);

        let start = self.ends.last().copied().unwrap_or(0);
        self.file.seek(SeekFrom::Start(start))?;
        self.file.write_all(&record)?;
        self.file.flush()?;
        self.ends.push(start.saturating_add(record.len() as u64));
        Ok(())
    }

    /// Cuts the log back to its first `count` records.
    pub fn keep_first(&mut self, count: usize) -> Result<(), StoreError> {
        if count >= self.ends.len() {
            return Ok(());
        }
        let end = if count == 0 {
            0
        } else {
            self.ends.get(count.saturating_sub(1)).copied().unwrap_or(0)
        };
        self.file.set_len(end)?;
        self.file.flush()?;
        self.ends.truncate(count);
        Ok(())
    }

    /// Reads every complete record, cutting the file back at the first one that
    /// cannot be read.
    fn scan(&mut self) -> Result<Recovered, StoreError> {
        self.file.seek(SeekFrom::Start(0))?;
        let total = self.file.metadata()?.len();
        let mut reader = BufReader::new(&self.file);

        let mut recovered = Recovered::default();
        let mut offset = 0u64;
        let mut ends = Vec::new();

        loop {
            let mut header = [0u8; 4];
            match reader.read_exact(&mut header) {
                Ok(()) => {}
                Err(_) => break,
            }
            let declared = usize::try_from(u32::from_le_bytes(header)).unwrap_or(usize::MAX);
            if declared > MAX_RECORD_BYTES {
                return Err(StoreError::RecordTooLarge {
                    index: ends.len(),
                    declared,
                });
            }

            let mut body = vec![0u8; declared];
            if reader.read_exact(&mut body).is_err() {
                // The tail was cut short, which is what a crash mid write
                // leaves behind.
                break;
            }
            let block = Block::decode(&body).map_err(|source| StoreError::Malformed {
                index: ends.len(),
                source,
            })?;

            offset = offset.saturating_add(4).saturating_add(declared as u64);
            ends.push(offset);
            recovered.blocks.push(block);
        }

        drop(reader);
        recovered.discarded_bytes = total.saturating_sub(offset);
        self.ends = ends;
        if recovered.discarded_bytes > 0 {
            self.file.set_len(offset)?;
            self.file.flush()?;
        }
        Ok(recovered)
    }
}

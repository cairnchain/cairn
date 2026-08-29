//! Every header a node has accepted, kept apart from the blocks.
//!
//! A node stops keeping blocks it has already applied, because the ledger they
//! add up to is a fixed size and the blocks are not. Headers are different:
//! they are what a newcomer is shown to settle which chain carries the most
//! work, and showing one means having it. At 182 bytes a header that is
//! 129 MB a year, against 50 GB a year for the same promise in Bitcoin, so
//! every node can carry it rather than the few that volunteer to.
//!
//! Records are a fixed size, which is what a header encoding to a fixed size
//! buys: the record for a height is a seek, with no index to keep beside it.
//! `a_header_is_a_fixed_size_record` holds that property in place.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cairn_ledger::block::BlockHeader;
use cairn_primitives::codec::{Decode, Encode};

use crate::StoreError;

/// The name the header log takes inside a node's directory.
pub const HEADER_LOG: &str = "headers.log";

/// Bytes one header takes on disk, which is what it takes on the wire.
pub const HEADER_BYTES: usize = 182;

/// Every header this node has accepted, oldest first.
#[derive(Debug)]
pub struct HeaderLog {
    file: File,
    path: PathBuf,
    /// Records held.
    count: u64,
    /// Height of the first record.
    ///
    /// Zero for a node that read its chain. A node handed a ledger starts
    /// wherever it was handed, exactly as its block log does.
    first: u64,
}

impl HeaderLog {
    /// Opens the log inside `directory`, creating it if needed.
    ///
    /// A trailing part of a record is a write that never finished, and is cut
    /// back. Nothing is decoded: a header that cannot be read is found when it
    /// is read, and the file is the same length either way.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, StoreError> {
        let directory = directory.as_ref();
        std::fs::create_dir_all(directory)?;
        let path = directory.join(HEADER_LOG);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        let mut log = Self {
            file,
            path,
            count: 0,
            first: 0,
        };
        let held = log.file.metadata()?.len();
        let record = HEADER_BYTES as u64;
        let whole = held.saturating_sub(held.checked_rem(record).unwrap_or(0));
        if whole != held {
            log.file.set_len(whole)?;
            log.file.flush()?;
        }
        log.count = whole.checked_div(record).unwrap_or(0);
        log.first = log.read(0)?.map_or(0, |header| header.height);
        Ok(log)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Height of the first header held, or zero when none is.
    pub fn first_height(&self) -> u64 {
        self.first
    }

    /// The height just past the last header held.
    pub fn reaches(&self) -> u64 {
        self.first.saturating_add(self.count)
    }

    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether this log holds the header at `height`.
    pub fn holds(&self, height: u64) -> bool {
        self.count > 0 && height >= self.first && height < self.reaches()
    }

    /// Adds one header to the end.
    ///
    /// A header that does not follow on from the last is refused. Positions
    /// here are heights, and a log where the two drifted apart would answer
    /// about the wrong header without any way to notice.
    pub fn append(&mut self, header: &BlockHeader) -> Result<(), StoreError> {
        if self.count == 0 {
            self.first = header.height;
        } else if header.height != self.reaches() {
            return Err(StoreError::OutOfOrder {
                expected: self.reaches(),
                found: header.height,
            });
        }
        let body = header.encode();
        if body.len() != HEADER_BYTES {
            return Err(StoreError::BlockTooLarge);
        }
        let at = self.count.saturating_mul(HEADER_BYTES as u64);
        self.file.seek(SeekFrom::Start(at))?;
        self.file.write_all(&body)?;
        self.file.flush()?;
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// The header at `height`.
    pub fn read_at(&self, height: u64) -> Result<Option<BlockHeader>, StoreError> {
        if !self.holds(height) {
            return Ok(None);
        }
        self.read(height.saturating_sub(self.first))
    }

    /// Cuts the log back so it holds nothing at `height` or past it.
    ///
    /// For a reorganisation, which takes headers off the branch this node was
    /// following. They are written again as the new branch is applied.
    pub fn keep_below(&mut self, height: u64) -> Result<(), StoreError> {
        if height >= self.reaches() {
            return Ok(());
        }
        let keep = height.saturating_sub(self.first).min(self.count);
        self.file
            .set_len(keep.saturating_mul(HEADER_BYTES as u64))?;
        self.file.flush()?;
        self.count = keep;
        if keep == 0 {
            self.first = 0;
        }
        Ok(())
    }

    /// The record at `index`, counted from the front of the file.
    fn read(&self, index: u64) -> Result<Option<BlockHeader>, StoreError> {
        if index >= self.count {
            return Ok(None);
        }
        let at = index.saturating_mul(HEADER_BYTES as u64);
        let mut file = &self.file;
        file.seek(SeekFrom::Start(at))?;
        let mut bytes = [0u8; HEADER_BYTES];
        file.read_exact(&mut bytes)?;
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        BlockHeader::decode(&bytes)
            .map(Some)
            .map_err(|source| StoreError::Malformed { index, source })
    }
}

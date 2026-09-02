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
//!
//! A fixed size is also what leaves nothing structural to catch a byte that
//! changed. Every field is a fixed-width primitive with no validation, so any
//! 182 bytes decode into a header and there is no such thing here as a header
//! that cannot be read. This is the one file a node serves without anything
//! having checked it: blocks are verified cryptographically as they are
//! replayed, and headers are what a newcomer is handed instead of blocks.
//!
//! So a record is checked against the record beside it. A header carries its
//! parent's identifier, which makes the log a hash chain that is already in
//! the bytes: a byte changed anywhere in a record changes the identifier the
//! record after it was written against. That is what a checksum would have
//! bought, without the bytes on disk, without a change to a format already
//! running, and stronger, because it says which chain the record belongs to
//! and not merely that it has not rotted.

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
    /// back. Two records are decoded, and no more however long the log is: see
    /// [`HeaderLog::head`] for why those two and not the rest.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_named(directory, HEADER_LOG)
    }

    /// The same, under another name.
    ///
    /// For the second log a node keeps while it fills in the headers from
    /// before it arrived: those are not its headers until they have been
    /// checked, and writing them into the real one before that would be
    /// believing a stranger.
    pub fn open_named(directory: impl AsRef<Path>, name: &str) -> Result<Self, StoreError> {
        let directory = directory.as_ref();
        std::fs::create_dir_all(directory)?;
        let path = directory.join(name);
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
            // Waited for, because a cut that has not reached the disk is a
            // file that comes back holding the part of a record this decided
            // was not one.
            log.file.sync_data()?;
        }
        log.count = whole.checked_div(record).unwrap_or(0);
        match log.head()? {
            Some(first) => log.first = first,
            None => log.count = 0,
        }
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
            // A log that holds no records and is not empty is one whose head
            // could not account for itself: `open` left the bytes alone rather
            // than delete a header log over one bad record. This is the moment
            // nothing could reach them again, so this is where they go, and
            // leaving them would have the next start count them as records
            // this log holds.
            self.file.set_len(0)?;
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

    /// Empties it, leaving a log that starts wherever the next header does.
    pub fn clear(&mut self) -> Result<(), StoreError> {
        self.file.set_len(0)?;
        // A cut is waited for and an append is not, and the difference is
        // which way losing it goes. A header that never landed is written
        // again from the blocks or asked for; headers this decided to drop
        // coming back are headers off a branch this node has left.
        self.file.sync_data()?;
        self.count = 0;
        self.first = 0;
        Ok(())
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
        self.file.sync_data()?;
        self.count = keep;
        if keep == 0 {
            self.first = 0;
        }
        Ok(())
    }

    /// The height this log starts at, if its head can account for itself.
    ///
    /// Every position here is a height worked out from this one number, so the
    /// first record decides where the whole log claims to be. Eight bytes
    /// changed in it used to move all of it: a node would say it began at
    /// height nine million and deny holding the header at zero it was holding,
    /// and nothing anywhere would object.
    ///
    /// So the record after it has to name it. Two records read at open, which
    /// costs the same on a log of three headers and one of ten million, and no
    /// other record needs it: the rest are checked as they are read, against
    /// the position they sit at and against their neighbour.
    ///
    /// A head the second record contradicts is not a head this log can build
    /// on, and there is nothing here that can say which of the two is the
    /// wrong one. It reports holding nothing rather than a geography it made
    /// up, and leaves the file exactly as it found it, so a node comes back up
    /// and fills in what its blocks can still show rather than serving a
    /// header it cannot vouch for.
    fn head(&self) -> Result<Option<u64>, StoreError> {
        let Some(head) = self.record(0)? else {
            return Ok(Some(0));
        };
        let head = Self::at(&head, 0)?;
        let Some(next) = self.record(1)? else {
            return Ok(Some(head.height));
        };
        let next = Self::at(&next, 1)?;
        if next.height == head.height.saturating_add(1) && next.previous == head.id() {
            Ok(Some(head.height))
        } else {
            Ok(None)
        }
    }

    /// The record at `index`, counted from the front of the file, and the two
    /// things it is not allowed to be wrong about.
    ///
    /// Its height is its position, so it has to be the height this position is
    /// for. And the record after it carries its identifier, so a byte changed
    /// anywhere in this record moves that identifier and is caught. The last
    /// record has nothing after it and is checked the other way instead, which
    /// covers its height and its parent and not the rest of it; the last
    /// header is the tip, which a node holds in memory as well.
    ///
    /// It costs one more record read and one hash per read. What it buys is
    /// that this file stops being the one thing a node serves without anything
    /// having looked at it: a header with bytes changed in it used to come
    /// back as truth at every read for the life of the node, the forest got
    /// built over it, and the only symptom was newcomers rejecting proofs that
    /// folded to a root nobody else had.
    fn read(&self, index: u64) -> Result<Option<BlockHeader>, StoreError> {
        let Some(bytes) = self.record(index)? else {
            return Ok(None);
        };
        let header = Self::at(&bytes, index)?;
        let expected = self.first.saturating_add(index);
        if header.height != expected {
            return Err(StoreError::Displaced {
                position: index,
                found: header.height,
                expected,
            });
        }

        let after = index.saturating_add(1);
        let linked = match self.record(after)? {
            Some(next) => Self::at(&next, after)?.previous == header.id(),
            None => match index.checked_sub(1) {
                Some(before) => match self.record(before)? {
                    Some(bytes) => header.previous == Self::at(&bytes, before)?.id(),
                    None => true,
                },
                None => true,
            },
        };
        if !linked {
            return Err(StoreError::Unlinked { height: expected });
        }
        Ok(Some(header))
    }

    /// The bytes of the record at `index`, with nothing checked.
    fn record(&self, index: u64) -> Result<Option<[u8; HEADER_BYTES]>, StoreError> {
        if index >= self.count {
            return Ok(None);
        }
        let at = index.saturating_mul(HEADER_BYTES as u64);
        let mut file = &self.file;
        file.seek(SeekFrom::Start(at))?;
        let mut bytes = [0u8; HEADER_BYTES];
        file.read_exact(&mut bytes)?;
        Ok(Some(bytes))
    }

    /// What those bytes decode to.
    ///
    /// It never fails, and saying so out loud is the point: there is no such
    /// thing as 182 bytes that are not a header, which is why the checks above
    /// exist at all.
    fn at(bytes: &[u8; HEADER_BYTES], index: u64) -> Result<BlockHeader, StoreError> {
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        BlockHeader::decode(bytes).map_err(|source| StoreError::Malformed { index, source })
    }
}

//! Keeping a chain across restarts.
//!
//! Blocks are appended to one file in the order they were accepted, and that
//! order is always replayable: a node only ever accepts a block whose parent it
//! already holds, so a parent can never appear after its child.
//!
//! There is no checksum on a record. Every block is verified cryptographically
//! when it is replayed, which catches anything a checksum would and a great
//! deal more.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cairn_ledger::block::Block;
use cairn_primitives::codec::{CodecError, Decode, Encode};

/// The name the block log takes inside a node's directory.
pub const BLOCK_LOG: &str = "blocks.log";

/// The name of the file holding where each record ends.
///
/// Eight bytes per record and nothing else, so the offset of record `n` sits
/// at `n * 8` and finding a block is a seek. Kept beside the log rather than
/// in memory: a node that held one offset per block would be spending memory
/// on the length of its history, which is the cost this whole design exists to
/// avoid, and it would have to read every block at every start to work them
/// out again.
///
/// Derived, never authoritative. Lose it and it is rebuilt from the log.
pub const BLOCK_INDEX: &str = "blocks.idx";

/// Bytes one entry of the index takes.
const OFFSET_BYTES: u64 = 8;

/// The name of the file that marks a directory as in use.
pub const LOCK_FILE: &str = "lock";

/// The ledger a node was handed, as it stood when it was handed over.
///
/// Only a node that joined a chain rather than reading it has one. Without it
/// such a node cannot start at all unless an archivist is reachable at that
/// moment, which would make every node that ever joined depend on the archive
/// service staying up for the rest of its life.
pub const HANDED_LEDGER: &str = "ledger.dat";

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
    #[error("{path} is already in use by {holder}, which is still running")]
    Locked { path: String, holder: String },
    #[error(
        "this filesystem does not support locking, so two nodes could write to \
         the same directory without noticing: {source}"
    )]
    Unlockable {
        #[source]
        source: std::io::Error,
    },
    #[error("record {index} is not a block: {source}")]
    Malformed {
        index: usize,
        #[source]
        source: CodecError,
    },
    #[error("the log reaches height {expected} and was handed height {found}")]
    OutOfOrder { expected: u64, found: u64 },
}

/// What opening a log found on disk.
///
/// The blocks themselves are counted rather than returned. A node that read
/// them all into a vector to replay them would hold its entire history in
/// memory for as long as the replay took, which on an old chain is the largest
/// allocation the process ever makes and is needed for no reason: they are
/// replayed once, in order, and never looked at together.
#[derive(Debug, Default)]
pub struct Recovered {
    /// Records the log holds.
    pub blocks: usize,
    /// Bytes dropped from the end because they were incomplete or unreadable.
    ///
    /// A torn record at the end is the ordinary trace of a crash during a
    /// write, and dropping it costs one block that will simply be fetched
    /// again.
    pub discarded_bytes: u64,
}

/// An append only record of every block a node has accepted.
///
/// Two files: the records themselves, and where each one ends. What this holds
/// in memory is how many there are and where the last one ends, and nothing
/// that grows with the chain.
#[derive(Debug)]
pub struct BlockLog {
    file: File,
    index: File,
    path: PathBuf,
    /// Records held.
    count: usize,
    /// Height of the first record, so a record's position and a block's height
    /// are not the same number.
    ///
    /// They were, back when every node read its chain from the first block. A
    /// node handed a ledger starts writing at the height it was handed, and a
    /// log that assumed otherwise wrote nothing at all: it looked for the block
    /// at position zero, which that node has never had and never will.
    ///
    /// Learned from the first record rather than stored beside it, because a
    /// second place to write it down is a second place for it to be wrong.
    first: u64,
    /// Byte offset just past the last record.
    end: u64,
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
        let index = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(BLOCK_INDEX))?;

        let mut log = Self {
            file,
            index,
            path,
            count: 0,
            first: 0,
            end: 0,
        };
        let recovered = log.recover()?;
        Ok((log, recovered))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Height of the first block held, or zero when nothing is held.
    pub fn first_height(&self) -> u64 {
        self.first
    }

    /// The height just past the last block held.
    ///
    /// What a node compares its branch against to know what is left to write.
    pub fn reaches(&self) -> u64 {
        self.first.saturating_add(self.count as u64)
    }

    /// Whether this log holds the block at `height`.
    pub fn holds(&self, height: u64) -> bool {
        self.count > 0 && height >= self.first && height < self.reaches()
    }

    /// Reads the block at `height`, rather than at a position.
    pub fn read_at(&self, height: u64) -> Result<Option<Block>, StoreError> {
        if !self.holds(height) {
            return Ok(None);
        }
        let Ok(index) = usize::try_from(height.saturating_sub(self.first)) else {
            return Ok(None);
        };
        self.read(index)
    }

    /// Cuts the log back so that it holds nothing at `height` or past it.
    pub fn keep_below(&mut self, height: u64) -> Result<(), StoreError> {
        let keep = height.saturating_sub(self.first).min(self.count as u64);
        self.keep_first(usize::try_from(keep).unwrap_or(usize::MAX))
    }

    /// Drops everything below `height`, so the log starts there.
    ///
    /// For a node that has written down the ledger those blocks add up to and
    /// no longer needs them to reach it. The records that stay are moved to
    /// the front of the file and the index is written again, which is one pass
    /// over what is kept rather than over what is dropped.
    pub fn keep_from(&mut self, height: u64) -> Result<(), StoreError> {
        if height <= self.first || self.count == 0 {
            return Ok(());
        }
        if height >= self.reaches() {
            return self.clear();
        }
        let dropped = usize::try_from(height.saturating_sub(self.first)).unwrap_or(self.count);
        let Some((start, _)) = self.bounds(dropped)? else {
            return Ok(());
        };

        // Read what is kept before anything is written, so a failure partway
        // leaves the log as it was rather than half moved.
        let room = usize::try_from(self.end.saturating_sub(start)).unwrap_or(0);
        let mut kept = Vec::with_capacity(room);
        let mut file = &self.file;
        file.seek(SeekFrom::Start(start))?;
        file.read_to_end(&mut kept)?;

        let mut ends = Vec::new();
        let mut offset = 0u64;
        for index in dropped..self.count {
            let Some((from, to)) = self.bounds(index)? else {
                break;
            };
            offset = offset.saturating_add(to.saturating_sub(from));
            ends.push(offset);
        }

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&kept)?;
        self.file.set_len(offset)?;
        self.file.flush()?;

        let mut written = Vec::with_capacity(ends.len().saturating_mul(8));
        for end in &ends {
            written.extend_from_slice(&end.to_le_bytes());
        }
        self.index.set_len(0)?;
        self.index.seek(SeekFrom::Start(0))?;
        self.index.write_all(&written)?;
        self.index.flush()?;

        self.count = ends.len();
        self.first = height;
        self.end = offset;
        Ok(())
    }

    /// Drops everything, leaving a log that starts wherever the next block does.
    pub fn clear(&mut self) -> Result<(), StoreError> {
        self.index.set_len(0)?;
        self.index.flush()?;
        self.file.set_len(0)?;
        self.file.flush()?;
        self.count = 0;
        self.first = 0;
        self.end = 0;
        Ok(())
    }

    /// Bytes the records take on disk.
    pub fn bytes(&self) -> u64 {
        self.end
    }

    /// Adds one block to the end of the log.
    ///
    /// The record goes down before the offset that points at it. Dying between
    /// the two leaves an index one entry short, and the tail of the log is
    /// then cut back to match on the next start: the block is lost and asked
    /// for again, which is what a torn write has always cost here. The other
    /// order would leave an offset pointing at bytes that were never written.
    pub fn append(&mut self, block: &Block) -> Result<(), StoreError> {
        // A log whose positions do not line up with heights would serve the
        // wrong block to everyone catching up, confidently. The first block
        // sets where the log starts; every one after it has to follow on.
        if self.count == 0 {
            self.first = block.header.height;
        } else if block.header.height != self.reaches() {
            return Err(StoreError::OutOfOrder {
                expected: self.reaches(),
                found: block.header.height,
            });
        }
        let body = block.encode();
        if body.len() > MAX_RECORD_BYTES {
            return Err(StoreError::BlockTooLarge);
        }
        let length = u32::try_from(body.len()).unwrap_or(u32::MAX);

        let mut record = Vec::with_capacity(body.len().saturating_add(4));
        length.encode_to(&mut record);
        record.extend_from_slice(&body);

        let start = self.end;
        self.file.seek(SeekFrom::Start(start))?;
        self.file.write_all(&record)?;
        self.file.flush()?;

        let end = start.saturating_add(record.len() as u64);
        self.write_offset(self.count, end)?;
        self.count = self.count.saturating_add(1);
        self.end = end;
        Ok(())
    }

    /// Writes where record `index` ends.
    fn write_offset(&mut self, index: usize, end: u64) -> Result<(), StoreError> {
        let at = (index as u64).saturating_mul(OFFSET_BYTES);
        self.index.seek(SeekFrom::Start(at))?;
        self.index.write_all(&end.to_le_bytes())?;
        self.index.flush()?;
        Ok(())
    }

    /// Where record `index` ends, and where it starts.
    fn bounds(&self, index: usize) -> Result<Option<(u64, u64)>, StoreError> {
        if index >= self.count {
            return Ok(None);
        }
        let mut file = &self.index;
        if index == 0 {
            let mut end = [0u8; 8];
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut end)?;
            return Ok(Some((0, u64::from_le_bytes(end))));
        }
        // The two offsets sit next to each other, so one read finds both.
        let mut pair = [0u8; 16];
        let at = (index as u64)
            .saturating_sub(1)
            .saturating_mul(OFFSET_BYTES);
        file.seek(SeekFrom::Start(at))?;
        file.read_exact(&mut pair)?;
        let start = u64::from_le_bytes(
            pair.get(..8)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 8]),
        );
        let end = u64::from_le_bytes(
            pair.get(8..)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 8]),
        );
        Ok(Some((start, end)))
    }

    /// Reads the record at `index`.
    ///
    /// Every read seeks, so this is for one block at a time. Reading the whole
    /// log in order is what [`BlockLog::replay`] is for.
    pub fn read(&self, index: usize) -> Result<Option<Block>, StoreError> {
        let Some((start, end)) = self.bounds(index)? else {
            return Ok(None);
        };
        let length = usize::try_from(end.saturating_sub(start)).unwrap_or(0);
        let body = length.saturating_sub(4);
        if body == 0 {
            return Ok(None);
        }

        // `&File` reads and seeks, so this needs no exclusive borrow and no
        // second handle on the file.
        let mut file = &self.file;
        file.seek(SeekFrom::Start(start.saturating_add(4)))?;
        let mut bytes = vec![0u8; body];
        file.read_exact(&mut bytes)?;
        let block =
            Block::decode(&bytes).map_err(|source| StoreError::Malformed { index, source })?;
        Ok(Some(block))
    }

    /// Every record in order, read one at a time.
    ///
    /// For the replay a node does when it starts. It holds one block at a
    /// time rather than all of them, which is the difference between a fixed
    /// cost and one that grows with the chain.
    ///
    /// Do not interleave this with [`BlockLog::read`]: both move the same file
    /// cursor, and the reader here carries a buffer that would then be reading
    /// from somewhere else.
    pub fn replay(&self) -> Replay<'_> {
        Replay {
            reader: BufReader::new(&self.file),
            index: 0,
            total: self.count,
            started: false,
        }
    }

    /// Cuts the log back to its first `count` records.
    ///
    /// The index is cut first. Between the two the index is the shorter of the
    /// pair, which is the state a torn append leaves and which the next start
    /// already knows how to repair.
    pub fn keep_first(&mut self, count: usize) -> Result<(), StoreError> {
        if count >= self.count {
            return Ok(());
        }
        let end = match count.checked_sub(1) {
            None => 0,
            Some(last) => self.bounds(last)?.map_or(0, |(_, end)| end),
        };
        let entries = (count as u64).saturating_mul(OFFSET_BYTES);
        self.index.set_len(entries)?;
        self.index.flush()?;
        self.file.set_len(end)?;
        self.file.flush()?;
        self.count = count;
        self.end = end;
        if count == 0 {
            self.first = 0;
        }
        Ok(())
    }

    /// Works out what the log holds, rebuilding the index only when it has to.
    ///
    /// The usual start reads sixteen bytes: how long the index is, and where
    /// the last record ends. Nothing is decoded and nothing is walked, so
    /// opening a log costs the same on a chain of ten blocks and one of ten
    /// million. Every block is still verified when it is replayed, which is
    /// where a record that cannot be read is found and where the log is cut.
    ///
    /// The index is rebuilt from the log when it is missing, when it is
    /// shorter than the log, or when it claims records the log does not reach.
    /// It is derived, so losing it costs one slow start and nothing else.
    fn recover(&mut self) -> Result<Recovered, StoreError> {
        let logged = self.file.metadata()?.len();
        let indexed = self.index.metadata()?.len();

        // A torn write to the index leaves a partial offset behind.
        let whole = indexed.saturating_sub(indexed % OFFSET_BYTES);
        if whole != indexed {
            self.index.set_len(whole)?;
            self.index.flush()?;
        }
        let count = usize::try_from(whole / OFFSET_BYTES).unwrap_or(0);

        if count == 0 {
            // Either there is nothing here, or the index is gone and the log
            // is not. Only the second needs the walk.
            if logged == 0 {
                self.count = 0;
                self.first = 0;
                self.end = 0;
                return Ok(Recovered::default());
            }
            return self.rebuild();
        }

        let mut last = [0u8; 8];
        let at = whole.saturating_sub(OFFSET_BYTES);
        (&self.index).seek(SeekFrom::Start(at))?;
        (&self.index).read_exact(&mut last)?;
        let end = u64::from_le_bytes(last);

        // The index reaches past the log, so one of them is not what this
        // process last wrote. The log is the record; the index is derived.
        if end > logged {
            return self.rebuild();
        }

        self.count = count;
        self.end = end;

        // Bytes past the last offset are a record that was being written when
        // something stopped, or the block of an index entry that never landed.
        // Either way they are not a record anything points at.
        let discarded = logged.saturating_sub(end);
        if discarded > 0 {
            self.file.set_len(end)?;
            self.file.flush()?;
        }
        self.first = self.height_of_first()?;
        Ok(Recovered {
            blocks: count,
            discarded_bytes: discarded,
        })
    }

    /// Reads back the height the log starts at.
    ///
    /// One record decoded when a node starts, which is what it costs not to
    /// keep this written down anywhere it could disagree with the log itself.
    fn height_of_first(&self) -> Result<u64, StoreError> {
        if self.count == 0 {
            return Ok(0);
        }
        Ok(self.read(0)?.map_or(0, |block| block.header.height))
    }

    /// Reads every complete record, cutting the file back at the first one that
    /// cannot be read, and writes the index out again from what it found.
    fn rebuild(&mut self) -> Result<Recovered, StoreError> {
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
            // Decoded and thrown away: the scan has to know whether a record
            // can be read, because that is where the file is cut, but the
            // block itself is read again when it is wanted.
            Block::decode(&body).map_err(|source| StoreError::Malformed {
                index: ends.len(),
                source,
            })?;

            offset = offset.saturating_add(4).saturating_add(declared as u64);
            ends.push(offset);
            recovered.blocks = recovered.blocks.saturating_add(1);
        }

        drop(reader);
        recovered.discarded_bytes = total.saturating_sub(offset);
        self.count = ends.len();
        self.end = offset;
        if recovered.discarded_bytes > 0 {
            self.file.set_len(offset)?;
            self.file.flush()?;
        }

        let mut written = Vec::with_capacity(ends.len().saturating_mul(8));
        for end in &ends {
            written.extend_from_slice(&end.to_le_bytes());
        }
        self.index.set_len(0)?;
        self.index.seek(SeekFrom::Start(0))?;
        self.index.write_all(&written)?;
        self.index.flush()?;
        self.first = self.height_of_first()?;
        Ok(recovered)
    }
}

/// Every block in a log, in the order they were written.
///
/// An error stops the walk: a record that cannot be read means the rest cannot
/// be trusted to be where it says it is, and a node that carried on would be
/// replaying a chain with a hole in it.
#[derive(Debug)]
pub struct Replay<'a> {
    reader: BufReader<&'a File>,
    index: usize,
    total: usize,
    started: bool,
}

impl Iterator for Replay<'_> {
    type Item = Result<Block, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total {
            return None;
        }
        if !self.started {
            self.started = true;
            if let Err(error) = self.reader.seek(SeekFrom::Start(0)) {
                self.index = self.total;
                return Some(Err(error.into()));
            }
        }

        let mut header = [0u8; 4];
        if let Err(error) = self.reader.read_exact(&mut header) {
            self.index = self.total;
            return Some(Err(error.into()));
        }
        let declared = usize::try_from(u32::from_le_bytes(header)).unwrap_or(usize::MAX);
        if declared > MAX_RECORD_BYTES {
            let index = self.index;
            self.index = self.total;
            return Some(Err(StoreError::RecordTooLarge { index, declared }));
        }
        let mut body = vec![0u8; declared];
        if let Err(error) = self.reader.read_exact(&mut body) {
            self.index = self.total;
            return Some(Err(error.into()));
        }
        let index = self.index;
        self.index = self.index.saturating_add(1);
        Some(Block::decode(&body).map_err(|source| StoreError::Malformed { index, source }))
    }
}

/// Marks a data directory as in use for as long as it is held.
///
/// Two processes appending to the same block log would interleave records and
/// leave neither chain readable.
///
/// The lock is held by the operating system on an open file, not by the
/// presence of the file itself. That distinction is what makes it survive a
/// machine losing power: the kernel drops the lock when the process ends,
/// however it ends, so a node killed outright or a server that reboots comes
/// straight back up. A lock that had to be cleaned up by hand would mean every
/// unattended restart needing a person, which is not a property a node can
/// have.
///
/// The file also carries the process identifier, which is written for the
/// operator to read and never trusted: a stale identifier is only ever a hint
/// in a message, and whether the lock is held is the kernel's answer alone.
#[derive(Debug)]
pub struct DirectoryLock {
    path: PathBuf,
    /// Holding it open is the lock. Dropping this releases it.
    file: File,
}

impl DirectoryLock {
    pub fn acquire(directory: impl AsRef<Path>) -> Result<Self, StoreError> {
        let directory = directory.as_ref();
        std::fs::create_dir_all(directory)?;
        let path = directory.join(LOCK_FILE);

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(StoreError::Locked {
                    path: path.display().to_string(),
                    holder: read_holder(&path),
                })
            }
            // A filesystem that does not support locking, most often a network
            // mount. Refusing is the only safe answer: silently carrying on
            // would let two nodes write to one log, which is the outcome this
            // exists to prevent.
            Err(TryLockError::Error(error)) => {
                return Err(StoreError::Unlockable { source: error })
            }
        }

        let mut file = file;
        file.set_len(0)?;
        let _ = write!(file, "{}", std::process::id());
        let _ = file.flush();
        Ok(Self { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// What the lock file says about who holds it, for the error message only.
///
/// Not always readable, and that is not a failure. Locks on Unix are advisory:
/// they stop another lock, not another read, so the process id written inside
/// comes back. On Windows they are mandatory and cover the bytes themselves,
/// so a file this node cannot lock is also a file it cannot read. The answer
/// is then the honest one rather than a guess, and an operator on that machine
/// has the task manager for the rest.
fn read_holder(path: &Path) -> String {
    let holder = std::fs::read_to_string(path).unwrap_or_default();
    let holder = holder.trim();
    if holder.is_empty() {
        "another process".to_owned()
    } else {
        format!("process {holder}")
    }
}

impl Drop for DirectoryLock {
    /// The file is left behind on purpose.
    ///
    /// Removing it would open a window where another process has the file open
    /// and then loses it from under itself, which turns a clean exclusion into
    /// a race. An idle lock file costs nothing.
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

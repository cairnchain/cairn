//! Keeping a chain across restarts.
//!
//! Blocks are appended to one file in the order they were accepted, and that
//! order is always replayable: a node only ever accepts a block whose parent it
//! already holds, so a parent can never appear after its child.
//!
//! There is no checksum on a record. Every block is verified cryptographically
//! when it is replayed, which catches anything a checksum would and a great
//! deal more. What a checksum would have been for on the other two files is
//! there already and cheaper: a header carries its parent's identifier, and a
//! forest node is the two beneath it folded together, so both are checked
//! against bytes that are already on the disk.
//!
//! The other rule this file keeps is about which of two files wins. The log is
//! the record; the index beside it is worked out from the log and never the
//! other way about. So recovery repairs the index in both directions and never
//! shortens the log, and the only bytes it takes off the end are a record the
//! file stops inside, which cannot become a record however often it is read.
//! `BlockLog::open` can then fail only because a file could not be reached,
//! never because of what is written in one, which is what an unattended node
//! needs from a start.
//!
//! What a record does have is durability. An append returns once the record
//! and the offset naming it are on the disk, in that order, because `flush`
//! says nothing about a disk — only about this program's buffers — and two
//! writes in flight at once land in whatever order the operating system
//! chooses. Without the sync, the careful ordering below is a description of
//! what this code does and not of what the disk ends up holding, and a power
//! cut can leave an offset pointing at bytes that were never written.
//!
//! It costs one sync of each file per block. At a block a minute that is
//! nothing, and what it buys is that an accepted block is a kept block —
//! which matters least for a node that can ask for it again, and most for an
//! archivist, which is the one role that cannot.

pub mod header_tree;
pub mod headers;

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
/// Derived, never authoritative, in either direction. Lose it and it is
/// rebuilt from the log; find it shorter than the log and it is written on
/// rather than believed. Nothing it says shortens the log, and nothing it says
/// is acted on without being checked against the record it describes.
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

pub use header_tree::{HeaderTree, HEADER_TREE};
pub use headers::{HeaderLog, HEADER_BYTES, HEADER_LOG};

/// Largest record the log will read or write.
///
/// A length read from disk is not necessarily a length this process wrote, so
/// it is checked before anything is reserved for it. Everywhere: the rebuild,
/// the replay and the single read all reserve against this and never against
/// the difference between two offsets, which is a number the index holds and
/// the index is a file like any other.
pub const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

/// The most a whole record can take on disk: a body at the ceiling, and the
/// four bytes that say how long it is.
fn max_record_on_disk() -> u64 {
    u64::try_from(MAX_RECORD_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(4)
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("could not reach the block log: {0}")]
    Io(#[from] std::io::Error),
    #[error("record {index} declares {declared} bytes, the limit is {MAX_RECORD_BYTES}")]
    RecordTooLarge { index: usize, declared: usize },
    #[error("block would not fit in one record")]
    BlockTooLarge,
    #[error(
        "this build encodes a header in {found} bytes and the log is laid out for \
         {HEADER_BYTES}, so every record after the first would be read at the wrong \
         offset"
    )]
    HeaderSizeChanged { found: usize },
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
    #[error("the header forest has no node of height {height} at {start}")]
    MissingNode { height: usize, start: u64 },
    #[error("the index puts record {index} between {start} and {end}, in {held} bytes of log")]
    Misindexed {
        index: usize,
        start: u64,
        end: u64,
        held: u64,
    },
    #[error("record {index} says it holds {declared} bytes, the index gives it {indexed}")]
    Mismatched {
        index: usize,
        declared: usize,
        indexed: u64,
    },
    #[error("the header at position {position} says its height is {found}, not {expected}")]
    Displaced {
        position: u64,
        found: u64,
        expected: u64,
    },
    #[error("the header at height {height} and the record beside it do not name each other")]
    Unlinked { height: u64 },
    #[error(
        "the forest node of height {height} covering the leaves from {start} is not the two \
         beneath it folded together"
    )]
    Unfolded { height: usize, start: u64 },
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
    /// Bytes cut off the end of the log, which no record accounted for.
    ///
    /// A record the file stops in the middle of is the ordinary trace of a
    /// crash during a write, and setting it aside costs one block that will
    /// simply be fetched again. Those bytes are cut away, because a record the
    /// file ends inside cannot become one however often it is read.
    ///
    /// Zero when `unreadable` is set, and the two must not be added together.
    /// This used to count that case as well, so a log damaged rather than cut
    /// short reported bytes as thrown away while they were still sitting on
    /// the disk, and the count was the whole tail from the bad record on
    /// rather than a fragment. An operator told bytes are gone looks for a
    /// backup; an operator told bytes are unreadable and still there looks at
    /// them.
    pub discarded_bytes: u64,
    /// Bytes left on the disk past the last record that could be read.
    ///
    /// Only ever set alongside `unreadable`, and set instead of
    /// `discarded_bytes` rather than beside it. Nothing was removed: this is
    /// how much of the log is standing there unread, which is what says
    /// whether the damage cost one block or a day of them.
    pub left_in_place: u64,
    /// The record a walk of the log stopped at, when what stopped it was a
    /// whole record that would not decode rather than one cut short.
    ///
    /// This is damage, not an interrupted write, and the two must not be
    /// reported to an operator in the same words. Nothing is cut for it: the
    /// bytes stay on the disk until the log grows over them, so a start that
    /// misread them once can read them back, and a person can still look at
    /// what is there.
    pub unreadable: Option<usize>,
}

/// Opens a scratch file, for holding a handle somewhere harmless.
fn hold(path: &Path) -> Result<File, StoreError> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?)
}

/// Makes a rename durable, where the platform has a way to say so.
///
/// Unix has one: syncing the directory itself. Windows does not let a
/// directory be opened as a file at all, and `ReplaceFile` is not something
/// the standard library reaches — so on Windows this is a no-op and a
/// compaction interrupted by a power cut can leave the old log in place. The
/// next start treats that as an index reaching past its log and rebuilds, so
/// nothing is served wrongly; what is lost is the compaction, not the chain.
#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

// The signature has to match the Unix one, which can fail. Clippy sees a
// function that never does and asks for the `Result` to go, which would only
// move the difference between the platforms into every caller.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_path: &Path) -> Result<(), StoreError> {
    Ok(())
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
    /// Where the log and its index live, so both can be written beside
    /// themselves and moved into place.
    directory: PathBuf,
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
    /// Bytes past that offset which recovery found and did not cut.
    ///
    /// Only a walk that stopped at a whole record it could not read leaves
    /// any, and it leaves them on purpose. They go when the log next grows
    /// over them, which is the moment nothing could reach them again anyway,
    /// and going then is what stops every later start from walking them.
    trailing: u64,
    /// Whether the two handles above are still on the two files this log
    /// names.
    ///
    /// True for the whole of an ordinary life. It goes false in one place: a
    /// compaction that let go of both handles and could not get them back.
    /// The log is then holding a scratch file that has been deleted, and a
    /// write to it lands on an inode nothing can ever read again.
    ///
    /// This is not the same as holding nothing, and the difference is what a
    /// node does next. A log that holds nothing is written from the start of
    /// the branch; a log that is not a log has to refuse, so that the gap
    /// between the chain and the disk opens where the node is watching for it
    /// instead of being closed by writes that go nowhere.
    usable: bool,
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

        // A move that never finished leaves these behind. They are derived and
        // point at nothing, so they go.
        let _ = std::fs::remove_file(directory.join(format!("{BLOCK_LOG}.part")));
        let _ = std::fs::remove_file(directory.join(format!("{BLOCK_INDEX}.part")));
        let _ = std::fs::remove_file(directory.join(format!("{BLOCK_LOG}.hold")));

        let mut log = Self {
            file,
            index,
            path,
            directory: directory.to_path_buf(),
            count: 0,
            first: 0,
            end: 0,
            trailing: 0,
            usable: true,
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
    ///
    /// A height is a position plus where the log begins, and where it begins
    /// is one record's word for it. Everything between the two is assumed to
    /// follow on, which is true of a log this code wrote and is a claim like
    /// any other once bytes have changed on a disk, so the block answers for
    /// its own height before it is handed over.
    ///
    /// [`HeaderLog::read`] has kept this check since a header that had moved
    /// came back as truth at every read for the life of a node. The block log
    /// did not, and it is the one a node serves blocks out of: a record whose
    /// height field changed still decoded, still matched the length its index
    /// gave it, and still opened a log reporting nothing wrong, so `read_at`
    /// answered a question about height five with the block from height nine.
    /// `cairn-net` sends that answer to whoever asked for height five, which
    /// refuses it and has every reason to think the sender is the problem.
    /// The check costs one comparison on a block that is decoded already, and
    /// what it buys is the failure being this node's, where it happened.
    ///
    /// Only here, and not in [`BlockLog::read`], which is asked about a
    /// position and answers about one: it is what `height_of_first` uses to
    /// learn where the log begins, so a height check there would be asking the
    /// record to confirm the number taken from it.
    pub fn read_at(&self, height: u64) -> Result<Option<Block>, StoreError> {
        if !self.holds(height) {
            return Ok(None);
        }
        let Ok(index) = usize::try_from(height.saturating_sub(self.first)) else {
            return Ok(None);
        };
        let Some(block) = self.read(index)? else {
            return Ok(None);
        };
        if block.header.height != height {
            return Err(StoreError::Displaced {
                position: index as u64,
                found: block.header.height,
                expected: height,
            });
        }
        Ok(Some(block))
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
        //
        // Exactly the records, never to the end of the file. Recovery leaves
        // the bytes of a record it could not read sitting past `self.end` on
        // purpose, and reading to the end copied them into the compacted log
        // and then set `trailing` to zero: the one thing that writes over them
        // is the guard in `append`, and it was disarmed for bytes that were
        // still there. A twenty record log damaged at its end came back from a
        // compaction sixty eight bytes longer than it said it was, with
        // nothing left that knew it.
        let room = self.end.saturating_sub(start);
        let mut kept = Vec::with_capacity(usize::try_from(room).unwrap_or(0));
        let mut file = &self.file;
        file.seek(SeekFrom::Start(start))?;
        file.take(room).read_to_end(&mut kept)?;

        let mut ends = Vec::new();
        let mut offset = 0u64;
        for index in dropped..self.count {
            let Some((from, to)) = self.bounds(index)? else {
                break;
            };
            offset = offset.saturating_add(to.saturating_sub(from));
            ends.push(offset);
        }
        let mut written = Vec::with_capacity(ends.len().saturating_mul(8));
        for end in &ends {
            written.extend_from_slice(&end.to_le_bytes());
        }

        // Written beside the log and moved into place, rather than over it.
        // Writing over it would leave, on a machine that stopped partway, a
        // file holding the front of the new log and the back of the old one,
        // with an index still pointing into the old offsets: a node would
        // serve blocks that are not the ones it names, confidently.
        //
        // The log moves first. Stopping between the two moves leaves an index
        // reaching past the log, which the next start already treats as an
        // index to be rebuilt.
        let staged_log = self.directory.join(format!("{BLOCK_LOG}.part"));
        let staged_index = self.directory.join(format!("{BLOCK_INDEX}.part"));
        let index_path = self.directory.join(BLOCK_INDEX);
        std::fs::write(&staged_log, &kept)?;
        std::fs::write(&staged_index, &written)?;

        // Both handles are let go of before the move. Unix renames over an
        // open file happily; Windows refuses, and a node is meant to run on
        // both. They point at a scratch file for the two lines it takes, since
        // a `File` closes when it is dropped and there is no other way to say
        // so.
        //
        // Both are opened before either is assigned, so that the last thing
        // that can fail with a `?` happens while this log is still on its own
        // files. Assigning as they were opened put the danger zone the comment
        // below describes one line above where the comment starts: a second
        // open that failed left `self.file` on the scratch, `self.index` on
        // the real index, and `usable` still true, which is the shape of a
        // node taking appends into a file the next start deletes while the
        // offsets naming them land in the index that survives.
        let scratch = self.directory.join(format!("{BLOCK_LOG}.hold"));
        let held = hold(&scratch)?;
        let held_index = hold(&scratch)?;
        self.file = held;
        self.index = held_index;

        // From here the handles are on a scratch file, so what this struct
        // says about itself and what it can actually read have parted company
        // until they are put back together. Nothing below may leave with `?`.
        //
        // It used to. A rename that failed, a directory that would not sync,
        // or a reopen refused took the error straight out of here with the
        // handles still on the scratch file and `count`, `first` and `end`
        // still describing the log that is no longer there. Measured on a
        // twenty record log whose reopen was refused: it went on reporting
        // twenty records from height zero, gave an unexpected end of file for
        // the block at height fifteen, replayed one record instead of twenty,
        // and then took an append and reported it written. That block went
        // into `blocks.log.hold`, which the next start deletes. The node saw
        // no gap, because the append succeeded, so nothing anywhere said the
        // chain was no longer being written down.
        let put_back = || -> Result<(File, File), StoreError> {
            std::fs::rename(&staged_log, &self.path)?;
            std::fs::rename(&staged_index, &index_path)?;
            sync_directory(&self.directory)?;
            let file = OpenOptions::new().read(true).write(true).open(&self.path)?;
            let index = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&index_path)?;
            Ok((file, index))
        };
        let (file, index) = match put_back() {
            Ok(handles) => handles,
            Err(error) => {
                // What is left cannot be read, so nothing here may go on
                // saying it can. Saying nothing is what would let the appends
                // carry on into the scratch file; saying nothing *and* that
                // this is not a log is what puts the gap where the node is
                // watching for it.
                self.count = 0;
                self.first = 0;
                self.end = 0;
                self.trailing = 0;
                self.usable = false;
                return Err(error);
            }
        };
        self.file = file;
        self.index = index;
        let _ = std::fs::remove_file(&scratch);

        self.count = ends.len();
        self.first = height;
        self.end = offset;
        self.trailing = 0;
        Ok(())
    }

    /// Drops everything, leaving a log that starts wherever the next block does.
    ///
    /// The log goes first, for the reason [`BlockLog::keep_first`] sets out: a
    /// crash between the two has to leave the index ahead of the log and not
    /// behind it, or the next start reads the whole log back.
    pub fn clear(&mut self) -> Result<(), StoreError> {
        self.file.set_len(0)?;
        self.file.sync_data()?;
        self.index.set_len(0)?;
        self.index.sync_data()?;
        self.count = 0;
        self.first = 0;
        self.end = 0;
        self.trailing = 0;
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
        // A compaction that could not put this back on its own files leaves
        // the handles below on a deleted scratch file. Writing there returns
        // success and reaches nobody, which is the one failure a node cannot
        // see: it is the appends that tell it the disk is keeping up.
        if !self.usable {
            return Err(StoreError::Io(std::io::Error::other(
                "this log is not on the files it names: a compaction could not \
                 open them again",
            )));
        }

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

        // Bytes recovery set aside and did not cut. Writing over them is the
        // moment they stop being reachable by anything, so this is where they
        // go: leaving them would have every later start walk them again.
        if self.trailing > 0 {
            self.file.set_len(self.end)?;
            self.trailing = 0;
        }

        let start = self.end;
        self.file.seek(SeekFrom::Start(start))?;
        self.file.write_all(&record)?;
        // The comment above is only true if the two writes reach the disk in
        // the order they were made, and without this they do not: `flush` says
        // nothing about the disk, only about this program's buffers, so both
        // are in flight at once and the order they land in belongs to the
        // operating system. An offset that lands first, followed by a power
        // cut, names bytes that were never written — which is the one outcome
        // the ordering was chosen to avoid.
        self.file.sync_data()?;

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
        // Once this returns, the block is on the disk and so is the offset
        // naming it. That is what an accepted block is allowed to mean: an
        // archivist that answers with proofs cannot fetch again what it lost.
        self.index.sync_data()?;
        Ok(())
    }

    /// Where record `index` ends, and where it starts.
    ///
    /// Two numbers off a disk, so they are checked before anything acts on
    /// them. `recover` only ever compares the last offset with the length of
    /// the log, which leaves every other entry to be checked here or nowhere:
    /// one flipped byte in the middle of the index used to pass the open
    /// untouched and hand `read` a record size chosen by the file, and near
    /// `u64::MAX` that is an allocation failure, which in Rust is a process
    /// abort with no message.
    fn bounds(&self, index: usize) -> Result<Option<(u64, u64)>, StoreError> {
        if index >= self.count {
            return Ok(None);
        }
        let checked = |start: u64, end: u64| {
            if end <= start || end > self.end || end.saturating_sub(start) > max_record_on_disk() {
                return Err(StoreError::Misindexed {
                    index,
                    start,
                    end,
                    held: self.end,
                });
            }
            Ok(Some((start, end)))
        };
        let mut file = &self.index;
        if index == 0 {
            let mut end = [0u8; 8];
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut end)?;
            return checked(0, u64::from_le_bytes(end));
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
        checked(start, end)
    }

    /// Reads the record at `index`.
    ///
    /// Every read seeks, so this is for one block at a time. Reading the whole
    /// log in order is what [`BlockLog::replay`] is for.
    ///
    /// A record says how long it is and so does the index, and only one of the
    /// two is the record. What is reserved comes from the log: the four bytes
    /// the seek used to skip over are read and checked against the ceiling and
    /// against the pair of offsets, which costs the four bytes and a
    /// comparison and is what puts `MAX_RECORD_BYTES` on this path at last.
    pub fn read(&self, index: usize) -> Result<Option<Block>, StoreError> {
        let Some((start, end)) = self.bounds(index)? else {
            return Ok(None);
        };

        // `&File` reads and seeks, so this needs no exclusive borrow and no
        // second handle on the file.
        let mut file = &self.file;
        file.seek(SeekFrom::Start(start))?;
        let mut header = [0u8; 4];
        file.read_exact(&mut header)?;
        let declared = usize::try_from(u32::from_le_bytes(header)).unwrap_or(usize::MAX);
        if declared > MAX_RECORD_BYTES {
            return Err(StoreError::RecordTooLarge { index, declared });
        }
        let indexed = end.saturating_sub(start);
        if u64::try_from(declared)
            .unwrap_or(u64::MAX)
            .saturating_add(4)
            != indexed
        {
            return Err(StoreError::Mismatched {
                index,
                declared,
                indexed,
            });
        }

        let mut bytes = vec![0u8; declared];
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
    /// The log is cut first, and the order is the opposite of an append's for
    /// the same reason an append's is what it is: whichever file is left
    /// disagreeing has to be the one recovery will put right rather than
    /// believe. An append writes its record before the offset, so a crash
    /// between the two leaves the log ahead of the index and the record is
    /// read forward and kept, which is what a block that was accepted and
    /// synced deserves. A cut leaves the index ahead of the log, which
    /// recovery already treats as an index to be worked out again, so the
    /// records this decided to drop stay dropped.
    ///
    /// Cutting the index first would have the next start read the abandoned
    /// records back out of the log and put them where this had just taken them
    /// from. That was safe only while a short index won, which is the rule
    /// this file no longer keeps.
    ///
    /// Both cuts are waited for. A `set_len` that has not reached the disk is
    /// a file that comes back longer than this asked for.
    pub fn keep_first(&mut self, count: usize) -> Result<(), StoreError> {
        if count >= self.count {
            return Ok(());
        }
        let end = match count.checked_sub(1) {
            None => 0,
            Some(last) => self.bounds(last)?.map_or(0, |(_, end)| end),
        };
        let entries = (count as u64).saturating_mul(OFFSET_BYTES);
        self.file.set_len(end)?;
        self.file.sync_data()?;
        self.index.set_len(entries)?;
        self.index.sync_data()?;
        self.count = count;
        self.end = end;
        self.trailing = 0;
        if count == 0 {
            self.first = 0;
        }
        Ok(())
    }

    /// Works out what the log holds, and puts the index back in line with it
    /// when the two disagree.
    ///
    /// The usual start reads sixteen bytes: how long the index is, and where
    /// the last record ends. Nothing is decoded and nothing is walked, so
    /// opening a log costs the same on a chain of ten blocks and one of ten
    /// million. Every block is still verified when it is replayed, which is
    /// where a record that cannot be read is found.
    ///
    /// When those sixteen bytes do not account for the whole log, the log
    /// wins, in both directions. It is the record and the index is worked out
    /// from it, so an index that reaches past the log is written again from
    /// the front, and one that stops short has the records past it read and
    /// named. Neither shortens the log.
    ///
    /// The asymmetry that used to sit here cost the chain. Only an index
    /// reaching too far was rebuilt; one that was merely short was believed,
    /// and the log cut back to it. `rebuild` writes the index with no sync and
    /// is exactly what runs after a crash, so a second crash before that write
    /// reached the platter left a short index and a whole log, and the start
    /// after it deleted every block the index no longer named. Six blocks
    /// measured, eight bytes of index left, five of them gone from a file that
    /// still held all six, reported to the operator as bytes of an unfinished
    /// write.
    ///
    /// The one thing recovery still cuts is a record the file ends inside,
    /// which is not a record whatever else is true.
    fn recover(&mut self) -> Result<Recovered, StoreError> {
        let logged = self.file.metadata()?.len();
        let indexed = self.index.metadata()?.len();

        // A torn write to the index leaves a partial offset behind.
        let whole = indexed.saturating_sub(indexed % OFFSET_BYTES);
        if whole != indexed {
            self.index.set_len(whole)?;
            self.index.sync_data()?;
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

        // The index reaches past the log, so there is nothing in it to build
        // on and it has to be worked out from the front.
        if end > logged {
            return self.rebuild();
        }

        self.count = count;
        self.end = end;

        if end < logged {
            // Splicing onto an offset that is not a record boundary would name
            // records that are not there, so the last entry the index does
            // have is checked before the rest are added after it.
            //
            // And the first, because `settle` reads record zero back to learn
            // where the log starts and had no answer for that read failing.
            // An index one entry short is the ordinary torn append; an index
            // with a damaged first offset is a byte of rot in a derived file.
            // Either alone was survivable and the two together were not: the
            // start refused with "the index puts record 0 between 0 and 0",
            // and an unattended node stayed down over a file this whole design
            // says is worked out from the log and never believed. The same
            // damage with the index at full length rebuilt and came back with
            // all twenty blocks.
            //
            // Two records decoded, on the crash path only.
            if self.read(count.saturating_sub(1)).is_err() || self.read(0).is_err() {
                return self.rebuild();
            }
            return self.extend(logged);
        }

        // Where the log starts is read back from its first record rather than
        // written down anywhere it could disagree. A first record that will
        // not read leaves the index with no meaning, so the log answers for
        // itself instead.
        match self.height_of_first() {
            Ok(first) => self.first = first,
            Err(_) => return self.rebuild(),
        }
        Ok(Recovered {
            blocks: count,
            discarded_bytes: 0,
            left_in_place: 0,
            unreadable: None,
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

    /// Reads every record the log holds and writes the index out again from
    /// what it found.
    fn rebuild(&mut self) -> Result<Recovered, StoreError> {
        let total = self.file.metadata()?.len();
        let walk = self.walk(0, 0, total)?;
        self.count = walk.ends.len();
        self.end = walk.offset;
        self.write_offsets(&walk.ends, 0)?;
        self.settle(walk.unreadable, total)
    }

    /// Reads the records the index does not reach and names them too.
    ///
    /// What lies past the last offset is either a record whose offset never
    /// landed, which is what a crash between the two writes of an append
    /// leaves and which is a block this node accepted and vouched for, or a
    /// record that stopped partway, which is not a record. Cutting the log to
    /// the index would throw the first away along with the second; reading
    /// forward costs one record on the ordinary crash and gets it back.
    fn extend(&mut self, total: u64) -> Result<Recovered, StoreError> {
        let from = self.count;
        let walk = self.walk(self.end, from, total)?;
        self.count = from.saturating_add(walk.ends.len());
        self.end = walk.offset;
        self.write_offsets(&walk.ends, from)?;
        self.settle(walk.unreadable, total)
    }

    /// Reads records forward from `from`, stopping at the first thing that is
    /// not one.
    ///
    /// Nothing is kept but where each record ends. Blocks are decoded and
    /// thrown away, because the walk has to know whether a record can be read
    /// and the block itself is read again when somebody wants it.
    fn walk(&self, from: u64, index_from: usize, total: u64) -> Result<Walk, StoreError> {
        let mut file = &self.file;
        file.seek(SeekFrom::Start(from))?;
        let mut reader = BufReader::new(file);

        let mut walk = Walk {
            ends: Vec::new(),
            offset: from,
            unreadable: None,
        };
        loop {
            let index = index_from.saturating_add(walk.ends.len());
            let mut header = [0u8; 4];
            if reader.read_exact(&mut header).is_err() {
                break;
            }
            let declared = usize::try_from(u32::from_le_bytes(header)).unwrap_or(usize::MAX);
            let left = total.saturating_sub(walk.offset).saturating_sub(4);
            if u64::try_from(declared).unwrap_or(u64::MAX) > left {
                // The file ends inside this record, so it is not one whatever
                // its length says. A write cut short is exactly this shape,
                // and so is a length prefix a bad byte made enormous: an
                // oversized length in the last record used to refuse the
                // start for ever instead of being read as the torn tail it is.
                break;
            }
            if declared > MAX_RECORD_BYTES {
                // The bytes are all there and there are more of them than any
                // block the rules allow, so this is not a length this process
                // wrote. Nothing is reserved for it.
                walk.unreadable = Some(index);
                break;
            }
            let mut body = vec![0u8; declared];
            if reader.read_exact(&mut body).is_err() {
                break;
            }
            if Block::decode(&body).is_err() {
                walk.unreadable = Some(index);
                break;
            }
            walk.offset = walk
                .offset
                .saturating_add(4)
                .saturating_add(u64::try_from(declared).unwrap_or(u64::MAX));
            walk.ends.push(walk.offset);
        }
        Ok(walk)
    }

    /// Settles what a walk left: the tail, and where the log starts.
    ///
    /// A walk that ran out of file cuts what it could not use, since those
    /// bytes can never become a record. A walk that stopped at a whole record
    /// it could not read cuts nothing: that is damage rather than an
    /// interrupted write, a start that misread it once may read it back, and
    /// a node that deleted the rest of its log over one bad byte would be
    /// doing more harm than the byte did. It comes back with the prefix, says
    /// so, and asks for the rest again.
    fn settle(&mut self, unreadable: Option<usize>, total: u64) -> Result<Recovered, StoreError> {
        let beyond = total.saturating_sub(self.end);
        self.trailing = 0;
        let cut = if beyond > 0 && unreadable.is_none() {
            self.file.set_len(self.end)?;
            self.file.sync_data()?;
            beyond
        } else {
            self.trailing = beyond;
            0
        };
        self.first = self.height_of_first()?;
        Ok(Recovered {
            blocks: self.count,
            discarded_bytes: cut,
            left_in_place: beyond.saturating_sub(cut),
            unreadable,
        })
    }

    /// Writes where records `from` onward end, and waits for them.
    ///
    /// The wait is the point. Without it the index is a file that can come
    /// back from a crash holding a prefix of what was written, and an index
    /// that has to be worked out again at every start is a slow start at every
    /// start. It used to be worse than slow: a short index was believed.
    fn write_offsets(&mut self, ends: &[u64], from: usize) -> Result<(), StoreError> {
        let at = (from as u64).saturating_mul(OFFSET_BYTES);
        let mut written = Vec::with_capacity(ends.len().saturating_mul(8));
        for end in ends {
            written.extend_from_slice(&end.to_le_bytes());
        }
        self.index.set_len(at)?;
        self.index.seek(SeekFrom::Start(at))?;
        self.index.write_all(&written)?;
        self.index.sync_data()?;
        Ok(())
    }
}

/// What reading records forward from one offset found.
#[derive(Debug)]
struct Walk {
    /// Where each record read ends, oldest first.
    ends: Vec<u64>,
    /// Where the last of them ends, or where the walk started if there were
    /// none.
    offset: u64,
    /// The record the walk stopped at, when it stopped at a whole one that
    /// would not decode rather than at the end of the file.
    unreadable: Option<usize>,
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

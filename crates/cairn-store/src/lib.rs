//! Keeping a chain across restarts.
//!
//! Blocks are appended to one file in the order they were accepted, and that
//! order is always replayable: a node only ever accepts a block whose parent it
//! already holds, so a parent can never appear after its child.
//!
//! There is no checksum on any of the three files, and none is wanted. What a
//! checksum would have been for is already in the bytes and is stronger: a
//! header carries its parent's identifier and names the transactions beneath
//! it, and a forest node is the two beneath it folded together, so every file
//! here is checked against bytes that are already on the disk, and what the
//! check says is which chain a record belongs to and not merely that it has
//! not rotted.
//!
//! Every block is also verified cryptographically when it is replayed, which
//! catches anything a checksum would and a great deal more. That sentence used
//! to stand here on its own, and it is about the replay, which is a start.
//! Between two starts the log is served, out of [`BlockLog::read_at`], to
//! every peer catching up, and until the check that function now makes it was
//! the height alone: eight bytes of a record that is hundreds. See `read_at`
//! for what the rest of them came back as.
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
//!
//! The same rule covers the files that are replaced whole rather than appended
//! to: the ledger a node starts from, its address book, the header log after a
//! merge, the compacted block log. Those go through
//! [`write_beside_and_move`], which waits for the bytes and then for the name,
//! so what a machine that stops leaves behind is the file that was there or
//! the file that was written. Without the first wait a rename can reach the
//! disk ahead of what it names, and the file comes back at its full length
//! holding whatever those blocks held before: present, the right size, and
//! nobody's.

pub mod header_tree;
pub mod headers;

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cairn_ledger::block::{Block, BlockHeader};
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

/// Bytes at the front of a record that say how long the rest of it is.
const LENGTH_BYTES: u64 = 4;

/// The name of the file that marks a directory as in use.
const LOCK_FILE: &str = "lock";

/// The most of the lock file read to say who holds it: a process identifier
/// is twenty digits at most, and the rest would only be a longer message.
const HOLDER_BYTES: u64 = 64;

/// The ledger a node was handed, as it stood when it was handed over.
///
/// Only a node that joined a chain rather than reading it has one. Without it
/// such a node cannot start at all unless an archivist is reachable at that
/// moment, which would make every node that ever joined depend on the archive
/// service staying up for the rest of its life.
pub const HANDED_LEDGER: &str = "ledger.dat";

pub use header_tree::{HeaderTree, HEADER_TREE, NODE_BYTES};
pub use headers::{HeaderLog, JoinFailed, HEADER_BYTES, HEADER_LOG};

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
    /// A read or a write the file system refused, in the file system's words.
    ///
    /// Naming no file, because five files come through here: the block log,
    /// its index, the header log, the header forest and the lock. It used to
    /// read "could not reach the block log" for all of them, so a header log
    /// that would not open was the block log twice over and a directory
    /// another node held was a block log nobody could reach. The file is
    /// named by whoever knows which one it was.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("record {index} declares {declared} bytes, the limit is {MAX_RECORD_BYTES}")]
    RecordTooLarge { index: usize, declared: usize },
    #[error("record {index} declares {declared} bytes and {left} are left in the log")]
    RecordPastTheEnd {
        index: usize,
        declared: usize,
        left: u64,
    },
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
    #[error(
        "the index beside the log had to be worked out again and would not go down: \
         {source}. Every block is still in the log itself and none of this is damage to \
         it; make room beside it and start again"
    )]
    IndexNotWritten {
        #[source]
        source: std::io::Error,
    },
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
    #[error("the record at height {height} holds transactions its own header does not name")]
    Unrooted { height: u64 },
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
    ///
    /// Read by the tests, which hold an open to what it found. A node counts
    /// the blocks it replays for itself, so nothing in production reads it.
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
    /// Records set aside because the log does not know where it starts.
    ///
    /// Its own place. The bytes are still there, nothing is cut, and this is
    /// neither a read fault nor an interrupted write: the records decode
    /// perfectly and disagree with each other about the first one's height. An
    /// operator told this looks at record zero, which is where the answer is.
    ///
    /// Before this existed the log took record zero's height on trust, so a
    /// log that did not know where it started said it started somewhere else,
    /// with every field of `Recovered` reading as a clean open.
    pub blocks_set_aside: usize,
}

/// Says which file a recovery could not write, where the answer is the index.
///
/// The log and the index are both reached through the same error, and only one
/// of them is ever the news: an operator told the block log could not be
/// reached goes looking for damage to the chain, and what is actually there is
/// a derived file that needs eight bytes a record of room.
fn index_not_written(error: StoreError) -> StoreError {
    match error {
        StoreError::Io(source) => StoreError::IndexNotWritten { source },
        other => other,
    }
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
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

// The signature has to match the Unix one, which can fail. Clippy sees a
// function that never does and asks for the `Result` to go, which would only
// move the difference between the platforms into every caller.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// The name a file is written under while it is being written.
///
/// Beside the real one and inside the same directory, so the move onto it is a
/// rename within one filesystem, which is the only kind that cannot half
/// happen.
#[must_use]
pub fn staged_beside(target: &Path) -> PathBuf {
    beside(target, ".part")
}

/// The same, under any suffix.
///
/// Added to the whole name rather than put in place of the extension: two
/// files a directory apart are `headers.log` and `headers.idx`, and a scratch
/// name made by replacing the extension would be the same name for both.
pub(crate) fn beside(target: &Path, suffix: &str) -> PathBuf {
    let mut name = target.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Writes `bytes` to `path` and does not return until the disk holds them.
///
/// For a file written beside the one it is going to replace. Two things
/// separate it from `std::fs::write`, and a node has been bitten by both.
///
/// The sync is the first. A write returns when the bytes are in the page
/// cache, so a machine that stops afterwards can bring the file back at its
/// full length holding whatever was on those blocks before. A file moved into
/// place on the strength of a write that never reached the platter is the
/// worst shape of all: present, the right size, and not the file anybody
/// wrote.
///
/// Nothing left behind is the second. What an interrupted write leaves is
/// bytes nobody can use, under a name the next attempt will write over
/// anyway, on the disk that was probably the reason it failed. Taking it away
/// is what stops a node that could not free space from having spent some.
fn write_and_sync(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let written = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        });
    if written.is_err() {
        let _ = std::fs::remove_file(path);
    }
    written
}

/// Moves `staged` onto `target`, and waits for the new name where the platform
/// has a way to.
///
/// The rename itself is what makes the replacement all or nothing: whoever
/// reads `target` next sees the file that was there or the file this wrote,
/// and never half of either.
fn move_into_place(staged: &Path, target: &Path) -> std::io::Result<()> {
    std::fs::rename(staged, target)?;
    sync_the_directory_of(target)
}

/// Waits for the directory `path` sits in, so a name that has just changed in
/// it is on the disk.
///
/// Separate from [`move_into_place`] for the caller that has to know which of
/// the two happened: a rename that did not happen leaves the file that was
/// there, and a rename that happened and was not waited for has still
/// happened. Reading the two as one failure means describing the file on the
/// disk wrongly, which for a log whose positions are heights is the worst
/// answer available.
///
/// Nothing in the suite measures any of this, and that is a fact about what a
/// test can do rather than a gap to fill. A mutation pass over this file made
/// this function answer `Ok(())` without doing anything, made
/// [`sync_directory`] do the same, made [`write_beside_and_move`] do the same,
/// and read the guard below as `true`, as `false` and with its `!` removed.
/// Six mutations, six survivors, with the whole of `cairn-store` green.
///
/// They survive because what they change is only visible after a machine
/// stops. `audit_a_compaction_stopped_at_each_step.rs` says the same thing
/// from the other side and in as many words: the states it builds are
/// "constructed rather than crashed into", and "whether the ordering actually
/// leaves only those states is a claim about `fsync` that nothing here can
/// reach". A test cannot cut the power, so a missing wait is a test that
/// passes.
///
/// The guard below is the one part that is not about power at all. It is for
/// a path with no directory in it, where the parent is the empty string and
/// opening it would fail: a node given an empty data directory writes
/// `blocks.log` and nothing else. Read the other way round, that write fails
/// for a node whose disk is fine. This said reaching it from a test meant
/// writing into the repository; a test can choose the directory it runs in,
/// and `audit_a_file_named_without_a_directory.rs` does, which holds the guard
/// read as `true` and read without its `!`. Read as `false` it skips the wait
/// for every path, which is one more of the survivors above.
pub(crate) fn sync_the_directory_of(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(directory) if !directory.as_os_str().is_empty() => sync_directory(directory),
        _ => Ok(()),
    }
}

/// Replaces `target` with `bytes`, so that a machine which stops partway
/// leaves the file that was there rather than half of a new one.
///
/// The order is the whole of it: the bytes reach the disk, then the name does.
/// Reversed, or with either step left to the page cache, an interrupted write
/// leaves the new name over contents that were never written, which for a file
/// a node cannot start without is the difference between an interrupted write
/// and a node that never comes back.
pub fn write_beside_and_move(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let staged = staged_beside(target);
    write_and_sync(&staged, bytes)?;
    if let Err(error) = move_into_place(&staged, target) {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
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
        // No `count > 0`: with none held, `reaches` is `first` and the range is empty.
        height >= self.first && height < self.reaches()
    }

    /// Reads the block at `height`, rather than at a position.
    ///
    /// A height is a position plus where the log begins, and where it begins
    /// is one record's word for it. Everything between the two is assumed to
    /// follow on, which is true of a log this code wrote and is a claim like
    /// any other once bytes have changed on a disk, so the block answers for
    /// its own height before it is handed over.
    ///
    /// This is the file a node serves blocks out of, and what leaves here
    /// leaves the node: `cairn_net` reads a peer's catch-up out of `read_at`,
    /// and a peer handed a record that is not the block it asked for refuses
    /// it and has every reason to think the sender is the problem. Every check
    /// below is there to make that failure this node's, where it happened.
    ///
    /// The height was once the whole of it, and a height is eight bytes of a
    /// record that is hundreds. Every other byte came back as truth: a state
    /// root, a nonce, a transaction. Swept one bit at a time over a four block
    /// log, 1681 of 1984 flips inside the log answered a height with a block
    /// nobody mined, and the log opened reporting nothing wrong. The header log
    /// beside it has refused that damage since the audit that put its link
    /// check in.
    ///
    /// Two more checks, and both read bytes that are here already. A header
    /// names its transactions through `transactions_root`, so the body answers
    /// to its own header. And a block carries its parent's identifier, which
    /// makes this file the same hash chain the header log is, so the record
    /// after this one has to name it; a block encodes its header first and a
    /// header is a fixed width, so that neighbour costs one seek and
    /// [`HEADER_BYTES`] however large the block is.
    ///
    /// The last record has nothing after it and is checked the other way
    /// instead, which covers its height and its parent and not the rest of it.
    /// The last record is the tip, which a node holds in memory as well and
    /// answers about from there.
    ///
    /// None of it in [`BlockLog::read`], which is asked about a position and
    /// answers about one: it is what `height_of_first` uses to learn where the
    /// log begins, so a height check there would be asking the record to
    /// confirm the number taken from it, and it is what `recover` walks, which
    /// has to stay the cheap open this whole file is built around.
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
        // Before the neighbour, because the neighbour covers the header alone
        // and the header is not the record: with the link check by itself the
        // 1681 wrong answers fell to 572, and every one of those 572 was a
        // byte of a transaction.
        if block.transactions_root() != block.header.transactions_root {
            return Err(StoreError::Unrooted { height });
        }
        if !self.named_by_its_neighbour(index, &block.header) {
            return Err(StoreError::Unlinked { height });
        }
        Ok(Some(block))
    }

    /// Whether the record beside record `index` names it.
    ///
    /// The record after it, which carries its identifier, or the record before
    /// it where there is none after.
    ///
    /// A neighbour that cannot be reached at all is not this record's failure
    /// and does not condemn it. That is the rule this whole file keeps about
    /// the index: it is derived, and one rotted offset in it must cost the one
    /// record it covers and not the sound record next door. The refusal for
    /// that entry is still raised, by whoever asks for the record it names.
    fn named_by_its_neighbour(&self, index: usize, header: &BlockHeader) -> bool {
        if let Ok(Some(next)) = self.header_of(index.saturating_add(1)) {
            return next.previous == header.id();
        }
        // The index entry for the record after this one would not read, which
        // is a fault in a derived file and not in the log. The record is still
        // there, and it begins where this one ends: a number this record's own
        // length prefix already agreed to, since that is what `read_at`
        // checked the record against before asking this. So what was lost is
        // the way of finding the neighbour and not the neighbour, and the
        // check that names every byte of this header is still available.
        //
        // Without this the answer fell through to the record before, which
        // names only this one's `previous` field: forty bytes of a header that
        // is hundreds, with the state root among the rest served as truth. Two
        // faults reach that state, one in the index and one in the log, which
        // is why a sweep that flips one byte at a time never found it.
        if let Ok(Some(next)) = self.header_after(index) {
            return next.previous == header.id();
        }
        let Some(before) = index.checked_sub(1) else {
            return true;
        };
        match self.header_of(before) {
            Ok(Some(earlier)) => header.previous == earlier.id(),
            _ => true,
        }
    }

    /// The header at the front of record `index`, and nothing else off it.
    ///
    /// `None` where there is no such record. A record too short to hold a
    /// header is not a block whatever else is true, and says so through the
    /// decoder rather than through a guess made here.
    fn header_of(&self, index: usize) -> Result<Option<BlockHeader>, StoreError> {
        let Some((start, end)) = self.bounds(index)? else {
            return Ok(None);
        };
        self.header_between(start, end, index)
    }

    /// The header at the front of the record that begins where record `index`
    /// ends, found through the log rather than through the index.
    ///
    /// For the one case the index is no use in and the log still is: an entry
    /// that will not read, with the record it names sitting where it always
    /// was. The end of this record is the start of that one, and how far it
    /// runs is its own length prefix.
    ///
    /// That length says how far the record runs and nothing about the header,
    /// which sits at a fixed offset and is a fixed width. It used to be asked
    /// anyway: a length past the end of the log, or past the largest record
    /// there can be, gave up here and answered nothing. Giving up is not
    /// neutral, because the caller then falls back to the record *before* this
    /// one, which names only its `previous` field, and that is the weak answer
    /// this whole road was built to stop being the answer.
    ///
    /// Measured on three faults rather than two, in
    /// `audit_a_neighbour_that_cannot_be_reached.rs`: a byte of a record's
    /// state root, the index entry for the record after it, and that record's
    /// own length prefix. Asking the length, the node served a block nobody
    /// mined. Not asking it, the header still reads — the read is bounded by
    /// `HEADER_BYTES` and a file too short to hold it fails the read — the
    /// link check sees the flipped byte, and the record is refused.
    fn header_after(&self, index: usize) -> Result<Option<BlockHeader>, StoreError> {
        let after = index.saturating_add(1);
        if after >= self.count {
            return Ok(None);
        }
        let Some((_, start)) = self.bounds(index)? else {
            return Ok(None);
        };
        let mut file = &self.file;
        file.seek(SeekFrom::Start(start))?;
        let mut length = [0u8; 4];
        file.read_exact(&mut length)?;
        let end = start
            .saturating_add(4)
            .saturating_add(u64::from(u32::from_le_bytes(length)));
        self.header_between(start, end, after)
    }

    /// The header at the front of the record between these two offsets.
    fn header_between(
        &self,
        start: u64,
        end: u64,
        index: usize,
    ) -> Result<Option<BlockHeader>, StoreError> {
        let body = usize::try_from(end.saturating_sub(start).saturating_sub(4)).unwrap_or(0);
        let want = body.min(HEADER_BYTES);
        let mut file = &self.file;
        file.seek(SeekFrom::Start(start.saturating_add(4)))?;
        let mut bytes = [0u8; HEADER_BYTES];
        file.read_exact(bytes.get_mut(..want).unwrap_or_default())?;
        BlockHeader::decode(bytes.get(..want).unwrap_or_default())
            .map(Some)
            .map_err(|source| StoreError::Malformed { index, source })
    }

    /// Cuts the log back so that it holds nothing at `height` or past it.
    pub fn keep_below(&mut self, height: u64) -> Result<(), StoreError> {
        self.still_on_its_files()?;
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
        self.still_on_its_files()?;
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
        //
        // Both staged files are on the disk before either is moved, which is
        // what makes the paragraph above a statement about the disk rather
        // than about this program's buffers. Written with `std::fs::write`,
        // the rename below could reach the platter first, and then a machine
        // that stopped came back with the log's name over bytes nothing had
        // written yet.
        //
        // A staging that fails takes its own files with it. What it leaves
        // otherwise is a copy of everything this node keeps, which is up to a
        // gigabyte, sitting on the disk this compaction was trying to free,
        // until some later start opens the log and clears it.
        let staged_log = self.directory.join(format!("{BLOCK_LOG}.part"));
        let staged_index = self.directory.join(format!("{BLOCK_INDEX}.part"));
        let index_path = self.directory.join(BLOCK_INDEX);
        let drop_staged = || {
            let _ = std::fs::remove_file(&staged_log);
            let _ = std::fs::remove_file(&staged_index);
        };
        if let Err(error) = write_and_sync(&staged_log, &kept)
            .and_then(|()| write_and_sync(&staged_index, &written))
        {
            drop_staged();
            return Err(error.into());
        }

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
        let parked = hold(&scratch).and_then(|one| hold(&scratch).map(|two| (one, two)));
        let (held, held_index) = match parked {
            Ok(handles) => handles,
            Err(error) => {
                drop_staged();
                return Err(error);
            }
        };
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
            // Each move is waited for before the next is made. One sync at the
            // end says both names are on the disk once it returns and nothing
            // at all about which arrived first, and which arrived first is the
            // whole of the paragraph above: the index may reach past the log,
            // never the other way about.
            move_into_place(&staged_log, &self.path)?;
            move_into_place(&staged_index, &index_path)?;
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
                // Whichever of the two never moved is a file nothing will ever
                // read, on a disk this was called to make room on.
                drop_staged();
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
        self.still_on_its_files()?;
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
    /// Refuses where this log is no longer on the files it names.
    ///
    /// A compaction that could not put the log back on its own files leaves
    /// the handles on a deleted scratch file. Writing there returns success
    /// and reaches nobody, which is the one failure a node cannot see: it is
    /// the writes that tell it the disk is keeping up.
    ///
    /// Asked by every mutator, which is five of them and used to be one.
    /// `append` was guarded and `clear`, `keep_first`, `keep_from` and
    /// `keep_below` were not, so on a log in that state a truncation reported
    /// success having reached a scratch file while `blocks.log` on disk still
    /// held everything; `keep_below` is the cut a reorganisation makes and
    /// `keep_from` is the trim. The header log beside this one has always
    /// asked the same question of all four of its own, under the same
    /// reasoning, in a function of the same shape.
    ///
    /// It was harmless only because `count` is already nought in that state,
    /// so "holds nothing" happened to be true of what the struct reports.
    /// Nothing held it to staying harmless.
    fn still_on_its_files(&self) -> Result<(), StoreError> {
        if self.usable {
            return Ok(());
        }
        Err(StoreError::Io(std::io::Error::other(
            "this log is not on the files it names: a compaction could not \
             open them again",
        )))
    }

    pub fn append(&mut self, block: &Block) -> Result<(), StoreError> {
        // A compaction that could not put this back on its own files leaves
        // the handles below on a deleted scratch file. Writing there returns
        // success and reaches nobody, which is the one failure a node cannot
        // see: it is the appends that tell it the disk is keeping up.
        self.still_on_its_files()?;

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
    ///
    /// A span shorter than the four bytes that say how long a record is cannot
    /// name one, and is refused here with the rest. It used to pass, and when
    /// it was the last entry and ended where the file ends the start kept it:
    /// `read` then ran off the end of the file asking for those four bytes, and
    /// the `UnexpectedEof` went out as a disk that could not be reached. The
    /// nightly campaign reported it on seven nights out of eight.
    fn bounds(&self, index: usize) -> Result<Option<(u64, u64)>, StoreError> {
        if index >= self.count {
            return Ok(None);
        }
        let checked = |start: u64, end: u64| {
            if end.saturating_sub(start) < LENGTH_BYTES
                || end > self.end
                || end.saturating_sub(start) > max_record_on_disk()
            {
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
            from: 0,
            left: self.end,
        }
    }

    /// The same, starting at the block at `height` rather than at the first.
    ///
    /// For a node that starts from a ledger it wrote: the blocks below it are
    /// already in the ledger, and walking them only to pass over them made a
    /// start read every block a node keeps, which on a node keeping all of
    /// them is a start that grows with the chain.
    ///
    /// Where the record is found is the index's word, and the index is
    /// derived, so the record there is asked for its height before anything
    /// starts from it. If the index cannot say, or says wrongly, this is the
    /// replay from the first record: the caller already passes over what it
    /// does not need, so the answer is slower and never different.
    pub fn replay_from(&self, height: u64) -> Replay<'_> {
        let mut replay = self.replay();
        // Every record is below the height asked for, so there is nothing to
        // read, and a replay from the front would read all of them to say so.
        if height >= self.reaches() {
            replay.index = self.count;
            return replay;
        }
        let Some(index) = height
            .checked_sub(self.first)
            .and_then(|index| usize::try_from(index).ok())
        else {
            return replay;
        };
        if !matches!(self.read_at(height), Ok(Some(_))) {
            return replay;
        }
        if let Ok(Some((start, _))) = self.bounds(index) {
            replay.index = index;
            replay.from = start;
            replay.left = self.end.saturating_sub(start);
        }
        replay
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
        self.still_on_its_files()?;
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
            // A log that does not know where it starts is a log that holds
            // nothing, which is what `HeaderLog::join` answers to the same
            // question. Reporting a height its own records disagree with is
            // the one answer that loses blocks.
            Ok(None) => return Ok(self.forget_what_it_cannot_place()),
            Ok(Some(first)) => self.first = first,
            Err(_) => return self.rebuild(),
        }
        Ok(Recovered {
            blocks: count,
            discarded_bytes: 0,
            left_in_place: 0,
            unreadable: None,
            blocks_set_aside: 0,
        })
    }

    /// Reads back the height the log starts at, if the log agrees with itself
    /// about it.
    ///
    /// One record decoded when a node starts, which is what it costs not to
    /// keep this written down anywhere it could disagree with the log itself.
    /// Two records, because one cannot be asked to confirm the number it is
    /// the source of and its neighbour can: the record after it carries its
    /// height and its identifier, so a byte changed anywhere in record zero
    /// moves one of the two.
    ///
    /// `None` is the log saying it does not know where it starts. It was the
    /// height of record zero and nothing else, so one bit of that field was
    /// enough to move the whole log: a six block log whose first record
    /// claimed height sixteen million opened reporting nothing wrong, denied
    /// holding the block at zero it was holding, and answered `Unlinked` for
    /// every height it claimed. `cairn-net`'s restart then read
    /// `first_height() > start` as a node that had joined above its disk,
    /// skipped the replay, and truncated the log: every block deleted, with
    /// `refused` reporting nought.
    ///
    /// `HeaderLog::head` is this function in the sibling file and has asked
    /// this since it was written. Its doc narrates the same failure about the
    /// log it was written for. This is the one it was not carried to.
    fn height_of_first(&self) -> Result<Option<u64>, StoreError> {
        if self.count == 0 {
            return Ok(Some(0));
        }
        let Some(head) = self.read(0)? else {
            return Ok(Some(0));
        };
        // A record one that will not read says nothing about record zero, and
        // is a different fault with its own answer: the index and the log
        // disagreeing about a length is reported where the read happens, by
        // `Mismatched`, and setting the whole log aside for it would take an
        // index fault and make it look like damage to the chain. So the check
        // is skipped rather than failed, and record zero is trusted as it was
        // before. What that gives up is the case where record zero and record
        // one are both damaged, which one flipped bit cannot produce.
        let Ok(Some(next)) = self.read(1) else {
            return Ok(Some(head.header.height));
        };
        if next.header.height == head.header.height.saturating_add(1)
            && next.header.previous == head.id()
        {
            Ok(Some(head.header.height))
        } else {
            Ok(None)
        }
    }

    /// Answers holding nothing, for a log whose records disagree about where
    /// it starts.
    ///
    /// Nothing is cut and nothing is written. The index is emptied in memory
    /// so no height is answered from a first record the log does not trust,
    /// and the bytes stay on the disk: a person can look at record zero, and a
    /// node that fetches the chain again writes over them.
    ///
    /// The shape `HeaderLog::join` uses for the same answer, which sets its
    /// count and first to nought and leaves the file alone.
    fn forget_what_it_cannot_place(&mut self) -> Recovered {
        let set_aside = self.count;
        self.count = 0;
        self.first = 0;
        self.end = 0;
        Recovered {
            blocks: 0,
            discarded_bytes: 0,
            left_in_place: 0,
            unreadable: None,
            blocks_set_aside: set_aside,
        }
    }

    /// Reads every record again, for a replay that met one it could not read.
    ///
    /// The start reads sixteen bytes of the log and decodes two records, so a
    /// record damaged in the middle of a log whose index is in line is first
    /// met by the replay, not by recovery. What recovery does with the same
    /// record is leave it and everything after it on the disk, unread, and
    /// this is that, asked for by whoever met it: the walk stops where the
    /// replay did, the index is written again up to there, and the bytes past
    /// it stay where they are until the log grows over them.
    pub fn read_again(&mut self) -> Result<Recovered, StoreError> {
        self.still_on_its_files()?;
        self.rebuild()
    }

    /// Reads every record the log holds and writes the index out again from
    /// what it found.
    fn rebuild(&mut self) -> Result<Recovered, StoreError> {
        let total = self.file.metadata()?.len();
        let walk = self.walk(0, 0, total)?;
        self.count = walk.ends.len();
        self.end = walk.offset;
        // Recovery is the one part of a start that writes, and this is the
        // write. A node whose index was lost cannot open on a disk with
        // nothing left, and what it used to say about that was "could not
        // reach the block log", which is the one file that is fine.
        self.write_offsets(&walk.ends, 0)
            .map_err(index_not_written)?;
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
        self.write_offsets(&walk.ends, from)
            .map_err(index_not_written)?;
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
        Self::walk_from(BufReader::new(file), from, index_from, total)
    }

    /// The same walk over any reader, so what it makes of a read the disk
    /// refuses can be asked without a disk that refuses.
    fn walk_from(
        mut reader: impl Read,
        from: u64,
        index_from: usize,
        total: u64,
    ) -> Result<Walk, StoreError> {
        let mut walk = Walk {
            ends: Vec::new(),
            offset: from,
            unreadable: None,
        };
        loop {
            let index = index_from.saturating_add(walk.ends.len());
            let mut header = [0u8; 4];
            // The file ending is the one failure that means the file ended.
            // Any other is the disk refusing, and was read as the end too:
            // `settle` then cut the log there and called the cut an
            // interrupted write, so one refused read deleted every block
            // after it. It goes back as the refusal it is, the way the seek
            // above already did.
            if let Err(error) = reader.read_exact(&mut header) {
                if error.kind() == ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(error.into());
            }
            let declared = usize::try_from(u32::from_le_bytes(header)).unwrap_or(usize::MAX);
            let left = total.saturating_sub(walk.offset).saturating_sub(4);
            if declared > MAX_RECORD_BYTES {
                // Longer than any block the rules allow, so this is not a
                // length this process wrote, wherever in the file it sits.
                // Nothing is reserved for it and nothing is cut for it.
                //
                // Asked before the one below, and the order is the whole of
                // it. That one reads a length overshooting the end of the file
                // as a write cut short, which is true of the last record and
                // was standing in for every record: for any earlier one the
                // bytes after it are whole records, and `settle` deletes all
                // of them because nothing set `unreadable`. One flipped bit in
                // the first record's length prefix emptied a six block log,
                // synced, and the operator read that some bytes of an
                // unfinished write had been dropped. Twenty one of the
                // prefix's thirty two bits do it.
                walk.unreadable = Some(index);
                break;
            }
            if u64::try_from(declared).unwrap_or(u64::MAX) > left {
                // A length this process could have written, reaching past the
                // end of the file. That reads as a write cut short, and it is
                // what one leaves — and it is also what one flipped bit leaves
                // in a prefix anywhere in the file, which is the same sentence
                // that was wrong above and is wrong here for the same reason.
                //
                // Moving the ceiling was not enough. `MAX_RECORD_BYTES` is four
                // megabytes against a block ceiling of a hundred and twenty
                // eight kilobytes, so a flip landing anywhere between the bytes
                // that remain and four megabytes was still read as a tail:
                // eleven of the prefix's thirty two bits went on emptying a six
                // block log after the ceiling was asked first.
                //
                // So neither branch cuts. A length is a number off a disk, and
                // whether it looks like one this process wrote says nothing
                // about whether a record follows it. The log does not delete
                // bytes it cannot account for: it says so, leaves them, and
                // `append` writes over them from the last whole record.
                //
                // What is still cut is the one thing that is not a length at
                // all: a file ending inside the four bytes that say how long a
                // record is, which is at most three bytes and cannot be hiding
                // a record.
                walk.unreadable = Some(index);
                break;
            }
            let mut body = vec![0u8; declared];
            if let Err(error) = reader.read_exact(&mut body) {
                if error.kind() == ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(error.into());
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
        let Some(first) = self.height_of_first()? else {
            return Ok(self.forget_what_it_cannot_place());
        };
        self.first = first;
        Ok(Recovered {
            blocks: self.count,
            discarded_bytes: cut,
            left_in_place: beyond.saturating_sub(cut),
            unreadable,
            blocks_set_aside: 0,
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
    /// Where the first record read begins: nought, or where
    /// [`BlockLog::replay_from`] found the record it was asked for.
    from: u64,
    /// Bytes of records still ahead of the cursor.
    ///
    /// The second of the two questions a length off a disk has to answer, and
    /// the one this walk was not asking. `BlockLog::read` asks it against the
    /// index and `Walk` against what is left in the file, under twenty five
    /// lines saying why a ceiling alone is not enough: `MAX_RECORD_BYTES` is
    /// four megabytes against a block ceiling of a hundred and twenty eight
    /// kilobytes, so a flipped bit landing anywhere in that gap passes the
    /// ceiling. Here it passed the ceiling and was then reserved for.
    left: u64,
}

impl Iterator for Replay<'_> {
    type Item = Result<Block, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total {
            return None;
        }
        if !self.started {
            self.started = true;
            if let Err(error) = self.reader.seek(SeekFrom::Start(self.from)) {
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
        self.left = self.left.saturating_sub(4);
        if declared > MAX_RECORD_BYTES {
            let index = self.index;
            self.index = self.total;
            return Some(Err(StoreError::RecordTooLarge { index, declared }));
        }
        // And against what is left, which is the guard the other two readers
        // of a record length carry and this one did not. Without it a prefix
        // saying four megabytes was reserved for in full and the short read
        // that followed reported a truncated file, so the walk paid the
        // allocation to learn something the length had already said.
        if u64::try_from(declared).unwrap_or(u64::MAX) > self.left {
            let index = self.index;
            let left = self.left;
            self.index = self.total;
            return Some(Err(StoreError::RecordPastTheEnd {
                index,
                declared,
                left,
            }));
        }
        self.left = self
            .left
            .saturating_sub(u64::try_from(declared).unwrap_or(u64::MAX));
        let mut body = vec![0u8; declared];
        if let Err(error) = self.reader.read_exact(&mut body) {
            self.index = self.total;
            return Some(Err(error.into()));
        }
        let index = self.index;
        match Block::decode(&body) {
            Ok(block) => {
                self.index = self.index.saturating_add(1);
                Some(Ok(block))
            }
            Err(source) => {
                // Stops, like the four above it. This one used to carry on,
                // and it is the only error this walk exists to find: the
                // others are a seek, a short read and a length past the
                // ceiling, none of which is what a corrupted record looks
                // like. Six records with the third one's body replaced
                // replayed as heights nought, one, three, four and five,
                // which is the chain with a hole in it that the doc on this
                // type names as the thing it cannot produce.
                //
                // The reason is the same for all five. A record that will not
                // decode means the cursor is no longer where the next record
                // begins, so everything read after it is read at an offset
                // nothing vouches for. A length prefix shortened by seven
                // bytes gave three reservations of up to four megabytes each
                // from a misaligned cursor before anything stopped.
                self.index = self.total;
                Some(Err(StoreError::Malformed { index, source }))
            }
        }
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
    // A line and no more. What is in there is a process identifier written
    // for this message, and it was read whole: a lock file of any length was
    // put into memory before anything was said about it.
    let mut read = Vec::new();
    if let Ok(file) = File::open(path) {
        let _ = file.take(HOLDER_BYTES).read_to_end(&mut read);
    }
    let holder = String::from_utf8_lossy(&read);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::{self, Read};

    use cairn_ledger::genesis;
    use cairn_ledger::note::NetworkId;
    use cairn_primitives::codec::Encode;

    use super::BlockLog;

    /// A disk that hands back `bytes` and then refuses every read after them.
    struct Refusing {
        bytes: io::Cursor<Vec<u8>>,
    }

    impl Read for Refusing {
        fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
            match self.bytes.read(into)? {
                0 => Err(io::Error::other("the disk refused the read")),
                read => Ok(read),
            }
        }
    }

    /// One record as the log frames it: its length, then the block.
    fn record() -> Vec<u8> {
        let block = genesis::block(NetworkId::DEVNET).unwrap().encode();
        let mut framed = u32::try_from(block.len()).unwrap().to_le_bytes().to_vec();
        framed.extend_from_slice(&block);
        framed
    }

    /// A read the disk refused is not the end of the file.
    ///
    /// The walk that rebuilds the index read every failed read as the file
    /// running out, and a walk that ran out of file has `settle` cut the log
    /// where it stopped, sync the cut, and report the bytes as an interrupted
    /// write. So one refused read while a node started deleted every block
    /// after it and told the operator a write had been cut short. Every log
    /// the tests walked was a real file that read, so a walk that could not
    /// tell a disk that failed from a file that ended passed.
    #[test]
    fn a_read_the_disk_refused_is_not_taken_for_the_end_of_the_file() {
        let whole = record();
        // Past what is handed back, as a file the disk will not read to its
        // end still is.
        let total = u64::try_from(whole.len() * 3).unwrap();

        let ended = BlockLog::walk_from(io::Cursor::new(whole.clone()), 0, 0, total).unwrap();
        assert_eq!(
            ended.ends.len(),
            1,
            "one whole record, then the end of the file"
        );

        // Refused where the next record's length would be, and then in the
        // middle of a record's body: the walk reads both.
        let mut cut_in_the_body = whole.clone();
        cut_in_the_body.extend_from_slice(whole.get(..8).unwrap());
        for (bytes, place) in [
            (whole.clone(), "the next record's length"),
            (cut_in_the_body, "a record's body"),
        ] {
            let refused = BlockLog::walk_from(
                Refusing {
                    bytes: io::Cursor::new(bytes),
                },
                0,
                0,
                total,
            );
            assert!(
                refused.is_err(),
                "a read the disk refused at {place} was taken for the end of the file, which \
                 has the log cut there and the cut reported as an interrupted write"
            );
        }
    }
}

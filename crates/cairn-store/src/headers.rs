//! Every header a node has accepted, kept apart from the blocks.
//!
//! A node stops keeping blocks it has already applied, because the ledger they
//! add up to is a fixed size and the blocks are not. Headers are different:
//! they are what a newcomer is shown to settle which chain carries the most
//! work, and showing one means having it. At 182 bytes a header that is
//! 95.7 MB a year, and the forest in [`crate::header_tree`] is 64 bytes a
//! header more: 129 MB a year altogether, against 50 GB a year for the same
//! promise in Bitcoin, so every node can carry it rather than the few that
//! volunteer to.
//!
//! The two halves are named apart because this file used to charge the header
//! alone with the whole 129 MB, which is the published figure for both. A
//! header is 95.7 MB a year and nothing here holds the other third, so a
//! reader adding this file's cost to the forest's got a third more than a node
//! actually pays. `cairn-explorer/tests/published_figures.rs` holds the paper
//! to the same split.
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
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cairn_ledger::block::BlockHeader;
use cairn_primitives::codec::{Decode, Encode};

use crate::StoreError;

/// A header with nothing in it, for measuring what one encodes to.
///
/// Every field is fixed width, so any header answers the question and this is
/// the one that needs no chain to exist.
fn a_header() -> BlockHeader {
    BlockHeader {
        version: 0,
        network: cairn_ledger::note::NetworkId::MAINNET,
        height: 0,
        previous: cairn_primitives::Hash32::ZERO,
        transactions_root: cairn_primitives::Hash32::ZERO,
        state_root: cairn_primitives::Hash32::ZERO,
        history: cairn_primitives::Hash32::ZERO,
        timestamp: 0,
        difficulty: 0,
        total_work: 0,
        nonce: 0,
    }
}

/// The name the header log takes inside a node's directory.
pub const HEADER_LOG: &str = "headers.log";

/// Bytes one header takes on disk, which is what it takes on the wire.
///
/// The log has no record boundaries: a header is found by multiplying its
/// index by this, so a header that stopped being this size would not be read
/// wrongly at one place, it would be read wrongly everywhere after the first.
/// Nothing about that is loud. The file is still the right shape, every record
/// still decodes into a plausible header, and a node reads a chain of nonsense
/// out of its own disk.
///
/// So it is taken from the header itself rather than written out, and checked
/// against what this build actually encodes at every open rather than only in
/// a test that has to be run. Adding a field to
/// [`BlockHeader`] and forgetting this number stops a node from starting
/// instead of teaching it a chain that was never mined.
pub const HEADER_BYTES: usize = BlockHeader::ENCODED_BYTES;

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
    /// Whether the handle above is still on the file this log names.
    ///
    /// True for the whole of an ordinary life. It goes false in one place: a
    /// merge that let go of the handle and could not get it back. Writes then
    /// have to refuse, because the alternative is appends that land on a
    /// deleted scratch file and report success, and it is the appends that
    /// tell a node its disk is keeping up.
    usable: bool,
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
        let found = a_header().encode().len();
        if found != HEADER_BYTES {
            return Err(StoreError::HeaderSizeChanged { found });
        }

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
            usable: true,
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

    /// Puts the records of `front` before this log's own, leaving one run.
    ///
    /// For a node that joined a chain and has collected the headers from
    /// before it arrived. It happens once in such a node's life.
    ///
    /// Written to a file beside this one and moved into place. It used to be
    /// done here, in place: the log was emptied and refilled, so a machine
    /// that stopped in the middle left a header log holding a prefix of the
    /// run being merged and nothing that knew it. The next start found headers
    /// stopping below the oldest block held, deleted every one of them, and
    /// said nothing at all.
    ///
    /// Streamed rather than gathered, for the same reason a replay reads one
    /// block at a time. The merge is every header a node holds, which is
    /// 95.7 MB a year and around 290 MB after thirty; holding them all to
    /// write them straight back out made the largest allocation the process
    /// ever performs out of the one cost this whole design exists to keep
    /// flat.
    ///
    /// The two runs have to meet exactly: `front` ends where this log begins.
    /// Anything else is refused before a byte is written, where it used to be
    /// found halfway through the refill.
    ///
    /// Nothing left behind of a merge that fails, and nothing changed: the
    /// staged file goes, both logs stand where they were, and the caller is
    /// told which half refused.
    pub fn join(&mut self, front: &HeaderLog) -> Result<(), JoinFailed> {
        self.still_on_its_file()?;
        front.still_on_its_file()?;
        if front.is_empty() {
            return Ok(());
        }
        if self.count > 0 && front.reaches() != self.first {
            return Err(StoreError::OutOfOrder {
                expected: self.first,
                found: front.reaches(),
            }
            .into());
        }
        let joined_first = front.first;
        let joined_count = front.count.saturating_add(self.count);

        let staged = crate::staged_beside(&self.path);
        if let Err(error) = self.stage_join(front, &staged) {
            let _ = std::fs::remove_file(&staged);
            return Err(error);
        }

        // The handle is let go of before the move, because Windows will not
        // rename over an open file. It points at a scratch file meanwhile,
        // since a `File` closes when it is dropped and there is no other way
        // to say so.
        let scratch = crate::beside(&self.path, ".hold");
        let parked = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&scratch);
        let parked = match parked {
            Ok(file) => file,
            Err(error) => {
                let _ = std::fs::remove_file(&staged);
                return Err(StoreError::from(error).into());
            }
        };
        self.file = parked;

        // From here the handle is on a scratch file, so nothing below may
        // leave with `?`: what this struct says about itself and what it can
        // read have parted company until they are put back together.
        // The rename on its own, told apart from the wait for it. A rename
        // that happened and was not waited for has still happened, and what
        // this struct says about itself has to describe the file that is now
        // there or every read is at the wrong offset.
        let moved = std::fs::rename(&staged, &self.path);
        let reopened = OpenOptions::new().read(true).write(true).open(&self.path);
        let _ = std::fs::remove_file(&staged);
        let _ = std::fs::remove_file(&scratch);
        match (moved, reopened) {
            (Ok(()), Ok(file)) => {
                self.file = file;
                self.first = joined_first;
                self.count = joined_count;
                crate::sync_the_directory_of(&self.path).map_err(StoreError::from)?;
                Ok(())
            }
            // The move is what changes the file, so a move that did not happen
            // leaves the log this handle was on, exactly as it was. Nothing
            // here is lost but the merge, which is asked for again.
            (Err(error), Ok(file)) => {
                self.file = file;
                Err(StoreError::from(error).into())
            }
            // Whatever is on the disk now, this handle is not on it and there
            // is no saying which of the two files it would have been. Appends
            // must not go on succeeding into a scratch file the next start
            // deletes, which is a node writing no headers down and being told
            // nothing about it.
            (_, Err(error)) => {
                self.count = 0;
                self.first = 0;
                self.usable = false;
                Err(StoreError::from(error).into())
            }
        }
    }

    /// Writes the two runs into `staged`, oldest record first.
    ///
    /// One header in hand at a time. This used to be a vector of every header
    /// the node holds, which is 95.7 MB a year and around 290 MB after thirty,
    /// built to be written straight back out again.
    ///
    /// Every record goes through the checked read on its way, so a byte that
    /// has changed anywhere in either log stops the merge here, with the
    /// staged file thrown away and both logs exactly as they were. That check
    /// is the reason this is not a copy of bytes: the header log is the one
    /// file a node serves without anything having verified it, and a merge
    /// that carried rot across would be writing it back down as truth.
    fn stage_join(&self, front: &HeaderLog, staged: &Path) -> Result<(), JoinFailed> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(staged)
            .map_err(StoreError::from)?;
        let mut out = BufWriter::new(file);
        for source in [front, self] {
            for height in source.first_height()..source.reaches() {
                let body = source.one(height)?.encode();
                if body.len() != HEADER_BYTES {
                    return Err(StoreError::BlockTooLarge.into());
                }
                out.write_all(&body).map_err(StoreError::from)?;
            }
        }
        let file = out
            .into_inner()
            .map_err(|error| StoreError::Io(error.into_error()))?;
        // Waited for before the move, or the name can reach the disk ahead of
        // what it names, and the log comes back at its full length holding
        // whatever those blocks held before.
        file.sync_all().map_err(StoreError::from)?;
        Ok(())
    }

    /// One record this log has already said it holds.
    ///
    /// So nothing here is an absence. A store that answers `None` inside the
    /// run it says it holds is disagreeing with itself, which is the same news
    /// as a refusal and belongs in the same channel.
    fn one(&self, height: u64) -> Result<BlockHeader, JoinFailed> {
        match self.read_at(height) {
            Ok(Some(header)) => Ok(header),
            Ok(None) => Err(JoinFailed::Read {
                height,
                source: StoreError::Io(std::io::Error::other(
                    "the log says it holds this record and produced nothing",
                )),
            }),
            Err(source) => Err(JoinFailed::Read { height, source }),
        }
    }

    /// Refuses where this log is no longer on the file it names.
    fn still_on_its_file(&self) -> Result<(), StoreError> {
        if self.usable {
            return Ok(());
        }
        Err(StoreError::Io(std::io::Error::other(
            "this header log is not on the file it names: a merge could not open \
             it again",
        )))
    }

    /// Adds one header to the end.
    ///
    /// A header that does not follow on from the last is refused. Positions
    /// here are heights, and a log where the two drifted apart would answer
    /// about the wrong header without any way to notice.
    pub fn append(&mut self, header: &BlockHeader) -> Result<(), StoreError> {
        self.still_on_its_file()?;
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
        self.still_on_its_file()?;
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
        self.still_on_its_file()?;
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

/// What stopped a merge of two header logs.
///
/// The two halves are told apart because a node says them in different words
/// and to different ends. A record it holds and cannot read back is its own
/// disk giving an answer it will not stand behind, and it is named by height
/// so somebody can go and look at it. A write it could not make is the disk
/// refusing to take something, which is the channel that says a node has
/// stopped keeping up with itself.
#[derive(Debug, thiserror::Error)]
pub enum JoinFailed {
    /// A record one of the two logs said it held and would not give back.
    #[error("the header at height {height} would not read back: {source}")]
    Read {
        height: u64,
        #[source]
        source: StoreError,
    },
    /// The merged log could not be put on the disk.
    #[error(transparent)]
    Write(#[from] StoreError),
}

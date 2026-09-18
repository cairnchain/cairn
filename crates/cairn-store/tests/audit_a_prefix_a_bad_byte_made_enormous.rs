//! What a log deletes when a length prefix goes wrong, and where.
//!
//! A walk of the log reads a four byte length and then that many bytes. Two
//! things can be wrong with the length, and they call for opposite answers. A
//! write cut short leaves a length reaching past the end of the file, and the
//! bytes after the last whole record are not a record: cutting them is right,
//! and it is what lets a node that lost power mid-append start again. A length
//! a bad byte made enormous looks the same from the prefix alone.
//!
//! The walk read the second as the first, and the note beside it said so in as
//! many words: "a write cut short is exactly this shape, and so is a length
//! prefix a bad byte made enormous". True of the **last** record, which is
//! what that note was written about. For any earlier record the bytes after it
//! are whole records, and nothing marked the walk as having found damage, so
//! everything past the bad prefix was deleted and synced.
//!
//! One flipped bit in the first record's prefix therefore emptied the whole
//! log, and the operator was told that some bytes of an unfinished write had
//! been dropped. For an archivist, which this crate names as the one role that
//! cannot ask for a block again, that line is printed over the deletion of its
//! archive.
//!
//! So the questions are asked the other way round. A length longer than any
//! block the rules allow is not one this process wrote, wherever it sits, and
//! nothing is cut for it. Only a length this process could have written, which
//! reaches past the end of the file, is a tail.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_store::{BlockLog, BLOCK_INDEX, BLOCK_LOG};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const BLOCKS: usize = 6;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-prefix-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn chain(count: usize) -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            block
        })
        .collect()
}

/// Where each record starts, read the way the walk reads them.
fn records(bytes: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut at = 0usize;
    while at + 4 <= bytes.len() {
        starts.push(at);
        let declared = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + declared;
    }
    starts
}

fn put(path: &Path, at: u64, value: &[u8]) {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(value).unwrap();
}

/// A log of `BLOCKS` records, with the index removed so the start has to walk.
///
/// The index going missing is what a crash between the two writes leaves, and
/// it is the ordinary road into this walk.
fn a_log_that_must_be_walked(name: &str) -> (PathBuf, Vec<usize>, u64) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &chain(BLOCKS) {
            log.append(block).unwrap();
        }
    }
    let path = directory.join(BLOCK_LOG);
    let bytes = std::fs::read(&path).unwrap();
    let starts = records(&bytes);
    assert_eq!(
        starts.len(),
        BLOCKS,
        "the fixture is a log of whole records"
    );
    let _ = std::fs::remove_file(directory.join(BLOCK_INDEX));
    (directory, starts, bytes.len() as u64)
}

/// A bad prefix in the first record does not take the rest of the log with it.
#[test]
fn a_prefix_no_process_wrote_is_damage_and_not_a_tail() {
    let (directory, starts, size) = a_log_that_must_be_walked("first");

    // The top bit of the length, which is the shape a single flipped bit
    // takes. It is longer than any block the rules allow.
    put(&directory.join(BLOCK_LOG), starts[0] as u64 + 3, &[0x80]);

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        recovered.discarded_bytes, 0,
        "a length no process here wrote is damage, and nothing is cut for damage. \
         {} of the {size} bytes in this log were deleted and synced, and every record \
         after the bad prefix was a whole one",
        recovered.discarded_bytes
    );
    assert!(
        recovered.unreadable.is_some(),
        "and it has to be reported as damage rather than as an unfinished write, because \
         an operator told bytes of a write were dropped goes looking for nothing"
    );
    assert_eq!(
        recovered.left_in_place, size,
        "the bytes stay on the disk, so a start that misread them once can read them back"
    );
    drop(log);

    let still_there = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
    assert_eq!(still_there, size, "the file is the size it was");

    let _ = std::fs::remove_dir_all(&directory);
}

/// A write cut short is left where it is, like every other length the log
/// cannot account for.
///
/// This used to be cut, on the reasoning that the bytes after the last whole
/// record are not a record. True of a tail. Also true of nothing, because one
/// flipped bit produces the same shape in a prefix anywhere in the file, and
/// there the bytes after it are whole records. Neither branch cuts now, and
/// what that costs is the word: an interrupted append is reported as bytes
/// left in place rather than as bytes dropped. Nothing is lost by it, because
/// `append` truncates to the last whole record before it writes.
#[test]
fn a_write_cut_short_is_left_where_it_is() {
    let (directory, starts, size) = a_log_that_must_be_walked("tail");

    // Half of the last record, which is what an interrupted append leaves.
    let last = *starts.last().unwrap() as u64;
    let keep = last + (size - last) / 2;
    {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(directory.join(BLOCK_LOG))
            .unwrap();
        file.set_len(keep).unwrap();
    }

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        recovered.blocks,
        BLOCKS - 1,
        "every whole record before the torn one is kept, which is what starting means"
    );
    assert_eq!(
        recovered.discarded_bytes, 0,
        "and nothing is deleted for a number this log cannot account for"
    );
    assert!(
        recovered.left_in_place > 0,
        "the bytes are left where a reader can still see them"
    );
    drop(log);

    let _ = std::fs::remove_dir_all(&directory);
}

/// Every single bit of every length prefix, and none of them empties the log.
///
/// The first test here flips one bit, and the bit it flips is the top one,
/// which is inside the range the first repair caught. That repair asked the
/// ceiling before the overshoot, and `MAX_RECORD_BYTES` is four megabytes
/// against a block ceiling of a hundred and twenty eight kilobytes, so eleven
/// of the thirty two bits still produced a length that looked like one this
/// process wrote and reached past the end of the file. All eleven went on
/// deleting every whole record behind them.
///
/// A test that flips one bit measures one bit. This is what the audit that
/// found it did, and what it should have been in the first place.
#[test]
fn no_single_flipped_bit_in_any_prefix_deletes_a_whole_record() {
    for record in 0..BLOCKS {
        for bit in 0..32u32 {
            let name = format!("sweep-{record}-{bit}");
            let (directory, starts, size) = a_log_that_must_be_walked(&name);
            let at = starts[record] as u64 + u64::from(bit / 8);
            let mut byte = [0u8; 1];
            {
                use std::io::{Read, Seek, SeekFrom};
                let mut file = std::fs::File::open(directory.join(BLOCK_LOG)).unwrap();
                file.seek(SeekFrom::Start(at)).unwrap();
                file.read_exact(&mut byte).unwrap();
            }
            byte[0] ^= 1 << (bit % 8);
            put(&directory.join(BLOCK_LOG), at, &byte);

            let (log, recovered) = BlockLog::open(&directory).unwrap();
            assert_eq!(
                recovered.discarded_bytes, 0,
                "record {record}, bit {bit}: {} of the {size} bytes in this log were deleted \
                 and synced. Every record after the damaged prefix was a whole one, and the \
                 operator is told that bytes of an unfinished write were dropped",
                recovered.discarded_bytes
            );
            drop(log);

            let still_there = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
            assert_eq!(
                still_there, size,
                "record {record}, bit {bit}: the file is {still_there} bytes and was {size}"
            );
            let _ = std::fs::remove_dir_all(&directory);
        }
    }
}

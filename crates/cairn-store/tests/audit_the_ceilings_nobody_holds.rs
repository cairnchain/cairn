//! Two guards on `MAX_RECORD_BYTES` that no test in the crate could fail on.
//!
//! The ceiling is checked in four places: `walk`, `read`, `bounds` and
//! `Replay::next`. The first two are held by tests. Deleting the check from
//! `Replay::next` leaves the suite green, and the replay is the one path a
//! node walks at every start without the index: a length prefix past the
//! ceiling in a record whose index entry is sound is never seen by the open
//! and is met first by the replay, which then reserves what the prefix says.
//! Deleting the check from `bounds` also leaves the suite green, and there it
//! costs nothing, because `read` and `header_of` reserve from the record's
//! own prefix and never from the pair of offsets.
//!
//! The first is held here. The second is recorded here as a guard with no
//! consequence, so that whoever next reads `bounds` knows which of its three
//! conditions is load bearing.
//!
//! And a third thing, found by reading those four places beside each other
//! rather than one at a time. A length off a disk has two questions to
//! answer: whether it is a length this process could have written, which is
//! the ceiling, and whether a record can actually follow it, which is what is
//! left. `read` asks the second against the index and `Walk` against the
//! file; `Replay::next` asked only the ceiling and then reserved what the
//! prefix said. `MAX_RECORD_BYTES` is four megabytes against a block ceiling
//! of a hundred and twenty eight kilobytes, so the gap a flipped bit can land
//! in and still clear the ceiling is most of the range. Held below.
//!
//! And a fourth thing, which the tests above could not have found because of
//! how they are built. **On a log smaller than the ceiling the two questions
//! have the same answer**: no length clearing four megabytes fits in a file of
//! a thousand bytes, so whichever is asked first, the other would have said
//! the same. Every fixture in this crate was that small, and the ceiling's own
//! position was therefore measured nowhere: moved by one, or read as equality,
//! the whole suite agreed.
//!
//! Real logs are not that small. A node's block log is the chain, so the case
//! that matters — a prefix over the ceiling with room in the file behind it —
//! is the case only a real log has, and read as equality every such log takes
//! a four megabyte record a flipped bit invented. The last test here builds a
//! log past the ceiling and asks the three readers of a length on both sides
//! of it.

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
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_store::{BlockLog, StoreError, BLOCK_INDEX, BLOCK_LOG, MAX_RECORD_BYTES};

const NOW: u64 = 2_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-ceilings-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn chain(count: usize) -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[8u8; 32]);
    let mut state = LedgerState::archiving();
    let mut clock = 1_000u64;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            block
        })
        .collect()
}

fn put(path: &Path, at: u64, value: &[u8]) {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(value).unwrap();
}

/// A middle record's length prefix past the ceiling, with the index sound.
///
/// The open reads sixteen bytes and record zero, so it sees nothing. The
/// replay is where the prefix is met, and it has to be refused by name there:
/// a reader that found out by trying would have reserved four gigabytes on
/// the way, on a phone.
#[test]
fn the_replay_refuses_a_length_past_the_ceiling_by_name() {
    let blocks = chain(6);
    let directory = scratch("replay");
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }
    let index = std::fs::read(directory.join(BLOCK_INDEX)).unwrap();
    let start_of_two = u64::from_le_bytes(index[8..16].try_into().unwrap());
    put(
        &directory.join(BLOCK_LOG),
        start_of_two,
        &u32::MAX.to_le_bytes(),
    );

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 6, "the open never looks at record two");
    assert_eq!(recovered.unreadable, None);

    let replayed: Vec<Result<Block, StoreError>> = log.replay().collect();
    assert_eq!(
        replayed.len(),
        3,
        "two records, the refusal, and then nothing"
    );
    assert!(replayed[0].is_ok());
    assert!(replayed[1].is_ok());
    assert!(
        matches!(
            replayed[2],
            Err(StoreError::RecordTooLarge {
                index: 2,
                declared
            }) if declared == u32::MAX as usize
        ),
        "the replay met a 4 GiB prefix and answered {:?}",
        replayed[2].as_ref().err().map(ToString::to_string)
    );
    // And the single read says the same, which is the check the suite holds.
    assert!(matches!(
        log.read(2),
        Err(StoreError::RecordTooLarge { index: 2, .. })
    ));
    let _ = std::fs::remove_dir_all(&directory);
}

/// A pair of index offsets that span more than a record can, inside a log
/// long enough to hold the span.
///
/// `bounds` refuses this as `Misindexed`. Without that condition `read`
/// refuses it as `Mismatched` after reading four bytes, and `header_of` reads
/// at most a header. So the condition changes the name of a refusal and
/// reserves nothing either way; it is measured here so that the difference is
/// written down rather than assumed.
#[test]
fn a_span_past_the_ceiling_is_refused_by_bounds_and_would_be_refused_without_it() {
    // A log longer than the ceiling, made of one real record and sparse zeros
    // past it, so the span can lie inside the file.
    let blocks = chain(2);
    let directory = scratch("span");
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        log.append(&blocks[0]).unwrap();
        log.append(&blocks[1]).unwrap();
    }
    let path = directory.join(BLOCK_LOG);
    let ceiling = cairn_store::MAX_RECORD_BYTES as u64 + 4;
    let index = std::fs::read(directory.join(BLOCK_INDEX)).unwrap();
    let end_of_zero = u64::from_le_bytes(index[0..8].try_into().unwrap());
    // Record one is now said to run from the end of record zero to one byte
    // past the widest record allowed, and the file is made long enough.
    let absurd_end = end_of_zero + ceiling + 1;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(absurd_end)
        .unwrap();
    put(&directory.join(BLOCK_INDEX), 8, &absurd_end.to_le_bytes());

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        recovered.blocks, 2,
        "the last offset equals the file length"
    );
    let answer = log.read(1);
    println!(
        "PROBE: a span of {} bytes inside a {} byte log: {:?}",
        ceiling + 1,
        absurd_end,
        answer.as_ref().err().map(ToString::to_string)
    );
    assert!(
        matches!(answer, Err(StoreError::Misindexed { index: 1, .. })),
        "refused by name, before the record's own prefix is read"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The other guard on a length, which two of the three readers carry.
///
/// A length off a disk has two questions to answer, not one. The ceiling says
/// whether it is a length this process could have written. What is left in
/// the log says whether a record can actually follow it. `BlockLog::read`
/// asks the second against the index and `Walk` asks it against the file,
/// under twenty five lines saying why the ceiling alone is not enough:
/// `MAX_RECORD_BYTES` is four megabytes against a block ceiling of a hundred
/// and twenty eight kilobytes, so a flipped bit landing anywhere in that gap
/// clears the ceiling.
///
/// `Replay::next` asked only the first, and then reserved what the prefix
/// said. A megabyte here, four at the ceiling, on the one path a node walks
/// at every start.
///
/// The assertion is the name and not the failure. Without the guard this
/// still ends the replay, because the short read that follows fails, so a
/// test asking only "does the replay stop" passes either way. What changes is
/// whether the allocation was spent first and whether the answer says which
/// of the two things went wrong.
#[test]
fn the_replay_refuses_a_length_reaching_past_the_end_by_name() {
    // Under the ceiling and far past the log, which is the gap the ceiling
    // cannot see: six small blocks are a few kilobytes all told.
    const ENORMOUS: u32 = 1024 * 1024;

    let blocks = chain(6);
    let directory = scratch("past-the-end");
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }

    let index = std::fs::read(directory.join(BLOCK_INDEX)).unwrap();
    let start_of_two = u64::from_le_bytes(index[8..16].try_into().unwrap());
    put(
        &directory.join(BLOCK_LOG),
        start_of_two,
        &ENORMOUS.to_le_bytes(),
    );

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 6, "the open never looks at record two");
    assert!(
        log.bytes() < u64::from(ENORMOUS),
        "the fixture only means something while the log is smaller than the \
         prefix it now carries: {} bytes",
        log.bytes()
    );

    let replayed: Vec<Result<Block, StoreError>> = log.replay().collect();
    assert_eq!(
        replayed.len(),
        3,
        "two records, the refusal, and then nothing"
    );
    assert!(replayed[0].is_ok());
    assert!(replayed[1].is_ok());
    assert!(
        matches!(
            replayed[2],
            Err(StoreError::RecordPastTheEnd { index: 2, declared, .. })
                if declared == ENORMOUS as usize
        ),
        "the replay met a prefix reaching past the log and answered {:?}",
        replayed[2].as_ref().err().map(ToString::to_string)
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// One synthetic record of about `bytes`, linked into a chain of them.
///
/// Nothing here is mined or validated, because nothing in the log validates:
/// `append` refuses a record over the ceiling and a height that does not
/// follow, and writes the bytes. What is wanted is a log **larger than
/// `MAX_RECORD_BYTES`**, and mining four megabytes of real blocks to get one
/// would take a hundred thousand of them.
fn a_wide_block(height: u64, previous: cairn_primitives::Hash32, bytes: usize) -> Block {
    let owner = SecretKey::from_bytes(&[9u8; 32]).public_key();
    let value = cairn_primitives::Amount::from_pebbles(1).unwrap();
    let per = Note::new(value, owner).encode().len();
    // Split across transfers rather than piled into one, because the decoder
    // holds a transfer to what the rules allow it to carry and a record that
    // will not decode is not a record.
    let each = 256;
    let transfers = bytes / (per * each).max(1) + 1;
    let transfers = (0..transfers)
        .map(|which| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(height * 1_000 + which as u64).to_le_bytes());
            cairn_ledger::transaction::Transfer::new(
                vec![cairn_ledger::transaction::Input::hot(
                    cairn_ledger::note::NoteId::new(cairn_primitives::Hash32::from_bytes(seed), 0),
                )],
                (0..each).map(|_| Note::new(value, owner)).collect(),
            )
        })
        .collect();
    Block {
        header: cairn_ledger::block::BlockHeader {
            version: cairn_ledger::block::BLOCK_VERSION,
            network: cairn_ledger::note::NetworkId::TESTNET,
            height,
            previous,
            transactions_root: cairn_primitives::Hash32::ZERO,
            state_root: cairn_primitives::Hash32::ZERO,
            history: cairn_primitives::Hash32::ZERO,
            timestamp: NOW,
            difficulty: 1,
            total_work: 0,
            nonce: height,
        },
        coinbase: CoinbaseTransaction::new(height, Vec::new()),
        transfers,
    }
}

/// A log larger than the ceiling, which is every real one and no test one.
///
/// Returns the directory and the size of the file.
fn a_log_past_the_ceiling(name: &str) -> (PathBuf, u64) {
    let directory = scratch(name);
    let wide = 110 * 1024;
    let mut height = 0u64;
    let mut previous = cairn_primitives::Hash32::ZERO;
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        while std::fs::metadata(directory.join(BLOCK_LOG))
            .map(|at| at.len())
            .unwrap_or(0)
            <= MAX_RECORD_BYTES as u64
        {
            let block = a_wide_block(height, previous, wide);
            previous = block.header.id();
            log.append(&block).unwrap();
            height += 1;
            assert!(height < 1_000, "the log is not growing");
        }
    }
    let size = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
    (directory, size)
}

/// Where the ceiling sits, on a log big enough for the question to be asked.
///
/// A length read off a disk has two questions to answer, which the note at
/// the top of this file sets out: whether it is a length this process could
/// have written, which is the ceiling, and whether a record can follow it,
/// which is what is left in the file. **On a log smaller than the ceiling the
/// two have the same answer**, because no length clearing four megabytes can
/// fit in a file of one thousand bytes. Every fixture in this crate is that
/// small, so the ceiling's own position was measured nowhere: moved by one,
/// or read as equality, the suite agreed.
///
/// Real logs are not that small. A node's block log is the chain, and the
/// case that matters — a prefix over the ceiling with room in the file behind
/// it — is the case only a real log has. Read as equality, every such log
/// takes a four megabyte record a flipped bit invented.
///
/// So the log here is built past the ceiling, and the three readers of a
/// length are each asked on both sides of it.
#[test]
fn the_ceiling_is_where_it_says_on_a_log_larger_than_itself() {
    let (directory, size) = a_log_past_the_ceiling("past");
    assert!(
        size > MAX_RECORD_BYTES as u64,
        "the log has to be larger than the ceiling or the question cannot be \
         asked: {size} bytes against a ceiling of {MAX_RECORD_BYTES}"
    );

    // One past the ceiling, with room behind it in the file. The only thing
    // that can refuse this is the ceiling.
    let over = u32::try_from(MAX_RECORD_BYTES).unwrap() + 1;
    assert!(
        u64::from(over) < size,
        "and the length has to fit in the file, or what refuses it is the room"
    );

    let (log, _) = BlockLog::open(&directory).unwrap();
    assert!(log.reaches() > 1, "the fixture is a log of whole records");

    // The reader that walks: the open itself, once the index is gone.
    //
    // Its ceiling is the one of the three that cannot be measured by what
    // comes back, and the reason is worth having written down rather than
    // taken for a gap. Read as equality or moved by one, the walk does not
    // stop at the prefix; it reads the four megabytes the prefix asked for,
    // hands them to the decoder, and the decoder refuses them. The verdict is
    // the same verdict. What the ceiling saves is the four megabytes, which is
    // the whole of what the note at the top of this file says it is for, and
    // a reservation is not something an assertion can see.
    //
    // So what is held here is that the walk refuses and cuts nothing, which
    // is the verdict, and the reservation is left to the note.
    drop(log);
    put(&directory.join(BLOCK_LOG), 0, &over.to_le_bytes());
    let _ = std::fs::remove_file(directory.join(BLOCK_INDEX));
    let (walked, after) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        after.unreadable,
        Some(0),
        "a length no process wrote is damage wherever it sits, and here there \
         is room behind it in the file"
    );
    assert_eq!(
        after.discarded_bytes, 0,
        "and nothing is cut for damage, which is what this file is about"
    );
    assert_eq!(
        after.blocks, 0,
        "and nothing is read past it: {} records came back",
        after.blocks
    );
    drop(walked);
    let _ = std::fs::remove_dir_all(&directory);

    // The two readers that seek: a sound index, and the prefix changed under
    // an open log so that the open does not meet it first.
    let (directory, _) = a_log_past_the_ceiling("seeking");
    let (log, _) = BlockLog::open(&directory).unwrap();
    assert!(log.reaches() > 1, "the fixture is a log of whole records");
    put(&directory.join(BLOCK_LOG), 0, &over.to_le_bytes());

    let read = log.read_at(0);
    assert!(
        matches!(
            read,
            Err(StoreError::RecordTooLarge {
                index: 0,
                declared
            }) if declared == MAX_RECORD_BYTES + 1
        ),
        "the single read has to name the ceiling rather than find out by \
         trying, and it said {read:?}"
    );

    let first = log.replay().next();
    assert!(
        matches!(
            first,
            Some(Err(StoreError::RecordTooLarge {
                index: 0,
                declared
            })) if declared == MAX_RECORD_BYTES + 1
        ),
        "and so does the replay, which is the path a start walks without an \
         index: it said {first:?}"
    );

    // And on the ceiling rather than over it, what answers is no longer the
    // ceiling. The record is not that long, so what refuses it is the pair of
    // offsets the index holds, which is the other question.
    put(
        &directory.join(BLOCK_LOG),
        0,
        &u32::try_from(MAX_RECORD_BYTES).unwrap().to_le_bytes(),
    );
    let on_it = log.read_at(0);
    assert!(
        !matches!(on_it, Err(StoreError::RecordTooLarge { .. })),
        "a length of exactly the ceiling is one this process could have \
         written, and it said {on_it:?}"
    );
    let on_it = log.replay().next();
    assert!(
        !matches!(on_it, Some(Err(StoreError::RecordTooLarge { .. }))),
        "and the replay reads the ceiling the same way the single read does, \
         or the two disagree about what a length this process could have \
         written is: it said {on_it:?}"
    );

    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
}

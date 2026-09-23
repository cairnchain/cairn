//! Surviving a restart, and a crash in the middle of a write.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_store::{BlockLog, StoreError, BLOCK_INDEX, BLOCK_LOG};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-block-log-{}-{name}", std::process::id()));
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

/// Everything the log holds, read back the way a node replays it.
fn read_back(log: &BlockLog) -> Vec<Block> {
    log.replay().map(|block| block.unwrap()).collect()
}

#[test]
fn a_fresh_directory_starts_empty() {
    let directory = scratch("fresh");
    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert!(log.is_empty());
    assert_eq!(recovered.blocks, 0);
    assert_eq!(recovered.discarded_bytes, 0);
    assert!(log.path().exists());
}

#[test]
fn blocks_come_back_in_the_order_they_went_in() {
    let directory = scratch("roundtrip");
    let blocks = chain(12);

    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
        assert_eq!(log.len(), 12);
    }

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(log.len(), 12);
    assert_eq!(recovered.blocks, 12);
    assert_eq!(recovered.discarded_bytes, 0);
    assert_eq!(read_back(&log), blocks, "and in order");
}

#[test]
fn appending_after_reopening_continues_the_log() {
    let directory = scratch("continue");
    let blocks = chain(6);

    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks[..3] {
            log.append(block).unwrap();
        }
    }
    {
        let (mut log, recovered) = BlockLog::open(&directory).unwrap();
        assert_eq!(recovered.blocks, 3);
        for block in &blocks[3..] {
            log.append(block).unwrap();
        }
    }

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 6);
    assert_eq!(read_back(&log), blocks);
}

/// A write cut short costs the block it was writing and nothing else.
///
/// It is left where it is rather than cut, which is the trade this log makes
/// everywhere a length is involved. The bytes after a length prefix are not a
/// record, and cutting them is right — for a tail. One flipped bit produces
/// the same shape in a prefix anywhere in the file, and there the bytes after
/// it are whole records, so cutting deleted six blocks and told the operator a
/// write had been interrupted. Eleven bits of a prefix still did it after the
/// first repair.
///
/// So nothing is cut for a length. What it costs is here: these seven bytes
/// are reported as left in place on every start until the node appends a
/// block, which on a node following a chain is the next one. What the other
/// side costs is an archive.
#[test]
fn a_write_cut_short_costs_only_the_block_it_was_writing() {
    let directory = scratch("torn");
    let blocks = chain(5);

    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }

    // Simulate a crash partway through a sixth record.
    let mut file = OpenOptions::new()
        .append(true)
        .open(directory.join(BLOCK_LOG))
        .unwrap();
    file.write_all(&[0x40, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03])
        .unwrap();
    drop(file);

    let (mut log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 5, "everything complete survived");
    assert_eq!(read_back(&log), blocks);
    assert_eq!(
        recovered.discarded_bytes, 0,
        "and nothing was deleted for it"
    );
    assert_eq!(
        recovered.left_in_place, 7,
        "the seven bytes are still there"
    );
    assert_eq!(log.len(), 5);

    // And the next block written writes over them, which is the one thing
    // that makes them stop being reachable by anything.
    let sixth = chain(6).pop().unwrap();
    log.append(&sixth).unwrap();
    drop(log);

    let (again_log, again) = BlockLog::open(&directory).unwrap();
    assert_eq!(again.discarded_bytes, 0);
    assert_eq!(
        again.left_in_place, 0,
        "the torn write is gone, written over"
    );
    assert_eq!(again.blocks, 6);
    assert_eq!(again_log.len(), 6);
}

/// A record that is not a block is reported when it is read.
///
/// Opening a log does not decode what it holds: that would mean reading the
/// whole chain to find out how long it is, at every start, forever. What the
/// index says is taken as read, and a record that turns out not to be a block
/// is found by whoever asks for it. A node asks for all of them as it replays,
/// so nothing goes unnoticed; it is noticed a moment later than it used to be.
#[test]
fn a_record_that_is_not_a_block_is_reported_when_it_is_read() {
    let directory = scratch("garbage");
    let blocks = chain(2);

    let end = {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        log.append(&blocks[0]).unwrap();
        std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len()
    };

    // A second record that is four bytes of nonsense, with an index entry
    // pointing at it, so nothing about the shape of either file gives it away.
    let mut file = OpenOptions::new()
        .append(true)
        .open(directory.join(BLOCK_LOG))
        .unwrap();
    file.write_all(&[0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef])
        .unwrap();
    drop(file);
    let mut index = OpenOptions::new()
        .append(true)
        .open(directory.join(cairn_store::BLOCK_INDEX))
        .unwrap();
    index.write_all(&(end + 8).to_le_bytes()).unwrap();
    drop(index);

    // And a third record, whole, behind the bad one. Without it the walk stops
    // at the second because there is nothing after it, and this test's own
    // claim that it stops *there* could not fail. The record that will not
    // decode has to have something behind it or the assertion is about the end
    // of the file.
    let mut file = OpenOptions::new()
        .append(true)
        .open(directory.join(BLOCK_LOG))
        .unwrap();
    let third = blocks[1].encode();
    file.write_all(&u32::try_from(third.len()).unwrap().to_le_bytes())
        .unwrap();
    file.write_all(&third).unwrap();
    drop(file);
    // The index holds where each record ends, which is what the entry written
    // above for the bad record is.
    let ends_at = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
    let mut index = OpenOptions::new()
        .append(true)
        .open(directory.join(cairn_store::BLOCK_INDEX))
        .unwrap();
    index.write_all(&ends_at.to_le_bytes()).unwrap();
    drop(index);

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        recovered.blocks, 3,
        "the index says three, and it is believed"
    );

    assert!(
        matches!(log.read(1), Err(StoreError::Malformed { index: 1, .. })),
        "silence would be worse"
    );
    assert!(
        log.read(2).is_ok(),
        "the third record is whole, and asking for it by name still gives it"
    );

    // And a replay stops there rather than carrying on past a hole. A record
    // that will not decode means the cursor is no longer where the next record
    // begins, so everything after it would be read at an offset nothing
    // vouches for. This walk used to hand back nought, the error, and then two
    // and three: the chain with a hole in it that `Replay`'s own doc names as
    // the thing it cannot produce.
    let replayed: Vec<_> = log.replay().collect();
    assert_eq!(
        replayed.len(),
        2,
        "the walk carried on past a record it could not read"
    );
    assert!(replayed[0].is_ok());
    assert!(replayed[1].is_err(), "the walk reports it too");
}

/// A whole record past the last good one, holding bytes that are not a block.
///
/// This is damage rather than an interrupted write: the file does not end
/// inside the record, it ends after it. So nothing is cut, and what the count
/// reports is how much is standing there unread. It used to report those same
/// bytes as thrown away while they sat on the disk, and the test asserted it,
/// which is how the contradiction survived a suite.
#[test]
fn a_record_that_is_not_a_block_is_named_and_left_alone() {
    let directory = scratch("trailing");
    let blocks = chain(2);

    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }

    let mut file = OpenOptions::new()
        .append(true)
        .open(directory.join(BLOCK_LOG))
        .unwrap();
    file.write_all(&[0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef])
        .unwrap();
    drop(file);

    let whole = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 2);
    assert_eq!(recovered.unreadable, Some(2), "damage, not a torn write");
    assert_eq!(recovered.discarded_bytes, 0, "and nothing was cut for it");
    assert_eq!(recovered.left_in_place, 8);
    assert_eq!(read_back(&log), blocks);
    drop(log);
    assert_eq!(
        std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len(),
        whole,
        "the bytes it reported are still where an operator can look at them"
    );
}

/// The index is derived, so losing it costs one slow start and nothing else.
#[test]
fn a_missing_index_is_rebuilt_from_the_log() {
    let directory = scratch("reindex");
    let blocks = chain(7);

    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }
    std::fs::remove_file(directory.join(cairn_store::BLOCK_INDEX)).unwrap();

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 7, "worked out from the log itself");
    assert_eq!(read_back(&log), blocks);
    assert_eq!(log.read(4).unwrap().unwrap(), blocks[4]);

    // Written back down, so the next start is quick again.
    let written = std::fs::metadata(directory.join(cairn_store::BLOCK_INDEX))
        .unwrap()
        .len();
    assert_eq!(written, 7 * 8);
}

/// An index that reaches past the log is not what this process last wrote.
#[test]
fn an_index_longer_than_the_log_is_rebuilt() {
    let directory = scratch("ahead");
    let blocks = chain(4);

    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }

    // Two more offsets, pointing at bytes that are not there.
    let mut index = OpenOptions::new()
        .append(true)
        .open(directory.join(cairn_store::BLOCK_INDEX))
        .unwrap();
    index.write_all(&u64::MAX.to_le_bytes()).unwrap();
    drop(index);

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        recovered.blocks, 4,
        "the log is the record, the index is not"
    );
    assert_eq!(read_back(&log), blocks);
}

/// A torn write to the index leaves part of an offset behind.
#[test]
fn a_partial_offset_is_cut_back() {
    let directory = scratch("partial");
    let blocks = chain(3);

    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }

    let mut index = OpenOptions::new()
        .append(true)
        .open(directory.join(cairn_store::BLOCK_INDEX))
        .unwrap();
    index.write_all(&[0x01, 0x02, 0x03]).unwrap();
    drop(index);

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 3);
    assert_eq!(read_back(&log), blocks);
}

/// An absurd length is never reserved, and what happens instead depends on
/// whether the bytes it claims are there.
///
/// Four bytes of length and nothing after them is a write that stopped between
/// the two, which is what a crash mid append leaves. The node starts, which is
/// the thing this was written for: it used to refuse the start instead, and go
/// on refusing it, which on an unattended node means a node that never comes
/// back over a torn tail.
///
/// Whether those four bytes are then cut turns on the number in them, and one
/// rule decides it wherever the record sits: a length longer than any block
/// the rules allow is not one this process wrote, so nothing is reserved for
/// it and nothing is cut for it. It is reported as damage, and the bytes are
/// left where they are, which a start that misread them once can read back.
///
/// That used to depend on whether the file was long enough to hold what the
/// length claimed — the file ending inside a record was read as a write cut
/// short. True of a tail and true of one bad byte in the first record of a
/// full log, where it deleted every whole record behind it. So the file's
/// length no longer decides it, and what that costs is here: four bytes of a
/// torn write are left in place rather than cut. `append` truncates to the
/// last whole record before it writes, so the next block removes them.
#[test]
fn an_absurd_record_length_is_never_reserved() {
    let torn = scratch("absurd-torn");
    std::fs::create_dir_all(&torn).unwrap();
    std::fs::write(torn.join(BLOCK_LOG), [0xff, 0xff, 0xff, 0xff]).unwrap();

    let (log, recovered) = BlockLog::open(&torn).unwrap();
    assert!(log.is_empty(), "nothing was reserved and the node starts");
    assert_eq!(
        recovered.discarded_bytes, 0,
        "nothing is cut for a length nothing here wrote"
    );
    assert_eq!(recovered.unreadable, Some(0), "reported as damage");
    assert_eq!(
        recovered.left_in_place, 4,
        "and left where a reader can see it"
    );
    drop(log);

    // One byte over the ceiling, in a file long enough to hold what it claims.
    // Sparse, so this costs no disk: what matters is the length.
    let present = scratch("absurd-present");
    std::fs::create_dir_all(&present).unwrap();
    let over = u32::try_from(cairn_store::MAX_RECORD_BYTES).unwrap() + 1;
    std::fs::write(present.join(BLOCK_LOG), over.to_le_bytes()).unwrap();
    OpenOptions::new()
        .write(true)
        .open(present.join(BLOCK_LOG))
        .unwrap()
        .set_len(u64::from(over) + 8)
        .unwrap();

    let (log, recovered) = BlockLog::open(&present).unwrap();
    assert!(log.is_empty(), "nothing was reserved and nothing was read");
    assert_eq!(recovered.unreadable, Some(0), "reported as damage");
    assert_eq!(
        recovered.discarded_bytes, 0,
        "nothing was cut, so nothing is reported as thrown away"
    );
    assert_eq!(
        recovered.left_in_place,
        u64::from(over) + 8,
        "and the whole of it is reported as standing there unread"
    );
    drop(log);
    assert_eq!(
        std::fs::metadata(present.join(BLOCK_LOG)).unwrap().len(),
        u64::from(over) + 8,
        "and left on the disk for somebody to look at"
    );

    let _ = std::fs::remove_dir_all(&torn);
    let _ = std::fs::remove_dir_all(&present);
}

#[test]
fn the_log_can_be_cut_back_to_a_prefix() {
    let directory = scratch("prefix");
    let blocks = chain(8);

    let (mut log, _) = BlockLog::open(&directory).unwrap();
    for block in &blocks {
        log.append(block).unwrap();
    }
    log.keep_first(3).unwrap();
    assert_eq!(log.len(), 3);
    drop(log);

    let (reopened, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 3);
    assert_eq!(read_back(&reopened), blocks[..3]);
    assert_eq!(recovered.discarded_bytes, 0);
}

/// A cut interrupted between its two files stays cut.
///
/// The order matters and it is the opposite of an append's. An append writes
/// its record before the offset naming it, so a crash between the two leaves
/// the log ahead of the index, and recovery reads the record forward and keeps
/// it: the block was accepted and synced and deserves to survive. A cut has to
/// leave the disagreement the other way round, or the same recovery reads the
/// abandoned records back out of the log and puts them where the cut had just
/// taken them from.
///
/// This is the shape of a machine stopping after the log was cut and before
/// the index was, which is the only shape a log-first cut can be caught in.
#[test]
fn a_cut_interrupted_between_its_two_files_stays_cut() {
    let directory = scratch("torn-cut");
    let blocks = chain(8);

    let end = {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
        // Where record two ends, which is what keeping three would cut to.
        let index = std::fs::read(directory.join(cairn_store::BLOCK_INDEX)).unwrap();
        u64::from_le_bytes(index[16..24].try_into().unwrap())
    };
    OpenOptions::new()
        .write(true)
        .open(directory.join(BLOCK_LOG))
        .unwrap()
        .set_len(end)
        .unwrap();

    let (log, _) = BlockLog::open(&directory).unwrap();
    assert_eq!(log.len(), 3, "the cut was undone by the start after it");
    assert_eq!(read_back(&log), blocks[..3]);
    drop(log);

    // And the index was written to match, so the next start is quick.
    assert_eq!(
        std::fs::metadata(directory.join(cairn_store::BLOCK_INDEX))
            .unwrap()
            .len(),
        3 * 8
    );
    drop(std::fs::remove_dir_all(&directory));

    // The state the other order would be caught in, spelled out because it is
    // the reason for the order rather than a thing that can happen now: the
    // index cut and the log not. Recovery reads the log forward from where the
    // index stops, which is exactly right for an interrupted append and
    // exactly wrong for an interrupted cut, and there is nothing in either
    // file that tells the two apart.
    let other = scratch("torn-cut-other");
    {
        let (mut log, _) = BlockLog::open(&other).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }
    OpenOptions::new()
        .write(true)
        .open(other.join(cairn_store::BLOCK_INDEX))
        .unwrap()
        .set_len(3 * 8)
        .unwrap();
    let (log, _) = BlockLog::open(&other).unwrap();
    assert_eq!(log.len(), blocks.len(), "the records are read back");
    drop(log);
    let _ = std::fs::remove_dir_all(&other);
}

/// A node that has forgotten a block it once applied has to be able to get it
/// back, because a peer catching up will ask for exactly those.
#[test]
fn any_single_block_can_be_read_back_by_position() {
    let directory = scratch("byindex");
    let blocks = chain(10);

    let (mut log, _) = BlockLog::open(&directory).unwrap();
    for block in &blocks {
        log.append(block).unwrap();
    }

    // Out of order on purpose: each read seeks for itself and leaves nothing
    // behind, so the order they are asked for cannot matter.
    for index in [7usize, 0, 9, 3, 0] {
        let found = log.read(index).unwrap().expect("that record exists");
        assert_eq!(&found, &blocks[index], "record {index}");
    }

    assert!(
        log.read(10).unwrap().is_none(),
        "past the end is nothing, not an error"
    );

    // And the log is still readable in order afterwards.
    assert_eq!(read_back(&log), blocks);
}

/// Dropping the front of the log rewrites both files. A machine that stops
/// partway must not leave a log holding the front of the new one and the back
/// of the old, with an index pointing into offsets that no longer mean
/// anything: a node would then serve blocks that are not the ones it names.
#[test]
fn dropping_the_front_of_the_log_is_all_or_nothing() {
    let directory = scratch("keep-from");
    let (mut log, _) = BlockLog::open(&directory).unwrap();
    let blocks = chain(20);
    for block in &blocks {
        log.append(block).unwrap();
    }
    assert_eq!(log.first_height(), 0);
    assert_eq!(log.reaches(), 20);

    log.keep_from(12).unwrap();
    assert_eq!(log.first_height(), 12, "it starts where it was told to");
    assert_eq!(log.reaches(), 20, "and still reaches the tip");
    assert!(log.read_at(11).unwrap().is_none(), "what went is gone");
    for height in 12..20u64 {
        let found = log.read_at(height).unwrap().expect("still held");
        assert_eq!(found.header.height, height, "at its own height");
        assert_eq!(found.id(), blocks[usize::try_from(height).unwrap()].id());
    }

    // Read back by a second process, which is what a restart is.
    drop(log);
    let (again, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 8);
    assert_eq!(
        again.first_height(),
        12,
        "where it starts survives a restart"
    );
    assert_eq!(again.reaches(), 20);
    assert_eq!(again.read_at(19).unwrap().unwrap().id(), blocks[19].id());
    assert!(
        !directory.join("blocks.log.part").exists(),
        "nothing was left half moved"
    );

    // And past the end, which empties it and leaves it ready for whatever
    // height comes next.
    drop(again);
    let (mut again, _) = BlockLog::open(&directory).unwrap();
    again.keep_from(99).unwrap();
    assert!(again.is_empty());
    again.append(&blocks[5]).unwrap();
    assert_eq!(again.first_height(), 5);
    assert_eq!(again.read_at(5).unwrap().unwrap().id(), blocks[5].id());

    let _ = std::fs::remove_dir_all(&directory);
}

/// Positions in the header log are heights, with no index beside it, which
/// works only because a header encodes to the same number of bytes every time.
/// If that ever stops being true this is where it is noticed, rather than in a
/// node answering about the wrong header.
#[test]
fn a_header_is_a_fixed_size_record() {
    let blocks = chain(6);
    for block in &blocks {
        assert_eq!(
            block.header.encode().len(),
            cairn_store::HEADER_BYTES,
            "a header at height {} is not the size the log assumes",
            block.header.height
        );
    }
}

#[test]
fn headers_are_read_back_by_height_and_cut_back_by_reorganisation() {
    let directory = scratch("headers");
    let blocks = chain(12);
    {
        let mut log = cairn_store::HeaderLog::open(&directory).unwrap();
        assert!(log.is_empty());
        for block in &blocks {
            log.append(&block.header).unwrap();
        }
        assert_eq!(log.first_height(), 0);
        assert_eq!(log.reaches(), 12);

        // A header that does not follow on is refused rather than written at a
        // position that is not its height.
        assert!(matches!(
            log.append(&blocks[3].header),
            Err(cairn_store::StoreError::OutOfOrder { .. })
        ));

        for height in 0..12u64 {
            let found = log.read_at(height).unwrap().expect("held");
            assert_eq!(
                found.id(),
                blocks[usize::try_from(height).unwrap()].header.id()
            );
        }
        assert!(log.read_at(12).unwrap().is_none());
    }

    // Reopened, it knows what it holds without being told.
    let mut log = cairn_store::HeaderLog::open(&directory).unwrap();
    assert_eq!(log.len(), 12);
    assert_eq!(log.reaches(), 12);
    assert_eq!(
        log.read_at(11).unwrap().unwrap().id(),
        blocks[11].header.id()
    );

    // A reorganisation takes the tail off, and the next branch is written over
    // the same ground.
    log.keep_below(9).unwrap();
    assert_eq!(log.reaches(), 9);
    assert!(log.read_at(9).unwrap().is_none());
    log.append(&blocks[9].header).unwrap();
    assert_eq!(log.reaches(), 10);

    let _ = std::fs::remove_dir_all(&directory);
}

/// A compaction moves the records and leaves nothing behind it.
///
/// Recovery sets aside the bytes of a record it could not read, past the end
/// of the log, on purpose: they stay until the log grows over them, and
/// `append` is what writes over them. `keep_from` read to the end of the file
/// rather than to the end of the records, so it copied those bytes into the
/// compacted log and then reported nothing past the end, which disarmed the
/// one thing that would have removed them. Sixty eight bytes of a twenty
/// record log survived a compaction with nothing left that knew they were
/// there.
#[test]
fn a_compaction_carries_the_records_and_not_what_lies_past_them() {
    let directory = scratch("compaction-tail");
    let blocks = chain(20);
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }

    // A whole record that will not decode: an honest length prefix and a body
    // that is not a block. That is damage rather than a torn write, so
    // recovery leaves it where it is and says so.
    let path = directory.join(BLOCK_LOG);
    let junk = vec![7u8; 64];
    {
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&u32::try_from(junk.len()).unwrap().to_le_bytes())
            .unwrap();
        file.write_all(&junk).unwrap();
        file.flush().unwrap();
    }

    let (mut log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.unreadable, Some(20));
    assert_eq!(recovered.left_in_place, 68, "left where they are, not cut");

    log.keep_from(10).unwrap();
    assert_eq!(log.len(), 10);
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        log.bytes(),
        "the compacted log is exactly the records it says it holds"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// A start refuses only over a file it could not reach.
///
/// The index is worked out from the log and never believed over it, so nothing
/// written in it may keep a node down. Two failures together used to: an index
/// one entry short of the log is the ordinary torn append, and a damaged first
/// offset is a byte of rot in a derived file. On that path `recover` checked
/// the last entry before splicing the log's tail onto it and nothing checked
/// the first, which `settle` then reads back to learn where the log starts.
/// The start refused with "the index puts record 0 between 0 and 0" and an
/// unattended node stayed down. The same damage with the index at full length
/// rebuilt and came back with every block.
#[test]
fn a_damaged_index_never_keeps_a_node_from_starting() {
    let blocks = chain(20);
    let entries = |directory: &PathBuf| {
        std::fs::metadata(directory.join(BLOCK_INDEX))
            .unwrap()
            .len()
            / 8
    };

    for short in [false, true] {
        let directory = scratch(if short { "index-short" } else { "index-full" });
        {
            let (mut log, _) = BlockLog::open(&directory).unwrap();
            for block in &blocks {
                log.append(block).unwrap();
            }
        }
        let held = entries(&directory);
        {
            let mut file = OpenOptions::new()
                .write(true)
                .open(directory.join(BLOCK_INDEX))
                .unwrap();
            if short {
                file.set_len((held - 1) * 8).unwrap();
            }
            file.write_all(&0u64.to_le_bytes()).unwrap();
            file.flush().unwrap();
        }

        let (log, _) = BlockLog::open(&directory)
            .unwrap_or_else(|error| panic!("short index = {short}: {error}"));
        assert_eq!(log.len(), 20, "short index = {short}");
        assert_eq!(log.first_height(), 0, "short index = {short}");
        assert_eq!(read_back(&log), blocks, "short index = {short}");

        let _ = std::fs::remove_dir_all(&directory);
    }
}

/// A log that has been cut at both ends still knows which heights it holds.
///
/// `first` is where the log begins, and every question about a height is
/// answered by subtracting it: `holds`, `read_at` and `reaches` are all that
/// one number and the count. `keep_first` sets it back to nought when the log
/// is emptied, which is right, and nothing had ever asked what it does when
/// the log is *not* emptied.
///
/// Nothing could have asked. Every fixture in this crate builds its chain from
/// height nought, so `first` is nought before the trim and nought after it,
/// and the two answers are the same answer. A log only begins somewhere else
/// once its bottom has been dropped, which is what `keep_from` is for and what
/// every node past `--keep` has done.
///
/// So: drop the bottom, then cut the top, and ask the questions a serving node
/// asks. Read the other way, a log holding heights twelve to fifteen says it
/// holds nought to three, and answers about blocks it does not have.
#[test]
fn a_log_cut_at_both_ends_still_knows_where_it_begins() {
    let blocks = chain(20);
    let directory = scratch("both-ends");
    let (mut log, _) = BlockLog::open(&directory).unwrap();
    for block in &blocks {
        log.append(block).unwrap();
    }

    // The bottom goes, which is what puts the log somewhere other than nought.
    log.keep_from(12).unwrap();
    assert_eq!(log.reaches(), 20, "the tip is where it was");
    assert!(
        log.read_at(12).unwrap().is_some(),
        "the log begins at twelve, which is the whole premise"
    );
    assert!(log.read_at(11).unwrap().is_none(), "and not below it");

    // Then the top, which is what a reorganisation does.
    log.keep_below(16).unwrap();
    assert_eq!(
        log.reaches(),
        16,
        "a log holding twelve to fifteen reaches sixteen, and it said {}",
        log.reaches()
    );

    // The heights either side of both edges, which is what `holds` is for and
    // what every read goes through.
    for height in [0u64, 11, 16, 17, 99] {
        assert!(
            !log.holds(height),
            "the log holds twelve to fifteen and says it holds {height}"
        );
        assert!(
            log.read_at(height).unwrap().is_none(),
            "and answers about {height}"
        );
    }
    // The count `holds` looks at first cannot be measured here and is not a
    // gap: an empty log reaches exactly where it begins, so the two
    // comparisons after it already answer no for every height.
    for height in 12..16u64 {
        assert!(log.holds(height), "the log does not say it holds {height}");
        let block = log
            .read_at(height)
            .unwrap()
            .unwrap_or_else(|| panic!("height {height} vanished"));
        assert_eq!(
            block.header.id(),
            blocks[usize::try_from(height).unwrap()].header.id(),
            "height {height} came back as another block"
        );
    }

    drop(log);
    let (again, _) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        again.reaches(),
        16,
        "and a start reads the same two numbers back off the disk"
    );
    assert!(again.holds(12) && !again.holds(16));

    drop(again);
    let _ = std::fs::remove_dir_all(&directory);
}

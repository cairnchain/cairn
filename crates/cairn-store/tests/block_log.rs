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
use cairn_store::{BlockLog, StoreError, BLOCK_LOG};

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

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 5, "everything complete survived");
    assert_eq!(read_back(&log), blocks);
    assert_eq!(recovered.discarded_bytes, 7);
    assert_eq!(log.len(), 5);

    // The file was cut back, so the next open finds nothing left over.
    let (again_log, again) = BlockLog::open(&directory).unwrap();
    assert_eq!(again.discarded_bytes, 0);
    assert_eq!(again.blocks, 5);
    assert_eq!(read_back(&again_log), blocks);
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
    let blocks = chain(1);

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

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        recovered.blocks, 2,
        "the index says two, and it is believed"
    );

    assert!(
        matches!(log.read(1), Err(StoreError::Malformed { index: 1, .. })),
        "silence would be worse"
    );
    // And a replay stops there rather than carrying on past a hole.
    let replayed: Vec<_> = log.replay().collect();
    assert!(replayed[0].is_ok());
    assert!(replayed[1].is_err(), "the walk reports it too");
}

/// Bytes past the last record are what a write that never finished leaves.
#[test]
fn bytes_the_index_does_not_reach_are_dropped() {
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

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 2);
    assert_eq!(recovered.discarded_bytes, 8);
    assert_eq!(read_back(&log), blocks);
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

#[test]
fn an_absurd_record_length_is_refused_before_anything_is_reserved() {
    let directory = scratch("absurd");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join(BLOCK_LOG), [0xff, 0xff, 0xff, 0xff]).unwrap();

    let outcome = BlockLog::open(&directory);
    assert!(matches!(
        outcome,
        Err(StoreError::RecordTooLarge { index: 0, .. })
    ));
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

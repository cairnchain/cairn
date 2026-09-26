//! A replay that starts at a height, and a replay that meets a record it
//! cannot read.
//!
//! A node that starts from a ledger it wrote needs the blocks above that
//! ledger and none of the ones below it. It used to read every block in the
//! log to pass the lower ones over, which on a node that keeps every block is
//! a start that grows with the chain. And a replay that met a record it could
//! not decode had nothing to say about it but the error, which the node read
//! as a place to cut the log.

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

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-partway-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn chain(count: usize) -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[6; 32]);
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

fn a_log_of(blocks: &[Block], name: &str) -> PathBuf {
    let directory = scratch(name);
    let (mut log, _) = BlockLog::open(&directory).unwrap();
    for block in blocks {
        log.append(block).unwrap();
    }
    directory
}

fn heights(log: &BlockLog, from: u64) -> Vec<u64> {
    log.replay_from(from)
        .map(|block| block.unwrap().header.height)
        .collect()
}

/// Where record `index` ends, as the index says.
fn end_of(directory: &Path, index: usize) -> usize {
    let entries = std::fs::read(directory.join(BLOCK_INDEX)).unwrap();
    usize::try_from(u64::from_le_bytes(
        entries[index * 8..index * 8 + 8].try_into().unwrap(),
    ))
    .unwrap()
}

/// A replay from a height begins with the block at that height and reads
/// nothing below it.
///
/// Nothing asked this, so a start from a ledger decoded every block under the
/// ledger only to pass it over.
#[test]
fn a_replay_from_a_height_begins_at_the_block_at_that_height() {
    let directory = a_log_of(&chain(8), "from-five");
    let (log, _) = BlockLog::open(&directory).unwrap();
    assert_eq!(heights(&log, 5), vec![5, 6, 7], "not the blocks from 5 up");
    assert_eq!(heights(&log, 7), vec![7], "not the last block alone");
    assert_eq!(
        heights(&log, 0),
        (0..8).collect::<Vec<_>>(),
        "not every block from the first"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A replay from a height at or past the end of the log reads nothing, rather
/// than every record to say that none of them is wanted.
#[test]
fn a_replay_from_past_the_end_reads_nothing() {
    let directory = a_log_of(&chain(4), "past-the-end");
    let (log, _) = BlockLog::open(&directory).unwrap();
    assert!(
        heights(&log, 4).is_empty(),
        "a replay from the end read something"
    );
    assert!(
        heights(&log, 9).is_empty(),
        "a replay from past the end read something"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// Where the index puts the record somewhere it is not, the replay starts at
/// the first record instead: the index is derived, and one wrong entry costs
/// a slower start and never a different one.
#[test]
fn a_replay_from_a_height_the_index_misplaces_starts_at_the_first_record() {
    let blocks = chain(8);
    let directory = a_log_of(&blocks, "misplaced");
    // The entry saying where record 4 ends, which is where record 5 begins,
    // moved to where record 3 begins. The record found there is block 3.
    let mut entries = std::fs::read(directory.join(BLOCK_INDEX)).unwrap();
    let wrong = u64::try_from(end_of(&directory, 2)).unwrap();
    entries[4 * 8..4 * 8 + 8].copy_from_slice(&wrong.to_le_bytes());
    std::fs::write(directory.join(BLOCK_INDEX), &entries).unwrap();

    let (log, _) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        heights(&log, 5),
        (0..8).collect::<Vec<_>>(),
        "a replay started from an index entry that names the wrong record"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A record in the middle that will not decode, read again, leaves the log
/// holding what is before it and every byte of the file where it was.
///
/// Nothing asked this, so the node could only meet such a record as the end
/// of its replay, and cut the log there.
#[test]
fn reading_again_past_a_record_that_will_not_decode_keeps_every_byte() {
    let directory = a_log_of(&chain(8), "read-again");
    let at = end_of(&directory, 4);
    let mut bytes = std::fs::read(directory.join(BLOCK_LOG)).unwrap();
    bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(directory.join(BLOCK_LOG), &bytes).unwrap();

    let (mut log, opened) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        (opened.blocks, opened.unreadable),
        (8, None),
        "premise: the index is in line, so the open reads none of the middle"
    );
    let found = log.read_again().unwrap();

    assert_eq!(
        (log.len(), found.unreadable),
        (5, Some(5)),
        "reading again did not stop at the record that will not decode"
    );
    assert_eq!(
        found.left_in_place,
        u64::try_from(bytes.len() - at).unwrap(),
        "and it does not say how much is left on the disk past it"
    );
    assert!(
        std::fs::read(directory.join(BLOCK_LOG)).unwrap() == bytes,
        "and reading again changed the log"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

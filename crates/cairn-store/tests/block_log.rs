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
                vec![Note::new(params.block_reward, miner.public_key())],
                [0; 8],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            block
        })
        .collect()
}

#[test]
fn a_fresh_directory_starts_empty() {
    let directory = scratch("fresh");
    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert!(log.is_empty());
    assert!(recovered.blocks.is_empty());
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
    assert_eq!(recovered.blocks, blocks);
    assert_eq!(recovered.discarded_bytes, 0);
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
        assert_eq!(recovered.blocks.len(), 3);
        for block in &blocks[3..] {
            log.append(block).unwrap();
        }
    }

    let (_, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, blocks);
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
    assert_eq!(recovered.blocks, blocks, "everything complete survived");
    assert_eq!(recovered.discarded_bytes, 7);
    assert_eq!(log.len(), 5);

    // The file was cut back, so the next open finds nothing left over.
    let (_, again) = BlockLog::open(&directory).unwrap();
    assert_eq!(again.discarded_bytes, 0);
    assert_eq!(again.blocks, blocks);
}

#[test]
fn a_record_that_is_not_a_block_is_reported_rather_than_ignored() {
    let directory = scratch("garbage");
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

    let outcome = BlockLog::open(&directory);
    assert!(
        matches!(outcome, Err(StoreError::Malformed { index: 2, .. })),
        "silence would be worse"
    );
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

    let (_, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, blocks[..3]);
    assert_eq!(recovered.discarded_bytes, 0);
}

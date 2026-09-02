//! What one changed byte costs a header log, and where it lands.
//!
//! `audit_out_of_room.rs` measures the cost of a short write. This measures
//! the other shape: a byte that changed in place, which a log reads back
//! without noticing unless the record it lands in is one the reader checks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_store::{HeaderLog, HEADER_LOG};

const NOW: u64 = 2_000_000_000;
const RECORDS: u64 = 200;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-headprobe-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn chain(count: u64) -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[7u8; 32]);
    let mut state = LedgerState::archiving();
    let mut clock = 1_000u64;
    let mut blocks = Vec::new();
    for _ in 0..count {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        blocks.push(block);
    }
    blocks
}

fn put(path: &std::path::Path, at: u64, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(bytes).unwrap();
}

fn build(name: &str, blocks: &[Block]) -> PathBuf {
    let directory = scratch(name);
    let mut headers = HeaderLog::open(&directory).unwrap();
    for block in blocks {
        headers.append(&block.header).unwrap();
    }
    directory
}

/// What one byte costs, as a function of where it lands.
#[test]
fn the_blast_radius_of_one_byte_depends_on_where_it_lands() {
    let blocks = chain(RECORDS);

    // Middle of the log: the record and its two neighbours are refused, and
    // the log still reports holding every record.
    let middle = build("middle", &blocks);
    put(&middle.join(HEADER_LOG), 100 * 182 + 40, &[0xff]);
    let log = HeaderLog::open(&middle).unwrap();
    let mut refused = 0u64;
    for height in 0..RECORDS {
        if log.read_at(height).is_err() {
            refused += 1;
        }
    }
    println!(
        "PROBE: one byte in record 100: log reports {} records from height {}, {refused} refused",
        log.len(),
        log.first_height()
    );
    assert_eq!(log.len(), RECORDS);
    drop(log);

    // The head. One byte, and the log reports holding nothing at all: `head`
    // finds record one does not name record zero, and `open` sets the count to
    // zero over a file that still holds every record.
    let head = build("head", &blocks);
    put(&head.join(HEADER_LOG), 40, &[0xff]);
    let mut log = HeaderLog::open(&head).unwrap();
    let bytes_before = std::fs::metadata(head.join(HEADER_LOG)).unwrap().len();
    println!(
        "PROBE: one byte in record 0: log reports {} records from height {}, file still {} bytes",
        log.len(),
        log.first_height(),
        bytes_before
    );

    // And the next append deletes the file, on purpose: `append` with a count
    // of zero calls `set_len(0)` first.
    log.append(&blocks[0].header).unwrap();
    let bytes_after = std::fs::metadata(head.join(HEADER_LOG)).unwrap().len();
    println!("PROBE: after one append the file is {bytes_after} bytes");
    drop(log);

    // The record the head is checked against. Same result, and this one is not
    // the head at all: it is an ordinary record whose only distinction is
    // sitting at index one.
    let second = build("second", &blocks);
    put(&second.join(HEADER_LOG), 182 + 40, &[0xff]);
    let log = HeaderLog::open(&second).unwrap();
    println!(
        "PROBE: one byte in record 1: log reports {} records from height {}",
        log.len(),
        log.first_height()
    );
    drop(log);

    let _ = std::fs::remove_dir_all(&middle);
    let _ = std::fs::remove_dir_all(&head);
    let _ = std::fs::remove_dir_all(&second);
}

/// And the availability half: an honest log written over by a real
/// reorganisation is still read back whole. A real fork shares its parent, so
/// the seam links; nothing here should refuse.
#[test]
fn a_log_written_over_by_a_reorganisation_is_still_read_back_whole() {
    let params = ConsensusParams::testnet();
    let honest_miner = SecretKey::from_bytes(&[7u8; 32]);
    let rival_miner = SecretKey::from_bytes(&[9u8; 32]);

    let mut state = LedgerState::archiving();
    let mut clock = 1_000u64;
    let mut honest = Vec::new();
    let mut forked_from = None;
    for _ in 0..RECORDS {
        if state.next_height().unwrap() == 150 {
            forked_from = Some(state.clone());
        }
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, honest_miner.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        honest.push(block);
    }

    // The rival branch: same parent at height 149, different blocks from 150.
    let mut fork = forked_from.unwrap();
    let mut fork_clock = 1_000 + 150 * 600;
    let mut rival = Vec::new();
    for _ in 0..(RECORDS - 150 + 5) {
        let height = fork.next_height().unwrap();
        fork_clock += 601;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, rival_miner.public_key())],
        );
        let block = assemble_block(&fork, coinbase, Vec::new(), &params, fork_clock, 0).unwrap();
        connect_block(&mut fork, &block, &params, NOW).unwrap();
        rival.push(block);
    }
    assert_ne!(rival[0].header.id(), honest[150].header.id());
    assert_eq!(rival[0].header.previous, honest[149].header.id());

    let directory = build("reorg", &honest);
    {
        let mut log = HeaderLog::open(&directory).unwrap();
        log.keep_below(150).unwrap();
        for block in &rival {
            log.append(&block.header).unwrap();
        }
    }
    let log = HeaderLog::open(&directory).unwrap();
    let mut refused = Vec::new();
    for height in 0..log.reaches() {
        if let Err(error) = log.read_at(height) {
            refused.push((height, error.to_string()));
        }
    }
    println!(
        "PROBE: after a real reorganisation at 150 the log holds {} records, {} refused",
        log.len(),
        refused.len()
    );
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        refused.is_empty(),
        "PROBE: an honest reorganised log is refused at {refused:?}"
    );
}

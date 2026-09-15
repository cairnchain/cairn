//! The on-disk states a machine can stop in during `BlockLog::keep_from`, and
//! what the next start makes of each.
//!
//! `keep_from` argues its ordering in a comment: the staged log and index are
//! synced, the log is moved into place and waited for, then the index, and
//! "stopping between the two moves leaves an index reaching past the log,
//! which the next start already treats as an index to be rebuilt". No test in
//! the crate builds that state; the compaction tests run it to completion. This
//! builds every state a stop can leave after a durable step and opens it.
//!
//! The states are constructed rather than crashed into, which is a
//! simulation of a machine stop and not one. What it holds is that recovery
//! gives the right answer for each state the ordering can leave; whether the
//! ordering actually leaves only those states is a claim about `fsync` that
//! nothing here can reach.

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
use cairn_store::{BlockLog, BLOCK_INDEX, BLOCK_LOG};

const NOW: u64 = 2_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-compaction-steps-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// Unmined, since nothing on the store's paths checks the work.
fn chain(count: usize) -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[5u8; 32]);
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

struct Files {
    log: Vec<u8>,
    index: Vec<u8>,
}

fn files(directory: &Path) -> Files {
    Files {
        log: std::fs::read(directory.join(BLOCK_LOG)).unwrap(),
        index: std::fs::read(directory.join(BLOCK_INDEX)).unwrap(),
    }
}

/// Lays a state out and opens it, returning what the start found.
fn start_from(
    name: &str,
    log: &[u8],
    index: &[u8],
    beside: &[(&str, &[u8])],
) -> (u64, u64, u64, u64) {
    let directory = scratch(name);
    std::fs::write(directory.join(BLOCK_LOG), log).unwrap();
    std::fs::write(directory.join(BLOCK_INDEX), index).unwrap();
    for (file, bytes) in beside {
        std::fs::write(directory.join(file), bytes).unwrap();
    }
    let (opened, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, opened.len(), "{name}");
    assert_eq!(recovered.unreadable, None, "{name}: nothing here is damage");
    assert_eq!(recovered.discarded_bytes, 0, "{name}: nothing here is torn");
    for height in opened.first_height()..opened.reaches() {
        let block = opened.read_at(height).unwrap().unwrap();
        assert_eq!(block.header.height, height, "{name}: height {height}");
    }
    let first = opened.first_height();
    let reaches = opened.reaches();
    drop(opened);
    let index_len = std::fs::metadata(directory.join(BLOCK_INDEX))
        .unwrap()
        .len();
    for (file, _) in beside {
        assert!(
            !directory.join(file).exists(),
            "{name}: {file} was left beside the log"
        );
    }
    let _ = std::fs::remove_dir_all(&directory);
    (first, reaches, index_len, (reaches - first) * 8)
}

/// Every durable step of a compaction, and the start after a stop at each.
#[test]
fn a_start_after_a_stop_at_each_step_of_a_compaction_holds_one_log() {
    let blocks = chain(20);
    let before = {
        let directory = scratch("before");
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
        drop(log);
        let held = files(&directory);
        let _ = std::fs::remove_dir_all(&directory);
        held
    };
    let after = {
        let directory = scratch("after");
        std::fs::write(directory.join(BLOCK_LOG), &before.log).unwrap();
        std::fs::write(directory.join(BLOCK_INDEX), &before.index).unwrap();
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        log.keep_from(12).unwrap();
        drop(log);
        let held = files(&directory);
        let _ = std::fs::remove_dir_all(&directory);
        held
    };
    assert_eq!(after.index.len(), 8 * 8);
    assert!(after.log.len() < before.log.len());

    let staged_log = format!("{BLOCK_LOG}.part");
    let staged_index = format!("{BLOCK_INDEX}.part");
    let hold = format!("{BLOCK_LOG}.hold");

    // Step 1: both staged files synced, nothing moved.
    let s1 = start_from(
        "staged-only",
        &before.log,
        &before.index,
        &[
            (&staged_log, &after.log),
            (&staged_index, &after.index),
            (&hold, b""),
        ],
    );
    // Step 2: the log moved and waited for, the index not yet.
    let s2 = start_from(
        "log-moved",
        &after.log,
        &before.index,
        &[(&staged_index, &after.index), (&hold, b"")],
    );
    // Step 3: both moved.
    let s3 = start_from("both-moved", &after.log, &after.index, &[(&hold, b"")]);
    // The order the comment argues against: the index moved before the log.
    let s2r = start_from(
        "index-moved-first",
        &before.log,
        &after.index,
        &[(&staged_log, &after.log), (&hold, b"")],
    );

    println!("PROBE: (first, reaches, index bytes on disk, index bytes owed)");
    println!("PROBE: staged only        {s1:?}");
    println!("PROBE: log moved first    {s2:?}");
    println!("PROBE: both moved         {s3:?}");
    println!("PROBE: index moved first  {s2r:?}");

    assert_eq!(
        s1,
        (0, 20, 160, 160),
        "a stop before either move leaves the old log"
    );
    assert_eq!(
        s2,
        (12, 20, 64, 64),
        "a stop between the moves comes back compacted"
    );
    assert_eq!(
        s3,
        (12, 20, 64, 64),
        "a stop after both moves comes back compacted"
    );
    // The reverse order is recovered too: the log is the record and the index
    // is worked out from it, so a new index over an old log is a rebuild or an
    // extension and never a belief.
    assert_eq!(s2r, (0, 20, 160, 160), "the other order leaves the old log");
}

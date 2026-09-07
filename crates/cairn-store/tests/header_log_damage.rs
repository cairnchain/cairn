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

// ---------------------------------------------------------------------------
// Merging the run collected from before a node arrived.
// ---------------------------------------------------------------------------

/// Two logs a node that joined a chain holds: the headers from where it was
/// handed on, and the run of everything before that, collected from a peer.
fn two_logs(name: &str, blocks: &[Block], at: usize) -> (PathBuf, HeaderLog, HeaderLog) {
    let directory = scratch(name);
    let mut headers = HeaderLog::open(&directory).unwrap();
    for block in &blocks[at..] {
        headers.append(&block.header).unwrap();
    }
    let mut front = HeaderLog::open_named(&directory, "headers.filling").unwrap();
    for block in &blocks[..at] {
        front.append(&block.header).unwrap();
    }
    (directory, headers, front)
}

/// **A merge that cannot finish leaves the log that was there.**
///
/// The merge used to empty the log and write it again in place, so a machine
/// that stopped partway left a header log holding a prefix of the collected
/// run and nothing at all that knew it. What the next start did with that
/// prefix was delete every header the node held, in silence, because the run
/// stopped below the oldest block it kept.
///
/// A directory sitting where the staged file goes stands in for the disk that
/// would not take it: it refuses that one write and disturbs nothing else.
#[test]
fn a_merge_that_cannot_be_written_changes_nothing() {
    let blocks = chain(60);
    let (directory, mut headers, front) = two_logs("merge-refused", &blocks, 40);
    let path = directory.join(HEADER_LOG);
    let held = std::fs::read(&path).unwrap();

    std::fs::create_dir(directory.join(format!("{HEADER_LOG}.part"))).unwrap();
    let refused = headers.join(&front);
    assert!(
        refused.is_err(),
        "a merge that could not be written said it worked"
    );
    assert_eq!(
        (headers.first_height(), headers.reaches()),
        (40, 60),
        "the log is what it was before the merge was tried"
    );
    assert_eq!(
        headers.read_at(40).unwrap().unwrap().id(),
        blocks[40].header.id(),
        "and it still answers out of it"
    );
    drop(headers);
    drop(front);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        held,
        "the file itself is byte for byte what it was"
    );

    // And the next start, which is where the old cost was paid: a log holding
    // 40 to 60 is a log that leads up to the blocks, so nothing is deleted.
    let again = HeaderLog::open(&directory).unwrap();
    assert_eq!((again.first_height(), again.reaches()), (40, 60));
    let _ = std::fs::remove_dir_all(&directory);
}

/// **A merge that finishes leaves one run and nothing beside it.**
///
/// The staged file and the scratch file both go. They are a copy of every
/// header the node holds, which is 95.7 MB a year, sitting on the disk of a
/// node that has just been told to keep less.
#[test]
fn a_merge_that_finishes_leaves_one_run_and_no_staged_file() {
    let blocks = chain(60);
    let (directory, mut headers, front) = two_logs("merge-done", &blocks, 40);

    headers.join(&front).expect("the disk is working");
    assert_eq!(
        (headers.first_height(), headers.reaches()),
        (0, 60),
        "one run, from the older of the two"
    );
    for (height, block) in blocks.iter().enumerate() {
        let found = headers.read_at(height as u64).unwrap().unwrap();
        assert_eq!(found.id(), block.header.id(), "header {height}");
    }
    drop(headers);
    drop(front);

    let left: Vec<String> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(HEADER_LOG) && name != HEADER_LOG)
        .collect();
    assert!(
        left.is_empty(),
        "the merge left files beside the log: {left:?}"
    );
    let again = HeaderLog::open(&directory).unwrap();
    assert_eq!((again.first_height(), again.reaches()), (0, 60));
    let _ = std::fs::remove_dir_all(&directory);
}

/// **Two runs that do not meet are refused before anything is written.**
///
/// The merge used to be appends: the first record of the second run that did
/// not follow on was refused, and by then the log had been emptied and half
/// refilled. There is nowhere in this code that can happen to, and this holds
/// the door shut.
#[test]
fn two_runs_that_do_not_meet_are_refused_with_the_log_untouched() {
    let blocks = chain(60);
    let (directory, mut headers, _front) = two_logs("merge-gap", &blocks, 40);
    // A run that stops short of where the log begins, which is what an
    // interrupted collection holds.
    let mut short = HeaderLog::open_named(&directory, "headers.short").unwrap();
    for block in &blocks[..30] {
        short.append(&block.header).unwrap();
    }

    let refused = headers.join(&short);
    assert!(refused.is_err(), "a run with a hole in it was merged");
    assert_eq!(
        (headers.first_height(), headers.reaches()),
        (40, 60),
        "and the log is untouched"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

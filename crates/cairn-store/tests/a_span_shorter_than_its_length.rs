//! An index entry naming fewer bytes than a record's length takes.
//!
//! The nightly campaign in `fuzz_record_framing.rs` failed on seven of the
//! eight runs between 14 and 21 September 2026, every time on the last record
//! the log claimed and every time in the same words: "failed as a filesystem
//! error rather than as damage: could not reach the block log: failed to fill
//! whole buffer". This is that shape built by hand.
//!
//! `bounds` refused a span that was empty, that reached past the log, or that
//! was longer than a record can be, and nothing else. A span of one to three
//! bytes is none of those and is shorter than the four bytes that say how long
//! a record is. When it is the last entry and ends where the file ends, the
//! start keeps it, and `read` ran off the end of the file inside `read_exact`:
//! an `UnexpectedEof`, reported as a disk that cannot be reached, about eight
//! bytes of a derived file on a disk that answers every read.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_store::{BlockLog, StoreError, BLOCK_INDEX, BLOCK_LOG};

const NOW: u64 = 2_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-short-span-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn chain() -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[3u8; 32]);
    let mut state = LedgerState::archiving();
    let mut clock = 1_000u64;
    (0..2)
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

/// A log of two real blocks and a third index entry `tail` bytes past the
/// second, with the log holding exactly those bytes so that the index and the
/// log agree on where the log ends and the start keeps the entry.
fn a_log_whose_last_entry_is(tail: &[u8], name: &str) -> BlockLog {
    let directory = scratch(name);
    let mut log = Vec::new();
    let mut index = Vec::new();
    for block in chain() {
        let body = block.encode();
        log.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        log.extend_from_slice(&body);
        index.extend_from_slice(&u64::try_from(log.len()).unwrap().to_le_bytes());
    }
    log.extend_from_slice(tail);
    index.extend_from_slice(&u64::try_from(log.len()).unwrap().to_le_bytes());
    std::fs::write(directory.join(BLOCK_LOG), &log).unwrap();
    std::fs::write(directory.join(BLOCK_INDEX), &index).unwrap();
    let (opened, _) = BlockLog::open(&directory).expect("a start is never refused for content");
    assert_eq!(
        opened.len(),
        3,
        "premise: the start did not keep the short entry, so nothing below is reached"
    );
    opened
}

/// A span of one, two or three bytes is an index entry that cannot name a
/// record, and is refused as one.
///
/// Nothing asked this, so the read ran off the end of the file and the node
/// was told the block log could not be reached: `catch_up_from` stopped the
/// restart's catch-up on it and a peer asking for that height was answered
/// nothing, both in the words for a failing disk.
#[test]
fn a_span_shorter_than_a_length_prefix_is_misindexed_and_not_a_disk_fault() {
    for short in 1..4usize {
        let log = a_log_whose_last_entry_is(&vec![0u8; short], &format!("short-{short}"));
        match log.read(2) {
            Err(StoreError::Misindexed { index: 2, .. }) => {}
            Err(StoreError::Io(_)) => panic!(
                "a span of {short} bytes the index names was reported as a disk that cannot \
                 be reached, on a disk that answered every read"
            ),
            _ => panic!("a span of {short} bytes was not refused as an index entry that cannot name a record"),
        }
        let _ = std::fs::remove_dir_all(log.path().parent().unwrap());
    }
}

/// And a span of exactly four bytes is not refused for its length: it holds a
/// length prefix, and what that prefix says is a question for the record.
///
/// The edge of the rule above. Without this a refusal drawn one byte too wide
/// would pass, and would call a record the index has right an index fault.
#[test]
fn a_span_that_holds_only_a_length_prefix_is_read_as_a_record() {
    let log = a_log_whose_last_entry_is(&0u32.to_le_bytes(), "prefix-only");
    match log.read(2) {
        Err(StoreError::Malformed { index: 2, .. }) => {}
        _ => panic!(
            "a four byte span saying its record is empty was not read as a record that is \
             not a block"
        ),
    }
    let _ = std::fs::remove_dir_all(log.path().parent().unwrap());
}

/// The other edge of the same check: a span longer than the largest record
/// there can be is refused as an index fault, and a span exactly that long is
/// read as a record.
///
/// Nothing reached this edge, since it takes a log of more than four
/// megabytes, so a check that refused nothing for its length, or refused one
/// byte too early, passed.
#[test]
fn a_span_longer_than_any_record_is_misindexed_and_one_at_the_ceiling_is_read() {
    let ceiling = u64::try_from(cairn_store::MAX_RECORD_BYTES).unwrap() + 4;
    for (over, name) in [(1u64, "over"), (0, "at")] {
        let directory = scratch(&format!("long-{name}"));
        let block = chain().remove(0);
        let body = block.encode();
        let mut log = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
        log.extend_from_slice(&body);
        let first = u64::try_from(log.len()).unwrap();
        // The second record's prefix says it is as long as a record can be,
        // and the file runs on as far as the index says, as zeros.
        log.extend_from_slice(
            &u32::try_from(cairn_store::MAX_RECORD_BYTES)
                .unwrap()
                .to_le_bytes(),
        );
        let end = first + ceiling + over;
        log.resize(usize::try_from(end).unwrap(), 0);
        let mut index = first.to_le_bytes().to_vec();
        index.extend_from_slice(&end.to_le_bytes());
        std::fs::write(directory.join(BLOCK_LOG), &log).unwrap();
        std::fs::write(directory.join(BLOCK_INDEX), &index).unwrap();

        let (opened, _) = BlockLog::open(&directory).expect("a start is never refused");
        assert_eq!(opened.len(), 2, "premise: the start kept both entries");
        let read = opened.read(1);
        let _ = std::fs::remove_dir_all(&directory);
        if over > 0 {
            assert!(
                matches!(read, Err(StoreError::Misindexed { index: 1, .. })),
                "a span one byte longer than any record was not refused as an index fault"
            );
        } else {
            assert!(
                matches!(read, Err(StoreError::Malformed { index: 1, .. })),
                "a span exactly as long as a record can be was refused before it was read"
            );
        }
    }
}

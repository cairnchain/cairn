//! What `append` does with the bytes past the last record the log stands
//! behind.
//!
//! Two kinds of bytes can be standing there, and `append` treats them
//! differently on purpose.
//!
//! The first is what a walk stopped at: a whole record that would not decode,
//! and everything after it. Recovery leaves those in place and counts them in
//! `trailing`, and `append` cuts them before it writes, because writing over
//! the front of them is the moment nothing can reach them again. Left there,
//! whatever the new record does not cover is read at the next start as more
//! of the log.
//!
//! The second is what a log sets aside when its records disagree about where
//! it starts. Nothing is counted in `trailing` for those, and `append` writes
//! over them in place without cutting. That is what lets a node handed its
//! first block again, which `cairn_net` does on a network that pins its first
//! block the moment it finds its log holding nothing, have the rest of its
//! records back at the next start rather than none of them.
//!
//! The guard in `append` that tells the two apart was held by no test. Read
//! as never true, the first kind stayed; read as always true, the second kind
//! went. The one test that reached it wrote a record longer than the tail it
//! was writing over, which covers the tail whether it is cut or not.

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
use cairn_store::{BlockLog, BLOCK_INDEX, BLOCK_LOG};

const NOW: u64 = 2_000_000_000;

/// Where `state_root` sits inside a record: four bytes of length prefix, then
/// the header's version, network, height, previous and transactions root.
const STATE_ROOT_IN_RECORD: u64 = 4 + 2 + 4 + 8 + 32 + 32;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-writes-over-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

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

fn built(directory: &Path, blocks: &[Block]) {
    let (mut log, _) = BlockLog::open(directory).unwrap();
    for block in blocks {
        log.append(block).unwrap();
    }
}

fn put(path: &Path, at: u64, value: &[u8]) {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(value).unwrap();
}

fn file_length(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

/// Three records set aside by a walk, and one block written after them.
///
/// Record three is made not to decode and the index is lost, so the walk
/// keeps three records and leaves three in place. The block then written at
/// height three is not the one the log held there, which is what a node
/// writes after taking the height from another branch, and it is one record
/// long against a tail of three.
///
/// Without the cut, the two records after it were still in the file behind
/// the one just written, lined up on a record boundary because blocks of the
/// same shape are the same length. The next start read them as records four
/// and five: a log reporting six blocks where four were written, two of them
/// from a branch this node had left, and the one at height four served.
#[test]
fn bytes_a_walk_set_aside_go_when_the_log_is_written_over_them() {
    let blocks = chain(6);
    let directory = scratch("walk");
    built(&directory, &blocks);

    // The last four bytes of a block with no transfers are how many it has.
    // Past what a block may carry, so the record will not decode.
    let index = std::fs::read(directory.join(BLOCK_INDEX)).unwrap();
    let end_of_three = u64::from_le_bytes(index[24..32].try_into().unwrap());
    put(
        &directory.join(BLOCK_LOG),
        end_of_three - 4,
        &u32::MAX.to_le_bytes(),
    );
    std::fs::remove_file(directory.join(BLOCK_INDEX)).unwrap();

    let (mut log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        (recovered.blocks, recovered.unreadable),
        (3, Some(3)),
        "the fixture is a walk stopped at record three"
    );
    assert!(
        recovered.left_in_place > 0,
        "and the records from three on are still in the file"
    );

    let mut other = blocks[3].clone();
    other.header.nonce ^= 1;
    assert_eq!(other.encode().len(), blocks[3].encode().len());
    log.append(&other).unwrap();
    assert_eq!(
        file_length(&directory.join(BLOCK_LOG)),
        log.bytes(),
        "bytes the walk set aside are still in the file past the record written \
         over them"
    );
    drop(log);

    let (log, again) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        again.blocks, 4,
        "the next start read set-aside records as part of the log"
    );
    assert!(
        matches!(log.read_at(4), Ok(None)),
        "height four is answered from a record this log set aside, on a branch \
         it has left"
    );
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
}

/// A log that could not place its first record, handed that record again.
///
/// A byte of record zero's state root is changed, so record one no longer
/// names it and the log sets all six aside, leaving every byte where it was.
/// The first block is then written again, as a node on a network that pins
/// its first block writes it on finding its log holding nothing. That write
/// lands over record zero and puts it right, and the five records after it
/// are the ones that were there.
///
/// Cutting before that write, which is what the guard read as always true
/// did, left one record of six in the file: an archivist, the one role that
/// cannot fetch a block again, lost every record the set-aside had been
/// careful to keep, on its first write after it.
#[test]
fn records_set_aside_for_a_first_record_are_kept_under_the_write_that_puts_it_right() {
    let blocks = chain(6);
    let directory = scratch("set-aside");
    built(&directory, &blocks);
    let path = directory.join(BLOCK_LOG);
    let size = file_length(&path);

    let before = std::fs::read(&path).unwrap()[usize::try_from(STATE_ROOT_IN_RECORD).unwrap()];
    put(&path, STATE_ROOT_IN_RECORD, &[before ^ 0x01]);
    let (mut log, recovered) = BlockLog::open(&directory).unwrap();
    assert!(
        log.is_empty() && recovered.blocks_set_aside == 6,
        "the fixture is a log that set its six records aside"
    );

    log.append(&blocks[0]).unwrap();
    assert_eq!(
        file_length(&path),
        size,
        "writing the first block again cut the records the log had set aside"
    );
    drop(log);

    let (log, again) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        again.blocks, 6,
        "the records after the one written again did not come back"
    );
    assert_eq!(log.read_at(5).unwrap().unwrap().id(), blocks[5].id());
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
}

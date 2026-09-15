//! What vouches for a record when the record after it cannot be reached.
//!
//! `named_by_its_neighbour` says: "A neighbour that cannot be reached at all
//! is not this record's failure and does not condemn it." True. The question
//! `read_at` needed answered is what then stands behind the record's bytes,
//! and the answer used to be the record *before* it, which can only confirm
//! the `previous` field: forty bytes of a record that is hundreds. The other
//! fields of the header, the state root among them, were then served as truth.
//!
//! What was lost in that state is the way of finding the neighbour and not the
//! neighbour: the index entry would not read, and the record itself sat where
//! it always had, at the offset this record's own checked length reaches. So
//! the neighbour is looked for there too, and the check that names every byte
//! of the header is available again.
//!
//! Reaching that state takes two faults, one in the index and one in the log,
//! which is why the single-flip sweep in
//! `audit_what_the_block_log_vouches_for.rs` never sees it: that sweep flips
//! one byte at a time. The header log beside it has no derived file to lose a
//! neighbour through, and refuses the same record under the analogous damage.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_store::{
    BlockLog, HeaderLog, StoreError, BLOCK_INDEX, BLOCK_LOG, HEADER_BYTES, HEADER_LOG,
};

const NOW: u64 = 2_000_000_000;

/// Where `state_root` sits inside a block record: four bytes of length, then
/// version, network, height, previous and transactions root.
const STATE_ROOT_IN_RECORD: usize = 4 + 2 + 4 + 8 + 32 + 32;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-neighbour-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn chain(count: usize) -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[6u8; 32]);
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

/// A six record log with one byte of record two's state root flipped and the
/// index entry ending record three set to a value `bounds` refuses.
fn damaged(name: &str, blocks: &[Block]) -> PathBuf {
    let directory = scratch(name);
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in blocks {
            log.append(block).unwrap();
        }
    }
    let index = std::fs::read(directory.join(BLOCK_INDEX)).unwrap();
    let start_of_two = u64::from_le_bytes(index[8..16].try_into().unwrap());
    let at = start_of_two + STATE_ROOT_IN_RECORD as u64;
    let before = std::fs::read(directory.join(BLOCK_LOG)).unwrap()[at as usize];
    put(&directory.join(BLOCK_LOG), at, &[before ^ 0x01]);
    put(&directory.join(BLOCK_INDEX), 3 * 8, &u64::MAX.to_le_bytes());
    directory
}

/// The measurement: what each store answers under two faults.
#[test]
fn a_record_is_vouched_for_by_its_neighbour_even_when_the_index_lost_it() {
    let blocks = chain(6);
    let directory = damaged("block-log", &blocks);

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(
        recovered.blocks, 6,
        "the open decodes record zero and reads sixteen bytes"
    );
    assert_eq!(recovered.unreadable, None);

    let mut served_wrong = 0usize;
    let mut refused = Vec::new();
    for height in 0..6u64 {
        match log.read_at(height) {
            Ok(Some(block)) => {
                if block.encode() != blocks[height as usize].encode() {
                    served_wrong += 1;
                    println!(
                        "PROBE: height {height} served with state root {:?}, mined {:?}",
                        block.header.state_root, blocks[height as usize].header.state_root
                    );
                }
            }
            Ok(None) => panic!("height {height} vanished"),
            Err(error) => refused.push((height, error.to_string())),
        }
    }
    println!("PROBE: block log, one byte in record 2 and one bad index entry for record 3:");
    println!(
        "PROBE:   {served_wrong} height(s) served with a block nobody mined, refused: {refused:?}"
    );
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);

    // The same shape on the header log: a byte in record two, record three
    // damaged as a whole. The header log has no index to lose a neighbour
    // through, so its neighbour is always reachable, and the changed byte is
    // caught by the link that neighbour carries.
    let directory = scratch("header-log");
    {
        let mut headers = HeaderLog::open(&directory).unwrap();
        for block in &blocks {
            headers.append(&block.header).unwrap();
        }
    }
    let path = directory.join(HEADER_LOG);
    let at = 2 * HEADER_BYTES + STATE_ROOT_IN_RECORD - 4;
    let before = std::fs::read(&path).unwrap()[at];
    put(&path, at as u64, &[before ^ 0x01]);
    put(&path, 3 * HEADER_BYTES as u64, &[0xff; HEADER_BYTES]);
    let headers = HeaderLog::open(&directory).unwrap();
    let header_two = headers.read_at(2);
    println!(
        "PROBE: header log, the same byte in record 2 and record 3 damaged: height 2 -> {:?}",
        header_two
            .as_ref()
            .map(|found| found.as_ref().map(|header| header.state_root))
    );
    assert!(
        matches!(header_two, Err(StoreError::Unlinked { height: 2 })),
        "the header log refuses a record with a changed byte"
    );
    let _ = std::fs::remove_dir_all(&directory);

    // The two logs answer the same way now, which is what the asymmetry
    // measured before the neighbour was looked for in the log as well as in
    // the index. It was one: the block log served record two with a changed
    // state root, and the header log beside it refused the same damage.
    assert_eq!(
        served_wrong, 0,
        "the block log served a record with a changed state root when the index \
         entry for the record beside it was unreadable, which is the state the \
         header log refuses under the same damage"
    );
}

/// The property `read_at` is written to hold.
///
/// It did not, until the neighbour was looked for where the log puts it rather
/// than only where the index says: its header sits at the offset record two's
/// own checked length reaches, and nothing read it there.
#[test]
fn a_changed_byte_is_refused_even_when_the_index_entry_beside_it_is_not() {
    let blocks = chain(6);
    let directory = damaged("property", &blocks);
    let (log, _) = BlockLog::open(&directory).unwrap();
    let answer = log
        .read_at(2)
        .map(|found| found.map(|block| block.encode()));
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        !matches!(&answer, Ok(Some(bytes)) if *bytes != blocks[2].encode()),
        "height 2 answered with a block nobody mined"
    );
}

use cairn_primitives::codec::Encode;

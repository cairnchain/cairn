//! `a_partial_offset_is_cut_back` in `block_log.rs` does not look at the
//! index after the open. Its two assertions, the count and the replay, are
//! satisfied by a start that leaves the three stray bytes in place: `whole`
//! is what the rest of recovery reads, and the next append writes over the
//! fragment. So the cut it is named for is held by nothing.
//!
//! This holds it, and says what the cut is worth: without it the index is
//! three bytes longer than the entries it holds until the next append, and
//! nothing reads those bytes. A guard with a small consequence, written down
//! so that it is a known one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::Write;
use std::path::PathBuf;

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_store::{BlockLog, BLOCK_INDEX};

const NOW: u64 = 2_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-partial-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn chain(count: usize) -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[9u8; 32]);
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

#[test]
fn a_partial_offset_is_gone_from_the_index_once_the_log_is_open() {
    let blocks = chain(3);
    let directory = scratch("cut");
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }
    let index = directory.join(BLOCK_INDEX);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&index)
        .unwrap()
        .write_all(&[0x01, 0x02, 0x03])
        .unwrap();
    assert_eq!(std::fs::metadata(&index).unwrap().len(), 27);

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(recovered.blocks, 3);
    // Before anything is appended, which is when the cut has to have happened
    // for the test to be about the cut.
    let held = std::fs::metadata(&index).unwrap().len();
    println!("PROBE: index was 27 bytes, the open left it {held}");
    assert_eq!(held, 24, "the stray bytes were left on the index");
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
}

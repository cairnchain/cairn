//! What asking a block log to keep from one past its tip does.
//!
//! `keep_from(height)` drops everything below `height`, so `keep_from` of the
//! height just past the last record drops everything: the whole log goes,
//! including the window a reorganisation reads bodies back from. That is
//! arithmetic rather than a defect, and it is written down here because it is
//! still reachable from the outside. A node's `trim_history` no longer passes
//! `tip + 1` unconditionally; it passes `cut_for(anchor, ...)`, which is
//! `anchor + 1 - affordable`, and `affordable` is the operator's byte budget
//! divided by the average record. A budget below one average block makes
//! `affordable` zero, and `Node::keep_blocks` takes any number.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_store::BlockLog;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-trim-{}-{name}", std::process::id()));
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

/// `keep_from` of the height just past the last record empties the log
/// entirely, so nothing below the tip can be read back afterwards. A node that
/// let go of the deep bodies in memory (as it does once they are "on disk")
/// would hold them nowhere.
///
/// Held as the property it is, so that whatever computes the cut is read
/// against it: this is what asking for one block too many costs.
#[test]
fn keep_from_one_past_the_tip_clears_the_whole_log() {
    let directory = scratch("clears");
    let blocks = chain(80);
    let (mut log, _) = BlockLog::open(&directory).unwrap();
    for block in &blocks {
        log.append(block).unwrap();
    }
    let tip = blocks.last().unwrap().header.height; // 79
    assert_eq!(log.len(), 80);
    assert_eq!(log.reaches(), tip + 1);

    // A window block a reorganisation might read back, present before the trim.
    assert!(log.read_at(10).unwrap().is_some());

    // This is `trim_history`'s operative line, verbatim.
    log.keep_from(tip + 1).unwrap();

    assert_eq!(
        log.len(),
        0,
        "the whole log was cleared, not trimmed to a window"
    );
    assert!(log.is_empty());
    assert!(
        log.read_at(10).unwrap().is_none(),
        "a window block a failed reorganisation would need is gone"
    );
    assert!(
        log.read_at(tip).unwrap().is_none(),
        "even the block the ledger stands for is gone"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

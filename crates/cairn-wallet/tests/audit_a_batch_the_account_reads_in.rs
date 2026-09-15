//! How many blocks the account takes in one go.
//!
//! `CATCH_UP_BATCH` is five hundred and twelve, and the note above it says
//! why: a wallet catching up on a long absence reads them in batches rather
//! than holding the chain while it walks the lot, so the page stays answerable
//! and the next block still arrives.
//!
//! Nothing could fail on it. Every test that calls `follow` calls it in a loop
//! until it returns nothing, which is the right way to use it and is why the
//! number never showed: set it to `u64::MAX` and the loop runs once instead of
//! twice and every one of them passes. The wallet would then hold the chain
//! for the length of whatever absence it was catching up on, which is the one
//! thing the batch exists to stop.
//!
//! Counted rather than timed. What one call takes is a number both a fast
//! machine and a slow one agree on.

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
use cairn_wallet::{Wallet, CATCH_UP_BATCH};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-batch-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

#[test]
fn one_call_reads_a_batch_and_leaves_the_rest_for_the_next() {
    let directory = scratch("batch");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[4; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    // A literal, and not the constant plus one. Written in terms of the
    // constant this test moves with it and holds only the mechanism, which is
    // what left the number unmeasured in the first place.
    let count = 513u64;
    assert!(
        CATCH_UP_BATCH < count,
        "this test offers {count} blocks to watch a batch of {CATCH_UP_BATCH} taken, and has to \
         offer more than a batch"
    );
    let rules = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let chain: Vec<Block> = (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(rules.initial_reward, secret.public_key())],
            );
            let block =
                assemble_block(&state, coinbase, Vec::<Transfer>::new(), &rules, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &rules, NOW).unwrap();
            block
        })
        .collect();

    let (wallet, _) = Wallet::open(&key_file, rules, &directory.join("data")).unwrap();
    for block in &chain {
        wallet.node().submit_block(block.clone()).unwrap();
    }

    let first = wallet.follow();
    assert_eq!(
        first as u64, CATCH_UP_BATCH,
        "one call read {first} blocks of {count}, so the chain was held for the whole absence \
         rather than a batch of it"
    );
    let second = wallet.follow();
    assert_eq!(
        second as u64,
        count - CATCH_UP_BATCH,
        "and what is left over is what the next call takes"
    );
    assert_eq!(wallet.follow(), 0, "and then there is nothing left");

    assert_eq!(
        wallet.history_covers().through,
        Some(count - 1),
        "between them the calls reached the tip"
    );

    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

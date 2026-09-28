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

/// Mines blocks on a private ledger, paying whoever is named.
#[derive(Clone)]
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn mine(&mut self, to: &cairn_crypto::PublicKey) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(self.params.initial_reward, *to)]);
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }
}

/// A note the account took up from its node at the end of a batch, paid by a
/// branch that then lost, does not stay in the account.
///
/// The node watches where this key's notes fall, including notes paid by
/// blocks the account has not read yet, and at the end of every batch the
/// account takes up what the node knows. Such a note came in with no height,
/// which the account read as a note from below where it began, that no
/// switch can take away, so a note from a branch that lost stayed for good,
/// shown as stranded money and put to archivists. Every test of a switch read
/// the account to the tip first.
#[test]
fn a_note_of_a_branch_that_lost_does_not_stay_in_the_account() {
    let directory = scratch("lost-branch");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[22; 32]);
    let mine = secret.public_key();
    let stranger = SecretKey::from_bytes(&[7; 32]).public_key();
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    // A hot set of four, so a note falls four blocks after it is paid, and a
    // shallow burial so a switch of a few blocks is followed.
    let rules = ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4);
    let data = directory.join("data");
    let (wallet, _) = Wallet::open(&key_file, rules, &data).unwrap();

    // Blocks to a stranger, one reward to this key near the top, and six more
    // so it has fallen by the time the wallet looks.
    let mut forge = Forge {
        params: rules,
        state: LedgerState::new(),
        clock: 1_000,
    };
    for _ in 0..CATCH_UP_BATCH + 83 {
        wallet.node().submit_block(forge.mine(&stranger)).unwrap();
    }
    let mut winning = forge.clone();
    wallet.node().submit_block(forge.mine(&mine)).unwrap();
    for _ in 0..6 {
        wallet.node().submit_block(forge.mine(&stranger)).unwrap();
    }
    // One look, one batch: the account is behind the node, which has watched
    // this key's reward fall.
    assert_eq!(
        wallet.follow() as u64,
        CATCH_UP_BATCH,
        "fixture: one batch was read"
    );

    // A heavier branch from the block before the reward, which never paid
    // this key.
    for _ in 0..9 {
        wallet.node().submit_block(winning.mine(&stranger)).unwrap();
    }
    wallet.follow_to_the_tip();
    let holdings = wallet.holdings();
    let movements = wallet.history();
    wallet.shutdown();
    drop(wallet);
    let (again, _) = Wallet::open(&key_file, rules, &data).unwrap();
    again.follow_to_the_tip();
    let after_restart = again.holdings();
    again.shutdown();
    drop(again);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        movements.is_empty(),
        "fixture: nothing on the chain as it stands ever paid this key"
    );
    assert_eq!(
        (holdings.total(), after_restart.total()),
        (
            cairn_primitives::Amount::ZERO,
            cairn_primitives::Amount::ZERO
        ),
        "a key the chain never paid is shown money: the reward of a branch that lost stays in \
         the account"
    );
}

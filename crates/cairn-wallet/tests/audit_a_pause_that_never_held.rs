//! The wait between two questions to the network, and the one wallet it never
//! held for.
//!
//! `SECURITY.md` names this sentence as one of the shapes every defect here has
//! had: "These are the places that were asked about and not answered for." True
//! of every place in the set until there are more than one message carries.
//!
//! It was repaired on one side. `still_outstanding` now keeps only the half a
//! question actually carried, which is what that name means. The comparison
//! that reads it was left reading every place this wallet holds, so it compares
//! a set of any size against a set of at most `MAX_PROVEN`. Past that many the
//! inclusion is false whatever has happened, and the wait never holds.
//!
//! The wallet it never held for is the one that needs it: more notes it cannot
//! place than one question carries, asking, getting nothing, and putting the
//! same question to the same strangers on every redraw of whatever is showing
//! the balance.
//!
//! Held by a count of the questions the node put to the network, and not by a
//! clock. A wait that holds is a count that stops going up, which is a thing
//! two machines agree about where the length of the wait is not.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::MAX_PROVEN;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Every block pays this key, so the notes it cannot place outnumber the places
/// one question carries. The suite beside this one pays every third block on
/// purpose, to stay under that number.
const PAID: usize = 220;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-pause-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(300);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// A wallet holding more notes it cannot place than one question carries.
fn a_wallet_with_more_stranded_than_one_question_carries(name: &str) -> (Wallet, PathBuf) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[3; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");

    let rules = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let chain: Vec<Block> = (0..PAID)
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

    {
        let (wallet, _) = Wallet::open(&key_file, rules, &data).unwrap();
        for block in &chain {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        while wallet.follow() > 0 {}
        assert!(wallet.node().write_ledger(), "the ledger went down first");
        wallet.node().keep_blocks(1);
        wait_for("the node to drop the blocks below its ledger", || {
            wallet.node().archived_at(0).is_none()
        });
    }

    // Started again from the ledger, which is what takes the places out of the
    // node's hands and leaves the wallet with notes it cannot place.
    let (wallet, _) = Wallet::open(&key_file, rules, &data).unwrap();
    while wallet.follow() > 0 {}
    (wallet, directory)
}

#[test]
fn a_wallet_with_more_stranded_notes_than_one_question_still_waits() {
    let (wallet, directory) = a_wallet_with_more_stranded_than_one_question_carries("many");
    let holdings = wallet.holdings();
    assert!(
        holdings.unprovable.len() > MAX_PROVEN,
        "this test needs more notes it cannot place than one question carries, and has {}",
        holdings.unprovable.len()
    );

    let first = wallet.recover_stranded();
    let after_one = wallet.node().proofs_asked_for();
    assert_eq!(
        after_one, 1,
        "asking once put {after_one} questions to the network"
    );

    // Whatever is showing the balance redraws, and redraws again. Nothing has
    // changed: the same places, the same peers, the same nothing.
    let _ = wallet.recover_stranded();
    let _ = wallet.recover_stranded();
    let _ = wallet.recover_stranded();
    let after_four = wallet.node().proofs_asked_for();

    assert_eq!(
        after_four, 1,
        "four redraws put {after_four} questions to the network where the wait \
         should have made it one: with more notes than a question carries, the \
         set that decides whether to wait is compared against one that cannot \
         contain it, so the answer is always that this is a new question"
    );
    assert_eq!(
        first.stranded,
        wallet.recover_stranded().stranded,
        "and what it reports does not change while it waits"
    );

    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

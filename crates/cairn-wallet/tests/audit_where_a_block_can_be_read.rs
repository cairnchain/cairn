//! Where the account starts reading, on a node that has let go of its oldest
//! blocks.
//!
//! An account that has to start over reads the chain again from the bottom.
//! When the block it asks for is not there, it asks the node where to begin
//! instead, and it used to ask where the branch begins.
//!
//! That is a true answer to a different question. The branch a node follows
//! begins at zero and goes on beginning at zero however much of it the node
//! has let go of; where a block can be *read* from is where the log starts,
//! which is wherever `--keep` last trimmed it. On every node past that size
//! the two numbers differ, and the account walked to a height the node had
//! nothing at, found the branch did not begin above where it already stood,
//! and stopped there for good.
//!
//! `cairn-net` names both numbers and says why, in the note on `blocks_from`:
//! without it "a block dropped off the bottom and a block not yet written look
//! the same", which is the same defect the explorer's index had.
//!
//! Two ordinary things make an account start over: a reorganisation, which is
//! the whole of `History::forget`, and an account file that would not read
//! back, which `cairnd` prints a line about saying the balance beside it
//! becomes right on its own. Neither did.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

use std::path::PathBuf;

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const HEIGHT: u64 = 90;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-reading-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn a_chain(to: &cairn_crypto::PublicKey, count: u64) -> Vec<Block> {
    let rules = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase =
                CoinbaseTransaction::new(height, vec![Note::new(rules.initial_reward, *to)]);
            let block =
                assemble_block(&state, coinbase, Vec::<Transfer>::new(), &rules, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &rules, NOW).unwrap();
            block
        })
        .collect()
}

/// A node holding `HEIGHT` blocks, with or without a ledger written down.
///
/// Writing the ledger and starting again is what cuts the log to the ledger's
/// own height, and it is the ordinary life of a node: `cairnd` writes one from
/// its upkeep round. So the shape below with `ledger` set is not a corner, it
/// is every node that has been restarted once.
struct Chain {
    directory: PathBuf,
    key_file: PathBuf,
    data: PathBuf,
}

impl Chain {
    fn open(name: &str, ledger: bool) -> (Self, Wallet) {
        let directory = scratch(name);
        std::fs::create_dir_all(&directory).unwrap();
        let key_file = directory.join("key");
        let secret = SecretKey::from_bytes(&[3; 32]);
        cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
        let data = directory.join("data");
        let chain = a_chain(&secret.public_key(), HEIGHT);

        let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
        for block in &chain {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        wallet.follow_to_the_tip();
        if ledger {
            // The ledger, and the blocks below it dropped by the budget, which
            // is what drops blocks: a start no longer cuts the log at the
            // ledger.
            assert!(wallet.node().write_ledger());
            wallet.node().keep_blocks(1);
            let started = std::time::Instant::now();
            while wallet.node().blocks_from().unwrap_or(0) == 0 {
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(120),
                    "the node never dropped the blocks below its ledger"
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        (
            Self {
                directory,
                key_file,
                data,
            },
            wallet,
        )
    }

    /// Throws the account away and opens both again, which is what a
    /// reorganisation and an account file that would not read back both leave.
    fn starting_over(&self, wallet: Wallet) -> Wallet {
        drop(wallet);
        std::fs::remove_file(self.data.join("history.dat")).unwrap();
        let (wallet, _) = Wallet::open(&self.key_file, params(), &self.data).unwrap();
        wallet
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn read_everything(wallet: &Wallet) -> usize {
    let mut read = 0usize;
    loop {
        let taken = wallet.follow();
        read += taken;
        if taken == 0 {
            return read;
        }
    }
}

#[test]
fn an_account_starting_over_reads_what_the_node_still_has() {
    let (chain, wallet) = Chain::open("restarted", true);
    let tip = wallet.node().height();
    let wallet = chain.starting_over(wallet);

    let readable_from = wallet.node().blocks_from();
    let branch_starts_at = wallet
        .node()
        .with_chain(cairn_chain::ChainStore::branch_start);
    assert_eq!(
        branch_starts_at,
        Some(0),
        "the branch this node follows still begins at zero"
    );
    assert!(
        readable_from > Some(0),
        "a node that wrote its ledger and started again was meant to have cut its log"
    );
    assert!(
        wallet.node().archived_at(0).is_none(),
        "and the block the account asks for first was meant to be gone"
    );

    let read = read_everything(&wallet);

    // Before this the account asked where the branch begins, was told zero,
    // found zero was not above the zero it already stood at, and stopped. It
    // read nothing, and went on reading nothing for the life of the wallet.
    assert!(
        read > 0,
        "an account starting over read no block at all, on a node holding {readable_from:?} up to {tip:?}"
    );
    let covers = wallet.history_covers();
    assert_eq!(
        covers.from, readable_from,
        "it began somewhere other than where the node can be read from"
    );
    assert_eq!(covers.through, tip, "it did not reach the tip");
}

/// And a node that has not written a ledger yet still holds every block, so
/// there is nothing to skip and the account begins at the first one.
///
/// This is what says the number above is read off the log rather than being a
/// way of always jumping forward.
#[test]
fn an_account_starting_over_on_a_whole_log_begins_at_the_first_block() {
    let (chain, wallet) = Chain::open("whole", false);
    let tip = wallet.node().height();
    let wallet = chain.starting_over(wallet);

    assert_eq!(
        wallet.node().blocks_from(),
        Some(0),
        "this node was meant to still hold every block"
    );
    let read = read_everything(&wallet);

    assert_eq!(
        read as u64, HEIGHT,
        "it did not read every block on the chain"
    );
    let covers = wallet.history_covers();
    assert_eq!(
        covers.from,
        Some(0),
        "it began somewhere other than the first block"
    );
    assert_eq!(covers.through, tip, "it did not reach the tip");
}

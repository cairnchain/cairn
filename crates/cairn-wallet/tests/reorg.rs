//! What the wallet's own history does when a branch it had read is undone.
//!
//! The ledger the node keeps is put back correctly on a reorganisation (that
//! was the fix in the most recent commit). The wallet's *history* (its own
//! "What happened" account, read forward block by block) is a separate store,
//! and this checks whether it survives the same event.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A private ledger that can fork, so two rival branches can be built off a
/// shared prefix.
struct Chain {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            params: ConsensusParams::testnet(),
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn fork(&self) -> Self {
        Self {
            params: self.params,
            state: self.state.clone(),
            clock: self.clock,
        }
    }

    /// One block paying `to` its coinbase.
    fn mine(&mut self, to: &PublicKey) -> Block {
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

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-wallet-reorg-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// After a reorganisation undoes a block that paid this key, its history must
/// not still list that payment: the note was undone, the money is not there,
/// and the ledger the node keeps already knows it.
#[test]
fn a_reorganisation_does_not_leave_a_phantom_movement_in_the_history() {
    let directory = scratch("phantom");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[1; 32]);
    let mine = secret.public_key();
    let stranger = SecretKey::from_bytes(&[7; 32]).public_key();
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let params = ConsensusParams::testnet();
    let reward = params.initial_reward;
    let (wallet, _) = Wallet::open(&key_file, params, &directory.join("data")).unwrap();

    // A shared first block, paying this key: both branches start from it.
    let mut common = Chain::new();
    let block0 = common.mine(&mine);
    wallet.node().submit_block(block0).unwrap();

    // Branch A: one more block, also paying this key. This is the block the
    // reorganisation will undo.
    let mut branch_a = common.fork();
    let a1 = branch_a.mine(&mine);
    wallet.node().submit_block(a1).unwrap();
    assert_eq!(wallet.progress().height, Some(1), "the node followed A");

    // The wallet reads its history off branch A. It now believes it mined
    // twice: block 0 and block 1.
    let on_a = wallet.history();
    assert_eq!(on_a.len(), 2, "two blocks on branch A paid this key");
    assert!(
        on_a.iter().any(|m| m.height == 1),
        "including the one at height 1 that the reorg will undo"
    );

    // Branch B: three blocks off the same prefix, paying a stranger, so it is
    // strictly heavier than A and does not pay this key at all past block 0.
    let mut branch_b = common.fork();
    let b1 = branch_b.mine(&stranger);
    let b2 = branch_b.mine(&stranger);
    let b3 = branch_b.mine(&stranger);
    wallet.node().submit_block(b1).unwrap();
    wallet.node().submit_block(b2).unwrap();
    wallet.node().submit_block(b3).unwrap();
    assert_eq!(
        wallet.progress().height,
        Some(3),
        "the node reorganised onto the heavier branch B"
    );

    // The ledger the node keeps is correct: only block 0 paid this key on the
    // branch that won, so exactly one reward is spendable. (This is what the
    // recent fix put right.)
    assert_eq!(
        wallet.holdings().spendable,
        reward,
        "only block 0's reward survives the reorganisation"
    );

    // The history must agree. On branch B this key was paid once, at block 0.
    let after = wallet.history();
    assert!(
        after.iter().all(|m| m.height != 1),
        "the block-1 payment was undone, so no movement may still name height 1: {after:?}"
    );
    assert_eq!(
        after.len(),
        1,
        "one payment survived the reorganisation, not two: {after:?}"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// The other half of the invariant: a payment that first appears on the
/// winning branch, at a height the wallet had already read past on the losing
/// one, must show up in the history. The node's ledger holds the note; the
/// history must not be the only place the money goes unexplained.
#[test]
fn a_reorganisation_does_not_lose_a_movement_that_only_the_winning_branch_has() {
    let directory = scratch("lost");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[2; 32]);
    let mine = secret.public_key();
    let stranger = SecretKey::from_bytes(&[7; 32]).public_key();
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let params = ConsensusParams::testnet();
    let reward = params.initial_reward;
    let (wallet, _) = Wallet::open(&key_file, params, &directory.join("data")).unwrap();

    // A shared first block, paying a stranger. This key has nothing yet.
    let mut common = Chain::new();
    let block0 = common.mine(&stranger);
    wallet.node().submit_block(block0).unwrap();

    // Branch A: one more block, also paying the stranger.
    let mut branch_a = common.fork();
    let a1 = branch_a.mine(&stranger);
    wallet.node().submit_block(a1).unwrap();

    // The wallet reads its (empty) history off branch A and moves its reading
    // point past height 1.
    assert!(wallet.history().is_empty(), "nothing has paid this key yet");

    // Branch B: heavier, and its block at height 1 pays THIS key. That is a
    // payment the wallet never saw on branch A and will never look back for.
    let mut branch_b = common.fork();
    let b1 = branch_b.mine(&mine);
    let b2 = branch_b.mine(&stranger);
    let b3 = branch_b.mine(&stranger);
    wallet.node().submit_block(b1).unwrap();
    wallet.node().submit_block(b2).unwrap();
    wallet.node().submit_block(b3).unwrap();
    assert_eq!(
        wallet.progress().height,
        Some(3),
        "the node reorganised onto the heavier branch B"
    );

    // The node's ledger holds the note branch B paid this key.
    assert_eq!(
        wallet.holdings().spendable,
        reward,
        "the winning branch paid this key once"
    );

    // The history has to hold it too.
    let after = wallet.history();
    assert_eq!(
        after.len(),
        1,
        "the payment on the winning branch must be in the history, not only in the ledger: {after:?}"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

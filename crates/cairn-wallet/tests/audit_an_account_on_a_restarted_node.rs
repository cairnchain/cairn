//! An account on a node that wrote its ledger down and started again.
//!
//! That is the ordinary life of a node, and it cuts the block log to the
//! ledger's height: the account can no longer read the blocks below where the
//! log begins. What it knows of them is what it read before, and what it can
//! learn from the node's ledger now. Each test here is something the account
//! got wrong about the blocks it can no longer read.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
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

/// Blocks paying this key before the ledger is written down.
const HEIGHT: u64 = 40;

/// A shallow burial so a ledger can be written after a few dozen blocks; the
/// hot set is left at its default so every reward stays hot.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
}

fn somebody(seed: u8) -> PublicKey {
    SecretKey::from_bytes(&[seed; 32]).public_key()
}

/// Mines blocks on a private ledger, paying whoever is named.
struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn fork(&self) -> Self {
        Self {
            state: self.state.clone(),
            clock: self.clock,
        }
    }

    fn mine(&mut self, to: &PublicKey, transfers: Vec<Transfer>) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, *to)]);
        let block =
            assemble_block(&self.state, coinbase, transfers, &params, self.clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }
}

/// A wallet that read `HEIGHT` blocks paying it, whose node then wrote its
/// ledger down and was started again.
struct Restarted {
    directory: PathBuf,
    forge: Forge,
    mine: PublicKey,
}

fn restarted(name: &str, keep_the_account: bool) -> (Restarted, Wallet) {
    let directory = std::env::temp_dir().join(format!(
        "cairn-restarted-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[3; 32]);
    let mine = secret.public_key();
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");

    let mut forge = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    let blocks: Vec<Block> = (0..HEIGHT).map(|_| forge.mine(&mine, Vec::new())).collect();
    {
        let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
        for block in &blocks {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        assert_eq!(wallet.history().len() as u64, HEIGHT);
        assert!(wallet.node().write_ledger());
        wallet.shutdown();
    }
    if !keep_the_account {
        std::fs::remove_file(data.join("history.dat")).unwrap();
    }

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    wallet.follow_to_the_tip();
    assert!(
        wallet.node().blocks_from() > Some(0),
        "a node that wrote its ledger and started again was meant to have cut its log"
    );
    assert_eq!(wallet.progress().height, Some(HEIGHT - 1));
    (
        Restarted {
            directory,
            forge,
            mine,
        },
        wallet,
    )
}

/// A reorganisation on a restarted node takes back only what the chain took.
///
/// Starting again set every movement aside as undone and gave each one back
/// as a block carrying it was read again, and on a node whose log begins
/// above zero the blocks below it are never read again. So a switch that took
/// nothing of this key's away left every movement below the log's first block
/// on the list of what the chain took back, for good, under a sentence saying
/// whoever was being paid has not been paid. No test reorganised a wallet on a
/// restarted node, so an account that said that passed.
#[test]
fn a_reorganisation_on_a_restarted_node_takes_back_only_what_the_chain_took() {
    let (mut chain, wallet) = restarted("undone-below-the-log", true);

    for _ in 0..4 {
        let block = chain.forge.mine(&chain.mine, Vec::new());
        wallet.node().submit_block(block).unwrap();
    }
    let before = wallet.history();
    assert_eq!(before.len() as u64, HEIGHT + 4);

    // One block at the tip paying a stranger, read by the account, then
    // replaced by two paying somebody else.
    let mut rival = chain.forge.fork();
    wallet
        .node()
        .submit_block(chain.forge.mine(&somebody(11), Vec::new()))
        .unwrap();
    wallet.follow_to_the_tip();
    wallet
        .node()
        .submit_block(rival.mine(&somebody(12), Vec::new()))
        .unwrap();
    wallet
        .node()
        .submit_block(rival.mine(&somebody(12), Vec::new()))
        .unwrap();
    assert_eq!(wallet.progress().height, Some(HEIGHT + 5));

    let after = wallet.history();
    assert!(
        wallet.undone().is_empty(),
        "the block the chain took away paid a stranger, and the account says the chain took \
         back movements of this key's that every block still carries"
    );
    assert_eq!(
        after.len(),
        before.len(),
        "and the list of what happened lost the movements below where the node's log begins"
    );
    assert_eq!(
        wallet.history_covers().missed_below,
        None,
        "and says it could not read blocks it had read"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&chain.directory);
}

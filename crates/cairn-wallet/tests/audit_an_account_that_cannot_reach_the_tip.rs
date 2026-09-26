//! What the balance says while the account cannot read its way to the tip.
//!
//! The account is read block by block off the node's disk, and a block the
//! disk will not give back, or has not taken yet, stops it there. The chain
//! goes on. What the balance holds back as stranded is not counted from the
//! chain: it is every note the account names that the node holds in neither
//! tier, which is money in an awkward place only if the block that spent it
//! has been read. Behind the tip, a note this key paid away looks exactly
//! like one it still owns.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn mine(&mut self, to: &PublicKey, transfers: Vec<Transfer>) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, *to)]);
        let block =
            assemble_block(&self.state, coinbase, transfers, &params, self.clock, 0).unwrap();
        let block = mine_block(block, 1 << 22).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }
}

/// A payment made while the account cannot read the block in front of it is
/// not counted back onto the balance as stranded money, and the line above
/// the balance does not vouch for it.
///
/// The notes a payment spends leave the account when it reads the block that
/// carried them. Stuck behind a block its disk will not give back, it never
/// does, so every note this key paid away came back as money the node cannot
/// prove, beside a warning saying the amount was still right. Nothing made a
/// disk refuse a block under a wallet that then paid somebody, so a wallet
/// that counted its own payments as stranded passed.
#[test]
fn a_payment_made_behind_an_unreadable_block_is_not_counted_as_stranded() {
    let directory = std::env::temp_dir().join(format!(
        "cairn-cannot-reach-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[21; 32]);
    let mine = secret.public_key();
    let stranger = SecretKey::from_bytes(&[7; 32]).public_key();
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();

    let mut forge = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    for _ in 0..4 {
        wallet
            .node()
            .submit_block(forge.mine(&mine, Vec::new()))
            .unwrap();
    }
    assert_eq!(wallet.follow_to_the_tip(), 4);

    // A payment, carried by the next block, whose record then goes bad: its
    // last byte is the count of its transfers. The account is one block
    // behind the tip and cannot read that block.
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    let amount = Amount::from_cairn("10").unwrap();
    let fee = wallet.floor_for(recipient, amount);
    let sent = wallet.send(recipient, amount, fee).unwrap();
    let transfer = wallet
        .node()
        .with_chain(|chain| chain.pooled(&sent.id).cloned())
        .expect("in the pool");
    wallet
        .node()
        .submit_block(forge.mine(&stranger, vec![transfer]))
        .unwrap();
    let log = directory.join("data").join("blocks.log");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&log)
        .unwrap();
    let end = file.seek(SeekFrom::End(-1)).unwrap();
    let mut last = [0u8; 1];
    file.read_exact(&mut last).unwrap();
    file.seek(SeekFrom::Start(end)).unwrap();
    file.write_all(&[last[0] ^ 0xFF]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(wallet.progress().height, Some(4));
    wallet.follow_to_the_tip();
    assert_eq!(
        wallet.history_covers().through,
        Some(3),
        "the account is stuck behind the block it cannot read, or this asks nothing"
    );

    let holdings = wallet.holdings();
    let warning = wallet
        .progress()
        .warning()
        .expect("the unread block is said");
    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        holdings.stranded,
        Amount::ZERO,
        "the note this key paid away is counted back onto the balance as money the node \
         cannot prove"
    );
    assert!(
        !warning.contains("still right"),
        "and the line above the balance says the amount is right: {warning}"
    );
}

//! What the wallet does with money.
//!
//! This is the part where a mistake costs somebody their coins rather than
//! their afternoon, so the tests here are about the money and not about the
//! plumbing: that a transfer the wallet signs is one the rules accept, that
//! what it says it holds is what it holds, that it refuses rather than
//! guesses, and that nothing goes missing between what is spent and what
//! comes back as change.

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
use cairn_primitives::Amount;
use cairn_wallet::{Wallet, WalletError};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-wallet-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// Mines blocks on a private ledger, paying whoever is named.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    /// One block paying `to`, carrying `transfers`.
    fn mine(&mut self, to: &cairn_crypto::PublicKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(self.params.initial_reward, *to)]);
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
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

/// A wallet holding `blocks` worth of mining rewards, and the forge that paid
/// them, so a test can carry on mining onto the same chain.
fn funded(name: &str, seed: u8, blocks: usize) -> (Wallet, Forge, PathBuf) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[seed; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
    let mut forge = Forge::new();
    for _ in 0..blocks {
        let block = forge.mine(&secret.public_key(), Vec::new());
        wallet.node().submit_block(block).unwrap();
    }
    (wallet, forge, directory)
}

/// What the network will carry for this spend, which is no longer nothing.
fn floor(wallet: &Wallet, to: PublicKey, amount: Amount) -> Amount {
    wallet.floor_for(to, amount)
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

/// The one that matters most: a transfer the wallet built and signed has to be
/// one the rules accept. A wallet that signs wrongly does not lose an
/// afternoon, it loses the money, and it would look like it had worked.
#[test]
fn a_transfer_the_wallet_signs_is_one_a_block_will_carry() {
    let (wallet, mut forge, directory) = funded("signs", 1, 4);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let before = wallet.holdings().spendable;
    assert_eq!(before, cairn("200"), "four blocks at fifty");

    let sent = wallet.send(recipient, cairn("120"), cairn("0.5")).unwrap();
    assert_eq!(sent.amount, cairn("120"));
    assert_eq!(sent.fee, cairn("0.5"));

    // Taken out of the wallet's own pool and put in a block by a miner who
    // checks it the way every node will.
    let carried: Vec<Transfer> = wallet.node().with_chain(|chain| {
        chain
            .pooled_transfers()
            .map(|(_, transfer)| transfer.clone())
            .collect()
    });
    assert_eq!(carried.len(), 1, "the transfer reached the pool");

    let miner = SecretKey::from_bytes(&[7; 32]).public_key();
    let block = forge.mine(&miner, carried);
    wallet.node().submit_block(block).unwrap();

    // What is left is what was there, less what was sent and what was paid to
    // carry it. Nothing is allowed to go missing in between.
    let after = wallet.holdings().spendable;
    assert_eq!(
        after,
        before
            .checked_sub(cairn("120"))
            .unwrap()
            .checked_sub(cairn("0.5"))
            .unwrap(),
        "the change came back and the fee did not"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A wallet that spends more than it has, or that quietly spends something it
/// cannot prove, is worse than one that refuses.
#[test]
fn spending_more_than_is_there_is_refused_and_says_so() {
    let (wallet, _forge, directory) = funded("short", 2, 2);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let error = wallet
        .send(
            recipient,
            cairn("500"),
            floor(&wallet, recipient, cairn("500")),
        )
        .unwrap_err();
    match error {
        WalletError::NotEnough { needed, have, .. } => {
            assert_eq!(needed, cairn("500"));
            assert_eq!(have, cairn("100"), "two blocks at fifty");
        }
        other => panic!("refused for the wrong reason: {other}"),
    }

    // And the fee counts towards it, which is where an off-by-one would sit:
    // exactly the balance is not enough once anything is paid to carry it.
    let error = wallet
        .send(recipient, cairn("100"), cairn("0.1"))
        .unwrap_err();
    assert!(
        matches!(error, WalletError::NotEnough { .. }),
        "the fee is part of what has to be covered"
    );

    // The balance less what the network asks to carry it does go through.
    // There is no sending all of it any more: a fee is part of the price.
    let paying = floor(&wallet, recipient, cairn("100"));
    let sending = cairn("100").checked_sub(paying).unwrap();
    assert!(wallet.send(recipient, sending, paying).is_ok());

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// Sending nothing costs the network a record of nothing happening.
#[test]
fn sending_nothing_is_refused() {
    let (wallet, _forge, directory) = funded("nothing", 3, 1);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    assert!(matches!(
        wallet.send(recipient, Amount::ZERO, Amount::ZERO),
        Err(WalletError::NothingToSend)
    ));

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A spend should gather as few notes as it can. Every note it takes is bytes
/// in the block and one more thing to sign, and a wallet that took ten fifties
/// to send sixty would be paying for eight of them for nothing.
#[test]
fn a_spend_takes_as_few_notes_as_it_can() {
    let (wallet, _forge, directory) = funded("fewest", 4, 6);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let paying = floor(&wallet, recipient, cairn("120"));
    let sent = wallet.send(recipient, cairn("120"), paying).unwrap();
    assert_eq!(
        sent.notes, 3,
        "three fifties cover a hundred and twenty, and two do not"
    );
    assert_eq!(
        sent.change,
        cairn("30").checked_sub(paying).unwrap(),
        "the change is what is left after the fee"
    );
    assert_eq!(
        sent.from_cold, 0,
        "nothing has fallen on a chain this short"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// What a wallet reports has to be what it can actually move. The total it
/// holds and the part it can spend are two numbers, and folding them into one
/// would show a balance that quietly goes down.
#[test]
fn what_is_held_and_what_can_move_are_two_numbers() {
    let (wallet, _forge, directory) = funded("holdings", 5, 3);
    let holdings = wallet.holdings();

    assert_eq!(holdings.spendable, cairn("150"));
    assert_eq!(holdings.stranded, Amount::ZERO, "nothing has fallen yet");
    assert_eq!(holdings.total(), cairn("150"));
    assert_eq!(holdings.notes.len(), 3);
    assert!(
        holdings.notes.iter().all(|held| !held.is_cold()),
        "a young chain has evicted nothing"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A wallet with no money at all must say so rather than fail in some other
/// way, because that is the state every wallet starts in.
#[test]
fn an_empty_wallet_holds_nothing_and_refuses_to_spend() {
    let directory = scratch("empty");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &SecretKey::from_bytes(&[6; 32])).unwrap();
    let (wallet, restored) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();

    assert_eq!(restored, 0, "nothing on disk to read back");
    let holdings = wallet.holdings();
    assert_eq!(holdings.spendable, Amount::ZERO);
    assert!(holdings.notes.is_empty());
    assert_eq!(wallet.progress().height, None, "no chain at all yet");

    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    assert!(matches!(
        wallet.send(recipient, cairn("1"), Amount::ZERO),
        Err(WalletError::NotEnough { .. })
    ));

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// The address is the one the key file names, and it is what a payer needs.
/// Getting this wrong sends money nowhere it can be recovered from.
#[test]
fn the_address_is_the_key_file_and_nothing_else() {
    let directory = scratch("address");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[8; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
    assert_eq!(wallet.address(), secret.public_key());
    assert_eq!(
        format!("{wallet:?}"),
        "Wallet(<key withheld>)",
        "and printing it says nothing about the key"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// The history is the wallet's own account of its money, and it has to survive
/// the wallet being closed. A wallet that rebuilt it from nothing every time
/// would lose everything older than the blocks it still keeps.
#[test]
fn the_history_is_written_down_and_read_back() {
    let directory = scratch("history");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[11; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");

    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    let mut forge = Forge::new();
    for _ in 0..4 {
        let block = forge.mine(&secret.public_key(), Vec::new());
        wallet.node().submit_block(block).unwrap();
    }

    // Mined four times, then spent once, and the spend lands in a block.
    wallet.send(recipient, cairn("60"), cairn("1")).unwrap();
    let carried: Vec<Transfer> = wallet.node().with_chain(|chain| {
        chain
            .pooled_transfers()
            .map(|(_, transfer)| transfer.clone())
            .collect()
    });
    let block = forge.mine(&recipient, carried);
    wallet.node().submit_block(block).unwrap();

    let movements = wallet.history();
    assert_eq!(movements.len(), 5, "four mined and one sent");
    assert_eq!(
        movements[0].direction,
        cairn_wallet::history::Direction::Sent
    );
    assert_eq!(
        movements[0].amount,
        cairn("61"),
        "what left is what was sent and what was paid to carry it"
    );
    assert!(movements[1..]
        .iter()
        .all(|m| m.direction == cairn_wallet::history::Direction::Mined));
    assert_eq!(wallet.history_covers().from, Some(0));
    wallet.shutdown();
    drop(wallet);

    // Opened again, it remembers rather than starting over.
    let (again, _) = Wallet::open(&key_file, params(), &data).unwrap();
    let remembered = again.history();
    assert_eq!(remembered.len(), 5, "it was written down");
    assert_eq!(remembered[0].amount, cairn("61"));
    assert_eq!(remembered[0].id, movements[0].id, "the same transfer");
    assert_eq!(again.history_covers().from, Some(0));

    again.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

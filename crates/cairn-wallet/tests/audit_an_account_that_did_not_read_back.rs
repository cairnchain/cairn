//! An account file the wallet could not read back, and what became of it.
//!
//! `History::load` tells four reasons apart: a file from before the stamp, a
//! file the disk changed, a file from a newer version, and a file that would
//! not open. For each, the wallet started an empty account, and the first
//! block it read was followed by a save that renamed the new account over the
//! old one. The one that was not read was gone.
//!
//! That file is the only record of where this key's fallen notes sit. For a
//! file from a newer version the wallet had just said "The file is whole and
//! your disk is fine. Going back to the newer version reads it again", and
//! then wrote over it; for a changed file it said "This is worth looking
//! into", and the file was gone before anybody looked. And every one of them
//! was told "the balance beside this becomes right on its own", which for
//! notes fallen below the window the node carries is a balance of nought.
//!
//! What holds now: a file that did not read back is moved aside under a name
//! nothing writes to, before anything can save, and the sentence names it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Amount;
use cairn_wallet::history::History;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A hot set of four, so notes fall to the cold set within a few blocks.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-unread-account-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
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

    fn mine(&mut self, to: &cairn_crypto::PublicKey) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(self.params.initial_reward, *to)]);
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
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

/// A key on disk, its data directory, and the key itself.
fn a_key(directory: &Path) -> (PathBuf, PathBuf, SecretKey) {
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[3; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");
    std::fs::create_dir_all(&data).unwrap();
    (key_file, data, secret)
}

/// Opens the wallet over whatever is in `data`, has it read `blocks`, which is
/// what makes it save its account, and closes it. Returns what it warned.
fn run_the_wallet_over(key_file: &Path, data: &Path, blocks: &[Block]) -> String {
    let (wallet, _) = Wallet::open(key_file, params(), data).unwrap();
    let warning = wallet
        .progress()
        .warning()
        .expect("an account that did not read back is said");
    for block in blocks {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    assert!(
        wallet.follow_to_the_tip() > 0,
        "the wallet read no block, so it never saved and nothing here was asked"
    );
    wallet.shutdown();
    warning
}

fn a_few_blocks_to(secret: &SecretKey) -> Vec<Block> {
    let mut forge = Forge::new();
    (0..3).map(|_| forge.mine(&secret.public_key())).collect()
}

/// Where the first account set aside goes.
fn first_aside(data: &Path) -> PathBuf {
    data.join("history.dat.unread-1")
}

/// An account written by a newer version is still there, whole, after an
/// older version has run over it, and the older version says where.
///
/// The wallet told its owner the file was whole and that going back to the
/// newer version reads it again, then wrote its own account over it at the
/// first block it read. Nothing ran a wallet over a newer file and looked at
/// the file afterwards, so the promise and the overwrite passed together.
#[test]
fn an_account_from_a_newer_version_is_kept_whole_when_an_older_one_runs() {
    let directory = scratch("newer");
    let (key_file, data, secret) = a_key(&directory);

    // What a newer version writes: a body this build cannot decode, under a
    // stamp that holds over it.
    let body = [0xEE_u8; 5];
    let mut newer = body.to_vec();
    newer.extend_from_slice(hash(Domain::WalletHistory, &body).as_bytes());
    std::fs::write(data.join("history.dat"), &newer).unwrap();

    let said = run_the_wallet_over(&key_file, &data, &a_few_blocks_to(&secret));

    assert!(
        said.contains("newer version"),
        "the setup did not reproduce a file from a newer version"
    );
    assert!(
        std::fs::read(first_aside(&data)).unwrap() == newer,
        "the newer version's account was not kept, byte for byte, once an older \
         version had run over it"
    );
    assert!(
        said.contains("history.dat.unread-1"),
        "the wallet did not say where it put the account it could not read"
    );
    assert!(
        History::load(&data.join("history.dat")).1.is_none(),
        "and the account this version wrote in its place is one it reads back"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// An account written before the stamp is kept, and so is one that would
/// not open.
///
/// Both were written over at the first block read: the first is a file that
/// decodes perfectly and is refused by design, which made the design a once
/// per upgrade loss of every fallen note's place; the second was said to be
/// worth looking into "before the next save writes over it", which came a
/// few seconds later. Nothing looked at either file after a wallet had run.
#[test]
fn an_account_from_before_the_stamp_or_one_that_would_not_open_is_kept() {
    let directory = scratch("older");
    let (key_file, data, secret) = a_key(&directory);
    let blocks = a_few_blocks_to(&secret);

    let mut account = History::new();
    for block in &blocks {
        account.take(block, secret.public_key());
    }
    let unstamped = account.encode();
    std::fs::write(data.join("history.dat"), &unstamped).unwrap();
    let said = run_the_wallet_over(&key_file, &data, &blocks);
    assert!(
        said.contains("older version"),
        "the setup did not reproduce a file from before the stamp"
    );
    assert!(
        std::fs::read(first_aside(&data)).unwrap() == unstamped,
        "the account from before the stamp was written over"
    );

    // A name the account cannot be opened under: a directory, with something
    // in it that would go with it.
    let elsewhere = scratch("would-not-open");
    let (key_file, data, _) = a_key(&elsewhere);
    std::fs::create_dir(data.join("history.dat")).unwrap();
    std::fs::write(data.join("history.dat").join("inside"), b"kept").unwrap();
    let said = run_the_wallet_over(&key_file, &data, &blocks);
    assert!(
        said.contains("would not open"),
        "the setup did not reproduce an account that would not open"
    );
    assert!(
        std::fs::read(first_aside(&data).join("inside")).unwrap() == b"kept",
        "what stood at the account's name was not kept"
    );
    assert!(
        data.join("history.dat").is_file(),
        "and this wallet's own account took the name back"
    );

    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&elsewhere);
}

/// A second account set aside takes a name of its own, and the first stays
/// as it was.
///
/// A name reused is a file written over, one step removed.
#[test]
fn an_account_set_aside_never_takes_the_name_of_one_set_aside_before() {
    let directory = scratch("second");
    let (key_file, data, _) = a_key(&directory);
    std::fs::write(first_aside(&data), b"set aside last time").unwrap();
    std::fs::write(data.join("history.dat"), b"not an account").unwrap();

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    let said = wallet.progress().warning().unwrap_or_default();
    wallet.shutdown();

    assert!(
        std::fs::read(first_aside(&data)).unwrap() == b"set aside last time",
        "the account set aside before was written over by the next one"
    );
    assert!(
        std::fs::read(data.join("history.dat.unread-2")).unwrap() == b"not an account",
        "the account that did not read back was not kept under a name of its own"
    );
    assert!(
        said.contains("history.dat.unread-2"),
        "the wallet did not name the file it kept"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A wallet whose account did not read back is not told its balance becomes
/// right on its own when the money fallen below the node's window is not in
/// it.
///
/// The key is paid in forty blocks of a hundred and twenty, a hundred more go
/// to a stranger, the node writes its ledger, and one byte of the account
/// changes. The balance then reads nought, nothing is named as stranded, and
/// the wallet said "the balance beside this becomes right on its own". Only
/// that some warning came back was ever asked.
#[test]
fn an_account_that_did_not_read_back_does_not_promise_the_balance_comes_right() {
    let directory = scratch("promise");
    let (key_file, data, secret) = a_key(&directory);
    let stranger = SecretKey::from_bytes(&[11; 32]).public_key();
    let mut forge = Forge::new();
    let blocks: Vec<Block> = (0..220)
        .map(|at| {
            if at < 120 && at % 3 == 0 {
                forge.mine(&secret.public_key())
            } else {
                forge.mine(&stranger)
            }
        })
        .collect();

    {
        let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
        for block in &blocks {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        wallet.follow_to_the_tip();
        assert!(wallet.holdings().total() > Amount::ZERO, "it was paid");
        assert!(wallet.node().write_ledger(), "the ledger went down");
        wallet.shutdown();
    }

    // One byte of the account changes, which is what a disk fault leaves.
    let account = data.join("history.dat");
    let mut bytes = std::fs::read(&account).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    std::fs::write(&account, &bytes).unwrap();

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    wallet.follow_to_the_tip();
    let said = wallet
        .progress()
        .warning()
        .expect("an account that did not read back is said");
    let total = wallet.holdings().total();
    wallet.shutdown();

    assert!(
        said.contains("the disk changed it"),
        "the setup did not reproduce an account the disk changed"
    );
    assert_eq!(
        total,
        Amount::ZERO,
        "the setup did not reproduce money fallen below the window the node carries"
    );
    assert!(
        !said.contains("becomes right"),
        "the wallet told its owner the balance becomes right on its own, and the \
         balance is nought"
    );
    assert!(
        said.contains("not counted"),
        "the wallet did not say that money fallen out of the set is missing from \
         the balance"
    );
    assert!(
        said.contains("history.dat.unread-1"),
        "the wallet did not say where the account it could not read went"
    );
    assert!(
        std::fs::read(first_aside(&data)).unwrap() == bytes,
        "the account worth looking into was gone by the time anybody could look"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A save that fails takes its partial file away, and leaves the account it
/// was replacing where it was.
///
/// The partial was left beside the account whenever the move into place
/// failed. Nothing made a save fail after the partial was written, so a
/// failure that left its leftovers passed.
#[test]
fn a_save_that_fails_leaves_nothing_beside_the_account() {
    let directory = scratch("failed-save");
    let account = directory.join("history.dat");
    // A name the account cannot be moved onto.
    std::fs::create_dir(&account).unwrap();
    std::fs::write(account.join("inside"), b"kept").unwrap();

    assert!(
        History::new().save(&account).is_err(),
        "a save that could not move its file into place was reported as written"
    );
    assert!(
        !directory.join("history.part").exists(),
        "a save that failed left its partial file beside the account"
    );
    assert!(
        std::fs::read(account.join("inside")).unwrap() == b"kept",
        "what stood at the account's name was touched by a save that failed"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The account is never written through a symbolic link standing at the name
/// of its partial file.
///
/// The partial was opened in place, which follows a link, and truncated,
/// which empties whatever the link names: a link planted in the data
/// directory, or brought back by a restore, named the file the account went
/// into, the key file included.
#[cfg(unix)]
#[test]
fn the_account_is_never_written_through_a_link_at_its_partial_name() {
    let directory = scratch("link");
    let (key_file, data, secret) = a_key(&directory);
    let before = std::fs::read(&key_file).unwrap();
    std::os::unix::fs::symlink(&key_file, data.join("history.part")).unwrap();

    History::new().save(&data.join("history.dat")).unwrap();

    assert!(
        std::fs::read(&key_file).unwrap() == before,
        "the account was written through a link into the key file"
    );
    assert!(
        cairn_wallet::keyfile::read(&key_file)
            .is_ok_and(|read| read.public_key() == secret.public_key()),
        "the key file no longer holds the key"
    );
    assert!(
        std::fs::symlink_metadata(data.join("history.dat"))
            .unwrap()
            .file_type()
            .is_file(),
        "the account is not a file of its own"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

//! An account file is this key's, or it is refused.
//!
//! `History::load` checked a stamp over the bytes, which says they are the
//! ones written and nothing about whose they are. A key given another key's
//! --data directory took that account for its own: it counted the other
//! key's notes, and its next save wrote over the only record of where the
//! other key's fallen notes sit. A person with two keys and two backups,
//! told by `restore` and `recover` which directory to give the others, can
//! put them together the wrong way round.
//!
//! What holds now: the account carries the address it was written for, a
//! key is refused an account written for another address with nothing on
//! the disk changed, and an account written before this carried the address
//! is taken as it always was and given it by the next save.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Address, Note};
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_wallet::history::History;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-another-key-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// A key file in `directory` for the key made of `byte`, and a data
/// directory beside it.
fn a_key(directory: &Path, byte: u8) -> (PathBuf, PathBuf, SecretKey) {
    let key_file = directory.join(format!("key-{byte}"));
    let secret = SecretKey::from_bytes(&[byte; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");
    std::fs::create_dir_all(&data).unwrap();
    (key_file, data, secret)
}

fn a_block_to(secret: &SecretKey) -> Block {
    let params = params();
    let state = LedgerState::new();
    let coinbase = CoinbaseTransaction::new(
        0,
        vec![Note::new(params.initial_reward, secret.public_key())],
    );
    let block = assemble_block(&state, coinbase, Vec::new(), &params, 1_600, 0).unwrap();
    let block = mine_block(block, ATTEMPTS).unwrap();
    connect_block(&mut LedgerState::new(), &block, &params, NOW).unwrap();
    block
}

/// Opens the wallet over `data`, has it read `block`, which makes it save its
/// account, and closes it.
fn run_the_wallet(key_file: &Path, data: &Path, block: &Block) {
    let (wallet, _) = Wallet::open(key_file, params(), data).unwrap();
    wallet.node().submit_block(block.clone()).unwrap();
    assert!(
        wallet.follow_to_the_tip() > 0,
        "fixture: the wallet read no block, so it never saved"
    );
    wallet.shutdown();
}

/// Every file in a directory and what it holds.
fn everything_in(directory: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(everything_in(&path));
        } else {
            let held = std::fs::read(&path).unwrap();
            found.push((path, held));
        }
    }
    found.sort();
    found
}

/// **A wallet writes down whose account it is, and opens it again.**
#[test]
fn an_account_is_written_for_its_key_and_opens_again_for_it() {
    let home = scratch("matching");
    let (key_file, data, secret) = a_key(&home, 3);
    run_the_wallet(&key_file, &data, &a_block_to(&secret));

    let (written, why) = History::load(&data.join("history.dat"));
    assert_eq!(why, None, "fixture: the account reads back");
    assert_eq!(
        written.owner(),
        Some(Address::from(secret.public_key())),
        "the account does not say whose it is"
    );
    let opened = Wallet::open(&key_file, params(), &data);
    let _ = std::fs::remove_dir_all(&home);
    let (wallet, _) = opened.expect("the key the account was written for was refused it");
    assert!(!wallet.history().is_empty(), "and it is the same account");
    wallet.shutdown();
}

/// **A key given another key's account is refused it, and nothing on the disk
/// changes.**
#[test]
fn an_account_written_for_another_key_is_refused_with_nothing_changed() {
    let home = scratch("mismatching");
    let (theirs_file, data, theirs) = a_key(&home, 3);
    run_the_wallet(&theirs_file, &data, &a_block_to(&theirs));
    let (mine_file, _, mine) = a_key(&home, 4);
    let before = everything_in(&data);

    let refused = Wallet::open(&mine_file, params(), &data);
    let after = everything_in(&data);
    let _ = std::fs::remove_dir_all(&home);

    let Err(refusal) = refused else {
        panic!("a key was given another key's account and took it for its own");
    };
    let said = refusal.to_string();
    let network = params().network;
    let theirs_text = Address::from(theirs.public_key()).to_text(network);
    let mine_text = Address::from(mine.public_key()).to_text(network);
    let start = theirs_text.rfind('1').unwrap() + 1 + 8;
    assert!(
        said.contains(&theirs_text[..start]) && said.contains(&mine_text[..start]),
        "the refusal does not name both addresses by their first characters: {said}"
    );
    assert!(
        said.contains("Nothing has been changed") && said.contains("--data"),
        "the refusal does not say what to do: {said}"
    );
    assert_eq!(before, after, "the refusal changed what is on the disk");
}

/// **An account written before it said whose it was is taken as it always
/// was, and says so from its next save.**
#[test]
fn an_account_from_before_the_address_is_read_and_given_it() {
    let home = scratch("upgraded");
    let (key_file, data, secret) = a_key(&home, 3);
    let path = data.join("history.dat");
    // What every release before this one wrote: an account that names no
    // owner.
    History::new().save(&path).unwrap();
    let (old, why) = History::load(&path);
    assert!(
        why.is_none() && old.owner().is_none(),
        "fixture: an account that names no owner reads back"
    );

    run_the_wallet(&key_file, &data, &a_block_to(&secret));
    let (saved, why) = History::load(&path);
    let set_aside = data.join("history.dat.unread-1").exists();
    let _ = std::fs::remove_dir_all(&home);
    assert!(
        why.is_none() && !set_aside,
        "an account from before the address was not taken as it was"
    );
    assert_eq!(
        saved.owner(),
        Some(Address::from(secret.public_key())),
        "an account from before the address was not given it by the next save"
    );
}

/// **An account that starts again from nothing is still this key's.**
///
/// `forget` rebuilds the account from what it keeps, and what it did not name
/// was dropped: a wallet past one deep reorganisation saved accounts that
/// named no owner again, and any key could take them.
#[test]
fn an_account_that_forgets_its_blocks_keeps_whose_it_is() {
    let owner = Address::from(SecretKey::from_bytes(&[3; 32]).public_key());
    let mut account = History::new();
    account.belongs_to(owner);
    account.forget(None);
    assert_eq!(account.owner(), Some(owner));
}

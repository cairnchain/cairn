//! Who else on this machine can read a wallet's account.
//!
//! `keyfile` creates the key at `0600` in the call that creates it, and
//! refuses to read one anybody else can, with a paragraph on why a warning
//! would be the wrong answer. The account file was written at whatever the
//! umask allowed, which is `0644` on most machines.
//!
//! It holds no key. It holds everything else: every note this key was paid,
//! what each is worth, which are still held, and where each of the fallen ones
//! sits. Anybody with an account on the same machine could read the whole of
//! one person's money, and link every note of it to every other.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-account-mode-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
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

/// Opens a wallet, pays it a few blocks, and reads the chain so that there is
/// an account on the disk to look at.
fn a_wallet_with_an_account(name: &str) -> (PathBuf, PathBuf, Block) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[5; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");

    let mut chain = a_chain(&secret.public_key(), 13);
    let one_more = chain.pop().unwrap();
    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    for block in chain {
        wallet.node().submit_block(block).unwrap();
    }
    while wallet.follow() > 0 {}
    drop(wallet);
    (directory, data.join("history.dat"), one_more)
}

#[test]
fn the_account_is_readable_by_its_owner_and_nobody_else() {
    let (directory, account, _) = a_wallet_with_an_account("plain");
    assert!(account.is_file(), "the wallet wrote no account to look at");

    let mode = mode_of(&account);
    assert_eq!(
        mode & 0o077,
        0,
        "the account is {mode:04o}: other accounts on this machine can read it"
    );
    assert_eq!(
        mode, 0o600,
        "the account is {mode:04o} and it should be 0600"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// And a partial file left by a write that stopped halfway does not carry its
/// own mode onto the account.
///
/// The mode a file is opened with applies to one being created. The partial
/// is written, synced and renamed over the account, so a partial already there
/// and already readable would hand the account its permissions.
#[test]
fn a_partial_file_left_behind_does_not_hand_the_account_its_mode() {
    let (directory, account, one_more) = a_wallet_with_an_account("partial");
    let partial = account.with_extension("part");

    std::fs::write(&partial, b"what a write that stopped halfway left").unwrap();
    std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(mode_of(&partial), 0o644, "the partial was set up readable");

    // One more block, so the wallet reads it and writes its account again
    // over that partial.
    let key_file = directory.join("key");
    let data = directory.join("data");
    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    wallet.node().submit_block(one_more).unwrap();
    assert!(
        wallet.follow() > 0,
        "the wallet read the block it was given"
    );
    drop(wallet);

    let mode = mode_of(&account);
    assert_eq!(
        mode, 0o600,
        "the account came back {mode:04o}, which is the partial file's mode"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

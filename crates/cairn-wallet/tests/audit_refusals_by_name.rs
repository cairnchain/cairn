//! Two refusals of the wallet, produced for their cause.
//!
//! `WalletError::CouldNotStart` is the sentence a person reads when the wallet
//! does not open, and `Discarded::WouldNotOpen` is the account it reads when
//! the file that holds it cannot be opened. Neither had been produced by any
//! test: the second's words were tested, and nothing ever made `History::load`
//! meet a path it could not open.
//!
//! Three more are not produced here, and why. `WalletError::NoRandomness` is
//! the operating system refusing randomness, which a test cannot arrange, and
//! `cairn_crypto::CryptoError::NoEntropy` is the same refusal one layer down.
//! `WalletError::AlreadyWaiting` needs the pool to hold the very transfer the
//! wallet offers, and the wallet leaves out of what it can spend every note a
//! pooled transfer already reaches for, so a second offer of the same spend is
//! refused as money the wallet does not have before it is signed. What is left
//! is the pool taking the same transfer between the wallet drafting it and
//! offering it, a race a test cannot arrange without a hook in the wallet.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use cairn_ledger::validation::ConsensusParams;
use cairn_wallet::history::{Discarded, History};
use cairn_wallet::{Wallet, WalletError};

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-wallet-by-name-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// A wallet whose key file is not there does not start, and says it could
/// not.
///
/// Nothing produced `CouldNotStart`, so a wallet that opened without a key, or
/// refused with some other sentence, passed.
#[test]
fn a_wallet_with_no_key_file_does_not_start() {
    let directory = scratch("no-key");
    let opened = Wallet::open(
        &directory.join("no-such-key"),
        ConsensusParams::testnet(),
        &directory.join("data"),
    );
    let could_not_start = matches!(opened, Err(WalletError::CouldNotStart(_)));
    drop(opened);
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        could_not_start,
        "a wallet with no key file was not refused as one that could not start"
    );
}

/// An account where a file is expected and a directory stands is read as one
/// that would not open, and not as an account that was never written.
///
/// The two lead to opposite things: a file that is not there is a wallet that
/// never ran, and one that will not open is a record of this key's notes that
/// has to be kept. Nothing produced `WouldNotOpen`, so a load that took the
/// first road for both passed.
#[test]
fn an_account_that_will_not_open_is_not_read_as_one_never_written() {
    let directory = scratch("would-not-open");
    let path = directory.join("history.dat");
    std::fs::create_dir_all(&path).unwrap();
    let (history, discarded) = History::load(&path);
    let absent = History::load(&directory.join("never-written"));
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        discarded,
        Some(Discarded::WouldNotOpen),
        "a directory where the account should be was not read as an account that \
         would not open"
    );
    assert_eq!(history.movements().count(), 0);
    assert_eq!(absent.1, None, "and an account never written is not news");
}

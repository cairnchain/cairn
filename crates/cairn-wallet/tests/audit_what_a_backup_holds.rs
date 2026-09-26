//! What a person is told to keep, and what the wallet keeps for them.
//!
//! A wallet is two files. The key spends the money. The account beside the
//! chain, `history.dat` in the data directory, is the only record of where a
//! note that has fallen out of the set every node holds now sits, and a
//! restore that carries the key without it finds none of that money:
//! `audit_what_a_key_alone_reaches.rs` holds the mechanism.
//!
//! The wallet said the opposite. `new` printed "That file is the only copy",
//! the help called the data directory "where this wallet keeps its copy of the
//! chain", which reads as a cache anybody may delete, and nothing anywhere
//! named the account as something to keep. A person who did exactly what they
//! were told lost every note that had fallen cold.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use cairn_wallet::history::History;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-backup-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn wallet(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args(arguments)
        .output()
        .expect("the wallet runs")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A key made by `new`, and a data directory holding an account for it.
fn a_wallet_with_an_account(home: &Path) -> (PathBuf, PathBuf) {
    let key = home.join("mine.key");
    let made = wallet(&["new", text(&key)]);
    assert!(made.status.success(), "the key was not made");
    let data = home.join("data");
    std::fs::create_dir_all(&data).unwrap();
    History::new().save(&data.join("history.dat")).unwrap();
    (key, data)
}

/// Making a key says that the account beside the chain has to be kept with
/// it, and how to keep the two together.
///
/// It said the key file was "the only copy" and nothing else. Nothing asked
/// what `new` tells a person to keep, so a wallet that sent them away holding
/// half of what a restore needs passed.
#[test]
fn making_a_key_says_the_account_has_to_be_kept_with_it() {
    let home = scratch("new");
    let key = home.join("mine.key");
    let made = wallet(&["new", text(&key)]);
    // As a paragraph rather than as the lines a terminal is given.
    let told = said(&made).split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(made.status.success(), "the key was not made");

    assert!(
        !told.contains("only copy"),
        "the wallet still tells its owner the key file is the only copy"
    );
    assert!(
        told.contains("history.dat"),
        "the wallet does not name the account a restore needs besides the key"
    );
    assert!(
        told.contains(&format!("cairn-wallet backup {}", key.display())),
        "the wallet does not say how to keep the key and the account together"
    );
    assert!(
        told.contains("no passphrase"),
        "the wallet does not say the key file is plain text"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// The help says the data directory holds the account as well as the chain,
/// and names the command that backs the two up.
///
/// `--data` was described as "where this wallet keeps its copy of the chain",
/// and nothing asked what the help says the directory is for, so a line that
/// invites deleting the only record of the fallen notes passed.
#[test]
fn the_help_says_what_the_data_directory_holds_besides_the_chain() {
    let shown = wallet(&["help"]);
    let told = said(&shown);
    assert!(shown.status.success(), "the help was not shown");

    let data = told
        .split("--data <directory>")
        .nth(1)
        .and_then(|rest| rest.split("--seed").next())
        .expect("the help describes --data");
    assert!(
        data.contains("history.dat"),
        "the help describes the data directory without the account it holds"
    );
    assert!(
        told.contains("cairn-wallet backup <key file>"),
        "the help does not name the command that backs a wallet up"
    );
}

/// A backup is the key file and the account, byte for byte, in a directory
/// of their own that only their owner can read.
///
/// There was no such command, and the two files live apart: the key wherever
/// its owner put it, the account in the data directory. A two-file backup
/// done by hand is one people get half right.
#[test]
fn backing_up_copies_the_key_and_the_account_together() {
    let home = scratch("both");
    let (key, data) = a_wallet_with_an_account(&home);
    let into = home.join("elsewhere").join("wallet-backup");

    let done = wallet(&[
        "backup",
        text(&key),
        "--data",
        text(&data),
        "--into",
        text(&into),
    ]);
    assert!(done.status.success(), "the backup was refused");

    assert!(
        std::fs::read(into.join("mine.key")).unwrap() == std::fs::read(&key).unwrap(),
        "the key in the backup is not the key"
    );
    assert!(
        std::fs::read(into.join("history.dat")).unwrap()
            == std::fs::read(data.join("history.dat")).unwrap(),
        "the account in the backup is not the account"
    );
    assert_eq!(
        std::fs::read_dir(&into).unwrap().count(),
        2,
        "the backup holds something besides the key and the account"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(&into.join("mine.key")),
            0o600,
            "the key in the backup is readable by somebody else"
        );
        assert_eq!(
            mode(&into.join("history.dat")),
            0o600,
            "the account in the backup is readable by somebody else"
        );
        assert_eq!(
            mode(&into),
            0o700,
            "the directory the backup made is open to somebody else"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// A backup never writes over a file, and a backup that is refused leaves
/// nothing behind.
///
/// A backup that replaced an older one would be the one moment a person has
/// neither: the older copy is gone before the newer is whole.
#[test]
fn a_backup_never_writes_over_a_file() {
    let home = scratch("twice");
    let (key, data) = a_wallet_with_an_account(&home);
    let into = home.join("wallet-backup");
    let arguments = [
        "backup",
        text(&key),
        "--data",
        text(&data),
        "--into",
        text(&into),
    ];
    assert!(
        wallet(&arguments).status.success(),
        "the first backup was refused"
    );
    let first = std::fs::read(into.join("history.dat")).unwrap();

    // The account changes, as it does every time the wallet reads a block.
    std::fs::write(data.join("history.dat"), b"a newer account").unwrap();
    let again = wallet(&arguments);
    assert!(
        !again.status.success(),
        "a second backup into the same place was not refused"
    );
    assert!(
        said(&again).contains("already"),
        "the refusal does not say what is in the way"
    );
    assert!(
        std::fs::read(into.join("history.dat")).unwrap() == first,
        "the account the first backup wrote was written over"
    );

    // A directory holding only the account is refused as well, and the key
    // is not written beside it.
    let half = home.join("half");
    std::fs::create_dir_all(&half).unwrap();
    std::fs::write(half.join("history.dat"), b"somebody's").unwrap();
    let refused = wallet(&[
        "backup",
        text(&key),
        "--data",
        text(&data),
        "--into",
        text(&half),
    ]);
    assert!(
        !refused.status.success(),
        "a backup over an account was not refused"
    );
    assert!(
        !half.join("mine.key").exists(),
        "a refused backup left the key behind it"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A key with no account beside it is not called a backup.
///
/// The account is written the first time the wallet reads the chain, so a
/// backup taken straight after `new` has nothing to carry. Copying the key
/// alone and calling that a backup is the defect this command exists to end.
#[test]
fn a_key_without_its_account_is_not_called_a_backup() {
    let home = scratch("alone");
    let key = home.join("mine.key");
    assert!(wallet(&["new", text(&key)]).status.success());
    let data = home.join("never-ran");
    let into = home.join("wallet-backup");

    let refused = wallet(&[
        "backup",
        text(&key),
        "--data",
        text(&data),
        "--into",
        text(&into),
    ]);
    assert!(
        !refused.status.success(),
        "a key without its account was backed up as if it were a wallet"
    );
    assert!(
        said(&refused).contains("holds no history.dat"),
        "the refusal does not name what is missing"
    );
    assert!(
        said(&refused).contains("half of a backup"),
        "the refusal does not say why a key alone is not copied"
    );
    assert!(
        !into.join("mine.key").exists(),
        "the key was copied on its own all the same"
    );

    // An account that is there and will not be read is a different refusal,
    // and not one that tells the person to go and run the wallet.
    let unreadable = home.join("unreadable");
    std::fs::create_dir_all(unreadable.join("history.dat")).unwrap();
    let refused = wallet(&[
        "backup",
        text(&key),
        "--data",
        text(&unreadable),
        "--into",
        text(&into),
    ]);
    assert!(
        !refused.status.success(),
        "an unreadable account was backed up"
    );
    assert!(
        said(&refused).contains("could not read"),
        "an account that would not be read was called missing"
    );
    assert!(
        !into.join("mine.key").exists(),
        "the key was copied on its own all the same"
    );
    let _ = std::fs::remove_dir_all(&home);
}

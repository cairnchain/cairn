//! AUDIT: the address of a running wallet page is a bearer token, and it was
//! printed wherever stdout went.
//!
//! `cairn-wallet open` prints two lines. The first is the public key to be
//! paid at, which is public by construction. The second is
//! `http://127.0.0.1:PORT/?k=SECRET`, and the secret in it is the only thing
//! standing between a page and whoever asks: anyone holding it can spend from
//! this wallet, and the command says so on the next line.
//!
//! On a terminal that is the operator's own screen and is the whole point of
//! the command. Redirected it is something else. A wallet run under a service
//! manager sends stdout to a journal, which outlives anybody's attention and is
//! commonly readable by a group rather than by one user, where the wallet's own
//! directory is not. So a spending token sat in a file readable by people who
//! could not read the keys, for as long as the wallet ran.
//!
//! Found by the code scanning this repository turned on, which called it
//! "writes self.secret to a log file" and was right about the shape even
//! though a terminal is not a log file. Of the three hundred and ten alerts it
//! raised this is the one that was a defect; the rest are test vectors and a
//! public key.
//!
//! What the fix is not: the token still works exactly as long as it did, and
//! the page is still on the loopback behind it. What changes is how long a copy
//! of the token lasts and who can reach that copy.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::PathBuf;

use cairn_wallet::serve::{Link, Opened};

const SECRET: &str = "1f8b0c4d2e6a7b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f6";

fn opened() -> Opened {
    Opened {
        address: SocketAddr::from(([127, 0, 0, 1], 8712)),
        secret: SECRET.to_owned(),
    }
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-link-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// A terminal is the operator looking at their own screen, and gets the address.
#[test]
fn a_terminal_is_handed_the_address_itself() {
    let data = scratch("terminal");
    let link = opened().hand_over(&data, true).unwrap();

    assert_eq!(link, Link::Shown(opened().url()));
    let Link::Shown(url) = link else {
        panic!("a terminal was handed something other than the address")
    };
    assert!(url.contains(SECRET), "the address has to carry the secret");

    // And nothing is left on disk for it.
    assert!(
        std::fs::read_dir(&data).unwrap().next().is_none(),
        "a terminal was handed the address and a file as well"
    );
    let _ = std::fs::remove_dir_all(&data);
}

/// Anything else is handed a path, and the secret goes nowhere near the stream.
#[test]
fn a_stream_that_is_not_a_terminal_is_handed_a_path() {
    let data = scratch("stream");
    let link = opened().hand_over(&data, false).unwrap();

    let Link::Written(path) = link.clone() else {
        panic!("a redirected stdout was handed the address itself")
    };

    // The whole of it: what the command prints names a file and not a secret.
    let printed = path.display().to_string();
    assert!(
        !printed.contains(SECRET),
        "the secret is in what gets printed, which is the defect"
    );
    assert!(printed.starts_with(&data.display().to_string()));

    // And the file holds the address the browser needs.
    let held = std::fs::read_to_string(&path).unwrap();
    assert_eq!(held, opened().url());
    assert!(held.contains(SECRET));

    // Readable by its owner and by nobody else, which is what the keys beside
    // it already have. Set as the file is created, so there is no moment where
    // the bytes are on disk under whatever the umask allowed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the link is readable by somebody other than its owner"
        );
    }

    // A second run writes over it rather than beside it.
    let again = opened().hand_over(&data, false).unwrap();
    assert_eq!(again, link);
    assert_eq!(std::fs::read_dir(&data).unwrap().count(), 1);

    // And a wallet that closes takes it away, so the next run does not find a
    // link to a page that is not there.
    Opened::let_the_link_go(&data);
    assert!(!path.exists());
    // Twice, because a wallet that never wrote one still calls this.
    Opened::let_the_link_go(&data);
    let _ = std::fs::remove_dir_all(&data);
}

/// A directory that is not there is a refusal rather than a silent loss.
///
/// The alternative is a wallet that says it wrote the link somewhere and did
/// not, which leaves an operator with a running page they cannot open and no
/// reason given.
#[test]
fn a_link_that_cannot_be_written_is_said_rather_than_swallowed() {
    let missing = std::env::temp_dir()
        .join("cairn-link-nowhere-at-all")
        .join("deeper");
    let refusal = opened()
        .hand_over(&missing, false)
        .expect_err("nothing to write into");
    assert!(
        refusal.contains("open-this-page"),
        "the refusal does not name the file it could not write: {refusal}"
    );
    assert!(
        !refusal.contains(SECRET),
        "the refusal carries the secret, which puts it back in the stream"
    );
}

/// A link file already there and already widened does not keep the mode it was
/// widened to.
///
/// The mode handed to `open` applies to a file being created and not to one
/// that is already there, so a file left from an earlier run took whatever it
/// had been widened to since, and the token went back into it at that mode.
/// The test above cannot see it: it clears the directory first, so the file is
/// always created new and the only mode it can ever read back is the one set
/// on creation.
///
/// Not an exotic state. Nothing clears `running`, so `let_the_link_go` never
/// runs on a wallet that is stopped the way wallets are stopped, and the file
/// survives every real run. A restore, a copy off a stick, or a `chmod -R`
/// over the data directory is what widens it.
///
/// The account file learned this and had the reasoning written down beside it.
/// The link file, which is the one holding something that spends the wallet,
/// did not.
#[cfg(unix)]
#[test]
fn a_link_file_left_widened_is_narrowed_again_before_the_token_goes_back_in() {
    use std::os::unix::fs::PermissionsExt as _;

    let data = scratch("widened");
    let path = data.join("open-this-page");

    // An earlier run's file, since widened by something outside the wallet.
    std::fs::write(&path, "http://127.0.0.1:1/?k=older").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644,
        "this test proves nothing unless the file starts readable by everybody"
    );

    opened().hand_over(&data, false).unwrap();

    let held = std::fs::read_to_string(&path).unwrap();
    assert!(
        held.contains(SECRET),
        "the file holds the token that spends this wallet: {held}"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600,
        "a spending token was written into a file anybody with an account on this machine \
         can read"
    );

    let _ = std::fs::remove_dir_all(&data);
}

/// The link is never written through a symbolic link standing at its name.
///
/// The file was opened in place, which follows a link, so a link planted in
/// the data directory, or brought back by a restore, named the file the
/// spending token went into, wherever that was and whoever could read it.
/// Every test here cleared the directory first, so the file was always
/// created new and a link at its name was never met.
#[cfg(unix)]
#[test]
fn the_link_is_never_written_through_a_symbolic_link_at_its_name() {
    let data = scratch("planted");
    let elsewhere = scratch("planted-target").join("readable-by-others");
    std::fs::write(&elsewhere, b"").unwrap();
    std::os::unix::fs::symlink(&elsewhere, data.join("open-this-page")).unwrap();

    let link = opened().hand_over(&data, false).unwrap();

    assert!(
        !std::fs::read_to_string(&elsewhere)
            .unwrap()
            .contains(SECRET),
        "the spending token was written through a symbolic link the wallet did not make"
    );
    let Link::Written(path) = link else {
        panic!("a redirected stdout was handed the address itself")
    };
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_file(),
        "what the operator is told to open is not a file the wallet made"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), opened().url());
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(elsewhere.parent().unwrap());
}

/// A link at the link file's name cannot empty the key file.
///
/// The file was truncated as it was opened, so whatever a planted link named
/// was emptied and refilled with the page's address. Named at the key, the
/// running wallet noticed nothing, since the key was already in memory, and
/// the next start found an address where the key had been.
#[cfg(unix)]
#[test]
fn a_link_at_the_link_file_s_name_cannot_empty_the_key_file() {
    let data = scratch("at-the-key");
    let keys = scratch("at-the-key-keys");
    let key_file = keys.join("alice.key");
    let secret = cairn_crypto::SecretKey::from_bytes(&[7; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    std::os::unix::fs::symlink(&key_file, data.join("open-this-page")).unwrap();

    opened().hand_over(&data, false).unwrap();

    assert!(
        cairn_wallet::keyfile::read(&key_file)
            .is_ok_and(|read| read.public_key() == secret.public_key()),
        "the key file was written over through a link named open-this-page"
    );
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&keys);
}

/// A link file an earlier run left is taken away when this run hands its
/// address to a terminal.
///
/// Only a wallet that closed cleanly took its file away, so after a wallet
/// stopped any other way, and then run again on a terminal, the data
/// directory went on holding an address to a page that was not there.
#[test]
fn a_link_an_earlier_run_left_is_taken_away_when_the_address_goes_to_a_terminal() {
    let data = scratch("stale");
    std::fs::write(data.join("open-this-page"), "http://127.0.0.1:1/?k=older").unwrap();

    let link = opened().hand_over(&data, true).unwrap();

    assert_eq!(link, Link::Shown(opened().url()));
    assert!(
        !data.join("open-this-page").exists(),
        "a link to a page that is gone was left beside a wallet that is running"
    );
    let _ = std::fs::remove_dir_all(&data);
}

/// Printing the page, or where its address went, does not print the token.
///
/// `SecretKey` and `Wallet` write their own `Debug` so that a key cannot reach
/// a log through a derived formatter. The token is the other thing here that
/// spends money, and both types that carry it took the derive, so a `{:?}` in
/// an error or a panic would have written it into the journal `hand_over`
/// keeps it out of. Nothing formatted either type.
#[test]
fn printing_the_page_or_its_link_does_not_print_the_token() {
    let page = opened();
    assert!(
        !format!("{page:?}").contains(SECRET),
        "the page prints the token that spends the wallet"
    );
    assert!(
        format!("{page:?}").contains("127.0.0.1:8712"),
        "and it still says where it is"
    );
    let shown = Link::Shown(page.url());
    assert!(
        !format!("{shown:?}").contains(SECRET),
        "the address handed to a terminal prints the token"
    );
    let written = Link::Written(PathBuf::from("data/open-this-page"));
    assert!(
        format!("{written:?}").contains("open-this-page"),
        "the path the address was written to is not a secret and is printed"
    );
}

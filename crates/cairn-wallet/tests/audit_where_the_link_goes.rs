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

//! Where a wallet goes first when it is told nothing.
//!
//! A wallet run without `--seed` has a starting point written into the
//! program, and it used to dial it on every run, whatever its own book held.
//! Whoever runs that machine was then told of every wallet session there was:
//! the address it came from and when, and, because a payment goes to every
//! peer at once and on a first run the seed is the only one, where each
//! payment came from. The seed is needed by a wallet that knows nobody, and
//! that is all it is needed for.
//!
//! The seeds are handed in as a function here, so a test can say whether they
//! were looked up at all: a lookup of the written-in name is a question to the
//! machine's name server, and that is already telling somebody.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use cairn_crypto::SecretKey;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::Node;
use cairn_wallet::{Wallet, FROM_THE_BOOK};

/// Far past anything a loaded runner takes to dial two addresses on the same
/// machine. It costs nothing when the book answers, which is the case it is
/// used for.
const LONG: Duration = Duration::from_secs(300);

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-where-it-starts-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// A key, and a wallet directory whose book holds `peers` from a run before.
fn a_wallet_that_met(name: &str, peers: &[&Node]) -> (PathBuf, PathBuf, PathBuf) {
    let directory = scratch(name);
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &SecretKey::from_bytes(&[5; 32])).unwrap();
    let data = directory.join("data");
    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    for peer in peers {
        assert!(wallet.reach(peer.address()), "fixture: the peer answered");
    }
    // Stopping writes the book down, which is what the next run starts from.
    wallet.shutdown();
    (directory, key_file, data)
}

/// **A wallet whose book brings it peers does not go to the seed.**
///
/// The wallet met two peers on an earlier run, so its book holds them, and
/// this run it is told nothing. It reaches them from the book, and the seeds
/// are never looked up. The count of peers is asserted too, so a wallet that
/// stopped waiting at once and dialled nobody does not pass for one that
/// needed no seed. Nothing asked this: the seed was dialled on every run.
#[test]
fn a_wallet_whose_book_brings_it_peers_does_not_go_to_the_seed() {
    let first = Node::bind(params(), loopback()).unwrap();
    let second = Node::bind(params(), loopback()).unwrap();
    let (directory, key_file, data) = a_wallet_that_met("book", &[&first, &second]);

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    let looked_up = Cell::new(false);
    let started = wallet.start_from_the_book(LONG, Vec::new(), || {
        looked_up.set(true);
        Vec::new()
    });
    let peers = wallet.node().peers_introduced();
    wallet.shutdown();
    first.shutdown();
    second.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        !looked_up.get(),
        "a wallet whose book held peers that answered looked the seed up \
         anyway, and the seed learns of every run"
    );
    assert_eq!(started, None, "and it says that no seed was needed");
    assert!(
        peers >= FROM_THE_BOOK,
        "and the peers it needed came out of its book"
    );
}

/// **A wallet whose book cannot bring it enough peers goes to the seed.**
///
/// The other side of the same rule. A wallet that knows nobody has no way
/// onto the network but the seed, and one whose book holds fewer addresses
/// than it would wait for goes there too, at once. The patience given is
/// unbounded, so a wallet that waited on a book that could never be enough
/// would never get here.
#[test]
fn a_wallet_whose_book_cannot_be_enough_goes_to_the_seed_at_once() {
    let seed = Node::bind(params(), loopback()).unwrap();
    let only = Node::bind(params(), loopback()).unwrap();

    for (name, met) in [("empty", Vec::new()), ("one", vec![&only])] {
        let (directory, key_file, data) = a_wallet_that_met(name, &met);
        let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
        let started =
            wallet.start_from_the_book(Duration::MAX, Vec::new(), || vec![seed.address()]);
        wallet.shutdown();
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(
            started,
            Some(1),
            "a wallet whose book held {} addresses did not reach the seed",
            met.len()
        );
    }

    seed.shutdown();
    only.shutdown();
}

/// **A wallet that went to the seed does not find it in its own book at the
/// next run.**
///
/// The seed's address was written into the book as an ordinary one, so the
/// next run, told nothing and with a book that looked enough, dialled it from
/// there within a second of starting, and said no seed was asked. Its operator
/// saw every session after the first, which is what going to the book first
/// was for sparing it. Nothing looked at what the book held of the seed.
#[test]
fn a_wallet_that_went_to_the_seed_does_not_find_it_in_its_book_after() {
    let seed = Node::bind(params(), loopback()).unwrap();
    let first = Node::bind(params(), loopback()).unwrap();
    let second = Node::bind(params(), loopback()).unwrap();
    let directory = scratch("seed-kept-out");
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &SecretKey::from_bytes(&[5; 32])).unwrap();
    let data = directory.join("data");

    // Nothing in the book, so the seed; and two peers met besides.
    {
        let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
        let started = wallet.start_from_the_book(LONG, Vec::new(), || vec![seed.address()]);
        assert_eq!(started, Some(1), "fixture: the first run reached the seed");
        for peer in [&first, &second] {
            assert!(wallet.reach(peer.address()), "fixture: a peer answered");
        }
        wallet.shutdown();
    }

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    let book = wallet.node().known_addresses();
    let looked_up = Cell::new(false);
    let started = wallet.start_from_the_book(LONG, Vec::new(), || {
        looked_up.set(true);
        Vec::new()
    });
    wallet.shutdown();
    for node in [&seed, &first, &second] {
        node.shutdown();
    }
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        started.is_none() && !looked_up.get(),
        "fixture: the book was enough and no seed was asked"
    );
    assert!(
        !book.contains(&seed.address()),
        "the seed a wallet went to is written into its book, and its node dials it first at \
         every run after"
    );
}

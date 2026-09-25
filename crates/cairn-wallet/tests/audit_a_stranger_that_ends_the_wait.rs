//! What ends a wallet's wait, and what only looks like it.
//!
//! `catch_up` waits for the chain to stop moving before the wallet answers
//! anything, because a wallet answering from a chain it has not finished
//! reading gives a wrong answer rather than a slow one. It stops waiting once
//! the height has held still for a moment and there is somebody who could have
//! sent more.
//!
//! That second half was read off the socket count. Its own doc comment names
//! the case it then failed to cover: "It is also what a peer that completes
//! the handshake and then says nothing leaves behind, and there is no reason
//! to make that free." A stranger who opens a connection to the wallet's
//! listener and says nothing is not somebody who could have sent anything, and
//! a message down that socket is refused as unannounced. One of them attached
//! was enough to cut every `--wait` to a couple of seconds, after which the
//! wallet answered `balance` and built `send` out of whatever chain was on
//! disk.
//!
//! Every other surface that reports peers was corrected to count the ones that
//! introduced themselves, under a comment saying exactly why. This one was
//! not, and neither was the check that decides whether a stranded payment is
//! worth trying again.
//!
//! The readings here are of a clock, which is what the thing under test is
//! made of. They are taken with a margin of several times the settle window,
//! so what they tell apart is a wait that ran out from one that was cut short,
//! not one scheduling from another.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Four times the settle window, so a wait that ran out and a wait that was
/// cut short are not the same reading under any scheduling.
const PATIENCE: Duration = Duration::from_secs(8);

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// An address a client can actually dial: a node listening on every interface
/// reports a place rather than a machine.
fn reachable(address: SocketAddr) -> SocketAddr {
    if address.ip().is_unspecified() {
        SocketAddr::from((Ipv4Addr::LOCALHOST, address.port()))
    } else {
        address
    }
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-stranger-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn until(patience: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    ready()
}

/// A wallet holding two rewards, with the blocks that paid them.
///
/// It has to hold something: a wallet with no height at all is waiting for a
/// chain that has not arrived, which is a different case and one `catch_up`
/// already refuses to cut short.
fn funded(name: &str, seed: u8) -> (Wallet, Vec<Block>, PathBuf) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[seed; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();

    let rules = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut blocks = Vec::new();
    for _ in 0..2 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(rules.initial_reward, secret.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &rules, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &rules, NOW).unwrap();
        wallet.node().submit_block(block.clone()).unwrap();
        blocks.push(block);
    }

    assert!(
        until(Duration::from_secs(10), || wallet.node().height().is_some()),
        "the wallet has to be holding a chain for this to be about waiting"
    );
    (wallet, blocks, directory)
}

/// A socket that says nothing does not end the wait.
#[test]
fn a_stranger_who_says_nothing_does_not_end_the_wait() {
    let (wallet, _blocks, directory) = funded("silent", 3);

    let quiet = TcpStream::connect(reachable(wallet.node().address())).unwrap();
    // Read what the node sends and answer nothing. A socket nobody reads from
    // is a different thing: the receive buffer fills, a write times out, and
    // the node closes the connection, which is the node being right and has
    // nothing to do with this.
    if let Ok(mut reading) = quiet.try_clone() {
        std::thread::spawn(move || {
            let mut bin = [0u8; 4096];
            while let Ok(read) = std::io::Read::read(&mut reading, &mut bin) {
                if read == 0 {
                    return;
                }
            }
        });
    }

    assert!(
        until(Duration::from_secs(10), || wallet.node().peer_count() == 1),
        "the connection was accepted, which is all the old answer looked at"
    );
    assert_eq!(
        wallet.node().peers_introduced(),
        0,
        "and nobody introduced themselves, which is the answer it should have \
         been looking at"
    );

    let began = Instant::now();
    wallet.catch_up(PATIENCE);
    let waited = began.elapsed();

    assert!(
        waited + Duration::from_secs(1) >= PATIENCE,
        "the wait was cut short after {waited:?} of {PATIENCE:?} by a stranger who had \
         said nothing. Whatever the wallet answers next, it answers out of the chain \
         that was already on disk."
    );

    drop(quiet);
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

/// And somebody who did introduce themselves still ends it, once the chain has
/// held still for the settle window and not before.
///
/// Without this the test above passes on a wallet that never stops waiting at
/// all, which is the other way to get every `--wait` wrong.
///
/// The lower bound is the third way, and nothing asked it: a wallet that
/// stopped at the first look that found a peer and an unmoved height passed.
/// That wallet answers a fifth of a second after it starts, out of whatever
/// chain it already had, while the blocks it was waiting for are on their way.
/// Measured from before the call, so the reading can only be longer than the
/// wait itself and a loaded machine cannot fail it.
#[test]
fn a_peer_that_introduced_itself_ends_the_wait() {
    let (wallet, blocks, directory) = funded("introduced", 4);

    // On the same chain, so there is nothing for it to send and the height
    // holds still.
    let peer = Node::bind(params(), loopback()).unwrap();
    for block in &blocks {
        peer.submit_block(block.clone()).unwrap();
    }
    peer.connect(reachable(wallet.node().address())).unwrap();

    assert!(
        until(Duration::from_secs(10), || wallet.node().peers_introduced()
            == 1),
        "the peer never introduced itself, so this test asks nothing"
    );

    let began = Instant::now();
    wallet.catch_up(PATIENCE);
    let waited = began.elapsed();

    assert!(
        waited + Duration::from_secs(1) < PATIENCE,
        "a wallet whose chain has stopped moving, with a peer that could have sent \
         more and did not, waited its whole {PATIENCE:?} out"
    );
    assert!(
        waited >= cairn_wallet::SETTLED_FOR,
        "the wait ended after {waited:?}, before the chain had held still for {:?}: \
         a wallet that answers then answers out of a chain it has not finished reading",
        cairn_wallet::SETTLED_FOR
    );

    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

/// A patience longer than the clock can count is a wait with no deadline, and
/// not a wait of nothing.
///
/// The deadline was the clock now plus the patience, and where that sum did
/// not fit in an `Instant` it was the clock now. So `--wait` given a number of
/// seconds past what the clock holds did not wait at all: the wallet answered
/// out of whatever chain was on disk, and then said that no chain had arrived
/// in that many seconds. Every patience the tests gave fitted, so a wallet
/// that turned the longest wait anyone can ask for into none passed.
#[test]
fn a_patience_past_what_the_clock_holds_still_waits_for_the_chain_to_settle() {
    let (wallet, blocks, directory) = funded("unbounded", 5);

    let peer = Node::bind(params(), loopback()).unwrap();
    for block in &blocks {
        peer.submit_block(block.clone()).unwrap();
    }
    peer.connect(reachable(wallet.node().address())).unwrap();
    assert!(
        until(Duration::from_secs(10), || wallet.node().peers_introduced()
            == 1),
        "the peer never introduced itself, so the wait could never end and this \
         test asks nothing"
    );
    assert!(
        Instant::now().checked_add(Duration::MAX).is_none(),
        "the longest patience fits this clock, so this test asks nothing"
    );

    let began = Instant::now();
    wallet.catch_up(Duration::MAX);
    let waited = began.elapsed();

    assert!(
        waited >= cairn_wallet::SETTLED_FOR,
        "the longest wait there is ended after {waited:?}, before the chain had \
         held still for {:?}: a patience the clock cannot count was read as none",
        cairn_wallet::SETTLED_FOR
    );

    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

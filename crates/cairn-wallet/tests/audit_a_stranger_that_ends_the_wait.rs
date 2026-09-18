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

/// And somebody who did introduce themselves still ends it.
///
/// Without this the test above passes on a wallet that never stops waiting at
/// all, which is the other way to get every `--wait` wrong.
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
        until(Duration::from_secs(10), || wallet
            .node()
            .peers_introduced()
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

    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

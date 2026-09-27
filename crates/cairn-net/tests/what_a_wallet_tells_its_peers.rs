//! What a node opened for a wallet tells the peers it dials about itself.
//!
//! A wallet is a node opened with `Node::open_watching`, on a port the system
//! picks, for the seconds a command takes. What it owes its peers is what any
//! node owes them: a handshake they can check. What it does not owe them is an
//! address to write down and hand on, because an address in a book travels to
//! strangers in every answer to `GetPeers`, and "a Cairn wallet ran at this
//! address" is a fact about a person.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::Node;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("cairn-wallet-tells-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// Waits for something that happens in milliseconds on a free machine, and
/// far longer than any loaded runner takes before it gives up.
fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(300);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

/// **A wallet's node is not written into the book of a peer it dials, and a
/// plain node still is.**
///
/// A node names the port it listens on when it introduces itself, and the
/// peer completes it with the address the connection came from and writes it
/// into its book. A wallet's node named the port the system had picked for it,
/// so every peer it greeted wrote the wallet's address down, handed it to
/// anybody who asked for addresses, and dialled it on its next round: while
/// the wallet ran, a stranger had a connection to it for the asking.
///
/// The peer is asked only once it counts the wallet as introduced, which is
/// after it has read the handshake and written down whatever it was going to.
/// A plain node dialling a peer of its own is written down, so the peer is not
/// simply one that writes nobody down; a peer of its own, because two nodes
/// that named the same address to one peer would be one node to it, and one
/// of the two connections would go. Nothing asked this, so a wallet that put
/// its address into every book it met passed.
#[test]
fn a_node_opened_for_a_wallet_is_not_written_into_its_peers_books() {
    let wallets_peer_directory = scratch("wallets-peer");
    let (wallets_peer, _) = Node::open(params(), loopback(), &wallets_peer_directory).unwrap();
    let plain_peer_directory = scratch("plain-peer");
    let (plain_peer, _) = Node::open(params(), loopback(), &plain_peer_directory).unwrap();

    let wallets_directory = scratch("wallet");
    let owner = SecretKey::from_bytes(&[1; 32]).public_key();
    let (wallet, _) =
        Node::open_watching(params(), loopback(), &wallets_directory, &[owner]).unwrap();
    wallet.connect(wallets_peer.address()).unwrap();
    wait_for("the peer to read the wallet's introduction", || {
        wallets_peer.peers_introduced() >= 1
    });
    let after_the_wallet = wallets_peer.known_addresses();

    let plain_directory = scratch("plain");
    let (plain, _) = Node::open(params(), loopback(), &plain_directory).unwrap();
    plain.connect(plain_peer.address()).unwrap();
    wait_for("the peer to read the plain node's introduction", || {
        plain_peer.peers_introduced() >= 1
    });
    let after_the_plain_node = plain_peer.known_addresses();

    let (wallet_address, plain_address) = (wallet.address(), plain.address());
    for node in [&plain, &wallet, &plain_peer, &wallets_peer] {
        node.shutdown();
    }
    for directory in [
        &wallets_peer_directory,
        &plain_peer_directory,
        &wallets_directory,
        &plain_directory,
    ] {
        let _ = std::fs::remove_dir_all(directory);
    }

    assert!(
        !after_the_wallet.contains(&wallet_address),
        "a peer wrote a wallet's address into its book, from where it is handed \
         to anybody who asks for addresses and dialled on the next round"
    );
    assert!(
        after_the_plain_node.contains(&plain_address),
        "a plain node that dialled a peer was not written down either, so the \
         peers write nobody down and the first half of this asks nothing"
    );
}

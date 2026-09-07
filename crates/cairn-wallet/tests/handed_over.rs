//! What a person is told about a payment that has just left.
//!
//! "Handed to the network, and waiting for a block" is the sentence somebody
//! reads before they hand over goods. `Sent::handed_on` is the whole of what
//! it rests on, and it used to be read off the peer count five seconds after
//! the fact: a wallet's node broadcasts a transfer once, at the instant its
//! pool takes it, and nothing gossips a pool afterwards. So a wallet that had
//! just opened broadcast to an empty peer table, watched a peer arrive two
//! seconds later, and told the person their money had gone.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
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
use cairn_primitives::Amount;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-handed-{}-{name}", std::process::id()));
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

/// Blocks on a private ledger, paying whoever is named.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, to: &cairn_crypto::PublicKey) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(self.params.initial_reward, *to)]);
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }
}

/// A wallet holding four rewards, with the blocks that paid them.
fn funded(name: &str, seed: u8) -> (Wallet, Vec<Block>, PathBuf) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[seed; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
    let mut forge = Forge::new();
    let mut blocks = Vec::new();
    for _ in 0..4 {
        let block = forge.mine(&secret.public_key());
        wallet.node().submit_block(block.clone()).unwrap();
        blocks.push(block);
    }
    (wallet, blocks, directory)
}

/// The claim: `handed_on` means a peer was offered it.
///
/// A socket that connects and says nothing is a peer this node cannot send
/// anything to: a message down it reaches a node that has not been introduced
/// to this one, which closes the connection and turns this host away. So there
/// is nowhere for the transfer to go, and the person must be told so.
///
/// The peer count says the opposite, and the peer count is what this used to
/// read. One stranger opening a socket to a wallet was enough to have it
/// report every payment made through it as handed to the network.
#[test]
fn a_socket_that_says_nothing_is_not_the_network() {
    let (wallet, _blocks, directory) = funded("silent-peer", 3);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let quiet = TcpStream::connect(wallet.node().address()).unwrap();
    assert!(
        until(Duration::from_secs(10), || wallet.node().peer_count() == 1),
        "the connection was accepted, which is all the old answer looked at"
    );

    let sent = wallet.send(recipient, cairn("10"), cairn("0.5")).unwrap();
    assert!(
        !sent.handed_on,
        "nobody was offered it, so nobody has been paid and the person has to \
         be told that"
    );
    assert_eq!(
        wallet.node().peer_count(),
        1,
        "and the peer count still said otherwise the whole time"
    );

    drop(quiet);
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

/// And the other half: a peer that arrives after the pool took the transfer is
/// still offered it, and `handed_on` says so.
///
/// This is the ordinary case for a person who opens a wallet and sends
/// something in the first minute. The one broadcast happened before this peer
/// existed; without somebody offering it again, the money sat in one process's
/// memory until that process stopped.
#[test]
fn a_peer_that_arrives_after_the_pool_took_it_is_still_offered_it() {
    let (wallet, blocks, directory) = funded("late-peer", 4);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    // On the same chain, so it can judge the transfer rather than refuse it.
    let receiver = Node::bind(params(), loopback()).unwrap();
    for block in &blocks {
        receiver.submit_block(block.clone()).unwrap();
    }

    assert_eq!(wallet.node().peer_count(), 0, "nobody to broadcast to");
    let listening = wallet.node().address();
    let arriving = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        receiver.connect(listening).unwrap();
        receiver
    });

    let sent = wallet.send(recipient, cairn("10"), cairn("0.5")).unwrap();
    let receiver = arriving.join().unwrap();
    assert!(sent.handed_on, "a peer took it into its queue");
    assert!(
        until(Duration::from_secs(10), || receiver
            .with_chain(|chain| chain.pooled(&sent.id).is_some())),
        "and it arrived, which is the fact the sentence on the screen is about"
    );

    drop(receiver);
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

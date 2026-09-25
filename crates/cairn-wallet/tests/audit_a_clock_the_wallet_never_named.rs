//! A wallet whose machine keeps a slow clock, and what it says about it.
//!
//! A block dated more than the allowed drift ahead of the reading machine's
//! clock is refused, and it is the one refusal two honest nodes can disagree
//! about. So a wallet on a machine whose clock is behind refuses every honest
//! block from the moment the chain moves past its clock, and from the outside
//! it looks like a wallet that is working: a height, a balance, and no
//! complaint. The height has stopped, payments to its owner do not arrive, and
//! the balance is the balance of a chain the network has left.
//!
//! `cairn_net::Node::clock_behind` has carried the evidence for that since the
//! node learned to count it, and `cairnd` prints a paragraph about the clock
//! from it. The wallet is a node as well, and `Progress::warning` read seven of
//! the states `cairnd` reports and not this one.

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
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::wire::write_message;
use cairn_net::Keeps;
use cairn_primitives::Hash32;
use cairn_wallet::Wallet;

const ATTEMPTS: u64 = 1 << 22;

/// This machine's own clock, which is the one the wallet's node reads.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-wallet-clock-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// Produces blocks on a private ledger, dated against this machine's clock so
/// the settled ones are ones the wallet takes.
struct Miner {
    state: LedgerState,
    clock: u64,
}

impl Miner {
    fn new() -> Self {
        Self {
            state: LedgerState::new(),
            clock: now() - 10_000,
        }
    }

    fn candidate(&self) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        let miner = SecretKey::from_bytes(&[1; 32]);
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
            &params,
            self.clock + 600,
            0,
        )
        .unwrap();
        mine_block(block, ATTEMPTS).expect("a nonce exists")
    }

    fn mine(&mut self) -> Block {
        let block = self.candidate();
        self.clock += 600;
        connect_block(&mut self.state, &block, &params(), self.clock).unwrap();
        block
    }
}

fn hello(nonce: u64, listen: u16) -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen,
        nonce,
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
    })
}

/// Reads everything the wallet's node sends down `socket` and answers nothing,
/// so a full receive buffer never ends the connection the test is about.
fn drain(socket: &TcpStream) {
    let Ok(mut reading) = socket.try_clone() else {
        return;
    };
    std::thread::spawn(move || {
        let mut scratch = [0u8; 4096];
        while let Ok(read) = std::io::Read::read(&mut reading, &mut scratch) {
            if read == 0 {
                return;
            }
        }
    });
}

/// A liveness bound, set far past what a loaded machine needs, and not a
/// measurement: it costs nothing once the condition holds.
fn wait_until(patience: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    ready()
}

/// A wallet whose node is refusing honest blocks for its clock says so where
/// its owner reads the balance.
///
/// Nothing asked this, so a wallet that had stopped following the chain for a
/// slow clock, with its node holding the evidence and `cairnd` printing it,
/// showed its owner a height, a balance and no warning at all.
#[test]
fn a_wallet_refusing_blocks_for_its_clock_says_so_beside_the_balance() {
    let directory = scratch("behind");
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &SecretKey::from_bytes(&[7; 32])).unwrap();
    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();

    let mut miner = Miner::new();
    for _ in 0..5 {
        wallet.node().submit_block(miner.mine()).unwrap();
    }
    assert!(
        wallet.progress().warning().is_none(),
        "a wallet that has refused nothing has nothing to say"
    );

    // One block for the next height, dated past what this machine's clock
    // allows and mined again, because the timestamp is under the work.
    let ahead = params().max_timestamp_drift + 900;
    let mut future = miner.candidate();
    future.header.timestamp = now() + ahead;
    let future = mine_block(future, ATTEMPTS).expect("a nonce exists");

    // Two connections advertising two different ports, which is two peers as
    // the node counts them, offering it four times each.
    let port = wallet.node().address().port();
    let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut sockets = Vec::new();
    for (nonce, listen) in [(4_711u64, 4_242u16), (4_712, 4_243)] {
        let mut socket = TcpStream::connect(at).unwrap();
        drain(&socket);
        write_message(&mut socket, params().network, &hello(nonce, listen)).unwrap();
        sockets.push(socket);
    }
    assert!(
        wait_until(Duration::from_secs(60), || wallet.node().peer_count() == 2),
        "both peers never arrived, so nothing below is being tested"
    );
    for _ in 0..4 {
        for socket in &mut sockets {
            write_message(
                socket,
                params().network,
                &Message::Block(Box::new(future.clone())),
            )
            .unwrap();
        }
    }
    assert!(
        wait_until(Duration::from_secs(60), || wallet
            .node()
            .clock_behind()
            .is_some()),
        "the node under the wallet never counted the refusals, so nothing below \
         is about the wallet"
    );

    let warning = wallet.progress().warning();
    wallet.shutdown();
    drop(sockets);
    let _ = std::fs::remove_dir_all(&directory);

    let warning = warning.expect(
        "the node under this wallet is refusing honest blocks for this machine's \
         clock, and the wallet had nothing to say beside the balance",
    );
    assert!(
        warning.contains("clock"),
        "the warning shown is not the one about the clock, so the owner is sent \
         to look at something else"
    );
}

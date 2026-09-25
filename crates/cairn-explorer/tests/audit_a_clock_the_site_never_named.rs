//! An explorer whose machine keeps a slow clock, and what `/api/status` says.
//!
//! A block dated more than the allowed drift ahead of the reading machine's
//! clock is refused, and it is the one refusal two honest nodes can disagree
//! about. An explorer on a slow clock refuses every honest block from the
//! moment the chain moves past its clock, and goes on serving the chain it
//! had as the chain, to strangers, with a height that has stopped.
//!
//! The `node` object of `/api/status` carries every other state its node can
//! report about itself, under a note on `Health` that nothing the node knows
//! should look healthy from here. `Node::clock_behind` was the one it did not
//! carry, and it is the one `cairnd` names first among the causes, because it
//! produces the symptoms of the others.
//!
//! The explorer is a binary with no library target, so both modules are
//! included by path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    dead_code
)]

#[path = "../src/api.rs"]
mod api;
#[path = "../src/index.rs"]
mod index;

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_http::{Request, Response};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::wire::write_message;
use cairn_net::{Keeps, Node};
use cairn_primitives::Hash32;

use api::Explorer;

const ATTEMPTS: u64 = 1 << 22;

/// This machine's own clock, which is the one the explorer's node reads.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// Produces blocks on a private ledger, dated against this machine's clock so
/// the settled ones are ones the explorer takes.
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

/// Reads everything the node sends down `socket` and answers nothing, so a
/// full receive buffer never ends the connection the test is about.
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

fn status(explorer: &Explorer) -> String {
    let request = Request {
        path: "/api/status".to_owned(),
        query: String::new(),
        head_only: false,
        post: false,
        body: String::new(),
        host: String::new(),
        origin: String::new(),
    };
    let answer: Response = explorer
        .answer(&request)
        .expect("the status route answered");
    String::from_utf8_lossy(&answer.body).into_owned()
}

/// A site whose node is refusing honest blocks for its clock says so in the
/// status it publishes, and a healthy one says in as many words that it is
/// not.
///
/// Nothing asked this, so an explorer that had stopped following the chain
/// for a slow clock, with its node holding the evidence and `cairnd` printing
/// it, published a `node` object that read exactly like a healthy one.
#[test]
fn a_site_refusing_blocks_for_its_clock_says_so_in_its_status() {
    let explorer = Explorer::new(
        Node::bind(params(), SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("a node on a free port"),
    );

    let mut miner = Miner::new();
    for _ in 0..5 {
        explorer.node().submit_block(miner.mine()).unwrap();
    }
    explorer.refresh();
    let healthy = status(&explorer);
    assert!(
        healthy.contains("\"clockBehind\":null"),
        "a node that has refused nothing does not say so in as many words, so \
         the field a reader would look for is not there"
    );

    let ahead = params().max_timestamp_drift + 900;
    let mut future = miner.candidate();
    future.header.timestamp = now() + ahead;
    let future = mine_block(future, ATTEMPTS).expect("a nonce exists");

    let at = explorer.node().address();
    let mut sockets = Vec::new();
    for (nonce, listen) in [(4_711u64, 4_242u16), (4_712, 4_243)] {
        let mut socket = TcpStream::connect(at).unwrap();
        drain(&socket);
        write_message(&mut socket, params().network, &hello(nonce, listen)).unwrap();
        sockets.push(socket);
    }
    assert!(
        wait_until(Duration::from_secs(60), || explorer.node().peer_count()
            == 2),
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
        wait_until(Duration::from_secs(60), || explorer
            .node()
            .clock_behind()
            .is_some()),
        "the node under the site never counted the refusals, so nothing below is \
         about the site"
    );

    let behind = status(&explorer);
    explorer.node().shutdown();
    drop(sockets);

    let object = behind
        .split_once("\"clockBehind\":{")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(inside, _)| inside.to_owned())
        .expect(
            "the node under this site is refusing honest blocks for this machine's \
             clock, and the status it publishes does not say so",
        );
    assert!(
        object.contains("\"peers\":2"),
        "the status does not say how many peers the refused blocks came from"
    );
    assert!(
        object.contains(&format!("\"drift\":{}", params().max_timestamp_drift)),
        "the status does not say what drift the rules allow, which is what the \
         gap is read against"
    );
    assert!(
        object.contains("\"ownFirstBlock\":false"),
        "the status does not say whether the evidence came off the wire or out \
         of the binary, which is the difference between a hint and a certainty"
    );
}

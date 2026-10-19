//! A miner that reaches a peer claiming a far heavier chain waits for it,
//! however long after its first peer it reaches that one.
//!
//! The time a miner gives a reached peer's heavier chain was a clock started
//! by the first peer reached, whatever that peer claimed, and closed for good
//! two block times later. A first peer that claimed nothing spent all of it,
//! and a peer reached after it, claiming six hundred blocks more, held the
//! miner for nothing: it went on mining floor blocks on its own tip, which at
//! the difficulty floor the wait for the chain cannot see. On testnet-8 that
//! shape mined 1 800 blocks on a tip the network had left.
//!
//! Run on devnet, where the block time is 5 seconds and the time given is 10.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cairn_ledger::note::NetworkId;
use cairn_net::message::{Handshake, Message};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::{Keeps, PROTOCOL_VERSION};
use cairn_primitives::Hash32;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Seconds after the node starts that the heavier peer introduces itself:
/// past the ten seconds devnet's two block times give peers' chains, counted
/// from the first peer reached.
const LATE: u64 = 16;
/// How long the node runs.
const RUN_FOR: u64 = 36;

/// A peer that waits `greet_after` from `start` before it introduces itself,
/// then claims `height` blocks carrying `work`, and answers nothing else but
/// a ping. It never hands a block over.
fn peer(
    door: TcpListener,
    start: Instant,
    greet_after: u64,
    height: u64,
    work: u128,
    nonce: u64,
    asked: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listen = door.local_addr().unwrap().port();
        door.set_nonblocking(true).unwrap();
        let deadline = start
            .checked_add(Duration::from_secs(RUN_FOR.saturating_add(10)))
            .unwrap();
        let mut stream = loop {
            match door.accept() {
                Ok((stream, _)) => break stream,
                Err(_) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let said = Handshake {
            version: PROTOCOL_VERSION,
            network: NetworkId::DEVNET,
            genesis: Hash32::ZERO,
            height,
            total_work: work,
            listen,
            nonce,
            keeps: Keeps::default(),
        };
        let mut greeted = false;
        let mut heard_hello = false;
        while Instant::now() < deadline {
            let mut answers = Vec::new();
            if !greeted && heard_hello && start.elapsed() >= Duration::from_secs(greet_after) {
                greeted = true;
                answers.push(Message::Welcome(said));
            }
            match read_message(&mut stream, NetworkId::DEVNET, MAX_FRAME_BYTES) {
                Ok(Incoming::Message(Message::Hello(_))) => heard_hello = true,
                Ok(Incoming::Message(Message::GetChain { .. })) => {
                    asked.store(true, Ordering::SeqCst);
                }
                Ok(Incoming::Message(Message::Ping(one))) => {
                    answers.push(Message::Pong(one));
                }
                Ok(_) => {}
                Err(_) => return,
            }
            for answer in &answers {
                if write_message(&mut stream, NetworkId::DEVNET, answer).is_err() {
                    return;
                }
            }
        }
    })
}

/// **A miner that reaches a peer claiming a far heavier chain waits for it,
/// though an earlier peer that claimed nothing was reached long before.**
#[test]
fn a_heavier_peer_reached_long_after_the_first_holds_the_miner() {
    let directory = std::env::temp_dir().join(format!(
        "cairnd-a-heavier-peer-reached-late-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let key = cairn_crypto::SecretKey::generate().unwrap().public_key();
    let quiet = TcpListener::bind("127.0.0.1:0").unwrap();
    let heavy = TcpListener::bind("127.0.0.1:0").unwrap();
    let quiet_at = quiet.local_addr().unwrap();
    let heavy_at = heavy.local_addr().unwrap();
    let asked = Arc::new(AtomicBool::new(false));

    let start = Instant::now();
    // At once, and with nothing to offer: the chain is at its first block and
    // this claims no more. It is a peer this node reached all the same.
    let first = peer(quiet, start, 0, 0, 0, 1, Arc::new(AtomicBool::new(false)));
    // And later, a peer claiming six hundred blocks of the heaviest chain
    // there could be, which it never hands over.
    let second = peer(heavy, start, LATE, 600, u128::MAX, 2, Arc::clone(&asked));

    let mut node = Command::new(env!("CARGO_BIN_EXE_cairnd"))
        .args([
            "--network",
            "devnet",
            "--data",
            &directory.to_string_lossy(),
            "--listen",
            "127.0.0.1:0",
            "--seed",
            &quiet_at.to_string(),
            "--seed",
            &heavy_at.to_string(),
            "--mine",
            &cairn_primitives::hex::encode(key.as_bytes()),
            "--status",
            "5",
            "--run-for",
            &RUN_FOR.to_string(),
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("cairnd starts");

    let mut mined_before = 0usize;
    let mut waiting = false;
    let mut waited = false;
    let mut mined_while_waiting: Vec<String> = Vec::new();
    for line in BufReader::new(node.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        let at = start.elapsed().as_secs();
        let said = line.split_once("] ").map_or("", |(_, said)| said);
        if said.starts_with("mining waits while this node takes the chain") {
            waiting = true;
            waited = true;
        } else if said.starts_with("mining again") {
            waiting = false;
        } else if said.starts_with("mined") {
            if waiting {
                mined_while_waiting.push(format!("at {at}s: {said}"));
            } else if !waited {
                mined_before += 1;
            }
        }
    }
    let status = node.wait().unwrap();
    first.join().unwrap();
    second.join().unwrap();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(status.success(), "the run ended on {status}");
    assert!(
        mined_before > 0,
        "fixture: the miner never mined before the heavier peer spoke, so the first peer \
         spent nothing"
    );
    assert!(
        asked.load(Ordering::SeqCst),
        "fixture: the node never asked the heavier peer for its chain, so it never read \
         the claim"
    );
    assert!(
        waited,
        "a miner that reached a peer claiming six hundred blocks more went on mining on its \
         own tip, because an earlier peer that claimed nothing had already been reached for \
         longer than the time it gives a peer's chain"
    );
    assert!(
        mined_while_waiting.is_empty(),
        "the miner said it waited for the heavier chain and mined all the same: {:?}",
        mined_while_waiting.get(..6).unwrap_or(&mined_while_waiting)
    );
}

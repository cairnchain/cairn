//! A piece of a join answer from a peer nobody asked.
//!
//! A `JoinPart` is not charged against the sender's window, on the ground
//! that only the peer a newcomer asked has any business sending one. What
//! holds that is the check in `join_piece` that the sender is the peer the
//! chooser asked to join from. Without it a stranger could open a newcomer's
//! collector with an answer of its own choosing, which would then throw away
//! the real answer and have the chooser blame the peer it had asked. The
//! visible trace of that: the newcomer goes on to ask the stranger for the
//! rest. The 2026-10-30 protocol bounds audit (F1) read the collector without
//! this check and reported it missing; this pins it from outside.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::{Handshake, Joining, Keeps, Message, PROTOCOL_VERSION};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::Hash32;

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[test]
fn a_newcomer_takes_no_piece_of_a_join_from_a_peer_it_did_not_ask() {
    let params = ConsensusParams::testnet();
    let network = params.network;
    let newcomer = Node::bind(params, loopback()).unwrap();

    let listener = TcpListener::bind(loopback()).unwrap();
    let address = listener.local_addr().unwrap();
    let asked = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&asked);
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();
        loop {
            let message = match read_message(&mut stream, network, MAX_FRAME_BYTES) {
                Ok(Incoming::Message(message)) => message,
                Ok(Incoming::Quiet) => continue,
                Err(_) => return,
            };
            match message {
                Message::Hello(_) => {
                    // Claims nothing, so nothing would ever ask it to help a
                    // join, and then answers a question nobody put.
                    let welcome = Message::Welcome(Handshake {
                        version: PROTOCOL_VERSION,
                        network,
                        genesis: Hash32::ZERO,
                        height: 0,
                        total_work: 0,
                        listen: 0,
                        nonce: 7,
                        keeps: Keeps {
                            headers: false,
                            cold_set: false,
                        },
                    });
                    let unasked = Message::JoinPart {
                        what: Joining::Weight,
                        at: Hash32::from_bytes([9; 32]),
                        part: 0,
                        parts: 2,
                        bytes: vec![0xAB; 512],
                    };
                    if write_message(&mut stream, network, &welcome).is_err()
                        || write_message(&mut stream, network, &unasked).is_err()
                    {
                        return;
                    }
                }
                Message::GetJoin { .. } => {
                    counted.fetch_add(1, Ordering::SeqCst);
                }
                Message::Ping(token) => {
                    let _ = write_message(&mut stream, network, &Message::Pong(token));
                }
                _ => {}
            }
        }
    });

    newcomer.connect(address).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        assert_eq!(
            asked.load(Ordering::SeqCst),
            0,
            "the newcomer took a piece from a peer it never asked, and asked it for the rest"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

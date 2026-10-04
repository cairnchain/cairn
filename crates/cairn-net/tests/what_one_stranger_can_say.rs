//! What one stranger can make a node say about the chain it is on.
//!
//! cairnd prints the count of blocks from a branch this node cannot switch to
//! on every status line once it is above nought, and the explorer shows it on
//! every page: the node may be on a branch the network has left, and starting
//! again from an empty directory is the only way onto theirs. What raises it
//! is any block the chain refuses as too old, and `ChainStore::add_block`
//! answers that for a block at or under the undo floor after checking its
//! work against the difficulty the block itself declares, before its parent is
//! looked for. So a block whose parent exists nowhere, sent by one greeted
//! stranger, cost a hash at the easiest difficulty and raised the count by
//! one each time it was sent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Keeps;
use cairn_net::Node;
use cairn_primitives::Hash32;

const ATTEMPTS: u64 = 1 << 22;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// testnet-8's rules with a burial of 32, so the undo floor is reached in 40
/// blocks rather than a thousand.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(32)
}

fn chain(count: usize) -> Vec<Block> {
    let params = params();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    let mut clock = now() - 100_000;
    let mut blocks = Vec::new();
    for _ in 0..count {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut state, &block, &params, clock).unwrap();
        blocks.push(block);
    }
    blocks
}

fn hello(nonce: u64, listen: u16) -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
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

fn pongs(socket: &TcpStream) -> mpsc::Receiver<u64> {
    let (heard, pongs) = mpsc::channel();
    let mut reading = socket.try_clone().unwrap();
    std::thread::spawn(move || {
        while let Ok(incoming) = read_message(&mut reading, params().network, MAX_FRAME_BYTES) {
            if let Incoming::Message(Message::Pong(number)) = incoming {
                if heard.send(number).is_err() {
                    return;
                }
            }
        }
    });
    pongs
}

fn ponged(pongs: &mpsc::Receiver<u64>, number: u64, patience: Duration) -> bool {
    let deadline = Instant::now() + patience;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match pongs.recv_timeout(left) {
            Ok(heard) if heard == number => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

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

/// **Blocks from nowhere, sent by one stranger, are not said as a branch the
/// network has left.**
///
/// The count went up by one for every such block from anybody and never came
/// down. Nothing asked who sent them, so a node that let one stranger write
/// its operator's most drastic line passed.
#[test]
fn a_block_with_no_parent_anywhere_is_not_a_chain_the_node_cannot_switch_to() {
    let settled = chain(40);
    let node = Node::bind(params(), SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    for block in &settled {
        node.submit_block(block.clone()).unwrap();
    }
    assert_eq!(node.height(), Some(39), "the node follows the 40 blocks");
    assert!(
        node.probation().is_none(),
        "a node that read its way up is not on probation"
    );
    assert_eq!(node.out_of_reach(), 0, "nothing has arrived yet");

    // Not a block of any chain: block 1 with its parent replaced by bytes no
    // block has ever hashed to, and the nonce found again for the difficulty
    // it declares (the easiest one).
    let mut orphan = settled[1].clone();
    orphan.header.previous = Hash32::from_bytes([0x5a; 32]);
    let orphan = mine_block(orphan, ATTEMPTS).expect("a nonce exists");

    let mut socket = TcpStream::connect(node.address()).unwrap();
    let pongs = pongs(&socket);
    write_message(&mut socket, params().network, &hello(4_711, 4_242)).unwrap();
    assert!(
        wait_until(Duration::from_secs(60), || node.peer_count() == 1),
        "the peer never arrived, so nothing below is being tested"
    );

    let sent = 5u64;
    for _ in 0..sent {
        write_message(
            &mut socket,
            params().network,
            &Message::Block(Box::new(orphan.clone())),
        )
        .unwrap();
    }
    write_message(&mut socket, params().network, &Message::Ping(0x0707)).unwrap();
    let read = ponged(&pongs, 0x0707, Duration::from_secs(120));
    let counted = node.out_of_reach();
    let still_held = node.peer_count();
    let height = node.height();
    node.shutdown();

    assert!(read, "the ping behind the blocks was never answered");
    assert_eq!(still_held, 1, "fixture: the stranger was let go of");
    assert_eq!(height, Some(39), "fixture: the node moved off its chain");
    assert_eq!(
        counted, 0,
        "a block whose parent exists nowhere, sent by one stranger for the price of \
         one hash at the easiest difficulty, was said as blocks from a chain this node \
         cannot switch to: cairnd prints on every status line that the node may be on a \
         branch the network has left, and the explorer page that what it shows may not \
         be what the network agrees on"
    );
}

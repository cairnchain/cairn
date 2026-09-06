//! What this node's own disk would not give back, and who hears about it.
//!
//! A node keeps its blocks in one file and where each record sits in another.
//! The second is derived: the store's own account of it says it is worked out
//! from the first and never believed. The start does not check all of it, and
//! it does not have to, because the replay that reads a chain back walks the
//! log forward and never opens the index at all.
//!
//! So one flipped byte in the middle of that index is invisible to everything
//! that starts a node and fatal to every later read of the one record it
//! covers. Two things came of that, and both are here.
//!
//! The first was that a node would not start. Filling the header log in from
//! the blocks is the first thing after the replay that reads a record by
//! position, and its failure was handed straight out of `Node::open`. Twelve
//! blocks out of twelve replayed, nothing was wrong with the chain, and an
//! unattended node stayed down for ever over a file the store rebuilds from
//! the blocks when it is asked to.
//!
//! The second was that a node that did start said nothing. Every read that
//! answers somebody else took the refusal as an absence: a peer asking for
//! that stretch was sent the blocks around it, dropped everything after the
//! hole because the parent never landed, and asked again. The height climbed,
//! the peers stayed connected, the stored height matched the chain, and the
//! only party who could see anything wrong was the peer, who has no way to
//! tell a node that will not answer from one that cannot.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::node::{Node, Reading};
use cairn_store::{BLOCK_INDEX, HEADER_LOG};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The record whose offset is spoiled.
///
/// Far enough from both ends to be a middle entry: the store checks the first
/// record and the last offset when it opens a log, and nothing in between.
const SPOILED: u64 = 5;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-own-disk-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn chain(count: usize) -> Vec<Block> {
    let miner = SecretKey::from_bytes(&[4; 32]);
    let params = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
            connect_block(&mut state, &block, &params, NOW).unwrap();
            block
        })
        .collect()
}

/// Turns one offset in the index into a number the log does not agree with.
///
/// A byte, in the middle, in the file the store says it can work out again.
/// Nothing is done to the blocks themselves: every record is whole, and a walk
/// of the log from the front reads all of them.
fn spoil_one_offset(directory: &Path) {
    let path = directory.join(BLOCK_INDEX);
    let mut bytes = std::fs::read(&path).unwrap();
    let at = (SPOILED as usize) * 8;
    assert!(
        bytes.len() > at + 16,
        "the index has to reach past the entry being spoiled and past the one after it"
    );
    bytes[at] ^= 0x40;
    std::fs::write(&path, &bytes).unwrap();
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let started = Instant::now();
    // Long, and long on purpose. This suite runs beside the rest of the
    // workspace on whatever machine happens to be building, and a bound set to
    // what the work takes on an idle one is a test that passes alone and fails
    // in a full run.
    while started.elapsed() < Duration::from_secs(60) {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("waited a minute for {what}");
}

/// The start. A node whose chain is entirely intact and whose header log needs
/// filling in used to be stopped by this, permanently and unattended.
#[test]
fn a_spoiled_index_entry_does_not_stop_a_node_from_starting() {
    let directory = scratch("start");
    let blocks = chain(12);
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    for block in &blocks {
        node.submit_block(block.clone()).unwrap();
    }
    node.shutdown();
    drop(node);

    // A node updated from a version that kept no headers, which is the case
    // the header catch-up exists for and the one that reads every block back.
    std::fs::remove_file(directory.join(HEADER_LOG)).unwrap();
    spoil_one_offset(&directory);

    let started = Node::open(params(), loopback(), &directory);
    let (node, restored) = match started {
        Ok(started) => started,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&directory);
            panic!(
                "a node with all twelve of its blocks on the disk refused to start: {error}. \
                 The index beside the log is derived and one byte of it had rotted."
            );
        }
    };
    let unread = node.unread();
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        restored.blocks, 12,
        "the replay reads the log forward and the index has nothing to do with it, \
         so every block is still there"
    );
    let unread = unread.expect("the refusal reached somebody");
    assert_eq!(unread.what, Reading::Blocks);
    assert_eq!(
        unread.height, SPOILED,
        "and it names the record the disk would not give back"
    );
    assert!(
        !unread.because.is_empty(),
        "in the store's own words, which is what tells an index that disagrees \
         with the log from a record that will not decode"
    );
}

/// And the running node. What a peer asking over the damaged stretch is served,
/// and what is said about it on the side that could see it.
#[test]
fn a_block_the_disk_refuses_a_peer_is_named_here_rather_than_left_to_the_peer() {
    // Past `WARM_BODIES`, so the blocks at the bottom of the chain are on the
    // disk and nowhere else. A node that answered this out of memory would
    // prove nothing about a disk.
    let blocks = chain(81);
    let host_directory = scratch("host");
    let (host, _) = Node::open(params(), loopback(), &host_directory).unwrap();
    for block in &blocks[..80] {
        host.submit_block(block.clone()).unwrap();
    }
    host.shutdown();
    drop(host);

    spoil_one_offset(&host_directory);

    let (host, restored) = Node::open(params(), loopback(), &host_directory).unwrap();
    assert_eq!(restored.blocks, 80, "the chain replayed whole");
    assert_eq!(
        host.unread(),
        None,
        "nothing has been read back by position yet, so nothing has been refused yet"
    );
    // One more block, which is what makes the chain let go of the bodies it
    // has written down. Until it does, every answer comes out of memory.
    host.submit_block(blocks[80].clone()).unwrap();

    let directory = scratch("peer");
    let (peer, _) = Node::open(params(), loopback(), &directory).unwrap();
    peer.connect(host.address()).unwrap();
    wait_for(
        "the peer to catch up to the block below the spoiled one",
        || peer.height() == Some(SPOILED - 1),
    );
    // Long enough for a second batch to have been asked for and answered, so
    // that stopping here is where it stops rather than where it had reached.
    std::thread::sleep(Duration::from_millis(500));

    let reached = peer.height();
    let unread = host.unread();
    // What an operator watching the serving node sees while this is going on.
    // Every one of these is the number a healthy node prints.
    println!(
        "the host: height {:?}, stored through {:?}, peers {}, blocks from {:?}",
        host.height(),
        host.written_through(),
        host.peer_count(),
        host.blocks_from(),
    );
    println!("and the peer catching up from it reached {reached:?} of 80");
    peer.shutdown();
    host.shutdown();
    drop(peer);
    drop(host);
    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&host_directory);

    assert_eq!(
        reached,
        Some(SPOILED - 1),
        "the peer applies what arrives in order and drops whatever hangs off the \
         missing block, so one refused record costs it the whole chain above"
    );
    let unread = unread.expect(
        "the peer was served a chain with a hole in it and this node said nothing \
         about it anywhere",
    );
    assert_eq!(unread.what, Reading::Blocks);
    // Either of the two the byte covers. An entry in that file is where one
    // record ends and where the next one starts, so spoiling one of them makes
    // two records unreadable, and which of the two is named is whichever the
    // peer asked for last.
    assert!(
        unread.height == SPOILED || unread.height == SPOILED + 1,
        "it named block {}, and the spoiled offset is the one between {SPOILED} and {}",
        unread.height,
        SPOILED + 1,
    );
    assert!(
        unread.refusals >= 1,
        "and it counts them, because one is a byte and a hundred is a drive"
    );
}

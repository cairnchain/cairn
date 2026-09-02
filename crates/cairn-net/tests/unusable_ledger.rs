//! A ledger file that is there and will not be taken is not a node that never
//! had one.
//!
//! Every node writes this file as it runs, and its own documentation calls it
//! a file a node cannot start without. Reading a failure to use it the same
//! way as its absence cost the node its whole history: the replay would start
//! at block zero, the log begins above that on any node that has written a
//! ledger, and the gap between them was read as a log leading nowhere and cut
//! to nothing.
//!
//! What was at stake was not only a node that joined a chain from a stranger.
//! A rules update that refused a node's own stored ledger would have emptied
//! it, and so would an operator tidying a directory.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, Block, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::{Node, NodeError};
use cairn_store::{BlockLog, HANDED_LEDGER};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const BLOCKS: usize = 40;

/// Rules written for a version this build does not have, from the first block.
/// A node one release behind reads its own stored ledger against these.
const AHEAD: &[Activation] = &[Activation {
    height: 0,
    version: BLOCK_VERSION + 1,
}];

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
        std::env::temp_dir().join(format!("cairn-unusable-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// A chain built off to the side, so a node can be given a real one.
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

/// A node that has run, written its own ledger down, and dropped the blocks
/// below it. Answers the directory and how many records its log holds.
fn a_node_that_wrote_its_ledger(name: &str) -> (PathBuf, usize) {
    let directory = scratch(name);
    let blocks = chain(BLOCKS);
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    for block in &blocks {
        node.submit_block(block.clone()).unwrap();
    }
    assert!(
        node.write_ledger(),
        "the node wrote down the ledger it will start from next time"
    );
    node.shutdown();
    drop(node);

    assert!(
        directory.join(HANDED_LEDGER).exists(),
        "every node writes this file as it runs"
    );
    let (log, _) = BlockLog::open(&directory).unwrap();
    let held = log.len();
    drop(log);
    assert!(held > 0, "and it still holds the blocks it validated");
    (directory, held)
}

/// The blocks are still there afterwards, whatever the file did.
fn still_holds(directory: &PathBuf, expected: usize) {
    let (log, _) = BlockLog::open(directory).unwrap();
    let held = log.len();
    drop(log);
    assert_eq!(
        held, expected,
        "the block log was emptied over a file this node could have been given again"
    );
}

#[test]
fn a_ledger_file_that_will_not_decode_does_not_cost_the_block_log() {
    let (directory, held) = a_node_that_wrote_its_ledger("garbled");
    std::fs::write(directory.join(HANDED_LEDGER), b"not a ledger").unwrap();

    let refused = Node::open(params(), loopback(), &directory);
    assert!(
        matches!(refused, Err(NodeError::UnusableLedger { .. })),
        "a file that is there and will not be read is not a node that never had one: {:?}",
        refused.map(|_| ())
    );
    still_holds(&directory, held);
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_ledger_the_rules_refuse_does_not_cost_the_block_log() {
    let (directory, held) = a_node_that_wrote_its_ledger("refused");

    // The shape a rule change takes from here: the same file, read by a build
    // whose rules say every height needs a version it does not have. That is
    // the position of every node that has not updated on the day one lands.
    let elsewhere = ConsensusParams {
        activations: AHEAD,
        ..params()
    };

    let refused = Node::open(elsewhere, loopback(), &directory);
    assert!(
        matches!(refused, Err(NodeError::UnusableLedger { .. })),
        "a ledger the rules refuse is not a node that never had one: {:?}",
        refused.map(|_| ())
    );
    still_holds(&directory, held);
    let _ = std::fs::remove_dir_all(&directory);
}

/// And the case the old reading was right about: no file at all is an ordinary
/// node, and it starts.
#[test]
fn a_node_with_no_ledger_file_starts_as_it_always_did() {
    let directory = scratch("absent");
    let blocks = chain(8);
    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    assert_eq!(restored.blocks, 0);
    for block in &blocks {
        node.submit_block(block.clone()).unwrap();
    }
    node.shutdown();
    drop(node);

    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    assert_eq!(
        restored.blocks,
        blocks.len(),
        "it read its own log back and applied every block"
    );
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

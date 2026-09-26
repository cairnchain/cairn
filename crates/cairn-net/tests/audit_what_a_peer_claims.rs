//! What a peer says its chain has when it introduces itself, kept.
//!
//! A handshake carries the height and the work behind the tip of the peer's
//! chain. The node read them once, to decide whether to ask the peer for its
//! chain, and threw them away, so a wallet waiting for its chain to catch up
//! had no way to tell a chain that had stopped at the network's tip from one
//! that had stopped behind it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// A chain of `length` blocks on the test rules.
fn chain(length: usize) -> Vec<Block> {
    let rules = params();
    let owner = cairn_crypto::SecretKey::generate().unwrap().public_key();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut blocks = Vec::new();
    for _ in 0..length {
        let height = state.next_height().unwrap();
        clock = clock.saturating_add(600);
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(rules.initial_reward, owner)]);
        let block = assemble_block(&state, coinbase, Vec::new(), &rules, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &rules, NOW).unwrap();
        blocks.push(block);
    }
    blocks
}

fn until(patience: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = Instant::now().checked_add(patience).unwrap();
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    ready()
}

/// The most work any peer claimed, with the height it gave, is what the node
/// says its peers claim.
///
/// Nothing kept it, so there was nothing to ask.
#[test]
fn the_most_work_a_peer_claimed_is_kept_with_its_height() {
    let longer = chain(3);
    let shorter = &longer[..1];
    let (ahead, behind) = (
        Node::bind(params(), loopback()).unwrap(),
        Node::bind(params(), loopback()).unwrap(),
    );
    for block in &longer {
        ahead.submit_block(block.clone()).unwrap();
    }
    for block in shorter {
        behind.submit_block(block.clone()).unwrap();
    }
    let (height, work) = (ahead.height().unwrap(), ahead.total_work());

    // Nobody to hear from, and so nothing claimed.
    let asking = Node::bind(params(), loopback()).unwrap();
    assert_eq!(asking.best_claim(), None, "a claim from nobody");
    asking.connect(behind.address()).unwrap();
    asking.connect(ahead.address()).unwrap();
    assert!(
        until(Duration::from_secs(20), || asking.best_claim()
            == Some((height, work))),
        "the most work a peer claimed in its handshake was not kept"
    );

    asking.shutdown();
    ahead.shutdown();
    behind.shutdown();
}

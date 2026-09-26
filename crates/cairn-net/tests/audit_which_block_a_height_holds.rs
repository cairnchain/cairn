//! Which block the branch a node follows carries at a height.
//!
//! A wallet asks this of its node every time it looks, to learn whether the
//! blocks it read are still the chain. The only way to ask used to be
//! `archived_at`, which reads and decodes the whole block off the block log,
//! and the block log is the one record a node trims from the front: a height
//! it let go of answered nothing, and nothing was read as nothing changed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::node::Node;

const NOW: u64 = 2_000_000_000;
const BLOCKS: u64 = 200;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(8)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn a_chain() -> Vec<Block> {
    let params = params();
    let miner = SecretKey::from_bytes(&[4; 32]).public_key();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..BLOCKS)
        .map(|height| {
            clock += 600;
            let coinbase =
                CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, miner)]);
            let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
            let block = mine_block(block, 1 << 22).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            block
        })
        .collect()
}

/// A node names the block its branch carries at every height it has a header
/// for, including heights a node started again from its own ledger no longer
/// holds in memory and has trimmed off its block log.
///
/// Nothing asked a node this without reading the block itself, so a node
/// that could only answer about blocks still on its log passed.
#[test]
fn a_node_names_the_block_at_every_height_it_has_a_header_for() {
    let directory = std::env::temp_dir().join(format!("cairn-which-block-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let chain = a_chain();
    {
        let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
        for block in &chain {
            node.submit_block(block.clone()).unwrap();
        }
        assert!(node.write_ledger());
        node.keep_blocks(1);
        let deadline = Instant::now() + Duration::from_secs(300);
        while node.archived_at(0).is_some() {
            assert!(Instant::now() < deadline, "the node never trimmed its log");
            std::thread::sleep(Duration::from_millis(20));
        }
        node.shutdown();
    }

    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    assert_eq!(node.height(), Some(BLOCKS - 1));
    assert!(
        node.with_chain(|held| held.id_at(1)).is_none() && node.archived_at(1).is_none(),
        "the chain in memory and the block log both still hold height 1, so this asks \
         nothing of the header log"
    );
    for (height, block) in (0..).zip(&chain) {
        assert_eq!(
            node.id_at(height),
            Some(block.id()),
            "the node did not name the block its branch carries at height {height}"
        );
    }
    assert_eq!(node.id_at(BLOCKS), None, "and names nothing above its tip");

    node.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

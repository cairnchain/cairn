//! What a node forgets when it takes a ledger it did not build.
//!
//! Found while working out what breaks if nobody runs an archivist. The
//! answer turned out not to depend on archivists at all: the one thing that
//! saves an ordinary wallet from ever needing one is that its node follows its
//! owner and writes down where each of its notes lands when it falls. That
//! following is held in the ledger state, and a ledger taken from somewhere
//! else replaces the state whole.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 20;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A short chain, and the headers that go with it.
fn chain(blocks: usize) -> (Vec<Block>, Vec<BlockHeader>) {
    let params = ConsensusParams::testnet();
    let miner = wallet(1);
    let mut state = LedgerState::new();
    let mut clock = 1_000_000u64;
    let mut made = Vec::new();
    for _ in 0..blocks {
        let height = state.next_height().unwrap();
        clock += 60;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        made.push(block);
    }
    let headers = made.iter().map(|block| block.header).collect();
    (made, headers)
}

/// Adopting a ledger discards the owners the node was told to follow.
///
/// `ChainStore::adopt` assigns the handed ledger over the node's own state,
/// and following an owner lives in that state. A ledger built somewhere else
/// follows nobody, because a handover carries the hot set, sixty four cold
/// roots and the grace window, and nothing about who anybody is watching.
///
/// What it costs is the whole of a wallet's recovery story. `cairn-net` names
/// the owners once, at `node.rs:1598`, and then adopts a ledger in two places:
/// at `node.rs:1621` from the `ledger.dat` on disk, and at `node.rs:2460` when
/// a newcomer joins from a peer. Both run after the naming and neither names
/// them again, so a node that joined rather than read follows nobody from the
/// moment it joined, and `keep_ledger` at `node.rs:2475` writes the file that
/// makes every later start do the same.
///
/// A node that follows nobody records no position for any note of its owner's
/// that falls. The wallet's own history keeps identifiers and values and no
/// positions, so it cannot supply one either, and there is no message in the
/// protocol by which it could ask anybody for a proof. The money is visible,
/// correct, and unspendable, and nothing says so until the owner tries.
///
/// Naming the owners again after every adopt would have worked and is the
/// wrong repair, because it leaves the trap set for the third caller. Who a
/// node follows is a fact about the node, so `adopt` carries it across rather
/// than letting a ledger from elsewhere decide it.
#[test]
fn an_adopted_ledger_does_not_decide_who_this_node_follows() {
    let params = ConsensusParams::testnet();
    let owner = wallet(7).public_key();

    // A ledger built by somebody else, following nobody, which is what a
    // handover and what `ledger.dat` both are.
    let (blocks, headers) = chain(4);
    let mut elsewhere = ChainStore::new(params);
    for block in blocks {
        elsewhere.add_block(block, NOW).unwrap();
    }
    let handed = elsewhere.ledger_at(elsewhere.height().unwrap()).unwrap();
    assert!(
        !handed.is_watching(&owner),
        "a ledger from elsewhere follows nobody"
    );

    // A node told to follow an owner, the way `cairn-net` does at start.
    let mut node = ChainStore::new(params);
    node.watch_owner(owner);
    assert!(node.state().is_watching(&owner));

    // And then handed a ledger, the way `cairn-net` does immediately after.
    node.adopt(handed.clone(), &headers).unwrap();
    assert!(
        node.state().is_watching(&owner),
        "a ledger from elsewhere does not decide who this node follows"
    );

    // Which is what lets the wallet keep working: a note of that owner's that
    // falls after the join has its position written down, so a proof can be
    // built for it. Without this the money was visible, correct and
    // unspendable, about three hours after a wallet first started.
    let mut second = ChainStore::new(params);
    second.watch_owner(owner);
    second.watch_owner(wallet(9).public_key());
    second.adopt(handed, &headers).unwrap();
    assert!(second.state().is_watching(&owner));
    assert!(second.state().is_watching(&wallet(9).public_key()));
}

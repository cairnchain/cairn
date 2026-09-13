//! Who wrote `ledger.dat` is not what decides whether a node owes anything for
//! it.
//!
//! An audit read the two facts side by side and drew a conclusion from them
//! that does not follow. The facts: a node handed a ledger writes it under the
//! name `ledger.dat`, and a node that read the chain from the first block
//! writes its own ledger under that same name. The conclusion drawn: the
//! second one restarts, `read_handed_ledger` reads the file, and the node
//! comes back reporting it was handed a ledger it in fact wrote itself. Three
//! surfaces then tell its operator to delete the data directory.
//!
//! The two facts are true. The conclusion is not, and this file is why.
//!
//! An undertaking is closed by a height and not by a provenance. What is read
//! back off the file is an anchor and the height the writer's own chain had
//! reached, and `Undertaking::resumed` keeps the undertaking only while the
//! restarted chain has not reached the second of those. A node writes its own
//! ledger anchored a burial below its tip, so the height it owes is the tip it
//! had when it wrote, and a restart replays its own blocks straight back to
//! it. It owes nothing, and it is told nothing.
//!
//! Which leaves the case the audit was reaching for, and it is the one where
//! probation is right rather than wrong: a node holding that file and not the
//! blocks above it cannot check its own way past its own anchor, and until
//! somebody sends those blocks back it is standing on an account of them it
//! cannot verify. That it wrote the account itself, on a machine whose disk
//! has since lost the blocks, does not make it checked. The second test here
//! is that case, and it is also what stops the first test from being an
//! assertion that cannot fail: without it, `probation().is_none()` would pass
//! just as well on a build where nothing ever puts a node on probation at all.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::node::Node;
use cairn_store::{BLOCK_INDEX, BLOCK_LOG, HANDED_LEDGER};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Blocks a ledger is anchored below its tip.
const BURIAL: u64 = 8;

/// Blocks the node reads for itself. Heights nought to twenty three, so the
/// anchor lands at fifteen and the tip it is owed to at twenty three.
const BLOCKS: usize = 24;

/// The height a ledger written at the tip of [`BLOCKS`] is anchored at.
const ANCHOR: u64 = (BLOCKS as u64) - 1 - BURIAL;

/// The height that ledger is owed to, which is the tip it was written at.
const OWED_TO: u64 = (BLOCKS as u64) - 1;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(BURIAL)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-whose-ledger-{}-{name}", std::process::id()));
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

/// A node that reads `blocks` for itself and writes its own ledger down.
///
/// The ledger is asked for rather than waited for. Upkeep writes one on its
/// own schedule once the log is over the budget, and a test that waited for
/// that schedule would be a test about a sleep.
fn a_node_that_wrote_its_own_ledger(directory: &Path, blocks: &[Block]) {
    let (node, _) = Node::open(params(), loopback(), directory).unwrap();
    for block in blocks {
        node.submit_block(block.clone()).unwrap();
    }
    assert!(
        node.probation().is_none(),
        "it read every block itself, so there was never anything owed"
    );
    assert!(
        node.write_ledger(),
        "the ledger this whole file is about was not written"
    );
    node.shutdown();
    drop(node);
    assert!(
        directory.join(HANDED_LEDGER).exists(),
        "the file a restart reads is the one under test"
    );
}

/// The claim. Its own ledger, read back, owes nothing.
#[test]
fn a_ledger_a_node_wrote_itself_is_nothing_owed_when_it_comes_back() {
    let directory = scratch("its-own");
    let blocks = chain(BLOCKS);
    a_node_that_wrote_its_own_ledger(&directory, &blocks);

    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    let probation = node.probation();
    let stranded = node.stranded();
    let height = node.height();
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        probation, None,
        "a node that read every block of its own chain was told it was holding \
         somebody else's account of it. The replay put back {} blocks and the \
         chain reached {height:?}.",
        restored.blocks
    );
    assert_eq!(
        stranded, None,
        "and nothing sent its operator to delete the directory"
    );
    assert_eq!(
        height,
        Some(OWED_TO),
        "the restart has to reach the tip the ledger was written at, because \
         that is the height that closes the undertaking"
    );
}

/// The same file, with the blocks above it gone: owed, and right to be.
///
/// This is the state the audit was reaching for, and the reading of it that
/// makes probation a defect has the direction backwards. A node holding an
/// anchor and none of the blocks between it and the height that anchor was
/// taken on cannot check its own way past it, whoever wrote the file down.
#[test]
fn the_same_file_is_owed_when_the_blocks_above_it_are_gone() {
    let directory = scratch("no-blocks");
    let blocks = chain(BLOCKS);
    a_node_that_wrote_its_own_ledger(&directory, &blocks);

    // What a disk that lost the log looks like, and what a node that dropped
    // every block it held would look like if anything let it drop this many.
    std::fs::remove_file(directory.join(BLOCK_LOG)).unwrap();
    std::fs::remove_file(directory.join(BLOCK_INDEX)).unwrap();

    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    let probation = node.probation();
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);

    let probation = probation.expect(
        "a node holding an anchor and none of the blocks above it has checked \
         nothing past that anchor, and saying so is the whole of what probation \
         is for",
    );
    assert_eq!(probation.anchor, ANCHOR, "the height the ledger stands at");
    assert_eq!(
        probation.settles_at, OWED_TO,
        "the height the anchor was taken on, which is the tip the file was \
         written at"
    );
    assert_eq!(
        probation.reached, ANCHOR,
        "nothing above it was read back, so nothing above it is checked"
    );
    assert_eq!(probation.checked(), 0);
    assert_eq!(probation.owed(), BURIAL);
}

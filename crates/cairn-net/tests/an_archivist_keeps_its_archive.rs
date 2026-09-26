//! An archivist is an archivist after a restart and after it arrives.
//!
//! The archive, every leaf of the cold set, is held in memory and built by
//! reading blocks as they are applied. A ledger carries the cold set as sixty
//! four roots, so a node that starts from a ledger, or is handed one when it
//! arrives, holds the roots and nothing under them. An archivist did both: it
//! started from its own `ledger.dat` whenever it had written one, and it took
//! a handover like any node joining a long chain. Either way it stopped being
//! an archivist, told every peer so on the handshake, and its operator was
//! still told at every start that it kept the whole cold set.
//!
//! What it does now: a start over a log that holds every block from the first
//! reads them all and rebuilds the archive, whatever ledger lies beside them;
//! a start over a log that begins higher up refuses, with nothing changed,
//! because the archive cannot be built from blocks that are not there; and an
//! archivist arriving on a long chain reads it rather than being handed it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::sync::JOIN_RATHER_THAN_READ;
use cairn_net::{Joined, Node};
use cairn_store::{BlockLog, BLOCK_LOG, HANDED_LEDGER};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

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
        std::env::temp_dir().join(format!("cairn-archivist-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn chain(rules: &ConsensusParams, count: usize) -> Vec<Block> {
    let miner = SecretKey::from_bytes(&[5; 32]);
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(rules.initial_reward, miner.public_key())],
            );
            let block =
                assemble_block(&state, coinbase, Vec::<Transfer>::new(), rules, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
            connect_block(&mut state, &block, rules, NOW).unwrap();
            block
        })
        .collect()
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(180) {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("waited three minutes for {what}");
}

/// An archivist started over its own ledger, with every block from the first
/// still on its disk, reads them all again and is still an archivist.
///
/// Nothing asked this, so the start adopted the ledger, whose cold set is
/// sixty four roots, and the node came back holding no leaf at all while
/// `cairnd` printed "keeping the whole cold set".
#[test]
fn an_archivist_started_over_its_own_ledger_rebuilds_its_archive() {
    let directory = scratch("own-ledger");
    let blocks = chain(&params(), 40);
    let (node, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    for block in &blocks {
        node.submit_block(block.clone()).unwrap();
    }
    let cold = node.cold_len();
    assert!(cold > 0, "premise: notes have fallen into the cold set");
    assert!(
        node.write_ledger(),
        "premise: the node wrote its ledger down"
    );
    node.shutdown();
    drop(node);
    assert!(directory.join(HANDED_LEDGER).exists());

    let (node, restored) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    let archiving = node.is_archiving();
    let height = node.height();
    let cold_after = node.cold_len();
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        archiving,
        "an archivist started over its own ledger is no longer archiving"
    );
    assert_eq!(
        (restored.blocks, height, cold_after),
        (blocks.len(), Some(39), cold),
        "the archive was not rebuilt by reading every block from the first"
    );
}

/// An archivist whose blocks begin above the first one refuses to start and
/// changes nothing, rather than starting as something else.
///
/// Nothing asked this, so a node that had trimmed its blocks came back from
/// `--archive` with the roots of the cold set and none of its leaves, and
/// told its operator and every peer the opposite.
#[test]
fn an_archivist_whose_blocks_do_not_begin_at_the_first_refuses_to_start() {
    let directory = scratch("trimmed");
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    for block in &chain(&params(), 40) {
        node.submit_block(block.clone()).unwrap();
    }
    node.keep_blocks(1);
    wait_for("the node to trim its blocks", || {
        node.blocks_from().unwrap_or(0) > 0
    });
    let from = node.blocks_from().unwrap();
    node.shutdown();
    drop(node);
    let before = std::fs::read(directory.join(BLOCK_LOG)).unwrap();

    let refused = Node::open_archiving(params(), loopback(), &directory);
    let said = match refused {
        Err(error) => error.to_string(),
        Ok((node, _)) => {
            let archiving = node.is_archiving();
            node.shutdown();
            drop(node);
            panic!("an archivist whose blocks begin at {from} started, archiving: {archiving}");
        }
    };
    let after = std::fs::read(directory.join(BLOCK_LOG)).unwrap();
    let (log, _) = BlockLog::open(&directory).unwrap();
    let first = log.first_height();
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(after == before, "the refused start changed the block log");
    assert_eq!(first, from, "and the log no longer begins where it did");
    assert!(
        said.contains(&format!("height {from}")),
        "the refusal does not say where the blocks begin: {said}"
    );
}

/// An archivist arriving on a chain long enough to be handed a ledger reads
/// it instead, and is an archivist when it gets there.
///
/// Nothing asked this, so an archivist with an empty directory joined a long
/// chain the way any node does, adopted a ledger holding the roots of the
/// cold set, and never archived anything from that moment on.
#[test]
fn an_archivist_arriving_on_a_long_chain_reads_it_rather_than_being_handed_it() {
    let rules = ConsensusParams::testnet().with_burial(8);
    let blocks = chain(&rules, usize::try_from(JOIN_RATHER_THAN_READ).unwrap() + 40);
    let top = u64::try_from(blocks.len()).unwrap() - 1;

    let keeping = scratch("keeper");
    let (keeper, _) = Node::open_archiving(rules, loopback(), &keeping).unwrap();
    keeper.keep_blocks(u64::MAX);
    for block in &blocks {
        keeper.submit_block(block.clone()).unwrap();
    }

    let arriving = scratch("arriving");
    let (newcomer, _) = Node::open_archiving(rules, loopback(), &arriving).unwrap();
    newcomer.connect(keeper.address()).unwrap();
    wait_for("the archivist to reach the tip", || {
        newcomer.height() == Some(top) || newcomer.joining() == Joined::Done
    });
    let joined = newcomer.joining();
    let archiving = newcomer.is_archiving();
    let cold = (newcomer.cold_len(), keeper.cold_len());

    newcomer.shutdown();
    keeper.shutdown();
    drop(newcomer);
    drop(keeper);
    let _ = std::fs::remove_dir_all(&keeping);
    let _ = std::fs::remove_dir_all(&arriving);

    assert_ne!(
        joined,
        Joined::Done,
        "an archivist arriving on a long chain was handed a ledger"
    );
    assert!(archiving, "and it is not archiving when it gets there");
    assert_eq!(cold.0, cold.1, "and its cold set is not the chain's");
}

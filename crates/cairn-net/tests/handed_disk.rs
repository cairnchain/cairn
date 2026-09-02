//! A node that joined a chain writes down the chain, and says nothing about
//! its disk.
//!
//! The walk that fills the header log used to start where the branch begins,
//! and a branch remembers identifiers by milestones far below the blocks
//! themselves. So it asked for a header the chain had let go of on purpose and
//! was refused at the first step, every time, for ever.
//!
//! What that cost was not the warning. It was the log: a node that joined a
//! chain never wrote a single header, so it could show a newcomer none of the
//! chain while its own introduction said it could. The warning was how it
//! showed, and it showed as the one thing it was not, a disk that had stopped
//! taking writes.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::Handover;
use cairn_ledger::note::Note;
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::node::Node;
use cairn_primitives::codec::Encode;

const NOW: u64 = 2_000_000_000;
const BURIAL: u64 = 8;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(BURIAL)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-probe-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("waited for {what} and it never happened");
}

struct Chain {
    state: LedgerState,
    past: Vec<LedgerState>,
    blocks: Vec<Block>,
    headers: Vec<BlockHeader>,
    history: Archive,
    clock: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
            headers: Vec::new(),
            history: Archive::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&self.state, coinbase, Vec::new(), &params, self.clock, 0).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        self.past.push(self.state.clone());
        self.history.add(header_leaf(&block.header.id())).unwrap();
        self.headers.push(block.header);
        self.blocks.push(block);
    }

    fn run(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner);
        }
    }

    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let anchor = self.history.prove_in(anchor_height, tip.height).unwrap();
        let from = anchor_height.saturating_sub(90) as usize;
        let recent: Vec<BlockHeader> = self.headers[from..=anchor_height as usize].to_vec();
        state
            .handover(
                at,
                tip,
                self.state.headers_before_tip(),
                anchor,
                self.headers[(anchor_height as usize + 1)..].to_vec(),
                recent,
            )
            .unwrap()
    }
}

/// A node that joined a chain, on a disk with nothing whatever wrong with it,
/// validates its way off probation, writes the chain down, and complains about
/// nothing.
#[test]
fn a_node_that_joined_a_chain_writes_it_down_and_says_nothing_about_its_disk() {
    let supplier = wallet(9);
    let mut source = Chain::new();
    source.run(&supplier, 120);
    let handover = source.handover();
    // A little past the tip the handover names, and past WARM_BODIES = 64.
    let mut extra = source;
    extra.run(&supplier, 200);
    let tail: Vec<Block> = extra.blocks[120..].to_vec();
    let source = extra;

    let directory = scratch("handed-disk");
    std::fs::write(
        directory.join(cairn_store::HANDED_LEDGER),
        handover.encode(),
    )
    .unwrap();

    let host_directory = scratch("handed-disk-host");
    let (host, _) = Node::open_archiving(params(), loopback(), &host_directory).unwrap();
    for block in &source.blocks[..120] {
        host.submit_block(block.clone()).unwrap();
    }

    let (node, _restored) = Node::open(params(), loopback(), &directory).unwrap();
    assert!(node.probation().is_some());
    assert_eq!(
        node.unwritten(),
        None,
        "nothing has been written yet, so nothing has been refused yet"
    );

    node.connect(host.address()).unwrap();
    wait_for("the burial to be validated", || node.height() == Some(119));

    let after_catchup = node.unwritten();

    // Now let it run on well past the window the branch keeps, so any
    // self-healing has every chance to happen.
    for block in &tail {
        host.submit_block(block.clone()).unwrap();
    }
    let last = 119 + tail.len() as u64;
    wait_for("the node to follow the whole chain", || {
        node.height() == Some(last)
    });

    let unwritten = node.unwritten();
    let written_through = node.written_through();
    let headers_held = {
        let log = cairn_store::HeaderLog::open(&directory).unwrap();
        (log.first_height(), log.len())
    };
    node.shutdown();
    host.shutdown();
    drop(node);
    drop(host);
    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&host_directory);

    println!("PROBE: after catching up to 119: unwritten = {after_catchup:?}");
    println!(
        "PROBE: at height {last}, header log holds {} records from height {}",
        headers_held.1, headers_held.0
    );
    println!("PROBE: written_through = {written_through:?}");
    println!("PROBE: unwritten = {unwritten:#?}");
    assert_eq!(
        after_catchup, None,
        "it complained before it had even finished catching up"
    );
    assert_eq!(
        unwritten, None,
        "a node that joined a chain and caught up on a healthy disk reports a \
         write it could not make"
    );
    assert_eq!(
        written_through,
        Some(last),
        "and its block log is level with the chain"
    );
    assert_eq!(
        headers_held,
        (0, last + 1),
        "the header log holds the chain, which is the whole of what a node \
         needs to show a newcomer where the work is"
    );
}

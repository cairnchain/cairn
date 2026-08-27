//! Five nodes told about one address each, finding everyone else, and one of
//! them restarting from its own directory.
//!
//! Run with `cargo run --release -p cairn-net --example gossip`.

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const CHAIN_LENGTH: usize = 20;
const NAMES: [&str; 5] = ["seed", "a", "b", "c", "d"];

fn main() {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let root = workspace();

    let mut ledger = LedgerState::new();
    let mut clock = 1_000u64;
    let chain: Vec<Block> = (0..CHAIN_LENGTH)
        .map(|_| forge(&mut ledger, &params, &miner, &mut clock))
        .collect();

    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut nodes: Vec<Node> = NAMES
        .iter()
        .map(|name| {
            Node::open(params, listen, root.join(name))
                .expect("a directory")
                .0
        })
        .collect();

    for block in &chain {
        nodes[0]
            .submit_block(block.clone())
            .expect("the seed accepts its own chain");
    }

    println!("A seed holding a {CHAIN_LENGTH} block chain, and four nodes told one address:");
    println!("the seed's. None of the four knows that the others exist.");
    println!();

    let seed = nodes[0].address();
    for node in nodes.iter().skip(1) {
        node.connect(seed).expect("the seed is listening");
    }

    let started = Instant::now();
    report(&nodes, started);
    settle(&nodes, |node| node.peer_count() >= 4);
    report(&nodes, started);

    println!();
    println!("Each pair of numbers is connections held over addresses known. Every");
    println!("node found the other four by asking the only one it had been given.");
    println!();

    let stopped = nodes[4].address();
    nodes[4].shutdown();
    drop(nodes.remove(4));
    println!("Node d is stopped, and started again from its own directory.");

    let (revived, restored) = Node::open(params, stopped, root.join("d")).expect("its directory");
    println!();
    println!("  blocks read back from disk   {}", restored.blocks);
    println!("  addresses read back          {}", restored.addresses);
    println!(
        "  height straight away         {}",
        revived.height().unwrap_or_default()
    );
    println!();
    println!("It was told nothing this time. Reconnecting from its own address book:");

    nodes.push(revived);
    let started = Instant::now();
    report(&nodes, started);
    settle(&nodes, |node| node.peer_count() >= 4);
    report(&nodes, started);

    let heights: Vec<_> = nodes.iter().map(Node::height).collect();
    println!();
    println!(
        "  same height on all five      {}",
        heights.iter().all(|h| *h == heights[0])
    );

    for node in &nodes {
        node.shutdown();
    }
    let _ = std::fs::remove_dir_all(&root);
}

fn workspace() -> PathBuf {
    let root = std::env::temp_dir().join(format!("cairn-gossip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    root
}

fn forge(
    state: &mut LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    clock: &mut u64,
) -> Block {
    let height = state.next_height().expect("the chain has room");
    *clock += 600;
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block = assemble_block(state, coinbase, Vec::<Transfer>::new(), params, *clock, 0)
        .expect("the block is valid");
    let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
    connect_block(state, &block, params, NOW).expect("it connects");
    block
}

fn settle(nodes: &[Node], ready: impl Fn(&Node) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if nodes.iter().all(&ready) {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    println!("  (they did not settle in time)");
}

fn report(nodes: &[Node], since: Instant) {
    let mut line = format!("  after {:>5.2}s  ", since.elapsed().as_secs_f64());
    for (name, node) in NAMES.iter().zip(nodes) {
        let _ = write!(
            line,
            "{name} {}/{:<4}",
            node.peer_count(),
            node.known_addresses().len()
        );
    }
    println!("{line}");
}

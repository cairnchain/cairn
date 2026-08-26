//! Five nodes on this machine, wired in a line, finding each other's blocks.
//!
//! Run with `cargo run --release -p cairn-net --example network`.

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const CHAIN_LENGTH: usize = 25;
const NAMES: [&str; 5] = ["seed", "a", "b", "c", "d"];

fn main() {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);

    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let chain: Vec<Block> = (0..CHAIN_LENGTH)
        .map(|_| forge(&mut state, &params, &miner, &mut clock))
        .collect();

    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let nodes: Vec<Node> = (0..NAMES.len())
        .map(|_| Node::bind(params, address).expect("a free port"))
        .collect();

    println!("Five nodes, each in its own listener, on this machine.");
    for (name, node) in NAMES.iter().zip(&nodes) {
        println!("  {name:<5} {}", node.address());
    }

    for block in &chain {
        nodes[0]
            .submit_block(block.clone())
            .expect("the seed accepts its own chain");
    }
    println!();
    println!(
        "The first holds a {CHAIN_LENGTH} block chain. The other four have never seen a block."
    );
    println!("Wiring them in a line, one connection each: seed to a to b to c to d.");
    println!();

    let started = Instant::now();
    for index in 1..nodes.len() {
        nodes[index]
            .connect(nodes[index - 1].address())
            .expect("the peer is listening");
    }

    report(&nodes, started);
    await_agreement(&nodes, CHAIN_LENGTH as u64 - 1);
    report(&nodes, started);

    println!();
    println!("Every node holds the whole ledger, and none of them spoke to more than");
    println!("two others. Now a block is mined at the far end of the line.");
    println!();

    let fresh = nodes[4].with_chain(|store| {
        let mut ledger = store.state().clone();
        forge(&mut ledger, &params, &miner, &mut clock)
    });
    let started = Instant::now();
    nodes[4]
        .submit_block(fresh.clone())
        .expect("the miner accepts its own block");

    report(&nodes, started);
    await_agreement(&nodes, CHAIN_LENGTH as u64);
    report(&nodes, started);

    let roots: Vec<_> = nodes
        .iter()
        .map(|node| node.with_chain(|store| store.state().state_root()))
        .collect();
    let tips: Vec<_> = nodes
        .iter()
        .map(|node| node.with_chain(ChainStore::tip))
        .collect();

    println!();
    println!("  it travelled back up the line, hop by hop, with nobody in charge");
    println!(
        "  same tip on all five          {}",
        tips.iter().all(|tip| *tip == tips[0])
    );
    println!(
        "  same ledger on all five       {}",
        roots.iter().all(|root| *root == roots[0])
    );
    println!("  tip                           {}", fresh.id());

    for node in &nodes {
        node.shutdown();
    }
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
        vec![Note::new(params.block_reward, miner.public_key())],
        [0; 8],
    );
    let block = assemble_block(state, coinbase, Vec::<Transfer>::new(), params, *clock, 0)
        .expect("the block is valid");
    let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
    connect_block(state, &block, params, NOW).expect("it connects");
    block
}

fn await_agreement(nodes: &[Node], height: u64) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if nodes.iter().all(|node| node.height() == Some(height)) {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    println!("  (they did not settle in time)");
}

fn report(nodes: &[Node], since: Instant) {
    let mut line = format!("  after {:>5.2}s  ", since.elapsed().as_secs_f64());
    for (name, node) in NAMES.iter().zip(nodes) {
        let height = node
            .height()
            .map_or_else(|| "-".to_owned(), |height| height.to_string());
        let _ = write!(line, "{name} {height:<4}");
    }
    println!("{line}");
}

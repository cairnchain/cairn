//! What one changed byte in the block log costs the start after it, as a
//! function of where the byte lands, on the role that keeps every block.
//!
//! `cairn-store`'s opening paragraphs say what its recovery does: "recovery
//! repairs the index in both directions and never shortens the log, and the
//! only bytes it takes off the end are a record the file stops inside". True
//! of `BlockLog::open`. The start that follows it replays the log through the
//! chain, and `Node::open_with` says what it does with a record the chain
//! refuses: "the log is cut there and the rest is asked for again. It costs a
//! partial resync once, on a node whose log was written before this rule
//! existed or interrupted in the middle of a reorganisation."
//!
//! Two causes are named and priced as partial. A third is a byte that changed
//! in place, which is the damage the store's own `read_at` was hardened
//! against because "1681 of 1984 flips inside the log answered a height with a
//! block nobody mined". On the replay path the same byte is a refusal, and the
//! cut runs from the refused record to the end of the log. For the archivist,
//! "the one role that cannot" ask for a block again in the store's words, a
//! byte in the first record is the whole history.
//!
//! Measured here rather than argued, with the byte in the first record and in
//! the seventh.

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

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::node::Node;
use cairn_store::{BlockLog, HeaderLog, BLOCK_INDEX, BLOCK_LOG};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Where `state_root` sits inside a record: four bytes of length, then
/// version, network, height, previous and transactions root.
const STATE_ROOT_IN_RECORD: u64 = 4 + 2 + 4 + 8 + 32 + 32;

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
        std::env::temp_dir().join(format!("cairn-one-byte-{}-{name}", std::process::id()));
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

/// One bit of the state root of record `record`, flipped in place.
fn flip_one_byte_in(directory: &Path, record: usize) {
    let index = std::fs::read(directory.join(BLOCK_INDEX)).unwrap();
    let start = if record == 0 {
        0
    } else {
        u64::from_le_bytes(index[(record - 1) * 8..record * 8].try_into().unwrap())
    };
    let at = start + STATE_ROOT_IN_RECORD;
    let path = directory.join(BLOCK_LOG);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[at as usize] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
}

/// What is on the disk once the node has closed its files.
fn on_disk(directory: &Path) -> (usize, u64) {
    let (log, _) = BlockLog::open(directory).unwrap();
    let headers = HeaderLog::open(directory).unwrap();
    (log.len(), headers.len())
}

/// Builds an archivist holding twelve blocks and twelve headers, flips one
/// bit of one record, starts it again, and reports what the start left.
fn cost_of_a_byte_in(record: usize) -> (usize, usize, (usize, u64)) {
    let directory = scratch(&format!("record-{record}"));
    let blocks = chain(12);
    let (node, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    for block in &blocks {
        node.submit_block(block.clone()).unwrap();
    }
    node.shutdown();
    drop(node);
    assert_eq!(
        on_disk(&directory),
        (12, 12),
        "twelve of each before the byte"
    );

    flip_one_byte_in(&directory, record);

    let (node, restored) = Node::open_archiving(params(), loopback(), &directory)
        .unwrap_or_else(|error| panic!("the archivist would not start: {error}"));
    node.shutdown();
    drop(node);
    let left = on_disk(&directory);
    let _ = std::fs::remove_dir_all(&directory);
    (restored.blocks, restored.refused, left)
}

#[test]
fn one_byte_in_the_first_record_costs_an_archivist_every_block_it_kept() {
    let seventh = cost_of_a_byte_in(6);
    let first = cost_of_a_byte_in(0);
    println!("PROBE: (replayed, refused, (blocks left on disk, headers left on disk))");
    println!("PROBE: one bit in record 6 of 12: {seventh:?}");
    println!("PROBE: one bit in record 0 of 12: {first:?}");

    assert_eq!(
        (seventh.0, seventh.1, seventh.2 .0),
        (6, 6, 6),
        "a byte in the seventh record costs the six records after it"
    );
    assert_eq!(
        (first.0, first.1, first.2 .0),
        (0, 12, 0),
        "a byte in the first record costs every record: the archivist's whole \
         block history is cut and asked for again"
    );
    assert_eq!(
        (seventh.2 .1, first.2 .1),
        (12, 12),
        "the headers survive either way, which is what names the block that \
         could have been fetched on its own"
    );
}

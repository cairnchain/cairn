//! TEMPORARY AUDIT PROBE - delete after running.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{ChainError, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

struct Chain {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Chain {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize) -> Vec<Block> {
        (0..count)
            .map(|_| {
                let height = self.state.next_height().unwrap();
                self.clock += 600;
                let coinbase = CoinbaseTransaction::new(
                    height,
                    vec![Note::new(self.params.initial_reward, miner.public_key())],
                );
                let block = assemble_block(
                    &self.state,
                    coinbase,
                    Vec::new(),
                    &self.params,
                    self.clock,
                    0,
                )
                .unwrap();
                let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
                connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
                block
            })
            .collect()
    }
}

/// A block that EXTENDS THE TIP, costs its maker no work (difficulty one
/// accepts every hash) and is invalid on a verdict the header settles: its
/// stated total work is not the work behind it.
fn free_bad_tip_block(
    height: u64,
    previous: Hash32,
    bytes: usize,
    nonce: u64,
    owner: &SecretKey,
) -> Block {
    let value = Amount::from_pebbles(1).unwrap();
    let per = Note::new(value, owner.public_key()).encode().len();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&nonce.to_le_bytes());
    let transfer = Transfer::new(
        vec![Input::hot(NoteId::new(Hash32::from_bytes(seed), 0))],
        (0..bytes / per.max(1))
            .map(|_| Note::new(value, owner.public_key()))
            .collect(),
    );
    Block {
        header: BlockHeader {
            version: BLOCK_VERSION,
            network: NetworkId::TESTNET,
            height,
            previous,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: NOW,
            difficulty: 1,
            // Wrong on purpose, and wrong in a way `settles_the_header` calls
            // a verdict about the header: `BlockError::WrongTotalWork`.
            total_work: u128::from(nonce) + 1_000_000,
            nonce,
        },
        coinbase: CoinbaseTransaction::new(height, Vec::new()),
        transfers: vec![transfer],
    }
}

#[test]
fn a_known_bad_block_resent_is_held_again_and_nothing_sweeps() {
    let rules = params();
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    let chain = shared.mine_empty(&miner, 6);

    let mut store = ChainStore::new(rules);
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.tip().unwrap();
    let tip_height = store.height().unwrap();
    let held_before = store.held_bytes();
    let entries_before = store.len();

    let count = 500u64;
    for nonce in 0..count {
        let block = free_bad_tip_block(tip_height + 1, tip, 4096, nonce, &wallet(9));
        let id = block.id();

        // First delivery: refused, remembered, and not kept.
        let first = store.add_block(block.clone(), NOW);
        assert!(
            matches!(first, Err(ChainError::InvalidBlock { .. })),
            "first delivery gave {first:?}"
        );
        assert!(
            !store.contains(&id),
            "a block that failed to apply was kept in memory"
        );

        // Second delivery: the set of bad blocks answers, and the body stays.
        let again = store.add_block(block, NOW);
        assert!(
            matches!(again, Err(ChainError::KnownBad { .. })),
            "second delivery gave {again:?}"
        );
        assert!(
            store.contains(&id),
            "nonce {nonce}: the re-sent bad block was not held"
        );
        assert!(
            store.block(&id).is_some(),
            "nonce {nonce}: its body was not held"
        );
    }

    let held_after = store.held_bytes();
    let entries_after = store.len();
    println!(
        "tip {tip_height}; before: {entries_before} entries / {held_before} bytes; \
         after {count} free bad blocks delivered twice each: {entries_after} entries / \
         {held_after} bytes. Grown by {} entries and {} bytes, at no proof of work.",
        entries_after - entries_before,
        held_after - held_before
    );

    assert_eq!(
        entries_after - entries_before,
        count as usize,
        "one entry per free bad block"
    );

    // And one ordinary block on the branch is what would sweep it, which is the
    // point: nothing on the refusal path does.
    println!("branch still at {:?}", store.height());
}

/// Same shape, with the sizes a network actually allows, to say what the line
/// costs per block.
#[test]
fn how_much_one_free_bad_block_costs_the_node() {
    let mut rules = params();
    rules.max_block_bytes = 128 * 1024;
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    let chain = shared.mine_empty(&miner, 6);

    let mut store = ChainStore::new(rules);
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.tip().unwrap();
    let tip_height = store.height().unwrap();
    let before = store.held_bytes();

    let count = 200u64;
    for nonce in 0..count {
        let block = free_bad_tip_block(tip_height + 1, tip, 120 * 1024, nonce, &wallet(9));
        let _ = store.add_block(block.clone(), NOW);
        let _ = store.add_block(block, NOW);
    }
    let after = store.held_bytes();
    println!(
        "{count} free bad blocks of ~120 kB: held bytes {before} -> {after}, \
         {} per block, ceiling {}",
        (after - before) / count as usize,
        ChainStore::held_bytes_ceiling(&rules)
    );
    assert!(
        after > before,
        "nothing was held, so the probe is wrong somewhere"
    );
}

/// Past the published ceiling, with the branch standing still, and then one
/// ordinary block to show the sweep exists and simply is not reached.
#[test]
fn past_the_ceiling_and_past_max_invalid() {
    let rules = params();
    let ceiling = ChainStore::held_bytes_ceiling(&rules);
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    let chain = shared.mine_empty(&miner, 8);

    let mut store = ChainStore::new(rules);
    for block in &chain[..7] {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.tip().unwrap();
    let tip_height = store.height().unwrap();

    // MAX_INVALID is 8_192, so this runs well past it.
    let count = 12_000u64;
    let mut marks = Vec::new();
    for nonce in 0..count {
        let block = free_bad_tip_block(tip_height + 1, tip, 16 * 1024, nonce, &wallet(9));
        let _ = store.add_block(block.clone(), NOW);
        let _ = store.add_block(block, NOW);
        if nonce % 3_000 == 2_999 {
            marks.push((nonce + 1, store.len(), store.held_bytes()));
        }
    }
    for (sent, entries, held) in &marks {
        println!("after {sent} free bad blocks: {entries} entries, {held} bytes held");
    }
    println!("ceiling is {ceiling} bytes");

    let over = store.held_bytes();
    assert!(
        over > ceiling,
        "held {over} against ceiling {ceiling}: probe did not reach the ceiling"
    );

    // One ordinary block on the branch: the sweep that was never reached.
    store.add_block(chain[7].clone(), NOW).unwrap();
    println!(
        "one ordinary block later: {} entries, {} bytes held",
        store.len(),
        store.held_bytes()
    );
}

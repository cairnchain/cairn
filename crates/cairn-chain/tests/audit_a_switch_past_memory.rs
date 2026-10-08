//! A heavier branch put together while what is held beside the branch is
//! full of heavier junk.
//!
//! A switch is tried only once every block of the rival is held off the
//! branch, and blocks beside the branch are let go of lightest first once
//! there are too many. A sibling of the followed tip carries the tip's whole
//! work, which is more than every block of a deep rival but its last, so a
//! store kept full of those lets go of each block of the rival as it lands:
//! its top is the lightest thing held, and the block after it is refused for a
//! parent the store has just dropped. With memory as the side store's only
//! bound, thirty two megabytes of such siblings, one block of the tip's work
//! for every hundred and twenty eight kilobytes, kept a node on the lighter
//! branch for as long as somebody paid for them (01-F2 of the audit of 8
//! October 2026).
//!
//! On a node with a disk the memory bound stays and the bodies past it go to
//! disk, so the junk has to fill the side store's whole budget to do the
//! same, which is about a hundred and ninety three megabytes on a public
//! network: more blocks of the tip's work than the deepest switch the rules
//! allow undoes. Here the junk fills memory and goes on arriving between the
//! rival's blocks, and the rival is put together and followed once it
//! outweighs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cairn_chain::{Accepted, ChainError, ChainStore, SideBodies, HELD_OVERHEAD, MAX_SIDE_BYTES};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::next_difficulty;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, mine_header, ConsensusParams,
};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

/// When the network opens, and when its first block is dated.
const OPENS: u64 = 1_000_000;

/// The node's clock, past every block here.
const NOW: u64 = 4_000_000_000;

const ATTEMPTS: u64 = 1 << 28;

/// Blocks of the branch followed above the first. The rival is one longer.
const FOLLOWED: u64 = 10;

/// Junk handed over before the rival's first block: past `MAX_SIDE_BYTES` on
/// its own.
const AHEAD: usize = 280;

fn rules() -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.opens_at = OPENS;
    params.genesis_difficulty = 64;
    params
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Somewhere to spill, standing in memory for the disk a node has.
#[derive(Clone, Debug, Default)]
struct Disk(Arc<Mutex<HashMap<Hash32, Block>>>);

impl SideBodies for Disk {
    fn put(&mut self, id: &Hash32, block: &Block) -> bool {
        self.0.lock().unwrap().insert(*id, block.clone());
        true
    }

    fn get(&self, id: &Hash32) -> Option<Block> {
        self.0.lock().unwrap().get(id).cloned()
    }

    fn remove(&mut self, id: &Hash32) {
        self.0.lock().unwrap().remove(id);
    }

    fn clear(&mut self) {
        self.0.lock().unwrap().clear();
    }
}

/// An honest block on `state`, dated `timestamp`, and the ledger after it.
fn mint(
    params: &ConsensusParams,
    state: &LedgerState,
    timestamp: u64,
    salt: u8,
) -> (Block, LedgerState) {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::with_extra(
        height,
        vec![Note::new(params.reward_at(height), wallet(1).public_key())],
        vec![salt],
    );
    let block = assemble_block(state, coinbase, Vec::new(), params, timestamp, 0).unwrap();
    let block = mine_block(block, ATTEMPTS).expect("a nonce at this difficulty");
    let mut after = state.clone();
    connect_block(&mut after, &block, params, NOW).unwrap();
    (block, after)
}

/// A block on `parent` carrying exactly what that parent demands, as large
/// as the rules allow, with a root that matches its body and nothing else
/// right about it: junk at the dearest price the door asks, a place beside
/// the branch for every block of its parent's work.
fn junk(params: &ConsensusParams, parent: &BlockHeader, nonce: u64) -> Block {
    let height = parent.height + 1;
    let value = Amount::from_pebbles(1).unwrap();
    let owner = wallet(9).public_key();
    let per = Note::new(value, owner).encode().len();
    let room = ChainStore::room_for_transfers(params.max_block_bytes);
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&nonce.to_le_bytes());
    let difficulty = next_difficulty(&parent.summary(), params.origin(), params.target_block_time);
    let mut block = Block {
        header: BlockHeader {
            version: BLOCK_VERSION,
            network: params.network,
            height,
            previous: parent.id(),
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: parent.timestamp + params.target_block_time,
            difficulty,
            total_work: parent.total_work + u128::from(difficulty),
            nonce: 0,
        },
        coinbase: CoinbaseTransaction::with_extra(height, Vec::new(), nonce.to_le_bytes().to_vec()),
        transfers: vec![Transfer::new(
            vec![Input::hot(NoteId::new(Hash32::from_bytes(seed), 0))],
            (0..room / per).map(|_| Note::new(value, owner)).collect(),
        )],
    };
    block.header.transactions_root = block.transactions_root();
    block.header = mine_header(block.header, ATTEMPTS).expect("a nonce at the demanded difficulty");
    assert!(block.encode().len() <= params.max_block_bytes);
    block
}

/// What a store answered for each block of the rival, and where it ended.
struct Delivered {
    answers: Vec<Result<Accepted, ChainError>>,
    tip: Option<Hash32>,
    spilled: usize,
    in_memory_beside: usize,
}

/// The branch followed, the rival, and the junk, handed to `store` in the
/// order this file is about: junk past memory first, then the rival's blocks
/// with a sibling of the tip after each.
fn deliver(
    store: &mut ChainStore,
    followed: &[Block],
    rival: &[Block],
    junk_blocks: &[Block],
) -> Delivered {
    for block in followed {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let mut junk_blocks = junk_blocks.iter();
    for block in junk_blocks.by_ref().take(AHEAD) {
        let _ = store.add_block(block.clone(), NOW);
    }
    let mut answers = Vec::new();
    let mut in_memory_beside = 0;
    let branch: usize = followed
        .iter()
        .map(|block| block.encode().len() + HELD_OVERHEAD)
        .sum();
    for block in rival {
        answers.push(store.add_block(block.clone(), NOW));
        if let Some(more) = junk_blocks.next() {
            let _ = store.add_block(more.clone(), NOW);
        }
        if store.tip() == followed.last().map(Block::id) {
            in_memory_beside = in_memory_beside.max(store.held_bytes() - branch);
        }
    }
    Delivered {
        answers,
        tip: store.tip(),
        spilled: store.spilled_bytes(),
        in_memory_beside,
    }
}

#[test]
fn junk_beside_the_tip_past_memory_does_not_keep_a_heavier_branch_from_being_followed() {
    let params = rules();
    let mut state = LedgerState::new();
    let mut followed = Vec::new();
    for height in 0..=FOLLOWED {
        let (block, after) = mint(&params, &state, OPENS + 60 * height, height as u8);
        followed.push(block);
        state = after;
    }
    let first = followed[0].clone();
    let tip = followed.last().unwrap().clone();
    let under_tip = followed[followed.len() - 2].header;

    // The rival forks at the first block and is one block longer, every block
    // of it on the same schedule as the branch followed, so it ties the tip
    // at the tip's height and outweighs it with its last block.
    let mut rival = Vec::new();
    let mut ledger = LedgerState::new();
    connect_block(&mut ledger, &first, &params, NOW).unwrap();
    for height in 1..=FOLLOWED + 1 {
        let (block, after) = mint(&params, &ledger, OPENS + 60 * height, 100 + height as u8);
        rival.push(block);
        ledger = after;
    }
    let rival_tip = rival.last().unwrap().clone();
    assert!(rival_tip.header.total_work > tip.header.total_work);
    assert!(
        rival[..rival.len() - 1]
            .iter()
            .all(|block| block.header.total_work <= tip.header.total_work),
        "every block of the rival but its last has to weigh no more than the tip, or a \
         switch is tried before the rival is whole"
    );

    // Siblings of the tip, each carrying the tip's whole work.
    let junk_blocks: Vec<Block> = (0..AHEAD as u64 + rival.len() as u64)
        .map(|nonce| junk(&params, &under_tip, nonce))
        .collect();
    assert_eq!(junk_blocks[0].header.total_work, tip.header.total_work);
    let ahead: usize = junk_blocks[..AHEAD]
        .iter()
        .map(|block| block.encode().len() + HELD_OVERHEAD)
        .sum();
    assert!(
        ahead > MAX_SIDE_BYTES,
        "the junk ahead of the rival has to fill memory on its own: {ahead} against \
         {MAX_SIDE_BYTES}"
    );

    // With somewhere to spill: the rival is held whole, and followed once it
    // outweighs.
    let disk = Disk::default();
    let mut with_a_disk = ChainStore::new(params);
    with_a_disk.spills_side_bodies_to(Box::new(disk.clone()));
    let spilling = deliver(&mut with_a_disk, &followed, &rival, &junk_blocks);
    println!(
        "with a disk: {} bytes spilled, at most {} in memory beside the branch, answers {:?}",
        spilling.spilled,
        spilling.in_memory_beside,
        spilling
            .answers
            .iter()
            .map(|answer| answer.as_ref().map(|_| ()).map_err(ToString::to_string))
            .collect::<Vec<_>>()
    );
    for (n, answer) in spilling.answers[..rival.len() - 1].iter().enumerate() {
        assert_eq!(
            answer,
            &Ok(Accepted::SideBranch),
            "rival block {n} was not held, with junk past memory beside the tip"
        );
    }
    assert!(
        matches!(
            spilling.answers.last(),
            Some(Ok(Accepted::Reorganised { added, .. })) if added.len() == rival.len()
        ),
        "the rival outweighed the tip and was not switched to: {:?}",
        spilling.answers.last()
    );
    assert_eq!(spilling.tip, Some(rival_tip.id()));
    assert_eq!(with_a_disk.total_work(), rival_tip.header.total_work);
    assert!(
        spilling.in_memory_beside <= MAX_SIDE_BYTES,
        "memory held {} bytes beside the branch, past its bound of {MAX_SIDE_BYTES}",
        spilling.in_memory_beside
    );
    assert!(
        spilling.spilled > 0,
        "nothing went to disk, so this did not reach the bound it is about"
    );

    // Without: the same delivery leaves the node where it was, which is the
    // switch memory alone cannot make. Each sibling past the bound drops the
    // rival from its top down, every block of it being lighter, and the next
    // block of the rival is refused for a parent the store has just dropped.
    let mut in_memory_only = ChainStore::new(params);
    let alone = deliver(&mut in_memory_only, &followed, &rival, &junk_blocks);
    assert_eq!(
        alone.tip,
        Some(tip.id()),
        "with memory as the side store's only bound the junk no longer keeps the rival \
         out, so this test no longer measures what the disk is for"
    );
    assert!(
        alone
            .answers
            .iter()
            .any(|answer| matches!(answer, Err(ChainError::UnknownParent(_)))),
        "{:?}",
        alone.answers
    );
}

/// A block the sweep lets go of as it lands is not answered as held.
///
/// `add_block` held the block, ran the sweep, and answered `SideBranch`
/// whatever the sweep had done, and the answer says the block was recorded.
/// A branch handed over in order past the side store's bound lost its newest
/// block that way at every delivery, and from outside the store nothing said
/// so: the network layer wrote down who had handed in a body nobody held, and
/// asked for the same blocks again (01-F4).
///
/// So the store is filled, with nowhere to spill, to within one large block
/// of its bound by siblings of the tip, which outweigh everything else beside
/// the branch, and offered a large block lighter than all of them.
#[test]
fn a_block_the_sweep_lets_go_of_as_it_lands_is_not_answered_as_held() {
    let params = rules();
    let mut state = LedgerState::new();
    let mut followed = Vec::new();
    for height in 0..=FOLLOWED {
        let (block, after) = mint(&params, &state, OPENS + 60 * height, height as u8);
        followed.push(block);
        state = after;
    }
    let mut store = ChainStore::new(params);
    for block in &followed {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let branch: usize = followed
        .iter()
        .map(|block| block.encode().len() + HELD_OVERHEAD)
        .sum();
    let under_tip = followed[followed.len() - 2].header;
    let mut nonce = 0;
    loop {
        let next = junk(&params, &under_tip, nonce);
        let weighs = next.encode().len() + HELD_OVERHEAD;
        if store.held_bytes() - branch + weighs > MAX_SIDE_BYTES {
            break;
        }
        assert_eq!(store.add_block(next, NOW), Ok(Accepted::SideBranch));
        nonce += 1;
    }

    // On the first block, so lighter than every sibling of the tip, and as
    // large as theirs, so it carries the store past its bound.
    let light = junk(&params, &followed[0].header, u64::MAX);
    let id = light.id();
    assert!(light.header.total_work < followed.last().unwrap().header.total_work);
    let answer = store.add_block(light, NOW);
    assert_eq!(
        answer,
        Err(ChainError::NoRoom { id }),
        "a block let go of by the sweep it set off was answered as held"
    );
    assert!(!store.contains(&id), "and it is not held");
    assert_eq!(store.tip(), followed.last().map(Block::id));
    assert!(store.held_bytes() - branch <= MAX_SIDE_BYTES);
}

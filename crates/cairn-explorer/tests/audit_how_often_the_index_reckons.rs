//! How often the walk pays for the whole index instead of for one block.
//!
//! `BATCH` bounds a turn at sixty four heights, and its own note says what
//! that buys: "a visitor waits for a turn rather than for the chain." True of
//! the blocks. One thing in a turn is not a block: `take_stock` iterates every
//! owner the index has ever seen and keeps the fifty heaviest, inside the
//! index lock, and it ran on every turn that reached the tip, which on a
//! running site is every block.
//!
//! Timed on a rising index, that read 2.4 ms at 24 576 owners, 8.3 at 98 304,
//! 32.8 at 393 216 and 138.8 at 1 572 864: sixty four times the owners for
//! fifty eight times the turn, on the same block. Counted here instead,
//! because what decides the cost is how often it runs and that is arithmetic;
//! the milliseconds are a fact about a machine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    dead_code
)]

#[path = "../src/index.rs"]
mod index;

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

use index::{Head, Held, Index, Reading};

const NOW: u64 = 2_000_000_000;

/// The block a run holds at `height`, the way a node answers for one.
fn at(blocks: &[Block], height: u64) -> Held {
    match blocks.get(usize::try_from(height).unwrap_or(usize::MAX)) {
        Some(block) => Held::Block(Box::new(block.clone())),
        None => Held::Waiting,
    }
}

/// And the identifier it carries there, which the walk asks for again once
/// its turn is over.
fn id_at(blocks: &[Block], height: u64) -> Option<cairn_primitives::Hash32> {
    blocks
        .get(usize::try_from(height).unwrap_or(usize::MAX))
        .map(Block::id)
}
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// A chain of `count` blocks, each paying a fresh address, so every block
/// gives the index one more owner to walk over.
fn chain(count: u64) -> Vec<Block> {
    let rules = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..count)
        .map(|at| {
            let miner = SecretKey::from_bytes(&[u8::try_from(at % 251).unwrap_or(0) + 1; 32]);
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(rules.initial_reward, miner.public_key())],
            );
            let block =
                assemble_block(&state, coinbase, Vec::<Transfer>::new(), &rules, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &rules, NOW).unwrap();
            block
        })
        .collect()
}

/// **A block does not buy a pass over every owner.**
///
/// The blocks arrive one at a time, the way they do on a running site: one
/// turn each, each reaching the tip it was given. What is counted is how many
/// of those turns worked the distribution out, which is the only number that
/// decides what this costs.
#[test]
fn the_distribution_is_reckoned_on_a_block_in_sixteen_and_not_on_every_one() {
    const BLOCKS: u64 = 64;

    let blocks = chain(BLOCKS);
    let mut walk = Index::new();
    let mut reckoned = 0usize;
    let mut last = None;

    for (arrived, _) in blocks.iter().enumerate() {
        let tip = u64::try_from(arrived).unwrap_or(u64::MAX);
        let head = Head {
            tip,
            at_last_read: walk.covers().and_then(|(_, through)| {
                blocks
                    .get(usize::try_from(through).unwrap_or(usize::MAX))
                    .map(Block::id)
            }),
        };
        while walk.refresh(
            &head,
            |height| at(&blocks, height),
            |height| id_at(&blocks, height),
        ) == Reading::More
        {}
        if walk.stock_at() != last {
            reckoned += 1;
            last = walk.stock_at();
        }
    }

    assert_eq!(walk.covers(), Some((0, BLOCKS - 1)), "the walk kept up");
    println!("{BLOCKS} blocks, the distribution worked out {reckoned} times");
    assert!(
        reckoned <= usize::try_from(BLOCKS / 16 + 1).unwrap_or(usize::MAX),
        "{BLOCKS} blocks made the walk pass over every owner {reckoned} times, which \
         is the one piece of work in a turn whose cost is the whole index"
    );
    // And it is worked out at all, or the count above is a count of a thing
    // that never happens.
    assert!(reckoned > 0, "the distribution was never worked out");
    assert!(
        walk.holders() > 0 && !walk.richest().is_empty(),
        "the table it works out is empty, so nothing here measured it"
    );
}

/// **And what it answers with says when it was worked out.**
///
/// A table of the largest holders a few blocks old is worth having. What it
/// must not do is pass for current, which is the same rule the coverage note
/// beside it keeps about how much of the chain was read.
#[test]
fn the_distribution_says_the_height_it_was_worked_out_at() {
    let blocks = chain(20);
    let mut walk = Index::new();
    let head = Head {
        tip: 19,
        at_last_read: None,
    };
    while walk.refresh(
        &head,
        |height| at(&blocks, height),
        |height| id_at(&blocks, height),
    ) == Reading::More
    {}

    assert_eq!(
        walk.stock_at(),
        Some(19),
        "the answer has to carry the height it was worked out at"
    );
}

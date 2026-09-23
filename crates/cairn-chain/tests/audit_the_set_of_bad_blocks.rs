//! What it costs a stranger to fill the set of blocks this node knows are bad.
//!
//! `ChainStore` remembers the identifier of every block that failed to apply,
//! so the same block is not revalidated each time it arrives. The set is
//! bounded by `MAX_INVALID`: past that many it is emptied rather than grown,
//! because the alternative is a table an anonymous peer gets to fill one entry
//! at a time, for the price of a block header at difficulty one.
//!
//! That bound had no test at all. Deleting the two lines that empty the set
//! left every test in this repository passing, which is the same thing as
//! saying nothing measured it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{ChainError, ChainStore, MAX_INVALID};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, BlockError, ConsensusParams,
};
use cairn_ledger::LedgerState;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

/// A short real chain, mined on a private ledger so a node has something to
/// follow before it is offered anything bad.
fn real_chain(count: usize) -> Vec<Block> {
    let miner = SecretKey::from_bytes(&[1; 32]);
    let rules = params();
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
            let block = assemble_block(&state, coinbase, Vec::new(), &rules, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
            connect_block(&mut state, &block, &rules, NOW).unwrap();
            block
        })
        .collect()
}

/// A block that builds on the tip, weighs more than the branch, and cannot
/// apply.
///
/// Difficulty one accepts every hash, so a maker spends no work on it, and
/// only the nonce changes between them, which is enough for a fresh
/// identifier. What it fails on is a header field, which is what puts it in
/// the set: a block whose header settles the matter can never become valid,
/// unlike one this build is merely too old to judge.
fn bad_block(height: u64, previous: Hash32, nonce: u64) -> Block {
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
            total_work: 0,
            nonce,
        },
        coinbase: CoinbaseTransaction::new(height, Vec::new()),
        transfers: Vec::new(),
    }
}

/// Offers `count` distinct bad blocks on the tip, and hands back the ones the
/// caller asked to keep hold of.
fn offer_bad_blocks(store: &mut ChainStore, tip: &Block, nonces: impl IntoIterator<Item = u64>) {
    for nonce in nonces {
        let bad = bad_block(tip.header.height + 1, tip.id(), nonce);
        let refusal = store.add_block(bad, NOW);
        assert!(
            matches!(
                refusal,
                Err(ChainError::InvalidBlock {
                    source: BlockError::WrongTotalWork { .. },
                    ..
                })
            ),
            "block {nonce} was refused for something other than its header: {refusal:?}"
        );
    }
}

/// The reason the set exists: a block that failed once is refused on the
/// strength of being remembered, without the work of judging it again.
#[test]
fn a_block_that_failed_once_is_not_judged_twice() {
    let chain = real_chain(3);
    let mut store = ChainStore::new(params());
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = chain.last().unwrap();
    let bad = bad_block(tip.header.height + 1, tip.id(), 7);
    let id = bad.id();

    assert!(
        matches!(
            store.add_block(bad.clone(), NOW),
            Err(ChainError::InvalidBlock {
                source: BlockError::WrongTotalWork { .. },
                ..
            })
        ),
        "the first offer should say what was wrong with the header"
    );
    assert_eq!(
        store.add_block(bad, NOW),
        Err(ChainError::KnownBad { id }),
        "the second offer should be answered from the set"
    );
}

/// A version the rules at this height refuse is remembered like any other
/// bad header.
///
/// `settles_the_header` sorts refusals into two piles: the ones that are
/// about the block, which go in the set for good, and the ones that are about
/// the reader, which do not, because an update reverses them. `WrongVersion`
/// is the one that looks like the second and belongs in the first: this build
/// knows the version the block carries and knows the rules where it sits, so
/// no update makes the block right.
///
/// Nothing measured which pile it went in. Taking `WrongVersion` out of that
/// list left every test in this repository passing, and a node would have
/// judged the same refused block again on every offer, for as long as anybody
/// kept offering it. That is the whole reason the set exists.
#[test]
fn a_version_the_rules_at_this_height_refuse_is_remembered() {
    let chain = real_chain(3);
    let mut store = ChainStore::new(params());
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = chain.last().unwrap();

    // Nothing else is wrong with it: the body is the one an honest producer
    // would publish on this tip, and only the version is not what the rules
    // at that height require. Version zero rather than one above the ceiling,
    // which is the other half of the pair and is deliberately not remembered.
    let miner = SecretKey::from_bytes(&[1; 32]);
    let rules = params();
    let mut state = LedgerState::new();
    for block in &chain {
        connect_block(&mut state, block, &rules, NOW).unwrap();
    }
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(rules.initial_reward, miner.public_key())],
    );
    let mut wrong = assemble_block(
        &state,
        coinbase,
        Vec::new(),
        &rules,
        tip.header.timestamp + 600,
        0,
    )
    .unwrap();
    assert_eq!(
        wrong.header.version, BLOCK_VERSION,
        "the producer builds at the version the rules ask for"
    );
    wrong.header.version = 0;
    let wrong = mine_block(wrong, ATTEMPTS).expect("a nonce exists");
    let id = wrong.id();

    assert_eq!(
        store.add_block(wrong.clone(), NOW),
        Err(ChainError::InvalidBlock {
            id,
            source: BlockError::WrongVersion {
                height,
                found: 0,
                required: BLOCK_VERSION,
            },
        }),
        "the first offer should name the version the rules require"
    );
    assert_eq!(
        store.add_block(wrong, NOW),
        Err(ChainError::KnownBad { id }),
        "the second offer should be answered from the set rather than judged again"
    );
}

/// What a stranger can make this node remember.
///
/// Every bad block costs its maker a header at difficulty one and nothing
/// else, and each distinct one is another identifier held. Past `MAX_INVALID`
/// the set is emptied rather than grown, so the price of the memory is bounded
/// at thirty two bytes times that count, and the price of emptying it is
/// revalidating a handful of blocks that will fail again the same way.
///
/// Read as counts rather than as a clock or a reading of this process: the
/// question is which of two answers comes back for a block offered again, and
/// both nodes in an exchange would agree on it.
#[test]
fn the_set_of_bad_blocks_is_emptied_rather_than_grown() {
    let chain = real_chain(3);
    let mut store = ChainStore::new(params());
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = chain.last().unwrap();
    let height = tip.header.height + 1;

    let first = bad_block(height, tip.id(), 0);
    let first_id = first.id();

    let filling = u64::try_from(MAX_INVALID).unwrap();
    offer_bad_blocks(&mut store, tip, 0..filling);

    // Exactly at the ceiling, and nothing has been let go of: the block that
    // went in first is still answered from the set. This half is what says the
    // set is not being emptied early, which a ceiling test that only looked
    // past the ceiling could not tell from one that is never filled at all.
    assert_eq!(
        store.add_block(first.clone(), NOW),
        Err(ChainError::KnownBad { id: first_id }),
        "the set dropped something before it was full"
    );

    // One past it. The set is emptied before the newcomer goes in, so the
    // block that went in first is judged afresh, and the newcomer is the one
    // now answered from the set.
    let last = bad_block(height, tip.id(), filling);
    let last_id = last.id();
    offer_bad_blocks(&mut store, tip, [filling]);

    assert!(
        matches!(
            store.add_block(first, NOW),
            Err(ChainError::InvalidBlock {
                source: BlockError::WrongTotalWork { .. },
                ..
            })
        ),
        "the set went past its ceiling: the oldest entry is still remembered"
    );
    assert_eq!(
        store.add_block(last, NOW),
        Err(ChainError::KnownBad { id: last_id }),
        "emptying the set lost the entry that had just been put in it"
    );
}

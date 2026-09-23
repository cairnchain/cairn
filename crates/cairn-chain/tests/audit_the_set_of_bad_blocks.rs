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
use cairn_ledger::block::{Block, BlockHeader, HeaderSummary, BLOCK_VERSION};
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::pow::median_time_past;
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
    real_chain_under(&params(), count)
}

/// The same, under rules the caller chose.
fn real_chain_under(rules: &ConsensusParams, count: usize) -> Vec<Block> {
    let miner = SecretKey::from_bytes(&[1; 32]);
    let rules = *rules;
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

/// The block an honest producer would publish on the tip of `chain`.
///
/// Every row below bends exactly one field of this, so what each row measures
/// is that field and nothing else.
fn next_block(rules: &ConsensusParams, chain: &[Block]) -> Block {
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    for block in chain {
        connect_block(&mut state, block, rules, NOW).unwrap();
    }
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(rules.initial_reward, miner.public_key())],
    );
    let clock = chain
        .last()
        .map_or(1_600, |block| block.header.timestamp + 600);
    let block = assemble_block(&state, coinbase, Vec::new(), rules, clock, 0).unwrap();
    mine_block(block, ATTEMPTS).expect("a nonce exists")
}

/// One row of the list below: what is bent, how, and the refusal that earns.
type Row = (
    &'static str,
    fn(&mut BlockHeader, u64),
    fn(&BlockError) -> bool,
);

/// Every refusal a peer can earn for a header is remembered, not just the one
/// the fixtures happened to produce.
///
/// `settles_the_header` sorts refusals into two piles. The ones about the
/// block go into the set of known bad identifiers and are never judged again.
/// The ones about the reader, a version above anything this build knows or
/// rules it lacks at that height, do not, because an update reverses them and
/// remembering one made un-updated nodes condemn the real chain for good.
///
/// Eleven refusals are in the first pile and **one of them was measured**.
/// Every other arm of that list could be deleted with this whole repository
/// still passing, because every fixture that ever made a bad block made the
/// same one: a header whose total work does not add up. Without the set a
/// node judges the same refused block again on every offer, for as long as
/// anybody keeps offering it, which is the whole reason the set exists.
///
/// So this is the list rather than one more example. Each row bends one field
/// of a block the rules would otherwise take, names the refusal that bending
/// earns, and asks for the block a second time.
///
/// The block is mined again after it is bent, because a bent header has a new
/// identifier and a node refuses one carrying no work before it judges it at
/// all: a different and much cheaper refusal, deliberately not remembered.
///
/// **Five of the eleven are not rows here**, and the reason is worth writing
/// down rather than hiding in a `#[ignore]`. Offering a block is not the only
/// way into `apply`, but it is the only one a stranger has, and on that path:
///
/// - `WrongHeight` is answered `BrokenHeight` by the cheap check that reads
///   the parent's height, before the block is ever applied;
/// - `WrongParent` is answered `UnknownParent`, because a block naming a
///   parent this node does not hold is not refused, it is held and waited on;
/// - `InsufficientWork` is answered `NoWork`, which is the same question
///   asked first and more cheaply;
/// - `WrongGenesis` is only asked at height zero, where there is no chain to
///   offer a block on;
/// - `HeightOverflow` needs a chain 2^64 blocks long.
///
/// The first three are reachable the other way in, applying a block already
/// held when a branch is switched to, and that is a different fixture. What
/// this test settles is the door a peer knocks on.
#[test]
fn every_refusal_a_peer_can_earn_for_a_header_is_remembered() {
    // Above the minimum, so a difficulty can be bent downwards and the header
    // still carry work for the number it claims. At the minimum there is
    // nothing below to bend to. The opening is set between the first block of
    // the chain and nothing, so a block can be dated before it.
    let mut rules = params();
    rules.genesis_difficulty = 1 << 8;
    rules.opens_at = 1_500;
    let chain = real_chain_under(&rules, 3);
    let honest = next_block(&rules, &chain);

    let median = median_time_past(
        &chain
            .iter()
            .map(|block| HeaderSummary {
                height: block.header.height,
                timestamp: block.header.timestamp,
                difficulty: block.header.difficulty,
            })
            .collect::<Vec<_>>(),
    )
    .expect("three blocks have a median");

    let rows: [Row; 6] = [
        (
            "a block from another network",
            |header, _| header.network = NetworkId::DEVNET,
            |source| matches!(source, BlockError::WrongNetwork { .. }),
        ),
        (
            "a block dated before the network opened",
            |header, _| header.timestamp = 1,
            |source| matches!(source, BlockError::BeforeTheNetworkOpened { .. }),
        ),
        (
            "a version these rules do not require",
            |header, _| header.version = 0,
            |source| matches!(source, BlockError::WrongVersion { .. }),
        ),
        (
            "a difficulty the schedule does not ask for",
            |header, _| header.difficulty = 1,
            |source| matches!(source, BlockError::WrongDifficulty { .. }),
        ),
        (
            "total work that does not add up",
            |header, _| header.total_work += 1,
            |source| matches!(source, BlockError::WrongTotalWork { .. }),
        ),
        (
            "a timestamp no later than the median",
            |header, median| header.timestamp = median,
            |source| matches!(source, BlockError::TimestampNotAfterMedian { .. }),
        ),
    ];

    for (what, bend, names) in rows {
        let mut store = ChainStore::new(rules);
        for block in &chain {
            store.add_block(block.clone(), NOW).unwrap();
        }

        let mut bent = honest.clone();
        bend(&mut bent.header, median);
        let bent = mine_block(bent, ATTEMPTS).expect("a nonce exists at this difficulty");
        let id = bent.id();

        let first = store.add_block(bent.clone(), NOW);
        assert!(
            matches!(&first, Err(ChainError::InvalidBlock { source, .. }) if names(source)),
            "{what} earned {first:?}, which is not the refusal this row is about"
        );
        assert_eq!(
            store.add_block(bent, NOW),
            Err(ChainError::KnownBad { id }),
            "{what} was judged again rather than answered from the set"
        );
    }
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

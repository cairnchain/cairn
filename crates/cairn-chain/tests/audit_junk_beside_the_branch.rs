//! What a stranger's blocks beside the branch can cost the branch.
//!
//! A block that loses the fork choice is held without being applied, and the
//! side store it is held in is bounded by count and by bytes. Two defects
//! lived there, both found by `fuzz_block_store.rs` and both cut down to the
//! sequences rebuilt here.
//!
//! The first is entry E05 of the testnet-8 attack catalogue. A side block's
//! difficulty was taken as claimed, so a block claiming difficulty one cost
//! one hash; and over its ceiling the side store dropped by height and then by
//! identifier, whatever the work, where a mined block's identifier sorts ahead
//! of free junk's. Four thousand junk blocks hung off the first block made the
//! node drop the first block of an honest heavier branch handed over after
//! them, refuse every later block of that branch for a parent it had dropped,
//! and stay on the lighter branch.
//!
//! The second is the ceiling itself. The side store was swept when a block
//! landed beside the branch and after a switch that held, and never after a
//! switch that failed. One junk branch made heavier than the tip is tried,
//! fails on its first block, and leaves the rest of it held above a block
//! that is no longer there; every block built on those afterwards was held
//! and never swept, 19 999 of them against 4 096.
//!
//! Both cut-down cases are refused at the door now, since their junk claims
//! less than its parent demands. So each defect is also held here with junk
//! the door takes, carrying exactly what its parent demands: the sweep has to
//! run after a failed switch whatever the junk cost, and a full store has to
//! keep an honest block that outweighs the junk however high the junk sits.
//! And the door itself, rule by rule.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use cairn_chain::{
    Accepted, ChainError, ChainStore, HELD_OVERHEAD, MAX_SIDE_BLOCKS, MAX_SIDE_BYTES,
};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::pow::next_difficulty;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, mine_header, BlockError, ConsensusParams,
};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

/// When the network opens, and when its first block is dated.
const OPENS: u64 = 1_000_000;

/// The node's clock, past every block here.
const NOW: u64 = 4_000_000_000;

const ATTEMPTS: u64 = 1 << 28;

/// The opening difficulty the campaign floods at: an honest block is worth
/// more than a whole flood of blocks claiming difficulty one, so the flood
/// stays lighter than the tip and is held rather than tried.
const HEAVY: u64 = 8_192;

fn rules(opening: u64) -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.opens_at = OPENS;
    params.genesis_difficulty = opening;
    params
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
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

/// A block claiming difficulty one and no work behind it, with a root that
/// matches its body and nothing else right about it: what the campaign's
/// floods are made of.
fn junk(height: u64, previous: Hash32, nonce: u64) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: BLOCK_VERSION,
            network: NetworkId::TESTNET,
            height,
            previous,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: OPENS + height,
            difficulty: 1,
            total_work: 0,
            nonce,
        },
        coinbase: CoinbaseTransaction::new(height, Vec::new()),
        transfers: Vec::new(),
    };
    block.header.transactions_root = block.transactions_root();
    block
}

/// A block on `parent` carrying exactly what that parent demands and nothing
/// else right about it: the difficulty the retarget asks of the parent, the
/// work behind the parent plus that, the network and the version. What the
/// door asks, and what junk costs now.
fn paid(params: &ConsensusParams, parent: &Block, timestamp: u64, nonce: u64) -> Block {
    let height = parent.header.height + 1;
    let difficulty = next_difficulty(
        &parent.header.summary(),
        params.origin(),
        params.target_block_time,
    );
    let mut block = Block {
        header: BlockHeader {
            version: BLOCK_VERSION,
            network: params.network,
            height,
            previous: parent.id(),
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp,
            difficulty,
            total_work: parent.header.total_work + u128::from(difficulty),
            nonce: 0,
        },
        coinbase: CoinbaseTransaction::with_extra(height, Vec::new(), nonce.to_le_bytes().to_vec()),
        transfers: Vec::new(),
    };
    block.header.transactions_root = block.transactions_root();
    block.header = mine_header(block.header, ATTEMPTS).expect("a nonce at the demanded difficulty");
    block
}

/// What the store holds off the branch it follows, in blocks and in bytes.
///
/// `branch` is every block of the followed branch, which on a chain this
/// short the store holds in full.
fn side(store: &ChainStore, branch: &[&Block]) -> (usize, usize) {
    let bytes: usize = branch
        .iter()
        .map(|block| block.encode().len() + HELD_OVERHEAD)
        .sum();
    (store.len() - branch.len(), store.held_bytes() - bytes)
}

/// The cut-down E05 case: a flood off the first block, then the heavier
/// honest branch handed over in order from the first block.
///
/// Seed 0x3, case 0 of the campaign. The node follows the first block and one
/// child of it; four thousand and ninety seven junk blocks hang off the first
/// block at the child's height; the honest branch through the child's sibling
/// is two blocks heavier. On the store before this, the sibling was dropped
/// as it arrived, its child was refused for a parent the node did not have,
/// and the node stayed on the branch worth half as much.
#[test]
fn an_honest_heavier_branch_handed_over_after_a_flood_is_followed() {
    let params = rules(HEAVY);
    let (first, at_first) = mint(&params, &LedgerState::new(), OPENS, 0);
    let (followed, _) = mint(&params, &at_first, OPENS + 20, 1);
    let (sibling, at_sibling) = mint(&params, &at_first, OPENS + 61, 2);
    let (above, at_above) = mint(&params, &at_sibling, OPENS + 121, 4);
    let (top, _) = mint(&params, &at_above, OPENS + 181, 5);
    assert!(top.header.total_work > followed.header.total_work);

    let mut store = ChainStore::new(params);
    store.add_block(first.clone(), NOW).unwrap();
    store.add_block(followed.clone(), NOW).unwrap();

    // Whatever each is answered: what is under test is what the node does
    // with the honest branch afterwards.
    for nonce in 0..=MAX_SIDE_BLOCKS as u64 {
        let _ = store.add_block(junk(1, first.id(), nonce), NOW);
        assert_eq!(store.tip(), Some(followed.id()), "junk moved the tip");
    }

    for block in [first, sibling, above, top.clone()] {
        let _ = store.add_block(block, NOW);
    }
    assert_eq!(
        store.tip(),
        Some(top.id()),
        "the heavier honest branch was handed over in order after the flood, and \
         the node stayed where it was"
    );
    assert_eq!(store.total_work(), top.header.total_work);
}

/// The cut-down ceiling case: a flood that outgrows the tip, is tried, fails,
/// and goes on arriving.
///
/// Seed 0xca12f0221d05ca12, case 0 of the campaign. The node follows three
/// blocks; a chain of junk hangs off the second, catches the tip after two
/// thousand blocks, and is tried on the next, which fails on its first block.
/// Everything built on the chain afterwards was held and never swept.
#[test]
fn the_side_store_stays_within_its_bounds_after_a_switch_that_failed() {
    let params = rules(HEAVY);
    let (first, at_first) = mint(&params, &LedgerState::new(), OPENS, 0);
    let (second, at_second) = mint(&params, &at_first, OPENS + 7_200, 3);
    let (third, _) = mint(&params, &at_second, OPENS + 10_800, 4);

    let mut store = ChainStore::new(params);
    for block in [&first, &second, &third] {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let branch = [&first, &second, &third];

    let mut previous = second.id();
    for index in 0..=(MAX_SIDE_BLOCKS as u64 + 1) {
        let block = junk(2 + index, previous, index);
        previous = block.id();
        let _ = store.add_block(block, NOW);
        assert_eq!(store.tip(), Some(third.id()), "junk moved the tip");
        let (blocks, bytes) = side(&store, &branch);
        assert!(
            blocks <= MAX_SIDE_BLOCKS && bytes <= MAX_SIDE_BYTES,
            "after junk block {index}: {blocks} blocks and {bytes} bytes held off the \
             branch, against {MAX_SIDE_BLOCKS} and {MAX_SIDE_BYTES}"
        );
    }
}

/// One thing changed in a header the door would take.
type Edit = fn(&mut BlockHeader);

/// Whether a refusal is the one that change should earn.
type Verdict = fn(&BlockError) -> bool;

/// The door, rule by rule: a block beside the branch is held only if it
/// carries what its parent alone settles.
///
/// Each block here is a block the door takes with one thing changed, and
/// mined again so that it does the work it claims: it is refused for that
/// one thing, it is not held, the tip does not move, and a verdict the header
/// alone settles is remembered against it, so offering it again is answered
/// from the set of refused blocks. Every one of them used to be held, at the
/// price of the work it claimed, until its branch was tried.
#[test]
fn a_block_beside_the_branch_is_held_only_if_it_carries_what_its_parent_demands() {
    // Close to the blocks, so the drift is a question.
    const CLOCK: u64 = OPENS + 3_600;
    let params = rules(64);
    let drift = params.max_timestamp_drift;
    let (first, at_first) = mint(&params, &LedgerState::new(), OPENS, 0);
    let (second, at_second) = mint(&params, &at_first, OPENS + 60, 1);
    let (third, _) = mint(&params, &at_second, OPENS + 120, 2);

    let mut store = ChainStore::new(params);
    for block in [&first, &second, &third] {
        store.add_block(block.clone(), CLOCK).unwrap();
    }

    // What the door takes, at either end of what it allows in time.
    for (nonce, timestamp) in [(1, OPENS + 130), (2, OPENS), (3, CLOCK + drift)] {
        let held = paid(&params, &second, timestamp, nonce);
        assert_eq!(
            store.add_block(held.clone(), CLOCK),
            Ok(Accepted::SideBranch),
            "a block carrying what its parent demands, dated {timestamp}, was not held"
        );
        assert!(store.contains(&held.id()));
    }

    let wrong: [(&str, Edit, Verdict, bool); 8] = [
        (
            "a difficulty above the parent's demand",
            |header| header.difficulty += 1,
            |source| {
                matches!(
                    source,
                    BlockError::WrongDifficulty {
                        expected: 64,
                        found: 65
                    }
                )
            },
            true,
        ),
        (
            "a difficulty below it",
            |header| header.difficulty -= 1,
            |source| {
                matches!(
                    source,
                    BlockError::WrongDifficulty {
                        expected: 64,
                        found: 63
                    }
                )
            },
            true,
        ),
        (
            "a total work that does not add up",
            |header| header.total_work += 1,
            |source| matches!(source, BlockError::WrongTotalWork { .. }),
            true,
        ),
        (
            "another network",
            |header| header.network = NetworkId::new(0x5eed_0001),
            |source| matches!(source, BlockError::WrongNetwork { .. }),
            true,
        ),
        (
            "a date before the network opened",
            |header| header.timestamp = OPENS - 1,
            |source| matches!(source, BlockError::BeforeTheNetworkOpened { .. }),
            true,
        ),
        (
            "a version past anything this build knows",
            |header| header.version = BLOCK_VERSION + 1,
            |source| matches!(source, BlockError::UnsupportedVersion(_)),
            false,
        ),
        (
            "a version its height does not ask for",
            |header| header.version = BLOCK_VERSION - 1,
            |source| matches!(source, BlockError::WrongVersion { .. }),
            true,
        ),
        (
            "a date past the drift",
            |header| header.timestamp = OPENS + 3_600 + 600 + 1,
            |source| matches!(source, BlockError::TimestampTooFarAhead { .. }),
            false,
        ),
    ];
    assert_eq!(
        drift, 600,
        "the date past the drift is written against this"
    );

    for (nonce, (what, edit, verdict, remembered)) in (10u64..).zip(wrong) {
        let mut block = paid(&params, &second, OPENS + 130, nonce);
        edit(&mut block.header);
        block.header = mine_header(block.header, ATTEMPTS).unwrap();
        let id = block.id();

        let answer = store.add_block(block.clone(), CLOCK);
        assert!(
            matches!(&answer, Err(ChainError::InvalidBlock { id: refused, source })
                if *refused == id && verdict(source)),
            "{what} was answered {answer:?}"
        );
        assert!(!store.contains(&id), "{what} was held");
        assert_eq!(store.tip(), Some(third.id()), "{what} moved the tip");

        let again = store.add_block(block, CLOCK);
        if remembered {
            assert!(
                matches!(
                    again,
                    Err(ChainError::KnownBad { id: known } | ChainError::KnownForeign { id: known, .. })
                        if known == id
                ),
                "{what} was judged again rather than answered from the set of refused \
                 blocks: {again:?}"
            );
        } else {
            assert_eq!(
                again, answer,
                "{what} was remembered, and nothing settles it for good"
            );
        }
    }

    // The one refusal this node reverses by waiting: the same block, once the
    // clock allows it, is held.
    let mut early = paid(&params, &second, OPENS + 130, 99);
    early.header.timestamp = CLOCK + drift + 1;
    early.header = mine_header(early.header, ATTEMPTS).unwrap();
    assert!(store.add_block(early.clone(), CLOCK).is_err());
    assert_eq!(store.add_block(early, CLOCK + 1), Ok(Accepted::SideBranch));
}

/// A block beside the branch at a height whose rules this build does not
/// have is not judged, and not held: the door says the node is out of date,
/// as the switch would have.
#[test]
fn a_block_beside_the_branch_under_rules_this_build_lacks_is_answered_as_out_of_date() {
    const SCHEDULED: &[Activation] = &[
        Activation {
            height: 0,
            version: BLOCK_VERSION,
        },
        Activation {
            height: 2,
            version: BLOCK_VERSION + 1,
        },
    ];
    let mut params = rules(64);
    params.activations = SCHEDULED;
    let (first, at_first) = mint(&params, &LedgerState::new(), OPENS, 0);
    let (followed, _) = mint(&params, &at_first, OPENS + 60, 1);
    let (rival, _) = mint(&params, &at_first, OPENS + 61, 2);

    let mut store = ChainStore::new(params);
    store.add_block(first, NOW).unwrap();
    store.add_block(followed.clone(), NOW).unwrap();
    assert_eq!(
        store.add_block(rival.clone(), NOW),
        Ok(Accepted::SideBranch)
    );

    let mut beyond = paid(&params, &rival, OPENS + 120, 1);
    beyond.header.version = BLOCK_VERSION + 1;
    beyond.header = mine_header(beyond.header, ATTEMPTS).unwrap();
    let answer = store.add_block(beyond.clone(), NOW);
    assert!(
        answer
            .as_ref()
            .is_err_and(|refused| refused.outdated().is_some()),
        "{answer:?}"
    );
    assert!(!store.contains(&beyond.id()));
    assert_eq!(store.tip(), Some(followed.id()));
    assert_eq!(
        store.add_block(beyond, NOW),
        answer,
        "a verdict about this build was remembered against the block"
    );
}

/// The bounds hold after a failed switch, with junk the door takes.
///
/// On a network at the difficulty floor every block demands one hash, so
/// junk carrying exactly what its parent demands is as free as it ever was,
/// and the second defect is reached the way it was: a junk branch made
/// heavier than the tip is tried and fails on its first block, the rest of
/// it is held over a parent that has gone, and blocks keep arriving on what
/// it left. Each is held, tried, and refused for that missing parent. They
/// are the first thing the sweep drops, and an honest block held beside the
/// branch all along outlasts every one of them.
#[test]
fn the_bounds_hold_after_a_failed_switch_whatever_is_built_on_what_it_left() {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::new();
    let mut branch = Vec::new();
    let mut states = Vec::new();
    for height in 0..4u64 {
        let (block, after) = mint(&params, &state, 1_000 + 600 * height, 0);
        branch.push(block);
        states.push(after.clone());
        state = after;
    }
    // Beside the tip, honest, and as heavy.
    let (honest, _) = mint(&params, &states[2], 1_000 + 600 * 3 + 1, 7);

    let mut store = ChainStore::new(params);
    for block in &branch {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(
        store.add_block(honest.clone(), NOW),
        Ok(Accepted::SideBranch)
    );
    let tip = branch[3].id();
    let held: Vec<&Block> = branch.iter().collect();

    // Off the second block, two blocks to tie the tip and a third to pass it.
    let first_junk = paid(&params, &branch[1], 4_000, 0);
    let second_junk = paid(&params, &first_junk, 4_600, 0);
    let third_junk = paid(&params, &second_junk, 5_200, 0);
    assert_eq!(
        store.add_block(first_junk.clone(), NOW),
        Ok(Accepted::SideBranch)
    );
    assert_eq!(
        store.add_block(second_junk.clone(), NOW),
        Ok(Accepted::SideBranch)
    );
    let tried = store.add_block(third_junk.clone(), NOW);
    assert!(
        matches!(&tried, Err(ChainError::InvalidBlock { id, .. }) if *id == first_junk.id()),
        "the junk branch was tried and failed on its first block: {tried:?}"
    );
    assert!(!store.contains(&first_junk.id()));
    assert!(
        store.contains(&third_junk.id()),
        "what the failed switch left is held"
    );

    for nonce in 1..=(MAX_SIDE_BLOCKS as u64 + 600) {
        let block = paid(&params, &third_junk, 5_800, nonce);
        let answer = store.add_block(block, NOW);
        assert!(
            matches!(answer, Err(ChainError::UnknownParent(gone)) if gone == first_junk.id()),
            "junk {nonce} above the failed switch was answered {answer:?}"
        );
        assert_eq!(store.tip(), Some(tip), "junk moved the tip");
        let (blocks, bytes) = side(&store, &held);
        assert!(
            blocks <= MAX_SIDE_BLOCKS && bytes <= MAX_SIDE_BYTES,
            "after junk {nonce}: {blocks} blocks and {bytes} bytes held off the branch, \
             against {MAX_SIDE_BLOCKS} and {MAX_SIDE_BYTES}"
        );
    }
    assert!(
        store.contains(&honest.id()),
        "an honest block beside the branch went before junk that no switch can reach"
    );
}

/// A full store keeps an honest block that outweighs the junk, however high
/// the junk sits.
///
/// The junk here is paid for: it hangs off a branch dated so far behind its
/// schedule that its difficulty has fallen to the floor, which the node's
/// clock allows, so each block of it carries what its parent demands and
/// costs one hash. It sits four heights above the honest branch's first
/// block and weighs less. The sweep that went by height dropped that block
/// as it arrived, which is E05 with junk the door takes; the sweep that goes
/// by work drops the junk.
#[test]
fn junk_lighter_than_an_honest_block_does_not_displace_it_however_high_it_sits() {
    let params = rules(16);
    let (first, at_first) = mint(&params, &LedgerState::new(), OPENS, 0);
    let (shared, at_shared) = mint(&params, &at_first, OPENS + 60, 1);
    let (followed, _) = mint(&params, &at_shared, OPENS + 120, 2);
    let (rival, at_rival) = mint(&params, &at_shared, OPENS + 100, 3);
    let (heavier, _) = mint(&params, &at_rival, OPENS + 110, 4);
    assert_eq!(rival.header.total_work, followed.header.total_work);
    assert!(heavier.header.total_work > followed.header.total_work);

    let mut store = ChainStore::new(params);
    for block in [&first, &shared, &followed] {
        store.add_block(block.clone(), NOW).unwrap();
    }

    // Off the first block, dated near the node's clock: billions of seconds
    // behind the schedule, so each block demands a quarter of its parent's
    // difficulty until the floor.
    let mut cheap = vec![paid(&params, &first, NOW - 10_000, 0)];
    while cheap.last().unwrap().header.difficulty > 1 || cheap.len() < 5 {
        let parent = cheap.last().unwrap();
        let next = paid(&params, parent, parent.header.timestamp + 1, 0);
        cheap.push(next);
    }
    for block in &cheap {
        assert_eq!(
            store.add_block(block.clone(), NOW),
            Ok(Accepted::SideBranch)
        );
    }
    let top = cheap.last().unwrap().clone();
    let junk: Vec<Block> = (1..=(MAX_SIDE_BLOCKS as u64))
        .map(|nonce| paid(&params, &top, NOW - 5_000, nonce))
        .collect();
    let weight = junk[0].header.total_work;
    assert!(
        weight < rival.header.total_work && junk[0].header.height > rival.header.height + 3,
        "the junk has to sit above the honest block and weigh less, or this is not E05"
    );
    for block in &junk {
        assert_eq!(
            store.add_block(block.clone(), NOW),
            Ok(Accepted::SideBranch)
        );
    }

    assert_eq!(
        store.add_block(rival.clone(), NOW),
        Ok(Accepted::SideBranch)
    );
    assert!(
        store.contains(&rival.id()),
        "the honest block went as it arrived"
    );
    assert!(matches!(
        store.add_block(heavier.clone(), NOW),
        Ok(Accepted::Reorganised { .. })
    ));
    assert_eq!(store.tip(), Some(heavier.id()));
}

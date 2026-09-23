//! What a peer can make this node carry between two blocks of its own branch.
//!
//! `ChainStore::held_bytes_ceiling` is documented as "the most this node will
//! ever hold in blocks", and `examples/window.rs` publishes a figure computed
//! from it under the sentence that none of it grows with the chain. Both are
//! true of the node as it stands *after* a block joins the branch it follows,
//! because that is where the sweeps run. `forget_unreachable_branches` and
//! `forget_oldest_side_blocks` are reached from `ChainStore::follow` and from
//! `add_block`, which is the side-branch path this file is about: a block
//! that loses the fork choice is swept on the way out rather than waiting for
//! the branch to move. This said `follow` and nowhere else, which was the gap
//! the second call was added to close, and the commit that added it moved two
//! other sentences to the past tense and left this one.
//!
//! A block that loses the fork choice never reaches `follow`. `add_block`
//! stores it and returns `Accepted::SideBranch`, and between one block of the
//! followed branch and the next nothing at all looks at what has piled up. So
//! the ceiling answers what the node settles at, and the question a ceiling
//! exists to answer is what a stranger can make it hold.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{
    Accepted, ChainStore, HELD_WINDOW, MAX_REORG_DEPTH, MAX_SIDE_BLOCKS, MAX_SIDE_BYTES, MILESTONE,
};
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

/// Mines a branch on a private ledger, so blocks exist without a node having
/// followed them.
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

/// A block off the followed branch, filled towards `bytes`, carrying the least
/// work there is.
///
/// Difficulty one accepts every hash, so this costs its maker no work at all.
/// Nothing here is validated: a block that loses the fork choice is stored and
/// never connected, so its body is never looked at. Only the nonce changes
/// between them, which is enough for a different identifier, so a whole branch
/// of these hangs off one parent rather than having to be chained.
fn side_block(height: u64, previous: Hash32, bytes: usize, nonce: u64, owner: &SecretKey) -> Block {
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
            total_work: 0,
            nonce,
        },
        coinbase: CoinbaseTransaction::new(height, Vec::new()),
        transfers: vec![transfer],
    }
}

/// A block already judged and refused is not taken into memory again.
///
/// The sweep that bounds what this node holds runs when a block joins the
/// followed branch. A block that loses the fork choice is swept where it
/// lands, which is the repair above. Neither reaches the third road: a block
/// claiming to extend the tip goes to `follow`, and when its identifier is
/// already in the set of bad ones `follow` refuses it at its first step and
/// returns before any sweep.
///
/// The body was held on the way in either way, and on that road nothing took
/// it out again. Difficulty one accepts every hash, so re-sending costs a
/// stranger nothing at all.
#[test]
fn a_block_already_refused_is_not_taken_into_memory_again() {
    let rules = params();
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    let chain = shared.mine_empty(&miner, 4);

    let mut store = ChainStore::new(rules);
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let settled = store.held_bytes();
    let tip = chain[chain.len() - 1].id();
    let next = store.height().unwrap() + 1;

    // Each claims to build straight on the tip, so each is weighed heavier
    // than the branch and taken to `follow`, and none of them can apply.
    let refused: Vec<Block> = (0..64u64)
        .map(|nonce| side_block(next, tip, 16 * 1024, nonce, &miner))
        .collect();

    for block in &refused {
        assert!(
            store.add_block(block.clone(), NOW).is_err(),
            "this test needs blocks the node refuses"
        );
    }
    let after_the_first_offer = store.held_bytes();

    // The same blocks again, which is the whole of the attack.
    for block in &refused {
        assert!(
            matches!(
                store.add_block(block.clone(), NOW),
                Err(cairn_chain::ChainError::KnownBad { .. })
            ),
            "a block refused once is refused again for having been refused, which is what \
             the set of bad identifiers is for"
        );
    }

    assert_eq!(
        store.held_bytes(),
        after_the_first_offer,
        "offering refused blocks again put {} more bytes into this node, at no proof of \
         work and for as long as it cares to keep offering. The set of bad identifiers \
         saved the judging and not the holding",
        store.held_bytes().saturating_sub(after_the_first_offer)
    );
    assert_eq!(
        store.held_bytes(),
        settled,
        "and a block that could not apply is not worth keeping at all"
    );
}

/// Offers `count` losing blocks and reports what the node then holds, without
/// letting its own branch move.
fn offer_side_blocks(rules: ConsensusParams, bytes: usize, count: u64) -> (usize, usize) {
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    let chain = shared.mine_empty(&miner, 30);

    let mut store = ChainStore::new(rules);
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.height(), Some(29));

    let parent = chain[0].id();
    for nonce in 0..count {
        let block = side_block(1, parent, bytes, nonce, &wallet(9));
        assert_eq!(
            store.add_block(block, NOW).unwrap(),
            Accepted::SideBranch,
            "a losing block was not held aside"
        );
    }
    (store.held_bytes(), store.len())
}

/// The sweep keeps the rivals a node may yet have to switch to, and counts
/// them.
///
/// Measured on a branch longer than the window a reorganisation may reach back
/// over, which is where a node holds its own blocks and a stranger's at once:
/// twelve thousand rivals of the tip leave it holding the branch's window plus
/// `MAX_SIDE_BLOCKS` of them, and no more, however many were offered.
///
/// Both halves matter. A node that kept no rivals would have a fork choice
/// deciding between its branch and nothing; one that kept them all would hold
/// whatever a stranger cared to send.
///
/// Which sweep the count belongs to is worth saying, because the obvious
/// answer is wrong. Joining the two halves of `forget_unreachable_branches`
/// with "and", or moving either of its thresholds, leaves this measurement
/// unchanged: what enforces both limits is `forget_oldest_side_blocks`, whose
/// own note says `MAX_SIDE_BLOCKS` "was a trigger and never a bound" until it
/// was made one. The first sweep drops what is out of reach; this is what the
/// second one settles at. What the first one does for itself is measured by
/// the test at the end of this file, on the one input that separates them.
#[test]
fn the_sweep_keeps_the_rivals_inside_the_window_and_counts_them() {
    let rules = params();
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    let chain = shared.mine_empty(&miner, MAX_REORG_DEPTH + 60);

    let mut store = ChainStore::new(rules);
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.height().expect("a chain to stand on");
    let branch_entries = store.len();
    assert!(
        tip > MAX_REORG_DEPTH as u64,
        "a branch longer than the window it may undo"
    );

    // Rivals of the tip, which is where a rival has to sit to be worth
    // anything: a node refuses a block from under the floor it has settled.
    let previous = store.id_at(tip - 1).expect("the block below the tip");
    for nonce in 0..12_000u64 {
        let block = side_block(tip, previous, 4096, nonce, &wallet(9));
        assert_eq!(
            store.add_block(block, NOW).unwrap(),
            Accepted::SideBranch,
            "a losing block was not held aside"
        );
    }

    assert!(
        store.len() > branch_entries,
        "the sweep dropped every rival, leaving the fork choice deciding \
         between this branch and nothing"
    );
    assert!(
        store.len() <= MAX_REORG_DEPTH + MAX_SIDE_BLOCKS + 1,
        "twelve thousand rivals left the node holding {} entries against its \
         own count of {}",
        store.len(),
        MAX_REORG_DEPTH + MAX_SIDE_BLOCKS + 1
    );
}

/// What a stranger can make a node hold has to be bounded by the node, not by
/// how much the stranger cares to send.
///
/// The blocks here are within the size the rules allow, hang off a block the
/// node already holds, and never win the fork choice. Each costs its maker no
/// proof of work, because a header may claim difficulty one and difficulty one
/// accepts every hash, and no body is ever read: `add_block` stores a losing
/// block and returns, so nothing in it is validated and its size is never
/// compared against `max_block_bytes` either.
///
/// `fork_choice.rs::what_a_node_holds_is_bounded_on_a_chain_younger_than_the_window`
/// measures the other half of this: it offers twenty such blocks, requires the
/// node to go over its ceiling, then moves the branch by one block and
/// requires it back under. That is the sweeps working. What nothing measures
/// is the gap they leave, and nothing in the code tells twenty from twenty
/// thousand: what the node holds is a straight line in what it was sent.
#[test]
fn a_node_stays_under_its_ceiling_while_the_branch_stands_still() {
    // Lowered so the published ceiling is within reach of a test, as the test
    // above it does. Nothing else is contrived.
    let mut rules = params();
    rules.max_block_bytes = 8192;
    let ceiling = ChainStore::held_bytes_ceiling(&rules);

    let (held, entries) = offer_side_blocks(rules, 4096, 12_000);
    let (twice, _) = offer_side_blocks(rules, 4096, 24_000);

    println!(
        "ceiling {ceiling} bytes; 12,000 losing blocks left the node holding {held} bytes \
         in {entries} entries, and 24,000 left it holding {twice}"
    );
    assert!(
        held <= ceiling,
        "a stranger took the node to {held} bytes against a ceiling of {ceiling}, \
         without the node's own branch ever moving"
    );
    assert!(
        twice < held * 2 - held / 4,
        "twice the blocks is twice the memory: {held} against {twice}, so what a \
         stranger can make this node hold is decided by the stranger"
    );
}

/// The same on the count, which is the ceiling `MAX_SIDE_BLOCKS` is written
/// for.
///
/// `forget_unreachable_branches` compares `blocks.len()` against
/// `MAX_REORG_DEPTH + MAX_SIDE_BLOCKS` and uses the answer to decide whether
/// to look. It is a trigger and never a bound: what it then drops is decided
/// by height and by bytes, so small blocks inside the window survive the sweep
/// however many of them there are.
#[test]
fn the_count_of_blocks_a_node_holds_is_bounded_by_the_count_it_is_written_against() {
    let rules = params();
    let limit = cairn_chain::MAX_REORG_DEPTH + 4_096;

    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    let chain = shared.mine_empty(&miner, 31);

    let mut store = ChainStore::new(rules);
    for block in &chain[..30] {
        store.add_block(block.clone(), NOW).unwrap();
    }

    let parent = chain[0].id();
    for nonce in 0..30_000u64 {
        let block = side_block(1, parent, 0, nonce, &wallet(9));
        store.add_block(block, NOW).unwrap();
    }
    let before = store.len();

    // One ordinary block on the branch, which is where every sweep runs.
    store.add_block(chain[30].clone(), NOW).unwrap();
    println!(
        "30,000 losing blocks of {} bytes each: {before} entries before the branch moved \
         and {} after, against a count ceiling of {limit}",
        store.held_bytes() / store.len(),
        store.len()
    );
    assert!(
        store.len() <= limit,
        "the node holds {} block entries against the {limit} the sweep is written \
         against, and the sweep it just ran dropped {}",
        store.len(),
        before.saturating_sub(store.len())
    );
}

/// What `held_bytes` counts has to stand for what a held block costs.
///
/// It counts the bytes a block arrived as. `examples/window.rs` measures what
/// decoding costs on top of that and publishes the factor, and the factor it
/// publishes is 1.4. It is measured on a block filled to the limit, where the
/// notes and the proofs are nearly all of the block and decoding one is close
/// to copying it. That is true, and the question a ceiling needs answered is
/// what the *cheapest* block costs, because the cheapest block is the one a
/// peer sends when it wants the node to hold as many as possible.
///
/// An empty one is 315 bytes on the wire and a fixed several hundred in
/// memory however few bytes it arrived as: a header, an `Option<Block>` with
/// a second header inside it, the accumulated work, the size, the identifier
/// it is filed under, and a heap allocation for each of the four vectors. So
/// the smallest block is where the counted bytes and the real cost part
/// company by the most, and it is the block this ceiling is up against.
///
/// Unlike the two above, nothing here is transient: these are blocks inside
/// the window, so every sweep keeps them, and `MAX_SIDE_BYTES` is the ceiling
/// that is supposed to be holding them.
#[test]
fn what_a_held_block_costs_is_near_what_the_count_says_it_costs() {
    use std::mem::size_of;

    let rules = params();
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    let chain = shared.mine_empty(&miner, 30);

    let mut store = ChainStore::new(rules);
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }

    let parent = chain[0].id();
    let count = 1_000u64;
    for nonce in 0..count {
        let block = side_block(1, parent, 0, nonce, &wallet(9));
        store.add_block(block, NOW).unwrap();
    }
    let counted = store.held_bytes() as u64 / (count + 30);

    // A floor, not a measurement: the fields of the entry the store files a
    // block under, the identifier it is filed under, and the two vectors that
    // have to be on the heap for a block carrying one transfer with one
    // input. Everything left out of it, the map's own spare slots and what an
    // allocator rounds each request up to, only makes the real figure larger.
    let floor = size_of::<Hash32>()
        + size_of::<BlockHeader>()
        + size_of::<Option<Block>>()
        + size_of::<u128>()
        + size_of::<usize>()
        + size_of::<Transfer>()
        + size_of::<Input>();

    // Read from `cairn-chain` rather than restated. It was restated, as a
    // `u64` literal beside a doc saying it is private there, so this file's
    // whole claim was about a number the library could move without it.
    let ceiling = MAX_SIDE_BYTES as u64;

    println!(
        "a block counted at {counted} bytes takes at least {floor} in memory, so the \
         {ceiling} bytes allowed for rival branches is at least {} of memory",
        (ceiling / counted) * floor as u64,
    );
    assert!(
        floor as u64 <= counted * 2,
        "a block counted at {counted} bytes takes at least {floor} in memory, so the \
         {ceiling} bytes this ceiling allows for rival branches is at least {} \
         of memory",
        (ceiling / counted) * floor as u64,
    );
}

/// The milestones a branch keeps are the one thing in a `ChainStore` that
/// grows with the chain, and what they cost is published.
///
/// `Branch::milestones` holds one identifier every `MILESTONE` heights, for
/// ever. The note on `MILESTONE` prices that at "thirty two kilobytes over
/// thirty years, against the gigabyte and a quarter that holding every
/// identifier would take", and `examples/window.rs` closes with "all of it is
/// bounded and none of it grows with the chain".
///
/// Thirty two kilobytes is a thousand and twenty four identifiers. A thousand
/// and twenty four is the spacing, not the count: thirty years of one minute
/// blocks is 15,768,000 blocks and therefore 15,398 milestones. The arithmetic
/// in the sentence is right and it is the arithmetic of a different question.
#[test]
fn what_the_milestones_cost_is_what_the_block_rate_says_they_cost() {
    const SOURCE: &str = include_str!("../src/lib.rs");
    const WINDOW: &str = include_str!("../examples/window.rs");

    let rules = params();
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    // Three milestone boundaries past the window's own start, so the rate can
    // be read off rather than assumed.
    let blocks = shared.mine_empty(&miner, 3 * 1024 + 8);

    let mut store = ChainStore::new(rules);
    for block in &blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }

    let height = store.height().unwrap();
    // Asked of the branch and not worked out from `held_ids`, whose list is
    // what this node can still name rather than what it stores. The two differ
    // by exactly one at every height past the window: the newest milestone is
    // inside it, so it is in that list once and stored all the same, and
    // subtracting the window from the list's length counted it as free.
    let milestones = store.milestone_count();
    assert_eq!(
        milestones as u64,
        height / 1024 + 1,
        "one identifier every thousand and twenty four heights, and one for height zero"
    );

    let thirty_years = 30 * 365 * 24 * 3_600 / rules.target_block_time;
    let kept = thirty_years / 1024 + 1;
    let bytes = kept * 32;
    println!(
        "at height {height} the branch keeps {milestones} milestones. Thirty years of \
         {}-second blocks is {thirty_years} blocks, so {kept} milestones and {bytes} bytes",
        rules.target_block_time
    );
    // Held against what the crate publishes rather than against a number
    // written here, because the figure being wrong was the whole finding: the
    // note said "a thousand and twenty four of these is thirty two kilobytes
    // over thirty years", and a thousand and twenty four is the spacing.
    let published: String = SOURCE.chars().filter(char::is_ascii_digit).collect();
    assert!(
        published.contains(&kept.to_string()) && published.contains(&bytes.to_string()),
        "the milestones cost {bytes} bytes over thirty years, and there are {kept} of \
         them, and the crate does not say either"
    );
    assert!(
        !SOURCE.contains("is thirty two kilobytes over thirty"),
        "the figure that counted the spacing as the count is back"
    );

    // And the example that prints a node's memory names it, because a total
    // that leaves out the one thing that grows is a total answering a
    // different question from the one it is printed under.
    assert!(
        WINDOW.contains("milestones, at thirty years"),
        "the example totals what a node holds without naming the one part of it \
         that grows with the chain"
    );
    assert!(
        !WINDOW.contains("none of it grows with the chain"),
        "the example is back to saying nothing grows with the chain"
    );
}

/// Each identifier a node can name, named once, in the order it says.
///
/// `held_ids` promises the window a reorganisation may reach and one
/// identifier every `MILESTONE` heights **before that**, oldest first. It used
/// to hand back the whole milestone list followed by the whole window, and the
/// window is `HELD_WINDOW` wide where the milestones are `MILESTONE` apart, so
/// one milestone is always inside the window past the first thousand blocks.
/// Measured at height 1536: 1 027 identifiers of which 1 026 are distinct, in
/// the order 0, 1024, 512, 513 and on. Both halves of the promise were false,
/// at every height past the window.
///
/// It had three readers, all tests, and one of them worked out what the branch
/// costs in memory as `held_ids().len() - HELD_WINDOW`, which was right only
/// because of the duplicate: the milestone inside the window is stored, and
/// subtracting the window counted it as free. That reader asks
/// `milestone_count` now, and the two numbers differ by one on purpose.
#[test]
fn the_identifiers_a_node_can_name_are_each_named_once_and_in_order() {
    let rules = params();
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    // Past the window and past three milestone boundaries, so there is both a
    // milestone below the window and a milestone inside it.
    let blocks = shared.mine_empty(&miner, 3 * 1024 + 8);

    let mut store = ChainStore::new(rules);
    for block in &blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }

    let oldest_held = blocks.len() - HELD_WINDOW;
    let spacing = usize::try_from(MILESTONE).unwrap();
    let mut expected: Vec<Hash32> = (0..oldest_held)
        .step_by(spacing)
        .map(|height| blocks[height].id())
        .collect();
    let below = expected.len();
    expected.extend(blocks[oldest_held..].iter().map(Block::id));

    assert!(
        below > 0 && store.milestone_count() > below,
        "the fixture needs a milestone below the window and one inside it, or \
         neither half of this is being asked: {below} below, {} stored",
        store.milestone_count()
    );

    let held = store.held_ids();
    assert_eq!(
        held, expected,
        "the identifiers a node can name are not the window and the milestones \
         before it, oldest first"
    );
    let distinct: std::collections::BTreeSet<Hash32> = held.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        held.len(),
        "an identifier is named twice, so counting this list counts it twice"
    );
}

/// What a rewind can no longer reach is dropped for being out of reach, and
/// not for being the oldest thing off the branch.
///
/// `forget_unreachable_branches` and `forget_oldest_side_blocks` run one after
/// the other and almost always want the same blocks gone, which is why the
/// test above can say that moving either threshold of the first one changes
/// nothing it measures. Everything the first one does for itself was measured
/// by the second: nine mutations of it survived both this package's suite and
/// `cairn-net`'s.
///
/// The input that separates them has to make the first sweep fire while the
/// second has nothing to do, and there is exactly one shape of it. The second
/// is inert while what is held off the branch is at most `MAX_SIDE_BLOCKS`,
/// the branch itself settles at `HELD_WINDOW`, and the first fires above
/// `MAX_REORG_DEPTH + MAX_SIDE_BLOCKS`. Those three numbers leave a single
/// point: `HELD_WINDOW + MAX_SIDE_BLOCKS`, which is one over the trigger,
/// because `HELD_WINDOW` is one more than `MAX_REORG_DEPTH`. So the fixture
/// fills to exactly that and no other count would do.
///
/// Then the only thing that moves is the cutoff. The rivals sit one height
/// above the oldest the branch still names, so two more blocks of the node's
/// own carry the cutoff past them, with the population off the branch
/// unchanged either side of it. Held before, gone after, and the second sweep
/// could not have been what dropped them: it was handed the same count and
/// the same bytes before, and dropped nothing.
///
/// The rival of the tip is the other half. It is off the branch too, and far
/// inside the window, so it distinguishes the sweep that reads the branch
/// *and* the height from one that reads the branch alone.
#[test]
fn what_a_rewind_can_no_longer_reach_is_dropped_before_it_is_oldest() {
    let rules = params();
    let miner = wallet(1);
    let mut shared = Chain::new(rules);
    let chain = shared.mine_empty(&miner, MAX_REORG_DEPTH + 60);

    let mut store = ChainStore::new(rules);
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.height().expect("a chain to stand on");

    // A rival of the tip: off the branch, and as far from the cutoff as this
    // node holds. Nothing about reach can justify dropping it.
    let under_tip = store.id_at(tip - 1).expect("the block below the tip");
    let recent = side_block(tip, under_tip, 0, 1, &wallet(9));
    let recent_id = recent.id();
    assert_eq!(
        store.add_block(recent, NOW).unwrap(),
        Accepted::SideBranch,
        "a rival of the tip was not held aside"
    );

    // One height above the oldest the branch still names, so their parent is
    // on the branch and stays there however often the sweep runs: a rival
    // hanging off a block the sweep is about to drop would be refused for an
    // unknown parent rather than held.
    let oldest = tip - MAX_REORG_DEPTH as u64;
    let at = oldest + 1;
    let parent = store
        .id_at(oldest)
        .expect("the oldest height the branch names");

    let trigger = MAX_REORG_DEPTH + MAX_SIDE_BLOCKS;
    let mut ancient = Vec::new();
    for nonce in 0..MAX_SIDE_BLOCKS as u64 {
        if store.len() > trigger {
            break;
        }
        let block = side_block(at, parent, 0, nonce, &wallet(9));
        let id = block.id();
        assert_eq!(
            store.add_block(block, NOW).unwrap(),
            Accepted::SideBranch,
            "a losing block was not held aside"
        );
        ancient.push(id);
    }
    assert!(
        store.len() > trigger,
        "{} rivals left the node holding {} entries, which is under the {trigger} the \
         first sweep looks at, so this fixture no longer reaches it",
        ancient.len(),
        store.len()
    );

    // What says the second sweep is not the one under measurement. It is
    // handed this population now and drops none of it, and it is handed the
    // same population after the cutoff moves.
    assert!(
        ancient.iter().all(|id| store.contains(id)),
        "the sweep by age has already run, so what the sweep by reach does is \
         hidden behind it again and this fixture separates nothing"
    );
    assert!(
        store.contains(&recent_id),
        "the rival of the tip is already gone"
    );
    let before = store.len();

    // Two, because the cutoff has to pass the height the rivals sit at, and it
    // stands one below them.
    for block in shared.mine_empty(&miner, 2) {
        store.add_block(block, NOW).unwrap();
    }

    assert!(
        ancient.iter().all(|id| !store.contains(id)),
        "the node still holds blocks no rewind it allows can reach: {} entries against \
         {before} before its branch moved by two",
        store.len()
    );
    assert!(
        store.contains(&recent_id),
        "the sweep dropped a rival of the tip, which is inside the window and is what \
         a fork choice would have to switch to"
    );
    assert!(
        store.len() <= HELD_WINDOW + 1,
        "the branch and the one rival still worth holding is {} entries, and the node \
         holds {}",
        HELD_WINDOW + 1,
        store.len()
    );
}

/// Crossing the ceiling is enough on its own to drop what a rewind cannot
/// reach, with nothing at all over the second sweep's limits.
///
/// The test above reaches this sweep by count. `by_count || by_bytes` has two
/// ways in, and a fixture that only ever arrives by the first leaves the
/// second free to be read backwards: with the byte threshold turned into `<`
/// or `==`, a node whose own window has outgrown its ceiling sweeps nothing,
/// and what it is holding is unreachable history it will never let go of.
///
/// Arriving by bytes means holding more than the ceiling while what is held
/// off the branch stays under [`MAX_SIDE_BYTES`], and the ceiling gives the
/// window a full block of room for every height in it. The gap between the
/// two is what `hold` adds on top of the wire form, `HELD_WINDOW` times
/// `HELD_OVERHEAD`: six hundred and twenty seven kilobytes of room, which is
/// what this stands in.
///
/// So the node reads one number differently from the miner that made these
/// blocks: the largest block it will take is the size of the blocks it is
/// actually being given, measured off them rather than written down. Its
/// window then weighs more than the ceiling allows the window, and a little
/// under `MAX_SIDE_BYTES` of rivals carries the total over while the sweep by
/// age still has nothing to do.
#[test]
fn crossing_the_ceiling_is_enough_to_drop_what_a_rewind_cannot_reach() {
    let mining = params();
    let miner = wallet(1);
    let mut shared = Chain::new(mining);
    let chain = shared.mine_empty(&miner, MAX_REORG_DEPTH + 60);

    let widest = chain
        .iter()
        .map(|block| block.encode().len())
        .max()
        .expect("a chain to measure");
    let rules = mining.with_max_block_bytes(widest);
    let ceiling = ChainStore::held_bytes_ceiling(&rules);

    let mut store = ChainStore::new(rules);
    for block in &chain {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.height().expect("a chain to stand on");

    let under_tip = store.id_at(tip - 1).expect("the block below the tip");
    let recent = side_block(tip, under_tip, 0, 1, &wallet(9));
    let recent_id = recent.id();
    assert_eq!(
        store.add_block(recent, NOW).unwrap(),
        Accepted::SideBranch,
        "a rival of the tip was not held aside"
    );

    let oldest = tip - MAX_REORG_DEPTH as u64;
    let at = oldest + 1;
    let parent = store
        .id_at(oldest)
        .expect("the oldest height the branch names");

    // Sixteen kilobytes each, so that filling `MAX_SIDE_BYTES` takes about two
    // thousand of them and the count never becomes the way in.
    let mut ancient = Vec::new();
    for nonce in 0..MAX_SIDE_BLOCKS as u64 {
        if store.held_bytes() > ceiling {
            break;
        }
        let block = side_block(at, parent, 16 * 1024, nonce, &wallet(9));
        let id = block.id();
        assert_eq!(
            store.add_block(block, NOW).unwrap(),
            Accepted::SideBranch,
            "a losing block was not held aside"
        );
        ancient.push(id);
    }
    assert!(
        store.held_bytes() > ceiling,
        "{} rivals left the node at {} bytes against a ceiling of {ceiling}, so this \
         fixture no longer reaches the sweep by size",
        ancient.len(),
        store.held_bytes()
    );

    // What says this arrived by the byte threshold and not by the other one.
    assert!(
        store.len() <= MAX_REORG_DEPTH + MAX_SIDE_BLOCKS,
        "the node holds {} entries, which is over the count this sweep also looks at, \
         so the byte threshold is not what let it in",
        store.len()
    );
    assert!(
        ancient.iter().all(|id| store.contains(id)),
        "the sweep by age has already run, so what the sweep by reach does is hidden \
         behind it again and this fixture separates nothing"
    );
    assert!(
        store.contains(&recent_id),
        "the rival of the tip is already gone"
    );
    let before = store.held_bytes();

    // Two, because the cutoff has to pass the height the rivals sit at, and it
    // stands one below them.
    for block in shared.mine_empty(&miner, 2) {
        store.add_block(block, NOW).unwrap();
    }

    assert!(
        ancient.iter().all(|id| !store.contains(id)),
        "the node is over its ceiling at {} bytes, against {before} before its branch \
         moved by two, and still holds blocks no rewind it allows can reach",
        store.held_bytes()
    );
    assert!(
        store.contains(&recent_id),
        "the sweep dropped a rival of the tip, which is inside the window and is what \
         a fork choice would have to switch to"
    );
    assert!(
        store.held_bytes() <= ceiling,
        "the node holds {} bytes against a ceiling of {ceiling}",
        store.held_bytes()
    );
}

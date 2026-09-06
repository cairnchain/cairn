//! AUDIT: a chain whose difficulty moves, judged block by block.
//!
//! `expected_difficulty` was instrumented across the whole workspace: 120 test
//! binaries, sixty six of which mine. It produced five outcomes, and every one
//! of them demanded of a block exactly what its parent already carried. No
//! block validated in this project had ever been asked to carry a different
//! difficulty from the one below it, so cumulative work was the height, and a
//! fork choice weighing work was indistinguishable from one counting blocks.
//!
//! The reason was one number. `ConsensusParams::testnet` opened at
//! `MIN_DIFFICULTY`, which is the floor, and every fixture spaced its blocks
//! ten times the target apart, which is the direction that wants lowering.
//! There was nowhere to lower to, so the retarget answered with the floor
//! forever. The published networks open at 2^23 and 2^27, where a test cannot
//! afford a second block, so nothing else was reachable either.
//!
//! `ConsensusParams::mineable_network` is the answer, and this file is what
//! establishes that it works: a chain mined fast and then slow, whose
//! difficulty rises above the opening and falls below it, with every block of
//! it going through `connect_block` under the same rules a node applies to a
//! block a stranger sends it.
//!
//! The last test here states the blindness rather than removing it, on
//! purpose. It mines the old fixture shape and asserts that it can produce
//! nothing else, so that the day somebody changes the opening difficulty of
//! `testnet()` this file says what that used to cost.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::pow::{meets_target, work_of, MIN_DIFFICULTY};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, expected_difficulty, mine_block, BlockError, ConsensusParams,
    MINEABLE_DIFFICULTY,
};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 24;
const TARGET: u64 = 60;
/// The first timestamp of every chain here.
const CLOCK: u64 = 1_000;

/// A depth a test can mine to, with the maturity following it the way a real
/// network sets the two.
const BURIAL: u64 = 8;

fn params() -> ConsensusParams {
    ConsensusParams::mineable_network(BURIAL)
}

/// Seconds between blocks, in runs: steady, four times too fast, four times
/// too slow, steady again.
///
/// Chosen by simulating the retarget rather than by trying numbers on a chain.
/// The fast run doubles the difficulty and the slow run halves it back through
/// the opening, and neither runs away: a spacing under the target is a feedback
/// loop, since the retarget raises the difficulty and the fixture goes on
/// producing blocks just as fast, so a long fast run climbs without bound and
/// stops being mineable. Twenty four blocks at half the target is where it was
/// stopped, and it costs about 369 000 hashes for the whole chain.
const SCHEDULE: [(u64, usize); 4] = [
    (TARGET, 12),
    (TARGET / 2, 24),
    (TARGET * 4, 24),
    (TARGET, 12),
];

/// What one block of the chain below was judged at.
struct Judged {
    height: u64,
    difficulty: u64,
    parent_difficulty: Option<u64>,
}

/// Mines a chain at the spacings given, through the ordinary rules.
///
/// Every block is assembled by `assemble_block`, solved, and applied by
/// `connect_block`, so the difficulty each one carries is the one the rules
/// demanded of it and not one this fixture chose.
fn mine_at(params: &ConsensusParams, spacings: &[u64]) -> (LedgerState, Vec<Block>, Vec<Judged>) {
    let miner = SecretKey::from_bytes(&[7; 32]);
    let mut state = LedgerState::new();
    let mut blocks = Vec::with_capacity(spacings.len());
    let mut judged = Vec::with_capacity(spacings.len());
    let mut clock = CLOCK;
    let mut parent_difficulty = None;

    for spacing in spacings {
        let height = state.next_height().unwrap();
        clock += spacing;
        let demanded = expected_difficulty(&state, params);
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), params, clock, 0).unwrap();
        assert_eq!(
            block.header.difficulty, demanded,
            "a producer states what the rules demand"
        );
        let block = mine_block(block, ATTEMPTS).expect("a nonce at this difficulty");
        connect_block(&mut state, &block, params, NOW).unwrap();
        judged.push(Judged {
            height,
            difficulty: block.header.difficulty,
            parent_difficulty,
        });
        parent_difficulty = Some(block.header.difficulty);
        blocks.push(block);
    }
    (state, blocks, judged)
}

fn spacings() -> Vec<u64> {
    SCHEDULE
        .iter()
        .flat_map(|(spacing, count)| std::iter::repeat_n(*spacing, *count))
        .collect()
}

/// The measurement this round exists for, made on a chain rather than argued.
///
/// Before this, the whole record of what `connect_block` was ever asked to
/// judge was `first` and `same`. Here it is asked for a difficulty above its
/// parent's and below it, dozens of times each, and it agrees with the
/// producer every time.
#[test]
fn a_chain_mined_off_schedule_is_judged_at_a_difficulty_that_moves() {
    let params = params();
    let (state, blocks, judged) = mine_at(&params, &spacings());

    let mut up = 0usize;
    let mut down = 0usize;
    let mut same = 0usize;
    for step in &judged {
        match step.parent_difficulty {
            None => {}
            Some(parent) if step.difficulty > parent => up += 1,
            Some(parent) if step.difficulty < parent => down += 1,
            Some(_) => same += 1,
        }
    }
    let difficulties: Vec<u64> = judged.iter().map(|step| step.difficulty).collect();
    let highest = *difficulties.iter().max().unwrap();
    let lowest = *difficulties.iter().min().unwrap();
    let distinct: std::collections::BTreeSet<u64> = difficulties.iter().copied().collect();
    println!(
        "{} blocks judged: {up} demanded more than the parent, {down} less, {same} the same; \
         difficulty ran {lowest}..={highest} over {} distinct values, opening at \
         {MINEABLE_DIFFICULTY}",
        judged.len(),
        distinct.len()
    );

    assert!(
        up > 0,
        "nothing was ever asked to carry more than its parent"
    );
    assert!(
        down > 0,
        "nothing was ever asked to carry less than its parent"
    );
    assert!(
        highest > MINEABLE_DIFFICULTY && lowest < MINEABLE_DIFFICULTY,
        "the chain never left the difficulty it opened at: {lowest}..={highest}"
    );
    assert!(
        distinct.len() > judged.len() / 2,
        "only {} distinct difficulties over {} blocks",
        distinct.len(),
        judged.len()
    );

    // And the point of all of it: work and height have come apart. A fork
    // choice that added up blocks instead of work agreed with this one on
    // every chain this project had ever built.
    let height = state.tip().unwrap().height;
    let work: u128 = difficulties.iter().copied().map(work_of).sum();
    assert_eq!(state.total_work(), work);
    assert!(
        work > u128::from(height) * 2,
        "work {work} against height {height} is still close enough to counting blocks"
    );
    assert_eq!(blocks.len(), judged.len());
}

/// The mutation the old fixtures could not tell from a valid block.
///
/// A block that keeps the difficulty its parent carried is the whole of what a
/// uniform chain produces, so on every chain this project had built it was
/// indistinguishable from an honest one. Here it is a forgery, and the rule
/// says so by name. The block is mined properly at the lower difficulty it
/// claims, so what refuses it is the number and not a missing nonce.
#[test]
fn a_block_that_keeps_its_parents_difficulty_is_refused_where_the_retarget_moved() {
    let params = params();
    // Far enough in that the retarget has been moving for a while.
    let mut spacings = spacings();
    spacings.truncate(24);
    let (mut state, _blocks, judged) = mine_at(&params, &spacings);

    let parent = judged.last().unwrap();
    let demanded = expected_difficulty(&state, &params);
    assert!(
        demanded > parent.difficulty,
        "the fixture has to be somewhere the retarget is actually moving: \
         parent {} and demanded {demanded}",
        parent.difficulty
    );

    let miner = SecretKey::from_bytes(&[7; 32]);
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let clock = state.recent_headers().last().unwrap().timestamp + TARGET;
    let honest =
        assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();

    let mut cheaper = honest;
    cheaper.header.difficulty = parent.difficulty;
    // The work has to follow, or the header would be wrong twice over and the
    // refusal would not be about the difficulty at all.
    cheaper.header.total_work = state
        .total_work()
        .saturating_add(work_of(parent.difficulty));
    let cheaper = mine_block(cheaper, ATTEMPTS).expect("an easier block is easier to mine");
    assert!(
        meets_target(&cheaper.id(), cheaper.header.difficulty),
        "mined at what it claims"
    );

    let refused = connect_block(&mut state, &cheaper, &params, NOW);
    assert!(
        matches!(
            refused,
            Err(BlockError::WrongDifficulty { expected, found })
                if expected == demanded && found == parent.difficulty
        ),
        "a block carrying its parent's difficulty was taken: {refused:?}"
    );
    assert_eq!(
        state.tip().unwrap().height,
        parent.height,
        "and the chain did not move"
    );
}

/// What every fixture in this workspace could produce, and nothing else.
///
/// Kept as a measurement rather than deleted, because it names the blindness.
/// `testnet()` opens on the floor, and the floor is the one difficulty a
/// retarget cannot lower, so a chain built on it answers the same number
/// however slowly its blocks come. Work is then the height, which is what let
/// a fork choice counting blocks pass for one weighing work for the life of
/// the project.
///
/// A spacing *under* the target would have moved it, since the floor stops
/// only the lowering, and that is the one thing no fixture did: every one of
/// them spaced blocks at or above the target, most of them ten times it. So
/// the floor is asserted over the spacings the fixtures actually used rather
/// than over every spacing, which would be false.
#[test]
fn the_shape_every_fixture_had_could_only_ever_be_asked_for_the_floor() {
    let params = ConsensusParams::testnet();
    assert_eq!(params.genesis_difficulty, MIN_DIFFICULTY);

    for spacing in [TARGET, 10 * TARGET] {
        let (state, _blocks, judged) = mine_at(&params, &[spacing; 16]);
        assert!(
            judged.iter().all(|step| step.difficulty == MIN_DIFFICULTY),
            "a chain at spacing {spacing} left the floor, which would be an \
             improvement worth reading this test for"
        );
        assert_eq!(
            state.total_work(),
            u128::from(state.tip().unwrap().height) + 1,
            "work is the height, which is the blindness this round removed"
        );
    }

    // And the direction the floor does not stop, so that the sentence above is
    // a fact about the fixtures rather than a claim about the rule.
    let (_state, _blocks, fast) = mine_at(&params, &[TARGET / 4; 16]);
    assert!(
        fast.iter().any(|step| step.difficulty > MIN_DIFFICULTY),
        "the floor is a floor, not a ceiling"
    );
}

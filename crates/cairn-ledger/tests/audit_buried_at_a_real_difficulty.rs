//! AUDIT: the burial rule, on a chain whose difficulty is not the floor.
//!
//! `HandoverError::BuriedAtTheWrongDifficulty` exists for a named attack, and
//! the sentence beside it says what it cost: before it, "the sender chose those
//! difficulties and could set them all to the floor, so a thousand blocks of
//! burial were a thousand hashes and the phrase buried a thousand deep bought
//! nothing at all".
//!
//! The arm was reachable only in the weakest possible way. Every fixture in
//! this workspace mined on `ConsensusParams::testnet()`, which opens on the
//! floor, so the run and the window under it both sat at difficulty one and the
//! only way to make the rule fire was to shake the recent timestamps until the
//! retarget asked for four instead of one. The forgery the arm is named for
//! was never built: an honest anchor at a difficulty worth something, with the
//! whole burial above it mined for one hash a block.
//!
//! Round eleven built it and could not say what refused it. It came back
//! `NotOnTheWeighedChain`, which is the forest rebuild at the very end of
//! `check_buried`, and the difficulty rule sits at the top of the same loop, so
//! that answer meant the forged forest was wrong rather than that the run was
//! caught. This file settles it: the forest is built the way an append only
//! forest is built, from the honest one below the anchor, so the rebuild has
//! nothing to object to, and the refusal that comes back is the difficulty
//! rule, at the first header of the run.
//!
//! The second half is the part the first cannot answer on its own. A forger
//! does not have to state a difficulty nobody demanded; it can date its blocks
//! far enough apart that the retarget lowers the difficulty for it, and walk
//! the run down to the floor legitimately. That is measured here rather than
//! argued, and what it costs is written down: the hashes it saves, and the
//! chain time it has to spend to save them.

#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::OnceLock;

use cairn_accumulator::forest::Forest;
use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{BlockHeader, HeaderSummary, BLOCK_VERSION};
use cairn_ledger::handover::{check_buried, HandoverError};
use cairn_ledger::note::Note;
use cairn_ledger::pow::{
    median_time_past, meets_target, next_difficulty, MIN_DIFFICULTY, RECENT_HEADERS,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, ConsensusParams, MINEABLE_DIFFICULTY,
};
use cairn_ledger::LedgerState;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 24;
const TARGET: u64 = 60;
/// The clamp `pow.rs` puts on a solve time before the retarget reads it.
const CEILING: u64 = 6 * TARGET;

/// The anchor sits at 175, so the honest chain has to reach it and then some.
/// The extra twenty four are the honest run the control tests use.
const HONEST: usize = 200;
const ANCHOR: usize = 175;
/// The burial the phrase in the docstring is about.
const RUN: usize = 1_024;

/// The burial and the maturity together, the way a network sets them. Nothing
/// here reads either: `check_buried` takes the run it is given. It is set so
/// that the rules these headers are judged by are a network's rules.
const BURIAL: u64 = 1_024;

fn params() -> ConsensusParams {
    ConsensusParams::mineable_network(BURIAL)
}

/// The one honest chain every test here works from.
///
/// Two hundred blocks at 4 096 is about eight hundred thousand hashes, and
/// five tests building their own would be five times that for no reason: none
/// of them changes the chain, they change what is handed over about it.
fn honest() -> &'static Chain {
    static CHAIN: OnceLock<Chain> = OnceLock::new();
    CHAIN.get_or_init(|| Chain::build(1, HONEST))
}

/// One honest chain, with the header forest as it stood at every height.
struct Chain {
    headers: Vec<BlockHeader>,
    forests: Vec<Archive>,
}

impl Chain {
    fn build(seed: u8, count: usize) -> Self {
        let params = params();
        let miner = SecretKey::from_bytes(&[seed; 32]);
        let mut state = LedgerState::new();
        let mut headers = Vec::with_capacity(count);
        let mut forests = Vec::with_capacity(count + 1);
        let mut forest = Archive::new();
        let mut clock = 1_000u64;

        forests.push(forest.clone());
        for _ in 0..count {
            let height = state.next_height().unwrap();
            // On schedule, so the retarget leaves the opening difficulty where
            // it is and the window under the anchor really demands it.
            clock += TARGET;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).expect("a nonce at this difficulty");
            connect_block(&mut state, &block, &params, NOW).unwrap();
            forest.add(header_leaf(&block.header.id()));
            forests.push(forest.clone());
            headers.push(block.header);
        }
        Self { headers, forests }
    }

    /// The forest as it stood before the header at `height`.
    fn before(&self, height: usize) -> Forest {
        self.forests[height].forest().roots_only()
    }
}

fn summaries(headers: &[BlockHeader]) -> Vec<HeaderSummary> {
    headers.iter().map(BlockHeader::summary).collect()
}

/// The last window of honest headers, ending at the anchor.
fn recent(chain: &Chain) -> Vec<BlockHeader> {
    chain.headers[ANCHOR + 1 - RECENT_HEADERS..=ANCHOR].to_vec()
}

/// Finds a nonce for a header the fixture wrote by hand.
fn solve(mut candidate: BlockHeader) -> BlockHeader {
    for nonce in 0..ATTEMPTS {
        candidate.nonce = nonce;
        if meets_target(&candidate.id(), candidate.difficulty) {
            return candidate;
        }
    }
    panic!("no nonce found at difficulty {}", candidate.difficulty);
}

/// A run of headers above the anchor, and the tip they end at.
///
/// `difficulty_of` is asked for the difficulty of each header, given the window
/// as it stands under it, so a forger that states whatever it likes and one
/// that states what the retarget demands are the same construction with one
/// closure changed. Everything else is built the way the rules build it: the
/// forest is the honest one below the anchor with the anchor and then each new
/// header folded in, and each header states the forest it follows.
fn forge<F>(chain: &Chain, count: usize, gap: u64, difficulty_of: F) -> Vec<BlockHeader>
where
    F: Fn(&[HeaderSummary]) -> u64,
{
    let params = params();
    let anchor = chain.headers[ANCHOR];
    let mut forest = chain.before(ANCHOR);
    forest.add(header_leaf(&anchor.id()));

    let mut window = summaries(&recent(chain));
    let mut previous = anchor;
    let mut run = Vec::with_capacity(count);
    let mut clock = anchor.timestamp;

    for _ in 0..count {
        let difficulty = difficulty_of(&window);
        clock += gap;
        let header = solve(BlockHeader {
            version: BLOCK_VERSION,
            network: params.network,
            height: previous.height + 1,
            previous: previous.id(),
            transactions_root: Hash32::ZERO,
            // Never read by `check_buried`: what it checks is the header
            // chain, and a forger writing its own ledger writes its own root.
            state_root: Hash32::from_bytes([0xab; 32]),
            history: forest.commitment(),
            timestamp: clock,
            difficulty,
            total_work: previous.total_work + u128::from(difficulty),
            nonce: 0,
        });
        forest.add(header_leaf(&header.id()));
        window.push(header.summary());
        if window.len() > RECENT_HEADERS {
            window.remove(0);
        }
        previous = header;
        run.push(header);
    }
    run
}

/// The honest run, so that everything refused below is refused for what it is
/// rather than because a real difficulty broke the check.
#[test]
fn an_honest_run_at_a_real_difficulty_ties_the_ledger_to_its_tip() {
    let chain = honest();
    let anchor = chain.headers[ANCHOR];
    assert_eq!(anchor.difficulty, MINEABLE_DIFFICULTY);
    assert_eq!(anchor.total_work, u128::from(MINEABLE_DIFFICULTY) * 176);

    check_buried(
        &anchor,
        chain.headers.last().unwrap(),
        &chain.before(ANCHOR),
        &chain.headers[ANCHOR + 1..],
        &recent(chain),
        &params(),
    )
    .expect("a real chain reaches its own tip");
}

/// The forgery the rule is named for, finished and given a clean answer.
///
/// An honest anchor carrying 4 096 and the work of a hundred and seventy six
/// blocks behind it, and a thousand and twenty four headers above it mined for
/// one hash each. The tip claims 721 920 where the honest chain of the same
/// height claims 4 915 200, so this is not a chain anybody would follow; what
/// is being measured is which rule turns it away, because the sender chooses
/// the run and this is the one thing it must not be able to buy cheaply.
///
/// The forest is built correctly on purpose. Round eleven's attempt came back
/// `NotOnTheWeighedChain`, which is the rebuild at the end of the same loop,
/// and could not say whether the difficulty rule would have caught it or
/// whether the forgery was simply malformed. Here the rebuild has nothing to
/// object to and the refusal is the difficulty rule, at the first header of the
/// run, naming the floor the sender stated and the 4 096 the retarget demanded.
#[test]
fn a_burial_mined_at_the_floor_is_refused_by_the_difficulty_rule_and_not_by_the_forest() {
    let chain = honest();
    let anchor = chain.headers[ANCHOR];
    let run = forge(chain, RUN, TARGET, |_| MIN_DIFFICULTY);
    let tip = *run.last().unwrap();

    assert_eq!(tip.height, 175 + RUN as u64);
    assert_eq!(
        tip.total_work,
        anchor.total_work + RUN as u128,
        "a thousand and twenty four blocks of burial for a thousand and twenty \
         four hashes, which is what the rule exists to stop"
    );
    println!(
        "anchor at {} carrying {} and work {}; a run of {RUN} at the floor \
         brings the tip to work {} against the {} an honest chain of that \
         height would carry",
        anchor.height,
        anchor.difficulty,
        anchor.total_work,
        tip.total_work,
        u128::from(MINEABLE_DIFFICULTY) * (176 + RUN as u128)
    );

    // The forest is the honest one below the anchor with the anchor and every
    // forged header folded in, which is exactly what `check_buried` rebuilds,
    // so the rebuild cannot be what refuses this.
    let rebuilt = {
        let mut forest = chain.before(ANCHOR);
        forest.add(header_leaf(&anchor.id()));
        for header in &run[..run.len() - 1] {
            forest.add(header_leaf(&header.id()));
        }
        forest.commitment()
    };
    assert_eq!(
        tip.history, rebuilt,
        "the tip commits to the forest the receiver rebuilds, less its own \
         leaf, which is the one leaf a tip is not in its own history for"
    );

    let refused = check_buried(
        &anchor,
        &tip,
        &chain.before(ANCHOR),
        &run,
        &recent(chain),
        &params(),
    );
    assert!(
        matches!(
            refused,
            Err(HandoverError::BuriedAtTheWrongDifficulty { at, stated, demanded })
                if at == anchor.height + 1
                    && stated == MIN_DIFFICULTY
                    && demanded == MINEABLE_DIFFICULTY
        ),
        "the difficulty rule was meant to be what stopped this, and it said \
         {refused:?}"
    );
}

/// And what the rule does not stop, measured rather than assumed.
///
/// A forger does not have to state a difficulty nobody demanded. It can date
/// its run far enough apart that the retarget lowers the difficulty for it, one
/// quarter at a time, and reach the floor honestly after six headers. Every
/// header then states exactly what the rules demand of it, and `check_buried`
/// takes the run.
///
/// So what the rule buys is not that a burial is expensive in hashes. It is
/// that a burial cheap in hashes is expensive in time: the retarget only lowers
/// for a timeline that really advanced, each gap counts for at most six times
/// the target, and the run has to be dated across the whole of it. The two
/// numbers this prints are the whole of the answer, and the second one is the
/// defence: a tip that far ahead of the fork cannot be produced at once, the
/// honest chain goes on working through it, and what the sampling weighs is
/// still 721 920 against everything the honest chain did meanwhile.
#[test]
fn a_burial_walked_down_to_the_floor_costs_time_instead_of_hashes() {
    let chain = honest();
    let anchor = chain.headers[ANCHOR];
    let run = forge(chain, RUN, CEILING, |window| {
        next_difficulty(window, TARGET)
    });
    let tip = *run.last().unwrap();

    check_buried(
        &anchor,
        &tip,
        &chain.before(ANCHOR),
        &run,
        &recent(chain),
        &params(),
    )
    .expect("every header states what the retarget demands of it");

    let hashes: u128 = run.iter().map(|h| u128::from(h.difficulty)).sum();
    let steps: Vec<u64> = run[..8].iter().map(|h| h.difficulty).collect();
    let seconds = tip.timestamp - anchor.timestamp;
    println!(
        "a run of {RUN} walked down {steps:?} to the floor: {hashes} hashes \
         against the {} an honest run of that length costs, and {seconds} \
         seconds of chain time, which is {} days",
        u128::from(MINEABLE_DIFFICULTY) * RUN as u128,
        seconds / 86_400
    );
    assert_eq!(steps[0], MINEABLE_DIFFICULTY);
    assert_eq!(run.last().unwrap().difficulty, MIN_DIFFICULTY);
    assert!(
        hashes * 10 < u128::from(MINEABLE_DIFFICULTY) * RUN as u128,
        "the hashes are the part the rule does not buy back"
    );
    assert!(
        seconds >= (RUN as u64) * CEILING,
        "and the time is the part it does: {seconds} seconds over {RUN} blocks"
    );
}

/// A run cannot be dated to suit itself either.
///
/// The median rule is the other half of what makes the timeline above cost
/// something: a forger that wants the retarget to lower the difficulty has to
/// move the timestamps forward, and a forger that wants the blocks to look
/// recent has to move them back, and this is what stops the second. It was
/// unreachable before for the same reason as the difficulty arm, because a run
/// at the floor under a window at the floor is refused for its difficulty first
/// wherever it is dated.
#[test]
fn a_run_dated_before_the_median_of_its_own_window_is_refused() {
    let chain = honest();
    let anchor = chain.headers[ANCHOR];
    let mut run = chain.headers[ANCHOR + 1..].to_vec();

    let window = summaries(&recent(chain));
    let median = median_time_past(&window).unwrap();
    // The difficulty it carries is what the window under it demands, and that
    // window does not include this header, so moving its timestamp leaves the
    // difficulty rule satisfied and reaches the one after it. Re-solved,
    // because a changed header is a changed identifier.
    run[0].timestamp = median;
    run[0] = solve(run[0]);

    let refused = check_buried(
        &anchor,
        chain.headers.last().unwrap(),
        &chain.before(ANCHOR),
        &run,
        &recent(chain),
        &params(),
    );
    assert!(
        matches!(
            refused,
            Err(HandoverError::BuriedOutOfTime { at }) if at == anchor.height + 1
        ),
        "a header dated on the median of its own window was taken: {refused:?}"
    );
}

/// The length of the run is the sender's to choose and the receiver's to check,
/// at a real difficulty like everything else here.
#[test]
fn a_run_that_stops_short_of_the_tip_is_refused_at_a_real_difficulty() {
    let chain = honest();
    let anchor = chain.headers[ANCHOR];
    let full = &chain.headers[ANCHOR + 1..];
    let short = full[..full.len() - 1].to_vec();

    let refused = check_buried(
        &anchor,
        chain.headers.last().unwrap(),
        &chain.before(ANCHOR),
        &short,
        &recent(chain),
        &params(),
    );
    assert!(
        matches!(
            refused,
            Err(HandoverError::BuriedRunWrongLength { given, wanted })
                if given == short.len() as u64 && wanted == full.len() as u64
        ),
        "and said {refused:?}"
    );
}

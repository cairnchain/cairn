//! What a fresh seed costs a forger, which is what the per-tip figure is
//! quoted against.
//!
//! The draw is seeded by the tip's own identifier, so a forger that dislikes
//! its questions finds another tip and asks again. The documents used to say a
//! tip costs the tip's own work, which made grinding a cost measured in the
//! chain's difficulty. The run up to the tip is held to the difficulty the
//! retarget demands, and the retarget lets a run whose stated gaps are long
//! walk that demand down to the floor, where every nonce is a valid tip. So
//! the price of a seed has a floor that is not the chain's difficulty: the
//! walk, paid once, and then the draw each tip seeds.
//!
//! These tests hold the three facts the documents now state: a tip at the
//! floor is weighed and every nonce of it is another draw; the walk is paid
//! once and measured in hours of stated time; and the published figure holds
//! against the grinding budget the documents name.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use cairn_accumulator::forest::ForestProof;
use cairn_accumulator::Archive;
use cairn_ledger::block::{BlockHeader, HeaderSummary, BLOCK_VERSION};
use cairn_ledger::pow::{
    meets_target, next_difficulty, DIFFICULTY_WINDOW, MIN_DIFFICULTY, RECENT_HEADERS,
};
use cairn_ledger::sampling::{
    check_start, draw, levels_of, seed_of, work_before, Sample, SampledStart, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::validation::{mine_header, ConsensusParams};
use cairn_primitives::Hash32;

const ATTEMPTS: u64 = 1 << 24;
const START: u64 = 1_000_000;
/// Blocks stated a second apart, which the retarget answers with the
/// steepest climb it allows.
const CLIMB: usize = 6;
/// Blocks on schedule, over which the difficulty settles.
const PLATEAU: usize = 100;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// The gap the retarget clamps a solve time to, six targets. Stating it on
/// every block walks the demand down as fast as the rule allows.
fn descent_gap() -> u64 {
    6 * params().target_block_time
}

/// A chain of headers, and the forest of everything below its tip.
struct Chain {
    below: Vec<BlockHeader>,
    archive: Archive,
    tip: BlockHeader,
}

fn next(previous: &BlockHeader, history: Hash32, timestamp: u64, difficulty: u64) -> BlockHeader {
    let candidate = BlockHeader {
        version: BLOCK_VERSION,
        network: params().network,
        height: previous.height + 1,
        previous: previous.id(),
        transactions_root: Hash32::ZERO,
        state_root: Hash32::ZERO,
        history,
        timestamp,
        difficulty,
        total_work: previous.total_work + u128::from(difficulty),
        nonce: 0,
    };
    mine_header(candidate, ATTEMPTS).expect("a nonce at this difficulty")
}

fn window(headers: &[BlockHeader]) -> Vec<HeaderSummary> {
    let from = headers.len().saturating_sub(DIFFICULTY_WINDOW + 1);
    headers[from..].iter().map(BlockHeader::summary).collect()
}

/// Climbs, holds, and then walks the retarget's demand down to the floor,
/// every header carrying exactly the difficulty the rules demand of it.
fn a_chain_that_ends_at_the_floor() -> Chain {
    let params = params();
    let mut archive = Archive::new();
    let genesis = mine_header(
        BlockHeader {
            version: BLOCK_VERSION,
            network: params.network,
            height: 0,
            previous: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: archive.forest().commitment(),
            timestamp: START,
            difficulty: MIN_DIFFICULTY,
            total_work: u128::from(MIN_DIFFICULTY),
            nonce: 0,
        },
        ATTEMPTS,
    )
    .unwrap();
    archive.add(header_leaf(&genesis.id())).unwrap();
    let mut below = vec![genesis];

    let mut gaps: Vec<u64> = Vec::new();
    gaps.extend(std::iter::repeat_n(1, CLIMB));
    gaps.extend(std::iter::repeat_n(params.target_block_time, PLATEAU));
    for gap in gaps {
        let previous = *below.last().unwrap();
        let demanded = next_difficulty(&window(&below), params.target_block_time);
        let header = next(
            &previous,
            archive.forest().commitment(),
            previous.timestamp + gap,
            demanded,
        );
        archive.add(header_leaf(&header.id())).unwrap();
        below.push(header);
    }
    loop {
        let previous = *below.last().unwrap();
        let demanded = next_difficulty(&window(&below), params.target_block_time);
        if demanded == MIN_DIFFICULTY {
            break;
        }
        let header = next(
            &previous,
            archive.forest().commitment(),
            previous.timestamp + descent_gap(),
            demanded,
        );
        archive.add(header_leaf(&header.id())).unwrap();
        below.push(header);
    }
    let previous = *below.last().unwrap();
    let tip = next(
        &previous,
        archive.forest().commitment(),
        previous.timestamp + descent_gap(),
        MIN_DIFFICULTY,
    );
    Chain {
        below,
        archive,
        tip,
    }
}

/// The showing an archivist would make of `tip` on this chain.
fn weighing(chain: &Chain, tip: BlockHeader) -> (SampledStart, Vec<u128>) {
    let params = params();
    let wanted = draw(
        seed_of(&tip),
        SAMPLES,
        work_before(&tip),
        levels_of(&tip, &params),
    );
    let samples: Vec<Sample> = wanted
        .iter()
        .map(|value| {
            let found = *chain
                .below
                .iter()
                .find(|header| work_before(header) <= *value && header.total_work > *value)
                .expect("a block spans every drawn value");
            Sample {
                header: found,
                proof: chain.archive.prove_in(found.height, tip.height).unwrap(),
            }
        })
        .collect();
    let pinned = samples.iter().map(|s| s.header.height).max().unwrap();
    let from = usize::try_from(pinned.saturating_sub(DIFFICULTY_WINDOW as u64)).unwrap();
    let parent = tip.height - 1;
    let mut tail = chain.below[from..].to_vec();
    tail.push(tip);
    let start = SampledStart {
        tip,
        tail,
        parent: Some(Sample {
            header: chain.below[usize::try_from(parent).unwrap()],
            proof: chain.archive.prove_in(parent, tip.height).unwrap(),
        }),
        genesis: ForestProof::default(),
        history: chain.archive.forest().roots_only(),
        samples,
    };
    (start, wanted)
}

/// A tip at the difficulty floor is weighed, and every nonce of it is another
/// tip with another draw, for no work beyond the draw itself.
///
/// The documents priced a fresh seed at the tip's own work, and the example
/// that measured grinding rolled nonces at the chain's difficulty. This chain
/// ran at over a thousand and walked the demand down to the floor inside the
/// rules, and its tip was weighed; so were eight more, each a nonce and
/// nothing else. That is the floor under a tip's cost the documents now
/// state, and a rule that changed it would fail here and send whoever made it
/// back to them.
#[test]
fn a_tip_at_the_floor_is_weighed_and_every_nonce_of_it_is_another_draw() {
    let params = params();
    let chain = a_chain_that_ends_at_the_floor();
    let (start, first) = weighing(&chain, chain.tip);
    let now = chain.tip.timestamp;

    let weighed = check_start(&start, now, &params)
        .expect("a chain whose every header carries the difficulty the retarget demanded");
    assert_eq!(weighed.tip, chain.tip.id());
    let pinned = start
        .samples
        .iter()
        .map(|sample| sample.header)
        .max_by_key(|header| header.height)
        .unwrap();
    assert_eq!(chain.tip.difficulty, MIN_DIFFICULTY);
    assert!(
        pinned.difficulty > 1_000,
        "the draw pinned a header at difficulty {}, so the chain never ran above the floor \
         and this shows nothing about a descent",
        pinned.difficulty
    );

    let mut asked = vec![first];
    for nonce in 1..=8u64 {
        let mut tip = chain.tip;
        tip.nonce = nonce;
        assert!(
            meets_target(&tip.id(), tip.difficulty),
            "at the floor every nonce is a tip"
        );
        let (again, questions) = weighing(&chain, tip);
        let weighed = check_start(&again, now, &params).expect("a re-nonced tip is weighed");
        assert_eq!(weighed.tip, tip.id());
        assert!(
            asked.iter().all(|earlier| *earlier != questions),
            "a re-nonced tip drew the same questions"
        );
        asked.push(questions);
    }
}

/// The walk to the floor, from a real difficulty, is paid once and in stated
/// time: hundreds of blocks and days of timestamps at the clamp ceiling.
///
/// The figures the documents quote for it, measured on the shipped retarget
/// from a window on schedule at each difficulty. The work of the walk is a
/// few blocks' worth at the difficulty it starts from, and the time is what a
/// forger who forked deep has anyway.
#[test]
fn the_walk_to_the_floor_is_paid_once_in_hours_of_stated_time() {
    let target = params().target_block_time;
    let mut measured = Vec::new();
    for bits in [30u32, 40] {
        let start = 1u64 << bits;
        let mut recent: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
            .map(|height| HeaderSummary {
                height,
                timestamp: START + height * target,
                difficulty: start,
            })
            .collect();
        let opened = recent.last().unwrap().timestamp;
        let mut blocks = 0u64;
        let mut work: u128 = 0;
        loop {
            let demanded = next_difficulty(&recent, target);
            if demanded == MIN_DIFFICULTY {
                break;
            }
            let last = *recent.last().unwrap();
            recent.push(HeaderSummary {
                height: last.height + 1,
                timestamp: last.timestamp + descent_gap(),
                difficulty: demanded,
            });
            recent.remove(0);
            blocks += 1;
            work += u128::from(demanded);
        }
        let hours = (recent.last().unwrap().timestamp - opened) / 3_600;
        let blocks_worth = work as f64 / start as f64;
        println!(
            "\n  from 2^{bits}: {blocks} blocks, {hours} h of stated time, {blocks_worth:.1} \
             blocks' work at the difficulty it left"
        );
        measured.push((bits, blocks, hours, blocks_worth));
    }
    assert_eq!(
        measured
            .iter()
            .map(|(bits, blocks, hours, _)| (*bits, *blocks, *hours))
            .collect::<Vec<_>>(),
        vec![(30, 611, 61), (40, 826, 82)],
        "the walk to the floor moved, and the specification and `SAMPLES` quote it"
    );
    for (bits, _, _, worth) in measured {
        assert!(
            worth < 30.0,
            "from 2^{bits} the walk cost {worth:.1} blocks' work, which is not the few the \
             documents say"
        );
    }
}

/// The published figure, per tip, against the grinding budget the documents
/// name for it.
///
/// A forger with `g` tips faces `g` times the per-tip chance, and a tip costs
/// the `SAMPLES` hashes of its own draw once the run is at the floor. The
/// inequality `SAMPLES` is set from gives 2^-161.9 a tip at forty per cent, so
/// 2^33 tips, 2^45 hashes, still leave the figure under 2^-128 and 2^34 do
/// not. The staircase the draw really is is worth more per question than the
/// inequality, so this is a floor under the budget and not the budget.
#[test]
fn the_published_figure_holds_against_the_grinding_budget_the_documents_name() {
    let share = 0.40f64;
    let lie = 1.0 - share / (1.0 - share);
    let levels = 15.0f64;
    let count = SAMPLES as f64;
    let per_tip = count * (1.0 - (1.0 / (1.0 - lie)).ln() / levels).ln() / 2f64.ln();
    println!("\n  per tip at forty per cent: 2^{per_tip:.1}");
    assert!(
        (per_tip - -161.9).abs() < 0.05,
        "the per-tip figure is 2^{per_tip:.2}, not the 2^-161.9 the documents quote"
    );

    let draw_bits = count.log2();
    assert!(
        (draw_bits - 12.0).abs() < f64::EPSILON,
        "a draw is 2^12 hashes"
    );
    let budget = 33.0f64;
    assert!(
        per_tip + budget <= -128.0,
        "2^{budget} tips put the figure past 2^-128"
    );
    assert!(
        per_tip + budget + 1.0 > -128.0,
        "the budget the documents name is not the largest the figure allows"
    );
}

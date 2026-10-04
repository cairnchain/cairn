//! What a fresh seed costs a forger, which is what the per-tip figure is
//! quoted against.
//!
//! The draw is seeded by the tip's own identifier, so a forger that dislikes
//! its questions finds another tip and asks again. The documents used to say a
//! tip costs the tip's own work, which made grinding a cost measured in the
//! chain's difficulty. The run up to the tip is held to the difficulty the
//! retarget demands, and the retarget lets a run dated behind its schedule
//! walk that demand down to the floor, a quarter a header, where every nonce
//! is a valid tip. So for a while the price of a seed was the walk, paid once,
//! and then the hashes of the draw each tip seeds.
//!
//! A newcomer now refuses a tip standing more than [`MOST_FALL`] times below
//! the hardest header of its run, from the pinned header up. These tests hold
//! that on chains that were mined: the tip walked to the floor is refused and
//! so is every nonce of it; a forger that lays a cheap stretch where the
//! deepest question lands, so that the pinned header is cheap too, is refused
//! all the same; an honest chain that lost sixteen times its hash rate is still
//! weighed, and one that lost forty eight is not until its run has passed the
//! loss. What the rule is worth in hashes, on testnet-7 and the devnet, is
//! measured in `the_price_of_a_seed.rs`. The walk and the budget the
//! documents quote are held here too.

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
    meets_target, next_difficulty, HALF_LIFE_IN_BLOCKS, MIN_DIFFICULTY, RECENT_HEADERS,
};
use cairn_ledger::sampling::BELOW_THE_PINNED;
use cairn_ledger::sampling::{
    check_start, draw, levels_of, seed_of, work_before, Sample, SampledStart, StartError,
    MOST_FALL, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::validation::{mine_header, ConsensusParams};
use cairn_primitives::Hash32;

const ATTEMPTS: u64 = 1 << 24;
const START: u64 = 1_000_000;
/// Blocks on schedule, which hold the difficulty where it opened.
const PLATEAU: usize = 100;
/// Where the chains below open, and sit until something moves them.
const OPENING: u64 = 4_096;

/// A network that opened when these chains' first blocks are dated, at the
/// difficulty they carry, so the retarget's schedule starts there.
fn params() -> ConsensusParams {
    ConsensusParams {
        opens_at: START,
        genesis_difficulty: OPENING,
        ..ConsensusParams::testnet()
    }
}

/// Two half lives and a target past the last block, after which the schedule
/// asks for a quarter of the difficulty, the most the bound lets one header
/// fall. Stating it on every block walks the demand down as fast as the rule
/// allows.
fn descent_gap() -> u64 {
    let target = params().target_block_time;
    2 * HALF_LIFE_IN_BLOCKS * target + target + 1
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
    let from = headers.len().saturating_sub(RECENT_HEADERS);
    headers[from..].iter().map(BlockHeader::summary).collect()
}

/// What the retarget asks of the header after the last of `recent`.
fn asked_after(recent: &[HeaderSummary]) -> u64 {
    let params = params();
    next_difficulty(
        recent.last().unwrap(),
        params.origin(),
        params.target_block_time,
    )
}

/// Mines a chain header by header, each at exactly the difficulty the
/// retarget demands of it, dated by whatever gap its miner states.
struct Miner {
    below: Vec<BlockHeader>,
    archive: Archive,
}

impl Miner {
    fn opened() -> Self {
        let params = params();
        let difficulty = params.genesis_difficulty;
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
                difficulty,
                total_work: u128::from(difficulty),
                nonce: 0,
            },
            ATTEMPTS,
        )
        .unwrap();
        archive.add(header_leaf(&genesis.id())).unwrap();
        Self {
            below: vec![genesis],
            archive,
        }
    }

    fn demanded(&self) -> u64 {
        asked_after(&window(&self.below))
    }

    fn header(&self, gap: u64) -> BlockHeader {
        let previous = *self.below.last().unwrap();
        next(
            &previous,
            self.archive.forest().commitment(),
            previous.timestamp + gap,
            self.demanded(),
        )
    }

    fn push(&mut self, gap: u64) {
        let header = self.header(gap);
        self.archive.add(header_leaf(&header.id())).unwrap();
        self.below.push(header);
    }

    fn sketch(&self) -> Sketch {
        Sketch {
            recent: window(&self.below),
            work: self.below.last().unwrap().total_work,
        }
    }

    /// Mines the tip on top of everything so far, `gap` after the last.
    fn finish(self, gap: u64) -> Chain {
        let tip = self.header(gap);
        Chain {
            below: self.below,
            archive: self.archive,
            tip,
        }
    }
}

/// The same chain as the retarget sees it, walked without mining, so that a
/// forger can plan a run before paying for it.
#[derive(Clone)]
struct Sketch {
    recent: Vec<HeaderSummary>,
    work: u128,
}

impl Sketch {
    fn demanded(&self) -> u64 {
        asked_after(&self.recent)
    }

    fn step(&mut self, gap: u64) {
        let last = *self.recent.last().unwrap();
        let difficulty = self.demanded();
        self.recent.push(HeaderSummary {
            height: last.height + 1,
            timestamp: last.timestamp + gap,
            difficulty,
        });
        if self.recent.len() > RECENT_HEADERS {
            self.recent.remove(0);
        }
        self.work += u128::from(difficulty);
    }

    /// The gap, of the three a forger steering the retarget would state,
    /// after which the retarget asks nearest to `goal`.
    fn towards(&self, goal: u64) -> u64 {
        let target = params().target_block_time;
        let distance = |gap: &u64| {
            let mut after = self.clone();
            after.step(*gap);
            ((after.demanded() as f64).ln() - (goal as f64).ln()).abs()
        };
        [1, target, descent_gap()]
            .into_iter()
            .min_by(|one, other| distance(one).total_cmp(&distance(other)))
            .unwrap()
    }
}

/// Holds, and then walks the retarget's demand down to the floor, every
/// header carrying exactly the difficulty the rules demand of it.
fn a_chain_that_ends_at_the_floor() -> Chain {
    let mut miner = Miner::opened();
    for _ in 0..PLATEAU {
        miner.push(params().target_block_time);
    }
    while miner.demanded() != MIN_DIFFICULTY {
        miner.push(descent_gap());
    }
    miner.finish(descent_gap())
}

/// Where the forger lays its cheap stretch, and what the run climbs to above
/// it.
const CHEAP: u64 = 64;
const CHEAP_BLOCKS: usize = 256;
/// How far down the forger walks the tip: the walk stops once the retarget
/// asks no more than this, and the tip carries what it then asks, which is
/// within the tie of the cheap stretch and far below the climb above it.
const WALKED_TO: u64 = 8;

/// A forger's answer to a tie on the pinned header alone.
///
/// The deepest question lands just under the band the draw leaves, so the
/// forger lays the headers there at a cheap difficulty, climbs to carry the
/// band, and walks back down to within the fall of the cheap header rather
/// than of anything above it. Every header carries the difficulty the
/// retarget demands of it. The top of the chain is planned before it is mined
/// so that half the work, which is where a chain this short is questioned up
/// to, falls inside the cheap stretch.
fn a_chain_cheap_where_the_deepest_question_lands() -> Chain {
    let target = params().target_block_time;
    let mut miner = Miner::opened();
    for _ in 0..PLATEAU {
        miner.push(target);
    }
    while miner.demanded() > CHEAP {
        let gap = miner.sketch().towards(CHEAP);
        miner.push(gap);
    }
    let stretch_from = miner.below.last().unwrap().total_work;
    for _ in 0..CHEAP_BLOCKS {
        let gap = miner.sketch().towards(CHEAP);
        miner.push(gap);
    }
    let stretch_to = miner.below.last().unwrap().total_work;

    // How long to hold the climb so that half the work before the tip falls
    // in the upper part of the cheap stretch.
    let aim = stretch_from + (stretch_to - stretch_from) * 3 / 4;
    let plan = |held: usize| -> Vec<u64> {
        let mut sketch = miner.sketch();
        let mut gaps = Vec::new();
        for _ in 0..held {
            let gap = sketch.towards(OPENING);
            sketch.step(gap);
            gaps.push(gap);
        }
        while sketch.demanded() > WALKED_TO {
            sketch.step(descent_gap());
            gaps.push(descent_gap());
        }
        gaps
    };
    let before_the_tip = |gaps: &[u64]| -> u128 {
        let mut sketch = miner.sketch();
        for gap in gaps {
            sketch.step(*gap);
        }
        sketch.work
    };
    let gaps = (1..1_000)
        .map(plan)
        .find(|gaps| before_the_tip(gaps) / 2 >= aim)
        .expect("a climb long enough to put half the work in the cheap stretch");
    for gap in gaps {
        miner.push(gap);
    }
    miner.finish(descent_gap())
}

/// An honest chain on schedule at [`OPENING`] whose miners then lose all but
/// `1/loss` of their hash rate, each block taking as long as its difficulty
/// asks of the rate that remains, until the retarget has answered.
fn a_chain_that_lost(loss: u64) -> Chain {
    let target = params().target_block_time;
    let mut miner = Miner::opened();
    for _ in 0..200 {
        miner.push(target);
    }
    let taking = |asked: u64| (target * asked * loss).div_ceil(OPENING);
    for _ in 0..250 {
        let gap = taking(miner.demanded());
        miner.push(gap);
    }
    let gap = taking(miner.demanded());
    miner.finish(gap)
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
    let from = usize::try_from(pinned.saturating_sub(BELOW_THE_PINNED)).unwrap();
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

/// The deepest header a weighing opened, which the run is measured from.
fn pinned_of(start: &SampledStart) -> BlockHeader {
    start
        .samples
        .iter()
        .map(|sample| sample.header)
        .max_by_key(|header| header.height)
        .unwrap()
}

/// A tip walked down to the difficulty floor is refused, and so is every
/// other nonce of it.
///
/// The documents priced a fresh seed at the tip's own work, and the rules let
/// a tip cost one hash: this chain ran at four thousand and walked the demand
/// down to the floor inside the retarget, and its tip was weighed; so
/// were eight more, each a nonce and nothing else, each with a draw of its
/// own. Nothing compared the tip with the run it stands on, so a forger paid
/// for the walk once and then asked for new questions at the price of a
/// hash. The tip now stands more than [`MOST_FALL`] times below the run's
/// hardest header and is refused whatever its nonce.
#[test]
fn a_tip_walked_down_to_the_floor_is_refused_and_so_is_every_nonce_of_it() {
    let params = params();
    let chain = a_chain_that_ends_at_the_floor();
    let now = chain.tip.timestamp;
    assert_eq!(chain.tip.difficulty, MIN_DIFFICULTY);

    let mut asked = Vec::new();
    for nonce in 0..=8u64 {
        let mut tip = chain.tip;
        tip.nonce = nonce;
        assert!(
            meets_target(&tip.id(), tip.difficulty),
            "at the floor every nonce is a tip"
        );
        let (start, questions) = weighing(&chain, tip);
        let pinned = pinned_of(&start);
        // The walk down is six headers of a quarter each, so the deepest
        // question lands in it more often than not; what matters is that it
        // lands on a header more than the fall above the floor.
        assert!(
            pinned.difficulty > MOST_FALL,
            "the draw pinned a header at difficulty {}, within the fall of the floor, so this \
             shows nothing about a descent",
            pinned.difficulty
        );
        let refused = check_start(&start, now, &params);
        assert!(
            matches!(
                refused,
                Err(StartError::TipFellTooFar { stated: MIN_DIFFICULTY, hardest })
                    if hardest >= pinned.difficulty
            ),
            "a tip at the floor under a run pinned at difficulty {} was not refused for its fall: \
             {refused:?}",
            pinned.difficulty
        );
        assert!(
            asked.iter().all(|earlier| *earlier != questions),
            "a re-nonced tip drew the same questions, so this would show nothing about grinding"
        );
        asked.push(questions);
    }
}

/// A forger that makes the pinned header cheap does not take the tip down
/// with it: the tip is held to the hardest header of the run above.
///
/// The obvious rule ties the tip to the pinned header alone, and a forger
/// chooses where its difficulty is low. This chain lays a cheap stretch just
/// where the deepest question lands, climbs out of it to carry the rest of
/// the work, and walks back down to a tip within the fall of the cheap
/// header. Tied to the pinned header, that tip was weighed; measured at
/// testnet-7's difficulty in `the_price_of_a_seed.rs`, it costs a forger two
/// thousand hashes rather than a quarter of a million. Held to the hardest
/// header of the run it is refused, and the draw is ground until it pins the
/// cheap stretch so that the case is the one the rule has to answer.
#[test]
fn a_cheap_pinned_header_does_not_let_the_tip_fall_below_the_run_above_it() {
    let params = params();
    let chain = a_chain_cheap_where_the_deepest_question_lands();
    let now = chain.tip.timestamp;

    let (start, pinned) = (0..64u64)
        .find_map(|nonce| {
            let mut tip = chain.tip;
            tip.nonce = nonce;
            if !meets_target(&tip.id(), tip.difficulty) {
                return None;
            }
            let (start, _) = weighing(&chain, tip);
            let pinned = pinned_of(&start);
            (pinned.difficulty <= 2 * CHEAP).then_some((start, pinned))
        })
        .expect("a tip whose deepest question lands in the cheap stretch");
    let tip = start.tip;
    let hardest = start
        .tail
        .iter()
        .filter(|header| header.height >= pinned.height)
        .map(|header| header.difficulty)
        .max()
        .unwrap();
    assert!(
        pinned.difficulty <= MOST_FALL * tip.difficulty,
        "the tip stands further below the pinned header than the fall allows, so this chain \
         does not tell a tie to the pinned header from a tie to the run"
    );
    assert!(
        hardest > MOST_FALL * tip.difficulty,
        "the run never climbed out of the cheap stretch, so it has nothing to show"
    );

    let refused = check_start(&start, now, &params);
    assert_eq!(
        refused,
        Err(StartError::TipFellTooFar {
            stated: tip.difficulty,
            hardest
        }),
        "a tip within the fall of a cheap pinned header, under a run that climbed far above \
         it, was weighed"
    );
}

/// An honest chain whose miners lost sixteen times their hash rate is still
/// weighed, and one that lost forty eight is refused until its run has
/// passed the loss.
///
/// The tie is a price on the forger and a cost to an honest chain, and this
/// is where the cost stops. Both chains ran on schedule, then each block took
/// as long as its difficulty asked of the rate that was left, and the
/// retarget answered; the draw pins a header from before the loss, so the run
/// carries the old difficulty and the tip the new one. Sixteen is inside the
/// fall with the room the retarget's own noise needs, which
/// `the_price_of_a_seed.rs` measures on chains with random block times; forty
/// eight is past it, and a newcomer reads that chain instead.
#[test]
fn a_chain_that_lost_sixteen_times_its_hash_rate_is_weighed_and_one_that_lost_forty_eight_is_not() {
    let params = params();
    for (loss, weighed) in [(16u64, true), (48, false)] {
        let chain = a_chain_that_lost(loss);
        let (start, _) = weighing(&chain, chain.tip);
        let pinned = pinned_of(&start);
        assert_eq!(
            pinned.difficulty, OPENING,
            "the draw pinned a header after the loss, so the run does not reach back across it"
        );
        let verdict = check_start(&start, chain.tip.timestamp, &params);
        if weighed {
            assert_eq!(
                verdict.map(|weighed| weighed.tip),
                Ok(chain.tip.id()),
                "an honest chain that lost sixteen times its hash rate was not weighed"
            );
        } else {
            assert!(
                matches!(verdict, Err(StartError::TipFellTooFar { .. })),
                "a chain whose tip stands forty eight times below its run was weighed: {verdict:?}"
            );
        }
    }
}

/// The walk to the floor, from a real difficulty, is paid once and in stated
/// time: a handful of headers, each falling by the whole bound, and a half
/// life of timestamps for every halving.
///
/// The figures the documents quote for it, measured on the shipped retarget
/// from a window on schedule at each difficulty. The work of the walk is a
/// block and a third at the difficulty it starts from, the first header and a
/// quarter of each before it, and the time is what a forger who forked deep
/// has anyway. Under the moving average this replaced it was 611 and 826
/// headers, 61 and 82 hours, and up to twenty one blocks' work: the new rule
/// walks down faster and asks less stated time, and neither is what the price
/// of a seed rests on. The walk is still there to be made; the tip it ends on
/// is what a newcomer now refuses, which the first test above holds.
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
        let origin = cairn_ledger::pow::Origin {
            timestamp: START,
            difficulty: start,
        };
        let opened = recent.last().unwrap().timestamp;
        let mut blocks = 0u64;
        let mut work: u128 = 0;
        loop {
            let demanded = next_difficulty(recent.last().unwrap(), origin, target);
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
        vec![(30, 15, 30), (40, 20, 40)],
        "the walk to the floor moved, and the specification and `SAMPLES` quote it"
    );
    for (bits, _, _, worth) in measured {
        assert!(
            worth < 1.5,
            "from 2^{bits} the walk cost {worth:.1} blocks' work, which is not the block and a \
             third the documents say"
        );
    }
}

/// The published figure, per tip, against the grinding budget the documents
/// name for it.
///
/// A forger with `g` tips faces `g` times the per-tip chance. The inequality
/// `SAMPLES` is set from gives 2^-161.9 a tip at forty per cent, so 2^33 tips
/// still leave the figure under 2^-128 and 2^34 do not. What 2^33 tips cost is
/// measured in `the_price_of_a_seed.rs`, since it is the tie that sets it. The
/// staircase the draw really is is worth more per question than the
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

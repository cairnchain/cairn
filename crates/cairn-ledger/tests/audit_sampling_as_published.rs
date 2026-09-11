//! AUDIT: two properties the joining argument states in prose, measured.
//!
//! Both are load-bearing and neither had ever been run. The first is the
//! bound the whole cost argument rests on, which the prose stated twelve times
//! looser than the rule enforces. The second is a bias in the draw that is not
//! a defect to fix but a property to state, and stating it without measuring
//! it is how a figure goes stale.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use cairn_ledger::block::HeaderSummary;
use cairn_ledger::pow::{next_difficulty, DIFFICULTY_WINDOW, MIN_DIFFICULTY};
use cairn_ledger::sampling::{draw, levels_for, SAMPLES, SHALLOWEST};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::Hash32;

const SAMPLING: &str = include_str!("../src/sampling.rs");
const PAPER: &str = include_str!("../../../docs/cairn-whitepaper.html");

/// Thirty years of a block a minute, which is the chain both papers describe.
const THIRTY_YEARS: u64 = 30 * 365 * 24 * 60;

/// What a forger has to wait out, in the papers' own terms: a thousand blocks
/// at the difficulty floor, spaced as tightly as the retarget still allows.
const CHEAP_BLOCKS: u64 = 1_000;

/// The tightest spacing that leaves a chain at the difficulty floor, read off
/// the rule rather than written down.
///
/// The prose used to say the target, and that is what the argument below used
/// to be priced at. At the floor the retarget answers `floor(target / gap)`,
/// which reaches one as soon as the gap passes half the target, so the true
/// answer is 31 seconds and the run costs half the chain time the papers
/// claimed for it. `tests/retarget_timewarp.rs` pins the same boundary against
/// a chain that was mined rather than a window written by hand.
fn cheapest_spacing_at_the_floor(target: u64) -> u64 {
    (1..=target)
        .find(|gap| {
            let window: Vec<HeaderSummary> = (0..=DIFFICULTY_WINDOW as u64)
                .map(|height| HeaderSummary {
                    height,
                    timestamp: 1_000_000 + height * gap,
                    difficulty: MIN_DIFFICULTY,
                })
                .collect();
            next_difficulty(&window, target) == MIN_DIFFICULTY
        })
        .unwrap_or(target)
}

/// The bound the cost argument rests on, and what the prose is allowed to say
/// about it.
///
/// `sampling.rs` said "a day ahead of the reader is refused" and the paper
/// said the same. Both are true, since a day ahead is indeed refused, and both
/// understate the rule by twelve times inside the one paragraph that rule
/// carries. What makes the attack cost real waiting is the gap between the
/// stated span of the cheap blocks and the drift, so quoting the drift twelve
/// times too large quietly gives the argument away.
#[test]
fn the_drift_the_joining_argument_rests_on_is_two_hours() {
    let params = ConsensusParams::testnet();
    assert_eq!(params.max_timestamp_drift, 2 * 60 * 60);
    for network in ["testnet", "testnet-6", "devnet"] {
        assert_eq!(
            ConsensusParams::for_network(network)
                .unwrap()
                .max_timestamp_drift,
            params.max_timestamp_drift,
            "{network} refuses a different future from the one the papers describe"
        );
    }

    let hours = params.max_timestamp_drift / 3_600;
    assert_eq!(hours, 2);
    assert!(
        SAMPLING.contains("refuses a tip more than two hours ahead of its own"),
        "the sampling doc no longer names the drift the rule enforces"
    );
    assert!(
        !SAMPLING.contains("a day ahead of the reader is refused"),
        "the day is back in the sampling doc"
    );
    assert!(
        PAPER.contains("More than two hours"),
        "the paper no longer names the drift the rule enforces"
    );
    assert!(
        !PAPER.contains("A day ahead of the"),
        "the day is back in the paper"
    );

    // And the shape of the argument, so that the two numbers are checked
    // against each other rather than each on its own: the cheap blocks have to
    // span a good deal more stated time than the reader will accept in
    // advance, or a forger waits out nothing.
    //
    // Priced at the spacing the rule actually permits. This used to multiply by
    // the target, which is what the prose said and what no rule demands, and it
    // put the margin at eight drifts where the rule buys four.
    let spacing = cheapest_spacing_at_the_floor(params.target_block_time);
    assert_eq!(spacing, 31, "the floor holds from {spacing} s a block");
    assert!(
        spacing > params.target_block_time / 2,
        "half the target exactly would still ask for twice the floor"
    );

    let stated = CHEAP_BLOCKS * spacing;
    assert!(
        stated > params.max_timestamp_drift * 4,
        "a thousand cheap blocks span {stated} seconds against a drift of {}",
        params.max_timestamp_drift
    );
    assert!(
        stated < params.max_timestamp_drift * 5,
        "the margin is four drifts and a bit, and quoting more of it is how this \
         went wrong the first time"
    );
    assert!(
        !SAMPLING.contains("have to be spaced at the target"),
        "the sampling doc is back to pricing the cheap run at the target"
    );
}

/// Halvings the draw spreads itself over, restated here from the two constants
/// rather than called, so that the shipped function is measured rather than
/// quoted back at itself.
fn restated_levels(blocks: u64) -> u32 {
    let separable = blocks / SHALLOWEST;
    u64::BITS - separable.max(1).leading_zeros()
}

/// The band a drawn work value falls in.
fn band_of(value: u128, total: u128, levels: u32) -> u32 {
    for level in 0..levels {
        let opens = total - (total >> level);
        let closes = total - (total >> (level + 1));
        if value >= opens && value < closes.max(opens + 1) {
            return level;
        }
    }
    levels
}

/// Draws taken for the even-spread measurement below.
///
/// A million puts the noise on one band at a third of a per cent, which is
/// enough to separate an even spread from the 3.9 per cent the four over-drawn
/// levels used to run at.
const DRAWS: usize = 1_000_000;

/// The bias the level draw used to carry, and the shape that carries none.
///
/// `bytes[0] % levels` is not uniform when `levels` does not divide 256. At
/// fourteen levels, which is a thirty year chain, four levels came up 19 times
/// in 256 and ten came up 18. The four were the deep end and the ten the end
/// nearest the tip, so the loss fell exactly where `FlyClient` wants the
/// density: 4096 draws did the work of 4032.
///
/// It was left alone for as long as the draw was left alone, on the grounds
/// that both sides computed the same biased list so nothing disagreed, and
/// that changing which positions a chain is asked about is a change every
/// prover and every newcomer makes on the same day. The level count moving off
/// the tip's height is that change, so the byte went with it.
///
/// The old extraction is written out below and put through the same bound the
/// new one passes, because a test for an even spread that cannot fail on an
/// uneven one measures nothing.
#[test]
fn the_level_draw_leans_on_no_end_of_the_chain() {
    let levels = restated_levels(THIRTY_YEARS);
    assert_eq!(
        levels,
        levels_for(THIRTY_YEARS),
        "the restatement has drifted from the shipped count"
    );
    assert_eq!(
        levels, 14,
        "a thirty year chain spreads over fourteen levels"
    );

    // What the byte cost, in whole numbers, so the figure is not read off a
    // float: 4096 draws, 18 of every 256 byte values per level, 14 levels.
    assert_eq!(256 % levels, 4, "four levels got one extra byte value each");
    let effective = u64::try_from(SAMPLES).unwrap() * 18 * u64::from(levels) / 256;
    assert_eq!(effective, 4_032, "4096 draws did the work of 4032");

    // The real draw, which is what the bound is actually taken over. A million
    // of them puts the noise on one band at a third of a percent, so a bound
    // of one percent separates an even spread from the 3.9 percent the four
    // over-drawn levels used to run at.
    let tip = Hash32::from_bytes([9; 32]);
    let total = u128::from(THIRTY_YEARS);
    let mut landed = vec![0u64; levels as usize + 1];
    for value in draw(tip, DRAWS, total, levels) {
        landed[band_of(value, total, levels) as usize] += 1;
    }
    assert_eq!(
        landed[levels as usize], 0,
        "every draw has to land in a level the halving reaches"
    );

    let uniform = DRAWS as f64 / f64::from(levels);
    for (level, drawn) in landed.iter().take(levels as usize).enumerate() {
        let off = (*drawn as f64 - uniform) / uniform;
        assert!(
            off.abs() < 0.01,
            "level {level} was drawn {:.4} of uniform",
            off + 1.0
        );
    }

    // And the same bound against the extraction that shipped for six networks,
    // rebuilt here from its own description. It fails, which is what makes the
    // paragraph above a measurement.
    let mut old = vec![0u64; levels as usize];
    for index in 0..DRAWS as u64 {
        let mut preimage = Vec::with_capacity(40);
        preimage.extend_from_slice(tip.as_bytes());
        preimage.extend_from_slice(&index.to_le_bytes());
        let bytes =
            cairn_primitives::hash::hash(cairn_primitives::hash::Domain::SamplingSeed, &preimage);
        let level = u32::from(bytes.as_bytes()[0]) % levels;
        old[level as usize] += 1;
    }
    let worst = old
        .iter()
        .map(|drawn| ((*drawn as f64 - uniform) / uniform).abs())
        .fold(0.0f64, f64::max);
    assert!(
        worst > 0.03,
        "the byte the draw used to read was only {:.2} percent off uniform, so          the bound above is not measuring the fix",
        worst * 100.0
    );
    assert!(
        old[0..4].iter().min().unwrap() > old[4..levels as usize].iter().max().unwrap(),
        "the four over-drawn levels have to be the deep ones, or the loss fell          somewhere other than where this reasoning puts it"
    );
}

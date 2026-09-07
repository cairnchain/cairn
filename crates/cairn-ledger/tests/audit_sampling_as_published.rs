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

use cairn_ledger::sampling::{draw, SAMPLES, SHALLOWEST};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::Hash32;

const SAMPLING: &str = include_str!("../src/sampling.rs");
const PAPER: &str = include_str!("../../../docs/cairn-whitepaper.html");

/// Thirty years of a block a minute, which is the chain both papers describe.
const THIRTY_YEARS: u64 = 30 * 365 * 24 * 60;

/// What a forger has to wait out, in the papers' own terms: a thousand blocks
/// at the difficulty floor, spaced at the target because the retarget demands
/// more of them otherwise.
const CHEAP_BLOCKS: u64 = 1_000;

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
    let stated = CHEAP_BLOCKS * params.target_block_time;
    assert!(
        stated > params.max_timestamp_drift * 8,
        "a thousand cheap blocks span {stated} seconds against a drift of {}",
        params.max_timestamp_drift
    );
}

/// Halvings the draw spreads itself over, restated here so the test can name a
/// level without reaching into a private function.
///
/// Checked below against the levels the real draw actually lands on, so this
/// staying in step with `levels_for` is a measurement rather than a promise.
fn levels_for(blocks: u64) -> u32 {
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

/// The bias in the level draw, stated as a property rather than fixed.
///
/// `bytes[0] % levels` is not uniform when `levels` does not divide 256. At
/// fourteen levels, which is a thirty year chain, four levels come up 19 times
/// in 256 and ten come up 18. The four are the deep end and the ten are the
/// end nearest the tip, so the loss falls exactly where `FlyClient` wants the
/// density: 4096 draws do the work of 4032.
///
/// Not fixed, and `draw`'s own doc says why at length. The short of it is that
/// both sides compute the same biased draw so nothing disagrees, that the 43
/// percent the papers hold three points back from was measured through this
/// very draw and so already contains the loss, and that changing which
/// positions a chain is asked about costs a network number.
#[test]
fn the_level_draw_is_biased_towards_the_deep_end_by_this_much() {
    let levels = levels_for(THIRTY_YEARS);
    assert_eq!(
        levels, 14,
        "a thirty year chain spreads over fourteen levels"
    );
    assert_eq!(256 % levels, 4, "four levels get one extra byte value each");

    let over = 19.0 * f64::from(levels) / 256.0;
    let under = 18.0 * f64::from(levels) / 256.0;
    assert!(
        (under - 0.984_375).abs() < 1e-9,
        "under-drawn by 1.5625 percent"
    );
    // In whole numbers, so the published count is not read off a float:
    // 4096 draws, 18 of every 256 byte values per level, 14 levels.
    let effective = u64::try_from(SAMPLES).unwrap() * 18 * u64::from(levels) / 256;
    assert_eq!(effective, 4_032, "4096 draws do the work of 4032");

    // And the real draw, which is what the bound is actually taken over.
    let total = u128::from(THIRTY_YEARS);
    let count = 1_000_000usize;
    let mut seen = vec![0u64; levels as usize + 1];
    for value in draw(Hash32::from_bytes([9; 32]), count, total, THIRTY_YEARS) {
        seen[band_of(value, total, levels) as usize] += 1;
    }
    assert_eq!(
        seen[levels as usize], 0,
        "every draw has to land in a level the halving reaches"
    );

    let uniform = count as f64 / f64::from(levels);
    for (level, drawn) in seen.iter().take(levels as usize).enumerate() {
        let share = *drawn as f64 / uniform;
        let expected = if level < 4 { over } else { under };
        assert!(
            (share - expected).abs() < 0.01,
            "level {level} was drawn {share:.4} of uniform against {expected:.4}"
        );
    }
    assert!(
        seen[0..4].iter().min().unwrap() > seen[4..levels as usize].iter().max().unwrap(),
        "the four over-drawn levels have to be the deep ones, or the loss falls \
         somewhere other than where this reasoning puts it"
    );
}

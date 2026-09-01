//! Audit: the difficulty retarget and the timestamp rules.
//!
//! Every test states a fact about the rules as they stand, so that a claim in
//! the audit report has something that was run behind it.
//!
//! The audit these were written for found a rule that read a solve time as
//! `current - previous` saturated to zero and then clamped into one second at
//! the bottom: a gap that ran forwards was worth up to the ceiling and a gap
//! that ran backwards was worth one second, so a miner could throw its own
//! timestamps forward and keep the difference. The tests that measured that
//! now measure the repaired rule instead, and each one keeps its account of
//! what went wrong, in the past tense. The rule that was replaced is kept in
//! this file as [`as_it_stood`], so that the tables below can be read side by
//! side and the repair means something.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::too_many_lines
)]

use std::fmt::Write as _;

use cairn_crypto::SecretKey;
use cairn_ledger::block::HeaderSummary;
use cairn_ledger::note::Note;
use cairn_ledger::pow::{
    median_time_past, next_difficulty, DIFFICULTY_WINDOW, MEDIAN_TIME_WINDOW, MIN_DIFFICULTY,
    RECENT_HEADERS,
};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, BlockError, ConsensusParams};
use cairn_ledger::LedgerState;

/// Every live network in this repository targets a minute, except devnet.
const TARGET: u64 = 60;

/// The ceiling `pow.rs` clamps a solve time into: `MAX_SOLVETIME_FACTOR` is
/// private, so it is restated here and checked against the code below.
const CEILING: u64 = 6 * TARGET;

/// The most one retarget may move the difficulty, restated here for the same
/// reason as the ceiling and checked against the code below.
const RETARGET_FACTOR: u64 = 4;

/// A retarget rule, so that a simulation can be run against more than one.
type Retarget = fn(&[HeaderSummary], u64) -> u64;

/// Which timeline a solve time is measured against.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Measured {
    /// The rule this audit found: unsigned, saturating, and clamped into one
    /// second at the bottom.
    AsItStood,
    /// Signed and clamped both ways, but against the parent's own claim rather
    /// than against what the retarget counted. This is the obvious repair and
    /// it is not enough; the test that says why is below.
    AgainstTheParent,
}

/// The two rules this file compares [`next_difficulty`] against.
///
/// Neither is a rule any node runs. They are here so that the tables can put a
/// number on what changed, which a table of the new rule alone cannot do.
fn retarget(recent: &[HeaderSummary], target: u64, measured: Measured) -> u64 {
    let Some(last) = recent.last().copied() else {
        return MIN_DIFFICULTY;
    };
    let available = recent.len().saturating_sub(1).min(DIFFICULTY_WINDOW);
    if available == 0 || target == 0 {
        return last.difficulty.max(MIN_DIFFICULTY);
    }
    let window = &recent[recent.len() - (available + 1)..];
    let ceiling = i128::from(target.saturating_mul(6));

    let mut weighted = 0i128;
    let mut total_difficulty = 0u128;
    for (index, pair) in window.windows(2).enumerate() {
        let gap = i128::from(pair[1].timestamp) - i128::from(pair[0].timestamp);
        let solvetime = match measured {
            Measured::AsItStood => gap.max(0).clamp(1, ceiling),
            Measured::AgainstTheParent => gap.clamp(-ceiling, ceiling),
        };
        weighted += (index as i128 + 1) * solvetime;
        total_difficulty += u128::from(pair[1].difficulty);
    }

    let previous = u128::from(last.difficulty).max(1);
    let cap = previous.saturating_mul(u128::from(RETARGET_FACTOR));
    let floor = (previous / u128::from(RETARGET_FACTOR)).max(u128::from(MIN_DIFFICULTY));
    let Ok(measured_time) = u128::try_from(weighted) else {
        return u64::try_from(cap).unwrap_or(u64::MAX).max(MIN_DIFFICULTY);
    };
    if measured_time == 0 {
        return u64::try_from(cap).unwrap_or(u64::MAX).max(MIN_DIFFICULTY);
    }
    let count = available as u128;
    let expected = count * (count + 1) / 2 * u128::from(target);
    let average = (total_difficulty / count).max(1);
    let next = average.saturating_mul(expected) / measured_time;
    u64::try_from(next.clamp(floor, cap))
        .unwrap_or(u64::MAX)
        .max(MIN_DIFFICULTY)
}

/// The rule this audit was written against, before the repair.
fn as_it_stood(recent: &[HeaderSummary], target: u64) -> u64 {
    retarget(recent, target, Measured::AsItStood)
}

/// Signed solve times clamped both ways against the parent's own timestamp.
fn against_the_parent(recent: &[HeaderSummary], target: u64) -> u64 {
    retarget(recent, target, Measured::AgainstTheParent)
}

/// A block draw that does not spread the attacker's blocks evenly.
///
/// Mining is a race nobody schedules, so a miner holding a share of the hash
/// rate holds runs of consecutive blocks with the frequency that share implies.
/// Whether those runs happen decides how much a timestamp rule leaks, so the
/// draw has to be a draw. Seeded, because a test that is different every run
/// is not a test.
struct Draw(u64);

impl Draw {
    fn new() -> Self {
        Self(0x2545_F491_4F6C_DD1D)
    }

    fn next(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A window kept the way `LedgerState` keeps it.
struct Window {
    recent: Vec<HeaderSummary>,
}

impl Window {
    fn new() -> Self {
        Self { recent: Vec::new() }
    }

    fn push(&mut self, height: u64, timestamp: u64, difficulty: u64) {
        self.recent.push(HeaderSummary {
            height,
            timestamp,
            difficulty,
        });
        if self.recent.len() > RECENT_HEADERS {
            self.recent.remove(0);
        }
    }

    fn median(&self) -> Option<u64> {
        median_time_past(&self.recent)
    }

    fn next(&self, target: u64) -> u64 {
        next_difficulty(&self.recent, target)
    }

    fn next_by(&self, target: u64, rule: Retarget) -> u64 {
        rule(&self.recent, target)
    }

    fn last(&self) -> HeaderSummary {
        *self.recent.last().unwrap()
    }
}

/// Fills a window with a chain that ran exactly on schedule.
fn settled(difficulty: u64, target: u64, blocks: u64) -> (Window, u64, u64) {
    let mut window = Window::new();
    let mut timestamp = 1_000_000u64;
    for height in 0..blocks {
        window.push(height, timestamp, difficulty);
        timestamp += target;
    }
    (window, blocks, timestamp)
}

// ---------------------------------------------------------------------------
// 1. What the retarget reads, and the two clamps it applies.
// ---------------------------------------------------------------------------

/// The window is the last `DIFFICULTY_WINDOW` solve times, which needs one
/// more header than that: 91 summaries for 90 gaps. `RECENT_HEADERS` is
/// exactly that, so a node that keeps the window can always apply the rule.
#[test]
fn the_window_is_inclusive_of_the_header_before_it() {
    assert_eq!(RECENT_HEADERS, DIFFICULTY_WINDOW + 1);

    // 91 headers and 92 headers give the same answer: the 92nd from the end
    // is outside the window and cannot influence it.
    let mut ninety_one = Window::new();
    let mut ninety_two = Window::new();
    ninety_two.push(0, 0, 1_000);
    for height in 0..91u64 {
        ninety_one.push(height, 1_000_000 + height * TARGET, 1_000);
        ninety_two.push(height + 1, 1_000_000 + height * TARGET, 1_000);
    }
    assert_eq!(ninety_one.next(TARGET), ninety_two.next(TARGET));

    // And the 91st from the end does influence it: it is one end of the
    // oldest gap. Moving it alone moves the answer.
    let mut moved = Window::new();
    for height in 0..91u64 {
        let timestamp = if height == 0 {
            1_000_000 - CEILING
        } else {
            1_000_000 + height * TARGET
        };
        moved.push(height, timestamp, 1_000);
    }
    assert_ne!(
        moved.next(TARGET),
        ninety_one.next(TARGET),
        "the oldest header in the window is inside it"
    );
}

/// A solve time that runs backwards is worth the time it gives back.
///
/// It used to be worth one second: the gap was read unsigned and saturating, so
/// a spike forward was worth up to the ceiling while the block that undid it
/// was worth almost nothing. That gap between what a lie cost and what the
/// correction returned was the whole of the exploit the rest of this file
/// measures.
#[test]
fn a_backwards_timestamp_is_worth_the_time_it_gives_back() {
    let (mut window, height, timestamp) = settled(1_000, TARGET, 91);

    // A block dated far ahead, then one dated back where it belongs.
    window.push(height, timestamp + 10_000, 1_000);
    let after_the_spike = window.next(TARGET);
    window.push(height + 1, timestamp + TARGET, 1_000);
    let after_the_return = window.next(TARGET);

    // The spike still lowers the difficulty: one clamped gap in the window is
    // one clamped gap, and that much a miner can always do.
    assert!(after_the_spike < 1_000, "the spike lowered the difficulty");

    // The return undoes it. The pair cost the miner that wrote it rather than
    // paying: it gave the window a ceiling and then took a ceiling back, which
    // is less time than the two blocks really took.
    assert!(
        after_the_return >= 1_000,
        "the return did not undo the spike: {after_the_return}"
    );
    assert!(
        after_the_return < 1_100,
        "and it did not overshoot far: {after_the_return}"
    );

    // What the same two blocks did under the rule as it stood: the spike was
    // kept and the return was worth one second, so the difficulty stayed down.
    let stood = window.next_by(TARGET, as_it_stood);
    assert!(
        stood < 1_000,
        "the rule as it stood should have kept the discount, gave {stood}"
    );
}

/// The ceiling on one solve time, and the ceiling on one retarget step, both
/// hold in both directions.
#[test]
fn both_clamps_hold_in_both_directions() {
    // Every gap at or beyond the ceiling counts the same.
    let mut at_ceiling = Window::new();
    let mut far_past_it = Window::new();
    for height in 0..91u64 {
        at_ceiling.push(height, 1_000_000 + height * CEILING, 1_000);
        far_past_it.push(height, 1_000_000 + height * CEILING * 1_000, 1_000);
    }
    assert_eq!(
        at_ceiling.next(TARGET),
        far_past_it.next(TARGET),
        "past the ceiling a longer gap buys nothing"
    );

    // One step down is at most a quarter, one step up at most fourfold.
    let mut flat = Window::new();
    for height in 0..91u64 {
        flat.push(height, 1_000_000, 1_000_000);
    }
    assert_eq!(
        flat.next(TARGET),
        1_000_000 * RETARGET_FACTOR,
        "capped at fourfold"
    );

    let mut stretched = Window::new();
    for height in 0..91u64 {
        stretched.push(height, 1_000_000 + height * 10_000_000, 1_000_000);
    }
    assert_eq!(
        stretched.next(TARGET),
        1_000_000 / RETARGET_FACTOR,
        "floored at a quarter"
    );
}

/// A timestamp thrown anywhere the rules allow is given back by the blocks
/// after it, so where in the window it sits does not matter and what it buys is
/// nothing. The retarget measures a timeline of its own that only moves by what
/// it counted, so the window telescopes to the distance between its two ends.
///
/// Under the rule as it stood the same block was worth a discount that grew the
/// nearer the tip it sat, because the weight on a gap grows towards the tip and
/// the correction that should have cancelled it was worth one second.
#[test]
fn a_lie_anywhere_in_the_window_is_given_back_by_the_blocks_after_it() {
    let on_schedule = {
        let mut window = Window::new();
        for height in 0..91u64 {
            window.push(height, 1_000_000 + height * TARGET, 1_000);
        }
        window
    };
    let honest = on_schedule.next(TARGET);

    // The same chain with one block dated a ceiling and a target early, which
    // is the largest backward step the clamp will read in full.
    let dated_early = |at: u64| {
        let mut window = Window::new();
        for height in 0..91u64 {
            let timestamp = 1_000_000 + height * TARGET;
            let timestamp = if height == at {
                timestamp - CEILING - TARGET
            } else {
                timestamp
            };
            window.push(height, timestamp, 1_000);
        }
        window
    };

    let answers: Vec<u64> = [10u64, 45, 80]
        .iter()
        .map(|at| dated_early(*at).next(TARGET))
        .collect();
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "where the lie sat changed the answer: {answers:?}"
    );
    let moved = answers[0].abs_diff(honest);
    assert!(
        moved * 100 < honest,
        "one block moved the difficulty by {moved} from {honest}"
    );

    let stood: Vec<u64> = [10u64, 45, 80]
        .iter()
        .map(|at| dated_early(*at).next_by(TARGET, as_it_stood))
        .collect();
    assert!(
        stood[0] > stood[1] && stood[1] > stood[2],
        "the rule as it stood should have paid more the nearer the tip: {stood:?}"
    );
    assert!(
        stood[2] * 100 < honest * 94,
        "and paid more than six percent at the tip: {} against {honest}",
        stood[2]
    );
}

/// Nothing in the retarget divides by zero, wraps, or panics at the extremes.
#[test]
fn the_arithmetic_survives_every_degenerate_window() {
    // No history at all.
    assert_eq!(next_difficulty(&[], TARGET), MIN_DIFFICULTY);
    assert_eq!(next_difficulty(&[], 0), MIN_DIFFICULTY);

    // One header: no gap to measure, so the difficulty stands.
    let one = [HeaderSummary {
        height: 0,
        timestamp: 5,
        difficulty: 7,
    }];
    assert_eq!(next_difficulty(&one, TARGET), 7);
    assert_eq!(next_difficulty(&one, 0), 7);

    // Every timestamp identical, at every length from two to the full window.
    for count in 2..=RECENT_HEADERS {
        let flat: Vec<HeaderSummary> = (0..count as u64)
            .map(|height| HeaderSummary {
                height,
                timestamp: 42,
                difficulty: 1_000,
            })
            .collect();
        let next = next_difficulty(&flat, TARGET);
        assert!(
            (MIN_DIFFICULTY..=4_000).contains(&next),
            "{count} identical timestamps gave {next}"
        );
    }

    // Timestamps running backwards the whole way.
    let backwards: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: u64::MAX - height * TARGET,
            difficulty: 1_000,
        })
        .collect();
    assert_eq!(next_difficulty(&backwards, TARGET), 4_000);

    // The largest difficulty representable, with the largest gaps.
    let huge: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: height.saturating_mul(u64::MAX / 128),
            difficulty: u64::MAX,
        })
        .collect();
    let next = next_difficulty(&huge, TARGET);
    assert_eq!(next, u64::MAX / 4, "floored at a quarter of u64::MAX");

    // And the same window with the difficulty already at the floor.
    let floored: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: height.saturating_mul(1_000_000),
            difficulty: MIN_DIFFICULTY,
        })
        .collect();
    assert_eq!(next_difficulty(&floored, TARGET), MIN_DIFFICULTY);

    // A target block time of zero, which no network uses but which the
    // function is handed anyway.
    let steady: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: height * TARGET,
            difficulty: 1_000,
        })
        .collect();
    assert_eq!(next_difficulty(&steady, 0), 1_000);

    // A first retarget on the shortest chain that has one.
    let two = [
        HeaderSummary {
            height: 0,
            timestamp: 0,
            difficulty: 1_000,
        },
        HeaderSummary {
            height: 1,
            timestamp: 0,
            difficulty: 1_000,
        },
    ];
    assert_eq!(next_difficulty(&two, TARGET), 4_000);

    // The rest of these are the windows a signed solve time made reachable.
    // They were unreachable while every gap was clamped up into one second.

    // A window that runs backwards the whole way at exactly the ceiling, and
    // one that runs backwards far faster: both measure less than no time, and
    // the answer to that is the steepest rise, not a division by zero.
    for step in [CEILING, CEILING * 1_000, u64::MAX / 128] {
        let backwards: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
            .map(|height| HeaderSummary {
                height,
                timestamp: u64::MAX - height.saturating_mul(step),
                difficulty: 1_000,
            })
            .collect();
        assert_eq!(next_difficulty(&backwards, TARGET), 4_000, "step {step}");
    }

    // A window that alternates the two extremes: every odd gap as far forward
    // as a timestamp can go, every even one as far back. The pair cancels, so
    // what is left is a window that measured almost nothing.
    let sawtooth: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: if height % 2 == 0 {
                1_000_000
            } else {
                u64::MAX - 1_000_000
            },
            difficulty: 1_000,
        })
        .collect();
    let next = next_difficulty(&sawtooth, TARGET);
    assert!(
        (MIN_DIFFICULTY..=4_000).contains(&next),
        "the sawtooth gave {next}"
    );

    // The same, at the largest difficulty a header can state, so the rise is
    // computed on a number that cannot be multiplied by four.
    let huge_sawtooth: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: if height % 2 == 0 { 0 } else { u64::MAX },
            difficulty: u64::MAX,
        })
        .collect();
    assert_eq!(next_difficulty(&huge_sawtooth, TARGET), u64::MAX);

    // One block dated at the end of time in an otherwise steady window, and
    // one dated at the start of it.
    for outlier in [0u64, u64::MAX] {
        let mut window: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
            .map(|height| HeaderSummary {
                height,
                timestamp: 1_000_000 + height * TARGET,
                difficulty: 1_000,
            })
            .collect();
        window[45].timestamp = outlier;
        let next = next_difficulty(&window, TARGET);
        assert!(
            (250..=4_000).contains(&next),
            "an outlier of {outlier} gave {next}"
        );
    }

    // A window whose timeline runs backwards overall while the difficulty is
    // already at the largest a header can carry: the rise has nowhere to go and
    // must not wrap.
    let capped: Vec<HeaderSummary> = (0..RECENT_HEADERS as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: 1_000_000 - height,
            difficulty: u64::MAX,
        })
        .collect();
    assert_eq!(next_difficulty(&capped, TARGET), u64::MAX);
}

/// Where a chain built under the rule as it stood and one built under the
/// repaired rule part company, which is the whole of what this change costs.
///
/// Nowhere, as long as every gap in the window is between one second and the
/// ceiling: the counted timeline is then the timestamps themselves and neither
/// clamp has anything to do, so the two rules return the same number. What
/// parts them is a window holding a gap of nothing, a gap that runs backwards,
/// or a gap longer than the ceiling with blocks after it to repay it. Any of
/// those and the two demand different difficulties, which makes them different
/// networks from that block on.
#[test]
fn the_two_rules_part_company_only_over_a_strange_timestamp() {
    let steady = |spacing: u64| {
        let mut window = Window::new();
        for height in 0..91u64 {
            window.push(height, 1_000_000 + height * spacing, 1_000);
        }
        window
    };
    for spacing in [1u64, 2, 59, TARGET, 359, CEILING] {
        let window = steady(spacing);
        assert_eq!(
            window.next(TARGET),
            window.next_by(TARGET, as_it_stood),
            "a chain spaced {spacing} s apart"
        );
    }

    // Drawn spacings inside the same range, in case a regular one hides
    // something.
    let mut draw = Draw::new();
    let mut window = Window::new();
    let mut timestamp = 1_000_000u64;
    for height in 0..91u64 {
        window.push(height, timestamp, 1_000);
        timestamp += 1 + (draw.next() * (CEILING - 1) as f64) as u64;
    }
    assert_eq!(window.next(TARGET), window.next_by(TARGET, as_it_stood));

    // And the three gaps that part them, each dropped in the middle of an
    // otherwise steady window. The difficulty is high because a gap of nothing
    // is worth one second to one rule and none to the other, and a difference
    // of one second in ninety needs somewhere to show.
    let with_gap_at_45 = |timestamp_at_45: u64| {
        let mut window = Window::new();
        for height in 0..91u64 {
            let timestamp = if height == 45 {
                timestamp_at_45
            } else {
                1_000_000 + height * TARGET
            };
            window.push(height, timestamp, 1_000_000_000);
        }
        window
    };
    let nothing = 1_000_000 + 44 * TARGET;
    for (name, timestamp) in [
        ("a gap of nothing", nothing),
        ("a gap that runs backwards", nothing - TARGET),
        ("a gap past the ceiling", nothing + CEILING * 4),
    ] {
        let window = with_gap_at_45(timestamp);
        assert_ne!(
            window.next(TARGET),
            window.next_by(TARGET, as_it_stood),
            "{name} should part them"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The exploit: a saw of timestamps that used to hold the difficulty down.
// ---------------------------------------------------------------------------

/// What one run of the attack came to.
struct Run {
    /// The difficulty at the end, as a fraction of where the chain started.
    ratio: f64,
    /// Real seconds a block took over the second half of the run.
    seconds_per_block: f64,
    /// Blocks mined before the difficulty had lost nine tenths of its value,
    /// or `None` if it never did.
    to_a_tenth: Option<usize>,
    /// Real seconds those blocks took.
    seconds_to_a_tenth: Option<f64>,
}

/// How the miner that lies writes its timestamps.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lie {
    /// Every block it finds sits one ceiling ahead of the wall clock, and its
    /// blocks are spread evenly through the chain. This is the saw the audit
    /// measured.
    Saw,
    /// Every block it finds sits one ceiling past the tip it extends, so a run
    /// of blocks it happens to win in a row drags the claimed timeline forward
    /// as fast as the clamp will read, and its blocks are drawn rather than
    /// spread. This is the strongest timestamp strategy found here.
    Greedy,
}

/// A miner holding `share` of the hash rate dates its own blocks forward. Its
/// blocks are valid: they clear the median, and they sit only a ceiling ahead
/// of the wall clock, far inside the two hours the rules allow. Every other
/// block is dated the way `cairn-node`'s miner dates one, which is the wall
/// clock raised to the median plus one.
///
/// The whole feedback loop is here: the difficulty decides the real solve
/// time, the real solve time and the lie together decide what the retarget
/// sees, and the retarget decides the next difficulty.
fn drag(rule: Retarget, lie: Lie, share: f64, blocks: usize, drift: u64) -> Run {
    let start = 1_000_000u64;
    // Total hash rate as difficulty solved per second, so at `start` a block
    // takes exactly the target.
    let rate = start as f64 / TARGET as f64;

    let (mut window, mut height, opened) = settled(start, TARGET, 91);
    let mut clock = opened as f64;
    let mut difficulty = window.next_by(TARGET, rule);

    let mut draw = Draw::new();
    let mut owed = 0.0f64;
    let mut measured_from = 0.0f64;
    let mut measured_blocks = 0usize;
    let sample_from = blocks / 2;
    let mut to_a_tenth = None;
    let mut seconds_to_a_tenth = None;
    let opened_clock = clock;

    for index in 0..blocks {
        // Real time this block took, at the difficulty it actually carries.
        clock += difficulty as f64 / rate;

        let attacker = if lie == Lie::Greedy {
            draw.next() < share
        } else {
            owed += share;
            let won = owed >= 1.0;
            if won {
                owed -= 1.0;
            }
            won
        };

        let earliest = window.median().map_or(0, |median| median + 1);
        let now = clock.round() as u64;
        let honest = now.max(earliest);
        let timestamp = match (attacker, lie) {
            (false, _) => honest,
            (true, Lie::Saw) => honest.saturating_add(CEILING),
            (true, Lie::Greedy) => honest
                .max(window.last().timestamp.saturating_add(CEILING))
                .min(now.saturating_add(drift))
                .max(earliest),
        };

        // A block no node would take yet has to wait for their clocks, which
        // is the only thing that ever holds this back.
        let publishable = timestamp as f64 - drift as f64;
        if publishable > clock {
            clock = publishable;
        }

        if index == sample_from {
            measured_from = clock;
        }
        if index >= sample_from {
            measured_blocks += 1;
        }

        window.push(height, timestamp, difficulty);
        height += 1;
        difficulty = window.next_by(TARGET, rule);

        if to_a_tenth.is_none() && difficulty as f64 <= start as f64 / 10.0 {
            to_a_tenth = Some(index + 1);
            seconds_to_a_tenth = Some(clock - opened_clock);
        }
    }

    Run {
        ratio: window.last().difficulty as f64 / start as f64,
        seconds_per_block: (clock - measured_from) / measured_blocks as f64,
        to_a_tenth,
        seconds_to_a_tenth,
    }
}

/// The shares the tables are taken at.
const SHARES: [f64; 12] = [
    0.02, 0.05, 0.08, 0.10, 0.12, 0.15, 0.17, 0.20, 0.25, 0.33, 0.40, 0.45,
];

/// One table of a rule against a strategy, drawn into `out` and handed back.
///
/// Drawn rather than printed a line at a time because the tests run alongside
/// each other, and two tables printed line by line come out shuffled together.
fn table(out: &mut String, name: &str, rule: Retarget, lie: Lie, drift: u64) -> Vec<(f64, Run)> {
    let _ = writeln!(out, "\n  {name}");
    out.push_str("  share   difficulty   block time   blocks to a tenth   hours\n");
    out.push_str("  -----   ----------   ----------   -----------------   -----\n");
    let mut rows = Vec::new();
    for share in SHARES {
        let run = drag(rule, lie, share, 4_000, drift);
        let _ = writeln!(
            out,
            "  {:>4.0}%   {:>10.4}   {:>8.2} s   {:>17}   {:>5}",
            share * 100.0,
            run.ratio,
            run.seconds_per_block,
            run.to_a_tenth
                .map_or_else(|| "never".to_string(), |n| n.to_string()),
            run.seconds_to_a_tenth
                .map_or_else(|| "-".to_string(), |s| format!("{:.1}", s / 3_600.0)),
        );
        rows.push((share, run));
    }
    rows
}

/// The saw, before and after, at every share up to nearly half the hash rate.
///
/// Under the rule as it stood the difficulty had no equilibrium past about a
/// sixth of the hash rate. A lying block was worth the ceiling to the retarget
/// and cost the block after it one second, so the retarget measured
///
///     share * (ceiling + 1) + (1 - 2 * share) * gap
///
/// seconds a block against a target of sixty, and that exceeds sixty whenever
/// the share exceeds `(target - 1) / ceiling`, about 16.4%, whatever the
/// difficulty. Past that there was no restoring term left and the difficulty
/// ran to the floor.
///
/// Now the correction is worth what it gives back, so the two cancel and the
/// retarget measures the time that really passed. The saw settles the chain
/// where it found it at every share, and the second table is what that looks
/// like.
#[test]
fn the_saw_no_longer_pays_for_itself() {
    let drift = ConsensusParams::testnet().max_timestamp_drift;

    // The control: nobody lies, the chain stays where it is and blocks take
    // the target.
    let honest = drag(next_difficulty, Lie::Saw, 0.0, 3_000, drift);
    assert!(
        (0.95..=1.05).contains(&honest.ratio),
        "an honest chain drifted to {}",
        honest.ratio
    );
    assert!(
        (57.0..=63.0).contains(&honest.seconds_per_block),
        "spacing {}",
        honest.seconds_per_block
    );
    assert!(honest.to_a_tenth.is_none());

    let runaway = (TARGET as f64 - 1.0) / (CEILING as f64);
    let mut out = format!(
        "\n  under the rule as it stood, a lie every {:.1}% of blocks had no equilibrium\n",
        runaway * 100.0
    );
    let before = table(
        &mut out,
        "the rule as it stood",
        as_it_stood,
        Lie::Saw,
        drift,
    );
    let after = table(
        &mut out,
        "the rule as repaired",
        next_difficulty,
        Lie::Saw,
        drift,
    );
    println!("{out}");

    // What the audit found, still reproduced by the rule it was found in.
    for (share, run) in &before {
        assert!(run.ratio < 0.99, "a {share} share moved nothing");
        assert!(
            run.seconds_per_block < TARGET as f64 * 0.99,
            "share {share}: blocks still take {} s",
            run.seconds_per_block
        );
    }
    let stood_at_a_sixth = before
        .iter()
        .find(|(share, _)| *share == 0.17)
        .expect("a sixth is in the table");
    assert!(
        stood_at_a_sixth.1.ratio < 0.01,
        "a sixth used to all but reach the floor, got {}",
        stood_at_a_sixth.1.ratio
    );

    // And what the repair comes to: an equilibrium at every share, within a
    // tenth of where the chain started, and blocks that still take the target.
    for (share, run) in &after {
        assert!(
            (0.90..=1.10).contains(&run.ratio),
            "share {share}: the difficulty settled at {}",
            run.ratio
        );
        assert!(
            (57.0..=63.0).contains(&run.seconds_per_block),
            "share {share}: blocks take {} s",
            run.seconds_per_block
        );
        assert!(
            run.to_a_tenth.is_none(),
            "share {share}: reached a tenth after {:?} blocks",
            run.to_a_tenth
        );
    }
}

/// Where the collapse began, measured rather than reasoned, and that it no
/// longer begins anywhere a minority can reach.
///
/// The search used to stop at about a sixth of the hash rate. It now runs all
/// the way up to a point short of a majority without finding anything, under
/// the greedy strategy as well as the saw. It stops there because a miner that
/// holds half the blocks has no need of a timestamp trick to rewrite a chain.
#[test]
fn no_share_short_of_a_majority_takes_the_difficulty_to_the_floor() {
    let drift = ConsensusParams::testnet().max_timestamp_drift;

    let mut stood_collapses_at = None;
    let mut share = 0.01f64;
    while share < 0.30 {
        if drag(as_it_stood, Lie::Saw, share, 4_000, drift).ratio < 0.001 {
            stood_collapses_at = Some(share);
            break;
        }
        share += 0.005;
    }
    let found = stood_collapses_at.expect("some share collapsed it");
    println!(
        "\n  the difficulty used to reach the floor from {:.1}% of the hash rate up",
        found * 100.0
    );
    assert!(
        (0.12..=0.20).contains(&found),
        "collapse began at {found}, expected about a sixth"
    );

    let mut worst = 1.0f64;
    let mut share = 0.01f64;
    while share < 0.50 {
        for lie in [Lie::Saw, Lie::Greedy] {
            let run = drag(next_difficulty, lie, share, 4_000, drift);
            assert!(
                run.to_a_tenth.is_none(),
                "a {share} share reached a tenth in {:?} blocks",
                run.to_a_tenth
            );
            worst = worst.min(run.seconds_per_block / TARGET as f64);
        }
        share += 0.01;
    }
    println!(
        "  it now reaches it from no share below a half, and the fastest any of\n  \
         them made the chain run is {:.0}% of the target block time\n",
        worst * 100.0
    );
    assert!(worst > 0.90, "blocks came {worst} of the target apart");
}

/// Why the solve time is measured against a timeline of the retarget's own and
/// not against the parent's timestamp.
///
/// Signing the gap and clamping it both ways against the parent is the obvious
/// repair, and it stops the saw dead. It leaves a smaller hole. A miner that
/// wins two blocks in a row can drag the tip a further ceiling ahead with the
/// second, and the honest block that follows can only hand one ceiling back:
/// the difference is time the retarget counted and nobody spent. Runs like that
/// arrive with the frequency a share implies, so the leak is worth about
/// `share^2 * ceiling` seconds a block, and there is a fixed point only while
/// that stays under the target. At a ceiling of six targets that is a share of
/// one over the square root of six, near 41%, which is inside what a minority
/// can hold.
///
/// Measuring against a timeline that only moves by what was counted removes it:
/// the window telescopes to the distance between its two ends, so the run gives
/// back over the blocks that follow exactly what it took.
#[test]
fn clamping_against_the_parent_would_have_left_a_share_of_it() {
    let drift = ConsensusParams::testnet().max_timestamp_drift;
    let mut out = String::new();
    let leaky = table(
        &mut out,
        "signed, clamped against the parent, against a miner that runs",
        against_the_parent,
        Lie::Greedy,
        drift,
    );
    let kept = table(
        &mut out,
        "signed, clamped against the counted timeline, the same miner",
        next_difficulty,
        Lie::Greedy,
        drift,
    );
    println!("{out}");

    let worst_leak = leaky
        .iter()
        .map(|(_, run)| run.ratio)
        .fold(f64::INFINITY, f64::min);
    assert!(
        worst_leak < 0.25,
        "clamping against the parent held up better than expected: {worst_leak}"
    );
    for (share, run) in &kept {
        assert!(
            (0.85..=1.40).contains(&run.ratio),
            "share {share}: the difficulty settled at {}",
            run.ratio
        );
        assert!(
            run.to_a_tenth.is_none(),
            "share {share} reached a tenth in {:?} blocks",
            run.to_a_tenth
        );
    }
}

/// The lie never has to leave the two hour drift the rules allow, and never
/// has to run ahead of the wall clock by more than the ceiling.
#[test]
fn the_lie_stays_well_inside_the_drift_the_rules_allow() {
    let params = ConsensusParams::testnet();
    assert_eq!(params.max_timestamp_drift, 7_200);
    // The whole retarget window is worth less than the drift a single block
    // is allowed. That is the mismatch the attack lives in.
    assert!(
        params.max_timestamp_drift > DIFFICULTY_WINDOW as u64 * params.target_block_time,
        "drift {} vs window {}",
        params.max_timestamp_drift,
        DIFFICULTY_WINDOW as u64 * params.target_block_time
    );
    // The push the attack uses is a twentieth of what it is allowed.
    assert!(CEILING * 20 <= params.max_timestamp_drift);

    let devnet = ConsensusParams::for_network("devnet").unwrap();
    assert_eq!(devnet.target_block_time, 5);
    assert_eq!(devnet.max_timestamp_drift, 7_200);
    assert_eq!(
        devnet.max_timestamp_drift,
        16 * DIFFICULTY_WINDOW as u64 * devnet.target_block_time,
        "on devnet the drift is sixteen whole retarget windows wide"
    );
}

/// A miner that holds every block (a private branch, or a network it has
/// eclipsed) used to drive its own difficulty to the floor with timestamps that
/// advance about a second a block, spending no drift budget and never waiting
/// for anyone's clock: five spikes in every eleven blocks, which is the most
/// the median rule leaves room for, took it from a million to one in under
/// eight hundred blocks.
///
/// It now pays for that instead. The spikes and the low blocks between them
/// cancel, so what the retarget measures is what the timestamps really say,
/// which is a second a block against a target of sixty. That is a chain running
/// sixty times too fast, and the answer to it is a difficulty that climbs by the
/// retarget's cap every block until the miner cannot find one.
///
/// Every timestamp here is checked against the median rule as a node would
/// apply it, so nothing in this branch would be refused: what stops it is the
/// difficulty it is asking for, not the validity of its timestamps.
#[test]
fn a_private_branch_pays_to_lie_about_its_own_solve_times() {
    let start = 1_000_000u64;

    // Five spikes in every eleven blocks. Six would put a spike on the median
    // and the low blocks would stop being valid, so five is the most the
    // median rule leaves room for.
    let pattern = [
        true, false, true, false, true, false, true, false, true, false, false,
    ];
    assert_eq!(pattern.len(), MEDIAN_TIME_WINDOW);
    assert_eq!(pattern.iter().filter(|spike| **spike).count(), 5);

    let branch = |rule: Retarget, blocks: usize| {
        let (mut window, mut height, mut low) = settled(start, TARGET, 91);
        let mut difficulty = window.next_by(TARGET, rule);
        let opened = low;
        let mut refused = 0usize;
        let mut to_floor = None;
        let mut spent = 0u128;
        for index in 0..blocks {
            let spike = pattern[index % pattern.len()];
            low += 1;
            let timestamp = if spike { low + CEILING } else { low };

            // The rule a node would apply, applied here.
            if let Some(median) = window.median() {
                if timestamp <= median {
                    refused += 1;
                }
            }

            spent = spent.saturating_add(u128::from(difficulty));
            window.push(height, timestamp, difficulty);
            height += 1;
            difficulty = window.next_by(TARGET, rule);
            if to_floor.is_none() && difficulty == MIN_DIFFICULTY {
                to_floor = Some(index + 1);
            }
        }
        (difficulty, refused, to_floor, spent, low - opened)
    };

    // What it used to come to.
    let (stood, refused, to_floor, _, advanced) = branch(as_it_stood, 2_000);
    assert_eq!(refused, 0, "every block in this branch clears the median");
    assert_eq!(stood, MIN_DIFFICULTY);
    let blocks = to_floor.unwrap();
    println!("\n  under the rule as it stood a wholly controlled branch reached");
    println!("  difficulty 1 in {blocks} blocks, its timestamps having advanced");
    println!("  {advanced} s in all, about a second a block");
    assert!(blocks < 800, "it took {blocks} blocks");
    // The drift budget is two hours and the whole run never asked for more
    // than a second a block, so no node ever had to wait for its clock.
    assert!(advanced < 2_100);

    // What it comes to now. A hundred blocks is already past anything the
    // branch could pay for, so the run is short.
    let (repaired, refused, to_floor, spent, _) = branch(next_difficulty, 100);
    assert_eq!(refused, 0, "every block in this branch clears the median");
    assert_eq!(to_floor, None, "it never reaches the floor");
    assert!(
        repaired > start,
        "the branch should be paying more, not less: {repaired} against {start}"
    );
    println!("\n  it now asks for difficulty {repaired} after a hundred blocks, having");
    println!(
        "  spent {spent} hashes, which is {} blocks' work at the difficulty it",
        spent / u128::from(start)
    );
    println!("  started from. The saw costs the branch that writes it.\n");
    // Four per block is the retarget's cap, and while the average difficulty in
    // the window lags behind the tip and holds the rise under that, a hundred
    // blocks of it is still five orders of magnitude the branch has to find.
    assert!(
        repaired > start * 100_000,
        "a hundred blocks of the saw only reached {repaired}"
    );
}

/// The only way left to the floor: be slow, and really be slow.
///
/// With no honest miner in the window to pull it back the difficulty still
/// falls as far as the rules allow. What it costs is time. Every gap is at the
/// ceiling, which is six minutes of chain time a block, and a timestamp cannot
/// outrun the wall clock by more than the drift, so a branch that spends chain
/// time this way is spending real time too.
#[test]
fn the_only_way_to_the_floor_is_to_be_slow() {
    let start = 1u64 << 40;
    let (mut window, mut height, mut clock) = settled(start, TARGET, 91);
    let mut difficulty = window.next(TARGET);
    let mut blocks = 0usize;

    // Every gap at the ceiling. This does spend real time (six minutes a
    // block), which is the honest reading of it: the branch really is slow.
    while difficulty > MIN_DIFFICULTY && blocks < 20_000 {
        clock += CEILING;
        window.push(height, clock, difficulty);
        height += 1;
        difficulty = window.next(TARGET);
        blocks += 1;
    }
    assert_eq!(difficulty, MIN_DIFFICULTY);
    let spent = clock - 1_000_000 - 91 * TARGET;
    println!("\n  {blocks} blocks at the ceiling take the difficulty from 2^40 to the floor");
    println!(
        "  and {spent} s of chain time with them, which is {:.1} days that a\n  \
         branch cannot claim without the clock behind it\n",
        spent as f64 / 86_400.0
    );
    // Roughly log base (6/5) of 2^40, since each block sheds a sixth once the
    // window is full: nothing like a fourfold step a block.
    assert!(blocks > 100, "it took {blocks} blocks");
    assert_eq!(spent, blocks as u64 * CEILING);
}

// ---------------------------------------------------------------------------
// 3. Determinism: the one rule that reads the node's own clock.
// ---------------------------------------------------------------------------

fn mined_at(state: &LedgerState, params: &ConsensusParams, timestamp: u64) -> cairn_ledger::Block {
    let miner = SecretKey::from_bytes(&[9u8; 32]);
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block = assemble_block(
        state,
        coinbase,
        Vec::<Transfer>::new(),
        params,
        timestamp,
        0,
    )
    .unwrap();
    cairn_ledger::validation::mine_block(block, 1 << 22).expect("a nonce exists at difficulty one")
}

/// The same block, the same chain, two nodes: one accepts it and one refuses
/// it, and the only difference between them is a second on the wall clock.
#[test]
fn one_second_of_clock_skew_decides_a_block_between_two_honest_nodes() {
    let params = ConsensusParams::testnet();
    let mut fast = LedgerState::archiving();
    let mut slow = LedgerState::archiving();

    let now = 2_000_000_000u64;
    let block = mined_at(&fast, &params, now + params.max_timestamp_drift);

    // The node whose clock says `now` takes it.
    assert!(connect_block(&mut fast, &block, &params, now).is_ok());

    // The node whose clock is one second behind refuses it.
    let refused = connect_block(&mut slow, &block, &params, now - 1).unwrap_err();
    assert!(
        matches!(refused, BlockError::TimestampTooFarAhead { .. }),
        "{refused:?}"
    );

    // And a second later the slow node would take the very same block, which
    // is what makes this refusal a delay rather than a verdict, at this
    // layer. What the layer above does with it is the finding.
    assert!(connect_block(&mut slow, &block, &params, now).is_ok());
}

/// The retarget is arithmetic on the headers and nothing else: no clock, no
/// floating point, no iteration over anything unordered. Signed solve times do
/// not change that, and the windows that exercise them answer the same way
/// every time they are asked.
#[test]
fn the_retarget_answers_the_same_way_every_time_it_is_asked() {
    let mut windows: Vec<Vec<HeaderSummary>> = Vec::new();
    let mut backwards = Vec::new();
    let mut sawtooth = Vec::new();
    let mut steady = Vec::new();
    for height in 0..RECENT_HEADERS as u64 {
        let base = 1_000_000 + height * TARGET;
        steady.push(HeaderSummary {
            height,
            timestamp: base,
            difficulty: 1_000,
        });
        backwards.push(HeaderSummary {
            height,
            timestamp: 1_000_000 - height,
            difficulty: 1_000,
        });
        sawtooth.push(HeaderSummary {
            height,
            timestamp: if height % 2 == 0 {
                base + CEILING
            } else {
                base
            },
            difficulty: 1_000,
        });
    }
    windows.push(steady);
    windows.push(backwards);
    windows.push(sawtooth);

    for window in &windows {
        let first = next_difficulty(window, TARGET);
        for _ in 0..16 {
            assert_eq!(next_difficulty(window, TARGET), first);
        }
        // The same headers behind a different allocation, in case anything
        // ever reads more than the values.
        let copied: Vec<HeaderSummary> = window.iter().rev().rev().copied().collect();
        assert_eq!(next_difficulty(&copied, TARGET), first);
    }
}

/// Everything else the retarget and the timestamp rules read comes from the
/// chain, so two nodes holding the same blocks demand the same difficulty.
#[test]
fn the_demanded_difficulty_reads_only_the_chain() {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::archiving();
    let mut copy = LedgerState::archiving();

    let mut now = 2_000_000_000u64;
    for _ in 0..12 {
        let block = mined_at(&state, &params, now);
        // Connected on two nodes whose clocks are hours apart.
        connect_block(&mut state, &block, &params, now).unwrap();
        connect_block(&mut copy, &block, &params, now + 5_000).unwrap();
        assert_eq!(
            cairn_ledger::validation::expected_difficulty(&state, &params),
            cairn_ledger::validation::expected_difficulty(&copy, &params)
        );
        assert_eq!(state.recent_headers(), copy.recent_headers());
        now += TARGET;
    }
}

// ---------------------------------------------------------------------------
// 4. The lower bound on a timestamp.
// ---------------------------------------------------------------------------

/// Time cannot be moved backwards past the median, and the median is taken
/// over the last eleven headers whatever else is in the window.
#[test]
fn the_median_is_the_only_floor_and_it_is_eleven_blocks_wide() {
    let mut window = Window::new();
    for height in 0..91u64 {
        window.push(height, 1_000_000 + height * TARGET, 1_000);
    }
    // The last eleven are heights 80..=90, timestamps 1_004_800..=1_005_400.
    // The median of eleven is the sixth, at height 85.
    assert_eq!(window.median(), Some(1_000_000 + 85 * TARGET));

    // So a block may be dated five blocks into the past and still stand.
    let five_back = 1_000_000 + 86 * TARGET;
    assert!(five_back > window.median().unwrap());

    // The window the median reads never grows: putting eighty more headers in
    // front of it changes nothing.
    let mut short = Window::new();
    for height in 80..91u64 {
        short.push(height, 1_000_000 + height * TARGET, 1_000);
    }
    assert_eq!(short.median(), window.median());
}

/// The median rule bounds a timestamp from below and nothing bounds it against
/// the parent, so a block may still be dated before the one it extends. That is
/// the rule as it was and the repair does not touch it: what changed is what
/// such a block is worth to the retarget, which is now the time it gives back
/// rather than one second.
#[test]
fn a_block_may_be_dated_before_its_own_parent() {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::archiving();
    let now = 2_000_000_000u64;

    // Eleven blocks a minute apart.
    let mut timestamps = Vec::new();
    for index in 0..11u64 {
        let stamp = now + index * TARGET;
        let block = mined_at(&state, &params, stamp);
        connect_block(&mut state, &block, &params, now + 100_000).unwrap();
        timestamps.push(stamp);
    }

    let median = median_time_past(state.recent_headers()).unwrap();
    let parent = state.tip().unwrap().timestamp;
    assert!(median < parent, "the median lags the parent");

    // A block dated before its parent, above the median, is accepted.
    let backdated = median + 1;
    assert!(backdated < parent);
    let block = mined_at(&state, &params, backdated);
    connect_block(&mut state, &block, &params, now + 100_000).unwrap();
    assert_eq!(state.tip().unwrap().timestamp, backdated);
}

/// The retarget window and the median window have different widths and neither
/// has a boundary the other respects, so nothing special happens at the seam.
#[test]
fn nothing_special_happens_where_the_two_windows_meet() {
    // A chain that is on schedule everywhere except the eleven blocks the
    // median reads. The retarget still reads all ninety gaps.
    let mut window = Window::new();
    for height in 0..80u64 {
        window.push(height, 1_000_000 + height * TARGET, 1_000);
    }
    let before = window.next(TARGET);
    for height in 80..91u64 {
        window.push(height, 1_000_000 + height * TARGET, 1_000);
    }
    let after = window.next(TARGET);
    assert!(
        (900..=1_100).contains(&before) && (900..=1_100).contains(&after),
        "{before} then {after}"
    );
}

// ---------------------------------------------------------------------------
// 5. Work accounting.
// ---------------------------------------------------------------------------

/// Work is the difficulty, so the work a chain accrues per second is its hash
/// rate and nothing else. Halving the difficulty doubles the blocks and buys
/// no work at all: this is why the fork choice is not what the timestamp
/// attack reaches.
#[test]
fn cheap_blocks_buy_blocks_and_never_work() {
    use cairn_ledger::pow::work_of;
    assert_eq!(work_of(1), 1);
    assert_eq!(work_of(u64::MAX), u128::from(u64::MAX));

    // A thousand and twenty four blocks at a quarter of the difficulty carry a
    // quarter of the work, and take a quarter of the time.
    let full: u128 = 1_024 * work_of(1_000_000);
    let cheap: u128 = 1_024 * work_of(250_000);
    assert_eq!(full / cheap, 4);
}

/// Cumulative work cannot overflow a `u128` on any chain this software could
/// produce, and the header rule that adds to it is checked rather than
/// wrapping.
#[test]
fn cumulative_work_cannot_reach_the_end_of_a_u128() {
    use cairn_ledger::pow::work_of;
    // The largest difficulty a header can state, for every block of a chain
    // running for a thousand years at a block a second.
    let blocks: u128 = 1_000 * 365 * 24 * 3_600;
    let most = work_of(u64::MAX).saturating_mul(blocks);
    assert!(most < u128::MAX / 2, "a thousand years cannot fill a u128");

    // And such a difficulty is not reachable anyway: one retarget moves at
    // most fourfold, and the target it implies is a single hash.
    let all_ones = cairn_ledger::pow::target_for(u64::MAX);
    assert_eq!(all_ones[0], 0);
}

/// A header cannot inflate the work it contributes by choosing a strange
/// difficulty: the difficulty it may state is the one the chain demands, and
/// the work it may state is that plus what stood before it.
#[test]
fn a_header_may_not_choose_the_work_it_contributes() {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::archiving();
    let now = 2_000_000_000u64;

    let honest = mined_at(&state, &params, now);
    let demanded = honest.header.difficulty;

    for claimed in [demanded + 1, demanded * 4, u64::MAX, MIN_DIFFICULTY - 1 + 2] {
        if claimed == demanded {
            continue;
        }
        let mut forged = honest.clone();
        forged.header.difficulty = claimed;
        forged.header.total_work = u128::from(claimed);
        let error = connect_block(&mut state, &forged, &params, now).unwrap_err();
        assert!(
            matches!(error, BlockError::WrongDifficulty { .. }),
            "difficulty {claimed} gave {error:?}"
        );
    }

    // And the work field alone, with the honest difficulty.
    for claimed in [0u128, 2, u128::MAX] {
        let mut forged = honest.clone();
        forged.header.total_work = claimed;
        let error = connect_block(&mut state, &forged, &params, now).unwrap_err();
        assert!(
            matches!(error, BlockError::WrongTotalWork { .. }),
            "work {claimed} gave {error:?}"
        );
    }

    connect_block(&mut state, &honest, &params, now).unwrap();
}

// ---------------------------------------------------------------------------
// 6. What a floored difficulty did to the reorganisation window.
// ---------------------------------------------------------------------------

/// A chain sitting at the floor, built for real and checked block by block by
/// the rules themselves.
///
/// The point is what the fork choice is then weighing. Cumulative work is the
/// sum of the difficulties, so a branch at difficulty one adds one unit of work
/// per block however much electricity was behind it. A thousand and twenty four
/// of them (the whole reorganisation window, and the whole depth a handed over
/// ledger is buried under) come to 1024 units of work, which is a thousand
/// hashes. The saw used to buy that: five spikes in every eleven blocks held a
/// chain at the floor while its timestamps advanced a second a block, so the
/// whole window fitted in twenty minutes of chain time, inside the two hour
/// drift, and a node whose clock stood at the fork took the entire branch at
/// once.
///
/// Time is what it costs now. Holding a chain at the floor takes a timeline
/// that really advances a target a block, because the retarget measures what
/// the timestamps say and no longer forgets the half of it that runs backwards.
/// A thousand and twenty four of those is seventeen hours of chain time, and a
/// node refuses anything more than two hours ahead of its own clock, so the
/// branch cannot arrive at once: the attacker has to sit through it in real
/// time while the honest chain keeps working.
#[test]
fn the_reorg_window_can_no_longer_be_had_for_a_thousand_hashes() {
    let params = ConsensusParams::testnet();
    assert_eq!(params.genesis_difficulty, MIN_DIFFICULTY);
    let window = 1_024usize;
    let opened = 2_000_000_000u64;
    let fork_clock = opened;

    // Five spikes in every eleven blocks, and every timestamp raised to clear
    // the median so that nothing here needs the reader to take it on trust:
    // each block goes through `connect_block`, which applies the median rule.
    let pattern = [
        true, false, true, false, true, false, true, false, true, false, false,
    ];

    // First the saw, on headers alone, because it stops being mineable long
    // before the window is full and the point is exactly that.
    let mut headers = Window::new();
    let mut low = opened;
    let mut demanded = MIN_DIFFICULTY;
    let mut mineable = 0usize;
    for index in 0..window {
        let median = headers.median().unwrap_or(0);
        low = low.saturating_add(1).max(median + 1);
        let timestamp = if pattern[index % pattern.len()] {
            low + CEILING
        } else {
            low
        };
        headers.push(index as u64, timestamp, demanded);
        demanded = headers.next(TARGET);
        if demanded == MIN_DIFFICULTY {
            mineable += 1;
        }
    }
    println!("\n  the saw that used to hold a chain at the floor for a whole window");
    println!("  now holds it there for {mineable} blocks, and by the end of the window");
    println!("  it is asking for difficulty {demanded}");
    assert!(
        mineable < window / 4,
        "the saw held the floor for {mineable} of {window} blocks"
    );
    assert!(demanded > 1_000_000, "it only reached {demanded}");

    // And a branch that does keep the floor, built for real. Its timestamps
    // have to advance a target a block, so it runs out of drift long before it
    // runs out of blocks: `connect_block` refuses the rest until the clock
    // catches up.
    let mut state = LedgerState::archiving();
    let mut timestamp = opened;
    let mut accepted = 0usize;
    let refusal = loop {
        if accepted == window {
            break None;
        }
        let block = mined_at(&state, &params, timestamp);
        assert_eq!(
            block.header.difficulty, MIN_DIFFICULTY,
            "a chain on schedule at the floor stays there"
        );
        match connect_block(&mut state, &block, &params, fork_clock) {
            Ok(_) => {
                accepted += 1;
                timestamp += TARGET;
            }
            Err(error) => break Some(error),
        }
    };

    let refusal = refusal.expect("the branch outruns the drift before the window is full");
    assert!(
        matches!(refusal, BlockError::TimestampTooFarAhead { .. }),
        "{refusal:?}"
    );
    let span = window as u64 * TARGET;
    println!(
        "  a branch that keeps the floor honestly spans {span} s, of which a node at\n  \
         the fork takes {accepted} blocks and refuses the rest until its own clock\n  \
         catches up: {:.1} hours of waiting, not twenty minutes\n",
        (span - params.max_timestamp_drift) as f64 / 3_600.0
    );
    assert!(
        accepted <= (params.max_timestamp_drift / TARGET + 1) as usize,
        "it took {accepted} blocks at once"
    );
    assert!(span > params.max_timestamp_drift * 8);
}

/// A brand new network, from its opening difficulty down, driven by a miner
/// that holds every block and dates them with the median-legal saw.
///
/// `testnet-4` opens at 2^27 and `devnet` at 2^23. The opening difficulty is
/// described as what makes the first seconds of a launch fair, and the saw used
/// to take either of them to the floor inside a single drift budget: a few
/// hundred blocks, an hour of chain time, and a few blocks' worth of hashes.
///
/// The same saw now walks the difficulty the other way on both networks, which
/// is the whole of the repair seen from a launch: a network's opening
/// difficulty is no longer something the first miner can write away.
#[test]
fn an_opening_difficulty_no_longer_falls_to_the_saw() {
    let pattern = [
        true, false, true, false, true, false, true, false, true, false, false,
    ];
    for (name, start, target) in [("testnet-4", 1u64 << 27, 60u64), ("devnet", 1 << 23, 5)] {
        let ceiling = target * 6;
        let saw = |rule: Retarget, limit: usize| {
            let mut window = Window::new();
            let opened = 1_000_000u64;
            let mut low = opened;
            let mut difficulty = start;
            let mut blocks = 0usize;
            let mut refused = 0usize;
            let mut spent: u128 = 0;

            while difficulty > MIN_DIFFICULTY && blocks < limit {
                spent = spent.saturating_add(u128::from(difficulty));
                let median = window.median().unwrap_or(0);
                low = low.saturating_add(1).max(median + 1);
                let timestamp = if pattern[blocks % pattern.len()] {
                    low + ceiling
                } else {
                    low
                };
                if timestamp <= median {
                    refused += 1;
                }
                window.push(blocks as u64, timestamp, difficulty);
                difficulty = window.next_by(target, rule);
                blocks += 1;
            }
            (difficulty, blocks, refused, spent, low - opened)
        };

        let (stood, blocks, refused, spent, advanced) = saw(as_it_stood, 20_000);
        assert_eq!(refused, 0, "{name}: every block clears the median");
        assert_eq!(stood, MIN_DIFFICULTY, "{name}");
        println!(
            "\n  {name}: 2^{} used to reach the floor in {blocks} blocks, {advanced} s of chain time",
            start.trailing_zeros(),
        );
        println!(
            "    which cost {spent} hashes, or {} blocks' work at the opening difficulty",
            spent / u128::from(start)
        );
        assert!(advanced < 7_200, "{name}: inside one drift budget");

        let (repaired, blocks, refused, _, _) = saw(next_difficulty, 200);
        assert_eq!(refused, 0, "{name}: every block clears the median");
        assert_eq!(blocks, 200, "{name}: it reached the floor after all");
        assert!(
            repaired > start,
            "{name}: the saw should cost, not save: {repaired} against {start}"
        );
        println!("    it now climbs to {repaired} over two hundred blocks instead");
    }
    println!();
}

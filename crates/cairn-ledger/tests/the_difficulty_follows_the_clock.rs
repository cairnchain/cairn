//! The retarget asks what the schedule says, and a burst cannot freeze the
//! chain.
//!
//! Three kinds of evidence, in order of how little they trust this file.
//!
//! The vectors in `asert_vectors.txt` come from an independent reference,
//! `asert_reference.py` in the testnet-8 wave's audit directory, written with
//! Python's unbounded integers from the specification's steps rather than
//! from this crate's code. They include the cases where this implementation
//! saturates a 128 bit intermediate, so they hold the claim that saturating
//! changes no answer.
//!
//! The properties are what the rule is for, asked over seeded random inputs:
//! on schedule nothing moves, a half life either way is a factor of two, a
//! later parent never asks for more, and the bound and the floor hold.
//!
//! The scenarios are the reason the rule changed. On 2 October 2026 a stranger
//! mined eighty testnet-7 blocks in two minutes with about 1 260 times the
//! honest hash rate, the moving average asked the first honest block after
//! them for 768 times the difficulty before, eleven hours at the honest rate,
//! and the chain was back near normal at block 1385, 33 hours after the
//! burst's last block. The same eighty headers are replayed here, then the
//! same burst at the median floor, a miner of that size staying five minutes
//! and an hour, an honest loss of nine tenths of the hash rate, and
//! departures large enough that the bound binds, each with a seeded generator
//! and the figure the documents publish held with room. Every figure is chain
//! time from the fixture's own solve times, not how long the test ran.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use cairn_ledger::block::HeaderSummary;
use cairn_ledger::pow::{
    median_time_past, next_difficulty, Origin, HALF_LIFE_IN_BLOCKS, MAX_RETARGET_FACTOR,
    MEDIAN_TIME_WINDOW, MIN_DIFFICULTY,
};

/// The vectors, as the reference printed them.
const VECTORS: &str = include_str!("asert_vectors.txt");

/// The specification, which says how many there are.
const SPECIFICATION: &str = include_str!("../../../docs/cairn-specification.md");

/// Every other place that says what a burst that leaves costs the honest
/// chain, by name.
const ELSEWHERE: [(&str, &str); 9] = [
    ("README.md", include_str!("../../../README.md")),
    ("genesis.rs", include_str!("../src/genesis.rs")),
    (
        "the whitepaper",
        include_str!("../../../docs/cairn-whitepaper.md"),
    ),
    (
        "the threat model",
        include_str!("../../../docs/cairn-threat-model.md"),
    ),
    (
        "the open questions",
        include_str!("../../../docs/cairn-open-questions.md"),
    ),
    ("note.rs", include_str!("../src/note.rs")),
    ("pow.rs", include_str!("../src/pow.rs")),
    ("the site", include_str!("../../../web/i18n/en.json")),
    ("le site", include_str!("../../../web/i18n/fr.json")),
];

/// The public networks' block time.
const TARGET: u64 = 60;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit.max(1)
    }

    /// Uniform in (0, 1].
    fn unit(&mut self) -> f64 {
        ((self.next() >> 11) as f64 + 1.0) / (1u64 << 53) as f64
    }

    /// Seconds until a miner of `rate` hashes a second finds a block of
    /// `difficulty`, which is exponential with mean `difficulty / rate`.
    fn solve(&mut self, difficulty: u64, rate: f64) -> f64 {
        -self.unit().ln() * difficulty as f64 / rate
    }
}

#[test]
fn every_vector_the_independent_reference_computed_is_answered_exactly() {
    let mut checked = Vec::new();
    for line in VECTORS.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 8, "a vector line has eight fields: {line}");
        let number = |index: usize| -> u64 { fields[index].parse().unwrap() };
        let origin = Origin {
            timestamp: number(2),
            difficulty: number(3),
        };
        let parent = HeaderSummary {
            height: number(4),
            timestamp: number(5),
            difficulty: number(6),
        };
        assert_eq!(
            next_difficulty(&parent, origin, number(1)),
            number(7),
            "vector {}",
            fields[0]
        );
        checked.push(fields[0]);
    }
    // A table that failed to load would pass every line of it, so the count
    // and the cases the specification's table quotes are asked by name. The
    // count is the one the specification states, read off its sentence: it
    // said 52 of a file that holds 50, and a check of at least fifty agreed
    // with both.
    let stated = SPECIFICATION
        .split_once("asert_vectors.txt` holds ")
        .and_then(|(_, after)| after.split_once(" of them"))
        .map(|(count, _)| count.parse::<usize>().unwrap())
        .expect("the specification says how many vectors the file holds");
    assert_eq!(
        checked.len(),
        stated,
        "the file holds {} vectors and the specification says {stated}",
        checked.len()
    );
    for name in [
        "block-one",
        "tau-ahead",
        "tau-behind",
        "clamp-up",
        "clamp-down",
        "floor-from-two",
        "saturate-ceiling",
        "far-ahead-max",
        "neg-round-1",
        "height-2^62",
        "target-zero",
    ] {
        assert!(checked.contains(&name), "the table lost {name}");
    }
}

/// On schedule the answer is the first block's difficulty, a half life
/// ahead it is exactly twice that and a half life behind exactly half, at any
/// height, from any origin, on any block time.
#[test]
fn the_schedule_is_unchanged_on_time_and_a_half_life_is_a_factor_of_two() {
    let mut rng = Rng(0x0A5E_2026_1003_0001);
    for _ in 0..20_000 {
        let target = [1u64, 5, 60, 600][rng.below(4) as usize];
        let tau = target * HALF_LIFE_IN_BLOCKS;
        let start = rng.below(1 << 40);
        let first = [
            1u64,
            2,
            4_096,
            1 << 23,
            1 << 27,
            1 << 40,
            rng.below(1 << 62) + 1,
        ][rng.below(7) as usize];
        let origin = Origin {
            timestamp: start,
            difficulty: first,
        };
        let height = rng.below(1 << 30);
        let on_time = start + target * height;
        let parent = |timestamp: u64| HeaderSummary {
            height,
            timestamp,
            difficulty: first,
        };
        assert_eq!(next_difficulty(&parent(on_time), origin, target), first);
        assert_eq!(
            next_difficulty(&parent(on_time + tau), origin, target),
            (first / 2).max(MIN_DIFFICULTY)
        );
        if on_time >= tau {
            assert_eq!(
                next_difficulty(&parent(on_time - tau), origin, target),
                2 * first
            );
        }
    }
}

/// A later parent never asks for more, and every answer is within the bound
/// of its parent and above the floor, whatever the parent says.
#[test]
fn a_later_parent_never_asks_for_more_and_the_bound_always_holds() {
    let mut rng = Rng(0x0A5E_2026_1003_0002);
    for _ in 0..20_000 {
        let target = [1u64, 5, 60, 600, 86_400][rng.below(5) as usize];
        let tau = target * HALF_LIFE_IN_BLOCKS;
        let origin = Origin {
            timestamp: rng.below(1 << 40),
            difficulty: rng.next().max(1),
        };
        let height = rng.below(1 << 32);
        let difficulty = [0, 1, u64::MAX, rng.next()][rng.below(4) as usize];
        let on_time = origin.timestamp + target * height;
        let earlier = on_time.saturating_sub(10 * tau) + rng.below(20 * tau);
        let later = earlier + rng.below(3 * tau);
        let at = |timestamp: u64| HeaderSummary {
            height,
            timestamp,
            difficulty,
        };
        let first = next_difficulty(&at(earlier), origin, target);
        let second = next_difficulty(&at(later), origin, target);
        assert!(first >= second, "{earlier} -> {first}, {later} -> {second}");

        let parent = u128::from(difficulty.max(MIN_DIFFICULTY));
        let floor = (parent / MAX_RETARGET_FACTOR).max(u128::from(MIN_DIFFICULTY));
        let cap = (parent * MAX_RETARGET_FACTOR).min(u128::from(u64::MAX));
        for answer in [first, second] {
            assert!(
                (floor..=cap).contains(&u128::from(answer)),
                "{difficulty} -> {answer}"
            );
        }
    }
}

/// The intruder's eighty blocks of 2 October, as they were stamped: seconds
/// after block 1195, which was dated 1 790 918 209 at difficulty 291 178 580.
/// From the explorer's API, in the testnet-7 audit's `headers.json`.
const INTRUDER: [u64; 80] = [
    17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20,
    21, 21, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 44,
    44, 44, 44, 44, 44, 45, 45, 45, 45, 45, 45, 117, 117, 117, 118, 120, 120, 121, 121, 122, 122,
    123, 123, 126, 128, 131, 134, 135, 137, 139, 144, 144,
];

/// The honest miner's rate before the burst, hashes a second, measured over
/// blocks 1000 to 1195.
const HONEST: f64 = 5_464_575.0;

/// The eighty headers themselves, put to the new rule.
///
/// The schedule is placed so that block 1195 stands exactly on it at the
/// difficulty it really carried, which is the honest chain in balance. The
/// moving average asked 223 570 119 402 of block 1276, 768 times block 1195's
/// and about eleven hours at the honest rate, and block 1385 was the first
/// after the burst asked less than twice what block 1195 carried, 33 hours
/// after the burst's last block. This asks what eighty blocks stated four
/// thousand six hundred and fifty six seconds ahead of the schedule are worth:
/// two and a half times, about two and a half minutes.
#[test]
fn the_burst_of_two_october_raises_the_next_block_two_and_a_half_times_not_seven_hundred() {
    let before = HeaderSummary {
        height: 1_195,
        timestamp: 1_790_918_209,
        difficulty: 291_178_580,
    };
    // What the moving average did, as the explorer served the real chain:
    // the figures the documents quote for it.
    let first_honest_asked: u64 = 223_570_119_402;
    let back_near_normal = HeaderSummary {
        height: 1_385,
        timestamp: 1_791_037_349,
        difficulty: 581_235_837,
    };
    assert_eq!(
        (first_honest_asked + before.difficulty / 2) / before.difficulty,
        768
    );
    assert!(back_near_normal.difficulty < 2 * before.difficulty);
    let burst_ended = before.timestamp + INTRUDER[79];
    assert_eq!(
        (back_near_normal.timestamp - burst_ended + 1_800) / 3_600,
        33
    );
    let origin = Origin {
        timestamp: before.timestamp - TARGET * before.height,
        difficulty: before.difficulty,
    };
    let mut parent = before;
    let mut paid: u128 = 0;
    for (index, offset) in INTRUDER.iter().enumerate() {
        let difficulty = next_difficulty(&parent, origin, TARGET);
        paid += u128::from(difficulty);
        parent = HeaderSummary {
            height: before.height + 1 + index as u64,
            timestamp: before.timestamp + offset,
            difficulty,
        };
    }
    let asked = next_difficulty(&parent, origin, TARGET);
    let ratio = asked as f64 / before.difficulty as f64;
    assert!(
        (2.4..2.5).contains(&ratio),
        "asked {asked}, {ratio:.3} times"
    );
    let minutes = asked as f64 / HONEST / 60.0;
    assert!(
        minutes < 2.5,
        "the next honest block waits {minutes:.1} min"
    );
    // And the burst itself cost what it raised: about eighty blocks at the
    // average of where it started and ended, against the 9.95e11 hashes the
    // moving average made it pay.
    assert!(paid < 50_000_000_000, "the burst paid {paid}");
}

/// Who mined a block in a simulation, and how it was stamped.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stamp {
    /// The wall clock, or the median floor if that is later.
    Honest,
    /// The median floor, the earliest time the rules accept.
    Floor,
    /// A fixed time, held to the floor.
    At(u64),
}

/// A chain under the retarget, mined by whoever the scenario says.
struct Chain {
    origin: Origin,
    recent: Vec<HeaderSummary>,
    /// Wall clock seconds.
    now: f64,
    rng: Rng,
}

impl Chain {
    /// A chain on schedule at the honest rate, warmed by two hundred blocks
    /// of it, which is how `tau.py` starts every scenario.
    fn warmed(seed: u64) -> Self {
        let start = 1_790_000_000;
        let steady = (HONEST * TARGET as f64) as u64;
        let mut chain = Self {
            origin: Origin {
                timestamp: start,
                difficulty: steady,
            },
            recent: vec![HeaderSummary {
                height: 0,
                timestamp: start,
                difficulty: steady,
            }],
            now: start as f64,
            rng: Rng(0x5EED_0000_0000_0001 ^ (seed + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)),
        };
        for _ in 0..200 {
            chain.mine(HONEST, Stamp::Honest);
        }
        chain
    }

    fn asked(&self) -> u64 {
        next_difficulty(self.recent.last().unwrap(), self.origin, TARGET)
    }

    /// One block at `rate`, and the seconds it took.
    fn mine(&mut self, rate: f64, stamp: Stamp) -> f64 {
        let difficulty = self.asked();
        let took = self.rng.solve(difficulty, rate);
        self.now += took;
        self.append(difficulty, stamp);
        took
    }

    fn append(&mut self, difficulty: u64, stamp: Stamp) {
        let floor = median_time_past(&self.recent).unwrap() + 1;
        let wanted = match stamp {
            Stamp::Honest => self.now as u64,
            Stamp::Floor => 0,
            Stamp::At(timestamp) => timestamp,
        };
        let parent = self.recent.last().unwrap();
        self.recent.push(HeaderSummary {
            height: parent.height + 1,
            timestamp: wanted.max(floor),
            difficulty,
        });
        if self.recent.len() > MEDIAN_TIME_WINDOW {
            self.recent.remove(0);
        }
    }

    /// The honest miner's next hundred blocks: the hours they took beyond a
    /// hundred targets, and the longest of them in minutes.
    fn honest_hundred(&mut self) -> (f64, f64) {
        let mut total = 0.0;
        let mut longest: f64 = 0.0;
        for _ in 0..100 {
            let took = self.mine(HONEST, Stamp::Honest);
            total += took;
            longest = longest.max(took);
        }
        ((total - 100.0 * TARGET as f64) / 3_600.0, longest / 60.0)
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

/// The eighty blocks again, on a chain the new rule kept in balance, as
/// stamped and then all at the median floor, and the honest miner's next
/// hundred blocks after each.
///
/// Measured at eight seeds: the hundred blocks come 1.0 hours late either
/// way, and the first of them is asked 2.45 times the difficulty before the
/// burst as stamped and 2.70 at the floor. The eighty blocks paid 2.1 and 2.3
/// hours of the honest rate, so the honest chain lost about half of what they
/// cost: the schedule does not make a burst this small cheap for the honest
/// chain, it keeps it small, an hour. The two delays agree because the
/// rule reads only the parent: the floor makes the burst's own blocks and
/// the first honest block dearer, and once that block is in, dated by a real
/// clock, the chain stands exactly where it would have. The plan published
/// 5.6 and 5.5 hours for a miner of this size staying five minutes, which
/// mines several times more than eighty blocks; under the moving average the
/// real burst cost the next block a mean of nearly four hours on its own.
#[test]
fn the_burst_as_stamped_and_at_the_floor_delays_the_next_hundred_blocks_by_hours_not_days() {
    for stamp in [Stamp::At(0), Stamp::Floor] {
        let mut delays = Vec::new();
        let mut firsts = Vec::new();
        let mut costs = Vec::new();
        for seed in 0..8 {
            let mut chain = Chain::warmed(seed);
            let before = chain.asked();
            let start = chain.now as u64;
            let mut paid = 0u128;
            for offset in INTRUDER {
                let difficulty = chain.asked();
                paid += u128::from(difficulty);
                let stamped = match stamp {
                    Stamp::At(_) => Stamp::At(start + offset),
                    other => other,
                };
                chain.append(difficulty, stamped);
            }
            chain.now = (start + INTRUDER[79]) as f64;
            firsts.push(chain.asked() as f64 / before as f64);
            delays.push(chain.honest_hundred().0);
            costs.push(paid as f64 / HONEST / 3_600.0);
        }
        let delay = median(delays);
        let first = median(firsts);
        let paid = median(costs);
        println!("eighty blocks: {delay:.2} h late for {paid:.2} honest hours paid");
        // A burst this small is not made cheap by the schedule: the honest
        // chain still loses about half of what it paid, which at this size
        // is an hour.
        assert!(
            (0.3..0.8).contains(&(delay / paid)),
            "the honest chain lost {:.2} of what the eighty blocks paid",
            delay / paid
        );
        assert!(
            delay < 2.5,
            "the next hundred blocks were {delay:.2} h late"
        );
        assert!(
            first < 3.5,
            "the first honest block was asked {first:.2} times"
        );
    }
}

/// A miner of 1 261 times the honest rate, the intruder's size, mining every
/// block for `seconds` of wall time and leaving: the hours the honest miner's
/// next hundred blocks come late beyond their targets, and the hours of the
/// honest rate the miner's own blocks cost.
fn presence(seed: u64, seconds: f64, stamp: Stamp) -> (f64, f64) {
    let mut chain = Chain::warmed(seed);
    let leaves = chain.now + seconds;
    let mut paid = 0u128;
    while chain.now < leaves {
        paid += u128::from(chain.asked());
        chain.mine(1_261.0 * HONEST, stamp);
    }
    (chain.honest_hundred().0, paid as f64 / HONEST / 3_600.0)
}

/// A miner of the intruder's size staying five minutes, which is the plan's
/// own scenario: its stall is hours where the moving average's was days.
///
/// The plan: 5.6 hours as stamped and 5.5 at the floor over the next hundred
/// honest blocks, at six seeds, against 71 and 230 for the moving average.
/// Measured here at eight seeds: 5.75 and 5.51. Held to eight, which no
/// moving average result comes near. The miner paid about 106 hours of the
/// honest rate for it, so the honest chain lost about a twentieth of what the
/// burst cost, where the moving average lost three fifths on the same basis.
#[test]
fn a_miner_of_twelve_hundred_times_the_rate_staying_five_minutes_costs_hours() {
    for stamp in [Stamp::Honest, Stamp::Floor] {
        let (delays, paid): (Vec<f64>, Vec<f64>) =
            (0..8).map(|seed| presence(seed, 300.0, stamp)).unzip();
        let delay = median(delays);
        let paid = median(paid);
        println!("five minutes: {delay:.2} h late for {paid:.1} honest hours paid");
        assert!(
            delay < 8.0,
            "the next hundred blocks were {delay:.2} h late"
        );
        assert!(
            delay / paid < 0.07,
            "the honest chain lost {:.3} of what the burst paid",
            delay / paid
        );
    }
}

/// A miner of the intruder's size staying an hour, under the rule as it
/// ships, the bound included.
///
/// The plan published 9.6 hours as stamped and 8.5 at the floor over the next
/// hundred honest blocks, measured on the rule without the bound, which it
/// said changed nothing. Here it binds. The miner leaves the chain asking six
/// to nine hundred times the honest difficulty, so the first honest block
/// waits that many target times, more than two half lives and a target, and
/// the schedule then asks a fall far past four: the bound holds each block
/// after it to a quarter of the last, and the stall grows by about a third of
/// that first wait. The plan's simulator and seeds re-run with the bound give
/// 11.3 and 10.7 hours. That first wait is drawn from an exponential whose
/// mean is ten or fifteen hours, so eight seeds are not enough to hold a
/// median: measured here at sixty four, 11.23 and 13.45 hours, for about
/// 1 260 hours of the honest rate paid, a hundredth of it.
#[test]
fn a_miner_of_twelve_hundred_times_the_rate_staying_an_hour_costs_half_a_day() {
    for stamp in [Stamp::Honest, Stamp::Floor] {
        let (delays, paid): (Vec<f64>, Vec<f64>) =
            (0..64).map(|seed| presence(seed, 3_600.0, stamp)).unzip();
        let delay = median(delays);
        let paid = median(paid);
        println!("an hour: {delay:.2} h late for {paid:.1} honest hours paid");
        assert!(
            (9.6..15.0).contains(&delay),
            "the next hundred blocks were {delay:.2} h late"
        );
        assert!(
            delay / paid < 0.015,
            "the honest chain lost {:.4} of what the burst paid",
            delay / paid
        );
    }
}

/// The seeded dice `the_price_of_a_seed.rs` rolls, so that a departure here
/// and a burst there draw the same solve times from the same seed.
struct Dice(u64);

impl Dice {
    fn uniform(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^= mixed >> 31;
        ((mixed >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }

    fn solve(&mut self, difficulty: u64, rate: f64) -> f64 {
        (-self.uniform().ln() * difficulty as f64 / rate).round()
    }
}

/// What a departure from `times` the opening difficulty leaves an honest
/// chain on testnet-8's rules.
struct Departure {
    /// Seconds the first honest block waits, and from the departure until the
    /// chain asks at most twice the opening difficulty again.
    first_wait: f64,
    stall: f64,
    /// Honest blocks asked the floor afterwards.
    at_the_floor: u64,
}

/// A chain on schedule at testnet-8's opening difficulty, mined by an honest
/// miner whose rate makes that difficulty take exactly the target; a miner of
/// 1 260 times that rate dates every block at the median floor until the
/// chain asks `times` the opening difficulty, then leaves. With `seed`, each
/// block's time is drawn from the dice; without, each block takes exactly the
/// mean time its difficulty asks. Honest blocks are stamped by the clock, or
/// the median plus one if that is later, and wait when that would be past the
/// drift. The same chain as `departure.py` in the wave's audit directory.
fn departure(times: u64, seed: Option<u64>) -> Departure {
    let params = cairn_ledger::validation::ConsensusParams::for_network("testnet-8").unwrap();
    let target = params.target_block_time;
    let opening = params.genesis_difficulty;
    let drift = params.max_timestamp_drift as f64;
    let rate = opening as f64 / target as f64;
    let mut dice = seed.map(Dice);
    let mut solve = |difficulty: u64, rate: f64| match dice.as_mut() {
        Some(dice) => dice.solve(difficulty, rate),
        None => difficulty as f64 / rate,
    };
    let start = 1u64 << 40;
    let origin = Origin {
        timestamp: start,
        difficulty: opening,
    };
    let mut recent: Vec<HeaderSummary> = (0..MEDIAN_TIME_WINDOW as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: start + height * target,
            difficulty: opening,
        })
        .collect();
    let mut clock = recent.last().unwrap().timestamp as f64;
    let mut left: Option<f64> = None;
    let mut first_wait = None;
    let mut stall = None;
    let mut at_the_floor = 0;
    let mut honest = 0u64;
    for index in 0..2_000_000u64 {
        let parent = *recent.last().unwrap();
        let asked = next_difficulty(&parent, origin, target);
        let median = median_time_past(&recent).unwrap();
        let timestamp = if left.is_none() && index >= 200 && asked < times * opening {
            clock += solve(asked, 1_260.0 * rate);
            median + 1
        } else {
            if left.is_none() && index >= 200 {
                left = Some(clock);
            }
            clock += solve(asked, rate);
            let timestamp = (clock as u64).max(median + 1);
            if timestamp as f64 > clock + drift {
                clock = timestamp as f64 - drift;
            }
            if let Some(left) = left {
                honest += 1;
                first_wait.get_or_insert(clock - left);
                if asked == MIN_DIFFICULTY {
                    at_the_floor += 1;
                }
                if stall.is_none() && asked <= 2 * opening {
                    stall = Some(clock - left);
                }
                if stall.is_some_and(|stall| honest > 100 && clock - left > stall + 86_400.0) {
                    break;
                }
            }
            timestamp
        };
        recent.push(HeaderSummary {
            height: parent.height + 1,
            timestamp,
            difficulty: asked,
        });
        if recent.len() > MEDIAN_TIME_WINDOW {
            recent.remove(0);
        }
    }
    Departure {
        first_wait: first_wait.unwrap(),
        stall: stall.unwrap(),
        at_the_floor,
    }
}

/// The bound adds about a third of the first honest block's wait to the
/// stall a large departure leaves.
///
/// The first honest block after a miner leaves a chain asking `X` times the
/// honest difficulty waits about `X` target times. Past about 120 times that
/// is more than two half lives and a target, so the schedule then asks a fall
/// of more than four and the bound holds the next block to a quarter of the
/// last, and the next, `X / 4 + X / 16 + ...` target times more, about `X / 3`.
/// Without the bound the same chain is asked the schedule's answer at once.
/// Measured with every block taking its mean time: a stall of 22.8 hours at
/// 1 024 times, 45.6 at 2 048 and 92.0 at 4 096, against 17.1, 34.2 and 69.0
/// for the rule without the bound in `departure.py`, which is `X / 3` target
/// times more within one per cent.
#[test]
fn the_bound_adds_a_third_of_the_first_wait_to_a_large_departure() {
    let target = 60.0;
    for times in [1_024u64, 2_048, 4_096] {
        let left = departure(times, None);
        let x = times as f64;
        println!(
            "{times} times, mean times: first honest block waits {:.1} h, stall {:.1} h, \
             {} blocks at the floor",
            left.first_wait / 3_600.0,
            left.stall / 3_600.0,
            left.at_the_floor
        );
        assert!(
            (left.first_wait / (x * target) - 1.0).abs() < 0.02,
            "the first honest block waited {:.0} target times after {times} times",
            left.first_wait / target
        );
        assert!(
            left.stall >= 0.98 * 4.0 / 3.0 * x * target,
            "{times} times stalled the chain {:.0} target times, not the four thirds of \
             {times} the bound makes it",
            left.stall / target
        );
    }
}

/// A departure from a few thousand times leaves the chain further behind its
/// schedule than the floor's edge, and the honest chain then runs hundreds or
/// thousands of blocks at difficulty 1 while it catches the schedule up.
///
/// The floor is the answer while the parent stands `log2(D) - 1` half lives
/// or more behind its schedule, 27 hours on testnet-8. A stall longer than
/// the branch's lead plus that puts the chain there, and the bound, by
/// lengthening the stall, puts it there sooner and further. The run is the
/// schedule's debt being repaid: blocks with almost no work behind them,
/// mined in minutes.
///
/// Pinned where every block takes the mean time its difficulty asks, which is
/// one path and not a draw: 579 blocks at the floor after a departure from
/// 2 048 times, 3 455 after 4 096 times, which the 2 October intruder's rate
/// reaches in under five hours, and 9 191 after 8 192 times. Random block
/// times put the median at 20.5, 2 244 and 7 793 over sixty four seeds. The
/// median stands lower because the first honest block's wait is drawn from an
/// exponential, whose median is `ln 2` of its mean, and a shorter wait leaves
/// less debt. The figures at 4 096 and 8 192 times are what `departure.py`,
/// the testnet-8 wave's simulator, prints for the same chain.
///
/// This test held a median over sixteen seeds, none at 2 048 times and 874 at
/// 4 096, and four documents quoted it. Both were low draws: a median of a
/// quantity one long gap decides moves by half or more between small sets of
/// seeds, and the testnet-9 study found it by running the same script on
/// sixty four. So the figure the documents lead with is the mean path, which
/// no seed moves.
#[test]
fn a_departure_from_thousands_of_times_ends_in_a_run_at_the_floor() {
    for (times, mean, median) in [
        (2_048u64, 579, 20.5),
        (4_096, 3_455, 2_244.0),
        (8_192, 9_191, 7_793.0),
    ] {
        let path = departure(times, None).at_the_floor;
        let mut runs: Vec<f64> = (0..64)
            .map(|seed| departure(times, Some(seed)).at_the_floor as f64)
            .collect();
        runs.sort_by(f64::total_cmp);
        let middle = f64::midpoint(runs[31], runs[32]);
        println!(
            "{times} times: {path} honest blocks at the floor on the mean path, a median \
             of {middle:.1} over 64 seeds"
        );
        assert_eq!(
            path, mean,
            "{times} times left {path} blocks at the floor on the mean path"
        );
        assert!(
            (middle - median).abs() <= 0.5,
            "{times} times left a median of {middle:.1} blocks at the floor over 64 seeds"
        );
    }
}

/// The documents quote the floor run as measured, and no longer the low draw.
///
/// Read like the burst figures below, with the line breaks and the comment
/// markers taken out.
#[test]
fn the_documents_quote_the_floor_run_as_measured() {
    let flat = |text: &str| {
        text.split_whitespace()
            .filter(|word| !matches!(*word, "///" | "//!" | "//"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let everywhere: Vec<(&str, String)> = ELSEWHERE
        .iter()
        .map(|(name, text)| (*name, flat(text)))
        .chain([("the specification", flat(SPECIFICATION))])
        .collect();
    for (name, text) in &everywhere {
        for retired in [
            "a median of 874 after a departure",
            "no block at the floor after a departure from 2 048",
            "aucun bloc au plancher après un départ de 2 048",
            "874 blocks at the floor",
            "874 après 4 096 fois, moins",
            "7 642 after",
            "7 642 après",
            "médiane sur seize graines :",
            "the median over sixteen seeds,",
        ] {
            assert!(!text.contains(retired), "{name} still says \"{retired}\"");
        }
    }
    let quoted = |name: &str, phrase: &str| {
        let (_, text) = everywhere.iter().find(|(named, _)| *named == name).unwrap();
        assert!(text.contains(phrase), "{name} no longer says \"{phrase}\"");
    };
    for name in ["pow.rs", "the threat model"] {
        quoted(name, "3 455 after a departure from 4 096 times");
        quoted(name, "2 244 and 7 793 over sixty four seeds");
    }
    quoted(
        "the specification",
        "3 455 blocks at the floor after a departure from 4 096 times and 9 191 after 8 192",
    );
    quoted("the specification", "2 244 and 7 793 over sixty four seeds");
    quoted(
        "the open questions",
        "579 blocs au plancher après un départ de 2 048 fois",
    );
    quoted("the open questions", "3 455 après 4 096 fois");
    quoted("the open questions", "9 191 après 8 192 fois");
    quoted("the open questions", "2 244 et de 7 793");
}

/// The watcher, which the open questions say rings on a run of floor blocks.
const WATCHER: &str = include_str!("../../../.github/scripts/watch_testnet.py");

/// The open questions record why sixty blocks and no cap were kept with nine
/// figures nothing in this repository measures: they come from the testnet-9
/// study's simulations, which live beside its audit and not here. The floor
/// run's figures were in the same position, stood in four documents a factor
/// of four low, and needed the guard above to stay corrected. So the item says
/// where its figures come from, and each is pinned here as quoted: changing
/// one without measuring it again in the study fails this, and whoever edits
/// it learns that the measurement is not in this repository.
///
/// The same item said the floor run's damage "is treated" outside consensus by
/// counting confirmations by work and by a watcher alarm, and neither existed.
/// The alarm does now, and is held to the document; the counting is owed.
#[test]
fn the_open_questions_quote_the_half_life_study_as_simulated_elsewhere() {
    let flat = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let (_, questions) = ELSEWHERE
        .iter()
        .find(|(name, _)| *name == "the open questions")
        .unwrap();
    let questions = flat(questions);
    for stated in [
        // Where the figures come from.
        "Les chiffres de ce paragraphe sont ceux de ses simulations, qui ne sont pas dans ce \
         dépôt, et aucun test d'ici ne les mesure",
        "en médiane sur trente-deux graines (<code>sims/q2_departures.py</code> de l'étude)",
        "les pertes de débit sur seize (<code>sims/q2_loss.py</code>)",
        "sur le chemin moyen, sans tirage (<code>sims/q2_onset.py</code>)",
        // The nine figures, each as the study measured it.
        "mesurée avec une borne de deux et une de huit, la course s'allonge à deux et raccourcit \
         un peu à huit, sans jamais disparaître",
        "allonge les grands blocages d'environ cinq heures à <code>K = 2</code>",
        "(de rien à deux heures à <code>K = 4</code>)",
        "67 heures à <code>K = 2</code> après un départ de 4 096 fois",
        "cent vingt blocs divisent par deux les grands blocages",
        "après une attaque d'environ 9 100 heures du débit honnête au lieu de 2 300",
        "les mille blocs suivants ont 6,6 heures de retard contre 3,3",
        "et 13,2 contre 6,6 après une perte de quatre-vingt-dix-neuf centièmes",
        "<code>K = 4</code> étant la meilleure constante",
        // What is done outside consensus, and what is owed.
        "Le surveillant du réseau de test sonne sur une suite de dix blocs au plancher \
         (l'alarme <code>floor-run</code> de <code>.github/scripts/watch_testnet.py</code>)",
        "Le portefeuille et l'explorateur devront compter les confirmations d'un paiement au \
         travail au-dessus de lui plutôt qu'en blocs : c'est dû, et ce n'est pas encore fait.",
    ] {
        assert!(
            questions.contains(stated),
            "the open questions no longer say \"{stated}\""
        );
    }
    assert!(
        !questions.contains("se traite hors du consensus : compter les confirmations"),
        "the open questions still say the floor run is treated by counting confirmations by work"
    );
    for (code, said) in [
        ("FLOOR = \"floor-run\"", "the alarm the open questions name"),
        (
            "FLOOR_RUN_BLOCKS = 10\n",
            "the ten blocks the open questions say it rings on",
        ),
        (
            "verdicts.append(check_floor_run(blocks))",
            "the check that rings it",
        ),
    ] {
        assert!(WATCHER.contains(code), "the watcher has lost {said}");
    }
}

/// Nine tenths of the hash rate leaves for good, and the blocks are back near
/// their target within the time the plan published, 3.8 hours, which is what
/// the moving average managed too (3.9). Measured as `tau.py` does: from the
/// loss until twenty blocks in a row average within a quarter of the target.
/// Measured here at eight seeds: 3.83 hours.
#[test]
fn a_loss_of_nine_tenths_of_the_hash_rate_settles_in_hours() {
    let mut settled = Vec::new();
    for seed in 0..8 {
        let mut chain = Chain::warmed(seed);
        let lost = chain.now;
        let mut gaps: Vec<(f64, f64)> = Vec::new();
        let mut when = f64::INFINITY;
        for _ in 0..4_000 {
            let took = chain.mine(HONEST / 10.0, Stamp::Honest);
            gaps.push((chain.now - took, took));
            if gaps.len() >= 20 {
                let window = &gaps[gaps.len() - 20..];
                let mean = window.iter().map(|(_, took)| took).sum::<f64>() / 20.0;
                if (mean - TARGET as f64).abs() < 0.25 * TARGET as f64 {
                    when = window[0].0 - lost;
                    break;
                }
            }
        }
        settled.push(when / 3_600.0);
    }
    let hours = median(settled);
    assert!(hours < 5.5, "settled after {hours:.2} h");
    assert!(
        hours > 1.0,
        "settled after {hours:.2} h, faster than a half life allows"
    );
}

/// A network opened long after its first block is dated stands behind its
/// schedule from the start, and is asked the least the bound allows, down to
/// the floor, until it has caught up.
///
/// The schedule starts at the first block. The devnet's pinned first block was
/// dated twenty nine days before it was mined, so that a test could mine a long
/// chain forward from it behind the wall clock, and a devnet node opened the
/// day it was mined stood twenty nine days behind. Measured on the devnet's
/// own rules and first block opened that late, with blocks dated as fast as
/// the median allows from that day on: the floor at the thirteenth block, and
/// the floor every block after it for about half a million blocks, until the
/// chain has caught the schedule up. Under the moving average a late opening
/// cost one easy block. So a published network's first block is minted at its
/// opening, which the specification requires, and the devnet's is minted again
/// with every restart and dated only `genesis::DEVNET_DATED_EARLY` early, which
/// is what that test needs.
#[test]
fn a_network_opened_long_after_its_first_block_is_nearly_free_until_it_catches_up() {
    let params = cairn_ledger::validation::ConsensusParams::for_network("devnet").unwrap();
    let first = cairn_ledger::genesis::block(params.network).unwrap();
    let origin = params.origin();
    let target = params.target_block_time;
    let opened = first.header.timestamp + 29 * 24 * 3_600;

    let mut recent = vec![first.header.summary()];
    let mut to_the_floor = None;
    let mut caught_up = None;
    let mut wall = opened;
    for height in 1..2_000_000u64 {
        let parent = *recent.last().unwrap();
        let asked = next_difficulty(&parent, origin, target);
        if to_the_floor.is_none() && asked == MIN_DIFFICULTY {
            to_the_floor = Some(height);
        }
        if to_the_floor.is_some() && asked > MIN_DIFFICULTY {
            caught_up = Some(height);
            break;
        }
        // As fast as the rules let a miner date its blocks: the median plus
        // one, and never before the wall clock of the day it opened, which
        // moves a second for every six blocks.
        if height % 6 == 0 {
            wall += 1;
        }
        let floor = median_time_past(&recent).unwrap() + 1;
        recent.push(HeaderSummary {
            height,
            timestamp: floor.max(wall),
            difficulty: asked,
        });
        if recent.len() > MEDIAN_TIME_WINDOW {
            recent.remove(0);
        }
    }
    let to_the_floor = to_the_floor.expect("the floor was never reached");
    let caught_up = caught_up.expect("the schedule was never caught up");
    println!(
        "devnet opened 29 days late: the floor at block {to_the_floor}, and left at block \
         {caught_up}"
    );
    assert!(to_the_floor <= 14, "the floor came at {to_the_floor}");
    assert!(
        caught_up > 450_000,
        "the late opening was caught up after {caught_up} blocks"
    );
}

/// The documents say what was measured about a burst that leaves.
///
/// Seven places said a burst costs the honest chain an eighty seventh of what
/// it paid, against seven tenths for the moving average. The eighty seventh
/// was the first honest block's wait over the burst's cost, and the seven
/// tenths the moving average's delay over a hundred blocks: two quantities,
/// and on the second one the schedule's figure for the 2 October burst is
/// about a half. The figures now come from one measurement of both rules, and
/// every document quotes the same ones. Read with the line breaks and the
/// comment markers taken out, since where a paragraph wraps is not part of
/// what it says.
#[test]
fn the_documents_quote_the_measured_cost_of_a_burst() {
    let flat = |text: &str| {
        text.split_whitespace()
            .filter(|word| !matches!(*word, "///" | "//!" | "//"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let everywhere: Vec<(&str, String)> = ELSEWHERE
        .iter()
        .map(|(name, text)| (*name, flat(text)))
        .chain([("the specification", flat(SPECIFICATION))])
        .collect();
    for (name, text) in &everywhere {
        for retired in [
            "eighty seventh",
            "eighty seven",
            "quatre-vingt-septième",
            "seven tenths",
            "seven in ten",
            "sept dixièmes",
            "about what it paid",
            "six hundred times",
            "day and a half to work",
            "for a day and a half",
            "pendant un jour et demi",
        ] {
            assert!(!text.contains(retired), "{name} still says \"{retired}\"");
        }
    }
    let quoted = |name: &str, phrase: &str| {
        let (_, text) = everywhere.iter().find(|(named, _)| *named == name).unwrap();
        assert!(text.contains(phrase), "{name} no longer says \"{phrase}\"");
    };
    quoted("the whitepaper", "1.0 h for 1.9 h");
    quoted("the whitepaper", "5.6 h for 106 h");
    quoted("the whitepaper", "11.3 h for 1 259 h");
    quoted("the whitepaper", "71 h for 117 h");
    quoted("the whitepaper", "298 h for 1 177 h");
    quoted("the specification", "1.0 hour for 1.9");
    quoted("the specification", "5.6 hours for 106");
    quoted("the specification", "11.3 hours for 1 259");
    quoted("pow.rs", "11.3 h for 1 259 h");
    quoted(
        "pow.rs",
        "11.3 hours late with the bound and 9.6 without it",
    );
    quoted("the threat model", "5.6 hours late after five minutes");
    quoted("the threat model", "11.3 after an hour");
    quoted("the open questions", "5,6 heures en retard");
    quoted("the open questions", "11,3 après une heure");
    quoted(
        "note.rs",
        "5.6 hours after the same five minutes, 11.3 after the same hour",
    );
    for name in [
        "README.md",
        "note.rs",
        "pow.rs",
        "the whitepaper",
        "the specification",
    ] {
        quoted(name, "768 times");
        quoted(name, "33 hours");
    }
}

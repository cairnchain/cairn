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
//! and the chain was back near normal at block 1385, a day and a half later.
//! The same eighty
//! headers are replayed here, then the same burst at the median floor, a miner
//! of that size staying five minutes, and an honest loss of nine tenths of the
//! hash rate, each with a seeded generator and the figure the wave's plan
//! published held with room. Every figure is chain time from the fixture's own
//! solve times, not how long the test ran.

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
    // and the cases the specification's table quotes are asked by name.
    assert!(checked.len() >= 50, "only {} vectors read", checked.len());
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
/// and about eleven hours at the honest rate. This asks what eighty blocks
/// stated four thousand six hundred and fifty six seconds ahead of the
/// schedule are worth: two and a half times, about two and a half minutes.
#[test]
fn the_burst_of_two_october_raises_the_next_block_two_and_a_half_times_not_seven_hundred() {
    let before = HeaderSummary {
        height: 1_195,
        timestamp: 1_790_918_209,
        difficulty: 291_178_580,
    };
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
/// burst as stamped and 2.70 at the floor. The two delays agree because the
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
        for seed in 0..8 {
            let mut chain = Chain::warmed(seed);
            let before = chain.asked();
            let start = chain.now as u64;
            for offset in INTRUDER {
                let difficulty = chain.asked();
                let stamped = match stamp {
                    Stamp::At(_) => Stamp::At(start + offset),
                    other => other,
                };
                chain.append(difficulty, stamped);
            }
            chain.now = (start + INTRUDER[79]) as f64;
            firsts.push(chain.asked() as f64 / before as f64);
            delays.push(chain.honest_hundred().0);
        }
        let delay = median(delays);
        let first = median(firsts);
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

/// A miner of the intruder's size staying five minutes, which is the plan's
/// own scenario: its stall is hours where the moving average's was days, and
/// what it leaves is the size of what it mined.
///
/// The plan: 5.6 hours as stamped and 5.5 at the floor over the next hundred
/// honest blocks, at six seeds, against 71 and 230 for the moving average.
/// Measured here at eight seeds: 5.75 and 5.51. Held to eight, which no
/// moving average result comes near.
#[test]
fn a_miner_of_twelve_hundred_times_the_rate_staying_five_minutes_costs_hours() {
    for stamp in [Stamp::Honest, Stamp::Floor] {
        let mut delays = Vec::new();
        for seed in 0..8 {
            let mut chain = Chain::warmed(seed);
            let leaves = chain.now + 300.0;
            while chain.now < leaves {
                chain.mine(1_261.0 * HONEST, stamp);
            }
            delays.push(chain.honest_hundred().0);
        }
        let delay = median(delays);
        assert!(
            delay < 8.0,
            "the next hundred blocks were {delay:.2} h late"
        );
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
/// The schedule starts at the first block. The devnet's pinned first block is
/// dated twenty nine days before it was mined, so that a test could mine a long
/// chain forward from it behind the wall clock; a devnet node opened the day
/// it was mined is twenty nine days behind. Measured on the devnet's own rules
/// and first block, with blocks dated as fast as the median allows from that
/// day on: the floor at the thirteenth block, and the floor every block after
/// it for about half a million blocks, until the chain has caught the schedule
/// up. Under the moving average a late opening cost one easy block. So a
/// published network's first block is minted at its opening, which the
/// specification requires, and the devnet's has to be minted again close to
/// the day it is used.
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

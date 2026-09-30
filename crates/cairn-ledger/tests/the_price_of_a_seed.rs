//! What a fresh seed costs a forger on testnet-6 and on the devnet, and what
//! the rule that prices it costs an honest chain that loses hash rate.
//!
//! Three readings of the run are measured side by side: no tie between the
//! tip and the run, which is what the rules were; a tie to the pinned header
//! alone, the rule the audit proposed and #237 deferred until something
//! measured it; and a tie to the hardest header from the pinned one up,
//! which is [`MOST_FALL`] and is what a newcomer now applies.
//!
//! The draw is seeded by the tip's identifier, so a forger that dislikes its
//! questions buys another tip. What a tip costs is its difficulty, and what
//! decides the lowest difficulty a forger can give its tip is the run up to
//! it: every header from the pinned one up is held to the retarget, the run
//! has to carry the band of work the draw leaves unresolved, and it may be at
//! most [`MOST_TAIL`] headers long. This measures that lowest price.
//!
//! **What it measures.** Runs of headers walked forward by the shipped
//! retarget and median rule, each header carrying exactly the difficulty
//! `next_difficulty` demands of it and dated by a forger choosing its gaps;
//! where the draw's deepest question lands, from the shipped `draw` over
//! seeds; and from those two, the difficulty of the cheapest tip that a
//! forger can present under each rule and the share of its tips it can
//! present at all. A tip is priced at its difficulty plus the hashes it takes
//! to learn that its draw caught the invented work, which is where a forger
//! stops.
//!
//! **What it does not.** Nothing here is mined: a header of difficulty `d` is
//! priced at `d` hashes, which is what mining it costs on average. The chance
//! that a draw misses a forger's invented work is taken from the inequality
//! the documents publish (2^-161.9 a tip at forty per cent), not measured
//! again. The forger's headers below the pinned one, its handover and its
//! ledger are not built: they are the same whatever rule the tip is held to.
//! And the chain is the one the published figure is for, fifteen halvings,
//! at each network's opening difficulty; a chain whose miners run slower
//! than that has a proportionally cheaper tip under any rule.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use cairn_ledger::block::HeaderSummary;
use cairn_ledger::pow::{
    median_time_past, next_difficulty, DIFFICULTY_WINDOW, MIN_DIFFICULTY, RECENT_HEADERS,
};
use cairn_ledger::sampling::{draw, levels_for, MOST_FALL, MOST_TAIL, SAMPLES};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::hash::{hash, Domain};

/// What #259's re-measurement told SECURITY.md, read here rather than
/// trusted: 03-Q1 found the figure attested only by a pull request body,
/// with no test tying it to what SECURITY.md's own prose says.
const SECURITY: &str = include_str!("../../../SECURITY.md");

/// Thirty years at a block a minute, the chain every published figure is for.
const BLOCKS: u64 = 30 * 365 * 24 * 60;
/// Seeds the draw is taken over, each standing for one tip.
const SEEDS: u64 = 256;
/// The clamp ceiling on a stated gap, in target block times.
const LONGEST: u64 = 6;

/// A run of headers as the rules see it, priced rather than mined.
#[derive(Clone)]
struct Walk {
    target: u64,
    window: Vec<HeaderSummary>,
    blocks: u64,
    work: u128,
    stated: u64,
    hardest: u64,
}

impl Walk {
    /// A window on schedule at one difficulty, which the retarget gives back
    /// unchanged.
    fn on_schedule_at(difficulty: u64, target: u64) -> Self {
        let window = (0..RECENT_HEADERS as u64)
            .map(|height| HeaderSummary {
                height,
                timestamp: 1_000_000 + height * target,
                difficulty,
            })
            .collect();
        Self {
            target,
            window,
            blocks: 0,
            work: 0,
            stated: 0,
            hardest: difficulty,
        }
    }

    fn demanded(&self) -> u64 {
        next_difficulty(&self.window, self.target)
    }

    /// One header at the difficulty demanded of it, `gap` seconds after the
    /// last, held to the median rule the run is held to.
    fn step(&mut self, gap: u64) -> u64 {
        let last = *self.window.last().unwrap();
        let difficulty = self.demanded();
        let header = HeaderSummary {
            height: last.height + 1,
            timestamp: last.timestamp + gap,
            difficulty,
        };
        assert!(
            median_time_past(&self.window).is_none_or(|median| header.timestamp > median),
            "a forger's header broke the median rule"
        );
        self.window.push(header);
        if self.window.len() > DIFFICULTY_WINDOW + 1 {
            self.window.remove(0);
        }
        self.blocks += 1;
        self.work += u128::from(difficulty);
        self.stated += gap;
        self.hardest = self.hardest.max(difficulty);
        difficulty
    }

    /// Walks down at the clamp ceiling while the next header would still be
    /// at or above `lowest`, and returns the last one, which is the tip.
    ///
    /// Not while the demand falls: near the floor a window of long gaps can
    /// ask the same again for a block or two before it falls on.
    fn down_to(&mut self, lowest: u64) -> u64 {
        let mut tip = self.step(LONGEST * self.target);
        for _ in 0..100_000 {
            if tip <= lowest || self.demanded() < lowest {
                return tip;
            }
            tip = self.step(LONGEST * self.target);
        }
        panic!("the walk never reached {lowest}");
    }
}

struct Network {
    name: &'static str,
    params: ConsensusParams,
}

fn networks() -> Vec<Network> {
    ["testnet-6", "devnet"]
        .into_iter()
        .map(|name| Network {
            name,
            params: ConsensusParams::for_network(name).unwrap(),
        })
        .collect()
}

/// The chain the figure is for, at this network's opening difficulty: its
/// work before the tip, its halvings, and the band the draw leaves.
fn chain(network: &Network) -> (u128, u32, u128) {
    let total = u128::from(BLOCKS) * u128::from(network.params.genesis_difficulty);
    let levels = levels_for(BLOCKS);
    (total, levels, total >> levels)
}

/// How far below the band the deepest question lands, one per seed.
fn deepest_gaps(total: u128, levels: u32, band: u128) -> Vec<u128> {
    (0..SEEDS)
        .map(|index| {
            let seed = hash(Domain::SamplingSeed, &index.to_le_bytes());
            let deepest = draw(seed, SAMPLES, total, levels)
                .into_iter()
                .max()
                .unwrap();
            total - band - deepest
        })
        .collect()
}

/// Hashes a forger spends learning that a tip's draw caught its invented
/// work, at forty per cent on the published inequality: it stops at the
/// first question that lands there.
fn looking(levels: u32) -> f64 {
    let lie: f64 = 1.0 - 0.4 / 0.6;
    let per_draw = (1.0 / (1.0 - lie)).ln() / f64::from(levels);
    // A hash for the seed and one per question until the first that lands.
    let questions = i32::try_from(SAMPLES).unwrap();
    1.0 + (1.0 - (1.0 - per_draw).powi(questions)) / per_draw
}

/// The cheapest tip under a rule, in hashes per tip that can be presented.
struct Price {
    tip: u64,
    presentable: f64,
    run: u64,
    note: String,
}

impl Price {
    fn per_tip(&self, looking: f64) -> f64 {
        (self.tip as f64 + looking) / self.presentable
    }
}

/// No rule: walk to the floor once, and every nonce is a tip.
fn without_a_rule(network: &Network) -> Price {
    let difficulty = network.params.genesis_difficulty;
    let mut walk = Walk::on_schedule_at(difficulty, network.params.target_block_time);
    let tip = walk.down_to(MIN_DIFFICULTY);
    Price {
        tip,
        presentable: 1.0,
        run: walk.blocks,
        note: format!(
            "walk from {difficulty}: {} blocks, {} h stated, {:.1} blocks' work",
            walk.blocks,
            walk.stated / 3_600,
            walk.work as f64 / difficulty as f64
        ),
    }
}

/// The band carried as cheaply in blocks as the retarget allows, starting
/// from a window on schedule at `from` and ending on a tip at or above
/// `lowest`: a climb, a plateau, and a walk down.
fn band_from(from: u64, band: u128, lowest: u64, target: u64) -> Option<Walk> {
    let mut best: Option<Walk> = None;
    for shift in 2..16 {
        let plateau = u64::try_from(band >> shift).ok()?.max(from);
        let mut walk = Walk::on_schedule_at(from, target);
        while walk.demanded() < plateau {
            walk.step(1);
        }
        for _ in 0..RECENT_HEADERS {
            walk.step(target);
        }
        let mut descent = walk.clone();
        descent.down_to(lowest);
        let short = band.saturating_sub(descent.work);
        let more = u64::try_from(short / u128::from(plateau)).ok()? + 1;
        for _ in 0..more {
            walk.step(target);
        }
        walk.down_to(lowest);
        if walk.work < band {
            continue;
        }
        if best.as_ref().is_none_or(|kept| walk.blocks < kept.blocks) {
            best = Some(walk);
        }
    }
    best
}

/// The tie to the pinned header alone: the tip may not be more than `fall`
/// times below the pinned header. The forger lays the headers just under the
/// band at a low difficulty, so the deepest question pins a cheap header,
/// climbs to carry the band, and walks back down to a sixteenth of the
/// cheap one.
fn tied_to_the_pinned(network: &Network, fall: u64, gaps: &[u128]) -> Price {
    let (_, _, band) = chain(network);
    let target = network.params.target_block_time;
    let mut best: Option<Price> = None;
    for bits in 4..40u32 {
        let dip = 1u64 << bits;
        let lowest = dip.div_ceil(fall).max(MIN_DIFFICULTY);
        let Some(walk) = band_from(dip, band, lowest, target) else {
            continue;
        };
        let room = MOST_TAIL.saturating_sub(RECENT_HEADERS as u64 + walk.blocks);
        let reach = u128::from(room) * u128::from(dip);
        let reached = gaps.iter().filter(|gap| **gap <= reach).count();
        if reached == 0 {
            continue;
        }
        let presentable = reached as f64 / gaps.len() as f64;
        let tip = *walk.window.last().map(|last| &last.difficulty).unwrap();
        let price = Price {
            tip,
            presentable,
            run: walk.blocks,
            note: format!("pinned header at {dip}, run peaks at {}", walk.hardest),
        };
        let looking = looking(levels_for(BLOCKS));
        if best
            .as_ref()
            .is_none_or(|kept| price.per_tip(looking) < kept.per_tip(looking))
        {
            best = Some(price);
        }
    }
    best.unwrap()
}

/// The tie to the hardest header from the pinned one up: the forger carries
/// the band flat, as low as the run's ceiling on its length allows, and walks
/// the last of it down to a sixteenth.
fn tied_to_the_run(network: &Network, fall: u64, gaps: &[u128]) -> Price {
    let (_, _, band) = chain(network);
    let target = network.params.target_block_time;
    let mut best: Option<Price> = None;
    for parts in (4_096u64..=8_192).step_by(64) {
        let flat = u64::try_from(band / u128::from(parts)).unwrap();
        let lowest = flat.div_ceil(fall);
        let mut walk = Walk::on_schedule_at(flat, target);
        let mut descent = walk.clone();
        descent.down_to(lowest);
        let short = band.saturating_sub(descent.work);
        let more = u64::try_from(short / u128::from(flat)).unwrap() + 1;
        for _ in 0..more {
            walk.step(target);
        }
        let tip = walk.down_to(lowest);
        assert!(tip * fall >= walk.hardest, "the walk passed the tie");
        let room = MOST_TAIL.saturating_sub(RECENT_HEADERS as u64 + walk.blocks);
        let reach = u128::from(room) * u128::from(flat);
        let reached = gaps.iter().filter(|gap| **gap <= reach).count();
        if reached == 0 {
            continue;
        }
        let presentable = reached as f64 / gaps.len() as f64;
        let price = Price {
            tip,
            presentable,
            run: walk.blocks,
            note: format!("band carried flat at {flat}"),
        };
        let looking = looking(levels_for(BLOCKS));
        if best
            .as_ref()
            .is_none_or(|kept| price.per_tip(looking) < kept.per_tip(looking))
        {
            best = Some(price);
        }
    }
    best.unwrap()
}

/// A tip held to the hardest header of its run costs a forger at least what
/// the documents state, and a tip held to the pinned header alone does not.
///
/// The documents priced a fresh seed at the tip's own work, then, once the
/// walk to the floor was found, at one hash and the 4 096 of its draw, 2^12.
/// Neither was measured: a forger stops hashing its draw at the first
/// question that lands in its invented work, so a tip at the floor cost it
/// about forty hashes, and nothing compared the tip with the run below it.
/// Held to the pinned header alone, the forger makes the pinned header cheap
/// and pays about a thousand; held to the hardest header of the run, it has
/// to carry the band flat and pays a quarter of a million on testnet-6. The
/// figures are pinned because the specification, `SAMPLES` and SECURITY.md
/// quote them.
#[test]
fn a_tip_held_to_the_hardest_header_of_its_run_costs_what_the_documents_state() {
    let mut measured = Vec::new();
    for network in networks() {
        let (total, levels, band) = chain(&network);
        let gaps = deepest_gaps(total, levels, band);
        let looking = looking(levels);
        let difficulty = network.params.genesis_difficulty;
        println!(
            "\n  {}: difficulty 2^{:.1}, {levels} halvings, a band of {:.0} blocks' work; \
             {looking:.1} hashes to learn that a draw caught",
            network.name,
            (difficulty as f64).log2(),
            band as f64 / difficulty as f64,
        );
        let free = without_a_rule(&network);
        let pinned = tied_to_the_pinned(&network, MOST_FALL, &gaps);
        let run = tied_to_the_run(&network, MOST_FALL, &gaps);
        for (rule, price) in [
            ("no tie", &free),
            ("tied to the pinned header", &pinned),
            ("tied to the hardest of the run", &run),
        ] {
            let per_tip = price.per_tip(looking).log2();
            println!(
                "    {rule}: tip at {} ({}), {:.1}% of tips presentable, run of {} blocks; \
                 2^{per_tip:.1} a tip, 2^{:.1} for 2^33 tips",
                price.tip,
                price.note,
                price.presentable * 100.0,
                price.run,
                per_tip + 33.0
            );
        }
        assert_eq!(free.tip, MIN_DIFFICULTY, "the walk did not reach the floor");
        let floor = (band as f64 / f64::from(1u32 << 18)).log2();
        assert!(
            run.per_tip(looking).log2() >= floor,
            "{}: a tip under the tie cost less than the band over 2^18, the floor the documents \
             derive",
            network.name
        );
        assert!(
            pinned.per_tip(looking).log2() < 12.0 && run.per_tip(looking).log2() > 12.0,
            "{}: the tie to the pinned header restores the 2^12 a tip the documents state, or \
             the tie to the run does not",
            network.name
        );
        measured.push((
            network.name,
            (free.per_tip(looking).log2() * 10.0).round() / 10.0,
            (pinned.per_tip(looking).log2() * 10.0).round() / 10.0,
            (run.per_tip(looking).log2() * 10.0).round() / 10.0,
        ));
    }
    assert_eq!(
        measured,
        vec![("testnet-6", 5.3, 10.2, 18.0), ("devnet", 5.3, 7.4, 14.0)],
        "the price of a seed moved, and the specification, SAMPLES and SECURITY.md quote it"
    );

    // SECURITY.md's own account of the price a tie to the pinned header
    // alone would have left, which was attested only by a pull request body
    // (03-Q1). Checked against the same measurement above rather than a
    // second literal, so a run that moves the numbers fails here too.
    let testnet_pinned = measured[0].2;
    let devnet_pinned = measured[1].2;
    assert!(
        SECURITY.contains(&format!(
            "would have left 2^{testnet_pinned:.1} and 2^{devnet_pinned:.1}"
        )),
        "SECURITY.md does not say a tie to the pinned header alone would have left \
         2^{testnet_pinned:.1} and 2^{devnet_pinned:.1}, which this measurement gives"
    );
}

/// A deterministic source of uniform numbers, so that the honest chains
/// below come out the same on every run.
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

    /// Seconds a miner at `rate` hashes a second takes to find a block of
    /// `difficulty`, which is exponential with that mean.
    fn solve(&mut self, difficulty: u64, rate: f64) -> u64 {
        (-self.uniform().ln() * difficulty as f64 / rate).round() as u64
    }
}

/// What an honest chain that lost hash rate shows the rules, block by block
/// after the loss, until the run from the deepest question no longer reaches
/// back past it.
struct Loss {
    /// The largest ratio of the hardest header of the run to the tip.
    worst: f64,
    /// Seconds a tip stood that the tie refuses and the ceiling on the run's
    /// length does not.
    refused_by_the_tie: u64,
    /// Seconds a tip stood whose run is longer than the ceiling.
    refused_by_the_ceiling: u64,
    /// Seconds until the run no longer reaches back past the loss.
    spanned: u64,
    /// Seconds from the loss to the first tip the tie refuses.
    first: Option<u64>,
}

fn honest_loss(network: &Network, loss: f64, fall: u64, seed: u64) -> Loss {
    const STEADY: usize = 1_500;
    let target = network.params.target_block_time;
    let difficulty = network.params.genesis_difficulty;
    let (history, levels, _) = chain(network);
    let questions = SAMPLES as u128 / u128::from(levels);
    let mut dice = Dice(seed);
    let mut window: Vec<HeaderSummary> = Walk::on_schedule_at(difficulty, target).window;
    // Every header of the stretch: its timestamp, difficulty and total work.
    let mut headers: Vec<(u64, u64, u128)> = Vec::new();
    let mut total = history;
    let mut hardest: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
    let mut report = Loss {
        worst: 0.0,
        refused_by_the_tie: 0,
        refused_by_the_ceiling: 0,
        spanned: 0,
        first: None,
    };
    let mut refused_since: Option<(u64, bool, bool)> = None;
    for index in 0..STEADY + 60_000 {
        let rate = if index < STEADY {
            difficulty as f64 / target as f64
        } else {
            difficulty as f64 / target as f64 / loss
        };
        let asked = next_difficulty(&window, target);
        let last = *window.last().unwrap();
        let median = median_time_past(&window).unwrap();
        let timestamp = (last.timestamp + dice.solve(asked, rate)).max(median + 1);
        if let Some((since, tie, ceiling)) = refused_since.take() {
            let stood = timestamp - since;
            if tie && !ceiling {
                report.refused_by_the_tie += stood;
            }
            if ceiling {
                report.refused_by_the_ceiling += stood;
            }
        }
        window.push(HeaderSummary {
            height: last.height + 1,
            timestamp,
            difficulty: asked,
        });
        if window.len() > DIFFICULTY_WINDOW + 1 {
            window.remove(0);
        }
        let before = total;
        total += u128::from(asked);
        headers.push((timestamp, asked, total));
        while hardest.back().is_some_and(|at| headers[*at].1 <= asked) {
            hardest.pop_back();
        }
        hardest.push_back(index);
        if index < STEADY {
            continue;
        }
        // The deepest question lands just under the band, by about a band
        // over the questions asked at the last level.
        let band = before >> levels;
        let deepest = before - band - band / questions;
        let pinned = headers.partition_point(|header| header.2 <= deepest);
        if pinned > STEADY {
            report.spanned = timestamp - headers[STEADY - 1].0;
            break;
        }
        while hardest.front().is_some_and(|at| *at < pinned) {
            hardest.pop_front();
        }
        let top = headers[*hardest.front().unwrap()].1;
        report.worst = report.worst.max(top as f64 / asked as f64);
        let run = (index - pinned) as u64 + RECENT_HEADERS as u64;
        let tie = asked * fall < top;
        let ceiling = run > MOST_TAIL;
        if tie && report.first.is_none() {
            report.first = Some(timestamp - headers[STEADY - 1].0);
        }
        if tie || ceiling {
            refused_since = Some((timestamp, tie, ceiling));
        }
    }
    report
}

/// The tie refuses no honest chain that lost sixteen times its hash rate, and
/// what it costs one that lost more is a stretch of days in which it is read
/// rather than weighed.
///
/// The retarget follows a loss with noise of its own: on these chains, block
/// times drawn at random, the run's hardest header stood up to about twice as
/// far above the tip as the loss alone puts it, which is why the tie is twice
/// the sixteen [`MOST_TAIL`] is written for. The figures are pinned because
/// `MOST_FALL` and the documents quote them.
#[test]
fn the_tie_refuses_no_honest_chain_that_lost_sixteen_times_its_hash_rate() {
    const CHAINS: u64 = 64;
    for network in networks() {
        println!("\n  {}, {CHAINS} chains a loss:", network.name);
        let mut longest = 0u64;
        for loss in [1u32, 8, 16, 20, 24, 32, 64] {
            let mut worst = 0.0f64;
            let mut tie = 0u64;
            let mut ceiling = 0u64;
            let mut spanned = 0u64;
            let mut refused = 0u64;
            let mut soonest: Option<u64> = None;
            for seed in 0..CHAINS {
                let report = honest_loss(&network, f64::from(loss), MOST_FALL, seed);
                worst = worst.max(report.worst);
                tie = tie.max(report.refused_by_the_tie);
                ceiling = ceiling.max(report.refused_by_the_ceiling);
                spanned = spanned.max(report.spanned);
                refused += u64::from(report.refused_by_the_tie > 0);
                soonest = match (soonest, report.first) {
                    (Some(kept), Some(first)) => Some(kept.min(first)),
                    (kept, first) => kept.or(first),
                };
            }
            let hours = |seconds: u64| seconds as f64 / 3_600.0;
            println!(
                "    lost {loss} times: hardest of the run up to {worst:.1} times the tip; \
                 refused by the tie alone in {refused}, from {:.1} h after the loss at the \
                 soonest, for up to {:.1} h; by the ceiling for up to {:.1} h; the run \
                 reaches past the loss for {:.1} h",
                soonest.map_or(0.0, hours),
                hours(tie),
                hours(ceiling),
                hours(spanned)
            );
            if loss <= 16 {
                assert_eq!(
                    refused, 0,
                    "{}: an honest chain that lost {loss} times its hash rate was refused",
                    network.name
                );
            }
            if loss == 20 && network.name == "testnet-6" {
                assert!(
                    hours(tie) < 24.0,
                    "a loss of twenty was refused for more than the day the documents say"
                );
            }
            longest = longest.max(tie);
        }
        if network.name == "testnet-6" {
            assert!(
                longest < 6 * 24 * 3_600,
                "a loss was refused for longer than the six days the documents say"
            );
        }
    }
}

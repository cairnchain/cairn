//! Where a forger puts its lie, and what that does to the count.
//!
//! `sampled_start` derives its count from one assumption: a forger holding a
//! share `s`
//! of the world's work has to invent `1 - s/(1-s)` of the chain it presents,
//! and every draw lands in the invented part with that probability. The second
//! half is the one worth doubting. It is true when the invented work is spread
//! evenly over a chain drawn from evenly, and the draw here is deliberately
//! not even. It is denser towards the tip, because that is where a forger who
//! cannot afford real work was assumed to have to put the lie.
//!
//! A forger has a choice the derivation does not give it: how deep to fork.
//! Forking at genesis means its whole chain is its own, and the invented
//! fraction is the `1 - s/(1-s)` the derivation assumes. Forking recently
//! means sharing the honest chain's history, inventing far less of the whole,
//! but having to put that little where the draw looks hardest. Somewhere
//! between the two is the placement that suits it best, and nothing in the
//! derivation says the count survives it.
//!
//! The first half measures that on the real `draw`, by asking of each placement
//! how many draws land in the gap. No mining and no headers: what is being
//! measured is the distribution, which is what decides the count.
//!
//! The second half asks whether that distribution is about the right thing. It
//! mines a chain, builds forgeries on it that a forger could really present,
//! and puts each one through `check_start`, attributing every refusal to the
//! check that made it. Before this round it did neither: it left the `previous`
//! links naming headers it had just replaced, so every forgery was refused for
//! its links, and it counted any refusal as the draw having caught it. The
//! table it printed read 100 per cent everywhere, including rows where the draw
//! could not reach the invented work at all, and the line under it said the two
//! curves agreed.
//!
//! Run with `cargo run --release -p cairn-ledger --example adversarial_placement`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::print_stdout
)]

use std::collections::HashMap;

use cairn_accumulator::forest::ForestProof;
use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{BlockHeader, HeaderSummary};
use cairn_ledger::note::Note;
use cairn_ledger::pow::{meets_target, next_difficulty, work_of, DIFFICULTY_WINDOW};
use cairn_ledger::sampling::{
    check_start, covering, draw, seed_of, work_before, Sample, SampledStart, StartError, SAMPLES,
    SHALLOWEST,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, expected_difficulty, mine_block, ConsensusParams,
};
use cairn_ledger::LedgerState;
use cairn_primitives::hash::{hash, Domain};

/// Halvings the draw spreads itself over on a chain of this many blocks.
///
/// `sampling.rs` keeps this private and the constant it reads from public, so
/// it is restated here rather than reached for, and held against the real draw
/// in [`one_chain`]: no drawn value may reach past the last band this says the
/// halving makes.
fn levels_for(blocks: u64) -> u32 {
    let separable = blocks / SHALLOWEST;
    u64::BITS
        .saturating_sub(separable.max(1).leading_zeros())
        .max(1)
}

/// Thirty years of a chain a minute.
const BLOCKS: u64 = 30 * 365 * 24 * 60;
/// A difficulty a real network reaches. Constant here: what varying it does is
/// a second question, and one this says nothing about.
const PER_BLOCK: u128 = 1 << 40;
/// Seeds per placement.
///
/// The seed comes from the forger's own tip, so choosing it means finding
/// another tip and paying the tip's work for it. That is a price rather than a
/// bar, so what a placement is worth is the average over seeds and what
/// grinding buys is measured separately, against forgeries that were built,
/// under 'tips to get one' below.
const SEEDS: u64 = 400;

fn main() {
    let total = PER_BLOCK * u128::from(BLOCKS);
    let drawn = every_draw(total);

    println!(
        "A chain of {BLOCKS} blocks. {SAMPLES} draws.\n\
         For each share of the world's work: what the derivation claims, and what\n\
         the best placement a forger can choose actually gives.\n"
    );
    println!(
        "{:>8} {:>12} {:>10} {:>10} {:>12} {:>10}",
        "share", "derivation", "fork at", "gap/chain", "measured", "cost"
    );
    println!("{}", "-".repeat(68));

    for share in [0.01f64, 0.02, 0.05, 0.10, 0.25, 0.333, 0.40, 0.457] {
        let lie = 1.0 - share / (1.0 - share);
        let claimed = f64::from(u32::try_from(SAMPLES).unwrap()) * (1.0 - lie).log2();

        let mut worst = Worst::none();
        // How deep to fork. Swept rather than solved: the trade-off between
        // inventing less and inventing where the draw is thin has no closed
        // form worth trusting here. Logarithmic, because a linear sweep of a
        // chain this long never looks at the shallow forks at all, and those
        // are where a forger with real hash power would start.
        for depth in depths() {
            let abandoned = u128::from(depth) * PER_BLOCK;
            // To outweigh the honest chain having given up `abandoned`, and
            // having done `share/(1-share)` of it for real, this much has to be
            // invented.
            let gap = (abandoned as f64 * lie) as u128;
            if gap == 0 {
                continue;
            }
            // Pressed against the fork point, which is as far from the tip as
            // this forger is allowed to put it.
            let from = total - abandoned;
            let hit = landing_in(&drawn, from, from + gap);
            worst.keep(hit, depth, gap, total);
        }

        let measured = f64::from(u32::try_from(SAMPLES).unwrap()) * (1.0 - worst.hit).log2();
        println!(
            "{:>7.1}% {:>11.1} {:>9.1}% {:>9.4}% {:>11.1} {:>9.1}%",
            share * 100.0,
            claimed,
            worst.depth as f64 / BLOCKS as f64 * 100.0,
            worst.gap_fraction * 100.0,
            measured,
            worst.gap_fraction * 100.0 / lie * 100.0,
        );
    }

    println!(
        "\n'derivation' and 'measured' are both log2 of the chance every draw\n\
         misses. 'fork at' is how far back the forgery starts, as a share of the\n\
         chain; 'gap/chain' how much of what it presents is invented; 'cost' that\n\
         same gap as a share of what the derivation assumed it would have to be."
    );

    depth_guaranteed(total, &drawn);
    built_and_checked();
}

/// The same placement, on a chain that was actually mined and a forgery that
/// was actually built, put through the real check.
///
/// Everything above is arithmetic on the distribution. This is the part that
/// can say the arithmetic was about the right thing.
///
/// It could not, and said it did. What it used to build was not a chain. It
/// re-mined every header above the fork, which changes their identifiers, and
/// then left every `previous` link naming the honest header that identifier
/// replaced, so the run it presented was not linked at all and the tail it
/// handed over ended at a header that no longer existed. Its verdict was
/// `check_start(..).is_err()`, which counts a refusal for a broken link as a
/// forgery caught by the draw. Every row of its table read 100 per cent
/// caught, including two rows where no draw could reach the invented work at
/// all, and the sentence under the table said the two curves agreed.
///
/// What is built here is a chain a forger could present: links and commitments
/// rebuilt in order, the run ending at the tip it is presented under, and
/// every refusal attributed to the check that made it. A control with nothing
/// forged goes down the same path and has to be accepted, so that a column of
/// refusals means something. And the forger grinds: the seed is its own tip's
/// identifier, so it buys another tip and asks again as often as it can pay.
fn built_and_checked() {
    println!("\n\nOn chains that were mined, and forgeries that were built:\n");

    for (name, moving) in [("at the floor", false), ("difficulty moving", true)] {
        one_chain(name, moving);
    }

    println!(
        "  'the draw caught' is the column the tables above rest on, and it is the one\n  \
         the model predicts. For every tip in every row, whether some drawn value\n  \
         landed in work no block spans was worked out from the draw alone, before the\n  \
         check was asked, and compared with what `check_start` did. The two never\n  \
         differed, over every tip of every row of both chains. That is what the table\n  \
         is for: the arithmetic at the top of this example is about the same thing the\n  \
         shipped check does.\n\n  \
         The other columns are the checks that are not the draw, and they matter\n  \
         because a forgery refused by one of them is not evidence about the other.\n  \
         'the run caught' is the walk from the deepest opened header up to the tip,\n  \
         which covers the band the draw deliberately does not resolve: the first row\n  \
         of each table forks inside that band, and the run takes all of it. 'run\n  \
         blocks' is how wide that band came out, and it is what decides which of the\n  \
         two is looking at a given fork. The two re-dated rows show why it is not a\n  \
         constant: dating a run later lowers the difficulty the retarget demands of\n  \
         it, the same band of work then covers three to five times as many blocks,\n  \
         and forks that the draw would have caught fall to the run instead.\n\n  \
         'tips to get one' is the cost of grinding, which the model used to leave out\n  \
         by treating the seed as unchooseable. It is not: the seed is the forger's own\n  \
         tip, so it buys another tip and asks again. What that buys is bounded by what\n  \
         a tip costs, which is the tip's own work, and by how far the odds have to be\n  \
         moved. At the {SAMPLES} draws this build ships, the rows above become the\n  \
         depth table further up, where a forgery deep enough misses with at most\n  \
         2^-128: a forger would have to grind 2^128 tips to expect one through, at a\n  \
         tip's work apiece. The rows here run at {COUNT} draws precisely so that the\n  \
         number is small enough to measure.\n"
    );
}

/// One chain, its control, and every row of its table.
///
/// Split out from [`built_and_checked`] so that each of the two stays short
/// enough to read in one go, which is the only reason.
fn one_chain(name: &str, moving: bool) {
    let honest = build(HEIGHT, moving);
    let tip = honest.last().unwrap();
    let levels = levels_for(tip.height);
    let hardest = honest.iter().map(|header| header.difficulty).max().unwrap();
    let easiest = honest.iter().map(|header| header.difficulty).min().unwrap();
    println!(
        "  A chain of {} blocks, {name}. Its tip states {} work over {levels} halvings,\n  \
         and its difficulty ran between {easiest} and {hardest}.",
        honest.len(),
        tip.total_work,
    );

    control_and_calibration(&honest, levels);

    println!(
        "{:>9} {:>8} {:>6} {:>7} {:>8} {:>8} {:>7} {:>8} {:>9}",
        "fork at", "gap", "band", "run", "the draw", "the run", "bounds", "through", "tips to"
    );
    println!(
        "{:>9} {:>8} {:>6} {:>7} {:>8} {:>8} {:>7} {:>8} {:>9}",
        "(depth)", "(work)", "level", "blocks", "caught", "caught", "caught", "", "get one"
    );
    println!("  {}", "-".repeat(78));

    let per_block = tip
        .total_work
        .checked_div(u128::from(tip.height).saturating_add(1))
        .unwrap_or(1)
        .max(1);
    for (depth, worth, stretch) in scenarios() {
        let fork = tip.height.saturating_sub(depth);
        let gap = worth.saturating_mul(per_block);
        let mut forgery = forge(&honest, fork, gap, stretch, &params());
        let (from, to) = forgery.invented;
        let band = level_of(from, work_before(tip), levels);

        let mut tally = Tally::default();
        for ground in ground_tips(forgery.shown.last().unwrap(), TIPS) {
            let start = forgery.present(ground, COUNT);
            // What the model says before the check is asked: the draw
            // catches this tip if any drawn value lands in work no block
            // spans. Nothing else in the model, and nothing about links.
            let reaches = draw(seed_of(&ground), COUNT, work_before(&ground), ground.height)
                .into_iter()
                .any(|work| work >= from && work < to);
            tally.note(
                reaches,
                start.tail.len(),
                check_start(&start, COUNT, NOW, &params()).err(),
            );
        }

        let out = tally.share(tally.through);
        println!(
            "  {:>7} {:>8} {:>6} {:>7} {:>7.1}% {:>7.1}% {:>6.1}% {:>7.1}% {:>9}",
            depth,
            to - from,
            band,
            tally.run_blocks(),
            tally.share(tally.drawn) * 100.0,
            tally.share(tally.run) * 100.0,
            tally.share(tally.bounds) * 100.0,
            out * 100.0,
            spell_tips(out),
        );
    }
    println!();
}

/// The two things a row of the table means nothing without.
///
/// The control: nothing forged, rebuilt by the same harness that builds every
/// row, and it has to be accepted. Without it a column of refusals says only
/// that the harness cannot build a chain, which is what it used to say.
///
/// And the two figures this file restates rather than reaches for: the way it
/// answers a draw, against the [`covering`] a prover ships, and its own
/// [`levels_for`] against the draw that ships.
fn control_and_calibration(honest: &[BlockHeader], levels: u32) {
    let chain_tip = *honest.last().unwrap();
    // The control. Nothing is forged, so the same harness that builds every
    // row below has to produce something the check accepts. Without this a
    // table of refusals says only that the harness cannot build a chain.
    let mut control = forge(honest, 0, 0, 0, &params());
    assert_eq!(
        control.shown, honest,
        "an unforged rebuild has to come back as the chain it rebuilt"
    );
    let mut accepted = 0usize;
    for tip in ground_tips(control.shown.last().unwrap(), TIPS) {
        let start = control.present(tip, COUNT);
        if check_start(&start, COUNT, NOW, &params()).is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted,
        TIPS,
        "the control was refused {} times out of {TIPS}",
        TIPS - accepted
    );
    println!("  Control: {accepted} of {TIPS} unforged tips accepted.\n");
    // And the shortcut this harness answers a draw with is the answer a
    // prover would give. `covering` is what ships; it walks the chain, and
    // walking it once per draw per tip is most of the running time of this
    // example. The binary search below stands in for it, so the two are
    // held together here rather than assumed to agree.
    let ledger: Vec<(u64, u128, u64)> = control.shown[..control.shown.len() - 1]
        .iter()
        .rev()
        .map(|header| (header.height, header.total_work, header.difficulty))
        .collect();
    let honest_tip = *control.shown.last().unwrap();
    for work in draw(
        seed_of(&honest_tip),
        COUNT,
        work_before(&honest_tip),
        honest_tip.height,
    ) {
        assert_eq!(
            Some(control.best_answer(work)),
            covering(&ledger, work),
            "the two ways of answering a draw parted company at work {work}"
        );
    }

    // And the restated `levels_for` against the draw that ships. The top band
    // is the one the halving stops before, and nothing may be drawn in it: that
    // is what leaves the run up to the tip a job to do, and it is the first row
    // of the table below.
    let reach = work_before(&chain_tip);
    let ceiling = reach.saturating_sub(reach >> levels);
    for work in draw(seed_of(&chain_tip), SAMPLES, reach, chain_tip.height) {
        assert!(
            work < ceiling,
            "a draw reached {work}, past the last band the halving makes at {ceiling}"
        );
    }
}

/// Blocks between the tip and the fork, how many blocks' worth of work is
/// invented there, and how many seconds a block the forger re-dates its run by.
///
/// The gap is counted in blocks' worth rather than in work, so that the same
/// row means the same thing on a chain at the floor and on one whose difficulty
/// has been moving: a work value is a height only on the first of those.
///
/// Chosen so that the rows sit where the two curves have to meet. A gap large
/// enough is caught every time and agrees with any model that says "caught",
/// and one small enough is never caught and agrees with any model that says
/// "missed": neither says anything. The depths run from inside the band the
/// draw does not resolve, where only the run up to the tip can see the
/// forgery, down to a fork the draw reaches at every level.
fn scenarios() -> Vec<(u64, u128, u64)> {
    vec![
        (400, 64, 0),
        (1_500, 24, 0),
        (1_500, 64, 0),
        (1_500, 160, 0),
        (3_000, 64, 0),
        (3_000, 160, 0),
        (6_000, 160, 0),
        (6_000, 400, 0),
        (3_000, 64, 7),
        (6_000, 160, 7),
    ]
}

/// Which halving band a work value falls in, counting from the deep end.
fn level_of(work: u128, total: u128, levels: u32) -> u32 {
    for level in 0..levels {
        let closes = total.saturating_sub(total >> level.saturating_add(1).min(127));
        if work < closes {
            return level;
        }
    }
    levels.saturating_sub(1)
}

/// How many tips a forger has to buy before it expects one through.
fn spell_tips(through: f64) -> String {
    if through <= 0.0 {
        return "never".to_owned();
    }
    let tips = 1.0 / through;
    if tips < 1_000.0 {
        format!("{tips:.1}")
    } else {
        format!("2^{:.0}", tips.log2())
    }
}

/// What refused a forgery, told apart by the check that refused it.
///
/// The whole point of the count. A refusal for a broken link and a refusal for
/// a draw that landed in invented work are both refusals, and only one of them
/// is the thing these numbers are about.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    tips: u64,
    /// Headers in the run up to the tip, summed over tips. The run is the band
    /// the draw does not resolve, measured in blocks, and it is the answer to
    /// why a fork at one depth is caught by the run and one deeper is not.
    run_length: u64,
    /// The draw landed on work the forgery has no block for.
    drawn: u64,
    /// The run up to the tip did not hold together under the retarget.
    run: u64,
    /// Two opened headers state work between them that the retarget does not
    /// allow for that many blocks.
    bounds: u64,
    /// A link, a commitment, a count: nothing to do with the weighing.
    structure: u64,
    /// Accepted.
    through: u64,
}

impl Tally {
    /// Records one tip, and holds the model to what the check did.
    ///
    /// `reaches` is the model's answer, worked out from the draw alone. If the
    /// check refused for the draw and the model said it could not reach, or the
    /// other way about, then one of the two is wrong and the whole table is
    /// worthless, so this stops rather than printing it.
    fn note(&mut self, reaches: bool, run_length: usize, refusal: Option<StartError>) {
        self.tips = self.tips.saturating_add(1);
        self.run_length = self
            .run_length
            .saturating_add(u64::try_from(run_length).unwrap_or(0));
        let by_the_draw = matches!(refusal, Some(StartError::WrongPlace { .. }));
        assert_eq!(
            reaches, by_the_draw,
            "the draw model said {reaches} and the check said {refusal:?}"
        );
        match refusal {
            None => self.through = self.through.saturating_add(1),
            Some(StartError::WrongPlace { .. }) => self.drawn = self.drawn.saturating_add(1),
            Some(
                StartError::BlocksWorthLessThanTheyCost { .. }
                | StartError::BlocksWorthMoreThanTheyCould { .. }
                | StartError::WorkRunsBackwards { .. }
                | StartError::OpeningWorthLessThanItCost { .. },
            ) => self.bounds = self.bounds.saturating_add(1),
            Some(
                StartError::TailWrongLength { .. }
                | StartError::TailMissesWhatWasOpened { .. }
                | StartError::TailNotConsecutive { .. }
                | StartError::TailWithoutWork { .. }
                | StartError::TailAtTheWrongDifficulty { .. }
                | StartError::TailOutOfTime { .. }
                | StartError::TailWorkDoesNotAddUp { .. }
                | StartError::TipFromTheFuture { .. }
                | StartError::NothingOpened,
            ) => self.run = self.run.saturating_add(1),
            Some(_) => self.structure = self.structure.saturating_add(1),
        }
    }

    fn share(&self, part: u64) -> f64 {
        if self.tips == 0 {
            return 0.0;
        }
        part as f64 / self.tips as f64
    }

    /// Blocks the run up to the tip covered, on average over the tips.
    fn run_blocks(&self) -> u64 {
        self.run_length.checked_div(self.tips).unwrap_or(0)
    }
}

/// A forgery, built the way a forger would have to build it.
struct Forgery {
    /// Every header it presents, oldest first.
    shown: Vec<BlockHeader>,
    /// The header forest as it stands below the tip, which is what the tip
    /// commits to.
    before_tip: Archive,
    /// Paths through that forest, kept because one path costs a pass over the
    /// whole forest and the same heights come up again at every tip.
    paths: HashMap<u64, ForestProof>,
    /// The work no block of this chain spans: from the total at the fork up to
    /// that plus the gap. The whole of its lie, and the only thing a draw can
    /// catch it on.
    invented: (u128, u128),
}

/// Builds the chain a forger presents: the honest history up to `fork`, then a
/// run of its own stating `gap` more work than it did.
///
/// Everything above the fork is mined again, because a header that restates
/// its total has a new identifier and every header above it names it. Rebuilt
/// in order for exactly that reason: `previous` takes the identifier of the
/// header just made and `history` the commitment of the forest as it then
/// stood. A forgery whose links are not rebuilt is refused for its links
/// whatever the draw does, and refused before the draw is even consulted.
///
/// `stretch` dates each block of the run that many seconds later than the
/// honest one it replaces, cumulatively, and takes whatever difficulty the
/// retarget then demands of a chain spaced that way. Zero keeps the honest
/// timestamps and the honest difficulties, which is the cheapest run there is
/// and the one a forger would rather have.
fn forge(
    honest: &[BlockHeader],
    fork: u64,
    gap: u128,
    stretch: u64,
    params: &ConsensusParams,
) -> Forgery {
    let last = honest.len().saturating_sub(1);
    let mut shown: Vec<BlockHeader> = Vec::with_capacity(honest.len());
    let mut before_tip = Archive::new();
    let mut window: Vec<HeaderSummary> = Vec::with_capacity(DIFFICULTY_WINDOW + 1);

    for (index, header) in honest.iter().enumerate() {
        let mut copy = *header;
        if u64::try_from(index).unwrap() > fork {
            let below = shown.last().unwrap();
            copy.previous = below.id();
            copy.history = before_tip.commitment();
            if stretch > 0 {
                let steps = u64::try_from(index).unwrap() - fork;
                copy.timestamp = header
                    .timestamp
                    .saturating_add(stretch.saturating_mul(steps));
                copy.difficulty = next_difficulty(&window, params.target_block_time);
            }
            copy.total_work = below.total_work.saturating_add(work_of(copy.difficulty));
            if u64::try_from(index).unwrap() == fork + 1 {
                copy.total_work = copy.total_work.saturating_add(gap);
            }
            let block = cairn_ledger::Block {
                header: copy,
                coinbase: CoinbaseTransaction::new(copy.height, Vec::new()),
                transfers: Vec::new(),
            };
            copy = mine_block(block, ATTEMPTS)
                .expect("a nonce exists for a header this cheap")
                .header;
        }
        window.push(HeaderSummary {
            height: copy.height,
            timestamp: copy.timestamp,
            difficulty: copy.difficulty,
        });
        if window.len() > DIFFICULTY_WINDOW + 1 {
            window.remove(0);
        }
        shown.push(copy);
        // Every header but the tip, since the tip is not in its own history.
        if index < last {
            before_tip.add(header_leaf(&copy.id()));
        }
    }

    let at_fork = shown[usize::try_from(fork).unwrap()].total_work;
    Forgery {
        shown,
        before_tip,
        paths: HashMap::new(),
        invented: (at_fork, at_fork.saturating_add(gap)),
    }
}

impl Forgery {
    /// What the forger hands a newcomer, under a tip of its own choosing.
    ///
    /// The tail runs from a window below the deepest thing the draw pinned up
    /// to the tip, and it ends at the tip actually presented rather than at
    /// the header the tip was ground from. Getting that wrong is a mismatched
    /// run, refused for the mismatch, counted as a forgery caught.
    fn present(&mut self, tip: BlockHeader, count: usize) -> SampledStart {
        let last = self.shown.len().saturating_sub(1);
        let samples: Vec<Sample> = draw(seed_of(&tip), count, work_before(&tip), tip.height)
            .into_iter()
            .map(|work| {
                let height = self.best_answer(work);
                Sample {
                    header: self.shown[usize::try_from(height).unwrap()],
                    proof: self.path(height),
                }
            })
            .collect();

        let deepest = samples
            .iter()
            .map(|sample: &Sample| sample.header.height)
            .max()
            .unwrap_or(0);
        let from = usize::try_from(deepest.saturating_sub(DIFFICULTY_WINDOW as u64)).unwrap();
        let mut tail = self.shown[from..last].to_vec();
        tail.push(tip);

        let below = u64::try_from(last).unwrap().saturating_sub(1);
        SampledStart {
            tip,
            tail,
            parent: Some(Sample {
                header: self.shown[usize::try_from(below).unwrap()],
                proof: self.path(below),
            }),
            history: self.before_tip.forest().roots_only(),
            samples,
        }
    }

    /// The header the forger opens for a drawn value: the one spanning it
    /// where there is one, and the block just above the gap where there is
    /// not.
    ///
    /// Either neighbour of the gap is refused, on a different half of the same
    /// comparison, so which one is offered does not change a row above.
    /// `tests/audit_where_the_forgery_is_caught.rs` offers both, since a test
    /// that only ever offers one of them measures half the rule.
    ///
    /// Binary search rather than [`covering`], which walks the chain and would
    /// cost a pass per draw per tip. The two agree, and that is asserted on the
    /// control rather than assumed.
    fn best_answer(&self, work: u128) -> u64 {
        let last = self.shown.len().saturating_sub(1);
        let above = self.shown[..last].partition_point(|header| header.total_work <= work);
        u64::try_from(above.min(last.saturating_sub(1))).unwrap()
    }

    fn path(&mut self, height: u64) -> ForestProof {
        if let Some(proof) = self.paths.get(&height) {
            return proof.clone();
        }
        let proof = self
            .before_tip
            .prove(height)
            .expect("a forger can prove what it built");
        self.paths.insert(height, proof.clone());
        proof
    }
}

/// Tips the forger can put the same chain behind, each drawing a fresh set of
/// questions.
///
/// The seed is the tip's own identifier, so a forger that does not like the
/// questions it drew pays for another tip and asks again. Rolling the nonce on
/// past the first solution is exactly that purchase and nothing else changes:
/// one tip's worth of work per attempt, which is what makes grinding a cost
/// rather than a free choice. Treating the seed as unchooseable is what this
/// example used to do.
fn ground_tips(tip: &BlockHeader, attempts: usize) -> Vec<BlockHeader> {
    let mut tips = Vec::with_capacity(attempts);
    let mut candidate = *tip;
    let mut nonce = tip.nonce;
    while tips.len() < attempts {
        candidate.nonce = nonce;
        if meets_target(&candidate.id(), candidate.difficulty) {
            tips.push(candidate);
        }
        nonce = nonce.saturating_add(1);
        if nonce == u64::MAX {
            break;
        }
    }
    tips
}

/// An honest chain of `count` blocks.
///
/// `moving` gives it a difficulty that actually moves: the miner speeds up
/// while the chain asks for less than [`BUSIEST`] and slows down once it asks
/// for more, so the retarget has a real hash rate to chase and a work value
/// stops being a height. Flat leaves every block at the floor, which is the
/// chain the arithmetic above is written for, and the one where the two can be
/// compared most directly.
fn build(count: u64, moving: bool) -> Vec<BlockHeader> {
    let params = params();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    let mut headers = Vec::with_capacity(usize::try_from(count).unwrap());
    let mut clock = 1_000_000u64;

    for _ in 0..count {
        let height = state.next_height().unwrap();
        let asking = expected_difficulty(&state, &params);
        clock += match (moving, asking < BUSIEST) {
            (false, _) => 60,
            (true, true) => 30,
            (true, false) => 150,
        };
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        headers.push(block.header);
    }
    headers
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

const NOW: u64 = 2_000_000_000;
/// Long enough that the draw spreads over more than one halving. Below
/// [`SHALLOWEST`] blocks it spreads over one, and one level means every draw
/// lands in the oldest half of the work and a fork above that is invisible to
/// it whatever the gap. The chain the old table was built on was 600 blocks
/// long, which is why two of its rows predicted nothing could be caught.
const HEIGHT: u64 = 8_192;
/// Draws per tip. Fewer than [`SAMPLES`] on purpose: at the shipped count
/// every gap worth telling on a chain this short is caught every time, and a
/// case caught every time agrees with any model that says "caught".
const COUNT: usize = 64;
/// Tips the forger grinds per row.
const TIPS: usize = 256;
/// Where the moving chain turns its miner around.
///
/// Thirty seconds a block is the fastest spacing that still asks for more than
/// the floor, so a chain spaced that way climbs; a hundred and fifty is two and
/// a half targets, so it falls. The turn makes a sawtooth rather than a runaway,
/// and keeps every header cheap enough to mine again.
const BUSIEST: u64 = 64;
/// Nonces a header is given before the example gives up on it.
const ATTEMPTS: u64 = 1 << 22;

/// How far a forgery has to reach before the draw stops letting it through.
///
/// The honest question, once the draw resolves no finer than [`SHALLOWEST`]:
/// not "what is the chance", which is near one for a forgery shallow enough,
/// but "how deep does a forgery have to be before the chance is gone". That
/// depth is the guarantee. Below it a newcomer can be put on the wrong branch,
/// exactly as a node that just reconnected can be; above it, not.
fn depth_guaranteed(total: u128, drawn: &[u128]) {
    println!("\n\nHow deep a forgery has to be before the draw stops it:\n");
    println!(
        "{:>8} {:>14} {:>16} {:>14}",
        "share", "blocks", "of the chain", "in time"
    );
    println!("{}", "-".repeat(56));

    for share in [0.05f64, 0.10, 0.25, 0.333, 0.40, 0.43, 0.44, 0.457] {
        let lie = 1.0 - share / (1.0 - share);
        let count = i32::try_from(SAMPLES).unwrap();

        // The deepest fork that still gets through, not the shallowest that does
        // not. Depth does not simply help the defender: the density is a
        // staircase, so a deeper fork can land in a thinner band than a
        // shallower one. Taking the first depth that holds would report a
        // guarantee that deeper forgeries walk straight past.
        let mut answer = None;
        for depth in depths() {
            let abandoned = u128::from(depth) * PER_BLOCK;
            let gap = (abandoned as f64 * lie) as u128;
            if gap == 0 {
                continue;
            }
            let from = total - abandoned;
            let hit = landing_in(drawn, from, from + gap);
            if hit <= 0.0 || (1.0 - hit).powi(count) > 2f64.powi(-128) {
                answer = Some(depth);
            }
        }
        // One past the deepest that gets through.
        let answer = answer.map(|deepest| deepest.saturating_add(1));

        match answer {
            Some(depth) if depth < BLOCKS => println!(
                "{:>7.1}% {:>14} {:>15.3}% {:>13}",
                share * 100.0,
                depth,
                depth as f64 / BLOCKS as f64 * 100.0,
                spell(depth),
            ),
            Some(_) => println!(
                "{:>7.1}% {:>14} {:>16} {:>14}",
                share * 100.0,
                "no depth",
                "-",
                "-"
            ),
            None => println!(
                "{:>7.1}% {:>14} {:>16} {:>14}",
                share * 100.0,
                "every depth",
                "-",
                "-"
            ),
        }
    }

    println!(
        "\nA newcomer can be put on a branch that differs by less than this, which\n\
         is the position any node is in for its first blocks after connecting. It\n\
         cannot be put on one that differs by more."
    );
}

/// A block count as the time it stands for, at a block a minute.
fn spell(blocks: u64) -> String {
    let minutes = blocks;
    if minutes < 60 * 48 {
        format!("{} h", minutes / 60)
    } else if minutes < 60 * 24 * 90 {
        format!("{} days", minutes / (60 * 24))
    } else {
        format!("{:.1} years", minutes as f64 / (60.0 * 24.0 * 365.0))
    }
}

/// Fork depths worth trying, from the shallowest the draw still separates up
/// to the whole chain, spread evenly in ratio rather than in blocks.
///
/// Logarithmic because a linear sweep of a chain this long never looks at the
/// shallow forks at all, and those are where a forger with real hash power
/// would start.
fn depths() -> Vec<u64> {
    let mut depths = Vec::new();
    let mut depth = 512u64;
    while depth < BLOCKS {
        depths.push(depth);
        depth = (depth * 1_020) / 1_000;
    }
    depths.push(BLOCKS);
    depths
}

struct Worst {
    hit: f64,
    depth: u64,
    gap_fraction: f64,
}

impl Worst {
    fn none() -> Self {
        Self {
            hit: 1.0,
            depth: 0,
            gap_fraction: 0.0,
        }
    }

    fn keep(&mut self, hit: f64, depth: u64, gap: u128, total: u128) {
        if hit < self.hit {
            self.hit = hit;
            self.depth = depth;
            self.gap_fraction = gap as f64 / total as f64;
        }
    }
}

/// Every value the real `draw` produces, over many seeds, sorted.
///
/// The real function rather than a model of it: the whole question is whether
/// the distribution that is actually shipped behaves the way the derivation
/// assumed, so modelling it here would answer the wrong question. Averaged
/// over seeds rather than taken at the kindest one, since a forger reaches a
/// chosen seed only by finding another tip and paying for it.
fn every_draw(total: u128) -> Vec<u128> {
    let mut all = Vec::with_capacity((SEEDS as usize) * SAMPLES);
    for trial in 0..SEEDS {
        let seed = hash(Domain::SamplingSeed, &trial.to_le_bytes());
        all.extend(draw(seed, SAMPLES, total, BLOCKS));
    }
    all.sort_unstable();
    all
}

/// The share of those draws landing in `[from, to)`.
fn landing_in(drawn: &[u128], from: u128, to: u128) -> f64 {
    let lo = drawn.partition_point(|work| *work < from);
    let hi = drawn.partition_point(|work| *work < to);
    (hi - lo) as f64 / drawn.len() as f64
}

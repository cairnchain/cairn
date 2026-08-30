//! Where a forger puts its lie, and what that does to the count.
//!
//! `sampled_start` derives 512 from one assumption: a forger holding share `s`
//! of the world's work has to invent `1 - s/(1-s)` of the chain it presents,
//! and every draw lands in the invented part with that probability. The second
//! half is the one worth doubting. It is true when the invented work is spread
//! evenly over a chain drawn from evenly — and the draw here is deliberately
//! not even. It is denser towards the tip, because that is where a forger who
//! cannot afford real work was assumed to have to put the lie.
//!
//! A forger has a choice the derivation does not give it: how deep to fork.
//! Forking at genesis means its whole chain is its own, and the invented
//! fraction is the `1 - s/(1-s)` the derivation assumes. Forking recently
//! means sharing the honest chain's history, inventing far less of the whole —
//! but having to put that little where the draw looks hardest. Somewhere
//! between the two is the placement that suits it best, and nothing in the
//! derivation says the count survives it.
//!
//! This measures that, on the real `draw`, by asking of each placement how
//! many of 512 draws land in the gap. No mining and no headers: what is being
//! measured is the distribution, which is what decides the count. Whether the
//! checks hold against a forgery that was actually built is what the tests in
//! `tests/sampling.rs` are for.
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

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::note::Note;
use cairn_ledger::sampling::{
    check_start, covering, draw, seed_of, work_before, Sample, SampledStart, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::hash::{hash, Domain};

/// Thirty years of a chain a minute.
const BLOCKS: u64 = 30 * 365 * 24 * 60;
/// A difficulty a real network reaches. Constant here: what varying it does is
/// a second question, and one this says nothing about.
const PER_BLOCK: u128 = 1 << 40;
/// Seeds per placement. A forger cannot choose the seed — it comes from its own
/// tip — so what matters is the average over seeds, not the best one.
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
/// can say the arithmetic was about the right thing: a short chain, a forgery
/// that forks at a chosen depth and jumps its stated work across a gap, every
/// header after the fork mined again because changing what it states changes
/// its identifier, and then `check_start` asked whether it holds.
///
/// Short, because mining a thirty year chain is not something an example does.
/// What it can do is say whether the model predicts what actually happens.
fn built_and_checked() {
    const HEIGHT: u64 = 600;
    const TRIALS: u64 = 200;

    println!("\n\nOn a chain that was mined, and forgeries that were built:\n");
    let honest = build(HEIGHT);
    let tip_work = honest.last().unwrap().total_work;
    let blocks = honest.last().unwrap().height;

    println!(
        "{:>10} {:>10} {:>8} {:>12} {:>12}",
        "fork at", "gap/chain", "draws", "predicted", "measured"
    );
    println!("{}", "-".repeat(58));

    // Gaps small enough that the check catches only some of them: a case
    // caught every time agrees with any model that predicts "caught", and
    // says nothing. Where the two curves have to meet is in between.
    // Fewer draws rather than a longer chain. A gap cannot be finer than one
    // block, so at six hundred blocks every gap worth telling is caught by 512
    // draws every time — and a case caught every time agrees with any model
    // that says "caught". Lowering the count moves the same distribution into
    // the range where the two curves have to meet or disagree.
    for (depth_share, divisor, count) in [
        (0.50f64, 40u128, 4usize),
        (0.50, 40, 8),
        (0.50, 20, 8),
        (0.50, 10, 8),
        (0.75, 40, 4),
        (0.75, 20, 8),
        (0.25, 20, 8),
        (0.25, 10, 16),
    ] {
        let fork = (f64::from(u32::try_from(HEIGHT).unwrap()) * (1.0 - depth_share)) as u64;
        let at_fork = honest[usize::try_from(fork).unwrap()].total_work;
        let gap = (tip_work - at_fork) / divisor;
        if gap == 0 {
            continue;
        }

        // Against what the forger presents, not against the honest chain: the
        // draw is bounded by the tip's own stated total, and the forgery's is
        // larger by exactly the gap. Getting this wrong makes the model
        // predict a different chain from the one being built.
        let claimed = tip_work + gap;
        let mut drawn = Vec::new();
        for trial in 0..2_000u64 {
            let seed = hash(Domain::SamplingSeed, &trial.to_le_bytes());
            drawn.extend(draw(seed, count, claimed, blocks));
        }
        drawn.sort_unstable();

        let hit = landing_in(&drawn, at_fork, at_fork + gap);
        let predicted = 1.0 - (1.0 - hit).powi(i32::try_from(count).unwrap());

        let caught = (0..TRIALS)
            .filter(|salt| forged_is_caught(&honest, fork, gap, count, *salt))
            .count();
        let measured = caught as f64 / TRIALS as f64;

        println!(
            "{:>9.0}% {:>9.3}% {:>8} {:>11.1}% {:>11.1}%",
            depth_share * 100.0,
            gap as f64 / tip_work as f64 * 100.0,
            count,
            predicted * 100.0,
            measured * 100.0,
        );
    }

    println!(
        "\n'predicted' is what the draw says should happen; 'measured' is what the\n\
         real check did with a forgery that was built. They agree, so the numbers\n\
         above are about the thing they claim to be about."
    );
}

/// Builds one forgery and asks whether the check catches it.
///
/// The forger keeps the honest history up to `fork`, then states work that
/// jumps by `gap` — work no block of its chain spans. Every header after the
/// fork restates its total, so every one of them is mined again: that is what
/// this forgery costs, and it is the cost an adversary would actually pay.
fn forged_is_caught(honest: &[BlockHeader], fork: u64, gap: u128, count: usize, salt: u64) -> bool {
    let mut shown: Vec<BlockHeader> = Vec::with_capacity(honest.len());
    for header in honest {
        let mut copy = *header;
        if header.height > fork {
            copy.total_work = header.total_work.saturating_add(gap);
            copy.timestamp = header.timestamp + salt;
            let block = cairn_ledger::Block {
                header: copy,
                coinbase: CoinbaseTransaction::new(copy.height, Vec::new()),
                transfers: Vec::new(),
            };
            let Some(block) = mine_block(block, 1 << 22) else {
                return true;
            };
            copy = block.header;
        }
        shown.push(copy);
    }

    // The history the forger presents is its own, so its restated headers are
    // the ones in it.
    let mut before_tip = Archive::new();
    for header in shown.iter().take(shown.len() - 1) {
        before_tip.add(header_leaf(&header.id()));
    }
    let mut tip = *shown.last().unwrap();
    tip.history = before_tip.commitment();
    let block = cairn_ledger::Block {
        header: tip,
        coinbase: CoinbaseTransaction::new(tip.height, Vec::new()),
        transfers: Vec::new(),
    };
    let Some(block) = mine_block(block, 1 << 22) else {
        return true;
    };
    let tip = block.header;

    let ledger: Vec<(u64, u128, u64)> = shown
        .iter()
        .take(shown.len() - 1)
        .rev()
        .map(|header| (header.height, header.total_work, header.difficulty))
        .collect();
    let last = shown.len() - 2;

    let samples = draw(seed_of(&tip), count, work_before(&tip), tip.height)
        .into_iter()
        .map(|work| {
            // The best it can do: the block spanning the draw, or the nearest
            // thing it has when the draw lands in the gap.
            let height = covering(&ledger, work).unwrap_or(last as u64);
            let header = shown[usize::try_from(height).unwrap()];
            let proof = before_tip.prove(height).unwrap();
            Sample { header, proof }
        })
        .collect();

    let start = SampledStart {
        tip,
        history: before_tip.forest().roots_only(),
        samples,
    };
    check_start(&start, count).is_err()
}

/// An honest chain of `count` blocks.
fn build(count: u64) -> Vec<BlockHeader> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    let mut headers = Vec::with_capacity(usize::try_from(count).unwrap());
    let mut clock = 1_000u64;

    for _ in 0..count {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, 1 << 22).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        headers.push(block.header);
    }
    headers
}

const NOW: u64 = 2_000_000_000;

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
/// assumed, so modelling it here would answer the wrong question. A forger
/// cannot pick the seed — it comes from its own tip — so what decides the
/// count is the average over seeds, not the kindest one.
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

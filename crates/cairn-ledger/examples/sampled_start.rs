//! How many headers a newcomer has to open before a lie cannot get past it.
//!
//! The protocol itself is in `cairn_ledger::sampling`, along with the tests
//! that say what it refuses. What is measured here is the one number the tests
//! cannot settle: how many draws are enough.
//!
//! The answer depends on what an adversary is trying to sell. A chain that
//! overstates its work by a little has to be wrong about only a little of
//! itself, so the questions have to be numerous enough that one of them lands
//! in that little. A chain overstating by a lot cannot answer almost anything.
//! So the number of draws is chosen against the smallest lie worth telling,
//! not against the largest.
//!
//! Run with `cargo run --release -p cairn-ledger --example sampled_start`.

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
    check_start, covering, draw, seed_of, work_before, Sample, SampledStart,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
/// Blocks in the honest chain the forger starts from.
const HEIGHT: u64 = 600;
/// Forgeries tried per setting, since a draw either catches one or does not
/// and the question is how often.
const TRIALS: usize = 200;

fn main() {
    let honest = build(HEIGHT);
    let tip = *honest.last().unwrap();
    println!("A chain of {HEIGHT} blocks, {} of work\n", tip.total_work);

    println!("How often a lie is caught, by how large it is and how many draws:\n");
    print!("{:>12}", "overstates");
    for count in [8usize, 16, 32, 64, 128] {
        print!("{count:>10}");
    }
    println!();
    println!("{}", "-".repeat(62));

    // How much more work the forger claims than it did. A tenth is already a
    // strong claim on a chain anyone else is also extending.
    for (lie, name) in [
        (Lie::AtTheEnd, "all at the end"),
        (Lie::Spread, "spread through"),
    ] {
        println!("\n  the lie is {name}:");
        for claim in [1.01f64, 1.05, 1.10, 1.50, 4.00] {
            print!("{:>11.0}%", (claim - 1.0) * 100.0);
            for count in [8usize, 16, 32, 64, 128] {
                let trials = if lie == Lie::Spread {
                    TRIALS / 10
                } else {
                    TRIALS
                };
                let caught = (0..trials)
                    .filter(|trial| {
                        caught_out(&honest, claim, count, u64::try_from(*trial).unwrap(), lie)
                    })
                    .count();
                print!("{:>9.0}%", caught as f64 / trials as f64 * 100.0);
            }
            println!();
        }
    }

    println!(
        "\nA forger that overstates by any amount leaves work no block spans, and\n\
         every draw landing in that work is one it cannot answer. Where it puts\n\
         the gap is the only choice it has. Piling it at the end is the simplest\n\
         forgery and the worst, because that is where the draw looks hardest.\n\
         Spreading it thinly through the chain is the best it can do, and it\n\
         costs mining every header again, which an adversary that could afford\n\
         would not need to forge."
    );

    println!(
        "\nWhat it costs to ask. A header is {} bytes and a proof is at most 64\n\
         hashes, so 128 draws is about {} kB, once, against the tens of\n\
         gigabytes of reading it replaces.",
        core::mem::size_of::<BlockHeader>(),
        128 * (core::mem::size_of::<BlockHeader>() + 64 * 32) / 1000,
    );

    at_full_size();
}

/// The same question at the size a real chain reaches.
///
/// Forging a chain of fifteen million blocks is not something to mine in an
/// example, and the numbers above are small enough that whole number rounding
/// decides them: at a difficulty of one, a block's work is one, and a gap of
/// one per cent of it rounds to nothing or to everything. So this asks the
/// question the other way round, of the draw alone: a forger spreading its lie
/// evenly leaves a gap in every block, and what matters is how likely a draw is
/// to land in one.
///
/// No mining and no headers, so it says nothing about whether the checks hold.
/// That is what the tests are for. This says how many draws to make.
fn at_full_size() {
    // Thirty years of a chain a minute, at a difficulty a real network reaches.
    let blocks = 30u64 * 365 * 24 * 60;
    let per_block = 1u128 << 40;
    let honest = per_block * u128::from(blocks);

    println!("\n\nAt {blocks} blocks, thirty years of a chain a minute:\n");
    print!("{:>12}", "overstates");
    for count in [32usize, 64, 128, 256, 512] {
        print!("{count:>10}");
    }
    println!();
    println!("{}", "-".repeat(62));

    for share in [0.001f64, 0.01, 0.05, 0.10, 0.50] {
        print!("{:>11.1}%", share * 100.0);
        let claimed = honest + (honest as f64 * share) as u128;
        for count in [32usize, 64, 128, 256, 512] {
            // Each block covers its own work out of a stretch scaled up by the
            // lie, so the fraction of every stretch that nothing spans is the
            // lie itself. A draw is caught when it lands in one.
            let mut missed = 0usize;
            for trial in 0..500u64 {
                let seed = cairn_primitives::hash::hash(
                    cairn_primitives::hash::Domain::SamplingSeed,
                    &trial.to_le_bytes(),
                );
                let caught = draw(seed, count, claimed, blocks).into_iter().any(|work| {
                    // Which block's stretch this lands in, and whereabouts.
                    let stretch = claimed / u128::from(blocks).max(1);
                    let within = work % stretch.max(1);
                    within >= per_block
                });
                if !caught {
                    missed += 1;
                }
            }
            print!("{:>9.0}%", (500 - missed) as f64 / 500.0 * 100.0);
        }
        println!();
    }

    from_the_threat();
}

/// What the count has to be, derived from the assumption the chain already
/// makes rather than read off the table above.
///
/// The table says how large a lie a given number of draws catches. It does not
/// say how large a lie a forger has to tell, and that is the question that
/// settles the count.
///
/// A forger holding a share of the world's work presents a chain heavier than
/// the honest one. It cannot mine what it did not mine, so the difference is
/// invented: work no block of its chain spans. If it holds `share` of the
/// total and the honest network holds the rest, then to pass the honest chain
/// it must claim more than `1 - share` while having done `share`, so at least
///
///     lie = 1 - share / (1 - share)
///
/// of what it presents is invented. That is not a small number for any share
/// the chain's own security assumption allows: at a third of the world's work
/// it is half the chain, and it only approaches zero as the share approaches
/// the half at which proof of work stops protecting anything at all.
///
/// Every draw lands in invented work with probability `lie`, so `count` draws
/// miss with probability `(1 - lie)^count`. Turned around, `count` draws hold
/// against every share up to the one where that probability reaches 2^-128.
fn from_the_threat() {
    println!("\n\nWhat a forger has to lie about, given what it holds:\n");
    println!(
        "{:>16}  {:>14}  {:>22}  {:>16}",
        "forger holds", "must invent", "draws for 2^-128", "at 512 draws"
    );
    println!("{}", "-".repeat(76));

    for share in [0.10f64, 0.20, 0.30, 0.40, 0.45, 0.49] {
        let lie = 1.0 - share / (1.0 - share);
        // count * -log2(1 - lie) >= 128
        let needed = (128.0 / -(1.0 - lie).log2()).ceil();
        let missed = (1.0 - lie).powi(512);
        println!(
            "{:>15.0}%  {:>13.1}%  {:>22.0}  {:>16}",
            share * 100.0,
            lie * 100.0,
            needed,
            if missed <= 2f64.powi(-128) {
                "holds".to_owned()
            } else {
                format!("2^{:.0}", missed.log2())
            },
        );
    }

    // The share at which the count stops reaching 2^-128.
    let share = margin(i32::try_from(cairn_ledger::sampling::SAMPLES).unwrap_or(512));
    println!(
        "\n{} draws hold against any forger up to {:.1}% of the world's work, at\n\
         2^-128. Past that the count would have to grow without bound, because a\n\
         forger at half the work has nothing left to invent: it can simply mine\n\
         the chain. That is the same assumption the chain itself rests on, so\n\
         this is not a weaker one, and the margin between {:.1}% and 50% is what\n\
         the count buys.",
        cairn_ledger::sampling::SAMPLES,
        share * 100.0,
        share * 100.0,
    );
    println!(
        "\nDoubling the count buys very little of that margin: 1024 draws reach\n\
         {:.1}% and 2048 reach {:.1}%. The cost is a megabyte against two, once.",
        margin(1024) * 100.0,
        margin(2048) * 100.0,
    );
}

/// The largest share of the world's work `count` draws hold against, at 2^-128.
fn margin(count: i32) -> f64 {
    let lie = 1.0 - 2f64.powf(-128.0 / f64::from(count));
    (1.0 - lie) / (2.0 - lie)
}

/// How a forger arranges the work it never did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lie {
    /// All of it at the end: the honest chain untouched, and a tip claiming
    /// more than it carries. The simplest forgery, and the worst one, because
    /// the whole gap sits where the draw looks hardest.
    AtTheEnd,
    /// Spread through the chain in proportion, so every block's stated total
    /// is scaled. The gaps are then spread as thinly as they can be, which is
    /// the best an adversary can do against a draw that leans towards the tip.
    Spread,
}

/// Whether a forgery claiming `claim` times the honest work is caught.
///
/// The forger cannot change the honest headers, since each one's identifier is
/// what fixes it in the tip's history and each one's work is real. What it can
/// do is restate the totals, and every restatement leaves work no block spans.
fn caught_out(honest: &[BlockHeader], claim: f64, count: usize, salt: u64, lie: Lie) -> bool {
    let real = *honest.last().unwrap();

    // The chain as the forger presents it. Under `Spread` the stated totals
    // are scaled, which means the headers themselves change, which means their
    // identifiers change, which means each one has to be mined again. That is
    // what an adversary with real hash power would have to spend, and it is
    // what makes this the strong forgery rather than the cheap one.
    let mut shown: Vec<BlockHeader> = Vec::with_capacity(honest.len());
    for header in honest {
        let mut copy = *header;
        if lie == Lie::Spread {
            copy.total_work = (header.total_work as f64 * claim) as u128;
            copy.timestamp = header.timestamp + salt;
            let block = cairn_ledger::Block {
                header: copy,
                coinbase: CoinbaseTransaction::new(copy.height, Vec::new()),
                transfers: Vec::new(),
            };
            let Some(block) = mine_block(block, ATTEMPTS) else {
                return true;
            };
            copy = block.header;
        }
        shown.push(copy);
    }

    let mut forged = *shown.last().unwrap();
    forged.total_work = (real.total_work as f64 * claim) as u128;
    forged.timestamp = real.timestamp + salt;
    let block = cairn_ledger::Block {
        header: forged,
        coinbase: CoinbaseTransaction::new(forged.height, Vec::new()),
        transfers: Vec::new(),
    };
    let Some(block) = mine_block(block, ATTEMPTS) else {
        return true;
    };
    let forged = block.header;

    // The history is the one the forger built, so its own headers are in it.
    let mut before_tip = Archive::new();
    for header in shown.iter().take(shown.len() - 1) {
        before_tip.add(header_leaf(&header.id()));
    }
    let mut with_tip = forged;
    with_tip.history = before_tip.commitment();
    let block = cairn_ledger::Block {
        header: with_tip,
        coinbase: CoinbaseTransaction::new(with_tip.height, Vec::new()),
        transfers: Vec::new(),
    };
    let Some(block) = mine_block(block, ATTEMPTS) else {
        return true;
    };
    let forged = block.header;

    let last = shown.len() - 2;
    let ledger: Vec<(u64, u128, u64)> = shown
        .iter()
        .take(shown.len() - 1)
        .rev()
        .map(|header| (header.height, header.total_work, header.difficulty))
        .collect();

    let samples = draw(seed_of(&forged), count, work_before(&forged), forged.height)
        .into_iter()
        .map(|work| {
            // The best it can do: the block that spans the draw, or the
            // closest thing it has when the draw lands in a gap.
            let height = covering(&ledger, work).unwrap_or(last as u64);
            let header = shown[usize::try_from(height).unwrap()];
            let proof = before_tip.prove(height).unwrap();
            Sample { header, proof }
        })
        .collect();

    let start = SampledStart {
        tip: forged,
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
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        headers.push(block.header);
    }
    headers
}

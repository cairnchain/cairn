//! Joining a long chain from a sample of its headers.
//!
//! This is a prototype, not the protocol. It exists to answer one question
//! that had to be answered before the header format is relied on: do the two
//! fields committed to yesterday actually let a newcomer conclude what work
//! stands behind a tip, without being handed the chain?
//!
//! What it does not do, and must not be read as doing: the sampling
//! distribution here is uniform over accumulated work, which is the simple
//! choice rather than the right one. `FlyClient`'s distribution samples the
//! recent end of the chain more densely, because that is where an adversary
//! who cannot afford real work has to put the lie. Taking that distribution,
//! with its proven parameters, is the next piece of work. The detection rates
//! printed below are therefore a demonstration that the mechanism bites, not a
//! security claim.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::print_stdout
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::note::Note;
use cairn_ledger::pow::{meets_target, work_of};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain};

/// Blocks in the chain the newcomer is asked to believe in.
const HEIGHT: u64 = 20_000;
/// Headers drawn per attempt.
const SAMPLES: usize = 128;
/// Attempts, when measuring how often a forged chain is caught.
const ATTEMPTS: usize = 400;
const MINING_ATTEMPTS: u64 = 1 << 22;

/// Everything a newcomer is handed: one header, and nothing else.
struct Tip {
    header: BlockHeader,
}

/// What someone who kept the headers can answer with.
struct Archivist {
    headers: Vec<BlockHeader>,
    /// The header forest as it stood before the tip, which is what the tip's
    /// `history` field commits to.
    before_tip: Archive,
}

impl Archivist {
    /// The header at `position`, and the proof that it sits there.
    fn answer(&self, position: u64) -> Option<(BlockHeader, cairn_accumulator::ForestProof)> {
        let header = *self.headers.get(usize::try_from(position).ok()?)?;
        let proof = self.before_tip.prove(position)?;
        Some((header, proof))
    }
}

fn main() {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    let mut headers = Vec::with_capacity(usize::try_from(HEIGHT).unwrap());

    println!("Building a chain of {HEIGHT} blocks");
    for _ in 0..HEIGHT {
        let height = state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &state,
            coinbase,
            Vec::<Transfer>::new(),
            &params,
            1_000 + height * 60,
            0,
        )
        .unwrap();
        let block = mine_block(block, MINING_ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, u64::MAX / 2).unwrap();
        headers.push(block.header);
    }

    let tip = Tip {
        header: *headers.last().unwrap(),
    };

    // The archivist rebuilds the forest as it stood before the tip, because
    // that is the state the tip's `history` field names. One leaf of
    // difference and nothing would verify.
    let mut before_tip = Archive::new();
    for header in &headers[..headers.len() - 1] {
        before_tip.add(header_leaf(&header.id()));
    }

    println!();
    println!("Does the archivist's forest match what the tip commits to?");
    println!("  tip says          {}", tip.header.history);
    println!("  archivist has     {}", before_tip.forest().commitment());
    let agrees = before_tip.forest().commitment() == tip.header.history;
    println!("  agreement         {}", if agrees { "yes" } else { "NO" });
    assert!(agrees, "the header commitment does not name what it should");

    let archivist = Archivist {
        headers: headers.clone(),
        before_tip,
    };

    // ---- the honest case ----

    println!();
    println!("A newcomer holding only the tip draws {SAMPLES} headers");
    let drawn = draw(&tip.header, SAMPLES, HEIGHT - 1);
    let outcome = examine(&tip, &archivist, &drawn);
    println!("  positions drawn   {}", drawn.len());
    println!(
        "  accepted          {}",
        if outcome.is_ok() { "yes" } else { "no" }
    );
    if let Err(reason) = &outcome {
        panic!("an honest chain was refused: {reason}");
    }

    let proof_bytes = drawn
        .iter()
        .filter_map(|position| archivist.answer(*position))
        .map(|(header, proof)| header.encode().len() + proof.siblings.len() * 32)
        .sum::<usize>();
    println!("  proof carried     {:.1} kB", proof_bytes as f64 / 1_024.0);
    println!(
        "  against reading   {:.1} MB of headers",
        HEIGHT as f64 * tip.header.encode().len() as f64 / 1_048_576.0
    );

    report_forgery(&headers);
}

/// How often a forged chain is caught, spread out and concentrated.
fn report_forgery(headers: &[BlockHeader]) {
    println!();
    println!("Now a forger, who cannot afford the work and inflates it instead.");
    println!("It fakes as few blocks as it can, because every fake is a chance");
    println!("of being drawn.");
    println!();
    println!(
        "  {:<14} {:>9} {:>14}",
        "blocks faked", "caught", "expected"
    );
    for share in [1u64, 2, 5, 10, 25] {
        let caught = (0..ATTEMPTS)
            .filter(|attempt| {
                let salt = u64::try_from(*attempt).unwrap_or(0);
                let (forged_tip, forger) = forge(headers, Lie::Scattered(share), salt);
                let drawn = draw(&forged_tip.header, SAMPLES, HEIGHT - 1);
                examine(&forged_tip, &forger, &drawn).is_err()
            })
            .count();
        // With a uniform draw, missing every fake has probability
        // (1 - share)^samples.
        let miss = (1.0 - share as f64 / 100.0).powi(i32::try_from(SAMPLES).unwrap_or(i32::MAX));
        println!(
            "  {:<13}% {:>8.1}% {:>13.1}%",
            share,
            caught as f64 * 100.0 / ATTEMPTS as f64,
            (1.0 - miss) * 100.0
        );
    }

    println!();
    println!("And the forger that matters: one that keeps the real chain and");
    println!("fakes only a recent stretch of it, which is the cheap attack.");
    println!();
    println!("  {:<14} {:>9}", "recent blocks", "caught");
    for tail in [2000u64, 500, 100, 20] {
        let caught = (0..ATTEMPTS)
            .filter(|attempt| {
                let salt = u64::try_from(*attempt).unwrap_or(0);
                let (forged_tip, forger) = forge(headers, Lie::Tail(tail), salt);
                let drawn = draw(&forged_tip.header, SAMPLES, HEIGHT - 1);
                examine(&forged_tip, &forger, &drawn).is_err()
            })
            .count();
        println!(
            "  {:<14} {:>8.1}%",
            tail,
            caught as f64 * 100.0 / ATTEMPTS as f64
        );
    }

    println!();
    println!("That last column is the whole reason FlyClient does not draw");
    println!("uniformly: a short recent lie is what a uniform draw misses, and");
    println!("their distribution leans on exactly that end of the chain.");
    println!("Taking it, with its proven parameters, is the work left.");
}

/// Picks positions to ask about, deterministically from the tip.
///
/// Derived from the tip rather than chosen freshly, so a prover cannot answer
/// a different question from the one asked, and no round trip is needed to
/// agree on which blocks are in play. That much is from `FlyClient` and is not
/// the part that needs calibrating.
fn draw(tip: &BlockHeader, count: usize, highest: u64) -> Vec<u64> {
    let seed = hash(Domain::BlockHeaderId, &tip.encode());
    let mut positions = Vec::with_capacity(count);
    let mut counter = 0u64;
    while positions.len() < count {
        let mut material = Vec::with_capacity(40);
        material.extend_from_slice(seed.as_bytes());
        material.extend_from_slice(&counter.to_le_bytes());
        let draw = hash(Domain::BlockHeaderId, &material);
        let bytes = draw.as_bytes();
        let value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let position = value % highest.max(1);
        if !positions.contains(&position) {
            positions.push(position);
        }
        counter += 1;
        if counter > 100_000 {
            break;
        }
    }
    positions
}

/// What a newcomer checks, holding only the tip.
fn examine(tip: &Tip, archivist: &Archivist, positions: &[u64]) -> Result<(), String> {
    // Rebuilt from the roots alone: the newcomer never holds the forest, only
    // the commitment the tip hands it.
    let mut running_work = 0u128;

    for position in positions {
        let Some((header, proof)) = archivist.answer(*position) else {
            return Err(format!("no answer for position {position}"));
        };

        // The work each header claims must be work it actually did.
        if !meets_target(&header.id(), header.difficulty) {
            return Err(format!("header at {position} carries no work"));
        }

        // And it must be the header that sits there, not merely a valid one.
        let leaf = header_leaf(&header.id());
        if !archivist
            .before_tip
            .forest()
            .verify(*position, leaf, &proof)
        {
            return Err(format!("header at {position} is not in the tip's history"));
        }

        // Its stated total must be consistent with its own difficulty and its
        // height, which is what stops a short chain wearing a long one's
        // numbers.
        if header.total_work < work_of(header.difficulty) {
            return Err(format!("header at {position} states less work than it did"));
        }
        if header.height != *position {
            return Err(format!(
                "header at {position} claims height {}",
                header.height
            ));
        }
        running_work = running_work.max(header.total_work);
    }

    // The tip cannot claim less than the heaviest header behind it.
    if tip.header.total_work < running_work {
        return Err("the tip claims less work than a header behind it".to_owned());
    }
    Ok(())
}

/// How a forger spends its lie.
#[derive(Clone, Copy)]
enum Lie {
    /// A percentage of blocks, spread across the whole chain.
    Scattered(u64),
    /// Only the last so many blocks, leaving the rest genuine.
    Tail(u64),
}

/// Builds a chain that claims work it never did.
///
/// Every faked header carries an inflated difficulty and no work behind it.
/// Real proof of work on every block is exactly what a forger cannot afford,
/// so the question is only how few blocks it has to fake and where.
fn forge(real: &[BlockHeader], lie: Lie, salt: u64) -> (Tip, Archivist) {
    let mut headers = Vec::with_capacity(real.len());
    let mut running = 0u128;
    let total = u64::try_from(real.len()).unwrap_or(u64::MAX);

    for (index, header) in real.iter().enumerate() {
        let mut forged = *header;
        let position = u64::try_from(index).unwrap_or(u64::MAX);
        let fake = match lie {
            Lie::Scattered(share) => {
                // Deterministic per attempt, so the draw and the lie are
                // independent of each other.
                let mut material = Vec::with_capacity(24);
                material.extend_from_slice(&position.to_le_bytes());
                material.extend_from_slice(&salt.to_le_bytes());
                let roll = hash(Domain::BlockHeaderId, &material);
                u64::from(roll.as_bytes()[0]) * 100 / 256 < share
            }
            Lie::Tail(length) => position >= total.saturating_sub(length),
        };

        if fake {
            // Claim a great deal of work, and do none of it.
            forged.difficulty = header.difficulty.saturating_mul(64);
            forged.nonce = salt;
        }
        running = running.saturating_add(work_of(forged.difficulty));
        forged.total_work = running;
        headers.push(forged);
    }

    // The forger's own forest, over its own headers: it commits to the chain
    // it is showing, which is the whole point of the exercise.
    let mut before_tip = Archive::new();
    for header in &headers[..headers.len() - 1] {
        before_tip.add(header_leaf(&header.id()));
    }
    let mut tip_header = *headers.last().unwrap();
    tip_header.history = before_tip.forest().commitment();

    (
        Tip { header: tip_header },
        Archivist {
            headers,
            before_tip,
        },
    )
}

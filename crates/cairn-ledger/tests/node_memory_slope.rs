//! A plain node's memory does not grow with the chain.
//!
//! This is the claim the whole design rests on, so it is measured rather than
//! argued: notes are made to fall into the cold set in the millions, and what
//! the process holds is read at intervals across the run. An archivist is run
//! beside it as the control, because a measurement that shows no slope is
//! only worth something if the same instrument shows one where a slope is
//! known to exist.

#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use cairn_crypto::PublicKey;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
/// The size the release quoted: 12,500 blocks is 3,198,976 fallen notes.
const BLOCKS: usize = 12_500;

fn rss_kb() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

/// Physical footprint as macOS reports it, which unlike the resident set
/// includes pages the memory compressor has taken.
fn footprint() -> String {
    let out = std::process::Command::new("footprint")
        .arg("-p")
        .arg(std::process::id().to_string())
        .output();
    match out {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|line| line.contains("footprint") || line.contains("TOTAL"))
            .take(3)
            .collect::<Vec<_>>()
            .join(" | "),
        Err(error) => format!("footprint unavailable: {error}"),
    }
}

/// The same, as a number in kilobytes.
fn footprint_kb() -> u64 {
    let out = std::process::Command::new("footprint")
        .arg("-p")
        .arg(std::process::id().to_string())
        .output();
    let Ok(out) = out else { return 0 };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(rest) = line.split("phys_footprint:").nth(1) else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let (Some(value), Some(unit)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(value) = value.parse::<f64>() else {
            continue;
        };
        return match unit {
            "GB" => (value * 1024.0 * 1024.0) as u64,
            "MB" => (value * 1024.0) as u64,
            "KB" => value as u64,
            _ => (value / 1024.0) as u64,
        };
    }
    0
}

fn fresh_owners(count: usize) -> Vec<PublicKey> {
    let mut out = Vec::with_capacity(count);
    let mut seed = 1u64;
    while out.len() < count {
        let mut bytes = [0u8; 32];
        let mut hasher =
            cairn_primitives::hash::Hasher::new(cairn_primitives::hash::Domain::NoteKey);
        hasher.update(&seed.to_le_bytes());
        bytes.copy_from_slice(hasher.finalize().as_bytes());
        seed += 1;
        if let Ok(key) = PublicKey::from_bytes(&bytes) {
            out.push(key);
        }
    }
    out
}

/// The same parameters `falling_chain` uses, so the two are comparable.
/// Mining is left out: the proof of work is not what is being weighed, and
/// `connect_block` is given `assemble_block`'s output directly.
fn run(blocks: usize, archiving: bool) {
    let mut params = ConsensusParams::testnet();
    params.hot_capacity = 1_024;
    params.max_evictions_per_block = 1_024;
    params.max_coinbase_outputs = 256;

    let owners = fresh_owners(256);
    let share = Amount::from_pebbles(params.initial_reward.as_pebbles() / 256).unwrap();

    let mut state = if archiving {
        LedgerState::archiving()
    } else {
        LedgerState::new()
    };
    let mut clock = 1_000u64;
    let chunk = blocks / 10;
    let label = if archiving { "ARCHIVING" } else { "PLAIN    " };

    println!(
        "\n== {label}: one ledger alive, every block dropped after it is applied ==\n\
         {:>10} {:>10} {:>9} {:>9} {:>10} {:>7} {:>7} {:>7} {:>7}",
        "blocks", "cold", "rss kB", "peak kB", "foot kB", "hot", "grace", "watch", "mature"
    );
    let mut marks: Vec<(u64, u64, u64)> = Vec::new();
    let mut peak = rss_kb();
    let base = peak;
    for at in 0..blocks {
        let height = state.next_height().unwrap();
        clock += 600;
        let outputs: Vec<Note> = owners
            .iter()
            .map(|owner| Note::new(share, *owner))
            .collect();
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        // The record is dropped here on purpose: this is the ledger's cost and
        // not the undo window's, which `zz_probe_undo_total.rs` weighs.
        connect_block(&mut state, &block, &params, NOW).unwrap();
        drop(block);
        if (at + 1) % chunk == 0 {
            let now = rss_kb();
            let foot = footprint_kb();
            peak = peak.max(now);
            let leaves = state.cold().len();
            assert_eq!(
                state.cold().is_archiving(),
                archiving,
                "the state is the kind asked for"
            );
            println!(
                "{:>10} {leaves:>10} {now:>9} {peak:>9} {foot:>10} {:>7} {:>7} {:>7} {:>7}",
                at + 1,
                state.hot_notes().count(),
                state.grace_len(),
                state.watched_paths(),
                state.maturing().len(),
            );
            marks.push((leaves, peak, foot));
        }
    }

    println!("  baseline before the first block: {base} kB");
    // Reading the set back. `ps -o rss=` counts resident pages only: a page
    // the operating system compressed or paged out while the run went on is
    // not resident and is not counted, however alive the data on it is. So
    // the set is walked once here, which faults every page of it back in, and
    // the resident set is read again.
    let before_touch = rss_kb();
    let mut proved = 0usize;
    let mut step = 0u64;
    while step < state.cold().len() {
        if state.cold().proof_of(step).is_some() {
            proved += 1;
        }
        step += 997;
    }
    println!(
        "  after walking the set back ({proved} proofs rebuilt): {} kB, up from {before_touch} kB",
        rss_kb()
    );
    println!(
        "  what the operating system says the process really occupies: {}",
        footprint()
    );
    let report = |name: &str, from: usize| {
        let (l0, p0, r0) = marks[from];
        let (l1, p1, r1) = marks[marks.len() - 1];
        println!(
            "  {name}: {l0} -> {l1} notes  |  rss-peak {:+} kB = {:.3} B a note  |  \
             FOOTPRINT {:+} kB = {:.3} B a note",
            p1 as i64 - p0 as i64,
            (p1 as f64 - p0 as f64) * 1024.0 / (l1 - l0) as f64,
            r1 as i64 - r0 as i64,
            (r1 as f64 - r0 as f64) * 1024.0 / (l1 - l0) as f64,
        );
    };
    report("slope over the whole run  ", 0);
    report("slope over the second half", marks.len() / 2);
    report("slope over the last fifth ", marks.len() - 3);

    let (l1, _, r1) = marks[marks.len() - 1];
    let (l0, _, r0) = marks[marks.len() / 2];
    let per = (r1 as f64 - r0 as f64) * 1024.0 / (l1 - l0) as f64;
    println!(
        "  extrapolated on the second-half slope: {:.2} GB at 3.2 billion fallen notes",
        per * 3.2e9 / 1e9
    );
    println!(
        "  what a plain node's bounded parts come to at 3.2 billion notes: the grace \
         window is {} paths and a path is log2(N) hashes, so {:.1} MB there against \
         {:.1} MB here",
        state.grace_len(),
        state.grace_len() as f64 * 3.2e9_f64.log2() * 32.0 / 1e6,
        state.grace_len() as f64 * (l1 as f64).log2() * 32.0 / 1e6,
    );
}

#[test]
fn a_plain_node_over_the_published_run() {
    run(BLOCKS, false);
}

#[test]
fn an_archivist_over_the_published_run() {
    run(BLOCKS, true);
}

/// The same, short, so the shape can be read quickly and repeated.
#[test]
fn a_plain_node_short_run() {
    run(2_500, false);
}

/// Validates the instrument before trusting any of the readings above.
///
/// First a known allocation, so `ps -o rss=` can be checked against a number
/// nobody has to model. Then an `Archive` of the same leaf count, which is
/// what an archivist's cold set is: a `Vec<Hash32>` of every leaf plus a
/// `Vec<Vec<Hash32>>` of the inner nodes, which the type's own comment puts
/// at "another thirty two bytes a block, on top of the thirty two the leaves
/// already cost".
#[test]
fn is_the_instrument_telling_the_truth() {
    use cairn_accumulator::Archive;
    use cairn_primitives::Hash32;

    const LEAVES: usize = 3_198_976;
    println!("\n== the instrument ==");
    let base = rss_kb();
    let known: Vec<[u8; 32]> = (0..LEAVES)
        .map(|at| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(at as u64).to_le_bytes());
            bytes
        })
        .collect();
    let after = rss_kb();
    println!(
        "  a Vec of {LEAVES} x 32 B should be {:.1} MB; ps says the resident set grew {:.1} MB",
        (LEAVES * 32) as f64 / 1e6,
        (after.saturating_sub(base)) as f64 * 1024.0 / 1e6,
    );
    std::hint::black_box(&known);
    drop(known);

    println!("\n== an Archive of the same leaf count ==");
    let base = rss_kb();
    let mut archive = Archive::new();
    let mut marks = Vec::new();
    for at in 0..LEAVES {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(at as u64).to_le_bytes());
        archive.add(Hash32::from_bytes(bytes));
        if (at + 1) % (LEAVES / 8) == 0 {
            marks.push((at + 1, rss_kb()));
        }
    }
    for (leaves, rss) in &marks {
        println!(
            "  {leaves:>9} leaves: {rss:>9} kB, {:>6.1} MB above the baseline = {:.1} B a leaf",
            (rss.saturating_sub(base)) as f64 * 1024.0 / 1e6,
            (rss.saturating_sub(base)) as f64 * 1024.0 / *leaves as f64,
        );
    }
    let (l0, r0) = marks[marks.len() / 2];
    let (l1, r1) = marks[marks.len() - 1];
    println!(
        "  slope over the second half: {:.1} B a leaf",
        (r1 as f64 - r0 as f64) * 1024.0 / (l1 - l0) as f64
    );
    assert!(archive.prove(0).is_some(), "it really is an archive");
    std::hint::black_box(&archive);
}

/// The Archive alone, in a process where nothing large was freed first.
#[test]
fn what_an_archive_alone_costs() {
    use cairn_accumulator::Archive;
    use cairn_primitives::Hash32;

    const LEAVES: usize = 3_198_976;
    let base = rss_kb();
    let mut archive = Archive::new();
    let mut marks = Vec::new();
    for at in 0..LEAVES {
        // A real leaf is a hash and does not compress. A leaf of mostly zero
        // bytes does, and this machine compresses inactive pages, which would
        // hide the very thing being measured.
        let mut hasher =
            cairn_primitives::hash::Hasher::new(cairn_primitives::hash::Domain::ForestLeaf);
        hasher.update(&(at as u64).to_le_bytes());
        archive.add(Hash32::from_bytes(*hasher.finalize().as_bytes()));
        if (at + 1) % (LEAVES / 8) == 0 {
            marks.push((at + 1, rss_kb()));
        }
    }
    println!("\n== an Archive alone, incompressible leaves, baseline {base} kB ==");
    for (leaves, rss) in &marks {
        println!(
            "  {leaves:>9} leaves: {rss:>9} kB, {:>6.1} MB above baseline = {:.1} B a leaf",
            (rss.saturating_sub(base)) as f64 * 1024.0 / 1e6,
            (rss.saturating_sub(base)) as f64 * 1024.0 / *leaves as f64,
        );
    }
    let (l0, r0) = marks[marks.len() / 2];
    let (l1, r1) = marks[marks.len() - 1];
    println!(
        "  slope over the second half: {:.1} B a leaf",
        (r1 as f64 - r0 as f64) * 1024.0 / (l1 - l0) as f64
    );
    assert!(archive.prove(0).is_some());
    std::hint::black_box(&archive);
}

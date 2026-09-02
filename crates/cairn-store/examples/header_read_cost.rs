//! What reading a header out of the log costs, measured rather than argued.
//!
//! The figures the release published for the header store come from here.
//! Timings are not assertions and a bound on one would fail on a busy machine
//! rather than on a regression, so this is an example: run it and read it.

#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::needless_range_loop
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

use cairn_ledger::block::BlockHeader;
use cairn_ledger::NetworkId;
use cairn_primitives::codec::Decode;
use cairn_primitives::Hash32;
use cairn_store::header_tree::HeaderTree;
use cairn_store::headers::{HeaderLog, HEADER_BYTES};

/// A cheap deterministic spread, so reads do not walk the file in order.
fn scatter(seed: u64) -> u64 {
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn header(height: u64, previous: Hash32) -> BlockHeader {
    BlockHeader {
        version: 1,
        network: NetworkId::TESTNET,
        height,
        previous,
        transactions_root: Hash32::from_bytes([(height % 251) as u8; 32]),
        state_root: Hash32::from_bytes([(height % 241) as u8; 32]),
        history: Hash32::from_bytes([(height % 239) as u8; 32]),
        timestamp: 1_000_000 + height * 600,
        difficulty: 1,
        total_work: u128::from(height),
        nonce: height,
    }
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let at = std::env::temp_dir().join(format!(
        "zz-probe-headers-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&at).unwrap();
    at
}

fn build_log(directory: &std::path::Path, count: u64) -> HeaderLog {
    let mut log = HeaderLog::open(directory).unwrap();
    let mut previous = Hash32::ZERO;
    for height in 0..count {
        let one = header(height, previous);
        previous = one.id();
        log.append(&one).unwrap();
    }
    log
}

/// What `read()` did before the link check: seek, read 182 bytes, decode.
/// No neighbour, no identifier.
fn naive_read(file: &mut File, index: u64) -> BlockHeader {
    file.seek(SeekFrom::Start(index * HEADER_BYTES as u64))
        .unwrap();
    let mut bytes = [0u8; HEADER_BYTES];
    file.read_exact(&mut bytes).unwrap();
    BlockHeader::decode(&bytes).unwrap()
}

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "DEBUG"
    } else {
        "RELEASE"
    }
}

/// Reading a header, old shape against new, at several log lengths.
fn what_reading_a_header_costs() {
    println!("\n== reading a header, profile {} ==", profile());
    for count in [1_024u64, 65_536, 262_144] {
        let directory = scratch(&format!("log{count}"));
        let log = build_log(&directory, count);
        let mut raw = OpenOptions::new()
            .read(true)
            .open(directory.join("headers.log"))
            .unwrap();

        let rounds = 20_000u64;
        // Warm both paths equally before either is timed.
        for step in 0..2_000 {
            let at = scatter(step) % count;
            std::hint::black_box(log.read_at(at).unwrap());
            std::hint::black_box(naive_read(&mut raw, at));
        }

        let mut old_best = f64::MAX;
        let mut new_best = f64::MAX;
        let mut old_all = Vec::new();
        let mut new_all = Vec::new();
        for run in 0..5u64 {
            let started = Instant::now();
            for step in 0..rounds {
                let at = scatter(run * rounds + step) % count;
                std::hint::black_box(naive_read(&mut raw, at));
            }
            let old = started.elapsed().as_nanos() as f64 / rounds as f64;

            let started = Instant::now();
            for step in 0..rounds {
                let at = scatter(run * rounds + step) % count;
                std::hint::black_box(log.read_at(at).unwrap());
            }
            let new = started.elapsed().as_nanos() as f64 / rounds as f64;

            old_best = old_best.min(old);
            new_best = new_best.min(new);
            old_all.push(old);
            new_all.push(new);
        }
        let spread = |all: &[f64]| {
            let lo = all.iter().copied().fold(f64::MAX, f64::min);
            let hi = all.iter().copied().fold(0.0f64, f64::max);
            (lo, hi)
        };
        let (olo, ohi) = spread(&old_all);
        let (nlo, nhi) = spread(&new_all);
        println!(
            "{count:>7} headers ({:>5} kB): old {old_best:>8.1} ns [{olo:.0}..{ohi:.0}], \
             new {new_best:>8.1} ns [{nlo:.0}..{nhi:.0}], ratio {:.2}x",
            count * HEADER_BYTES as u64 / 1024,
            new_best / old_best
        );
        std::fs::remove_dir_all(&directory).ok();
    }
}

/// How often the neighbour record the new `read()` reaches for is on a page
/// the first record did not already bring in. This is the whole of the cold
/// case: a second read inside the same 4 kB page is free.
fn how_often_the_neighbour_is_on_another_page() {
    let page = 4_096u64;
    let record = HEADER_BYTES as u64;
    let mut crossing = 0u64;
    let total = 100_000u64;
    for index in 0..total {
        let start = index * record;
        let neighbour = start + record;
        if start / page != (neighbour + record - 1) / page {
            crossing += 1;
        }
    }
    println!(
        "\n== the neighbour read, cold ==\n{HEADER_BYTES} B records in {page} B pages: \
         the neighbour lands outside the page the record itself brought in {:.1}% of the \
         time ({crossing} of {total}). The other {:.1}% costs no I/O at all, only the \
         syscall.",
        crossing as f64 * 100.0 / total as f64,
        100.0 - crossing as f64 * 100.0 / total as f64
    );
}

/// A `HeaderTree` filled to `leaves`, and what `prove_in` costs on it.
fn what_building_a_proof_costs() {
    println!("\n== building a proof, profile {} ==", profile());
    println!("(the tree does one leaf read plus two node reads and one hash per level;");
    println!(" before the repair it was one node read per level and no hash)");
    for leaves in [1_024u64, 4_096, 8_192, 16_384, 262_144, 1_048_576] {
        let directory = scratch(&format!("tree{leaves}"));
        let mut tree = HeaderTree::open(&directory).unwrap();
        for at in 0..leaves {
            tree.append(Hash32::from_bytes([(at % 253) as u8; 32]))
                .unwrap();
        }
        let height = (leaves as f64).log2() as usize;

        let rounds = 3_000u64;
        for step in 0..500 {
            std::hint::black_box(tree.prove_in(scatter(step) % leaves, leaves).unwrap());
        }
        // What `prove_in` did before: one sibling read per level, no leaf
        // read, no parent read, no hash. Same files, same syscalls.
        let mut levels: Vec<File> = (0..=height)
            .map(|at| {
                OpenOptions::new()
                    .read(true)
                    .open(directory.join(format!("headers.tree.{at}")))
                    .unwrap()
            })
            .collect();
        let old_shape = |levels: &mut Vec<File>, position: u64| -> Hash32 {
            let mut index = position;
            let mut last = Hash32::ZERO;
            for level in 0..height {
                let file = &mut levels[level];
                let at = (index ^ 1) * 32;
                if file.metadata().unwrap().len() >= at + 32 {
                    file.seek(SeekFrom::Start(at)).unwrap();
                    let mut bytes = [0u8; 32];
                    file.read_exact(&mut bytes).unwrap();
                    last = Hash32::from_bytes(bytes);
                }
                index >>= 1;
            }
            last
        };

        for step in 0..500 {
            std::hint::black_box(old_shape(&mut levels, scatter(step) % leaves));
        }

        let mut best = f64::MAX;
        let mut old_best = f64::MAX;
        let mut all = Vec::new();
        for run in 0..5u64 {
            let started = Instant::now();
            for step in 0..rounds {
                let at = scatter(run * rounds + step) % leaves;
                std::hint::black_box(old_shape(&mut levels, at));
            }
            old_best = old_best.min(started.elapsed().as_nanos() as f64 / rounds as f64);

            let started = Instant::now();
            for step in 0..rounds {
                let at = scatter(run * rounds + step) % leaves;
                std::hint::black_box(tree.prove_in(at, leaves).unwrap());
            }
            let each = started.elapsed().as_nanos() as f64 / rounds as f64;
            best = best.min(each);
            all.push(each);
        }
        let lo = all.iter().copied().fold(f64::MAX, f64::min);
        let hi = all.iter().copied().fold(0.0f64, f64::max);
        println!(
            "{leaves:>8} leaves (depth {height:>2}): old {:>7.2} µs, new {:>7.2} µs \
             [{:.2}..{:.2}], ratio {:.2}x, {:>6.0} ns a level, {} node reads",
            old_best / 1000.0,
            best / 1000.0,
            lo / 1000.0,
            hi / 1000.0,
            best / old_best,
            best / height as f64,
            2 * height + 1,
        );
        std::fs::remove_dir_all(&directory).ok();
    }
}

fn main() {
    what_reading_a_header_costs();
    how_often_the_neighbour_is_on_another_page();
    what_building_a_proof_costs();
}

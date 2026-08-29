//! What it costs an archivist to answer a newcomer.
//!
//! Weighing a chain takes 512 header proofs, and a proof here is built by
//! hashing subtrees up from the leaves. That is the plain way to do it and it
//! costs a pass over the archive per proof, which is fine on a young chain and
//! is the question this asks on an old one: the answer is cached per tip, and
//! a tip lasts one block.
//!
//! Run with `cargo run --release -p cairn-accumulator --example proving`.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::print_stdout
)]

use std::time::Instant;

use cairn_accumulator::forest::forest_leaf;
use cairn_accumulator::Archive;

const SIZES: [u64; 6] = [1_024, 8_192, 65_536, 262_144, 1_048_576, 4_194_304];
/// Proofs a newcomer asks for, which is the sampling count.
const SAMPLES: usize = 512;

fn main() {
    println!("What one archivist spends answering one newcomer.\n");
    println!(
        "{:>12}  {:>14}  {:>16}  {:>14}",
        "blocks", "one proof", "512 of them", "a block lasts"
    );
    println!("{}", "-".repeat(62));
    let mut last = (0u64, 0f64);

    for size in SIZES {
        let mut archive = Archive::new();
        for index in 0..size {
            archive.add(forest_leaf(&index.to_le_bytes()));
        }

        // Spread across the archive, as a draw is.
        let places: Vec<u64> = (0..32).map(|n| (size / 32) * n).collect();
        let started = Instant::now();
        for place in &places {
            assert!(archive.prove(*place).is_some());
        }
        let each = started.elapsed().as_secs_f64() / places.len() as f64;
        let all = each * SAMPLES as f64;

        println!(
            "{:>12}  {:>13.1}us  {:>15.3}s  {:>14}",
            size,
            each * 1e6,
            all,
            if all < 60.0 { "enough" } else { "NOT ENOUGH" },
        );
        last = (size, all);
    }
    assert!(last.0 > 0);

    println!(
        "\nA tip lasts one block, which is a minute, and the answer is built per\n\
         tip. An archivist that takes longer than that to build one is an\n\
         archivist that never finishes an answer. Holding the inner nodes is\n\
         what turns a pass over the whole archive into one hash per level, and\n\
         it costs the archivist another thirty two bytes a block."
    );
    undoing();

    println!(
        "\nWhat is left grows with the depth of the forest rather than its size,\n\
         which is one more hash for every doubling of the chain. Thirty years\n\
         of a block a minute is four doublings past the last row here."
    );
}

/// What it costs an archivist to undo blocks, which a reorganisation makes it
/// do once per block.
fn undoing() {
    println!("\n\nWhat one archivist spends undoing one block.\n");
    println!(
        "{:>12}  {:>16}  {:>18}",
        "blocks", "one undone", "a window of 1024"
    );
    println!("{}", "-".repeat(50));

    for size in [8_192u64, 65_536, 262_144, 1_048_576] {
        let mut archive = Archive::new();
        for index in 0..size {
            archive.add(forest_leaf(&index.to_le_bytes()));
        }
        let started = Instant::now();
        for _ in 0..8 {
            assert!(archive.remove_last());
        }
        let each = started.elapsed().as_secs_f64() / 8.0;
        println!(
            "{:>12}  {:>14.1}us  {:>16.4}s",
            size,
            each * 1e6,
            each * 1024.0
        );
    }
}

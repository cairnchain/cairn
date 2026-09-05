//! What carrying the history actually costs.
//!
//! The validation state is bounded by rule. The history is not, and this
//! measures what that means in bytes and in minutes rather than in adjectives.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use std::collections::VecDeque;
use std::time::Instant;

use cairn_accumulator::forest::tree_of;
use cairn_crypto::SecretKey;
use cairn_ledger::note::Note;
use cairn_ledger::sampling::{draw, SAMPLES};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

/// Blocks in each measurement.
///
/// It was 2 000, and it must not be. A chain of [`BUSY`] ordinary payments a
/// block ends each block with sixty-five notes more than it started: one from
/// the coinbase, and one for every payment, since a payment spends one note and
/// makes two. The hot set holds 131 072, so two thousand of these blocks leave
/// 130 064 notes in it, fifteen blocks short of the tier filling.
///
/// Fifteen blocks is not a margin. Past it the oldest notes start falling, and
/// the oldest notes are the ones this spends, so half the run would be
/// measuring payments that need a proof this purse does not carry. An
/// instrument standing that close to a cliff goes over it the next time a
/// constant moves, and the figures it published would be an average of two
/// different things. The run stops well short instead, and the assertion at
/// the end of `measure` is what says it really did.
const SAMPLE: usize = 1_024;
/// Transfers per block in the busy measurement. A block may carry 4096, but a
/// chain that busy is not the one worth planning around.
const BUSY: usize = 64;

/// A note this run can spend, and which of the two keys signs for it.
type Held = (cairn_ledger::note::NoteId, Note, bool);

/// Validates `SAMPLE` blocks carrying `transfers_each` transfers, and reports
/// the cost of one block.
///
/// The funding is the part that had to be repaired. This asked for sixty-four
/// transfers a block and could fund sixteen, because the purse it spent from
/// was refilled by the coinbase alone and a coinbase carries at most sixteen
/// outputs. So 1 999 of 2 000 blocks carried exactly sixteen, and every figure
/// built on the result, including a thirty-year download, was short by four
/// times over.
///
/// What funds it now is the payments themselves: an ordinary payment spends
/// one note and creates two, the payee's and the change, so a chain of them
/// makes more notes than it spends. Both come back to the purse because this
/// program holds both keys, which changes nothing about the bytes or the work
/// (a key is thirty-two bytes whoever owns it) and is the whole difference
/// between asking for sixty-four and getting them.
fn measure(transfers_each: usize) -> (usize, f64, f64) {
    // A reward is spendable at once here. What is being measured is the cost
    // of validating a busy block, and every transfer in one of these spends a
    // coinbase paid a few blocks earlier; making them wait a thousand blocks
    // would measure the same block after a longer setup.
    let params = ConsensusParams::testnet().with_coinbase_maturity(0);
    let keys = [
        SecretKey::from_bytes(&[1; 32]),
        SecretKey::from_bytes(&[2; 32]),
    ];

    let mut state = LedgerState::new();
    let mut header_bytes = 0usize;
    let mut block_bytes = 0usize;
    let mut spent = 0.0f64;
    // Notes available to spend, oldest first. Oldest and not newest: taking
    // the newest would respend the same note over and over, halving its value
    // each time until it could not be split, where taking the oldest spreads
    // the splitting across the whole purse and never goes more than a few
    // deep.
    let mut purse: VecDeque<Held> = VecDeque::new();

    // Enough blocks of coinbase alone that the first measured block can be
    // funded, since a payment needs a note before it can make two.
    let warmup = transfers_each.div_ceil(params.max_coinbase_outputs.max(1));
    for index in 0..(warmup + SAMPLE) {
        let measuring = index >= warmup;
        let height = state.next_height().unwrap();
        // Paid out in pieces while warming up, so the purse has something to
        // start from, and in one piece once the measuring begins: that is the
        // block the paper quotes, and two instruments measuring "a block with
        // sixty-four ordinary payments" have to measure the same block.
        let pieces = if measuring || transfers_each == 0 {
            1
        } else {
            params.max_coinbase_outputs
        };
        let each = cairn_primitives::Amount::from_pebbles(
            params.initial_reward.as_pebbles() / pieces as u64,
        )
        .unwrap();
        let outputs: Vec<Note> = (0..pieces)
            .map(|_| Note::new(each, keys[0].public_key()))
            .collect();
        let coinbase = CoinbaseTransaction::new(height, outputs);

        let mut transfers = Vec::new();
        let mut made: Vec<Held> = Vec::new();
        if measuring {
            while transfers.len() < transfers_each {
                let (id, note, mine) = purse.pop_front().expect("the purse was funded");
                let half = note.value.as_pebbles() / 2;
                assert!(half > 0, "a note was split until it could not be");
                let rest = note.value.as_pebbles() - half;
                let outputs = vec![
                    Note::new(
                        cairn_primitives::Amount::from_pebbles(half).unwrap(),
                        keys[1].public_key(),
                    ),
                    Note::new(
                        cairn_primitives::Amount::from_pebbles(rest).unwrap(),
                        keys[0].public_key(),
                    ),
                ];
                let mut transfer =
                    Transfer::new(vec![cairn_ledger::transaction::Input::hot(id)], outputs);
                transfer.sign_input(params.network, 0, &note, &keys[usize::from(mine)]);
                for (index, (id, note)) in transfer.created_notes().into_iter().enumerate() {
                    made.push((id, note, index == 0));
                }
                transfers.push(transfer);
            }
            assert_eq!(transfers.len(), transfers_each, "every payment was funded");
        }

        let block =
            assemble_block(&state, coinbase, transfers, &params, 1_000 + height * 60, 0).unwrap();

        let at = Instant::now();
        connect_block(&mut state, &block, &params, u64::MAX / 2).unwrap();
        if measuring {
            spent += at.elapsed().as_secs_f64();
            if index == warmup {
                header_bytes = block.header.encode().len();
            }
            block_bytes += block.encode().len();
        }
        purse.extend(
            block
                .coinbase
                .created_notes()
                .into_iter()
                .map(|(id, note)| (id, note, false)),
        );
        purse.extend(made);
    }

    // Nothing fell, so every block above is the same kind of block. Without
    // this the run would quietly start evicting once the tier filled and the
    // average would be of two different things, which is the shape of the
    // defect this whole instrument was repaired for.
    assert_eq!(
        state.cold_len(),
        0,
        "the tier filled during the run, so SAMPLE is no longer short enough"
    );

    (
        header_bytes,
        block_bytes as f64 / SAMPLE as f64,
        spent / SAMPLE as f64,
    )
}

/// What one hot note costs a node, measured rather than guessed.
///
/// `examples/footprint.rs` builds the structures and reads the resident memory
/// back: 237 bytes for the map and the ordering, 279 for the tree. It was 813
/// before a public key stopped being kept in the form it is verified in, which
/// is where the figure below used to come from and why it is named here rather
/// than written into two format strings.
const HOT_BYTES_PER_NOTE: f64 = 516.0;

fn main() {
    let params = ConsensusParams::testnet();
    let (header_bytes, empty_size, empty_cost) = measure(0);
    let (_, busy_size, busy_cost) = measure(BUSY);
    let per_block = busy_cost;

    println!("Measured over {SAMPLE} blocks each, one core");
    println!();
    println!("  header                    {header_bytes} bytes");
    println!("  block, empty              {empty_size:.0} bytes");
    println!("  block, {BUSY} transfers      {busy_size:.0} bytes");
    println!("  validation, empty         {:.3} ms", empty_cost * 1_000.0);
    println!(
        "  validation, {BUSY} transfers {:.3} ms",
        busy_cost * 1_000.0
    );
    println!();
    println!("Revalidating from nothing, at the busy rate, one block a minute:");
    println!();
    println!(
        "  {:<10} {:>12} {:>12} {:>14}",
        "age", "blocks", "headers", "revalidation"
    );
    for years in [1u64, 5, 10, 30] {
        let blocks = years * 365 * 24 * 60;
        let headers = blocks * header_bytes as u64;
        let seconds = per_block * blocks as f64;
        println!(
            "  {:<10} {:>12} {:>10.1} MB {:>11.1} h",
            format!("{years} year{}", if years == 1 { "" } else { "s" }),
            blocks,
            headers as f64 / 1_000_000.0,
            seconds / 3_600.0,
        );
    }
    println!();
    println!("And the download, at the busy rate:");
    println!();
    for years in [1u64, 10, 30] {
        let blocks = years * 365 * 24 * 60;
        println!(
            "  {:<10} {:>10.1} GB of blocks",
            format!("{years} year{}", if years == 1 { "" } else { "s" }),
            blocks as f64 * busy_size / 1_000_000_000.0,
        );
    }
    println!();
    println!("The same revalidation, at one block every ten minutes:");
    println!();
    for years in [10u64, 30] {
        let blocks = years * 365 * 24 * 6;
        let headers = blocks * header_bytes as u64;
        let seconds = per_block * blocks as f64;
        println!(
            "  {:<10} {:>12} {:>10.1} MB {:>11.1} h",
            format!("{years} years"),
            blocks,
            headers as f64 / 1_000_000.0,
            seconds / 3_600.0,
        );
    }
    println!();
    println!(
        "For comparison, the validation state a node holds is capped at {} notes, {:.0} MB.",
        params.hot_capacity,
        params.hot_capacity as f64 * HOT_BYTES_PER_NOTE / 1_000_000.0
    );
    println!();
    println!("What the header commitment costs, and what it is for:");
    println!();
    println!("  a node carries          64 hashes, 2 kB, at any age");
    println!("  a header grew by        48 bytes, {header_bytes} in total");
    let sampled = sampled_bytes(30 * 365 * 24 * 60, header_bytes);
    println!(
        "  sampled start, 30 years {} sampled headers, {:.1} MB, plus {:.0} MB of state",
        SAMPLES,
        sampled as f64 / 1_000_000.0,
        params.hot_capacity as f64 * HOT_BYTES_PER_NOTE / 1_000_000.0
    );
    println!();
    println!("The sampled figure is the draw this build actually makes, with the");
    println!("path each answer carries, against the gigabytes it takes to read");
    println!("every header instead.");
}

/// What a sampled start costs to carry, for a chain of `blocks` blocks.
///
/// One header per draw, plus the path that shows where that header sits in
/// the tip's forest. This used to be a hundred and twenty-eight headers times
/// twelve: the count was the one from before the draw was rederived, and the
/// twelve stood in for a path of the deepest kind a forest can hold, sixty-four
/// hashes. A thirty-year chain has no tree anywhere near that deep, so the
/// factor was wrong in the safe direction and the count was wrong in the other.
///
/// Both are read off the build instead. The draw is the real one, and the path
/// length is whatever tree the position falls in: a forest lays its trees out
/// largest first, so where a draw lands decides what its answer costs.
///
/// The chain is taken as one of even difficulty, so that a work value is a
/// height. That is what makes a drawn number a position; a real chain's
/// difficulty moves, and moves the mapping with it, but not the shape of the
/// forest or the count of the draw.
fn sampled_bytes(blocks: u64, header_bytes: usize) -> u64 {
    let seed = Hash32::from_bytes([7; 32]);
    let mut total = 0u64;
    for work in draw(seed, SAMPLES, u128::from(blocks), blocks) {
        let position = u64::try_from(work).unwrap_or(0);
        let depth = tree_of(blocks, position).map_or(0, |(height, _)| height);
        // The header, and the proof beside it: a sibling per level, and the
        // count the sequence is written with.
        total += header_bytes as u64 + depth as u64 * 32 + 4;
    }
    total
}

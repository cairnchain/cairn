//! What it costs to join a chain, against what it costs to read one.
//!
//! Two exchanges, both once. First a newcomer decides which chain is heaviest
//! from a sample of its headers; then it is handed the ledger at that chain's
//! tip. The handover does not grow with the chain's age at all. The sampling
//! grows by the depth of a Merkle path, which is a logarithm: the table below
//! prints it at one, ten and thirty years so the reader can see it move by
//! less than a per cent over the range.
//!
//! The sampling figure here used to be 9.4 MB and is 3.3. Both halves of it
//! were wrong: a header priced at `size_of::<BlockHeader>()`, 192, where the
//! wire writes 182, and a path priced at sixty-four levels, which is how many
//! trees a forest holds once it has `2^64` leaves rather than how deep one
//! path is. What is measured now is the encoding of a real [`SampledStart`],
//! so no arithmetic here stands between the format and the number.
//!
//! Run with `cargo run --release -p cairn-ledger --example joining`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::indexing_slicing,
    clippy::print_stdout
)]

use cairn_accumulator::forest::{tree_of, Forest, ForestProof};
use cairn_crypto::SecretKey;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::handover::BURIAL;
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::sampling::{draw, sample_bytes, Sample, SampledStart, SAMPLES, SHALLOWEST};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
/// Hot sets to measure at. The last is what the rules actually allow, and
/// mining enough blocks to fill it takes a moment.
const SIZES: [usize; 4] = [1_024, 4_096, 16_384, 131_072];
/// Chain ages the sampling is measured at, in blocks at one a minute.
const AGES: [(u64, u64); 3] = [(1, 525_600), (10, 5_256_000), (30, 15_768_000)];

fn main() {
    println!("What joining a chain costs\n");
    println!(
        "{:>12}  {:>12}  {:>12}  {:>12}",
        "hot notes", "ledger", "per note", "sampling"
    );
    println!("{}", "-".repeat(56));

    // A sampled start is a tip, its parent, sixty four hashes of history, one
    // opened header per draw, and the run from the deepest of those up to the
    // tip. It does not depend on the ledger, so it is the same on every row.
    //
    // The run is what ties the top of a chain to a difficulty anybody can
    // check, and it is about a thousand headers: the draw stops resolving that
    // far from the tip, so that is exactly the stretch nothing else looks at.
    let sampling = sampled_start_bytes(AGES[AGES.len() - 1].1);

    for capacity in SIZES {
        let bytes = handover_bytes(capacity);
        println!(
            "{:>12}  {:>12}  {:>12}  {:>12}",
            with_commas(capacity),
            format_bytes(bytes),
            format!("{} B", bytes / capacity.max(1)),
            format_bytes(sampling),
        );
    }

    println!(
        "\nThe sampling column is at thirty years. It is the only part of this\n\
         that moves with the chain's age at all, and what moves is the depth of\n\
         a Merkle path:"
    );
    for (years, blocks) in AGES {
        println!(
            "  {:<10} {:>12} blocks   {:>10}",
            format!("{years} year{}", if years == 1 { "" } else { "s" }),
            with_commas(usize::try_from(blocks).unwrap_or(0)),
            format!("{} kB", sampled_start_bytes(blocks) / 1_000),
        );
    }

    // The ceiling read off the rules rather than written here. A block that
    // full is the worst case and not the ordinary one: `examples/history.rs`
    // measures a block of sixty-four ordinary payments at twelve kilobytes,
    // and thirty years of those is 197 GB rather than what this prints.
    let full = ConsensusParams::testnet().max_block_bytes;
    println!(
        "\nAgainst reading the chain instead: thirty years of blocks at the {}\n\
         bytes a block may take is {}, and every byte of it has to be\n\
         validated. Joining this way is two exchanges that do not grow with it,\n\
         and the handover is most of the cost at the hot set the rules allow.",
        with_commas(full),
        format_bytes(
            usize::try_from(AGES[AGES.len() - 1].1)
                .unwrap_or(usize::MAX)
                .saturating_mul(full)
        ),
    );

    println!(
        "\nWhat is in a handover: the hot set, which is nearly all of it; the\n\
         cold set as sixty four hashes; the grace window with a proof for each\n\
         note in it, which is the only part that could be trimmed and is worth\n\
         its size, since without it a newcomer refuses spends everyone else\n\
         takes; and the last {RECENT_HEADERS} headers, which the difficulty rule reads."
    );

    // The run between the ledger and the tip. It is what says the ledger
    // belongs to the chain that was weighed, and it is checked block by block,
    // which is also what makes the burial cost work rather than block count.
    let buried = usize::try_from(BURIAL).unwrap_or(0) * BlockHeader::ENCODED_BYTES;
    println!(
        "\nAnd the {} headers between the ledger and the tip, {}. A newcomer is\n\
         about to ask for those blocks in full anyway, so what this adds to the\n\
         exchange is the headers arriving before the ledger is stood behind\n\
         rather than after.",
        with_commas(usize::try_from(BURIAL).unwrap_or(0)),
        format_bytes(buried),
    );
}

/// What a sampled start takes on the wire, for a chain of `blocks` headers.
///
/// Measured rather than summed: a start of the real shape is built and encoded,
/// so the tip, the parent, the sixty four hashes of history, the framing around
/// each vector and the run up to the tip are all counted by the format itself.
/// Only the depths are worked out, and they are worked out from the forest a
/// chain that long makes.
///
/// The headers are blank. Every field in one is fixed width, so what is in them
/// changes nothing about the bytes, and mining fifteen million real ones to
/// weigh them is not an option this program has.
fn sampled_start_bytes(blocks: u64) -> usize {
    let mut history = Forest::new();
    for index in 0..blocks {
        history.add(Hash32::from_bytes([(index % 251) as u8; 32]));
    }

    let seed = Hash32::from_bytes([7; 32]);
    let path = |position: u64| ForestProof {
        siblings: vec![Hash32::ZERO; tree_of(blocks, position).map_or(0, |(height, _)| height)],
    };
    let samples: Vec<Sample> = draw(seed, SAMPLES, u128::from(blocks), blocks)
        .into_iter()
        .map(|work| Sample {
            header: blank_header(),
            proof: path(u64::try_from(work).unwrap_or(0)),
        })
        .collect();

    // Two instruments for the part they share. `sampling::sample_bytes` adds
    // the drawn answers up from the encoding's field widths; this one hands
    // them to the encoding. A disagreement means one of the two has drifted,
    // which is the failure this whole example was repaired for.
    let opened: usize = samples.iter().map(|s| s.encode().len()).sum();
    assert_eq!(
        u64::try_from(opened).unwrap_or(0),
        sample_bytes(seed, blocks),
        "the drawn answers cost what the library says they cost"
    );

    let run = usize::try_from(SHALLOWEST).unwrap_or(0) + RECENT_HEADERS;
    SampledStart {
        tip: blank_header(),
        tail: vec![blank_header(); run],
        parent: Some(Sample {
            header: blank_header(),
            proof: path(blocks.saturating_sub(1)),
        }),
        history,
        samples,
    }
    .encode()
    .len()
}

fn blank_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        network: NetworkId::MAINNET,
        height: 0,
        previous: Hash32::ZERO,
        transactions_root: Hash32::ZERO,
        state_root: Hash32::ZERO,
        history: Hash32::ZERO,
        timestamp: 0,
        difficulty: 1,
        total_work: 0,
        nonce: 0,
    }
}

/// A ledger filled to `capacity` notes, handed over, measured.
fn handover_bytes(capacity: usize) -> usize {
    let params = ConsensusParams::testnet().with_hot_capacity(capacity);
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::archiving();
    let mut headers = Vec::new();
    let mut clock = 1_000u64;

    // Sixteen notes a block is what a coinbase may pay out, so filling a hot
    // set of a hundred thousand takes a while and is the point.
    let per_block = params.max_coinbase_outputs;
    let each = params.initial_reward.as_pebbles() / per_block as u64;
    let first = params.initial_reward.as_pebbles() - each * (per_block as u64 - 1);

    while state.hot_len() < capacity || headers.len() <= RECENT_HEADERS {
        let height = state.next_height().unwrap();
        clock += 600;
        let outputs: Vec<Note> = (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(
                    cairn_primitives::Amount::from_pebbles(value).unwrap(),
                    miner.public_key(),
                )
            })
            .collect();
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        headers.push(block.header);
    }

    // Measured at the tip, which no real handover is. What burying it adds is
    // the run of headers between the ledger and the tip, which is counted
    // separately below because it depends on the burial depth and not on the
    // hot set.
    let tip = *headers.last().unwrap();
    let from = headers.len().saturating_sub(RECENT_HEADERS);
    state
        .handover(
            tip,
            tip,
            state.headers_before_tip(),
            cairn_accumulator::forest::ForestProof {
                siblings: Vec::new(),
            },
            Vec::new(),
            headers[from..].to_vec(),
        )
        .expect("every note in the window has a path")
        .encode()
        .len()
}

fn with_commas(value: usize) -> String {
    let text = value.to_string();
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index > 0 && (text.len() - index) % 3 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_000_000_000 {
        return format!("{:.1} GB", bytes as f64 / 1e9);
    }
    if bytes >= 1_000_000 {
        return format!("{:.1} MB", bytes as f64 / 1e6);
    }
    format!("{} kB", bytes / 1_000)
}

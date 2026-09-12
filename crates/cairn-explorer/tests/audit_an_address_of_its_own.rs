//! What one note costs the index when notes do not share an owner.
//!
//! [`index::BYTES_PER_NOTE`] is the figure `/api/status` multiplies by, and
//! its own doc comment says where it comes from: "The dearest is the ordinary
//! payment, one note to the payee and one back as change, which has the fewest
//! notes to spread the rest over: 565 bytes a note." The comment also records
//! why the figure before it was wrong, and the reason was the same one: "it
//! was calibrated on the widest fan-out alone, which is the cheapest per note
//! and which nobody sends."
//!
//! The shape is not the whole of what sets the cost. Every shape weighed in
//! `audit_index_cost.rs` hands its outputs to a pool of three thousand
//! addresses reused block after block, so an owner entry and the two lists
//! hanging off it are spread over a hundred and thirty notes each. That ratio
//! is not a property of the traffic shape, it is not stated anywhere, and it
//! is the largest term in the answer.
//!
//! Nothing here reads a resident set. The index is walked and then weighed out
//! of what it will say about itself: the number of entries in each table, and
//! the capacity each owner's two lists actually hold. Every container, every
//! allocator header and every empty slot in a hash table is left out, so the
//! figure below is a floor under what the index occupies and not an estimate
//! of it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    dead_code
)]

#[path = "../src/index.rs"]
mod index;

use std::mem::size_of;

use cairn_crypto::PublicKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

use index::{Head, Held, Index, Movement, NoteRecord, Reading};

/// Distinct public keys, made the way `audit_index_cost.rs` makes them.
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

/// One block of ordinary payments: a transfer spends the one before it and
/// pays two owners, a payee and a change address.
///
/// `cursor` says where in `owners` this block starts, so a caller can decide
/// how many notes an owner ends up holding. That is the whole variable here.
/// Every block holds the same number of transfers, so a height's cursor is
/// its height times that, and a block can be built when it is asked for
/// rather than held in a list beside the index being weighed.
fn payment_block(
    height: u64,
    miner: PublicKey,
    owners: &[PublicKey],
    cursor: usize,
    params: &ConsensusParams,
) -> Block {
    let dust = Amount::from_pebbles(1).unwrap();
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, miner)]);
    let mut transfers: Vec<Transfer> = Vec::new();
    let mut bytes = 200 + coinbase.encode().len();
    let mut previous = NoteId::new(coinbase.id(), 0);
    let mut cursor = cursor;
    loop {
        let outputs: Vec<Note> = (0..2)
            .map(|step| Note::new(dust, owners[(cursor + step) % owners.len()]))
            .collect();
        let transfer = Transfer::new(vec![Input::hot(previous)], outputs);
        let size = transfer.encode().len();
        if bytes + size > params.max_block_bytes {
            break;
        }
        bytes += size;
        cursor += 2;
        previous = NoteId::new(transfer.id(), 0);
        transfers.push(transfer);
    }
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            network: params.network,
            height,
            previous: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 1_000 + height,
            difficulty: 1,
            total_work: u128::from(height),
            nonce: height,
        },
        coinbase,
        transfers,
    };
    block.header.transactions_root = block.transactions_root();
    assert!(block.encode().len() <= params.max_block_bytes);
    block
}

/// The bytes the index is holding, counted out of its own tables.
///
/// A floor: the key and the value of every entry, and the capacity each
/// owner's two lists have actually taken. No hash table slack, no B-tree
/// slack, no allocator header, nothing for `richest`.
fn payload(index: &Index, owners: &[PublicKey], miner: PublicKey) -> u64 {
    let size = index.size();
    let mut bytes = size
        .notes
        .saturating_mul((size_of::<NoteId>() + size_of::<NoteRecord>()) as u64);
    bytes = bytes.saturating_add(
        size.transactions
            .saturating_mul((size_of::<Hash32>() + size_of::<Location>()) as u64),
    );
    let mut seen = 0u64;
    for owner in owners.iter().chain(std::iter::once(&miner)) {
        let Some(record) = index.owner(owner) else {
            continue;
        };
        seen += 1;
        bytes = bytes.saturating_add((size_of::<PublicKey>() + size_of::<OwnerRecord>()) as u64);
        bytes = bytes
            .saturating_add((record.notes.capacity() * size_of::<NoteId>()) as u64)
            .saturating_add((record.movements.capacity() * size_of::<Movement>()) as u64);
    }
    assert_eq!(
        seen, size.owners,
        "every owner the index holds has to be weighed"
    );
    bytes
}

use index::{Location, OwnerRecord};

/// The resident set of this process, in kilobytes, as `audit_index_cost.rs`
/// reads it.
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

/// Walks the index to the tip, the way `Explorer::refresh` does.
fn read_all(index: &mut Index, head: &Head, block_at: impl Fn(u64) -> Held) {
    while index.refresh(head, &block_at, |_| None) == Reading::More {}
}

/// Weighs one chain and says what a note cost on it.
///
/// Returns the counted floor per note and the resident growth per note. The
/// second is only worth reading in a process nothing else has run in.
fn weigh(label: &str, notes_per_owner: usize) -> (u64, u64) {
    let mut params = ConsensusParams::testnet();
    params.coinbase_maturity = 0;
    let blocks = 20u64;

    // One block's worth of notes, so the owner pool can be sized from it.
    let scratch = fresh_owners(4);
    let sample = payment_block(0, scratch[0], &scratch, 0, &params);
    let per_block: usize = sample
        .transfers
        .iter()
        .map(|transfer| transfer.outputs.len())
        .sum();
    let wanted = (per_block * blocks as usize)
        .div_ceil(notes_per_owner)
        .max(2);
    // The miner is the last of them, so it is never also a payee: an owner
    // counted twice would weigh the tables wrong.
    let mut owners = fresh_owners(wanted + 1);
    let miner = owners.pop().unwrap();
    drop(sample);
    drop(scratch);

    // The owner list is made before this, so its own memory is in the
    // baseline, and the blocks are built one at a time inside the walk and
    // dropped, so none of them is either. What is left between the two
    // readings is the index.
    let baseline = rss_kb();
    let mut index = Index::new();
    let head = Head {
        tip: blocks,
        at_last_read: None,
    };
    read_all(&mut index, &head, |height| {
        if height < blocks {
            let cursor = usize::try_from(height).unwrap_or(0) * per_block;
            Held::Block(Box::new(payment_block(
                height, miner, &owners, cursor, &params,
            )))
        } else {
            Held::Waiting
        }
    });
    let grew = rss_kb().saturating_sub(baseline);

    let size = index.size();
    let held = payload(&index, &owners, miner);
    let each = held / size.notes.max(1);
    let resident = grew.saturating_mul(1024) / size.notes.max(1);
    println!(
        "{label}: {} notes over {} owners ({:.1} notes an owner), {} transactions, \
         {} movements",
        size.notes,
        size.owners,
        size.notes as f64 / size.owners.max(1) as f64,
        size.transactions,
        size.movements,
    );
    println!(
        "  the tables alone hold {held} bytes, which is {each} a note; the index \
         says {} and publishes {} MB",
        index::BYTES_PER_NOTE,
        size.bytes / 1_000_000,
    );
    std::hint::black_box(&index);
    (each, resident)
}

/// The figure the site publishes was calibrated where an owner holds a hundred
/// and thirty notes, and it is stated as a property of the traffic shape.
///
/// It is not. The same shape, with one address per note, costs more than the
/// published figure before a single byte of container overhead is counted.
/// An operator sizing a machine off `/api/status` on a chain with many
/// addresses on it is told a number that is under the floor.
#[test]
fn a_note_of_its_own_address_costs_more_than_the_index_says_a_note_costs() {
    // The first shape is weighed first so its resident reading is taken in a
    // process nothing else has allocated in, which is the only way that
    // reading is worth anything. The finding is the counted floor: two
    // readings of a machine are a measurement of the machine.
    let mut readings = Vec::new();
    for (label, per_owner) in [
        ("an address of its own for every note", 1),
        ("two notes an address", 2),
        ("four notes an address", 4),
        ("the pool the published figure was weighed on", 130),
    ] {
        let (floor, resident) = weigh(label, per_owner);
        readings.push((label, per_owner, floor, resident));
    }
    println!();
    for (at, (label, per_owner, floor, resident)) in readings.iter().enumerate() {
        // Only the first resident reading is worth printing: a later shape is
        // handed memory the one before it freed and reads far too low, which
        // is what `audit_index_cost.rs` says at the top of the file.
        let said = if at == 0 {
            format!("{resident:>4} resident")
        } else {
            "   - resident".to_owned()
        };
        println!(
            "{per_owner:>4} notes an owner: {floor:>4} bytes a note counted, {said}  ({label})"
        );
    }

    let (_, _, alone, _) = readings[0];
    assert!(
        alone <= index::BYTES_PER_NOTE,
        "one address per note costs the index at least {alone} bytes a note, and \
         `/api/status` multiplies by {}. The floor counted here leaves out every \
         hash table slot, every B-tree node's slack and every allocator header, \
         so the real figure is higher again. BYTES_PER_NOTE is a function of how \
         many notes an owner holds and its doc comment states it as a function of \
         the traffic shape alone.",
        index::BYTES_PER_NOTE,
    );
}

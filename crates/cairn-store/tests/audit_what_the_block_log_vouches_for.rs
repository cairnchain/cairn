//! What the block log will answer for, against what the header log beside it
//! will.
//!
//! The header log checks every record against the record next to it, because a
//! header carries its parent's identifier and that makes the file a hash chain
//! already written down. `read_at` on the block log checks one field: the
//! height. Everything else in a record comes back as truth.
//!
//! That matters because of which of the two files is served. Headers are shown
//! to a newcomer; blocks are handed to every peer catching up, out of
//! `cairn_net`'s `blocks_under_one_hold`, which reads them with this same
//! `read_at`. The reasoning `read_at` already carries about its height check,
//! that what it buys is the failure being this node's where it happened, is
//! the reasoning for the rest of the record too, and the price is the one the
//! header log already pays: a block encodes its header first and a header is a
//! fixed width, so the neighbour costs one seek and 182 bytes however large
//! the block is.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::counting;
use cairn_store::{BlockLog, HeaderLog, BLOCK_INDEX, BLOCK_LOG, HEADER_BYTES, HEADER_LOG};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Where `state_root` sits inside a record: four bytes of length prefix, then
/// the header, whose version, network, height, previous and transactions root
/// come first.
const STATE_ROOT_IN_RECORD: usize = 4 + 2 + 4 + 8 + 32 + 32;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-vouches-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn chain(count: usize) -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            block
        })
        .collect()
}

fn built(directory: &Path, blocks: &[Block]) {
    let (mut log, _) = BlockLog::open(directory).unwrap();
    for block in blocks {
        log.append(block).unwrap();
    }
}

/// Where each record starts, read off the log the way the index does.
fn records(bytes: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut at = 0usize;
    while at + 4 <= bytes.len() {
        starts.push(at);
        let declared = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + declared;
    }
    starts
}

fn put(path: &Path, at: u64, value: &[u8]) {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(value).unwrap();
}

/// One byte of a record's state root, which is neither its length nor its
/// height, so nothing about the shape of either file gives it away.
///
/// The log opens clean, reports five records, and answers about height two
/// with a block nobody mined. `cairn_net::Shared::blocks_under_one_hold` hands
/// that answer to whoever asked for height two, which refuses it and has every
/// reason to think the sender is the problem.
#[test]
fn a_record_with_a_changed_byte_is_not_served_as_the_block_it_is_not() {
    let blocks = chain(5);
    let directory = scratch("one-byte");
    built(&directory, &blocks);

    let path = directory.join(BLOCK_LOG);
    let whole = std::fs::read(&path).unwrap();
    let at = records(&whole)[2] + STATE_ROOT_IN_RECORD;
    put(&path, at as u64, &[whole[at] ^ 0x01]);

    let (log, recovered) = BlockLog::open(&directory).expect("the open decodes one record");
    assert_eq!(recovered.blocks, 5, "nothing about the shape gives it away");
    assert_eq!(recovered.unreadable, None);

    let answer = log.read_at(2).map(|found| found.map(|block| block.id()));
    assert!(
        !matches!(answer, Ok(Some(id)) if id != blocks[2].id()),
        "height 2 came back as a block nobody mined, and this node will send it \
         to whoever asked: {answer:?}"
    );

    // The blocks either side are untouched, so this refuses records and not
    // the log, exactly as the header log does.
    assert_eq!(log.read_at(0).unwrap().unwrap().id(), blocks[0].id());
    assert_eq!(log.read_at(4).unwrap().unwrap().id(), blocks[4].id());
    let _ = std::fs::remove_dir_all(&directory);
}

/// The same byte, in the same field, of the header log beside it.
///
/// Recorded here so the two files can be read against each other in one place:
/// this one refuses, and it has refused since the audit that put the link
/// check in.
#[test]
fn the_header_log_already_refuses_the_same_damage() {
    let blocks = chain(5);
    let directory = scratch("header-same");
    {
        let mut headers = HeaderLog::open(&directory).unwrap();
        for block in &blocks {
            headers.append(&block.header).unwrap();
        }
    }
    let path = directory.join(HEADER_LOG);
    let at = 2 * HEADER_BYTES + (STATE_ROOT_IN_RECORD - 4);
    let before = std::fs::read(&path).unwrap()[at];
    put(&path, at as u64, &[before ^ 0x01]);

    let headers = HeaderLog::open(&directory).unwrap();
    assert!(
        headers.read_at(2).is_err(),
        "the header log served a record with a changed byte"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// Every byte of the log and of its index, flipped one at a time, two bits
/// each.
///
/// The store may refuse, may come back short, may come back empty. What it may
/// not do is answer about a height with something that is not what was written
/// there, because that answer leaves this node and is refused somewhere else.
///
/// The last record is counted apart and not held to it, for the reason the
/// header log's last record is not: it has nothing after it to name it, so
/// what the record before can say about it is its height and its parent and
/// not the rest. The last record is the tip, which a node holds in memory as
/// well, and `cairn_net` answers about it out of memory before it reaches the
/// disk at all.
///
/// The index half of the sweep passes and always has: an offset off the disk
/// is checked against the record it describes. It is swept alongside so the
/// two halves are measured by the same rule.
#[test]
fn no_single_flipped_byte_makes_a_height_answer_with_another_block() {
    let blocks = chain(4);
    let source = scratch("sweep-source");
    built(&source, &blocks);
    let whole_log = std::fs::read(source.join(BLOCK_LOG)).unwrap();
    let whole_index = std::fs::read(source.join(BLOCK_INDEX)).unwrap();
    let _ = std::fs::remove_dir_all(&source);
    let want: Vec<Vec<u8>> = blocks.iter().map(Encode::encode).collect();
    let last_record = *records(&whole_log).last().unwrap();

    let mut wrong = 0usize;
    let mut wrong_in_the_last_record = 0usize;
    let mut wrong_from_the_index = 0usize;
    let mut tried = 0usize;
    let mut first = String::new();

    for (which, len) in [(0usize, whole_log.len()), (1, whole_index.len())] {
        for byte in 0..len {
            for bit in [0x01u8, 0x80] {
                tried += 1;
                let directory = scratch("sweep");
                std::fs::create_dir_all(&directory).unwrap();
                let mut log_bytes = whole_log.clone();
                let mut index_bytes = whole_index.clone();
                if which == 0 {
                    log_bytes[byte] ^= bit;
                } else {
                    index_bytes[byte] ^= bit;
                }
                std::fs::write(directory.join(BLOCK_LOG), &log_bytes).unwrap();
                std::fs::write(directory.join(BLOCK_INDEX), &index_bytes).unwrap();
                if let Ok((log, _)) = BlockLog::open(&directory) {
                    for (position, block) in blocks.iter().enumerate() {
                        if let Ok(Some(found)) = log.read_at(block.header.height) {
                            if found.encode() != want[position] {
                                if which == 1 {
                                    wrong_from_the_index += 1;
                                } else if byte >= last_record {
                                    wrong_in_the_last_record += 1;
                                } else {
                                    wrong += 1;
                                    if first.is_empty() {
                                        first = format!(
                                            "byte {byte}, bit {bit:#x}: height {} answered \
                                             with another block",
                                            block.header.height
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                let _ = std::fs::remove_dir_all(&directory);
            }
        }
    }
    eprintln!(
        "{tried} flips, {} of them inside the last record: {wrong_in_the_last_record} wrong \
         answers there, {wrong} elsewhere, {wrong_from_the_index} from the index",
        (whole_log.len() - last_record) * 2
    );
    assert_eq!(
        (wrong, wrong_from_the_index),
        (0, 0),
        "{tried} flips: {wrong} wrong answers from a record with another one \
         after it, {wrong_from_the_index} from the index. First: {first}"
    );
}

/// What the checks cost, against what the block they answer about costs.
///
/// Two of the three hash: the body is folded into a root, and the neighbour's
/// header is hashed to get the identifier the link is compared against. Both
/// are work `read_at` did not do before, on the path a peer catching up reads
/// out of, so what they cost is a fair question and the answer is owed.
///
/// Counted in bytes fed to a hasher rather than timed. What a check costs is
/// how much it hashes, and that is arithmetic; timing two runs on a loaded
/// machine measures the machine, which this project has had to learn twice.
///
/// The figure it is held against is the one a node already pays for the same
/// block: connecting it to the ledger folds the same transactions into the
/// same root and hashes the same header, plus a signature check for every
/// input and a pass over the state. A read that costs no more than that
/// cannot be the expensive half of serving a block, and a node serving out of
/// this file has already paid the larger figure for every record in it.
#[test]
fn answering_for_a_record_hashes_less_than_accepting_it_did() {
    let mut params = ConsensusParams::testnet();
    params.coinbase_maturity = 0;

    let miner = SecretKey::from_bytes(&[3; 32]);
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut spendable: Vec<Block> = Vec::new();
    let mut blocks: Vec<Block> = Vec::new();
    let mut accepted = 0u64;

    // Rewards first, then one block spending every one of them, which is a
    // block carrying as many transfers as the rewards before it allow.
    for round in 0..17usize {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let transfers: Vec<Transfer> = if round < 16 {
            Vec::new()
        } else {
            spendable
                .iter()
                .map(|earlier| {
                    let note = earlier.coinbase.outputs[0];
                    let mut transfer = Transfer::new(
                        vec![cairn_ledger::transaction::Input::hot(
                            cairn_ledger::note::NoteId::new(earlier.coinbase.id(), 0),
                        )],
                        vec![Note::new(
                            cairn_primitives::Amount::from_pebbles(note.value.as_pebbles() / 2)
                                .unwrap(),
                            miner.public_key(),
                        )],
                    );
                    transfer.sign_input(params.network, 0, &note, &miner);
                    transfer
                })
                .collect()
        };
        let block = assemble_block(&state, coinbase, transfers, &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        // What accepting the packed block costs, counted around the one call
        // that does it rather than around a second ledger built to match.
        counting::reset();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        accepted = counting::reset();
        if round < 16 {
            spendable.push(block.clone());
        }
        blocks.push(block);
    }

    let packed = blocks.last().unwrap().clone();
    let carried = packed.transfers.len();
    assert!(
        carried >= 16,
        "the block has to carry transfers to measure anything"
    );

    let directory = scratch("what-it-costs");
    built(&directory, &blocks);
    let (log, _) = BlockLog::open(&directory).unwrap();
    let height = packed.header.height;
    // Warmed, so the figure is the checks and not a first decode's cost.
    log.read_at(height).unwrap().unwrap();
    counting::reset();
    let served = log.read_at(height).unwrap().expect("the record is there");
    let read = counting::reset();
    assert_eq!(served.id(), packed.id());

    println!(
        "a block carrying {carried} transfers: {accepted} bytes hashed to accept it, \
         {read} to answer for it when it is served, {}%",
        read * 100 / accepted.max(1)
    );
    assert!(
        read <= accepted,
        "answering for a record hashes {read} bytes where accepting the same \
         block hashed {accepted}. A node has already paid the larger of the two \
         for every record in this file"
    );
}

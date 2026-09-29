//! Refusals of the store, produced for their cause.
//!
//! `StoreError::Unrooted` was only ever counted by a fuzz campaign whose tally
//! nothing asserts, and `StoreError::MissingNode`, returned from eleven places
//! in the header forest, by no test at all. A refusal nothing produces can be
//! swapped for another, or lost, with every test green.
//!
//! Three more are not produced here, and why. `Unlockable` needs a filesystem
//! that cannot lock a file, which a test cannot choose. `IndexNotWritten` needs
//! the index to open for writing and then refuse a write, which a full disk or
//! a device such as Linux's `/dev/full` does and nothing portable does; the
//! full-disk audit behind `CAIRN_AUDIT_FULL_DIR` is where it belongs.
//! `HeaderSizeChanged` compares this build's header encoding with a constant
//! of this build, so it cannot fire until a build changes one without the
//! other.

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
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};
use cairn_store::{BlockLog, HeaderTree, StoreError, BLOCK_LOG, HEADER_TREE};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-store-by-name-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
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

/// A record whose header is its own and whose body is not is refused as a body
/// its header does not name.
///
/// The body is another coinbase of the same length, so the record's framing,
/// its height and its link to its neighbours all still hold, and the one thing
/// wrong is the thing this refusal is for. Nothing produced it, so a read
/// that answered with the body or with some other refusal passed.
#[test]
fn a_record_carrying_a_body_its_header_does_not_name_is_refused_for_it() {
    let blocks = chain(5);
    let directory = scratch("unrooted");
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }

    let mut other = blocks[2].clone();
    let paid = other.coinbase.outputs[0];
    other.coinbase.outputs[0] = Note::new(
        Amount::from_pebbles(paid.value.as_pebbles() - 1).unwrap(),
        paid.owner,
    );
    let body = other.encode();
    assert_eq!(
        body.len(),
        blocks[2].encode().len(),
        "the swapped body changed the record's length"
    );
    let path = directory.join(BLOCK_LOG);
    let whole = std::fs::read(&path).unwrap();
    let start = records(&whole)[2] + 4 + BlockHeader::ENCODED_BYTES;
    put(&path, start as u64, &body[BlockHeader::ENCODED_BYTES..]);

    let (log, _) = BlockLog::open(&directory).unwrap();
    let answer = log.read_at(2).map(|found| found.map(|block| block.id()));
    let neighbours = (log.read_at(1).is_ok(), log.read_at(3).is_ok());
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        matches!(answer, Err(StoreError::Unrooted { height: 2 })),
        "a record whose body its header does not name was answered {answer:?}"
    );
    assert_eq!(
        neighbours,
        (true, true),
        "the records either side were refused too"
    );
}

/// A record whose one damaged byte is inside a signature is refused as a body
/// its header does not name.
///
/// A header named its transactions by their identifiers, which leave out
/// signatures and witnesses, so the root check read none of those bytes and
/// the link to the next record reads the header alone. A byte flipped inside a
/// signature on the disk came back from `read_at` as the block and was served
/// to peers as what the miner produced. Nothing asked this, so a log that
/// served a block nobody mined passed. The root now commits to every byte of
/// each transfer, so the same check refuses it.
#[test]
fn a_record_whose_signature_was_damaged_is_refused() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(0);
    let miner = SecretKey::from_bytes(&[1; 32]);
    let payee = SecretKey::from_bytes(&[2; 32]);
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut blocks: Vec<Block> = Vec::new();
    for height in 0..5u64 {
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let mut transfers = Vec::new();
        if height == 2 {
            let spent = Note::new(params.initial_reward, miner.public_key());
            let mut payment = Transfer::new(
                vec![Input::hot(NoteId::new(blocks[1].coinbase.id(), 0))],
                vec![Note::new(spent.value, payee.public_key())],
            );
            payment.sign_input(params.network, 0, &spent, &miner);
            transfers.push(payment);
        }
        let block = assemble_block(&state, coinbase, transfers, &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        blocks.push(block);
    }

    let directory = scratch("signature");
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks {
            log.append(block).unwrap();
        }
    }

    // Where the signature sits in the block's own encoding, found rather than
    // counted, so this does not depend on the width of what comes before it.
    let encoded = blocks[2].encode();
    let signature = blocks[2].transfers[0].inputs[0].signature.to_bytes();
    let within = encoded
        .windows(signature.len())
        .position(|window| window == signature.as_slice())
        .expect("the block's encoding carries the signature");
    let path = directory.join(BLOCK_LOG);
    let whole = std::fs::read(&path).unwrap();
    let at = records(&whole)[2] + 4 + within + 7;
    put(&path, at as u64, &[whole[at] ^ 0x01]);

    let (log, _) = BlockLog::open(&directory).unwrap();
    let answer = log.read_at(2).map(|found| found.map(|block| block.id()));
    let neighbours = (log.read_at(1).is_ok(), log.read_at(3).is_ok());
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        matches!(answer, Err(StoreError::Unrooted { height: 2 })),
        "a record with a byte of a signature damaged was answered {answer:?}"
    );
    assert_eq!(
        neighbours,
        (true, true),
        "the records either side were refused too"
    );
}

/// A level of the header forest that has lost its nodes is refused by the
/// height and the place of the node that is missing.
///
/// Nothing produced `MissingNode`, from any of the eleven places that return
/// it, so a forest that answered a node it does not have with some other
/// refusal passed. What a person is told is where in the forest to look.
#[test]
fn a_forest_level_that_lost_its_nodes_is_refused_by_the_node_missing() {
    let directory = scratch("missing");
    let mut tree = HeaderTree::open(&directory).unwrap();
    for leaf in 0..8u8 {
        tree.append(Hash32::from_bytes([leaf + 1; 32])).unwrap();
    }
    assert!(
        tree.prove_in(0, 8).unwrap().is_some(),
        "a whole forest proves"
    );

    // The level above the leaves, emptied under the open forest, the way a
    // write that never landed leaves it.
    std::fs::OpenOptions::new()
        .write(true)
        .open(directory.join(format!("{HEADER_TREE}.1")))
        .unwrap()
        .set_len(0)
        .unwrap();
    let proved = tree.prove_in(0, 8).map(|proof| proof.is_some());
    assert!(
        matches!(
            proved,
            Err(StoreError::MissingNode {
                height: 1,
                start: 0
            })
        ),
        "a proof through a node that is not there was answered {proved:?}"
    );

    // And a repair asked to rebuild over leaves nothing can vouch for.
    let mended = tree.mend_below(1, 4, &|_| Ok(None));
    drop(tree);
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        matches!(
            mended,
            Err(StoreError::MissingNode {
                height: 0,
                start: 4
            })
        ),
        "a repair over a leaf nothing vouches for was answered {mended:?}"
    );
}

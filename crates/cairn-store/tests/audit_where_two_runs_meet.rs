//! What `HeaderLog::join` means by two runs meeting.
//!
//! Its own account says "The two runs have to meet exactly: `front` ends where
//! this log begins. Anything else is refused before a byte is written." The
//! sentence is true and it is about heights. Two runs off two different chains
//! meet in height wherever one stops and the other starts, and the merge took
//! them: it writes one file, reports success, and what comes out is a log with
//! a record in it that nothing will read back, for the rest of that node's
//! life.
//!
//! Nobody reaches it today. `cairn_net::Shared::fill_headers` weighs the whole
//! collected run against the commitment the oldest held header carries before
//! it merges anything, and a run off another chain fails there. That check
//! lives one crate up, in one caller, and this is the store telling a caller
//! its runs met.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_store::HeaderLog;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-meet-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// A chain of `count` blocks, with `seed` deciding whose coinbase they pay, so
/// two seeds give two chains of the same heights and different identifiers.
fn chain(count: usize, seed: u8) -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[seed; 32]);
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

fn written(name: &str, blocks: &[Block]) -> (HeaderLog, PathBuf) {
    let directory = scratch(name);
    let mut log = HeaderLog::open(&directory).unwrap();
    for block in blocks {
        log.append(&block.header).unwrap();
    }
    (log, directory)
}

/// Heights 0, 1 and 2 of one chain in front of heights 3, 4 and 5 of another.
/// The two runs abut and nothing joins them.
#[test]
fn two_runs_that_abut_without_joining_up_are_refused() {
    let mine = chain(6, 1);
    let theirs = chain(6, 2);
    assert_eq!(
        mine[2].header.height, theirs[2].header.height,
        "the two chains have to run over the same heights"
    );
    assert_ne!(
        mine[2].header.id(),
        theirs[2].header.id(),
        "and be two chains"
    );

    let (front, front_at) = written("front", &theirs[..3]);
    let (mut log, at) = written("back", &mine[3..]);
    assert_eq!(front.reaches(), log.first_height(), "they meet in height");

    let merged = log.join(&front);
    assert!(
        merged.is_err(),
        "two runs off two chains were merged into one log, and the record where \
         they meet will not read back: {:?}",
        log.read_at(2).err()
    );
    // Nothing changed, which is what a refusal before a byte is written means.
    assert_eq!(log.first_height(), 3);
    assert_eq!(log.len(), 3);

    let _ = std::fs::remove_dir_all(&at);
    let _ = std::fs::remove_dir_all(&front_at);
}

/// The same shape where the runs do join up, so the check above refuses a
/// mismatch rather than the merge.
#[test]
fn two_runs_of_one_chain_still_merge() {
    let blocks = chain(6, 1);
    let (front, front_at) = written("good-front", &blocks[..3]);
    let (mut log, at) = written("good-back", &blocks[3..]);

    log.join(&front).expect("one chain, two runs");
    assert_eq!(log.first_height(), 0);
    assert_eq!(log.len(), 6);
    for block in &blocks {
        assert_eq!(
            log.read_at(block.header.height).unwrap().unwrap().id(),
            block.header.id()
        );
    }

    let _ = std::fs::remove_dir_all(&at);
    let _ = std::fs::remove_dir_all(&front_at);
}

/// A log says which heights it holds, at both ends of the run and on both
/// sides of it.
///
/// Three claims joined by "and": it holds something, the height is not below
/// where the run starts, and it is not past where the run reaches. Joining any
/// two of them with "or" makes a log answer for heights it does not hold, and
/// what reads this decides whether a node goes to the disk for a header or
/// tells a peer it has nothing. `cargo mutants` turned both joins and the
/// whole suite stayed green.
#[test]
fn a_log_holds_the_heights_of_its_run_and_no_others() {
    let blocks = chain(4, 1);
    let (empty, directory) = written("holds-empty", &[]);
    assert!(
        !empty.holds(0),
        "a log with nothing in it holds no height at all"
    );
    drop(empty);
    let _ = std::fs::remove_dir_all(&directory);

    let (log, directory) = written("holds", &blocks);
    assert_eq!(log.len(), 4);
    for height in 0..4 {
        assert!(log.holds(height), "the run it was given, at {height}");
    }
    assert!(
        !log.holds(log.reaches()),
        "and not the height it reaches, which is the next one to be written"
    );
    assert!(!log.holds(u64::MAX), "nor anything past that");

    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
}

/// A log with nothing in it takes any run, and one that was emptied is empty
/// on disk as well as in memory.
///
/// `join` asks whether this log holds anything before it asks whether the run
/// in front of it ends where this one starts, because a log holding nothing
/// starts nowhere. `cargo mutants` could make that first question always
/// answer yes, and a node filling in the headers from before it arrived would
/// be told its own empty log is out of order. And `clear` could do nothing at
/// all with the suite green, which is a log that says it is empty and holds
/// every header it ever had.
#[test]
fn an_empty_log_takes_any_run_and_an_emptied_one_is_empty_on_disk() {
    let blocks = chain(6, 1);

    let (front, front_directory) = written("front-run", &blocks[..3]);
    let (mut empty, empty_directory) = written("takes-any", &[]);
    assert!(empty.is_empty());
    empty
        .join(&front)
        .expect("a log holding nothing starts nowhere");
    assert_eq!(empty.len(), 3, "and takes the run it was given");

    empty.clear().unwrap();
    assert_eq!(empty.len(), 0, "an emptied log holds nothing");
    drop(empty);

    let back = HeaderLog::open(&empty_directory).unwrap();
    assert_eq!(
        back.len(),
        0,
        "and holds nothing when it is opened again, which is what says the \
         file was cut rather than the count forgotten"
    );

    drop(back);
    drop(front);
    let _ = std::fs::remove_dir_all(&front_directory);
    let _ = std::fs::remove_dir_all(&empty_directory);
}

/// A log cut back keeps the height it starts at, and says so.
///
/// `keep_below` sets the start to nought only when it kept nothing, because a
/// log that still holds headers still starts where it did. `cargo mutants`
/// could turn that test around, and then a log cut back would claim to start
/// at height nought while holding headers from somewhere else: every height
/// it answers about after that is wrong by the distance it really started at.
#[test]
fn a_log_cut_back_still_starts_where_it_started() {
    let blocks = chain(9, 1);
    let (mut log, directory) = written("cut-back", &blocks[5..]);
    assert_eq!(log.len(), 4);
    assert!(log.holds(5), "it starts at five, not at nought");
    assert!(!log.holds(0));

    log.keep_below(7).unwrap();
    assert_eq!(log.len(), 2, "heights five and six are kept");
    assert!(
        log.holds(5) && log.holds(6),
        "and it still answers for them"
    );
    assert!(
        !log.holds(0) && !log.holds(7),
        "and for nothing outside the run it has left"
    );

    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
}

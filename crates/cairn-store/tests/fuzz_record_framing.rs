//! Record framing, read off a disk that may have rotted.
//!
//! Every other byte reader in this workspace is fed by a sender. This one is
//! fed by a filesystem, which is the one source that can hand back something
//! nobody wrote: a sector that changed under the node, a machine that stopped
//! between two writes, a file restored from a backup of a different chain.
//! An audit found the block log's four byte record header and the header
//! log's fixed width records had no fuzz target between them.
//!
//! What a rebuild has to hold, whatever is on the disk:
//!
//! 1. **A start fails only because a file could not be reached.** `lib.rs`
//!    says so in its opening paragraphs: `BlockLog::open` "can then fail only
//!    because a file could not be reached, never because of what is written
//!    in one, which is what an unattended node needs from a start". That is a
//!    claim with a shape. Every other `StoreError` coming out of `open` would
//!    break it, and every one of them means a node that stays down until
//!    somebody notices.
//! 2. **Nothing is reserved for a number read off a disk.** A length prefix
//!    is not a length this process wrote. Past the ceiling it is refused by
//!    name, and near `u64::MAX` the alternative is an allocation failure,
//!    which in Rust is a process abort with no message.
//! 3. **What recovery says it did is consistent.** Bytes cut and bytes left
//!    in place are different news for an operator and are never both. The
//!    count reported is the count held.
//! 4. **Recovery settles.** Opening twice discards nothing the second time.
//!    A log that shed a record at every start is the defect `recover`'s own
//!    doc comment records having had, measured at five blocks of six.
//! 5. **A log that holds anything can read its own first record.** Recovery
//!    reads it to learn where the log begins, so this is not a hope: it is
//!    what every path through `recover` has already established, and a
//!    failure here means the log came back claiming a geography it cannot
//!    show.
//!
//! Two arms, counted apart: logs assembled out of length prefixes and
//! bodies, and a log a node wrote with bytes changed in it.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use cairn_crypto::SecretKey;
use cairn_fuzz::{mutate, Arms, Built, Campaign, Rng};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_store::{
    BlockLog, HeaderLog, Recovered, StoreError, BLOCK_INDEX, BLOCK_LOG, HEADER_BYTES, HEADER_LOG,
    MAX_RECORD_BYTES,
};

const NOW: u64 = 2_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-fuzz-store-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a scratch directory");
    directory
}

/// A short run of real blocks, built once for the whole file.
///
/// Not mined. Nothing on this path checks the work: `walk` decodes a record
/// and `read_at` checks a header against its neighbour and its own body, and
/// none of that is the nonce. Mining would cost the campaign its case count
/// for a field no reader here looks at.
fn chain() -> &'static [Block] {
    static CHAIN: OnceLock<Vec<Block>> = OnceLock::new();
    CHAIN.get_or_init(|| {
        let params = ConsensusParams::testnet();
        let miner = SecretKey::from_bytes(&[3u8; 32]);
        let mut state = LedgerState::archiving();
        let mut clock = 1_000u64;
        (0..6)
            .map(|_| {
                let height = state.next_height().unwrap();
                clock += 600;
                let coinbase = CoinbaseTransaction::new(
                    height,
                    vec![Note::new(params.initial_reward, miner.public_key())],
                );
                let block =
                    assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
                connect_block(&mut state, &block, &params, NOW).unwrap();
                block
            })
            .collect()
    })
}

/// One record: four bytes of length, then the body.
fn framed(body: &[u8]) -> Vec<u8> {
    let mut record = u32::try_from(body.len())
        .unwrap_or(u32::MAX)
        .to_le_bytes()
        .to_vec();
    record.extend_from_slice(body);
    record
}

/// A whole log of real records, and the index that names them.
fn a_real_log(count: usize) -> (Vec<u8>, Vec<u8>) {
    let mut log = Vec::new();
    let mut index = Vec::new();
    for block in chain().iter().take(count) {
        log.extend_from_slice(&framed(&block.encode()));
        index.extend_from_slice(&(log.len() as u64).to_le_bytes());
    }
    (log, index)
}

/// Puts a log and an index on the disk and opens them.
fn open_with(
    directory: &Path,
    log: &[u8],
    index: &[u8],
) -> Result<(BlockLog, Recovered), StoreError> {
    std::fs::write(directory.join(BLOCK_LOG), log).expect("the scratch file is writable");
    std::fs::write(directory.join(BLOCK_INDEX), index).expect("the scratch file is writable");
    BlockLog::open(directory)
}

/// Whether a failed open is one the module says is possible.
///
/// The whole list of what an unattended start is allowed to die of. Anything
/// else is a node that will not come back up because of what is written in a
/// file, which is the thing `lib.rs` promises cannot happen.
fn only_about_reaching_a_file(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Io(_) | StoreError::IndexNotWritten { .. } | StoreError::Unlockable { .. }
    )
}

/// Everything an opened log has to be, whatever was on the disk.
///
/// Returns whether it came back holding a record, so a campaign can say how
/// far each arm got.
fn holds(
    directory: &Path,
    log: &BlockLog,
    recovered: &Recovered,
    case: usize,
    served: &mut Served,
) -> bool {
    assert_eq!(
        recovered.blocks,
        log.len(),
        "recovery reported {} records and the log holds {} (case {case})",
        recovered.blocks,
        log.len()
    );

    // Bytes gone and bytes still there are different news and never both.
    // An operator told bytes are gone looks for a backup; one told bytes are
    // unreadable and still on the disk looks at them.
    if recovered.unreadable.is_some() {
        assert_eq!(
            recovered.discarded_bytes, 0,
            "damage was reported as an unfinished write as well (case {case})"
        );
    }
    if recovered.left_in_place > 0 {
        assert!(
            recovered.unreadable.is_some(),
            "{} bytes were left in place with nothing said about why (case {case})",
            recovered.left_in_place
        );
    }

    // Every record costs its own four byte header at the very least, so a
    // count of records is bounded by the file. A log reporting more records
    // than the file could frame would be one whose count came from the index
    // rather than from the log, which is the direction this whole module
    // refuses to read in.
    let logged = std::fs::metadata(directory.join(BLOCK_LOG))
        .map(|found| found.len())
        .unwrap_or(0);
    assert!(
        (log.len() as u64).saturating_mul(4) <= logged,
        "the log says it holds {} records and the file is {logged} bytes \
         (case {case})",
        log.len()
    );

    if log.is_empty() {
        assert_eq!(
            log.first_height(),
            0,
            "an empty log starts nowhere (case {case})"
        );
        return false;
    }

    // Recovery read this record to learn where the log begins, by every path
    // through it, so a failure here is a log that came back claiming a
    // geography it cannot show.
    let first = log
        .read(0)
        .unwrap_or_else(|error| {
            panic!("the first record would not read back: {error} (case {case})")
        })
        .unwrap_or_else(|| panic!("the log holds records and has no record zero (case {case})"));
    assert_eq!(
        first.header.height,
        log.first_height(),
        "the log starts at a height its own first record does not (case {case})"
    );
    assert_eq!(
        log.reaches(),
        log.first_height().saturating_add(log.len() as u64),
        "the log reaches somewhere other than its own length (case {case})"
    );

    // Every other record answers or refuses by name, and never with an
    // allocation. `read` reserves from the log's own prefix and checks it
    // against the ceiling and against the index, which is what makes this
    // loop safe to run on bytes nobody wrote.
    for index in 0..log.len() {
        match log.read(index) {
            Ok(Some(block)) => {
                // A record that decoded is a record whose bytes are all
                // there, so its height is a number and its own body answers
                // to its own header or it does not; both are findings for
                // `read_at`, not for here.
                let _ = block.header.height;
            }
            Ok(None) => panic!("record {index} of {} is missing (case {case})", log.len()),
            Err(error) => assert!(
                !matches!(error, StoreError::Io(_)),
                "record {index} failed as a filesystem error rather than as damage: \
                 {error} (case {case})"
            ),
        }
    }

    // And the path a peer's catch-up is served out of, which is the one that
    // leaves the node. A block or a named refusal; never a panic.
    //
    // Counted by which refusal, because this is where the assertion could be
    // about nothing. The three checks `read_at` makes and `read` does not are
    // the ones that were added after a bit sweep found 1681 answers of 1984
    // coming back as blocks nobody mined, and a campaign that never reached
    // them would be asserting the shape of an error it never saw.
    for height in log.first_height()..log.reaches() {
        match log.read_at(height) {
            Ok(Some(block)) => {
                assert_eq!(
                    block.header.height, height,
                    "a record was served under the wrong height (case {case})"
                );
                served.answered = served.answered.saturating_add(1);
            }
            Ok(None) => panic!("the log holds {height} and would not give it (case {case})"),
            Err(error) => match error {
                StoreError::Displaced { .. } => {
                    served.displaced = served.displaced.saturating_add(1);
                }
                StoreError::Unrooted { .. } => {
                    served.unrooted = served.unrooted.saturating_add(1);
                }
                StoreError::Unlinked { .. } => {
                    served.unlinked = served.unlinked.saturating_add(1);
                }
                StoreError::Malformed { .. }
                | StoreError::Misindexed { .. }
                | StoreError::Mismatched { .. }
                | StoreError::RecordTooLarge { .. } => {
                    served.framing = served.framing.saturating_add(1);
                }
                other => panic!(
                    "serving height {height} failed with {other}, which is not \
                     damage to a record (case {case})"
                ),
            },
        }
    }

    true
}

/// How the path a peer is served out of answered, by branch.
#[derive(Clone, Copy, Debug, Default)]
struct Served {
    answered: usize,
    /// A record whose header names a height other than the one it sits at.
    displaced: usize,
    /// A record holding transactions its own header does not name.
    unrooted: usize,
    /// A record the record beside it does not name.
    unlinked: usize,
    /// Refused before any of the three above, by the framing.
    framing: usize,
}

/// A log assembled out of length prefixes and bodies.
///
/// The fresh arm is built rather than drawn for the reason the other three
/// targets in this audit are: a four byte prefix decides everything, and a
/// drawn one is a number in the billions. `plausible_bytes` puts a length
/// under the ceiling about one time in nine against one in seventy for
/// `bytes`, which helps and is not enough on its own, so the lengths here
/// are written rather than drawn and only the bodies are generated.
fn a_log(rng: &mut Rng) -> (Vec<u8>, Vec<u8>) {
    let mut log = Vec::new();
    let mut index = Vec::new();
    let blocks = chain();

    for _ in 0..rng.between(0, 5) {
        let body = match rng.below(8) {
            // A real block, which is the only body that decodes and so the
            // only one that makes a record a record.
            0..=4 => blocks
                .get(rng.below(blocks.len()))
                .map(Encode::encode)
                .unwrap_or_default(),
            5 => Vec::new(),
            6 => {
                let len = rng.between(0, 300);
                rng.plausible_bytes(len)
            }
            _ => {
                // A real block with bytes changed in it, which is the body
                // that gets furthest into the decoder before it is refused.
                let encoded = blocks.first().map(Encode::encode).unwrap_or_default();
                mutate(rng, &encoded, std::slice::from_ref(&encoded))
            }
        };

        let declared = match rng.below(12) {
            // A prefix that does not match the body, which is the shape of a
            // write cut short and of a sector that changed.
            0 => rng.edgy_u32(),
            1 => u32::try_from(MAX_RECORD_BYTES)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
            2 => u32::MAX,
            3 => u32::try_from(body.len())
                .unwrap_or(u32::MAX)
                .saturating_add(1),
            4 => u32::try_from(body.len())
                .unwrap_or(u32::MAX)
                .saturating_sub(1),
            _ => u32::try_from(body.len()).unwrap_or(u32::MAX),
        };
        log.extend_from_slice(&declared.to_le_bytes());
        log.extend_from_slice(&body);
        index.extend_from_slice(&(log.len() as u64).to_le_bytes());
    }

    // And then the index, which is a file like any other and is where a
    // number a reader acts on can come from without a record behind it.
    match rng.below(8) {
        0 => index.clear(),
        1 => index.truncate(index.len().saturating_sub(rng.between(1, 8))),
        2 => index.extend_from_slice(&rng.edgy_u64().to_le_bytes()),
        3 => {
            let at = rng.below(index.len().max(1));
            if let Some(byte) = index.get_mut(at) {
                *byte ^= 1u8 << (rng.below(8) as u32);
            }
        }
        4 => {
            let len = rng.between(0, 40);
            index = rng.plausible_bytes(len);
        }
        _ => {}
    }

    // A tail past the last record, which is what a crash during an append
    // leaves and what recovery has to tell from damage.
    if rng.chance(4) {
        let len = rng.between(1, 40);
        log.extend_from_slice(&rng.plausible_bytes(len));
    }

    (log, index)
}

/// Logs a node itself wrote, for the bending arm.
fn corpus() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for count in [1usize, 2, 4, 6] {
        seeds.push(a_real_log(count).0);
    }
    seeds
}

#[test]
fn a_log_of_any_bytes_opens_or_says_a_file_could_not_be_reached() {
    let campaign = Campaign::named("store: block log framing");
    let directory = scratch("framing");
    let corpus = corpus();
    let mut arms = Arms::default();
    let mut refused = 0usize;
    let mut served = Served::default();

    // Fifteen hundred rather than the twenty thousand the pure decoder
    // campaigns run. Every case here writes two files and reads every record
    // back through the path a peer is served out of, which is six
    // milliseconds against a codec case's microsecond. `CAIRN_FUZZ_SECONDS`
    // is what this target is really for.
    let ran = campaign.run(1_500, |case, rng| {
        let (built, log, index) = if rng.bool() {
            let (log, index) = a_log(rng);
            (Built::FromNothing, log, index)
        } else {
            let seed = rng.pick(&corpus).cloned().unwrap_or_default();
            let bent = mutate(rng, &seed, &corpus);
            // The index bent alongside the log, because the pair is what a
            // start reads and a campaign that always handed a sound index
            // would never reach `bounds`.
            let mut index = Vec::new();
            for _ in 0..rng.between(0, 6) {
                index.extend_from_slice(&rng.edgy_u64().to_le_bytes());
            }
            (Built::ByBending, bent, index)
        };

        match open_with(&directory, &log, &index) {
            Ok((opened, recovered)) => {
                arms.saw(
                    built,
                    holds(&directory, &opened, &recovered, case, &mut served),
                );
            }
            Err(error) => {
                assert!(
                    only_about_reaching_a_file(&error),
                    "a start failed because of what is written in a file: {error} \
                     (case {case})"
                );
                refused += 1;
                arms.saw(built, false);
            }
        }
    });

    arms.report("store: block log framing");
    eprintln!("store: {refused} opens failed, all of them about reaching a file");
    eprintln!("store: records served {served:?}");
    assert!(ran.cases >= 500, "the campaign ran {} cases", ran.cases);
    assert!(
        arms.from_nothing.accepted > 0,
        "not one assembled log came back holding a record: {:?}",
        arms.from_nothing
    );
    assert!(
        arms.by_bending.accepted > 0,
        "not one bent log came back holding a record: {:?}",
        arms.by_bending
    );
    // The path a peer is served out of was reached and answered. Without
    // this, every assertion inside the loop is one a log holding nothing
    // satisfies for free.
    assert!(
        served.answered > 0,
        "no record was ever served, so the checks on the serving path were \
         never reached"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// Opening twice is the same as opening once.
///
/// The campaign above says nothing about what a second start finds, and a
/// second start is what a node actually does for the rest of its life. This
/// is the shape of the defect `recover`'s own doc comment records: six blocks
/// measured, five of them gone, because a short index was believed. A log
/// that sheds a record at every start passes every assertion above, once.
#[test]
fn a_second_start_finds_what_the_first_one_left() {
    let campaign = Campaign::named("store: recovery settles");
    let directory = scratch("settles");
    let corpus = corpus();

    let ran = campaign.run(750, |case, rng| {
        let (log, index) = if rng.bool() {
            a_log(rng)
        } else {
            let seed = rng.pick(&corpus).cloned().unwrap_or_default();
            let bent = mutate(rng, &seed, &corpus);
            let (_, index) = a_real_log(rng.between(0, 6));
            (bent, index)
        };

        let Ok((first, found)) = open_with(&directory, &log, &index) else {
            return;
        };
        let held = first.len();
        let reaches = first.reaches();
        let unreadable = found.unreadable;
        drop(first);

        let (again, second) = BlockLog::open(&directory).unwrap_or_else(|error| {
            panic!("a second start failed where the first did not: {error} (case {case})")
        });
        assert_eq!(
            again.len(),
            held,
            "a second start found {} records where the first left {held} (case {case})",
            again.len()
        );
        assert_eq!(
            again.reaches(),
            reaches,
            "a second start put the log at a different height (case {case})"
        );
        assert_eq!(
            second.discarded_bytes, 0,
            "a second start threw away {} more bytes (case {case})",
            second.discarded_bytes
        );
        assert_eq!(
            second.unreadable, unreadable,
            "a second start disagreed about which record is damaged (case {case})"
        );
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    let _ = std::fs::remove_dir_all(&directory);
}

/// One number changed in the middle of the index, which is the damage the
/// index is not checked against anywhere else.
///
/// `recover` only ever compares the last offset with the length of the log,
/// so every other entry is checked in `bounds` or nowhere. The doc comment
/// there records what nowhere cost: "one flipped byte in the middle of the
/// index used to pass the open untouched and hand `read` a record size chosen
/// by the file, and near `u64::MAX` that is an allocation failure, which in
/// Rust is a process abort with no message".
///
/// The middle, on purpose. Recovery reads record zero and the last record and
/// rebuilds from the log if either fails, so those two are already covered
/// and an entry between them is the one that survives the start.
#[test]
fn a_number_changed_in_the_middle_of_the_index_costs_one_record() {
    let campaign = Campaign::named("store: a damaged index entry");
    let directory = scratch("index");
    let (log, sound) = a_real_log(6);
    let entries = sound.len() / 8;
    assert!(entries >= 4, "the sweep needs a middle to damage");

    let mut refused = 0usize;
    let mut survived = 0usize;
    let mut kept = 0usize;

    let ran = campaign.run(1_000, |case, rng| {
        let mut index = sound.clone();
        // Never the first entry and never the last: those two are read at
        // every start and send recovery back to the log.
        let entry = rng.between(1, entries.saturating_sub(2));
        let at = entry.saturating_mul(8);
        let value = if rng.chance(2) {
            rng.edgy_u64()
        } else {
            // Near the sound value, which is the damage a single changed bit
            // makes and the damage a check on the difference would miss.
            let sound_value = u64::from_le_bytes(sound[at..at + 8].try_into().unwrap());
            sound_value ^ (1u64 << (rng.below(64) as u32))
        };
        index[at..at + 8].copy_from_slice(&value.to_le_bytes());

        let Ok((opened, recovered)) = open_with(&directory, &log, &index) else {
            panic!("a damaged index entry stopped a start (case {case})")
        };
        holds(
            &directory,
            &opened,
            &recovered,
            case,
            &mut Served::default(),
        );

        // The premise of the whole test. Recovery reads the first record and
        // the last and rebuilds from the log if either fails, so a start that
        // rebuilt would have written the damaged entry away and left this
        // campaign asking about a sound index. It does not: the entry sits
        // between the two records that are checked, and the start keeps every
        // record.
        assert_eq!(
            opened.len(),
            entries,
            "the start rebuilt the index, so nothing damaged survived to be \
             read (case {case})"
        );
        kept += 1;

        // The record the damaged entry names, and the one after it, are the
        // two the entry decides the bounds of. Either answers or refuses by
        // name; nothing reserves against the number.
        for index in [entry, entry.saturating_add(1)] {
            if index >= opened.len() {
                continue;
            }
            match opened.read(index) {
                Ok(Some(_)) => survived += 1,
                Ok(None) => panic!("record {index} went missing (case {case})"),
                Err(error) => {
                    assert!(
                        matches!(
                            error,
                            StoreError::Misindexed { .. }
                                | StoreError::Mismatched { .. }
                                | StoreError::RecordTooLarge { .. }
                                | StoreError::Malformed { .. }
                        ),
                        "a damaged index entry gave {error} (case {case})"
                    );
                    refused += 1;
                }
            }
        }
    });

    assert!(ran.cases >= 200, "the campaign ran {} cases", ran.cases);
    eprintln!(
        "store: {kept} starts kept the damaged entry, {refused} records refused \
         by name, {survived} read anyway"
    );
    // What this measured, and it is a result rather than a worry: two
    // thousand damaged entries over a thousand cases, and every one of them
    // refused. The reason is that the index gives a record a span and the
    // record's own prefix gives it a length, and `read` requires the two to
    // agree exactly. Any change to either end of an entry moves a span, so
    // there is no changed entry that reads through as though nothing had
    // happened. The count is printed rather than asserted equal, because a
    // drawn value that happened to land on the sound one would fail an
    // equality and would not be a defect.
    assert!(kept > 0, "no start ever kept a damaged entry to be read");
    assert!(
        refused > 0,
        "no damaged entry was ever refused, so this campaign is measuring a \
         reader it never reached"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A length prefix past the ceiling is refused by name and nothing is
/// reserved for it.
///
/// The distinction is the same one `fuzz_codec.rs` makes about a sequence
/// count. A reader that checked the number first answers `RecordTooLarge`; a
/// reader that found out by trying would have asked this process for four
/// gigabytes on the way. The index says the record is small, so `bounds`
/// lets it through and the log's own prefix is what `read` has to catch.
#[test]
fn a_length_prefix_past_the_ceiling_is_refused_by_name() {
    let campaign = Campaign::named("store: a length past the ceiling");
    let directory = scratch("ceiling");
    let (sound, index) = a_real_log(6);

    let ran = campaign.run(2_000, |case, rng| {
        let mut log = sound.clone();
        // The second record's prefix, for the reason the test above damages
        // the middle of the index: recovery reads the first and the last.
        let at = u64::from_le_bytes(index[0..8].try_into().unwrap()) as usize;
        let declared = match rng.below(4) {
            0 => u32::try_from(MAX_RECORD_BYTES)
                .unwrap_or(u32::MAX)
                .saturating_add(1),
            1 => u32::MAX,
            2 => 0x8000_0000,
            _ => {
                u32::try_from(MAX_RECORD_BYTES).unwrap_or(u32::MAX)
                    + u32::try_from(rng.between(1, 1 << 20)).unwrap_or(1)
            }
        };
        log[at..at + 4].copy_from_slice(&declared.to_le_bytes());

        let (opened, recovered) = open_with(&directory, &log, &index)
            .unwrap_or_else(|error| panic!("a bad prefix stopped a start: {error} (case {case})"));
        holds(
            &directory,
            &opened,
            &recovered,
            case,
            &mut Served::default(),
        );

        match opened.read(1) {
            Err(StoreError::RecordTooLarge {
                declared: found, ..
            }) => assert_eq!(
                found, declared as usize,
                "the refusal named a different length (case {case})"
            ),
            // A start that rebuilt from the log put the record count
            // somewhere else, so there is no record one to ask about.
            Ok(None) => {}
            other => panic!(
                "a prefix of {declared} was answered with {other:?} rather than \
                 refused where it was read (case {case})"
            ),
        }
    });

    assert!(ran.cases >= 200, "the campaign ran {} cases", ran.cases);
    let _ = std::fs::remove_dir_all(&directory);
}

/// The header log, whose records have no framing at all.
///
/// A header is a fixed width and every field in it is a fixed width
/// primitive with no validation, so `headers.rs` says out loud that "any 182
/// bytes decode into a header and there is no such thing here as a header
/// that cannot be read". That makes this the one reader where the campaign
/// cannot be about refusing bad bytes, because there are none. It is about
/// what the log does with bytes that decode into headers nobody wrote.
#[test]
fn a_header_log_of_any_bytes_opens_and_answers_for_its_head() {
    let campaign = Campaign::named("store: header log framing");
    let directory = scratch("headers");
    let path = directory.join(HEADER_LOG);
    let sound: Vec<u8> = chain()
        .iter()
        .flat_map(|block| block.header.encode())
        .collect();
    let corpus = vec![sound.clone()];
    let mut arms = Arms::default();

    let ran = campaign.run(1_500, |case, rng| {
        let (built, bytes) = if rng.bool() {
            // Whole records and part records, because a part record is what
            // an append cut short leaves and cutting it back is the one thing
            // `open` does to the file.
            let whole = rng.between(0, 4).saturating_mul(HEADER_BYTES);
            let part = rng.between(0, HEADER_BYTES);
            let len = whole.saturating_add(part);
            (Built::FromNothing, rng.plausible_bytes(len))
        } else {
            (Built::ByBending, mutate(rng, &sound, &corpus))
        };
        std::fs::write(&path, &bytes).expect("the scratch file is writable");

        let log = HeaderLog::open(&directory)
            .unwrap_or_else(|error| panic!("a header log would not open: {error} (case {case})"));

        let on_disk = std::fs::metadata(&path)
            .map(|found| found.len())
            .unwrap_or(0);
        assert_eq!(
            on_disk % HEADER_BYTES as u64,
            0,
            "a part record was left on the file (case {case})"
        );
        let records = on_disk / HEADER_BYTES as u64;
        // Either every record is held, or none is and the bytes are left
        // alone. The second is what a head that its neighbour contradicts
        // comes to: `open` reports holding nothing rather than a geography it
        // made up, and leaves the file for somebody to look at.
        assert!(
            log.len() == records || log.is_empty(),
            "a log of {records} records came back holding {} (case {case})",
            log.len()
        );
        assert_eq!(
            log.reaches(),
            log.first_height().saturating_add(log.len()),
            "a log reaches somewhere other than its own length (case {case})"
        );

        if log.is_empty() {
            assert!(!log.holds(0), "an empty log holds nothing (case {case})");
            arms.saw(built, false);
            return;
        }

        // The head accounted for itself at open, by both of the two things
        // that can be wrong with it, so reading it back has to work. A
        // failure here is the log disagreeing with the check it just passed.
        let head = log
            .read_at(log.first_height())
            .unwrap_or_else(|error| panic!("the head would not read back: {error} (case {case})"))
            .unwrap_or_else(|| panic!("a log that holds records has no head (case {case})"));
        assert_eq!(
            head.height,
            log.first_height(),
            "the head is not at the height the log starts at (case {case})"
        );

        // Every other record answers or is named damage. Never `Ok(None)`:
        // the log said it holds these heights.
        for height in log.first_height()..log.reaches() {
            match log.read_at(height) {
                Ok(Some(header)) => assert_eq!(header.height, height),
                Ok(None) => panic!("the log holds {height} and would not give it (case {case})"),
                Err(error) => assert!(
                    matches!(
                        error,
                        StoreError::Displaced { .. }
                            | StoreError::Unlinked { .. }
                            | StoreError::Malformed { .. }
                    ),
                    "reading height {height} gave {error} (case {case})"
                ),
            }
        }
        arms.saw(built, true);
    });

    arms.report("store: header log framing");
    assert!(ran.cases >= 500, "the campaign ran {} cases", ran.cases);
    assert!(
        arms.from_nothing.accepted > 0,
        "not one assembled header log came back holding a record: {:?}",
        arms.from_nothing
    );
    assert!(
        arms.by_bending.accepted > 0,
        "not one bent header log came back holding a record: {:?}",
        arms.by_bending
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The measurement behind the fresh arm being assembled rather than drawn.
///
/// The claim this file makes about `plausible_bytes` and about writing the
/// lengths rather than drawing them, in runnable form.
#[test]
fn the_fresh_arm_is_worth_running() {
    let directory = scratch("worthwhile");
    let mut rng = Rng::new(31);
    let mut assembled = 0usize;
    let mut drawn = 0usize;

    for _ in 0..400 {
        let (log, index) = a_log(&mut rng);
        if let Ok((opened, _)) = open_with(&directory, &log, &index) {
            if !opened.is_empty() {
                assembled += 1;
            }
        }

        let len = rng.between(0, 600);
        let log = rng.bytes(len);
        let len = rng.between(0, 40);
        let index = rng.bytes(len);
        if let Ok((opened, _)) = open_with(&directory, &log, &index) {
            if !opened.is_empty() {
                drawn += 1;
            }
        }
    }

    eprintln!("store: {assembled} assembled logs held a record, {drawn} drawn ones");
    // A hundred and twenty five of four hundred as measured, and the floor is
    // set well under it: the number moves with the vocabulary, and a test
    // that has to be retuned on every change is a test people delete.
    assert!(
        assembled > 60,
        "only {assembled} of 400 assembled logs came back holding a record"
    );
    assert_eq!(
        drawn, 0,
        "{drawn} drawn logs held a record, so the assembler is no longer buying \
         anything"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The ceiling and the record header, pinned rather than sampled.
#[test]
fn the_edges_of_a_record_are_where_they_say_they_are() {
    let directory = scratch("edges");

    // A log holding nothing at all.
    let (log, recovered) = open_with(&directory, &[], &[]).expect("an empty directory opens");
    assert!(log.is_empty());
    assert_eq!(recovered.discarded_bytes, 0);
    assert_eq!(recovered.unreadable, None);
    drop(log);

    // Four bytes that say zero and no body. Not a block, and the walk stops
    // at it rather than at the end of the file, so nothing is cut.
    let (log, recovered) = open_with(&directory, &0u32.to_le_bytes(), &[]).expect("it opens");
    assert!(log.is_empty());
    assert_eq!(
        recovered.unreadable,
        Some(0),
        "a zero length record is damage"
    );
    assert_eq!(recovered.discarded_bytes, 0, "and damage is never cut");
    assert_eq!(recovered.left_in_place, 4);
    drop(log);

    // Three bytes, which cannot even be a length. The file ends inside the
    // record, so they are cut.
    let (log, recovered) = open_with(&directory, &[1, 2, 3], &[]).expect("it opens");
    assert!(log.is_empty());
    assert_eq!(recovered.unreadable, None, "a short write is not damage");
    assert_eq!(recovered.discarded_bytes, 3);
    drop(log);

    // A length past the ceiling is damage whether or not the bytes behind it
    // are there, and the start is not refused either way, which is what that
    // ceiling was put here for.
    //
    // Whether the file is long enough to hold what a length claims used to
    // decide this, and it decided it wrongly: the same four bytes are what one
    // bad byte leaves in the first record of a full log, where reading them as
    // a torn tail deleted every whole record behind them. So the length of the
    // file no longer decides it, and these four are left where a reader can
    // still see them rather than cut.
    let over = u32::try_from(MAX_RECORD_BYTES)
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    let (log, recovered) = open_with(&directory, &over.to_le_bytes(), &[]).expect("it opens");
    assert!(log.is_empty(), "nothing was reserved and the node starts");
    assert_eq!(
        recovered.unreadable,
        Some(0),
        "a length nothing wrote is damage"
    );
    assert_eq!(recovered.discarded_bytes, 0, "and damage is never cut");
    assert_eq!(recovered.left_in_place, 4);
    drop(log);

    let _ = std::fs::remove_dir_all(&directory);
}

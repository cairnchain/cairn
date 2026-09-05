//! What the store does when it runs out of room, and what it does with a file
//! that came back torn.
//!
//! An adversarial pass. Every test here states the claim it is testing and the
//! scenario that puts it under strain; a test that passes is a claim that held.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_store::{
    BlockLog, HeaderLog, HeaderTree, StoreError, BLOCK_INDEX, BLOCK_LOG, HEADER_LOG,
};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-out-of-room-{}-{name}", std::process::id()));
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

fn cut_to(path: &Path, bytes: u64) {
    OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(bytes)
        .unwrap();
}

fn put(path: &Path, at: u64, value: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(value).unwrap();
}

// ---------------------------------------------------------------------------
// A torn block log, cut at every plausible point.
// ---------------------------------------------------------------------------

/// The claim: a log cut short at any byte opens, and what comes back is a
/// prefix of what went in.
///
/// Both files are cut together, which is the shape a `set_len` interrupted by
/// a crash leaves, and separately, which is the shape a torn append leaves.
#[test]
fn a_log_cut_at_every_length_opens_to_a_prefix() {
    let blocks = chain(6);
    let source = scratch("sweep-source");
    built(&source, &blocks);
    let whole = std::fs::read(source.join(BLOCK_LOG)).unwrap();
    let index = std::fs::read(source.join(BLOCK_INDEX)).unwrap();
    let _ = std::fs::remove_dir_all(&source);

    for cut in 0..=whole.len() {
        let directory = scratch("sweep");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(BLOCK_LOG), &whole[..cut]).unwrap();
        std::fs::write(directory.join(BLOCK_INDEX), &index).unwrap();

        let opened = BlockLog::open(&directory);
        let (log, _) =
            opened.unwrap_or_else(|error| panic!("cut at {cut} refused to open: {error}"));
        let back: Vec<Block> = log.replay().map(Result::unwrap).collect();
        assert!(
            back.len() <= blocks.len(),
            "cut at {cut} produced more blocks than went in"
        );
        for (position, block) in back.iter().enumerate() {
            assert_eq!(
                block.id(),
                blocks[position].id(),
                "cut at {cut} changed the block at {position}"
            );
        }
        let _ = std::fs::remove_dir_all(&directory);
    }
}

/// The claim under test, from `recover`: the index is derived, so losing it
/// costs one slow start and nothing else.
///
/// It used to cost the chain. `recover` rebuilt only when the index held no
/// whole entry at all, or when its last offset reached past the log. An index
/// that was merely short was believed and the log was cut back to it, so every
/// block the index no longer named was deleted from a file that still held it.
/// Six blocks in a 1488 byte log, eight bytes of index left: five of the six
/// gone, and the operator told that 1240 bytes of an unfinished write had been
/// dropped.
///
/// Getting short took no adversary. `rebuild` wrote the index with no sync and
/// is exactly what runs after a crash, so a second crash before it reached the
/// platter left this state.
///
/// The log is the record now in both directions. Every cut of the index comes
/// back to the same six blocks and the same file.
#[test]
fn an_index_cut_short_is_written_again_from_the_log() {
    let blocks = chain(6);
    let source = scratch("index-source");
    built(&source, &blocks);
    let whole = std::fs::read(source.join(BLOCK_LOG)).unwrap();
    let index = std::fs::read(source.join(BLOCK_INDEX)).unwrap();
    let _ = std::fs::remove_dir_all(&source);

    for cut in 0..=index.len() {
        let directory = scratch("index-sweep");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(BLOCK_LOG), &whole).unwrap();
        std::fs::write(directory.join(BLOCK_INDEX), &index[..cut]).unwrap();

        let (log, recovered) = BlockLog::open(&directory)
            .unwrap_or_else(|error| panic!("index cut at {cut} refused to open: {error}"));
        assert_eq!(
            log.len(),
            blocks.len(),
            "index cut to {cut} bytes lost blocks the log still held"
        );
        assert_eq!(recovered.discarded_bytes, 0, "index cut to {cut} bytes");
        assert_eq!(recovered.unreadable, None, "index cut to {cut} bytes");
        let back: Vec<Block> = log.replay().map(Result::unwrap).collect();
        for (position, block) in back.iter().enumerate() {
            assert_eq!(block.id(), blocks[position].id(), "index cut to {cut}");
        }
        drop(log);

        assert_eq!(
            std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len() as usize,
            whole.len(),
            "index cut to {cut} bytes shortened the log"
        );
        // And written back down, so the slow start is the one start.
        assert_eq!(
            std::fs::read(directory.join(BLOCK_INDEX)).unwrap(),
            index,
            "index cut to {cut} bytes was not put back"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}

/// The other half of the same rule: the record whose offset never landed comes
/// back rather than being thrown away.
///
/// A crash between the two writes of an append is the ordinary case, and it
/// used to cost the block: the log was cut to the index. The record is whole
/// and was synced before the offset was even attempted, so reading forward
/// from where the index stops finds it, at the price of one record walked.
#[test]
fn a_record_whose_offset_never_landed_is_named_rather_than_dropped() {
    let blocks = chain(4);
    let directory = scratch("lost-offset");
    built(&directory, &blocks);

    // The last offset removed, which is the state an append that wrote its
    // record and stopped leaves behind.
    let index = directory.join(BLOCK_INDEX);
    let held = std::fs::metadata(&index).unwrap().len();
    cut_to(&index, held - 8);

    let (log, recovered) = BlockLog::open(&directory).unwrap();
    assert_eq!(log.len(), 4, "the block was accepted and it is still here");
    assert_eq!(recovered.discarded_bytes, 0);
    assert_eq!(log.read(3).unwrap().unwrap().id(), blocks[3].id());
    drop(log);

    assert_eq!(
        std::fs::metadata(&index).unwrap().len(),
        held,
        "and the offset was written back"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------
// A block log with bytes changed rather than lost.
// ---------------------------------------------------------------------------

/// The claim under test: a node refuses or repairs, never carries on with
/// something wrong.
///
/// One byte flipped inside a record's body, with the index intact. The open
/// path reads sixteen bytes and decodes nothing, so nothing notices here; the
/// question is whether anything notices later.
#[test]
fn a_flipped_byte_in_a_record_is_not_noticed_until_it_is_read() {
    let blocks = chain(4);
    let directory = scratch("flip-body");
    built(&directory, &blocks);

    // Somewhere inside the second record, past its length prefix.
    let log = directory.join(BLOCK_LOG);
    let at = std::fs::metadata(&log).unwrap().len() / 2;
    let before = std::fs::read(&log).unwrap()[at as usize];
    put(&log, at, &[before ^ 0xff]);

    let (log, recovered) = BlockLog::open(&directory).expect("a fast open decodes nothing");
    assert_eq!(recovered.blocks, blocks.len());
    assert_eq!(recovered.discarded_bytes, 0);

    // The replay is where it is caught, and it stops there rather than
    // carrying on with a hole.
    let mut good = 0usize;
    let mut stopped = false;
    for block in log.replay() {
        if block.is_err() {
            stopped = true;
            break;
        }
        good += 1;
    }
    assert!(
        stopped || good < blocks.len(),
        "a corrupted record replayed as if it were whole"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim: a log whose index has to be rebuilt refuses rather than lies.
///
/// It refused, and the refusal was permanent. A single flipped byte inside a
/// record body, with the index gone, made `BlockLog::open` return an error at
/// every start from then on, and the node never came back up without a person
/// deleting a file. An unattended node that does not come back is the thing
/// the lock file was carefully designed to avoid.
///
/// It comes back on the prefix now, says what it found, and does not cut the
/// file: the bytes past the damage stay where they are, so a start that
/// misread them once can read them back and a person can still look. What is
/// held is a prefix of what went in, which is what the node asks for the rest
/// against.
#[test]
fn a_corrupt_record_with_no_index_comes_back_on_the_prefix() {
    let blocks = chain(4);
    let directory = scratch("rebuild-corrupt");
    built(&directory, &blocks);

    let path = directory.join(BLOCK_LOG);
    let whole = std::fs::metadata(&path).unwrap().len();
    let at = whole / 2;
    let before = std::fs::read(&path).unwrap()[at as usize];
    put(&path, at, &[before ^ 0xff]);
    std::fs::remove_file(directory.join(BLOCK_INDEX)).unwrap();

    for attempt in 0..3 {
        let (log, recovered) = BlockLog::open(&directory)
            .unwrap_or_else(|error| panic!("attempt {attempt}: would not start: {error}"));
        let held = log.len();
        assert!(
            held < blocks.len(),
            "attempt {attempt}: nothing was noticed"
        );
        assert_eq!(
            recovered.unreadable,
            Some(held),
            "attempt {attempt}: the damage is named, and not as a torn write"
        );
        assert_eq!(
            recovered.discarded_bytes, 0,
            "attempt {attempt}: nothing was cut, and the count that says bytes \
             were thrown away must not say so while they are still on the disk"
        );
        assert!(
            recovered.left_in_place > 0,
            "attempt {attempt}: what is standing there unread is what says \
             whether this cost one block or a day of them"
        );

        // Every record it does claim is one of the ones that went in.
        let back: Vec<Block> = log.replay().map(Result::unwrap).collect();
        assert_eq!(back.len(), held);
        for (position, block) in back.iter().enumerate() {
            assert_eq!(block.id(), blocks[position].id());
        }
        drop(log);

        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            whole,
            "attempt {attempt}: recovery cut the log"
        );
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim: a length read off the disk is checked before anything is
/// reserved for it.
///
/// It was, on the rebuild path, and the check refused the start for ever. An
/// oversized length prefix in the *last* record is exactly what a torn write
/// leaves: the four bytes that say how long a record is landed and the record
/// did not, so the file ends inside it. That is a torn tail whatever the
/// number says, and it is read as one now. Nothing is reserved either way,
/// which is what the ceiling is for.
#[test]
fn an_oversized_length_prefix_in_the_last_record_is_a_torn_tail() {
    let blocks = chain(3);
    let directory = scratch("huge-length");
    built(&directory, &blocks);

    // Where the last record begins: everything but its own bytes.
    let last = blocks[blocks.len() - 1].encode().len() as u64 + 4;
    let whole = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
    let last_start = whole - last;

    put(
        &directory.join(BLOCK_LOG),
        last_start,
        &u32::MAX.to_le_bytes(),
    );
    std::fs::remove_file(directory.join(BLOCK_INDEX)).unwrap();

    let (log, recovered) = BlockLog::open(&directory)
        .unwrap_or_else(|error| panic!("a log claiming a 4 GiB record would not start: {error}"));
    assert_eq!(log.len(), blocks.len() - 1, "the tail went, and only it");
    assert_eq!(recovered.discarded_bytes, last);
    assert_eq!(
        recovered.unreadable, None,
        "a record the file ends inside is a torn write, not damage"
    );
    assert_eq!(log.read(1).unwrap().unwrap().id(), blocks[1].id());
    drop(log);

    assert_eq!(
        std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len(),
        last_start,
        "bytes a record ends inside can never become one, so they go"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim under test: `MAX_RECORD_BYTES` exists because "a length read from
/// disk is not necessarily a length this process wrote, so it is checked
/// before anything is reserved for it".
///
/// It was checked on the rebuild path and on the replay path, and not on the
/// one a serving node uses. `bounds` took two offsets straight out of the
/// index and `read` reserved the difference, with no ceiling: the offset
/// ending record two set to 64 MiB reserved 64 MiB, and nearer `u64::MAX` that
/// is an allocation failure, which in Rust is a process abort with no message.
/// One flipped byte anywhere but in the last entry got past `recover`, because
/// only the last entry is ever compared with the length of the log.
///
/// Two offsets are two numbers off a disk now, checked before anything acts on
/// them; and the record says how long it is as well, which is the account that
/// wins, because the record is the record.
#[test]
fn the_read_path_reserves_nothing_the_index_alone_asked_for() {
    let blocks = chain(6);
    let directory = scratch("index-flip");
    built(&directory, &blocks);

    // The offset ending record two, made to name a record far larger than any
    // block the rules allow. Not the last entry, so `recover` never looks at
    // it, and the size is chosen by the file rather than by any rule here.
    put(
        &directory.join(BLOCK_INDEX),
        16,
        &(64u64 << 20).to_le_bytes(),
    );

    let (log, recovered) = BlockLog::open(&directory).expect("nothing looks at the middle");
    assert_eq!(recovered.blocks, blocks.len(), "no rebuild was triggered");

    // The record it says runs to 64 MiB, and the one that then appears to
    // start there. Both are pairs of offsets that do not describe a record in
    // this log, and neither reserves anything.
    for index in [2usize, 3] {
        let read = log.read(index);
        assert!(
            matches!(read, Err(StoreError::Misindexed { .. })),
            "record {index} came back as {read:?}"
        );
    }

    // What the flipped byte did not touch still reads, so this refuses the two
    // records the damage covers and not the log.
    assert_eq!(log.read(0).unwrap().unwrap().id(), blocks[0].id());
    assert_eq!(log.read(5).unwrap().unwrap().id(), blocks[5].id());
    let _ = std::fs::remove_dir_all(&directory);
}

/// The same ceiling, against an index that stays inside the log.
///
/// A pair of offsets can be wrong without being absurd, and then the only
/// account left is the record's own four bytes. They have to agree with the
/// index, and a read where they do not is a read that never happens.
#[test]
fn a_record_and_the_index_have_to_agree_about_its_length() {
    let blocks = chain(4);
    let directory = scratch("index-short");
    built(&directory, &blocks);

    // The offset ending record one moved back by sixteen bytes: still inside
    // the log, still in order, and no longer where that record ends.
    let index = directory.join(BLOCK_INDEX);
    let held = std::fs::read(&index).unwrap();
    let was = u64::from_le_bytes(held[8..16].try_into().unwrap());
    put(&index, 8, &(was - 16).to_le_bytes());

    let (log, _) = BlockLog::open(&directory).unwrap();
    assert!(
        matches!(log.read(1), Err(StoreError::Mismatched { index: 1, .. })),
        "the record says one length and the index another"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------
// The header log.
// ---------------------------------------------------------------------------

/// The claim: a trailing part of a record is a write that never finished, and
/// is cut back.
#[test]
fn a_header_log_cut_at_every_length_opens_to_a_prefix() {
    let blocks = chain(5);
    let directory = scratch("header-source");
    {
        let mut headers = HeaderLog::open(&directory).unwrap();
        for block in &blocks {
            headers.append(&block.header).unwrap();
        }
    }
    let whole = std::fs::read(directory.join(HEADER_LOG)).unwrap();
    let _ = std::fs::remove_dir_all(&directory);

    for cut in 0..=whole.len() {
        let directory = scratch("header-sweep");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(HEADER_LOG), &whole[..cut]).unwrap();
        let headers = HeaderLog::open(&directory)
            .unwrap_or_else(|error| panic!("header cut at {cut} refused to open: {error}"));
        assert_eq!(
            headers.len() as usize,
            cut / 182,
            "header cut at {cut} came back the wrong length"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}

/// The claim under test, from `HeaderLog::open_named`: "Nothing is decoded: a
/// header that cannot be read is found when it is read."
///
/// Nothing was ever found, because there is no such header. Every field of a
/// `BlockHeader` is a fixed-width primitive with no validation, so any 182
/// bytes decode and `read` could not return `Malformed` however hard it tried.
/// There is no checksum and a fixed-size record leaves nothing structural to
/// catch a changed byte, so a header log with bytes changed in it was served
/// as truth, at open and at every read, for the life of the node.
///
/// The check that was missing is already in the bytes. A header carries its
/// parent's identifier, so a byte changed anywhere in a record moves the
/// identifier the record after it was written against. That costs one more
/// record read and one hash, and it buys more than a checksum: it says which
/// chain the record belongs to.
#[test]
fn a_header_that_the_record_beside_it_does_not_name_is_refused() {
    let blocks = chain(5);
    let directory = scratch("header-garbage");
    {
        let mut headers = HeaderLog::open(&directory).unwrap();
        for block in &blocks {
            headers.append(&block.header).unwrap();
        }
    }

    // Records two and three, leaving the head alone so the log still says it
    // starts at zero and the damage is purely in what it would serve.
    for (record, pattern) in [(2u64, 0xffu8), (3, 0x5a)] {
        put(&directory.join(HEADER_LOG), record * 182, &[pattern; 182]);
    }
    let headers = HeaderLog::open(&directory).expect("the open is still cheap");
    assert_eq!(headers.len(), 5, "nothing was decided about the file");
    assert_eq!(headers.first_height(), 0);

    // 0xff bytes still decode, and still say their height is u64::MAX. They no
    // longer come back as a header.
    assert!(
        matches!(headers.read_at(2), Err(StoreError::Displaced { .. })),
        "a header at a height that is not its position was served"
    );
    assert!(
        matches!(headers.read_at(3), Err(StoreError::Displaced { .. })),
        "and so was the next one"
    );

    // The record before the damage is sound and is refused all the same: what
    // vouches for it is the record after it, and that is the damaged one. A
    // node that will not answer about one header either side of a bad byte is
    // paying the honest price.
    assert!(
        matches!(headers.read_at(1), Err(StoreError::Unlinked { height: 1 })),
        "a header vouched for by 182 bytes of nothing was served"
    );
    assert!(
        matches!(headers.read_at(4), Err(StoreError::Unlinked { height: 4 })),
        "the tip stood on a record it does not name"
    );

    // And two records away it is unaffected, so this refuses headers rather
    // than the log.
    assert_eq!(
        headers.read_at(0).unwrap().unwrap().id(),
        blocks[0].header.id()
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A record with only one field changed, which is what the link check is for
/// and what the position check cannot see.
///
/// Nothing about a header's own bytes says a state root is wrong. What says so
/// is the record after it, which committed to the identifier those bytes had.
#[test]
fn a_changed_field_no_position_could_notice_is_caught_by_the_record_after_it() {
    let blocks = chain(4);
    let directory = scratch("header-field");
    {
        let mut headers = HeaderLog::open(&directory).unwrap();
        for block in &blocks {
            headers.append(&block.header).unwrap();
        }
    }

    // One byte of the nonce of the record at height one. Its height, its
    // version and its network are all untouched, and it is still 182 bytes.
    let nonce = 182 + 182 - 8;
    let before = std::fs::read(directory.join(HEADER_LOG)).unwrap()[nonce];
    put(&directory.join(HEADER_LOG), nonce as u64, &[before ^ 0x01]);

    let headers = HeaderLog::open(&directory).unwrap();
    assert!(
        matches!(headers.read_at(1), Err(StoreError::Unlinked { height: 1 })),
        "a header with a changed byte was served as truth"
    );
    assert_eq!(
        headers.read_at(0).unwrap().unwrap().id(),
        blocks[0].header.id(),
        "and the records around it are unaffected"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The one thing the open does read: the first record, to learn where the log
/// starts.
///
/// Every position here is a height worked out from that one number, so eight
/// bytes changed in it used to move the whole log. A node claimed to begin at
/// height nine million and denied holding the header at zero that it held, and
/// nothing anywhere objected.
///
/// The record after it has to name it now. Nothing can say which of the two is
/// the wrong one, so the log reports holding nothing rather than a geography
/// it invented, and it leaves the file exactly as it found it: the node comes
/// back up and fills its headers in from the blocks it still has.
#[test]
fn a_corrupted_first_record_no_longer_moves_the_header_log() {
    let blocks = chain(3);
    let directory = scratch("header-first");
    {
        let mut headers = HeaderLog::open(&directory).unwrap();
        for block in &blocks {
            headers.append(&block.header).unwrap();
        }
    }
    let path = directory.join(HEADER_LOG);
    let whole = std::fs::metadata(&path).unwrap().len();

    // The height field of the first record, set to something far away. Bytes
    // 6..14: version is two bytes, the network four, then the height.
    put(&path, 6, &9_000_000u64.to_le_bytes());
    let headers = HeaderLog::open(&directory).expect("it still starts");
    assert_eq!(headers.first_height(), 0, "and claims no ground at all");
    assert_eq!(headers.reaches(), 0);
    assert!(headers.is_empty());
    assert!(
        !headers.holds(9_000_000),
        "the node no longer says it holds a stretch of chain it never saw"
    );
    drop(headers);

    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        whole,
        "and nothing was deleted over one bad record"
    );

    // What a node does next: fill the log in again from the blocks it still
    // has. The records the damaged log held go then, and not before, so the
    // next start does not count them as headers this log holds.
    let mut headers = HeaderLog::open(&directory).unwrap();
    headers.append(&blocks[2].header).unwrap();
    drop(headers);
    let headers = HeaderLog::open(&directory).unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers.first_height(), 2);
    assert_eq!(
        headers.read_at(2).unwrap().unwrap().id(),
        blocks[2].header.id()
    );
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------
// The header forest.
// ---------------------------------------------------------------------------

/// The claim under test: a level that disagrees with the leaves is put back
/// into line rather than believed.
///
/// Agreement was measured in length alone, so a level of the right length
/// holding the wrong bytes was never looked at. Zeroing one node at level one
/// gave a forest that opened with the right leaf count and served a proof with
/// a zero where a hash belongs: it folded to a root nobody else had, nothing
/// reported it, and a restart did not clear it. This is the same damage the
/// torn-append repair was written for, in the one direction that repair's own
/// doc comment does not cover.
///
/// A proof is folded as it is built now, and every fold compared with the node
/// the forest holds in that place. The open is as cheap as it was: nothing is
/// rehashed until somebody asks for a path.
#[test]
fn a_forest_node_changed_in_place_is_caught_by_the_fold() {
    let directory = scratch("forest-flip");
    {
        let mut forest = HeaderTree::open(&directory).unwrap();
        for n in 0..16u64 {
            forest
                .append(cairn_primitives::Hash32::from_bytes([(n as u8) + 1; 32]))
                .unwrap();
        }
    }
    let level_one = directory.join(format!("{}.1", cairn_store::HEADER_TREE));
    // The node at level one covering leaves two and three, which is the
    // sibling every proof for leaf zero folds through.
    put(&level_one, 32, &[0u8; 32]);

    let forest = HeaderTree::open(&directory).expect("the open still costs nothing");
    assert_eq!(forest.len(), 16, "and still says nothing");
    assert!(
        matches!(
            forest.prove_in(0, 16),
            Err(StoreError::Unfolded { height: 2, .. })
        ),
        "a zeroed node was served as if it were a hash"
    );

    // The leaves are untouched and so is every path that does not run through
    // the changed node, so this refuses paths rather than the forest.
    assert!(forest.prove_in(0, 2).unwrap().is_some());
    assert!(forest.prove_in(8, 16).unwrap().is_some());
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------
// No room at all.
// ---------------------------------------------------------------------------

/// Fills the filesystem `directory` sits on, so a write that follows has
/// nowhere to go, and returns what to remove to give the room back.
///
/// Written in closed, synced pieces of shrinking size. A write that only
/// reaches the page cache comes back successful on a filesystem with delayed
/// allocation, and space a filesystem set aside for an open file can come back
/// when that file is closed — so neither one write nor one handle is enough to
/// say the disk is full.
fn eat_the_room(directory: &Path) -> PathBuf {
    let room = directory.join("ballast");
    std::fs::create_dir_all(&room).unwrap();
    let mut piece = 0usize;
    for size in [4 * 1024 * 1024usize, 256 * 1024, 16 * 1024, 1024, 64] {
        let chunk = vec![0u8; size];
        loop {
            piece += 1;
            assert!(
                piece < 100_000,
                "the filesystem never ran out; make it smaller"
            );
            let path = room.join(format!("{piece}"));
            let Ok(mut file) = std::fs::File::create(&path) else {
                break;
            };
            if file.write_all(&chunk).is_err() || file.sync_all().is_err() {
                drop(file);
                let _ = std::fs::remove_file(&path);
                break;
            }
        }
    }
    room
}

/// The claim: an append returns once the record and the offset naming it are
/// on the disk, and a body let go of before it was written is a body nobody
/// has.
///
/// Run against a directory on a small filesystem, named by
/// `CAIRN_AUDIT_FULL_DIR`; the test fills what is left of it itself. Skips
/// otherwise, because a filesystem that is genuinely full is not something a
/// portable test can make.
#[test]
fn an_append_with_no_room_leaves_the_log_where_it_was() {
    let Ok(root) = std::env::var("CAIRN_AUDIT_FULL_DIR") else {
        eprintln!("skipped: set CAIRN_AUDIT_FULL_DIR to a directory on a small filesystem");
        return;
    };
    let root = PathBuf::from(root);
    let directory = root.join("blocklog");
    let _ = std::fs::remove_dir_all(&directory);
    let blocks = chain(40);

    let (mut log, _) = BlockLog::open(&directory).unwrap();
    // A few blocks before the room goes, so there is a log to compare against.
    for block in &blocks[..4] {
        log.append(block).unwrap();
    }
    let ballast = eat_the_room(&root);

    let mut written = 4usize;
    let mut failed = None;
    for block in &blocks[4..] {
        match log.append(block) {
            Ok(()) => written += 1,
            Err(error) => {
                failed = Some(error);
                break;
            }
        }
    }
    let failed = failed.expect("the filesystem had room after being filled");
    eprintln!("wrote {written} of 40 blocks, then: {failed}");

    // What the log says in memory is what `release_bodies` is handed, so it
    // must not be ahead of the disk.
    assert_eq!(log.len(), written);
    let reaches = log.reaches();
    let bytes = log.bytes();
    drop(log);

    let held = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
    let indexed = std::fs::metadata(directory.join(BLOCK_INDEX))
        .unwrap()
        .len();
    eprintln!("on disk: {held} bytes of log, {indexed} of index, memory says {bytes}");

    // The room back, so the reopen is not itself starved.
    std::fs::remove_dir_all(&ballast).unwrap();

    let (log, recovered) = BlockLog::open(&directory)
        .unwrap_or_else(|error| panic!("a log left by a full disk would not reopen: {error}"));
    assert_eq!(
        log.len(),
        written,
        "the disk and the memory disagreed after a write that ran out"
    );
    assert_eq!(log.reaches(), reaches);
    eprintln!(
        "reopened with {} blocks, {} bytes dropped",
        log.len(),
        recovered.discarded_bytes
    );
    let back: Vec<Block> = log.replay().map(Result::unwrap).collect();
    assert_eq!(back.len(), written);
    for (position, block) in back.iter().enumerate() {
        assert_eq!(block.id(), blocks[position].id());
    }
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
}

/// The same for the header log, which is what a node shows a newcomer.
///
/// The difference from the block log is that there is no index to cut against,
/// so the file itself is where a torn record has to be noticed.
#[test]
fn a_header_append_with_no_room_leaves_no_half_record_behind() {
    let Ok(root) = std::env::var("CAIRN_AUDIT_FULL_DIR") else {
        eprintln!("skipped: set CAIRN_AUDIT_FULL_DIR to a directory on a small filesystem");
        return;
    };
    let root = PathBuf::from(root);
    let directory = root.join("headerlog");
    let _ = std::fs::remove_dir_all(&directory);
    let blocks = chain(40);

    let mut headers = HeaderLog::open(&directory).unwrap();
    for block in &blocks[..4] {
        headers.append(&block.header).unwrap();
    }
    let ballast = eat_the_room(&root);

    let mut written = 4u64;
    let mut failed = None;
    for block in &blocks[4..] {
        match headers.append(&block.header) {
            Ok(()) => written += 1,
            Err(error) => {
                failed = Some(error);
                break;
            }
        }
    }
    let failed = failed.expect("the filesystem had room after being filled");
    eprintln!("wrote {written} of 40 headers, then: {failed}");
    assert_eq!(headers.len(), written);
    drop(headers);

    let held = std::fs::metadata(directory.join(HEADER_LOG)).unwrap().len();
    std::fs::remove_dir_all(&ballast).unwrap();

    let headers = HeaderLog::open(&directory).expect("a torn header log reopens");
    eprintln!(
        "the file held {held} bytes ({} whole records, {} spare); reopened with {}",
        held / 182,
        held % 182,
        headers.len()
    );
    assert_eq!(
        headers.len(),
        written,
        "a header the log never finished writing came back as one it holds"
    );
    for height in headers.first_height()..headers.reaches() {
        assert!(headers.read_at(height).unwrap().is_some());
    }
    drop(headers);
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim under test: a node that cannot write says so rather than carrying
/// on quietly.
///
/// A disk with nothing left at all is the case where it says so loudest: the
/// store cannot be opened, so the node refuses to start. Recorded here for what
/// it means to an operator, not because it is wrong.
#[test]
fn a_store_cannot_be_opened_at_all_on_a_full_disk() {
    let Ok(root) = std::env::var("CAIRN_AUDIT_FULL_DIR") else {
        eprintln!("skipped: set CAIRN_AUDIT_FULL_DIR to a directory on a small filesystem");
        return;
    };
    let root = PathBuf::from(root);
    let ballast = eat_the_room(&root);
    let directory = root.join("cold-start");

    eprintln!(
        "block log:  {:?}",
        BlockLog::open(&directory).map(|(l, _)| l.len())
    );
    eprintln!(
        "header log: {:?}",
        HeaderLog::open(&directory).map(|l| l.len())
    );
    eprintln!(
        "forest:     {:?}",
        HeaderTree::open(&directory).map(|f| f.len())
    );
    eprintln!(
        "lock:       {:?}",
        cairn_store::DirectoryLock::acquire(&directory).map(|_| "acquired")
    );

    std::fs::remove_dir_all(&ballast).unwrap();
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------
// Making room.
// ---------------------------------------------------------------------------

/// The claim under test, from `keep_from`: "The records that stay are moved to
/// the front of the file and the index is written again, which is one pass over
/// what is kept rather than over what is dropped."
///
/// One pass, through memory and through a second copy of the file. The kept
/// records are read into one `Vec` and written to a file beside the log before
/// the log is replaced, so making room needs as much room again as the part of
/// the log that is being kept — which by default is a gigabyte.
///
/// This is the path a node takes *because* its disk is filling up.
#[test]
fn making_room_needs_as_much_room_again_as_it_keeps() {
    let Ok(root) = std::env::var("CAIRN_AUDIT_FULL_DIR") else {
        eprintln!("skipped: set CAIRN_AUDIT_FULL_DIR to a directory on a small filesystem");
        return;
    };
    let root = PathBuf::from(root);
    let directory = root.join("compaction");
    let _ = std::fs::remove_dir_all(&directory);
    let blocks = chain(60);

    let (mut log, _) = BlockLog::open(&directory).unwrap();
    for block in &blocks {
        log.append(block).unwrap();
    }
    let held = log.bytes();
    let before: Vec<_> = log.replay().map(|b| b.unwrap().id()).collect();

    // Everything else on the disk, so there is room for the log and not for a
    // second copy of it.
    let ballast = eat_the_room(&root);

    let outcome = log.keep_from(30);
    eprintln!("keeping the top half of a {held} byte log with no room: {outcome:?}");
    assert!(
        outcome.is_err(),
        "the compaction found room; make the filesystem smaller"
    );

    // What matters is that the failure left the log alone rather than half
    // moved: it is still every block, still readable, still at its old height.
    assert_eq!(log.len(), blocks.len());
    assert_eq!(log.first_height(), 0);
    let after: Vec<_> = log.replay().map(|b| b.unwrap().id()).collect();
    assert_eq!(before, after, "a failed compaction changed the log");
    drop(log);

    std::fs::remove_dir_all(&ballast).unwrap();
    let (log, recovered) = BlockLog::open(&directory).expect("and it reopens");
    assert_eq!(log.len(), blocks.len());
    assert_eq!(recovered.discarded_bytes, 0);
    let back: Vec<_> = log.replay().map(|b| b.unwrap().id()).collect();
    assert_eq!(before, back);
    // The staged copy left behind is cleared by the open, so nothing
    // accumulates.
    assert!(!directory.join(format!("{BLOCK_LOG}.part")).exists());
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
}

/// The same claim, on a disk with room: the compaction holds everything it
/// keeps in one allocation, whose size is the operator's budget and not
/// anything this crate bounds.
///
/// Nothing is broken here — it is written down because a phone is the stated
/// target and `cairn_net::KEEP_BLOCK_BYTES` is a gigabyte.
#[test]
fn making_room_holds_everything_it_keeps_in_one_allocation() {
    let directory = scratch("compaction-memory");
    let blocks = chain(40);
    let (mut log, _) = BlockLog::open(&directory).unwrap();
    for block in &blocks {
        log.append(block).unwrap();
    }
    let kept_from = 10u64;
    let dropped_bytes = {
        let mut total = 0u64;
        for block in &blocks[..kept_from as usize] {
            total += block.encode().len() as u64 + 4;
        }
        total
    };
    let whole = log.bytes();
    log.keep_from(kept_from).unwrap();
    eprintln!(
        "a {whole} byte log keeping {} of it read {} bytes into memory at once",
        whole - dropped_bytes,
        whole - dropped_bytes
    );
    assert_eq!(log.len(), blocks.len() - kept_from as usize);
    assert_eq!(log.first_height(), kept_from);
    let back: Vec<_> = log.replay().map(|b| b.unwrap().id()).collect();
    for (position, id) in back.iter().enumerate() {
        assert_eq!(*id, blocks[position + kept_from as usize].id());
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim: a compaction that cannot finish leaves a log that can account
/// for itself, rather than one describing files it no longer holds.
///
/// `keep_from` lets go of both handles before it renames anything, because
/// Windows will not rename over an open file. Between letting go and getting
/// them back there are four things that can fail, and every one of them used
/// to leave with `?`: the handles stayed on the scratch file, and `count`,
/// `first` and `end` went on describing the log that was no longer there.
///
/// What that cost is not a bad read. A node reads its log rarely and appends
/// to it every block, and the appends went on succeeding: into a scratch file
/// the next start deletes. The node saw no gap between its chain and its disk,
/// because the writes returned success, so the one watch that would have
/// stopped it never fired.
///
/// The failure is injected at the reopen, which is the last of the four and
/// the only one that can be made to fail without a filesystem to break: the
/// staged log is put there first with no read permission, `fs::write` keeps
/// the mode of a file already present, and the rename carries it into place.
#[cfg(unix)]
#[test]
fn a_compaction_that_cannot_finish_leaves_a_log_that_says_so() {
    use std::os::unix::fs::PermissionsExt;

    let directory = scratch("compaction-interrupted");
    let blocks = chain(20);
    let (mut log, _) = BlockLog::open(&directory).unwrap();
    for block in &blocks {
        log.append(block).unwrap();
    }
    assert_eq!(log.len(), blocks.len());

    let staged = directory.join(format!("{BLOCK_LOG}.part"));
    std::fs::write(&staged, b"").unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o200)).unwrap();

    let refused = log.keep_from(10);
    assert!(refused.is_err(), "the reopen has to fail: {refused:?}");

    // What it says about itself is now true of what it can reach.
    assert_eq!(
        log.len(),
        0,
        "it claimed {} records it cannot read",
        log.len()
    );
    assert!(!log.holds(15));
    assert!(matches!(log.read_at(15), Ok(None)));
    assert_eq!(log.replay().count(), 0);

    // And the one call a node makes every block is refused rather than
    // answered by a write that reaches nobody.
    let next = &blocks[19];
    assert!(
        log.append(next).is_err(),
        "an append onto a log that lost its files was taken and reported \
         written, and the block went into a scratch file the next start deletes"
    );
    assert_eq!(log.len(), 0, "and it did not count one either");

    // The blocks themselves are on the disk, where the compaction put them, so
    // a start that can open the file finds the compacted log waiting.
    drop(log);
    std::fs::set_permissions(
        directory.join(BLOCK_LOG),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let (log, _) = BlockLog::open(&directory).expect("and it opens again");
    assert_eq!(log.len(), blocks.len() - 10);
    assert_eq!(log.first_height(), 10);
    let back: Vec<_> = log.replay().map(|block| block.unwrap().id()).collect();
    for (position, id) in back.iter().enumerate() {
        assert_eq!(*id, blocks[position + 10].id());
    }
    drop(log);
    let _ = std::fs::remove_dir_all(&directory);
}

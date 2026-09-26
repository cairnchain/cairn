//! What a start does with the disk it is given, when what is on it is not
//! what this build or this command line expects.
//!
//! A start reads back the block log and the ledger beside it, and there are
//! two kinds of reason to refuse what it finds. One is about the record: a
//! block that does not extend the branch, a body that no longer applies, a
//! file that will not decode. The other is about the reader: a build without
//! the rules for a height, or a node started for another network on the same
//! directory. The first can be mended by what the network sends back. The
//! second cannot, because the same build refuses the same blocks from the
//! network, so the only thing a start can do about it is stop, change nothing,
//! and say which of the two it is.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, Block, BLOCK_VERSION};
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::{Node, NodeError, Restored};
use cairn_store::{
    BlockLog, DirectoryLock, HeaderLog, HeaderTree, BLOCK_INDEX, BLOCK_LOG, HANDED_LEDGER,
    HEADER_LOG,
};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The height the rules move to the next version at, in the schedule a build
/// one release behind carries.
const CHANGE: u64 = 5;

/// That schedule: the opening version, then the next one from `CHANGE`, which
/// this build has no rules for.
const ANNOUNCED: &[Activation] = &[
    Activation {
        height: 0,
        version: BLOCK_VERSION,
    },
    Activation {
        height: CHANGE,
        version: BLOCK_VERSION + 1,
    },
];

/// Rules written for a version this build does not have, from the first block.
const AHEAD: &[Activation] = &[Activation {
    height: 0,
    version: BLOCK_VERSION + 1,
}];

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-start-disk-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn chain(rules: &ConsensusParams, count: usize) -> Vec<Block> {
    let miner = SecretKey::from_bytes(&[4; 32]);
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(rules.initial_reward, miner.public_key())],
            );
            let block =
                assemble_block(&state, coinbase, Vec::<Transfer>::new(), rules, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
            connect_block(&mut state, &block, rules, NOW).unwrap();
            block
        })
        .collect()
}

/// Eight blocks: five under the opening rules, then three carrying the next
/// version, chained on one another with real work behind each. What a newer
/// build would have validated and written.
fn a_log_written_by_a_newer_build() -> Vec<Block> {
    let miner = SecretKey::from_bytes(&[7; 32]);
    let rules = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut written: Vec<Block> = Vec::new();
    for height in 0..(CHANGE + 3) {
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(rules.initial_reward, miner.public_key())],
        );
        let assembled = assemble_block(&state, coinbase, Vec::new(), &rules, clock, 0).unwrap();
        let block = if height < CHANGE {
            let block = mine_block(assembled, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &rules, NOW).unwrap();
            block
        } else {
            // The state moves on with the old version's twin, so the next
            // header has a height and a parent to build on.
            let twin = mine_block(assembled.clone(), ATTEMPTS).unwrap();
            connect_block(&mut state, &twin, &rules, NOW).unwrap();
            let mut next = assembled;
            next.header.version = BLOCK_VERSION + 1;
            next.header.previous = written.last().unwrap().id();
            mine_block(next, ATTEMPTS).unwrap()
        };
        written.push(block);
    }
    written
}

fn write_log(directory: &Path, blocks: &[Block]) {
    let (mut log, _) = BlockLog::open(directory).unwrap();
    for block in blocks {
        log.append(block).unwrap();
    }
}

fn records_in(directory: &Path) -> usize {
    let (log, _) = BlockLog::open(directory).unwrap();
    log.len()
}

fn bytes_of(directory: &Path, name: &str) -> Vec<u8> {
    std::fs::read(directory.join(name)).unwrap_or_default()
}

/// What a start that should have stopped said, or the fact that it started.
fn refusal(opened: Result<(Node, Restored), NodeError>) -> String {
    match opened {
        Err(error) => error.to_string(),
        Ok((node, restored)) => {
            node.shutdown();
            drop(node);
            panic!(
                "the node started, having replayed {} blocks and cut {}",
                restored.blocks, restored.refused
            );
        }
    }
}

/// A node that has run, written its own ledger down, and stopped.
fn a_node_that_wrote_its_ledger(name: &str) -> PathBuf {
    let directory = scratch(name);
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    for block in &chain(&params(), 40) {
        node.submit_block(block.clone()).unwrap();
    }
    assert!(node.write_ledger(), "the node wrote its ledger down");
    node.shutdown();
    drop(node);
    assert!(directory.join(HANDED_LEDGER).exists());
    directory
}

/// A build one release behind, started on a log a newer build wrote past an
/// activation, stops and cuts nothing.
///
/// Nothing asked this, so a rollback to the previous binary passed while the
/// replay counted every block from the activation height as refused and cut
/// it off the disk: three valid blocks of eight gone, and the operator told
/// "neither loses anything but time". For an archivist those are the archive.
#[test]
fn a_log_past_the_rules_this_build_has_stops_the_start_and_keeps_every_block() {
    let directory = scratch("newer-build");
    write_log(&directory, &a_log_written_by_a_newer_build());
    let before = bytes_of(&directory, BLOCK_LOG);
    let one_release_behind = ConsensusParams {
        activations: ANNOUNCED,
        ..params()
    };

    let said = refusal(Node::open(one_release_behind, loopback(), &directory));

    assert!(
        bytes_of(&directory, BLOCK_LOG) == before,
        "a start by a build without the rules for a height changed the block log"
    );
    assert_eq!(
        records_in(&directory),
        8,
        "and the log still holds every record"
    );
    assert!(
        said.contains(&format!("height {CHANGE}")) && said.contains("build"),
        "the refusal does not name the height or say that a build is the cure: {said}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A node started once under the wrong network name, on a directory another
/// network's node wrote, stops and cuts nothing.
///
/// Nothing asked this, so the replay refused the first record, counted all
/// eight as refused, cut the log to nothing and wrote the other network's
/// first block in its place: one mistyped `--network` on the default
/// directory, and the chain it held was gone.
#[test]
fn a_log_of_another_network_stops_the_start_and_keeps_every_block() {
    let directory = scratch("other-network");
    write_log(&directory, &chain(&params(), 8));
    let before = bytes_of(&directory, BLOCK_LOG);
    let mistaken = ConsensusParams {
        network: NetworkId::new(0x00ab_cdef),
        ..params()
    };

    let said = refusal(Node::open(mistaken, loopback(), &directory));

    assert!(
        bytes_of(&directory, BLOCK_LOG) == before,
        "a start under another network's name changed the block log"
    );
    assert!(
        said.contains(&params().network.to_string()),
        "the refusal does not name the network the directory belongs to: {said}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A ledger this build is too old for is answered with a build, not with the
/// remedy for a damaged file.
///
/// Nothing asked this, so every refusal of `ledger.dat` said to put a copy
/// back or delete it, "which costs the stored blocks", to an operator whose
/// copy would be refused the same way and whose deletion cures nothing.
#[test]
fn a_ledger_this_build_is_too_old_for_is_answered_with_a_build() {
    let directory = a_node_that_wrote_its_ledger("ledger-too-old");
    let held = records_in(&directory);
    let behind = ConsensusParams {
        activations: AHEAD,
        ..params()
    };

    let said = refusal(Node::open(behind, loopback(), &directory));

    assert!(
        !said.contains("delete it"),
        "a ledger refused because this build is too old is told to delete it: {said}"
    );
    assert!(
        said.contains("build"),
        "and it is not told that a build is the cure: {said}"
    );
    assert_eq!(records_in(&directory), held, "and the blocks are all there");
    let _ = std::fs::remove_dir_all(&directory);
}

/// A ledger of another network is answered with the network, not with the
/// remedy for a damaged file.
///
/// Nothing asked this, so a directory opened under a mistaken `--network` was
/// told to delete its ledger, which costs the blocks of the network it
/// belongs to.
#[test]
fn a_ledger_of_another_network_is_answered_with_the_network() {
    let directory = a_node_that_wrote_its_ledger("ledger-network");
    let held = records_in(&directory);
    let other = ConsensusParams {
        network: NetworkId::new(0x00ab_cdef),
        ..params()
    };

    let said = refusal(Node::open(other, loopback(), &directory));

    assert!(
        !said.contains("delete it"),
        "a ledger of another network is told to delete it: {said}"
    );
    assert!(
        said.contains(&params().network.to_string()),
        "and it is not told which network the directory belongs to: {said}"
    );
    assert_eq!(records_in(&directory), held, "and the blocks are all there");
    let _ = std::fs::remove_dir_all(&directory);
}

/// A header log that will not open is named, and is not called the block log.
///
/// Nothing asked this, so every file of the store was the block log: the
/// header log, the forest, the lock, and the operator was sent to a file that
/// was fine.
#[test]
fn a_header_log_that_will_not_open_is_named_and_not_called_the_block_log() {
    let directory = scratch("headers");
    std::fs::create_dir_all(directory.join(HEADER_LOG)).unwrap();

    let said = refusal(Node::open(params(), loopback(), &directory));

    assert!(
        !said.contains("block log"),
        "a header log that would not open was reported as the block log: {said}"
    );
    assert!(
        said.contains(HEADER_LOG),
        "and the file that would not open is not named: {said}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A directory another node holds is said as a held directory.
///
/// Nothing asked this, so it was "could not reach the block log", and an
/// operator went looking at a file nothing was wrong with.
#[test]
fn a_directory_another_node_holds_is_not_called_an_unreachable_block_log() {
    let directory = scratch("locked");
    let held = DirectoryLock::acquire(&directory).unwrap();

    let said = refusal(Node::open(params(), loopback(), &directory));

    drop(held);
    assert!(
        !said.contains("block log"),
        "a lock another process holds was reported as the block log: {said}"
    );
    assert!(
        said.contains("already in use"),
        "and the lock is not named: {said}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A record in the middle of the log that will not decode is left on the
/// disk, the way the store's own recovery leaves it, and is not cut.
///
/// Nothing asked this, so the same byte met two policies depending on whether
/// the index beside the log happened to be in line. Met by the store's walk,
/// the bytes were left in place and reported as unreadable; met by the
/// replay, everything from that record on was cut, and reported as blocks
/// "set aside". On an archivist those are the copy nobody else has.
#[test]
fn a_record_that_will_not_decode_is_left_on_the_disk_and_not_cut() {
    let directory = scratch("undecodable");
    let (node, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    for block in &chain(&params(), 12) {
        node.submit_block(block.clone()).unwrap();
    }
    node.shutdown();
    drop(node);
    assert_eq!(
        records_in(&directory),
        12,
        "twelve records before the damage"
    );

    // The length prefix of the seventh record, made longer than any record
    // can be. The index is untouched and in line, so the start reads sixteen
    // bytes of it and meets the damage in the replay.
    let index = bytes_of(&directory, BLOCK_INDEX);
    let seventh = usize::try_from(u64::from_le_bytes(index[40..48].try_into().unwrap())).unwrap();
    let mut log = bytes_of(&directory, BLOCK_LOG);
    log[seventh..seventh + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(directory.join(BLOCK_LOG), &log).unwrap();

    let (node, restored) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    node.shutdown();
    drop(node);

    assert!(
        bytes_of(&directory, BLOCK_LOG) == log,
        "a record the replay could not decode had the log cut under it"
    );
    assert_eq!(
        (restored.blocks, restored.refused, restored.unreadable),
        (6, 0, Some(6)),
        "the start does not report the seventh record as unreadable and the six before it \
         as replayed, with nothing cut"
    );
    assert!(
        restored.left_in_place > 0,
        "and it does not say how much is left on the disk unread"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A build without the next version in its schedule at all, started on a log
/// a newer build wrote past the activation, stops the same way and cuts
/// nothing.
///
/// The other face of a rollback: this build does not know the rules change,
/// so the blocks past it carry a version above anything it has rather than
/// the version its schedule names. Nothing asked it, so it was counted
/// refused and cut like a record that changed.
#[test]
fn a_log_past_a_version_this_build_has_never_heard_of_stops_the_start() {
    let directory = scratch("unheard-of");
    write_log(&directory, &a_log_written_by_a_newer_build());
    let before = bytes_of(&directory, BLOCK_LOG);

    let said = refusal(Node::open(params(), loopback(), &directory));

    assert!(
        bytes_of(&directory, BLOCK_LOG) == before,
        "a start by a build without the next version changed the block log"
    );
    assert!(
        said.contains(&format!("height {CHANGE}")) && said.contains("build"),
        "the refusal does not name the height or say that a build is the cure: {said}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A ledger dated before the network this node was started for opened is
/// another network's ledger, not a damaged file.
///
/// Nothing asked this, so it was told to delete the file: a directory kept
/// from an earlier run of a network under the same name.
#[test]
fn a_ledger_from_before_this_network_opened_is_answered_with_the_network() {
    let directory = a_node_that_wrote_its_ledger("ledger-before");
    let later = ConsensusParams {
        opens_at: NOW,
        ..params()
    };

    let said = refusal(Node::open(later, loopback(), &directory));

    assert!(
        !said.contains("delete it") && said.contains("another network"),
        "a ledger from before this network opened is not told it holds another network's \
         chain: {said}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A record further up the log that names another network is a record that
/// changed, and is cut like one: the start goes on from the blocks before it.
///
/// Only the first record decides whether a directory is another network's.
/// Nothing held that, so a start that stopped on any such record would have
/// passed, and a node would refuse to start over one changed byte.
#[test]
fn a_record_of_another_network_further_up_the_log_is_cut_and_the_start_goes_on() {
    let directory = scratch("changed-network");
    let mut blocks = chain(&params(), 8);
    let mut changed = blocks[5].clone();
    changed.header.network = NetworkId::new(0x00ab_cdef);
    blocks[5] = mine_block(changed, ATTEMPTS).unwrap();
    write_log(&directory, &blocks);

    let (node, restored) = Node::open(params(), loopback(), &directory)
        .unwrap_or_else(|error| panic!("a record that changed stopped the start: {error}"));
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        (restored.blocks, restored.refused),
        (5, 3),
        "the start did not go on from the five blocks before the changed record"
    );
}

/// A `ledger.dat` that is there and will not be read stops the start, and
/// is not taken for a node that never wrote one.
///
/// Absence is the one failure that means no ledger. Nothing held the line
/// between the two, so a start that read every failure to open the file as
/// absence passed, and that is the reading that once replayed from block
/// zero over a log beginning higher up and cut it to nothing.
#[test]
fn a_ledger_file_that_will_not_be_read_stops_the_start() {
    let directory = scratch("unreadable-ledger");
    std::fs::create_dir_all(directory.join(HANDED_LEDGER)).unwrap();

    let said = refusal(Node::open(params(), loopback(), &directory));
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        said.contains("could not be read"),
        "a ledger file that would not be read was not said to be unreadable: {said}"
    );
}

/// A header log that reaches past the block log is left as it is: the two
/// agree where both hold, and a header written ahead of its block is what a
/// stop between the two writes of an ordinary block leaves.
///
/// The mend above cuts where the two logs disagree and nowhere else. Nothing
/// held the other side of that, so a start that cut every header past the
/// last block passed, reporting headers replaced that were never on another
/// branch.
#[test]
fn a_header_written_ahead_of_its_block_is_not_cut() {
    let directory = scratch("ahead");
    let blocks = chain(&params(), 13);
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    for block in &blocks[..12] {
        node.submit_block(block.clone()).unwrap();
    }
    node.shutdown();
    drop(node);
    {
        let mut headers = HeaderLog::open(&directory).unwrap();
        headers.append(&blocks[12].header).unwrap();
    }

    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    node.shutdown();
    drop(node);
    let reaches = HeaderLog::open(&directory).unwrap().reaches();
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        (restored.headers_replaced, reaches),
        (0, 13),
        "a header written ahead of its block was cut as another branch's"
    );
}

/// Waits for something a node's upkeep does, for as long as a loaded machine
/// could need and no longer.
fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_secs(120) {
        if ready() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("waited two minutes for {what}");
}

/// A start keeps the blocks the running node kept under its budget.
///
/// Nothing asked this, so every restart cut the log one past the ledger's
/// anchor, which is the rule the budget replaced: a node that kept the blocks
/// from 12 up under its budget came back holding them from 22, and stayed
/// short until the chain had grown by a budget's worth again, handing whole
/// ledgers to peers a little behind in the meantime.
#[test]
fn a_start_keeps_the_blocks_the_budget_kept() {
    let directory = scratch("budget");
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    for block in &chain(&params(), 30) {
        node.submit_block(block.clone()).unwrap();
    }
    let budget = node.kept_bytes() / 30 * 10;
    node.keep_blocks(budget);
    wait_for("the running node to trim to its budget", || {
        node.blocks_from().unwrap_or(0) > 0
    });
    let kept = node.blocks_from();
    node.shutdown();
    drop(node);

    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    let after = node.blocks_from();
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        after, kept,
        "the start cut the blocks the running node had kept under its budget"
    );
}

/// A branch off `main` at `fork`, mined by another key so every header on it
/// differs from the one it stands beside.
fn side_branch(main: &[Block], fork: usize, count: usize) -> Vec<Block> {
    let rules = params();
    let miner = SecretKey::from_bytes(&[7; 32]);
    let mut state = LedgerState::new();
    for block in &main[..fork] {
        connect_block(&mut state, block, &rules, NOW).unwrap();
    }
    let mut clock = 1_000u64 + 600 * u64::try_from(fork).unwrap() + 300;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(rules.initial_reward, miner.public_key())],
            );
            let block =
                assemble_block(&state, coinbase, Vec::<Transfer>::new(), &rules, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
            connect_block(&mut state, &block, &rules, NOW).unwrap();
            block
        })
        .collect()
}

/// A start after a stop between the header write and the block write of a
/// reorganisation leaves a header log that agrees with the chain at every
/// height, and says what it cut.
///
/// Nothing asked this, so the start filled the header log in from the blocks
/// after whatever it held, which was the abandoned branch from the fork: a
/// log of the old branch, then the new one, then the old one again. Nothing
/// afterwards visited the seam, the forest stopped at it for good, the node
/// stopped showing newcomers the chain and stopped keeping its budget, and at
/// every block it reported a header the store would not vouch for, in the
/// words for a disk that changed a byte.
#[test]
fn a_stop_in_the_middle_of_a_reorganisation_leaves_no_seam_in_the_headers() {
    const FORK: usize = 5;
    const SIDE: usize = 3;
    const HELD: usize = 12;
    let main = chain(&params(), HELD + 1);
    let side = side_branch(&main, FORK, SIDE);
    assert_eq!(side[0].header.previous, main[FORK - 1].id());

    let directory = scratch("seam");
    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    for block in &main[..HELD] {
        node.submit_block(block.clone()).unwrap();
    }
    node.shutdown();
    drop(node);

    // What a stop leaves after `write_headers` and `grow_forest` have run for
    // a reorganisation to the side branch and before `write_blocks` has: the
    // header log cut at the fork and holding the side branch, the forest cut
    // at the fork, the block log untouched.
    {
        let mut headers = HeaderLog::open(&directory).unwrap();
        headers.keep_below(u64::try_from(FORK).unwrap()).unwrap();
        for block in &side {
            headers.append(&block.header).unwrap();
        }
        let mut forest = HeaderTree::open(&directory).unwrap();
        forest.keep_first(u64::try_from(FORK).unwrap()).unwrap();
    }

    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    node.submit_block(main[HELD].clone()).unwrap();
    let unwritten = node.unwritten().is_some();
    node.shutdown();
    drop(node);

    let headers = HeaderLog::open(&directory).unwrap();
    let disagree = (0..=HELD)
        .filter(|height| {
            headers
                .read_at(u64::try_from(*height).unwrap())
                .ok()
                .flatten()
                != Some(main[*height].header)
        })
        .count();
    drop(headers);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        disagree, 0,
        "after the start and one block, the header log disagrees with the chain"
    );
    assert!(
        !unwritten,
        "and the node reports a header write it could not make after one block"
    );
    assert_eq!(
        restored.headers_replaced,
        u64::try_from(SIDE).unwrap(),
        "and the start does not say it cut the abandoned branch's headers"
    );
}

/// A `ledger.dat` longer than any ledger this build writes or takes is
/// refused by its length, before it is read.
///
/// Every decoder behind a start bounds what it builds, and none of them was
/// reached until the whole file was in memory: a ledger file of any length
/// was allocated in full first, and a failed allocation is a process gone
/// with no message.
#[test]
fn a_ledger_file_longer_than_any_ledger_is_refused_before_it_is_read() {
    let directory = scratch("long-ledger");
    // Sparse: a length on the disk, with nothing written to it.
    let file = std::fs::File::create(directory.join(HANDED_LEDGER)).unwrap();
    file.set_len(1 << 30).unwrap();
    drop(file);

    let said = refusal(Node::open(params(), loopback(), &directory));
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        said.contains("longer than any ledger"),
        "a ledger file of a gigabyte was read before it was refused: {said}"
    );

    // And a file exactly at the ceiling the refusal names is read, and
    // refused for what it holds rather than for its length.
    let ceiling: u64 = said
        .rsplit_once('(')
        .and_then(|(_, rest)| rest.split_once(" bytes)"))
        .and_then(|(number, _)| number.parse().ok())
        .expect("the refusal names the ceiling");
    let directory = scratch("ledger-at-the-ceiling");
    let file = std::fs::File::create(directory.join(HANDED_LEDGER)).unwrap();
    file.set_len(ceiling).unwrap();
    drop(file);
    let said = refusal(Node::open(params(), loopback(), &directory));
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        said.contains("not a ledger this build can read"),
        "a ledger file exactly at the ceiling was refused for its length: {said}"
    );
}

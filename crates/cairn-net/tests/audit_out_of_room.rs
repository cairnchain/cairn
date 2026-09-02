//! What a node does when its disk stops taking writes, and what it does with a
//! file that came back torn.
//!
//! An adversarial pass over the writes a running node makes: the ledger it
//! keeps so it can start without one, the block log, the header log, and the
//! address book. Every test states the claim it is testing.
//!
//! The tests that need a filesystem with a real edge take one from
//! `CAIRN_AUDIT_FULL_DIR` and fill what is left of it themselves. They skip
//! when it is not set, because a disk that is genuinely full is not something a
//! portable test can make.

#![allow(
    clippy::maybe_infinite_iter,
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::Handover;
use cairn_ledger::note::Note;
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::book::AddressBook;
use cairn_net::node::{Node, Writing, MAX_BEHIND};
use cairn_primitives::codec::Encode;
use cairn_store::{
    BlockLog, HeaderLog, HeaderTree, BLOCK_INDEX, BLOCK_LOG, HANDED_LEDGER, HEADER_LOG,
};

const NOW: u64 = 2_000_000_000;
const BURIAL: u64 = 8;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(BURIAL)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-room-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// A chain built without mining: testnet's first difficulty is met by the
/// block as assembled, so a thousand blocks cost no work.
struct Chain {
    state: LedgerState,
    past: Vec<LedgerState>,
    blocks: Vec<Block>,
    headers: Vec<BlockHeader>,
    history: Archive,
    clock: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
            headers: Vec::new(),
            history: Archive::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&self.state, coinbase, Vec::new(), &params, self.clock, 0).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        self.past.push(self.state.clone());
        self.history.add(header_leaf(&block.header.id())).unwrap();
        self.headers.push(block.header);
        self.blocks.push(block);
    }

    fn run(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner);
        }
    }

    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let anchor = self.history.prove_in(anchor_height, tip.height).unwrap();
        let from = anchor_height.saturating_sub(90) as usize;
        let recent: Vec<BlockHeader> = self.headers[from..=anchor_height as usize].to_vec();
        state
            .handover(
                at,
                tip,
                self.state.headers_before_tip(),
                anchor,
                self.headers[(anchor_height as usize + 1)..].to_vec(),
                recent,
            )
            .expect("a node can hand over what it holds")
    }
}

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

// ---------------------------------------------------------------------------
// The ledger a node was handed.
// ---------------------------------------------------------------------------

/// The claim under test, from `keep_ledger`: "Written whole, to a name beside
/// the old one, and moved into place. A process that stops partway leaves the
/// previous file untouched rather than half of a new one, which for a file a
/// node cannot start without is the difference between an interrupted write
/// and a node that never comes back."
///
/// The rename covers a process that stops between the two writes. It does not
/// cover a machine that stops: `std::fs::write` returns when the bytes are in
/// the page cache, and nothing syncs the staged file before the rename or the
/// directory after it, so a power cut can leave the new name pointing at
/// nothing. This test does not simulate the power cut — it puts the file into
/// the state one would leave and asks what the next start does with it.
///
/// What it does is delete the node's entire block log.
#[test]
fn a_torn_handed_ledger_deletes_the_whole_block_log() {
    let mut source = Chain::new();
    source.run(&wallet(9), 120);
    let handover = source.handover();
    let anchor = handover.at.height;
    let ledger = handover.encode();

    let directory = scratch("torn-ledger");
    std::fs::write(directory.join(HANDED_LEDGER), &ledger).unwrap();
    // The blocks a joined node validates its way through, which start above
    // the anchor and are the only copy it has.
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &source.blocks[(anchor as usize + 1)..] {
            log.append(block).unwrap();
        }
    }
    let before = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
    assert!(before > 0);

    // A node opens it and finds what it left.
    {
        let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
        assert_eq!(restored.blocks, source.blocks.len() - anchor as usize - 1);
        assert!(!restored.rejoining);
        assert_eq!(node.height(), Some(source.headers.last().unwrap().height));
        drop(node);
    }

    // Now the shape a rename made durable ahead of its contents leaves: the
    // name is there and the bytes are not.
    std::fs::write(directory.join(HANDED_LEDGER), &ledger[..ledger.len() / 2]).unwrap();

    let (node, restored) = Node::open(params(), loopback(), &directory)
        .expect("the node starts, which is the part that is right");
    let after = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
    drop(node);

    // It says so, which is the part that is right.
    assert!(
        restored.rejoining,
        "the operator is told the stored blocks start partway up the chain"
    );
    // And then it deletes them.
    assert_eq!(
        after, 0,
        "the block log survived; it was {before} bytes and is now {after}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The same, one byte at a time, to show it is not a property of where the cut
/// falls: every truncation of the handed ledger except none at all costs the
/// node every block it holds.
#[test]
fn every_cut_of_the_handed_ledger_costs_the_same() {
    let mut source = Chain::new();
    source.run(&wallet(9), 40);
    let handover = source.handover();
    let anchor = handover.at.height;
    let ledger = handover.encode();
    let above = &source.blocks[(anchor as usize + 1)..];

    let mut kept = Vec::new();
    // A handful of cuts rather than all of them: opening a node binds a socket
    // and starts threads, so this is the sample that shows the shape.
    for cut in [0usize, 1, 16, 256, ledger.len() / 2, ledger.len() - 1] {
        let directory = scratch(&format!("cut-{cut}"));
        std::fs::write(directory.join(HANDED_LEDGER), &ledger[..cut]).unwrap();
        {
            let (mut log, _) = BlockLog::open(&directory).unwrap();
            for block in above {
                log.append(block).unwrap();
            }
        }
        let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
        drop(node);
        let held = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
        kept.push((cut, restored.rejoining, held));
        let _ = std::fs::remove_dir_all(&directory);
    }

    for (cut, rejoining, held) in &kept {
        eprintln!("ledger cut to {cut:>4} bytes: rejoining {rejoining}, log left {held} bytes");
    }
    assert!(
        kept.iter()
            .all(|(_, rejoining, held)| *rejoining && *held == 0),
        "some cut left the log alone: {kept:?}"
    );
}

// ---------------------------------------------------------------------------
// A branch the chain has already let go of.
// ---------------------------------------------------------------------------

/// The claim under test, from `write_blocks`: "Everything the branch carries
/// beyond what the log holds. Usually one block; more if a write failed earlier
/// and the log fell behind."
///
/// The catch-up reads `chain.block_at`, which returns a reference and therefore
/// can only come from memory. A chain lets go of a body once it is deeper than
/// it can undo, whether or not a log ever took it. So the catch-up works only
/// while the gap is inside that window: past it there is nothing left to catch
/// up from, and the log stops for good.
///
/// This test pins the memory half — that a body is dropped on a schedule of its
/// own, with no regard for what reached the disk.
#[test]
fn a_chain_lets_go_of_bodies_the_disk_may_never_have_taken() {
    let depth = cairn_chain::MAX_REORG_DEPTH as u64;
    let mut source = Chain::new();
    source.run(&wallet(4), (depth + 40) as usize);

    let mut chain = cairn_chain::ChainStore::new(params());
    for block in &source.blocks {
        chain.add_block(block.clone(), NOW).unwrap();
    }
    let tip = chain.height().unwrap();

    // Nothing was ever attached to read bodies back from, so this is a chain
    // with no disk at all — and it drops them anyway.
    assert!(
        chain.block_at(tip).is_some(),
        "the tip is held, or the test proves nothing"
    );
    assert!(
        chain.block_at(tip - depth + 1).is_some(),
        "the window is held"
    );
    assert!(
        chain.block_at(0).is_none(),
        "a block a thousand deep is gone from memory"
    );
    assert!(
        chain.block_at(tip - depth - 5).is_none(),
        "and so is everything past the window"
    );
    eprintln!(
        "tip {tip}, window {depth}: block_at(0) is {:?}",
        chain.block_at(0).map(Block::id)
    );
}

/// The other half, with a real node and a real filesystem edge: a log that
/// falls behind while there is no room never catches up, and nothing says so.
///
/// Blocks keep arriving and being accepted the whole time. The chain's height
/// climbs; the log's does not.
#[test]
fn a_log_that_falls_behind_while_the_disk_is_full_stays_behind() {
    let Ok(root) = std::env::var("CAIRN_AUDIT_FULL_DIR") else {
        eprintln!("skipped: set CAIRN_AUDIT_FULL_DIR to a directory on a small filesystem");
        return;
    };
    let root = PathBuf::from(root);
    let directory = root.join("node");
    let _ = std::fs::remove_dir_all(&directory);

    let depth = cairn_chain::MAX_REORG_DEPTH;
    let mut source = Chain::new();
    source.run(&wallet(4), depth + 60);

    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    node.keep_blocks(u64::MAX);
    for block in &source.blocks[..20] {
        node.submit_block(block.clone()).unwrap();
    }
    let written = std::fs::metadata(directory.join(BLOCK_LOG)).unwrap().len();
    assert!(written > 0);
    assert!(node.archived_at(19).is_some(), "the log holds what it took");

    let ballast = eat_the_room(&root);

    // Every block from here on is accepted; how much of it reaches the disk is
    // what this test is about.
    let mut accepted = 20usize;
    for block in &source.blocks[20..] {
        if node.submit_block(block.clone()).is_ok() {
            accepted += 1;
        }
    }
    let reached = |node: &Node| (0..).find(|h| node.archived_at(*h).is_none()).unwrap_or(0);
    let stuck = reached(&node);
    eprintln!(
        "accepted {accepted} blocks; chain at {:?}, log reaches {stuck}",
        node.height()
    );
    assert!(
        stuck < 200,
        "the disk was not full enough for this test to mean anything: log reached {stuck}"
    );

    // The room comes back. Nothing asks for it, so nothing happens; and the
    // blocks in between are past the window a chain can undo, so nothing can.
    std::fs::remove_dir_all(&ballast).unwrap();
    let mut more = Chain::new();
    more.run(&wallet(4), depth + 70);
    for block in &more.blocks[(depth + 60)..] {
        let _ = node.submit_block(block.clone());
    }
    let after = reached(&node);
    eprintln!(
        "with the room back, the log reaches {after} and the chain is at {:?}",
        node.height()
    );
    assert_eq!(
        after, stuck,
        "the log caught up once the room came back, which would be the happy answer"
    );

    // What the operator can see: a height that is right and a log that is not.
    let height = node.height().unwrap();
    assert!(
        height > stuck + 100,
        "the chain is far past what the log holds"
    );
    assert!(
        node.archived_at(height).is_none(),
        "the node cannot serve the tip it says it is at"
    );
    drop(node);

    // And at the next start it comes back at the log's height, not the chain's.
    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    eprintln!(
        "restarted: {} blocks restored, chain at {:?}, was at {height}",
        restored.blocks,
        node.height()
    );
    assert_eq!(restored.blocks, stuck as usize);
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim this fix makes: a node whose disk has stopped taking writes says
/// so while there is still time to act on it, and stops itself before the
/// blocks in the gap are past saving.
///
/// The test above pins what a node with a full disk does to its chain. This
/// one pins what it now says about it, and what it does about the saying.
///
/// The two numbers that matter are the chain's height, which is memory, and
/// the disk's, which is what survives a restart. On the code this was written
/// against there was no surface anywhere on `Node` for the second one, so an
/// operator watching a healthy status line had no way to ask the one question
/// that would have told them.
#[test]
fn a_node_whose_disk_stops_taking_writes_says_so_and_then_stops() {
    let Ok(root) = std::env::var("CAIRN_AUDIT_FULL_DIR") else {
        eprintln!("skipped: set CAIRN_AUDIT_FULL_DIR to a directory on a small filesystem");
        return;
    };
    let root = PathBuf::from(root);
    let directory = root.join("saying");
    let _ = std::fs::remove_dir_all(&directory);

    let mut source = Chain::new();
    source.run(&wallet(4), (MAX_BEHIND + 80) as usize);

    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    node.keep_blocks(u64::MAX);
    for block in &source.blocks[..20] {
        node.submit_block(block.clone()).unwrap();
    }
    assert_eq!(node.written_through(), Some(19), "the disk is level so far");
    assert!(node.unwritten().is_none(), "and has nothing to say");

    let ballast = eat_the_room(&root);

    // One block at a time, so what the node says can be read against how far
    // behind it has fallen rather than against the end of a batch.
    let mut said_at = None;
    let mut losing_at = None;
    let mut stopped_at = None;
    for block in &source.blocks[20..] {
        let _ = node.submit_block(block.clone());
        let Some(unwritten) = node.unwritten() else {
            continue;
        };
        if said_at.is_none() {
            eprintln!(
                "first word at {} blocks behind: {} / {}",
                unwritten.blocks, unwritten.what, unwritten.because
            );
            said_at = Some(unwritten.clone());
        }
        if losing_at.is_none() && unwritten.blocks > 0 {
            losing_at = Some(unwritten.clone());
        }
        if !unwritten.within_reach {
            stopped_at = Some(unwritten);
            break;
        }
    }
    std::fs::remove_dir_all(&ballast).unwrap();

    let Some(said) = said_at else {
        panic!("the filesystem never ran out; make it smaller");
    };
    assert!(
        !said.because.is_empty(),
        "it passes on what the disk said, which is the actionable half"
    );
    assert!(
        said.blocks <= 2,
        "it is said on the first write that does not land, not after a hundred: {}",
        said.blocks
    );

    // Which write fails first belongs to the filesystem, not to this node: the
    // headers go down before the blocks and a header record is smaller, so the
    // last space on the disk may take one and refuse the other. What has to be
    // true is that the report names the blocks once blocks are what is being
    // lost, because that is the one an operator has to act on before the
    // window closes.
    let losing = losing_at.expect("the log fell behind, or this test proves nothing");
    eprintln!(
        "first block lost: {} / {}, disk at {:?}",
        losing.what, losing.because, losing.written_through
    );
    assert_eq!(losing.what, Writing::Blocks);

    let stopped = stopped_at.expect("a gap past saving is one the node stops on");
    eprintln!(
        "stopped at {} blocks behind: chain {}, disk {:?}",
        stopped.blocks, stopped.reached, stopped.written_through
    );
    assert!(
        stopped.blocks > MAX_BEHIND,
        "nothing gives up before the number it published"
    );
    assert!(
        stopped.blocks <= MAX_BEHIND + 2,
        "and nothing waits past it either, since every block after costs one more"
    );
    assert!(
        stopped.blocks < cairn_chain::MAX_REORG_DEPTH as u64,
        "it stops inside the window a chain still holds bodies over, which is \
         the whole reason there is a number"
    );
    assert_eq!(
        stopped.written_through,
        node.written_through(),
        "and it names the height a restart would begin at"
    );
    assert_eq!(
        stopped.reached,
        node.height().unwrap(),
        "beside the height the status line shows, which is the other one"
    );

    // Stopped, in the way `outdated` and `stranded` stop a node: the flag that
    // every loop inside it reads is cleared, so nothing is attached to it any
    // more. Shown against a control, because a witness nobody can dial would
    // prove this by accident.
    let witness = Node::bind(params(), loopback()).unwrap();
    let control = Node::bind(params(), loopback()).unwrap();
    control.connect(witness.address()).unwrap();
    assert_eq!(control.peer_count(), 1, "the witness takes connections");
    node.connect(witness.address()).unwrap();
    assert_eq!(
        node.peer_count(),
        0,
        "a node that has stopped does not take one"
    );

    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------
// The address book.
// ---------------------------------------------------------------------------

/// The claim: "A lost address book costs a node its head start, never its
/// chain."
///
/// `save` writes over the file rather than beside it, so a write that runs out
/// halfway leaves a shorter book with a partial last line. Nothing is lost that
/// matters, because a line that will not parse is skipped.
#[test]
fn a_torn_address_book_costs_only_the_addresses_it_lost() {
    let directory = scratch("book");
    let mut book = AddressBook::new();
    for n in 1..40u8 {
        book.insert(SocketAddr::from(([10, 0, 0, n], 9000 + u16::from(n))));
    }
    book.save(&directory).unwrap();
    let path = directory.join("peers.txt");
    let whole = std::fs::read(&path).unwrap();

    let mut smallest = usize::MAX;
    for cut in 0..=whole.len() {
        std::fs::write(&path, &whole[..cut]).unwrap();
        let back = AddressBook::load(&directory);
        assert!(
            back.len() <= book.len(),
            "cut at {cut} produced addresses nobody wrote"
        );
        smallest = smallest.min(back.len());
    }
    eprintln!("39 addresses; the worst cut left {smallest}");
    let _ = std::fs::remove_dir_all(&directory);
}

/// And what a full disk does to it.
///
/// `save` writes straight over the file rather than beside it, so unlike the
/// ledger and the wallet's history there is no rename standing between a write
/// that runs out and the file that was there. What this test found on the
/// filesystem it was run against is that the write still succeeded, so it is a
/// report rather than a defect: the shape is there, the failure was not
/// reproduced, and the exposure is one address book, which costs a head start
/// and never a chain.
#[test]
fn an_address_book_that_cannot_be_written_says_so() {
    let Ok(root) = std::env::var("CAIRN_AUDIT_FULL_DIR") else {
        eprintln!("skipped: set CAIRN_AUDIT_FULL_DIR to a directory on a small filesystem");
        return;
    };
    let root = PathBuf::from(root);
    let directory = root.join("book");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();

    // Spread across neighbourhoods, because the book keeps only
    // `MAX_PER_GROUP` from any one of them and a book that capped itself would
    // look exactly like a write that ran out.
    let mut book = AddressBook::new();
    for n in 1..30u8 {
        book.insert(SocketAddr::from(([10, n, 0, 1], 9000 + u16::from(n))));
    }
    book.save(&directory).unwrap();
    let whole = std::fs::read(directory.join("peers.txt")).unwrap().len();

    let mut bigger = AddressBook::new();
    for a in 1..30u8 {
        for b in 1..8u8 {
            bigger.insert(SocketAddr::from(([10, a, b, 1], 9000 + u16::from(b))));
        }
    }
    let held = bigger.len();
    let ballast = eat_the_room(&root);
    let outcome = bigger.save(&directory);
    let left = std::fs::metadata(directory.join("peers.txt"))
        .unwrap()
        .len();
    std::fs::remove_dir_all(&ballast).unwrap();

    eprintln!(
        "save of {held} addresses on a full disk: {outcome:?}; the file went from {whole} to \
         {left} bytes"
    );
    let back = AddressBook::load(&directory);
    eprintln!("what came back: {} addresses", back.len());
    // Either the write got through, or it was reported. What must not happen
    // is a quiet success over a file that is now shorter than it was.
    assert!(
        outcome.is_err() || back.len() == held,
        "the save said it worked and the book came back short"
    );
    assert!(whole > 0 && left > 0);
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------
// Opening the store when there is nothing left.
// ---------------------------------------------------------------------------

/// The claim: a node that cannot write says so rather than carrying on.
///
/// On a disk with nothing left at all it says so as loudly as it can: it
/// refuses to start. Recorded for what it means to an operator.
#[test]
fn a_node_will_not_start_on_a_disk_with_nothing_left() {
    let Ok(root) = std::env::var("CAIRN_AUDIT_FULL_DIR") else {
        eprintln!("skipped: set CAIRN_AUDIT_FULL_DIR to a directory on a small filesystem");
        return;
    };
    let root = PathBuf::from(root);
    let ballast = eat_the_room(&root);
    let directory = root.join("cold");
    let outcome = Node::open(params(), loopback(), &directory);
    let said = match &outcome {
        Ok(_) => "started".to_owned(),
        Err(error) => error.to_string(),
    };
    std::fs::remove_dir_all(&ballast).unwrap();
    eprintln!("opening a node with no room: {said}");
    drop(outcome);
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim: the header log is kept whatever happens to the blocks, because it
/// is what a newcomer is shown.
///
/// Rebuilt from the blocks at the next start when it falls behind, so a header
/// write that ran out costs nothing while the blocks are still there. This test
/// is what makes that true or false.
#[test]
fn a_header_log_left_short_is_rebuilt_from_the_blocks() {
    let mut source = Chain::new();
    source.run(&wallet(4), 30);
    let directory = scratch("headers-short");
    {
        let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
        node.keep_blocks(u64::MAX);
        for block in &source.blocks {
            node.submit_block(block.clone()).unwrap();
        }
    }
    let whole = std::fs::metadata(directory.join(HEADER_LOG)).unwrap().len();
    assert_eq!(whole, 30 * 182);

    // What a header write that ran out leaves, cut back to whole records by
    // the open that follows.
    std::fs::OpenOptions::new()
        .write(true)
        .open(directory.join(HEADER_LOG))
        .unwrap()
        .set_len(10 * 182)
        .unwrap();

    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    drop(node);
    let back = HeaderLog::open(&directory).unwrap();
    eprintln!("headers cut to 10, came back as {}", back.len());
    assert_eq!(
        back.len(),
        30,
        "the headers were not rebuilt from the blocks that are still there"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------
// What the node says about its own disk.
// ---------------------------------------------------------------------------

/// The claim: a node whose disk is taking what it writes says nothing at all.
///
/// The first half of every surface here. A report an operator learns to ignore
/// is worse than no report, so the healthy case is tested before any of the
/// broken ones.
#[test]
fn a_node_whose_disk_is_working_says_nothing_about_it() {
    let mut source = Chain::new();
    source.run(&wallet(4), 30);
    let directory = scratch("healthy");

    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    node.keep_blocks(u64::MAX);
    assert!(
        restored.unreadable.is_none(),
        "nothing was there to misread"
    );
    for block in &source.blocks {
        node.submit_block(block.clone()).unwrap();
    }

    assert_eq!(node.height(), Some(29));
    assert_eq!(
        node.written_through(),
        Some(29),
        "the disk is level with the chain, and now there is somewhere to ask"
    );
    assert!(
        node.unwritten().is_none(),
        "and a working disk has nothing to report: {:?}",
        node.unwritten()
    );
    assert!(node.write_ledger(), "the ledger goes down too");
    assert!(
        node.unwritten().is_none(),
        "which also said nothing: {:?}",
        node.unwritten()
    );
    assert!(
        node.unjudged().is_none(),
        "and no block arrived that this build could not read"
    );

    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim, from `write_ledger`: "Writes this node's ledger down, returning
/// the height it stands for."
///
/// It used to return a bool nobody read, and to reach a `keep_ledger` that
/// answered `is_ok() && is_ok()`. A node that cannot write its ledger cannot
/// get under its disk budget either, because dropping the blocks below one
/// starts by writing several megabytes, so on the disk this fails on it is the
/// whole of the trouble.
///
/// A directory sitting where the staged file goes stands in for the full disk.
/// It refuses that one write and disturbs nothing else, which is what makes
/// this about the ledger rather than about whatever else a read-only directory
/// would take down with it.
#[test]
fn a_ledger_that_cannot_be_written_says_so() {
    let mut source = Chain::new();
    source.run(&wallet(4), 50);
    let directory = scratch("no-ledger");

    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    node.keep_blocks(u64::MAX);
    for block in &source.blocks[..30] {
        node.submit_block(block.clone()).unwrap();
    }
    assert!(node.write_ledger(), "it works while the disk does");
    assert!(node.unwritten().is_none());

    // Past the tip the last one was written for, or the answer comes back out
    // of what was written rather than off the disk.
    for block in &source.blocks[30..] {
        node.submit_block(block.clone()).unwrap();
    }
    std::fs::create_dir(directory.join(format!("{HANDED_LEDGER}.part"))).unwrap();

    assert!(!node.write_ledger(), "and it cannot now");
    let said = node
        .unwritten()
        .expect("a ledger that would not write is worth a word");
    eprintln!("what the node said: {} / {}", said.what, said.because);
    assert_eq!(said.what, Writing::Ledger);
    assert!(
        !said.because.is_empty(),
        "and it passes on what the disk said, which is the actionable half"
    );
    assert_eq!(
        said.blocks, 0,
        "no block was lost by it, and the report says which trouble this is"
    );
    assert_eq!(
        node.written_through(),
        node.height(),
        "the blocks are still going down; it is the ledger that is not"
    );

    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim, from `HeaderLog::read`: a header the store will not vouch for is
/// reported rather than returned. And the claim it meets here, from
/// `write_headers` and `grow_forest`, that both of them keep the disk in line
/// with the branch.
///
/// Every read in those two walks was taken with `.ok().flatten()`, which turns
/// the store's refusal into "there is no header here". Read that way it is
/// silence: the header log is written again from the chain, which is the right
/// repair and the right outcome, and nobody is ever told that a byte of a
/// header file changed under them. A disk that did that once will do it again,
/// and the next one may be a record the chain can no longer replace.
#[test]
fn a_header_the_store_will_not_read_is_said_out_loud_and_costs_nothing_else() {
    let mut source = Chain::new();
    source.run(&wallet(4), 31);
    let directory = scratch("bad-header");
    {
        let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
        node.keep_blocks(u64::MAX);
        for block in &source.blocks[..30] {
            node.submit_block(block.clone()).unwrap();
        }
        assert_eq!(node.written_through(), Some(29));
    }
    assert_eq!(HeaderTree::open(&directory).unwrap().len(), 30);

    // The parent named by the last header. Changing it breaks the two links
    // that record takes part in and nothing else on the disk, which is the
    // smallest damage the store has a word for. A header is a version, a
    // network, a height and then the parent.
    let previous_at = 2 + 4 + 8;
    let path = directory.join(HEADER_LOG);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[29 * 182 + previous_at] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();
    {
        let log = HeaderLog::open(&directory).unwrap();
        assert!(
            log.read_at(29).is_err(),
            "the store has to be refusing, or this test proves nothing"
        );
        assert!(log.read_at(27).is_ok(), "and refusing about that one only");
    }

    let (node, _) = Node::open(params(), loopback(), &directory).unwrap();
    node.keep_blocks(u64::MAX);
    node.submit_block(source.blocks[30].clone()).unwrap();
    let said = node.unwritten();
    drop(node);

    let said = said.expect("a store that refused a read is worth a word");
    eprintln!("what the node said: {} / {}", said.what, said.because);
    assert_eq!(said.what, Writing::Headers);
    assert!(
        said.because.contains("29"),
        "and it names the record: {}",
        said.because
    );
    assert_eq!(said.blocks, 0, "no block was lost by it");

    // And the repair still happens, which is what makes the report worth
    // reading rather than a node giving up on one byte.
    let headers = HeaderLog::open(&directory).unwrap();
    assert_eq!(headers.reaches(), 31, "the headers were written again");
    assert!(headers.read_at(29).is_ok(), "including the damaged one");
    assert_eq!(
        HeaderTree::open(&directory).unwrap().len(),
        31,
        "and the forest over them"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// The claim, from `Recovered::unreadable`: "This is damage, not an interrupted
/// write, and the two must not be reported to an operator in the same words."
///
/// `Restored` did not carry it, so a node whose log holds a record that will
/// not decode showed its operator a byte count and no word for what happened.
#[test]
fn a_record_the_store_cannot_read_is_named_rather_than_counted_in_bytes() {
    let mut source = Chain::new();
    source.run(&wallet(4), 10);
    let directory = scratch("bad-record");
    {
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &source.blocks {
            log.append(block).unwrap();
        }
    }

    // Where the sixth record's body begins, taken from the index while there
    // still is one: it holds where each record ends, eight bytes each.
    let index = std::fs::read(directory.join(BLOCK_INDEX)).unwrap();
    let ends: Vec<u64> = index
        .chunks_exact(8)
        .map(|entry| u64::from_le_bytes(entry.try_into().unwrap()))
        .collect();
    let body = (ends[4] + 4) as usize;
    let until = ends[5] as usize;

    let path = directory.join(BLOCK_LOG);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[body..until].fill(0xFF);
    std::fs::write(&path, &bytes).unwrap();
    // Without this the index is believed and only the last record is read, so
    // the walk that meets the damage never happens.
    std::fs::remove_file(directory.join(BLOCK_INDEX)).unwrap();

    let (node, restored) = Node::open(params(), loopback(), &directory).unwrap();
    eprintln!(
        "record 5 of 10 made unreadable: restored {} blocks, {} bytes set aside, unreadable {:?}",
        restored.blocks, restored.discarded_bytes, restored.unreadable
    );
    assert_eq!(
        restored.unreadable,
        Some(5),
        "the operator is told which record, not just that some bytes went"
    );
    assert_eq!(
        restored.blocks, 5,
        "and the node starts from the ones before"
    );
    assert_eq!(
        restored.discarded_bytes, 0,
        "nothing was cut for it, so nothing is reported as thrown away"
    );
    assert!(
        restored.left_in_place > 0,
        "and what is standing there unread is what says how much this cost"
    );
    assert_eq!(node.written_through(), Some(4));
    drop(node);

    // Nothing was cut for it, which is the store's rule and the reason an
    // operator can still go and look.
    let after = std::fs::metadata(&path).unwrap().len();
    assert_eq!(
        after as usize,
        bytes.len(),
        "the bytes are still on the disk"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

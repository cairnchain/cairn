//! What the explorer's index costs, measured rather than reasoned.
//!
//! The index is included as a module rather than linked, because the explorer
//! is a binary and has no library target. Nothing in `src/` is changed.
//!
//! The memory figures are read off the process's resident set, which means
//! they are only worth anything when a test has a process to itself: run one
//! at a time with
//!
//! ```text
//! cargo test --release -p cairn-explorer --test audit_index_cost \
//!     -- --nocapture --exact <name>
//! ```
//!
//! Run together in one process, a later test is handed memory an earlier one
//! freed and reads far too low. The times are safe either way.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    dead_code,
    unused_imports,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::clone_on_copy,
    clippy::redundant_closure,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::match_wildcard_for_single_variants,
    clippy::empty_line_after_doc_comments,
    clippy::too_many_lines,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value
)]

#[path = "../src/index.rs"]
mod index;

use std::cell::Cell;
use std::time::Instant;

use cairn_chain::{Accepted, ChainStore};
use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::{Decode, Encode};

use index::{Head, Held, Index, Reading};

/// Reads until the walk is level with the tip, which is what
/// `Explorer::refresh` does with it.
///
/// One call reads a batch and says whether there is more, so that the site can
/// be answered between turns; a caller that wants the whole chain read comes
/// straight back for the next one. Every figure in this file is about a whole
/// read, so they all go through here.
///
/// The head is worked out again for every turn, because it is a statement
/// about what the index has read and that changes with each turn. `Explorer`
/// does the same, for the same reason.
fn read_all(
    index: &mut Index,
    head: impl Fn(&Index) -> Option<Head>,
    block_at: impl Fn(u64) -> Held,
) {
    loop {
        let Some(now) = head(index) else {
            return;
        };
        if index.refresh(&now, &block_at) == Reading::Done {
            return;
        }
    }
}

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Mines blocks on a private ledger, so a branch can be built off to the side.
#[derive(Clone)]
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_many(&mut self, miner: &SecretKey, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine(miner)).collect()
    }

    fn fork(&self) -> Self {
        self.clone()
    }
}

fn feed(store: &mut ChainStore, blocks: &[Block]) -> Vec<Accepted> {
    blocks
        .iter()
        .map(|block| store.add_block(block.clone(), NOW).unwrap())
        .collect()
}

/// The two questions the explorer asks with the chain held, taken together.
///
/// Everything after this runs with the chain let go of, which is the shape
/// the walk below is measured in.
fn head_of(store: &ChainStore, index: &Index) -> Option<Head> {
    Some(Head {
        tip: store.height()?,
        at_last_read: index.covers().and_then(|(_, through)| store.id_at(through)),
    })
}

/// A block log, as a node keeps one: a run of heights with nothing under
/// `from`.
///
/// The distinction it exists to make is the one the walk needed and did not
/// have. A height under `from` is one this node dropped and will never hold
/// again; a height over the run is one that has not reached the disk yet. A
/// walk that reads the two the same way stops at the first and never starts.
struct Shelf {
    blocks: std::collections::HashMap<u64, Block>,
    from: u64,
}

impl Shelf {
    fn of(blocks: &[Block]) -> Self {
        Self {
            blocks: blocks
                .iter()
                .map(|block| (block.header.height, block.clone()))
                .collect(),
            from: 0,
        }
    }

    fn add(&mut self, block: &Block) {
        self.blocks.insert(block.header.height, block.clone());
    }

    /// Drops everything under `height`, the way upkeep does when the log has
    /// grown past what the operator allows it.
    fn trim_to(&mut self, height: u64) {
        self.blocks.retain(|at, _| *at >= height);
        self.from = height;
    }

    fn held(&self, store: &ChainStore, height: u64) -> Held {
        if let Some(block) = store.block_at(height) {
            return Held::Block(Box::new(block.clone()));
        }
        if let Some(block) = self.blocks.get(&height) {
            return Held::Block(Box::new(block.clone()));
        }
        if height < self.from {
            Held::Dropped
        } else {
            Held::Waiting
        }
    }
}

/// How long it takes to mine the cheapest possible chain, so the rest of these
/// numbers can be read next to what producing them cost.
#[test]
fn mining_rate() {
    let mut forge = Forge::new(params());
    let miner = wallet(1);
    let started = Instant::now();
    let _ = forge.mine_many(&miner, 200);
    let took = started.elapsed();
    println!("mined 200 empty blocks in {took:?} ({:?} each)", took / 200);
}

/// Reads the resident set of this process, in kilobytes, as the operating
/// system reports it. Coarse, and a real measurement rather than a sum of
/// `size_of` guesses.
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

/// A reorganisation makes the index read the whole chain again, not the part
/// that changed. That much is deliberate. What it used to do besides, and no
/// longer does, is hold the chain while it happened.
///
/// The claim under test is the one in `Index::refresh`'s own comment:
/// "A reorganisation drops the whole index and reads the branch again."
/// Unwinding would be faster and is not worth its own set of bugs. What was
/// wrong was never the re-reading: it was that `Explorer::refresh` took the
/// index lock, then the node's single chain lock, and then called
/// `archived_at` once per block inside it. `answer`'s doc comment two lines
/// below says why that must not happen, and `refresh` did exactly that for
/// the whole chain: six seconds of frozen node at half a million empty blocks
/// for one reorganisation of one block, minutes at a hundred notes a block,
/// with incoming block validation queued behind it.
///
/// `Index::refresh` can no longer do it. It is handed a `Head`, which is two
/// numbers read in one go, and the reader it walks with is called with
/// nothing held. The test below holds the chain the way a node does and
/// proves the reader can take it.
///
/// The blocks the walk cannot get from the chain are served from a shelf here,
/// which is what `Node::archived_at` does off a disk in the running program.
/// So the times below are a floor: every shelf read is a file seek and a
/// decode on the real thing.
#[test]
fn a_reorganisation_rereads_the_whole_chain_and_holds_nothing_while_it_does() {
    for (length, depth) in [
        (1_000usize, 1usize),
        (3_000, 1),
        (3_000, 10),
        (3_000, 1_000),
    ] {
        let miner = wallet(1);
        let rival = wallet(9);

        let mut base = Forge::new(params());
        let common = base.mine_many(&miner, length - depth);
        let mut good_forge = base.fork();
        let good = good_forge.mine_many(&miner, depth);
        let mut bad_forge = base.fork();
        let bad = bad_forge.mine_many(&rival, depth + 2);

        let mut shelf = Shelf::of(&common);
        for block in &good {
            shelf.add(block);
        }

        let mut store = ChainStore::archiving(params());
        feed(&mut store, &common);
        feed(&mut store, &good);
        assert_eq!(store.height(), Some(length as u64 - 1));

        let reads = Cell::new(0usize);
        let off_shelf = Cell::new(0usize);
        let mut index = Index::new();
        let head = head_of(&store, &index).unwrap();
        let started = Instant::now();
        read_all(
            &mut index,
            |_| Some(head),
            |height| {
                reads.set(reads.get() + 1);
                if store.block_at(height).is_none() {
                    off_shelf.set(off_shelf.get() + 1);
                }
                shelf.held(&store, height)
            },
        );
        let first = started.elapsed();
        let first_reads = reads.get();
        assert_eq!(index.blocks_read(), length, "the whole chain was indexed");

        // One block on top: the ordinary case, for contrast.
        let extra = good_forge.mine(&miner);
        shelf.add(&extra);
        feed(&mut store, std::slice::from_ref(&extra));
        reads.set(0);
        let started = Instant::now();
        read_all(
            &mut index,
            |index| head_of(&store, index),
            |height| {
                reads.set(reads.get() + 1);
                shelf.held(&store, height)
            },
        );
        let extend = started.elapsed();
        let extend_reads = reads.get();

        // Now the reorganisation.
        for block in &bad {
            shelf.add(block);
        }
        feed(&mut store, &bad);
        assert_eq!(
            store.tip(),
            bad.last().map(Block::id),
            "the rival branch must have won for this to measure anything"
        );

        reads.set(0);
        off_shelf.set(0);
        let started = Instant::now();
        read_all(
            &mut index,
            |index| head_of(&store, index),
            |height| {
                reads.set(reads.get() + 1);
                if store.block_at(height).is_none() {
                    off_shelf.set(off_shelf.get() + 1);
                }
                shelf.held(&store, height)
            },
        );
        let after = started.elapsed();
        let after_reads = reads.get();

        println!(
            "chain {length:5}, reorg depth {:5}: build {first:>9.2?} ({first_reads} read) | \
             +1 block {extend:>9.2?} ({extend_reads} read) | \
             after reorg {after:>9.2?} ({after_reads} read, {} of them off the shelf)",
            depth + 1,
            off_shelf.get(),
        );

        assert_eq!(extend_reads, 1, "an ordinary new block reads one block");
        assert_eq!(
            after_reads,
            index.blocks_read(),
            "and a reorganisation of {depth} reads the whole branch again"
        );
    }
}

/// And the rebuild above runs with the chain let go of.
///
/// The chain sits behind a lock here, as it does inside a node, and the
/// reader the walk calls takes it for every block. Before, that lock was
/// already in `Explorer::refresh`'s hand for the whole rebuild and every peer
/// waited behind it; `Index::refresh` could not have been written any other
/// way, because it was handed the chain itself. It is handed two numbers now.
#[test]
fn the_walk_can_be_interrupted_by_the_node_it_reads() {
    use std::sync::Mutex;

    let miner = wallet(1);
    let mut forge = Forge::new(params());
    let blocks = forge.mine_many(&miner, 200);

    let mut built = ChainStore::archiving(params());
    feed(&mut built, &blocks);
    let store = Mutex::new(built);

    let mut index = Index::new();
    let head = {
        let chain = store.lock().unwrap();
        head_of(&chain, &index).unwrap()
    };

    let taken = Cell::new(0usize);
    read_all(
        &mut index,
        |_| Some(head),
        |height| {
            // What the node itself does between blocks, and what used to queue
            // behind the whole rebuild.
            let chain = store
                .try_lock()
                .expect("the chain is not held while a block is read");
            taken.set(taken.get() + 1);
            match chain.block_at(height) {
                Some(block) => Held::Block(Box::new(block.clone())),
                None => Held::Waiting,
            }
        },
    );

    assert_eq!(index.blocks_read(), 200);
    assert_eq!(taken.get(), 200, "and every block was read the same way");
}

/// Distinct public keys, made the cheapest way that still produces a value
/// `PublicKey::from_bytes` accepts.
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

/// A block log that has been trimmed costs the index the blocks that were
/// trimmed, and nothing else.
///
/// It used to cost the index everything. `cairn_net::KEEP_BLOCK_BYTES` is a
/// gigabyte and `Node::start` sets it on every node, archiving or not.
/// `cairn-node` let an operator raise it with `--keep`; `cairn-explorer` had
/// no such option and never called `Node::keep_blocks`, so the one program
/// whose whole purpose is answering about every block ever quietly stopped
/// holding the early ones. `Index::refresh` then walked from height zero and
/// `break`d at the first height it could not get, which was height zero. The
/// index held nothing, `/api/address` answered `balance "0"` with
/// `counted: true`, and the home page showed a real issued supply beside
/// `Addresses holding: 0`.
///
/// Both halves are repaired. The explorer keeps every block unless an
/// operator says otherwise, so the trim below does not happen on a default
/// build at all; and where an operator has asked for a budget, the walk steps
/// over what was dropped and the index says where it starts.
#[test]
fn a_trimmed_log_costs_the_index_only_the_blocks_that_were_trimmed() {
    let miner = wallet(1);
    let mut forge = Forge::new(params());
    let blocks = forge.mine_many(&miner, 1_500);

    let mut store = ChainStore::archiving(params());
    feed(&mut store, &blocks);
    assert_eq!(store.height(), Some(1_499));

    // A log trimmed to its budget: it starts at `cut` and holds nothing below.
    let cut = 100u64;
    let mut shelf = Shelf::of(&blocks);
    shelf.trim_to(cut);
    assert!(
        matches!(shelf.held(&store, 0), Held::Dropped),
        "the log no longer holds the first block, and says which kind of \
         nothing that is"
    );
    assert!(matches!(shelf.held(&store, 1_499), Held::Block(_)));

    let mut index = Index::new();
    for _ in 0..5 {
        read_all(
            &mut index,
            |index| head_of(&store, index),
            |height| shelf.held(&store, height),
        );
    }

    assert_eq!(
        index.blocks_read(),
        1_400,
        "every block the node still holds, and not one fewer"
    );
    assert_eq!(index.covers(), Some((cut, 1_499)));
    assert!(
        !index.reads_from_the_start(),
        "and it says out loud that it does not go back to the first block"
    );
    assert_eq!(index.totals().blocks, 1_400);
    assert_eq!(
        index.holders(),
        1,
        "the address that mined this chain is on the page, not missing from it"
    );
    assert!(index
        .owner(&miner.public_key())
        .is_some_and(|record| record.balance() > cairn_primitives::Amount::ZERO));
}

/// The same, reached without a restart: a reorganisation resets the index, and
/// the walk that follows starts again from where the node's blocks start.
///
/// This is the shape that mattered. The index survived a trim while the
/// process ran, because it only ever asked for heights above what it already
/// had. A reorganisation threw that away, and the next walk asked for height
/// zero on a node that no longer held it, stopped there, and never recovered:
/// not on the next pass, not on the next twenty, not on a restart.
#[test]
fn a_reorganisation_on_a_trimmed_log_rebuilds_from_where_the_blocks_start() {
    let miner = wallet(1);
    let rival = wallet(9);

    let mut base = Forge::new(params());
    let common = base.mine_many(&miner, 1_400);
    let mut good = base.fork();
    let good_blocks = good.mine_many(&miner, 100);
    let mut bad = base.fork();
    let bad_blocks = bad.mine_many(&rival, 101);

    let mut store = ChainStore::archiving(params());
    feed(&mut store, &common);
    feed(&mut store, &good_blocks);

    // While the log still holds everything, the index is complete.
    let mut shelf = Shelf::of(&common);
    for block in &good_blocks {
        shelf.add(block);
    }
    let mut index = Index::new();
    read_all(
        &mut index,
        |index| head_of(&store, index),
        |height| shelf.held(&store, height),
    );
    assert_eq!(index.blocks_read(), 1_500);
    assert!(index.reads_from_the_start());
    let before = index
        .owner(&miner.public_key())
        .map(|record| record.balance())
        .unwrap();
    assert!(before > cairn_primitives::Amount::ZERO);

    // Upkeep trims the log to its budget. Nothing breaks: the index only ever
    // asks for heights above what it has.
    shelf.trim_to(100);
    read_all(
        &mut index,
        |index| head_of(&store, index),
        |height| shelf.held(&store, height),
    );
    assert_eq!(
        index.blocks_read(),
        1_500,
        "a trim on its own costs nothing"
    );

    // Then one reorganisation.
    for block in &bad_blocks {
        shelf.add(block);
    }
    feed(&mut store, &bad_blocks);
    assert_eq!(store.tip(), bad_blocks.last().map(Block::id));

    read_all(
        &mut index,
        |index| head_of(&store, index),
        |height| shelf.held(&store, height),
    );

    assert_eq!(
        index.blocks_read(),
        1_401,
        "the reorganisation reset the index, and the walk that followed \
         stepped over the hundred blocks this node had dropped rather than \
         stopping at the first of them"
    );
    assert_eq!(index.covers(), Some((100, 1_500)));
    assert!(!index.reads_from_the_start());
    // It held 1,500 rewards. It now holds the 1,300 it was paid in blocks
    // this node still has: the hundred under the cut are gone with the blocks,
    // and the hundred above the fork went with the branch. Both are real
    // subtractions and neither is the index giving up.
    let kept = cairn_primitives::Amount::from_pebbles(params().initial_reward.as_pebbles() * 1_300)
        .unwrap();
    assert_eq!(
        index.owner(&miner.public_key()).map(|r| r.balance()),
        Some(kept),
        "the address that held {before:?} is not empty, and what it lost is \
         exactly the blocks this node no longer has"
    );
    assert_eq!(index.holders(), 2);

    // And it stays there, however long the site runs.
    for _ in 0..20 {
        read_all(
            &mut index,
            |index| head_of(&store, index),
            |height| shelf.held(&store, height),
        );
    }
    assert_eq!(index.blocks_read(), 1_401);
}

/// A block packed with dust, shaped the way an attacker would shape it: as
/// many outputs to fresh addresses as `max_block_bytes` allows.
///
/// `spend` is the note the first transfer consumes, so the walk exercises
/// `Index::debit` as well as `Index::credit`. Every later transfer spends an
/// output of the one before it, which is what a real fan-out looks like.
fn dust_block(
    height: u64,
    miner: PublicKey,
    owners: &[PublicKey],
    params: &ConsensusParams,
) -> Block {
    let dust = cairn_primitives::Amount::from_pebbles(1).unwrap();
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, miner)]);
    let mut transfers: Vec<Transfer> = Vec::new();
    let mut bytes = 200 + coinbase.encode().len();
    let mut previous = cairn_ledger::note::NoteId::new(coinbase.id(), 0);
    let mut taken = 0usize;
    loop {
        let take = params.max_outputs_per_transfer.min(owners.len() - taken);
        if take == 0 {
            break;
        }
        let outputs: Vec<Note> = owners[taken..taken + take]
            .iter()
            .map(|owner| Note::new(dust, *owner))
            .collect();
        let transfer = Transfer::new(
            vec![cairn_ledger::transaction::Input::hot(previous)],
            outputs,
        );
        let size = transfer.encode().len();
        if bytes + size > params.max_block_bytes {
            break;
        }
        bytes += size;
        taken += take;
        previous = cairn_ledger::note::NoteId::new(transfer.id(), 0);
        transfers.push(transfer);
    }
    let mut block = Block {
        header: cairn_ledger::block::BlockHeader {
            version: 1,
            network: params.network,
            height,
            previous: cairn_primitives::Hash32::ZERO,
            transactions_root: cairn_primitives::Hash32::ZERO,
            state_root: cairn_primitives::Hash32::ZERO,
            history: cairn_primitives::Hash32::ZERO,
            timestamp: 1_000 + height,
            difficulty: 1,
            total_work: u128::from(height),
            nonce: height,
        },
        coinbase,
        transfers,
    };
    block.header.transactions_root = block.transactions_root();
    assert!(
        block.encode().len() <= params.max_block_bytes,
        "a block an attacker could actually get mined"
    );
    block
}

/// What one block of dust costs the explorer's index, in bytes and in seconds.
///
/// The blocks here are not offered to consensus: they are handed straight to
/// the walk, which is what a reorganisation or a restart does with them. Their
/// shape is one consensus would accept, which is what makes the cost real.
#[test]
fn what_a_block_of_dust_costs_the_index() {
    let params = params();
    let miner = wallet(1).public_key();

    // The chain only sets the height the walk runs to. The blocks the walk
    // reads are the dust ones.
    let mut forge = Forge::new(params.clone());
    let mut store = ChainStore::archiving(params.clone());
    let filler = forge.mine_many(&wallet(2), 40);
    feed(&mut store, &filler);

    let per_block = dust_block(0, miner, &fresh_owners(4_096), &params);
    let notes_per_block: usize = per_block
        .transfers
        .iter()
        .map(|transfer| transfer.outputs.len())
        .sum();
    println!(
        "one block at the byte ceiling: {} bytes, {} transfers, {} dust notes",
        per_block.encode().len(),
        per_block.transfers.len(),
        notes_per_block,
    );

    // What that block costs whoever mines it, under this node's own pool
    // policy. Consensus asks for nothing: a miner building its own block pays
    // none of this.
    let mut floor = 0u64;
    for transfer in &per_block.transfers {
        let weight = cairn_chain::transfer_weight(transfer, transfer.encode().len(), 1);
        floor = floor.saturating_add(cairn_chain::fee_floor(weight).as_pebbles());
    }
    println!(
        "the pool would ask {floor} pebbles for it ({:.4} CAIRN), which is {} pebbles a note; \
         a miner building the block itself pays nothing",
        floor as f64 / 100_000_000.0,
        floor / notes_per_block as u64,
    );

    // Owners are made first so their own memory is in the baseline.
    let owners = fresh_owners(notes_per_block);
    let blocks = 30usize;
    let baseline = rss_kb();

    let mut index = Index::new();
    let head = head_of(&store, &index).unwrap();
    let started = Instant::now();
    read_all(
        &mut index,
        |_| Some(head),
        |height| {
            if height < blocks as u64 {
                Held::Block(Box::new(dust_block(height, miner, &owners, &params)))
            } else {
                Held::Waiting
            }
        },
    );
    let took = started.elapsed();
    let grew = rss_kb().saturating_sub(baseline);

    let notes = index.totals().notes_created as usize;
    println!(
        "{blocks} blocks of dust: {notes} notes, indexed in {took:?} ({:?} a block), \
         resident set grew {grew} kB = {} bytes a note",
        took / blocks as u32,
        grew * 1024 / notes as u64,
    );
    println!(
        "at one block a minute that is {:.1} GB a year of index, for {:.1} CAIRN a year \
         at the pool's floor and nothing at all to a miner",
        (grew * 1024) as f64 / blocks as f64 * 525_600.0 / 1e9,
        floor as f64 / 1e8 * 525_600.0,
    );
    assert!(notes > 3_000 * blocks / 2, "the blocks really were packed");

    // What the index now says about itself, which is what `/api/status`
    // carries and what a page can put in front of whoever is paying for it.
    // None of this was written down anywhere before.
    let size = index.size();
    println!(
        "the index reports {} notes, {} transactions, {} owners, {} movements, \
         and {} MB at {} bytes a note",
        size.notes,
        size.transactions,
        size.owners,
        size.movements,
        size.bytes / 1_000_000,
        index::BYTES_PER_NOTE,
    );
    assert_eq!(size.notes, index.totals().notes_created);
    assert!(size.bytes > 0);
}

/// A block of transfers that each pay `fan_out` owners and spend the one
/// before them, cycling through the pool of owners as they go.
///
/// `dust_block` is this at its widest, where a transfer pays two hundred and
/// fifty six. The fan-out is a number here because what a note costs the index
/// is not decided by the note: the index also keeps an entry per transaction
/// and a movement per side of every note, and the narrower the transfers the
/// fewer notes those are spread over.
fn payment_block(
    height: u64,
    miner: PublicKey,
    owners: &[PublicKey],
    fan_out: usize,
    params: &ConsensusParams,
) -> Block {
    let dust = cairn_primitives::Amount::from_pebbles(1).unwrap();
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, miner)]);
    let mut transfers: Vec<Transfer> = Vec::new();
    let mut bytes = 200 + coinbase.encode().len();
    let mut previous = cairn_ledger::note::NoteId::new(coinbase.id(), 0);
    let mut at = 0usize;
    loop {
        let outputs: Vec<Note> = (0..fan_out)
            .map(|step| Note::new(dust, owners[(at + step) % owners.len()]))
            .collect();
        let transfer = Transfer::new(
            vec![cairn_ledger::transaction::Input::hot(previous)],
            outputs,
        );
        let size = transfer.encode().len();
        if bytes + size > params.max_block_bytes {
            break;
        }
        bytes += size;
        at += fan_out;
        previous = cairn_ledger::note::NoteId::new(transfer.id(), 0);
        transfers.push(transfer);
    }
    let mut block = Block {
        header: cairn_ledger::block::BlockHeader {
            version: 1,
            network: params.network,
            height,
            previous: cairn_primitives::Hash32::ZERO,
            transactions_root: cairn_primitives::Hash32::ZERO,
            state_root: cairn_primitives::Hash32::ZERO,
            history: cairn_primitives::Hash32::ZERO,
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

/// Weighs the index over thirty blocks of one shape, and says what one note
/// really cost against what [`index::BYTES_PER_NOTE`] says it costs.
///
/// Returns what the index came to hold, so the caller can hold the two ratios
/// that explain the reading: notes per transaction and movements per note.
/// Those are counted rather than measured, so they stand however busy the
/// machine is, and the bytes are printed for whoever is reading the run.
fn weigh_shape(label: &str, fan_out: usize) -> index::Size {
    let params = params();
    let miner = wallet(1).public_key();
    let owners = fresh_owners(3_072);
    let blocks = 30u64;
    let head = Head {
        tip: blocks,
        at_last_read: None,
    };

    let baseline = rss_kb();
    let mut index = Index::new();
    read_all(
        &mut index,
        |_| Some(head),
        |height| {
            if height < blocks {
                Held::Block(Box::new(payment_block(
                    height, miner, &owners, fan_out, &params,
                )))
            } else {
                Held::Waiting
            }
        },
    );
    let grew = rss_kb().saturating_sub(baseline);
    let size = index.size();
    println!(
        "{label}: {} notes, {} transactions, {} owners, {} movements, \
         {:.1} notes a transaction, {:.2} movements a note",
        size.notes,
        size.transactions,
        size.owners,
        size.movements,
        size.notes as f64 / size.transactions.max(1) as f64,
        size.movements as f64 / size.notes.max(1) as f64,
    );
    println!(
        "  the index says {} bytes a note; the resident set says {} bytes a note",
        index::BYTES_PER_NOTE,
        grew * 1024 / size.notes.max(1),
    );
    std::hint::black_box(&index);
    size
}

/// The ordinary payment: one note to the payee, one back as change.
///
/// The dearest shape there is per note, and what almost every transfer on any
/// chain actually is. It is where `BYTES_PER_NOTE` comes from, and it is why
/// the figure is 565 and not the five hundred the site used to state: five
/// hundred was calibrated on the widest fan-out alone, which is the cheapest
/// per note and which nobody sends.
///
/// A note is what the index counts, and a note is not the whole of what it
/// keeps: there is an entry per transaction and a movement per side of every
/// note as well, and this shape has the fewest notes to spread them over.
#[test]
fn what_an_ordinary_payment_costs_the_index() {
    let size = weigh_shape("2 outputs a transfer (payee and change)", 2);
    assert!(
        size.movements * 10 > size.notes * 14,
        "this shape spends nearly every note it makes, so it runs to about \
         three movements for every two notes"
    );
    assert!(
        size.notes < size.transactions * 3,
        "and to two notes a transaction"
    );
}

/// A small fan-out, as a miner paying a pool would send.
#[test]
fn what_a_small_fan_out_costs_the_index() {
    let size = weigh_shape("8 outputs a transfer", 8);
    assert!(size.notes > size.transactions * 6);
    assert!(size.movements < size.notes * 13 / 10);
}

/// The widest fan-out a transfer may have, which is the shape the five hundred
/// was calibrated on: 236 notes to a transaction and one movement a note, so
/// everything the index keeps besides the notes is spread thin.
#[test]
fn what_a_wide_fan_out_costs_the_index() {
    let size = weigh_shape("256 outputs a transfer", 256);
    assert!(
        size.notes > size.transactions * 100,
        "the transaction entries are spread over hundreds of notes each"
    );
    assert!(
        size.movements < size.notes * 11 / 10,
        "and one transfer spends one note however many it makes"
    );
}

/// The same bytes, sent to one address instead of many: what the movements
/// list costs, and what bounds it.
#[test]
fn what_a_single_address_can_be_made_to_carry() {
    let params = params();
    let miner = wallet(1).public_key();
    let victim = wallet(3).public_key();

    let mut forge = Forge::new(params.clone());
    let mut store = ChainStore::archiving(params.clone());
    let filler = forge.mine_many(&wallet(2), 40);
    feed(&mut store, &filler);

    let sample = dust_block(0, miner, &fresh_owners(4_096), &params);
    let per_block: usize = sample
        .transfers
        .iter()
        .map(|transfer| transfer.outputs.len())
        .sum();
    let owners = vec![victim; per_block];

    let blocks = 30usize;
    let baseline = rss_kb();
    let mut index = Index::new();
    let head = head_of(&store, &index).unwrap();
    let started = Instant::now();
    read_all(
        &mut index,
        |_| Some(head),
        |height| {
            if height < blocks as u64 {
                Held::Block(Box::new(dust_block(height, miner, &owners, &params)))
            } else {
                Held::Waiting
            }
        },
    );
    let took = started.elapsed();
    let grew = rss_kb().saturating_sub(baseline);

    let record = index.owner(&victim).unwrap();
    println!(
        "{blocks} blocks aimed at one address: {} notes and {} movements on it, \
         built in {took:?}, resident set grew {grew} kB",
        record.notes.len(),
        record.movements.len(),
    );
    println!(
        "that is {} notes and {} movements per block, on one address, with no ceiling \
         on either in `OwnerRecord`",
        record.notes.len() / blocks,
        record.movements.len() / blocks,
    );

    // What answering one page about that address then costs.
    let started = Instant::now();
    let mut seen = 0usize;
    for id in record.notes.iter().rev().take(10_000) {
        if index.note(id).is_some_and(|note| note.is_unspent()) {
            seen += 1;
        }
    }
    println!(
        "one /api/address request walks {seen} of them in {:?} with the chain lock held, \
         which `Explorer::answer` used to do twice and now does once",
        started.elapsed()
    );
}

/// What a block costs to get back off a disk, which is what every height below
/// the reorganisation window costs during a rebuild.
///
/// Modelled the way `BlockLog` does it: a record file and an offset table,
/// seek, read, decode. `Node::archived_at` takes the log lock and does this
/// with the chain lock already held by `Explorer::refresh`.
#[test]
fn what_a_block_costs_off_a_disk() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let params = params();
    let miner = wallet(1).public_key();
    let owners = fresh_owners(3_500);
    let blocks: Vec<Block> = (0..200)
        .map(|height| dust_block(height, miner, &owners, &params))
        .collect();

    let directory = std::env::temp_dir().join(format!("cairn-audit-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("blocks");
    let mut offsets = Vec::new();
    {
        let mut file = std::fs::File::create(&path).unwrap();
        let mut at = 0u64;
        for block in &blocks {
            let bytes = block.encode();
            offsets.push((at, bytes.len()));
            file.write_all(&bytes).unwrap();
            at += bytes.len() as u64;
        }
        file.sync_all().unwrap();
    }

    let mut file = std::fs::File::open(&path).unwrap();
    let mut buffer = vec![0u8; 200_000];
    // Read them out of order, which is what a cold cache looks like.
    let order: Vec<usize> = (0..blocks.len()).map(|i| (i * 97) % blocks.len()).collect();

    let started = Instant::now();
    let mut held = 0usize;
    for index in &order {
        let (at, len) = offsets[*index];
        file.seek(SeekFrom::Start(at)).unwrap();
        file.read_exact(&mut buffer[..len]).unwrap();
        held += buffer[0] as usize;
    }
    let reading = started.elapsed();

    let started = Instant::now();
    let mut read = 0usize;
    for index in &order {
        let (at, len) = offsets[*index];
        file.seek(SeekFrom::Start(at)).unwrap();
        file.read_exact(&mut buffer[..len]).unwrap();
        let block = Block::decode(&buffer[..len]).unwrap();
        read += block.transfers.len();
    }
    let took = started.elapsed();
    let count = blocks.len() as u32;
    println!(
        "a block at the byte ceiling ({} kB, 3072 notes): read {:?}, read and decode {:?} \
         ({read} transfers, {held} bytes touched)",
        offsets[0].1 / 1000,
        reading / count,
        took / count,
    );

    // And the same for a block with nothing in it, which is what a quiet chain
    // is made of.
    let empty: Vec<Vec<u8>> = (0..200)
        .map(|height| {
            let mut block = dust_block(height, miner, &[], &params);
            block.header.transactions_root = block.transactions_root();
            block.encode()
        })
        .collect();
    let started = Instant::now();
    let mut seen = 0u64;
    for bytes in &empty {
        seen += Block::decode(bytes).unwrap().header.height;
    }
    println!(
        "an empty block ({} bytes): decode {:?} (checked {seen})",
        empty[0].len(),
        started.elapsed() / empty.len() as u32,
    );
    std::fs::remove_dir_all(&directory).ok();

    println!(
        "so a rebuild of a chain of N blocks used to hold the chain lock for about \
         N x ({:?} read + 2.4ms index) once the blocks were past the reorganisation \
         window. The reads are still there; the lock is not held across them",
        took / blocks.len() as u32
    );
}

/// What one anonymous `/api/blocks?limit=128` costs, reproduced from the same
/// pieces the route uses.
///
/// `block_summary` re-encodes every block to report its size, and `block_fees`
/// looks up every input of every transfer in the index. Those two are the
/// whole of what a page of blocks spends, and `Explorer::answer` used to do
/// them twice: it ran the entire route once to find out which heights it
/// would need off the log, threw the answer away, fetched them, and ran the
/// entire route again. Its comment said the first pass cost one write of a
/// page that was going to be written anyway. It cost a full recomputation, so
/// one anonymous GET bought twice the chain lock a peer's own `GetBlocks`
/// does, and `GetBlocks` is deliberately answered outside that lock.
///
/// The first reading now skips both. What it is for is naming heights, and
/// it does that and nothing else. The route-level regression test is in
/// `answers.rs`, which drives the real thing; the figures here are what makes
/// the difference worth the flag.
#[test]
fn what_one_anonymous_page_of_blocks_costs() {
    let params = params();
    let miner = wallet(1).public_key();
    let owners = fresh_owners(3_500);

    let mut store = ChainStore::archiving(params.clone());
    let mut forge = Forge::new(params.clone());
    feed(&mut store, &forge.mine_many(&wallet(2), 200));

    let mut index = Index::new();
    let head = head_of(&store, &index).unwrap();
    read_all(
        &mut index,
        |_| Some(head),
        |height| {
            if height < 160 {
                Held::Block(Box::new(dust_block(height, miner, &owners, &params)))
            } else {
                Held::Waiting
            }
        },
    );

    let page: Vec<Block> = (0..128)
        .map(|height| dust_block(height, miner, &owners, &params))
        .collect();

    let started = Instant::now();
    let mut bytes = 0usize;
    let mut lookups = 0usize;
    for block in &page {
        // What `block_summary` does for `size`.
        bytes += block.encode().len();
        // What `block_fees` does for a block of hot spends.
        for transfer in &block.transfers {
            for input in &transfer.inputs {
                if index.note(&input.note_id).is_some() {
                    lookups += 1;
                }
            }
            let _ = transfer.total_output();
        }
    }
    let once = started.elapsed();
    println!(
        "one page of 128 blocks: {once:?}, {} MB re-encoded, {lookups} index lookups",
        bytes / 1_000_000
    );

    // The naming reading, which is what is left of the first pass: it asks
    // the chain for each height of the page, is told no, and writes the
    // height down for the fetch that follows.
    let above = store.height().unwrap_or(0).saturating_add(1);
    let started = Instant::now();
    let mut named: Vec<u64> = Vec::new();
    for step in 0..128u64 {
        let height = above.saturating_add(step);
        if store.block_at(height).is_none() {
            named.push(height);
        }
    }
    let naming = started.elapsed();
    let named = named.len();

    println!(
        "`Explorer::answer` used to run the whole route twice for any page below the \
         reorganisation window: {:?} of chain lock for one anonymous GET. It now runs \
         it once, after a naming reading that costs {naming:?} for the same {named} \
         heights: {:?}",
        once * 2,
        once + naming,
    );
    assert_eq!(named, 128);
}

/// Blocks that push notes into the cold set as fast as the rules allow, so the
/// archivist's exception can be weighed against the plain node's constant.
fn falling_chain(blocks: usize) -> (ConsensusParams, Vec<Block>) {
    let mut params = params();
    params.hot_capacity = 1_024;
    params.max_evictions_per_block = 1_024;
    params.max_coinbase_outputs = 256;

    let owners = fresh_owners(256);
    let share =
        cairn_primitives::Amount::from_pebbles(params.initial_reward.as_pebbles() / 256).unwrap();

    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut out = Vec::with_capacity(blocks);
    for _ in 0..blocks {
        let height = state.next_height().unwrap();
        clock += 600;
        let outputs: Vec<Note> = owners
            .iter()
            .map(|owner| Note::new(share, *owner))
            .collect();
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        out.push(block);
    }
    (params, out)
}

/// Blocks in the two cold-set measurements.
///
/// The figures quoted in the report were taken at 12,500 blocks, which is
/// 3,198,976 fallen notes: 72 bytes a fallen note for the archivist and 0 for
/// the plain node. That run takes about eight minutes a side. This is the
/// size at which the same shape is still legible in a minute.
const FALLING: usize = 5_000;

/// What an archivist's cold set costs, measured as a slope.
///
/// A single before-and-after reading of the resident set understates: memory
/// freed earlier in the process is handed back out rather than asked for
/// again. The slope between two readings taken well after that pool is gone
/// is what the chain actually costs per note.
fn cold_set_cost(archiving: bool) {
    let (params, blocks) = falling_chain(FALLING);
    let mut state = if archiving {
        LedgerState::archiving()
    } else {
        LedgerState::new()
    };
    let chunk = FALLING / 5;
    let mut marks: Vec<(u64, u64)> = Vec::new();
    let mut peak = rss_kb();
    let started = Instant::now();
    for (index, block) in blocks.iter().enumerate() {
        connect_block(&mut state, block, &params, NOW).unwrap();
        if (index + 1) % chunk == 0 {
            // The running peak, not the reading: this allocator hands pages
            // back to the operating system, so a plain reading of the resident
            // set falls as well as rises and its slope means nothing.
            peak = peak.max(rss_kb());
            marks.push((state.cold().len(), peak));
        }
    }
    let took = started.elapsed();
    let label = if archiving { "ARCHIVING" } else { "PLAIN    " };
    for (leaves, rss) in &marks {
        println!("{label} after {leaves:>8} fallen notes: resident set peaked at {rss} kB");
    }
    let (first_leaves, first_rss) = marks[1];
    let (last_leaves, last_rss) = marks[marks.len() - 1];
    let per_note = (last_rss.saturating_sub(first_rss) * 1024)
        .checked_div(last_leaves.saturating_sub(first_leaves))
        .unwrap_or(0);
    println!(
        "{label} slope from {first_leaves} to {last_leaves} fallen notes: \
         {} kB for {} notes = {per_note} bytes a fallen note (applied in {took:?})",
        last_rss.saturating_sub(first_rss),
        last_leaves - first_leaves,
    );
}

#[test]
fn the_archivists_exception() {
    cold_set_cost(true);
}

/// The claim the whole project rests on, and the shape of the exception the
/// explorer is: a plain node's memory does not move with the cold set, and an
/// archivist's does, for ever.

/// The same chain on a plain node, which keeps sixty four hashes for the same
/// set. The difference between the two slopes is the exception.
#[test]
fn the_plain_nodes_constant() {
    cold_set_cost(false);
}

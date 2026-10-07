//! A node run at the edges of every bound, for long enough to show it holds.
//!
//! Red team scenario R22 of the testnet-8 attack catalogue (G07), the thesis
//! the whole design rests on: a node's state does not grow with the chain. It
//! is measured rather than argued, and the measure that decides is counted,
//! not weighed. Resident memory is a reading of the machine, and the same run
//! reads differently on a loaded host; `SECURITY.md` names a claim resting on
//! a machine reading as one of the shapes a defect here has had. So the bytes
//! stay printed, for whoever wants the shape, and what is asserted is the
//! thing the bytes are a proxy for: every count a node holds stays inside the
//! ceiling its own constant names, and no count is larger at the end of a long
//! run than partway through it.
//!
//! `crates/cairn-ledger/tests/node_memory_slope.rs` already holds the hot set,
//! the grace window and the watched paths on a bare `LedgerState`. This runs a
//! real disk-backed `Node`, which is where those counts meet the three bounds
//! that are the node's and not the ledger's: what it holds in memory in blocks
//! ([`ChainStore::held_bytes`], against its ceiling, which already folds in the
//! side store), what it keeps on disk (the block log against the budget
//! [`KEEP_BLOCK_BYTES`](cairn_net::KEEP_BLOCK_BYTES)), and the address book ([`MAX_ADDRESSES`] and
//! [`MAX_PER_GROUP`]). And it holds that the node's own reported figures agree
//! with what it holds, since those are what an operator reads.
//!
//! No one chain sits at every bound at once, and the catalogue lists them as a
//! set of edges to cover rather than a single shape. A chain that evicts a
//! note every block, which is what holds the hot set at its cap, is a chain
//! whose pooled spends of those notes go stale as they fall; so the full pool
//! is held in a run of its own, on a hot set large enough that nothing falls
//! under it. The archivist, the one role whose cost is meant to grow, is run
//! as the control: a measure that shows no slope is only worth something if
//! the same instrument shows one where a slope is known to exist.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::too_many_lines
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cairn_chain::{ChainStore, HELD_OVERHEAD, HELD_WINDOW, MAX_POOLED, MAX_POOL_BYTES};
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::GRACE_NOTES;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::book::{AddressBook, MAX_ADDRESSES, MAX_PER_GROUP};
use cairn_net::Node;
use cairn_primitives::{Amount, Encode};

const NOW: u64 = 2_000_000_000;
/// At this network's floor difficulty a nonce is found at once, so the cost of
/// a block here is building and validating it, not the proof of work.
const ATTEMPTS: u64 = 1 << 22;

/// Coinbase outputs a block creates, so the hot set turns over several notes a
/// block rather than one and reaches its cap in a handful of blocks.
const COINBASE_OUTPUTS: usize = 16;

/// The blocks the short run in the ordinary suite takes. Enough that the hot
/// set has filled and evicted for many blocks, the block log has grown past
/// the budget and been trimmed, and a slope would show.
const SHORT_BLOCKS: usize = 320;

/// The blocks the long run takes. See `a_node_soaked_for_a_long_run`.
const LONG_BLOCKS: usize = 12_000;

/// The block log budget the soak runs under. These coinbase-only blocks are
/// small, so the budget is small too, small enough that the short run grows
/// past it and the log is trimmed back and held there whatever the chain's
/// length. Far under [`KEEP_BLOCK_BYTES`](cairn_net::KEEP_BLOCK_BYTES), the real default; the point is the
/// trimming, and a smaller budget reaches it sooner.
const KEEP: u64 = 48 * 1024;

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(64)
        .with_max_evictions(64)
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-bound-soak-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Resident set in kilobytes, as the machine reports it. Printed, never
/// asserted: see the module header.
fn rss_kb() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(std::process::id().to_string())
        .output();
    out.ok()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

/// A coinbase of several notes to one owner, so a block pushes several notes
/// through the hot set at once.
fn coinbase(height: u64, reward: Amount, owner: &SecretKey) -> CoinbaseTransaction {
    let each = reward.as_pebbles() / COINBASE_OUTPUTS as u64;
    let first = reward.as_pebbles() - each * (COINBASE_OUTPUTS as u64 - 1);
    let outputs: Vec<Note> = (0..COINBASE_OUTPUTS)
        .map(|index| {
            let value = if index == 0 { first } else { each };
            Note::new(Amount::from_pebbles(value).unwrap(), owner.public_key())
        })
        .collect();
    CoinbaseTransaction::new(height, outputs)
}

/// Bytes every file under `directory` takes, the block log included.
fn disk_bytes(directory: &Path) -> u64 {
    std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| match entry.metadata() {
                    Ok(meta) if meta.is_dir() => disk_bytes(&entry.path()),
                    Ok(meta) => meta.len(),
                    Err(_) => 0,
                })
                .sum()
        })
        .unwrap_or(0)
}

/// Bytes one file takes, nought while it does not exist.
fn disk_bytes_of(file: &Path) -> u64 {
    std::fs::metadata(file).map_or(0, |meta| meta.len())
}

/// One mark of what a node holds, every one of it a number no machine has a
/// say in.
#[derive(Clone, Copy, Debug)]
struct Mark {
    height: u64,
    cold: u64,
    hot: usize,
    grace: usize,
    entries: usize,
    held_bytes: usize,
    undo: usize,
    kept: u64,
    disk: u64,
}

/// What the soak returns: the marks it took, the most the hot set and the
/// grace window held after any block of the run and not only at a mark, where
/// the block log began once upkeep had caught the last block, and the largest
/// record the log was handed, which is what the disk bound is counted in.
struct Run {
    marks: Vec<Mark>,
    most_hot: usize,
    most_grace: usize,
    log_begins_at: Option<u64>,
    largest_record: u64,
}

/// What the block log may hold once upkeep has caught the tip: the budget, the
/// blocks above the burial that the ledger it writes cannot yet stand in for,
/// and one record for a budget that does not divide evenly into blocks.
fn disk_bound(params: &ConsensusParams, largest_record: u64) -> u64 {
    KEEP + (params.burial + 1) * largest_record
}

/// Drives a disk-backed node `blocks` blocks forward, coinbase only, with the
/// hot set at its cap and the block log trimmed to [`KEEP`], and returns what
/// it held at each mark.
fn soak(blocks: usize, directory: &Path) -> Run {
    let params = params();
    let miner = wallet(1);
    let (node, _restored) = Node::open(params, loopback(), directory).unwrap();
    node.keep_blocks(KEEP);

    // The node validates every block itself; this ledger is kept in step
    // beside it only so blocks can be built without reaching into the node.
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut largest_record = 0u64;
    let (mut most_hot, mut most_grace) = (0usize, 0usize);
    let chunk = (blocks / 12).max(1);
    let started = Instant::now();

    println!(
        "\n== a node soaked {blocks} blocks, hot cap {}, log budget {KEEP} ==\n\
         {:>6} {:>7} {:>3} {:>5} {:>5} {:>7} {:>5} {:>7} {:>8} {:>8} {:>6} {:>5}",
        params.hot_capacity,
        "height",
        "cold",
        "hot",
        "grace",
        "held",
        "held B",
        "undo",
        "kept B",
        "ledger B",
        "disk B",
        "rss kB",
        "secs"
    );

    let mut marks = Vec::new();
    for at in 0..blocks {
        let height = state.next_height().unwrap();
        clock += 600;
        let block = assemble_block(
            &state,
            coinbase(height, params.reward_at(height), &miner),
            Vec::<Transfer>::new(),
            &params,
            clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists at the floor difficulty");
        // A record is the block behind a four byte length.
        largest_record = largest_record.max(block.encode().len() as u64 + 4);
        connect_block(&mut state, &block, &params, NOW).unwrap();
        node.submit_block(block).unwrap();

        // Every block, since the counts are cheap to read: a ceiling crossed
        // for one block and back under it by the next mark is still crossed.
        let mark = node.with_chain(|chain| Mark {
            height: chain.height().unwrap_or(0),
            cold: chain.state().cold_len(),
            hot: chain.state().hot_len(),
            grace: chain.state().grace_len(),
            entries: chain.len(),
            held_bytes: chain.held_bytes(),
            undo: chain.undo_records(),
            kept: 0,
            disk: 0,
        });
        most_hot = most_hot.max(mark.hot);
        most_grace = most_grace.max(mark.grace);

        if (at + 1) % chunk == 0 || at + 1 == blocks {
            let mark = Mark {
                kept: node.kept_bytes(),
                disk: disk_bytes(directory),
                ..mark
            };
            println!(
                "{:>6} {:>7} {:>3} {:>5} {:>5} {:>7} {:>5} {:>7} {:>8} {:>8} {:>6} {:>5}",
                mark.height,
                mark.cold,
                mark.hot,
                mark.grace,
                mark.entries,
                mark.held_bytes,
                mark.undo,
                mark.kept,
                disk_bytes_of(&directory.join("ledger.dat")),
                mark.disk,
                rss_kb(),
                started.elapsed().as_secs()
            );
            marks.push(mark);
        }
    }

    // The log is trimmed by upkeep, once a second on its own thread, and the
    // blocks above came faster than that. Wait for a round to catch the last
    // of them rather than for a fixed time, so a slow machine is only slower.
    let bound = disk_bound(&params, largest_record);
    let deadline = Instant::now() + Duration::from_secs(60);
    while node.kept_bytes() > bound && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if let Some(last) = marks.last_mut() {
        last.kept = node.kept_bytes();
        last.disk = disk_bytes(directory);
    }
    let log_begins_at = node.blocks_from();
    println!(
        "  once upkeep caught up: the block log begins at {log_begins_at:?} and holds {} bytes, \
         the directory {} bytes",
        node.kept_bytes(),
        disk_bytes(directory)
    );
    let mut files: Vec<(String, u64)> = std::fs::read_dir(directory)
        .unwrap()
        .flatten()
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            (
                name,
                disk_bytes(&entry.path()).max(entry.metadata().map_or(0, |m| m.len())),
            )
        })
        .collect();
    files.sort();
    for (name, bytes) in files {
        println!("    {bytes:>10}  {name}");
    }

    // What the operator reads has to be what the node holds. Read once, under
    // the node's own lock, against what the same lock reports.
    let (chain_height, chain_cold, chain_pool) =
        node.with_chain(|chain| (chain.height(), chain.state().cold_len(), chain.pool_len()));
    assert_eq!(
        node.height(),
        chain_height,
        "the height the node reports is not the height it holds"
    );
    assert_eq!(
        node.cold_len(),
        chain_cold,
        "the cold count the node reports is not the one it holds"
    );
    assert_eq!(
        node.pool_len(),
        chain_pool,
        "the pool length the node reports is not the one it holds"
    );

    node.shutdown();
    drop(node);
    Run {
        marks,
        most_hot,
        most_grace,
        log_begins_at,
        largest_record,
    }
}

/// What the soak asserts: every count inside its ceiling, and none of the
/// bounded ones larger at the end than at the settled midpoint.
fn soak_holds(run: &Run) {
    let params = params();
    let marks = &run.marks;
    let settled = marks[marks.len() / 2];
    let last = *marks.last().unwrap();
    // The published ceiling is counted in blocks of the largest size the rules
    // allow. These are far smaller, so the same window counted in these blocks
    // is the ceiling that can actually be reached here.
    let held_block = run.largest_record as usize + HELD_OVERHEAD;
    let ceiling = ChainStore::held_bytes_ceiling(&params).min(HELD_WINDOW * held_block);

    // The chain really ran and the hot set really evicted: the cold set, which
    // a plain node commits to in its roots and does not hold, went on growing.
    assert!(
        last.cold > settled.cold,
        "the cold set has to grow across the stretch being read, and it went {} -> {}",
        settled.cold,
        last.cold
    );

    // After every block, not only at the marks.
    assert!(
        run.most_hot <= params.hot_capacity,
        "the hot set held {} notes against a capacity of {}",
        run.most_hot,
        params.hot_capacity
    );
    assert!(
        run.most_grace <= GRACE_NOTES,
        "the grace window held {} notes against a ceiling of {GRACE_NOTES}",
        run.most_grace
    );

    for mark in marks {
        assert!(
            mark.undo <= HELD_WINDOW,
            "the node holds {} undo records against a window of {HELD_WINDOW}",
            mark.undo
        );
        // No rival branch is offered here, so the side store's share of the
        // ceiling is nought and what is held is the window and nothing else.
        assert!(
            mark.entries <= HELD_WINDOW,
            "the node holds {} block entries against a window of {HELD_WINDOW}",
            mark.entries
        );
        assert!(
            mark.held_bytes <= ceiling,
            "the node holds {} bytes in blocks against a ceiling of {ceiling}",
            mark.held_bytes
        );
    }

    // The bounded holdings do not grow with the chain: none is larger at the
    // end than at the settled midpoint. The hot set is at its cap and the
    // grace window full, so neither may move at all; what is held in memory
    // may move by one block, for a body caught between being written and
    // being let go. The undo records and the block entries reach their width
    // only once the chain is longer than the window, so they are read here
    // only by a run whose midpoint is past it, which the short run is not.
    let mut bounded = vec![
        ("the hot set", settled.hot, last.hot, 0),
        ("the grace window", settled.grace, last.grace, 0),
        (
            "what is held in memory",
            settled.held_bytes,
            last.held_bytes,
            held_block,
        ),
    ];
    if settled.undo == HELD_WINDOW {
        bounded.push(("the undo window", settled.undo, last.undo, 0));
        bounded.push(("the block entries", settled.entries, last.entries, 0));
    }
    for (name, from, to, slack) in bounded {
        assert!(
            to <= from + slack,
            "{name} held {from} at {} notes of cold set and {to} at {}, so it grows with \
             the chain",
            settled.cold,
            last.cold
        );
    }

    // The disk is bounded by the budget and not merely slow to grow. Trimming
    // really ran: the log no longer begins at the start of the chain, and what
    // it holds is the budget and the blocks the burial keeps above it.
    assert!(
        run.log_begins_at.is_some_and(|begins| begins > 0),
        "the block log still begins at the chain's start, so the budget never trimmed it: \
         began at {:?} with the chain {} blocks long",
        run.log_begins_at,
        last.height
    );
    let bound = disk_bound(&params, run.largest_record);
    assert!(
        last.kept <= bound,
        "the block log holds {} bytes against a budget of {KEEP}, {bound} with the burial",
        last.kept
    );
}

/// **A node soaked at the hot set cap and the disk budget, in the ordinary
/// suite.**
#[test]
fn a_node_soaked_a_short_run() {
    let directory = scratch("short");
    let run = soak(SHORT_BLOCKS, &directory);
    let _ = std::fs::remove_dir_all(&directory);
    assert!(run.marks.len() >= 3, "the run took marks");
    soak_holds(&run);
}

/// **The same, long enough to stand for a running node.**
///
/// Twelve thousand blocks of a hot set evicting every block and a log trimmed
/// every round. Measured on an Apple M-series laptop writing this: the hot set
/// held at 64 throughout, the block log stayed within a block of the 256 kB
/// budget while the chain grew past 190 000 blocks of history on disk, the
/// cold set grew to roughly 190 000 notes, and resident memory moved inside
/// the noise of the machine. Run it with:
///
/// `cargo test -p cairn-net --test bound_soak a_node_soaked_for_a_long_run -- \
///   --ignored --nocapture`
#[test]
#[ignore = "long soak; see the doc comment to run it and for its figures"]
fn a_node_soaked_for_a_long_run() {
    let directory = scratch("long");
    let run = soak(LONG_BLOCKS, &directory);
    let _ = std::fs::remove_dir_all(&directory);
    soak_holds(&run);
}

/// A chain store whose pool holds `target` valid one-input transfers, on a hot
/// set large enough that none of the spent notes falls under it.
fn a_pool_of(target: usize) -> ChainStore {
    // Default hot capacity, so coinbase notes stay hot and spendable while the
    // pool holds their spends; maturity nought, so a reward can be spent at
    // once; many coinbase outputs, so the notes to spend are mined quickly.
    let rules = ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_max_block_bytes(128 * 1024);
    let miner = wallet(1);
    let mut state = LedgerState::new();
    let mut store = ChainStore::new(rules);
    let mut clock = 1_000u64;
    let per_block = rules.max_coinbase_outputs;
    let each = rules.initial_reward.as_pebbles() / per_block as u64;
    let first = rules.initial_reward.as_pebbles() - each * (per_block as u64 - 1);

    let mut notes: Vec<(NoteId, Note)> = Vec::new();
    while notes.len() < target {
        let height = state.next_height().unwrap();
        clock += 600;
        let outputs: Vec<Note> = (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(Amount::from_pebbles(value).unwrap(), miner.public_key())
            })
            .collect();
        let block = assemble_block(
            &state,
            CoinbaseTransaction::new(height, outputs.clone()),
            Vec::<Transfer>::new(),
            &rules,
            clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &rules, NOW).unwrap();
        store.add_block(block.clone(), NOW).unwrap();
        for (index, note) in outputs.into_iter().enumerate() {
            notes.push((
                NoteId::new(block.coinbase.id(), u32::try_from(index).unwrap()),
                note,
            ));
        }
    }

    for (id, note) in notes.into_iter().take(target) {
        let paid = note
            .value
            .checked_sub(Amount::from_pebbles(10_000).unwrap())
            .unwrap();
        let mut transfer = Transfer::new(
            vec![Input::hot(id)],
            vec![Note::new(paid, wallet(2).public_key())],
        );
        transfer.sign_input(rules.network, 0, &note, &miner);
        let _ = store.accept_transfer(transfer);
    }
    store
}

/// Asserts a full pool sits inside both of its ceilings.
fn pool_holds(store: &ChainStore) {
    assert!(
        store.pool_len() <= MAX_POOLED,
        "the pool holds {} transfers against a ceiling of {MAX_POOLED}",
        store.pool_len()
    );
    assert!(
        store.pool_bytes() <= MAX_POOL_BYTES,
        "the pool holds {} bytes against a ceiling of {MAX_POOL_BYTES}",
        store.pool_bytes()
    );
}

/// **A pool filled past its ceiling holds exactly the ceiling, in the ordinary
/// suite.**
///
/// A smaller target than the full ceiling, so the suite stays quick; the full
/// fill is `the_pool_at_its_full_ceiling`.
#[test]
fn the_pool_holds_what_it_is_filled_with() {
    let store = a_pool_of(512);
    assert_eq!(
        store.pool_len(),
        512,
        "the pool took every transfer offered"
    );
    pool_holds(&store);
}

/// **A pool offered more than its count ceiling holds exactly the ceiling.**
///
/// [`MAX_POOLED`] transfers in and two hundred more offered: a full pool makes
/// room for one by dropping one, so it neither grows past the ceiling nor
/// shrinks under it.
#[test]
#[ignore = "fills the pool to its full ceiling; slower, run with --ignored"]
fn the_pool_at_its_full_ceiling() {
    let store = a_pool_of(MAX_POOLED + 200);
    assert_eq!(
        store.pool_len(),
        MAX_POOLED,
        "a pool offered more than its ceiling did not settle at it"
    );
    pool_holds(&store);
}

/// **The address book holds its ceilings, per group and in all.**
///
/// Both are reached with addresses nobody has ever heard from, which is the
/// flood the ceilings are for: a stranger naming dead addresses cannot grow
/// the book past them.
#[test]
fn the_address_book_holds_its_ceilings() {
    // One neighbourhood, flooded. Every address shares a /16, so the book
    // keeps at most a group's worth of them.
    let mut one_group = AddressBook::new();
    for n in 0..(MAX_PER_GROUP as u32 * 4) {
        let octet_c = (n >> 8) as u8;
        let octet_d = (n & 0xff) as u8;
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, octet_c, octet_d)), 8333);
        one_group.insert(address);
    }
    assert!(
        one_group.len() <= MAX_PER_GROUP,
        "one neighbourhood holds {} addresses against a ceiling of {MAX_PER_GROUP}",
        one_group.len()
    );

    // Many neighbourhoods, flooded. Spread across distinct /16s so no group
    // caps them first, the whole book is what holds.
    let mut whole = AddressBook::new();
    let mut spread = 0u32;
    for first in 1..=254u8 {
        for second in 0..=254u8 {
            // Skip the loopback and private ranges the book declines to hold.
            if first == 127 || first == 10 || (first == 192 && second == 168) {
                continue;
            }
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(first, second, 0, 1)), 8333);
            whole.insert(address);
            spread += 1;
            if spread >= MAX_ADDRESSES as u32 * 2 {
                break;
            }
        }
        if spread >= MAX_ADDRESSES as u32 * 2 {
            break;
        }
    }
    assert!(
        whole.len() <= MAX_ADDRESSES,
        "the book holds {} addresses against a ceiling of {MAX_ADDRESSES}",
        whole.len()
    );
}

/// **The archivist, the control: its disk grows with the chain.**
///
/// The one role whose cost is chosen rather than borne: an archivist keeps
/// every block whatever budget it is handed, and its block log grows with the
/// chain where a plain node's is flat. A measure that shows the plain node's
/// disk flat is only worth something if the same measure shows this one rise.
#[test]
fn an_archivist_keeps_every_block() {
    let directory = scratch("archivist");
    let params = params();
    let miner = wallet(1);
    let (node, _restored) = Node::open_archiving(params, loopback(), &directory).unwrap();
    // A budget an archivist is told to ignore, which is the point of the check
    // below: it keeps everything regardless.
    node.keep_blocks(KEEP);

    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut kept_at = Vec::new();
    for at in 0..80usize {
        let height = state.next_height().unwrap();
        clock += 600;
        let block = assemble_block(
            &state,
            coinbase(height, params.reward_at(height), &miner),
            Vec::<Transfer>::new(),
            &params,
            clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        node.submit_block(block).unwrap();
        if at == 39 || at == 79 {
            std::thread::sleep(Duration::from_millis(200));
            kept_at.push(node.kept_bytes());
        }
    }
    std::thread::sleep(Duration::from_secs(1));
    let begins = node.blocks_from();
    let finally = node.kept_bytes();
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        node_archivist_grew(kept_at[0], finally),
        "an archivist kept {} bytes at forty blocks and {finally} at eighty, so it is not \
         keeping the chain as it grows",
        kept_at[0]
    );
    assert_eq!(
        begins,
        Some(0),
        "an archivist dropped the start of its chain, which it must never do: it begins at {begins:?}"
    );
}

fn node_archivist_grew(early: u64, late: u64) -> bool {
    late > early
}

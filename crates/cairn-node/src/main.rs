//! A Cairn node.

mod mining;
mod options;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_net::node::Probation;
use cairn_net::{Joined, Node};

const TICK: Duration = Duration::from_millis(100);

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Err(message) = run(&arguments) {
        eprintln!("cairnd: {message}");
        eprintln!();
        eprintln!("{}", options::HELP);
        std::process::exit(2);
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
    let Some(options) = options::resolve_options(arguments)? else {
        println!("{}", options::HELP);
        return Ok(());
    };

    println!("cairnd {}", env!("CARGO_PKG_VERSION"));
    print!("{}", options::describe(&options));

    let started = if options.archive {
        Node::open_archiving
    } else {
        Node::open
    };
    let (node, restored) = started(options.params, options.listen, &options.data)
        .map_err(|error| format!("could not start: {error}"))?;
    node.keep_blocks(options.keep);
    let node = Arc::new(node);

    println!("listening    {}", node.address());
    println!(
        "restored     {} blocks, {} addresses",
        restored.blocks, restored.addresses
    );
    if restored.rejoining {
        println!(
            "             the stored blocks start partway up the chain, so this \
             node joins again rather than reading its way back"
        );
    }
    if restored.refused > 0 {
        println!(
            "             {} stored blocks were set aside; they will be asked for again",
            restored.refused
        );
    }
    if restored.discarded_bytes > 0 {
        println!(
            "             {} bytes of an unfinished write were dropped",
            restored.discarded_bytes
        );
    }
    // A node that was handed a ledger owes the network its own check of the
    // blocks above it, and until it has done that it is not a node on a chain,
    // it is a node holding somebody's account of one. Said here rather than
    // only in the status line, because this is the moment an operator finds
    // out what they are starting.
    if let Some(probation) = node.probation() {
        println!("probation    {probation}");
        println!(
            "             it does not mine, does not take transfers, and does not \
             answer as a node on a chain until it has"
        );
    }
    println!();

    // The names, not just what they resolved to: a node that could not look
    // anything up at this moment asks again while it runs, rather than sitting
    // with nothing to dial for as long as it is up.
    node.start_from_names(options.seed_names.clone());

    for seed in &options.seeds {
        // Written down before it is dialled, so a seed that is down right now
        // is tried again later rather than never known at all.
        node.remember_seed(*seed);
        match node.connect(*seed) {
            Ok(()) => println!("reached      {seed}"),
            Err(error) => println!("unreachable  {seed} ({error}), will keep trying"),
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let miner = options.mine_to.map(|key| {
        let node = Arc::clone(&node);
        let running = Arc::clone(&running);
        let params = options.params;
        let started = Instant::now();
        thread::spawn(move || {
            // A node on probation would have every block it made refused, and
            // would spend every core it has finding them. Waiting here is the
            // same rule stated where it costs nothing: what the node will not
            // do is settled by `submit_block`, and this only keeps the machine
            // from doing it pointlessly.
            let mut said = false;
            while running.load(Ordering::SeqCst) && node.probation().is_some() {
                if !said {
                    said = true;
                    println!(
                        "[{:>8}] mining waits until this node has checked the blocks \
                         above the ledger it was handed",
                        stamp(started),
                    );
                }
                thread::sleep(TICK);
            }
            if !running.load(Ordering::SeqCst) {
                return;
            }
            mining::run(&node, &params, key, &running, |block| {
                println!(
                    "[{:>8}] mined  height {:<6} difficulty {:<10} {}",
                    stamp(started),
                    block.header.height,
                    block.header.difficulty,
                    short(&block.id().to_string()),
                );
            });
        })
    });

    watch(&node, &options, &running);

    running.store(false, Ordering::SeqCst);
    node.shutdown();
    if let Some(miner) = miner {
        let _ = miner.join();
    }
    println!("stopped");
    Ok(())
}

/// Prints where the node stands, until it is asked to stop.
///
/// Everything worth keeping is written as it happens, so a node killed at any
/// moment loses nothing but the blocks it was in the middle of receiving.
fn watch(node: &Node, options: &options::Options, running: &AtomicBool) {
    let started = Instant::now();
    let status = Duration::from_secs(options.status_period.max(1));
    let limit = options.run_for.map(Duration::from_secs);
    let mut next = Duration::ZERO;

    while running.load(Ordering::SeqCst) {
        // A rule took effect at a height this build has no rules for. Going on
        // would mean refusing every peer that had updated and following
        // whoever had not, so the node says which version it needs and stops.
        if let Some(outdated) = node.outdated() {
            println!(
                "[{:>8}] stopping: the rules at height {} are block version {}, and this \
                 build knows only version {}. Update and start again; the chain on disk \
                 is kept and nothing is lost.",
                stamp(started),
                outdated.height,
                outdated.required,
                outdated.known,
            );
            return;
        }
        // A ledger this node was handed, and blocks above it that nobody will
        // deliver. It cannot get back below where it was handed on, so there
        // is nothing to wait for and nothing it can do about it; the cure is
        // the operator's.
        if let Some(stranded) = node.stranded() {
            println!(
                "[{:>8}] stopping: this node was handed a ledger at height {}, and had to check its \
                 way to height {} before it could stand behind it. It waited {} seconds with \
                 peers to ask and not one of the blocks in between arrived{}. It holds \
                 nothing below the ledger, so no chain forking under it can be followed from \
                 here. Delete the data directory and start again, from a seed you trust.",
                stamp(started),
                stranded.anchor,
                stranded.settles_at,
                stranded.waited,
                if stranded.out_of_reach > 0 {
                    format!(
                        ", while {} blocks arrived from a chain it cannot reach",
                        stranded.out_of_reach
                    )
                } else {
                    String::new()
                },
            );
            return;
        }
        if let Some(limit) = limit {
            if started.elapsed() >= limit {
                return;
            }
        }
        if started.elapsed() >= next {
            next = next.saturating_add(status);
            let height = node
                .height()
                .map_or_else(|| "-".to_owned(), |height| height.to_string());
            println!(
                "[{:>8}] height {height:<6} peers {:<4} known {:<5} cold {:<8} work {}",
                stamp(started),
                node.peer_count(),
                node.known_addresses().len(),
                node.cold_len(),
                node.total_work(),
            );
            // A node being handed a ledger has no height to show until the
            // whole of it has arrived, so without this it reads as stuck.
            match node.joining() {
                Joined::No | Joined::Done => {}
                joining => println!("           joining  {joining}"),
            }
            // And once it has arrived, the height it shows is the anchor's
            // rather than this node's, which without this reads as a healthy
            // node. It is not one until the line below stops appearing.
            if let Some(probation) = node.probation() {
                println!(
                    "           {}",
                    probation_line(&probation, node.out_of_reach())
                );
            }
        }
        thread::sleep(TICK);
    }
}

/// The status line for a node that has not yet stood behind the ledger it was
/// handed.
///
/// Blocks arriving from a chain this node cannot reach are named alongside,
/// because that combination, a height that does not move and blocks it can do
/// nothing with, is what being on the wrong chain looks like from the outside.
fn probation_line(probation: &Probation, out_of_reach: u64) -> String {
    if out_of_reach == 0 {
        return format!("probation {probation}");
    }
    format!("probation {probation}, and {out_of_reach} blocks arrived from a chain it cannot reach")
}

fn stamp(since: Instant) -> String {
    let seconds = since.elapsed().as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3_600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

fn short(text: &str) -> &str {
    text.get(..12).unwrap_or(text)
}

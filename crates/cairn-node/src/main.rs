//! A Cairn node.

mod mining;
mod options;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

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
    println!();

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
        }
        thread::sleep(TICK);
    }
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

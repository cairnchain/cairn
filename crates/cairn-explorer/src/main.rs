//! A Cairn node that also serves a website.
//!
//! It follows the chain like any other node, keeps the cold set the way an
//! archivist does, and builds an index on top so a page can ask who owns what.
//! That index is a cost which grows with the chain. It is here, in a program
//! nobody has to run, precisely so it is not there, in the program everybody
//! does.

mod api;
mod assets;
mod index;
mod options;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cairn_net::Node;

use crate::api::Explorer;

/// How often the index reads what the chain has added.
///
/// Fast enough that a block appears on the page about when it appears on the
/// network, slow enough that a busy page cannot make the node wait on it.
const REFRESH: Duration = Duration::from_millis(500);

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Err(message) = run(&arguments) {
        eprintln!("cairn-explorer: {message}");
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

    println!("cairn-explorer {}", env!("CARGO_PKG_VERSION"));
    println!(
        "network      {} (0x{:08x})",
        options.params.network_name(),
        options.params.network.as_u32()
    );
    match options.params.genesis {
        Some(genesis) => println!("starts from  {genesis}"),
        None => println!("starts from  nothing pinned"),
    }

    // Everything above is a question about the settings, and everything below
    // starts a node. A script updating a machine needs the first without the
    // second: a retired test network leaves its name in a unit file, and an
    // explorer that will not start is a worse answer than a script that saw
    // the refusal and asked for the current name instead.
    if arguments.iter().any(|argument| argument == "--check") {
        return Ok(());
    }

    let (node, restored) = Node::open_archiving(options.params, options.listen, &options.data)
        .map_err(|error| format!("could not start: {error}"))?;
    // Before anything else this node does. A node's own budget is a gigabyte
    // and it drops the oldest blocks past it, which for an explorer is the
    // blocks it needs most: the index is built by walking from the first block
    // up, so a trimmed log costs it not the blocks that were trimmed but every
    // block there is.
    node.keep_blocks(options.keep);
    println!("listening    {}", node.address());
    println!("blocks       {} kept on disk", options::size(options.keep));
    println!(
        "restored     {} blocks, {} addresses",
        restored.blocks, restored.addresses
    );

    // The names, not just what they resolved to, so a machine that could not
    // look anything up at this moment asks again while it runs.
    node.start_from_names(options.seed_names.clone());

    for seed in &options.seeds {
        node.remember_seed(*seed);
        match node.connect(*seed) {
            Ok(()) => println!("reached      {seed}"),
            Err(error) => println!("unreachable  {seed} ({error}), will keep trying"),
        }
    }

    let listener =
        cairn_http::bind(options.http).map_err(|error| format!("could not serve HTTP: {error}"))?;
    let served = listener
        .local_addr()
        .map_err(|error| format!("could not read the HTTP address: {error}"))?;

    let explorer = Arc::new(Explorer::new(node));
    let running = Arc::new(AtomicBool::new(true));

    let indexer = {
        let explorer = Arc::clone(&explorer);
        let running = Arc::clone(&running);
        thread::Builder::new()
            .name("explorer-index".to_owned())
            .spawn(move || {
                while running.load(Ordering::SeqCst) {
                    explorer.refresh();
                    thread::sleep(REFRESH);
                }
            })
            .map_err(|error| format!("could not start the indexer: {error}"))?
    };

    // The door opens now, and not after the first pass over the chain. It used
    // to wait for it: on a chain of any size that is minutes of a bound socket
    // with nobody answering, so a visitor got a page that hung rather than one
    // that said what was going on. The site can say "still reading the chain",
    // and it does, which is better than saying nothing slowly.

    let languages: Vec<&str> = assets::LOCALES.iter().map(|(code, _, _)| *code).collect();
    println!("languages    {}", languages.join(", "));
    println!();
    println!("open         http://{served}/");
    println!();

    let answering = Arc::clone(&explorer);
    cairn_http::serve(&listener, &running, move |request| {
        answering
            .answer(request)
            .unwrap_or_else(|| assets::answer(request))
    });

    running.store(false, Ordering::SeqCst);
    explorer.node().shutdown();
    let _ = indexer.join();
    println!("stopped");
    Ok(())
}

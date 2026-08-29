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

    let (node, restored) = Node::open_archiving(options.params, options.listen, &options.data)
        .map_err(|error| format!("could not start: {error}"))?;
    println!("listening    {}", node.address());
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

    // First pass before the door opens, so the page is not empty for the first
    // half second after a restart.
    explorer.refresh();

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

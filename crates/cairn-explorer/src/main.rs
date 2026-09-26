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
mod said;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cairn_net::{Node, NodeError};

use crate::api::Explorer;

/// How often the index reads what the chain has added.
///
/// Fast enough that a block appears on the page about when it appears on the
/// network, slow enough that a busy page cannot make the node wait on it.
const REFRESH: Duration = Duration::from_millis(500);

/// How often the explorer asks its node whether it has stopped itself, which
/// is how often `cairnd` asks.
const TICK: Duration = Duration::from_millis(100);

/// Why this program is stopping, when it did not get as far as serving.
///
/// Two things, and they were one. A command line this program cannot read is
/// the operator's to fix, and the usage text is what fixes it. A start that
/// failed had a command line that was right: the directory is held by
/// another explorer, the port is taken, the disk will not have it. The usage
/// text at somebody in that position sends them looking for a mistake that is
/// not there, and one exit code for both left whatever started this program
/// unable to tell them apart. `cairnd` made this distinction first; this is
/// its `Stopping`, for the same reasons.
#[derive(Debug)]
enum Stopping {
    /// The command line, which the usage text is the answer to. Exits two.
    Misread(String),
    /// Everything after it, where the message is the whole answer. Exits one.
    CouldNotStart(String),
}

impl std::fmt::Display for Stopping {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Misread(message) | Self::CouldNotStart(message) => formatter.write_str(message),
        }
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Err(message) = run(&arguments) {
        eprintln!("cairn-explorer: {message}");
        if let Stopping::Misread(_) = message {
            eprintln!();
            eprintln!("{}", options::HELP);
            std::process::exit(2);
        }
        std::process::exit(1);
    }
}

/// Waits for the node to stop itself and says why, or for this program to be
/// asked to stop.
///
/// `stopped` is the node's own account, asked every [`TICK`]. The node stops
/// itself in three states and ends every loop it runs, and the explorer went
/// on serving what it had for as long as the process lived: a frozen chain,
/// nothing in the journal, and a `Restart=always` that never fired because
/// the process never ended.
fn watch(stopped: impl Fn() -> Option<String>, running: &AtomicBool) -> Option<String> {
    loop {
        if let Some(fault) = stopped() {
            return Some(fault);
        }
        if !running.load(Ordering::SeqCst) {
            return None;
        }
        thread::sleep(TICK);
    }
}

/// What the open found on the disk, and the three things `cairnd` says before
/// it has answered anybody.
///
/// Every way the disk was short when it opened, and not two of them. The
/// explorer is the archivist `cairnd`'s paragraph about a set-aside log speaks
/// to, and it was the one program that never printed it.
fn say_what_the_start_found(
    node: &Node,
    restored: &cairn_net::Restored,
    params: &cairn_ledger::validation::ConsensusParams,
    directory: &str,
) {
    for line in said::what_was_restored(restored, directory) {
        println!("{line}");
    }
    if let Some(unread) = node.unread() {
        for line in said::wrapped(&said::will_not_read_back(&unread, directory)) {
            println!("             {line}");
        }
    }
    if let Some(probation) = node.probation() {
        println!("probation    {probation}");
        println!("             every page on the site says so until it has");
    }
    if let Some(ahead) = said::rules_running_out(params, node.height()) {
        for line in said::wrapped(&ahead) {
            println!("             {line}");
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(arguments: &[String]) -> Result<(), Stopping> {
    let Some(options) = options::resolve_options(arguments).map_err(Stopping::Misread)? else {
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
    //
    // Read from the settings rather than by looking through the words the
    // operator typed. Looking through them found `--check` wherever it stood,
    // including where it stood as the value of something else, so
    // `--data --check` printed the settings and stopped without ever starting
    // the site, and the operator who meant to name a directory got an exit
    // code of nought for it.
    if options.check {
        return Ok(());
    }

    let (node, restored) = Node::open_archiving(options.params, options.listen, &options.data)
        .map_err(|error| Stopping::CouldNotStart(format!("could not start: {error}")))?;
    // Before anything else this node does. A node's own budget is a gigabyte
    // and it drops the oldest blocks past it, which for an explorer is the
    // blocks it needs most: the index is built by walking from the first block
    // up, so a trimmed log costs it not the blocks that were trimmed but every
    // block there is.
    node.keep_blocks(options.keep);
    println!("listening    {}", node.address());
    println!(
        "blocks       {}",
        options::kept(options.keep, &options.params)
    );
    let directory = options.data.display().to_string();
    say_what_the_start_found(&node, &restored, &options.params, &directory);

    // The names, not just what they resolved to, so a machine that could not
    // look anything up at this moment asks again while it runs.
    node.start_from_names(options.seed_names.clone());

    for seed in &options.seeds {
        node.remember_seed(*seed);
        // Three lines and not two. A dial that completes and a peer this node
        // holds are different things, and `connect` used to answer `Ok(())`
        // for both: a seed turned away for want of room was printed as
        // `reached`, and the operator counted it.
        match node.connect(*seed) {
            Ok(()) => println!("reached      {seed}"),
            Err(NodeError::NotKept { because, .. }) => {
                println!("not kept     {seed} ({because}), will keep trying");
            }
            Err(error) => println!("unreachable  {seed} ({error}), will keep trying"),
        }
    }

    let listener = cairn_http::bind(options.http)
        .map_err(|error| Stopping::CouldNotStart(format!("could not serve HTTP: {error}")))?;
    let served = listener.local_addr().map_err(|error| {
        Stopping::CouldNotStart(format!("could not read the HTTP address: {error}"))
    })?;

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
            .map_err(|error| {
                Stopping::CouldNotStart(format!("could not start the indexer: {error}"))
            })?
    };

    // The node's own verdict on itself, read for the process and not only
    // written into `/api/status`. When the node stops itself this program says
    // why and ends on a code of one, which is what the unit reads. The server
    // below looks at its flag only when somebody connects, so it is not asked
    // to stop, it is stopped.
    //
    // Written here rather than in a function of its own, because nothing in
    // the suite can put a running node in any of those three states: the
    // decision is `watch`, which is held, and what is left is the glue.
    {
        let explorer = Arc::clone(&explorer);
        let running = Arc::clone(&running);
        thread::Builder::new()
            .name("explorer-watch".to_owned())
            .spawn(move || {
                let node = explorer.node();
                let fault = watch(
                    || {
                        said::stopped_itself(
                            node.outdated(),
                            node.stranded(),
                            node.unwritten(),
                            &directory,
                        )
                    },
                    &running,
                );
                if let Some(fault) = fault {
                    println!("stopping: {fault}");
                    running.store(false, Ordering::SeqCst);
                    node.shutdown();
                    println!("stopped on the fault above");
                    std::process::exit(1);
                }
            })
            .map_err(|error| {
                Stopping::CouldNotStart(format!("could not start the watch: {error}"))
            })?;
    }

    // The door opens now, and not after the first pass over the chain. It used
    // to wait for it: on a chain of any size that is minutes of a bound socket
    // with nobody answering, so a visitor got a page that hung rather than one
    // that said what was going on. The site can say "still reading the chain",
    // and it does.
    //
    // It could not, for a while, and the door being open was the whole of what
    // had been fixed. The indexer above holds the index while it reads and
    // every route wants the index, so opening early bought a socket that
    // accepted connections and then answered nobody until the first pass was
    // over. The walk now stops every so often and lets go, which is what makes
    // the sentence above true rather than intended.

    let languages: Vec<&str> = assets::LOCALES.iter().map(|(code, _, _)| *code).collect();
    println!("languages    {}", languages.join(", "));
    println!();
    println!("open         http://{served}/");
    println!();

    // Without bodies: no route here takes one, and a POST whose body never
    // came held a slot for the whole deadline behind the proxy, where every
    // reader shares the loopback address the per-address ceiling skips.
    let answering = Arc::clone(&explorer);
    cairn_http::serve_without_bodies(&listener, &running, move |request| {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::watch;

    /// The explorer stops when its node stops itself, and says why.
    ///
    /// It read its node's three fatal states only to write them into
    /// `/api/status`, and nothing read them for the process: an explorer whose
    /// disk had filled went on serving a frozen chain for as long as it ran,
    /// and nothing looked for them to fail on.
    #[test]
    fn the_explorer_stops_when_its_node_stops_itself() {
        let running = AtomicBool::new(true);
        let asked = std::cell::Cell::new(0u32);
        let said = watch(
            || {
                asked.set(asked.get().saturating_add(1));
                (asked.get() > 2).then(|| "the disk under here stopped".to_owned())
            },
            &running,
        );
        assert_eq!(
            said.as_deref(),
            Some("the disk under here stopped"),
            "a node that stopped itself is not noticed"
        );
        assert_eq!(asked.get(), 3, "it is asked again until it says so");

        let running = AtomicBool::new(false);
        assert_eq!(
            watch(|| None, &running),
            None,
            "an explorer asked to stop is stopped as asked, with no fault to say"
        );
        let running = AtomicBool::new(false);
        assert!(
            watch(|| Some("stopped".to_owned()), &running).is_some(),
            "a fault is said even when the explorer was already stopping"
        );
    }
}

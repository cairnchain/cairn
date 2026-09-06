//! A Cairn node.

mod mining;
mod options;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_net::node::{Probation, Unjudged, Unread, Unweighable, Unwritten, MAX_BEHIND};
use cairn_net::{Filling, Joined, Node, Restored};

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

    // Everything above is a question about the settings, and everything below
    // starts a node. A script updating a machine needs the first without the
    // second: a test network that has been retired leaves its name written in
    // a unit file, and a node that will not start is a worse answer than a
    // script that saw the refusal and asked for the current name instead.
    if arguments.iter().any(|argument| argument == "--check") {
        return Ok(());
    }

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
    say_what_was_restored(&restored, &options.data.display().to_string());
    // Before the node has answered anybody, because filling the headers in
    // from the blocks is the first thing that reads them back, and a refusal
    // there used to come out of the open as a failure to start.
    if let Some(unread) = node.unread() {
        for line in wrapped(&will_not_read_back(
            &unread,
            &options.data.display().to_string(),
        )) {
            println!("             {line}");
        }
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
    // Named once. Every line below that has anything to say about the disk
    // has to say which disk, because a machine running three of these has
    // three of them.
    let directory = options.data.display().to_string();
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
        // The disk stopped taking what this node writes, and it has now
        // accepted more blocks than it could ever write down. Nothing an
        // operator does from here puts those blocks on the disk, so what is
        // left to protect is the directory itself: every block accepted past
        // this point is one more the disk does not have, and one more the next
        // start has to fetch again.
        if let Some(unwritten) = node.unwritten().filter(|held| !held.within_reach) {
            println!(
                "[{:>8}] stopping: {}",
                stamp(started),
                lost_the_disk(&unwritten, &directory),
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
            // The disk beside the chain, because they are two different
            // numbers and only one of them survives a restart. On a healthy
            // node they are the same and this costs a column.
            let stored = node
                .written_through()
                .map_or_else(|| "-".to_owned(), |height| height.to_string());
            println!(
                "[{:>8}] height {height:<6} stored {stored:<6} peers {:<4} known {:<5} \
                 cold {:<8} work {}",
                stamp(started),
                node.peer_count(),
                node.known_addresses().len(),
                node.cold_len(),
                node.total_work(),
            );
            say_what_the_numbers_do_not(node, &directory);
        }
        thread::sleep(TICK);
    }
}

/// The lines under a status line, for every state a healthy node's numbers
/// look exactly like.
///
/// Each of these is a node that climbs in height, keeps its peers and prints
/// the line a working node prints, while something it is failing at goes
/// unmentioned. That is why they are lines and not a flag: an operator reads
/// prose, and every one of these needs a sentence to be understood at all.
fn say_what_the_numbers_do_not(node: &Node, directory: &str) {
    let say = |text: &str| {
        for line in wrapped(text) {
            println!("           {line}");
        }
    };
    // A node whose disk has stopped taking writes shows nothing else: it
    // validates, it climbs, and every other line here is the line a healthy
    // node prints.
    if let Some(unwritten) = node.unwritten() {
        say(&falling_behind(&unwritten, directory));
    }
    // A disk that will not give back a record it holds. Beside the line above
    // rather than instead of it: a node can be keeping everything it writes
    // and still be unable to read part of what it wrote earlier, and those are
    // two different afternoons.
    if let Some(unread) = node.unread() {
        say(&will_not_read_back(&unread, directory));
    }
    // And a node the network has left behind shows nothing but a height that
    // has stopped moving.
    if let Some(unjudged) = node.unjudged() {
        say(&too_old(&unjudged));
    }
    // And a node with no chain that nobody can show one to. Every showing it
    // is offered fails, it falls back to reading block by block, and what an
    // operator saw was a node taking hours with peers it kept dropping.
    if let Some(unweighable) = node.unweighable() {
        say(&cannot_weigh(&unweighable));
    }
    // A node being handed a ledger has no height to show until the whole of it
    // has arrived, so without this it reads as stuck.
    match node.joining() {
        Joined::No | Joined::Done => {}
        joining => println!("           joining  {joining}"),
    }
    // And once it has arrived, the height it shows is the anchor's rather than
    // this node's, which without this reads as a healthy node. It is not one
    // until the line below stops appearing.
    if let Some(probation) = node.probation() {
        println!(
            "           {}",
            probation_line(&probation, node.out_of_reach())
        );
    }
    // And a node that has arrived and still cannot answer the question a
    // newcomer asks. Every other state above has had a line here for longer
    // than this one, which is the first stretch of every join and used to be
    // the whole of one. It is also the only line that says the disk is not
    // being held to what `--keep` asked for.
    if let Some(filling) = node.filling() {
        say(&still_filling(&filling, directory));
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

/// What the disk held when this node opened it.
///
/// The moment an operator finds out what they are starting, which is why the
/// two ways a stored log can be short are told apart here rather than added
/// together into a byte count.
fn say_what_was_restored(restored: &Restored, directory: &str) {
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
    if restored.left_in_place > 0 {
        println!(
            "             {} bytes past it are still on the disk, unread",
            restored.left_in_place
        );
    }
    // Told apart from the line above, because they mean opposite things. Bytes
    // at the end of the file are a machine that stopped mid write, and they
    // cost one block. A whole record that will not read is damage, and it is
    // left exactly where it is: nothing here is confident enough about what
    // those bytes are to delete them.
    // Before the block log's version of the same news, because this one costs
    // more: a block set aside is asked for again in seconds, and headers the
    // blocks cannot replace are only ever given back by a peer that kept them.
    if restored.headers_set_aside > 0 {
        for line in wrapped(&format!(
            "{} stored headers were set aside because the first of them could not be \
             checked against the one after it. Nothing was deleted and the bytes are \
             still on the disk to look at. This node writes the headers again from the \
             blocks it kept and asks the network for the rest, and until it has them it \
             cannot show the chain to anybody arriving new. If this happens again after \
             a clean restart, the disk under {directory} is the thing to check.",
            restored.headers_set_aside
        )) {
            println!("             {line}");
        }
    }
    if let Some(record) = restored.unreadable {
        for line in wrapped(&format!(
            "stored block {record} will not read back. That is damage to the file rather \
             than an unfinished write, so nothing was cut for it and the bytes are still on \
             the disk to look at. This node starts from the blocks before it and asks the \
             network for the rest. If it happens again after a clean restart, the disk under \
             {directory} is the thing to check."
        )) {
            println!("             {line}");
        }
    }
}

/// The disk this node keeps and the block it has reached, said in one place.
///
/// Both messages below need it and it is the awkward half of either: the log
/// may hold nothing at all, and "up to block none" is not a sentence.
fn as_far_as(unwritten: &Unwritten) -> String {
    match unwritten.written_through {
        Some(height) => format!(
            "The chain is at block {} and the disk holds up to block {height}, so {} blocks \
             have been accepted and not kept",
            unwritten.reached, unwritten.blocks
        ),
        None => format!(
            "The chain is at block {} and the disk holds no blocks at all, so all {} of them \
             have been accepted and not kept",
            unwritten.reached, unwritten.blocks
        ),
    }
}

/// What an operator is told while a disk that has stopped taking writes can
/// still be given room in time.
///
/// Written for somebody who has never read the protocol. What it has to carry
/// is that the healthy-looking numbers beside it are memory, that nothing
/// below them is being kept, and that there is a deadline.
fn falling_behind(unwritten: &Unwritten, directory: &str) -> String {
    format!(
        "the disk under {directory} is not taking what this node writes. It was writing {}, \
         and the disk said: {}. {}: a restart begins at the disk's number and asks the \
         network for the rest, which it can only be given while other people still have \
         them. Free some room under that directory, or find out what else is wrong with it. \
         More than {MAX_BEHIND} blocks behind, the missing ones are gone from this node's \
         memory too and no amount of room brings them back, so it stops there rather than \
         go on making its own disk less worth restarting from.",
        unwritten.what,
        unwritten.because,
        as_far_as(unwritten),
    )
}

/// And what they are told once it cannot.
///
/// The deadline in the line above, reached. There is nothing left to ask of
/// the operator except the same thing, and the reason for stopping has to be
/// clear enough that nobody reads it as the node giving up early.
fn lost_the_disk(unwritten: &Unwritten, directory: &str) -> String {
    format!(
        "the disk under {directory} stopped taking what this node writes, and it has now \
         accepted more blocks than it can ever write down. It was writing {}, and the disk \
         said: {}. {}, and the blocks in between have left this node's memory, so there \
         is nowhere left to read them from and no room would help. It stops here so that \
         what is on the disk is still worth starting from: every block it took from now on \
         would be one more the disk does not have. Free some room under that directory and \
         start it again.",
        unwritten.what,
        unwritten.because,
        as_far_as(unwritten),
    )
}

/// What an operator is told while this node cannot yet show the chain to
/// somebody arriving new.
///
/// The costly half is the disk, and it is the half nobody would guess:
/// showing a newcomer the chain and writing down this node's own summary of it
/// are proved against the same header forest, and writing that summary is
/// what lets a node drop old blocks. So `--keep` is not being kept while this
/// lasts, and it is said as a number here rather than left for somebody to
/// notice a directory growing.
///
/// Not a fault, and written not to read like one. Nothing is wrong with the
/// machine, nothing has been lost, and the cure happens on its own for as
/// long as some peer holds the older part of the chain.
fn still_filling(filling: &Filling, directory: &str) -> String {
    let disk = if filling.over_the_keep() {
        format!(
            " It also cannot write down the summary that lets it drop old blocks, which is \
             proved against the same thing, so the {} of blocks under {directory} will go on \
             growing past the {} it was asked to hold. Both end together.",
            options::size(filling.bytes),
            options::size(filling.keep),
        )
    } else {
        String::new()
    };
    // What it holds, rather than how it came to hold it. Three different things
    // land here: a node that joined a chain and was given it from the anchor
    // down, one whose stored headers were set aside and rewritten from the
    // blocks it had left, and one whose disk refused a header write so the
    // headers stop short of the tip. Naming any of them as the cause would be
    // wrong two times in three. The numbers say which it is without guessing,
    // and the two that are somebody's fault already have lines of their own.
    format!(
        "this node cannot yet show the chain to somebody arriving new. It holds the \
         headers from block {} up to block {}, it can prove where {} of them sit, and the \
         chain is at block {}. It collects what is missing from its peers as it runs, and \
         nobody can join the network through this node until it has it all.{disk} If the \
         height above keeps moving and these numbers do not, no peer this node has found \
         holds the part it is missing, and connecting it to one that does is the only \
         thing to do.",
        filling.from,
        filling.through.saturating_sub(1),
        filling.proved,
        filling.reaches.saturating_sub(1),
    )
}

/// What an operator is told when this node's own disk will not give back
/// something it holds.
///
/// Written for somebody who has never read the protocol, and the hard part is
/// that nothing looks wrong. The height climbs, the peers connect, the disk
/// takes every write. What is happening is that some of what this node
/// already wrote will not come back out, so the peers asking it for that
/// stretch are quietly served answers with holes in them and go elsewhere.
///
/// It says what to check rather than what to do. The index beside the blocks
/// is worked out from the blocks and can be worked out again, so a node that
/// says this and comes back clean was carrying a derived file that had rotted;
/// one that says it again is being told something about the drive.
fn will_not_read_back(unread: &Unread, directory: &str) -> String {
    let again = if unread.refusals > 1 {
        format!(
            " It has happened {} times since this node started.",
            unread.refusals
        )
    } else {
        String::new()
    };
    format!(
        "the disk under {directory} will not give back something this node put there. It \
         was reading {} at block {}, and the store said: {}.{again} Nothing has been \
         deleted and nothing has been cut: the record is still on the disk to look at, and \
         the chain this node follows is not affected by it. What is affected is everybody \
         else. A peer catching up over that block is sent the blocks around it and drops \
         the rest, so it looks to them like a node that will not answer, and this node is \
         quietly doing less for the network than the line above it suggests. A restart \
         reads the disk again and will say this again if the damage is real, which is the \
         cheapest way to find out. After that, the drive under {directory} is the thing to \
         look at, along with anything else on this machine that has been unhappy.",
        unread.what, unread.height, unread.because,
    )
}

/// What an operator is told when the blocks arriving are written under rules
/// this build does not have.
///
/// Deliberately not a verdict. The node has not stopped and is not going to:
/// what makes a block unreadable is a number in a field, and a stranger can
/// write one. What this asks the reader to do is put it beside the height,
/// which is the half of the evidence a stranger cannot manufacture.
fn too_old(unjudged: &Unjudged) -> String {
    format!(
        "this build looks too old for the chain it is on. {} blocks from {} peers over the \
         last {} minutes are written under block version {}, and this build has the rules \
         only for version {}, so it cannot judge them and is not following them. It has not \
         stopped on that, because anyone can write a version number in a block. But if the \
         height above has also stopped moving, the network has changed its rules and this \
         node needs a newer build: installing one loses nothing on disk, and the chain here \
         is picked up where it was left.",
        unjudged.blocks,
        unjudged.peers,
        unjudged.over / 60,
        unjudged.version,
        unjudged.known,
    )
}

/// What an operator is told when nobody's showing of the chain will weigh.
///
/// Deliberately not a verdict either, and for the same reason as
/// [`too_old`]: two addresses are two peers. What it does is offer the reading
/// an operator cannot make from the outside, because from the outside a chain
/// this build cannot weigh and a peer inventing one look identical: peers
/// asked, peers dropped, and a height that takes hours to move.
fn cannot_weigh(unweighable: &Unweighable) -> String {
    format!(
        "no peer has been able to show this node what work stands behind the chain. {} showings          from {} peers, over {} minutes, were all refused with the same words: {}. Nothing has          stopped. This node is reading the chain block by block instead, which is how nodes          worked before the shorter way existed, and it checks more rather than less; what it          costs is time and bandwidth. Peers making chains up is one reason for this line. The          other is a chain whose difficulty has fallen far below what it once ran at, which needs          a longer run of headers than this build will take: that one mends itself as the chain          catches up, and until it does every honest node answering is refused in exactly this          way.",
        unweighable.showings,
        unweighable.peers,
        unweighable.over / 60,
        unweighable.because,
    )
}

/// Breaks a paragraph into lines that fit a terminal.
///
/// Everything above is written for a person rather than for a log parser, and
/// a person reading a two hundred column line has been given the words and not
/// the sense of them.
fn wrapped(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len().saturating_add(word.len()) >= 76 {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
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

/// What an operator actually reads.
///
/// The numbers matter more than the words and the words matter more than
/// usual: these lines are the whole of what a person has to go on, and two of
/// the three are printed by a node that looks healthy in every other respect.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod said_out_loud {
    use super::{cannot_weigh, falling_behind, lost_the_disk, still_filling, too_old, wrapped};
    use cairn_net::node::{Unjudged, Unweighable, Unwritten, Writing};
    use cairn_net::Filling;

    fn behind(blocks: u64, within_reach: bool) -> Unwritten {
        Unwritten {
            what: Writing::Blocks,
            because: "No space left on device (os error 28)".to_owned(),
            reached: 1_083,
            written_through: Some(32),
            blocks,
            within_reach,
        }
    }

    /// A node nobody can show the chain to prints the lines of a healthy one:
    /// peers, a clock, and a height that is simply absent. What was missing is
    /// what to do about it, and the two readings, because from the outside a
    /// chain this build cannot weigh and a peer making one up are the same
    /// sight.
    #[test]
    fn the_line_about_an_unweighable_chain_carries_both_readings() {
        let text = cannot_weigh(&Unweighable {
            because: "it could not be read as a weighing at all".to_owned(),
            showings: 5,
            peers: 3,
            over: 600,
        });
        assert!(text.contains('5') && text.contains('3'), "{text}");
        assert!(text.contains("10 minutes"), "{text}");
        assert!(
            text.contains("it could not be read as a weighing at all"),
            "the words the refusal used are what tells the two apart: {text}"
        );
        assert!(
            text.contains("reading the chain block by block"),
            "and what the node is doing meanwhile: {text}"
        );
        assert!(
            text.contains("difficulty has fallen"),
            "the reading that is nobody's fault has to be in it: {text}"
        );
        assert!(
            text.contains("making chains up"),
            "and so does the one that is: {text}"
        );
    }

    /// Every number a person needs in order to act, in every one of them.
    #[test]
    fn the_lines_carry_the_two_heights_the_reason_and_the_directory() {
        for text in [
            falling_behind(&behind(1_051, true), "/var/lib/cairn"),
            lost_the_disk(&behind(1_051, false), "/var/lib/cairn"),
        ] {
            for line in wrapped(&text) {
                eprintln!("{line}");
            }
            eprintln!();
            assert!(text.contains("1083"), "the height the chain reached");
            assert!(text.contains("block 32"), "the height the disk holds");
            assert!(text.contains("1051"), "and the difference, said as blocks");
            assert!(
                text.contains("No space left on device"),
                "what the disk said"
            );
            assert!(text.contains("/var/lib/cairn"), "and which disk");
        }
    }

    /// A log holding nothing at all is the awkward case, and it has to be a
    /// sentence rather than the word "none" in a gap.
    #[test]
    fn a_disk_with_no_blocks_on_it_is_still_a_sentence() {
        let mut nothing = behind(1_084, true);
        nothing.written_through = None;
        let text = falling_behind(&nothing, "/var/lib/cairn");
        eprintln!("{}", wrapped(&text).join("\n"));
        assert!(text.contains("no blocks at all"));
        assert!(!text.contains("block None"));
    }

    /// The disk figure is the whole reason this line exists, so it has to be
    /// there whenever the disk is over its budget and absent when it is not:
    /// a node that has just joined is inside its budget, and telling it its
    /// disk is running away would be a fault reported where there is none.
    #[test]
    fn the_line_about_filling_in_names_the_disk_only_when_the_disk_is_over() {
        let over = Filling {
            from: 32,
            through: 160,
            proved: 0,
            reaches: 160,
            bytes: 31_744,
            keep: 1_000,
        };
        let text = still_filling(&over, "/var/lib/cairn");
        eprintln!("{}", wrapped(&text).join("\n"));
        eprintln!();
        assert!(
            text.contains("from block 32"),
            "where its own headers start"
        );
        assert!(
            text.contains("block 159"),
            "where they stop, and the chain too"
        );
        assert!(text.contains("31744 bytes"), "what the disk holds");
        assert!(text.contains("1000 bytes"), "against what was asked for");
        assert!(text.contains("/var/lib/cairn"), "and which disk");

        // The shape that used to come out as "collecting the 0 blocks below
        // block 0 from its peers": headers level with the chain at the bottom
        // and short at the top, which is a disk that refused a write and not a
        // node waiting on anybody.
        let short_at_the_top = Filling {
            from: 0,
            through: 140,
            proved: 140,
            ..over
        };
        let text = still_filling(&short_at_the_top, "/var/lib/cairn");
        eprintln!("{}", wrapped(&text).join("\n"));
        eprintln!();
        assert!(text.contains("from block 0 up to block 139"), "{text}");
        assert!(text.contains("prove where 140 of them sit"), "{text}");
        assert!(text.contains("chain is at block 159"), "{text}");

        let under = Filling { bytes: 500, ..over };
        let text = still_filling(&under, "/var/lib/cairn");
        eprintln!("{}", wrapped(&text).join("\n"));
        assert!(
            !text.contains("growing past"),
            "a node inside its budget is not told its disk is running away: {text}"
        );
        assert!(
            text.contains("cannot yet show the chain"),
            "but it is still told the thing it cannot do"
        );
    }

    /// The one line that is a suspicion rather than a fact has to read like
    /// one, or an operator acts on a number a stranger wrote.
    #[test]
    fn the_line_about_an_old_build_does_not_pretend_to_be_certain() {
        let text = too_old(&Unjudged {
            version: 2,
            known: 1,
            blocks: 11,
            peers: 3,
            over: 1_920,
        });
        eprintln!("{}", wrapped(&text).join("\n"));
        assert!(text.contains("version 2"), "the version it saw");
        assert!(text.contains("11 blocks"), "how much of it there was");
        assert!(text.contains("3 peers"), "and from how many places");
        assert!(text.contains("32 minutes"), "over what stretch");
        assert!(
            text.contains("has not stopped"),
            "and that the node has not acted on it"
        );
    }
}

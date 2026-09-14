//! A node that is refused one visitor has to go on answering the door.
//!
//! `accept_loop` polls the listener and used to leave on any error that was
//! not `WouldBlock` or `Interrupted`. Leaving ended the thread, and the thread
//! owned the `TcpListener`, so the port closed for the life of the process.
//! Nothing recorded it: `running` stayed true, every peer already connected
//! went on working, the node went on following the chain and dialling out, and
//! `cairnd` went on printing a healthy line under the `listening <address>` it
//! had printed once at the top.
//!
//! What the loop's own comment says is "Fifty milliseconds of idle polling
//! buys an exit that always works". True, and it answers whether the loop can
//! be made to leave. The question was whether it can leave when nobody asked.
//!
//! The error that reaches that arm in practice is `accept` being refused for
//! want of a file descriptor. That is a fact about the process or the host at
//! that instant and not about any peer, and it clears the moment somebody
//! hangs up, which is exactly when a node most needs to still be listening.
//! `ENFILE` is worse than per process: another program on the same machine
//! exhausting the file table for a moment is enough to take a seed address off
//! the network until its operator restarts it.
//!
//! Descriptor limits are a Unix idea, so this runs there. The test lowers its
//! own limit by running itself again under `ulimit -n`, because a limit in the
//! millions takes too long to fill.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::arithmetic_side_effects
)]

use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use cairn_ledger::validation::ConsensusParams;
use cairn_net::Node;

/// Set in the run that does the work, absent in the run that starts it.
const UNDER_A_SMALL_LIMIT: &str = "CAIRN_UNDER_A_SMALL_LIMIT";

/// Low enough to fill in a moment, high enough that a node can open its files,
/// bind, and hold a connection before the table runs out.
const DESCRIPTORS: usize = 256;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(8)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("cairn-door-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Runs this same test binary again, under a descriptor limit small enough to
/// exhaust, and reports whether it passed.
fn again_under_a_small_limit(test: &str) -> bool {
    let exe = std::env::current_exe().unwrap();
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ulimit -n {DESCRIPTORS}; exec \"$1\" --exact --nocapture --test-threads 1 {test}",
        ))
        .arg("sh")
        .arg(&exe)
        .arg(test)
        .env(UNDER_A_SMALL_LIMIT, "1")
        .status()
        .unwrap()
        .success()
}

/// Opens a file over and over until the process cannot, then hands back all
/// but `spare` of them.
fn fill_the_table(spare: usize) -> Vec<File> {
    let mut held = Vec::new();
    while let Ok(file) = File::open("/dev/null") {
        held.push(file);
        assert!(held.len() < 100_000, "the descriptor limit is not small");
    }
    for _ in 0..spare {
        held.pop();
    }
    held
}

/// Waits for `count` to reach `wanted`, and answers with what it reached.
///
/// A bounded wait and not an assertion: what is asserted on is the count, and
/// the count is the same on any machine. A machine slow enough to miss this
/// fails the test rather than passing it.
fn until(wanted: u64, count: impl Fn() -> u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let reached = count();
        if reached >= wanted {
            return reached;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    count()
}

#[test]
fn a_node_refused_one_visitor_goes_on_listening() {
    if std::env::var(UNDER_A_SMALL_LIMIT).is_err() {
        assert!(
            again_under_a_small_limit("a_node_refused_one_visitor_goes_on_listening"),
            "the run under a small descriptor limit failed"
        );
        return;
    }

    let directory = scratch("listening");
    let (node, _restored) = Node::open(params(), loopback(), &directory).unwrap();
    let address = node.address();

    // One connection taken before the table is filled, so that what the test
    // measures afterwards is the accept and not the node being unable to start.
    let first = TcpStream::connect(address).unwrap();

    // Everything but one descriptor, and the one left is what the visitor
    // below spends dialling. The accept that would take this node's end of
    // that connection has nothing to take it with.
    let held = fill_the_table(1);
    let knocking = TcpStream::connect(address);

    let turned_away = until(1, || node.turned_away());

    // The table is given back before anything is asked of the node, so that
    // what it answers next is not answered under the same exhaustion.
    drop(held);
    drop(knocking);

    // The door is still open. Before this the listener went out with the
    // thread and this dial came back refused by the kernel. Asked before the
    // count below, because this is the claim and the count is only what says
    // the run reached it.
    let after = TcpStream::connect(address);
    assert!(
        after.is_ok(),
        "a node turned away at least one visitor and then stopped listening: {after:?}"
    );
    assert!(
        turned_away >= 1,
        "no visitor was turned away, so this run measured nothing"
    );

    drop(first);
    node.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_door_that_stays_shut_is_said_to_be_shut() {
    if std::env::var(UNDER_A_SMALL_LIMIT).is_err() {
        assert!(
            again_under_a_small_limit("a_door_that_stays_shut_is_said_to_be_shut"),
            "the run under a small descriptor limit failed"
        );
        return;
    }

    let directory = scratch("shut");
    let (node, _restored) = Node::open(params(), loopback(), &directory).unwrap();
    let address = node.address();
    let keeping_it_open = TcpStream::connect(address).unwrap();

    assert_eq!(node.unanswered(), None, "nothing has been refused yet");

    let held = fill_the_table(1);
    let knocking = TcpStream::connect(address);
    let refusals = until(1, || node.turned_away());
    let said = node.unanswered();
    drop(held);
    drop(knocking);

    assert!(
        refusals >= 1,
        "no visitor was turned away, so this run measured nothing"
    );
    let said = said.expect("a visitor was turned away and nothing was said about it");
    assert!(said.refusals >= 1, "it reported {} refusals", said.refusals);
    assert!(
        !said.because.is_empty(),
        "it reported no reason for the refusals"
    );
    println!("the door was shut, and it said: {}", said.because);

    // And it clears itself once a visitor gets in, rather than standing until
    // somebody restarts the node.
    let after = TcpStream::connect(address).unwrap();
    let cleared = Instant::now() + Duration::from_secs(10);
    while node.unanswered().is_some() && Instant::now() < cleared {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        node.unanswered(),
        None,
        "the door opened again and it still says it is shut"
    );

    drop(after);
    drop(keeping_it_open);
    node.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

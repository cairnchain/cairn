//! Whether a setting an operator typed reaches the node it is about.
//!
//! Everything under `--check` answers a narrower question than it looks like
//! it answers. It says the setting was read and printed, which is true and is
//! not what an operator needs: what they need is that the node then runs that
//! way. Between the two sits `run`, which hands each setting on by hand, and
//! nothing held it to doing so.
//!
//! Measured before this file existed: `--archive` never taken, `--keep`
//! replaced by the default, the seeds emptied, the miner never spawned. The
//! suite passed, every test of it.
//!
//! So these run the real program and ask the network what it turned out to be,
//! which is the only place the answer is not this node's own word for it. A
//! second node in this process dials the one under test and reports what it
//! met.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use cairn_ledger::validation::ConsensusParams;
use cairn_net::Node;

/// Long enough for a dial, a handshake and an answer, and short enough that a
/// test that goes wrong ends by itself.
const RUN_FOR: &str = "30";

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairnd-reaches-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn devnet() -> ConsensusParams {
    ConsensusParams::for_network("devnet").expect("devnet exists")
}

/// A running `cairnd`, and the address it said it was listening on.
struct Running {
    child: Child,
    address: SocketAddr,
    lines: BufReader<std::process::ChildStdout>,
}

impl Running {
    fn start(arguments: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cairnd"))
            .args(arguments)
            .stdout(Stdio::piped())
            .spawn()
            .expect("cairnd runs");
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cairnd was started with a pipe and has none");
        };
        // Built before a word of it is read, so that whatever happens next the
        // child is one this test still ends.
        let mut running = Self {
            child,
            address: loopback(),
            lines: BufReader::new(stdout),
        };
        running.address = running.listening_at();
        running
    }

    /// The address it says it is listening on, read off its own first lines.
    ///
    /// Read rather than chosen, because a port chosen by this test is a port
    /// something else on the machine may hold, and a test that fails for that
    /// reason says nothing about the node.
    fn listening_at(&mut self) -> SocketAddr {
        let mut said = String::new();
        loop {
            said.clear();
            let read = self
                .lines
                .read_line(&mut said)
                .expect("cairnd says something");
            assert!(read > 0, "cairnd stopped before it said it was listening");
            if let Some(rest) = said.trim().strip_prefix("listening") {
                return rest.trim().parse().expect("an address");
            }
        }
    }

    /// Reads on until a line holds `what`, or gives up.
    ///
    /// Waited for rather than asserted on: what is asserted is whether the
    /// line came, and a machine too slow to produce it fails this test rather
    /// than passing it.
    fn says(&mut self, what: &str, within: Duration) -> bool {
        let giving_up = Instant::now() + within;
        let mut said = String::new();
        while Instant::now() < giving_up {
            said.clear();
            match self.lines.read_line(&mut said) {
                Ok(0) | Err(_) => return false,
                Ok(_) => {
                    if said.contains(what) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Dials the node under test from one in this process, and reports what the
/// handshake said about it.
fn what_a_peer_meets(address: SocketAddr, directory: &std::path::Path) -> (usize, usize) {
    let (watcher, _) = Node::open(devnet(), loopback(), directory).unwrap();
    watcher.remember_seed(address);
    let _ = watcher.connect(address);

    // Waited on until the peer says it keeps the cold set, and not until it
    // merely turns up: those are two moments, and reading the second for the
    // first is how this test passed for a node that was archiving.
    //
    // Both calls below spend the same wait. The one that expects nothing
    // spends all of it, so it cannot come back empty by being asked sooner.
    let giving_up = Instant::now() + Duration::from_secs(20);
    while Instant::now() < giving_up && watcher.archiving_peers() == 0 {
        std::thread::sleep(Duration::from_millis(20));
    }
    let met = (watcher.peers_introduced(), watcher.archiving_peers());
    watcher.shutdown();
    met
}

/// `--archive` is a promise made on the handshake, so a peer is who can say
/// whether it was kept.
#[test]
fn archive_reaches_the_node_and_the_network_is_told() {
    let directory = scratch("archive");
    let archiving = Running::start(&[
        "--data",
        &directory.join("on").to_string_lossy(),
        "--network",
        "devnet",
        "--listen",
        "127.0.0.1:0",
        "--archive",
        "--run-for",
        RUN_FOR,
    ]);
    let (introduced, archives) =
        what_a_peer_meets(archiving.address, &directory.join("watching-on"));
    assert_eq!(introduced, 1, "the peer never introduced itself");
    assert_eq!(
        archives, 1,
        "a node started with --archive told the network it keeps nothing of the kind"
    );
    drop(archiving);

    let plain = Running::start(&[
        "--data",
        &directory.join("off").to_string_lossy(),
        "--network",
        "devnet",
        "--listen",
        "127.0.0.1:0",
        "--run-for",
        RUN_FOR,
    ]);
    let (introduced, archives) = what_a_peer_meets(plain.address, &directory.join("watching-off"));
    assert_eq!(introduced, 1, "the peer never introduced itself");
    assert_eq!(
        archives, 0,
        "a node started without --archive said it keeps the cold set anyway, so the flag says \
         nothing either way"
    );
    drop(plain);
    let _ = std::fs::remove_dir_all(&directory);
}

/// `--seed` is an address to start from, and the node at that address is who
/// can say whether anybody started from it.
///
/// It reaches the node by two roads, and this holds one of them.
///
/// The addresses that resolved are dialled on the way up and the dial is
/// reported, which is the road a seed given as an address takes, and it is the
/// road this test is on. Both the dial and the line it prints are asserted,
/// because the peer arriving can be got by the other road and the line cannot.
///
/// The names go to `start_from_names`, for a node that could look nothing up
/// at this moment to ask again while it runs. **That road is not held here**,
/// and cutting it alone leaves this test green, which is worth writing down
/// rather than leaving for somebody to find with a mutation. It is reached
/// only by a node with no seed address at all, so a seed given as an address
/// never takes it: holding it needs a name that fails to resolve at start and
/// resolves later, which is a name server this test would have to own.
#[test]
fn a_seed_reaches_the_node_and_is_dialled() {
    let directory = scratch("seed");
    let (waiting, _) = Node::open(devnet(), loopback(), directory.join("waiting")).unwrap();
    let seed = waiting.address();

    let mut node = Running::start(&[
        "--data",
        &directory.join("dialling").to_string_lossy(),
        "--network",
        "devnet",
        "--listen",
        "127.0.0.1:0",
        "--seed",
        &seed.to_string(),
        "--run-for",
        RUN_FOR,
    ]);
    let _ = node.address;

    // The dial the node makes on its way up, and says it made. This is the
    // road `start_from_names` is not on.
    let reported = node.says("reached", Duration::from_secs(20));

    let giving_up = Instant::now() + Duration::from_secs(20);
    while Instant::now() < giving_up && waiting.peers_introduced() == 0 {
        std::thread::sleep(Duration::from_millis(20));
    }
    let arrived = waiting.peers_introduced();
    waiting.shutdown();
    drop(node);

    assert_eq!(
        arrived, 1,
        "a node given a seed never dialled it, so the address an operator typed went nowhere"
    );
    assert!(
        reported,
        "it dialled the seed and never said so, so an operator watching it start cannot tell a \
         seed that was reached from one that was passed over"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// `--mine` is the one setting whose whole effect is blocks, so blocks are
/// what says it arrived.
#[test]
fn mine_reaches_the_node_and_blocks_are_produced() {
    let directory = scratch("mine");
    let key = cairn_crypto::SecretKey::from_bytes(&[9; 32]).public_key();
    let mut node = Running::start(&[
        "--data",
        &directory.to_string_lossy(),
        "--network",
        "devnet",
        "--listen",
        "127.0.0.1:0",
        "--mine",
        &cairn_primitives::hex::encode(key.as_bytes()),
        "--status",
        "1",
        "--run-for",
        RUN_FOR,
    ]);

    assert!(
        node.says("mined", Duration::from_secs(60)),
        "a node started with --mine produced no block in a minute on devnet, where a block is \
         five seconds and the difficulty is the lowest there is"
    );
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

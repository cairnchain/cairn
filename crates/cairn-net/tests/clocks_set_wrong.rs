//! Nodes whose clocks disagree, over real sockets: what each refuses, holds
//! and says, and whether the nodes whose clocks are right stay on one chain.
//!
//! R12 of the testnet-8 attack catalogue (B05). A node reads its clock against
//! a block in one place only, the drift a block may run ahead of it, ten
//! targets: "the clock is read for the drift a block may run ahead and
//! nothing else" (the threat model, on an operator). A refusal for it is not
//! remembered, not held against whoever sent it, and reversed by waiting.
//!
//! How a clock is set wrong here. Every node in one process reads the same
//! clock, `SystemTime::now`, and nothing takes another. But the drift is read
//! only as `timestamp > now + drift`, so a node given a drift of `drift +
//! offset` is, for every judgement it makes, a node whose clock reads `now +
//! offset`. Each node below is given the drift its offset folds into, and
//! each miner dates its blocks by its own offset, past the median of recent
//! blocks as `cairnd --mine` does. Where a node has to be further behind than
//! the drift, the others are put ahead instead, which is the same thing seen
//! from the slow one. Figures a node reports are reported against its own
//! drift, so a test reads the difference between the two, which is what the
//! operator's line prints.
//!
//! The catalogue's lab ran devnet, whose drift is fifty seconds, at five
//! minutes slow and fast and an hour fast. What decides every outcome is the
//! offset against the drift, so this runs the public networks' drift of ten
//! minutes at offsets inside it, just past it, and an hour past it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::pow::median_time_past;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::node::{TurnedAway, TARGET_PEERS};
use cairn_net::Node;
use cairn_primitives::Hash32;

const ATTEMPTS: u64 = 1 << 22;

/// A liveness bound, far past what any of this takes on a loaded runner.
/// Every wait here is for something to happen.
const PATIENCE: Duration = Duration::from_secs(180);

/// The drift every network allows: ten targets.
const DRIFT: u64 = ConsensusParams::testnet().max_timestamp_drift;

/// The target block time, which is what "within one block" is measured in.
const BLOCK: u64 = ConsensusParams::testnet().target_block_time;

/// Blocks refused from two peers before a node says its clock looks behind,
/// as `cairn_net::node` counts them. Mined a few over, since a block one peer
/// offers twice is counted once or twice depending on when it is asked for.
const SAID_AFTER: usize = 8;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The rules for a node whose clock reads `offset` seconds from this
/// machine's: see the top of this file.
fn clocked(offset: i64) -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.max_timestamp_drift = u64::try_from(DRIFT as i64 + offset).unwrap();
    params
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn key(seed: usize) -> PublicKey {
    SecretKey::from_bytes(&[u8::try_from(seed).unwrap(); 32]).public_key()
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("waited {PATIENCE:?} for {what}");
}

fn tip(node: &Node) -> Option<Hash32> {
    node.with_chain(ChainStore::tip)
}

fn holds(node: &Node, block: &Block) -> bool {
    let id = block.id();
    node.with_chain(|chain| chain.contains(&id))
}

/// Five blocks every node holds before anything is measured, dated in the
/// recent past so that no clock here refuses them.
fn shared() -> Vec<Block> {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::new();
    let mut clock = now() - 10_000;
    (0..5)
        .map(|_| {
            clock += BLOCK;
            let height = state.next_height().unwrap();
            let coinbase =
                CoinbaseTransaction::new(height, vec![Note::new(params.reward_at(height), key(1))]);
            let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &params, now()).unwrap();
            block
        })
        .collect()
}

/// A node whose clock reads `offset` from this machine's, holding the shared
/// blocks.
fn started(shared: &[Block], offset: i64) -> Node {
    let node = Node::bind(clocked(offset), loopback()).unwrap();
    for block in shared {
        node.submit_block(block.clone()).unwrap();
    }
    node
}

/// What the miner on `node` finds next, built as `cairnd --mine` builds it, on
/// the node's own chain and dated by the miner's clock, `offset` from this
/// machine's, or past the median of recent blocks, whichever is later.
fn mine_on(node: &Node, offset: i64, to: &PublicKey) -> Block {
    let params = ConsensusParams::testnet();
    let block = node.with_chain(|chain| {
        let state = chain.state();
        let height = state.next_height().unwrap();
        let earliest = median_time_past(state.recent_headers()).map_or(0, |median| median + 1);
        let clock = u64::try_from(now() as i64 + offset).unwrap();
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(params.reward_at(height), *to)]);
        assemble_block(state, coinbase, Vec::new(), &params, clock.max(earliest), 0).unwrap()
    });
    let block = mine_block(block, ATTEMPTS).unwrap();
    node.submit_block(block.clone()).unwrap();
    block
}

fn link(from: &Node, to: &[&Node]) {
    for node in to {
        from.connect(node.address()).unwrap();
    }
}

/// **Clocks five minutes slow and five minutes fast, inside the drift, change
/// nothing.**
///
/// Two nodes on the right time, one five minutes slow and one five minutes
/// fast whose miner dates its blocks by it. Each block, the honest miner's or
/// the fast one's, is taken by all four, and nobody says anything about a
/// clock.
#[test]
fn clocks_five_minutes_out_either_way_inside_the_drift_follow_one_chain() {
    let shared = shared();
    let right = started(&shared, 0);
    let also_right = started(&shared, 0);
    let slow = started(&shared, -300);
    let fast = started(&shared, 300);
    link(&also_right, &[&right]);
    link(&slow, &[&right, &also_right]);
    link(&fast, &[&right, &also_right]);
    let everyone = [&right, &also_right, &slow, &fast];
    wait_for("everyone to be introduced", || {
        right.peers_introduced() >= 3 && also_right.peers_introduced() >= 3
    });

    for round in 0..3 {
        for (miner, offset) in [(&right, 0), (&fast, 300)] {
            let block = mine_on(miner, offset, &key(2 + round));
            wait_for("every node to take the block", || {
                everyone.iter().all(|node| tip(node) == Some(block.id()))
            });
        }
    }

    let roots: Vec<Hash32> = everyone
        .iter()
        .map(|node| node.with_chain(|chain| chain.state().state_root()))
        .collect();
    let said: Vec<bool> = everyone
        .iter()
        .map(|node| node.clock_behind().is_some())
        .collect();
    let turned_away: Vec<_> = everyone.iter().map(|node| node.refused_hosts()).collect();
    for node in everyone {
        node.shutdown();
    }
    assert!(roots.iter().all(|root| *root == roots[0]));
    assert_eq!(
        said, [false; 4],
        "a clock inside the drift was said to be out"
    );
    assert!(turned_away.iter().all(|one| *one == TurnedAway::default()));
}

/// **A node a little more than the drift behind refuses the network's blocks,
/// keeps its peers, and takes the blocks by itself the moment its clock
/// allows them, within one block.**
///
/// The others are fifteen seconds ahead of this machine and the slow node is
/// the drift and those fifteen seconds behind them, so every block they mine
/// stands just past what it takes, and stops standing past it fifteen seconds
/// on. That moment is what setting the clock right brings forward: in both, a
/// block refused for the clock becomes one it takes. What is measured is that
/// it then takes them on its own, with no further block, which is what a
/// refused block's peer being asked again once the clock allows exists for
/// (`cairn_net::sync::PeerState::clock_allows_at`).
///
/// Within one block: the catalogue's pass is recovery within one block of the
/// clock being fixed, and a block is sixty seconds here. The node rereads an
/// idle connection every five, so this is twelve times what it needs.
#[test]
fn a_node_just_past_the_drift_behind_waits_and_takes_the_blocks_once_its_clock_allows() {
    const AHEAD: i64 = 15;
    let shared = shared();
    let right = started(&shared, AHEAD);
    let also_right = started(&shared, AHEAD);
    let slow = started(&shared, -(DRIFT as i64));
    link(&also_right, &[&right]);
    link(&slow, &[&right, &also_right]);
    wait_for("everyone to be introduced", || {
        slow.peers_introduced() >= 2 && also_right.peers_introduced() >= 2
    });
    let before = tip(&slow);

    let mined: Vec<Block> = (0..SAID_AFTER)
        .map(|at| mine_on(&right, AHEAD, &key(10 + at)))
        .collect();
    let newest = mined.last().unwrap().clone();
    // The moment the newest of them is no longer past the slow node's drift,
    // by this machine's clock. Nothing is mined from here on.
    let allowed = newest.header.timestamp;
    wait_for("the other node on the right time to take them", || {
        tip(&also_right) == Some(newest.id())
    });
    let looked = now();
    let refusing = (tip(&slow), mined.iter().any(|block| holds(&slow, block)));

    wait_for(
        "the slow node to take the blocks once its clock allows them",
        || tip(&slow) == Some(newest.id()),
    );
    let taken = now();
    let kept = (slow.peer_count(), slow.refused_hosts());
    for node in [&right, &also_right, &slow] {
        node.shutdown();
    }

    // Only a look taken before the moment shows a refusal; a runner that
    // stalled past it has nothing left to refuse.
    if looked + 1 < mined[0].header.timestamp {
        assert_eq!(
            refusing.0, before,
            "the slow node followed blocks past its drift"
        );
        assert!(
            !refusing.1,
            "the slow node held a block refused for its clock"
        );
    }
    assert!(
        kept.0 >= 2,
        "the slow node let go of a peer for its own clock"
    );
    assert_eq!(kept.1, TurnedAway::default());
    assert!(
        taken <= allowed + BLOCK,
        "the slow node took the blocks {} seconds after its clock allowed them, more than a \
         block",
        taken.saturating_sub(allowed)
    );
}

/// **A miner whose clock is more than the drift ahead mines blocks every node
/// on the right time refuses; it is not held against it, those nodes stay on
/// one chain, and its own blocks are replaced.**
///
/// The miner is eleven minutes fast. Beside it, a node an hour fast that
/// mines nothing and is connected to everybody. Each round the fast miner
/// finds a block on its tip and then the honest miner finds two.
///
/// What each is told. The fast miner's node refuses nothing and says nothing
/// about a clock; the line for it is `cairnd`'s miner saying its last blocks
/// were each replaced at the same height and to check the clock, which reads
/// exactly what this measures and is held in `cairn-node`'s own tests
/// (`its_own_blocks_replaced_three_times_running_are_said_once`). The node an
/// hour fast takes each of those blocks and follows it until the honest
/// branch is heavier, and is told nothing either. And it passes them on, so
/// the nodes on the right time are offered them by two peers and say that
/// their own clock looks behind, which is the wrong machine: the line says a
/// run of fast miners reads the same from there, and is evidence and not a
/// verdict. That line is also what shows they judged the blocks, rather than
/// not having been sent them.
#[test]
fn a_miner_more_than_the_drift_fast_mines_blocks_only_fast_clocks_keep() {
    const FAST: i64 = 660;
    const HOUR: i64 = 3_600;
    let shared = shared();
    let right = started(&shared, 0);
    let also_right = started(&shared, 0);
    let fast = started(&shared, FAST);
    let hour = started(&shared, HOUR);
    link(&also_right, &[&right]);
    link(&fast, &[&right, &also_right]);
    link(&hour, &[&right, &also_right, &fast]);
    let everyone = [&right, &also_right, &fast, &hour];
    wait_for("everyone to be introduced", || {
        right.peers_introduced() >= 3 && also_right.peers_introduced() >= 3
    });

    let mut its_own = Vec::new();
    for round in 0..SAID_AFTER {
        let found = mine_on(&fast, FAST, &key(30));
        wait_for(
            "the node an hour fast to follow the fast miner's block",
            || tip(&hour) == Some(found.id()),
        );
        let honest: Vec<Block> = (0..2)
            .map(|_| mine_on(&right, 0, &key(31 + round)))
            .collect();
        let newest = honest[1].id();
        wait_for("every node to stand on the honest branch", || {
            everyone.iter().all(|node| tip(node) == Some(newest))
        });
        its_own.push(found);
        if right.clock_behind().is_some() && also_right.clock_behind().is_some() {
            break;
        }
    }
    wait_for(
        "the nodes on the right time to have judged the fast miner's blocks",
        || right.clock_behind().is_some() && also_right.clock_behind().is_some(),
    );

    let held_by_the_right: Vec<bool> = its_own
        .iter()
        .map(|block| holds(&right, block) || holds(&also_right, block))
        .collect();
    let replaced: Vec<bool> = its_own
        .iter()
        .map(|block| fast.id_at(block.header.height) != Some(block.id()))
        .collect();
    let fast_said = (fast.clock_behind(), hour.clock_behind());
    let turned_away: Vec<_> = everyone.iter().map(|node| node.refused_hosts()).collect();
    let kept = (fast.peer_count(), hour.peer_count());
    for node in everyone {
        node.shutdown();
    }

    assert!(
        held_by_the_right.iter().all(|held| !held),
        "a node on the right time holds a block dated past its drift: {held_by_the_right:?}"
    );
    assert!(
        replaced.iter().all(|gone| *gone),
        "a block the fast miner mined is still on its own branch: {replaced:?}"
    );
    assert_eq!(fast_said, (None, None));
    assert!(
        turned_away.iter().all(|one| *one == TurnedAway::default()),
        "somebody was turned away over a clock: {turned_away:?}"
    );
    assert!(
        kept.0 >= 3 && kept.1 >= 3,
        "a peer was let go of over a clock: {kept:?}"
    );
}

/// **A node an hour behind, with as many peers as a node looks for, refuses
/// everything, says so with a figure, keeps its peers, builds nothing
/// anybody follows, and catches up once its clock is set right.**
///
/// The network is an hour ahead of this machine and the slow node is this
/// machine, connected to `TARGET_PEERS` nodes of the network. While it is
/// behind, its own miner finds two blocks on the last block it took. Setting
/// its clock right is a restart from its own directory with the network's
/// time: a running node's drift cannot be moved here, and the path a running
/// node takes when its clock steps forward, the refused block's peer asked
/// again once the clock allows it, is the one measured above.
///
/// Eight peers because the line needs eight refused blocks, and a slow node
/// is offered one per peer: see the test after this one.
#[test]
fn a_node_an_hour_behind_refuses_says_so_and_catches_up_once_its_clock_is_set() {
    const HOUR: i64 = 3_600;
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "cairn-hour-behind-{}-{:?}",
        std::process::id(),
        thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let shared = shared();
    let network: Vec<Node> = (0..TARGET_PEERS).map(|_| started(&shared, HOUR)).collect();
    for node in &network[1..] {
        link(node, &[&network[0]]);
    }
    let (slow, _) = Node::open(clocked(0), loopback(), &directory).unwrap();
    for block in &shared {
        slow.submit_block(block.clone()).unwrap();
    }
    for node in &network {
        link(&slow, &[node]);
    }
    wait_for("everyone to be introduced", || {
        slow.peers_introduced() >= TARGET_PEERS
    });

    let mined: Vec<Block> = (0..3)
        .map(|at| mine_on(&network[0], HOUR, &key(40 + at)))
        .collect();
    let newest = mined.last().unwrap().id();
    wait_for("the network to take them", || {
        network.iter().all(|node| tip(node) == Some(newest))
    });
    wait_for("the slow node to say its clock looks behind", || {
        slow.clock_behind().is_some()
    });
    let lonely: Vec<Block> = (0..2).map(|_| mine_on(&slow, 0, &key(49))).collect();
    wait_for(
        "the network to have been offered the slow node's blocks",
        || lonely.iter().all(|block| holds(&network[0], block)),
    );

    let said = slow.clock_behind().unwrap();
    let behind = (
        tip(&slow),
        mined.iter().any(|block| holds(&slow, block)),
        slow.peer_count(),
        slow.refused_hosts(),
        network.iter().all(|node| tip(node) == Some(newest)),
    );
    slow.shutdown();
    drop(slow);

    // Set right, and started again from the same directory.
    let (slow, restored) = Node::open(clocked(HOUR), loopback(), &directory).unwrap();
    assert!(restored.blocks > 0, "fixture: the slow node kept nothing");
    link(&slow, &[&network[0], &network[1]]);
    wait_for("the node set right to take the network's chain", || {
        tip(&slow) == Some(newest)
    });
    let after = (slow.clock_behind(), slow.id_at(lonely[0].header.height));
    slow.shutdown();
    for node in &network {
        node.shutdown();
    }
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        behind.0,
        Some(lonely[1].id()),
        "the slow node did not stay on what it could take"
    );
    assert!(
        !behind.1,
        "the slow node held a block refused for its clock"
    );
    assert!(
        behind.2 >= TARGET_PEERS,
        "the slow node let go of a peer for its own clock"
    );
    assert_eq!(behind.3, TurnedAway::default());
    assert!(
        behind.4,
        "a node on the network's time followed the slow node's blocks"
    );
    // An hour behind, and the line says at least the hour less the drift.
    let out_by = said.seconds.saturating_sub(said.drift);
    assert!(
        out_by >= (HOUR as u64) - DRIFT,
        "the slow node said its clock looks only {out_by} seconds behind: {said:?}"
    );
    assert_eq!(said.peers, TARGET_PEERS);
    assert_eq!(
        after.0, None,
        "the node set right still says its clock is behind"
    );
    assert_ne!(
        after.1,
        Some(lonely[0].id()),
        "the node set right is still on the blocks it mined while behind"
    );
}

/// **A node an hour behind with three peers says its clock looks behind.**
///
/// The catalogue's lab: four nodes, one of them slow. The line exists for
/// exactly this machine (`Node::clock_behind`, `cairnd`'s status and the
/// wallet's warning) and asks for eight blocks refused for the clock from two
/// peers, on the reading that "a machine running behind refuses whatever it is
/// offered, from everybody, for as long as it is wrong" (`BEHIND_BLOCKS` in
/// `cairn_net::node`).
///
/// A gap, kept failing on purpose. A slow node refuses the first block each
/// peer offers past its drift, and every block after it arrives with that
/// parent missing: an orphan, which is never judged against the clock, and on
/// which the chain is not asked of that peer again until the clock allows the
/// refused block (`cairn_net::sync::PeerState::clock_allows_at`). So the count
/// is one per peer, and stays there for as long as the refused block stands
/// past the drift: fifty minutes for a node an hour behind. Eight peers or
/// more and it is said, as the test above shows; three, or a wallet's few, and
/// a machine an hour behind, or a week behind after a flat battery, follows
/// nothing and says nothing.
///
/// A minute: a block on this network, and hundreds of times what reading
/// eight blocks from three peers takes.
#[test]
fn a_node_an_hour_behind_with_three_peers_says_its_clock_looks_behind() {
    const HOUR: i64 = 3_600;
    let shared = shared();
    let network: Vec<Node> = (0..3).map(|_| started(&shared, HOUR)).collect();
    for node in &network[1..] {
        link(node, &[&network[0]]);
    }
    let slow = started(&shared, 0);
    for node in &network {
        link(&slow, &[node]);
    }
    wait_for("everyone to be introduced", || slow.peers_introduced() >= 3);

    let mut newest = None;
    for at in 0..SAID_AFTER {
        newest = Some(mine_on(&network[0], HOUR, &key(60 + at)).id());
    }
    wait_for("the network to take them", || {
        network.iter().all(|node| tip(node) == newest)
    });
    let deadline = Instant::now() + Duration::from_secs(BLOCK);
    while slow.clock_behind().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }

    let said = slow.clock_behind();
    let followed = tip(&slow) == newest;
    slow.shutdown();
    for node in &network {
        node.shutdown();
    }
    assert!(
        !followed,
        "fixture: the slow node took blocks an hour ahead of it"
    );
    assert!(
        said.is_some(),
        "a node an hour behind the network, offered {SAID_AFTER} blocks by each of three \
         peers, follows none of them and says nothing about its clock"
    );
}

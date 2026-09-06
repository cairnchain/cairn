//! A ledger this build has no rules for, and who gets charged for it.
//!
//! A rule that changes names the height it takes effect at, and the height is
//! in the software long before the rules are. So a node one release behind
//! meets a chain it cannot judge, and the whole of this project's answer to
//! that is written where blocks arrive: the block is not taken, nothing is
//! held against the peer that sent it, the verdict is named, and a person can
//! read it beside a height that has stopped moving.
//!
//! None of that was written where a ledger arrives. `land_the_ledger` put both
//! the check and the adoption inside an `.ok()`, so a handover this build had
//! no rules for came out as a peer that had failed to show its chain: the
//! archivist that had updated paid a pause that doubles to half an hour, the
//! next one paid it too, and the verdict itself reached nobody. What an
//! operator saw was a node with no chain dropping every peer it spoke to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, Block, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::sync::JOIN_RATHER_THAN_READ;
use cairn_net::Node;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Rules written for a version this build does not have, from the first block.
/// A node one release behind reads every chain there is against these.
const AHEAD: &[Activation] = &[Activation {
    height: 0,
    version: BLOCK_VERSION + 1,
}];

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(8)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// A chain built off to the side, so a node can be handed a real one.
fn chain(count: usize) -> Vec<Block> {
    let miner = SecretKey::from_bytes(&[1; 32]);
    let params = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..count)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            block
        })
        .collect()
}

/// **A handover this build cannot judge is named, and nobody is blamed.**
///
/// AUDIT, repaired. The verdict is now told apart from every other reason a
/// ledger might not be taken, reported through the same channel the reading
/// path has always used, and the claim behind it stops counting without the
/// address paying anything.
///
/// The reading path reaches the same verdict on its own, so this test has to
/// be sure it is not what it measured. It is not: the chooser will not offer a
/// read until a full retry pause after the join attempt ended, so inside the
/// window below no block has been asked for, and the height beside the
/// assertion says so.
#[test]
fn a_ledger_from_past_this_builds_rules_is_named_rather_than_blamed_on_a_peer() {
    let blocks = chain(usize::try_from(JOIN_RATHER_THAN_READ).unwrap() + 40);
    let top = (blocks.len() - 1) as u64;

    let directory = std::env::temp_dir().join(format!("cairn-toonew-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let (keeper, _) = Node::open_archiving(params(), loopback(), &directory).unwrap();
    for block in &blocks {
        keeper.submit_block(block.clone()).unwrap();
    }
    assert_eq!(keeper.height(), Some(top));

    // The position of every node that has not updated on the day a rule lands.
    let behind = ConsensusParams {
        activations: AHEAD,
        ..params()
    };
    let newcomer = Node::bind(behind, loopback()).unwrap();
    newcomer.connect(keeper.address()).unwrap();

    // Well inside the pause before a read would be offered, so nothing here
    // can have come from a block arriving.
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && newcomer.outdated().is_none() {
        thread::sleep(Duration::from_millis(50));
    }
    let said = newcomer.outdated();
    let height = newcomer.height();
    let peers = newcomer.peer_count();

    newcomer.shutdown();
    keeper.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    let said = said.expect(
        "a ledger from past this build's rules was refused and nothing said so, which is the \
         node dropping the peer that served it and going quiet",
    );
    assert_eq!(said.required, BLOCK_VERSION + 1, "the rules it lacks");
    assert_eq!(said.known, BLOCK_VERSION, "and the rules it has");
    assert_eq!(
        height, None,
        "no block was read, so the verdict came from the handover and not from the fallback"
    );
    assert!(
        peers > 0,
        "the peer that served the ledger was dropped, and it did nothing wrong"
    );
}

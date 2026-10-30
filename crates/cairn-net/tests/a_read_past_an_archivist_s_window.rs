//! A node reading the chain from the first block reaches the tip of an
//! archivist whose chain is longer than the window it holds in memory.
//!
//! On testnet-8, about 34 000 blocks long, a wallet recovering its money and a
//! fresh explorer both stood still at block 1 152 for good. The choice reads
//! the first 1 025 blocks itself, in batches of 128 from the first, so it
//! hands over at 1 152, and from there the node asks as any node catching up
//! does: it shows the archivist where it stands, and the archivist says from
//! where to go on.
//!
//! Two things were wrong at that point, one on each end, and either alone
//! stopped the read.
//!
//! The archivist answered from the first block. It holds in memory the last
//! thousand and twenty five identifiers and one every thousand and twenty
//! four heights, and a locator from 1 152 names nothing of either but the
//! first block, so memory agreed there and the disk, which holds 1 152, was
//! never asked. The reader was told to start at 1.
//!
//! And told that, the reader could not get past what it held. It asks no
//! lower than the bottom of its own window, 129, which is blocks it already
//! follows; the next round, past them, was asked at the price of a push since
//! the round before moved nothing, so what it brought was not written down,
//! and the round after was asked from 129 again. The same two batches, for as
//! long as it ran.
//!
//! Run on the depth testnet-8 undoes, since the stop sits where the choice
//! ends, and a chain long enough that the archivist's memory holds neither
//! 1 152 nor anything a locator from there names.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::{ChainStore, HELD_WINDOW};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, MAX_REQUESTED, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::Hash32;

/// The depth testnet-8 undoes, which is where the choice hands over.
const UNDO: u64 = 1_024;

/// Where the read stood still on testnet-8: the choice ends at the first
/// block past the depth, and the batch that brought it, the ninth of 128 from
/// the first, ends here.
const STOOD_STILL_AT: u64 = 1_152;

/// Blocks the archivist holds: enough that a window of memory below its tip
/// holds nothing at or below where the read stood still, and a batch more.
const BLOCKS: u64 = STOOD_STILL_AT + HELD_WINDOW as u64 + 2 * MAX_REQUESTED as u64;

/// How long the read is given once the peer is reached. A liveness bound on a
/// loaded runner, not a measurement: over the loopback it takes seconds.
const PATIENCE: Duration = Duration::from_secs(240);

fn rules() -> ConsensusParams {
    ConsensusParams::mineable_network(UNDO)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-read-past-a-window-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn wait_until(patience: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    ready()
}

/// The chain, a block interval apart, mined once for every test here.
fn the_chain() -> &'static [Block] {
    static CHAIN: OnceLock<Vec<Block>> = OnceLock::new();
    CHAIN.get_or_init(|| {
        let params = rules();
        let mut state = LedgerState::new();
        let mut clock = params.opens_at;
        (0..BLOCKS)
            .map(|_| {
                let height = state.next_height().unwrap();
                clock += params.target_block_time;
                let reward = Note::new(
                    params.reward_at(height),
                    SecretKey::from_bytes(&[1; 32]).public_key(),
                );
                let coinbase = CoinbaseTransaction::new(height, vec![reward]);
                let block = assemble_block(&state, coinbase, vec![], &params, clock, 0).unwrap();
                let block = mine_block(block, 1 << 26).expect("a block on these rules is cheap");
                connect_block(&mut state, &block, &params, clock + 1).unwrap();
                block
            })
            .collect()
    })
}

/// A node holding `blocks` over a directory of its own, `archiving` or not.
fn holding(name: &str, blocks: &[Block], archiving: bool) -> (Node, PathBuf) {
    let directory = scratch(name);
    let (node, _) = if archiving {
        Node::open_archiving(rules(), loopback(), &directory).unwrap()
    } else {
        Node::open(rules(), loopback(), &directory).unwrap()
    };
    for block in blocks {
        node.submit_block(block.clone()).unwrap();
    }
    (node, directory)
}

/// **A wallet recovering its money, reading from the first block, reaches an
/// archivist's tip far past the window the archivist holds in memory.**
///
/// The scene of testnet-8 on 29 October: it stood still at 1 152 with the
/// archivist connected and answering, and said so after three minutes.
#[test]
fn a_read_from_the_first_block_reaches_the_tip_of_a_chain_longer_than_a_window() {
    let chain = the_chain();
    let (archivist, archivist_directory) = holding("archivist", chain, true);
    let tip = archivist.with_chain(ChainStore::tip).unwrap();
    assert!(
        archivist
            .with_chain(|chain| chain.id_at(STOOD_STILL_AT))
            .is_none(),
        "fixture: the archivist's memory holds no identifier where the read stood still"
    );
    let directory = scratch("reader");
    let (reader, _) = Node::open_recovering(rules(), loopback(), &directory, &[]).unwrap();

    reader.connect(archivist.address()).unwrap();
    let reached = wait_until(PATIENCE, || reader.with_chain(ChainStore::tip) == Some(tip));
    let (height, first) = (reader.height(), reader.blocks_from());
    reader.shutdown();
    archivist.shutdown();
    drop((reader, archivist));
    let _ = std::fs::remove_dir_all(&directory);
    let _ = std::fs::remove_dir_all(&archivist_directory);

    assert!(
        reached,
        "a node reading from the first block stood at height {height:?} after {PATIENCE:?}, \
         below the archivist's tip at {}: testnet-8 stood still at {STOOD_STILL_AT}",
        BLOCKS - 1
    );
    assert_eq!(first, Some(0), "and it read the chain from the first block");
}

/// The greeting a bare socket opens with, claiming nothing.
fn greeting() -> Message {
    Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: rules().network,
        genesis: rules().genesis.unwrap_or(Hash32::ZERO),
        height: 0,
        total_work: 0,
        listen: 0,
        nonce: 0x0115_2001,
        keeps: Keeps::default(),
    })
}

/// **Asked where a node standing at 1 152 goes on from, an archivist whose
/// memory holds nothing there answers past 1 152, from its disk.**
///
/// It answered from the first block, because memory always holds that one
/// and was asked over the whole locator before the disk was asked of any of
/// it.
#[test]
fn an_archivist_answers_a_node_far_behind_from_where_it_stands() {
    let chain = the_chain();
    let (archivist, archivist_directory) = holding("answering", chain, true);
    let standing = usize::try_from(STOOD_STILL_AT).unwrap() + 1;
    let (behind, behind_directory) = holding("behind", &chain[..standing], false);
    let locator = behind.with_chain(ChainStore::locator);
    behind.shutdown();
    drop(behind);
    assert!(
        locator.iter().all(|entry| entry.height == 0
            || archivist
                .with_chain(|chain| chain.id_at(entry.height))
                .is_none()),
        "fixture: the archivist's memory places nothing in the locator but the first block"
    );

    let network = rules().network;
    let mut socket = TcpStream::connect(archivist.address()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write_message(&mut socket, network, &greeting()).unwrap();
    write_message(&mut socket, network, &Message::GetChain { locator }).unwrap();
    let answer = loop {
        match read_message(&mut socket, network, MAX_FRAME_BYTES) {
            Ok(Incoming::Message(Message::Chain { from, count })) => break Some((from, count)),
            Ok(Incoming::Message(Message::Ping(nonce))) => {
                write_message(&mut socket, network, &Message::Pong(nonce)).unwrap();
            }
            Ok(_) => {}
            Err(_) => break None,
        }
    };
    archivist.shutdown();
    drop(archivist);
    let _ = std::fs::remove_dir_all(&archivist_directory);
    let _ = std::fs::remove_dir_all(&behind_directory);

    assert_eq!(
        answer.map(|(from, _)| from),
        Some(STOOD_STILL_AT + 1),
        "an archivist asked by a node standing at {STOOD_STILL_AT} said to go on from \
         {answer:?} (from, count), where its disk holds every block to its tip"
    );
}

/// **A node standing more than a window behind, told by a peer to go on from
/// the first block, walks past what it holds and reaches the peer's tip.**
///
/// What every archivist of 0.14.0 and earlier answers, so a reader built after
/// this still has to get past it. Asked of the layer that decides what to ask,
/// with the peer played by hand: every question about its chain is answered
/// from the first block, and every block asked for is delivered, a window of
/// the peer's allowance apart.
#[test]
fn a_node_told_to_start_from_the_first_block_walks_past_what_it_holds() {
    let chain = the_chain();
    let now = chain.last().unwrap().header.timestamp + 60;
    let standing = usize::try_from(STOOD_STILL_AT).unwrap() + 1;
    let store_of = |blocks: &[Block]| {
        let mut store = ChainStore::new(rules());
        for block in blocks {
            store.add_block(block.clone(), now).unwrap();
        }
        store
    };
    let work = store_of(chain).total_work();
    let mut reader = store_of(&chain[..standing]);
    let mut peer = PeerState {
        greeted: true,
        height: BLOCKS - 1,
        total_work: work,
        ..PeerState::default()
    };
    let mut local = Local {
        chain: &mut reader,
        keeps: Keeps::default(),
        listen: 0,
        nonce: 1,
    };

    // The rounds a walk takes from the bottom of the reader's window to past
    // its tip, eight of blocks it holds and one of new ones, and as many again.
    let rounds = 2 * (HELD_WINDOW / MAX_REQUESTED + 2);
    let mut asked_above = 0;
    let mut at = now;
    let mut said = vec![Message::Chain {
        from: 1,
        count: BLOCKS - 1,
    }];
    for _ in 0..rounds {
        let mut next = Vec::new();
        for message in said {
            let reaction = on_message(&mut local, &mut peer, message, at);
            assert!(reaction.drop_peer.is_none(), "{:?}", reaction.drop_peer);
            for reply in reaction.reply {
                match reply {
                    Message::GetChain { .. } => next.push(Message::Chain {
                        from: 1,
                        count: BLOCKS - 1,
                    }),
                    Message::GetBlocks(heights) => {
                        asked_above = asked_above.max(heights.iter().copied().max().unwrap_or(0));
                        next.extend(heights.iter().filter_map(|height| {
                            let block = chain.get(usize::try_from(*height).ok()?)?;
                            Some(Message::Block(Box::new(block.clone())))
                        }));
                    }
                    _ => {}
                }
            }
        }
        if asked_above > STOOD_STILL_AT || next.is_empty() {
            break;
        }
        said = next;
        at += 11;
    }

    assert!(
        asked_above > STOOD_STILL_AT,
        "a node standing at {STOOD_STILL_AT}, told by its peer to go on from the first block, \
         asked for nothing above {asked_above} in {rounds} rounds"
    );
}

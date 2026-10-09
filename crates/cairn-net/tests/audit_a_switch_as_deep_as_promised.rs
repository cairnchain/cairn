//! A node switches to a heavier branch handed to it in order, however much
//! of the branch there is to hold before it outweighs.
//!
//! A switch is tried only once every block of the rival is held off the
//! branch, so what a node may hold there is the deepest switch it can make.
//! That was `MAX_SIDE_BYTES` of memory, two hundred and fifty six blocks as
//! large as the rules allow, while the documents promise a thousand and
//! twenty four. Past it the sweep beside the branch let go of the block that
//! had just arrived, since a branch not yet heavier than the tip has its top
//! as its lightest block, and refused every block after it for a parent it
//! had dropped; the node answered `SideBranch` for the blocks it let go of
//! and then `UnknownParent`, which the network layer reads as history not yet
//! caught up to and asks for again, for ever (01-F2 of the audit of 8 October
//! 2026, measured there at fifty six blocks held of eighty).
//!
//! A node with a disk spills the bodies past that bound to a directory of its
//! own. These are measured on a node opened on a directory, over real full
//! blocks, valid ones, since the switch at the end applies every one of them:
//! a rival past the memory bound, handed over in order, is held whole and
//! followed once it outweighs; and a node stopped while it was putting one
//! together starts again with nothing beside its branch, its own branch and
//! its log as they were, and puts the rival together again when it is handed
//! over again.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use cairn_chain::{Accepted, ChainStore, MAX_SIDE_BYTES};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;
use cairn_store::SIDE_BODIES;

/// When the network opens: in the past of every machine running this, so a
/// node's own clock takes every block here.
const OPENS: u64 = 1_700_000_000;

/// Blocks of the rival, every one of them as full as the rules allow: past
/// `MAX_SIDE_BYTES` by a megabyte. The branch followed is one shorter.
const RIVAL: u64 = 262;

/// Rewards spendable at once, which is what lets every block of the rival
/// carry payments; and room for each block to push out of the hot set what
/// its payments put in, once the set is full.
fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_max_evictions(4_096);
    params.opens_at = OPENS;
    params
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn miner() -> SecretKey {
    SecretKey::from_bytes(&[1; 32])
}

/// A block on `state` at `height`, a minute after the last, whose coinbase
/// pays the miner in sixteen notes.
fn coinbase(params: &ConsensusParams, height: u64, salt: u8) -> CoinbaseTransaction {
    let each = Amount::from_pebbles(params.reward_at(height).as_pebbles() / 16).unwrap();
    CoinbaseTransaction::with_extra(
        height,
        vec![Note::new(each, miner().public_key()); 16],
        vec![salt],
    )
}

fn mine(params: &ConsensusParams, state: &mut LedgerState, block: Block) -> Block {
    let block = mine_block(block, 1 << 20).expect("a nonce at the floor");
    connect_block(state, &block, params, u64::MAX / 2).unwrap();
    block
}

/// The branch followed, the first block of both included, and the rival
/// forking at that first block, built once for every test here.
struct Branches {
    followed: Vec<Block>,
    rival: Vec<Block>,
}

fn branches() -> &'static Branches {
    static BUILT: OnceLock<Branches> = OnceLock::new();
    BUILT.get_or_init(build)
}

fn build() -> Branches {
    let params = params();
    let mut state = LedgerState::new();
    let first = assemble_block(
        &state,
        coinbase(&params, 0, 0),
        Vec::new(),
        &params,
        OPENS,
        0,
    )
    .unwrap();
    let first = mine(&params, &mut state, first);
    let after_first = state.clone();

    let mut followed = vec![first.clone()];
    for height in 1..RIVAL {
        let block = assemble_block(
            &state,
            coinbase(&params, height, 0),
            Vec::new(),
            &params,
            OPENS + 60 * height,
            0,
        )
        .unwrap();
        followed.push(mine(&params, &mut state, block));
    }

    // Each block spends the miner's newest notes into two hundred and fifty
    // five notes of a pebble and the change, until the next would not fit,
    // and one more cut to what room is left. The newest, because the oldest
    // fall out of the hot set as it fills, and a note that has fallen is
    // spent with a proof.
    let owner = miner().public_key();
    let dust = Amount::from_pebbles(1).unwrap();
    let per = Note::new(dust, owner).encode().len();
    let room = ChainStore::room_for_transfers(params.max_block_bytes);
    let spend = |id: NoteId, note: Note, outputs: usize| {
        let mut notes = vec![Note::new(dust, owner); outputs - 1];
        notes.push(Note::new(
            Amount::from_pebbles(note.value.as_pebbles() - (outputs as u64 - 1)).unwrap(),
            owner,
        ));
        let mut transfer = Transfer::new(vec![Input::hot(id)], notes);
        transfer.sign_input(params.network, 0, &note, &miner());
        transfer
    };
    let mut state = after_first;
    let mut newest: Vec<(NoteId, Note)> = first.coinbase.created_notes();
    let mut rival = Vec::new();
    for height in 1..=RIVAL {
        let mut transfers = Vec::new();
        let mut used = 0usize;
        while let Some((id, note)) = newest.pop() {
            let whole = spend(id, note, 256);
            let size = whole.encode().len();
            if used + size <= room {
                used += size;
                transfers.push(whole);
                continue;
            }
            let one = spend(id, note, 1).encode().len();
            if used + one <= room {
                transfers.push(spend(id, note, 1 + (room - used - one) / per));
            }
            break;
        }
        let paid = coinbase(&params, height, 1);
        let block = assemble_block(
            &state,
            paid.clone(),
            transfers,
            &params,
            OPENS + 60 * height,
            0,
        )
        .unwrap();
        let block = mine(&params, &mut state, block);
        for transfer in &block.transfers {
            newest.extend(
                transfer
                    .created_notes()
                    .into_iter()
                    .filter(|(_, note)| note.value > dust),
            );
        }
        newest.extend(paid.created_notes());
        rival.push(block);
    }
    Branches { followed, rival }
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-deep-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn files_in(directory: &Path) -> usize {
    std::fs::read_dir(directory).map_or(0, |entries| entries.flatten().count())
}

/// Hands the rival over in order and says what came back for each block.
fn hand_over(node: &Node, rival: &[Block]) -> Vec<String> {
    rival
        .iter()
        .map(|block| match node.submit_block(block.clone()) {
            Ok(Accepted::SideBranch) => "SideBranch".to_owned(),
            Ok(Accepted::Reorganised { added, .. }) => format!("Reorganised({})", added.len()),
            other => format!("{other:?}"),
        })
        .collect()
}

/// A heavier branch past the memory bound, handed over in order, is held
/// whole and followed once it outweighs.
#[test]
fn a_heavier_branch_past_what_memory_holds_is_put_together_and_followed() {
    let Branches { followed, rival } = branches();
    let params = params();
    let bytes: usize = rival.iter().map(|block| block.encode().len()).sum();
    assert!(
        bytes > MAX_SIDE_BYTES,
        "the rival has to be past what memory holds beside the branch: {bytes} against \
         {MAX_SIDE_BYTES}"
    );
    assert!(
        rival[..rival.len() - 1]
            .iter()
            .all(|block| block.header.total_work <= followed.last().unwrap().header.total_work)
            && rival.last().unwrap().header.total_work > followed.last().unwrap().header.total_work,
        "the rival has to outweigh the branch followed with its last block and not before"
    );

    let directory = scratch("followed");
    let (node, _) = Node::open(params, loopback(), &directory).unwrap();
    for block in followed {
        node.submit_block(block.clone()).unwrap();
    }
    assert_eq!(node.height(), Some(RIVAL - 1));

    let last = rival.len() - 1;
    let answers = hand_over(&node, &rival[..last]);
    let (whole, spilled, held, ceiling) = node.with_chain(|chain| {
        (
            rival[..last]
                .iter()
                .all(|block| chain.contains(&block.id())),
            chain.spilled_bytes(),
            chain.held_bytes(),
            ChainStore::held_bytes_ceiling(chain.params()),
        )
    });
    println!(
        "{last} rival blocks, {bytes} bytes, handed over: {spilled} bytes spilled, {held} held in \
         memory, {} files beside the branch",
        files_in(&directory.join(SIDE_BODIES))
    );
    assert!(
        answers.iter().all(|answer| answer == "SideBranch"),
        "a block of the rival was not held: {answers:?}"
    );
    assert!(
        whole,
        "the rival is not held whole, so a switch onto it cannot be tried"
    );
    assert!(
        spilled > 0,
        "nothing went to disk, so this did not pass the memory bound"
    );
    assert!(
        held <= ceiling,
        "memory holds {held} bytes against a ceiling of {ceiling}"
    );
    assert!(files_in(&directory.join(SIDE_BODIES)) > 0);

    let switched = hand_over(&node, &rival[last..]);
    assert_eq!(
        switched,
        vec![format!("Reorganised({})", rival.len())],
        "the rival outweighed the branch followed and was not switched to"
    );
    assert_eq!(node.id_at(RIVAL), Some(rival[last].id()));
    assert_eq!(
        node.with_chain(ChainStore::spilled_bytes),
        0,
        "the rival is followed now, and something of it is still spilled beside the branch"
    );
    assert_eq!(
        files_in(&directory.join(SIDE_BODIES)),
        0,
        "the rival's bodies went back into memory and their files stayed on the disk"
    );
    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

/// A node stopped while it was putting a rival together starts with nothing
/// beside its branch, its branch and its log as they were, and puts the rival
/// together again from the start.
///
/// Bodies spilled beside the branch are a cache. The entries naming them
/// live in the memory of the process that wrote them, so a start empties the
/// directory, a file cut short by a machine that stopped included, and the
/// branch the node followed comes back off its log untouched by any of it.
#[test]
fn a_node_stopped_while_putting_a_rival_together_starts_again_from_its_own_branch() {
    let Branches { followed, rival } = branches();
    let params = params();
    let directory = scratch("restarted");
    let side = directory.join(SIDE_BODIES);

    let (node, _) = Node::open(params, loopback(), &directory).unwrap();
    for block in followed {
        node.submit_block(block.clone()).unwrap();
    }
    // Past what memory holds beside the branch, and short of the block that
    // outweighs.
    let stopped_at = rival.len() - 2;
    let answers = hand_over(&node, &rival[..stopped_at]);
    assert!(
        answers.iter().all(|answer| answer == "SideBranch"),
        "{answers:?}"
    );
    assert!(
        node.with_chain(ChainStore::spilled_bytes) > 0 && files_in(&side) > 0,
        "nothing went to disk before the stop, so the stop tests nothing"
    );
    node.shutdown();
    drop(node);

    // What a machine stopping mid write leaves: a body cut short.
    std::fs::write(side.join("cut-short.blk"), [0x5a; 300]).unwrap();

    let (again, restored) = Node::open(params, loopback(), &directory).unwrap();
    assert_eq!(
        files_in(&side),
        0,
        "a start read bodies spilled by a run before it"
    );
    assert_eq!(
        restored.refused, 0,
        "the log was cut, so the spill reached it"
    );
    assert_eq!(
        again.height(),
        Some(RIVAL - 1),
        "the branch followed did not come back"
    );
    assert_eq!(again.id_at(RIVAL - 1), followed.last().map(Block::id));
    assert!(
        again.with_chain(|chain| rival.iter().all(|block| !chain.contains(&block.id()))),
        "a block of the rival is held after a start, which nothing on the disk vouches for"
    );

    let answers = hand_over(&again, rival);
    assert!(
        answers[..rival.len() - 1]
            .iter()
            .all(|answer| answer == "SideBranch"),
        "{answers:?}"
    );
    assert_eq!(
        answers.last(),
        Some(&format!("Reorganised({})", rival.len())),
        "the rival handed over again after the start was not switched to"
    );
    assert_eq!(again.id_at(RIVAL), rival.last().map(Block::id));
    again.shutdown();
    drop(again);
    let _ = std::fs::remove_dir_all(&directory);
}

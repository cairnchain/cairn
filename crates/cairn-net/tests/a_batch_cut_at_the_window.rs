//! A node catching up on a chain of full blocks, a window at a time.
//!
//! A peer serves a batch only as far as the asker's window of allowance pays
//! for, and of full blocks that is some forty of the hundred and twenty eight a
//! batch asks for. What the asker did about the rest was nothing: its next
//! question goes out only once nothing is awaited, and the heights left were
//! awaited until the batch's patience gave them up, a minute after the last
//! block arrived. So a node catching up on its own branch moved one window of
//! blocks a minute, where a chain of empty blocks arrives in one batch.

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
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::sync::BATCH_PATIENCE;
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;

/// Full blocks above the two every node holds.
const DEPTH: usize = 60;
/// Transfers in a full block.
const LANES: usize = 5;
/// Notes each of those transfers moves on.
const WIDTH: usize = 128;

/// What one window of a peer's allowance buys of blocks served: eight
/// thousand one hundred and ninety two units of five hundred and twelve bytes.
const ONE_WINDOW: usize = 4 * 1024 * 1024;

/// A reward is spendable at once, so the second block can fan the first
/// block's reward out into the notes every later block moves on.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    /// The next block, its reward paid out as `outputs`.
    fn mine_paying(&mut self, outputs: Vec<Note>, transfers: Vec<Transfer>) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block =
            assemble_block(&self.state, coinbase, transfers, &params, self.clock, 0).unwrap();
        let block = mine_block(block, 1 << 22).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }
}

/// `total` in `parts`, the remainder on the last, so nothing is left as fee.
fn split(total: Amount, parts: usize) -> Vec<Amount> {
    let pebbles = total.as_pebbles();
    let count = u64::try_from(parts).unwrap();
    let each = pebbles / count;
    let last = pebbles - each * (count - 1);
    (1..=count)
        .map(|part| Amount::from_pebbles(if part == count { last } else { each }).unwrap())
        .collect()
}

/// Two blocks every node holds, the second fanning five rewards out into 640
/// notes, then `DEPTH` blocks each moving all 640 on.
fn a_chain_of_full_blocks() -> (Vec<Block>, Vec<Block>) {
    let params = params();
    let key = SecretKey::from_bytes(&[1; 32]);
    let me = key.public_key();
    let reward = || vec![Note::new(params.initial_reward, me)];
    let mut forge = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    let seeds = split(params.initial_reward, LANES)
        .into_iter()
        .map(|value| Note::new(value, me))
        .collect();
    let first = forge.mine_paying(seeds, Vec::new());
    let mut lanes: Vec<Vec<(NoteId, Note)>> = Vec::new();
    let mut fanned = Vec::new();
    for lane in 0..LANES {
        let seed = first.coinbase.outputs[lane];
        let outputs = split(seed.value, WIDTH)
            .into_iter()
            .map(|value| Note::new(value, me))
            .collect();
        let at = u32::try_from(lane).unwrap();
        let mut transfer = Transfer::new(
            vec![Input::hot(NoteId::new(first.coinbase.id(), at))],
            outputs,
        );
        transfer.sign_input(params.network, 0, &seed, &key);
        lanes.push(transfer.created_notes());
        fanned.push(transfer);
    }
    let second = forge.mine_paying(reward(), fanned);
    let mut full = Vec::new();
    for _ in 0..DEPTH {
        let mut transfers = Vec::new();
        let mut next = Vec::new();
        for lane in &lanes {
            let inputs = lane.iter().map(|(id, _)| Input::hot(*id)).collect();
            let outputs = lane.iter().map(|(_, note)| *note).collect();
            let mut transfer = Transfer::new(inputs, outputs);
            for (index, (_, note)) in lane.iter().enumerate() {
                let index = u32::try_from(index).unwrap();
                transfer.sign_input(params.network, index, note, &key);
            }
            next.push(transfer.created_notes());
            transfers.push(transfer);
        }
        lanes = next;
        full.push(forge.mine_paying(reward(), transfers));
    }
    (vec![first, second], full)
}

/// **A node catching up on full blocks is handed the next window of them as
/// soon as the window turns, not a batch's patience later.**
///
/// The node holds the two first blocks and dials a peer holding sixty full
/// blocks more, which weigh more than a window of that peer's allowance buys.
/// The first batch stops where the window runs out. The rest used to be asked
/// for only once the batch's patience had given it up, a minute after its
/// last block, so the node could not reach the tip in less than that minute;
/// asked for again once the window has turned, it arrives within seconds of
/// the first. Nothing asked this, since every chain the suite caught up on was
/// of empty blocks, which arrive in one batch.
#[test]
fn a_node_catching_up_on_full_blocks_is_not_held_a_patience_per_window() {
    let (shared, full) = a_chain_of_full_blocks();
    let weights: usize = full.iter().map(|block| block.encode().len()).sum();
    assert!(
        weights > ONE_WINDOW,
        "the premise: the blocks above the two shared weigh more than one window buys"
    );
    let params = params();
    let catching_up = Node::bind(params, loopback()).unwrap();
    for block in &shared {
        catching_up.submit_block(block.clone()).unwrap();
    }
    let holding = Node::bind(params, loopback()).unwrap();
    for block in shared.iter().chain(&full) {
        holding.submit_block(block.clone()).unwrap();
    }
    let tip = holding.height();

    let began = Instant::now();
    catching_up.connect(holding.address()).unwrap();
    let patience = Duration::from_secs(BATCH_PATIENCE);
    while catching_up.height() != tip && began.elapsed() < patience {
        thread::sleep(Duration::from_millis(20));
    }
    let took = began.elapsed();
    let reached = catching_up.height();
    catching_up.shutdown();
    holding.shutdown();

    assert_eq!(
        reached, tip,
        "a node catching up on full blocks had not reached the tip a whole batch's \
         patience after it began: the rest of a batch the serving peer cut at the window \
         is asked for only once the patience has given it up"
    );
    assert!(took < patience);
}

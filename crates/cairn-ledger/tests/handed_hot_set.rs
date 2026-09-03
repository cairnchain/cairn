//! A handed over hot set that names the same note twice.
//!
//! The hot set is committed to as a tree keyed by note identifier, so a list
//! naming a note twice folds to exactly the root of the list naming it once.
//! The second entry rides in free, past every check a handover has, and the
//! root matches the header it is checked against.
//!
//! What it buys is a place in the eviction order, which is kept by age beside
//! the tree and is the one structure a receiver builds from the list rather
//! than from the commitment. Two entries for one note at two heights are two
//! places there and one entry in the tree, and the receiver's tier stops being
//! the tier the network is keeping.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::Note;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const HOT: usize = 16;
const BURIAL: u64 = 8;
const MATURITY: u64 = 4;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(HOT)
        .with_burial(BURIAL)
        .with_coinbase_maturity(MATURITY)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

struct Node {
    state: LedgerState,
    past: Vec<LedgerState>,
    blocks: Vec<Block>,
    history: Archive,
    headers: Vec<BlockHeader>,
    clock: u64,
}

impl Node {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
            history: Archive::new(),
            headers: Vec::new(),
            clock: 1_000,
        }
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize) {
        let params = params();
        for _ in 0..count {
            let height = self.state.next_height().unwrap();
            self.clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block =
                assemble_block(&self.state, coinbase, Vec::new(), &params, self.clock, 0).unwrap();
            connect_block(&mut self.state, &block, &params, NOW).unwrap();
            self.past.push(self.state.clone());
            self.blocks.push(block.clone());
            self.history
                .add(cairn_ledger::state::header_leaf(&block.header.id()))
                .unwrap();
            self.headers.push(block.header);
        }
    }

    fn anchor_height(&self) -> u64 {
        self.headers.last().unwrap().height - BURIAL
    }

    fn to_catch_up(&self) -> Vec<Block> {
        self.blocks[(self.anchor_height() as usize + 1)..].to_vec()
    }

    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let tip_history = self.state.headers_before_tip();
        let anchor = self.history.prove_in(anchor_height, tip.height).unwrap();
        let first = (anchor_height as usize + 1).saturating_sub(RECENT_HEADERS);
        state
            .handover(
                at,
                tip,
                tip_history,
                anchor,
                self.headers[(anchor_height as usize + 1)..].to_vec(),
                self.headers[first..=anchor_height as usize].to_vec(),
            )
            .unwrap()
    }
}

/// **A hot set naming one note twice is refused.**
///
/// Refused rather than tolerated, because a list that names a note twice is
/// not a ledger anybody built: there is no honest sender that produces one.
///
/// What it cost when it was taken, measured with fifteen notes handed over and
/// one of them named a second time at another height. A release build took the
/// ledger, took two blocks, and refused the third for a state root it did not
/// produce, and every honest block after it for the same reason. A debug build
/// did not get that far: the first block applied trips the assertion that the
/// map and the age index are the same size, so a stranger offering a ledger
/// could stop any node built that way.
#[test]
fn a_hot_set_naming_one_note_twice_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    // One short of the tier, so the duplicate still fits under the ceiling the
    // receiver checks and is not caught by that instead.
    node.mine_empty(&miner, (HOT - 1) + BURIAL as usize);

    let mut handover = node.handover();
    let real = handover.hot.len();
    assert!(
        accept(&handover, &params).is_ok(),
        "the honest ledger is taken, so the refusal below is about the duplicate"
    );

    // The newest note, named again with an age older than anything real. Two
    // heights rather than one: the age index is a set of pairs, so naming it
    // twice at the same height changes nothing and would test nothing.
    let mut phantom = handover
        .hot
        .iter()
        .max_by_key(|(_, entry)| entry.height)
        .copied()
        .unwrap();
    let oldest = handover
        .hot
        .iter()
        .map(|(_, entry)| entry.height)
        .min()
        .unwrap();
    assert_ne!(phantom.1.height, oldest, "the two heights have to differ");
    phantom.1.height = oldest;
    handover.hot.insert(0, phantom);
    assert_eq!(handover.hot.len(), real + 1);

    let refused = accept(&handover, &params);
    assert!(
        matches!(refused, Err(HandoverError::DuplicateHotNote(id)) if id == phantom.0),
        "a ledger naming one note twice was taken: {:?}",
        refused.map(|_| ())
    );
}

/// **And the ledger is the same one whichever way it was written.**
///
/// The refusal above is the outer line. The inner one is that the eviction
/// order has a single definition: it used to be written out by hand when a
/// handover was taken and through `remember_hot` everywhere else, and only one
/// of those two took the stale entry out when it replaced one. A ledger built
/// from a handover must be indistinguishable from the same ledger built by
/// replaying the blocks, because every node that disagrees about the eviction
/// order computes a different state root at the next overflow.
#[test]
fn a_ledger_taken_from_a_handover_evicts_in_the_same_order_as_one_replayed() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, (HOT - 1) + BURIAL as usize);

    let handover = node.handover();
    let mut taken = accept(&handover, &params).expect("an honest ledger");

    // Every block above the anchor, applied to the ledger that was handed
    // over. If the two ways of writing the tier differ anywhere, the roots
    // part company at the first block that overflows it.
    for block in node.to_catch_up() {
        connect_block(&mut taken, &block, &params, NOW)
            .expect("a node that was handed a ledger follows the chain above it");
    }
    assert_eq!(
        taken.state_root(),
        node.state.state_root(),
        "the handed ledger and the replayed one stopped agreeing"
    );
}

//! AUDIT PROBE. Not part of the shipped suite; delete after reading.
//!
//! The adjacent case to the `adopt` repair in 2e5ac9f. That repair carries the
//! watched owners across when a handed ledger replaces the one a node had, so
//! notes that fall AFTER the handover are followed. This asks about the notes
//! that fell BEFORE it and are still in the window the handover carries.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::Note;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const HOT: usize = 8;
const BURIAL: u64 = 8;
const MATURITY: u64 = 4;
/// `GRACE_BLOCKS` in `cairn-ledger::state`.
const GRACE_BLOCKS: usize = 64;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(HOT)
        .with_burial(BURIAL)
        .with_coinbase_maturity(MATURITY)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

struct Source {
    state: LedgerState,
    past: Vec<LedgerState>,
    blocks: Vec<Block>,
    headers: Vec<BlockHeader>,
    history: Archive,
    clock: u64,
}

impl Source {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
            headers: Vec::new(),
            history: Archive::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) {
        let params = params();
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
        self.history.add(header_leaf(&block.header.id())).unwrap();
        self.headers.push(block.header);
        self.blocks.push(block);
    }

    fn handover_at(&self, anchor_height: u64) -> Handover {
        let tip = *self.headers.last().unwrap();
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let anchor = self.history.prove_in(anchor_height, tip.height).unwrap();
        let first = (anchor_height as usize + 1).saturating_sub(RECENT_HEADERS);
        state
            .handover(
                at,
                tip,
                self.state.headers_before_tip(),
                anchor,
                self.headers[(anchor_height as usize + 1)..].to_vec(),
                self.headers[first..=anchor_height as usize].to_vec(),
            )
            .unwrap()
    }
}

/// A note that fell into the cold set just before the anchor is carried in the
/// handover's grace window, with a path. Once the window ages past it, that
/// path is let go of, because `watch_owner` only says who to follow from now
/// on and nothing back-fills what the window already holds.
///
/// The control is a node that replayed the same chain with the same owner
/// watched. It keeps the path.
#[test]
fn a_handed_ledger_takes_up_the_notes_that_fell_before_the_anchor() {
    let params = params();
    let miner = wallet(1);
    let owner = miner.public_key();

    let mut source = Source::new();
    // Long enough that the hot set has overflowed many times, so the cold set
    // holds plenty and the grace window is full.
    let run = RECENT_HEADERS + GRACE_BLOCKS + 40;
    for _ in 0..run {
        source.mine(&miner);
    }
    let anchor_height = source.headers.last().unwrap().height - BURIAL;

    // The handed node: takes the ledger, then follows its owner, which is what
    // `adopt` now preserves and what a wallet asks for.
    let handover = source.handover_at(anchor_height);
    let mut handed = accept(&handover, &params).expect("the handover checks out");
    handed.watch_owner(owner);

    // The control: a plain node that read the chain, following the same owner
    // from the start.
    let mut control = LedgerState::default();
    control.watch_owner(owner);
    for block in &source.blocks[..=anchor_height as usize] {
        connect_block(&mut control, block, &params, NOW).unwrap();
    }
    assert_eq!(control.state_root(), handed.state_root());

    // One note out of the window the handover carried: it fell before the
    // anchor and belongs to the owner both nodes follow.
    let (id, position, _note) = handed
        .grace_window()
        .into_iter()
        .flatten()
        .next()
        .expect("the window carried something");

    assert!(
        handed.cold().proof_of(position).is_some(),
        "the handover carried a path for it"
    );
    assert!(control.cold().proof_of(position).is_some());
    println!(
        "control follows the note: {}; handed node follows it: {}",
        control.watched_position(&id).is_some(),
        handed.watched_position(&id).is_some()
    );

    // Now let the window age past it, on both.
    for block in &source.blocks[(anchor_height as usize + 1)..] {
        connect_block(&mut handed, block, &params, NOW).unwrap();
        connect_block(&mut control, block, &params, NOW).unwrap();
    }
    let mut extra = source.state.clone();
    let mut clock = source.clock;
    for _ in 0..(GRACE_BLOCKS + 8) {
        let height = extra.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(&extra, coinbase, Vec::new(), &params, clock, 0).unwrap();
        connect_block(&mut extra, &block, &params, NOW).unwrap();
        connect_block(&mut handed, &block, &params, NOW).unwrap();
        connect_block(&mut control, &block, &params, NOW).unwrap();
    }

    let control_holds = control.cold().proof_of(position).is_some();
    let handed_holds = handed.cold().proof_of(position).is_some();
    println!(
        "after the window aged past it, control can prove it: {control_holds}, \
         handed node can prove it: {handed_holds}"
    );
    assert!(
        control_holds,
        "the control lost it too, so this proves nothing"
    );
    assert!(
        handed_holds,
        "money that fell before the anchor is visible, correct and unspendable \
         on a node that was handed its ledger"
    );
}

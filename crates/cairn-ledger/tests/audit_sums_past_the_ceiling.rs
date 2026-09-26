//! The block refusals for a sum that does not fit, produced for their cause.
//!
//! Three refusals in the block order are about arithmetic running out of room,
//! and no test had ever produced one: `ValueOverflow`, `WorkOverflow` and
//! `HeightOverflow`. A refusal nothing produces may not say what it claims, and
//! a check nothing reaches can be deleted with every test green.
//!
//! One is produced here: `ValueOverflow`, a coinbase whose outputs, each of
//! them an amount, add up to more than any amount can be.
//!
//! Beside it, the handover's own sum, `TiersAboveTheSchedule`, both where it
//! overflows and where it is only too large: the one test that reached it
//! accepted it or a state root that did not match, so either check could go
//! with the suite green.
//!
//! The rest are not produced, and why:
//!
//! - `ValueOverflow` from the fees, and from the reward plus the fees
//!   (`evaluate_block_body`). A fee is what a transfer's inputs hold beyond its
//!   outputs, the inputs are notes this chain made, and no ledger holds more
//!   than the schedule has paid, so the fees of one block and the reward
//!   beside them stay under the ceiling on any chain the rules let exist.
//! - `WorkOverflow`. It needs a ledger whose total work leaves less room than
//!   one more block's work. A replayed chain cannot get there: a block is worth
//!   at most `u64::MAX`, so it would take two to the sixty four of them. A
//!   handed ledger could, until pull request 237: its run of headers was added
//!   up saturating, so a chain rewritten to claim all the work there is was
//!   taken, and the next block was refused for this. Now the run above the
//!   anchor is added up with checked arithmetic and must fit, and the next
//!   block is one of the difficulties that run was judged at, so its work fits
//!   too.
//! - `HeightOverflow`. It needs a ledger at height `u64::MAX`, and a ledger is
//!   only ever handed over a burial below its tip, so the tip would have to
//!   sit past the last height there is. What reaches it is a handed ledger
//!   within a burial of the end followed by blocks up to it, and the header
//!   forest such a ledger commits to has close to two to the sixty four
//!   leaves, which would have to be forged root by root. Not built here, so
//!   not shown either way.

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
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::Note;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_header, ConsensusParams};
use cairn_ledger::{BlockError, LedgerState};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const BURIAL: u64 = 8;
const SPACING: u64 = 600;
const ATTEMPTS: u64 = 1 << 24;

fn rules() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(BURIAL)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain long enough to hand a ledger over from, with every state it passed
/// through.
struct Chain {
    params: ConsensusParams,
    state: LedgerState,
    past: Vec<LedgerState>,
    blocks: Vec<Block>,
}

impl Chain {
    fn new(length: u64) -> Self {
        let params = rules();
        let mut chain = Self {
            params,
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
        };
        let mut clock = 1_000u64;
        for _ in 0..length {
            let height = chain.state.next_height().unwrap();
            clock += SPACING;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.reward_at(height), wallet(1).public_key())],
            );
            let block =
                assemble_block(&chain.state, coinbase, Vec::new(), &params, clock, 0).unwrap();
            connect_block(&mut chain.state, &block, &params, NOW).unwrap();
            chain.past.push(chain.state.clone());
            chain.blocks.push(block);
        }
        chain
    }

    fn header(&self, height: u64) -> BlockHeader {
        self.blocks[height as usize].header
    }
}

/// A coinbase whose outputs are each an amount and together are not one is
/// refused for the sum, whether it is assembled or offered.
///
/// Nothing produced `BlockError::ValueOverflow`, so a block order that lost the
/// check, or answered it with another refusal, passed. Two outputs of the
/// whole supply are also more than the reward, so this is the check that says
/// so before the one that compares the claim with the reward.
#[test]
fn a_coinbase_whose_outputs_add_up_past_any_amount_is_refused_for_it() {
    let chain = Chain::new(3);
    let params = chain.params;
    let height = chain.state.next_height().unwrap();
    let whole = || Note::new(Amount::MAX_MONEY, wallet(2).public_key());
    let greedy = CoinbaseTransaction::new(height, vec![whole(), whole()]);
    assert!(
        greedy.total_output().is_none(),
        "the two outputs fit in an amount, so this asks nothing"
    );
    let clock = chain.state.tip().unwrap().timestamp + SPACING;

    let assembled = assemble_block(
        &chain.state,
        greedy.clone(),
        Vec::<Transfer>::new(),
        &params,
        clock,
        0,
    );
    assert!(
        matches!(assembled, Err(BlockError::ValueOverflow)),
        "a coinbase paying out more than any amount was assembled, or refused for \
         something else: {assembled:?}"
    );

    // Offered rather than assembled: an honest block with the coinbase swapped
    // and the header resealed over it, so every rule before the body holds.
    let honest = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), wallet(2).public_key())],
    );
    let mut block = assemble_block(&chain.state, honest, Vec::new(), &params, clock, 0).unwrap();
    block.coinbase = greedy;
    block.header.transactions_root = block.transactions_root();
    block.header = mine_header(block.header, ATTEMPTS).unwrap();
    let mut state = chain.state.clone();
    let offered = connect_block(&mut state, &block, &params, NOW);
    assert!(
        matches!(offered, Err(BlockError::ValueOverflow)),
        "a block whose coinbase pays out more than any amount was taken, or refused \
         for something else: {offered:?}"
    );
}

/// The ledger `chain` would hand over, a burial below its tip.
fn handed_over(chain: &Chain) -> Handover {
    let tip_height = chain.state.tip().unwrap().height;
    let anchor_height = tip_height - BURIAL;
    let first = (anchor_height + 1).saturating_sub(RECENT_HEADERS as u64);
    let mut archive = Archive::new();
    for height in 0..tip_height {
        archive
            .add(header_leaf(&chain.header(height).id()))
            .unwrap();
    }
    let headers: Vec<BlockHeader> = (first..=tip_height).map(|at| chain.header(at)).collect();
    let at_index = (anchor_height - first) as usize;
    chain.past[anchor_height as usize]
        .handover(
            headers[at_index],
            headers[headers.len() - 1],
            archive.forest().roots_only(),
            archive.prove_in(anchor_height, tip_height).unwrap(),
            headers[at_index + 1..].to_vec(),
            headers[..=at_index].to_vec(),
        )
        .unwrap()
}

/// A handed ledger whose notes add up to more than any amount is refused for
/// holding more than was issued, at the sum rather than past it.
///
/// The notes in the hot set and the grace window travel with their values,
/// so a receiver adds them up before it rebuilds anything, and a sum that
/// does not fit in an amount is the most any ledger could claim to hold. The
/// one test that reached `TiersAboveTheSchedule` accepted it or a state root
/// that did not match, so a check that let the sum wrap, or refused for the
/// root instead, passed.
#[test]
fn a_handed_ledger_whose_notes_add_up_past_any_amount_is_refused_for_them() {
    let chain = Chain::new(RECENT_HEADERS as u64 + BURIAL + 4);
    let params = chain.params;
    let mut handover = handed_over(&chain);
    accept(&handover, &params).expect("the ledger as the chain hands it over is taken");
    assert!(handover.hot.len() >= 2, "two notes to make too large");
    for (_, entry) in handover.hot.iter_mut().take(2) {
        entry.note = Note::new(Amount::MAX_MONEY, entry.note.owner);
    }
    let supply = handover.supply;
    assert_eq!(
        accept(&handover, &params).map(|_| ()),
        Err(HandoverError::TiersAboveTheSchedule {
            height: handover.at.height,
            held: Amount::MAX_MONEY,
            ceiling: supply,
        }),
        "a ledger holding two notes of the whole supply was not refused for what it holds"
    );
}

/// A handed ledger holding a pebble more than it says was issued is refused
/// for it, and says both numbers.
///
/// The issued total is a field the sender writes beside the notes, and the
/// state root folds in both, so a sender who mined the burial chooses both.
/// What the receiver can do is hold the notes it can count to the total, and
/// the test that reached this accepted it or a state root that did not match.
#[test]
fn a_handed_ledger_holding_more_than_it_says_was_issued_is_refused_for_it() {
    let chain = Chain::new(RECENT_HEADERS as u64 + BURIAL + 4);
    let params = chain.params;
    let mut handover = handed_over(&chain);
    let held = Amount::checked_sum(
        handover
            .hot
            .iter()
            .map(|(_, entry)| entry.note.value)
            .chain(
                handover
                    .grace
                    .iter()
                    .flatten()
                    .map(|(_, _, note)| note.value),
            ),
    )
    .unwrap();
    let declared = Amount::from_pebbles(held.as_pebbles() - 1).unwrap();
    handover.supply = declared;
    assert_eq!(
        accept(&handover, &params).map(|_| ()),
        Err(HandoverError::TiersAboveTheSchedule {
            height: handover.at.height,
            held,
            ceiling: declared,
        }),
        "a ledger holding a pebble more than it declares was not refused for it"
    );
}

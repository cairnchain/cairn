//! AUDIT: the block that is checked by more than one thread.
//!
//! Past `SPLIT_ABOVE` signatures a block's signatures are checked on several
//! threads and the answers are merged. Nothing in the workspace ever built a
//! block that large: every fixture spends one note or a handful, so the
//! threaded half of `first_failure` had never run, in a suite of fifteen
//! hundred tests.
//!
//! What that cost is measured rather than argued. `cargo mutants` deleted the
//! `!` in the spawned closure, so each thread looked for a signature that
//! *does* hold and reported it as the one that does not, and the whole suite
//! stayed green. Under that change every valid block carrying enough
//! signatures is refused, which no honest node could do anything about and no
//! test would have said a word about.
//!
//! So both answers are asked of a block over the line: one where every
//! signature holds, which must be taken, and one where a signature in the
//! middle does not, which must be refused and named.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, BlockError, ConsensusParams};
use cairn_ledger::{LedgerState, TransferError};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
/// Comfortably past the sixty four signatures that split the work, so the
/// threads really are asked for, and small enough to mine in a moment.
const SIGNATURES: usize = 80;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(1)
}

/// A ledger holding `SIGNATURES` notes of one size, all owned by one miner,
/// and the identifier of each.
///
/// A coinbase may pay at most sixteen outputs, so the notes come from several
/// blocks rather than one.
fn a_purse_of_notes() -> (LedgerState, Vec<NoteId>, Note) {
    const PER_BLOCK: usize = 16;
    let params = params();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();
    // Every note the same size, so one signature is like another and what
    // differs between the two tests below is only whether it holds.
    let per_block = u64::try_from(PER_BLOCK).unwrap();
    let each = Amount::from_pebbles(params.reward_at(0).as_pebbles() / per_block).unwrap();
    let mut ids: Vec<NoteId> = Vec::with_capacity(SIGNATURES);
    let mut clock = 1_000u64;

    while ids.len() < SIGNATURES {
        let height = state.next_height().unwrap();
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(each, miner.public_key()); PER_BLOCK]);
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        clock += params.target_block_time;
        for index in 0..u32::try_from(PER_BLOCK).unwrap() {
            if ids.len() < SIGNATURES {
                ids.push(NoteId::new(block.coinbase.id(), index));
            }
        }
    }

    // One more block, so the last coinbase is mature and its notes can be
    // spent.
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), wallet(2).public_key())],
    );
    let block =
        assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
    connect_block(&mut state, &block, &params, NOW).unwrap();

    (state, ids, Note::new(each, miner.public_key()))
}

/// One transfer spending every note, signed by their owner at every input but
/// `wrong`, which is signed by somebody else.
fn spend_them_all(ids: &[NoteId], note: &Note, wrong: Option<usize>) -> Transfer {
    let params = params();
    let held = u64::try_from(ids.len()).unwrap();
    let total = Amount::from_pebbles(note.value.as_pebbles() * held).unwrap();
    let mut transfer = Transfer::new(
        ids.iter().copied().map(Input::hot).collect(),
        vec![Note::new(total, wallet(7).public_key())],
    );
    for (index, _) in ids.iter().enumerate() {
        let owner = if wrong == Some(index) {
            wallet(9)
        } else {
            wallet(1)
        };
        transfer.sign_input(params.network, u32::try_from(index).unwrap(), note, &owner);
    }
    transfer
}

/// What a block carrying `transfer` is refused for, if anything.
fn judge(state: &LedgerState, transfer: Transfer) -> Result<Block, BlockError> {
    let params = params();
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), wallet(2).public_key())],
    );
    let clock = 1_000 + params.target_block_time * 20;
    assemble_block(state, coinbase, vec![transfer], &params, clock, 0)
}

/// Every signature holds, and a block over the line is taken.
#[test]
fn a_block_whose_signatures_all_hold_is_taken_past_the_line() {
    let (mut state, ids, note) = a_purse_of_notes();
    assert!(
        ids.len() > 64,
        "fewer signatures than the split and this asks nothing"
    );
    let transfer = spend_them_all(&ids, &note, None);

    let block = judge(&state, transfer).expect("every signature on it holds");
    connect_block(&mut state, &block, &params(), NOW).expect("and the ledger takes it");
}

/// One signature in the middle does not hold, and it is the one named.
#[test]
fn the_signature_that_does_not_hold_is_the_one_named() {
    let (state, ids, note) = a_purse_of_notes();
    let wrong = ids.len() / 2;
    let transfer = spend_them_all(&ids, &note, Some(wrong));

    match judge(&state, transfer) {
        Err(BlockError::InvalidTransfer {
            source: TransferError::InvalidSignature { input_index },
            ..
        }) => assert_eq!(input_index, wrong, "another signature was named"),
        other => panic!("a signature that does not hold was answered {other:?}"),
    }
}

//! The edge of the maturity window, and what reads it.
//!
//! Read only. Nothing here changes a source file.
//!
//! The window holds a coinbase until its notes are spendable, and the rule
//! that refuses a spend compares the height the next block will carry against
//! the height the coinbase matures at. Those two are not the same test: on the
//! last block of the wait a coinbase is still in the window and its notes are
//! already spendable. Anything that reads membership as "cannot be spent" is
//! one block out, which is what the wallet does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// On the block before it matures, a coinbase is in the window and spendable.
///
/// The window is right, and so is the rule: `advance_maturing` drops an entry
/// on the block where `matures_at <= height`, and `resolve_input` refuses only
/// while `next_height < matures_at`. So on the one block where the next height
/// equals the maturity, the entry is still there and the spend goes through.
///
/// A reader that takes presence in the window for "not spendable" therefore
/// under-reports by one block. `cairn-wallet`'s `reckon` does exactly that:
/// it counts a note as `ripening` whenever `coinbase_matures_at` answers at
/// all. Conservative rather than dangerous, since it only withholds money the
/// network would have accepted, and worth knowing because the comment beside
/// it says the reason is that the network would turn the transfer away.
#[test]
fn a_coinbase_is_in_the_window_on_the_block_it_becomes_spendable() {
    let maturity = 4u64;
    let params = ConsensusParams::testnet().with_coinbase_maturity(maturity);
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), miner.public_key())],
    );
    let first = assemble_block(&state, coinbase, Vec::new(), &params, 1_000, 0).unwrap();
    connect_block(&mut state, &first, &params, NOW).unwrap();
    let id = NoteId::new(first.coinbase.id(), 0);
    let note = Note::new(params.reward_at(0), miner.public_key());
    let source = first.coinbase.id();

    // Up to the block before the one it matures on.
    while state.next_height().unwrap() < maturity {
        assert!(
            state.coinbase_matures_at(&source).is_some(),
            "still waiting at {}",
            state.next_height().unwrap()
        );
        let height = state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        let block = assemble_block(
            &state,
            coinbase,
            Vec::new(),
            &params,
            1_000 + height * 600,
            0,
        )
        .unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
    }

    // The next block is the one it matures on, and the entry is still in the
    // window at this moment.
    assert_eq!(state.next_height().unwrap(), maturity);
    assert_eq!(
        state.coinbase_matures_at(&source),
        Some(maturity),
        "the window still names it on the block it becomes spendable"
    );

    // And the spend goes through all the same.
    let mut transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(note.value, wallet(9).public_key())],
    );
    transfer.sign_input(params.network, 0, &note, &miner);
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), miner.public_key())],
    );
    let block = assemble_block(
        &state,
        coinbase,
        vec![transfer],
        &params,
        1_000 + height * 600,
        0,
    )
    .expect("the wait is over, so the block is valid");
    connect_block(&mut state, &block, &params, NOW).expect("and it applies");
    assert!(state.coinbase_matures_at(&source).is_none());
}

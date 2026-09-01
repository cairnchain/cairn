//! Adversarial audit of the wait a coinbase serves before it can be spent.
//!
//! The reward is the one note in the chain with no parent. Every other note is
//! made by a transfer, and a transfer can be mined again on whichever branch
//! wins; a coinbase belongs to one block and dies with it. So a reward spent
//! before its block is settled is money the recipient can lose to a
//! reorganisation nobody had to cheat to cause.
//!
//! The rule is asked of the coinbase that paid a note rather than of the note,
//! so it cannot be got round by moving the note. That is what every test here
//! is really about: the hot set, the grace window and the cold set are three
//! different ways of holding the same note, and all three have to answer the
//! same way.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, disconnect_block, BlockError, TransferError, COINBASE_MATURITY,
};
use cairn_ledger::{Block, ConnectedBlock, ConsensusParams, LedgerState};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const SPACING: u64 = 600;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Mines one block paying the whole reward to `miner`, carrying `transfers`.
fn mine(
    state: &mut LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    transfers: Vec<Transfer>,
) -> (Block, ConnectedBlock) {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), miner.public_key())],
    );
    let block = assemble_block(
        state,
        coinbase,
        transfers,
        params,
        1_000 + height * SPACING,
        0,
    )
    .unwrap();
    let connected = connect_block(state, &block, params, NOW).unwrap();
    (block, connected)
}

/// A transfer that spends one note the spender still holds in full.
fn spend_as_hot(params: &ConsensusParams, id: NoteId, note: Note, owner: &SecretKey) -> Transfer {
    let mut transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(note.value, wallet(9).public_key())],
    );
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

/// What a block carrying `transfer` would be refused for, if anything.
fn refusal(
    state: &LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    transfer: Transfer,
) -> Result<Block, BlockError> {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), miner.public_key())],
    );
    assemble_block(
        state,
        coinbase,
        vec![transfer],
        params,
        1_000 + height * SPACING,
        0,
    )
}

// ---------------------------------------------------------------------------
// 1. The rule, on a note that never leaves the hot set.
// ---------------------------------------------------------------------------

#[test]
fn a_coinbase_cannot_be_spent_before_the_depth_and_can_be_spent_on_it() {
    let maturity = 8u64;
    let params = ConsensusParams::testnet().with_coinbase_maturity(maturity);
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let (first, _) = mine(&mut state, &params, &miner, Vec::new());
    let coin = NoteId::new(first.coinbase.id(), 0);
    let note = Note::new(params.reward_at(0), miner.public_key());

    // Every height from the one after it up to the one before maturity.
    while state.next_height().unwrap() < maturity {
        let height = state.next_height().unwrap();
        let refused = refusal(
            &state,
            &params,
            &miner,
            spend_as_hot(&params, coin, note, &miner),
        );
        assert!(
            matches!(
                refused,
                Err(BlockError::InvalidTransfer {
                    index: 0,
                    source: TransferError::ImmatureCoinbase { matures_at, .. },
                }) if matures_at == maturity
            ),
            "a reward paid at height 0 was spendable at height {height}: {refused:?}"
        );
        mine(&mut state, &params, &miner, Vec::new());
    }

    // And on the height it matures at, which is where it stops being a rule.
    assert_eq!(state.next_height().unwrap(), maturity);
    let (block, _) = mine(
        &mut state,
        &params,
        &miner,
        vec![spend_as_hot(&params, coin, note, &miner)],
    );
    assert_eq!(block.transfers.len(), 1);
    assert!(state.hot_note(&coin).is_none(), "the note was not spent");
}

/// The question is asked of the coinbase, so however many notes it paid, they
/// all wait the same wait.
#[test]
fn every_note_one_coinbase_paid_waits_the_same_wait() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(4);
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let split = Amount::from_pebbles(params.reward_at(0).as_pebbles() / 3).unwrap();
    let coinbase = CoinbaseTransaction::new(
        0,
        vec![
            Note::new(split, miner.public_key()),
            Note::new(split, miner.public_key()),
            Note::new(split, miner.public_key()),
        ],
    );
    let block = assemble_block(&state, coinbase, Vec::new(), &params, 1_000, 0).unwrap();
    connect_block(&mut state, &block, &params, NOW).unwrap();

    for index in 0..3u32 {
        let id = NoteId::new(block.coinbase.id(), index);
        let refused = refusal(
            &state,
            &params,
            &miner,
            spend_as_hot(&params, id, Note::new(split, miner.public_key()), &miner),
        );
        assert!(
            matches!(
                refused,
                Err(BlockError::InvalidTransfer {
                    source: TransferError::ImmatureCoinbase { .. },
                    ..
                })
            ),
            "output {index} of the same coinbase did not wait: {refused:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The same note, held the other two ways.
// ---------------------------------------------------------------------------

/// The hole the rule would have had if it had been written against the hot
/// set, where a note's creation height is recorded, rather than against the
/// coinbase that paid it.
///
/// A hot note carries the height it was made at; a cold note does not, and the
/// leaf it takes deliberately leaves it out. So a rule that read the hot entry
/// would have covered a reward until the tier pushed it out and stopped
/// covering it after, and pushing it out is something a miner can pay to have
/// happen: the tier holds a hundred and thirty one thousand notes and a block
/// may push out a thousand of them. Falling would have been how you laundered
/// a reward, which is worse than no rule at all because it looks like one.
#[test]
fn a_reward_that_fell_out_of_the_hot_set_is_no_more_spendable_for_it() {
    // A tier of four, so the reward is pushed out within a few blocks. The
    // wait has to outlast the grace window as well, or the note would be past
    // both by the time it needs a proof and half of this would go untested.
    const WAIT: u64 = 96;
    let params = ConsensusParams::testnet()
        .with_hot_capacity(4)
        .with_max_evictions(4)
        .with_coinbase_maturity(WAIT);
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let (first, _) = mine(&mut state, &params, &miner, Vec::new());
    let coin = NoteId::new(first.coinbase.id(), 0);
    let note = Note::new(params.reward_at(0), miner.public_key());

    // Enough blocks to push it out of the tier, and few enough that it is
    // nowhere near mature.
    for _ in 0..6 {
        mine(&mut state, &params, &miner, Vec::new());
    }
    assert!(
        state.hot_note(&coin).is_none(),
        "the note never left the hot set, so this tests nothing"
    );
    assert!(
        state.next_height().unwrap() < WAIT,
        "the wait was over before the note fell"
    );

    // First while it is still spendable without a proof, which is the path a
    // spender takes when a note has only just fallen.
    assert!(
        state.within_grace(&coin).is_some(),
        "the note is not in the grace window, so that path is untested"
    );
    let refused = refusal(
        &state,
        &params,
        &miner,
        spend_as_hot(&params, coin, note, &miner),
    );
    assert!(
        matches!(
            refused,
            Err(BlockError::InvalidTransfer {
                source: TransferError::ImmatureCoinbase {
                    matures_at: WAIT,
                    ..
                },
                ..
            })
        ),
        "a fallen reward was spendable through the grace window: {refused:?}"
    );

    // Then past the window, carrying its own proof, which is the whole of what
    // a cold spend is and the path that has no height to read.
    while state.within_grace(&coin).is_some() {
        mine(&mut state, &params, &miner, Vec::new());
    }
    assert!(
        state.next_height().unwrap() < WAIT,
        "the wait was over before the grace window was"
    );
    let position = state
        .cold()
        .locate(&coin, &note)
        .expect("it fell somewhere");
    let proof = state
        .cold()
        .prove(position)
        .expect("an archivist proves it");
    let mut cold = Transfer::new(
        vec![Input::cold(coin, note, position, proof)],
        vec![Note::new(note.value, wallet(9).public_key())],
    );
    cold.sign_input(params.network, 0, &note, &miner);
    let refused = refusal(&state, &params, &miner, cold);
    assert!(
        matches!(
            refused,
            Err(BlockError::InvalidTransfer {
                source: TransferError::ImmatureCoinbase {
                    matures_at: WAIT,
                    ..
                },
                ..
            })
        ),
        "a reward laundered through the cold set was spendable: {refused:?}"
    );

    // And once the wait is over it spends from the cold set like any other
    // note, so what the rule delayed it did not destroy.
    while state.next_height().unwrap() < WAIT {
        mine(&mut state, &params, &miner, Vec::new());
    }
    let position = state.cold().locate(&coin, &note).expect("still there");
    let proof = state.cold().prove(position).expect("and still provable");
    let mut cold = Transfer::new(
        vec![Input::cold(coin, note, position, proof)],
        vec![Note::new(note.value, wallet(9).public_key())],
    );
    cold.sign_input(params.network, 0, &note, &miner);
    let (block, _) = mine(&mut state, &params, &miner, vec![cold]);
    assert_eq!(block.transfers.len(), 1, "the wait outlived itself");
}

/// What happens to a reward spent through several hops before it matures: the
/// question does not arise, because there is no first hop.
///
/// The rule is on the note and not on the money, and it can be, because a note
/// that cannot move has no descendants to follow. Anything else would mean
/// carrying a mark on every note descended from a young coinbase, through
/// every transfer, in state that has to be bounded.
#[test]
fn a_reward_has_no_descendants_to_taint_because_it_cannot_move_at_all() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(6);
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let (first, _) = mine(&mut state, &params, &miner, Vec::new());
    let coin = NoteId::new(first.coinbase.id(), 0);
    let note = Note::new(params.reward_at(0), miner.public_key());

    // Every height before maturity, the first hop is refused, so no second hop
    // was ever available to anybody.
    for _ in 1..6u64 {
        assert!(
            matches!(
                refusal(
                    &state,
                    &params,
                    &miner,
                    spend_as_hot(&params, coin, note, &miner)
                ),
                Err(BlockError::InvalidTransfer {
                    source: TransferError::ImmatureCoinbase { .. },
                    ..
                })
            ),
            "the first hop went through, and the rest of this argument with it"
        );
        mine(&mut state, &params, &miner, Vec::new());
    }

    // Once it moves, what it made is an ordinary note with an ordinary parent,
    // spendable in the very next block, because a transfer can be mined again
    // on any branch and a coinbase cannot.
    let (block, _) = mine(
        &mut state,
        &params,
        &miner,
        vec![spend_as_hot(&params, coin, note, &miner)],
    );
    let child = NoteId::new(block.transfers[0].id(), 0);
    let child_note = Note::new(note.value, wallet(9).public_key());
    let (next, _) = mine(
        &mut state,
        &params,
        &miner,
        vec![spend_as_hot(&params, child, child_note, &wallet(9))],
    );
    assert_eq!(
        next.transfers.len(),
        1,
        "what a matured reward paid is not itself made to wait"
    );
}

// ---------------------------------------------------------------------------
// 3. The window itself: committed to, and exact both ways.
// ---------------------------------------------------------------------------

#[test]
fn the_window_holds_one_entry_per_paying_block_and_no_more_than_the_depth() {
    let maturity = 5u64;
    let params = ConsensusParams::testnet().with_coinbase_maturity(maturity);
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    for _ in 0..20 {
        mine(&mut state, &params, &miner, Vec::new());
        let held = state.maturing().len() as u64;
        assert!(
            held <= maturity,
            "the window holds {held} at height {:?}, past the depth of {maturity}",
            state.tip().map(|tip| tip.height)
        );
    }
    assert_eq!(
        state.maturing().len() as u64,
        maturity,
        "a chain paying every block should be carrying exactly the depth"
    );

    // A coinbase that pays nobody creates nothing that has to wait, so it
    // takes no place: the first block of every network here is one of those.
    let empty = CoinbaseTransaction::new(state.next_height().unwrap(), Vec::new());
    let height = state.next_height().unwrap();
    let block = assemble_block(
        &state,
        empty,
        Vec::new(),
        &params,
        1_000 + height * SPACING,
        0,
    )
    .unwrap();
    let before = state.maturing().len();
    connect_block(&mut state, &block, &params, NOW).unwrap();
    assert_eq!(
        state.maturing().len(),
        before - 1,
        "a block paying nobody added something to wait for"
    );
}

#[test]
fn an_undo_puts_the_window_and_the_root_back_exactly() {
    let params = ConsensusParams::testnet()
        .with_coinbase_maturity(5)
        .with_hot_capacity(4)
        .with_max_evictions(4);
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let mut connected = Vec::new();
    for _ in 0..12 {
        let (_, applied) = mine(&mut state, &params, &miner, Vec::new());
        connected.push(applied);
    }

    let window = state.maturing();
    let root = state.state_root();
    let supply = state.supply();

    // Far enough back that entries have to come off the front and go back on.
    let mut taken = Vec::new();
    for _ in 0..7 {
        taken.push(connected.pop().unwrap());
        disconnect_block(&mut state, taken.last().unwrap());
    }
    assert_ne!(
        state.maturing(),
        window,
        "seven blocks came off and nothing moved, so nothing is being tested"
    );

    for applied in taken.iter().rev() {
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
            1_000 + height * SPACING,
            0,
        )
        .unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        let _ = applied;
    }

    assert_eq!(state.maturing(), window, "the window came back different");
    assert_eq!(state.supply(), supply, "the supply came back different");
    assert_eq!(
        state.state_root(),
        root,
        "a root that is right going forward and wrong coming back forks honest nodes"
    );
}

/// The mainnet depth is the deepest reorganisation a node accepts, which is
/// the whole claim the rule makes. Written out here so that moving either
/// number without the other fails a test rather than a network.
#[test]
fn the_depth_is_the_one_the_rest_of_the_design_already_runs_on() {
    assert_eq!(
        COINBASE_MATURITY,
        cairn_ledger::handover::BURIAL,
        "a reward matures when its block is settled, and this is where settled is decided"
    );
    assert_eq!(
        ConsensusParams::testnet().coinbase_maturity,
        COINBASE_MATURITY
    );
    let devnet = ConsensusParams::for_network("devnet").unwrap();
    assert_eq!(
        devnet.coinbase_maturity, devnet.burial,
        "a throwaway network shortens both or neither"
    );
}

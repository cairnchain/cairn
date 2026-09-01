//! A transfer stripped of its signatures carries the same identifier.
//!
//! `Transfer::id()` is taken over the body and deliberately leaves out the
//! witnesses and the signatures, so that a proof refreshed on the way does not
//! make a different transaction. The cost is that anyone who sees a transfer
//! go past can replace its signatures with unsigned ones and relay something
//! byte different under the same identifier.
//!
//! That is only an attack if a node writes the identifier down before it
//! checks the signatures. This one does not, and what it passes on is the
//! transfer it holds rather than the one it was handed. Pinned here because
//! the obvious way to make relaying cheaper, a set of identifiers already
//! seen, would undo it without failing anything else.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_crypto::{SecretKey, Signature};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A reward is spendable at once here.
///
/// These tests all spend a coinbase shortly after mining it, and none of them
/// is about the wait that normally stands between the two. What the wait is
/// worth is audited in `cairn-ledger/tests/audit_coinbase_maturity.rs`.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

#[test]
fn a_twin_with_its_signatures_removed_does_not_lock_the_real_one_out() {
    let params = params();
    let miner = wallet(1);
    let payee = wallet(2);

    let mut state = LedgerState::new();
    let mut store = ChainStore::new(params);
    let mut clock = NOW;
    for _ in 0..3 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        let block: Block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut state, &block, &params, NOW).unwrap();
        store.add_block(block, NOW).unwrap();
    }

    let (id, entry) = state
        .hot_notes()
        .find(|(_, entry)| entry.note.owner == miner.public_key())
        .expect("the miner was paid");
    let note = entry.note;
    let half = note.value.as_pebbles() / 2;
    let fee = 10_000u64;
    let mut real = Transfer::new(
        vec![Input::hot(id)],
        vec![
            Note::new(Amount::from_pebbles(half).unwrap(), payee.public_key()),
            Note::new(
                Amount::from_pebbles(note.value.as_pebbles() - half - fee).unwrap(),
                miner.public_key(),
            ),
        ],
    );
    real.sign_input(params.network, 0, &note, &miner);

    // What anyone who saw it go past can make: the same body, and therefore
    // the same identifier, with nothing standing behind it.
    let mut stripped = real.clone();
    for input in &mut stripped.inputs {
        input.signature = Signature::unsigned();
    }
    assert_eq!(
        stripped.id(),
        real.id(),
        "the identifier is taken over the body, so the twin shares it"
    );
    assert_ne!(
        stripped.encode(),
        real.encode(),
        "and it is not the same bytes"
    );

    // The twin arrives first, as it would if the attacker were closer.
    assert!(
        store.accept_transfer(stripped).is_err(),
        "nothing stands behind it, so it is refused"
    );
    assert!(
        store.pooled(&real.id()).is_none(),
        "and it left nothing behind that names it"
    );

    // So the real one is still taken, which is the whole point.
    assert_eq!(
        store.accept_transfer(real.clone()),
        Ok(true),
        "the payment is not locked out by a copy of itself"
    );
    let held = store.pooled(&real.id()).expect("it is in the pool");
    assert_eq!(
        held.encode(),
        real.encode(),
        "and what a node passes on is what it holds, not what it was handed"
    );
}

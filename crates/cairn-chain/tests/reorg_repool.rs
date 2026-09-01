//! What happens to a payment carried by a block that gets undone.
//!
//! A reorganisation takes blocks off the followed branch, and with them the
//! transfers they carried. Those transfers were paid for and are still wanted:
//! the money goes back to the sender, the payment is in no block, and unless
//! somebody puts it back in the pool it is simply cancelled. The party best
//! placed to notice is the one who was told it had been sent, which is the
//! worst possible answer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{Accepted, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain built block by block, with the ledger kept alongside so a transfer
/// can be signed against the notes that really exist.
struct Source {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Source {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: NOW,
        }
    }

    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.reward_at(height), miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }
}

/// The one note this miner holds, and what it is worth.
fn one_note(state: &LedgerState, owner: &SecretKey) -> (cairn_ledger::note::NoteId, Note) {
    state
        .hot_notes()
        .find(|(_, entry)| entry.note.owner == owner.public_key())
        .map(|(id, entry)| (id, entry.note))
        .expect("the miner was paid")
}

#[test]
fn a_payment_undone_by_a_reorganisation_goes_back_in_the_pool() {
    let miner = wallet(1);
    let payee = wallet(2);
    let params = params();

    let mut source = Source::new();
    let mut store = ChainStore::new(params.clone());
    for _ in 0..3 {
        let block = source.mine(&miner, Vec::new());
        store.add_block(block, NOW).unwrap();
    }

    // A payment out of the miner's oldest note, carried by the next block.
    let (id, note) = one_note(&source.state, &miner);
    let half = note.value.as_pebbles() / 2;
    let fee = 10_000u64;
    let mut payment = Transfer::new(
        vec![Input::hot(id)],
        vec![
            Note::new(Amount::from_pebbles(half).unwrap(), payee.public_key()),
            Note::new(
                Amount::from_pebbles(note.value.as_pebbles() - half - fee).unwrap(),
                miner.public_key(),
            ),
        ],
    );
    payment.sign_input(params.network, 0, &note, &miner);
    let paid = payment.id();

    let carried = source.mine(&miner, vec![payment]);
    store.add_block(carried, NOW).unwrap();
    assert_eq!(store.height(), Some(3));
    assert!(
        store.pooled(&paid).is_none(),
        "while it is in a block it does not need to be in the pool"
    );

    // A heavier branch that forks below the block carrying the payment. It is
    // built by a second chain that never saw the payment, which is what a real
    // reorganisation looks like from here.
    let mut rival = Source::new();
    let mut branch = Vec::new();
    for _ in 0..5 {
        branch.push(rival.mine(&miner, Vec::new()));
    }

    let mut reorganised = false;
    for block in branch {
        if matches!(
            store.add_block(block, NOW),
            Ok(Accepted::Reorganised { .. })
        ) {
            reorganised = true;
        }
    }
    assert!(reorganised, "the heavier branch was taken");

    assert!(
        store.pooled(&paid).is_some(),
        "the payment the undone block carried is waiting to be mined again, \
         rather than having been cancelled by a reorganisation nobody told \
         the sender about"
    );
}

/// The other half of the rule, and the one that would be a defect if it were
/// wrong: a transfer the winning branch already carries must not come back.
/// It is refused for spending notes that are spent, which is the same answer
/// by a shorter road than looking for it.
#[test]
fn a_payment_the_winning_branch_also_carries_does_not_come_back() {
    let miner = wallet(1);
    let payee = wallet(2);
    let params = params();

    let mut source = Source::new();
    let mut store = ChainStore::new(params.clone());
    for _ in 0..3 {
        let block = source.mine(&miner, Vec::new());
        store.add_block(block, NOW).unwrap();
    }

    let (id, note) = one_note(&source.state, &miner);
    let half = note.value.as_pebbles() / 2;
    let fee = 10_000u64;
    let mut payment = Transfer::new(
        vec![Input::hot(id)],
        vec![
            Note::new(Amount::from_pebbles(half).unwrap(), payee.public_key()),
            Note::new(
                Amount::from_pebbles(note.value.as_pebbles() - half - fee).unwrap(),
                miner.public_key(),
            ),
        ],
    );
    payment.sign_input(params.network, 0, &note, &miner);
    let paid = payment.id();

    // The same ledger, so the same notes: this branch carries the payment too,
    // and then goes further.
    let mut rival = Source {
        params: params.clone(),
        state: source.state.clone(),
        clock: source.clock,
    };
    let carried = source.mine(&miner, vec![payment.clone()]);
    store.add_block(carried, NOW).unwrap();

    let mut branch = vec![rival.mine(&miner, vec![payment])];
    for _ in 0..4 {
        branch.push(rival.mine(&miner, Vec::new()));
    }
    for block in branch {
        let _ = store.add_block(block, NOW);
    }

    assert!(
        store.pooled(&paid).is_none(),
        "it is already in a block on the branch that won, so putting it back \
         in the pool would be offering a payment that has been made"
    );
}

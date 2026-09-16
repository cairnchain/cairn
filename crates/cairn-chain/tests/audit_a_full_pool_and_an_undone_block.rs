//! A pool at its ceiling, and a block coming off the branch.
//!
//! A reorganisation takes blocks off the followed branch, and with them the
//! transfers they carried. Those transfers were paid for and are still wanted,
//! so `repool` offers them back. Before offering anything it reads the pool's
//! size, and gives up when the pool is at its ceiling.
//!
//! A full pool is not a pool that refuses. `accept_transfer` makes room for
//! whoever pays a better rate than the least the pool already holds, and
//! turns away only what would not improve it. So "the pool is full" is a true
//! sentence, and it answers a different question from the one being asked,
//! which is "will this transfer be turned away". A payment paying a hundred
//! times the floor is worth more than anything a full pool of floor-payers
//! holds, and it is exactly what the reading throws out.
//!
//! And the reading gives up on the whole rewind rather than on the one
//! transfer, so one look at a full pool cancels every payment the
//! reorganisation undid, not merely the first.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{Accepted, ChainStore, MAX_POOLED};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Comfortably past the floor of an ordinary spend.
const PLAIN_FEE: u64 = 10_000;

/// A reward is spendable at once here.
///
/// These tests spend a coinbase shortly after mining it, and none of them is
/// about the wait that normally stands between the two.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// A chain built block by block, with the ledger kept alongside so a rival
/// branch can fork from a point this one has already passed.
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
            clock: 1_000,
        }
    }

    fn mine(&mut self, outputs: Vec<Note>, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(height, outputs);
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

    /// The reward, split into as many notes as a coinbase may pay, so a test
    /// can reach the pool's ceiling without mining a block per transfer.
    fn split_reward(&self, to: &SecretKey) -> Vec<Note> {
        let per_block = self.params.max_coinbase_outputs;
        let each = self.params.initial_reward.as_pebbles() / per_block as u64;
        let first = self.params.initial_reward.as_pebbles() - each * (per_block as u64 - 1);
        (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(pebbles(value), to.public_key())
            })
            .collect()
    }
}

/// Spends one note to `to`, leaving `fee` behind.
fn spend(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    to: &SecretKey,
    fee: Amount,
) -> Transfer {
    let paid = note.value.checked_sub(fee).unwrap();
    let mut transfer = Transfer::new(vec![Input::hot(id)], vec![Note::new(paid, to.public_key())]);
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

/// A full pool is not a pool that refuses, so it is not a reason to cancel a
/// payment a reorganisation undid.
///
/// The pool here is filled to its ceiling with transfers paying the plain fee.
/// The block that is then undone carries one paying a hundred times that,
/// which is worth more than anything the pool holds and which
/// `accept_transfer` would let in by displacing the cheapest. It never gets
/// asked.
#[test]
fn a_payment_undone_comes_back_even_when_the_pool_is_full() {
    let miner = wallet(1);
    let payee = wallet(2);
    let params = params();

    let mut source = Source::new();
    let mut store = ChainStore::new(params);

    // Enough notes to fill the pool, and one more for the payment that the
    // reorganisation will undo. Every one of them is paid by a block below
    // the fork, so the rival branch carries them too and nothing in the pool
    // is made impossible by the reorganisation itself.
    let mut notes: Vec<(NoteId, Note)> = Vec::new();
    while notes.len() <= MAX_POOLED {
        let outputs = source.split_reward(&miner);
        let block = source.mine(outputs.clone(), Vec::new());
        store.add_block(block.clone(), NOW).unwrap();
        for (index, note) in outputs.into_iter().enumerate() {
            notes.push((
                NoteId::new(block.coinbase.id(), u32::try_from(index).unwrap()),
                note,
            ));
        }
    }

    // The fork point: a rival that has seen every funding block and nothing
    // after it.
    let mut rival = Source {
        params,
        state: source.state.clone(),
        clock: source.clock,
    };

    // A payment worth far more than anything the pool will hold, carried by
    // the block that is about to be undone.
    let (id, note) = notes[MAX_POOLED];
    let payment = spend(&params, id, note, &miner, &payee, pebbles(PLAIN_FEE * 100));
    let paid = payment.id();
    let carried = source.mine(source.split_reward(&miner), vec![payment]);
    store.add_block(carried, NOW).unwrap();
    assert!(
        store.pooled(&paid).is_none(),
        "while it is in a block it does not need to be in the pool"
    );

    // The pool, filled to its ceiling with the least it will carry.
    for (id, note) in notes.iter().take(MAX_POOLED) {
        let filler = spend(&params, *id, *note, &miner, &wallet(3), pebbles(PLAIN_FEE));
        assert!(store.accept_transfer(filler).unwrap());
    }
    assert_eq!(store.pool_len(), MAX_POOLED, "the ceiling is reached");

    // A heavier branch that forks below the block carrying the payment.
    let mut reorganised = false;
    for _ in 0..5 {
        let block = rival.mine(rival.split_reward(&miner), Vec::new());
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
        "a payment paying a hundred times the floor was thrown away because \
         the pool was full of transfers paying the floor. A full pool makes \
         room for whoever pays a better rate; reading its size is a true \
         answer to a different question, and it is given for the whole \
         rewind rather than for the one transfer"
    );
}

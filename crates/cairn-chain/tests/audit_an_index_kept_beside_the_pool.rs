//! Two indexes kept alongside the pool rather than derived from it.
//!
//! Every transfer arriving has to be asked whether anything already waiting
//! spends a note it spends. That question used to be answered by walking every
//! input of every pooled transfer, on every arrival, so filling a pool cost the
//! square of its ceiling, and the ceiling is a number an attacker reaches by
//! paying the floor. The reason for not doing that was already written in this
//! crate, beside `pool_by_rate`, and it is the same reason: a peer sending
//! transfers as fast as it can would otherwise decide how much work each one
//! causes.
//!
//! Which is why both are held here now. This file was written citing
//! `pool_by_rate` as the precedent for the index it checks, and checked only
//! the one it was written for. They are the same structure kept for the same
//! reason, moved by the same four places, and deleting the removal of a
//! `pool_by_rate` entry in `drop_pooled` left the whole suite green.
//!
//! What a stale entry there costs is worse than the one this file started
//! with. `accept_transfer` walks the cheap end to make room and stops at
//! `let Some(losing) = self.pool.get(victim) else { return Ok(false) }`, so
//! one entry naming a transfer that has gone makes a full pool refuse
//! everything that arrives after it. And the set grows under neither of the
//! pool's two ceilings, because neither counts it.
//!
//! What the removal costs is that the index is now a thing that can be wrong.
//! Derived, it could not disagree with the pool; kept, it agrees only for as
//! long as every place that moves the pool remembers to move it too. So that
//! is what these hold: after every kind of move the pool makes, the index says
//! exactly what a fresh pass over the pool would say, in both directions. A
//! missing entry lets two spends of one note both wait. A stale one is harder
//! to see, and that is the point: the next spend of that note overwrites it
//! and nothing looks wrong, so what is left is an entry per note per
//! displacement, under neither of the two ceilings the pool has.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

use cairn_chain::{Accepted, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::hash::Hash32;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const PLAIN_FEE: u64 = 10_000;

/// A reward is spendable at once here.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// What the index would say if it were still being derived.
fn derived(store: &ChainStore) -> BTreeMap<NoteId, Hash32> {
    let mut spenders = BTreeMap::new();
    for (id, transfer) in store.pooled_transfers() {
        for input in &transfer.inputs {
            spenders.insert(input.note_id, *id);
        }
    }
    spenders
}

/// The index as it is kept.
fn kept(store: &ChainStore) -> BTreeMap<NoteId, Hash32> {
    store
        .pooled_spenders()
        .map(|(note, holder)| (*note, *holder))
        .collect()
}

/// The rate index as the pool itself would answer it.
///
/// A list and not a map, in both directions, because the kept side is a set of
/// pairs and could hold one identifier twice at two different rates. Folded
/// into a map that would be invisible, which is the shape of mistake this
/// whole file is about.
fn derived_rates(store: &ChainStore) -> Vec<(Hash32, u128)> {
    let mut rates: Vec<(Hash32, u128)> = store.pooled_rates().map(|(id, at)| (*id, at)).collect();
    rates.sort_unstable();
    rates
}

/// The rate index as it is kept.
fn kept_rates(store: &ChainStore) -> Vec<(Hash32, u128)> {
    let mut rates: Vec<(Hash32, u128)> = store.pooled_by_rate().map(|(at, id)| (*id, at)).collect();
    rates.sort_unstable();
    rates
}

#[track_caller]
fn agrees(store: &ChainStore, after: &str) {
    let kept = kept(store);
    let derived = derived(store);
    assert_eq!(
        kept, derived,
        "after {after} the index kept beside the pool disagrees with the pool \
         itself. A note it does not name that the pool does spend lets two \
         spends of one note both wait; a note it names that the pool no longer \
         spends is quietly overwritten by the next spend of it, and until then \
         it is an entry under neither ceiling the pool has"
    );
    assert_eq!(
        kept_rates(store),
        derived_rates(store),
        "after {after} the rate index kept beside the pool disagrees with the \
         pool itself. An entry naming a transfer that has gone stops the walk \
         `accept_transfer` makes to free room, so a full pool refuses \
         everything; a transfer missing from it is one no miner reading this \
         node ever picks; and neither of the pool's two ceilings counts either"
    );
}

/// A chain built block by block, with the ledger kept alongside.
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

/// Every way the pool moves, and the index still says what the pool says.
///
/// The moves are the four that exist: a transfer taken, a transfer displaced
/// by one paying more for the same note, the pool reconsidered because the
/// branch moved, and transfers offered back by a rewind.
#[test]
fn the_index_says_what_the_pool_says_after_every_move() {
    let miner = wallet(1);
    let payee = wallet(2);
    let params = params();

    let mut source = Source::new();
    let mut store = ChainStore::new(params);

    let mut notes: Vec<(NoteId, Note)> = Vec::new();
    for _ in 0..4 {
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
    agrees(&store, "a chain with nothing in the pool");

    // Taken.
    for (id, note) in notes.iter().take(8) {
        let transfer = spend(&params, *id, *note, &miner, &payee, pebbles(PLAIN_FEE));
        assert!(store.accept_transfer(transfer).unwrap());
    }
    agrees(&store, "eight transfers were taken");

    // Displaced: the same note, paying more.
    let (id, note) = notes[0];
    let better = spend(
        &params,
        id,
        note,
        &miner,
        &wallet(3),
        pebbles(PLAIN_FEE * 10),
    );
    let replacing = better.id();
    assert!(store.accept_transfer(better).unwrap(), "it pays more");
    assert_eq!(store.pool_len(), 8, "it took a place, not a seat");
    agrees(
        &store,
        "one transfer displaced another spending the same note",
    );
    assert_eq!(
        store.pooled_spenders().find(|(note, _)| **note == id),
        Some((&id, &replacing)),
        "the note is spoken for by the transfer that displaced, not the one displaced"
    );

    // The fork point, before the branch carries any of this.
    let mut rival = Source {
        params,
        state: source.state.clone(),
        clock: source.clock,
    };

    // Reconsidered: a block carrying four of the pooled transfers makes them
    // impossible, and the pool drops them without going through a displacement.
    let carried: Vec<Transfer> = store
        .pooled_transfers()
        .take(4)
        .map(|(_, transfer)| transfer.clone())
        .collect();
    let block = source.mine(source.split_reward(&miner), carried);
    store.add_block(block, NOW).unwrap();
    assert_eq!(store.pool_len(), 4, "what the block carried left the pool");
    agrees(&store, "a block carried four of them away");

    // Offered back: a heavier branch undoes that block, and its transfers are
    // offered to the pool again.
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
    assert_eq!(store.pool_len(), 8, "the four came back to join the four");
    agrees(&store, "a reorganisation offered four of them back");
}

/// A displaced transfer takes every note it spoke for with it, not only the
/// one it lost.
///
/// A transfer spending two notes, displaced by one spending the first, leaves
/// the second named in the index by a transfer that is no longer in the pool.
/// Nothing refuses the next spend of that note, which is why this is not
/// visible from outside: the entry is simply overwritten. What is left is an
/// entry per note per displacement, and displacing is something a stranger
/// does as often as it cares to between two blocks, at the price of a fee it
/// gets back when its own transfer is displaced in turn. The pool has a
/// ceiling in transfers and a ceiling in bytes, and this index sat under
/// neither.
#[test]
fn a_displaced_transfer_frees_every_note_it_spoke_for() {
    let miner = wallet(1);
    let payee = wallet(2);
    let params = params();

    let mut source = Source::new();
    let mut store = ChainStore::new(params);
    let mut notes: Vec<(NoteId, Note)> = Vec::new();
    for _ in 0..2 {
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

    let (first, one) = notes[0];
    let (second, two) = notes[1];

    let together = one
        .value
        .checked_add(two.value)
        .unwrap()
        .checked_sub(pebbles(PLAIN_FEE))
        .unwrap();
    let mut both = Transfer::new(
        vec![Input::hot(first), Input::hot(second)],
        vec![Note::new(together, payee.public_key())],
    );
    both.sign_input(params.network, 0, &one, &miner);
    both.sign_input(params.network, 1, &two, &miner);
    let spending_both = both.id();
    assert!(store.accept_transfer(both).unwrap());
    agrees(&store, "a transfer spending two notes was taken");

    // Paying for what it displaces, the floor again on top, and a better rate.
    let taking_the_first = spend(
        &params,
        first,
        one,
        &miner,
        &wallet(3),
        pebbles(PLAIN_FEE * 20),
    );
    assert!(
        store.accept_transfer(taking_the_first).unwrap(),
        "it pays for what it displaces and the floor again"
    );
    assert!(
        store.pooled(&spending_both).is_none(),
        "the transfer spending both notes was displaced"
    );

    agrees(
        &store,
        "a transfer spending two notes was displaced by one spending the first",
    );
}

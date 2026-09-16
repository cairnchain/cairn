//! What one block costs a node that is holding a pool.
//!
//! Every block that moves the branch makes `prune_pool` ask the whole pool
//! again, because what a transfer pays and what it takes both move with the
//! state. The note on it says exactly that, and it is true of both halves of
//! the rate. What it was also doing was checking every signature again.
//!
//! A signature covers the network, the version, the transfer's own identifier,
//! the position of the input, and the value and owner of the note being spent.
//! Every one of those is settled by the transfer and by the identifier of the
//! note it names, and a note identifier commits to the note. So the state
//! cannot move the answer, and everything in this pool arrived through
//! `accept_transfer`, which asked.
//!
//! Counted in bytes fed to a hasher, which is a number two machines agree on,
//! and not in how long a block took. The curve verifications saved with them
//! do not show in this count at all and are the larger half.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::hash::counting;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const PLAIN_FEE: u64 = 10_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

struct Node {
    params: ConsensusParams,
    ledger: LedgerState,
    store: ChainStore,
    clock: u64,
}

impl Node {
    fn new() -> Self {
        let params = params();
        Self {
            params,
            ledger: LedgerState::new(),
            store: ChainStore::new(params),
            clock: 1_000,
        }
    }

    fn mine_paying(&mut self, miner: &SecretKey, outputs: Vec<Note>) -> Vec<(NoteId, Note)> {
        let height = self.ledger.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(height, outputs.clone());
        let block = assemble_block(
            &self.ledger,
            coinbase,
            Vec::<Transfer>::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.ledger, &block, &self.params, NOW).unwrap();
        self.store.add_block(block.clone(), NOW).unwrap();
        let _ = miner;
        outputs
            .into_iter()
            .enumerate()
            .map(|(index, note)| {
                (
                    NoteId::new(block.coinbase.id(), u32::try_from(index).unwrap()),
                    note,
                )
            })
            .collect()
    }

    /// Mines an empty block and reports what applying it hashed.
    fn cost_of_one_more_block(&mut self) -> u64 {
        let height = self.ledger.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(height, Vec::new());
        let block = assemble_block(
            &self.ledger,
            coinbase,
            Vec::<Transfer>::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.ledger, &block, &self.params, NOW).unwrap();

        counting::reset();
        self.store.add_block(block, NOW).unwrap();
        counting::hashed()
    }
}

fn spend(params: &ConsensusParams, id: NoteId, note: Note, owner: &SecretKey) -> Transfer {
    let paid = note.value.checked_sub(pebbles(PLAIN_FEE)).unwrap();
    let mut transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(paid, wallet(2).public_key())],
    );
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

/// Fills the pool with `pooled` valid one input transfers, then reports what
/// one further block costs the node, in bytes hashed.
fn cost_with_a_pool_of(pooled: usize) -> u64 {
    let miner = wallet(1);
    let rules = params();
    let mut node = Node::new();
    let per_block = rules.max_coinbase_outputs;

    let each = rules.initial_reward.as_pebbles() / per_block as u64;
    let first = rules.initial_reward.as_pebbles() - each * (per_block as u64 - 1);

    let mut notes = Vec::new();
    while notes.len() < pooled {
        let outputs: Vec<Note> = (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(Amount::from_pebbles(value).unwrap(), miner.public_key())
            })
            .collect();
        notes.extend(node.mine_paying(&miner, outputs));
    }

    for (id, note) in notes.into_iter().take(pooled) {
        let transfer = spend(&rules, id, note, &miner);
        assert_eq!(node.store.accept_transfer(transfer), Ok(true));
    }

    node.cost_of_one_more_block()
}

/// What a block costs a node holding a pool, per transfer waiting in it.
///
/// The claim the whole design rests on is that what a node costs does not grow
/// with the chain. This is the narrower one beside it: what a block costs does
/// not grow with the pool, which is a thing anyone can fill to its ceiling for
/// the price of the fees.
#[test]
fn a_block_costs_about_the_same_whatever_is_waiting_in_the_pool() {
    let empty = cost_with_a_pool_of(0);
    let some = cost_with_a_pool_of(64);
    let more = cost_with_a_pool_of(256);

    let over = more.saturating_sub(empty);
    assert!(
        over < 256,
        "a pool of 256 transfers added {over} bytes hashed to a block, which is {} a transfer. \
         Before the signatures stopped being checked again it was 169 a transfer, and the pool \
         holds four thousand of them",
        over / 256
    );
    assert!(
        some >= empty && more >= some,
        "the cost is meant to be read as growing with the pool or not at all: {empty}, {some}, \
         {more}"
    );
}

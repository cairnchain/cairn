//! AUDIT SCRATCH TEST — end-to-end consequence of block-id malleability.
//!
//! A block id is the header id, and the header commits to signatures/witnesses
//! nowhere (its `transactions_root` is a Merkle root over `Transfer::id()`,
//! which excludes them). So for any honest block B, an attacker can build a twin
//! B' = B with one input signature replaced by garbage: same id, different
//! bytes, invalid.
//!
//! `ChainStore` keys both its dedup and its invalid-block memory on the block
//! id. Deliver B' before B and the node stores B' under B's id, marks that id
//! invalid, and then treats the honest B as a duplicate — so the honest block is
//! refused. This is a work-free, targeted relay DoS (the twin inherits B's PoW).
//!
//! This test asserts the honest block is still accepted after the twin. It
//! FAILS on current code.

#![allow(
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{Accepted, ChainStore};
use cairn_crypto::{SecretKey, Signature};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// Produces real (mined, valid) blocks on a private copy of the ledger.
struct Branch {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Branch {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
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
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists at min difficulty");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine(miner, Vec::new())).collect()
    }
}

fn coinbase_note(block: &Block, params: &ConsensusParams, miner: &SecretKey) -> (NoteId, Note) {
    (
        NoteId::new(block.coinbase.id(), 0),
        Note::new(params.initial_reward, miner.public_key()),
    )
}

#[test]
fn an_invalid_twin_seen_first_must_not_lock_out_the_honest_block() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(2);

    // A branch: genesis plus eleven more, then a block that spends a coinbase
    // note to Alice. That last block carries a real signature.
    let mut branch = Branch::new(params);
    let shared = branch.mine_empty(&miner, 12);
    let (funded, funded_note) = coinbase_note(&shared[11], &params, &miner);

    let mut payment = Transfer::new(
        vec![Input::hot(funded)],
        vec![Note::new(funded_note.value, alice.public_key())],
    );
    payment.sign_input(params.network, 0, &funded_note, &miner);
    let honest = branch.mine(&miner, vec![payment]);

    // The attacker's twin: same block, one signature turned to garbage.
    let mut twin = honest.clone();
    twin.transfers[0].inputs[0].signature = Signature::from_bytes(&[0xABu8; 64]);
    assert_eq!(twin.id(), honest.id(), "the twin shares the honest id");
    assert_ne!(twin.encode(), honest.encode(), "yet is a different block");

    // A victim node follows the shared prefix.
    let mut store = ChainStore::new(params);
    for block in &shared {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.height(), Some(11));

    // The attacker delivers the INVALID twin first. It is correctly rejected.
    let twin_outcome = store.add_block(twin.clone(), NOW);
    assert!(
        twin_outcome.is_err(),
        "the twin is invalid: {twin_outcome:?}"
    );

    // The honest block now arrives. It must still be accepted and extend the
    // chain. On current code the id-keyed caches refuse it.
    let honest_outcome = store.add_block(honest.clone(), NOW);
    assert_eq!(
        honest_outcome,
        Ok(Accepted::Extended),
        "the honest block was locked out by an invalid twin that shared its id \
         (got {honest_outcome:?}); the node cannot follow the real chain past this height"
    );
    assert_eq!(
        store.height(),
        Some(12),
        "the node should have followed the honest block to height 12"
    );
}

//! AUDIT SCRATCH TEST: end-to-end consequence of block-id malleability.
//!
//! A block id is the header id, and the header commits to signatures/witnesses
//! nowhere (its `transactions_root` is a Merkle root over `Transfer::id()`,
//! which excludes them). So for any honest block B, an attacker can build a twin
//! B' = B with one input signature replaced by garbage: same id, different
//! bytes, invalid.
//!
//! `ChainStore` keys both its dedup and its invalid-block memory on the block
//! id. Deliver B' before B and the node stores B' under B's id, marks that id
//! invalid, and then treats the honest B as a duplicate: the honest block is
//! refused. This is a work-free, targeted relay DoS (the twin inherits B's PoW).
//!
//! The first test here asserts the honest block is still accepted after the
//! twin, which is the case the identifier-keyed caches used to lose.
//!
//! The second is the other order. A twin of a block the node is *already*
//! following inherits its work and its identifier, and the checks that stand
//! between a stranger and this node's memory are all about the header, which
//! the twin copies exactly. What decided the matter was the body it arrived
//! with, and the body is the one part an identifier does not commit to.
//!
//! The third is the half the branch does not settle: a block held *off* the
//! branch, which is every rival a node is weighing. Nothing there has been
//! applied, so neither body is known good, and whichever arrived last used to
//! take the place of whichever arrived first. Last is the easy half of that
//! race, and what it buys is a heavier branch the node then refuses, with the
//! peer that brought it blamed for a body it never sent.

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

/// A reward is spendable at once here.
///
/// These tests all spend a coinbase shortly after mining it, and none of them
/// is about the wait that normally stands between the two. What the wait is
/// worth is audited in `cairn-ledger/tests/audit_coinbase_maturity.rs`.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
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

    /// A second branch carrying on from where this one stands.
    fn fork(&self) -> Self {
        Self {
            params: self.params,
            state: self.state.clone(),
            clock: self.clock,
        }
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

/// A twin cannot take the body of a block this node already follows.
///
/// Same header, so the same identifier and the same work, and a body paying
/// the reward to somebody else. The twin used to fall through the held-block
/// check because the bodies differ, pass the work and the depth floor because
/// the header is the real one's, and then have `hold` write its body over the
/// real one. The node answered `SideBranch` and carried on at the same height,
/// following the real block's identifier while holding the forgery under it.
/// `block_at` is the accessor a node serves blocks from and writes its log
/// from, so what it answers with at a height on the branch is not this
/// crate's business alone.
///
/// It costs the sender a copy. The branch is what settles it: a block already
/// on the branch was applied, and no body arriving later reopens that.
#[test]
fn a_twin_of_a_block_already_followed_cannot_take_its_body() {
    let params = params();
    let miner = wallet(1);
    let thief = wallet(9);

    let mut branch = Branch::new(params);
    let blocks = branch.mine_empty(&miner, 12);

    let mut store = ChainStore::new(params);
    for block in &blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.height(), Some(11));

    let real = &blocks[5];
    let mut twin = real.clone();
    twin.coinbase =
        CoinbaseTransaction::new(5, vec![Note::new(params.reward_at(5), thief.public_key())]);
    assert_eq!(twin.id(), real.id(), "the twin shares the identifier");
    assert_ne!(twin.encode(), real.encode(), "yet is a different block");

    let outcome = store.add_block(twin.clone(), NOW);
    assert_eq!(
        outcome,
        Ok(Accepted::Duplicate),
        "a block already on the branch is settled, whatever body arrives \
         under its identifier: {outcome:?}"
    );
    assert_eq!(
        store.block_at(5),
        Some(real),
        "and what the node holds at that height is still the block it applied"
    );
    assert_eq!(store.height(), Some(11), "with nothing else disturbed");
}

/// Nor of a block held off it, which is where the same copy still landed.
///
/// The branch settles the case above and says nothing about this one. A block
/// a node is holding aside has not been applied, so neither body under that
/// identifier is known good, and `hold` wrote whichever arrived last over
/// whichever arrived first. Last is the easy half of that race: a twin is made
/// by copying a block, so it cannot exist before the block it copies, and an
/// attacker who merely answers every honest delivery wins it every time.
///
/// What that buys is the branch. The forgery sits under the real block's
/// identifier until the branch it is on becomes the heaviest, and then the
/// switch onto it reads the forged body, fails on a root that does not match,
/// and leaves the node on the lighter branch. `cairn-net` reads that refusal
/// as `DropReason::BadBlock` against whoever delivered the block above it,
/// which is the peer carrying the winning chain: it is disconnected and
/// refused for a body it never sent.
///
/// And offering the real block again does not undo it. It weighs no more than
/// the branch already followed, so it is filed aside as a side branch, and
/// nothing re-weighs the block above it: measured here, the node stays where
/// it was until the tip of the winning branch is offered a second time.
///
/// So a body is taken only for an identifier this node holds no body for. The
/// one it holds is the one it tries; if that fails it is dropped, and the next
/// to arrive gets its turn, which is what
/// `an_invalid_twin_seen_first_must_not_lock_out_the_honest_block` measures.
#[test]
fn a_twin_of_a_block_held_off_the_branch_cannot_take_its_body() {
    let params = params();
    let miner = wallet(1);
    let thief = wallet(9);

    // Eleven blocks both branches share, then two on the one this node
    // follows and three on the rival, which is therefore the heavier.
    let mut branch = Branch::new(params);
    let shared = branch.mine_empty(&miner, 11);
    let mut aside = branch.fork();
    let followed = branch.mine_empty(&miner, 2);
    let rival = aside.mine_empty(&wallet(2), 3);

    let mut store = ChainStore::new(params);
    for block in shared.iter().chain(followed.iter()) {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.height(), Some(12));

    // The rival's first two blocks, held aside: at that point it carries the
    // same work as the branch being followed, and a tie keeps what is followed.
    for block in &rival[..2] {
        assert_eq!(
            store.add_block(block.clone(), NOW),
            Ok(Accepted::SideBranch)
        );
    }
    assert_eq!(store.block(&rival[0].id()), Some(&rival[0]));

    // The twin: the real header, so the real identifier and the real work,
    // and a body paying the reward to somebody else.
    let mut twin = rival[0].clone();
    twin.coinbase = CoinbaseTransaction::new(
        11,
        vec![Note::new(params.reward_at(11), thief.public_key())],
    );
    assert_eq!(twin.id(), rival[0].id(), "the twin shares the identifier");
    assert_ne!(twin.encode(), rival[0].encode(), "yet is a different block");

    assert_eq!(
        store.add_block(twin, NOW),
        Ok(Accepted::SideBranch),
        "the branch it hangs from is no heavier for the copy arriving"
    );
    assert_eq!(
        store.block(&rival[0].id()),
        Some(&rival[0]),
        "the body this node holds under that identifier is the one it was \
         holding, not the one that arrived over it"
    );

    // And then the block that makes the rival the heaviest branch, from the
    // peer that has it. The switch reads the body held for the block below,
    // so this is where a forgery taken above would be paid for.
    assert_eq!(
        store.add_block(rival[2].clone(), NOW),
        Ok(Accepted::Reorganised {
            removed: followed.iter().rev().map(Block::id).collect(),
            added: rival.iter().map(Block::id).collect(),
        }),
        "the heavier branch was refused, and the peer that brought it blamed"
    );
    assert_eq!(store.height(), Some(13));
    assert_eq!(store.tip(), Some(rival[2].id()));
}

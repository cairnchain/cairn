//! AUDIT SCRATCH TEST: end-to-end consequence of block-id malleability.
//!
//! A block id is the header id, and the header used to commit to signatures
//! and witnesses nowhere (its `transactions_root` was a Merkle root over
//! `Transfer::id()`, which excludes them). So for any honest block B, an
//! attacker could build a twin B' = B with one input signature replaced by
//! garbage: same id, different bytes, invalid. The root commits to each
//! transfer's whole encoding now, so that twin is refused as a body its header
//! does not name; any other body under a real header still shares the id, and
//! the tests here hold what the chain does about that.
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

use cairn_chain::{Accepted, ChainError, ChainStore};
use cairn_crypto::{SecretKey, Signature};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, ColdWitness, Input, Transfer, Witness};
use cairn_ledger::validation::{
    assemble_block, connect_block, evaluate_block_body, mine_block, BlockError, ConsensusParams,
};
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
/// whichever arrived first. Last is the easy half of that race: an attacker
/// who merely answers every honest delivery wins it every time. First is the
/// other order, which a copy forwarded without being checked also wins; see
/// `a_side_block_whose_body_is_not_the_one_its_header_names_is_refused_before_it_is_held`
/// for what answers that.
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

/// A node on a two block branch, a rival of `rival_len` blocks off the same
/// eleven, and a copy of the rival's first block: the real header, and a body
/// paying the reward to somebody else.
fn a_node_behind_a_rival(rival_len: usize) -> (ChainStore, Vec<Block>, Block) {
    let params = params();
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let shared = branch.mine_empty(&miner, 11);
    let mut aside = branch.fork();
    let followed = branch.mine_empty(&miner, 2);
    let rival = aside.mine_empty(&wallet(2), rival_len);

    let mut store = ChainStore::new(params);
    for block in shared.iter().chain(followed.iter()) {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.height(), Some(12));

    let mut copy = rival[0].clone();
    copy.coinbase = CoinbaseTransaction::new(
        11,
        vec![Note::new(params.reward_at(11), wallet(9).public_key())],
    );
    assert_eq!(copy.id(), rival[0].id(), "the copy shares the identifier");
    assert_ne!(copy.encode(), rival[0].encode(), "yet is a different block");
    (store, rival, copy)
}

/// A copy of a side block whose body is not the one its header names is
/// refused on arrival, and blamed on whoever sent it.
///
/// A block that loses the fork choice is held without being applied, and the
/// first body held under an identifier is the one tried. That order is not
/// safe either: a copy cannot exist before the block it copies, but it can
/// reach a node before the real one does, since forwarding without checking
/// is quicker than checking. The copy was held, the real body offered after it
/// was thrown away, and the delivery of the block that made that branch the
/// heaviest came back refused for the copy's body, which `cairn-net` charged to
/// the peer that delivered it.
///
/// Whether a body is the one its header names needs no ledger: it is one
/// Merkle root. Nothing asked it of a block held aside, so a node holding
/// whatever body arrived first passed, and the delivery of the real third
/// block was answered `InvalidBlock` for the first.
#[test]
fn a_side_block_whose_body_is_not_the_one_its_header_names_is_refused_before_it_is_held() {
    let (mut store, rival, copy) = a_node_behind_a_rival(3);

    let refused = store.add_block(copy.clone(), NOW);
    assert!(
        matches!(
            &refused,
            Err(ChainError::InvalidBlock {
                id,
                source: BlockError::TransactionsRootMismatch { .. },
            }) if *id == copy.id()
        ),
        "a body that does not produce its header's transaction root was held aside \
         unjudged, so its sender was refused nothing"
    );
    assert!(
        store.block(&rival[0].id()).is_none(),
        "and nothing is held under the identifier it copied"
    );

    for block in &rival[..2] {
        assert_eq!(
            store.add_block(block.clone(), NOW),
            Ok(Accepted::SideBranch)
        );
    }
    let delivered = store.add_block(rival[2].clone(), NOW);
    assert!(
        matches!(delivered, Ok(Accepted::Reorganised { .. })),
        "the delivery of the block that makes the rival the heaviest was refused"
    );
    assert_eq!(store.tip(), Some(rival[2].id()));
}

/// Sending that copy again before every delivery does not keep a node off the
/// heavier branch either.
///
/// After a switch failed on the copy, the copy was dropped, sent again, and
/// held again ahead of the real block, so every delivery of the rival's next
/// block failed the same way and the node stayed at height twelve under a
/// heavier valid branch for as long as the sender cared to keep sending.
/// Nothing asked this, so a node that could be held there by one connection
/// re-sending one copy passed.
#[test]
fn a_copy_sent_again_before_every_delivery_does_not_keep_a_node_off_the_heavier_branch() {
    let (mut store, rival, copy) = a_node_behind_a_rival(5);

    let mut refused = 0usize;
    for real in rival.iter().skip(1) {
        let _ = store.add_block(copy.clone(), NOW);
        let _ = store.add_block(rival[0].clone(), NOW);
        if store.add_block(real.clone(), NOW).is_err() {
            refused += 1;
        }
    }
    assert_eq!(
        refused, 0,
        "honest deliveries of the rival branch were refused for a copy sent ahead of them"
    );
    assert_eq!(
        store.tip(),
        rival.last().map(Block::id),
        "a node offered every block of a heavier valid branch stayed on the lighter one"
    );
}

/// Eleven blocks both branches share and two more on the branch a node
/// follows, with the node holding them, and the branch a rival grows from,
/// left where the two part.
fn parted(params: ConsensusParams) -> (ChainStore, Vec<Block>, Branch) {
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let shared = branch.mine_empty(&miner, 11);
    let aside = branch.fork();
    let followed = branch.mine_empty(&miner, 2);

    let mut store = ChainStore::new(params);
    for block in shared.iter().chain(followed.iter()) {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(store.height(), Some(12));
    (store, shared, aside)
}

/// A rival of three off `aside`, its first block carrying `payment`.
fn rival_carrying(aside: &mut Branch, payment: Transfer) -> Vec<Block> {
    let other = wallet(3);
    vec![
        aside.mine(&other, vec![payment]),
        aside.mine(&other, Vec::new()),
        aside.mine(&other, Vec::new()),
    ]
}

/// `copy` is refused on arrival as a body its header does not name, nothing
/// is held under its identifier, and the real block and its branch are then
/// taken as they arrive.
fn refused_and_then_the_real_branch_taken(store: &mut ChainStore, rival: &[Block], copy: &Block) {
    let refused = store.add_block(copy.clone(), NOW);
    assert!(
        matches!(
            &refused,
            Err(ChainError::InvalidBlock {
                id,
                source: BlockError::TransactionsRootMismatch { .. },
            }) if *id == copy.id()
        ),
        "a copy that differs from a mined block in its signatures or witnesses alone was \
         not refused as a body its header does not name"
    );
    assert!(
        store.block(&rival[0].id()).is_none(),
        "and something is held under the identifier it copied"
    );

    assert_eq!(
        store.add_block(rival[0].clone(), NOW),
        Ok(Accepted::SideBranch)
    );
    assert_eq!(
        store.block(&rival[0].id()),
        Some(&rival[0]),
        "the real block, arriving after the copy, is not the body held under its identifier"
    );
    assert_eq!(
        store.add_block(rival[1].clone(), NOW),
        Ok(Accepted::SideBranch)
    );
    let delivered = store.add_block(rival[2].clone(), NOW);
    assert!(
        matches!(delivered, Ok(Accepted::Reorganised { .. })),
        "the delivery of the block that makes the rival the heaviest was refused"
    );
    assert_eq!(store.tip(), rival.last().map(Block::id));
}

/// A copy of a side block that changes only a signature is refused before it
/// is held, and the real block, delivered after it, is the one held.
///
/// A transfer's identifier leaves its signatures and witnesses out, and a
/// block's `transactions_root` was taken over those identifiers, so a copy
/// with one signature turned to garbage kept the real block's header, and so
/// its identifier and its work, and produced the root that header names. Held
/// first, it was the body the node tried when its branch became the heaviest,
/// and the real body, arriving second, had been turned away. Nothing asked
/// this, so a node that held a body nobody mined under a mined block's
/// identifier passed.
#[test]
fn a_copy_that_changes_only_a_signature_is_refused_before_it_is_held() {
    let params = params();
    let (mut store, shared, mut aside) = parted(params);
    let miner = wallet(1);
    let (funded, funded_note) = coinbase_note(&shared[10], &params, &miner);
    let mut payment = Transfer::new(
        vec![Input::hot(funded)],
        vec![Note::new(funded_note.value, wallet(2).public_key())],
    );
    payment.sign_input(params.network, 0, &funded_note, &miner);
    let rival = rival_carrying(&mut aside, payment);

    let mut copy = rival[0].clone();
    copy.transfers[0].inputs[0].signature = Signature::from_bytes(&[0xAB; 64]);
    assert_eq!(copy.id(), rival[0].id(), "the copy shares the identifier");
    assert_ne!(copy.encode(), rival[0].encode(), "yet is a different block");

    refused_and_then_the_real_branch_taken(&mut store, &rival, &copy);
}

/// A copy of a side block that spends a note in the grace window with its
/// proof, where the miner spent it without, is refused before it is held.
///
/// Inside the window both witness tags are accepted for the same spend, and
/// every node holds the window's paths, so anybody relaying such a block can
/// make a copy carrying the other tag. That copy is not merely held: it is
/// valid, reaches the same state, and is applied, written to the block log and
/// served as the block, and nothing can tell it from what the miner produced.
/// Nothing asked this, so a node whose record of a block could be a body the
/// miner never carried passed.
#[test]
fn a_copy_that_swaps_a_grace_spend_for_its_proof_is_refused_before_it_is_held() {
    // A tier of four, so the first rewards have fallen by the time the
    // branches part, and the window, which holds the last sixty four landings,
    // still names them.
    let params = params().with_hot_capacity(4);
    let (mut store, shared, mut aside) = parted(params);
    let miner = wallet(1);
    let (fallen, note) = coinbase_note(&shared[0], &params, &miner);
    let (position, held) = aside
        .state
        .within_grace(&fallen)
        .expect("the premise: the first reward fell and the window still names it");
    assert_eq!(held, note);
    let proof = aside
        .state
        .cold()
        .proof_of(position)
        .expect("every node holds the paths of the window's notes");

    let mut payment = Transfer::new(
        vec![Input::hot(fallen)],
        vec![Note::new(note.value, wallet(2).public_key())],
    );
    payment.sign_input(params.network, 0, &note, &miner);
    let parent = aside.state.clone();
    let rival = rival_carrying(&mut aside, payment);

    let mut copy = rival[0].clone();
    copy.transfers[0].inputs[0].witness = Witness::Cold(Box::new(ColdWitness {
        note,
        position,
        proof,
    }));
    assert_eq!(copy.id(), rival[0].id(), "the copy shares the identifier");
    assert_ne!(copy.encode(), rival[0].encode(), "yet is a different block");
    assert!(
        evaluate_block_body(&parent, &copy.coinbase, &copy.transfers, &params).is_ok(),
        "the premise: the copy's body is one the rules accept on the rival's parent"
    );

    refused_and_then_the_real_branch_taken(&mut store, &rival, &copy);
}

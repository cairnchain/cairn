//! Being handed a ledger instead of replaying the chain that made it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
/// Small enough that notes fall out of it during the run, which is the whole
/// point: a handover that never crossed a tier would prove nothing.
const HOT: usize = 8;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_hot_capacity(HOT)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain, kept the way a node that has been running keeps one.
struct Node {
    state: LedgerState,
    headers: Vec<BlockHeader>,
    clock: u64,
}

impl Node {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            headers: Vec::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&self.state, coinbase, transfers, &params, self.clock, 0).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        self.headers.push(block.header);
        block
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner, Vec::new());
        }
    }

    /// What this node would hand to someone starting out.
    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let from = self.headers.len().saturating_sub(RECENT_HEADERS);
        self.state.handover(tip, self.headers[from..].to_vec())
    }
}

/// A ledger handed over is the ledger that was handed.
///
/// Not merely one that looks like it: the test carries on from the rebuilt
/// ledger and from the original in step, and requires that they agree on every
/// block after that. A state root matching once says the pieces line up; two
/// ledgers producing the same next block says they are the same ledger.
#[test]
fn a_handed_over_ledger_carries_on_exactly_as_the_one_it_came_from() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    // Enough that the hot set has overflowed and the grace window is full.
    node.mine_empty(&miner, RECENT_HEADERS + 40);

    let handover = node.handover();
    let mut fresh = accept(&handover, params.hot_capacity).expect("it checks out");

    assert_eq!(fresh.state_root(), node.state.state_root());
    assert_eq!(fresh.grace_root(), node.state.grace_root());
    assert_eq!(fresh.history_root(), node.state.history_root());
    assert_eq!(fresh.tip().unwrap().id, node.state.tip().unwrap().id);
    assert_eq!(fresh.hot_len(), node.state.hot_len());
    assert_eq!(fresh.cold_len(), node.state.cold_len());

    // And now the part that matters: both carry on, and stay together.
    for _ in 0..20 {
        let block = node.mine(&miner, Vec::new());
        connect_block(&mut fresh, &block, &params, NOW)
            .expect("a handed over ledger takes what the chain does");
        assert_eq!(fresh.state_root(), node.state.state_root());
    }
}

/// The case the grace window commitment exists for.
///
/// A note that fell a few blocks ago is spendable without a proof, and only a
/// node holding the window knows which ones those are. A newcomer handed a
/// ledger has to be able to take a block that spends one, and before the state
/// root committed to the window it could not: it would have started empty and
/// refused.
#[test]
fn a_handed_over_ledger_accepts_a_spend_from_the_grace_window() {
    let params = params();
    let miner = wallet(1);
    let recipient = wallet(2);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 4);

    // A note the miner was paid early on, which the hot set has long since
    // pushed out but the grace window still covers.
    let fallen = node
        .state
        .grace_window()
        .last()
        .and_then(|block| block.first().copied())
        .expect("something fell in the last block");
    let (id, _, fallen_note) = fallen;

    let handover = node.handover();
    assert!(!handover.grace.is_empty(), "the window travels");
    let mut fresh = accept(&handover, params.hot_capacity).expect("it checks out");
    assert_eq!(
        fresh.grace_len(),
        node.state.grace_len(),
        "and arrives whole"
    );

    let (position, _) = node.state.within_grace(&id).expect("the giver has it");
    assert!(
        fresh.within_grace(&id).is_some(),
        "and so does the one handed over"
    );
    assert!(
        fresh.cold().proof_of(position).is_some(),
        "along with the proof that spending it takes"
    );

    // Spent with no proof at all, which only the window makes possible.
    let mut transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(fallen_note.value, recipient.public_key())],
    );
    transfer.sign_input(params.network, 0, &fallen_note, &miner);

    let block = node.mine(&miner, vec![transfer]);
    assert_eq!(block.transfers.len(), 1, "the spend went into a block");
    connect_block(&mut fresh, &block, &params, NOW)
        .expect("a handed over ledger knows what has just fallen");
    assert_eq!(fresh.state_root(), node.state.state_root());
    assert_eq!(
        fresh
            .hot_note(&NoteId::new(block.transfers[0].id(), 0))
            .map(|paid| paid.value),
        Some(fallen_note.value),
        "and the payee holds it"
    );
}

/// A ledger that does not produce the header it claims to belong to.
#[test]
fn a_ledger_that_does_not_match_its_header_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    // One note quietly worth more than it was.
    let (id, mut entry) = handover.hot[0];
    entry.note = Note::new(
        Amount::from_pebbles(entry.note.value.as_pebbles() + 1).unwrap(),
        entry.note.owner,
    );
    handover.hot[0] = (id, entry);

    assert_eq!(
        accept(&handover, params.hot_capacity).err(),
        Some(HandoverError::StateRootMismatch),
        "a ledger is only worth what its header says about it"
    );
}

/// A grace window of the sender's choosing.
///
/// The one a header would not have caught before it committed to the window.
#[test]
fn a_grace_window_the_header_does_not_commit_to_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    handover.grace.clear();

    assert_eq!(
        accept(&handover, params.hot_capacity).err(),
        Some(HandoverError::StateRootMismatch),
        "an empty window is a different ledger, and the header says which"
    );
}

/// Headers from somewhere else, or none at all.
#[test]
fn a_history_the_header_does_not_commit_to_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut other = Node::new();
    other.mine_empty(&wallet(9), RECENT_HEADERS + 8);

    let mut handover = node.handover();
    handover.headers = other.state.headers_before_tip();

    assert_eq!(
        accept(&handover, params.hot_capacity).err(),
        Some(HandoverError::HistoryMismatch),
    );
}

/// A run of headers that does not lead to the one being handed over.
#[test]
fn recent_headers_that_are_not_a_chain_are_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    // One header replaced by a real one from further back, so the run still
    // looks like headers but no longer links.
    handover.recent[2] = node.headers[0];

    assert_eq!(
        accept(&handover, params.hot_capacity).err(),
        Some(HandoverError::RecentNotConsecutive),
    );

    // And a run that stops short of the header it belongs to.
    let mut handover = node.handover();
    handover.recent.pop();
    assert_eq!(
        accept(&handover, params.hot_capacity).err(),
        Some(HandoverError::RecentNotEndingAtTip),
    );
}

/// A hot set larger than the rules allow, before anything is built from it.
#[test]
fn a_hot_set_past_the_cap_is_refused_before_it_is_built() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    let filler = handover.hot[0];
    while handover.hot.len() <= params.hot_capacity {
        handover.hot.push(filler);
    }

    assert!(
        matches!(
            accept(&handover, params.hot_capacity),
            Err(HandoverError::HotSetTooLarge { .. })
        ),
        "how much work a handover costs is not for its sender to decide"
    );
}

/// A handover crosses the wire and is still the same ledger.
#[test]
fn a_handover_survives_a_round_trip() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 20);

    let handover = node.handover();
    let bytes = cairn_primitives::codec::Encode::encode(&handover);
    let read_back = <Handover as cairn_primitives::codec::Decode>::decode(&bytes)
        .expect("what it wrote, it reads");

    let rebuilt = accept(&read_back, params.hot_capacity).expect("and it still checks out");
    assert_eq!(rebuilt.state_root(), node.state.state_root());
    assert_eq!(rebuilt.hot_len(), node.state.hot_len());
    assert_eq!(rebuilt.grace_len(), node.state.grace_len());

    println!(
        "a handover of {} blocks takes {} bytes",
        node.headers.len(),
        bytes.len()
    );
}

/// Sizes a reader reserves for are the sender's to name, so each is capped.
#[test]
fn a_handover_that_names_absurd_sizes_is_refused_while_reading() {
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 4);

    let handover = node.handover();
    let good = cairn_primitives::codec::Encode::encode(&handover);

    // The hot set count sits right after the two forests, and the forests are
    // fixed width for a given shape, so the count is found by reading up to it.
    // Rather than compute the offset, every prefix is truncated and fed back:
    // a reader that reserves before checking would run out of memory on one of
    // them rather than returning an error.
    for cut in (8..good.len()).step_by(good.len() / 20 + 1) {
        let outcome = <Handover as cairn_primitives::codec::Decode>::decode(&good[..cut]);
        assert!(
            outcome.is_err(),
            "a message cut short at {cut} should not read as a whole one"
        );
    }
}

/// The case the proof window commitment exists for.
///
/// A proof describes the cold set at the moment it was taken, and the set
/// moves with every block. A spender who took one a few blocks ago has done
/// nothing wrong, so a handful of recent states are kept and a proof against
/// any of them is taken. A newcomer handed a ledger holds none of those unless
/// they come with it, and before the state root committed to them it would
/// have refused every proof not taken at the exact tip.
#[test]
fn a_handed_over_ledger_accepts_a_proof_taken_a_few_blocks_ago() {
    let params = params();
    let miner = wallet(1);
    let recipient = wallet(2);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    // A note that fell long enough ago to be out of the grace window, so
    // spending it takes a proof rather than nothing.
    let old = node
        .state
        .grace_window()
        .first()
        .and_then(|block| block.first().copied())
        .expect("something fell early on");
    let (id, position, fallen_note) = old;

    // The proof as it stands now, taken before the chain moves on.
    let proof = node
        .state
        .cold()
        .prove(position)
        .expect("an archivist can build one");

    // The chain moves under it, which is exactly the case the window covers.
    node.mine_empty(&miner, 3);

    let handover = node.handover();
    assert!(!handover.bygone.is_empty(), "the window travels");
    let mut fresh = accept(&handover, params.hot_capacity).expect("it checks out");
    assert_eq!(
        fresh.proof_window_root(),
        node.state.proof_window_root(),
        "and arrives whole"
    );

    let mut transfer = Transfer::new(
        vec![Input::cold(id, fallen_note, position, proof)],
        vec![Note::new(fallen_note.value, recipient.public_key())],
    );
    transfer.sign_input(params.network, 0, &fallen_note, &miner);

    let block = node.mine(&miner, vec![transfer]);
    assert_eq!(block.transfers.len(), 1, "the spend went into a block");
    connect_block(&mut fresh, &block, &params, NOW)
        .expect("a handed over ledger takes a proof the chain took");
    assert_eq!(fresh.state_root(), node.state.state_root());
}

/// A proof window of the sender's choosing.
#[test]
fn a_proof_window_the_header_does_not_commit_to_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    handover.bygone.clear();

    assert_eq!(
        accept(&handover, params.hot_capacity).err(),
        Some(HandoverError::StateRootMismatch),
        "an empty window is a different ledger, and the header says which"
    );
}

//! Whether a switch between branches is the inverse of what it undoes.
//!
//! `fork_choice.rs` compares a state root across a reorganisation of empty
//! blocks. A state root is one hash over the hot set, and a ledger is more
//! than that: a cold accumulator that only ever appends, a grace window that
//! remembers where each fallen note went, a run of recent headers the median
//! and the retarget are read off, the positions this node keeps for the owner
//! it watches, and a cursor saying how far back it can still undo. Every one
//! of those is changed by applying a block and has to be changed back exactly
//! by undoing it, or two nodes that saw the same blocks in different orders
//! are on the same tip with different ledgers.
//!
//! So this compares the two nodes on everything either of them can be asked,
//! over branches that fill a hot tier several times, push notes into the cold
//! set on both sides, and pay an owner the node is watching.

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
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
/// Small, so notes fall out of the tier while the branches are being built and
/// the cold accumulator is what a switch has to put back.
const CAPACITY: usize = 8;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_hot_capacity(CAPACITY)
}

/// Mines on a private ledger, so a branch exists without a node following it.
#[derive(Clone)]
struct Chain {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
    /// Every coinbase note paid so far, oldest first, with the seed of the
    /// wallet that can sign for it.
    paid: Vec<(NoteId, Note, u8)>,
}

impl Chain {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
            paid: Vec::new(),
        }
    }

    fn mine(&mut self, seed: u8, transfers: Vec<Transfer>) -> Block {
        let miner = wallet(seed);
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
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        self.paid.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(self.params.initial_reward, miner.public_key()),
            seed,
        ));
        block
    }

    fn mine_empty(&mut self, seed: u8, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine(seed, Vec::new())).collect()
    }

    /// A payment out of the newest coinbase note, split into `outputs` notes,
    /// which pushes that many places out of a tier that is already full.
    fn payment(&self, outputs: usize, payee: &SecretKey) -> Transfer {
        let (id, note, seed) = &self.paid[self.paid.len() - 1];
        let owner = wallet(*seed);
        let each = note.value.as_pebbles() / (outputs as u64 + 1);
        let mut transfer = Transfer::new(
            vec![Input::hot(*id)],
            (0..outputs)
                .map(|_| Note::new(Amount::from_pebbles(each).unwrap(), payee.public_key()))
                .collect(),
        );
        transfer.sign_input(self.params.network, 0, note, &owner);
        transfer
    }
}

fn feed(store: &mut ChainStore, blocks: &[Block]) -> Vec<Accepted> {
    blocks
        .iter()
        .map(|block| store.add_block(block.clone(), NOW).unwrap())
        .collect()
}

/// Everything two nodes standing on the same tip have to agree about.
///
/// Compared as text so a difference names itself rather than coming back as a
/// pair of hashes.
fn everything_it_can_be_asked(store: &ChainStore) -> Vec<String> {
    let state = store.state();
    let mut watched: Vec<(NoteId, u64, Note)> = state.watched_notes().collect();
    watched.sort_by_key(|(id, _, _)| *id);
    vec![
        format!("tip {:?}", store.tip()),
        format!("height {:?}", store.height()),
        format!("total work {}", store.total_work()),
        format!("state root {:?}", state.state_root()),
        format!("history root {:?}", state.history_root()),
        format!("grace root {:?}", state.grace_root()),
        format!("cold roots {:?}", state.cold_roots()),
        format!("cold notes {}", state.cold_len()),
        format!("next cold position {}", state.next_cold_position()),
        format!("hot notes {}", state.hot_len()),
        format!("notes in grace {}", state.grace_len()),
        format!("grace window {:?}", state.grace_window()),
        format!("supply {:?}", state.supply()),
        format!("recent headers {:?}", state.recent_headers()),
        format!("headers committed {}", state.headers_committed()),
        format!("maturing rewards {:?}", state.maturing()),
        format!("watched notes {watched:?}"),
        format!("undo records {}", store.undo_records()),
        format!("held from {}", store.held_from()),
        format!("branch start {:?}", store.branch_start()),
        format!("held identifiers {:?}", store.held_ids()),
        format!("locator {:?}", store.locator()),
        format!(
            "pool {:?}",
            store
                .pooled_transfers()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
        ),
        format!("pool bytes {}", store.pool_bytes()),
    ]
}

fn diverging_branches() -> (Vec<Block>, Vec<Block>, Vec<Block>, SecretKey) {
    let rules = params();
    let payee = wallet(3);
    let watched = wallet(4);

    let mut shared = Chain::new(rules);
    // Several times the tier, so notes are falling all the way through the
    // grace window into the cold set before either branch starts.
    let common = shared.mine_empty(1, 14);

    let mut ours = shared.clone();
    let ours_blocks = (0..3)
        .map(|_| {
            let payment = ours.payment(3, &payee);
            ours.mine(1, vec![payment])
        })
        .collect();

    let mut theirs = shared.clone();
    let theirs_blocks = (0..5)
        .map(|_| {
            let payment = theirs.payment(2, &watched);
            theirs.mine(2, vec![payment])
        })
        .collect();

    (common, ours_blocks, theirs_blocks, watched)
}

/// A node that reorganised onto a branch has to be indistinguishable from one
/// that applied that branch from the start.
#[test]
fn a_reorganisation_leaves_the_state_it_would_have_reached_without_one() {
    let rules = params();
    let (common, ours, theirs, watched) = diverging_branches();

    let mut reorganised = ChainStore::new(rules);
    reorganised.watch_owner(watched.public_key());
    feed(&mut reorganised, &common);
    feed(&mut reorganised, &ours);
    let outcomes = feed(&mut reorganised, &theirs);
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Accepted::Reorganised { .. })),
        "the rival never took the branch, so nothing here is a reorganisation: {outcomes:?}"
    );

    let mut direct = ChainStore::new(rules);
    direct.watch_owner(watched.public_key());
    feed(&mut direct, &common);
    feed(&mut direct, &theirs);

    // The losing branch put notes into the accumulator too, and different
    // ones, so undoing it is not a no-op on the one structure that only ever
    // appends.
    let mut losing = ChainStore::new(rules);
    feed(&mut losing, &common);
    feed(&mut losing, &ours);
    assert!(
        losing.state().cold_len() > 0 && direct.state().cold_len() > 0,
        "no note reached the cold set, so the accumulator was never exercised"
    );
    assert_ne!(
        losing.state().cold_roots(),
        direct.state().cold_roots(),
        "the two branches leave the same accumulator, so undoing one proves nothing"
    );
    for (was, should) in everything_it_can_be_asked(&reorganised)
        .into_iter()
        .zip(everything_it_can_be_asked(&direct))
    {
        assert_eq!(was, should, "a reorganised node differs from a direct one");
    }
}

/// And a switch that fails partway has to leave the node exactly where it
/// stood, in the same terms.
///
/// `fork_choice.rs::a_branch_containing_a_bad_block_leaves_the_node_exactly_where_it_was`
/// checks the tip, the state root, the height and the work. This checks the
/// accumulator, the grace window, the headers the retarget reads, the watched
/// positions and the pool as well, over a rewind that crosses the whole tier.
#[test]
fn a_switch_that_fails_partway_leaves_the_node_where_it_stood() {
    let rules = params();
    let (common, ours, theirs, watched) = diverging_branches();

    let mut store = ChainStore::new(rules);
    store.watch_owner(watched.public_key());
    feed(&mut store, &common);
    feed(&mut store, &ours);
    let before = everything_it_can_be_asked(&store);

    // Three blocks on this side against five on the rival's, so the rival
    // wins on its fourth. Break that one: the switch rewinds three, applies
    // three, and fails on the block that asked for it.
    let breaks_at = 3;
    let mut broken = theirs.clone();
    broken[breaks_at].transfers[0].inputs[0].signature =
        cairn_crypto::Signature::from_bytes(&[7u8; 64]);

    for block in &broken[..breaks_at] {
        assert_eq!(
            store.add_block(block.clone(), NOW).unwrap(),
            Accepted::SideBranch,
            "the rival took the branch before the block that was meant to fail"
        );
    }
    let refused = store.add_block(broken[breaks_at].clone(), NOW);
    // Named, because the whole of this test is what happens after the rewind.
    // Any earlier refusal would leave nothing to have been put back.
    assert!(
        matches!(
            refused,
            Err(cairn_chain::ChainError::InvalidBlock {
                source: cairn_ledger::validation::BlockError::InvalidTransfer { .. },
                ..
            })
        ),
        "the block was refused before the rewind, so nothing was put back: {refused:?}"
    );

    for (was, should) in everything_it_can_be_asked(&store).into_iter().zip(before) {
        assert_eq!(was, should, "a failed switch moved the node");
    }
}

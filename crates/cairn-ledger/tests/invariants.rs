//! The two invariants that, broken, split the chain, on sequences nobody chose.
//!
//! Every other test in this suite runs a case its author had in mind. That is
//! the wrong shape for these two, because the failure they guard against is by
//! definition the case nobody thought of: three networks have been reset over
//! something the state committed to and nobody had recontrolled.
//!
//! The first invariant is that undoing a block puts the state back exactly as
//! it stood. `disconnect_block` is written as the step-by-step inverse of
//! `connect_block`, and nothing but two length assertions, which a release
//! build compiles out, checks that it is. An asymmetry there does not look
//! like a bug at the node that has it: it looks like the rest of the network
//! being wrong.
//!
//! The second is that a chain reorganisation lands on the state the winning
//! branch alone would have built. A node that arrives at a different one after
//! walking back and forward has forked from the network without an attacker
//! and without an error anyone can see.
//!
//! Deterministic throughout: the generator is seeded and written here, in the
//! shape `cairn-net`'s fuzz campaigns already use, so a failure names a seed
//! and an index rather than a run that cannot be had again. The hot capacity
//! is set low so that notes fall to the cold set, the grace window fills, and
//! proofs are needed, which is the interaction the design review named as the
//! least covered part of the system. What was actually reached is asserted at
//! the end of each test, because a generator that quietly stopped producing
//! spends would leave both of these passing while checking nothing.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::{HotEntry, GRACE_BLOCKS};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, disconnect_block, mine_block, ConnectedBlock, ConsensusParams,
};
use cairn_ledger::{Block, LedgerState};
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const SPACING: u64 = 600;
const MINING_ATTEMPTS: u64 = 1 << 22;

/// Small enough that notes fall within a handful of blocks, so every sequence
/// exercises eviction, the grace window and cold spends rather than staying in
/// the hot set where nothing interesting happens.
const CAPACITY: usize = 4;

/// A generator written here rather than pulled in, so a failing case is a seed
/// and an index and nothing else has to be installed to reproduce it.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Any non-zero state will do; zero is the one that would stick.
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next() % bound as u64) as usize
    }
}

/// Everything two nodes have to agree on, in one comparable value.
///
/// Wider than `state_root` on purpose. The root commits to six things; the
/// structures that answer *which note is oldest* and *what is still spendable
/// without a proof* are not among them, and an undo that restored the root but
/// not those would pass a check on the root alone and diverge one block later.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fingerprint {
    state_root: Hash32,
    history_root: Hash32,
    grace_root: Hash32,
    headers_committed: u64,
    total_work: u128,
    tip: Option<cairn_ledger::state::Tip>,
    recent: Vec<cairn_ledger::block::HeaderSummary>,
    hot: Vec<(NoteId, HotEntry)>,
    hot_len: usize,
    cold_len: u64,
    grace_len: usize,
    next_cold_position: u64,
    grace: Vec<Vec<(NoteId, u64, Note)>>,
    /// The proofs kept current for watched owners.
    ///
    /// In no root at all, and restored by a route nothing states: undoing a
    /// block assigns a clone of the forest as it stood, and the proofs come
    /// back only because `watched` is a field of what is cloned. A node that
    /// lost them would still agree with everyone about every block, and would
    /// quietly stop being able to prove notes it was proving a moment before.
    watched: Vec<(NoteId, u64, Note)>,
}

fn fingerprint(state: &LedgerState) -> Fingerprint {
    let mut hot: Vec<(NoteId, HotEntry)> = state.hot_notes().collect();
    // The iterator's order is the map's, not the state's; sorting makes the
    // comparison about content rather than about how it was walked.
    hot.sort_by_key(|(id, _)| *id);
    Fingerprint {
        state_root: state.state_root(),
        history_root: state.history_root(),
        grace_root: state.grace_root(),
        headers_committed: state.headers_committed(),
        total_work: state.total_work(),
        tip: state.tip(),
        recent: state.recent_headers().to_vec(),
        hot,
        hot_len: state.hot_len(),
        cold_len: state.cold_len(),
        grace_len: state.grace_len(),
        next_cold_position: state.next_cold_position(),
        grace: state.grace_window(),
        watched: {
            let mut watched: Vec<(NoteId, u64, Note)> = state.watched_notes().collect();
            watched.sort_by_key(|(id, _, _)| *id);
            watched
        },
    }
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_hot_capacity(CAPACITY)
}

/// A note somebody in this test holds, and the key that can sign for it.
#[derive(Clone, Copy)]
struct Held {
    id: NoteId,
    note: Note,
    owner: u8,
}

/// What the generator managed to reach, counted so it can be asserted.
///
/// A sequence generator is itself untested code. If it stops producing cold
/// spends because a condition drifted, both tests below keep passing and stop
/// meaning anything, which is the failure mode worth guarding against here.
#[derive(Default, Debug)]
struct Reached {
    blocks: u64,
    hot_spends: u64,
    cold_spends: u64,
    evictions: u64,
    undos: u64,
    watched_seen: u64,
}

/// Builds the transfers for one block out of what the state actually holds.
///
/// Where a note sits decides how it is spent: still hot, or fallen but inside
/// the grace window, and it goes in by identifier alone; fallen out of it, and
/// it needs its position and a proof. Reading that from the state rather than
/// tracking it here is deliberate: a spend built on this test's idea of where
/// a note sits would test this test.
fn draw_transfers(
    state: &LedgerState,
    params: &ConsensusParams,
    rng: &mut Rng,
    held: &mut Vec<Held>,
    reached: &mut Reached,
) -> (Vec<Transfer>, Vec<Held>) {
    let wanted = rng.below(3);
    let mut transfers = Vec::new();
    let mut created = Vec::new();

    for _ in 0..wanted {
        if held.is_empty() {
            break;
        }

        // Half the draws go looking for a note that has left the grace window,
        // because a uniform draw almost never finds one: a note is spent within
        // a few blocks of being made, and the window is sixty four deep. The
        // bias is deliberate and it is the point: the cold path is the one
        // nothing else here covers, and a generator that reaches it twice in a
        // thousand blocks has not covered it either.
        let picked = if rng.next() % 2 == 0 {
            let fallen: Vec<usize> = held
                .iter()
                .enumerate()
                .filter(|(_, h)| {
                    state.hot_note(&h.id).is_none()
                        && state.within_grace(&h.id).is_none()
                        && state.cold().locate(&h.id, &h.note).is_some()
                })
                .map(|(index, _)| index)
                .collect();
            if fallen.is_empty() {
                rng.below(held.len())
            } else {
                fallen[rng.below(fallen.len())]
            }
        } else {
            rng.below(held.len())
        };
        let Held { id, note, owner } = held[picked];

        let input = if state.hot_note(&id) == Some(note) || state.within_grace(&id).is_some() {
            reached.hot_spends += 1;
            Input::hot(id)
        } else if let Some(position) = state.cold().locate(&id, &note) {
            let Some(proof) = state.cold().prove(position) else {
                continue;
            };
            reached.cold_spends += 1;
            Input::cold(id, note, position, proof)
        } else {
            // Already spent by an earlier transfer in this same block, or gone
            // from every tier. Nothing to do with it.
            continue;
        };

        // Whole value to the recipient: a transfer that left fees behind would
        // need the coinbase to claim them, and what is under test here is not
        // the fee rule.
        let recipient = 2 + (rng.below(3) as u8);
        let mut transfer = Transfer::new(
            vec![input],
            vec![Note::new(note.value, wallet(recipient).public_key())],
        );
        transfer.sign_input(params.network, 0, &note, &wallet(owner));

        created.push(Held {
            id: NoteId::new(transfer.id(), 0),
            note: Note::new(note.value, wallet(recipient).public_key()),
            owner: recipient,
        });
        held.retain(|h| h.id != id);
        transfers.push(transfer);
    }

    (transfers, created)
}

/// Mines and connects one block, or gives up on this one and says so.
///
/// Assembly can refuse for reasons that are not what is under test (a block
/// too large, a height that overflowed), and a sequence that hit one of those
/// is not a failure, it is a sequence with one block fewer.
fn advance(
    state: &mut LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    transfers: Vec<Transfer>,
) -> Option<(Block, ConnectedBlock)> {
    let height = state.next_height()?;
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let candidate = assemble_block(
        state,
        coinbase,
        transfers,
        params,
        1_000 + height * SPACING,
        0,
    )
    .ok()?;
    let block = mine_block(candidate, MINING_ATTEMPTS)?;
    let connected = connect_block(state, &block, params, NOW).ok()?;
    Some((block, connected))
}

/// Grows the chain by `count` blocks, returning what was mined and what it made.
fn extend(
    state: &mut LedgerState,
    params: &ConsensusParams,
    rng: &mut Rng,
    miner: &SecretKey,
    held: &mut Vec<Held>,
    count: usize,
    reached: &mut Reached,
) -> Vec<(Fingerprint, Block, ConnectedBlock)> {
    let mut applied = Vec::new();
    for _ in 0..count {
        let before = fingerprint(state);
        let (transfers, created) = draw_transfers(state, params, rng, held, reached);
        let Some((block, connected)) = advance(state, params, miner, transfers) else {
            continue;
        };
        reached.blocks += 1;
        reached.evictions += connected.transition.evicted.len() as u64;
        reached.watched_seen += state.watched_notes().count() as u64;
        held.extend(created);
        held.push(Held {
            id: NoteId::new(block.coinbase.id(), 0),
            note: Note::new(params.initial_reward, miner.public_key()),
            owner: 1,
        });
        applied.push((before, block, connected));
    }
    applied
}

/// The first invariant: an undo is an exact inverse, at every depth.
#[test]
fn undoing_any_sequence_of_blocks_restores_the_state_exactly() {
    const SEQUENCES: u64 = 12;
    let params = params();
    let miner = wallet(1);
    let mut reached = Reached::default();

    for seed in 0..SEQUENCES {
        let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut state = LedgerState::archiving();
        // Without this, watched proofs are always empty and the field for them
        // in the fingerprint compares nothing to nothing.
        state.watch_owner(wallet(2).public_key());
        let mut held = Vec::new();

        // Past GRACE_BLOCKS, so that notes age out of the window and can only
        // be spent against the cold set with a proof. Shorter sequences never
        // reach the tier boundary at all, which is where the design review
        // says the least covered interaction lives.
        let depth = GRACE_BLOCKS + 8 + rng.below(20);
        let applied = extend(
            &mut state,
            &params,
            &mut rng,
            &miner,
            &mut held,
            depth,
            &mut reached,
        );

        // Backwards, one at a time. Each step has to land on the fingerprint
        // taken before that very block went on, not merely on something that
        // hashes the same.
        for (before, block, connected) in applied.iter().rev() {
            disconnect_block(&mut state, connected);
            reached.undos += 1;
            assert_eq!(
                fingerprint(&state),
                *before,
                "seed {seed}: undoing block {} left a different state",
                block.header.height
            );
        }

        assert_eq!(
            fingerprint(&state),
            fingerprint(&LedgerState::archiving()),
            "seed {seed}: the whole sequence undone is an empty state"
        );
    }

    // Measured at 963 blocks, 924 hot spends, 25 cold spends, 1684 evictions.
    // The thresholds sit well under that: what they are guarding against is a
    // generator that stopped reaching a case, not a run that reached three
    // fewer than last time.
    assert_eq!(
        reached.undos, reached.blocks,
        "every block applied was undone: {reached:?}"
    );
    assert!(
        reached.blocks > 800 && reached.hot_spends > 600 && reached.evictions > 1_000,
        "the sequences ran deep enough to fill and spill the hot set: {reached:?}"
    );
    assert!(
        reached.cold_spends > 15,
        "notes aged out of the grace window and were spent against a proof: {reached:?}"
    );
    assert!(
        reached.watched_seen > 100,
        "proofs were kept for a watched owner, so restoring them was tested: {reached:?}"
    );
}

/// The second invariant: a reorganisation lands where the branch alone would.
#[test]
fn a_reorganisation_lands_on_the_state_the_winning_branch_alone_would_build() {
    const SEQUENCES: u64 = 12;
    let params = params();
    let miner = wallet(1);
    let mut reached = Reached::default();
    let mut reorgs = 0u64;

    for seed in 0..SEQUENCES {
        let mut rng = Rng::new(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) ^ 0x5DEE_CE66);

        // Two nodes, taken to the same fork point by the same blocks: one will
        // walk a losing branch and come back, the other will never have seen
        // it. Whether they agree afterwards is the whole question.
        let mut walker = LedgerState::archiving();
        let mut control = LedgerState::archiving();
        walker.watch_owner(wallet(2).public_key());
        control.watch_owner(wallet(2).public_key());
        let mut held = Vec::new();

        // The fork point sits past the grace window, so both branches spend
        // across the tier boundary rather than out of the hot set alone.
        let shared_depth = GRACE_BLOCKS + 8 + rng.below(10);
        let shared = extend(
            &mut walker,
            &params,
            &mut rng,
            &miner,
            &mut held,
            shared_depth,
            &mut reached,
        );
        for (_, block, _) in &shared {
            connect_block(&mut control, block, &params, NOW)
                .expect("the control node accepts the same blocks");
        }
        assert_eq!(
            fingerprint(&walker),
            fingerprint(&control),
            "seed {seed}: the two nodes start level"
        );

        // What the losing branch is allowed to spend. Cloned, because the
        // branch spends notes that have to be spendable again on the branch
        // that wins.
        let at_fork = held.clone();

        let losing_depth = 1 + rng.below(6);
        let losing = extend(
            &mut walker,
            &params,
            &mut rng,
            &miner,
            &mut held.clone(),
            losing_depth,
            &mut reached,
        );
        if losing.is_empty() {
            continue;
        }
        for (_, _, connected) in losing.iter().rev() {
            disconnect_block(&mut walker, connected);
            reached.undos += 1;
        }
        assert_eq!(
            fingerprint(&walker),
            fingerprint(&control),
            "seed {seed}: the losing branch left nothing behind"
        );

        // Now the branch that wins, built on the node that walked back, and
        // replayed on the node that never moved.
        let mut winning_held = at_fork;
        let winning_depth = 1 + rng.below(6);
        let winning = extend(
            &mut walker,
            &params,
            &mut rng,
            &miner,
            &mut winning_held,
            winning_depth,
            &mut reached,
        );
        if winning.is_empty() {
            continue;
        }
        for (_, block, _) in &winning {
            connect_block(&mut control, block, &params, NOW)
                .expect("the branch that one node built, the other accepts");
        }
        reorgs += 1;

        assert_eq!(
            fingerprint(&walker),
            fingerprint(&control),
            "seed {seed}: walking a branch and coming back changed where the chain lands"
        );
    }

    assert_eq!(
        reorgs, SEQUENCES,
        "every sequence built a losing branch, walked it back, and built another"
    );
    assert!(
        reached.cold_spends > 15 && reached.evictions > 1_000,
        "the reorganisations crossed the tier boundary rather than staying hot: {reached:?}"
    );
    assert!(
        reached.watched_seen > 100,
        "proofs were kept for a watched owner across the reorganisations: {reached:?}"
    );
}

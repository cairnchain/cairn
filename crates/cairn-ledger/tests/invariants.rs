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
//!
//! Two holes in that net were found by asking what the generator could not
//! reach, and both were reached by nothing else either.
//!
//! `watch_owner` was called once, on an empty state. The interesting half of
//! it is the back-fill, which takes up whatever of its owner's notes are
//! already sitting in the grace window, and an empty state has none: round
//! nine's defect lived in undoing a block that landed one of those, and this
//! file could not have produced the case. The ask is now made partway through
//! a run.
//!
//! And every sequence ran on `LedgerState::archiving()` alone, which keeps the
//! leaves and rebuilds any path it wants. `ColdSet::watch` does nothing to an
//! archive, so the number of paths this file exercised was measured at zero
//! while its grace window held eighty notes. Everything the last two rounds
//! rewrote about keeping paths current, `PathsBefore` and `Forest::rewind_to`
//! and the sibling arithmetic under them, is on the other arm, and it is the
//! arm a node a person runs takes. Both kinds now run every sequence, and what
//! each of them can still prove is compared block by block.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::ForestProof;
use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::{cold_leaf, HotEntry, GRACE_BLOCKS};
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
    /// The fallen notes this node follows for a watched owner, and where each
    /// one sits.
    ///
    /// This is what a wallet is told and it is in no root at all, so a node
    /// that answered wrongly here would go on agreeing with the whole network
    /// about every block. The paths themselves are not in this: an archivist
    /// keeps none and builds them, so they are in [`PlainPrint::paths`], on the
    /// kind of node that does keep them.
    ///
    /// The doc that stood here said an undo restored these by assigning a clone
    /// of the forest as it stood. That route is gone, and had been for two
    /// rounds: the clone was the nine gigabytes `PathsBefore` exists to remove.
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

/// The owner a wallet asks about partway through, rather than before the first
/// block.
///
/// A distinct owner from the one watched from the start, because what it
/// answers about is compared differently: notes taken up by a late ask belong
/// to no block and are in no undo record, so an undo below the moment of the
/// ask legitimately holds fewer of them than the fingerprint from before it.
/// Everything else has to match to the byte.
const LATE: u8 = 4;

/// The same fingerprint with one owner's followed notes left out.
///
/// For comparing across the moment a wallet asked. Only that owner's entries
/// may differ there; that they are still coherent is what
/// [`every_followed_note_can_be_proved`] says.
fn without(print: &Fingerprint, owner: PublicKey) -> Fingerprint {
    let mut copy = print.clone();
    copy.watched.retain(|(_, _, note)| note.owner != owner);
    copy
}

/// What following a note is supposed to establish, asked of every one of them.
///
/// `watched_notes` is read as three claims at once: this note has fallen, it
/// sits at this place, and this node can prove it there. None of the three is
/// in any root, so no other node ever disagrees when one is wrong; the only
/// reader is a wallet, and what it is handed is a place and a path.
///
/// Round nine's defect was exactly a broken one of these. `watch_owner` takes
/// up whatever of its owner's is sitting in the grace window, and those notes
/// belong to no block, so undoing the block that landed one left the entry
/// naming a place the forest no longer had. The state root agreed with the
/// whole network throughout.
fn every_followed_note_can_be_proved(state: &LedgerState, when: &str) {
    for (id, position, note) in state.watched_notes() {
        assert!(
            position < state.next_cold_position(),
            "{when}: {id:?} is followed at place {position}, and the forest has handed out {}",
            state.next_cold_position()
        );
        assert!(
            state.hot_note(&id).is_none(),
            "{when}: {id:?} is followed as a fallen note and is in the hot set"
        );
        let Some(proof) = state.cold().proof_of(position) else {
            panic!("{when}: no path is kept for followed note {id:?} at place {position}");
        };
        assert!(
            state.cold().verify(position, cold_leaf(&id, &note), &proof),
            "{when}: the path kept for followed note {id:?} at place {position} proves nothing"
        );
    }
}

/// The same for the grace window, which makes the same promise to everybody.
///
/// A note that fell moments ago is spendable without the spender bringing a
/// proof, and that only works because every node holds one for it. The window
/// is committed to; the paths under it are not, so an undo that mended one
/// wrongly is invisible until somebody tries to spend.
fn every_path_kept_proves_its_note(state: &LedgerState, when: &str) {
    for (id, position, note) in state.grace_window().into_iter().flatten() {
        let Some(proof) = state.cold().proof_of(position) else {
            panic!("{when}: {id:?} sits in the grace window at place {position} with no path");
        };
        assert!(
            state.cold().verify(position, cold_leaf(&id, &note), &proof),
            "{when}: the path for {id:?} at place {position} in the window proves nothing"
        );
    }
    every_followed_note_can_be_proved(state, when);
}

/// A plain node's fingerprint: the common part, and the paths it keeps.
///
/// Both kinds of node run every sequence here, because they do not run the
/// same code. `LedgerState::archiving()` holds the leaves and rebuilds any
/// path it wants, so `ColdSet::watch` does nothing to it and it keeps none:
/// measured at zero, on runs whose grace window held eighty notes. That left
/// the other arm of `ColdSet::rewind` unreached by this file, and with it
/// `PathsBefore` and the sibling arithmetic in `Forest::rewind_to`, which is
/// what the last two rounds rewrote and what a node a person runs uses.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PlainPrint {
    common: Fingerprint,
    /// Every place this node can still produce a path for, and the path.
    paths: Vec<(u64, ForestProof)>,
}

fn plain_print(state: &LedgerState) -> PlainPrint {
    let mut paths = Vec::new();
    for position in 0..state.next_cold_position() {
        if let Some(proof) = state.cold().proof_of(position) {
            paths.push((position, proof));
        }
    }
    assert_eq!(
        paths.len(),
        state.watched_paths(),
        "what the node says it keeps is what it can answer for"
    );
    PlainPrint {
        common: fingerprint(state),
        paths,
    }
}

/// One block, and what applying it left on each of the two nodes.
struct Step {
    before: Fingerprint,
    before_plain: PlainPrint,
    block: Block,
    connected: ConnectedBlock,
    connected_plain: ConnectedBlock,
}

/// One party, running both kinds of node over the same blocks.
struct Nodes {
    /// The archivist. It holds the leaves, so the generator asks this one
    /// where a note sits and for the proof of a cold spend.
    archive: LedgerState,
    /// The node a person runs.
    plain: LedgerState,
}

impl Nodes {
    fn new() -> Self {
        Self {
            archive: LedgerState::archiving(),
            plain: LedgerState::new(),
        }
    }

    fn watch_owner(&mut self, owner: PublicKey) {
        self.archive.watch_owner(owner);
        self.plain.watch_owner(owner);
    }

    /// Everything each of them holds, checked against the roots it holds.
    fn coherent(&self, when: &str) {
        every_followed_note_can_be_proved(&self.archive, when);
        every_path_kept_proves_its_note(&self.plain, when);
    }
}

/// Whether an undo landed on the state the block it undid went on top of.
///
/// `apart` names an owner whose followed notes may differ, which is the one a
/// wallet asked about partway through. Nothing else may, in either node.
fn landed_on(nodes: &Nodes, step: &Step, apart: Option<PublicKey>, why: &str) {
    let now = fingerprint(&nodes.archive);
    let now_plain = plain_print(&nodes.plain);
    let Some(owner) = apart else {
        assert_eq!(now, step.before, "{why}");
        assert_eq!(now_plain, step.before_plain, "{why}, paths and all");
        return;
    };
    assert_eq!(without(&now, owner), without(&step.before, owner), "{why}");
    assert_eq!(
        without(&now_plain.common, owner),
        without(&step.before_plain.common, owner),
        "{why}, on the node a person runs"
    );
    assert_eq!(
        now_plain.paths, step.before_plain.paths,
        "{why}, in the paths it keeps"
    );
}

/// Feeds a run of blocks to a party that did not build them.
fn replay(nodes: &mut Nodes, steps: &[Step], params: &ConsensusParams) {
    for step in steps {
        connect_block(&mut nodes.archive, &step.block, params, NOW)
            .expect("a node that did not build these blocks still accepts them");
        connect_block(&mut nodes.plain, &step.block, params, NOW)
            .expect("and so does the plain one beside it");
    }
}

/// Two parties that ought to be indistinguishable, compared as both kinds.
fn level(left: &Nodes, right: &Nodes, why: &str) {
    assert_eq!(
        fingerprint(&left.archive),
        fingerprint(&right.archive),
        "{why}"
    );
    assert_eq!(
        plain_print(&left.plain),
        plain_print(&right.plain),
        "{why}, once the paths are compared too"
    );
}

/// A reward is spendable at once here.
///
/// These tests all spend a coinbase shortly after mining it, and none of them
/// is about the wait that normally stands between the two. What the wait is
/// worth is audited in `audit_coinbase_maturity.rs`.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(CAPACITY)
        .with_coinbase_maturity(0)
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
    /// Notes a late ask took up out of the grace window. Zero here means the
    /// back-fill was never reached, which is what this file used to do.
    back_filled: u64,
    /// The most paths the plain node was keeping current at once. Zero here
    /// means the path mending was never reached, which is what this file used
    /// to do.
    paths_kept: u64,
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
    nodes: &mut Nodes,
    params: &ConsensusParams,
    miner: &SecretKey,
    transfers: Vec<Transfer>,
) -> Option<(Block, ConnectedBlock, ConnectedBlock)> {
    let state = &mut nodes.archive;
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
    // Not `ok()?`: the two kinds of node judge the same block by the same
    // rules, and one taking what the other refused is itself the failure.
    let connected_plain = connect_block(&mut nodes.plain, &block, params, NOW)
        .expect("a node that keeps no leaves takes what an archivist took");
    Some((block, connected, connected_plain))
}

/// Grows the chain by `count` blocks, returning what was mined and what it made.
fn extend(
    nodes: &mut Nodes,
    params: &ConsensusParams,
    rng: &mut Rng,
    miner: &SecretKey,
    held: &mut Vec<Held>,
    count: usize,
    reached: &mut Reached,
) -> Vec<Step> {
    let mut applied = Vec::new();
    for _ in 0..count {
        let before = fingerprint(&nodes.archive);
        let before_plain = plain_print(&nodes.plain);
        let (transfers, created) = draw_transfers(&nodes.archive, params, rng, held, reached);
        let Some((block, connected, connected_plain)) = advance(nodes, params, miner, transfers)
        else {
            continue;
        };
        reached.blocks += 1;
        reached.evictions += connected.transition.evicted.len() as u64;
        reached.watched_seen += nodes.archive.watched_notes().count() as u64;
        reached.paths_kept = reached.paths_kept.max(nodes.plain.watched_paths() as u64);
        nodes.coherent("after a block");
        held.extend(created);
        held.push(Held {
            id: NoteId::new(block.coinbase.id(), 0),
            note: Note::new(params.initial_reward, miner.public_key()),
            owner: 1,
        });
        applied.push(Step {
            before,
            before_plain,
            block,
            connected,
            connected_plain,
        });
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
        let mut nodes = Nodes::new();
        // Without this, watched proofs are always empty and the field for them
        // in the fingerprint compares nothing to nothing.
        nodes.watch_owner(wallet(2).public_key());
        let mut held = Vec::new();

        // Past GRACE_BLOCKS, so that notes age out of the window and can only
        // be spent against the cold set with a proof. Shorter sequences never
        // reach the tier boundary at all, which is where the design review
        // says the least covered interaction lives.
        let depth = GRACE_BLOCKS + 8 + rng.below(20);
        let mut applied = extend(
            &mut nodes,
            &params,
            &mut rng,
            &miner,
            &mut held,
            depth,
            &mut reached,
        );

        // Partway through, which is the whole point of it being here. Asking
        // before the first block is what this file used to do, and a wallet
        // that has never asked a running node about an address is not the case
        // worth generating: `watch_owner` back-fills whatever of its owner's
        // notes are already sitting in the grace window, and that back-fill,
        // being in no block and in no undo record, is where round nine's
        // defect was. An ask before block one back-fills an empty window and
        // reaches none of it.
        let late = wallet(LATE).public_key();
        let watched_from = applied.len();
        nodes.watch_owner(late);
        reached.back_filled += nodes
            .archive
            .watched_notes()
            .filter(|(_, _, note)| note.owner == late)
            .count() as u64;
        nodes.coherent("just after the ask");

        let after = 8 + rng.below(20);
        applied.extend(extend(
            &mut nodes,
            &params,
            &mut rng,
            &miner,
            &mut held,
            after,
            &mut reached,
        ));

        // Backwards, one at a time. Each step has to land on the fingerprint
        // taken before that very block went on, not merely on something that
        // hashes the same.
        for (index, step) in applied.iter().enumerate().rev() {
            disconnect_block(&mut nodes.archive, &step.connected);
            disconnect_block(&mut nodes.plain, &step.connected_plain);
            reached.undos += 1;
            nodes.coherent("after an undo");
            let why = format!(
                "seed {seed}: undoing block {} left a different state",
                step.block.header.height
            );
            // Below the ask, only the asker's own notes may differ: the ones
            // it took up out of the window belong to blocks down here, and
            // undoing one of those lets go of the note it landed. Everything
            // the chain decides still has to match, and so do the paths, since
            // the ask keeps no path the window was not keeping already.
            let apart = if index >= watched_from {
                None
            } else {
                Some(late)
            };
            landed_on(&nodes, step, apart, &why);
        }

        // Which includes the notes the late ask took up. They are in no undo
        // record, and what lets go of them is the undo of the block that made
        // each one fall, so a sequence undone to nothing has to have let go of
        // every one.
        level(
            &nodes,
            &Nodes::new(),
            &format!("seed {seed}: the whole sequence undone is an empty state"),
        );
    }

    // Measured at 1182 blocks, 1053 hot spends, 121 cold spends, 2120
    // evictions, 161 notes taken up by the ask partway through and 101 paths
    // kept at once on the plain node. The thresholds sit well under all of
    // that: what they are guarding against is a generator that stopped
    // reaching a case, not a run that reached three fewer than last time.
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
    assert!(
        reached.back_filled > 50,
        "a wallet asking partway through found notes already in the window: {reached:?}"
    );
    assert!(
        reached.paths_kept > 50,
        "the plain node was mending real paths rather than an empty map: {reached:?}"
    );
}

/// Two parties taken to the same point by the same blocks, both asked about a
/// second owner once they are there.
///
/// One of them will walk a losing branch and come back and the other will
/// never have seen it, so what they hold has to be indistinguishable now. The
/// ask is made here rather than on an empty state because that is what makes
/// both of them carry followed notes belonging to no block and named in no
/// undo record: what a branch then spends out of that set has to come back
/// through the record the spend wrote, and what the ceiling displaces has to
/// come back the same way.
fn at_a_fork(
    params: &ConsensusParams,
    rng: &mut Rng,
    miner: &SecretKey,
    reached: &mut Reached,
    seed: u64,
) -> (Nodes, Nodes, Vec<Held>) {
    let mut walker = Nodes::new();
    let mut control = Nodes::new();
    walker.watch_owner(wallet(2).public_key());
    control.watch_owner(wallet(2).public_key());
    let mut held = Vec::new();

    // The fork point sits past the grace window, so both branches spend across
    // the tier boundary rather than out of the hot set alone.
    let depth = GRACE_BLOCKS + 8 + rng.below(10);
    let shared = extend(&mut walker, params, rng, miner, &mut held, depth, reached);
    replay(&mut control, &shared, params);
    level(
        &walker,
        &control,
        &format!("seed {seed}: the two nodes start level"),
    );

    let late = wallet(LATE).public_key();
    walker.watch_owner(late);
    control.watch_owner(late);
    reached.back_filled += walker
        .archive
        .watched_notes()
        .filter(|(_, _, note)| note.owner == late)
        .count() as u64;
    level(
        &walker,
        &control,
        &format!("seed {seed}: the same ask on the same state takes up the same notes"),
    );
    walker.coherent("just after the ask");
    (walker, control, held)
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

        let (mut walker, mut control, held) =
            at_a_fork(&params, &mut rng, &miner, &mut reached, seed);

        // What the losing branch is allowed to spend. Kept, because the branch
        // spends notes that have to be spendable again on the branch that wins.
        let at_fork = held;

        let losing_depth = 1 + rng.below(6);
        let losing = extend(
            &mut walker,
            &params,
            &mut rng,
            &miner,
            &mut at_fork.clone(),
            losing_depth,
            &mut reached,
        );
        if losing.is_empty() {
            continue;
        }
        for step in losing.iter().rev() {
            disconnect_block(&mut walker.archive, &step.connected);
            disconnect_block(&mut walker.plain, &step.connected_plain);
            reached.undos += 1;
            walker.coherent("walking a branch back");
        }
        level(
            &walker,
            &control,
            &format!("seed {seed}: the losing branch left nothing behind"),
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
        replay(&mut control, &winning, &params);
        reorgs += 1;

        // The second half of `level` is the sharper one. Two nodes that
        // reached one tip by different routes have to be able to prove the
        // same notes: the paths are in no root, so a node that mended one
        // wrongly agrees with the network about every block and then refuses a
        // spend everyone else takes.
        level(
            &walker,
            &control,
            &format!("seed {seed}: walking a branch and coming back changed where the chain lands"),
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
    assert!(
        reached.back_filled > 50,
        "a wallet asking at the fork found notes already in the window: {reached:?}"
    );
    assert!(
        reached.paths_kept > 50,
        "the plain nodes were mending real paths rather than an empty map: {reached:?}"
    );
}

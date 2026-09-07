//! Adversarial audit of the sentence the rest of the machinery exists for: no
//! coin is created, none is destroyed by anything but a fee nobody claimed,
//! and every coin that exists is owned by exactly one person.
//!
//! Three places where that sentence could stop being true.
//!
//! The first is the handover. A newcomer takes somebody else's account of who
//! owns what, and every part of it is checked against the header that commits
//! to it. That is an argument about work, not about arithmetic: a sender that
//! did out-mine the network for the burial chose the state root, and with it
//! the hot set, the grace window and the issued total. The one thing in a
//! handover that follows from the rules instead is the total: a chain at a
//! height holds at most what the schedule has paid by then, and that is a
//! subtraction nobody can mine their way past.
//!
//! The second is a branch swap that lands lower than it started. A coinbase
//! that matured on the branch being left has not matured on the one being
//! joined, and the money it paid has to become unspendable again.
//!
//! The third is the line between the tiers, asked of a block that is spending
//! and evicting at once: a note may be in one tier or the other and never in
//! both or in neither. `audit_emission.rs` asks the same thing as a count of
//! what each tier holds; this asks it of the transition a block commits to,
//! on traffic built so that the note a block spends is the note eviction
//! would otherwise reach for first.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::print_stdout,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, disconnect_block, BlockError, ConsensusParams, TransferError,
};
use cairn_ledger::{ConnectedBlock, LedgerState};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;

/// Shallow, so a handover is reachable without mining a thousand blocks.
const BURIAL: u64 = 8;

/// Short, and not nothing: a handover carries the coinbases still waiting, so
/// these are worth more with something in that window.
const MATURITY: u64 = 4;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// The rules a node checking a handover here runs under.
fn honest() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(BURIAL)
        .with_coinbase_maturity(MATURITY)
}

/// A chain, kept the way a node that has been running keeps one.
struct Node {
    params: ConsensusParams,
    state: LedgerState,
    past: Vec<LedgerState>,
    history: Archive,
    headers: Vec<BlockHeader>,
    clock: u64,
}

impl Node {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::archiving(),
            past: Vec::new(),
            history: Archive::new(),
            headers: Vec::new(),
            clock: 1_000,
        }
    }

    /// One block paying its whole reward, and nothing else.
    fn mine(&mut self, miner: &SecretKey) {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.reward_at(height), miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        self.past.push(self.state.clone());
        self.history
            .add(header_leaf(&block.header.id()))
            .expect("the header forest has room");
        self.headers.push(block.header);
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner);
        }
    }

    /// What this node would hand to somebody starting out: never the ledger at
    /// the tip, always the one [`BURIAL`] blocks below it.
    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let anchor = self
            .history
            .prove_in(anchor_height, tip.height)
            .expect("the header sits in the forest before the tip");
        let first = (anchor_height as usize + 1).saturating_sub(RECENT_HEADERS);
        state
            .handover(
                at,
                tip,
                self.state.headers_before_tip(),
                anchor,
                self.headers[(anchor_height as usize + 1)..].to_vec(),
                self.headers[first..=anchor_height as usize].to_vec(),
            )
            .expect("every note in the window has a path")
    }
}

// ---------------------------------------------------------------------------
// 1. The handover, against the schedule rather than against the header.
// ---------------------------------------------------------------------------

/// A ledger holding more than the schedule can have paid is refused.
///
/// Every other check in `handover::accept` ends at the header: rebuild the
/// piece, compare it against what the header committed to, and the header
/// against the work behind it. A sender that mined the burial chose that
/// header and everything under it, so nothing on that road can tell an honest
/// ledger from one its author wrote for itself.
///
/// This one does not go by that road. A coinbase claims at most what the
/// schedule pays plus the fees its own block's transfers gave up, and a fee
/// the coinbase declines is destroyed, so the issued total at a height is at
/// most what the schedule has paid by then. It is one subtraction, and no
/// amount of work gets past it.
///
/// The chain here is a real one, mined block by block under rules that pay one
/// pebble a block more than the network's. That is the smallest lie there is,
/// and it is what makes the bound worth stating: the check is exact rather
/// than a margin.
#[test]
fn a_handed_ledger_holding_more_than_the_schedule_paid_is_refused() {
    let honest = honest();
    let mut generous = honest;
    generous.initial_reward = honest
        .initial_reward
        .checked_add(Amount::from_pebbles(1).unwrap())
        .unwrap();

    let mut node = Node::new(generous);
    node.mine_empty(&wallet(1), RECENT_HEADERS + 8);
    let handover = node.handover();
    let at = handover.at.height;

    // Under its own rules the chain is sound, and the ledger it hands over is
    // one every other check in `accept` is happy with. So what follows is not
    // a handover that was broken some other way.
    accept(&handover, &generous).expect("a chain is valid under the rules that made it");

    let ceiling = honest.emitted_by(at);
    let over = handover.supply.checked_sub(ceiling).unwrap();
    println!(
        "at height {at} the ledger holds {} and the schedule allows {ceiling}, \
         which is {over} too much",
        handover.supply
    );
    assert_eq!(
        over.as_pebbles(),
        at + 1,
        "one pebble a block, and the anchor is at height {at}"
    );

    assert_eq!(
        accept(&handover, &honest).err(),
        Some(HandoverError::SupplyAboveTheSchedule {
            height: at,
            supply: handover.supply,
            ceiling,
        }),
        "a ledger holding money this network's schedule never paid was taken"
    );
}

/// And a ledger holding exactly what the schedule paid is taken.
///
/// The other half, and the half that keeps the bound from being written a
/// block short. Every block of this chain claims its whole reward and pays no
/// fee, so the total sits exactly on the ceiling, which is the only place a
/// bound written off by one would show.
#[test]
fn a_handed_ledger_holding_exactly_what_the_schedule_paid_is_taken() {
    let params = honest();
    let mut node = Node::new(params);
    node.mine_empty(&wallet(1), RECENT_HEADERS + 8);
    let handover = node.handover();
    let at = handover.at.height;

    assert_eq!(
        handover.supply,
        params.emitted_by(at),
        "every block took its whole reward, so the total is the schedule's own"
    );
    let fresh = accept(&handover, &params).expect("an honest ledger sits on the ceiling");
    assert_eq!(fresh.supply(), params.emitted_by(at));
}

/// The bound is the schedule's, not a constant: it follows the halvings.
///
/// A ceiling worked out from the opening rate alone would be far too generous
/// past the first era and would let a forged ledger through exactly where the
/// schedule is doing the most work.
#[test]
fn the_ceiling_a_handover_is_held_to_follows_the_halvings() {
    let mut params = honest();
    params.halving_interval = 4;
    params.tail_reward = Amount::from_cairn("1").unwrap();

    let mut running = Amount::ZERO;
    for height in 0..24u64 {
        running = running.checked_add(params.reward_at(height)).unwrap();
        assert_eq!(
            params.emitted_by(height),
            running,
            "the ceiling at height {height} is not what the schedule paid"
        );
    }
    // Flat from the opening rate would be four times this by the last height.
    let flat = Amount::from_pebbles(params.initial_reward.as_pebbles() * 24).unwrap();
    assert!(
        params.emitted_by(23) < flat,
        "the ceiling did not fall with the schedule"
    );
}

// ---------------------------------------------------------------------------
// 2. A branch swap that lands below where it started.
// ---------------------------------------------------------------------------

/// A reward that matured on one branch is locked again on a shorter one.
///
/// A node follows work rather than height, so the branch it moves to can end
/// lower than the one it leaves. A coinbase that had matured is then a
/// coinbase that has not, and the money it paid has to stop being spendable
/// again: the block that paid it is reachable once more, and a reorganisation
/// that took it away would leave whoever was paid on with money no honest
/// miner could put back.
///
/// The whole trip is checked in both directions, because a total that is right
/// going forward and wrong coming back forks nodes that did nothing wrong.
#[test]
fn a_reward_that_matured_on_one_branch_is_locked_again_on_a_shorter_one() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(8);
    let miner = wallet(1);
    let alice = wallet(2);
    let rival = wallet(3);
    let mut state = LedgerState::archiving();

    // A chain to height 9, and a note of the first reward it paid.
    let mut applied: Vec<ConnectedBlock> = Vec::new();
    let mut first_coinbase = None;
    let mut clock = 1_000u64;
    for height in 0..10u64 {
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        applied.push(connect_block(&mut state, &block, &params, NOW).unwrap());
        if height == 0 {
            first_coinbase = Some(block.coinbase.id());
        }
    }
    let paid_by = first_coinbase.unwrap();
    let reward = NoteId::new(paid_by, 0);
    let reward_note = Note::new(params.reward_at(0), miner.public_key());

    assert_eq!(
        state.coinbase_matures_at(&paid_by),
        None,
        "at height 9 the first reward has been spendable since height 8"
    );
    assert_eq!(state.supply(), params.emitted_by(9));

    // The state to come back to, so the round trip can be checked exactly.
    let at_nine = state.state_root();

    // Undo to height 2, which is where the branches part.
    for _ in 0..7 {
        disconnect_block(&mut state, &applied.pop().unwrap());
    }
    assert_eq!(state.tip().unwrap().height, 2);
    assert_eq!(
        state.supply(),
        params.emitted_by(2),
        "an undo left the total somewhere the schedule does not put it"
    );
    assert_eq!(
        state.coinbase_matures_at(&paid_by),
        Some(8),
        "the first reward went back into the window it had left"
    );
    assert!(
        state.hot_note(&reward).is_some(),
        "and the note it paid is unspent again"
    );

    // A rival branch of two blocks, so the tip lands at height 4: lower than
    // the branch that was left, and below the maturity of the reward.
    let mut rival_applied: Vec<ConnectedBlock> = Vec::new();
    for height in 3..5u64 {
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), rival.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        rival_applied.push(connect_block(&mut state, &block, &params, NOW).unwrap());
    }
    assert_eq!(state.tip().unwrap().height, 4);
    assert_eq!(
        state.supply(),
        params.emitted_by(4),
        "the schedule pays by height, so a shorter branch has paid out less"
    );

    // And the reward is locked again. The block that would carry the spend
    // sits at height 5, which is three short of the maturity.
    let mut spend = Transfer::new(
        vec![Input::hot(reward)],
        vec![Note::new(
            reward_note.value.checked_sub(pebbles(1)).unwrap(),
            alice.public_key(),
        )],
    );
    spend.sign_input(params.network, 0, &reward_note, &miner);
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(
            params.reward_at(height).checked_add(pebbles(1)).unwrap(),
            rival.public_key(),
        )],
    );
    let refused = assemble_block(&state, coinbase, vec![spend], &params, clock + 600, 0);
    assert!(
        matches!(
            refused,
            Err(BlockError::InvalidTransfer {
                index: 0,
                source: TransferError::ImmatureCoinbase { matures_at: 8, .. },
            })
        ),
        "a reward that stopped being settled was still spendable: {refused:?}"
    );

    // Back the other way: undo the rival and reapply what was there, and the
    // ledger has to be the one it was, to the root.
    for _ in 0..2 {
        disconnect_block(&mut state, &rival_applied.pop().unwrap());
    }
    assert_eq!(state.supply(), params.emitted_by(2));
    for height in 3..10u64 {
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        // The same blocks as the first time round, so the timestamps have to
        // be the ones they had.
        let block = assemble_block(
            &state,
            coinbase,
            Vec::new(),
            &params,
            1_000 + (height + 1) * 600,
            0,
        )
        .unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
    }
    assert_eq!(state.tip().unwrap().height, 9);
    assert_eq!(
        state.state_root(),
        at_nine,
        "the branch came back different from the one that was left"
    );
    assert_eq!(state.supply(), params.emitted_by(9));
    assert_eq!(
        state.coinbase_matures_at(&paid_by),
        None,
        "and the reward is settled again"
    );
}

// ---------------------------------------------------------------------------
// 3. One tier or the other, never both and never neither.
// ---------------------------------------------------------------------------

/// A block that spends and evicts at once puts no note in two places.
///
/// The eviction order is the oldest hot note first, and the oldest hot note is
/// exactly the one a spender is most likely to be spending. If a block could
/// both spend a note and push it down, the ledger would take it out of the hot
/// set for the spend and put it into the cold set for the fall, and the money
/// would exist twice: once as a leaf nobody can spend, once as the outputs it
/// paid for.
///
/// Asked of the transitions a real chain produces rather than of the planner
/// on its own, because the two have to agree and only one of them is what a
/// block commits to.
#[test]
fn a_note_the_block_spends_is_never_a_note_the_block_pushes_down() {
    // A tier of eight, so every block after the first is evicting, and a
    // reward spendable at once so the spends land where the evictions do.
    let params = ConsensusParams::testnet()
        .with_hot_capacity(8)
        .with_coinbase_maturity(0);
    let miner = wallet(1);
    let alice = wallet(2);
    let mut state = LedgerState::archiving();
    let mut purse: Vec<(NoteId, Note)> = Vec::new();
    let mut evictions = 0usize;
    let mut spends = 0usize;

    for height in 0..40u64 {
        // Split the reward, so a block creates several notes and pushes
        // several out.
        let each = params.reward_at(height).as_pebbles() / 4;
        let outputs: Vec<Note> = (0..4)
            .map(|_| Note::new(Amount::from_pebbles(each).unwrap(), miner.public_key()))
            .collect();
        let coinbase = CoinbaseTransaction::new(height, outputs);

        // And spend the oldest note still in the hot set, which is the one
        // eviction would otherwise reach for.
        let mut transfers = Vec::new();
        if let Some(position) = purse
            .iter()
            .position(|(id, _)| state.hot_note(id).is_some())
        {
            let (id, note) = purse.remove(position);
            let mut transfer = Transfer::new(
                vec![Input::hot(id)],
                vec![Note::new(
                    note.value.checked_sub(pebbles(1)).unwrap(),
                    alice.public_key(),
                )],
            );
            transfer.sign_input(params.network, 0, &note, &miner);
            transfers.push(transfer);
        }

        let fees = if transfers.is_empty() {
            Amount::ZERO
        } else {
            pebbles(1)
        };
        let mut coinbase = coinbase;
        if let Some(first) = coinbase.outputs.first_mut() {
            first.value = first.value.checked_add(fees).unwrap();
        }
        let block = assemble_block(
            &state,
            coinbase,
            transfers,
            &params,
            1_000 + height * 600,
            0,
        )
        .unwrap();
        let connected = connect_block(&mut state, &block, &params, NOW).unwrap();
        let moved = &connected.transition;

        let pushed: BTreeSet<NoteId> = moved.evicted.iter().map(|(id, _)| *id).collect();
        let taken: BTreeSet<NoteId> = moved.spent_hot.iter().copied().collect();
        let lifted: BTreeSet<NoteId> = moved.spent_cold.iter().map(|spend| spend.id).collect();
        assert!(
            pushed.is_disjoint(&taken),
            "block {height} both spent and pushed down the same note"
        );
        assert!(
            pushed.is_disjoint(&lifted),
            "block {height} pushed down a note it had taken out of the cold set"
        );
        assert!(
            taken.is_disjoint(&lifted),
            "block {height} spent one note out of both tiers"
        );
        // And no note is in both tiers afterwards, which is the property the
        // three above are the block's own share of.
        for (id, _) in &moved.evicted {
            assert!(
                state.hot_note(id).is_none(),
                "a note that fell is still in the hot set"
            );
        }
        evictions += pushed.len();
        spends += taken.len() + lifted.len();

        for (id, note) in block.coinbase.created_notes() {
            purse.push((id, note));
        }
        for transfer in &block.transfers {
            for (id, note) in transfer.created_notes() {
                if note.owner == miner.public_key() {
                    purse.push((id, note));
                }
            }
        }
    }

    println!("{evictions} notes pushed down and {spends} spent over forty blocks");
    assert!(evictions > 0, "nothing fell, so nothing was tested");
    assert!(spends > 0, "nothing was spent, so nothing was tested");
    assert_eq!(
        state.supply(),
        params.emitted_by(39),
        "the tier moved money about and the total did not stay put"
    );
}

fn pebbles(value: u64) -> Amount {
    Amount::from_pebbles(value).unwrap()
}

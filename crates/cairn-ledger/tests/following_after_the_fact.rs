//! A node told to follow an address after the notes have already fallen.
//!
//! `watch_owner` takes up the fallen notes already sitting in the grace
//! window, because the node is holding a path for each of them anyway and
//! dropping it when the window ages past would strand the money. Those notes
//! belong to no block, so no undo record names them.
//!
//! That was read as harmless, on the grounds that the case it exists for is a
//! node handed a ledger it can undo nothing below. It is not: `watch_owner`
//! is what a wallet asks a *running* node for, and a reorganisation that
//! undoes the block one of those notes fell in reaches every one of them.
//!
//! What went wrong when it did. The note went back into the hot set and the
//! entry stayed, so the node answered "it fell at position seven" about a note
//! that was hot, and could produce no proof for a place the forest no longer
//! had. Then the branch that won landed the same note somewhere else, and the
//! order kept beside the map gained a second entry for it while the map gained
//! none. That order is what decides which followed note is let go of when the
//! ceiling bites, so the stray entry costs a note that is still followed; a
//! debug build stops on the length assertion in `commit` instead, which is a
//! node a wallet can halt by asking it to follow an address.
//!
//! So the property is the one a person would state: being told after the fact
//! lands in the same place as being told from the start, whatever the chain
//! does afterwards.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use cairn_accumulator::{Forest, ForestProof};
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::{HotEntry, GRACE_NOTES, WATCHED_NOTES};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, disconnect_block, mine_block, ConsensusParams,
};
use cairn_ledger::{Block, ConnectedBlock, LedgerState};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;

/// Small enough that a note falls every block or two, so a run of a dozen
/// blocks fills the grace window with something worth following.
const HOT: usize = 4;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(HOT)
        .with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn candidate(
    state: &LedgerState,
    clock: &mut u64,
    miner: &SecretKey,
    transfers: Vec<Transfer>,
) -> Block {
    let params = params();
    let height = state.next_height().unwrap();
    *clock += 600;
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    assemble_block(state, coinbase, transfers, &params, *clock, 0).unwrap()
}

/// Every note the node says it follows, sorted, with where it says it fell.
fn followed(state: &LedgerState) -> Vec<(NoteId, u64)> {
    let mut held: Vec<(NoteId, u64)> = state
        .watched_notes()
        .map(|(id, position, _)| (id, position))
        .collect();
    held.sort_unstable();
    held
}

/// Notes it follows and cannot prove.
///
/// The release-visible half. A wallet asking where its note fell is answered
/// out of this map, and an answer the node cannot back with a path is an
/// answer about a note that is not there.
fn unprovable(state: &LedgerState) -> Vec<(NoteId, u64)> {
    state
        .watched_notes()
        .filter(|(id, position, note)| {
            !state.cold().proof_of(*position).is_some_and(|proof| {
                state
                    .cold()
                    .verify(*position, cairn_ledger::cold_leaf(id, note), &proof)
            })
        })
        .map(|(id, position, _)| (id, position))
        .collect()
}

#[test]
fn a_node_told_late_follows_what_a_node_told_from_the_start_follows() {
    let params = params();
    let miner = wallet(1);

    // Told after the run, so the back-fill in `watch_owner` is what puts the
    // notes in the map.
    let mut late = LedgerState::new();
    // Told before the first block, so every entry was put there by the block
    // that landed the note.
    let mut early = LedgerState::new();
    early.watch_owner(miner.public_key());

    let mut clock = 1_000u64;
    let mut late_undo: Vec<ConnectedBlock> = Vec::new();
    let mut early_undo: Vec<ConnectedBlock> = Vec::new();

    for _ in 0..12 {
        let block = candidate(&late, &mut clock, &miner, Vec::new());
        late_undo.push(connect_block(&mut late, &block, &params, NOW).unwrap());
        early_undo.push(connect_block(&mut early, &block, &params, NOW).unwrap());
    }
    late.watch_owner(miner.public_key());

    let fell = late.cold_len();
    assert!(
        fell >= 4,
        "only {fell} notes fell, so there is little to follow"
    );
    assert_eq!(
        followed(&late),
        followed(&early),
        "the two nodes do not start out following the same notes"
    );
    assert!(unprovable(&late).is_empty());
    assert!(unprovable(&early).is_empty());

    // Two blocks off both, which takes two of those notes back out of the cold
    // set and into the hot one.
    let before = late.next_cold_position();
    for _ in 0..2 {
        disconnect_block(&mut late, &late_undo.pop().unwrap());
        disconnect_block(&mut early, &early_undo.pop().unwrap());
    }
    assert!(
        late.next_cold_position() < before,
        "the undo took nothing back out of the cold set, so nothing is being tested"
    );
    assert_eq!(
        unprovable(&late),
        Vec::new(),
        "the node follows a note it cannot prove: it went back into the hot set \
         and the entry stayed behind"
    );
    assert_eq!(
        followed(&late),
        followed(&early),
        "undoing a block left the node told late following notes the node told \
         from the start does not"
    );

    // The branch that wins spends the note that would otherwise have fallen
    // first, so the eviction order shifts and the next note to fall takes a
    // place a different note had held.
    let mut by_age: Vec<(NoteId, HotEntry)> = early.hot_notes().collect();
    by_age.sort_unstable_by_key(|(id, entry)| (entry.height, *id));
    let (spend_id, spend_entry) = by_age[0];
    let mut transfer = Transfer::new(
        vec![Input::hot(spend_id)],
        vec![Note::new(spend_entry.note.value, wallet(3).public_key())],
    );
    transfer.sign_input(params.network, 0, &spend_entry.note, &miner);

    let block = candidate(&early, &mut clock, &miner, vec![transfer]);
    connect_block(&mut early, &block, &params, NOW).unwrap();
    // On the node told late this is where the map and the order beside it used
    // to come apart, which a debug build stops on.
    connect_block(&mut late, &block, &params, NOW).unwrap();

    assert_eq!(
        followed(&late),
        followed(&early),
        "the two nodes ended a reorganisation following different notes"
    );
    assert!(unprovable(&late).is_empty());
    assert!(unprovable(&early).is_empty());
    assert!(
        followed(&late).iter().any(|(_, at)| *at >= before - 2),
        "the winning branch landed nothing, so the second half of this proves nothing"
    );
}

// ---------------------------------------------------------------------------
// Told late on a node whose followed set is full.
// ---------------------------------------------------------------------------

/// Rules under which a single block can fill the grace window: a hot set of
/// one, so everything a block pays falls at once, and room for four thousand
/// outputs in a block.
fn crowded() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(1)
        .with_coinbase_maturity(0)
        .with_max_evictions(1 << 20)
        .with_max_block_bytes(8 << 20)
}

/// `max_outputs_per_transfer` on every network.
const OUTPUTS: usize = 256;

fn pebbles(value: u64) -> Amount {
    Amount::from_pebbles(value).unwrap()
}

/// A coinbase paying `funder` sixteen equal notes.
fn sixteen(height: u64, funder: &SecretKey, extra: &[u8]) -> CoinbaseTransaction {
    let each = pebbles(crowded().reward_at(height).as_pebbles() / 16);
    CoinbaseTransaction::with_extra(
        height,
        vec![Note::new(each, funder.public_key()); 16],
        extra.to_vec(),
    )
}

/// Spends one of `funder`'s notes, hot or in the grace window, into 256 notes
/// of `value` for `payee`. A note in the window takes no proof from its
/// spender, which is what the window is for.
fn fan_out(
    state: &LedgerState,
    spent: NoteId,
    funder: &SecretKey,
    payee: &SecretKey,
    value: u64,
) -> Transfer {
    let note = state
        .hot_note(&spent)
        .or_else(|| state.within_grace(&spent).map(|(_, note)| note))
        .expect("a note this node holds in full");
    let outputs = vec![Note::new(pebbles(value), payee.public_key()); OUTPUTS];
    let mut transfer = Transfer::new(vec![Input::hot(spent)], outputs);
    transfer.sign_input(crowded().network, 0, &note, funder);
    transfer
}

fn crowded_block(
    state: &LedgerState,
    coinbase: CoinbaseTransaction,
    transfers: Vec<Transfer>,
) -> Block {
    let height = state.next_height().unwrap();
    let block = assemble_block(
        state,
        coinbase,
        transfers,
        &crowded(),
        1_000 + height * 600,
        0,
    )
    .expect("a block this chain would make");
    mine_block(block, 1 << 20).expect("the floor accepts the first nonce")
}

/// Builds the next block on `state` and applies it there.
fn extend(
    state: &mut LedgerState,
    coinbase: CoinbaseTransaction,
    transfers: Vec<Transfer>,
) -> ConnectedBlock {
    let block = crowded_block(state, coinbase, transfers);
    connect_block(state, &block, &crowded(), NOW).expect("a block assembled against this state")
}

/// A node following `owner` with a full set, asked to follow `other` as well,
/// and a rival to the block that ran the owner's cheapest notes out of the
/// grace window.
struct Crowded {
    follower: LedgerState,
    after_one: LedgerState,
    second: ConnectedBlock,
    third: ConnectedBlock,
    rival: Block,
    cheapest: (NoteId, u64),
}

fn crowded_follower() -> Crowded {
    let funder = wallet(11);
    let owner = wallet(12);
    let other = wallet(13);
    let mut follower = LedgerState::new();
    follower.watch_owner(owner.public_key());

    let first_pay = sixteen(0, &funder, b"");
    extend(&mut follower, first_pay.clone(), Vec::new());

    // Four thousand notes to the owner, all falling at once into the window.
    let second_pay = sixteen(1, &funder, b"");
    let transfers = (0..16u32)
        .map(|index| {
            fan_out(
                &follower,
                NoteId::new(first_pay.id(), index),
                &funder,
                &owner,
                100_000,
            )
        })
        .collect();
    extend(&mut follower, second_pay.clone(), transfers);
    let after_one = follower.clone();

    // Four thousand more, worth twice as much, which runs the first four
    // thousand out of the window while the owner still wants their paths.
    let third_pay = sixteen(2, &funder, b"");
    let transfers = (0..16u32)
        .map(|index| {
            fan_out(
                &follower,
                NoteId::new(second_pay.id(), index),
                &funder,
                &owner,
                200_000,
            )
        })
        .collect();
    let second = extend(&mut follower, third_pay.clone(), transfers);
    assert!(
        follower.watched_notes().count() <= WATCHED_NOTES,
        "the followed set is at or under its ceiling, so no block has let anything go"
    );

    // The owner's cheapest note: out of the window now, and first in line
    // when the ceiling bites.
    let cheapest = after_one
        .grace_window()
        .into_iter()
        .flatten()
        .filter(|(_, _, note)| note.owner == owner.public_key())
        .map(|(id, position, _)| (id, position))
        .min_by_key(|(_, position)| *position)
        .expect("the owner was paid in the first block");
    assert!(
        follower.within_grace(&cheapest.0).is_none()
            && follower.cold().proof_of(cheapest.1).is_some(),
        "the cheapest note left the window and its path was kept for the owner"
    );

    // Two hundred and fifty six notes to somebody else, in the window.
    let to_other = fan_out(
        &follower,
        NoteId::new(third_pay.id(), 0),
        &funder,
        &other,
        300_000,
    );
    let third = extend(&mut follower, sixteen(3, &funder, b""), vec![to_other]);

    // A rival to the block that ran the cheapest note out of the window,
    // spending it from the window with no proof, as the window allows.
    let note = after_one
        .within_grace(&cheapest.0)
        .map(|(_, note)| note)
        .unwrap();
    let mut spend = Transfer::new(
        vec![Input::hot(cheapest.0)],
        vec![Note::new(pebbles(50_000), owner.public_key())],
    );
    spend.sign_input(crowded().network, 0, &note, &owner);
    let rival = crowded_block(&after_one, sixteen(2, &funder, b"rival"), vec![spend]);
    let mut bystander = after_one.clone();
    connect_block(&mut bystander, &rival, &crowded(), NOW)
        .expect("a node that follows nobody takes the rival");

    // And the wallet asks the running node to follow `other`, whose notes
    // the window holds: the set goes over its ceiling.
    follower.watch_owner(other.public_key());

    Crowded {
        follower,
        after_one,
        second,
        third,
        rival,
        cheapest,
    }
}

/// A node asked to follow a second owner on a full set, and then carried back
/// by a reorganisation, still takes a block every other node takes.
///
/// `watch_owner` trimmed the set back under its ceiling with a record it threw
/// away, and let go of the path of the cheapest note it held: one the owner's
/// block had already run out of the window, keeping the path only because the
/// owner was followed. No record anywhere held that path, so undoing the block
/// put the note back into the committed window with nothing behind it, and a
/// proofless spend of it every other node takes was refused here as
/// `MissingProof`, with the same state root as everyone. The node could not
/// hand its ledger to a newcomer either.
#[test]
fn a_node_asked_to_follow_more_than_its_ceiling_takes_a_valid_block_after_a_reorganisation() {
    let Crowded {
        mut follower,
        after_one,
        second,
        third,
        rival,
        cheapest,
    } = crowded_follower();

    assert!(
        follower.watched_notes().count() <= WATCHED_NOTES + GRACE_NOTES,
        "asking once put the set over its ceiling by more than one window"
    );

    disconnect_block(&mut follower, &third);
    disconnect_block(&mut follower, &second);
    assert_eq!(
        follower.state_root(),
        after_one.state_root(),
        "back on the state every node agrees on"
    );
    assert!(
        follower.within_grace(&cheapest.0).is_some(),
        "the note is in the window again, as the commitment says"
    );

    let mut carried_on = follower.clone();
    assert!(
        connect_block(&mut carried_on, &rival, &crowded(), NOW).is_ok(),
        "the same state root as every other node, and a block they all take was refused"
    );
    assert!(
        follower
            .handover(
                rival.header,
                rival.header,
                Forest::default(),
                ForestProof::default(),
                Vec::new(),
                Vec::new(),
            )
            .is_ok(),
        "a note in the window has no path, so this ledger cannot be handed to anybody"
    );
}

/// The block after the ask brings the set back under its ceiling, and undoing
/// that block puts back every path it let go of.
///
/// Letting go at the next block rather than at the ask is what makes the let
/// go undoable: the block's own record holds each path it drops. Asked of the
/// same scenario, with that block in between and undone first.
#[test]
fn the_block_after_the_ask_trims_the_set_and_its_undo_puts_the_paths_back() {
    let Crowded {
        mut follower,
        after_one,
        second,
        third,
        rival,
        cheapest,
    } = crowded_follower();

    let funder = wallet(11);
    let fourth = extend(&mut follower, sixteen(4, &funder, b""), Vec::new());
    assert!(
        follower.watched_notes().count() <= WATCHED_NOTES,
        "a block went by and the set is still over its ceiling"
    );
    assert!(
        follower.cold().proof_of(cheapest.1).is_none(),
        "the cheapest note is the one the ceiling lets go of"
    );

    disconnect_block(&mut follower, &fourth);
    assert!(
        follower.cold().proof_of(cheapest.1).is_some(),
        "undoing the block that let the path go did not put it back"
    );
    disconnect_block(&mut follower, &third);
    disconnect_block(&mut follower, &second);
    assert_eq!(follower.state_root(), after_one.state_root());

    let taken = connect_block(&mut follower, &rival, &crowded(), NOW);
    assert!(
        taken.is_ok(),
        "the same state root as every other node, and a block they all take was refused"
    );
}

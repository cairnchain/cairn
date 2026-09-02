//! Adversarial audit of the undo record, the delta rewind, and the handover,
//! as they stand after testnet-6.
//!
//! Read only. Nothing here changes a source file.
//!
//! The claim under test is that a node that undoes a block reaches, byte for
//! byte through every commitment and through every path it keeps current, the
//! state it would have reached by never having applied it; and that a ledger
//! can be handed over after any sequence of spends, by a plain node and by an
//! archivist alike, with the two producing the same thing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::cast_possible_truncation
)]

use std::fmt::Write as _;

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::state::{header_leaf, GRACE_BLOCKS};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, disconnect_block, ConsensusParams};
use cairn_ledger::{ConnectedBlock, LedgerState};
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const HOT: usize = 4;
const BURIAL: u64 = 8;
const MATURITY: u64 = 3;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(HOT)
        .with_burial(BURIAL)
        .with_coinbase_maturity(MATURITY)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Everything two nodes following the same chain must agree about, whatever
/// kind of node each is.
///
/// The proofs are in here on purpose. A plain node mends the paths it keeps
/// current, an archivist rebuilds them from its leaves, and the whole of the
/// delta rewind rests on those two answers being the same one.
fn shared(state: &LedgerState) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "state_root {:?}", state.state_root());
    let _ = writeln!(out, "grace_root {:?}", state.grace_root());
    let _ = writeln!(out, "cold {:?}", state.cold_roots());
    let _ = writeln!(out, "supply {:?}", state.supply().as_pebbles());
    let _ = writeln!(out, "history {:?}", state.history_root());
    let _ = writeln!(out, "before_tip {:?}", state.headers_before_tip());
    let _ = writeln!(out, "committed {}", state.headers_committed());
    let _ = writeln!(out, "tip {:?}", state.tip());
    let _ = writeln!(out, "recent {:?}", state.recent_headers());
    let mut hot: Vec<_> = state.hot_notes().collect();
    hot.sort_by_key(|(id, _)| id.encode());
    for (id, entry) in hot {
        let _ = writeln!(out, "hot {:?} {:?} {}", id, entry.note, entry.height);
    }
    for (at, coinbase) in state.maturing() {
        let _ = writeln!(out, "maturing {at} {coinbase:?}");
    }
    let mut listed = 0usize;
    for (index, block) in state.grace_window().iter().enumerate() {
        for (id, position, note) in block {
            listed += 1;
            let _ = writeln!(out, "grace {index} {id:?} {position} {note:?}");
            // The invariant a handover rests on. A note in the window with no
            // proof is a ledger nobody can be handed: the sender drops the
            // proof it does not have and the receiver refuses for a missing
            // one. `LedgerState::handover` says nothing when this fails, so it
            // is said here.
            let proof = state
                .cold()
                .proof_of(*position)
                .unwrap_or_else(|| panic!("no proof for the window note at {position}"));
            assert!(
                state
                    .cold()
                    .verify(*position, cairn_ledger::cold_leaf(id, note), &proof),
                "the proof kept for the window note at {position} does not check out"
            );
            let _ = writeln!(out, "  proof {proof:?}");
            assert_eq!(
                state.within_grace(id).map(|(at, _)| at),
                Some(*position),
                "a note in the window is not in the index at the place the window gives"
            );
        }
    }
    assert_eq!(
        listed,
        state.grace_len(),
        "the window and the index it is read through disagree"
    );
    out
}

/// The same, plus what only this node holds.
fn full(state: &LedgerState) -> String {
    let mut out = shared(state);
    for (id, position, note) in state.watched_notes() {
        let _ = writeln!(out, "watched {id:?} {position} {note:?}");
        let _ = writeln!(out, "  proof {:?}", state.cold().proof_of(position));
    }
    let _ = writeln!(out, "paths {}", state.watched_paths());
    out
}

/// Three nodes of different kinds, following one chain in lockstep.
struct Network {
    /// Keeps sixty four hashes and the paths the window wants.
    plain: LedgerState,
    /// The same, and follows one owner as well, so the ceiling and the window
    /// both have a say in which paths it keeps.
    watcher: LedgerState,
    /// Keeps every leaf.
    keeper: LedgerState,
    /// Each node's ledger as it stood after every block, so a handover can be
    /// taken from where a node really takes one: far below its own tip.
    past_plain: Vec<LedgerState>,
    past_watcher: Vec<LedgerState>,
    past_keeper: Vec<LedgerState>,
    plain_undo: Vec<ConnectedBlock>,
    watcher_undo: Vec<ConnectedBlock>,
    keeper_undo: Vec<ConnectedBlock>,
    blocks: Vec<Block>,
    headers: Vec<BlockHeader>,
    history: Archive,
    clock: u64,
    /// Notes believed unspent: identifier, note, and who can sign for it.
    ///
    /// Carried by the network rather than by the generator, so a chain built a
    /// block at a time is the same chain as one built all at once.
    purse: Vec<(NoteId, Note, u8, u64)>,
}

impl Network {
    fn new(followed: &SecretKey) -> Self {
        let mut watcher = LedgerState::new();
        watcher.watch_owner(followed.public_key());
        Self {
            plain: LedgerState::new(),
            watcher,
            keeper: LedgerState::archiving(),
            past_plain: Vec::new(),
            past_watcher: Vec::new(),
            past_keeper: Vec::new(),
            plain_undo: Vec::new(),
            watcher_undo: Vec::new(),
            keeper_undo: Vec::new(),
            blocks: Vec::new(),
            headers: Vec::new(),
            history: Archive::new(),
            clock: 1_000,
            purse: Vec::new(),
        }
    }

    fn height(&self) -> u64 {
        self.keeper.next_height().unwrap()
    }

    fn apply(&mut self, block: &Block) {
        let params = params();
        self.plain_undo
            .push(connect_block(&mut self.plain, block, &params, NOW).unwrap());
        self.watcher_undo
            .push(connect_block(&mut self.watcher, block, &params, NOW).unwrap());
        self.keeper_undo
            .push(connect_block(&mut self.keeper, block, &params, NOW).unwrap());
        self.past_plain.push(self.plain.clone());
        self.past_watcher.push(self.watcher.clone());
        self.past_keeper.push(self.keeper.clone());
        self.blocks.push(block.clone());
        self.history.add(header_leaf(&block.header.id())).unwrap();
        self.headers.push(block.header);
    }

    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let params = params();
        let height = self.height();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&self.keeper, coinbase, transfers, &params, self.clock, 0).unwrap();
        self.apply(&block);
        block
    }

    fn undo_one(&mut self) {
        let plain = self.plain_undo.pop().unwrap();
        disconnect_block(&mut self.plain, &plain);
        let watcher = self.watcher_undo.pop().unwrap();
        disconnect_block(&mut self.watcher, &watcher);
        let keeper = self.keeper_undo.pop().unwrap();
        disconnect_block(&mut self.keeper, &keeper);
        self.past_plain.pop();
        self.past_watcher.pop();
        self.past_keeper.pop();
        self.blocks.pop();
        self.headers.pop();
        assert!(self.history.remove_last());
    }

    /// The witness this chain's state calls for, and nothing about the
    /// spender's preference.
    fn witness(&self, id: NoteId, note: Note) -> Option<Input> {
        if self.keeper.hot_note(&id).is_some() {
            return Some(Input::hot(id));
        }
        if self.keeper.within_grace(&id).is_some() {
            return Some(Input::hot(id));
        }
        let position = self.keeper.cold().locate(&id, &note)?;
        let proof = self.keeper.cold().prove(position)?;
        Some(Input::cold(id, note, position, proof))
    }

    fn spendable(&self, id: NoteId) -> bool {
        match self.keeper.coinbase_matures_at(&id.source) {
            None => true,
            Some(at) => self.height() >= at,
        }
    }

    fn handover(&self) -> (Handover, Handover, Handover) {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let tip_history = self.keeper.headers_before_tip();
        let anchor = self
            .history
            .prove_in(anchor_height, tip.height)
            .expect("the anchor sits in the forest before the tip");
        let first = (anchor_height as usize + 1).saturating_sub(RECENT_HEADERS);
        let buried = self.headers[(anchor_height as usize + 1)..].to_vec();
        let recent = self.headers[first..=anchor_height as usize].to_vec();
        // Each node's own ledger at the anchor, which is what it would send.
        let build = |state: &LedgerState| {
            state
                .handover(
                    at,
                    tip,
                    tip_history.clone(),
                    anchor.clone(),
                    buried.clone(),
                    recent.clone(),
                )
                .expect("every note in the window has a path")
        };
        (
            build(&self.past_plain[anchor_height as usize]),
            build(&self.past_watcher[anchor_height as usize]),
            build(&self.past_keeper[anchor_height as usize]),
        )
    }
}

/// A transfer paying `note` on to `to`, split into `parts` so a block can be
/// made to push notes out of the hot set.
fn pay(
    net: &Network,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    to: &SecretKey,
    parts: usize,
) -> Option<Transfer> {
    let input = net.witness(id, note)?;
    let each = note.value.as_pebbles() / parts as u64;
    if each == 0 {
        return None;
    }
    let mut outputs = Vec::new();
    let mut left = note.value.as_pebbles();
    for _ in 0..parts - 1 {
        outputs.push(Note::new(Amount::from_pebbles(each)?, to.public_key()));
        left -= each;
    }
    // The last output carries the remainder less one pebble, so the transfer
    // pays a fee and the supply has something to move against.
    outputs.push(Note::new(Amount::from_pebbles(left - 1)?, to.public_key()));
    let mut transfer = Transfer::new(vec![input], outputs);
    transfer.sign_input(params().network, 0, &note, owner);
    Some(transfer)
}

/// Builds a chain with the whole cast in it: evictions, spends out of the
/// grace window, spends out of the cold set with a proof the spender carries,
/// coinbases crossing their maturity, and fees moving the supply.
fn busy_chain(net: &mut Network, miner: &SecretKey, alice: &SecretKey, bob: &SecretKey, len: u64) {
    for _ in 0..len {
        let round = net.height();
        let mut transfers = Vec::new();
        let mut used: Vec<usize> = Vec::new();
        // Several spends a block, spread across the purse so that one is old
        // (cold, with a proof the spender carries), one is in the window, and
        // one is still hot. Notes that fell in one block took consecutive
        // places, so spreading the picks is what puts two removals in one tree
        // and two in different ones.
        // A note is spent either while it is still young, which reaches the
        // hot set and the window, or once it has aged past the window
        // entirely, which is the only way to reach a spend that carries its
        // own proof. Notes in between are left alone so that some of them get
        // there.
        let mut picks: Vec<usize> = Vec::new();
        let mut young = 0usize;
        let mut old = 0usize;
        for (at, (_, _, _, born)) in net.purse.iter().enumerate() {
            let age = round.saturating_sub(*born);
            if age > GRACE_BLOCKS as u64 + 4 && old < 3 {
                picks.push(at);
                old += 1;
            } else if age <= 2 && young < 3 {
                picks.push(at);
                young += 1;
            }
        }
        picks.sort_unstable();
        for pick in picks {
            let (id, note, owner, _) = net.purse[pick];
            if !net.spendable(id) {
                continue;
            }
            let signer = wallet(owner);
            let (to, to_seed) = if round % 2 == 0 {
                (alice, 2u8)
            } else {
                (bob, 3u8)
            };
            let parts = 1 + (round as usize % 3);
            let Some(transfer) = pay(net, id, note, &signer, to, parts) else {
                continue;
            };
            used.push(pick);
            for (made, note) in transfer.created_notes() {
                net.purse.push((made, note, to_seed, round));
            }
            transfers.push(transfer);
        }
        used.sort_unstable();
        for pick in used.into_iter().rev() {
            net.purse.remove(pick);
        }
        let block = net.mine(miner, transfers);
        net.purse.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(params().initial_reward, miner.public_key()),
            1,
            round,
        ));
    }
}

/// A plain node, a following node and an archivist agree on every commitment
/// and on every path the grace window needs, block after block.
#[test]
fn three_kinds_of_node_hold_the_same_window() {
    let (miner, alice, bob) = (wallet(1), wallet(2), wallet(3));
    let mut net = Network::new(&alice);
    // Past the window's sixty four blocks, so blocks age off the far end and
    // the paths that went with them are let go of.
    for step in 0..80u64 {
        busy_chain(&mut net, &miner, &alice, &bob, 1);
        let plain = shared(&net.plain);
        assert_eq!(plain, shared(&net.watcher), "watcher differs at {step}");
        assert_eq!(plain, shared(&net.keeper), "archivist differs at {step}");
    }
}

/// Undoing a block leaves the state it would have had by never applying it.
///
/// Every commitment, every note, and every path the node keeps current, for a
/// reorganisation of every depth from one block to twelve.
#[test]
fn an_undo_of_any_depth_reaches_the_state_that_was_there() {
    let (miner, alice, bob) = (wallet(1), wallet(2), wallet(3));
    for depth in 1..=12usize {
        let mut net = Network::new(&alice);
        // Past the grace window's own edge, so every undo below crosses it.
        busy_chain(&mut net, &miner, &alice, &bob, 70);
        let mut expected_plain = Vec::new();
        let mut expected_watcher = Vec::new();
        let mut expected_keeper = Vec::new();
        for _ in 0..depth {
            expected_plain.push(full(&net.plain));
            expected_watcher.push(full(&net.watcher));
            expected_keeper.push(full(&net.keeper));
            busy_chain(&mut net, &miner, &alice, &bob, 1);
        }
        for step in (0..depth).rev() {
            net.undo_one();
            assert_eq!(
                full(&net.plain),
                expected_plain[step],
                "plain node, depth {depth}, back to step {step}"
            );
            assert_eq!(
                full(&net.watcher),
                expected_watcher[step],
                "following node, depth {depth}, back to step {step}"
            );
            assert_eq!(
                full(&net.keeper),
                expected_keeper[step],
                "archivist, depth {depth}, back to step {step}"
            );
        }
    }
}

/// And a ledger undone to a point can still be handed over from it.
///
/// This is the claim the whole release turns on: after any sequence of spends
/// a handover is takeable, and the plain node and the archivist send the same
/// thing.
#[test]
fn a_handover_holds_after_any_sequence_of_spends() {
    let (miner, alice, bob) = (wallet(1), wallet(2), wallet(3));
    let mut net = Network::new(&alice);
    busy_chain(&mut net, &miner, &alice, &bob, 70);
    let params = params();
    for step in 0..20u64 {
        busy_chain(&mut net, &miner, &alice, &bob, 1);
        if net.headers.last().unwrap().height < BURIAL {
            continue;
        }
        let (plain, watcher, keeper) = net.handover();
        assert_eq!(
            plain.encode(),
            keeper.encode(),
            "a plain node and an archivist send different ledgers at {step}"
        );
        assert_eq!(
            plain.encode(),
            watcher.encode(),
            "following an owner changes what is sent at {step}"
        );
        let rebuilt = accept(&plain, &params)
            .unwrap_or_else(|error| panic!("handover refused at step {step}: {error}"));
        assert_eq!(
            rebuilt.state_root(),
            plain.at.state_root,
            "a rebuilt ledger does not reproduce its header at {step}"
        );
    }
}

/// A ledger rebuilt from a handover, then driven forward, then undone, is the
/// same as one that replayed the chain and was undone the same way.
#[test]
fn a_rebuilt_ledger_undoes_the_way_a_replayed_one_does() {
    let (miner, alice, bob) = (wallet(1), wallet(2), wallet(3));
    let mut net = Network::new(&alice);
    busy_chain(&mut net, &miner, &alice, &bob, 80);
    let params = params();

    let (plain, _, _) = net.handover();
    let anchor = plain.at.height;
    let mut rebuilt = accept(&plain, &params).expect("the handover is takeable");

    // Catch the rebuilt ledger up to the tip, block by block, as a newcomer
    // does, keeping what it takes to undo each one.
    let mut undo = Vec::new();
    let mut expected = Vec::new();
    for block in &net.blocks[(anchor as usize + 1)..] {
        expected.push(shared(&rebuilt));
        undo.push(
            connect_block(&mut rebuilt, block, &params, NOW).unwrap_or_else(|error| {
                panic!("a newcomer refused block {}: {error}", block.header.height)
            }),
        );
    }
    assert_eq!(
        rebuilt.state_root(),
        net.plain.state_root(),
        "a rebuilt ledger caught up to a different tip"
    );

    // And back down again, which crosses the grace window's own edge and the
    // maturity boundary on the way.
    for step in (0..undo.len()).rev() {
        let record = undo.pop().unwrap();
        disconnect_block(&mut rebuilt, &record);
        assert_eq!(
            shared(&rebuilt),
            expected[step],
            "a rebuilt ledger undone to {step} is not the one it was"
        );
    }
}

/// What the chains above actually put the machinery through.
///
/// A test that exercises nothing passes for the wrong reason, so this prints
/// the shape of the traffic and asserts the parts that matter were reached.
#[test]
fn the_traffic_reaches_the_parts_it_claims_to() {
    let (miner, alice, bob) = (wallet(1), wallet(2), wallet(3));
    let mut net = Network::new(&alice);
    let mut cold_spends = 0usize;
    let mut window_spends = 0usize;
    let mut dropped_blocks = 0usize;
    let mut most_watched = 0usize;
    let mut most_paths = 0usize;
    let mut window_full = 0usize;
    for _ in 0..150u64 {
        let before: Vec<u64> = net
            .keeper
            .grace_window()
            .iter()
            .flatten()
            .map(|(_, at, _)| *at)
            .collect();
        busy_chain(&mut net, &miner, &alice, &bob, 1);
        let block = net.blocks.last().unwrap();
        for transfer in &block.transfers {
            for input in &transfer.inputs {
                match &input.witness {
                    cairn_ledger::Witness::Cold(_) => cold_spends += 1,
                    cairn_ledger::Witness::Hot => {
                        if net.keeper.hot_entry(&input.note_id).is_none() && !before.is_empty() {
                            window_spends += 1;
                        }
                    }
                }
            }
        }
        let after: Vec<u64> = net
            .keeper
            .grace_window()
            .iter()
            .flatten()
            .map(|(_, at, _)| *at)
            .collect();
        for at in &before {
            if !after.contains(at) {
                dropped_blocks += 1;
            }
        }
        most_watched = most_watched.max(net.watcher.watched_notes().count());
        most_paths = most_paths.max(net.watcher.watched_paths());
        window_full = window_full.max(net.keeper.grace_window().len());
    }
    println!(
        "cold spends {cold_spends}, window spends {window_spends}, notes leaving the window \
         {dropped_blocks}, window depth {window_full}, followed notes {most_watched}, \
         paths {most_paths}"
    );
    assert!(cold_spends > 0, "no spend carried its own proof");
    assert!(dropped_blocks > 0, "nothing ever left the grace window");
    assert!(window_full >= 64, "the window never filled");
    assert!(most_watched > 0, "the following node followed nothing");
}

/// The handover a node really sends, built the way a node really builds one.
///
/// `cairn_chain::ChainStore::ledger_at` clones the state and undoes its way
/// down to the anchor, because keeping a second ledger about is what the undo
/// records exist to make unnecessary. So the ledger that goes out is one that
/// has been through a thousand undos, and every path the grace window needs
/// has to have survived all of them. Taking the handover from a snapshot, as
/// the test above does, never asks that question.
#[test]
fn a_handover_built_by_undoing_to_the_anchor_is_takeable() {
    let (miner, alice, bob) = (wallet(1), wallet(2), wallet(3));
    let params = params();
    for extra in [0u64, 1, 7, 23] {
        let mut net = Network::new(&alice);
        busy_chain(&mut net, &miner, &alice, &bob, 70 + extra);

        let tip = *net.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = net.headers[anchor_height as usize];
        let tip_history = net.plain.headers_before_tip();
        let anchor = net
            .history
            .prove_in(anchor_height, tip.height)
            .expect("the anchor sits in the forest before the tip");
        let first = (anchor_height as usize + 1).saturating_sub(RECENT_HEADERS);
        let buried = net.headers[(anchor_height as usize + 1)..].to_vec();
        let recent = net.headers[first..=anchor_height as usize].to_vec();

        // Down to the anchor by undoing, which is the one way a node has of
        // getting there.
        let expected_plain = full(&net.past_plain[anchor_height as usize]);
        let expected_watcher = full(&net.past_watcher[anchor_height as usize]);
        let expected_keeper = full(&net.past_keeper[anchor_height as usize]);
        while net.headers.last().unwrap().height > anchor_height {
            net.undo_one();
        }
        assert_eq!(full(&net.plain), expected_plain, "plain, extra {extra}");
        assert_eq!(
            full(&net.watcher),
            expected_watcher,
            "watcher, extra {extra}"
        );
        assert_eq!(
            full(&net.keeper),
            expected_keeper,
            "archivist, extra {extra}"
        );

        for (name, state) in [
            ("plain", &net.plain),
            ("watcher", &net.watcher),
            ("archivist", &net.keeper),
        ] {
            let handover = state
                .handover(
                    at,
                    tip,
                    tip_history.clone(),
                    anchor.clone(),
                    buried.clone(),
                    recent.clone(),
                )
                .unwrap_or_else(|error| {
                    panic!("the {name} node could not hand its undone ledger on: {error}")
                });
            let rebuilt = accept(&handover, &params).unwrap_or_else(|error| {
                panic!("the {name} node's undone ledger was refused, extra {extra}: {error}")
            });
            assert_eq!(rebuilt.state_root(), at.state_root);
        }
    }
}

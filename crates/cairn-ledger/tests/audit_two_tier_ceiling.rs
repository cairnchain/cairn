//! Adversarial audit of the two tier state: the ceiling, eviction, the grace
//! window, and reconstruction.
//!
//! Read only: nothing here changes a source file. Every test either
//! demonstrates a break or clears an area by exercising it.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::similar_names
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
/// Small enough that notes fall out of it inside a short test.
const HOT: usize = 8;
/// Shallow, so a test does not have to mine a thousand blocks.
const BURIAL: u64 = 8;

/// A reward is spendable at once here.
///
/// These tests all spend a coinbase shortly after mining it, and none of them
/// is about the wait that normally stands between the two. What the wait is
/// worth is audited in `audit_coinbase_maturity.rs`.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(HOT)
        .with_burial(BURIAL)
        .with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain, kept the way a node that has been running keeps one.
struct Node {
    state: LedgerState,
    past: Vec<LedgerState>,
    blocks: Vec<Block>,
    history: Archive,
    headers: Vec<BlockHeader>,
    clock: u64,
}

impl Node {
    /// A node that keeps every leaf, so it can rebuild any proof.
    fn archiving() -> Self {
        Self::with(LedgerState::archiving())
    }

    /// A node that keeps sixty four hashes and nothing else, which is what the
    /// design says an ordinary node is.
    fn plain() -> Self {
        Self::with(LedgerState::new())
    }

    fn with(state: LedgerState) -> Self {
        Self {
            state,
            past: Vec::new(),
            blocks: Vec::new(),
            history: Archive::new(),
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
        self.past.push(self.state.clone());
        self.blocks.push(block.clone());
        self.history
            .add(cairn_ledger::state::header_leaf(&block.header.id()))
            .unwrap();
        self.headers.push(block.header);
        block
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner, Vec::new());
        }
    }

    fn anchor_height(&self) -> u64 {
        self.headers.last().unwrap().height - BURIAL
    }

    fn buried(&self) -> &LedgerState {
        &self.past[self.anchor_height() as usize]
    }

    fn to_catch_up(&self) -> Vec<Block> {
        self.blocks[(self.anchor_height() as usize + 1)..].to_vec()
    }

    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let tip_history = self.state.headers_before_tip();
        let anchor = self
            .history
            .prove_in(anchor_height, tip.height)
            .expect("the header sits in the forest before the tip");
        let first = (anchor_height as usize + 1).saturating_sub(RECENT_HEADERS);
        state
            .handover(
                at,
                tip,
                tip_history,
                anchor,
                self.headers[(anchor_height as usize + 1)..].to_vec(),
                self.headers[first..=anchor_height as usize].to_vec(),
            )
            .expect("every note in the window has a path")
    }
}

/// Spends one note that the grace window still covers, returning its id.
fn spend_one_from_grace(node: &mut Node, owner: &SecretKey, payee: &SecretKey) -> NoteId {
    let params = params();
    let (id, _, note) = node
        .state
        .grace_window()
        .iter()
        .rev()
        .flatten()
        .copied()
        .find(|(_, _, note)| note.owner == owner.public_key())
        .expect("something the miner owns fell recently");

    let mut transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(note.value, payee.public_key())],
    );
    transfer.sign_input(params.network, 0, &note, owner);
    let block = node.mine(owner, vec![transfer]);
    assert_eq!(block.transfers.len(), 1, "the spend went into a block");
    id
}

/// A spend takes the note out of the grace window.
///
/// It did not, and that broke the handover outright. The window holds what
/// fell in the last sixty four blocks, which are exactly the notes most likely
/// to move. Spending one emptied its leaf and dropped the path the node was
/// keeping for it, and left the note on the window, so the window went on
/// naming a note nothing could prove.
///
/// The window is what fell recently and may still be spent with no proof from
/// the spender, and a note that has been spent may not be spent at all, so it
/// has no business there. Taking it out changes the window, which a header
/// commits to, so this is a consensus change and not a repair to bookkeeping.
#[test]
fn a_spend_takes_the_note_out_of_the_window() {
    let miner = wallet(1);
    let payee = wallet(2);

    let mut node = Node::plain();
    node.mine_empty(&miner, RECENT_HEADERS + 4);
    let before = node.state.grace_len();
    let spent = spend_one_from_grace(&mut node, &miner, &payee);

    assert!(
        node.state.within_grace(&spent).is_none(),
        "a spent note has no place in the window"
    );
    assert_eq!(
        node.state.grace_len(),
        node.state
            .grace_window()
            .iter()
            .map(Vec::len)
            .sum::<usize>(),
        "and the index says what the window says"
    );
    assert!(
        node.state.grace_len() < before + 16,
        "the window really moved"
    );

    // Every note left on the window has a path, and it still folds to the
    // commitment as it stands. That is the invariant the window rests on: a
    // spender presents nothing, so the node must hold one.
    for (id, position, note) in node.state.grace_window().iter().flatten() {
        let proof = node
            .state
            .cold()
            .proof_of(*position)
            .expect("a note on the window has a path");
        assert!(node
            .state
            .cold()
            .verify(*position, cairn_ledger::cold_leaf(id, note), &proof));
    }
    assert_eq!(
        node.state.watched_paths(),
        node.state.grace_len(),
        "and nothing else is being kept current"
    );
}

/// A ledger hands over after any sequence of spends, and a plain node and an
/// archivist hand over the same one.
///
/// Neither could. A spent note stayed on the window with its leaf emptied and
/// its path let go of, so a plain node carried a note it had no proof for and
/// the receiver, which wants one for every note on the window, refused the
/// whole ledger with `MissingGraceProof`. An archivist failed differently and
/// just as hard: it rebuilt a path to the now empty place, sent it, and the
/// receiver checked it against the note as it was before the spend and
/// answered `BadGraceProof`. The two errors are why the first form of this
/// read as a missing feature rather than as one fault.
///
/// It was not a corner. `examples/blocksize.rs` measures the window turning
/// over in twelve blocks at full blocks and says in its own words that a
/// fallen note is spent inside that same block, so on any chain with traffic
/// the handover was broken essentially always. That means nobody could join
/// without replaying the entire chain, which is the one thing this design
/// exists to make unnecessary, and an attacker who wanted it kept that way
/// paid one ordinary transfer of a hundred and ninety one bytes every sixty
/// four blocks.
#[test]
fn a_ledger_hands_over_across_any_sequence_of_spends() {
    let params = params();
    let miner = wallet(1);
    let payee = wallet(2);

    let mut plain = Node::plain();
    let spent = drive_with_spends(&mut plain, &miner, &payee);
    let mut keeper = Node::archiving();
    let also_spent = drive_with_spends(&mut keeper, &miner, &payee);
    assert!(spent.len() >= 5, "the run really did spend from the window");
    assert_eq!(spent, also_spent, "both nodes were driven the same way");
    assert_eq!(plain.state.state_root(), keeper.state.state_root());

    for id in &spent {
        assert!(
            plain.state.within_grace(id).is_none(),
            "a spent note is off the window"
        );
    }

    let from_plain = plain.handover();
    let from_keeper = keeper.handover();
    let on_the_window: usize = from_plain.grace.iter().map(Vec::len).sum();
    assert!(on_the_window > 0, "there is a window to hand over");
    assert_eq!(
        from_plain.grace_proofs.len(),
        on_the_window,
        "a path travels with every note on the window"
    );
    assert_eq!(
        from_plain.grace, from_keeper.grace,
        "the two kinds of node hand over the same window"
    );
    let mut mine: Vec<(u64, cairn_accumulator::ForestProof)> = from_plain.grace_proofs.clone();
    let mut theirs = from_keeper.grace_proofs.clone();
    mine.sort_by_key(|(at, _)| *at);
    theirs.sort_by_key(|(at, _)| *at);
    assert_eq!(mine, theirs, "and the same paths, hash for hash");

    for (offered, from) in [
        (&from_plain, "a plain node"),
        (&from_keeper, "an archivist"),
    ] {
        let mut fresh = accept(offered, &params)
            .unwrap_or_else(|why| panic!("the ledger from {from} was refused: {why}"));
        assert_eq!(fresh.state_root(), plain.buried().state_root());
        for block in plain.to_catch_up() {
            connect_block(&mut fresh, &block, &params, NOW).expect("it validates its way up");
        }
        assert_eq!(fresh.state_root(), plain.state.state_root());
        assert_eq!(fresh.grace_root(), plain.state.grace_root());
    }
}

/// A run that spends out of the window as often as the window refills, then
/// buries the result deep enough to be handed over.
fn drive_with_spends(node: &mut Node, miner: &SecretKey, payee: &SecretKey) -> Vec<NoteId> {
    node.mine_empty(miner, RECENT_HEADERS + 4);
    let mut spent = Vec::new();
    for round in 0..12usize {
        if round % 2 == 0 {
            spent.push(spend_one_from_grace(node, miner, payee));
        } else {
            node.mine_empty(miner, 1);
        }
    }
    node.mine_empty(miner, BURIAL as usize);
    spent
}

/// And the honest case, so the break above is not simply "handover is broken".
#[test]
fn a_ledger_with_an_untouched_window_hands_over_fine() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::plain();
    node.mine_empty(&miner, RECENT_HEADERS + 4 + BURIAL as usize);

    let handover = node.handover();
    let mut fresh = accept(&handover, &params).expect("nothing was spent, so it checks out");
    assert_eq!(fresh.state_root(), node.buried().state_root());
    for block in node.to_catch_up() {
        connect_block(&mut fresh, &block, &params, NOW).expect("it validates its way up");
    }
    assert_eq!(fresh.state_root(), node.state.state_root());
}

// ---------------------------------------------------------------------------
// The ceiling.
// ---------------------------------------------------------------------------

/// A miner that splits its reward across the sixteen notes a coinbase may
/// carry, which is the cheapest way to push notes out of the hot set.
fn split_coinbase(height: u64, owner: &SecretKey, params: &ConsensusParams) -> CoinbaseTransaction {
    let reward = params.reward_at(height).as_pebbles();
    let each = reward / params.max_coinbase_outputs as u64;
    let outputs = (0..params.max_coinbase_outputs)
        .map(|_| Note::new(Amount::from_pebbles(each).unwrap(), owner.public_key()))
        .collect();
    CoinbaseTransaction::new(height, outputs)
}

/// A chain driven so that notes fall every block, with the undo record of each
/// block kept the way `cairn_chain::ChainStore` keeps them.
struct Churn {
    state: LedgerState,
    kept: Vec<cairn_ledger::ConnectedBlock>,
    clock: u64,
}

impl Churn {
    fn new(state: LedgerState) -> Self {
        Self {
            state,
            kept: Vec::new(),
            clock: 1_000,
        }
    }

    fn run(&mut self, miner: &SecretKey, blocks: usize, params: &ConsensusParams) {
        for _ in 0..blocks {
            let height = self.state.next_height().unwrap();
            self.clock += 600;
            let coinbase = split_coinbase(height, miner, params);
            let block =
                assemble_block(&self.state, coinbase, Vec::new(), params, self.clock, 0).unwrap();
            let connected = connect_block(&mut self.state, &block, params, NOW).unwrap();
            self.kept.push(connected);
        }
    }
}

/// An undo record carries the paths the block changed, and not a copy of the
/// whole map.
///
/// It carried the whole map. `BlockUndo` keeps `cold_before`, whose comment
/// called it "sixty four hashes"; it was `ColdSet::snapshot`, which was
/// `Forest::clone`, and a `Forest` carries its watched map. That map holds a
/// full path for every note in the grace window, because a note that falls is
/// watched so it can be spent without a proof. A node keeps one record per
/// block for `cairn_chain::MAX_REORG_DEPTH` blocks, which is a thousand and
/// twenty four, so the map was held a thousand times over: three hundred and
/// twenty one megabytes at this test's scale and nine gigabytes at the shipped
/// window with a mature cold set, against a stated ceiling of sixty eight
/// megabytes. `examples/blocksize.rs` carefully accounts for the hundred and
/// thirty four megabytes of block bodies a node holds for the same window and
/// said nothing about this, because nothing measured it.
///
/// A block only ever lengthens the paths it does not rewrite, and how long a
/// path should be is decided by the leaf count, so undoing an addition is a
/// truncation and needs nothing written down. What is written down is the
/// paths beside a leaf the block emptied and the ones it stopped watching,
/// with their siblings held once each rather than once per path.
///
/// Run with `--nocapture` to see the figures.
#[test]
fn an_undo_record_carries_only_what_the_block_changed() {
    let params = params();
    let miner = wallet(1);
    let mut churn = Churn::new(LedgerState::new());
    churn.run(&miner, 200, &params);

    let window = churn.state.grace_len();
    assert_eq!(
        churn.state.watched_paths(),
        window,
        "every note in the window is watched, and nothing else is"
    );
    assert!(window > 0, "the run has to have pushed notes out");

    // What a copy of the map costs, which is what each record used to be.
    let map_bytes: usize = churn
        .state
        .grace_window()
        .iter()
        .flatten()
        .filter_map(|(_, position, _)| churn.state.cold().proof_of(*position))
        .map(|proof| proof.size_in_bytes())
        .sum();

    let from = churn.kept.len();
    churn.run(&miner, 64, &params);
    let records = &churn.kept[from..];
    let held: usize = records.iter().map(|one| one.undo.path_bytes()).sum();
    let paths: usize = records.iter().map(|one| one.undo.paths_held()).sum();
    let each = held / records.len();

    let depth = cairn_chain_reorg_depth();
    println!(
        "grace window {window} notes, a copy of its paths {map_bytes} B; \
         over {depth} records that was {:.1} MB",
        (map_bytes * depth) as f64 / 1e6
    );
    println!(
        "a record now holds {} paths and {each} B; over {depth} records, {:.1} MB",
        paths / records.len(),
        (each * depth) as f64 / 1e6
    );

    assert!(
        each * 8 < map_bytes,
        "a record is {each} B against a copy of the map at {map_bytes} B"
    );
    // A block lets go of what fell one block ago, so a record holds about one
    // block's landing and never the window.
    for one in records {
        assert!(
            one.undo.paths_held() * 4 < window,
            "a record holds {} paths against a window of {window}",
            one.undo.paths_held()
        );
    }
}

/// The reorganisation depth a node keeps undo records for. Restated rather
/// than depended on, so this crate's tests do not pull in `cairn-chain`.
const fn cairn_chain_reorg_depth() -> usize {
    1_024
}

/// A watched owner costs a bounded amount, however much is paid in, and dust
/// displaces nothing.
///
/// It cost whatever anyone cared to spend. The set of owners is bounded by
/// what an operator typed and the set of notes was not, and the two were read
/// as one bound: `commit` put in every fallen note of a watched owner,
/// `remember_grace` skipped the unwatch for those owners, and nothing took
/// either out except a spend. Measured on the run below, nine hundred and
/// fifty two paths after sixty blocks and four thousand seven hundred and
/// ninety two after three hundred, strictly climbing, four and a half times
/// the window it was supposed to be bounded by. A wallet node follows its own
/// address, and an address is a public key on a public chain, so a dust note
/// of a hundred and ninety one bytes bought the victim a permanent entry, a
/// permanent path, and a copy of that path in each of a thousand undo records.
///
/// There is a ceiling now, and what it lets go of first is the least valuable
/// note held, which is what makes the ceiling worth having: displacing a note
/// costs more than that note is worth, [`WATCHED_NOTES`] times over.
#[test]
fn a_watched_owner_costs_a_bounded_amount_however_much_is_paid_in() {
    // Enough notes a block that the ceiling is reached in a short test rather
    // than in half a day of them.
    let params = ConsensusParams {
        max_coinbase_outputs: 128,
        max_evictions_per_block: 512,
        max_block_bytes: 1024 * 1024,
        ..params()
    };
    let miner = wallet(1);

    let mut churn = Churn::new(LedgerState::new());
    churn.state.watch_owner(miner.public_key());
    churn.run(&miner, 60, &params);
    let early = churn.state.watched_notes().count();
    churn.run(&miner, 60, &params);
    let late = churn.state.watched_notes().count();

    println!(
        "watched notes: {early} after 60 blocks, {late} after 120; \
         paths held {} against a window of {}",
        churn.state.watched_paths(),
        churn.state.grace_len()
    );
    assert!(
        late <= cairn_ledger::state::WATCHED_NOTES,
        "{late} notes followed against a ceiling of {}",
        cairn_ledger::state::WATCHED_NOTES
    );
    assert_eq!(
        late,
        cairn_ledger::state::WATCHED_NOTES,
        "and the ceiling really did bite, or this proves nothing"
    );
    assert!(
        churn.state.watched_paths()
            <= cairn_ledger::state::WATCHED_NOTES + cairn_ledger::state::GRACE_NOTES,
        "the paths kept are the window plus what is followed, and no more"
    );

    // Dust paid to a followed address displaces nothing. The block below pays
    // that owner a hundred and twenty eight notes of one pebble, which all
    // fall, and not one of them ends up in the set: they arrive as the least
    // valuable thing in it and are the first thing the ceiling lets go of.
    let dust = Amount::from_pebbles(1).unwrap();
    let worth = |state: &LedgerState| {
        state
            .watched_notes()
            .fold(Amount::ZERO, |sum, (_, _, note)| {
                sum.checked_add(note.value).unwrap()
            })
    };
    let before = worth(&churn.state);
    let height = churn.state.next_height().unwrap();
    churn.clock += 600;
    let paying_dust = CoinbaseTransaction::new(
        height,
        (0..params.max_coinbase_outputs)
            .map(|_| Note::new(dust, miner.public_key()))
            .collect(),
    );
    let block = assemble_block(
        &churn.state,
        paying_dust,
        Vec::new(),
        &params,
        churn.clock,
        0,
    )
    .unwrap();
    churn
        .kept
        .push(connect_block(&mut churn.state, &block, &params, NOW).unwrap());

    assert!(
        churn
            .state
            .watched_notes()
            .all(|(_, _, note)| note.value > dust),
        "a dust note got into the set"
    );
    assert_eq!(
        churn.state.watched_notes().count(),
        cairn_ledger::state::WATCHED_NOTES,
        "and the set is still full of notes worth having"
    );
    assert!(
        worth(&churn.state) >= before,
        "a block of dust made the set worth less: {before:?} then {:?}",
        worth(&churn.state)
    );

    // Against the same run with nobody followed, which stays at the window.
    let mut plain = Churn::new(LedgerState::new());
    plain.run(&miner, 120, &params);
    assert_eq!(
        plain.state.watched_paths(),
        plain.state.grace_len(),
        "a node that follows nobody holds only the window"
    );
}

// ---------------------------------------------------------------------------
// The grace window.
// ---------------------------------------------------------------------------

/// Every note in the window has a proof, and that proof still works.
///
/// This is the invariant the window rests on: a spender presents nothing, so
/// the node must hold a path that folds to the cold commitment as it stands
/// right now. It is checked after every block of a run that both pushes notes
/// out and spends them back out of the cold set, which is what moves the
/// siblings of everything else in the same tree.
#[test]
fn every_note_in_the_window_has_a_proof_that_still_verifies() {
    let params = params();
    let miner = wallet(1);
    let payee = wallet(2);
    let mut node = Node::plain();
    node.mine_empty(&miner, 12);

    for round in 0..80 {
        // Every third block, spend something out of the window, which empties
        // a leaf and moves the siblings of everything beside it.
        let transfers = if round % 3 == 0 {
            match node
                .state
                .grace_window()
                .iter()
                .rev()
                .flatten()
                .copied()
                .find(|(_, _, note)| note.owner == miner.public_key())
            {
                None => Vec::new(),
                Some((id, _, note)) => {
                    let mut transfer = Transfer::new(
                        vec![Input::hot(id)],
                        vec![Note::new(note.value, payee.public_key())],
                    );
                    transfer.sign_input(params.network, 0, &note, &miner);
                    vec![transfer]
                }
            }
        } else {
            Vec::new()
        };
        node.mine(&miner, transfers);

        let mut proved = 0usize;
        let mut missing = Vec::new();
        for (id, position, note) in node.state.grace_window().iter().flatten() {
            match node.state.cold().proof_of(*position) {
                None => missing.push(*position),
                Some(proof) => {
                    assert!(
                        node.state.cold().verify(
                            *position,
                            cairn_ledger::cold_leaf(id, note),
                            &proof
                        ),
                        "round {round}: the proof held for position {position} is stale"
                    );
                    proved += 1;
                }
            }
        }
        // Nothing is missing. A note whose leaf a spend emptied leaves the
        // window with it, so the window never names a place the node cannot
        // prove. It used to, which is the same fault the handover tests above
        // describe, seen from this side.
        assert!(
            missing.is_empty(),
            "round {round}: the window names {} places with no path: {missing:?}",
            missing.len()
        );
        assert_eq!(proved, node.state.grace_len(), "round {round}");
    }
}

/// A note the window covers is never also in the hot set, and never listed
/// twice.
#[test]
fn the_window_and_the_hot_set_never_hold_the_same_note() {
    let params = params();
    let _ = &params;
    let miner = wallet(1);
    let mut node = Node::plain();
    node.mine_empty(&miner, 120);

    let window: Vec<NoteId> = node
        .state
        .grace_window()
        .iter()
        .flatten()
        .map(|(id, _, _)| *id)
        .collect();
    let mut sorted = window.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), window.len(), "a note sits in the window once");
    assert_eq!(window.len(), node.state.grace_len(), "and the index agrees");

    for id in &window {
        assert!(
            node.state.hot_note(id).is_none(),
            "a note that fell is still in the hot set"
        );
    }
    for (id, _) in node.state.hot_notes() {
        assert!(
            node.state.within_grace(&id).is_none(),
            "a hot note is also in the window"
        );
    }
}

/// The window cannot be widened. Both bounds bite, and the one that bites
/// first is whichever runs out first.
#[test]
fn the_window_holds_at_most_what_the_two_bounds_allow() {
    let params = params();
    let miner = wallet(1);
    let mut churn = Churn::new(LedgerState::new());
    churn.run(&miner, 300, &params);

    let window = churn.state.grace_window();
    assert!(
        window.len() <= cairn_ledger::state::GRACE_BLOCKS,
        "the window holds {} blocks",
        window.len()
    );
    let held: usize = window.iter().map(Vec::len).sum();
    assert!(
        held <= cairn_ledger::state::GRACE_NOTES,
        "{held} notes held"
    );
    assert_eq!(held, churn.state.grace_len());
    // Sixteen a block for sixty four blocks, which is the block bound biting
    // before the note bound.
    assert_eq!(window.len(), cairn_ledger::state::GRACE_BLOCKS);
    println!("window: {} blocks, {held} notes", window.len());
}

/// Undoing across the edge of the window puts back the blocks that aged out,
/// with their proofs.
#[test]
fn a_reorganisation_across_the_windows_edge_puts_it_back() {
    let params = params();
    let miner = wallet(1);
    let mut churn = Churn::new(LedgerState::new());
    churn.run(&miner, 100, &params);

    let before_root = churn.state.grace_root();
    let before_state = churn.state.state_root();
    let before_window = churn.state.grace_window();
    let before_watched = churn.state.watched_paths();

    // Deeper than the window, so blocks really did fall out of the far end
    // while these were applied.
    churn.run(&miner, cairn_ledger::state::GRACE_BLOCKS + 5, &params);
    assert_ne!(churn.state.grace_root(), before_root);

    for connected in churn.kept.split_off(100).iter().rev() {
        cairn_ledger::disconnect_block(&mut churn.state, connected);
    }

    assert_eq!(
        churn.state.grace_root(),
        before_root,
        "the window came back"
    );
    assert_eq!(churn.state.state_root(), before_state);
    assert_eq!(churn.state.grace_window(), before_window);
    assert_eq!(
        churn.state.watched_paths(),
        before_watched,
        "and so did the proofs it needs, which no root would have caught"
    );
    for (id, position, note) in churn.state.grace_window().iter().flatten() {
        let proof = churn
            .state
            .cold()
            .proof_of(*position)
            .expect("a note in the window keeps its proof across a reorganisation");
        assert!(churn
            .state
            .cold()
            .verify(*position, cairn_ledger::cold_leaf(id, note), &proof));
    }
}

// ---------------------------------------------------------------------------
// Eviction.
// ---------------------------------------------------------------------------

/// The order is total, and it is the same order twice.
///
/// Ties are broken by identifier, so two notes created in the same block still
/// have one answer between them. Anything less and two nodes holding the same
/// notes could evict different ones and disagree about the root.
#[test]
fn the_eviction_order_is_total_and_the_same_every_time() {
    let params = params();
    let miner = wallet(1);
    let mut churn = Churn::new(LedgerState::new());
    churn.run(&miner, 40, &params);

    let created: Vec<(NoteId, Note)> = Vec::new();
    let empty = std::collections::BTreeSet::new();
    for over in 1..=HOT {
        let filler: Vec<(NoteId, Note)> = (0..over)
            .map(|index| {
                (
                    NoteId::new(cairn_primitives::Hash32::from_bytes([index as u8; 32]), 0),
                    Note::new(params.initial_reward, miner.public_key()),
                )
            })
            .collect();
        let once = churn
            .state
            .plan_evictions(&empty, &filler, params.hot_capacity);
        let twice = churn
            .state
            .plan_evictions(&empty, &filler, params.hot_capacity);
        assert_eq!(once, twice, "the plan is a function of the state");
        assert_eq!(once.len(), over, "one falls for each one that arrives");

        // And it is the oldest, by height then identifier.
        let mut expected: Vec<(u64, NoteId)> = churn
            .state
            .hot_notes()
            .map(|(id, entry)| (entry.height, id))
            .collect();
        expected.sort();
        let chosen: Vec<NoteId> = once.iter().map(|(id, _)| *id).collect();
        let wanted: Vec<NoteId> = expected.iter().take(over).map(|(_, id)| *id).collect();
        assert_eq!(chosen, wanted, "the oldest fall, ties broken by identifier");
    }
    let _ = created;
}

/// Nothing an attacker puts in a block moves the order.
///
/// The key is `(height created, identifier)`, and both are settled the moment
/// a note exists. Spending notes only takes candidates off the list; it never
/// promotes one. So the only thing a block can do is decide how far down the
/// list the cut falls, and it pays for every step in notes it has to create.
#[test]
fn a_block_cannot_choose_which_note_falls_only_how_many() {
    let params = params();
    let miner = wallet(1);
    let mut churn = Churn::new(LedgerState::new());
    churn.run(&miner, 40, &params);

    let mut ordered: Vec<(u64, NoteId)> = churn
        .state
        .hot_notes()
        .map(|(id, entry)| (entry.height, id))
        .collect();
    ordered.sort();

    // Whatever is spent, whatever is created, the notes that fall are always a
    // prefix of that one order with the spent ones skipped.
    for round in 0..24usize {
        let spend_count = round % (ordered.len().min(4) + 1);
        let spent: std::collections::BTreeSet<NoteId> = ordered
            .iter()
            .rev()
            .take(spend_count)
            .map(|(_, id)| *id)
            .collect();
        let make = 1 + round % 6;
        let created: Vec<(NoteId, Note)> = (0..make)
            .map(|index| {
                (
                    NoteId::new(
                        cairn_primitives::Hash32::from_bytes([(round * 8 + index) as u8; 32]),
                        0,
                    ),
                    Note::new(params.initial_reward, miner.public_key()),
                )
            })
            .collect();

        let plan = churn
            .state
            .plan_evictions(&spent, &created, params.hot_capacity);
        let wanted: Vec<NoteId> = ordered
            .iter()
            .filter(|(_, id)| !spent.contains(id))
            .take(plan.len())
            .map(|(_, id)| *id)
            .collect();
        assert_eq!(
            plan.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            wanted,
            "round {round}: the plan is not the prefix of the one order"
        );
    }
}

/// A note created and pushed out by the very block that made it.
///
/// This is the corner the eviction step runs last for. It has to look the same
/// to a node that holds the cold set and to one that holds sixty four hashes,
/// or the two follow different chains.
#[test]
fn a_note_that_falls_the_moment_it_is_made_looks_the_same_to_both_kinds_of_node() {
    let params = ConsensusParams::testnet().with_hot_capacity(4);
    let miner = wallet(1);

    let mut plain = LedgerState::new();
    let mut keeper = LedgerState::archiving();
    let mut clock = 1_000u64;

    for _ in 0..40 {
        let height = plain.next_height().unwrap();
        clock += 600;
        // Sixteen notes into a drawer that holds four: twelve of them fall
        // without ever having been reachable.
        let coinbase = split_coinbase(height, &miner, &params);
        let block = assemble_block(&plain, coinbase, Vec::new(), &params, clock, 0).unwrap();
        connect_block(&mut plain, &block, &params, NOW).unwrap();
        connect_block(&mut keeper, &block, &params, NOW).unwrap();
        assert_eq!(plain.state_root(), keeper.state_root());
        assert_eq!(plain.grace_root(), keeper.grace_root());
        assert_eq!(plain.cold_len(), keeper.cold_len());
        assert!(plain.hot_len() <= params.hot_capacity);
    }
    assert!(plain.cold_len() > 0, "notes really did fall");
}

/// The cap on how many notes one block may push out cannot be got round by any
/// shape of block, because the projection is refused before it is applied.
#[test]
fn the_eviction_cap_holds_whatever_shape_the_block_takes() {
    // Sixteen coinbase notes a block against a cap of four: the assembler
    // itself refuses to build it.
    let params = ConsensusParams::testnet()
        .with_hot_capacity(8)
        .with_max_evictions(4);
    let miner = wallet(1);
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;

    let mut refused = 0usize;
    for _ in 0..12 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = split_coinbase(height, &miner, &params);
        match assemble_block(&state, coinbase, Vec::new(), &params, clock, 0) {
            Ok(block) => {
                connect_block(&mut state, &block, &params, NOW).unwrap();
            }
            Err(cairn_ledger::BlockError::TooManyEvictions { count, limit }) => {
                refused += 1;
                assert!(count > limit);
            }
            Err(other) => panic!("{other}"),
        }
        assert!(state.hot_len() <= params.hot_capacity);
    }
    assert!(refused > 0, "the cap really did bite");
}

// ---------------------------------------------------------------------------
// A latent split: a block that lands more notes than the window can hold.
// ---------------------------------------------------------------------------

/// A block landing more notes than the window can hold leaves nothing behind.
///
/// It left everything behind. `remember_grace` wrote the index before
/// `advance_grace` decided what the window kept, and never reconciled the two.
/// `advance_grace` drops blocks off the front until the window is inside both
/// bounds, so a block landing more than `GRACE_NOTES` notes ran the front out
/// and lost its own landing as well, and the window kept none of it. Every one
/// of those notes was already in `grace_index`, which only ever lost entries
/// for blocks popped off the front of the window, and that block was never on
/// the window at all. Nothing removed them, ever.
///
/// Two things followed. The index grew without limit, holding notes the
/// committed window said nothing about. And a node that had applied the block
/// let those notes be spent with no proof, while a node handed the same state
/// rebuilt the index from the window alone and refused the same block. Both
/// agreed on every root, so nothing told the two states apart: a consensus
/// split with nobody at fault and nothing to point at.
///
/// It was not reachable under the parameters this network ships, because
/// `max_evictions_per_block` is `hot_capacity >> 7`, which is 1024 against a
/// `GRACE_NOTES` of 8192, and the block size caps note creation near three
/// thousand. So the invariant "one block cannot land more than the window
/// holds" was load bearing, undocumented, and enforced by a ratio between two
/// constants that have nothing to do with each other. It is not load bearing
/// now: the index is written from the window the step produced, so the two
/// cannot come apart whatever a block lands.
#[test]
fn a_block_landing_more_than_the_window_holds_leaves_nothing_behind() {
    let landing = cairn_ledger::state::GRACE_NOTES + 100;
    let params = ConsensusParams {
        hot_capacity: 8,
        max_evictions_per_block: landing * 2,
        max_coinbase_outputs: landing,
        max_block_bytes: 8 * 1024 * 1024,
        // The spend below is of a reward, and the wait is not what is being
        // shown here.
        coinbase_maturity: 0,
        ..ConsensusParams::testnet()
    };
    // The same rules with an ordinary sized coinbase, for the blocks either
    // side of the one that matters.
    let mut small = params;
    small.max_coinbase_outputs = 16;
    let miner = wallet(1);

    let (mut state, mut clock, (orphan, note)) =
        one_block_bigger_than_the_window(&params, &small, &miner);

    let window = state.grace_window();
    let on_the_window: usize = window.iter().map(Vec::len).sum();
    println!(
        "window: {} blocks holding {on_the_window} notes; index: {} notes",
        window.len(),
        state.grace_len()
    );
    assert_eq!(on_the_window, 0, "the window kept nothing");
    assert_eq!(
        state.grace_len(),
        0,
        "and the index kept nothing either: it says what the window says"
    );
    assert_eq!(
        state.watched_paths(),
        0,
        "and no path is being kept current for a note nothing can spend"
    );

    // The header commits to a window holding nothing, and this node agrees
    // with that, which is the whole point: a node handed this state rebuilds
    // the index from the window and reaches the same place.
    assert_eq!(
        state.grace_root(),
        LedgerState::new().grace_root(),
        "the committed window is the empty one"
    );

    // So a proofless spend of one of those notes is refused, where before it
    // went through here and was refused by a node holding the same roots.
    assert!(state.within_grace(&orphan).is_none());
    let mut transfer = Transfer::new(
        vec![Input::hot(orphan)],
        vec![Note::new(note.value, wallet(2).public_key())],
    );
    transfer.sign_input(params.network, 0, &note, &miner);
    let spend_height = state.next_height().unwrap();
    let refused = assemble_block(
        &state,
        split_coinbase(spend_height, &miner, &small),
        vec![transfer],
        &small,
        clock + 600,
        0,
    );
    assert!(
        matches!(
            refused,
            Err(cairn_ledger::BlockError::InvalidTransfer {
                index: 0,
                source: cairn_ledger::TransferError::MissingProof { .. }
            })
        ),
        "a note the committed window does not hold was spent without a proof: {refused:?}"
    );

    // And the window and the index stay together as the chain goes on.
    for _ in 0..cairn_ledger::state::GRACE_BLOCKS + 4 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = split_coinbase(height, &miner, &small);
        let block = assemble_block(&state, coinbase, Vec::new(), &small, clock, 0).unwrap();
        connect_block(&mut state, &block, &small, NOW).unwrap();
        let held: usize = state.grace_window().iter().map(Vec::len).sum();
        assert_eq!(held, state.grace_len(), "at height {height}");
    }
    let after: usize = state.grace_window().iter().map(Vec::len).sum();
    println!(
        "after another {} blocks: window {after} notes, index {} notes",
        cairn_ledger::state::GRACE_BLOCKS + 4,
        state.grace_len()
    );
}

/// An ordinary block, then one landing more notes than the window can ever
/// hold. Answers with the clock it left off at and with one of the notes that
/// block landed and lost, which is what the spend below reaches for.
fn one_block_bigger_than_the_window(
    params: &ConsensusParams,
    small: &ConsensusParams,
    miner: &SecretKey,
) -> (LedgerState, u64, (NoteId, Note)) {
    let landing = params.max_coinbase_outputs;
    let mut state = LedgerState::new();
    let mut clock = 1_600u64;

    // One ordinary block first, so the window has something on it to lose.
    let coinbase = split_coinbase(0, miner, small);
    let block = assemble_block(&state, coinbase, Vec::new(), small, clock, 0).unwrap();
    connect_block(&mut state, &block, small, NOW).unwrap();
    assert!(state.grace_len() > 0);

    let height = state.next_height().unwrap();
    clock += 600;
    let each = params.reward_at(height).as_pebbles() / landing as u64;
    let coinbase = CoinbaseTransaction::new(
        height,
        (0..landing)
            .map(|_| Note::new(Amount::from_pebbles(each).unwrap(), miner.public_key()))
            .collect(),
    );
    let block = assemble_block(&state, coinbase, Vec::new(), params, clock, 0).unwrap();
    connect_block(&mut state, &block, params, NOW).unwrap();

    // The coinbase paid them all to the same owner for the same amount, so any
    // of them that is no longer in the hot set will do.
    let orphan = (0..landing)
        .map(|index| NoteId::new(block.coinbase.id(), index as u32))
        .find(|id| state.hot_note(id).is_none())
        .expect("one of the notes really did fall");
    let note = Note::new(Amount::from_pebbles(each).unwrap(), miner.public_key());
    (state, clock, (orphan, note))
}

// ---------------------------------------------------------------------------
// Reconstruction.
// ---------------------------------------------------------------------------

/// Everything two nodes have to agree on, including the parts no root covers.
///
/// `cairn-ledger/tests/invariants.rs` already compares the roots, the window
/// and the watched notes across an undo. What it does not compare is the
/// watched proofs themselves, which are the paths a node needs to let a fallen
/// note be spent without one. They sit in no commitment at all, so a node that
/// lost them would agree with everybody about every block and quietly stop
/// being able to accept a spend the rest of the network accepts.
fn deep_fingerprint(state: &LedgerState) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(state.state_root().as_bytes());
    out.extend_from_slice(state.grace_root().as_bytes());
    out.extend_from_slice(state.history_root().as_bytes());
    out.extend_from_slice(state.cold().commitment().as_bytes());
    out.extend_from_slice(&state.cold_len().to_le_bytes());
    out.extend_from_slice(&state.next_cold_position().to_le_bytes());
    out.extend_from_slice(&(state.hot_len() as u64).to_le_bytes());
    out.extend_from_slice(&(state.grace_len() as u64).to_le_bytes());
    out.extend_from_slice(&(state.watched_paths() as u64).to_le_bytes());
    for position in 0..state.next_cold_position() {
        match state.cold().proof_of(position) {
            None => out.push(0),
            Some(proof) => {
                out.push(1);
                out.extend_from_slice(&position.to_le_bytes());
                for sibling in &proof.siblings {
                    out.extend_from_slice(sibling.as_bytes());
                }
            }
        }
    }
    out
}

/// A state reached by walking a branch and coming back is the state of a node
/// that never left, down to the proofs it holds.
#[test]
fn undoing_a_branch_restores_even_what_no_root_commits_to() {
    let params = params();
    let shared_miner = wallet(1);
    let losing_miner = wallet(3);
    let winning_miner = wallet(4);
    let payee = wallet(2);

    // Plain nodes, because they are the ones that keep a watched map: an
    // archivist keeps none and rebuilds every proof from its leaves, so the
    // part of the state no root covers exists only on an ordinary node.
    let mut walker = Churn::new(LedgerState::new());
    walker.run(&shared_miner, 90, &params);
    let mut control = Churn::new(walker.state.clone());
    control.clock = walker.clock;

    let at_the_fork = deep_fingerprint(&walker.state);

    // The losing branch: a grace spend, a cold spend, and plain blocks.
    let losing = build_branch(&mut walker, &losing_miner, &payee, &params);
    assert!(losing > 0, "the losing branch really was built");
    assert_ne!(deep_fingerprint(&walker.state), at_the_fork);

    // Undone, newest first, which is what a reorganisation does.
    for connected in walker.kept.split_off(90).iter().rev() {
        cairn_ledger::disconnect_block(&mut walker.state, connected);
    }
    assert_eq!(
        deep_fingerprint(&walker.state),
        at_the_fork,
        "coming back is not the same as never having gone"
    );

    // Now both take the winning branch, one having walked the other one first.
    walker.clock = control.clock;
    let a = build_branch(&mut walker, &winning_miner, &payee, &params);
    let b = build_branch(&mut control, &winning_miner, &payee, &params);
    assert_eq!(a, b, "both built the same branch");
    assert_eq!(
        deep_fingerprint(&walker.state),
        deep_fingerprint(&control.state),
        "a node that reorganised and one that never did are not the same node"
    );

    // The part of that comparison no root reaches: the paths themselves, and
    // that they still work. A path that came back wrong would leave the two
    // nodes agreeing on every root and disagreeing about whether a note in the
    // window can be spent.
    let mut checked = 0usize;
    for (id, position, note) in walker.state.grace_window().iter().flatten() {
        let kept = walker
            .state
            .cold()
            .proof_of(*position)
            .expect("a note on the window came back with no path at all");
        assert!(
            walker
                .state
                .cold()
                .verify(*position, cairn_ledger::cold_leaf(id, note), &kept),
            "position {position} came back with a path that no longer folds"
        );
        checked += 1;
    }
    assert!(
        checked > 100,
        "only {checked} paths were compared, so the comparison proves little"
    );

    // And an archivist fed the same branch lands on the same roots, which is
    // the other half: the two kinds of node are meant to be the same node. It
    // keeps no paths at all, which is why the comparison above needs a plain
    // one.
    let mut keeper = Churn::new(LedgerState::archiving());
    keeper.run(&shared_miner, 90, &params);
    build_branch(&mut keeper, &winning_miner, &payee, &params);
    assert_eq!(keeper.state.state_root(), walker.state.state_root());
    assert_eq!(keeper.state.grace_root(), walker.state.grace_root());
    assert_eq!(
        keeper.state.cold().commitment(),
        walker.state.cold().commitment()
    );
    assert_eq!(keeper.state.watched_paths(), 0);
}

/// A short branch that pushes notes out every block and spends one back out of
/// the cold set without a proof, which is the step that empties a leaf and
/// moves the siblings of every watched place beside it.
fn build_branch(
    churn: &mut Churn,
    miner: &SecretKey,
    payee: &SecretKey,
    params: &ConsensusParams,
) -> usize {
    let mut spends = 0usize;
    for round in 0..16usize {
        let mut transfers = Vec::new();
        if round == 2 {
            // A note the window still covers: no proof from the spender.
            if let Some((id, _, note)) = churn
                .state
                .grace_window()
                .iter()
                .rev()
                .flatten()
                .copied()
                .find(|(_, _, note)| note.owner == wallet(1).public_key())
            {
                let mut transfer = Transfer::new(
                    vec![Input::hot(id)],
                    vec![Note::new(note.value, payee.public_key())],
                );
                transfer.sign_input(params.network, 0, &note, &wallet(1));
                transfers.push(transfer);
                spends += 1;
            }
        }
        let height = churn.state.next_height().unwrap();
        churn.clock += 600;
        let coinbase = split_coinbase(height, miner, params);
        let block =
            assemble_block(&churn.state, coinbase, transfers, params, churn.clock, 0).unwrap();
        let connected = connect_block(&mut churn.state, &block, params, NOW).unwrap();
        churn.kept.push(connected);
    }
    spends
}

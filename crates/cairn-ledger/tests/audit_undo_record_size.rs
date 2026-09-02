//! What one block's undo record actually holds, on a real chain.
//!
//! Read only. Nothing here changes a source file.
//!
//! Every figure printed here is read off `connect_block`'s own return value.
//! That is the point of the file. The figure this replaces was taken from a
//! forest built by hand, watching only the places one block lets go of, and
//! never emptying a leaf: it measured one of the two ways a path gets written
//! down, and the one it missed was the larger by an order of magnitude and
//! decided by the cold set's shape rather than by anything the block did.
//!
//! Four shapes are measured, and the last is the worst one. Over the thousand
//! and twenty four records a node keeps, on this machine, before the repair
//! and after it:
//!
//! | shape                                     | before   | after   |
//! |-------------------------------------------|----------|---------|
//! | ordinary chain, worst single record       | 933.7 MB | 39.6 MB |
//! | ordinary chain, mean                      | 382.0 MB |  3.3 MB |
//! | one spend, window of 8192 in one tree     | 933.7 MB |   8 B   |
//! | a followed owner at the watched ceiling   | 1549.6 MB | 33.7 MB |
//!
//! The two figures the release published were 686 paths and 77.9 kB for a
//! record, and 79.8 MB over the records a node keeps. Neither was wrong about
//! the case it measured; both were wrong about which cases there are.
//!
//! What is left is not nothing, and it is worth saying what it is. A record
//! now holds exactly the paths a node let go of because the grace window aged
//! past them or a followed owner's ceiling displaced them. Nothing in the
//! block says what those were, so nothing can work them out. A window ageing
//! off takes consecutive places and their siblings are shared, which is what
//! makes the first figure kilobytes; a ceiling displacing followed notes takes
//! scattered ones, which share almost nothing, and that is the term to watch.
//!
//! Run with `--nocapture` to see the figures.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::{cold_leaf, ConnectedBlock, LedgerState};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
/// Undo records a node keeps, which is `cairn_chain::MAX_REORG_DEPTH`.
const RECORDS: usize = 1_024;
/// The ledger's `GRACE_NOTES`, restated so a failure reads on its own.
const GRACE_NOTES: usize = 8_192;
/// The ledger's `WATCHED_NOTES`.
const WATCHED_NOTES: usize = 8_192;
/// Depth of a path in a mature cold set of about a billion notes.
///
/// A chain a test can drive is far shallower than that, and every per path
/// figure below is linear in the depth: a record holds hashes named by the
/// place they cover, and a path has one per level. So each measurement is
/// printed as it stands and again as it would stand on a mature set.
const MATURE_DEPTH: f64 = 30.0;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A reward is spendable at once here, and the hot set is small enough that
/// notes start falling within a few blocks.
///
/// Nothing else is moved. The eviction cap and the block size stay where the
/// rules put them, so a block here cannot do more than a block on the network.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(16)
        .with_coinbase_maturity(0)
}

/// A chain driven a block at a time, with the number of notes each block
/// pushes out of the hot set chosen by the caller.
///
/// The node measured is a plain one, which is what almost every node is: it
/// holds the cold roots and the paths for what it must be able to prove, and
/// nothing else.
struct Chain {
    state: LedgerState,
    params: ConsensusParams,
    miner: SecretKey,
    /// The other owner a block pays, so a followed owner's notes are spread
    /// through the set rather than consecutive.
    other: SecretKey,
    /// Notes worth splitting, which is how a block lands many at once.
    purse: Vec<(NoteId, Note)>,
    clock: u64,
    /// Fraction of a block's landing paid to `miner`, out of four.
    share: u64,
}

impl Chain {
    fn new(watch: Option<PublicKey>, share: u64) -> Self {
        let mut state = LedgerState::new();
        if let Some(owner) = watch {
            state.watch_owner(owner);
        }
        Self {
            state,
            params: params(),
            miner: wallet(1),
            other: wallet(2),
            purse: Vec::new(),
            clock: 1_000,
            share,
        }
    }

    /// Whether the node can still hand out a path for a note in the window.
    ///
    /// Asked rather than assumed, because a note whose leaf has already gone
    /// would be refused and take the whole block with it.
    fn provable(&self, position: u64, id: &NoteId, note: &Note) -> bool {
        self.state.cold().proof_of(position).is_some_and(|proof| {
            self.state
                .cold()
                .verify(position, cold_leaf(id, note), &proof)
        })
    }

    /// The most recent note in the purse that can still be spent.
    fn spendable(&mut self) -> Option<(NoteId, Note)> {
        while let Some((id, note)) = self.purse.pop() {
            if self.state.hot_note(&id).is_some() {
                return Some((id, note));
            }
            if let Some((position, held)) = self.state.within_grace(&id) {
                if self.provable(position, &id, &held) {
                    return Some((id, note));
                }
            }
        }
        None
    }

    /// One block that lands about `landing` notes and spends `spends` notes
    /// out of the grace window.
    ///
    /// A note in the window is spent the way a wallet spends one: named as a
    /// hot input with no proof, because every node still holds the path. That
    /// is the ordinary case this whole record exists for, and it is a removal
    /// from the cold set.
    fn block(&mut self, landing: usize, spends: usize) -> ConnectedBlock {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let mut transfers = Vec::new();

        // One coinbase note, and a split of an older one to make up the rest.
        // The split is what pushes notes out of the hot set, which is what a
        // block of ordinary payments does. Chosen first, so the spend below
        // cannot pick the same note out of the window.
        let parts = landing.saturating_sub(1);
        let split = if parts > 0 { self.spendable() } else { None };
        if let Some((id, note)) = split {
            let each = note.value.as_pebbles() / parts as u64;
            if each > 0 {
                let outputs: Vec<Note> = (0..parts)
                    .map(|index| {
                        let owner = if (index as u64 % 4) < self.share {
                            self.miner.public_key()
                        } else {
                            self.other.public_key()
                        };
                        Note::new(Amount::from_pebbles(each).unwrap(), owner)
                    })
                    .collect();
                let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
                transfer.sign_input(self.params.network, 0, &note, &self.miner);
                transfers.push(transfer);
            }
        }

        let mut spent = 0usize;
        for (id, position, note) in self.state.grace_window().into_iter().flatten() {
            if spent >= spends {
                break;
            }
            if split.map(|(held, _)| held) == Some(id) || !self.provable(position, &id, &note) {
                continue;
            }
            let owner = if note.owner == self.miner.public_key() {
                &self.miner
            } else {
                &self.other
            };
            let mut transfer = Transfer::new(
                vec![Input::hot(id)],
                vec![Note::new(note.value, owner.public_key())],
            );
            transfer.sign_input(self.params.network, 0, &note, owner);
            transfers.push(transfer);
            spent += 1;
        }

        let reward = self.params.reward_at(height);
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(reward, self.miner.public_key())]);
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let connected = connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        self.purse.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(reward, self.miner.public_key()),
        ));
        connected
    }

    /// Drives the chain until the cold set has handed out exactly `target`
    /// places, so the forest is one perfect tree when the next block empties a
    /// leaf in it.
    ///
    /// A power of two is not a corner case. A cold set passes through one
    /// every time it doubles, and a record whose size is decided by how much
    /// of the watched map sits in one tree is at its largest there.
    fn fill_to(&mut self, target: u64, spends: usize) {
        while self.state.next_cold_position() < target {
            let want = target - self.state.next_cold_position();
            // A block lands its coinbase, the split it made, and whatever the
            // spends paid on, and the split's own note may or may not still
            // have been hot. So the last few places are taken one at a time,
            // by a block that only pays itself.
            if want > 4 {
                self.block((want - 3).min(200) as usize, spends);
            } else {
                self.block(1, 0);
            }
        }
        assert_eq!(
            self.state.next_cold_position(),
            target,
            "the chain overshot the leaf count this measurement is taken at"
        );
    }
}

/// Says what a record costs, as it stands and as it would on a mature set.
fn report(what: &str, held: &ConnectedBlock, depth: f64) {
    let bytes = held.undo.path_bytes();
    println!(
        "{what}: {} paths, {bytes} B; over {RECORDS} records {:.1} MB, \
         and {:.1} MB at a mature depth of {MATURE_DEPTH:.0}",
        held.undo.paths_held(),
        (bytes * RECORDS) as f64 / 1e6,
        (bytes * RECORDS) as f64 / 1e6 * (MATURE_DEPTH / depth),
    );
}

/// Shapes one and two: an ordinary chain, worst record and mean.
///
/// Every block pushes a few hundred notes out of the hot set and spends one
/// out of the grace window, which is what a payment written while a block
/// landed becomes. Nothing here is adversarial and nothing is rare.
#[test]
fn what_an_ordinary_block_writes_down() {
    let mut chain = Chain::new(None, 4);
    let mut worst = 0usize;
    let mut worst_paths = 0usize;
    let mut worst_at = 0u64;
    let mut total = 0usize;
    let mut blocks = 0usize;

    for round in 0..48u64 {
        let connected = chain.block(200, 1);
        let bytes = connected.undo.path_bytes();
        total += bytes;
        blocks += 1;
        if bytes > worst {
            worst = bytes;
            worst_paths = connected.undo.paths_held();
            worst_at = round;
        }
    }

    let window = chain.state.grace_len();
    let watching = chain.state.watched_paths();
    println!(
        "48 blocks, cold set {} leaves, window {window} notes, {watching} paths watched",
        chain.state.next_cold_position()
    );
    println!(
        "worst single record: {worst_paths} paths, {worst} B at block {worst_at}; \
         over {RECORDS} records {:.1} MB",
        (worst * RECORDS) as f64 / 1e6
    );
    println!(
        "mean over this run, over {RECORDS} records: {:.1} MB",
        (total / blocks * RECORDS) as f64 / 1e6
    );

    // The finding this file was opened for. A record used to hold a path for
    // every watched place in the emptied leaf's tree, which for a leaf count
    // that is a power of two is every path the node holds: 8127 paths and 911
    // kB for one ordinary block, against a stated 686 paths and 77.9 kB.
    //
    // What bounds it now is what the block let go of, and a block lets go of
    // one block's worth of notes ageing off the window.
    assert!(
        worst_paths * 2 < window,
        "one record held {worst_paths} paths against a window of {window}, which means \
         its size is decided by how much of the watched map sits in one tree rather \
         than by what the block did"
    );
}

/// Shape three: one spend with the window at its ceiling, all in one tree.
///
/// The cold set is driven to a leaf count that is a power of two, so it is a
/// single perfect tree and every watched path is one the removal brings up to
/// date. This is the shape that turned a stated 79.8 MB into 940 MB.
#[test]
fn a_spend_with_the_whole_window_in_one_tree() {
    const LEAVES: u64 = 8_192;
    let mut chain = Chain::new(None, 4);
    chain.fill_to(LEAVES, 1);

    let window = chain.state.grace_len();
    let watching = chain.state.watched_paths();
    assert_eq!(window, watching, "every note in the window is watched");
    assert!(
        window >= GRACE_NOTES / 2,
        "the window is only {window} notes, so this is not the shape it claims to be"
    );

    let connected = chain.block(2, 1);
    println!("cold set {LEAVES} leaves in one tree, window {window} notes, all watched, one spend",);
    report("one spend in one tree", &connected, 13.0);

    assert!(
        connected.undo.paths_held() * 4 < window,
        "the record holds {} paths against a window of {window} sitting in one tree",
        connected.undo.paths_held()
    );
}

/// Shape four, and the worst of them: a node following an owner, at the
/// ceiling.
///
/// A followed owner's notes fell whenever that owner was paid, so they are
/// spread across the cold set rather than consecutive, and two places far
/// apart share almost no siblings. A record that held a path for each of them
/// therefore held a nearly full path apiece: at the `WATCHED_NOTES` ceiling
/// and a mature depth that was seven and a half megabytes for one block, and
/// seven and a half gigabytes over the records a node keeps, which is where
/// the change that this repairs had started.
#[test]
fn a_node_following_an_owner_at_the_watched_ceiling() {
    const LEAVES: u64 = 16_384;
    let followed = wallet(1).public_key();
    // Half of each block's landing is paid to the followed owner, and a
    // block's notes fall in identifier order, so its places are shot through
    // the run rather than sitting at one end of it.
    let mut chain = Chain::new(Some(followed), 2);
    chain.fill_to(LEAVES, 1);

    let watching = chain.state.watched_paths();
    let following = chain.state.watched_notes().count();
    println!(
        "cold set {LEAVES} leaves in one tree, {following} notes followed for one owner, \
         {watching} paths watched, window {} notes",
        chain.state.grace_len()
    );
    assert!(
        following > WATCHED_NOTES / 4,
        "only {following} notes are followed, so this is not the ceiling shape"
    );

    // A run past the point where the ceiling starts displacing followed notes,
    // which is the one thing that makes a node let go of a scattered path.
    let mut worst = 0usize;
    let mut worst_paths = 0usize;
    let mut connected = chain.block(2, 1);
    for _ in 0..8 {
        let one = chain.block(200, 1);
        if one.undo.path_bytes() > worst {
            worst = one.undo.path_bytes();
            worst_paths = one.undo.paths_held();
            connected = one;
        }
    }

    report(
        "one spend beside a followed owner's notes",
        &connected,
        14.0,
    );
    println!("worst of the run: {worst_paths} paths, {worst} B");
    assert!(
        worst_paths * 4 < watching,
        "the record holds {worst_paths} paths against {watching} watched, which means \
         a removal is still writing down what it brought up to date"
    );
}

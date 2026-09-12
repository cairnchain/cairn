//! What the one check in a handover that does not end at the header weighs.
//!
//! `handover::accept` weighs `handover.supply` against what the schedule can
//! have paid by the anchor's height, and the module said of it: "A ledger that
//! holds more was not produced by these rules, whatever work stands behind the
//! header that commits to it." True of the number. The ledger rebuilt out of
//! the same message was never weighed against it, and the two are separate
//! fields of one state root that a sender who mined the burial chooses
//! together, so a hot set worth five hundred million CAIRN travelled under a
//! declared total of four thousand five hundred and fifty and was spent on the
//! next block.
//!
//! Part of it is closed here and part of it cannot be. The hot set is on the
//! wire, so what it holds is added up and held against the declared total, and
//! so is the grace window, which travels note by note for the same reason and
//! which this file's first repair left out: see
//! `audit_the_window_is_on_the_wire_too.rs`. The cold set is sixty four
//! hashes, and adding those up would mean holding the set, which is the one
//! thing this design exists so a node does not have to do. The third test
//! below takes the same money through that tier and passes: it is here to
//! record what stands, not to be fixed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::too_many_lines
)]

use cairn_accumulator::{Archive, Forest, SparseMerkleTree};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{BlockHeader, HeaderSummary};
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::{median_time_past, meets_target, next_difficulty, work_of, RECENT_HEADERS};
use cairn_ledger::state::{header_leaf, HotEntry};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::{cold_leaf, note_key, LedgerState};
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain, Hasher};
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
const BURIAL: u64 = 8;
const MATURITY: u64 = 4;
const SPACING: u64 = 600;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn rules() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(BURIAL)
        .with_coinbase_maturity(MATURITY)
}

// ---------------------------------------------------------------------------
// The state root, rebuilt from the published fields rather than asked of the
// implementation, so a forged ledger can be given the root it deserves.
// ---------------------------------------------------------------------------

fn hot_value(note: &Note, height: u64) -> Hash32 {
    let mut hasher = Hasher::new(Domain::HotNoteValue);
    hasher.update(&note.encode());
    hasher.update(&height.encode());
    hasher.finalize()
}

fn hot_root(hot: &[(NoteId, HotEntry)]) -> (Hash32, u64) {
    let mut tree = SparseMerkleTree::new();
    for (id, entry) in hot {
        tree.insert(note_key(id), hot_value(&entry.note, entry.height));
    }
    (tree.root(), tree.len() as u64)
}

fn grace_root(window: &[Vec<(NoteId, u64, Note)>]) -> Hash32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(window.len() as u64).to_le_bytes());
    for landing in window {
        bytes.extend_from_slice(&(landing.len() as u64).to_le_bytes());
        for (id, position, note) in landing {
            bytes.extend_from_slice(&id.encode());
            bytes.extend_from_slice(&position.to_le_bytes());
            bytes.extend_from_slice(&note.encode());
        }
    }
    hash(Domain::GraceWindow, &bytes)
}

/// The eight fields a state root folds, in order.
fn state_root_of(handover: &Handover) -> Hash32 {
    let (hot, hot_len) = hot_root(&handover.hot);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(hot.as_bytes());
    bytes.extend_from_slice(&hot_len.to_le_bytes());
    bytes.extend_from_slice(handover.cold.commitment().as_bytes());
    bytes.extend_from_slice(&handover.cold.len().to_le_bytes());
    bytes.extend_from_slice(grace_root(&handover.grace).as_bytes());
    bytes.extend_from_slice(&(handover.maturing.len() as u64).to_le_bytes());
    for (matures_at, coinbase) in &handover.maturing {
        bytes.extend_from_slice(&matures_at.to_le_bytes());
        bytes.extend_from_slice(coinbase.as_bytes());
    }
    bytes.extend_from_slice(&handover.supply.encode());
    hash(Domain::StateCommitment, &bytes)
}

fn what_the_hot_set_is_worth(handover: &Handover) -> Amount {
    Amount::checked_sum(handover.hot.iter().map(|(_, entry)| entry.note.value))
        .expect("the hot set sums")
}

// ---------------------------------------------------------------------------
// A node that has been running, kept the way the other handover audits keep
// one.
// ---------------------------------------------------------------------------

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

    fn mine(&mut self, miner: &SecretKey) {
        let height = self.state.next_height().unwrap();
        self.clock += SPACING;
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
        self.history.add(header_leaf(&block.header.id())).unwrap();
        self.headers.push(block.header);
    }

    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let anchor = self.history.prove_in(anchor_height, tip.height).unwrap();
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
            .unwrap()
    }
}

fn summary(header: &BlockHeader) -> HeaderSummary {
    HeaderSummary {
        height: header.height,
        timestamp: header.timestamp,
        difficulty: header.difficulty,
    }
}

/// Rebuilds the run from the anchor to the tip over a doctored anchor.
///
/// Every header the run carries is checked by `check_buried`: consecutive,
/// carrying the difficulty the retarget demands, later than the median of the
/// window before it, and adding its own work to the total. None of that costs
/// anything on a chain at the difficulty floor, which is where this fixture's
/// rules put it, and that is the point: nothing above the anchor has to be
/// re-mined for the anchor to be rewritten.
fn rerun_above(handover: &mut Handover, below: &[BlockHeader], params: &ConsensusParams) {
    let at = handover.at;
    let tip_height = handover.tip.height;

    let mut archive = Archive::new();
    for header in below {
        archive.add(header_leaf(&header.id())).unwrap();
    }
    archive.add(header_leaf(&at.id())).unwrap();

    let mut window: Vec<HeaderSummary> = handover.recent.iter().map(summary).collect();
    if let Some(last) = window.last_mut() {
        *last = summary(&at);
    }
    let mut previous = at;
    let mut buried = Vec::new();
    let mut clock = at.timestamp;

    for height in (at.height + 1)..=tip_height {
        clock += SPACING;
        let difficulty = next_difficulty(&window, params.target_block_time);
        let mut header = BlockHeader {
            version: 1,
            network: params.network,
            height,
            previous: previous.id(),
            // Neither is read by anything on this path: what a buried header
            // commits to is never checked, only that it was mined and that it
            // links.
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: archive.forest().commitment(),
            timestamp: clock,
            difficulty,
            total_work: previous.total_work + work_of(difficulty),
            nonce: 0,
        };
        assert!(
            median_time_past(&window).is_none_or(|median| header.timestamp > median),
            "the forged run is not later than its own median"
        );
        while !meets_target(&header.id(), difficulty) {
            header.nonce += 1;
        }
        if height < tip_height {
            archive.add(header_leaf(&header.id())).unwrap();
        }
        window.push(summary(&header));
        if window.len() > RECENT_HEADERS {
            window.remove(0);
        }
        previous = header;
        buried.push(header);
    }

    let tip_history: Forest = archive.forest().roots_only();
    handover.anchor = archive.prove_in(at.height, tip_height).unwrap();
    handover.tip_history = tip_history;
    handover.tip = previous;
    handover.buried = buried;
    if let Some(last) = handover.recent.last_mut() {
        *last = at;
    }
}

// ---------------------------------------------------------------------------

/// The recomputation above is the one the implementation does.
///
/// Asserted first, so that the forgery below cannot pass for a defect when it
/// is really a test that cannot compute a state root.
#[test]
fn the_root_rebuilt_here_is_the_root_the_anchor_carries() {
    let params = rules();
    let mut node = Node::new(params);
    for _ in 0..(RECENT_HEADERS as u64 + BURIAL) {
        node.mine(&wallet(1));
    }
    let handover = node.handover();
    assert_eq!(
        state_root_of(&handover),
        handover.at.state_root,
        "the eight fields folded here are not the eight the ledger folds"
    );
    accept(&handover, &params).expect("an honest handover is taken");
}

/// A handover declaring a lawful total while carrying a hot set worth five
/// hundred million CAIRN.
///
/// The schedule has paid 4 550 CAIRN by the anchor's height, and the total this
/// message declares is exactly that, so `SupplyAboveTheSchedule` has nothing to
/// say. The notes it handed over were worth 500 004 550 CAIRN, every one of
/// them spendable by whoever holds the key, and the receiver's own `supply()`
/// afterwards read 4 550.
///
/// The check that was supposed to stop it read the number a sender wrote beside
/// the ledger rather than the ledger. Both are in the state root, so a sender
/// who mined the burial chooses both, and nothing compared them.
///
/// The hot set is on the wire, so it can be added up. It is, together with
/// the grace window, which is on the wire too and was not counted until
/// `audit_the_window_is_on_the_wire_too.rs` said so. This is refused now.
#[test]
fn a_handed_ledger_holding_more_than_it_declares_is_refused() {
    let params = rules();
    let mut node = Node::new(params);
    for _ in 0..(RECENT_HEADERS as u64 + BURIAL) {
        node.mine(&wallet(1));
    }

    let mut handover = node.handover();
    let at_height = handover.at.height;
    let lawful = handover.supply;
    let honest_worth = what_the_hot_set_is_worth(&handover);
    assert_eq!(
        lawful,
        params.emitted_by(at_height),
        "the honest chain sits exactly on the ceiling"
    );

    // One note out of nothing, in the tier every node holds in full.
    let forged = Amount::from_pebbles(50_000_000_000_000_000).unwrap();
    handover.hot.push((
        NoteId::new(Hash32::from_bytes([0xEE; 32]), 0),
        HotEntry {
            note: Note::new(forged, wallet(9).public_key()),
            height: 0,
        },
    ));

    let mut at = handover.at;
    at.state_root = state_root_of(&handover);
    handover.at = at;
    let below: Vec<BlockHeader> = node.headers[..at_height as usize].to_vec();
    rerun_above(&mut handover, &below, &params);

    let ceiling = params.emitted_by(at_height);
    let held = what_the_hot_set_is_worth(&handover);
    println!(
        "\n  anchor at height {at_height}\n  \
         the schedule has paid at most      {ceiling}\n  \
         the handover declares              {}\n  \
         the notes it hands over are worth  {held}\n  \
         honest chain's notes were worth    {honest_worth}\n",
        handover.supply
    );

    let taken = accept(&handover, &params);
    if let Ok(state) = &taken {
        // And it is money, not a number: the note spends on the very next
        // block, out of a ledger whose own total says it does not exist.
        let mut fresh = state.clone();
        let height = fresh.next_height().unwrap();
        let id = NoteId::new(Hash32::from_bytes([0xEE; 32]), 0);
        let note = Note::new(forged, wallet(9).public_key());
        let mut transfer = Transfer::new(
            vec![Input::hot(id)],
            vec![Note::new(forged, wallet(3).public_key())],
        );
        transfer.sign_input(params.network, 0, &note, &wallet(9));
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), wallet(1).public_key())],
        );
        let block = assemble_block(
            &fresh,
            coinbase,
            vec![transfer],
            &params,
            at.timestamp + SPACING,
            0,
        )
        .expect("the forged note builds a block");
        connect_block(&mut fresh, &block, &params, NOW).expect("and the block is taken");
        println!(
            "  spent on the next block: {forged} paid to a stranger, and the ledger \
             still says it has issued {}\n",
            fresh.supply()
        );

        let rebuilt = Amount::checked_sum(state.hot_notes().map(|(_, entry)| entry.note.value))
            .expect("the rebuilt hot set sums");
        assert!(
            rebuilt <= state.supply(),
            "a ledger holding {rebuilt} was taken against a declared total of {}, \
             which is {} the schedule never paid",
            state.supply(),
            rebuilt.checked_sub(state.supply()).unwrap()
        );
    }
    assert!(
        taken.is_err(),
        "a ledger whose notes are worth more than the schedule has ever paid was taken"
    );
}

/// The same money, in the tier no receiver can sum.
///
/// The tightening the test above asks for is free and exact: the hot set
/// arrives in full, so a receiver can add it up and refuse a ledger holding
/// more than it declares. This is the half that tightening does not reach. The
/// cold set arrives as sixty four hashes, and a note in it is worth whatever
/// its leaf says: a sender who mined the burial writes the leaf, and the
/// receiver takes the ledger, holds a lawful total, and spends the note with
/// the proof the sender kept.
///
/// So the sentence "a ledger that holds more was not produced by these rules"
/// cannot be made true by any check on this exchange. What the schedule bounds
/// is the number beside the ledger.
#[test]
fn the_tier_that_cannot_be_added_up_is_not_bounded_by_the_declared_total() {
    let params = rules();
    let mut node = Node::new(params);
    for _ in 0..(RECENT_HEADERS as u64 + BURIAL) {
        node.mine(&wallet(1));
    }

    let mut handover = node.handover();
    let at_height = handover.at.height;
    assert!(
        handover.cold.is_empty() && handover.grace_proofs.is_empty(),
        "this fixture never evicted, so the cold set is where the forgery can go alone"
    );

    let forged = Amount::from_pebbles(50_000_000_000_000_000).unwrap();
    let id = NoteId::new(Hash32::from_bytes([0xC0; 32]), 0);
    let note = Note::new(forged, wallet(9).public_key());
    let mut archive = Archive::new();
    archive.add(cold_leaf(&id, &note)).unwrap();
    handover.cold = archive.forest().roots_only();

    let mut at = handover.at;
    at.state_root = state_root_of(&handover);
    handover.at = at;
    let below: Vec<BlockHeader> = node.headers[..at_height as usize].to_vec();
    rerun_above(&mut handover, &below, &params);

    let mut state = accept(&handover, &params)
        .expect("nothing in this exchange can weigh a cold set it does not hold");
    assert_eq!(
        state.supply(),
        params.emitted_by(at_height),
        "the total it declares is exactly what the schedule paid"
    );

    let height = state.next_height().unwrap();
    let proof = archive.prove(0).unwrap();
    let mut transfer = Transfer::new(
        vec![Input::cold(id, note, 0, proof)],
        vec![Note::new(forged, wallet(3).public_key())],
    );
    transfer.sign_input(params.network, 0, &note, &wallet(9));
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), wallet(1).public_key())],
    );
    let block = assemble_block(
        &state,
        coinbase,
        vec![transfer],
        &params,
        at.timestamp + SPACING,
        0,
    )
    .expect("a cold note nobody can add up builds a block");
    connect_block(&mut state, &block, &params, NOW).expect("and the block is taken");

    println!(
        "\n  a cold set of one leaf worth {forged}, under a declared total of {}\n",
        state.supply()
    );

    // Recorded rather than refused, which is the whole point of this test.
    //
    // The hot half is closed: what the hot set holds is on the wire and is
    // added up and held against the declared total. This half cannot be, by
    // anybody: the cold set arrives as sixty four hashes, and adding them up
    // would mean holding the set, which is the one thing the design exists so
    // a node does not have to do. There is no receiver-side check to write.
    //
    // What it costs the attacker is unchanged and is the whole defence: out
    // mining the network for the burial. What it changes is the sentence, and
    // the sentence is now what the code does. A test that passes here and a
    // paragraph beside the check are how this stays known rather than being
    // found again.
    assert!(
        forged > state.supply(),
        "this test is only about money the schedule never paid, and {forged} is \
         inside a declared total of {}",
        state.supply()
    );
}

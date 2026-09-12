//! Adversarial audit of the line between the tiers, asked of a ledger that
//! was handed over rather than built.
//!
//! "A note may be in one tier or the other and never in both or in neither" is
//! a property of a ledger a node replayed: eviction takes a note out of the hot
//! set on the way down, and `audit_two_tier_ceiling.rs` asserts it on a chain
//! of a hundred and twenty blocks. A ledger that arrives whole is a second door
//! to the same state, and the two lists that decide this arrive side by side in
//! the message, unread against each other.
//!
//! A note named in both is spent twice: once out of the hot set, and once more
//! out of the window, which is the door that exists so a note that fell moments
//! ago still spends without a proof.

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
use cairn_ledger::{note_key, LedgerState};
use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain, Hasher};
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
const BURIAL: u64 = 8;
const MATURITY: u64 = 4;
const SPACING: u64 = 600;
/// Small enough that notes start falling within a few blocks, so the window a
/// handover carries is a real one.
const TIER: usize = 8;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn rules() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(BURIAL)
        .with_coinbase_maturity(MATURITY)
        .with_hot_capacity(TIER)
}

// ---------------------------------------------------------------------------
// The state root, rebuilt from the published fields.
// ---------------------------------------------------------------------------

fn hot_value(note: &Note, height: u64) -> Hash32 {
    let mut hasher = Hasher::new(Domain::HotNoteValue);
    hasher.update(&note.encode());
    hasher.update(&height.encode());
    hasher.finalize()
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

fn state_root_of(handover: &Handover) -> Hash32 {
    let mut tree = SparseMerkleTree::new();
    for (id, entry) in &handover.hot {
        tree.insert(note_key(id), hot_value(&entry.note, entry.height));
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(tree.root().as_bytes());
    bytes.extend_from_slice(&(tree.len() as u64).to_le_bytes());
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

/// Rebuilds the run from the anchor to the tip over a rewritten anchor.
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
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: archive.forest().commitment(),
            timestamp: clock,
            difficulty,
            total_work: previous.total_work + work_of(difficulty),
            nonce: 0,
        };
        assert!(median_time_past(&window).is_none_or(|median| header.timestamp > median));
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

/// One block spending `input`, on top of `state`.
fn spend(
    state: &mut LedgerState,
    params: &ConsensusParams,
    input: Input,
    note: &Note,
    owner: &SecretKey,
    paid_to: u8,
    clock: u64,
) -> Result<(), cairn_ledger::BlockError> {
    let height = state.next_height().unwrap();
    let mut transfer = Transfer::new(
        vec![input],
        vec![Note::new(note.value, wallet(paid_to).public_key())],
    );
    transfer.sign_input(params.network, 0, note, owner);
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), wallet(1).public_key())],
    );
    let block = assemble_block(state, coinbase, vec![transfer], params, clock, 0)?;
    connect_block(state, &block, params, NOW)?;
    Ok(())
}

/// The recomputation above is the one the implementation does.
#[test]
fn the_root_rebuilt_here_is_the_root_the_anchor_carries() {
    let params = rules();
    let mut node = Node::new(params);
    for _ in 0..(RECENT_HEADERS as u64 + BURIAL) {
        node.mine(&wallet(1));
    }
    let handover = node.handover();
    assert_eq!(state_root_of(&handover), handover.at.state_root);
    accept(&handover, &params).expect("an honest handover is taken");
}

/// A handed ledger that names one note in both tiers spends it twice.
///
/// The hot set and the grace window arrive as two lists in one message. Each
/// is checked against the header, and a sender who mined the burial wrote the
/// header, so neither check says anything about the other. Nothing compares
/// them, and a replayed ledger cannot produce the overlap, so nothing ever had
/// to.
///
/// The note is spent as a hot note on the first block, which takes it out of
/// the hot set and leaves the window naming it. On the second block the same
/// identifier resolves through the window instead, with the path the handover
/// itself supplied, and pays a second time.
#[test]
fn a_handed_ledger_naming_a_note_in_both_tiers_spends_it_twice() {
    let params = rules();
    let miner = wallet(1);
    let mut node = Node::new(params);
    for _ in 0..(RECENT_HEADERS as u64 + BURIAL) {
        node.mine(&miner);
    }

    let mut handover = node.handover();
    let at_height = handover.at.height;
    assert!(
        !handover.grace.iter().all(Vec::is_empty),
        "the fixture never evicted, so there is no window to name a note twice"
    );

    // A note in the window whose coinbase has already matured, so the wait is
    // not what refuses the spend.
    let waiting: Vec<Hash32> = handover.maturing.iter().map(|(_, id)| *id).collect();
    // The newest end of the window, so the two blocks that follow do not age
    // it out before the second spend is offered.
    let mut window: Vec<(NoteId, u64, Note)> = handover.grace.iter().flatten().copied().collect();
    window.reverse();
    let (id, position, note) = window
        .iter()
        .find(|(id, _, _)| !waiting.contains(&id.source))
        .copied()
        .expect("a matured note sits in the window");

    // Named in the hot set as well, in the place of a note the ledger drops.
    // The tier's own cap therefore does not move, and neither does the count
    // the header commits to.
    let displaced = handover.hot[0];
    handover.hot[0] = (
        id,
        HotEntry {
            note,
            height: displaced.1.height,
        },
    );

    let mut at = handover.at;
    at.state_root = state_root_of(&handover);
    handover.at = at;
    let below: Vec<BlockHeader> = node.headers[..at_height as usize].to_vec();
    rerun_above(&mut handover, &below, &params);

    let taken = accept(&handover, &params);
    let mut state = match taken {
        Ok(state) => state,
        Err(refused) => {
            // The defect is absent: the ledger was refused, and the reason is
            // printed so a refusal for some unrelated reason is not read as a
            // rule that is there.
            println!("\n  the forged ledger was refused: {refused}\n");
            return;
        }
    };

    assert!(
        state.hot_note(&id).is_some(),
        "the forged ledger did not take the note into the hot set"
    );
    assert!(
        state.within_grace(&id).is_some(),
        "the forged ledger did not keep the note in the window"
    );

    let before = Amount::checked_sum(state.hot_notes().map(|(_, entry)| entry.note.value)).unwrap();
    let clock = at.timestamp;

    // Once out of the hot set.
    spend(
        &mut state,
        &params,
        Input::hot(id),
        &note,
        &miner,
        3,
        clock + SPACING,
    )
    .expect("the note spends out of the hot set");
    assert!(state.hot_note(&id).is_none());

    // And once more out of the window, which still names it and still holds
    // the path the handover supplied.
    let again = spend(
        &mut state,
        &params,
        Input::hot(id),
        &note,
        &miner,
        4,
        clock + 2 * SPACING,
    );

    let after = Amount::checked_sum(state.hot_notes().map(|(_, entry)| entry.note.value)).unwrap();
    // Two payees, each holding a note worth what the one note was worth.
    let paid: Vec<Amount> = [3u8, 4]
        .iter()
        .filter_map(|seed| {
            let owner = wallet(*seed).public_key();
            state
                .hot_notes()
                .find(|(_, entry)| entry.note.owner == owner)
                .map(|(_, entry)| entry.note.value)
        })
        .collect();
    println!(
        "\n  note at cold position {position}, worth {}\n  \
         hot set before the two spends {before}, after {after}\n  \
         second spend: {again:?}\n  \
         payees holding a note of that value afterwards: {paid:?}\n",
        note.value
    );
    assert!(
        again.is_err(),
        "the same note paid twice: {} was spent out of the hot set and then out \
         of the grace window, out of a ledger a node took whole",
        note.value
    );
}

/// **And a window that names one place twice is refused.**
///
/// The third of the same family, found by reading rather than by running, and
/// written down here because reading is not measuring. The leaf to check a
/// grace proof against was worked out by walking to the first entry at a
/// position, so a second entry there was verified against nothing: the loop
/// found a proof already watched for that position and let it through. Two
/// entries, two spendable notes, one leaf in the cold set.
///
/// Positions are handed out in order and never reused, so a window naming one
/// twice is not a window this chain produced, and the check is a map instead
/// of a walk.
#[test]
fn a_window_that_names_one_place_twice_is_not_a_window_this_chain_produced() {
    let params = rules();
    let miner = wallet(1);
    let mut node = Node::new(params);
    for _ in 0..(RECENT_HEADERS as u64 + BURIAL) {
        node.mine(&miner);
    }

    let honest = node.handover();
    accept(&honest, &params).expect("the fixture's own handover is taken");

    let mut handover = honest.clone();
    let at_height = handover.at.height;
    let window: Vec<(NoteId, u64, Note)> = handover.grace.iter().flatten().copied().collect();
    assert!(
        window.len() >= 2,
        "the fixture evicted {} notes, and this needs two",
        window.len()
    );

    // A second entry at the first entry's place, naming a different note that
    // nothing in the cold set ever held. The proof list is left alone: it
    // already carries one for that position, which is the whole of what made
    // this work.
    // Worth one pebble, and the value matters. What this test is about is the
    // place, and a note worth more than the total the same message declares
    // is refused by the sum over the tiers that arrive in full before the
    // place is ever looked at. A forgery that trips two rules measures the
    // first one.
    let (_, position, _) = window[0];
    let invented = (
        NoteId::new(Hash32::from_bytes([0xB1; 32]), 0),
        position,
        Note::new(
            cairn_primitives::Amount::from_pebbles(1).unwrap(),
            wallet(9).public_key(),
        ),
    );
    let last = handover
        .grace
        .iter()
        .rposition(|fell| !fell.is_empty())
        .expect("the window holds something");
    handover.grace[last].push(invented);

    let mut at = handover.at;
    at.state_root = state_root_of(&handover);
    handover.at = at;
    let below: Vec<BlockHeader> = node.headers[..at_height as usize].to_vec();
    rerun_above(&mut handover, &below, &params);

    let refused =
        accept(&handover, &params).expect_err("a window naming one place twice was taken");
    println!("\n  refused: {refused}\n");
    assert!(
        format!("{refused}").contains(&format!("position {position} twice")),
        "refused for something other than the place named twice: {refused}"
    );
}

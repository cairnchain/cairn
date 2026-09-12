//! SEAM AUDIT: the third tier a handover carries in full, and nobody adds up.
//!
//! `audit_what_the_ceiling_weighs.rs` splits a handed ledger in two and
//! decides the argument on that split: "The hot set is on the wire, so what it
//! holds is added up and held against the declared total. The cold set is
//! sixty four hashes, and adding those up would mean holding the set, which is
//! the one thing this design exists so a node does not have to do."
//!
//! Both sentences are true and the split has three parts. The grace window
//! travels in full as well, note by note, value by value, because a receiver
//! cannot spend out of it otherwise: `Handover::grace` is
//! `Vec<Vec<(NoteId, u64, Note)>>` and the notes in it are the ones spendable
//! with no proof from the spender at all. It is countable by the receiver for
//! exactly the reason the hot set is, and `against_each_other` counts only the
//! hot set.
//!
//! So the free half of the repair covers one of the two countable tiers. This
//! test hands over a ledger whose hot set is honest, whose declared total is
//! the lawful 4 550 CAIRN, and whose grace window holds one note worth five
//! hundred million, and spends it on the next block with `Input::hot`.
//!
//! What this does not claim: it buys an attacker nothing the cold set does not
//! already buy, and the cost is the same in both cases, which is out-mining
//! the network for the burial. It is the sentence that is wrong, and the check
//! that closes it is the same one line that closed the hot half.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    clippy::similar_names
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

// The state root rebuilt from the published fields, so a forged ledger can be
// given the root it deserves. The same eight fields as
// `audit_what_the_ceiling_weighs.rs`, and the first test below holds this
// against the implementation before anything is forged.

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

/// What the two tiers a receiver holds in full come to, added up.
fn what_arrives_in_full(handover: &Handover) -> Amount {
    let hot = handover.hot.iter().map(|(_, entry)| entry.note.value);
    let window = handover
        .grace
        .iter()
        .flatten()
        .map(|(_, _, note)| note.value);
    Amount::checked_sum(hot.chain(window)).expect("the two countable tiers sum")
}

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
/// Every header the run carries is checked by `check_buried`, and none of that
/// costs anything on a chain at the difficulty floor, which is where this
/// fixture's rules put it. That is what "out-mined the network for the burial"
/// comes to in a test.
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

/// The root rebuilt here is the root the anchor carries.
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

/// The grace window arrives note by note and is not held to the declared
/// total.
///
/// The hot set is added up and refused when it holds more than the message
/// says the chain has issued. The grace window is the other half of the
/// ledger a receiver holds in full, and the check does not read it: one note
/// worth five hundred million CAIRN travels there under a declared total of
/// 4 550, is accepted, and spends on the next block with no proof from the
/// spender, because a note in the window is exactly the one kind that needs
/// none.
#[test]
fn a_note_in_the_grace_window_is_not_weighed_against_the_declared_total() {
    let params = rules();
    let mut node = Node::new(params);
    for _ in 0..(RECENT_HEADERS as u64 + BURIAL) {
        node.mine(&wallet(1));
    }

    let mut handover = node.handover();
    let at_height = handover.at.height;
    assert!(
        handover.cold.is_empty() && handover.grace.iter().flatten().count() == 0,
        "this fixture never evicted, so the window is empty until this test fills it"
    );
    let honest = what_arrives_in_full(&handover);

    // One leaf in the cold set, and the window naming it. Both are fields of
    // the one state root, which a sender that mined the burial writes.
    let forged = Amount::from_pebbles(50_000_000_000_000_000).unwrap();
    let id = NoteId::new(Hash32::from_bytes([0x67; 32]), 0);
    let note = Note::new(forged, wallet(9).public_key());
    let mut archive = Archive::new();
    archive.add(cold_leaf(&id, &note)).unwrap();
    handover.cold = archive.forest().roots_only();
    handover.grace = vec![vec![(id, 0, note)]];
    handover.grace_proofs = vec![(0, archive.prove(0).unwrap())];

    let mut at = handover.at;
    at.state_root = state_root_of(&handover);
    handover.at = at;
    let below: Vec<BlockHeader> = node.headers[..at_height as usize].to_vec();
    rerun_above(&mut handover, &below, &params);

    let ceiling = params.emitted_by(at_height);
    let held = what_arrives_in_full(&handover);
    println!(
        "\n  anchor at height {at_height}\n  \
         the schedule has paid at most            {ceiling}\n  \
         the handover declares                    {}\n  \
         the two tiers that arrive in full hold   {held}\n  \
         the honest chain's two tiers held        {honest}\n",
        handover.supply
    );

    let taken = accept(&handover, &params);
    if let Ok(state) = &taken {
        assert_eq!(
            state.supply(),
            ceiling,
            "the total it declares is exactly what the schedule paid"
        );
        assert!(
            state.within_grace(&id).is_some(),
            "the window the receiver rebuilt holds the note"
        );

        // Spent with `Input::hot`, which is to say with nothing: a note in the
        // window is the one kind the spender needs no path for, and the path
        // the window needs came with the handover and was checked against the
        // cold commitment on the way in.
        let mut fresh = state.clone();
        let height = fresh.next_height().unwrap();
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
        .expect("a note in the handed window builds a block with no proof at all");
        connect_block(&mut fresh, &block, &params, NOW).expect("and the block is taken");
        println!(
            "  spent on the next block with no proof: {forged} paid to a stranger, \
             and the ledger still says it has issued {}\n",
            fresh.supply()
        );
    }

    assert!(
        taken.is_err(),
        "a handover whose countable tiers hold {held} was taken against a declared \
         total of {}, and the window is as countable as the hot set",
        handover.supply
    );
}

//! AUDIT: four refusals in `accept` that nothing measured at their edge.
//!
//! Found by mutation rather than by reading: each of the four survived a
//! change to the comparison that makes it, with the whole suite green. A
//! refusal nothing measures at its edge is a refusal nobody knows the shape
//! of, and three of these four decide whether a newcomer takes a ledger.
//!
//! - both headers are asked for their work, and either failing is enough;
//! - a build too old to judge the tip says so, whatever version the tip
//!   claims;
//! - a grace window of exactly what the rules keep is kept;
//! - a header dated at the very moment the network opened is inside it.
//!
//! The chain here is mined at a difficulty where an identifier has to be
//! found, because at the floor every identifier meets the target and the
//! first of the four cannot be asked at all. Which is also what the three
//! refusals below the four are about: they are the ones an enumeration of
//! every refusal in the workspace found no test had ever seen, and every one
//! of them is about work on a header of a run.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, BlockHeader, BLOCK_VERSION};
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::{meets_target, RECENT_HEADERS};
use cairn_ledger::state::{header_leaf, Fallen, GRACE_BLOCKS, GRACE_NOTES};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 24;
/// High enough that an identifier has to be found and low enough that a
/// hundred of them take under a second.
const OPENING: u64 = 4_096;
const BURIAL: u64 = 8;
/// The first block's timestamp. Everything is dated from here.
const CLOCK: u64 = 1_000;

fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet().with_burial(BURIAL);
    params.genesis_difficulty = OPENING;
    params
}

/// A chain mined at a difficulty, kept the way a node that has been running
/// keeps one.
struct Node {
    past: Vec<LedgerState>,
    history: Archive,
    headers: Vec<BlockHeader>,
}

impl Node {
    fn mined(count: usize) -> Self {
        let params = params();
        let miner = SecretKey::from_bytes(&[3; 32]);
        let mut state = LedgerState::archiving();
        let mut node = Self {
            past: Vec::new(),
            history: Archive::new(),
            headers: Vec::new(),
        };
        let mut clock = CLOCK;
        for _ in 0..count {
            let height = state.next_height().unwrap();
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).expect("a nonce at this difficulty");
            connect_block(&mut state, &block, &params, NOW).unwrap();
            clock += params.target_block_time;
            node.past.push(state.clone());
            node.history.add(header_leaf(&block.header.id())).unwrap();
            node.headers.push(block.header);
        }
        node
    }

    /// What this node would hand to someone starting out.
    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let at_height = tip.height - BURIAL;
        let at = self.headers[at_height as usize];
        let anchor = self.history.prove_in(at_height, tip.height).unwrap();
        let first = (at_height as usize + 1).saturating_sub(RECENT_HEADERS);
        self.past[at_height as usize]
            .handover(
                at,
                tip,
                self.past[tip.height as usize].headers_before_tip(),
                anchor,
                self.headers[(at_height as usize + 1)..].to_vec(),
                self.headers[first..=at_height as usize].to_vec(),
            )
            .expect("every note in the window has a path")
    }
}

/// The header whose identifier no longer meets its own target, found by
/// turning the nonce until it does not.
fn without_work(header: BlockHeader) -> BlockHeader {
    let mut broken = header;
    while meets_target(&broken.id(), broken.difficulty) {
        broken.nonce += 1;
    }
    broken
}

/// The control the three refusals below are worth nothing without.
#[test]
fn the_ledger_this_chain_really_has_is_taken() {
    let node = Node::mined(RECENT_HEADERS + 8);
    accept(&node.handover(), &params()).expect("its own rules take its ledger");
}

/// Both headers are asked, and either one failing is enough.
///
/// The tip is pinned by the weighing that came before, so the anchor is the
/// one a sender writes freely, and it is the one this asks about. The two
/// questions are joined by "or": asking for both to fail would take a ledger
/// whose anchor was never mined, as long as the tip beside it was.
#[test]
fn an_anchor_without_work_is_refused_while_the_tip_still_has_its_own() {
    let node = Node::mined(RECENT_HEADERS + 8);
    let mut handover = node.handover();
    handover.at = without_work(handover.at);
    assert!(
        meets_target(&handover.tip.id(), handover.tip.difficulty),
        "the tip is untouched, so the refusal below is about the anchor alone"
    );
    assert_eq!(
        accept(&handover, &params()).err(),
        Some(HandoverError::HeaderWithoutWork)
    );
}

/// A build whose rules stop below the tip says so, whatever the tip claims.
///
/// The two halves of the version question are asked in order, and the order is
/// the point: what the rules require at the tip's height is read first, and a
/// build that does not have those rules cannot judge the header at all. A tip
/// understating its version is not a bad block to such a node, it is a block
/// it has no rules for, and answering `WrongVersion` would blame a peer for
/// this node being old.
#[test]
fn a_build_without_the_rules_at_the_tip_is_too_old_and_not_owed_a_verdict() {
    let node = Node::mined(RECENT_HEADERS + 8);
    let handover = node.handover();
    let ahead: &[Activation] = &[
        Activation {
            height: 0,
            version: BLOCK_VERSION,
        },
        Activation {
            height: 5,
            version: BLOCK_VERSION + 1,
        },
    ];
    let announced = ConsensusParams {
        activations: ahead,
        ..params()
    };
    assert_eq!(
        handover.tip.version, BLOCK_VERSION,
        "the tip carries what this build knows, which is what makes the two \
         halves answer differently"
    );
    assert_eq!(
        accept(&handover, &announced).err(),
        Some(HandoverError::SoftwareTooOld {
            height: handover.tip.height,
            required: BLOCK_VERSION + 1,
            known: BLOCK_VERSION,
        })
    );
}

/// A window holding exactly what the rules keep is kept.
///
/// The sibling test holds the other side of this line, one note further up.
/// Between them the refusal has a place rather than a direction.
#[test]
fn a_grace_window_of_exactly_what_the_rules_keep_is_not_too_much() {
    let node = Node::mined(RECENT_HEADERS + 8);
    let mut handover = node.handover();
    // Worth nothing, so the window holds no money it was not already holding:
    // what is under test is how many notes it names, not what they are worth.
    let miner = SecretKey::from_bytes(&[3; 32]);
    let fallen: Fallen = (
        NoteId::new(Hash32::from_bytes([7; 32]), 0),
        handover.at.height,
        Note::new(Amount::ZERO, miner.public_key()),
    );

    let blocks = GRACE_BLOCKS.min(64);
    let mut stuffed = vec![Vec::new(); blocks];
    let mut left = GRACE_NOTES;
    for block in &mut stuffed {
        let take = left.min(GRACE_NOTES / blocks);
        block.extend(std::iter::repeat_n(fallen, take));
        left -= take;
    }
    stuffed[0].extend(std::iter::repeat_n(fallen, left));
    let notes: usize = stuffed.iter().map(Vec::len).sum();
    assert_eq!(notes, GRACE_NOTES, "exactly the window the rules keep");
    handover.grace = stuffed;

    let refused = accept(&handover, &params()).err();
    assert!(
        !matches!(refused, Some(HandoverError::GraceWindowHoldsTooMuch { .. })),
        "a window of exactly what the rules keep was refused for holding too much: \
         {refused:?}"
    );
}

/// The opening moment is inside the network, not before it.
///
/// `opens_at` is the first moment a block may be dated, and a header dated at
/// it exactly is the first honest block of the network. Refusing it would
/// refuse the chain everybody else follows, from the block that starts it.
#[test]
fn a_header_dated_at_the_opening_itself_is_taken() {
    let node = Node::mined(RECENT_HEADERS + 8);
    let handover = node.handover();
    let earliest = handover
        .recent
        .iter()
        .chain(handover.buried.iter())
        .chain([&handover.at, &handover.tip])
        .map(|header| header.timestamp)
        .min()
        .expect("the handover carries headers");
    let mut opening = params();
    opening.opens_at = earliest;
    accept(&handover, &opening).expect("a chain whose earliest header opens the network");
}

/// A header of the buried run without work of its own is refused, and named.
///
/// Found by enumeration rather than by reading: `BuriedWithoutWork` was a
/// refusal no test in the workspace had ever seen. The run between the ledger
/// and the tip is the one stretch a newcomer walks itself, and a header in it
/// that was never mined is the cheapest thing a sender can offer.
#[test]
fn a_buried_header_without_work_is_refused_and_named() {
    let node = Node::mined(RECENT_HEADERS + 8);
    let mut handover = node.handover();
    let at = handover.buried.len() / 2;
    let height = handover.buried[at].height;
    handover.buried[at] = without_work(handover.buried[at]);

    assert_eq!(
        accept(&handover, &params()).err(),
        Some(HandoverError::BuriedWithoutWork { at: height })
    );
}

/// And the same for the run below the anchor, which seeds the window the
/// burial above it is judged against.
#[test]
fn a_recent_header_without_work_is_refused() {
    let node = Node::mined(RECENT_HEADERS + 8);
    let mut handover = node.handover();
    let at = handover.recent.len() / 2;
    handover.recent[at] = without_work(handover.recent[at]);

    assert_eq!(
        accept(&handover, &params()).err(),
        Some(HandoverError::RecentWithoutWork)
    );
}

/// A buried run that does not end at the tip is refused for that, whatever
/// else is right about it.
///
/// The tip here is the same header mined again: every field but the nonce is
/// what it was, it carries its own work, and the forest it commits to is the
/// one that was handed over. What is wrong with it is that the run stops one
/// header short of it, which is what this refusal is for and what no test had
/// asked.
#[test]
fn a_buried_run_that_stops_short_of_the_tip_is_refused_for_that() {
    let node = Node::mined(RECENT_HEADERS + 8);
    let mut handover = node.handover();
    let mut again = handover.tip;
    again.nonce += 1;
    while !meets_target(&again.id(), again.difficulty) {
        again.nonce += 1;
    }
    assert_ne!(again.id(), handover.tip.id());
    handover.tip = again;

    assert_eq!(
        accept(&handover, &params()).err(),
        Some(HandoverError::BuriedRunNotEndingAtTheTip)
    );
}

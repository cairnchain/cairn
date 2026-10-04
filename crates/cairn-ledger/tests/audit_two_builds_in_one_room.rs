//! AUDIT: what half a network running the release before the other one costs.
//!
//! Every other pass over the version machinery has asked what one build does
//! about a rule change. This one asks what two builds owe each other while a
//! change waits: which of them gets to decide that the other is behind, and
//! what they have to agree about byte for byte in the meantime.
//!
//! `tests/activation.rs` and `tests/audit_rule_change.rs` cover the schedule
//! itself, and nothing here repeats them. What is here is what they do not
//! reach: a verdict about this build's own age drawn from a header nobody has
//! placed on a chain yet, and then the known answers two builds have to arrive
//! at identically for any of the rest to mean anything, which nothing in the
//! workspace wrote down. The encodings, twenty blocks of ledger, the retarget,
//! and the schedule of every network this build ships.

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
use cairn_ledger::block::{Block, BlockHeader, HeaderSummary, BLOCK_VERSION};
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::pow::{meets_target, next_difficulty, Origin, RECENT_HEADERS};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::hex;
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
const HOT: usize = 8;
const BURIAL: u64 = 8;
const MATURITY: u64 = 4;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(HOT)
        .with_burial(BURIAL)
        .with_coinbase_maturity(MATURITY)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain kept the way `tests/handover.rs` keeps one, so a real handover can
/// be produced and then bent by one field.
struct Node {
    state: LedgerState,
    past: Vec<LedgerState>,
    history: Archive,
    headers: Vec<BlockHeader>,
    clock: u64,
}

impl Node {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            past: Vec::new(),
            history: Archive::new(),
            headers: Vec::new(),
            clock: 1_000,
        }
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize) {
        let params = params();
        for _ in 0..count {
            let height = self.state.next_height().unwrap();
            self.clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block =
                assemble_block(&self.state, coinbase, Vec::new(), &params, self.clock, 0).unwrap();
            connect_block(&mut self.state, &block, &params, NOW).unwrap();
            self.past.push(self.state.clone());
            self.history
                .add(cairn_ledger::state::header_leaf(&block.header.id()))
                .unwrap();
            self.headers.push(block.header);
        }
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

/// **A node must not conclude it is out of date from a header nobody has
/// placed on a chain.**
///
/// `SoftwareTooOld` is the one verdict that stops a node: `cairn-net` keeps it
/// in `Shared::outdated` and `cairn-node`'s `stopped_itself` prints it and
/// exits, telling the operator to update. So the evidence for it has to be
/// something a stranger cannot write.
///
/// For a block that was settled: `validation::check_header` draws it only from
/// `params.version_at(state.next_height())`, this node's own schedule at this
/// node's own tip, and a version the block itself carries can never reach it.
///
/// `handover::accept` had the other shape. It read `at.version` at the top,
/// among the things asked "before anything else is looked at", and the proof
/// that `at` is on the weighed chain comes further down. `tip` is pinned by the
/// caller, which checks the ledger names the header the weighing settled on,
/// and `land_the_ledger` says so in as many words. Nothing pins `at` until the
/// forest proof.
///
/// So the anchor was a header the sender wrote: this network, a timestamp past
/// its opening, the difficulty floor, where `target_for` returns all ones and
/// any identifier meets it. One hash, no work, and the receiver stops itself
/// and tells its operator to go and install a release that does not exist.
///
/// The clause was also unreachable honestly. Versions rise with height and the
/// anchor sits below the tip, so `at.version` above this build's ceiling while
/// `tip.version` is not is a combination no chain produces.
#[test]
fn an_anchor_nobody_has_placed_cannot_tell_this_build_it_is_too_old() {
    let params = params();
    let mut node = Node::new();
    node.mine_empty(&wallet(1), RECENT_HEADERS + 40);

    let honest = node.handover();
    accept(&honest, &params).expect("the handover it was built from checks out");

    let mut forged = honest.clone();
    forged.at = BlockHeader {
        version: BLOCK_VERSION + 1,
        network: params.network,
        height: honest.at.height,
        previous: Hash32::ZERO,
        transactions_root: Hash32::ZERO,
        state_root: Hash32::ZERO,
        history: Hash32::ZERO,
        timestamp: honest.at.timestamp,
        difficulty: cairn_ledger::pow::MIN_DIFFICULTY,
        total_work: 1,
        nonce: 0,
    };

    assert!(
        meets_target(&forged.at.id(), forged.at.difficulty),
        "the floor takes any identifier, which is what makes this free"
    );

    let refused = accept(&forged, &params).expect_err("an invented anchor is not a ledger");
    assert!(
        !matches!(refused, HandoverError::SoftwareTooOld { .. }),
        "a stranger stopped this node by writing a number in a header it had \
         not shown belonged to any chain: {refused:?}"
    );

    // And the honest reading of the same situation is untouched: a build one
    // release behind, handed a ledger from a chain that really has moved, is
    // still told it is the one that is behind. That verdict comes from the
    // tip, which the caller pinned to the chain the weighing settled on.
    let mut moved = honest.clone();
    moved.tip.version = BLOCK_VERSION + 1;
    assert!(
        matches!(
            accept(&moved, &params),
            Err(HandoverError::SoftwareTooOld {
                required,
                known: BLOCK_VERSION,
                ..
            }) if required == BLOCK_VERSION + 1
        ),
        "the chain moving is still this build's problem to admit"
    );
}

/// A header with every field distinct, so a swap between two of the same width
/// moves the bytes rather than cancelling out.
fn pinned_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        network: NetworkId::TESTNET,
        height: 0x0011_2233_4455_6677,
        previous: Hash32::from_bytes([0xa1; 32]),
        transactions_root: Hash32::from_bytes([0xb2; 32]),
        state_root: Hash32::from_bytes([0xc3; 32]),
        history: Hash32::from_bytes([0xd4; 32]),
        timestamp: 0x0102_0304_0506_0708,
        difficulty: 0x1122_3344_5566_7788,
        total_work: 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
        nonce: 0xfedc_ba98_7654_3210,
    }
}

fn pinned_coinbase() -> CoinbaseTransaction {
    CoinbaseTransaction::with_extra(
        0x0102_0304_0506_0708,
        vec![
            Note::new(Amount::from_pebbles(1).unwrap(), wallet(1).public_key()),
            Note::new(
                Amount::from_pebbles(0x0f0e_0d0c).unwrap(),
                wallet(2).public_key(),
            ),
        ],
        b"cairn audit vector".to_vec(),
    )
}

fn pinned_transfer() -> Transfer {
    Transfer::new(
        vec![
            Input::hot(NoteId::new(Hash32::from_bytes([0x11; 32]), 0)),
            Input::hot(NoteId::new(Hash32::from_bytes([0x22; 32]), 0x0304_0506)),
        ],
        vec![Note::new(
            Amount::from_pebbles(0x0708_090a).unwrap(),
            wallet(3).public_key(),
        )],
    )
}

/// **What two builds have to produce the same bytes for, and what says so.**
///
/// `cairn-primitives/tests/audit_vectors.rs` opens by saying it pins
/// "everything a node has to agree with every other node about", and it pins
/// every hash domain and the Merkle tree. It does not pin a single
/// encoding, and the encodings are the other half: a domain says how bytes are
/// hashed, an `Encode` says which bytes.
///
/// So the tripwire had a hole exactly the shape of an ordinary tidy-up.
/// Swapping two fields of the same width in `BlockHeader::encode_to` and
/// `decode_from` together leaves every round trip passing, leaves
/// `ENCODED_BYTES` at the number `cairn-store` asserts, leaves every domain
/// vector green, and gives every header on the chain a different identifier.
/// Two builds that differ by that edit are two networks, and nothing in the
/// workspace said a word.
///
/// These are the vectors. A failure here is a hard fork, not a refactor. The
/// header carries a different value in every field, so a swap moves the bytes
/// rather than cancelling out.
#[test]
fn the_encodings_two_builds_share_still_produce_the_bytes_they_did() {
    let header = pinned_header();
    assert_eq!(
        hex::encode(&header.encode()),
        "01005a5241437766554433221100\
         a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\
         b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\
         c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3\
         d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4\
         0807060504030201\
         8877665544332211\
         000102030405060708090a0b0c0d0e0f\
         1032547698badcfe",
        "the header's shape changed: every block ever mined has a new identifier"
    );
    assert_eq!(
        header.id().to_string(),
        "cb0e19a1f54ae138fc02d426e4fb3e45da98694c8c36013fe8177b2c4c5dd84d"
    );
    assert_eq!(
        header.encode().len(),
        BlockHeader::ENCODED_BYTES,
        "and the header log finds a record by multiplying an index by this"
    );

    let coinbase = pinned_coinbase();
    assert_eq!(
        coinbase.id().to_string(),
        "770c3f6e50b78d2fe8edd6d913889d4d29ab85c024aeb3ff684b4d81021b12e9",
        "a coinbase identifier names every note it paid"
    );
    let transfer = pinned_transfer();
    assert_eq!(
        transfer.id().to_string(),
        "8c3cfc8c709b462ed817f5de8c79aecbabebfb9cc510f554e7a51a383d1d006d",
        "and a transfer identifier is what names the notes it creates"
    );

    let block = Block {
        header,
        coinbase,
        transfers: vec![transfer],
    };
    assert_eq!(
        block.transactions_root().to_string(),
        "1456ffec07a66b3e02fa496cb49f2896e132f30030833e4bca62fc96ba32bba2",
        "the coinbase leads the transfers, each transfer is committed to by its whole \
         encoding, and the order is consensus"
    );
}

/// **And what two builds have to compute the same number for.**
///
/// The vectors above cover the bytes on the wire. This covers what a build
/// works out from them: the same twenty blocks, and the four commitments and
/// two totals that decide whether two nodes are on one chain.
///
/// It is a wide net on purpose. It moves for a change in the emission
/// schedule, in the retarget, in the eviction order, in how a note is keyed,
/// in how the hot, cold, grace and header structures are folded, and in any
/// rounding or saturation inside those. Every one of those is a fork if two
/// builds do it differently, and none of them had a value written down.
///
/// The blocks are mined at the difficulty floor with a fixed clock, so nothing
/// here is a measurement: it is the same arithmetic every time.
#[test]
fn twenty_blocks_still_come_to_what_they_came_to() {
    let mut node = Node::new();
    node.mine_empty(&wallet(1), 20);
    let state = &node.state;

    assert_eq!(
        state.state_root().to_string(),
        "c76b3db4b5604af3106c720c5a505b9379d56a1c55c16e6aeb1fb1b767c83375",
        "the hot set, the cold set and the grace window, which a header commits \
         to together"
    );
    assert_eq!(
        state.grace_root().to_string(),
        "5f7349ad1ba8075627d8974559b0f04c029d154488fb337e193d8cfba7bdfbce",
        "and the window on its own, which only overflows because the hot set here \
         holds eight"
    );
    assert_eq!(
        state.history_root().to_string(),
        "cd89989bf63556c9dba7de3bc60cc11c05304afc5890272fc8631012e1ce593c"
    );
    assert_eq!(
        state.supply().as_pebbles(),
        100_000_000_000,
        "twenty blocks of what the schedule pays at the opening"
    );
    assert_eq!(
        state.total_work(),
        20,
        "and twenty blocks at the floor are worth one each"
    );
    assert_eq!(
        state.tip().unwrap().id.to_string(),
        "a2a72094864ba91c39ca94ed132a5546163ad0df05134a5a550d974c94c478bb"
    );
}

/// **Every network this build ships answers `version_at` the way the field
/// says it does.**
///
/// The schedule is read backwards and the first entry at or below the height
/// wins, which is the right answer only for an ascending list, and
/// `tests/audit_rule_change.rs` shows two builds carrying the same three
/// changes in different orders putting one height under different rules
/// without a word. `schedule_is_sound` is the guard, and its own comment says
/// it is "checked at build time for every shipped network".
///
/// It is checked at build time for the one constant every shipped network
/// happens to share today. The day a network gets a schedule of its own, that
/// assertion does not cover it and nothing says so. This asks the question of
/// each network by name, so a schedule added to one of them is checked whether
/// or not whoever adds it remembers the constant assertion.
#[test]
fn every_network_this_build_ships_has_a_schedule_read_the_way_it_is_written() {
    for name in ["testnet", "testnet-8", "devnet"] {
        let params = ConsensusParams::for_network(name).expect("a network this build ships");
        let schedule = params.activations;
        let opening = schedule.first().expect("a schedule is never empty");
        assert_eq!(
            opening.height, 0,
            "{name} leaves the rules below its first entry to whatever the \
             binary's own ceiling happens to be"
        );
        for pair in schedule.windows(2) {
            assert!(
                pair[1].height > pair[0].height && pair[1].version > pair[0].version,
                "{name}'s schedule does not ascend, so version_at reads it wrongly"
            );
        }
        // And the reading agrees with the writing, at each entry and just below
        // it, which is the only property the backwards walk is for.
        for entry in schedule {
            assert_eq!(params.version_at(entry.height), entry.version, "{name}");
            if let Some(below) = entry.height.checked_sub(1) {
                assert!(params.version_at(below) < entry.version, "{name}");
            }
        }
    }
}

/// **And the one piece of consensus arithmetic the chain above never reaches.**
///
/// The twenty blocks are mined at the floor, so the retarget answers the floor
/// at every step and none of its arithmetic is inside that vector. It is the
/// place the classic disagreements live: it floors a signed division, splits
/// an exponent into a shift and a fraction, evaluates a cubic, shifts both
/// ways, saturates and clamps, and every one of those is a number two builds
/// have to reach identically or they demand different difficulties of the
/// same block and part company on the next one.
///
/// Ten parents, each reaching a different arm: the first block's child, a
/// network with no block time, blocks found as fast as the median allows,
/// blocks exactly on time, a stall that lands on the descent bound, a chain
/// already at the floor, a parent early by a fraction of a half life, one late
/// by a second and by a fraction, and a difficulty at the ceiling asked to
/// rise. `tests/asert_vectors.txt` holds fifty more, from an independent
/// reference.
#[test]
fn the_retarget_still_answers_what_it_answered() {
    let origin = Origin {
        timestamp: 1_000,
        difficulty: 4_096,
    };
    let parent = |height: u64, timestamp: u64, difficulty: u64| HeaderSummary {
        height,
        timestamp,
        difficulty,
    };
    let on_time = 1_000 + 90 * 60;

    assert_eq!(
        next_difficulty(&parent(0, 1_000, 4_096), origin, 60),
        4_096,
        "the first block's child carries the first block's difficulty"
    );
    assert_eq!(
        next_difficulty(&parent(90, on_time, 4_096), origin, 0),
        4_096,
        "a network with no target block time never retargets"
    );

    // Ninety blocks a second apart, an hour and a half ahead of the schedule,
    // against ninety exactly on time.
    assert_eq!(
        next_difficulty(&parent(90, 1_090, 4_096), origin, 60),
        11_385
    );
    assert_eq!(
        next_difficulty(&parent(90, on_time, 4_096), origin, 60),
        4_096
    );

    // A stall far past two half lives: what comes back is the descent the
    // bound allows and not the one the clock asks for.
    assert_eq!(
        next_difficulty(&parent(90, 1_000 + 90 * 100_000, 4_096), origin, 60),
        1_024
    );

    // And the floor holds the bottom, whatever the clock says.
    let floor = Origin {
        timestamp: 1_000,
        difficulty: 1,
    };
    assert_eq!(
        next_difficulty(&parent(90, 1_000 + 90 * 100_000, 1), floor, 60),
        1
    );

    // A fraction of a half life either side, so the cubic is inside the
    // answer, and one second late, so the floored division is.
    assert_eq!(
        next_difficulty(&parent(90, on_time - 1_234, 4_096), origin, 60),
        5_194
    );
    assert_eq!(
        next_difficulty(&parent(90, on_time + 1, 4_096), origin, 60),
        4_095
    );
    assert_eq!(
        next_difficulty(&parent(90, on_time + 777, 4_096), origin, 60),
        3_527
    );

    // A difficulty at the ceiling asked to double stays at the ceiling.
    let top = Origin {
        timestamp: 1_000,
        difficulty: u64::MAX,
    };
    assert_eq!(
        next_difficulty(&parent(90, on_time - 3_600, u64::MAX), top, 60),
        u64::MAX
    );
}

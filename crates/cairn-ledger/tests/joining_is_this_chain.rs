//! Whether the joining exchange asks *which* chain it is being handed.
//!
//! Weighing a chain and taking its ledger settles how much work stands behind
//! a tip. It does not settle that the tip belongs to the network this node
//! follows, and for a while nothing on either path asked. Two fields say so,
//! both of them read off every block by `validation::check_header` and neither
//! of them read here.
//!
//! The network identifier is the whole of the numbering scheme: a network that
//! changes a rule starts over and takes the next number so that a node still on
//! the old one is told plainly it is on another network. A newcomer was weighed
//! onto another network's chain, took its ledger, and then refused every block
//! that chain went on to produce.
//!
//! The opening moment is the sharper of the two. It is published ahead of a
//! launch so that whoever knew about the network first cannot have mined it
//! quietly the week before, and the claim is that *every* node refuses blocks
//! dated earlier. Every node did not. A chain premined before the opening
//! carries the work that head start bought, and a node with no chain of its own
//! weighed it, took it, and sat on a chain every established node refuses.
//!
//! Both are measured here against the same honest chain, which has to go on
//! being taken: a check that refused an honest chain would be worse than the
//! gap it closes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::pow::{DIFFICULTY_WINDOW, RECENT_HEADERS};
use cairn_ledger::sampling::{
    check_start, draw, seed_of, work_before, Sample, SampledStart, StartError, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 24;
/// High enough that a header cannot be mined by accident, low enough that a
/// hundred and forty of them take under a second.
const OPENING: u64 = 4_096;
const HEIGHT: u64 = 140;
const BURIAL: u64 = 8;
/// The first timestamp of the chain built below. Everything is dated from here.
const CLOCK: u64 = 1_000;

/// A network identifier no chain here was mined under.
const FOREIGN: NetworkId = NetworkId::new(0xDEAD_BEEF);

/// The rules the chain below is mined under: a real network name and an
/// opening moment before any of it.
fn mined_under() -> ConsensusParams {
    let mut params = ConsensusParams::testnet().with_burial(BURIAL);
    params.genesis_difficulty = OPENING;
    params
}

/// One honest chain, with everything the two halves of a join are built from.
struct Joined {
    start: SampledStart,
    handover: Handover,
}

/// Mines a chain and builds the showing and the ledger a newcomer would be
/// handed off it, exactly as an honest peer would.
fn honest_join() -> Joined {
    let params = mined_under();
    let miner = SecretKey::from_bytes(&[3; 32]);
    let mut state = LedgerState::new();
    let mut headers: Vec<BlockHeader> = Vec::new();
    let mut at_state: Option<LedgerState> = None;
    let anchor_height = HEIGHT - 1 - params.burial;
    let mut clock = CLOCK;

    for _ in 0..HEIGHT {
        let height = state.next_height().unwrap();
        clock += params.target_block_time;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce at this difficulty");
        connect_block(&mut state, &block, &params, NOW).unwrap();
        headers.push(block.header);
        if height == anchor_height {
            at_state = Some(state.clone());
        }
    }

    let tip = *headers.last().unwrap();
    // Everything before the tip, which is what the tip's `history` commits to.
    let mut archive = Archive::new();
    for header in headers.iter().take(usize::try_from(tip.height).unwrap()) {
        archive.add(header_leaf(&header.id()));
    }

    let wanted = draw(seed_of(&tip), SAMPLES, work_before(&tip), tip.height);
    let samples: Vec<Sample> = wanted
        .iter()
        .map(|value| {
            let found = *headers
                .iter()
                .find(|header| {
                    let before = header.total_work - u128::from(header.difficulty);
                    before <= *value && header.total_work > *value
                })
                .unwrap_or_else(|| panic!("nothing spans work {value}"));
            Sample {
                header: found,
                proof: archive.prove_in(found.height, tip.height).unwrap(),
            }
        })
        .collect();
    let deepest = samples.iter().map(|s| s.header.height).max().unwrap();
    let from = usize::try_from(deepest.saturating_sub(DIFFICULTY_WINDOW as u64)).unwrap();
    let below = tip.height - 1;
    let start = SampledStart {
        tip,
        parent: Some(Sample {
            header: headers[usize::try_from(below).unwrap()],
            proof: archive.prove_in(below, tip.height).unwrap(),
        }),
        tail: headers[from..].to_vec(),
        history: archive.forest().roots_only(),
        samples,
    };

    let anchor = usize::try_from(anchor_height).unwrap();
    let at = headers[anchor];
    let handover = at_state
        .unwrap()
        .handover(
            at,
            tip,
            archive.forest().roots_only(),
            archive.prove_in(at.height, tip.height).unwrap(),
            headers[anchor + 1..].to_vec(),
            headers[anchor + 1 - RECENT_HEADERS..=anchor].to_vec(),
        )
        .unwrap();

    Joined { start, handover }
}

/// The control the two refusals below are worth nothing without.
#[test]
fn the_chain_these_rules_mined_is_still_taken() {
    let joined = honest_join();
    let params = mined_under();
    check_start(&joined.start, SAMPLES, NOW, &params).expect("its own rules weigh it");
    accept(&joined.handover, &params).expect("its own rules take its ledger");
}

/// A newcomer is not weighed onto another network's chain.
///
/// The same header offered as a block is refused by `check_header` for the
/// same reason, which is what makes this a gap between two paths rather than a
/// rule nobody had written.
#[test]
fn a_chain_from_another_network_is_refused_by_both_halves_of_a_join() {
    let joined = honest_join();
    let mut ours = mined_under();
    ours.network = FOREIGN;

    let weighed = check_start(&joined.start, SAMPLES, NOW, &ours);
    assert!(
        matches!(weighed, Err(StartError::WrongNetwork { .. })),
        "the weighing took another network's chain: {weighed:?}"
    );
    let taken = accept(&joined.handover, &ours);
    assert!(
        matches!(taken, Err(HandoverError::WrongNetwork { .. })),
        "the handover took another network's ledger: {taken:?}"
    );
}

/// A newcomer is not weighed onto a chain that was mined before the network
/// opened.
///
/// That is the premine the opening moment exists to refuse, and the head start
/// is worth exactly the extra work it bought. Every block of this chain is
/// dated before the opening the reader was given, so an established node would
/// refuse all of it.
#[test]
fn a_chain_mined_before_the_network_opened_is_refused_by_both_halves_of_a_join() {
    let joined = honest_join();
    let mut ours = mined_under();
    ours.opens_at = NOW;
    assert!(
        joined.start.tip.timestamp < ours.opens_at,
        "the chain has to predate the opening for this to be measuring anything"
    );

    let weighed = check_start(&joined.start, SAMPLES, NOW, &ours);
    assert!(
        matches!(weighed, Err(StartError::BeforeTheNetworkOpened { .. })),
        "the weighing took a chain mined before the network opened: {weighed:?}"
    );
    let taken = accept(&joined.handover, &ours);
    assert!(
        matches!(taken, Err(HandoverError::BeforeTheNetworkOpened { .. })),
        "the handover took a ledger from before the network opened: {taken:?}"
    );
}

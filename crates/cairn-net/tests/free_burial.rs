//! What the burial actually costs whoever has to lay it.
//!
//! `BURIAL` is a height: `at.height + burial <= tip.height`. The security
//! argument reads that as a thousand and twenty-four blocks' worth of work,
//! done while the chain stayed the heaviest on offer. That reading holds only
//! if the difficulty over those blocks is beyond the sender's reach.
//!
//! It was not. `accept` checked that each handed-over `recent` header met its
//! own declared difficulty and that the run was consecutive. It never checked
//! that declared difficulty against the retarget rule, and never looked at the
//! timestamps at all, yet those ninety-one headers are the entire input to
//! `expected_difficulty` and `median_time_past` for every block the newcomer
//! then validates. So a sender chose the price of its own burial.
//!
//! The handover now carries every header between the anchor and the tip, and
//! each of them is judged by the rule a node applies to any other block: the
//! difficulty its window demands, a timestamp past that window's median, its
//! own work added to the total. What a burial costs is therefore what the
//! chain costs, which is a number nobody in the exchange gets to pick. A chain
//! genuinely sitting on the floor still has a cheap burial, as this test
//! shows, and is also worth nothing in the fork choice, which is the answer to
//! why that is not a way in.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_chain::{Accepted, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::handover::{accept, Handover, BURIAL};
use cairn_ledger::note::Note;
use cairn_ledger::pow::{median_time_past, MIN_DIFFICULTY, RECENT_HEADERS};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{
    assemble_block, connect_block, expected_difficulty, ConsensusParams,
};
use cairn_ledger::LedgerState;

/// A clock in 2033, which is what a node validating this would have.
const NOW: u64 = 2_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// **A chain that really is on the floor has a burial that costs nothing, and
/// that is not a way in.**
///
/// A supplier hands over an anchor whose ninety-one `recent` headers sit at the
/// difficulty floor and are stamped in 1970. Nothing objects, and nothing
/// should: the chain really was mined there, so the floor is what its window
/// demands and what the run above it carries.
///
/// The newcomer then demands `MIN_DIFFICULTY` of the next block, and measures
/// its timestamp against a median from 1970. So the thousand and twenty-four
/// blocks that are supposed to stand between the anchor and the tip, the
/// entire substance of the guarantee, are produced here with no mining at all,
/// stamped across seventeen hours of a stated time that has already happened,
/// and every one of them is accepted.
///
/// What used to make this an attack was that a sender could hand such a window
/// down from a chain that was nowhere near the floor. The second half of this
/// test is that half: the same run, offered against a window that demands more
/// than the floor, is refused.
#[test]
fn a_floor_chain_has_a_cheap_burial_and_a_sender_cannot_claim_one() {
    let params = params();
    let supplier = wallet(9);

    // The supplier's chain. Blocks ten times slower than the target, so the
    // retarget pins the difficulty to its floor and stays there.
    let mut state = LedgerState::archiving();
    let mut headers: Vec<BlockHeader> = Vec::new();
    let mut history = Archive::new();
    let mut clock = 1_000u64;
    let mut anchor_state: Option<LedgerState> = None;

    let anchor_height = RECENT_HEADERS as u64 + 4;
    let tip_height = anchor_height + BURIAL;

    for height in 0..=tip_height {
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, supplier.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        history.add(header_leaf(&block.header.id())).unwrap();
        headers.push(block.header);
        if height == anchor_height {
            anchor_state = Some(state.clone());
        }
    }

    let at = headers[anchor_height as usize];
    let tip = headers[tip_height as usize];
    assert_eq!(
        at.difficulty, MIN_DIFFICULTY,
        "the whole run sits on the floor"
    );
    assert!(
        at.timestamp < 100_000_000,
        "and is stamped in the last century, not this one"
    );

    let anchor_state = anchor_state.unwrap();
    let from = anchor_height + 1 - RECENT_HEADERS as u64;
    let recent: Vec<BlockHeader> = headers[from as usize..=anchor_height as usize].to_vec();
    let handover = Handover {
        at,
        tip,
        tip_history: state.headers_before_tip(),
        anchor: history.prove_in(anchor_height, tip.height).unwrap(),
        hot: anchor_state.hot_notes().collect(),
        cold: anchor_state.cold_roots(),
        grace: anchor_state.grace_window(),
        grace_proofs: anchor_state
            .grace_window()
            .iter()
            .flatten()
            .filter_map(|(_, position, _)| {
                Some((*position, anchor_state.cold().proof_of(*position)?))
            })
            .collect(),
        headers: anchor_state.headers_before_tip(),
        buried: headers[(anchor_height as usize + 1)..].to_vec(),
        recent: recent.clone(),
    };

    // Taken, with no objection to the difficulty or to the timestamps.
    let taken = accept(&handover, &params).unwrap();
    assert_eq!(
        expected_difficulty(&taken, &params),
        MIN_DIFFICULTY,
        "the newcomer will demand nothing of the next block"
    );
    let median = median_time_past(taken.recent_headers()).unwrap();
    assert!(
        median < 100_000_000,
        "and will compare its timestamp against a median from 1970, so the \
         whole run may be stamped in the past"
    );

    let mut chain = ChainStore::new(params);
    chain.adopt(taken, &recent).unwrap();

    // The burial, laid in one pass. No mining loop: at the floor every hash
    // meets the target. No waiting: every timestamp is behind the validator's
    // clock, which the drift rule does not police.
    let attacker = wallet(2);
    let mut stamp = at.timestamp;
    for _ in 0..BURIAL {
        stamp += params.target_block_time;
        assert!(stamp < NOW, "still in the past, so no drift rule applies");
        let height = chain.state().next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), attacker.public_key())],
        );
        let block = assemble_block(chain.state(), coinbase, Vec::new(), &params, stamp, 0).unwrap();
        assert_eq!(
            block.header.difficulty, MIN_DIFFICULTY,
            "and it never rises: the run was handed over on the floor"
        );
        assert!(
            matches!(chain.add_block(block, NOW), Ok(Accepted::Extended)),
            "every one of the thousand is taken"
        );
    }

    assert_eq!(chain.height(), Some(tip_height));
    assert_eq!(
        chain.total_work(),
        u128::from(tip_height) + 1,
        "a thousand and twenty-four blocks of burial, and the whole chain is \
         worth one hash per block, which is also what it is worth to anybody \
         choosing between chains"
    );

    a_floor_run_cannot_be_claimed_off_a_busier_window(&handover);
}

/// The half that used to be free. The same run, offered under a window whose
/// blocks came fast, is refused: that window demands more than the floor, and
/// the sender does not get to say otherwise.
fn a_floor_run_cannot_be_claimed_off_a_busier_window(handover: &Handover) {
    let mut claimed = handover.clone();
    for (step, header) in claimed.recent.iter_mut().enumerate() {
        header.timestamp = 1_000 + step as u64;
    }
    let refused = accept(&claimed, &params());
    assert!(
        refused.is_err(),
        "a floor run cannot be claimed off a window that demands more, and \
         accept said {refused:?}"
    );
}

/// A handover from an honest chain mined to `tip`, anchored at `anchor`.
fn a_handover_at(anchor: u64, tip: u64) -> Handover {
    let params = params();
    let supplier = wallet(9);
    let mut state = LedgerState::archiving();
    let mut headers: Vec<BlockHeader> = Vec::new();
    let mut history = Archive::new();
    let mut clock = 1_000u64;
    let mut anchor_state: Option<LedgerState> = None;

    for height in 0..=tip {
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, supplier.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        history.add(header_leaf(&block.header.id())).unwrap();
        headers.push(block.header);
        if height == anchor {
            anchor_state = Some(state.clone());
        }
    }
    let anchor_state = anchor_state.unwrap();
    let from = anchor + 1 - RECENT_HEADERS as u64;
    Handover {
        at: headers[anchor as usize],
        tip: headers[tip as usize],
        tip_history: state.headers_before_tip(),
        anchor: history.prove_in(anchor, tip).unwrap(),
        hot: anchor_state.hot_notes().collect(),
        cold: anchor_state.cold_roots(),
        grace: anchor_state.grace_window(),
        grace_proofs: anchor_state
            .grace_window()
            .iter()
            .flatten()
            .filter_map(|(_, position, _)| {
                Some((*position, anchor_state.cold().proof_of(*position)?))
            })
            .collect(),
        headers: anchor_state.headers_before_tip(),
        buried: headers[(anchor as usize + 1)..=tip as usize].to_vec(),
        recent: headers[from as usize..=anchor as usize].to_vec(),
    }
}

/// **A node killed between adopting and catching up came back as an ordinary
/// node on a chain, with nothing recording what it was promised.**
///
/// This is the disk a node has the instant the ledger lands: the handover
/// written down by `keep_ledger`, and not one block above it. `read_handed_ledger`
/// re-runs the whole of `accept` on those bytes, which is right as far as it
/// goes, but `accept` is exactly the check that does not look at the burial.
///
/// So the node started at the anchor, reported a height, reported `Joined::No`
/// (which the type documents as "this node has a chain"), and reported a
/// `Restored` saying nothing had been set aside. The thousand and twenty-four
/// blocks it had undertaken to validate for itself, and the tip it was told
/// they lead to, were in memory only: `Progress` does not survive the process,
/// and the chooser was finished the moment the chain was not empty. Nobody was
/// ever going to be asked for them.
///
/// The undertaking is now read back off the same file the ledger comes from,
/// which is where it always was: `Handover` carries both heights, and that
/// file is only replaced once this node can write a ledger of its own, which
/// is once it has validated the whole stretch. So the promise survives the
/// restart because it never depended on the process at all.
#[test]
fn a_join_interrupted_before_the_burial_comes_back_still_owing_it() {
    use cairn_net::joining::Joined;
    use cairn_net::node::Node;
    use cairn_primitives::codec::Encode;
    use std::net::{Ipv4Addr, SocketAddr};

    let params = params();
    let anchor_height = RECENT_HEADERS as u64 + 4;
    let tip_height = anchor_height + BURIAL;
    let handover = a_handover_at(anchor_height, tip_height);
    let at = handover.at;

    // The disk of a node that adopted and was then killed: the ledger it was
    // handed, and no blocks over it.
    let directory = std::env::temp_dir().join(format!("cairn-audit-cut-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join(cairn_store::HANDED_LEDGER),
        handover.encode(),
    )
    .unwrap();

    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (node, restored) = Node::open(params, address, &directory).unwrap();

    assert_eq!(
        node.height(),
        Some(anchor_height),
        "it comes straight back onto the anchor"
    );
    assert_eq!(
        node.total_work(),
        at.total_work,
        "and carries the work the anchor's own header claimed"
    );
    assert_eq!(
        restored.blocks, 0,
        "not one block of the burial was ever validated"
    );
    assert!(
        !restored.rejoining,
        "and nothing was set aside, which is true and not a fault"
    );

    let probation = node
        .probation()
        .expect("the promise the anchor was taken on outlives the process that made it");
    assert_eq!(probation.anchor, anchor_height);
    assert_eq!(
        probation.settles_at, tip_height,
        "including the height it has to validate its way to"
    );
    assert_eq!(probation.checked(), 0, "none of which it has checked");
    assert_eq!(probation.owed(), BURIAL);
    assert_ne!(
        node.joining(),
        Joined::No,
        "so it does not come back reporting itself as a node that was never \
         joining anything"
    );
    assert!(node.outdated().is_none(), "nothing else is wrong with it");
    assert!(
        node.stranded().is_none(),
        "and it has not been given the chance to get the blocks yet"
    );

    node.shutdown();
    drop(node);
    let _ = std::fs::remove_dir_all(&directory);
}

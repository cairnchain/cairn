//! A version this build knows and the rules at this height do not allow.
//!
//! One half of the version machinery was closed first: a version this build
//! has never heard of, which it cannot judge and must not blame anybody for.
//! This is the other half, and it needs the opposite answer at every turn.
//!
//! A block carries exactly the version its height demands. Where this build
//! knows both numbers it can say the block is wrong rather than that it cannot
//! tell, and saying "cannot tell" instead was wrong twice over: a chain from
//! the abandoned side of a rule change came in through the door meant for
//! blocks nobody can judge yet, and a stranger could make any node report
//! itself out of date by writing a number in a field.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use cairn_accumulator::Archive;
use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::Note;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::Message;
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::Keeps;

const NOW: u64 = 2_000_000_000;
const BURIAL: u64 = 8;
const HOT: usize = 8;
const MATURITY: u64 = 4;

/// The rules the network actually runs: version one from height zero, which is
/// what `ConsensusParams::testnet()` ships.
fn honest() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(HOT)
        .with_burial(BURIAL)
        .with_coinbase_maturity(MATURITY)
}

/// A *different* rule set, standing in for "the other side of a rule change".
///
/// Everything about it is identical to `honest()` except the version its
/// blocks carry, which is the one field a scheduled rule change moves. A
/// node running `honest()` must never stand behind a chain built under this
/// one, exactly as an updated node must never stand behind the pre-fork
/// chain.
const OTHER_RULES: &[Activation] = &[Activation {
    height: 0,
    version: BLOCK_VERSION - 1,
}];

fn wrong_side() -> ConsensusParams {
    ConsensusParams {
        activations: OTHER_RULES,
        ..honest()
    }
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

struct Miner {
    params: ConsensusParams,
    state: LedgerState,
    past: Vec<LedgerState>,
    blocks: Vec<Block>,
    history: Archive,
    headers: Vec<BlockHeader>,
    clock: u64,
}

impl Miner {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
            history: Archive::new(),
            headers: Vec::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
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
        let block = mine_block(block, 1 << 22).unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        self.past.push(self.state.clone());
        self.blocks.push(block.clone());
        self.history
            .add(cairn_ledger::state::header_leaf(&block.header.id()))
            .unwrap();
        self.headers.push(block.header);
        block
    }

    fn mine_many(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner);
        }
    }

    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let tip_history = self.state.headers_before_tip();
        let anchor = self.history.prove_in(anchor_height, tip.height).unwrap();
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
            .unwrap()
    }
}

/// **A ledger built under rules this node does not run is refused.**
///
/// `handover::accept` and `ChainStore::adopt` used to check only that the
/// version was not ABOVE what this build knows. Neither asked whether it was
/// the version the rules at that height demand, so a node running one rule set
/// adopted, whole and without a word, a ledger built under another. Mapped
/// onto a real activation: an updated node handed the abandoned pre-fork chain
/// took it, reported itself up to date, and answered balances out of it.
///
/// Both doors are checked, because a ledger comes through either one.
#[test]
fn a_ledger_built_under_rules_this_node_does_not_run_is_refused() {
    let miner = wallet(1);
    let mut wrong = Miner::new(wrong_side());
    wrong.mine_many(&miner, RECENT_HEADERS + 40);

    let handover = wrong.handover();
    let rules = honest();

    // The node's own rules say every height needs this version.
    assert_eq!(rules.version_at(handover.tip.height), BLOCK_VERSION);
    // The ledger it is being handed carries a different one, at every height.
    assert_eq!(handover.tip.version, BLOCK_VERSION - 1);
    assert_eq!(handover.at.version, BLOCK_VERSION - 1);

    let refused = accept(&handover, &rules);
    assert!(
        matches!(
            refused,
            Err(cairn_ledger::handover::HandoverError::WrongVersion { .. })
        ),
        "a ledger whose headers break this node's version rule was taken: {refused:?}"
    );

    // And the same at the other door, for a ledger obtained any other way. The
    // state itself is built under the rules that made it, so this is the check
    // standing on its own rather than leaning on the one above.
    let state = accept(&handover, &wrong_side()).expect("its own rules take it");
    let mut chain = ChainStore::new(rules);
    let refused = chain.adopt(state, &handover.recent);
    assert!(
        matches!(
            refused,
            Err(cairn_chain::ChainError::InvalidBlock {
                source: cairn_ledger::validation::BlockError::UnsupportedVersion(_),
                ..
            })
        ),
        "adopt took it: {refused:?}"
    );
    assert_eq!(chain.height(), None, "and nothing was left behind");
}

/// **A version below the rules is the sender's problem, not this build's.**
///
/// It used to come back as `UnsupportedVersion`, which means: the peer is not
/// blamed, the verdict is not remembered, and the block is counted as evidence
/// that THIS BUILD is too old for the chain. That is the opposite conclusion.
/// A version below the required one, where this build knows both numbers, is
/// evidence the sender is behind or lying.
///
/// It was reachable at the cost of one hash: the work check reads the
/// difficulty the block claims, and the version check sits above the check
/// that catches a lie about it. So a stranger on a chain at the difficulty
/// floor could make any node say it was out of date.
///
/// The peer is still not refused. On the day a rule changes, every node that
/// has not updated sends these in good faith.
#[test]
fn a_version_below_the_rules_is_the_senders_problem_and_is_not_counted() {
    let rules = ConsensusParams::testnet();
    let miner = wallet(2);

    let mut chain = ChainStore::new(rules);
    let mut state = LedgerState::archiving();
    let mut clock = 1_000u64;
    for _ in 0..5 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(rules.initial_reward, miner.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &rules, clock, 0).unwrap();
        let block = mine_block(block, 1 << 22).unwrap();
        connect_block(&mut state, &block, &rules, NOW).unwrap();
        chain.add_block(block, NOW).unwrap();
    }

    // The next block, made to carry a version the rules do not allow at that
    // height and that this build knows perfectly well.
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(rules.initial_reward, miner.public_key())],
    );
    let mut under = assemble_block(&state, coinbase, Vec::new(), &rules, clock + 600, 0).unwrap();
    under.header.version = BLOCK_VERSION - 1;
    let under = mine_block(under, 1 << 22).unwrap();

    let mut peer = PeerState {
        greeted: true,
        height: 1_000,
        total_work: 1,
        ..PeerState::default()
    };
    let reaction = on_message(
        &mut Local {
            keeps: Keeps {
                headers: true,
                cold_set: false,
            },
            nonce: 1,
            chain: &mut chain,
            listen: 4242,
        },
        &mut peer,
        Message::Block(Box::new(under)),
        NOW,
    );

    assert_eq!(
        reaction.unjudged, None,
        "a number in a field must not be able to make this node report itself \
         out of date"
    );
    let dropped = reaction
        .drop_peer
        .expect("a peer on the other side of a rule change is not a peer to sync with");
    assert!(
        matches!(dropped, cairn_net::sync::DropReason::ForeignRules { .. }),
        "it is somewhere else, not misbehaving: {dropped:?}"
    );
    assert!(
        !dropped.is_misbehaviour(),
        "and refusing the host would turn the first minutes of a fork into an \
         updated node banning most of the network"
    );
}

//! Adversarial pass over the rule change machinery.
//!
//! `tests/activation.rs` checks the machinery from the inside: a node that has
//! been told a change is coming, meeting a height it has no rules for, says so
//! and stops. This file asks the questions from the outside. Who has that
//! schedule, what does a node without it do, and what does a version number
//! buy that a height did not already buy.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::block::{Activation, Block, BLOCK_VERSION};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, BlockError, ConsensusParams,
};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const SPACING: u64 = 600;
const ATTEMPTS: u64 = 1 << 22;

/// The schedule the *new* release ships: a change at height five.
const ANNOUNCED: &[Activation] = &[
    Activation {
        height: 0,
        version: BLOCK_VERSION,
    },
    Activation {
        height: 5,
        version: BLOCK_VERSION + 1,
    },
];

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn mine(state: &mut LedgerState, params: &ConsensusParams, miner: &SecretKey) -> Block {
    let block = candidate(state, params, miner, None);
    connect_block(state, &block, params, NOW).expect("it holds");
    block
}

/// A block built by the rules in `params`, then made to carry `version` if one
/// is named, and mined again because the version is inside the identifier.
fn candidate(
    state: &LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    version: Option<u16>,
) -> Block {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let mut block = assemble_block(
        state,
        coinbase,
        Vec::new(),
        params,
        1_000 + height * SPACING,
        0,
    )
    .expect("this build can judge the height it is building at");
    if let Some(version) = version {
        block.header.version = version;
    }
    mine_block(block, ATTEMPTS).expect("a nonce exists at this difficulty")
}

/// The whole safety of a scheduled change rests on who holds the schedule, and
/// the answer is: only the release that also implements it.
///
/// `activations` is a `&'static [Activation]` inside `ConsensusParams`. A node
/// running the release before the change has the one-entry list from
/// `ConsensusParams::testnet`, so `version_at` answers `BLOCK_VERSION` at every
/// height, including heights past the change. It therefore never reaches
/// `SoftwareTooOld`. It reaches the line below it, which compares the version
/// the block carries against the version it thinks the height demands, and
/// calls the block unsupported.
///
/// That is the opposite of what the machinery exists to do. `SoftwareTooOld`
/// is carried out to `Outdated`, told apart from every other refusal, and the
/// node stops on it without blaming the peer. `UnsupportedVersion` is an
/// ordinary bad block: `cairn-chain` remembers it against the identifier for
/// as long as the process lives, and `cairn-net` closes the connection with
/// `DropReason::BadBlock`, which `is_misbehaviour` reports as true, so the
/// peer is refused for a while as well.
#[test]
fn a_build_without_the_schedule_calls_the_new_chain_a_bad_block() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();

    let mut state = LedgerState::archiving();
    for _ in 0..5 {
        mine(&mut state, &plain, &miner);
    }
    assert_eq!(state.next_height().unwrap(), 5);

    // What the updated majority mines at height five: the version its schedule
    // demands there.
    let after_the_change = candidate(&state, &plain, &miner, Some(BLOCK_VERSION + 1));
    assert_eq!(after_the_change.header.version, BLOCK_VERSION + 1);

    // A node running the release *before* the change. Its schedule is the
    // default one, with nothing scheduled.
    let refused = connect_block(&mut state, &after_the_change, &plain, NOW).unwrap_err();

    assert_eq!(
        refused,
        BlockError::UnsupportedVersion(BLOCK_VERSION + 1),
        "the node blames the block, and the whole point of the machinery was \
         that it blame itself"
    );
    assert!(
        !matches!(refused, BlockError::SoftwareTooOld { .. }),
        "and it never reaches the refusal that would have made it stop"
    );

    // The same node, had it been given the schedule one release earlier, says
    // the opposite thing about the very same block.
    let announced = ConsensusParams {
        activations: ANNOUNCED,
        ..plain
    };
    assert_eq!(
        connect_block(&mut state, &after_the_change, &announced, NOW).unwrap_err(),
        BlockError::SoftwareTooOld {
            height: 5,
            required: BLOCK_VERSION + 1,
            known: BLOCK_VERSION,
        },
        "so the verdict on one block turns on whether a release nobody has \
         written yet was announced a release early"
    );
}

/// The other direction, which is the one that splits a chain quietly.
///
/// A block carrying the *old* version at a height the change governs is
/// refused by every updated node and accepted by every node that never got the
/// schedule. So the two populations do not merely fail to agree on the new
/// chain: they each follow a chain of their own, and the old one is never told.
#[test]
fn an_old_version_past_the_change_is_accepted_by_exactly_the_nodes_that_are_wrong() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();
    let announced = ConsensusParams {
        activations: ANNOUNCED,
        ..plain
    };

    let mut behind = LedgerState::archiving();
    for _ in 0..5 {
        mine(&mut behind, &plain, &miner);
    }
    let mut ahead = LedgerState::archiving();
    for _ in 0..5 {
        mine(&mut ahead, &plain, &miner);
    }

    // A miner still on the old release keeps mining the old version past the
    // height. Nothing stops it: its own build sees no change there.
    let stale = candidate(&behind, &plain, &miner, None);
    assert_eq!(stale.header.version, BLOCK_VERSION);

    connect_block(&mut behind, &stale, &plain, NOW)
        .expect("a node without the schedule takes it and follows on");

    // A node that has the schedule refuses the very same block. It is not
    // outdated, it is up to date, and the block is genuinely wrong for the
    // height.
    let refused = connect_block(&mut ahead, &stale, &announced, NOW).unwrap_err();
    assert_eq!(
        refused,
        BlockError::SoftwareTooOld {
            height: 5,
            required: BLOCK_VERSION + 1,
            known: BLOCK_VERSION,
        }
    );

    // The two ledgers have parted at height five, and the one in the wrong is
    // the one that noticed nothing.
    assert_ne!(
        behind.tip().map(|tip| tip.id),
        ahead.tip().map(|tip| tip.id)
    );
}

/// A version number never decides anything by itself.
///
/// `version_at` has two readers in the whole workspace, and both of them only
/// fill in or check the header's `version` field. No rule anywhere is written
/// against a version or against a height. So the sentence "blocks before that
/// height go on being judged by the rule that judged them" is a promise made
/// by whoever writes the next rule change, not a property this code has: an
/// updated build applies today's rules at every height unless the author
/// remembers to write the height test by hand.
#[test]
fn what_a_scheduled_change_actually_changes_is_one_field() {
    let plain = ConsensusParams::testnet();
    let quiet = ConsensusParams {
        // A change scheduled at height three, under a version this build has.
        activations: &[
            Activation {
                height: 0,
                version: BLOCK_VERSION,
            },
            Activation {
                height: 3,
                version: BLOCK_VERSION,
            },
        ],
        ..plain
    };

    let miner = wallet(1);
    let mut with = LedgerState::archiving();
    let mut without = LedgerState::archiving();
    for _ in 0..6 {
        let block = mine(&mut with, &quiet, &miner);
        connect_block(&mut without, &block, &plain, NOW)
            .expect("the schedule changed nothing a node can see");
    }
    assert_eq!(
        with.state_root(),
        without.state_root(),
        "an activation whose version this build already knows is a no-op, \
         because a version gates nothing"
    );
}

/// The schedule is read newest first and never checked, so the order it is
/// written in is consensus.
///
/// The field is documented "oldest first" and nothing enforces it. Two builds
/// with the same set of changes, one of them written out of order, answer
/// differently about which rules govern a height, and neither notices. The
/// mistake this invites is the ordinary one: appending a change and getting
/// its height wrong, or listing changes newest first the way changelogs are.
#[test]
fn a_schedule_written_out_of_order_answers_wrongly_and_says_nothing() {
    let plain = ConsensusParams::testnet();

    let ordered = ConsensusParams {
        activations: &[
            Activation {
                height: 0,
                version: BLOCK_VERSION,
            },
            Activation {
                height: 50,
                version: BLOCK_VERSION + 1,
            },
            Activation {
                height: 100,
                version: BLOCK_VERSION + 2,
            },
        ],
        ..plain
    };
    let shuffled = ConsensusParams {
        activations: &[
            Activation {
                height: 0,
                version: BLOCK_VERSION,
            },
            Activation {
                height: 100,
                version: BLOCK_VERSION + 2,
            },
            Activation {
                height: 50,
                version: BLOCK_VERSION + 1,
            },
        ],
        ..plain
    };

    assert_eq!(ordered.version_at(150), BLOCK_VERSION + 2);
    assert_eq!(
        shuffled.version_at(150),
        BLOCK_VERSION + 1,
        "the same three changes, written in a different order, put height 150 \
         under different rules"
    );
    assert_ne!(ordered.version_at(150), shuffled.version_at(150));
}

/// The fallback in `version_at` makes the rules of early heights depend on the
/// software rather than on the network.
///
/// `map_or(BLOCK_VERSION, ...)` answers with whatever the *reading build's*
/// highest version happens to be when no activation sits at or below the
/// height. A schedule whose first entry is not height zero therefore demands a
/// different version of the chain's opening blocks from one release to the
/// next, and the difference invalidates history rather than the future.
/// `testnet()` opens at height zero so nothing hits this today; it is a
/// trapdoor under whoever writes the next schedule.
#[test]
fn a_schedule_that_does_not_start_at_zero_asks_the_binary_what_genesis_needs() {
    let plain = ConsensusParams::testnet();
    let gapped = ConsensusParams {
        activations: &[Activation {
            height: 5,
            version: BLOCK_VERSION,
        }],
        ..plain
    };
    // Today this reads as harmless, because the fallback and the network's
    // opening version are the same number. They are the same number only
    // until this build's `BLOCK_VERSION` moves.
    assert_eq!(gapped.version_at(0), BLOCK_VERSION);
    assert_eq!(
        gapped.version_at(0),
        gapped.version_at(5),
        "heights below the first entry answer with the build's own ceiling, \
         so a release that raises BLOCK_VERSION silently re-judges every \
         block below it"
    );
}

/// Nothing a stranger sends can make a node call itself outdated.
///
/// `SoftwareTooOld` is decided by `params.version_at(state.next_height())`:
/// the node's own schedule, at the node's own tip. The block is not consulted.
/// So the flag cannot be raised from outside, which is the property that keeps
/// it from being a free way to stop any node.
#[test]
fn being_outdated_is_decided_by_where_this_node_stands_and_by_nothing_sent_to_it() {
    let miner = wallet(1);
    let plain = ConsensusParams::testnet();
    let announced = ConsensusParams {
        activations: ANNOUNCED,
        ..plain
    };

    let mut state = LedgerState::archiving();
    for _ in 0..4 {
        mine(&mut state, &announced, &miner);
    }
    assert_eq!(state.next_height().unwrap(), 4);

    // Every shape of nonsense, offered one below the change. None of them is
    // answered with the refusal that stops the node.
    let good = candidate(&state, &announced, &miner, None);
    let mut lying_height = good.clone();
    lying_height.header.height = 5;
    let mut lying_version = good.clone();
    lying_version.header.version = BLOCK_VERSION + 9;
    let mut lying_parent = good.clone();
    lying_parent.header.previous = cairn_primitives::Hash32::ZERO;

    for block in [&lying_height, &lying_version, &lying_parent] {
        let refused = connect_block(&mut state.clone(), block, &announced, NOW).unwrap_err();
        assert!(
            !matches!(refused, BlockError::SoftwareTooOld { .. }),
            "a peer talked this node into saying it was too old: {refused:?}"
        );
    }

    // And one block later, standing at the change, the node says it whatever
    // it is shown, including the good block above.
    connect_block(&mut state, &good, &announced, NOW).unwrap();
    assert_eq!(state.next_height().unwrap(), 5);
    for block in [&good, &lying_height, &lying_version, &lying_parent] {
        assert!(
            matches!(
                connect_block(&mut state.clone(), block, &announced, NOW),
                Err(BlockError::SoftwareTooOld { .. })
            ),
            "at the change the node judges nothing, which is the point"
        );
    }
}

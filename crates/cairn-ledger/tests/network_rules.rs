//! What every named network has to hold, whatever else it changes.
//!
//! Devnet exists to move fast, so it lowers numbers the public networks do
//! not. What it must not lower is a number the design states a relation
//! between: a reward spendable before its block settles is money that can be
//! taken back from someone who followed the rules.
//!
//! The relation is a floor and not a ceiling, and this file asserted the
//! ceiling for a while: a maturity of nought under a burial of a thousand
//! passed, while the message it would have printed described exactly that as
//! the failure. Both shipped networks set the two equal, so nothing caught it
//! from the outside.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cairn_ledger::validation::ConsensusParams;

/// Every name [`ConsensusParams::for_network`] answers to.
const NAMED: [&str; 4] = ["mainnet", "testnet", "testnet-6", "devnet"];

/// The names that answer today, so a rename cannot quietly empty the checks
/// below. A test that skips every case passes.
#[test]
fn the_networks_that_exist_are_the_ones_these_checks_cover() {
    let answering: Vec<&str> = NAMED
        .into_iter()
        .filter(|name| ConsensusParams::for_network(name).is_some())
        .collect();
    assert_eq!(
        answering,
        vec!["testnet", "testnet-6", "devnet"],
        "mainnet is not a network until its first block is mined, and the rest \
         are what the checks below are actually reading"
    );
}

/// Whether a rule set waits at least as long to pay out as it waits to call a
/// block settled.
///
/// One definition, applied to the networks that exist and to a rule set built
/// to break it. The check used to be written inline over the shipped networks
/// only, and both of those set the two numbers equal, so it read the same
/// whichever way round the comparison went: a maturity of nought under a
/// burial of a thousand passed, while the message it printed on failure
/// described exactly that as the failure.
fn settles_before_it_pays(params: &ConsensusParams) -> bool {
    params.coinbase_maturity >= params.burial
}

#[test]
fn no_network_lets_a_reward_move_before_its_block_settles() {
    for name in NAMED {
        let Some(params) = ConsensusParams::for_network(name) else {
            continue;
        };
        assert!(
            settles_before_it_pays(&params),
            "{name} pays out {} blocks before it calls {} settled",
            params.burial.saturating_sub(params.coinbase_maturity),
            params.burial
        );
    }
}

/// The same question asked of rules that are free to get it wrong, which is
/// what the shipped networks cannot do.
#[test]
fn the_relation_is_a_floor_and_not_a_ceiling() {
    // A reward spendable at once on a chain that undoes sixty four blocks.
    let broken = ConsensusParams::testnet()
        .with_burial(64)
        .with_coinbase_maturity(0);
    assert!(
        !settles_before_it_pays(&broken),
        "a maturity of nought under a burial of sixty four read as sound, \
         which is money taken back from somebody who followed the rules"
    );

    let equal = ConsensusParams::testnet()
        .with_burial(64)
        .with_coinbase_maturity(64);
    assert!(
        settles_before_it_pays(&equal),
        "what every network here sets"
    );

    // Above is the safe side, which is why there is a floor and no ceiling:
    // the depth a node refuses to undo past is the smaller of its build's
    // window and this network's burial, so a maturity at or above the burial
    // is at or above that depth whichever of the two is smaller.
    let generous = ConsensusParams::testnet()
        .with_burial(64)
        .with_coinbase_maturity(1_024);
    assert!(settles_before_it_pays(&generous));
}

#[test]
fn every_network_answers_to_the_name_it_reports() {
    for name in NAMED {
        let Some(params) = ConsensusParams::for_network(name) else {
            continue;
        };
        let reported = params.network_name();
        assert_eq!(
            ConsensusParams::for_network(reported),
            Some(params),
            "{name} reports itself as {reported}, which builds different rules"
        );
    }
}

/// What each network's eviction cap actually buys, in blocks.
///
/// The cap is written as a hundred and twenty eighth of the default tier, and
/// the sentence beside it says that emptying the tier therefore takes at least
/// that many blocks however the blocks are stuffed. The sentence is about the
/// two numbers together, and devnet moves one of them: it takes the tier down
/// to sixty four and leaves the cap where it was, so the cap is sixteen times
/// the tier and one block empties the whole thing.
///
/// That is the other direction of this file's subject. It is not a rule devnet
/// lowered below a floor; it is a rule devnet left above a ceiling, so the one
/// bound on how fast the hot set turns over is the one bound a throwaway
/// network does not rehearse. There is no number that keeps the relation at
/// that size, which is why the answer is written down rather than asserted
/// equal: a hundred and twenty eighth of sixty four is nought, and a cap of
/// one refuses an ordinary devnet payment.
#[test]
fn the_eviction_cap_buys_a_hundred_and_twenty_eight_blocks_and_on_devnet_one() {
    let blocks_to_empty = |name: &str| {
        let params = ConsensusParams::for_network(name).expect("a network that answers");
        params
            .hot_capacity
            .div_ceil(params.max_evictions_per_block.max(1))
    };
    assert_eq!(
        blocks_to_empty("testnet-6"),
        128,
        "the public tier stopped taking a hundred and twenty eight blocks to empty"
    );
    assert_eq!(
        blocks_to_empty("devnet"),
        1,
        "devnet's cap started binding, which would be an improvement worth \
         reading the comment beside it for"
    );
}

/// The rule set fixtures mine on is a public network's, field by field.
///
/// [`ConsensusParams::mineable_network`] exists because no test can mine
/// testnet-6, which opens at 2^27. What a test can afford is a lower opening
/// difficulty, and for a long time the way to get one was
/// `ConsensusParams::testnet()`, which opens at the floor. A chain on the floor
/// cannot retarget downwards, so every fixture in this workspace validated
/// blocks carrying their parents' difficulty and nothing else, and three
/// defects lived where that blindness reached.
///
/// The danger in answering that with a fourth rule set is that it drifts: a
/// number changes on the public networks, nothing changes here, and the
/// fixtures go on rehearsing a shape no network has. So the comparison is made
/// against `testnet-6` on the whole struct rather than on the fields somebody
/// remembered, with only the four this deliberately moves written out. A field
/// added to `ConsensusParams` is covered the day it is added, without anybody
/// having to come back here.
#[test]
fn the_rules_a_test_can_mine_are_a_public_networks_rules() {
    let public = ConsensusParams::for_network("testnet-6").expect("a network that answers");
    let mineable = ConsensusParams::mineable_network(public.burial);

    // The four. A test mines its own first block, so nothing is pinned and
    // there is no opening moment to sit after; and it opens at a difficulty a
    // machine can solve in about a millisecond rather than in an afternoon.
    let expected = ConsensusParams {
        network: mineable.network,
        genesis: mineable.genesis,
        opens_at: mineable.opens_at,
        genesis_difficulty: mineable.genesis_difficulty,
        ..public
    };
    assert_eq!(
        mineable, expected,
        "the rules fixtures mine on differ from testnet-6 in something other \
         than the network it is not and the difficulty it could not afford"
    );
    assert!(
        mineable.genesis_difficulty > cairn_ledger::pow::MIN_DIFFICULTY,
        "an opening on the floor is the blindness this exists to remove: the \
         retarget can only ever want to lower it, and lowering is refused"
    );

    // And the pairing the fixtures were missing even where they raised the
    // difficulty. `with_burial(8)` leaves the maturity at a thousand and
    // twenty four, which no network ships.
    for burial in [8u64, 32, 80, 1_024] {
        let shaped = ConsensusParams::mineable_network(burial);
        assert_eq!(
            shaped.coinbase_maturity, shaped.burial,
            "a network sets the two equal, and a fixture that does not is \
             testing a network nobody runs"
        );
        assert!(settles_before_it_pays(&shaped));
    }
}

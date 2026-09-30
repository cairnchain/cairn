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
const NAMED: [&str; 4] = ["mainnet", "testnet", "testnet-7", "devnet"];

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
        vec!["testnet", "testnet-7", "devnet"],
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
/// to sixty four, and it used to leave the cap where it was, sixteen times the
/// tier, so one block emptied the whole thing and the one bound on how fast
/// the hot set turns over was the one bound a throwaway network did not
/// rehearse. It takes the cap down to thirty two with the tier now, which is
/// as low as it goes while a block still has room for payments beside a full
/// coinbase: see the next test.
#[test]
fn the_eviction_cap_buys_a_hundred_and_twenty_eight_blocks_and_on_devnet_two() {
    let blocks_to_empty = |name: &str| {
        let params = ConsensusParams::for_network(name).expect("a network that answers");
        params
            .hot_capacity
            .div_ceil(params.max_evictions_per_block.max(1))
    };
    assert_eq!(
        blocks_to_empty("testnet-7"),
        128,
        "the public tier stopped taking a hundred and twenty eight blocks to empty"
    );
    assert_eq!(
        blocks_to_empty("devnet"),
        2,
        "devnet's cap moved, which is worth reading the comment where devnet \
         is built for"
    );
}

/// Every network's eviction cap is below its tier and above its coinbase.
///
/// Below the tier, or one block empties it: devnet inherited the public cap
/// of a thousand and twenty four over a tier of sixty four, and nothing here
/// asked. Above the coinbase, because a miner's `selection` keeps room for a
/// full coinbase out of the cap: a cap no larger than that leaves a full tier
/// carrying no payment at all, which is the other way a small network can get
/// this wrong.
#[test]
fn every_networks_eviction_cap_is_below_its_tier_and_above_its_coinbase() {
    for name in NAMED {
        let Some(params) = ConsensusParams::for_network(name) else {
            continue;
        };
        assert!(
            params.max_evictions_per_block < params.hot_capacity,
            "{name} lets one block push out {} notes from a tier of {}, so a \
             single block empties it",
            params.max_evictions_per_block,
            params.hot_capacity
        );
        assert!(
            params.max_evictions_per_block > params.max_coinbase_outputs,
            "{name} caps a block at {} evictions and keeps {} for its coinbase, \
             so a full tier carries no payment",
            params.max_evictions_per_block,
            params.max_coinbase_outputs
        );
    }
}

/// Every named network's widest transfer fits what a block has for transfers
/// once the tier is full, or the network is named here as one where the
/// pool's refusal is what keeps such a transfer out.
///
/// A transfer may make `max_outputs_per_transfer` notes and free none, and a
/// full tier leaves a block its eviction cap less its coinbase. On devnet that
/// is two hundred and fifty six against sixteen, and the pool took a transfer
/// no block could carry while the tier stayed full, and held it, ranked on a
/// fee it never paid. The pool refuses one now as `TooManyPlacesForABlock`,
/// held in `cairn-chain/tests/pool.rs`. Nothing compared the two numbers, so
/// devnet's cap moved to thirty two and nobody asked what it left a transfer;
/// the next network whose numbers leave that gap has to be named here.
#[test]
fn every_networks_widest_transfer_fits_a_full_tiers_block_or_is_named_as_refused() {
    const REFUSED_BY_THE_POOL: [&str; 1] = ["devnet"];
    for name in NAMED {
        let Some(params) = ConsensusParams::for_network(name) else {
            continue;
        };
        let left = params
            .max_evictions_per_block
            .saturating_sub(params.max_coinbase_outputs);
        assert_eq!(
            params.max_outputs_per_transfer <= left,
            !REFUSED_BY_THE_POOL.contains(&name),
            "{name}: a transfer may take {} places and a full tier leaves a block {left} for \
             transfers, and whether the two fit is not what this list says",
            params.max_outputs_per_transfer
        );
    }
}

/// Every named network charges the place price, and so do the rules fixtures
/// mine on; only the bare test rules charge nothing.
///
/// The price is what makes a place cost a miner what it costs anyone, and a
/// network that left it at nought would be one where a miner flushes the hot
/// set for free, which is what it exists to end. `testnet()` carries nought
/// for the reason it carries the floor difficulty: it is what most tests
/// build on, and they are not about fees.
#[test]
fn every_network_charges_the_place_price_and_only_the_test_rules_do_not() {
    use cairn_ledger::validation::PLACE_PRICE;
    use cairn_primitives::Amount;

    assert!(PLACE_PRICE > Amount::ZERO, "a price of nought is no price");
    for name in NAMED {
        let Some(params) = ConsensusParams::for_network(name) else {
            continue;
        };
        assert_eq!(
            params.place_price, PLACE_PRICE,
            "{name} does not charge the place price"
        );
    }
    assert_eq!(
        ConsensusParams::mineable_network(32).place_price,
        PLACE_PRICE,
        "the rules fixtures mine on charge nothing for a place, so no fixture \
         rehearses what a public network asks"
    );
    assert_eq!(ConsensusParams::testnet().place_price, Amount::ZERO);
}

/// The rule set fixtures mine on is a public network's, field by field.
///
/// [`ConsensusParams::mineable_network`] exists because no test can mine
/// testnet-7, which opens at 2^27. What a test can afford is a lower opening
/// difficulty, and for a long time the way to get one was
/// `ConsensusParams::testnet()`, which opens at the floor. A chain on the floor
/// cannot retarget downwards, so every fixture in this workspace validated
/// blocks carrying their parents' difficulty and nothing else, and three
/// defects lived where that blindness reached.
///
/// The danger in answering that with a fourth rule set is that it drifts: a
/// number changes on the public networks, nothing changes here, and the
/// fixtures go on rehearsing a shape no network has. So the comparison is made
/// against `testnet-7` on the whole struct rather than on the fields somebody
/// remembered, with only the four this deliberately moves written out. A field
/// added to `ConsensusParams` is covered the day it is added, without anybody
/// having to come back here.
#[test]
fn the_rules_a_test_can_mine_are_a_public_networks_rules() {
    let public = ConsensusParams::for_network("testnet-7").expect("a network that answers");
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
        "the rules fixtures mine on differ from testnet-7 in something other \
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

/// Every network this build knows answers to a name, retired ones included.
///
/// `every_network_answers_to_the_name_it_reports` covers the two that are
/// still live, because `for_network` is where it starts and only live networks
/// have rules. The retired ones are the reason the table exists: a node on an
/// old build meets `testnet-5` on the wire and nowhere else, and every one of
/// those constants says a node left behind "is then told plainly that it is on
/// another network, rather than failing somewhere confusing".
///
/// What it was told was a thirty two bit marker. Three errors print a network
/// at somebody — a frame from the wrong one, a peer following another, a block
/// belonging elsewhere — and all three printed `{:#010x}` or the derived
/// `Debug`, so the operator read `0x43415258` and had nothing to look up. The
/// five constants that carry the translation were read by nothing at all.
#[test]
fn a_retired_network_is_named_and_not_written_out_in_hexadecimal() {
    use cairn_ledger::note::NetworkId;

    for (id, expected) in [
        (NetworkId::MAINNET, "mainnet"),
        (NetworkId::TESTNET_1, "testnet-1"),
        (NetworkId::TESTNET_2, "testnet-2"),
        (NetworkId::TESTNET_3, "testnet-3"),
        (NetworkId::TESTNET_4, "testnet-4"),
        (NetworkId::TESTNET_5, "testnet-5"),
        (NetworkId::TESTNET_6, "testnet-6"),
        (NetworkId::TESTNET_7, "testnet-7"),
        (NetworkId::DEVNET_1, "devnet-1"),
        (NetworkId::DEVNET, "devnet"),
    ] {
        assert_eq!(id.name(), Some(expected), "the table is short a network");
        assert_eq!(
            id.to_string(),
            expected,
            "a named network still came out as a number"
        );
    }

    // A marker nobody named comes out as the marker, which is the honest
    // answer rather than a fallback: there is nothing to say about it.
    let stranger = NetworkId::new(0xdead_beef);
    assert_eq!(stranger.name(), None);
    assert_eq!(stranger.to_string(), "0xdeadbeef");

    // And the rules read the same table rather than keeping a second one. It
    // knew two of the eight, so a node on a retired network was told
    // "unnamed" while the constant naming it sat unread two files away.
    let live = ConsensusParams::for_network("testnet-7").unwrap();
    assert_eq!(live.network_name(), NetworkId::TESTNET_7.name().unwrap());
}

/// The next test network was named before it started, and now it has.
///
/// A node reads a marker's name from its own build, so a node that takes no
/// release once the network starts over can name the new one only if a
/// release before the restart already did. Without that, every testnet-6 node
/// still running when testnet-7 starts reads its peers as `0x4341525a`, which
/// is the message the table above exists to replace. The name shipped ahead
/// of the network in 0.9.5; this restart is the release where `for_network`
/// catches up to it.
#[test]
fn the_next_test_network_is_named_before_it_starts() {
    use cairn_ledger::note::NetworkId;

    let next = NetworkId::new(0x4341_525A);
    assert_eq!(next, NetworkId::TESTNET_7);
    assert_eq!(next.name(), Some("testnet-7"));
    assert_eq!(next.to_string(), "testnet-7");
    assert!(
        ConsensusParams::for_network("testnet-7").is_some(),
        "testnet-7 is the network this restart opens"
    );
}

/// The network a rule set names is the network its first block belongs to.
///
/// `for_network` writes the network three times in each arm: once as the
/// `network` field, and twice more as the argument to `genesis::pinned` and
/// `genesis::opens_at`. Nothing held those three together, and the obvious
/// cover does not: `every_network_answers_to_the_name_it_reports` above asks
/// whether the rules and the name they report agree *with each other*, and
/// they would agree just as well if both were wrong, because the name is read
/// off the same field. A true sentence about a round trip, offered as the
/// answer to a question about which network this is.
///
/// What a disagreement costs: every header carries the network it was built
/// under and it is the first thing checked on the way in, so a build that
/// names one network and pins another's first block refuses every honest peer
/// and has every block it mines refused. Each half looks correct on its own.
///
/// The testnet arm cannot show this today, and that is worth knowing rather
/// than assuming. `NetworkId::TESTNET` is an alias for `TESTNET_7`, so naming
/// `TESTNET_7` there writes a value the spread rule set already carried:
/// deleting the line is an equivalent mutation, and it is noted where it sits.
/// The day that alias moves to the next testnet, this test is what says the
/// line has to be there. Measured both ways: with the alias pointed at
/// `TESTNET_6` and the line gone, this fails; with the line back, it passes.
#[test]
fn the_network_a_rule_set_names_is_the_one_its_first_block_belongs_to() {
    for name in NAMED {
        let Some(params) = ConsensusParams::for_network(name) else {
            continue;
        };
        assert_eq!(
            params.genesis,
            cairn_ledger::genesis::pinned(params.network),
            "{name} names {:?} and pins a first block that is not that \
             network's, so every header it builds carries a network its own \
             chain does not start on",
            params.network
        );
        assert_eq!(
            params.opens_at,
            cairn_ledger::genesis::opens_at(params.network),
            "{name} names {:?} and opens at a moment that is not that \
             network's",
            params.network
        );
        assert!(
            params.genesis.is_some(),
            "{name} answers `for_network` and so is a network that exists, \
             which means it has a first block"
        );
    }
}

/// Every network lets a timestamp run ten of its own blocks ahead of a
/// reader's clock, and no further.
///
/// The allowance was two hours on every network, whatever its block time:
/// twenty of the retarget's clamp ceilings on testnet and two hundred and
/// forty on devnet. A minority dating its blocks that far ahead, or an honest
/// miner an hour or two fast, pulled the median past real time and made the
/// retarget read honest blocks as arriving in no time, which
/// `retarget_timewarp.rs` measures. A number written once for every network
/// was the shape of the defect, so the relation is asked of each of them.
#[test]
fn every_network_lets_a_timestamp_run_ten_blocks_ahead_and_no_further() {
    for name in NAMED {
        let Some(params) = ConsensusParams::for_network(name) else {
            continue;
        };
        assert_eq!(
            params.max_timestamp_drift,
            10 * params.target_block_time,
            "{name} lets a timestamp run {} s ahead on a {} s block",
            params.max_timestamp_drift,
            params.target_block_time
        );
    }
    for params in [
        ConsensusParams::testnet(),
        ConsensusParams::mineable_network(8),
    ] {
        assert_eq!(
            params.max_timestamp_drift,
            10 * params.target_block_time,
            "the rules the tests run under let a timestamp run {} s ahead",
            params.max_timestamp_drift
        );
    }
}

/// Every network's ledger fits the handover's decoder.
///
/// A hot set a network's rules allow and the decoder refuses, or a maturity
/// window longer than the decoder reads, is a ledger no node on that network
/// can be handed: every join refuses it as malformed, and says nothing more.
/// The transaction ceilings are held to the rules by the build; these two
/// were held by nothing but the distance between the numbers.
#[test]
fn every_network_can_be_handed_the_ledger_its_rules_allow() {
    use cairn_ledger::handover::{MAX_HOT, MAX_MATURING};

    for name in NAMED {
        let Some(params) = ConsensusParams::for_network(name) else {
            continue;
        };
        assert!(
            params.hot_capacity <= MAX_HOT,
            "{name} allows a hot set the handover's decoder refuses"
        );
        assert!(
            params.coinbase_maturity <= u64::try_from(MAX_MATURING).unwrap(),
            "{name} keeps a maturity window the handover's decoder refuses"
        );
    }
}

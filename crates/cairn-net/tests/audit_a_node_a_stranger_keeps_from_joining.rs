//! Two ways a stranger kept a node from ever reaching the chain, both of them
//! a true sentence standing where an answer was needed.
//!
//! A node with no chain has to pick between what its peers claim, and it holds
//! everybody off while it picks: a block taken from anybody is the beginning
//! of following them. Both halves of that are bounded. A claim that is made
//! and not shown pauses the address that made it, so turns cost addresses; and
//! the list of paused addresses has a ceiling, so a stranger cannot decide how
//! much memory the node spends.
//!
//! The ceiling used to drop the newcomer rather than the oldest entry. The
//! note beside it asks the right question, whether the list grows without
//! bound, and answers it truthfully. What it does not ask is whether a full
//! list still pauses anybody, and it did not: an address nothing writes down
//! is an address nothing pauses.
//!
//! And the mark saying a choice had opened was never cleared. It is read as
//! "a choice is open", and what it holds is "a long claim arrived once".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{IpAddr, Ipv4Addr};

use cairn_net::choosing::{Approach, Chooser, JoinProgress, Step, MAX_UNBACKED_HOSTS};
use cairn_net::sync::JOIN_RATHER_THAN_READ;

const LONG: u64 = JOIN_RATHER_THAN_READ + 10;

/// Past the ceiling, so the list is full and the next address is the one the
/// old rule threw away.
const SPENT: u64 = MAX_UNBACKED_HOSTS as u64 + 64;

fn host(index: u64) -> IpAddr {
    let bytes = index.to_be_bytes();
    IpAddr::V4(Ipv4Addr::new(203, bytes[5], bytes[6], bytes[7]))
}

/// A stranger says it has a long chain and then goes away.
///
/// One connection and one message, and on a network where nobody else has a
/// long chain yet there is never another claim to settle. The mark saying a
/// choice had opened stayed set, and with nobody being asked that holds every
/// peer off: every block, announcement and chain from everybody was dropped,
/// in silence, for the life of the process. Nothing could reopen it, because a
/// claim is taken from the introduction and a second greeting is refused, so
/// the peers already here could never acquire one however much chain they went
/// on to gain.
#[test]
fn a_claim_that_left_does_not_shut_the_door_behind_it() {
    let mut chooser = Chooser::new();
    let start = 100u64;

    // Two honest peers, neither with a chain worth claiming, which is every
    // node on a network in its first hours.
    let honest = vec![1u64, 2];

    chooser.noted(9, Some(host(9)), 1, LONG, true, start);
    assert!(
        chooser.holds_off(1),
        "while a long claim stands there is a choice to make, and holding off is right"
    );

    // The stranger is gone. It is not in `connected`, so nothing it said is
    // left to settle.
    let mut now = start;
    for _ in 0..8 {
        now += 60;
        let _ = chooser.step(now, true, 0, JoinProgress::NothingYet, &honest);
    }

    for peer in &honest {
        assert!(
            !chooser.holds_off(*peer),
            "a stranger sent one message and hung up, and this node is still dropping \
             every block from peer {peer}. There is nothing left to choose between: the \
             mark that a choice opened is being read as a choice that is open"
        );
    }
}

/// And one peer still connected does not hold the door shut either.
///
/// The mark that a choice opened is armed by a claim long enough to be past
/// the reorganisation limit, and it was cleared when the *claims* ran out. A
/// claim is written down for every peer that says it has any work at all, so
/// one peer connected and claiming a single block kept the mark set and the
/// door shut on everybody. That is one connection more than the stranger had
/// to make already, and on a network in its first hours the peers with short
/// chains are all of them.
#[test]
fn one_peer_with_a_short_chain_does_not_hold_the_door_shut() {
    let mut chooser = Chooser::new();
    let start = 100u64;

    // The stranger: a long claim, then gone.
    chooser.noted(9, Some(host(9)), 1, LONG, true, start);

    // An ordinary peer of a young network: a block or two, and it stays.
    let short = 3u64;
    chooser.noted(short, Some(host(short)), 1, 1, true, start);

    let honest = vec![1u64, 2, short];
    let mut now = start;
    for _ in 0..8 {
        now += 60;
        let _ = chooser.step(now, true, 0, JoinProgress::NothingYet, &honest);
    }

    for peer in [1u64, 2] {
        assert!(
            !chooser.holds_off(peer),
            "a stranger sent one message and hung up, and one peer claiming a single block \
             is enough to keep this node dropping every block from peer {peer}. The mark \
             that a choice opened is armed by a long claim and was being cleared on the \
             absence of any claim at all"
        );
    }
}

/// A full list of paused addresses still pauses the address that just failed.
///
/// The list exists so that a peer cannot wash a broken claim clean by
/// reconnecting: a claim that failed is excluded by its own mark for as long
/// as it lasts, and a reconnection makes a new claim with no mark on it. Only
/// the address is remembered, so an address the list had no room for came back
/// as good as new, as often as it liked, for nothing.
#[test]
fn a_full_list_of_paused_addresses_still_pauses_a_new_one() {
    let mut chooser = Chooser::new();
    let mut now = 100u64;

    // An honest peer that claims less than the stranger and can show what it
    // claims. It is here throughout, so every turn the stranger takes is a
    // turn this one waits through.
    let honest = 1u64;
    chooser.noted(honest, Some(host(1)), 500, LONG, true, now);

    // The stranger spends an address a turn until the list is full and past
    // it. That is the price the design means it to pay.
    for index in 0..SPENT {
        let peer = 1_000 + index;
        chooser.noted(peer, Some(host(peer)), 9_000, LONG, true, now);
        now += 1;
        chooser.failed(peer, now);
    }

    // The last of them comes back on the same address under a new connection,
    // which is a claim with nothing held against it. Everything the node knows
    // about that address is in the list.
    let again = host(1_000 + SPENT - 1);
    let returning = 5_000u64;
    chooser.noted(returning, Some(again), 9_000, LONG, true, now);

    let connected = vec![honest, returning];
    let mut asked_the_honest_one = false;
    for _ in 0..8 {
        now += 1;
        if matches!(
            chooser.step(now, true, 0, JoinProgress::NothingYet, &connected),
            Step::Ask(peer, Approach::Join) if peer == honest
        ) {
            asked_the_honest_one = true;
            break;
        }
    }

    assert!(
        asked_the_honest_one,
        "an address whose claim just failed came back and was asked again at once, so the \
         honest peer beside it is never reached. Filling the list is meant to cost an \
         address a turn, and past its ceiling it stopped costing anything: an address \
         nothing writes down is an address nothing pauses"
    );
}

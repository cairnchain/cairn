//! A stranger with more addresses than the chooser remembers, beside a
//! newcomer and one honest peer.
//!
//! Scenario R7 of the testnet-8 attack catalogue, at a supply of addresses
//! past `MAX_UNBACKED_HOSTS`. An address that had failed twice used to wait out
//! a turn for every address on the chooser's list, and the list forgets its
//! oldest entry past that ceiling. An address it forgot had failed no times,
//! so a stranger with one address more than the list holds paid a first
//! failure's thirty seconds for ever, never a round, and was handed every
//! turn: in seven days of a newcomer's clock the honest peer beside it was not
//! asked once.
//!
//! Turns now go round the connections, and what bounds the wait is the peer
//! table: `choosing::ASKED_WITHIN`. Driven on the chooser alone, as
//! `choosing.rs` is pure: one honest peer that could show a lighter chain stays
//! connected throughout, and the stranger holds as many connections as it
//! likes, each from an address nobody has seen, claiming more, saying nothing
//! when asked, hanging up when its window is spent and dialling straight back
//! from its next address.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{IpAddr, Ipv6Addr};

use cairn_net::choosing::{Chooser, JoinProgress, Step, ASKED_WITHIN, MAX_UNBACKED_HOSTS};
use cairn_net::node::MOST_FROM_OUTSIDE;

/// The honest peer's connection number.
const HONEST: u64 = 1;

/// Work the honest peer claims, and the heavier work the stranger claims.
const HONEST_WORK: u128 = 1_000;
const STRANGER_WORK: u128 = 2_000;

/// A chain long enough to be worth settling on every public network.
const LONG: u64 = 2_000;

/// Seconds a stranger's connection stays once asked: its answering window.
/// It hangs up as the window ends and its next address is connected in the
/// same second, before the round that gives up on it hands out the next turn,
/// which is the arrangement that took every turn.
const STAYS: u64 = 30;

/// Seconds the simulation runs: seven days of the newcomer's clock.
const HORIZON: u64 = 7 * 24 * 60 * 60;

/// The stranger's `n`th address, each in a /64 of its own.
fn address(n: u64) -> IpAddr {
    let high = u16::try_from(n >> 16).unwrap();
    let low = u16::try_from(n & 0xffff).unwrap();
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, high, low, 0, 0, 0, 1))
}

fn honest_address() -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1))
}

/// Runs a stranger holding `held` connections at a time, each from the next
/// of `addresses` addresses, reused in turn. The honest peer greets
/// `honest_after` seconds in. Says how long after its greeting the honest peer
/// was first asked to show its chain, and how many turns the stranger had.
fn when_the_honest_peer_is_asked(
    addresses: u64,
    held: usize,
    honest_after: u64,
) -> (Option<u64>, u64) {
    let mut chooser = Chooser::new();
    let start = 1_000_000;
    let mut now = start;
    let mut next_id = 100u64;
    let mut used = 0u64;
    // The stranger's connections: number, and when it was asked if it was.
    let mut holding: Vec<(u64, Option<u64>)> = Vec::new();
    let mut honest_since = None;
    let mut turns = 0;
    while now < start + HORIZON {
        if honest_since.is_none() && now >= start + honest_after {
            chooser.noted(HONEST, Some(honest_address()), HONEST_WORK, LONG, true, now);
            honest_since = Some(now);
        }
        // A connection whose window is spent hangs up, and its place is taken
        // at once from the next address.
        holding.retain(|(_, asked)| asked.is_none_or(|at| now - at < STAYS));
        while holding.len() < held {
            next_id += 1;
            let from = address(used % addresses);
            used += 1;
            chooser.noted(next_id, Some(from), STRANGER_WORK, LONG, true, now);
            holding.push((next_id, None));
        }
        let mut connected: Vec<u64> = holding.iter().map(|(id, _)| *id).collect();
        if honest_since.is_some() {
            connected.push(HONEST);
        }
        match chooser.step(now, true, 0, JoinProgress::NothingYet, &connected) {
            Step::Ask(HONEST, _) => return (honest_since.map(|since| now - since), turns),
            Step::Ask(peer, _) => {
                turns += 1;
                for (id, asked) in &mut holding {
                    if *id == peer {
                        *asked = Some(now);
                    }
                }
            }
            _ => {}
        }
        now += 1;
    }
    (None, turns)
}

/// **However many addresses the stranger holds, the honest peer is asked
/// within the bound the peer table sets.**
///
/// One connection at a time, which is the arrangement that found it, from a
/// supply of addresses well past what the chooser remembers and from one
/// within it, and the sixty two of the measured case.
#[test]
fn a_stranger_s_addresses_do_not_keep_the_honest_peer_from_its_turn() {
    for addresses in [
        62,
        MAX_UNBACKED_HOSTS as u64,
        MAX_UNBACKED_HOSTS as u64 + 1,
        16 * MAX_UNBACKED_HOSTS as u64,
    ] {
        let (asked, turns) = when_the_honest_peer_is_asked(addresses, 1, 0);
        println!("{addresses} addresses: honest peer asked after {asked:?} s, {turns} turns");
        assert!(
            asked.is_some_and(|after| after <= ASKED_WITHIN),
            "with {addresses} addresses the honest peer was asked after {asked:?} s, against \
             a bound of {ASKED_WITHIN} s: {turns} turns went to the stranger"
        );
    }
}

/// **And a stranger holding every connection a node takes from outside,
/// already there when the honest peer arrives, delays it by two rotations at
/// most.**
#[test]
fn a_full_table_of_strangers_delays_the_honest_peer_two_rotations_at_most() {
    let addresses = 16 * MAX_UNBACKED_HOSTS as u64;
    for honest_after in [0, 5, 400] {
        let (asked, turns) =
            when_the_honest_peer_is_asked(addresses, MOST_FROM_OUTSIDE, honest_after);
        println!(
            "{MOST_FROM_OUTSIDE} connections held, honest peer {honest_after} s late: asked \
             after {asked:?} s, {turns} turns"
        );
        assert!(
            asked.is_some_and(|after| after <= ASKED_WITHIN),
            "{MOST_FROM_OUTSIDE} strangers held the honest peer, arriving {honest_after} s in, \
             for {asked:?} s against a bound of {ASKED_WITHIN} s: {turns} turns went to them"
        );
    }
}

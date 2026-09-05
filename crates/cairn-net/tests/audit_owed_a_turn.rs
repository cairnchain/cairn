//! What a stranger holding connections can cost a node that has already
//! proved a chain.
//!
//! Two properties have to hold together, and the repair this file was written
//! against held only the first. A claim that stood there when the proof landed
//! and was never asked must not be shut out by a deadline: shutting it out is
//! how a stranger made a node take the lighter of two chains it could see. And
//! the wait must not grow with the number of connections a stranger holds:
//! when every claim was owed an answering window of its own, forty seven
//! addresses bought forty seven windows one after another.
//!
//! ```text
//! silent heavier claims   owed a window each   sharing one budget
//!                     0                   0s                   0s
//!                     1                  31s                  31s
//!                     2                  61s                  61s
//!                     4                 121s                 121s
//!                     8                 241s                 151s
//!                    16                 481s                 151s
//!                    47                1411s                 151s
//!            47, dribbling             8461s                 181s
//! ```
//!
//! The left column is what a full peer table cost before: twenty three
//! minutes, or two hours and twenty one for a stranger that dribbled rather
//! than going quiet, since a join that is moving is ended by the attempt
//! patience and not by the silence check. The right column is what one shared
//! budget costs, and it stops moving. What is asserted below is the ceiling
//! the module states, [`HELD_OFF_AT_MOST`], which no arrangement of claims may
//! cross.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{IpAddr, Ipv4Addr};

use cairn_net::choosing::{Approach, Chooser, JoinProgress, Step, HELD_OFF_AT_MOST};
use cairn_net::node::MAX_PEERS;
use cairn_net::sync::JOIN_RATHER_THAN_READ;

const LONG: u64 = JOIN_RATHER_THAN_READ + 10;

/// A full peer table of stranger's connections: one node holds this many
/// peers, and every one of them can be a connection claiming a chain it will
/// never show.
const FULL_TABLE: u64 = MAX_PEERS as u64 - 1;

/// Roughly when the shared budget runs out, which is where a stranger wanting
/// the longest wait switches from quick turns to one that never finishes.
const TURNS_ARE_CHEAP_UNTIL: u64 = 120;

fn host(index: u64) -> IpAddr {
    let bytes = index.to_be_bytes();
    IpAddr::V4(Ipv4Addr::new(203, 0, bytes[6], bytes[7]))
}

/// How the stranger's connections behave once they are asked to show a chain.
#[derive(Clone, Copy, Debug)]
enum Answering {
    /// Nothing comes back, so the silence check ends each attempt.
    Never,
    /// Pieces keep arriving and the exchange never finishes, which only the
    /// attempt patience ends.
    Dribbling,
    /// Quiet until [`TURNS_ARE_CHEAP_UNTIL`], then dribbling on the turn that
    /// straddles the end of the budget. This is the arrangement that
    /// costs the most: the node will not cut off a peer that is delivering,
    /// so the stranger spends its addresses on quick turns and its one long
    /// one on the last of them.
    QuietThenDribbling,
}

impl Answering {
    fn at(self, since_proof: u64) -> JoinProgress {
        let quiet = match self {
            Self::Never => true,
            Self::Dribbling => false,
            Self::QuietThenDribbling => since_proof < TURNS_ARE_CHEAP_UNTIL,
        };
        if quiet {
            JoinProgress::NothingYet
        } else {
            JoinProgress::Moving
        }
    }
}

/// Drives a chooser to the moment it commits, and says how many seconds after
/// the first showing that was.
///
/// One decoy that can show a light chain, and `sybils` connections that claim
/// more and answer as `answering` says. Nothing honest is present, so every
/// second past the first showing is a second the node spends refusing to use a
/// chain it has already proved.
fn seconds_until(sybils: u64, answering: Answering) -> u64 {
    let mut chooser = Chooser::new();
    let start = 100u64;
    // The decoy claims the most, so it is asked first and shows its chain.
    chooser.noted(1, Some(host(1)), 2_000, LONG, true, start);
    let mut connected = vec![1u64];
    for index in 0..sybils {
        let peer = 10 + index;
        chooser.noted(peer, Some(host(peer)), 1_000, LONG, true, start);
        connected.push(peer);
    }

    let mut now = start + 2;
    assert_eq!(
        chooser.step(now, true, 0, JoinProgress::NothingYet, &connected),
        Step::Ask(1, Approach::Join),
        "the heaviest claim is asked first"
    );
    let proven_at = now;
    // It shows what it has. Everything else still claims more, so the node may
    // not commit yet.
    if chooser.shown(1, 50, now) {
        return 0;
    }

    // Round the chooser forward a second at a time until it lets the proved
    // chain through.
    for _ in 0..100_000u64 {
        now += 1;
        let progress = answering.at(now - proven_at);
        match chooser.step(now, true, 0, progress, &connected) {
            Step::Ask(1, _) => {
                // The decoy is asked again; it shows the same chain.
                if chooser.shown(1, 50, now) {
                    return now - proven_at;
                }
            }
            Step::Ask(_, _) | Step::Quiet => {}
            Step::Nudge(_) => return now - proven_at,
        }
    }
    panic!("the chooser never committed");
}

/// The wait stops growing once there are more claims than the shared budget
/// has turns for, and it never crosses the stated ceiling.
#[test]
fn the_hold_off_does_not_grow_with_the_number_of_silent_claims() {
    let mut seen = Vec::new();
    for sybils in [0, 1, 2, 4, 8, 16, FULL_TABLE] {
        let waited = seconds_until(sybils, Answering::Never);
        println!("{sybils} silent heavier claims -> committed after {waited}s");
        seen.push((sybils, waited));
    }
    for (sybils, waited) in &seen {
        assert!(
            *waited <= HELD_OFF_AT_MOST,
            "{sybils} claims held the node off for {waited}s, past the {HELD_OFF_AT_MOST}s ceiling"
        );
    }
    let many = seen[seen.len() - 1].1;
    let some = seen[seen.len() - 2].1;
    assert_eq!(
        many, some,
        "a stranger bought more time by holding more connections: {seen:?}"
    );
}

/// A full peer table of connections, and what it comes to against what it
/// would come to if every claim were owed a window of its own.
#[test]
fn a_full_peer_table_costs_far_less_than_a_window_each() {
    let table = seconds_until(FULL_TABLE, Answering::Never);
    let a_window_each = FULL_TABLE * 30;
    println!(
        "{FULL_TABLE} silent heavier claims (a full peer table) -> {table}s, \
         where a window each would have been {a_window_each}s, \
         against a ceiling of {HELD_OFF_AT_MOST}s"
    );
    assert!(
        table <= HELD_OFF_AT_MOST,
        "a full peer table held the node off for {table}s"
    );
    assert!(
        table < a_window_each / 2,
        "a full peer table still costs about a window each: {table}s"
    );
}

/// Dribbling rather than going quiet used to buy six times as long, because a
/// join that is moving is ended by the attempt patience and not by the silence
/// check. It now buys one attempt patience in total rather than one per claim,
/// because the budget the turns come out of is shared and no new turn is
/// handed out once it is spent.
#[test]
fn dribbling_rather_than_going_silent_buys_one_attempt_and_not_one_each() {
    let silent = seconds_until(FULL_TABLE, Answering::Never);
    let dribbling = seconds_until(FULL_TABLE, Answering::Dribbling);
    println!("{FULL_TABLE} claims, silent -> {silent}s; dribbling -> {dribbling}s");
    assert!(
        dribbling <= HELD_OFF_AT_MOST,
        "dribbling held the node off for {dribbling}s, past the {HELD_OFF_AT_MOST}s ceiling"
    );
}

/// The arrangement that costs the most, which is what the ceiling is for:
/// cheap quiet turns while the budget lasts, and one delivery that never
/// finishes on the turn that straddles the end of it.
#[test]
fn the_worst_arrangement_of_claims_stays_under_the_ceiling() {
    let mut worst = 0;
    for sybils in [1, 2, 4, 8, 16, FULL_TABLE] {
        for answering in [
            Answering::Never,
            Answering::Dribbling,
            Answering::QuietThenDribbling,
        ] {
            let waited = seconds_until(sybils, answering);
            assert!(
                waited <= HELD_OFF_AT_MOST,
                "{sybils} claims {answering:?} held the node off for {waited}s, \
                 past the {HELD_OFF_AT_MOST}s ceiling"
            );
            worst = worst.max(waited);
        }
    }
    println!("the worst arrangement cost {worst}s, against a ceiling of {HELD_OFF_AT_MOST}s");
}

/// Drives a chooser whose best proof belongs to a peer that has since failed,
/// against one machine at one address holding two sockets.
///
/// Two and not one, offset by half an answering window, because one socket
/// leaves a gap: the round in which its claim is asked and fails is a round
/// with nothing heavier standing, and the node slips through it. Two staggered
/// sockets is what one machine holding two connections looks like, and it is
/// within `MAX_PER_HOST`.
///
/// Returns how long after the first showing the node committed, or `None` if it
/// never did inside `watch`.
fn seconds_until_after_a_lost_proof(watch: u64) -> Option<u64> {
    let mut chooser = Chooser::new();
    let start = 100u64;
    // The heaviest claimant, and the one the node asks first.
    chooser.noted(1, Some(host(1)), 2_000, LONG, true, start);
    // The chain the node can actually be handed, which is lighter.
    chooser.noted(2, Some(host(2)), 400, LONG, true, start);
    let mut connected = vec![1u64, 2];

    let mut now = start + 2;
    assert_eq!(
        chooser.step(now, true, 0, JoinProgress::NothingYet, &connected),
        Step::Ask(1, Approach::Join),
        "the heaviest claim is asked first"
    );
    let proven_at = now;
    // It weighs its chain, really and checkably, and then goes away before the
    // ledger lands. Nothing about that needs an attacker.
    chooser.shown(1, 900, now);
    chooser.failed(1, now + 1);

    // The two sockets, and when each next hangs up and dials back.
    let mut sockets = [
        (50u64, proven_at + 1),
        (51u64, proven_at + 1 + FIRST_ANSWER_WINDOW / 2),
    ];
    for (id, _) in sockets {
        chooser.noted(id, Some(host(9)), u128::MAX / 2, LONG, true, now);
        connected.push(id);
    }
    let mut next_id = 100u64;

    for _ in 0..watch {
        now += 1;
        for socket in &mut sockets {
            if now < socket.1 {
                continue;
            }
            chooser.failed(socket.0, now);
            connected.retain(|peer| *peer != socket.0);
            next_id += 1;
            socket.0 = next_id;
            socket.1 = now + FIRST_ANSWER_WINDOW;
            connected.push(socket.0);
            chooser.noted(socket.0, Some(host(9)), u128::MAX / 2, LONG, true, now);
        }
        match chooser.step(now, true, 0, JoinProgress::NothingYet, &connected) {
            Step::Ask(2, _) => {
                if chooser.shown(2, 400, now) {
                    return Some(now - proven_at);
                }
            }
            Step::Nudge(_) => return Some(now - proven_at),
            Step::Ask(_, _) | Step::Quiet => {}
        }
    }
    None
}

/// Long enough for a claim that was asked to have run its answering window out.
const FIRST_ANSWER_WINDOW: u64 = 30;

/// **The ceiling was not a ceiling once the best proof belonged to a peer that
/// had gone.**
///
/// `allows` opened its escape hatch only when what was being adopted weighed at
/// least as much as the heaviest thing anybody had ever *shown*, and that figure
/// never fell when the peer who showed it failed. So a peer that weighed its
/// chain and then went away before handing the ledger over left behind a number
/// no chain still on offer could match: the patience never opened, and any
/// claim heavier than what was left blocked the commitment for ever. Claims
/// cost a stranger a reconnection.
///
/// Measured on the code this was written against: one address, four times the
/// ceiling, still holding. The whole file above measures arrangements where the
/// node commits to the very chain it proved, which is the one case where the
/// old comparison was true.
#[test]
fn a_proof_whose_owner_went_away_does_not_hold_the_node_off_for_ever() {
    let watch = HELD_OFF_AT_MOST * 4;
    let waited = seconds_until_after_a_lost_proof(watch);
    let Some(waited) = waited else {
        panic!(
            "a node whose best proof belongs to a peer that failed was still \
             held off a chain it had proved after {watch}s, against a ceiling \
             of {HELD_OFF_AT_MOST}s, by one stranger at one address"
        );
    };
    assert!(
        waited <= HELD_OFF_AT_MOST,
        "a lost proof cost {waited}s, past the {HELD_OFF_AT_MOST}s ceiling"
    );
    println!("a proof whose owner went away cost {waited}s, against {HELD_OFF_AT_MOST}s");
}

// ---------------------------------------------------------------------------
// What an address that will not show a chain can spend of a node's attention.
//
// The turns above are rationed by a budget counted in seconds. This half is
// rationed by the addresses a stranger has to spend to buy them, and the two
// have to hold together: a stranger that cannot buy time by holding
// connections must not be able to buy it by hanging up either.
// ---------------------------------------------------------------------------

/// One address holding `sockets_each` connections at each of `hosts`
/// addresses. Every one of them goes quiet the moment it is asked, and dials
/// back only once the node has written its claim off, which is the earliest a
/// real one could notice.
///
/// One honest peer stands beside them the whole time with a real chain it can
/// show. Returns how long until the node commits to it, and how many times it
/// was asked at all.
fn against_silent_addresses(hosts: u64, sockets_each: usize, watch: u64) -> (Option<u64>, u32) {
    let mut chooser = Chooser::new();
    let start = 100u64;
    chooser.noted(1, Some(host(1)), 1_000, LONG, true, start);
    let mut connected: Vec<u64> = vec![1];
    let mut next_id = 50u64;
    // Each live socket: its peer number, the address behind it, and when it was
    // asked, if it is under a question.
    let mut live: Vec<(u64, u64, Option<u64>)> = Vec::new();
    for index in 0..hosts {
        for _ in 0..sockets_each {
            next_id += 1;
            chooser.noted(
                next_id,
                Some(host(20 + index)),
                u128::MAX / 2,
                LONG,
                true,
                start,
            );
            connected.push(next_id);
            live.push((next_id, 20 + index, None));
        }
    }

    let mut now = start + 2;
    let mut asked_honest = 0u32;
    for _ in 0..watch {
        now += 1;
        match chooser.step(now, true, 0, JoinProgress::NothingYet, &connected) {
            Step::Ask(1, _) => {
                asked_honest += 1;
                if chooser.shown(1, 1_000, now) {
                    return (Some(now - (start + 2)), asked_honest);
                }
            }
            Step::Ask(peer, _) => {
                if let Some(entry) = live.iter_mut().find(|(id, _, _)| *id == peer) {
                    entry.2 = Some(now);
                }
            }
            Step::Nudge(_) => return (Some(now - (start + 2)), asked_honest),
            Step::Quiet => {}
        }
        let spent: Vec<(u64, u64)> = live
            .iter()
            .filter(|(_, _, asked)| {
                asked.is_some_and(|at| now.saturating_sub(at) >= FIRST_ANSWER_WINDOW)
            })
            .map(|(id, at, _)| (*id, *at))
            .collect();
        for (id, at) in spent {
            connected.retain(|other| *other != id);
            live.retain(|(other, _, _)| *other != id);
            next_id += 1;
            connected.push(next_id);
            live.push((next_id, at, None));
            chooser.noted(next_id, Some(host(at)), u128::MAX / 2, LONG, true, now);
        }
    }
    (None, asked_honest)
}

/// **Two connections at one address took every turn a node had, for ever.**
///
/// The pause an address earns by failing to show a chain was stamped on to a
/// claim when the claim was first heard. A claim already standing when its
/// neighbour failed therefore carried no stamp, so the address's second
/// connection was never paused by the first one's failure. Two of them, which
/// is exactly `MAX_PER_HOST`, handed the turn back and forth: each was asked,
/// went quiet for its answering window, and was written off at the moment the
/// other came out of its pause, so the heaviest standing claim was always one
/// of theirs.
///
/// Measured on the code this was written against: twenty times
/// [`HELD_OFF_AT_MOST`], one honest peer with a real chain standing there the
/// whole time, asked zero times. The price was two connections and one
/// reconnection every half minute.
#[test]
fn two_connections_at_one_address_cannot_take_every_turn() {
    let watch = HELD_OFF_AT_MOST * 20;
    for sockets in [1usize, 2, 3] {
        let (waited, asked) = against_silent_addresses(1, sockets, watch);
        let Some(waited) = waited else {
            panic!(
                "{sockets} connections at one address kept a node from a chain it could \
                 see for more than {watch}s, and the honest peer was asked {asked} times"
            );
        };
        println!("{sockets} connection(s) at one address cost {waited}s, honest asked {asked}");
        assert!(
            waited <= HELD_OFF_AT_MOST,
            "{sockets} connections at one address cost {waited}s, past {HELD_OFF_AT_MOST}s"
        );
    }
}

/// The same, for a stranger that spreads over addresses instead of sockets.
///
/// A flat pause let two of them do what two sockets did, because each came out
/// of its pause exactly as the other went in. The pause now doubles with each
/// further failure at an address, so reusing a handful of them costs more every
/// time round, and a stranger that wants the node's whole attention has to keep
/// finding addresses it has not already spent. That is the price this module
/// has always said a turn has.
///
/// Not bounded by [`HELD_OFF_AT_MOST`], which is about a chain a node has
/// already proved and this node has proved nothing. What is asserted is that
/// the wait ends, and that it grows with what the stranger spends rather than
/// with how long it is willing to wait.
#[test]
fn reusing_a_handful_of_addresses_does_not_buy_turns_for_ever() {
    let watch = HELD_OFF_AT_MOST * 40;
    let mut seen = Vec::new();
    for hosts in [2u64, 4, FULL_TABLE / 2] {
        let (waited, asked) = against_silent_addresses(hosts, 1, watch);
        let Some(waited) = waited else {
            panic!(
                "{hosts} addresses, reused and never fresh, kept a node from a chain it \
                 could see for more than {watch}s, and the honest peer was asked {asked} times"
            );
        };
        println!("{hosts} silent addresses cost {waited}s, honest asked {asked}");
        seen.push((hosts, waited));
    }
    let (fewest, cheapest) = seen[0];
    let (most, dearest) = seen[seen.len() - 1];
    assert!(
        dearest > cheapest,
        "{most} addresses bought no more time than {fewest} did: {seen:?}"
    );
}

/// **The pause must never reach the peer whose chain the node proved.**
///
/// Reading the address's failures when a turn is handed out, rather than
/// stamping them on to a claim, is what closes the two-socket turn above. It
/// also puts every claim behind a shared address inside the pause, and the
/// supplier of the one chain a node has proved may well be behind one: one
/// carrier NAT, one office. A stranger holding the other connection there then
/// paused that supplier every time it went quiet itself, the one claim under
/// the ceiling was never picked, and the commitment never came.
///
/// Measured while writing this: twenty times [`HELD_OFF_AT_MOST`] and still
/// holding, where the code before it cost ninety one seconds. So a claim that
/// has been shown is exempt: the pause is against words, and a chain somebody
/// weighed is not a word.
#[test]
fn a_stranger_beside_the_proved_supplier_cannot_hold_the_node_off() {
    let mut chooser = Chooser::new();
    let start = 100u64;
    // The supplier the node ends up taking its chain from, and a stranger
    // sharing its address, which is what one gateway looks like from here.
    chooser.noted(1, Some(host(7)), 500, LONG, true, start);
    let mut connected = vec![1u64];
    let mut stranger = 50u64;
    chooser.noted(stranger, Some(host(7)), u128::MAX / 2, LONG, true, start);
    connected.push(stranger);
    // And a second stranger that never reuses an address, so there is always a
    // claim standing that no pause applies to. Without it the last rung of the
    // choice hands the supplier its turn anyway and this measures nothing: what
    // is being measured is whether the supplier is reachable while somebody
    // else is always askable, which is what a stranger arranges for free.
    let mut fresh = 60u64;
    let mut fresh_host = 200u64;
    chooser.noted(
        fresh,
        Some(host(fresh_host)),
        u128::MAX / 4,
        LONG,
        true,
        start,
    );
    connected.push(fresh);

    let mut now = start + 2;
    assert!(matches!(
        chooser.step(now, true, 0, JoinProgress::NothingYet, &connected),
        Step::Ask(_, _)
    ));
    let proven_at = now;
    assert!(
        !chooser.shown(1, 500, now),
        "a heavier claim stands, so this may not commit yet"
    );

    let watch = HELD_OFF_AT_MOST * 20;
    let mut next_id = 100u64;
    let mut asked_at: Option<u64> = None;
    let mut fresh_asked_at: Option<u64> = None;
    for _ in 0..watch {
        now += 1;
        match chooser.step(now, true, 0, JoinProgress::NothingYet, &connected) {
            Step::Ask(1, _) => {
                if chooser.shown(1, 500, now) {
                    let waited = now - proven_at;
                    println!(
                        "a stranger beside the proved supplier cost {waited}s, \
                         against {HELD_OFF_AT_MOST}s"
                    );
                    assert!(
                        waited <= HELD_OFF_AT_MOST,
                        "a stranger sharing the supplier's address cost {waited}s, \
                         past the {HELD_OFF_AT_MOST}s ceiling"
                    );
                    return;
                }
            }
            Step::Ask(peer, _) if peer == stranger => asked_at = Some(now),
            Step::Ask(peer, _) if peer == fresh => fresh_asked_at = Some(now),
            Step::Ask(_, _) | Step::Quiet => {}
            Step::Nudge(_) => return,
        }
        if asked_at.is_some_and(|at| now.saturating_sub(at) >= FIRST_ANSWER_WINDOW) {
            connected.retain(|other| *other != stranger);
            next_id += 1;
            stranger = next_id;
            connected.push(stranger);
            chooser.noted(stranger, Some(host(7)), u128::MAX / 2, LONG, true, now);
            asked_at = None;
        }
        if fresh_asked_at.is_some_and(|at| now.saturating_sub(at) >= FIRST_ANSWER_WINDOW) {
            connected.retain(|other| *other != fresh);
            next_id += 1;
            fresh = next_id;
            fresh_host += 1;
            connected.push(fresh);
            chooser.noted(
                fresh,
                Some(host(fresh_host)),
                u128::MAX / 4,
                LONG,
                true,
                now,
            );
            fresh_asked_at = None;
        }
    }
    panic!(
        "a stranger sharing the proved supplier's address held the node off a chain it \
         had proved for more than {watch}s, against a ceiling of {HELD_OFF_AT_MOST}s"
    );
}

/// **A pause is never the end of the road, which is what lets it grow.**
///
/// Letting the pause double with each failure only costs what an address that
/// keeps failing is worth, provided it can never leave a node with nobody to
/// ask. The last resort is what guarantees that: it ignores the pause entirely
/// and reads from the heaviest claim there is, inside `RETRY_PAUSE`, however
/// long the pause on that address has grown to.
///
/// Reading and not a handover, deliberately, and `tests/shared_address_claims.rs`
/// owns the other half of that argument: a handover is taken on the strength of
/// the claim behind it, so a claim inside its pause must not buy one. What the
/// pause costs is the cheap way in, never the chain.
#[test]
fn a_paused_address_is_still_read_from_when_it_is_all_there_is() {
    let mut chooser = Chooser::new();
    let start = 100u64;
    // A stranger and an honest peer behind one gateway, and nobody else at all.
    let mut stranger = 50u64;
    chooser.noted(stranger, Some(host(7)), u128::MAX / 2, LONG, true, start);
    chooser.noted(1, Some(host(7)), 500, LONG, true, start);
    let mut connected = vec![stranger, 1u64];

    let mut now = start + 2;
    let mut next_id = 100u64;
    let mut asked_at: Option<u64> = None;
    for _ in 0..HELD_OFF_AT_MOST {
        now += 1;
        match chooser.step(now, true, 0, JoinProgress::NothingYet, &connected) {
            Step::Ask(1, approach) => {
                let waited = now - (start + 2);
                println!("the only peer left was asked after {waited}s as {approach:?}");
                assert!(
                    waited <= FIRST_ANSWER_WINDOW + 2,
                    "the only peer this node could see waited {waited}s for a turn"
                );
                assert_eq!(
                    approach,
                    Approach::Read,
                    "a claim inside its own address's pause was handed a whole ledger on \
                     the strength of the claim"
                );
                return;
            }
            Step::Ask(peer, _) if peer == stranger => asked_at = Some(now),
            Step::Ask(_, _) | Step::Quiet => {}
            Step::Nudge(_) => panic!("there is no chain to finish on"),
        }
        if asked_at.is_some_and(|at| now.saturating_sub(at) >= FIRST_ANSWER_WINDOW) {
            connected.retain(|other| *other != stranger);
            next_id += 1;
            stranger = next_id;
            connected.push(stranger);
            chooser.noted(stranger, Some(host(7)), u128::MAX / 2, LONG, true, now);
            asked_at = None;
        }
    }
    panic!("the only peer this node could see was never asked at all");
}

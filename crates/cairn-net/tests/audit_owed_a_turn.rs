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

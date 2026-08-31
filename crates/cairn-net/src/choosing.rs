//! Choosing the chain a node starts from.
//!
//! A node with no chain gets one choice that matters: past the
//! reorganisation limit a fork choice is final, so the first long chain it
//! commits to is the one it keeps, whether it was handed a ledger or read
//! every block. Left to the wire, that choice belongs to whoever answers
//! first, and the first answer is the one an attacker races to give.
//!
//! So the choice is made here, once, and deliberately. Peers get a moment to
//! introduce themselves. The one claiming the most work is asked to show it.
//! Nothing is adopted while a heavier claim stands unexamined, and a claim
//! whose owner cannot show it stops counting, for the address it came from
//! and not just for the connection, so hanging up and coming back does not
//! make it words again.
//!
//! Pure by design, like [`crate::sync`]: it is told what happened and says
//! what to do, and never reads a clock or touches a socket, so the whole of
//! it can be tested by handing it moments.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::sync::JOIN_RATHER_THAN_READ;

/// Seconds a node with nothing waits for peers to introduce themselves
/// before it asks anybody for a chain.
///
/// The claims this exists to hear arrive in the first round trip after a
/// connection opens, and the node dials its book once a second, so two
/// seconds is two rounds of introductions. The cost of waiting longer is
/// paid by every node that ever starts; the cost of waiting less is making
/// the one irreversible choice against fewer claims than were seconds away.
const SETTLING: u64 = 2;

/// Seconds a chosen peer has to produce anything at all: the first piece of
/// a weighing, or the first block of a chain offered for reading.
///
/// The same reasoning as the join patience in [`crate::node`]: many times
/// what one answer takes on any link that could carry the exchange, and
/// being wrong costs one attempt against one peer rather than anything
/// lasting.
const FIRST_ANSWER_PATIENCE: u64 = 30;

/// Seconds a join attempt may run in total before the claim behind it stops
/// counting.
///
/// The quiet check gives up sooner when nothing arrives; this is the ceiling
/// on an attempt that keeps arriving and never finishes, which is the way to
/// stall a node that a quiet check cannot see. A real handover is a weighing
/// and a ledger of a few dozen pieces, throttled to eight pieces a window on
/// the serving side, so an honest one on a slow link fits well inside this.
const ATTEMPT_PATIENCE: u64 = 180;

/// Seconds after the first successful weighing before unshown heavier claims
/// stop holding the node off the chain it has proved.
///
/// Claims are chased heaviest first and each failed one stops counting, so
/// this only matters against a supply of fresh claims from fresh addresses.
/// However many arrive, once this has passed the node takes the heaviest
/// chain anybody actually showed it.
const PROVEN_PATIENCE: u64 = 120;

/// Seconds before a peer whose claim already failed is worth asking again,
/// once nobody with an unbroken claim is left.
///
/// Reading is the fallback that cannot be captured, but asking the same
/// broken peer every round would be a tight loop of nothing.
const RETRY_PAUSE: u64 = 30;

/// What one peer says stands behind its chain, and what has become of the
/// claim since.
#[derive(Clone, Debug)]
struct Claim {
    work: u128,
    height: u64,
    /// Whether the peer can show the chain, which is what a join takes.
    archives: bool,
    /// The address the claim came from, so a failed one outlives the
    /// connection that made it.
    host: Option<IpAddr>,
    /// Set when the peer was asked to show this claim and could not. Words
    /// that failed once are not waited on twice.
    unbacked: bool,
    /// When this peer was last asked, so the last resort does not ask the
    /// same broken peer every round.
    tried: Option<u64>,
}

/// How a chosen peer is asked to show its chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Approach {
    /// Weigh it and be handed the ledger, for a chain long enough that
    /// reading it costs more, from a peer that can show it.
    Join,
    /// Read it block by block, which proves itself as it goes.
    Read,
}

/// What the join collector says about the attempt in flight, told to
/// [`Chooser::step`] because the collector is the only party that knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinProgress {
    /// No piece has arrived at all.
    NothingYet,
    /// Pieces are arriving.
    Moving,
    /// Pieces arrived, and then stopped for longer than the join waits.
    Stalled,
}

/// What the node should do about the choice this round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing. There is no choice in front of the node, or the one being
    /// made is still moving.
    Quiet,
    /// Ask this peer to show the chain it claims.
    Ask(u64, Approach),
    /// The choice is made. These peers still claim more work than the chain
    /// the node now follows, and the ordinary rules take it from here: their
    /// chains arrive as branches and the fork choice weighs them.
    Nudge(Vec<u64>),
}

/// The one choice a node with no chain makes about whom to follow.
///
/// Peers are named by the node's connection numbers, which is the one name
/// for a peer that the peer did not choose itself.
#[derive(Debug, Default)]
pub struct Chooser {
    claims: HashMap<u64, Claim>,
    /// Addresses whose claims went unshown, kept apart from the claims
    /// because a claim leaves with its connection and this must not.
    unbacked_hosts: HashSet<IpAddr>,
    /// When the first claim long enough to be final arrived. Until one has,
    /// there is no choice to make: a short chain is never past the
    /// reorganisation limit, so following the wrong one is undone by the
    /// fork choice like any other branch.
    first_claim_at: Option<u64>,
    /// The peer currently asked to show its claim, how, and since when.
    asked: Option<(u64, Approach, u64)>,
    /// The most work any peer has shown rather than said, and when the
    /// first showing landed, which is when the patience for unshown heavier
    /// claims starts running.
    proven: Option<(u128, u64)>,
    /// Set once the node has a chain. The choice was the whole job, so
    /// after it there is nothing here for the rest of the node's life.
    done: bool,
}

impl Chooser {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Notes what a peer claims to have. Only called while this node has no
    /// chain, which is the only time the claim is more than small talk.
    pub fn noted(
        &mut self,
        peer: u64,
        host: Option<IpAddr>,
        work: u128,
        height: u64,
        archives: bool,
        now: u64,
    ) {
        if self.done || work == 0 {
            return;
        }
        // A claim from an address that already failed to show one starts
        // failed. This is what stops a peer washing its claim clean by
        // reconnecting under a fresh connection number.
        let unbacked = host.is_some_and(|host| self.unbacked_hosts.contains(&host));
        self.claims.insert(
            peer,
            Claim {
                work,
                height,
                archives,
                host,
                unbacked,
                tried: None,
            },
        );
        if height >= JOIN_RATHER_THAN_READ && self.first_claim_at.is_none() {
            self.first_claim_at = Some(now);
        }
    }

    /// Whether messages that would start this node following `peer`'s chain
    /// are held off while the choice is open.
    ///
    /// Everyone but the peer being asked, and everyone during the settling,
    /// because a block taken from anybody is the beginning of following them.
    #[must_use]
    pub fn holds_off(&self, peer: u64) -> bool {
        if self.done || self.first_claim_at.is_none() {
            return false;
        }
        self.asked.is_none_or(|(asked, _, _)| asked != peer)
    }

    /// Whether a piece of a join answer from `peer` is the one being waited
    /// on. Pieces from anybody else are noise: they used to land in the one
    /// collection there is and tear it down.
    #[must_use]
    pub fn asked_join(&self, peer: u64) -> bool {
        self.asked
            .is_some_and(|(asked, approach, _)| asked == peer && approach == Approach::Join)
    }

    /// A weighing completed: `peer` showed that `work` really stands behind
    /// its chain. Says whether to go on and take the ledger.
    ///
    /// The evidence replaces the words in both directions. A peer that
    /// claimed more than it showed is now worth what it showed, so the
    /// difference cannot go on holding anything off.
    pub fn shown(&mut self, peer: u64, work: u128, now: u64) -> bool {
        if let Some(claim) = self.claims.get_mut(&peer) {
            claim.work = work;
        }
        self.proven = Some(match self.proven {
            None => (work, now),
            Some((best, at)) => (best.max(work), at),
        });
        self.allows(peer, work, now)
    }

    /// The last look before a commitment: whether anything heard since still
    /// outweighs what `peer` showed.
    ///
    /// When it does, the attempt ends here and the heavier claimant is asked
    /// next, rather than adopting the best answer so far while a better one
    /// is claimed to exist. The exception is a claim that has been given its
    /// time: once something has been proven for [`PROVEN_PATIENCE`], words
    /// alone stop counting against it.
    pub fn allows(&mut self, peer: u64, work: u128, now: u64) -> bool {
        let heavier = self
            .claims
            .iter()
            .any(|(other, claim)| *other != peer && !claim.unbacked && claim.work > work);
        let patience_over = self
            .proven
            .is_some_and(|(best, at)| work >= best && now.saturating_sub(at) >= PROVEN_PATIENCE);
        if heavier && !patience_over {
            self.asked = None;
            return false;
        }
        true
    }

    /// The peer asked to show its claim could not: what came back does not
    /// add up, or nothing came back at all. The claim stops counting.
    pub fn failed(&mut self, peer: u64, now: u64) {
        if let Some(claim) = self.claims.get_mut(&peer) {
            claim.unbacked = true;
            claim.tried = Some(now);
            if let Some(host) = claim.host {
                self.unbacked_hosts.insert(host);
            }
        }
        if self.asked.is_some_and(|(asked, _, _)| asked == peer) {
            self.asked = None;
        }
    }

    /// One round of the choice.
    pub fn step(
        &mut self,
        now: u64,
        chain_is_empty: bool,
        chain_work: u128,
        join: JoinProgress,
        connected: &[u64],
    ) -> Step {
        if self.done {
            return Step::Quiet;
        }
        if !chain_is_empty {
            return self.finish(chain_work, connected);
        }
        let Some(first) = self.first_claim_at else {
            return Step::Quiet;
        };

        // A peer that left mid attempt took its answer with it, and a claim
        // that leaves when asked is a claim that was not going to be shown.
        if let Some((peer, _, _)) = self.asked {
            if !connected.contains(&peer) {
                self.failed(peer, now);
            }
        }
        // The rest leave with their claims and nothing held against them: a
        // claim that was never tested is only gone, not broken.
        self.claims.retain(|peer, _| connected.contains(peer));

        if now.saturating_sub(first) < SETTLING {
            return Step::Quiet;
        }

        if let Some((peer, approach, at)) = self.asked {
            let age = now.saturating_sub(at);
            let stalled = match approach {
                Approach::Join => {
                    join == JoinProgress::Stalled
                        || (join == JoinProgress::NothingYet && age >= FIRST_ANSWER_PATIENCE)
                        || age >= ATTEMPT_PATIENCE
                }
                // A read shows its first block or it shows nothing; the
                // moment one lands the chain is no longer empty and this is
                // never reached again.
                Approach::Read => age >= FIRST_ANSWER_PATIENCE,
            };
            if !stalled {
                return Step::Quiet;
            }
            self.failed(peer, now);
        }

        // Once something has been proven and its patience has run out, only
        // claims the proof already covers are worth asking about: whatever
        // still claims more has had its time to show it.
        let ceiling = self
            .proven
            .and_then(|(best, at)| (now.saturating_sub(at) >= PROVEN_PATIENCE).then_some(best));
        let pick = self
            .pick(ceiling)
            .or_else(|| self.pick(None))
            .or_else(|| self.last_resort(now));
        let Some((peer, approach)) = pick else {
            return Step::Quiet;
        };
        if let Some(claim) = self.claims.get_mut(&peer) {
            claim.tried = Some(now);
        }
        self.asked = Some((peer, approach, now));
        Step::Ask(peer, approach)
    }

    /// The heaviest claim still standing, and how to ask about it.
    fn pick(&self, ceiling: Option<u128>) -> Option<(u64, Approach)> {
        let (peer, claim) = self
            .claims
            .iter()
            .filter(|(_, claim)| !claim.unbacked)
            .filter(|(_, claim)| ceiling.is_none_or(|most| claim.work <= most))
            .max_by_key(|(peer, claim)| (claim.work, **peer))?;
        let approach = if claim.archives && claim.height >= JOIN_RATHER_THAN_READ {
            Approach::Join
        } else {
            Approach::Read
        };
        Some((*peer, approach))
    }

    /// When every claim has failed, the heaviest of them is read anyway.
    ///
    /// Reading checks every block as it arrives, so it cannot be captured by
    /// a claim the way a handover can; what was lost by the failures is only
    /// the cheap way in. A node surrounded entirely by peers whose claims
    /// fail rotates through them for as long as that is true, which is the
    /// most it can honestly do.
    fn last_resort(&self, now: u64) -> Option<(u64, Approach)> {
        let (peer, _) = self
            .claims
            .iter()
            .filter(|(_, claim)| {
                claim
                    .tried
                    .is_none_or(|tried| now.saturating_sub(tried) >= RETRY_PAUSE)
            })
            .max_by_key(|(peer, claim)| (claim.work, **peer))?;
        Some((*peer, Approach::Read))
    }

    /// The node has a chain, so the choice is made and this is over.
    ///
    /// What is handed back is every peer still claiming more work than that
    /// chain carries. They were held off while the choice was open, and
    /// nothing else will ever ask them: a node only asks for a chain when a
    /// message from the peer gives it a reason to, and the messages that
    /// would have were the ones held off.
    fn finish(&mut self, chain_work: u128, connected: &[u64]) -> Step {
        self.done = true;
        let asked = self.asked.map(|(peer, _, _)| peer);
        let mut behind: Vec<u64> = self
            .claims
            .iter()
            .filter(|(peer, claim)| {
                connected.contains(peer) && claim.work > chain_work && Some(**peer) != asked
            })
            .map(|(peer, _)| *peer)
            .collect();
        if behind.is_empty() {
            return Step::Quiet;
        }
        behind.sort_unstable();
        Step::Nudge(behind)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    const LONG: u64 = JOIN_RATHER_THAN_READ + 10;

    fn host(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    /// A chooser with two long claims: peer 1 heavy, peer 2 lighter.
    fn contested() -> Chooser {
        let mut chooser = Chooser::new();
        chooser.noted(1, Some(host(1)), 900, LONG, true, 100);
        chooser.noted(2, Some(host(2)), 500, LONG, true, 100);
        chooser
    }

    #[test]
    fn nothing_is_asked_until_the_settling_has_passed() {
        let mut chooser = contested();
        assert_eq!(
            chooser.step(100, true, 0, JoinProgress::NothingYet, &[1, 2]),
            Step::Quiet,
            "the claims only just arrived"
        );
        assert_eq!(
            chooser.step(100 + SETTLING, true, 0, JoinProgress::NothingYet, &[1, 2]),
            Step::Ask(1, Approach::Join),
            "and then the heaviest claimant is asked, not the first"
        );
    }

    #[test]
    fn a_short_claim_opens_no_choice() {
        let mut chooser = Chooser::new();
        chooser.noted(1, Some(host(1)), 900, 10, true, 100);
        assert_eq!(
            chooser.step(1_000, true, 0, JoinProgress::NothingYet, &[1]),
            Step::Quiet,
            "a short chain is never past the reorganisation limit"
        );
        assert!(
            !chooser.holds_off(2),
            "so nobody is held off while none is claimed"
        );
    }

    #[test]
    fn a_peer_that_cannot_show_a_chain_is_read_instead() {
        let mut chooser = Chooser::new();
        chooser.noted(1, Some(host(1)), 900, LONG, false, 100);
        assert_eq!(
            chooser.step(200, true, 0, JoinProgress::NothingYet, &[1]),
            Step::Ask(1, Approach::Read)
        );
    }

    #[test]
    fn everyone_but_the_asked_peer_is_held_off_while_the_choice_is_open() {
        let mut chooser = contested();
        assert!(chooser.holds_off(1), "held off while settling");
        assert!(chooser.holds_off(2));
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2]);
        assert!(!chooser.holds_off(1), "the asked peer may answer");
        assert!(chooser.holds_off(2));
        assert!(chooser.asked_join(1));
        assert!(!chooser.asked_join(2));
    }

    #[test]
    fn a_showing_that_matches_the_best_claim_is_adopted() {
        let mut chooser = contested();
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2]);
        assert!(
            chooser.shown(1, 900, 210),
            "nothing outweighs what was shown"
        );
    }

    #[test]
    fn a_heavier_claim_heard_in_time_retargets_the_choice() {
        let mut chooser = contested();
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2]);
        chooser.noted(3, Some(host(3)), 2_000, LONG, true, 205);
        assert!(
            !chooser.shown(1, 900, 210),
            "somebody claims more than was shown"
        );
        assert_eq!(
            chooser.step(211, true, 0, JoinProgress::NothingYet, &[1, 2, 3]),
            Step::Ask(3, Approach::Join),
            "and that somebody is asked next"
        );
    }

    #[test]
    fn a_claim_that_fails_stops_counting() {
        let mut chooser = contested();
        chooser.noted(3, Some(host(3)), 2_000, LONG, true, 100);
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2, 3]);
        chooser.failed(3, 210);
        assert_eq!(
            chooser.step(211, true, 0, JoinProgress::NothingYet, &[1, 2, 3]),
            Step::Ask(1, Approach::Join),
            "the next heaviest gets its turn"
        );
        assert!(
            chooser.shown(1, 900, 220),
            "and the failed claim no longer holds adoption off"
        );
    }

    #[test]
    fn reconnecting_does_not_wash_a_failed_claim_clean() {
        let mut chooser = contested();
        chooser.noted(3, Some(host(3)), 2_000, LONG, true, 100);
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2, 3]);
        chooser.failed(3, 210);
        // The same address comes back as a new connection, claiming more
        // than ever.
        chooser.noted(4, Some(host(3)), 3_000, LONG, true, 211);
        assert_eq!(
            chooser.step(212, true, 0, JoinProgress::NothingYet, &[1, 2, 4]),
            Step::Ask(1, Approach::Join),
            "the fresh number changes nothing about the failed address"
        );
        assert!(chooser.shown(1, 900, 220));
    }

    #[test]
    fn an_attempt_that_never_answers_is_given_up_on() {
        let mut chooser = contested();
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2]);
        let waited = 200 + FIRST_ANSWER_PATIENCE;
        assert_eq!(
            chooser.step(waited, true, 0, JoinProgress::NothingYet, &[1, 2]),
            Step::Ask(2, Approach::Join),
            "silence ends the attempt and the next claimant is asked"
        );
    }

    #[test]
    fn an_attempt_that_answers_and_never_finishes_is_given_up_on() {
        let mut chooser = contested();
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2]);
        let dripping = 200 + ATTEMPT_PATIENCE - 1;
        assert_eq!(
            chooser.step(dripping, true, 0, JoinProgress::Moving, &[1, 2]),
            Step::Quiet,
            "pieces are still arriving, so the attempt stands"
        );
        assert_eq!(
            chooser.step(
                200 + ATTEMPT_PATIENCE,
                true,
                0,
                JoinProgress::Moving,
                &[1, 2]
            ),
            Step::Ask(2, Approach::Join),
            "but not for ever"
        );
    }

    #[test]
    fn a_peer_that_leaves_mid_attempt_fails_its_claim() {
        let mut chooser = contested();
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2]);
        assert_eq!(
            chooser.step(201, true, 0, JoinProgress::NothingYet, &[2]),
            Step::Ask(2, Approach::Join),
            "the asked peer is gone, so the next is asked"
        );
        chooser.noted(1, Some(host(1)), 900, LONG, true, 202);
        assert!(
            chooser.shown(2, 500, 210),
            "the claim that left when asked does not count on its return"
        );
    }

    #[test]
    fn heavier_words_stop_counting_once_their_patience_is_over() {
        let mut chooser = contested();
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2]);
        assert!(chooser.shown(1, 900, 210), "proven, and the clock starts");
        // A supply of fresh claims from fresh addresses, each heavier than
        // what was shown, none ever showing anything.
        chooser.noted(3, Some(host(3)), 5_000, LONG, true, 211);
        assert!(
            !chooser.allows(1, 900, 212),
            "inside the patience they hold"
        );
        let over = 210 + PROVEN_PATIENCE;
        assert!(
            chooser.allows(1, 900, over),
            "past it the proven chain is taken"
        );
        assert_eq!(
            chooser.step(over, true, 0, JoinProgress::NothingYet, &[1, 2, 3]),
            Step::Ask(1, Approach::Join),
            "and it is the proven claimant that is asked again, not the words"
        );
    }

    #[test]
    fn when_every_claim_has_failed_the_heaviest_is_read_anyway() {
        let mut chooser = contested();
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2]);
        chooser.failed(1, 210);
        chooser.step(211, true, 0, JoinProgress::NothingYet, &[1, 2]);
        chooser.failed(2, 220);
        assert_eq!(
            chooser.step(
                221 + RETRY_PAUSE,
                true,
                0,
                JoinProgress::NothingYet,
                &[1, 2]
            ),
            Step::Ask(1, Approach::Read),
            "reading checks every block, so it cannot be captured"
        );
    }

    #[test]
    fn a_chain_landing_ends_the_choice_and_names_who_still_claims_more() {
        let mut chooser = contested();
        chooser.noted(3, Some(host(3)), 700, LONG, true, 100);
        chooser.step(200, true, 0, JoinProgress::NothingYet, &[1, 2, 3]);
        assert_eq!(
            chooser.step(210, false, 600, JoinProgress::NothingYet, &[1, 2, 3]),
            Step::Nudge(vec![3]),
            "peer 3 claims more than the chain carries, peer 2 does not, \
             and peer 1 is the one the chain came from"
        );
        assert_eq!(
            chooser.step(211, false, 600, JoinProgress::NothingYet, &[1, 2, 3]),
            Step::Quiet,
            "the choice was the whole job"
        );
        assert!(!chooser.holds_off(2), "nobody is held off after it");
    }
}

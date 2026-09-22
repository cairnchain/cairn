//! Turning away peers that have behaved badly.
//!
//! A node cannot afford to reconnect indefinitely to something that wastes its
//! time, and cannot afford to remember every address that ever annoyed it
//! either. So refusals expire, and the table they live in is bounded.
//!
//! Nothing here is consensus. Two nodes refusing different peers still build
//! the same chain, which is why this can be a local policy at all.

use std::collections::HashMap;
use std::net::IpAddr;

/// How long a peer that misbehaved is turned away for.
pub const REFUSAL_SECONDS: u64 = 600;

/// Addresses held under refusal at once.
///
/// Bounded because the table is fed by whoever connects: an attacker with many
/// addresses would otherwise choose how much memory this node spends
/// remembering them.
///
/// The ceiling is on memory, and what it must not cost is the refusal. A full
/// table used to return without writing anything down, so every refusal this
/// node computed past that point was discarded and every misbehaving host was
/// free to come straight back. Filling it costs one connection and one
/// unannounced frame per address, which an address range supplies.
///
/// `choosing::MAX_UNBACKED_HOSTS` is the same table with the same number and
/// had the same defect, repaired with that reasoning written beside it. This
/// is the sibling it was not carried to.
pub const MAX_REFUSED: usize = 1_024;

/// Whether an address is one this node is willing to turn away.
///
/// The loopback address never is. Several nodes on one machine is how the
/// software is developed, tested and demonstrated, and every one of them
/// arrives from the same address: refusing it would mean a wallet, a node and
/// an explorer on one machine locking each other out for reasons nobody would
/// guess. Anything already running inside the machine has far more direct ways
/// to interfere than connecting to a socket, so there is nothing to defend
/// here anyway.
pub fn can_be_refused(host: IpAddr) -> bool {
    !host.is_loopback()
}

/// Addresses turned away, and until when.
#[derive(Debug, Default)]
pub struct Refusals {
    until: HashMap<IpAddr, u64>,
}

impl Refusals {
    pub fn new() -> Self {
        Self::default()
    }

    /// Turns `host` away for a while, starting from `now`.
    ///
    /// Expired entries are dropped on the way in, so the table stays small
    /// without needing a sweep of its own.
    ///
    /// A full table gives up the entry closest to being forgotten rather than
    /// giving up the refusal. Returning was what it did, and a refusal
    /// computed and then dropped is this layer's oldest defect: the node
    /// decided a host had misbehaved, said nothing, and let it back.
    ///
    /// What is given up is real and is the lesser of the two. An attacker
    /// holding the table full shortens how long anyone else stays refused, and
    /// cannot stop anyone being refused. A host already in the table is
    /// written again whatever the count, so a repeat offender is extended
    /// rather than left on its old deadline.
    pub fn refuse(&mut self, host: IpAddr, now: u64) {
        if !can_be_refused(host) {
            return;
        }
        // The same comparison `refuses` makes, and it has to be: an entry the
        // sweep keeps and `refuses` answers no to is a slot held by a refusal
        // that is over, which at a full table costs somebody a live one.
        self.until.retain(|_, until| *until > now);
        let until = now.saturating_add(REFUSAL_SECONDS);
        if let Some(held) = self.until.get_mut(&host) {
            *held = until;
            return;
        }
        while self.until.len() >= MAX_REFUSED {
            let Some(soonest) = self
                .until
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(host, _)| *host)
            else {
                break;
            };
            self.until.remove(&soonest);
        }
        self.until.insert(host, until);
    }

    pub fn refuses(&self, host: IpAddr, now: u64) -> bool {
        self.until.get(&host).is_some_and(|until| *until > now)
    }

    pub fn forget_expired(&mut self, now: u64) {
        self.until.retain(|_, until| *until > now);
    }

    pub fn len(&self) -> usize {
        self.until.len()
    }

    pub fn is_empty(&self) -> bool {
        self.until.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Refusals, MAX_REFUSED, REFUSAL_SECONDS};
    use std::net::{IpAddr, Ipv4Addr};

    fn host(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
    }

    #[test]
    fn a_refused_address_is_turned_away() {
        let mut refusals = Refusals::new();
        refusals.refuse(host(1), 1_000);
        assert!(refusals.refuses(host(1), 1_000));
        assert!(!refusals.refuses(host(2), 1_000));
    }

    #[test]
    fn a_refusal_runs_out() {
        let mut refusals = Refusals::new();
        refusals.refuse(host(1), 1_000);
        assert!(refusals.refuses(host(1), 1_000 + REFUSAL_SECONDS - 1));
        assert!(!refusals.refuses(host(1), 1_000 + REFUSAL_SECONDS));
    }

    #[test]
    fn expired_refusals_are_forgotten() {
        let mut refusals = Refusals::new();
        refusals.refuse(host(1), 1_000);
        refusals.refuse(host(2), 1_000);
        assert_eq!(refusals.len(), 2);
        refusals.forget_expired(1_000 + REFUSAL_SECONDS);
        assert!(refusals.is_empty());
    }

    #[test]
    fn the_table_does_not_grow_without_limit() {
        let mut refusals = Refusals::new();
        for index in 0..(MAX_REFUSED + 500) {
            let last = u8::try_from(index % 256).unwrap_or(0);
            let third = u8::try_from((index / 256) % 256).unwrap_or(0);
            refusals.refuse(IpAddr::V4(Ipv4Addr::new(198, 51, third, last)), 1_000);
        }
        assert!(refusals.len() <= MAX_REFUSED);
    }

    /// And a full table still refuses somebody, which is what it is for.
    ///
    /// The test above asks whether the table grows without limit and answers
    /// that it does not. That was the whole of what was held here, and it is
    /// not the question this table exists to answer. A full one returned
    /// without writing anything down: every refusal computed past that point
    /// was discarded, and filling it costs one connection and one unannounced
    /// frame per address.
    #[test]
    fn a_full_table_still_turns_the_next_one_away() {
        let mut refusals = Refusals::new();
        for index in 0..MAX_REFUSED {
            let last = u8::try_from(index % 256).unwrap_or(0);
            let third = u8::try_from((index / 256) % 256).unwrap_or(0);
            refusals.refuse(IpAddr::V4(Ipv4Addr::new(198, 51, third, last)), 1_000);
        }
        assert_eq!(refusals.len(), MAX_REFUSED, "the table is full");

        let next = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        assert!(!refusals.refuses(next, 1_000), "and does not hold this one");
        refusals.refuse(next, 1_000);
        assert!(
            refusals.refuses(next, 1_000),
            "a host this node decided to refuse is refused, whatever the table \
             already holds"
        );
        assert!(
            refusals.len() <= MAX_REFUSED,
            "and the ceiling is still kept"
        );
    }

    /// A refusal that is over is gone, at the exact moment it is over.
    ///
    /// The sweep and `refuses` ask the same question of the same field and
    /// must agree about the instant the deadline falls on. `cargo mutants`
    /// found they were held apart: moving the sweep to `>=` keeps an entry
    /// that `refuses` already answers no to, and no test noticed. One dead
    /// entry is nothing; a table full of them is a table that evicts a live
    /// refusal to make room it already had.
    #[test]
    fn a_refusal_is_over_at_the_moment_it_is_over() {
        let mut refusals = Refusals::new();
        let host = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        refusals.refuse(host, 1_000);
        let over = 1_000 + REFUSAL_SECONDS;

        assert!(
            refusals.refuses(host, over - 1),
            "held up to the last second"
        );
        assert!(
            !refusals.refuses(host, over),
            "and not at the deadline itself"
        );

        // The sweep runs on the way into `refuse`, so refusing somebody else
        // at that same instant is what asks it.
        refusals.refuse(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), over);
        assert_eq!(
            refusals.len(),
            1,
            "an entry the sweep kept is one `refuses` already says nothing \
             about, holding a slot a live refusal would need"
        );
    }

    /// A host already held costs nobody else their refusal.
    ///
    /// The first version of this test asked whether a repeat offender's
    /// deadline is moved forward, and that holds whether or not the shortcut
    /// exists: without it the host is evicted by the loop and written back
    /// with the new deadline anyway. What the shortcut buys is the eviction
    /// that does not happen, and mutating it is what said so.
    #[test]
    fn a_host_already_held_does_not_cost_another_one_its_refusal() {
        let mut refusals = Refusals::new();
        let mut held = Vec::new();
        // One instant throughout, so nothing expires under the test and the
        // only thing that can remove an entry is the room being made.
        let early = 1_000u64;
        let now = early + 1;
        for index in 0..(MAX_REFUSED - 1) {
            let last = u8::try_from(index % 256).unwrap_or(0);
            let third = u8::try_from((index / 256) % 256).unwrap_or(0);
            let host = IpAddr::V4(Ipv4Addr::new(198, 51, third, last));
            refusals.refuse(host, early);
            held.push(host);
        }
        // The one with the later deadline, so it is never the entry the room
        // would be made out of.
        let again = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        refusals.refuse(again, now);
        assert_eq!(refusals.len(), MAX_REFUSED, "the table is full");

        let before = held.iter().filter(|h| refusals.refuses(**h, now)).count();
        assert_eq!(before, MAX_REFUSED - 1, "every one of them is held");

        refusals.refuse(again, now);
        let after = held.iter().filter(|h| refusals.refuses(**h, now)).count();
        assert_eq!(
            after, before,
            "refusing a host the table already holds gave up somebody else's \
             refusal to make room it did not need"
        );
        assert!(
            refusals.refuses(again, now + REFUSAL_SECONDS - 1),
            "and the repeat offender is held from now rather than from before"
        );
    }

    /// Otherwise a node, a wallet and an explorer on one machine would lock
    /// each other out.
    #[test]
    fn the_loopback_address_is_never_refused() {
        let mut refusals = Refusals::new();
        refusals.refuse(IpAddr::V4(Ipv4Addr::LOCALHOST), 1_000);
        assert!(!refusals.refuses(IpAddr::V4(Ipv4Addr::LOCALHOST), 1_000));
        assert!(refusals.is_empty());
    }
}

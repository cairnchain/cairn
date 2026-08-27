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
    pub fn refuse(&mut self, host: IpAddr, now: u64) {
        if !can_be_refused(host) {
            return;
        }
        self.until.retain(|_, until| *until > now);
        if self.until.len() >= MAX_REFUSED {
            return;
        }
        self.until.insert(host, now.saturating_add(REFUSAL_SECONDS));
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

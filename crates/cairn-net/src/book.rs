//! Where the peers are.
//!
//! A node that has to be told every address by hand is not part of a network,
//! it is part of a configuration file. The book is how a node keeps the
//! addresses it has been given or been told about, and carries them across a
//! restart.
//!
//! Two things it must never do. It must never keep dialling the dead, or a
//! node spends its life on machines that are gone. And it must never end up
//! empty, because a node that knows no address has no way back: nobody to ask,
//! nobody to be told about. The first is what the misses below are for. The
//! second is what seeds are for.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use crate::message::PeerAddress;

/// The name the address book takes inside a node's directory.
pub const PEER_FILE: &str = "peers.txt";

/// Addresses held before new ones are ignored.
///
/// The book is filled by strangers, so it needs a ceiling. Seeds are outside
/// it: they come from the operator, and the ceiling is there against
/// strangers.
pub const MAX_ADDRESSES: usize = 4_096;

/// Addresses kept from any one neighbourhood of the internet.
///
/// A ceiling on its own is not enough. Whoever fills the book decides who a
/// node can reach, and filling it is cheap for anyone holding a block of
/// addresses: rent one machine, name four thousand addresses on the same
/// range, and every real peer learned afterwards is turned away at a full
/// book. The node then talks only to whoever wrote it, which is the whole
/// attack, since a node that sees only one view of the chain can be told
/// anything about it.
///
/// Addresses are grouped by the part of them that is expensive to vary. Two
/// bytes for IPv4 and four for IPv6 is roughly what one operator gets from one
/// provider, so filling this book now means holding addresses across a hundred
/// and twenty eight separate neighbourhoods rather than one.
pub const MAX_PER_GROUP: usize = 32;

/// Failed dials in a row before an address is dropped.
///
/// Three rather than one, because a machine can be restarting, and rather
/// than ten, because an address that has not answered three times running is
/// almost never coming back. What it costs to be wrong is one address that
/// has to be learned again from a peer.
///
/// Three only means something alongside the waiting below. Counted against
/// dials a second apart, three misses is three seconds, and three seconds of
/// a bad connection would empty the book.
pub const MAX_MISSES: u8 = 3;

/// How long an address is left alone after one failed dial.
///
/// It doubles twice over per further miss, so an address that has just missed
/// is tried again in a minute, and one that has missed twice in four. A node
/// therefore spends about five minutes finding out that an address is gone,
/// which is longer than a server takes to reboot and shorter than anyone
/// waits for a network.
const RETRY_DELAY: u64 = 60;

/// The longest an address is ever left alone.
///
/// Only seeds live long enough to reach it, since nothing else survives three
/// misses. Ten minutes is short enough that a node whose network came back an
/// hour ago is not still waiting, and long enough that dialling a machine that
/// is genuinely gone costs nothing worth counting.
const MAX_QUIET: u64 = 600;

/// What is known about one address beyond the address itself.
///
/// None of this is written down. A restart forgets which addresses were quiet
/// and finds out again in a few seconds, which is a better trade than a file
/// format carrying counters that mean nothing to the person reading it. Being
/// a seed is not written down either: it is told to the book at every start by
/// whoever started the node.
#[derive(Clone, Copy, Debug, Default)]
struct Known {
    /// Failed dials in a row, cleared by any peer that introduces itself.
    misses: u8,
    /// When it last spoke, or when it was first written down.
    heard: u64,
    /// The moment before which this address is not dialled again.
    quiet_until: u64,
    /// Given at the start rather than learned along the way.
    seed: bool,
}

impl Known {
    /// How long to leave an address alone after `misses` failures running.
    fn quiet_for(misses: u8) -> u64 {
        let steps = u32::from(misses.saturating_sub(1)).saturating_mul(2);
        RETRY_DELAY
            .checked_shl(steps)
            .unwrap_or(MAX_QUIET)
            .min(MAX_QUIET)
    }
}

/// Addresses a node knows about.
///
/// A book that only ever grows is a book that fills with the dead. Addresses
/// that stop answering are dropped, and the ones that answered most recently
/// are the ones dialled and passed on first, so a node spends its attention
/// on peers that exist.
///
/// Seeds are the exception, and they are the reason a node can always come
/// back. They are dialled more and more slowly when they do not answer, like
/// everything else, but they are never dropped. An address the operator gave
/// is the one thing in the book that was not learned from the network, so it
/// is the one thing the network cannot take away.
#[derive(Clone, Debug, Default)]
pub struct AddressBook {
    known: BTreeMap<SocketAddr, Known>,
    /// How many addresses each neighbourhood holds.
    ///
    /// Counted as they go in and out rather than walked for on each insert,
    /// so a peer naming five hundred addresses in one message costs five
    /// hundred lookups and not five hundred passes over the book.
    groups: BTreeMap<Group, usize>,
}

/// The part of an address that is expensive for one party to vary.
type Group = [u8; 4];

/// Which neighbourhood an address belongs to.
fn group_of(address: &SocketAddr) -> Group {
    match address.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            [octets[0], octets[1], 0, 0]
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            [octets[0], octets[1], octets[2], octets[3]]
        }
    }
}

impl AddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.known.len()
    }

    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }

    pub fn contains(&self, address: &SocketAddr) -> bool {
        self.known.contains_key(address)
    }

    pub fn iter(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.known.keys().copied()
    }

    /// Records an address, returning whether it was new.
    ///
    /// An address already known keeps what is known about it: being mentioned
    /// again by a peer is not evidence that it answers.
    pub fn insert(&mut self, address: SocketAddr) -> bool {
        if !is_dialable(&address) || self.known.len() >= MAX_ADDRESSES {
            return false;
        }
        if self.known.contains_key(&address) {
            return false;
        }
        let group = group_of(&address);
        let held = self.groups.get(&group).copied().unwrap_or(0);
        if held >= MAX_PER_GROUP {
            return false;
        }
        self.known.insert(address, Known::default());
        self.groups.insert(group, held.saturating_add(1));
        true
    }

    /// Records an address the operator gave, which is never dropped.
    ///
    /// Marking one already in the book is the ordinary case: the book is read
    /// back from disk before the seeds are known, so the same addresses are
    /// usually already there as plain entries.
    pub fn insert_seed(&mut self, address: SocketAddr) -> bool {
        if !is_dialable(&address) {
            return false;
        }
        let fresh = !self.known.contains_key(&address);
        let entry = self.known.entry(address).or_default();
        let was_seed = entry.seed;
        entry.seed = true;
        if fresh {
            // Counted like any other, so a seed does not sit outside the
            // accounting, but never refused by it: the operator decides.
            let group = group_of(&address);
            let held = self.groups.get(&group).copied().unwrap_or(0);
            self.groups.insert(group, held.saturating_add(1));
        }
        !was_seed
    }

    /// Whether this address was given rather than learned.
    pub fn is_seed(&self, address: &SocketAddr) -> bool {
        self.known.get(address).is_some_and(|known| known.seed)
    }

    /// The addresses this node was started from.
    pub fn seeds(&self) -> Vec<SocketAddr> {
        self.known
            .iter()
            .filter(|(_, known)| known.seed)
            .map(|(address, _)| *address)
            .collect()
    }

    pub fn remove(&mut self, address: &SocketAddr) -> bool {
        if self.known.remove(address).is_none() {
            return false;
        }
        let group = group_of(address);
        match self.groups.get(&group).copied().unwrap_or(0) {
            0 | 1 => {
                self.groups.remove(&group);
            }
            held => {
                self.groups.insert(group, held.saturating_sub(1));
            }
        }
        true
    }

    /// Notes that this address introduced itself.
    ///
    /// Clears whatever was held against it: a peer that speaks now is a peer
    /// that exists now, whatever it did earlier.
    pub fn answered(&mut self, address: &SocketAddr, now: u64) {
        if let Some(known) = self.known.get_mut(address) {
            known.misses = 0;
            known.heard = now;
            known.quiet_until = 0;
        }
    }

    /// Notes that a dial to this address came to nothing.
    ///
    /// Returns whether that was the last chance it had. A seed has no last
    /// chance: it is left alone for longer and longer, and kept.
    pub fn missed(&mut self, address: &SocketAddr, now: u64) -> bool {
        let Some(known) = self.known.get_mut(address) else {
            return false;
        };
        known.misses = known.misses.saturating_add(1);
        known.quiet_until = now.saturating_add(Known::quiet_for(known.misses));
        if known.misses < MAX_MISSES || known.seed {
            return false;
        }
        self.remove(address);
        true
    }

    /// Forgets every miss held against every address.
    ///
    /// For the one case where a run of failed dials says nothing about the
    /// addresses: the machine itself was not on the network. A laptop that
    /// slept, a cable pulled out, a connection that dropped for a minute. The
    /// node cannot tell which, and it does not need to. What it can tell is
    /// that the whole world went quiet at once, and the whole world does not
    /// go quiet at once.
    pub fn forgive_all(&mut self) {
        for known in self.known.values_mut() {
            known.misses = 0;
            known.quiet_until = 0;
        }
    }

    /// Addresses worth dialling, the most recently heard from first.
    ///
    /// An address never heard from sorts last but is still offered, since a
    /// node starting out has nothing else and every peer begins unheard.
    pub fn candidates(&self) -> Vec<SocketAddr> {
        self.ordered()
            .into_iter()
            .map(|(address, _)| address)
            .collect()
    }

    /// Addresses worth dialling right now, in the same order.
    ///
    /// An address that just failed is left out until its wait is over, so a
    /// bad minute costs a node one dial rather than an address.
    pub fn ready(&self, now: u64) -> Vec<SocketAddr> {
        self.ordered()
            .into_iter()
            .filter(|(_, known)| known.quiet_until <= now)
            .map(|(address, _)| address)
            .collect()
    }

    /// Every address, most recently heard from first.
    fn ordered(&self) -> Vec<(SocketAddr, Known)> {
        let mut ordered: Vec<(SocketAddr, Known)> =
            self.known.iter().map(|(a, k)| (*a, *k)).collect();
        ordered.sort_by(|left, right| {
            right
                .1
                .heard
                .cmp(&left.1.heard)
                .then_with(|| left.0.cmp(&right.0))
        });
        ordered
    }

    /// Addresses to hand to a peer that asked.
    ///
    /// Half the places go to the addresses heard from most recently, because
    /// passing on the ones that answer is what stops the dead spreading. The
    /// other half rotates with `turn` through everything else, because a book
    /// that always answers with the same names is a book whose other names
    /// never reach anyone: a node learns an address, never passes it on, and
    /// the network stays as connected as it was on the day it started.
    ///
    /// Rotating rather than drawing at random keeps this a pure function of
    /// the book and the number given, which is what makes it testable. The
    /// caller passes the clock, so what circulates changes by the second.
    pub fn sample(&self, max: usize, turn: u64) -> Vec<PeerAddress> {
        let ordered = self.candidates();
        if ordered.len() <= max {
            return ordered.into_iter().map(PeerAddress).collect();
        }

        let fresh = max / 2;
        let mut chosen: Vec<SocketAddr> = ordered.get(..fresh).unwrap_or_default().to_vec();
        let rest = ordered.get(fresh..).unwrap_or_default();
        if rest.is_empty() {
            return chosen.into_iter().map(PeerAddress).collect();
        }

        let span = u64::try_from(rest.len()).unwrap_or(1).max(1);
        let start = usize::try_from(turn.checked_rem(span).unwrap_or(0)).unwrap_or(0);
        for step in 0..max.saturating_sub(fresh) {
            let Some(at) = start.saturating_add(step).checked_rem(rest.len()) else {
                break;
            };
            let Some(address) = rest.get(at) else {
                break;
            };
            chosen.push(*address);
        }
        chosen.into_iter().map(PeerAddress).collect()
    }

    /// Reads the book from `directory`, treating an unreadable or missing file
    /// as an empty one. A lost address book costs a node its head start, never
    /// its chain.
    pub fn load(directory: impl AsRef<Path>) -> Self {
        let path = directory.as_ref().join(PEER_FILE);
        let Ok(contents) = std::fs::read_to_string(path) else {
            return Self::new();
        };
        let mut book = Self::new();
        for line in contents.lines() {
            if let Ok(address) = line.trim().parse::<SocketAddr>() {
                book.insert(address);
            }
        }
        book
    }

    /// Writes the book to `directory`, one address per line.
    ///
    /// Plain text on purpose: an operator should be able to read and edit the
    /// list of machines their node will talk to.
    pub fn save(&self, directory: impl AsRef<Path>) -> std::io::Result<()> {
        let directory = directory.as_ref();
        std::fs::create_dir_all(directory)?;
        let mut contents = String::new();
        for address in self.known.keys() {
            contents.push_str(&address.to_string());
            contents.push('\n');
        }
        std::fs::write(directory.join(PEER_FILE), contents)
    }
}

/// Whether an address is worth keeping at all.
fn is_dialable(address: &SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn address(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(203, 0, 113, last), port))
    }

    /// Addresses spread thinly enough across neighbourhoods that a test
    /// wanting a full book is not stopped by the per neighbourhood ceiling on
    /// the way there: a fresh neighbourhood every [`MAX_PER_GROUP`] of them.
    fn spread(index: usize) -> SocketAddr {
        let neighbourhood = u8::try_from(index / MAX_PER_GROUP).unwrap_or(0);
        let within = u8::try_from(index % MAX_PER_GROUP).unwrap_or(0);
        SocketAddr::from((Ipv4Addr::new(10, neighbourhood, within, 1), 9_000))
    }

    /// Misses far enough apart that the waiting never hides one.
    fn miss_repeatedly(book: &mut AddressBook, address: &SocketAddr, times: u8) {
        for step in 0..u64::from(times) {
            book.missed(address, step.saturating_mul(MAX_QUIET));
        }
    }

    #[test]
    fn addresses_go_in_once() {
        let mut book = AddressBook::new();
        assert!(book.insert(address(1, 9000)));
        assert!(
            !book.insert(address(1, 9000)),
            "the same address is not new twice"
        );
        assert!(
            book.insert(address(1, 9001)),
            "a different port is a different peer"
        );
        assert_eq!(book.len(), 2);
        assert!(book.contains(&address(1, 9000)));
        assert!(book.remove(&address(1, 9000)));
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn addresses_that_cannot_be_dialled_are_refused() {
        let mut book = AddressBook::new();
        assert!(!book.insert(address(1, 0)), "port zero reaches nothing");
        assert!(!book.insert(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9000))));
        assert!(!book.insert(SocketAddr::from((Ipv4Addr::BROADCAST, 9000))));
        assert!(!book.insert(SocketAddr::from((Ipv4Addr::new(224, 0, 0, 1), 9000))));
        assert!(!book.insert(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 9000))));
        assert!(
            !book.insert_seed(address(1, 0)),
            "not even from an operator"
        );
        assert!(book.is_empty());
    }

    #[test]
    fn the_book_stops_growing_at_its_ceiling() {
        let mut book = AddressBook::new();
        for index in 0..MAX_ADDRESSES {
            book.insert(spread(index));
        }
        assert_eq!(book.len(), MAX_ADDRESSES, "the ceiling is reachable");
        assert!(!book.insert(spread(MAX_ADDRESSES)), "and it holds");
        assert_eq!(book.len(), MAX_ADDRESSES);
    }

    /// Whoever fills the book decides who a node can reach.
    ///
    /// A ceiling alone would let anyone holding one range of addresses name
    /// four thousand of them and leave no room for a real peer learned
    /// afterwards. The node would then talk only to whoever wrote the book,
    /// and a node that sees one view of the chain can be told anything.
    #[test]
    fn no_one_neighbourhood_can_fill_the_book() {
        let mut book = AddressBook::new();

        // One party, one range, as many ports as it likes.
        for port in 0..1_000u16 {
            book.insert(address(1, port.saturating_add(1_024)));
        }
        assert_eq!(book.len(), MAX_PER_GROUP, "it got its share and no more");

        // Varying the last byte is the same neighbourhood and buys nothing.
        for last in 0..255u8 {
            book.insert(address(last, 9_000));
        }
        assert_eq!(book.len(), MAX_PER_GROUP);

        // And a peer somewhere else still gets in.
        assert!(book.insert(SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 9_000))));

        // Room comes back as its addresses go.
        let held: Vec<SocketAddr> = book
            .iter()
            .filter(|entry| group_of(entry) == group_of(&address(1, 1_024)))
            .collect();
        for entry in &held {
            book.remove(entry);
        }
        assert!(book.insert(address(1, 1_024)), "the count came back down");
    }

    /// The operator's own addresses are counted but never refused.
    #[test]
    fn a_seed_is_not_turned_away_by_a_crowded_neighbourhood() {
        let mut book = AddressBook::new();
        for step in 0..MAX_PER_GROUP {
            let port = u16::try_from(step).unwrap_or(0).saturating_add(1_024);
            book.insert(address(1, port));
        }
        assert!(!book.insert(address(1, 9_999)), "full for strangers");
        assert!(
            book.insert_seed(address(1, 9_999)),
            "but not for the operator"
        );
        assert!(book.is_seed(&address(1, 9_999)));
    }

    /// The ceiling is there against strangers, and a seed is not a stranger.
    #[test]
    fn a_full_book_still_takes_a_seed() {
        let mut book = AddressBook::new();
        for index in 0..MAX_ADDRESSES {
            book.insert(spread(index));
        }
        let full = book.len();
        assert!(!book.insert(address(255, 65_535)), "full for strangers");
        assert!(book.insert_seed(address(255, 65_535)));
        assert!(book.is_seed(&address(255, 65_535)));
        assert_eq!(book.len(), full.saturating_add(1));
    }

    #[test]
    fn a_sample_is_bounded() {
        let mut book = AddressBook::new();
        for index in 0..76 {
            book.insert(spread(index));
        }
        assert_eq!(book.len(), 76);
        assert_eq!(book.sample(10, 0).len(), 10);
        assert_eq!(book.sample(1_000, 0).len(), book.len());
    }

    /// A book that only grows is a book that fills with the dead.
    #[test]
    fn an_address_that_never_answers_is_dropped() {
        let mut book = AddressBook::new();
        book.insert(address(1, 9000));

        for attempt in 1..MAX_MISSES {
            assert!(
                !book.missed(&address(1, 9000), u64::from(attempt) * MAX_QUIET),
                "still worth another try after {attempt} miss(es)"
            );
            assert!(book.contains(&address(1, 9000)));
        }
        assert!(
            book.missed(&address(1, 9000), u64::from(MAX_MISSES) * MAX_QUIET),
            "the last chance is used up"
        );
        assert!(!book.contains(&address(1, 9000)));
        assert!(book.is_empty());
    }

    /// The one address a node can always fall back on. A node whose book has
    /// emptied has no way back onto the network at all, so the addresses its
    /// operator gave it outlive any run of silence.
    #[test]
    fn a_seed_is_never_dropped() {
        let mut book = AddressBook::new();
        book.insert_seed(address(1, 9000));

        miss_repeatedly(&mut book, &address(1, 9000), 50);

        assert!(book.contains(&address(1, 9000)));
        assert!(book.is_seed(&address(1, 9000)));
        assert_eq!(book.seeds(), vec![address(1, 9000)]);
    }

    /// An address already in the book keeps its place when it turns out to be
    /// a seed, which is the ordinary case: the book is read from disk before
    /// the command line is.
    #[test]
    fn an_address_can_become_a_seed() {
        let mut book = AddressBook::new();
        book.insert(address(1, 9000));
        book.answered(&address(1, 9000), 900);

        assert!(book.insert_seed(address(1, 9000)), "newly a seed");
        assert!(!book.insert_seed(address(1, 9000)), "and not twice");
        assert_eq!(book.len(), 1);

        miss_repeatedly(&mut book, &address(1, 9000), 10);
        assert!(book.contains(&address(1, 9000)));
    }

    /// Dialled once a second, three misses is three seconds, and a bad minute
    /// would empty the book. The waiting is what makes three misses mean an
    /// address that is gone rather than a connection that hiccuped.
    #[test]
    fn an_address_that_just_missed_is_left_alone_for_a_while() {
        let mut book = AddressBook::new();
        book.insert(address(1, 9000));
        book.insert(address(2, 9000));

        book.missed(&address(1, 9000), 1_000);

        assert_eq!(
            book.ready(1_000),
            vec![address(2, 9000)],
            "the one that just failed is not dialled again this second"
        );
        assert_eq!(
            book.ready(1_000 + RETRY_DELAY).len(),
            2,
            "a minute later it is"
        );

        // And the wait grows, so a node stops spending attention on it.
        book.missed(&address(1, 9000), 1_000 + RETRY_DELAY);
        assert_eq!(book.ready(1_000 + RETRY_DELAY * 2).len(), 1);
        assert_eq!(book.ready(1_000 + RETRY_DELAY * 5).len(), 2);
    }

    /// However long a seed has been silent, it is tried again before long.
    #[test]
    fn a_seed_is_never_left_alone_for_more_than_ten_minutes() {
        let mut book = AddressBook::new();
        book.insert_seed(address(1, 9000));

        miss_repeatedly(&mut book, &address(1, 9000), 20);

        let last = 19 * MAX_QUIET;
        assert!(book.ready(last).is_empty());
        assert_eq!(book.ready(last + MAX_QUIET), vec![address(1, 9000)]);
    }

    /// A machine restarting must not cost its address a place in the book.
    #[test]
    fn answering_clears_what_was_held_against_an_address() {
        let mut book = AddressBook::new();
        book.insert(address(1, 9000));

        book.missed(&address(1, 9000), 100);
        book.missed(&address(1, 9000), 200);
        book.answered(&address(1, 9000), 1_000);

        assert_eq!(
            book.ready(1_000),
            vec![address(1, 9000)],
            "and dialled again"
        );

        // Back to a full allowance rather than one miss from being dropped.
        for attempt in 1..MAX_MISSES {
            assert!(!book.missed(&address(1, 9000), u64::from(attempt) * MAX_QUIET));
        }
        assert!(book.contains(&address(1, 9000)));
    }

    /// The whole world does not go quiet at once. When every address stops
    /// answering together, the machine is what changed.
    #[test]
    fn a_node_that_was_away_holds_nothing_against_anyone() {
        let mut book = AddressBook::new();
        book.insert(address(1, 9000));
        book.insert(address(2, 9000));

        book.missed(&address(1, 9000), 1_000);
        book.missed(&address(2, 9000), 1_000);
        assert!(book.ready(1_000).is_empty());

        book.forgive_all();

        assert_eq!(book.ready(1_000).len(), 2, "both worth trying again");
        for attempt in 1..MAX_MISSES {
            assert!(!book.missed(&address(1, 9000), u64::from(attempt) * MAX_QUIET));
        }
        assert!(book.contains(&address(1, 9000)), "with a full allowance");
    }

    /// Being mentioned again by a peer is not evidence that an address works.
    #[test]
    fn hearing_about_an_address_again_does_not_absolve_it() {
        let mut book = AddressBook::new();
        book.insert(address(1, 9000));
        book.missed(&address(1, 9000), 0);
        book.missed(&address(1, 9000), MAX_QUIET);

        assert!(!book.insert(address(1, 9000)), "not new");
        assert!(
            book.missed(&address(1, 9000), MAX_QUIET * 2),
            "its record should have survived being mentioned again"
        );
        assert!(!book.contains(&address(1, 9000)));
    }

    #[test]
    fn the_ones_that_answered_most_recently_come_first() {
        let mut book = AddressBook::new();
        book.insert(address(1, 9000));
        book.insert(address(2, 9000));
        book.insert(address(3, 9000));

        book.answered(&address(3, 9000), 500);
        book.answered(&address(1, 9000), 900);

        assert_eq!(
            book.candidates(),
            vec![
                address(1, 9000), // heard most recently
                address(3, 9000),
                address(2, 9000), // never heard from, so last
            ]
        );

        // And what is passed on follows the same order, so the dead do not
        // spread through the network.
        let shared: Vec<SocketAddr> = book.sample(2, 0).into_iter().map(|entry| entry.0).collect();
        assert_eq!(shared, vec![address(1, 9000), address(3, 9000)]);
    }

    /// A book that always answers with the same names is a book whose other
    /// names never reach anyone.
    #[test]
    fn what_is_passed_on_rotates_so_every_address_gets_out() {
        let mut book = AddressBook::new();
        for index in 0..40 {
            book.insert(spread(index));
        }
        // A few that answered, so there is something to keep at the front.
        for index in 0..4 {
            book.answered(&spread(index), 1_000 + index as u64);
        }

        let names = |turn: u64| -> Vec<SocketAddr> {
            book.sample(8, turn)
                .into_iter()
                .map(|entry| entry.0)
                .collect()
        };

        // The freshest half is the same every time, on purpose: passing on
        // what answers is what stops the dead spreading.
        let first = names(0);
        assert_eq!(first.len(), 8);
        for turn in 1..20u64 {
            assert_eq!(names(turn).get(..4), first.get(..4), "the fresh half holds");
        }

        // And over enough turns, everything in the book has been offered.
        let mut seen: std::collections::BTreeSet<SocketAddr> = std::collections::BTreeSet::new();
        for turn in 0..64u64 {
            for address in names(turn) {
                seen.insert(address);
            }
        }
        assert_eq!(seen.len(), book.len(), "every address reached someone");
    }

    /// A book smaller than what is asked for is handed over whole.
    #[test]
    fn a_small_book_is_passed_on_entire() {
        let mut book = AddressBook::new();
        for index in 0..5 {
            book.insert(spread(index));
        }
        for turn in 0..8u64 {
            assert_eq!(book.sample(64, turn).len(), 5);
        }
    }

    #[test]
    fn missing_an_address_the_book_never_had_changes_nothing() {
        let mut book = AddressBook::new();
        assert!(!book.missed(&address(9, 9000), 0));
        assert!(book.is_empty());
    }

    #[test]
    fn the_book_survives_a_round_trip_through_a_file() {
        let directory =
            std::env::temp_dir().join(format!("cairn-book-{}-{}", std::process::id(), "roundtrip"));
        let _ = std::fs::remove_dir_all(&directory);

        let mut book = AddressBook::new();
        book.insert(address(1, 9000));
        book.insert(SocketAddr::from((Ipv6Addr::LOCALHOST, 9001)));
        book.save(&directory).unwrap();

        let read_back = AddressBook::load(&directory);
        assert_eq!(read_back.len(), 2);
        assert!(read_back.contains(&address(1, 9000)));

        let text = std::fs::read_to_string(directory.join(PEER_FILE)).unwrap();
        assert_eq!(
            text.lines().count(),
            2,
            "one address per line, readable by a person"
        );
    }

    #[test]
    fn a_missing_or_broken_file_reads_as_an_empty_book() {
        let directory =
            std::env::temp_dir().join(format!("cairn-book-{}-{}", std::process::id(), "broken"));
        let _ = std::fs::remove_dir_all(&directory);
        assert!(AddressBook::load(&directory).is_empty());

        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(PEER_FILE),
            "not an address\n203.0.113.1:9000\n",
        )
        .unwrap();
        let book = AddressBook::load(&directory);
        assert_eq!(book.len(), 1, "the readable lines are kept");
    }
}

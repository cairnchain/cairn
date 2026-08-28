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
/// The book is filled by strangers, so it needs a ceiling. Ignoring new
/// entries once full is the simplest policy that cannot be gamed into
/// unbounded memory; a real network wants eviction that resists an attacker
/// flooding the book with addresses it controls. Seeds are outside this
/// ceiling: they come from the operator, and the ceiling is there against
/// strangers.
pub const MAX_ADDRESSES: usize = 4_096;

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
        self.known.insert(address, Known::default());
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
        let entry = self.known.entry(address).or_default();
        let was_seed = entry.seed;
        entry.seed = true;
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
        self.known.remove(address).is_some()
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
        self.known.remove(address);
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

    /// Addresses to hand to a peer that asked, most recently heard first.
    ///
    /// Passing on the addresses that answered most recently is what stops the
    /// dead spreading: an address nobody has reached in a while is dropped
    /// here before it is handed to anyone else.
    ///
    /// The same addresses still come back every time. Varying them matters
    /// against a peer trying to become someone's whole view of the network,
    /// and belongs with peer scoring rather than here.
    pub fn sample(&self, max: usize) -> Vec<PeerAddress> {
        self.candidates()
            .into_iter()
            .take(max)
            .map(PeerAddress)
            .collect()
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
            let port = u16::try_from(index % 60_000)
                .unwrap_or(1)
                .saturating_add(1_024);
            let last = u8::try_from(index / 60_000).unwrap_or(0);
            book.insert(address(last, port));
        }
        let filled = book.len();
        assert!(filled > 0);
        book.insert(address(255, 65_535));
        assert!(book.len() <= MAX_ADDRESSES);
        assert_eq!(book.len(), filled.min(MAX_ADDRESSES));
    }

    /// The ceiling is there against strangers, and a seed is not a stranger.
    #[test]
    fn a_full_book_still_takes_a_seed() {
        let mut book = AddressBook::new();
        for index in 0..MAX_ADDRESSES {
            let port = u16::try_from(index % 60_000)
                .unwrap_or(1)
                .saturating_add(1_024);
            let last = u8::try_from(index / 60_000).unwrap_or(0);
            book.insert(address(last, port));
        }
        assert!(!book.insert(address(255, 65_535)), "full for strangers");
        assert!(book.insert_seed(address(255, 65_535)));
        assert!(book.is_seed(&address(255, 65_535)));
    }

    #[test]
    fn a_sample_is_bounded() {
        let mut book = AddressBook::new();
        for port in 1_024..1_100u16 {
            book.insert(address(1, port));
        }
        assert_eq!(book.sample(10).len(), 10);
        assert_eq!(book.sample(1_000).len(), book.len());
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
        let shared: Vec<SocketAddr> = book.sample(2).into_iter().map(|entry| entry.0).collect();
        assert_eq!(shared, vec![address(1, 9000), address(3, 9000)]);
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

//! Where the peers are.
//!
//! A node that has to be told every address by hand is not part of a network,
//! it is part of a configuration file. The book is how a node keeps the
//! addresses it has been given or been told about, and carries them across a
//! restart.

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
/// flooding the book with addresses it controls.
pub const MAX_ADDRESSES: usize = 4_096;

/// Failed dials in a row before an address is dropped.
///
/// Three rather than one, because a machine can be restarting, and rather
/// than ten, because an address that has not answered three times running is
/// almost never coming back. What it costs to be wrong is one address that
/// has to be learned again from a peer.
pub const MAX_MISSES: u8 = 3;

/// What is known about one address beyond the address itself.
///
/// None of this is written down. A restart forgets which addresses were quiet
/// and finds out again in a few seconds, which is a better trade than a file
/// format carrying counters that mean nothing to the person reading it.
#[derive(Clone, Copy, Debug, Default)]
struct Known {
    /// Failed dials in a row, cleared by any peer that introduces itself.
    misses: u8,
    /// When it last spoke, or when it was first written down.
    heard: u64,
}

/// Addresses a node knows about.
///
/// A book that only ever grows is a book that fills with the dead. Addresses
/// that stop answering are dropped, and the ones that answered most recently
/// are the ones dialled and passed on first, so a node spends its attention
/// on peers that exist.
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
        }
    }

    /// Notes that a dial to this address came to nothing.
    ///
    /// Returns whether that was the last chance it had.
    pub fn missed(&mut self, address: &SocketAddr) -> bool {
        let Some(known) = self.known.get_mut(address) else {
            return false;
        };
        known.misses = known.misses.saturating_add(1);
        if known.misses < MAX_MISSES {
            return false;
        }
        self.known.remove(address);
        true
    }

    /// Addresses worth dialling, the most recently heard from first.
    ///
    /// An address never heard from sorts last but is still offered, since a
    /// node starting out has nothing else and every peer begins unheard.
    pub fn candidates(&self) -> Vec<SocketAddr> {
        let mut ordered: Vec<(SocketAddr, Known)> =
            self.known.iter().map(|(a, k)| (*a, *k)).collect();
        ordered.sort_by(|left, right| {
            right
                .1
                .heard
                .cmp(&left.1.heard)
                .then_with(|| left.0.cmp(&right.0))
        });
        ordered.into_iter().map(|(address, _)| address).collect()
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
                !book.missed(&address(1, 9000)),
                "still worth another try after {attempt} miss(es)"
            );
            assert!(book.contains(&address(1, 9000)));
        }
        assert!(book.missed(&address(1, 9000)), "the last chance is used up");
        assert!(!book.contains(&address(1, 9000)));
        assert!(book.is_empty());
    }

    /// A machine restarting must not cost its address a place in the book.
    #[test]
    fn answering_clears_what_was_held_against_an_address() {
        let mut book = AddressBook::new();
        book.insert(address(1, 9000));

        book.missed(&address(1, 9000));
        book.missed(&address(1, 9000));
        book.answered(&address(1, 9000), 1_000);

        // Back to a full allowance rather than one miss from being dropped.
        for _ in 1..MAX_MISSES {
            assert!(!book.missed(&address(1, 9000)));
        }
        assert!(book.contains(&address(1, 9000)));
    }

    /// Being mentioned again by a peer is not evidence that an address works.
    #[test]
    fn hearing_about_an_address_again_does_not_absolve_it() {
        let mut book = AddressBook::new();
        book.insert(address(1, 9000));
        book.missed(&address(1, 9000));
        book.missed(&address(1, 9000));

        assert!(!book.insert(address(1, 9000)), "not new");
        assert!(
            book.missed(&address(1, 9000)),
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
        assert!(!book.missed(&address(9, 9000)));
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

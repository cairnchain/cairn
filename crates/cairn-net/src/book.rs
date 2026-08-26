//! Where the peers are.
//!
//! A node that has to be told every address by hand is not part of a network,
//! it is part of a configuration file. The book is how a node keeps the
//! addresses it has been given or been told about, and carries them across a
//! restart.

use std::collections::BTreeSet;
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

/// Addresses a node knows about.
#[derive(Clone, Debug, Default)]
pub struct AddressBook {
    known: BTreeSet<SocketAddr>,
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
        self.known.contains(address)
    }

    pub fn iter(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.known.iter().copied()
    }

    /// Records an address, returning whether it was new.
    pub fn insert(&mut self, address: SocketAddr) -> bool {
        if !is_dialable(&address) || self.known.len() >= MAX_ADDRESSES {
            return false;
        }
        self.known.insert(address)
    }

    pub fn remove(&mut self, address: &SocketAddr) -> bool {
        self.known.remove(address)
    }

    /// Addresses to hand to a peer that asked.
    ///
    /// The same addresses come back every time. Varying them matters against a
    /// peer trying to become someone's whole view of the network, and belongs
    /// with peer scoring rather than here.
    pub fn sample(&self, max: usize) -> Vec<PeerAddress> {
        self.known
            .iter()
            .take(max)
            .copied()
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
        for address in &self.known {
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

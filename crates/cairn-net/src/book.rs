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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    /// Whether this address said, last time it introduced itself, that it
    /// keeps the cold set.
    ///
    /// Not written down either, and for a reason of its own beyond the one
    /// above: whether a machine archives is its operator's choice and can stop
    /// being true between one start and the next, so a file carrying it would
    /// be a file that sends a wallet somewhere that has stopped answering.
    /// Heard again on the first handshake of every connection, which costs
    /// nothing, and it is only ever used to decide who to ask first.
    archives: bool,
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
    /// Writes down what an address said about keeping the cold set.
    ///
    /// Only for an address already in the book. Learning about an archivist is
    /// not a reason to write down an address that would not otherwise be kept,
    /// because who this node dials is decided by the book's own rules and not
    /// by what a stranger says it can do for anyone.
    pub fn keeps_the_cold_set(&mut self, address: &SocketAddr, archives: bool) {
        if let Some(known) = self.known.get_mut(address) {
            known.archives = archives;
        }
    }

    /// Addresses that said they keep the cold set, newest first.
    ///
    /// For a wallet that needs a path rebuilt and is connected to nobody who
    /// can rebuild one. Ordered by when each last spoke, because the one that
    /// spoke most recently is the one most likely to answer a dial.
    pub fn archivists(&self) -> Vec<SocketAddr> {
        let mut found: Vec<(u64, SocketAddr)> = self
            .known
            .iter()
            .filter(|(_, known)| known.archives)
            .map(|(address, known)| (known.heard, *address))
            .collect();
        found.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
        found.into_iter().map(|(_, address)| address).collect()
    }

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

/// Whether an address is an address at all.
///
/// Everything the operator hands the book passes only this. Where a node runs
/// is the operator's business: a lab on `10/8`, a devnet on loopback and a
/// machine on the open internet are all somebody's real network, and a book
/// that second-guessed the person who started the node would be refusing the
/// one address they were sure about.
fn is_dialable(address: &SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

/// Which part of the internet an address belongs to.
///
/// The book cares because these are not interchangeable in the one situation
/// that matters: a stranger naming an address is choosing who this node opens
/// a connection to. A peer out on the internet has no way of knowing anything
/// true about the inside of this machine, or of the network this machine sits
/// in, so an address there from such a peer is not a peer address that
/// happens to be private. It is a door the stranger would like knocked on,
/// from a host that is probably allowed to knock: a database with no password
/// because it is only reachable from inside, an admin port, or
/// `169.254.169.254`, which on a rented machine is where the credentials
/// live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Realm {
    /// Reachable from anywhere, which is what a peer address is meant to be.
    Open,
    /// Inside this machine.
    Loopback,
    /// Inside whatever network this machine sits in.
    Private,
    /// Reachable with no router in between, which is where a rented machine
    /// keeps the service that hands out its credentials.
    LinkLocal,
}

/// Which part of the internet `ip` belongs to.
///
/// Not an inventory of every range anybody ever reserved. What is named here
/// is what a stranger has a reason to name, and everything else is treated as
/// out in the world: an address in some unallocated block costs this node one
/// dial that fails, which is what the misses above are for.
pub fn realm_of(ip: IpAddr) -> Realm {
    match ip {
        IpAddr::V4(v4) => realm_of_v4(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Realm::Loopback;
            }
            // A v4 address wearing a v6 hat is still that v4 address, and
            // this is the whole of why the hat comes off: `::ffff:127.0.0.1`
            // reaches the same place `127.0.0.1` does, and a rule that read
            // the two differently would be a rule with a spelling anybody
            // could use. Checked after loopback, because `::1` is inside the
            // older of the two mappings and is not the address `0.0.0.1`.
            if let Some(v4) = v6.to_ipv4() {
                return realm_of_v4(v4);
            }
            // The other hat, and the one a phone actually wears. On an
            // IPv6-only network a NAT64 gateway carries a v4 address inside
            // RFC 6052's well known prefix, so `10.0.0.1` arrives as
            // `64:ff9b::a00:1`. Read as it stands it is an open address in a
            // range nobody owns, and this node would write somebody's inside
            // into its book and pass it on to everyone else.
            //
            // RFC 8215 reserves `64:ff9b:1::/48` for a network's own choice of
            // prefix, and its last thirty two bits carry the address the same
            // way. Both are taken off here; a gateway using some other prefix
            // of its own is not something this can know about from the address
            // alone.
            let octets = v6.octets();
            let well_known = octets[..4] == [0x00, 0x64, 0xff, 0x9b]
                && octets[4..12].iter().all(|byte| *byte == 0);
            let local_use = octets[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01]
                && octets[6..12].iter().all(|byte| *byte == 0);
            if well_known || local_use {
                return realm_of_v4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ));
            }
            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                Realm::LinkLocal
            } else if (octets[0] & 0xfe) == 0xfc {
                Realm::Private
            } else {
                Realm::Open
            }
        }
    }
}

fn realm_of_v4(ip: Ipv4Addr) -> Realm {
    if ip.is_loopback() {
        Realm::Loopback
    } else if ip.is_link_local() {
        Realm::LinkLocal
    } else if ip.is_private() || matches!(ip.octets(), [100, 64..=127, _, _]) {
        // Carrier-grade translation sits with the private ranges: it is
        // somebody's inside, and nothing out here can reach it.
        Realm::Private
    } else {
        Realm::Open
    }
}

/// Whether an address a peer named is one this node will write down.
///
/// The book has three doors and they are not equally trusted, which is the
/// whole of the rule here.
///
/// The operator's door is [`AddressBook::insert_seed`], and it takes whatever
/// it is given. The socket's door is the address a live peer is reachable at,
/// which is the address the connection actually came from with the port the
/// peer named; the part that matters there was observed by this node rather
/// than asserted by anybody, so a stranger cannot use it to name a third
/// party.
///
/// This is the third door, and everything through it is a stranger's choice
/// of who this node talks to. An address out in the world is taken from
/// anybody: that is how a network is learned, and the worst a bad one costs
/// is a dial that fails. A loopback, private or link-local address is not
/// taken from just anybody, because from out on the internet nobody can know
/// anything true about the inside of this machine. It is taken when two
/// things hold at once: this node went out and dialled the peer saying it,
/// rather than answering a connection somebody else chose, and the peer is
/// itself in the same part of the internet as the address it is naming.
///
/// Those two are what let a devnet on loopback and a lab on `10/8` work as
/// they always have, since there every peer a node dials is in the same
/// place as everything it will be told about. Out on the internet they hold
/// for nobody, which is the point: no peer there is in the same realm as this
/// machine's insides, so nothing there gets to name them.
pub fn worth_hearing_about(address: &SocketAddr, teller: Option<IpAddr>, dialled: bool) -> bool {
    if !is_dialable(address) {
        return false;
    }
    let realm = realm_of(address.ip());
    if realm == Realm::Open {
        return true;
    }
    dialled && teller.is_some_and(|at| realm_of(at) == realm)
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

    /// **A stranger used to choose which addresses a node dialled, and the
    /// inside of the machine was among them.**
    ///
    /// Nothing refused loopback, `10/8`, `172.16/12`, `192.168/16` or
    /// `169.254/16`, and any greeted peer could put sixty four addresses in
    /// the book per message for one unit. The node then opened a TCP
    /// connection to whatever was in there and wrote its own handshake into
    /// it. Not a way of forging a request, since the bytes are fixed, but a
    /// way of making a host that is probably allowed to reach an internal
    /// service knock on it, and `169.254.169.254` is where a rented machine
    /// keeps its credentials.
    #[test]
    fn a_peer_out_in_the_world_cannot_name_the_inside_of_this_machine() {
        let far_away = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)));
        for named in [
            "127.0.0.1:22",
            "10.0.0.5:6379",
            "172.16.4.4:9200",
            "192.168.1.1:80",
            "169.254.169.254:80",
            "[::ffff:127.0.0.1]:22",
            "[::1]:22",
            "[fd00::1]:9000",
            "[fe80::1]:9000",
        ] {
            let address: SocketAddr = named.parse().unwrap();
            assert!(
                !worth_hearing_about(&address, far_away, true),
                "{named} was taken from a peer out on the internet"
            );
        }
        // And what a peer address is supposed to be still goes in from
        // anybody, dialled or not: that is how a network is learned, and the
        // worst a bad one costs is a dial that fails.
        let open: SocketAddr = "198.51.100.9:9000".parse().unwrap();
        assert!(worth_hearing_about(&open, far_away, false));
        assert!(worth_hearing_about(&open, None, false));
    }

    /// The devnet and the lab, which are how this software is developed and
    /// run, and where every address in sight is private.
    #[test]
    fn a_peer_in_the_same_place_may_name_addresses_there() {
        let near: SocketAddr = "10.0.0.5:9000".parse().unwrap();
        let neighbour = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)));
        assert!(
            worth_hearing_about(&near, neighbour, true),
            "a peer this node dialled inside the same network"
        );
        assert!(
            !worth_hearing_about(&near, neighbour, false),
            "but not one that dialled in: that connection is somebody else's choice"
        );
        assert!(
            !worth_hearing_about(&near, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), true),
            "and not from inside this machine, which is a different place again"
        );

        let here: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert!(worth_hearing_about(
            &here,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            true
        ));
    }

    /// Whatever the operator says is where their node runs.
    #[test]
    fn the_operators_own_addresses_are_not_second_guessed() {
        let mut book = AddressBook::new();
        assert!(book.insert_seed("127.0.0.1:9000".parse().unwrap()));
        assert!(book.insert_seed("10.0.0.5:9000".parse().unwrap()));
        assert_eq!(book.seeds().len(), 2);
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

    #[test]
    fn an_address_that_keeps_the_cold_set_can_be_found_again() {
        let mut book = AddressBook::new();
        let plain: SocketAddr = "203.0.113.1:9000".parse().unwrap();
        let keeper: SocketAddr = "203.0.113.2:9000".parse().unwrap();
        book.insert(plain);
        book.insert(keeper);
        book.answered(&plain, 100);
        book.answered(&keeper, 200);
        book.keeps_the_cold_set(&plain, false);
        book.keeps_the_cold_set(&keeper, true);

        assert_eq!(
            book.archivists(),
            vec![keeper],
            "the one that said it keeps the set, and only that one"
        );

        // An operator can stop archiving between one connection and the next,
        // and the claim is heard again on every handshake.
        book.keeps_the_cold_set(&keeper, false);
        assert!(book.archivists().is_empty());
    }

    #[test]
    fn what_an_address_keeps_is_not_a_reason_to_write_it_down() {
        let mut book = AddressBook::new();
        let stranger: SocketAddr = "203.0.113.9:9000".parse().unwrap();
        book.keeps_the_cold_set(&stranger, true);
        assert!(
            book.is_empty(),
            "who this node dials is decided by the book's own rules, not by \
             what somebody says they could do for anyone"
        );
    }
}

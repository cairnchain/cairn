//! Where a node that has never spoken to anyone starts.
//!
//! A node with an empty address book has to be told about one machine before
//! it can be told about the rest, and asking somebody who has just downloaded
//! a program to go and find an address first is asking them not to run it. So
//! a starting point is written into the program, in the open, exactly as the
//! first block is.
//!
//! This is the one place the network leans on somebody. It is worth saying
//! plainly what that does and does not mean. A seed hands over two things:
//! addresses of other nodes, and blocks. Both are checked here against rules
//! written in this repository, so a seed that lies is a seed that gets
//! dropped, not a seed that is believed. And it is needed once: a node that
//! has met anybody at all keeps its own book of addresses and never reads this
//! list again.
//!
//! Names, and no addresses behind them. An address written here would be a
//! machine somebody rents today and somebody else rents in two years, and
//! every fresh node in the world would go and knock on a stranger's door. It
//! would also buy less than it looks: against a name that is blocked rather
//! than merely down, three addresses are no harder to block than one. So
//! redundancy belongs in the zone file, where a name can carry several
//! machines and gain another without anybody downloading anything again.
//!
//! What that costs is worth naming too. A network whose only starting point
//! is one name under one domain has one person who could lose it. The answer
//! is not a fallback address, it is a second name that somebody else owns, and
//! that goes in here the day somebody else runs a node worth starting from.

use std::net::{SocketAddr, ToSocketAddrs};

use cairn_ledger::note::NetworkId;

/// The default port a node listens on, and so the one a seed is named with.
///
/// Both halves of that sentence were false. `cairnd` listened on
/// `"0.0.0.0:9944"` written into its own options, and every seed below is
/// named with the port written out again, so this constant was read by nothing
/// but the test beside it: moving it moved nothing. It is what `cairnd` builds
/// its default from now, and `every_written_in_seed_is_named_with_the_default_
/// port` holds the names, which have to stay strings because a `const` array
/// of them cannot be formatted.
pub const DEFAULT_PORT: u16 = 9944;

/// Where to start on the third test network.
///
/// One name, carrying however many machines the zone file says. Adding an
/// entry point is a line in that file; it is not a release.
const TESTNET_6: [&str; 1] = ["seed.cairnchain.org:9944"];

/// The starting points written into the program for `network`.
///
/// The throwaway network has none on purpose: it is one machine talking to
/// itself, and a devnet node that reached a public seed would be a devnet node
/// wasting its time on a network it cannot follow.
pub fn written_in(network: NetworkId) -> &'static [&'static str] {
    match network {
        NetworkId::TESTNET_6 => &TESTNET_6,
        _ => &[],
    }
}

/// The most addresses one name may put in front of a node.
///
/// Every address a name answers with goes into the address book as a seed,
/// and a seed sits outside the book's ceiling and is never removed, because
/// the book's own note says seeds "come from the operator". The operator names
/// the name. What the name answers is the zone's, or whoever answers in its
/// place, and it was taken whole: one reply of four thousand addresses filled
/// the book with entries nothing learned from the network could displace, and
/// the node dialled only the set that reply chose.
///
/// Sixty four keeps what a name is for. A seed service behind one name is a
/// handful of machines, and sixty four of them is redundancy many times over,
/// while leaving a single answer at a sixty fourth of the book.
pub const MOST_PER_NAME: usize = 64;

/// Every address `text` names, up to [`MOST_PER_NAME`].
///
/// All of them rather than the first, because that is what carries the
/// redundancy this list deliberately does not: one name answers with every
/// machine behind it, and a node tries them all. Not without bound, because
/// what a name answers with is not the operator's to vouch for.
pub fn resolve(text: &str) -> Result<Vec<SocketAddr>, String> {
    let found: Vec<SocketAddr> = text
        .to_socket_addrs()
        .map_err(|error| format!("`{text}` is not an address: {error}"))?
        .collect();
    if found.is_empty() {
        return Err(format!("`{text}` resolved to nothing"));
    }
    Ok(what_a_name_is_worth(found))
}

/// The part of a name's answer a node takes: at most [`MOST_PER_NAME`], in the
/// order it came.
///
/// Its own function so that the cap can be asked without a name that answers
/// with thousands, which is not something a test can make a resolver do.
pub fn what_a_name_is_worth(mut found: Vec<SocketAddr>) -> Vec<SocketAddr> {
    found.truncate(MOST_PER_NAME);
    found
}

/// One address, for a setting that can only name one: what to listen on.
pub fn resolve_one(text: &str) -> Result<SocketAddr, String> {
    resolve(text)?
        .first()
        .copied()
        .ok_or_else(|| format!("`{text}` resolved to nothing"))
}

/// The names to start from, given what the operator asked for.
///
/// Kept apart from resolving them because a node holds on to these: a name
/// that would not resolve at the moment it started is asked again later, and
/// that is only possible if the name survived the lookup.
pub fn names_for(asked: &[String], network: NetworkId) -> Vec<String> {
    if asked.is_empty() {
        written_in(network)
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    } else {
        asked.to_vec()
    }
}

/// Every address to start from, given what the operator asked for.
///
/// What they asked for wins outright when they asked for anything, and there a
/// name that will not resolve stops the node: a seed somebody typed and that
/// cannot be reached is a mistake, and a node that quietly went somewhere else
/// instead would hide it.
///
/// With nothing asked for, the list written in above is used, and there a name
/// that will not resolve is passed over rather than fatal. A machine whose
/// name server is not up yet at the moment the node starts should come up
/// anyway; the node asks again once it is running.
pub fn start_from(asked: &[String], network: NetworkId) -> Result<Vec<SocketAddr>, String> {
    gather(&names_for(asked, network), !asked.is_empty(), resolve)
}

/// Every address `names` resolve to by `resolve`, in order and without
/// repeats, stopping at the first failure only when `strict`.
///
/// Apart from [`start_from`] so the lenient half can be asked. It is reached
/// only when a written-in name will not resolve, and whether one does is up to
/// the machine's name server on the day, which a test cannot choose.
fn gather(
    names: &[String],
    strict: bool,
    resolve: impl Fn(&str) -> Result<Vec<SocketAddr>, String>,
) -> Result<Vec<SocketAddr>, String> {
    let mut found: Vec<SocketAddr> = Vec::new();

    for name in names {
        let addresses = match resolve(name) {
            Ok(addresses) => addresses,
            Err(error) if strict => return Err(error),
            Err(_) => continue,
        };
        for address in addresses {
            if !found.contains(&address) {
                found.push(address);
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    /// A name's answer is taken up to a ceiling, and the book still has room
    /// for what the network teaches afterwards.
    ///
    /// Before the ceiling, every address a name answered with became a seed,
    /// and a seed is outside the book's ceiling and never removed. A reply of
    /// five thousand filled the book, and `insert` then refused every address
    /// learned from a peer for the life of the node: it dialled only what one
    /// DNS answer chose. The book's own tests insert one seed.
    #[test]
    fn one_names_answer_cannot_fill_the_book() {
        use crate::book::{AddressBook, MAX_ADDRESSES};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // An answer the size of an eclipse, spread over enough address groups
        // that no per group ceiling is what stops it.
        let answer: Vec<SocketAddr> = (0..(MAX_ADDRESSES + 1_000))
            .map(|index| {
                let index = u32::try_from(index).unwrap_or(0);
                let [a, b, c, d] = (0x0B00_0000u32 + index * 257).to_be_bytes();
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), DEFAULT_PORT)
            })
            .collect();

        let taken = super::what_a_name_is_worth(answer);
        assert_eq!(
            taken.len(),
            super::MOST_PER_NAME,
            "a name's answer is taken up to the ceiling and no further"
        );

        let mut book = AddressBook::default();
        for address in &taken {
            book.insert_seed(*address);
        }
        let learned = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), DEFAULT_PORT);
        assert!(
            book.insert(learned),
            "an address learned from a peer still finds room after a name has \
             been answered"
        );
    }

    /// And `resolve` takes a name's answer through that ceiling.
    ///
    /// The test above holds the ceiling and cannot hold that `resolve` uses
    /// it: no resolver a test can reach answers with thousands, so a `resolve`
    /// that returned what it found untouched stayed green there. So the one
    /// call site is read instead, the way this repository reads the method
    /// table the HTTP header describes.
    #[test]
    fn resolve_takes_a_names_answer_through_the_ceiling() {
        const SOURCE: &str = include_str!("seeds.rs");
        let body = SOURCE
            .split_once("pub fn resolve(text: &str)")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .expect("resolve is written here")
            .0;
        assert!(
            body.contains("what_a_name_is_worth("),
            "resolve hands back a name's answer without the ceiling: {body}"
        );
    }

    /// Every address written into the program is named with the default port.
    ///
    /// The names have to be literals: a `const [&str; N]` cannot be built by
    /// formatting. So the port appears twice, here and in `DEFAULT_PORT`, and
    /// this is what keeps the two agreed. Without it the constant was read by
    /// nothing at all, which is how it came to describe a node that listened
    /// somewhere else.
    #[test]
    fn every_written_in_seed_is_named_with_the_default_port() {
        let suffix = format!(":{}", super::DEFAULT_PORT);
        let mut seen = 0usize;
        for network in [NetworkId::TESTNET_6] {
            for name in super::written_in(network) {
                assert!(
                    name.ends_with(&suffix),
                    "`{name}` is not named with the default port {suffix}"
                );
                seen += 1;
            }
        }
        assert!(seen > 0, "or this walked an empty list and held nothing");
    }

    use super::*;

    #[test]
    fn a_devnet_node_is_left_to_itself() {
        assert!(written_in(NetworkId::DEVNET).is_empty());
        assert!(start_from(&[], NetworkId::DEVNET)
            .expect("nothing to resolve")
            .is_empty());
    }

    /// Every written-in entry has to be something the resolver would accept in
    /// shape, whatever DNS answers today. A missing port is the mistake this
    /// catches, and it is one that would only show up on a machine with no
    /// network, where the name fails for the wrong reason and is passed over.
    #[test]
    fn every_written_in_seed_names_a_port() {
        for name in written_in(NetworkId::TESTNET_6) {
            let (host, port) = name.rsplit_once(':').expect("a seed names a port");
            assert!(!host.is_empty(), "`{name}` names no host");
            assert!(
                port.parse::<u16>().is_ok(),
                "`{name}` does not end in a port number"
            );
        }
    }

    #[test]
    fn what_was_asked_for_wins_and_is_not_repeated() {
        let asked = vec!["127.0.0.1:9944".to_owned(), "127.0.0.1:9944".to_owned()];
        let found = start_from(&asked, NetworkId::TESTNET_6).expect("a literal address resolves");
        assert_eq!(found.len(), 1, "the same address twice is one address");
        assert_eq!(
            found.first().map(ToString::to_string),
            Some("127.0.0.1:9944".to_owned())
        );
    }

    #[test]
    fn a_seed_that_was_asked_for_and_cannot_be_reached_stops_the_node() {
        let asked = vec!["127.0.0.1".to_owned()];
        assert!(start_from(&asked, NetworkId::TESTNET_6).is_err(), "no port");
    }

    /// A written-in name that will not resolve is passed over, and one the
    /// operator typed stops the node.
    ///
    /// The lenient half was never reached: the only written-in name resolves
    /// on any machine with a network, so a `start_from` that stopped the node
    /// over any name at all passed, and a node started before its name server
    /// was up refused to start.
    #[test]
    fn a_written_in_name_that_will_not_resolve_is_passed_over() {
        let reached: SocketAddr = "127.0.0.1:9944".parse().unwrap();
        let names = vec!["down.invalid:9944".to_owned(), "up.invalid:9944".to_owned()];
        let answer = |name: &str| {
            if name.starts_with("up.") {
                Ok(vec![reached])
            } else {
                Err(format!("`{name}` resolved to nothing"))
            }
        };
        assert_eq!(
            gather(&names, false, answer),
            Ok(vec![reached]),
            "a written-in name that would not resolve stopped the node, or \
             took the next one with it"
        );
        assert!(
            gather(&names, true, answer).is_err(),
            "a name the operator asked for and that will not resolve was \
             passed over in silence"
        );
    }

    #[test]
    fn one_address_is_taken_for_a_setting_that_can_only_be_one() {
        let listen = resolve_one("0.0.0.0:9944").expect("a literal address resolves");
        assert_eq!(listen.port(), DEFAULT_PORT);
    }
}

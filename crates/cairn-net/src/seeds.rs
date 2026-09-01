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

/// Every address `text` names.
///
/// All of them, not the first. That is what carries the redundancy this list
/// deliberately does not: one name answers with every machine behind it, and
/// a node tries them all.
pub fn resolve(text: &str) -> Result<Vec<SocketAddr>, String> {
    let found: Vec<SocketAddr> = text
        .to_socket_addrs()
        .map_err(|error| format!("`{text}` is not an address: {error}"))?
        .collect();
    if found.is_empty() {
        return Err(format!("`{text}` resolved to nothing"));
    }
    Ok(found)
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
    let strict = !asked.is_empty();
    let mut found: Vec<SocketAddr> = Vec::new();

    for name in names_for(asked, network) {
        let addresses = match resolve(&name) {
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

    #[test]
    fn one_address_is_taken_for_a_setting_that_can_only_be_one() {
        let listen = resolve_one("0.0.0.0:9944").expect("a literal address resolves");
        assert_eq!(listen.port(), DEFAULT_PORT);
    }
}

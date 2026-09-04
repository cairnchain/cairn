//! A v4 address wearing the other v6 hat.
//!
//! `realm_of` took the `::ffff:` hat off, because `::ffff:127.0.0.1` reaches
//! the same place `127.0.0.1` does and a rule that read the two differently
//! would be a rule with a spelling anybody could use. There is a second
//! spelling, and it is the one a phone actually wears: on an IPv6-only network
//! a NAT64 gateway carries a v4 address inside RFC 6052's well known prefix,
//! so `10.0.0.1` arrives as `64:ff9b::a00:1`.
//!
//! Read as it stands that is an open address in a range nobody owns. So a
//! stranger out on the internet could name somebody's inside, or this node's
//! own loopback, or a cloud metadata service, and have it written into the
//! book and passed on to every other node.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use cairn_net::book::{realm_of, worth_hearing_about, Realm};

/// Both prefixes that carry a v4 address in their last thirty two bits: RFC
/// 6052's well known one, and the range RFC 8215 reserves for a network's own.
#[test]
fn a_v4_address_carried_through_nat64_is_read_as_the_address_it_is() {
    let cases: [(&str, Realm); 8] = [
        ("64:ff9b::7f00:1", Realm::Loopback),     // 127.0.0.1
        ("64:ff9b::a00:1", Realm::Private),       // 10.0.0.1
        ("64:ff9b::c0a8:101", Realm::Private),    // 192.168.1.1
        ("64:ff9b::6440:1", Realm::Private),      // 100.64.0.1, carrier grade
        ("64:ff9b::a9fe:a9fe", Realm::LinkLocal), // 169.254.169.254, metadata
        ("64:ff9b::c633:6404", Realm::Open),      // 198.51.100.4
        ("64:ff9b:1::a00:1", Realm::Private),     // the same, local use prefix
        ("64:ff9b:1::c633:6404", Realm::Open),
    ];
    for (text, want) in cases {
        let ip: IpAddr = text.parse().unwrap();
        assert_eq!(realm_of(ip), want, "{text}");
    }
}

/// The consequence, which is what makes it worth a rule rather than a tidy.
#[test]
fn a_stranger_cannot_name_an_inside_address_through_nat64() {
    let metadata: Ipv6Addr = "64:ff9b::a9fe:a9fe".parse().unwrap();
    let far_away = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)));
    let named = SocketAddr::new(IpAddr::V6(metadata), 80);
    assert!(
        !worth_hearing_about(&named, far_away, false),
        "a stranger out on the internet named a link local address in a \
         spelling the range list did not know, and it was written down"
    );
}

/// **The reserved range is a `/48`, and it was read as though it were a `/96`.**
///
/// RFC 6052's well known prefix is a `/96`: the address is the whole of what
/// follows it, and requiring the bits in between to be zero is right. RFC 8215
/// reserves a `/48`, and the extra forty eight bits are the point of it: a
/// network picks its own translation prefix out of the range. Requiring those
/// to be zero as well recognised exactly one such choice, and every other one
/// walked past the rule.
///
/// So `64:ff9b:1:1::a9fe:a9fe` was an open address in a range nobody owns, and
/// a stranger naming it was passing on a peer. So was `64:ff9b:1:1::7f00:1`,
/// which is this machine.
#[test]
fn any_translation_prefix_out_of_the_reserved_range_is_unwrapped() {
    let cases: [(&str, Realm); 6] = [
        ("64:ff9b:1:1::a9fe:a9fe", Realm::LinkLocal), // 169.254.169.254
        ("64:ff9b:1:abcd::7f00:1", Realm::Loopback),  // 127.0.0.1
        ("64:ff9b:1:0:1::a00:1", Realm::Private),     // 10.0.0.1
        ("64:ff9b:1:ffff:ffff:ffff:c0a8:101", Realm::Private), // 192.168.1.1
        // A translated address that really is out in the world stays out in
        // the world, whichever prefix carried it.
        ("64:ff9b:1:1::c633:6404", Realm::Open), // 198.51.100.4
        ("64:ff9b:1::c633:6404", Realm::Open),
    ];
    for (text, want) in cases {
        let ip: IpAddr = text.parse().unwrap();
        assert_eq!(realm_of(ip), want, "{text}");
    }

    // The consequence, which is the reason this is a rule and not a tidy.
    let metadata: Ipv6Addr = "64:ff9b:1:1::a9fe:a9fe".parse().unwrap();
    let far_away = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)));
    assert!(
        !worth_hearing_about(&SocketAddr::new(IpAddr::V6(metadata), 80), far_away, false),
        "a stranger named a link local address through a translation prefix the \
         rule knew the range of but not the spelling, and it was written down"
    );
}

/// And nothing that is not one of those prefixes is unwrapped. `2001:db8::` is
/// documentation space and its last thirty two bits are not an address.
#[test]
fn only_the_prefixes_that_carry_an_address_are_unwrapped() {
    for text in ["2001:db8::7f00:1", "2002:c0a8:101::", "64:ff9c::7f00:1"] {
        let ip: IpAddr = text.parse().unwrap();
        assert_eq!(
            realm_of(ip),
            Realm::Open,
            "{text} is not a v4 address in a hat"
        );
    }
}

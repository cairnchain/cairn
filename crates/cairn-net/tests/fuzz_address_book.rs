//! The address book file, under a generator that does not know what an
//! address is.
//!
//! `peers.txt` is plain text on purpose, so that an operator can read and
//! edit the list of machines their node will talk to. That is the whole
//! reason this needs a campaign: every other reader in this workspace is fed
//! by something that wrote what it reads, and this one is fed by a person, by
//! a build from a year ago, and by whatever a text editor leaves behind.
//! An audit found it had no fuzz target.
//!
//! What the book must hold, on the way in from a disk and not only on the way
//! in from a peer:
//!
//! 1. **The ceilings hold.** No more than [`MAX_ADDRESSES`] addresses, and no
//!    more than [`MAX_PER_GROUP`] from any one neighbourhood. Both exist
//!    against somebody filling the book to decide who this node talks to, and
//!    a file is a way of filling it: a node whose directory somebody can write
//!    to, a backup restored from a machine that was attacked, or a list
//!    somebody was handed and pasted in.
//! 2. **Nothing undialable gets in.** Port zero, the unspecified address, the
//!    broadcast address and the multicast ranges reach nothing, and a node
//!    that wrote one down would spend dials on it for ever.
//! 3. **Reading a file is not a way to lose the book.** An unreadable or
//!    missing file is an empty book, never a failure, because a lost address
//!    book is meant to cost a node its head start and never its chain.
//! 4. **What is written comes back.** A book saved and read again holds the
//!    same addresses, which is the whole of what carrying a book across a
//!    restart means.
//!
//! Two arms, counted apart. One assembles a file out of address-shaped lines,
//! which is what it takes to get past `parse::<SocketAddr>`; the other bends
//! a file a node wrote.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use cairn_fuzz::{mutate, Arms, Built, Campaign, Rng};
use cairn_net::book::{AddressBook, MAX_ADDRESSES, MAX_PER_GROUP, PEER_FILE};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-fuzz-book-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a scratch directory");
    directory
}

/// Which neighbourhood an address belongs to.
///
/// Written out again here rather than read off the book, and that is the
/// point of it. `book.rs` keeps a running count per group and the ceiling is
/// enforced against that count; a book whose accounting had drifted from the
/// rule it documents would satisfy its own counter and fail this. Two bytes
/// for IPv4 and four for IPv6 is what the module says the rule is.
fn group_of(address: &SocketAddr) -> [u8; 5] {
    match address.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            [4, octets[0], octets[1], 0, 0]
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            [6, octets[0], octets[1], octets[2], octets[3]]
        }
    }
}

/// Whether an address is one this node could dial.
///
/// The same rule as `is_dialable` in `book.rs`, written out for the same
/// reason as `group_of` above.
fn dialable(address: &SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

/// Everything a loaded book has to be, whatever was in the file.
///
/// Returns whether the book holds anything, so a campaign can say how far
/// each arm got. An empty book is the answer to an unreadable file and is
/// therefore not an acceptance.
fn holds(book: &AddressBook, what: &str, case: usize) -> bool {
    let held: Vec<SocketAddr> = book.iter().collect();

    assert_eq!(
        held.len(),
        book.len(),
        "{what}: the book counted {} addresses and handed back {} (case {case})",
        book.len(),
        held.len()
    );

    // The book is filled by strangers, and a file is a stranger. Breaking
    // this would mean a book with no ceiling on the load path: rent one
    // machine, write four million addresses into somebody's peers.txt, and
    // the node holds all of them.
    assert!(
        held.len() <= MAX_ADDRESSES,
        "{what}: the book came back holding {} addresses, past the ceiling of \
         {MAX_ADDRESSES} (case {case})",
        held.len()
    );

    let mut per_group: BTreeMap<[u8; 5], usize> = BTreeMap::new();
    for address in &held {
        // A node that dialled this would be dialling nothing, for ever: the
        // misses that drop an address are counted against dials that failed,
        // and an address that cannot be dialled at all never gets one.
        assert!(
            dialable(address),
            "{what}: the book came back holding {address}, which reaches nothing \
             (case {case})"
        );
        let count = per_group.entry(group_of(address)).or_insert(0);
        *count = count.saturating_add(1);
    }

    // The ceiling that matters more than the one above. The whole book can be
    // filled from one range for the price of renting that range, and a node
    // that only ever talks to one operator can be told anything about the
    // chain. Breaking it on the load path would mean the file is the door
    // that is not watched.
    for (group, count) in &per_group {
        assert!(
            *count <= MAX_PER_GROUP,
            "{what}: neighbourhood {group:?} came back holding {count} addresses, \
             past the ceiling of {MAX_PER_GROUP} (case {case})"
        );
    }

    // What the book says it knows and what it hands back are the same set.
    for address in &held {
        assert!(
            book.contains(address),
            "{what}: the book handed back {address} and denies knowing it (case {case})"
        );
    }

    !held.is_empty()
}

/// A peers file assembled out of address-shaped lines.
///
/// Drawn bytes reach `SocketAddr::from_str` and are refused by it every time:
/// the parser wants digits, dots or colons, and a port. So the fresh arm is
/// built, and `the_fresh_arm_is_worth_running` measures what that is worth.
fn a_peers_file(rng: &mut Rng) -> Vec<u8> {
    let mut text = String::new();
    for _ in 0..rng.between(0, 40) {
        match rng.below(16) {
            // Things an editor or an older build leaves behind, none of which
            // is an address and all of which have to be stepped over rather
            // than stop the read.
            0 => text.push_str("# written by cairn 0.1\n"),
            1 => text.push('\n'),
            2 => text.push_str("   \n"),
            3 => {
                let junk = rng.between(0, 24);
                let bytes = rng.plausible_bytes(junk);
                text.push_str(&String::from_utf8_lossy(&bytes));
                text.push('\n');
            }
            // An address with the trailing carriage return a file edited on
            // another operating system carries.
            4 => {
                let _ = writeln!(text, "{}\r", an_address(rng));
            }
            // An address with the spaces a person leaves around it.
            5 => {
                let _ = writeln!(text, "  {}  ", an_address(rng));
            }
            // An address with no port, which an older build might have
            // written and which reaches nothing.
            6 => {
                let _ = writeln!(text, "{}", an_address(rng).ip());
            }
            // The last line with no newline after it, which is what a write
            // cut short leaves.
            7 => {
                let _ = write!(text, "{}", an_address(rng));
            }
            _ => {
                let _ = writeln!(text, "{}", an_address(rng));
            }
        }
    }
    text.into_bytes()
}

/// An address, weighted towards the ones the ceilings are about.
fn an_address(rng: &mut Rng) -> SocketAddr {
    let port = match rng.below(8) {
        // Port zero reaches nothing and is the one a hand-edited file is
        // likeliest to hold, because it is what an unset port prints as.
        0 => 0,
        1 => u16::MAX,
        _ => u16::try_from(rng.between(1, 65_535)).unwrap_or(9_000),
    };
    let ip = match rng.below(10) {
        // A handful of neighbourhoods, so the per-group ceiling is reached
        // rather than only asserted. Three /16 ranges over a generator that
        // writes up to forty lines a file is what it takes.
        0..=5 => {
            let block = u8::try_from(rng.below(3)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::new(
                203,
                block,
                u8::try_from(rng.below(256)).unwrap_or(0),
                u8::try_from(rng.below(256)).unwrap_or(0),
            ))
        }
        6 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        7 => IpAddr::V4(Ipv4Addr::BROADCAST),
        8 => IpAddr::V4(Ipv4Addr::new(
            224,
            u8::try_from(rng.below(256)).unwrap_or(0),
            0,
            1,
        )),
        _ => IpAddr::V6(Ipv6Addr::from(rng.array::<16>())),
    };
    SocketAddr::from((ip, port))
}

/// Files a node itself wrote, for the bending arm to start from.
fn corpus() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();

    let mut small = String::new();
    for last in 0u8..8 {
        let _ = writeln!(small, "203.0.113.{last}:9333");
    }
    seeds.push(small.into_bytes());

    // One neighbourhood at its ceiling, which is the file that most nearly
    // reaches the check the campaign is about.
    let mut crowded = String::new();
    for index in 0..MAX_PER_GROUP {
        let _ = writeln!(crowded, "198.51.{}.1:9333", index % 256);
    }
    seeds.push(crowded.into_bytes());

    seeds.push(b"[2001:db8::1]:9333\n[::1]:9333\n".to_vec());
    seeds.push(b"127.0.0.1:9333\n".to_vec());
    seeds.push(Vec::new());
    seeds
}

#[test]
fn any_file_at_all_gives_a_book_within_its_ceilings() {
    let campaign = Campaign::named("book: any file");
    let directory = scratch("anyfile");
    let path = directory.join(PEER_FILE);
    let corpus = corpus();
    let mut arms = Arms::default();

    let ran = campaign.run(4_000, |case, rng| {
        let (built, bytes) = if rng.bool() {
            (Built::FromNothing, a_peers_file(rng))
        } else {
            let seed = rng.pick(&corpus).cloned().unwrap_or_default();
            (Built::ByBending, mutate(rng, &seed, &corpus))
        };
        std::fs::write(&path, &bytes).expect("the scratch file is writable");
        let book = AddressBook::load(&directory);
        arms.saw(built, holds(&book, "any file", case));
    });

    arms.report("book: any file");
    assert!(ran.cases >= 500, "the campaign ran {} cases", ran.cases);
    assert!(
        arms.from_nothing.accepted > 0,
        "not one assembled file put an address in the book: {:?}",
        arms.from_nothing
    );
    assert!(
        arms.by_bending.accepted > 0,
        "not one bent file put an address in the book: {:?}",
        arms.by_bending
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A file made entirely of one neighbourhood, which is the attack the
/// per-group ceiling is against.
///
/// The campaign above asserts the ceiling and the assertion is satisfied by a
/// book that never gets near it. This reaches it on purpose, every case, and
/// fails if the load path stops enforcing it. Without this the assertion up
/// there is about nothing.
#[test]
fn a_file_holding_one_neighbourhood_is_cut_to_the_ceiling() {
    let campaign = Campaign::named("book: one neighbourhood");
    let directory = scratch("crowded");
    let path = directory.join(PEER_FILE);

    let ran = campaign.run(64, |case, rng| {
        let block = u8::try_from(rng.below(256)).unwrap_or(0);
        let lines = MAX_PER_GROUP.saturating_mul(rng.between(2, 8));
        let mut text = String::new();
        for index in 0..lines {
            let _ = writeln!(
                text,
                "198.{block}.{}.{}:9333",
                index / 256 % 256,
                index % 256
            );
        }
        std::fs::write(&path, text.as_bytes()).expect("the scratch file is writable");

        let book = AddressBook::load(&directory);
        assert!(
            holds(&book, "one neighbourhood", case),
            "a file of {lines} addresses put nothing in the book (case {case})"
        );
        assert_eq!(
            book.len(),
            MAX_PER_GROUP,
            "a file naming {lines} addresses in one neighbourhood loaded {} of \
             them (case {case})",
            book.len()
        );
    });

    assert!(ran.cases >= 1, "the campaign ran {} cases", ran.cases);
    let _ = std::fs::remove_dir_all(&directory);
}

/// A file with more addresses than the whole book holds.
///
/// Spread across neighbourhoods, so what stops it is the book's own ceiling
/// and not the one above. The same argument as the test before it: the
/// assertion in `holds` is satisfied by never reaching the number, and this
/// reaches it.
#[test]
fn a_file_longer_than_the_book_is_cut_to_the_book() {
    let directory = scratch("overfull");
    let path = directory.join(PEER_FILE);

    // Every address in its own /16 up to the ceiling, then more of the same.
    // Two hundred and fifty six blocks of thirty two is eight thousand one
    // hundred and ninety two, which is twice the book.
    let mut text = String::new();
    let mut written = 0usize;
    for high in 0u8..=255 {
        for low in 0..MAX_PER_GROUP {
            let _ = writeln!(text, "198.{high}.{}.1:9333", low % 256);
            written += 1;
        }
    }
    assert!(
        written > MAX_ADDRESSES,
        "the file has to be longer than the book to test anything"
    );
    std::fs::write(&path, text.as_bytes()).expect("the scratch file is writable");

    let book = AddressBook::load(&directory);
    assert!(holds(&book, "overfull", 0));
    assert_eq!(
        book.len(),
        MAX_ADDRESSES,
        "a file naming {written} addresses loaded {} of them",
        book.len()
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A file that cannot be read at all is an empty book and never a failure.
///
/// `load` has no error to return, which is a design decision and not an
/// oversight: a lost address book costs a node its head start, never its
/// chain. So the property is that every unreadable shape produces a book
/// rather than a panic, and this covers the shapes that are not text.
#[test]
fn a_file_that_is_not_text_is_an_empty_book() {
    let campaign = Campaign::named("book: not text");
    let directory = scratch("nottext");
    let path = directory.join(PEER_FILE);
    let mut empty = 0usize;

    let ran = campaign.run(2_000, |case, rng| {
        let len = rng.between(0, 512);
        // Drawn rather than plausible, on purpose: this arm is about what is
        // not text at all, and the boundary bytes are most of what is not.
        let bytes = rng.bytes(len);
        std::fs::write(&path, &bytes).expect("the scratch file is writable");

        let book = AddressBook::load(&directory);
        holds(&book, "not text", case);
        if book.is_empty() {
            empty += 1;
        }
    });

    assert!(ran.cases >= 200, "the campaign ran {} cases", ran.cases);
    // Almost all of it: `read_to_string` refuses the file outright the moment
    // one byte is not UTF-8, and what survives that is refused line by line.
    assert!(
        empty.saturating_mul(10) > ran.cases.saturating_mul(9),
        "{empty} of {} drawn files gave an empty book, which is too few to be \
         the refusal path",
        ran.cases
    );

    // And the two shapes that are not a file at all.
    let _ = std::fs::remove_file(&path);
    assert!(
        AddressBook::load(&directory).is_empty(),
        "a missing file is an empty book"
    );
    assert!(
        AddressBook::load(directory.join("nowhere")).is_empty(),
        "a missing directory is an empty book"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A book written down and read back holds the same addresses.
///
/// This is the whole of what carrying a book across a restart means, and it
/// is the one property here that the file format and the parser have to agree
/// on rather than the parser alone.
#[test]
fn a_book_written_down_comes_back_the_same() {
    let campaign = Campaign::named("book: round trip");
    let directory = scratch("roundtrip");

    let ran = campaign.run(200, |case, rng| {
        let mut book = AddressBook::new();
        for _ in 0..rng.between(0, 120) {
            book.insert(an_address(rng));
        }
        let before: Vec<SocketAddr> = book.iter().collect();

        book.save(&directory)
            .expect("the scratch directory is writable");
        let again = AddressBook::load(&directory);
        let after: Vec<SocketAddr> = again.iter().collect();

        // A book holds only what went through `insert`, so everything in it
        // is under both ceilings already and the reload cannot refuse any of
        // it. A mismatch would mean the file cannot carry something the book
        // can hold: a v6 address written in a spelling the parser does not
        // take, or an address whose text form loses the scope it went in
        // with.
        assert_eq!(
            before,
            after,
            "a book of {} addresses came back as {} (case {case})",
            before.len(),
            after.len()
        );
    });

    assert!(ran.cases >= 50, "the campaign ran {} cases", ran.cases);
    let _ = std::fs::remove_dir_all(&directory);
}

/// A full book survives a restart without losing anything.
///
/// The campaign above only ever builds books of a hundred and twenty
/// addresses, so it never asks the question that matters: a book at the
/// ceiling is written out sorted and read back in that order, and every
/// address after the first thirty two of a neighbourhood is offered to an
/// `insert` that has to make room for it. A reload that dropped so much as
/// one would be a node quietly shedding peers at every start.
#[test]
fn a_full_book_survives_being_written_down() {
    let directory = scratch("fullroundtrip");

    let mut book = AddressBook::new();
    for high in 0u8..=255 {
        for low in 0..MAX_PER_GROUP {
            let last = u8::try_from(low % 256).unwrap_or(0);
            book.insert(SocketAddr::from((Ipv4Addr::new(198, high, last, 1), 9_333)));
        }
    }
    assert_eq!(book.len(), MAX_ADDRESSES, "the book has to be full");
    let before: Vec<SocketAddr> = book.iter().collect();

    book.save(&directory)
        .expect("the scratch directory is writable");
    let again = AddressBook::load(&directory);
    assert!(holds(&again, "full round trip", 0));
    assert_eq!(
        again.iter().collect::<Vec<SocketAddr>>(),
        before,
        "a full book lost addresses on the way back off the disk"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The measurement behind the fresh arm being assembled rather than drawn.
#[test]
fn the_fresh_arm_is_worth_running() {
    let directory = scratch("worthwhile");
    let path = directory.join(PEER_FILE);
    let mut rng = Rng::new(29);
    let mut assembled = 0usize;
    let mut drawn = 0usize;

    for _ in 0..500 {
        let bytes = a_peers_file(&mut rng);
        std::fs::write(&path, &bytes).expect("the scratch file is writable");
        if !AddressBook::load(&directory).is_empty() {
            assembled += 1;
        }

        let len = rng.between(0, 400);
        let bytes = rng.bytes(len);
        std::fs::write(&path, &bytes).expect("the scratch file is writable");
        if !AddressBook::load(&directory).is_empty() {
            drawn += 1;
        }
    }

    eprintln!("book: {assembled} assembled files loaded something, {drawn} drawn ones");
    assert!(
        assembled > 250,
        "only {assembled} of 500 assembled files put an address in the book"
    );
    assert!(
        drawn.saturating_mul(10) < assembled,
        "{drawn} drawn files put an address in the book against {assembled} \
         assembled ones, so the assembler is no longer buying anything"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

//! The versions the specification says this build speaks, held to the code.
//!
//! The handshake paragraph said the protocol version "is 7 today" through the
//! whole of version eight. A number copied into prose has no reader but a
//! person, so nothing noticed when the constant moved.
//!
//! The same held for the allowance table, which the specification says is what
//! the reference implementation charges. Six of its rows were prices the
//! project had changed, each because the old one was a defect, and the table
//! went on publishing the old ones through three later edits of the document.
//! So every row is priced here through the implementation, and so is the tag
//! every message is sent under.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use cairn_chain::{ChainStore, Located};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BLOCK_VERSION};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Joining, Placed};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::{Keeps, Message, PeerAddress, PROTOCOL_VERSION};
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

/// The specification with every run of whitespace made one space, so that a
/// phrase is found whichever line it was wrapped across.
fn specification() -> String {
    include_str!("../../../docs/cairn-specification.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn the_specification_states_the_protocol_version_this_build_speaks() {
    let stated = format!("handshake, it is {PROTOCOL_VERSION} today,");
    assert!(
        specification().contains(&stated),
        "the specification does not say `{stated}`"
    );
}

#[test]
fn the_specification_states_the_highest_block_version_this_build_knows() {
    let stated = format!("up to a ceiling, which is {BLOCK_VERSION} today.");
    assert!(
        specification().contains(&stated),
        "the specification does not say `{stated}`"
    );
}

/// A moment at the start of an allowance window, so that everything priced
/// here falls in one.
const NOW: u64 = 2_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn greeted() -> PeerState {
    PeerState {
        greeted: true,
        ..PeerState::default()
    }
}

/// What a greeted peer is charged for `message`, the way a node charges it:
/// the frame by its size before it is decoded, and then the message.
fn charged_to(peer: &mut PeerState, chain: &mut ChainStore, message: Message) -> u32 {
    let before = peer.spent;
    assert!(
        peer.afford_reading(&message.encode(), NOW),
        "a fresh window could not pay for reading a {}",
        message.kind()
    );
    let mut local = Local {
        chain,
        keeps: Keeps::default(),
        listen: 0,
        nonce: 1,
    };
    on_message(&mut local, peer, message, NOW);
    peer.spent - before
}

fn charged(message: Message) -> u32 {
    charged_to(&mut greeted(), &mut ChainStore::new(params()), message)
}

fn identifiers(count: u64) -> Vec<Located> {
    (0..count)
        .map(|at| Located::new(at, Hash32::from_bytes([7; 32])))
        .collect()
}

fn addresses(count: u8) -> Vec<PeerAddress> {
    (0..count)
        .map(|last| {
            PeerAddress(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)),
                9,
            ))
        })
        .collect()
}

fn a_transfer(inputs: u32, outputs: u32) -> Transfer {
    let spending = (0..inputs)
        .map(|index| Input::hot(NoteId::new(Hash32::from_bytes([3; 32]), index)))
        .collect();
    let owner = SecretKey::from_bytes(&[5; 32]).public_key();
    let created = (0..outputs)
        .map(|_| Note::new(Amount::from_pebbles(1).unwrap(), owner))
        .collect();
    Transfer::new(spending, created)
}

/// The first block of a chain, mined so that it lands, and paying enough
/// owners to weigh more than one unit.
fn a_first_block() -> Block {
    let params = params();
    let state = LedgerState::new();
    let height = state.next_height().unwrap();
    let owners = u64::try_from(params.max_coinbase_outputs).unwrap();
    let one = Amount::from_pebbles(1).unwrap();
    let rest = Amount::from_pebbles(params.initial_reward.as_pebbles() - (owners - 1)).unwrap();
    let outputs = (0..owners)
        .map(|index| {
            let mut seed = [2u8; 32];
            seed[..8].copy_from_slice(&index.to_le_bytes());
            let value = if index == 0 { rest } else { one };
            Note::new(value, SecretKey::from_bytes(&seed).public_key())
        })
        .collect();
    let coinbase = CoinbaseTransaction::new(height, outputs);
    let block = assemble_block(&state, coinbase, Vec::new(), &params, 1_600, height).unwrap();
    mine_block(block, 1 << 22).unwrap()
}

/// Units for the bytes of `message`, the rate the whole table is written in.
fn per_512_bytes(message: &Message) -> u32 {
    u32::try_from(message.encode().len().div_ceil(512)).unwrap()
}

/// Holds that a greeted peer is charged for `message` what its row states, or
/// what reading its frame cost where that is more, since a message pays the
/// larger of the two.
fn priced(message: Message, stated: u32) {
    let kind = message.kind();
    let size = message.encode().len();
    let expected = stated.max(per_512_bytes(&message));
    let paid = charged(message);
    assert_eq!(
        paid,
        expected,
        "a {kind} of {size} bytes was charged {paid}, where its row says {stated} and its frame \
         costs {}",
        size.div_ceil(512)
    );
}

/// A row of the allowance table as the specification writes it.
fn row(message: &str, cost: &str) -> String {
    format!("<tr><td>{message}</td><td>{cost}</td></tr>")
}

/// Every row of the allowance table is what the reference implementation
/// charges.
///
/// Each row is found in the document as written here, and the price it states
/// is worked out here from its own words and compared with what a node takes
/// out of a peer's window for a message of that kind, at the smallest size, at
/// the ceiling it names and one past it. A row the document changes and the
/// code does not, or the other way round, fails here.
#[test]
fn every_row_of_the_allowance_table_is_what_the_implementation_charges() {
    let document = specification();
    let rows = [
        row("GetChain", "8, plus 1 per locator entry, counted up to 64"),
        row(
            "GetBlocks",
            "1 per height, counted up to 128, and each block as it is served",
        ),
        row("GetHeaders", "1 per header, counted up to 512"),
        row("GetProofs", "8 per position, counted up to 64"),
        row("GetPeers", "64"),
        row("GetJoin", "1 024"),
        row("Peers", "1 per address carried, counted up to 64"),
        row("Announce", "1 per identifier carried, counted up to 512"),
        row("Headers", "1 per header carried, counted up to 512"),
        row("Proofs", "8 per path carried, counted up to 64"),
        row("Transaction", "4 per input and 4 per output"),
        row(
            "Block this node asked for",
            "1 per 512 bytes of the message, rounded up, and 1 once it is on the branch this node follows",
        ),
        row(
            "Block nobody asked for, or announced and then asked for",
            "8, plus 1 per 512 bytes of the message, rounded up",
        ),
        row("Ping, Pong, Chain", "1"),
        row("Hello, Welcome, JoinPart", "nothing"),
    ];
    for stated in &rows {
        assert!(
            document.contains(stated.as_str()),
            "the allowance table does not carry `{stated}`"
        );
    }

    for count in [0, 1, 64, 65] {
        let locator = identifiers(count);
        let stated = 8 + u32::try_from(count.min(64)).unwrap();
        priced(Message::GetChain { locator }, stated);
    }
    for count in [0, 1, 128, 129] {
        let stated = u32::try_from(count.min(128)).unwrap();
        priced(Message::GetBlocks((0..count).collect()), stated);
    }
    for count in [0, 1, 512, 513, 1_000_000] {
        let stated = u32::try_from(count.min(512)).unwrap();
        priced(Message::GetHeaders { from: 0, count }, stated);
    }
    for count in [0, 1, 64, 65] {
        let stated = 8 * u32::try_from(count.min(64)).unwrap();
        priced(Message::GetProofs((0..count).collect()), stated);
    }
    priced(Message::GetPeers, 64);
    for what in [Joining::Weight, Joining::Ledger] {
        priced(Message::GetJoin { what, part: 0 }, 1_024);
    }
    for count in [0, 1, 64, 65] {
        priced(Message::Peers(addresses(count)), u32::from(count.min(64)));
    }
    for count in [1, 512, 513] {
        let stated = u32::try_from(count.min(512)).unwrap();
        priced(Message::Announce(identifiers(count)), stated);
    }
    let header = a_first_block().header;
    for count in [1, 512, 513] {
        let headers = vec![header; count];
        let stated = u32::try_from(count.min(512)).unwrap();
        priced(Message::Headers { from: 0, headers }, stated);
    }
    for count in [1, 64, 65] {
        let placed = (0..count)
            .map(|position| Placed {
                position,
                proof: None,
            })
            .collect();
        priced(
            Message::Proofs(placed),
            8 * u32::try_from(count.min(64)).unwrap(),
        );
    }
    for (inputs, outputs) in [(1, 1), (1, 2), (2, 256), (256, 1), (256, 256)] {
        let transfer = a_transfer(inputs, outputs);
        priced(
            Message::Transaction(Box::new(transfer)),
            4 * inputs + 4 * outputs,
        );
    }

    // A block asked for that lands, and the same block asked for where it
    // cannot land, since its parent is nowhere.
    let landing = Message::Block(Box::new(a_first_block()));
    assert!(
        per_512_bytes(&landing) > 1,
        "the fixture's block weighs one unit"
    );
    let mut asked = greeted();
    asked.awaiting.insert(0);
    let mut chain = ChainStore::new(params());
    assert_eq!(charged_to(&mut asked, &mut chain, landing.clone()), 1);
    assert_eq!(chain.height(), Some(0), "the fixture's block did not land");
    let mut asked = greeted();
    asked.awaiting.insert(0);
    let mut elsewhere = ChainStore::new(params());
    let mut orphan = a_first_block();
    orphan.header.height = 7;
    orphan.header.previous = Hash32::from_bytes([9; 32]);
    orphan.header.difficulty = 1;
    asked.awaiting.insert(7);
    let orphan = Message::Block(Box::new(orphan));
    assert_eq!(
        charged_to(&mut asked, &mut elsewhere, orphan.clone()),
        per_512_bytes(&orphan)
    );

    // Nobody asked, or it was announced first: the floor and the bytes, landed
    // or not.
    assert_eq!(charged(orphan.clone()), 8 + per_512_bytes(&orphan));
    let mut offered = greeted();
    offered.awaiting.insert(0);
    offered.offered.insert(0);
    assert_eq!(
        charged_to(
            &mut offered,
            &mut ChainStore::new(params()),
            landing.clone()
        ),
        8 + per_512_bytes(&landing)
    );

    for small in [
        Message::Ping(1),
        Message::Pong(1),
        Message::Chain { from: 0, count: 0 },
    ] {
        priced(small, 1);
    }

    // Nothing for an introduction, which is read before a peer has one.
    for introduction in [
        Message::Hello(a_handshake()),
        Message::Welcome(a_handshake()),
    ] {
        let mut stranger = PeerState::default();
        let mut chain = ChainStore::new(params());
        assert!(stranger.afford_reading(&introduction.encode(), NOW));
        let mut local = Local {
            chain: &mut chain,
            keeps: Keeps::default(),
            listen: 0,
            nonce: 1,
        };
        on_message(&mut local, &mut stranger, introduction, NOW);
        assert_eq!(stranger.spent, 0, "an introduction was charged");
    }
    // And nothing for a piece of a join answer, which a node takes before the
    // allowance and never hands to the layer that prices messages, so reading
    // it is the only charge there could be.
    let piece = Message::JoinPart {
        what: Joining::Ledger,
        at: Hash32::ZERO,
        part: 0,
        parts: 1,
        bytes: vec![0; 64 * 1024],
    };
    let mut peer = greeted();
    assert!(peer.afford_reading(&piece.encode(), NOW));
    assert_eq!(
        peer.spent, 0,
        "reading a piece of a join answer was charged"
    );
}

/// The window and the rate the table is written in are the ones the
/// implementation keeps.
#[test]
fn the_window_and_the_rate_a_frame_is_charged_at_are_the_ones_stated() {
    let document = specification();
    for stated in [
        "A peer's allowance is 8 192 units per window. A window is ten seconds,",
        "charge every frame from a peer that has introduced itself one unit per 512 bytes, rounded up, before it decodes it",
        "so a message pays the larger of the two and never both",
    ] {
        assert!(document.contains(stated), "the allowance section does not say `{stated}`");
    }

    // 8 192 units in a window of ten seconds, counted off the clock.
    let mut chain = ChainStore::new(params());
    let mut peer = greeted();
    let mut local = Local {
        chain: &mut chain,
        keeps: Keeps::default(),
        listen: 0,
        nonce: 1,
    };
    let mut pings = 0u32;
    while answered(&mut local, &mut peer, NOW + 9) {
        pings += 1;
        assert!(pings <= 8_192, "a window paid for more than 8 192 units");
    }
    assert_eq!(pings, 8_192, "a window paid for {pings} units");
    assert!(
        answered(&mut local, &mut peer, NOW + 10),
        "ten seconds on is not a fresh window"
    );

    // A frame is charged one unit per 512 bytes, rounded up, and a message
    // whose own price is less pays that and no more.
    for (bytes, units) in [(1, 1), (512, 1), (513, 2), (4_096, 8)] {
        let mut peer = greeted();
        assert!(peer.afford_reading(&vec![0; bytes], NOW));
        assert_eq!(peer.spent, units, "a frame of {bytes} bytes");
        let mut chain = ChainStore::new(params());
        let mut local = Local {
            chain: &mut chain,
            keeps: Keeps::default(),
            listen: 0,
            nonce: 1,
        };
        on_message(&mut local, &mut peer, Message::Pong(1), NOW);
        assert_eq!(
            peer.spent, units,
            "a pong read out of a frame of {bytes} bytes"
        );
    }
}

/// Whether a ping at `now` is answered, which is whether the window pays for it.
fn answered(local: &mut Local<'_>, peer: &mut PeerState, now: u64) -> bool {
    !on_message(local, peer, Message::Ping(1), now)
        .reply
        .is_empty()
}

fn a_handshake() -> Handshake {
    Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: Hash32::ZERO,
        tip: Hash32::ZERO,
        height: 0,
        total_work: 0,
        listen: 9,
        nonce: 3,
        keeps: Keeps::default(),
    }
}

/// Every message is sent under the tag the message table gives it, and a
/// handshake is the size the document says.
///
/// Read off the table rather than written out again here, so that a row the
/// document renumbers and the code does not, or a message the code adds and
/// the table leaves out, fails.
#[test]
fn every_message_is_sent_under_the_tag_the_table_gives_it() {
    let document = specification();
    let section = document
        .split_once("## The message set")
        .and_then(|(_, after)| after.split_once("Every counted sequence here carries a ceiling"))
        .map(|(section, _)| section)
        .expect("the specification has a message set with its table first");
    let mut table = Vec::new();
    let mut rest = section;
    while let Some(at) = rest.find("<tr><td class=\"n\">") {
        rest = &rest[at + "<tr><td class=\"n\">".len()..];
        let (tag, after) = rest.split_once("</td><td>").unwrap();
        let (name, _) = after.split_once("</td>").unwrap();
        table.push((tag.parse::<u8>().unwrap(), name.to_owned()));
    }

    let block = a_first_block();
    let messages = [
        Message::Hello(a_handshake()),
        Message::Welcome(a_handshake()),
        Message::Ping(1),
        Message::Pong(1),
        Message::GetChain {
            locator: identifiers(1),
        },
        Message::Chain { from: 0, count: 1 },
        Message::GetBlocks(vec![0]),
        Message::Block(Box::new(block.clone())),
        Message::Announce(identifiers(1)),
        Message::GetPeers,
        Message::Peers(addresses(1)),
        Message::Transaction(Box::new(a_transfer(1, 1))),
        Message::GetJoin {
            what: Joining::Weight,
            part: 0,
        },
        Message::JoinPart {
            what: Joining::Weight,
            at: Hash32::ZERO,
            part: 0,
            parts: 1,
            bytes: vec![1],
        },
        Message::GetHeaders { from: 0, count: 1 },
        Message::Headers {
            from: 0,
            headers: vec![block.header],
        },
        Message::GetProofs(vec![0]),
        Message::Proofs(vec![Placed {
            position: 0,
            proof: None,
        }]),
    ];
    for message in &messages {
        let named: String = message.kind().split_whitespace().collect();
        let Some((tag, _)) = table
            .iter()
            .find(|(_, name)| name.eq_ignore_ascii_case(&named))
        else {
            panic!("the message table has no row for a {}", message.kind());
        };
        assert_eq!(
            message.encode()[0],
            *tag,
            "a {} is sent under another tag than the table gives it",
            message.kind()
        );
    }
    let tags: Vec<u8> = table.iter().map(|(tag, _)| *tag).collect();
    let expected: Vec<u8> = (0..u8::try_from(messages.len()).unwrap()).collect();
    assert_eq!(
        tags, expected,
        "the message table is not one row for each message, in the order of its tags"
    );

    assert!(document.contains("A handshake is 108 bytes"));
    assert_eq!(
        Message::Hello(a_handshake()).encode().len(),
        1 + 108,
        "a handshake is not the 108 bytes the document says, after its tag"
    );
}

//! Every message a peer can send, and the frame reader underneath them.
//!
//! `crates/cairn-net/tests/fuzz.rs` already feeds bent messages to the
//! decoders and checks nothing breaks. This asks the harder question, one the
//! module's own opening paragraph makes: it says "every list a peer can send
//! is capped, and every cap is enforced while decoding". That is a claim with
//! a shape, and a shape can be tested.
//!
//! The test that tells the two apart is a count with nothing behind it. A
//! decoder that read the count and compared it against its cap answers by
//! naming what it refused. One that built the list until the bytes ran out
//! answers that the input ended, which is a decoder that did the work first
//! and asked afterwards.
//!
//! Eight of the eighteen message variants answer the second way. They are
//! bounded, because a frame is capped at a megabyte, so this is not the
//! unbounded allocation the caps were written against. It is the same rule
//! read late: `GetProofs` names a cap of sixty four positions and will build a
//! hundred and thirty one thousand of them first. Pinned below, measured, with
//! what the fix is.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{self, Read};

use cairn_accumulator::ForestProof;
use cairn_chain::{Located, MAX_LOCATOR};
use cairn_crypto::{PublicKey, SecretKey, Signature};
use cairn_fuzz::{mutate, Campaign, Rng};
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_net::message::PeerAddress;
use cairn_net::message::{
    Handshake, Joining, Keeps, Message, Placed, JOIN_PART_BYTES, MAX_ANNOUNCED, MAX_CHAIN,
    MAX_HEADERS, MAX_JOIN_PARTS, MAX_PROVEN, MAX_REQUESTED, MAX_SHARED_ADDRESSES, PROTOCOL_VERSION,
};
use cairn_net::wire::{read_message, write_message, Incoming, WireError, MAX_FRAME_BYTES};
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::{Amount, Hash32};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

fn keys() -> &'static [PublicKey; 2] {
    static KEYS: OnceLock<[PublicKey; 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            SecretKey::from_bytes(&[11; 32]).public_key(),
            SecretKey::from_bytes(&[12; 32]).public_key(),
        ]
    })
}

/// Whatever decodes re-encodes to the bytes it came from, and reads a settled
/// number of them.
///
/// Nothing in this file needs the weaker claim `cairn-ledger` makes for its
/// join answers: no message carries a `Forest`. A `JoinPart` carries one
/// inside its opaque payload, and opaque is exactly what saves it.
fn round_trips<T: Encode + Decode>(bytes: &[u8], what: &str, case: usize) -> bool {
    let Ok(value) = T::decode(bytes) else {
        return false;
    };
    assert_eq!(
        value.encode(),
        bytes,
        "{what} accepted an encoding it does not itself produce (case {case}, bytes {})",
        hex::encode(bytes)
    );

    let mut trailing = bytes.to_vec();
    trailing.extend_from_slice(&[0x5a; 5]);
    let mut reader = Reader::new(&trailing);
    let inside = T::decode_from(&mut reader).expect("it decoded a moment ago");
    assert_eq!(
        inside.encode(),
        bytes,
        "{what} read a different value because of what followed it (case {case})"
    );
    assert_eq!(reader.remaining(), 5);
    true
}

fn a_hash(rng: &mut Rng) -> Hash32 {
    Hash32::from_bytes(rng.array::<32>())
}

fn a_header(rng: &mut Rng) -> BlockHeader {
    BlockHeader {
        version: 1,
        network: NetworkId::TESTNET,
        height: rng.edgy_u64(),
        previous: a_hash(rng),
        transactions_root: a_hash(rng),
        state_root: a_hash(rng),
        history: a_hash(rng),
        timestamp: rng.edgy_u64(),
        difficulty: rng.edgy_u64(),
        total_work: u128::from(rng.edgy_u64()),
        nonce: rng.edgy_u64(),
    }
}

fn a_note(rng: &mut Rng) -> Note {
    let ceiling = Amount::MAX_MONEY.as_pebbles().saturating_add(1);
    Note::new(
        Amount::from_pebbles(rng.edgy_u64() % ceiling).unwrap_or(Amount::ZERO),
        keys()[rng.below(2)],
    )
}

fn a_block(rng: &mut Rng) -> Block {
    Block {
        header: a_header(rng),
        coinbase: CoinbaseTransaction::new(rng.edgy_u64(), vec![a_note(rng)]),
        transfers: (0..rng.between(0, 3))
            .map(|_| Transfer {
                version: 1,
                inputs: (0..rng.between(0, 3))
                    .map(|_| Input {
                        note_id: NoteId::new(a_hash(rng), rng.edgy_u32()),
                        witness: cairn_ledger::transaction::Witness::Hot,
                        signature: Signature::from_bytes(&rng.array::<64>()),
                    })
                    .collect(),
                outputs: (0..rng.between(0, 3)).map(|_| a_note(rng)).collect(),
            })
            .collect(),
    }
}

fn an_address(rng: &mut Rng) -> PeerAddress {
    if rng.bool() {
        PeerAddress(SocketAddr::from((
            Ipv4Addr::from(rng.array::<4>()),
            u16::try_from(rng.below(65_536)).unwrap_or(0),
        )))
    } else {
        PeerAddress(SocketAddr::from((
            Ipv6Addr::from(rng.array::<16>()),
            u16::try_from(rng.below(65_536)).unwrap_or(0),
        )))
    }
}

fn a_handshake(rng: &mut Rng) -> Handshake {
    Handshake {
        version: rng.edgy_u32(),
        network: NetworkId::new(rng.edgy_u32()),
        genesis: a_hash(rng),
        tip: a_hash(rng),
        height: rng.edgy_u64(),
        total_work: u128::from(rng.edgy_u64()),
        listen: u16::try_from(rng.below(65_536)).unwrap_or(0),
        nonce: rng.edgy_u64(),
        keeps: Keeps {
            headers: rng.bool(),
            cold_set: rng.bool(),
        },
    }
}

/// One of every variant, so a mutation campaign starts inside each branch
/// rather than outside all of them.
fn a_message(rng: &mut Rng) -> Message {
    match rng.below(18) {
        0 => Message::Hello(a_handshake(rng)),
        1 => Message::Welcome(a_handshake(rng)),
        2 => Message::Ping(rng.edgy_u64()),
        3 => Message::Pong(rng.edgy_u64()),
        4 => Message::GetChain {
            locator: (0..rng.between(0, MAX_LOCATOR))
                .map(|_| Located::new(rng.edgy_u64(), a_hash(rng)))
                .collect(),
        },
        5 => Message::Chain {
            from: rng.edgy_u64(),
            count: rng.edgy_u64() % MAX_CHAIN.saturating_add(1),
        },
        6 => Message::GetBlocks(
            (0..rng.between(0, MAX_REQUESTED))
                .map(|_| rng.edgy_u64())
                .collect(),
        ),
        7 => Message::Block(Box::new(a_block(rng))),
        8 => Message::Announce(
            (0..rng.between(0, 8))
                .map(|_| Located::new(rng.edgy_u64(), a_hash(rng)))
                .collect(),
        ),
        9 => Message::GetPeers,
        10 => Message::Peers(
            (0..rng.between(0, MAX_SHARED_ADDRESSES))
                .map(|_| an_address(rng))
                .collect(),
        ),
        11 => Message::Transaction(Box::new(Transfer::new(
            vec![Input::hot(NoteId::new(a_hash(rng), rng.edgy_u32()))],
            vec![a_note(rng)],
        ))),
        12 => Message::GetJoin {
            what: if rng.bool() {
                Joining::Weight
            } else {
                Joining::Ledger
            },
            part: rng.edgy_u32(),
        },
        13 => {
            let parts = u32::try_from(rng.between(1, 8)).unwrap_or(1);
            let len = rng.between(0, 64);
            Message::JoinPart {
                what: Joining::Ledger,
                at: a_hash(rng),
                part: u32::try_from(rng.below(parts as usize)).unwrap_or(0),
                parts,
                bytes: rng.bytes(len),
            }
        }
        14 => Message::GetHeaders {
            from: rng.edgy_u64(),
            count: rng.edgy_u64(),
        },
        15 => Message::Headers {
            from: rng.edgy_u64(),
            headers: (0..rng.between(0, 6)).map(|_| a_header(rng)).collect(),
        },
        16 => Message::GetProofs(
            (0..rng.between(0, MAX_PROVEN))
                .map(|_| rng.edgy_u64())
                .collect(),
        ),
        _ => Message::Proofs(
            (0..rng.between(0, 8))
                .map(|_| Placed {
                    position: rng.edgy_u64(),
                    proof: rng.bool().then(|| ForestProof {
                        siblings: (0..rng.between(0, 6)).map(|_| a_hash(rng)).collect(),
                    }),
                })
                .collect(),
        ),
    }
}

fn corpus(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = (0..64).map(|_| a_message(rng).encode()).collect();
    seeds.push(Keeps::default().encode());
    seeds.push(a_handshake(rng).encode());
    seeds.push(an_address(rng).encode());
    seeds.push(Joining::Weight.encode());
    seeds
}

#[test]
fn every_message_variant_refuses_or_round_trips() {
    let campaign = Campaign::named("net: messages");
    let seeds = corpus(&mut campaign.stream(0));
    let mut reached = [0usize; 18];
    let mut accepted = 0usize;

    let ran = campaign.run(20_000, |case, rng| {
        let bytes = if rng.chance(4) {
            let len = rng.between(0, 400);
            rng.bytes(len)
        } else {
            let seed = rng.pick(&seeds).cloned().unwrap_or_default();
            mutate(rng, &seed, &seeds)
        };

        if round_trips::<Message>(&bytes, "Message", case) {
            accepted += 1;
            if let Ok(message) = Message::decode(&bytes) {
                let tag = bytes.first().copied().unwrap_or(0) as usize;
                if let Some(slot) = reached.get_mut(tag) {
                    *slot += 1;
                }
                // Whatever a message weighs, it is a number and not a panic.
                assert!(message.weight() > 0);
            }
        }
        round_trips::<Handshake>(&bytes, "Handshake", case);
        round_trips::<Keeps>(&bytes, "Keeps", case);
        round_trips::<PeerAddress>(&bytes, "PeerAddress", case);
        round_trips::<Placed>(&bytes, "Placed", case);
        round_trips::<Joining>(&bytes, "Joining", case);
        round_trips::<Located>(&bytes, "Located", case);
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    assert!(accepted > 0, "not one input reached the message decoder");
    let variants = reached.iter().filter(|count| **count > 0).count();
    assert!(
        variants >= 15,
        "only {variants} of 18 message variants were ever decoded"
    );
}

/// A message this node would send comes back the same through its own wire.
#[test]
fn a_framed_message_survives_the_round_trip_over_the_wire() {
    let campaign = Campaign::named("net: framing");

    let ran = campaign.run(4_000, |case, rng| {
        let message = a_message(rng);
        let mut framed = Vec::new();
        write_message(&mut framed, NetworkId::TESTNET, &message)
            .expect("a message this node built fits its own frame");

        let mut source = Feeding::new(framed);
        match read_message(&mut source, NetworkId::TESTNET) {
            Ok(Incoming::Message(back)) => assert_eq!(
                back.encode(),
                message.encode(),
                "a message changed on its way through the wire (case {case})"
            ),
            other => panic!("the wire would not read back what it wrote: {other:?} (case {case})"),
        }
    });

    assert!(ran.cases >= 500, "the campaign ran {} cases", ran.cases);
}

/// The frame reader, fed whatever a socket might hand it.
///
/// Three silences and a lie, which is every way this can go: a frame that is
/// complete, one that stops partway, one that never starts, and one whose
/// declared length is a number the peer chose.
#[test]
fn the_frame_reader_refuses_anything_it_cannot_read() {
    let campaign = Campaign::named("net: frames");
    let seeds = {
        let mut rng = campaign.stream(0);
        (0..32)
            .map(|_| {
                let mut framed = Vec::new();
                write_message(&mut framed, NetworkId::TESTNET, &a_message(&mut rng)).unwrap();
                framed
            })
            .collect::<Vec<_>>()
    };
    let mut read = 0usize;
    let mut quiet = 0usize;
    let mut refused = 0usize;

    let ran = campaign.run(20_000, |_, rng| {
        let bytes = if rng.chance(3) {
            let len = rng.between(0, 64);
            rng.bytes(len)
        } else {
            let seed = rng.pick(&seeds).cloned().unwrap_or_default();
            mutate(rng, &seed, &seeds)
        };

        let mut source = Feeding::new(bytes);
        match read_message(&mut source, NetworkId::TESTNET) {
            Ok(Incoming::Message(message)) => {
                read += 1;
                assert!(message.weight() > 0);
            }
            Ok(Incoming::Quiet) => quiet += 1,
            Err(_) => refused += 1,
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    assert!(read > 0 && refused > 0, "{read} read, {refused} refused");
    let _ = quiet;
}

/// A frame longer than the cap is refused before the buffer is made.
#[test]
fn a_frame_longer_than_the_cap_is_refused_before_it_is_reserved() {
    let campaign = Campaign::named("net: frame lengths");

    let ran = campaign.run(2_000, |_, rng| {
        let declared = u32::try_from(MAX_FRAME_BYTES)
            .unwrap()
            .saturating_add(1)
            .saturating_add(rng.edgy_u32() % 1_000_000);
        let mut frame = NetworkId::TESTNET.as_u32().encode();
        frame.extend_from_slice(&declared.encode());
        // Nothing behind the header at all. A reader that reserved first would
        // have made a buffer of `declared` bytes before finding that out.
        let mut source = Feeding::new(frame);
        match read_message(&mut source, NetworkId::TESTNET) {
            Err(WireError::FrameTooLarge { declared: found }) => {
                assert_eq!(found, declared as usize);
            }
            other => panic!("a frame of {declared} bytes was answered with {other:?}"),
        }
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
}

/// A reader over a fixed buffer that runs dry rather than blocking.
///
/// A socket would time out here. This returns the deadline error instead, so
/// the same code path is walked without a second thread and a real port.
#[derive(Debug)]
struct Feeding {
    bytes: Vec<u8>,
    at: usize,
    dry: bool,
}

impl Feeding {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            at: 0,
            dry: false,
        }
    }
}

impl Read for Feeding {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.dry {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let left = self.bytes.len().saturating_sub(self.at);
        if left == 0 {
            self.dry = true;
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let take = left.min(out.len());
        out[..take].copy_from_slice(&self.bytes[self.at..self.at + take]);
        self.at = self.at.saturating_add(take);
        Ok(take)
    }
}

/// The defect that was pinned here, and the rule that closed it.
///
/// `crates/cairn-net/src/message.rs` opens by saying "every list a peer can
/// send is capped, and every cap is enforced while decoding". Eight variants
/// enforced theirs after decoding instead: they read the whole sequence through
/// `Vec::<T>::decode_from`, which stops at `MAX_SEQUENCE_LEN`, and only then
/// compared its length against the cap that was meant to govern it.
///
/// What that cost was bounded, and the bound was the frame rather than the cap.
/// A frame is a megabyte, and the smallest element of each of these lists is
/// between seven and forty bytes, so what a peer got built before its cap was
/// consulted was:
///
/// | variant     | cap | built from one frame | over |
/// |-------------|-----|----------------------|------|
/// | `GetChain`  |  64 |               26 214 | 409x |
/// | `GetBlocks` | 128 |              131 072 | 1024x |
/// | `Announce`  | 512 |               26 214 |  51x |
/// | `Peers`     |  64 |              149 795 | 2340x |
/// | `Headers`   | 512 |                5 761 |  11x |
/// | `GetProofs` |  64 |              131 072 | 2048x |
/// | `Proofs`    |  64 |              116 508 | 1820x |
/// | `JoinPart`  | 524 288 B |      1 048 530 B |   2x |
///
/// `a_full_frame_of_peers_is_built_in_full_before_its_cap_is_read` measured the
/// `Peers` row rather than arguing it: a hundred and fifty thousand
/// `PeerAddress` is about four and a half megabytes held for a one megabyte
/// frame, thrown away a moment later, and a node holds several dozen
/// connections at once.
///
/// So it was never the unbounded allocation the caps were written against. It
/// was the same rule read late, and the distance between the rule and what was
/// built before it ran was a factor of two thousand.
///
/// All eight now go through `cairn_primitives::codec::take_at_most`, which is
/// what `Block`, `Transfer` and `CoinbaseTransaction` already used and what
/// their own comments say it is there for: "because decoding is not free and
/// happens before any rule has looked at the frame". Nothing a peer could send
/// and have accepted before is refused now; what changed is where the refusal
/// happens and what the answer is called, which is why this asks for
/// `InvalidValue` where it used to ask for `UnexpectedEnd`.
///
/// Found by the campaign above, through the probe that offers a count with
/// nothing behind it.
#[test]
fn eight_message_lists_read_their_cap_before_they_build_the_list() {
    // A count far past every cap here and inside `MAX_SEQUENCE_LEN`, so what
    // decides the answer is the variant's own rule and not the codec ceiling.
    let declared = 900_000u32;

    let late = [
        ("GetChain", 4u8, MAX_LOCATOR),
        ("GetBlocks", 6, MAX_REQUESTED),
        ("Announce", 8, MAX_ANNOUNCED),
        ("Peers", 10, MAX_SHARED_ADDRESSES),
        ("GetProofs", 16, MAX_PROVEN),
        ("Proofs", 17, MAX_PROVEN),
    ];

    for (what, tag, cap) in late {
        let mut bytes = tag.encode();
        bytes.extend_from_slice(&declared.encode());
        assert!(
            matches!(
                Message::decode(&bytes),
                Err(CodecError::InvalidValue { .. })
            ),
            "{what} read a count of {declared} past its cap of {cap} before refusing it"
        );
    }

    // `Headers` reads a height first, and `JoinPart` a tag, a hash and two
    // counts, so their probes carry a head.
    let mut headers = 15u8.encode();
    headers.extend_from_slice(&0u64.encode());
    headers.extend_from_slice(&declared.encode());
    assert!(
        matches!(
            Message::decode(&headers),
            Err(CodecError::InvalidValue { .. })
        ),
        "Headers read a count past its cap of {MAX_HEADERS} before refusing it"
    );

    let mut join = 13u8.encode();
    join.extend_from_slice(&Joining::Ledger.encode());
    join.extend_from_slice(&Hash32::ZERO.encode());
    join.extend_from_slice(&0u32.encode());
    join.extend_from_slice(&1u32.encode());
    join.extend_from_slice(&declared.encode());
    assert!(
        matches!(Message::decode(&join), Err(CodecError::InvalidValue { .. })),
        "JoinPart read a payload length past its cap of {JOIN_PART_BYTES} before refusing it"
    );

    // And the other half of the rule: a list inside its cap is still read.
    let mut room = 10u8.encode();
    room.extend_from_slice(&0u32.encode());
    assert_eq!(Message::decode(&room), Ok(Message::Peers(Vec::new())));
}

/// The widest row of the table above, as a frame a peer could really send.
///
/// A frame of exactly the size the wire allows, filled with the smallest
/// address there is: a hundred and forty nine thousand seven hundred and
/// ninety five of them against a cap of sixty four. It used to be built in
/// full and then measured, and the proof that it was is that the refusal named
/// the cap rather than the end of the frame.
///
/// That proof no longer separates the two shapes, because the refusal is the
/// same one read earlier. What separates them is the probe in the test above,
/// which declares a count with nothing behind it: a decoder that reads the
/// list first runs out of bytes and says so, and one that reads the count
/// first names the cap. This is kept for the size, which is the part a reader
/// of the table wants to check.
#[test]
fn a_full_frame_of_peers_is_refused_at_its_count() {
    // Tag, count, then seven bytes an address: a tag of four, four octets and
    // a port.
    let room = MAX_FRAME_BYTES.saturating_sub(5);
    let held = room.checked_div(7).unwrap_or(0);
    assert_eq!(held, 149_795);

    let mut frame = 10u8.encode();
    frame.extend_from_slice(&u32::try_from(held).unwrap().encode());
    for _ in 0..held {
        frame.push(4);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(&0u16.to_le_bytes());
    }
    assert!(frame.len() <= MAX_FRAME_BYTES, "the probe is a legal frame");

    assert_eq!(
        Message::decode(&frame),
        Err(CodecError::InvalidValue {
            type_name: "address list"
        }),
        "a full frame of addresses was not refused by the cap that governs it"
    );
    assert!(
        held > MAX_SHARED_ADDRESSES.saturating_mul(2_000),
        "{held} addresses against a cap of {MAX_SHARED_ADDRESSES}"
    );
}

/// The other half of the same measurement: the cap is read, eventually.
///
/// A frame carrying more elements than the cap allows, all of them well
/// formed, is refused for the cap and not for anything else. Which proves the
/// decoder read every one of them: an early refusal could not have got there.
#[test]
fn a_list_past_its_cap_is_refused_only_after_every_element_is_built() {
    // One past each cap, with every element present.
    let over: Vec<u64> = (0..=MAX_PROVEN as u64).collect();
    assert_eq!(over.len(), MAX_PROVEN + 1);
    assert_eq!(
        Message::decode(&Message::GetProofs(over.clone()).encode()),
        Err(CodecError::InvalidValue {
            type_name: "height list"
        }),
        "a list one past the cap is refused for the cap"
    );

    // And one exactly at it is taken, so the cap is where it says it is.
    let at = &over[..MAX_PROVEN];
    assert!(Message::decode(&Message::GetProofs(at.to_vec()).encode()).is_ok());

    let placed: Vec<Placed> = (0..=MAX_PROVEN as u64)
        .map(|position| Placed {
            position,
            proof: None,
        })
        .collect();
    assert_eq!(
        Message::decode(&Message::Proofs(placed.clone()).encode()),
        Err(CodecError::InvalidValue {
            type_name: "Proofs"
        })
    );
    assert!(Message::decode(&Message::Proofs(placed[..MAX_PROVEN].to_vec()).encode()).is_ok());
}

/// The caps that are read where the count is read, so a fix to the seven does
/// not quietly undo these.
#[test]
fn the_caps_that_are_already_read_early_stay_early() {
    // A chain answer names a count and no elements, so its cap is the only
    // thing that can refuse it.
    let mut chain = 5u8.encode();
    chain.extend_from_slice(&0u64.encode());
    chain.extend_from_slice(&MAX_CHAIN.saturating_add(1).encode());
    assert_eq!(
        Message::decode(&chain),
        Err(CodecError::InvalidValue {
            type_name: "chain length"
        })
    );

    // A join answer claiming more pieces than any answer takes is refused
    // before its payload length is even read.
    let mut join = 13u8.encode();
    join.extend_from_slice(&Joining::Ledger.encode());
    join.extend_from_slice(&Hash32::ZERO.encode());
    join.extend_from_slice(&0u32.encode());
    join.extend_from_slice(&MAX_JOIN_PARTS.saturating_add(1).encode());
    assert_eq!(
        Message::decode(&join),
        Err(CodecError::InvalidValue {
            type_name: "JoinPart"
        })
    );

    // And one whose piece number is past the count it declares.
    let mut wrong = 13u8.encode();
    wrong.extend_from_slice(&Joining::Ledger.encode());
    wrong.extend_from_slice(&Hash32::ZERO.encode());
    wrong.extend_from_slice(&3u32.encode());
    wrong.extend_from_slice(&3u32.encode());
    assert_eq!(
        Message::decode(&wrong),
        Err(CodecError::InvalidValue {
            type_name: "JoinPart"
        })
    );
}

/// A tag nothing answers to is refused, and every tag that is answered to is
/// one this build knows.
#[test]
fn a_tag_past_the_last_variant_is_refused() {
    let campaign = Campaign::named("net: tags");

    let ran = campaign.run(2_000, |_, rng| {
        let tag = rng.byte();
        let mut bytes = tag.encode();
        let len = rng.between(0, 200);
        bytes.extend_from_slice(&rng.bytes(len));
        if tag > 17 {
            assert_eq!(
                Message::decode(&bytes),
                Err(CodecError::InvalidValue {
                    type_name: "Message"
                }),
                "tag {tag} was answered by something"
            );
        }
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    // A tripwire rather than a fact about the version: a protocol change that
    // adds a message has to move the tag this campaign calls the last one.
    // Seven and eight both changed which positions a chain is asked about and
    // neither added a variant, so seventeen still is.
    assert_eq!(
        PROTOCOL_VERSION, 8,
        "a protocol change should read this file"
    );
}

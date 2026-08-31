//! Feeding the decoders what a hostile peer would.
//!
//! A node decodes bytes chosen by strangers. Every message below arrives over
//! a socket from someone who was never asked to be honest, so what these check
//! is not that valid input works — the other tests do that — but that invalid
//! input fails, in every way it can be invalid, without taking the node with
//! it.
//!
//! Three campaigns, because they find different things. Random bytes reach the
//! decoders that accept almost any prefix. Mutations of a valid message reach
//! the ones behind a length or a tag that random bytes never get past. And
//! truncation at every length reaches the readers that assume more is coming.
//!
//! Deterministic throughout: the generator is seeded and written here, so a
//! failure names an input that can be reproduced rather than a lucky run that
//! cannot. This is what a fuzzer does, held in the test suite so it runs on
//! every change rather than when someone remembers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::Handover;
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::sampling::SampledStart;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A generator written here rather than pulled in, so a failing case is a
/// seed and an index and nothing else has to be installed to reproduce it.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Any non-zero state will do; zero is the one that would stick.
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next() >> 56).unwrap_or(0)
    }

    fn below(&mut self, limit: usize) -> usize {
        let Ok(span) = u64::try_from(limit) else {
            return 0;
        };
        if span == 0 {
            return 0;
        }
        usize::try_from(self.next() % span).unwrap_or(0)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}

/// What every decoder has to hold, whatever it is handed.
///
/// Not panicking is the first half. The second is that anything accepted has
/// exactly one encoding: two byte strings decoding to the same value would
/// give a block two identifiers, and a node deciding between them would be
/// deciding between two chains.
fn survives<T: Encode + Decode>(bytes: &[u8], what: &str, seed: u64, index: usize) -> usize {
    let Ok(value) = T::decode(bytes) else {
        return 0;
    };
    assert_eq!(
        value.encode(),
        bytes,
        "{what} accepted an encoding that is not the one it produces \
         (seed {seed}, case {index})"
    );
    1
}

/// Runs one campaign over every type that arrives from a peer, returning how
/// many of them accepted the input.
///
/// Counted because a fuzz campaign that never gets past the first byte tests
/// only the refusal path, and would pass for ever while covering nothing. Each
/// test below says how far it expects to get.
fn feed(bytes: &[u8], seed: u64, index: usize) -> usize {
    survives::<Message>(bytes, "Message", seed, index)
        + survives::<Handshake>(bytes, "Handshake", seed, index)
        + survives::<Block>(bytes, "Block", seed, index)
        + survives::<BlockHeader>(bytes, "BlockHeader", seed, index)
        + survives::<Transfer>(bytes, "Transfer", seed, index)
        + survives::<CoinbaseTransaction>(bytes, "CoinbaseTransaction", seed, index)
        + survives::<Handover>(bytes, "Handover", seed, index)
        + survives::<SampledStart>(bytes, "SampledStart", seed, index)
        + survives::<Note>(bytes, "Note", seed, index)
        + survives::<NoteId>(bytes, "NoteId", seed, index)
}

#[test]
fn random_bytes_are_refused_rather_than_fatal() {
    let seed = 0x0CA1_2026_u64;
    let mut rng = Rng::new(seed);
    let mut accepted = 0usize;
    for index in 0..4_000 {
        let len = rng.below(600);
        let bytes = rng.bytes(len);
        accepted += feed(&bytes, seed, index);
    }
    // Fixed-width types take any bytes of the right length, so some of this
    // has to land. None landing would mean the campaign never reached a
    // decoder at all.
    assert!(accepted > 0, "not one random input reached a decoder");
}

/// Random bytes rarely get past a tag or a length. Bending a valid message
/// does, which is where a decoder that trusted one field to agree with
/// another would be caught.
#[test]
fn a_valid_message_bent_out_of_shape_is_refused_rather_than_fatal() {
    let seed = 0x1CA1_2026_u64;
    let mut rng = Rng::new(seed);
    let samples = valid_messages();
    let mut accepted = 0usize;

    for index in 0..6_000 {
        let original = &samples[rng.below(samples.len())];
        let mut bytes = original.clone();
        if bytes.is_empty() {
            continue;
        }
        // One to four bytes changed, which keeps enough of the shape for the
        // decoder to get well inside itself before anything is wrong.
        for _ in 0..=rng.below(4) {
            let at = rng.below(bytes.len());
            bytes[at] = rng.byte();
        }
        accepted += feed(&bytes, seed, index);
    }
    // Most of a valid message survives a few bent bytes, so most cases should
    // still decode. Far fewer would mean the mutations are landing somewhere
    // that refuses everything, and the campaign would be testing one branch.
    assert!(
        accepted > 1_000,
        "only {accepted} of 6000 bent messages reached a decoder"
    );
}

/// A frame can end early: a peer that hangs up, a link that drops. Every
/// prefix of every valid message has to be refused rather than read past.
#[test]
fn every_prefix_of_a_valid_message_is_refused_rather_than_fatal() {
    let seed = 0x2CA1_2026_u64;
    let mut cases = 0usize;
    for (index, message) in valid_messages().iter().enumerate() {
        for cut in 0..message.len() {
            feed(&message[..cut], seed, index * 10_000 + cut);
            cases += 1;
        }
    }
    assert!(cases > 1_000, "only {cases} prefixes were tried");
}

/// A length that says one thing and a body that says another is the shape of
/// nearly every decoder bug worth having. This walks the count of a sequence
/// through the values a hostile peer would choose.
#[test]
fn a_declared_length_that_lies_is_refused_rather_than_fatal() {
    let seed = 0x3CA1_2026_u64;
    let samples = valid_messages();
    let lies: [u32; 8] = [
        0,
        1,
        u32::MAX,
        u32::MAX - 1,
        1 << 20,
        (1 << 20) + 1,
        1 << 24,
        1 << 31,
    ];

    let mut index = 0usize;
    let mut accepted = 0usize;
    for message in &samples {
        for at in 0..message.len().saturating_sub(4) {
            for lie in lies {
                let mut bytes = message.clone();
                bytes[at..at + 4].copy_from_slice(&lie.to_le_bytes());
                accepted += feed(&bytes, seed, index);
                index += 1;
            }
        }
    }
    assert!(index > 1_000, "only {index} lengths were tried");
    // A lie about a length usually breaks the message, and sometimes lands on
    // a field where the value is legitimate. Both have to be reached.
    assert!(accepted > 0, "not one altered length reached a decoder");
}

/// Decoding is only the first gate. What a newcomer is handed then goes
/// through checks that rebuild a whole ledger and weigh a whole chain, and
/// those run on bytes a stranger chose. They have to refuse rather than break.
#[test]
fn a_bent_ledger_and_a_bent_weighing_are_refused_rather_than_fatal() {
    let seed = 0x4CA1_2026_u64;
    let mut rng = Rng::new(seed);
    let params = ConsensusParams::testnet().with_burial(8);

    let (handover, start) = valid_join_answers();
    let ledger = handover.encode();
    let weighing = start.encode();
    let mut took = 0usize;
    let mut weighed = 0usize;

    for _ in 0..2_000 {
        let mut bytes = ledger.clone();
        for _ in 0..=rng.below(3) {
            let at = rng.below(bytes.len());
            bytes[at] = rng.byte();
        }
        if let Ok(bent) = Handover::decode(&bytes) {
            // Refusing is the expected answer; accepting a bent one would be
            // a defect this cannot see, which is what the handover tests are
            // for. What is checked here is that neither outcome is a panic.
            if cairn_ledger::handover::accept(&bent, params.hot_capacity, params.burial).is_ok() {
                took += 1;
            }
        }
    }

    for _ in 0..2_000 {
        let mut bytes = weighing.clone();
        for _ in 0..=rng.below(3) {
            let at = rng.below(bytes.len());
            bytes[at] = rng.byte();
        }
        if let Ok(bent) = SampledStart::decode(&bytes) {
            if cairn_ledger::sampling::check_start(&bent, bent.samples.len()).is_ok() {
                weighed += 1;
            }
        }
    }

    // An unbent one has to pass, or the campaign proves nothing about the
    // checks it is bending.
    assert!(
        cairn_ledger::handover::accept(&handover, params.hot_capacity, params.burial).is_ok(),
        "the ledger these mutations start from is not one that would be taken"
    );
    let _ = (took, weighed);
}

/// A ledger a newcomer would be handed, and the weighing that comes before it.
fn valid_join_answers() -> (Handover, SampledStart) {
    let params = ConsensusParams::testnet().with_burial(8);
    let miner = SecretKey::from_bytes(&[5; 32]);
    let mut state = LedgerState::new();
    let mut archive = cairn_accumulator::Archive::new();
    let mut headers = Vec::new();
    let mut past = Vec::new();
    let mut clock = 1_000u64;

    for _ in 0..40 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        past.push(state.clone());
        headers.push(block.header);
        archive.add(cairn_ledger::state::header_leaf(&block.header.id()));
    }

    let tip = *headers.last().unwrap();
    // The run of recent headers the difficulty rule reads, which a handover
    // has to carry in full or it is refused before anything else is looked at.
    let last = usize::try_from(tip.height - params.burial).unwrap();
    let from = (last + 1).saturating_sub(cairn_ledger::pow::RECENT_HEADERS);
    let recent = headers[from..=last].to_vec();
    // From below the tip, as any handover is: one at the tip is refused for
    // where it sits, which would make this campaign bend nothing.
    let anchor_height = tip.height - params.burial;
    let at = headers[usize::try_from(anchor_height).unwrap()];
    let handover = past[usize::try_from(anchor_height).unwrap()].handover(
        at,
        tip,
        state.headers_before_tip(),
        archive
            .prove_in(anchor_height, tip.height)
            .expect("it can prove its own history"),
        recent,
    );
    let start = cairn_ledger::sampling::open_start(
        &tip,
        state.headers_before_tip(),
        16,
        |height| headers.get(usize::try_from(height).unwrap()).copied(),
        |height| archive.prove_in(height, tip.height),
    )
    .expect("an archivist can weigh its own chain");
    (handover, start)
}

/// One of each thing a peer can send, encoded.
fn valid_messages() -> Vec<Vec<u8>> {
    let params = ConsensusParams::testnet().with_burial(8);
    let miner = SecretKey::from_bytes(&[9; 32]);
    let mut state = LedgerState::new();
    let mut blocks = Vec::new();
    let mut clock = 1_000u64;

    for _ in 0..3 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        blocks.push(block);
    }

    let tip = blocks.last().unwrap().clone();
    let transfer = Transfer::new(
        vec![Input::hot(NoteId::new(Hash32::from_bytes([4; 32]), 0))],
        vec![Note::new(
            Amount::from_pebbles(10).unwrap(),
            miner.public_key(),
        )],
    );
    let handshake = Handshake {
        version: PROTOCOL_VERSION,
        network: NetworkId::TESTNET,
        genesis: blocks[0].id(),
        tip: tip.id(),
        height: 2,
        total_work: 3,
        archives: true,
        listen: 9944,
        nonce: 77,
    };
    // Only ever encoded, never accepted: this campaign feeds shapes to the
    // decoder, and what a decoder does with nonsense is the whole question.
    let handover = state.handover(
        tip.header,
        tip.header,
        cairn_accumulator::forest::Forest::new(),
        cairn_accumulator::forest::ForestProof {
            siblings: Vec::new(),
        },
        vec![tip.header],
    );

    vec![
        Message::Hello(handshake).encode(),
        Message::Welcome(handshake).encode(),
        Message::GetPeers.encode(),
        Message::Block(Box::new(tip.clone())).encode(),
        Message::Transaction(Box::new(transfer.clone())).encode(),
        Message::GetJoin {
            what: cairn_net::message::Joining::Ledger,
            part: 3,
        }
        .encode(),
        tip.encode(),
        tip.header.encode(),
        transfer.encode(),
        handover.encode(),
    ]
}

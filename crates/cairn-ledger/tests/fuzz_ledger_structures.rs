//! Every ledger structure a stranger can send, under a generator.
//!
//! Nine types travel between nodes and are decoded before any rule has looked
//! at them: `NetworkId`, `NoteId`, `Note`, `Witness`, `Input`, `Transfer`,
//! `CoinbaseTransaction`, `BlockHeader`, `Block`, and the two largest of all,
//! `Handover` and `SampledStart`.
//!
//! Three claims, and each is checked against arbitrary bytes and against real
//! encodings bent out of shape:
//!
//! 1. Refusal is total. Nothing panics, aborts or hangs.
//! 2. What is accepted re-encodes to the bytes it came from. The two
//!    exceptions are `Handover` and `SampledStart`, which both carry a
//!    `Forest`, and a forest takes its roots in an order it will not write:
//!    see `cairn-accumulator/tests/fuzz_accumulator.rs`. For those two the
//!    claim is that the canonical form is a fixed point, which is what
//!    everything downstream actually depends on.
//! 3. A count past a cap is refused where the count is read, before any of
//!    what it names is built. This is the one that has been fixed here
//!    repeatedly, and the test can tell the two apart: a decoder that checked
//!    first names the type it refused, and one that found out by running its
//!    loop until the bytes ran out says the input ended.
//!
//! Nothing here mines. A decoder has no opinion about proof of work, and a
//! campaign that spent its time searching for nonces would be a campaign that
//! ran a hundred cases.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::OnceLock;

use cairn_accumulator::forest::{Forest, ForestProof};
use cairn_crypto::{PublicKey, SecretKey, Signature};
use cairn_fuzz::{mutate, Campaign, Rng};
use cairn_ledger::block::{Block, BlockHeader, MOST_TRANSFERS};
use cairn_ledger::handover::{Handover, MOST_BURIED};
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::sampling::{Sample, SampledStart, MOST_TAIL, SAMPLES};
use cairn_ledger::state::{Fallen, HotEntry, Maturing, GRACE_BLOCKS, GRACE_NOTES};
use cairn_ledger::transaction::{
    CoinbaseTransaction, ColdWitness, Input, Transfer, Witness, MAX_COINBASE_EXTRA,
    MOST_COINBASE_OUTPUTS, MOST_INPUTS, MOST_OUTPUTS,
};
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::{Amount, Hash32};

/// Public keys drawn once.
///
/// Deriving one is a scalar multiplication, and a campaign that derived a key
/// per case would be measuring `ed25519-dalek` rather than these decoders.
fn keys() -> &'static [PublicKey; 4] {
    static KEYS: OnceLock<[PublicKey; 4]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            SecretKey::from_bytes(&[1; 32]).public_key(),
            SecretKey::from_bytes(&[2; 32]).public_key(),
            SecretKey::from_bytes(&[3; 32]).public_key(),
            SecretKey::from_bytes(&[4; 32]).public_key(),
        ]
    })
}

/// Whatever decodes re-encodes to the bytes it came from, reads a settled
/// number of them, and reads nothing after them.
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

    // Every one of these is read inside a larger frame at least once, so what
    // follows must make no difference to what is read.
    let mut trailing = bytes.to_vec();
    trailing.extend_from_slice(&[0xa5; 7]);
    let mut reader = Reader::new(&trailing);
    let inside = T::decode_from(&mut reader).expect("it decoded a moment ago");
    assert_eq!(
        inside.encode(),
        bytes,
        "{what} read a different value because of what followed it (case {case})"
    );
    assert_eq!(
        reader.remaining(),
        7,
        "{what} consumed a different number of bytes inside a frame (case {case})"
    );
    true
}

/// The weaker claim, for the two types that carry a `Forest`.
///
/// A forest takes its roots in any order and writes them in one, so these two
/// have several encodings apiece. What still has to hold, and what every
/// receiver leans on, is that the canonical form is a fixed point.
fn settles<T: Encode + Decode>(bytes: &[u8], what: &str, case: usize) -> bool {
    let Ok(value) = T::decode(bytes) else {
        return false;
    };
    let canonical = value.encode();
    let again = T::decode(&canonical).unwrap_or_else(|error| {
        panic!("{what} will not read back what it wrote: {error} (case {case})")
    });
    assert_eq!(
        again.encode(),
        canonical,
        "{what} has no fixed point (case {case}, bytes {})",
        hex::encode(bytes)
    );
    true
}

fn a_hash(rng: &mut Rng) -> Hash32 {
    Hash32::from_bytes(rng.array::<32>())
}

/// Version numbers, including ones no build knows how to judge.
fn a_version(rng: &mut Rng) -> u16 {
    u16::try_from(rng.edgy_u32() & 0xffff).unwrap_or(0)
}

fn an_amount(rng: &mut Rng) -> Amount {
    let ceiling = Amount::MAX_MONEY.as_pebbles().saturating_add(1);
    Amount::from_pebbles(rng.edgy_u64() % ceiling).unwrap_or(Amount::ZERO)
}

fn a_note(rng: &mut Rng) -> Note {
    Note::new(an_amount(rng), keys()[rng.below(4)])
}

fn a_note_id(rng: &mut Rng) -> NoteId {
    NoteId::new(a_hash(rng), rng.edgy_u32())
}

fn a_proof(rng: &mut Rng, most: usize) -> ForestProof {
    let depth = rng.between(0, most);
    ForestProof {
        siblings: (0..depth).map(|_| a_hash(rng)).collect(),
    }
}

fn a_witness(rng: &mut Rng) -> Witness {
    if rng.bool() {
        Witness::Hot
    } else {
        Witness::Cold(Box::new(ColdWitness {
            note: a_note(rng),
            position: rng.edgy_u64(),
            proof: a_proof(rng, 6),
        }))
    }
}

fn an_input(rng: &mut Rng) -> Input {
    Input {
        note_id: a_note_id(rng),
        witness: a_witness(rng),
        signature: Signature::from_bytes(&rng.array::<64>()),
    }
}

fn a_transfer(rng: &mut Rng, most: usize) -> Transfer {
    Transfer {
        version: a_version(rng),
        inputs: (0..rng.between(0, most)).map(|_| an_input(rng)).collect(),
        outputs: (0..rng.between(0, most)).map(|_| a_note(rng)).collect(),
    }
}

fn a_coinbase(rng: &mut Rng) -> CoinbaseTransaction {
    let extra = rng.between(0, MAX_COINBASE_EXTRA);
    CoinbaseTransaction {
        version: a_version(rng),
        height: rng.edgy_u64(),
        outputs: (0..rng.between(0, MOST_COINBASE_OUTPUTS))
            .map(|_| a_note(rng))
            .collect(),
        extra: rng.bytes(extra),
    }
}

fn a_header(rng: &mut Rng) -> BlockHeader {
    BlockHeader {
        version: a_version(rng),
        network: NetworkId::new(rng.edgy_u32()),
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

fn a_block(rng: &mut Rng) -> Block {
    Block {
        header: a_header(rng),
        coinbase: a_coinbase(rng),
        transfers: (0..rng.between(0, 4)).map(|_| a_transfer(rng, 3)).collect(),
    }
}

/// A forest of whatever size, built the only way a forest can be.
fn a_forest(rng: &mut Rng) -> Forest {
    let mut forest = Forest::new();
    for _ in 0..rng.between(0, 40) {
        if forest.add(a_hash(rng)).is_none() {
            break;
        }
    }
    forest
}

/// A handover with the shape of a real one and none of the truth of one.
///
/// It will not be accepted by `handover::accept`, which is not what this is
/// for: what a decoder does before any rule has run is the question here, and
/// that is decided by the shape alone.
fn a_handover(rng: &mut Rng) -> Handover {
    let hot: Vec<(NoteId, HotEntry)> = (0..rng.between(0, 8))
        .map(|_| {
            (
                a_note_id(rng),
                HotEntry {
                    note: a_note(rng),
                    height: rng.edgy_u64(),
                },
            )
        })
        .collect();
    let grace: Vec<Vec<Fallen>> = (0..rng.between(0, 3))
        .map(|_| {
            (0..rng.between(0, 3))
                .map(|_| (a_note_id(rng), rng.edgy_u64(), a_note(rng)))
                .collect()
        })
        .collect();
    let grace_proofs: Vec<(u64, ForestProof)> = (0..rng.between(0, 3))
        .map(|_| (rng.edgy_u64(), a_proof(rng, 6)))
        .collect();
    let maturing: Vec<Maturing> = (0..rng.between(0, 4))
        .map(|_| (rng.edgy_u64(), a_hash(rng)))
        .collect();

    Handover {
        at: a_header(rng),
        tip: a_header(rng),
        tip_history: a_forest(rng),
        anchor: a_proof(rng, 6),
        hot,
        cold: a_forest(rng),
        grace,
        grace_proofs,
        maturing,
        supply: an_amount(rng),
        headers: a_forest(rng),
        buried: (0..rng.between(0, 4)).map(|_| a_header(rng)).collect(),
        recent: (0..rng.between(0, 4)).map(|_| a_header(rng)).collect(),
    }
}

fn a_sample(rng: &mut Rng) -> Sample {
    Sample {
        header: a_header(rng),
        proof: a_proof(rng, 6),
    }
}

fn a_sampled_start(rng: &mut Rng) -> SampledStart {
    SampledStart {
        tip: a_header(rng),
        tail: (0..rng.between(0, 4)).map(|_| a_header(rng)).collect(),
        parent: rng.bool().then(|| a_sample(rng)),
        history: a_forest(rng),
        samples: (0..rng.between(0, 4)).map(|_| a_sample(rng)).collect(),
    }
}

/// Encodings of the small structures, which is where a mutation campaign
/// spends most usefully: they are cheap to decode and they nest inside
/// everything else.
fn small_corpus(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut seeds = vec![
        NetworkId::MAINNET.encode(),
        NetworkId::TESTNET.encode(),
        Witness::Hot.encode(),
        Note::new(Amount::ZERO, keys()[0]).encode(),
        Note::new(Amount::MAX_MONEY, keys()[1]).encode(),
    ];
    for _ in 0..6 {
        seeds.push(a_note(rng).encode());
        seeds.push(a_note_id(rng).encode());
        seeds.push(a_witness(rng).encode());
        seeds.push(an_input(rng).encode());
        seeds.push(a_header(rng).encode());
    }
    seeds
}

fn transaction_corpus(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for _ in 0..4 {
        seeds.push(a_transfer(rng, 4).encode());
        seeds.push(a_coinbase(rng).encode());
        seeds.push(a_block(rng).encode());
    }
    seeds.push(Transfer::new(Vec::new(), Vec::new()).encode());
    seeds.push(CoinbaseTransaction::new(0, Vec::new()).encode());
    seeds
}

fn join_corpus(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for _ in 0..3 {
        seeds.push(a_handover(rng).encode());
        seeds.push(a_sampled_start(rng).encode());
        seeds.push(a_sample(rng).encode());
    }
    seeds
}

#[test]
fn the_small_structures_refuse_or_round_trip() {
    let campaign = Campaign::named("ledger: small structures");
    let seeds = small_corpus(&mut campaign.stream(0));
    let mut accepted = [0usize; 6];

    let ran = campaign.run(20_000, |case, rng| {
        let bytes = if rng.bool() {
            let len = rng.between(0, 200);
            rng.plausible_bytes(len)
        } else {
            let seed = rng.pick(&seeds).cloned().unwrap_or_default();
            mutate(rng, &seed, &seeds)
        };

        if round_trips::<NetworkId>(&bytes, "NetworkId", case) {
            accepted[0] += 1;
        }
        if round_trips::<NoteId>(&bytes, "NoteId", case) {
            accepted[1] += 1;
        }
        if round_trips::<Note>(&bytes, "Note", case) {
            accepted[2] += 1;
        }
        if round_trips::<Witness>(&bytes, "Witness", case) {
            accepted[3] += 1;
        }
        if round_trips::<Input>(&bytes, "Input", case) {
            accepted[4] += 1;
        }
        if round_trips::<BlockHeader>(&bytes, "BlockHeader", case) {
            accepted[5] += 1;
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    for (index, count) in accepted.iter().enumerate() {
        assert!(*count > 0, "decoder {index} was never reached");
    }
}

#[test]
fn the_transactions_refuse_or_round_trip() {
    let campaign = Campaign::named("ledger: transactions");
    let seeds = transaction_corpus(&mut campaign.stream(0));
    let mut accepted = [0usize; 3];

    let ran = campaign.run(20_000, |case, rng| {
        let bytes = if rng.chance(4) {
            let len = rng.between(0, 400);
            rng.plausible_bytes(len)
        } else {
            let seed = rng.pick(&seeds).cloned().unwrap_or_default();
            mutate(rng, &seed, &seeds)
        };

        if round_trips::<Transfer>(&bytes, "Transfer", case) {
            accepted[0] += 1;
        }
        if round_trips::<CoinbaseTransaction>(&bytes, "CoinbaseTransaction", case) {
            accepted[1] += 1;
        }
        if round_trips::<Block>(&bytes, "Block", case) {
            accepted[2] += 1;
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    for (index, count) in accepted.iter().enumerate() {
        assert!(*count > 0, "decoder {index} was never reached");
    }
}

#[test]
fn the_join_answers_refuse_or_settle() {
    let campaign = Campaign::named("ledger: join answers");
    let seeds = join_corpus(&mut campaign.stream(0));
    let mut accepted = [0usize; 3];

    let ran = campaign.run(8_000, |case, rng| {
        let bytes = if rng.chance(6) {
            let len = rng.between(0, 600);
            rng.plausible_bytes(len)
        } else {
            let seed = rng.pick(&seeds).cloned().unwrap_or_default();
            mutate(rng, &seed, &seeds)
        };

        if settles::<Handover>(&bytes, "Handover", case) {
            accepted[0] += 1;
        }
        if settles::<SampledStart>(&bytes, "SampledStart", case) {
            accepted[1] += 1;
        }
        if round_trips::<Sample>(&bytes, "Sample", case) {
            accepted[2] += 1;
        }
    });

    assert!(ran.cases >= 500, "the campaign ran {} cases", ran.cases);
    for (index, count) in accepted.iter().enumerate() {
        assert!(*count > 0, "decoder {index} was never reached");
    }
}

/// A count is refused where it is read, or it is refused after the work.
///
/// The two are told apart by which error comes back. A decoder that checked
/// the count first names the thing it refused. One that ran its loop until the
/// bytes ran out says the input ended, which means it built as much of the
/// sequence as the frame could pay for before deciding it did not want any of
/// it.
///
/// Every count below is offered with an empty body, so the distinction is
/// clean: there is nothing to read, and a decoder that gets as far as reading
/// is a decoder that did not check.
fn refusal_for(what: &str, over: u32, tail: &[u8], decode: impl Fn(&[u8]) -> Option<CodecError>) {
    // First, that the probe reaches the field at all. With a count of zero the
    // decoder has to get past it, and either finish or ask for what comes
    // next. Anything else means `tail` is not what this decoder reads before
    // the count, and every assertion below would be about the wrong field.
    let mut reaches = Vec::new();
    reaches.extend_from_slice(tail);
    reaches.extend_from_slice(&0u32.encode());
    let got_there = decode(&reaches);
    assert!(
        matches!(got_there, None | Some(CodecError::UnexpectedEnd)),
        "the probe for {what} does not reach the count it is about: {got_there:?}"
    );

    let mut bytes = Vec::new();
    bytes.extend_from_slice(tail);
    bytes.extend_from_slice(&over.encode());
    let answer = decode(&bytes);
    assert!(
        !matches!(answer, Some(CodecError::UnexpectedEnd)),
        "{what} discovered a count of {over} was too large by running out of bytes, \
         which means it had already started building it"
    );
    assert!(
        answer.is_some(),
        "{what} accepted a count of {over} with nothing behind it"
    );
}

#[test]
fn a_transfer_refuses_an_input_count_where_it_reads_it() {
    let campaign = Campaign::named("ledger: transfer caps");

    let ran = campaign.run(2_000, |_, rng| {
        let over = u32::try_from(MOST_INPUTS)
            .unwrap()
            .saturating_add(1)
            .saturating_add(rng.edgy_u32() % 1_000_000);
        // Version, then the input count.
        refusal_for("Transfer inputs", over, &1u16.encode(), |bytes| {
            Transfer::decode(bytes).err()
        });

        let over = u32::try_from(MOST_OUTPUTS)
            .unwrap()
            .saturating_add(1)
            .saturating_add(rng.edgy_u32() % 1_000_000);
        // Version, an empty input list, then the output count.
        let mut head = 1u16.encode();
        head.extend_from_slice(&0u32.encode());
        refusal_for("Transfer outputs", over, &head, |bytes| {
            Transfer::decode(bytes).err()
        });
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
}

#[test]
fn a_coinbase_refuses_an_output_count_where_it_reads_it() {
    let campaign = Campaign::named("ledger: coinbase caps");

    let ran = campaign.run(2_000, |_, rng| {
        let over = u32::try_from(MOST_COINBASE_OUTPUTS)
            .unwrap()
            .saturating_add(1)
            .saturating_add(rng.edgy_u32() % 1_000_000);
        let mut head = 1u16.encode();
        head.extend_from_slice(&0u64.encode());
        refusal_for("CoinbaseTransaction outputs", over, &head, |bytes| {
            CoinbaseTransaction::decode(bytes).err()
        });
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
}

#[test]
fn a_block_refuses_a_transfer_count_where_it_reads_it() {
    let campaign = Campaign::named("ledger: block caps");

    let ran = campaign.run(2_000, |_, rng| {
        let over = u32::try_from(MOST_TRANSFERS)
            .unwrap()
            .saturating_add(1)
            .saturating_add(rng.edgy_u32() % 1_000_000);
        // A header, then an empty coinbase, then the transfer count.
        let mut head = BlockHeader {
            version: 1,
            network: NetworkId::TESTNET,
            height: 0,
            previous: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 0,
            difficulty: 1,
            total_work: 1,
            nonce: 0,
        }
        .encode();
        head.extend_from_slice(&CoinbaseTransaction::new(0, Vec::new()).encode());
        refusal_for("Block transfers", over, &head, |bytes| {
            Block::decode(bytes).err()
        });
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
}

/// The largest thing a stranger can send, and the caps it has to hold before a
/// byte is reserved.
///
/// Seven counts, and every one of them is a number the sender chose. Each is
/// walked to just past its cap with nothing behind it, and each has to be
/// refused for what it says rather than for what did not follow.
#[test]
fn a_handover_refuses_every_count_where_it_reads_it() {
    let hot_over = 1u32 << 21;
    let maturing_over = 1u32 << 17;

    let head = handover_head();

    // The hot set.
    refusal_for("Handover hot set", hot_over, &head, |bytes| {
        Handover::decode(bytes).err()
    });

    // The grace window, in blocks.
    let mut before_grace = head.clone();
    before_grace.extend_from_slice(&0u32.encode());
    refusal_for(
        "Handover grace window",
        u32::try_from(GRACE_BLOCKS).unwrap().saturating_add(1),
        &before_grace,
        |bytes| Handover::decode(bytes).err(),
    );

    // The paths for that window.
    let mut before_proofs = before_grace.clone();
    before_proofs.extend_from_slice(&0u32.encode());
    refusal_for(
        "Handover grace proofs",
        u32::try_from(GRACE_NOTES).unwrap().saturating_add(1),
        &before_proofs,
        |bytes| Handover::decode(bytes).err(),
    );

    // The maturity window.
    let mut before_maturing = before_proofs.clone();
    before_maturing.extend_from_slice(&0u32.encode());
    refusal_for(
        "Handover maturity window",
        maturing_over,
        &before_maturing,
        |bytes| Handover::decode(bytes).err(),
    );

    // The recent headers, which come after the supply.
    let mut before_recent = before_maturing.clone();
    before_recent.extend_from_slice(&0u32.encode());
    before_recent.extend_from_slice(&Amount::ZERO.encode());
    refusal_for(
        "Handover recent headers",
        u32::try_from(RECENT_HEADERS).unwrap().saturating_add(1),
        &before_recent,
        |bytes| Handover::decode(bytes).err(),
    );

    // The buried run.
    let mut before_buried = before_recent.clone();
    before_buried.extend_from_slice(&0u32.encode());
    refusal_for(
        "Handover buried run",
        u32::try_from(MOST_BURIED).unwrap().saturating_add(1),
        &before_buried,
        |bytes| Handover::decode(bytes).err(),
    );
}

/// Everything a `Handover` reads before the first count a sender chooses.
fn handover_head() -> Vec<u8> {
    let header = BlockHeader {
        version: 1,
        network: NetworkId::TESTNET,
        height: 0,
        previous: Hash32::ZERO,
        transactions_root: Hash32::ZERO,
        state_root: Hash32::ZERO,
        history: Hash32::ZERO,
        timestamp: 0,
        difficulty: 1,
        total_work: 1,
        nonce: 0,
    };
    let mut head = header.encode();
    head.extend_from_slice(&header.encode());
    head.extend_from_slice(&Forest::new().encode());
    head.extend_from_slice(&ForestProof::default().encode());
    head.extend_from_slice(&Forest::new().encode());
    head.extend_from_slice(&Forest::new().encode());
    head
}

/// The same for the weighing that comes before a handover.
#[test]
fn a_sampled_start_refuses_every_count_where_it_reads_it() {
    let header = BlockHeader {
        version: 1,
        network: NetworkId::TESTNET,
        height: 0,
        previous: Hash32::ZERO,
        transactions_root: Hash32::ZERO,
        state_root: Hash32::ZERO,
        history: Hash32::ZERO,
        timestamp: 0,
        difficulty: 1,
        total_work: 1,
        nonce: 0,
    };
    let mut head = header.encode();
    head.extend_from_slice(&Forest::new().encode());
    // No parent.
    head.extend_from_slice(&0u8.encode());

    refusal_for(
        "SampledStart samples",
        u32::try_from(SAMPLES).unwrap().saturating_add(1),
        &head,
        |bytes| SampledStart::decode(bytes).err(),
    );

    let mut before_tail = head.clone();
    before_tail.extend_from_slice(&0u32.encode());
    refusal_for(
        "SampledStart tail",
        u32::try_from(MOST_TAIL).unwrap().saturating_add(1),
        &before_tail,
        |bytes| SampledStart::decode(bytes).err(),
    );
}

/// Nothing a decoder builds is larger than the bytes that paid for it.
///
/// The observable form of "no declared length drives an allocation". Every
/// element of every sequence here costs at least one byte on the wire, so a
/// value holding more elements than the frame has bytes could only have come
/// from a count the sender chose.
#[test]
fn nothing_decoded_holds_more_than_its_bytes_paid_for() {
    let campaign = Campaign::named("ledger: nothing is held for free");
    let seeds = {
        let mut rng = campaign.stream(0);
        let mut seeds = transaction_corpus(&mut rng);
        seeds.extend(join_corpus(&mut rng));
        seeds
    };

    let ran = campaign.run(8_000, |_, rng| {
        let seed = rng.pick(&seeds).cloned().unwrap_or_default();
        let bytes = mutate(rng, &seed, &seeds);
        let paid = bytes.len();

        if let Ok(transfer) = Transfer::decode(&bytes) {
            assert!(transfer.inputs.len() <= paid);
            assert!(transfer.outputs.len() <= paid);
        }
        if let Ok(coinbase) = CoinbaseTransaction::decode(&bytes) {
            assert!(coinbase.outputs.len() <= paid);
            assert!(coinbase.extra.len() <= MAX_COINBASE_EXTRA);
        }
        if let Ok(block) = Block::decode(&bytes) {
            assert!(block.transfers.len() <= paid);
        }
        if let Ok(handover) = Handover::decode(&bytes) {
            assert!(handover.hot.len() <= paid);
            assert!(handover.grace.len() <= paid);
            assert!(handover.grace_proofs.len() <= paid);
            assert!(handover.maturing.len() <= paid);
            assert!(handover.recent.len() <= paid);
            assert!(handover.buried.len() <= paid);
        }
        if let Ok(start) = SampledStart::decode(&bytes) {
            assert!(start.samples.len() <= paid);
            assert!(start.tail.len() <= paid);
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
}

/// The caps hold in the other direction too: a count exactly at the cap is
/// allowed, and one past it is not.
///
/// A cap tested only from above is a cap that could have been set to zero.
#[test]
fn each_cap_is_where_it_says_it_is() {
    // A transfer at the cap, and one input past it.
    let mut rng = Rng::new(1);
    let at_the_cap = Transfer {
        version: 1,
        inputs: (0..MOST_INPUTS)
            .map(|_| Input::hot(a_note_id(&mut rng)))
            .collect(),
        outputs: Vec::new(),
    };
    let bytes = at_the_cap.encode();
    assert!(Transfer::decode(&bytes).is_ok(), "the cap refuses itself");

    let over = Transfer {
        version: 1,
        inputs: (0..=MOST_INPUTS)
            .map(|_| Input::hot(a_note_id(&mut rng)))
            .collect(),
        outputs: Vec::new(),
    };
    assert_eq!(
        Transfer::decode(&over.encode()),
        Err(CodecError::InvalidValue {
            type_name: "transfer inputs"
        })
    );

    // A coinbase whose extra is exactly what is allowed, and one byte more.
    let at_the_cap = CoinbaseTransaction::with_extra(0, Vec::new(), vec![7; MAX_COINBASE_EXTRA]);
    assert!(CoinbaseTransaction::decode(&at_the_cap.encode()).is_ok());
    let over = CoinbaseTransaction::with_extra(0, Vec::new(), vec![7; MAX_COINBASE_EXTRA + 1]);
    assert_eq!(
        CoinbaseTransaction::decode(&over.encode()),
        Err(CodecError::InvalidValue {
            type_name: "coinbase extra"
        })
    );
}

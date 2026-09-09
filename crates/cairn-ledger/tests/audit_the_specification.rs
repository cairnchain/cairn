//! AUDIT: test vectors built from `docs/cairn-specification.md` and from
//! nothing else.
//!
//! The specification was written from the code, which is the way a
//! specification goes wrong: it says what its author remembered rather than
//! what the code does. One normative sentence about what a transfer identifier
//! covers was written backwards and caught only by going back to the source.
//!
//! So everything below is written the other way round. Each helper here
//! implements a structure's layout or a procedure from the document's own
//! words: the field tables, the numbered steps and the domain table are the
//! whole of the input. Where the document did not say enough to write a
//! helper, the assumption is named in a comment on the helper, and every one
//! of those is a finding about the specification rather than about the code.
//!
//! Where that independence is not complete it is said rather than claimed.
//! Looking for the struct fields to build values from, two encoders were seen
//! before the helpers that pin them were written: `BlockHeader`'s, and the
//! first four checks of `check_transfer_shape`. So the header layout vector
//! and the first three orderings in the transfer shape vector are confirming
//! rather than independent. Everything else here was written from the
//! document, and the header vector still checks the document's own byte
//! widths, which sum to the 182 it names.
//!
//! Two things the document does not contain at all, and which had to be taken
//! from the code because a vector cannot be written without them:
//!
//! - the context strings of ten of the twenty hash domains. The table in
//!   *What the state root commits to* publishes ten. The transfer domain, the
//!   coinbase domain, the block header domain, the signature domain, the
//!   sampling domain, the three Merkle domains and the header history domain
//!   are named in the prose and their constants are never given, and a tenth,
//!   the state entry domain, is not named anywhere in the document. `Domain`
//!   is used by name below wherever that happens, so what these vectors pin
//!   is the preimage and not the key it is hashed under.
//! - how `transactions_root` is built. It is a header field and refusal
//!   nineteen, and the document never says which leaves go into it, in what
//!   order, or under what tree.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::similar_names
)]

use std::collections::BTreeSet;

use cairn_accumulator::{Forest, ForestProof, Key, SparseMerkleTree};
use cairn_crypto::{PublicKey, SecretKey, Signature};
use cairn_ledger::block::{BlockHeader, HeaderSummary};
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::pow::{
    median_time_past, meets_target, next_difficulty, target_for, work_of, MIN_DIFFICULTY,
};
use cairn_ledger::sampling::{covering, draw, seed_of, work_before, Sample, SAMPLES, SHALLOWEST};
use cairn_ledger::state::{cold_leaf, note_key};
use cairn_ledger::transaction::{
    CoinbaseTransaction, Input, Transfer, Witness, COINBASE_VERSION, TRANSFER_VERSION,
};
use cairn_ledger::validation::{
    assemble_block, check_transfer_shape, connect_block, expected_difficulty, TransferError,
};
use cairn_ledger::{Block, ConsensusParams, LedgerState};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::{Amount, Decode, Encode, Hash32};

// ---------------------------------------------------------------------------
// Encoding the way part 1 describes it.
// ---------------------------------------------------------------------------

/// A sequence: "a `u32` count, little-endian, followed by that many items back
/// to back in order".
fn spec_sequence_header(count: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(&(count as u32).to_le_bytes());
}

/// A note: value as an eight byte amount, then the thirty two byte owner.
fn spec_note_bytes(note: &Note) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&note.value.as_pebbles().to_le_bytes());
    out.extend_from_slice(note.owner.as_bytes());
    out
}

/// A note identifier: the thirty two byte source, then the index as a `u32`.
fn spec_note_id_bytes(id: &NoteId) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(id.source.as_bytes());
    out.extend_from_slice(&id.index.to_le_bytes());
    out
}

/// A witness: a `u8` tag, then the bytes of the shape it selects.
///
/// Assumed, because the document does not say: the proof inside a cold witness
/// is a sequence of hashes in the sense part 1 gives, a `u32` count then the
/// siblings. The document gives that encoding for the proof beside a *sample*
/// in the weighing, at "4 + 32d", and never gives one for the proof inside a
/// witness.
fn spec_witness_bytes(witness: &Witness) -> Vec<u8> {
    let mut out = Vec::new();
    match witness {
        Witness::Hot => out.push(0),
        Witness::Cold(cold) => {
            out.push(1);
            out.extend_from_slice(&spec_note_bytes(&cold.note));
            out.extend_from_slice(&cold.position.to_le_bytes());
            spec_sequence_header(cold.proof.siblings.len(), &mut out);
            for sibling in &cold.proof.siblings {
                out.extend_from_slice(sibling.as_bytes());
            }
        }
    }
    out
}

/// An input: the note identifier, the witness, the signature.
fn spec_input_bytes(input: &Input) -> Vec<u8> {
    let mut out = spec_note_id_bytes(&input.note_id);
    out.extend_from_slice(&spec_witness_bytes(&input.witness));
    out.extend_from_slice(&input.signature.to_bytes());
    out
}

/// A transfer: version, sequence of inputs, sequence of notes.
fn spec_transfer_bytes(transfer: &Transfer) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&transfer.version.to_le_bytes());
    spec_sequence_header(transfer.inputs.len(), &mut out);
    for input in &transfer.inputs {
        out.extend_from_slice(&spec_input_bytes(input));
    }
    spec_sequence_header(transfer.outputs.len(), &mut out);
    for note in &transfer.outputs {
        out.extend_from_slice(&spec_note_bytes(note));
    }
    out
}

/// A coinbase: version, height, sequence of notes, sequence of bytes.
fn spec_coinbase_bytes(coinbase: &CoinbaseTransaction) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&coinbase.version.to_le_bytes());
    out.extend_from_slice(&coinbase.height.to_le_bytes());
    spec_sequence_header(coinbase.outputs.len(), &mut out);
    for note in &coinbase.outputs {
        out.extend_from_slice(&spec_note_bytes(note));
    }
    spec_sequence_header(coinbase.extra.len(), &mut out);
    out.extend_from_slice(&coinbase.extra);
    out
}

/// The eleven header fields, in the order the table gives them.
fn spec_header_bytes(header: &BlockHeader) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&header.version.to_le_bytes());
    out.extend_from_slice(&header.network.as_u32().to_le_bytes());
    out.extend_from_slice(&header.height.to_le_bytes());
    out.extend_from_slice(header.previous.as_bytes());
    out.extend_from_slice(header.transactions_root.as_bytes());
    out.extend_from_slice(header.state_root.as_bytes());
    out.extend_from_slice(header.history.as_bytes());
    out.extend_from_slice(&header.timestamp.to_le_bytes());
    out.extend_from_slice(&header.difficulty.to_le_bytes());
    out.extend_from_slice(&header.total_work.to_le_bytes());
    out.extend_from_slice(&header.nonce.to_le_bytes());
    out
}

/// "A block is its header, its coinbase, and its sequence of transfers."
fn spec_block_bytes(block: &Block) -> Vec<u8> {
    let mut out = spec_header_bytes(&block.header);
    out.extend_from_slice(&spec_coinbase_bytes(&block.coinbase));
    spec_sequence_header(block.transfers.len(), &mut out);
    for transfer in &block.transfers {
        out.extend_from_slice(&spec_transfer_bytes(transfer));
    }
    out
}

/// The transfer identifier's preimage: "the version, the count of inputs, each
/// input's note identifier alone, and the outputs".
///
/// Assumed, because the document says "the outputs" rather than spelling the
/// count out a second time: the outputs are a sequence in the part 1 sense, so
/// their own `u32` count is in the preimage.
fn spec_transfer_id_preimage(transfer: &Transfer) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&transfer.version.to_le_bytes());
    spec_sequence_header(transfer.inputs.len(), &mut out);
    for input in &transfer.inputs {
        out.extend_from_slice(&spec_note_id_bytes(&input.note_id));
    }
    spec_sequence_header(transfer.outputs.len(), &mut out);
    for note in &transfer.outputs {
        out.extend_from_slice(&spec_note_bytes(note));
    }
    out
}

/// What a signature commits to: "the network identifier, the transfer's
/// version, the transfer's identifier, the input's index, and the value and
/// owner of the note being spent".
///
/// Assumed: the index is a `u32`, which is the width the public signature of
/// `sign_input` names. The document gives no width for it.
fn spec_signature_message(
    transfer: &Transfer,
    network: NetworkId,
    index: u32,
    spent: &Note,
) -> Hash32 {
    let mut out = Vec::new();
    out.extend_from_slice(&network.as_u32().to_le_bytes());
    out.extend_from_slice(&transfer.version.to_le_bytes());
    out.extend_from_slice(
        hash(Domain::TransferId, &spec_transfer_id_preimage(transfer)).as_bytes(),
    );
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&spec_note_bytes(spent));
    hash(Domain::SignatureMessage, &out)
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn owner(seed: u8) -> PublicKey {
    wallet(seed).public_key()
}

fn note(pebbles: u64, seed: u8) -> Note {
    Note::new(Amount::from_pebbles(pebbles).unwrap(), owner(seed))
}

fn note_id(source: u8, index: u32) -> NoteId {
    NoteId::new(Hash32::from_bytes([source; 32]), index)
}

/// A transfer with one hot input and one cold input, signed, so that both
/// witness shapes and a real signature are in the bytes under test.
fn sample_transfer() -> Transfer {
    let spent = note(700_000_000, 3);
    let cold = note(300_000_000, 4);
    let proof = ForestProof {
        siblings: vec![
            Hash32::from_bytes([0x11; 32]),
            Hash32::from_bytes([0x22; 32]),
            Hash32::from_bytes([0x33; 32]),
        ],
    };
    let mut transfer = Transfer::new(
        vec![
            Input::hot(note_id(0xa1, 0)),
            Input::cold(note_id(0xb2, 7), cold, 42, proof),
        ],
        vec![note(600_000_000, 5), note(400_000_000, 6)],
    );
    transfer.sign_input(NetworkId::TESTNET, 0, &spent, &wallet(3));
    transfer.sign_input(NetworkId::TESTNET, 1, &note(300_000_000, 4), &wallet(4));
    transfer
}

fn sample_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        network: NetworkId::TESTNET,
        height: 0x0102_0304_0506_0708,
        previous: Hash32::from_bytes([0x41; 32]),
        transactions_root: Hash32::from_bytes([0x42; 32]),
        state_root: Hash32::from_bytes([0x43; 32]),
        history: Hash32::from_bytes([0x44; 32]),
        timestamp: 0x1122_3344_5566_7788,
        difficulty: 0x00ff_00ff_00ff_00ff,
        total_work: 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10,
        nonce: 0xdead_beef_cafe_f00d,
    }
}

// ---------------------------------------------------------------------------
// 1. The encodings.
// ---------------------------------------------------------------------------

#[test]
fn a_note_encodes_as_an_amount_then_an_owner() {
    let subject = note(1_234_567_890, 7);
    let built = spec_note_bytes(&subject);
    assert_eq!(
        built.len(),
        40,
        "the table says eight bytes then thirty two"
    );
    assert_eq!(&built[..8], &1_234_567_890u64.to_le_bytes());
    assert_eq!(subject.encode(), built);
}

#[test]
fn a_note_identifier_encodes_as_a_source_then_an_index() {
    let subject = note_id(0x5a, 0x0102_0304);
    let built = spec_note_id_bytes(&subject);
    assert_eq!(built.len(), 36);
    assert_eq!(&built[32..], &[0x04, 0x03, 0x02, 0x01]);
    assert_eq!(subject.encode(), built);
}

#[test]
fn a_transfer_encodes_as_version_inputs_outputs() {
    let subject = sample_transfer();
    let built = spec_transfer_bytes(&subject);

    // The widths the two tables promise, read back out of the bytes rather
    // than taken on trust: two for the version, four for each count, thirty
    // six then one then sixty four for a hot input.
    assert_eq!(&built[..2], &TRANSFER_VERSION.to_le_bytes());
    assert_eq!(&built[2..6], &2u32.to_le_bytes());
    assert_eq!(built[42], 0, "a hot witness is the tag and nothing further");
    // Version and count, then a hot input of 36 + 1 + 64 bytes, then the
    // second input's own 36 byte identifier, which puts its tag here.
    assert_eq!(built[107], 0xb2, "the second input starts with its source");
    assert_eq!(
        built[143], 1,
        "a cold witness is the tag and the note after"
    );

    assert_eq!(subject.encode(), built);
}

#[test]
fn a_coinbase_encodes_as_version_height_outputs_extra() {
    let subject = CoinbaseTransaction::with_extra(
        9,
        vec![note(5_000_000_000, 1)],
        b"a miner's bytes".to_vec(),
    );
    let built = spec_coinbase_bytes(&subject);
    assert_eq!(built.len(), 2 + 8 + 4 + 40 + 4 + 15);
    assert_eq!(&built[..2], &COINBASE_VERSION.to_le_bytes());
    assert_eq!(&built[2..10], &9u64.to_le_bytes());
    assert_eq!(subject.encode(), built);
}

#[test]
fn a_block_header_encodes_as_eleven_fields_and_is_a_hundred_and_eighty_two_bytes() {
    let subject = sample_header();
    let built = spec_header_bytes(&subject);
    assert_eq!(
        built.len(),
        182,
        "the document calls the header a fixed 182 bytes"
    );
    assert_eq!(BlockHeader::ENCODED_BYTES, 182);
    assert_eq!(subject.encode(), built);

    // The order is the part that a swap would leave every round trip passing,
    // so it is checked field by field rather than only in the whole.
    assert_eq!(&built[0..2], &1u16.to_le_bytes());
    assert_eq!(&built[2..6], &NetworkId::TESTNET.as_u32().to_le_bytes());
    assert_eq!(&built[6..14], &subject.height.to_le_bytes());
    assert_eq!(&built[14..46], subject.previous.as_bytes());
    assert_eq!(&built[46..78], subject.transactions_root.as_bytes());
    assert_eq!(&built[78..110], subject.state_root.as_bytes());
    assert_eq!(&built[110..142], subject.history.as_bytes());
    assert_eq!(&built[142..150], &subject.timestamp.to_le_bytes());
    assert_eq!(&built[150..158], &subject.difficulty.to_le_bytes());
    assert_eq!(&built[158..174], &subject.total_work.to_le_bytes());
    assert_eq!(&built[174..182], &subject.nonce.to_le_bytes());
}

#[test]
fn a_block_encodes_as_a_header_a_coinbase_and_a_sequence_of_transfers() {
    let block = Block {
        header: sample_header(),
        coinbase: CoinbaseTransaction::new(3, vec![note(5_000_000_000, 1)]),
        transfers: vec![sample_transfer()],
    };
    assert_eq!(block.encode(), spec_block_bytes(&block));
}

// ---------------------------------------------------------------------------
// 2. The identifiers.
// ---------------------------------------------------------------------------

#[test]
fn a_block_identifier_is_its_header_hashed_under_the_block_header_domain() {
    let header = sample_header();
    let expected = hash(Domain::BlockHeaderId, &spec_header_bytes(&header));
    assert_eq!(header.id(), expected);

    let block = Block {
        header,
        coinbase: CoinbaseTransaction::new(3, vec![note(5_000_000_000, 1)]),
        transfers: Vec::new(),
    };
    assert_eq!(
        block.id(),
        expected,
        "the identifier of a block is the identifier of its header"
    );
}

/// The document gives no separate rule for a coinbase identifier, so the
/// general one in part 3 applies: the hash of its encoding under its domain.
#[test]
fn a_coinbase_identifier_is_its_encoding_hashed_under_the_coinbase_domain() {
    let coinbase = CoinbaseTransaction::with_extra(11, vec![note(42, 2)], vec![0xaa, 0xbb]);
    assert_eq!(
        coinbase.id(),
        hash(Domain::CoinbaseId, &spec_coinbase_bytes(&coinbase))
    );
}

#[test]
fn a_transfer_identifier_covers_the_version_the_inputs_note_ids_and_the_outputs() {
    let transfer = sample_transfer();
    assert_eq!(
        transfer.id(),
        hash(Domain::TransferId, &spec_transfer_id_preimage(&transfer))
    );
    assert_ne!(
        transfer.id(),
        hash(Domain::TransferId, &spec_transfer_bytes(&transfer)),
        "a transfer's identifier is not the hash of its wire encoding"
    );
}

#[test]
fn changing_a_signature_or_a_witness_leaves_the_transfer_identifier_alone() {
    let transfer = sample_transfer();
    let before = transfer.id();

    let mut resigned = transfer.clone();
    resigned.inputs[0].signature = Signature::from_bytes(&[0x5c; 64]);
    assert_eq!(resigned.id(), before, "a signature is left out");

    let mut rewitnessed = transfer.clone();
    rewitnessed.inputs[1].witness = Witness::Hot;
    assert_eq!(rewitnessed.id(), before, "a witness is left out");

    let mut refreshed = transfer.clone();
    if let Witness::Cold(cold) = &mut refreshed.inputs[1].witness {
        cold.proof.siblings.push(Hash32::from_bytes([0x77; 32]));
        cold.position += 1;
    } else {
        panic!("the fixture's second input is the cold one");
    }
    assert_eq!(
        refreshed.id(),
        before,
        "refreshing a stale proof does not change what was built on it"
    );

    // And the converse, or the assertions above would hold of a constant.
    let mut moved = transfer.clone();
    moved.inputs[0].note_id.index += 1;
    assert_ne!(moved.id(), before);
    let mut repaid = transfer.clone();
    repaid.outputs[0] = note(1, 9);
    assert_ne!(repaid.id(), before);
    let mut reversioned = transfer;
    reversioned.version += 1;
    assert_ne!(reversioned.id(), before);
}

#[test]
fn a_signature_commits_to_the_network_version_identifier_index_and_spent_note() {
    let transfer = sample_transfer();
    let spent = note(700_000_000, 3);
    assert_eq!(
        transfer.signature_message(NetworkId::TESTNET, 0, &spent),
        spec_signature_message(&transfer, NetworkId::TESTNET, 0, &spent)
    );

    // The two that are "not obvious" in the document's own words: a wallet
    // shown a false value or a false owner signs a different message.
    let lied_value = note(700_000_001, 3);
    assert_ne!(
        transfer.signature_message(NetworkId::TESTNET, 0, &lied_value),
        transfer.signature_message(NetworkId::TESTNET, 0, &spent)
    );
    let lied_owner = note(700_000_000, 8);
    assert_ne!(
        transfer.signature_message(NetworkId::TESTNET, 0, &lied_owner),
        transfer.signature_message(NetworkId::TESTNET, 0, &spent)
    );
    // And the other three fields.
    assert_ne!(
        transfer.signature_message(NetworkId::DEVNET, 0, &spent),
        transfer.signature_message(NetworkId::TESTNET, 0, &spent)
    );
    assert_ne!(
        transfer.signature_message(NetworkId::TESTNET, 1, &spent),
        transfer.signature_message(NetworkId::TESTNET, 0, &spent)
    );
}

// ---------------------------------------------------------------------------
// 3. Proof of work.
// ---------------------------------------------------------------------------

/// `MAX / d`, truncated, done in base 2^32 so that it is not the same long
/// division the document says the reference implementation performs.
fn spec_target(difficulty: u64) -> [u8; 32] {
    if difficulty <= 1 {
        return [0xff; 32];
    }
    let divisor = u128::from(difficulty);
    let mut out = [0u8; 32];
    let mut remainder: u128 = 0;
    for limb in 0..8usize {
        let current = (remainder << 32) | u128::from(u32::MAX);
        let quotient = current / divisor;
        remainder = current % divisor;
        out[limb * 4..limb * 4 + 4].copy_from_slice(&(quotient as u32).to_be_bytes());
    }
    out
}

fn one_above(value: [u8; 32]) -> Option<[u8; 32]> {
    let mut out = value;
    for byte in out.iter_mut().rev() {
        let (next, carried) = byte.overflowing_add(1);
        *byte = next;
        if !carried {
            return Some(out);
        }
    }
    None
}

#[test]
fn the_target_is_the_whole_range_divided_by_the_difficulty() {
    // The eight answers the document publishes, spelled the way it spells
    // them, so the table is checked and not only the division.
    let published: [(u64, Vec<u8>); 8] = [
        (1, vec![0xff; 32]),
        (2, [vec![0x7f], vec![0xff; 31]].concat()),
        (3, vec![0x55; 32]),
        (4, [vec![0x3f], vec![0xff; 31]].concat()),
        (5, vec![0x33; 32]),
        (4_096, [vec![0x00, 0x0f], vec![0xff; 30]].concat()),
        (1 << 23, [vec![0x00, 0x00, 0x01], vec![0xff; 29]].concat()),
        (
            1 << 27,
            [vec![0x00, 0x00, 0x00, 0x1f], vec![0xff; 28]].concat(),
        ),
    ];
    for (difficulty, want) in published {
        assert_eq!(
            target_for(difficulty).to_vec(),
            want,
            "the published target for difficulty {difficulty}"
        );
        assert_eq!(spec_target(difficulty).to_vec(), want);
    }

    // Zero and one agree, which is the whole reason the first branch exists.
    assert_eq!(target_for(0), [0xff; 32]);
    assert_eq!(target_for(0), target_for(1));

    // And the division itself, over a spread that is not a power of two.
    for difficulty in [
        2u64,
        3,
        7,
        10,
        999,
        65_535,
        1_000_003,
        u64::MAX / 3,
        u64::MAX,
    ] {
        assert_eq!(
            target_for(difficulty),
            spec_target(difficulty),
            "the long division at difficulty {difficulty}"
        );
    }
}

#[test]
fn an_identifier_equal_to_the_target_meets_it_and_one_above_does_not() {
    for difficulty in [2u64, 3, 4_096, 1 << 27, 1_000_003] {
        let target = target_for(difficulty);
        assert!(
            meets_target(&Hash32::from_bytes(target), difficulty),
            "equality passes, at difficulty {difficulty}"
        );
        let above = one_above(target).expect("a target below the whole range");
        assert!(
            !meets_target(&Hash32::from_bytes(above), difficulty),
            "one above the target is refused, at difficulty {difficulty}"
        );
    }
    // At the floor every identifier meets the target.
    assert!(meets_target(
        &Hash32::from_bytes([0xff; 32]),
        MIN_DIFFICULTY
    ));
}

#[test]
fn the_work_a_block_contributes_is_its_difficulty_unchanged() {
    for difficulty in [0u64, 1, 2, 4_096, 1 << 27, u64::MAX] {
        assert_eq!(work_of(difficulty), u128::from(difficulty));
    }
    let header = sample_header();
    assert_eq!(
        work_before(&header),
        header.total_work - u128::from(header.difficulty)
    );
}

// ---------------------------------------------------------------------------
// 4. The difficulty retarget, as the fourteen numbered steps.
// ---------------------------------------------------------------------------

/// Steps 2 to 14. Step 1 is not reachable through this function: it names the
/// network's genesis difficulty, which `next_difficulty` is not given.
fn spec_next_difficulty(run: &[HeaderSummary], target_block_time: u64) -> u64 {
    let m = run.len();
    assert!(
        m > 0,
        "step 1 is asked of the network, not of this function"
    );
    let last = run[m - 1];
    let n = usize::min(m - 1, 90);
    if n == 0 || target_block_time == 0 {
        return last.difficulty.max(1);
    }
    let window = &run[m - 1 - n..];
    let ceiling = i128::from(target_block_time) * 6;
    let mut counted = i128::from(window[0].timestamp);
    let mut weighted: i128 = 0;
    let mut sum_of_difficulty: u128 = 0;
    for (i, summary) in window.iter().enumerate().skip(1) {
        let gap = (i128::from(summary.timestamp) - counted).clamp(-ceiling, ceiling);
        counted += gap;
        weighted += (i as i128) * gap;
        sum_of_difficulty += u128::from(summary.difficulty);
    }
    let previous = last.difficulty.max(1);
    if weighted <= 0 {
        return previous.saturating_mul(4);
    }
    let n_wide = n as u128;
    let expected = n_wide * (n_wide + 1) / 2 * u128::from(target_block_time);
    let average = (sum_of_difficulty / n_wide).max(1);
    let next = average.saturating_mul(expected) / (weighted as u128);
    let low = u128::from((previous / 4).max(1));
    let high = u128::from(previous.saturating_mul(4));
    u64::try_from(next.clamp(low, high))
        .unwrap_or(u64::MAX)
        .max(1)
}

/// A run of `count` summaries at one difficulty, evenly spaced.
fn even_run(count: usize, spacing: u64, difficulty: u64) -> Vec<HeaderSummary> {
    (0..count as u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: 1_000_000 + height * spacing,
            difficulty,
        })
        .collect()
}

#[test]
fn the_retarget_answers_what_the_documents_worked_figures_say() {
    let target = 60u64;

    // A full window warmed exactly on schedule at a million, with the last
    // block arriving at the clamp ceiling. The document says 900 990.
    let mut window = even_run(91, target, 1_000_000);
    window[90].timestamp = window[89].timestamp + 6 * target;
    assert_eq!(next_difficulty(&window, target), 900_990);
    assert_eq!(spec_next_difficulty(&window, target), 900_990);

    // A hundred times the target late is the same block, because the clamp
    // makes it the same block.
    let mut far = even_run(91, target, 1_000_000);
    far[90].timestamp = far[89].timestamp + 100 * target;
    assert_eq!(next_difficulty(&far, target), 900_990);
    assert_eq!(spec_next_difficulty(&far, target), 900_990);

    // On schedule, the difficulty does not move.
    let steady = even_run(91, target, 1_000_000);
    assert_eq!(next_difficulty(&steady, target), 1_000_000);
    assert_eq!(spec_next_difficulty(&steady, target), 1_000_000);
}

#[test]
fn the_floor_is_held_from_thirty_one_seconds_and_not_from_sixty() {
    let target = 60u64;
    let published = [
        (1u64, 4u64),
        (15, 4),
        (20, 3),
        (30, 2),
        (31, 1),
        (60, 1),
        (600, 1),
    ];
    for (spacing, want) in published {
        let window = even_run(91, spacing, MIN_DIFFICULTY);
        assert_eq!(
            next_difficulty(&window, target),
            want,
            "the floor at {spacing} seconds a block"
        );
        assert_eq!(spec_next_difficulty(&window, target), want);
    }
}

#[test]
fn a_span_of_zero_or_a_span_running_backwards_is_the_steepest_rise_allowed() {
    let target = 60u64;

    let flat: Vec<HeaderSummary> = (0..91u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: 1_000_000,
            difficulty: 1_000,
        })
        .collect();
    assert_eq!(next_difficulty(&flat, target), 4_000);
    assert_eq!(spec_next_difficulty(&flat, target), 4_000);

    let backwards: Vec<HeaderSummary> = (0..91u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: 1_000_000 - height * 10,
            difficulty: 1_000,
        })
        .collect();
    assert_eq!(next_difficulty(&backwards, target), 4_000);
    assert_eq!(spec_next_difficulty(&backwards, target), 4_000);

    // Saturation rather than a wrap, at the top.
    let huge: Vec<HeaderSummary> = (0..91u64)
        .map(|height| HeaderSummary {
            height,
            timestamp: 1_000_000,
            difficulty: u64::MAX,
        })
        .collect();
    assert_eq!(next_difficulty(&huge, target), u64::MAX);
    assert_eq!(spec_next_difficulty(&huge, target), u64::MAX);
}

#[test]
fn a_chain_shorter_than_the_window_runs_the_same_formula() {
    let target = 60u64;

    // One summary: n is 0, so the block at height 1 carries the genesis
    // difficulty unchanged.
    let one = even_run(1, target, 12_345);
    assert_eq!(next_difficulty(&one, target), 12_345);
    assert_eq!(spec_next_difficulty(&one, target), 12_345);

    // Two summaries: the first retarget, off a single gap.
    for spacing in [1u64, 30, 59, 60, 61, 120, 360, 100_000] {
        let two = even_run(2, spacing, 1_000_000);
        assert_eq!(
            next_difficulty(&two, target),
            spec_next_difficulty(&two, target),
            "the first retarget at {spacing} seconds"
        );
    }

    // Every length from one to a hundred, so that both the short case and the
    // "use only the last 91" cut are covered.
    for count in 1..=100usize {
        let run = even_run(count, 45, 500_000);
        assert_eq!(
            next_difficulty(&run, target),
            spec_next_difficulty(&run, target),
            "a run of {count} summaries"
        );
    }
}

#[test]
fn a_node_given_a_longer_run_uses_only_the_last_ninety_one() {
    let target = 60u64;
    let long = even_run(400, 45, 500_000);
    let cut = &long[long.len() - 91..];
    assert_eq!(
        next_difficulty(&long, target),
        next_difficulty(cut, target),
        "history beyond 91 summaries must not change the answer"
    );
    assert_eq!(
        spec_next_difficulty(&long, target),
        next_difficulty(cut, target)
    );
}

#[test]
fn the_retarget_agrees_over_a_sweep_of_awkward_windows() {
    let target = 60u64;
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut checked = 0u32;
    for case in 0..600u32 {
        let count = 1 + (next() % 120) as usize;
        let mut timestamp = 1_000_000i128;
        let mut run = Vec::with_capacity(count);
        for height in 0..count as u64 {
            // Steps well past the clamp in both directions, so the timeline
            // the retarget keeps for itself is exercised rather than assumed.
            let step = (next() % 1_500) as i128 - 500;
            timestamp = (timestamp + step).max(0);
            let difficulty = match case % 4 {
                0 => 1,
                1 => 1 + next() % 8,
                2 => 1 + next() % 4_000_000,
                _ => u64::MAX / (1 + next() % 3),
            };
            run.push(HeaderSummary {
                height,
                timestamp: timestamp as u64,
                difficulty,
            });
        }
        assert_eq!(
            next_difficulty(&run, target),
            spec_next_difficulty(&run, target),
            "case {case}, {count} summaries"
        );
        checked += 1;
    }
    assert_eq!(checked, 600);
}

#[test]
fn an_empty_branch_takes_the_networks_genesis_difficulty() {
    let params = ConsensusParams::testnet();
    let state = LedgerState::new();
    assert_eq!(
        expected_difficulty(&state, &params),
        params.genesis_difficulty.max(MIN_DIFFICULTY)
    );
}

// ---------------------------------------------------------------------------
// 5. The median time past.
// ---------------------------------------------------------------------------

/// "the last 11 header summaries of the branch, or all of them if it holds
/// fewer: take their timestamps, sort them ascending, and take the element at
/// index `len / 2`".
fn spec_median_time_past(run: &[HeaderSummary]) -> Option<u64> {
    if run.is_empty() {
        return None;
    }
    let start = run.len().saturating_sub(11);
    let mut stamps: Vec<u64> = run[start..]
        .iter()
        .map(|summary| summary.timestamp)
        .collect();
    stamps.sort_unstable();
    stamps.get(stamps.len() / 2).copied()
}

#[test]
fn the_median_time_past_takes_the_upper_middle_and_never_an_average() {
    assert_eq!(median_time_past(&[]), None);
    assert_eq!(spec_median_time_past(&[]), None);

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for count in 1..=40usize {
        let run: Vec<HeaderSummary> = (0..count as u64)
            .map(|height| HeaderSummary {
                height,
                timestamp: next() % 100_000,
                difficulty: 1,
            })
            .collect();
        assert_eq!(
            median_time_past(&run),
            spec_median_time_past(&run),
            "a branch of {count} summaries"
        );
    }

    // The even case said out loud: two middle values, and the upper one wins.
    let two = vec![
        HeaderSummary {
            height: 0,
            timestamp: 100,
            difficulty: 1,
        },
        HeaderSummary {
            height: 1,
            timestamp: 200,
            difficulty: 1,
        },
    ];
    assert_eq!(median_time_past(&two), Some(200));
    assert_eq!(spec_median_time_past(&two), Some(200));
}

// ---------------------------------------------------------------------------
// 6. Emission.
// ---------------------------------------------------------------------------

/// "Let `e = h / 1 051 200` ... Let `r` be the opening reward in pebbles
/// shifted right by `e` bits, taken as 0 when `e` is 64 or more. The reward is
/// the larger of `r` and the floor reward."
fn spec_reward_at(height: u64) -> u64 {
    let era = height / 1_051_200;
    let shifted = if era >= 64 {
        0
    } else {
        5_000_000_000u64 >> era
    };
    shifted.max(1_000_000)
}

#[test]
fn the_reward_follows_the_shift_and_the_floor() {
    let params = ConsensusParams::testnet();

    // The published era table, first height and rate.
    let table: [(u64, u64); 14] = [
        (0, 5_000_000_000),
        (1_051_200, 2_500_000_000),
        (2_102_400, 1_250_000_000),
        (3_153_600, 625_000_000),
        (4_204_800, 312_500_000),
        (5_256_000, 156_250_000),
        (6_307_200, 78_125_000),
        (7_358_400, 39_062_500),
        (8_409_600, 19_531_250),
        (9_460_800, 9_765_625),
        (10_512_000, 4_882_812),
        (11_563_200, 2_441_406),
        (12_614_400, 1_220_703),
        (13_665_600, 1_000_000),
    ];
    for (height, want) in table {
        assert_eq!(spec_reward_at(height), want, "the era opening at {height}");
        assert_eq!(
            params.reward_at(height).as_pebbles(),
            want,
            "the era opening at {height}"
        );
    }

    // The boundaries, either side, and a spread through the middle.
    for era in 0..20u64 {
        for offset in [0u64, 1, 1_051_199] {
            let height = era * 1_051_200 + offset;
            assert_eq!(
                params.reward_at(height).as_pebbles(),
                spec_reward_at(height),
                "the reward at height {height}"
            );
        }
    }
    for height in [
        1u64,
        7,
        999_999,
        10_512_000,
        13_665_599,
        u64::MAX / 2,
        u64::MAX,
    ] {
        assert_eq!(
            params.reward_at(height).as_pebbles(),
            spec_reward_at(height)
        );
    }

    // "The thirteen rates in the table sum to 9 998 779 296 pebbles."
    let rates: u64 = (0..13u64).map(|era| spec_reward_at(era * 1_051_200)).sum();
    assert_eq!(rates, 9_998_779_296);
    assert_eq!(
        u128::from(rates) * 1_051_200,
        10_510_716_795_955_200,
        "the whole of the halvings"
    );

    // And the ceiling, which is the bound on every amount in the protocol.
    assert_eq!(Amount::MAX_MONEY.as_pebbles(), 100_000_000_000_000_000);
}

// ---------------------------------------------------------------------------
// 7. The sampling draw. The document names this as its own worst gap.
// ---------------------------------------------------------------------------

/// "`bit_length(x)` is 64 less the number of leading zero bits of `x` as a
/// `u64`".
fn spec_bit_length(value: u64) -> u32 {
    64 - value.leading_zeros()
}

/// `separable = height / 1024`, `levels = max(bit_length(max(separable, 1)), 1)`
fn spec_levels(height: u64) -> u32 {
    spec_bit_length((height / 1_024).max(1)).max(1)
}

/// What a reimplementation reaching for a base-two logarithm writes instead.
/// Identical everywhere except at a power of two, which is the point.
fn logarithm_levels(height: u64) -> u32 {
    let separable = (height / 1_024).max(1);
    let mut levels = 0u32;
    while (1u64 << levels) < separable {
        levels += 1;
    }
    levels.max(1)
}

/// The seven steps of the draw, in order.
fn spec_draw(seed: Hash32, count: usize, total: u128, blocks: u64) -> Vec<u128> {
    if total == 0 || count == 0 {
        return Vec::new();
    }
    let levels = u128::from(spec_levels(blocks));
    let mut drawn = Vec::with_capacity(count);
    for index in 0..count as u64 {
        let mut preimage = Vec::with_capacity(40);
        preimage.extend_from_slice(seed.as_bytes());
        preimage.extend_from_slice(&index.to_le_bytes());
        let bytes = hash(Domain::SamplingSeed, &preimage);
        let bytes = bytes.as_bytes();

        let level = u128::from(bytes[0]) % levels;
        let mut within_bytes = [0u8; 16];
        within_bytes.copy_from_slice(&bytes[8..24]);
        let within = u128::from_le_bytes(within_bytes);

        let far = total >> u32::min(level as u32, 127);
        let near = total >> u32::min(level as u32 + 1, 127);
        let width = far.saturating_sub(near).max(1);
        let value = (total.saturating_sub(far))
            .saturating_add(within % width)
            .min(total - 1);
        drawn.push(value);
    }
    drawn
}

#[test]
fn the_seed_is_the_tips_identifier_hashed_under_the_sampling_domain() {
    let tip = sample_header();
    assert_eq!(
        seed_of(&tip),
        hash(Domain::SamplingSeed, tip.id().as_bytes()),
        "a hash encodes as its bytes, with no length prefix"
    );
}

#[test]
fn the_level_count_counts_leading_zeros_and_not_a_logarithm() {
    // The two agree away from a power of two and part on one, which is what
    // makes this vector worth having at all.
    let mut apart = 0u32;
    for exponent in 1..40u32 {
        let separable = 1u64 << exponent;
        let height = separable * 1_024;
        assert_eq!(spec_levels(height), exponent + 1);
        assert_eq!(logarithm_levels(height), exponent);
        apart += 1;
        // One block either side, where they agree again.
        assert_eq!(
            spec_levels(height + 1_024),
            logarithm_levels(height + 1_024)
        );
        assert_eq!(
            spec_levels(height - 1_024),
            logarithm_levels(height - 1_024)
        );
    }
    assert_eq!(apart, 39);

    // The figure the document publishes: thirty years at a block a minute.
    assert_eq!(spec_levels(30 * 365 * 24 * 60), 14);
    // And the narrowest band the draw separates.
    assert_eq!(SHALLOWEST, 1_024);
    assert_eq!(SAMPLES, 4_096);
}

#[test]
fn the_draw_is_the_seven_steps_the_document_gives() {
    let seeds = [
        Hash32::ZERO,
        Hash32::from_bytes([0xff; 32]),
        hash(Domain::SamplingSeed, b"a tip"),
        hash(Domain::SamplingSeed, b"another tip"),
    ];
    // Heights chosen so that `separable` lands on a power of two on purpose,
    // and either side of one, and below the first band.
    let mut heights = vec![0u64, 1, 1_023, 1_024, 1_025, 2_047, 30 * 365 * 24 * 60];
    for exponent in 0..24u32 {
        let separable = 1u64 << exponent;
        heights.push(separable * 1_024);
        heights.push(separable * 1_024 + 1);
        heights.push(separable * 1_024 - 1);
    }
    // Totals on powers of two, either side, and at the extremes of a u128.
    let mut totals = vec![0u128, 1, 2, 3, 1_000, u128::MAX, u128::MAX - 1];
    for exponent in 0..127u32 {
        totals.push(1u128 << exponent);
        totals.push((1u128 << exponent) + 1);
    }

    let mut agreed = 0u32;
    for seed in seeds {
        for &blocks in &heights {
            for &total in &totals {
                let count = 4;
                assert_eq!(
                    draw(seed, count, total, blocks),
                    spec_draw(seed, count, total, blocks),
                    "the draw at total {total}, height {blocks}"
                );
                agreed += 1;
            }
        }
    }
    assert!(agreed > 25_000, "only {agreed} combinations were compared");

    // The empty cases the document names, and a full draw at the published
    // count, which is the one a real weighing runs.
    assert!(draw(seeds[0], 0, 1_000, 10_000).is_empty());
    assert!(draw(seeds[0], 8, 0, 10_000).is_empty());
    let full = draw(seeds[2], SAMPLES, 1 << 40, 30 * 365 * 24 * 60);
    assert_eq!(full.len(), SAMPLES);
    assert_eq!(
        full,
        spec_draw(seeds[2], SAMPLES, 1 << 40, 30 * 365 * 24 * 60)
    );
}

#[test]
fn a_logarithm_in_place_of_the_leading_zeros_would_draw_different_questions() {
    // The claim the document makes about its own gap, measured: at a power of
    // two the two level counts differ, and a draw made under the wrong one is
    // a different draw. Without this the vector above could be passing on a
    // range where the mistake does not show.
    let seed = hash(Domain::SamplingSeed, b"a tip");
    let total = 1u128 << 40;
    let mut differed = 0u32;
    for exponent in 1..20u32 {
        let blocks = (1u64 << exponent) * 1_024;
        let honest = spec_draw(seed, 32, total, blocks);
        let mistaken: Vec<u128> = {
            // The same seven steps with the one substitution.
            let levels = u128::from(logarithm_levels(blocks));
            (0..32u64)
                .map(|index| {
                    let mut preimage = Vec::with_capacity(40);
                    preimage.extend_from_slice(seed.as_bytes());
                    preimage.extend_from_slice(&index.to_le_bytes());
                    let bytes = hash(Domain::SamplingSeed, &preimage);
                    let bytes = bytes.as_bytes();
                    let level = u128::from(bytes[0]) % levels;
                    let mut within_bytes = [0u8; 16];
                    within_bytes.copy_from_slice(&bytes[8..24]);
                    let within = u128::from_le_bytes(within_bytes);
                    let far = total >> (level as u32);
                    let near = total >> (level as u32 + 1);
                    let width = far.saturating_sub(near).max(1);
                    (total - far).saturating_add(within % width).min(total - 1)
                })
                .collect()
        };
        assert_ne!(
            honest, mistaken,
            "at height {blocks} the two level counts drew the same questions"
        );
        differed += 1;
    }
    assert_eq!(differed, 19);
}

#[test]
fn a_drawn_value_names_the_header_whose_own_work_spans_it() {
    // `h.total_work - h.difficulty <= value` and `h.total_work > value`.
    // Assumed, because the document describes the search and not the call:
    // the tuple the implementation takes is height, total work, difficulty.
    let mut headers = Vec::new();
    let mut total = 0u128;
    for height in 0..64u64 {
        let difficulty = 10 + height % 7;
        total += u128::from(difficulty);
        headers.push((height, total, difficulty));
    }
    for value in 0..total {
        let found = covering(&headers, value).expect("every value below the total is covered");
        let (height, work, difficulty) = headers[found as usize];
        assert_eq!(height, found);
        assert!(work - u128::from(difficulty) <= value && work > value);
    }
    assert_eq!(covering(&headers, total), None);
}

// ---------------------------------------------------------------------------
// 8. The state root.
// ---------------------------------------------------------------------------

/// A subtree hashes by what it holds and by nothing else.
fn spec_subtree(items: &[([u8; 32], Hash32)], depth: usize) -> Hash32 {
    match items.len() {
        0 => hash(Domain::AccumulatorEmpty, &[]),
        1 => {
            let (key, value) = items[0];
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(&key);
            bytes.extend_from_slice(value.as_bytes());
            hash(Domain::AccumulatorLeaf, &bytes)
        }
        _ => {
            let split = items.partition_point(|(key, _)| !bit_at(key, depth));
            let left = spec_subtree(&items[..split], depth + 1);
            let right = spec_subtree(&items[split..], depth + 1);
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(left.as_bytes());
            bytes.extend_from_slice(right.as_bytes());
            hash(Domain::AccumulatorNode, &bytes)
        }
    }
}

/// "read as a path from the root, one bit per level, starting at the most
/// significant bit of the first byte; a set bit means the right child".
fn bit_at(key: &[u8; 32], depth: usize) -> bool {
    key[depth / 8] & (0x80 >> (depth % 8)) != 0
}

fn spec_hot_root(mut entries: Vec<([u8; 32], Hash32)>) -> Hash32 {
    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    spec_subtree(&entries, 0)
}

/// "the hash, under the note key domain, of the note identifier's 36-byte
/// encoding".
fn spec_note_key(id: &NoteId) -> [u8; 32] {
    hash(Domain::NoteKey, &spec_note_id_bytes(id)).to_bytes()
}

/// "the hash, under the hot note value domain, of the note's 40-byte encoding
/// followed by the height of the block that created it, as a `u64`".
fn spec_hot_value(subject: &Note, height: u64) -> Hash32 {
    let mut bytes = spec_note_bytes(subject);
    bytes.extend_from_slice(&height.to_le_bytes());
    hash(Domain::HotNoteValue, &bytes)
}

/// "its 36-byte identifier then its 40-byte encoding, under the forest leaf
/// domain".
fn spec_cold_leaf(id: &NoteId, subject: &Note) -> Hash32 {
    let mut bytes = spec_note_id_bytes(id);
    bytes.extend_from_slice(&spec_note_bytes(subject));
    hash(Domain::ForestLeaf, &bytes)
}

fn spec_empty_leaf() -> Hash32 {
    hash(Domain::ForestLeaf, &[])
}

fn spec_forest_node(left: Hash32, right: Hash32) -> Hash32 {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(left.as_bytes());
    bytes.extend_from_slice(right.as_bytes());
    hash(Domain::ForestNode, &bytes)
}

/// "the new leaf becomes a tree of height 0; while a tree of the same height
/// already exists, that existing tree becomes the left child, the carry
/// becomes the right, and the two merge into a tree one height taller".
fn spec_forest_roots(leaves: &[Hash32]) -> Vec<Option<Hash32>> {
    let mut roots: Vec<Option<Hash32>> = vec![None; 64];
    for leaf in leaves {
        let mut carry = *leaf;
        let mut height = 0usize;
        while let Some(existing) = roots[height].take() {
            carry = spec_forest_node(existing, carry);
            height += 1;
        }
        roots[height] = Some(carry);
    }
    roots
}

/// "`leaves` as a `u64`; `live` as a `u64`; then, for each height from 0 to 63
/// in ascending order that has a tree, one byte of height followed by that
/// tree's 32-byte root".
fn spec_cold_commitment(leaves: &[Hash32], live: u64) -> Hash32 {
    let roots = spec_forest_roots(leaves);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&live.to_le_bytes());
    for (height, root) in roots.iter().enumerate() {
        if let Some(root) = root {
            bytes.push(height as u8);
            bytes.extend_from_slice(root.as_bytes());
        }
    }
    hash(Domain::ForestRoots, &bytes)
}

/// "the number of landings as a `u64`; then, for each landing in order, the
/// number of notes in it as a `u64`, then for each note its 36-byte
/// identifier, its position as a `u64`, and its 40-byte encoding".
fn spec_grace_root(window: &[Vec<(NoteId, u64, Note)>]) -> Hash32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(window.len() as u64).to_le_bytes());
    for landing in window {
        bytes.extend_from_slice(&(landing.len() as u64).to_le_bytes());
        for (id, position, subject) in landing {
            bytes.extend_from_slice(&spec_note_id_bytes(id));
            bytes.extend_from_slice(&position.to_le_bytes());
            bytes.extend_from_slice(&spec_note_bytes(subject));
        }
    }
    hash(Domain::GraceWindow, &bytes)
}

/// The eight fields the table gives, in that order, and nothing else.
fn spec_state_root(
    hot_root: Hash32,
    hot_count: u64,
    cold_commitment: Hash32,
    cold_count: u64,
    grace_root: Hash32,
    maturing: &[(u64, Hash32)],
    issued: u64,
) -> Hash32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(hot_root.as_bytes());
    bytes.extend_from_slice(&hot_count.to_le_bytes());
    bytes.extend_from_slice(cold_commitment.as_bytes());
    bytes.extend_from_slice(&cold_count.to_le_bytes());
    bytes.extend_from_slice(grace_root.as_bytes());
    bytes.extend_from_slice(&(maturing.len() as u64).to_le_bytes());
    for (height, id) in maturing {
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(id.as_bytes());
    }
    bytes.extend_from_slice(&issued.to_le_bytes());
    hash(Domain::StateCommitment, &bytes)
}

#[test]
fn the_two_public_leaf_functions_hash_what_the_document_says_they_do() {
    let id = note_id(0x3c, 5);
    let subject = note(999, 2);
    assert_eq!(note_key(&id), Key::from_bytes(spec_note_key(&id)));
    assert_eq!(cold_leaf(&id, &subject), spec_cold_leaf(&id, &subject));
}

#[test]
fn the_hot_tree_hashes_by_what_a_subtree_holds_and_by_nothing_else() {
    // The empty root, the lone leaf that hashes the same at every depth, and
    // sets big enough that the paths branch at several levels.
    let mut tree = SparseMerkleTree::new();
    assert_eq!(tree.root(), hash(Domain::AccumulatorEmpty, &[]));
    assert_eq!(spec_hot_root(Vec::new()), tree.root());

    let mut entries: Vec<([u8; 32], Hash32)> = Vec::new();
    for index in 0..64u32 {
        let id = NoteId::new(Hash32::from_bytes([(index % 7) as u8; 32]), index);
        let subject = note(u64::from(index) + 1, (index % 5) as u8);
        let key = spec_note_key(&id);
        let value = spec_hot_value(&subject, u64::from(index) / 4);
        tree.insert(Key::from_bytes(key), value);
        entries.push((key, value));
        assert_eq!(
            tree.root(),
            spec_hot_root(entries.clone()),
            "the root over {} notes",
            entries.len()
        );
    }

    // And removal takes it back down the same path, so the root is a function
    // of the set rather than of how the set was reached.
    while let Some((key, _)) = entries.pop() {
        tree.remove(Key::from_bytes(key));
        assert_eq!(tree.root(), spec_hot_root(entries.clone()));
    }
}

#[test]
fn an_empty_state_folds_to_the_eight_empty_fields() {
    let state = LedgerState::new();
    let hot_root = hash(Domain::AccumulatorEmpty, &[]);
    let cold = spec_cold_commitment(&[], 0);
    let grace = spec_grace_root(&state.grace_window());
    assert_eq!(state.grace_root(), grace);
    assert_eq!(
        state.state_root(),
        spec_state_root(hot_root, 0, cold, 0, grace, &[], 0)
    );
}

#[test]
fn the_state_root_is_the_eight_fields_folded_in_that_order() {
    // A tier small enough that blocks push notes out of it, a maturity short
    // enough that a reward can be spent inside the fixture, and a spend of a
    // note sitting in the grace window, so that `live` and `leaves` part.
    let params = ConsensusParams::testnet()
        .with_hot_capacity(4)
        .with_burial(2)
        .with_coinbase_maturity(2);
    let miner = wallet(1);
    let mut state = LedgerState::new();

    // Every leaf the accumulator was handed, in position order, and the
    // positions that have since been emptied. Both are kept here rather than
    // read off the implementation.
    let mut leaves: Vec<Hash32> = Vec::new();
    let mut emptied: BTreeSet<u64> = BTreeSet::new();
    let mut spendable: Vec<(NoteId, u64, Note)> = Vec::new();
    let mut roots_compared = 0u32;

    for height in 0..12u64 {
        let reward = params.reward_at(height);
        let half = Amount::from_pebbles(reward.as_pebbles() / 2).unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![
                Note::new(half, miner.public_key()),
                Note::new(
                    Amount::from_pebbles(reward.as_pebbles() - half.as_pebbles()).unwrap(),
                    owner(2),
                ),
            ],
        );

        // From the fourth block on, spend a note that has already fallen and
        // is still inside the window, which empties its leaf.
        let mut transfers = Vec::new();
        let mut spent_position = None;
        if height >= 4 {
            if let Some((id, position, fallen)) = spendable
                .iter()
                .find(|(id, _, fallen)| {
                    fallen.owner == miner.public_key()
                        && state.within_grace(id).is_some()
                        && state
                            .coinbase_matures_at(&id.source)
                            .is_none_or(|at| at <= height)
                })
                .copied()
            {
                let mut transfer = Transfer::new(
                    vec![Input::hot(id)],
                    vec![Note::new(fallen.value, owner(6))],
                );
                transfer.sign_input(params.network, 0, &fallen, &wallet(1));
                transfers.push(transfer);
                spent_position = Some(position);
            }
        }

        let block = assemble_block(
            &state,
            coinbase,
            transfers,
            &params,
            1_000 + height * 600,
            0,
        )
        .expect("the fixture builds a block the rules accept");
        connect_block(&mut state, &block, &params, 2_000_000_000).expect("and accepts it");

        if let Some(position) = spent_position {
            emptied.insert(position);
        }

        // This block's landing is the newest in the window.
        let window = state.grace_window();
        if let Some(landing) = window.last() {
            for (id, position, fallen) in landing {
                assert_eq!(
                    *position,
                    leaves.len() as u64,
                    "positions are handed out in order and never reused"
                );
                leaves.push(spec_cold_leaf(id, fallen));
                spendable.push((*id, *position, *fallen));
            }
        }

        // The two counters, checked against what was recorded here rather than
        // taken from the implementation.
        let live = leaves.len() as u64 - emptied.len() as u64;
        assert_eq!(state.next_cold_position(), leaves.len() as u64);
        assert_eq!(state.cold_len(), live, "the cold count is the live leaves");

        let folded: Vec<Hash32> = leaves
            .iter()
            .enumerate()
            .map(|(position, leaf)| {
                if emptied.contains(&(position as u64)) {
                    spec_empty_leaf()
                } else {
                    *leaf
                }
            })
            .collect();

        let hot: Vec<([u8; 32], Hash32)> = state
            .hot_notes()
            .map(|(id, entry)| {
                (
                    spec_note_key(&id),
                    spec_hot_value(&entry.note, entry.height),
                )
            })
            .collect();

        let grace = spec_grace_root(&window);
        assert_eq!(
            state.grace_root(),
            grace,
            "the grace root at height {height}"
        );

        let want = spec_state_root(
            spec_hot_root(hot),
            state.hot_len() as u64,
            spec_cold_commitment(&folded, live),
            live,
            grace,
            &state.maturing(),
            state.supply().as_pebbles(),
        );
        assert_eq!(
            state.state_root(),
            want,
            "the state root at height {height}"
        );
        assert_eq!(
            block.header.state_root, want,
            "and the root the header carries"
        );
        roots_compared += 1;
    }

    assert_eq!(roots_compared, 12);
    assert!(
        !leaves.is_empty(),
        "the fixture never evicted anything, so the cold half was not exercised"
    );
    assert!(
        !emptied.is_empty(),
        "the fixture never emptied a leaf, so live and leaves never parted"
    );
}

// ---------------------------------------------------------------------------
// 9. The numbers the document names as network parameters.
// ---------------------------------------------------------------------------

#[test]
fn the_published_network_parameters_are_what_the_networks_carry() {
    let public = ConsensusParams::for_network("testnet-6").expect("the network the draft names");
    assert_eq!(public.hot_capacity, 131_072);
    assert_eq!(public.max_evictions_per_block, 1_024);
    assert_eq!(public.coinbase_maturity, 1_024);
    assert_eq!(public.burial, 1_024);
    assert_eq!(public.target_block_time, 60);
    assert_eq!(public.genesis_difficulty, 1 << 27);
    assert_eq!(public.max_timestamp_drift, 7_200);
    assert_eq!(public.halving_interval, 1_051_200);
    assert_eq!(public.initial_reward.as_pebbles(), 5_000_000_000);
    assert_eq!(public.tail_reward.as_pebbles(), 1_000_000);
    assert_eq!(public.activations.len(), 1);
    assert_eq!(public.activations[0].height, 0);
    assert_eq!(public.activations[0].version, 1);
    assert_eq!(public.version_at(0), 1);
    assert_eq!(public.version_at(u64::MAX), 1);

    let devnet = ConsensusParams::for_network("devnet").expect("the throwaway network");
    assert_eq!(devnet.hot_capacity, 64);
    assert_eq!(devnet.max_evictions_per_block, 1_024);
    assert_eq!(devnet.coinbase_maturity, 32);
    assert_eq!(devnet.burial, 32);
    assert_eq!(devnet.genesis_difficulty, 1 << 23);
    assert_eq!(devnet.target_block_time, 5);
    assert_eq!(
        devnet.max_timestamp_drift, public.max_timestamp_drift,
        "the drift allowance is the same everywhere"
    );
    assert_eq!(devnet.halving_interval, public.halving_interval);

    // "The maturity MUST be at or above the network's burial."
    for params in [&public, &devnet] {
        assert!(params.coinbase_maturity >= params.burial);
    }

    // Two transaction versions, each compared for equality against a constant.
    assert_eq!(TRANSFER_VERSION, 1);
    assert_eq!(COINBASE_VERSION, 1);
}

// ---------------------------------------------------------------------------
// 10. Everything a block derives that nothing in the block declares.
//
// "Nothing in a block declares any part of it." Which notes fall, where each
// one lands, what the window holds afterwards, which coinbases are still
// waiting and what the issued total comes to are each derived. So each one is
// derived again here, from the document's procedures, and compared block by
// block against what the implementation reached.
// ---------------------------------------------------------------------------

/// "Two note identifiers are ordered by their 32-byte source hash first,
/// compared byte by byte from the first, then by their index as a number."
fn spec_id_order(id: &NoteId) -> ([u8; 32], u32) {
    (id.source.to_bytes(), id.index)
}

/// The parts of a ledger a block changes.
#[derive(Default)]
struct SpecLedger {
    /// The note identifier, the note, and the height of the block that made it.
    hot: Vec<(NoteId, Note, u64)>,
    cold_leaves: Vec<Hash32>,
    emptied: BTreeSet<u64>,
    window: Vec<Vec<(NoteId, u64, Note)>>,
    maturing: Vec<(u64, Hash32)>,
    supply: u64,
}

impl SpecLedger {
    fn hot_at(&self, id: &NoteId) -> Option<usize> {
        self.hot.iter().position(|(held, _, _)| held == id)
    }

    fn in_window(&self, id: &NoteId) -> Option<(u64, Note)> {
        self.window
            .iter()
            .flatten()
            .find(|(held, _, _)| held == id)
            .map(|(_, position, note)| (*position, *note))
    }

    fn apply(&mut self, block: &Block, params: &ConsensusParams) {
        let height = block.header.height;

        // Where each input's note is coming from, and what it was worth. A
        // note spent under the grace window is not a hot spend: it had already
        // fallen, and it comes out of the cold set.
        let mut spent_hot: Vec<NoteId> = Vec::new();
        let mut spent_cold: Vec<u64> = Vec::new();
        let mut fees: u64 = 0;
        for transfer in &block.transfers {
            let mut taken = 0u64;
            for input in &transfer.inputs {
                if let Some(index) = self.hot_at(&input.note_id) {
                    taken += self.hot[index].1.value.as_pebbles();
                    spent_hot.push(input.note_id);
                } else {
                    let (position, note) = self
                        .in_window(&input.note_id)
                        .expect("the fixture spends only notes it can account for");
                    taken += note.value.as_pebbles();
                    spent_cold.push(position);
                }
            }
            let paid: u64 = transfer
                .outputs
                .iter()
                .map(|note| note.value.as_pebbles())
                .sum();
            fees += taken.saturating_sub(paid);
        }

        // "the transfers in the order they appear in the block, each
        // transfer's outputs in index order, then the coinbase's outputs in
        // index order".
        let mut created: Vec<(NoteId, Note)> = Vec::new();
        for transfer in &block.transfers {
            let source = transfer.id();
            for (index, note) in transfer.outputs.iter().enumerate() {
                created.push((NoteId::new(source, index as u32), *note));
            }
        }
        let coinbase_id = block.coinbase.id();
        for (index, note) in block.coinbase.outputs.iter().enumerate() {
            created.push((NoteId::new(coinbase_id, index as u32), *note));
        }

        // Step 1: every cold spend is emptied.
        for position in &spent_cold {
            self.emptied.insert(*position);
        }

        // Steps 3 and 4: the hot spends come out, the created notes go in,
        // carrying this block's height.
        let parent_hot = self.hot.clone();
        self.hot.retain(|(id, _, _)| !spent_hot.contains(id));
        let surviving = self.hot.len();
        for (id, note) in &created {
            self.hot.push((*id, *note, height));
        }

        // "the first `overflow` of the hot set, ordered by the height they
        // were created at ascending, then by note identifier ascending,
        // skipping any note in spent".
        let overflow = surviving
            .saturating_add(created.len())
            .saturating_sub(params.hot_capacity);
        let mut falling: Vec<(NoteId, Note)> = Vec::new();
        if overflow > 0 {
            let mut candidates: Vec<(NoteId, Note, u64)> = parent_hot
                .into_iter()
                .filter(|(id, _, _)| !spent_hot.contains(id))
                .collect();
            candidates.sort_by_key(|(id, _, at)| (*at, spec_id_order(id)));
            falling.extend(
                candidates
                    .into_iter()
                    .take(overflow)
                    .map(|(id, note, _)| (id, note)),
            );
            // "If the hot set does not hold `overflow` such notes, the
            // shortfall is made up from created, ordered by note identifier
            // ascending, taking from the start."
            if falling.len() < overflow {
                let mut short = created.clone();
                short.sort_by_key(|(id, _)| spec_id_order(id));
                for entry in short {
                    if falling.len() == overflow {
                        break;
                    }
                    falling.push(entry);
                }
            }
        }

        // Step 5: each falls out of the tree and takes the next free position.
        let mut landing: Vec<(NoteId, u64, Note)> = Vec::new();
        for (id, note) in &falling {
            let position = self.cold_leaves.len() as u64;
            self.cold_leaves.push(spec_cold_leaf(id, note));
            let held = self
                .hot_at(id)
                .expect("a note falls out of the tier it was in");
            self.hot.remove(held);
            landing.push((*id, position, *note));
        }

        // The grace window's three steps, in order.
        for held in &mut self.window {
            held.retain(|(_, position, _)| !spent_cold.contains(position));
        }
        self.window.push(landing);
        while self.window.len() > 64 || self.window.iter().map(Vec::len).sum::<usize>() > 8_192 {
            self.window.remove(0);
        }

        // The maturity window's two steps.
        self.maturing.retain(|(at, _)| *at > height);
        let matures_at = height.saturating_add(params.coinbase_maturity);
        if !block.coinbase.outputs.is_empty() && matures_at > height {
            self.maturing.push((matures_at, coinbase_id));
        }

        // The issued total: what the coinbase paid against what the transfers
        // gave up, in whichever direction it goes.
        let paid: u64 = block
            .coinbase
            .outputs
            .iter()
            .map(|note| note.value.as_pebbles())
            .sum();
        if paid >= fees {
            self.supply += paid - fees;
        } else {
            self.supply -= fees - paid;
        }
    }

    fn live(&self) -> u64 {
        self.cold_leaves.len() as u64 - self.emptied.len() as u64
    }

    fn folded_leaves(&self) -> Vec<Hash32> {
        self.cold_leaves
            .iter()
            .enumerate()
            .map(|(position, leaf)| {
                if self.emptied.contains(&(position as u64)) {
                    spec_empty_leaf()
                } else {
                    *leaf
                }
            })
            .collect()
    }

    fn state_root(&self) -> Hash32 {
        let hot: Vec<([u8; 32], Hash32)> = self
            .hot
            .iter()
            .map(|(id, note, at)| (spec_note_key(id), spec_hot_value(note, *at)))
            .collect();
        spec_state_root(
            spec_hot_root(hot),
            self.hot.len() as u64,
            spec_cold_commitment(&self.folded_leaves(), self.live()),
            self.live(),
            spec_grace_root(&self.window),
            &self.maturing,
            self.supply,
        )
    }
}

/// A chain long enough that the window's own bound runs, with a tier small
/// enough that every block pushes notes out of it.
#[test]
fn every_derivation_a_block_forces_is_the_one_the_document_describes() {
    let params = ConsensusParams::testnet()
        .with_hot_capacity(4)
        .with_burial(2)
        .with_coinbase_maturity(2);
    let miner = wallet(1);
    let mut state = LedgerState::new();
    let mut mine = SpecLedger::default();

    let mut spent_a_hot_note = false;
    let mut spent_a_window_note = false;
    let mut destroyed_money = false;
    let mut trimmed_the_window = false;

    for height in 0..70u64 {
        let reward = params.reward_at(height);
        // Every fourth block claims nothing, so a fee is destroyed rather than
        // collected and the issued total falls. It also leaves the coinbase
        // with no outputs, which is the case the maturity window skips.
        let claiming = height % 4 != 3;
        let outputs = if claiming {
            let half = Amount::from_pebbles(reward.as_pebbles() / 2).unwrap();
            vec![
                Note::new(half, miner.public_key()),
                Note::new(
                    Amount::from_pebbles(reward.as_pebbles() - half.as_pebbles()).unwrap(),
                    owner(2),
                ),
            ]
        } else {
            Vec::new()
        };
        let coinbase = CoinbaseTransaction::new(height, outputs);

        // A transfer paying a fee, spending whichever of the miner's own notes
        // is reachable: hot when one is hot, out of the window when one is not.
        let mut transfers = Vec::new();
        if height >= 4 {
            let hot_pick = mine
                .hot
                .iter()
                .find(|(id, note, _)| {
                    note.owner == miner.public_key()
                        && note.value.as_pebbles() > 1_000
                        && state
                            .coinbase_matures_at(&id.source)
                            .is_none_or(|at| at <= height)
                })
                .map(|(id, note, _)| (*id, *note));
            let window_pick = mine
                .window
                .iter()
                .flatten()
                .find(|(id, _, note)| {
                    note.owner == miner.public_key()
                        && note.value.as_pebbles() > 1_000
                        && state
                            .coinbase_matures_at(&id.source)
                            .is_none_or(|at| at <= height)
                })
                .map(|(id, _, note)| (*id, *note));
            // Alternate, so both tiers are spent from over the run.
            let pick = if height % 2 == 0 {
                hot_pick.or(window_pick)
            } else {
                window_pick.or(hot_pick)
            };
            if let Some((id, note)) = pick {
                if mine.hot_at(&id).is_some() {
                    spent_a_hot_note = true;
                } else {
                    spent_a_window_note = true;
                }
                let keep = Amount::from_pebbles(note.value.as_pebbles() - 1_000).unwrap();
                let mut transfer =
                    Transfer::new(vec![Input::hot(id)], vec![Note::new(keep, owner(6))]);
                transfer.sign_input(params.network, 0, &note, &miner);
                transfers.push(transfer);
                if !claiming {
                    destroyed_money = true;
                }
            }
        }

        let block = assemble_block(
            &state,
            coinbase,
            transfers,
            &params,
            1_000 + height * 600,
            0,
        )
        .expect("the fixture builds a block the rules accept");
        connect_block(&mut state, &block, &params, 2_000_000_000).expect("and accepts it");
        mine.apply(&block, &params);

        if mine.window.len() == 64 {
            trimmed_the_window = true;
        }

        // The hot set, note for note, with the height each carries.
        let mut theirs: Vec<(NoteId, Note, u64)> = state
            .hot_notes()
            .map(|(id, entry)| (id, entry.note, entry.height))
            .collect();
        let mut ours = mine.hot.clone();
        theirs.sort_by_key(|(id, _, at)| (*at, spec_id_order(id)));
        ours.sort_by_key(|(id, _, at)| (*at, spec_id_order(id)));
        assert_eq!(ours, theirs, "the hot set after the block at {height}");

        // What fell, where it landed, and what the window holds.
        assert_eq!(
            mine.window,
            state.grace_window(),
            "the grace window after the block at {height}"
        );
        assert_eq!(state.next_cold_position(), mine.cold_leaves.len() as u64);
        assert_eq!(state.cold_len(), mine.live());
        assert_eq!(
            state.maturing(),
            mine.maturing,
            "the maturity window after the block at {height}"
        );
        assert_eq!(
            state.supply().as_pebbles(),
            mine.supply,
            "the issued total after the block at {height}"
        );
        assert_eq!(
            state.state_root(),
            mine.state_root(),
            "the state root after the block at {height}"
        );
        assert_eq!(block.header.state_root, mine.state_root());
    }

    assert!(spent_a_hot_note, "no note was spent out of the hot set");
    assert!(spent_a_window_note, "no note was spent out of the window");
    assert!(destroyed_money, "the issued total never fell");
    assert!(
        trimmed_the_window,
        "the window never reached its 64 landing bound"
    );
    assert!(
        mine.cold_leaves.len() > 64,
        "only {} notes ever fell",
        mine.cold_leaves.len()
    );
}

// ---------------------------------------------------------------------------
// 11. A proof, verified the way the five steps say.
// ---------------------------------------------------------------------------

/// Steps 1 and 3: find the tree holding the position by reading `leaves` from
/// the highest bit down, and take the index within it.
fn spec_tree_of(leaves: u64, position: u64) -> Option<(usize, u64)> {
    if position >= leaves {
        return None;
    }
    let mut first = 0u64;
    for height in (0..64usize).rev() {
        if leaves & (1u64 << height) == 0 {
            continue;
        }
        let span = 1u64 << height;
        if position < first + span {
            return Some((height, position - first));
        }
        first += span;
    }
    None
}

/// Steps 4 and 5: fold the leaf up the siblings and compare with the root.
fn spec_proof_holds(
    roots: &[Option<Hash32>],
    leaves: u64,
    position: u64,
    leaf: Hash32,
    siblings: &[Hash32],
) -> bool {
    let Some((height, mut index)) = spec_tree_of(leaves, position) else {
        return false;
    };
    if siblings.len() != height {
        return false;
    }
    let mut running = leaf;
    for sibling in siblings {
        running = if index & 1 == 0 {
            spec_forest_node(running, *sibling)
        } else {
            spec_forest_node(*sibling, running)
        };
        index >>= 1;
    }
    roots.get(height).and_then(|root| *root) == Some(running)
}

#[test]
fn a_node_holds_a_proof_for_every_note_in_its_window_and_it_folds_to_the_roots() {
    let params = ConsensusParams::testnet()
        .with_hot_capacity(4)
        .with_burial(2)
        .with_coinbase_maturity(2);
    let miner = wallet(1);
    let mut state = LedgerState::new();
    let mut mine = SpecLedger::default();
    let mut proofs_checked = 0u32;

    for height in 0..24u64 {
        let reward = params.reward_at(height);
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![
                Note::new(
                    Amount::from_pebbles(reward.as_pebbles() / 2).unwrap(),
                    miner.public_key(),
                ),
                Note::new(
                    Amount::from_pebbles(reward.as_pebbles() - reward.as_pebbles() / 2).unwrap(),
                    owner(2),
                ),
            ],
        );
        let block = assemble_block(
            &state,
            coinbase,
            Vec::new(),
            &params,
            1_000 + height * 600,
            0,
        )
        .expect("a block the rules accept");
        connect_block(&mut state, &block, &params, 2_000_000_000).expect("and accepts it");
        mine.apply(&block, &params);

        let roots = spec_forest_roots(&mine.folded_leaves());
        let leaves = mine.cold_leaves.len() as u64;
        for landing in &mine.window {
            for (id, position, note) in landing {
                let proof = state
                    .cold()
                    .proof_of(*position)
                    .expect("a node holds a path for every note in its window");
                assert!(
                    spec_proof_holds(
                        &roots,
                        leaves,
                        *position,
                        spec_cold_leaf(id, note),
                        &proof.siblings,
                    ),
                    "the path for position {position} after the block at {height}"
                );
                proofs_checked += 1;
            }
        }
    }
    assert!(
        proofs_checked > 100,
        "only {proofs_checked} paths were folded"
    );
}

// ---------------------------------------------------------------------------
// 12. The numbers the document names, and the ones it leaves out.
// ---------------------------------------------------------------------------

#[test]
fn the_constants_the_document_publishes_are_the_ones_the_build_carries() {
    use cairn_ledger::block::MOST_TRANSFERS;
    use cairn_ledger::handover::MOST_BURIED;
    use cairn_ledger::pow::{
        DIFFICULTY_WINDOW, MAX_RETARGET_FACTOR, MEDIAN_TIME_WINDOW, RECENT_HEADERS,
    };
    use cairn_ledger::sampling::MOST_TAIL;
    use cairn_ledger::state::{GRACE_BLOCKS, GRACE_NOTES};
    use cairn_primitives::codec::MAX_SEQUENCE_LEN;

    assert_eq!(DIFFICULTY_WINDOW, 90, "gaps the answer is weighed over");
    assert_eq!(RECENT_HEADERS, 91, "summaries a node must hold");
    assert_eq!(MEDIAN_TIME_WINDOW, 11);
    assert_eq!(MAX_RETARGET_FACTOR, 4);
    assert_eq!(MIN_DIFFICULTY, 1);
    assert_eq!(GRACE_BLOCKS, 64);
    assert_eq!(GRACE_NOTES, 8_192);
    assert_eq!(MAX_SEQUENCE_LEN, 1_048_576);
    assert_eq!(MOST_TRANSFERS, 4_096);
    assert_eq!(MOST_BURIED, 4_096);
    assert_eq!(
        MOST_TAIL,
        16 * 1_024 + 90,
        "sixteen times the unresolved band plus one retarget window"
    );
    assert_eq!(MOST_TAIL, 16_474);

    // "A build knows versions up to a ceiling, which is 1 today."
    assert_eq!(cairn_ledger::block::BLOCK_VERSION, 1);
    // "The reference implementation follows at most 8 192 notes."
    assert_eq!(cairn_ledger::state::WATCHED_NOTES, 8_192);
}

/// Five limits the document states as rules and never gives a number for.
///
/// Each is a refusal in one of the normative tables: `TooManyInputs`,
/// `TooManyOutputs`, `BlockTooLarge`, and the bound the coinbase's `extra` and
/// its output count are said to have. A second implementation reading the
/// document alone would pick its own, and two nodes picking differently refuse
/// different transfers. They are pinned here so that a change to one shows up
/// against the document that ought to have carried it.
#[test]
fn the_limits_the_document_names_without_numbering_are_recorded_here() {
    use cairn_ledger::transaction::{
        MAX_COINBASE_EXTRA, MOST_COINBASE_OUTPUTS, MOST_INPUTS, MOST_OUTPUTS,
    };

    let params = ConsensusParams::for_network("testnet-6").unwrap();
    assert_eq!(params.max_inputs_per_transfer, 256);
    assert_eq!(params.max_outputs_per_transfer, 256);
    assert_eq!(params.max_coinbase_outputs, 16);
    assert_eq!(params.max_block_bytes, 128 * 1_024);
    assert_eq!(MOST_INPUTS, 256);
    assert_eq!(MOST_OUTPUTS, 256);
    assert_eq!(MOST_COINBASE_OUTPUTS, 16);
    assert_eq!(MAX_COINBASE_EXTRA, 64);
}

// ---------------------------------------------------------------------------
// 13. The refusals the document numbers, in the order it numbers them.
// ---------------------------------------------------------------------------

#[test]
fn a_transfers_shape_is_refused_in_the_order_the_table_gives() {
    let params = ConsensusParams::testnet();
    let duplicate = note_id(0x77, 0);
    let good = note(1_000, 1);
    let zero = Note::new(Amount::ZERO, owner(1));
    let ceiling = Note::new(Amount::MAX_MONEY, owner(1));

    // Each case breaks two rules at once, and the lower number must win.
    let mut version_and_no_inputs = Transfer::new(Vec::new(), Vec::new());
    version_and_no_inputs.version = TRANSFER_VERSION + 1;
    assert_eq!(
        check_transfer_shape(&version_and_no_inputs, &params),
        Err(TransferError::UnsupportedVersion(TRANSFER_VERSION + 1)),
        "1 before 2"
    );

    let nothing_at_all = Transfer::new(Vec::new(), Vec::new());
    assert_eq!(
        check_transfer_shape(&nothing_at_all, &params),
        Err(TransferError::NoInputs),
        "2 before 3"
    );

    let too_many: Vec<Input> = (0..=params.max_inputs_per_transfer)
        .map(|index| Input::hot(note_id(0x88, index as u32)))
        .collect();
    let no_outputs = Transfer::new(too_many.clone(), Vec::new());
    assert_eq!(
        check_transfer_shape(&no_outputs, &params),
        Err(TransferError::NoOutputs),
        "3 before 4"
    );

    let both_counts = Transfer::new(
        too_many,
        (0..=params.max_outputs_per_transfer)
            .map(|_| good)
            .collect(),
    );
    assert_eq!(
        check_transfer_shape(&both_counts, &params),
        Err(TransferError::TooManyInputs {
            count: params.max_inputs_per_transfer + 1,
            limit: params.max_inputs_per_transfer,
        }),
        "4 before 5"
    );

    let outputs_and_duplicate = Transfer::new(
        vec![Input::hot(duplicate), Input::hot(duplicate)],
        (0..=params.max_outputs_per_transfer)
            .map(|_| good)
            .collect(),
    );
    assert_eq!(
        check_transfer_shape(&outputs_and_duplicate, &params),
        Err(TransferError::TooManyOutputs {
            count: params.max_outputs_per_transfer + 1,
            limit: params.max_outputs_per_transfer,
        }),
        "5 before 6"
    );

    let duplicate_and_zero = Transfer::new(
        vec![Input::hot(duplicate), Input::hot(duplicate)],
        vec![zero],
    );
    assert_eq!(
        check_transfer_shape(&duplicate_and_zero, &params),
        Err(TransferError::DuplicateInput(duplicate)),
        "6 before 7"
    );

    let zero_and_overflow =
        Transfer::new(vec![Input::hot(duplicate)], vec![ceiling, zero, ceiling]);
    assert_eq!(
        check_transfer_shape(&zero_and_overflow, &params),
        Err(TransferError::ZeroValueOutput { index: 1 }),
        "7 before 8"
    );

    let overflow = Transfer::new(vec![Input::hot(duplicate)], vec![ceiling, ceiling]);
    assert_eq!(
        check_transfer_shape(&overflow, &params),
        Err(TransferError::ValueOverflow),
        "8, and the outputs do not sum"
    );

    // And a transfer that breaks none of them passes the shape check.
    let sound = Transfer::new(vec![Input::hot(duplicate)], vec![good]);
    assert_eq!(check_transfer_shape(&sound, &params), Ok(()));
}

// ---------------------------------------------------------------------------
// 14. What a decoder must refuse.
// ---------------------------------------------------------------------------

#[test]
fn a_witness_tag_the_rules_do_not_know_is_refused_rather_than_skipped() {
    let sound = Transfer::new(vec![Input::hot(note_id(0x12, 3))], vec![note(9, 1)]);
    let bytes = sound.encode();
    assert_eq!(Transfer::decode(&bytes).unwrap(), sound);

    // The tag sits after the version, the count and the note identifier.
    for tag in [2u8, 3, 0xff] {
        let mut broken = bytes.clone();
        broken[42] = tag;
        assert!(
            Transfer::decode(&broken).is_err(),
            "a witness tag of {tag} was not refused"
        );
    }
}

#[test]
fn a_forest_on_the_wire_has_to_be_one_something_could_have_produced() {
    fn forest_bytes(leaves: u64, live: u64, roots: &[(u8, Hash32)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&leaves.to_le_bytes());
        out.extend_from_slice(&live.to_le_bytes());
        out.extend_from_slice(&(roots.len() as u32).to_le_bytes());
        for (height, root) in roots {
            out.push(*height);
            out.extend_from_slice(root.as_bytes());
        }
        out
    }
    let root = |seed: u8| Hash32::from_bytes([seed; 32]);

    // Five leaves is bits 0 and 2, so exactly two trees.
    let sound = forest_bytes(5, 5, &[(0, root(1)), (2, root(2))]);
    assert!(
        Forest::decode(&sound).is_ok(),
        "a forest whose roots are the set bits of its leaf count"
    );

    assert!(
        Forest::decode(&forest_bytes(5, 6, &[(0, root(1)), (2, root(2))])).is_err(),
        "live above leaves"
    );
    assert!(
        Forest::decode(&forest_bytes(5, 5, &[(0, root(1)), (0, root(2))])).is_err(),
        "two roots at one height"
    );
    assert!(
        Forest::decode(&forest_bytes(5, 5, &[(0, root(1)), (1, root(2))])).is_err(),
        "roots that are not the set bits of the leaf count"
    );
    assert!(
        Forest::decode(&forest_bytes(5, 5, &[(0, root(1))])).is_err(),
        "a tree the leaf count says exists and the message leaves out"
    );
    let many: Vec<(u8, Hash32)> = (0..65u8).map(|height| (height, root(height))).collect();
    assert!(
        Forest::decode(&forest_bytes(u64::MAX, u64::MAX, &many)).is_err(),
        "more roots than a forest can hold"
    );
}

#[test]
fn a_public_key_that_is_not_a_usable_point_is_refused_at_decode() {
    // The canonical small-order points, the two non-canonical encodings of
    // them, and bytes that are not a point at all. Every one of these is a
    // key whose signatures verify for anybody, so a note locked to one is a
    // note anybody can spend.
    let refused = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];
    for text in refused {
        let bytes = cairn_primitives::hex::decode_array::<32>(text).unwrap();
        assert!(
            PublicKey::from_bytes(&bytes).is_err(),
            "{text} was accepted as an owner"
        );
        assert!(
            PublicKey::decode(&bytes).is_err(),
            "{text} decoded as an owner"
        );
    }

    // And a real key still decodes, or the assertions above hold of nothing.
    let honest = owner(3);
    assert_eq!(PublicKey::decode(&honest.encode()).unwrap(), honest);
}

// ---------------------------------------------------------------------------
// 15. The two edges the document gives a height for.
// ---------------------------------------------------------------------------

/// A chain paying the whole reward to one miner, so that from the fifth block
/// on exactly one note falls per block and every fallen note is spendable.
fn falling_chain() -> (ConsensusParams, SecretKey) {
    (
        ConsensusParams::testnet()
            .with_hot_capacity(4)
            .with_burial(2)
            .with_coinbase_maturity(2),
        wallet(1),
    )
}

/// Mines up to `f + offset` and there offers a proofless spend of the note
/// that fell in the block at height `f`, where `f` is the first block that
/// evicts anything.
fn spend_a_fallen_note_after(offset: u64) -> Result<Block, cairn_ledger::BlockError> {
    let (params, miner) = falling_chain();
    let mut state = LedgerState::new();
    let mut fell: Option<(u64, NoteId, Note)> = None;

    loop {
        let height = state.next_height().unwrap();
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );

        let ready = fell
            .as_ref()
            .is_some_and(|(at, _, _)| height == at + offset);
        let transfers = if ready {
            let (_, id, note) = fell.unwrap();
            let keep = Amount::from_pebbles(note.value.as_pebbles() - 1_000).unwrap();
            let mut transfer = Transfer::new(vec![Input::hot(id)], vec![Note::new(keep, owner(6))]);
            transfer.sign_input(params.network, 0, &note, &miner);
            vec![transfer]
        } else {
            Vec::new()
        };

        let built = assemble_block(
            &state,
            coinbase,
            transfers,
            &params,
            1_000 + height * 600,
            0,
        );
        if ready {
            return built;
        }
        let block = built.expect("a block with no transfers in it");
        connect_block(&mut state, &block, &params, 2_000_000_000).expect("and it holds");

        if fell.is_none() {
            if let Some(landing) = state.grace_window().last() {
                if let Some((id, _, note)) = landing.first() {
                    fell = Some((height, *id, *note));
                }
            }
        }
    }
}

/// The one sentence in part 4 that reads two ways, pinned to the reading the
/// rules produce.
///
/// "a note that fell in the block at height *f* is in the window from the
/// block at height *f* + 1 through the block at height *f* + 64 inclusive, and
/// is out of it from *f* + 65."
///
/// Taken as a statement about what the window holds, that is off by one at
/// both ends: the window appends this block's landing and then drops from the
/// oldest end while it holds more than 64, so after the block at height *h* it
/// holds the landings of heights *h* - 63 to *h*, and the landing from *f* is
/// in it after blocks *f* through *f* + 63. The derivation test above pins
/// that. Taken as a statement about which blocks may spend the note without a
/// proof it is exact, because a block's inputs are resolved against the state
/// as it stood at its parent. This is that reading, at both edges.
#[test]
fn a_note_that_fell_may_be_spent_without_a_proof_for_sixty_four_blocks_and_not_the_next() {
    assert!(
        spend_a_fallen_note_after(64).is_ok(),
        "a note that fell at f must still be spendable proofless at f + 64"
    );
    let refused = spend_a_fallen_note_after(65).expect_err("f + 65 is past the window");
    assert!(
        matches!(
            refused,
            cairn_ledger::BlockError::InvalidTransfer {
                source: TransferError::MissingProof { .. },
                ..
            }
        ),
        "past the window a proofless spend is MissingProof, got {refused:?}"
    );
}

#[test]
fn a_reward_is_spendable_exactly_on_the_block_whose_height_the_entry_names() {
    let maturity = 8u64;
    let params = ConsensusParams::testnet().with_coinbase_maturity(maturity);
    let miner = wallet(1);

    // The same chain twice, offering the spend one block apart.
    for (offset, must_hold) in [(maturity - 1, false), (maturity, true)] {
        let mut state = LedgerState::new();
        let mut coin: Option<(NoteId, Note)> = None;
        let mut outcome = None;
        for height in 0..=offset {
            let reward = params.reward_at(height);
            let coinbase =
                CoinbaseTransaction::new(height, vec![Note::new(reward, miner.public_key())]);
            let transfers = if height == offset {
                let (id, note) = coin.expect("the first coinbase was recorded");
                let mut transfer =
                    Transfer::new(vec![Input::hot(id)], vec![Note::new(note.value, owner(6))]);
                transfer.sign_input(params.network, 0, &note, &miner);
                vec![transfer]
            } else {
                Vec::new()
            };
            let built = assemble_block(
                &state,
                coinbase,
                transfers,
                &params,
                1_000 + height * 600,
                0,
            );
            if height == offset {
                outcome = Some(built);
                break;
            }
            let block = built.expect("a block with no transfers in it");
            connect_block(&mut state, &block, &params, 2_000_000_000).expect("and it holds");
            if coin.is_none() {
                coin = Some((
                    NoteId::new(block.coinbase.id(), 0),
                    block.coinbase.outputs[0],
                ));
            }
        }
        let outcome = outcome.expect("the loop reached the height it was built for");
        if must_hold {
            assert!(
                outcome.is_ok(),
                "the reward is spendable on the entry's own height"
            );
        } else {
            let refused = outcome.expect_err("one block early is refused");
            assert!(
                matches!(
                    refused,
                    cairn_ledger::BlockError::InvalidTransfer {
                        source: TransferError::ImmatureCoinbase { matures_at, .. },
                        ..
                    } if matures_at == maturity
                ),
                "one block early is ImmatureCoinbase at the entry's height, got {refused:?}"
            );
        }
    }
}

#[test]
fn there_is_no_chaining_inside_a_block() {
    let params = ConsensusParams::testnet()
        .with_burial(2)
        .with_coinbase_maturity(2);
    let miner = wallet(1);
    let mut state = LedgerState::new();
    let mut coin: Option<(NoteId, Note)> = None;

    for height in 0..4u64 {
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        let block = assemble_block(
            &state,
            coinbase,
            Vec::new(),
            &params,
            1_000 + height * 600,
            0,
        )
        .expect("a block with no transfers in it");
        connect_block(&mut state, &block, &params, 2_000_000_000).expect("and it holds");
        if coin.is_none() {
            coin = Some((
                NoteId::new(block.coinbase.id(), 0),
                block.coinbase.outputs[0],
            ));
        }
    }

    let (id, note) = coin.expect("a matured reward");
    let onward = Note::new(note.value, wallet(5).public_key());
    let mut first = Transfer::new(vec![Input::hot(id)], vec![onward]);
    first.sign_input(params.network, 0, &note, &miner);
    let made = NoteId::new(first.id(), 0);
    let mut second = Transfer::new(
        vec![Input::hot(made)],
        vec![Note::new(onward.value, owner(6))],
    );
    second.sign_input(params.network, 0, &onward, &wallet(5));

    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), miner.public_key())],
    );
    let refused = assemble_block(
        &state,
        coinbase,
        vec![first, second],
        &params,
        1_000 + height * 600,
        0,
    )
    .expect_err("a note this block creates is not in the state its inputs are resolved against");
    assert!(
        matches!(
            refused,
            cairn_ledger::BlockError::InvalidTransfer {
                index: 1,
                source: TransferError::MissingProof { .. } | TransferError::UnknownNote(_),
            }
        ),
        "the second transfer must not find the first's output, got {refused:?}"
    );
}

#[test]
fn the_block_at_height_one_carries_the_genesis_difficulty_unchanged() {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::new();
    assert_eq!(
        expected_difficulty(&state, &params),
        params.genesis_difficulty
    );

    let block = assemble_block(
        &state,
        CoinbaseTransaction::new(0, vec![Note::new(params.reward_at(0), owner(1))]),
        Vec::new(),
        &params,
        1_000,
        0,
    )
    .expect("the first block");
    assert_eq!(block.header.difficulty, params.genesis_difficulty);
    connect_block(&mut state, &block, &params, 2_000_000_000).expect("and it holds");
    assert_eq!(
        expected_difficulty(&state, &params),
        params.genesis_difficulty,
        "the block at height 1 sees one summary, so n is 0"
    );
}

/// The window's own bound, run over labelled landings and nothing else.
///
/// This is the document's three steps applied to a hundred blocks, with each
/// landing labelled by the height it came from. It takes no chain and reads no
/// code: it is the arithmetic of the rule the document gives, run to show what
/// the sentence quoted above says when it is read as a statement about what
/// the window holds.
#[test]
fn what_the_window_holds_after_a_block_spans_the_sixty_four_heights_below_it() {
    let mut window: Vec<u64> = Vec::new();
    for height in 0..100u64 {
        window.push(height);
        while window.len() > 64 {
            window.remove(0);
        }
        if height >= 63 {
            assert_eq!(window.len(), 64);
            assert_eq!(
                *window.first().unwrap(),
                height - 63,
                "the oldest landing after the block at {height}"
            );
            assert_eq!(*window.last().unwrap(), height);
        }
    }
    // So a landing from height f is in the window after the blocks at heights
    // f through f + 63, and gone after f + 64. The block at height f + 64 is
    // the last that can spend it proofless, because a block's inputs are
    // resolved against its parent's state.
    let fell = 10u64;
    let mut held = Vec::new();
    let mut window: Vec<u64> = Vec::new();
    for height in 0..100u64 {
        window.push(height);
        while window.len() > 64 {
            window.remove(0);
        }
        if window.contains(&fell) {
            held.push(height);
        }
    }
    assert_eq!(*held.first().unwrap(), fell);
    assert_eq!(*held.last().unwrap(), fell + 63);
}

/// "A decoder MUST refuse a proof of more than 64 siblings, which is the most
/// trees a forest can hold."
#[test]
fn a_sample_carrying_more_than_sixty_four_siblings_is_refused() {
    fn sample_bytes(siblings: usize) -> Vec<u8> {
        let mut out = spec_header_bytes(&sample_header());
        spec_sequence_header(siblings, &mut out);
        for index in 0..siblings {
            out.extend_from_slice(Hash32::from_bytes([index as u8; 32]).as_bytes());
        }
        out
    }
    assert!(
        Sample::decode(&sample_bytes(64)).is_ok(),
        "sixty four siblings is the deepest tree a forest holds"
    );
    assert!(
        Sample::decode(&sample_bytes(65)).is_err(),
        "sixty five siblings names a tree no forest can hold"
    );
    // And the shape the table gives, so the length is checked as well as the
    // ceiling: a header of 182 bytes, then a count, then the siblings.
    assert_eq!(sample_bytes(3).len(), 182 + 4 + 3 * 32);
    assert_eq!(
        Sample::decode(&sample_bytes(3)).unwrap().header,
        sample_header()
    );
}

/// Four refusals a peer can trip that the document does not state.
///
/// The document's Conformance section is explicit about what this means:
/// "Anything not stated here is not a rule. If the reference implementation
/// refuses something this document does not say it must refuse, that is a
/// defect in the implementation or an omission here." Each of these is a
/// block an implementation built from the document alone would accept and
/// this one refuses, which is a split in the direction that section warns
/// about. Accounting for the rest of `BlockError`: every other variant is
/// either named in the document or, in the case of `NoteNotWhereProved`, a
/// guard against this node disagreeing with itself rather than a rule about a
/// block.
#[test]
fn four_block_refusals_the_document_does_not_carry() {
    let params = ConsensusParams::testnet();
    let good = Note::new(params.reward_at(0), owner(1));

    // "`extra` is free bytes for a miner, bounded, and committed to like
    // everything else." The bound is not given, and neither is the refusal.
    let long_extra = CoinbaseTransaction::with_extra(0, vec![good], vec![0u8; 65]);
    assert!(
        matches!(
            assemble_block(
                &LedgerState::new(),
                long_extra,
                Vec::new(),
                &params,
                1_000,
                0
            ),
            Err(cairn_ledger::BlockError::CoinbaseExtraTooLarge { .. })
        ),
        "the coinbase extra bound is a rule the document does not carry"
    );

    // No limit on coinbase outputs appears anywhere in the document.
    let one_pebble = Note::new(Amount::from_pebbles(1).unwrap(), owner(1));
    let many = CoinbaseTransaction::new(0, vec![one_pebble; 17]);
    assert!(
        matches!(
            assemble_block(&LedgerState::new(), many, Vec::new(), &params, 1_000, 0),
            Err(cairn_ledger::BlockError::TooManyCoinbaseOutputs { .. })
        ),
        "the coinbase output limit is a rule the document does not carry"
    );

    // The document requires ZeroValueOutput of a transfer and says nothing
    // about a coinbase paying a note worth nothing.
    let worthless = CoinbaseTransaction::new(0, vec![Note::new(Amount::ZERO, owner(1))]);
    assert!(
        matches!(
            assemble_block(
                &LedgerState::new(),
                worthless,
                Vec::new(),
                &params,
                1_000,
                0
            ),
            Err(cairn_ledger::BlockError::ZeroValueCoinbaseOutput { .. })
        ),
        "a coinbase output worth nothing is refused by a rule not written down"
    );

    // And a count of transfers, which the document bounds only by bytes.
    let mut narrow = ConsensusParams::testnet();
    narrow.max_transfers_per_block = 1;
    let junk = Transfer::new(vec![Input::hot(note_id(0x99, 0))], vec![one_pebble]);
    assert!(
        matches!(
            assemble_block(
                &LedgerState::new(),
                CoinbaseTransaction::new(0, vec![good]),
                vec![junk.clone(), junk],
                &narrow,
                1_000,
                0
            ),
            Err(cairn_ledger::BlockError::TooManyTransfers { .. })
        ),
        "the transfer count limit is a rule the document does not carry"
    );
}

//! AUDIT: what a stranger's transfer makes a node hash before it is refused.
//!
//! A transfer's identifier is an encoding of its whole body and a hash of that
//! encoding. Every signature on the transfer commits to it, and it is the same
//! value for all of them, because the identifier deliberately leaves the
//! signatures out so that it is known before signing.
//!
//! It was asked for once per input anyway. At the two hundred and fifty six
//! inputs and two hundred and fifty six outputs the rules allow, the body is
//! 19 466 bytes, so a transfer that arrived as 36 106 bytes was re-encoded and
//! re-hashed 256 times: five megabytes each way, 139 times what was received.
//! All of it ran before the first signature was looked at, and the signatures
//! are checked with a short circuit, so one nonsense signature threw the whole
//! of it away for the price of one comparison. A peer could send that as fast
//! as it could upload, and be refused each time without being disconnected or
//! marked.
//!
//! The same path judges a mined block, so it was not only a relay cost: every
//! node on the network paid it for every block full of such transfers.
//!
//! So this counts, and does not time. Two durations compared would be a
//! measurement of whatever else the machine was doing; the claim being held to
//! is that the work a message can ask for is bounded by the length of the
//! message, and that is a count. `cairn-primitives` counts bytes fed to a
//! hasher, per thread, in test builds only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use std::collections::{BTreeMap, BTreeSet};

use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{
    CoinbaseTransaction, Input, Transfer, COINBASE_VERSION, TRANSFER_VERSION,
};
use cairn_ledger::validation::{
    assemble_block, check_transfer, connect_block, mine_block, ConsensusParams, TransferError,
};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::{CodecError, Decode, Encode};
use cairn_primitives::hash::{counting, Domain, Hasher};
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 20;

/// The rules, with the reward spendable after two blocks instead of after a
/// thousand.
///
/// Nothing in this file is about maturity, and the two are kept equal for the
/// reason the field's own note gives. A thousand blocks of mining to reach a
/// spendable note would be minutes of test for a number that does not move.
fn params() -> ConsensusParams {
    ConsensusParams {
        burial: 2,
        coinbase_maturity: 2,
        ..ConsensusParams::testnet()
    }
}

fn owner() -> SecretKey {
    SecretKey::from_bytes(&[9; 32])
}

/// A chain of exactly the blocks this file needs, and the notes they leave.
struct Chain {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: 1_000_000,
        }
    }

    fn mine(&mut self, coinbase: CoinbaseTransaction, transfers: Vec<Transfer>) {
        self.clock += 60;
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .expect("the body should assemble");
        let block = mine_block(block, ATTEMPTS).expect("difficulty one takes an early nonce");
        connect_block(&mut self.state, &block, &self.params, NOW).expect("it should apply");
    }

    fn plain(&mut self, to: &SecretKey) -> (NoteId, Note) {
        let height = self.state.next_height().unwrap();
        let reward = self.params.reward_at(height);
        let note = Note::new(reward, to.public_key());
        let coinbase = CoinbaseTransaction::new(height, vec![note]);
        let id = NoteId::new(coinbase.id(), 0);
        self.mine(coinbase, Vec::new());
        (id, note)
    }

    fn empty(&mut self) {
        let height = self.state.next_height().unwrap();
        self.mine(CoinbaseTransaction::new(height, Vec::new()), Vec::new());
    }
}

/// A state holding `count` spendable notes of one pebble each, all one owner's.
///
/// Made by a transfer rather than by a coinbase, so that they are spendable at
/// once: a coinbase may pay at most sixteen notes and they wait for maturity,
/// and what a transfer creates waits for nothing.
fn a_state_holding(count: usize) -> (LedgerState, ConsensusParams, Vec<(NoteId, Note)>) {
    let holder = owner();
    let mut chain = Chain::new();
    let (funded, note) = chain.plain(&holder);
    chain.empty();
    chain.empty();

    let outputs: Vec<Note> = (0..count)
        .map(|_| Note::new(Amount::from_pebbles(1).unwrap(), holder.public_key()))
        .collect();
    let mut spreading = Transfer::new(vec![Input::hot(funded)], outputs.clone());
    spreading.sign_input(chain.params.network, 0, &note, &holder);
    let spread_id = spreading.id();

    let height = chain.state.next_height().unwrap();
    chain.mine(
        CoinbaseTransaction::new(height, Vec::new()),
        vec![spreading],
    );

    let notes = outputs
        .into_iter()
        .enumerate()
        .map(|(index, note)| (NoteId::new(spread_id, u32::try_from(index).unwrap()), note))
        .collect();
    (chain.state, chain.params, notes)
}

/// What a transfer of `inputs` inputs costs a node that refuses it.
struct Cost {
    /// Bytes the transfer took on the wire.
    received: usize,
    /// Bytes the node fed to a hasher answering it.
    hashed: u64,
}

/// The cost of refusing a transfer of `notes` inputs paying `notes` outputs.
///
/// Square on purpose: at 256 it is the largest transfer the rules admit, which
/// is where the body being re-encoded per input cost the most.
fn cost_of_refusing(notes: usize) -> Cost {
    let (state, params, held) = a_state_holding(notes);
    let holder = owner();

    // Every input signed by nobody, which is what an attacker sends: the
    // signatures are the last thing checked and the first bad one ends it, so
    // everything before that point is work the sender did not pay for.
    let spending: Vec<Input> = held.iter().map(|(id, _)| Input::hot(*id)).collect();
    let paying: Vec<Note> = (0..notes)
        .map(|_| Note::new(Amount::from_pebbles(1).unwrap(), holder.public_key()))
        .collect();
    let transfer = Transfer::new(spending, paying);
    let received = transfer.encode().len();

    counting::reset();
    let refused = check_transfer(
        &transfer,
        &state,
        &BTreeSet::new(),
        &BTreeMap::new(),
        &params,
    );
    let hashed = counting::hashed();

    assert_eq!(
        refused,
        Err(TransferError::InvalidSignature { input_index: 0 }),
        "an unsigned transfer is refused at its first input"
    );
    Cost { received, hashed }
}

/// Nothing about what is signed changed, and this is what says so.
///
/// The message is written out here the way it reads in the rule: the network,
/// the version, the identifier, the position of the input, and the value and
/// owner of the note being spent, in that order, under the signature message
/// domain. Holding the implementation to a separate statement of the rule is
/// the point. If the two ever part company, a wallet signs one thing and a
/// validator checks another, and every signature in the pool stops holding.
#[test]
fn the_message_a_signature_covers_is_the_one_it_always_was() {
    let holder = owner();
    let spent = Note::new(Amount::from_pebbles(1_000).unwrap(), holder.public_key());
    let transfer = Transfer::new(
        vec![
            Input::hot(NoteId::new(Hash32::from_bytes([4; 32]), 0)),
            Input::hot(NoteId::new(Hash32::from_bytes([5; 32]), 7)),
        ],
        vec![Note::new(
            Amount::from_pebbles(900).unwrap(),
            holder.public_key(),
        )],
    );
    let network = ConsensusParams::testnet().network;

    for index in 0..2u32 {
        let mut hasher = Hasher::new(Domain::SignatureMessage);
        hasher.update(&network.encode());
        hasher.update(&transfer.version.encode());
        hasher.update(transfer.id().as_bytes());
        hasher.update(&index.encode());
        hasher.update(&spent.value.encode());
        hasher.update(spent.owner.as_bytes());
        assert_eq!(
            transfer.signature_message(network, index, &spent),
            hasher.finalize(),
            "the message signed at input {index} is not the one the rule states"
        );
    }

    // And the value hoisted out of the loop is the identifier itself, not
    // something derived from it that happens to agree at one input.
    assert_eq!(transfer.signing(network).id(), transfer.id());
    for index in 0..2u32 {
        assert_eq!(
            transfer.signing(network).message(index, &spent),
            transfer.signature_message(network, index, &spent)
        );
    }
}

/// The one that was found: hashing has to stay proportional to the message.
///
/// It stands at 40 458 bytes hashed for 36 106 received, which is 1.1 times.
/// Four times is a bound with room in it, because the point is the order and
/// not the constant. The same measurement before the fix read 5 023 754 bytes
/// for the same 36 106, which is 139.1 times, and missed a bound of four by a
/// factor of thirty five.
#[test]
fn refusing_a_full_transfer_hashes_about_what_it_received() {
    let cost = cost_of_refusing(256);
    let ratio = cost.hashed as f64 / cost.received as f64;
    assert!(
        cost.hashed < 4 * u64::try_from(cost.received).unwrap(),
        "refusing {} bytes hashed {} of them, {ratio:.1} times what arrived",
        cost.received,
        cost.hashed
    );
}

/// And it is proportional, not merely small at one size.
///
/// A bound at one size can be met by a constant that happens to be generous.
/// Four times the notes for four times the work is the shape that says the
/// cost follows the message: it reads 10 122 bytes at 64 and 40 458 at 256,
/// a factor of exactly 4.0. Squared it would be sixteen, and it was: the same
/// pair before the fix read 322 058 and 5 023 754, a factor of 15.6.
#[test]
fn four_times_the_notes_is_about_four_times_the_work() {
    let small = cost_of_refusing(64);
    let large = cost_of_refusing(256);
    let growth = large.hashed as f64 / small.hashed as f64;
    assert!(
        large.hashed < small.hashed * 6,
        "64 notes hashed {}, 256 notes hashed {}, a factor of {growth:.1}",
        small.hashed,
        large.hashed
    );
}

// ---------------------------------------------------------------------------
// The other half of the same bill: what a frame costs before any rule sees it.
// ---------------------------------------------------------------------------

/// A transfer frame promising `inputs` inputs and carrying none of them.
///
/// Truncated on purpose. A decoder that reads the count and stops has one
/// answer, and a decoder that starts building has another, so the error says
/// which of the two happened without anything having to be counted.
fn a_transfer_promising_inputs(inputs: u32) -> Vec<u8> {
    let mut frame = TRANSFER_VERSION.encode();
    frame.extend(inputs.encode());
    frame
}

/// The same, past the inputs: no inputs at all, then a promise of `outputs`.
fn a_transfer_promising_outputs(outputs: u32) -> Vec<u8> {
    let mut frame = a_transfer_promising_inputs(0);
    frame.extend(outputs.encode());
    frame
}

/// A coinbase frame promising `outputs` outputs and carrying none of them.
fn a_coinbase_promising(outputs: u32) -> Vec<u8> {
    let mut frame = COINBASE_VERSION.encode();
    frame.extend(7u64.encode());
    frame.extend(outputs.encode());
    frame
}

/// A block frame promising `transfers` transfers and carrying none of them.
fn a_block_promising(transfers: u32) -> Vec<u8> {
    let header = BlockHeader {
        version: 1,
        network: ConsensusParams::testnet().network,
        height: 0,
        previous: Hash32::ZERO,
        transactions_root: Hash32::ZERO,
        state_root: Hash32::ZERO,
        history: Hash32::ZERO,
        timestamp: 1_000,
        difficulty: 1,
        total_work: 1,
        nonce: 0,
    };
    let mut frame = header.encode();
    frame.extend(CoinbaseTransaction::new(0, Vec::new()).encode());
    frame.extend(transfers.encode());
    frame
}

/// Notes a megabyte of wire can hold, which is what bounded the old decoder.
const NOTES_IN_A_FRAME: u32 = 26_214;

/// The ceiling is read off the declared count, before a note is built.
///
/// Every note carries a public key and reading one is an Edwards
/// decompression: 7.7 microseconds on the machine
/// `cairn-crypto/examples/verify.rs` was last run on. A megabyte of wire holds
/// 26 214 forty-byte notes, so a peer could buy about two hundred milliseconds
/// of curve arithmetic with one message, and the shape check would then refuse
/// it for having too many outputs, having built the whole of it first.
///
/// `UnexpectedEnd` here would mean the decoder went looking for notes that are
/// not in the frame, which is the behaviour this replaced.
#[test]
fn a_frame_promising_more_than_the_rules_allow_is_refused_unread() {
    assert_eq!(
        Transfer::decode(&a_transfer_promising_outputs(NOTES_IN_A_FRAME)),
        Err(CodecError::InvalidValue {
            type_name: "transfer outputs"
        }),
    );
    assert_eq!(
        Transfer::decode(&a_transfer_promising_inputs(NOTES_IN_A_FRAME)),
        Err(CodecError::InvalidValue {
            type_name: "transfer inputs"
        }),
    );
    assert_eq!(
        CoinbaseTransaction::decode(&a_coinbase_promising(NOTES_IN_A_FRAME)),
        Err(CodecError::InvalidValue {
            type_name: "coinbase outputs"
        }),
    );
    // A transfer is ten bytes empty, so a megabyte of them is a hundred
    // thousand: fewer curve points than the notes above, and the same argument.
    assert_eq!(
        Block::decode(&a_block_promising(104_857)),
        Err(CodecError::InvalidValue {
            type_name: "block transfers"
        }),
    );
}

/// And it is the rules' own ceiling, not one of the decoder's choosing.
///
/// A decoder stricter than consensus would refuse a transfer every node
/// accepts: valid, unrelayable, and silent. The largest transfer the rules
/// admit has to go over the wire and come back, and the first one past that
/// has to be turned away. The build already fails if the two numbers part
/// company; this is the same claim made against real frames.
#[test]
fn the_ceiling_admits_exactly_what_the_rules_admit() {
    let holder = owner();
    let note = || Note::new(Amount::from_pebbles(1).unwrap(), holder.public_key());
    let input = |seed: u8| Input::hot(NoteId::new(Hash32::from_bytes([seed; 32]), 0));
    let rules = ConsensusParams::testnet();

    let full = Transfer::new(
        (0..rules.max_inputs_per_transfer)
            .map(|index| input(u8::try_from(index % 256).unwrap()))
            .collect(),
        (0..rules.max_outputs_per_transfer)
            .map(|_| note())
            .collect(),
    );
    let bytes = full.encode();
    assert_eq!(
        Transfer::decode(&bytes).as_ref(),
        Ok(&full),
        "the largest transfer the rules allow has to survive the wire"
    );

    let too_many_inputs = Transfer::new(
        (0..=rules.max_inputs_per_transfer)
            .map(|index| input(u8::try_from(index % 256).unwrap()))
            .collect(),
        vec![note()],
    );
    assert_eq!(
        Transfer::decode(&too_many_inputs.encode()),
        Err(CodecError::InvalidValue {
            type_name: "transfer inputs"
        }),
    );

    let too_many_outputs = Transfer::new(
        vec![input(1)],
        (0..=rules.max_outputs_per_transfer)
            .map(|_| note())
            .collect(),
    );
    assert_eq!(
        Transfer::decode(&too_many_outputs.encode()),
        Err(CodecError::InvalidValue {
            type_name: "transfer outputs"
        }),
    );
}

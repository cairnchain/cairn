//! What one allowance window buys in signature verifications.
//!
//! A transfer carries between one and `max_inputs_per_transfer` inputs, and
//! every one of them is a note resolved out of the ledger and an Ed25519
//! signature checked against it. Verifying one is the most expensive thing
//! this node does per byte received, and it costs several times what folding a
//! path against the cold set costs, which the same table prices at eight a
//! place.
//!
//! `Transaction` cost four units, for one input or for two hundred and fifty
//! six.
//!
//! **Why the cheap rejections do not cover it.** A transfer whose signatures
//! are nonsense is refused after a handful of checks, because `first_failure`
//! stops at the first one that does not hold and splits the work across
//! threads that each stop at their own. A transfer whose arithmetic is wrong
//! is refused before a single signature is looked at, because the fee is
//! worked out in the same pass that resolves the inputs and returns first. So
//! the whole of a transfer's signature work is reached only by a transfer
//! whose signatures all hold, and that is a transfer whose sender owns the
//! notes.
//!
//! **Which is not a defence.** Two hundred and fifty six notes are one
//! transfer's worth of outputs. Spending them again, in a variant differing by
//! one pebble, is a different identifier, resolves the same way, and is
//! refused by the pool only on the rate it offers, which is worked out after
//! `check_transfer` has verified every signature. So the same two hundred and
//! fifty six signatures can be presented again for four units, as often as the
//! window allows.
//!
//! Counted rather than timed: what a verification takes is the machine's
//! business, and what this is about is how many of them one window buys, which
//! is a property of the table.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{Input, Transfer};
use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::Message;
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::Keeps;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn solo(chain: &mut ChainStore) -> Local<'_> {
    Local {
        keeps: Keeps {
            headers: true,
            cold_set: false,
        },
        nonce: 1,
        chain,
        listen: 4242,
    }
}

fn greeted() -> PeerState {
    PeerState {
        greeted: true,
        height: 1_000,
        total_work: 1,
        ..PeerState::default()
    }
}

/// What one message of this shape took out of the peer's window.
fn charged_for(message: Message) -> u32 {
    let mut chain = ChainStore::new(params());
    let mut peer = greeted();
    let reaction = on_message(&mut solo(&mut chain), &mut peer, message, NOW);
    assert!(
        reaction.drop_peer.is_none(),
        "none of these is misbehaviour"
    );
    peer.spent
}

/// The most inputs a transfer on a named network may carry.
fn most_inputs() -> usize {
    params().max_inputs_per_transfer
}

/// The body a transfer of this shape encodes to.
fn a_body(inputs: usize) -> Transfer {
    let owner = SecretKey::from_bytes(&[7; 32]).public_key();
    let spending: Vec<Input> = (0..inputs)
        .map(|index| {
            Input::hot(NoteId::new(
                Hash32::from_bytes([3; 32]),
                u32::try_from(index).unwrap_or(u32::MAX),
            ))
        })
        .collect();
    Transfer::new(
        spending,
        vec![Note::new(Amount::from_pebbles(1).unwrap(), owner)],
    )
}

/// How many bytes of transfer one unit of allowance buys, at this shape.
///
/// The right way round for a price: a unit should buy about the same amount of
/// work whatever the message is made of, and bytes are what an attacker has to
/// spend to send one.
fn bytes_a_unit_buys(inputs: usize) -> usize {
    let body = a_body(inputs);
    let bytes = body.encode().len();
    let spent = charged_for(Message::Transaction(Box::new(body)));
    bytes
        .checked_div(usize::try_from(spent.max(1)).unwrap_or(1))
        .unwrap_or(bytes)
}

/// A unit buys about the same amount of transfer whatever shape it is in.
///
/// This is the whole of it. A flat price on a message whose size and whose
/// work both run from one input to two hundred and fifty six means the units
/// buy whatever the sender chooses: the large shape was the cheap one, by the
/// full ratio between the two.
#[test]
fn a_unit_buys_about_the_same_transfer_whichever_shape_it_is_in() {
    let small = bytes_a_unit_buys(1);
    let large = bytes_a_unit_buys(most_inputs());
    println!(
        "one unit buys {small} bytes of a one input transfer and {large} bytes \
         of a {} input one",
        most_inputs()
    );

    // Four is slack and not a measurement: what is being refused is a price
    // that is wrong by orders of magnitude, and the two shapes differ in their
    // fixed parts as well as in their inputs.
    assert!(
        large <= small.saturating_mul(4),
        "one unit buys {large} bytes of a transfer presenting {} signatures and \
         only {small} bytes of one presenting a single signature, so the \
         largest and dearest shape is the cheapest to send",
        most_inputs()
    );
}

/// And the price moves with the signatures, which is what pays for them.
#[test]
fn a_transfer_is_priced_by_the_signatures_it_presents() {
    let one = charged_for(Message::Transaction(Box::new(a_body(1))));
    let many = charged_for(Message::Transaction(Box::new(a_body(most_inputs()))));
    println!(
        "a transfer of 1 input costs {one}; one of {} costs {many}",
        most_inputs()
    );
    assert!(
        many > one,
        "a transfer presenting {} signatures cost {many} and one presenting a \
         single signature cost {one}, so the price says nothing about how much \
         verifying it takes",
        most_inputs()
    );
}

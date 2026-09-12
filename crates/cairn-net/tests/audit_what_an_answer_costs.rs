//! What a peer pays to be answered, against what it pays to answer.
//!
//! Every list in this protocol is capped while decoding and priced by its
//! length, and the two directions of an exchange are priced in the same
//! currency: a header served costs what a header taken in costs, and an
//! address handed over costs what an address learned costs. The paths into
//! the cold set were the last pair where that was not true. Asking for one
//! cost eight units; being handed sixty four of them cost one unit for the
//! lot, because `Proofs` fell through to the catch-all arm.
//!
//! The two ends do comparable work. Serving a place walks a tree and puts
//! about a kilobyte on the wire. Taking one reads that kilobyte back and folds
//! it against a commitment this node worked out for itself, hash by hash, with
//! the chain held for the length of the fold.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::ForestProof;
use cairn_chain::ChainStore;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::{Message, Placed, MAX_PROVEN};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::Keeps;
use cairn_primitives::Hash32;

/// A multiple of the ten second window, so every message in one measurement
/// falls inside one allowance.
const NOW: u64 = 2_000_000_000;

/// Far above what one window pays for at any sane price, so a measurement is
/// ended by the allowance and never by its own ceiling.
const ROUNDS: u64 = 100_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn keeping_everything(chain: &mut ChainStore) -> Local<'_> {
    Local {
        keeps: Keeps {
            headers: true,
            cold_set: true,
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

/// The largest ask one message carries.
fn a_full_ask(round: u64) -> Message {
    Message::GetProofs(
        (0..MAX_PROVEN as u64)
            .map(|place| round * MAX_PROVEN as u64 + place)
            .collect(),
    )
}

/// The largest answer one message carries, at the depth a real one reaches.
///
/// Nothing here has to fold. What is being counted is what the node is charged
/// for being handed the message, which is settled before a single sibling is
/// looked at.
fn an_answer_of(places: u64, round: u64) -> Message {
    Message::Proofs(
        (0..places)
            .map(|place| Placed {
                position: round * MAX_PROVEN as u64 + place,
                proof: Some(ForestProof {
                    siblings: vec![Hash32::ZERO; 32],
                }),
            })
            .collect(),
    )
}

fn a_full_answer(round: u64) -> Message {
    an_answer_of(MAX_PROVEN as u64, round)
}

/// Places one peer can make this node handle in one allowance window.
///
/// Counted rather than timed. What a price decides is how many messages a
/// window pays for, and that is arithmetic; timing two runs of folds on a
/// loaded machine measures the machine.
///
/// The loop ends where the allowance does, which is the one place `spent`
/// stops moving: a peer that cannot afford a message is answered with silence
/// and charged nothing.
fn places_in_one_window(each: impl Fn(u64) -> Message, carried: u64) -> u64 {
    let mut chain = ChainStore::new(params());
    let mut peer = greeted();
    let mut handled = 0u64;
    for round in 0..ROUNDS {
        let before = peer.spent;
        on_message(
            &mut keeping_everything(&mut chain),
            &mut peer,
            each(round),
            NOW,
        );
        if peer.spent == before {
            break;
        }
        handled += carried;
    }
    handled
}

/// What one message costs this peer, which is the figure both tests rest on.
fn charged_for(message: Message) -> u32 {
    let mut chain = ChainStore::new(params());
    let mut peer = greeted();
    on_message(&mut keeping_everything(&mut chain), &mut peer, message, NOW);
    peer.spent
}

/// **Places one window folds, against places the same window builds.**
///
/// `GetProofs` is charged a unit for every place it asks about, whether or not
/// a path comes back, because a node that cannot prove a place still had to
/// look. An answer was charged one unit whatever it carried, and what it
/// carries is up to [`MAX_PROVEN`] paths, each of them folded against the cold
/// set while the chain is held.
///
/// So one window bought a thousand and twenty four paths built here and half a
/// million folded here, a factor of five hundred and twelve, and the cheaper
/// of the two is the one that takes the chain's lock.
#[test]
fn a_path_costs_no_less_to_fold_than_to_build() {
    let built = places_in_one_window(a_full_ask, MAX_PROVEN as u64);
    let folded = places_in_one_window(a_full_answer, MAX_PROVEN as u64);

    assert!(
        folded <= built,
        "one window had {folded} paths folded against the cold set and {built} \
         built out of it, a factor of {}. Both walk the same tree, and the \
         cheaper of the two is the one that holds the chain while it works",
        folded / built.max(1),
    );
    assert_eq!(
        charged_for(a_full_answer(0)),
        charged_for(a_full_ask(0)),
        "the two ends of the path exchange are priced in the same currency"
    );
}

/// **And a short answer costs less than a full one.**
///
/// The other half of pricing by length: a peer that has one path to hand over
/// must not be charged as though it sent the largest answer the wire carries.
/// The same rule the address list and the header run follow, and the reason a
/// flat [`MAX_PROVEN`] would be the wrong repair.
#[test]
fn a_short_answer_is_not_charged_as_a_full_one() {
    let one_at_a_time = places_in_one_window(|round| an_answer_of(1, round), 1);
    let in_full = places_in_one_window(a_full_answer, MAX_PROVEN as u64);

    assert_eq!(
        one_at_a_time, in_full,
        "a window pays for the same number of paths however they are packed"
    );
    assert!(
        charged_for(an_answer_of(1, 0)) < charged_for(a_full_answer(0)),
        "a peer handing over what it has is charged for what it sent, not for \
         what it could have sent"
    );
}

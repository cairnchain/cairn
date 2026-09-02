//! What one connection's allowance costs the connection beside it.
//!
//! A connection starts where its address left off, so hanging up is not a way
//! of being handed a fresh window. That repair is right and it stays. What it
//! did wrongly was renew: the inheritance ran at every window boundary rather
//! than once, so two connections at one address shared a count for as long as
//! they both lived.
//!
//! The people that hurt were not attackers. Two nodes behind one carrier NAT,
//! one office, one cloud gateway; whichever spoke second each window was
//! answered with silence for as long as the other kept talking. Two hundred
//! and forty messages over five minutes made a neighbour invisible, and window
//! boundaries are `unix_time / 10`, which anybody can compute.

#![allow(
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::{Arc, Mutex};

use cairn_chain::ChainStore;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::{Joining, Message};
use cairn_net::sync::{on_message, Allowance, Local, PeerState, Window};

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn solo(chain: &mut ChainStore) -> Local<'_> {
    Local {
        keeps: cairn_net::Keeps {
            headers: true,
            cold_set: false,
        },
        nonce: 1,
        chain,
        listen: 4242,
    }
}

/// A connection from an address the node keeps a count for, already greeted.
fn behind(address: &Arc<Mutex<Window>>) -> PeerState {
    PeerState {
        greeted: true,
        height: 1_000,
        total_work: 1,
        allowance: Allowance::at(address),
        ..PeerState::default()
    }
}

/// Whether the node answered at all. `Reaction::idle()` with nothing in it is
/// what an exhausted allowance produces.
fn answered(reaction: &cairn_net::sync::Reaction) -> bool {
    !reaction.reply.is_empty()
        || reaction.share_addresses
        || reaction.join.is_some()
        || reaction.locate.is_some()
        || reaction.headers.is_some()
        || !reaction.fetch.is_empty()
}

// ---------------------------------------------------------------------------
// CLAIM 2: the allowance window is kept per ADDRESS.
// ---------------------------------------------------------------------------

/// **A neighbour's first window costs its own, and no more than that.**
///
/// One window of silence is what the reconnect defence actually needs: a
/// connection that has just opened cannot be told apart from one that hung up
/// and dialled back, so it inherits. From its second window on it has its own
/// history and is answered out of it.
#[test]
fn a_neighbour_on_the_same_address_is_starved_for_one_window_and_no_longer() {
    let mut chain = ChainStore::new(params());
    let address = Arc::new(Mutex::new(Window::default()));
    let now = 2_000_000_000u64; // a multiple of the ten second window

    // The noisy neighbour. Eight join requests, which is the most expensive
    // thing the protocol has and is a perfectly legitimate message.
    let mut noisy = behind(&address);
    let mut spent = 0u32;
    for part in 0..8u32 {
        let reaction = on_message(
            &mut solo(&mut chain),
            &mut noisy,
            Message::GetJoin {
                what: Joining::Ledger,
                part,
            },
            now,
        );
        if answered(&reaction) {
            spent += 1;
        }
    }
    assert_eq!(spent, 8, "eight join requests is one whole window");

    // The victim's connection opens now. It is a different machine and has
    // spent nothing, but from the outside it is also what a reconnect looks
    // like, so this window is not its own.
    let mut victim = behind(&address);
    let served_at_once = (0..16)
        .filter(|_| {
            answered(&on_message(
                &mut solo(&mut chain),
                &mut victim,
                Message::GetPeers,
                now,
            ))
        })
        .count();
    assert_eq!(served_at_once, 0, "the window it opened in was spent");

    // The next window is its own, and every one after it, for as long as it
    // stays connected.
    for window in 1..6u64 {
        let later = now + window * 10;
        for part in 0..8u32 {
            on_message(
                &mut solo(&mut chain),
                &mut noisy,
                Message::GetJoin {
                    what: Joining::Ledger,
                    part,
                },
                later,
            );
        }
        let served = (0..16)
            .filter(|_| {
                answered(&on_message(
                    &mut solo(&mut chain),
                    &mut victim,
                    Message::GetPeers,
                    later,
                ))
            })
            .count();
        assert_eq!(
            served, 16,
            "window {window}: the neighbour spent its own and the victim was \
             answered {served} times out of 16"
        );
    }
}

/// **And hanging up is still not a way to be handed a fresh window.**
///
/// The half the inheritance exists for. A connection that spends its window,
/// closes, and dials back from the same address begins where it left off:
/// this is the same address, and a new connection cannot prove it is not the
/// old one.
#[test]
fn a_reconnect_inside_the_window_still_comes_back_with_nothing() {
    let mut chain = ChainStore::new(params());
    let address = Arc::new(Mutex::new(Window::default()));
    let now = 2_000_000_000u64;

    let mut first = behind(&address);
    for part in 0..8u32 {
        on_message(
            &mut solo(&mut chain),
            &mut first,
            Message::GetJoin {
                what: Joining::Ledger,
                part,
            },
            now,
        );
    }
    drop(first);

    let mut again = behind(&address);
    let served = (0..16)
        .filter(|_| {
            answered(&on_message(
                &mut solo(&mut chain),
                &mut again,
                Message::GetPeers,
                now,
            ))
        })
        .count();
    assert_eq!(
        served, 0,
        "dialling back inside the same window was answered {served} times, so \
         a window can be refilled by hanging up"
    );
}

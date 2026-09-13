//! Every message that carries a list, weighed against every other one.
//!
//! `cost_of` prices six messages by what their list carries, and says why
//! beside three of them in the same words: "priced by what it carries, because
//! what it carries is what this node does with it". Addresses are weighed and
//! written into the book under the book's lock. Headers are appended to a log,
//! which is a disk write apiece. Paths are folded against the cold set with
//! the chain held.
//!
//! `Announce` carries up to `MAX_ANNOUNCED` identifiers and cost one unit,
//! whatever it carried. What this node does with it is a lookup apiece in the
//! block table, and the block table is behind the chain lock, which is the one
//! lock in this node that every other thread waits on.
//!
//! So this counts, for one allowance window, how much of each list a peer can
//! buy. Counted rather than timed: a lookup takes what the machine takes, and
//! the question is not how long one costs but how many a window buys, which is
//! a property of the table and not of the machine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use cairn_chain::{ChainStore, Located};
use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::{Message, PeerAddress, MAX_ANNOUNCED, MAX_SHARED_ADDRESSES};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::Keeps;
use cairn_primitives::Hash32;

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
    let before = peer.spent;
    let reaction = on_message(&mut solo(&mut chain), &mut peer, message, NOW);
    assert!(
        reaction.drop_peer.is_none(),
        "none of these is misbehaviour"
    );
    peer.spent.saturating_sub(before)
}

fn an_announcement(entries: usize) -> Message {
    Message::Announce(
        (0..u64::try_from(entries).unwrap_or(u64::MAX))
            .map(|step| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&step.to_le_bytes());
                Located::new(1_000_000 + step, Hash32::from_bytes(id))
            })
            .collect(),
    )
}

fn addresses(entries: usize) -> Message {
    Message::Peers(
        (0..u32::try_from(entries).unwrap_or(u32::MAX))
            .map(|step| {
                let octets = (step % 200 + 11).to_le_bytes();
                let address = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, octets[0])),
                    9944 + (step % 1000) as u16,
                );
                PeerAddress(address)
            })
            .collect(),
    )
}

/// A list is priced by what it carries, and every list is.
///
/// The two here are the same shape: a bounded run of entries a stranger sends
/// unasked, which this node then walks one by one. One of them was priced by
/// what it carries and the other by the fact that it arrived.
#[test]
fn a_full_list_costs_what_it_carries_whichever_list_it_is() {
    let full = u32::try_from(MAX_ANNOUNCED).unwrap_or(u32::MAX);
    let announced = charged_for(an_announcement(MAX_ANNOUNCED));
    let learned = charged_for(addresses(MAX_SHARED_ADDRESSES));
    println!(
        "a full announcement of {MAX_ANNOUNCED} costs {announced}; \
         a full address list of {MAX_SHARED_ADDRESSES} costs {learned}"
    );

    assert!(
        announced >= full,
        "an announcement of {MAX_ANNOUNCED} identifiers cost {announced}. Every \
         one of them is a lookup in the block table, which is behind the chain \
         lock, and the table beside this prices a list by what it carries: a \
         full address list of {MAX_SHARED_ADDRESSES} costs {learned}."
    );
}

/// And the price moves with the length, which is what "by what it carries"
/// means and what a flat price cannot do.
#[test]
fn an_announcement_of_one_does_not_cost_what_an_announcement_of_many_does() {
    let one = charged_for(an_announcement(1));
    let many = charged_for(an_announcement(MAX_ANNOUNCED));
    println!("one identifier costs {one}; {MAX_ANNOUNCED} of them cost {many}");

    // The honest case is one. A node announces what it just applied, which is
    // one block per message it took, so nothing in an ordinary exchange pays
    // more than it used to.
    assert_eq!(one, 1, "the honest announcement is one identifier");
    assert!(
        many > one,
        "{MAX_ANNOUNCED} identifiers cost {many} and one costs {one}, so the \
         price says nothing about the length"
    );
}

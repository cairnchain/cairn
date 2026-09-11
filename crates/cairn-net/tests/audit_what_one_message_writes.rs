//! What one message makes a node put on a disk, and what the allowance
//! charges for it.
//!
//! Every list a peer can send is capped while decoding and priced by its
//! length: a locator entry, a height in a batch, a place to prove, an address
//! handed over. One was not. A run of headers offered rather than asked for
//! was charged as a single message, and it is the one message in the protocol
//! whose answer is a write: every header in it is appended to a log, record by
//! record, before anything has looked at whether the run is the truth.
//!
//! The price the node puts on the same records read back out is one unit each.
//! So the same disk answered for a header at one unit a read and at a five
//! hundred and twelfth of a unit a write, and the cheaper of the two was the
//! one that grows a file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::note::NetworkId;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::message::{Message, MAX_HEADERS};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::Keeps;
use cairn_primitives::Hash32;

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

/// A header at `height`, which is all this measurement needs of one.
///
/// Nothing here is weighed against a chain: what is being counted is how many
/// records the node is told to file, which is decided before a single one of
/// them is looked at.
fn a_header(height: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        network: NetworkId::TESTNET,
        height,
        previous: Hash32::ZERO,
        transactions_root: Hash32::ZERO,
        state_root: Hash32::ZERO,
        history: Hash32::ZERO,
        timestamp: 0,
        difficulty: 1,
        total_work: 1,
        nonce: 0,
    }
}

/// The largest run one message carries, which is what the decoder lets in.
fn a_full_run(from: u64) -> Message {
    Message::Headers {
        from,
        headers: (0..MAX_HEADERS as u64)
            .map(|step| a_header(from + step))
            .collect(),
    }
}

/// Header records one peer can make this node file in one allowance window.
///
/// Counted rather than timed. What a price decides is how many asks a window
/// pays for, and that is arithmetic; timing two runs of disk writes on a
/// loaded machine measures the machine.
fn records_written_in_one_window(chain: &mut ChainStore) -> u64 {
    let now = 2_000_000_000u64; // a multiple of the ten second window
    let mut peer = greeted();
    let mut filed = 0u64;
    // Far above what one window can pay for at any sane price, so the loop is
    // ended by the allowance and never by its own ceiling.
    for run in 0..1_000_000u64 {
        let reaction = on_message(
            &mut solo(chain),
            &mut peer,
            a_full_run(run * MAX_HEADERS as u64),
            now,
        );
        let Some((_, headers)) = reaction.offered_headers else {
            break;
        };
        filed += headers.len() as u64;
    }
    filed
}

/// Header records the same peer can make it read back off the same log.
fn records_read_in_one_window(chain: &mut ChainStore) -> u64 {
    let now = 2_000_000_000u64;
    let mut peer = greeted();
    let mut read = 0u64;
    for _ in 0..1_000_000u64 {
        let reaction = on_message(
            &mut solo(chain),
            &mut peer,
            Message::GetHeaders {
                from: 0,
                count: MAX_HEADERS as u64,
            },
            now,
        );
        let Some((_, count)) = reaction.headers else {
            break;
        };
        read += count;
    }
    read
}

/// **Records one window files, against records the same window reads.**
///
/// `GetHeaders` is charged a unit for every header it serves, which is a seek
/// and a read. A run offered back was charged one unit whatever it carried,
/// and what it carries is up to [`MAX_HEADERS`] records appended to a log. A
/// write is not the cheaper of the two operations, and this was the only list
/// in the protocol whose price did not move with its length.
///
/// What it cost a node is measured in the file it keeps. A node that was
/// handed a ledger a million and a half blocks up fills in the headers from
/// before it arrived, one run at a time, from whichever peer holds the turn.
/// At one unit a message that whole gap was about three thousand units, a
/// third of a single window: a million and a half records written, a million
/// and a half read back to weigh them, and a forest built over all of it.
/// Asking the same node to read those same headers out costs a million and a
/// half units, which is a hundred and eighty three windows, or half an hour of
/// asking as fast as the allowance allows.
#[test]
fn a_run_of_headers_costs_what_taking_it_in_costs() {
    let mut chain = ChainStore::new(params());
    let written = records_written_in_one_window(&mut chain);
    let read = records_read_in_one_window(&mut chain);

    assert!(
        written <= read,
        "one peer had {written} header records filed to a disk out of one \
         allowance window and {read} read off it, a factor of {}. Both are a \
         record on the same log, and the cheaper of the two is the one that \
         grows the file",
        written / read.max(1),
    );
}

/// **And a short run costs less than a full one.**
///
/// The other half of pricing by length: a peer that has only a handful of
/// headers left to hand over must not be charged as though it sent the largest
/// run the wire carries. The same rule the address list follows.
#[test]
fn a_short_run_is_not_charged_as_a_full_one() {
    let mut chain = ChainStore::new(params());
    let now = 2_000_000_000u64;

    let mut one_at_a_time = greeted();
    let mut singles = 0u64;
    for run in 0..1_000_000u64 {
        let reaction = on_message(
            &mut solo(&mut chain),
            &mut one_at_a_time,
            Message::Headers {
                from: run,
                headers: vec![a_header(run)],
            },
            now,
        );
        if reaction.offered_headers.is_none() {
            break;
        }
        singles += 1;
    }

    let mut in_full_runs = greeted();
    let mut runs = 0u64;
    for run in 0..1_000_000u64 {
        let reaction = on_message(
            &mut solo(&mut chain),
            &mut in_full_runs,
            a_full_run(run * MAX_HEADERS as u64),
            now,
        );
        if reaction.offered_headers.is_none() {
            break;
        }
        runs += 1;
    }

    assert!(
        singles > runs,
        "a window took in {singles} single headers and {runs} full runs of \
         {MAX_HEADERS}. A peer handing over what it has left is charged for \
         what it sent, not for what it could have sent"
    );
}

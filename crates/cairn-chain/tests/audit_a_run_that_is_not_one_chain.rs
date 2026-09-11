//! What a node stands behind when it is handed a run of headers.
//!
//! A node that joins a chain rather than reading it takes two things from a
//! stranger: a ledger, and the run of headers that ends at the tip the ledger
//! belongs to. `ChainStore::adopt` is the door both come through, and the
//! branch it builds from the run is what the node answers every question about
//! where it stands with.
//!
//! The run is the half nothing here used to look at. `Handover` checks the one
//! it carries, and the two callers in `cairn-net` both go through it, so this
//! is a door that is closed today from the outside. It is still the door:
//! `adopt` is a public entry point on this crate, it takes a slice of headers
//! from whoever calls it, and it already re-asks the version question of a
//! ledger that has been through the same check, for the reason written beside
//! it. What follows is what the run being wrong costs, measured rather than
//! argued.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{ChainError, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 20;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A short chain, and the headers that go with it.
fn chain(blocks: usize, miner: &SecretKey) -> (Vec<Block>, Vec<BlockHeader>) {
    let params = ConsensusParams::testnet();
    let mut state = LedgerState::new();
    let mut clock = 1_000_000u64;
    let mut made = Vec::new();
    for _ in 0..blocks {
        let height = state.next_height().unwrap();
        clock += 60;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        made.push(block);
    }
    let headers = made.iter().map(|block| block.header).collect();
    (made, headers)
}

/// The ledger a node that built the chain would hand over, and its run.
fn handed(blocks: usize) -> (LedgerState, Vec<BlockHeader>) {
    let params = ConsensusParams::testnet();
    let (made, headers) = chain(blocks, &wallet(1));
    let mut source = ChainStore::new(params);
    for block in made {
        source.add_block(block, NOW).unwrap();
    }
    let state = source.ledger_at(source.height().unwrap()).unwrap();
    (state, headers)
}

/// A run with a hole in it is refused, and the run it was cut from is taken.
///
/// `Branch::from_tail` reads the run twice over. It files the nth header at the
/// nth height above the first, which is what `id_at` answers from, and it
/// indexes each one back by the height the header itself claims, which is what
/// `height_of` and `agrees_with` answer from. Both are right about a run that
/// is one consecutive chain, and a run with a hole makes them different numbers
/// for the same block, with nothing anywhere to say so: the ledger's tip still
/// matches the last header, which is the only thing that used to be asked.
///
/// What it costs is the node's word about where it stands. Taken with the
/// fourth of eight headers left out, the branch ran to height 6 while the
/// ledger reported 7; `id_at` answered nothing at all for the tip; and
/// `locator`, which is what this node offers a peer to find where two branches
/// part, named height 6 beside the identifier of the header from height 7, and
/// three more positions under it, none of which this node had ever held. The
/// same lookup answers `agrees_with`, so a peer naming the real header at
/// height 6 would have been told no. A node that cannot say where it is cannot
/// be synced by anybody, and it does not know that about itself.
#[test]
fn a_run_of_headers_with_a_hole_in_it_is_not_a_branch_a_node_can_stand_behind() {
    let params = ConsensusParams::testnet();
    let (state, headers) = handed(8);

    let mut gapped = headers.clone();
    gapped.remove(3);
    assert_eq!(
        gapped.last().map(BlockHeader::id),
        headers.last().map(BlockHeader::id),
        "it still ends at the tip the ledger belongs to, which is what was asked"
    );

    let mut joined = ChainStore::new(params);
    assert_eq!(
        joined.adopt(state.clone(), &gapped),
        Err(ChainError::BrokenRun { height: 4 }),
        "the height that does not follow on from the one before it"
    );
    assert!(
        joined.is_empty(),
        "and a run refused leaves the node on no chain rather than on a \
         branch it cannot place itself on"
    );

    // The same ledger with the run it was actually cut from.
    assert_eq!(joined.adopt(state, &headers), Ok(()));
    assert_eq!(joined.height(), Some(7));
    assert_eq!(joined.id_at(7), headers.last().map(BlockHeader::id));
    for entry in joined.locator() {
        assert!(
            joined.agrees_with(&entry),
            "the locator names height {}, which this node does not hold",
            entry.height
        );
        assert_eq!(
            headers
                .iter()
                .find(|header| header.id() == entry.id)
                .map(|header| header.height),
            Some(entry.height),
            "and the height it names for that header is the header's own"
        );
    }
}

/// A run whose headers do not name each other is refused for the same reason.
///
/// The heights can be consecutive and the chain still not be one: a header
/// carries what it was built on, and a run where that is not the header before
/// it is two branches spliced. `id_at` would then answer, for a height on this
/// node's own branch, a block that is on somebody else's.
#[test]
fn a_run_spliced_out_of_two_branches_is_refused_though_its_heights_run_on() {
    let params = ConsensusParams::testnet();
    let (state, headers) = handed(8);
    let (_, elsewhere) = chain(8, &wallet(2));
    assert_ne!(elsewhere[4].id(), headers[4].id(), "two different chains");

    let mut spliced = headers.clone();
    spliced[4] = elsewhere[4];
    assert_eq!(spliced[4].height, headers[4].height, "the heights run on");

    let mut joined = ChainStore::new(params);
    assert_eq!(
        joined.adopt(state, &spliced),
        Err(ChainError::BrokenRun { height: 4 }),
        "the first header that does not name the one before it"
    );
    assert!(joined.is_empty());
}

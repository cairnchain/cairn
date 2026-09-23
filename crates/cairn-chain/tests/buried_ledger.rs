//! Reaching the buried ledger a handover is built from.
//!
//! `own_ledger` and the ledger-serving path both call
//! `chain.ledger_at(tip - params.burial)`: the anchor a newcomer is handed and
//! the one a node re-checks for itself. On mainnet `burial == MAX_REORG_DEPTH`
//! (both 1024), so the anchor sits exactly `MAX_REORG_DEPTH` blocks below the
//! tip. This test checks that `ledger_at` can actually reach it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{ChainStore, MAX_REORG_DEPTH};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

struct Miner {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Miner {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: 1_000,
        }
    }
    fn mine(&mut self, miner: &SecretKey) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }
}

/// The mainnet burial depth: a handover's anchor sits `MAX_REORG_DEPTH` blocks
/// below the tip, and `ledger_at` has to be able to rebuild it, or no node can
/// ever serve or re-check a buried ledger.
///
/// A node holds `MAX_REORG_DEPTH + 1` undo records, enough to reorganise that
/// deep, and therefore enough to undo its way to a state `MAX_REORG_DEPTH`
/// blocks back. `ledger_at`'s own guard refuses one block short of that.
///
/// One more than the depth, because the block a switch lands on has to be
/// nameable and holdable as well as reachable: see `forget_what_cannot_change`.
#[test]
fn the_burial_anchor_can_be_rebuilt() {
    let miner = wallet(1);
    let mut source = Miner::new();
    let mut store = ChainStore::new(params());

    // One block past the point where the undo window starts trimming.
    for _ in 0..=(MAX_REORG_DEPTH as u64) {
        let block = source.mine(&miner);
        store.add_block(block, NOW).unwrap();
    }

    let tip = store.height().unwrap();
    let burial = MAX_REORG_DEPTH as u64; // what params.burial is on mainnet
    let anchor = tip - burial;

    // The undo records to reach the anchor are all present: the window holds a
    // full MAX_REORG_DEPTH of them, and the height one deeper than the anchor
    // is reconstructable, so the record needed to undo the last block down to
    // the anchor is held too.
    assert_eq!(store.undo_records(), MAX_REORG_DEPTH + 1);
    assert!(
        store.ledger_at(anchor + 1).is_some(),
        "one block shallower than the anchor rebuilds fine"
    );

    // So the anchor itself must rebuild. It does not: `ledger_at` refuses
    // `height < undo_from`, and after trimming `undo_from == anchor + 1`, so
    // the burial anchor, the exact height every handover is taken from, is
    // rejected by one.
    assert!(
        store.ledger_at(anchor).is_some(),
        "the burial anchor at height {anchor} (tip {tip} minus burial {burial}) \
         cannot be rebuilt, so own_ledger and the handover-serving path both \
         return None on any network where burial == MAX_REORG_DEPTH (testnet-6 \
         and mainnet both do)"
    );

    // And the edge itself, read off what is held rather than off the anchor.
    // The two were the same number when this was written and are not any more:
    // the records reach past the anchor now, so everything above says nothing
    // about where the window ends. Nothing in this workspace had ever gone far
    // enough for it to end at all, which is a whole edge no fixture stood on:
    // the chain above is exactly `HELD_WINDOW` long and the first record is
    // only let go on the block after it.
    for _ in 0..4 {
        let block = source.mine(&miner);
        store.add_block(block, NOW).unwrap();
    }
    let tip = store.height().unwrap();
    // Records cover every height from `undo_from` to the tip, and a rewind
    // lands on the height below the first of them.
    let held = u64::try_from(store.undo_records()).unwrap();
    let undo_from = tip + 1 - held;
    assert!(
        undo_from > 1,
        "the window has trimmed, so there is an edge to stand on"
    );
    assert!(
        store.ledger_at(undo_from - 1).is_some(),
        "the deepest height a rewind lands on is the one below the first record"
    );
    assert!(
        store.ledger_at(undo_from - 2).is_none(),
        "and one deeper than that is past what was kept"
    );
}

/// What `ledger_at` answers is a ledger at that height, and nothing where it
/// cannot be at one.
///
/// Three things were unmeasured here and each is a different way of handing
/// back the wrong chain. The test above and the ones beside it ask only
/// whether an answer came, never what height it is at, and they ask only
/// about heights at or below the tip.
///
/// - The walk down is what makes the answer a ledger at that height. Turned
///   around it does not run, and the present comes back wearing a height it
///   does not have. This is the ledger a newcomer is handed.
/// - Past the tip, one condition read as two answers with the present again,
///   for a height this node has not reached.
///
/// The deep edge is the other half and belongs to the test above, which mines
/// far enough for the window to trim. It had drifted off that edge: the
/// records reach further back than when it was written, so it was asking
/// about a height comfortably inside. It is read off `undo_records` now, so
/// it stands on the edge wherever the edge moves to.
#[test]
fn a_ledger_at_a_height_is_at_that_height_or_is_not_given() {
    let miner = wallet(1);
    let mut source = Miner::new();
    let mut store = ChainStore::new(params());
    for _ in 0..8 {
        let block = source.mine(&miner);
        store.add_block(block, NOW).unwrap();
    }

    let tip = store.height().unwrap();
    for height in 0..=tip {
        let at = store
            .ledger_at(height)
            .unwrap_or_else(|| panic!("height {height} is inside the window"));
        assert_eq!(
            at.tip().map(|tip| tip.height),
            Some(height),
            "the ledger given for height {height} has to be the one at it"
        );
    }

    for above in [tip + 1, tip + 2, tip + 1000] {
        assert!(
            store.ledger_at(above).is_none(),
            "height {above} is above the tip {tip} and this node has no ledger there"
        );
    }
}

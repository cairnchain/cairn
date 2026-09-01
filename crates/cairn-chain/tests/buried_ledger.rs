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
/// A node holds `MAX_REORG_DEPTH` undo records, enough to reorganise that
/// deep, and therefore enough to undo its way to a state `MAX_REORG_DEPTH`
/// blocks back. `ledger_at`'s own guard refuses one block short of that.
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
    assert_eq!(store.undo_records(), MAX_REORG_DEPTH);
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
         return None on any network where burial == MAX_REORG_DEPTH (testnet-4 \
         and mainnet both do)"
    );
}

//! Tying a handed-over ledger to the tip that was weighed.
//!
//! A forest proof says a header sits at a position in a forest. It does not
//! say the forest is a chain, and the forest belongs to whoever made the tip.
//! That gap was worth a whole ledger: a forger took the honest chain's headers,
//! swapped one leaf for a header of a private chain it had mined for nothing,
//! and mined a tip at the difficulty floor. The two headers sat at the same
//! height and spanned the same unit of work, so no draw could tell them apart.
//!
//! What closes it is that the forest is append only. A newcomer holds the
//! forest as it stood before the anchor, because the anchor commits to it, so
//! it can add the anchor and every header above it and see whether it arrives
//! at the forest the tip commits to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::BlockHeader;
use cairn_ledger::handover::{check_buried, HandoverError, MOST_BURIED};
use cairn_ledger::note::Note;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
/// Enough for a full window below the anchor and a run above it.
const BURIED: usize = 40;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// A chain, and the header forest as it stood at every height of it.
struct Chain {
    headers: Vec<BlockHeader>,
    forests: Vec<Archive>,
}

impl Chain {
    /// `seed` decides who is paid, so two chains built with different seeds
    /// are different chains at every height.
    fn build(seed: u8, count: usize) -> Self {
        let params = params();
        let miner = SecretKey::from_bytes(&[seed; 32]);
        let mut state = LedgerState::new();
        let mut headers = Vec::with_capacity(count);
        let mut forests = Vec::with_capacity(count + 1);
        let mut forest = Archive::new();
        let mut clock = 1_000u64;

        forests.push(forest.clone());
        for _ in 0..count {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            forest.add(header_leaf(&block.header.id()));
            forests.push(forest.clone());
            headers.push(block.header);
        }
        Self { headers, forests }
    }

    /// The forest as it stood before the header at `height`.
    fn before(&self, height: usize) -> cairn_accumulator::forest::Forest {
        self.forests[height].forest().roots_only()
    }
}

/// The anchor, the tip, and everything between them, out of one honest chain.
struct Handed {
    at: BlockHeader,
    tip: BlockHeader,
    before_at: cairn_accumulator::forest::Forest,
    buried: Vec<BlockHeader>,
    recent: Vec<BlockHeader>,
}

fn handed(chain: &Chain) -> Handed {
    let anchor = chain.headers.len() - 1 - BURIED;
    let first_recent = anchor + 1 - RECENT_HEADERS;
    Handed {
        at: chain.headers[anchor],
        tip: *chain.headers.last().unwrap(),
        before_at: chain.before(anchor),
        buried: chain.headers[anchor + 1..].to_vec(),
        recent: chain.headers[first_recent..=anchor].to_vec(),
    }
}

fn built() -> Chain {
    Chain::build(1, RECENT_HEADERS + BURIED + 1)
}

#[test]
fn an_honest_run_ties_the_ledger_to_the_tip() {
    let chain = built();
    let handed = handed(&chain);
    check_buried(
        &handed.at,
        &handed.tip,
        &handed.before_at,
        &handed.buried,
        &handed.recent,
        &params(),
    )
    .expect("a real chain reaches its own tip");
}

/// The forgery the check exists for. A leaf somewhere below the anchor is a
/// header from another chain, and nothing about the run itself is touched.
/// Rebuilding the forest from the anchor upward arrives somewhere the tip does
/// not commit to, and it does not matter where the swap was or whether any
/// draw would ever have looked there.
#[test]
fn a_swapped_leaf_anywhere_below_the_anchor_is_caught() {
    let honest = built();
    let elsewhere = Chain::build(9, honest.headers.len());
    let handed = handed(&honest);
    let anchor = honest.headers.len() - 1 - BURIED;

    let refused = check_buried(
        &handed.at,
        &handed.tip,
        &elsewhere.before(anchor),
        &handed.buried,
        &handed.recent,
        &params(),
    );
    assert!(
        matches!(refused, Err(HandoverError::NotOnTheWeighedChain)),
        "the run is honest and the ground under it is not, and it said {refused:?}"
    );
}

/// And the same for an anchor that is a genuine header of another chain: the
/// run above it names a parent it does not have.
#[test]
fn an_anchor_from_another_chain_is_caught() {
    let honest = built();
    let elsewhere = Chain::build(9, honest.headers.len());
    let handed = handed(&honest);
    let anchor = honest.headers.len() - 1 - BURIED;

    let refused = check_buried(
        &elsewhere.headers[anchor],
        &handed.tip,
        &elsewhere.before(anchor),
        &handed.buried,
        &handed.recent,
        &params(),
    );
    assert!(
        refused.is_err(),
        "an anchor mined for nothing on a private chain cannot reach this tip"
    );
}

/// The burial has to have been mined. Before this the sender chose the
/// difficulties of the run and could put every one of them on the floor, so a
/// thousand blocks of burial were a thousand hashes. The window decides that
/// number now, so a window whose blocks came fast demands more than the floor
/// and an honest-looking run at the floor is refused.
#[test]
fn a_run_at_a_difficulty_nobody_demanded_is_refused() {
    let chain = built();
    let mut handed = handed(&chain);
    for (step, header) in handed.recent.iter_mut().enumerate() {
        header.timestamp = 1_000 + step as u64;
    }
    let refused = check_buried(
        &handed.at,
        &handed.tip,
        &handed.before_at,
        &handed.buried,
        &handed.recent,
        &params(),
    );
    assert!(
        matches!(
            refused,
            Err(HandoverError::BuriedAtTheWrongDifficulty { .. })
        ),
        "the retarget decides that number, not the sender, and said {refused:?}"
    );
}

/// The anchor's own total work used to be a number the sender wrote down and
/// nobody read. It is now the tip's, which the sampling established, less a
/// run checked block by block.
#[test]
fn work_that_does_not_add_up_along_the_run_is_refused() {
    let chain = built();
    let mut handed = handed(&chain);
    handed.at.total_work = u128::MAX / 2;
    handed.buried[0].previous = handed.at.id();
    let refused = check_buried(
        &handed.at,
        &handed.tip,
        &handed.before_at,
        &handed.buried,
        &handed.recent,
        &params(),
    );
    assert!(
        matches!(refused, Err(HandoverError::BuriedWorkDoesNotAddUp { .. })),
        "an anchor cannot state whatever work it likes, and said {refused:?}"
    );
}

#[test]
fn a_run_that_stops_short_of_the_tip_is_refused() {
    let chain = built();
    let handed = handed(&chain);
    let short = handed.buried[..handed.buried.len() - 1].to_vec();
    let refused = check_buried(
        &handed.at,
        &handed.tip,
        &handed.before_at,
        &short,
        &handed.recent,
        &params(),
    );
    assert!(
        matches!(refused, Err(HandoverError::BuriedRunWrongLength { .. })),
        "the run has as many headers as there are heights between, and said {refused:?}"
    );
}

/// The sender chooses the length and the receiver walks it, so the length
/// needs a ceiling of its own.
#[test]
fn a_run_longer_than_the_ceiling_is_refused() {
    let chain = built();
    let mut handed = handed(&chain);
    handed.tip.height = handed.at.height + MOST_BURIED + 1;
    let refused = check_buried(
        &handed.at,
        &handed.tip,
        &handed.before_at,
        &handed.buried,
        &handed.recent,
        &params(),
    );
    assert!(
        matches!(refused, Err(HandoverError::BuriedRunWrongLength { .. })),
        "and said {refused:?}"
    );
}

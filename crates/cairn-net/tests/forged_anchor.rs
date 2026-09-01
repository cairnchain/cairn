//! Whether the work a newcomer weighs actually belongs to the tip it adopts.
//!
//! The join is two exchanges. `check_start` weighs a tip by opening headers
//! drawn from the work behind it; `accept` then takes a ledger anchored to
//! that tip. Everything the newcomer commits to rests on the tip being the end
//! of the chain whose work was opened.
//!
//! These tests ask whether anything actually ties the two together.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::forest::Forest;
use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::Note;
use cairn_ledger::sampling::{
    check_start, draw, seed_of, work_before, Sample, SampledStart, StartError, SAMPLES,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
/// Shallow, so a test does not have to mine a thousand blocks to reach an
/// anchor. Nothing here turns on the depth.
const BURIAL: u64 = 8;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(BURIAL)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain kept the way a running node keeps one, plus the ledger at every
/// height so a test can reach back without undo records.
struct Chain {
    state: LedgerState,
    past: Vec<LedgerState>,
    blocks: Vec<Block>,
    headers: Vec<BlockHeader>,
    history: Archive,
    clock: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
            headers: Vec::new(),
            history: Archive::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) {
        let params = params();
        let height = self.state.next_height().unwrap();
        // Ten times the target, so the retarget keeps the difficulty on its
        // floor and every header in these tests is worth exactly one.
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&self.state, coinbase, Vec::new(), &params, self.clock, 0).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        self.past.push(self.state.clone());
        self.history.add(header_leaf(&block.header.id())).unwrap();
        self.headers.push(block.header);
        self.blocks.push(block);
    }

    fn run(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner);
        }
    }

    fn tip(&self) -> BlockHeader {
        *self.headers.last().unwrap()
    }
}

/// The position in a forest of one-work headers that covers a drawn value.
///
/// With every header at the difficulty floor, the header at height `h` spans
/// exactly `[h, h + 1)`, so the value drawn *is* the position that answers it.
fn covering_position(headers: &[BlockHeader], work: u128) -> usize {
    headers
        .iter()
        .position(|header| {
            let before = header.total_work - u128::from(header.difficulty);
            before <= work && header.total_work > work
        })
        .unwrap()
}

/// **The weighing is forgeable at the cost of one hash.**
///
/// `check_start` never asks that the tip stands at the end of the headers it
/// opens. It asks that the tip commits to a forest, that the opened headers
/// sit in that forest, and that each carries real work covering its drawn
/// value. Every one of those is satisfied by a forest of somebody else's
/// headers.
///
/// So an attacker took the honest chain's headers, which are public and served
/// by `GetHeaders` to anyone who asks, built a forest of them, mined one header
/// at the difficulty floor to sit on top, and claimed the honest chain's whole
/// weight for a tip that was on no chain at all.
///
/// The weighing now asks the tip to open the header it was built on, in its
/// own history, at the height below it, carrying the work its total leaves
/// over. A tip mined on nothing has no such header to give, and mining one
/// that does means mining on the chain it claims.
#[test]
fn a_tip_on_no_chain_has_no_parent_to_open() {
    let honest_miner = wallet(1);
    let mut honest = Chain::new();
    honest.run(&honest_miner, 2_100);

    let real_tip = honest.tip();
    assert_eq!(real_tip.difficulty, 1, "the floor, so work equals height");

    // Everything an attacker needs, and nothing it could not download.
    let stolen: Vec<BlockHeader> = honest.headers.clone();

    // Its own forest over those headers: the same leaves, so the same
    // commitment the honest chain has, but it is the attacker that decides
    // which header sits on top of it.
    let mut forest = Archive::new();
    for header in &stolen {
        forest.add(header_leaf(&header.id())).unwrap();
    }

    // One header, at the difficulty floor, which every hash satisfies. It
    // names the attacker's own state root and its own parent; nothing in the
    // weighing looks at either.
    let forged_tip = BlockHeader {
        version: real_tip.version,
        network: real_tip.network,
        height: stolen.len() as u64,
        previous: cairn_primitives::Hash32::from_bytes([0xAB; 32]),
        transactions_root: cairn_primitives::Hash32::from_bytes([0xCD; 32]),
        state_root: cairn_primitives::Hash32::from_bytes([0xEF; 32]),
        history: forest.commitment(),
        timestamp: real_tip.timestamp + 600,
        difficulty: 1,
        // One more than the honest chain carries, which is all it takes to be
        // the heaviest claim a newcomer hears.
        total_work: real_tip.total_work + 1,
        nonce: 0,
    };

    // The draws, which the attacker can compute exactly as the victim will.
    let wanted = draw(
        seed_of(&forged_tip),
        SAMPLES,
        work_before(&forged_tip),
        forged_tip.height,
    );
    let roots: Forest = forest.forest().roots_only();
    let samples: Vec<Sample> = wanted
        .iter()
        .map(|work| {
            let position = covering_position(&stolen, *work);
            Sample {
                header: stolen[position],
                proof: forest.prove_in(position as u64, forged_tip.height).unwrap(),
            }
        })
        .collect();

    // The best parent the forger has is the honest tip, which really does sit
    // at the height below and really is in the forest. It is not the header
    // its tip names, because its tip was mined on nothing.
    let start = SampledStart {
        tip: forged_tip,
        parent: Some(Sample {
            header: real_tip,
            proof: forest.prove_in(real_tip.height, forged_tip.height).unwrap(),
        }),
        history: roots,
        samples,
    };

    let refused = check_start(&start, SAMPLES);
    assert!(
        matches!(refused, Err(StartError::ParentNotTheTipsOwn)),
        "a tip standing on nothing has no parent to open, and it said {refused:?}"
    );
}

/// **And the ledger hung off that tip could be anything.**
///
/// `accept` ties the ledger's own header `at` to the tip through the tip's
/// header forest. That forest is the attacker's, so the tie holds and proves
/// nothing: `at` comes from a private chain the attacker mined for itself at
/// the difficulty floor, with a coinbase paying whoever it likes, and the
/// forest that vouches for it is the honest chain's headers with one leaf
/// swapped.
///
/// The swap is invisible to the weighing, because a header at the difficulty
/// floor spans one unit of work and the header it displaces spanned the same
/// one.
#[test]
fn an_invented_ledger_cannot_borrow_a_weight_it_did_not_earn() {
    let honest_miner = wallet(1);
    let mut honest = Chain::new();
    honest.run(&honest_miner, 2_100);
    let real_tip = honest.tip();

    // The attacker's own chain, mined for nothing at the difficulty floor.
    // Its ledger pays the attacker every coinbase there has ever been.
    let attacker = wallet(9);
    let mut private = Chain::new();
    private.run(&attacker, 40);

    // The anchor: a genuine header of the attacker's private chain, with the
    // genuine ledger that belongs to it. Everything about it checks out,
    // against the wrong chain.
    let anchor_height = 20usize;
    let at = private.headers[anchor_height];
    let anchor_state = &private.past[anchor_height];
    let recent: Vec<BlockHeader> = private.headers[..=anchor_height].to_vec();

    // The forged forest: the honest chain's leaves, with the attacker's anchor
    // put in at its own height. Both headers sit at the difficulty floor and
    // both are the same number of blocks in, so both state the same total
    // work and cover the same unit of it. Nothing the draw can ask notices.
    let mut leaves: Vec<BlockHeader> = honest.headers.clone();
    assert_eq!(
        leaves[anchor_height].total_work, at.total_work,
        "the displaced header spanned the work the anchor now spans"
    );
    leaves[anchor_height] = at;

    let mut forest = Archive::new();
    for header in &leaves {
        forest.add(header_leaf(&header.id())).unwrap();
    }

    let forged_tip = BlockHeader {
        version: real_tip.version,
        network: real_tip.network,
        height: leaves.len() as u64,
        previous: cairn_primitives::Hash32::from_bytes([0xAB; 32]),
        transactions_root: cairn_primitives::Hash32::from_bytes([0xCD; 32]),
        state_root: cairn_primitives::Hash32::from_bytes([0xEF; 32]),
        history: forest.commitment(),
        timestamp: real_tip.timestamp + 600,
        difficulty: 1,
        total_work: real_tip.total_work + 1,
        nonce: 0,
    };

    // The weighing first, exactly as the victim runs it.
    let wanted = draw(
        seed_of(&forged_tip),
        SAMPLES,
        work_before(&forged_tip),
        forged_tip.height,
    );
    let samples: Vec<Sample> = wanted
        .iter()
        .map(|work| {
            let position = covering_position(&leaves, *work);
            Sample {
                header: leaves[position],
                proof: forest.prove_in(position as u64, forged_tip.height).unwrap(),
            }
        })
        .collect();
    let start = SampledStart {
        tip: forged_tip,
        parent: Some(Sample {
            header: leaves[leaves.len() - 1],
            proof: forest
                .prove_in((leaves.len() - 1) as u64, forged_tip.height)
                .unwrap(),
        }),
        history: forest.forest().roots_only(),
        samples,
    };
    let refused = check_start(&start, SAMPLES);
    assert!(
        matches!(refused, Err(StartError::ParentNotTheTipsOwn)),
        "the weighing now asks the tip for its own parent, and it said {refused:?}"
    );
    // And the ledger under it, offered anyway, is refused a second time and
    // for a different reason. The run between the anchor and the tip is the
    // best the forger has, the honest chain's own headers, and it does not
    // begin where the anchor ends: the forger cannot mine a bridge from a
    // header of its private chain to a tip on the honest one.
    let handover = Handover {
        at,
        tip: forged_tip,
        buried: leaves[anchor_height + 1..]
            .iter()
            .copied()
            .chain(std::iter::once(forged_tip))
            .collect(),
        tip_history: forest.forest().roots_only(),
        anchor: forest
            .prove_in(anchor_height as u64, forged_tip.height)
            .unwrap(),
        hot: anchor_state.hot_notes().collect(),
        cold: anchor_state.cold_roots(),
        grace: anchor_state.grace_window(),
        grace_proofs: anchor_state
            .grace_window()
            .iter()
            .flatten()
            .filter_map(|(_, position, _)| {
                Some((*position, anchor_state.cold().proof_of(*position)?))
            })
            .collect(),
        headers: anchor_state.headers_before_tip(),
        recent: recent.clone(),
    };

    let refused = accept(&handover, &params());
    assert!(
        matches!(refused, Err(HandoverError::BuriedRunNotConsecutive { .. })),
        "the invented ledger is refused, and it said {refused:?}"
    );
}

/// **The general form, and what closed it.**
///
/// Nothing of the honest chain had to be disturbed. The forest is the
/// attacker's, so it could simply be longer: the honest leaves first, then the
/// anchor, then enough padding to satisfy the burial. The padding was not
/// headers at all, just thirty-two bytes of nothing.
///
/// The draw never reached any of it. `levels_for` stops the halving
/// `SHALLOWEST` blocks from the tip, so the top slice of the claimed work was
/// never opened, and every draw that was made landed in the honest headers,
/// which answered it perfectly. There was no probability left in it to argue
/// about: the forgery was deterministic.
///
/// What closed it is that height and work are no longer separate claims. The
/// difficulty may fall by at most a fixed factor per block and never below the
/// floor, so the blocks between two headers whose place is established have a
/// least amount of work, and a thousand of them cannot be worth one hash. The
/// forgery is now refused before the ledger under it is ever looked at.
#[test]
fn padding_a_forest_out_to_the_burial_depth_is_refused() {
    let honest_miner = wallet(1);
    let mut honest = Chain::new();
    honest.run(&honest_miner, 2_100);
    let real_tip = honest.tip();

    // The attacker's private chain, run out to the height it wants its anchor
    // to claim. Empty blocks at the difficulty floor: no work, and its own
    // coinbase every time.
    let attacker = wallet(9);
    let mut private = Chain::new();
    private.run(&attacker, 2_101);

    let anchor_height = honest.headers.len(); // 2100, one past the honest tip
    let at = private.headers[anchor_height];
    assert_eq!(at.height, anchor_height as u64);
    let anchor_state = &private.past[anchor_height];
    let recent: Vec<BlockHeader> = private.headers[anchor_height + 1 - 91..=anchor_height].to_vec();

    // Honest leaves, then the anchor, then padding that is not a header.
    let mut forest = Archive::new();
    for header in &honest.headers {
        forest.add(header_leaf(&header.id())).unwrap();
    }
    forest.add(header_leaf(&at.id())).unwrap();
    for filler in 0..BURIAL {
        forest
            .add(cairn_primitives::Hash32::from_bytes([filler as u8; 32]))
            .unwrap();
    }

    // A real header of its own to sit directly under the tip, so that the tip
    // has a parent to open. At the difficulty floor every hash satisfies it,
    // so this costs the forger nothing either.
    let stand_on = BlockHeader {
        version: real_tip.version,
        network: real_tip.network,
        height: forest.len(),
        previous: cairn_primitives::Hash32::from_bytes([0x11; 32]),
        transactions_root: cairn_primitives::Hash32::from_bytes([0x22; 32]),
        state_root: cairn_primitives::Hash32::from_bytes([0x33; 32]),
        history: cairn_primitives::Hash32::from_bytes([0x44; 32]),
        timestamp: real_tip.timestamp + 600,
        difficulty: 1,
        total_work: real_tip.total_work,
        nonce: 0,
    };
    forest.add(header_leaf(&stand_on.id())).unwrap();

    let forged_tip = BlockHeader {
        version: real_tip.version,
        network: real_tip.network,
        height: forest.len(),
        previous: stand_on.id(),
        transactions_root: cairn_primitives::Hash32::from_bytes([0xCD; 32]),
        state_root: cairn_primitives::Hash32::from_bytes([0xEF; 32]),
        history: forest.commitment(),
        timestamp: real_tip.timestamp + 1_200,
        difficulty: 1,
        total_work: real_tip.total_work + 1,
        nonce: 0,
    };
    assert!(
        at.height + BURIAL <= forged_tip.height,
        "buried as deep as the rules ask"
    );

    let wanted = draw(
        seed_of(&forged_tip),
        SAMPLES,
        work_before(&forged_tip),
        forged_tip.height,
    );
    assert!(
        wanted.iter().all(|work| *work < real_tip.total_work),
        "every draw lands inside the honest chain's work, so every one of them \
         is answered by an honest header"
    );
    let samples: Vec<Sample> = wanted
        .iter()
        .map(|work| {
            let position = covering_position(&honest.headers, *work);
            Sample {
                header: honest.headers[position],
                proof: forest.prove_in(position as u64, forged_tip.height).unwrap(),
            }
        })
        .collect();
    let start = SampledStart {
        tip: forged_tip,
        parent: Some(Sample {
            header: stand_on,
            proof: forest.prove_in(stand_on.height, forged_tip.height).unwrap(),
        }),
        history: forest.forest().roots_only(),
        samples,
    };
    // Every draw is still answered perfectly, which is the point: the samples
    // were never the weak part. What refuses the forgery is the stretch of
    // chain between the last header opened and the tip, which states almost no
    // work for a great many blocks.
    let refused = check_start(&start, SAMPLES);
    assert!(
        matches!(refused, Err(StartError::BlocksWorthLessThanTheyCost { .. })),
        "the padding cost nothing and must not weigh anything, but the weighing said {refused:?}"
    );

    // And so the ledger hung off it is never reached. Kept here so the test
    // still names what was at stake: this is the anchor a newcomer would have
    // adopted, holding a ledger the attacker wrote for itself.
    let _ = (anchor_state, &recent);
}

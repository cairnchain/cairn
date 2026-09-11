//! AUDIT: which check refuses a forgery, and whether the draw is one of them.
//!
//! `examples/adversarial_placement` corroborates the sampling bound by building
//! forgeries and putting them through `check_start`. For eighteen rounds it
//! corroborated nothing. It re-mined every header above the fork, which changes
//! their identifiers, and then left every `previous` link naming the header that
//! identifier had replaced. The run it presented was not a chain, so
//! `check_the_parent` refused it before the draw was consulted, and the verdict
//! it recorded was `check_start(..).is_err()`, which counts that refusal as a
//! forgery the draw had caught. Its table read 100 per cent caught in every row,
//! including two rows where no draw could reach the invented work at all, and
//! the line under the table said the model and the measurement agreed.
//!
//! The example is rebuilt. This is the part of it that belongs in a suite: fast,
//! and pinning the three things that went wrong so that none of them can come
//! back quietly.
//!
//! Counted rather than timed throughout. Nothing here measures a duration.

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
use cairn_ledger::note::Note;
use cairn_ledger::pow::{meets_target, work_of, DIFFICULTY_WINDOW};
use cairn_ledger::sampling::{
    check_start, draw, levels_of, seed_of, work_before, Sample, SampledStart, StartError,
    SHALLOWEST,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
/// Draws per tip, and tips per forgery. Small: what is being pinned is which
/// check answers, not a rate to three figures.
const COUNT: usize = 32;
const TIPS: usize = 24;

/// Long enough that the draw spreads over two halvings rather than one.
///
/// Below `SHALLOWEST` blocks the draw has a single level, and a single level
/// means every drawn value lands in the oldest half of the work and a fork
/// anywhere above that is invisible to the draw whatever the gap. The old
/// example ran on 600 blocks, which is why two of its rows predicted that
/// nothing could be caught while the table beside them read 100 per cent.
const HEIGHT: u64 = 3 * SHALLOWEST;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// An honest chain, mined block by block under the real rules.
fn build(count: u64) -> Vec<BlockHeader> {
    let params = params();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let mut state = LedgerState::new();
    let mut headers = Vec::with_capacity(usize::try_from(count).unwrap());
    let mut clock = 1_000_000u64;

    for _ in 0..count {
        let height = state.next_height().unwrap();
        clock += params.target_block_time;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        headers.push(block.header);
    }
    headers
}

/// A chain a forger presents, and the work no block of it spans.
struct Forgery {
    shown: Vec<BlockHeader>,
    before_tip: Archive,
    invented: (u128, u128),
}

/// Builds the forgery: the honest history up to `fork`, then a run of its own
/// that states `gap` more work than it did.
///
/// `relink` is the whole point of this file. True rebuilds the links and the
/// commitments in order, which is what a forger has to do and what makes the
/// run a chain. False leaves them naming the headers the re-mining replaced,
/// which is what the example used to hand over.
fn forge(honest: &[BlockHeader], fork: u64, gap: u128, relink: bool) -> Forgery {
    let last = honest.len() - 1;
    let mut shown: Vec<BlockHeader> = Vec::with_capacity(honest.len());
    let mut before_tip = Archive::new();

    for (index, header) in honest.iter().enumerate() {
        let mut copy = *header;
        if index as u64 > fork {
            let below = *shown.last().unwrap();
            if relink {
                copy.previous = below.id();
                copy.history = before_tip.commitment();
            } else if index == last {
                // What the old harness did, and all it did: the tip's own
                // commitment, so that the forgery gets as far as the checks
                // that read the chain rather than being turned away at the
                // door. Every header under it keeps the link and the
                // commitment of the header its re-mining replaced.
                copy.history = before_tip.commitment();
            }
            copy.total_work = below.total_work + work_of(copy.difficulty);
            if index as u64 == fork + 1 {
                copy.total_work += gap;
            }
            let block = cairn_ledger::Block {
                header: copy,
                coinbase: CoinbaseTransaction::new(copy.height, Vec::new()),
                transfers: Vec::new(),
            };
            copy = mine_block(block, ATTEMPTS).unwrap().header;
        }
        shown.push(copy);
        // Everything but the tip, since a tip is not in its own history.
        if index < last {
            before_tip.add(header_leaf(&copy.id()));
        }
    }

    let at_fork = shown[usize::try_from(fork).unwrap()].total_work;
    Forgery {
        shown,
        before_tip,
        invented: (at_fork, at_fork + gap),
    }
}

impl Forgery {
    /// What the forger hands over under a tip of its own choosing.
    ///
    /// The run ends at the tip actually presented. Ending it at the header the
    /// tip was ground from is a mismatched run, refused for the mismatch, and
    /// counted by the old harness as a forgery caught.
    fn present(&self, tip: BlockHeader, count: usize, reach_up: bool) -> SampledStart {
        let last = self.shown.len() - 1;
        let samples: Vec<Sample> = draw(
            seed_of(&tip),
            count,
            work_before(&tip),
            levels_of(&tip, &params()),
        )
        .into_iter()
        .map(|work| {
            // The block spanning the draw where there is one. Where the
            // draw fell in invented work there is none, and the forgery has
            // two neighbours to choose between: the block below the gap,
            // whose total falls short of the value, and the block above it,
            // whose own work starts past the value. `reach_up` picks which,
            // because the check refuses each for a different half of one
            // comparison and a test that only ever offers one of them
            // measures half the rule.
            let above = self.shown[..last]
                .partition_point(|header| header.total_work <= work)
                .min(last - 1);
            let spans = work_before(&self.shown[above]) <= work;
            let at = if spans || reach_up {
                above
            } else {
                above.saturating_sub(1)
            };
            Sample {
                header: self.shown[at],
                proof: self.before_tip.prove(at as u64).unwrap(),
            }
        })
        .collect();

        let deepest = samples
            .iter()
            .map(|sample: &Sample| sample.header.height)
            .max()
            .unwrap_or(0);
        let from = usize::try_from(deepest.saturating_sub(DIFFICULTY_WINDOW as u64)).unwrap();
        let mut tail = self.shown[from..last].to_vec();
        tail.push(tip);

        SampledStart {
            tip,
            tail,
            parent: Some(Sample {
                header: self.shown[last - 1],
                proof: self.before_tip.prove(last as u64 - 1).unwrap(),
            }),
            history: self.before_tip.forest().roots_only(),
            samples,
        }
    }

    /// Whether the draw alone catches this tip: whether some drawn value lands
    /// in work no block of the forgery spans. Worked out from the draw and
    /// nothing else, so that it can be held against what the check did.
    fn the_draw_reaches(&self, tip: &BlockHeader, count: usize) -> bool {
        let (from, to) = self.invented;
        draw(
            seed_of(tip),
            count,
            work_before(tip),
            levels_of(tip, &params()),
        )
        .into_iter()
        .any(|work| work >= from && work < to)
    }
}

/// Tips over the same chain, each drawing a different set of questions.
///
/// The seed is the tip's own identifier, so a forger buys another tip and asks
/// again. Rolling the nonce past the first solution is that purchase exactly:
/// one tip's work per attempt, and nothing below the tip changes.
fn ground_tips(tip: &BlockHeader, attempts: usize) -> Vec<BlockHeader> {
    let mut tips = Vec::with_capacity(attempts);
    let mut candidate = *tip;
    let mut nonce = tip.nonce;
    while tips.len() < attempts {
        candidate.nonce = nonce;
        if meets_target(&candidate.id(), candidate.difficulty) {
            tips.push(candidate);
        }
        nonce += 1;
    }
    tips
}

/// The harness has to be able to build something the check accepts, or a table
/// of refusals says only that it cannot build a chain.
///
/// Rebuilding with nothing forged has to give back the chain it rebuilt, header
/// for header, and every tip ground over it has to be accepted.
#[test]
fn a_rebuild_with_nothing_forged_is_the_chain_it_rebuilt_and_is_accepted() {
    let honest = build(HEIGHT);
    let control = forge(&honest, 0, 0, true);
    assert_eq!(
        control.shown, honest,
        "an unforged rebuild came back as a different chain"
    );

    for tip in ground_tips(control.shown.last().unwrap(), TIPS) {
        for reach_up in [false, true] {
            let start = control.present(tip, COUNT, reach_up);
            check_start(&start, COUNT, NOW, &params()).expect("the control has to be accepted");
        }
    }
}

/// The mistake itself, pinned so that it cannot come back quietly.
///
/// A forgery whose links are not rebuilt is refused for its links, whatever the
/// draw does and wherever the lie was put. Every refusal the old example counted
/// as a forgery caught by the draw was this one.
#[test]
fn a_forgery_whose_links_are_not_rebuilt_is_refused_for_its_links() {
    let honest = build(HEIGHT);
    let tip_height = honest.last().unwrap().height;
    // Deep enough that the draw cannot reach the lie at all, so that any
    // refusal here is plainly not the draw's doing.
    let fork = tip_height - 400;

    let unlinked = forge(&honest, fork, 64, false);
    for tip in ground_tips(unlinked.shown.last().unwrap(), TIPS) {
        assert!(
            !unlinked.the_draw_reaches(&tip, COUNT),
            "this fork was meant to be out of the draw's reach"
        );
        let start = unlinked.present(tip, COUNT, true);
        let refusal = check_start(&start, COUNT, NOW, &params());
        assert!(
            matches!(refusal, Err(StartError::ParentNotTheTipsOwn)),
            "a forgery with stale links was refused for {refusal:?}"
        );
    }
}

/// What the draw does, told apart from what the other checks do.
///
/// Two forgeries, both built the way a forger would have to build them, and
/// both refused. One is refused by the draw and one is not, and the difference
/// is the only thing the sampling bound is about.
#[test]
fn the_draw_refuses_a_lie_it_reaches_and_never_one_it_does_not() {
    let honest = build(HEIGHT);
    let tip_height = honest.last().unwrap().height;

    // Out of reach. The draw stops resolving `SHALLOWEST` blocks from the tip,
    // and on a chain this long that band is the whole of the top level. What
    // covers it is the walk up to the tip, not the draw.
    let shallow = forge(&honest, tip_height - 400, 64, true);
    let mut by_the_run = 0usize;
    for tip in ground_tips(shallow.shown.last().unwrap(), TIPS) {
        assert!(
            !shallow.the_draw_reaches(&tip, COUNT),
            "the draw should not reach a fork inside the band it does not resolve"
        );
        let refusal = check_start(&shallow.present(tip, COUNT, true), COUNT, NOW, &params());
        assert!(
            !matches!(refusal, Err(StartError::WrongPlace { .. })),
            "the draw refused a lie it cannot see"
        );
        if matches!(refusal, Err(StartError::TailWorkDoesNotAddUp { .. })) {
            by_the_run += 1;
        }
    }
    assert_eq!(
        by_the_run, TIPS,
        "the run up to the tip is what covers this band, and it did not"
    );

    // In reach, and the model and the check have to agree tip for tip: the draw
    // refuses exactly those tips whose drawn values land in work no block
    // spans, and no others.
    let deep = forge(&honest, tip_height - 2_000, 200, true);
    let mut caught = 0usize;
    let mut through = 0usize;
    for tip in ground_tips(deep.shown.last().unwrap(), TIPS) {
        let reaches = deep.the_draw_reaches(&tip, COUNT);
        // Both neighbours, because a forger opens whichever gets through and
        // the check refuses each on a different half of the same comparison.
        for reach_up in [false, true] {
            let refusal = check_start(&deep.present(tip, COUNT, reach_up), COUNT, NOW, &params());
            assert_eq!(
                reaches,
                matches!(refusal, Err(StartError::WrongPlace { .. })),
                "reaching {} the gap, the draw said {reaches} and the check said {refusal:?}",
                if reach_up { "above" } else { "below" }
            );
            if !reaches && refusal.is_ok() && reach_up {
                through += 1;
            }
        }
        if reaches {
            caught += 1;
        }
    }
    // Both branches exercised, or the agreement above was tested on one of
    // them. The forger grinding a tip is what makes the second column real: it
    // buys another seed at the price of another tip.
    assert!(caught > 0, "no tip was caught by the draw");
    assert!(through > 0, "no tip got through, so grinding buys nothing");
    println!(
        "\n  a lie of 200 work at 2000 blocks deep: {caught} of {TIPS} tips caught by the\n  \
         draw, {through} through. A forger that grinds tips asks again for the price of\n  \
         a tip, which is the tip's own work.\n"
    );
}

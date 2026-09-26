//! The two largest things a stranger sends, bent, and taken past the decoder.
//!
//! A node that joins is handed a ledger of about twelve kilobytes and, before
//! it, a weighing of the chain the ledger hangs from. Both are bytes a stranger
//! chose, and both go on from the decoder into checks that rebuild a whole
//! ledger (`handover::accept`) and weigh a whole chain (`check_start`). Every
//! other campaign in the workspace stops at the decoder.
//!
//! What is held is the question those checks exist to answer: a bent one is
//! refused, or it is the one it was bent from. A bent ledger that is taken
//! and differs from the genuine one differs in something the checks do not
//! hold the sender to, and a newcomer would build its node on it.
//!
//! This was a fixed loop in `fuzz.rs`: four thousand cases, one to three
//! bytes overwritten, on a seed that never moved, and nothing asserted about
//! what was taken. It counted the ledgers `accept` took and threw the count
//! away, beside a comment saying that taking a bent one "would be a defect
//! this cannot see". And because it used none of `cairn_fuzz::Campaign`, the
//! nightly run, which varies the seed and runs for a budget, had nothing to
//! vary. Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::SecretKey;
use cairn_fuzz::{mutate, Campaign};
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::Note;
use cairn_ledger::sampling::{check_start_with_count, open_start, SampledStart};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::{Decode, Encode};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_burial(8)
}

/// How far one kind of answer got.
#[derive(Debug, Default)]
struct Reached {
    /// Bent and handed to the decoder.
    fed: usize,
    /// Decoded, and so handed on to the check.
    checked: usize,
    /// Taken by the check.
    taken: usize,
}

impl Reached {
    fn report(&self, what: &str) {
        eprintln!(
            "{what}: {} bent, {} decoded and checked, {} taken",
            self.fed, self.checked, self.taken
        );
    }

    /// At least one in a thousand of what was bent got as far as the check.
    ///
    /// Measured on the fixed loop this replaced: 87 to 98 per cent of the
    /// ledgers decoded. A campaign whose bends all die at the decoder asks
    /// the check nothing and passes.
    fn reached_the_check(&self, what: &str) {
        assert!(self.fed > 0, "no {what} was ever bent");
        assert!(
            self.checked.saturating_mul(1_000) >= self.fed,
            "{} of {} bent {what}s decoded, so the check behind the decoder was \
             hardly asked anything",
            self.checked,
            self.fed
        );
    }
}

/// A bent ledger or weighing is refused, or it is the one it was bent from.
///
/// The ledger and the weighing are bent by every operator `cairn_fuzz` has,
/// with the other as material to splice from. What decodes is handed to the
/// check a joining node runs on it, at the count of samples the genuine
/// weighing was built for (sixteen, so a case costs milliseconds where a node
/// asks `SAMPLES`), fixed rather than read off the bent weighing. What the
/// check takes has to encode as the genuine one does, but for the one field
/// this network gives nothing to check against: see the weighing's arm.
///
/// Nothing asked this, so a check that took a bent ledger passed: the loop
/// this replaced counted what `accept` took and never looked at it.
#[test]
fn a_bent_ledger_or_weighing_is_refused_or_is_the_one_it_was_bent_from() {
    let campaign = Campaign::named("net: bent join answers");
    let params = params();
    let (handover, start) = valid_join_answers();
    let count = start.samples.len();
    // An unbent one has to pass, or the campaign proves nothing about the
    // checks it is bending.
    assert!(
        accept(&handover, &params).is_ok(),
        "the ledger these bends start from is not one that would be taken"
    );
    assert!(
        check_start_with_count(&start, count, NOW, &params).is_ok(),
        "the weighing these bends start from is not one that would be taken"
    );
    let ledger = handover.encode();
    let weighing = start.encode();
    let corpus = [ledger.clone(), weighing.clone()];

    let mut ledgers = Reached::default();
    let mut weighings = Reached::default();
    let seed = campaign.seed();
    let ran = campaign.run(2_000, |case, rng| {
        if rng.bool() {
            let bytes = mutate(rng, &ledger, &corpus);
            ledgers.fed += 1;
            let Ok(bent) = Handover::decode(&bytes) else {
                return;
            };
            ledgers.checked += 1;
            if accept(&bent, &params).is_ok() {
                ledgers.taken += 1;
                assert!(
                    bent.encode() == ledger,
                    "case {case} of seed {seed:#x}: a bent ledger was taken and is not the \
                     one it was bent from, so `accept` does not hold the sender to \
                     something it changed"
                );
            }
        } else {
            let bytes = mutate(rng, &weighing, &corpus);
            weighings.fed += 1;
            let Ok(bent) = SampledStart::decode(&bytes) else {
                return;
            };
            weighings.checked += 1;
            if check_start_with_count(&bent, count, NOW, &params).is_ok() {
                weighings.taken += 1;
                // Save for the proof that the chain starts from the block the
                // network pins. This network pins none, so that proof is
                // checked against nothing (`check_the_genesis` says so) and
                // is the one field a taken weighing may carry bent.
                let mut compared = bent.clone();
                compared.genesis = start.genesis.clone();
                assert!(
                    compared.encode() == weighing,
                    "case {case} of seed {seed:#x}: a bent weighing was taken and is not \
                     the one it was bent from, so `check_start` does not hold the sender \
                     to something it changed"
                );
            }
        }
    });

    ledgers.report("net: bent ledgers");
    weighings.report("net: bent weighings");
    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    ledgers.reached_the_check("ledger");
    weighings.reached_the_check("weighing");
}

/// A ledger a newcomer would be handed, and the weighing that comes before it.
///
/// Mined once per test, off the case path, so the budget is spent on the
/// checks and not on nonces.
fn valid_join_answers() -> (Handover, SampledStart) {
    let params = params();
    let miner = SecretKey::from_bytes(&[5; 32]);
    let mut state = LedgerState::new();
    let mut archive = cairn_accumulator::Archive::new();
    let mut headers = Vec::new();
    let mut past = Vec::new();
    let mut clock = 1_000u64;

    for _ in 0..40 {
        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &params, NOW).unwrap();
        past.push(state.clone());
        headers.push(block.header);
        archive.add(cairn_ledger::state::header_leaf(&block.header.id()));
    }

    let tip = *headers.last().unwrap();
    // The run of recent headers the difficulty rule reads, which a handover
    // has to carry in full or it is refused before anything else is looked at.
    let last = usize::try_from(tip.height - params.burial).unwrap();
    let from = (last + 1).saturating_sub(cairn_ledger::pow::RECENT_HEADERS);
    let recent = headers[from..=last].to_vec();
    // From below the tip, as any handover is: one at the tip is refused for
    // where it sits, which would make this campaign bend nothing.
    let anchor_height = tip.height - params.burial;
    let at = headers[usize::try_from(anchor_height).unwrap()];
    let handover = past[usize::try_from(anchor_height).unwrap()]
        .handover(
            at,
            tip,
            state.headers_before_tip(),
            archive
                .prove_in(anchor_height, tip.height)
                .expect("it can prove its own history"),
            headers[usize::try_from(anchor_height).unwrap() + 1..].to_vec(),
            recent,
        )
        .expect("a node can hand over what it holds");
    let start = open_start(
        &tip,
        state.headers_before_tip(),
        16,
        &params,
        |height| headers.get(usize::try_from(height).unwrap()).copied(),
        |height| archive.prove_in(height, tip.height),
    )
    .expect("an archivist can weigh its own chain");
    (handover, start)
}

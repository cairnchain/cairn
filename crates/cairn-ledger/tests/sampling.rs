//! Deciding which chain is heaviest without downloading any of them.

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
use cairn_ledger::pow::work_of;
use cairn_ledger::sampling::{
    check_start, covering, draw, open_start, seed_of, work_before, Sample, SampledStart, StartError,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
/// Long enough that the draw has somewhere to land at every level it reaches,
/// short enough that mining it is a second.
const HEIGHT: u64 = 300;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// A chain, and everything someone who kept it can answer with.
struct Keeper {
    headers: Vec<BlockHeader>,
    /// The header forest as it stood before the tip, which is what the tip's
    /// history field commits to.
    before_tip: Archive,
}

impl Keeper {
    /// Mines `count` blocks and keeps every header.
    fn build(count: u64) -> Self {
        let params = params();
        let miner = SecretKey::from_bytes(&[1; 32]);
        let mut state = LedgerState::new();
        let mut headers = Vec::with_capacity(usize::try_from(count).unwrap());
        let mut clock = 1_000u64;

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
            headers.push(block.header);
        }

        // Everything but the tip, which is what the tip commits to.
        let mut before_tip = Archive::new();
        for header in headers.iter().take(headers.len() - 1) {
            before_tip.add(header_leaf(&header.id()));
        }
        Self {
            headers,
            before_tip,
        }
    }

    fn tip(&self) -> BlockHeader {
        *self.headers.last().unwrap()
    }

    /// Everything a verifier's draw would ask about, in the order it asked.
    fn open(&self, count: usize) -> SampledStart {
        let tip = self.tip();
        let ledger: Vec<(u64, u128, u64)> = self
            .headers
            .iter()
            .rev()
            .map(|header| (header.height, header.total_work, header.difficulty))
            .collect();

        let samples = draw(seed_of(&tip), count, work_before(&tip), tip.height)
            .into_iter()
            .map(|work| {
                let height = covering(&ledger, work).expect("some block spans it");
                let header = self.headers[usize::try_from(height).unwrap()];
                let proof = self
                    .before_tip
                    .prove(height)
                    .expect("a keeper can prove what it kept");
                Sample { header, proof }
            })
            .collect();

        SampledStart {
            tip,
            history: self.before_tip.forest().roots_only(),
            samples,
        }
    }
}

/// A chain that was really made says so, and is believed.
#[test]
fn an_honest_chain_answers_every_question_asked_of_it() {
    let keeper = Keeper::build(HEIGHT);
    let start = keeper.open(64);

    let weighed = check_start(&start, 64).expect("an honest chain checks out");
    assert_eq!(weighed.height, HEIGHT - 1);
    assert_eq!(weighed.total_work, keeper.tip().total_work);
    assert_eq!(weighed.tip, keeper.tip().id());
}

/// What the whole thing is for: a chain claiming work it never did.
///
/// The tip is rewritten to state far more work than the chain behind it
/// carries. Every header under it is untouched and honest, so each one opens
/// correctly and proves it sits where it says. What gives the lie away is the
/// question the draw asks: for work inside the invented range, there is no
/// block that spans it, and the forger has nothing to open.
#[test]
fn a_tip_that_overstates_its_work_is_caught() {
    let keeper = Keeper::build(HEIGHT);
    let honest = keeper.tip();

    let mut forged = honest;
    forged.total_work = honest.total_work * 4;
    // Mined again, so the lie carries the work a tip has to carry. An attacker
    // who could not do even this could not offer a tip at all.
    let block = cairn_ledger::Block {
        header: forged,
        coinbase: CoinbaseTransaction::new(forged.height, Vec::new()),
        transfers: Vec::new(),
    };
    let forged = mine_block(block, ATTEMPTS).unwrap().header;

    // The forger answers as best it can: for each drawn value it opens the
    // block that spans it if there is one, and its own tip otherwise.
    let ledger: Vec<(u64, u128, u64)> = keeper
        .headers
        .iter()
        .rev()
        .map(|header| (header.height, header.total_work, header.difficulty))
        .collect();
    let samples = draw(seed_of(&forged), 64, work_before(&forged), forged.height)
        .into_iter()
        .map(|work| {
            let height = covering(&ledger, work).unwrap_or(HEIGHT - 2);
            let header = keeper.headers[usize::try_from(height).unwrap()];
            let proof = keeper.before_tip.prove(height).unwrap();
            Sample { header, proof }
        })
        .collect();

    let start = SampledStart {
        tip: forged,
        history: keeper.before_tip.forest().roots_only(),
        samples,
    };

    assert!(
        matches!(check_start(&start, 64), Err(StartError::WrongPlace { .. })),
        "a tip claiming four times its work should not pass"
    );
}

/// A chain that hands over a history of its own choosing.
#[test]
fn a_history_the_tip_does_not_commit_to_is_refused() {
    let keeper = Keeper::build(HEIGHT);
    let other = Keeper::build(HEIGHT / 2);

    let start = SampledStart {
        history: other.before_tip.forest().roots_only(),
        ..keeper.open(16)
    };
    assert_eq!(
        check_start(&start, 16),
        Err(StartError::HistoryMismatch),
        "the tip commits to its history, so a different one is not it"
    );
}

/// A header that was never in this chain, however real it is elsewhere.
#[test]
fn a_header_from_another_chain_is_refused() {
    let keeper = Keeper::build(HEIGHT);
    let other = Keeper::build(HEIGHT);

    let mut start = keeper.open(16);
    // A real header, mined for real, from a chain that is not this one.
    start.samples[0].header = other.headers[10];

    assert!(
        matches!(
            check_start(&start, 16),
            Err(StartError::NotInHistory { .. })
        ),
        "being a real block somewhere is not being a block here"
    );
}

/// A header claiming work it never did, wherever it claims to sit.
///
/// Claiming a difficulty is claiming to have searched that many times for a
/// hash. Raising the number on a header that was found at an easier one leaves
/// a header whose own identifier does not meet what it claims, which anybody
/// can see for the cost of one hash.
#[test]
fn a_header_without_work_is_refused() {
    let keeper = Keeper::build(HEIGHT);
    let mut start = keeper.open(16);
    start.samples[0].header.difficulty = u64::MAX / 2;

    assert!(
        matches!(
            check_start(&start, 16),
            Err(StartError::SampleWithoutWork { .. })
        ),
        "a header that did no work proves nothing about a chain"
    );
}

/// Answering a different question than the one asked.
#[test]
fn a_header_that_does_not_span_the_work_drawn_is_refused() {
    let keeper = Keeper::build(HEIGHT);
    let mut start = keeper.open(16);

    // A real header from this very chain, at the wrong place for this draw.
    let wanted = draw(
        seed_of(&start.tip),
        16,
        work_before(&start.tip),
        start.tip.height,
    );
    let elsewhere = keeper
        .headers
        .iter()
        .find(|header| {
            let before = header.total_work.saturating_sub(work_of(header.difficulty));
            !(before <= wanted[0] && header.total_work > wanted[0])
        })
        .copied()
        .expect("some other header exists");
    start.samples[0].header = elsewhere;
    start.samples[0].proof = keeper.before_tip.prove(elsewhere.height).unwrap();

    assert!(
        matches!(check_start(&start, 16), Err(StartError::WrongPlace { .. })),
        "the answer has to be to the question that was asked"
    );
}

/// Fewer answers than questions.
#[test]
fn a_short_answer_is_refused() {
    let keeper = Keeper::build(HEIGHT);
    let mut start = keeper.open(16);
    start.samples.truncate(15);

    assert!(
        matches!(check_start(&start, 16), Err(StartError::WrongCount { .. })),
        "every question has to be answered"
    );
}

/// A tip that shrank its own history to make room for headers anywhere.
#[test]
fn a_history_shorter_than_the_tip_is_refused() {
    let keeper = Keeper::build(HEIGHT);
    let mut start = keeper.open(16);
    start.tip.height += 1;

    assert!(
        matches!(
            check_start(&start, 16),
            Err(StartError::HistoryWrongLength { .. } | StartError::TipWithoutWork)
        ),
        "the history holds one leaf per block before the tip, and no fewer"
    );
}

/// A keeper builds the answer, and a newcomer takes it.
///
/// The two halves of the exchange, run against each other rather than each
/// against a hand written expectation: whatever the draw asks, the keeper
/// finds, and the newcomer accepts what the keeper found. Neither side was
/// told what the questions would be.
#[test]
fn a_keeper_answers_a_draw_it_did_not_choose() {
    let keeper = Keeper::build(HEIGHT);
    let tip = keeper.tip();
    let by_height: Vec<BlockHeader> = keeper.headers.clone();

    let start = open_start(
        &tip,
        keeper.before_tip.forest().roots_only(),
        64,
        |height| by_height.get(usize::try_from(height).ok()?).copied(),
        |height| keeper.before_tip.prove(height),
    )
    .expect("a keeper can answer");

    assert_eq!(start.samples.len(), 64);
    let weighed = check_start(&start, 64).expect("and the answer stands up");
    assert_eq!(weighed.total_work, tip.total_work);

    // The heights it opened are the ones the draw asked about, found by
    // halving rather than by walking, which is the only way this scales.
    let wanted = draw(seed_of(&tip), 64, work_before(&tip), tip.height);
    for (sample, work) in start.samples.iter().zip(wanted) {
        assert_eq!(
            covering(
                &keeper
                    .headers
                    .iter()
                    .take(keeper.headers.len() - 1)
                    .rev()
                    .map(|h| (h.height, h.total_work, h.difficulty))
                    .collect::<Vec<_>>(),
                work
            ),
            Some(sample.header.height),
        );
    }
}

/// A node that validates and nothing more says so rather than guessing.
#[test]
fn a_node_that_did_not_keep_the_headers_cannot_answer() {
    let keeper = Keeper::build(HEIGHT);
    let tip = keeper.tip();
    let by_height: Vec<BlockHeader> = keeper.headers.clone();

    let start = open_start(
        &tip,
        keeper.before_tip.forest().roots_only(),
        16,
        |height| by_height.get(usize::try_from(height).ok()?).copied(),
        // Sixty four hashes is enough to check a proof and not to build one.
        |_| None,
    );
    assert!(start.is_none(), "an honest no beats a made up yes");
}

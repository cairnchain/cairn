//! AUDIT: the sampling bound, the input a prover used to write down, and the
//! rule that took it back.
//!
//! `SECURITY.md` says the bound is a conjecture and asks for work that proves
//! it or breaks it. An earlier round of this file broke it, and the break was
//! not in the arithmetic: it was in an input the derivation treated as the
//! chain's and the protocol let a prover write down.
//!
//! `SAMPLES` sets the count from
//!
//! ```text
//! (1 - ln(1/(1-lie))/levels)^count <= 2^-128
//! ```
//!
//! and every quantity in it but `levels` is fixed by the forger's share. The
//! `levels` was `bit_length(tip.height / 1024)`, read off a field of the tip.
//! Height is not work, and the only rule holding the two together is
//! `check_the_gaps`, which asks a run of `n` blocks between two opened headers
//! to be worth at least what a descent to the floor allows. That is
//! `n * MIN_DIFFICULTY`, and `MIN_DIFFICULTY` is one. So a chain whose blocks
//! averaged difficulty `d` could state a height `d` times the one it had, buy
//! `log2(d)` more halvings with it, and take that many slices off what every
//! draw was worth.
//!
//! `levels_of` is the rule now: the halvings come from how old the tip says its
//! chain is, over the block time the network aims at, and never past the
//! height. A reader refuses a tip dated more than its drift allowance ahead of
//! its own clock, so the deepest a stated chain can halve is the deepest the
//! real one can.
//!
//! The first two tests are the closure, on a chain that is built and put
//! through the shipped check. The third and fourth are why the height had to
//! come out of the draw rather than be bounded inside it: it is priced at
//! exactly one unit a block, and a stated height need not exist at all. The
//! fifth and sixth are what the rule is worth, measured on the shipped `draw`
//! at the size every published figure is quoted at.
//!
//! `examples/searching_for_a_break` is the search these conclusions came out
//! of. Counted rather than timed throughout: nothing here measures a duration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::print_stdout
)]

use cairn_accumulator::forest::{node_hash, Forest, ForestProof};
use cairn_ledger::block::BlockHeader;
use cairn_ledger::note::NetworkId;
use cairn_ledger::pow::{work_of, DIFFICULTY_WINDOW, MIN_DIFFICULTY};
use cairn_ledger::sampling::{
    check_start, draw, levels_for, levels_of, seed_of, work_before, Sample, SampledStart,
    StartError, MOST_TAIL, SAMPLES, SHALLOWEST,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{mine_block, ConsensusParams};
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Hash32;

/// Blocks that carry the work, at [`HARD`] apiece.
const CARRYING: u64 = 2_048;
/// Difficulty those blocks were mined at.
///
/// Above the floor, and that is the whole point: the ratio between this and
/// [`MIN_DIFFICULTY`] is how far a stated height can be inflated. A real chain
/// runs this ratio at forty bits and more; here it is nine, which used to be
/// enough to take the level count from two to eight.
const HARD: u64 = 512;
/// Height the tip states.
const STATED: u64 = 1 << 17;
/// Nonces a header is given before the test gives up on it.
const ATTEMPTS: u64 = 1 << 22;
/// When the chain opens, in its own clock.
const OPENS: u64 = 1_000_000;

/// The rules this chain is weighed under.
///
/// The opening moment is the fixture's own, because the level count is now read
/// from the distance between it and the tip: a network whose opening the test
/// does not set is a network the tip is measured against by accident.
fn params() -> ConsensusParams {
    ConsensusParams {
        opens_at: OPENS,
        ..ConsensusParams::testnet()
    }
}

/// A chain that states a height far past the blocks carrying its work.
struct Padded {
    /// Every header, oldest first, the tip last.
    shown: Vec<BlockHeader>,
    /// The forest as it stands below the tip.
    before_tip: Forest,
}

/// Builds it: [`CARRYING`] blocks at [`HARD`], then floor blocks up to a stated
/// height of [`STATED`].
///
/// The floor blocks are real. Each costs one hash, because difficulty one
/// accepts every identifier, and each is worth `MIN_DIFFICULTY`, which is
/// exactly what `check_the_gaps` asks of it. That is the price of a stated
/// height and there is no other.
///
/// `descend` gives the first four floor blocks the difficulties the retarget's
/// steepest descent allows, 128 down to 2, which is what makes the run worth
/// exactly what the gap check demands of it. Without them it is worth 166 less,
/// and the check says so; that is the third test.
fn build(descend: bool) -> Padded {
    let params = params();
    let mut shown: Vec<BlockHeader> = Vec::with_capacity(usize::try_from(STATED).unwrap() + 1);
    let mut forest = Forest::new();
    let mut before_tip = Forest::new();
    let mut clock = OPENS;
    let mut carried = 0u128;
    let mut previous = Hash32::from_bytes([0; 32]);

    for height in 0..=STATED {
        let difficulty = difficulty_at(height, descend);
        carried += work_of(difficulty);
        clock += params.target_block_time;
        let header = BlockHeader {
            version: 1,
            network: NetworkId::TESTNET,
            height,
            previous,
            transactions_root: Hash32::from_bytes([1; 32]),
            state_root: Hash32::from_bytes([2; 32]),
            history: forest.commitment(),
            timestamp: clock,
            difficulty,
            total_work: carried,
            nonce: 0,
        };
        let block = cairn_ledger::Block {
            header,
            coinbase: CoinbaseTransaction::new(height, Vec::new()),
            transfers: Vec::new(),
        };
        let header = mine_block(block, ATTEMPTS)
            .expect("a nonce exists for a header this cheap")
            .header;
        previous = header.id();
        if height == STATED {
            // A tip is not in its own history, so the forest handed over is
            // the one that stood before it.
            before_tip = forest.roots_only();
        } else {
            forest.add(header_leaf(&previous));
        }
        shown.push(header);
    }

    Padded { shown, before_tip }
}

/// The difficulty a height carries.
///
/// The blocks carrying the work sit at [`HARD`]; the four below the switch walk
/// down by the retarget's own factor of four, which is what `least_work_over`
/// prices a descent at; everything above sits on the floor.
fn difficulty_at(height: u64, descend: bool) -> u64 {
    if height < CARRYING {
        return HARD;
    }
    if !descend {
        return MIN_DIFFICULTY;
    }
    match height - CARRYING {
        0 => 128,
        1 => 32,
        2 => 8,
        3 => 2,
        _ => MIN_DIFFICULTY,
    }
}

impl Padded {
    fn tip(&self) -> BlockHeader {
        *self.shown.last().unwrap()
    }

    /// The height whose header spans a drawn value, which is what a prover
    /// answers with.
    fn answer(&self, work: u128) -> u64 {
        let last = self.shown.len() - 1;
        let above = self.shown[..last].partition_point(|header| header.total_work <= work);
        u64::try_from(above.min(last - 1)).unwrap()
    }

    /// What the prover hands a newcomer.
    ///
    /// The forest is rebuilt with the drawn positions watched, since a path
    /// falls out of an addition and cannot be recovered from the roots
    /// afterwards. Two passes over the leaves, which is what an archivist does
    /// with a disk instead.
    fn present(&self, count: usize) -> SampledStart {
        let tip = self.tip();
        let drawn = draw(
            seed_of(&tip),
            count,
            work_before(&tip),
            levels_of(&tip, &params()),
        );
        let mut wanted: Vec<u64> = drawn.iter().map(|work| self.answer(*work)).collect();
        wanted.push(tip.height - 1);
        wanted.sort_unstable();
        wanted.dedup();

        let mut forest = Forest::new();
        let mut watching = wanted.iter().copied().peekable();
        for header in &self.shown[..self.shown.len() - 1] {
            let (position, proof) = forest.add(header_leaf(&header.id())).unwrap();
            if watching.peek() == Some(&position) {
                forest.watch(position, proof);
                watching.next();
            }
        }
        assert_eq!(
            forest.commitment(),
            self.before_tip.commitment(),
            "the rebuilt forest is not the one the tip commits to"
        );

        let open = |height: u64| Sample {
            header: self.shown[usize::try_from(height).unwrap()],
            proof: forest.proof_of(height).unwrap().clone(),
        };
        let samples: Vec<Sample> = drawn
            .into_iter()
            .map(|work| open(self.answer(work)))
            .collect();

        let deepest = samples
            .iter()
            .map(|sample: &Sample| sample.header.height)
            .max()
            .unwrap_or(0);
        let from = usize::try_from(deepest.saturating_sub(DIFFICULTY_WINDOW as u64)).unwrap();
        let tail = self.shown[from..].to_vec();

        SampledStart {
            tip,
            tail,
            parent: Some(open(tip.height - 1)),
            history: self.before_tip.roots_only(),
            samples,
        }
    }
}

/// The break, closed: the number the level count is read from is not one the
/// prover writes down.
///
/// The chain below is the one that broke the bound. It is still accepted, and
/// it should be: a chain that really is this old and this tall, with the work
/// to price both, is not a forgery. What has changed is what it is asked. The
/// same tip stating a height of 2^61 draws the same questions, because the
/// questions come from the distance between the network's opening and the
/// tip's own timestamp, and the chain cannot be older than the network.
#[test]
fn the_level_count_is_not_read_from_a_number_the_prover_writes_down() {
    let padded = build(true);
    let tip = padded.tip();
    let start = padded.present(SAMPLES);
    let now = tip.timestamp;

    // Through the wire and back first. A weighing that only exists as a struct
    // in this process is not a weighing a peer can send.
    let wire = start.encode();
    let start = SampledStart::decode(&wire).expect("a forged weighing has to survive its own wire");
    check_start(&start, SAMPLES, now, &params())
        .expect("a chain whose work and age are both real has to be accepted");

    let params = params();
    let asked = levels_of(&tip, &params);

    // The break, in two lines. The stated height moves the old count and not
    // the new one.
    for stated in [STATED * 64, STATED * 4_096, 1 << 61, u64::MAX] {
        let taller = BlockHeader {
            height: stated,
            ..tip
        };
        assert_ne!(
            levels_for(tip.height),
            levels_for(taller.height),
            "a height of {stated} was supposed to move the count that used to be read"
        );
        assert_eq!(
            asked,
            levels_of(&taller, &params),
            "a height of {stated} moved the count that is read now"
        );
    }

    // And the count it is asked at is the one its own age buys, which is the
    // one every chain of that age is asked at, honest or not.
    let age = (tip.timestamp - params.opens_at) / params.target_block_time;
    assert_eq!(asked, levels_for(age.min(tip.height)));

    let carried = u128::from(CARRYING) * u128::from(HARD);
    let padding = tip.total_work - carried;
    println!(
        "\n  {CARRYING} blocks at difficulty {HARD} carry {carried} work. Stating a height\n  \
         of {STATED} costs {padding} more, at MIN_DIFFICULTY a block, and used to take\n  \
         the draw from {} halvings to {}. It now takes it to {asked}, which is what the\n  \
         chain's own age buys and what a chain of that age gets whatever it says about\n  \
         its height.\n",
        levels_for(CARRYING),
        levels_for(tip.height),
    );
}

/// And the ceiling is the reader's own clock, held before a question is asked.
///
/// The same chain, offered to a reader whose clock says the network opened only
/// as long ago as the work in it took. The tip is dated past what that reader
/// will take, and it is refused for that and not for anything the draw found:
/// the samples are emptied first, so a refusal for the count or for a sample
/// would come out instead if the order had drifted.
#[test]
fn a_tip_dated_past_the_reader_is_refused_before_a_question_is_asked() {
    let padded = build(true);
    let tip = padded.tip();
    let mut start = padded.present(SAMPLES);
    let params = params();

    let honestly = OPENS + CARRYING * params.target_block_time;
    assert!(tip.timestamp > honestly + params.max_timestamp_drift);

    start.samples.clear();
    let refusal = check_start(&start, SAMPLES, honestly, &params);
    assert!(
        matches!(refusal, Err(StartError::TipFromTheFuture { .. })),
        "a tip from the future was refused for {refusal:?} instead"
    );

    // A drift's worth of slack and no more, which is 120 blocks at a block a
    // minute against a chain of {STATED}.
    let blocks_of_slack = params.max_timestamp_drift / params.target_block_time;
    assert_eq!(blocks_of_slack, 120);
    let accepted = levels_for((tip.timestamp - OPENS) / params.target_block_time);
    let honest_count = levels_for(CARRYING + blocks_of_slack);
    assert!(
        accepted > honest_count,
        "the fixture is not one where the clock is the binding constraint"
    );
}

/// A stated height is priced at exactly `MIN_DIFFICULTY` a block, from both
/// sides.
///
/// This is why the height had to come out of the draw rather than be bounded
/// inside it. The run above the carrying blocks states exactly what
/// `check_the_gaps` demands of it, and one unit a block less is refused by the
/// same check. There is no ceiling to be had from the pricing: a chain worth
/// `W` prices a stated height of `W / MIN_DIFFICULTY`, so the level count a
/// prover could reach was decided by the chain's work and by nothing the draw
/// or the decoder said.
#[test]
fn the_stated_height_is_priced_at_one_unit_a_block_and_not_less() {
    let short = build(false);
    let start = short.present(SAMPLES);
    let now = short.tip().timestamp;
    let refusal = check_start(&start, SAMPLES, now, &params());
    assert!(
        matches!(refusal, Err(StartError::BlocksWorthLessThanTheyCost { .. })),
        "a run worth less than the descent allows was refused for {refusal:?}"
    );

    // The shortfall is the descent and nothing else: what the retarget's
    // steepest fall from 512 is worth over its first five blocks, against five
    // blocks at the floor.
    let Err(StartError::BlocksWorthLessThanTheyCost { stated, least, .. }) = refusal else {
        panic!("the refusal changed shape");
    };
    assert_eq!(
        least - stated,
        (128 + 32 + 8 + 2 + 1) - 5,
        "the descent's own cost"
    );

    // At a real chain's numbers that pricing allowed fifty-odd halvings where
    // the count was set for fourteen.
    let real = REAL * u128::from(YEARS);
    let priced = u64::try_from(real / u128::from(MIN_DIFFICULTY)).unwrap_or(u64::MAX);
    assert_eq!(levels_for(YEARS), 14, "what the count is set for");
    assert!(
        levels_for(priced) >= 53,
        "a chain worth {real} prices a height of {priced}, which is only {} halvings",
        levels_for(priced)
    );
}

/// Thirty years of a chain a minute, which is the size every published figure
/// is quoted at.
const YEARS: u64 = 30 * 365 * 24 * 60;
/// Difficulty a real chain runs at.
const REAL: u128 = 1 << 40;
/// Seeds a hit rate is measured over here.
///
/// The seed is the tip's own identifier, so a placement is worth its average
/// over seeds. Enough to tell one figure from another and no more: the search
/// that found these placements is in `examples/searching_for_a_break` and runs
/// at 512.
const SEEDS: u64 = 32;

/// Every draw the shipped function makes for one level count, sorted.
///
/// Built once per count and asked many questions, because the questions are
/// what a search is and the draws are what they are asked of.
struct Board {
    levels: u32,
    total: u128,
    drawn: Vec<u128>,
}

impl Board {
    fn of(levels: u32, total: u128) -> Self {
        let mut drawn = Vec::with_capacity((SEEDS as usize) * SAMPLES);
        for trial in 0..SEEDS {
            let seed: Hash32 = hash(Domain::SamplingSeed, &trial.to_le_bytes());
            drawn.extend(draw(seed, SAMPLES, total, levels));
        }
        drawn.sort_unstable();
        Self {
            levels,
            total,
            drawn,
        }
    }

    /// Whether a chain stating this many halvings can be weighed at all.
    ///
    /// The run up to the tip carries every block of the band the draw leaves
    /// unresolved, plus a retarget window. Past [`MOST_TAIL`] a reader refuses
    /// the weighing before it looks at a draw, so a prover that understates the
    /// count has refused its own weighing.
    fn weighable(&self) -> bool {
        let band = self.total >> self.levels.min(127);
        band / REAL + u128::from(DIFFICULTY_WINDOW as u64) < u128::from(MOST_TAIL)
    }

    /// The share of draws landing in `[from, to)`.
    fn landing_in(&self, from: u128, to: u128) -> f64 {
        let lo = self.drawn.partition_point(|work| *work < from);
        let hi = self.drawn.partition_point(|work| *work < to);
        (hi - lo) as f64 / self.drawn.len() as f64
    }
}

/// `log2` of the chance all [`SAMPLES`] draws miss.
fn miss_log2(hit: f64) -> f64 {
    if hit <= 0.0 {
        return 0.0;
    }
    SAMPLES as f64 * (1.0 - hit).log2()
}

/// The best gap a forger at `share` can place on a chain stating this count.
///
/// The gap runs from a band's shallow edge down by a factor of `1/sigma`, which
/// is where the staircase is cheapest: inside one band the draw is uniform, so
/// a gap of fixed depth ratio costs least when it is pressed against the
/// shallow edge. The smooth `1/x` density the derivation assumes prices the
/// same gap at `log2(1/sigma)/levels`, which is higher.
///
/// Only bands the run up to the tip does not already cover are considered.
fn best_miss(board: &Board, share: f64) -> f64 {
    let sigma = share / (1.0 - share);
    let total = board.total;
    let floor = (total >> board.levels.min(127)) + u128::from(DIFFICULTY_WINDOW as u64 + 1) * REAL;
    let mut best = f64::NEG_INFINITY;
    for level in 0..board.levels {
        let shallow = total >> level.saturating_add(1).min(127);
        if shallow < floor {
            continue;
        }
        let deep = (shallow as f64 / sigma) as u128;
        if deep >= total || deep <= shallow {
            continue;
        }
        best = best.max(miss_log2(board.landing_in(total - deep, total - shallow)));
    }
    best
}

/// Every level count a prover can state on a thirty year chain, and whether a
/// reader would weigh a chain stating it.
fn every_count(total: u128) -> Vec<Board> {
    (1..=levels_for(YEARS))
        .map(|levels| Board::of(levels, total))
        .collect()
}

/// At forty per cent, no level count a prover can state puts the forgery
/// through.
///
/// The published figure is forty per cent. This is the test that failed before
/// the rule changed: a stated height of 2^61 took the same forgery from 2^-207
/// to 2^-58 against a published 2^-128. The ceiling is now the honest count, so
/// the only counts left to search are the honest one and the ones below it, and
/// a count below it makes every draw worth more rather than less.
#[test]
fn at_forty_percent_no_count_a_prover_can_state_puts_the_forgery_through() {
    let total = REAL * u128::from(YEARS);
    let boards = every_count(total);
    let honest = boards.last().unwrap();
    assert_eq!(honest.levels, levels_for(YEARS));

    let mut refused = 0u32;
    let mut worst = f64::NEG_INFINITY;
    for board in &boards {
        if !board.weighable() {
            refused += 1;
            continue;
        }
        worst = worst.max(best_miss(board, 0.40));
    }

    assert!(
        best_miss(honest, 0.40) < -128.0,
        "at the honest count the best placement misses with 2^{:.1}",
        best_miss(honest, 0.40)
    );
    assert!(
        worst < -128.0,
        "some count a prover can state reached 2^{worst:.1} against a published 2^-128"
    );
    assert!(
        refused > 0,
        "every count was weighable, so the filter is idle"
    );

    println!(
        "\n  A forger at 40% of the world's work, on a chain of {YEARS} blocks. Of the\n  \
         {} level counts a prover can state, {refused} are refused for the length of the\n  \
         run they demand. Over the rest its best placement misses every one of {SAMPLES}\n  \
         draws with 2^{worst:.1}. The published figure is 2^-128, and when the count came\n  \
         off the stated height this read 2^-58.\n",
        boards.len(),
    );
}

/// And the share the draw holds to is back above the published forty.
#[test]
fn the_share_the_draw_holds_to_is_above_the_published_forty() {
    let total = REAL * u128::from(YEARS);
    let boards: Vec<Board> = every_count(total)
        .into_iter()
        .filter(Board::weighable)
        .collect();

    let mut low = 0.05f64;
    let mut high = 0.50f64;
    for _ in 0..12 {
        let middle = f64::midpoint(low, high);
        let best = boards
            .iter()
            .map(|board| best_miss(board, middle))
            .fold(f64::NEG_INFINITY, f64::max);
        if best <= -128.0 {
            low = middle;
        } else {
            high = middle;
        }
    }

    assert!(
        low > 0.40,
        "the draw held to {:.2}% and the published figure is 40%",
        low * 100.0
    );
    assert!(
        low < 0.46,
        "the draw held to {:.2}%, which is further than `SAMPLES` claims, so one of \
         the two is wrong",
        low * 100.0
    );
    println!(
        "\n  Measured over {} level counts a prover can state, the count reaches 2^-128 up\n  \
         to {:.1}% of the world's work. `SAMPLES` publishes 40% and says it measured 43.\n  \
         Against a forger that also wrote down its own height this read 31.\n",
        boards.len(),
        low * 100.0,
    );
}

/// Leaves a forger really holds, in the test below. Everything above this
/// position in its forest is one filler leaf repeated.
const REALLY: u64 = 4;

/// The subtree at `start` of this height: filler wholesale when it holds
/// nothing real, and otherwise two halves of the same question.
///
/// This is what makes a stated height free to commit to. A subtree holding
/// nothing a forger will be asked to open is one hash it already has, whatever
/// its height, so a forest of any size costs what the opened positions cost and
/// nothing for the rest.
fn subtree(level: u32, start: u64, real: &[Hash32], empty: &[Hash32]) -> Hash32 {
    if start >= REALLY {
        return empty[usize::try_from(level).unwrap()];
    }
    if level == 0 {
        return real[usize::try_from(start).unwrap()];
    }
    let half = 1u64 << (level - 1);
    node_hash(
        subtree(level - 1, start, real, empty),
        subtree(level - 1, start + half, real, empty),
    )
}

/// A stated height also costs nothing to commit to.
///
/// The other half of "free", and the one that decided whether the height a
/// prover states could be bounded by what it can hold. It cannot. A forest
/// travels as its leaf count and one root per tree, and a path is checked by
/// folding it against that root. Nothing asks what is at a position nobody
/// opened, and a prover opens [`SAMPLES`] of them.
///
/// So it picks one filler leaf, folds it up to every height in as many hashes
/// as there are heights, builds the small subtrees that hold what it does open,
/// and commits the fold. The forest below is 2^61 leaves, of which four exist,
/// and the shipped `Forest::verify` accepts every one of them.
///
/// This is why the height could not be bounded where it was read: the price of
/// a stated height is the one `check_the_gaps` charges and no other, at
/// `MIN_DIFFICULTY` a block, in work the forger was inventing anyway. It is not
/// `n` headers, `n` hashes, or `n` bytes of anything.
#[test]
fn a_forest_of_two_to_the_sixty_one_leaves_costs_four_of_them() {
    const DEPTH: u32 = 61;

    let real: Vec<Hash32> = (0..REALLY)
        .map(|position| header_leaf(&hash(Domain::SamplingSeed, &position.to_le_bytes())))
        .collect();
    let filler = header_leaf(&Hash32::from_bytes([7; 32]));

    // The all-filler subtree at each height, which is one hash per height and
    // not one per leaf. This is the whole trick.
    let mut empty = Vec::with_capacity(usize::try_from(DEPTH).unwrap() + 1);
    empty.push(filler);
    for level in 1..=usize::try_from(DEPTH).unwrap() {
        let below = empty[level - 1];
        empty.push(node_hash(below, below));
    }

    let leaves = 1u64 << DEPTH;
    let root = subtree(DEPTH, 0, &real, &empty);
    let mut wire = Vec::new();
    leaves.encode_to(&mut wire);
    leaves.encode_to(&mut wire);
    1u32.encode_to(&mut wire);
    u8::try_from(DEPTH).unwrap().encode_to(&mut wire);
    root.encode_to(&mut wire);
    let forest = Forest::decode(&wire).expect("a forest whose roots are the set bits of its count");
    assert_eq!(forest.leaves(), leaves);

    for position in 0..REALLY {
        let siblings = (0..DEPTH)
            .map(|level| subtree(level, ((position >> level) ^ 1) << level, &real, &empty))
            .collect();
        let proof = ForestProof { siblings };
        assert!(
            forest.verify(position, real[usize::try_from(position).unwrap()], &proof),
            "a path into a forest of {leaves} leaves did not fold to its root"
        );
        assert!(
            !forest.verify(position, filler, &proof),
            "the same path folded a different leaf to the same root"
        );
    }

    println!(
        "\n  A forest of {leaves} leaves, of which {REALLY} exist. The filler folds up to\n  \
         every height in {DEPTH} hashes, and no subtree holding nothing real is ever\n  \
         built: what a forest costs is what is opened in it. Every path is {DEPTH}\n  \
         siblings, and the shipped verifier takes all of them.\n"
    );
}

/// The narrowest band the draw separates, unchanged by any of this.
#[test]
fn the_draw_still_stops_a_thousand_blocks_from_the_tip() {
    assert_eq!(SHALLOWEST, 1_024);
    assert_eq!(levels_for(YEARS), 14);
}

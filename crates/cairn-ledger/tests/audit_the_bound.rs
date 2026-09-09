//! AUDIT: the sampling bound, and the two places it is not a theorem.
//!
//! `SECURITY.md` says the bound is a conjecture and asks for work that proves
//! it or breaks it. This breaks it, and the break is not in the arithmetic: it
//! is in an input the derivation treats as the chain's and the protocol lets a
//! prover write down.
//!
//! `SAMPLES` sets the count from
//!
//! ```text
//! (1 - ln(1/(1-lie))/levels)^count <= 2^-128
//! ```
//!
//! and every quantity in it but `levels` is fixed by the forger's share. The
//! `levels` is `bit_length(tip.height / 1024)`, read off a field of the tip.
//! Height is not work, and the only rule holding the two together is
//! `check_the_gaps`, which asks a run of `n` blocks between two opened headers
//! to be worth at least what a descent to the floor allows. That is
//! `n * MIN_DIFFICULTY`, and `MIN_DIFFICULTY` is one. So a chain whose blocks
//! average difficulty `d` can state a height `d` times the one it has, buy
//! `log2(d)` more halvings with it, and take that many slices off what every
//! draw is worth.
//!
//! The first test builds one and puts it through the shipped check. The second
//! prices it, from both sides: exactly one unit a block, and the check refuses a
//! unit less. The fifth is the other half of the price, and the sharper half: a
//! stated block need not exist at all. A forest travels as a leaf count and its
//! roots, and only the positions a draw opens are ever folded, so a forger
//! commits to a forest of any size in as many hashes as it has heights. What it
//! pays for a stated height is what `check_the_gaps` charges, in work it was
//! already inventing, and nothing else.
//!
//! The third and fourth are what that does to the published figure, measured on
//! the shipped `draw` at the size the figure is quoted at: 40 per cent stops
//! holding, and what does hold is nearer 31.
//!
//! `examples/breaking_the_bound` is the search these conclusions came out of.
//! Counted rather than timed throughout: nothing here measures a duration.

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
    check_start, draw, seed_of, work_before, Sample, SampledStart, StartError, SAMPLES, SHALLOWEST,
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
/// runs this ratio at forty bits and more; here it is nine, which is enough to
/// take the level count from two to eight.
const HARD: u64 = 512;
/// Height the tip states.
const STATED: u64 = 1 << 17;
/// Nonces a header is given before the test gives up on it.
const ATTEMPTS: u64 = 1 << 22;
/// When the chain opens, in its own clock.
const OPENS: u64 = 1_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// Halvings the draw spreads itself over, restated from `sampling.rs`, which
/// keeps this private and the constant it reads from public.
fn levels_for(blocks: u64) -> u32 {
    let separable = blocks / SHALLOWEST;
    u64::BITS
        .saturating_sub(separable.max(1).leading_zeros())
        .max(1)
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
/// and the check says so; that is the second test.
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
        let drawn = draw(seed_of(&tip), count, work_before(&tip), tip.height);
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

/// A prover writes down the number the draw's level count is computed from, and
/// the shipped check takes it.
///
/// This is the break. Everything else in this file is what it costs and what it
/// is worth.
#[test]
fn the_level_count_is_read_from_a_number_the_prover_writes_down() {
    let padded = build(true);
    let tip = padded.tip();
    let start = padded.present(SAMPLES);
    let now = tip.timestamp;

    // Through the wire and back first. A weighing that only exists as a struct
    // in this process is not a weighing a peer can send, and the decoder is
    // where a ceiling on the stated height would have to live if there were
    // one. There is not: it bounds the sample count and the run up to the tip,
    // and nothing else.
    let wire = start.encode();
    let start = SampledStart::decode(&wire).expect("a forged weighing has to survive its own wire");
    check_start(&start, SAMPLES, now, &params())
        .expect("a chain padded to a stated height has to be accepted, or there is no break");

    let carried = u128::from(CARRYING) * u128::from(HARD);
    let padding = tip.total_work - carried;
    assert_eq!(tip.height, STATED);
    assert_eq!(levels_for(CARRYING), 2, "the blocks carrying the work");
    assert_eq!(levels_for(tip.height), 8, "the height the tip states");

    // What the extra six halvings cost, which is one hash a block.
    assert!(
        padding * 8 < carried,
        "the padding is {padding} against {carried} carried, which is not cheap"
    );
    println!(
        "\n  {CARRYING} blocks at difficulty {HARD} carry {carried} work. Stating a height\n  \
         of {STATED} costs {padding} more, at MIN_DIFFICULTY a block, and takes the\n  \
         draw from {} halvings to {}. Every draw is then worth 1/{} of what the count\n  \
         was set assuming, and the check accepted it.\n",
        levels_for(CARRYING),
        levels_for(tip.height),
        levels_for(tip.height) / levels_for(CARRYING),
    );
}

/// And it is priced at exactly `MIN_DIFFICULTY` a block, from both sides.
///
/// The run above the carrying blocks states exactly what `check_the_gaps`
/// demands of it. One unit a block less, which is what dropping the retarget's
/// descent takes off it, and the same check refuses.
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

    // And that price is the only ceiling there is. A chain worth `W` prices a
    // stated height of `W / MIN_DIFFICULTY`, so the level count a prover can
    // reach is decided by the chain's work and not by anything the draw or the
    // decoder says. At a real chain's numbers that is fifty-odd halvings where
    // the count was set for fourteen.
    let real = REAL * u128::from(YEARS);
    let priced = u64::try_from(real / u128::from(MIN_DIFFICULTY)).unwrap_or(u64::MAX);
    assert_eq!(levels_for(YEARS), 14, "what the count was set for");
    assert!(
        levels_for(priced) >= 53,
        "a chain worth {real} prices a height of {priced}, which is only \
         {} halvings",
        levels_for(priced)
    );
}

/// Thirty years of a chain a minute, which is the size every published figure
/// is quoted at.
const YEARS: u64 = 30 * 365 * 24 * 60;
/// Difficulty a real chain runs at, which is what decides how far its stated
/// height can be inflated.
const REAL: u128 = 1 << 40;
/// Seeds a hit rate is measured over here.
///
/// The seed is the tip's own identifier, so a placement is worth its average
/// over seeds. Enough to tell 2^-58 from 2^-128 and no more: the search that
/// found these placements is in `examples/breaking_the_bound` and runs at 512.
const SEEDS: u64 = 32;

/// Every draw the shipped function makes for one stated height, sorted.
///
/// Built once per height and asked many questions, because the questions are
/// what a search is and the draws are what they are asked of.
struct Board {
    height: u64,
    levels: u32,
    total: u128,
    drawn: Vec<u128>,
}

impl Board {
    fn of(height: u64, total: u128) -> Self {
        let mut drawn = Vec::with_capacity((SEEDS as usize) * SAMPLES);
        for trial in 0..SEEDS {
            let seed: Hash32 = hash(Domain::SamplingSeed, &trial.to_le_bytes());
            drawn.extend(draw(seed, SAMPLES, total, height));
        }
        drawn.sort_unstable();
        Self {
            height,
            levels: levels_for(height),
            total,
            drawn,
        }
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

/// The best gap a forger at `share` can place on a chain stating this height.
///
/// The gap runs from a band's shallow edge down by a factor of `1/sigma`, which
/// is where the staircase is cheapest: inside one band the draw is uniform, so
/// a gap of fixed depth ratio costs least when it is pressed against the
/// shallow edge. The smooth `1/x` density the derivation assumes prices the
/// same gap at `log2(1/sigma)/levels`, which is higher.
///
/// Only bands the run up to the tip does not already cover are considered, and
/// only heights the gap itself prices: a run of `height` blocks has to be worth
/// `height * MIN_DIFFICULTY`, and the gap is what states it.
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
        if u128::from(board.height) * u128::from(MIN_DIFFICULTY) > deep - shallow {
            continue;
        }
        best = best.max(miss_log2(board.landing_in(total - deep, total - shallow)));
    }
    best
}

/// At forty per cent the count reaches 2^-128 at the honest height and does not
/// at a height the prover chooses.
///
/// The published figure is forty per cent. It survives everything
/// `adversarial_placement` searches. It does not survive the height.
#[test]
fn at_forty_percent_a_chosen_height_puts_the_forgery_through() {
    let total = REAL * u128::from(YEARS);
    let honest = best_miss(&Board::of(YEARS, total), 0.40);
    // 2^61 is priced by a gap of a quarter of the chain, which is what a forger
    // at forty per cent has to invent to outweigh a fork three quarters back.
    let chosen = best_miss(&Board::of(1 << 61, total), 0.40);

    assert!(
        honest < -128.0,
        "at the honest height the best placement misses with 2^{honest:.1}, and the \
         count is supposed to reach 2^-128"
    );
    assert!(
        chosen > -128.0,
        "a chosen height was supposed to break the bound and only reached 2^{chosen:.1}"
    );
    println!(
        "\n  A forger at 40% of the world's work, on a chain of {YEARS} blocks:\n  \
         at the honest height its best placement misses every one of {SAMPLES} draws\n  \
         with 2^{honest:.1}. Stating a height of 2^61 instead, which costs it nothing it\n  \
         was not already inventing, the same forgery misses with 2^{chosen:.1}. The\n  \
         published figure is 2^-128.\n"
    );
}

/// The share the draw actually holds to, measured the same way.
///
/// `SAMPLES` says 43 per cent measured and 40 published, three points of margin.
/// Against a forger that also writes down its own height there is no margin:
/// the figure is below 40, not above it.
#[test]
fn the_share_the_draw_holds_to_is_below_the_published_forty() {
    let total = REAL * u128::from(YEARS);
    let heights = [YEARS, 1 << 32, 1 << 45, 1 << 52, 1 << 61];
    let boards: Vec<Board> = heights
        .iter()
        .map(|height| Board::of(*height, total))
        .collect();

    let mut low = 0.05f64;
    let mut high = 0.50f64;
    for _ in 0..8 {
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
        low < 0.40,
        "the draw held to {:.2}% and the published figure is 40%, so this test is \
         measuring the wrong thing",
        low * 100.0
    );
    println!(
        "\n  Measured over {} stated heights, the count reaches 2^-128 up to {:.1}% of the\n  \
         world's work and no further. `SAMPLES` publishes 40% and says it measured 43.\n  \
         The difference is the level count, which the derivation treats as the chain's\n  \
         and the protocol lets a prover write down.\n",
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
/// The other half of "free", and the one that decides whether the height a
/// forger states is bounded by what it can hold. It is not. A forest travels as
/// its leaf count and one root per tree, and a path is checked by folding it
/// against that root. Nothing asks what is at a position nobody opened, and a
/// forger opens [`SAMPLES`] of them.
///
/// So it picks one filler leaf, folds it up to every height in as many hashes
/// as there are heights, builds the small subtrees that hold what it does open,
/// and commits the fold. The forest below is 2^61 leaves, of which four exist,
/// and the shipped `Forest::verify` accepts every one of them.
///
/// This is why the price of a stated height is the one `check_the_gaps` charges
/// and no other: `MIN_DIFFICULTY` a block, in work the forger was inventing
/// anyway. It is not `n` headers, `n` hashes, or `n` bytes of anything.
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

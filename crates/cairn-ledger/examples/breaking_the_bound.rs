//! Searching for a placement the sampling bound does not survive.
//!
//! `adversarial_placement` searches one family: a fork depth, the work gap that
//! depth forces, and a count of draws. Everything else it holds fixed, and in
//! particular it holds fixed the one input to the draw that a prover writes
//! down itself. This searches the wider family, and the wider family contains a
//! placement the published figure does not survive.
//!
//! Four axes, and the fourth is the one that matters.
//!
//! **Where the gap sits inside a halving band.** The density the bound is
//! derived for is `1/x`, and the density the draw ships is a staircase of
//! halvings standing in for it. Inside one band the draw is uniform, so a gap
//! spanning a fixed *ratio* of depths is worth different amounts depending on
//! where the band boundaries fall across it, and the cheapest position is the
//! gap pressed against a band's shallow edge: `p_band * (1/sigma - 1)` against
//! the derivation's `log2(1/sigma) / levels`. This is a real gap between the
//! derivation and the thing shipped, worth some forty bits at the shares that
//! matter, and it is already inside the published figure: the geometric sweep
//! `adversarial_placement` runs lands on the same optimum without naming it,
//! which is why `SAMPLES` says 43 measured against a derivation saying more.
//! It is separated out here so that the next person does not search it again.
//!
//! **Which band.** One byte modulo `levels` does not divide evenly, so the
//! first `256 mod levels` bands are drawn more often than the rest. A forger
//! puts its gap in one of the others. Worth 1.6 per cent at the honest height,
//! and more once the level count is larger.
//!
//! **Whether the gap is one piece.** It is: the density falls with depth, so
//! splitting the lie moves part of it shallower. Searched and reported anyway,
//! because a family nobody searched is not a family nobody can use.
//!
//! **How many bands there are.** `levels` is `bit_length(height / 1024)`, read
//! off the tip's stated height. Height is not work. The only thing holding a
//! stated height down is `check_the_gaps`, which asks a run of `n` blocks to be
//! worth at least `n * MIN_DIFFICULTY`, and `MIN_DIFFICULTY` is one. A chain
//! running at difficulty `d` can therefore state a height `d` times its own and
//! still price it, in work it was inventing anyway, and every doubling of the
//! stated height takes another slice off what each draw is worth. This is the
//! axis nobody varied, and it is worth twelve points of the forger's share:
//! the count reaches 2^-128 to 43.3 per cent against a forger that takes the
//! height as given, and to 31.2 against one that writes it down.
//!
//! That a forger can write it down is not arithmetic and is not measured here.
//! It is built and put through the shipped check in
//! `tests/audit_the_bound.rs`.
//!
//! Run with `cargo run --release -p cairn-ledger --example breaking_the_bound`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::print_stdout,
    clippy::too_many_lines
)]

use cairn_ledger::pow::{DIFFICULTY_WINDOW, MIN_DIFFICULTY};
use cairn_ledger::sampling::{draw, SAMPLES, SHALLOWEST};
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::Hash32;

/// Thirty years of a chain a minute, which is the size every published figure
/// is quoted at.
const BLOCKS: u64 = 30 * 365 * 24 * 60;
/// Difficulty the honest chain runs at, which is what decides how far a stated
/// height can be inflated: a block at the floor is worth `MIN_DIFFICULTY`, so
/// `total_work / MIN_DIFFICULTY` is the largest height anything prices.
const PER_BLOCK: u128 = 1 << 40;
/// Seeds per measurement in the sweep.
///
/// The seed is the tip's own identifier, so a forger reaches a chosen one only
/// by finding another tip. What a placement is worth is therefore its average
/// over seeds, and grinding is a separate, priced thing.
const SEEDS: u64 = 64;
/// Seeds the winner is re-measured over, once the sweep has found it.
const SEEDS_FOR_THE_WINNER: u64 = 512;
/// What the count is set to reach.
const TARGET: f64 = -128.0;
/// A header and its path's length prefix, from `Sample`'s own encoding.
const SAMPLES_BYTES: u32 = 182 + 4;

fn main() {
    let total = PER_BLOCK * u128::from(BLOCKS);
    println!(
        "A chain of {BLOCKS} blocks at difficulty {PER_BLOCK}, stating {total} work.\n\
         {SAMPLES} draws. Every number below comes from the shipped `draw`.\n"
    );

    let heights = claimable_heights(total);
    let mut boards: Vec<Board> = Vec::with_capacity(heights.len());
    for height in heights {
        boards.push(Board::of(height, total, SEEDS));
    }

    let mut tried = 0usize;
    println!("What the best placement in each family is worth, by the forger's share:\n");
    println!(
        "{:>7} {:>11} {:>11} {:>11} {:>11}",
        "share", "derivation", "one band", "aligned", "any height"
    );
    println!(
        "{:>7} {:>11} {:>11} {:>11} {:>11}",
        "", "log2 miss", "log2 miss", "log2 miss", "log2 miss"
    );
    println!("{}", "-".repeat(56));

    let mut rows: Vec<Row> = Vec::new();
    for share in [0.10f64, 0.20, 0.30, 0.3229, 0.35, 0.40, 0.4337, 0.45] {
        let honest = &boards[0];
        let smooth = smooth_model(share, honest.levels);
        let swept = best_over(honest, share, &Sweep::Depths, &mut tried);
        let aligned = best_over(honest, share, &Sweep::Aligned, &mut tried);
        let mut anywhere = aligned;
        for board in &boards {
            let found = best_over(board, share, &Sweep::Aligned, &mut tried);
            if found.miss > anywhere.miss {
                anywhere = found;
            }
            let split = best_over(board, share, &Sweep::Split, &mut tried);
            if split.miss > anywhere.miss {
                anywhere = split;
            }
        }
        println!(
            "{:>6.2}% {:>11.1} {:>11.1} {:>11.1} {:>11.1}",
            share * 100.0,
            smooth,
            swept.miss,
            aligned.miss,
            anywhere.miss
        );
        rows.push(Row { share, anywhere });
    }

    println!(
        "\n  'derivation' is `(1 - log2(1/sigma)/levels)^{SAMPLES}` at the honest height,\n  \
         which is what `SAMPLES` computes its count from. 'one band' is the sweep\n  \
         `adversarial_placement` already does, at the honest height. 'aligned' is the\n  \
         same sweep with the gap's shallow end put on a band boundary. 'any height' adds\n  \
         the stated height to the search. {tried} placements were measured over\n  \
         {SEEDS} seeds apiece to fill this table."
    );

    the_winner(&rows, total);
    the_threshold(&boards);
    the_depth_guarantee(&boards, total);
    the_shape_of_the_argument();
}

/// The placement that beat the published figure, re-measured and priced.
fn the_winner(rows: &[Row], total: u128) {
    println!("\n\nThe best placement found, at each share, re-measured over {SEEDS_FOR_THE_WINNER} seeds:\n");
    println!(
        "{:>7} {:>9} {:>7} {:>9} {:>11} {:>12} {:>10}",
        "share", "height", "levels", "band", "fork at", "gap/chain", "log2 miss"
    );
    println!("{}", "-".repeat(72));
    for row in rows {
        let placement = row.anywhere;
        let board = Board::of(placement.height, total, SEEDS_FOR_THE_WINNER);
        let hit = board.landing_in(&placement.pieces);
        let miss = miss_log2(hit);
        println!(
            "{:>6.2}% {:>9} {:>7} {:>7} {:>10.4}% {:>11.5}% {:>10.1}",
            row.share * 100.0,
            spell(placement.height),
            placement.levels,
            placement.band,
            placement.fork as f64 / total as f64 * 100.0,
            placement.gap as f64 / total as f64 * 100.0,
            miss
        );
    }
    let deepest = rows
        .iter()
        .map(|row| row.anywhere.height.trailing_zeros())
        .max()
        .unwrap_or(0);
    let wire = u64::from(SAMPLES_BYTES + 32 * deepest) * SAMPLES as u64;
    println!(
        "\n  'height' is what the tip states, against {BLOCKS} blocks that carry the work.\n  \
         'fork at' is how far back the forgery starts, as a share of the chain's work;\n  \
         'gap/chain' how much of what it presents no block of it spans. A row whose\n  \
         'log2 miss' is above {TARGET:.0} is a forgery the shipped count does not stop.\n\n  \
         A taller forest means longer paths, and that is the only thing the height costs\n  \
         on the wire: {SAMPLES} answers at {deepest} siblings apiece is {wire} bytes,\n  \
         against the 3.1 MB a weighing of the honest chain takes and the 48 MB a node\n  \
         will hold for one.\n\n  \
         And the margin for grinding goes with it. `SAMPLES` says a forger with 2^80\n  \
         tips faces 2^80 times the chance and that 2^80 against 2^-128 is still 2^-48,\n  \
         so the margin absorbs it. Against the 40 per cent row above it does not: 2^80\n  \
         tips against a miss of 2^-58 is a certainty, and what is left holding the line\n  \
         is only the price of a tip, which is a tip's own work."
    );
}

/// The share the draw still holds to, measured rather than derived.
fn the_threshold(boards: &[Board]) {
    println!("\n\nThe largest share the count still reaches 2^{TARGET:.0} against:\n");
    println!(
        "{:>28} {:>10} {:>12}",
        "what the forger may choose", "share", "levels used"
    );
    println!("{}", "-".repeat(52));

    let mut tried = 0usize;
    let honest = &boards[0];
    for (name, held) in [
        (
            "the swept family",
            threshold(std::slice::from_ref(honest), &Sweep::Depths, &mut tried),
        ),
        (
            "band alignment",
            threshold(std::slice::from_ref(honest), &Sweep::Aligned, &mut tried),
        ),
        (
            "and the stated height",
            threshold(boards, &Sweep::Aligned, &mut tried),
        ),
    ] {
        println!("{name:>28} {:>9.2}% {:>12}", held.0 * 100.0, held.1);
    }
    println!(
        "\n  A further {tried} placements were measured for this table. The published\n  \
         figure is 40 percent, and `SAMPLES` says it was measured at 43 with three\n  \
         points held back. The first row reproduces that. The third is what a forger\n  \
         that also writes down its own height gets, and it is below the published\n  \
         figure, not above it. Every row of it is a placement whose stated height is\n  \
         priced by the gap it carries, at `MIN_DIFFICULTY` a block, so none of them is\n  \
         asking the forger for work it was not already inventing."
    );
}

/// The guarantee stated as a depth, which is how `SAMPLES` states it.
///
/// "A forger at 40% cannot put a newcomer on a branch differing from the real
/// one by more than about 1240 blocks." That is the sentence, and this is the
/// sweep behind it, run twice: once with the height the honest chain has, and
/// once with the height a forger writes down for itself.
///
/// Only depths the draw is responsible for are swept. A fork shallower than the
/// band the draw leaves unresolved, plus the retarget window under it, is caught
/// by the run up to the tip, and counting that as the draw's doing is the
/// mistake this whole file stands downstream of.
fn the_depth_guarantee(boards: &[Board], total: u128) {
    println!("\n\nHow deep a forgery can be and still get past the draw:\n");
    println!(
        "{:>7} {:>12} {:>14} {:>12} {:>14} {:>8}",
        "share", "honest", "shallowest", "chosen", "shallowest", "levels"
    );
    println!(
        "{:>7} {:>12} {:>14} {:>12} {:>14} {:>8}",
        "", "height", "through", "height", "through", ""
    );
    println!("{}", "-".repeat(72));

    for share in [0.10f64, 0.20, 0.30, 0.35, 0.40, 0.4337] {
        let honest = through_at(std::slice::from_ref(&boards[0]), share, total);
        let chosen = through_at(boards, share, total);
        println!(
            "{:>6.2}% {:>12} {:>14} {:>12} {:>14} {:>8}",
            share * 100.0,
            honest.tally(),
            honest.shallowest(),
            chosen.tally(),
            chosen.shallowest(),
            chosen
                .levels
                .map_or_else(|| "-".to_owned(), |levels| levels.to_string()),
        );
    }

    println!(
        "\n  The columns count fork depths that get through with better than 2^{TARGET:.0},\n  \
         out of the depths swept, and name the shallowest of them in blocks. The honest\n  \
         column reproduces the published sentence: nothing the draw is responsible for\n  \
         gets past it below 43 per cent. The chosen column is the same forger writing\n  \
         down a larger height, and at 40 per cent every depth the draw resolves gets\n  \
         through.\n\n  \
         The band a draw lands in is one byte modulo `levels`, so the least a band can\n  \
         be worth is `floor(256/levels)/256`: {}/256 at the honest height and {}/256 at\n  \
         2^61. Every draw a forger faces is worth the second, and the count was set from\n  \
         the first. A stated height is priced by `check_the_gaps` at `MIN_DIFFICULTY` a\n  \
         block, which on a chain worth {total} allows a stated height of\n  \
         {} before anything refuses it.",
        256 / levels_for(BLOCKS),
        256 / levels_for(1 << 61),
        total / u128::from(MIN_DIFFICULTY),
    );
}

/// Fork depths that got through, out of the ones swept.
struct Through {
    past: usize,
    swept: usize,
    first: Option<u64>,
    levels: Option<u32>,
}

impl Through {
    fn tally(&self) -> String {
        format!("{} of {}", self.past, self.swept)
    }

    fn shallowest(&self) -> String {
        self.first
            .map_or_else(|| "-".to_owned(), |depth| depth.to_string())
    }
}

/// Which fork depths, in blocks of the honest chain, get past the draw.
///
/// Every depth rather than the deepest: the density is a staircase, so a deeper
/// fork can fall in a thinner band than a shallower one, and a single number
/// reports a guarantee that forgeries on either side of it walk past.
fn through_at(boards: &[Board], share: f64, total: u128) -> Through {
    let sigma = share / (1.0 - share);
    let mut held = Through {
        past: 0,
        swept: 0,
        first: None,
        levels: None,
    };
    let mut depth = SHALLOWEST / 2;
    loop {
        let deep = u128::from(depth) * PER_BLOCK;
        let shallow = (deep as f64 * sigma) as u128;
        let gap = deep.saturating_sub(shallow);
        let mut swept = false;
        for board in boards {
            if gap == 0 || shallow < board.out_of_the_runs_reach() {
                continue;
            }
            if u128::from(board.height) * u128::from(MIN_DIFFICULTY) > gap {
                continue;
            }
            swept = true;
            let mut pieces = [(0u128, 0u128); 4];
            pieces[0] = (total - deep, total - shallow);
            if miss_log2(board.landing_in(&pieces)) > TARGET {
                held.past += 1;
                held.first = held.first.or(Some(depth));
                held.levels = Some(board.levels);
                break;
            }
        }
        if swept {
            held.swept += 1;
        }
        if depth >= BLOCKS {
            break;
        }
        depth = (depth * 1_030 / 1_000 + 1).min(BLOCKS);
    }
    held
}

/// What would have to be shown for the bound to stand.
fn the_shape_of_the_argument() {
    println!("{ARGUMENT}");
}

/// The argument, laid out at column zero so that what is printed is what is
/// written here.
const ARGUMENT: &str = "
The shape of an argument that would settle it
---------------------------------------------

The claim has three parts, and the first two hold.

1. A forger holding share `s` must invent `1 - s/(1-s)` of what it abandons.
   Arithmetic.

2. Whatever fork depth `D` it chooses, the gap it invents lies at depths
   `[sigma*D, D]` from the tip, with `sigma = s/(1-s)`. The ratio of the two
   ends is `1/sigma` whatever `D` is, which is exactly why a `1/x` density
   gives every fork depth the same weight. This is the good idea in the design
   and it survives everything below.

3. A draw therefore lands in the gap with probability `log2(1/sigma)/levels`.
   This is the step that is not a theorem, and it fails twice.

The first failure is that the shipped density is not `1/x`. It is a staircase:
a band uniformly, then a point uniformly inside it. Over a gap of fixed depth
ratio the staircase pays `p_band * (1/sigma - 1)` when the gap is pressed
against a band's shallow edge, against the smooth `log2(1/sigma)/levels`. The
two agree only where the gap is exactly one band wide; everywhere else the
staircase is lower, down to a factor of `ln 2` as `s` approaches a half, which
is where the count is set. A forger chooses where the boundaries fall by
choosing `D`, so a proof has to price the gap at the staircase's own minimum,
`min_band p_band * (1/sigma - 1)`, and not at the integral it stands for. This
failure is worth about forty bits and is already inside the published figure:
it is the difference between the derivation column above and the measured 43
per cent.

The second failure is that neither `p_band` nor `levels` is the verifier's to
set. `levels` is `bit_length(height / 1024)` and `height` is a field of the
tip; `p_band` is at worst `floor(256/levels)/256`, so it falls with `levels`
too. Nothing ties `height` to work except `check_the_gaps`, which prices an
unopened run at `MIN_DIFFICULTY` a block, and `MIN_DIFFICULTY` is one. A proof
needs a premise the protocol does not supply: that the number of bands is
bounded by something the forger cannot write down. This failure is worth twelve
points of share and is not inside the published figure.

So a proof would need three things, and the protocol as it stands supplies none
of them.

  - A ceiling `Lmax` on `levels` that no prover can raise.
  - A floor `q` on `p_band` over every band a forger can address. While the
    level is drawn from one byte this follows from `Lmax`; drawn from more, it
    stops depending on it.
  - `(1 - q*(1/sigma - 1))^count <= 2^-128` at the share being claimed, which
    is the inequality `SAMPLES` already writes down, with the per-draw term it
    should have had.

Three ways to supply the first, each a changed rule and so each a new network
number. Choosing among them is a decision rather than a patch.

  - Take `levels` from the tip's stated total work rather than its height. A
    forger then buys a band only by claiming twice the work, and claiming work
    is the one thing the draw is already looking for, so the lever closes on
    itself.
  - Name `levels` as a protocol constant, so that no field of the tip enters
    the draw at all, and set `count` from that constant. Cheapest to state, and
    the easiest to get wrong on a chain much shorter or much longer than the
    one it was named for.
  - Keep the height and price it: refuse a weighing whose stated height exceeds
    its stated work divided by something above `MIN_DIFFICULTY`, or charge an
    unopened run more than one unit a block. The only one of the three that
    leaves the draw alone, and the only one that has to argue with an honest
    chain that really did fall to the floor.

Independently of all three, the level should be drawn from more than one byte,
which `draw`'s own documentation already says, and which is what takes `p_band`
out of the forger's hands.
";

/// One share and the best placement found for it.
struct Row {
    share: f64,
    anywhere: Placement,
}

/// A gap, where it sits, and what the draw does to it.
#[derive(Clone, Copy)]
struct Placement {
    height: u64,
    levels: u32,
    band: u32,
    fork: u128,
    gap: u128,
    /// Up to four pieces of gap, as work intervals. Fixed width so a placement
    /// stays `Copy` and the sweep can keep the best without allocating.
    pieces: [(u128, u128); 4],
    miss: f64,
}

impl Placement {
    fn nothing() -> Self {
        Self {
            height: 0,
            levels: 0,
            band: 0,
            fork: 0,
            gap: 0,
            pieces: [(0, 0); 4],
            miss: f64::NEG_INFINITY,
        }
    }
}

/// Which family of fork depths to sweep.
enum Sweep {
    /// What `adversarial_placement` sweeps: depths spread evenly in ratio.
    Depths,
    /// Depths that put the gap's shallow end exactly on a band boundary.
    Aligned,
    /// The gap cut into pieces and spread across bands.
    Split,
}

/// Every draw the shipped function makes for one stated height, sorted.
struct Board {
    height: u64,
    levels: u32,
    total: u128,
    drawn: Vec<u128>,
}

impl Board {
    fn of(height: u64, total: u128, seeds: u64) -> Self {
        let mut drawn = Vec::with_capacity((seeds as usize) * SAMPLES);
        for trial in 0..seeds {
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

    /// The share of draws landing in any of the pieces.
    fn landing_in(&self, pieces: &[(u128, u128); 4]) -> f64 {
        let mut hit = 0usize;
        for (from, to) in pieces {
            if to <= from {
                continue;
            }
            let lo = self.drawn.partition_point(|work| work < from);
            let hi = self.drawn.partition_point(|work| work < to);
            hit += hi - lo;
        }
        hit as f64 / self.drawn.len() as f64
    }

    /// The shallowest depth a gap may reach before the run up to the tip is
    /// what refuses it rather than the draw.
    ///
    /// The draw resolves no finer than the top band, and the run starts a full
    /// retarget window below the deepest thing the draw pinned. A gap shallower
    /// than that is caught, but not by the draw, and counting it here is the
    /// mistake this whole file exists downstream of.
    fn out_of_the_runs_reach(&self) -> u128 {
        (self.total >> self.levels.min(127)) + u128::from(DIFFICULTY_WINDOW as u64 + 1) * PER_BLOCK
    }
}

/// The best placement in one family, on one board, for one share.
fn best_over(board: &Board, share: f64, sweep: &Sweep, tried: &mut usize) -> Placement {
    let sigma = share / (1.0 - share);
    if sigma >= 1.0 {
        return Placement::nothing();
    }
    let floor = board.out_of_the_runs_reach();
    let mut best = Placement::nothing();

    for shallow in shallow_ends(board, sweep) {
        if shallow < floor {
            continue;
        }
        let deep = (shallow as f64 / sigma) as u128;
        if deep >= board.total || deep <= shallow {
            continue;
        }
        let gap = deep - shallow;
        // The height has to be priced by the gap it is carried in: a run of
        // `height` blocks between two opened headers must state at least
        // `height * MIN_DIFFICULTY`, and the gap is what states it.
        if u128::from(board.height) * u128::from(MIN_DIFFICULTY) > gap {
            continue;
        }
        let pieces = if matches!(sweep, Sweep::Split) {
            let Some(pieces) = split(board, deep, gap, floor) else {
                continue;
            };
            pieces
        } else {
            let mut one = [(0u128, 0u128); 4];
            one[0] = (board.total - deep, board.total - shallow);
            one
        };
        *tried += 1;
        let miss = miss_log2(board.landing_in(&pieces));
        if miss > best.miss {
            best = Placement {
                height: board.height,
                levels: board.levels,
                band: band_of(shallow, board.total, board.levels),
                fork: deep,
                gap,
                pieces,
                miss,
            };
        }
    }
    best
}

/// The gap cut into four and spread over four bands, deepest piece first.
///
/// The pieces still add up to the whole gap and still sit above the fork, so
/// what moves is only which bands they fall in: the deepest piece keeps the
/// fork's own depth and each of the other three is pressed against the shallow
/// edge of the next band up. Under a density that falls with depth this cannot
/// beat one piece at the deepest place available, and it does not; it is here
/// so that the family is searched rather than assumed away.
///
/// `None` when the four cannot all be placed. A placement that puts only part
/// of the lie somewhere is not a placement: the rest of the lie is still in the
/// chain and still catchable, and scoring the fraction is how a search talks
/// itself into a result.
fn split(board: &Board, deep: u128, gap: u128, floor: u128) -> Option<[(u128, u128); 4]> {
    let total = board.total;
    let each = gap / 4;
    let mut pieces = [(0u128, 0u128); 4];
    pieces[0] = (total - deep, total - (deep - each));
    let mut ceiling = deep - each;
    let deepest = band_of(deep, total, board.levels);
    for (step, piece) in pieces.iter_mut().enumerate().skip(1) {
        let level = deepest.checked_add(u32::try_from(step).ok()?)?;
        if level >= board.levels {
            return None;
        }
        let near = total >> level.saturating_add(1).min(127);
        let far = near.checked_add(each)?;
        if near < floor || far > ceiling {
            return None;
        }
        *piece = (total - far, total - near);
        ceiling = near;
    }
    Some(pieces)
}

/// Depths for the gap's shallow end, in the family being swept.
fn shallow_ends(board: &Board, sweep: &Sweep) -> Vec<u128> {
    match sweep {
        // Every band boundary, which is where the staircase is cheapest, and a
        // geometric sweep between them so that the boundary being the optimum
        // is measured rather than assumed.
        Sweep::Aligned | Sweep::Split => {
            let mut ends: Vec<u128> = (0..board.levels)
                .map(|level| board.total >> level.saturating_add(1).min(127))
                .collect();
            let mut end = board.total;
            while end > 1 {
                ends.push(end);
                end = end * 1_000 / 1_090;
            }
            ends
        }
        // What `adversarial_placement` sweeps: depths spread evenly in ratio,
        // read as the gap's deep end and converted here to its shallow one so
        // that the two families are compared on the same axis.
        Sweep::Depths => {
            let mut ends = Vec::new();
            let mut depth = SHALLOWEST / 2;
            while depth < board.height {
                ends.push(u128::from(depth) * PER_BLOCK);
                depth = (depth * 1_020) / 1_000;
            }
            ends
        }
    }
}

/// The largest share the count still reaches the target against, to two places.
fn threshold(boards: &[Board], sweep: &Sweep, tried: &mut usize) -> (f64, u32) {
    let mut low = 0.01f64;
    let mut high = 0.50f64;
    let mut levels = 0u32;
    for _ in 0..24 {
        let middle = f64::midpoint(low, high);
        let mut best = Placement::nothing();
        for board in boards {
            let found = best_over(board, middle, sweep, tried);
            if found.miss > best.miss {
                best = found;
            }
        }
        if best.miss <= TARGET {
            levels = best.levels;
            low = middle;
        } else {
            high = middle;
        }
    }
    (low, levels)
}

/// `log2` of the chance every draw misses a gap hit with probability `hit`.
fn miss_log2(hit: f64) -> f64 {
    if hit <= 0.0 {
        return 0.0;
    }
    SAMPLES as f64 * (1.0 - hit).log2()
}

/// What the derivation in `SAMPLES` says, at one share and one level count.
fn smooth_model(share: f64, levels: u32) -> f64 {
    let sigma = share / (1.0 - share);
    let per_draw = (1.0 / sigma).log2() / f64::from(levels);
    SAMPLES as f64 * (1.0 - per_draw).log2()
}

/// Which halving band a depth from the tip falls in, counting from the deep end.
///
/// Band `level` covers depths `(total >> (level + 1), total >> level]`, so a
/// depth exactly on a boundary belongs to the deeper of the two.
fn band_of(depth: u128, total: u128, levels: u32) -> u32 {
    for level in 0..levels {
        let far = total >> level.min(127);
        let near = total >> level.saturating_add(1).min(127);
        if depth > near && depth <= far {
            return level;
        }
    }
    levels.saturating_sub(1)
}

/// Heights worth claiming: the honest one, then every doubling that
/// `check_the_gaps` still prices out of a chain worth `total`.
fn claimable_heights(total: u128) -> Vec<u64> {
    let mut heights = vec![BLOCKS];
    let ceiling = u64::try_from(total / u128::from(MIN_DIFFICULTY)).unwrap_or(u64::MAX);
    let mut height = BLOCKS.next_power_of_two();
    while height <= ceiling / 2 {
        heights.push(height);
        height *= 2;
    }
    heights
}

/// Halvings the draw spreads itself over, restated from `sampling.rs`, which
/// keeps it private and the constant it reads from public.
fn levels_for(blocks: u64) -> u32 {
    let separable = blocks / SHALLOWEST;
    u64::BITS
        .saturating_sub(separable.max(1).leading_zeros())
        .max(1)
}

/// A height as a power of two where it is one, since the table is mostly those.
fn spell(height: u64) -> String {
    if height.is_power_of_two() {
        format!("2^{}", height.trailing_zeros())
    } else {
        format!("{height}")
    }
}

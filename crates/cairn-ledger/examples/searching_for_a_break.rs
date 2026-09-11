//! Searching for a placement the sampling bound does not survive.
//!
//! `adversarial_placement` searches one family: a fork depth, the work gap that
//! depth forces, and a count of draws. Everything else it holds fixed. This
//! searches the wider family, and the wider family is where the one break this
//! project has found was found.
//!
//! Four axes, and the fourth is the one that mattered.
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
//! **Which band.** The level used to be drawn as one byte modulo `levels`,
//! which does not divide evenly, so the first `256 mod levels` bands were drawn
//! more often than the rest and a forger put its gap in one of the others. The
//! level now comes from eight bytes scaled rather than reduced, so the axis is
//! worth nothing; it is still swept, because a family nobody searches is not a
//! family nobody can use.
//!
//! **Whether the gap is one piece.** It is: the density falls with depth, so
//! splitting the lie moves part of it shallower. Searched and reported anyway,
//! for the same reason.
//!
//! **How many bands there are.** This is the axis that broke the bound, and the
//! axis the rule has since been changed under. `levels` used to be
//! `bit_length(tip.height / 1024)`, read off the tip's stated height, and a
//! height is not work: the only thing holding one down is `check_the_gaps`,
//! which asks a run of `n` blocks to be worth at least `n * MIN_DIFFICULTY`,
//! and `MIN_DIFFICULTY` is one. A chain running at difficulty `d` could state a
//! height `d` times its own and price it in work it was inventing anyway, and
//! every doubling took another slice off what each draw was worth. Nobody had
//! varied it. It was worth twelve points of the forger's share: the count
//! reached 2^-128 to 43.3 per cent against a forger taking the height as given,
//! and to 31.2 against one writing it down.
//!
//! `levels_of` is what the rule became. The halvings are counted from how old
//! the chain says it is rather than from how tall, over the block time the
//! network aims at, and never past the height. A reader refuses a tip dated
//! more than its drift allowance ahead of its own clock, so the deepest a
//! stated chain can halve is the deepest the real one can. The axis still has a
//! range, because a prover may always understate, and what it costs to
//! understate is a wider band nearest the tip and so a longer run of headers to
//! hand over: past `MOST_TAIL` the weighing is refused before a draw is looked
//! at. So this sweeps every level count a prover can reach, says which of them
//! a reader would refuse outright, and searches the rest.
//!
//! Run with `cargo run --release -p cairn-ledger --example searching_for_a_break`.

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

use cairn_ledger::pow::DIFFICULTY_WINDOW;
use cairn_ledger::sampling::{draw, levels_for, MOST_TAIL, SAMPLES, SHALLOWEST};
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

fn main() {
    let total = PER_BLOCK * u128::from(BLOCKS);
    println!(
        "A chain of {BLOCKS} blocks at difficulty {PER_BLOCK}, stating {total} work.\n\
         {SAMPLES} draws. Every number below comes from the shipped `draw`.\n"
    );

    let every: Vec<Board> = reachable_levels()
        .into_iter()
        .map(|levels| Board::of(levels, total, SEEDS))
        .collect();
    let refused: Vec<u32> = every
        .iter()
        .filter(|board| !board.weighable())
        .map(|board| board.levels)
        .collect();
    let boards: Vec<Board> = every.into_iter().filter(Board::weighable).collect();
    println!(
        "  The honest count is {} halvings, and a prover may state anything up to it.\n           {} of those are refused before a draw is looked at, because the run up to\n           the tip they ask for is past the ceiling of {MOST_TAIL} headers: {refused:?}.\n           The other {} are searched.\n",
        levels_for(BLOCKS),
        refused.len(),
        boards.len(),
    );

    let mut tried = 0usize;
    println!("What the best placement in each family is worth, by the forger's share:\n");
    println!(
        "{:>7} {:>11} {:>11} {:>11} {:>11}",
        "share", "derivation", "one band", "aligned", "any count"
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
        "\n  'derivation' is `(1 - log2(1/sigma)/levels)^{SAMPLES}` at the honest count,\n  \
         which is what `SAMPLES` computes its count from. 'one band' is the sweep\n  \
         `adversarial_placement` already does, at the honest count. 'aligned' is the\n  \
         same sweep with the gap's shallow end put on a band boundary. 'any count' adds\n  \
         every level count a prover can state to the search. {tried} placements were\n  \
         measured over {SEEDS} seeds apiece to fill this table."
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
        "{:>7} {:>8} {:>9} {:>11} {:>12} {:>10}",
        "share", "levels", "band", "fork at", "gap/chain", "log2 miss"
    );
    println!("{}", "-".repeat(64));
    for row in rows {
        let placement = row.anywhere;
        let board = Board::of(placement.levels, total, SEEDS_FOR_THE_WINNER);
        let hit = board.landing_in(&placement.pieces);
        let miss = miss_log2(hit);
        println!(
            "{:>6.2}% {:>8} {:>9} {:>10.4}% {:>11.5}% {:>10.1}",
            row.share * 100.0,
            placement.levels,
            placement.band,
            placement.fork as f64 / total as f64 * 100.0,
            placement.gap as f64 / total as f64 * 100.0,
            miss
        );
    }
    println!(
        "\n  'levels' is how many halvings the tip's own age buys it, against the {}\n  \
         the honest chain of {BLOCKS} blocks gets. 'fork at' is how far back the\n  \
         forgery starts, as a share of the chain's work; 'gap/chain' how much of what\n  \
         it presents no block of it spans. A row whose 'log2 miss' is above\n  \
         {TARGET:.0} is a forgery the shipped count does not stop.\n\n  \
         The margin for grinding survives with the figure. `SAMPLES` says a forger\n  \
         with 2^80 tips faces 2^80 times the chance and that 2^80 against 2^-128 is\n  \
         still 2^-48, so the margin absorbs it. When the level count could be written\n  \
         down that was no longer true: 2^80 tips against a miss of 2^-58 is a\n  \
         certainty, and all that held the line was the price of a tip.",
        levels_for(BLOCKS),
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
            "and the stated level count",
            threshold(boards, &Sweep::Aligned, &mut tried),
        ),
    ] {
        println!("{name:>28} {:>9.2}% {:>12}", held.0 * 100.0, held.1);
    }
    println!(
        "\n  A further {tried} placements were measured for this table. The published\n  \
         figure is 40 percent, and `SAMPLES` says it was measured at 42.96. The\n  \
         first row reproduces that. The third adds every level\n  \
         count a prover can state, and it does not move: understating the count makes\n  \
         each draw worth more, and overstating it is what the tip's own age refuses.\n  \
         When the count came off the stated height instead, this row read 31.2."
    );
}

/// The guarantee stated as a depth, which is how `SAMPLES` states it.
///
/// "A forger at 40% cannot put a newcomer on a branch differing from the real
/// one by more than about 1240 blocks." That is the sentence, and this is the
/// sweep behind it, run twice: once at the count the honest chain's own age
/// buys, and once over every count a prover could state instead.
///
/// Only depths the draw is responsible for are swept. A fork shallower than the
/// band the draw leaves unresolved, plus the retarget window under it, is caught
/// by the run up to the tip, and counting that as the draw's doing is the
/// mistake this whole file stands downstream of.
fn the_depth_guarantee(boards: &[Board], total: u128) {
    println!("\n\nHow deep a forgery can be and still get past the draw:\n");
    println!(
        "{:>7} {:>12} {:>14} {:>12} {:>14} {:>8}",
        "share", "honest", "shallowest", "any", "shallowest", "levels"
    );
    println!(
        "{:>7} {:>12} {:>14} {:>12} {:>14} {:>8}",
        "", "count", "through", "count", "through", ""
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
         gets past it below 42.96 per cent. The second column lets the forger state any\n  \
         level count a reader would accept, and it does not move.\n\n  \
         It used to. When the count came off the tip's stated height, a forger at 40\n  \
         per cent got every depth the draw resolves through: `check_the_gaps` prices\n  \
         an unopened run at one unit a block, so a chain worth {total} priced a\n  \
         stated height of as many blocks, and that bought {} halvings against the\n  \
         honest {}.",
        levels_for(u64::try_from(total).unwrap_or(u64::MAX)),
        levels_for(BLOCKS),
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

The second failure was that neither `p_band` nor `levels` was the verifier's to
set, and this is the one the rule has since been changed under. `levels` was
`bit_length(height / 1024)` and `height` is a field of the tip; `p_band` was at
worst `floor(256/levels)/256`, so it fell with `levels` too. Nothing tied
`height` to work except `check_the_gaps`, which prices an unopened run at
`MIN_DIFFICULTY` a block, and `MIN_DIFFICULTY` is one. That failure was worth
twelve points of share and was not inside the published figure.

A proof would need three things, and the protocol now supplies two of them.

  - A ceiling `Lmax` on `levels` that no prover can raise. `levels_of` is that
    ceiling: the count comes from how old the tip says the chain is, over the
    block time the network aims at, and a reader refuses a tip dated more than
    its drift allowance past its own clock. So `Lmax` is the honest chain's own
    count, and a prover reaches it rather than passing it. Understating is left
    open and costs the prover: fewer halvings means a wider band nearest the
    tip, and that band is a run of headers it has to hand over in full, refused
    past `MOST_TAIL`.
  - A floor `q` on `p_band` over every band a forger can address. The level is
    drawn from eight bytes scaled by `levels` rather than one byte reduced by
    it, so `q` is `1/levels` to within one part in 2^64 and no longer depends
    on how the byte divides.
  - `(1 - q*(1/sigma - 1))^count <= 2^-128` at the share being claimed, which
    is the inequality `SAMPLES` already writes down, with the per-draw term it
    should have had. This one is still not proved here. What is measured is
    that no placement this file can construct beats it.

Two ways of supplying the first were considered and not taken. Naming `levels`
as a protocol constant puts no field of the tip in the draw at all, and is the
easiest to get wrong on a chain much shorter or much longer than the one the
constant was named for. Pricing the height, by charging an unopened run more
than one unit a block, leaves the draw alone and has to argue with an honest
chain that really did fall to the floor. The age was taken because it is the
only one of the three whose ceiling a reader can check against something it
holds itself.
";

/// One share and the best placement found for it.
struct Row {
    share: f64,
    anywhere: Placement,
}

/// A gap, where it sits, and what the draw does to it.
#[derive(Clone, Copy)]
struct Placement {
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

/// Every draw the shipped function makes for one stated level count, sorted.
struct Board {
    levels: u32,
    total: u128,
    drawn: Vec<u128>,
}

impl Board {
    fn of(levels: u32, total: u128, seeds: u64) -> Self {
        let mut drawn = Vec::with_capacity((seeds as usize) * SAMPLES);
        for trial in 0..seeds {
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
    /// unresolved, plus a retarget window. Past `MOST_TAIL` headers a reader
    /// refuses the weighing before it looks at a single draw, so a forger that
    /// states too few halvings has refused its own forgery.
    fn weighable(&self) -> bool {
        let band = self.total >> self.levels.min(127);
        let blocks = band / PER_BLOCK + u128::from(DIFFICULTY_WINDOW as u64) + 1;
        blocks <= u128::from(MOST_TAIL)
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
            while depth < BLOCKS {
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

/// Level counts a prover can reach on this chain, honest one first.
///
/// The ceiling is the honest count, because that is what the reader's clock
/// allows: a tip cannot say the network has been running longer than it has.
/// Everything below it a prover may state freely, so everything below it is
/// searched, and the ones a reader would refuse for the length of the run they
/// demand are marked rather than dropped.
fn reachable_levels() -> Vec<u32> {
    (1..=levels_for(BLOCKS)).rev().collect()
}

//! The figures the paper publishes, measured against the build that serves it.
//!
//! The explorer compiles the whitepaper into its own binary, so the paper and
//! the code ship as one thing and can be checked as one thing. Every figure
//! here is deterministic: a block of a named shape encodes to a fixed number
//! of bytes, and thirty years of them at a block a minute is a multiplication.
//! Timings are not, so they are printed and not asserted.
//!
//! This exists because the table went stale twice over in six days and nothing
//! noticed. The header grew by the forty-eight bytes of the two commitments
//! the paper's own section 7 describes, and the header row was corrected while
//! the two block rows were not, so the table disagreed with itself by exactly
//! the number it stated elsewhere. Underneath that, the instrument the block
//! rows came from asked for sixty-four transfers a block and could only fund
//! sixteen, because a coinbase carries at most sixteen outputs and the purse
//! it spent from was refilled by the coinbase alone. So a figure labelled
//! "64 transfers" was the cost of sixteen, and every quantity built on it, the
//! thirty-year download included, was short by the same factor.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::print_stdout
)]

use cairn_accumulator::forest::tree_of;
use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::sampling::{draw, levels_for, open_start, seed_of, MOST_TAIL, SAMPLES};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const PAPER: &str = include_str!("../../../docs/cairn-whitepaper.html");
const SPECIFICATION: &str = include_str!("../../../docs/cairn-specification.html");
const README: &str = include_str!("../../../README.md");
const DESIGN: &str = include_str!("../../../docs/cairn-design.html");
/// The survey of what already exists, which a node serves at `/prior-art`.
///
/// It had no guard at all until this line was written, and it publishes the
/// cap, the header, the forest and the grace window, every one of them a
/// figure this build decides.
const PRIOR_ART: &str = include_str!("../../../docs/cairn-prior-art.html");
const SITE_EN: &str = include_str!("../../../web/i18n/en.json");
const SITE_FR: &str = include_str!("../../../web/i18n/fr.json");
/// The source that acts on the cap, which quotes the same two figures in the
/// comment explaining why it reports what it reports. Included here because
/// the last published figure to go stale had a guard already, in a file the
/// guard did not reach.
const NET_NODE: &str = include_str!("../../cairn-net/src/node.rs");

/// Thirty years of a block a minute, which is what both tables are about.
const THIRTY_YEARS: u64 = 30 * 365 * 24 * 60;

/// A value from the parameter list, by the label beside it.
fn parameter(label: &str) -> String {
    let key = format!("<span class=\"k\">{label}</span><span class=\"v\">");
    let rest = PAPER
        .split_once(&key)
        .unwrap_or_else(|| panic!("the paper no longer lists `{label}`"))
        .1;
    rest.split_once("</span>")
        .expect("a closed span")
        .0
        .trim()
        .to_owned()
}

/// The size column of a row of the thirty-year table, by the quantity it names.
fn table_row(label: &str) -> String {
    let key = format!("<td>{label}</td>");
    let rest = PAPER
        .split_once(&key)
        .unwrap_or_else(|| panic!("the paper no longer has a row for `{label}`"))
        .1;
    let cell = rest.split_once("<td class=\"n\">").expect("a size cell").1;
    cell.split_once("</td>")
        .expect("a closed cell")
        .0
        .trim()
        .to_owned()
}

/// The small numbers the French papers write in words rather than digits.
///
/// A word is as much a published figure as a numeral, and this is the whole
/// of what makes one checkable. A number nobody has taught this test the word
/// for stops the test rather than passing quietly.
fn in_french(value: usize) -> &'static str {
    match value {
        8 => "huit",
        64 => "soixante-quatre",
        other => panic!(
            "the French papers write their small figures in words and this test \
             has no word for {other}"
        ),
    }
}

/// The number beside the section whose heading is `heading`.
///
/// Section numbers are counted by `cairn-docs` and never typed, except in the
/// one place a document points at a section in its own prose. That is the
/// only place left where the number a reader is sent to and the number the
/// section carries can part company.
fn section_number(page: &str, heading: &str) -> String {
    let above = page
        .split_once(&format!("<h2>{heading}</h2>"))
        .unwrap_or_else(|| panic!("no section of this page is headed `{heading}`"))
        .0;
    let rail = above
        .rsplit_once("<div class=\"num\">")
        .expect("a section carries its number beside it")
        .1;
    rail.trim_start_matches("<span>")
        .chars()
        .take_while(char::is_ascii_digit)
        .collect()
}

/// The figure a page writes immediately before `phrase`.
///
/// For a number the page quotes from somewhere else: read out of the page
/// rather than written down here, so that a comparison against it is the
/// document's own comparison and not a second copy of it.
fn figure_before(page: &str, phrase: &str) -> usize {
    let before = page
        .split_once(phrase)
        .unwrap_or_else(|| panic!("the page no longer says `{phrase}`"))
        .0;
    let mut digits: Vec<char> = before
        .chars()
        .rev()
        .take_while(|character| character.is_ascii_digit() || *character == ' ')
        .filter(char::is_ascii_digit)
        .collect();
    digits.reverse();
    digits
        .iter()
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("no figure stands before `{phrase}`"))
}

/// A figure written the way the paper writes one: a space every three digits.
fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(' ');
        }
        out.push(digit);
    }
    out
}

/// A chain the measured blocks are built on, with a purse of notes to spend.
struct Bench {
    params: ConsensusParams,
    state: LedgerState,
    miner: SecretKey,
    spender: SecretKey,
    purse: Vec<(NoteId, Note)>,
    clock: u64,
}

impl Bench {
    /// `payments` is how many notes each filling block puts in the purse.
    fn new(fill: usize) -> Self {
        let params = ConsensusParams::testnet().with_coinbase_maturity(0);
        let mut bench = Self {
            params,
            state: LedgerState::new(),
            miner: SecretKey::from_bytes(&[1; 32]),
            spender: SecretKey::from_bytes(&[2; 32]),
            purse: Vec::new(),
            clock: 1_000,
        };
        let each = Amount::from_pebbles(
            params.initial_reward.as_pebbles() / params.max_coinbase_outputs as u64,
        )
        .unwrap();
        for _ in 0..fill {
            let height = bench.state.next_height().unwrap();
            bench.clock += 60;
            let outputs: Vec<Note> = (0..bench.params.max_coinbase_outputs)
                .map(|_| Note::new(each, bench.spender.public_key()))
                .collect();
            let coinbase = CoinbaseTransaction::new(height, outputs);
            let block = assemble_block(
                &bench.state,
                coinbase,
                Vec::<Transfer>::new(),
                &bench.params,
                bench.clock,
                0,
            )
            .unwrap();
            connect_block(&mut bench.state, &block, &bench.params, u64::MAX / 2).unwrap();
            bench.purse.extend(block.coinbase.created_notes());
        }
        bench
    }

    /// One ordinary payment: the note in, the payee out, and the change back.
    fn payment(&mut self) -> Transfer {
        let (id, note) = self.purse.pop().expect("a note to spend");
        let half = Amount::from_pebbles(note.value.as_pebbles() / 2).unwrap();
        let mut transfer = Transfer::new(
            vec![Input::hot(id)],
            vec![
                Note::new(half, self.miner.public_key()),
                Note::new(half, self.spender.public_key()),
            ],
        );
        transfer.sign_input(self.params.network, 0, &note, &self.spender);
        transfer
    }

    /// A block whose coinbase pays one output, carrying `payments` of them.
    fn block(&mut self, payments: usize) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 60;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(
                self.params.initial_reward,
                self.miner.public_key(),
            )],
        );
        let transfers: Vec<Transfer> = (0..payments).map(|_| self.payment()).collect();
        assert_eq!(transfers.len(), payments, "every payment was funded");
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        connect_block(&mut self.state, &block, &self.params, u64::MAX / 2).unwrap();
        block
    }
}

/// The three byte figures in the parameter list are the ones this build
/// produces.
///
/// The header is the only one that ever agreed. The empty block was 196 and
/// the busy one 3 211, which are both exactly forty-eight bytes short: the
/// figures predate the two header commitments and were never taken again. The
/// busy one was short by a good deal more than that besides, because it was
/// measured on blocks carrying sixteen payments and published as sixty-four.
#[test]
fn the_papers_block_sizes_are_the_sizes_this_build_encodes() {
    let mut bench = Bench::new(8);
    let empty = bench.block(0);
    let busy = bench.block(64);
    let payment = {
        let mut one = Bench::new(1);
        one.payment().encode().len()
    };

    let header = empty.header.encode().len();
    let empty = empty.encode().len();
    let busy = busy.encode().len();
    println!("header {header}, empty block {empty}, 64 payments {busy}, one payment {payment}");

    assert_eq!(parameter("Header size"), format!("{header} bytes"));
    assert_eq!(parameter("Empty block"), format!("{empty} bytes"));
    assert_eq!(
        parameter("Block with 64 ordinary payments"),
        format!("{} bytes", grouped(busy as u64))
    );
    assert_eq!(
        parameter("Ordinary payment"),
        format!("{payment} bytes"),
        "the shape every other figure here is quoted in"
    );
}

/// The thirty-year table is the block size it names, multiplied out.
///
/// Decimal gigabytes, as the rest of the paper counts. The two rows checked
/// here were 48 GB and 2 GB, and the instrument they came from divided by
/// 1 073 741 824 while writing GB, so even the arithmetic they did do was in
/// the other unit from the figures beside them.
#[test]
fn the_papers_thirty_year_totals_are_the_sizes_it_names_multiplied_out() {
    let mut bench = Bench::new(8);
    let empty = bench.block(0);
    let header = empty.header.encode().len() as u64;
    let busy = bench.block(64).encode().len() as u64;

    let blocks = (THIRTY_YEARS * busy) as f64 / 1e9;
    let headers = (THIRTY_YEARS * header) as f64 / 1e9;
    println!("thirty years: {blocks:.0} GB of blocks, {headers:.1} GB of headers");

    assert_eq!(
        table_row("All blocks, to download"),
        format!("{blocks:.0} GB")
    );
    assert_eq!(
        table_row("All headers, to read"),
        format!("{headers:.1} GB")
    );
}

/// What a node keeps for ever is a header and its place in the forest, not a
/// header alone.
///
/// The paper said "182 bytes a header: 129 MB a year" twice, and 182 bytes a
/// header is 95.7 MB a year. The missing third is the forest node each header
/// adds, which is the half that makes the figure the price of being able to
/// take in a newcomer rather than the price of keeping headers.
#[test]
fn the_headers_a_year_figure_counts_the_forest_the_headers_make() {
    let mut bench = Bench::new(1);
    let header = bench.block(0).header.encode().len() as u64;
    // A leaf and the inner node above it, which is what a forest holds per
    // item; the same figure `cairn-chain/examples/archivist.rs` counts with.
    let forest_node = 64u64;
    let a_year = 365 * 24 * 60;
    let each = header + forest_node;
    let megabytes = (a_year * each) as f64 / 1e6;
    println!("{each} bytes a block kept for ever, {megabytes:.0} MB a year");

    assert_eq!(format!("{megabytes:.0} MB"), "129 MB");
    assert!(
        PAPER.contains(&format!(
            "{header} bytes a header and {forest_node} for its place in the forest"
        )),
        "the paper has to say what the 129 MB is made of"
    );
}

/// The README quotes the number of headers a newcomer actually opens.
///
/// It said 512 in the paragraph that describes joining and 4 096 in the one
/// that describes the correction, two pages apart, and 512 is the figure the
/// second paragraph exists to disown.
#[test]
fn the_readme_quotes_the_draw_count_this_build_uses() {
    let draws = grouped(cairn_ledger::sampling::SAMPLES as u64);
    assert!(
        README.contains(&format!("draws {draws} old headers")),
        "the README describes joining with a draw count this build does not use"
    );
    assert!(
        !README.contains("draws 512 old headers"),
        "512 is the count the README itself says was wrong"
    );
}

/// The paper's limitations do not name an omission this build has closed.
///
/// Section 4.3 said there was no message by which a wallet could ask an
/// archivist for a proof, and that a wallet whose node had not kept the
/// position had nowhere to turn. The message set carries `GetProofs` and
/// `Proofs`; the wallet asks with them, dials for an archivist when it knows
/// none, and folds every answer against a root its own node worked out. A
/// limitations section is the first thing an outside reviewer reads, so a
/// closed hole left standing in it costs more than an open one stated plainly.
#[test]
fn the_papers_limitations_do_not_name_a_hole_the_protocol_has_closed() {
    // Referencing them is the check: these compile only while the wire has
    // them, and this test exists to fail on the day one is removed.
    let asked = cairn_net::Message::GetProofs(vec![7]);
    let answered = cairn_net::Message::Proofs(Vec::new());
    assert_eq!(asked.kind(), "get proofs");
    assert_eq!(answered.kind(), "proofs");

    assert!(
        !PAPER.contains(
            "there is no\n      message in this protocol by which a wallet can ask an archivist"
        ),
        "the paper still states an omission the message set has closed"
    );
    assert!(
        PAPER.contains("A wallet now asks for the paths it is missing"),
        "and it has to say what closed it"
    );
}

/// A chain long enough to take a real sampled weighing off, with the forest
/// the headers make so that every draw can be proved.
struct Weighed {
    headers: Vec<BlockHeader>,
    history: Archive,
    state: LedgerState,
}

impl Weighed {
    fn new(blocks: usize) -> Self {
        let params = ConsensusParams::testnet();
        let miner = SecretKey::from_bytes(&[3; 32]);
        let mut built = Self {
            headers: Vec::new(),
            history: Archive::new(),
            state: LedgerState::new(),
        };
        let mut clock = 1_000u64;
        for _ in 0..blocks {
            let height = built.state.next_height().unwrap();
            clock += 60;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(
                &built.state,
                coinbase,
                Vec::<Transfer>::new(),
                &params,
                clock,
                0,
            )
            .unwrap();
            connect_block(&mut built.state, &block, &params, u64::MAX / 2).unwrap();
            built.history.add(header_leaf(&block.header.id())).unwrap();
            built.headers.push(block.header);
        }
        built
    }
}

/// What weighing a thirty year chain costs is what this build puts on the wire
/// for one.
///
/// The paper said 9 MB in three places, the site in two more and in two
/// languages, the README once, and one of the French papers said 8. The
/// encoder puts 3.3 MB on the wire. The figure came from
/// `cairn-ledger/examples/joining.rs`, which prices every one of the 4 096
/// paths at sixty four levels and every header at its size in memory: sixty
/// four is how many trees a forest can hold at 2^64 leaves, and the deepest
/// tree over thirty years of blocks is twenty three levels. Beside it,
/// `cairn-ledger/examples/history.rs` counts the same thing at the depth each
/// draw actually lands at and says three, and so does the doc comment on
/// `sampling::SAMPLES`. Two instruments for one published figure, differing by
/// three times over, and the papers quoted the louder one.
///
/// Neither instrument is what goes on the wire, so neither is used here. A real
/// weighing is taken off a chain this test mines and taken apart: what does not
/// grow with the chain is measured, and what does is the one path per draw. The
/// model is checked against the encoder to the byte before it is applied at a
/// height nothing can mine to.
#[test]
fn the_papers_weighing_is_the_size_this_build_encodes() {
    let built = Weighed::new(2_048);
    let tip = *built.headers.last().unwrap();
    let start = open_start(
        &tip,
        built.state.headers_before_tip(),
        SAMPLES,
        &ConsensusParams::testnet(),
        |height| {
            usize::try_from(height)
                .ok()
                .and_then(|at| built.headers.get(at))
                .copied()
        },
        |height| built.history.prove_in(height, tip.height),
    )
    .expect("a weighing of a chain this node holds whole");

    // A sample is a header and a path, and a path is a sibling per level of the
    // tree its leaf sits in. Checked against the encoder rather than asserted
    // of it: this equality is the whole licence for the arithmetic below.
    let encoded = start.encode().len();
    let samples = start.samples.encode().len();
    let levels: usize = start.samples.iter().map(|s| s.proof.depth()).sum();
    let per_sample = start.tip.encode().len() + 4;
    assert_eq!(
        samples,
        4 + SAMPLES * per_sample + 32 * levels,
        "a weighing is no longer a header and a path per draw, so what follows \
         is no longer arithmetic about this encoder"
    );

    // Everything else in a weighing is the same at any height: the tip, the
    // header below it, and the run from the deepest draw up to the tip, which
    // is a fixed distance because the draw stops resolving there.
    let fixed = encoded - samples;
    let thirty = THIRTY_YEARS;
    let leaves = thirty - 1;
    let mut levels_then = 0u64;
    for at in draw(
        seed_of(&tip),
        SAMPLES,
        u128::from(thirty),
        levels_for(thirty),
    ) {
        let position = u64::try_from(at).unwrap_or(0);
        levels_then += tree_of(leaves, position).map_or(0, |(depth, _)| depth) as u64;
    }
    let roots = u64::from(leaves.count_ones()) - u64::from(tip.height.count_ones());
    let whole =
        fixed as u64 + 4 + SAMPLES as u64 * per_sample as u64 + 32 * levels_then + 32 * roots;
    let megabytes = whole as f64 / 1e6;
    println!(
        "a weighing is {encoded} bytes over {} blocks and {whole} over thirty years, {megabytes:.2} MB",
        built.headers.len(),
    );

    // No path can be longer than the deepest tree a forest of this many leaves
    // holds, so this is the most a weighing can ever come to at that height.
    let deepest = 63 - u64::from(leaves.leading_zeros());
    let most = fixed as u64
        + 4
        + SAMPLES as u64 * per_sample as u64
        + 32 * deepest * SAMPLES as u64
        + 32 * roots;
    assert!(
        whole <= most,
        "{whole} is past the {most} a forest {deepest} levels deep can cost"
    );

    let stated = format!("about {megabytes:.0} MB");
    assert!(
        PAPER.contains(&format!("Weighing a thirty year chain costs {stated}")),
        "the paper does not say weighing costs {stated}"
    );
    assert!(
        PAPER.contains(&format!("{stated} to weigh the\n      chain")),
        "the paper's arrival note does not say weighing costs {stated}"
    );
    assert!(
        README.contains("about\nthree megabytes against the hundred and ninety-seven gigabytes"),
        "the README does not say what weighing costs in the same figure"
    );
    assert!(
        PRIOR_ART.contains(&format!(
            "environ {megabytes:.0} Mo pour rejoindre trente ans de"
        )),
        "the survey paper's next-steps list does not say weighing costs \
         {megabytes:.0} Mo, which is what this build puts on the wire"
    );
}

/// What a newcomer validates for itself is the block limit times the window,
/// counted the way the rest of the paper counts.
///
/// The note under the table said "at most 128 MB" and then, of the same
/// quantity in the next sentence, "under 150 MB on a saturated one", so the
/// ceiling it named was smaller than the figure it gave for reaching it. 128 MB
/// is the limit times the window in binary megabytes, and every other size in
/// the paper is decimal: the same bytes are 134.
#[test]
fn the_burial_a_newcomer_validates_is_the_block_limit_times_the_window() {
    let params = ConsensusParams::testnet();
    let blocks = cairn_chain::MAX_REORG_DEPTH;
    let bytes = blocks * params.max_block_bytes;
    let megabytes = bytes as f64 / 1e6;
    println!(
        "{blocks} blocks at {} bytes each is {megabytes:.0} MB",
        params.max_block_bytes
    );

    assert!(
        PAPER.contains(&format!("at most {megabytes:.0} MB")),
        "the paper does not say the burial is at most {megabytes:.0} MB"
    );
    assert!(
        !PAPER.contains("under\n      150 MB on a saturated one"),
        "the paper still names a saturated figure above the ceiling beside it"
    );
}

/// The French papers say what arriving costs, and it has to be the same cost
/// the English one is held to.
///
/// It was not. It said forty eight gigabytes to download thirty years of
/// chain and a hundred megabytes of state at the end of it. The first is the
/// figure from before the instrument was fixed: the bench asked for sixty
/// four transfers a block and could fund sixteen, so every quantity built on
/// it was short by four times over, and 197 GB is what the corrected one
/// gives. The second is the hot set from before it was re-measured, 107 MB
/// against 68.
///
/// Both had already been corrected everywhere a test could see them. The
/// guard against the old hot-set figure runs over the two lesson files and
/// the whitepaper and not over this document, and nothing at all looked at
/// the download. A paper nothing reads is a paper that keeps whatever it was
/// last told, and this one is the one a French reader is sent to first.
///
/// The survey paper repeats the same download beside what replaces it, and
/// was read by nothing at all until it was added here.
#[test]
fn the_french_papers_quote_the_arrival_the_english_one_is_held_to() {
    let mut bench = Bench::new(8);
    let busy = bench.block(64).encode().len() as u64;
    let header = bench.block(0).header.encode().len() as u64;
    let blocks = (THIRTY_YEARS * busy) as f64 / 1e9;
    let headers = (THIRTY_YEARS * header) as f64 / 1e9;
    let state = table_row("Validation state a node holds");
    let megabytes = state.strip_suffix(" MB").expect("a size in megabytes");
    println!("arriving costs {blocks:.0} GB against {headers:.1} GB of headers, for {state}");

    for said in [
        format!("{blocks:.0} gigaoctets à télécharger"),
        format!("un état qui en pèse {megabytes} Mo"),
        format!(
            "au lieu de {} gigaoctets",
            format!("{headers:.1}").replace('.', ",")
        ),
    ] {
        assert!(
            DESIGN.contains(&said),
            "the design paper does not say `{said}`, which is what the English one \
             is held to and what this build encodes"
        );
    }
    let said = format!("contre les {blocks:.0} Go qu'ils");
    assert!(
        PRIOR_ART.contains(&said),
        "the survey paper does not say `{said}`, which is the download its own \
         next-steps list says the weighing replaces"
    );
}

/// The survey paper weighs our header against the one it quotes, and the
/// ratio it prints has to be the ratio those two figures make.
///
/// This is the paper's headline finding, in the panel above the first
/// section and again in the card the finding comes from: their headers are
/// 1 487 bytes, ours are 182, so ours are eight times smaller. Nothing held
/// either end of that. The header grew by forty eight bytes once already,
/// when the two commitments went in, and the day it grows again "eight times"
/// becomes seven and the sentence a reader trusts most in this document is
/// the one that went stale first.
///
/// Their figure is read out of the page rather than written down here: the
/// comparison is the document's own, and this test checks the arithmetic on
/// it rather than replacing it.
#[test]
fn the_survey_papers_headers_are_eight_times_smaller_because_this_build_encodes_them_so() {
    let mut bench = Bench::new(1);
    let ours = bench.block(0).header.encode().len();
    let theirs = figure_before(PRIOR_ART, " octets chacun sur cette chaîne");
    let times = theirs.checked_div(ours).expect("a header of some size");
    println!("their header is {theirs} bytes against our {ours}, {times} times");

    for said in [
        format!(
            "en-tête fait {ours} octets, {} fois moins",
            in_french(times)
        ),
        format!("Les nôtres sont {} fois plus petits", in_french(times)),
        format!("Les nôtres font {ours} octets."),
    ] {
        assert!(
            PRIOR_ART.contains(&said),
            "the survey paper does not say `{said}`, which is what this build \
             encodes and what its own quoted figure divides by"
        );
    }
}

/// What the survey paper's tables say Cairn bounds is what this build bounds.
///
/// The tables and the ledger set Cairn beside what everybody else built, and
/// every Cairn cell in them is a rule this build applies: the size of the hot
/// set, the hashes a node carries for everything else, and the grace window
/// that makes the boundary a guarantee rather than a hope. A comparison is
/// only worth reading if its own column is true.
#[test]
fn the_survey_papers_tables_bound_what_this_build_bounds() {
    let params = ConsensusParams::testnet();
    let notes = grouped(params.hot_capacity as u64);
    let roots = cairn_accumulator::forest::MAX_HEIGHT;
    let grace = cairn_ledger::state::GRACE_BLOCKS;
    println!("{notes} hot notes, {roots} roots, {grace} blocks of grace");

    for said in [
        format!("Le tiroir : {notes} billets, un nombre"),
        format!("Oui, {notes} billets"),
        format!("{notes} est un effectif"),
        format!("chaque nœud garde {roots} empreintes"),
        format!("tout le reste en {} empreintes", in_french(roots)),
        format!("Nos {} blocs de grâce", in_french(grace)),
        format!("Chez nous, {} blocs de grâce", in_french(grace)),
    ] {
        assert!(
            PRIOR_ART.contains(&said),
            "the survey paper does not say `{said}`, which is what this build \
             holds a node to"
        );
    }
}

/// A section a paper sends a reader to is the section that is there.
///
/// `cairn-docs` counts the section numbers, so no heading carries one that
/// can go stale. A cross-reference in prose does: "the whitepaper devotes its
/// section 8 to it" is a number typed by a person about a number counted by a
/// program, and inserting a section anywhere above either of them moves one
/// and not the other. This paper makes two such references, one to the
/// English paper and one to itself.
#[test]
fn the_survey_paper_sends_a_reader_to_the_sections_that_are_there() {
    let dilemma = section_number(PAPER, "The limit that applies, and where Cairn falls");
    let closest = section_number(
        PRIOR_ART,
        "L'expiration d'état d'Ethereum, prise comme une construction",
    );
    println!(
        "the dilemma is section {dilemma} of the whitepaper, the neighbour section {closest} here"
    );

    for said in [
        format!("le whitepaper y consacre sa section {dilemma}."),
        format!("section {closest}. Ce qui reste revendiqué"),
    ] {
        assert!(
            PRIOR_ART.contains(&said),
            "the survey paper does not say `{said}`, and a reader sent to a \
             section that has moved is sent to the wrong one"
        );
    }
}

/// The proof a holder carries is the size the papers say it is.
///
/// Both French papers publish it, the design paper as the four rows of the
/// table its whole thesis is in and the survey paper as the range between
/// their ends, and it is the figure that answers the one objection this
/// design invites: if the node holds nothing, what does the holder hold. It
/// was measured once by `cairn-accumulator/examples/scale.rs` and typed into
/// two documents, and nothing has looked at it since.
///
/// Measured here exactly as that example measures it, sampling evenly across
/// the set, because an average over a different sample is a different figure.
#[test]
fn the_french_papers_quote_the_proof_a_holder_carries() {
    use cairn_accumulator::{Key, SparseMerkleTree};
    use cairn_primitives::hash::{hash, Domain};

    let key = |index: u64| Key::from_hash(hash(Domain::StateEntry, &index.to_le_bytes()));
    let mut tree = SparseMerkleTree::new();
    let mut filled = 0u64;
    let mut average = Vec::new();
    for notes in [1_000u64, 10_000, 100_000, 1_000_000] {
        while filled < notes {
            tree.insert(key(filled), hash(Domain::MerkleLeaf, &filled.to_le_bytes()));
            filled += 1;
        }
        let sampled = 2_000u64.min(notes);
        let step = notes / sampled;
        let total: usize = (0..sampled)
            .map(|sample| tree.prove(key(sample * step)).size_in_bytes())
            .sum();
        average.push((notes, total / usize::try_from(sampled).unwrap_or(1)));
    }
    for (notes, bytes) in &average {
        println!("{notes} notes: a proof is {bytes} bytes on average");
    }
    let (_, smallest) = average.first().expect("a measured size");
    let (_, largest) = average.last().expect("a measured size");

    assert!(
        PRIOR_ART.contains(&format!("{smallest} à {largest} octets mesurés")),
        "the survey paper does not say a proof is {smallest} to {largest} bytes, \
         which is what this build measures at the ends of the design paper's table"
    );
    for (notes, bytes) in &average {
        let said = format!("<td class=\"num\">{bytes} o</td>");
        assert!(
            DESIGN.contains(&said),
            "the design paper's table has no row saying a proof at {notes} notes \
             is {bytes} bytes"
        );
    }
}

/// Blocks in a year at a block a minute, which is what the cliff below is
/// measured in.
const A_YEAR: u64 = 365 * 24 * 60;

/// A chain that ran at one difficulty and then, after losing most of its hash
/// rate, at a lower one.
///
/// Piecewise linear in work, so the block covering a drawn work value is
/// arithmetic rather than a search: a chain of thirty years is fifteen million
/// blocks, and materialising one per point of the sweep below is minutes.
///
/// The step is instant here and is not on a real chain: the retarget moves by
/// at most a factor of four a block and lags by a window, so a fall of five
/// hundred takes a handful of blocks to arrive. Against the tens of thousands
/// of blocks the answer is measured in, that is nothing, and it errs towards
/// the chain being weighable rather than away from it.
struct Fallen {
    before: u64,
    high: u128,
    low: u128,
    blocks: u64,
}

impl Fallen {
    fn new(age: u64, factor: u64, since: u64) -> Self {
        const HIGH: u64 = 1_000_000;
        Self {
            before: age - since,
            high: u128::from(HIGH),
            low: u128::from((HIGH / factor).max(1)),
            blocks: age,
        }
    }

    fn total_at(&self, height: u64) -> u128 {
        if height < self.before {
            (u128::from(height) + 1) * self.high
        } else {
            u128::from(self.before) * self.high + (u128::from(height - self.before) + 1) * self.low
        }
    }

    /// The lowest height whose own work spans `work`, which is where a draw
    /// lands. The rule `sampling::covering` applies, in closed form.
    fn covering(&self, work: u128) -> u64 {
        let joint = u128::from(self.before) * self.high;
        if work < joint {
            u64::try_from(work / self.high).unwrap_or(0)
        } else {
            self.before + u64::try_from((work - joint) / self.low).unwrap_or(0)
        }
    }

    /// The run of headers `check_the_tail` demands of this chain: a full
    /// retarget window below the deepest header the draw pinned, up to the tip.
    fn run_wanted(&self, seed: u8) -> u64 {
        let window = u64::try_from(cairn_ledger::pow::DIFFICULTY_WINDOW).unwrap();
        let tip = self.blocks - 1;
        let difficulty = if tip < self.before {
            self.high
        } else {
            self.low
        };
        let behind = self.total_at(tip) - difficulty;
        let pinned = draw(
            cairn_primitives::Hash32::from_bytes([seed; 32]),
            SAMPLES,
            behind,
            cairn_ledger::sampling::levels_for(tip),
        )
        .iter()
        .map(|work| self.covering(*work))
        .max()
        .unwrap_or(0);
        tip - pinned.saturating_sub(window) + 1
    }
}

/// The soonest after the loss that this chain stops being weighable, in
/// blocks. `None` if it is weighable throughout.
fn cliff(age: u64, factor: u64) -> Option<u64> {
    let mut first = None;
    let mut since = 256u64;
    while since < age {
        if Fallen::new(age, factor, since).run_wanted(7) > MOST_TAIL {
            first.get_or_insert(since);
        }
        // Geometric, because what is being located is an order of magnitude
        // rather than a block: a linear walk over thirty years of them is an
        // afternoon of hashing for two figures quoted to the day. A sixteenth
        // a step, in whole numbers, so the same points are visited on every
        // machine.
        since = since + since / 16 + 1;
    }
    first
}

/// **What a chain that loses its miners costs a newcomer, as the paper states
/// it.**
///
/// The run of headers a weighing carries is capped, and the cap is a real
/// limit rather than a formality: past it a chain cannot be weighed at all and
/// a newcomer has to read it. The paper's own instrument for the weighing,
/// above, treats that run as a fixed distance from the tip, which it is only
/// while the difficulty is near the chain's lifetime average. It is a band of
/// work, so when the difficulty at the tip falls the same band covers more
/// blocks.
///
/// Every figure the paper publishes about that is measured here, against this
/// build's own `draw` and its own `MOST_TAIL`, because a figure about a limit
/// nobody will meet for years is exactly the kind that goes stale unwatched.
#[test]
fn the_papers_cliff_on_a_chain_that_lost_its_miners_is_the_one_this_build_has() {
    let paper = flowing();
    let header = BlockHeader::ENCODED_BYTES as u64;
    let ceiling = format!("{} headers", grouped(MOST_TAIL));
    let ceiling_mb = format!("{:.1} MB", (MOST_TAIL * header) as f64 / 1e6);
    println!("the cap on the run is {ceiling}, {ceiling_mb}");
    assert!(
        paper.contains(&ceiling),
        "the paper does not say the run is capped at {ceiling}"
    );
    assert!(
        paper.contains(&format!("about {ceiling_mb}")),
        "the paper does not price the cap at {ceiling_mb}"
    );
    // And in both languages of the site, whose "honest limits" section is
    // where a reader is sent for exactly this kind of sentence. A figure
    // published in three places and measured in one is how the last fourteen
    // went stale.
    for (language, text) in [("English", SITE_EN), ("French", SITE_FR)] {
        assert!(
            text.contains(&grouped(MOST_TAIL)),
            "the {language} site does not say the run is capped at {}",
            grouped(MOST_TAIL)
        );
    }
}

/// **And the shape of chain that reaches it, which is where the paper's
/// figures come from.**
///
/// Two figures: the loss that first puts a chain out of reach, which depends
/// on its length, and how soon after the loss that begins. Both are quoted in
/// the paper, in the site's honest limits, and in the comment beside the code
/// that reports the state, so all three are held to the same measurement here.
#[test]
fn the_papers_account_of_which_chains_reach_the_cliff_is_the_measured_one() {
    let paper = flowing();
    // Where the cliff begins, per chain length: the smallest loss that reaches
    // it at all. The paper quotes the range across these.
    let ages = [
        A_YEAR / 4,
        A_YEAR / 2,
        A_YEAR,
        2 * A_YEAR,
        3 * A_YEAR,
        10 * A_YEAR,
        30 * A_YEAR,
    ];
    let factors = [16u64, 24, 32, 48];
    let mut thresholds = Vec::new();
    let mut soonest = u64::MAX;
    for age in ages {
        let mut reached = None;
        for factor in factors {
            if let Some(first) = cliff(age, factor) {
                soonest = soonest.min(first);
                if reached.is_none() {
                    reached = Some(factor);
                }
            }
        }
        println!(
            "a chain of {:.2} years first cannot be weighed after losing {:?} times its work",
            age as f64 / A_YEAR as f64,
            reached
        );
        thresholds.push(reached.expect("every length here reaches it at some loss"));
    }
    let least = *thresholds.iter().min().unwrap();
    let most = *thresholds.iter().max().unwrap();
    let onset = soonest / (24 * 60);
    println!("the cliff begins at a loss of {least} to {most}, {onset} days after it");

    assert!(
        !factors
            .iter()
            .take(1)
            .any(|factor| ages.iter().any(|age| cliff(*age, *factor).is_some())),
        "sixteen times reaches the cliff after all, and the paper says it does not"
    );
    assert!(
        paper.contains(&format!(
            "loses {} to {} times its hash rate",
            spelled(least),
            spelled(most)
        )),
        "the paper does not say the cliff begins at a loss of {least} to {most}"
    );
    assert!(
        paper.contains(&format!("about {} days after the loss", spelled(onset))),
        "the paper does not say the cliff begins {onset} days after the loss"
    );
    // And the comment beside the code that reports it, which quotes both. The
    // comment markers come off first: a sentence that wraps in a doc comment
    // has a `///` sitting in the middle of it.
    let source = NET_NODE
        .lines()
        .map(|line| line.trim_start().trim_start_matches('/'))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        source.contains(&format!(
            "loses {} to {} times its hash rate",
            spelled(least),
            spelled(most)
        )),
        "`cairn-net`'s own account of why it reports this no longer says a loss \
         of {least} to {most}"
    );
    assert!(
        source.contains(&format!("about {} days after the loss", spelled(onset))),
        "`cairn-net`'s own account no longer says {onset} days after the loss"
    );
}

/// **And what raising the cap would have to buy, which is the whole of the
/// argument for keeping it: the run needed has no bound of its own.**
#[test]
fn the_papers_figure_for_a_chain_far_past_the_cliff_is_the_measured_one() {
    let paper = flowing();
    let header = BlockHeader::ENCODED_BYTES as u64;
    //
    // One named point rather than the worst of the sweep above. The worst of a
    // sweep is partly a figure about the step size: this was published off the
    // sweep first, and moved by half a percent the moment the grid was made to
    // walk in whole numbers, which is a published figure resting on its own
    // instrument's resolution.
    let worst = Fallen::new(30 * A_YEAR, 4_096, A_YEAR).run_wanted(7);
    let worst_mb = format!("{:.0} MB", (worst * header) as f64 / 1e6);
    println!(
        "a thirty year chain a year after a four thousand fold loss wants {worst} headers, \
         {worst_mb}"
    );
    assert!(
        worst > MOST_TAIL,
        "a chain this far down is weighable after all, and the paper says it is not"
    );
    assert!(
        paper.contains(&grouped(worst)),
        "the paper does not say a four thousand fold loss wants {} headers",
        grouped(worst)
    );
    assert!(
        paper.contains(&worst_mb),
        "the paper does not price that run at {worst_mb}"
    );
}

/// The paper with its line breaks taken out, for phrases longer than a line.
///
/// A guard that matched the paper's own wrapping would be a guard against
/// reflowing a paragraph, which is not what any of these are for.
fn flowing() -> String {
    PAPER.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The small numbers the paper writes in words rather than digits.
fn spelled(value: u64) -> &'static str {
    match value {
        11 => "eleven",
        16 => "sixteen",
        24 => "twenty four",
        32 => "thirty two",
        48 => "forty eight",
        other => panic!("the paper has no word for {other}, so the figure moved"),
    }
}

/// The depth a newcomer can be put at, against the depth this node will undo.
///
/// The paper says a forger at 40% cannot place a newcomer further than about
/// 1 240 blocks from the real chain, and `MAX_REORG_DEPTH` is 1 024. The
/// paragraph used to conclude that the first was shallower than the second,
/// which its own two figures refute, and nothing held them against each other.
///
/// So this holds them. It asserts the gap as it stands rather than the property
/// anyone would want, because the property does not hold: a newcomer at the far
/// end of the guarantee needs a switch deeper than the deepest this node makes.
/// If somebody closes the gap, by resolving the draw finer or by raising the
/// limit, this fails and the paragraph has to be rewritten with it. That is the
/// point: the two numbers cannot drift apart again in silence, in either
/// direction.
#[test]
fn the_depth_a_newcomer_can_be_put_at_is_read_against_the_depth_this_node_undoes() {
    let stated: u64 = 1_240;
    assert!(
        PAPER.contains("1 240 blocks"),
        "the paper no longer says 1 240 blocks; whatever it says now has to be \
         read against MAX_REORG_DEPTH here"
    );
    let undone = u64::try_from(cairn_chain::MAX_REORG_DEPTH).unwrap_or(u64::MAX);
    assert_eq!(undone, 1_024, "MAX_REORG_DEPTH moved");
    assert!(
        stated > undone,
        "the guarantee is now inside what this node will undo, which is the \
         property everyone wants and which the paper's paragraph says does not \
         hold. Rewrite that paragraph."
    );
    assert!(
        PAPER.contains("deeper than the node's own reorganisation limit"),
        "the paper has to say that the depth a newcomer can be put at is deeper \
         than what this node will undo, because it is"
    );
}

/// The ceilings the specification lists for each counted sequence on the wire.
///
/// They live here rather than beside the specification's other guards because
/// this is the only crate that sees both the document and `cairn-net`. Each one
/// is read from the constant the decoder uses, so a cap that moves takes the
/// table with it or fails.
#[test]
fn the_specification_lists_the_ceiling_every_message_list_carries() {
    use cairn_net::message::{
        MAX_ANNOUNCED, MAX_CHAIN, MAX_HEADERS, MAX_PROVEN, MAX_REQUESTED, MAX_SHARED_ADDRESSES,
    };

    let spec = SPECIFICATION
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let rows = [
        (
            "GetChain",
            grouped(cairn_chain::MAX_LOCATOR as u64),
            "entries",
        ),
        ("Chain", grouped(MAX_CHAIN), "(a count, not a sequence)"),
        ("GetBlocks", grouped(MAX_REQUESTED as u64), "heights"),
        ("Announce", grouped(MAX_ANNOUNCED as u64), "identifiers"),
        ("Peers", grouped(MAX_SHARED_ADDRESSES as u64), "addresses"),
        ("Headers", grouped(MAX_HEADERS as u64), "headers"),
        ("GetProofs", grouped(MAX_PROVEN as u64), "heights"),
        ("Proofs", grouped(MAX_PROVEN as u64), "placed proofs"),
    ];
    for (message, cap, unit) in rows {
        let row = format!("<tr><td>{message}</td><td class=\"n\">{cap} {unit}</td></tr>");
        assert!(
            spec.contains(&row),
            "the specification does not give {message} a ceiling of {cap} {unit}"
        );
    }

    // The two that are measured in bytes rather than in elements.
    assert!(
        spec.contains(&format!(
            "<tr><td>JoinPart</td><td class=\"n\">{} parts, {} bytes a part</td></tr>",
            grouped(u64::from(cairn_net::message::MAX_JOIN_PARTS)),
            grouped(cairn_net::message::JOIN_PART_BYTES as u64),
        )),
        "the specification does not price a join part the way the decoder does"
    );
    assert!(
        spec.contains(&format!(
            "A frame is at most {} bytes",
            grouped(cairn_net::wire::MAX_FRAME_BYTES as u64)
        )),
        "the specification does not give a frame the size the wire allows"
    );
}

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

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const PAPER: &str = include_str!("../../../docs/cairn-whitepaper.html");
const README: &str = include_str!("../../../README.md");

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

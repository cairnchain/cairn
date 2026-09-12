//! What a connection is allowed to deliver, against what this site sends.
//!
//! `cairn-http` gives a connection one moment for the whole of it, and the
//! answering half of that moment is worth a fixed number of bytes at the
//! slowest link the server writes for. Past it the socket is shut with the
//! body part written, and a body short of its own `content-length` is an
//! incomplete message: the reader gets a transport error, not a short page.
//!
//! The ceiling used to carry a note saying what paid for it: "the biggest
//! document compiled in is some fifty kilobytes, and the API pages are capped
//! at a couple of hundred rows. So for everything actually served the length
//! is what decides, and this only ever catches an answer nobody has written
//! yet." Both halves had stopped being true, and the second was never an
//! answer to the question: a page capped in rows is not capped in bytes.
//!
//! What was measured when this file was written, against a budget of 163 840
//! bytes: the specification at 167 016, one page of the pool at 8 063 655 from
//! a forty nine byte request, and one block at 747 809 from a forty four byte
//! request, six times the block's own wire form. The pool is paid for by
//! whoever fills it. The block is not: once it is on the chain that is the
//! answer for ever, for free.
//!
//! Everything here is weighed the way the server holds it. The documents are
//! read out of the binary, and the pages are built over a real node.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    dead_code
)]

#[path = "../src/api.rs"]
mod api;
#[path = "../src/assets.rs"]
mod assets;
#[path = "../src/index.rs"]
mod index;

use std::net::SocketAddr;

use cairn_crypto::SecretKey;
use cairn_http::{Request, Response};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::Amount;

use api::Explorer;

/// The most a connection can carry, at the link the server writes for.
///
/// Taken from the server rather than restated, because it is the exact number
/// the socket enforces: the answering half of a connection's moment, at the
/// slowest link the server undertakes to write for. Nothing here recomputes
/// it, which is the point of it being published.
fn deliverable() -> usize {
    cairn_http::most_one_answer_carries()
}

fn asking(path: &str, query: &str) -> Request {
    Request {
        path: path.to_owned(),
        query: query.to_owned(),
        head_only: false,
        post: false,
        body: String::new(),
        host: String::new(),
        origin: String::new(),
    }
}

/// What one request costs to write down, head and all, as a caller sends it.
fn asked_bytes(path: &str, query: &str) -> usize {
    format!("GET {path}?{query} HTTP/1.1\r\nhost: cairn\r\n\r\n").len()
}

/// Every compiled-in page, weighed as the server holds it.
///
/// The papers are the point: a protocol whose whole argument is that you
/// should check things for yourself has to be readable by somebody on a slow
/// link, and the specification is the one that says how.
#[test]
fn every_document_this_site_serves_fits_in_the_time_a_connection_is_given() {
    let budget = deliverable();
    let mut over: Vec<(String, usize)> = Vec::new();
    for path in [
        "/",
        "/cairn.css",
        "/cairn.js",
        "/languages.json",
        "/i18n/en.json",
        "/i18n/fr.json",
        "/whitepaper",
        "/specification",
        "/design",
        "/open-questions",
        "/prior-art",
        "/cairn-whitepaper.css",
        "/cairn-design.css",
        "/cairn-prior-art.css",
    ] {
        let answer = assets::answer(&asking(path, ""));
        assert_eq!(answer.status, 200, "{path}");
        println!(
            "{path:<24} {:>8} bytes, {:>3}% of what a connection may carry",
            answer.body.len(),
            answer.body.len() * 100 / budget
        );
        if answer.body.len() > budget {
            over.push((path.to_owned(), answer.body.len()));
        }
    }
    assert!(
        over.is_empty(),
        "these are served today and cannot be delivered to a reader at the \
         link this server says it writes for. A connection may carry {budget} \
         bytes: {over:?}"
    );
}

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.coinbase_maturity = 0;
    params
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) -> Block {
        self.carrying(miner, Vec::new())
    }

    fn carrying(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::with_extra(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
            Vec::new(),
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }
}

/// A transfer spending one reward and fanning it out into `outputs` notes.
///
/// The shape a caller would want if it were choosing what this site has to
/// write out: the rules allow two hundred and fifty six outputs on one
/// transfer, and every one of them is a note reference, a value, an owner and
/// four fields about where it stands, written out in full.
fn fan_out(
    params: &ConsensusParams,
    secret: &SecretKey,
    note_id: NoteId,
    note: Note,
    outputs: usize,
) -> Transfer {
    // A tenth of the reward spread over the outputs, so the rest is fee and
    // nothing here turns on what a pool charges.
    let each = Amount::from_pebbles(note.value.as_pebbles() / 10 / outputs as u64).unwrap();
    let notes: Vec<Note> = (0..outputs)
        .map(|_| Note::new(each, secret.public_key()))
        .collect();
    let mut transfer = Transfer::new(vec![Input::hot(note_id)], notes);
    transfer.sign_input(params.network, 0, &note, secret);
    transfer
}

/// One page of the pool, weighed against what a connection may carry.
///
/// `MAX_PAGE` is a hundred and twenty eight and the pool holds four megabytes
/// of transfers a stranger put there for nothing. A row is a transfer, and a
/// transfer is up to two hundred and fifty six outputs, each of which is a
/// note reference, a value, an owner and four fields about where it stands.
/// Nothing tied the number of rows to a number of bytes, and a hundred and
/// twenty eight of them came to eight megabytes.
///
/// The page stops on bytes now, and the second half of this test is that it
/// still advances: a ceiling that produces a page nobody can get past is a
/// caller asking the same question for ever, which is the defect this project
/// fixed once already at `chain_after`.
#[test]
fn a_page_of_the_pool_is_a_ceiling_on_bytes_and_not_only_on_rows() {
    /// One page, as a caller may ask for it. `MAX_PAGE` is 128.
    const TRANSFERS: usize = 128;
    /// What the rules allow one transfer, which is `max_outputs_per_transfer`.
    const OUTPUTS: usize = 256;

    let params = params();
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    let blocks: Vec<Block> = (0..TRANSFERS).map(|_| forge.mine(&miner)).collect();

    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let explorer = Explorer::new(Node::bind(params, address).expect("a node on a free port"));
    for block in &blocks {
        explorer
            .node()
            .submit_block(block.clone())
            .expect("a block this node built the ledger for");
    }

    // What filling the pool costs whoever fills it, which is what the answer
    // below has to be priced against.
    let mut put_there = 0usize;
    for block in &blocks {
        let note_id = NoteId::new(block.coinbase.id(), 0);
        let note = block.coinbase.outputs[0];
        let transfer = fan_out(&params, &miner, note_id, note, OUTPUTS);
        put_there += cairn_primitives::codec::Encode::encode(&transfer).len();
        explorer
            .node()
            .submit_transaction(transfer)
            .expect("a transfer the ledger accepts");
    }
    explorer.refresh();

    let pooled = explorer.node().pool_len();
    assert_eq!(
        pooled, TRANSFERS,
        "the pool has to be filled to test anything"
    );

    let query = "limit=128";
    let request = asking("/api/pool", query);
    let answer: Response = explorer.answer(&request).expect("the pool route answered");
    assert_eq!(answer.status, 200);

    let asked = asked_bytes("/api/pool", query);
    let sent = answer.body.len();
    let budget = deliverable();
    let body = String::from_utf8(answer.body.clone()).expect("json is text");
    let rows = body.matches("\"inputs\":").count();
    println!(
        "filling the pool cost {put_there} bytes, once. After that {asked} \
         bytes asked buys {sent} bytes written, over {rows} of the {pooled} \
         rows asked for: {} bytes a row, {} times what was asked, {}% of what \
         a connection may carry ({budget}).",
        sent / rows.max(1),
        sent / asked,
        sent * 100 / budget,
    );
    assert!(
        sent <= budget,
        "one page of the pool, out of the 128 rows a caller may ask for, \
         comes to {sent} bytes from a {asked} byte request. A connection may \
         carry {budget} at the link this server writes for, so the rest is \
         written into a socket that is then shut, and the reader gets an \
         incomplete message rather than a short one."
    );

    // And the rest is reachable. The rows the ceiling cut are named by the
    // pointer the page already carried, so a reader that wants them asks
    // again from there rather than asking the same question for ever.
    assert!(
        body.contains("\"next\":") && !body.contains("\"next\":null"),
        "the pool was cut short and named no next page: {}",
        &body[body.len().saturating_sub(200)..]
    );
    assert!(
        rows > 0 && rows < pooled,
        "{rows} of {pooled} rows were served, which is not a page that was cut"
    );
}

/// One block, which is the answer nobody has to pay for twice.
///
/// The pool above costs whoever fills it: the pool prices a transfer by the
/// places it takes in the hot set, so a fan-out is dear and the page empties
/// as blocks carry it away. A block does not. Once a block carrying those
/// transfers is on the chain, `/api/block/<height>` writes them out in full,
/// to anybody who asks, for as long as the chain exists, and the only ceiling
/// over it is `max_block_bytes`, which is a ceiling on the wire form and not
/// on what this route writes.
#[test]
fn one_block_is_never_written_out_larger_than_a_connection_can_carry() {
    let params = params();
    let miner = wallet(3);
    let mut forge = Forge::new(params);

    // Enough rewards to spend, then one block carrying as many fan-outs as
    // `max_block_bytes` allows.
    let mut early: Vec<Block> = (0..16).map(|_| forge.mine(&miner)).collect();
    let mut transfers = Vec::new();
    for block in &early {
        let note_id = NoteId::new(block.coinbase.id(), 0);
        let candidate = fan_out(&params, &miner, note_id, block.coinbase.outputs[0], 256);
        let so_far: usize = transfers
            .iter()
            .map(|transfer| cairn_primitives::codec::Encode::encode(transfer).len())
            .sum();
        let more = cairn_primitives::codec::Encode::encode(&candidate).len();
        if so_far + more + 4096 > params.max_block_bytes {
            break;
        }
        transfers.push(candidate);
    }
    let carried = transfers.len();
    let packed = forge.carrying(&miner, transfers);
    early.push(packed.clone());

    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let explorer = Explorer::new(Node::bind(params, address).expect("a node on a free port"));
    for block in &early {
        explorer
            .node()
            .submit_block(block.clone())
            .expect("a block this node built the ledger for");
    }
    explorer.refresh();

    let height = packed.header.height;
    let path = format!("/api/block/{height}");
    let answer = explorer
        .answer(&asking(&path, ""))
        .expect("the block route answered");
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );

    let on_the_wire = cairn_primitives::codec::Encode::encode(&packed).len();
    let asked = asked_bytes(&path, "");
    let sent = answer.body.len();
    let budget = deliverable();
    println!(
        "a block of {on_the_wire} bytes carrying {carried} transfers is \
         written out as {sent} bytes for a {asked} byte request: {} times the \
         block, {} times what was asked, {}% of what a connection may carry \
         ({budget}).",
        sent / on_the_wire.max(1),
        sent / asked,
        sent * 100 / budget,
    );
    assert!(
        sent <= budget,
        "one block of {on_the_wire} bytes, inside every rule the chain has, is \
         written out as {sent} bytes. A connection may carry {budget} at the \
         link this server writes for, and there is no fee, no rate and no \
         ceiling anywhere between the two: the block is on the chain and this \
         is the answer to `{path}` for ever."
    );

    // The block still says how many transfers it carries, and names where the
    // ones it did not write out begin. A page that loses the count is a page
    // that reports a block as smaller than it is.
    let body = String::from_utf8(answer.body.clone()).expect("json is text");
    assert!(
        body.contains(&format!("\"transferCount\":{carried}")),
        "the block has to say how many transfers it carries, not how many it wrote"
    );
    assert!(
        body.contains("\"transfersNext\":") && !body.contains("\"transfersNext\":null"),
        "the transfers were cut short and named no next page"
    );

    // And asking from there is answered, which is what makes the pointer worth
    // anything.
    let more = explorer
        .answer(&asking(&path, "from=1"))
        .expect("the block route answered the second page");
    assert_eq!(more.status, 200);
    assert!(more.body.len() <= budget);
}

//! `/api/address` says a figure is exact whenever the index started at block
//! zero, whether or not it has got to the end.
//!
//! The field is `counted`, and the site reads nothing else about an address:
//! `atLeast()` in `web/cairn.js` puts a "≥" in front of the notes held when
//! `counted` is false and prints the number bare when it is true, and the
//! address view is one of the three that never calls `coverageLine`, so the
//! flag is the whole of what a reader is told.
//!
//! It is worked out as `held.whole && context.index.reads_from_the_start()`,
//! and the comment above it names two ways the count can be a floor: the walk
//! over one address stopped at `ADDRESS_SCAN`, or the index does not go back
//! to the first block. There is a third, it is the commonest one, and it is
//! the one the rest of this file exists for: the index goes back to the first
//! block and has not reached the tip.
//!
//! `reads_from_the_start()` is `span.from == 0`. It is true from the moment
//! the first block goes in, so it is true after sixty four blocks of two and
//! a half million. `coverage.whole`, written into the same response by
//! `coverage()`, is `reads_from_the_start() && behind == 0` and gets it
//! right. One body therefore carries both "I have not read the whole chain"
//! and "this count is exact", and the page reads the second one.
//!
//! The window is not a corner case. `coverage`'s own doc comment says so:
//! "it is the first minutes of every run and every restart, and the door is
//! deliberately opened during it". It is also every gap between one turn of
//! the walk and the next on a running site.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    dead_code
)]

#[path = "../src/api.rs"]
mod api;
#[path = "../src/index.rs"]
mod index;

use std::net::SocketAddr;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_http::{Request, Response};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::Amount;

use api::Explorer;

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

#[derive(Clone)]
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

    fn carrying(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::with_extra(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
            miner.public_key().as_bytes()[..4].to_vec(),
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

    fn mine(&mut self, miner: &SecretKey) -> Block {
        self.carrying(miner, Vec::new())
    }

    fn mine_many(&mut self, miner: &SecretKey, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine(miner)).collect()
    }
}

fn reward(blocks: &[Block], height: u64) -> (NoteId, Note) {
    let block = &blocks[height as usize];
    let note = block.coinbase.outputs[0];
    (NoteId::new(block.coinbase.id(), 0), note)
}

fn spend(
    params: &ConsensusParams,
    secret: &SecretKey,
    notes: &[(NoteId, Note)],
    to: PublicKey,
    amount: Amount,
) -> Transfer {
    let inputs = notes
        .iter()
        .map(|(id, _)| Input::hot(*id))
        .collect::<Vec<_>>();
    let mut transfer = Transfer::new(inputs, vec![Note::new(amount, to)]);
    for (index, (_, note)) in notes.iter().enumerate() {
        transfer.sign_input(params.network, index as u32, note, secret);
    }
    transfer
}

fn explorer(params: ConsensusParams) -> Explorer {
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Explorer::new(Node::bind(params, address).expect("a node on a free port"))
}

fn feed(explorer: &Explorer, blocks: &[Block]) {
    for block in blocks {
        explorer
            .node()
            .submit_block(block.clone())
            .expect("a block this node built the ledger for");
    }
}

fn ask(explorer: &Explorer, rest: &str) -> Response {
    let request = Request {
        path: format!("/api/{rest}"),
        query: String::new(),
        head_only: false,
        post: false,
        body: String::new(),
        host: String::new(),
        origin: String::new(),
    };
    explorer.answer(&request).expect("an API route answered")
}

fn body(answer: &Response) -> String {
    String::from_utf8_lossy(&answer.body).into_owned()
}

fn says(answer: &Response, field: &str, value: &str) -> bool {
    body(answer).contains(&format!("\"{field}\":{value}"))
}

/// An index that started at block zero and has not reached the tip calls its
/// figures exact.
///
/// Five blocks. The index reads the first four and is then given the fifth
/// without being asked to read it, which is where a running site sits between
/// one turn of the walk and the next, and where it sits for the whole of its
/// first pass over a real chain.
///
/// Block four spends the reward block zero paid, so at the tip the miner
/// holds three notes and four rewards' worth minus what it sent. The index
/// has not read block four, so it answers four notes and four rewards. That
/// much is honest arithmetic over a shorter chain. What is not honest is the
/// flag beside it: `counted` says the four is exact, in a body whose own
/// `coverage` object says `whole: false` and `behind: 1`.
#[test]
fn an_index_that_has_not_reached_the_tip_still_calls_its_figures_exact() {
    let params = params();
    let miner = wallet(1);
    let rival = wallet(9);
    let alice = wallet(3).public_key();

    let mut forge = Forge::new(params);
    let mut blocks = forge.mine_many(&miner, 4);
    let paid = reward(&blocks, 0);
    let half = Amount::from_pebbles(params.initial_reward.as_pebbles() / 2).unwrap();
    let sent = spend(&params, &miner, std::slice::from_ref(&paid), alice, half);
    // Mined by somebody else, so the fee does not come back to the miner and
    // the arithmetic below has one moving part.
    blocks.push(forge.carrying(&rival, vec![sent.clone()]));

    let explorer = explorer(params);
    feed(&explorer, &blocks[..4]);
    explorer.refresh();

    let address = miner.public_key().to_string();
    let whole = ask(&explorer, &format!("address/{address}"));
    assert!(says(&whole, "counted", "true"), "{}", body(&whole));
    assert!(says(&whole, "unspentNotes", "4"), "{}", body(&whole));
    assert!(says(&whole, "whole", "true"), "{}", body(&whole));

    // The fifth block reaches the node. Nothing tells the walk to run, which
    // is the ordinary state of a site between turns.
    feed(&explorer, &blocks[4..]);

    let answer = ask(&explorer, &format!("address/{address}"));
    let page = body(&answer);
    assert!(says(&answer, "behind", "1"), "{page}");
    assert!(
        says(&answer, "whole", "false"),
        "the coverage object knows: {page}"
    );
    assert!(
        says(&answer, "unspentNotes", "4"),
        "and the count is one too many, which is not the defect: {page}"
    );

    // A note this chain has spent, listed among the notes the address holds.
    let spent = format!("\"note\":\"{}", paid.0.source);
    assert!(page.contains(&spent), "{page}");

    assert!(
        !says(&answer, "counted", "true"),
        "the same body says `whole:false` and `counted:true`. `counted` is the \
         only thing web/cairn.js reads about how much of the chain stands \
         behind an address: `atLeast()` prints the notes held bare when it is \
         true, and the address view never calls `coverageLine`. So the page \
         states four notes held, one of them spent, as a fact about the chain. \
         `counted` is `held.whole && reads_from_the_start()` in \
         cairn-explorer/src/api.rs; `coverage.whole` in the same body is \
         `reads_from_the_start() && behind == 0` and is the one that is right: \
         {page}"
    );
}

/// The same flag on an address the index has never seen.
///
/// `counted: true` beside `balance: "0"` is the answer this route exists not
/// to give. It was fixed for an index that had read nothing, which is the
/// state that lasts for one turn of the walk, and left standing for an index
/// that has read part of the chain, which is the state that lasts for the
/// rest of the first pass.
#[test]
fn an_address_the_index_has_not_reached_is_told_its_nought_is_exact() {
    let params = params();
    let miner = wallet(1);
    let rival = wallet(9);
    let alice = wallet(3).public_key();

    let mut forge = Forge::new(params);
    let mut blocks = forge.mine_many(&miner, 4);
    let paid = reward(&blocks, 0);
    let half = Amount::from_pebbles(params.initial_reward.as_pebbles() / 2).unwrap();
    let sent = spend(&params, &miner, std::slice::from_ref(&paid), alice, half);
    blocks.push(forge.carrying(&rival, vec![sent]));

    let explorer = explorer(params);
    feed(&explorer, &blocks[..4]);
    explorer.refresh();
    feed(&explorer, &blocks[4..]);

    let answer = ask(&explorer, &format!("address/{alice}"));
    let page = body(&answer);
    assert!(says(&answer, "balance", "\"0\""), "{page}");
    assert!(says(&answer, "whole", "false"), "{page}");
    assert!(
        !says(&answer, "counted", "true"),
        "alice was paid in the block this index has not read, and is told her \
         nought is an exact nought: {page}"
    );
}

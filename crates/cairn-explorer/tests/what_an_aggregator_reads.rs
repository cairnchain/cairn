//! The supply, in the shape a price aggregator fetches it.
//!
//! An aggregator is handed two URLs and reads each body as one number: the
//! money there is, and the money that can move. Neither is a field it can
//! check against anything, so these hold both to the ledger the rest of the
//! site reads, at the same height, and hold the difference between them to the
//! one thing that separates them, the rewards that are not spendable yet.
//!
//! The explorer is a binary with no library target, so its two modules are
//! included by path, as `answers.rs` does.

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
#[path = "../src/index.rs"]
mod index;

use std::net::SocketAddr;

use cairn_crypto::SecretKey;
use cairn_http::{Request, Response};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::Amount;

use api::Explorer;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A reward waits this many blocks here, rather than the thousand the public
/// networks wait, so a chain short enough to mine in a test has some of its
/// rewards waiting and some already free.
const MATURITY: u64 = 3;

fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.coinbase_maturity = MATURITY;
    params
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Mines `count` blocks, each paying `paying(height)` to the miner.
fn mine(params: ConsensusParams, count: u64, paying: impl Fn(u64) -> Amount) -> Vec<Block> {
    let miner = wallet(1);
    let mut state = LedgerState::new();
    let mut clock = 1_000;
    let mut blocks = Vec::new();
    for height in 0..count {
        clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(paying(height), miner.public_key())]);
        let block = assemble_block(&state, coinbase, Vec::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut state, &block, &params, NOW).unwrap();
        blocks.push(block);
    }
    blocks
}

/// The reward in full, which is what a miner takes.
fn in_full(params: ConsensusParams) -> impl Fn(u64) -> Amount {
    move |height| params.reward_at(height)
}

fn explorer(params: ConsensusParams, blocks: &[Block]) -> Explorer {
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let explorer = Explorer::new(Node::bind(params, address).expect("a node on a free port"));
    for block in blocks {
        explorer
            .node()
            .submit_block(block.clone())
            .expect("a block this node built the ledger for");
    }
    explorer.refresh();
    explorer
}

fn ask(explorer: &Explorer, rest: &str) -> Response {
    explorer
        .answer(&Request {
            path: format!("/api/{rest}"),
            query: String::new(),
            head_only: false,
            post: false,
            body: String::new(),
            host: String::new(),
            origin: String::new(),
        })
        .expect("an API route answered")
}

fn body(answer: &Response) -> String {
    String::from_utf8_lossy(&answer.body).into_owned()
}

/// The text of a string field, or the bare text of a number or null.
///
/// The writer emits no spaces, so the JSON is read without parsing it, as the
/// other tests of this site read it.
fn field(answer: &Response, name: &str) -> String {
    let text = body(answer);
    let key = format!("\"{name}\":");
    let rest = text
        .split_once(&key)
        .unwrap_or_else(|| panic!("no `{name}` in {text}"))
        .1;
    match rest.strip_prefix('"') {
        Some(quoted) => quoted.split_once('"').unwrap().0.to_owned(),
        None => rest
            .split(|c: char| c == ',' || c == '}')
            .next()
            .unwrap()
            .to_owned(),
    }
}

fn pebbles(cairn: &str) -> u64 {
    Amount::from_cairn(cairn)
        .unwrap_or_else(|| panic!("`{cairn}` is not an amount in CAIRN"))
        .as_pebbles()
}

/// Whether `text` is a whole number of CAIRN with exactly eight decimals and
/// nothing else, not even a line ending.
fn is_a_plain_figure(text: &str) -> bool {
    let Some((whole, fraction)) = text.split_once('.') else {
        return false;
    };
    !whole.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.len() == 8
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
}

/// What the rewards nobody can spend yet came to, counted from the blocks
/// rather than asked of the ledger: a reward at height `h` can be spent in
/// the block at `h + MATURITY`, so at tip `t`, whose next block is `t + 1`,
/// the ones still waiting are those above `t + 1 - MATURITY`.
fn still_waiting(blocks: &[Block]) -> u64 {
    let tip = blocks.last().unwrap().header.height;
    blocks
        .iter()
        .filter(|block| block.header.height + MATURITY > tip + 1)
        .map(|block| block.coinbase.total_output().unwrap().as_pebbles())
        .sum()
}

/// **The total is the figure `/api/status` serves as issued, at the same
/// height, and the circulating figure is that total less the rewards still
/// waiting.**
///
/// A miner here takes a little less than its reward at every other block, so
/// what the chain issued is not the schedule's running total, and a total
/// worked out from the schedule rather than read off the ledger would fail.
#[test]
fn the_two_figures_are_the_ledgers_at_the_height_status_names() {
    let params = params();
    let short = |height: u64| {
        let full = params.reward_at(height).as_pebbles();
        Amount::from_pebbles(if height % 2 == 0 { full } else { full - 7 }).unwrap()
    };
    let blocks = mine(params, 8, short);
    let explorer = explorer(params, &blocks);

    let status = ask(&explorer, "status");
    let supply = ask(&explorer, "supply");
    let total = ask(&explorer, "supply/total");
    let circulating = ask(&explorer, "supply/circulating");

    let issued: u64 = field(&status, "issued").parse().unwrap();
    let paid: u64 = blocks
        .iter()
        .map(|block| block.coinbase.total_output().unwrap().as_pebbles())
        .sum();
    assert_eq!(issued, paid, "the ledger issued what the coinbases took");
    assert_ne!(
        issued,
        params.emitted_by(7).as_pebbles(),
        "the fixture leaves some of the schedule unclaimed, or it proves nothing"
    );

    // The account the guide gives: the schedule's running total is the
    // total, what was destroyed, and what was left unclaimed.
    let destroyed: u64 = field(&status, "destroyed").parse().unwrap();
    let unclaimed: u64 = field(&status, "unclaimed").parse().unwrap();
    assert_eq!(
        issued + destroyed + unclaimed,
        params.emitted_by(7).as_pebbles(),
        "{}",
        body(&status)
    );

    assert_eq!(field(&supply, "height"), "7");
    assert_eq!(field(&supply, "height"), field(&status, "height"));
    assert_eq!(pebbles(&body(&total)), issued, "{}", body(&total));
    assert_eq!(pebbles(&field(&supply, "total")), issued);

    let waiting = still_waiting(&blocks);
    assert!(waiting > 0 && waiting < issued, "some waiting, some free");
    assert_eq!(pebbles(&field(&supply, "maturing")), waiting);
    assert_eq!(
        pebbles(&body(&circulating)),
        issued - waiting,
        "{}",
        body(&circulating)
    );
    assert_eq!(pebbles(&field(&supply, "circulating")), issued - waiting);
    explorer.node().shutdown();
}

/// **The rewards counted as waiting are exactly the ones the rules refuse to
/// let anybody spend.**
///
/// `still_waiting` above is this test's own reading of the window, and a
/// reading can be off by one in the same direction as the code it checks. So
/// the edge is asked of the rules: the oldest reward counted as waiting cannot
/// be spent in the next block, and the newest one counted as free can.
#[test]
fn the_rewards_counted_as_waiting_are_the_ones_the_rules_will_not_spend() {
    let params = params();
    let blocks = mine(params, 6, in_full(params));
    let mut state = LedgerState::new();
    for block in &blocks {
        connect_block(&mut state, block, &params, NOW).unwrap();
    }
    let tip = blocks.last().unwrap().header.height;
    let miner = wallet(1);
    let spend_of = |height: u64| {
        let block = &blocks[height as usize];
        let note = block.coinbase.outputs[0];
        let id = cairn_ledger::note::NoteId::new(block.coinbase.id(), 0);
        let half = Amount::from_pebbles(note.value.as_pebbles() / 2).unwrap();
        let mut transfer = cairn_ledger::transaction::Transfer::new(
            vec![cairn_ledger::transaction::Input::hot(id)],
            vec![Note::new(half, wallet(2).public_key())],
        );
        transfer.sign_input(params.network, 0, &note, &miner);
        transfer
    };
    let carried = |height: u64| {
        let coinbase = CoinbaseTransaction::new(tip + 1, Vec::new());
        assemble_block(
            &state,
            coinbase,
            vec![spend_of(height)],
            &params,
            1_000 + 600 * (tip + 2),
            0,
        )
        .is_ok()
    };
    let oldest_waiting = tip + 2 - MATURITY;
    assert!(
        !carried(oldest_waiting),
        "the reward at {oldest_waiting} is counted as waiting and the rules spend it"
    );
    assert!(
        carried(oldest_waiting - 1),
        "the reward at {} is counted as free and the rules will not spend it",
        oldest_waiting - 1
    );
}

/// **Each plain figure is one number in whole CAIRN and nothing around it,
/// served the way every other answer here is.**
#[test]
fn a_plain_figure_is_a_number_an_aggregator_can_read() {
    let params = params();
    let blocks = mine(params, 5, in_full(params));
    let explorer = explorer(params, &blocks);
    for path in ["supply/total", "supply/circulating"] {
        let answer = ask(&explorer, path);
        assert_eq!(answer.status, 200, "{path}: {}", body(&answer));
        assert_eq!(answer.content_type, "text/plain; charset=utf-8", "{path}");
        assert_eq!(
            answer.cache,
            ask(&explorer, "status").cache,
            "{path} is cached unlike the rest of the API"
        );
        assert!(
            is_a_plain_figure(&body(&answer)),
            "{path} answered `{}`",
            body(&answer)
        );
    }
    let supply = ask(&explorer, "supply");
    assert_eq!(supply.content_type, "application/json; charset=utf-8");
    assert_eq!(field(&supply, "unit"), "CAIRN");
    assert_eq!(field(&supply, "decimals"), "8");
    explorer.node().shutdown();
}

/// **There is no maximum supply, and the answer says so rather than serving
/// the monetary ceiling as one.**
///
/// What the schedule does have is published beside it: the height the floor
/// takes over, what the halvings pay before it, and the floor. All three are
/// the figures the specification gives, reached through the answer.
#[test]
fn the_schedule_has_no_maximum_and_says_what_it_has_instead() {
    let params = params();
    let blocks = mine(params, 2, in_full(params));
    let explorer = explorer(params, &blocks);
    let supply = ask(&explorer, "supply");
    assert_eq!(field(&supply, "maximum"), "null", "{}", body(&supply));
    assert_eq!(field(&supply, "floorFrom"), "13665600");
    assert_eq!(field(&supply, "beforeTheFloor"), "105107167.95955200");
    assert_eq!(
        pebbles(&field(&supply, "beforeTheFloor")),
        params.emitted_by(13_665_599).as_pebbles()
    );
    assert_eq!(field(&supply, "floorPerBlock"), "0.01000000");
    // The floor is where the reward stops halving, and the block before it
    // still pays more than the floor.
    assert_eq!(params.reward_at(13_665_600), params.tail_reward);
    assert!(params.reward_at(13_665_599) > params.tail_reward);
    explorer.node().shutdown();
}

/// **A node that does not hold the blocks that paid the waiting rewards says
/// it cannot count them, and does not count them as free.**
///
/// The window of waiting rewards is wider here than the blocks a node holds
/// in memory, which no public network does, so that the oldest of them has
/// been let go of: the one way a node that built its own ledger reaches the
/// state a node handed its ledger starts in.
#[test]
fn rewards_this_node_cannot_count_leave_the_circulating_figure_unknown() {
    let mut params = params();
    let window = cairn_chain::HELD_WINDOW as u64;
    params.coinbase_maturity = window + 4;
    let blocks = mine(params, window + 3, in_full(params));
    let explorer = explorer(params, &blocks);

    let circulating = ask(&explorer, "supply/circulating");
    assert_eq!(circulating.status, 503, "{}", body(&circulating));
    assert_eq!(circulating.content_type, "application/json; charset=utf-8");
    assert!(
        body(&circulating).contains("\"error\":"),
        "{}",
        body(&circulating)
    );
    let supply = ask(&explorer, "supply");
    assert_eq!(field(&supply, "circulating"), "null");
    assert_eq!(field(&supply, "maturing"), "null");
    let total = ask(&explorer, "supply/total");
    assert_eq!(total.status, 200, "the total does not need the blocks");
    explorer.node().shutdown();
}

/// **The floor is found where the reward first stops falling, on a schedule
/// whose last halving lands exactly on it.**
///
/// The shipped schedule passes the floor between two halvings, so a search
/// that stopped one halving late would find the same height there and be
/// wrong on any schedule that halves onto the floor exactly. This one does:
/// sixty four pebbles halving every four blocks reach the floor of eight at
/// the third halving.
#[test]
fn the_floor_is_where_the_reward_first_stops_falling() {
    let mut params = params();
    params.initial_reward = Amount::from_pebbles(64).unwrap();
    params.tail_reward = Amount::from_pebbles(8).unwrap();
    params.halving_interval = 4;
    let blocks = mine(params, 2, in_full(params));
    let explorer = explorer(params, &blocks);
    let supply = ask(&explorer, "supply");
    assert_eq!(field(&supply, "floorFrom"), "12", "{}", body(&supply));
    assert_eq!(params.reward_at(12), params.tail_reward);
    assert!(params.reward_at(11) > params.tail_reward);
    assert_eq!(
        pebbles(&field(&supply, "beforeTheFloor")),
        4 * (64 + 32 + 16)
    );
    explorer.node().shutdown();
}

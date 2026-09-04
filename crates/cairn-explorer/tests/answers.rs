//! What the site says it knows, and what it does not.
//!
//! Three of the seven things the first audit of this explorer found were one
//! thing said three ways: the site stated as fact something it did not know.
//! A balance of nought marked exact, a fee of nought that was a fee nobody had
//! worked out, and a transaction served under somebody else's identifier. Each
//! is worse than the site being slow or expensive, because a person reading a
//! nought has no way at all to tell it from a real nought.
//!
//! The audit after it found four more of the same, all in the window between
//! the door opening and the index finishing its first pass over the chain: a
//! spent note published as unspent, a transaction the site was printing on one
//! page and denying on another, a transaction identifier announced as an
//! address, and a table of the largest holders of a chain nothing had read. It
//! found the walk throwing away every block under a record a disk would not
//! read, and it found that the sentence the site exists to show while it is
//! reading the chain was the one thing it could not serve while it was reading
//! the chain.
//!
//! These drive the real routes, over a real node, and hold each of them to
//! what it now says. The explorer is a binary with no library target, so both
//! modules are included by path. Nothing in `src/` is changed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    dead_code
)]

#[path = "../src/api.rs"]
mod api;
#[path = "../src/index.rs"]
mod index;

use std::net::SocketAddr;
use std::time::Instant;

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
use index::{Head, Held, Index, Reading};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The rules these tests run under.
///
/// The one departure from the shipped test rules is how long a reward waits
/// before it can be spent. Everything here that matters happens inside ten
/// blocks, and the real number is a thousand: a test that mined its way past
/// it would measure the miner rather than the explorer.
///
/// Nought and not two, because a number in between would be saying something
/// the design does not say: a reward matures where its network calls a block
/// settled, and these tests are not on a network that has moved that number.
/// Nought is the one setting outside the rule rather than in the middle of it,
/// and it says what these tests need, which is that a reward can be spent
/// without mining a thousand blocks first.
fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.coinbase_maturity = 0;
    params
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Mines blocks on a private ledger, so a branch can be built off to the side.
#[derive(Clone)]
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
    /// Notes each coinbase pays out, which is what sets the size of a block
    /// on a chain that carries nothing else.
    outputs: usize,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
            outputs: 1,
        }
    }

    fn paying_in(mut self, notes: usize) -> Self {
        self.outputs = notes;
        self
    }

    fn carrying(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let share = self
            .params
            .initial_reward
            .as_pebbles()
            .saturating_div(self.outputs as u64);
        let outputs: Vec<Note> = (0..self.outputs)
            .map(|_| Note::new(Amount::from_pebbles(share).unwrap(), miner.public_key()))
            .collect();
        let coinbase = CoinbaseTransaction::with_extra(
            height,
            outputs,
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

    fn fork(&self) -> Self {
        self.clone()
    }
}

/// The reward note block `height` paid, which is the only money these tests
/// have to move.
fn reward(blocks: &[Block], height: u64) -> (NoteId, Note) {
    let block = &blocks[height as usize];
    let note = block.coinbase.outputs[0];
    (NoteId::new(block.coinbase.id(), 0), note)
}

/// A transfer spending `notes`, paying `amount` to `to` and the rest in fees.
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

/// An explorer over a node that keeps nothing on disk.
///
/// Enough for everything here: what these tests are about is what the routes
/// say, and the routes read the chain and the index rather than the log.
fn explorer(params: ConsensusParams) -> Explorer {
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Explorer::new(Node::bind(params, address).expect("a node on a free port"))
}

/// An explorer over a node that keeps the cold set, which is what a real one
/// is: only an archivist can say where a fallen note sits, and a node that
/// cannot answer that question cannot tell a fallen note from one that never
/// existed.
struct Archiving {
    explorer: Explorer,
    directory: std::path::PathBuf,
}

impl Archiving {
    fn open(params: ConsensusParams, name: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("cairn-answers-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (node, _) = Node::open_archiving(params, address, &directory)
            .expect("a node on a free port and a fresh directory");
        Self {
            explorer: Explorer::new(node),
            directory,
        }
    }
}

impl Drop for Archiving {
    fn drop(&mut self) {
        self.explorer.node().shutdown();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
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
    let (path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, query),
        None => (rest, ""),
    };
    let request = Request {
        path: format!("/api/{path}"),
        query: query.to_owned(),
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

/// Whether the answer carries `field` set to exactly `value`.
///
/// The writer emits no spaces, so this reads the JSON without parsing it,
/// which is the same trade the site's own translation check makes.
fn says(answer: &Response, field: &str, value: &str) -> bool {
    body(answer).contains(&format!("\"{field}\":{value}"))
}

/// A transaction is never served under another transaction's identifier.
///
/// `transaction()` took a location from the index, a block from the chain, and
/// wrote out whatever sat at that position without checking that it was the
/// one asked for. Between a reorganisation and the next refresh, which is up
/// to half a second, the index still holds locations from the branch this node
/// has left. A request for a transaction that was on it found a stale height
/// and position and was handed whatever the new branch put there: another
/// transfer, or the new coinbase at position zero. The `id` in the body was
/// the other one's, and the page rendered it as the one that had been searched
/// for.
#[test]
fn a_transaction_is_never_served_under_another_ones_identifier() {
    let params = params();
    let miner = wallet(1);
    let rival = wallet(9);
    let alice = wallet(3).public_key();
    let bob = wallet(4).public_key();

    let mut base = Forge::new(params);
    let common = base.mine_many(&miner, 4);
    let paid = reward(&common, 0);
    let half = Amount::from_pebbles(params.initial_reward.as_pebbles() / 2).unwrap();

    // Two branches, each spending the same reward, each to somebody else. So
    // both branches carry a transfer at the same height and the same position,
    // and the two transfers are not the same transfer.
    let mut good = base.fork();
    let mine = spend(&params, &miner, std::slice::from_ref(&paid), alice, half);
    let good_blocks = vec![good.carrying(&miner, vec![mine.clone()])];

    let mut bad = base.fork();
    let theirs = spend(&params, &miner, std::slice::from_ref(&paid), bob, half);
    let mut bad_blocks = vec![bad.carrying(&rival, vec![theirs.clone()])];
    bad_blocks.extend(bad.mine_many(&rival, 2));

    let explorer = explorer(params);
    feed(&explorer, &common);
    feed(&explorer, &good_blocks);
    explorer.refresh();

    let coinbase = good_blocks[0].coinbase.id();
    let transfer = mine.id();
    assert_ne!(
        transfer,
        theirs.id(),
        "the two branches differ where it counts"
    );

    // While they are on the branch, both are answered, and answered as
    // themselves.
    for id in [coinbase, transfer] {
        let answer = ask(&explorer, &format!("tx/{id}"));
        assert_eq!(answer.status, 200, "{id} is on the branch");
        assert!(
            says(&answer, "id", &format!("\"{id}\"")),
            "{}",
            body(&answer)
        );
    }

    // The rival branch wins. The index is deliberately not refreshed: this is
    // the half second the audit was about.
    feed(&explorer, &bad_blocks);
    assert_eq!(
        explorer.node().height(),
        Some(6),
        "the rival branch must have won for this to test anything"
    );

    for (id, what) in [(coinbase, "coinbase"), (transfer, "transfer")] {
        let answer = ask(&explorer, &format!("tx/{id}"));
        assert_eq!(
            answer.status,
            404,
            "the {what} that was abandoned is not answered with whoever \
             replaced it: {}",
            body(&answer)
        );
    }

    // And the ones that really are there answer for themselves.
    explorer.refresh();
    let answer = ask(&explorer, &format!("tx/{}", theirs.id()));
    assert_eq!(answer.status, 200);
    assert!(says(&answer, "id", &format!("\"{}\"", theirs.id())));
}

/// A note from a branch this node has left is not reported as sitting safely
/// in the cold set.
///
/// `tier_of` read "neither in the hot set nor inside the grace window" as "in
/// the cave", which for a note that no longer exists anywhere is the most
/// reassuring of the four answers and the only wrong one.
#[test]
fn a_note_from_an_abandoned_branch_is_not_called_cold() {
    let params = params();
    let miner = wallet(1);
    let rival = wallet(9);

    let mut base = Forge::new(params);
    let common = base.mine_many(&miner, 3);
    let mut good = base.fork();
    let good_blocks = good.mine_many(&miner, 1);
    let mut bad = base.fork();
    let bad_blocks = bad.mine_many(&rival, 3);

    let archiving = Archiving::open(params, "abandoned-note");
    let explorer = &archiving.explorer;
    feed(explorer, &common);
    feed(explorer, &good_blocks);
    explorer.refresh();

    let doomed = NoteId::new(good_blocks[0].coinbase.id(), 0);
    let reference = format!("{}:{}", doomed.source, doomed.index);
    let answer = ask(explorer, &format!("note/{reference}"));
    assert_eq!(answer.status, 200);
    assert!(says(&answer, "tier", "\"hot\""), "{}", body(&answer));

    feed(explorer, &bad_blocks);
    let answer = ask(explorer, &format!("note/{reference}"));
    assert!(
        says(&answer, "tier", "\"unknown\""),
        "a note nobody holds is not in the cave: {}",
        body(&answer)
    );
}

/// A fee nobody worked out is not printed as a fee.
///
/// `transfer_object` accumulated only the inputs it found in the index, so
/// `totalIn` was a partial sum printed under the label "Total spent" and the
/// fee taken from it was understated and printed as a fact. The block-level
/// figure forty lines above had already been repaired to say nothing in the
/// same case, so one request could produce a page reading "Fees: Not indexed"
/// at the top and a made-up fee on every transfer under it.
#[test]
fn a_fee_the_explorer_could_not_work_out_is_not_printed_as_one() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(3).public_key();

    let mut forge = Forge::new(params);
    let early = forge.mine_many(&miner, 5);

    let explorer = explorer(params);
    feed(&explorer, &early);
    explorer.refresh();
    assert!(says(&ask(&explorer, "status"), "fromTheStart", "true"));

    // Two more blocks the index has not read, then a transfer spending one
    // reward the index knows about and one it does not.
    let later = forge.mine_many(&miner, 3);
    let known = reward(&early, 0);
    let unknown = (
        NoteId::new(later[0].coinbase.id(), 0),
        later[0].coinbase.outputs[0],
    );
    let both = params
        .initial_reward
        .checked_add(params.initial_reward)
        .unwrap();
    let paid = Amount::from_pebbles(both.as_pebbles() - 1_000).unwrap();
    let transfer = spend(&params, &miner, &[known, unknown], alice, paid);
    let carrying = forge.carrying(&miner, vec![transfer.clone()]);

    feed(&explorer, &later);
    feed(&explorer, std::slice::from_ref(&carrying));
    // Deliberately not refreshed. This is any block above what the index has
    // read, which is the ordinary way a reader arrives here.

    let answer = ask(&explorer, &format!("block/{}", carrying.header.height));
    assert_eq!(answer.status, 200);
    let page = body(&answer);
    assert!(
        page.contains("\"fees\":null"),
        "the block level says it does not know: {page}"
    );
    assert!(
        page.contains("\"totalIn\":null"),
        "and so does the transfer, rather than printing the half of it that \
         happened to be in the index: {page}"
    );
    assert!(
        page.contains("\"fee\":null"),
        "and the fee under it is not a number: {page}"
    );

    // Once the index has read those blocks, both figures are real.
    explorer.refresh();
    let answer = ask(&explorer, &format!("block/{}", carrying.header.height));
    let page = body(&answer);
    assert!(page.contains("\"fees\":\"1000\""), "{page}");
    assert!(
        page.contains(&format!("\"totalIn\":\"{}\"", both.as_pebbles())),
        "{page}"
    );
    assert!(page.contains("\"fee\":\"1000\""), "{page}");
}

/// An explorer that has read nothing says so, rather than answering that
/// nobody owns anything.
///
/// `/api/address` answered `balance "0"` with `counted: true`, which is the
/// flag that exists to mean "this figure is exact". The only signal anywhere
/// was a count of blocks in the footer, in the dimmest ink on the page, with
/// nothing to compare it against.
#[test]
fn an_index_that_has_read_nothing_does_not_call_nought_exact() {
    let params = params();
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(&miner, 4);

    let explorer = explorer(params);
    feed(&explorer, &blocks);

    // Before the first pass over the chain, which on a real chain is minutes
    // and is exactly when the site is first reachable.
    let address = miner.public_key().to_string();
    let answer = ask(&explorer, &format!("address/{address}"));
    assert!(says(&answer, "balance", "\"0\""));
    assert!(
        says(&answer, "counted", "false"),
        "nought, and the page is told it is not an exact nought: {}",
        body(&answer)
    );

    let status = ask(&explorer, "status");
    assert!(says(&status, "fromTheStart", "false"), "{}", body(&status));
    assert!(says(&status, "behind", "4"), "{}", body(&status));
    assert!(says(&status, "blocks", "0"), "{}", body(&status));

    explorer.refresh();

    let answer = ask(&explorer, &format!("address/{address}"));
    assert!(says(&answer, "counted", "true"));
    assert!(!says(&answer, "balance", "\"0\""));

    let status = ask(&explorer, "status");
    assert!(says(&status, "fromTheStart", "true"));
    assert!(says(&status, "behind", "0"));
    assert!(says(&status, "from", "0"));
    assert!(says(&status, "through", "3"));
}

/// The site can ask the node whether it is still following the chain.
///
/// It called five `Node` methods and none of them was one of these, so it went
/// on serving a frozen tip, a frozen supply and a frozen block list with no
/// notice at all. What is checked here is that the answers are carried at all:
/// a node that has stopped following its chain is not a state a test can put a
/// healthy node into, and the site's job is to pass on what it is told.
#[test]
fn the_site_asks_the_node_how_it_is() {
    let params = params();
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(&miner, 2);

    let explorer = explorer(params);
    feed(&explorer, &blocks);
    explorer.refresh();

    let status = ask(&explorer, "status");
    let page = body(&status);
    assert!(
        page.contains("\"node\":{") && page.contains("\"index\":{"),
        "both are objects of their own, and the answer is one document: {page}"
    );
    for field in ["outdated", "stranded", "probation"] {
        assert!(
            page.contains(&format!("\"{field}\":null")),
            "a healthy node says nothing is wrong with it, in as many words: {page}"
        );
    }
    assert!(says(&status, "joining", "\"no\""), "{page}");
    assert!(says(&status, "outOfReach", "0"), "{page}");

    // And what the index costs, which nobody had written down.
    assert!(page.contains("\"bytesPerNote\":565"), "{page}");
    assert!(page.contains("\"bytesPerNote\":72"), "{page}");
    assert!(page.contains("\"movements\":"), "{page}");
}

/// A rebuild of the index does not stop the node it runs on.
///
/// `Explorer::refresh` took the index lock, then the node's single global
/// chain lock, and called `archived_at` once per block inside it.
/// `Explorer::answer`'s own doc comment two lines below says why that must not
/// happen: seeking a disk with the chain held is one anonymous caller deciding
/// how long every peer waits. Everything on the peer side queued behind it,
/// incoming block validation included, and the cost moved with the length of
/// the chain rather than with the depth of the reorganisation that caused it.
///
/// What is counted here is how often the node can ask its own chain a question
/// while the rebuild runs. It used to be able to ask once.
#[test]
fn a_rebuild_does_not_stop_the_node() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let params = params();
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    // Long enough that the rebuild is not over before the other thread has
    // had a chance to be shut out of anything.
    let blocks = forge.mine_many(&miner, 1_200);

    let explorer = explorer(params);
    feed(&explorer, &blocks);

    let running = AtomicBool::new(true);
    let asked = AtomicU64::new(0);
    let longest = AtomicU64::new(0);

    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut last = Instant::now();
            while running.load(Ordering::Relaxed) {
                // The cheapest question the node asks its own chain, and the
                // first thing to queue behind anything holding it.
                let _ = explorer.node().height();
                longest.fetch_max(last.elapsed().as_micros() as u64, Ordering::Relaxed);
                asked.fetch_add(1, Ordering::Relaxed);
                last = Instant::now();
            }
        });

        // Let the other thread get going, so what is counted is the rebuild.
        while asked.load(Ordering::Relaxed) < 10 {
            std::hint::spin_loop();
        }
        asked.store(0, Ordering::Relaxed);
        longest.store(0, Ordering::Relaxed);
        let started = Instant::now();
        explorer.refresh();
        let rebuild = started.elapsed();
        let during = asked.load(Ordering::Relaxed);
        let waited = longest.load(Ordering::Relaxed);
        running.store(false, Ordering::Relaxed);

        println!(
            "rebuilding 1,200 blocks took {rebuild:?}; the node asked its own chain \
             {during} questions while it ran, waiting at most {waited} us for one"
        );
        // The walk reached the tip. It does not reach the first block: a
        // node holding no blocks on disk keeps only the window a
        // reorganisation could touch, so the bottom of this chain is gone and
        // the index starts where the node's blocks start, which is the whole
        // of the first repair in this file.
        let status = ask(&explorer, "status");
        assert!(says(&status, "behind", "0"), "{}", body(&status));
        // The walk takes the chain for one block at a time and lets it go
        // between, so a thread spinning on it gets a turn or several per
        // block and the count grows with the chain. Held across the walk, all
        // it gets is the moment before the lock is taken: a couple of hundred
        // however long the rebuild is, and then nothing until it is over.
        assert!(
            during > 1_000,
            "the node got {during} questions in during a {rebuild:?} rebuild, \
             which is a node stopped rather than a node interleaved"
        );
    });
}

/// One anonymous GET buys one route, not two.
///
/// `Explorer::answer` ran the whole route a second time whenever any block had
/// to come off the log, which is nearly every page about history. Its comment
/// said the second pass cost one write of a page that was going to be written
/// anyway; it cost a full recomputation, every block re-encoded and every
/// input of every transfer looked up again, with the chain held throughout.
///
/// The first reading now does neither, and the whole of what this holds in
/// place is that skipping them does not reach the answer: every size and every
/// fee the page reports is still there.
#[test]
fn the_reading_that_names_heights_does_not_reach_the_answer() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(3).public_key();

    let mut forge = Forge::new(params);
    let mut blocks = forge.mine_many(&miner, 4);
    let paid = reward(&blocks, 0);
    let half = Amount::from_pebbles(params.initial_reward.as_pebbles() / 2).unwrap();
    let transfer = spend(&params, &miner, std::slice::from_ref(&paid), alice, half);
    blocks.push(forge.carrying(&miner, vec![transfer.clone()]));

    let explorer = explorer(params);
    feed(&explorer, &blocks);
    explorer.refresh();

    let answer = ask(&explorer, "blocks?limit=25");
    let page = body(&answer);
    assert!(
        !page.contains("\"size\":null"),
        "every size is a number: {page}"
    );
    assert!(!page.contains("\"fees\":null"), "and every fee is: {page}");

    let answer = ask(&explorer, &format!("block/{}", blocks[4].header.height));
    let page = body(&answer);
    assert!(!page.contains("\"size\":null"), "{page}");
    assert!(page.contains(&format!(
        "\"fee\":\"{}\"",
        params.initial_reward.as_pebbles() - half.as_pebbles()
    )));
}

/// What one anonymous page of blocks costs the node that answers it.
///
/// The page here is the largest a caller may ask for, over blocks the size a
/// coinbase paying its reward out in two hundred and fifty six notes makes
/// them. What `/api/blocks` spends on such a page is encoding every block
/// again to report how large it is, and that used to happen twice.
#[test]
fn what_a_page_of_blocks_costs_the_node_that_answers_it() {
    let mut params = params();
    params.max_coinbase_outputs = 256;
    let miner = wallet(1);

    let mut forge = Forge::new(params).paying_in(256);
    let blocks = forge.mine_many(&miner, 200);
    println!(
        "a block of {} notes is {} bytes",
        blocks[0].coinbase.outputs.len(),
        cairn_primitives::codec::Encode::encode(&blocks[0]).len(),
    );

    let explorer = explorer(params);
    feed(&explorer, &blocks);
    explorer.refresh();

    let rounds = 50;
    let started = Instant::now();
    for _ in 0..rounds {
        let answer = ask(&explorer, "blocks?limit=128");
        assert_eq!(answer.status, 200);
    }
    let took = started.elapsed();
    println!(
        "/api/blocks?limit=128 answered in {:?}, which is the chain lock one \
         anonymous GET buys",
        took / rounds
    );
}

/// A record the disk will not read is not a block the node let go of.
///
/// `held_at` had one number to decide with, `written_through`, and every way a
/// read can fail arrives as the same empty answer: a misindexed record, an
/// oversized one, a torn one, a bad sector. All of them looked like a height
/// below the bottom of the log, which is the one answer that lets the walk step
/// over a height and carry on above it. The other end of the run was a method
/// call away and had a doc comment saying it existed for this.
#[test]
fn a_record_the_disk_will_not_read_is_not_a_block_the_node_dropped() {
    // A log holding blocks five through nineteen, as a node past its block
    // budget keeps one.
    assert!(
        matches!(api::nothing_at(4, Some(5), Some(19)), Held::Dropped),
        "under the run: gone with the blocks, and never coming back"
    );
    assert!(
        matches!(api::nothing_at(20, Some(5), Some(19)), Held::Waiting),
        "over the run: not written yet, and it will be"
    );
    assert!(
        matches!(api::nothing_at(7, Some(5), Some(19)), Held::Refused),
        "inside the run: the record is there and the disk would not read it, \
         which is a fault in the machine and not an answer about the chain"
    );
    assert!(
        matches!(api::nothing_at(0, None, None), Held::Dropped),
        "and a node keeping no blocks at all is holding nothing under its \
         chain, with nothing coming"
    );
}

/// One refused read costs the blocks under it nothing.
///
/// The walk used to read a refusal as the bottom of the log moving up: it
/// threw the whole index away and carried on from the height above the one it
/// could not read. Every refresh after that resumed from where the last one
/// stopped, so the blocks underneath were never asked for again, and every
/// transaction, note and balance in them was gone from `/api/tx`, `/api/note`
/// and `/api/address` until somebody restarted the program. One bad sector in
/// a four hundred thousand block archive did that.
#[test]
fn a_refused_read_costs_the_blocks_under_it_nothing() {
    let miner = wallet(1);
    let mut forge = Forge::new(params());
    let chain = forge.mine_many(&miner, 20);
    let tip = 19u64;

    // One passing read error at height seven, exactly as a bad sector reads
    // the first time and not the second.
    let refuse = std::cell::Cell::new(Some(7u64));
    let read = |height: u64| -> Held {
        if refuse.get() == Some(height) {
            refuse.set(None);
            return Held::Refused;
        }
        match chain.get(height as usize) {
            Some(block) => Held::Block(Box::new(block.clone())),
            None => Held::Waiting,
        }
    };

    let mut index = Index::new();
    let head = Head {
        tip,
        at_last_read: None,
    };
    while index.refresh(&head, read) == Reading::More {}

    assert_eq!(
        index.covers(),
        Some((0, 6)),
        "the walk stopped at the height it could not read, keeping everything \
         it had read under it"
    );
    assert!(
        index.reads_from_the_start(),
        "and it still goes back to the first block, which it did not before"
    );
    assert!(
        index.locate(&chain[0].coinbase.id()).is_some(),
        "blocks nought to six are answered about, not thrown away"
    );

    // The next turn asks for the same height again, and this time gets it.
    let head = Head {
        tip,
        at_last_read: Some(chain[6].id()),
    };
    while index.refresh(&head, read) == Reading::More {}
    assert_eq!(index.covers(), Some((0, tip)), "and the hole is filled in");
    assert!(index.locate(&chain[7].coinbase.id()).is_some());
    assert!(index.locate(&chain[0].coinbase.id()).is_some());
}

/// A rebuild that reads back as many blocks as it threw away still works out
/// who holds what.
///
/// The distribution was worked out again only when the block count over a pass
/// had changed. A pass that reset partway and then read back exactly as many
/// blocks as it started with came out equal, so the table was left as the reset
/// had left it: empty. `/api/holders` then answered that nobody on the chain
/// holds anything, over an index that had just read ten blocks of coinbases.
#[test]
fn a_rebuild_of_the_same_length_still_counts_who_holds_what() {
    let miner = wallet(1);
    let mut forge = Forge::new(params());
    let chain = forge.mine_many(&miner, 21);

    // The log is cut under the walk at height ten, which is the one thing that
    // makes the walk throw away what it has read and start again mid pass.
    let read = |height: u64| -> Held {
        if height == 10 {
            return Held::Dropped;
        }
        match chain.get(height as usize) {
            Some(block) => Held::Block(Box::new(block.clone())),
            None => Held::Waiting,
        }
    };

    let mut index = Index::new();
    let head = Head {
        tip: 9,
        at_last_read: None,
    };
    while index.refresh(&head, read) == Reading::More {}
    assert_eq!(index.blocks_read(), 10);
    assert_eq!(index.holders(), 1, "the miner holds what it mined");

    // Ten blocks in, ten blocks out: the count is where it began.
    let head = Head {
        tip: 20,
        at_last_read: Some(chain[9].id()),
    };
    while index.refresh(&head, read) == Reading::More {}
    assert_eq!(index.blocks_read(), 10, "ten in, ten out");
    assert_eq!(index.covers(), Some((11, 20)));
    assert_eq!(
        index.holders(),
        1,
        "and the table is worked out again over what the walk read, rather \
         than left as the reset left it"
    );
    assert!(!index.richest().is_empty());
}

/// While the index is still reading, the site says so rather than answering.
///
/// The door opens before the first pass over the chain, on purpose, so this is
/// the state a real visitor meets on every restart for as long as the pass
/// takes. Four answers in it were statements about the chain rather than about
/// the index: a note the chain had spent was published as unspent, `/api/tx`
/// said "no such transaction" about a transfer `/api/block` was printing in
/// the same instant, the search box called that transaction an address, and
/// none of them said a word about how much had been read.
#[test]
fn while_the_index_is_still_reading_the_answers_say_so() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(3).public_key();

    let mut forge = Forge::new(params);
    let mut chain = forge.mine_many(&miner, 3);
    let paid = reward(&chain, 0);

    // A transaction identifier is thirty two bytes and so is an address, and
    // about half of all thirty two byte strings are addresses. Only one whose
    // identifier happens to be one can be mistaken for one, so the fee on this
    // transfer is nudged until this identifier is. That is the whole of the
    // arrangement: everything after it is one ordinary payment.
    let mut sent = paid.1.value.as_pebbles() / 2;
    let transfer = loop {
        let amount = Amount::from_pebbles(sent).unwrap();
        let transfer = spend(&params, &miner, std::slice::from_ref(&paid), alice, amount);
        if PublicKey::from_bytes(transfer.id().as_bytes()).is_ok() {
            break transfer;
        }
        sent -= 1;
        assert!(sent > 0, "a transfer whose identifier reads as an address");
    };
    let moved = transfer.id();
    chain.push(forge.carrying(&miner, vec![transfer]));

    let explorer = explorer(params);
    feed(&explorer, &chain);
    // Deliberately not refreshed.

    // The site is holding the block and names the transfer in it.
    let block = ask(&explorer, "block/3");
    assert_eq!(block.status, 200);
    assert!(body(&block).contains(&moved.to_string()));
    assert!(
        says(&block, "whole", "false"),
        "and the page that carries it says the index has not read the chain: {}",
        body(&block)
    );

    // The same program, the same instant, asked about that same transfer.
    let one = ask(&explorer, &format!("tx/{moved}"));
    assert_eq!(one.status, 404, "{}", body(&one));
    assert!(
        says(&one, "whole", "false") && says(&one, "behind", "4"),
        "a four hundred and four that says how much of the chain was looked \
         in: {}",
        body(&one)
    );

    // The note block three spent, on the page for the block that made it.
    let zero = ask(&explorer, "block/0");
    assert!(
        !says(&zero, "spent", "false"),
        "a note nothing has read is not published as unspent: {}",
        body(&zero)
    );
    assert!(says(&zero, "spent", "null"), "{}", body(&zero));

    let note = ask(
        &explorer,
        &format!("note/{}:{}", paid.0.source, paid.0.index),
    );
    assert_eq!(note.status, 404);
    assert!(says(&note, "whole", "false"), "{}", body(&note));

    // The search box still guesses, because an address nobody has paid is not
    // in the index either. What it no longer leaves out is that it guessed
    // against part of a chain.
    let found = ask(&explorer, &format!("search?q={moved}"));
    assert!(says(&found, "kind", "\"address\""), "{}", body(&found));
    assert!(
        says(&found, "whole", "false"),
        "the guess says what it was made against: {}",
        body(&found)
    );

    // All of it flips once the index has read the chain, which is what makes
    // every one of them a statement about the index and not about the chain.
    explorer.refresh();

    let one = ask(&explorer, &format!("tx/{moved}"));
    assert_eq!(one.status, 200, "{}", body(&one));
    assert!(says(&one, "whole", "true"), "{}", body(&one));
    let zero = ask(&explorer, "block/0");
    assert!(says(&zero, "spent", "true"), "{}", body(&zero));
    let found = ask(&explorer, &format!("search?q={moved}"));
    assert!(says(&found, "kind", "\"transaction\""), "{}", body(&found));

    explorer.node().shutdown();
}

/// The holders table says how much of the chain it counted.
///
/// `/api/status` carries `fromTheStart` and `/api/address` carries `counted`.
/// This route carried neither, and its whole content is a claim about every
/// owner on the chain. An index that had read nothing answered `holders: 0`
/// with an empty table, which is the shape of a complete answer.
#[test]
fn the_holders_table_says_how_much_of_the_chain_it_counted() {
    let params = params();
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    let chain = forge.mine_many(&miner, 3);

    let explorer = explorer(params);
    feed(&explorer, &chain);

    let empty = ask(&explorer, "holders");
    assert!(says(&empty, "holders", "0"), "{}", body(&empty));
    assert!(
        says(&empty, "whole", "false") && says(&empty, "behind", "3"),
        "nobody holds anything, out of nothing read: {}",
        body(&empty)
    );

    explorer.refresh();
    let counted = ask(&explorer, "holders");
    assert!(says(&counted, "holders", "1"), "{}", body(&counted));
    assert!(says(&counted, "whole", "true"), "{}", body(&counted));

    explorer.node().shutdown();
}

/// The site is answered while it is reading the chain.
///
/// The door is opened before the first pass over the chain so that a visitor
/// gets a page saying "still reading the chain" rather than one that hangs.
/// That was true of the socket and false of everything behind it:
/// `Explorer::refresh` held the index across the whole walk and every route
/// takes the index on its first line, so the sentence the page exists to show
/// while the chain is read was the one thing that could not be served while
/// the chain was read. Measured at a thousand two hundred blocks, `/api/status`
/// was answered no times at all during the walk, and the single request in
/// flight waited the whole of it.
///
/// The walk now stops every so often and puts the index down. What is held
/// here is that a route is answered many times over during a rebuild, and that
/// no one answer waits anything like the length of it.
#[test]
fn a_route_is_answered_while_the_index_is_being_built() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let params = params();
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(&miner, 1_200);

    let explorer = explorer(params);
    feed(&explorer, &blocks);

    let running = AtomicBool::new(true);
    let asked = AtomicU64::new(0);
    let longest = AtomicU64::new(0);

    std::thread::scope(|scope| {
        scope.spawn(|| {
            while running.load(Ordering::Relaxed) {
                // The one route whose whole purpose is saying how far the
                // index has got. Timed around the call, so a request that is
                // blocked and then completes records the wait.
                let began = Instant::now();
                let _ = ask(&explorer, "status");
                longest.fetch_max(began.elapsed().as_micros() as u64, Ordering::Relaxed);
                asked.fetch_add(1, Ordering::Relaxed);
            }
        });

        while asked.load(Ordering::Relaxed) < 10 {
            std::hint::spin_loop();
        }
        asked.store(0, Ordering::Relaxed);
        longest.store(0, Ordering::Relaxed);
        let started = Instant::now();
        explorer.refresh();
        let rebuild = started.elapsed();
        let during = asked.load(Ordering::Relaxed);
        running.store(false, Ordering::Relaxed);
        let waited = longest.load(Ordering::Relaxed);

        println!(
            "reading 1,200 blocks took {rebuild:?}; /api/status was answered {during} \
             times while it ran, and the longest answer took {waited} us"
        );
        assert!(
            during >= 10,
            "{during} answers got through during the read, which is a site \
             that stopped rather than one that kept talking"
        );
        assert!(
            u128::from(waited) * 2 < rebuild.as_micros().max(2),
            "one /api/status waited {waited} us across a {rebuild:?} read, \
             which is a route queued behind the walk rather than served \
             between its turns"
        );

        // And what it says at the end of it is where it got to. This node
        // keeps no blocks on disk, so the bottom of the chain went with the
        // window a reorganisation could touch, and the index names the height
        // it starts at rather than passing off what it has as the whole.
        let status = ask(&explorer, "status");
        assert!(says(&status, "behind", "0"), "{}", body(&status));
        assert!(
            !body(&status).contains("\"from\":null"),
            "{}",
            body(&status)
        );
    });

    explorer.node().shutdown();
}

/// The lesson pages quote the same hot-set figure this program serves.
///
/// The site says three times, in two languages, what a note costs a node and
/// what the drawer weighs full. Those were 813 bytes and 107 MB, from before a
/// public key stopped carrying its decoded point. The papers were corrected to
/// 516 and 68 six days later; the lessons were not, and `/api/status` had been
/// serving 516 beside them the whole time. Somebody reading the page that
/// exists to explain the thesis was told the number the thesis turns on, and
/// told it half as large again as it is.
///
/// Read out of the running route rather than written down here, so the day the
/// measurement moves this fails rather than drifts.
#[test]
fn the_lessons_quote_the_hot_set_this_program_serves() {
    const EN: &str = include_str!("../../../web/i18n/en.json");
    const FR: &str = include_str!("../../../web/i18n/fr.json");

    let explorer = explorer(ConsensusParams::testnet());
    let status = body(&ask(&explorer, "status"));
    // Scoped to the hot object: `bytesPerNote` is also what the index costs
    // and what a fallen note costs an archivist, and those are other numbers.
    let hot = status.split_once("\"hot\":{").expect("a hot object").1;
    let digits = |text: &str, key: &str| -> u64 {
        let rest = text.split_once(key).expect("the field").1;
        rest.chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .expect("a number")
    };
    let per_note = digits(hot, "\"bytesPerNote\"");
    let at_capacity = digits(hot, "\"bytesAtCapacity\"");
    let megabytes = at_capacity.saturating_add(500_000) / 1_000_000;
    println!("the route says {per_note} bytes a note, {megabytes} MB at capacity");

    for (language, text) in [("English", EN), ("French", FR)] {
        assert!(
            text.contains(&format!("{per_note} bytes per note"))
                || text.contains(&format!("{per_note} octets par billet")),
            "the {language} lesson does not quote the {per_note} bytes a note this build measures"
        );
        assert!(
            text.contains(&format!("{megabytes} MB at capacity"))
                || text.contains(&format!("{megabytes} Mo à pleine capacité")),
            "the {language} lesson does not quote the {megabytes} MB the drawer comes to"
        );
        assert!(
            !text.contains("107 MB")
                && !text.contains("107 Mo")
                && !text.contains("107 méga")
                && !text.contains("107 mega"),
            "the {language} lesson still carries the figure from before the correction"
        );
    }
    explorer.node().shutdown();
}

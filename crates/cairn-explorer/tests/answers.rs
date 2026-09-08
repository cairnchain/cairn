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
use std::time::{Duration, Instant};

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

    // The disk half. The four above are about the chain, and a node can be
    // following it perfectly while writing none of it down.
    for field in ["unwritten", "unread", "unjudged", "unweighable", "filling"] {
        assert!(
            page.contains(&format!("\"{field}\":null")),
            "a healthy node says nothing is wrong with its disk either, in as \
             many words: {page}"
        );
    }
    // Null on a node with no block log wired, which is what these tests give
    // it; what matters here is that the field is served at all.
    assert!(page.contains("\"writtenThrough\":"), "{page}");
}

/// **A node whose disk has stopped taking writes does not read as a healthy
/// one.**
///
/// This page is the one program in the project that publishes the chain to
/// strangers, and it read five of the nine things its node can say about
/// itself. All five are about the chain. So a node whose disk had filled went
/// on validating, went on climbing, wrote nothing, and once it was
/// `MAX_BEHIND` past what it had written it switched itself off: measured, the
/// `node` object was byte for byte identical before and after, and the banner
/// fell through to the line about not being connected to anybody, whose last
/// clause promises it will learn about a new block when somebody reaches it
/// again. Nobody can. The listening socket is still bound, so a visitor's
/// connection completes and is never attached to anything.
///
/// `cairnd` reads all of these and stops on the fatal one, and so does the
/// wallet, which is what makes this an oversight rather than a decision.
///
/// The height on the disk is what makes this test worth more than the shape:
/// it is the one of the five whose value a healthy node moves, so a page that
/// stopped asking the node and answered from nothing would show it standing at
/// nought while the tip climbed. Filling a disk is not something this file can
/// do; `cairn-net/tests/audit_out_of_room.rs` does that against a real small
/// filesystem, and what is pinned here is that the answer carries the fields
/// at all and reads the moving one from the node rather than from a default.
#[test]
fn the_site_can_see_a_disk_that_has_stopped() {
    let params = params();
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(&miner, 6);

    let held = Archiving::open(params, "disk-visible");
    feed(&held.explorer, &blocks);
    held.explorer.refresh();

    let page = body(&ask(&held.explorer, "status"));
    // `unweighable` among them: a node nobody can show the chain to joins by
    // reading every block instead, which takes hours and from here is a site
    // with no chain on it and no complaint.
    for field in ["unwritten", "unread", "unjudged", "unweighable", "filling"] {
        assert!(
            page.contains(&format!("\"{field}\"")),
            "the site cannot see {field}, so a node in that state looks healthy \
             from here: {page}"
        );
    }
    assert!(
        page.contains("\"writtenThrough\":5"),
        "the height on the disk is not the one this node reached, so the page \
         is answering from something other than the node: {page}"
    );
}

/// **A node whose disk grows with the chain says so, in both numbers.**
///
/// While a node cannot show a newcomer the chain it cannot write its own
/// summary of it either, because the two are proved against the same header
/// forest, and writing that summary is what lets it drop old blocks. So
/// `--keep` is not being kept, and the disk grows with the chain, which is the
/// one thing this design exists to prevent.
///
/// The page served the bytes on the disk and not the budget beside them, so
/// there was nothing to read them against. The pair is the news; half of it is
/// a number.
///
/// The head record of the header log is damaged on purpose, which is what puts
/// a node in this state: the store will not stand behind a record whose
/// successor no longer names it, sets the headers aside, and rewrites them
/// from the blocks it still has, which start above the first block.
#[test]
fn a_node_that_cannot_hold_its_disk_budget_serves_both_numbers() {
    // A burial a test can reach, so upkeep writes a ledger and drops the
    // blocks under it, which is what every node with the default does once it
    // has a gigabyte.
    let params = params().with_burial(8);
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(&miner, 60);

    let directory = std::env::temp_dir().join(format!(
        "cairn-answers-{}-over-the-keep",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    {
        let (node, _) = Node::open_archiving(params, address, &directory).unwrap();
        node.keep_blocks(1);
        for block in &blocks {
            node.submit_block(block.clone()).unwrap();
        }
        let mut trimmed = false;
        for _ in 0..80 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if node.blocks_from().unwrap_or(0) > 0 {
                trimmed = true;
                break;
            }
        }
        assert!(trimmed, "the log was never trimmed, so this proves nothing");
        node.shutdown();
    }

    // A header is a version, a network, a height and then the parent. Changing
    // the head record's parent changes its identifier, so the record after it
    // no longer names it, which is the one thing the store refuses on. The
    // headers are then rewritten from the blocks that are left, which start
    // above the first block, so the node holds a chain it cannot show.
    let path = directory.join(cairn_store::HEADER_LOG);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[2 + 4 + 8] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();

    let (node, _) = Node::open_archiving(params, address, &directory).unwrap();
    node.keep_blocks(1);
    let filling = node
        .filling()
        .expect("a node that cannot show the chain to a newcomer");
    assert!(
        filling.over_the_keep(),
        "the disk is over the budget, which is what this is about: {filling:?}"
    );
    let explorer = Explorer::new(node);
    explorer.refresh();
    let page = body(&ask(&explorer, "status"));

    assert!(
        page.contains(&format!("\"bytes\":{}", filling.bytes)),
        "the bytes on the disk, read from the node rather than a default: {page}"
    );
    assert!(
        page.contains("\"keep\":1"),
        "and the budget they are over, or the bytes say nothing: {page}"
    );
    assert!(
        page.contains("\"overTheKeep\":true"),
        "said plainly as well, because the comparison is the news: {page}"
    );

    explorer.node().shutdown();
    drop(explorer);
    let _ = std::fs::remove_dir_all(&directory);
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
/// while the rebuild runs, against how often it manages the same question with
/// nobody rebuilding. The second half is the repair to this test. It used to
/// require a thousand questions and nothing else, which is a number about a
/// machine rather than about this code: the same spinning thread gets through
/// a few hundred turns on a busy CI runner and ten thousand on an idle laptop,
/// over the same rebuild. CI read a rebuild of 1.73 ms, in which no thread of
/// its was ever going to reach a thousand turns, and the test failed there
/// because the code was fast. The rate is now measured on the machine that is
/// running it, moments before, and what the rebuild has to leave standing is a
/// share of that rate rather than a count.
#[test]
fn a_rebuild_does_not_stop_the_node() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Long enough for the free-running count to be a rate rather than a
    /// sample, and short beside anything the rest of this test does.
    const UNHINDERED: std::time::Duration = std::time::Duration::from_millis(50);
    /// What the rebuild may cost the thread beside it. A walk that takes the
    /// chain for one block and lets it go between leaves that thread a seventh
    /// of what it had here; a walk that holds the chain to the tip leaves it
    /// one turn, whatever the machine. A fortieth sits between the two with
    /// room on both sides: five times under what the repaired walk leaves, and
    /// a hundred times over what a walk that stops the node does.
    const SHARE: u64 = 40;
    /// How small a share of a rebuild the longest single wait has to be.
    ///
    /// The two cases are two orders of magnitude apart, which is what makes
    /// this readable at all. A walk that takes the chain for one block and lets
    /// it go between makes the worst wait one block's work: measured over five
    /// idle runs, 26 to 49 microseconds of a 3.3 millisecond rebuild, about one
    /// percent. A walk that holds the chain to the tip makes the thread beside
    /// it wait the whole rebuild for its next turn, which is a hundred percent.
    ///
    /// Half sits between them, and it is set from the loaded case rather than
    /// the idle one. Inside a full workspace run this machine was seen at 936
    /// microseconds of a 3.3 millisecond rebuild, twenty eight percent, with
    /// the walk working correctly. A third would have refused that, and did.
    ///
    /// What this cannot do is fail on demand. Holding the chain across the walk
    /// is the defect it describes, and it cannot be written: `held_at` takes
    /// the chain itself, so a walk holding it would be a thread waiting on
    /// itself. The per-block release is enforced by the shape of the code
    /// rather than by a choice somebody could quietly reverse, and this stands
    /// as the measurement that says so. The neighbouring test
    /// `a_route_is_answered_while_the_index_is_being_built` is the one that
    /// does fail on demand: emptying `stand_aside` leaves it answering
    /// `/api/status` once over a whole rebuild.
    const SHARE_OF_THE_WALK: u32 = 2;

    let params = params();
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    // Long enough that a scheduling hiccup is a small share of it.
    //
    let blocks = forge.mine_many(&miner, 12_000);

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

        // What that thread manages with nobody holding the chain, on this
        // machine, in this run. Sleeping rather than spinning here, so the
        // measurement is of the node and not of two threads fighting over one
        // processor.
        asked.store(0, Ordering::Relaxed);
        let began = Instant::now();
        std::thread::sleep(UNHINDERED);
        let free = asked.load(Ordering::Relaxed);
        let freely = began.elapsed();

        asked.store(0, Ordering::Relaxed);
        longest.store(0, Ordering::Relaxed);
        let started = Instant::now();
        explorer.refresh();
        let rebuild = started.elapsed();
        let during = asked.load(Ordering::Relaxed);
        let waited = longest.load(Ordering::Relaxed);
        running.store(false, Ordering::Relaxed);

        // What the same thread would have got through over the length of the
        // rebuild had nothing been in its way.
        // Scaled in microseconds with integers. It is a count against a ratio
        // of two durations, and a float here buys nothing but a cast the
        // workspace lints refuse.
        let unhindered = Some(u128::from(free))
            .and_then(|count| count.checked_mul(rebuild.as_micros()))
            .and_then(|scaled| scaled.checked_div(freely.as_micros().max(1)))
            .and_then(|count| u64::try_from(count).ok())
            .unwrap_or(u64::MAX);
        println!(
            "rebuilding 12,000 blocks took {rebuild:?}; the node asked its own chain \
             {during} questions while it ran, against {unhindered} it would have \
             answered in that time with nobody rebuilding ({free} in {freely:?}), \
             waiting at most {waited} us for one"
        );
        // The walk reached the tip. It does not reach the first block: a
        // node holding no blocks on disk keeps only the window a
        // reorganisation could touch, so the bottom of this chain is gone and
        // the index starts where the node's blocks start, which is the whole
        // of the first repair in this file.
        let status = ask(&explorer, "status");
        assert!(says(&status, "behind", "0"), "{}", body(&status));
        assert!(
            unhindered >= 100,
            "with nobody rebuilding, this thread would have asked {unhindered} \
             questions over a rebuild of {rebuild:?}, which is too few for the \
             count during the rebuild to say anything"
        );
        // The walk takes the chain for one block at a time and lets it go
        // between, so a thread spinning on it gets a turn or several per
        // block and the count keeps pace with the chain. Held across the walk,
        // all it gets is the moment before the lock is taken and one turn when
        // it is given back.
        // The longest one question waited, against how long the whole rebuild
        // took. That is the difference between the two cases and nothing else
        // is: a walk that holds the chain to the tip makes the thread beside it
        // wait the whole rebuild for its next turn, and a walk that takes the
        // chain a block at a time never makes it wait for more than a block.
        //
        // The count cannot say it. Comparing a thread that takes a lock once
        // per block against a thread spinning on nothing measures the lock, not
        // the walk: at 1 200 blocks that read 160 turns against 54 807 free
        // running in the same 4.6 ms, which is 342 times and looks like a node
        // stopped dead. It was not stopped. It was interleaved, once per block,
        // and 1 200 blocks is where 160 comes from.
        //
        // The size is the other half, and it took three attempts to see it. At
        // 1 200 blocks the rebuild is about two milliseconds, so one ordinary
        // scheduling hiccup is a third of the whole measurement: the same
        // build read 47 microseconds waited on one run and 936 on the next,
        // against a rebuild that barely moved. Neither statistic can separate
        // two cases inside its own noise. Ten times the blocks makes the
        // rebuild long enough that a hiccup is a few percent of it, which is
        // what lets a ratio mean anything at all.
        let longest = Duration::from_micros(waited);
        assert!(
            longest.saturating_mul(SHARE_OF_THE_WALK) < rebuild,
            "one question waited {longest:?} of a {rebuild:?} rebuild, so the walk held \
             the chain across it rather than taking it a block at a time. The node got \
             {during} questions in while it ran, against {unhindered} free running in \
             the same time"
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

/// Every page that quotes the hot set quotes the figure this program serves.
///
/// The site said three times, in two languages, what a note costs a node and
/// what the drawer weighs full. Those were 813 bytes and 107 MB, from before a
/// public key stopped carrying its decoded point. The papers were corrected to
/// 516 and 68 six days later; the lessons were not, and `/api/status` had been
/// serving 516 beside them the whole time. Somebody reading the page that
/// exists to explain the thesis was told the number the thesis turns on, and
/// told it half as large again as it is.
///
/// The lessons were the half that had gone stale, so the lessons were the half
/// that got a test. The papers say it in five more places and the README in
/// three, and none of those was covered by anything: the same six days would
/// have passed unnoticed the other way round. They are all here now.
///
/// The one figure on the site that is neither of the two measurements but the
/// distance between them.
///
/// Five sentences in four files say the index is the larger of the explorer's
/// two growing costs by about eight, and the eight is not written down
/// anywhere: it is 565 over 72, and it moves the day either of those moves.
/// Both halves have instruments and the ratio between them had none, so a
/// correction to one constant would have left every one of those sentences
/// confidently wrong, in two languages, with nothing to catch it. That is the
/// exact shape of the last thirteen wrong figures: the number was checked and
/// the sentence built on it was not.
///
/// The ratio is what is held, not the wording, and it is held to the whole
/// number the sentences round it to. The failure names where to go.
#[test]
fn the_ratio_the_site_calls_eight_is_the_one_this_program_serves() {
    const EN: &str = include_str!("../../../web/i18n/en.json");
    const FR: &str = include_str!("../../../web/i18n/fr.json");
    const SCRIPT: &str = include_str!("../../../web/cairn.js");

    let explorer = explorer(ConsensusParams::testnet());
    let status = body(&ask(&explorer, "status"));
    explorer.node().shutdown();
    let digits = |text: &str, key: &str| -> u64 {
        let rest = text.split_once(key).expect("the field").1;
        rest.chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .expect("a number")
    };
    let index = digits(
        status.split_once("\"index\":{").expect("an index object").1,
        "\"bytesPerNote\"",
    );
    let cold = digits(
        status.split_once("\"cold\":{").expect("a cold object").1,
        "\"bytesPerNote\"",
    );
    let times = index
        .saturating_add(cold / 2)
        .checked_div(cold)
        .expect("a fallen note costs something");
    println!("the route says {index} bytes a note against {cold}, which is {times} times");

    // Where the sentence is, so whoever moves a constant is told rather than
    // left to search. The comment in the script and the two doc comments are
    // as much a published figure as the prose: they are what the next person
    // reads before deciding the pages are right.
    for (where_it_is, text, phrase) in [
        (
            "web/i18n/en.json",
            EN,
            "the larger of its two by about eight times",
        ),
        (
            "web/i18n/fr.json",
            FR,
            "le plus lourd de ses deux coûts, d'un facteur huit environ",
        ),
        (
            "web/cairn.js",
            SCRIPT,
            "the smaller half of it by nearly eight times",
        ),
    ] {
        assert!(
            text.contains(phrase),
            "{where_it_is} no longer says `{phrase}`, which is what this checks"
        );
    }
    assert_eq!(
        times, 8,
        "the index costs {index} bytes a note and the cold set {cold}, which is {times} \
         times and not eight. Every one of these says eight and all of them are now \
         wrong: web/i18n/en.json, web/i18n/fr.json, web/cairn.js, and the doc comments \
         on INDEX_BYTES_PER_NOTE in cairn-explorer/src/api.rs and on BYTES_PER_NOTE in \
         cairn-explorer/src/index.rs"
    );
}

/// Read out of the running route rather than written down here, so the day the
/// measurement moves this fails rather than drifts.
#[test]
fn the_pages_that_quote_the_hot_set_quote_what_this_program_serves() {
    const EN: &str = include_str!("../../../web/i18n/en.json");
    const FR: &str = include_str!("../../../web/i18n/fr.json");
    const PAPER: &str = include_str!("../../../docs/cairn-whitepaper.html");
    const DESIGN: &str = include_str!("../../../docs/cairn-design.html");
    const README: &str = include_str!("../../../README.md");
    const QUESTIONS: &str = include_str!("../../../docs/cairn-open-questions.html");

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

    // The paper states both figures in its parameter list and both again in
    // its thirty-year table, which is the row the whole design is about.
    for stated in [
        format!("<span class=\"k\">Bytes per hot note, measured</span><span class=\"v\">{per_note}</span>"),
        format!("<span class=\"k\">Hot set at capacity</span><span class=\"v\">{megabytes} MB</span>"),
        format!("measured at {per_note} bytes each, about {megabytes} MB"),
        format!("{per_note} bytes per note, which is the note"),
    ] {
        assert!(
            PAPER.contains(&stated),
            "the paper does not say `{stated}`, which is what this program serves"
        );
    }
    assert!(
        DESIGN.contains(&format!("un billet chaud coûte {per_note} octets"))
            && DESIGN.contains(&format!("soit environ {megabytes} Mo")),
        "the design paper does not quote the hot set this program serves"
    );
    assert!(
        README.contains(&format!("about {megabytes} MB, whatever the chain's age"))
            && README.contains(&format!("{megabytes} MB of hot notes")),
        "the README does not quote the hot set this program serves"
    );

    // The other measured per-note figure, and the same story two days later.
    // The cold set's cost was written into the open questions by hand on the
    // 31st as 64 bytes, the measured slope landed at 72 on the 2nd, and the
    // whole of that paper's archivist table is that figure times the traffic
    // it names down the side. The lessons never drifted because they take it
    // from this route; the paper did because it did not.
    let cold = status.split_once("\"cold\":{").expect("a cold object").1;
    let per_fallen = digits(cold, "\"bytesPerNote\"");
    println!("the route says {per_fallen} bytes a fallen note");
    assert!(
        QUESTIONS.contains(&format!(
            "l'archive de la cave, {per_fallen} octets par billet tombé"
        )),
        "the open questions do not quote the {per_fallen} bytes a fallen note this build measures"
    );
    explorer.node().shutdown();
}

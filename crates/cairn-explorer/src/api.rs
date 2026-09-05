//! Answering the questions a page asks about the chain.
//!
//! Amounts, difficulties and accumulated work are sent as decimal strings
//! rather than JSON numbers. A pebble count runs past what a double can hold
//! exactly, and a money figure that is silently rounded in the last digits is
//! the kind of wrong that nobody notices until it matters.

use std::cell::RefCell;
use std::sync::{Mutex, MutexGuard, PoisonError};

use cairn_chain::{ChainStore, Outdated};
use cairn_crypto::PublicKey;
use cairn_ledger::block::Block;
use cairn_ledger::emission::reward_at;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::work_of;
use cairn_ledger::transaction::{Transfer, Witness};
use cairn_ledger::validation::ConsensusParams;
use cairn_net::joining::Joined;
use cairn_net::node::{Probation, Stranded};
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::{hex, Amount, Hash32};

use crate::index::{Head, Held, Index, NoteRecord, Reading, Size};
use cairn_http::Writer;
use cairn_http::{Request, Response};

/// Blocks listed per page.
const PAGE: usize = 25;
/// Largest page a caller may ask for.
///
/// An answer that quotes blocks holds all of them at once while it is written,
/// and a block runs to `max_block_bytes`, so the ceiling on a page is a ceiling
/// on what one stranger can make this node carry. It is the same order as the
/// number of blocks a peer may ask for in one message, for the same reason.
const MAX_PAGE: usize = 128;
/// Entries returned for one address before the caller has to ask for more.
///
/// Both the notes an address holds and the movements through it are paged. An
/// address that has mined for a year holds hundreds of thousands of notes, and
/// an answer carrying all of them is one an anonymous caller could ask for
/// repeatedly to make this node do arbitrary work and send arbitrary bytes.
const ADDRESS_PAGE: usize = 100;
/// Notes looked at for one address before the walk gives up.
///
/// Wide enough that an ordinary address is counted exactly, narrow enough that
/// the cost of asking stays the caller's own rather than everyone else's.
const ADDRESS_SCAN: usize = 10_000;

/// Bytes one hot note costs a node: the note itself, its identifier, and its
/// share of the sparse tree.
///
/// Written down here rather than worked out, and that has to be said plainly
/// because the doc comment used to claim the opposite: "the number moves if the
/// implementation ever changes", of a literal that moves when somebody edits it.
/// It cannot be worked out here. The reading comes from
/// `cairn-ledger/examples/footprint.rs`, which builds the three structures in a
/// process of their own and reads the resident set back, because the answer is
/// dominated by what an allocator does rather than by the size of a note; a
/// resident reading is not something a test can assert on.
///
/// What is checked is the half that went wrong last time. This figure was 813
/// until a public key stopped being kept in the form it is verified in, and
/// every page that quoted it went on quoting 813 for five days after the papers
/// were corrected. `tests/answers.rs` now reads this out of the running route
/// and holds the papers, the README and both languages of the lessons against
/// it, so the pages and the program can no longer drift apart.
const HOT_BYTES_PER_NOTE: u64 = 516;

/// Bytes one fallen note costs a node that keeps the whole cold set, measured
/// the same way.
///
/// A slope and not a reading: the resident set was taken at five points over
/// three million fallen notes, and this is what it climbed by. The same
/// measurement on a node that keeps only the roots has no slope at all, which
/// is the claim the protocol rests on and the reason this cost is an
/// archivist's alone.
const COLD_BYTES_PER_NOTE: u64 = 72;

/// Bytes one note that has ever existed costs the index.
///
/// Named here so `/api/status` can carry both figures side by side. The site
/// used to call the cold set the explorer's growing cost, and the index is
/// nearly eight times larger, so the page was pointing at the smaller half.
const INDEX_BYTES_PER_NOTE: u64 = crate::index::BYTES_PER_NOTE;

/// The node the explorer reads, plus what it keeps on top of it.
pub(crate) struct Explorer {
    node: Node,
    index: Mutex<Index>,
    /// How many callers are waiting for the index at this moment.
    ///
    /// Read by the walk between turns. A lock is not a queue on any of these
    /// platforms: the walk let go of the index nineteen times over one
    /// measured rebuild and was handed it straight back every time, while one
    /// `/api/status` waited half the rebuild out. This is how the walk knows
    /// somebody is there.
    waiting: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for Explorer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Explorer").finish_non_exhaustive()
    }
}

impl Explorer {
    pub(crate) fn new(node: Node) -> Self {
        Self {
            node,
            index: Mutex::new(Index::new()),
            waiting: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) fn node(&self) -> &Node {
        &self.node
    }

    /// The index, counted as waited for while it is waited for.
    fn index(&self) -> MutexGuard<'_, Index> {
        use std::sync::atomic::Ordering;
        self.waiting.fetch_add(1, Ordering::Relaxed);
        let index = self.index.lock().unwrap_or_else(PoisonError::into_inner);
        self.waiting.fetch_sub(1, Ordering::Relaxed);
        index
    }

    /// Reads whatever the chain has added since the last call.
    ///
    /// The chain is taken twice, for one question each, and let go of before
    /// any block is read. It used to be held for the whole walk, with a seek
    /// and a decode per block inside it, which made one ordinary
    /// reorganisation of one block stop the entire node for as long as it
    /// took to read the chain back: six seconds at half a million empty
    /// blocks, minutes at a hundred notes a block, with incoming block
    /// validation queued behind it the whole time.
    ///
    /// The index is taken and put down once per turn of the walk rather than
    /// once for the whole of it, which is the other half of the same thing.
    /// Every route on this site takes the index on its first line, so a walk
    /// that held it to the tip answered nobody until it got there: measured at
    /// a thousand two hundred blocks, `/api/status` was answered no times at
    /// all while the walk ran, and the one request in flight waited the whole
    /// of it. That is the site the door was opened early to avoid.
    pub(crate) fn refresh(&self) {
        loop {
            let began = std::time::Instant::now();
            if self.read_a_batch() == Reading::Done {
                return;
            }
            self.stand_aside(began.elapsed());
        }
    }

    /// Waits for whoever wanted the index to have had it, for no longer than
    /// the turn just taken.
    ///
    /// Letting go of a lock and asking for it back in the same breath is a
    /// request these platforms are glad to grant: the thread still running is
    /// the one that gets it, and the request that arrived while it ran waits
    /// on. Measured, the walk let go nineteen times over one rebuild and one
    /// `/api/status` still waited half of that rebuild out.
    ///
    /// Bounded by what the turn cost, because the index has to be built whether
    /// anyone is asking or not: however hard this site is being asked, reading
    /// the chain cannot come to more than twice what it would come to with
    /// nobody looking.
    fn stand_aside(&self, took: std::time::Duration) {
        use std::sync::atomic::Ordering;
        let began = std::time::Instant::now();
        while self.waiting.load(Ordering::Relaxed) > 0 && began.elapsed() < took {
            std::thread::yield_now();
        }
    }

    /// One turn of the walk, with the index taken for that turn alone.
    fn read_a_batch(&self) -> Reading {
        let mut index = self.index();
        let last_read = index.covers().map(|(_, through)| through);
        let head = self.node.with_chain(|chain| {
            chain.height().map(|tip| Head {
                tip,
                at_last_read: last_read.and_then(|height| chain.id_at(height)),
            })
        });
        let Some(head) = head else {
            return Reading::Done;
        };
        index.refresh(&head, |height| self.held_at(height))
    }

    /// One block of the followed branch, with the chain held for as little of
    /// it as the answer allows.
    ///
    /// Everything the chain has to say is asked in one turn of its lock, and
    /// the disk is only touched once that lock is gone. A node holds the
    /// bodies of the blocks it could still have to undo and no more, so a
    /// rebuild reads almost all of its blocks off a disk, and seeking a disk
    /// with the chain held is what this whole shape exists to stop.
    ///
    /// The log holds one run of heights and says where both ends of it are, so
    /// a height it will not produce is under the run, over it, or inside it.
    /// The last is a fault in the machine: the record is there and the disk
    /// would not read it back. Only the first is a block that is gone for
    /// good, and only for the first may the walk step over the height and
    /// carry on above it.
    ///
    /// Asking [`Node::written_through`] alone could not tell the third from
    /// the first, because every way a read can fail arrives as `None`. So one
    /// unreadable record in the middle of an archive was read as the bottom of
    /// the run moving up: the index threw away every block it had read under
    /// it and started again above it, and since each refresh resumes from
    /// where the last one stopped, nothing went back for them while the
    /// process ran. [`Node::blocks_from`] is the other end of the run, it
    /// exists for exactly this, and it was one call away the whole time.
    fn held_at(&self, height: u64) -> Held {
        // The identifier the branch carries here, where the chain still holds
        // one, and the body if the chain still holds that.
        let (expected, in_memory) = self
            .node
            .with_chain(|chain| (chain.id_at(height), chain.block_at(height).cloned()));
        if let Some(block) = in_memory {
            return Held::Block(Box::new(block));
        }

        if let Some(block) = self.node.archived_at(height) {
            // The log is brought level with the chain just after the chain
            // moves, so for a moment after a reorganisation it still holds
            // the branch this node has left. A block off that branch is one
            // the index would go on to answer about as though it had
            // happened. Where the chain still remembers what its branch
            // carries at this height, the chain is the authority, and where
            // it does not the height is too deep for anything to have
            // changed under it.
            return if expected.is_none_or(|id| id == block.id()) {
                Held::Block(Box::new(block))
            } else {
                Held::Waiting
            };
        }

        nothing_at(height, self.node.blocks_from(), self.node.written_through())
    }

    /// Routes one request, or reports that nothing here answers it.
    ///
    /// Read twice, with both locks let go of in between. A node holds the
    /// bodies of the blocks it could still have to undo and no more, so most
    /// of what an answer quotes comes off a disk, and seeking a disk with the
    /// chain held is one anonymous caller deciding how long every peer waits.
    /// So the first reading answers from memory and *names* the heights it
    /// could not have; those are fetched with nothing held; the second reading
    /// is the answer. It is what the sync layer does with the blocks a peer
    /// asks for, for the same reason.
    ///
    /// The first reading is thrown away, and used to be a whole answer built
    /// and discarded: every block re-encoded to report its size and every
    /// input of every transfer looked up to work out a fee, twice, for any
    /// page about history. It now skips both, which is the whole of what an
    /// answer costs. What is left of it is a walk that names heights.
    pub(crate) fn answer(&self, request: &Request) -> Option<Response> {
        // Before either lock. Everything else this server serves (the page,
        // its script, the papers) would otherwise queue behind the indexer
        // for a chain it is never going to read.
        request.after("/api/")?;

        // Before the chain, because two of these questions are answered out
        // of the chain itself and asking them with it in hand is this node
        // waiting on itself.
        let health = Health::of(&self.node);

        let (_, wanted) = self.read(request, &[], Pass::Naming, &health);
        let fetched: Vec<Block> = wanted
            .iter()
            .filter_map(|height| self.node.archived_at(*height))
            .collect();
        // Whatever the second reading still wants is a block this node does
        // not hold, and it is answered around rather than asked for again.
        self.read(request, &fetched, Pass::Answering, &health).0
    }

    /// One reading of the request, with the blocks fetched for it so far, and
    /// the heights it turned out to still want.
    fn read(
        &self,
        request: &Request,
        fetched: &[Block],
        pass: Pass,
        health: &Health,
    ) -> (Option<Response>, Vec<u64>) {
        let index = self.index();
        self.node.with_chain(|chain| {
            let context = Context {
                chain,
                index: &index,
                health,
                fetched,
                pass,
                wanted: RefCell::new(Vec::new()),
            };
            let answer = route(&context, request);
            (answer, context.wanted.into_inner())
        })
    }
}

/// Which kind of nothing a height is, when the node would not produce a block
/// for it.
///
/// `from` and `through` are the two ends of the one run of blocks the log
/// holds. Under the run the block is gone for good and the walk may step over
/// it. Over the run it has not been written yet. Between them the record is
/// there and the disk would not hand it back, and that is a fault in the
/// machine rather than an answer about the chain: the walk stops on it and
/// asks again next time.
///
/// Kept apart from its caller because it is the whole of the repair. It used
/// to read `through` alone, so a record that would not read looked exactly
/// like the bottom of the run moving up, and one bad sector cost the index
/// every block underneath it for as long as the process ran.
pub(crate) fn nothing_at(height: u64, from: Option<u64>, through: Option<u64>) -> Held {
    match (from, through) {
        (Some(from), Some(through)) => {
            if height < from {
                Held::Dropped
            } else if height <= through {
                Held::Refused
            } else {
                Held::Waiting
            }
        }
        // A node keeping no blocks at all has nothing under the window its
        // chain holds in memory, and nothing is coming.
        _ => Held::Dropped,
    }
}

/// What the node says about its own state.
///
/// The site asked it none of this. It called five `Node` methods and not one
/// of them was about whether the node was still following the chain, so it
/// went on serving a frozen tip, a frozen supply and a frozen list of blocks
/// with no notice anywhere. Two of these mean the node has stopped and will
/// not start again on its own, and from the outside all of them look exactly
/// like a node that is working.
#[derive(Debug)]
struct Health {
    outdated: Option<Outdated>,
    stranded: Option<Stranded>,
    probation: Option<Probation>,
    joining: Joined,
    out_of_reach: u64,
    peers: usize,
}

impl Health {
    /// Asked with nothing held. `probation` and `joining` read the chain, so
    /// this cannot be done from inside a route.
    fn of(node: &Node) -> Self {
        Self {
            outdated: node.outdated(),
            stranded: node.stranded(),
            probation: node.probation(),
            joining: node.joining(),
            out_of_reach: node.out_of_reach(),
            peers: node.peer_count(),
        }
    }
}

/// Which of the two readings of a request this is.
///
/// The naming one exists to write down the heights the answer will need, and
/// nothing it produces is sent, so it does not do the two things a route
/// spends its time on. An anonymous GET used to buy twice the chain lock a
/// peer's own request for the same blocks does, and what waits behind that
/// lock is incoming block validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pass {
    Naming,
    Answering,
}

/// Everything a route reads, held still for the length of one answer.
struct Context<'a> {
    chain: &'a ChainStore,
    index: &'a Index,
    health: &'a Health,
    /// Blocks already fetched off the log for this request. A page's worth at
    /// most, which is what bounds the memory one answer stands for.
    fetched: &'a [Block],
    pass: Pass,
    /// Heights this reading wanted and did not have, for the one after it.
    wanted: RefCell<Vec<u64>>,
}

impl Context<'_> {
    fn params(&self) -> &ConsensusParams {
        self.chain.params()
    }

    /// Whether this reading is the one whose answer is sent.
    ///
    /// What it guards is the work, not the shape: a field left out of the
    /// reading nobody sees is a field nobody misses.
    fn answering(&self) -> bool {
        self.pass == Pass::Answering
    }

    /// The block at `height` on the followed branch, when it is already in
    /// hand.
    ///
    /// A node lets go of the bodies of blocks too deep to be undone, which is
    /// what keeps its memory from growing with the chain. An explorer answers
    /// about all of them, so the rest sit in the log in order of height, and
    /// nothing here goes to the log, because this runs with the chain held. A
    /// height that is not in hand is written down instead, and the reading
    /// after this one has it.
    fn block_at(&self, height: u64) -> Option<Block> {
        if let Some(block) = self.chain.block_at(height) {
            return Some(block.clone());
        }
        if let Some(block) = self
            .fetched
            .iter()
            .find(|block| block.header.height == height)
        {
            return Some(block.clone());
        }
        let mut wanted = self.wanted.borrow_mut();
        if !wanted.contains(&height) {
            wanted.push(height);
        }
        None
    }

    /// The same, found by identifier.
    fn block(&self, id: &Hash32) -> Option<Block> {
        if let Some(block) = self.chain.block(id) {
            return Some(block.clone());
        }
        self.block_at(self.chain.height_of(id)?)
    }

    fn height(&self) -> Option<u64> {
        self.chain.height()
    }

    /// Blocks mined on top of the one at `height`, the block itself counted.
    fn confirmations(&self, height: u64) -> u64 {
        self.height()
            .and_then(|tip| tip.checked_sub(height))
            .and_then(|behind| behind.checked_add(1))
            .unwrap_or(0)
    }
}

/// Writes how large something is, in the reading that reports it.
///
/// Encoding a block again to count its bytes is the largest single thing a
/// page of blocks does: a hundred and twenty eight of them at the byte
/// ceiling is a hundred and twenty eight megabytes through the encoder. The
/// naming reading does not need the number and no longer pays for it.
fn field_size(json: &mut Writer, context: &Context<'_>, encode: impl FnOnce() -> usize) {
    match context.answering().then(encode) {
        Some(size) => json.field_usize("size", size),
        None => json.field_null("size"),
    }
}

fn route(context: &Context<'_>, request: &Request) -> Option<Response> {
    if let Some(rest) = request.after("/api/") {
        return Some(match rest {
            "status" => status(context),
            "params" => params(context),
            "blocks" => blocks(context, request),
            "pool" => pool(context, request),
            "holders" => holders(context),
            "search" => search(context, request),
            other => match other.split_once('/') {
                Some(("block", reference)) => block(context, reference),
                Some(("tx", id)) => transaction(context, id),
                Some(("address", owner)) => address(context, owner, request),
                Some(("note", id)) => note(context, id),
                _ => Response::error(404, "no such endpoint"),
            },
        });
    }
    None
}

fn status(context: &Context<'_>) -> Response {
    let params = context.params();
    let state = context.chain.state();
    let totals = context.index.totals();
    let tip_height = context.height();

    let mut json = Writer::new();
    json.begin_object();

    json.key("network");
    network_object(&mut json, params);

    json.key("tip");
    match (tip_height, context.chain.tip()) {
        (Some(height), Some(id)) => {
            json.begin_object();
            json.field_u64("height", height);
            json.field_str("id", &id.to_string());
            if let Some(block) = context.block(&id) {
                json.field_u64("timestamp", block.header.timestamp);
                json.field_str("difficulty", &block.header.difficulty.to_string());
                json.field_usize("transfers", block.transfers.len());
            }
            json.end_object();
        }
        _ => json.null(),
    }

    json.field_str("work", &context.chain.total_work().to_string());
    json.field_usize("blocksKnown", context.chain.len());
    json.field_usize("indexed", context.index.blocks_read());
    json.field_usize("peers", context.health.peers);
    json.field_usize("pool", context.chain.pool_len());
    json.field_bool("archiving", context.chain.is_archiving());

    json.key("index");
    index_object(&mut json, context, tip_height);

    json.key("node");
    node_object(&mut json, context);

    json.key("hot");
    json.begin_object();
    json.field_usize("notes", state.hot_len());
    json.field_usize("capacity", params.hot_capacity);
    json.field_u64("bytesPerNote", HOT_BYTES_PER_NOTE);
    json.field_str(
        "bytesAtCapacity",
        &u64::try_from(params.hot_capacity)
            .unwrap_or(u64::MAX)
            .saturating_mul(HOT_BYTES_PER_NOTE)
            .to_string(),
    );
    json.field_usize("grace", state.grace_len());
    json.end_object();

    json.key("cold");
    json.begin_object();
    json.field_str("notes", &state.cold().len().to_string());
    // What a node actually carries for the cold set, whatever its size.
    json.field_usize("roots", 64);
    json.field_u64("bytesPerNote", COLD_BYTES_PER_NOTE);
    json.field_bool("kept", state.cold().is_archiving());
    json.end_object();

    json.key("supply");
    json.begin_object();
    // The ledger states this now, so the explorer stops keeping its own books
    // beside it. Two numbers for the same thing meant either could be wrong
    // and nothing would say which, and the chain's own answer is the one a
    // header commits to.
    json.field_str("issued", &state.supply().as_pebbles().to_string());
    // What the index made of the same chain, kept so the two can be compared
    // rather than trusted. They are computed from different things: the
    // ledger from emission accounting, this from the notes themselves.
    json.field_str("counted", &totals.issued().as_pebbles().to_string());
    json.field_str("fees", &totals.fees.as_pebbles().to_string());
    json.field_str(
        "paidToMiners",
        &totals.paid_to_miners.as_pebbles().to_string(),
    );
    let next_height = tip_height
        .and_then(|height| height.checked_add(1))
        .unwrap_or(0);
    json.field_str(
        "nextReward",
        &reward_at(
            next_height,
            params.halving_interval,
            params.initial_reward,
            params.tail_reward,
        )
        .as_pebbles()
        .to_string(),
    );
    json.field_u64("halvingInterval", params.halving_interval);
    json.field_u64(
        "nextHalving",
        next_halving(next_height, params.halving_interval),
    );
    json.end_object();

    json.key("chain");
    json.begin_object();
    json.field_u64("transfers", totals.transfers);
    json.field_u64("notesCreated", totals.notes_created);
    json.field_u64("notesSpent", totals.notes_spent);
    json.field_usize("holders", context.index.holders());
    json.end_object();

    json.end_object();
    Response::json(json.finish())
}

/// How much of the chain the index has read, and what it cost to read it.
///
/// Every number a page states about who owns what comes out of this index and
/// is only as wide as the index is. Until this was reported, the one signal
/// that it had read nothing at all was a count of blocks in the footer, in the
/// palest ink on the page, with nothing to compare it against.
fn index_object(json: &mut Writer, context: &Context<'_>, tip: Option<u64>) {
    let covered = context.index.covers();
    let size = context.index.size();
    json.begin_object();
    if let Some((from, through)) = covered {
        json.field_u64("from", from);
        json.field_u64("through", through);
    } else {
        json.field_null("from");
        json.field_null("through");
    }
    json.field_u64("behind", behind_of(tip, covered));
    json.field_bool("fromTheStart", context.index.reads_from_the_start());
    json.field_usize("blocks", context.index.blocks_read());
    index_cost(json, size);
    json.end_object();
}

/// Blocks of the branch the index has not read.
fn behind_of(tip: Option<u64>, covered: Option<(u64, u64)>) -> u64 {
    match (tip, covered) {
        (Some(tip), Some((_, through))) => tip.saturating_sub(through),
        (Some(tip), None) => tip.saturating_add(1),
        _ => 0,
    }
}

/// What the index had read when this answer was written.
///
/// Every route under here answers out of the index, and the index is not the
/// chain: it is as much of the chain as this program has read since it
/// started. The gap between the two is not a corner case. It is the first
/// minutes of every run and every restart, and the door is deliberately opened
/// during it, so it is a window strangers are invited into.
///
/// Inside that window four answers were stated as facts about the chain. A
/// note the chain had already spent was published as unspent. `/api/tx` said
/// "no such transaction" about a transfer `/api/block` was printing in the
/// same instant off the same program. The search box, given a transaction
/// identifier, announced it as an address. And the holders table answered that
/// nobody on this chain holds anything. One thing was missing from all four:
/// how much of the chain had been read. It is written here, once, and carried
/// by every answer that comes out of the index.
fn coverage(json: &mut Writer, context: &Context<'_>) {
    let covered = context.index.covers();
    let behind = behind_of(context.height(), covered);
    json.key("coverage");
    json.begin_object();
    if let Some((from, through)) = covered {
        json.field_u64("from", from);
        json.field_u64("through", through);
    } else {
        json.field_null("from");
        json.field_null("through");
    }
    json.field_u64("behind", behind);
    // The chain from its first block to where it now reaches. Anything short
    // of that and something this answer does not carry may still be on the
    // chain, which is the difference between "there is no such thing" and "I
    // have not got there yet".
    json.field_bool("whole", context.index.reads_from_the_start() && behind == 0);
    json.end_object();
}

/// A four hundred and four that says how much of the chain was looked in.
///
/// The status stays what it was: this program does not have the thing. What it
/// carries now is whether it could have. A bare 404 from an index that has read
/// a tenth of the chain reads as "no such transaction" and means "not yet",
/// and the page says different words for the two.
fn not_found(context: &Context<'_>, message: &str) -> Response {
    let mut json = Writer::new();
    json.begin_object();
    json.field_str("error", message);
    coverage(&mut json, context);
    json.end_object();
    Response {
        status: 404,
        ..Response::json(json.finish())
    }
}

/// What the index is made of, so an operator can find out what running this
/// program will come to.
fn index_cost(json: &mut Writer, size: Size) {
    json.field_str("notes", &size.notes.to_string());
    json.field_str("transactions", &size.transactions.to_string());
    json.field_str("owners", &size.owners.to_string());
    json.field_str("movements", &size.movements.to_string());
    json.field_u64("bytesPerNote", INDEX_BYTES_PER_NOTE);
    json.field_str("bytes", &size.bytes.to_string());
}

/// Whether the node under this website is still following the chain.
///
/// Two of these mean it has stopped and will not start again, and from the
/// outside all of them look exactly like a node that is working: a height, a
/// supply, a list of blocks, and no complaint. The website ran on its own flag
/// and never asked, so it went on serving a tip that had stopped moving with
/// nothing anywhere to say so. The wallet has a sentence for every one of
/// them; this is where the site gets the same.
fn node_object(json: &mut Writer, context: &Context<'_>) {
    let node = context.health;
    json.begin_object();

    match node.outdated {
        Some(outdated) => {
            json.key("outdated");
            json.begin_object();
            json.field_u64("height", outdated.height);
            json.field_u64("required", u64::from(outdated.required));
            json.field_u64("known", u64::from(outdated.known));
            json.end_object();
        }
        None => json.field_null("outdated"),
    }

    match node.stranded {
        Some(stranded) => {
            json.key("stranded");
            json.begin_object();
            json.field_u64("anchor", stranded.anchor);
            json.field_u64("settlesAt", stranded.settles_at);
            json.field_u64("waited", stranded.waited);
            json.end_object();
        }
        None => json.field_null("stranded"),
    }

    match node.probation {
        Some(probation) => {
            json.key("probation");
            json.begin_object();
            json.field_u64("anchor", probation.anchor);
            json.field_u64("checked", probation.checked());
            json.field_u64("owed", probation.owed());
            json.end_object();
        }
        None => json.field_null("probation"),
    }

    json.field_str("joining", &node.joining.to_string());
    json.field_u64("outOfReach", node.out_of_reach);
    json.end_object();
}

/// Blocks left before the reward halves.
fn next_halving(height: u64, interval: u64) -> u64 {
    if interval == 0 {
        return 0;
    }
    let into = height.checked_rem(interval).unwrap_or(0);
    interval.saturating_sub(into)
}

fn network_object(json: &mut Writer, params: &ConsensusParams) {
    json.begin_object();
    json.field_str("name", params.network_name());
    json.field_str("id", &format!("0x{:08x}", params.network.as_u32()));
    match params.genesis {
        Some(genesis) => json.field_str("genesis", &genesis.to_string()),
        None => json.field_null("genesis"),
    }
    json.field_u64("opensAt", params.opens_at);
    json.end_object();
}

/// The rules of the network, as one document a page can render.
///
/// Every field here is consensus but one. Two nodes that disagree on any of
/// them build different chains while believing they are on the same one, which
/// is why the page shows them rather than describing them from memory. The one
/// that is not is `bytesPerNote`, which is a measurement of this build and not
/// a rule: it rides along because the capacity beside it means nothing to a
/// reader without it.
fn params(context: &Context<'_>) -> Response {
    let params = context.params();
    let mut json = Writer::new();
    json.begin_object();
    json.key("network");
    network_object(&mut json, params);
    json.field_u64("targetBlockTime", params.target_block_time);
    json.field_str("genesisDifficulty", &params.genesis_difficulty.to_string());
    json.field_usize("hotCapacity", params.hot_capacity);
    json.field_u64("bytesPerNote", HOT_BYTES_PER_NOTE);
    json.field_str(
        "initialReward",
        &params.initial_reward.as_pebbles().to_string(),
    );
    json.field_str("tailReward", &params.tail_reward.as_pebbles().to_string());
    json.field_u64("halvingInterval", params.halving_interval);
    json.field_str(
        "pebblesPerCairn",
        &cairn_primitives::amount::PEBBLES_PER_CAIRN.to_string(),
    );
    json.field_usize("maxTransfersPerBlock", params.max_transfers_per_block);
    json.field_usize("maxInputsPerTransfer", params.max_inputs_per_transfer);
    json.field_usize("maxOutputsPerTransfer", params.max_outputs_per_transfer);
    json.field_u64("maxTimestampDrift", params.max_timestamp_drift);
    json.end_object();
    Response::json(json.finish())
}

/// How much one answer carries, as the caller asked for it.
///
/// Clamped rather than refused: somebody who asks for a million is handed a
/// page, and somebody who asks for none is still handed something. What is not
/// on offer is an answer whose size is the caller's to choose, because the work
/// of building it is not the caller's to pay.
fn limit_of(request: &Request) -> usize {
    request
        .parameter("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(PAGE)
        .clamp(1, MAX_PAGE)
}

/// Where a page starts, counted from the first entry.
fn offset_of(request: &Request) -> usize {
    request
        .parameter("from")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
}

/// Where to ask from next, when anything is left to ask for.
fn next_after(offset: usize, listed: usize, total: usize) -> Option<usize> {
    let next = offset.saturating_add(listed);
    (next < total).then_some(next)
}

fn blocks(context: &Context<'_>, request: &Request) -> Response {
    let Some(tip) = context.height() else {
        let mut json = Writer::new();
        json.begin_object();
        json.key("blocks");
        json.begin_array();
        json.end_array();
        json.field_null("next");
        json.end_object();
        return Response::json(json.finish());
    };

    let from = request
        .parameter("from")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(tip)
        .min(tip);
    let limit = limit_of(request);

    let mut json = Writer::new();
    json.begin_object();
    json.key("blocks");
    json.begin_array();
    // A fixed run of heights rather than a walk until the page is full. A node
    // that cannot produce a block for a height would otherwise be sent down the
    // chain looking for one, and how far it went would be the caller's to
    // decide. A page is what is there in that run, which may be less.
    let mut height = from;
    let mut walked = 0usize;
    while walked < limit {
        // The naming reading wants the heights and nothing else, and this is
        // the page where that is the whole of the difference: a hundred and
        // twenty eight blocks named costs a hundred and twenty eight lookups,
        // where a hundred and twenty eight blocks written out is every one of
        // them through the encoder and every input of every transfer looked
        // up in the index.
        if let Some(block) = context.block_at(height) {
            if context.answering() {
                block_summary(&mut json, context, &block);
            }
        }
        walked = walked.saturating_add(1);
        let Some(under) = height.checked_sub(1) else {
            break;
        };
        height = under;
    }
    json.end_array();
    match from.checked_sub(u64::try_from(walked).unwrap_or(u64::MAX)) {
        Some(next) => json.field_u64("next", next),
        None => json.field_null("next"),
    }
    json.end_object();
    Response::json(json.finish())
}

fn block_summary(json: &mut Writer, context: &Context<'_>, block: &Block) {
    json.begin_object();
    json.field_u64("height", block.header.height);
    json.field_str("id", &block.id().to_string());
    json.field_u64("timestamp", block.header.timestamp);
    json.field_str("difficulty", &block.header.difficulty.to_string());
    json.field_usize("transfers", block.transfers.len());
    field_size(json, context, || block.encode().len());
    json.field_str(
        "paidToMiner",
        &block
            .coinbase
            .total_output()
            .unwrap_or(Amount::ZERO)
            .as_pebbles()
            .to_string(),
    );
    match block.coinbase.outputs.first() {
        Some(output) => json.field_str("miner", &output.owner.to_string()),
        None => json.field_null("miner"),
    }
    match block_fees(context, block) {
        Some(fees) => json.field_str("fees", &fees.as_pebbles().to_string()),
        None => json.field_null("fees"),
    }
    json.end_object();
}

/// What senders paid in this block, measured from the transfers rather than
/// worked back from the coinbase.
///
/// Taking the coinbase minus the schedule looked equivalent and is not. A
/// miner may claim less than it is owed, which is legal and burns the
/// difference, and a block from such a miner then showed no fees at all next
/// to transfers that plainly paid some. Worse, the running total on the same
/// page is computed the honest way, so the two numbers disagreed and neither
/// said why.
///
/// `None` where a note a transfer spent is not in the index, which happens
/// while it is still reading its way up the chain. Saying so beats printing a
/// zero that reads like an answer.
fn block_fees(context: &Context<'_>, block: &Block) -> Option<Amount> {
    // The naming reading does not report this and does not pay for it: it is
    // a lookup per input of every transfer in the block, which at the byte
    // ceiling is three thousand of them.
    if !context.answering() {
        return None;
    }
    let index = context.index;
    let mut paid = Amount::ZERO;
    for transfer in &block.transfers {
        let mut spent = Amount::ZERO;
        for input in &transfer.inputs {
            let value = match &input.witness {
                // A cold spender carries the note it is spending, so the
                // value is in the block and needs nothing else.
                Witness::Cold(cold) => cold.note.value,
                Witness::Hot => index.note(&input.note_id)?.value,
            };
            spent = spent.checked_add(value)?;
        }
        let made = transfer.total_output()?;
        paid = paid.checked_add(spent.checked_sub(made)?)?;
    }
    Some(paid)
}

fn block(context: &Context<'_>, reference: &str) -> Response {
    let Some(block) = resolve_block(context, reference) else {
        return Response::error(404, "no such block");
    };
    let height = block.header.height;
    let params = context.params();

    let mut json = Writer::new();
    json.begin_object();
    json.field_u64("height", height);
    json.field_str("id", &block.id().to_string());
    json.field_str("previous", &block.header.previous.to_string());
    json.field_u64("version", u64::from(block.header.version));
    json.field_str("network", context.params().network_name());
    json.field_u64("timestamp", block.header.timestamp);
    json.field_str("difficulty", &block.header.difficulty.to_string());
    json.field_str("nonce", &block.header.nonce.to_string());
    json.field_str("work", &work_of(block.header.difficulty).to_string());
    json.field_str("totalWork", &block.header.total_work.to_string());
    json.field_str("history", &block.header.history.to_string());
    json.field_str(
        "transactionsRoot",
        &block.header.transactions_root.to_string(),
    );
    json.field_str("stateRoot", &block.header.state_root.to_string());
    field_size(&mut json, context, || block.encode().len());
    json.field_u64("confirmations", context.confirmations(height));
    match height
        .checked_add(1)
        .and_then(|next| context.block_at(next))
    {
        Some(next) => json.field_str("next", &next.id().to_string()),
        None => json.field_null("next"),
    }

    match block_fees(context, &block) {
        Some(fees) => json.field_str("fees", &fees.as_pebbles().to_string()),
        None => json.field_null("fees"),
    }
    json.field_str(
        "reward",
        &reward_at(
            height,
            params.halving_interval,
            params.initial_reward,
            params.tail_reward,
        )
        .as_pebbles()
        .to_string(),
    );

    json.key("coinbase");
    json.begin_object();
    let coinbase = block.coinbase.id();
    json.field_str("id", &coinbase.to_string());
    json.field_str(
        "total",
        &block
            .coinbase
            .total_output()
            .unwrap_or(Amount::ZERO)
            .as_pebbles()
            .to_string(),
    );
    json.field_str("extra", &hex::encode(&block.coinbase.extra));
    match readable(&block.coinbase.extra) {
        Some(text) => json.field_str("extraText", &text),
        None => json.field_null("extraText"),
    }
    json.key("outputs");
    json.begin_array();
    for (index, output) in block.coinbase.outputs.iter().enumerate() {
        let id = NoteId::new(coinbase, u32::try_from(index).unwrap_or(u32::MAX));
        output_object(&mut json, context, &id, output);
    }
    json.end_array();
    json.end_object();

    json.key("transfers");
    json.begin_array();
    for transfer in &block.transfers {
        transfer_object(&mut json, context, transfer, false);
    }
    json.end_array();

    // This page is read off the chain and its notes are read off the index, so
    // it is the one place the two can be seen disagreeing: the block is here,
    // and whether its notes have been spent may not be known yet.
    coverage(&mut json, context);
    json.end_object();
    Response::json(json.finish())
}

fn resolve_block(context: &Context<'_>, reference: &str) -> Option<Block> {
    if let Ok(height) = reference.parse::<u64>() {
        return context.block_at(height);
    }
    let id = parse_hash(reference)?;
    context.block(&id)
}

fn output_object(json: &mut Writer, context: &Context<'_>, id: &NoteId, note: &Note) {
    json.begin_object();
    json.field_u64("index", u64::from(id.index));
    json.field_str("note", &note_reference(id));
    json.field_str("value", &note.value.as_pebbles().to_string());
    json.field_str("owner", &note.owner.to_string());
    if let Some(record) = context.index.note(id) {
        json.field_bool("spent", !record.is_unspent());
        match record.spent_by {
            Some(spender) => json.field_str("spentBy", &spender.to_string()),
            None => json.field_null("spentBy"),
        }
        match record.spent_at {
            Some(height) => json.field_u64("spentAt", height),
            None => json.field_null("spentAt"),
        }
        json.field_str("tier", tier_of(context, id, &record));
    } else {
        // Nothing known about this note, which for a note printed off a block
        // means the index has not read that far. It used to say `false` here,
        // and false is the answer to a question this program had not asked:
        // a note the chain had spent years ago was published as unspent, on
        // the strength of a lookup that came back empty.
        json.field_null("spent");
        json.field_null("spentBy");
        json.field_null("spentAt");
        json.field_str("tier", "unknown");
    }
    json.end_object();
}

/// Where a note stands: still in the drawer every node holds, still inside the
/// window where a fallen note needs no proof, or down in the cave.
fn tier_of(context: &Context<'_>, id: &NoteId, record: &NoteRecord) -> &'static str {
    if !record.is_unspent() {
        return "spent";
    }
    let state = context.chain.state();
    if state.hot_note(id).is_some() {
        return "hot";
    }
    if state.within_grace(id).is_some() {
        return "grace";
    }
    // The cold set is asked rather than assumed. "Neither hot nor in grace"
    // used to be read as "in the cave", and a note the index still carries
    // from a branch this node has left is neither of the three: for the half
    // second between a reorganisation and the next refresh, a note that no
    // longer exists anywhere was reported as sitting safely in the cold set.
    // Only an archivist can answer, and an explorer is one.
    let cold = state.cold();
    if !cold.is_archiving()
        || cold
            .locate(id, &Note::new(record.value, record.owner))
            .is_some()
    {
        return "cold";
    }
    "unknown"
}

fn transfer_object(json: &mut Writer, context: &Context<'_>, transfer: &Transfer, full: bool) {
    let id = transfer.id();
    json.begin_object();
    json.field_str("id", &id.to_string());
    json.field_str("kind", "transfer");
    field_size(json, context, || transfer.encode().len());
    json.field_u64("version", u64::from(transfer.version));

    // What the transfer spent, or nothing at all where one input could not be
    // valued. It used to be the sum of the inputs it happened to find, printed
    // under "Total spent" as though it were the whole, with a fee worked out
    // from it that was understated and stated as a fact. The block-level
    // figure a few lines above had already been repaired to say `null` in the
    // same case; this one had not, so one request could produce a page reading
    // "Fees: Not indexed" at the top and "fee 0 CAIRN" on every transfer
    // under it.
    let mut consumed = Some(Amount::ZERO);
    json.key("inputs");
    json.begin_array();
    for input in &transfer.inputs {
        json.begin_object();
        json.field_str("note", &note_reference(&input.note_id));
        json.field_str("source", &input.note_id.source.to_string());
        json.field_u64("index", u64::from(input.note_id.index));
        json.field_str(
            "witness",
            match input.witness {
                Witness::Hot => "hot",
                Witness::Cold(_) => "cold",
            },
        );
        match &input.witness {
            Witness::Cold(witness) => json.field_str("position", &witness.position.to_string()),
            Witness::Hot => json.field_null("position"),
        }
        // A cold spender carries the note it is spending, so the block itself
        // says what the input was worth and the index is not consulted. Only
        // a hot spend has to be looked up, and only that can come back empty.
        let spent = match &input.witness {
            Witness::Cold(cold) => Some((cold.note.value, cold.note.owner)),
            Witness::Hot => context
                .index
                .note(&input.note_id)
                .map(|record| (record.value, record.owner)),
        };
        if let Some((value, owner)) = spent {
            consumed = consumed.and_then(|total| total.checked_add(value));
            json.field_str("value", &value.as_pebbles().to_string());
            json.field_str("owner", &owner.to_string());
        } else {
            consumed = None;
            json.field_null("value");
            json.field_null("owner");
        }
        json.end_object();
    }
    json.end_array();

    json.key("outputs");
    json.begin_array();
    for (index, output) in transfer.outputs.iter().enumerate() {
        let note_id = NoteId::new(id, u32::try_from(index).unwrap_or(u32::MAX));
        output_object(json, context, &note_id, output);
    }
    json.end_array();

    let produced = transfer.total_output().unwrap_or(Amount::ZERO);
    match consumed {
        Some(total) => json.field_str("totalIn", &total.as_pebbles().to_string()),
        None => json.field_null("totalIn"),
    }
    json.field_str("totalOut", &produced.as_pebbles().to_string());
    match consumed.and_then(|total| total.checked_sub(produced)) {
        Some(fee) => json.field_str("fee", &fee.as_pebbles().to_string()),
        None => json.field_null("fee"),
    }

    if full {
        if let Some(location) = context.index.locate(&id) {
            json.field_u64("height", location.height);
            json.field_u64("position", u64::from(location.position));
            json.field_u64("confirmations", context.confirmations(location.height));
            if let Some(block) = context.block_at(location.height) {
                json.field_str("block", &block.id().to_string());
                json.field_u64("timestamp", block.header.timestamp);
            } else {
                json.field_null("block");
                json.field_null("timestamp");
            }
        } else {
            json.field_null("height");
            json.field_null("position");
            json.field_u64("confirmations", 0);
            json.field_null("block");
            json.field_null("timestamp");
        }
    }
    json.end_object();
}

fn transaction(context: &Context<'_>, reference: &str) -> Response {
    let Some(id) = parse_hash(reference) else {
        return Response::error(400, "not a transaction identifier");
    };

    if let Some(transfer) = context.chain.pooled(&id) {
        let mut json = Writer::new();
        json.begin_object();
        json.field_bool("pooled", true);
        json.key("transaction");
        transfer_object(&mut json, context, transfer, true);
        coverage(&mut json, context);
        json.end_object();
        return Response::json(json.finish());
    }

    let Some(location) = context.index.locate(&id) else {
        return not_found(context, "no such transaction");
    };
    let Some(block) = context.block_at(location.height) else {
        return not_found(context, "no such transaction");
    };

    // Whatever sits at that position has to be the transaction that was asked
    // for. Between a reorganisation and the next refresh, which is half a
    // second, the index still holds locations from the branch this node has
    // left: a request for a transaction that was on it found a stale height
    // and position and was handed whatever the new branch put there, or the
    // new coinbase, under the identifier the reader had typed.
    let mut json = Writer::new();
    json.begin_object();
    json.field_bool("pooled", false);
    json.key("transaction");
    if location.position == 0 {
        if block.coinbase.id() != id {
            return not_found(context, "no such transaction");
        }
        coinbase_object(&mut json, context, &block);
    } else {
        let index = usize::try_from(location.position)
            .ok()
            .and_then(|position| position.checked_sub(1));
        match index.and_then(|index| block.transfers.get(index)) {
            Some(transfer) if transfer.id() == id => {
                transfer_object(&mut json, context, transfer, true);
            }
            _ => return not_found(context, "no such transaction"),
        }
    }
    coverage(&mut json, context);
    json.end_object();
    Response::json(json.finish())
}

fn coinbase_object(json: &mut Writer, context: &Context<'_>, block: &Block) {
    let id = block.coinbase.id();
    json.begin_object();
    json.field_str("id", &id.to_string());
    json.field_str("kind", "coinbase");
    field_size(json, context, || block.coinbase.encode().len());
    json.field_u64("version", u64::from(block.coinbase.version));
    json.key("inputs");
    json.begin_array();
    json.end_array();
    json.key("outputs");
    json.begin_array();
    for (index, output) in block.coinbase.outputs.iter().enumerate() {
        let note_id = NoteId::new(id, u32::try_from(index).unwrap_or(u32::MAX));
        output_object(json, context, &note_id, output);
    }
    json.end_array();
    let total = block.coinbase.total_output().unwrap_or(Amount::ZERO);
    json.field_str("totalIn", "0");
    json.field_str("totalOut", &total.as_pebbles().to_string());
    json.field_null("fee");
    json.field_str("extra", &hex::encode(&block.coinbase.extra));
    match readable(&block.coinbase.extra) {
        Some(text) => json.field_str("extraText", &text),
        None => json.field_null("extraText"),
    }
    json.field_u64("height", block.header.height);
    json.field_u64("position", 0);
    json.field_u64("confirmations", context.confirmations(block.header.height));
    json.field_str("block", &block.id().to_string());
    json.field_u64("timestamp", block.header.timestamp);
    json.end_object();
}

/// A page of what an address still holds, and how sure the count under it is.
#[derive(Debug)]
struct Holdings {
    /// The newest unspent notes, at most a page of them.
    listed: Vec<(NoteId, NoteRecord)>,
    /// Unspent notes the walk saw, which is every one of them when it finished.
    unspent: usize,
    /// Whether the walk reached the end of the list.
    whole: bool,
}

/// Walks an address's notes newest first, and stops walking.
///
/// Notes are kept in the order they arrived and each says for itself whether it
/// has been spent, so the newest unspent ones are found by walking back past
/// the spent. An address that has mined for a year holds hundreds of thousands
/// of them, and walking all of them is work an anonymous caller could ask for as
/// often as they liked, with the chain held the whole time. So the walk has a
/// ceiling.
///
/// What that costs is exactness past the ceiling, where the count becomes a
/// floor. The answer carries which of the two it is rather than leaving a reader
/// to assume the wrong one.
fn holdings(notes: &[NoteId], record: impl Fn(&NoteId) -> Option<NoteRecord>) -> Holdings {
    let mut listed = Vec::new();
    let mut unspent = 0usize;
    for id in notes.iter().rev().take(ADDRESS_SCAN) {
        let Some(note) = record(id) else {
            continue;
        };
        if !note.is_unspent() {
            continue;
        }
        unspent = unspent.saturating_add(1);
        if listed.len() < ADDRESS_PAGE {
            listed.push((*id, note));
        }
    }
    Holdings {
        listed,
        unspent,
        whole: notes.len() <= ADDRESS_SCAN,
    }
}

fn address(context: &Context<'_>, reference: &str, request: &Request) -> Response {
    let Some(owner) = parse_owner(reference) else {
        return Response::error(400, "not an address");
    };
    let offset = offset_of(request);

    let mut json = Writer::new();
    json.begin_object();
    json.field_str("address", &owner.to_string());

    let Some(record) = context.index.owner(&owner) else {
        json.field_str("balance", "0");
        json.field_str("received", "0");
        json.field_str("spent", "0");
        json.field_usize("notes", 0);
        json.field_usize("unspentNotes", 0);
        json.field_bool("moreNotes", false);
        // Never an unqualified yes for an address nothing is known about. An
        // index that does not reach the first block has never seen most of
        // this chain, and answering "nought, and that is exact" about every
        // address on it is the worst thing this program can do: a reader has
        // no way at all to tell it from a real balance of nought.
        json.field_bool("counted", context.index.reads_from_the_start());
        json.key("unspent");
        json.begin_array();
        json.end_array();
        json.key("history");
        json.begin_array();
        json.end_array();
        json.field_usize("movements", 0);
        json.field_null("next");
        coverage(&mut json, context);
        json.end_object();
        return Response::json(json.finish());
    };

    json.field_str("balance", &record.balance().as_pebbles().to_string());
    json.field_str("received", &record.received.as_pebbles().to_string());
    json.field_str("spent", &record.spent.as_pebbles().to_string());
    json.field_usize("notes", record.notes.len());

    let held = holdings(&record.notes, |id| context.index.note(id));
    json.key("unspent");
    json.begin_array();
    for (id, note) in &held.listed {
        json.begin_object();
        json.field_str("note", &note_reference(id));
        json.field_str("value", &note.value.as_pebbles().to_string());
        json.field_u64("createdAt", note.created_at);
        json.field_str("tier", tier_of(context, id, note));
        json.end_object();
    }
    json.end_array();
    json.field_usize("unspentNotes", held.unspent);
    json.field_bool("moreNotes", held.unspent > held.listed.len());
    // Whether that count is the whole of it, or the floor the walk stopped at.
    // A reader is owed the difference: a figure that quietly means "at least"
    // is the kind of wrong nobody notices until it matters. Two ways it can
    // be a floor, and one answer for both: the walk over this address stopped
    // at its ceiling, or the index itself does not go back to the first block.
    json.field_bool(
        "counted",
        held.whole && context.index.reads_from_the_start(),
    );

    // One line per movement: a note arriving, and later the transfer that
    // spent it. The index records these as the chain produces them, so they
    // are already in order and a page is a slice rather than a sort.
    let movements = &record.movements;
    let total = movements.len();
    let end = total.saturating_sub(offset);
    let start = end.saturating_sub(ADDRESS_PAGE);

    json.key("history");
    json.begin_array();
    for movement in movements.get(start..end).unwrap_or_default().iter().rev() {
        json.begin_object();
        json.field_u64("height", movement.height);
        json.field_str("direction", if movement.incoming { "in" } else { "out" });
        json.field_str("transaction", &movement.transaction.to_string());
        json.field_str("value", &movement.value.as_pebbles().to_string());
        match context.block_at(movement.height) {
            Some(block) => json.field_u64("timestamp", block.header.timestamp),
            None => json.field_null("timestamp"),
        }
        json.end_object();
    }
    json.end_array();
    json.field_usize("movements", total);
    if start > 0 {
        json.field_usize("next", offset.saturating_add(end.saturating_sub(start)));
    } else {
        json.field_null("next");
    }

    coverage(&mut json, context);
    json.end_object();
    Response::json(json.finish())
}

fn note(context: &Context<'_>, reference: &str) -> Response {
    let Some(id) = parse_note(reference) else {
        return Response::error(400, "not a note identifier");
    };
    let Some(record) = context.index.note(&id) else {
        return not_found(context, "no such note");
    };
    let mut json = Writer::new();
    json.begin_object();
    json.field_str("note", &note_reference(&id));
    json.field_str("source", &id.source.to_string());
    json.field_u64("index", u64::from(id.index));
    json.field_str("value", &record.value.as_pebbles().to_string());
    json.field_str("owner", &record.owner.to_string());
    json.field_u64("createdAt", record.created_at);
    json.field_str("tier", tier_of(context, &id, &record));
    match record.spent_at {
        Some(height) => json.field_u64("spentAt", height),
        None => json.field_null("spentAt"),
    }
    match record.spent_by {
        Some(by) => json.field_str("spentBy", &by.to_string()),
        None => json.field_null("spentBy"),
    }
    // Where a fallen note sits in the forest, which is what a proof is about.
    match context
        .chain
        .state()
        .cold()
        .locate(&id, &Note::new(record.value, record.owner))
    {
        Some(position) => json.field_str("position", &position.to_string()),
        None => json.field_null("position"),
    }
    coverage(&mut json, context);
    json.end_object();
    Response::json(json.finish())
}

/// What is waiting for a block, a page of it at a time.
///
/// The pool has a ceiling in bytes and none in transfers, so a run of small
/// ones is a long list. Writing every one of them out is work an anonymous
/// caller could ask for as often as they liked, and bytes this node then has to
/// send. `count` is the whole of it; the array is one page.
fn pool(context: &Context<'_>, request: &Request) -> Response {
    let total = context.chain.pool_len();
    let offset = offset_of(request);
    let limit = limit_of(request);

    let mut json = Writer::new();
    json.begin_object();
    json.field_usize("count", total);
    json.key("transfers");
    json.begin_array();
    let mut listed = 0usize;
    for (_, transfer) in context.chain.pooled_transfers().skip(offset).take(limit) {
        transfer_object(&mut json, context, transfer, false);
        listed = listed.saturating_add(1);
    }
    json.end_array();
    match next_after(offset, listed, total) {
        Some(next) => json.field_usize("next", next),
        None => json.field_null("next"),
    }
    json.end_object();
    Response::json(json.finish())
}

/// Who holds the most, out of what has been read.
///
/// The whole content of this answer is a claim about every owner on the chain,
/// and it was the one route that said nothing at all about how much of the
/// chain it had counted. An index that has read nothing answered `holders: 0`
/// with an empty table, which is the shape of a complete answer and reads as
/// one.
fn holders(context: &Context<'_>) -> Response {
    let mut json = Writer::new();
    json.begin_object();
    json.field_usize("holders", context.index.holders());
    json.key("richest");
    json.begin_array();
    for (owner, balance) in context.index.richest() {
        json.begin_object();
        json.field_str("address", &owner.to_string());
        json.field_str("balance", &balance.as_pebbles().to_string());
        json.end_object();
    }
    json.end_array();
    coverage(&mut json, context);
    json.end_object();
    Response::json(json.finish())
}

/// Works out what someone pasted into the search box.
///
/// The answer carries what the index had read when it was worked out, because
/// the last step of the walk below is a guess and the guess is only as good as
/// the index. A transaction identifier the index has not reached falls past
/// every lookup and lands on `parse_owner`, which succeeds for any thirty two
/// bytes that make a point, so the site announced somebody's transaction as an
/// address and took them to a page saying it held nothing. The guess is still
/// made, because an address that has never been paid is not in the index either
/// and looking it up is a reasonable thing to want. What is no longer left out
/// is that it was a guess made off part of a chain.
fn search(context: &Context<'_>, request: &Request) -> Response {
    let query = request.parameter("q").unwrap_or_default();
    let query = query.trim();

    let mut json = Writer::new();
    json.begin_object();
    json.field_str("query", query);
    if let Some((kind, target)) = matched(context, query) {
        json.field_str("kind", kind);
        json.field_str("target", &target);
    } else {
        json.field_str("kind", "unknown");
        json.field_null("target");
    }
    coverage(&mut json, context);
    json.end_object();
    Response::json(json.finish())
}

/// What the text turns out to be, and where that lives.
///
/// A block identifier, a transaction identifier and an address are all thirty
/// two bytes, so the text alone cannot say which it is. Each is looked up in
/// turn and the first that exists wins; an address is last because it is the
/// only one that needs nothing to exist.
fn matched(context: &Context<'_>, query: &str) -> Option<(&'static str, String)> {
    if let Ok(height) = query.parse::<u64>() {
        if context.block_at(height).is_some() {
            return Some(("block", format!("/block/{height}")));
        }
    }

    if let Some(id) = parse_note(query) {
        if context.index.note(&id).is_some() {
            return Some(("note", format!("/note/{}", note_reference(&id))));
        }
    }

    if let Some(hash) = parse_hash(query) {
        if let Some(block) = context.block(&hash) {
            return Some(("block", format!("/block/{}", block.header.height)));
        }
        if context.index.locate(&hash).is_some() || context.chain.pooled(&hash).is_some() {
            return Some(("transaction", format!("/tx/{hash}")));
        }
    }

    let owner = parse_owner(query)?;
    Some(("address", format!("/address/{owner}")))
}

/// How a note is written down: the transaction that made it, then which output.
fn note_reference(id: &NoteId) -> String {
    format!("{}:{}", id.source, id.index)
}

fn parse_hash(text: &str) -> Option<Hash32> {
    hex::decode_array::<32>(text).map(Hash32::from_bytes)
}

fn parse_owner(text: &str) -> Option<PublicKey> {
    let bytes = hex::decode_array::<32>(text)?;
    PublicKey::from_bytes(&bytes).ok()
}

fn parse_note(text: &str) -> Option<NoteId> {
    let (source, index) = text.split_once(':')?;
    Some(NoteId::new(parse_hash(source)?, index.parse().ok()?))
}

/// The coinbase message, when it is one.
///
/// Miners put arbitrary bytes here as search space, so anything that is not
/// printable text is left as hexadecimal rather than shown as mojibake.
fn readable(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    text.chars()
        .all(|character| !character.is_control())
        .then(|| text.to_owned())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::{
        holdings, limit_of, next_after, offset_of, ADDRESS_PAGE, ADDRESS_SCAN, MAX_PAGE, PAGE,
    };
    use crate::index::NoteRecord;
    use cairn_crypto::SecretKey;
    use cairn_http::Request;
    use cairn_ledger::note::NoteId;
    use cairn_primitives::{Amount, Hash32};

    fn asking(query: &str) -> Request {
        Request {
            path: "/api/pool".to_owned(),
            query: query.to_owned(),
            head_only: false,
            post: false,
            body: String::new(),
            host: String::new(),
            origin: String::new(),
        }
    }

    fn note_id(index: usize) -> NoteId {
        NoteId::new(
            Hash32::from_bytes([9; 32]),
            u32::try_from(index).unwrap_or(u32::MAX),
        )
    }

    /// One note still held and one already spent, otherwise alike.
    fn records() -> (NoteRecord, NoteRecord) {
        let unspent = NoteRecord {
            value: Amount::from_pebbles(1).unwrap(),
            owner: SecretKey::from_bytes(&[7; 32]).public_key(),
            created_at: 1,
            spent_at: None,
            spent_by: None,
        };
        (
            unspent,
            NoteRecord {
                spent_at: Some(2),
                ..unspent
            },
        )
    }

    /// How much work an answer is has to be this node's decision. An explorer
    /// on a public address is answering strangers, and one of them asking for
    /// everything at once must cost them a page and no more.
    #[test]
    fn a_caller_does_not_choose_how_large_an_answer_is() {
        assert_eq!(limit_of(&asking("")), PAGE, "a page, unasked");
        assert_eq!(limit_of(&asking("limit=5")), 5);
        assert_eq!(
            limit_of(&asking("limit=1000000")),
            MAX_PAGE,
            "asking for everything is asking for a page"
        );
        assert_eq!(
            limit_of(&asking("limit=0")),
            1,
            "and asking for nothing is still answered"
        );
        assert_eq!(limit_of(&asking("limit=-1")), PAGE);
        assert_eq!(limit_of(&asking("limit=plenty")), PAGE);

        assert_eq!(offset_of(&asking("")), 0);
        assert_eq!(offset_of(&asking("from=40")), 40);
        assert_eq!(offset_of(&asking("from=-1")), 0);
    }

    #[test]
    fn a_page_names_the_next_one_only_when_there_is_one() {
        assert_eq!(next_after(0, 25, 100), Some(25));
        assert_eq!(next_after(75, 25, 100), None, "the last page ends the walk");
        assert_eq!(next_after(0, 3, 3), None);
        assert_eq!(next_after(0, 0, 0), None, "and nothing waiting has no page");
    }

    #[test]
    fn what_an_address_holds_is_one_page_of_the_newest() {
        let (unspent, spent) = records();
        let notes: Vec<NoteId> = (0..400usize).map(note_id).collect();
        // Every other note spent, so a page is filled from a list twice as
        // long as itself.
        let held = holdings(&notes, |id| {
            Some(if id.index % 2 == 0 { spent } else { unspent })
        });

        assert_eq!(held.listed.len(), ADDRESS_PAGE, "one page and no more");
        assert_eq!(
            held.listed.first().map(|(id, _)| id.index),
            Some(399),
            "newest first"
        );
        assert_eq!(held.unspent, 200, "and every note held was counted");
        assert!(held.whole, "because the walk reached the end of the list");
    }

    /// The figure an address answers with is one a reader takes at face value,
    /// so where it stops being a total it has to say so rather than read as one.
    #[test]
    fn a_walk_over_an_address_stops_and_says_that_it_stopped() {
        let (unspent, _) = records();

        let notes: Vec<NoteId> = (0..=ADDRESS_SCAN).map(note_id).collect();
        let held = holdings(&notes, |_| Some(unspent));
        assert_eq!(held.listed.len(), ADDRESS_PAGE);
        assert_eq!(
            held.unspent, ADDRESS_SCAN,
            "the walk stopped where it says it does"
        );
        assert!(!held.whole, "and does not call where it stopped a total");

        let notes: Vec<NoteId> = (0..ADDRESS_SCAN).map(note_id).collect();
        let held = holdings(&notes, |_| Some(unspent));
        assert_eq!(held.unspent, ADDRESS_SCAN);
        assert!(held.whole, "one note under the ceiling and it is exact");
    }
}

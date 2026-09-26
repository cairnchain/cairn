//! What an explorer keeps that a node deliberately throws away.
//!
//! A Cairn node forgets on purpose: that is the whole thesis, and it is why
//! running one costs the same in ten years as today. An explorer is the
//! opposite service. It keeps every note that ever existed and an index from
//! owners to their notes, which is exactly the growing cost the protocol
//! refuses to put on validators. Keeping the two apart is not tidiness. It is
//! the claim: this file is what the chain does not make anyone carry.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use cairn_crypto::PublicKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::NoteId;
use cairn_primitives::{Amount, Hash32};

/// Where a transaction sits on the followed branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Location {
    pub(crate) height: u64,
    /// Zero for the coinbase, then one per transfer in block order.
    pub(crate) position: u32,
}

/// One note and what became of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NoteRecord {
    pub(crate) value: Amount,
    pub(crate) owner: PublicKey,
    /// Height of the block that created it.
    pub(crate) created_at: u64,
    /// Height of the block that spent it, once one has.
    pub(crate) spent_at: Option<u64>,
    /// The transfer that spent it.
    pub(crate) spent_by: Option<Hash32>,
}

impl NoteRecord {
    pub(crate) fn is_unspent(&self) -> bool {
        self.spent_at.is_none()
    }
}

/// One movement in or out of an owner's holdings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Movement {
    pub(crate) height: u64,
    /// True for a note arriving, false for one being spent.
    pub(crate) incoming: bool,
    pub(crate) transaction: Hash32,
    pub(crate) value: Amount,
}

/// Everything an owner has ever been paid.
#[derive(Clone, Debug, Default)]
pub(crate) struct OwnerRecord {
    /// Notes made out to this owner, oldest first.
    pub(crate) notes: Vec<NoteId>,
    /// Every movement, in the order the chain produced them.
    ///
    /// Recorded as it happens rather than assembled and sorted per request.
    /// A miner's address accumulates hundreds of thousands of these, and
    /// rebuilding that list to answer one page was work an anonymous caller
    /// could ask for as often as they liked.
    pub(crate) movements: Vec<Movement>,
    /// Everything paid to this owner, in pebbles.
    ///
    /// Not an amount, on purpose. An amount stops at the most money there
    /// will ever be, which bounds what an owner holds and not what has passed
    /// through it: change comes back to the key that spent, so an address
    /// holding a hundred thousand that pays ten thousand times has been paid
    /// a billion. A `u64` of pebbles reaches about a hundred and eighty times
    /// the ceiling, and past that it stops, which [`OwnerRecord::turnover_counted`]
    /// says: an exchange paying withdrawals out of one large note with the
    /// change back to itself gets there in months.
    pub(crate) received: u64,
    /// What this owner's unspent notes come to, in pebbles.
    ///
    /// Kept rather than worked out as what came in less what went out. That
    /// was the balance for a while, both halves counted in pebbles and both
    /// stopping at the top of a `u64`, and past that point every payment in
    /// was dropped whole while every payment out still counted: the balance
    /// slid to nothing with the notes that made it still unspent in this same
    /// index. What an owner holds is a sum of notes that exist, so it is under
    /// the most money there will ever be and cannot stop counting. The record
    /// is the same sixteen bytes it was, so what the index costs a note does
    /// not move.
    pub(crate) held: u64,
}

impl OwnerRecord {
    pub(crate) fn balance(&self) -> Amount {
        Amount::from_pebbles(self.held).unwrap_or(Amount::MAX_MONEY)
    }

    /// Everything this owner paid out: what came in, less what is still here.
    ///
    /// A floor rather than a total once what came in has stopped counting.
    pub(crate) fn spent(&self) -> u64 {
        self.received.saturating_sub(self.held)
    }

    /// Whether what came in and what went out are totals, or floors because
    /// what came in has passed what a count of pebbles can hold.
    pub(crate) fn turnover_counted(&self) -> bool {
        self.received < u64::MAX
    }
}

/// Totals over the followed branch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Totals {
    pub(crate) blocks: u64,
    pub(crate) transfers: u64,
    pub(crate) notes_created: u64,
    pub(crate) notes_spent: u64,
    /// Everything paid to miners, rewards and fees together.
    pub(crate) paid_to_miners: Amount,
    /// The part of that which came from senders rather than from emission.
    pub(crate) fees: Amount,
}

impl Totals {
    /// Money in existence: everything paid to miners less the fees, since a
    /// fee is money that already existed.
    ///
    /// What a coinbase declines to claim, of its reward or of the fees, is
    /// destroyed and never appears here, so this can sit below the schedule
    /// without the index being wrong. It said Cairn burns nothing, which is
    /// the one case that makes the total fall.
    pub(crate) fn issued(&self) -> Amount {
        self.paid_to_miners
            .checked_sub(self.fees)
            .unwrap_or(Amount::ZERO)
    }
}

/// The explorer's view of the chain.
#[derive(Debug, Default)]
pub(crate) struct Index {
    /// The stretch of the branch already read, or nothing before the first
    /// block goes in.
    span: Option<Span>,
    /// Transaction identifier to where it sits. Covers coinbases and transfers.
    ///
    /// One entry per transaction that has ever been mined, and nothing takes
    /// any of them out. That is the price of answering `/api/tx` about a
    /// transaction from years ago, and [`Index::size`] is where an operator
    /// reads what it has come to.
    at: HashMap<Hash32, Location>,
    /// Block identifier to the height it was read at, one entry a block.
    ///
    /// The branch names identifiers for the last [`cairn_chain::HELD_WINDOW`]
    /// heights and no further, so a block older than about seventeen hours
    /// was served by its height and was "no such block" by its identifier,
    /// and the search box sent whoever pasted one to an address holding
    /// nothing. Forty bytes of content a block, which is about twenty one
    /// megabytes a year at a block a minute, beside the six hundred and
    /// twenty seven a note; [`BYTES_PER_BLOCK`] counts it.
    blocks: HashMap<Hash32, u64>,
    /// The time each block read carries in its header, from the lowest height
    /// read up.
    ///
    /// Eight bytes a block, so that a page listing what moved through an
    /// address can say when without the blocks: it read up to a hundred whole
    /// blocks off the disk, with the log's lock taken for each, to print a
    /// hundred timestamps, and a block the disk would not give back was a
    /// movement with no date.
    times: Vec<u64>,
    notes: BTreeMap<NoteId, NoteRecord>,
    owners: HashMap<PublicKey, OwnerRecord>,
    totals: Totals,
    /// Movements over every owner, counted as they are recorded.
    ///
    /// Summed here rather than by walking the owners, because a page that
    /// says what this index costs should not cost a pass over it.
    movements: u64,
    /// Worked out once per refresh rather than once per request.
    richest: Vec<(PublicKey, Amount)>,
    holders: usize,
    /// Whether anything has gone into the index, or been thrown out of it,
    /// since the two above were last worked out.
    ///
    /// This used to be read off the block count: take it before the walk,
    /// compare it after. A walk that threw the index away partway and then
    /// read back exactly as many blocks as it had before came out equal, so
    /// the distribution was not worked out again over a table the reset had
    /// emptied, and the site answered that nobody on the chain held anything.
    /// Kept here rather than in the walk because a walk now stops on a batch
    /// bound and the debt outlives the turn that ran up.
    stock_due: bool,
    /// The height the distribution was last worked out at.
    ///
    /// `None` until it has been worked out once. What it gates is how often
    /// the one piece of work here whose cost is the whole index runs, and
    /// what it is published as is the age of the answer.
    stock_at: Option<u64>,
    /// The height the next turn of the walk asks for.
    ///
    /// The walk used to work this out from the span, which is only set once a
    /// block has gone in. That was enough while a walk ran to the tip in one
    /// go, and is not enough now that it stops on a bound: a node that has
    /// dropped more blocks off its bottom than one turn steps over would have
    /// left the span empty at the end of every turn, and every turn would have
    /// started again at height zero.
    resume: u64,
    /// What the newest blocks read did, oldest first, for [`UNDO_DEPTH`] of
    /// them, so that a switch of branch can be taken back rather than answered
    /// by reading the chain again.
    undo: VecDeque<Undo>,
}

/// What one block did to the index, kept so a switch can take it back.
///
/// Not the block. What taking a block back needs is which transactions it
/// carried and which notes it spent; the notes it made are named by the
/// transactions and the number of outputs each had, and every other table is
/// either keyed by those or appended to in the order of the chain.
#[derive(Clone, Debug)]
struct Undo {
    height: u64,
    id: Hash32,
    /// Every transaction the block carried, coinbase first, with how many
    /// notes each one made.
    made: Vec<(Hash32, u32)>,
    /// The notes it spent that this index knew, in the order it spent them.
    spent: Vec<NoteId>,
    /// What went onto the two money totals for it, which is what comes off.
    paid: Amount,
    fees: Amount,
}

/// The run of blocks the index has read, and what stood at the top of it.
///
/// This used to be every identifier the walk had ever seen, oldest first:
/// thirty two bytes a block, eighty four megabytes at two and a half million
/// blocks, and exactly one of them ever compared against anything. What the
/// comparison needs is the last, so the last is what is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    /// The lowest height read. Zero on a node that still holds its first
    /// block; higher on one that dropped the oldest before the index got
    /// there, which is a shorter answer and not a wrong one, so long as it
    /// is said out loud.
    from: u64,
    /// The highest height read.
    through: u64,
    /// The identifier the branch carried at `through` when it was read. The
    /// one hash worth keeping: a branch that changed under any block below
    /// this changed under this one too.
    id: Hash32,
}

/// What the chain says about itself, read in one go.
///
/// Two questions, both answered from memory, both asked with the chain held
/// and answered before the walk begins. The walk that follows goes to a disk
/// for every block it reads, and it used to do that with the chain still in
/// its hand: one reorganisation then stopped the whole node for as long as it
/// took to read the chain back, incoming blocks included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    /// How far the followed branch reaches.
    pub(crate) tip: u64,
    /// The identifier the branch now carries at the highest height the index
    /// read, or `None` where the node no longer holds one that deep.
    pub(crate) at_last_read: Option<Hash32>,
}

/// Whether the branch still carries `id` at `height`.
///
/// `None` from the chain means the height is past what it still holds an
/// identifier for, and that is two different things. Below the tip it is too
/// deep to have changed, since a switch deeper than the undo window is
/// refused, so it is taken as agreeing. Above the tip it is not deep at all:
/// it is past the end of a branch that got shorter, and every height the turn
/// relied on up there answers `None` for that reason.
///
/// Which is why `reaches` has to be the tip as it is now and not the one the
/// turn began with. Measured against the one it began with, a branch that
/// shrank inside the turn agrees at every height above its new end, because
/// every one of them is under the old one. The index then settles holding
/// blocks off a branch nobody follows, and `behind_of` takes the distance
/// from a tip below where it thinks it has read, which saturates to nothing:
/// the site says it has read the whole chain while every answer comes off
/// those blocks.
///
/// `None` for `reaches` is a chain with no tip at all, which agrees with
/// nothing.
fn still_the_branch(
    height: u64,
    id: Hash32,
    reaches: Option<u64>,
    id_at: &impl Fn(u64) -> Option<Hash32>,
) -> bool {
    match id_at(height) {
        Some(now) => now == id,
        None => reaches.is_some_and(|tip| height <= tip),
    }
}

/// How many notes a transaction with `outputs` outputs makes, as note
/// identifiers count them.
fn outputs_of(outputs: usize) -> u32 {
    u32::try_from(outputs).unwrap_or(u32::MAX)
}

/// What a node could produce for one height of the branch it follows.
///
/// Four answers and not two. A node keeps one run of blocks and drops the
/// oldest as the run grows past what its operator allows it, so a height it
/// cannot produce is one of three things: one it has let go of, which will
/// never come back; one that has not reached its disk yet, which will; or one
/// inside the run it is holding that the disk would not give back, which is a
/// fault in the machine and not an answer about the chain.
///
/// Reading the first two the same way is what left this index stopped at the
/// first hole for the rest of the run: an explorer past its block budget
/// answered every question about every address with nought, and called the
/// figure exact. Reading the third as the first was worse and lasted longer:
/// the walk stepped over a block that was there, threw away every block it had
/// read under it, and never came back for any of them while the process ran.
#[derive(Debug)]
pub(crate) enum Held {
    /// The block, ready to read.
    Block(Box<Block>),
    /// Let go of. This node's blocks begin somewhere above this height.
    Dropped,
    /// Not on this node yet, and expected.
    Waiting,
    /// Inside the run this node holds, and the disk would not hand it back: a
    /// torn record, a misindexed one, a bad sector. The block is neither gone
    /// nor late, so the walk stops and asks for the same height again rather
    /// than going on without it.
    Refused,
}

/// Owners listed in the holders table.
const RICHEST: usize = 50;

/// Blocks between one reckoning of the distribution and the next.
///
/// The one piece of work in the walk whose cost is the whole index rather
/// than the block just read. Sixteen blocks is a quarter of an hour on this
/// network, and a table of the largest holders a quarter of an hour old is
/// still a table of the largest holders; what it must not do is pretend
/// otherwise, so the answer says the height it was worked out at.
const STOCK_EVERY: u64 = 16;

/// Heights one turn of the walk gets through before it puts the index down.
///
/// The walk holds the index while it reads, and every question the site
/// answers wants the index too, so a walk that runs all the way to the tip in
/// one turn is a site that answers nothing at all until it gets there. On a
/// chain of any size that is minutes of a bound socket with nobody answering,
/// which is exactly what opening the door early was meant to remove. So the
/// walk stops here, says there is more, and is called straight back. What it
/// costs is the lock taken again per turn, which is nothing beside one block
/// off a disk; what it buys is that a visitor waits for a turn rather than for
/// the chain.
const BATCH: u64 = 64;

/// Blocks the index can take back one at a time, newest first.
///
/// A switch of branch used to be answered by throwing the whole index away
/// and reading the chain again, and the chain calls the switch that ends an
/// ordinary tie between two miners ordinary: it happens on some node every
/// time two blocks are found at once. On an explorer that was every block the
/// node holds read back off the disk, a seek and a decode each, with every
/// page saying the index was partial for as long as it took.
///
/// What taking a block back needs is kept for this many of the newest blocks
/// read: a few dozen bytes for an ordinary block, and some fifty kilobytes for
/// one at the byte ceiling full of spends, so the whole of it stays a few
/// megabytes however long the chain grows. A switch deeper than this is read
/// again from the start, which is what every switch cost before.
///
/// More than a turn of the walk, because the check at the bottom of a turn
/// relies on every height the turn read and on the one it started from, and a
/// switch landing inside a turn can reach below all of them.
pub(crate) const UNDO_DEPTH: usize = 128;

/// How far one turn of the walk got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reading {
    /// Nothing more to read for now: level with the tip it was given, or
    /// stopped at a height this node cannot produce yet.
    Done,
    /// Stopped on the batch bound with the chain still above it. The caller
    /// lets go of the index and comes straight back.
    More,
}

/// Turns a walk until it has read as far as the chain reaches, and says
/// whether it got there.
///
/// `refresh` reads one batch and hands the index back, because holding it for
/// a whole rebuild is what would make the site stop answering. Reading to the
/// end is calling it until it says [`Reading::Done`], and that was written out
/// at eleven places in this crate: nine as a bare `while ... == Reading::More
/// {}` with nothing stopping them, and twice as a hand-written counter bounded
/// at a million turns. Three answers to one question, and the two counted ones
/// count to a number nothing chose.
///
/// The bound here is read off the chain instead. A turn that says `More`
/// stopped on the batch bound with the chain still above it, so it read at
/// least one height, and a chain has no more heights to read than its tip
/// names. Since a batch is many heights, that is far more turns than an honest
/// read takes and far fewer than for ever.
///
/// The answer is a `bool` rather than a panic because this runs in the site as
/// well as in the suite, and the two want different things from it: a test
/// asserts on it and fails, while the walk in the site returns and is called
/// again, which is what it would do at the tip anyway.
pub(crate) fn read_to_the_end(reach: u64, mut turn: impl FnMut() -> Reading) -> bool {
    for _ in 0..=reach {
        if turn() == Reading::Done {
            return true;
        }
    }
    false
}

/// Bytes one note that has ever existed costs the index, measured on the
/// running implementation.
///
/// Every note ever made, spent or not, with its owner, its value, the two
/// heights and the movements on both sides of it. It is the explorer's real
/// growing cost and it is nearly nine times the one the site used to name: a
/// node that keeps the whole cold set carries seventy two bytes for each note
/// that has fallen, and a node that keeps none carries nothing at all.
///
/// A note is what is counted, and a note is not the whole of what is kept: the
/// index also holds an entry per transaction, a movement per side of every
/// note, and an entry per owner with two lists hanging off it. None of those
/// is fixed per note, so the figure is a function of two things and not one.
/// It holds an entry per block as well, which is counted apart, at
/// [`BYTES_PER_BLOCK`], because it is the one table whose size is the chain's
/// length rather than what the chain carries.
///
/// **The shape of the traffic.** `audit_index_cost.rs` weighs three, one test
/// each. The dearest is the ordinary payment, one note to the payee and one
/// back as change, which has the fewest notes to spread the rest over; the
/// wide fan-outs come out cheaper. That variable was found and fixed, and the
/// note here said so: the figure had been calibrated on the widest fan-out
/// alone, "which is the cheapest per note and which nobody sends".
///
/// **How many notes an owner holds.** Not found at the same time, and it is
/// the larger term. Every shape weighed there reuses one pool of addresses
/// block after block, so an owner entry and its two lists are spread over
/// about a hundred and thirty notes, and a hundred and thirty is not a
/// property of the traffic shape. Counted out of the index's own tables, with
/// every hash-table slot, B-tree slack and allocator header left out, so
/// these are floors:
///
/// | notes an owner holds | bytes a note |
/// |---:|---:|
/// | 1 | **627** |
/// | 2 | 396 |
/// | 4 | 308 |
/// | 130 | 346 |
///
/// One address per note is the privacy-standard shape and the cheapest way to
/// inflate somebody else's index, and a payee's address is the payee's choice
/// and not the sending wallet's. So it is the one quoted, the way the dearest
/// traffic shape is: an operator sizing a machine off this figure is not
/// helped by the friendliest of either variable.
///
/// This is content and not occupancy, which is the distinction
/// `cairn-accumulator`'s `archivist_cost.rs` draws for the archive. Taken
/// resident at the same shape it reads 916 to 936, about one and a half times
/// this, and that is what a machine actually has to have.
pub(crate) const BYTES_PER_NOTE: u64 = 627;

/// Bytes one block costs the index beside its notes: its identifier and the
/// height it sits at, so that it can be found by the one as it is by the
/// other, and the time in its header, so that a page can date a movement
/// without the block.
///
/// Content, like [`BYTES_PER_NOTE`], and counted apart from it because it is
/// a cost of the chain's length and not of what the chain carries: a chain of
/// empty blocks pays it and nothing else.
pub(crate) const BYTES_PER_BLOCK: u64 = 48;

/// What the index is made of, for the operator who has to pay for it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Size {
    pub(crate) notes: u64,
    pub(crate) transactions: u64,
    pub(crate) owners: u64,
    pub(crate) movements: u64,
    /// Blocks it can find by their identifier.
    pub(crate) blocks: u64,
    /// What that comes to, at [`BYTES_PER_NOTE`] and [`BYTES_PER_BLOCK`].
    pub(crate) bytes: u64,
}

impl Index {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Reads whatever the chain has added since the last call.
    ///
    /// A reorganisation takes back the blocks it undid, newest first, and
    /// reads the ones it applied. This used to drop the whole index and read
    /// the branch again, on the grounds that reorganisations are short and
    /// rare. They are short; they are not rare, because the chain calls a tie
    /// between two miners ordinary and every tie resolves as a switch on some
    /// node, and on an explorer that switch cost every block the node holds
    /// read back off the disk. A switch deeper than [`UNDO_DEPTH`] is still
    /// answered that way, and so is a log cut from under the walk.
    ///
    /// `block_at` reads one block of the followed branch from wherever it is.
    /// A node lets go of the bodies of blocks too deep to be undone, and an
    /// index built from the start of the chain wants exactly those, so this
    /// goes to a disk and must be called with no lock held.
    ///
    /// One call reads at most [`BATCH`] heights and then says whether there is
    /// more. Reading to the tip in one call was minutes with this index held,
    /// and the site cannot answer a single question without it: the sentence
    /// the page exists to show while the chain is being read was the one thing
    /// that could not be served while the chain was being read.
    ///
    /// `head` is about what this index has read, so a caller coming back for
    /// the next turn works it out again: `at_last_read` is the identifier the
    /// branch carries at the highest height read, and after a turn that is a
    /// different height. Handing the same one back says the branch changed
    /// under the index, and it is taken back to where the branch parted.
    pub(crate) fn refresh(
        &mut self,
        head: &Head,
        block_at: impl Fn(u64) -> Held,
        id_at: impl Fn(u64) -> Option<Hash32>,
        tip_now: impl Fn() -> Option<u64>,
    ) -> Reading {
        // Whether what was read last time is still on the branch. Only the
        // last block has to be checked: everything under it was checked when
        // it was read, and a branch that changed under one of them changed
        // under this one too.
        if let Some(span) = self.span {
            // From the head, which was taken with the chain in hand before
            // this turn started. The check at the bottom asks the chain again
            // and is the one that sees a switch land inside the turn; asking
            // the chain here as well would be asking it about a moment that
            // has not happened yet.
            let agrees = match head.at_last_read {
                Some(id) => id == span.id,
                // Past what the chain still holds an identifier for. Nothing
                // that deep can have changed, so it is taken as agreeing.
                None => span.through <= head.tip,
            };
            if !agrees {
                // The branch moved, and what is left to find out is how far
                // down. That is a question about the chain as it stands, so it
                // is asked of the chain rather than of the head: the highest
                // block read that the branch still carries is where the two
                // part, and everything above it is taken back. Everything
                // under it was one branch when it was read, and a branch is a
                // chain, so a block the branch still carries has under it only
                // blocks the branch still carries.
                if !self.back_to_the_branch(span.through, &id_at) {
                    *self = Self::new();
                }
            }
        }
        // Every height this turn ends up relying on, and the identifier it
        // relied on there. Asked again once the turn is over, which is the
        // whole of the second half of this check. At most one more than
        // `BATCH` entries: the top of what was already read, and what this
        // turn reads on top of it.
        let mut relies_on: Vec<(u64, Hash32)> = self
            .span
            .map(|span| vec![(span.through, span.id)])
            .unwrap_or_default();

        // Height zero on a fresh index, and the walk steps over whatever of
        // the bottom of the chain this node no longer holds rather than
        // stopping there.
        let mut height = self.resume;
        let mut reading = Reading::Done;
        let mut walked = 0u64;
        while height <= head.tip {
            if walked >= BATCH {
                reading = Reading::More;
                break;
            }
            match block_at(height) {
                Held::Block(block) => {
                    let id = block.id();
                    relies_on.push((height, id));
                    self.apply(&block, id);
                    self.stock_due = true;
                    self.span = Some(match self.span {
                        Some(span) => Span {
                            through: height,
                            id,
                            ..span
                        },
                        None => Span {
                            from: height,
                            through: height,
                            id,
                        },
                    });
                }
                Held::Dropped => {
                    // Nothing read before this height is worth checking any
                    // more, because nothing read before it is kept.
                    relies_on.clear();
                    // Below anything read this is only a shorter index, and
                    // the index says where it starts. Above it, the log was
                    // cut while this walk was inside it, so everything read
                    // so far has a hole under it. An index with a hole answers
                    // wrongly rather than shortly, so it starts again here.
                    if self.span.is_some() {
                        *self = Self::new();
                        self.stock_due = true;
                    }
                }
                // Both stop the walk where it stands, and the next turn
                // asks for this same height again. Waiting is a height that
                // has not reached this node's disk yet; refused is one that
                // is on it and would not read, which may be a fault that
                // passes and may be a disk on its way out. Stepping over
                // either would leave a hole under everything above it, and
                // an index with a hole in it answers wrongly rather than
                // shortly.
                Held::Waiting | Held::Refused => break,
            }
            height = height.saturating_add(1);
            // Written down as the walk goes, so that a turn which stepped over
            // nothing but dropped heights still leaves the next one further up
            // the chain than it started.
            self.resume = height;
            walked = walked.saturating_add(1);
        }
        // And the branch was still that branch when the turn ended.
        //
        // The check at the top asks once, before a block is read, and the
        // sentence beside it is true: everything under the last block read
        // was checked when it was read. What it does not cover is the turn
        // itself. `read_a_batch` takes the chain, asks two questions, gives it
        // back, and only then reads up to sixty four heights, taking the lock
        // again for each. A switch landing inside that window changes the
        // branch under heights already read, and the walk then reads the
        // heights above it off the branch that won and stamps the span with
        // the winner's identifier, so the check at the top of the next turn
        // agrees. And agrees for ever, because nothing looks below the last
        // block again.
        //
        // What that leaves is an index holding blocks off a branch nobody
        // has, permanently, with `coverage.whole` true. Measured: a transfer
        // the followed branch carries answered "no such transaction" while
        // `/api/block` printed it in the same instant off the same program,
        // and an address was shown a balance it was never paid.
        //
        // Asked of every height the turn relies on and not of the one it
        // ended at. The end of the span cannot see a switch below it, because
        // the span's own top was read after the switch landed and agrees with
        // it; and the height the turn started from cannot see a switch above
        // itself, which a generator over this walk found in eighteen cases.
        // A branch is a chain, so two heights agreeing says nothing about the
        // heights between them when what is between them came off somewhere
        // else. There is no cheaper sufficient question than all of them, and
        // all of them is at most sixty five, against the sixty four blocks
        // the turn has just read off a disk.
        // Asked after the walk rather than taken from the head, because the
        // head is the tip this turn began with and the whole of this check is
        // about what happened since. A branch that got shorter inside the turn
        // is invisible to the head's own number.
        //
        // What it does about a height that moved is take it back, with
        // everything read above it and whatever under it the branch no longer
        // carries either: the switch may have landed below where the turn
        // began, and the check at the top made what is under the turn one
        // branch, which is not yet saying it is this one.
        let reaches = tip_now();
        let still = |height, id| still_the_branch(height, id, reaches, &id_at);
        let moved = relies_on
            .iter()
            .filter(|(height, id)| !still(*height, *id))
            .map(|(height, _)| *height)
            .min();
        let started_over = moved.is_some();
        if let Some(height) = moved {
            if !self.back_to_the_branch(height.saturating_sub(1), &id_at) {
                *self = Self::new();
                self.stock_due = true;
            }
        }
        // Not between batches: reckoning the distribution is the one thing here
        // that costs the whole index rather than the block just read, and a
        // rebuild would otherwise pay for it once per turn all the way up the
        // chain. `take_stock` bounds how often it runs beyond that.
        if self.stock_due && reading == Reading::Done && !started_over {
            self.take_stock(head.tip);
        }
        // And `reading` as the walk left it, not `More` because of the reset.
        // `Explorer::refresh` loops until a turn says `Done`, so a reset that
        // asked for another turn would be a reset that asked for another turn
        // for as long as the disagreement lasted. One reset per call, and the
        // rebuild is the next call's work: the index says how much of the
        // chain it has read, and right after a reset the honest answer is
        // none of it.
        reading
    }

    fn apply(&mut self, block: &Block, id: Hash32) {
        let height = block.header.height;
        self.totals.blocks = self.totals.blocks.saturating_add(1);
        self.blocks.insert(id, height);
        self.times.push(block.header.timestamp);
        let mut undo = Undo {
            height,
            id,
            made: Vec::with_capacity(block.transfers.len().saturating_add(1)),
            spent: Vec::new(),
            paid: Amount::ZERO,
            fees: Amount::ZERO,
        };

        let coinbase = block.coinbase.id();
        self.at.insert(
            coinbase,
            Location {
                height,
                position: 0,
            },
        );
        undo.made
            .push((coinbase, outputs_of(block.coinbase.outputs.len())));
        for (id, note) in block.coinbase.created_notes() {
            self.credit(id, note.value, note.owner, height);
        }
        let paid = block.coinbase.total_output().unwrap_or(Amount::ZERO);
        if let Some(total) = self.totals.paid_to_miners.checked_add(paid) {
            self.totals.paid_to_miners = total;
            undo.paid = paid;
        }

        for (index, transfer) in block.transfers.iter().enumerate() {
            let position = u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .unwrap_or(u32::MAX);
            let id = transfer.id();
            self.at.insert(id, Location { height, position });
            self.totals.transfers = self.totals.transfers.saturating_add(1);
            undo.made.push((id, outputs_of(transfer.outputs.len())));

            let mut consumed = Amount::ZERO;
            for input in &transfer.inputs {
                if let Some(value) = self.debit(&input.note_id, height, id) {
                    consumed = consumed.checked_add(value).unwrap_or(consumed);
                    undo.spent.push(input.note_id);
                }
            }
            for (note_id, note) in transfer.created_notes() {
                self.credit(note_id, note.value, note.owner, height);
            }
            let produced = transfer.total_output().unwrap_or(Amount::ZERO);
            // A transfer can never produce more than it consumes; consensus
            // refuses one that does, so the difference is the fee.
            if let Some(fee) = consumed.checked_sub(produced) {
                if let Some(total) = self.totals.fees.checked_add(fee) {
                    self.totals.fees = total;
                    undo.fees = undo.fees.checked_add(fee).unwrap_or(undo.fees);
                }
            }
        }

        self.undo.push_back(undo);
        if self.undo.len() > UNDO_DEPTH {
            self.undo.pop_front();
        }
    }

    /// Takes back every block read above where the branch parted from what
    /// this index holds, looking no higher than `highest`, and says whether it
    /// could.
    ///
    /// Where they parted is the highest block read that the branch still
    /// carries, and a block the branch carries has under it only blocks the
    /// branch carries, because a branch is a chain: every identifier names
    /// the one below it.
    ///
    /// Carries, said by the chain naming the same identifier at that height.
    /// A chain that names nothing there is not taken as agreeing here, the
    /// way the checks above take it for a height too deep to have changed:
    /// the branch has already moved, and what is being looked for is proof of
    /// where it still stands.
    fn back_to_the_branch(&mut self, highest: u64, id_at: &impl Fn(u64) -> Option<Hash32>) -> bool {
        let parted = self
            .undo
            .iter()
            .rev()
            .filter(|undo| undo.height <= highest)
            .find(|undo| id_at(undo.height) == Some(undo.id))
            .map(|undo| undo.height.saturating_add(1));
        parted.is_some_and(|height| self.unwind_from(height))
    }

    /// Takes back every block read at `height` and above, newest first, and
    /// says whether it could.
    ///
    /// It cannot when a block that has to go is older than what this index
    /// kept the means to take back, or when nothing it read would be left
    /// under `height` to stand on. The caller then starts again from nothing,
    /// which is what every switch used to cost.
    fn unwind_from(&mut self, height: u64) -> bool {
        let Some(span) = self.span else {
            return false;
        };
        if height > span.through {
            return true;
        }
        while let Some(undo) = self.undo.pop_back() {
            if undo.height < height {
                self.undo.push_back(undo);
                break;
            }
            self.take_back(&undo);
        }
        // The block under `height` is the new top, and its identifier is the
        // one the next turn compares, so it has to be one this index kept.
        // Where it is not, the caller starts again, and what was taken back on
        // the way here goes with the rest.
        let Some(top) = self.undo.back() else {
            return false;
        };
        self.span = Some(Span {
            through: top.height,
            id: top.id,
            ..span
        });
        self.resume = top.height.saturating_add(1);
        // The table of the largest holders was worked out on the branch that
        // lost, and it says the height it was worked out at, which is now a
        // height on another branch. It is worked out again rather than left
        // to its usual sixteen blocks.
        self.stock_due = true;
        self.stock_at = None;
        true
    }

    /// Takes back the newest block this index read, which `undo` describes.
    fn take_back(&mut self, undo: &Undo) {
        let mut touched: Vec<PublicKey> = Vec::new();
        for id in undo.spent.iter().rev() {
            let Some(record) = self.notes.get_mut(id) else {
                continue;
            };
            record.spent_at = None;
            record.spent_by = None;
            let (value, owner) = (record.value, record.owner);
            if let Some(record) = self.owners.get_mut(&owner) {
                record.held = record.held.saturating_add(value.as_pebbles());
            }
            self.totals.notes_spent = self.totals.notes_spent.saturating_sub(1);
            touched.push(owner);
        }
        for (source, outputs) in undo.made.iter().rev() {
            for index in (0..*outputs).rev() {
                let Some(record) = self.notes.remove(&NoteId::new(*source, index)) else {
                    continue;
                };
                if let Some(owner) = self.owners.get_mut(&record.owner) {
                    owner.held = owner.held.saturating_sub(record.value.as_pebbles());
                    // Once what came in has stopped counting it stays stopped.
                    // Taking a payment off a figure that is already a floor
                    // would make the floor read as a total.
                    if owner.turnover_counted() {
                        owner.received = owner.received.saturating_sub(record.value.as_pebbles());
                    }
                }
                self.totals.notes_created = self.totals.notes_created.saturating_sub(1);
                touched.push(record.owner);
            }
            self.at.remove(source);
        }
        // An owner's two lists are in the order of the chain and this block is
        // the newest read, so what it added to them is at their ends.
        let made: HashSet<Hash32> = undo.made.iter().map(|(id, _)| *id).collect();
        touched.sort_unstable();
        touched.dedup();
        for owner in touched {
            let Some(record) = self.owners.get_mut(&owner) else {
                continue;
            };
            while record
                .notes
                .last()
                .is_some_and(|id| made.contains(&id.source))
            {
                record.notes.pop();
            }
            while record
                .movements
                .last()
                .is_some_and(|movement| movement.height == undo.height)
            {
                record.movements.pop();
                self.movements = self.movements.saturating_sub(1);
            }
            // Paid only on the branch that lost, which a fresh read of the
            // winning one would never have met. Every movement is a note of
            // this owner's arriving or leaving, so an owner with no notes left
            // has no movements left either.
            if record.notes.is_empty() {
                self.owners.remove(&owner);
            }
        }
        self.blocks.remove(&undo.id);
        self.times.pop();
        let transfers = u64::try_from(undo.made.len().saturating_sub(1)).unwrap_or(u64::MAX);
        self.totals.transfers = self.totals.transfers.saturating_sub(transfers);
        self.totals.blocks = self.totals.blocks.saturating_sub(1);
        self.totals.paid_to_miners = self
            .totals
            .paid_to_miners
            .checked_sub(undo.paid)
            .unwrap_or(Amount::ZERO);
        self.totals.fees = self
            .totals
            .fees
            .checked_sub(undo.fees)
            .unwrap_or(Amount::ZERO);
    }

    fn credit(&mut self, id: NoteId, value: Amount, owner: PublicKey, height: u64) {
        self.notes.insert(
            id,
            NoteRecord {
                value,
                owner,
                created_at: height,
                spent_at: None,
                spent_by: None,
            },
        );
        let record = self.owners.entry(owner).or_default();
        record.notes.push(id);
        record.movements.push(Movement {
            height,
            incoming: true,
            transaction: id.source,
            value,
        });
        self.movements = self.movements.saturating_add(1);
        record.received = record.received.saturating_add(value.as_pebbles());
        record.held = record.held.saturating_add(value.as_pebbles());
        self.totals.notes_created = self.totals.notes_created.saturating_add(1);
    }

    /// Marks a note spent and returns what it was worth.
    fn debit(&mut self, id: &NoteId, height: u64, by: Hash32) -> Option<Amount> {
        let record = self.notes.get_mut(id)?;
        record.spent_at = Some(height);
        record.spent_by = Some(by);
        let value = record.value;
        let owner = record.owner;
        if let Some(owner) = self.owners.get_mut(&owner) {
            owner.held = owner.held.saturating_sub(value.as_pebbles());
            owner.movements.push(Movement {
                height,
                incoming: false,
                transaction: by,
                value,
            });
            self.movements = self.movements.saturating_add(1);
        }
        self.totals.notes_spent = self.totals.notes_spent.saturating_add(1);
        Some(value)
    }

    pub(crate) fn totals(&self) -> Totals {
        self.totals
    }

    /// Blocks read so far.
    pub(crate) fn blocks_read(&self) -> usize {
        usize::try_from(self.totals.blocks).unwrap_or(usize::MAX)
    }

    /// The lowest and highest heights this index has read, if it has read any.
    pub(crate) fn covers(&self) -> Option<(u64, u64)> {
        self.span.map(|span| (span.from, span.through))
    }

    /// Whether it read the chain from its first block.
    ///
    /// The one that matters is `false`. An index that starts above zero knows
    /// nothing about what an address held before it started reading, so every
    /// balance it gives is a figure about part of the chain and not about the
    /// chain. Somebody reading a balance of nought has no way of telling that
    /// from a real balance of nought unless the page says which it is.
    pub(crate) fn reads_from_the_start(&self) -> bool {
        matches!(self.span, Some(span) if span.from == 0)
    }

    /// What this index is made of.
    pub(crate) fn size(&self) -> Size {
        let notes = u64::try_from(self.notes.len()).unwrap_or(u64::MAX);
        let blocks = u64::try_from(self.blocks.len()).unwrap_or(u64::MAX);
        Size {
            notes,
            transactions: u64::try_from(self.at.len()).unwrap_or(u64::MAX),
            owners: u64::try_from(self.owners.len()).unwrap_or(u64::MAX),
            movements: self.movements,
            blocks,
            bytes: notes
                .saturating_mul(BYTES_PER_NOTE)
                .saturating_add(blocks.saturating_mul(BYTES_PER_BLOCK)),
        }
    }

    /// The height a block this index read sits at, by its identifier.
    pub(crate) fn height_of(&self, block: &Hash32) -> Option<u64> {
        self.blocks.get(block).copied()
    }

    /// The time in the header of the block this index read at `height`.
    pub(crate) fn timestamp_at(&self, height: u64) -> Option<u64> {
        let from = self.span?.from;
        let at = usize::try_from(height.checked_sub(from)?).ok()?;
        self.times.get(at).copied()
    }

    pub(crate) fn locate(&self, transaction: &Hash32) -> Option<Location> {
        self.at.get(transaction).copied()
    }

    pub(crate) fn note(&self, id: &NoteId) -> Option<NoteRecord> {
        self.notes.get(id).copied()
    }

    pub(crate) fn owner(&self, owner: &PublicKey) -> Option<&OwnerRecord> {
        self.owners.get(owner)
    }

    /// Owners holding anything, heaviest first.
    ///
    /// Read from what the last refresh worked out. Sorting every owner in
    /// order to answer one page was work any caller could ask for at will;
    /// now it happens once per block, whether anyone is looking or not.
    pub(crate) fn richest(&self) -> &[(PublicKey, Amount)] {
        &self.richest
    }

    /// How many owners hold anything at all.
    pub(crate) fn holders(&self) -> usize {
        self.holders
    }

    /// Works out the distribution, at most once every [`STOCK_EVERY`] blocks.
    ///
    /// This is the one thing in the walk whose cost is the whole index rather
    /// than the block that was just read, and the reason `BATCH` exists is
    /// that a visitor should wait for a turn and not for the chain. It ran on
    /// every turn that reached the tip, which on a running site is every
    /// block, and it took the index lock while it iterated every owner and
    /// sorted them all to keep fifty:
    ///
    /// | owners | one new block |
    /// |---:|---:|
    /// | 24 576 | 2.4 ms |
    /// | 98 304 | 8.3 ms |
    /// | 393 216 | 32.8 ms |
    /// | 1 572 864 | 138.8 ms |
    ///
    /// Sixty four times the owners cost fifty eight times the turn, for the
    /// same block. Two things changed. The fifty heaviest are selected rather
    /// than sorted, which is one pass instead of a sort of everything; and it
    /// runs on a block in sixteen rather than on every one, because a table
    /// of the largest holders is a summary and nobody is owed it to the
    /// block. What it costs to be that stale is stated rather than hidden:
    /// the answer carries the height it was worked out at.
    fn take_stock(&mut self, tip: u64) {
        let due = match self.stock_at {
            Some(at) => tip.saturating_sub(at) >= STOCK_EVERY,
            None => true,
        };
        if !due {
            return;
        }
        self.stock_due = false;
        self.stock_at = Some(tip);
        let mut held: Vec<(PublicKey, Amount)> = self
            .owners
            .iter()
            .map(|(owner, record)| (*owner, record.balance()))
            .filter(|(_, balance)| *balance > Amount::ZERO)
            .collect();
        self.holders = held.len();
        // Ordered only as far as the fifty that are kept. The rest of the
        // order is nobody's answer, and paying for it was the larger half of
        // what this cost.
        let keep = RICHEST.min(held.len());
        if keep < held.len() {
            held.select_nth_unstable_by(keep, |left, right| {
                right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
            });
            held.truncate(keep);
        }
        held.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        self.richest = held;
    }

    /// The height the distribution above was worked out at.
    pub(crate) fn stock_at(&self) -> Option<u64> {
        self.stock_at
    }

    /// Everything this index says about the chain, written out in one order,
    /// so a test can ask whether two indexes reached by different roads say
    /// the same thing.
    ///
    /// Read by the suites that include this file, and not by the unit tests
    /// beside it.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn contents(&self) -> String {
        let at: BTreeMap<_, _> = self.at.iter().collect();
        let owners: BTreeMap<_, _> = self.owners.iter().collect();
        let blocks: BTreeMap<_, _> = self.blocks.iter().collect();
        format!(
            "{:?}\n{at:?}\n{blocks:?}\n{:?}\n{:?}\n{owners:?}\n{:?}\n{}",
            self.span, self.times, self.notes, self.totals, self.movements
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use cairn_crypto::SecretKey;
    use cairn_ledger::note::NoteId;
    use cairn_primitives::{Amount, Hash32};

    use super::Index;

    /// What an owner holds is told right however much has passed through it.
    ///
    /// What an owner was paid and what it paid out were kept as amounts, and
    /// an amount stops at the most money there will ever be. What an owner
    /// holds is below that; what has passed through one is not, because a
    /// wallet sends its change back to the key it spent from, so an address
    /// holding a hundred thousand that pays ten thousand times has been paid
    /// a billion. Past that point every payment in was dropped whole while
    /// every payment out still counted, and the balance slid to nothing and
    /// stayed there, on the page that tells a person what they hold. Every
    /// index the tests built had seen a few block rewards, so an index that
    /// stopped counting at the ceiling passed.
    #[test]
    fn an_owner_whose_money_has_gone_round_past_the_ceiling_is_told_what_it_holds() {
        let owner = SecretKey::generate().unwrap().public_key();
        let half = Amount::from_pebbles(Amount::MAX_MONEY.as_pebbles() / 2).unwrap();
        let mut index = Index::new();

        // Half of everything there can be, paid in and out twice, and then in
        // once more: a billion and a half through the address, half a billion
        // still in it.
        for turn in 0..3u8 {
            let id = NoteId::new(Hash32::from_bytes([turn; 32]), 0);
            index.credit(id, half, owner, u64::from(turn));
            if turn < 2 {
                index.debit(&id, u64::from(turn), Hash32::from_bytes([turn; 32]));
            }
        }

        let record = index.owner(&owner).unwrap();
        assert_eq!(
            record.balance(),
            half,
            "an owner holding half of all the money there can be was told it held \
             another figure, because what had passed through it was counted as an \
             amount and stopped counting at the ceiling"
        );
        let pebbles = half.as_pebbles();
        assert_eq!(
            (record.received, record.spent()),
            (pebbles * 3, pebbles * 2),
            "what the owner was paid and paid out stopped counting at the ceiling"
        );
        assert!(
            record.turnover_counted(),
            "a turnover well inside what a count of pebbles holds is called a floor"
        );
    }

    /// What an owner holds is told right past the point where a count of
    /// pebbles stops, and the two turnover figures say they have become
    /// floors.
    ///
    /// The balance was what came in less what went out, both counted in
    /// pebbles and both saturating. Change comes back to the key that spent,
    /// so an address paying out of one large note counts that note in and out
    /// again on every payment, and past `u64::MAX` pebbles every payment in was
    /// dropped whole while every payment out still counted: the balance slid
    /// to nought with the notes that made it still unspent in the same index.
    /// Nothing drove that much through one owner, so a balance worked out that
    /// way passed.
    #[test]
    fn an_owner_whose_turnover_passes_what_a_count_can_hold_keeps_its_balance() {
        let owner = SecretKey::generate().unwrap().public_key();
        let half = Amount::from_pebbles(Amount::MAX_MONEY.as_pebbles() / 2).unwrap();
        let mut index = Index::new();

        // Half of everything there can be, paid back to the same key over and
        // over: past u64::MAX pebbles by a couple of payments.
        let payments = u64::MAX / half.as_pebbles() + 2;
        let mut held = NoteId::new(Hash32::from_bytes([0; 32]), 0);
        index.credit(held, half, owner, 0);
        for payment in 1..=payments {
            let mut source = [0u8; 32];
            source[..8].copy_from_slice(&payment.to_le_bytes());
            let spender = Hash32::from_bytes(source);
            index.debit(&held, payment, spender);
            held = NoteId::new(spender, 0);
            index.credit(held, half, owner, payment);
        }

        let record = index.owner(&owner).unwrap();
        assert_eq!(
            record.balance(),
            half,
            "an owner still holding one note worth half of all the money there can \
             be was told it held another figure, because what had passed through it \
             stopped counting and what went out did not"
        );
        assert!(
            !record.turnover_counted(),
            "what came in stopped counting, and nothing says that the two turnover \
             figures are now floors rather than totals"
        );
        assert!(
            record.spent() > 0 && record.spent() < record.received,
            "what went out is published as a floor below what came in"
        );
    }
}

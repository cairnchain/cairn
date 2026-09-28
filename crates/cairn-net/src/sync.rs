//! What a node does when a message arrives.
//!
//! Pure by design: it reads the chain, the address book, and what is known
//! about one peer, and says what to send. No sockets, no threads, and no clock
//! it reads itself. Everything that decides whether two nodes converge lives
//! here, so all of it can be tested by handing it messages.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use cairn_chain::{Accepted, ChainError, ChainStore, Located, Outdated, MAX_LOCATOR};
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::NetworkId;
use cairn_ledger::validation::BlockError;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;

use crate::book::worth_hearing_about;
use crate::message::{
    carries_a_join_part, Handshake, Joining, Keeps, Message, PeerAddress, Placed, MAX_ANNOUNCED,
    MAX_HEADERS, MAX_PROVEN, MAX_REQUESTED, MAX_SHARED_ADDRESSES, PROTOCOL_VERSION,
};

/// Everything of the surrounding node this layer is allowed to see.
#[derive(Debug)]
pub struct Local<'a> {
    pub chain: &'a mut ChainStore,
    /// What this node kept, which is what it can be asked for: the headers,
    /// so a newcomer can be shown which chain carries the most work, and the
    /// cold set, so a wallet can be told where one of its fallen notes sits.
    ///
    /// Two answers rather than one. They cost nothing alike, almost every node
    /// gives the first and almost none gives the second, and while they shared
    /// a field the second was claimed by everybody and offered by nobody.
    pub keeps: Keeps,
    /// The port this node names when it introduces itself, so peers can pass
    /// its address along. Nought for a node that does not offer itself to be
    /// dialled, which is a wallet's, and its peers then write nothing down.
    pub listen: u16,
    /// What this node calls itself on the wire, so it can recognise its own
    /// connection coming back to it.
    pub nonce: u64,
}

/// What this node knows about one peer.
#[derive(Clone, Debug, Default)]
pub struct PeerState {
    /// Whether the peer has introduced itself. Nothing else is answered until
    /// it has.
    pub greeted: bool,
    pub height: u64,
    /// The most work this peer has claimed for its chain: what it wrote in
    /// its greeting, raised by any block it delivers above what this node
    /// holds that claims more.
    ///
    /// It was the greeting and nothing else, and nothing revised it. Every
    /// long-lived connection of a node at the tip was greeted at equal work,
    /// so a node that missed one block, lost a tie at one height, or refused
    /// a block for its timestamp heard the next block from that peer, found
    /// its parent missing, and asked for nothing, for as long as the
    /// connection lived.
    pub total_work: u128,
    /// The number the peer drew when it started, as it said in its
    /// introduction. Both ends of a pair hold both numbers once greeted, which
    /// is what makes it the thing to break a tie between two connections on.
    pub nonce: u64,
    /// What the peer said it kept. Choosing whom to join has to know the
    /// first about everyone who spoke, and a wallet looking for somebody to
    /// rebuild a path has to know the second.
    pub keeps: Keeps,
    /// Heights asked for and not yet received. While this is non empty the node
    /// is mid batch and does not ask for more.
    ///
    /// Heights rather than identifiers, because what is asked for is a stretch
    /// of a branch and a node does not know what a peer holds at a height
    /// until it arrives. A block that turns up is checked against the chain
    /// like any other; what this tracks is only whether the question has been
    /// answered.
    pub awaiting: BTreeSet<u64>,
    /// Of those, the ones this node asked about because this peer announced
    /// them rather than because it was catching up.
    ///
    /// The two are not the same errand and only one of them is owed a
    /// discount. Catching up, this node walks heights it worked out itself and
    /// goes and asks for them; the peer answering is doing this node a favour,
    /// and what reading its block cost is handed back once the block is on
    /// the branch this node follows. An announcement is the other direction:
    /// the peer offered, and a block offered is a block pushed, which is what
    /// the byte price is for.
    ///
    /// Told apart here because the ask that follows an announcement looks
    /// exactly like the ask that follows a catch-up, and `awaiting` remembers
    /// only the height. A peer that announced first could therefore write its
    /// own discount, and the heights in an announcement are the peer's to
    /// choose: a hundred and twenty eight invented identifiers armed a hundred
    /// and twenty eight full-sized blocks at a unit each, which is four times
    /// cheaper than the flat price this was all meant to abolish.
    pub offered: BTreeSet<u64>,
    /// Whether this node has a `GetChain` outstanding to this peer.
    ///
    /// `awaiting` is filled from two places and [`Self::offered`] was written
    /// at one of them. The other is the answer to a `GetChain`, whose `from`
    /// and `count` the peer writes: a peer that sends a `Chain` nobody asked
    /// for fills `awaiting` with heights of its own choosing, and every block
    /// it then pushes at one of them is charged the catching-up price. Which
    /// is the same defect `offered` was added for, through the door it was not
    /// added to. Measured afterwards: a discount of one thousand two hundred
    /// and eighty nine times, and a window of allowance buying four point nine
    /// gigabytes by that road against three and three quarter megabytes by the
    /// one that was closed.
    ///
    /// Set where a `GetChain` is sent, which is only ever this node's own
    /// doing, and taken by the `Chain` that answers it. This layer sends one
    /// from `greet` and `follow_up`; the node sends one from outside it, and
    /// says so through [`asked_for_the_chain`], which it could not do until
    /// that was written: every answer to the node's own questions was priced
    /// as a push.
    ///
    /// This said "nothing a peer says sets it", which was true of the
    /// assignment and false of what causes it. `follow_up` asks again whenever
    /// nothing is outstanding and `total_work` says the peer is ahead, and
    /// `total_work` is a number the peer writes, in its greeting and in the
    /// blocks it delivers. So a peer claiming the most work there is kept the
    /// gate open for good, and emptied `awaiting` itself by sending a block at
    /// each height it had named: every block it pushed, fully decoded and never
    /// applied because its parent was invented, re-armed the discount for the
    /// next hundred and twenty eight. One unit a block, against a frame
    /// ceiling two thousand times larger than a unit pays for.
    ///
    /// Armed again only when the last round moved this node's own chain: see
    /// [`Self::work_when_asked`].
    pub chain_asked: bool,
    /// This node's own total work when it last asked this peer for the chain.
    ///
    /// The one number in this exchange the peer does not write. A round of
    /// catching up that delivered blocks this node could apply raised it, and
    /// only such a round earns the next one the catching up price. A round
    /// whose blocks connected to nothing left it where it was, and the next
    /// `GetChain` still goes out, because this node does want the chain from a
    /// peer that says it has more, but its answer pays what any push pays.
    pub work_when_asked: Option<u128>,
    /// When the outstanding batch was asked for, or when the last block of it
    /// arrived, whichever is later.
    ///
    /// A peer that answers everything else but never delivers the blocks it
    /// was asked for would otherwise hold this node mid batch indefinitely,
    /// which is a way of stalling a sync without ever looking unresponsive.
    ///
    /// Renewed by a block of the batch arriving, which is the reading the
    /// wire's own patience takes: a link that keeps delivering is still going.
    /// Measured from the ask alone, a peer sending a full batch more slowly
    /// than one batch a patience was asked for the chain again while it was
    /// still sending, sent the same blocks twice, and paid for both.
    ///
    /// Not renewed by what the peer volunteers. An ask starts the patience of
    /// a batch when none is out, or when it answers a `GetChain` this node
    /// sent; a `Chain` nobody asked for, or an announcement, adds its heights
    /// to a batch already out and leaves its patience where it was. Both used
    /// to renew it, whatever heights they named, so a peer that never sent a
    /// block of its batch and named the same heights again once a minute held
    /// this node mid batch for as long as it cared to.
    ///
    /// One of two times this struct keeps, both about what this node is waiting
    /// on, and deliberately. When a peer last said anything is a different
    /// question with a different answer, and the answer is `last_heard` in the
    /// connection loop, which is where the decision that reads it is made:
    /// ninety seconds of quiet ends the connection. A `last_message` was kept
    /// here as well, written on every message from every peer and read by
    /// nothing, which is two records of one fact where only one of them
    /// decides. Whoever wants a rule about a quiet peer wants the one in the
    /// loop.
    pub asked_at: u64,
    /// The last block this peer delivered that this node holds off the
    /// branch it follows, until the next `Chain` this peer sends takes it.
    ///
    /// What lets a branch that parts below the tip arrive a window at a
    /// time. A peer serves a batch only as far as the asker's window pays
    /// for, and a block off the branch followed is never handed its price
    /// back, so of a branch of full blocks one round brings what one window
    /// buys, about thirty two blocks. The next round asked from where the
    /// branches part, as every round does, and brought the same blocks
    /// again: a heavier branch weighing more than a window was never taken.
    /// It is asked from past this block instead, while everything below it
    /// down to the branch followed is still held. See [`past_what_arrived`].
    ///
    /// Taken rather than read, so a block that is not on the branch the peer
    /// now offers steers one round at most. A round asked past it that
    /// brings nothing to hold leaves nothing here, and the next is asked
    /// from where the branches part.
    pub aside: Option<Located>,
    /// The moment this node's clock allows a block this peer sent that it
    /// refused for being dated ahead of it, while that moment is still to
    /// come.
    ///
    /// The chain is not asked of this peer before then. Every block above the
    /// refused one hangs on it, so each arrived with its parent missing and
    /// asked for the chain, whose answer named the refused block again, to be
    /// refused again: a batch a round trip for as long as the clock was
    /// behind. And once the wait was over nothing asked, so the refused block
    /// came back only with the peer's next announcement.
    pub clock_allows_at: Option<u64>,
    /// Where the connection came from, filled in by whoever opened it.
    pub remote: Option<IpAddr>,
    /// Whether this node went out and opened this connection.
    ///
    /// The one thing about a peer that is not the peer's to decide. A
    /// connection somebody else opened is a connection somebody else chose,
    /// and what such a peer says about the rest of the network is weighed
    /// accordingly: see [`worth_hearing_about`].
    pub dialled: bool,
    /// Where this peer says it can be reached, which is its own port on the
    /// address the connection came from.
    pub advertised: Option<SocketAddr>,
    /// What answering this one connection has cost so far.
    ///
    /// Kept for the sake of being readable rather than because anything
    /// decides on it. What decides is [`PeerState::allowance`], which belongs
    /// to the address and not to the socket.
    ///
    /// Held by [`PeerState::afford`]; nothing else should touch it.
    pub spent: u32,
    /// What reading the frame the current message came in was charged, before
    /// a byte of it was decoded.
    ///
    /// Counted toward that message's price and taken by [`on_message`], so a
    /// frame's charge settles the message it carried and no other. See
    /// [`PeerState::afford_reading`].
    pub paid_to_read: u32,
    /// Work this peer may still ask for in the current window.
    ///
    /// Nothing here stops a peer asking as fast as its connection allows, and
    /// what it asks for is not free: a block to validate, a signature to
    /// check, a hundred and twenty eight records to read off a disk. Without a
    /// ceiling, how much a node spends answering is decided by whoever
    /// connects to it, which is the cheapest attack there is on a program that
    /// answers strangers.
    pub allowance: Allowance,
}

/// How long a peer's allowance lasts before it is handed out again.
const WINDOW_SECONDS: u64 = 10;

/// Whether `now` falls in a later allowance window than `then`.
///
/// For the one party outside this layer that has to know: a node collecting a
/// handover, whose next question went unanswered because the peer serving it
/// had spent the window it was asked in. When that window has turned is
/// exactly when asking again is worth anything, and it is the only thing
/// about the accounting anybody out there needs.
pub fn a_window_has_turned(then: u64, now: u64) -> bool {
    let window = |at: u64| at.checked_div(WINDOW_SECONDS).unwrap_or(0);
    window(now) > window(then)
}

/// What has been spent inside one window, and which window that was.
///
/// Windows are counted off the clock rather than from whenever a peer first
/// spoke, so that a connection and the address it arrived from are always
/// talking about the same ten seconds. Without that they could not hand the
/// count between them, which is what the whole of this exists to do.
#[derive(Clone, Copy, Debug, Default)]
pub struct Window {
    spent: u32,
    window: u64,
}

impl Window {
    /// Moves to the window `now` falls in, saying whether that is a new one.
    fn roll(&mut self, now: u64) -> bool {
        let window = now.checked_div(WINDOW_SECONDS).unwrap_or(0);
        if window == self.window {
            return false;
        }
        self.window = window;
        self.spent = 0;
        true
    }

    /// Whether this still says anything about what may be spent now.
    ///
    /// A window that has passed is worth nothing to anybody, which is what
    /// lets the node drop the ones belonging to addresses that have gone.
    pub(crate) fn current(&self, now: u64) -> bool {
        self.window == now.checked_div(WINDOW_SECONDS).unwrap_or(0)
    }
}

/// What one connection may still ask for, and what its address has already
/// asked for this window.
///
/// The second half is the repair, and it is a narrow one. The window used to
/// live on the socket and nothing else, so a peer refilled it by hanging up:
/// greet, spend it, close, dial back. That costs a TCP handshake and a Hello,
/// and it earns no refusal, because asking is not misbehaviour and neither is
/// reconnecting. One address drew six thousand chain answers in six seconds
/// across six connections, where the allowance intends one thousand per ten.
///
/// So a connection now begins where the address it came from left off. What
/// it deliberately does not do is pool: two connections open at once each
/// spend their own, because that is what an honest pair of nodes behind one
/// address is, and what the address keeps is the largest of them rather than
/// the sum. The ceiling on one address is therefore `MAX_PER_HOST` allowances
/// a window instead of as many as it cares to dial, which is a number this
/// node chooses rather than one a stranger does.
///
/// Shared state in a layer that is otherwise a pure function of what it is
/// handed, and the exception is deliberate: what is being repaired is
/// precisely that this state used to begin again with each socket. A peer
/// built without an address keeps only its own count, which is what a test
/// handing messages to [`on_message`] gets and what a node never uses.
#[derive(Clone, Debug, Default)]
pub struct Allowance {
    mine: Window,
    address: Option<Arc<Mutex<Window>>>,
    /// Whether this connection has asked for anything yet.
    ///
    /// What decides whether it inherits its address's spend. See
    /// [`Self::afford`].
    opened: bool,
}

impl Allowance {
    /// The allowance of a connection from an address the node keeps a count
    /// for.
    pub fn at(address: &Arc<Mutex<Window>>) -> Self {
        Self {
            mine: Window::default(),
            address: Some(Arc::clone(address)),
            opened: false,
        }
    }

    /// Takes `cost`, saying whether it was there.
    ///
    /// A poisoned lock means a thread panicked holding it, which the release
    /// profile turns into an abort. Carrying on with the count is better than
    /// a second panic.
    fn afford(&mut self, cost: u32, now: u64) -> bool {
        let rolled = self.mine.roll(now);
        // A connection starts where its address left off, so hanging up is not
        // a way of being handed a fresh window.
        //
        // Only at its first question, which is the whole of what that defends.
        // Doing it at every window boundary made the count shared for as long
        // as both connections lived, and the harm was not to an attacker: two
        // people behind one carrier NAT, or one office, or one cloud gateway,
        // and whichever spoke second each window was answered with silence for
        // as long as the other kept talking. Two hundred and forty messages
        // over five minutes made a neighbour invisible, and window boundaries
        // are `unix_time / 10`, which anybody can compute.
        //
        // A connection that stayed open across a boundary has nothing to
        // inherit: it never hung up, so its own count is the honest one.
        if rolled && !self.opened {
            let carried = self.address.as_ref().map(|window| {
                let mut held = window.lock().unwrap_or_else(PoisonError::into_inner);
                held.roll(now);
                held.spent
            });
            if let Some(spent) = carried {
                self.mine.spent = spent;
            }
        }
        self.opened = true;
        let after = self.mine.spent.saturating_add(cost);
        if after > ALLOWANCE {
            return false;
        }
        self.mine.spent = after;
        if let Some(window) = self.address.as_ref() {
            let mut held = window.lock().unwrap_or_else(PoisonError::into_inner);
            held.roll(now);
            held.spent = held.spent.max(after);
        }
        true
    }

    /// Gives back `units` of what this connection spent in the window `now`
    /// falls in.
    ///
    /// The address keeps the most it saw rather than following this down,
    /// because what it keeps is the largest spend of any connection from it
    /// and this cannot tell whose that was. So a connection opened from the
    /// same address later in the same window may begin a little above what
    /// was really spent, by at most one frame, which errs the way the
    /// inheritance is for.
    ///
    /// A window that has turned since the charge has nothing of it left to
    /// give back, and is left alone.
    fn hand_back(&mut self, units: u32, now: u64) {
        if self.mine.current(now) {
            self.mine.spent = self.mine.spent.saturating_sub(units);
        }
    }
}

/// What a peer may ask for within one window.
///
/// This is not the same as the ceiling the node keeps on how many messages a
/// peer may send, which is there against a peer repeating itself hundreds of
/// times a second and closes the connection when it is passed. This one counts
/// what answering costs rather than how often it is asked: two thousand
/// messages are within that ceiling, and two thousand asking for a hundred and
/// twenty eight blocks each is a quarter of a million records to read off a
/// disk. Being asked a lot is not misbehaviour, so this slows rather than
/// closes.
///
/// Set from what an honest peer needs rather than from what feels safe. The
/// most a peer ever legitimately wants is a full sync, which asks for blocks as
/// fast as it can take them: at this allowance that is eight hundred blocks a
/// second, and nothing else an honest peer does comes anywhere near it.
///
/// That is what the allowance permits and not what a sync does, and the two
/// were written here as one number. This said that eight hundred a second put
/// thirty years of chain on a disk in five hours, "which is what the bandwidth
/// alone would take", and neither half follows: the allowance decides nothing
/// about how fast a catch-up runs. Two nodes over a loopback socket, with empty
/// blocks and no link in the way at all, were measured at a hundred blocks a
/// second, steady, over two thousand nine hundred of them: an eighth of what
/// this allows, and thirty years at that rate is forty-four hours rather than
/// five. Whatever paces a catch-up, and the exchange asks a fresh locator and
/// waits a round trip for every [`MAX_REQUESTED`] blocks, it is not this. So
/// this stays a ceiling an honest sync does not come near, which is all it was
/// ever for, and the duration it used to promise belongs to whoever measures
/// the exchange rather than here. `tests/network.rs` prints that reading off
/// the catch-up it already runs, so whoever doubts the figure can take it
/// again.
pub(crate) const ALLOWANCE: u32 = 8_192;

/// What each kind of message costs to answer, in the same units.
///
/// Roughly proportional to the work rather than measured: a block has to be
/// validated, a transfer carries signatures, and a block read off a disk is a
/// seek. Being roughly right is what matters, since the ceiling is far above
/// what an honest peer asks for and far below what a busy one could spend.
const COST_TRIVIAL: u32 = 1;
const COST_CHAIN: u32 = 8;
/// What one input of a transfer costs to take.
///
/// This was the price of a whole transfer, and a transfer carries between one
/// and `max_inputs_per_transfer` of them. Every input is a note resolved out
/// of the ledger and an Ed25519 signature checked against it, and verifying
/// one is the dearest thing this node does per byte received: more than a fold
/// against the cold set, which the same table prices at eight a place.
///
/// Flat, the price bought whatever the sender chose to make the message out
/// of. One unit bought thirty seven bytes of a one input transfer and six
/// thousand four hundred and seventy six bytes of a two hundred and fifty six
/// input one, so the largest and dearest shape was the cheapest to send, by
/// the full ratio between the two.
///
/// **Why the cheap refusals do not cover it.** A transfer whose signatures are
/// nonsense is refused after a handful of checks, because `first_failure`
/// stops at the first that does not hold and splits the work across threads
/// that each stop at their own. A transfer whose arithmetic is wrong is
/// refused before a signature is looked at, because the fee is worked out in
/// the same pass that resolves the inputs and returns first. So a transfer's
/// whole signature cost is reached only by one whose signatures all hold,
/// which is a sender that owns the notes.
///
/// **Which is not a defence.** Two hundred and fifty six notes are one
/// transfer's worth of outputs. Spending them again in a variant differing by
/// a pebble is a different identifier, resolves the same way, and is refused
/// by the pool only on the rate it offers, which `ChainStore::accept_transfer`
/// works out after `check_transfer` has verified every signature.
///
/// Four an input, which is what a whole transfer used to cost. The outputs are
/// priced beside it, by [`COST_PER_OUTPUT`], so an ordinary payment of one
/// input and two outputs costs twelve.
const COST_PER_INPUT: u32 = 4;
/// What one output of a transfer costs to take.
///
/// Priced because it is not free, and the price above said nothing about it.
/// An output is a note, and reading a note off the wire decompresses its
/// owner's key off the curve and checks it for its subgroup, before anything
/// has looked at the price. Measured beside a signature check on one machine:
/// forty seven microseconds an output against fifty one a verification. So a
/// transfer of one input and two hundred and fifty six outputs cost four
/// units and twelve milliseconds, and a unit spent on that shape bought a
/// hundred and twenty six times the processor a unit spent on an ordinary
/// payment did. The widest shape was the cheapest way to make this node
/// compute, which is the defect [`COST_PER_INPUT`] was written against,
/// reached through the other list.
///
/// The same price as an input, since the work is about the same. At the block
/// ceiling this network allows, relaying every transfer the chain can carry
/// then costs one peer's window between a tenth and a quarter of it, by shape,
/// and a sixth for ordinary payments.
const COST_PER_OUTPUT: u32 = 4;
/// What a block this node did not ask for costs, on top of its bytes.
///
/// The bytes are the price and this is the floor under them, so the smallest
/// block still costs what it used to and nothing arrives for nothing.
const COST_BLOCK: u32 = 8;
/// What reaching the disk for one block costs.
///
/// The seek and nothing else. This used to be the whole price of a block, on
/// the reasoning that a header and a block are both "a seek and a read", which
/// is true of the disk and false of the wire: the same unit bought a hundred
/// and twenty eight kilobytes here and a hundred and eighty two bytes there.
/// What the block puts on the wire is charged separately, by
/// [`what_the_wire_costs`], because it is the one thing the ask cannot say.
const COST_PER_BLOCK_SERVED: u32 = 1;
/// What one header served costs, which is one read off the header log.
///
/// A header is smaller than a block and cheaper to send, but the disk does not
/// care: both are a seek and a read. Charging the ask rather than what it
/// serves is what let one seventeen byte request buy five hundred and twelve
/// reads, which is the whole of the difference between a limit that counts
/// what answering costs and one that counts messages.
///
/// Flat, unlike the block charge, because a header is a fixed size and the ask
/// therefore states what the answer weighs.
const COST_PER_HEADER_SERVED: u32 = 1;
/// What one header a peer hands this node costs to take in.
///
/// The same price as handing one out, for the same reason the address charges
/// are the same in both directions: filing a header is a record appended to a
/// log, and a write is not the cheaper end of a disk. A run of
/// [`MAX_HEADERS`] of them was one unit for all five hundred and twelve, and
/// it is the only list in the protocol whose price did not move with its
/// length.
///
/// The argument for the flat price was that a run from anybody but the peer
/// this node is filling from is refused before a byte of it is written, so an
/// unwanted one costs a comparison. True, and it is an argument about
/// strangers rather than about the price: the peer holding the turn is a
/// stranger too, chosen by nothing better than being the lowest connection
/// number this node had, and what it hands over is written record by record
/// before anything has looked at whether it is the truth. A node handed a
/// ledger a million and a half blocks up would file that whole gap, read it
/// all back to weigh it, and build a forest over it, for about three thousand
/// units: a third of one window, where reading the same headers out of the
/// same node costs a hundred and eighty three of them.
///
/// A node that has filled its headers in asks for nothing and is handed
/// nothing, and one still filling asks once a round, which is one run a
/// second: five thousand one hundred and twenty units of a supplier's window
/// out of eight thousand one hundred and ninety two. That leaves what an
/// honest supplier spends on everything else it does, and it is the rate the
/// exchange already ran at rather than a new one.
const COST_PER_HEADER_TAKEN: u32 = COST_PER_HEADER_SERVED;
/// What one address handed to a peer that asked costs.
///
/// The cheapest message there is drew the largest answer a peer can get for
/// nothing: nine bytes on the wire bought twelve hundred, a hundred and
/// thirty five times over, and the asker set the size of it by filling the
/// book with IPv6 addresses first, which weigh nineteen bytes each against
/// seven. At one unit an allowance window bought eight thousand of those
/// answers, which is ten megabytes out of a node for a kilobyte in.
///
/// Charged as what the largest answer costs rather than as what this node's
/// book happens to hold, for the same reason the header charge is on the ask
/// and not on the reply: a price that moves with the book is a price whoever
/// fills the book gets to set. At this cost a window answers a hundred and
/// twenty eight, and an honest peer asks about once a second.
///
/// The price stopped moving with the book and the work went on moving with
/// it: each of those hundred and twenty eight answers copied the whole book
/// and sorted it, under the book's lock. That is the same sentence about the
/// same message and it is repaired in [`crate::book::AddressBook::sample`],
/// which now reads what it hands over and nothing else.
const COST_PER_ADDRESS_SERVED: u32 = 1;
/// What one address a peer hands this node costs to take in.
///
/// The same price as handing one out, for the same reason: taking one in is
/// weighing it, looking up its neighbourhood, and putting it in the book in
/// the order the book keeps. A `Peers` message carrying
/// [`MAX_SHARED_ADDRESSES`] of them was one unit for all sixty four, so a
/// window bought half a million of those insertions for a peer that spent it
/// on nothing else, all of them under the one lock that dialling, saving and
/// every other peer's addresses wait on.
///
/// It is a message this node asked for, and it is still charged, because
/// nothing on the wire says a peer was asked: a stranger sends the same
/// message unbidden and it costs the same to take. A node asks each peer for
/// addresses about once a second, so an honest peer pays sixty four units ten
/// times in a window against eight thousand.
const COST_PER_ADDRESS_LEARNED: u32 = 1;
/// What one place proved costs to answer for.
///
/// A path is about a kilobyte on a chain with a million fallen notes, which is
/// five headers' worth of wire for a fraction of the disk, so the wire is what
/// this is priced on. Eight rather than five because building one is done with
/// the chain in hand: a header comes off a disk while everybody else carries
/// on, and this does not.
///
/// Charged on what is asked for rather than on what comes back, like the
/// header charge and for the same reason. A node that cannot prove a place
/// still had to look, and a price that only applied to answers found would let
/// a peer ask for places nobody has, for nothing, all day.
///
/// At this price an allowance window buys sixteen full requests, which is a
/// thousand and twenty four paths, and a wallet recovering asks once.
const COST_PER_PLACE_PROVED: u32 = 8;
/// What one path a peer hands this node costs to take in.
///
/// The same price as building one, for the same reason the header and address
/// charges are the same in both directions: the two ends of this exchange do
/// comparable work. Serving a place walks a tree and puts about a kilobyte on
/// the wire; taking one reads that kilobyte back and folds it against a
/// commitment this node worked out for itself, under the chain's lock.
///
/// `Proofs` fell through to the catch-all arm at one unit for the whole
/// message, and a message carries [`MAX_PROVEN`] paths. So the same node
/// charged eight units to build a path and a five hundred and twelfth of a
/// unit to fold one, which is the last of the take-and-serve pairs to be
/// priced in the same currency.
const COST_PER_PLACE_TAKEN: u32 = COST_PER_PLACE_PROVED;

/// What one identifier in an announcement costs to take.
///
/// A lookup in the block table, which is cheaper than any other entry priced
/// here: an address is weighed and written into the book under the book's
/// lock, a header is a record appended to a log, and a path is a fold against
/// the cold set. One unit is the floor of this table's currency, so it is what
/// the cheapest entry costs, and what it buys is that the price moves with the
/// length at all.
///
/// The lock is why it is not free. The block table is behind the chain, which
/// is the one lock in this node every other thread waits on, and an
/// announcement is a stranger handing this node a run of lookups to do while
/// holding it. `MAX_ANNOUNCED` of them cost one unit between them, so one
/// window bought four million of those lookups where the same window buys
/// eight thousand addresses. Both are bounded runs a stranger sends unasked
/// and this node then walks one by one.
///
/// An honest announcement carries one identifier, because a node announces
/// what it has just applied and that is one block per message it took. Nothing
/// in an ordinary exchange pays more than it did.
const COST_PER_ANNOUNCED: u32 = 1;

/// What one piece of a join answer costs to build and send.
///
/// An eighth of a window, so a newcomer collecting twenty two pieces takes
/// three windows and a peer asking for nothing else is spending everything it
/// has on it.
const COST_JOIN: u32 = ALLOWANCE / 8;

/// Bytes of an answer a peer draws for one unit of its allowance.
///
/// Everything above prices a seek, and a seek is what a header costs and not
/// what a block does. `GetBlocks` for [`MAX_REQUESTED`] heights is a kilobyte
/// of request and up to sixteen megabytes of reply, and at one unit a block a
/// window bought eight thousand of them: a gigabyte per ten seconds per
/// address, sold for six and a half kilobytes a second of asking. Per unit
/// that is a hundred and twenty eight kilobytes where a header buys a hundred
/// and eighty two bytes, and nothing drops a repeat, so the same heights are
/// answered for as long as the peer cares to ask.
///
/// The number is not a new judgement. A join answer is the largest thing this
/// node ever builds for anybody, and it already fixed this rate: a part is
/// [`crate::message::JOIN_PART_BYTES`] and costs [`COST_JOIN`], which is five
/// hundred and twelve bytes to the unit. Blocks are charged the same, so the
/// two largest answers a stranger can draw cost the same per byte and a window
/// buys four megabytes of either. `the_two_largest_answers_cost_the_same_per_byte`
/// holds the two numbers together.
const BYTES_PER_UNIT: usize = 512;

/// What putting `bytes` of answer on the wire costs, on top of whatever the
/// ask already paid for reaching the disk.
///
/// Rounded up, so the smallest block still costs a unit and a chain of empty
/// blocks is priced by its seeks, which is what it costs.
///
/// Charged on what is served rather than on what is asked for, which is the
/// opposite of the rule the header and the path charges follow, and the reason
/// is that this is the one price the ask cannot state. A header is a fixed
/// hundred and eighty two bytes and a path is about a kilobyte, so the ask
/// bounds them; a block is anything up to what the consensus rules allow, and
/// only whoever read it off the disk knows which. Charging the ceiling would
/// mean a full batch of empty blocks costing sixteen megabytes' worth of
/// allowance, which no honest sync could afford.
#[must_use]
fn what_the_wire_costs(bytes: usize) -> u32 {
    u32::try_from(bytes.div_ceil(BYTES_PER_UNIT)).unwrap_or(u32::MAX)
}

impl PeerState {
    /// A peer just connected, reached at `remote`.
    pub fn new(remote: Option<IpAddr>) -> Self {
        Self {
            remote,
            ..Self::default()
        }
    }

    /// Takes `cost` from this peer's allowance, saying whether it was there.
    ///
    /// The window is the address's rather than the connection's, so what a
    /// peer spends here is spent whether or not it stays.
    fn afford(&mut self, cost: u32, now: u64) -> bool {
        if !self.allowance.afford(cost, now) {
            return false;
        }
        self.spent = self.spent.saturating_add(cost);
        true
    }

    /// Takes what putting `bytes` on the wire costs, saying whether it was
    /// there.
    ///
    /// Called as a batch is served rather than after it, so a peer that has
    /// spent its window is handed what it could afford and the rest is not
    /// read, not encoded and not queued. A peer that gets a short batch asks
    /// for the rest of it once its patience with the batch runs out, which is
    /// what it already does about the heights this node no longer holds, and
    /// from past what arrived, whether that went onto the branch it follows
    /// or was held aside: see [`PeerState::aside`].
    pub(crate) fn afford_serving(&mut self, bytes: usize, now: u64) -> bool {
        self.afford(what_the_wire_costs(bytes), now)
    }

    /// Takes what reading `frame` costs, before a byte of it is decoded,
    /// saying whether it was there.
    ///
    /// A frame is decoded before anything in it can be priced, and decoding
    /// is not free: every note in it is an owner's key decompressed off the
    /// curve and checked for its subgroup, about fifty microseconds each. The
    /// price used to be asked only after that, in [`on_message`], so eight
    /// hundred kilobytes of note owners from a peer that had introduced itself
    /// cost this node nine tenths of a second of processor for the price of
    /// one message against the flood ceiling, and a window that was spent
    /// slowed none of it: a refusal was silence, and the next frame was
    /// decoded like the last.
    ///
    /// So a frame is charged what its bytes cost first, at the rate a block
    /// served is, and one this peer cannot pay for is not decoded at all. The
    /// charge is a deposit rather than a second price: it counts toward what
    /// the message it carried turns out to cost, and a message pays the larger
    /// of the two.
    ///
    /// Two frames are not charged. One from a peer that has not introduced
    /// itself, because it may only be a handshake, which is free, a few
    /// hundred bytes, and the only frame such a peer may send at all. And a
    /// piece of a join answer from the peer this node is collecting one from,
    /// which is taken before the allowance as the answer to a question this
    /// node asked that peer by name: charging it here would have that peer's
    /// window refuse pieces this node went and asked for, and decoding one is
    /// a copy of its bytes. `collecting` answers whether this is that peer,
    /// and is asked only of a frame tagged as a piece.
    ///
    /// Only that peer. The tag is the first byte of the frame and anybody can
    /// write it, so any greeted peer had every frame it tagged as a piece read
    /// and decoded outside its allowance, a megabyte at a time up to the flood
    /// ceiling, to be dropped only afterwards as a piece nobody had asked for.
    pub fn afford_reading(
        &mut self,
        frame: &[u8],
        now: u64,
        collecting: impl FnOnce() -> bool,
    ) -> bool {
        self.paid_to_read = 0;
        if !self.greeted || (carries_a_join_part(frame) && collecting()) {
            return true;
        }
        let deposit = what_the_wire_costs(frame.len());
        if !self.afford(deposit, now) {
            return false;
        }
        self.paid_to_read = deposit;
        true
    }

    /// Takes what `price` still owes once what reading its frame cost is
    /// counted toward it, and says what the message came to in all, or `None`
    /// when the window could not pay the rest.
    ///
    /// A message pays the larger of the two and never both. The frame's charge
    /// is taken here whatever happens, so it settles this message and no
    /// later one.
    fn settle(&mut self, price: u32, now: u64) -> Option<u32> {
        let paid = std::mem::take(&mut self.paid_to_read);
        self.afford(price.saturating_sub(paid), now)
            .then(|| price.max(paid))
    }

    /// Gives back `units` this peer paid, now that the message they paid for
    /// has turned out to cost less.
    fn hand_back(&mut self, units: u32, now: u64) {
        self.allowance.hand_back(units, now);
        self.spent = self.spent.saturating_sub(units);
    }
}

/// Why a peer is no longer worth talking to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DropReason {
    #[error("peer sent a {kind} before introducing itself")]
    Unannounced { kind: &'static str },
    #[error("peer introduced itself twice")]
    RepeatedHandshake,
    #[error("peer speaks protocol version {theirs}, this node speaks {PROTOCOL_VERSION}")]
    WrongVersion { theirs: u32 },
    #[error("peer follows network {theirs}")]
    WrongNetwork { theirs: NetworkId },
    #[error("peer follows a chain starting at {theirs}, which is not this one")]
    ForeignChain { theirs: Hash32 },
    #[error(
        "peer sent a block for height {height} carrying version {found}, where the \
         rules this node follows are version {required}"
    )]
    ForeignRules {
        height: u64,
        found: u16,
        required: u16,
    },
    #[error("peer sent a block this node rejects")]
    BadBlock { id: Hash32 },
    #[error("this node could not read back a block of its own, so it left this connection")]
    OwnStore,
    #[error("this connection is this node talking to itself")]
    Ourselves,
}

impl DropReason {
    /// Whether this peer behaved badly, rather than merely belonging elsewhere.
    ///
    /// A node on another network or an older protocol has done nothing wrong
    /// and may be on this one tomorrow, so it is disconnected rather than
    /// refused, and its address is kept. A peer sending a block this node
    /// rejects, or speaking before introducing itself, is broken or probing,
    /// and is worth turning away for a while.
    pub fn is_misbehaviour(self) -> bool {
        match self {
            Self::Unannounced { .. } | Self::RepeatedHandshake | Self::BadBlock { .. } => true,
            // Reaching yourself is a fact about routing, not a fault, and the
            // node it happened to is this one.
            Self::WrongVersion { .. }
            | Self::WrongNetwork { .. }
            | Self::ForeignChain { .. }
            // On the day a rule changes, every node that has not updated sends
            // blocks under the old version in good faith. They belong to the
            // chain this node left rather than to a peer doing anything wrong,
            // and refusing the host would turn the first minutes of a fork
            // into an updated node banning most of the network.
            | Self::ForeignRules { .. }
            // The peer asked for a switch and this node could not make it.
            // Whatever went wrong is on this side of the wire.
            | Self::OwnStore
            | Self::Ourselves => false,
        }
    }
}

/// What to do about one received message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reaction {
    /// Answers for the peer that sent the message.
    pub reply: Vec<Message>,
    /// What the block in this message did to the followed branch, when there
    /// was one and it was new. The node writes its log from this: what has to
    /// be kept on disk is the branch being followed, not every block that ever
    /// arrived.
    pub applied: Option<Accepted>,
    /// Paths a peer offered back for places this node asked about.
    ///
    /// Named rather than folded here, like the locator and the join piece
    /// below it and for the same reason: folding one reads the cold set, and
    /// this runs with the chain held.
    ///
    /// It is named *here* rather than taken before this layer, which is where
    /// it used to be taken. The node's reading loop hands an answer to
    /// whatever asked for it before the chain has been near it, which is right
    /// for an answer nobody asked for: it is dropped without costing
    /// anything. What it also did was carry this message past the one place
    /// that charges for work, so the price the table puts on a path folded
    /// against the cold set was never asked for.
    pub(crate) placed: Vec<Placed>,
    /// Blocks newly worth telling every other peer about, with where they sit.
    pub broadcast: Vec<Located>,
    /// A locator a peer sent, waiting to be answered.
    ///
    /// Answering it means finding the last position in it this node agrees
    /// with, and a node no longer holds an identifier for every height: for
    /// anything older than a reorganisation could reach, the answer is on a
    /// disk. Named here and resolved once the chain is let go of, for the same
    /// reason blocks are.
    /// An option rather than an empty list standing for no question: a node
    /// with no chain at all sends an empty locator, and that is exactly the
    /// node most in need of an answer.
    pub locate: Option<Vec<Located>>,
    /// A piece of a join answer a peer asked for.
    ///
    /// Named rather than built here. Building one means encoding a ledger,
    /// which is megabytes, and this runs with the chain held.
    pub join: Option<(Joining, u32)>,
    /// A run of headers a peer asked for: where to start, and how many.
    ///
    /// Named rather than read here, for the same reason blocks are: they come
    /// off a disk, and this runs with the chain held.
    pub headers: Option<(u64, u64)>,
    /// Places in the cold set a peer asked to have proved.
    ///
    /// Named rather than answered here, for the same reason the blocks are.
    /// Building a path means walking the archive a level at a time, and this
    /// runs with the chain held; sixty four of those under that lock is a
    /// stranger deciding how long everyone else waits, which is what an audit
    /// found a join request doing for a hundred and fifty eight milliseconds.
    ///
    /// An option rather than an empty list standing for no question, so that a
    /// peer that asked about nothing is told apart from a peer that asked
    /// nothing. The first is owed an answer, even an empty one.
    pub prove: Option<Vec<u64>>,
    /// A run of headers a peer offered as the ones from before this node
    /// arrived, and the height it says they start at.
    ///
    /// Named rather than taken here, again because taking them reaches a
    /// disk: they go into a log of their own and the forest they make is
    /// weighed against a commitment. Named *here* rather than picked out of
    /// the stream before it reaches this layer, which is where they used to
    /// be taken, so that a run from a peer that has not introduced itself is
    /// refused like anything else it might send.
    pub offered_headers: Option<(u64, Vec<BlockHeader>)>,
    /// Heights on the followed branch a peer asked for.
    ///
    /// Named rather than read here, because most of them are read off a disk
    /// and this runs with the chain held. A hundred and twenty eight seeks
    /// under that lock is a peer deciding how long everyone else waits. The
    /// node gathers them once it has let go, in the order they were asked for.
    pub fetch: Vec<u64>,
    /// Set when a peer asked for addresses.
    ///
    /// Named rather than answered here, for the same reason the blocks and
    /// the headers are. The answer is drawn from the whole book, which holds
    /// up to `MAX_ADDRESSES` entries in two maps and has to be ordered before
    /// any of it can be shared, and this runs with the chain held. Worse,
    /// this layer used to be handed a copy of that book for *every* message
    /// from every peer, so serving a seventeen byte ping cost an amount the
    /// asker set with address lists that cost it one unit each, inside the
    /// node's one global lock. Nothing here reads the book any more, and the
    /// one message that needs it is answered once the chain is let go of.
    pub share_addresses: bool,
    /// Addresses worth adding to the book.
    pub learned: Vec<SocketAddr>,
    /// Addresses worth taking out of it.
    ///
    /// Detecting a connection to oneself is only half the job. Left in the
    /// book, the address is dialled again a second later, and the node spends
    /// its life opening connections to itself and closing them.
    pub forget: Vec<SocketAddr>,
    /// Transfers the pool did not hold before, worth passing on.
    pub relayed: Vec<Hash32>,
    /// Set when the connection should be closed.
    pub drop_peer: Option<DropReason>,
    /// A block whose body this peer handed in and this node now holds off its
    /// branch, unjudged.
    ///
    /// Named so the node can write down who sent it. A body held aside is
    /// only tried when its branch becomes the heaviest, usually on the
    /// delivery of a later block by somebody else, and by then the one
    /// message that could say whose body it was is long gone.
    pub held_aside: Option<Hash32>,
    /// A block held aside below the one that arrived, whose body failed when
    /// the arrival made its branch the heaviest.
    ///
    /// Not this peer's doing, and it used to be charged to this peer: the
    /// refusal names the block that failed, every such refusal became
    /// `BadBlock` against the peer in hand, and the peer in hand is the one
    /// carrying the heavier branch. Named instead, so the node can refuse
    /// whoever handed in that body.
    pub failed_below: Option<Hash32>,
    /// The height of a block this node refused because it can never take it,
    /// rather than because it has not caught up to it yet.
    ///
    /// The two refusals look identical from here and mean opposite things,
    /// and only one of them was ever said out loud. A block whose parent has
    /// not arrived is ordinary and resolves itself. A block hanging below
    /// everything this node holds does not: a node handed a ledger holds
    /// nothing under the height it was handed on and never will, so a branch
    /// forking under there cannot be assembled however much of it arrives.
    ///
    /// Set rather than acted on, because what it means is a question about
    /// this node and not about the block or the peer that sent it.
    pub unreachable: Option<u64>,
    /// Set when the block that arrived is judged by rules this software does
    /// not have.
    ///
    /// The node stops on this rather than carrying on. Carrying on would mean
    /// refusing every peer that had updated and following whoever had not,
    /// which is worse than not running: a wallet reading a balance off an
    /// abandoned chain is answered confidently and wrongly.
    pub outdated: Option<Outdated>,
    /// The version of a block this build could not read, when one arrived.
    ///
    /// Not a bad block and not a bad peer. A block written under rules this
    /// software does not have becomes readable the moment the software is
    /// updated, so refusing it is a judgement about the reader; the block is
    /// not remembered as bad and the messenger is not blamed for carrying it.
    ///
    /// That correctness had a cost, which this is here to pay. Before it,
    /// these fell through to the last arm below and the connection was closed
    /// and the host refused, so an un-updated node banned everyone who had
    /// updated. After it, the same node refused the real chain in total
    /// silence and its operator saw only a height that had stopped moving.
    ///
    /// So the version is named and passed up, where peers are counted. One of
    /// these means nothing: it is a number in a field, and the check that
    /// would catch a lie about the work behind the block sits below the check
    /// that reads the version.
    pub unjudged: Option<u16>,
    /// Seconds by which a refused block's timestamp stood ahead of this node's
    /// own clock, when one did.
    ///
    /// The one refusal in the whole rule set that two honest nodes can
    /// disagree about, and that the same node reverses simply by waiting. It
    /// is measured against a clock this machine keeps, so what it says is
    /// about the reader as much as about the block, and the reading worth
    /// having is not about either: a run of these is a machine whose clock is
    /// wrong, and nothing else in this node ever mentions a clock to the
    /// person running it.
    ///
    /// Named rather than acted on, and counted where peers are counted, for
    /// the same reason [`Self::unjudged`] is: one of these is a number a
    /// stranger writes in a field.
    pub ahead_of_the_clock: Option<u64>,
    /// The first height a peer said it can supply, when that is above this
    /// node's tip, in answer to this node's own question for its chain.
    ///
    /// A peer answers from where its log begins when that is above anything
    /// this node agrees with, and a node further behind than its peers keep
    /// blocks for is answered that way by all of them. It used to ask for
    /// those heights all the same, take blocks whose parents it would never
    /// hold, and ask for the chain again after each batch, for as long as it
    /// ran, printing healthy lines under a height that did not move. It
    /// cannot be handed a ledger either, since it already follows a chain.
    /// Never set for a node that holds nothing of its own, which can be.
    ///
    /// Named rather than acted on, and counted where peers are counted: one
    /// of these is a number a peer writes, and what a node should conclude
    /// from several is a question about the node.
    pub cannot_supply: Option<u64>,
}

impl Reaction {
    fn idle() -> Self {
        Self::default()
    }

    fn reply(messages: Vec<Message>) -> Self {
        Self {
            reply: messages,
            ..Self::default()
        }
    }

    fn close(reason: DropReason) -> Self {
        Self {
            drop_peer: Some(reason),
            ..Self::default()
        }
    }
}

/// What this node says about itself.
pub fn local_handshake(chain: &ChainStore, keeps: Keeps, listen: u16, nonce: u64) -> Handshake {
    Handshake {
        version: PROTOCOL_VERSION,
        network: chain.params().network,
        genesis: first_block(chain).unwrap_or(Hash32::ZERO),
        tip: chain.tip().unwrap_or(Hash32::ZERO),
        height: chain.height().unwrap_or_default(),
        total_work: chain.total_work(),
        keeps,
        listen,
        nonce,
    }
}

fn accept_handshake(chain: &ChainStore, theirs: &Handshake) -> Result<(), DropReason> {
    if theirs.version != PROTOCOL_VERSION {
        return Err(DropReason::WrongVersion {
            theirs: theirs.version,
        });
    }
    if theirs.network != chain.params().network {
        return Err(DropReason::WrongNetwork {
            theirs: theirs.network,
        });
    }
    // A node with no chain of its own has nothing to compare against and has to
    // take the genesis it is about to be handed. Choosing whom to ask first is
    // what a seed address is: the one piece of trust in the whole protocol, and
    // it belongs to whoever runs the node, not to the network.
    if let Some(ours) = first_block(chain) {
        if theirs.genesis != ours && theirs.genesis != Hash32::ZERO {
            return Err(DropReason::ForeignChain {
                theirs: theirs.genesis,
            });
        }
    }
    Ok(())
}

/// The block this node's chain starts at, for saying and for checking.
///
/// The rules first, because a named network pins its first block and that is
/// known before a single one arrives. The branch second, for a rule set that
/// pins nothing, which is what tests run on.
///
/// Reading only the branch was a hole with no attacker in it and no noise: a
/// node handed a ledger has a branch that starts at its anchor and no first
/// milestone, so it answered nothing, introduced itself with a genesis of
/// zeroes, and let every peer past the one check that says "you are on another
/// chain". The nodes it failed for were the ones that had just arrived.
fn first_block(chain: &ChainStore) -> Option<Hash32> {
    chain.params().genesis.or_else(|| chain.genesis())
}

fn greet(local: &Local<'_>, peer: &mut PeerState, theirs: Handshake, answer: bool) -> Reaction {
    if peer.greeted {
        return Reaction::close(DropReason::RepeatedHandshake);
    }
    // Before anything else, and before the address is written down: a node
    // that reaches itself would otherwise spend one of its few connections on
    // itself, and keep its own address in the book to try again later.
    if theirs.nonce == local.nonce {
        let mut reaction = Reaction::close(DropReason::Ourselves);
        // The address this connection came from, completed by the port the
        // handshake names, is this node's own. Take it out of the book, or it
        // will be dialled again on the next sweep.
        if let Some(ip) = peer.remote {
            if theirs.listen != 0 {
                reaction.forget.push(SocketAddr::new(ip, theirs.listen));
            }
        }
        return reaction;
    }
    if let Err(reason) = accept_handshake(local.chain, &theirs) {
        return Reaction::close(reason);
    }

    peer.greeted = true;
    peer.height = theirs.height;
    peer.total_work = theirs.total_work;
    peer.nonce = theirs.nonce;
    peer.keeps = theirs.keeps;

    let mut reaction = Reaction::idle();
    // The peer names its own port; the address it is reachable at is that port
    // on the address this connection actually came from. Taking the address
    // from the socket rather than from the peer is what stops one node
    // advertising someone else.
    if let Some(ip) = peer.remote {
        if theirs.listen != 0 {
            let address = SocketAddr::new(ip, theirs.listen);
            peer.advertised = Some(address);
            reaction.learned.push(address);
        }
    }

    if answer {
        reaction.reply.push(Message::Welcome(local_handshake(
            local.chain,
            local.keeps,
            local.listen,
            local.nonce,
        )));
    }
    if theirs.total_work > local.chain.total_work() {
        // A node with no chain of its own facing one long enough to be final
        // does not ask here at all. Whatever it starts following first is
        // what it keeps, so the choice of whom to ask is made once, by the
        // node, against every claim it has heard, rather than by whichever
        // handshake this happens to be. A short chain carries no such
        // weight: following the wrong one is undone by the fork choice like
        // any other branch, so it is simply asked for.
        //
        // No chain of its own includes the first block a named network pins,
        // which a node lays down the moment it starts. Asking whether the
        // chain was empty instead meant no newcomer on a real network ever
        // held off here, so every one of them read the chain block by block.
        let held_for_the_choice =
            local.chain.holds_nothing_of_its_own() && theirs.height >= JOIN_RATHER_THAN_READ;
        if !held_for_the_choice {
            peer.chain_asked = true;
            peer.work_when_asked = Some(local.chain.total_work());
            reaction.reply.push(Message::GetChain {
                locator: local.chain.locator(),
            });
        }
    }
    reaction.reply.push(Message::GetPeers);
    reaction
}

/// How long a batch of blocks may be outstanding before the node gives up on
/// it and asks again.
///
/// Public so a test names this number rather than restating it.
pub const BATCH_PATIENCE: u64 = 60;

/// The chain length past which being handed a ledger beats reading one.
///
/// A handover is about twelve megabytes whatever the chain's age. Reading a
/// chain costs what the chain weighs, which is its length times what its
/// blocks carry, and a node deciding has no idea what the blocks it has not
/// read carry. So the crossing point cannot be worked out exactly: on an empty
/// chain it is tens of thousands of blocks, and on a full one it is under a
/// hundred.
///
/// A thousand is inside that range and wrong in the cheap direction at both
/// ends. Below it a node reads a chain that would have been a little quicker
/// to be handed; above it, on a chain of empty blocks, it accepts twelve
/// megabytes where a few would have done. Either mistake costs seconds, once,
/// and what matters is that a node chooses rather than starting both and
/// taking whichever finishes.
///
/// It carries a second duty on purpose: it matches the deepest
/// reorganisation a node accepts, so a chain this long is also one a node
/// with nothing cannot back out of once it follows it. That is why a
/// newcomer facing a chain past this length does not ask on the handshake,
/// and lets [`crate::choosing`] decide whom to ask instead.
///
/// Held to that by the build below rather than by this sentence alone, as the
/// other two numbers tied to the same depth are (`MAX_BEHIND` and the
/// handover's burial): a change to either end that forgot the other would
/// leave a newcomer committing, on a handshake, to a chain it can no longer
/// back out of.
pub const JOIN_RATHER_THAN_READ: u64 = 1_024;

const _: () = assert!(JOIN_RATHER_THAN_READ == cairn_chain::MAX_REORG_DEPTH as u64);

/// Heights one peer may have outstanding at any moment.
///
/// This was unbounded. Two messages a peer pays one unit each for (a chain it
/// says it has, a block it says it found) both extended the set and both
/// pushed back the only thing that emptied it, so a peer that kept talking
/// kept the set and kept adding to it. A thousand of them, a fraction of one
/// allowance window, held a hundred and twenty eight thousand heights.
///
/// Four batches rather than one, which a catch-up turned out to need. A node
/// that asks for a stretch its peer has since let go of hears nothing back,
/// and what moves it on is the next thing that peer says about its chain. With
/// room for only the batch already outstanding, that arrived and was dropped,
/// and the node waited out `BATCH_PATIENCE` instead: a minute of nothing, for
/// each stretch, on a sync that should take seconds. Four is still four
/// kilobytes and still a ceiling; unbounded was the defect, not the size.
///
/// Two paths reach it, and only one of them used to keep it.
/// `request_range` counts what a batch would newly wait on and refuses the
/// batch that does not fit; `request_announced` asked whether there was any
/// room at all and then admitted up to [`MAX_REQUESTED`] heights against it.
/// The set reached 639 where this says 512, and while it is over, every range
/// this node asks for is refused by the path that does keep the ceiling: an
/// announcement a peer chose to send stalled this node's own catching up.
///
/// Public so a test names this number rather than restating it. A test that
/// wrote `512` would pass on the day somebody changed it here.
pub const MAX_AWAITING: usize = MAX_REQUESTED * 4;

/// The first height worth asking for of a branch a peer offers from `from`.
///
/// `from` itself, as a rule. A peer answers a locator with the height past
/// the highest position it agrees with, and a locator runs from the tip down,
/// so every position above that one was put to it and refused. When the peer
/// is on another branch, the heights between `from` and this node's tip are
/// that branch, which this node does not have, and nothing above them can be
/// applied without them. Asking only above the tip left a node that was not
/// listening while a heavier branch's first blocks went round unable ever to
/// take it, and after a switch that failed on a body held aside, unable ever
/// to ask for the real one again.
///
/// Where the locator skips heights, the peer agrees below where the branches
/// part rather than at it, so the first of what comes back is already here.
/// That is less than one batch: `from` is taken only within a batch of the
/// tip, so the batch asked from it always reaches past the tip, and asks for
/// more blocks of the other branch than this node holds of its own above
/// where the two part, or all of them.
///
/// Asks for, and is not always sent. A peer serves a batch only as far as the
/// asker's window pays for, which of full blocks is about thirty two, so a
/// round that starts here every time is sent the same first blocks every
/// time. The next round starts from past what arrived instead: see
/// [`past_what_arrived`]. More blocks are not more work either: a branch
/// whose blocks are so much lighter than this node's that two batches of them
/// still weigh less is asked for the same two batches in turn, and is not
/// taken from this answer.
///
/// A batch or more below the tip, only what lies above the tip is asked for.
/// A peer that recognises nothing it was shown answers from nought, which a
/// locator always shows, and one that joined holds no identifier for the
/// heights below where it joined. Asking from there is a batch of blocks this
/// node already follows, the same batch every round, and the node never asks
/// past its tip. A branch that parts that deep is not taken from this answer.
fn first_wanted(chain: &ChainStore, from: u64) -> u64 {
    let have = chain.height().map_or(0, |tip| tip.saturating_add(1));
    let batch = u64::try_from(MAX_REQUESTED).unwrap_or(u64::MAX);
    let within_a_batch = have.saturating_sub(from) < batch;
    if within_a_batch {
        from
    } else {
        have
    }
}

/// Where a round of asking for a peer's branch from `start` goes on from,
/// given `arrived`, the last block that peer delivered off the branch this
/// node follows.
///
/// Past that block, when every block from it down to where it meets the
/// branch followed is still held, and it meets that branch no lower than
/// just below `start`: everything in between is here already, and asking for
/// it again is what kept a heavier branch weighing more than one window away
/// for good. `start` otherwise. A body that failed a switch is dropped, and so
/// are the lowest blocks off the branch when too many are held, so a stretch
/// with a hole in it is asked for again from where it parts, which is where
/// the hole is. A block of a branch that parts lower is not on the branch the
/// peer offers now, and is not followed either.
///
/// The walk is a batch at most, the bound [`first_wanted`] draws, so what it
/// costs is about what asking for the batch it spares costs. A longer stretch
/// is asked from `start`, and what arrives for that leaves a block within a
/// batch of it for the round after.
fn past_what_arrived(chain: &ChainStore, start: u64, arrived: Option<Located>) -> u64 {
    let Some(last) = arrived else {
        return start;
    };
    let mut at = last;
    for _ in 0..=MAX_REQUESTED {
        if chain.agrees_with(&at) {
            // Where what is held meets the branch followed. At `last` itself,
            // nothing is held aside at all.
            return if at.height == last.height {
                start
            } else {
                last.height.saturating_add(1)
            };
        }
        match (chain.block(&at.id), at.height.checked_sub(1)) {
            (Some(block), Some(below)) if at.height >= start => {
                at = Located::new(below, block.header.previous);
            }
            _ => return start,
        }
    }
    start
}

/// Asks for a stretch of a peer's branch, starting at `from`.
///
/// `prompted` is whether this node had asked for a chain. It decides nothing
/// about what is asked and everything about what the answers cost: the price
/// of a block is discounted when this node went looking for it, and a `Chain`
/// nobody asked for is the peer choosing the heights that discount applies to.
fn request_range(
    chain: &ChainStore,
    peer: &mut PeerState,
    from: u64,
    count: u64,
    now: u64,
    prompted: bool,
) -> Reaction {
    let wanted = usize::try_from(count)
        .unwrap_or(MAX_REQUESTED)
        .min(MAX_REQUESTED);
    if wanted == 0 {
        return follow_up(chain, peer, now);
    }
    let batch: Vec<u64> = (0..wanted)
        .filter_map(|step| u64::try_from(step).ok())
        .map(|step| from.saturating_add(step))
        .collect();
    // Only what this would newly wait on counts against the ceiling. Asking
    // again for a stretch already outstanding grows nothing, and is how a sync
    // gets past a peer that answered part of one.
    let room = MAX_AWAITING.saturating_sub(peer.awaiting.len());
    if batch
        .iter()
        .filter(|at| !peer.awaiting.contains(at))
        .count()
        > room
    {
        // Not a dead end. `BATCH_PATIENCE` was read in `follow_up` and nowhere
        // else, so returning nothing here left a peer that had filled the set
        // to its ceiling in a state the node never left: the patience was
        // never evaluated and the chain was never asked for again. Its sibling
        // `request_announced` has always ended this way; this one did not.
        return follow_up(chain, peer, now);
    }
    // Read before the heights go in: see [`PeerState::asked_at`].
    let starts_a_batch = prompted || peer.awaiting.is_empty();
    peer.awaiting.extend(batch.iter().copied());
    if !prompted {
        // Nobody asked for this, so the heights in it are the peer's to
        // choose and the blocks that follow pay the price of a push.
        peer.offered.extend(batch.iter().copied());
    }
    if starts_a_batch {
        peer.asked_at = now;
    }
    Reaction::reply(vec![Message::GetBlocks(batch)])
}

/// Asks for the blocks among `ids` this node does not have.
///
/// For blocks a peer announced, which arrive with the height they sit at.
fn request_announced(
    chain: &ChainStore,
    peer: &mut PeerState,
    ids: &[Located],
    now: u64,
) -> Reaction {
    // Spent down per height rather than read once. Asked once, this admitted
    // every new height in the announcement as long as there was room for a
    // single one, so a set with one place left took a hundred and twenty eight
    // more: `MAX_AWAITING` named 512 and the set held 639. A height already
    // outstanding costs nothing, because asking again for it grows nothing.
    let mut room = MAX_AWAITING.saturating_sub(peer.awaiting.len());
    // **No height bound here, and this paragraph used to say there was one.**
    // It described a ceiling drawn against what the peer claimed at the
    // handshake, with a batch's worth of slack and a floor underneath. That
    // bound was written, tried twice and taken out again: drawn against this
    // node's own tip it stops a node catching up at all, because a node behind
    // the chain is *told* it is behind by an announcement from far ahead of
    // it; drawn against the peer's claimed height it broke the same fixture
    // for the same reason. What closed the defect was telling the two errands
    // apart instead, which is [`PeerState::offered`] below.
    //
    // The comment stayed after the bound went, so a reader checking whether an
    // announcement's heights are checked would have found a paragraph saying
    // they are and a filter that only counts room. They are not checked. What
    // stops an invented height buying a discount is that it is marked as
    // offered, and what stops it buying anything else is that a block at a
    // height this node cannot use is refused by `ChainStore::add_block`.
    let wanted: Vec<u64> = ids
        .iter()
        .filter(|entry| !chain.contains(&entry.id))
        .map(|entry| entry.height)
        .filter(|at| {
            if peer.awaiting.contains(at) {
                return true;
            }
            if room == 0 {
                return false;
            }
            room = room.saturating_sub(1);
            true
        })
        .take(MAX_REQUESTED)
        .collect();
    if wanted.is_empty() {
        return follow_up(chain, peer, now);
    }
    // An announcement is always the peer's own doing, so it starts a batch's
    // patience only where none is out: see [`PeerState::asked_at`].
    let starts_a_batch = peer.awaiting.is_empty();
    peer.awaiting.extend(wanted.iter().copied());
    // Written down as offered, so that the ask this is about to send is not
    // mistaken later for one this node went looking for.
    peer.offered.extend(wanted.iter().copied());
    if starts_a_batch {
        peer.asked_at = now;
    }
    Reaction::reply(vec![Message::GetBlocks(wanted)])
}

/// Once a batch has landed, asks for the next one if this node is still behind.
///
/// This is what drives a sync forward: each answer produces the next question,
/// and the questions stop when the node has caught up.
///
/// The one exception is a batch that never arrives. A peer answering
/// everything else while quietly never sending the blocks it was asked for
/// looks perfectly healthy and stalls the sync all the same, so an outstanding
/// batch is abandoned after [`BATCH_PATIENCE`] and the question asked again.
/// That half needs a clock rather than an answer, and [`tick`] is what runs it
/// when no answer comes.
fn follow_up(chain: &ChainStore, peer: &mut PeerState, now: u64) -> Reaction {
    give_up_on_a_stalled_batch(peer, now);
    // Asking now would bring back a block this node's clock still refuses.
    // See [`PeerState::clock_allows_at`].
    if let Some(at) = peer.clock_allows_at {
        if now < at {
            return Reaction::idle();
        }
        peer.clock_allows_at = None;
    }
    if peer.awaiting.is_empty() && peer.total_work > chain.total_work() {
        let now_work = chain.total_work();
        // The discount only for a peer whose last round moved this node's
        // chain. `total_work` above is the peer's word and gates the asking;
        // this is this node's own and gates the price.
        peer.chain_asked = peer.work_when_asked.is_none_or(|before| now_work > before);
        peer.work_when_asked = Some(now_work);
        return Reaction::reply(vec![Message::GetChain {
            locator: chain.locator(),
        }]);
    }
    Reaction::idle()
}

/// Writes down that this node asked `peer` for its chain from outside this
/// layer, so the `Chain` that answers is taken as an answer.
///
/// By the same rule `follow_up` keeps: the discount is for a peer asked for
/// the first time or whose last round moved this node's chain, so a question
/// the node repeats while nothing arrives, which the probation does every half
/// minute, does not buy a peer a batch at a unit a block each time. A mark
/// already standing is kept, so a greeting's question still outstanding is not
/// unmarked by one put from outside after it.
pub fn asked_for_the_chain(chain: &ChainStore, peer: &mut PeerState) {
    let now_work = chain.total_work();
    let earned = peer.work_when_asked.is_none_or(|before| now_work > before);
    peer.chain_asked = peer.chain_asked || earned;
    peer.work_when_asked = Some(now_work);
}

/// Abandons the outstanding batch once [`BATCH_PATIENCE`] has passed without a
/// block of it arriving, and says whether it did.
///
/// A clock that went back says nothing about how long the batch has been
/// out, so the wait starts again from the present rather than reading nought
/// until the clock climbs back past the ask. The chooser pulls every moment it
/// holds to the present for the same reason, and the probation restarts its
/// wait; this one did neither, so a step back of an hour added an hour to the
/// sixty seconds a quiet peer was given.
fn give_up_on_a_stalled_batch(peer: &mut PeerState, now: u64) -> bool {
    peer.asked_at = peer.asked_at.min(now);
    if peer.awaiting.is_empty() || now.saturating_sub(peer.asked_at) < BATCH_PATIENCE {
        return false;
    }
    peer.awaiting.clear();
    peer.offered.clear();
    true
}

/// What the passing of time alone owes one peer: a batch past its patience
/// given up on and the chain asked for again, and the chain asked for once
/// the clock allows a block it refused.
///
/// Run after every message this layer answers, and by the connection's loop
/// whenever a read comes back with nothing to read. The patience used to be
/// read only where a `Chain`, an `Announce` or a `Block` arrived, so a peer
/// that had answered everything it was asked and went on talking about
/// anything else, or said nothing at all, held this node mid batch until its
/// next announcement: a block interval away, whatever the patience said.
pub fn tick(chain: &ChainStore, peer: &mut PeerState, now: u64) -> Reaction {
    let gave_up = give_up_on_a_stalled_batch(peer, now);
    let allowed = peer.clock_allows_at.is_some_and(|at| now >= at);
    if gave_up || allowed {
        return follow_up(chain, peer, now);
    }
    Reaction::idle()
}

/// Whether a block whose parent this node does not hold is one it can never
/// hold, rather than one it has merely not caught up to.
///
/// The floor is the lowest height this node holds anything at, which is zero
/// for a node that read its chain and the height it was handed on for a node
/// that joined. A block at or below that floor needs a parent under it, and
/// the only blocks such a node can ever apply are ones building on what it
/// already has, so nothing will ever put that parent within reach.
///
/// Conservative on purpose. A block above the floor whose parent is missing
/// may still be part of a branch arriving bottom up, and calling that
/// unreachable would turn an ordinary sync into an alarm.
fn below_everything_held(chain: &ChainStore, height: u64) -> bool {
    chain.branch_start().is_some_and(|floor| height <= floor)
}

// The last two arms answer the same way for opposite reasons, and collapsing
// them would bury which is which.
#[allow(clippy::match_same_arms)]
fn on_block(chain: &mut ChainStore, peer: &mut PeerState, block: Block, now: u64) -> Reaction {
    let id = block.id();
    let height = block.header.height;
    let claimed = block.header.total_work;
    // A block of the batch arriving is the batch still coming. See
    // [`PeerState::asked_at`].
    if peer.awaiting.remove(&height) {
        peer.asked_at = now;
    }
    peer.offered.remove(&height);
    // Whether a body is already held under this identifier, in which case the
    // one this peer sent is not the one kept.
    let held_before = chain.block(&id).is_some();

    match chain.add_block(block, now) {
        Ok(accepted @ (Accepted::Extended | Accepted::Reorganised { .. })) => {
            let mut reaction = follow_up(chain, peer, now);
            reaction.applied = Some(accepted);
            reaction.broadcast.push(Located::new(height, id));
            reaction
        }
        Ok(Accepted::SideBranch) => {
            let mut reaction = follow_up(chain, peer, now);
            if !held_before {
                reaction.held_aside = Some(id);
            }
            reaction
        }
        Ok(Accepted::Duplicate) => follow_up(chain, peer, now),
        // Missing history rather than a bad peer: the block is fine, this node
        // simply has not caught up to where it hangs. Asking again from a fresh
        // locator resolves it.
        //
        // Asked of this peer because this peer sent it. A block claiming more
        // work than this node's whole chain says the peer that delivered it is
        // ahead, whatever it said when it introduced itself, and the greeting
        // used to be the only figure `follow_up` read. Every connection a node
        // at the tip keeps was greeted at equal work, so a missed announcement,
        // a tie at one height settled the other way, or a block refused for
        // its timestamp left the next block hanging on a parent nobody would
        // ever name again. The claim is the peer's word, as its greeting was,
        // and the price of the batch that answers is kept by
        // [`PeerState::work_when_asked`] rather than by it.
        //
        // Unless it hangs below everything this node holds, which is not
        // history it is missing but history it can never have. Nothing is held
        // against the peer there either; the difference is only that waiting
        // will not fix it, and that used to go unrecorded. Nor is the chain
        // asked for there: its answer would be the same branch, refused again.
        Err(ChainError::UnknownParent(_) | ChainError::NotGenesis) => {
            let out_of_reach = below_everything_held(chain, height);
            if !out_of_reach {
                peer.total_work = peer.total_work.max(claimed);
            }
            let mut reaction = follow_up(chain, peer, now);
            if out_of_reach {
                reaction.unreachable = Some(height);
            }
            reaction
        }
        // The peer did nothing wrong and this node cannot judge what it sent.
        // Named rather than counted against the peer, and the node stops.
        Err(error) if error.outdated().is_some() => Reaction {
            outdated: error.outdated(),
            ..Reaction::idle()
        },
        // A branch this node cannot reach is not a peer's fault. It means this
        // node is somewhere it cannot get back from, which is what happens to
        // one that was handed a chain and later meets the real one. Dropping
        // the messenger there is the worst possible answer: it keeps the wrong
        // chain and cuts off the only party telling it so. Nothing is held
        // against the peer, and the block is simply not taken.
        //
        // Not taken, and now said: this is the one refusal that means the node
        // itself is in the wrong place, and it used to pass in silence.
        Err(ChainError::ForkTooDeep { .. } | ChainError::TooOld { .. }) => Reaction {
            unreachable: Some(height),
            ..Reaction::idle()
        },
        // A block written under rules this build does not have. The chain
        // stopped remembering these against the block, because an update
        // reverses them; this stops holding them against the peer, for the
        // same reason and with the same weight of argument. Without it an
        // un-updated node closed the connection and refused the host, which is
        // every peer that had updated, one message each.
        //
        // Counted where peers are counted, and nothing more is done about it
        // here: what a run of these from several peers means is a question
        // about this node, and this layer is not the one that can see it.
        Err(ChainError::InvalidBlock {
            source: BlockError::UnsupportedVersion(version),
            ..
        }) => Reaction {
            unjudged: Some(version),
            ..Reaction::idle()
        },
        // The other side of a rule change. The chain remembers the block,
        // because this build knows both numbers and no update reverses the
        // verdict, and the peer is disconnected without being refused: it is
        // somewhere else, not misbehaving. Counted nowhere, which is the point
        // of telling it apart from the arm above: a stranger writing a number
        // into a field must not be able to make this node report itself out of
        // date.
        Err(ChainError::InvalidBlock {
            source:
                BlockError::WrongVersion {
                    height,
                    found,
                    required,
                },
            ..
        }) => Reaction::close(DropReason::ForeignRules {
            height,
            found,
            required,
        }),
        // The same block, or a branch through it, offered again: by the next
        // node that has not updated, in the same good faith as the first. It
        // was answered as a block refused for a rule and fell to the last arm,
        // so the first messenger was let go and every one after it refused.
        Err(ChainError::KnownForeign {
            height,
            found,
            required,
            ..
        }) => Reaction::close(DropReason::ForeignRules {
            height,
            found,
            required,
        }),
        // This node's own store, not the block and not the peer. It is
        // reachable without anybody doing anything wrong: a heavier branch is
        // offered, this node rewinds its own to take it, the new branch fails,
        // and putting the old one back needs a body the log no longer holds.
        // What comes back says the tree lost a block it had recorded, which is
        // true and is about this machine.
        //
        // So the peer is disconnected and not refused. The chain is short and
        // this node knows it: the next peer it talks to offers the blocks
        // again, and they are applied to what it has. Banning the messenger
        // was the one response that made that slower.
        Err(ChainError::Corrupt) => Reaction::close(DropReason::OwnStore),
        // A block dated further ahead than this node's clock allows. The only
        // refusal here that the same node reverses by waiting, and the only
        // one two honest nodes can disagree about: a miner eight minutes fast,
        // on a network that allows ten, publishes a block valid to everybody
        // whose clock is right, and a node two minutes slow refuses it.
        //
        // It used to fall through to the arm below, so that node closed the
        // connection and refused the host for `REFUSAL_SECONDS`, which is ten
        // minutes to buy itself where it needed two to wait. Every peer that
        // offered the block got the same, so within seconds it had refused its
        // whole book and `dial_from_book` would not dial any of them back. It
        // eclipsed itself and charged it to peers that had done nothing.
        //
        // Nothing taken and nothing closed, rather than a drop reason that
        // does not count as misbehaviour. Closing would make this node dial
        // back, be offered the same block, and refuse it again, which is a
        // loop that costs both ends a connection each time round; and there is
        // nothing to end the connection for, since the peer is right and this
        // node is the one that has to wait.
        //
        // What brings the block back is this peer being asked for the chain
        // once the clock allows the block, and not before. This said "the
        // block is offered again by whoever announces the next one", and what
        // is offered is the next block, whose parent is this one: it asked
        // nothing of a peer greeted as an equal, and of any other it asked at
        // once, for an answer naming this block again, refused again.
        //
        // The block claims more work than this node holds, as a block above
        // the tip does, so it is counted as the peer being ahead: see the arm
        // for a missing parent.
        //
        // Said, though, because this is the only place in the node that can
        // see a clock is wrong. See [`Reaction::ahead_of_the_clock`].
        Err(ChainError::InvalidBlock {
            source: BlockError::TimestampTooFarAhead { timestamp, drift },
            ..
        }) => {
            peer.total_work = peer.total_work.max(claimed);
            let allowed = timestamp.saturating_sub(drift);
            peer.clock_allows_at = Some(peer.clock_allows_at.map_or(allowed, |at| at.max(allowed)));
            Reaction {
                ahead_of_the_clock: Some(timestamp.saturating_sub(now)),
                ..Reaction::idle()
            }
        }
        // A block below this one failed, not this one. It was held aside
        // unjudged, which is every block of a branch lighter than the one
        // followed, and this delivery made its branch the heaviest, so the
        // switch read its body and the body did not hold. An identifier is
        // taken over a header alone, so that body can be a copy another peer
        // sent ahead of the real block, and the peer here, which built on or
        // relayed the real one, is the last to blame for it.
        //
        // It used to be the one blamed: disconnected and its host refused,
        // while the sender of the body had been answered `SideBranch`. So the
        // failed block is named for the node to refuse whoever handed that
        // body in, unless the verdict is about this node rather than about
        // the body, and this peer is asked again for its chain, which is
        // where the real body is.
        //
        // Asked because the block it delivered made its branch the heaviest,
        // so it claims more work than this node's chain, and that is counted
        // as the peer being ahead: see the arm for a missing parent. Without
        // it only a peer greeted as ahead was asked, and every long-lived
        // connection of a node at the tip was greeted as an equal.
        Err(ChainError::InvalidBlock { id: failed, source }) if failed != id => {
            peer.total_work = peer.total_work.max(claimed);
            let mut reaction = follow_up(chain, peer, now);
            reaction.failed_below = dropped_for(&source, failed)
                .is_misbehaviour()
                .then_some(failed);
            reaction
        }
        Err(ChainError::InvalidBlock { source, .. }) => Reaction::close(dropped_for(&source, id)),
        Err(_) => Reaction::close(DropReason::BadBlock { id }),
    }
}

/// Why a peer is left whose block `id` was refused for `source`, among the
/// refusals nothing above answers otherwise.
///
/// Every one of them is the block's doing, and so the peer's, except one the
/// ledger documents as this node disagreeing with itself: the transition was
/// projected against this same state a moment before, and applying it found
/// a note somewhere else. No peer can cause that. It fell to `BadBlock` with
/// the rest, so if it ever fired this node would refuse every honest peer that
/// offered the chain, one message each. It is left the way this node's own
/// store is left: the connection closed, the host not refused.
fn dropped_for(source: &BlockError, id: Hash32) -> DropReason {
    match source {
        BlockError::NoteNotWhereProved => DropReason::OwnStore,
        _ => DropReason::BadBlock { id },
    }
}

/// What answering one message will cost, taken before it is spent.
///
/// What is counted is work this peer causes: what it asks for, and what it
/// sends that nobody asked it for. A block this node asked for is not charged,
/// because refusing to take delivery of what you requested is a way of never
/// finishing a sync. An unasked one is, because that is a stranger handing
/// this node work.
fn cost_of(message: &Message, peer: &PeerState) -> u32 {
    match message {
        // Priced by the locator, because the locator is what the work is.
        //
        // Every entry this node does not hold in memory is answered off the
        // disk: an index seek, a record read, a whole `Block::decode` and a
        // header hash, and the walk only stops when one of them matches, so a
        // locator of entries that match nothing costs one read each. A flat
        // price meant sixty four of those for the same eight units that buy
        // eight disk reads through `GetBlocks`, and the answer is twenty five
        // bytes, so nothing downstream ever noticed. Charged in the same
        // currency as those reads, so the two asks cost the same for the same
        // work.
        Message::GetChain { locator } => {
            let entries = u32::try_from(locator.len().min(MAX_LOCATOR)).unwrap_or(u32::MAX);
            COST_CHAIN.saturating_add(entries.saturating_mul(COST_PER_BLOCK_SERVED))
        }
        // The largest thing a peer can ask for, and the only one that is worth
        // more to it than it costs this node, so it is charged accordingly: a
        // peer joining gets through in a handful of windows and one asking
        // over and over gets nowhere.
        Message::GetJoin { .. } => COST_JOIN,
        // Priced by what it carries, for the reason every list here is priced
        // that way, and at the rate this file already fixed for the largest
        // things on the wire. [`BYTES_PER_UNIT`] says why five hundred and
        // twelve bytes is the unit: "the two largest answers a stranger can
        // draw cost the same per byte". A block arriving is the largest thing
        // a stranger can send, and it was the one message left at a flat
        // price: eight units for anything up to a hundred and twenty eight
        // kilobytes, which is sixteen kilobytes to the unit against five
        // hundred and twelve for the same bytes going out. Thirty two times
        // cheaper to push at this node than to draw from it.
        //
        // Measuring it means encoding it again, and that is a constant factor
        // on work already done: the decode that produced this block read every
        // one of those bytes off the wire first. What it buys is the one
        // number that says what arrived, where the ask cannot.
        //
        // A block this node asked for costs what its bytes cost and not the
        // floor under them, and it used to cost one unit whatever it weighed,
        // while `add_block` went on to validate it. What one unit still buys is
        // the answer that turned out to be worth having: once the block is on
        // the branch this node follows, `on_message` hands the rest back,
        // because a block on that branch carries the work its validation was
        // paid for with. A block a peer can make for nothing, under a parent
        // it invented or off to the side at the lowest difficulty there is,
        // is never on that branch and keeps its price.
        Message::Block(block) => {
            // The discount is for an answer to something this node went and
            // asked for, which is what catching up is. A block this node was
            // offered is charged the floor as well however the asking went,
            // and nothing is handed back, because being offered something and
            // then asking for it is not the same errand as going to look for
            // it.
            //
            // Measured on the whole message rather than on the block, since
            // the message is what reading it was charged for, so that the two
            // agree to the unit.
            let wire = what_the_wire_costs(message.encode().len());
            if asked_for(peer, block.header.height) {
                wire
            } else {
                COST_BLOCK.saturating_add(wire)
            }
        }
        // Priced by the inputs it presents and the outputs it creates, for the
        // reason every list here is priced by what it carries: what it carries
        // is what this node does with it, and here that is a note resolved and
        // a signature verified for each input, and a key off the curve for
        // each output, which the decode has already done by the time this is
        // asked.
        Message::Transaction(transfer) => {
            let presented = u32::try_from(transfer.inputs.len()).unwrap_or(u32::MAX);
            let created = u32::try_from(transfer.outputs.len()).unwrap_or(u32::MAX);
            presented
                .saturating_mul(COST_PER_INPUT)
                .saturating_add(created.saturating_mul(COST_PER_OUTPUT))
        }
        Message::GetBlocks(ids) => {
            let wanted = u32::try_from(ids.len().min(MAX_REQUESTED)).unwrap_or(u32::MAX);
            wanted.saturating_mul(COST_PER_BLOCK_SERVED)
        }
        Message::GetHeaders { count, .. } => {
            let wanted = u32::try_from((*count).min(MAX_HEADERS as u64)).unwrap_or(u32::MAX);
            wanted.saturating_mul(COST_PER_HEADER_SERVED)
        }
        Message::GetProofs(positions) => {
            let wanted = u32::try_from(positions.len().min(MAX_PROVEN)).unwrap_or(u32::MAX);
            wanted.saturating_mul(COST_PER_PLACE_PROVED)
        }
        // Paths offered back. Priced by what it carries, like the run of
        // headers above and the address list below it: what it carries is what
        // this node does with it, which here is a fold per path against the
        // cold set, taken while the chain is held.
        Message::Proofs(placed) => {
            let carried = u32::try_from(placed.len().min(MAX_PROVEN)).unwrap_or(u32::MAX);
            carried.saturating_mul(COST_PER_PLACE_TAKEN)
        }
        // Priced by what it carries, like the three below it. What this node
        // does with each identifier is a lookup in the block table, and the
        // block table is behind the chain lock. A flat price here meant a
        // stranger could hand over `MAX_ANNOUNCED` of those for what one of
        // them costs, and the only message in this table whose price said
        // nothing about its length was the one whose work happens under the
        // lock everything else in this node waits on.
        Message::Announce(ids) => {
            let carried = u32::try_from(ids.len().min(MAX_ANNOUNCED)).unwrap_or(u32::MAX);
            carried.saturating_mul(COST_PER_ANNOUNCED)
        }
        Message::GetPeers => {
            let carried = u32::try_from(MAX_SHARED_ADDRESSES).unwrap_or(u32::MAX);
            carried.saturating_mul(COST_PER_ADDRESS_SERVED)
        }
        // Priced by what it carries, because what it carries is what this node
        // does with it: every address is weighed, looked up and written into
        // the order the book keeps, under the book's lock.
        Message::Peers(addresses) => {
            let carried =
                u32::try_from(addresses.len().min(MAX_SHARED_ADDRESSES)).unwrap_or(u32::MAX);
            carried.saturating_mul(COST_PER_ADDRESS_LEARNED)
        }
        // A run of headers offered rather than asked for. Priced by what it
        // carries, like the address list above and for the same reason: what
        // it carries is what this node does with it, which here is a record
        // appended to a log for every header in the run.
        Message::Headers { headers, .. } => {
            let carried = u32::try_from(headers.len().min(MAX_HEADERS)).unwrap_or(u32::MAX);
            carried.saturating_mul(COST_PER_HEADER_TAKEN)
        }
        // Named rather than left to a default, which is what this table had:
        // `_ => COST_TRIVIAL` covered these six, so a message added later
        // would have been priced at one unit by nobody's decision. The
        // allowance's other table, `taken_before_the_allowance` in `node.rs`,
        // is exhaustive for exactly that reason and says so, and this is the
        // table the reason matters most for. `Chain` is the one worth reading:
        // it opens a catch-up, and its price came from the default rather
        // than from anybody weighing what a catch-up draws.
        //
        // The greeting pair never reaches here, since `on_message` answers
        // them first, and a keepalive costs what it carries, which is
        // nothing. A `Chain` is a count and a height, whatever it then asks
        // for being priced as the blocks arrive. A `JoinPart` is taken before
        // the allowance altogether, as a piece of an answer this node asked
        // one named peer for.
        Message::Hello(_)
        | Message::Welcome(_)
        | Message::Ping(_)
        | Message::Pong(_)
        | Message::Chain { .. }
        | Message::JoinPart { .. } => COST_TRIVIAL,
    }
}

/// Takes a block a peer was `charged` for, and hands the price back down to
/// one unit if it was an answer this node asked for and is now on the branch
/// this node follows. One held off that branch instead is written down as the
/// last this peer delivered there: see [`PeerState::aside`].
///
/// Handed back only for a block on that branch, which it cannot be without the
/// work its header claims at the difficulty this chain demands. Everything
/// else a peer answers an ask with costs it nothing to make: a block under a
/// parent it invented, or one hung off an old block claiming the lowest
/// difficulty there is, which is taken aside unvalidated. Handing those back
/// too would give every connection a batch of decodes for nothing, because the
/// first `GetChain` is asked on the handshake and its answer is a batch this
/// node asked for.
fn on_block_charged(
    chain: &mut ChainStore,
    peer: &mut PeerState,
    block: Block,
    charged: u32,
    now: u64,
) -> Reaction {
    let at = block.header.height;
    let id = block.id();
    let asked = asked_for(peer, at);
    let reaction = on_block(chain, peer, block, now);
    if asked && chain.id_at(at) == Some(id) {
        peer.hand_back(charged.saturating_sub(COST_TRIVIAL), now);
    }
    // Held, and not where the branch followed is: new here, or a body this
    // node already held from this peer or from another. Not a block hanging
    // on a parent nobody has sent yet, which is not held at all, and would
    // otherwise put what did arrive out of reach of the next round.
    if chain.block(&id).is_some() && chain.id_at(at) != Some(id) {
        peer.aside = Some(Located::new(at, id));
    }
    reaction
}

/// Whether a block arriving at `at` answers a question this node went and
/// asked, rather than one a peer offered it.
fn asked_for(peer: &PeerState, at: u64) -> bool {
    peer.awaiting.contains(&at) && !peer.offered.contains(&at)
}

/// Handles one message from one peer.
pub fn on_message(
    local: &mut Local<'_>,
    peer: &mut PeerState,
    message: Message,
    now: u64,
) -> Reaction {
    match &message {
        Message::Hello(theirs) => return greet(local, peer, *theirs, true),
        Message::Welcome(theirs) => return greet(local, peer, *theirs, false),
        _ => {}
    }

    if !peer.greeted {
        return Reaction::close(DropReason::Unannounced {
            kind: message.kind(),
        });
    }

    // A peer that has used its window is answered with silence rather than
    // closed. What it asked for is not wrong, there has only been a lot of it,
    // and it asks again a moment later against a fresh window.
    //
    // What reading the frame cost is already paid and counts toward this.
    let Some(charged) = peer.settle(cost_of(&message, peer), now) else {
        return Reaction::idle();
    };

    let mut reaction = answer(local, peer, message, charged, now);
    // Whatever the message was, and after it: a block of the batch arriving
    // at the last moment is still the batch arriving.
    if reaction.drop_peer.is_none() {
        let due = tick(local.chain, peer, now);
        reaction.reply.extend(due.reply);
    }
    reaction
}

/// What one message from an introduced peer that could afford it calls for.
///
/// `charged` is what the message cost the peer, which a block this node asked
/// for hands back once it is on the branch followed.
fn answer(
    local: &mut Local<'_>,
    peer: &mut PeerState,
    message: Message,
    charged: u32,
    now: u64,
) -> Reaction {
    match message {
        // A pong needs no answer, a second introduction was already refused
        // above, and a piece of a join answer belongs to whoever is collecting
        // one rather than here.
        Message::Pong(_) | Message::Hello(_) | Message::Welcome(_) | Message::JoinPart { .. } => {
            Reaction::idle()
        }
        // Named rather than folded, and named here rather than before this
        // layer, which is what makes the price above it something the peer
        // actually pays.
        Message::Proofs(placed) => Reaction {
            placed,
            ..Reaction::idle()
        },
        // Headers from before this node arrived. Named rather than taken, and
        // named here rather than earlier: this is where a peer has to have
        // introduced itself and to have an allowance left, and a run that
        // reached a disk before either was asked was a run any stranger could
        // hand this node.
        Message::Headers { from, headers } => Reaction {
            offered_headers: Some((from, headers)),
            ..Reaction::idle()
        },
        Message::Ping(nonce) => Reaction::reply(vec![Message::Pong(nonce)]),
        Message::GetChain { locator } => Reaction {
            locate: Some(locator),
            ..Reaction::idle()
        },
        Message::GetHeaders { from, count } => Reaction {
            headers: Some((from, count.min(MAX_HEADERS as u64))),
            ..Reaction::idle()
        },
        // Named rather than answered here, and capped here rather than
        // wherever the answer is built: what a peer asks for is the one number
        // in this exchange a peer chooses.
        Message::GetProofs(positions) => Reaction {
            prove: Some(positions.into_iter().take(MAX_PROVEN).collect()),
            ..Reaction::idle()
        },
        Message::Chain { from, count } => {
            // Taken whatever this answer comes to: see [`PeerState::aside`].
            let arrived = peer.aside.take();
            let start = past_what_arrived(local.chain, first_wanted(local.chain, from), arrived);
            let end = from.saturating_add(count);
            // Taken rather than read, so one `GetChain` pays for one answer
            // and a peer that sends five gets the price of a push for four.
            let prompted = std::mem::take(&mut peer.chain_asked);
            let have = local.chain.height().map_or(0, |tip| tip.saturating_add(1));
            // Nothing this node holds connects to a stretch that starts above
            // its tip, so none of it is asked for: see
            // [`Reaction::cannot_supply`]. Not the chain again either, which
            // would only bring the same answer back. A node with no chain of
            // its own has a chooser to ask somebody else, and is left to it.
            //
            // No chain of its own includes the first block a named network
            // pins, as at the handshake. Asking whether the chain was empty
            // counted a newcomer on a real network among the nodes further
            // behind than their peers keep, which follow a chain and cannot
            // be handed one, where it holds nothing and can be.
            if from > have && !local.chain.holds_nothing_of_its_own() {
                return Reaction {
                    cannot_supply: prompted.then_some(from),
                    ..Reaction::idle()
                };
            }
            if start >= end {
                follow_up(local.chain, peer, now)
            } else {
                request_range(
                    local.chain,
                    peer,
                    start,
                    end.saturating_sub(start),
                    now,
                    prompted,
                )
            }
        }
        Message::Announce(ids) => {
            let capped: Vec<Located> = ids.into_iter().take(MAX_ANNOUNCED).collect();
            request_announced(local.chain, peer, &capped, now)
        }
        // Named rather than answered here. A peer catching up asks for a run
        // of consecutive heights and applies them in the order they arrive,
        // since a block whose parent has not landed yet is dropped. Some of
        // those sit in memory and some on a disk, and answering the memory
        // ones here and the disk ones afterwards would deliver them out of
        // order: the tail of a batch first, refused, then the head. So the
        // whole batch is gathered in one place, in the order asked for.
        Message::GetBlocks(heights) => Reaction {
            fetch: heights.into_iter().take(MAX_REQUESTED).collect(),
            ..Reaction::idle()
        },
        Message::Block(block) => on_block_charged(local.chain, peer, *block, charged, now),
        // The clock decides which half of the book rotates into this answer,
        // so a peer asking twice does not hear the same names twice.
        // Both answers are megabytes, so building one runs after the chain is
        // let go of, and the cost is charged as though it were the largest
        // thing a peer can ask for, because it is.
        Message::GetJoin { what, part } => Reaction {
            join: Some((what, part)),
            ..Reaction::idle()
        },
        Message::GetPeers => Reaction {
            share_addresses: true,
            ..Reaction::idle()
        },
        // The last two arms say nothing for opposite reasons, and collapsing
        // them would bury which is which.
        #[allow(clippy::match_same_arms)]
        Message::Transaction(transfer) => {
            let id = transfer.id();
            match local.chain.accept_transfer(*transfer) {
                Ok(true) => Reaction {
                    relayed: vec![id],
                    ..Reaction::idle()
                },
                // Already held, or the pool is full. Neither says anything bad
                // about the peer.
                Ok(false) => Reaction::idle(),
                // A transfer this node cannot use is not proof of a bad peer:
                // it may simply be spending a note this node has already seen
                // spent on the branch it follows.
                Err(_) => Reaction::idle(),
            }
        }
        // Whoever sends this is choosing who the node opens a connection to,
        // which is why the list is weighed rather than written down. A
        // stranger naming `169.254.169.254` is not passing on a peer.
        Message::Peers(addresses) => {
            let learned = addresses
                .into_iter()
                .take(MAX_SHARED_ADDRESSES)
                .map(|PeerAddress(address)| address)
                .filter(|address| worth_hearing_about(address, peer.remote, peer.dialled))
                .collect();
            Reaction {
                learned,
                ..Reaction::idle()
            }
        }
    }
}

/// What an ask costs, which has to be what the ask makes this node do.
///
/// A `GetChain` is answered out of memory when it can be, and off the disk
/// when it cannot: an index seek, a record read, a whole `Block::decode` and a
/// header hash for every locator entry that matches nothing, and the walk
/// stops only when one matches. The price was flat, so sixty four of those
/// reads cost the same eight units that buy eight through `GetBlocks`, and the
/// answer is twenty five bytes either way, so nothing downstream could notice.
///
/// Measured here rather than over a socket. What the price does is decide how
/// many asks a window pays for, and that is arithmetic; counting answers on a
/// connection measures what the socket carried in the time the test waited,
/// which is a fact about the machine. A first attempt at this test did exactly
/// that and read 180 against 65 on one run and 52 against 79 on the next.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod what_an_ask_costs {
    use super::{
        a_window_has_turned, cost_of, what_the_wire_costs, PeerState, Window, ALLOWANCE,
        BYTES_PER_UNIT, COST_CHAIN, COST_JOIN, COST_PER_BLOCK_SERVED, COST_PER_HEADER_SERVED,
        COST_TRIVIAL, WINDOW_SECONDS,
    };
    use crate::message::{
        Message, PeerAddress, JOIN_PART_BYTES, MAX_HEADERS, MAX_REQUESTED, MAX_SHARED_ADDRESSES,
    };
    use cairn_chain::{Located, MAX_LOCATOR};
    use cairn_crypto::SecretKey;
    use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
    use cairn_ledger::note::{NetworkId, Note};
    use cairn_ledger::transaction::CoinbaseTransaction;
    use cairn_primitives::codec::Encode;
    use cairn_primitives::{Amount, Hash32};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// A block carrying `outputs` coinbase notes, so its size is chosen and
    /// nothing else about it matters: pricing never looks at whether a block
    /// is valid, which is the whole of why a peer can send one for nothing.
    ///
    /// The nonce carries the count, so that two of these are two blocks. An
    /// identifier is the hash of a header and this fixture leaves
    /// `transactions_root` at zero, so without it a block of one output and a
    /// block of four hundred have the same identifier and a test about telling
    /// them apart cannot.
    fn block_of(outputs: usize) -> Block {
        let owner = SecretKey::from_bytes(&[7; 32]).public_key();
        let value = Amount::from_pebbles(1).unwrap();
        Block {
            header: BlockHeader {
                version: BLOCK_VERSION,
                network: NetworkId::TESTNET,
                height: 1,
                previous: Hash32::ZERO,
                transactions_root: Hash32::ZERO,
                state_root: Hash32::ZERO,
                history: Hash32::ZERO,
                timestamp: 1_000,
                difficulty: 1,
                total_work: 0,
                nonce: outputs as u64,
            },
            coinbase: CoinbaseTransaction::new(
                1,
                (0..outputs).map(|_| Note::new(value, owner)).collect(),
            ),
            transfers: Vec::new(),
        }
    }

    /// When asking again is worth anything.
    ///
    /// The one thing about this accounting that anybody outside this layer
    /// reads: a node collecting a handover whose question went unanswered
    /// waits for the window to turn before asking again. Answering yes to
    /// every pair makes it ask straight back into a window already spent,
    /// which is the hammering the allowance exists to stop; answering yes only
    /// where the two are the same window makes it wait for ever. Nothing
    /// measured either.
    #[test]
    fn a_window_turns_when_the_clock_crosses_into_the_next_one() {
        let window = WINDOW_SECONDS;
        assert!(
            !a_window_has_turned(0, window - 1),
            "the same window, at both ends of it"
        );
        assert!(
            a_window_has_turned(window - 1, window),
            "one second later is the next window"
        );
        assert!(
            !a_window_has_turned(window, window * 2 - 1),
            "and the next window is a window too"
        );
        assert!(a_window_has_turned(0, window * 5), "several windows on");
        assert!(
            !a_window_has_turned(window * 5, 0),
            "a clock that went backwards has not turned a window"
        );
    }

    /// A window is worth keeping exactly while rolling it would change nothing.
    ///
    /// `current` is the one question a node asks a window from outside the
    /// accounting, and it asks it to decide whether to drop the record of an
    /// address that has gone. The two have to agree: a window `current` calls
    /// dead while `roll` would still add to its count loses a spend, and one
    /// it calls alive while `roll` would reset it is a record the node keeps
    /// for ever, which is the map growing without bound that the sweep
    /// exists to stop. Nothing measured either half.
    #[test]
    fn a_window_is_current_exactly_while_it_still_holds_its_count() {
        for begun in [0_u64, 7, WINDOW_SECONDS, 41, 12_345] {
            let mut window = Window::default();
            window.roll(begun);
            for now in [0_u64, 1, 9, 10, 11, 41, 49, 50, 12_345, 12_350] {
                let mut rolled = window;
                let turned = rolled.roll(now);
                assert_eq!(
                    window.current(now),
                    !turned,
                    "a window begun at {begun} answered {} about {now}, where rolling it to \
                     {now} {} the count",
                    window.current(now),
                    if turned { "threw away" } else { "kept" }
                );
            }
        }
    }

    fn asks_a_window_pays_for(message: &Message) -> u32 {
        let mut peer = PeerState::new(None);
        let cost = cost_of(message, &peer);
        // Nothing costs less than the cheapest price, so a window that pays
        // for more asks than this never runs out, and waiting for it would
        // hang the suite rather than fail it.
        let most = ALLOWANCE / COST_TRIVIAL;
        let mut asks = 0u32;
        while peer.afford(cost, 0) {
            asks = asks.saturating_add(1);
            assert!(asks <= most, "a window paid for more asks than it holds");
        }
        asks
    }

    #[test]
    fn a_locator_costs_what_its_entries_cost() {
        let empty = Message::GetChain {
            locator: Vec::new(),
        };
        let full = Message::GetChain {
            locator: (0..MAX_LOCATOR)
                .map(|entry| {
                    Located::new(
                        u64::try_from(entry).unwrap_or(0),
                        Hash32::from_bytes([u8::try_from(entry % 256).unwrap_or(0); 32]),
                    )
                })
                .collect(),
        };

        let carrying_nothing = asks_a_window_pays_for(&empty);
        let carrying_a_full_one = asks_a_window_pays_for(&full);

        assert_eq!(
            carrying_nothing,
            ALLOWANCE / COST_CHAIN,
            "an ask that reaches no disk costs the ask and nothing else"
        );
        let each = COST_CHAIN + u32::try_from(MAX_LOCATOR).unwrap_or(0) * COST_PER_BLOCK_SERVED;
        assert_eq!(
            carrying_a_full_one,
            ALLOWANCE / each,
            "and one carrying {MAX_LOCATOR} entries costs {each}, which is the ask plus one \
             block read for each of them, in the same currency `GetBlocks` pays in"
        );
        // Both numbers above are worked out from the same constants the code
        // uses, so both hold at any price including none: set
        // `COST_PER_BLOCK_SERVED` to zero, which is the flat price this test
        // is named for, and they go on passing. The claim is that entries
        // cost, and the claim is a comparison.
        assert!(
            carrying_a_full_one < carrying_nothing,
            "a window pays for {carrying_a_full_one} asks carrying {MAX_LOCATOR} entries and \
             {carrying_nothing} carrying none, so the entries are free and the flat price \
             this test exists to refuse is back"
        );
    }

    /// What an announcement can arm, which is the escape hatch beside the
    /// price above and not a separate question.
    ///
    /// A block a peer announced is charged as an answer to something already
    /// asked for, and `awaiting` is what says it was asked for. That set is
    /// filled from the heights a peer wrote into an announcement, so a peer
    /// that announces first writes its own discount: a hundred and twenty
    /// eight invented identifiers bought a hundred and twenty eight
    /// full-sized blocks at a unit each, which is four times cheaper than the
    /// flat price the change above exists to abolish.
    ///
    /// Two things close it and both are needed. A height has to be one this
    /// node could put a block at, and the block that arrives has to be the one
    /// that was announced.
    #[test]
    fn an_announcement_does_not_write_its_own_discount() {
        let block = block_of(400);
        let at = block.header.height;
        let bytes = Message::Block(Box::new(block.clone())).encode().len();

        // Catching up: this node walked to the height itself and went and
        // asked. The peer answering is doing it a favour.
        let mut looking = PeerState::new(None);
        looking.awaiting.insert(at);
        let a_favour = cost_of(&Message::Block(Box::new(block.clone())), &looking);
        assert_eq!(
            a_favour,
            what_the_wire_costs(bytes),
            "an answer to an ask this node made is charged its bytes and no floor under \
             them; the rest of the favour is handed back once it lands, which \
             `a_block_asked_for_is_discounted_only_once_it_is_on_the_branch` holds"
        );

        // Offered: the same height, in the same set, reached because the peer
        // announced it. The ask looks identical from here and the errand is
        // the other one.
        let mut offered = PeerState::new(None);
        offered.awaiting.insert(at);
        offered.offered.insert(at);
        let a_push = cost_of(&Message::Block(Box::new(block)), &offered);

        assert!(
            a_push > a_favour,
            "a peer that announced first was charged {a_push} for {bytes} bytes against the \
             {a_favour} an answer costs, so announcing is a way of setting your own price. \
             The heights in an announcement are the peer's to choose"
        );
        assert_eq!(
            a_push,
            what_the_wire_costs(bytes).saturating_add(8),
            "and it is charged what its bytes cost, like any block nobody asked for"
        );
    }

    /// What a block costs the peer that sends it, against what the same bytes
    /// cost the node that serves them.
    ///
    /// `BYTES_PER_UNIT` says why five hundred and twelve bytes is the unit:
    /// "the two largest answers a stranger can draw cost the same per byte".
    /// A block arriving is the largest thing a stranger can send, and it was
    /// the one message priced flat, at eight units for anything up to the
    /// block ceiling. That is sixteen kilobytes to the unit against five
    /// hundred and twelve for the same bytes going out: thirty two times
    /// cheaper to push at this node than to draw from it.
    #[test]
    fn a_block_sent_costs_what_its_bytes_cost() {
        let small = block_of(1);
        let large = block_of(400);
        let small_bytes = small.encode().len();
        let large_bytes = large.encode().len();
        assert!(
            large_bytes > small_bytes * 8,
            "this test needs two blocks of very different sizes, and they are \
             {small_bytes} and {large_bytes}"
        );

        let sending_small = cost_of(&Message::Block(Box::new(small)), &PeerState::new(None));
        let sending_large = cost_of(&Message::Block(Box::new(large)), &PeerState::new(None));

        assert!(
            sending_large > sending_small,
            "a block of {large_bytes} bytes costs {sending_large} to send at this node and \
             one of {small_bytes} costs {sending_small}, so the bytes are free and a peer \
             pushes a block for what a peer pushes an empty one"
        );
        // And at the rate the file already fixed, rather than at some other
        // one: what the bytes cost going in is what they cost going out.
        assert_eq!(
            sending_large - sending_small,
            what_the_wire_costs(large_bytes) - what_the_wire_costs(small_bytes),
            "the difference between them is the difference in what the wire costs, which is \
             the rate `BYTES_PER_UNIT` fixes for everything else this size"
        );
    }

    /// How much of this node a peer can draw off it in one window.
    ///
    /// Bytes rather than seeks, because the seek is what a header costs and
    /// the megabyte is what a block costs, and one price was covering both.
    fn bytes_a_window_serves(block_bytes: usize) -> usize {
        let mut peer = PeerState::new(None);
        let ask = Message::GetBlocks((0..MAX_REQUESTED as u64).collect());
        let mut served = 0usize;
        // The ask is charged first, then each block as it goes out, which is
        // the order the node serves in.
        //
        // Bounded by what the cheapest ask costs: a window that pays for more
        // than that never runs out, and waiting for it would hang the suite
        // rather than fail it.
        let most = ALLOWANCE / COST_TRIVIAL;
        let mut asks = 0u32;
        while peer.afford(cost_of(&ask, &peer), 0) {
            asks = asks.saturating_add(1);
            assert!(asks <= most, "a window paid for more asks than it holds");
            for _ in 0..MAX_REQUESTED {
                if !peer.afford_serving(block_bytes, 0) {
                    return served;
                }
                served = served.saturating_add(block_bytes);
            }
        }
        served
    }

    /// The largest answer a stranger can draw off this node, and the second
    /// largest, cost the same per byte.
    #[test]
    fn the_two_largest_answers_cost_the_same_per_byte() {
        let per_unit_of_a_join = JOIN_PART_BYTES / usize::try_from(COST_JOIN).unwrap_or(1);
        assert_eq!(
            per_unit_of_a_join, BYTES_PER_UNIT,
            "a join part is {JOIN_PART_BYTES} bytes for {COST_JOIN} units, which is the \
             rate blocks are charged at"
        );
        assert_eq!(what_the_wire_costs(0), 0, "nothing served costs nothing");
        assert_eq!(
            what_the_wire_costs(1),
            1,
            "and anything at all costs a unit, so a chain of empty blocks is \
             priced by its seeks"
        );
        assert_eq!(what_the_wire_costs(BYTES_PER_UNIT), 1);
        assert_eq!(what_the_wire_costs(BYTES_PER_UNIT + 1), 2);
    }

    /// A window buys about four megabytes of blocks whatever the blocks weigh,
    /// where it used to buy four megabytes of small ones and a gigabyte of
    /// large ones.
    #[test]
    fn a_window_buys_the_same_megabytes_whatever_a_block_weighs() {
        // Read off the rules rather than written out. This said
        // "`ConsensusParams::mainnet` and `testnet` both cap a block here"
        // beside a literal, and there is no `mainnet`: `for_network` answers
        // `None` for it, because the network is not made yet. So the sentence
        // named a thing that does not exist to vouch for a number that was a
        // copy of one that does.
        let at_the_consensus_limit =
            cairn_ledger::validation::ConsensusParams::testnet().max_block_bytes;
        let drawn = bytes_a_window_serves(at_the_consensus_limit);
        let ceiling = usize::try_from(ALLOWANCE).unwrap_or(0) * BYTES_PER_UNIT;
        assert!(
            drawn <= ceiling,
            "one address drew {drawn} bytes of blocks out of one window, where the \
             allowance is worth {ceiling}. At {COST_PER_BLOCK_SERVED} a block and \
             nothing for the wire this was {} bytes, which is a gigabyte per ten \
             seconds bought with about sixty six kilobytes of asking",
            usize::try_from(ALLOWANCE).unwrap_or(0) * at_the_consensus_limit,
        );
        assert!(
            drawn * 2 > ceiling,
            "and it is not so tight that a peer syncing a full chain cannot use it: \
             {drawn} bytes against a window worth {ceiling}"
        );

        // An honest sync on the chain this software actually runs is nowhere
        // near it: an empty block is a few hundred bytes, so the seek is still
        // what a block costs and the window buys thousands of them.
        let empty = 200;
        let blocks = bytes_a_window_serves(empty) / empty;
        assert!(
            blocks >= 4_000,
            "an empty-block sync gets {blocks} blocks a window, and two nodes over a \
             loopback socket were measured at a hundred a second, which is a thousand \
             a window"
        );
    }

    /// Handing this node addresses costs what being handed them costs.
    ///
    /// A `Peers` message makes this node weigh, look up and write down every
    /// address in it, under the book's lock, and it was one unit for all sixty
    /// four of them: a window bought half a million insertions.
    #[test]
    fn addresses_cost_the_same_to_take_in_as_to_hand_out() {
        let full: Vec<PeerAddress> = (0..MAX_SHARED_ADDRESSES)
            .map(|step| {
                PeerAddress(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        203,
                        0,
                        113,
                        u8::try_from(step % 256).unwrap_or(0),
                    )),
                    9_000,
                ))
            })
            .collect();
        let handed_over = asks_a_window_pays_for(&Message::Peers(full));
        let asked_for = asks_a_window_pays_for(&Message::GetPeers);
        assert_eq!(
            handed_over,
            asked_for,
            "a window takes in {handed_over} full address lists and hands out \
             {asked_for}. At one unit a message it took in {ALLOWANCE} of them, which \
             is {} addresses written into the book",
            ALLOWANCE.saturating_mul(u32::try_from(MAX_SHARED_ADDRESSES).unwrap_or(0)),
        );

        // And a shorter list costs less, so a peer answering with what it has
        // is not charged for what it has not.
        let one = asks_a_window_pays_for(&Message::Peers(vec![PeerAddress(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            9_000,
        ))]));
        assert_eq!(one, ALLOWANCE);
    }

    /// Per unit, a block used to buy seven hundred times what a header buys.
    #[test]
    fn a_unit_buys_about_as_much_wire_through_either_ask() {
        let header_bytes = 182;
        let a_unit_of_headers = header_bytes / usize::try_from(COST_PER_HEADER_SERVED).unwrap_or(1);
        let a_unit_of_blocks = BYTES_PER_UNIT;
        let ratio = a_unit_of_blocks / a_unit_of_headers.max(1);
        assert!(
            ratio <= 4,
            "a unit buys {a_unit_of_blocks} bytes through `GetBlocks` and \
             {a_unit_of_headers} through `GetHeaders`, a factor of {ratio}. It was \
             {} before the wire was priced, and a window of {MAX_HEADERS}-header asks \
             is the honest comparison",
            (128 * 1024) / header_bytes,
        );
    }
}

/// What a refused block says about the peer that delivered it.
#[cfg(test)]
mod refused_blocks {
    use super::{dropped_for, BlockError, DropReason, Hash32};

    /// A block refused for a verdict about this node is not held against the
    /// peer that delivered it, and every other refusal still is.
    ///
    /// Nothing asked this, so a node that refused every honest peer offering
    /// the chain for a disagreement inside its own ledger passed. No known
    /// block reaches that verdict, which is why it is asked of the mapping.
    #[test]
    fn a_verdict_about_this_node_is_not_held_against_the_peer() {
        let id = Hash32::from_bytes([7; 32]);
        let own = dropped_for(&BlockError::NoteNotWhereProved, id);
        assert!(
            !own.is_misbehaviour(),
            "a verdict the ledger calls this node disagreeing with itself refused the peer"
        );
        assert_eq!(own, DropReason::OwnStore);
        let theirs = dropped_for(
            &BlockError::StateRootMismatch {
                expected: Hash32::ZERO,
                found: id,
            },
            id,
        );
        assert_eq!(
            theirs,
            DropReason::BadBlock { id },
            "a block that is wrong on its own account stopped being the peer's doing"
        );
    }
}

/// What reading a frame costs, and what the message in it then costs on top.
///
/// Counted in units and in keys rather than timed. What a price decides is how
/// much of a given kind of work a window pays for, which is arithmetic; the
/// processor time behind each key was measured once, beside a signature check
/// on the same machine, and is written where the prices are.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod what_a_frame_costs {
    use super::{
        on_message, what_the_wire_costs, Local, Message, PeerState, ALLOWANCE, COST_TRIVIAL,
    };
    use crate::message::{Joining, Keeps};
    use cairn_chain::ChainStore;
    use cairn_crypto::SecretKey;
    use cairn_ledger::block::Block;
    use cairn_ledger::note::{Note, NoteId};
    use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
    use cairn_ledger::validation::{assemble_block, mine_block, ConsensusParams};
    use cairn_ledger::LedgerState;
    use cairn_primitives::codec::Encode;
    use cairn_primitives::{Amount, Hash32};

    const NOW: u64 = 2_000_000_000;

    fn params() -> ConsensusParams {
        ConsensusParams::testnet()
    }

    fn greeted() -> PeerState {
        PeerState {
            greeted: true,
            ..PeerState::default()
        }
    }

    fn local(chain: &mut ChainStore) -> Local<'_> {
        Local {
            chain,
            keeps: Keeps::default(),
            listen: 0,
            nonce: 1,
        }
    }

    /// What `message` took out of a greeted peer's window, handed straight to
    /// the layer that prices it.
    fn charged(chain: &mut ChainStore, peer: &mut PeerState, message: Message) -> u32 {
        let before = peer.spent;
        on_message(&mut local(chain), peer, message, NOW);
        peer.spent - before
    }

    /// A transfer spending `inputs` notes into `outputs` new ones, every owner
    /// a real key, so decoding it does the whole of its work.
    fn transfer(inputs: u32, outputs: u32) -> Transfer {
        let spending = (0..inputs)
            .map(|index| Input::hot(NoteId::new(Hash32::from_bytes([3; 32]), index)))
            .collect();
        let created = (0..outputs)
            .map(|index| {
                let mut seed = [9u8; 32];
                seed[..4].copy_from_slice(&index.to_le_bytes());
                Note::new(
                    Amount::from_pebbles(1).unwrap(),
                    SecretKey::from_bytes(&seed).public_key(),
                )
            })
            .collect();
        Transfer::new(spending, created)
    }

    /// The first block of a chain, mined for real so it lands, and paying as
    /// many owners as the rules let a coinbase pay so it weighs more than one
    /// unit's worth of bytes: a block that weighs one unit costs one unit
    /// whether or not anything is handed back, and could not tell the two
    /// apart.
    fn first_block() -> Block {
        let params = params();
        let state = LedgerState::new();
        let height = state.next_height().unwrap();
        let owners = u64::try_from(params.max_coinbase_outputs).unwrap();
        let one = Amount::from_pebbles(1).unwrap();
        let rest = Amount::from_pebbles(params.initial_reward.as_pebbles() - (owners - 1)).unwrap();
        let outputs = (0..owners)
            .map(|index| {
                let mut seed = [1u8; 32];
                seed[..8].copy_from_slice(&index.to_le_bytes());
                let owner = SecretKey::from_bytes(&seed).public_key();
                Note::new(if index == 0 { rest } else { one }, owner)
            })
            .collect();
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block = assemble_block(&state, coinbase, Vec::new(), &params, 1_600, height).unwrap();
        mine_block(block, 1 << 22).unwrap()
    }

    /// A transfer is priced by the keys its decode checks as well as by the
    /// signatures its inputs carry.
    ///
    /// Every output is an owner's key, decompressed off the curve and checked
    /// for its subgroup while the frame is decoded, and that costs about what
    /// verifying a signature does. The price counted the inputs alone, so a
    /// transfer of one input and two hundred and fifty six outputs was charged
    /// what an ordinary payment is: a unit spent on the widest shape bought a
    /// hundred and twenty eight times the keys a unit spent on a payment did,
    /// and a greeted peer that sent nothing else bought about twenty five
    /// seconds of this node's processor a window. Nothing compared the two
    /// shapes, so a price that ignored the outputs passed.
    #[test]
    fn a_unit_buys_about_the_same_keys_whatever_shape_a_transfer_is() {
        let mut chain = ChainStore::new(params());
        let most = u32::try_from(params().max_outputs_per_transfer).unwrap();
        let ordinary = transfer(1, 2);
        let widest = transfer(1, most);
        let ordinary_keys = u32::try_from(ordinary.outputs.len()).unwrap();
        let widest_keys = u32::try_from(widest.outputs.len()).unwrap();

        let ordinary_price = charged(
            &mut chain,
            &mut greeted(),
            Message::Transaction(Box::new(ordinary)),
        );
        let widest_price = charged(
            &mut chain,
            &mut greeted(),
            Message::Transaction(Box::new(widest)),
        );

        // Keys a unit buys, cross multiplied: the widest shape may buy up to
        // four times what a payment does, which is slack and not a figure.
        assert!(
            widest_keys * ordinary_price <= 4 * ordinary_keys * widest_price,
            "a transfer of {widest_keys} outputs was charged {widest_price} and an ordinary \
             payment of {ordinary_keys} was charged {ordinary_price}, so a unit spent on the \
             widest shape buys {} times the keys off the curve a unit spent on a payment \
             does, and the widest shape is the cheapest way to make this node compute",
            (widest_keys * ordinary_price) / (ordinary_keys * widest_price).max(1),
        );
        // And the widest is still a transfer a window pays for.
        assert!(widest_price < ALLOWANCE);
    }

    /// A block this node asked for pays for its bytes unless it lands on the
    /// branch this node follows, and then it pays one unit.
    ///
    /// The discount for answering an ask was one unit whatever the block
    /// weighed, and `add_block` then took it and, for one it could place,
    /// validated it. The first `GetChain` goes out on the handshake to any
    /// peer claiming more work, so its answer is a batch this node asked for,
    /// and a peer could fill that batch with blocks under parents it
    /// invented: a hundred and twenty eight frames of note owners, each
    /// decoded and never applied, at a unit apiece. Nothing tried an asked-for
    /// block that did not land, so a discount that asked nothing of the answer
    /// passed.
    #[test]
    fn a_block_asked_for_is_discounted_only_once_it_is_on_the_branch() {
        let mut chain = ChainStore::new(params());

        // One under a parent nobody has, which is free to make.
        let mut invented = first_block();
        invented.header.height = 5;
        invented.header.previous = Hash32::from_bytes([7; 32]);
        // The lowest difficulty there is, which any identifier meets, so what
        // stops it is the parent.
        invented.header.difficulty = 1;
        let invented_bytes = Message::Block(Box::new(invented.clone())).encode().len();
        assert!(
            what_the_wire_costs(invented_bytes) > COST_TRIVIAL,
            "the fixture's block has to weigh more than a unit for its price to say anything"
        );
        let mut asked = greeted();
        asked.awaiting.insert(5);
        let paid = charged(&mut chain, &mut asked, Message::Block(Box::new(invented)));
        assert_eq!(
            paid,
            what_the_wire_costs(invented_bytes),
            "a block this node asked for, that it could not place, was charged {paid} for \
             {invented_bytes} bytes: the discount went to an answer anybody can make, and \
             a batch of them is a batch of decodes for next to nothing"
        );

        // And one that lands, which carries its work.
        let real = first_block();
        let real_bytes = Message::Block(Box::new(real.clone())).encode().len();
        assert!(what_the_wire_costs(real_bytes) > COST_TRIVIAL);
        let mut asked = greeted();
        asked.awaiting.insert(0);
        let paid = charged(&mut chain, &mut asked, Message::Block(Box::new(real)));
        assert_eq!(chain.height(), Some(0), "the fixture's block did not land");
        assert_eq!(
            paid, COST_TRIVIAL,
            "a block this node asked for, that landed on its branch, was charged {paid}: an \
             honest catch-up pays for its bytes at every block"
        );
        // And what was handed back is back in the window, not only in the
        // count kept for reading: the window is what decides the next ask.
        let mut left = 0u32;
        while asked.afford(1, NOW) {
            left += 1;
        }
        assert_eq!(
            left,
            ALLOWANCE - COST_TRIVIAL,
            "the window a landed block was handed back to has {left} units left"
        );

        // The same block announced first and then asked for lands the same way
        // and is not an answer: nothing is handed back to a push.
        let mut chain = ChainStore::new(params());
        let real = first_block();
        let pushed = super::COST_BLOCK + what_the_wire_costs(real_bytes);
        let mut offered = greeted();
        offered.awaiting.insert(0);
        offered.offered.insert(0);
        let paid = charged(&mut chain, &mut offered, Message::Block(Box::new(real)));
        assert_eq!(chain.height(), Some(0), "the fixture's block did not land");
        assert_eq!(
            paid, pushed,
            "a block this node was offered, that landed, was handed back to {paid}: an \
             announcement wrote its own discount"
        );
    }

    /// A frame is charged by its size before it is read, and that charge is
    /// part of the price of what was in it rather than a second price.
    ///
    /// New with the charge, so what it holds is that the charge is what the
    /// document says it is: one unit per `BYTES_PER_UNIT` bytes rounded up, a
    /// message paying the larger of that and its own price, and nothing for a
    /// frame the window cannot pay for.
    #[test]
    fn a_frame_is_charged_before_it_is_read_and_counts_toward_its_price() {
        let mut chain = ChainStore::new(params());

        // An ask whose price is more than its frame: it pays its price.
        let ask = Message::GetBlocks((0..128).collect());
        let frame = ask.encode();
        let mut peer = greeted();
        assert!(peer.afford_reading(&frame, NOW, || false));
        assert_eq!(peer.spent, what_the_wire_costs(frame.len()));
        on_message(&mut local(&mut chain), &mut peer, ask, NOW);
        assert_eq!(peer.spent, 128, "an ask paid its frame and its price both");

        // A frame whose bytes cost more than its message does: it pays for
        // the bytes, since the bytes are what reading it was.
        let pong = Message::Pong(3);
        let mut padded = pong.encode();
        padded.resize(4 * 512, 0);
        let mut peer = greeted();
        assert!(peer.afford_reading(&padded, NOW, || false));
        on_message(&mut local(&mut chain), &mut peer, pong, NOW);
        assert_eq!(
            peer.spent, 4,
            "a frame's charge was handed back for a cheap message"
        );

        // A window that cannot pay for the frame is not charged for it, and
        // says so.
        let mut peer = greeted();
        assert!(peer.afford_reading(&vec![0u8; 512 * 8_000], NOW, || false));
        let before = peer.spent;
        assert!(
            !peer.afford_reading(&vec![0u8; 512 * 193], NOW, || false),
            "a window with 192 units left paid for a frame of 193"
        );
        assert_eq!(peer.spent, before);
        assert_eq!(
            peer.paid_to_read, 0,
            "a frame not paid for left a charge behind"
        );
    }

    /// Two frames are not charged: a stranger's, which may only be a
    /// handshake, and a piece of a join answer from the peer this node asked
    /// for one.
    ///
    /// Charging the second would have the answering peer's window refuse the
    /// pieces this node went and asked for, and a collector left waiting for
    /// a piece that was read and thrown away blames the peer that sent it.
    #[test]
    fn a_handshake_and_a_join_piece_asked_for_are_read_for_nothing() {
        let piece = Message::JoinPart {
            what: Joining::Ledger,
            at: Hash32::ZERO,
            part: 0,
            parts: 1,
            bytes: vec![0u8; crate::message::JOIN_PART_BYTES],
        };
        let mut peer = greeted();
        assert!(peer.afford_reading(&piece.encode(), NOW, || true));
        assert_eq!(
            peer.spent, 0,
            "a piece of a join answer this node asked for was charged for its bytes"
        );

        let mut stranger = PeerState::default();
        assert!(stranger.afford_reading(&vec![0u8; 4 * 1024], NOW, || false));
        assert_eq!(
            stranger.spent, 0,
            "a peer that had not said who it was was charged"
        );
    }

    /// A piece of a join answer from a peer this node did not ask is charged
    /// for its bytes like any other frame.
    ///
    /// The piece goes free because this node went and asked one named peer
    /// for it, and the tag says nothing about who was asked: it is the first
    /// byte of the frame, and anybody can write it. Nothing asked, so a peer
    /// nobody was collecting from had every frame tagged as a piece read and
    /// decoded outside its allowance, a megabyte at a time up to the flood
    /// ceiling, and dropped only after.
    #[test]
    fn a_join_piece_nobody_asked_for_is_charged_for_its_bytes() {
        let piece = Message::JoinPart {
            what: Joining::Ledger,
            at: Hash32::ZERO,
            part: 0,
            parts: 1,
            bytes: vec![0u8; crate::message::JOIN_PART_BYTES],
        };
        let frame = piece.encode();
        let mut unasked = greeted();
        assert!(unasked.afford_reading(&frame, NOW, || false));
        assert_eq!(
            unasked.spent,
            what_the_wire_costs(frame.len()),
            "a piece of a join answer from a peer nobody asked was read for nothing"
        );
    }
}

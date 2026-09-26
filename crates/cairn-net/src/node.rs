//! Carrying messages between machines.
//!
//! One thread reads from each peer and one writes to it, rather than an
//! asynchronous runtime. A node keeps tens of connections, not thousands, so
//! the runtime would buy nothing here and cost a large dependency inside the
//! process people are being asked to run and audit. Blocking reads and a
//! channel per peer are the whole design, and they can be read in an afternoon.
//!
//! Nothing here decides anything. Every decision belongs to [`crate::sync`],
//! which this module calls while holding the chain, and to the consensus rules
//! underneath it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cairn_accumulator::forest::{Forest, ForestProof};
use cairn_chain::{Accepted, Bodies, ChainError, ChainStore, Located, Outdated, MAX_REORG_DEPTH};
use cairn_crypto::PublicKey;
use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::genesis;
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::NetworkId;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::sampling::{check_start, open_start, SampledStart, SAMPLES};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::Transfer;
use cairn_ledger::validation::BlockError;
use cairn_ledger::validation::ConsensusParams;
use cairn_ledger::validation::TransferError;
use cairn_ledger::LedgerState;
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Hash32;
use cairn_store::{
    staged_beside, write_beside_and_move, BlockLog, DirectoryLock, HeaderLog, HeaderTree,
    JoinFailed, StoreError, BLOCK_LOG, HANDED_LEDGER, HEADER_BYTES, HEADER_LOG, HEADER_TREE,
};

use crate::book::AddressBook;
use crate::choosing::{self, Approach, Chooser, JoinProgress};
use crate::joining::{most_join_bytes, Collecting, Joined, Progress};
use crate::message::{
    Joining, Keeps, Message, Placed, JOIN_PART_BYTES, MAX_CHAIN, MAX_HEADERS, MAX_PROVEN,
    MAX_SHARED_ADDRESSES,
};
use crate::refusal::{can_be_refused, Refusals};
use crate::sync::{
    a_window_has_turned, local_handshake, on_message, Allowance, Local, PeerState, Reaction, Window,
};
use crate::wire::{most_from, read_message, write_message, Incoming, WireError};

/// Connections a node dials for itself.
pub const TARGET_PEERS: usize = 8;

/// Connections a node holds at once, dialled and accepted together.
///
/// Without a ceiling, anyone can open connections until the node runs out of
/// threads. Each one costs two threads and a read buffer, so the ceiling is
/// what turns an unbounded cost into a known one.
pub const MAX_PEERS: usize = 48;

/// Connections somebody else can hold on a node that has reached nobody.
///
/// [`MAX_PEERS`] less the slots held back for the peers a node goes out and
/// chooses, which is the whole of [`TARGET_PEERS`] while it has reached
/// nobody and shrinks to nothing once it has.
///
/// There was no number between the two. The accept loop and the dialling
/// round asked the same question, so a table somebody else filled was a table
/// this node could not dial out of, and filling it is not misbehaviour:
/// forty eight connections that greet, are welcomed and speak every few
/// seconds are never refused and never fall quiet. `MAX_PER_HOST` is two per
/// exact address, so that is twenty four addresses, a quarter of a /24 or
/// twenty four out of one machine's IPv6 /64.
pub const MOST_FROM_OUTSIDE: usize = MAX_PEERS - TARGET_PEERS;

/// Connections accepted from any one address.
///
/// A single machine opening every slot would leave a node surrounded by one
/// peer wearing many hats, which is the cheapest way to isolate it.
const MAX_PER_HOST: usize = 2;

/// Addresses whose allowance is counted separately at once.
///
/// The table is fed by whoever connects, so without a ceiling an attacker
/// holding one IPv6 range would decide how much memory this node spends
/// remembering what everybody spent. The same reasoning, and the same number,
/// as [`crate::refusal::MAX_REFUSED`]. Only addresses with a live connection
/// or a window still running are held at all, so this is far above what an
/// honest node ever reaches.
const MAX_ADDRESS_WINDOWS: usize = 1_024;

/// How long a dial may hang before it is given up on.
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);
/// How long one round of upkeep may spend opening connections.
///
/// `TcpStream::connect_timeout` blocks the thread it is called on, and the
/// thread it is called on is the one that also drives the choice a node with no
/// chain is making, the turn to fill in its old headers, the join it is waiting
/// on and the ledger it is on probation for. An address routed nowhere holds a
/// dial for the whole of [`DIAL_TIMEOUT`], and a round dialled up to
/// [`TARGET_PEERS`] of them one after another.
///
/// So one `Peers` message, which is charged a single unit of a peer's
/// allowance, took a round of upkeep from just over a second to twenty five,
/// measured. The addresses cost the stranger nothing to invent and they are
/// reached first by a node that has not found enough live peers yet, which is
/// the node whose chooser can least afford to run once every twenty five
/// seconds.
///
/// A round now spends this much and goes back to the rest of its work; what is
/// left is dialled on the next one. It is the time and not the number that is
/// capped, because a dial that fails fast is not the problem: an address that
/// refuses comes back in microseconds, so a book full of those is still worked
/// through in one round. Only the ones that hang are rationed, and one of those
/// per round is what this buys.
const DIAL_BUDGET: Duration = Duration::from_secs(3);
/// How long a read waits before the loop looks up to check on things.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a write may block before the peer is treated as gone.
const WRITE_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a peer may say nothing at all before it is dropped.
///
/// A node asks every peer for addresses once a second and a healthy one
/// answers, so silence this long is not quiet, it is absent.
const PEER_SILENCE: Duration = Duration::from_secs(90);
/// Messages one peer may send within [`FLOOD_WINDOW`] before it is treated as
/// flooding rather than talking.
///
/// A peer catching up sends blocks in batches and is nowhere near this. A peer
/// asking the same question hundreds of times a second is not syncing.
const MAX_MESSAGES_PER_WINDOW: u32 = 2_000;
/// The window that count is measured over.
const FLOOD_WINDOW: u64 = 10;
/// Messages queued for one peer before further ones are dropped.
///
/// A peer this far behind is not keeping up, and queueing without limit would
/// let it decide how much memory this node spends. Dropped announcements cost
/// it nothing lasting: it asks for what it is missing on the next exchange.
const OUTBOUND_QUEUE: usize = 256;
/// Bytes queued for one peer before further messages are dropped.
///
/// The count above is in messages, and a message on this wire is nine bytes or
/// half a megabyte. Two `GetBlocks` for `MAX_REQUESTED` heights each filled
/// that queue with two hundred and fifty six blocks, up to thirty two
/// megabytes on one connection and about a gigabyte and a half across
/// [`MAX_PEERS`], and it is not something a peer has to work at: the writer
/// gives a frame [`crate::wire::FRAME_PATIENCE`] and renews it on
/// progress, so a peer reading at the floor a frame has to clear, about three
/// and a quarter kilobytes a second, is never judged late and holds all of it.
/// Forty eight connections held that way cost the far end a hundred and fifty
/// four kilobytes a second.
///
/// Four megabytes is what a window of allowance buys, since a peer pays five
/// hundred and twelve bytes to the unit for anything large. So a peer cannot
/// have more waiting for it than it has paid for, and paying again means
/// waiting out a window.
const OUTBOUND_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// How long the accept loop waits between looks when nothing is arriving.
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// How often the node looks for peers and saves its address book.
const MAINTENANCE_PERIOD: Duration = Duration::from_millis(1_000);

/// Seconds between two attempts to look up the names a node starts from.
///
/// Only ever reached by a node that has no seed address at all, so this is the
/// pace of a machine waiting for its name server rather than of anything the
/// network does.
pub const NAME_LOOKUP_PERIOD: u64 = 30;

/// Bytes of blocks a node keeps on disk before it writes its ledger down and
/// drops what is below it.
///
/// A node does not need the blocks it has already applied. It needs the ledger
/// they add up to, which is a fixed size, and the window it could still undo,
/// which it holds in memory anyway. What the rest is for is other people: a
/// peer a little behind reads them rather than being handed a whole ledger.
///
/// So this is not a cost the design has to carry, it is a service, and a
/// gigabyte is a generous amount of it. On a busy chain that is five days of
/// blocks; on a quiet one it is years. A node that wants to keep everything
/// says so and keeps everything.
///
/// Without this a node's disk grew with the chain for ever, which is the one
/// thing this design exists not to do: two terabytes at thirty years, on a
/// chain running at the limit.
pub const KEEP_BLOCK_BYTES: u64 = 1_000_000_000;

/// Seconds a join may go without a piece arriving before it is given up on.
///
/// Being handed a ledger is the one exchange a node cannot finish on its own,
/// and the only signal that the peer serving it has stopped answering is that
/// nothing arrives. Without this a newcomer whose archivist hangs up waits for
/// ever, holding no chain and asking nobody else, which is the worst state the
/// software can be in: running, connected, and permanently useless.
///
/// Thirty seconds is many times what a piece takes on any link that could
/// carry the exchange at all, and the cost of being wrong is one round of
/// reading the chain instead.
const JOIN_PATIENCE: u64 = 30;

/// Seconds a node on probation waits for blocks above its anchor before it
/// asks somebody other than whoever handed it the ledger.
///
/// A handover is deliberately taken from below the tip, and the blocks in
/// between are the whole of what stands behind it. Nothing used to go and get
/// them a second time: the one question that started the catch-up went to the
/// peer that supplied the anchor, and if that peer went quiet with the blocks
/// undelivered the node waited for the rest of its life. This is how long it
/// waits before asking everyone else instead.
///
/// The blocks are not a peer's to give or withhold: any node on that chain
/// has them, and a node that has proved the anchor is entitled to ask anybody
/// for what sits above it.
const BURIAL_PATIENCE: u64 = 30;

/// Seconds a node on probation may go with nothing arriving at all, while it
/// has somebody to ask, before it says it is stranded and stops.
///
/// What it is waiting for is the burial: a thousand and twenty four blocks,
/// which any node on that chain serves in seconds. An hour of a connected node
/// hearing nothing at all is not a slow link, it is a chain nobody else has,
/// and this node cannot get off it: being handed a ledger leaves it holding
/// nothing below the anchor, so no branch forking under there can be assembled
/// however much of it arrives. Starting again from an empty directory is the
/// only cure, and an operator can only apply it if they are told.
///
/// Long, because the cost of being wrong is stopping a node that would have
/// caught up. Nothing shorter is needed: the clock runs on the chain moving,
/// so a node making any progress at all never reaches it.
const STRANDING_PATIENCE: u64 = 3_600;

/// Seconds the peer a node is filling its headers in from may go without
/// getting on with it before another peer is asked instead.
const HEADER_PATIENCE: u64 = 30;

/// Headers a turn has to collect to be given [`HEADER_PATIENCE`] again.
///
/// The turn used to be renewed by a single header, and a single header is what
/// a peer sent. One connection answering each question with one header held the
/// turn for as long as it cared to: measured over seventy five seconds it moved
/// the collection sixty eight places out of three hundred and one and nobody
/// else was asked once. The node then never fills its old headers in, so
/// `Store::can_show_the_chain` stays false for the rest of its life and it can
/// never take a newcomer in, which is the one thing this whole exchange exists
/// to keep alive.
///
/// So progress is a run rather than a header, the shape [`crate::wire`] already
/// uses for a frame: a link that keeps delivering keeps its turn, and one that
/// stops loses it. One full answer per patience window is thirty times below
/// what an honest peer manages, since the node asks once a second and an answer
/// carries up to this many. Nothing shorter would do: the floor has to sit
/// under the slowest honest supplier, and what it has to sit above is one.
const HEADER_RUN: u64 = MAX_HEADERS as u64;

/// Blocks the chain may run ahead of the block log before the node stops.
///
/// Not a preference about disk, the way [`KEEP_BLOCK_BYTES`] is. A chain lets
/// go of a block body once it is more than [`MAX_REORG_DEPTH`] below the tip,
/// on a schedule of its own that knows nothing about what reached the disk,
/// and bringing a log level again means reading those bodies back out of
/// memory. So a log further behind than that window can never be brought level
/// however much room comes back, and somewhere below that number a node whose
/// disk has stopped taking writes has to stop with it.
///
/// A quarter of the window rather than the edge of it. What the other three
/// quarters buy is the operator: the line saying the disk has stopped taking
/// what this node writes appears on the first block that fails, and this is
/// how long they have to free some room before carrying on stops being worth
/// more than what it costs. Past here every block accepted is work that will
/// be done again, and the disk the node would be restarted from only falls
/// further behind the chain it is meant to be a copy of.
pub const MAX_BEHIND: u64 = 256;

const _: () = assert!(MAX_BEHIND < MAX_REORG_DEPTH as u64);

/// Blocks written under rules this build does not have, before it says out
/// loud that it looks too old for the chain it is on.
///
/// One of these is not evidence of anything. The version is a number in a
/// field, the work behind a block claiming an unknown version is whatever
/// difficulty that block claims, and the check that would catch a lie about
/// the difficulty sits below the check that reads the version. So a stranger
/// can manufacture these cheaply, and a node that concluded anything from one
/// would be letting a stranger write its diagnosis.
///
/// A run of them, from several peers, spread over time, is a different thing:
/// that is what a chain whose rules moved on looks like from a node that was
/// not updated. Even then this is only said and never acted on, for the same
/// reason.
const UNJUDGED_BLOCKS: u64 = 8;

/// Addresses those blocks have to have arrived from.
///
/// Two rather than one, because one peer is one machine and one machine is
/// what a stranger has. It is not proof: whoever holds two addresses meets it.
/// It is the cheapest condition that makes the claim cost more than one
/// machine, and it only started meaning that once these were counted by
/// address; counted by connection, one machine met it by hanging up.
const UNJUDGED_PEERS: usize = 2;

/// A peer, for the two surfaces above that count peers.
///
/// Where the peer says it can be reached, which is its own port on the address
/// the connection came from: the unit this codebase means by a peer everywhere
/// else, and the one the address book keeps.
///
/// Both of these used to count [`PeerId`]s, which are handed out one per socket
/// and never reused. A single machine at a single address therefore met the
/// "two peers" condition by hanging up and dialling back, which costs it a TCP
/// handshake and is not misbehaviour, and the word the operator read was
/// "peers": a line telling somebody their build is too old for the chain was a
/// line one stranger could write.
///
/// Still not proof, and the failure that is left is worth naming. A machine
/// willing to say it listens on two different ports can present two of these,
/// bounded by the connections one host may hold at once. What has gone is the
/// case that costs nothing and is not even a lie.
///
/// A peer that has named no port counts as its address with no port, so every
/// connection from it is the one peer rather than as many as it opens.
type Sender = SocketAddr;

/// How one connection counts towards those two.
fn sender_of(advertised: Option<SocketAddr>, host: Option<IpAddr>) -> Option<Sender> {
    advertised.or_else(|| host.map(|host| SocketAddr::new(host, 0)))
}

/// Seconds the first and the last of them have to be apart.
///
/// A burst is one peer's idea; a chain that has moved on goes on producing
/// these for as long as this node is running, because every updated peer
/// announces every new block.
const UNJUDGED_STRETCH: u64 = 300;

/// Seconds of meeting none of them before the count starts again.
///
/// A rule change renews its own evidence, so nothing is lost by forgetting an
/// old one. What is gained is that a handful met over a year, which is the
/// ordinary background of a network somebody is testing something on, never
/// adds up to a claim about this build.
const UNJUDGED_MEMORY: u64 = 3_600;

/// Addresses counted towards [`UNJUDGED_PEERS`] at once.
///
/// The table is fed by whoever connects, so it needs a ceiling like every
/// other table here. What is being asked of it is whether more than one peer
/// is involved, and this is far above the number that settles that.
const UNJUDGED_SENDERS: usize = 64;

/// Showings that failed to weigh, saying the same thing each time, before a
/// person is told the chain itself may be the reason.
///
/// One of these is the sender's doing and is treated as such: the chooser
/// stops counting the claim behind it and asks the next claimant. Three
/// saying the same words is a different question, and it is the question this
/// exists for: this build refuses a run of headers longer than
/// `cairn_ledger::sampling::MOST_TAIL`, and a chain whose difficulty has
/// fallen far below what it ran at needs a longer one. Measured over the
/// project's own `draw`: a chain that loses twenty four to forty eight times
/// its hash rate, depending on its length, and does not recover, cannot be
/// weighed at all from about five days after the loss until months or years
/// after it. Every archivist then fails identically, honestly, and the node
/// falls back to reading the chain. What was missing is anybody being told.
///
/// Falls back to reading it from whoever kept the bodies, which is not
/// everybody. A node keeps every header and [`KEEP_BLOCK_BYTES`] of blocks,
/// and drops what is below the ledger it wrote; a header does not rebuild a
/// deleted body. So the two ways in do not fail together and do not recover
/// together, and on the day this fires a newcomer gets on the chain only if
/// some reachable peer chose to keep more than it had to. See
/// `tests/audit_reading_the_chain_needs_bodies.rs`.
const UNWEIGHED_SHOWINGS: u64 = 3;

/// Addresses those showings have to have come from.
///
/// The same reasoning as [`UNJUDGED_PEERS`] and the same honest caveat:
/// whoever holds two addresses meets it, so this is the cheapest condition
/// that makes the claim cost more than one machine, and not proof of anything.
/// It is said and never acted on.
const UNWEIGHED_PEERS: usize = 2;

/// Addresses counted towards [`UNWEIGHED_PEERS`] at once.
const UNWEIGHED_SENDERS: usize = 64;

/// Blocks refused for being dated ahead of this machine's clock before a
/// person is told the clock is the likely reason.
///
/// One is a number a stranger wrote in a field, exactly as an unreadable
/// version is, and this node cannot tell one apart from a miner whose own
/// clock is fast. A run of them is different: every block on the chain is
/// dated, so a machine running behind refuses whatever it is offered, from
/// everybody, for as long as it is wrong.
const BEHIND_BLOCKS: u64 = 8;

/// Addresses those blocks have to have arrived from.
///
/// The same reasoning as [`UNJUDGED_PEERS`] and the same honest caveat:
/// whoever holds two addresses meets it. What it rules out is the case that
/// costs nothing, which is one machine with a fast clock.
const BEHIND_PEERS: usize = 2;

/// Addresses counted towards [`BEHIND_PEERS`] at once.
const BEHIND_SENDERS: usize = 64;

/// Seconds of refusing none of them before the count starts again.
///
/// A clock that is wrong renews its own evidence with every block the network
/// produces, so nothing that matters is lost by forgetting. What is gained is
/// that one block from a miner with a fast clock, met an hour ago, never adds
/// up to a claim about this machine.
const BEHIND_MEMORY: u64 = 3_600;

/// A gap between two rounds of maintenance that means the machine was away.
///
/// A round takes a second. Thirty of them passing at once is not a busy
/// machine, it is a laptop that was closed, a container that was paused, or a
/// clock that was put right. Whatever it was, the node was not on the network
/// while it happened, and every address that failed to answer meanwhile failed
/// for a reason that has nothing to do with the address.
const AWAY_GAP: u64 = 30;
/// Maintenance sleeps in slices so a shutdown does not wait out a full period.
const SLEEP_SLICE: Duration = Duration::from_millis(50);

/// How often a node waiting on a path looks to see whether one has arrived.
///
/// An answer is one round trip on a connection that is already open, so this
/// is the granularity of a wait measured in tens of milliseconds rather than a
/// poll of anything slow.
const RECOVERY_POLL: Duration = Duration::from_millis(50);

/// Addresses dialled when a node needs a path and knows nobody who can build
/// one.
///
/// Small on purpose. This is a node opening connections because of something
/// its own operator asked for, and the ordinary upkeep is what fills the rest
/// of its connections. Four is enough that one machine being down does not end
/// the attempt, and few enough that it cannot become a way of spending this
/// node's connections.
const REACH_FOR_ARCHIVISTS: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("could not open the connection: {0}")]
    Io(#[from] io::Error),
    /// The store refused, in its own words, which name the file where they
    /// know it.
    ///
    /// This had a prefix of its own, "could not reach the block log", on top
    /// of a store error that said the same, so every file of the store was the
    /// block log: a header log that would not open, and a directory another
    /// node held.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// One file of this node's directory, named, and what the store said
    /// about it.
    #[error("could not use {file}: {source}")]
    File {
        file: &'static str,
        #[source]
        source: StoreError,
    },
    /// What is on this disk was written under rules this build does not have.
    ///
    /// Deliberately fatal, before anything is written, and deliberately not
    /// [`NodeError::UnusableLedger`]. That one is a file to put back or
    /// delete. This one is about the reader: a build one release behind the
    /// rules, started on a disk a newer one wrote, which is what a rollback
    /// looks like. The replay used to count every block from the activation
    /// height as refused and cut it, and the ledger was answered with the
    /// remedy for a damaged file; the same build refuses the same blocks from
    /// the network, so neither cured anything and both cost blocks.
    #[error(
        "{file} was written under rules this build does not have: {because}. Nothing on          the disk has been changed. Start it again with a build that has the rules for          that height, and the chain here is picked up where it was left; deleting          anything would not help, because this build refuses the same blocks from the          network"
    )]
    OtherRules { file: &'static str, because: String },
    /// A node asked to keep the whole cold set, over blocks that do not begin
    /// at the first one.
    ///
    /// The archive is built by reading every block from the first, at every
    /// start, and the ones below `from` are not on this disk. Such a node used
    /// to start from its ledger instead, holding the cold set's roots and none
    /// of its leaves, and to tell every peer and its operator that it kept the
    /// whole set.
    #[error(
        "this node was asked to keep the whole cold set, and the blocks on its disk begin \
         at height {from}. The archive is built by reading every block from the first at \
         every start, and those below {from} are not here, so nothing has been changed \
         and it has not started. An archivist keeps every block it reads: give it a \
         directory of its own, where it reads the chain from the first block, or start \
         this one without keeping the cold set"
    )]
    CannotArchive { from: u64 },
    /// What is on this disk is another network's chain.
    ///
    /// The same shape as [`NodeError::OtherRules`], about the command line
    /// rather than the build: one start under a mistyped `--network` on a
    /// directory another network's node wrote. The replay used to refuse its
    /// first record, cut the log to nothing and write this network's first
    /// block in its place.
    #[error(
        "{file} holds another network's chain: {because}. Nothing on the disk has been          changed. If that is the network meant, start this node for it; if not, this          node needs a directory of its own, because this one is that network's"
    )]
    OtherNetwork { file: &'static str, because: String },
    /// The ledger this node starts from is there and cannot be used.
    ///
    /// Deliberately fatal, and deliberately before anything is written. The
    /// blocks on the disk build on this ledger, so without it they lead
    /// nowhere, and the one thing a node must not do about that is decide it
    /// never had a chain and clear the disk to match.
    #[error(
        "{because}. The blocks on this disk build on that ledger, so nothing has been \
         changed: put the file back if there is a copy of it, or delete it, which \
         costs the stored blocks and has this node join the chain again. It keeps its \
         headers and its address book either way"
    )]
    UnusableLedger { because: String },
    /// The socket opened and was closed again without becoming a peer.
    ///
    /// A connection that completes is not a peer. This node lets one go when
    /// it already holds as many as it takes, when it holds as many from that
    /// host as it takes, when it is stopping, and when the socket could not be
    /// set up. Every one of those answered `Ok(())`, and what the operator
    /// read on the line under it was `reached`.
    #[error(
        "the connection to {address} was opened and closed again without being kept: \
         {because}. The address is in the book, so upkeep dials it again"
    )]
    NotKept {
        address: SocketAddr,
        because: &'static str,
    },
}

/// What a node handed a ledger has still to check before it stands behind it.
///
/// Taking a handover checks that the anchor carries work, that it sits where
/// it says in the tip's header forest, and that the ledger matches what it
/// commits to. It deliberately checks nothing about the blocks between the
/// anchor and that tip: whether they exist, and whether anyone did the work
/// they stand for, is settled by this node validating them and by nothing
/// else. Until it has, the ledger it is holding is a stranger's account of a
/// state nobody here watched being built.
///
/// So a node that has been handed one is on probation, and this is it saying
/// so. It follows the branch, it takes blocks, it announces what it applies;
/// what it will not do is anything that treats the anchor as settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probation {
    /// The height the ledger was handed at.
    pub anchor: u64,
    /// The height this node's own validation has to reach: the anchor plus
    /// the burial depth.
    ///
    /// The burial depth rather than whatever tip the handover named, and the
    /// two are not always the same number. A supplier may anchor its ledger
    /// further below its tip than the rules demand, and the extra is its
    /// business rather than this node's: what the anchor was taken on is the
    /// burial, and validating that much is the whole of what was owed. The
    /// rest is ordinary catching up.
    ///
    /// It is also, exactly, the height at which this node becomes able to
    /// build a ledger of its own, since that reads back through undo records
    /// this node only has for blocks it applied itself. Which is why nothing
    /// else has to be written down: the file the undertaking is read from
    /// cannot be replaced until the undertaking is met.
    pub settles_at: u64,
    /// How far that validation has got.
    pub reached: u64,
}

impl Probation {
    /// Blocks above the anchor this node has checked for itself.
    #[must_use]
    pub const fn checked(&self) -> u64 {
        self.reached.saturating_sub(self.anchor)
    }

    /// Blocks it undertook to check when it took the anchor.
    #[must_use]
    pub const fn owed(&self) -> u64 {
        self.settles_at.saturating_sub(self.anchor)
    }
}

impl std::fmt::Display for Probation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "checked {} of the {} blocks above the ledger handed over at height {}",
            self.checked(),
            self.owed(),
            self.anchor
        )
    }
}

/// What a node that cannot yet show a newcomer the chain is still missing.
///
/// The first stretch of every join, and it was the whole of one before the
/// header exchange stopped handing the turn back to a peer that spoiled it. A
/// node handed a ledger holds headers from where it was handed on and no path
/// through what came before, so until it has collected the rest from the
/// network there is a question it cannot answer.
///
/// The half nobody would guess is the disk. Showing a newcomer the chain and
/// writing down this node's own ledger are proved against the same header
/// forest, and dropping old blocks is what writing that ledger is for. So a
/// node in this state does not drop anything: measured on a node handed a
/// ledger at height 32 and asked to keep one byte, the chain reached 159 and
/// the log still began at 32, thirty one kilobytes and climbing, with every
/// other line an operator could read saying the node was well. `--keep` is a
/// promise, and this is the one state where it is not being kept.
///
/// Three numbers and not one, because there are three ways to fall short of
/// showing the chain and they call for different afternoons. Headers that
/// start above the first block is the ordinary one, and it mends itself. But
/// headers that stop below the tip, or a forest that does, is a write the disk
/// would not take, and a line that only knew how to say the first would have
/// told such a node it was collecting nothing from nobody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Filling {
    /// The lowest header this node holds. Everything below it is what it is
    /// still asking the network for.
    pub from: u64,
    /// One past the highest header it holds.
    pub through: u64,
    /// Leaves in the forest built over those headers, which is what a place in
    /// the chain is proved against.
    pub proved: u64,
    /// How far the chain has got, so each of the three above can be said
    /// against something rather than as "some".
    pub reaches: u64,
    /// Bytes of blocks on the disk now.
    pub bytes: u64,
    /// Bytes of blocks the operator asked this node to hold.
    ///
    /// Kept beside the figure above rather than compared here, because the
    /// pair is the news: a node over its budget and unable to do anything
    /// about it has a disk that grows with the chain, and that is the one
    /// thing this whole design exists to prevent.
    pub keep: u64,
}

impl Filling {
    /// Whether the disk has grown past what this node was asked to hold.
    #[must_use]
    pub const fn over_the_keep(&self) -> bool {
        self.bytes > self.keep
    }
}

/// A node that cannot get on from where it was handed its ledger.
///
/// Told apart from every other way of being behind, for the same reason
/// [`Outdated`] is: this one has no cure the node can apply. A node that read
/// its chain can always rewind and take another branch. A node handed a ledger
/// holds nothing below its anchor, so a heavier chain forking under there
/// cannot be assembled at all, and every block of it is refused for want of a
/// parent this node will never obtain. What it holds is not a branch it chose
/// badly, it is the only branch it has, and starting again from an empty
/// directory is the only way off it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stranded {
    /// The height the ledger was handed at, which is as far as this node ever
    /// got.
    pub anchor: u64,
    /// The height it had to validate its way to before it could stand behind
    /// that ledger.
    pub settles_at: u64,
    /// How long it waited for the blocks in between, with somebody to ask.
    pub waited: u64,
    /// Blocks it was offered meanwhile and could not reach, which is what a
    /// heavier chain forking below the anchor looks like from in here.
    pub out_of_reach: u64,
}

/// What came of asking the network where a wallet's fallen notes sit.
///
/// A note that has fallen out of the set every node keeps can only be spent
/// alongside a path showing where it sits, and that path moves every time
/// another note falls. A wallet whose own node stopped keeping one has money
/// it can see and cannot move, and the only cure is to ask somebody who kept
/// the whole set. This is the account of that asking, so that whatever is
/// showing the balance can say what happened rather than naming a service and
/// leaving the person to find it.
#[derive(Clone, Debug, Default)]
pub struct Recovered {
    /// Peers the question went to. Zero means there was nobody to ask at all.
    pub asked: usize,
    /// How many of those said they keep the whole cold set.
    ///
    /// Told apart from the rest because it is the difference between having
    /// asked the wrong people and having nobody to ask. A wallet with peers
    /// but no archivist among them is one connection away from an answer.
    pub archivists: usize,
    /// Peers that answered at all, whatever the answer was.
    pub answered: usize,
    /// The paths that folded to this node's own commitment, by place.
    ///
    /// Nothing else comes out of here. A path that did not fold is not a
    /// weaker answer, it is no answer, and it is counted below instead.
    pub proofs: BTreeMap<u64, ForestProof>,
    /// Answers refused because the path did not reach this node's commitment.
    ///
    /// Not necessarily a peer behaving badly, which is why nothing is held
    /// against one for it. The cold set moves whenever a note falls, and a
    /// path built a moment before a block landed no longer reaches the
    /// commitment that is there now. A wrong answer and a late one look the
    /// same from here, so both are simply not used.
    pub refused: usize,
}

/// Why this node would not take something offered to it.
#[derive(Debug, thiserror::Error)]
pub enum Refused {
    /// The node has not validated its way to the tip it was handed, so the
    /// ledger this would be built on is still somebody else's word.
    #[error("this node is still validating the ledger it was handed: {0}")]
    OnProbation(Probation),
    #[error(transparent)]
    Block(#[from] ChainError),
    #[error(transparent)]
    Transfer(#[from] TransferError),
}

/// What replaying a stored chain found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Restored {
    /// Blocks read back and reapplied.
    pub blocks: usize,
    /// Blocks read back but not replayed, and therefore cut from the log.
    ///
    /// Two things end a replay with a cut. A block that no longer applies,
    /// which means the bytes changed underneath the node. And a block that
    /// applies but does not extend the branch, which means the log is not the
    /// followed branch in order of height: a log written before that was the
    /// rule, or one left mid reorganisation by a machine that stopped.
    ///
    /// Neither loses anything but time. What was cut is asked for again, and
    /// a node that was following the heaviest branch still is.
    ///
    /// Two things that used to be counted here are not. A refusal about the
    /// reader, a build without the rules for a height or a node started for
    /// another network, stops the start with nothing cut
    /// ([`NodeError::OtherRules`], [`NodeError::OtherNetwork`]): the same
    /// build refuses the same blocks from the network, so nothing cut for it
    /// ever came back. And a record that will not decode is left on the disk
    /// and reported through `unreadable`, as recovery reports it.
    pub refused: usize,
    /// Bytes cut off the end of the log because a write never finished.
    ///
    /// Zero when `unreadable` is set: nothing is cut for damage, and a count
    /// saying bytes were thrown away while they are still on the disk sends an
    /// operator looking for a backup instead of at the file.
    pub discarded_bytes: u64,
    /// Bytes left on the disk past the last record that could be read.
    ///
    /// The other half, and only ever set alongside `unreadable`. Nothing was
    /// removed: this is how much of the log is standing there unread, which is
    /// what says whether the damage cost one block or a day of them.
    pub left_in_place: u64,
    /// The record a walk of the log stopped at, when what stopped it was a
    /// whole record that would not decode rather than one cut short.
    ///
    /// Told apart from `discarded_bytes` because the two mean opposite things
    /// to whoever is running the node. Bytes at the end are the ordinary trace
    /// of a machine that stopped mid write, and they cost one block. A whole
    /// record the store cannot read is damage, and nothing was cut for it: the
    /// bytes stay on the disk until the log grows over them, which is the
    /// first block this node writes, and a start that read them wrongly once
    /// can read them again before then.
    ///
    /// Met by the store when the index beside the log was out of line, and by
    /// the replay when it was not. The replay used to cut the log there, so
    /// the same byte met two policies depending on a derived file.
    pub unreadable: Option<usize>,
    /// Header records the store would not stand behind, left on the disk and
    /// counted here.
    ///
    /// A header log's first record decides where the whole log claims to be,
    /// so a head the record after it does not name is one the log cannot
    /// build on. The store reports holding nothing rather than a geography it
    /// made up, and deliberately leaves the bytes exactly where they are so
    /// that somebody can look at them.
    ///
    /// Left on the disk by the store, and not for long. What happens next is
    /// that the log is written again from the blocks this node still has, and
    /// the first of those writes cuts the file to nothing, at this start when
    /// there are blocks and at the first block accepted when there are none. A
    /// node keeps a gigabyte of blocks and every header ever, so what the
    /// blocks can replace is the recent end and what they cannot is most of
    /// it. Measured: a node holding headers 0 to 59 with blocks 52 to 59 came
    /// back holding headers 52 to 59, could no longer show a newcomer the
    /// chain, and could no longer write the ledger that lets it drop old
    /// blocks. Before this count it reported a clean start with nothing set
    /// aside at all, and after it the operator was told the bytes were still
    /// on the disk to look at, which the same start had written over.
    ///
    /// Told apart from `unreadable`, which is the same kind of news about the
    /// block log. Both are damage rather than an interrupted write, and this
    /// one costs the node something the network can give back rather than
    /// anything of its own.
    pub headers_set_aside: u64,
    /// Header records deleted because the blocks left them stranded.
    ///
    /// The header log holds one run, and this is the shape it cannot hold: a
    /// run that stops below the height the blocks begin at. Nothing joins the
    /// two, and the log cannot take the blocks' headers while it holds a run
    /// that does not lead up to them, so it is emptied and written again from
    /// the blocks.
    ///
    /// The way in was a merge of the collected headers that was interrupted:
    /// [`join_logs`] emptied the log and refilled it in place, so a machine
    /// that stopped in the middle of one left exactly this, and the start after
    /// it deleted every header the node held, could no longer show a newcomer
    /// the chain, and reported what a healthy start reports. The merge is
    /// written beside the log and moved into place now, so what is left to
    /// arrive here is a log an older build left in that state, or bytes that
    /// changed on a disk.
    ///
    /// Told apart from `headers_set_aside`, which is the store declining to
    /// stand behind a head and leaving the bytes where they are. These bytes
    /// are gone. What they cost is the same and it is given back the same way:
    /// the node collects the run from before it arrived again, from a peer
    /// that kept it.
    pub headers_dropped: u64,
    /// Header records cut because they were of a branch the blocks are not
    /// on, and written again from the blocks.
    ///
    /// What a machine stopped in the middle of a reorganisation leaves. The
    /// new branch's headers are written before its blocks, so a stop between
    /// the two leaves the header log on the new branch from the fork and the
    /// block log on the old one, and the start comes back on the old one. It
    /// used to fill the header log in from the blocks after whatever it held,
    /// which stitched a log of the old branch, the new one and the old one
    /// again. Nothing afterwards took the seam out: the forest stopped at it,
    /// the node stopped showing newcomers the chain and keeping its budget,
    /// and it reported a header the store would not vouch for at every block.
    ///
    /// Nothing is lost by the cut. What replaces them is the headers of the
    /// branch this node is on, read off its own blocks.
    pub headers_replaced: u64,
    /// Block records set aside because the log does not know where it starts.
    ///
    /// The store reads where the log begins off its first record, and asks the
    /// record after it whether that is right. When the two disagree the store
    /// stands behind neither and answers holding nothing, leaving the bytes
    /// alone.
    ///
    /// Told apart from `unreadable`, which is a record that would not decode.
    /// These decode perfectly and disagree with each other, which is why the
    /// count is the whole log rather than a position in it.
    ///
    /// The bytes are left alone by the store and not by the node: the first
    /// block this node writes goes over the first record, and on a network
    /// that pins its first block that is this start, which writes it there.
    ///
    /// Before the store asked, one bit of record zero's height field moved the
    /// whole log: a node opened reporting nothing wrong, denied holding the
    /// block at zero it was holding, and then read `first_height() > start` as
    /// a node that had joined above its own disk. That skipped the replay and
    /// truncated the log. Every block deleted, `refused` reporting nought, and
    /// for an archivist the whole history, which is the one role that cannot
    /// ask for it back.
    pub blocks_set_aside: usize,
    /// Whether the log was set aside because it does not start at the first
    /// block of the chain.
    ///
    /// A node handed a ledger writes its log from the height it was handed.
    /// Replaying means applying each block to a ledger built from the one
    /// before it, and this node never had those, so there is nothing to replay
    /// against. It joins again, which costs it twelve megabytes and costs the
    /// log the blocks it had written. Not a fault, and worth telling apart
    /// from one.
    pub rejoining: bool,
    /// Addresses read back from the address book.
    pub addresses: usize,
}

/// What a node was putting on its disk when the disk would not take it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writing {
    /// The blocks it has accepted. The one that costs the chain: a node that
    /// stops writing these comes back at the height of what it last wrote and
    /// asks for the rest again, and can only be given them while somebody else
    /// still has them.
    Blocks,
    /// The headers, and the forest of them a node proves things against. What
    /// a node that stops writing these loses is the ability to show a newcomer
    /// which chain carries the most work. It goes on following the chain
    /// correctly and goes on saying it can answer.
    Headers,
    /// The ledger a node writes down so its next start does not begin at the
    /// first block, and the blocks below it that writing one lets go. The
    /// cheapest of the three to lose, and the one that fails first on a disk
    /// with nothing left, because getting under a disk budget starts by
    /// writing several megabytes.
    Ledger,
}

impl Writing {
    /// Which of two refusals is the one worth saying, highest first.
    ///
    /// The order is what each one costs to lose, and it is not a nicety. A
    /// node over its disk budget asks for its ledger to be written once every
    /// round of upkeep, so on a disk with nothing left the ledger fails once a
    /// second; without an order between them, that would replace the account
    /// of the blocks that are not reaching the disk at all, every second, for
    /// as long as the node ran.
    const fn costs(self) -> u8 {
        match self {
            Self::Blocks => 2,
            Self::Headers => 1,
            Self::Ledger => 0,
        }
    }
}

impl std::fmt::Display for Writing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Blocks => "the blocks it has accepted",
            Self::Headers => "the headers it shows the chain with",
            Self::Ledger => "the ledger it starts from",
        })
    }
}

/// Why this node is not taking connections, if it is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unanswered {
    /// What the listener said, in its own words: too many open files, out of
    /// memory. It is the difference between an operator who has to raise a
    /// limit and one whose machine is in trouble, and this node is in no
    /// position to tell them which.
    pub because: String,
    /// Visitors turned away in a row. It goes back to nothing the moment one
    /// is let in, so a figure here is a door that is still shut.
    pub refusals: u64,
}

/// What this node has taken on and not managed to put on its disk.
///
/// A node whose disk has stopped taking writes goes on doing everything else.
/// It takes blocks, it validates them, it climbs in height, it announces what
/// it applied, and every line it prints is the line a healthy node prints.
/// What it is not doing is keeping any of it, and the gap that opens is not
/// one it closes later: the catch-up reads block bodies out of memory, and a
/// chain lets go of a body once it is more than [`MAX_REORG_DEPTH`] below the
/// tip. Measured on a real full disk, a node accepted a thousand and eighty
/// four blocks against a log frozen at thirty three, and came back at thirty
/// two.
///
/// So this is said while the gap is still small enough to be worth acting on,
/// and the node stops itself at [`MAX_BEHIND`] rather than carrying on making
/// its own disk less worth restarting from.
///
/// `None` on a node whose disk is taking what it writes, which is every
/// healthy one. A write that failed once and was made good by the next block
/// never reaches this: the next block writes everything the log is missing, so
/// an ordinary hiccup closes itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unwritten {
    /// What this node was writing when the disk last refused it.
    pub what: Writing,
    /// What the disk said, in its own words: no space left on device,
    /// permission denied, input/output error. It is the difference between an
    /// operator who has to free some room and one who has a failing drive, and
    /// this node is in no position to tell them which.
    pub because: String,
    /// The height the chain had reached the last time this was looked at.
    pub reached: u64,
    /// The highest block that is on the disk, or `None` for a log holding
    /// nothing at all.
    pub written_through: Option<u64>,
    /// Blocks accepted and not written, which is what a restart costs.
    pub blocks: u64,
    /// Whether those blocks could still reach the disk if the room came back.
    ///
    /// False once the gap has passed [`MAX_BEHIND`], and false for good,
    /// because the node stops there. It still holds the blocks in the gap when
    /// it does, since [`MAX_BEHIND`] sits inside the window a chain holds
    /// bodies over, but a node that has stopped writes nothing: what is left
    /// is a directory that is still worth starting from because it stopped
    /// falling further behind, and a restart that asks the network for the
    /// rest.
    pub within_reach: bool,
}

/// What this node was reading back off its own disk when the disk refused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    /// A block. What a peer catching up asks for, what the chain reads back
    /// when it has to undo something, and what an explorer quotes.
    Blocks,
    /// A header, or the forest built over them. What a newcomer is shown to
    /// settle which chain carries the most work.
    Headers,
}

impl std::fmt::Display for Reading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Blocks => "a block it had accepted",
            Self::Headers => "a header it shows the chain with",
        })
    }
}

/// A record this node holds, was asked for, and could not read back.
///
/// The counterpart of [`Unwritten`], and the half that had no channel. A write
/// the disk will not take is this node's own history not being kept, and it is
/// said. A read the disk will not answer is somebody else's question going
/// unanswered, and it was said nowhere at all.
///
/// It is not a record this node no longer keeps. A peer asking for a block
/// below what this node holds is told nothing, and is right to be; a wallet
/// asking a node that keeps no archive is told to ask an archivist. This is
/// the third case, where the log says the record is there, the disk will not
/// produce it, and whoever asked hears exactly the same silence as in the
/// first two.
///
/// What that costs is quiet, and the quiet is the defect. The node goes on
/// following the chain, goes on announcing what it applies, goes on
/// introducing itself as a node that can answer, and every peer catching up
/// over that stretch is handed a batch with a hole in it. A catch-up applies
/// blocks in the order they arrive and drops any whose parent has not landed,
/// so one refused record throws away the whole tail of every batch that spans
/// it, from every peer that asks, for as long as the node runs. Measured in
/// `tests/own_disk.rs` on a node whose block index had one flipped byte: it
/// starts clean, its height, its peer count and its stored height all read
/// like a healthy node's, and the peer reading from it stops one block below
/// the damage and stays there.
///
/// The count does not go down and is not cleared by a read that worked. A
/// refusal is about one record; a later read that succeeded was a different
/// question and says nothing about this one, and clearing on it would hide
/// steady damage behind ordinary traffic. A restart clears it, because a
/// restart re-opens the log and finds out again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unread {
    /// What was being read when the disk last refused.
    pub what: Reading,
    /// The height of that record.
    pub height: u64,
    /// What the store said, in its own words. The difference between an index
    /// that disagrees with the log, which is a derived file that can be worked
    /// out again, and a record that will not decode, which is not.
    pub because: String,
    /// How many reads have been refused since this node started.
    pub refusals: u64,
}

/// What says this build is too old for the chain it is on.
///
/// A block written under rules this software does not have is not a bad block
/// and its sender is not a bad peer: an update makes the same block readable,
/// so the judgement is about the reader. The node therefore refuses it,
/// remembers nothing against it, blames nobody, and carries on. The cost of
/// getting that right is that an un-updated node now refuses the real chain in
/// silence rather than loudly, and its operator sees a height that has simply
/// stopped moving.
///
/// This is the silence answered. It is evidence and not a verdict: the node
/// does not stop on it, because the version is a number a stranger can write
/// in a field, and a node that stopped on one would be handing a stranger the
/// power to stop it. A run of them, from more than one peer, spread over time,
/// is worth a person's attention and nothing more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unjudged {
    /// The highest block version this node was offered and could not read.
    pub version: u16,
    /// The highest version this build has the rules for.
    pub known: u16,
    /// Blocks it met.
    pub blocks: u64,
    /// Connections they arrived on.
    pub peers: usize,
    /// Seconds between the first of them and the last.
    pub over: u64,
}

/// What says this node cannot weigh the chain it is being offered.
///
/// A newcomer joins by being shown what work stands behind a chain rather than
/// by reading every block of it, and a showing that does not check out is
/// ordinarily the sender's doing: the chooser stops counting its claim and the
/// next claimant is asked. That stays, whatever this says, because the peer
/// did send something this node could not use and the hold-off is what stops
/// a stranger occupying a newcomer's attention.
///
/// What did not exist is the other reading. When every showing fails with the
/// same words, the peers are not the thing they have in common: the chain is.
/// This build takes a run of headers up to a fixed length, and a chain whose
/// difficulty has fallen far below what it ran at needs a longer one, so an
/// honest archivist serving an honest chain is refused and looks exactly like
/// a liar. The node still gets its chain, by reading it block by block, which
/// is slower and no less safe. Before this, nothing about any of it reached
/// the person running it: both errors were dropped where they were made, and
/// the only trace was a join that took hours.
///
/// Evidence and not a verdict, for the same reason as [`Unjudged`]: two
/// addresses are two peers, and a node that stopped on this would be handing a
/// stranger a way to stop it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unweighable {
    /// What the last of them said, in the words of whatever refused it. The
    /// difference between a run of headers longer than this build takes, which
    /// is this build meeting a chain it cannot weigh, and a sample in the
    /// wrong place, which is somebody making one up.
    pub because: String,
    /// Showings that failed with these words.
    pub showings: u64,
    /// Connections they came from.
    pub peers: usize,
    /// Seconds between the first of them and the last.
    pub over: u64,
}

/// What says this machine's clock is behind the network's.
///
/// A block dated more than the allowed drift ahead of the reading node's own
/// clock is refused, and it is the one refusal in the rule set that two honest
/// nodes can disagree about: the reader reverses it by waiting. So a machine
/// whose clock is slow refuses honest blocks, and until this existed it said
/// nothing at all about a clock to the person running it. Nowhere else in this
/// node does either.
///
/// Evidence and not a verdict, for the same reason as [`Unjudged`]: a
/// timestamp is a number a stranger writes in a field. The exception is
/// [`Self::own_first_block`], which is the network's first block as compiled
/// into this binary, refused by this machine. Nobody else wrote that one, so
/// one of those settles it on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Behind {
    /// Seconds the furthest refused block stood ahead of this clock. What the
    /// clock is wrong by is this less the drift below.
    pub seconds: u64,
    /// Seconds of drift the rules allow before a block is refused at all.
    pub drift: u64,
    /// Blocks refused for it.
    pub blocks: u64,
    /// Connections they arrived on.
    pub peers: usize,
    /// Set when what was refused was this build's own first block, which no
    /// peer sent and nobody but this machine can have got wrong.
    pub own_first_block: bool,
}

type PeerId = u64;

/// One peer's queue of things to say, bounded in messages and in bytes.
///
/// The channel bounds the first at [`OUTBOUND_QUEUE`] and says nothing about
/// the second, which is the whole of [`OUTBOUND_QUEUE_BYTES`]. What is counted
/// is what has been handed to the writer and not yet written, so the bound is
/// on memory this node is holding rather than on anything it has said.
#[derive(Clone, Debug)]
struct Outbound {
    sender: SyncSender<(Message, usize)>,
    /// Bytes queued and not yet written.
    waiting: Arc<AtomicUsize>,
}

impl Outbound {
    fn new(sender: SyncSender<(Message, usize)>) -> Self {
        Self {
            sender,
            waiting: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A queue nobody reads, for a connection this node has finished with.
    fn nowhere() -> Self {
        let (sender, _) = mpsc::sync_channel(1);
        Self::new(sender)
    }

    /// Queues `message`, saying whether there was room for it.
    fn try_send(&self, message: Message) -> Result<(), ()> {
        let weight = message.weight();
        self.hand_over(message, weight)
    }

    /// The same, for a caller that has already weighed what it is sending.
    ///
    /// Weighing a block means encoding it, and the one caller that serves
    /// blocks has to weigh them anyway to charge for them.
    fn hand_over(&self, message: Message, weight: usize) -> Result<(), ()> {
        // Claimed before the message is handed over, so two threads queueing
        // at once cannot both be told there is room for the last of it.
        let room = self
            .waiting
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                let after = held.saturating_add(weight);
                (after <= OUTBOUND_QUEUE_BYTES).then_some(after)
            });
        if room.is_err() {
            return Err(());
        }
        if self.sender.try_send((message, weight)).is_err() {
            self.waiting.fetch_sub(weight, Ordering::SeqCst);
            return Err(());
        }
        Ok(())
    }

    /// Bytes queued and not yet written.
    #[cfg(test)]
    fn queued(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }
}

/// One live connection, as the rest of the node sees it.
struct Peer {
    outbound: Outbound,
    /// Kept so a shutdown can unblock the thread reading from it.
    stream: TcpStream,
    /// Where the connection came from, which is the only address about this
    /// peer that it did not choose itself.
    host: Option<IpAddr>,
    /// Where this peer says it listens, once it has said so.
    advertised: Option<SocketAddr>,
    /// The address this node dialled to reach it, when it dialled.
    ///
    /// Kept beside `advertised` because that one arrives only with the
    /// handshake, and an address that accepts a connection and then says
    /// nothing never fills it in. Upkeep skips the addresses it already holds
    /// a connection to, and reading only `advertised` meant a silent address
    /// was never among them: it was dialled again the next round, and again,
    /// until every outbound slot this node has went to the one address a
    /// stranger had named. Nine connections to one address inside five
    /// seconds, against a target of eight, and what the node then knew about
    /// the chain came only through connections that stranger chose.
    dialled_to: Option<SocketAddr>,
    /// Whether this node opened the connection, rather than answering one.
    ///
    /// A connection somebody else opened is a connection somebody else chose,
    /// and counting it as one of this node's own is how a stranger decides who
    /// it talks to.
    dialled: bool,
    /// Whether this peer has introduced itself.
    ///
    /// Read by [`Shared::broadcast`], and it has to be. A peer goes into this
    /// table the moment its socket is accepted, and the welcome is only queued
    /// once its hello has arrived, so anything broadcast in between reaches a
    /// node this one has not been introduced to. That is `Unannounced`, which
    /// closes the connection and refuses the host: a node's own eagerness,
    /// spent on the peer that had just arrived.
    ///
    /// Only the accepting side has the gap. A node that dialled queued its
    /// hello inside `attach_peer`, and one channel is one order, so everything
    /// after it lands after it.
    greeted: bool,
    /// Whether this peer said it keeps the cold set, and so can rebuild a path
    /// for a note that fell long ago.
    ///
    /// A claim and nothing more, which is all it has to be: what such a peer
    /// hands over is folded against a commitment this node worked out itself,
    /// so a lie costs the liar a message and this node a comparison. What the
    /// claim saves is asking every peer in turn and waiting on the ones that
    /// were never going to answer.
    archives: bool,
}

impl Peer {
    /// Whether this node may send this peer anything but its own
    /// introduction.
    ///
    /// See [`Peer::greeted`]. A connection this node accepted and has not yet
    /// answered a hello on is one where every other message costs the
    /// connection: the peer refuses it as unannounced, closes, and turns this
    /// host away for a while.
    const fn worth_speaking_to(&self) -> bool {
        self.dialled || self.greeted
    }
}

struct Shared {
    params: ConsensusParams,
    address: SocketAddr,
    /// Drawn once at start. A node behind a router cannot recognise its own
    /// address coming back from a peer, but it can recognise this.
    nonce: u64,
    chain: Mutex<ChainStore>,
    /// Absent when the node keeps its chain only in memory.
    ///
    /// Behind an `Arc` because the chain reads block bodies back through it:
    /// it holds one of these too, and neither owns the other, so there is no
    /// cycle to break.
    log: Arc<Mutex<Option<Store>>>,
    book: Mutex<AddressBook>,
    /// The one choice a node with no chain makes about whom to follow.
    ///
    /// A claim is not proof, and nothing here treats one as proof. What the
    /// claims are for is knowing when *not* to believe a chain that has
    /// proved itself: weighing shows that one chain's work is real, never
    /// that it is the most. A newcomer that adopted the first chain to prove
    /// itself would be taking the first answer rather than the best, and the
    /// first answer is the one an attacker races to give.
    choosing: Mutex<Chooser>,
    /// Names this node was told to start from, kept as names.
    ///
    /// A name is looked up again while the book holds no seed at all, because
    /// a node started before its machine could resolve anything would
    /// otherwise sit with nothing to dial and no way to hear of anybody, for
    /// as long as it ran.
    seed_names: Mutex<Vec<String>>,
    /// When those names were last looked up, so a machine with no name server
    /// asks every so often rather than every round.
    names_looked_up_at: AtomicU64,
    /// The book's change count as of the last write of it that got through.
    ///
    /// `u64::MAX` until one has, which no real count reaches: it would take
    /// the addresses to have moved eighteen quintillion times.
    book_written_at: AtomicU64,
    directory: Option<PathBuf>,
    /// Bytes of blocks this node keeps on disk. `u64::MAX` keeps everything,
    /// which is what a node that offers the history to others does.
    ///
    /// Settable while running, because it is an operator's choice about disk
    /// rather than anything the rules have an opinion on.
    keep_bytes: AtomicU64,
    /// Held for as long as the node runs, so no second process writes to the
    /// same directory.
    _lock: Option<DirectoryLock>,
    peers: Mutex<HashMap<PeerId, Peer>>,
    /// The most any one connection from each address has spent this window.
    ///
    /// Held here rather than only beside the connection, and that is the whole
    /// of the repair. An allowance kept on the socket was an allowance a peer
    /// refilled by hanging up and dialling back, which costs it a TCP
    /// handshake and a Hello and earns it no refusal, since asking is not
    /// misbehaviour. A connection now starts where its address left off.
    /// [`crate::sync::Allowance`] says what that changes and what it does not.
    windows: Mutex<HashMap<IpAddr, Arc<Mutex<Window>>>>,
    /// The mark shared by every address past the ceiling on that table.
    ///
    /// The table is fed by whoever connects, so it needs one, and running out
    /// of room must not be a way of being handed a fresh allowance. Crowding
    /// it therefore makes the crowd share a mark, which is the only direction
    /// this can fail in safely.
    crowded_window: Arc<Mutex<Window>>,
    /// Peers turned away for a while, for something they did earlier.
    refusals: Mutex<Refusals>,
    /// The last join answer built of each kind, kept so a newcomer asking for
    /// its pieces in turn is answered from one build rather than from twenty
    /// two.
    ///
    /// One of each kind and not one per peer: building a ledger is megabytes,
    /// and this is the difference between a node that can be joined and a node
    /// anybody can make spend its memory. Both kinds are held because a
    /// newcomer weighs a chain before it asks for the ledger, so two arriving
    /// a moment apart are each in a different half of that; with one slot
    /// between them they would take turns throwing away the other's build, and
    /// every piece would be built again from the disk.
    ///
    /// A newcomer asking about a different tip replaces its kind, which costs
    /// the one it displaced a rebuild and no more.
    joined: Mutex<[Option<Prepared>; 2]>,
    /// The tip the ledger on disk was written for, and the height that ledger
    /// stands at.
    ///
    /// Upkeep asks for the ledger to be written every round for as long as the
    /// block log is over its budget, and what it would write only changes when
    /// the tip does. Without this a node past its budget unwound its ledger to
    /// the burial, read a burial's worth of headers off the disk and rewrote
    /// several megabytes, once a second, for the rest of its life.
    written: Mutex<Option<(Hash32, Located)>>,
    /// How far this node is through joining a chain it was not on.
    joining: Mutex<Progress>,
    /// When this node last asked again for a piece of a join answer that had
    /// not arrived, so a slow piece is waited for rather than asked for once
    /// a second.
    join_asked_again_at: AtomicU64,
    /// What this node undertook when it took a ledger it was handed, while it
    /// still owes it.
    ///
    /// A leaf: the chain may be held while this is taken, never the other way
    /// round.
    probation: Mutex<Option<Undertaking>>,
    /// How long this node waits on that undertaking before it gives up.
    ///
    /// An operator's choice, like how many bytes of blocks to keep: a node on
    /// a link that comes and goes may be worth leaving longer, and one an
    /// operator is watching is worth giving up on sooner.
    stranding_patience: AtomicU64,
    /// Blocks refused because this node can never reach the branch they sit
    /// on, rather than because it has not caught up to them.
    ///
    /// Counted rather than only acted on. A node handed a ledger holds nothing
    /// below its anchor, so a heavier chain forking under there arrives as a
    /// stream of blocks it can do nothing with, and that used to pass in
    /// complete silence: the peer is not blamed, which is right, and nothing
    /// else was said either, which is how an operator ends up watching a
    /// healthy-looking height that never moves.
    out_of_reach: AtomicU64,
    /// Set once, if this node turns out to be somewhere it cannot get on from.
    ///
    /// Kept rather than only acted on, for the same reason [`Shared::outdated`]
    /// is: whatever started the node has to be able to say why it stopped, and
    /// this is the one stop whose cure is the operator's to apply.
    stranded: Mutex<Option<Stranded>>,
    /// The peer this node is filling its old headers in from, and what its
    /// turn has left to run.
    ///
    /// One peer at a time, and only that peer's runs are taken. There is a
    /// single collection and anybody may send headers, so before this a
    /// stranger's one junk header fixed where the collection started, every
    /// honest run after it was dropped for starting somewhere else, and the
    /// whole thing was thrown away at the commitment check. That could be
    /// repeated for the price of one message, which is a joined node that can
    /// never fill in its headers and so can never show the chain to anybody.
    /// The same defect [`join_piece`] was fixed for, in the other collection.
    filling_from: Mutex<Option<Turn>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    next_id: AtomicU64,
    running: AtomicBool,
    /// Whether somebody is already winding this node down.
    ///
    /// Separate from [`Shared::running`], which says whether the node is still
    /// working. Two paths clear that from inside, a block from a height this
    /// build has no rules for and a handed ledger nobody delivers the burial
    /// for, and [`Node::shutdown`] used to read it as "already stopped" and
    /// return having done none of what it says: no socket shut, no thread
    /// joined, the address book unsaved, and the directory lock alive inside
    /// whatever peer thread was still in a read. Winding down is a thing that
    /// happens once, and this is what says whether it has.
    winding_down: AtomicBool,
    /// Set once, if this node ever meets a height it has no rules for.
    ///
    /// Kept rather than only acted on, so whatever started the node can say
    /// why it stopped. Running on would mean following the chain of whoever
    /// had not updated either.
    outdated: Mutex<Option<Outdated>>,
    /// What the last pass at the disk did not manage to put on it.
    ///
    /// A leaf, like [`Shared::stranded`]: the chain and the log may both be
    /// held while this is taken, and neither may be taken while it is.
    unwritten: Mutex<Option<Unwritten>>,
    /// What the disk would not read back when somebody asked for it.
    ///
    /// A leaf as well, and it has to be: this is written from inside the reads
    /// that hold the log, so anything it took would be taken under the log and
    /// there is no order that survives that. It takes nothing.
    unread: Mutex<Option<Unread>>,
    /// Why this node is not taking connections, if it is not.
    ///
    /// A leaf, like [`Shared::unwritten`]: it is written from the accept loop,
    /// which holds nothing else while it writes it.
    ///
    /// The loop used to leave on any error it did not recognise, and the listener
    /// went with the thread, so the port closed for the life of the process.
    /// Every other part of the node went on working and saying so, which is how a
    /// seed address goes dark while its operator reads a healthy status line.
    unanswered: Mutex<Option<Unanswered>>,
    /// Visitors this node could not take, over its whole life.
    ///
    /// Counted rather than only reported, because [`Shared::unanswered`] is
    /// cleared the moment one is let in, and a node refusing one visitor in ten
    /// would otherwise never show it.
    turned_away: AtomicU64,
    /// Forest nodes built again from the leaves beneath them, over this
    /// node's whole life.
    ///
    /// A figure here is a disk that dropped something this node wrote and
    /// went on running, which is worth an operator knowing even though the
    /// node put it right by itself: a disk that lost one node has not
    /// finished.
    mended_nodes: AtomicU64,
    /// Questions this node has put to the network about where fallen notes
    /// sit, over its whole life.
    ///
    /// Counted because the wallet above it waits between two of them, and a
    /// wait is held by whether the count stops going up rather than by how
    /// long anything took.
    proofs_asked_for: AtomicU64,
    /// Why the address book could not be written down, if it could not.
    ///
    /// A leaf as well, and it is written from upkeep and from the shutdown.
    /// The write itself used to be `let _ = book.save(directory)`, on a file a
    /// node reads on every start: a directory that will not take it costs the
    /// node every address it has learned, so it comes back knowing only the
    /// seeds it was started with, and nothing anywhere said a word.
    unsaved_book: Mutex<Option<String>>,
    /// Blocks this build turned out not to be able to read, and who sent them.
    ///
    /// Also a leaf, and for the same reason: it is written from the thread
    /// reading a peer, which has just let go of the chain.
    unjudged: Mutex<Unreadable>,
    /// Showings of what work stands behind a chain that would not weigh, and
    /// who sent them.
    ///
    /// A leaf as well. It is written after the weighing, which holds neither
    /// the chain nor the collection, and it takes nothing.
    unweighed: Mutex<Unweighed>,
    /// Blocks refused for being dated ahead of this machine's clock, and who
    /// sent them.
    ///
    /// A leaf as well, written from the thread reading a peer once the chain
    /// has been let go of, and once at start for this build's own first block.
    out_of_step: Mutex<OutOfStep>,
    /// What this node is asking the network about where fallen notes sit.
    ///
    /// Empty on a node nobody has asked to recover anything, which is every
    /// node that is not carrying a wallet.
    asking: Mutex<Asking>,
}

/// One question about where fallen notes sit, and what has come back.
///
/// The asker's side of the exchange, and the only side that keeps anything.
/// An answerer is handed places, looks them up, answers and forgets: it holds
/// nothing per asker, which is what stops a stranger making a node remember
/// things on its behalf. Somebody has to remember what was asked while the
/// answers travel, and it is the one who wants the answer.
///
/// One question at a time. A second one replaces the first, for the same
/// reason a fresh join attempt starts from nothing: what came back for a
/// question nobody is waiting on any more is not worth the room.
///
/// A leaf, like [`Shared::stranded`]: the chain may be taken while this is
/// held nowhere, and this is never held while the chain is.
#[derive(Debug, Default)]
struct Asking {
    /// The places asked about, and the leaf each answer has to fold to.
    ///
    /// The leaf is what makes an answer checkable without trusting anybody. A
    /// path is folded with it from the place named upward, and what comes out
    /// either is the commitment this node worked out for itself or the answer
    /// is worth nothing.
    wanted: BTreeMap<u64, Hash32>,
    /// Connections the question went to, so an answer from anybody else is
    /// dropped before it costs this node a look at the chain.
    asked: HashSet<PeerId>,
    /// Connections that answered, whatever they said.
    answered: HashSet<PeerId>,
    /// Paths that folded.
    found: BTreeMap<u64, ForestProof>,
    /// Answers that did not.
    refused: usize,
}

impl Asking {
    /// Whether every place asked about has been answered for.
    fn satisfied(&self) -> bool {
        !self.wanted.is_empty() && self.found.len() >= self.wanted.len()
    }
}

/// The account of one question about where fallen notes sit, and the end of
/// the question.
///
/// Taken from the collection rather than kept alongside it, so there is one
/// record of what happened and not two that can disagree.
///
/// The collection is emptied here, which is the whole of what ends a question.
/// Nothing else did: `recover_proofs` wrote a fresh [`Asking`] on the way in
/// and left it standing on the way out, so a wallet that had recovered once
/// kept, for as long as the process ran, a list of places it was still willing
/// to be told about and a list of peers still allowed to tell it. Every one of
/// those peers could hand over [`MAX_PROVEN`] paths whenever it liked, and
/// each of them was folded against the cold set with the chain held. A
/// question nobody is waiting on is not a question.
fn finished(asking: &mut Asking, archivists: usize) -> Recovered {
    let done = Recovered {
        asked: asking.asked.len(),
        archivists,
        answered: asking.answered.len(),
        proofs: std::mem::take(&mut asking.found),
        refused: asking.refused,
    };
    *asking = Asking::default();
    done
}

/// What ends a question, and what a question that never ended left open.
///
/// Kept next to [`finished`] rather than in the suite, because what is being
/// pinned is the state of a collection nothing outside this file can see. It
/// is the reason the defect ran as long as it did: `recover_proofs` writes a
/// fresh [`Asking`] on the way in, so a second recovery looks correct from
/// outside however the first one ended.
#[cfg(test)]
mod what_is_taken_for_nothing {
    use super::{taken_before_the_allowance, Joining, Message};
    use crate::message::Placed;
    use cairn_primitives::Hash32;

    /// One message, and being able to say so is the repair.
    ///
    /// What is on this list is taken before the chain has been near it and
    /// before the allowance has been asked about, so every entry is work a
    /// stranger gets for nothing. The list had no name, which is how it came
    /// to have two entries.
    #[test]
    fn one_message_is_taken_before_the_allowance_and_it_is_the_join_piece() {
        assert!(taken_before_the_allowance(&Message::JoinPart {
            what: Joining::Ledger,
            at: Hash32::ZERO,
            part: 0,
            parts: 1,
            bytes: Vec::new(),
        }));
    }

    /// The one that used to be on it, and what it cost to be there.
    ///
    /// A run of paths is work: each is folded against the cold set with the
    /// chain held, and `cost_of` prices it at eight, the same as asking for
    /// one. Taken here, it went past `cost_of` entirely, so the price was
    /// charged to nobody: a peer this node had asked could offer the same
    /// sixty four paths again and again inside the few seconds the question
    /// stays open, every one of them folded, for free.
    ///
    /// The test that held that price drives `on_message`, which is a path this
    /// message did not take.
    #[test]
    fn a_run_of_paths_is_not_taken_before_the_allowance() {
        let offered = Message::Proofs(vec![Placed {
            position: 0,
            proof: None,
        }]);
        assert!(
            !taken_before_the_allowance(&offered),
            "a run of paths folded against the cold set has a price, and this \
             is what decides whether anybody is asked for it"
        );
    }

    /// And nothing else drifted onto it.
    #[test]
    fn nothing_else_is_taken_before_the_allowance() {
        for message in [
            Message::Ping(1),
            Message::Pong(1),
            Message::GetPeers,
            Message::Peers(Vec::new()),
            Message::Announce(Vec::new()),
            Message::GetBlocks(Vec::new()),
            Message::GetProofs(Vec::new()),
            Message::Chain { from: 0, count: 0 },
            Message::GetChain {
                locator: Vec::new(),
            },
        ] {
            assert!(
                !taken_before_the_allowance(&message),
                "{} is taken for nothing",
                message.kind()
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod ending_a_question {
    use super::{finished, Asking, ForestProof, Hash32};
    use std::collections::{BTreeMap, HashSet};

    /// A question in the state `recover_proofs` leaves one in: places still
    /// wanted, a peer that was asked, and a path that folded.
    fn mid_question() -> Asking {
        Asking {
            wanted: BTreeMap::from([(7, Hash32::ZERO), (9, Hash32::ZERO)]),
            asked: HashSet::from([3]),
            answered: HashSet::from([3]),
            found: BTreeMap::from([(
                7,
                ForestProof {
                    siblings: Vec::new(),
                },
            )]),
            refused: 1,
        }
    }

    /// **A question nobody is waiting on accepts nothing.**
    ///
    /// Both lists are what let a peer through: `asked` decides whose paths are
    /// looked at, `wanted` decides which places are folded. Left standing,
    /// they were a channel every peer that had ever been asked could keep
    /// sending [`crate::message::MAX_PROVEN`] paths down, each of them folded
    /// against the cold set with the chain held, for as long as the process
    /// ran. A wallet asks once and then holds that open for its lifetime.
    #[test]
    fn the_end_of_a_question_is_the_end_of_what_it_will_accept() {
        let mut asking = mid_question();
        let done = finished(&mut asking, 1);

        assert_eq!(done.asked, 1, "the account is taken before the reset");
        assert_eq!(done.refused, 1);
        assert_eq!(done.proofs.len(), 1, "the paths that folded come out");

        assert!(
            asking.asked.is_empty(),
            "a peer that was asked can still be answered by"
        );
        assert!(
            asking.wanted.is_empty(),
            "places are still being watched for"
        );
        assert!(asking.found.is_empty() && asking.answered.is_empty());
        assert_eq!(asking.refused, 0);
    }
}

/// Blocks written under rules this build does not have, as they add up.
///
/// Counted rather than acted on. What one of these means is settled in
/// [`too_old_for_the_chain`], which is the whole of the rule and is kept apart
/// from the counting so it can be read on its own.
#[derive(Debug, Default)]
struct Unreadable {
    /// The highest version met, which is the one worth naming: a node told
    /// about several is being told the chain moved past the furthest of them.
    version: u16,
    blocks: u64,
    /// The peers they arrived from, up to [`UNJUDGED_SENDERS`].
    peers: HashSet<Sender>,
    /// When the first arrived, and when the last did.
    first: u64,
    last: u64,
}

/// Which refusal a report of unwritten blocks carries, given the one a pass
/// just met and the one already standing.
///
/// Kept out of [`Shared`] so it can be read and tested on its own: on a real
/// disk the refusals arrive in whatever order the filesystem gives them, and
/// the case that matters, a cheap refusal arriving after a costly one, is the
/// ledger failing once a second behind blocks that have stopped reaching the
/// disk at all.
fn the_refusal_to_say(
    fresh: Option<&Refusing>,
    standing: Option<&Unwritten>,
) -> Option<(Writing, String)> {
    match (fresh, standing) {
        // The costlier of the two stands, for the reason in
        // [`Writing::costs`]. Between two of the same cost the fresh words
        // are said, being what the disk says now.
        (Some(fresh), Some(standing)) if standing.what.costs() > fresh.what.costs() => {
            Some((standing.what, standing.because.clone()))
        }
        (Some(fresh), _) => Some((fresh.what, fresh.because.clone())),
        // A pass with nothing to write says nothing new about why the disk
        // stopped taking things, so what opened the gap still stands.
        (None, Some(standing)) => Some((standing.what, standing.because.clone())),
        // A gap with nothing anywhere to explain it, which is a log that was
        // already short when this node opened it. The next block applied
        // tries to fill it and finds out why it cannot; guessing here would
        // only put a made up sentence in front of an operator.
        (None, None) => None,
    }
}

/// Counts one block this build could not read, against the address it came
/// from.
///
/// Kept out of [`Shared`] so the counting can be read and tested on its own.
/// What it has to get right is that the same machine arriving twice is one
/// peer: these used to be counted by connection, and a connection is handed
/// out one per socket and never reused, so one address met the condition by
/// hanging up and dialling back. See [`Sender`].
fn count_unreadable(met: &mut Unreadable, from: Option<Sender>, version: u16, now: u64) {
    // A stretch with none of these in it ends the count. A chain whose rules
    // moved on renews its own evidence every block, so nothing that matters is
    // lost by forgetting; what is gained is that a stray one a year ago never
    // adds up to a claim about this build.
    // An empty count is not asked first: starting it again changes nothing.
    let lapsed = now < met.last || now.saturating_sub(met.last) > UNJUDGED_MEMORY;
    if lapsed {
        *met = Unreadable::default();
    }
    if met.blocks == 0 {
        met.first = now;
    }
    met.version = met.version.max(version);
    met.blocks = met.blocks.saturating_add(1);
    met.last = now;
    if let Some(from) = from {
        if met.peers.len() < UNJUDGED_SENDERS {
            met.peers.insert(from);
        }
    }
}

/// Whether what this node has met adds up to a build too old for its chain.
///
/// Three conditions and every one of them is needed, because each one on its
/// own is something a stranger can produce for the price of a message. Kept
/// out of the counting so that the rule is one function that can be read and
/// tested without a network.
fn too_old_for_the_chain(met: &Unreadable) -> Option<Unjudged> {
    if met.blocks < UNJUDGED_BLOCKS || met.peers.len() < UNJUDGED_PEERS {
        return None;
    }
    // A clock that went backwards says nothing about how long these have been
    // arriving, so it says nothing at all rather than a negative stretch. Not
    // asked on its own: it leaves `over` at nought, which the stretch refuses.
    let over = met.last.saturating_sub(met.first);
    if over < UNJUDGED_STRETCH {
        return None;
    }
    Some(Unjudged {
        version: met.version,
        known: BLOCK_VERSION,
        blocks: met.blocks,
        peers: met.peers.len(),
        over,
    })
}

// A clock that went backwards leaves nothing of a stretch, so the stretch is
// what refuses it, in every build and not only the ones that run the tests.
const _: () = assert!(UNJUDGED_STRETCH > 0);

/// Showings that would not weigh, as they add up.
///
/// Counted rather than acted on, the same shape as [`Unreadable`]. What one of
/// them means is settled by the chooser; what a run of them means is settled
/// in [`no_showing_checks_out`], kept apart so the rule can be read on its own.
#[derive(Debug, Default)]
struct Unweighed {
    /// What they said, which has to be the same words each time. A different
    /// refusal is a different question and starts the count again: peers
    /// failing in three different ways are three peers, and peers failing in
    /// one way are a chain.
    because: String,
    showings: u64,
    /// The peers they came from, up to [`UNWEIGHED_SENDERS`].
    peers: HashSet<Sender>,
    /// When the first arrived, and when the last did.
    first: u64,
    last: u64,
}

/// Whether one more connection from `host` fits beside the connections held,
/// given where each of them came from.
///
/// Apart from the table of peers so the rule can be held on its own: a peer
/// cannot be built without a socket, so nothing asked it, and counting every
/// other address against this one, or letting it one past its share, passed.
fn room_beside(held: impl Iterator<Item = Option<IpAddr>>, host: IpAddr) -> bool {
    held.filter(|from| *from == Some(host)).count() < MAX_PER_HOST
}

/// Whether an address's mark is still worth keeping: something holds it, or
/// its window is the current one. Kept apart from the table it prunes so the
/// rule can be held on its own.
fn still_counted(window: &Arc<Mutex<Window>>, now: u64) -> bool {
    Arc::strong_count(window) > 1
        || window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .current(now)
}

/// Counts one showing of a chain's work that would not weigh, against the
/// address it came from.
///
/// Kept out of [`Shared`] so the counting can be read and tested on its own,
/// as the two counts beside it are. It is the same count, and it was the one
/// of the three left inside, with every one of its comparisons held by
/// nothing.
fn count_unweighed(met: &mut Unweighed, from: Option<Sender>, because: &str, now: u64) {
    // A different refusal is a different question. Three peers failing in
    // three ways are three peers; three failing in one way are a chain, and
    // only the second is worth a person's afternoon.
    //
    // An empty count is not asked whether it has lapsed: starting it again
    // changes nothing, and asking was one more comparison nothing could see.
    let lapsed = met.because != because || now < met.last;
    if lapsed {
        *met = Unweighed::default();
    }
    if met.showings == 0 {
        met.first = now;
        because.clone_into(&mut met.because);
    }
    met.showings = met.showings.saturating_add(1);
    met.last = now;
    if let Some(from) = from {
        if met.peers.len() < UNWEIGHED_SENDERS {
            met.peers.insert(from);
        }
    }
}

/// Whether what this node has met adds up to a chain it cannot weigh.
///
/// No stretch of time is asked for, unlike [`too_old_for_the_chain`], and the
/// difference is what renews the evidence. A chain whose rules moved on
/// produces an unreadable block for as long as a node is up, so demanding that
/// they be spread out costs nothing there. Showings stop: a node asks one
/// claimant at a time and runs out of claimants, and three that arrive quickly
/// may be all there ever are. A stretch here would mean the line comes after
/// the hours of reading it exists to explain, or never comes at all.
fn no_showing_checks_out(met: &Unweighed) -> Option<Unweighable> {
    if met.showings < UNWEIGHED_SHOWINGS || met.peers.len() < UNWEIGHED_PEERS {
        return None;
    }
    // A clock that went backwards says nothing about how long these have been
    // arriving, so it says nothing at all rather than a negative stretch.
    if met.last < met.first {
        return None;
    }
    Some(Unweighable {
        because: met.because.clone(),
        showings: met.showings,
        peers: met.peers.len(),
        over: met.last.saturating_sub(met.first),
    })
}

/// Blocks refused for being dated ahead of this machine's clock, as they add
/// up.
///
/// Counted rather than acted on, the same shape as [`Unreadable`]. What one of
/// these means is nothing; what a run of them means is settled in
/// [`clock_is_behind`], kept apart so the rule can be read on its own.
#[derive(Debug, Default)]
struct OutOfStep {
    /// The furthest ahead of this clock any of them was dated. The furthest
    /// rather than the last, because what a person needs is the largest gap
    /// the machine has actually met.
    ahead: u64,
    blocks: u64,
    /// The peers they arrived from, up to [`BEHIND_SENDERS`].
    peers: HashSet<Sender>,
    /// When the last of them arrived.
    last: u64,
    /// Set when this node refused the first block of its own network, which is
    /// compiled into this binary and which no peer sent it.
    own_first_block: bool,
}

/// Counts one block refused for standing ahead of this machine's clock.
///
/// Kept out of [`Shared`] so the counting can be read and tested on its own,
/// and counted by address rather than by connection for the reason
/// [`Sender`] gives.
fn count_out_of_step(met: &mut OutOfStep, from: Option<Sender>, ahead: u64, now: u64) {
    // An empty count is not asked first: starting it again changes nothing.
    let lapsed = now < met.last || now.saturating_sub(met.last) > BEHIND_MEMORY;
    if lapsed {
        let own_first_block = met.own_first_block;
        *met = OutOfStep {
            own_first_block,
            ..OutOfStep::default()
        };
    }
    met.ahead = met.ahead.max(ahead);
    met.blocks = met.blocks.saturating_add(1);
    met.last = now;
    if let Some(from) = from {
        if met.peers.len() < BEHIND_SENDERS {
            met.peers.insert(from);
        }
    }
}

/// Whether what this node has refused adds up to a clock that is behind.
///
/// Two ways to meet it, and they are not the same evidence. A run of blocks
/// from several peers is the ordinary one, and it is circumstantial in the way
/// [`too_old_for_the_chain`] is: a timestamp is a number, and whoever holds
/// two addresses can write two of them.
///
/// Refusing this build's own first block is not circumstantial at all. That
/// block is in the binary, its date is older than every chain on the network,
/// and the only way to be past it is for this machine's clock to be behind the
/// day the network opened. One is enough, and it is worth saying on its own
/// because the node cannot start at all: it has no chain, so every peer's tip
/// fails the same check and there is nothing to show for it but a height that
/// never appears.
///
/// That half is spent the moment the node has a chain, which is what
/// `still_without_a_chain` carries. The first block is laid down once, at
/// start, and a clock put right while the node runs lets it take the chain
/// from a peer instead; left ungated the line would follow such a node for the
/// rest of its life, telling its owner to fix something already fixed.
fn clock_is_behind(met: &OutOfStep, drift: u64, still_without_a_chain: bool) -> Option<Behind> {
    let own_first_block = met.own_first_block && still_without_a_chain;
    let enough =
        own_first_block || (met.blocks >= BEHIND_BLOCKS && met.peers.len() >= BEHIND_PEERS);
    if !enough {
        return None;
    }
    Some(Behind {
        seconds: met.ahead,
        drift,
        blocks: met.blocks,
        peers: met.peers.len(),
        own_first_block,
    })
}

/// Whose turn it is to supply the headers from before this node arrived.
///
/// The turn is one peer's from end to end, because a run half from one peer and
/// half from another would be thrown out at the commitment check with neither
/// of them shown to be wrong. What it costs an honest peer that goes quiet mid
/// run is the part it had sent, once.
#[derive(Clone, Copy, Debug)]
struct Turn {
    peer: PeerId,
    /// When the turn was last renewed.
    moved: u64,
    /// How far the collection had reached then, so what renews the turn is a
    /// run and not a header. See [`HEADER_RUN`].
    marked: u64,
    /// Set when this peer's collection was thrown away, so that the turn is
    /// over at once instead of at [`HEADER_PATIENCE`].
    ///
    /// The turn used to be forgotten outright at that point, and forgetting it
    /// is what handed it straight back: with nothing remembered,
    /// [`Shared::asks_headers_of`] starts the round again at the lowest
    /// connected identifier, which is the oldest connection. So a peer that
    /// stayed connected longest could answer every question with two headers
    /// that do not follow on, have the collection thrown away, and be asked
    /// again on the next round, for ever. Measured: fifty one collections
    /// spoiled in sixty seconds for eighteen kilobytes, from one connection,
    /// with a peer that could have answered the whole run in one message never
    /// asked once. The node then never fills its old headers in, so
    /// `Store::can_show_the_chain` stays false for the rest of its life and it
    /// can never take a newcomer in.
    ///
    /// Remembering who it was is what makes the next line of
    /// [`Shared::asks_headers_of`] mean what it says: the turn goes to the next
    /// peer along, and a node surrounded by peers that spoil the collection
    /// works through them rather than asking the same one for ever.
    spoiled: bool,
}

/// The undertaking a node took on with a handed ledger, as it stands.
///
/// Held rather than worked out again from the file it came from, because the
/// answer moves with the chain and the file does not. What survives a restart
/// is the pair of heights, which the file does carry: [`read_handed_ledger`]
/// reads them back, and where the chain has got to is read off the chain.
#[derive(Clone, Copy, Debug)]
struct Undertaking {
    anchor: u64,
    settles_at: u64,
    /// The highest the chain had reached when it last moved.
    reached: u64,
    /// When that was, so waiting is counted from the chain moving rather than
    /// from the node starting.
    moved: u64,
    /// When somebody was last asked for what is missing.
    ///
    /// Starts at nothing rather than at the moment the undertaking began, so
    /// the first round asks. A node that has just adopted, or has just come
    /// back on to a ledger it was handed, has no reason to sit quiet for half
    /// a minute first: the question it needs answering is the only thing
    /// standing between it and being a node.
    asked: Option<u64>,
}

impl Undertaking {
    /// The undertaking a node comes back to after a restart.
    ///
    /// `None` when there is none left to keep: a chain already at or past the
    /// tip the handover named has validated the burial, which is the whole of
    /// what was owed.
    fn resumed(anchor: u64, settles_at: u64, reached: Option<u64>, now: u64) -> Option<Self> {
        let reached = reached?;
        (reached < settles_at).then_some(Self {
            anchor,
            settles_at,
            reached,
            moved: now,
            asked: None,
        })
    }
}

/// What one round of upkeep owes an undertaking, given where the chain has
/// reached.
///
/// Separated from everything that holds a lock so the rule can be read, and
/// tested, on its own: it is three deadlines and their order matters.
fn owed_this_round(
    held: &mut Undertaking,
    reached: u64,
    peers: usize,
    patience: u64,
    now: u64,
) -> Owed {
    // A clock that went backwards says nothing about how long this has been
    // waiting, so the waiting starts again rather than counting a negative.
    // The same reading [`has_gone_quiet`] takes of one.
    if reached > held.reached || now < held.moved {
        held.reached = held.reached.max(reached);
        held.moved = now;
        return Owed::Waiting;
    }
    // Nobody to ask is a different fault with a different cure, and it is not
    // this node's to diagnose: an operator whose node has no peers has a
    // network to mend, not a directory to wipe.
    if peers == 0 {
        return Owed::Waiting;
    }

    let still = now.saturating_sub(held.moved);
    if still >= patience {
        return Owed::GivenUp(Stranded {
            anchor: held.anchor,
            settles_at: held.settles_at,
            waited: still,
            out_of_reach: 0,
        });
    }
    let due = held
        .asked
        .is_none_or(|at| now < at || now.saturating_sub(at) >= BURIAL_PATIENCE);
    if due {
        held.asked = Some(now);
        return Owed::AskAgain;
    }
    Owed::Waiting
}

/// What one round of upkeep decided about an undertaking.
enum Owed {
    /// Nothing to do: the chain is moving, or it has not been still long
    /// enough to be worth acting on.
    Waiting,
    /// Ask everybody for what is missing, because whoever was supplying it has
    /// stopped.
    AskAgain,
    /// Waiting has stopped being the answer.
    GivenUp(Stranded),
}

/// The height a block log should be cut back to, keeping everything above it.
///
/// Two floors, and the lower of them wins.
///
/// The first is the window the chain can still undo. The chain lets go of
/// block bodies from memory in the belief that this log holds them, so cutting
/// into that window leaves a reorganisation that fails partway with nowhere to
/// read back the branch it was restoring, and a node on neither branch.
/// Whatever an operator sets, this much is not theirs to drop.
///
/// The second is the budget they did set. What that buys is other people: a
/// peer a little behind reads blocks here rather than being handed a whole
/// ledger. Below it, blocks go.
///
/// This once dropped everything below the ledger, which is to say everything,
/// because the ledger stands for the tip. A node then kept nothing on disk
/// however large its budget, could answer nobody who was behind, and had
/// quietly taken away the floor its own released bodies stand on.
///
/// The budget is met on an average rather than by measuring each block. It is
/// an operator's preference about disk, not a rule anything depends on, and
/// walking the whole log to spend it exactly would cost more than it saves.
fn cut_for(tip: u64, held: u64, bytes: u64, keep: u64) -> u64 {
    let average = bytes.checked_div(held).unwrap_or(0).max(1);
    let affordable = keep.checked_div(average).unwrap_or(0);
    tip.saturating_add(1).saturating_sub(affordable)
}

/// The most header reads any one take of the log answers for.
///
/// Not a limit on what a peer may ask for. A run of [`MAX_HEADERS`] still
/// comes back whole; it comes back in this many reads at a time, with the log
/// let go of between them. What is bounded here is how long one answer keeps
/// the disk to itself.
///
/// The disk is a single lock and [`Shared::persist`] takes it with the chain
/// already in hand, so a thread that has just validated a block waits on the
/// log holding the chain, and every thread that wants the chain waits behind
/// that one. A stranger's read request therefore set how long this node took
/// to accept its own block. Five hundred and twelve header reads measured
/// 1.2 ms with the file in the page cache and 33 to 170 ms without it, and an
/// address may buy sixteen of those runs per allowance window.
const READS_PER_HOLD: u64 = 32;

/// The same for block records.
///
/// Smaller, because a header is a fixed hundred and eighty two bytes and a
/// block is anything up to `max_block_bytes`. `MAX_REQUESTED` of those is
/// sixteen megabytes read, decoded and cloned, which is 13 ms of disk alone
/// with the file already in the page cache.
const BLOCKS_PER_HOLD: usize = 8;

/// Gathers `total` positions a few at a time, so no one take of a lock
/// answers for the whole of a run.
///
/// `take` is given a start and a length, answers for that much or less, and
/// holds nothing by the time it returns. Its second answer says whether there
/// is any point asking again.
///
/// `follows` says whether one thing belongs directly after another. A run
/// assembled across several takes is a run assembled across a log that can
/// move: a reorganisation between two of them leaves an answer whose halves
/// come off different branches, which is a run that never existed. It is
/// refused whole rather than served torn, and saying nothing is a legal
/// answer to every ask that reaches here.
fn gathered_a_few_at_a_time<T>(
    total: usize,
    per_take: usize,
    mut take: impl FnMut(usize, usize) -> (Vec<T>, bool),
    follows: impl Fn(&T, &T) -> bool,
) -> Vec<T> {
    let per_take = per_take.max(1);
    let mut all: Vec<T> = Vec::new();
    let mut at = 0;
    while at < total {
        let run = per_take.min(total.saturating_sub(at));
        let (some, more) = take(at, run);
        for one in some {
            if all.last().is_some_and(|before| !follows(before, &one)) {
                return Vec::new();
            }
            all.push(one);
        }
        if !more {
            break;
        }
        at = at.saturating_add(run);
    }
    all
}

impl Shared {
    /// A poisoned lock means a thread panicked while holding it. The release
    /// profile aborts on panic, so this cannot happen there; in a debug build
    /// carrying on with the data is more useful than a second panic.
    fn chain(&self) -> MutexGuard<'_, ChainStore> {
        self.chain.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes down that a visitor was turned away, and what said so.
    ///
    /// Both halves together, because they are one fact. Counting without
    /// saying is what this had for a while: `turned_away` moved on every
    /// refusal and `unanswered` was set only by the accept, so a node refusing
    /// everybody three descriptors short of the line had a rising count and an
    /// operator who was told nothing. "Turned away and counted" is true and is
    /// not the answer to whether anyone will learn the door is shut.
    ///
    /// The run is the figure that matters and it is kept here rather than in a
    /// caller's local, because there are six callers now and one of them used
    /// to own it.
    fn could_not_take_a_visitor(&self, because: &str) {
        self.turned_away.fetch_add(1, Ordering::Relaxed);
        let mut said = self.unanswered();
        let refusals = said
            .as_ref()
            .map_or(0, |held| held.refusals)
            .saturating_add(1);
        *said = Some(Unanswered {
            because: because.to_owned(),
            refusals,
        });
    }

    /// Says a visitor was let in, so what is written down is a door that is
    /// still shut rather than one that was.
    fn took_a_visitor(&self) {
        let mut said = self.unanswered();
        if said.is_some() {
            *said = None;
        }
    }

    fn peers(&self) -> MutexGuard<'_, HashMap<PeerId, Peer>> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn refusals(&self) -> MutexGuard<'_, Refusals> {
        self.refusals.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The allowance a connection from `host` spends against.
    ///
    /// It carries the mark that address left behind, which is what makes
    /// hanging up worth nothing. A connection with no address to speak of
    /// keeps only its own count; nothing on a socket reaches this node
    /// without an address, and refusing to answer at all would be a
    /// stranger's way of closing a door on somebody else.
    fn allowance_for(&self, host: Option<IpAddr>) -> Allowance {
        let Some(host) = host else {
            return Allowance::default();
        };
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(window) = windows.get(&host) {
            return Allowance::at(window);
        }
        if windows.len() >= MAX_ADDRESS_WINDOWS {
            return Allowance::at(&self.crowded_window);
        }
        let window = Arc::new(Mutex::new(Window::default()));
        let allowance = Allowance::at(&window);
        windows.insert(host, window);
        allowance
    }

    /// Drops the marks of addresses that have gone and finished spending.
    ///
    /// A mark is kept while anything still holds it, so a live connection
    /// never loses its count, and while the window it belongs to is still the
    /// current one, so an address that hung up a second ago cannot come back
    /// to a fresh allowance. Past both it is only a row in a table an
    /// attacker feeds.
    fn forget_spent_windows(&self, now: u64) {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        windows.retain(|_, window| still_counted(window, now));
    }

    /// Turns `host` away for a while.
    ///
    /// Only for peers that behaved badly, never for peers that merely belong
    /// somewhere else: a node on another network has done nothing wrong and
    /// may be on this one tomorrow.
    fn refuse(&self, host: IpAddr, now: u64) {
        self.refusals().refuse(host, now);
    }

    fn refuses(&self, host: IpAddr, now: u64) -> bool {
        self.refusals().refuses(host, now)
    }

    /// Whether one more connection from `host` is welcome.
    fn has_room_for(&self, host: Option<IpAddr>) -> bool {
        let peers = self.peers();
        if peers.len() >= MAX_PEERS {
            return false;
        }
        let Some(host) = host else {
            return true;
        };
        if !can_be_refused(host) {
            return true;
        }
        room_beside(peers.values().map(|peer| peer.host), host)
    }

    /// Whether one more connection somebody else opened is welcome.
    ///
    /// See [`MOST_FROM_OUTSIDE`] for the figure this leaves a node that has
    /// reached nobody.
    ///
    /// The ceiling above, less the slots this node still needs to reach the
    /// peers it chooses for itself. There was no number between
    /// [`TARGET_PEERS`] and [`MAX_PEERS`]: the accept loop and the dialling
    /// round asked the same question, so once the table was full the dialling
    /// round could not open anything, and the table filling was not something
    /// this node decided.
    ///
    /// Nothing about filling it is misbehaviour. Forty eight connections that
    /// greet, are welcomed and say a word every few seconds are never refused
    /// and never fall quiet, and `MAX_PER_HOST` is two per exact address, so
    /// that is twenty four addresses: a quarter of a /24, or twenty four out
    /// of one machine's IPv6 /64. Measured: the victim reported forty eight
    /// peers, knew thirty three addresses, and never dialled the one its
    /// operator gave it. For a node with no chain that hands the one
    /// irreversible choice it makes to whoever filled the table, because every
    /// claim it hears is theirs and it cannot reach anybody else.
    ///
    /// "Has this node room for another connection" is true, and it is the
    /// question the accept loop needed answered. The dialling round needed
    /// "has this node room for a connection it chooses".
    fn has_room_to_accept(&self, host: Option<IpAddr>) -> bool {
        let held = {
            let peers = self.peers();
            let dialled = peers.values().filter(|peer| peer.dialled).count();
            peers
                .len()
                .saturating_add(TARGET_PEERS.saturating_sub(dialled))
        };
        if held >= MAX_PEERS {
            return false;
        }
        self.has_room_for(host)
    }

    /// Ends one connection, leaving its own threads to clear it up.
    ///
    /// The socket is shut rather than the entry taken out of the table, so
    /// what happens next is what happens to any peer that goes away: the
    /// reading loop fails, the writer is freed, and the slot is given up once
    /// both are finished with it.
    fn hang_up(&self, id: PeerId) {
        if let Some(peer) = self.peers().get(&id) {
            let _ = peer.stream.shutdown(Shutdown::Both);
        }
    }

    fn book(&self) -> MutexGuard<'_, AddressBook> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn choosing(&self) -> MutexGuard<'_, Chooser> {
        self.choosing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn joining(&self) -> MutexGuard<'_, Progress> {
        self.joining.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn joined(&self) -> MutexGuard<'_, [Option<Prepared>; 2]> {
        self.joined.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn written(&self) -> MutexGuard<'_, Option<(Hash32, Located)>> {
        self.written.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn undertaking(&self) -> MutexGuard<'_, Option<Undertaking>> {
        self.probation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn filling_from(&self) -> MutexGuard<'_, Option<Turn>> {
        self.filling_from
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// What this node still owes on the ledger it was handed, given where its
    /// chain has reached.
    ///
    /// Worked out against the chain each time rather than kept up to date
    /// beside it. The chain moves in half a dozen places and the answer is one
    /// comparison, so a second record of it would only be a second thing to
    /// forget to move.
    ///
    /// The height is passed in because most callers hold the chain already,
    /// and taking it here would be a thread waiting on itself.
    fn probation_at(&self, height: Option<u64>) -> Option<Probation> {
        let mut undertaking = self.undertaking();
        let held = (*undertaking)?;
        let reached = height.unwrap_or(held.anchor);
        if reached >= held.settles_at {
            // Over, and over for good. From here the node can build a ledger
            // of its own, which is what replaces the file this came from.
            *undertaking = None;
            return None;
        }
        Some(Probation {
            anchor: held.anchor,
            settles_at: held.settles_at,
            reached,
        })
    }

    /// The same, for callers holding nothing.
    fn probation(&self) -> Option<Probation> {
        let height = self.chain().height();
        self.probation_at(height)
    }

    /// Writes down what this node has taken on by adopting an anchor.
    fn undertake(&self, anchor: u64, settles_at: u64, now: u64) {
        *self.undertaking() = Undertaking::resumed(anchor, settles_at, Some(anchor), now);
    }

    /// One round of the undertaking: where the chain has got to, and what to
    /// do about it having got no further.
    fn probation_round(&self, height: Option<u64>, peers: usize, now: u64) -> Option<Owed> {
        self.probation_at(height)?;
        let patience = self.stranding_patience.load(Ordering::Relaxed);
        let mut undertaking = self.undertaking();
        let held = undertaking.as_mut()?;
        let reached = height.unwrap_or(held.anchor);
        let mut owed = owed_this_round(held, reached, peers, patience, now);
        if let Owed::GivenUp(stranded) = &mut owed {
            stranded.out_of_reach = self.out_of_reach.load(Ordering::Relaxed);
        }
        Some(owed)
    }

    /// How a connection counts towards the two surfaces that count peers
    /// rather than connections.
    fn sender_for(&self, id: PeerId) -> Option<Sender> {
        let peers = self.peers();
        let peer = peers.get(&id)?;
        sender_of(peer.advertised, peer.host)
    }

    /// Hands `message` to one peer, if it is still there.
    ///
    /// Queued and never waited on, for the same reason a broadcast is.
    fn send_to(&self, id: PeerId, message: Message) {
        if let Some(peer) = self.peers().get(&id) {
            let _ = peer.outbound.try_send(message);
        }
    }

    fn seed_names(&self) -> MutexGuard<'_, Vec<String>> {
        self.seed_names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn threads(&self) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
        self.threads.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Why this node stopped following the chain, if it did.
    ///
    /// Taken past a poisoning like every other lock here. It used to be read
    /// with `.lock().ok()`, which answers `None` for ever once any thread has
    /// panicked while holding it, and this is the one answer a node owes
    /// whoever started it: without it a debug build says nothing at all about
    /// why it stopped, and whatever is watching goes on watching a node whose
    /// `running` is already false.
    fn outdated(&self) -> MutexGuard<'_, Option<Outdated>> {
        self.outdated.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Why this node cannot get on from where it stands, if it cannot.
    fn stranded(&self) -> MutexGuard<'_, Option<Stranded>> {
        self.stranded.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn unanswered(&self) -> MutexGuard<'_, Option<Unanswered>> {
        self.unanswered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes down what the last pass at the disk left behind, and stops the
    /// node when what it left can no longer be made good.
    ///
    /// The height is passed in because both callers hold the chain already,
    /// and taking it here would be a thread waiting on itself.
    ///
    /// A pass that wrote everything and refused nothing clears whatever was
    /// held, so a disk that comes back says so by this going quiet.
    fn note_writing(&self, wrote: &Wrote, reached: Option<u64>) {
        let Some(reached) = reached else { return };
        let behind = reached.saturating_add(1).saturating_sub(wrote.reaches);
        let mut held = self
            .unwritten
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Past saving already. Nothing later is a better account of it, and it
        // is the answer this node owes whoever started it.
        if held.as_ref().is_some_and(|held| !held.within_reach) {
            return;
        }
        if behind == 0 && wrote.refusing.is_none() {
            *held = None;
            return;
        }
        let Some((what, because)) = the_refusal_to_say(wrote.refusing.as_ref(), held.as_ref())
        else {
            return;
        };
        let within_reach = behind <= MAX_BEHIND;
        *held = Some(Unwritten {
            what,
            because,
            reached,
            written_through: wrote.reaches.checked_sub(1),
            blocks: behind,
            within_reach,
        });
        if !within_reach {
            self.running.store(false, Ordering::SeqCst);
        }
    }

    /// The same, for a write that is not the branch: the ledger this node
    /// starts from, and the blocks that writing one lets it drop.
    ///
    /// Those run on their own round of upkeep rather than beside a block being
    /// applied, so the heights are read here. Chain first and log second, as
    /// everywhere, and this must be called with neither held.
    fn note_refusal(&self, refusing: Refusing) {
        let tip = self.chain().height();
        let on_disk = {
            let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
            log.as_ref().map_or(0, |store| store.blocks.reaches())
        };
        self.note_writing(
            &Wrote {
                reaches: on_disk,
                refusing: Some(refusing),
            },
            tip,
        );
    }

    /// Writes down one read of this node's own disk that the disk refused.
    ///
    /// Called from inside the reads themselves, which hold the log. It takes
    /// nothing but its own lock, so it can be.
    ///
    /// The record is not cut, not rewritten and not acted on. Every caller
    /// goes on to answer around the record as it always did: a peer is sent
    /// the blocks that did read, a newcomer is sent the headers that did, and
    /// an explorer is told the height is missing. All this adds is that
    /// somebody is told, which is the whole of what was absent.
    fn could_not_read(&self, what: Reading, height: u64, because: &impl std::fmt::Display) {
        let mut held = self.unread.lock().unwrap_or_else(PoisonError::into_inner);
        let refusals = held.as_ref().map_or(0, |held| held.refusals);
        *held = Some(Unread {
            what,
            height,
            because: because.to_string(),
            refusals: refusals.saturating_add(1),
        });
    }

    /// Counts one block this build could not read, and who sent it.
    ///
    /// Nothing is held against the peer here or anywhere: it is carrying what
    /// its own chain carries, and this node is the one that cannot read it.
    fn cannot_judge(&self, from: Option<Sender>, version: u16, now: u64) {
        let mut met = self.unjudged.lock().unwrap_or_else(PoisonError::into_inner);
        count_unreadable(&mut met, from, version, now);
    }

    /// Counts one block refused for standing further ahead than this node's
    /// clock allows, and who sent it.
    ///
    /// Nothing is held against the peer here or anywhere. The block is valid
    /// to every node whose clock is right, and this node reverses the refusal
    /// by waiting; what a run of them says is about this machine.
    fn clock_looks_behind(&self, from: Option<Sender>, ahead: u64, now: u64) {
        let mut met = self
            .out_of_step
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        count_out_of_step(&mut met, from, ahead, now);
    }

    /// Writes down that this node refused the first block of its own network.
    ///
    /// Nobody sent it: it is in the binary. The only way to be past its date
    /// is for this machine's clock to be behind the day the network opened,
    /// and the node then has no chain, fails every peer's tip the same way,
    /// and cannot start. It used to do all of that without a word.
    fn own_first_block_refused(&self, ahead: u64, now: u64) {
        let mut met = self
            .out_of_step
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        met.own_first_block = true;
        count_out_of_step(&mut met, None, ahead, now);
    }

    /// Counts one showing of a chain's work that would not weigh, and who sent
    /// it.
    ///
    /// Beside the chooser rather than instead of it. The peer still loses its
    /// turn where it always did: this node was handed bytes it could not use,
    /// and whether that is the sender's fault is exactly what it cannot tell
    /// from one showing. What this adds is the reading it could never make
    /// before, which needs more than one showing to make.
    fn could_not_weigh(&self, from: Option<Sender>, because: &str, now: u64) {
        let mut met = self
            .unweighed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        count_unweighed(&mut met, from, because, now);
    }

    fn network(&self) -> NetworkId {
        self.params.network
    }

    /// Writes down what the chain now follows, taking the log lock itself.
    ///
    /// For callers that hold the chain and nothing else. Where the log is
    /// already held, call [`write_branch`] with it.
    /// Writes what a block did, and lets go of the bodies it makes safe to
    /// let go of.
    ///
    /// The chain is passed in already held, and taken mutably because the
    /// second half changes it: what it may stop keeping in memory depends on
    /// what has just reached the disk, so the two belong together.
    fn persist(&self, accepted: &Accepted, chain: &mut ChainStore) {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(log) = log.as_mut() {
            let wrote = write_branch(log, accepted, chain);
            // Bodies now on disk, and far enough back that no ordinary
            // reorganisation reads them. Said after writing, never before: a
            // body let go of before it was written is a body nobody has.
            chain.release_bodies(log.blocks.first_height(), log.blocks.reaches());
            self.note_writing(&wrote, chain.height());
        }
    }

    /// Writes this node's ledger down and drops the blocks below it, when the
    /// log has grown past what this node keeps.
    ///
    /// The ledger goes down first, and is on the disk before the blocks go. A
    /// machine that stops between the two leaves a log longer than it needed
    /// to be, which the first round of upkeep after the next start trims; the
    /// other order would leave a node with neither the blocks nor the ledger
    /// that replaces them.
    ///
    /// First in the order the disk sees, which is what [`Shared::keep_ledger`]
    /// is careful about and did not used to be: the ledger's bytes sat in the
    /// page cache while the compaction below synced the directory the two
    /// files share, so the deletion was made durable and the file that
    /// replaces what it deleted was not.
    fn trim_history(&self) {
        let keep = self.keep_bytes.load(Ordering::Relaxed);
        let over = {
            let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
            log.as_ref()
                .is_some_and(|store| store.blocks.bytes() > keep)
        };
        if !over {
            return;
        }
        let Some(at) = self.write_ledger() else {
            return;
        };

        // The chain is not held across writing the ledger, which is megabytes
        // and would stop the node for as long as it took. So it may have
        // reorganised in between, and the ledger just written would then stand
        // for a branch this node is no longer on. Dropping blocks against it
        // would leave a node believing an abandoned chain on its next start.
        //
        // Asked again here, and if it moved nothing is dropped: the next round
        // of upkeep writes a ledger for wherever the chain ended up.
        if !self.chain().agrees_with(&at) {
            return;
        }

        // Taken and let go of again, because saying what it refused means
        // reading the chain, and this node takes the chain before the log.
        let refusing = {
            let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(log) = log.as_mut() else { return };
            // A log that no longer reaches that height was rewritten by a
            // reorganisation between the two checks above, and dropping
            // against it would throw away blocks this node still holds.
            if !log.blocks.holds(at.height) {
                return;
            }

            let held = u64::try_from(log.blocks.len()).unwrap_or(u64::MAX);
            let cut = cut_for(at.height, held, log.blocks.bytes(), keep);
            if cut <= log.blocks.first_height() {
                return;
            }
            log.blocks
                .keep_from(cut)
                .err()
                .map(|error| Refusing::at(Writing::Ledger, &error))
        };
        // A node that cannot drop what it has already written down is a node
        // whose disk only grows, which on the disk this fails on is the whole
        // of the trouble. It used to be the one write here that said nothing
        // at all.
        if let Some(refusing) = refusing {
            self.note_refusal(refusing);
        }
    }

    /// Writes this node's ledger down, returning the height it stands for.
    ///
    /// Separate from dropping the blocks below it, because the two are two
    /// steps and a machine can stop between them. Writing first is what makes
    /// that survivable: what is left is a ledger and more blocks than needed,
    /// rather than neither.
    ///
    /// Asked for once a round while the log is over its budget, and the answer
    /// only changes when the tip does, so a tip already written for is
    /// answered from what was written. Everything below then happens once a
    /// block instead of once a second.
    ///
    /// What is left under the chain lock is the ledger being unwound to the
    /// burial, which is the chain's own work and nothing else's. The headers,
    /// the forest paths, the encoding and the write itself run with the chain
    /// let go of; they used to run with it held, and the node stopped for
    /// them.
    fn write_ledger(&self) -> Option<Located> {
        let tip = self.chain().tip()?;
        if let Some((for_tip, at)) = *self.written() {
            if for_tip == tip {
                return Some(at);
            }
        }
        let ground = self.ground_for(Joining::Ledger)?;
        let anchor_height = ground.at.height.checked_sub(self.params.burial)?;
        let bytes = self.build_join(Joining::Ledger, &ground)?;
        let anchor = self.header_off_disk(anchor_height)?;
        if !self.keep_ledger(&bytes) {
            return None;
        }
        let at = Located::new(anchor_height, anchor.id());
        // What is recorded is the tip this file was built against, not the tip
        // now: the chain may have moved while it was being built, and then the
        // next round finds a tip it has nothing written for and writes again.
        *self.written() = Some((ground.at.id, at));
        Some(at)
    }

    /// Keeps the ledger this node was handed, so it can start again without
    /// one.
    ///
    /// Written whole, to a name beside the old one, and moved into place. A
    /// process that stops partway leaves the previous file untouched rather
    /// than half of a new one, which for a file a node cannot start without is
    /// the difference between an interrupted write and a node that never comes
    /// back.
    ///
    /// This says nothing until the disk has said it, which is what
    /// [`write_beside_and_move`] adds and what a rename on its own never
    /// bought. The rename covers a process that stops; it does not cover a
    /// machine that stops. `std::fs::write` returned with the bytes in the
    /// page cache, and the rename could reach the platter ahead of them, so a
    /// power cut left `ledger.dat` at its full length holding whatever those
    /// blocks held before. That file does not decode, `Node::open` refuses to
    /// start over it, and by then [`Shared::trim_history`] has already deleted
    /// the blocks below it: the node does not start, and no later start does
    /// either, because there is nothing left to start from. The ordering in
    /// `trim_history` is a statement about the disk only if this is.
    ///
    /// Called with no lock held, because saying what the disk refused takes
    /// the chain and then the log.
    fn keep_ledger(&self, bytes: &[u8]) -> bool {
        let Some(directory) = self.directory.as_ref() else {
            return false;
        };
        if let Err(error) = write_beside_and_move(&directory.join(HANDED_LEDGER), bytes) {
            self.note_refusal(Refusing::at(Writing::Ledger, &error));
            return false;
        }
        true
    }

    /// How far this node's branch runs past the first position in `locator`
    /// this node agrees with, which is the highest only on a locator ordered
    /// from the tip down. See `ChainStore::chain_after`, which this answers
    /// out of memory and the disk together.
    ///
    /// Memory first, which answers whenever the peer is anywhere near this
    /// node's tip. A peer far behind names heights this node no longer holds
    /// an identifier for, and the answer for those is on the disk: without
    /// that, the only position both sides could agree on would be one of the
    /// few this node keeps, and a peer would be told to start again from far
    /// behind where it had already reached.
    fn chain_after(&self, locator: &[Located], max: u64) -> (u64, u64) {
        let (reaches, agreed) = {
            let chain = self.chain();
            let reaches = chain.height().map_or(0, |tip| tip.saturating_add(1));
            let agreed = locator
                .iter()
                .find(|entry| chain.agrees_with(entry))
                .map(|entry| entry.height);
            (reaches, agreed)
        };

        // The log is taken and let go of once per entry rather than held for
        // the walk. A locator carries up to `MAX_LOCATOR` positions and each
        // one read here is a whole block off the disk decoded and hashed, so
        // the walk held the disk for megabytes while a thread with the chain
        // in hand waited to write a block it had just validated. There is no
        // run to tear: each entry is its own question, and the answer to it
        // does not depend on what the entry before it found.
        let agreed = agreed.or_else(|| {
            locator.iter().find_map(|entry| {
                // A refusal here is not an entry the peer and this node
                // disagree about. It is this node failing to look, and the two
                // used to be the same answer: the position was passed over,
                // the walk ran out of entries, and the peer was told from zero,
                // which is this node's disk reported as a fact about somebody
                // else's chain.
                let block = self.block_off_disk(entry.height)?;
                (block.id() == entry.id).then_some(entry.height)
            })
        });

        // Where this node can start, for a peer it agrees with about nothing.
        // That is a newcomer, whose locator is empty, and it is the one asker
        // that has to be told the truth here: it has no chain of its own to
        // fall back on and no other way to learn what this node can supply.
        //
        // Zero was the answer, worked out from the height the branch reaches
        // and never from the heights this node can still produce a body for. A
        // node that has written its ledger down holds no body below it, which
        // is every node past its disk budget and the whole reason a node's
        // disk does not grow with the chain. So it pointed a newcomer at the
        // first block, was asked for it, and answered with nothing, which from
        // the far end is indistinguishable from a peer that stopped talking:
        // the newcomer waited out its patience, asked again, was pointed at
        // the first block again, and did that for the rest of its life.
        //
        // The same mistake as the one the walk above was fixed for, one step
        // further on: this node's disk stated as a fact about somebody else's
        // chain. What it can hand over starts where its log does.
        let floor = {
            let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
            log.as_ref().map_or(0, |store| store.blocks.first_height())
        };
        let from = agreed.map_or(floor, |height| height.saturating_add(1));
        (from, reaches.saturating_sub(from).min(max))
    }

    /// The blocks the followed branch carries at `heights`, in that order.
    ///
    /// A few at a time, with both locks let go of between them. What each take
    /// does is two passes so that neither lock is held over the other's work:
    /// memory first, with the chain held for the length of a few clones and let
    /// go before any disk is touched, then the log, which holds the branch in
    /// order of height and answers for everything older.
    ///
    /// Order is the point. A peer catching up applies what arrives as it
    /// arrives, and a block whose parent has not landed is dropped, so a batch
    /// delivered out of order is a batch mostly thrown away.
    fn blocks_at(&self, heights: &[u64]) -> Vec<Block> {
        gathered_a_few_at_a_time(
            heights.len(),
            BLOCKS_PER_HOLD,
            |at, run| {
                let want = heights.get(at..at.saturating_add(run)).unwrap_or_default();
                (self.blocks_under_one_hold(want), true)
            },
            // Only heights that came back next to each other can be checked,
            // and those are the ones a peer applies as a chain. Two of them
            // that do not link came off different branches, which is an
            // answer this node never held.
            |before, after| {
                after.header.height != before.header.height.saturating_add(1)
                    || after.header.previous == before.id()
            },
        )
    }

    /// A few of those blocks, with each of the two locks taken once and let go
    /// of before this returns.
    ///
    /// The bound is written here rather than at the caller because this is the
    /// function that holds the locks. It bounds both: the memory pass clones
    /// what it finds, and `MAX_REQUESTED` blocks cloned under the chain is
    /// sixteen megabytes of copying with everything else stopped.
    fn blocks_under_one_hold(&self, heights: &[u64]) -> Vec<Block> {
        let heights = heights.get(..BLOCKS_PER_HOLD).unwrap_or(heights);
        let mut found: Vec<Option<Block>> = {
            let chain = self.chain();
            heights
                .iter()
                .map(|height| chain.block_at(*height).cloned())
                .collect()
        };

        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(log) = log.as_ref() {
            for (slot, height) in found.iter_mut().zip(heights.iter()) {
                if slot.is_none() {
                    // A height this log does not hold and a height it holds
                    // and will not produce leave the same gap in the answer,
                    // and the peer cannot tell them apart either way. The
                    // difference is whose fault it is, and this is where it
                    // is known.
                    *slot = match log.blocks.read_at(*height) {
                        Ok(found) => found,
                        Err(error) => {
                            self.could_not_read(Reading::Blocks, *height, &error);
                            None
                        }
                    };
                }
            }
        }
        found.into_iter().flatten().collect()
    }

    /// The paths for the places in the cold set a peer asked about, in the
    /// order it asked about them.
    ///
    /// Answered by whoever can, which is the point. A node that kept the whole
    /// set rebuilds a path from the leaves it holds; a node following an owner
    /// already holds the path for that owner's notes and hands it over as it
    /// stands. Neither has to know which of the two it is, because the cold
    /// set answers the same question for both. A node that is neither says so
    /// with nothing where the path would be, which is not the same as saying
    /// nothing.
    ///
    /// The chain is taken here and let go of again rather than held across the
    /// whole reaction, which is why this is not answered where the message was
    /// read. A path is a walk up one tree, sixty four hashes at the very most,
    /// so the whole of a full request is measured in microseconds; what it must
    /// not do is queue behind, or in front of, a block being validated.
    fn place(&self, positions: &[u64]) -> Vec<Placed> {
        let chain = self.chain();
        let cold = chain.state().cold();
        positions
            .iter()
            .map(|position| Placed {
                position: *position,
                proof: cold.proof_of(*position),
            })
            .collect()
    }

    fn asking(&self) -> MutexGuard<'_, Asking> {
        self.asking.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes down what a peer said it keeps, beside the connection and in the
    /// book.
    ///
    /// Beside the connection so a wallet needing a path knows who to ask now.
    /// In the book so one that comes back tomorrow, needing a path and
    /// connected to nobody who can build one, has somewhere to knock. Neither
    /// is trusted for anything: what an archivist hands over is checked, and
    /// this only decides who is asked first.
    fn note_what_it_keeps(&self, id: PeerId, advertised: Option<SocketAddr>, archives: bool) {
        if let Some(peer) = self.peers().get_mut(&id) {
            peer.archives = archives;
            // Called once the introduction has been read, which is the moment
            // this connection is safe to send anything else down.
            peer.greeted = true;
        }
        if let Some(address) = advertised {
            self.book().keeps_the_cold_set(&address, archives);
        }
    }

    /// Connections worth asking where a fallen note sits, and how many of them
    /// said they keep the whole set.
    ///
    /// Peers that claim the service, when there are any. When there are none,
    /// everybody, and the reason is that the claim is only a claim in the
    /// other direction too: a node that never said it archives still holds the
    /// path for every note of an owner it follows, which is what a second
    /// wallet on the same key is. Asking costs one small message each and is
    /// answered plainly either way, and it beats telling somebody their money
    /// is out of reach without having asked anyone.
    fn worth_asking(&self) -> (Vec<PeerId>, usize) {
        let peers = self.peers();
        let archivists: Vec<PeerId> = peers
            .iter()
            .filter(|(_, peer)| peer.archives)
            .map(|(id, _)| *id)
            .collect();
        let archiving = archivists.len();
        if archiving > 0 {
            return (archivists, archiving);
        }
        (peers.keys().copied().collect(), 0)
    }

    /// Takes an answer about where fallen notes sit, keeping only the paths
    /// that fold.
    ///
    /// Only from a connection this node asked, and only about the places it
    /// asked about. An answer from anybody else is a stranger handing this
    /// node work to do with the chain in hand, which is what the join
    /// collector had to be taught to refuse for the same reason.
    ///
    /// The chain is taken between two turns of this node's own state rather
    /// than while it is held, because the order the locks are taken in is the
    /// whole of what keeps two threads from waiting on each other.
    fn take_placed(&self, from: PeerId, placed: &[Placed]) {
        let checking: Vec<(u64, Hash32, ForestProof)> = {
            let mut asking = self.asking();
            if !asking.asked.contains(&from) {
                return;
            }
            asking.answered.insert(from);
            placed
                .iter()
                .filter_map(|entry| {
                    let leaf = *asking.wanted.get(&entry.position)?;
                    Some((entry.position, leaf, entry.proof.clone()?))
                })
                .collect()
        };
        if checking.is_empty() {
            return;
        }
        let folded: Vec<(u64, ForestProof, bool)> = {
            let chain = self.chain();
            let cold = chain.state().cold();
            checking
                .into_iter()
                .map(|(position, leaf, proof)| {
                    let holds = cold.verify(position, leaf, &proof);
                    (position, proof, holds)
                })
                .collect()
        };
        let mut asking = self.asking();
        for (position, proof, holds) in folded {
            if holds {
                asking.found.insert(position, proof);
            } else {
                asking.refused = asking.refused.saturating_add(1);
            }
        }
    }

    /// Takes addresses out of the book, so they are not dialled again.
    fn forget(&self, addresses: &[SocketAddr]) {
        if addresses.is_empty() {
            return;
        }
        let mut book = self.book();
        for address in addresses {
            book.remove(address);
        }
    }

    fn remember(&self, addresses: &[SocketAddr]) {
        if addresses.is_empty() {
            return;
        }
        let mut book = self.book();
        for address in addresses {
            if *address != self.address {
                book.insert(*address);
            }
        }
    }

    /// Hands `message` to every peer but `except`.
    ///
    /// Queued rather than written here, so one unresponsive peer cannot hold up
    /// the thread that is announcing a block to everyone else. The queue is
    /// bounded and this never waits on it: a peer too far behind to take the
    /// message loses it and asks for what it missed later, which is a better
    /// outcome than letting it decide how much memory this node spends.
    /// Hands `message` to every peer but one, and says how many took it.
    ///
    /// The count is peers whose outbound queue accepted it, which is as far as
    /// this node can say synchronously and is a great deal further than
    /// "somebody was connected". Callers that only broadcast ignore it; the
    /// one that has to tell a person whether their money left does not.
    fn broadcast(&self, except: Option<PeerId>, message: &Message) -> usize {
        let mut taken = 0usize;
        for (id, peer) in self.peers().iter() {
            if Some(*id) == except {
                continue;
            }
            if !peer.worth_speaking_to() {
                continue;
            }
            // A full queue and a gone peer are both left alone: the first
            // catches up by asking, and the second is already being cleared up
            // by the thread that was reading from it.
            if peer.outbound.try_send(message.clone()).is_ok() {
                taken = taken.saturating_add(1);
            }
        }
        taken
    }
}

/// Lays down the network's first block, so a node that has never spoken to
/// anyone still knows where the story starts.
///
/// A network without one pinned leaves this alone, which is what tests and
/// unnamed networks do.
///
/// It goes into the log as well as into memory. The log is the followed branch
/// in order of height with nothing left out, and a first block held only in
/// memory breaks that on the very first restart: the log would start at height
/// one, which is a log this node cannot replay, so it would set aside every
/// block it had and start over. A node mining a real network lost its chain
/// every time it was restarted, and every test here ran on a network with no
/// first block to pin, so nothing said so.
/// Says how far ahead of `now` the first block stood, when that is why it was
/// refused.
///
/// The refusal used to be dropped whole. It is the one that costs a node its
/// whole start: with no chain it fails every peer's tip the same way, so it
/// keeps no peer, reaches no height, and prints the line a node waiting for
/// its first peer prints. Nothing anywhere said the word clock.
fn open_the_chain(
    chain: &mut ChainStore,
    log: Option<&mut BlockLog>,
    params: ConsensusParams,
    now: u64,
) -> Option<u64> {
    // Only for a network that pins its first block. An unnamed one, which is
    // what tests use, starts from whatever it is given.
    if params.genesis.is_none() || !chain.is_empty() {
        return None;
    }
    let block = genesis::block(params.network)?;
    if let Err(error) = chain.add_block(block.clone(), now) {
        // Every other way of refusing the block in this binary is a defect in
        // the binary and no clock would mend it. This one is a machine dated
        // before the day the network opened, which the person running it can
        // fix in a minute once somebody says so.
        return match error {
            ChainError::InvalidBlock {
                source: BlockError::TimestampTooFarAhead { timestamp, .. },
                ..
            } => Some(timestamp.saturating_sub(now)),
            _ => None,
        };
    }
    if let Some(log) = log {
        if log.is_empty() {
            let _ = log.append(&block);
        }
    }
    None
}

/// A number this node calls itself by, for one run.
///
/// Only ever compared for equality, so what matters is that two nodes do not
/// draw the same one. If the system refuses to give randomness, the clock is
/// a poor substitute but a harmless one: the worst case is failing to notice
/// a connection to oneself, which is what happened before this existed.
fn fresh_nonce() -> u64 {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_ok() {
        return u64::from_le_bytes(bytes);
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |since| u64::try_from(since.as_nanos()).unwrap_or(1))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default()
}

/// A running node: a listener, its peers, and the chain they agree on.
pub struct Node {
    shared: Arc<Shared>,
    address: SocketAddr,
}

impl Node {
    /// Starts a node that keeps nothing across a restart.
    pub fn bind(params: ConsensusParams, address: SocketAddr) -> Result<Self, NodeError> {
        Self::start(
            params,
            address,
            ChainStore::new(params),
            None,
            AddressBook::new(),
            None,
            None,
            None,
            None,
        )
    }

    /// Starts a node backed by `directory`, replaying whatever it already holds.
    ///
    /// Replay revalidates every block rather than trusting the file. That is
    /// slower than reading back a saved state, and it is the honest thing to do
    /// while no saved state is signed for: a node should not believe its own
    /// disk any more than it believes a stranger.
    pub fn open(
        params: ConsensusParams,
        address: SocketAddr,
        directory: impl Into<PathBuf>,
    ) -> Result<(Self, Restored), NodeError> {
        Self::open_with(params, address, directory, false, &[])
    }

    /// The same, keeping track of where these owners' notes go when they fall
    /// and holding their proofs current.
    ///
    /// This is what a wallet asks for. The owners have to be named before the
    /// chain is replayed, because what is learned is learned as notes fall.
    pub fn open_watching(
        params: ConsensusParams,
        address: SocketAddr,
        directory: impl Into<PathBuf>,
        owners: &[PublicKey],
    ) -> Result<(Self, Restored), NodeError> {
        Self::open_with(params, address, directory, false, owners)
    }

    /// The same, keeping the cold set so it can answer with proofs.
    pub fn open_archiving(
        params: ConsensusParams,
        address: SocketAddr,
        directory: impl Into<PathBuf>,
    ) -> Result<(Self, Restored), NodeError> {
        Self::open_with(params, address, directory, true, &[])
    }

    // Every step here is a decision about a file already on the disk, and each
    // one is written where it is because of what the step before it left
    // behind: the ledger before the replay, the replay before the cut, the cut
    // before the headers. Splitting it would move those orderings into a call
    // graph, where the next person to change one cannot see the others.
    #[allow(clippy::too_many_lines)]
    fn open_with(
        params: ConsensusParams,
        address: SocketAddr,
        directory: impl Into<PathBuf>,
        archiving: bool,
        owners: &[PublicKey],
    ) -> Result<(Self, Restored), NodeError> {
        let directory = directory.into();
        let lock = DirectoryLock::acquire(&directory)?;
        let (mut log, recovered) = BlockLog::open(&directory).map_err(in_file(BLOCK_LOG))?;

        let mut chain = if archiving {
            ChainStore::archiving(params)
        } else {
            ChainStore::new(params)
        };
        // Named before anything is replayed: where a note falls is learned as
        // it falls, and there is no going back for it afterwards.
        for owner in owners {
            chain.watch_owner(*owner);
        }
        let now = unix_now();
        // One block at a time, straight off the disk. Reading them all into a
        // vector first would make the largest allocation this process ever
        // performs out of a chain it looks at once and in order.
        //
        // Anything but a plain extension ends the replay. The log is meant to
        // be the followed branch in order of height, and that is what makes a
        // record's position its height and lets a node find a block it has
        // forgotten. A record that does not extend the branch breaks that, so
        // the log is cut there and the rest is asked for again. It costs a
        // partial resync once, on a node whose log was written before this
        // rule existed or interrupted in the middle of a reorganisation.
        //
        // Not every end is a cut. A refusal about this build or this command
        // line stops the start with the disk as it was, a record that will
        // not decode is left where it is, and a read the disk refuses stops
        // the start; each is said where it is met below.
        //
        // A node handed a ledger cannot read its way back to it, because the
        // blocks it holds build on a ledger it never applied. So it keeps the
        // ledger it was handed, and starts from that. Without it such a node
        // could only start while an archivist happened to be reachable, which
        // would tie every node that ever joined to the archive service staying
        // up for the rest of its life.
        // A file that is there and will not be taken is not the same news as
        // no file at all, and reading the two the same way cost a node its
        // whole history. The replay would start at block zero, the log begins
        // above that on any node that has written a ledger, and the gap
        // between them is read as a log that leads nowhere and cut to nothing.
        //
        // So this stops instead, with the disk untouched and the reason said.
        // A copy of the file can be put back; without one, deleting it has the
        // node join the chain again, which costs the stored blocks and keeps
        // the headers and the book. Neither is possible once the blocks have
        // been deleted, which is why `keep_ledger` waits for the disk before
        // `trim_history` deletes any. Every node writes this file as it runs,
        // so what used to be at stake was not only a node that joined a chain:
        // a rules update that refused a node's own stored ledger would have
        // emptied it.
        //
        // Staged files left by a machine that stopped mid write go now: the
        // ledger, and the two header logs a merge writes beside. They are
        // bytes under names nothing reads, and this is the one moment they are
        // certainly nobody's, because the directory lock above is held and no
        // thread of this node has started. Swept here rather than in the store
        // for exactly that reason: anything else that opens a header log is a
        // reader, and a reader that deleted these would be deleting a merge
        // this node is in the middle of.
        for name in [HANDED_LEDGER, HEADER_LOG, FILLING_LOG] {
            let _ = std::fs::remove_file(staged_beside(&directory.join(name)));
        }
        for name in [HEADER_LOG, FILLING_LOG] {
            let _ = std::fs::remove_file(directory.join(format!("{name}.hold")));
        }
        // An archivist does not start from a ledger. The archive, every leaf of
        // the cold set, is held in memory and built by reading blocks as they
        // are applied, and a ledger carries the cold set as sixty four roots:
        // adopting one left a node holding the roots and none of the leaves,
        // which it then said on every handshake while its operator was told
        // at every start that it kept the whole set. So it reads every block
        // from the first, whatever ledger lies beside them, and where its
        // blocks do not begin at the first it cannot build the archive at all
        // and says so rather than starting as something else.
        let handed = if archiving {
            if !log.is_empty() && log.first_height() > 0 {
                return Err(NodeError::CannotArchive {
                    from: log.first_height(),
                });
            }
            None
        } else {
            read_handed_ledger(&directory, &params)?
        };
        let handed = match handed {
            Some((state, recent, anchor, promised)) => {
                chain
                    .adopt(state, &recent)
                    .map_err(|error| NodeError::UnusableLedger {
                        because: format!("{HANDED_LEDGER} could not be adopted: {error}"),
                    })?;
                Some((recent, anchor, promised))
            }
            None => None,
        };
        let from = handed
            .as_ref()
            .and_then(|(recent, _, _)| recent.last())
            .map(|tip| tip.height.saturating_add(1));

        // Where the replay has to start: after the ledger if there is one, and
        // at the first block if there is not.
        let start = from.unwrap_or(0);

        // The log has to reach the point the ledger leaves off. It may begin
        // before it, which is what a node that was stopped between writing its
        // ledger and dropping the blocks below it looks like: those blocks are
        // simply passed over. It may not begin after it, because then nothing
        // joins the two and there is no chain to be had.
        let rejoining = !log.is_empty() && log.first_height() > start;
        let mut applied = 0usize;
        let mut unreadable = false;
        if !rejoining {
            // From the ledger's tip rather than from the first record: what
            // is below it is in the ledger already, and on a node that keeps
            // every block, reading them to pass them over was a start that
            // grew with the chain.
            for block in log.replay_from(start) {
                let block = match block {
                    Ok(block) => block,
                    // The disk refusing a read says nothing about what is
                    // written there, and cutting the log for it deleted every
                    // block past a read that might have worked a second later.
                    // The same answer `BlockLog::open` gives: a start fails
                    // only over a file it could not reach.
                    Err(StoreError::Io(source)) => {
                        return Err(NodeError::File {
                            file: BLOCK_LOG,
                            source: StoreError::Io(source),
                        })
                    }
                    // A record that will not decode. Recovery leaves such a
                    // record and everything after it on the disk, unread, and
                    // this was the one place the same byte was met by a cut
                    // instead: which of the two it met depended on whether the
                    // index beside the log happened to be in line.
                    Err(_) => {
                        unreadable = true;
                        break;
                    }
                };
                // Already in the ledger this node started from.
                if block.header.height < start {
                    continue;
                }
                // Judged against its own timestamp, not against the clock.
                //
                // These are blocks this node validated and wrote down itself.
                // Every rule is checked again, and one of them, the drift
                // ceiling, is a fact about the reader rather than about the
                // block: a header cannot sit more than the drift ahead of its
                // own timestamp, so asking it this way asks a question the
                // block already answered.
                //
                // On the wall clock it was the one rule whose answer could
                // change while the block did not. A machine whose clock steps
                // back, which is an NTP correction or a dead battery, refused
                // its own blocks from here, `break` cut the replay, and
                // everything past that point was counted refused and dropped
                // from the log. `Restored::refused` says what was cut is asked
                // for again; the peers offer it back and this node refuses it
                // again for the same reason, so a machine with a wrong clock
                // was stuck at that height for as long as the clock stayed
                // wrong. The same shape as `ChainStore::reapply`, one crate up.
                let its_own_clock = block.header.timestamp;
                let height = block.header.height;
                match chain.add_block(block, its_own_clock) {
                    Ok(Accepted::Extended) => applied = applied.saturating_add(1),
                    // A refusal about this build or this command line rather
                    // than about the block stops the start here, with nothing
                    // cut. The same build refuses the same blocks from the
                    // network, so what a cut would have asked for again could
                    // never have been taken back, and the blocks it deleted
                    // were valid ones some other build had written.
                    Err(error) => {
                        if let Some(stop) = about_the_reader(height, applied == 0, &error) {
                            return Err(stop);
                        }
                        break;
                    }
                    Ok(_) => break,
                }
            }
        }
        let read_again = if unreadable {
            Some(log.read_again().map_err(in_file(BLOCK_LOG))?)
        } else {
            None
        };
        let reached = start.saturating_add(applied as u64);
        let refused = if rejoining {
            0
        } else {
            // Only the records at or past where the replay began were ever
            // going to be applied. The ones before it were passed over, and
            // passing over is not refusing.
            usize::try_from(log.reaches().saturating_sub(start.max(log.first_height())))
                .unwrap_or(0)
                .saturating_sub(applied)
        };
        // Nothing to cut when nothing was refused and the log is not being set
        // aside, and then this cuts nothing: the log already ends at `reached`.
        log.keep_below(reached).map_err(in_file(BLOCK_LOG))?;
        // The blocks below the ledger stay. They were once dropped here, on
        // the reading that a log beginning below the ledger was a node
        // stopped before it could drop them, which was true while the trim
        // dropped everything below the ledger. It keeps what its budget
        // affords now (`cut_for`), so this was cutting what the running node
        // kept on purpose: every restart left a node holding nothing below
        // its anchor, with a budget it had been keeping. A log over its budget
        // is trimmed by the first round of upkeep, by the budget's rule.

        // The network's first block, for a node that has nothing. After the
        // replay rather than before it: a chain that already holds the first
        // block turns the first record replayed into a duplicate, which is not
        // an extension, which ends the replay and sets aside everything this
        // node had.
        // Nothing to record it on yet: this runs before the node exists. The
        // same refusal is met again inside `Node::start`, which has somewhere
        // to write it down.
        let _ = open_the_chain(&mut chain, Some(&mut log), params, now);

        // Headers are kept whatever happens to the blocks. A node updated from
        // a version that had no header log has an empty one and a chain, so it
        // is filled in from the blocks that are still there. Everything older
        // than those is gone, which costs this node the ability to answer a
        // newcomer about that stretch and nothing else.
        let mut headers = HeaderLog::open(&directory).map_err(in_file(HEADER_LOG))?;
        let headers_set_aside = headers_the_store_will_not_stand_behind(&headers);
        let CaughtUp {
            dropped: headers_dropped,
            replaced: headers_replaced,
            unread,
        } = catch_up_headers(&mut headers, &log);
        let mut forest = HeaderTree::open(&directory).map_err(in_file(HEADER_TREE))?;
        // A refusal here is not lost by being dropped: nothing has been
        // started yet that could carry it, and the first block this node
        // applies runs the same pass again and reports what it finds.
        let _ = grow_forest(&mut forest, &headers);
        let mut filling =
            HeaderLog::open_named(&directory, FILLING_LOG).map_err(in_file(FILLING_LOG))?;
        // What was being collected is only useful while it leads up to the
        // oldest header held. A restart in the middle of a reorganisation, or
        // after the chain moved on, can leave it pointing nowhere.
        if headers.first_height() == 0 || filling.first_height() != 0 {
            let _ = filling.clear();
        }
        let log = Store {
            blocks: log,
            headers,
            forest,
            filling,
            filling_epoch: 0,
        };

        // What this node still owes on a ledger it was handed, carried across
        // the restart. Worked out after the replay, because how much of the
        // burial it has already validated is exactly what the replay settles.
        let probation = handed.and_then(|(_, anchor, promised)| {
            Undertaking::resumed(anchor, promised, chain.height(), now)
        });

        let book = AddressBook::load(&directory);
        // What reading the log again after the replay found, where the replay
        // met a record it could not read, in place of what the open found.
        let (discarded_bytes, left_in_place, unreadable) = match read_again {
            Some(found) => (
                recovered
                    .discarded_bytes
                    .saturating_add(found.discarded_bytes),
                found.left_in_place,
                found.unreadable,
            ),
            None => (
                recovered.discarded_bytes,
                recovered.left_in_place,
                recovered.unreadable,
            ),
        };
        let restored = Restored {
            blocks: applied,
            refused,
            discarded_bytes,
            left_in_place,
            unreadable,
            blocks_set_aside: recovered.blocks_set_aside,
            rejoining,
            headers_set_aside,
            headers_dropped,
            headers_replaced,
            addresses: book.len(),
        };

        let node = Self::start(
            params,
            address,
            chain,
            Some(log),
            book,
            Some(directory),
            Some(lock),
            probation,
            unread,
        )?;
        Ok((node, restored))
    }

    #[allow(clippy::too_many_arguments)]
    fn start(
        params: ConsensusParams,
        address: SocketAddr,
        chain: ChainStore,
        log: Option<Store>,
        book: AddressBook,
        directory: Option<PathBuf>,
        lock: Option<DirectoryLock>,
        probation: Option<Undertaking>,
        unread: Option<Unread>,
    ) -> Result<Self, NodeError> {
        let listener = TcpListener::bind(address)?;
        let address = listener.local_addr()?;

        let shared = Arc::new(Shared {
            params,
            address,
            nonce: fresh_nonce(),
            chain: Mutex::new(chain),
            log: Arc::new(Mutex::new(log)),
            book: Mutex::new(book),
            choosing: Mutex::new(Chooser::new()),
            seed_names: Mutex::new(Vec::new()),
            names_looked_up_at: AtomicU64::new(0),
            book_written_at: AtomicU64::new(u64::MAX),
            directory,
            keep_bytes: AtomicU64::new(KEEP_BLOCK_BYTES),
            _lock: lock,
            peers: Mutex::new(HashMap::new()),
            windows: Mutex::new(HashMap::new()),
            crowded_window: Arc::new(Mutex::new(Window::default())),
            refusals: Mutex::new(Refusals::new()),
            joined: Mutex::new([None, None]),
            written: Mutex::new(None),
            joining: Mutex::new(Progress::Idle),
            join_asked_again_at: AtomicU64::new(0),
            probation: Mutex::new(probation),
            stranding_patience: AtomicU64::new(STRANDING_PATIENCE),
            out_of_reach: AtomicU64::new(0),
            stranded: Mutex::new(None),
            filling_from: Mutex::new(None),
            threads: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            running: AtomicBool::new(true),
            winding_down: AtomicBool::new(false),
            outdated: Mutex::new(None),
            unwritten: Mutex::new(None),
            unread: Mutex::new(unread),
            unanswered: Mutex::new(None),
            turned_away: AtomicU64::new(0),
            mended_nodes: AtomicU64::new(0),
            proofs_asked_for: AtomicU64::new(0),
            unsaved_book: Mutex::new(None),
            unjudged: Mutex::new(Unreadable::default()),
            unweighed: Mutex::new(Unweighed::default()),
            out_of_step: Mutex::new(OutOfStep::default()),
            asking: Mutex::new(Asking::default()),
        });

        {
            // Chain first and log second, here as everywhere. A node started
            // with no directory has no log to write the first block to, which
            // is what `Node::bind` does and what tests use.
            let mut chain = shared.chain();
            let now = unix_now();
            let (has_log, ahead) = {
                let mut log = shared.log.lock().unwrap_or_else(PoisonError::into_inner);
                let blocks = log.as_mut().map(|store| &mut store.blocks);
                let present = blocks.is_some();
                (present, open_the_chain(&mut chain, blocks, params, now))
            };
            if let Some(ahead) = ahead {
                shared.own_first_block_refused(ahead, now);
            }
            // A chain with a log behind it may let go of the bodies it has
            // written; one without has nowhere to read them back from, so it
            // keeps every one it might still need.
            if has_log {
                chain.reads_bodies_from(Arc::new(FromLog(Arc::downgrade(&shared))));
            }
        }

        // Asked for, for the reason set out in `attach_peer`: a machine that
        // will not make a thread is answered rather than panicked on. Here it
        // is a node that does not start, which the caller can say out loud.
        let accepting = Arc::clone(&shared);
        let accept = thread::Builder::new()
            .name("cairn-accept".to_owned())
            .spawn(move || accept_loop(&accepting, &listener))?;
        let keeping = Arc::clone(&shared);
        let maintain = match thread::Builder::new()
            .name("cairn-upkeep".to_owned())
            .spawn(move || maintenance_loop(&keeping))
        {
            Ok(maintain) => maintain,
            Err(error) => {
                // The one above is already running and owns the listener, so
                // it is told to stop and waited for rather than left behind a
                // node that never came into being.
                shared.running.store(false, Ordering::SeqCst);
                let _ = accept.join();
                return Err(error.into());
            }
        };
        {
            let mut threads = shared.threads();
            threads.push(accept);
            threads.push(maintain);
        }

        Ok(Self { shared, address })
    }

    /// Where this node listens.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Writes down an address the operator gave, whether or not it answers.
    ///
    /// This is what a node falls back on. Every other address in the book was
    /// learned from the network and can be taken away by it: peers stop
    /// answering, the misses add up, the entries go. A node whose book has
    /// emptied is not on the network and has no way back onto it, because
    /// rejoining means asking someone, and it has nobody left to ask. Seeds
    /// are the addresses that never go, so there is always someone to ask.
    ///
    /// Called before dialling, so a seed that happens to be down at the moment
    /// this node starts is still tried again later rather than never known.
    pub fn remember_seed(&self, address: SocketAddr) {
        self.shared.book().insert_seed(address);
    }

    /// Names to start from, kept as names rather than as the addresses they
    /// stand for today.
    ///
    /// An address resolved once at startup is an address a node has for good,
    /// including when the name later means something else, and no address at
    /// all when the lookup happened to fail. Held here, a name is asked again
    /// while this node has no seed to dial, so one that starts before its
    /// machine can resolve anything still joins on its own.
    pub fn start_from_names(&self, names: Vec<String>) {
        *self.shared.seed_names() = names;
    }

    /// Dials one address and keeps the connection, if there is room for it.
    ///
    /// The address is remembered either way: it answered, which is more than
    /// most of the book can say, and the next round of upkeep can dial it when
    /// a slot comes free. What is not done is taking the connection past the
    /// ceiling, onto a node that has stopped, or from a host this node is
    /// refusing: this is the third way into the peer table, after the accept
    /// loop and upkeep dialling, and it was the one that consulted none of
    /// them.
    ///
    /// The refusal was the last of the three to be carried here, and the case
    /// that shows why is `reach_for_an_archivist`, whose own doc calls itself
    /// "an ordinary dial made a few seconds early rather than a second way of
    /// choosing who this node talks to". The ordinary dial asks the refusal
    /// table; without this, that one did not, so it was exactly the second way
    /// it says it is not, for up to `REACH_FOR_ARCHIVISTS` hosts a round.
    ///
    /// An operator naming a seed on the command line loses nothing by it. The
    /// address is written into the book before the dial, so it is tried again
    /// by upkeep once the refusal lapses, and the refusal lapses on its own
    /// after [`crate::refusal::REFUSAL_SECONDS`]. What the operator gets in
    /// the meantime is the reason, which is more than a silent retry gave
    /// them.
    ///
    /// `Ok(())` means this node holds the connection. It used to mean the
    /// three-way handshake completed, which is a different sentence: a socket
    /// this node shut in the next statement for want of room answered `Ok(())`
    /// and was printed as `reached`, and the wallet counted it as a seed it had
    /// got to. Everything that turns the connection away now says so.
    pub fn connect(&self, address: SocketAddr) -> Result<(), NodeError> {
        // Before the dial, which is where both of the other two ask it: the
        // accept loop asks before it takes the stream and the dial round
        // filters its candidates. Asking after would spend a `DIAL_TIMEOUT`
        // on a host that is turned away at the end of it, up to
        // `REACH_FOR_ARCHIVISTS` times a round, and the round only happens
        // when the node is already short of peers.
        let refused = "this node is refusing that host for now, after it sent \
                       something a peer should not send";
        if self.shared.refuses(address.ip(), unix_now()) {
            return Err(NodeError::NotKept {
                address,
                because: refused,
            });
        }

        let stream = TcpStream::connect_timeout(&address, DIAL_TIMEOUT)?;
        self.shared.book().insert(address);
        let host = stream.peer_addr().ok().map(|at| at.ip());
        // And again on the host the socket actually reached. A refusal is
        // about a machine and one machine answers on more than one address,
        // so the address dialled and the host that answered are two questions
        // and both are asked.
        if host.is_some_and(|host| self.shared.refuses(host, unix_now())) {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(NodeError::NotKept {
                address,
                because: refused,
            });
        }
        if !self.shared.has_room_for(host) {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(NodeError::NotKept {
                address,
                because: "this node already holds as many connections as it takes",
            });
        }
        if !attach_peer(&self.shared, stream, Some(address)) {
            return Err(NodeError::NotKept {
                address,
                because: "this node is stopping, or the socket could not be set up",
            });
        }
        Ok(())
    }

    /// Connections this node is holding, introduced or not.
    ///
    /// What it costs in threads and buffers, which is what the ceiling on
    /// connections is about. It is not what an operator means by "peers": see
    /// [`Self::peers_introduced`].
    pub fn peer_count(&self) -> usize {
        self.shared.peers().len()
    }

    /// Peers that have introduced themselves, which is the number worth
    /// showing a person.
    ///
    /// A socket that connects and says nothing is not somebody to ask
    /// anything: a message down it is refused as unannounced and closes the
    /// connection. Every surface that reports "peers" reported the sockets, so
    /// a wallet with one silent stranger attached told its owner it had
    /// reached the network and the trouble must be elsewhere, and a node handed
    /// a ledger counted the same stranger as somebody it had asked for the
    /// blocks it was waiting on.
    pub fn peers_introduced(&self) -> usize {
        self.shared
            .peers()
            .values()
            .filter(|peer| peer.worth_speaking_to())
            .count()
    }

    /// Addresses this node knows about, whether or not it is connected to them.
    pub fn known_addresses(&self) -> Vec<SocketAddr> {
        self.shared.book().iter().collect()
    }

    /// Reads the chain. The lock is held only for the call.
    pub fn with_chain<T>(&self, read: impl FnOnce(&ChainStore) -> T) -> T {
        read(&self.shared.chain())
    }

    /// A block read straight from the log, by its height on the branch.
    ///
    /// This takes the log lock and not the chain lock, so it can be called
    /// from inside [`Node::with_chain`]. That is the position anything reading
    /// old blocks is in: it has already asked the chain, which no longer holds
    /// the bodies of blocks too deep to be undone, and is now asking the disk.
    pub fn archived_at(&self, height: u64) -> Option<Block> {
        let log = self
            .shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match log.as_ref()?.blocks.read_at(height) {
            Ok(found) => found,
            Err(error) => {
                self.shared.could_not_read(Reading::Blocks, height, &error);
                None
            }
        }
    }

    pub fn height(&self) -> Option<u64> {
        self.with_chain(ChainStore::height)
    }

    /// Writes this node's ledger to its directory, so a restart begins there
    /// rather than at the first block.
    ///
    /// Done on its own schedule as the log grows. This is for an operator
    /// about to stop a node, and for tests.
    pub fn write_ledger(&self) -> bool {
        self.shared.write_ledger().is_some()
    }

    /// Sets how many bytes of blocks this node keeps on disk.
    ///
    /// `u64::MAX` keeps every block ever accepted, which is what a node
    /// offering the history to others does and what the disk cost of the chain
    /// is measured against.
    pub fn keep_blocks(&self, bytes: u64) {
        self.shared.keep_bytes.store(bytes, Ordering::Relaxed);
    }

    /// How many bytes of blocks this node is holding on disk.
    pub fn kept_bytes(&self) -> u64 {
        let log = self
            .shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        log.as_ref().map_or(0, |store| store.blocks.bytes())
    }

    /// Offers this node a run of headers as the ones from before it arrived.
    ///
    /// For tests. The node checks them exactly as it checks a run that came
    /// off the network, which is the point: there is no way in that skips the
    /// check, here or anywhere. What it does stand in for is who sent them: a
    /// caller reaching straight into the node is not a peer, so it takes the
    /// place of whoever this node is filling from.
    pub fn take_offered_headers(&self, from: u64, headers: &[BlockHeader]) {
        let now = unix_now();
        let peer = {
            let mut filling = self.shared.filling_from();
            let held = *filling;
            let peer = held.map_or(0, |turn| turn.peer);
            // Renewed here rather than left to the run to earn, because this
            // door is the operator's and not a stranger's: what arrives through
            // it is as large as the caller chose to make it.
            *filling = Some(Turn {
                peer,
                moved: now,
                marked: held.map_or(0, |turn| turn.marked),
                spoiled: false,
            });
            peer
        };
        self.shared.take_headers(peer, from, headers, now);
    }

    /// How far this node is through joining a chain it was not on.
    ///
    /// A node being handed a ledger shows no height until the whole of it has
    /// arrived, which without this reads as a node doing nothing.
    ///
    /// A node on probation reports the join as done, because it is: the answer
    /// arrived whole and the ledger is in the chain. What that does not say is
    /// that the node stands behind it, and [`Node::probation`] is where to ask
    /// that. Read from the undertaking rather than from the join so that it
    /// survives a restart: the join lives in this process, the undertaking is
    /// on the disk.
    ///
    /// Takes the chain lock, so it cannot be called from inside
    /// [`Self::with_chain`]. See [`Self::probation`].
    pub fn joining(&self) -> Joined {
        if self.probation().is_some() {
            return Joined::Done;
        }
        self.shared
            .joining
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reported()
    }

    /// What this node has still to check before it stands behind the ledger it
    /// was handed, or `None` for a node that owes nothing.
    ///
    /// `None` covers both a node that read its chain from the first block and
    /// one that was handed a ledger and has since validated its way past the
    /// tip that ledger was buried under. The two are the same thing here: a
    /// node whose own work stands behind everything it answers about.
    /// Takes the chain lock, so it cannot be called from inside
    /// [`Self::with_chain`]: the mutex is not reentrant and the process stops
    /// there with nothing said. The same is true of [`Self::joining`]. Read
    /// them before taking the chain, which is what a face wanting both does
    /// anyway.
    pub fn probation(&self) -> Option<Probation> {
        self.shared.probation()
    }

    /// Why this node cannot get on from where it stands, if it cannot.
    ///
    /// Set when a node handed a ledger has waited out its patience for the
    /// blocks above the anchor with peers to ask and none of them delivering.
    /// The node stops on it as it does on [`Node::outdated`], and for the same
    /// reason: carrying on would mean answering confidently off a ledger
    /// nothing will ever stand behind. Unlike that one the cure is the
    /// operator's, and it is to start again from an empty directory.
    pub fn stranded(&self) -> Option<Stranded> {
        *self.shared.stranded()
    }

    /// The highest block this node has on its disk, or `None` for one keeping
    /// nothing.
    ///
    /// The height in a status line is the chain's, which is memory. This is
    /// the disk, and on a healthy node the two are the same number. Where they
    /// are not, this is the one an operator needs: it is where a restart
    /// begins, it is the highest block this node can serve to a peer that is
    /// behind, and until now there was nowhere at all to ask for it.
    pub fn written_through(&self) -> Option<u64> {
        let log = self
            .shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        log.as_ref()?.blocks.reaches().checked_sub(1)
    }

    /// Why the address book could not be written down, if it could not.
    ///
    /// Nothing on the chain depends on this file, which is why it was the one
    /// write here whose failure was thrown away. What depends on it is the
    /// next start: without it a node comes back knowing only the seeds it was
    /// given, and on a machine whose seeds have moved on that is a node that
    /// finds nobody.
    pub fn unsaved_addresses(&self) -> Option<String> {
        self.shared
            .unsaved_book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The lowest block on the disk.
    ///
    /// The pair of [`Self::written_through`], and what tells a height the log
    /// has let go of from one it has not reached. The log holds one run, so
    /// anything between these two numbers is there and anything outside them
    /// is not, which is the whole of what somebody walking the chain from the
    /// bottom needs: without it, a block dropped off the bottom and a block
    /// not yet written look the same, and stopping at the first of them is
    /// how the explorer's index came to read nothing at all and say the
    /// answer was exact.
    pub fn blocks_from(&self) -> Option<u64> {
        let log = self
            .shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Some(log.as_ref()?.blocks.first_height())
    }

    /// What this node has accepted and not managed to put on its disk.
    ///
    /// `None` on a node whose disk is taking what it writes. A node whose disk
    /// has stopped shows nothing else: it climbs in height, it announces, and
    /// its status line is a healthy node's. This is the only place that says
    /// otherwise, and once [`Unwritten::within_reach`] is false the node has
    /// stopped, for the reason written there.
    pub fn unwritten(&self) -> Option<Unwritten> {
        self.shared
            .unwritten
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What this node holds on its disk and could not read back for somebody.
    ///
    /// `None` on a node whose disk is answering, which is every healthy one.
    /// The pair of [`Self::unwritten`], and the half that had nowhere to be
    /// said: a write the disk refuses costs this node its own history, and a
    /// read the disk refuses costs whoever asked their answer, quietly, on a
    /// node that goes on looking exactly like one that can answer.
    ///
    /// The node does not stop on it and nothing is cut for it. A read refusal
    /// is about one record; the chain is not wrong, the branch is not short,
    /// and the record may still be there to look at. What it is worth is a
    /// person going to look.
    pub fn unread(&self) -> Option<Unread> {
        self.shared
            .unread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the blocks arriving say this build is too old for its chain.
    ///
    /// `None` until a run of blocks this software cannot read has come from
    /// more than one peer over a stretch of time. The node does not stop on
    /// it, on purpose: what makes a block unreadable is a number in a field,
    /// and stopping on that would be a door a stranger could walk through.
    /// Somebody who can compare it against a height that has stopped moving is
    /// the right reader for it.
    pub fn unjudged(&self) -> Option<Unjudged> {
        let met = self
            .shared
            .unjudged
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        too_old_for_the_chain(&met)
    }

    /// Whether the showings this node is being offered say the chain itself
    /// cannot be weighed by this build.
    ///
    /// `None` until several showings have failed in the same words, from more
    /// than one peer. What this answers is the question an operator watching
    /// that had no way to ask, which is why it is taking hours.
    ///
    /// It used to say here that a node with no chain still gets one either
    /// way, by reading it block by block, which is slower and no less safe.
    /// Slower and no less safe is true; either way is not. Reading needs
    /// bodies, and a node keeps [`KEEP_BLOCK_BYTES`] of them and drops what is
    /// below the ledger it wrote, so the beginning of the chain is held only
    /// by whoever chose to keep it. A newcomer that cannot weigh the chain
    /// and cannot reach such a peer does not get on it at all. Nothing here
    /// says that yet, which is the next thing this report needs: see
    /// `tests/audit_reading_the_chain_needs_bodies.rs` for what a peer at its
    /// default budget can and cannot serve.
    ///
    /// And `None` again the moment a chain arrives, however it arrived.
    /// Showings are only ever weighed while a node has nothing, so the count
    /// is frozen from then on, and left ungated it would follow a node that
    /// had long since read its chain for the rest of its life, telling its
    /// owner to wait for something that had already happened.
    pub fn unweighable(&self) -> Option<Unweighable> {
        if !self.shared.chain().is_empty() {
            return None;
        }
        let met = self
            .shared
            .unweighed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        no_showing_checks_out(&met)
    }

    /// Whether the blocks this node is refusing say its own clock is behind.
    ///
    /// `None` until a run of them has arrived from more than one peer, or
    /// until this node has refused the first block of its own network, which
    /// is in the binary and settles it on its own.
    ///
    /// Not a verdict and never acted on: a timestamp is a number a stranger
    /// writes in a field, and a node that stopped on one would be handing a
    /// stranger a way to stop it. What it is worth is somebody looking at the
    /// machine's clock, and it is the only place in this node that mentions
    /// one.
    pub fn clock_behind(&self) -> Option<Behind> {
        // The chain first and let go of before the count is taken, which is
        // the order everything here takes them in.
        let still_without_a_chain = self.shared.chain().is_empty();
        let met = self
            .shared
            .out_of_step
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        clock_is_behind(
            &met,
            self.shared.params.max_timestamp_drift,
            still_without_a_chain,
        )
    }

    /// What this node is still missing before it can show a newcomer the
    /// chain, or `None` for one that can show it now.
    ///
    /// `None` also for a node started without a directory, which keeps no
    /// headers to be missing any of and no disk to grow: there is a real
    /// question about such a node and this is not the place it is asked.
    ///
    /// Takes the chain and then the log, which is the order everything here
    /// takes them in, so it cannot be called from inside
    /// [`Self::with_chain`].
    pub fn filling(&self) -> Option<Filling> {
        let reaches = {
            let chain = self.shared.chain();
            chain.height().map_or(0, |tip| tip.saturating_add(1))
        };
        let log = self
            .shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let store = log.as_ref()?;
        if store.can_show_the_chain(reaches) {
            return None;
        }
        Some(Filling {
            from: store.headers.first_height(),
            through: store.headers.reaches(),
            proved: store.forest.len(),
            reaches,
            bytes: store.blocks.bytes(),
            keep: self.shared.keep_bytes.load(Ordering::Relaxed),
        })
    }

    /// Blocks this node was offered and can never reach.
    ///
    /// Zero on a healthy node. Anything else means somebody is following a
    /// branch that parts from this one below the point this node was handed
    /// on, which it cannot cross to however much of that branch arrives.
    pub fn out_of_reach(&self) -> u64 {
        self.shared.out_of_reach.load(Ordering::Relaxed)
    }

    /// Sets how long this node waits for the blocks above an anchor it was
    /// handed before it says it is stranded.
    ///
    /// An operator's choice about how long to leave a node that may be waiting
    /// on a peer that is coming back, in the way [`Node::keep_blocks`] is one
    /// about disk. The default is an hour.
    pub fn wait_for_the_burial(&self, seconds: u64) {
        self.shared
            .stranding_patience
            .store(seconds, Ordering::Relaxed);
    }

    pub fn total_work(&self) -> u128 {
        self.with_chain(ChainStore::total_work)
    }

    /// Offers a locally produced block to the chain, announcing it if it lands.
    ///
    /// Refused while this node is on probation. A block made here is built on
    /// the ledger this node is holding, and a node that cannot yet be trusted
    /// to know what the chain is has no business manufacturing blocks on it:
    /// what it would produce is real work spent extending an account of the
    /// world that nobody has stood behind, and it would announce the result to
    /// everyone. Blocks arriving from peers are not affected, and they are
    /// what ends the probation.
    pub fn submit_block(&self, block: Block) -> Result<Accepted, Refused> {
        let id = block.id();
        let height = block.header.height;
        let accepted = {
            let mut chain = self.shared.chain();
            if let Some(probation) = self.shared.probation_at(chain.height()) {
                return Err(Refused::OnProbation(probation));
            }
            let accepted = chain.add_block(block, unix_now())?;
            // Written while the chain is still held, so the log cannot record
            // a branch the chain has already moved off.
            self.shared.persist(&accepted, &mut chain);
            accepted
        };
        if matches!(accepted, Accepted::Extended | Accepted::Reorganised { .. }) {
            self.shared
                .broadcast(None, &Message::Announce(vec![Located::new(height, id)]));
        }
        Ok(accepted)
    }

    /// Offers a transfer to the pool, passing it on if it was new.
    ///
    /// Refused while this node is on probation, for the same reason a block
    /// is. Whether a transfer can be spent is a question about the ledger, and
    /// this node is holding one it has not stood behind: taking the transfer
    /// would be answering that question off a stranger's word, and passing it
    /// on would be spreading the answer.
    pub fn submit_transaction(&self, transfer: Transfer) -> Result<bool, Refused> {
        let message = Message::Transaction(Box::new(transfer.clone()));
        let fresh = {
            let mut chain = self.shared.chain();
            if let Some(probation) = self.shared.probation_at(chain.height()) {
                return Err(Refused::OnProbation(probation));
            }
            chain.accept_transfer(transfer)?
        };
        if fresh {
            self.shared.broadcast(None, &message);
        }
        Ok(fresh)
    }

    /// Offers a transfer this node already holds to every peer again, and says
    /// how many took it into their queue.
    ///
    /// [`Self::submit_transaction`] broadcasts once, at the instant the pool
    /// takes the transfer, to whoever is connected then. For a node that has
    /// just started that is regularly nobody: a wallet's `send` runs seconds
    /// after `open`, the handshake has not finished, the broadcast reaches an
    /// empty peer table, and nothing here ever offers it again. The pool is
    /// not gossiped and a peer that arrives afterwards is never told. So the
    /// money sat in one process's memory until that process stopped, while the
    /// person who sent it read that it had been handed to the network.
    ///
    /// Nought means nobody was offered it. A transfer no longer in the pool,
    /// because a block carried it or because it was evicted, answers nought
    /// too: there is nothing to offer, and this says what happened rather than
    /// what it hoped.
    pub fn offer_again(&self, id: &Hash32) -> usize {
        let Some(transfer) = self.with_chain(|chain| chain.pooled(id).cloned()) else {
            return 0;
        };
        self.shared
            .broadcast(None, &Message::Transaction(Box::new(transfer)))
    }

    /// Notes in the cold set, which this node commits to in thirty two bytes
    /// whether or not it keeps any of them.
    pub fn cold_len(&self) -> u64 {
        self.with_chain(|chain| chain.state().cold_len())
    }

    /// Whether this node can rebuild a proof for someone who lost theirs.
    pub fn is_archiving(&self) -> bool {
        self.with_chain(ChainStore::is_archiving)
    }

    /// Connected peers that say they keep the whole cold set.
    ///
    /// For whatever is showing a wallet its money: a note whose path this node
    /// cannot build is money that can be seen and not moved, and the first
    /// thing its owner needs to know is whether anybody here could help.
    pub fn archiving_peers(&self) -> usize {
        self.shared
            .peers()
            .values()
            .filter(|peer| peer.archives)
            .count()
    }

    /// Asks the network where these fallen notes sit, and checks what comes
    /// back against this node's own commitment.
    ///
    /// `wanted` is the place each note is believed to sit and the leaf it must
    /// fold to, which is what makes the answer worth taking from a stranger.
    /// Whoever answers is handed a list of places and nothing else: not the
    /// notes, not the owner, not who is asking about what.
    ///
    /// Nothing here trusts anybody. A path is folded from the place named up
    /// to a commitment this node worked out for itself, block by block, and
    /// one that does not reach it is simply not used. That is why this can be
    /// asked of an anonymous peer at all, and why a peer that answers wrongly
    /// is not held to have misbehaved: the cold set moves whenever a note
    /// falls, so an honest path built a moment too early fails in exactly the
    /// same way as an invented one.
    ///
    /// Waits, because there is nothing useful for the caller to do meanwhile
    /// and the answer is one round trip. It gives up early once every place
    /// has been answered for.
    pub fn recover_proofs(&self, wanted: &[(u64, Hash32)], patience: Duration) -> Recovered {
        if wanted.is_empty() {
            return Recovered::default();
        }
        self.shared.proofs_asked_for.fetch_add(1, Ordering::Relaxed);
        // Capped here as well as on the wire, so a caller that asks about more
        // than one message carries is answered about what fits rather than
        // having its question silently truncated by a peer.
        let asked_about: BTreeMap<u64, Hash32> = wanted.iter().take(MAX_PROVEN).copied().collect();
        let positions: Vec<u64> = asked_about.keys().copied().collect();
        *self.shared.asking() = Asking {
            wanted: asked_about,
            ..Asking::default()
        };

        // Nobody here keeps the set, so reach for somebody this node has met
        // who said they did. A claim heard on an earlier connection is the
        // only lead there is, and following it costs a dial.
        if self.archiving_peers() == 0 {
            self.reach_for_an_archivist();
        }

        let deadline = Instant::now().checked_add(patience);
        loop {
            let (worth_asking, archivists) = self.shared.worth_asking();
            let fresh: Vec<PeerId> = {
                let mut asking = self.shared.asking();
                worth_asking
                    .into_iter()
                    .filter(|peer| asking.asked.insert(*peer))
                    .collect()
            };
            for peer in fresh {
                self.shared
                    .send_to(peer, Message::GetProofs(positions.clone()));
            }
            {
                let mut asking = self.shared.asking();
                // Every place answered for, or everyone asked has answered and
                // there is nothing further to wait on.
                if asking.satisfied()
                    || (!asking.asked.is_empty() && asking.answered.len() >= asking.asked.len())
                {
                    return finished(&mut asking, archivists);
                }
            }
            if deadline.is_none_or(|end| Instant::now() >= end) {
                let mut asking = self.shared.asking();
                return finished(&mut asking, archivists);
            }
            thread::sleep(RECOVERY_POLL);
        }
    }

    /// Opens a connection to an address that said it keeps the cold set.
    ///
    /// Only reached by a node that needs a path and is connected to nobody who
    /// can build one, which for a wallet is the moment its owner is looking at
    /// money it cannot move. One address at a time and only ones already in
    /// the book, so this is an ordinary dial made a few seconds early rather
    /// than a second way of choosing who this node talks to.
    fn reach_for_an_archivist(&self) {
        let known: Vec<SocketAddr> = self.shared.book().archivists();
        let connected: Vec<SocketAddr> = self
            .shared
            .peers()
            .values()
            .filter_map(|peer| peer.advertised.or(peer.dialled_to))
            .collect();
        for address in known
            .into_iter()
            .filter(|address| !connected.contains(address))
            .take(REACH_FOR_ARCHIVISTS)
        {
            let _ = self.connect(address);
        }
    }

    /// Transfers waiting for a block.
    pub fn pool_len(&self) -> usize {
        self.shared.chain().pool_len()
    }

    /// The rules this node turned out not to have, if it met any.
    ///
    /// Set when a block arrived from a height whose rules are newer than this
    /// software. The node has stopped following the chain at that point, on
    /// purpose: the alternative is to refuse every updated peer and go on
    /// answering from a chain the network has left.
    pub fn outdated(&self) -> Option<Outdated> {
        *self.shared.outdated()
    }

    /// Why this node is not taking connections, if it is not.
    ///
    /// Cleared the moment a visitor is let in, so what this holds is a door
    /// that is still shut rather than one that was. A node in this state is
    /// still following the chain and still dialling out: what it has stopped
    /// being is reachable, which is the one thing about itself it cannot see.
    pub fn unanswered(&self) -> Option<Unanswered> {
        self.shared.unanswered().clone()
    }

    /// Visitors this node could not take, over its whole life.
    pub fn turned_away(&self) -> u64 {
        self.shared.turned_away.load(Ordering::Relaxed)
    }

    /// Forest nodes this node found torn and built again from the leaves.
    ///
    /// Zero on a disk that has kept what it was given. Anything else is a
    /// disk that dropped a write and a node that carried on: put right,
    /// and worth saying, because a disk that lost one node has not
    /// finished.
    pub fn mended_nodes(&self) -> u64 {
        self.shared.mended_nodes.load(Ordering::Relaxed)
    }

    /// Questions this node has put to the network about where fallen notes
    /// sit.
    ///
    /// For whoever waits between two of them: a wait that holds is a count
    /// that stops going up, which is a thing two machines agree about where
    /// the length of the wait is not.
    pub fn proofs_asked_for(&self) -> u64 {
        self.shared.proofs_asked_for.load(Ordering::Relaxed)
    }

    /// Closes every connection, stops the listener, and saves what is worth
    /// keeping.
    ///
    /// What decides whether this has already been done is [`Shared::winding_down`]
    /// and not [`Shared::running`]. A node can clear `running` from inside: a
    /// block from a height this build has no rules for, or a handed ledger
    /// whose burial nobody delivers. Reading that as "already stopped" meant
    /// this did none of what it says on exactly the two occasions it mattered
    /// most, and said nothing about it: the caller saw `shutdown` return, saw
    /// `Drop` return, and had a node that looked stopped while a peer thread
    /// went on holding the directory lock for as long as a stranger cared to
    /// keep feeding it a frame.
    pub fn shutdown(&self) {
        self.shared.running.store(false, Ordering::SeqCst);
        if self.shared.winding_down.swap(true, Ordering::SeqCst) {
            return;
        }
        save_book(&self.shared);
        // Until the table stays empty. Nothing has to be woken: the accept
        // loop polls, and every peer thread is either reading with a deadline
        // or on a socket just shut. What the round is for is a connection
        // taken while this was joining, which adds its thread after the table
        // was taken.
        loop {
            for peer in self.shared.peers().values() {
                let _ = peer.stream.shutdown(Shutdown::Both);
            }
            let handles = std::mem::take(&mut *self.shared.threads());
            if handles.is_empty() {
                break;
            }
            for handle in handles {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// What became of a message offered to the join collector.
enum Taken {
    /// It was a piece of a join answer, and has been dealt with.
    Handled,
    /// It was, and answering it failed, which ends this peer.
    Failed,
    /// It was something else entirely.
    Other(Message),
}

/// Hands a message to the join collector if that is what it is.
fn join_piece(shared: &Arc<Shared>, from: PeerId, message: Message, outbound: &Outbound) -> Taken {
    let Message::JoinPart {
        what,
        at,
        part,
        parts,
        bytes,
    } = message
    else {
        return Taken::Other(message);
    };
    // Only the peer the node chose to ask is collected from. Anybody may
    // send a piece, and there is one collection: before this check, a piece
    // from somebody else landed in it, did not fit, and tore down an honest
    // exchange at the cost of one message.
    if !shared.choosing().asked_join(from) {
        return Taken::Handled;
    }
    let Some(next) = take_join_part(shared, from, what, at, part, parts, bytes) else {
        return Taken::Handled;
    };
    if outbound.try_send(next).is_err() {
        return Taken::Failed;
    }
    Taken::Handled
}

/// Hands a message to whichever of this node's own collections it answers.
///
/// **One message, and the set is the point.** What is taken here is taken
/// before the chain has been near it and before the allowance has been asked
/// about, so everything in this set is work a stranger gets for nothing. That
/// is the right trade for a join piece: it is a piece of an answer to a
/// question this node put to one named peer, anybody else's copy is dropped on
/// a comparison, and the alternative is a node that cannot be handed a chain
/// without paying for every stranger who offers it one.
///
/// It was the wrong trade for a run of paths, and nothing said so because the
/// set had no name. `Proofs` was taken here too, which carried it past
/// `cost_of` entirely: the price the table puts on a path folded against the
/// cold set is eight, the same as asking for one, and it was charged to
/// nobody. A peer this node had asked could offer the same sixty four paths
/// again and again inside the few seconds the question stays open, and every
/// one of them was folded with the chain held, for free.
///
/// So a run of paths is named in the reaction and folded once the chain is let
/// go of, like the locator and the join piece the same reaction carries, and
/// it goes through the one place that charges for work on the way.
fn collected(shared: &Arc<Shared>, from: PeerId, message: Message, outbound: &Outbound) -> Taken {
    if !taken_before_the_allowance(&message) {
        return Taken::Other(message);
    }
    join_piece(shared, from, message, outbound)
}

/// Whether this message is taken before the allowance has been asked about.
///
/// The set is the point, and until now it was not written down anywhere: it
/// was whatever `collected` happened to match on, and it grew by one without
/// anybody noticing. What an entry on it costs is nothing at all, so it is
/// worth being able to read the whole of it in one place.
///
/// Exhaustive rather than a `matches!`, so that a new message is a decision
/// somebody has to make here rather than a default somebody gets.
const fn taken_before_the_allowance(message: &Message) -> bool {
    match message {
        // A piece of an answer to a question this node put to one named peer.
        // Anybody else's copy is dropped on a comparison, and the alternative
        // is a node that cannot be handed a chain without paying for every
        // stranger who offers it one.
        Message::JoinPart { .. } => true,
        // Everything else, and `Proofs` in particular. A run of paths is work:
        // each one is folded against the cold set with the chain held, and the
        // table prices it at eight, the same as asking for it.
        Message::Hello(_)
        | Message::Welcome(_)
        | Message::Ping(_)
        | Message::Pong(_)
        | Message::GetChain { .. }
        | Message::Chain { .. }
        | Message::GetBlocks(_)
        | Message::Block(_)
        | Message::Announce(_)
        | Message::GetPeers
        | Message::Peers(_)
        | Message::Transaction(_)
        | Message::GetJoin { .. }
        | Message::GetHeaders { .. }
        | Message::Headers { .. }
        | Message::GetProofs(_)
        | Message::Proofs(_) => false,
    }
}

/// Takes one piece of a join answer, and says what to ask for next.
///
/// A join is two exchanges in sequence: what work stands behind a chain, and
/// then the ledger at its tip. Each arrives in pieces, and each is checked as
/// a whole once its pieces are all here, because a piece on its own proves
/// nothing and a header commits to the whole or to none of it.
///
/// Anything that does not check out ends the attempt rather than being argued
/// with, and tells the chooser, which stops counting the claim and asks the
/// next claimant on its own round.
fn take_join_part(
    shared: &Arc<Shared>,
    from: PeerId,
    what: Joining,
    at: Hash32,
    part: u32,
    parts: u32,
    bytes: Vec<u8>,
) -> Option<Message> {
    let now = unix_now();
    // Filing the piece is all that happens with the collector held. What
    // follows once the last piece lands is a weighing of four thousand samples
    // or a ledger accepted, adopted and written to disk in one multi-megabyte
    // go, and none of it is anybody else's business: upkeep asks this same
    // collector how the join is going once a second, and whatever is showing a
    // status asks every hundred milliseconds. Both used to wait out the whole
    // landing.
    let (next, whole, weighed) = {
        let mut joining = shared.joining();

        // A node that already has a chain is not joining one. This arrives
        // when an answer outlived the question, which costs nothing to ignore.
        if !shared.chain().is_empty() {
            *joining = Progress::Landed;
            return None;
        }

        let (next, whole) = take_piece(
            &mut joining,
            shared,
            from,
            what,
            at,
            part,
            parts,
            bytes,
            now,
        );
        // The tip the weighing settled on, which the ledger has to belong to.
        let weighed = match &*joining {
            Progress::Fetching { tip, .. } | Progress::Weighed { tip, .. } => Some(*tip),
            _ => None,
        };
        (next, whole, weighed)
    };
    let Some(whole) = whole else {
        return next;
    };
    match what {
        Joining::Weight => weigh_what_was_shown(shared, from, &whole, now),
        Joining::Ledger => land_the_ledger(shared, from, &whole, weighed, now),
    }
}

/// Files one piece, and says what to ask for next and whether the answer is
/// whole.
#[allow(clippy::too_many_arguments)]
fn take_piece(
    joining: &mut Progress,
    shared: &Arc<Shared>,
    from: PeerId,
    what: Joining,
    at: Hash32,
    part: u32,
    parts: u32,
    bytes: Vec<u8>,
    now: u64,
) -> (Option<Message>, Option<Vec<u8>>) {
    // What state this piece leaves the attempt in, and what to ask next.
    match std::mem::take(joining) {
        Progress::Landed => (None, None),
        // The first piece of the weighing, which is where a join starts.
        Progress::Idle => {
            let Some(started) = Collecting::started(what, at, part, parts, bytes, now) else {
                return (fail_attempt(joining, shared, from, now), None);
            };
            step(joining, started, None)
        }
        // The first piece of the ledger. The tip carries over from the
        // weighing, because the ledger has to be the one belonging to the
        // chain that was weighed.
        Progress::Weighed { tip, .. } => {
            let Some(started) = Collecting::started(what, at, part, parts, bytes, now) else {
                return (fail_attempt(joining, shared, from, now), None);
            };
            step(joining, started, Some(tip))
        }
        Progress::Weighing(mut collecting) => {
            if !collecting.take(what, at, part, bytes, now) {
                // The pieces held cannot be completed, so the attempt is
                // dropped and this node falls back to reading the chain.
                return (fail_attempt(joining, shared, from, now), None);
            }
            step(joining, collecting, None)
        }
        Progress::Fetching {
            tip,
            mut collecting,
        } => {
            if !collecting.take(what, at, part, bytes, now) {
                return (fail_attempt(joining, shared, from, now), None);
            }
            step(joining, collecting, Some(tip))
        }
    }
}

/// Weighs a whole showing of what work stands behind a chain.
///
/// Four thousand and ninety six samples, each with a path through the tip's
/// forest to check. The collector is not held for it: nothing about this
/// touches the collection, and everything that asks how a join is going does.
fn weigh_what_was_shown(
    shared: &Arc<Shared>,
    from: PeerId,
    whole: &[u8],
    now: u64,
) -> Option<Message> {
    // Both refusals were dropped on the floor here. What the sender lost was
    // its turn, which is right; what nobody got was the reason, and the two
    // readings of it are not the same afternoon. A sample in the wrong place
    // is somebody making a chain up. A run of headers longer than this build
    // takes is this build meeting a chain whose difficulty has fallen far
    // below what it ran at, where every archivist alive fails identically and
    // honestly. See [`Unweighable`] for what that costs and how long it lasts.
    let weighed = SampledStart::decode(whole)
        // Said rather than passed on bare. The codec names the type it refused
        // and nothing else, which as a line for a person reads as a program
        // talking to itself; and this is the refusal the tail ceiling comes
        // out of, so it is the one worth placing.
        .map_err(|error| format!("it could not be read as a weighing at all ({error})"))
        .and_then(|start| {
            check_start(&start, now, &shared.params)
                .map(|weighed| (weighed, start.tip))
                .map_err(|error| error.to_string())
        });
    if let Err(because) = &weighed {
        // The address is read and let go of before the count is taken, so the
        // table of these stays the leaf its own comment says it is.
        shared.could_not_weigh(shared.sender_for(from), because, now);
    }
    let mut joining = shared.joining();
    // The attempt may have been given up on while this was being weighed:
    // upkeep starts a fresh one when the chooser turns to somebody else, and
    // an answer to the old question must not be filed against the new one.
    if !matches!(*joining, Progress::Weighing(_)) {
        return None;
    }
    let Ok((shown, tip)) = weighed else {
        return fail_attempt(&mut joining, shared, from, now);
    };

    // What weighing settles is that *this* chain's work was really done. It
    // does not settle that no heavier chain exists, and the two were treated
    // as the same thing here, which is the whole of what a newcomer had to get
    // right.
    //
    // Difficulty follows whatever hashrate is present, so a forger with a
    // small share can mine a slow, entirely self-consistent chain for weeks
    // and have it prove itself. It never out-mines anybody. It only has to
    // answer first.
    //
    // So the chooser is told what was shown, and a chain that proves itself
    // goes forward only while nobody credible claims more. When somebody does,
    // this attempt ends and that somebody is asked to show it, which costs a
    // slow start rather than a wrong one. The peer here did nothing wrong and
    // its showing is kept: if the heavier claim cannot be shown, this chain is
    // the one that comes back.
    if !shared.choosing().shown(from, shown.total_work, now) {
        *joining = Progress::Idle;
        return None;
    }

    *joining = Progress::Weighed { tip, since: now };
    Some(Message::GetJoin {
        what: Joining::Ledger,
        part: 0,
    })
}

/// Takes a whole ledger, checks it, adopts it and writes it down.
///
/// `weighed` is the tip the showing settled on, read off the collection before
/// it was let go of. The ledger has to belong to that chain: a peer that
/// weighed one and handed over another would otherwise have its second answer
/// taken on the strength of the first. The tip it names has to be the one that
/// was weighed, and what ties the ledger to that tip is inside `accept`: the
/// ledger's own header is proved to sit in the tip's header forest, and to sit
/// far enough below it.
///
/// None of this runs with the collector held. Checking the handover, adopting
/// it and writing several megabytes to disk is the longest single stretch of
/// work in a join, and it has nothing to say to the round of upkeep that asks
/// how the join is going once a second.
fn land_the_ledger(
    shared: &Arc<Shared>,
    from: PeerId,
    whole: &[u8],
    weighed: Option<BlockHeader>,
    now: u64,
) -> Option<Message> {
    let tip = weighed?;
    // The last look before the one commitment this node gets to make. A
    // heavier claim can have arrived while the ledger was crossing, and
    // adopting past it would be taking the best answer so far while a better
    // one is said to exist.
    //
    // Read into a variable rather than asked inside the `if`, so the chooser
    // is let go of before the collector is taken. Everywhere else takes those
    // two the other way round, and a condition holds its guard for the whole
    // of the statement it is in.
    let allowed = shared.choosing().allows(from, tip.total_work, now);
    if !allowed {
        *shared.joining() = Progress::Idle;
        return None;
    }
    let landed = take_the_ledger(shared, whole, &tip, now);
    let mut joining = shared.joining();
    match landed {
        Landed::Refused => return fail_attempt(&mut joining, shared, from, now),
        // Not the sender's doing, and it used to be charged to the sender: an
        // archivist that had updated was held off for a growing pause, and so
        // was the next one, and the one after that, because every peer worth
        // asking hands over the same ledger. The verdict itself reached
        // nobody, because both errors went into an `.ok()`. What the reading
        // path has always done with this is name it, hold it against no peer,
        // and let a person read it beside a height that is not moving.
        //
        // The claim still stops counting, because this node cannot be handed
        // that chain whoever offers it, and going round again would be a loop.
        // The node is not stopped, which is where this parts company with the
        // reading path: there the height is the chain's own next block and not
        // a stranger's to choose, and here a newcomer with nothing would be
        // stopped for good on a height any claimant can name. The stop still
        // comes, from the first block this node then reads, which is the one
        // form of this verdict whose height nobody gets to pick.
        Landed::TooOld(outdated) => {
            shared.outdated().get_or_insert(outdated);
            shared.choosing().cannot_be_taken(from, now);
            *joining = Progress::Idle;
            return None;
        }
        Landed::Took => {}
    }
    *joining = Progress::Landed;
    drop(joining);
    // A ledger arrives from below the tip on purpose, so landing one is not
    // arriving: the blocks between it and the tip are the part this node
    // checks for itself, and it has to go and ask for them. Nothing else
    // would: what drives a sync forward is a block landing, and none is on its
    // way.
    Some(Message::GetChain {
        locator: shared.chain().locator(),
    })
}

/// What came of a ledger arriving.
enum Landed {
    /// It checked out, was adopted, and is written down.
    Took,
    /// It did not check out. Whichever of the many ways, it is the sender's
    /// doing and costs the sender the exchange.
    Refused,
    /// This build has no rules for the chain the ledger belongs to.
    ///
    /// A judgement about the reader and not about the sender, the same as a
    /// block from past an activation: an update makes the same ledger
    /// readable, and every peer that has updated hands over the same one.
    TooOld(Outdated),
}

/// Checks a ledger, adopts it, and writes down what adopting it means.
///
/// Split out from the deciding above so that the one question that matters
/// there, whose doing a refusal was, is not buried inside a chain of `and_then`
/// that had thrown the answer away before it was asked.
fn take_the_ledger(shared: &Arc<Shared>, whole: &[u8], tip: &BlockHeader, now: u64) -> Landed {
    let Ok(handover) = Handover::decode(whole) else {
        return Landed::Refused;
    };
    if handover.tip.id() != tip.id() {
        return Landed::Refused;
    }
    let state = match accept(&handover, &shared.params) {
        Ok(state) => state,
        Err(HandoverError::SoftwareTooOld {
            height,
            required,
            known,
        }) => {
            return Landed::TooOld(Outdated {
                height,
                required,
                known,
            })
        }
        Err(_) => return Landed::Refused,
    };
    // Asked again on the way in, because the ledger is checked against the
    // rules and adopting it is checked against this node's own chain, and the
    // two refuse for different reasons.
    if let Err(error) = shared.chain().adopt(state, &handover.recent) {
        return error.outdated().map_or(Landed::Refused, Landed::TooOld);
    }
    // What the anchor was taken on: the blocks between it and the tip it
    // names, which `accept` asks nothing about. Written down before anything
    // else, because from this moment the node is holding a ledger nobody has
    // stood behind and everything it does with it has to know that.
    let anchor = handover.at.height;
    shared.undertake(
        anchor,
        settles_at(anchor, handover.tip.height, &shared.params),
        now,
    );
    // Kept only once it has been taken, so what is on disk is a ledger this
    // node checked and adopted rather than one it merely received.
    shared.keep_ledger(whole);
    // The run of headers the ledger came with, written down. Without them this
    // node has no oldest header of its own, and so nothing to check a filled-in
    // run against: it would never be able to take anyone in.
    shared.seed_headers(&handover.recent);
    Landed::Took
}

/// Ends a join attempt whose answer does not add up, and says so.
///
/// This used to fall back to reading the chain from the same peer, which
/// quietly committed to whatever that peer held: reading a chain past the
/// reorganisation limit is as final as being handed its ledger. Now the
/// claim stops counting and the chooser asks the next claimant on its own
/// round, so a failed answer costs its owner the exchange rather than
/// costing this node its choice.
fn fail_attempt(
    joining: &mut Progress,
    shared: &Arc<Shared>,
    from: PeerId,
    now: u64,
) -> Option<Message> {
    shared.choosing().failed(from, now);
    *joining = Progress::Idle;
    None
}

/// Files a collection back where it belongs, and says what is still missing.
///
/// Returns what to ask for next, and the whole answer once nothing is missing.
fn step(
    joining: &mut Progress,
    collecting: Collecting,
    tip: Option<BlockHeader>,
) -> (Option<Message>, Option<Vec<u8>>) {
    let wanted = collecting.wanted();
    let what = collecting.what;
    let whole = collecting.whole();
    *joining = match tip {
        Some(tip) => Progress::Fetching { tip, collecting },
        None => Progress::Weighing(collecting),
    };
    let asking = wanted.map(|part| Message::GetJoin { what, part });
    (asking, whole)
}

/// Reads block bodies back off the log, for the chain that let go of them.
///
/// Holds the same lock the node does rather than a second copy of anything, so
/// what it reads is what the node has. Everything that calls into this already
/// holds the chain, and this takes the log: chain first and log second, as
/// everywhere else.
///
/// Weakly, because the chain this is handed to lives inside the very thing it
/// points back at. A strong reference would be a node that never drops.
#[derive(Debug)]
struct FromLog(Weak<Shared>);

impl Bodies for FromLog {
    fn body(&self, height: u64) -> Option<Block> {
        let shared = self.0.upgrade()?;
        let log = shared.log.lock().unwrap_or_else(PoisonError::into_inner);
        match log.as_ref()?.blocks.read_at(height) {
            Ok(found) => found,
            Err(error) => {
                // A body the chain needs and cannot get is already answered:
                // the switch fails, `ChainError::Corrupt` comes back, and the
                // connection that asked for it is dropped without the peer
                // being blamed. What was missing is that an operator watching
                // saw a connection go and nothing else, so a disk eating one
                // record looked like a network with a flaky peer on it.
                shared.could_not_read(Reading::Blocks, height, &error);
                None
            }
        }
    }
}

/// Where headers being filled in are kept until they check out.
const FILLING_LOG: &str = "headers.filling";

/// What a node keeps on disk, under one lock.
///
/// Two files with two different lifetimes: the blocks, which a node drops once
/// it has written down the ledger they add up to, and the headers, which it
/// keeps because they are what a newcomer is shown. Held together so there is
/// no order between them to get wrong.
#[derive(Debug)]
struct Store {
    blocks: BlockLog,
    headers: HeaderLog,
    /// The forest those headers make, so this node can prove where one sits
    /// rather than only check somebody else's proof.
    forest: HeaderTree,
    /// Headers from before this node arrived, while they are being collected.
    ///
    /// Kept apart from the real log until they check out, because until then
    /// they are a stranger's word. A node that wrote them straight in would be
    /// taking that word, which is the one thing this design does not do.
    filling: HeaderLog,
    /// Which collection the run above belongs to.
    ///
    /// Counted because the run is checked against a commitment with the log
    /// let go of between records, and what is merged has to be what was
    /// checked. Nothing appends past the point that ends the collection, so
    /// the only thing that can happen meanwhile is the whole of it being
    /// thrown away and started again, and this is what says whether it was.
    /// A length would not: a run thrown away and refilled to the same length
    /// is a different run.
    filling_epoch: u64,
}

impl Store {
    /// Throws the collected run away, and says that what comes next is a
    /// different collection.
    fn discard_filling(&mut self) {
        let _ = self.filling.clear();
        self.filling_epoch = self.filling_epoch.saturating_add(1);
    }

    /// Whether this node holds the whole header forest, back to the first
    /// block.
    ///
    /// What it takes to show a newcomer which chain carries the most work. A
    /// node that joined a chain rather than reading it holds the headers from
    /// where it was handed on, which is not enough to prove anything about
    /// what came before.
    fn can_show_the_chain(&self, reaches: u64) -> bool {
        self.headers.first_height() == 0
            && self.headers.reaches() >= reaches
            && self.forest.len() >= reaches
    }

    /// Whether the collection weighed at `epoch`, against the header at
    /// `oldest`, is no longer what this store holds.
    ///
    /// What is merged has to be what was weighed. The epoch says the
    /// collection was not thrown away and started again while the log was let
    /// go of, and the oldest header says nobody merged it first.
    ///
    /// Asked here rather than inline in [`Shared::fill_headers`] because the
    /// only way to reach it there is another thread moving the store between
    /// two takes of the lock, which no test can arrange on purpose.
    fn moved_since_weighed(&self, oldest: u64, epoch: u64) -> bool {
        self.filling_epoch != epoch
            || self.headers.first_height() != oldest
            || self.filling.reaches() < oldest
    }
}

/// A step of the header merge that this node's own disk refused.
///
/// Kept apart from a run that did not add up, and the distance between the two
/// is the whole of why it exists. A collection that was invented is a supplier
/// that could not show what it claimed, and the answer is to give the turn to
/// somebody else. A disk is not, and giving the turn away for one means the
/// entire run again, from the next peer, and the next, each of them marked as
/// having spoiled it, for as long as the node runs. On a chain of any age that
/// run is the whole history before this node arrived, so the node pays for its
/// own disk in somebody else's bandwidth, over and over, and the line its
/// operator is shown at the end of it says to connect it to a peer that holds
/// the missing part, which is the one thing that cannot help.
#[derive(Debug)]
enum OwnDisk {
    /// A record this log holds and would not give back. Nothing was written,
    /// so nothing is lost by stopping here.
    Read {
        what: Reading,
        height: u64,
        because: String,
    },
    /// A record this log would not take.
    Write(Refusing),
}

/// What became of a run of headers offered to a node filling in what came
/// before it arrived.
enum Filled {
    /// Nothing this node could use, and nothing lost.
    Ignored,
    /// The collection grew, and how far it now reaches. The distance says
    /// whether whoever supplied it is getting on with it or only answering.
    Grew(u64),
    /// What was collected was thrown away, and has to be gathered again.
    Discarded,
    /// The run was whole and checked out, and this node's own disk stopped the
    /// rest. Nobody is at fault out there and nobody's turn is spent on it.
    OwnDisk(OwnDisk),
}

/// A join answer, built once and handed out in pieces.
struct Prepared {
    what: Joining,
    at: Hash32,
    bytes: Vec<u8>,
}

/// What the join answer this node holds says about one question.
///
/// Three answers and not two, because the two ways of having no piece to send
/// call for opposite things. An answer about another tip is worth rebuilding.
/// A current answer that has no such part is not: building it again produces
/// the same answer and the same silence, at the price of the whole build.
enum Held {
    /// The piece asked for.
    Piece(Message),
    /// The answer is current, and has no piece with that number.
    NoSuchPart,
    /// Nothing held that this question is about.
    Nothing,
}

/// One piece of an answer already built.
fn piece_of(ready: &Prepared, part: u32) -> Option<Message> {
    let parts = ready.bytes.len().div_ceil(JOIN_PART_BYTES).max(1);
    let index = usize::try_from(part).ok()?;
    let start = index.checked_mul(JOIN_PART_BYTES)?;
    let end = start.saturating_add(JOIN_PART_BYTES).min(ready.bytes.len());
    let bytes = ready.bytes.get(start..end)?.to_vec();

    Some(Message::JoinPart {
        what: ready.what,
        at: ready.at,
        part,
        parts: u32::try_from(parts).unwrap_or(u32::MAX),
        bytes,
    })
}

/// Everything the chain has to say about one of these answers.
///
/// Taken in one go, so that the reading and encoding that follow can run with
/// the chain let go of. What is here is memory and nothing else: the tip, the
/// forest of sixty four hashes it commits to, and, for the answer that carries
/// a ledger, that ledger unwound to the burial. Everything the build goes on
/// to need is on the disk, and the disk is not the chain's to hold shut.
struct Ground {
    /// The tip all of this was taken against, so what is built from it can be
    /// weighed against the chain again before it is used.
    at: Located,
    history: Forest,
    /// The ledger a burial below the tip, for the answer that carries one.
    buried: Option<LedgerState>,
}

impl Shared {
    /// One piece of what a newcomer asked for, building the whole only if the
    /// last one built is not it.
    ///
    /// `None` when this node cannot answer, which is the honest reply from one
    /// that validates and nothing more: proving where a header sits takes a
    /// path through the header forest, and everybody else holds sixty four
    /// hashes.
    ///
    /// The build runs with nothing held at all. It used to run under the join
    /// cache, the chain and the log at once, so one stranger asking to be
    /// handed the chain stopped every other thread in the node for as long as
    /// the answer took: four thousand and ninety six binary searches over the
    /// headers, a header read off the disk at every step of each, and a forest
    /// path with every sample. No block was validated and no transfer taken
    /// meanwhile, and the cost was paid again on every new block, because this
    /// cache is keyed on the tip.
    fn serve_join(&self, what: Joining, part: u32) -> Option<Message> {
        match self.held_join(what, part) {
            Held::Piece(piece) => return Some(piece),
            // The answer this node holds is the current one and simply has no
            // such piece. That is a fact about the question, and it used to be
            // read as a fact about the cache: one `GetJoin` naming a part past
            // the end rebuilt the whole answer, every time it was sent, and
            // nothing went back for it. Seventeen bytes bought five hundred and
            // seventy milliseconds on a chain of four hundred, against thirty
            // four to hand over a piece that existed, and the cost grows with
            // the chain.
            Held::NoSuchPart => return None,
            Held::Nothing => {}
        }
        let ground = self.ground_for(what)?;
        let bytes = self.build_join(what, &ground)?;
        self.keep_join(
            Prepared {
                what,
                at: ground.at.id,
                bytes,
            },
            &ground.at,
            part,
        )
    }

    /// What the answer already held says about the question being asked.
    fn held_join(&self, what: Joining, part: u32) -> Held {
        let held = self.joined();
        let Some(tip) = self.chain().tip() else {
            return Held::Nothing;
        };
        let Some(Some(ready)) = held.get(what.slot()) else {
            return Held::Nothing;
        };
        if ready.at != tip {
            return Held::Nothing;
        }
        // From here the answer is the one this question is about, so the only
        // thing left that piece_of can object to is the part.
        piece_of(ready, part).map_or(Held::NoSuchPart, Held::Piece)
    }

    /// Puts a freshly built answer in its slot, and takes one piece of it.
    ///
    /// `None` when the chain left the tip it was built against while it was
    /// being built. Keeping it would put an answer about a chain this node is
    /// no longer on where the answer about the chain it is on belongs, and
    /// whoever was collecting that one would have to have it built again. The
    /// peer that asked hears nothing this round and asks again, which is the
    /// cheaper of the two.
    ///
    /// A tip once left is never returned to: a branch is followed for carrying
    /// more work than the last, so the work behind the tip only rises. That is
    /// what makes this check enough on its own. If the chain still stands
    /// where it did, it never went anywhere in between, and every header read
    /// off the disk during the build belonged to this branch.
    fn keep_join(&self, prepared: Prepared, from: &Located, part: u32) -> Option<Message> {
        let mut held = self.joined();
        if !self.chain().agrees_with(from) {
            return None;
        }
        let slot = held.get_mut(prepared.what.slot())?;
        *slot = Some(prepared);
        piece_of(slot.as_ref()?, part)
    }

    /// What the chain has to say about an answer of this kind.
    ///
    /// The chain is held for this and for nothing else.
    fn ground_for(&self, what: Joining) -> Option<Ground> {
        let chain = self.chain();
        let height = chain.height()?;
        let buried = match what {
            Joining::Weight => None,
            // The one thing here that is not a copy of something small. Only
            // the chain can unwind its own ledger, since what undoes a block
            // is held there and nowhere else, so this is the part that has to
            // happen under the lock.
            Joining::Ledger => Some(chain.ledger_at(height.checked_sub(self.params.burial)?)?),
        };
        Some(Ground {
            at: Located::new(height, chain.id_at(height)?),
            history: chain.state().headers_before_tip(),
            buried,
        })
    }

    /// One header off the disk.
    ///
    /// The log is taken for the read and let go of again, rather than held
    /// across a build that does thousands of these. [`Shared::persist`] takes
    /// the log with the chain already in hand, so a build holding the log
    /// would stop the chain just as surely as holding the chain itself: the
    /// next thread to validate a block would be waiting on the log with the
    /// chain in its own hand, and everybody else behind it.
    fn header_off_disk(&self, height: u64) -> Option<BlockHeader> {
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let store = log.as_ref()?;
        // The header log first: a node keeps every header and only the most
        // recent blocks, so this is the one that answers about the far end of
        // the chain.
        match store.headers.read_at(height) {
            Ok(Some(header)) => return Some(header),
            Ok(None) => {}
            Err(error) => self.could_not_read(Reading::Headers, height, &error),
        }
        match store.blocks.read_at(height) {
            Ok(found) => Some(found?.header),
            Err(error) => {
                self.could_not_read(Reading::Blocks, height, &error);
                None
            }
        }
    }

    /// One block off the disk, taken and let go of the same way.
    fn block_off_disk(&self, height: u64) -> Option<Block> {
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        match log.as_ref()?.blocks.read_at(height) {
            Ok(found) => found,
            Err(error) => {
                self.could_not_read(Reading::Blocks, height, &error);
                None
            }
        }
    }

    /// Where a header sits in the forest a chain of `leaves` committed to.
    fn proof_off_disk(&self, height: u64, leaves: u64) -> Option<ForestProof> {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let error = match log.as_ref()?.forest.prove_in(height, leaves) {
            Ok(proof) => return proof,
            Err(error) => error,
        };

        // A node that will not fold is the one refusal here that is this
        // node's own disk and not a question it was asked. The forest writes
        // without waiting, so a level whose length landed before its bytes did
        // leaves a node of the right length holding the wrong ones, and the
        // repair that runs at every start puts a level right by its length and
        // walks straight past it.
        //
        // Nothing wrote it again. A node at height `k` sits on the path of the
        // `2^k` leaves beneath it and is the sibling of the `2^k` beside it,
        // so leaving it there refused `2^(k + 1)` leaves for the life of this
        // node: a wallet asking where one of its fallen notes sits was told
        // no, every time, for ever, by a node that was otherwise well.
        //
        // So it is built again from the leaves, and the leaves themselves are
        // put back from the header log, which is the one thing here the forest
        // is not derived from. Reading them off the forest and folding upward
        // on trust wrote one torn leaf into every node above it, until the
        // forest agreed with itself and served everybody a root nobody has.
        let StoreError::Unfolded { height: at, start } = error else {
            self.could_not_read(Reading::Headers, height, &error);
            return None;
        };
        let store = log.as_mut()?;
        let leaf_of = |position: u64| -> Result<Option<Hash32>, StoreError> {
            Ok(store
                .headers
                .read_at(position)?
                .map(|header| header_leaf(&header.id())))
        };
        if let Err(error) = store.forest.mend_below(at, start, &leaf_of) {
            self.could_not_read(Reading::Headers, height, &error);
            return None;
        }
        self.mended_nodes.fetch_add(1, Ordering::Relaxed);
        match store.forest.prove_in(height, leaves) {
            Ok(proof) => proof,
            Err(error) => {
                self.could_not_read(Reading::Headers, height, &error);
                None
            }
        }
    }

    /// Whether this node can show a newcomer which chain carries the most
    /// work.
    ///
    /// The chain is passed in because the caller already holds it, and taking
    /// it twice is how two threads end up holding these two the other way
    /// round from each other.
    fn shows_the_chain(&self, chain: &ChainStore) -> bool {
        let reaches = chain.height().map_or(0, |tip| tip.saturating_add(1));
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        log.as_ref()
            .is_some_and(|store| store.can_show_the_chain(reaches))
    }

    /// Writes down the headers a handover came with.
    ///
    /// They are the tail of the chain that was weighed, so they are as
    /// vouched for as the ledger itself, and they are what everything filled
    /// in afterwards is checked against.
    fn seed_headers(&self, recent: &[BlockHeader]) {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(store) = log.as_mut() else {
            return;
        };
        if !store.headers.is_empty() {
            return;
        }
        for header in recent {
            if store.headers.append(header).is_err() {
                let _ = store.headers.clear();
                return;
            }
        }
    }

    /// The peer to ask for the next run of headers, and the run to ask for.
    ///
    /// One peer at a time, and [`Shared::take_headers`] takes runs from that
    /// peer only. Asking everybody was cheaper and looked harmless, since the
    /// answer is checked rather than trusted; what it missed is that the
    /// checking happens at the end, over a collection anybody could put the
    /// first header into. A peer that stops adding to it loses its turn, and so
    /// does one whose run has to be thrown away, and in both cases the turn
    /// goes to the next one along rather than back to the same peer: see
    /// [`Turn::spoiled`], which is the half of that this used to get wrong. So
    /// a node surrounded by peers that cannot answer works through them rather
    /// than asking the same one for ever.
    fn asks_headers_of(&self, connected: &[PeerId], now: u64) -> Option<(PeerId, Message)> {
        // Nothing missing, nothing to do, and in particular no turn to pass
        // on: a node that has filled its headers in would otherwise throw away
        // an empty collection once a round for the rest of its life.
        let asking = self.wants_headers()?;
        let previous = *self.filling_from();
        let keeps_turn = previous.is_some_and(|turn| {
            !turn.spoiled
                && connected.contains(&turn.peer)
                && now.saturating_sub(turn.moved) < HEADER_PATIENCE
        });
        if let Some(turn) = previous.filter(|_| keeps_turn) {
            return Some((turn.peer, asking));
        }
        let next = previous
            .map(|turn| turn.peer)
            .and_then(|peer| {
                connected
                    .iter()
                    .copied()
                    .filter(|other| *other > peer)
                    .min()
            })
            .or_else(|| connected.iter().copied().min())?;
        // A collection is one peer's work from end to end. What is left of the
        // last peer's goes when its turn does, because a run half from one
        // peer and half from another is the thing this whole arrangement
        // exists to prevent: it would be thrown out at the commitment check
        // whichever half was the lie, and neither peer would have been shown
        // to be wrong. It costs an honest peer that goes quiet mid run the
        // part it had sent, once.
        self.clear_filling();
        // Nothing collected yet, and the run always starts at height zero, so
        // how far it reaches is how much this turn has fetched.
        *self.filling_from() = Some(Turn {
            peer: next,
            moved: now,
            marked: 0,
            spoiled: false,
        });
        // Asked again after the clearing, because what is missing has just
        // become the whole of it.
        self.wants_headers().map(|fresh| (next, fresh))
    }

    /// Throws away what was being collected, so the next peer starts it.
    fn clear_filling(&self) {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(store) = log.as_mut() {
            store.discard_filling();
        }
    }

    /// The next run of headers this node is missing from before it arrived,
    /// or `None` when it is missing none.
    fn wants_headers(&self) -> Option<Message> {
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let store = log.as_ref()?;
        if store.headers.first_height() == 0 {
            return None;
        }
        let from = if store.filling.is_empty() {
            0
        } else {
            store.filling.reaches()
        };
        if from >= store.headers.first_height() {
            return None;
        }
        Some(Message::GetHeaders {
            from,
            count: MAX_HEADERS as u64,
        })
    }

    /// Takes a run of headers `peer` offered as the ones from before this node
    /// arrived.
    ///
    /// Only from the peer this node is filling from. Anybody may send headers
    /// and there is one collection: before this check, a stranger's single
    /// header fixed where the collection started, every honest run after it
    /// was dropped for starting somewhere else, and the whole thing was thrown
    /// away at the commitment check below. One message bought that, and it
    /// could be sent again, so a joined node could be kept from ever filling
    /// its headers in and therefore from ever being able to show the chain to
    /// anyone.
    ///
    /// What is taken is still believed of nobody. The run goes into a log of
    /// its own, and only once it reaches the oldest header this node holds is
    /// the forest it makes compared with the commitment that header already
    /// carries. A sender that invented any of it is caught there; one that
    /// sent a truthful run out of order, or with a gap, is caught by the log
    /// itself. Losing its turn is what it costs.
    fn take_headers(&self, peer: PeerId, from: u64, headers: &[BlockHeader], now: u64) {
        if !self.filling_from().is_some_and(|turn| turn.peer == peer) {
            return;
        }
        match self.fill_headers(from, headers) {
            Filled::Ignored => {}
            // A run, so this peer keeps its turn. A header is not a run, and
            // that is the whole of the difference: renewing on one meant a peer
            // answering each question with a single header held the turn for
            // ever, and the node never filled its headers in at all.
            Filled::Grew(reached) => {
                if let Some(turn) = self.filling_from().as_mut() {
                    if reached.saturating_sub(turn.marked) >= HEADER_RUN {
                        turn.marked = reached;
                        turn.moved = now;
                    }
                }
            }
            // What was collected is gone, and whoever supplied it has just
            // shown it could not. The next peer is asked on the next round,
            // which takes remembering who this one was: see [`Turn::spoiled`].
            Filled::Discarded => {
                if let Some(turn) = self.filling_from().as_mut() {
                    turn.spoiled = true;
                }
            }
            // This node's disk, said in this node's own channels and held
            // against nobody. The turn stays where it is: the supplier has
            // done nothing wrong, and the patience on the turn still moves it
            // along if nothing else happens, so this cannot pin the node to
            // one peer either.
            //
            // Reached with no lock held, which the write half needs: saying
            // what a write cost takes the chain and then the log.
            Filled::OwnDisk(OwnDisk::Read {
                what,
                height,
                because,
            }) => self.could_not_read(what, height, &because),
            Filled::OwnDisk(OwnDisk::Write(refusing)) => self.note_refusal(refusing),
        }
    }

    /// The collecting half of [`Shared::take_headers`], with the question of
    /// who sent the run already settled.
    ///
    /// Three steps, and only the first and last hold the log. Filing a run is
    /// a few hundred records at most, which is what arrives in one message.
    /// Weighing the whole collection against the commitment is a read per
    /// header of everything before this node arrived, which for a node that
    /// joined a million and a half blocks up is a million and a half reads;
    /// holding the log across those stops every thread that wants to write a
    /// block down, because they take the chain first and the log second and so
    /// wait here with the chain in hand.
    fn fill_headers(&self, from: u64, headers: &[BlockHeader]) -> Filled {
        let (oldest, epoch) = {
            let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(store) = log.as_mut() else {
                return Filled::Ignored;
            };
            let oldest = store.headers.first_height();
            if oldest == 0 || headers.is_empty() {
                return Filled::Ignored;
            }
            let expected = if store.filling.is_empty() {
                0
            } else {
                store.filling.reaches()
            };
            if from != expected {
                return Filled::Ignored;
            }

            let held = store.filling.reaches();
            for header in headers {
                if header.height >= oldest {
                    break;
                }
                // The collection goes either way, because half a run is no
                // use to the walk that weighs it. Whose turn goes with it
                // depends on which of the two refusals this is, and reading
                // them as one cost the whole repair above.
                //
                // A run that does not follow on is the supplier's doing: it
                // was asked for a height and answered with another, and the
                // log is only the first thing to notice. That loses the turn,
                // which is what `Turn::spoiled` exists for.
                //
                // Anything else is this node's disk, said in this node's own
                // channels and held against nobody, and the turn stays where
                // it is because the supplier has done nothing wrong.
                //
                // Both used to be the second. So a peer answering every
                // question with a run starting at the wrong height kept its
                // turn for the full patience, over and over, and the node
                // charged its own disk for it: measured at twenty six
                // collections thrown away with the turn handed straight back
                // each time, and the turn only ever passing on when it ran
                // out.
                if let Err(error) = store.filling.append(header) {
                    store.discard_filling();
                    if matches!(error, StoreError::OutOfOrder { .. }) {
                        return Filled::Discarded;
                    }
                    return Filled::OwnDisk(OwnDisk::Write(Refusing::at(Writing::Headers, &error)));
                }
            }
            if store.filling.reaches() < oldest {
                return if store.filling.reaches() > held {
                    Filled::Grew(store.filling.reaches())
                } else {
                    Filled::Ignored
                };
            }
            (oldest, store.filling_epoch)
        };

        // Everything that came before the oldest header held is here. The one
        // question left is whether it is the truth, and that header answers
        // it: what it carries is the commitment to every header before it.
        let Some(anchor) = self.header_off_disk(oldest) else {
            return Filled::Ignored;
        };
        let mut forest = cairn_accumulator::Archive::new();
        for height in 0..oldest {
            // Three answers, and only one of them is about the supplier. A
            // record that is not there is a run that was thrown away or never
            // finished, which costs its owner the turn. A record this node
            // cannot read is this node, and used to cost the supplier the turn
            // just the same.
            let header = match self.filling_at(height, epoch) {
                Ok(Some(header)) => header,
                Ok(None) => return self.throw_the_run_away(epoch),
                Err(own) => return Filled::OwnDisk(own),
            };
            forest.add(header_leaf(&header.id()));
        }
        if forest.commitment() != anchor.history {
            // Somebody made them up, or sent the wrong chain's. Start over
            // rather than keep any of it, and give somebody else the turn.
            return self.throw_the_run_away(epoch);
        }

        // Only now are they this node's own headers. Written in front of what
        // it had, and the forest built again over the whole.
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(store) = log.as_mut() else {
            return Filled::Ignored;
        };
        if store.moved_since_weighed(oldest, epoch) {
            return Filled::Ignored;
        }
        if let Err(own) = join_logs(&mut store.headers, &store.filling) {
            return Filled::OwnDisk(own);
        }
        store.discard_filling();
        // As at the open: the next block applied runs this again and says what
        // it found, and this one is holding the log.
        let _ = grow_forest(&mut store.forest, &store.headers);
        Filled::Grew(oldest)
    }

    /// One record of the run being collected, with the log taken for the read
    /// alone.
    ///
    /// `None` once the collection it belongs to has been thrown away, which is
    /// what stops a reading of one run being weighed as a reading of another.
    fn filling_at(&self, height: u64, epoch: u64) -> Result<Option<BlockHeader>, OwnDisk> {
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(store) = log.as_ref() else {
            return Ok(None);
        };
        if store.filling_epoch != epoch {
            return Ok(None);
        }
        match store.filling.read_at(height) {
            Ok(header) => Ok(header),
            Err(error) => Err(OwnDisk::Read {
                what: Reading::Headers,
                height,
                because: error.to_string(),
            }),
        }
    }

    /// Throws away the run that was being collected, if it is still that run.
    fn throw_the_run_away(&self, epoch: u64) -> Filled {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(store) = log.as_mut() {
            if store.filling_epoch == epoch {
                store.discard_filling();
            }
        }
        Filled::Discarded
    }

    /// A run of headers off the disk, for a node filling in what came before
    /// it arrived.
    ///
    /// Read from the header log, which every node keeps whole whatever it does
    /// with its blocks, so this is an answer almost any node can give.
    fn headers_from(&self, from: u64, count: u64) -> Vec<BlockHeader> {
        let want = usize::try_from(count)
            .unwrap_or(MAX_HEADERS)
            .min(MAX_HEADERS);
        let per_take = usize::try_from(READS_PER_HOLD).unwrap_or(1);
        gathered_a_few_at_a_time(
            want,
            per_take,
            |at, run| {
                let at = from.saturating_add(u64::try_from(at).unwrap_or(0));
                self.headers_under_one_hold(at, u64::try_from(run).unwrap_or(0))
            },
            // A run whose halves come off different branches is refused. The
            // header log checks each record against its neighbour on the way
            // out, so the only seam this covers is the one between two takes,
            // and it is checked with nothing held.
            |before, after| after.previous == before.id(),
        )
    }

    /// A few of those headers, with the log taken once and let go of before
    /// this returns.
    ///
    /// The bound is written here rather than at the caller because this is the
    /// function that holds the lock, and what is being bounded is the hold.
    ///
    /// The second answer says whether the run goes on. It stops either way: a
    /// newcomer applies headers in order and one with a gap in it is worth
    /// nothing. What a stop says here is that asking again would read the same
    /// nothing, and a run cut short by this node's own disk is still told apart
    /// from one that simply ran out, which from the far end look the same.
    fn headers_under_one_hold(&self, from: u64, count: u64) -> (Vec<BlockHeader>, bool) {
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(store) = log.as_ref() else {
            return (Vec::new(), false);
        };
        let asked = from.saturating_add(count.min(READS_PER_HOLD));
        let stop = asked.min(store.headers.reaches());
        let mut headers = Vec::new();
        for height in from..stop {
            match store.headers.read_at(height) {
                Ok(Some(header)) => headers.push(header),
                Ok(None) => return (headers, false),
                Err(error) => {
                    self.could_not_read(Reading::Headers, height, &error);
                    return (headers, false);
                }
            }
        }
        (headers, stop == asked)
    }

    /// Builds the whole of what a newcomer asked for, holding nothing.
    ///
    /// Both answers reach for headers all over the chain, and a node holds the
    /// bodies of only the ones it could still undo, so everything is read from
    /// the log: for the far end of the chain that was always true, and for the
    /// near end it costs a page cache hit rather than the chain lock.
    ///
    /// This is also what a node writes down for itself. It used to be written
    /// twice, once here and once in a second copy of the same walk, and the
    /// second copy said in as many words that it was doing what this does.
    ///
    /// `None` when the log has not caught up with the chain `ground` was taken
    /// against. That is a node that cannot answer yet rather than one with a
    /// wrong answer, and it says nothing rather than answering badly.
    fn build_join(&self, what: Joining, ground: &Ground) -> Option<Vec<u8>> {
        let header_at = |height: u64| self.header_off_disk(height);
        let tip = header_at(ground.at.height)?;
        if tip.id() != ground.at.id {
            return None;
        }

        match what {
            Joining::Weight => {
                // Proved against the forest from before the tip, which is the
                // one the tip's own header vouches for, and read from disk
                // rather than from memory: holding it in memory would be a
                // gigabyte at thirty years.
                let prove = |height: u64| self.proof_off_disk(height, tip.height);
                let start = open_start(
                    &tip,
                    ground.history.clone(),
                    SAMPLES,
                    &self.params,
                    header_at,
                    prove,
                )?;
                Some(start.encode())
            }
            Joining::Ledger => {
                // Not this node's ledger as it stands. One from far enough
                // below the tip that whoever wrote it had to keep mining over
                // it, which is the only thing a newcomer can lean on: it
                // cannot check a ledger, having watched no transaction go
                // past. The same one this node keeps for itself, for the same
                // reason: one path, one set of rules, and a node that reads
                // its own disk back checks it the way anybody else would.
                let anchor_height = tip.height.checked_sub(self.params.burial)?;
                let anchor = self.proof_off_disk(anchor_height, tip.height)?;
                build_ledger(
                    ground.buried.as_ref()?,
                    &header_at(anchor_height)?,
                    &tip,
                    ground.history.clone(),
                    anchor,
                    header_at,
                )
                .map(|held| held.encode())
            }
        }
    }
}

/// Brings the log in line with the branch the chain now follows.
///
/// The log holds the followed branch in order of height, and nothing else. It
/// could as easily hold every block as it arrived, which is simpler to write
/// and what this used to do, but then a record's position means nothing: the
/// fifth record is the fifth block that turned up, and asking for the block at
/// height five means reading the whole file. Keeping the branch instead makes
/// position and height the same number, which is what lets a node forget a
/// block and still find it again.
///
/// The cost is that a reorganisation rewrites the tail. That is bounded by how
/// deep a reorganisation may go, and reorganisations are rare.
///
/// A failure here does not stop the node on the spot: it costs blocks on the
/// next restart rather than the chain this node is following, and a disk that
/// refuses one write often takes the next. What it does is report, so that
/// [`Shared::note_writing`] can watch the gap and stop the node before the gap
/// stops being one anything can close.
fn write_branch(store: &mut Store, accepted: &Accepted, chain: &ChainStore) -> Wrote {
    // All three run whatever the others said. The forest is what the header
    // log says it is and follows it either way, and the blocks are a separate
    // file with a separate way of failing.
    let headers = write_headers(&mut store.headers, chain);
    let forest = grow_forest(&mut store.forest, &store.headers);
    let blocks = write_blocks(&mut store.blocks, accepted, chain);
    Wrote {
        reaches: store.blocks.reaches(),
        // The blocks first when more than one refused. They are the half that
        // costs a restart the chain rather than the ability to show it.
        refusing: blocks.or(headers).or(forest),
    }
}

/// What one pass at bringing the disk in line with the branch managed.
struct Wrote {
    /// The height the block log now reaches, one past the highest block on
    /// the disk.
    reaches: u64,
    /// What stopped the pass, when something did.
    refusing: Option<Refusing>,
}

/// A write the disk would not take, in the words the store used.
///
/// The words matter more than the fact. "No space left on device" and
/// "input/output error" call for two different afternoons, and nothing in here
/// is in a position to tell them apart, so both are carried up whole to
/// somebody who is.
#[derive(Clone, Debug)]
struct Refusing {
    what: Writing,
    because: String,
}

impl Refusing {
    fn at(what: Writing, because: &impl std::fmt::Display) -> Self {
        Self {
            what,
            because: because.to_string(),
        }
    }
}

/// Brings the header forest in line with the header log.
///
/// The forest is what the log says it is, so it follows rather than being
/// written alongside: one place decides which headers this node is on, and the
/// other agrees with it.
///
/// Only a log that starts at the first block can make a forest at all. A node
/// handed a ledger has headers from where it was handed on, and no path
/// through what came before them exists to be built.
/// A record the store refuses to read is not a record that is not there, and
/// this is the walk where the difference used to be lost. Every read here was
/// taken with `.ok().flatten()`, so a header the store would not vouch for
/// read as absent: the leaf it should have matched matched nothing, the walk
/// went on down, and it has no floor, so one damaged record took the forest
/// back to nothing. The gentler ending was as bad and quieter: the loop that
/// fills the forest in stopped at the first refused read, the forest stayed
/// short, and this node went on running as one that had simply decided not to
/// show anyone the chain.
///
/// So a refusal ends the pass where it happens, nothing is cut on the strength
/// of it, and it is carried up to be said out loud.
fn grow_forest(forest: &mut HeaderTree, headers: &HeaderLog) -> Option<Refusing> {
    if headers.first_height() != 0 {
        return None;
    }
    // Where the two part company, walked back from the end. A reorganisation
    // replaces headers without shortening the log, so the lengths agreeing is
    // not the same as the contents agreeing.
    //
    // A forest longer than the log needs no cut of its own before this: the
    // walk starts no further than the log reaches, and the cut after it takes
    // the forest back to where they agree, which is never past that.
    let mut common = forest.len().min(headers.reaches());
    while common > 0 {
        let at = common.saturating_sub(1);
        let held = match forest.leaf_at(at) {
            Ok(leaf) => leaf,
            Err(error) => return Some(Refusing::at(Writing::Headers, &error)),
        };
        let now = match headers.read_at(at) {
            Ok(header) => header.map(|header| header_leaf(&header.id())),
            Err(error) => return Some(Refusing::at(Writing::Headers, &error)),
        };
        if held.is_some() && held == now {
            break;
        }
        common = at;
    }
    if forest.len() > common {
        if let Err(error) = forest.keep_first(common) {
            return Some(Refusing::at(Writing::Headers, &error));
        }
    }
    for height in forest.len()..headers.reaches() {
        let header = match headers.read_at(height) {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(error) => return Some(Refusing::at(Writing::Headers, &error)),
        };
        if let Err(error) = forest.append(header_leaf(&header.id())) {
            return Some(Refusing::at(Writing::Headers, &error));
        }
    }
    None
}

/// Brings the header log in line with the branch this node follows.
///
/// Headers are kept whatever happens to the blocks, because they are what a
/// newcomer is shown to settle which chain carries the most work. A node that
/// dropped them could no longer answer, and would still be saying it can.
///
/// A reorganisation takes the tail off and the new branch is written over the
/// same ground, which is the same shape as the block log and bounded the same
/// way.
fn write_headers(headers: &mut HeaderLog, chain: &ChainStore) -> Option<Refusing> {
    let reaches = chain.height()?.saturating_add(1);

    // Where the log and the branch part company. Walking back from the tip
    // rather than trusting the log, since a reorganisation may have replaced
    // headers the log still holds without shortening it.
    //
    // A refusal from the store is kept rather than returned on the spot. It
    // tells this walk nothing about the branch, so the walk goes on and the
    // log is written again from the chain wherever the chain still holds the
    // blocks, which is what a node did with a damaged record before any of
    // this reported anything. What the refusal is for is the operator: one
    // changed byte in a header file is a disk worth hearing about, whether or
    // not the node managed to put itself right afterwards.
    let mut refusing = None;
    let mut common = headers.reaches().min(reaches);
    while common > headers.first_height() {
        let at = common.saturating_sub(1);
        let held = match headers.read_at(at) {
            Ok(header) => header.map(|header| header.id()),
            Err(error) => {
                refusing.get_or_insert_with(|| Refusing::at(Writing::Headers, &error));
                None
            }
        };
        let now = chain
            .block_at(at)
            .map(|block| block.header.id())
            .or_else(|| chain.id_at(at));
        match (held, now) {
            (Some(held), Some(now)) if held == now => break,
            // Nothing to compare against this far back: the chain no longer
            // holds an identifier for it, and what is written stands.
            (_, None) => break,
            _ => common = at,
        }
    }
    // The cut goes ahead whatever the walk had to say. Headers that no longer
    // follow the branch are worse than headers missing: what the log holds is
    // what this node shows a newcomer, and a forest is built over it and
    // proved against, so leaving an abandoned branch in place would have this
    // node handing out proofs that fold to a root nobody else has. Short is
    // the safe direction; wrong is not.
    if headers.reaches() > common {
        if let Err(error) = headers.keep_below(common) {
            return Some(Refusing::at(Writing::Headers, &error));
        }
    }

    // Where the chain can still answer, not where its branch begins. A branch
    // remembers identifiers by milestones far below the blocks themselves, and
    // a block is dropped once it is past undoing, so starting at the branch's
    // beginning asks for headers this chain let go of on purpose and is
    // refused at the first step.
    //
    // On a node that joined a chain, that first step was its whole life: the
    // header log stayed empty for ever, so it could show a newcomer none of
    // the chain while its own introduction said it could, and every block it
    // applied reported a write it could not make on a disk with nothing wrong
    // with it. Starting at the anchor is the honest answer, and the chain
    // below it is one that node was never given.
    let mut height = if headers.is_empty() {
        chain.held_from()
    } else {
        headers.reaches()
    };
    while height < reaches {
        // Nothing here can write this one. A chain keeps block bodies for a
        // window behind its tip and reads the rest back off the block log, and
        // this walk holds the chain, so what it cannot see in memory it cannot
        // have. The log stops where it stops, which costs this node the
        // ability to show a newcomer the chain and costs the chain itself
        // nothing. Said, because a node that has quietly stopped being able to
        // answer goes on looking exactly like one that can.
        // The header, not the block. A chain keeps a header for every block on
        // its branch whatever happens to the body, and a header log wants
        // headers. Asking for the block meant a node was refused a hundred and
        // eighty two bytes for the want of a body it had no use for, and on a
        // node that joined a chain that refusal came on the very first height:
        // its header log stayed empty for the rest of its life, so it could
        // show a newcomer none of the chain while its own introduction said it
        // could.
        let Some(header) = chain.header_at(height) else {
            return refusing.or_else(|| {
                Some(Refusing::at(
                    Writing::Headers,
                    &format!(
                        "the header at height {height} cannot be written down: the chain has \
                         let go of the block it comes from"
                    ),
                ))
            });
        };
        if let Err(error) = headers.append(&header) {
            return Some(Refusing::at(Writing::Headers, &error));
        }
        height = height.saturating_add(1);
    }
    refusing
}

fn write_blocks(log: &mut BlockLog, accepted: &Accepted, chain: &ChainStore) -> Option<Refusing> {
    let added = match accepted {
        Accepted::Duplicate | Accepted::SideBranch => return None,
        // The block just applied is the tip, and the log ends one short.
        Accepted::Extended => 1usize,
        Accepted::Reorganised { added, .. } => added.len(),
    };

    // Where the branch and what the log held part company, counted from the
    // branch rather than from the log. Counting from the log would be right
    // only while the two agree, and a write that failed earlier leaves them
    // disagreeing: the log would then be cut in the wrong place, or extended
    // from the wrong end, and every record past that point would sit at a
    // position that is not its height. A node reading its own log by position
    // would serve the wrong blocks, confidently, to everyone catching up.
    let reaches = chain.height()?.saturating_add(1);
    let common = reaches.saturating_sub(added as u64);
    if log.reaches() > common {
        if let Err(error) = log.keep_below(common) {
            return Some(Refusing::at(Writing::Blocks, &error));
        }
    }
    // Everything the branch carries beyond what the log holds. Usually one
    // block; more if a write failed earlier and the log fell behind.
    //
    // A log that holds nothing starts wherever the first block this node can
    // still produce sits, which for a node handed a ledger is the height it
    // was handed rather than zero. Counting from the log's own length instead
    // would look for a block at position zero, which such a node has never had
    // and never will, and it would write nothing for the rest of its life.
    //
    // The first block it can still produce, and not the block just applied.
    // Those are the same only while every earlier write landed: a first write
    // the disk refused, which is the network's first block appended when the
    // node opens and never checked, left a log beginning partway up the chain,
    // and the next start read that as a node that had joined above its own
    // disk and cut every block in it.
    let mut height = if log.is_empty() {
        let mut lowest = reaches.saturating_sub(added as u64);
        while let Some(below) = lowest.checked_sub(1) {
            if chain.block_at(below).is_none() {
                break;
            }
            lowest = below;
        }
        lowest
    } else {
        log.reaches()
    };
    while height < reaches {
        // A block the chain has already let go of cannot be written. This is
        // the end of the road for a log that fell behind: the catch-up reads
        // bodies out of memory, and past the reorganisation window there are
        // none. Said rather than broken out of, because a gap that has reached
        // this is a gap nothing will ever close, and until now nothing
        // anywhere reported it.
        let Some(block) = chain.block_at(height) else {
            return Some(Refusing::at(
                Writing::Blocks,
                &format!(
                    "the block at height {height} left memory before the disk took it, \
                     so there is nowhere left to read it from"
                ),
            ));
        };
        if let Err(error) = log.append(block) {
            return Some(Refusing::at(Writing::Blocks, &error));
        }
        height = height.saturating_add(1);
    }
    None
}

/// Answers the questions the sync layer set aside, now that nothing is held.
///
/// A locator and a request for blocks both reach the disk for a peer far
/// enough behind, and both run with the chain held. Returns whether the peer
/// is still worth writing to.
fn answer_deferred(
    shared: &Arc<Shared>,
    peer: &mut PeerState,
    reaction: &Reaction,
    outbound: &Outbound,
    now: u64,
) -> bool {
    if let Some(locator) = reaction.locate.as_ref() {
        let (from, count) = shared.chain_after(locator, MAX_CHAIN);
        if outbound.try_send(Message::Chain { from, count }).is_err() {
            return false;
        }
    }
    // Gathered in one place so they go out in the order they were asked for: a
    // peer applies them as they arrive, and one whose parent has not landed is
    // dropped.
    //
    // Weighed here and nowhere earlier. The ask says how many blocks, and a
    // block is anything up to what the consensus rules allow, so what this
    // costs to put on the wire is known once the block is in hand and not
    // before. `GetBlocks` was priced at a seek a block and nothing for the
    // megabyte that follows it, which sold a gigabyte per ten seconds for
    // about six and a half kilobytes a second of asking.
    for block in shared.blocks_at(&reaction.fetch) {
        let answer = Message::Block(Box::new(block));
        let weight = answer.weight();
        // What it could not afford is not sent, and the peer asks again
        // against a fresh window. A short batch is what it already gets for
        // heights this node no longer holds, so nothing downstream is new.
        if !peer.afford_serving(weight, now) {
            break;
        }
        // And a queue this full is a peer that has stopped reading rather than
        // one that is behind, so the rest of the batch is not built for it
        // either. The connection is left to the writer's own deadline.
        if outbound.hand_over(answer, weight).is_err() {
            break;
        }
    }
    // A piece of a join answer, built now that nothing is held. A node that
    // cannot answer says nothing rather than answering badly.
    if let Some((what, part)) = reaction.join {
        if let Some(piece) = shared.serve_join(what, part) {
            if outbound.try_send(piece).is_err() {
                return false;
            }
        }
    }
    // Paths through the cold set, built now that the chain is nobody's. The
    // answer always names every place that was asked about, including the ones
    // this node cannot place: a wallet with money it cannot move has to be
    // able to tell a node that cannot help from a node that has gone away, and
    // go and ask somebody else.
    if let Some(positions) = reaction.prove.as_ref() {
        let placed = shared.place(positions);
        if outbound.try_send(Message::Proofs(placed)).is_err() {
            return false;
        }
    }
    if let Some((from, count)) = reaction.headers {
        let headers = shared.headers_from(from, count);
        if !headers.is_empty()
            && outbound
                .try_send(Message::Headers { from, headers })
                .is_err()
        {
            return false;
        }
    }
    // Addresses, drawn now that the chain is nobody's. The book has to be
    // ordered before any of it can be shared, and doing that under the chain
    // was the one place where the size of a stranger's book decided how long
    // everybody else waited.
    //
    // The clock decides which half of the book rotates into this answer, so a
    // peer asking twice does not hear the same names twice.
    if reaction.share_addresses {
        let sample = shared.book().sample(MAX_SHARED_ADDRESSES, unix_now());
        if outbound.try_send(Message::Peers(sample)).is_err() {
            return false;
        }
    }
    true
}

/// Writes the address book down, and says so when the disk will not take it.
///
/// The book is not the chain and losing it costs nothing that cannot be
/// learned again. What it costs is the next start: a node that comes back with
/// an empty book knows only the seeds on its command line, and an operator who
/// has never seen this file fail has no reason to look for it.
fn save_book(shared: &Arc<Shared>) {
    let Some(directory) = shared.directory.as_ref() else {
        return;
    };
    // Nothing is copied or written while the addresses stand where the last
    // write left them. The file is a list of addresses, so a round in which
    // none went in or out would write the same bytes over the same bytes, and
    // that is most rounds of most nodes: upkeep runs once a second for the
    // life of the node, and it was copying the whole book, turning up to four
    // thousand addresses into ninety kilobytes of text and handing it to the
    // disk every time.
    let (book, changes) = {
        let book = shared.book();
        let changes = book.changes();
        if shared.book_written_at.load(Ordering::Relaxed) == changes {
            return;
        }
        (book.clone(), changes)
    };
    let refusal = book.save(directory).err().map(|error| error.to_string());
    if refusal.is_none() {
        // Only a write that got through. Otherwise the next round tries again,
        // which is the whole of what a node can do about a disk that refused.
        shared.book_written_at.store(changes, Ordering::Relaxed);
    }
    *shared
        .unsaved_book
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = refusal;
}

/// Takes connections, and turns away the ones this node has no room for.
///
/// Accepting without limit is the cheapest attack there is: two threads and a
/// read buffer per connection, and nothing stopping one machine from opening
/// thousands. The three refusals here are the ceiling, the per address share,
/// and peers still under refusal for something they did earlier.
///
/// The listener is polled rather than blocked on. A blocking accept only
/// returns when someone connects, so stopping the node meant opening a
/// connection to it purely to wake this thread. On a node listening on a
/// public address that connection can fail, and then the node never stops:
/// an operator's stop or reboot would hang on a process waiting for a
/// visitor. Fifty milliseconds of idle polling buys an exit that always works.
fn accept_loop(shared: &Arc<Shared>, listener: &TcpListener) {
    let polling = listener.set_nonblocking(true).is_ok();
    while shared.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, from)) => {
                shared.took_a_visitor();
                // A socket accepted from a non-blocking listener inherits that
                // mode on some platforms. Left alone, every read on it would
                // return immediately and be taken for a deadline passing.
                let _ = stream.set_nonblocking(false);
                if !shared.running.load(Ordering::SeqCst) {
                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }
                let host = from.ip();
                if shared.refuses(host, unix_now()) || !shared.has_room_to_accept(Some(host)) {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                attach_peer(shared, stream, None);
            }
            Err(error) if polling && error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                // Leaving here ended the thread, and the thread owned the
                // listener, so the port closed for the life of the process
                // while everything else about the node went on working and
                // saying so. What reaches this arm is almost never the socket
                // being gone. It is the process or the machine being out of
                // descriptors, which is a fact about this moment rather than
                // about any peer, and it clears the instant somebody hangs up:
                // exactly the moment a node most needs to still be listening.
                //
                // So the loop waits and asks again, and counts what it was
                // refused with rather than going quiet. Nothing here can spin:
                // every turn through it sleeps the same poll the idle path does.
                shared.could_not_take_a_visitor(&error.to_string());
                thread::sleep(ACCEPT_POLL);
            }
        }
    }
}

/// Keeps the node connected to roughly [`TARGET_PEERS`] peers, and writes the
/// address book down so the next start is not from nothing.
fn maintenance_loop(shared: &Arc<Shared>) {
    let mut last_round = unix_now();
    while shared.running.load(Ordering::SeqCst) {
        let mut waited = Duration::ZERO;
        while waited < MAINTENANCE_PERIOD {
            if !shared.running.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(SLEEP_SLICE);
            waited = waited.saturating_add(SLEEP_SLICE);
        }
        if !shared.running.load(Ordering::SeqCst) {
            return;
        }
        let now = unix_now();
        // A machine that was away comes back holding nothing against anyone.
        // Without this a laptop closed for a night wakes with an empty book
        // and no way back onto the network: every address it knew failed while
        // it slept, and an address that fails enough times is dropped.
        if was_away(last_round, now) {
            shared.book().forgive_all();
        }
        last_round = now;
        // Asking again matters: a peer that joined after this node introduced
        // itself is only ever learned about by asking a second time.
        shared.broadcast(None, &Message::GetPeers);
        look_up_seed_names(shared, now);
        dial_from_book(shared, now);
        save_book(shared);
        collect_finished(shared);
        shared.trim_history();
        // Peers this node can actually put a question to, which is not every
        // socket in the table. A connection that has not introduced itself
        // cannot be asked anything, and counting one as somebody to ask is
        // what told a node handed a ledger that it had waited an hour "with
        // peers to ask" while nobody had been asked at all, and sent its
        // operator to delete the directory over it.
        let connected: Vec<PeerId> = shared
            .peers()
            .iter()
            .filter(|(_, peer)| peer.worth_speaking_to())
            .map(|(id, _)| *id)
            .collect();
        // Headers from before this node arrived, if it joined a chain rather
        // than reading one. Any node that read the chain can answer and the
        // answer is checked rather than trusted, so there is nobody in
        // particular to ask; but there is one collection, so exactly one peer
        // is asked at a time and only that one is collected from.
        if let Some((peer, asking)) = shared.asks_headers_of(&connected, now) {
            shared.send_to(peer, asking);
        }
        keep_the_undertaking(shared, &connected, now);
        ask_again_for_the_join(shared, now);
        drive_choosing(shared, now);
        shared.refusals().forget_expired(now);
        shared.forget_spent_windows(now);
    }
}

/// One round of what a node handed a ledger owes itself.
///
/// A handover lands from below the tip on purpose, and what stands behind it
/// is the blocks in between, which this node has to validate for itself. One
/// question went out when the ledger landed, to the peer that supplied it, and
/// nothing ever asked again: a supplier that went quiet with those blocks
/// undelivered left the node waiting for the rest of its life, holding a
/// ledger nobody had stood behind and telling nobody anything was wrong.
///
/// So the undertaking is kept here. The blocks are not that peer's to give or
/// withhold, and everyone else is asked for them once it stops delivering.
/// Asking a fresh peer for a fresh anchor is not the answer and could not be:
/// a node already following a chain cannot adopt another, and the anchor was
/// never the part in doubt. What is missing is the blocks above it, and anyone
/// on that chain has them.
fn keep_the_undertaking(shared: &Arc<Shared>, connected: &[PeerId], now: u64) {
    let height = shared.chain().height();
    let Some(owed) = shared.probation_round(height, connected.len(), now) else {
        return;
    };
    match owed {
        Owed::Waiting => {}
        Owed::AskAgain => {
            let locator = shared.chain().locator();
            shared.broadcast(None, &Message::GetChain { locator });
        }
        // Said and stopped, the way an outdated node is. Carrying on would
        // mean going on answering off a ledger nothing is ever going to stand
        // behind, which for a wallet reading a balance is a confident wrong
        // answer rather than a slow one.
        Owed::GivenUp(stranded) => {
            shared.stranded().get_or_insert(stranded);
            shared.running.store(false, Ordering::SeqCst);
        }
    }
}

/// Asks again for the piece of a join answer that has not arrived.
///
/// The one thing the collection cannot do for itself. A join is a chain of
/// questions, each piece that lands asking for the next, and nothing else
/// ever asks. So the first question that goes unanswered ends the whole
/// exchange, and half a minute later [`JOIN_PATIENCE`] gives up on it and
/// starts again from the first piece. The collector was written expecting a
/// node to ask again for what it is missing; no part of the node ever did.
///
/// A question goes unanswered for one ordinary reason above all others: the
/// peer serving it had spent the allowance window it was asked in. A handover
/// is deliberately the most expensive thing a peer can ask for, at an eighth
/// of a window per piece, so any join of more than eight pieces runs that
/// window out by design and is meant to carry on in the next one.
///
/// Which is why the question is asked again when that window has turned,
/// rather than after some number of seconds. It is the moment the answer can
/// change, it needs no guess about how fast a piece travels, and it cannot
/// fire more than once a window however long the collection is still.
///
/// Asked of the same peer, because a collection belongs to the peer it was
/// started from and a piece from anybody else is refused.
fn ask_again_for_the_join(shared: &Arc<Shared>, now: u64) {
    // An archivist reads rather than joins (see `drive_choosing`), and the
    // chooser still has the turn down as a join. Asking again here is what
    // started the join it had not asked for.
    if shared.chain().is_archiving() {
        return;
    }
    let Some((peer, asked_at)) = shared.choosing().asking_join() else {
        return;
    };
    let last = shared.join_asked_again_at.load(Ordering::Relaxed);
    if !a_window_has_turned(last, now) {
        return;
    }
    let asking = {
        let joining = shared
            .joining
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // When the last piece landed, or when the peer was asked if none has:
        // the first question is as droppable as the rest, and the one nobody
        // else would ever ask again.
        let since = joining.moved().unwrap_or(asked_at);
        if a_window_has_turned(since, now) {
            still_wanted(&joining)
        } else {
            None
        }
    };
    let Some((what, part)) = asking else {
        return;
    };
    shared.join_asked_again_at.store(now, Ordering::Relaxed);
    shared.send_to(peer, Message::GetJoin { what, part });
}

/// The piece a join is waiting on, or `None` when it is waiting on nothing.
fn still_wanted(joining: &Progress) -> Option<(Joining, u32)> {
    match joining {
        // Asked and nothing back at all, which is where a join is when the
        // question that starts it is the one that went missing.
        Progress::Idle => Some((Joining::Weight, 0)),
        Progress::Landed => None,
        Progress::Weighing(collecting) => Some((Joining::Weight, collecting.wanted()?)),
        // Between the two halves, with nothing yet to count: the first piece
        // of the ledger is the one that says how many there are.
        Progress::Weighed { .. } => Some((Joining::Ledger, 0)),
        Progress::Fetching { collecting, .. } => Some((Joining::Ledger, collecting.wanted()?)),
    }
}

/// The ledger at `at`, with the headers a newcomer needs to stand behind it.
///
/// Two runs travel in full. The recent ones are what the difficulty and
/// timestamp rules read, so a node that has them can check the next block. The
/// buried ones are every header between this ledger and the tip that was
/// weighed, and they are what says the ledger belongs to that chain at all: a
/// forest proof only places a header in a forest the sender made, so on its
/// own it can be satisfied by swapping a leaf. Whoever takes them rebuilds the
/// forest from them and checks the run block by block.
fn build_ledger(
    state: &LedgerState,
    at: &BlockHeader,
    tip: &BlockHeader,
    tip_history: Forest,
    anchor: ForestProof,
    header_at: impl Fn(u64) -> Option<BlockHeader>,
) -> Option<Handover> {
    // The headers before the one this ledger belongs to, not before the tip:
    // they are what the difficulty and timestamp rules read, and the first
    // block this newcomer will check is the one after `at`.
    let from = at
        .height
        .saturating_sub(u64::try_from(RECENT_HEADERS.saturating_sub(1)).unwrap_or(0));
    let mut recent = Vec::with_capacity(RECENT_HEADERS);
    for height in from..=at.height {
        recent.push(header_at(height)?);
    }

    let span = usize::try_from(tip.height.checked_sub(at.height)?).ok()?;
    let mut buried = Vec::with_capacity(span.min(1024));
    for height in at.height.checked_add(1)?..=tip.height {
        buried.push(header_at(height)?);
    }
    // `None` when the ledger cannot show where one of the notes in its grace
    // window sits, which is a node that has nothing to hand over rather than
    // one with a bad answer.
    state
        .handover(*at, *tip, tip_history, anchor, buried, recent)
        .ok()
}

/// Records a header log holds and will not answer for.
///
/// Asked before the log is filled in from the blocks, because filling it in is
/// what destroys the evidence: the first header appended to a log holding no
/// records cuts the file. Until that moment, a log reporting nothing over a
/// file with whole records in it is the store saying it will not stand behind
/// its own head. See [`Restored::headers_set_aside`].
fn headers_the_store_will_not_stand_behind(headers: &HeaderLog) -> u64 {
    if !headers.is_empty() {
        return 0;
    }
    std::fs::metadata(headers.path())
        .map(|held| held.len().checked_div(HEADER_BYTES as u64).unwrap_or(0))
        .unwrap_or(0)
}

/// Fills the header log in from the blocks, for the stretch it is missing.
///
/// For a node updated from a version that kept no headers, and for one whose
/// header log was lost. Both are the same case: what the blocks can still show
/// is written, and what they cannot is gone.
///
/// Best effort, and that is the repair. This used to hand its failure back out
/// of [`Node::open`], and the failure is reachable without any damage to the
/// chain at all: the index beside the block log is a derived file, the store
/// checks its last offset against the length of the log and no other, and the
/// replay that starts a node reads the log forward and never opens the index.
/// So one flipped byte in the middle of it replays twelve blocks out of twelve,
/// reports a clean start, and then refuses the very first read this makes.
/// Measured: `record 5 says it holds 244 bytes, the index gives it 184`, out of
/// `Node::open`, on every start, for ever, on a node whose blocks were all
/// there and whose index the store rebuilds from those blocks when it is asked
/// to. An unattended node stayed down over it.
///
/// So it stops where the disk stopped answering and keeps what it wrote. The
/// stretch it could not write is not lost either: the first block this node
/// accepts runs [`write_headers`], which fills the log from the chain's own
/// headers rather than from the disk, and that walk needs no block bodies at
/// all. What is returned is for the operator, because a disk that ate one
/// record has not finished.
fn catch_up_headers(headers: &mut HeaderLog, blocks: &BlockLog) -> CaughtUp {
    if blocks.is_empty() {
        return CaughtUp::default();
    }
    let from = if headers.is_empty() {
        blocks.first_height()
    } else {
        headers.reaches()
    };
    if from < blocks.first_height() {
        // A gap nothing can fill: the headers stop before the blocks start.
        // Starting again from the blocks is the most that can be said.
        //
        // Counted before the cut, and reported. This deletes every header the
        // node had, which is the one loss here that the network has to give
        // back rather than the blocks: until a peer does, the node cannot show
        // a newcomer which chain carries the most work. It used to say nothing
        // whatever, and a start that emptied the header log printed what a
        // healthy start prints.
        let dropped = headers.len();
        if let Err(error) = headers.keep_below(0) {
            return CaughtUp {
                dropped: 0,
                replaced: 0,
                unread: Some(stopped_at(Reading::Headers, 0, &error)),
            };
        }
        return CaughtUp {
            dropped,
            replaced: 0,
            unread: catch_up_from(headers, blocks, blocks.first_height()),
        };
    }
    // Where the header log leaves the branch the blocks hold. A stop between
    // the two writes of a reorganisation leaves the headers on the new branch
    // from the fork and the blocks on the old one, and filling in after that
    // stitched the old branch on top of the new: a seam nothing afterwards
    // visits, since every later walk starts at the tip and stops at the first
    // record that agrees.
    let (from, replaced) = match off_the_branch(headers, blocks) {
        Some(fork) => {
            let replaced = headers.reaches().saturating_sub(fork);
            if let Err(error) = headers.keep_below(fork) {
                return CaughtUp {
                    dropped: 0,
                    replaced: 0,
                    unread: Some(stopped_at(Reading::Headers, fork, &error)),
                };
            }
            (fork, replaced)
        }
        None => (from, 0),
    };
    CaughtUp {
        dropped: 0,
        replaced,
        unread: catch_up_from(headers, blocks, from),
    }
}

/// The height from which the header log holds a branch the block log does
/// not, or `None` where the two agree at the top of what both hold.
///
/// Walked back from there and no further than a reorganisation can reach,
/// since that is the only way the two come apart. A record either side will
/// not read ends the walk with nothing to cut: that is the disk's news, and
/// the first block this node accepts reads the same record and says so. So
/// does finding no height within that reach where the two agree, which no
/// reorganisation leaves and which the blocks could not mend anyway.
fn off_the_branch(headers: &HeaderLog, blocks: &BlockLog) -> Option<u64> {
    let top = headers.reaches().min(blocks.reaches());
    let bottom = headers
        .first_height()
        .max(blocks.first_height())
        .max(top.saturating_sub(u64::try_from(MAX_REORG_DEPTH).unwrap_or(u64::MAX)));
    for at in (bottom..top).rev() {
        let held = headers.read_at(at).ok()??;
        let block = blocks.read_at(at).ok()??;
        if held.id() == block.header.id() {
            let fork = at.saturating_add(1);
            return (fork < top).then_some(fork);
        }
    }
    None
}

/// What filling the header log in from the blocks did.
#[derive(Debug, Default)]
struct CaughtUp {
    /// Headers deleted because the blocks left them stranded.
    ///
    /// See [`Restored::headers_dropped`]. Zero on every ordinary start.
    dropped: u64,
    /// Headers cut because they were of a branch the blocks are not on.
    ///
    /// See [`Restored::headers_replaced`]. Zero on every ordinary start.
    replaced: u64,
    /// A read or a write that the disk refused partway through the fill.
    unread: Option<Unread>,
}

/// The same, and it is where both halves can refuse.
///
/// A block that will not read is this node's own disk, and it is what the
/// return value is for. A header that will not be written is the same disk
/// from the other side, and it is carried the same way rather than being made
/// fatal: the next block accepted tries the identical write and reports it
/// through [`Unwritten`], which is the channel for a disk that will not take
/// what this node puts on it and says so in the words the disk used.
fn catch_up_from(headers: &mut HeaderLog, blocks: &BlockLog, from: u64) -> Option<Unread> {
    for height in from..blocks.reaches() {
        let block = match blocks.read_at(height) {
            Ok(Some(block)) => block,
            Ok(None) => break,
            Err(error) => return Some(stopped_at(Reading::Blocks, height, &error)),
        };
        if let Err(error) = headers.append(&block.header) {
            return Some(stopped_at(Reading::Headers, height, &error));
        }
    }
    None
}

/// One refusal met before the node exists to be told about it.
fn stopped_at(what: Reading, height: u64, because: &impl std::fmt::Display) -> Unread {
    Unread {
        what,
        height,
        because: because.to_string(),
        refusals: 1,
    }
}

/// Puts `front` in front of `log`, leaving one run from the older of the two.
///
/// Every record is rewritten, which is a pass over the headers and happens
/// once in the life of a node that joined a chain.
///
/// Every failure here is this node's own disk and none of them is the
/// supplier's: the run being merged has already been weighed against the
/// commitment the oldest header carries, so by this point it is known to be
/// the truth. They used to be indistinguishable from a run that was invented,
/// and the node blamed whoever had just handed it a correct one.
///
/// The merge itself is [`HeaderLog::join`], which writes the two runs into a
/// file beside the log and moves it into place. This used to read every header
/// into one vector, empty the log and write them back: 290 MB in hand at
/// thirty years of chain, on the one cost this design exists to keep flat, and
/// a machine that stopped in the middle left a header log holding a prefix
/// with nothing that knew it. What the next start did with that prefix was
/// delete every header the node had, in silence. Both halves of that are gone:
/// the merge holds one header at a time, and an interrupted one leaves the log
/// that was there.
fn join_logs(log: &mut HeaderLog, front: &HeaderLog) -> Result<(), OwnDisk> {
    log.join(front).map_err(|failed| match failed {
        JoinFailed::Read { height, source } => OwnDisk::Read {
            what: Reading::Headers,
            height,
            because: source.to_string(),
        },
        JoinFailed::Write(error) => OwnDisk::Write(Refusing::at(Writing::Headers, &error)),
    })
}

/// Reads back the ledger a node was handed, if it kept one.
///
/// Put through `accept` again on the way in, so a file that rotted, was
/// truncated, or was written by a build with other rules is refused rather
/// than believed. What that costs is one pass over a file this node only has
/// if it joined.
///
/// Not *exactly* as it was when it arrived, which is what this said. The
/// network path pins one more thing before `accept` runs: `take_the_ledger`
/// refuses unless `handover.tip.id()` is the tip the sampling weighed. Nothing
/// weighs a tip on the way off the disk, and `accept` takes neither a clock
/// nor a tip to compare against, so a self-consistent handover mined at the
/// floor satisfies every rule it does apply.
///
/// Which is not a hole so much as a sentence that promised more than the code
/// keeps: whoever can write this file can rewrite the block log and the key
/// beside it, and has not needed to forge anything. The claim worth making is
/// the one made of replay in `Node::open`, where every block really is
/// revalidated rather than taken on the file's word. Said here so that nobody
/// reads this file as carrying that guarantee too.
///
/// The undertaking comes back with it, because this file is where it is
/// written down. `accept` says nothing about the blocks above the anchor;
/// validating them is what the anchor was taken on the promise of, and a node
/// that forgot the promise on its way through a restart came back looking like
/// an ordinary node on an ordinary chain. Nothing else on the disk records it
/// and nothing else needs to: the file is only replaced once this node can
/// write a ledger of its own, which is once it has validated that stretch.
/// Where a node handed a ledger at `anchor`, under a tip at `tip`, has to get
/// its own validation to.
///
/// The burial depth, which is what the anchor was taken on the promise of, and
/// never further even when the handover names a tip deeper than the rules
/// demand. A supplier is free to anchor further down; what it is not free to
/// do is set how much this node owes itself.
///
/// The `min` is there because a rule this depends on lives in `accept`, which
/// refuses a handover shallower than the burial. Leaning on it rather than
/// restating it would make this quietly wrong the day that rule moved.
fn settles_at(anchor: u64, tip: u64, params: &ConsensusParams) -> u64 {
    anchor.saturating_add(params.burial).min(tip)
}

/// A ledger read back off the disk: the state, the headers below its tip, the
/// height it is anchored at, and the height this node must reach on its own
/// before it will stand behind it.
type Handed = (LedgerState, Vec<BlockHeader>, u64, u64);

/// Reads the ledger a node starts from, telling a file that is not there apart
/// from one that is and will not be used.
fn read_handed_ledger(
    directory: &Path,
    params: &ConsensusParams,
) -> Result<Option<Handed>, NodeError> {
    let unusable = |because: String| NodeError::UnusableLedger { because };
    // No ledger this build writes or takes is longer than a join may be, and
    // the length is asked before anything is read. Every decoder behind this
    // bounds what it builds, and none of them was reached until the whole
    // file was in memory, so a file of any length was allocated in full first.
    let most = u64::try_from(most_join_bytes()).unwrap_or(u64::MAX);
    let too_long = |length: u64| {
        unusable(format!(
            "{HANDED_LEDGER} is {length} bytes, longer than any ledger this build writes or \
             takes ({most} bytes)"
        ))
    };
    let read = std::fs::File::open(directory.join(HANDED_LEDGER)).and_then(|file| {
        let length = file.metadata()?.len();
        if length > most {
            return Ok(Err(length));
        }
        // Bounded again, for a file that grew since it was measured: what is
        // past the ceiling is not read, and what is read will not decode.
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut io::Read::take(file, most), &mut bytes)?;
        Ok(Ok(bytes))
    });
    let bytes = match read {
        Ok(Err(length)) => return Err(too_long(length)),
        Ok(Ok(bytes)) => bytes,
        // The one failure that means what the caller used to assume of all of
        // them. A node with no ledger file has not written one yet, which is
        // every node before its first, and it starts from its own log.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(unusable(format!(
                "{HANDED_LEDGER} could not be read: {error}"
            )))
        }
    };
    let handover = Handover::decode(&bytes).map_err(|error| {
        unusable(format!(
            "{HANDED_LEDGER} is not a ledger this build can read: {error}"
        ))
    })?;
    let state = accept(&handover, params).map_err(|error| ledger_refused(&error))?;
    let anchor = handover.at.height;
    Ok(Some((
        state,
        handover.recent,
        anchor,
        settles_at(anchor, handover.tip.height, params),
    )))
}

/// What a start says about a stored ledger the rules refused.
///
/// Four of the refusals are about this build or this command line and not
/// about the file: rules this build does not have at a height, a version the
/// rules there do not name, and a header from another network or from before
/// this one opened. Those were told to put a copy back or delete the file,
/// "which costs the stored blocks", and a copy is refused the same way while
/// deleting it cures nothing: for another network's directory it costs that
/// network's node its blocks.
fn ledger_refused(error: &HandoverError) -> NodeError {
    match *error {
        HandoverError::SoftwareTooOld { .. } | HandoverError::WrongVersion { .. } => {
            NodeError::OtherRules {
                file: HANDED_LEDGER,
                because: error.to_string(),
            }
        }
        // Said from the fields rather than through the error's own words,
        // which print the two networks as bare numbers.
        HandoverError::WrongNetwork {
            height,
            expected,
            found,
        } => NodeError::OtherNetwork {
            file: HANDED_LEDGER,
            because: format!(
                "the header at {height} belongs to {found}, and this node was started for \
                 {expected}"
            ),
        },
        HandoverError::BeforeTheNetworkOpened { .. } => NodeError::OtherNetwork {
            file: HANDED_LEDGER,
            because: error.to_string(),
        },
        _ => NodeError::UnusableLedger {
            because: format!("{HANDED_LEDGER} was refused: {error}"),
        },
    }
}

/// Whether a block the replay refused was refused for something about this
/// build or this command line, and what to stop the start with if so.
///
/// A build without the rules for a height, which is `SoftwareTooOld` where
/// the schedule names the height and `UnsupportedVersion` where it does not;
/// and the first record of the log belonging to another network, which is one
/// start under a mistyped `--network`. Only the first: a record further up
/// the log that names another network is not a directory of another network,
/// it is a record that changed, and it is refused like any other.
fn about_the_reader(height: u64, first: bool, error: &ChainError) -> Option<NodeError> {
    let ChainError::InvalidBlock { source, .. } = error else {
        return None;
    };
    match source {
        BlockError::SoftwareTooOld { .. } => Some(NodeError::OtherRules {
            file: BLOCK_LOG,
            because: source.to_string(),
        }),
        BlockError::UnsupportedVersion(version) => Some(NodeError::OtherRules {
            file: BLOCK_LOG,
            because: format!(
                "the block at height {height} is version {version}, and this build knows only \
                 version {BLOCK_VERSION}"
            ),
        }),
        BlockError::WrongNetwork { .. } | BlockError::BeforeTheNetworkOpened { .. } if first => {
            Some(NodeError::OtherNetwork {
                file: BLOCK_LOG,
                because: format!("the block at height {height}: {source}"),
            })
        }
        _ => None,
    }
}

/// Names the file of this node's directory a store error came from.
fn in_file(file: &'static str) -> impl FnOnce(StoreError) -> NodeError {
    move |source| NodeError::File { file, source }
}

/// Works out what to do about one message, and writes down anything it
/// changed.
///
/// Everything that needs the chain happens here and nowhere else, so it is
/// held once and let go before a single byte is sent: a slow peer must never
/// be able to stall the chain for everyone.
fn decide(
    shared: &Arc<Shared>,
    peer: &mut PeerState,
    message: Message,
) -> (Reaction, Vec<Transfer>) {
    // Chain first and log second, here and everywhere, so two threads never
    // take these two the other way round from each other.
    let mut chain = shared.chain();

    // The log is taken twice rather than held across the decision, because the
    // decision may itself read a block body off it: a chain that let go of a
    // body reads it back through this same lock, and holding it here would be
    // this thread waiting on itself.
    let reaches = chain.height().map_or(0, |tip| tip.saturating_add(1));
    let shows = {
        let log = shared.log.lock().unwrap_or_else(PoisonError::into_inner);
        log.as_ref()
            .is_some_and(|store| store.can_show_the_chain(reaches))
    };
    let keeps = Keeps {
        headers: shows,
        cold_set: chain.is_archiving(),
    };
    let mut local = Local {
        chain: &mut chain,
        keeps,
        listen: shared.address.port(),
        nonce: shared.nonce,
    };
    let reaction = on_message(&mut local, peer, message, unix_now());

    // Written while the chain is still held, so the log cannot record a branch
    // the chain has already moved off.
    if let Some(accepted) = reaction.applied.as_ref() {
        let wrote = {
            let mut log = shared.log.lock().unwrap_or_else(PoisonError::into_inner);
            log.as_mut().map(|log| {
                let wrote = write_branch(log, accepted, &chain);
                // Bodies now on disk, and far enough back that no ordinary
                // reorganisation reads them. Said after writing, never before:
                // a body let go of before it was written is a body nobody has.
                chain.release_bodies(log.blocks.first_height(), log.blocks.reaches());
                wrote
            })
        };
        // Once the log is let go of, because what this reads next is a leaf
        // and the order the locks are taken in is the whole of what keeps two
        // threads from waiting on each other.
        if let Some(wrote) = wrote {
            shared.note_writing(&wrote, chain.height());
        }
    }
    let passing: Vec<Transfer> = reaction
        .relayed
        .iter()
        .filter_map(|id| chain.pooled(id).cloned())
        .collect();
    (reaction, passing)
}

/// Whether the flood window that began at `started` is over by `now`.
///
/// A clock that went backwards says nothing about how long the window has been
/// open, so the window starts again rather than counting a negative. The same
/// reading [`was_away`] takes of the same event, and here it is not only
/// liveness: without it a step back of an hour held one window open for that
/// hour, and the first peer to send [`MAX_MESSAGES_PER_WINDOW`] messages
/// inside it was dropped as a flood and its host refused for
/// [`crate::refusal::REFUSAL_SECONDS`]. Two thousand messages is a few seconds
/// of any peer serving a catch-up, so what the step bought was a node banning
/// whoever was feeding it.
fn window_is_over(started: u64, now: u64) -> bool {
    now < started || now.saturating_sub(started) >= FLOOD_WINDOW
}

/// Whether the gap between two rounds of maintenance means the machine was not
/// running, or not on the network, while it passed.
///
/// The clock going backwards counts as away too. It says the same thing: what
/// this node believes about the last few minutes is not to be trusted.
fn was_away(previous: u64, now: u64) -> bool {
    now < previous || now.saturating_sub(previous) >= AWAY_GAP
}

/// Notes what a peer introduced itself as having, for the choice a node
/// with no chain has in front of it.
///
/// Only such a node has that choice: one with a chain weighs branches by
/// their work as they arrive, and what anyone claims is neither here nor
/// there.
fn note_claim(shared: &Arc<Shared>, id: PeerId, peer: &PeerState) {
    let empty = shared.chain().is_empty();
    if !empty {
        return;
    }
    shared.choosing().noted(
        id,
        peer.remote,
        peer.total_work,
        peer.height,
        peer.keeps.headers,
        unix_now(),
    );
}

/// One round of the choice a node with no chain makes about whom to follow.
///
/// Everything the chooser reads is gathered first and each lock is let go of
/// before the next is taken, so no two of them are ever held together and
/// nothing here can wait on a thread that is waiting on it.
fn drive_choosing(shared: &Arc<Shared>, now: u64) {
    let join = {
        let joining = shared
            .joining
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match joining.moved() {
            None => JoinProgress::NothingYet,
            Some(moved) if has_gone_quiet(Some(moved), now) => JoinProgress::Stalled,
            Some(_) => JoinProgress::Moving,
        }
    };
    let connected: Vec<PeerId> = shared.peers().keys().copied().collect();
    let (empty, work, archiving) = {
        let chain = shared.chain();
        (chain.is_empty(), chain.total_work(), chain.is_archiving())
    };
    let step = shared.choosing().step(now, empty, work, join, &connected);
    match step {
        choosing::Step::Quiet => {}
        // An archivist reads the chain rather than being handed it. A ledger
        // carries the cold set as sixty four roots, so an archivist that took
        // one held none of its leaves and never archived anything from then
        // on. Reading is asked of the same peer, and the chooser's patience
        // for a first answer is the same for both.
        choosing::Step::Ask(peer, Approach::Join | Approach::Read) if archiving => {
            let locator = shared.chain().locator();
            shared.send_to(peer, Message::GetChain { locator });
        }
        choosing::Step::Ask(peer, Approach::Join) => {
            // A fresh attempt starts from nothing: pieces of an old one
            // would not fit it, and noticing that used to cost the attempt.
            *shared
                .joining
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Progress::Idle;
            shared.send_to(
                peer,
                Message::GetJoin {
                    what: Joining::Weight,
                    part: 0,
                },
            );
        }
        choosing::Step::Ask(peer, Approach::Read) => {
            let locator = shared.chain().locator();
            shared.send_to(peer, Message::GetChain { locator });
        }
        // The choice is made. Whoever still claims more than the chain this
        // node took was held off while it chose, and gets the ordinary
        // question now: their chains arrive as branches, and the fork choice
        // weighs branches for a living.
        choosing::Step::Nudge(peers) => {
            let locator = shared.chain().locator();
            for peer in peers {
                shared.send_to(
                    peer,
                    Message::GetChain {
                        locator: locator.clone(),
                    },
                );
            }
        }
    }
}

/// Whether a join that last moved at `moved` has been quiet long enough to be
/// given up on.
///
/// `None` means there is no join to give up on. A clock that went backwards
/// counts as quiet: what this node believes about how long it has been waiting
/// is then worth nothing, and reading the chain instead costs one round.
const fn has_gone_quiet(moved: Option<u64>, now: u64) -> bool {
    match moved {
        None => false,
        Some(moved) => now < moved || now.saturating_sub(moved) >= JOIN_PATIENCE,
    }
}

/// Joins the threads of peers that have already gone.
///
/// Without this the handles pile up for the life of the process: one per peer
/// that ever connected, which on a node left running is a slow leak fed by
/// anyone who cares to connect and hang up.
fn collect_finished(shared: &Arc<Shared>) {
    let mut done = Vec::new();
    {
        let mut threads = shared.threads();
        let mut index = 0usize;
        while index < threads.len() {
            let finished = threads.get(index).is_some_and(JoinHandle::is_finished);
            if finished {
                done.push(threads.swap_remove(index));
            } else {
                index = index.saturating_add(1);
            }
        }
    }
    for handle in done {
        let _ = handle.join();
    }
}

/// Turns the names this node starts from into addresses it can dial.
///
/// Only while the book holds no seed at all. That is the case this exists for:
/// a node whose machine could not resolve anything at the moment it started
/// has nothing to dial and no way to learn of anybody, and would sit there for
/// as long as it ran, looking like a network that does not exist. Once one
/// address lands it is kept for good and the book takes over, so this stops on
/// its own and never runs again.
///
/// A lookup can block, so it is spaced out rather than tried every round.
fn look_up_seed_names(shared: &Arc<Shared>, now: u64) {
    if shared.book().has_seeds() {
        return;
    }
    let last = shared.names_looked_up_at.load(Ordering::Relaxed);
    if last > 0 && now.saturating_sub(last) < NAME_LOOKUP_PERIOD {
        return;
    }
    shared.names_looked_up_at.store(now, Ordering::Relaxed);

    let names = shared.seed_names().clone();
    for name in names {
        // Outside the book lock: a lookup with no name server to answer it
        // takes seconds, and nothing else should wait on that.
        let Ok(addresses) = crate::seeds::resolve(&name) else {
            continue;
        };
        let mut book = shared.book();
        for address in addresses {
            book.insert_seed(address);
        }
    }
}

fn dial_from_book(shared: &Arc<Shared>, now: u64) {
    let (connected, count) = {
        let peers = shared.peers();
        // Both the address a peer introduced itself at and the address this
        // node dialled to reach it. Only the first was read here, and it is
        // filled in by the handshake: an address that accepts a connection
        // and never speaks has none, so it was never among the ones already
        // held, and every round dialled it again. One such address took every
        // outbound slot the node had, and the node then saw the chain only
        // through connections a stranger had chosen for it, which is the
        // eclipse `MAX_PER_GROUP` is written against arriving by another door.
        let connected: HashSet<SocketAddr> = peers
            .values()
            .flat_map(|peer| [peer.advertised, peer.dialled_to])
            .flatten()
            .collect();
        // Only the ones this node went out and opened. A connection somebody
        // else opened does not tell this node anything about the network: the
        // stranger chose it. Counting those was enough to stop a node dialling
        // at all: hold eight connections open and it never looks for anybody
        // again, and then sees the world through whoever is holding them.
        (
            connected,
            peers.values().filter(|peer| peer.dialled).count(),
        )
    };
    let wanted = TARGET_PEERS.saturating_sub(count);
    if wanted == 0 {
        return;
    }

    // Most recently heard from first, so a node spends its attention on peers
    // that have proved they exist rather than on whatever sorts lowest, and
    // only those whose wait after a failed dial is over.
    //
    // Not cut to `wanted` here, which is the whole of the second half of this
    // repair. `wanted` is a bound on dials to make, and truncating the list to
    // it made it a bound on candidates to consider: every address skipped
    // inside the loop, for a refusal or for no room, was a dial that simply
    // did not happen. Filling the front of the order with addresses that
    // refuse every dial then stopped a node dialling anything, which is what
    // one stranger and twenty four claimed ports did. The loop counts what it
    // opened instead, the book is bounded at `MAX_ADDRESSES` so the walk is
    // too, and `DIAL_BUDGET` still ends a round that is taking too long.
    let candidates: Vec<SocketAddr> = shared
        .book()
        .ready(now)
        .into_iter()
        .filter(|address| *address != shared.address && !connected.contains(address))
        .collect();

    let dialling_since = Instant::now();
    let mut opened = 0usize;
    for address in candidates {
        if opened >= wanted || !shared.running.load(Ordering::SeqCst) {
            return;
        }
        // Checked before the dial rather than after, so a round always opens at
        // least one connection however slow the last one was. Otherwise a node
        // whose every address hangs would stop dialling altogether.
        if dialling_since.elapsed() >= DIAL_BUDGET {
            return;
        }
        let host = address.ip();
        if shared.refuses(host, now) || !shared.has_room_for(Some(host)) {
            continue;
        }
        match TcpStream::connect_timeout(&address, DIAL_TIMEOUT) {
            Ok(stream) => {
                attach_peer(shared, stream, Some(address));
                opened = opened.saturating_add(1);
            }
            // An address that never answers would otherwise be dialled every
            // second forever, and handed to every peer that asks.
            Err(_) => {
                shared.book().missed(&address, now);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Registration {
    Recorded,
    /// Another connection to the same peer already exists, and this is it.
    Redundant(PeerId),
}

/// Notes where a peer says it listens, and names the other connection to it
/// when there is one.
///
/// Which connection that is has to come back with the answer. Only one of a
/// pair ever reaches this, because a connection asks once and then sets
/// `announced`: the first of the two to get here is told it is the only one,
/// and the second is the only one that ever hears about the pair. So the
/// second is the only one that can end it, and it has to be able to end
/// either half. It used to be handed nothing but a yes, so all it could do was
/// leave, and when the rule said the other one should leave instead, neither
/// did: two connections between the same pair of nodes, both greeted, both
/// counted and both held for as long as they stayed open.
fn register(shared: &Arc<Shared>, id: PeerId, address: SocketAddr) -> Registration {
    let mut peers = shared.peers();
    let existing = peers
        .iter()
        .find(|(other, entry)| **other != id && entry.advertised == Some(address))
        .map(|(other, _)| *other);
    if let Some(entry) = peers.get_mut(&id) {
        entry.advertised = Some(address);
    }
    existing.map_or(Registration::Recorded, Registration::Redundant)
}

/// Which of two connections between the same pair of nodes is dropped.
///
/// Two nodes that dial each other at the same moment end up holding two
/// connections. The one that survives is the one opened by whichever node has
/// the lower address, a comparison both sides make identically, so both drop
/// the same connection rather than each dropping the other's.
fn loses_the_tie(ours: SocketAddr, theirs: SocketAddr, initiator: bool) -> bool {
    let our_dial_survives = ours < theirs;
    if initiator {
        !our_dial_survives
    } else {
        our_dial_survives
    }
}

/// Takes a connection into the peer table and starts its two threads.
///
/// `dialled` names the address this node went out to, and is `None` for a
/// connection somebody else opened. It is not the same thing as the address
/// the peer will introduce itself at, and the difference is what a silent
/// address used to live in.
///
/// False means the connection was let go of and this node holds no peer for
/// it. Nobody read that before, because there was nothing to read: the three
/// ways out below all looked like the way through, and [`Node::connect`]
/// reported every one of them to the operator as a peer reached.
/// Starts the thread that writes everything this node sends to one peer.
///
/// Asked for rather than taken. `thread::spawn` panics when the machine will
/// not make a thread, and the caller runs on the thread that owns the
/// listener, so the panic closed the port for the life of the process. That is
/// the outcome the `Err` arm in `accept_loop` was written to avoid, and it is
/// reached from here by a different road: there the machine is out of
/// descriptors, here it is out of threads, and both are facts about this
/// moment rather than about any visitor.
fn start_writing(
    id: PeerId,
    mut writing_end: TcpStream,
    inbox: mpsc::Receiver<(Message, usize)>,
    network: NetworkId,
    written: Arc<AtomicUsize>,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("cairn-write-{id}"))
        .spawn(move || {
            while let Ok((message, weight)) = inbox.recv() {
                let outcome = write_message(&mut writing_end, network, &message);
                // Off the count whether or not it reached the far end. What is
                // being counted is what this node is holding, and once the write
                // has returned it is holding nothing.
                written.fetch_sub(weight, Ordering::SeqCst);
                if outcome.is_err() {
                    break;
                }
            }
            let _ = writing_end.shutdown(Shutdown::Both);
        })
}

fn attach_peer(shared: &Arc<Shared>, stream: TcpStream, dialled: Option<SocketAddr>) -> bool {
    let initiator = dialled.is_some();
    // Nothing is attached to a node that has stopped. Checked here and again
    // under the thread table below, because between the two a shutdown can
    // take that table and this thread would then never be joined.
    if !shared.running.load(Ordering::SeqCst) {
        let _ = stream.shutdown(Shutdown::Both);
        return false;
    }
    // Counted here as well as in `accept_loop`. A machine out of descriptors
    // runs out at whichever call asks next, and that is the accept on one run
    // and one of these on the next; a visitor counted only when it was the
    // accept is a count that means "turned away at one particular step" while
    // saying "visitors this node could not take". The figure an operator reads
    // went up or stayed flat on the same exhaustion depending on timing, and
    // the test that holds the door open measured nothing on the runs where it
    // stayed flat.
    let clone = || match stream.try_clone() {
        Ok(end) => Some(end),
        Err(error) => {
            shared.could_not_take_a_visitor(&error.to_string());
            None
        }
    };
    let (Some(writing_end), Some(shutdown_end), Some(closing_end)) = (clone(), clone(), clone())
    else {
        return false;
    };
    let remote = stream.peer_addr().ok().map(|address| address.ip());
    // Small messages benefit from going out immediately rather than waiting for
    // a larger packet to fill, and every message here is an answer someone is
    // blocked on.
    let _ = stream.set_nodelay(true);
    // Deadlines on both directions. Without them a peer that opens a frame and
    // stops, or one that stops reading, holds a thread of this node for as long
    // as it cares to keep the socket open.
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = writing_end.set_write_timeout(Some(WRITE_TIMEOUT));

    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    let (sender, inbox) = mpsc::sync_channel::<(Message, usize)>(OUTBOUND_QUEUE);
    let outbound = Outbound::new(sender);
    shared.peers().insert(
        id,
        Peer {
            outbound: outbound.clone(),
            dialled: initiator,
            greeted: false,
            stream: shutdown_end,
            host: remote,
            advertised: None,
            dialled_to: dialled,
            archives: false,
        },
    );

    let network = shared.network();
    let written = Arc::clone(&outbound.waiting);
    let Ok(writer) = start_writing(id, writing_end, inbox, network, written) else {
        // The closure went with the error, and the socket half it held with
        // it. What is left is the table entry, which nothing would ever come
        // back to remove: the thread that does that is the one below, and it
        // is not going to be started either.
        shared.peers().remove(&id);
        shared.could_not_take_a_visitor("this machine would not start a thread to write to it");
        let _ = closing_end.shutdown(Shutdown::Both);
        return false;
    };

    if initiator {
        let hello = {
            let chain = shared.chain();
            let shows = shared.shows_the_chain(&chain);
            let keeps = Keeps {
                headers: shows,
                cold_set: chain.is_archiving(),
            };
            Message::Hello(local_handshake(
                &chain,
                keeps,
                shared.address.port(),
                shared.nonce,
            ))
        };
        let _ = outbound.try_send(hello);
    }

    // Held where both this thread and the reader can reach it. The reader
    // joins it, because the connection is given up only once both threads are
    // finished with it; but if the reader is never started the closure holding
    // it goes with the error, and a thread nobody joins is the one thing the
    // table below exists to prevent. So whichever of the two gets there takes
    // it, and the other finds it gone.
    let writer = Arc::new(Mutex::new(Some(writer)));
    let joining = Arc::clone(&writer);

    let reading = Arc::clone(shared);
    // The same, and with one more thing to undo: the writer is already running.
    let handle = thread::Builder::new()
        .name(format!("cairn-read-{id}"))
        .spawn(move || {
            read_loop(&reading, stream, id, &outbound, remote, dialled);
            drop(outbound);
            // The writer waits on the channel closing, and the channel cannot
            // close while the peer table still holds a sender for it. So the
            // table's sender is swapped for one nobody reads: the slot stays
            // counted, which is what it is for, and what was queued behind it is
            // let go of. The connection is given up only once both threads are
            // finished with it, so nothing this node still holds for a peer sits
            // outside its own accounting: before this, the slot went first, the
            // same host could take another, and up to a queue's worth of answers
            // and two threads went on living for a peer already given up on.
            if let Some(peer) = reading.peers().get_mut(&id) {
                peer.outbound = Outbound::nowhere();
            }
            if let Some(writer) = joining
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                let _ = writer.join();
            }
            reading.peers().remove(&id);
        });
    let Ok(handle) = handle else {
        // Taking the entry out drops the table's sender, and the closure went
        // with the error and took the other one, so nothing holds the channel
        // open and the writer's `recv` returns. Shut the socket first, because
        // the writer may be part way through a message and a deadline is not
        // what this should wait out.
        let _ = closing_end.shutdown(Shutdown::Both);
        shared.peers().remove(&id);
        shared.could_not_take_a_visitor("this machine would not start a thread to read from it");
        if let Some(writer) = writer.lock().unwrap_or_else(PoisonError::into_inner).take() {
            let _ = writer.join();
        }
        return false;
    };
    // Under the thread table, so a connection taken while a shutdown is
    // emptying it is not left with a thread nobody joins. A shutdown that got
    // here first has already cleared `running`, and the socket is shut so the
    // read fails at once rather than waiting out a deadline.
    let mut threads = shared.threads();
    if !shared.running.load(Ordering::SeqCst) {
        let _ = closing_end.shutdown(Shutdown::Both);
    }
    threads.push(handle);
    true
}

/// Writes down the three blocks a node refuses without blaming anybody.
///
/// All three are here rather than among the reasons to drop a peer because
/// none of them is the peer's doing, and all three used to pass in silence: an
/// operator saw a height that had stopped moving and nothing else. Counted, so
/// a run of them from several peers can be read for what it is.
fn note_what_was_not_taken(
    shared: &Arc<Shared>,
    reaction: &Reaction,
    from: Option<Sender>,
    now: u64,
) {
    // A block on a branch this node can never cross to. A node whose height
    // never moves while these arrive has been handed a chain nobody else is
    // on, and until this there was nowhere that showed.
    if reaction.unreachable.is_some() {
        shared.out_of_reach.fetch_add(1, Ordering::Relaxed);
    }
    // A block written under rules this build does not have. It is carrying
    // what its own chain carries, and this node is the one that cannot read
    // it; a run of these from several peers is a node the network has left
    // behind.
    if let Some(version) = reaction.unjudged {
        shared.cannot_judge(from, version, now);
    }
    // A block dated further ahead than this node's clock allows. This one used
    // to close the connection and refuse the host for ten minutes, so a node
    // two minutes slow banned every peer that offered it a block a slightly
    // fast miner had published, which is every peer it had. A run of these
    // from several peers is this machine's clock, and nothing else in the node
    // ever mentions one.
    if let Some(ahead) = reaction.ahead_of_the_clock {
        shared.clock_looks_behind(from, ahead, now);
    }
}

/// Whether a framing failure is the peer's fault rather than the network's.
///
/// A closed socket or a peer from another network has done nothing wrong. A
/// peer that announces a size past the limit, or sends something that does not
/// decode, wrote those bytes itself: nothing between the two ends produces
/// them, so it is broken or probing either way.
///
/// A frame that stalls is the other kind, and it used to be counted here. It
/// is a fact about a link and not about whoever is at the end of it. The floor
/// a frame has to clear is `PROGRESS_BYTES` in `FRAME_PATIENCE`, about three
/// and a quarter kilobytes a second, and the argument for lowering it to that
/// applies word for word to what is done about falling under it: a phone on a
/// weak signal, or a rural line, delivers under it steadily. Refusing the host
/// for [`crate::refusal::REFUSAL_SECONDS`] over that is a node deciding, for
/// ten minutes at a time, that a design whose whole point is that anyone can
/// run a full node does not mean anyone.
///
/// The connection still ends, which is the whole of what a stalled frame
/// costs anybody: the thread, the slot and the buffer are let go of at once,
/// and a link that cannot carry a frame cannot carry a chain either. What it
/// no longer costs is the address, so a link that comes back is talked to.
fn is_peer_fault(error: &WireError) -> bool {
    matches!(
        error,
        WireError::FrameTooLarge { .. } | WireError::Malformed(_)
    )
}

/// Whether this node lets a message reach the layer that decides about it.
///
/// Both reasons are about this node rather than about the message or the peer,
/// and both leave the message where it is rather than answering it badly.
///
/// A block taken while the node is still choosing whom to follow is the
/// beginning of following whoever sent it, and the first block followed past
/// the reorganisation limit is the choice being made by a stranger. The peer's
/// turn comes when the chooser asks it, or once the choice is made.
///
/// A transfer is judged against the ledger this node holds, and a node on
/// probation has not stood behind that ledger: taking the transfer would be
/// answering off somebody else's word, and passing it on would be spreading
/// the answer. A peer that has not introduced itself is let through so that
/// the layer below can refuse it for that, which is the worse fault.
fn held_off(shared: &Arc<Shared>, id: PeerId, peer: &PeerState, message: &Message) -> bool {
    if matches!(
        message,
        Message::Block(_) | Message::Announce(_) | Message::Chain { .. }
    ) && shared.choosing().holds_off(id)
    {
        return true;
    }
    peer.greeted && matches!(message, Message::Transaction(_)) && shared.probation().is_some()
}

/// What this connection turns out to be, once the peer has named itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    Keep,
    HangUp,
}

/// Files a peer's own account of where it listens, and says whether this half
/// of a duplicate pair is the one to end.
///
/// Run once per connection, the first time the peer names an address.
///
/// Two things happen here and only one of them is about the address the peer
/// named. The book is told what this node reached, which is the address this
/// node chose and not the one the peer chose: an address that answers a dial
/// goes to the front of the order this node dials and gossips from, and an
/// address that dialled in has proved its host exists and nothing about
/// whether anything listens where it says it does. The port in a handshake is
/// a number the peer wrote.
///
/// That was not the rule, and one stranger from one address said hello 2 135
/// times from twenty four claimed ports and took the whole front of the order.
/// Every dial a round went to an address that refused it, a greeting cleared
/// the retry pause each time, and the victim never reached the one address its
/// operator gave it. It held one connection and knew twenty five addresses, so
/// neither the connection ceiling nor an empty book is what stopped it.
fn what_it_said_it_was(
    shared: &Arc<Shared>,
    id: PeerId,
    peer: &PeerState,
    dialled: Option<SocketAddr>,
    last_heard: u64,
) -> Ending {
    if let Some(reached) = dialled {
        shared.book().answered(&reached, last_heard);
    }
    let Some(address) = peer.advertised else {
        return Ending::Keep;
    };
    if let Registration::Redundant(other) = register(shared, id, address) {
        if loses_the_tie(shared.address, address, dialled.is_some()) {
            return Ending::HangUp;
        }
        // This is the half to keep, so the other half goes. Both ends work the
        // rule out the same way, so they end the same connection; what neither
        // end could do before was end it from this side of the pair.
        shared.hang_up(other);
    }
    Ending::Keep
}

fn read_loop(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    id: PeerId,
    outbound: &Outbound,
    remote: Option<IpAddr>,
    dialled: Option<SocketAddr>,
) {
    let initiator = dialled.is_some();
    let network = shared.network();
    let mut peer = PeerState::new(remote);
    // The window belongs to the address, not to this socket, so what a peer
    // spent on the connection before this one is already gone from it.
    peer.allowance = shared.allowance_for(remote);
    peer.dialled = initiator;
    let mut announced = false;
    let mut last_heard = unix_now();
    let mut window_start = last_heard;
    let mut in_window = 0u32;
    let mut misbehaved = false;

    // Reads carry a deadline, so this loop looks up regularly rather than
    // waiting on a peer that may never speak again. Two silences are told
    // apart: a peer with nothing to say between frames is fine and stays, and
    // a peer holding a frame open is not and goes.
    //
    // Labelled because every way out of it has to reach the socket at the
    // bottom. Three of them used to return instead, and a peer that stopped
    // reading its answers took one of those: the socket was left open, so the
    // writing thread stayed inside a write nobody was taking, holding
    // everything queued behind it.
    'reading: while shared.running.load(Ordering::SeqCst) {
        // A small cap until this peer has said who it is. The frame cap is what
        // the protocol allows between nodes that know each other; this is what
        // a stranger gets, and a handshake is a fixed set of fields a few
        // hundred bytes long. Before it arrives, a megabyte of notes bought
        // one and a third seconds of this node's processor, because decoding
        // one decompresses a curve point for every owner in it. The budget
        // that would have charged for that is `held_off`, twenty lines below,
        // and by then the work is done.
        let message = match read_message(&mut stream, network, most_from(announced)) {
            Ok(Incoming::Message(message)) => {
                last_heard = unix_now();
                if window_is_over(window_start, last_heard) {
                    window_start = last_heard;
                    in_window = 0;
                }
                in_window = in_window.saturating_add(1);
                if in_window > MAX_MESSAGES_PER_WINDOW {
                    misbehaved = true;
                    break;
                }
                message
            }
            Ok(Incoming::Quiet) => {
                if unix_now().saturating_sub(last_heard) >= PEER_SILENCE.as_secs() {
                    break;
                }
                continue;
            }
            // No arm for an interrupted read: `read_message` goes round again
            // on one itself, so it never reaches here.
            Err(error) => {
                misbehaved = is_peer_fault(&error);
                break;
            }
        };

        if held_off(shared, id, &peer, &message) {
            continue;
        }

        // An answer to something this node went out and asked for belongs to
        // whoever is collecting it, which is this node rather than the layer
        // that reads messages.
        let message = match collected(shared, id, message, outbound) {
            Taken::Handled => continue,
            Taken::Failed => break 'reading,
            Taken::Other(message) => message,
        };

        // Whether this message is the introduction, before it is consumed:
        // what a peer claims is said there and nowhere else.
        let introduction = matches!(message, Message::Hello(_) | Message::Welcome(_));

        // The chain is held for the decision and for writing the log, and let
        // go before anything is sent, so a slow peer never stalls the chain.
        let (mut reaction, passing) = decide(shared, &mut peer, message);

        // Paths offered back for places this node asked about, folded now that
        // the chain has been let go of. Named in the reaction rather than
        // taken before this layer, which is what carried them past the one
        // place that charges for work.
        if !reaction.placed.is_empty() {
            shared.take_placed(id, &reaction.placed);
        }

        if introduction && peer.greeted {
            note_claim(shared, id, &peer);
        }
        shared.remember(&reaction.learned);
        if introduction && peer.greeted {
            shared.note_what_it_keeps(id, peer.advertised, peer.keeps.cold_set);
        }
        shared.forget(&reaction.forget);
        if !announced && peer.advertised.is_some() {
            announced = true;
            if what_it_said_it_was(shared, id, &peer, dialled, last_heard) == Ending::HangUp {
                break;
            }
        }

        for reply in reaction.reply.drain(..) {
            // A full queue means the peer is not reading what it asked for, so
            // the answer would be stale by the time it arrived.
            if outbound.try_send(reply).is_err() {
                break 'reading;
            }
        }
        // What the sync layer named rather than answered, because answering
        // either reaches a disk and it runs with the chain held.
        if !answer_deferred(shared, &mut peer, &reaction, outbound, last_heard) {
            break 'reading;
        }
        // Headers from before this node arrived, taken now that the chain has
        // been let go of: they are written to a log and weighed against a
        // commitment, and both reach a disk. Named with the peer that sent
        // them, because there is one collection and it belongs to one peer.
        if let Some((from, headers)) = reaction.offered_headers.take() {
            shared.take_headers(id, from, &headers, last_heard);
        }
        note_what_was_not_taken(
            shared,
            &reaction,
            sender_of(peer.advertised, remote),
            last_heard,
        );
        if !reaction.broadcast.is_empty() {
            shared.broadcast(Some(id), &Message::Announce(reaction.broadcast));
        }
        for transfer in passing {
            shared.broadcast(Some(id), &Message::Transaction(Box::new(transfer)));
        }
        // Not this peer's fault and not something to disconnect over: every
        // peer that has updated would send the same block. The node stops.
        if let Some(outdated) = reaction.outdated {
            shared.outdated().get_or_insert(outdated);
            shared.running.store(false, Ordering::SeqCst);
            break;
        }
        if let Some(reason) = reaction.drop_peer {
            misbehaved = reason.is_misbehaviour();
            break;
        }
    }

    note_the_ending(shared, remote, dialled, misbehaved, peer.greeted);
    // Always, however the loop ended. It is what frees the writing thread: a
    // write on a socket just shut fails at once, wherever in a frame it was.
    let _ = stream.shutdown(Shutdown::Both);
}

/// What the node holds against an address once its connection has ended.
///
/// Two different judgements, and neither is about the message that happened
/// to be last. A peer that behaved badly is turned away for a while. And an
/// address this node went out to, that took the connection and then never
/// introduced itself, has a miss counted against it exactly as one that
/// refused the dial outright does. It is worse than a refusal, in fact: a
/// refused dial costs a syscall, and this one held an outbound slot until
/// `PEER_SILENCE` was up. Without it such an address stays in the book for
/// good and is dialled again every ninety seconds for the life of the node.
fn note_the_ending(
    shared: &Arc<Shared>,
    remote: Option<IpAddr>,
    dialled: Option<SocketAddr>,
    misbehaved: bool,
    greeted: bool,
) {
    let now = unix_now();
    if misbehaved {
        if let Some(host) = remote {
            shared.refuse(host, now);
        }
    }
    if let Some(address) = dialled {
        if !greeted {
            shared.book().missed(&address, now);
        }
    }
}

/// What a node's disk and its header log are held to: how they are opened,
/// filled in from before the node arrived, written after a block, and cut, and
/// what the node says about them.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod disk_and_headers {
    use std::io::{Seek, SeekFrom, Write};
    use std::net::Ipv4Addr;

    use cairn_ledger::note::Note;
    use cairn_ledger::transaction::CoinbaseTransaction;
    use cairn_ledger::validation::{assemble_block, connect_block, mine_block};
    use cairn_store::HEADER_TREE;

    use super::*;

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    /// An empty directory of its own.
    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("cairn-disk-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    /// A short valid chain built off to the side, and the ledger after each
    /// of its blocks.
    fn forged(count: usize, params: ConsensusParams) -> (Vec<Block>, Vec<LedgerState>) {
        let miner = cairn_crypto::SecretKey::from_bytes(&[7; 32]);
        let mut state = LedgerState::new();
        let mut clock = 1_000u64;
        let mut blocks = Vec::new();
        let mut states = Vec::new();
        for _ in 0..count {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            // The search for a nonce starts at the height rather than at a
            // written-in number; any start finds one at this difficulty.
            let block = assemble_block(
                &state,
                coinbase,
                Vec::<Transfer>::new(),
                &params,
                clock,
                height,
            )
            .unwrap();
            let block = mine_block(block, 1 << 22).unwrap();
            connect_block(&mut state, &block, &params, clock).unwrap();
            blocks.push(block);
            states.push(state.clone());
        }
        (blocks, states)
    }

    /// Headers that link to each other, with nothing mined behind them.
    ///
    /// Enough for a header log, which checks that each record sits at its own
    /// height and names the one before it, and for nothing that weighs a run
    /// against a commitment.
    fn linked(count: u64) -> Vec<BlockHeader> {
        let mut previous = Hash32::ZERO;
        (0..count)
            .map(|height| {
                let header = BlockHeader {
                    version: BLOCK_VERSION,
                    network: ConsensusParams::testnet().network,
                    height,
                    previous,
                    transactions_root: Hash32::from_bytes([7; 32]),
                    state_root: Hash32::from_bytes([9; 32]),
                    history: Hash32::from_bytes([11; 32]),
                    timestamp: 1_000_000 + height * 600,
                    difficulty: 1,
                    total_work: u128::from(height),
                    nonce: height,
                };
                previous = header.id();
                header
            })
            .collect()
    }

    /// A store over `directory` holding these headers, and this run being
    /// collected from before them.
    fn store_in(directory: &Path, headers: &[BlockHeader], filling: &[BlockHeader]) -> Store {
        let (blocks, _) = BlockLog::open(directory).unwrap();
        let mut held = HeaderLog::open(directory).unwrap();
        for header in headers {
            held.append(header).unwrap();
        }
        let mut collected = HeaderLog::open_named(directory, FILLING_LOG).unwrap();
        for header in filling {
            collected.append(header).unwrap();
        }
        Store {
            blocks,
            headers: held,
            forest: HeaderTree::open(directory).unwrap(),
            filling: collected,
            filling_epoch: 0,
        }
    }

    /// A node started over `store`, with an empty chain and nobody to talk to.
    fn started(store: Store, directory: &Path) -> Node {
        let params = ConsensusParams::testnet();
        Node::start(
            params,
            loopback(),
            ChainStore::new(params),
            Some(store),
            AddressBook::new(),
            Some(directory.to_path_buf()),
            None,
            None,
            None,
        )
        .unwrap()
    }

    fn with_store<T>(node: &Node, read: impl FnOnce(&Store) -> T) -> T {
        let log = node
            .shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        read(log.as_ref().unwrap())
    }

    fn finish(node: Node, directory: &Path) {
        node.shutdown();
        drop(node);
        let _ = std::fs::remove_dir_all(directory);
    }

    /// A node opened over `directory` that has taken these blocks and written
    /// them down.
    fn holding(blocks: &[Block], params: ConsensusParams, directory: &Path) -> Node {
        let (node, _) = Node::open(params, loopback(), directory).unwrap();
        for block in blocks {
            node.submit_block(block.clone()).unwrap();
        }
        node
    }

    fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if ready() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("waited for {what} and it never happened");
    }

    /// A chain that already holds its first block is not given it again, and
    /// neither is its log.
    ///
    /// Nothing asked this, so a node that laid the pinned first block down
    /// again whenever its chain had anything in it passed. The chain calls the
    /// second copy a duplicate and takes it quietly, and the log, if it was
    /// empty, got a block at height zero at its front: on a node handed a
    /// ledger, whose chain is full and whose log starts empty, that is a log
    /// that no longer starts where the ledger does.
    #[test]
    fn a_chain_that_holds_its_first_block_is_not_given_it_again() {
        let params = ConsensusParams::for_network("testnet-6").expect("testnet-6 exists");
        let opened = genesis::opens_at(params.network);
        let directory = scratch("first-block-again");
        let (mut log, _) = BlockLog::open(&directory).unwrap();

        let mut chain = ChainStore::new(params);
        assert!(open_the_chain(&mut chain, None, params, opened + 60).is_none());
        assert!(
            !chain.is_empty(),
            "the fixture has to hold the first block, or the question below is empty"
        );

        assert!(open_the_chain(&mut chain, Some(&mut log), params, opened + 60).is_none());
        let written = log.len();
        drop(log);
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(
            written, 0,
            "a chain that already held its first block had it written again into a log \
             that did not"
        );
    }

    /// What a node was writing or reading when its disk refused is said in
    /// words that name it.
    ///
    /// These are what an operator reads when a disk is failing. Nothing read
    /// them, so a node saying nothing at all in their place passed.
    #[test]
    fn what_a_node_was_writing_or_reading_is_named_in_words() {
        let said = [
            (Writing::Blocks.to_string(), "blocks"),
            (Writing::Headers.to_string(), "headers"),
            (Writing::Ledger.to_string(), "ledger"),
            (Reading::Blocks.to_string(), "block"),
            (Reading::Headers.to_string(), "header"),
        ];
        for (words, names) in said {
            assert!(
                words.contains(names),
                "an operator was told the disk refused {words:?}, which does not name the {names}"
            );
        }
    }

    /// A question about where fallen notes sit is satisfied once every place
    /// asked about has a path, and not before.
    ///
    /// Nothing asked it on its own. Every recovery in the suite ends with the
    /// one peer asked having answered, which ends the wait by the other half
    /// of the condition, so a question that was never satisfied by its paths
    /// passed: it waited for the slowest peer asked, or the whole patience,
    /// with every path it wanted already in hand.
    #[test]
    fn a_question_is_satisfied_once_every_place_asked_about_has_a_path() {
        let path = || ForestProof {
            siblings: Vec::new(),
        };
        let mut asking = Asking {
            wanted: BTreeMap::from([(7, Hash32::ZERO), (9, Hash32::ZERO)]),
            ..Asking::default()
        };
        assert!(!asking.satisfied(), "nothing has come back yet");
        asking.found.insert(7, path());
        assert!(!asking.satisfied(), "one place of two has a path");
        asking.found.insert(9, path());
        assert!(
            asking.satisfied(),
            "every place asked about has a path and the question is still open"
        );
        assert!(
            !Asking::default().satisfied(),
            "a question about nothing is answered by nothing"
        );
    }

    /// Headers that end exactly where the blocks begin are carried on from the
    /// blocks, and none of them is dropped.
    ///
    /// The gap the catch-up deletes the header log for is headers that stop
    /// before the blocks start. Nothing tried the case one step away, so a
    /// catch-up that counted "no gap" as a gap passed, and a node whose header
    /// log ended at the first block it still held lost every header it had and
    /// said it had dropped them.
    #[test]
    fn headers_that_end_where_the_blocks_begin_are_carried_on() {
        let (blocks, _) = forged(6, ConsensusParams::testnet());
        let directory = scratch("headers-meet-blocks");
        let (mut log, _) = BlockLog::open(&directory).unwrap();
        for block in &blocks[3..] {
            log.append(block).unwrap();
        }
        let mut headers = HeaderLog::open(&directory).unwrap();
        for block in &blocks[..3] {
            headers.append(&block.header).unwrap();
        }

        let caught = catch_up_headers(&mut headers, &log);
        let held = (headers.first_height(), headers.reaches());
        drop((log, headers));
        let _ = std::fs::remove_dir_all(&directory);

        assert_eq!(
            caught.dropped, 0,
            "headers that led straight into the blocks were counted as stranded"
        );
        assert!(caught.unread.is_none(), "nothing refused a read or a write");
        assert_eq!(
            held,
            (0, 6),
            "the header log was not carried on from the blocks without a break"
        );
    }

    /// A ledger file that is there and cannot be read stops the node, rather
    /// than being taken for no file at all.
    ///
    /// Nothing tried a read that fails for any reason but the file being
    /// missing, so a node that read every failure as "no ledger" passed. That
    /// is the node that replays from block zero over a log beginning above it
    /// and cuts the log to nothing, which is what the refusal exists to stop.
    #[test]
    fn a_ledger_file_that_cannot_be_read_stops_the_node() {
        let params = ConsensusParams::testnet();
        let directory = scratch("unreadable-ledger");
        assert!(
            matches!(read_handed_ledger(&directory, &params), Ok(None)),
            "no file is no ledger"
        );
        // A name that is there and cannot be read as a file, on every system.
        std::fs::create_dir_all(directory.join(HANDED_LEDGER)).unwrap();

        match Node::open(params, loopback(), &directory) {
            Err(NodeError::UnusableLedger { because }) => {
                let _ = std::fs::remove_dir_all(&directory);
                assert!(
                    because.contains("could not be read"),
                    "the node stopped, and said something other than that it could not \
                     read the file"
                );
            }
            Err(other) => {
                let _ = std::fs::remove_dir_all(&directory);
                panic!("the node stopped for another reason: {other}");
            }
            Ok((node, _)) => {
                finish(node, &directory);
                panic!(
                    "a node started over a ledger file it could not read, as if there were \
                     no file"
                );
            }
        }
    }

    /// Headers off a branch replaced at the same length are written again from
    /// the chain.
    ///
    /// Two miners finding a block at the same height is the ordinary way a
    /// branch is replaced, and it leaves the header log exactly as long as the
    /// chain. Nothing wrote headers after one, so a walk that stopped at the
    /// first header it held, whatever that header was, passed: the node went
    /// on showing a newcomer the branch it had left.
    #[test]
    fn headers_off_a_branch_replaced_at_the_same_length_are_written_again() {
        let params = ConsensusParams::testnet();
        let (blocks, _) = forged(5, params);
        let mut chain = ChainStore::new(params);
        for block in &blocks {
            chain.add_block(block.clone(), 2_000_000_000).unwrap();
        }

        let directory = scratch("same-length-headers");
        let mut headers = HeaderLog::open(&directory).unwrap();
        // The same three, then a fourth and a fifth the chain does not have.
        let mut left: Vec<BlockHeader> = blocks[..3].iter().map(|block| block.header).collect();
        for replaced in &blocks[3..] {
            let previous = left.last().unwrap().id();
            left.push(BlockHeader {
                previous,
                nonce: replaced.header.nonce.wrapping_add(1),
                ..replaced.header
            });
        }
        for header in &left {
            headers.append(header).unwrap();
        }

        let refusing = write_headers(&mut headers, &chain);
        let held: Vec<Hash32> = (0..5)
            .map(|height| headers.read_at(height).unwrap().unwrap().id())
            .collect();
        let reaches = headers.reaches();
        drop(headers);
        let _ = std::fs::remove_dir_all(&directory);

        assert!(refusing.is_none(), "nothing refused a write");
        assert_eq!(reaches, 5, "the log is as long as the chain");
        for (height, block) in blocks.iter().enumerate() {
            assert_eq!(
                held[height],
                block.id(),
                "the header at {height} is still the one off the branch this node left"
            );
        }
    }

    /// Headers below anything the chain can compare them against stand, and
    /// the gap above them is said.
    ///
    /// A node handed a ledger holds identifiers only from the headers that came
    /// with it. Nothing gave the walk a header log reaching below those, so a
    /// walk that took "nothing to compare against" as "wrong" passed, and it
    /// deleted every header the node held on the strength of a chain that had
    /// no opinion about any of them.
    #[test]
    fn headers_below_what_the_chain_can_compare_against_stand() {
        let params = ConsensusParams::testnet();
        let (blocks, states) = forged(11, params);
        let recent: Vec<BlockHeader> = blocks[6..].iter().map(|block| block.header).collect();
        let mut chain = ChainStore::new(params);
        chain.adopt(states[10].clone(), &recent).unwrap();
        assert!(
            chain.id_at(3).is_none(),
            "the fixture has to be a chain with nothing to say about height 3"
        );

        let directory = scratch("headers-below-the-chain");
        let mut headers = HeaderLog::open(&directory).unwrap();
        for block in &blocks[..4] {
            headers.append(&block.header).unwrap();
        }

        let refusing = write_headers(&mut headers, &chain);
        let held = (headers.first_height(), headers.reaches());
        drop(headers);
        let _ = std::fs::remove_dir_all(&directory);

        assert_eq!(
            held,
            (0, 4),
            "headers the chain had nothing to compare against were cut"
        );
        assert!(
            refusing.is_some(),
            "and the stretch above them that nothing can write was not said"
        );
    }

    /// Where a collection of headers from before a node arrived is left after
    /// a restart: the first header it holds and how far it reaches.
    fn filling_after_a_restart(
        name: &str,
        headers: &[BlockHeader],
        filling: &[BlockHeader],
    ) -> (u64, u64) {
        let directory = scratch(name);
        drop(store_in(&directory, headers, filling));
        let (node, _) = Node::open(ConsensusParams::testnet(), loopback(), &directory).unwrap();
        let left = with_store(&node, |store| {
            (store.filling.first_height(), store.filling.reaches())
        });
        finish(node, &directory);
        left
    }

    /// A collection of headers from before a node arrived survives a restart
    /// while it still leads up to the oldest header held.
    ///
    /// Nothing restarted a node in the middle of one, so a start that threw
    /// every collection away passed. On a chain of any age that collection is
    /// the whole history before the node arrived, fetched again from nothing
    /// after every restart.
    #[test]
    fn a_collection_that_leads_up_to_the_headers_survives_a_restart() {
        let headers = linked(30);
        assert_eq!(
            filling_after_a_restart("filling-kept", &headers[20..], &headers[..8]),
            (0, 8),
            "a collection leading up to the oldest header held was thrown away at the start"
        );
    }

    /// A collection that leads nowhere is thrown away at the start: one left
    /// beside a header log that already begins at the first block, and one
    /// that does not begin at the first block itself.
    ///
    /// Nothing started a node over either, so a start that kept both passed,
    /// and a collection beside a whole header log is headers nobody needs
    /// being offered to a merge that has nothing to merge them in front of.
    #[test]
    fn a_collection_that_leads_nowhere_is_thrown_away_at_the_start() {
        let headers = linked(30);
        assert_eq!(
            filling_after_a_restart("filling-beside-whole", &headers[..10], &headers[..4]),
            (0, 0),
            "a collection was kept beside a header log that already begins at the first block"
        );
        assert_eq!(
            filling_after_a_restart("filling-off-the-ground", &headers[20..], &headers[3..6]),
            (0, 0),
            "a collection that does not begin at the first block was kept"
        );
    }

    /// The headers a handover came with are written into an empty log, and a
    /// log that already holds headers is left as it is.
    ///
    /// Nothing looked at the log after seeding it, so a seed that wrote
    /// nothing passed, as did one that wrote only into a log that was not
    /// empty: a node that joined a chain then held no headers to fill in
    /// below, and a second seed ran a handover's headers on past what the
    /// node had.
    #[test]
    fn handed_headers_are_written_only_into_an_empty_log() {
        let directory = scratch("seeded");
        let (node, _) = Node::open(ConsensusParams::testnet(), loopback(), &directory).unwrap();
        let headers = linked(12);

        node.shared.seed_headers(&headers[5..9]);
        let seeded = with_store(&node, |store| {
            (store.headers.first_height(), store.headers.reaches())
        });
        // A run that would follow straight on, which is the one a log that
        // only refused what did not follow would take.
        node.shared.seed_headers(&headers[9..]);
        let again = with_store(&node, |store| {
            (store.headers.first_height(), store.headers.reaches())
        });
        finish(node, &directory);

        assert_eq!(
            seeded,
            (5, 9),
            "the headers a handover came with were not written into an empty log"
        );
        assert_eq!(
            again,
            (5, 9),
            "a log that already held headers was written to"
        );
    }

    /// Throwing a collection away empties it and counts whatever comes next as
    /// another collection.
    ///
    /// Nothing looked at the collection after it was thrown away, so a throw
    /// that kept every header passed. What it would keep is half one peer's
    /// run for the next peer to add to, which is the mixed run the whole turn
    /// arrangement exists to prevent, and a count that did not move would let
    /// a weighing of the old run be merged as the new one.
    #[test]
    fn a_collection_thrown_away_is_empty_and_counted_as_another() {
        let directory = scratch("thrown-away");
        let headers = linked(30);
        let node = started(
            store_in(&directory, &headers[20..], &headers[..8]),
            &directory,
        );

        node.shared.clear_filling();
        let left = with_store(&node, |store| (store.filling.len(), store.filling_epoch));
        finish(node, &directory);

        assert_eq!(
            left,
            (0, 1),
            "a collection thrown away still held headers, or was counted as the same one"
        );
    }

    /// A run that did not add up is thrown away only while it is still the run
    /// that was weighed.
    ///
    /// Nothing threw a run away with a stale count, so a node that threw away
    /// whatever was there on the word of a weighing of some earlier run passed,
    /// and so did one that kept the run it had just weighed and found invented.
    #[test]
    fn a_run_is_thrown_away_only_while_it_is_the_run_that_was_weighed() {
        let directory = scratch("thrown-when-weighed");
        let headers = linked(30);
        let node = started(
            store_in(&directory, &headers[20..], &headers[..8]),
            &directory,
        );

        let stale = node.shared.throw_the_run_away(7);
        let after_stale = with_store(&node, |store| (store.filling.len(), store.filling_epoch));
        let current = node.shared.throw_the_run_away(0);
        let after_current = with_store(&node, |store| (store.filling.len(), store.filling_epoch));
        finish(node, &directory);

        assert!(matches!(stale, Filled::Discarded) && matches!(current, Filled::Discarded));
        assert_eq!(
            after_stale,
            (8, 0),
            "a run was thrown away on the word of a weighing of another run"
        );
        assert_eq!(
            after_current,
            (0, 1),
            "the run that was weighed and did not add up was kept"
        );
    }

    /// A node that holds every header back to the first block takes no run of
    /// headers from before it arrived.
    ///
    /// Nothing offered one, so a node that went on to weigh and merge a run
    /// whenever the run was not empty passed. With nothing before the first
    /// block to collect, what it weighed was an empty forest against the first
    /// header, and what it did next was throw away or merge a collection
    /// nobody had asked for.
    #[test]
    fn a_node_holding_every_header_takes_no_run_from_before_it_arrived() {
        let directory = scratch("whole-takes-nothing");
        let headers = linked(10);
        let node = started(store_in(&directory, &headers, &[]), &directory);

        let offered = node.shared.fill_headers(0, &headers[..3]);
        let left = with_store(&node, |store| {
            (
                store.headers.first_height(),
                store.headers.reaches(),
                store.filling.len(),
                store.filling_epoch,
            )
        });
        finish(node, &directory);

        assert!(
            matches!(offered, Filled::Ignored),
            "a node holding every header did something with a run from before it arrived"
        );
        assert_eq!(left, (0, 10, 0, 0), "and its logs were touched");
    }

    /// A run that adds to a collection says how far the collection now reaches,
    /// and one that adds nothing says nothing happened.
    ///
    /// The difference is what keeps a supplier's turn: a run renews it and a
    /// run of nothing does not. Nothing looked at the answer for a run short of
    /// the oldest header, so answering "ignored" to a run that grew the
    /// collection passed, as did answering "grew" to one that added nothing.
    #[test]
    fn a_run_that_adds_to_a_collection_says_so_and_one_that_adds_nothing_does_not() {
        let directory = scratch("grew-or-not");
        let headers = linked(30);
        let node = started(store_in(&directory, &headers[20..], &[]), &directory);

        let part = node.shared.fill_headers(0, &headers[..8]);
        // Asked from where the collection ends, and carrying only headers this
        // node already holds, so nothing in it is added.
        let nothing = node.shared.fill_headers(8, &headers[20..22]);
        let reaches = with_store(&node, |store| store.filling.reaches());
        finish(node, &directory);

        assert!(
            matches!(part, Filled::Grew(8)),
            "a run that grew the collection to 8 was not reported as growing it"
        );
        assert!(
            matches!(nothing, Filled::Ignored),
            "a run that added nothing was reported as growing the collection"
        );
        assert_eq!(
            reaches, 8,
            "and the collection holds what the first run brought"
        );
    }

    /// A collection is merged only while it is what was weighed: the same
    /// collection, in front of the same oldest header, still reaching it.
    ///
    /// The weighing lets go of the log for a read per header, and any of the
    /// three can change meanwhile. Nothing could make one change at the right
    /// moment, so the check was held by nothing, and a check that asked only
    /// two of the three, or asked them all at once, passed.
    #[test]
    fn a_collection_is_merged_only_while_it_is_what_was_weighed() {
        let directory = scratch("what-was-weighed");
        let headers = linked(30);
        let mut store = store_in(&directory, &headers[20..], &headers[..20]);

        let untouched = store.moved_since_weighed(20, 0);
        let thrown_and_gathered_again = store.moved_since_weighed(20, 1);
        let merged_by_somebody_else = store.moved_since_weighed(19, 0);
        store.filling.keep_below(10).unwrap();
        let short_of_the_header = store.moved_since_weighed(20, 0);
        drop(store);
        let _ = std::fs::remove_dir_all(&directory);

        assert!(
            !untouched,
            "a collection nobody touched was taken for one that moved"
        );
        assert!(
            thrown_and_gathered_again,
            "a collection thrown away and gathered again was taken for the one weighed"
        );
        assert!(
            merged_by_somebody_else,
            "a collection was taken as weighed against a header log that begins elsewhere"
        );
        assert!(
            short_of_the_header,
            "a collection no longer reaching the header it was weighed against was taken"
        );
    }

    /// Headers offered through the door the tests use are checked and merged
    /// like any others.
    ///
    /// Nothing looked at a node after offering it headers this way, so a door
    /// that did nothing at all passed, and every test standing on it measured
    /// a node that had been offered nothing.
    #[test]
    fn headers_offered_through_the_test_door_are_checked_and_merged() {
        let (blocks, _) = forged(30, ConsensusParams::testnet());
        let headers: Vec<BlockHeader> = blocks.iter().map(|block| block.header).collect();
        let directory = scratch("offered");
        let node = started(store_in(&directory, &headers[20..], &[]), &directory);

        node.take_offered_headers(0, &headers[..20]);
        let held = with_store(&node, |store| {
            (
                store.headers.first_height(),
                store.headers.reaches(),
                store.forest.len(),
                store.filling.len(),
            )
        });
        finish(node, &directory);

        assert_eq!(
            held,
            (0, 30, 30, 0),
            "a run offered through the test door that checks out was not merged in front of \
             the headers, with the forest built over the whole"
        );
    }

    /// A disk holding exactly its budget is not over it, and writes no ledger
    /// to get under it.
    ///
    /// Nothing set a budget equal to what a node held, so a node that counted
    /// the budget itself as over it passed, and it wrote a ledger of several
    /// megabytes every time its log reached the budget exactly, to drop
    /// nothing.
    #[test]
    fn a_disk_exactly_at_its_budget_writes_no_ledger_to_get_under_it() {
        let params = ConsensusParams::testnet().with_burial(8);
        let (blocks, _) = forged(20, params);
        let directory = scratch("at-budget");
        let node = holding(&blocks, params, &directory);
        let ledger = directory.join(HANDED_LEDGER);

        let bytes = node.kept_bytes();
        node.keep_blocks(bytes);
        node.shared.trim_history();
        let at_budget = (ledger.exists(), node.blocks_from());

        // The control: a budget far below it, so the question above is known
        // to be one this node can answer by writing a ledger.
        node.keep_blocks(1);
        node.shared.trim_history();
        wait_until("the log to be trimmed", || {
            node.blocks_from().unwrap_or(0) > 0
        });
        let over_budget = ledger.exists();
        finish(node, &directory);

        assert_eq!(
            at_budget,
            (false, Some(0)),
            "a disk holding exactly its budget wrote a ledger or dropped blocks"
        );
        assert!(over_budget, "a disk over its budget wrote no ledger");
    }

    /// A position the disk holds another block at is not one this node agrees
    /// with.
    ///
    /// Nothing sent a locator naming a block this node held on disk under
    /// another identifier, so a walk that agreed with any position the disk
    /// held something at passed. The peer was then told to start above a block
    /// it does not share with this node, and every block it was sent after
    /// that built on a parent it did not have.
    #[test]
    fn a_position_the_disk_holds_another_block_at_is_not_agreed_with() {
        let params = ConsensusParams::testnet();
        let (blocks, _) = forged(6, params);
        let directory = scratch("disagreed");
        let node = holding(&blocks, params, &directory);

        let elsewhere = Located::new(3, Hash32::from_bytes([0xab; 32]));
        let answer = node.shared.chain_after(&[elsewhere], 100);
        finish(node, &directory);

        assert_eq!(
            answer,
            (0, 6),
            "a position the disk holds another block at was agreed with"
        );
    }

    /// A block on this node's disk is read back off it.
    ///
    /// The disk half of answering a peer far behind, and nothing asked it
    /// directly: a read that found nothing passed every test that went through
    /// it, because every one of them agreed with the peer in memory first.
    #[test]
    fn a_block_on_the_disk_is_read_back_off_it() {
        let params = ConsensusParams::testnet();
        let (blocks, _) = forged(6, params);
        let directory = scratch("read-back");
        let node = holding(&blocks, params, &directory);

        let read = node.shared.block_off_disk(3).map(|block| block.id());
        let past_the_end = node.shared.block_off_disk(6).is_none();
        finish(node, &directory);

        assert_eq!(
            read,
            Some(blocks[3].id()),
            "the block at 3 is on the disk and was not read back"
        );
        assert!(past_the_end, "and a height past the log is nothing");
    }

    /// A forest node mended on the way to a proof is counted.
    ///
    /// The count is what tells an operator the disk dropped a write, and
    /// nothing tore a node under a running node, so a count that stayed at
    /// nought passed.
    #[test]
    fn a_forest_node_mended_on_the_way_to_a_proof_is_counted() {
        let params = ConsensusParams::testnet();
        let (blocks, _) = forged(16, params);
        let directory = scratch("mended");
        finish_keeping(holding(&blocks, params, &directory));

        // The last node of level one, over leaves fourteen and fifteen: a node
        // of the right length holding the wrong bytes, which is what a level
        // whose length landed before its bytes did leaves behind.
        let mut level = std::fs::OpenOptions::new()
            .write(true)
            .open(directory.join(format!("{HEADER_TREE}.1")))
            .unwrap();
        level.seek(SeekFrom::Start(7 * 32)).unwrap();
        level.write_all(&[0u8; 32]).unwrap();
        drop(level);

        let (node, _) = Node::open(params, loopback(), &directory).unwrap();
        let before = node.mended_nodes();
        let proof = node.shared.proof_off_disk(14, 16);
        let after = node.mended_nodes();
        finish(node, &directory);

        assert_eq!(before, 0, "nothing had been mended yet");
        assert!(
            proof.is_some(),
            "the torn node was not mended, so there was nothing to count"
        );
        assert_eq!(
            after, 1,
            "a forest node mended on the way to a proof was not counted"
        );
    }

    fn finish_keeping(node: Node) {
        node.shutdown();
        drop(node);
    }

    /// The cold set a node reports is the one its chain holds.
    ///
    /// Nothing put more than one note in a node's cold set and asked, so a
    /// node that answered nought, or one, passed. The number is what a wallet
    /// shows to say how much there is that it might have to ask about.
    #[test]
    fn the_cold_set_a_node_reports_is_the_one_its_chain_holds() {
        let params = ConsensusParams::testnet()
            .with_hot_capacity(4)
            .with_max_evictions(4);
        let (blocks, _) = forged(16, params);
        let node = Node::bind(params, loopback()).unwrap();
        for block in &blocks {
            node.submit_block(block.clone()).unwrap();
        }
        let reported = node.cold_len();
        let held = node.with_chain(|chain| chain.state().cold_len());
        node.shutdown();

        assert!(
            held > 1,
            "the fixture has to put more than one note in the cold set, or nought and one \
             are both right"
        );
        assert_eq!(
            reported, held,
            "the node reported a cold set other than the one its chain holds"
        );
    }

    /// A question about where fallen notes sit is counted once it is put, and
    /// a question about nothing is not a question.
    ///
    /// Nothing asked the count of a node that had asked nothing, so a count
    /// that said one before anything was asked passed.
    #[test]
    fn a_question_is_counted_once_it_is_put_and_not_before() {
        let node = Node::bind(ConsensusParams::testnet(), loopback()).unwrap();
        let before = node.proofs_asked_for();
        let _ = node.recover_proofs(&[], Duration::ZERO);
        let about_nothing = node.proofs_asked_for();
        let _ = node.recover_proofs(&[(0, Hash32::ZERO)], Duration::ZERO);
        let once = node.proofs_asked_for();
        node.shutdown();

        assert_eq!(
            before, 0,
            "a node that had asked nothing counted a question"
        );
        assert_eq!(about_nothing, 0, "a question about nothing was counted");
        assert_eq!(once, 1, "a question that was put was not counted");
    }

    /// A question that everybody asked has answered ends there, rather than at
    /// the end of its patience.
    ///
    /// Every recovery in the suite waited within its patience and looked only
    /// at what came back, so a wait that ran to the end of the patience
    /// whatever the answers passed. That is a wallet held for the whole wait
    /// by a peer that answered at once that it could not help.
    #[test]
    fn a_question_everyone_asked_has_answered_ends_there() {
        let params = ConsensusParams::testnet();
        let answering = Node::bind(params, loopback()).unwrap();
        let asking = Node::bind(params, loopback()).unwrap();
        asking.connect(answering.address()).unwrap();
        wait_until("the two nodes to introduce themselves", || {
            asking.peers_introduced() == 1
        });

        let patience_seconds = 10;
        let started = Instant::now();
        let answer =
            asking.recover_proofs(&[(0, Hash32::ZERO)], Duration::from_secs(patience_seconds));
        let took = started.elapsed().as_secs();
        asking.shutdown();
        answering.shutdown();

        assert_eq!(
            (answer.asked, answer.answered),
            (1, 1),
            "the one peer was asked and answered"
        );
        assert!(
            took < patience_seconds / 2,
            "a question everyone asked had answered was held open for {took} seconds of a \
             patience of {patience_seconds}"
        );
    }

    /// A node connected to nobody reaches for an archivist it has heard of.
    ///
    /// Nothing started a recovery from a node with nobody connected and an
    /// archivist in its book, so a node that never reached, or reached only
    /// for addresses it was already connected to, passed. That is a wallet
    /// told its money is out of reach while the address of somebody who could
    /// help sat in its own book.
    #[test]
    fn a_node_connected_to_nobody_reaches_for_an_archivist_it_has_heard_of() {
        let params = ConsensusParams::testnet();
        let answering = Node::bind(params, loopback()).unwrap();
        let asking = Node::bind(params, loopback()).unwrap();
        let known = answering.address();
        {
            let mut book = asking.shared.book();
            assert!(book.insert(known), "the address goes into the book");
            book.keeps_the_cold_set(&known, true);
            // A dial that came to nothing, so the dial round of upkeep leaves
            // it alone for a minute and the only way to it is the reach.
            let _ = book.missed(&known, unix_now());
        }

        let answer = asking.recover_proofs(&[(0, Hash32::ZERO)], Duration::from_secs(5));
        asking.shutdown();
        answering.shutdown();

        assert_eq!(
            answer.asked, 1,
            "a node connected to nobody asked nobody, with an archivist in its book"
        );
    }
}

/// What it takes before a node says its build is too old for its chain.
///
/// AUDIT: nothing counted these at all. A version above what this build knows
/// stopped being remembered against the block and stopped being blamed on the
/// peer, which is right, and the whole of what an un-updated node then did
/// about the real chain was refuse it in silence.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod unjudged_tests {
    use super::{
        count_unreadable, too_old_for_the_chain, Unreadable, UNJUDGED_BLOCKS, UNJUDGED_MEMORY,
        UNJUDGED_PEERS, UNJUDGED_SENDERS, UNJUDGED_STRETCH,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// One peer, as it says it can be reached.
    fn address(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), 9_944)
    }

    /// The same machine, on a different connection: a fresh source port, the
    /// same peer. This is the arrival that used to count twice.
    fn again(last: u8) -> SocketAddr {
        address(last)
    }

    /// A record of `blocks` of them from `peers` addresses, spread over `over`.
    ///
    /// Addresses and not connections, which is the repair this counting
    /// needed: a connection is handed out one per socket and never reused, so
    /// one machine at one address met the "two peers" condition by hanging up
    /// and dialling back.
    fn met(blocks: u64, peers: u64, over: u64) -> Unreadable {
        Unreadable {
            version: 7,
            blocks,
            peers: (0..peers).map(|n| address(n as u8)).collect(),
            first: 1_000,
            last: 1_000 + over,
        }
    }

    /// The claim: this is evidence, and each half of it on its own is
    /// something a stranger can produce for the price of a message.
    #[test]
    fn every_condition_is_needed_and_none_of_them_is_enough() {
        let enough = met(UNJUDGED_BLOCKS, UNJUDGED_PEERS as u64, UNJUDGED_STRETCH);
        let said = too_old_for_the_chain(&enough).expect("all three met");
        assert_eq!(said.version, 7, "and it names the version it saw");
        assert_eq!(said.peers, UNJUDGED_PEERS);
        assert_eq!(said.over, UNJUDGED_STRETCH);

        assert!(
            too_old_for_the_chain(&met(
                UNJUDGED_BLOCKS - 1,
                UNJUDGED_PEERS as u64,
                UNJUDGED_STRETCH
            ))
            .is_none(),
            "a handful of blocks is a handful of numbers in a field"
        );
        assert!(
            too_old_for_the_chain(&met(UNJUDGED_BLOCKS, 1, UNJUDGED_STRETCH)).is_none(),
            "one peer is one machine, and one machine is what a stranger has"
        );
        assert!(
            too_old_for_the_chain(&met(
                UNJUDGED_BLOCKS,
                UNJUDGED_PEERS as u64,
                UNJUDGED_STRETCH - 1
            ))
            .is_none(),
            "a burst is one idea; a chain that moved on goes on producing these"
        );
    }

    /// A clock that went backwards says nothing about how long these have been
    /// arriving, so it is not allowed to say anything at all.
    #[test]
    fn a_clock_that_went_backwards_proves_nothing() {
        let mut backwards = met(UNJUDGED_BLOCKS, UNJUDGED_PEERS as u64, UNJUDGED_STRETCH);
        backwards.last = backwards.first - 1;
        assert!(too_old_for_the_chain(&backwards).is_none());
    }

    /// Nothing met is nothing said, which is the answer for every healthy node
    /// on a chain whose rules have not moved.
    #[test]
    fn a_node_that_has_met_none_of_them_says_nothing() {
        assert!(too_old_for_the_chain(&Unreadable::default()).is_none());
    }

    /// The claim under `UNJUDGED_PEERS`: "one peer is one machine, and one
    /// machine is what a stranger has".
    ///
    /// These were counted by connection, and a connection is handed out one
    /// per socket and never reused. So one machine at one address met the
    /// condition by hanging up and dialling back, which costs it a TCP
    /// handshake and is not misbehaviour, and the line the operator then read
    /// said "8 blocks from 2 peers" and told them to install a newer build.
    #[test]
    fn one_machine_arriving_again_is_still_one_peer() {
        let mut met = Unreadable::default();
        for round in 0..UNJUDGED_BLOCKS {
            count_unreadable(&mut met, Some(again(7)), 7, 1_000 + round * 60);
        }
        assert_eq!(met.blocks, UNJUDGED_BLOCKS);
        assert_eq!(
            met.peers.len(),
            1,
            "however many sockets they arrived on, that is one machine"
        );
        assert!(
            too_old_for_the_chain(&met).is_none(),
            "and one machine does not get to tell somebody their build is out of \
             date: {met:?}"
        );

        // A second address does, which is the whole of what the condition is
        // worth and all it was ever meant to claim.
        count_unreadable(&mut met, Some(address(8)), 7, 1_000 + UNJUDGED_STRETCH * 2);
        let said = too_old_for_the_chain(&met).expect("two addresses over the stretch");
        assert_eq!(said.peers, UNJUDGED_PEERS);
    }

    /// A silence longer than the memory ends the count, and nothing shorter
    /// does.
    ///
    /// The rule is written out above `count_unreadable`, which is kept apart so
    /// it can be tested on its own, and nothing held it. A count that never
    /// lapsed passed, as did one that lapsed a second early, one that started
    /// again whenever two blocks arrived in the same second, and one a clock
    /// stepping back left standing. The peers it keeps were capped one past
    /// the cap.
    #[test]
    fn the_count_lapses_after_a_silence_and_not_before() {
        let mut met = Unreadable::default();
        count_unreadable(&mut met, Some(address(1)), 7, 1_000);
        count_unreadable(&mut met, Some(address(2)), 7, 1_000);
        assert_eq!(
            met.blocks, 2,
            "two in one second are two, not a fresh start"
        );

        count_unreadable(&mut met, Some(address(3)), 7, 1_000 + UNJUDGED_MEMORY);
        assert_eq!(
            met.blocks, 3,
            "a silence as long as the memory is not past it"
        );

        let later = 1_000 + 2 * UNJUDGED_MEMORY + 1;
        count_unreadable(&mut met, Some(address(4)), 7, later);
        assert_eq!(
            (met.blocks, met.first, met.peers.len()),
            (1, later, 1),
            "a silence past the memory starts the count again"
        );

        count_unreadable(&mut met, Some(address(5)), 7, 500);
        assert_eq!(
            (met.blocks, met.first),
            (1, 500),
            "and so does a clock that stepped back"
        );

        let mut crowd = Unreadable::default();
        for peer in 0..=UNJUDGED_SENDERS {
            count_unreadable(&mut crowd, Some(address(peer as u8)), 7, 1_000);
        }
        assert_eq!(
            crowd.peers.len(),
            UNJUDGED_SENDERS,
            "the peers are kept up to the cap and no further"
        );
    }
}

/// What a node does with the peers it holds and the rounds it keeps: whom it
/// dials, what it reads off a connection, what it writes down when one ends,
/// and what it asks for again.
///
/// Most of it runs on a node none of whose own threads are running, so what a
/// test does to it is the only thing happening to it. A node's rounds run on
/// the real clock and would otherwise race whatever a test puts in front of
/// them.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod peers_and_loops {
    use std::net::Ipv4Addr;

    use crate::book::MAX_MISSES;
    use crate::message::{Handshake, PROTOCOL_VERSION};
    use crate::sync::JOIN_RATHER_THAN_READ;

    use super::*;

    fn local() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    /// A node none of whose own threads are running.
    ///
    /// Stopped rather than never started, because starting is what builds
    /// one.
    fn quiet() -> Node {
        let node = Node::bind(ConsensusParams::testnet(), local()).unwrap();
        node.shutdown();
        node
    }

    /// Stops what a test started by hand on a quiet node: the connections it
    /// dialled, and the threads reading and writing them.
    fn stop_all(node: &Node) {
        node.shared.running.store(false, Ordering::SeqCst);
        node.shared.winding_down.store(false, Ordering::SeqCst);
        node.shutdown();
    }

    /// Both ends of one connection on this machine.
    fn a_socket() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(local()).unwrap();
        let far = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (near, _) = listener.accept().unwrap();
        (near, far)
    }

    /// A place in the peer table, for a test about the table rather than about
    /// anything said on a connection. The socket is there only so a shutdown
    /// has something to close.
    fn stand_in(socket: &TcpStream, dialled: bool) -> Peer {
        Peer {
            outbound: Outbound::nowhere(),
            stream: socket.try_clone().unwrap(),
            host: None,
            advertised: None,
            dialled_to: None,
            dialled,
            greeted: false,
            archives: false,
        }
    }

    /// A listener nothing accepts from, standing for an address worth
    /// dialling. A dial to it completes and then waits.
    fn a_door() -> TcpListener {
        TcpListener::bind(local()).unwrap()
    }

    /// Connections this node went out and opened, counted off its table.
    ///
    /// Off the table rather than off the far end, because a dial is in the
    /// table before the round that made it returns, and a listener on this
    /// machine may not have the connection ready to take for a moment after.
    fn dialled(node: &Node) -> usize {
        node.shared
            .peers()
            .values()
            .filter(|peer| peer.dialled_to.is_some())
            .count()
    }

    /// Headers linked from `from` up, with nothing mined: a header log checks
    /// heights and links, and nothing here weighs work. Everything else is
    /// the devnet's first header, so no field is made up here.
    fn headers_from(from: u64, count: u64, network: NetworkId) -> Vec<BlockHeader> {
        let first = genesis::block(NetworkId::DEVNET).unwrap().header;
        let mut previous = Hash32::ZERO;
        (from..from + count)
            .map(|height| {
                let header = BlockHeader {
                    network,
                    height,
                    previous,
                    ..first
                };
                previous = header.id();
                header
            })
            .collect()
    }

    /// A quiet node whose header log holds `count` headers from `from` up, and
    /// the directory it keeps them in.
    ///
    /// Anywhere above nought is what a node handed a ledger holds: its own
    /// headers from the anchor up, and none from before it arrived.
    fn holding_headers(from: u64, count: u64, name: &str) -> (Node, PathBuf) {
        let params = ConsensusParams::testnet();
        let directory = std::env::temp_dir().join(format!("cairn-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let (blocks, _) = BlockLog::open(&directory).unwrap();
        let mut headers = HeaderLog::open(&directory).unwrap();
        for header in headers_from(from, count, params.network) {
            headers.append(&header).unwrap();
        }
        let store = Store {
            blocks,
            headers,
            forest: HeaderTree::open(&directory).unwrap(),
            filling: HeaderLog::open_named(&directory, FILLING_LOG).unwrap(),
            filling_epoch: 0,
        };
        let node = Node::start(
            params,
            local(),
            ChainStore::new(params),
            Some(store),
            AddressBook::new(),
            Some(directory.clone()),
            None,
            None,
            None,
        )
        .unwrap();
        node.shutdown();
        (node, directory)
    }

    /// One connection into a quiet node, with this test at the far end and
    /// the node's reading loop at the near one.
    ///
    /// What the node says back lands in `said` rather than on the wire, so a
    /// test reads the node's answers without a writer in between.
    struct Line {
        node: Node,
        id: PeerId,
        far: TcpStream,
        said: mpsc::Receiver<(Message, usize)>,
        reading: JoinHandle<()>,
    }

    impl Line {
        /// Opens one into `node`: a connection this node dialled to `dialled`,
        /// or without it one somebody else opened.
        fn open(node: Node, dialled: Option<SocketAddr>) -> Self {
            node.shared.running.store(true, Ordering::SeqCst);
            let (near, far) = a_socket();
            let remote = near.peer_addr().ok().map(|address| address.ip());
            let id = node.shared.next_id.fetch_add(1, Ordering::Relaxed);
            let (sender, said) = mpsc::sync_channel(4_096);
            let outbound = Outbound::new(sender);
            node.shared.peers().insert(
                id,
                Peer {
                    outbound: outbound.clone(),
                    host: remote,
                    dialled_to: dialled,
                    ..stand_in(&near, dialled.is_some())
                },
            );
            let shared = Arc::clone(&node.shared);
            let reading =
                thread::spawn(move || read_loop(&shared, near, id, &outbound, remote, dialled));
            Self {
                node,
                id,
                far,
                said,
                reading,
            }
        }

        fn send(&mut self, message: &Message) {
            // A node that has hung up is what some of these tests are about,
            // so a write it no longer takes is not a failure here.
            let _ = write_message(&mut self.far, self.node.shared.network(), message);
        }

        /// Whether the node answers with something `wanted` picks out.
        fn hears(&self, wanted: impl Fn(&Message) -> bool) -> bool {
            while let Ok((message, _)) = self.said.recv_timeout(Duration::from_secs(10)) {
                if wanted(&message) {
                    return true;
                }
            }
            false
        }

        /// Whether the node ends the connection by itself, given a while to.
        fn ends(&self) -> bool {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if self.reading.is_finished() {
                    return true;
                }
                thread::sleep(Duration::from_millis(10));
            }
            false
        }

        /// Hangs up this end, waits for the loop to finish, and hands the node
        /// back quiet.
        fn close(self) -> Node {
            let _ = self.far.shutdown(Shutdown::Both);
            self.reading.join().unwrap();
            self.node.shared.running.store(false, Ordering::SeqCst);
            self.node
        }
    }

    /// An introduction from a peer listening on 9944, claiming `height` blocks
    /// carrying `work`, under the number it `drew` at start.
    fn hello(network: NetworkId, height: u64, work: u128, drew: u64) -> Message {
        Message::Hello(Handshake {
            version: PROTOCOL_VERSION,
            network,
            genesis: Hash32::ZERO,
            tip: Hash32::ZERO,
            height,
            total_work: work,
            listen: 9_944,
            nonce: drew,
            keeps: Keeps {
                headers: true,
                cold_set: false,
            },
        })
    }

    /// A number drawn at start that is not the node's own.
    fn stranger(node: &Node) -> u64 {
        !node.shared.nonce
    }

    /// A peer's queue holds what one window of allowance buys, to within one
    /// message.
    ///
    /// The ceiling was held from above and never from below. A queue of one
    /// megabyte passed, and what does not fit is not sent: a peer that had
    /// paid for a window of blocks could be sent a quarter of them, and a
    /// piece of a join that did not fit ended the connection it was for.
    #[test]
    fn a_queue_holds_what_a_window_of_allowance_buys() {
        // `ALLOWANCE` units of `BYTES_PER_UNIT` bytes, as `sync` prices them.
        const WINDOW_BUYS: usize = 8_192 * 512;
        let block = Message::JoinPart {
            what: Joining::Ledger,
            at: Hash32::ZERO,
            part: 0,
            parts: 1,
            bytes: vec![0u8; 128 * 1024],
        };
        let weight = block.weight();
        let (sender, _inbox) = mpsc::sync_channel(OUTBOUND_QUEUE);
        let outbound = Outbound::new(sender);
        while outbound.try_send(block.clone()).is_ok() {}
        let held = outbound.queued();
        assert!(
            held <= WINDOW_BUYS,
            "more was queued for one peer than a window of allowance buys"
        );
        assert!(
            held + weight > WINDOW_BUYS,
            "the queue refused an answer with room left under what a window buys"
        );
    }

    /// A node that has reached nobody takes exactly as many connections from
    /// outside as `MOST_FROM_OUTSIDE` says.
    ///
    /// The figure is what operators and the audits read, and nothing tied it
    /// to the rule that makes it: the audits ask for at least that many, so a
    /// figure of six passed them all while the node went on taking forty.
    #[test]
    fn a_node_that_has_reached_nobody_takes_what_it_says_from_outside() {
        let node = quiet();
        let (socket, _far) = a_socket();
        let visitor = Some(IpAddr::from([203, 0, 113, 9]));
        {
            let mut peers = node.shared.peers();
            for id in 1..MOST_FROM_OUTSIDE {
                peers.insert(u64::try_from(id).unwrap(), stand_in(&socket, false));
            }
        }
        assert!(
            node.shared.has_room_to_accept(visitor),
            "a node one short of what it says it takes from outside turned a visitor away"
        );
        node.shared.peers().insert(
            u64::try_from(MOST_FROM_OUTSIDE).unwrap(),
            stand_in(&socket, false),
        );
        assert!(
            !node.shared.has_room_to_accept(visitor),
            "a node that has reached nobody took more from outside than it says"
        );
    }

    /// Enough showings from enough peers say the chain cannot be weighed, in
    /// one second as much as over an hour, and a clock that went backwards
    /// says nothing.
    ///
    /// Nothing asked the rule itself. Wanting a third peer passed, and so did
    /// wanting the showings spread over more than one second, which a node
    /// asking one claimant after another in quick succession may never get.
    #[test]
    fn showings_from_enough_peers_say_the_chain_cannot_be_weighed_at_once() {
        let from =
            |last: u64| SocketAddr::from(([203, 0, 113, u8::try_from(last).unwrap()], 9_944));
        let met = |showings: u64, peers: u64| {
            let mut met = Unweighed::default();
            for showing in 0..showings {
                count_unweighed(&mut met, Some(from(showing % peers + 1)), "no path", 1_000);
            }
            met
        };
        let two = u64::try_from(UNWEIGHED_PEERS).unwrap();

        let said = no_showing_checks_out(&met(UNWEIGHED_SHOWINGS, two))
            .expect("enough showings from enough peers in one second said nothing");
        assert_eq!(said.peers, UNWEIGHED_PEERS);
        assert_eq!(said.showings, UNWEIGHED_SHOWINGS);
        assert_eq!(said.over, 0);

        assert!(
            no_showing_checks_out(&met(UNWEIGHED_SHOWINGS - 1, two)).is_none(),
            "one showing short was enough"
        );
        assert!(
            no_showing_checks_out(&met(UNWEIGHED_SHOWINGS, two - 1)).is_none(),
            "one peer short was enough"
        );

        let mut backwards = met(UNWEIGHED_SHOWINGS, two);
        backwards.first = backwards.last + 1;
        assert!(
            no_showing_checks_out(&backwards).is_none(),
            "a clock that went backwards was taken as a stretch of showings"
        );
    }

    /// The burial is asked for at most once in a second, and asked for again
    /// when the clock is put back behind the last question.
    ///
    /// Neither edge was held: a second question in the same second passed,
    /// and so did a clock put back behind the last question leaving the node
    /// to wait out a patience counted from a moment that has not come yet.
    #[test]
    fn the_burial_is_asked_for_once_a_second_and_again_after_the_clock_steps_back() {
        let mut held = Undertaking::resumed(100, 1_124, Some(100), 1_000).unwrap();
        assert!(matches!(
            owed_this_round(&mut held, 100, 1, STRANDING_PATIENCE, 1_040),
            Owed::AskAgain
        ));
        assert!(
            matches!(
                owed_this_round(&mut held, 100, 1, STRANDING_PATIENCE, 1_040),
                Owed::Waiting
            ),
            "the burial was asked for twice in one second"
        );
        assert!(
            matches!(
                owed_this_round(&mut held, 100, 1, STRANDING_PATIENCE, 1_020),
                Owed::AskAgain
            ),
            "a clock put back behind the last question left the node waiting on it"
        );
    }

    /// Adopting an anchor starts the probation that goes with it.
    ///
    /// Nothing looked. A node that took a handed ledger and wrote nothing down
    /// passed, which is a node answering off a ledger nobody has stood behind
    /// while saying it owes nothing.
    #[test]
    fn an_anchor_taken_is_a_probation_begun() {
        let node = quiet();
        assert_eq!(
            node.probation(),
            None,
            "a node that took nothing owes nothing"
        );
        node.shared.undertake(100, 1_124, 5_000);
        assert_eq!(
            node.probation(),
            Some(Probation {
                anchor: 100,
                settles_at: 1_124,
                reached: 100,
            }),
            "a node that took an anchor said it owed nothing for it"
        );
    }

    /// Blocks this build cannot read, and blocks from a branch it cannot
    /// reach, are counted where an operator reads them.
    ///
    /// Nothing followed either count out of the connection loop. Counting none
    /// of the unreadable ones passed, as did a node that never said it was too
    /// old whatever it had met, and one that said nought blocks were out of
    /// its reach however many had arrived.
    #[test]
    fn what_was_not_taken_reaches_the_operator() {
        let node = quiet();
        let unreadable = Reaction {
            unjudged: Some(9),
            ..Reaction::default()
        };
        for block in 0..UNJUDGED_BLOCKS {
            let from =
                SocketAddr::from(([203, 0, 113, u8::try_from(block % 2 + 1).unwrap()], 9_944));
            let at = 1_000 + block * UNJUDGED_STRETCH / (UNJUDGED_BLOCKS - 1);
            note_what_was_not_taken(&node.shared, &unreadable, Some(from), at);
        }
        let said = node
            .unjudged()
            .expect("a run of unreadable blocks from two peers over the stretch said nothing");
        assert_eq!(
            (said.version, said.blocks, said.peers, said.over),
            (9, UNJUDGED_BLOCKS, UNJUDGED_PEERS, UNJUDGED_STRETCH)
        );

        assert_eq!(node.out_of_reach(), 0, "nothing has arrived out of reach");
        let unreachable = Reaction {
            unreachable: Some(5),
            ..Reaction::default()
        };
        note_what_was_not_taken(&node.shared, &unreachable, None, 2_000);
        note_what_was_not_taken(&node.shared, &unreachable, None, 2_001);
        assert_eq!(
            node.out_of_reach(),
            2,
            "blocks from a branch this node cannot reach went uncounted"
        );
    }

    /// Refusing this build's own first block is written down, and said while
    /// the node has no chain.
    ///
    /// Nothing called the note: a node that refused its own network's first
    /// block and wrote nothing passed, which is the one clock this node can be
    /// sure is wrong, and nobody told.
    #[test]
    fn refusing_its_own_first_block_is_written_down() {
        let node = quiet();
        assert_eq!(node.clock_behind(), None);
        node.shared.own_first_block_refused(4_000, 1_000);
        let said = node
            .clock_behind()
            .expect("refusing its own first block said nothing");
        assert!(said.own_first_block, "and it was not said for what it was");
        assert_eq!(said.seconds, 4_000);
    }

    /// A node says it can show a newcomer the chain only when its log holds
    /// every header from the first.
    ///
    /// The answer goes into every greeting this node dials out with, and
    /// nothing asked it. A node saying yes with no log at all passed, and so
    /// did one saying no with everything in hand, which is a node the chooser
    /// of every newcomer passes over.
    #[test]
    fn a_node_shows_the_chain_only_from_a_log_that_starts_at_the_beginning() {
        let shows = |node: &Node| {
            let chain = node.shared.chain();
            node.shared.shows_the_chain(&chain)
        };
        assert!(
            !shows(&quiet()),
            "a node that keeps nothing said it could show the chain"
        );

        let (whole, first) = holding_headers(0, 0, "shows-whole");
        let (handed, second) = holding_headers(10, 3, "shows-handed");
        let (whole_shows, handed_shows) = (shows(&whole), shows(&handed));
        drop((whole, handed));
        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
        assert!(
            whole_shows,
            "a node holding every header from the first said it could not show the chain"
        );
        assert!(
            !handed_shows,
            "a node missing the headers from before it arrived said it could show the chain"
        );
    }

    /// The peer filling the old headers in keeps its turn for
    /// `HEADER_PATIENCE` seconds and not one more.
    ///
    /// Nothing held the edge. A turn kept through its last second passed,
    /// which is one more second a peer that has stopped delivering holds up
    /// the one exchange that lets this node take a newcomer in.
    #[test]
    fn the_turn_to_fill_the_headers_in_passes_on_once_its_patience_is_spent() {
        let (node, directory) = holding_headers(10, 3, "turn");
        *node.shared.filling_from() = Some(Turn {
            peer: 1,
            moved: 1_000,
            marked: 0,
            spoiled: false,
        });
        let before = node
            .shared
            .asks_headers_of(&[1, 2], 1_000 + HEADER_PATIENCE - 1)
            .map(|(peer, _)| peer);
        let after = node
            .shared
            .asks_headers_of(&[1, 2], 1_000 + HEADER_PATIENCE)
            .map(|(peer, _)| peer);
        drop(node);
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(
            before,
            Some(1),
            "the turn was taken away inside its patience"
        );
        assert_eq!(after, Some(2), "the turn was kept past its patience");
    }

    /// A ledger in two pieces is taken whole, and a piece naming another
    /// ledger ends the attempt.
    ///
    /// Nothing handed a ledger over in more than one piece: taking every
    /// piece that belonged as the end of the attempt, and filing every piece
    /// that did not, both passed.
    #[test]
    fn a_ledger_in_pieces_is_taken_whole_and_a_stray_piece_ends_it() {
        let node = quiet();
        let tip = headers_from(40, 1, node.shared.network())[0];
        let at = Hash32::from_bytes([3; 32]);
        let fetching = || Progress::Fetching {
            tip,
            collecting: Collecting::started(Joining::Ledger, at, 0, 2, vec![1, 2], 1_000).unwrap(),
        };

        let mut joining = fetching();
        let (next, whole) = take_piece(
            &mut joining,
            &node.shared,
            7,
            Joining::Ledger,
            at,
            1,
            2,
            vec![3],
            1_001,
        );
        assert_eq!(
            whole,
            Some(vec![1, 2, 3]),
            "the last piece of a ledger was not taken"
        );
        assert!(next.is_none(), "a whole ledger asked for more");
        assert!(matches!(joining, Progress::Fetching { .. }));

        let mut joining = fetching();
        let elsewhere = Hash32::from_bytes([4; 32]);
        let (next, whole) = take_piece(
            &mut joining,
            &node.shared,
            7,
            Joining::Ledger,
            elsewhere,
            1,
            2,
            vec![3],
            1_001,
        );
        assert!(
            whole.is_none() && next.is_none(),
            "a piece of another ledger was taken"
        );
        assert!(
            matches!(joining, Progress::Idle),
            "a piece of another ledger did not end the attempt"
        );
    }

    /// Peer `id`, in the table with its queue read by the test, claiming a
    /// chain long enough that this node would be handed its ledger, heard at
    /// `at`.
    fn a_claimant(
        node: &Node,
        socket: &TcpStream,
        id: PeerId,
        at: u64,
    ) -> mpsc::Receiver<(Message, usize)> {
        let (sender, inbox) = mpsc::sync_channel(8);
        node.shared.peers().insert(
            id,
            Peer {
                outbound: Outbound::new(sender),
                ..stand_in(socket, true)
            },
        );
        node.shared
            .choosing()
            .noted(id, None, 10, JOIN_RATHER_THAN_READ, true, at);
        inbox
    }

    /// Whether what a peer was sent is the first question of a join.
    fn asks_for_the_join(message: &Result<(Message, usize), mpsc::TryRecvError>) -> bool {
        matches!(
            message,
            Ok((
                Message::GetJoin {
                    what: Joining::Weight,
                    part: 0
                },
                _
            ))
        )
    }

    /// A join still moving is left alone, and one gone quiet for as long as a
    /// join waits is given up on.
    ///
    /// The round read how the join was going and nothing held what it read.
    /// A join taken for stalled the moment its first piece landed passed, as
    /// did one never taken for stalled however quiet, which leaves a node
    /// waiting on a peer that stopped sending for the three minutes an attempt
    /// is allowed rather than the half minute a join is.
    #[test]
    fn a_join_is_given_up_on_once_it_goes_quiet_and_not_while_it_moves() {
        let node = quiet();
        let (socket, _far) = a_socket();
        let inbox = a_claimant(&node, &socket, 7, 10_000);
        let asked = 10_060;
        drive_choosing(&node.shared, asked);
        assert!(asks_for_the_join(&inbox.try_recv()));
        assert_eq!(node.shared.choosing().asking_join(), Some((7, asked)));

        // The first piece lands.
        let at = Hash32::from_bytes([3; 32]);
        *node.shared.joining() = Progress::Weighing(
            Collecting::started(Joining::Weight, at, 0, 4, vec![1], asked).unwrap(),
        );
        drive_choosing(&node.shared, asked + 1);
        assert_eq!(
            node.shared.choosing().asking_join(),
            Some((7, asked)),
            "a join whose first piece had just landed was given up on"
        );
        drive_choosing(&node.shared, asked + JOIN_PATIENCE);
        assert_eq!(
            node.shared.choosing().asking_join(),
            None,
            "a join quiet for as long as a join waits was not given up on"
        );
    }

    /// The first question of a join, gone unanswered, is asked again once the
    /// window it went out in has turned, and once only in the next.
    ///
    /// Nothing ran this. A node that never asked again passed, as did one
    /// that asked again only inside the window it had last asked in, which is
    /// never, since the last time starts at nought. Either way a dropped first
    /// question ended the join half a minute later and cost the claimant its
    /// turn.
    #[test]
    fn an_unanswered_join_is_asked_again_once_its_window_has_turned() {
        let node = quiet();
        let (socket, _far) = a_socket();
        let inbox = a_claimant(&node, &socket, 7, 10_000);
        // Asked at the top of a window, so the next begins ten seconds on.
        drive_choosing(&node.shared, 10_060);
        assert!(asks_for_the_join(&inbox.try_recv()));

        ask_again_for_the_join(&node.shared, 10_065);
        assert!(
            inbox.try_recv().is_err(),
            "asked again inside the window the question went out in"
        );
        ask_again_for_the_join(&node.shared, 10_070);
        assert!(
            asks_for_the_join(&inbox.try_recv()),
            "a join whose first question went unanswered was not asked again"
        );
        ask_again_for_the_join(&node.shared, 10_075);
        assert!(
            inbox.try_recv().is_err(),
            "asked again twice inside one window"
        );
    }

    /// What a join waits on is the first piece it lacks, and a join that has
    /// landed waits on nothing.
    #[test]
    fn what_a_join_waits_on_is_the_first_piece_it_lacks() {
        let tip = headers_from(40, 1, ConsensusParams::testnet().network)[0];
        let at = Hash32::from_bytes([3; 32]);
        let collecting =
            |what, part| Collecting::started(what, at, part, 3, vec![1], 1_000).unwrap();
        assert_eq!(still_wanted(&Progress::Idle), Some((Joining::Weight, 0)));
        assert_eq!(still_wanted(&Progress::Landed), None);
        assert_eq!(
            still_wanted(&Progress::Weighing(collecting(Joining::Weight, 0))),
            Some((Joining::Weight, 1))
        );
        assert_eq!(
            still_wanted(&Progress::Weighed { tip, since: 1_000 }),
            Some((Joining::Ledger, 0))
        );
        assert_eq!(
            still_wanted(&Progress::Fetching {
                tip,
                collecting: collecting(Joining::Ledger, 1),
            }),
            Some((Joining::Ledger, 0))
        );
    }

    /// A round dials what the node is short of and no more.
    ///
    /// Nothing held the count: a round that went on dialling past what it
    /// wanted passed, which is a node opening a connection to everything in
    /// its book once a second.
    #[test]
    fn a_round_dials_what_the_node_is_short_of_and_no_more() {
        let node = quiet();
        let (socket, _far) = a_socket();
        {
            let mut peers = node.shared.peers();
            for id in 1..TARGET_PEERS {
                peers.insert(u64::try_from(id).unwrap(), stand_in(&socket, true));
            }
        }
        let doors = [a_door(), a_door()];
        for door in &doors {
            node.shared.book().insert(door.local_addr().unwrap());
        }
        node.shared.running.store(true, Ordering::SeqCst);
        dial_from_book(&node.shared, 1_000);
        let reached = dialled(&node);
        stop_all(&node);
        assert_eq!(
            reached, 1,
            "a node one peer short of its target dialled more than one"
        );
    }

    /// A node whose table is full dials nobody.
    ///
    /// The round took a dial as allowed when either the refusal or the room
    /// said so, and nothing held it to both: dialling out of a full table
    /// passed, which is one connection more than the ceiling says a node
    /// holds.
    #[test]
    fn a_node_whose_table_is_full_dials_nobody() {
        let node = quiet();
        let (socket, _far) = a_socket();
        {
            let mut peers = node.shared.peers();
            for id in 0..MAX_PEERS {
                peers.insert(u64::try_from(id).unwrap(), stand_in(&socket, false));
            }
        }
        let door = a_door();
        node.shared.book().insert(door.local_addr().unwrap());
        node.shared.running.store(true, Ordering::SeqCst);
        dial_from_book(&node.shared, 1_000);
        let reached = dialled(&node);
        stop_all(&node);
        assert_eq!(reached, 0, "a node with every slot taken dialled another");
    }

    /// A peer may send as many messages as a window allows, and the next one
    /// ends it.
    ///
    /// Nothing sent that many. A ceiling one message lower passed, which ends
    /// the connection of a peer that did nothing but stay inside it.
    #[test]
    fn a_peer_may_say_as_much_as_a_window_allows_and_no_more() {
        let node = quiet();
        let greeting = hello(node.shared.network(), 0, 0, stranger(&node));
        let mut line = Line::open(node, None);
        line.send(&greeting);
        // The introduction was the first of them.
        let last = u64::from(MAX_MESSAGES_PER_WINDOW) - 1;
        for turn in 1..=last {
            line.send(&Message::Ping(turn));
        }
        assert!(
            line.hears(|message| matches!(message, Message::Pong(turn) if *turn == last)),
            "the last message a window allows was taken for a flood"
        );
        line.send(&Message::Ping(last + 1));
        let ended = line.ends();
        drop(line.close());
        assert!(ended, "a message past what a window allows was taken");
    }

    /// A claim is taken from the introduction and from nothing said after it.
    ///
    /// The loop notes a claim when a greeted peer introduces itself, and
    /// nothing held the pair. Noting one at every message a greeted peer sent
    /// passed, which hands a claim that has already failed a fresh start each
    /// time its peer says anything at all, a ping included.
    #[test]
    fn a_claim_that_failed_is_not_renewed_by_what_its_peer_says_next() {
        let node = quiet();
        let greeting = hello(
            node.shared.network(),
            JOIN_RATHER_THAN_READ,
            10,
            stranger(&node),
        );
        let mut line = Line::open(node, None);
        line.send(&greeting);
        assert!(line.hears(|message| matches!(message, Message::Welcome(_))));
        let now = unix_now();
        line.node.shared.choosing().failed(line.id, now);
        line.send(&Message::Ping(1));
        assert!(line.hears(|message| matches!(message, Message::Pong(1))));
        let step = line.node.shared.choosing().step(
            now + 5,
            true,
            0,
            JoinProgress::NothingYet,
            &[line.id],
        );
        drop(line.close());
        assert_eq!(
            step,
            choosing::Step::Quiet,
            "a claim that had failed was asked again after its peer sent a ping"
        );
    }

    /// A connection that turns out to be this node's own takes its address
    /// out of the book, and is never counted as a peer that introduced
    /// itself.
    ///
    /// Neither half was held. A node that kept its own address passed, which
    /// is a node dialling itself again on a later round, and so did one that
    /// marked the connection greeted, which is a node sending news down a
    /// connection it had just refused.
    #[test]
    fn meeting_itself_forgets_its_own_address_and_greets_nobody() {
        let node = quiet();
        let own = SocketAddr::from((Ipv4Addr::LOCALHOST, 9_944));
        node.shared.book().insert(own);
        let greeting = hello(node.shared.network(), 0, 0, node.shared.nonce);
        let mut line = Line::open(node, None);
        let id = line.id;
        line.send(&greeting);
        let ended = line.ends();
        let node = line.close();
        assert!(ended, "a node that met itself kept the connection");
        assert!(
            !node.shared.book().contains(&own),
            "a node that met itself kept its own address to dial again"
        );
        assert_eq!(
            node.shared.peers().get(&id).map(|peer| peer.greeted),
            Some(false),
            "a connection refused at its introduction was marked greeted"
        );
    }

    /// An address this node dialled that spoke before introducing itself is
    /// charged a miss, and is not credited with answering first.
    ///
    /// Nothing held any of it. A loop that wrote the connection down as
    /// announced before it had named any address passed, which credits the
    /// dial as answered and wipes every miss held against the address, and so
    /// did an ending that charged nothing, or charged only peers that had
    /// greeted. Each leaves an address that never once introduced itself in
    /// the book for good.
    #[test]
    fn a_dialled_address_that_never_introduced_itself_is_charged_a_miss() {
        let node = quiet();
        let dialled = SocketAddr::from((Ipv4Addr::LOCALHOST, 9_955));
        {
            let mut book = node.shared.book();
            book.insert(dialled);
            for _ in 1..MAX_MISSES {
                book.missed(&dialled, 1_000);
            }
        }
        let mut line = Line::open(node, Some(dialled));
        line.send(&Message::Ping(1));
        let ended = line.ends();
        let node = line.close();
        assert!(
            ended,
            "a peer that spoke before introducing itself was kept"
        );
        assert!(
            !node.shared.book().contains(&dialled),
            "an address that never introduced itself survived its last miss"
        );
    }

    /// The first block of a chain, mined here. A network with no first block
    /// pinned takes whichever one it is given.
    fn a_first_block(params: ConsensusParams) -> Block {
        let miner = cairn_crypto::SecretKey::generate().unwrap();
        let state = LedgerState::new();
        let height = state.next_height().unwrap();
        let coinbase = cairn_ledger::transaction::CoinbaseTransaction::new(
            height,
            vec![cairn_ledger::note::Note::new(
                params.initial_reward,
                miner.public_key(),
            )],
        );
        let block = cairn_ledger::validation::assemble_block(
            &state,
            coinbase,
            Vec::<Transfer>::new(),
            &params,
            1_600,
            height,
        )
        .unwrap();
        cairn_ledger::validation::mine_block(block, 1 << 22).unwrap()
    }

    /// A block this node took from one peer is announced to the others, and a
    /// message that brought nothing new is not.
    ///
    /// Nothing held which way round the test went. Announcing only when there
    /// was nothing to announce passed, which is a node that never passes on a
    /// block it took and sends every other peer an empty announcement for
    /// every message any one of them sends it.
    #[test]
    fn a_block_taken_is_passed_on_and_nothing_else_is() {
        let node = quiet();
        let params = ConsensusParams::testnet();
        let block = a_first_block(params);
        let (socket, _far) = a_socket();
        let (sender, others) = mpsc::sync_channel(64);
        node.shared.peers().insert(
            1_000,
            Peer {
                outbound: Outbound::new(sender),
                ..stand_in(&socket, true)
            },
        );
        let greeting = hello(params.network, 0, 0, stranger(&node));
        let mut line = Line::open(node, None);
        line.send(&greeting);
        assert!(line.hears(|message| matches!(message, Message::Welcome(_))));
        line.send(&Message::Block(Box::new(block.clone())));
        line.send(&Message::Ping(1));
        assert!(line.hears(|message| matches!(message, Message::Pong(1))));
        drop(line.close());

        let told: Vec<Message> = others.try_iter().map(|(message, _)| message).collect();
        let announced = told.iter().any(|message| {
            matches!(message, Message::Announce(ids) if ids.iter().any(|at| at.id == block.header.id()))
        });
        assert!(announced, "a block this node took was not passed on");
        assert_eq!(
            told.len(),
            1,
            "the other peers were told something besides the block"
        );
    }
}

/// What a node says and does about a clock, its own or a block's.
///
/// AUDIT: nothing anywhere in this crate or the one above it ever mentioned a
/// clock to the person running the node, and the one refusal that turns on a
/// clock was answered by refusing the host that carried it.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod clock_tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use cairn_ledger::genesis;
    use cairn_ledger::validation::ConsensusParams;

    use super::{
        clock_is_behind, count_out_of_step, is_peer_fault, open_the_chain, window_is_over,
        ChainStore, OutOfStep, WireError, BEHIND_BLOCKS, BEHIND_MEMORY, BEHIND_PEERS,
        BEHIND_SENDERS, FLOOD_WINDOW,
    };
    use crate::wire::MAX_FRAME_BYTES;

    const DRIFT: u64 = 7_200;

    fn address(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last)), 8_333)
    }

    /// **A frame that stalls is a fact about a link, not a fault of whoever is
    /// at the end of it.**
    ///
    /// AUDIT, repaired. `Stalled` was counted a peer fault, so a link falling
    /// under the frame floor cost its host [`crate::refusal::REFUSAL_SECONDS`]
    /// rather than the connection alone. The floor is `PROGRESS_BYTES` in
    /// `FRAME_PATIENCE`, about three and a quarter kilobytes a second, and the
    /// argument written above that constant for lowering it that far says a
    /// phone on a weak signal or a rural line delivers under it steadily. That
    /// argument is about what a slow link is, so it applies to the ban as much
    /// as to the floor.
    #[test]
    fn a_slow_link_loses_its_connection_and_not_its_address() {
        assert!(
            !is_peer_fault(&WireError::Stalled {
                had: 1_024,
                wanted: MAX_FRAME_BYTES,
            }),
            "a link that could not keep up is refused for ten minutes, on a \
             design whose whole claim is that anyone can run a full node"
        );

        // What a peer wrote itself, which nothing between the two ends
        // produces. These must stay faults or a node stops defending itself.
        assert!(is_peer_fault(&WireError::FrameTooLarge {
            declared: MAX_FRAME_BYTES + 1,
            limit: MAX_FRAME_BYTES,
        }));
        assert!(is_peer_fault(&WireError::Malformed(
            cairn_primitives::codec::CodecError::UnexpectedEnd
        )));
        assert!(
            !is_peer_fault(&WireError::Io(io::Error::from(
                io::ErrorKind::ConnectionReset
            ))),
            "and a closed socket never was one"
        );
    }

    /// **A clock stepping back must not turn an ordinary peer into a flood.**
    ///
    /// AUDIT, repaired. The window rolled on `now - started >= FLOOD_WINDOW`
    /// with nothing said about `now` going behind `started`, so a step back of
    /// an hour held one ten second window open for that hour. Every message
    /// counted into it, and the first peer past `MAX_MESSAGES_PER_WINDOW`,
    /// which is a few seconds of any peer serving a catch-up, was dropped as a
    /// flood and its host refused.
    #[test]
    fn a_clock_stepping_back_does_not_make_a_peer_look_like_a_flood() {
        let opened = 100_000;
        assert!(!window_is_over(opened, opened));
        assert!(!window_is_over(opened, opened + FLOOD_WINDOW - 1));
        assert!(window_is_over(opened, opened + FLOOD_WINDOW));
        assert!(
            window_is_over(opened, opened - 3_600),
            "an hour back is not an hour of one peer's messages in one window"
        );
    }

    /// A record of `blocks` refusals from `peers` addresses.
    fn met(blocks: u64, peers: u64) -> OutOfStep {
        let mut record = OutOfStep::default();
        for block in 0..blocks {
            let from = address((block % peers.max(1)) as u8);
            count_out_of_step(&mut record, Some(from), 900, 1_000 + block);
        }
        record
    }

    /// The claim: this is evidence and not a verdict, so each half on its own
    /// is something one machine with a fast clock can produce.
    #[test]
    fn both_conditions_are_needed_before_a_clock_is_blamed() {
        let enough = met(BEHIND_BLOCKS, BEHIND_PEERS as u64);
        let said = clock_is_behind(&enough, DRIFT, false).expect("both met");
        assert_eq!(said.blocks, BEHIND_BLOCKS);
        assert_eq!(said.peers, BEHIND_PEERS);
        assert_eq!(said.seconds, 900, "and it names the gap it actually saw");
        assert_eq!(said.drift, DRIFT);
        assert!(!said.own_first_block);

        assert!(
            clock_is_behind(&met(BEHIND_BLOCKS - 1, BEHIND_PEERS as u64), DRIFT, false).is_none(),
            "a handful is a miner with a fast clock"
        );
        assert!(
            clock_is_behind(&met(BEHIND_BLOCKS, 1), DRIFT, false).is_none(),
            "and one address is one machine, which is what a stranger has"
        );
    }

    /// **The one clock refusal that is nobody else's word.**
    ///
    /// The first block of the network is compiled into this binary. No peer
    /// sends it and nobody but this machine can be wrong about it, so one is
    /// enough where a run from several peers is otherwise needed.
    #[test]
    fn refusing_this_builds_own_first_block_says_it_on_its_own() {
        let mut record = OutOfStep {
            own_first_block: true,
            ..OutOfStep::default()
        };
        count_out_of_step(&mut record, None, 4_000, 1_000);
        let said = clock_is_behind(&record, DRIFT, true).expect("its own first block settles it");
        assert!(said.own_first_block);
        assert_eq!(said.peers, 0, "nobody sent it");

        assert!(
            clock_is_behind(&record, DRIFT, false).is_none(),
            "and it is spent once the node has a chain: the first block is laid \
             down once at start, so a clock put right while the node runs lets \
             it take the chain from a peer, and a line that stayed would be \
             telling its owner to fix something already fixed"
        );
    }

    /// **A machine dated before the day the network opened cannot start, and
    /// used to do it in silence.**
    ///
    /// AUDIT, repaired. `open_the_chain` read the refusal out of an
    /// `is_err()` and returned. The node then had no chain, so every peer's
    /// tip failed the same check, it kept nobody and showed no height, and
    /// what an operator had to work from was a node that looked like one
    /// waiting for its first peer.
    #[test]
    fn a_clock_behind_the_first_block_is_named_rather_than_dropped() {
        let params = ConsensusParams::for_network("testnet-6").expect("testnet-6 exists");
        let opened = genesis::opens_at(params.network);
        assert!(opened > 0, "testnet-6 pins a first block");

        let mut chain = ChainStore::new(params);
        let ahead = open_the_chain(&mut chain, None, params, opened - DRIFT - 60)
            .expect("a machine this far behind refuses its own first block");
        assert_eq!(ahead, DRIFT + 60, "and how far behind it is, is the answer");
        assert!(chain.is_empty(), "the block is still not taken");

        // And a machine whose clock is right lays the block down and says
        // nothing, which is every ordinary start.
        let mut chain = ChainStore::new(params);
        assert!(open_the_chain(&mut chain, None, params, opened + 60).is_none());
        assert!(!chain.is_empty());
    }

    /// A network with no first block pinned, which is what the tests
    /// everywhere else in this crate run on, is left alone whatever the clock
    /// says.
    #[test]
    fn a_network_without_a_pinned_first_block_is_left_alone() {
        let params = ConsensusParams::testnet();
        assert!(params.genesis.is_none());
        let mut chain = ChainStore::new(params);
        assert!(open_the_chain(&mut chain, None, params, 0).is_none());
        assert!(chain.is_empty());
    }

    /// A silence longer than the memory ends the count of blocks from the
    /// future, and does not end what the first block of this network said.
    ///
    /// The same rule as the count of unreadable blocks, written the same way,
    /// and held by nothing either: a count that never lapsed passed, as did
    /// one that lapsed a second early or at every second block in one second,
    /// and one that forgot this node had refused its own network's first
    /// block, which no peer sent it and no silence unsays.
    #[test]
    fn a_silence_ends_the_count_and_not_what_the_first_block_said() {
        let mut record = OutOfStep {
            own_first_block: true,
            ..OutOfStep::default()
        };
        count_out_of_step(&mut record, Some(address(1)), 900, 1_000);
        count_out_of_step(&mut record, Some(address(2)), 900, 1_000);
        assert_eq!(
            record.blocks, 2,
            "two in one second are two, not a fresh start"
        );

        count_out_of_step(&mut record, Some(address(3)), 900, 1_000 + BEHIND_MEMORY);
        assert_eq!(
            record.blocks, 3,
            "a silence as long as the memory is not past it"
        );

        count_out_of_step(
            &mut record,
            Some(address(4)),
            900,
            1_000 + 2 * BEHIND_MEMORY + 1,
        );
        assert_eq!(
            (record.blocks, record.peers.len()),
            (1, 1),
            "a silence past the memory starts the count again"
        );
        assert!(
            record.own_first_block,
            "and leaves standing that this node refused its own first block"
        );

        count_out_of_step(&mut record, Some(address(5)), 900, 500);
        assert_eq!(
            record.blocks, 1,
            "a clock that stepped back starts it again"
        );

        let mut crowd = OutOfStep::default();
        for peer in 0..=BEHIND_SENDERS {
            count_out_of_step(&mut crowd, Some(address(peer as u8)), 900, 1_000);
        }
        assert_eq!(
            crowd.peers.len(),
            BEHIND_SENDERS,
            "the peers are kept up to the cap and no further"
        );
    }
}

/// How far a node lets its disk fall behind before it stops.
///
/// AUDIT: nothing measured the gap and nothing bounded it. A node with a full
/// disk climbed in height for as long as it was left running, and the blocks
/// it had accepted left memory on a schedule that knew nothing about what had
/// reached the disk.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod behind_tests {
    use super::{MAX_BEHIND, MAX_REORG_DEPTH};

    /// The claim from [`MAX_BEHIND`]: a log further behind than the window a
    /// chain keeps bodies for can never be brought level, so the number a node
    /// stops at has to sit below that window rather than at it.
    #[test]
    fn a_node_stops_inside_the_window_it_could_still_catch_up_over() {
        let window = u64::try_from(MAX_REORG_DEPTH).unwrap();
        assert!(
            MAX_BEHIND < window,
            "stopping at or past {window} is stopping after the blocks are already gone"
        );
        assert!(
            MAX_BEHIND.saturating_mul(2) <= window,
            "and there has to be room left over for an operator to act in"
        );
    }
}

/// The rules a node handed a ledger keeps itself to.
///
/// AUDIT: none of this existed. A node acted on an anchor the instant it
/// landed, never asked anybody for the blocks that were supposed to stand
/// behind it, and had no way of saying it had not got them.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod undertaking_tests {
    use super::{owed_this_round, Owed, Undertaking, BURIAL_PATIENCE, STRANDING_PATIENCE};

    fn taken(now: u64) -> Undertaking {
        Undertaking::resumed(100, 1_124, Some(100), now).unwrap()
    }

    /// A node that has already validated its way past the tip it was handed
    /// under owes nothing, which is what ends the probation across a restart.
    #[test]
    fn an_undertaking_already_met_is_not_resumed() {
        assert!(Undertaking::resumed(100, 1_124, Some(1_123), 0).is_some());
        assert!(Undertaking::resumed(100, 1_124, Some(1_124), 0).is_none());
        assert!(Undertaking::resumed(100, 1_124, Some(2_000), 0).is_none());
        assert!(
            Undertaking::resumed(100, 1_124, None, 0).is_none(),
            "and a node with no chain at all took no anchor"
        );
    }

    /// The first round asks. A node that has just adopted, or has just come
    /// back onto a ledger it was handed, has nothing to gain by sitting quiet
    /// first: the question is the only thing between it and being a node.
    #[test]
    fn the_blocks_above_the_anchor_are_asked_for_at_once_and_then_again() {
        let mut held = taken(1_000);
        assert!(matches!(
            owed_this_round(&mut held, 100, 1, STRANDING_PATIENCE, 1_000),
            Owed::AskAgain
        ));
        assert!(
            matches!(
                owed_this_round(&mut held, 100, 1, STRANDING_PATIENCE, 1_001),
                Owed::Waiting
            ),
            "and not again a second later"
        );
        assert!(
            matches!(
                owed_this_round(
                    &mut held,
                    100,
                    1,
                    STRANDING_PATIENCE,
                    1_000 + BURIAL_PATIENCE
                ),
                Owed::AskAgain
            ),
            "but the supplier does not get to be the only one ever asked"
        );
    }

    /// A node with nobody to ask is not stranded, it is disconnected, and the
    /// two have different cures.
    #[test]
    fn a_node_with_no_peers_is_neither_asked_nor_given_up_on() {
        let mut held = taken(1_000);
        assert!(matches!(
            owed_this_round(&mut held, 100, 0, 0, 1_000 + STRANDING_PATIENCE),
            Owed::Waiting
        ));
    }

    /// The clock runs on the chain moving, not on the node being up, so a
    /// node making any progress at all never reaches the end of the patience.
    #[test]
    fn a_chain_that_moves_starts_the_waiting_again() {
        let mut held = taken(1_000);
        let nearly = 1_000 + STRANDING_PATIENCE - 1;
        assert!(matches!(
            owed_this_round(&mut held, 400, 1, STRANDING_PATIENCE, nearly),
            Owed::Waiting
        ));
        assert!(
            matches!(
                owed_this_round(&mut held, 400, 1, STRANDING_PATIENCE, nearly + 1),
                Owed::AskAgain
            ),
            "one block arrived, so the hour is counted from there"
        );
    }

    /// Waiting stops being the answer. The node says so and stops, because
    /// what it holds is a ledger nothing is ever going to stand behind.
    #[test]
    fn a_node_that_never_gets_the_burial_says_so() {
        let mut held = taken(1_000);
        let waited = 1_000 + STRANDING_PATIENCE;
        assert!(matches!(
            owed_this_round(&mut held, 100, 1, STRANDING_PATIENCE, waited - 1),
            Owed::AskAgain | Owed::Waiting
        ));
        let Owed::GivenUp(stranded) =
            owed_this_round(&mut held, 100, 1, STRANDING_PATIENCE, waited)
        else {
            panic!("an hour of nothing, with peers to ask, is not something to wait out");
        };
        assert_eq!(stranded.anchor, 100);
        assert_eq!(stranded.settles_at, 1_124);
        assert_eq!(stranded.waited, STRANDING_PATIENCE);
    }

    /// A clock put right is not evidence about anything, least of all about
    /// how long this node has been waiting.
    #[test]
    fn a_clock_that_went_backwards_starts_the_waiting_again() {
        let mut held = taken(1_000);
        assert!(matches!(
            owed_this_round(&mut held, 100, 1, 0, 900),
            Owed::Waiting
        ));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod quiet_tests {
    use super::{has_gone_quiet, JOIN_PATIENCE};

    #[test]
    fn a_join_is_given_up_on_only_once_it_has_gone_quiet() {
        assert!(
            !has_gone_quiet(None, 1_000),
            "a node that is not joining has nothing to give up on"
        );
        assert!(!has_gone_quiet(Some(1_000), 1_000), "a piece just arrived");
        assert!(
            !has_gone_quiet(Some(1_000), 1_000 + JOIN_PATIENCE - 1),
            "still inside what a slow link is allowed"
        );
        assert!(
            has_gone_quiet(Some(1_000), 1_000 + JOIN_PATIENCE),
            "nothing arrived for as long as this waits"
        );
        assert!(
            has_gone_quiet(Some(1_000), 900),
            "a clock that went backwards says how long it waited is worthless"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::net::Ipv4Addr;

    use cairn_store::HEADER_LOG;

    use cairn_ledger::note::Note;
    use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
    use cairn_ledger::validation::{assemble_block, connect_block, mine_block};
    use cairn_ledger::LedgerState;

    use super::*;

    fn address(last: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, last), 9_000))
    }

    /// A port the operating system picks, which is what every other test that
    /// starts a node asks for.
    ///
    /// The one test here that really binds used to name port 9000, and two
    /// tests wanting one port is one of them failing: under the parallel suite
    /// it panicked with `AddrInUse`, from a bind that has nothing to do with
    /// what it is about. The addresses above are still fixed, because nothing
    /// binds them: they are two peers being compared with each other.
    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    /// A branch replaced at the same length is replaced in the forest.
    ///
    /// Two miners each finding a block at the same height is the ordinary way
    /// a branch is replaced, and it replaces headers without shortening the
    /// log. The note inside `grow_forest` says so, and no forest here was ever
    /// grown from a log that did it: every one only got longer or shorter. So
    /// a walk that never looked back passed, as did one that stopped at the
    /// first leaf it held whatever that leaf was, and one that found where the
    /// two part and then cut nothing. Each leaves the forest proving headers
    /// the chain no longer has.
    #[test]
    fn a_branch_replaced_at_the_same_length_is_replaced_in_the_forest() {
        let directory =
            std::env::temp_dir().join(format!("cairn-same-length-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut headers = HeaderLog::open(&directory).unwrap();
        let mut forest = HeaderTree::open(&directory).unwrap();

        let first = linked_headers(5, ConsensusParams::testnet().network);
        for header in &first {
            headers.append(header).unwrap();
        }
        assert!(grow_forest(&mut forest, &headers).is_none());
        assert_eq!(forest.len(), 5);

        // The same three, then another fourth and fifth.
        let mut second = first[..3].to_vec();
        for replaced in &first[3..] {
            let previous = second.last().unwrap().id();
            second.push(BlockHeader {
                previous,
                nonce: replaced.nonce + 100,
                ..*replaced
            });
        }
        headers.keep_below(3).unwrap();
        for header in &second[3..] {
            headers.append(header).unwrap();
        }
        assert_eq!(headers.reaches(), 5, "the log is exactly as long as it was");

        assert!(grow_forest(&mut forest, &headers).is_none());
        assert_eq!(forest.len(), 5);
        for header in &second {
            assert_eq!(
                forest.leaf_at(header.height).unwrap(),
                Some(header_leaf(&header.id())),
                "the leaf at {} is the header the log holds there",
                header.height
            );
        }
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A report of unwritten blocks names the costlier refusal, and between two
    /// of one cost the words the disk says now.
    ///
    /// The ledger fails once a second on a full disk, and the report it would
    /// otherwise replace is the one about blocks not reaching the disk at all.
    /// No test reached the choice between them: the audits that fill a disk
    /// run with no budget, so the ledger is never written, and a report that
    /// let the cheapest refusal speak over the dearest passed them all.
    #[test]
    fn the_costlier_refusal_is_the_one_said() {
        let standing = |what, because: &str| Unwritten {
            what,
            because: because.to_owned(),
            reached: 40,
            written_through: Some(20),
            blocks: 19,
            within_reach: true,
        };
        let fresh = |what, because: &str| Refusing {
            what,
            because: because.to_owned(),
        };

        let said = the_refusal_to_say(
            Some(&fresh(Writing::Ledger, "no space left on device")),
            Some(&standing(Writing::Blocks, "no space left on device")),
        );
        assert_eq!(
            said.map(|(what, _)| what),
            Some(Writing::Blocks),
            "the ledger does not speak over blocks that are being lost"
        );

        let said = the_refusal_to_say(
            Some(&fresh(Writing::Blocks, "input/output error")),
            Some(&standing(Writing::Headers, "no space left on device")),
        );
        assert_eq!(
            said,
            Some((Writing::Blocks, "input/output error".to_owned())),
            "and blocks speak over anything cheaper"
        );

        let said = the_refusal_to_say(
            Some(&fresh(Writing::Blocks, "input/output error")),
            Some(&standing(Writing::Blocks, "no space left on device")),
        );
        assert_eq!(
            said,
            Some((Writing::Blocks, "input/output error".to_owned())),
            "between two of one cost the disk's words now are the ones said"
        );

        assert_eq!(
            the_refusal_to_say(None, Some(&standing(Writing::Headers, "gone"))),
            Some((Writing::Headers, "gone".to_owned())),
            "a pass that met nothing leaves what opened the gap standing"
        );
        assert_eq!(the_refusal_to_say(None, None), None);
    }

    /// The table of address marks lets go of the ones nothing counts for.
    ///
    /// Each address a connection arrives from leaves a mark, and the table of
    /// them is fed by strangers. A pass that dropped none passed everything
    /// here, which is a table that grows by one row per address until it is
    /// full and every newcomer shares the one crowded allowance.
    #[test]
    fn marks_nothing_counts_for_are_let_go_of() {
        let node = Node::bind(ConsensusParams::testnet(), loopback()).unwrap();
        let live = IpAddr::from([203, 0, 113, 1]);
        let gone = IpAddr::from([203, 0, 113, 2]);
        let connection = node.shared.allowance_for(Some(live));
        drop(node.shared.allowance_for(Some(gone)));

        node.shared.forget_spent_windows(1_000_000);
        {
            let windows = node
                .shared
                .windows
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            assert!(
                windows.contains_key(&live),
                "a live connection keeps its mark"
            );
            assert!(
                !windows.contains_key(&gone),
                "an address that left and whose window is over is let go of"
            );
        }
        drop(connection);
    }

    /// A node with no seed looks its names up, and waits its period before
    /// looking again.
    ///
    /// This is the only way a node that could resolve nothing at start comes
    /// to know of anybody, and nothing ran it: looking up every round passed,
    /// as did never looking up again after a lookup, looking one second
    /// early, and waiting one second past the period.
    #[test]
    fn a_node_with_no_seed_looks_its_names_up_and_not_too_often() {
        let node = Node::bind(ConsensusParams::testnet(), loopback()).unwrap();
        // The last lookup is put in 2096 before there is a name to look up,
        // so the node's own rounds, on today's clock, never find one due.
        let last = 4_000_000_000;
        node.shared
            .names_looked_up_at
            .store(last, Ordering::Relaxed);
        // An address for documentation, which resolves without asking anyone.
        node.shared.seed_names().push("192.0.2.7:9944".to_owned());

        look_up_seed_names(&node.shared, last + NAME_LOOKUP_PERIOD - 1);
        assert!(
            !node.shared.book().has_seeds(),
            "a lookup a second before its period was taken"
        );
        look_up_seed_names(&node.shared, last + NAME_LOOKUP_PERIOD);
        assert!(
            node.shared.book().has_seeds(),
            "and the one its period allows was not"
        );
    }

    /// The threads of peers that have gone are collected.
    ///
    /// One handle per peer that ever connected, kept for the life of the
    /// process unless this runs, and nothing ran it: a pass that collected
    /// nothing passed, which is a leak fed by anybody who connects and hangs
    /// up.
    #[test]
    fn the_threads_of_peers_that_have_gone_are_collected() {
        let node = Node::bind(ConsensusParams::testnet(), loopback()).unwrap();
        let before = node.shared.threads().len();
        let handles: Vec<_> = (0..3).map(|_| std::thread::spawn(|| {})).collect();
        while !handles.iter().all(JoinHandle::is_finished) {
            std::thread::yield_now();
        }
        node.shared.threads().extend(handles);

        collect_finished(&node.shared);
        assert!(
            node.shared.threads().len() <= before,
            "three finished threads were left holding their handles"
        );
    }

    /// One address gets its share of connections and no more, and other
    /// addresses do not count against it.
    #[test]
    fn an_address_gets_its_share_of_connections_and_no_more() {
        let one = IpAddr::from([203, 0, 113, 1]);
        let other = IpAddr::from([203, 0, 113, 2]);
        let held = |from_one: usize| {
            std::iter::repeat_n(Some(one), from_one)
                .chain(std::iter::repeat_n(Some(other), MAX_PER_HOST))
                .chain(std::iter::once(None))
        };
        assert!(
            room_beside(held(MAX_PER_HOST - 1), one),
            "one short of its share, and every other address full, is room for one"
        );
        assert!(
            !room_beside(held(MAX_PER_HOST), one),
            "a whole share is no room"
        );
        assert!(
            room_beside(held(MAX_PER_HOST), IpAddr::from([198, 51, 100, 4])),
            "and an address holding nothing has room whatever the others hold"
        );
    }

    /// A short valid chain, built off to the side.
    fn chain_of(count: usize, params: ConsensusParams) -> Vec<Block> {
        let miner = cairn_crypto::SecretKey::from_bytes(&[7; 32]);
        let mut state = LedgerState::new();
        let mut clock = 1_000u64;
        (0..count)
            .map(|_| {
                let height = state.next_height().unwrap();
                clock = clock.saturating_add(600);
                let coinbase = CoinbaseTransaction::new(
                    height,
                    vec![Note::new(params.initial_reward, miner.public_key())],
                );
                let block =
                    assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                        .unwrap();
                let block = mine_block(block, 1 << 22).unwrap();
                connect_block(&mut state, &block, &params, clock).unwrap();
                block
            })
            .collect()
    }

    /// A chain of headers with nothing mined, for filling a header log.
    ///
    /// Nothing at this layer weighs work: the header log checks that each
    /// record sits at its own height and links to its neighbour, and that is
    /// all these have to satisfy. Mining five hundred and twelve blocks to
    /// count reads would be minutes spent on the one thing the count does not
    /// depend on.
    fn linked_headers(count: u64, network: NetworkId) -> Vec<BlockHeader> {
        let mut previous = Hash32::ZERO;
        (0..count)
            .map(|height| {
                let header = BlockHeader {
                    version: BLOCK_VERSION,
                    network,
                    height,
                    previous,
                    transactions_root: Hash32::from_bytes([7; 32]),
                    state_root: Hash32::from_bytes([9; 32]),
                    history: Hash32::from_bytes([11; 32]),
                    timestamp: 1_000_000_u64.saturating_add(height.saturating_mul(600)),
                    difficulty: 1,
                    total_work: u128::from(height),
                    nonce: height,
                };
                previous = header.id();
                header
            })
            .collect()
    }

    /// How many reads one take of the disk answers for, which is what every
    /// other thread waits out.
    ///
    /// There is one lock over the whole log, and `Shared::persist` takes it
    /// with the chain already in hand. So a thread that has just validated a
    /// block waits on the log holding the chain, and every thread that wants
    /// the chain waits behind that one. A stranger asking for `MAX_HEADERS`
    /// used to hold the log for all five hundred and twelve reads: measured on
    /// this machine, 1.2 ms with the file in the page cache and 33 to 170 ms
    /// without it, and one address may buy sixteen of those runs per allowance
    /// window.
    ///
    /// A host this node is refusing is refused whichever door it comes to.
    ///
    /// Three ways reach the peer table: the accept loop, the dial round of
    /// upkeep, and `Node::connect`. The first two ask the refusal table. The
    /// third asked the ceiling and the running flag and not that, under a doc
    /// saying it was "the one that consulted neither" — mended for two of the
    /// three and left short on the one about a host's conduct.
    ///
    /// The case that makes it a defect rather than an omission is
    /// `reach_for_an_archivist`, whose own doc calls itself "an ordinary dial
    /// made a few seconds early rather than a second way of choosing who this
    /// node talks to". The ordinary dial asks; without this it did not, so it
    /// was the second way it says it is not, for up to `REACH_FOR_ARCHIVISTS`
    /// hosts a round, and reached for exactly when a node is short of peers
    /// and least able to afford a bad one.
    ///
    /// Both directions, because a refusal that turned everybody away would be
    /// a node that cannot dial at all.
    #[test]
    fn a_refused_host_is_turned_away_at_every_door_into_the_peer_table() {
        let params = ConsensusParams::testnet();
        let listening = Node::bind(params, loopback()).unwrap();
        let dialling = Node::bind(params, loopback()).unwrap();

        // An ordinary dial first, so what follows is the refusal and not the
        // fixture. The loopback is never refused and the reason is written
        // beside `can_be_refused`, which is why the refused host below is a
        // documentation address instead.
        dialling
            .connect(listening.address())
            .expect("an ordinary host is dialled");

        let elsewhere = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 9_944);
        dialling.shared.refuse(elsewhere.ip(), unix_now());
        assert!(
            dialling.shared.refuses(elsewhere.ip(), unix_now()),
            "the fixture has to have refused it, or the assertion below is empty"
        );

        // `NotKept` and not an I/O error is the whole assertion. Nothing is
        // listening at a documentation address, so a dial would have come back
        // as a connection failure; coming back named means the question was
        // asked before the socket was spent.
        let turned_away = dialling.connect(elsewhere);
        assert!(
            matches!(
                &turned_away,
                Err(NodeError::NotKept { because, .. }) if because.contains("refusing that host")
            ),
            "a host this node is refusing was let in through the third door, or was \
             refused only after a dial was spent on it: {turned_away:?}"
        );

        listening.shutdown();
        dialling.shutdown();
    }

    /// Counted rather than timed, on purpose. Two wall clocks read at
    /// different moments is what four tests here have had to be repaired for,
    /// and the number that is the finding is how many reads one hold answers
    /// for. That is arithmetic.
    #[test]
    fn one_take_of_the_disk_answers_for_a_bounded_run_of_headers() {
        let params = ConsensusParams::testnet();
        let directory = std::env::temp_dir().join(format!("cairn-hold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let (node, _) = Node::open(params, loopback(), &directory).unwrap();

        let run = u64::try_from(MAX_HEADERS).unwrap();
        {
            let mut log = node
                .shared
                .log
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let store = log.as_mut().unwrap();
            for header in linked_headers(run + 8, params.network) {
                store.headers.append(&header).unwrap();
            }
        }

        let (under_one, more) = node.shared.headers_under_one_hold(0, run);
        assert_eq!(
            u64::try_from(under_one.len()).unwrap(),
            READS_PER_HOLD,
            "one take of the log answered for {} reads, and a peer may ask for {run}",
            under_one.len()
        );
        assert!(more, "and says the run goes on rather than ending there");

        let whole = node.shared.headers_from(0, run);
        assert_eq!(
            whole.len(),
            MAX_HEADERS,
            "the peer still gets the whole run it asked for"
        );
        for (at, header) in whole.iter().enumerate() {
            assert_eq!(
                header.height,
                u64::try_from(at).unwrap(),
                "the run came back in order"
            );
        }

        drop(node);
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The same for blocks, where the take bounds the chain as well as the log.
    ///
    /// A block is anything up to `max_block_bytes` rather than the fixed
    /// hundred and eighty two bytes of a header, and the memory pass clones
    /// what it finds. `MAX_REQUESTED` of them is sixteen megabytes copied with
    /// the chain held, which is not the disk waiting on the disk: it is every
    /// thread that wants the chain waiting on one that is answering a
    /// stranger.
    #[test]
    fn one_take_of_the_disk_answers_for_a_bounded_run_of_blocks() {
        let params = ConsensusParams::testnet();
        let blocks = chain_of(BLOCKS_PER_HOLD * 3, params);
        let node = Node::bind(params, loopback()).unwrap();
        {
            let mut chain = node.shared.chain();
            for block in &blocks {
                chain.add_block(block.clone(), 2_000_000_000).unwrap();
            }
        }

        let heights: Vec<u64> = (0..u64::try_from(blocks.len()).unwrap()).collect();
        let under_one = node.shared.blocks_under_one_hold(&heights);
        assert_eq!(
            under_one.len(),
            BLOCKS_PER_HOLD,
            "one take answered for {} blocks, and a peer may name {} heights",
            under_one.len(),
            heights.len()
        );

        let whole = node.shared.blocks_at(&heights);
        assert_eq!(
            whole.len(),
            blocks.len(),
            "the peer still gets every block it named"
        );
        for (at, block) in whole.iter().enumerate() {
            assert_eq!(
                block.header.height,
                u64::try_from(at).unwrap(),
                "and gets them in the order it named them"
            );
        }
    }

    /// A run whose halves came off different branches is refused whole.
    ///
    /// This is what several takes buys and one take did not have to think
    /// about. Between two of them the log can be rewritten by a
    /// reorganisation, and the two halves then belong to chains that never
    /// shared a tip. Serving that is worse than serving nothing: the far end
    /// cannot tell it from a chain this node stands behind.
    #[test]
    fn a_run_assembled_across_a_log_that_moved_is_refused_rather_than_torn() {
        let one = linked_headers(4, NetworkId::TESTNET);
        let other = linked_headers(4, NetworkId::MAINNET);
        let follows = |before: &BlockHeader, after: &BlockHeader| after.previous == before.id();

        let takes = std::cell::Cell::new(0_usize);
        let torn = gathered_a_few_at_a_time(
            4,
            2,
            |at, _| {
                takes.set(takes.get() + 1);
                let from = if at == 0 { &one } else { &other };
                (from.get(at..at + 2).unwrap().to_vec(), true)
            },
            follows,
        );
        assert_eq!(takes.get(), 2, "both takes ran");
        assert!(
            torn.is_empty(),
            "a run whose second half came off another branch was served whole, \
             {} headers of it, rather than refused",
            torn.len()
        );

        let takes = std::cell::Cell::new(0_usize);
        let whole = gathered_a_few_at_a_time(
            4,
            2,
            |at, _| {
                takes.set(takes.get() + 1);
                (one.get(at..at + 2).unwrap().to_vec(), true)
            },
            follows,
        );
        assert_eq!(takes.get(), 2, "the same two takes");
        assert_eq!(
            whole.len(),
            4,
            "and a run that did not move comes back whole"
        );
    }

    /// A log that never took the first block the chain holds starts at that
    /// block, and not at whichever block came next.
    ///
    /// Nothing asked this, so the rule for an empty log, start at the block
    /// just applied, wrote a log beginning partway up the chain whenever the
    /// first write had failed: the network's first block, appended when a
    /// node opens and never checked, or any first block a full disk refused.
    /// The next start read that log as a node that had joined above its own
    /// disk, set it aside as rejoining and cut every block in it.
    #[test]
    fn a_log_that_never_took_the_first_block_starts_at_the_first_block_held() {
        let params = ConsensusParams::testnet();
        let blocks = chain_of(6, params);

        let directory =
            std::env::temp_dir().join(format!("cairn-first-missed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let (blocks_log, _) = BlockLog::open(&directory).unwrap();
        let mut store = Store {
            blocks: blocks_log,
            headers: HeaderLog::open(&directory).unwrap(),
            forest: HeaderTree::open(&directory).unwrap(),
            filling: HeaderLog::open_named(&directory, FILLING_LOG).unwrap(),
            filling_epoch: 0,
        };

        // What a refused first write leaves: a chain of five and a log of
        // nothing at all.
        let mut chain = ChainStore::new(params);
        for block in &blocks[..5] {
            chain.add_block(block.clone(), 2_000_000_000).unwrap();
        }
        let accepted = chain.add_block(blocks[5].clone(), 2_000_000_000).unwrap();
        let wrote = write_branch(&mut store, &accepted, &chain);
        let _ = std::fs::remove_dir_all(&directory);

        assert!(wrote.refusing.is_none(), "nothing was refused");
        assert_eq!(
            (store.blocks.first_height(), store.blocks.len()),
            (0, 6),
            "a log that missed its first block was started partway up the chain"
        );
    }

    /// A log that fell behind is caught up, not written past.
    ///
    /// A write can fail: a full disk, a directory that went away. The chain
    /// carries on, because losing the log costs blocks on the next start and
    /// not the branch this node follows. What must not happen is the next
    /// block being appended anyway, landing at a position that is not its
    /// height. Every record after that would sit at the wrong height, and a
    /// node answering a newcomer by position would hand out the wrong blocks
    /// while believing it had answered.
    #[test]
    fn a_log_that_fell_behind_is_caught_up_rather_than_written_past() {
        let params = ConsensusParams::testnet();
        let blocks = chain_of(6, params);

        let directory = std::env::temp_dir().join(format!("cairn-behind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let (blocks_log, _) = BlockLog::open(&directory).unwrap();
        let mut store = Store {
            blocks: blocks_log,
            headers: HeaderLog::open(&directory).unwrap(),
            forest: HeaderTree::open(&directory).unwrap(),
            filling: HeaderLog::open_named(&directory, FILLING_LOG).unwrap(),
            filling_epoch: 0,
        };

        let mut chain = ChainStore::new(params);
        for block in &blocks[..5] {
            chain.add_block(block.clone(), 2_000_000_000).unwrap();
        }
        // What a failed write leaves: a chain of five, a log of two.
        store.blocks.append(&blocks[0]).unwrap();
        store.blocks.append(&blocks[1]).unwrap();

        let accepted = chain.add_block(blocks[5].clone(), 2_000_000_000).unwrap();
        assert_eq!(accepted, Accepted::Extended);
        let wrote = write_branch(&mut store, &accepted, &chain);
        assert!(wrote.refusing.is_none(), "nothing was refused");
        assert_eq!(wrote.reaches, 6, "and the log says how far it now reaches");

        assert_eq!(
            store.blocks.len(),
            6,
            "the log caught up rather than skipping ahead"
        );
        assert_eq!(store.headers.reaches(), 6, "and so did the headers");
        assert_eq!(store.forest.len(), 6, "and the forest they make");
        for (height, want) in blocks.iter().enumerate() {
            let at = u64::try_from(height).unwrap();
            let found = store.blocks.read_at(at).unwrap().unwrap();
            assert_eq!(found.id(), want.id(), "record {height} is not that height");
            let header = store.headers.read_at(at).unwrap().unwrap();
            assert_eq!(header.id(), want.id(), "header {height} is not that height");
        }

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A header merge that this node's own disk stops is not the supplier's
    /// doing, and used to be charged to it.
    ///
    /// A node that joined a chain fills in the headers from before it arrived
    /// from one peer at a time. The run is weighed against the commitment the
    /// oldest header it holds already carries, so by the time the two logs are
    /// joined the run is known to be the truth. Every way the join could fail
    /// from there is this node's own disk, and all of them came back as the
    /// same bare `false`, which the caller read as a collection that did not
    /// add up: the supplier lost its turn, the next peer was asked for the
    /// whole run again, and it lost its turn the same way. On a chain of any
    /// age that run is the entire history before the node arrived, so the node
    /// paid for its own disk in somebody else's bandwidth, round the whole
    /// book, for as long as it ran, while the line its operator was shown said
    /// to find it a peer that held the missing part.
    #[test]
    fn a_merge_this_node_s_own_disk_stopped_costs_the_supplier_nothing() {
        let params = ConsensusParams::testnet();
        let blocks = chain_of(30, params);
        let oldest = 20u64;
        // Far enough above `oldest` that reading the anchor still works: a
        // spoiled record breaks the link with the one after it, and nothing
        // else.
        let spoiled = 25u64;

        let directory = std::env::temp_dir().join(format!("cairn-merge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let (blocks_log, _) = BlockLog::open(&directory).unwrap();
        let mut headers = HeaderLog::open(&directory).unwrap();
        let mut filling = HeaderLog::open_named(&directory, FILLING_LOG).unwrap();
        // What a node that joined at `oldest` holds: its own headers from
        // there up, and a run of everything before it that is one short.
        for block in &blocks[usize::try_from(oldest).unwrap()..] {
            headers.append(&block.header).unwrap();
        }
        for block in &blocks[..usize::try_from(oldest).unwrap() - 1] {
            filling.append(&block.header).unwrap();
        }
        let store = Store {
            blocks: blocks_log,
            headers,
            forest: HeaderTree::open(&directory).unwrap(),
            filling,
            filling_epoch: 0,
        };

        // One byte inside a record this node wrote itself. Every byte is part
        // of the identifier the record after it names, so any of them breaks
        // the link, which is what the store refuses on.
        let path = directory.join(HEADER_LOG);
        let mut bytes = std::fs::read(&path).unwrap();
        let at = usize::try_from(spoiled - oldest).unwrap() * HEADER_BYTES + 40;
        bytes[at] ^= 0x20;
        std::fs::write(&path, &bytes).unwrap();

        let node = Node::start(
            params,
            loopback(),
            ChainStore::new(params),
            Some(store),
            AddressBook::new(),
            Some(directory.clone()),
            None,
            None,
            None,
        )
        .unwrap();
        // The turn a peer would be holding, put there rather than waited for:
        // what is on trial is what the answer costs it, not how it got one.
        *node.shared.filling_from() = Some(Turn {
            peer: 7,
            moved: 1_000,
            marked: 0,
            spoiled: false,
        });

        let last = blocks[usize::try_from(oldest).unwrap() - 1].header;
        node.shared
            .take_headers(7, oldest - 1, std::slice::from_ref(&last), 1_001);

        let turn = (*node.shared.filling_from()).unwrap();
        let unread = node.unread();
        let held = {
            let log = node
                .shared
                .log
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let store = log.as_ref().unwrap();
            (store.headers.first_height(), store.headers.reaches())
        };
        node.shutdown();
        drop(node);
        let _ = std::fs::remove_dir_all(&directory);

        assert!(
            !turn.spoiled,
            "the peer sent a run that checked out against the commitment and was \
             charged for this node's disk"
        );
        let unread = unread.expect("and nothing anywhere said what had happened");
        assert_eq!(unread.what, Reading::Headers);
        // Either of the pair. A header answers for the link with the one
        // beside it, so a record with a changed byte refuses at its own height
        // and at the one below, and the walk meets the lower of the two first.
        assert!(
            unread.height == spoiled || unread.height == spoiled - 1,
            "it named {}, and the spoiled record is at {spoiled}",
            unread.height
        );
        assert_eq!(
            held,
            (oldest, 30),
            "and nothing was written, because every read happens before the \
             clear that empties the log"
        );
    }

    /// A laptop closed for a night is the case this exists for: the thread
    /// below stops with the machine, and the seconds it missed are the only
    /// trace left of the time it was not on the network."""
    #[test]
    fn a_long_gap_between_rounds_means_the_machine_was_away() {
        assert!(!was_away(1_000, 1_000), "no time passed at all");
        assert!(!was_away(1_000, 1_000 + AWAY_GAP - 1), "a busy machine");
        assert!(was_away(1_000, 1_000 + AWAY_GAP), "a machine that stopped");
        assert!(was_away(1_000, 1_000 + 30_000), "one that slept for hours");
        assert!(was_away(1_000, 900), "and a clock that was put right");
    }

    #[test]
    fn both_sides_of_a_double_connection_drop_the_same_one() {
        let lower = address(1);
        let higher = address(2);

        // The lower address keeps the connection it opened, so it drops the one
        // that came in; the higher address drops the one it opened. Those are
        // the same connection seen from its two ends.
        assert!(!loses_the_tie(lower, higher, true));
        assert!(loses_the_tie(lower, higher, false));

        assert!(loses_the_tie(higher, lower, true));
        assert!(!loses_the_tie(higher, lower, false));
    }

    #[test]
    fn exactly_one_of_the_two_connections_is_dropped() {
        let lower = address(1);
        let higher = address(2);
        // What each node decides about each of its two connections.
        let dropped = [
            loses_the_tie(lower, higher, true),
            loses_the_tie(higher, lower, false),
        ];
        assert_eq!(dropped.iter().filter(|verdict| **verdict).count(), 0);

        let other = [
            loses_the_tie(lower, higher, false),
            loses_the_tie(higher, lower, true),
        ];
        assert_eq!(
            other.iter().filter(|verdict| **verdict).count(),
            2,
            "both ends agree"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod trimming {
    use super::cut_for;

    /// What the budget buys, which is other people: a peer a little behind
    /// reads blocks here rather than being handed a whole ledger.
    #[test]
    fn a_budget_keeps_roughly_what_it_pays_for() {
        // Ten thousand blocks of a hundred thousand bytes, and a budget for a
        // fifth of them.
        let cut = cut_for(10_000, 10_000, 10_000 * 100_000, 2_000 * 100_000);
        assert_eq!(cut, 8_001, "the newest two thousand are kept");
    }

    /// The defect this replaced. The ledger stands for the tip, so cutting
    /// below the ledger cut below the tip, which is everything: a node kept
    /// nothing on disk however large its budget, and could answer nobody who
    /// was behind.
    #[test]
    fn a_large_budget_drops_nothing() {
        assert_eq!(cut_for(500, 500, 500 * 100_000, u64::MAX), 0);
    }

    /// An empty log has no average to take, and must not divide by it.
    #[test]
    fn nothing_held_is_not_a_division_by_nothing() {
        assert_eq!(cut_for(0, 0, 0, 1_000), 0);
    }
}

/// What one peer can have waiting for it.
///
/// Counted rather than timed, because what the ceiling does is decide how many
/// messages of a given size go into a queue, and that is arithmetic. Timing it
/// would measure a socket buffer, which is a fact about the machine.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod what_a_queue_holds {
    use super::{mpsc, Message, Outbound, OUTBOUND_QUEUE, OUTBOUND_QUEUE_BYTES};
    use crate::message::Joining;
    use cairn_primitives::Hash32;

    /// A join part, which is the largest thing this node builds for a peer
    /// and behaves on this queue exactly as a block does.
    fn weighing(bytes: usize) -> Message {
        Message::JoinPart {
            what: Joining::Ledger,
            at: Hash32::ZERO,
            part: 0,
            parts: 1,
            bytes: vec![0u8; bytes],
        }
    }

    /// Messages accepted before the queue refuses, and the bytes they came to.
    fn accepted(each: usize) -> (usize, usize) {
        let (sender, inbox) = mpsc::sync_channel(OUTBOUND_QUEUE);
        let outbound = Outbound::new(sender);
        let mut taken = 0usize;
        while outbound.try_send(weighing(each)).is_ok() {
            taken = taken.saturating_add(1);
        }
        let held = outbound.queued();
        drop(inbox);
        (taken, held)
    }

    /// The bound that was there counts messages, and a message on this wire is
    /// nine bytes or half a megabyte.
    #[test]
    fn a_queue_is_bounded_in_bytes_and_not_only_in_messages() {
        let block = 128 * 1024;
        let (blocks, held) = accepted(block);
        assert!(
            held <= OUTBOUND_QUEUE_BYTES,
            "{held} bytes queued against a ceiling of {OUTBOUND_QUEUE_BYTES}"
        );
        assert!(
            blocks < OUTBOUND_QUEUE,
            "{blocks} messages of {block} bytes went into one peer's queue, and the \
             only bound was {OUTBOUND_QUEUE} messages: two `GetBlocks` for \
             MAX_REQUESTED heights each put {OUTBOUND_QUEUE} blocks in it, which is \
             {} bytes on one connection",
            OUTBOUND_QUEUE.saturating_mul(block),
        );

        // And the message bound still does the work it was there for, since
        // ten thousand nine-byte answers are not a memory problem.
        let (small, _) = accepted(0);
        assert_eq!(
            small, OUTBOUND_QUEUE,
            "small messages are still bounded by the count and nothing else"
        );
    }

    /// A message larger than the whole ceiling would never go out at all, so
    /// the ceiling has to be above the largest thing this node sends. Held at
    /// the point the numbers are written rather than at the point a test runs.
    const _: () = assert!(crate::message::JOIN_PART_BYTES < OUTBOUND_QUEUE_BYTES);
    const _: () = assert!(crate::wire::MAX_FRAME_BYTES < OUTBOUND_QUEUE_BYTES);

    #[test]
    fn the_largest_message_still_fits() {
        let (parts, _) = accepted(crate::message::JOIN_PART_BYTES);
        assert!(parts >= 1, "one join part goes into an empty queue");
    }
}

/// The count of showings that would not weigh, and the rule for which
/// address marks are worth keeping.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unweighed_tests {
    use super::{count_unweighed, still_counted, Unweighed, Window, UNWEIGHED_SENDERS};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    fn address(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), 9_944)
    }

    /// The same words from anybody add up, other words start again, and so
    /// does a clock that stepped back.
    ///
    /// The same count as the two beside it, and the one left inside `Shared`,
    /// so nothing could reach it: a count that never started again passed, as
    /// did one that started again only when both the words and the clock
    /// changed, one that started again whenever two showings came in the same
    /// second, and a cap on peers one past the cap.
    #[test]
    fn the_same_refusal_adds_up_and_a_different_one_starts_again() {
        let mut met = Unweighed::default();
        count_unweighed(&mut met, Some(address(1)), "no path", 1_000);
        count_unweighed(&mut met, Some(address(2)), "no path", 1_000);
        assert_eq!(met.showings, 2, "two in one second are two");

        count_unweighed(
            &mut met,
            Some(address(3)),
            "a root that does not fold",
            1_010,
        );
        assert_eq!(
            (met.showings, met.first, met.peers.len()),
            (1, 1_010, 1),
            "other words are another question"
        );
        assert_eq!(met.because, "a root that does not fold");

        count_unweighed(&mut met, Some(address(4)), "a root that does not fold", 900);
        assert_eq!(
            (met.showings, met.first),
            (1, 900),
            "and a clock that stepped back starts it again"
        );

        let mut crowd = Unweighed::default();
        for peer in 0..=UNWEIGHED_SENDERS {
            count_unweighed(
                &mut crowd,
                Some(address(u8::try_from(peer).unwrap())),
                "no path",
                1_000,
            );
        }
        assert_eq!(crowd.peers.len(), UNWEIGHED_SENDERS, "kept up to the cap");
    }

    /// A mark is kept while something holds it or while its window lasts, and
    /// dropped once neither is true.
    ///
    /// Held by nothing: keeping every mark forever passed, as did dropping one
    /// a live connection was still counting against, which is the refill by
    /// hanging up that the marks exist to stop.
    #[test]
    fn a_mark_is_kept_while_it_counts_for_something() {
        let held = Arc::new(Mutex::new(Window::default()));
        let connection = Arc::clone(&held);
        assert!(
            still_counted(&held, 100),
            "a live connection still counts against it"
        );
        drop(connection);

        let alone = Arc::new(Mutex::new(Window::default()));
        assert!(still_counted(&alone, 5), "its window is the current one");
        assert!(
            !still_counted(&alone, 100),
            "nobody holds it and its window is over"
        );
    }
}

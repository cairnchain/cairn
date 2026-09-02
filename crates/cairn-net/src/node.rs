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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cairn_accumulator::forest::{Forest, ForestProof};
use cairn_chain::{Accepted, Bodies, ChainError, ChainStore, Located, Outdated, MAX_REORG_DEPTH};
use cairn_crypto::PublicKey;
use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::genesis;
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::NetworkId;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::sampling::{check_start, open_start, SampledStart, SAMPLES};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::Transfer;
use cairn_ledger::validation::ConsensusParams;
use cairn_ledger::validation::TransferError;
use cairn_ledger::LedgerState;
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Hash32;
use cairn_store::{BlockLog, DirectoryLock, HeaderLog, HeaderTree, StoreError, HANDED_LEDGER};

use crate::book::AddressBook;
use crate::choosing::{self, Approach, Chooser, JoinProgress};
use crate::joining::{Collecting, Joined, Progress};
use crate::message::{
    Joining, Keeps, Message, Placed, JOIN_PART_BYTES, MAX_CHAIN, MAX_HEADERS, MAX_PROVEN,
    MAX_SHARED_ADDRESSES,
};
use crate::refusal::{can_be_refused, Refusals};
use crate::sync::{
    a_window_has_turned, local_handshake, on_message, Allowance, Local, PeerState, Reaction, Window,
};
use crate::wire::{read_message, write_message, Incoming, WireError};

/// Connections a node dials for itself.
pub const TARGET_PEERS: usize = 8;

/// Connections a node holds at once, dialled and accepted together.
///
/// Without a ceiling, anyone can open connections until the node runs out of
/// threads. Each one costs two threads and a read buffer, so the ceiling is
/// what turns an unbounded cost into a known one.
pub const MAX_PEERS: usize = 48;

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
/// adding one before another peer is asked instead.
const HEADER_PATIENCE: u64 = 30;

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

/// Connections those blocks have to have arrived on.
///
/// Two rather than one, because one peer is one machine and one machine is
/// what a stranger has. It is not proof either: whoever holds several
/// addresses holds several connections. It is the cheapest condition that
/// makes the claim cost more than a single message.
const UNJUDGED_PEERS: usize = 2;

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

/// Connections counted towards [`UNJUDGED_PEERS`] at once.
///
/// The table is fed by whoever connects, so it needs a ceiling like every
/// other table here. What is being asked of it is whether more than one peer
/// is involved, and this is far above the number that settles that.
const UNJUDGED_SENDERS: usize = 64;

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
    #[error("could not reach the block log: {0}")]
    Store(#[from] StoreError),
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
    /// Two things end a replay. A block that no longer applies, which means
    /// the file changed underneath the node or the rules did. And a block that
    /// applies but does not extend the branch, which means the log is not the
    /// followed branch in order of height: a log written before that was the
    /// rule, or one left mid reorganisation by a machine that stopped.
    ///
    /// Neither loses anything but time. What was cut is asked for again, and
    /// a node that was following the heaviest branch still is.
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
    /// bytes are still on the disk to be looked at, and a node that read them
    /// wrongly once can read them again.
    pub unreadable: Option<usize>,
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
    /// False once the gap has passed [`MAX_BEHIND`], and false for good. The
    /// blocks in it are no longer anywhere this node can read them from, so
    /// nothing an operator does now puts them on the disk; what is left is a
    /// node that stops, and a directory that is still worth starting from
    /// because it stopped falling further behind.
    pub within_reach: bool,
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

type PeerId = u64;

/// One live connection, as the rest of the node sees it.
struct Peer {
    outbound: SyncSender<Message>,
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
    /// The peer this node is filling its old headers in from, and when that
    /// peer last added one.
    ///
    /// One peer at a time, and only that peer's runs are taken. There is a
    /// single collection and anybody may send headers, so before this a
    /// stranger's one junk header fixed where the collection started, every
    /// honest run after it was dropped for starting somewhere else, and the
    /// whole thing was thrown away at the commitment check. That could be
    /// repeated for the price of one message, which is a joined node that can
    /// never fill in its headers and so can never show the chain to anybody.
    /// The same defect [`join_piece`] was fixed for, in the other collection.
    filling_from: Mutex<Option<(PeerId, u64)>>,
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
    /// Blocks this build turned out not to be able to read, and who sent them.
    ///
    /// Also a leaf, and for the same reason: it is written from the thread
    /// reading a peer, which has just let go of the chain.
    unjudged: Mutex<Unreadable>,
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

/// The account of one question about where fallen notes sit.
///
/// Taken from the collection rather than kept alongside it, so there is one
/// record of what happened and not two that can disagree.
fn finished(asking: &Asking, archivists: usize) -> Recovered {
    Recovered {
        asked: asking.asked.len(),
        archivists,
        answered: asking.answered.len(),
        proofs: asking.found.clone(),
        refused: asking.refused,
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
    /// The connections they arrived on, up to [`UNJUDGED_SENDERS`].
    peers: HashSet<PeerId>,
    /// When the first arrived, and when the last did.
    first: u64,
    last: u64,
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
    // arriving, so it says nothing at all rather than a negative stretch. The
    // same reading `owed_this_round` takes of one.
    if met.last < met.first {
        return None;
    }
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

impl Shared {
    /// A poisoned lock means a thread panicked while holding it. The release
    /// profile aborts on panic, so this cannot happen there; in a debug build
    /// carrying on with the data is more useful than a second panic.
    fn chain(&self) -> MutexGuard<'_, ChainStore> {
        self.chain.lock().unwrap_or_else(PoisonError::into_inner)
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
        windows.retain(|_, window| {
            Arc::strong_count(window) > 1
                || window
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .current(now)
        });
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
        let from_host = peers
            .values()
            .filter(|peer| peer.host == Some(host))
            .count();
        from_host < MAX_PER_HOST
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

    fn filling_from(&self) -> MutexGuard<'_, Option<(PeerId, u64)>> {
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
        let (what, because) = match (wrote.refusing.as_ref(), held.as_ref()) {
            // The costlier of the two stands, for the reason in
            // [`Writing::costs`].
            (Some(fresh), Some(standing)) if standing.what.costs() > fresh.what.costs() => {
                (standing.what, standing.because.clone())
            }
            (Some(fresh), _) => (fresh.what, fresh.because.clone()),
            // A pass with nothing to write says nothing new about why the disk
            // stopped taking things, so what opened the gap still stands.
            (None, Some(standing)) => (standing.what, standing.because.clone()),
            // A gap with nothing anywhere to explain it, which is a log that
            // was already short when this node opened it. The next block
            // applied tries to fill it and finds out why it cannot; guessing
            // here would only put a made up sentence in front of an operator.
            (None, None) => return,
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

    /// Counts one block this build could not read, and who sent it.
    ///
    /// Nothing is held against the peer here or anywhere: it is carrying what
    /// its own chain carries, and this node is the one that cannot read it.
    fn cannot_judge(&self, from: PeerId, version: u16, now: u64) {
        let mut met = self.unjudged.lock().unwrap_or_else(PoisonError::into_inner);
        // A stretch with none of these in it ends the count. A chain whose
        // rules moved on renews its own evidence every block, so nothing that
        // matters is lost by forgetting; what is gained is that a stray one a
        // year ago never adds up to a claim about this build.
        let lapsed =
            met.blocks > 0 && (now < met.last || now.saturating_sub(met.last) > UNJUDGED_MEMORY);
        if lapsed {
            *met = Unreadable::default();
        }
        if met.blocks == 0 {
            met.first = now;
        }
        met.version = met.version.max(version);
        met.blocks = met.blocks.saturating_add(1);
        met.last = now;
        if met.peers.len() < UNJUDGED_SENDERS {
            met.peers.insert(from);
        }
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
    /// The ledger goes down first. A process that stops between the two leaves
    /// a log longer than it needed to be, which costs a slower start; the
    /// other order would leave a node with neither the blocks nor the ledger
    /// that replaces them.
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
    /// Called with no lock held, because saying what the disk refused takes
    /// the chain and then the log.
    fn keep_ledger(&self, bytes: &[u8]) -> bool {
        let Some(directory) = self.directory.as_ref() else {
            return false;
        };
        let target = directory.join(HANDED_LEDGER);
        let partial = directory.join(format!("{HANDED_LEDGER}.part"));
        if let Err(error) = std::fs::write(&partial, bytes) {
            self.note_refusal(Refusing::at(Writing::Ledger, &error));
            return false;
        }
        if let Err(error) = std::fs::rename(&partial, &target) {
            self.note_refusal(Refusing::at(Writing::Ledger, &error));
            return false;
        }
        true
    }

    /// How far this node's branch runs past the last position in `locator` it
    /// agrees with.
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

        let agreed = agreed.or_else(|| {
            let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
            let log = log.as_ref()?;
            locator.iter().find_map(|entry| {
                let block = log.blocks.read_at(entry.height).ok().flatten()?;
                (block.id() == entry.id).then_some(entry.height)
            })
        });

        let from = agreed.map_or(0, |height| height.saturating_add(1));
        (from, reaches.saturating_sub(from).min(max))
    }

    /// The blocks the followed branch carries at `heights`, in that order.
    ///
    /// Two passes, so neither lock is held over the other's work. Memory
    /// first, with the chain held for the length of a few clones and let go
    /// before any disk is touched; then the log, which holds the branch in
    /// order of height and answers for everything older.
    ///
    /// Order is the point. A peer catching up applies what arrives as it
    /// arrives, and a block whose parent has not landed is dropped, so a batch
    /// delivered out of order is a batch mostly thrown away.
    fn blocks_at(&self, heights: &[u64]) -> Vec<Block> {
        if heights.is_empty() {
            return Vec::new();
        }
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
                    *slot = log.blocks.read_at(*height).ok().flatten();
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
    fn broadcast(&self, except: Option<PeerId>, message: &Message) {
        for (id, peer) in self.peers().iter() {
            if Some(*id) == except {
                continue;
            }
            // A full queue and a gone peer are both left alone: the first
            // catches up by asking, and the second is already being cleared up
            // by the thread that was reading from it.
            let _ = peer.outbound.try_send(message.clone());
        }
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
fn open_the_chain(
    chain: &mut ChainStore,
    log: Option<&mut BlockLog>,
    params: ConsensusParams,
    now: u64,
) {
    // Only for a network that pins its first block. An unnamed one, which is
    // what tests use, starts from whatever it is given.
    if params.genesis.is_none() || !chain.is_empty() {
        return;
    }
    let Some(block) = genesis::block(params.network) else {
        return;
    };
    if chain.add_block(block.clone(), now).is_err() {
        return;
    }
    if let Some(log) = log {
        if log.is_empty() {
            let _ = log.append(&block);
        }
    }
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

    fn open_with(
        params: ConsensusParams,
        address: SocketAddr,
        directory: impl Into<PathBuf>,
        archiving: bool,
        owners: &[PublicKey],
    ) -> Result<(Self, Restored), NodeError> {
        let directory = directory.into();
        let lock = DirectoryLock::acquire(&directory)?;
        let (mut log, recovered) = BlockLog::open(&directory)?;

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
        // A node handed a ledger cannot read its way back to it, because the
        // blocks it holds build on a ledger it never applied. So it keeps the
        // ledger it was handed, and starts from that. Without it such a node
        // could only start while an archivist happened to be reachable, which
        // would tie every node that ever joined to the archive service staying
        // up for the rest of its life.
        let handed = read_handed_ledger(&directory, &params).and_then(
            |(state, recent, anchor, promised)| {
                chain.adopt(state, &recent).ok()?;
                Some((recent, anchor, promised))
            },
        );
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
        if !rejoining {
            for block in log.replay() {
                let Ok(block) = block else { break };
                // Already in the ledger this node started from.
                if block.header.height < start {
                    continue;
                }
                if !matches!(chain.add_block(block, now), Ok(Accepted::Extended)) {
                    break;
                }
                applied = applied.saturating_add(1);
            }
        }
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
        if refused > 0 || rejoining {
            log.keep_below(reached)?;
        }
        // Blocks the ledger already stands for, still on disk because this
        // node was stopped before it could drop them. Dropped now, so the
        // next start does not walk them again.
        if !rejoining && log.first_height() < start {
            log.keep_from(start)?;
        }

        // The network's first block, for a node that has nothing. After the
        // replay rather than before it: a chain that already holds the first
        // block turns the first record replayed into a duplicate, which is not
        // an extension, which ends the replay and sets aside everything this
        // node had.
        open_the_chain(&mut chain, Some(&mut log), params, now);

        // Headers are kept whatever happens to the blocks. A node updated from
        // a version that had no header log has an empty one and a chain, so it
        // is filled in from the blocks that are still there. Everything older
        // than those is gone, which costs this node the ability to answer a
        // newcomer about that stretch and nothing else.
        let mut headers = HeaderLog::open(&directory)?;
        catch_up_headers(&mut headers, &log)?;
        let mut forest = HeaderTree::open(&directory)?;
        // A refusal here is not lost by being dropped: nothing has been
        // started yet that could carry it, and the first block this node
        // applies runs the same pass again and reports what it finds.
        let _ = grow_forest(&mut forest, &headers);
        let mut filling = HeaderLog::open_named(&directory, FILLING_LOG)?;
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
        let restored = Restored {
            blocks: applied,
            refused,
            discarded_bytes: recovered.discarded_bytes,
            left_in_place: recovered.left_in_place,
            unreadable: recovered.unreadable,
            rejoining,
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
            unjudged: Mutex::new(Unreadable::default()),
            asking: Mutex::new(Asking::default()),
        });

        {
            // Chain first and log second, here as everywhere. A node started
            // with no directory has no log to write the first block to, which
            // is what `Node::bind` does and what tests use.
            let mut chain = shared.chain();
            let has_log = {
                let mut log = shared.log.lock().unwrap_or_else(PoisonError::into_inner);
                let blocks = log.as_mut().map(|store| &mut store.blocks);
                let present = blocks.is_some();
                open_the_chain(&mut chain, blocks, params, unix_now());
                present
            };
            // A chain with a log behind it may let go of the bodies it has
            // written; one without has nowhere to read them back from, so it
            // keeps every one it might still need.
            if has_log {
                chain.reads_bodies_from(Arc::new(FromLog(Arc::clone(&shared.log))));
            }
        }

        let accepting = Arc::clone(&shared);
        let accept = thread::spawn(move || accept_loop(&accepting, &listener));
        let keeping = Arc::clone(&shared);
        let maintain = thread::spawn(move || maintenance_loop(&keeping));
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

    /// Opens a connection to a peer, introduces this node, and remembers the
    /// address for next time.
    /// Dials one address and keeps the connection, if there is room for it.
    ///
    /// The address is remembered either way: it answered, which is more than
    /// most of the book can say, and the next round of upkeep can dial it when
    /// a slot comes free. What is not done is taking the connection past the
    /// ceiling or onto a node that has stopped: this is the third way into the
    /// peer table, after the accept loop and upkeep dialling, and it was the
    /// one that consulted neither.
    pub fn connect(&self, address: SocketAddr) -> Result<(), NodeError> {
        let stream = TcpStream::connect_timeout(&address, DIAL_TIMEOUT)?;
        self.shared.book().insert(address);
        if !self
            .shared
            .has_room_for(stream.peer_addr().ok().map(|at| at.ip()))
        {
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        attach_peer(&self.shared, stream, Some(address));
        Ok(())
    }

    pub fn peer_count(&self) -> usize {
        self.shared.peers().len()
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
        log.as_ref()?.blocks.read_at(height).ok().flatten()
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
            let peer = filling.map_or(0, |(peer, _)| peer);
            *filling = Some((peer, now));
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
                let asking = self.shared.asking();
                // Every place answered for, or everyone asked has answered and
                // there is nothing further to wait on.
                if asking.satisfied()
                    || (!asking.asked.is_empty() && asking.answered.len() >= asking.asked.len())
                {
                    return finished(&asking, archivists);
                }
            }
            if deadline.is_none_or(|end| Instant::now() >= end) {
                let asking = self.shared.asking();
                return finished(&asking, archivists);
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
fn join_piece(
    shared: &Arc<Shared>,
    from: PeerId,
    message: Message,
    outbound: &SyncSender<Message>,
) -> Taken {
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
/// Two things this node goes out and asks for: the pieces of a chain it is
/// joining, and the paths for notes it can no longer place. Both are answers
/// to a question this node asked, both belong to a collection it is keeping
/// rather than to any decision about the peer that sent them, and an answer
/// nobody asked for is dropped before it costs anything. That last part is
/// what makes it safe to take these before the chain has been near them.
fn collected(
    shared: &Arc<Shared>,
    from: PeerId,
    message: Message,
    outbound: &SyncSender<Message>,
) -> Taken {
    match join_piece(shared, from, message, outbound) {
        Taken::Other(Message::Proofs(placed)) => {
            shared.take_placed(from, &placed);
            Taken::Handled
        }
        other => other,
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
    let weighed = SampledStart::decode(whole).ok().and_then(|start| {
        let weighed = check_start(&start, SAMPLES, now, &shared.params).ok()?;
        Some((weighed, start.tip))
    });
    let mut joining = shared.joining();
    // The attempt may have been given up on while this was being weighed:
    // upkeep starts a fresh one when the chooser turns to somebody else, and
    // an answer to the old question must not be filed against the new one.
    if !matches!(*joining, Progress::Weighing(_)) {
        return None;
    }
    let Some((shown, tip)) = weighed else {
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
    let landed = Handover::decode(whole)
        .ok()
        .filter(|handover| handover.tip.id() == tip.id())
        .and_then(|handover| {
            let state = accept(&handover, &shared.params).ok()?;
            shared.chain().adopt(state, &handover.recent).ok()?;
            // What the anchor was taken on: the blocks between it and the tip
            // it names, which `accept` asks nothing about. Written down before
            // anything else, because from this moment the node is holding a
            // ledger nobody has stood behind and everything it does with it
            // has to know that.
            let anchor = handover.at.height;
            shared.undertake(
                anchor,
                settles_at(anchor, handover.tip.height, &shared.params),
                now,
            );
            // Kept only once it has been taken, so what is on disk is a ledger
            // this node checked and adopted rather than one it merely
            // received.
            shared.keep_ledger(whole);
            // The run of headers the ledger came with, written down. Without
            // them this node has no oldest header of its own, and so nothing
            // to check a filled-in run against: it would never be able to take
            // anyone in.
            shared.seed_headers(&handover.recent);
            Some(())
        });
    let mut joining = shared.joining();
    if landed.is_none() {
        return fail_attempt(&mut joining, shared, from, now);
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
#[derive(Debug)]
struct FromLog(Arc<Mutex<Option<Store>>>);

impl Bodies for FromLog {
    fn body(&self, height: u64) -> Option<Block> {
        let log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        log.as_ref()?.blocks.read_at(height).ok()?
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
}

/// What became of a run of headers offered to a node filling in what came
/// before it arrived.
enum Filled {
    /// Nothing this node could use, and nothing lost.
    Ignored,
    /// The collection grew, so whoever supplied it is answering.
    Grew,
    /// What was collected was thrown away, and has to be gathered again.
    Discarded,
}

/// A join answer, built once and handed out in pieces.
struct Prepared {
    what: Joining,
    at: Hash32,
    bytes: Vec<u8>,
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
        if let Some(piece) = self.held_join(what, part) {
            return Some(piece);
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

    /// One piece of the answer already held, when it is the answer to the
    /// question being asked.
    fn held_join(&self, what: Joining, part: u32) -> Option<Message> {
        let held = self.joined();
        let tip = self.chain().tip()?;
        let ready = held.get(what.slot())?.as_ref()?;
        if ready.at != tip {
            return None;
        }
        piece_of(ready, part)
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
        if let Ok(Some(header)) = store.headers.read_at(height) {
            return Some(header);
        }
        Some(store.blocks.read_at(height).ok()??.header)
    }

    /// Where a header sits in the forest a chain of `leaves` committed to.
    fn proof_off_disk(&self, height: u64, leaves: u64) -> Option<ForestProof> {
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        log.as_ref()?.forest.prove_in(height, leaves).ok()?
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
    /// first header into. A peer that stops adding to it loses its turn, and
    /// the next one along is asked, so a node surrounded by peers that cannot
    /// answer works through them rather than asking the same one for ever.
    fn asks_headers_of(&self, connected: &[PeerId], now: u64) -> Option<(PeerId, Message)> {
        // Nothing missing, nothing to do, and in particular no turn to pass
        // on: a node that has filled its headers in would otherwise throw away
        // an empty collection once a round for the rest of its life.
        let asking = self.wants_headers()?;
        let previous = *self.filling_from();
        let keeps_turn = previous.is_some_and(|(peer, moved)| {
            connected.contains(&peer) && now.saturating_sub(moved) < HEADER_PATIENCE
        });
        if let Some((peer, _)) = previous.filter(|_| keeps_turn) {
            return Some((peer, asking));
        }
        let next = previous
            .map(|(peer, _)| peer)
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
        *self.filling_from() = Some((next, now));
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
        if !self.filling_from().is_some_and(|(asked, _)| asked == peer) {
            return;
        }
        match self.fill_headers(from, headers) {
            Filled::Ignored => {}
            // Progress, so this peer keeps its turn.
            Filled::Grew => {
                if let Some(entry) = self.filling_from().as_mut() {
                    entry.1 = now;
                }
            }
            // What was collected is gone, and whoever supplied it has just
            // shown it could not. The next peer is asked on the next round.
            Filled::Discarded => *self.filling_from() = None,
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
                if store.filling.append(header).is_err() {
                    store.discard_filling();
                    return Filled::Discarded;
                }
            }
            if store.filling.reaches() < oldest {
                return if store.filling.reaches() > held {
                    Filled::Grew
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
            let Some(header) = self.filling_at(height, epoch) else {
                return self.throw_the_run_away(epoch);
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
        // What is merged has to be what was weighed. The epoch says the
        // collection was not thrown away and started again while the log was
        // let go of, and the oldest header says nobody merged it first.
        if store.filling_epoch != epoch
            || store.headers.first_height() != oldest
            || store.filling.reaches() < oldest
        {
            return Filled::Ignored;
        }
        if !join_logs(&mut store.headers, &store.filling) {
            return Filled::Discarded;
        }
        store.discard_filling();
        // As at the open: the next block applied runs this again and says what
        // it found, and this one is holding the log.
        let _ = grow_forest(&mut store.forest, &store.headers);
        Filled::Grew
    }

    /// One record of the run being collected, with the log taken for the read
    /// alone.
    ///
    /// `None` once the collection it belongs to has been thrown away, which is
    /// what stops a reading of one run being weighed as a reading of another.
    fn filling_at(&self, height: u64, epoch: u64) -> Option<BlockHeader> {
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let store = log.as_ref()?;
        if store.filling_epoch != epoch {
            return None;
        }
        store.filling.read_at(height).ok()?
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
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(store) = log.as_ref() else {
            return Vec::new();
        };
        let stop = from
            .saturating_add(count.min(MAX_HEADERS as u64))
            .min(store.headers.reaches());
        let mut headers = Vec::new();
        for height in from..stop {
            let Ok(Some(header)) = store.headers.read_at(height) else {
                break;
            };
            headers.push(header);
        }
        headers
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
                let start = open_start(&tip, ground.history.clone(), SAMPLES, header_at, prove)?;
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
    if forest.len() > headers.reaches() {
        if let Err(error) = forest.keep_first(headers.reaches()) {
            return Some(Refusing::at(Writing::Headers, &error));
        }
    }
    // Where the two part company, walked back from the end. A reorganisation
    // replaces headers without shortening the log, so the lengths agreeing is
    // not the same as the contents agreeing.
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
    let mut height = if log.is_empty() {
        reaches.saturating_sub(added as u64)
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
    reaction: &Reaction,
    outbound: &SyncSender<Message>,
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
    for block in shared.blocks_at(&reaction.fetch) {
        if outbound.try_send(Message::Block(Box::new(block))).is_err() {
            return false;
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

fn save_book(shared: &Arc<Shared>) {
    let Some(directory) = shared.directory.as_ref() else {
        return;
    };
    let book = shared.book().clone();
    let _ = book.save(directory);
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
                // A socket accepted from a non-blocking listener inherits that
                // mode on some platforms. Left alone, every read on it would
                // return immediately and be taken for a deadline passing.
                let _ = stream.set_nonblocking(false);
                if !shared.running.load(Ordering::SeqCst) {
                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }
                let host = from.ip();
                if shared.refuses(host, unix_now()) || !shared.has_room_for(Some(host)) {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                attach_peer(shared, stream, None);
            }
            Err(error) if polling && error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
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
        let connected: Vec<PeerId> = shared.peers().keys().copied().collect();
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

/// Fills the header log in from the blocks, for the stretch it is missing.
///
/// For a node updated from a version that kept no headers, and for one whose
/// header log was lost. Both are the same case: what the blocks can still show
/// is written, and what they cannot is gone.
fn catch_up_headers(headers: &mut HeaderLog, blocks: &BlockLog) -> Result<(), StoreError> {
    if blocks.is_empty() {
        return Ok(());
    }
    let from = if headers.is_empty() {
        blocks.first_height()
    } else {
        headers.reaches()
    };
    if from < blocks.first_height() {
        // A gap nothing can fill: the headers stop before the blocks start.
        // Starting again from the blocks is the most that can be said.
        headers.keep_below(0)?;
        return catch_up_from(headers, blocks, blocks.first_height());
    }
    catch_up_from(headers, blocks, from)
}

fn catch_up_from(headers: &mut HeaderLog, blocks: &BlockLog, from: u64) -> Result<(), StoreError> {
    for height in from..blocks.reaches() {
        let Some(block) = blocks.read_at(height)? else {
            break;
        };
        headers.append(&block.header)?;
    }
    Ok(())
}

/// Puts `front` in front of `log`, leaving one run from the older of the two.
///
/// Every record is rewritten, which is a pass over the headers and happens
/// once in the life of a node that joined a chain.
fn join_logs(log: &mut HeaderLog, front: &HeaderLog) -> bool {
    let mut all = Vec::new();
    for height in front.first_height()..front.reaches() {
        let Ok(Some(header)) = front.read_at(height) else {
            return false;
        };
        all.push(header);
    }
    for height in log.first_height()..log.reaches() {
        let Ok(Some(header)) = log.read_at(height) else {
            return false;
        };
        all.push(header);
    }
    if log.clear().is_err() {
        return false;
    }
    for header in &all {
        if log.append(header).is_err() {
            return false;
        }
    }
    true
}

/// Reads back the ledger a node was handed, if it kept one.
///
/// Checked again on the way in, exactly as it was when it arrived over the
/// network. A node does not believe its own disk any more than it believes a
/// stranger, and what this costs is one pass over a file it only has if it
/// joined.
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

fn read_handed_ledger(
    directory: &Path,
    params: &ConsensusParams,
) -> Option<(LedgerState, Vec<BlockHeader>, u64, u64)> {
    let bytes = std::fs::read(directory.join(HANDED_LEDGER)).ok()?;
    let handover = Handover::decode(&bytes).ok()?;
    let state = accept(&handover, params).ok()?;
    let anchor = handover.at.height;
    Some((
        state,
        handover.recent,
        anchor,
        settles_at(anchor, handover.tip.height, params),
    ))
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
    let (empty, work) = {
        let chain = shared.chain();
        (chain.is_empty(), chain.total_work())
    };
    let step = shared.choosing().step(now, empty, work, join, &connected);
    match step {
        choosing::Step::Quiet => {}
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
    if !shared.book().seeds().is_empty() {
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
    let candidates: Vec<SocketAddr> = shared
        .book()
        .ready(now)
        .into_iter()
        .filter(|address| *address != shared.address && !connected.contains(address))
        .take(wanted)
        .collect();

    for address in candidates {
        if !shared.running.load(Ordering::SeqCst) {
            return;
        }
        let host = address.ip();
        if shared.refuses(host, now) || !shared.has_room_for(Some(host)) {
            continue;
        }
        match TcpStream::connect_timeout(&address, DIAL_TIMEOUT) {
            Ok(stream) => attach_peer(shared, stream, Some(address)),
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
    /// Another connection to the same peer already exists.
    Redundant,
}

/// Notes where a peer says it listens, and reports whether this is the second
/// connection to it.
fn register(shared: &Arc<Shared>, id: PeerId, address: SocketAddr) -> Registration {
    let mut peers = shared.peers();
    let existing = peers
        .iter()
        .any(|(other, entry)| *other != id && entry.advertised == Some(address));
    if let Some(entry) = peers.get_mut(&id) {
        entry.advertised = Some(address);
    }
    if existing {
        Registration::Redundant
    } else {
        Registration::Recorded
    }
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
fn attach_peer(shared: &Arc<Shared>, stream: TcpStream, dialled: Option<SocketAddr>) {
    let initiator = dialled.is_some();
    // Nothing is attached to a node that has stopped. Checked here and again
    // under the thread table below, because between the two a shutdown can
    // take that table and this thread would then never be joined.
    if !shared.running.load(Ordering::SeqCst) {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }
    let Ok(writing_end) = stream.try_clone() else {
        return;
    };
    let Ok(shutdown_end) = stream.try_clone() else {
        return;
    };
    let Ok(closing_end) = stream.try_clone() else {
        return;
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
    let (outbound, inbox) = mpsc::sync_channel::<Message>(OUTBOUND_QUEUE);
    shared.peers().insert(
        id,
        Peer {
            outbound: outbound.clone(),
            dialled: initiator,
            stream: shutdown_end,
            host: remote,
            advertised: None,
            dialled_to: dialled,
            archives: false,
        },
    );

    let network = shared.network();
    let writer = thread::spawn(move || {
        let mut writing_end = writing_end;
        while let Ok(message) = inbox.recv() {
            if write_message(&mut writing_end, network, &message).is_err() {
                break;
            }
        }
        let _ = writing_end.shutdown(Shutdown::Both);
    });

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

    let reading = Arc::clone(shared);
    let handle = thread::spawn(move || {
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
            let (nowhere, _) = mpsc::sync_channel(1);
            peer.outbound = nowhere;
        }
        let _ = writer.join();
        reading.peers().remove(&id);
    });
    // Under the thread table, so a connection taken while a shutdown is
    // emptying it is not left with a thread nobody joins. A shutdown that got
    // here first has already cleared `running`, and the socket is shut so the
    // read fails at once rather than waiting out a deadline.
    let mut threads = shared.threads();
    if !shared.running.load(Ordering::SeqCst) {
        let _ = closing_end.shutdown(Shutdown::Both);
    }
    threads.push(handle);
}

/// Whether a framing failure is the peer's fault rather than the network's.
///
/// A closed socket or a peer from another network has done nothing wrong. A
/// peer that opens a frame and stops, announces a size past the limit, or
/// sends something that does not decode is either broken or probing.
fn is_peer_fault(error: &WireError) -> bool {
    matches!(
        error,
        WireError::Stalled { .. } | WireError::FrameTooLarge { .. } | WireError::Malformed(_)
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

fn read_loop(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    id: PeerId,
    outbound: &SyncSender<Message>,
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
        let message = match read_message(&mut stream, network) {
            Ok(Incoming::Message(message)) => {
                last_heard = unix_now();
                if last_heard.saturating_sub(window_start) >= FLOOD_WINDOW {
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
            Err(WireError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
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

        if introduction && peer.greeted {
            note_claim(shared, id, &peer);
            // Written down beside the connection and in the book. Beside the
            // connection so a wallet can pick who to ask now; in the book so
            // one that comes back tomorrow, needing a proof and connected to
            // nobody who can give it, has a door to knock on.
            shared.note_what_it_keeps(id, peer.advertised, peer.keeps.cold_set);
        }

        shared.remember(&reaction.learned);
        shared.forget(&reaction.forget);
        if !announced {
            if let Some(address) = peer.advertised {
                announced = true;
                // It spoke, so whatever was held against it no longer holds.
                shared.book().answered(&address, last_heard);
                if register(shared, id, address) == Registration::Redundant
                    && loses_the_tie(shared.address, address, initiator)
                {
                    break;
                }
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
        if !answer_deferred(shared, &reaction, outbound) {
            break 'reading;
        }
        // Headers from before this node arrived, taken now that the chain has
        // been let go of: they are written to a log and weighed against a
        // commitment, and both reach a disk. Named with the peer that sent
        // them, because there is one collection and it belongs to one peer.
        if let Some((from, headers)) = reaction.offered_headers.take() {
            shared.take_headers(id, from, &headers, last_heard);
        }
        // A block on a branch this node can never cross to. Nothing is done
        // about it and nothing is held against the peer; it is counted,
        // because a node whose height never moves while these arrive is a
        // node that has been handed a chain nobody else is on, and until now
        // there was nowhere that showed.
        if reaction.unreachable.is_some() {
            shared.out_of_reach.fetch_add(1, Ordering::Relaxed);
        }
        // A block written under rules this build does not have. Nothing is
        // held against the peer, which is why it is here rather than among the
        // reasons to drop one: it is carrying what its own chain carries, and
        // this node is the one that cannot read it. Counted, because a node
        // that has met a run of these from several peers has almost certainly
        // been left behind by the network, and that used to show up as nothing
        // but a height that had stopped moving.
        if let Some(version) = reaction.unjudged {
            shared.cannot_judge(id, version, last_heard);
        }
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
        too_old_for_the_chain, Unreadable, UNJUDGED_BLOCKS, UNJUDGED_PEERS, UNJUDGED_STRETCH,
    };

    /// A record of `blocks` of them from `peers` peers, spread over `over`.
    fn met(blocks: u64, peers: u64, over: u64) -> Unreadable {
        Unreadable {
            version: 7,
            blocks,
            peers: (0..peers).collect(),
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
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use std::net::Ipv4Addr;

    use cairn_ledger::note::Note;
    use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
    use cairn_ledger::validation::{assemble_block, connect_block, mine_block};
    use cairn_ledger::LedgerState;

    use super::*;

    fn address(last: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, last), 9_000))
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

    /// A laptop closed for a night is the case this exists for: the thread
    /// below stops with the machine, and the seconds it missed are the only
    /// trace left of the time it was not on the network.
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

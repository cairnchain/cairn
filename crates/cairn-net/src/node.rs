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

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cairn_accumulator::forest::{Forest, ForestProof};
use cairn_chain::{Accepted, Bodies, ChainError, ChainStore, Located, Outdated};
use cairn_crypto::PublicKey;
use cairn_ledger::block::{Block, BlockHeader};
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
use crate::joining::{Collecting, Joined, Progress};
use crate::message::{Joining, Message, JOIN_PART_BYTES, MAX_CHAIN, MAX_HEADERS};
use crate::refusal::{can_be_refused, Refusals};
use crate::sync::{local_handshake, on_message, Local, PeerState, Reaction};
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

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("could not open the connection: {0}")]
    Io(#[from] io::Error),
    #[error("could not reach the block log: {0}")]
    Store(#[from] StoreError),
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
    /// Bytes dropped from the end of the log because a write never finished.
    pub discarded_bytes: u64,
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
    /// Whether this node opened the connection, rather than answering one.
    ///
    /// A connection somebody else opened is a connection somebody else chose,
    /// and counting it as one of this node's own is how a stranger decides who
    /// it talks to.
    dialled: bool,
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
    /// How far this node is through joining a chain it was not on.
    joining: Mutex<Progress>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    next_id: AtomicU64,
    running: AtomicBool,
    /// Set once, if this node ever meets a height it has no rules for.
    ///
    /// Kept rather than only acted on, so whatever started the node can say
    /// why it stopped. Running on would mean following the chain of whoever
    /// had not updated either.
    outdated: Mutex<Option<Outdated>>,
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

    fn seed_names(&self) -> MutexGuard<'_, Vec<String>> {
        self.seed_names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn threads(&self) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
        self.threads.lock().unwrap_or_else(PoisonError::into_inner)
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
            write_branch(log, accepted, chain);
            chain.release_bodies(log.blocks.first_height(), log.blocks.reaches());
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

        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(log) = log.as_mut() {
            // A log that no longer reaches that height was rewritten by a
            // reorganisation between the two checks above, and dropping
            // against it would throw away blocks this node still holds.
            if !log.blocks.holds(at.height) {
                return;
            }

            let held = u64::try_from(log.blocks.len()).unwrap_or(u64::MAX);
            let cut = cut_for(at.height, held, log.blocks.bytes(), keep);
            if cut > log.blocks.first_height() {
                let _ = log.blocks.keep_from(cut);
            }
        }
    }

    /// Writes this node's ledger down, returning the height it stands for.
    ///
    /// Separate from dropping the blocks below it, because the two are two
    /// steps and a machine can stop between them. Writing first is what makes
    /// that survivable: what is left is a ledger and more blocks than needed,
    /// rather than neither.
    fn write_ledger(&self) -> Option<Located> {
        let bytes = self.own_ledger()?;
        let at = Handover::decode(&bytes).ok()?.at;
        self.keep_ledger(&bytes)
            .then(|| Located::new(at.height, at.id()))
    }

    /// Keeps the ledger this node was handed, so it can start again without
    /// one.
    ///
    /// Written whole, to a name beside the old one, and moved into place. A
    /// process that stops partway leaves the previous file untouched rather
    /// than half of a new one, which for a file a node cannot start without is
    /// the difference between an interrupted write and a node that never comes
    /// back.
    fn keep_ledger(&self, bytes: &[u8]) -> bool {
        let Some(directory) = self.directory.as_ref() else {
            return false;
        };
        let target = directory.join(HANDED_LEDGER);
        let partial = directory.join(format!("{HANDED_LEDGER}.part"));
        std::fs::write(&partial, bytes).is_ok() && std::fs::rename(&partial, &target).is_ok()
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
        let handed = read_handed_ledger(&directory, &params)
            .and_then(|(state, recent)| chain.adopt(state, &recent).ok().map(|()| recent));
        let from = handed
            .as_ref()
            .and_then(|recent| recent.last())
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
        grow_forest(&mut forest, &headers);
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
        };

        let book = AddressBook::load(&directory);
        let restored = Restored {
            blocks: applied,
            refused,
            discarded_bytes: recovered.discarded_bytes,
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
        )?;
        Ok((node, restored))
    }

    fn start(
        params: ConsensusParams,
        address: SocketAddr,
        chain: ChainStore,
        log: Option<Store>,
        book: AddressBook,
        directory: Option<PathBuf>,
        lock: Option<DirectoryLock>,
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
            seed_names: Mutex::new(Vec::new()),
            names_looked_up_at: AtomicU64::new(0),
            directory,
            keep_bytes: AtomicU64::new(KEEP_BLOCK_BYTES),
            _lock: lock,
            peers: Mutex::new(HashMap::new()),
            refusals: Mutex::new(Refusals::new()),
            joined: Mutex::new([None, None]),
            joining: Mutex::new(Progress::Idle),
            threads: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            running: AtomicBool::new(true),
            outdated: Mutex::new(None),
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
    pub fn connect(&self, address: SocketAddr) -> Result<(), NodeError> {
        let stream = TcpStream::connect_timeout(&address, DIAL_TIMEOUT)?;
        self.shared.book().insert(address);
        attach_peer(&self.shared, stream, true);
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
    /// check, here or anywhere.
    pub fn take_offered_headers(&self, from: u64, headers: &[BlockHeader]) {
        self.shared.take_headers(from, headers);
    }

    /// How far this node is through joining a chain it was not on.
    ///
    /// A node being handed a ledger shows no height until the whole of it has
    /// arrived, which without this reads as a node doing nothing.
    pub fn joining(&self) -> Joined {
        self.shared
            .joining
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reported()
    }

    pub fn total_work(&self) -> u128 {
        self.with_chain(ChainStore::total_work)
    }

    /// Offers a locally produced block to the chain, announcing it if it lands.
    pub fn submit_block(&self, block: Block) -> Result<Accepted, ChainError> {
        let id = block.id();
        let height = block.header.height;
        let accepted = {
            let mut chain = self.shared.chain();
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
    pub fn submit_transaction(&self, transfer: Transfer) -> Result<bool, TransferError> {
        let message = Message::Transaction(Box::new(transfer.clone()));
        let fresh = self.shared.chain().accept_transfer(transfer)?;
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
        self.shared.outdated.lock().ok().and_then(|held| *held)
    }

    /// Closes every connection, stops the listener, and saves what is worth
    /// keeping.
    pub fn shutdown(&self) {
        if !self.shared.running.swap(false, Ordering::SeqCst) {
            return;
        }
        save_book(&self.shared);
        for peer in self.shared.peers().values() {
            let _ = peer.stream.shutdown(Shutdown::Both);
        }
        // Nothing has to be woken: the accept loop polls, and every peer
        // thread is either reading with a deadline or on a socket just shut.
        let handles = std::mem::take(&mut *self.shared.threads());
        for handle in handles {
            let _ = handle.join();
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
fn join_piece(shared: &Arc<Shared>, message: Message, outbound: &SyncSender<Message>) -> Taken {
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
    let Some(next) = take_join_part(shared, what, at, part, parts, bytes) else {
        return Taken::Handled;
    };
    if outbound.try_send(next).is_err() {
        return Taken::Failed;
    }
    Taken::Handled
}

/// Takes one piece of a join answer, and says what to ask for next.
///
/// A join is two exchanges in sequence: what work stands behind a chain, and
/// then the ledger at its tip. Each arrives in pieces, and each is checked as
/// a whole once its pieces are all here, because a piece on its own proves
/// nothing and a header commits to the whole or to none of it.
///
/// Anything that does not check out ends the attempt rather than being argued
/// with. There is another peer, and a node with no chain has nothing to lose
/// by starting again.
fn take_join_part(
    shared: &Arc<Shared>,
    what: Joining,
    at: Hash32,
    part: u32,
    parts: u32,
    bytes: Vec<u8>,
) -> Option<Message> {
    let now = unix_now();
    let mut joining = shared
        .joining
        .lock()
        .unwrap_or_else(PoisonError::into_inner);

    // A node that already has a chain is not joining one. This arrives when an
    // answer outlived the question, which costs nothing to ignore.
    if !shared.chain().is_empty() {
        *joining = Progress::Landed;
        return None;
    }

    // What state this piece leaves the attempt in, and what to ask next.
    let (next, whole) = match std::mem::take(&mut *joining) {
        Progress::Landed => return None,
        // The first piece of the weighing, which is where a join starts.
        Progress::Idle => {
            let Some(started) = Collecting::started(what, at, part, parts, bytes, now) else {
                return Some(give_up(&mut joining, shared));
            };
            step(&mut joining, started, None)
        }
        // The first piece of the ledger. The tip carries over from the
        // weighing, because the ledger has to be the one belonging to the
        // chain that was weighed.
        Progress::Weighed { tip, .. } => {
            let Some(started) = Collecting::started(what, at, part, parts, bytes, now) else {
                return Some(give_up(&mut joining, shared));
            };
            step(&mut joining, started, Some(tip))
        }
        Progress::Weighing(mut collecting) => {
            if !collecting.take(what, at, part, bytes, now) {
                // The pieces held cannot be completed, so the attempt is
                // dropped and this node falls back to reading the chain.
                return Some(give_up(&mut joining, shared));
            }
            step(&mut joining, collecting, None)
        }
        Progress::Fetching {
            tip,
            mut collecting,
        } => {
            if !collecting.take(what, at, part, bytes, now) {
                return Some(give_up(&mut joining, shared));
            }
            step(&mut joining, collecting, Some(tip))
        }
    };
    let Some(whole) = whole else {
        return next;
    };

    match what {
        Joining::Weight => {
            let weighed = SampledStart::decode(&whole)
                .ok()
                .filter(|start| check_start(start, SAMPLES).is_ok());
            let Some(start) = weighed else {
                return Some(give_up(&mut joining, shared));
            };
            // What this settles is which chain is heaviest and nothing else.
            // The ledger at that chain's tip is the next thing to ask for.
            *joining = Progress::Weighed {
                tip: start.tip,
                since: now,
            };
            Some(Message::GetJoin {
                what: Joining::Ledger,
                part: 0,
            })
        }
        Joining::Ledger => {
            let expected = match &*joining {
                Progress::Fetching { tip, .. } | Progress::Weighed { tip, .. } => tip.id(),
                _ => return None,
            };
            let landed = Handover::decode(&whole)
                .ok()
                // The ledger has to belong to the chain that was weighed. A
                // peer that weighed one and handed over another would
                // otherwise have its second answer taken on the strength of
                // the first.
                // The tip it names has to be the one that was weighed. What
                // ties the ledger to that tip is inside `accept`: the ledger's
                // own header is proved to sit in the tip's header forest, and
                // to sit far enough below it.
                .filter(|handover| handover.tip.id() == expected)
                .and_then(|handover| {
                    let state =
                        accept(&handover, shared.params.hot_capacity, shared.params.burial).ok()?;
                    shared.chain().adopt(state, &handover.recent).ok()?;
                    // Kept only once it has been taken, so what is on disk is
                    // a ledger this node checked and adopted rather than one
                    // it merely received.
                    shared.keep_ledger(&whole);
                    // The run of headers the ledger came with, written down.
                    // Without them this node has no oldest header of its own,
                    // and so nothing to check a filled-in run against: it
                    // would never be able to take anyone in.
                    shared.seed_headers(&handover.recent);
                    Some(())
                });
            if landed.is_none() {
                return Some(give_up(&mut joining, shared));
            }
            *joining = Progress::Landed;
            // A ledger arrives from below the tip on purpose, so landing one
            // is not arriving: the blocks between it and the tip are the part
            // this node checks for itself, and it has to go and ask for them.
            // Nothing else would — what drives a sync forward is a block
            // landing, and none is on its way.
            Some(Message::GetChain {
                locator: shared.chain().locator(),
            })
        }
    }
}

/// Abandons a join and asks for the chain the long way instead.
///
/// A node that asked to be handed a ledger and did not get one still has to
/// end up on the chain. Nothing about a failed handover says the peer is at
/// fault, so it is asked the ordinary question rather than dropped.
fn give_up(joining: &mut Progress, shared: &Arc<Shared>) -> Message {
    *joining = Progress::Idle;
    Message::GetChain {
        locator: shared.chain().locator(),
    }
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
}

impl Store {
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

/// A join answer, built once and handed out in pieces.
struct Prepared {
    what: Joining,
    at: Hash32,
    bytes: Vec<u8>,
}

impl Shared {
    /// One piece of what a newcomer asked for, building the whole only if the
    /// last one built is not it.
    ///
    /// `None` when this node cannot answer, which is the honest reply from one
    /// that validates and nothing more: proving where a header sits takes a
    /// path through the header forest, and everybody else holds sixty four
    /// hashes.
    fn serve_join(&self, what: Joining, part: u32) -> Option<Message> {
        let mut held = self.joined.lock().unwrap_or_else(PoisonError::into_inner);
        let tip = self.chain().tip()?;

        let slot = held.get_mut(what.slot())?;
        if slot.as_ref().is_none_or(|ready| ready.at != tip) {
            *slot = Some(Prepared {
                what,
                at: tip,
                bytes: self.build_join(what)?,
            });
        }
        let ready = slot.as_ref()?;

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

    /// Takes a run of headers offered as the ones from before this node
    /// arrived.
    ///
    /// Nothing here is believed. They are written to a log of their own, and
    /// only once they reach the oldest header this node holds is the forest
    /// they make compared with the commitment that header already carries. A
    /// sender that invented any of them is caught there; one that sent a
    /// truthful run out of order, or with a gap, is caught by the log itself.
    fn take_headers(&self, from: u64, headers: &[BlockHeader]) {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(store) = log.as_mut() else {
            return;
        };
        let oldest = store.headers.first_height();
        if oldest == 0 || headers.is_empty() {
            return;
        }
        let expected = if store.filling.is_empty() {
            0
        } else {
            store.filling.reaches()
        };
        if from != expected {
            return;
        }

        for header in headers {
            if header.height >= oldest {
                break;
            }
            if store.filling.append(header).is_err() {
                let _ = store.filling.clear();
                return;
            }
        }
        if store.filling.reaches() < oldest {
            return;
        }

        // Everything that came before the oldest header held is here. The one
        // question left is whether it is the truth, and that header answers
        // it: what it carries is the commitment to every header before it.
        let Ok(Some(anchor)) = store.headers.read_at(oldest) else {
            return;
        };
        let mut forest = cairn_accumulator::Archive::new();
        for height in 0..oldest {
            let Ok(Some(header)) = store.filling.read_at(height) else {
                let _ = store.filling.clear();
                return;
            };
            forest.add(header_leaf(&header.id()));
        }
        if forest.commitment() != anchor.history {
            // Somebody made them up, or sent the wrong chain's. Start over
            // rather than keep any of it.
            let _ = store.filling.clear();
            return;
        }

        // Only now are they this node's own headers. Written in front of what
        // it had, and the forest built again over the whole.
        if !join_logs(&mut store.headers, &store.filling) {
            return;
        }
        let _ = store.filling.clear();
        grow_forest(&mut store.forest, &store.headers);
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

    /// Builds the whole of what a newcomer asked for.
    ///
    /// Both answers reach for headers all over the chain, and a node holds the
    /// bodies of only the ones it could still undo, so everything older is
    /// read from the log. Chain first and log second, as everywhere.
    fn build_join(&self, what: Joining) -> Option<Vec<u8>> {
        let chain = self.chain();
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let header_at = |height: u64| -> Option<BlockHeader> {
            if let Some(block) = chain.block_at(height) {
                return Some(block.header);
            }
            let store = log.as_ref()?;
            // The header log first: a node keeps every header and only the
            // most recent blocks, so this is the one that answers about the
            // far end of the chain.
            if let Ok(Some(header)) = store.headers.read_at(height) {
                return Some(header);
            }
            Some(store.blocks.read_at(height).ok()??.header)
        };

        let state = chain.state();
        let tip = header_at(chain.height()?)?;

        match what {
            Joining::Weight => {
                // Proved against the forest from before the tip, which is the
                // one the tip's own header vouches for, and read from disk
                // rather than from memory: holding it in memory would be a
                // gigabyte at thirty years.
                let before_tip = tip.height;
                let prove = |height: u64| log.as_ref()?.forest.prove_in(height, before_tip).ok()?;
                let start =
                    open_start(&tip, state.headers_before_tip(), SAMPLES, header_at, prove)?;
                Some(start.encode())
            }
            Joining::Ledger => {
                // Not this node's ledger as it stands. One from far enough
                // below the tip that whoever wrote it had to keep mining over
                // it, which is the only thing a newcomer can lean on: it
                // cannot check a ledger, having watched no transaction go
                // past.
                let anchor_height = tip.height.checked_sub(self.params.burial)?;
                let buried = chain.ledger_at(anchor_height)?;
                let anchor = log
                    .as_ref()?
                    .forest
                    .prove_in(anchor_height, tip.height)
                    .ok()??;
                build_ledger(
                    &buried,
                    &header_at(anchor_height)?,
                    &tip,
                    state.headers_before_tip(),
                    anchor,
                    header_at,
                )
                .map(|held| held.encode())
            }
        }
    }

    /// This node's own ledger, written down so it can start from it.
    ///
    /// The same thing it would hand a newcomer, kept for itself. A node that
    /// has one does not have to read its way back from the first block, which
    /// is what lets it stop keeping every block it ever accepted.
    fn own_ledger(&self) -> Option<Vec<u8>> {
        let chain = self.chain();
        let log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let header_at = |height: u64| -> Option<BlockHeader> {
            if let Some(block) = chain.block_at(height) {
                return Some(block.header);
            }
            let store = log.as_ref()?;
            // The header log first: a node keeps every header and only the
            // most recent blocks, so this is the one that answers about the
            // far end of the chain.
            if let Ok(Some(header)) = store.headers.read_at(height) {
                return Some(header);
            }
            Some(store.blocks.read_at(height).ok()??.header)
        };
        let tip = header_at(chain.height()?)?;
        // The same buried ledger it would hand a stranger, and for the same
        // reason: one path, one set of rules, and a node that reads its own
        // disk back checks it the way anybody else would.
        let anchor_height = tip.height.checked_sub(self.params.burial)?;
        let buried = chain.ledger_at(anchor_height)?;
        let anchor = log
            .as_ref()?
            .forest
            .prove_in(anchor_height, tip.height)
            .ok()??;
        build_ledger(
            &buried,
            &header_at(anchor_height)?,
            &tip,
            chain.state().headers_before_tip(),
            anchor,
            header_at,
        )
        .map(|held| held.encode())
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
/// A failure here costs blocks on the next restart, not the chain this node is
/// following, so it does not stop the node.
fn write_branch(store: &mut Store, accepted: &Accepted, chain: &ChainStore) {
    write_headers(&mut store.headers, chain);
    grow_forest(&mut store.forest, &store.headers);
    write_blocks(&mut store.blocks, accepted, chain);
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
fn grow_forest(forest: &mut HeaderTree, headers: &HeaderLog) {
    if headers.first_height() != 0 {
        return;
    }
    if forest.len() > headers.reaches() && forest.keep_first(headers.reaches()).is_err() {
        return;
    }
    // Where the two part company, walked back from the end. A reorganisation
    // replaces headers without shortening the log, so the lengths agreeing is
    // not the same as the contents agreeing.
    let mut common = forest.len().min(headers.reaches());
    while common > 0 {
        let at = common.saturating_sub(1);
        let held = forest.leaf_at(at).ok().flatten();
        let now = headers
            .read_at(at)
            .ok()
            .flatten()
            .map(|header| header_leaf(&header.id()));
        if held.is_some() && held == now {
            break;
        }
        common = at;
    }
    if forest.len() > common && forest.keep_first(common).is_err() {
        return;
    }
    for height in forest.len()..headers.reaches() {
        let Some(header) = headers.read_at(height).ok().flatten() else {
            break;
        };
        if forest.append(header_leaf(&header.id())).is_err() {
            break;
        }
    }
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
fn write_headers(headers: &mut HeaderLog, chain: &ChainStore) {
    let Some(tip) = chain.height() else { return };
    let reaches = tip.saturating_add(1);

    // Where the log and the branch part company. Walking back from the tip
    // rather than trusting the log, since a reorganisation may have replaced
    // headers the log still holds without shortening it.
    let mut common = headers.reaches().min(reaches);
    while common > headers.first_height() {
        let at = common.saturating_sub(1);
        let held = headers.read_at(at).ok().flatten().map(|header| header.id());
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
    if headers.reaches() > common && headers.keep_below(common).is_err() {
        return;
    }

    let mut height = if headers.is_empty() {
        chain.branch_start().unwrap_or(0)
    } else {
        headers.reaches()
    };
    while height < reaches {
        let Some(header) = chain.block_at(height).map(|block| block.header) else {
            break;
        };
        if headers.append(&header).is_err() {
            break;
        }
        height = height.saturating_add(1);
    }
}

fn write_blocks(log: &mut BlockLog, accepted: &Accepted, chain: &ChainStore) {
    let added = match accepted {
        Accepted::Duplicate | Accepted::SideBranch => return,
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
    let Some(tip) = chain.height() else { return };
    let reaches = tip.saturating_add(1);
    let common = reaches.saturating_sub(added as u64);
    if log.reaches() > common && log.keep_below(common).is_err() {
        return;
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
        // A block the chain has already let go of cannot be written, so the
        // log stays short and the rest is asked for again after a restart.
        let Some(block) = chain.block_at(height) else {
            break;
        };
        if log.append(block).is_err() {
            break;
        }
        height = height.saturating_add(1);
    }
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
                attach_peer(shared, stream, false);
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
        // Headers from before this node arrived, if it joined a chain rather
        // than reading one. Asked of everybody: any node that read the chain
        // can answer, and the answer is checked rather than trusted, so there
        // is nobody in particular to ask.
        if let Some(asking) = shared.wants_headers() {
            shared.broadcast(None, &asking);
        }
        abandon_stalled_join(shared, now);
        shared.refusals().forget_expired(now);
    }
}

/// The ledger at `tip`, with the headers the difficulty rule reads.
///
/// The run of recent headers travels in full, and whoever takes it checks that
/// they are consecutive and end at this tip.
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
    Some(state.handover(*at, *tip, tip_history, anchor, recent))
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
fn read_handed_ledger(
    directory: &Path,
    params: &ConsensusParams,
) -> Option<(LedgerState, Vec<BlockHeader>)> {
    let bytes = std::fs::read(directory.join(HANDED_LEDGER)).ok()?;
    let handover = Handover::decode(&bytes).ok()?;
    let state = accept(&handover, params.hot_capacity, params.burial).ok()?;
    Some((state, handover.recent))
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
    let book = shared.book().clone();

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
    let mut local = Local {
        chain: &mut chain,
        book: &book,
        shows_the_chain: shows,
        listen: shared.address.port(),
        nonce: shared.nonce,
    };
    let reaction = on_message(&mut local, peer, message, unix_now());

    // Written while the chain is still held, so the log cannot record a branch
    // the chain has already moved off.
    if let Some(accepted) = reaction.applied.as_ref() {
        let mut log = shared.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(log) = log.as_mut() {
            write_branch(log, accepted, &chain);
            // Bodies now on disk, and far enough back that no ordinary
            // reorganisation reads them. Said after writing, never before: a
            // body let go of before it was written is a body nobody has.
            chain.release_bodies(log.blocks.first_height(), log.blocks.reaches());
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

/// Gives up on a join nothing has arrived for, and goes back to reading.
///
/// The other ways a join ends are all answers: a piece that does not fit, a
/// weight that does not check out, a ledger that does not match the tip it was
/// weighed at. Silence is the one that has to be noticed rather than handled,
/// and it is the likeliest of them, since it is what a peer hanging up looks
/// like.
fn abandon_stalled_join(shared: &Arc<Shared>, now: u64) {
    let asking = {
        let mut joining = shared
            .joining
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !has_gone_quiet(joining.moved(), now) {
            return;
        }
        give_up(&mut joining, shared)
    };
    // Asked of everyone rather than of the peer that went quiet, which is the
    // one peer known not to be answering.
    shared.broadcast(None, &asking);
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
        let connected: HashSet<SocketAddr> =
            peers.values().filter_map(|peer| peer.advertised).collect();
        // Only the ones this node went out and opened. A connection somebody
        // else opened does not tell this node anything about the network: the
        // stranger chose it. Counting those was enough to stop a node dialling
        // at all — hold eight connections open and it never looks for anybody
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
            Ok(stream) => attach_peer(shared, stream, true),
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

fn attach_peer(shared: &Arc<Shared>, stream: TcpStream, initiator: bool) {
    let Ok(writing_end) = stream.try_clone() else {
        return;
    };
    let Ok(shutdown_end) = stream.try_clone() else {
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
            Message::Hello(local_handshake(
                &chain,
                shows,
                shared.address.port(),
                shared.nonce,
            ))
        };
        let _ = outbound.try_send(hello);
    }

    let reading = Arc::clone(shared);
    let handle = thread::spawn(move || {
        read_loop(&reading, stream, id, &outbound, remote, initiator);
        reading.peers().remove(&id);
        drop(outbound);
        let _ = writer.join();
    });
    shared.threads().push(handle);
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

fn read_loop(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    id: PeerId,
    outbound: &SyncSender<Message>,
    remote: Option<IpAddr>,
    initiator: bool,
) {
    let network = shared.network();
    let mut peer = PeerState::new(remote);
    let mut announced = false;
    let mut last_heard = unix_now();
    let mut window_start = last_heard;
    let mut in_window = 0u32;
    let mut misbehaved = false;

    // Reads carry a deadline, so this loop looks up regularly rather than
    // waiting on a peer that may never speak again. Two silences are told
    // apart: a peer with nothing to say between frames is fine and stays, and
    // a peer holding a frame open is not and goes.
    while shared.running.load(Ordering::SeqCst) {
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

        // Headers from before this node arrived belong to whoever asked for
        // them, which is this node rather than the layer that reads messages.
        if let Message::Headers { from, headers } = &message {
            shared.take_headers(*from, headers);
            continue;
        }

        // A piece of a join answer belongs to whoever is collecting one, which
        // is this node rather than the layer that reads messages.
        let message = match join_piece(shared, message, outbound) {
            Taken::Handled => continue,
            Taken::Failed => return,
            Taken::Other(message) => message,
        };

        // The chain is held for the decision and for writing the log, and let
        // go before anything is sent, so a slow peer never stalls the chain.
        let (mut reaction, passing) = decide(shared, &mut peer, message);

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
                return;
            }
        }
        // What the sync layer named rather than answered, because answering
        // either reaches a disk and it runs with the chain held.
        if !answer_deferred(shared, &reaction, outbound) {
            return;
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
            if let Ok(mut held) = shared.outdated.lock() {
                held.get_or_insert(outdated);
            }
            shared.running.store(false, Ordering::SeqCst);
            break;
        }
        if let Some(reason) = reaction.drop_peer {
            misbehaved = reason.is_misbehaviour();
            break;
        }
    }

    if misbehaved {
        if let Some(host) = remote {
            shared.refuse(host, unix_now());
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
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
        write_branch(&mut store, &accepted, &chain);

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

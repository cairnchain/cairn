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
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cairn_chain::{Accepted, ChainError, ChainStore, Located};
use cairn_crypto::PublicKey;
use cairn_ledger::block::Block;
use cairn_ledger::genesis;
use cairn_ledger::note::NetworkId;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::sampling::{open_start, SAMPLES};
use cairn_ledger::transaction::Transfer;
use cairn_ledger::validation::ConsensusParams;
use cairn_ledger::validation::TransferError;
use cairn_primitives::codec::Encode;
use cairn_primitives::Hash32;
use cairn_store::{BlockLog, DirectoryLock, StoreError};

use crate::book::AddressBook;
use crate::message::{Joining, Message, JOIN_PART_BYTES, MAX_CHAIN};
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
}

struct Shared {
    params: ConsensusParams,
    address: SocketAddr,
    /// Drawn once at start. A node behind a router cannot recognise its own
    /// address coming back from a peer, but it can recognise this.
    nonce: u64,
    chain: Mutex<ChainStore>,
    /// Absent when the node keeps its chain only in memory.
    log: Mutex<Option<BlockLog>>,
    book: Mutex<AddressBook>,
    directory: Option<PathBuf>,
    /// Held for as long as the node runs, so no second process writes to the
    /// same directory.
    _lock: Option<DirectoryLock>,
    peers: Mutex<HashMap<PeerId, Peer>>,
    /// Peers turned away for a while, for something they did earlier.
    refusals: Mutex<Refusals>,
    /// The last join answer built, kept so a newcomer asking for its pieces in
    /// turn is answered from one build rather than from twenty two.
    ///
    /// One answer, not one per peer: building a ledger is megabytes, and this
    /// is the difference between a node that can be joined and a node anybody
    /// can make spend its memory. A second newcomer asking about a different
    /// tip replaces it, which costs the first one a rebuild and no more.
    joined: Mutex<Option<Joined>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    next_id: AtomicU64,
    running: AtomicBool,
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
    fn persist(&self, accepted: &Accepted, chain: &ChainStore) {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(log) = log.as_mut() {
            write_branch(log, accepted, chain);
        }
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
                let index = usize::try_from(entry.height).ok()?;
                let block = log.read(index).ok().flatten()?;
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
                    *slot = usize::try_from(*height)
                        .ok()
                        .and_then(|index| log.read(index).ok().flatten());
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
fn open_the_chain(chain: &mut ChainStore, params: ConsensusParams, now: u64) {
    // Only for a network that pins its first block. An unnamed one, which is
    // what tests use, starts from whatever it is given.
    if params.genesis.is_none() || !chain.is_empty() {
        return;
    }
    if let Some(block) = genesis::block(params.network) {
        let _ = chain.add_block(block, now);
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
        open_the_chain(&mut chain, params, now);
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
        let mut applied = 0usize;
        for block in log.replay() {
            let Ok(block) = block else { break };
            if !matches!(chain.add_block(block, now), Ok(Accepted::Extended)) {
                break;
            }
            applied = applied.saturating_add(1);
        }
        let refused = recovered.blocks.saturating_sub(applied);
        if refused > 0 {
            log.keep_first(applied)?;
        }

        let book = AddressBook::load(&directory);
        let restored = Restored {
            blocks: applied,
            refused,
            discarded_bytes: recovered.discarded_bytes,
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
        log: Option<BlockLog>,
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
            log: Mutex::new(log),
            book: Mutex::new(book),
            directory,
            _lock: lock,
            peers: Mutex::new(HashMap::new()),
            refusals: Mutex::new(Refusals::new()),
            joined: Mutex::new(None),
            threads: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            running: AtomicBool::new(true),
        });

        {
            let mut chain = shared.chain();
            open_the_chain(&mut chain, params, unix_now());
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
        let index = usize::try_from(height).ok()?;
        let log = self
            .shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        log.as_ref()?.read(index).ok().flatten()
    }

    pub fn height(&self) -> Option<u64> {
        self.with_chain(ChainStore::height)
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
            self.shared.persist(&accepted, &chain);
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

/// A join answer, built once and handed out in pieces.
struct Joined {
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

        let fresh = held
            .as_ref()
            .is_none_or(|ready| ready.what != what || ready.at != tip);
        if fresh {
            *held = Some(Joined {
                what,
                at: tip,
                bytes: self.build_join(what)?,
            });
        }
        let ready = held.as_ref()?;

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

    /// Builds the whole of what a newcomer asked for.
    fn build_join(&self, what: Joining) -> Option<Vec<u8>> {
        let chain = self.chain();
        let state = chain.state();
        let tip_id = chain.tip()?;
        let tip = chain.block(&tip_id).map(|block| block.header)?;

        match what {
            Joining::Weight => {
                let start = open_start(
                    &tip,
                    state.headers_before_tip(),
                    SAMPLES,
                    |height| chain.block_at(height).map(|block| block.header),
                    |height| state.prove_header(height),
                )?;
                Some(start.encode())
            }
            Joining::Ledger => {
                // The headers the difficulty rule reads, in full, which the
                // asker checks are consecutive and end at this tip.
                let from = tip
                    .height
                    .saturating_sub(u64::try_from(RECENT_HEADERS.saturating_sub(1)).unwrap_or(0));
                let mut recent = Vec::with_capacity(RECENT_HEADERS);
                for height in from..=tip.height {
                    recent.push(chain.block_at(height).map(|block| block.header)?);
                }
                Some(state.handover(tip, recent).encode())
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
/// A failure here costs blocks on the next restart, not the chain this node is
/// following, so it does not stop the node.
fn write_branch(log: &mut BlockLog, accepted: &Accepted, chain: &ChainStore) {
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
    let common = usize::try_from(reaches)
        .unwrap_or(usize::MAX)
        .saturating_sub(added);
    if log.len() > common && log.keep_first(common).is_err() {
        return;
    }
    // Everything the branch carries beyond what the log holds. Usually one
    // block; more if a write failed earlier and the log fell behind.
    let mut height = u64::try_from(log.len()).unwrap_or(u64::MAX);
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
        dial_from_book(shared, now);
        save_book(shared);
        collect_finished(shared);
        shared.refusals().forget_expired(now);
    }
}

/// Whether the gap between two rounds of maintenance means the machine was not
/// running, or not on the network, while it passed.
///
/// The clock going backwards counts as away too. It says the same thing: what
/// this node believes about the last few minutes is not to be trusted.
fn was_away(previous: u64, now: u64) -> bool {
    now < previous || now.saturating_sub(previous) >= AWAY_GAP
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

fn dial_from_book(shared: &Arc<Shared>, now: u64) {
    let (connected, count) = {
        let peers = shared.peers();
        let connected: HashSet<SocketAddr> =
            peers.values().filter_map(|peer| peer.advertised).collect();
        (connected, peers.len())
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
            Message::Hello(local_handshake(&chain, shared.address.port(), shared.nonce))
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

        // The chain is held for the decision and for writing the log, and let
        // go before anything is sent, so a slow peer never stalls the chain.
        let (mut reaction, passing) = {
            // Chain first and log second, here and everywhere, so two threads
            // never take these two the other way round from each other.
            let mut chain = shared.chain();
            let book = shared.book().clone();
            let mut log = shared.log.lock().unwrap_or_else(PoisonError::into_inner);

            let mut local = Local {
                chain: &mut chain,
                book: &book,
                listen: shared.address.port(),
                nonce: shared.nonce,
            };
            let reaction = on_message(&mut local, &mut peer, message, unix_now());

            // Written while the chain is still held, so the log cannot record
            // a branch the chain has already moved off.
            if let (Some(accepted), Some(log)) = (reaction.applied.as_ref(), log.as_mut()) {
                write_branch(log, accepted, &chain);
            }
            let passing: Vec<Transfer> = reaction
                .relayed
                .iter()
                .filter_map(|id| chain.pooled(id).cloned())
                .collect();
            (reaction, passing)
        };

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
        let (mut log, _) = BlockLog::open(&directory).unwrap();

        let mut chain = ChainStore::new(params);
        for block in &blocks[..5] {
            chain.add_block(block.clone(), 2_000_000_000).unwrap();
        }
        // What a failed write leaves: a chain of five, a log of two.
        log.append(&blocks[0]).unwrap();
        log.append(&blocks[1]).unwrap();

        let accepted = chain.add_block(blocks[5].clone(), 2_000_000_000).unwrap();
        assert_eq!(accepted, Accepted::Extended);
        write_branch(&mut log, &accepted, &chain);

        assert_eq!(log.len(), 6, "the log caught up rather than skipping ahead");
        for (height, want) in blocks.iter().enumerate() {
            let found = log.read(height).unwrap().unwrap();
            assert_eq!(found.id(), want.id(), "record {height} is not that height");
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

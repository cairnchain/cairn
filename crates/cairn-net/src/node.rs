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

use cairn_chain::{Accepted, ChainError, ChainStore};
use cairn_crypto::PublicKey;
use cairn_ledger::block::Block;
use cairn_ledger::genesis;
use cairn_ledger::note::NetworkId;
use cairn_ledger::transaction::Transfer;
use cairn_ledger::validation::ConsensusParams;
use cairn_ledger::validation::TransferError;
use cairn_store::{BlockLog, DirectoryLock, StoreError};

use crate::book::AddressBook;
use crate::message::Message;
use crate::refusal::{can_be_refused, Refusals};
use crate::sync::{local_handshake, on_message, Local, PeerState};
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
    /// Blocks read back but refused, and therefore cut from the log.
    ///
    /// Every block in the log was valid when it was written, so a refusal here
    /// means the file changed underneath the node or the rules did.
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

    /// Writes blocks the chain has already accepted.
    ///
    /// A failure here costs the blocks on the next restart, not the chain the
    /// node is following, so it does not stop the node.
    fn persist(&self, blocks: &[Block]) {
        if blocks.is_empty() {
            return;
        }
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(log) = log.as_mut() else {
            return;
        };
        for block in blocks {
            let _ = log.append(block);
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
        let mut applied = 0usize;
        for block in &recovered.blocks {
            if chain.add_block(block.clone(), now).is_err() {
                break;
            }
            applied = applied.saturating_add(1);
        }
        let refused = recovered.blocks.len().saturating_sub(applied);
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

    pub fn height(&self) -> Option<u64> {
        self.with_chain(ChainStore::height)
    }

    pub fn total_work(&self) -> u128 {
        self.with_chain(ChainStore::total_work)
    }

    /// Offers a locally produced block to the chain, announcing it if it lands.
    pub fn submit_block(&self, block: Block) -> Result<Accepted, ChainError> {
        let id = block.id();
        let accepted = self.shared.chain().add_block(block.clone(), unix_now())?;
        if matches!(accepted, Accepted::Duplicate) {
            return Ok(accepted);
        }
        self.shared.persist(&[block]);
        if matches!(accepted, Accepted::Extended | Accepted::Reorganised { .. }) {
            self.shared.broadcast(None, &Message::Announce(vec![id]));
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
        // Asking again matters: a peer that joined after this node introduced
        // itself is only ever learned about by asking a second time.
        shared.broadcast(None, &Message::GetPeers);
        dial_from_book(shared);
        save_book(shared);
        collect_finished(shared);
        shared.refusals().forget_expired(unix_now());
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

fn dial_from_book(shared: &Arc<Shared>) {
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

    let candidates: Vec<SocketAddr> = shared
        .book()
        .iter()
        .filter(|address| *address != shared.address && !connected.contains(address))
        .take(wanted)
        .collect();

    for address in candidates {
        if !shared.running.load(Ordering::SeqCst) {
            return;
        }
        let host = address.ip();
        if shared.refuses(host, unix_now()) || !shared.has_room_for(Some(host)) {
            continue;
        }
        if let Ok(stream) = TcpStream::connect_timeout(&address, DIAL_TIMEOUT) {
            attach_peer(shared, stream, true);
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
    let mut peer = PeerState {
        remote,
        ..PeerState::default()
    };
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

        // The chain is held for the decision and released before anything is
        // written, so a slow peer never stalls the chain itself.
        let (reaction, fresh, passing) = {
            let mut chain = shared.chain();
            let book = shared.book().clone();
            let mut local = Local {
                chain: &mut chain,
                book: &book,
                listen: shared.address.port(),
                nonce: shared.nonce,
            };
            let reaction = on_message(&mut local, &mut peer, message, unix_now());
            let fresh: Vec<Block> = reaction
                .stored
                .iter()
                .filter_map(|id| chain.block(id).cloned())
                .collect();
            let passing: Vec<Transfer> = reaction
                .relayed
                .iter()
                .filter_map(|id| chain.pooled(id).cloned())
                .collect();
            (reaction, fresh, passing)
        };

        shared.persist(&fresh);
        shared.remember(&reaction.learned);
        shared.forget(&reaction.forget);
        if !announced {
            if let Some(address) = peer.advertised {
                announced = true;
                if register(shared, id, address) == Registration::Redundant
                    && loses_the_tie(shared.address, address, initiator)
                {
                    break;
                }
            }
        }

        for reply in reaction.reply {
            // A full queue means the peer is not reading what it asked for, so
            // the answer would be stale by the time it arrived.
            if outbound.try_send(reply).is_err() {
                return;
            }
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
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn address(last: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, last), 9_000))
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

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
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cairn_chain::{Accepted, ChainError, ChainStore};
use cairn_ledger::block::Block;
use cairn_ledger::note::NetworkId;
use cairn_ledger::validation::ConsensusParams;
use cairn_store::{BlockLog, StoreError};

use crate::book::AddressBook;
use crate::message::Message;
use crate::sync::{local_handshake, on_message, Local, PeerState};
use crate::wire::{read_message, write_message, WireError};

/// Connections a node tries to keep open.
pub const TARGET_PEERS: usize = 8;

/// How long a dial may hang before it is given up on.
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);
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
    outbound: Sender<Message>,
    /// Kept so a shutdown can unblock the thread reading from it.
    stream: TcpStream,
    /// Where this peer says it listens, once it has said so.
    advertised: Option<SocketAddr>,
}

struct Shared {
    params: ConsensusParams,
    address: SocketAddr,
    chain: Mutex<ChainStore>,
    /// Absent when the node keeps its chain only in memory.
    log: Mutex<Option<BlockLog>>,
    book: Mutex<AddressBook>,
    directory: Option<PathBuf>,
    peers: Mutex<HashMap<PeerId, Peer>>,
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
    /// the thread that is announcing a block to everyone else.
    fn broadcast(&self, except: Option<PeerId>, message: &Message) {
        for (id, peer) in self.peers().iter() {
            if Some(*id) == except {
                continue;
            }
            let _ = peer.outbound.send(message.clone());
        }
    }
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
        let directory = directory.into();
        let (mut log, recovered) = BlockLog::open(&directory)?;

        let mut chain = ChainStore::new(params);
        let now = unix_now();
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

        let node = Self::start(params, address, chain, Some(log), book, Some(directory))?;
        Ok((node, restored))
    }

    fn start(
        params: ConsensusParams,
        address: SocketAddr,
        chain: ChainStore,
        log: Option<BlockLog>,
        book: AddressBook,
        directory: Option<PathBuf>,
    ) -> Result<Self, NodeError> {
        let listener = TcpListener::bind(address)?;
        let address = listener.local_addr()?;

        let shared = Arc::new(Shared {
            params,
            address,
            chain: Mutex::new(chain),
            log: Mutex::new(log),
            book: Mutex::new(book),
            directory,
            peers: Mutex::new(HashMap::new()),
            threads: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            running: AtomicBool::new(true),
        });

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
        // The listener blocks in accept, so it takes one connection to wake it.
        let _ = TcpStream::connect_timeout(&self.address, DIAL_TIMEOUT);

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

fn accept_loop(shared: &Arc<Shared>, listener: &TcpListener) {
    while shared.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if !shared.running.load(Ordering::SeqCst) {
                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }
                attach_peer(shared, stream, false);
            }
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

    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    let (outbound, inbox) = mpsc::channel::<Message>();
    shared.peers().insert(
        id,
        Peer {
            outbound: outbound.clone(),
            stream: shutdown_end,
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
            Message::Hello(local_handshake(&chain, shared.address.port()))
        };
        let _ = outbound.send(hello);
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

fn read_loop(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    id: PeerId,
    outbound: &Sender<Message>,
    remote: Option<std::net::IpAddr>,
    initiator: bool,
) {
    let network = shared.network();
    let mut peer = PeerState {
        remote,
        ..PeerState::default()
    };
    let mut announced = false;

    // Reads block until a frame arrives or the socket closes. A peer that opens
    // a frame and then stalls holds this thread, which is what peer scoring and
    // stall timeouts are for; neither exists yet.
    while shared.running.load(Ordering::SeqCst) {
        let message = match read_message(&mut stream, network) {
            Ok(message) => message,
            Err(WireError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };

        // The chain is held for the decision and released before anything is
        // written, so a slow peer never stalls the chain itself.
        let (reaction, fresh) = {
            let mut chain = shared.chain();
            let book = shared.book().clone();
            let mut local = Local {
                chain: &mut chain,
                book: &book,
                listen: shared.address.port(),
            };
            let reaction = on_message(&mut local, &mut peer, message, unix_now());
            let fresh: Vec<Block> = reaction
                .stored
                .iter()
                .filter_map(|id| chain.block(id).cloned())
                .collect();
            (reaction, fresh)
        };

        shared.persist(&fresh);
        shared.remember(&reaction.learned);
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
            if outbound.send(reply).is_err() {
                return;
            }
        }
        if !reaction.broadcast.is_empty() {
            shared.broadcast(Some(id), &Message::Announce(reaction.broadcast));
        }
        if reaction.drop_peer.is_some() {
            break;
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

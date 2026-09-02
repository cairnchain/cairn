//! What a node does when a message arrives.
//!
//! Pure by design: it reads the chain, the address book, and what is known
//! about one peer, and says what to send. No sockets, no threads, and no clock
//! it reads itself. Everything that decides whether two nodes converge lives
//! here, so all of it can be tested by handing it messages.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use cairn_chain::{Accepted, ChainError, ChainStore, Located, Outdated};
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::NetworkId;
use cairn_ledger::validation::BlockError;
use cairn_primitives::Hash32;

use crate::book::worth_hearing_about;
use crate::message::{
    Handshake, Joining, Message, PeerAddress, MAX_ANNOUNCED, MAX_HEADERS, MAX_REQUESTED,
    MAX_SHARED_ADDRESSES, PROTOCOL_VERSION,
};

/// Everything of the surrounding node this layer is allowed to see.
#[derive(Debug)]
pub struct Local<'a> {
    pub chain: &'a mut ChainStore,
    /// Whether this node holds the whole header forest, and so can show a
    /// newcomer which chain carries the most work.
    ///
    /// Not the same question as archiving the cold set. That is a service for
    /// a wallet that lost a proof; this is what lets anyone join at all, and
    /// it costs 182 bytes a block rather than a set that grows with every note
    /// ever spent. Almost every node can answer yes.
    pub shows_the_chain: bool,
    /// The port this node listens on, so peers can pass its address along.
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
    pub total_work: u128,
    /// Whether the peer said it can show a newcomer the whole chain, which
    /// is what choosing whom to join has to know about everyone who spoke.
    pub archives: bool,
    /// Heights asked for and not yet received. While this is non empty the node
    /// is mid batch and does not ask for more.
    ///
    /// Heights rather than identifiers, because what is asked for is a stretch
    /// of a branch and a node does not know what a peer holds at a height
    /// until it arrives. A block that turns up is checked against the chain
    /// like any other; what this tracks is only whether the question has been
    /// answered.
    pub awaiting: BTreeSet<u64>,
    /// When the outstanding batch was asked for.
    ///
    /// A peer that answers everything else but never delivers the blocks it
    /// was asked for would otherwise hold this node mid batch indefinitely,
    /// which is a way of stalling a sync without ever looking unresponsive.
    pub asked_at: u64,
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
    pub last_message: u64,
    /// What answering this one connection has cost so far.
    ///
    /// Kept for the sake of being readable rather than because anything
    /// decides on it. What decides is [`PeerState::allowance`], which belongs
    /// to the address and not to the socket.
    ///
    /// Held by [`PeerState::afford`]; nothing else should touch it.
    pub spent: u32,
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
    pub fn current(&self, now: u64) -> bool {
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
}

impl Allowance {
    /// The allowance of a connection from an address the node keeps a count
    /// for.
    pub fn at(address: &Arc<Mutex<Window>>) -> Self {
        Self {
            mine: Window::default(),
            address: Some(Arc::clone(address)),
        }
    }

    /// Takes `cost`, saying whether it was there.
    ///
    /// A poisoned lock means a thread panicked holding it, which the release
    /// profile turns into an abort. Carrying on with the count is better than
    /// a second panic.
    fn afford(&mut self, cost: u32, now: u64) -> bool {
        if self.mine.roll(now) {
            // A connection starts where its address left off, so hanging up
            // is not a way of being handed a fresh window.
            let carried = self.address.as_ref().map(|window| {
                let mut held = window.lock().unwrap_or_else(PoisonError::into_inner);
                held.roll(now);
                held.spent
            });
            if let Some(spent) = carried {
                self.mine.spent = spent;
            }
        }
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
/// most a peer ever legitimately wants is a full sync, which asks for blocks
/// as fast as it can take them; at this allowance that is eight hundred blocks
/// a second, so thirty years of chain arrives in about five hours, which is
/// what the bandwidth alone would take. Nothing else an honest peer does comes
/// anywhere near it.
const ALLOWANCE: u32 = 8_192;

/// What each kind of message costs to answer, in the same units.
///
/// Roughly proportional to the work rather than measured: a block has to be
/// validated, a transfer carries signatures, and a block read off a disk is a
/// seek. Being roughly right is what matters, since the ceiling is far above
/// what an honest peer asks for and far below what a busy one could spend.
const COST_TRIVIAL: u32 = 1;
const COST_CHAIN: u32 = 8;
const COST_TRANSFER: u32 = 4;
const COST_BLOCK: u32 = 8;
const COST_PER_BLOCK_SERVED: u32 = 1;
/// What one header served costs, which is one read off the header log.
///
/// A header is smaller than a block and cheaper to send, but the disk does not
/// care: both are a seek and a read. Charging the ask rather than what it
/// serves is what let one seventeen byte request buy five hundred and twelve
/// reads, which is the whole of the difference between a limit that counts
/// what answering costs and one that counts messages.
const COST_PER_HEADER_SERVED: u32 = 1;
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
const COST_PER_ADDRESS_SERVED: u32 = 1;
/// What one piece of a join answer costs to build and send.
///
/// An eighth of a window, so a newcomer collecting twenty two pieces takes
/// three windows and a peer asking for nothing else is spending everything it
/// has on it.
const COST_JOIN: u32 = ALLOWANCE / 8;

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
    #[error("peer follows network {theirs:?}")]
    WrongNetwork { theirs: NetworkId },
    #[error("peer follows a chain starting at {theirs}, which is not this one")]
    ForeignChain { theirs: Hash32 },
    #[error("peer sent a block this node rejects")]
    BadBlock { id: Hash32 },
    #[error("this connection is this node talking to itself")]
    Ourselves,
}

impl DropReason {
    /// Whether this peer behaved badly, rather than merely belonging elsewhere.
    ///
    /// A node on another network or an older protocol has done nothing wrong
    /// and may be on this one tomorrow, so it is disconnected and forgotten
    /// rather than refused. A peer sending a block this node rejects, or
    /// speaking before introducing itself, is broken or probing, and is worth
    /// turning away for a while.
    pub fn is_misbehaviour(self) -> bool {
        match self {
            Self::Unannounced { .. } | Self::RepeatedHandshake | Self::BadBlock { .. } => true,
            // Reaching yourself is a fact about routing, not a fault, and the
            // node it happened to is this one.
            Self::WrongVersion { .. }
            | Self::WrongNetwork { .. }
            | Self::ForeignChain { .. }
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
pub fn local_handshake(
    chain: &ChainStore,
    shows_the_chain: bool,
    listen: u16,
    nonce: u64,
) -> Handshake {
    Handshake {
        version: PROTOCOL_VERSION,
        network: chain.params().network,
        genesis: chain.genesis().unwrap_or(Hash32::ZERO),
        tip: chain.tip().unwrap_or(Hash32::ZERO),
        height: chain.height().unwrap_or_default(),
        total_work: chain.total_work(),
        archives: shows_the_chain,
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
    if let Some(ours) = chain.genesis() {
        if theirs.genesis != ours && theirs.genesis != Hash32::ZERO {
            return Err(DropReason::ForeignChain {
                theirs: theirs.genesis,
            });
        }
    }
    Ok(())
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
    peer.archives = theirs.archives;

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
            local.shows_the_chain,
            local.listen,
            local.nonce,
        )));
    }
    if theirs.total_work > local.chain.total_work() {
        // A node with no chain facing one long enough to be final does not
        // ask here at all. Whatever it starts following first is what it
        // keeps, so the choice of whom to ask is made once, by the node,
        // against every claim it has heard, rather than by whichever
        // handshake this happens to be. A short chain carries no such
        // weight: following the wrong one is undone by the fork choice like
        // any other branch, so it is simply asked for.
        let held_for_the_choice = local.chain.is_empty() && theirs.height >= JOIN_RATHER_THAN_READ;
        if !held_for_the_choice {
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
pub const JOIN_RATHER_THAN_READ: u64 = 1_024;

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
const MAX_AWAITING: usize = MAX_REQUESTED * 4;

/// Asks for a stretch of a peer's branch, starting at `from`.
fn request_range(peer: &mut PeerState, from: u64, count: u64, now: u64) -> Reaction {
    let wanted = usize::try_from(count)
        .unwrap_or(MAX_REQUESTED)
        .min(MAX_REQUESTED);
    if wanted == 0 {
        return Reaction::idle();
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
        return Reaction::idle();
    }
    peer.awaiting.extend(batch.iter().copied());
    peer.asked_at = now;
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
    let room = MAX_AWAITING.saturating_sub(peer.awaiting.len());
    let wanted: Vec<u64> = ids
        .iter()
        .filter(|entry| !chain.contains(&entry.id))
        .map(|entry| entry.height)
        .filter(|at| peer.awaiting.contains(at) || room > 0)
        .take(MAX_REQUESTED)
        .collect();
    if wanted.is_empty() {
        return follow_up(chain, peer, now);
    }
    peer.awaiting.extend(wanted.iter().copied());
    peer.asked_at = now;
    Reaction::reply(vec![Message::GetBlocks(wanted)])
}

/// Once a batch has landed, asks for the next one if this node is still behind.
///
/// This is what drives a sync forward without any timer: each answer produces
/// the next question, and the questions stop when the node has caught up.
///
/// The one exception is a batch that never arrives. A peer answering
/// everything else while quietly never sending the blocks it was asked for
/// looks perfectly healthy and stalls the sync all the same, so an outstanding
/// batch is abandoned after [`BATCH_PATIENCE`] and the question asked again.
fn follow_up(chain: &ChainStore, peer: &mut PeerState, now: u64) -> Reaction {
    if !peer.awaiting.is_empty() && now.saturating_sub(peer.asked_at) >= BATCH_PATIENCE {
        peer.awaiting.clear();
    }
    if peer.awaiting.is_empty() && peer.total_work > chain.total_work() {
        return Reaction::reply(vec![Message::GetChain {
            locator: chain.locator(),
        }]);
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
    peer.awaiting.remove(&height);

    match chain.add_block(block, now) {
        Ok(accepted @ (Accepted::Extended | Accepted::Reorganised { .. })) => {
            let mut reaction = follow_up(chain, peer, now);
            reaction.applied = Some(accepted);
            reaction.broadcast.push(Located::new(height, id));
            reaction
        }
        Ok(Accepted::SideBranch) => follow_up(chain, peer, now),
        Ok(Accepted::Duplicate) => follow_up(chain, peer, now),
        // Missing history rather than a bad peer: the block is fine, this node
        // simply has not caught up to where it hangs. Asking again from a fresh
        // locator resolves it.
        //
        // Unless it hangs below everything this node holds, which is not
        // history it is missing but history it can never have. Nothing is held
        // against the peer there either; the difference is only that waiting
        // will not fix it, and that used to go unrecorded.
        Err(ChainError::UnknownParent(_) | ChainError::NotGenesis) => {
            let out_of_reach = below_everything_held(chain, height);
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
        Err(_) => Reaction::close(DropReason::BadBlock { id }),
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
        Message::GetChain { .. } => COST_CHAIN,
        // The largest thing a peer can ask for, and the only one that is worth
        // more to it than it costs this node, so it is charged accordingly: a
        // peer joining gets through in a handful of windows and one asking
        // over and over gets nowhere.
        Message::GetJoin { .. } => COST_JOIN,
        Message::Block(block) => {
            if peer.awaiting.contains(&block.header.height) {
                COST_TRIVIAL
            } else {
                COST_BLOCK
            }
        }
        Message::Transaction(_) => COST_TRANSFER,
        Message::GetBlocks(ids) => {
            let wanted = u32::try_from(ids.len().min(MAX_REQUESTED)).unwrap_or(u32::MAX);
            wanted.saturating_mul(COST_PER_BLOCK_SERVED)
        }
        Message::GetHeaders { count, .. } => {
            let wanted = u32::try_from((*count).min(MAX_HEADERS as u64)).unwrap_or(u32::MAX);
            wanted.saturating_mul(COST_PER_HEADER_SERVED)
        }
        Message::GetPeers => {
            let carried = u32::try_from(MAX_SHARED_ADDRESSES).unwrap_or(u32::MAX);
            carried.saturating_mul(COST_PER_ADDRESS_SERVED)
        }
        // A run of headers offered rather than asked for. Charged as one
        // message and not as five hundred writes, because a run from anybody
        // but the peer this node is filling from is refused before a byte of
        // it is written, so what an unwanted one costs is a comparison.
        _ => COST_TRIVIAL,
    }
}

/// Handles one message from one peer.
pub fn on_message(
    local: &mut Local<'_>,
    peer: &mut PeerState,
    message: Message,
    now: u64,
) -> Reaction {
    peer.last_message = now;

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
    if !peer.afford(cost_of(&message, peer), now) {
        return Reaction::idle();
    }

    match message {
        // A pong needs no answer, a second introduction was already refused
        // above, and a piece of a join answer belongs to whoever is collecting
        // one rather than here.
        Message::Pong(_) | Message::Hello(_) | Message::Welcome(_) | Message::JoinPart { .. } => {
            Reaction::idle()
        }
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
        Message::Chain { from, count } => {
            // What the peer offers, minus what this node already has. A peer
            // can only agree with a position it was shown, and this node shows
            // it the heights it still holds identifiers for, so the agreement
            // can land well behind where this node actually is. Asking from
            // there would mean receiving what it already holds, one useful
            // block at a time.
            let have = local.chain.height().map_or(0, |tip| tip.saturating_add(1));
            let start = from.max(have);
            let end = from.saturating_add(count);
            if start >= end {
                follow_up(local.chain, peer, now)
            } else {
                request_range(peer, start, end.saturating_sub(start), now)
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
        Message::Block(block) => on_block(local.chain, peer, *block, now),
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

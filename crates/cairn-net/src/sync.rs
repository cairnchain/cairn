//! What a node does when a message arrives.
//!
//! Pure by design: it reads the chain and what is known about one peer, and
//! says what to send. No sockets, no threads, and no clock it reads itself.
//! Everything that decides whether two nodes converge lives here, so all of it
//! can be tested by handing it messages.

use std::collections::BTreeSet;

use cairn_chain::{Accepted, ChainError, ChainStore};
use cairn_ledger::note::NetworkId;
use cairn_primitives::Hash32;

use crate::message::{
    Handshake, Message, MAX_ANNOUNCED, MAX_CHAIN, MAX_REQUESTED, PROTOCOL_VERSION,
};

/// What this node knows about one peer.
#[derive(Clone, Debug, Default)]
pub struct PeerState {
    /// Whether the peer has introduced itself. Nothing else is answered until
    /// it has.
    pub greeted: bool,
    pub height: u64,
    pub total_work: u128,
    /// Blocks asked for and not yet received. While this is non empty the node
    /// is mid batch and does not ask for more.
    pub awaiting: BTreeSet<Hash32>,
    pub last_message: u64,
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
}

/// What to do about one received message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reaction {
    /// Answers for the peer that sent the message.
    pub reply: Vec<Message>,
    /// Blocks newly worth telling every other peer about.
    pub broadcast: Vec<Hash32>,
    /// Set when the connection should be closed.
    pub drop_peer: Option<DropReason>,
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
pub fn local_handshake(chain: &ChainStore) -> Handshake {
    Handshake {
        version: PROTOCOL_VERSION,
        network: chain.params().network,
        genesis: chain.genesis().unwrap_or(Hash32::ZERO),
        tip: chain.tip().unwrap_or(Hash32::ZERO),
        height: chain.height().unwrap_or_default(),
        total_work: chain.total_work(),
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
    // take the genesis it is about to be handed. Choosing whom to ask is what a
    // seed address is: the one piece of trust in the whole protocol, and it
    // belongs to whoever runs the node, not to the network.
    if let Some(ours) = chain.genesis() {
        if theirs.genesis != ours && theirs.genesis != Hash32::ZERO {
            return Err(DropReason::ForeignChain {
                theirs: theirs.genesis,
            });
        }
    }
    Ok(())
}

fn greet(chain: &ChainStore, peer: &mut PeerState, theirs: Handshake, answer: bool) -> Reaction {
    if peer.greeted {
        return Reaction::close(DropReason::RepeatedHandshake);
    }
    if let Err(reason) = accept_handshake(chain, &theirs) {
        return Reaction::close(reason);
    }

    peer.greeted = true;
    peer.height = theirs.height;
    peer.total_work = theirs.total_work;

    let mut reply = Vec::new();
    if answer {
        reply.push(Message::Welcome(local_handshake(chain)));
    }
    if theirs.total_work > chain.total_work() {
        reply.push(Message::GetChain {
            locator: chain.locator(),
        });
    }
    Reaction::reply(reply)
}

/// Asks for the blocks among `ids` this node does not have.
fn request_missing(chain: &ChainStore, peer: &mut PeerState, ids: &[Hash32]) -> Reaction {
    let missing = chain.missing(ids.iter());
    if missing.is_empty() {
        return follow_up(chain, peer);
    }
    let batch: Vec<Hash32> = missing.into_iter().take(MAX_REQUESTED).collect();
    peer.awaiting.extend(batch.iter().copied());
    Reaction::reply(vec![Message::GetBlocks(batch)])
}

/// Once a batch has landed, asks for the next one if this node is still behind.
///
/// This is what drives a sync forward without any timer: each answer produces
/// the next question, and the questions stop when the node has caught up.
fn follow_up(chain: &ChainStore, peer: &PeerState) -> Reaction {
    if peer.awaiting.is_empty() && peer.total_work > chain.total_work() {
        return Reaction::reply(vec![Message::GetChain {
            locator: chain.locator(),
        }]);
    }
    Reaction::idle()
}

// The last two arms answer the same way for opposite reasons, and collapsing
// them would bury which is which.
#[allow(clippy::match_same_arms)]
fn on_block(
    chain: &mut ChainStore,
    peer: &mut PeerState,
    block: cairn_ledger::block::Block,
    now: u64,
) -> Reaction {
    let id = block.id();
    peer.awaiting.remove(&id);

    match chain.add_block(block, now) {
        Ok(Accepted::Extended | Accepted::Reorganised { .. }) => {
            let mut reaction = follow_up(chain, peer);
            reaction.broadcast.push(id);
            reaction
        }
        Ok(Accepted::Duplicate | Accepted::SideBranch) => follow_up(chain, peer),
        // Missing history rather than a bad peer: the block is fine, this node
        // simply has not caught up to where it hangs. Asking again from a fresh
        // locator resolves it.
        Err(ChainError::UnknownParent(_) | ChainError::NotGenesis) => follow_up(chain, peer),
        Err(_) => Reaction::close(DropReason::BadBlock { id }),
    }
}

/// Handles one message from one peer.
pub fn on_message(
    chain: &mut ChainStore,
    peer: &mut PeerState,
    message: Message,
    now: u64,
) -> Reaction {
    peer.last_message = now;

    match &message {
        Message::Hello(theirs) => return greet(chain, peer, *theirs, true),
        Message::Welcome(theirs) => return greet(chain, peer, *theirs, false),
        _ => {}
    }

    if !peer.greeted {
        return Reaction::close(DropReason::Unannounced {
            kind: message.kind(),
        });
    }

    match message {
        Message::Ping(nonce) => Reaction::reply(vec![Message::Pong(nonce)]),
        // A pong needs no answer, and a second introduction was already refused
        // above, so neither reaches here with anything to say.
        Message::Pong(_) | Message::Hello(_) | Message::Welcome(_) => Reaction::idle(),
        Message::GetChain { locator } => {
            Reaction::reply(vec![Message::Chain(chain.chain_after(&locator, MAX_CHAIN))])
        }
        Message::Chain(ids) => request_missing(chain, peer, &ids),
        Message::Announce(ids) => {
            let capped: Vec<Hash32> = ids.into_iter().take(MAX_ANNOUNCED).collect();
            request_missing(chain, peer, &capped)
        }
        Message::GetBlocks(ids) => {
            let reply = ids
                .iter()
                .take(MAX_REQUESTED)
                .filter_map(|id| chain.block(id).cloned())
                .map(|block| Message::Block(Box::new(block)))
                .collect();
            Reaction::reply(reply)
        }
        Message::Block(block) => on_block(chain, peer, *block, now),
    }
}

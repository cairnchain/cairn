//! What a wallet does, with nothing in it about how it is shown.
//!
//! A wallet is a node that happens to hold a key. It follows the chain and
//! checks every block for itself, which is the whole point of this design:
//! nothing here asks a server what the balance is, and nothing here would
//! believe it if it did.
//!
//! Everything that touches money lives in this library and nowhere else. What
//! sits on top of it is a face: a terminal today, a page served on the
//! machine's own loopback next, and something native on a phone later. Faces
//! are rewritten; this is not. A key is read into this process and never
//! leaves it — no face is ever handed one, and none can sign.

pub mod keyfile;
pub mod page;
pub mod serve;

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use cairn_accumulator::ForestProof;
use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{Input, Transfer};
use cairn_ledger::validation::ConsensusParams;
use cairn_net::{Joined, Node};
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

/// What can go wrong, said in terms a person can act on.
///
/// Not strings: a face has to be able to tell "you asked for more than you
/// have" from "the network would not take it", because one is the person's
/// mistake and the other is not.
#[derive(Clone, Debug, thiserror::Error)]
pub enum WalletError {
    #[error("could not start: {0}")]
    CouldNotStart(String),
    #[error("`{0}` is not an address: {1}")]
    BadAddress(String, String),
    #[error("a transfer of nothing would only cost state")]
    NothingToSend,
    #[error("that total is too large")]
    TooLarge,
    #[error(
        "{needed} is more than the {have} this wallet can spend{}",
        stranded_note(*stranded)
    )]
    NotEnough {
        needed: Amount,
        have: Amount,
        /// Money held in notes whose proof this node cannot produce. Real
        /// money, and the reason a balance must never be shown as one number.
        stranded: Amount,
    },
    #[error(
        "this spend gathers {notes} notes and takes {bytes} bytes, more than \
         the {limit} a block carries. Send a smaller amount, more than once: \
         each one leaves fewer notes behind."
    )]
    TooBulky {
        notes: usize,
        bytes: usize,
        limit: usize,
    },
    #[error("the network would not take it: {0}")]
    Refused(String),
}

fn stranded_note(stranded: Amount) -> String {
    if stranded == Amount::ZERO {
        String::new()
    } else {
        format!(". Another {stranded} sits in notes this node cannot prove")
    }
}

/// One note this wallet owns, and what it takes to spend it.
#[derive(Clone, Debug)]
pub struct Held {
    pub id: NoteId,
    pub note: Note,
    /// Where it fell and how to prove it, once it has fallen. The node was
    /// asked to watch this owner, so the proof it hands back is current.
    pub fallen: Option<(u64, ForestProof)>,
}

impl Held {
    /// Whether spending this one takes a proof travelling with it.
    #[must_use]
    pub const fn is_cold(&self) -> bool {
        self.fallen.is_some()
    }
}

/// What this key holds.
#[derive(Clone, Debug)]
pub struct Holdings {
    /// What can be spent right now.
    pub spendable: Amount,
    /// Money in notes that have fallen and whose proof this node cannot
    /// produce.
    ///
    /// Not a rounding error and not a detail: it is money, and it cannot move
    /// until an archivist rebuilds the proof. A wallet that folded it into the
    /// total would show a balance that quietly went down, which is the worst
    /// thing a wallet can tell anyone.
    pub stranded: Amount,
    /// Every note, newest first, so a face can show where the money sits.
    pub notes: Vec<Held>,
}

impl Holdings {
    /// Everything this key owns, spendable or not.
    #[must_use]
    pub fn total(&self) -> Amount {
        self.spendable
            .checked_add(self.stranded)
            .unwrap_or(self.spendable)
    }
}

/// Where this wallet's node has got to.
#[derive(Clone, Copy, Debug)]
pub struct Progress {
    pub height: Option<u64>,
    pub peers: usize,
    pub joining: Joined,
    pub total_work: u128,
}

/// What a spend did, once it has left.
#[derive(Clone, Copy, Debug)]
pub struct Sent {
    pub id: Hash32,
    pub amount: Amount,
    pub fee: Amount,
    pub change: Amount,
    /// Notes gathered to cover it, and how many needed a proof.
    pub notes: usize,
    pub from_cold: usize,
    /// Whether a peer took it. False means it is not spent: nobody has it.
    pub handed_on: bool,
}

/// A key, and the node that verifies the chain it lives on.
///
/// Deliberately says nothing about itself when printed. A key that reached a
/// log, a crash report or a terminal recording is a key that is gone, and the
/// derive that would have done it is one line.
pub struct Wallet {
    node: Node,
    secret: SecretKey,
    params: ConsensusParams,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Wallet(<key withheld>)")
    }
}

impl Wallet {
    /// Opens the key at `path` and starts a node that watches it.
    ///
    /// The owner is named before any block is replayed, because where a note
    /// falls is learned as it falls and there is no going back for it.
    pub fn open(
        path: &Path,
        params: ConsensusParams,
        data: &Path,
    ) -> Result<(Self, usize), WalletError> {
        let secret = keyfile::read(path).map_err(WalletError::CouldNotStart)?;
        let mine = secret.public_key();
        let listen: SocketAddr = "0.0.0.0:0"
            .parse()
            .map_err(|_| WalletError::CouldNotStart("bad listen address".to_owned()))?;
        let (node, restored) = Node::open_watching(params, listen, data, &[mine])
            .map_err(|error| WalletError::CouldNotStart(error.to_string()))?;
        Ok((
            Self {
                node,
                secret,
                params,
            },
            restored.blocks,
        ))
    }

    /// The public key money is paid to.
    #[must_use]
    pub fn address(&self) -> PublicKey {
        self.secret.public_key()
    }

    #[must_use]
    pub const fn params(&self) -> &ConsensusParams {
        &self.params
    }

    #[must_use]
    pub const fn node(&self) -> &Node {
        &self.node
    }

    /// Reaches for a peer, and remembers it whether or not it answers now.
    pub fn reach(&self, seed: SocketAddr) -> bool {
        self.node.remember_seed(seed);
        self.node.connect(seed).is_ok()
    }

    /// Where the node has got to.
    #[must_use]
    pub fn progress(&self) -> Progress {
        Progress {
            height: self.node.height(),
            peers: self.node.peer_count(),
            joining: self.node.joining(),
            total_work: self.node.total_work(),
        }
    }

    /// Waits until the chain stops moving, or until patience runs out.
    ///
    /// A wallet that answered from a chain it had not finished reading would
    /// show a balance from the past, which for a wallet is a wrong answer
    /// rather than a slow one.
    pub fn catch_up(&self, patience: Duration) {
        let deadline = Instant::now()
            .checked_add(patience)
            .unwrap_or_else(Instant::now);
        let mut last = self.node.height();
        let mut still_since = Instant::now();

        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
            let height = self.node.height();
            if height == last {
                if self.node.peer_count() > 0 && still_since.elapsed() > Duration::from_secs(2) {
                    return;
                }
            } else {
                last = height;
                still_since = Instant::now();
            }
        }
    }

    /// Everything this key owns, and what part of it cannot move.
    #[must_use]
    pub fn holdings(&self) -> Holdings {
        let mine = self.address();
        self.node.with_chain(|chain| {
            let state = chain.state();
            let mut notes: Vec<Held> = state
                .hot_notes()
                .filter(|(_, entry)| entry.note.owner == mine)
                .map(|(id, entry)| Held {
                    id,
                    note: entry.note,
                    fallen: None,
                })
                .collect();

            let mut stranded = Amount::ZERO;
            for (id, position, note) in state.watched_notes() {
                if note.owner != mine {
                    continue;
                }
                match state.cold().proof_of(position) {
                    Some(proof) => notes.push(Held {
                        id,
                        note,
                        fallen: Some((position, proof)),
                    }),
                    None => stranded = stranded.checked_add(note.value).unwrap_or(stranded),
                }
            }

            let spendable = notes.iter().fold(Amount::ZERO, |sum, held| {
                sum.checked_add(held.note.value).unwrap_or(sum)
            });
            Holdings {
                spendable,
                stranded,
                notes,
            }
        })
    }

    /// Builds, signs and hands over a transfer.
    ///
    /// Nothing about this is shown anywhere: the key is used here and the
    /// signature is made here, so a face never holds either.
    pub fn send(
        &self,
        recipient: PublicKey,
        amount: Amount,
        fee: Amount,
    ) -> Result<Sent, WalletError> {
        if amount == Amount::ZERO {
            return Err(WalletError::NothingToSend);
        }
        let needed = amount.checked_add(fee).ok_or(WalletError::TooLarge)?;

        let holdings = self.holdings();
        let (spending, gathered) =
            select(&holdings.notes, needed).ok_or(WalletError::NotEnough {
                needed,
                have: holdings.spendable,
                stranded: holdings.stranded,
            })?;
        let change = gathered.checked_sub(needed).ok_or(WalletError::NotEnough {
            needed,
            have: holdings.spendable,
            stranded: holdings.stranded,
        })?;

        let mine = self.address();
        let mut outputs = vec![Note::new(amount, recipient)];
        if change > Amount::ZERO {
            outputs.push(Note::new(change, mine));
        }

        let inputs = spending
            .iter()
            .map(|held| match &held.fallen {
                None => Input::hot(held.id),
                Some((position, proof)) => {
                    Input::cold(held.id, held.note, *position, proof.clone())
                }
            })
            .collect();
        let mut transfer = Transfer::new(inputs, outputs);
        for (index, held) in spending.iter().enumerate() {
            let Ok(index) = u32::try_from(index) else {
                return Err(WalletError::TooLarge);
            };
            transfer.sign_input(self.params.network, index, &held.note, &self.secret);
        }

        // A transfer no block can carry would be refused by the network, and
        // it is better to say so here than to have the refusal come back as a
        // rule nobody outside the protocol has heard of. It happens when a
        // wallet holds its money in many small fallen notes, each of which
        // travels with its own proof.
        let bytes = transfer.encode().len();
        if bytes > self.params.max_block_bytes {
            return Err(WalletError::TooBulky {
                notes: spending.len(),
                bytes,
                limit: self.params.max_block_bytes,
            });
        }

        let id = transfer.id();
        let from_cold = spending.iter().filter(|held| held.is_cold()).count();
        self.node
            .submit_transaction(transfer)
            .map_err(|error| WalletError::Refused(error.to_string()))?;

        // Held open long enough for the transfer to leave. Reporting a spend
        // that reached nobody as done would be telling someone their money
        // moved when it did not.
        let handed_on = wait_until(Duration::from_secs(5), || self.node.peer_count() > 0);
        std::thread::sleep(Duration::from_millis(500));

        Ok(Sent {
            id,
            amount,
            fee,
            change,
            notes: spending.len(),
            from_cold,
            handed_on,
        })
    }

    pub fn shutdown(&self) {
        self.node.shutdown();
    }
}

/// Picks notes to cover `needed`, largest first so a spend uses as few as it
/// can and leaves as little dust behind.
///
/// Notes the nodes still hold come first whatever their size, because
/// spending one of those costs no proof: a wallet that reached for a fallen
/// note while a hot one would do would be paying bytes for nothing.
fn select(held: &[Held], needed: Amount) -> Option<(Vec<Held>, Amount)> {
    let mut sorted = held.to_vec();
    sorted.sort_by(|left, right| {
        left.is_cold()
            .cmp(&right.is_cold())
            .then_with(|| right.note.value.cmp(&left.note.value))
    });

    let mut chosen = Vec::new();
    let mut gathered = Amount::ZERO;
    for note in sorted {
        if gathered >= needed {
            break;
        }
        gathered = gathered.checked_add(note.note.value)?;
        chosen.push(note);
    }
    (gathered >= needed).then_some((chosen, gathered))
}

fn wait_until(patience: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = Instant::now()
        .checked_add(patience)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    ready()
}

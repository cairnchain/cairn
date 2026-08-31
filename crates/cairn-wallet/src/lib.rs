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

pub mod history;
pub mod keyfile;
pub mod page;
pub mod serve;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::history::{History, Movement};
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
    #[error("this transfer has to pay at least {needed}")]
    FeeTooLow { needed: Amount },
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

/// What the history is written to, inside the wallet's own directory.
const HISTORY_FILE: &str = "history.dat";

/// Blocks read into the history in one go.
///
/// A wallet catching up on a long absence reads them in batches rather than
/// holding the chain while it walks the lot, so the page stays answerable and
/// the next block still arrives.
const CATCH_UP_BATCH: u64 = 512;

/// A key, and the node that verifies the chain it lives on.
///
/// Deliberately says nothing about itself when printed. A key that reached a
/// log, a crash report or a terminal recording is a key that is gone, and the
/// derive that would have done it is one line.
pub struct Wallet {
    node: Node,
    secret: SecretKey,
    params: ConsensusParams,
    /// This key's own account of what happened to it, kept beside the chain
    /// rather than in it.
    history: Mutex<History>,
    /// Where that account is written down.
    history_file: PathBuf,
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
        let history_file = data.join(HISTORY_FILE);
        let history = History::load(&history_file);
        Ok((
            Self {
                node,
                secret,
                params,
                history: Mutex::new(history),
                history_file,
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

    /// What a transfer to `recipient` for `amount` would have to pay.
    ///
    /// Worked out from the transfer this wallet would actually build, since
    /// what a transfer costs the network depends on its shape: how many notes
    /// it gathers, whether any of them travel with a proof, and how many
    /// places it leaves behind in the set every node holds.
    ///
    /// An estimate, and the one place it can be short is where paying the fee
    /// makes the wallet reach for another note. Then sending says so.
    pub fn floor_for(&self, recipient: PublicKey, amount: Amount) -> Amount {
        let holdings = self.holdings();
        let Some((spending, gathered)) = select(&holdings.notes, amount) else {
            return Amount::ZERO;
        };
        let mut outputs = vec![Note::new(amount, recipient)];
        if let Some(change) = gathered.checked_sub(amount) {
            if change > Amount::ZERO {
                outputs.push(Note::new(change, self.address()));
            }
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
        let transfer = Transfer::new(inputs, outputs);
        let bytes = transfer.encode().len();
        cairn_chain::fee_floor(cairn_chain::transfer_weight(&transfer, bytes))
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

    /// Reads the blocks the history has not seen yet, and writes it down.
    ///
    /// Returns how many it took. Called as often as anything wants to look at
    /// the history: it costs nothing when there is nothing new.
    ///
    /// A wallet that cannot read the block it is waiting for has either
    /// dropped it or was handed a ledger that starts past it. Neither is a
    /// fault, and neither can be read around, so the history starts from where
    /// the wallet can actually see.
    pub fn follow(&self) -> usize {
        let Some(tip) = self.node.height() else {
            return 0;
        };
        let mine = self.address();
        let mut history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Before reading forward: is what it already read still the chain? A
        // branch that was undone leaves this history describing blocks nobody
        // has any more, and reading on from there would stack the winning
        // branch on top of the losing one.
        if history.diverged(|height| self.node.archived_at(height).map(|block| block.id())) {
            history.forget();
            let _ = history.save(&self.history_file);
        }

        let mut taken = 0usize;
        let stop = tip.saturating_add(1);
        while history.next() < stop && (taken as u64) < CATCH_UP_BATCH {
            let height = history.next();
            let Some(block) = self.node.archived_at(height) else {
                // Nothing to read here. If the wallet holds later blocks, the
                // history begins where they do rather than staying stuck.
                let first = self.node.with_chain(cairn_chain::ChainStore::branch_start);
                match first {
                    Some(first) if first > height => history.skip_to(first),
                    _ => break,
                }
                continue;
            };
            history.take(&block, mine);
            taken = taken.saturating_add(1);
        }

        if taken > 0 {
            let _ = history.save(&self.history_file);
        }
        taken
    }

    /// This key's own account of what happened to it, newest first.
    #[must_use]
    pub fn history(&self) -> Vec<Movement> {
        self.follow();
        self.history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .movements()
            .copied()
            .collect()
    }

    /// The first height the history could see, so a face can say what it does
    /// not cover rather than implying it covers everything.
    #[must_use]
    pub fn history_from(&self) -> Option<u64> {
        self.history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .from()
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

        // The network turns away a transfer that pays less than the floor, so
        // the refusal is better said here, with the number, than fetched back
        // from a pool the sender cannot see. A fee of nothing was the ordinary
        // case until the floor existed, and a wallet that went on sending them
        // would look broken rather than out of date.
        let floor = cairn_chain::fee_floor(cairn_chain::transfer_weight(&transfer, bytes));
        if fee < floor {
            return Err(WalletError::FeeTooLow { needed: floor });
        }

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

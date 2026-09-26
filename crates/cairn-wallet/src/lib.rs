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
//! leaves it: no face is ever handed one, and none can sign.

pub mod history;
pub mod keyfile;
mod page;
pub mod pending;
pub mod serve;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::history::{Discarded, Fork, History, Movement};
use crate::pending::{Handed, Pending};
use cairn_accumulator::ForestProof;
use cairn_chain::{ChainStore, Outdated};
use cairn_crypto::{random_bytes, PublicKey, SecretKey};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{Input, Transfer};
use cairn_ledger::validation::{ConsensusParams, TransferError};
use cairn_net::node::{
    Behind, Probation, Refused, Stranded, Unjudged, Unread, Unweighable, Unwritten,
};
use cairn_net::{Joined, Node, MAX_PROVEN};
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

/// An address, read the one way this program reads one.
///
/// Every face takes an address as thirty two bytes of hexadecimal and has to
/// answer the same question about the same string. There were two readers and
/// they disagreed: the web face trimmed and the command line did not, so a
/// pasted address with a space on the end was taken by the form and refused by
/// `cairn-wallet send`. The web face's own doc said it read an address "the way
/// every other face of this program reads one" and that "there is one reader of
/// it now", and both sentences were false when they were written.
///
/// What comes back is [`WalletError::BadAddress`], which exists for this and
/// was built nowhere. The web face answered `NothingToSend`, so somebody who
/// mistyped an address was told "a transfer of nothing would only cost state",
/// which is an answer about the amount to a fault in the recipient. The
/// command line answered a bare `String`, which is what the note on
/// [`WalletError`] forbids in its first sentence.
///
/// Trimming rather than refusing the space: an address arrives pasted, and
/// what is on either side of it is not something the person typed on purpose.
///
/// # Errors
///
/// [`WalletError::BadAddress`] if the text is not thirty two bytes of
/// hexadecimal, or is thirty two bytes that are not a key.
pub fn parse_address(text: &str) -> Result<PublicKey, WalletError> {
    let text = text.trim();
    let bytes = cairn_primitives::hex::decode_array::<32>(text).ok_or_else(|| {
        WalletError::BadAddress(text.to_owned(), "not 32 bytes of hexadecimal".to_owned())
    })?;
    PublicKey::from_bytes(&bytes)
        .map_err(|error| WalletError::BadAddress(text.to_owned(), error.to_string()))
}

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
        "{needed} is more than the {have} this wallet can spend{}{}{}",
        ripening_note(*ripening),
        waiting_note(*waiting),
        stranded_note(*stranded)
    )]
    NotEnough {
        needed: Amount,
        have: Amount,
        /// Block rewards this wallet holds that cannot move yet. The one kind
        /// of money the refusal left unnamed beside the two below, so a miner
        /// whose whole balance was a young reward was told they had nothing.
        ripening: Amount,
        /// Money already handed to a payment no block has carried yet. Not
        /// spendable and not gone: it comes back as change, or it goes to
        /// whoever is being paid, and until a block decides which, neither.
        waiting: Amount,
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
    #[error(
        "this payment would have to gather {over} notes, and the network carries at most {limit} \
         in one payment. The largest {limit} this wallet holds come to {reach}, and the fee has \
         to come out of that too. Nothing was sent. Send less than {reach}, leaving room for the \
         fee: the change comes back as a single note, so each payment leaves the money in fewer \
         pieces and a few of them will move the lot."
    )]
    TooManyNotes {
        /// How many notes covering the amount would have taken.
        over: usize,
        /// How many the network carries in one payment.
        limit: usize,
        /// What the largest `limit` notes come to.
        reach: Amount,
    },
    #[error("{0}")]
    Refused(String),
    #[error(
        "this exact payment is already waiting for a block, as {id}. It was not sent a second \
         time and nobody has been paid twice. Wait for a block to carry it, which takes a few \
         minutes, and if you meant to pay the same person again, send it after that"
    )]
    AlreadyWaiting { id: Hash32 },
    #[error(
        "there was no room for it: this wallet's node is already holding as many waiting \
         transfers as it will, and this one does not pay enough to take the place of the \
         cheapest. Nothing was sent. Send it again paying more to be carried"
    )]
    NoRoom,
    #[error(
        "that fee is {fee}, to send {amount}. The network asks {floor} to carry this one, so \
         the fee as typed is out of all proportion to the payment. Nothing was sent: check \
         where the decimal point went. If you really do mean to pay it, say so and send again"
    )]
    FeeOutOfProportion {
        fee: Amount,
        amount: Amount,
        floor: Amount,
    },
    #[error(
        "the operating system would not provide the randomness this spend needs to keep its \
         shape to itself, so nothing was sent rather than something that says which output is \
         yours"
    )]
    NoRandomness,
}

/// What a person is told when this build has no rules for the chain it is on.
///
/// `following` is whether the wallet had a chain when it found out. It used to
/// be assumed, and the sentence said the height and the balance shown were
/// from before the moment it stopped. A wallet can now meet this verdict in
/// the ledger it is handed on its very first start, where there is no height
/// and no balance to be from before anything, and telling somebody to look at
/// numbers that are not there is worse than saying nothing.
fn too_old_for_this_chain(outdated: &Outdated, following: bool) -> String {
    let standing = if following {
        "It stopped following the chain there on purpose, so the height and the balance shown \
         are from before that moment and will not move again."
    } else {
        "It never got as far as a chain: what it was offered is written under those rules, so \
         there is no height and no balance here yet."
    };
    format!(
        "This wallet is too old for the chain it is on. The rules from block {} need version \
         {}, and this program knows only version {}. {standing} Install a newer wallet and \
         start it again: nothing on disk is lost, and the key file is not touched.",
        outdated.height, outdated.required, outdated.known
    )
}

/// What a person is told when no peer can show this node the chain.
///
/// Its own function rather than another arm inline, because the arm it sits
/// beside is already the longest thing in this file and a reader looking for
/// one of these should not have to walk the others.
fn nobody_could_show_it(unweighable: &Unweighable) -> String {
    format!(
        "No peer has been able to show this wallet's node what work stands behind the chain. {} \
         showings from {} different peers over {} seconds were all refused with the same words: \
         {}. Nothing has stopped and nothing is lost: the node is reading the chain block by \
         block instead, which checks more rather than less and takes longer. The balance appears \
         when it has finished. Leave it running.",
        unweighable.showings, unweighable.peers, unweighable.over, unweighable.because
    )
}

fn stranded_note(stranded: Amount) -> String {
    if stranded == Amount::ZERO {
        String::new()
    } else {
        format!(". Another {stranded} sits in notes this node cannot prove")
    }
}

fn ripening_note(ripening: Amount) -> String {
    if ripening == Amount::ZERO {
        String::new()
    } else {
        format!(
            ". Another {ripening} is in block rewards that cannot move until their blocks are \
             settled"
        )
    }
}

fn waiting_note(waiting: Amount) -> String {
    if waiting == Amount::ZERO {
        String::new()
    } else {
        format!(". Another {waiting} is held by a payment waiting for a block")
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

    /// This note as a transfer spends it, unsigned.
    fn as_input(&self) -> Input {
        match &self.fallen {
            None => Input::hot(self.id),
            Some((position, proof)) => Input::cold(self.id, self.note, *position, proof.clone()),
        }
    }
}

/// A spend worked out but not yet built, signed or handed over.
///
/// The same arithmetic answers two questions, so it is done in one place:
/// what a fee left blank should be, and what the spend about to be made costs.
/// They used to be worked out separately and they disagreed.
struct Draft {
    spending: Vec<Held>,
    change: Amount,
    bytes: usize,
    floor: Amount,
    /// What the pool weighs it at, which is what its fee is ranked against.
    weight: usize,
    /// What a note of it falling out of the hot set before a block carries
    /// it can add to the floor.
    margin: Amount,
}

/// What this key holds.
#[derive(Clone, Debug)]
pub struct Holdings {
    /// What can be spent right now.
    pub spendable: Amount,
    /// Block rewards this wallet holds that cannot move yet.
    ///
    /// A reward is the one kind of note whose existence depends on its block
    /// surviving, so the rules keep it still until its block is past any
    /// reorganisation. Counted apart rather than hidden: a miner who saw a
    /// balance drop by fifty CAIRN with no explanation would reasonably think
    /// something had gone wrong.
    pub ripening: Amount,
    /// The height the first of them can move at, if any are waiting.
    pub ripe_at: Option<u64>,
    /// Money handed to a payment that no block has carried yet.
    ///
    /// Counted apart from what can be spent, and taken out of it, because a
    /// note promised to a transfer waiting in the pool is a note the network
    /// will not let anybody spend twice. Waiting in this node's pool, or on
    /// this wallet's own record of what it handed over, which is what
    /// outlives the process: see [`Wallet::waiting`]. A wallet that went on counting it
    /// would build a second transfer out of the same notes, watch the pool
    /// turn it away for being the one it already holds, and tell its owner
    /// their money had moved again. That is how a person pays once and hands
    /// over twice.
    ///
    /// It is not gone either. Part of it comes back as change and the rest
    /// goes to whoever is being paid, and until a block carries the transfer
    /// neither has happened.
    pub waiting: Amount,
    /// Money in notes that have fallen and whose proof this node cannot
    /// produce.
    ///
    /// Not a rounding error and not a detail: it is money, and it cannot move
    /// until an archivist rebuilds the proof. A wallet that folded it into the
    /// total would show a balance that quietly went down, which is the worst
    /// thing a wallet can tell anyone.
    pub stranded: Amount,
    /// The notes that money is in, so a wallet can go and ask for what it
    /// takes to move them.
    ///
    /// Named rather than only counted. A total says there is a problem; this
    /// says which notes have it and where each one landed, which is everything
    /// somebody who kept the whole record needs to be asked.
    pub unprovable: Vec<Unprovable>,
    /// Notes this wallet's own account still names, and has stopped answering
    /// for, because it was moved past the blocks that would have said.
    ///
    /// Not counted into anything. A note leaves the account when this wallet
    /// reads the block that spent it, and when the node has let go of a block
    /// this wallet still needed, that reading never happens: what became of
    /// this key over that range is simply not in the account. So every note it
    /// held at that moment is one it can no longer stand behind, and on an
    /// ordinary wallet most of them turn out to have been spent.
    ///
    /// Kept apart from [`Holdings::unprovable`] rather than folded into it,
    /// because the two say opposite things. A note there is money, and what it
    /// needs is somebody who kept the set to rebuild a path to it. A note here
    /// may be money and may be a payment this key made, and the wallet cannot
    /// say which. So they are named here, to whoever holds the wallet, and to
    /// nobody else.
    ///
    /// Only notes with nothing to point at reach this. One the account watched
    /// fall carries a place, and a place is both evidence that this key held it
    /// and the only handle by which anyone could be asked about it, so that one
    /// stays counted. A node restarted from its own written ledger walks past
    /// blocks it no longer holds as a matter of course, and a rule that did not
    /// narrow here would stop every wallet on one from counting its stranded
    /// money at all.
    pub unaccounted: Vec<Unprovable>,
    /// The notes a spend can reach for, so a face can show where the money
    /// sits.
    ///
    /// Notes a waiting payment already holds are not among them, which is the
    /// same rule as [`Holdings::spendable`] said in the form the selection
    /// reads.
    pub notes: Vec<Held>,
}

impl Holdings {
    /// Everything this key owns, spendable or not.
    ///
    /// All four, because every note this wallet holds is counted into exactly
    /// one of them. Rewards inside the maturity window were left out of this
    /// sum while the sentence above still said "everything", so a miner whose
    /// only money was the block it had just found was told it owned nothing.
    #[must_use]
    pub fn total(&self) -> Amount {
        [self.waiting, self.ripening, self.stranded]
            .into_iter()
            .try_fold(self.spendable, Amount::checked_add)
            .unwrap_or(self.spendable)
    }

    /// What to say about notes this account has stopped answering for, if any.
    ///
    /// Said rather than shown as a figure, because a figure invites addition.
    /// These are not money this wallet is standing behind: they are notes it
    /// has lost track of, and the honest thing to do with a number it cannot
    /// vouch for is to name it and say why.
    #[must_use]
    pub fn unaccounted_note(&self) -> Option<String> {
        let count = self.unaccounted.len();
        if count == 0 {
            return None;
        }
        let worth = self
            .unaccounted
            .iter()
            .map(|one| one.note.value)
            .try_fold(Amount::ZERO, Amount::checked_add)
            .unwrap_or(Amount::ZERO);
        let notes = if count == 1 {
            "one note".to_owned()
        } else {
            format!("{count} notes")
        };
        Some(format!(
            "This wallet's account still names {notes}, worth {worth} if they are all still \
             yours, that it has stopped answering for. The node had let go of blocks \
             this wallet had not read yet, so what became of them over that range was \
             never read, and on a wallet that has paid anybody most of them are notes \
             that were paid away. They are left out of the balance rather than counted \
             into it, and out of what any archivist is asked about, since the places on \
             that list would be places this key no longer owns."
        ))
    }

    /// Whether this key holds nothing at all.
    ///
    /// Not the same question as whether a spend has anything to reach for, and
    /// the two were answered by one test. [`Holdings::notes`] holds what can be
    /// spent right now, so it is empty for a wallet whose money is a young
    /// reward, for one whose notes are all promised to a payment waiting for a
    /// block, and for one whose notes have fallen where its node cannot place
    /// them. Both faces read that as an empty wallet and said so, directly
    /// beside their own sentence naming the amount.
    #[must_use]
    pub fn empty_handed(&self) -> bool {
        self.total() == Amount::ZERO
    }
}

/// One note this key owns whose path this wallet's node cannot produce.
///
/// Real money in an awkward place. A note that has fallen out of the set every
/// node keeps can only be spent alongside a path showing where it sits, that
/// path changes every time another note falls, and no node keeps one for ever
/// for somebody it is not following. What is left is this: the note, and where
/// it landed.
#[derive(Clone, Copy, Debug)]
pub struct Unprovable {
    pub id: NoteId,
    pub note: Note,
    /// Where it landed, if this wallet's own account saw it land.
    ///
    /// Without it there is nobody to ask. The set is a list of hashes with no
    /// name attached to any of them, so where a note sits is the only handle
    /// anyone has on it, and a wallet that never saw one of its notes fall
    /// never had that handle.
    pub fell_at: Option<u64>,
}

/// What came of asking somebody to rebuild the paths this wallet is missing.
///
/// Kept so that whatever is showing the balance can say what happened, rather
/// than naming a service and leaving the person holding the wallet to go and
/// find it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Recovery {
    /// Notes that could not be spent when this ran.
    pub stranded: usize,
    /// How many of those this wallet could not even ask about, having never
    /// seen where they landed.
    pub unplaceable: usize,
    /// Peers the question went to. Zero means there was nobody to ask.
    pub asked: usize,
    /// How many of those said they keep the whole record.
    pub archivists: usize,
    /// Peers that answered at all, whatever the answer was.
    pub answered: usize,
    /// Notes that can move again, because somebody rebuilt what it takes.
    pub rebuilt: usize,
    /// Answers this wallet would not use, because what came back did not fit
    /// the chain its own node has checked.
    pub refused: usize,
    /// Notes left for the next round, because one question does not carry
    /// them.
    ///
    /// A question to the network names at most [`MAX_PROVEN`] places, and a
    /// wallet with more stranded notes than that asks about the first of them
    /// and comes back for the rest. Counted and said out loud, because
    /// "stranded 100, rebuilt 64" invites the reader to conclude that
    /// thirty six were asked about and went unanswered, and none of them was
    /// asked about at all.
    pub not_yet_asked: usize,
}

impl Recovery {
    /// What to tell the person holding the wallet, in words that do not
    /// assume they know how any of this works.
    ///
    /// `None` when there is nothing to say, which is a wallet with no money in
    /// this state at all.
    #[must_use]
    pub fn words(&self) -> Option<String> {
        if self.stranded == 0 {
            return None;
        }
        let notes = if self.stranded == 1 {
            "one note".to_owned()
        } else {
            format!("{} notes", self.stranded)
        };
        // At least one note is stranded here, so every one of them rebuilt is
        // also at least one rebuilt, and asking that as well asked nothing.
        if self.rebuilt >= self.stranded {
            return Some(format!(
                "Spending a note that has been put away needs a small piece of \
                 evidence that goes stale, and this wallet's own copy had gone \
                 stale for {notes}. It asked {} of the machines it is connected \
                 to, got fresh evidence back, and checked it against the chain it \
                 has verified itself. That money can move again.",
                self.asked
            ));
        }
        // Every note in this state, and no way to ask about any of them. Said
        // before the rest because the rest all end in something to try, and
        // there is nothing to try here.
        if self.unplaceable >= self.stranded {
            return Some(format!(
                "This wallet holds {notes} it cannot spend and cannot ask about. \
                 Spending a note that has been put away needs to know where it \
                 was put, and this wallet was not running when that happened, so \
                 it has no way to say which note to ask after. The money is not \
                 lost: it is on the chain and it is yours. Nothing here can reach \
                 it."
            ));
        }
        let mut said = if self.rebuilt > 0 {
            format!(
                "Spending a note that has been put away needs a small piece of \
                 evidence that goes stale, and this wallet's own copy had gone \
                 stale for {notes}. It asked around and got fresh evidence for {} \
                 of them, checked against the chain it has verified itself. The \
                 rest is still stuck, and asking again later may find it.",
                self.rebuilt
            )
        } else if self.asked == 0 {
            format!(
                "This wallet holds {notes} it cannot spend yet. Spending a note \
                 that has been put away needs a small piece of evidence that goes \
                 stale, and this wallet's copy has. Rebuilding one takes a machine \
                 that kept the whole record, and this wallet is not connected to \
                 anything at all. Connect to a peer that was started with \
                 --archive, or start one yourself."
            )
        } else if self.archivists == 0 {
            format!(
                "This wallet holds {notes} it cannot spend yet. Spending a note \
                 that has been put away needs a small piece of evidence that goes \
                 stale, and this wallet's copy has. Rebuilding one takes a machine \
                 that kept the whole record, and none of the {} this wallet is \
                 connected to says it did. Connect to a peer started with \
                 --archive, or start one yourself.",
                self.asked
            )
        } else {
            format!(
                "This wallet holds {notes} it cannot spend yet. It asked {} machines \
                 that keep the whole record, and none of them could say where these \
                 notes sit. Asking again later may do better; so may a different peer.",
                self.archivists
            )
        };

        // The notes that are not waiting on anything above, because nobody was
        // asked about them yet. Every sentence above ends in a reason the
        // money has not come back: nobody could answer, nobody here keeps the
        // record, there is nobody to ask. None of those is true of a note that
        // is simply behind the first sixty four in the queue, and reading
        // "rebuilt 64 of 100" without this invites exactly the wrong
        // conclusion, that thirty six were asked about and went unanswered.
        //
        // Before the line below rather than after it, because this one ends in
        // waiting and that one ends in nothing to wait for, and the order the
        // rest of this follows is worst last.
        if self.not_yet_asked > 0 {
            let _ = write!(
                said,
                " {} of them have not been asked about yet: one question to \
                 the network carries {MAX_PROVEN} at a time, and this wallet \
                 comes back for the rest by itself.",
                self.not_yet_asked
            );
        }

        // And the part of it that none of those sentences is true about. Every
        // one of them ends in something worth doing: wait, connect to an
        // archivist, try another peer. A note whose place this wallet never
        // saw is not waiting on any of that, and telling somebody to keep
        // trying for money nothing here can reach is the one answer that is
        // worse than saying so.
        if self.unplaceable > 0 {
            let _ = write!(
                said,
                " {} of them this wallet cannot ask about at all: it was not \
                 running when they were put away, so it has no way to say which \
                 note to ask after. Those are yours and on the chain, and nothing \
                 here reaches them.",
                self.unplaceable
            );
        }
        Some(said)
    }
}

/// A payment this wallet handed over that no block carries yet.
///
/// A wallet that could not say this had only two things to tell its owner
/// about a payment, done and not done, and a payment spends most of its first
/// few minutes being neither.
#[derive(Clone, Debug)]
pub struct Waiting {
    pub id: Hash32,
    /// What leaves this key when a block carries it: what is being paid, and
    /// the fee with it.
    pub amount: Amount,
    /// What it holds meanwhile, which is more. The difference comes back as
    /// change, and comes back only when a block carries it.
    pub committed: Amount,
    /// Whether this wallet's own node holds it now, which is what lets it
    /// offer it to peers.
    ///
    /// False for a payment the node let go of and would not take back, and
    /// for one an earlier run wrote down that the node has not taken yet. Its
    /// notes are held either way: a peer may still hold the payment, and a
    /// second one built from other notes would then pay twice.
    pub pooled: bool,
    /// Why this wallet's node does not hold it, in words, when it does not.
    pub why: Option<String>,
    /// The block from which its notes come back to the balance, when this
    /// wallet's node has refused to take it back.
    pub held_until: Option<u64>,
}

/// A payment this wallet handed over that no block carried, and that it has
/// stopped waiting on.
///
/// Said rather than dropped. A payment that vanished from the list of waiting
/// ones while the balance went back up looked exactly like one a block had
/// carried, until no `sent` line arrived, and nobody was told it was not
/// coming.
#[derive(Clone, Debug)]
pub struct NotCarried {
    pub id: Hash32,
    /// What it would have taken from this key: the payment and its fee.
    pub amount: Amount,
    /// Why this wallet stopped waiting on it.
    pub why: String,
    /// The block at which it did.
    pub at: u64,
}

/// An account this wallet had written down and did not read back, and where
/// it went.
///
/// Moved before anything could save over it. What it holds is the only record
/// of where this key's fallen notes sit, and every reason a file fails to read
/// back leaves it worth having: the version that wrote it reads it, the fault
/// that stopped it opening can be mended, or somebody wants to see what the
/// disk did to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetAside {
    /// Why it was not read back.
    pub why: Discarded,
    /// Where it is now, under a name nothing writes to.
    pub kept_as: PathBuf,
}

/// Where this wallet's node has got to.
#[derive(Clone, Debug)]
pub struct Progress {
    pub height: Option<u64>,
    pub peers: usize,
    pub joining: Joined,
    /// What the node has still to check before it stands behind the ledger it
    /// was handed.
    ///
    /// Asked for because joining reports itself done while this is set: the
    /// ledger arrived whole and it is in the chain, and none of that is this
    /// node having checked it. A wallet showing a height and a balance out of
    /// a ledger nobody here validated is doing the one thing this library says
    /// it does not do.
    pub probation: Option<Probation>,
    /// The rules this software turned out not to have, if it met any.
    pub outdated: Option<Outdated>,
    /// Why the node cannot get on from where it stands, if it cannot.
    pub stranded: Option<Stranded>,
    /// What the node under this wallet was writing when its disk last refused
    /// it, if it did.
    ///
    /// A node whose disk is full keeps validating and keeps climbing, and
    /// writes nothing. From the outside that is a wallet working normally,
    /// until the machine restarts and comes back where the disk left off.
    pub unwritten: Option<Unwritten>,
    /// What the node under this wallet could not read back off its own disk,
    /// if it failed to.
    ///
    /// This wallet's list of what it was paid is read block by block off that
    /// disk, and a block it will not give back stops the reading there and
    /// leaves it there: skipping over it is not on offer, because which notes
    /// are this key's is built up as the blocks go past, and a history with a
    /// hole in it would go on calling a stranger's transfer ours. The balance
    /// beside it stays right, because it is counted from the chain and not
    /// from this account.
    ///
    /// So what it looks like is a page saying "still reading" about blocks it
    /// is not going to read, next to a height that keeps climbing, for ever.
    pub unread: Option<Unread>,
    /// Whether the blocks the node is refusing say this machine's clock is
    /// behind the network's, if enough of them came from enough peers, or if
    /// the one it refused was the network's first.
    ///
    /// A block dated too far past the reading machine's clock is refused, so
    /// a wallet on a slow clock refuses every honest block from the moment the
    /// chain moves past its clock. What it shows is a height that has stopped
    /// beside the balance of a chain the network has left, and payments to its
    /// owner never arrive. `cairnd` has named this since the node learned to
    /// count it, and the wallet, where the balance is read, did not.
    pub clock_behind: Option<Behind>,
    /// Blocks the node met that this build has no rules to judge, if enough of
    /// them came from enough peers to mean anything.
    pub unjudged: Option<Unjudged>,
    /// Whether nobody can show this node the work behind the chain, if enough
    /// showings from enough peers failed the same way to mean anything.
    ///
    /// A wallet starting for the first time joins by being shown that, and
    /// falls back to reading the chain block by block when it cannot be. From
    /// the outside those are the same thing: a wallet with no balance yet,
    /// taking a long time. This is the difference said out loud.
    pub unweighable: Option<Unweighable>,
    /// Whether this wallet's own account of what it was paid is reaching the
    /// disk.
    ///
    /// It keeps working from memory when it is not, which is right: refusing
    /// to show a balance because a file will not write helps nobody. Saying
    /// nothing is not right. This account is the only record of what this key
    /// was paid outside the chain itself, and a wallet that has stopped
    /// keeping it is one restart away from reading its way back from the
    /// oldest block its node still holds.
    pub keeping_its_account: bool,
    /// Why the account this wallet had written down was not read back, if it
    /// was there and was not used, and where it was put.
    ///
    /// Set once at start and left set, because what it costs does not go away
    /// when the rescan catches up: the movements below where the reading
    /// restarts, and the places of the notes that fell before it, are missing
    /// whatever the height says afterwards, until that file or a backup is
    /// put back.
    pub lost_its_account: Option<SetAside>,
}

/// The line for a wallet whose machine's clock is behind the network's.
///
/// It names something outside the program, which no other line here does,
/// and it is the one reading a person cannot make from the outside: a wallet
/// on a slow clock shows a height and a balance exactly like one whose peers
/// have gone quiet, and the two are mended in different places.
fn clock_is_slow(behind: &Behind) -> String {
    let out_by = behind.seconds.saturating_sub(behind.drift);
    if behind.own_first_block {
        return format!(
            "The clock on this machine is behind the day this network opened, by at least \
             {out_by} seconds: this wallet refused the network's first block, which is \
             written into this program and which nobody sent it. Until the clock is right it \
             cannot follow the chain at all, so there is no balance to show. Set the time on \
             this machine and start the wallet again. Nothing is lost and the key file is not \
             touched."
        );
    }
    format!(
        "The clock on this machine looks at least {out_by} seconds slow. {} blocks from {} \
         different peers were refused for being dated ahead of it, the furthest by {} \
         seconds, where the rules allow {}. Until the clock is right this wallet cannot \
         follow the chain: the height beside this has stopped, payments made to you since \
         will not appear, and the balance is the one it had then. Anyone can write a date \
         into a block, so this is a reason to look at the clock rather than a verdict. \
         Nothing is lost and the key file is not touched.",
        behind.blocks, behind.peers, behind.seconds, behind.drift,
    )
}

/// The line for a wallet whose own account of what it was paid did not read
/// back.
///
/// Its own function because the reasons need different sentences and the one
/// thing they must not do is share a vague one: an operator told their disk is
/// suspect looks at hardware, and one told their wallet is a version behind
/// looks at the version.
fn lost_its_account(lost: &SetAside) -> String {
    let because = match lost.why {
        Discarded::BeforeTheStamp => {
            "It was written by an older version of this wallet, which did not stamp \
             the file, and this one only reads back a file it can tell is the one it \
             wrote. This happens once."
        }
        Discarded::DidNotVerify => {
            "It was there and its contents were not the ones this wallet wrote, which \
             means the disk changed it. This is worth looking into."
        }
        Discarded::FromANewerVersion => {
            "It was written by a newer version of this wallet and holds things this \
             one has no reader for. The file is whole and your disk is fine, and the \
             newer version reads it again if it is put back as history.dat."
        }
        Discarded::WouldNotOpen => {
            "It is there and would not open, so nothing here has read a byte of it: a \
             permission this wallet does not have, a disk that would not answer, or a \
             name something else has taken. This is worth looking into."
        }
    };
    format!(
        "This wallet did not read back the account it had written down. {because} It has \
         been moved aside, to {}, and nothing will write over it. This wallet is reading \
         the chain again from the oldest block its node still holds. Money this key was \
         paid that had fallen out of the set every node holds long before that block is \
         not counted in the balance beside this, and this wallet cannot find it on its \
         own: where it fell was written down only in that account. A backup of \
         history.dat finds it again: close the wallet, put the backup in its data \
         directory, and start it again. Nothing is lost on the chain and the key file is \
         not touched.",
        lost.kept_as.display()
    )
}

impl Progress {
    /// What is wrong with the numbers beside this, in words a face can show
    /// without knowing what a node is.
    ///
    /// All of these look, from the outside, exactly like a wallet that is
    /// working: a height, a balance, and no complaint. Some of them mean the
    /// height stopped moving some time ago and will not start again, and one
    /// means the balance is a stranger's word rather than this wallet's own
    /// reading. None of them is worth hiding to keep a page tidy.
    ///
    /// Only one line is shown, so the order is a ranking, and the ranking is
    /// what the numbers beside it are worth. First the two that mean this
    /// wallet has stopped following the chain and will not start again. Then
    /// the one that means the number is not this wallet's own reading at all,
    /// and then the one that means it is this wallet's reading of a chain the
    /// network has left. Then the ones that mean the number is right and
    /// something else is at risk, and last the two about this wallet's own
    /// account. Those can mean money missing from the number, which by that
    /// ranking would put them higher. They stay last because each can sit
    /// there a long time, the lost account's for the whole run, and above the
    /// others it would hide a full disk or a slow clock, each mended by doing
    /// something now, for as long as it sat there.
    ///
    /// Probation used to be last of all, under three lines that say in as many
    /// words that the balance is right. It is set whenever the node under this
    /// wallet joined a chain rather than reading one, which is most of the
    /// first hour of every join, so a wallet whose disk was full or whose
    /// account file would not write was told "the balance beside this is right
    /// for the chain as it stands" while it was showing a stranger's account of
    /// somebody's money. The line above the money must never be the one that
    /// vouches for it.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        if let Some(outdated) = self.outdated {
            return Some(too_old_for_this_chain(&outdated, self.height.is_some()));
        }
        if let Some(stranded) = self.stranded {
            return Some(format!(
                "This wallet was handed the ledger at block {}, and had to check its own way to \
                 block {} before it could stand behind it. The blocks in between never arrived, \
                 and it holds nothing below block {}, so there is no other way to reach them. \
                 The balance shown is not one this wallet has checked. Close this wallet, delete \
                 everything in its data directory except history.dat, which is its own account \
                 of this key and the only record of where its fallen notes sit, and start it \
                 again from a peer you trust. The key file is a separate file and is not \
                 touched by that.",
                stranded.anchor, stranded.settles_at, stranded.anchor
            ));
        }
        if let Some(probation) = self.probation {
            return Some(format!(
                "This wallet has not yet checked the chain it is showing you. It was handed the \
                 ledger at block {} and has checked {} of the {} blocks above it that it has to \
                 check first. Until it has, the balance below is somebody else's account of your \
                 money rather than this wallet's own. It carries on by itself; wait for this \
                 line to go before believing the number.",
                probation.anchor,
                probation.checked(),
                probation.owed()
            ));
        }
        // Above the lines that say the balance is right, because under a slow
        // clock it is not: it is this wallet's own reading of a chain the
        // network has left. `cairnd` prints every line it has and puts this
        // one below the disk; here only one is shown, and the disk's line
        // would tell the person the balance is right for the chain as it
        // stands.
        if let Some(behind) = &self.clock_behind {
            return Some(clock_is_slow(behind));
        }
        if let Some(unwritten) = &self.unwritten {
            let kept = unwritten.written_through.map_or_else(
                || "nothing at all".to_owned(),
                |height| format!("block {height}"),
            );
            let lost = if unwritten.within_reach {
                "They can still reach it if the room comes back."
            } else {
                "The node has stopped rather than fall further behind, so nothing \
                 done now will put them on the disk, and a restart asks the network \
                 for them."
            };
            return Some(format!(
                "The disk under the node this wallet runs is not taking what it writes. \
                 It said: {}. The chain has reached block {} and the disk holds {}, so {} \
                 blocks have been accepted and not kept, and a restart begins at the \
                 disk's number. {} The balance beside this is right for the chain as it \
                 stands; what is at risk is having to read it all again.",
                unwritten.because, unwritten.reached, kept, unwritten.blocks, lost
            ));
        }
        if let Some(unread) = &self.unread {
            return Some(format!(
                "The disk under the node this wallet runs will not give back the block at \
                 {}. It said: {}. Nothing has been deleted, and the amount beside this is \
                 still right: it is counted from the chain rather than from the list of \
                 payments below. The list is what stops. It is read one block at a time and \
                 it cannot step over one, so it will sit where it is however long the page \
                 says it is still reading, and payments made after that block will not \
                 appear in it. Close this wallet and start it again: that reads the disk \
                 afresh, and if this comes back, the disk on this machine is what needs \
                 looking at.",
                unread.height, unread.because,
            ));
        }
        if let Some(unjudged) = &self.unjudged {
            return Some(format!(
                "This program looks too old for the chain it is on. It met {} blocks \
                 built under rules it does not have, from {} different peers over {} \
                 seconds, the newest of them written for version {} where this build \
                 knows version {}. Nothing has stopped: anyone can write a version \
                 number into a block, so this is a reason to look rather than a verdict. \
                 If the height beside this has also stopped moving, install a newer \
                 version. Nothing on disk is lost and the key file is not touched.",
                unjudged.blocks, unjudged.peers, unjudged.over, unjudged.version, unjudged.known
            ));
        }
        if let Some(unweighable) = &self.unweighable {
            return Some(nobody_could_show_it(unweighable));
        }
        if !self.keeping_its_account {
            return Some(
                "This wallet cannot write down its own account of what you have been \
                 paid. The balance beside this is still right, and what this wallet has \
                 learned since the file was last written is kept in memory only: if the \
                 wallet is closed before this is mended, that is gone, including where \
                 any note of this key fell out of the set every node holds in that time, \
                 which is money this wallet then cannot find on its own. The usual cause \
                 is a disk with nothing left on it."
                    .to_owned(),
            );
        }
        if let Some(lost) = &self.lost_its_account {
            return Some(lost_its_account(lost));
        }
        None
    }
}

/// How much of the chain this key's own account of itself covers.
///
/// A history that is behind and does not say so is worse than one that is
/// short and does: a person reading a list headed "what happened, newest
/// first" whose newest entry is a hundred blocks old has been told something
/// untrue about their own money.
#[derive(Clone, Copy, Debug)]
pub struct Covered {
    /// The first height it could read, or `None` if it has read nothing.
    pub from: Option<u64>,
    /// The newest height it has read.
    pub through: Option<u64>,
    /// The height below which the list of movements may be missing entries,
    /// because the node had let go of blocks this account still needed.
    ///
    /// Apart from `from`, which says where the account starts. A gap in the
    /// middle is a third thing: the blocks below it were read and their
    /// movements are listed, and moving `from` past them would be as untrue as
    /// leaving it where it was.
    pub missed_below: Option<u64>,
    /// Where the chain itself has got to.
    pub tip: Option<u64>,
}

impl Covered {
    /// Blocks the chain has that the account has not read.
    #[must_use]
    pub fn behind(&self) -> u64 {
        match (self.tip, self.through) {
            (Some(tip), Some(through)) => tip.saturating_sub(through),
            (Some(tip), None) => tip.saturating_add(1),
            _ => 0,
        }
    }
}

/// What a wallet that holds nothing at all says about it, given where its
/// account of this key begins.
///
/// Said here once for both faces. The page told somebody restored from the
/// key alone to check the height, and the command line to check the network,
/// and neither is where the money is: an account that begins above the first
/// block never read the blocks that paid this key before it, and a note from
/// then that has fallen out of the set every node holds has nothing to name
/// it by but the account file that recorded it.
#[must_use]
pub fn nothing_here_yet(covered: &Covered) -> String {
    match covered.from {
        Some(from) if from > 0 => format!(
            "Nothing here yet. This wallet's account of this key begins at block {from}. If \
             this key was paid before that, money that has since fallen out of the set every \
             node holds may be missing here, and only a history.dat that recorded it can find \
             it: close the wallet, put a backup of that file in its data directory, and run \
             this again. Otherwise, check that the wallet reached a peer and caught up to the \
             height you expect."
        ),
        _ => "Nothing here yet. If this key should hold something, check that the wallet \
              reached a peer and caught up to the height you expect."
            .to_owned(),
    }
}

/// What a spend did, once it has left.
///
/// It has left, and it has not arrived. A transfer handed to the network waits
/// in a pool until a miner puts it in a block, which takes minutes, and none
/// of it has happened while this is being read. Whatever shows this has to say
/// so: a face that reports a payment as done is a face that has somebody hand
/// over the goods.
#[derive(Clone, Copy, Debug)]
pub struct Sent {
    pub id: Hash32,
    pub amount: Amount,
    pub fee: Amount,
    pub change: Amount,
    /// Notes gathered to cover it, and how many needed a proof.
    pub notes: usize,
    pub from_cold: usize,
    /// Whether this wallet got it as far as a peer: at least one connected
    /// peer's outbound queue accepted it, and the wallet then waited for that
    /// queue to be written to the socket.
    ///
    /// False means nobody was offered it: nobody has it. It used to be read
    /// off the peer count, which answers the question "was anybody connected
    /// five seconds after the one broadcast" and not the question its own name
    /// asks.
    ///
    /// True is a socket write and no more. No message in the protocol answers
    /// a transfer, so a peer that refused it and a peer that kept it are the
    /// same here, and only a block confirms anything. Whatever shows this
    /// says "offered to", never "handed to the network".
    pub handed_on: bool,
    /// How many peers it was written to.
    pub offered: usize,
}

/// A path somebody rebuilt for this wallet, if it still reaches the set as it
/// stands.
///
/// Checked rather than remembered, and checked here rather than where it
/// arrived. A path folds from the place a note sits up to a single value the
/// whole set comes to, and that value changes every time a note falls
/// anywhere, so a path that was right a minute ago can be wrong now. This is
/// the same check the network itself will make when the note is spent, which
/// is why doing it here is worth anything: a wallet that offered a stale one
/// would be building a payment nobody will carry.
fn current(
    rebuilt: &BTreeMap<NoteId, (u64, ForestProof)>,
    state: &cairn_ledger::LedgerState,
    id: NoteId,
    note: Note,
) -> Option<(u64, ForestProof)> {
    let (position, proof) = rebuilt.get(&id)?;
    let leaf = cairn_ledger::state::cold_leaf(&id, &note);
    state
        .cold()
        .verify(*position, leaf, proof)
        .then(|| (*position, proof.clone()))
}

/// What the history is written to, inside the wallet's own directory.
///
/// Half of a wallet's backup: [`keyfile::back_up`] copies it with the key.
const HISTORY_FILE: &str = "history.dat";

/// How long a wallet waits for somebody to rebuild the paths it is missing.
///
/// One round trip on connections that are already open, so this is generous
/// rather than tight. What it is generous for is the case where nobody
/// connected keeps the record and the node has to open a connection to
/// somebody who does before it can ask at all.
const RECOVERY_PATIENCE: Duration = Duration::from_secs(3);

/// How long between two attempts at the same thing.
///
/// A page redraws itself every second, and each redraw counts the money. Asking
/// the network every time would be a wallet with an awkward note in it sending
/// a stranger a question a second for as long as it was left open. Fifteen
/// seconds is short enough that somebody who has just connected to an
/// archivist sees their money come back while they are still looking at the
/// screen.
const RECOVERY_PAUSE: Duration = Duration::from_secs(15);

/// Blocks read into the history in one go.
///
/// A wallet catching up on a long absence reads them in batches rather than
/// holding the chain while it walks the lot, so the page stays answerable and
/// the next block still arrives.
///
/// Public so that the test which holds it can count against the number rather
/// than against a copy of it: a copy is a second place the same fact lives,
/// and the one that moves is never the copy.
pub const CATCH_UP_BATCH: u64 = 512;

/// How long the chain has to sit still, with somebody to ask, before catching
/// up counts as done.
///
/// Public for the reason [`CATCH_UP_BATCH`] is: the test that holds the wait to
/// it counts against the number rather than against a copy of it.
pub const SETTLED_FOR: Duration = Duration::from_secs(2);

/// How far above what the network asks a fee may go before the wallet stops
/// and makes sure it was meant.
///
/// Wide on purpose. Paying several times the floor to be carried sooner is an
/// ordinary thing to want, and a wallet that questioned it would teach its
/// owner to wave the question away, which is the state in which the fee that
/// really was a slip goes through.
const STEEP_MULTIPLE: u64 = 100;

/// Rounds the blank-fee quote is allowed before it gives up and lets sending
/// name the number instead.
///
/// Two is the usual answer and three is the most that has been seen: the fee
/// only ever moves the quote by making the spend reach for another note, and
/// there are not many notes to reach for.
const QUOTE_ROUNDS: usize = 8;

/// How long a payment this wallet's node holds goes without being offered to
/// its peers again, when no peer has arrived since.
///
/// A peer arriving is the reason that matters and it is acted on at once:
/// nothing gossips a pool, so a peer that connects after a payment was handed
/// over is never told of it otherwise. This is for the rest, a peer that was
/// offered it and dropped it, and costs each peer one message a minute for as
/// long as the payment waits.
const OFFER_PAUSE: Duration = Duration::from_secs(60);

/// What the page and the command line say about a payment this wallet is
/// waiting on that its own node does not hold, when its node has said nothing
/// against it.
const NOT_IN_THE_POOL: &str = "most often because it had no room for it. It is handed over \
     again each time this wallet is looked at, and offered to its peers once it is taken";

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
    /// Whether the last attempt to write it down worked.
    wrote_history: Mutex<bool>,
    /// Why the account on disk was not read back at start, if it was not, and
    /// where it was moved.
    lost_its_account: Option<SetAside>,
    /// Paths somebody else rebuilt, for notes this wallet's node cannot place.
    ///
    /// Held here rather than handed to the node, because the node has no way
    /// to keep them current: a path is worth what it is worth against the set
    /// as it stands, and this node's cold set moves every time a note falls
    /// anywhere. So each one is checked again, against the set as it stands,
    /// every time the money is counted. One that has gone stale is simply not
    /// offered, and asking again costs one message.
    rebuilt: Mutex<BTreeMap<NoteId, (u64, ForestProof)>>,
    /// What came of the last time this wallet asked.
    ///
    /// Kept because a face reads this as often as it redraws, and the asking
    /// is a round trip to a stranger.
    last_recovery: Mutex<Asked>,
    /// The payments this wallet handed over and the chain has not settled,
    /// as written down beside the account.
    pending: Mutex<Pending>,
    /// Where that record is written down.
    pending_file: PathBuf,
    /// What became of a record that was there at start and did not read
    /// back, if one did not.
    pending_set_aside: Option<pending::NotReadBack>,
    /// Whether the last attempt to write the record down worked.
    wrote_pending: Mutex<bool>,
    /// How many peers the waiting payments were last offered to, and when.
    offered: Mutex<(usize, Option<Instant>)>,
}

/// The places one question to the network carries, out of everything this
/// wallet would like to ask about.
///
/// `Node::recover_proofs` caps the list at [`MAX_PROVEN`] on the way in, which
/// is right for it: one message carries that many and a caller that asked
/// about more would otherwise have its question truncated by whoever answered
/// it. What the cap does not do is tell this wallet which half is which, and
/// this wallet is the only party that needs to know.
fn one_question(wanted: &[(u64, Hash32)]) -> &[(u64, Hash32)] {
    wanted.get(..wanted.len().min(MAX_PROVEN)).unwrap_or(wanted)
}

/// The places that were put to the network and came back without an answer.
///
/// Takes everything the wallet wanted to ask about and does the cut itself,
/// rather than trusting a caller to hand it the asked-about half. That is the
/// whole repair: what used to stand here was filled from `wanted`, which is a
/// different set the moment there are more than [`MAX_PROVEN`] of them, and
/// there was nothing in the shape of the call to say which of the two it
/// should have been.
///
/// What it feeds is the decision to wait. [`Asked::unresolved`] says "the
/// places that were asked about and not answered for", and the pause reads it
/// as exactly that: a wallet stuck on the same places with the same peers
/// would get the same nothing, so waiting is right. For a place nobody was
/// asked about, waiting buys nothing at all, and a wallet with a hundred
/// stranded notes spent [`RECOVERY_PAUSE`] between each batch of sixty four
/// it had never put a question about.
fn still_outstanding(
    wanted: &[(u64, Hash32)],
    answered: &BTreeMap<u64, ForestProof>,
) -> BTreeSet<u64> {
    one_question(wanted)
        .iter()
        .map(|(at, _)| *at)
        .filter(|at| !answered.contains_key(at))
        .collect()
}

/// The last time this wallet asked the network for paths, and what came of it.
#[derive(Clone, Debug, Default)]
struct Asked {
    report: Recovery,
    /// When, so a face redrawing itself once a second does not send a stranger
    /// a question once a second.
    at: Option<Instant>,
    /// The places that were asked about and not answered for.
    ///
    /// What decides whether asking again is worth anything. A wallet stuck on
    /// the same places, with the same peers, would get the same nothing, and
    /// waiting is the right answer. A wallet stuck on a place that was
    /// answered for last time is a different matter: the path it was given has
    /// gone stale, which happens whenever enough notes fall to change the
    /// shape of the set, and its owner is looking at money that worked a
    /// moment ago. That one asks again at once.
    unresolved: BTreeSet<u64>,
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
        let (history, discarded) = History::load(&history_file);
        // Before anything can save, since a save renames a new account over
        // this name. A file that did not read back is the only record of where
        // this key's fallen notes sit, and it is moved, never written over.
        // One that cannot even be moved stops the wallet here, which is the
        // one way left of not writing over it.
        let lost_its_account = discarded
            .map(|why| {
                History::set_aside(&history_file)
                    .map(|kept_as| SetAside { why, kept_as })
                    .map_err(|error| {
                        WalletError::CouldNotStart(format!(
                            "{} did not read back, and moving it aside to keep it did not \
                             finish: {error}. This wallet has not started, so nothing has \
                             written over it: it is under that name, or beside it with \
                             .unread- and a number after it. Move it somewhere safe and start \
                             the wallet again.",
                            history_file.display()
                        ))
                    })
            })
            .transpose()?;
        let pending_file = data.join(pending::PENDING_FILE);
        let (pending, pending_set_aside) = Pending::load(&pending_file);
        Ok((
            Self {
                node,
                secret,
                params,
                history: Mutex::new(history),
                history_file,
                wrote_history: Mutex::new(true),
                rebuilt: Mutex::new(BTreeMap::new()),
                last_recovery: Mutex::new(Asked::default()),
                lost_its_account,
                pending: Mutex::new(pending),
                pending_file,
                pending_set_aside,
                wrote_pending: Mutex::new(true),
                offered: Mutex::new((0, None)),
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
    /// And worked out more than once, because the fee is part of what has to
    /// be covered. Pricing a transfer that gathers enough for the amount and
    /// then sending one that gathers enough for the amount and the fee are two
    /// different transfers whenever the fee crosses a note boundary, and the
    /// second is the larger. Quoting the first was a number this wallet then
    /// refused, and it refused it on exactly the round amounts people type. So
    /// the quote is fed back in until the transfer it prices is the transfer
    /// that would be built, which takes two passes and settles.
    ///
    /// Exactly what the pool asks now, and no more, which is the number to
    /// show beside a fee and the least a named fee may be. It is not the fee
    /// to pay when none is named: see [`Wallet::fee_for`].
    pub fn floor_for(&self, recipient: PublicKey, amount: Amount) -> Amount {
        self.quoted(recipient, amount, |draft| draft.floor)
    }

    /// What this wallet pays to carry `amount` to `recipient` when nobody
    /// names a fee.
    ///
    /// Not the floor. The pool asks the floor again of every transfer it
    /// holds after every block, and the floor moves: a note the payment
    /// spends that falls out of the hot set before a block carries it frees
    /// no place any more, and the payment weighs a place more. A payment
    /// paying exactly the floor was let go of by every pool the block after
    /// that, and on a small hot set that is a matter of seconds. So the quote
    /// carries a place's worth over the floor for every place a falling note
    /// can add, which is what [`margin_of`] works out.
    ///
    /// And when the pool is full, enough to rank above the cheapest transfer
    /// it holds: a full pool makes room only for a better rate, and a quote at
    /// the floor into a pool kept full at the floor was refused for as long
    /// as somebody paid to keep it so.
    pub fn fee_for(&self, recipient: PublicKey, amount: Amount) -> Amount {
        self.quoted(recipient, amount, |draft| {
            let cheapest = self.node.with_chain(|chain| {
                crowded(
                    chain.pool_len(),
                    chain.pool_bytes(),
                    cairn_chain::pooled_cost(draft.bytes, draft.spending.len()),
                    chain.pooled_by_rate().next().map(|(rate, _)| rate),
                )
            });
            asking(draft, cheapest)
        })
    }

    /// The fee `price` asks of the transfer this wallet would build, fed back
    /// in until the transfer it prices is the one that would be built.
    fn quoted(
        &self,
        recipient: PublicKey,
        amount: Amount,
        price: impl Fn(&Draft) -> Amount,
    ) -> Amount {
        let holdings = self.holdings();
        let mut fee = Amount::ZERO;
        for _ in 0..QUOTE_ROUNDS {
            let Some(needed) = amount.checked_add(fee) else {
                return fee;
            };
            // Not enough to cover the amount and this fee together. Sending is
            // where that is said, with the numbers; quoting a larger fee here
            // would only make it worse.
            let Ok(draft) = self.draft(&holdings, recipient, amount, needed) else {
                return fee;
            };
            let asked = price(&draft);
            if asked <= fee {
                return fee;
            }
            fee = asked;
        }
        fee
    }

    /// The transfer this wallet would build to pay `amount` while gathering
    /// `needed`, unsigned and in selection order, with what it costs.
    ///
    /// Unsigned costs nothing in accuracy: a signature is a fixed number of
    /// bytes whether it has been made or not, so what this measures is what
    /// the finished transfer weighs. Selection order costs nothing either,
    /// because shuffling moves bytes around without adding any.
    fn draft(
        &self,
        holdings: &Holdings,
        recipient: PublicKey,
        amount: Amount,
        needed: Amount,
    ) -> Result<Draft, NoDraft> {
        let (spending, gathered) =
            select(&holdings.notes, needed, self.params.max_inputs_per_transfer)?;
        let change = gathered.checked_sub(needed).ok_or(NoDraft::Short)?;
        let mut outputs = vec![Note::new(amount, recipient)];
        if change > Amount::ZERO {
            outputs.push(Note::new(change, self.address()));
        }
        let inputs = spending.iter().map(Held::as_input).collect();
        let transfer = Transfer::new(inputs, outputs);
        let bytes = transfer.encode().len();
        let freed = spending.iter().filter(|held| held.fallen.is_none()).count();
        let weight = cairn_chain::transfer_weight(&transfer, bytes, freed);
        Ok(Draft {
            floor: cairn_chain::fee_floor(weight),
            margin: margin_of(freed, transfer.outputs.len()),
            weight,
            bytes,
            spending,
            change,
        })
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
            peers: self.node.peers_introduced(),
            joining: self.node.joining(),
            probation: self.node.probation(),
            outdated: self.node.outdated(),
            stranded: self.node.stranded(),
            unwritten: self.node.unwritten(),
            unread: self.node.unread(),
            clock_behind: self.node.clock_behind(),
            unjudged: self.node.unjudged(),
            unweighable: self.node.unweighable(),
            keeping_its_account: *self
                .wrote_history
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            lost_its_account: self.lost_its_account.clone(),
        }
    }

    /// Waits until the chain stops moving, or until patience runs out.
    ///
    /// A wallet that answered from a chain it had not finished reading would
    /// show a balance from the past, which for a wallet is a wrong answer
    /// rather than a slow one.
    ///
    /// A chain that has not arrived at all is not a chain that has stopped
    /// moving, and telling the two apart is the whole of what is careful here.
    /// A node being handed a ledger reports no height until the last piece of
    /// it lands, so its height sits at nothing for as long as the handover
    /// takes; read as a number that is not changing, that is a wallet giving
    /// up two seconds into a thirty second wait and answering nought. It is
    /// also what a peer that completes the handshake and then says nothing
    /// leaves behind, and there is no reason to make that free.
    ///
    /// That guard read "no height", and on both networks that exist it could
    /// never hold: their first block is written into the program and seated
    /// before anything arrives, so the height is block nought from the first
    /// moment and stays there for the whole of a handover. So the wait also
    /// goes on while a ledger is still arriving, and while any peer said, when
    /// it introduced itself, that its chain has more work than this one.
    /// "Stopped moving" and "the network's tip" were read as the same thing,
    /// and the number that tells them apart was in every handshake and thrown
    /// away. Anybody can write a number into a handshake, so a peer that lies
    /// about it can make a wallet wait out its patience and do nothing more.
    ///
    /// What the wait came to is returned, so a face can say so and a spend
    /// can refuse to be built from a chain still on its way.
    pub fn catch_up(&self, patience: Duration) -> Waited {
        // None for a patience past what the clock can count, which is a wait
        // with no deadline. It was the clock now, so the longest `--wait` a
        // person could type waited for nothing and then said no chain had
        // arrived in all that time.
        let deadline = Instant::now().checked_add(patience);
        let mut last = self.node.height();
        let mut still_since = Instant::now();
        let mut moved = false;

        loop {
            let look = self.look();
            if look.height != last {
                last = look.height;
                still_since = Instant::now();
                moved = true;
            }
            let still = still_since.elapsed();
            if settled(&look, still) {
                return Waited::Settled;
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return ran_out(&look, still, moved);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// What catching up reads each time it looks.
    fn look(&self) -> Look {
        Look {
            height: self.node.height(),
            // Peers that have introduced themselves, not sockets. A stranger
            // that connects to this wallet's listener and says nothing is not
            // somebody who could have sent the blocks it is waiting for, and
            // counting it cut every `--wait` short: the wallet then answered
            // `balance` and built `send` from whatever chain was on disk.
            peers: self.node.peers_introduced(),
            joining: self.node.joining(),
            work: self.node.total_work(),
            claim: self.node.best_claim(),
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
        //
        // Asked of the chain's own identifiers, which the node holds in memory
        // for every height a switch can reach and keeps in its header log
        // below that. It used to be asked of the block log: a read and a
        // decode of the newest block on every look, four times a page view,
        // to learn thirty two bytes, and a log the node trims from the front,
        // so a block replaced and then trimmed away read as unchanged.
        match history.fork(Some(tip), |height| self.node.id_at(height)) {
            None => {}
            Some(Fork::At(fork)) => {
                history.rewind_to(fork);
                self.write_history(&history);
            }
            Some(Fork::Deeper) => {
                // Below every block the account remembers, which one switch
                // cannot reach: an account written before it remembered more
                // than its newest block, or one that had to let go of its
                // oldest. The line is how deep a switch this node will follow
                // from the tip as it stands, and what the account keeps below
                // it is set out on `History::forget`.
                let reach = self.node.with_chain(cairn_chain::ChainStore::undo_limit);
                let settled_below = tip.checked_sub(reach);
                history.forget(settled_below);
                self.write_history(&history);
            }
        }

        let mut taken = 0usize;
        let stop = tip.saturating_add(1);
        while history.next() < stop && (taken as u64) < CATCH_UP_BATCH {
            let height = history.next();
            let Some(block) = self.node.archived_at(height) else {
                // Nothing to read here. If the node holds later blocks, the
                // history begins where they do rather than staying stuck.
                //
                // Where the node can be read from, and not where the branch it
                // follows begins. Those are different numbers on any node that
                // has let go of its oldest blocks, which is every node past
                // `--keep`: the branch still begins at zero and the log begins
                // wherever trimming left it. Asked the branch, this walked to a
                // height the node had nothing at, found the answer was not
                // above where it already stood, and stopped there for good. An
                // account that had to start over on such a node read no block
                // ever again, and the line that says it is reading the chain
                // again to rebuild itself was true of the intention only.
                //
                // The higher of the two, because a block below where the branch
                // begins is not on this chain whatever the log still holds.
                let first = self
                    .node
                    .blocks_from()
                    .into_iter()
                    .chain(self.node.with_chain(cairn_chain::ChainStore::branch_start))
                    .max();
                match first {
                    Some(first) if first > height => history.skip_to(first),
                    _ => break,
                }
                continue;
            };
            if !history.take(&block, mine) {
                // Not built on the block read before it: the chain switched
                // since this call looked. The next call finds where.
                break;
            }
            taken = taken.saturating_add(1);
        }

        if taken > 0 {
            self.write_history(&history);
        }
        drop(history);
        self.note_where_they_landed();
        taken
    }

    /// Reads to the tip rather than one batch of it, and says how much it took.
    ///
    /// [`Self::follow`] reads at most [`CATCH_UP_BATCH`] blocks, because that
    /// is how the lock is let go of often enough for the next block to arrive.
    /// Reading to the tip is calling it until it has nothing left, and that
    /// was written out at eighteen places in this crate as three tokens with
    /// no name: sixteen in tests and twice here. A copy is a second place the
    /// same fact lives, and the one that moves is never the copy.
    ///
    /// Bounded, which the eighteen were not. A turn that reads nothing ends
    /// this, and if a turn never stops reading the count ends it instead: a
    /// turn that reads takes at least one block, and a chain has no more
    /// blocks to take than it has heights. That is [`CATCH_UP_BATCH`] times
    /// the turns a full read needs, so the bound is nowhere near an honest
    /// read and squarely in front of one that cannot stop.
    ///
    /// The difference is what happens when the reading breaks. Unbounded, a
    /// wallet that could not move forward span here for ever: in a test that
    /// is a run which hangs instead of failing, and in a node it is a page
    /// that never answers. Bounded, both say so. What comes back at the bound
    /// is an account that is behind, which is what comes back the instant any
    /// of these return anyway: the chain moves on.
    pub fn follow_to_the_tip(&self) -> usize {
        let heights = self.node.height().map_or(0, |tip| tip.saturating_add(1));
        let mut taken = 0usize;
        for _ in 0..=heights {
            let read = self.follow();
            if read == 0 {
                break;
            }
            taken = taken.saturating_add(read);
        }
        taken
    }

    /// Writes down where this key's fallen notes landed, while the node can
    /// still say.
    ///
    /// It cannot always. A node keeps track of a fallen note for the owners it
    /// follows and for as long as it has room, and past that it lets the least
    /// valuable ones go; a node restarted from a ledger it wrote down keeps
    /// none of them at all, because where a note landed is a fact about this
    /// machine rather than about the chain and a ledger carries neither the
    /// asking nor the answer.
    ///
    /// The place is the half worth keeping. It is fixed for as long as the
    /// block the note fell in stands, while the path up to it moves every time
    /// another note falls, which is why nobody keeps paths for strangers and
    /// why the place is what a wallet has to be able to name later. A branch
    /// that wins over the block can put the note elsewhere, and whatever the
    /// node says now is written over what it said then.
    ///
    /// Walked rather than watched for, because there is nowhere to hang the
    /// watching: what the node knows is a map, and comparing it against this
    /// account is a pass over the wallet's own notes. Nothing is written
    /// unless something was learned.
    ///
    /// A pass over the node's notes rather than over this account's, which is
    /// the direction that matters. The node knows notes this account does not:
    /// a wallet reading a chain from a ledger it was handed starts at the
    /// anchor, and its node comes out of that handover holding the notes that
    /// fell in the window below it. Those are taken up here, value and all.
    fn note_where_they_landed(&self) {
        let mine = self.address();
        // The value travels with the place. A note this account never read the
        // block for is one the account cannot name without it, and those are
        // exactly the notes worth writing down: a wallet handed a ledger comes
        // out of the handover with a window of them that its node knows and
        // its own reading never saw.
        let landed: Vec<(NoteId, u64, Amount)> = self.node.with_chain(|chain| {
            chain
                .state()
                .watched_notes()
                .filter(|(_, _, note)| note.owner == mine)
                .map(|(id, position, note)| (id, position, note.value))
                .collect()
        });
        if landed.is_empty() {
            return;
        }
        let mut history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut learned = false;
        for (id, position, value) in landed {
            learned |= history.fell_at(id, value, position);
        }
        if learned {
            self.write_history(&history);
        }
    }

    /// This key's own account of what happened to it, newest first.
    ///
    /// Reads its way to the chain's tip rather than one batch of it. Reading
    /// in batches is how the lock is let go of often enough for the next block
    /// to arrive, and it was never meant to be how far the history goes: a
    /// wallet six hundred blocks behind showed the first five hundred and
    /// twelve, headed the list "what happened, newest first", and left the
    /// last eighty-eight out without a word.
    #[must_use]
    pub fn history(&self) -> Vec<Movement> {
        self.follow_to_the_tip();
        self.history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .movements()
            .copied()
            .collect()
    }

    /// What the history took back when the chain changed under it, newest
    /// first.
    ///
    /// Money that moved and then did not. Kept separately from the movements
    /// because it is not one: it describes a block nobody has any more.
    #[must_use]
    pub fn undone(&self) -> Vec<Movement> {
        self.history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .undone()
            .copied()
            .collect()
    }

    /// What the history covers, so a face can say what it does not rather than
    /// implying it covers everything.
    #[must_use]
    pub fn history_covers(&self) -> Covered {
        let tip = self.node.height();
        let history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let from = history.from();
        Covered {
            from,
            through: from.and(history.next().checked_sub(1)),
            missed_below: history.missed_below(),
            tip,
        }
    }

    /// Everything this key owns, and what part of it cannot move.
    ///
    /// The confirmed ledger is only half the answer. What is waiting in the
    /// pool has not happened, but the notes it holds are promised, and money a
    /// wallet shows as spendable had better be money it can spend.
    ///
    /// Looks after the payments this wallet handed over on the way, which is
    /// what [`Self::tended`] sets out: a face asks this every time it redraws,
    /// and that is how often a payment waiting on the network needs looking
    /// after.
    #[must_use]
    pub fn holdings(&self) -> Holdings {
        self.tended().holdings
    }

    /// The payments this wallet has handed over that no block carries yet.
    ///
    /// Read from this wallet's own record as well as from its node's pool.
    /// The pool is memory in this process, and the command line is a process
    /// that hands a payment over and exits: read from the pool alone, the
    /// next command knew nothing of the payment the last one made.
    #[must_use]
    pub fn waiting(&self) -> Vec<Waiting> {
        self.tended().waiting
    }

    /// The payments this wallet stopped waiting on without a block carrying
    /// them, newest first, for [`pending::NAMED_FOR`] blocks after it did.
    ///
    /// As the last look at the money left them: [`Self::holdings`] and
    /// [`Self::waiting`] are what look after the payments, and a face asks
    /// one of them first.
    #[must_use]
    pub fn not_carried(&self) -> Vec<NotCarried> {
        let mine = self.address();
        let mut named: Vec<NotCarried> = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ended()
            .filter_map(|one| {
                let (at, why) = one.ended.clone()?;
                // A payment to this key's own address takes only its fee.
                let amount = if one.to == mine {
                    one.fee
                } else {
                    one.amount.checked_add(one.fee).unwrap_or(one.amount)
                };
                Some(NotCarried {
                    id: one.id(),
                    amount,
                    why,
                    at,
                })
            })
            .collect();
        named.reverse();
        named
    }

    /// What to say when this wallet's record of the payments it handed over
    /// is not being kept, if it is not.
    ///
    /// A record that was there at start and did not read back is set aside
    /// rather than written over, and one that will not write leaves every
    /// payment in memory only. Either way the next start knows nothing of a
    /// payment made now, which is the defect the record exists to end, so it
    /// is said wherever the waiting payments are.
    #[must_use]
    pub fn payments_unkept(&self) -> Option<String> {
        let wrote = *self
            .wrote_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &self.pending_set_aside {
            Some(pending::NotReadBack::Moved(path)) => Some(format!(
                "This wallet's record of the payments it handed over did not read back, and was \
                 moved to {} rather than written over. A payment made before this start and not \
                 carried yet is not listed here, and its notes are counted as spendable: do not \
                 pay the same thing again until the chain shows whether it arrived.",
                path.display()
            )),
            Some(pending::NotReadBack::Stuck) => Some(
                "This wallet's record of the payments it handed over did not read back and could \
                 not be moved out of the way, so it is left as it is and nothing is written over \
                 it. Payments made now are kept in memory only, and a payment made before this \
                 start and not carried yet is not listed here: do not pay the same thing again \
                 until the chain shows whether it arrived."
                    .to_owned(),
            ),
            None if !wrote => Some(
                "This wallet cannot write down the payments it hands over. They are kept in \
                 memory only, so once it is closed the next start will not know a payment made \
                 now is waiting. The usual cause is a disk with nothing left on it."
                    .to_owned(),
            ),
            None => None,
        }
    }

    /// Forgets a payment if nobody was offered it, for a face about to close
    /// that says so. Says whether it forgot it.
    ///
    /// The command line exits once it has answered, and the pool goes with
    /// it, so a payment no peer's queue ever took is one nobody has: it tells
    /// the person so, and to run the command again. Kept in the record, the
    /// next start would hand that payment over as well, and the one run again
    /// would pay a second time from other notes. A payment any peer was
    /// offered may be carried whatever this wallet forgets, so that one is
    /// kept.
    pub fn forget_if_unoffered(&self, sent: &Sent) -> bool {
        if sent.handed_on {
            return false;
        }
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let forgot = pending.settle(&sent.id);
        if forgot {
            self.write_pending(&pending);
        }
        forgot
    }

    /// Writes the record of payments down, and remembers if it could not.
    ///
    /// Not over a record that was there and did not read back and could not
    /// be moved out of the way: what it held may be payments still waiting.
    fn write_pending(&self, pending: &Pending) {
        if self.pending_set_aside == Some(pending::NotReadBack::Stuck) {
            return;
        }
        let kept = pending.save(&self.pending_file).is_ok();
        *self
            .wrote_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = kept;
    }

    /// Counts the money, and looks after every payment this wallet handed
    /// over and the chain has not settled.
    ///
    /// Four things, each of which used to be nobody's job.
    ///
    /// A payment a block carried is taken off the record, and one whose notes
    /// something else spent is said to be not carried, since nothing will
    /// carry it now.
    ///
    /// A payment the pool no longer holds is handed to it again, with fresh
    /// evidence for each note it spends. What identifies a transfer, and what
    /// its signatures commit to, leave that evidence out, so the payment is
    /// the same one: a proof for a fallen note goes stale whenever the cold
    /// set moves, and a note that fell after the payment was made needs one
    /// it did not have. A pool that still refuses it says why, and the words
    /// are kept.
    ///
    /// A payment refused for [`pending::HELD_AFTER_REFUSAL`] blocks is let
    /// go of: its notes come back to the balance and it is named as not
    /// carried.
    ///
    /// And every payment the pool holds is offered to peers again when a peer
    /// has arrived since the last time. Nothing gossips a pool, so a payment
    /// made with nobody connected, or handed back to a pool at start, reached
    /// nobody, and the page said it was waiting for a block for as long as it
    /// stayed open.
    fn tended(&self) -> Reckoned {
        let reckoned = self.reckon();
        let Some(tip) = self.node.height() else {
            return reckoned;
        };
        let before = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for id in &reckoned.gone {
            self.settle_or_end(id, tip);
        }
        self.settle_the_carried();
        // Whether anything was handed back, which changes what the pool
        // holds and so what the money comes to.
        let mut handed_back = false;
        let live: Vec<Handed> = before.live().cloned().collect();
        for one in &live {
            let id = one.id();
            let pooled = reckoned
                .waiting
                .iter()
                .any(|waiting| waiting.id == id && waiting.pooled);
            if pooled {
                // Taken back by some other road, a peer passing it on again
                // among them, and so no longer refused: the wait before its
                // notes come back would otherwise run on and let go of a
                // payment the pool is holding.
                self.pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .taken_back(&id);
            } else if !reckoned.gone.contains(&id) {
                self.hand_back(one, &reckoned.promised, tip);
                handed_back = true;
            }
        }
        let changed = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.age(tip);
            let changed = *pending != before;
            if changed {
                self.write_pending(&pending);
            }
            changed
        };
        let reckoned = if changed || handed_back {
            self.reckon()
        } else {
            reckoned
        };
        self.offer_waiting(&reckoned.waiting);
        reckoned
    }

    /// Takes a payment whose notes are no longer this key's off the record:
    /// settled if a block this wallet read carried it, and named as not
    /// carried if not.
    fn settle_or_end(&self, id: &Hash32, tip: u64) {
        let made_at = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live()
            .find(|one| one.id() == *id)
            .map_or(0, |one| one.made_at);
        let (carried, read_all_of_it) = {
            let history = self
                .history
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let carried = history.movements().any(|movement| movement.id == *id);
            let read_all_of_it =
                read_every_block_since(history.next(), history.missed_below(), made_at, tip);
            (carried, read_all_of_it)
        };
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if carried {
            pending.settle(id);
            return;
        }
        let why = if read_all_of_it {
            "the notes it spends are no longer this key's on the chain as it stands, and no \
             block this wallet read carried it: another payment from this key spent them, or \
             the block that paid them was undone"
        } else {
            "the notes it spends are no longer this key's on the chain as it stands. This wallet \
             could not read every block since it was handed over, so whether one of them \
             carried it is not something it can say; the balance is counted from the chain and \
             is right either way"
        };
        pending.end(id, tip, why);
    }

    /// Takes off the record every payment named as not carried that a block
    /// this wallet read carried after all, from a peer that still held it.
    fn settle_the_carried(&self) {
        let ended: Vec<Hash32> = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ended()
            .map(Handed::id)
            .collect();
        let carried: Vec<Hash32> = {
            let history = self
                .history
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ended
                .into_iter()
                .filter(|id| history.movements().any(|movement| movement.id == *id))
                .collect()
        };
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in &carried {
            pending.settle(id);
        }
    }

    /// Hands a payment this wallet's node no longer holds back to it, and
    /// notes what the node said.
    ///
    /// As it was made first, and with fresh evidence for each note only if
    /// that is refused. A note that has just fallen can still be spent
    /// without a proof for a while, and a proof is bytes the fee has to
    /// cover, so evidence that is merely newer is not evidence that is
    /// better.
    fn hand_back(&self, one: &Handed, promised: &BTreeMap<NoteId, Held>, tip: u64) {
        let id = one.id();
        let mut fresh = one.transfer.clone();
        for input in &mut fresh.inputs {
            if let Some(held) = promised.get(&input.note_id) {
                input.witness = held.as_input().witness;
            }
        }
        let mut answer = self.node.submit_transaction(one.transfer.clone());
        if answer.is_err() && fresh != one.transfer {
            answer = self.node.submit_transaction(fresh);
        }
        note_the_answer(
            &mut self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            &id,
            tip,
            &answer,
        );
    }

    /// Offers every payment this wallet's node holds for it to its peers, when
    /// [`offer_due`] says it is time.
    fn offer_waiting(&self, waiting: &[Waiting]) {
        let peers = self.node.peers_introduced();
        let mut last = self
            .offered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if !offer_due(peers, *last, now) {
            last.0 = peers;
            return;
        }
        for one in waiting.iter().filter(|one| one.pooled) {
            self.node.offer_again(&one.id);
        }
        *last = (peers, Some(now));
    }

    /// Asks the network to rebuild what it takes to spend the notes this
    /// wallet's own node can no longer place, and says what happened.
    ///
    /// Money in this state is real, correct and unspendable, and until now the
    /// only thing a wallet did about it was name a service and leave its owner
    /// to go and find one. This is the wallet going and finding one.
    ///
    /// Nothing is trusted. What comes back is a path, and a path either folds
    /// to a value this wallet's own node worked out from the blocks it checked
    /// itself, or it is thrown away. So the question can be put to an
    /// anonymous stranger, which is the whole reason it is a question a node
    /// asks another node rather than a request to a website somebody has to
    /// keep running.
    ///
    /// Waits, because it is one round trip and there is nothing useful to do
    /// meanwhile, and asks again at most every [`RECOVERY_PAUSE`], because
    /// whatever is showing the balance calls this every time it redraws.
    pub fn recover_stranded(&self) -> Recovery {
        let holdings = self.holdings();
        if holdings.unprovable.is_empty() {
            let mut last = self
                .last_recovery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            last.report = Recovery::default();
            last.unresolved.clear();
            return Recovery::default();
        }

        // The place is what is asked about and the leaf is what the answer has
        // to fold to. Neither says whose money it is: a leaf is a hash, and a
        // place is a number, so what a wallet hands an archivist is a list of
        // positions in a set that archivist already holds in full.
        let wanted: Vec<(u64, Hash32)> = holdings
            .unprovable
            .iter()
            .filter_map(|one| {
                Some((
                    one.fell_at?,
                    cairn_ledger::state::cold_leaf(&one.id, &one.note),
                ))
            })
            .collect();
        {
            let last = self
                .last_recovery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let paused = last
                .at
                .is_some_and(|asked| asked.elapsed() < RECOVERY_PAUSE);
            // Three ways the pause does not apply, and each of them is a
            // moment somebody is waiting on. Asking about a place that was
            // answered for before means the path has gone stale rather than
            // that nobody has one. Somebody worth asking arriving is the whole
            // of what an empty-handed wallet was waiting for. And a wallet
            // that had nobody at all to ask has a fresh question the moment it
            // has anybody.
            // The half a question actually carries, on both sides of the
            // comparison. `unresolved` holds the places that were asked about
            // and not answered for, which `still_outstanding` was repaired to
            // mean: at most one message's worth of them. Reading it against
            // every place this wallet holds compares a set of any size with a
            // set of at most sixty four, so past that many the inclusion is
            // false whatever has happened and the wait never holds.
            //
            // A wallet with more than sixty four notes it cannot place is
            // exactly the one that needs the wait: it asked, got nothing, and
            // would put the same question to the same strangers on every
            // redraw of whatever is showing the balance.
            let asking_about: BTreeSet<u64> =
                one_question(&wanted).iter().map(|(at, _)| *at).collect();
            let same_question = asking_about.is_subset(&last.unresolved);
            let better_now = self.node.archiving_peers() > last.report.archivists
                || (last.report.asked == 0 && self.node.peers_introduced() > 0);
            if paused && same_question && !better_now {
                return last.report;
            }
        }

        let unplaceable = holdings.unprovable.len().saturating_sub(wanted.len());
        // Cut here rather than left to be cut on the way in. `recover_proofs`
        // takes the first [`MAX_PROVEN`] and drops the rest, which is right
        // for it and leaves this wallet unable to tell what it asked about
        // from what it merely wrote down.
        let asking = one_question(&wanted);
        let not_yet_asked = wanted.len().saturating_sub(asking.len());
        let answer = self.node.recover_proofs(asking, RECOVERY_PATIENCE);

        // Back from places to notes. The answer is about places because that
        // is all the answerer was told, and this wallet is the only party that
        // knows which of its notes each one is.
        let mut rebuilt = self
            .rebuilt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut mended = 0usize;
        for one in &holdings.unprovable {
            let Some(position) = one.fell_at else {
                continue;
            };
            let Some(proof) = answer.proofs.get(&position) else {
                continue;
            };
            rebuilt.insert(one.id, (position, proof.clone()));
            mended = mended.saturating_add(1);
        }
        drop(rebuilt);

        let recovery = Recovery {
            stranded: holdings.unprovable.len(),
            unplaceable,
            asked: answer.asked,
            archivists: answer.archivists,
            answered: answer.answered,
            rebuilt: mended,
            refused: answer.refused,
            not_yet_asked,
        };
        let mut last = self
            .last_recovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        last.unresolved = still_outstanding(&wanted, &answer.proofs);
        last.report = recovery;
        last.at = Some(Instant::now());
        recovery
    }

    /// What the last asking came to, without asking again.
    ///
    /// For a face that has already asked once and is redrawing.
    #[must_use]
    pub fn last_recovery(&self) -> Recovery {
        self.last_recovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .report
    }

    /// Writes the account down, and remembers if it could not.
    ///
    /// A wallet keeps working from memory when its disk is full, which is the
    /// right thing to do: refusing to show a balance because a file cannot be
    /// written would help nobody. What is not right is saying nothing. The
    /// account is the only record of what this key was paid that exists
    /// anywhere outside the chain, and a wallet that has stopped keeping it
    /// is one restart away from having to read its way back from the oldest
    /// block its node still holds.
    fn write_history(&self, history: &History) {
        let kept = history.save(&self.history_file).is_ok();
        *self
            .wrote_history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = kept;
    }

    /// One reading of the chain answering both, since the pool decides what is
    /// spendable and the notes decide what the pool is holding.
    #[allow(clippy::too_many_lines)]
    fn reckon(&self) -> Reckoned {
        // Before a coin of it is counted. This wallet's account answers for
        // what this key held as of the last block the account read, and every
        // line below reads it as what this key holds now. A note this key was
        // paid and a note a block carried away look identical from the
        // account, and only reading that block tells them apart.
        //
        // So a wallet that had spent money and not yet read the block carrying
        // the payment counted every note it spent back onto its own balance,
        // as `stranded`: real money the node cannot place. Four rewards of
        // fifty, a payment of a hundred and twenty, and a key that owns 79.5
        // was shown 229.5 with 150 of it stuck. The same notes then went onto
        // the list of places this wallet asks strangers to rebuild paths to,
        // which are places it no longer owns.
        //
        // `history` reads to the tip for the same reason and says so, and the
        // two disagreed inside one answer: the served page counted the money
        // out of an account that was behind and listed the movements out of
        // one that was not, in the same object.
        self.follow_to_the_tip();
        let mine = self.address();
        // This wallet's own account of what it has been paid, which is what
        // lets it notice a note the node has stopped following, and where each
        // one landed, which is what lets it ask about one.
        let (recorded, landed, unanswered): (
            BTreeMap<NoteId, Amount>,
            BTreeMap<NoteId, u64>,
            BTreeSet<NoteId>,
        ) = {
            let history = self
                .history
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let held: BTreeMap<NoteId, Amount> = history.held().collect();
            let landed = held
                .keys()
                .filter_map(|id| Some((*id, history.where_it_fell(id)?)))
                .collect();
            let unanswered: BTreeSet<NoteId> = history.unaccounted().collect();
            (held, landed, unanswered)
        };
        // Paths somebody else rebuilt for this wallet. Each is checked below
        // against the set as it stands rather than remembered as good, because
        // the set moves whenever a note falls and a path is worth exactly what
        // it is worth now.
        let rebuilt = self
            .rebuilt
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default();
        // The payments this wallet wrote down and is still waiting on. Taken
        // before the chain, and let go of, so no lock here is held across
        // another.
        let handed: Vec<Handed> = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live()
            .cloned()
            .collect();
        let (holdings, waiting, answered, gone, promised_notes) = self.node.with_chain(|chain| {
            let state = chain.state();
            let mut held: Vec<Held> = state
                .hot_notes()
                .filter(|(_, entry)| entry.note.owner == mine)
                .map(|(id, entry)| Held {
                    id,
                    note: entry.note,
                    fallen: None,
                })
                .collect();

            // Notes that have fallen out of the set every node keeps. Ours
            // either way; spendable only while a path to one can be produced,
            // by this node or by somebody who rebuilt it for us.
            let mut unprovable: Vec<Unprovable> = Vec::new();
            // Three places a path can come from, in the order they are worth
            // trying. What the node says it is watching is this node's own
            // bookkeeping and is taken as it stands. What this wallet wrote
            // down about where a note landed is trusted about as far as the
            // file it came out of, so a path found through it is folded before
            // it is offered. And a path somebody else rebuilt is folded for
            // that reason and one more: the set moves whenever a note falls
            // anywhere, so it may simply have gone stale since it arrived.
            let place = |id: NoteId, note: Note, watched: Option<u64>| {
                let recorded = landed.get(&id).copied();
                let fallen = watched
                    .and_then(|at| Some((at, state.cold().proof_of(at)?)))
                    .or_else(|| {
                        let at = recorded?;
                        let proof = state.cold().proof_of(at)?;
                        let leaf = cairn_ledger::state::cold_leaf(&id, &note);
                        state.cold().verify(at, leaf, &proof).then_some((at, proof))
                    })
                    .or_else(|| current(&rebuilt, state, id, note));
                match fallen {
                    Some(fallen) => Ok(Held {
                        id,
                        note,
                        fallen: Some(fallen),
                    }),
                    None => Err(Unprovable {
                        id,
                        note,
                        fell_at: watched.or(recorded),
                    }),
                }
            };

            for (id, position, note) in state.watched_notes() {
                if note.owner != mine {
                    continue;
                }
                match place(id, note, Some(position)) {
                    Ok(one) => held.push(one),
                    Err(one) => unprovable.push(one),
                }
            }

            // A note this wallet was paid that the node holds in neither
            // tier it can reach. The node follows a fallen note's proof only
            // while it has room, and past that it lets the least valuable
            // ones go, so a wallet reading only the node would watch money
            // leave its balance with nothing said. It is not lost: it is a
            // note whose proof has to be rebuilt by somebody who kept the
            // set, which is what an archivist is for.
            let seen: BTreeSet<NoteId> = held
                .iter()
                .map(|one| one.id)
                .chain(unprovable.iter().map(|one| one.id))
                .collect();
            let mut unanswered_for: Vec<Unprovable> = Vec::new();
            for (id, value) in &recorded {
                if seen.contains(id) {
                    continue;
                }
                let note = Note::new(*value, mine);
                match place(*id, note, None) {
                    Ok(one) => held.push(one),
                    // A note the account stopped answering for, that the node
                    // cannot place, and that this wallet has no place for
                    // either. Then there is nothing at all to point at: it was
                    // spent while the account was not reading, or it fell while
                    // the account was not reading, and from here those look the
                    // same. Counting it makes the balance too high by
                    // everything this key paid away in that range.
                    //
                    // The place is what narrows it, and the narrowing is the
                    // whole of the care this needs. A note this account watched
                    // fall is one it read a block for: that reading is from
                    // below the gap and says nothing about the gap, but it is
                    // evidence, and it is what makes the note askable at all. A
                    // node restarted from a written ledger walks past blocks it
                    // no longer holds as a matter of course, so every wallet on
                    // one would otherwise stop counting all of its stranded
                    // money at once. Between over-counting a note that may have
                    // been spent and a balance that quietly goes down, this
                    // project has already said which is worse, and
                    // `audit_what_forgetting_throws_away` holds it to that.
                    Err(one) if unanswered.contains(id) && one.fell_at.is_none() => {
                        unanswered_for.push(one);
                    }
                    Err(one) => unprovable.push(one),
                }
            }

            let values: BTreeMap<NoteId, Amount> = held
                .iter()
                .map(|one| (one.id, one.note.value))
                .chain(unprovable.iter().map(|one| (one.id, one.note.value)))
                .collect();

            // Every note the node had something to say about, which settles
            // the question for any of them the account had stopped answering
            // for. Marking is done a whole account at a time, because a gap is
            // a fact about a range and not about a note; unmarking is done one
            // note at a time, as each is found again. Without it a note that
            // was merely still in the hot set when the gap opened would stay
            // marked, and the day it fell out of reach for real it would be
            // left out of the balance instead of counted as stranded, which is
            // a balance going quietly down.
            let answered_after_all: Vec<NoteId> = values.keys().copied().collect();

            let (committed, waiting, gone) = waiting_on(chain, &values, mine, &handed);

            let mut notes = Vec::with_capacity(held.len());
            let mut spendable = Amount::ZERO;
            let mut promised = Amount::ZERO;
            // The notes themselves, so a payment the pool let go of can be
            // handed over again with fresh evidence of each.
            let mut promised_notes: BTreeMap<NoteId, Held> = BTreeMap::new();
            let mut ripening = Amount::ZERO;
            let mut ripe_at: Option<u64> = None;
            for one in held {
                let value = one.note.value;
                if committed.contains(&one.id) {
                    promised = promised.checked_add(value).unwrap_or(promised);
                    promised_notes.insert(one.id, one);
                } else if let Some(at) = state
                    .coinbase_matures_at(&one.id.source)
                    .filter(|at| state.next_height().is_none_or(|next| next < *at))
                {
                    // A block reward cannot move until its block is past
                    // reorganisation. Offering it as spendable would have the
                    // wallet build transfers the network turns away, which
                    // reads to its owner as their own money being refused.
                    //
                    // Being in the window is not the same as being held back,
                    // and reading it that way cost a miner one block. The
                    // ledger drops an entry once the tip has reached the
                    // height it names, and refuses a spend while the next
                    // block would sit below it, so on the block where the two
                    // meet the entry is still there and the money can move.
                    ripening = ripening.checked_add(value).unwrap_or(ripening);
                    ripe_at = Some(ripe_at.map_or(at, |soonest: u64| soonest.min(at)));
                } else {
                    spendable = spendable.checked_add(value).unwrap_or(spendable);
                    notes.push(one);
                }
            }
            let mut stranded = Amount::ZERO;
            let mut out_of_reach = Vec::new();
            for one in unprovable {
                let value = one.note.value;
                if committed.contains(&one.id) {
                    promised = promised.checked_add(value).unwrap_or(promised);
                } else {
                    stranded = stranded.checked_add(value).unwrap_or(stranded);
                    out_of_reach.push(one);
                }
            }

            (
                Holdings {
                    spendable,
                    waiting: promised,
                    ripening,
                    ripe_at,
                    stranded,
                    unprovable: out_of_reach,
                    unaccounted: unanswered_for,
                    notes,
                },
                waiting,
                answered_after_all,
                gone,
                promised_notes,
            )
        });

        // Outside the chain, on purpose. Everything that takes both of these
        // takes the account first and the chain second, and taking them the
        // other way round here is how two threads end up each holding what the
        // other is waiting for.
        if !answered.is_empty() {
            let mut history = self
                .history
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut changed = false;
            for id in &answered {
                changed |= history.accounted_for(id);
            }
            if changed {
                self.write_history(&history);
            }
        }
        Reckoned {
            holdings,
            waiting,
            gone,
            promised: promised_notes,
        }
    }

    /// Builds, signs and hands over a transfer.
    ///
    /// Nothing about this is shown anywhere: the key is used here and the
    /// signature is made here, so a face never holds either.
    ///
    /// A fee out of all proportion to the amount is refused rather than paid.
    /// See [`Wallet::send_over_the_odds`] for the way past that, which exists
    /// because paying over the odds is sometimes exactly what was meant.
    pub fn send(
        &self,
        recipient: PublicKey,
        amount: Amount,
        fee: Amount,
    ) -> Result<Sent, WalletError> {
        self.spend(recipient, amount, fee, false)
    }

    /// The same spend, with a fee out of all proportion taken as meant.
    ///
    /// A wallet cannot tell a decimal point in the wrong place from somebody
    /// who wants their transfer in the next block whatever it costs, and both
    /// happen. So it stops and asks once, and this is the answer: the ceiling
    /// is one a person can step over on purpose, because a ceiling they
    /// cannot is a wallet deciding how much their own hurry is worth.
    pub fn send_over_the_odds(
        &self,
        recipient: PublicKey,
        amount: Amount,
        fee: Amount,
    ) -> Result<Sent, WalletError> {
        self.spend(recipient, amount, fee, true)
    }

    /// Why a spend of `amount` paying `fee` could not even be drafted, if it
    /// could not, asked without making it.
    ///
    /// For a quote. What a quote prices is the transfer this wallet would
    /// build, and for money it does not have there is none: the quote used to
    /// price nothing at nothing, and the page said the network asked nought
    /// to carry a payment that sending then refused for want of money. This
    /// is the question sending asks first, asked once for both.
    pub fn could_not_draft(
        &self,
        recipient: PublicKey,
        amount: Amount,
        fee: Amount,
    ) -> Option<WalletError> {
        self.drafted(recipient, amount, fee).err()
    }

    fn drafted(
        &self,
        recipient: PublicKey,
        amount: Amount,
        fee: Amount,
    ) -> Result<Draft, WalletError> {
        if amount == Amount::ZERO {
            return Err(WalletError::NothingToSend);
        }
        let needed = amount.checked_add(fee).ok_or(WalletError::TooLarge)?;

        let holdings = self.holdings();
        self.draft(&holdings, recipient, amount, needed)
            .map_err(|why| match why {
                NoDraft::SpreadTooThin { over, reach } => WalletError::TooManyNotes {
                    over,
                    limit: self.params.max_inputs_per_transfer,
                    reach,
                },
                NoDraft::Short => WalletError::NotEnough {
                    needed,
                    have: holdings.spendable,
                    ripening: holdings.ripening,
                    waiting: holdings.waiting,
                    stranded: holdings.stranded,
                },
            })
    }

    fn spend(
        &self,
        recipient: PublicKey,
        amount: Amount,
        fee: Amount,
        meant: bool,
    ) -> Result<Sent, WalletError> {
        let draft = self.drafted(recipient, amount, fee)?;

        // The network turns away a transfer that pays less than the floor, so
        // the refusal is better said here, with the number, than fetched back
        // from a pool the sender cannot see. A fee of nothing was the ordinary
        // case until the floor existed, and a wallet that went on sending them
        // would look broken rather than out of date.
        if fee < draft.floor {
            return Err(WalletError::FeeTooLow {
                needed: draft.floor,
            });
        }
        if !meant && fee > ceiling(amount, draft.floor) {
            return Err(WalletError::FeeOutOfProportion {
                fee,
                amount,
                floor: draft.floor,
            });
        }

        // A transfer no block can carry would be refused by the network, and
        // it is better to say so here than to have the refusal come back as a
        // rule nobody outside the protocol has heard of. It happens when a
        // wallet holds its money in many small fallen notes, each of which
        // travels with its own proof.
        //
        // Measured against what a block carries rather than against how big a
        // block is. Those differ by the room a block sets aside for its header
        // and its coinbase, and asking the second question let every gather
        // between the two through: the pool took it, the notes were committed,
        // the sender was told to wait a few minutes, and no miner ever chose
        // it. One note adds about a hundred bytes and the two limits are four
        // thousand apart, so the first gather to cross what a block carries is
        // always inside a whole block: this refusal could not fire on the very
        // spend it was written for.
        let carried = ChainStore::room_for_transfers(self.params.max_block_bytes);
        if draft.bytes > carried {
            return Err(WalletError::TooBulky {
                notes: draft.spending.len(),
                bytes: draft.bytes,
                limit: carried,
            });
        }

        // Nothing about the order of a transfer is meant to say anything, and
        // as it stood both halves of the order said plenty. The change went
        // last every time, so an observer who knew that followed this wallet
        // from one payment to the next whatever key the change was paid to,
        // and the fresh keys that work is heading for would have bought
        // nothing. The inputs came out in the order they were chosen, hot
        // before cold and then largest first, which is a signature saying
        // which program built the transfer and resolves the change output on
        // its own. Both are one shuffle, done before signing because what is
        // signed commits to the order.
        let mut spending = draft.spending;
        shuffle(&mut spending)?;
        let mut outputs = vec![Note::new(amount, recipient)];
        if draft.change > Amount::ZERO {
            outputs.push(Note::new(draft.change, self.address()));
        }
        shuffle(&mut outputs)?;

        let inputs = spending.iter().map(Held::as_input).collect();
        let mut transfer = Transfer::new(inputs, outputs);
        for (index, held) in spending.iter().enumerate() {
            let Ok(index) = u32::try_from(index) else {
                return Err(WalletError::TooLarge);
            };
            transfer.sign_input(self.params.network, index, &held.note, &self.secret);
        }

        let id = transfer.id();
        let from_cold = spending.iter().filter(|held| held.is_cold()).count();
        let handed = Handed {
            transfer: transfer.clone(),
            to: recipient,
            amount,
            fee,
            made_at: self.node.height().unwrap_or(0),
            refused: None,
            ended: None,
        };
        // The answer matters. A pool that already holds this identifier, and a
        // full pool that would rather keep what it has, both leave nothing
        // pooled and nothing broadcast, and both say so by returning false
        // rather than by failing. Read as success, that is a wallet reporting
        // a payment the network never took, which is how somebody hands over
        // two things for one payment.
        let taken = self
            .node
            .submit_transaction(transfer)
            .map_err(|error| WalletError::Refused(said_plainly(&error)))?;
        if !taken {
            let already = self.node.with_chain(|chain| chain.pooled(&id).is_some());
            return Err(if already {
                WalletError::AlreadyWaiting { id }
            } else {
                WalletError::NoRoom
            });
        }

        // Written down the moment the pool has it, before anybody is offered
        // it, so that no later start can count its notes as spendable again.
        // See `pending`.
        {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.hand(handed);
            self.write_pending(&pending);
        }

        // Offered until somebody takes it, rather than waited on until a peer
        // exists. The submission above broadcasts once, at the instant the pool
        // takes the transfer, and a wallet sends seconds after it opened: on
        // that broadcast the peer table is regularly still empty. Nothing
        // gossips a pool, so the peer that finished its handshake a second
        // later was never told, and this read the peer count, said the money
        // had been handed to the network, and shut the node down with the
        // transfer in it and nowhere else.
        let offered = Cell::new(0usize);
        let handed_on = wait_until(Duration::from_secs(5), || {
            offered.set(self.node.offer_again(&id));
            offered.get() > 0
        });
        // Long enough for the queue that took it to be written to the socket.
        std::thread::sleep(Duration::from_millis(500));

        Ok(Sent {
            id,
            amount,
            fee,
            change: draft.change,
            notes: spending.len(),
            from_cold,
            handed_on,
            offered: offered.get(),
        })
    }

    pub fn shutdown(&self) {
        self.node.shutdown();
    }
}

/// What waiting for the chain came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Waited {
    /// The chain held still for [`SETTLED_FOR`] with a peer to ask, and no
    /// peer said its chain had more work than this one.
    Settled,
    /// The wait ran out with the chain still on its way: a ledger still
    /// arriving, blocks still landing, no chain at all yet, or a peer saying
    /// its chain has more work before the chain had held still long enough
    /// to tell a chain on its way from a peer that says more than it sends.
    StillMoving,
    /// The wait ran out with the chain held still below what a peer said its
    /// chain had. `ours` is where this wallet's chain stands and `theirs` is
    /// the height that peer gave. A number in a handshake, so a reason to
    /// say so rather than a verdict.
    Behind { ours: Option<u64>, theirs: u64 },
    /// The wait ran out with nobody to ask.
    Alone,
}

/// What catching up sees each time it looks.
#[derive(Clone, Copy, Debug)]
struct Look {
    height: Option<u64>,
    peers: usize,
    joining: Joined,
    work: u128,
    claim: Option<(u64, u128)>,
}

impl Look {
    /// Whether a ledger is on its way in, which a height does not show: it
    /// sits where it was until the last piece lands.
    const fn joining(&self) -> bool {
        matches!(
            self.joining,
            Joined::Weighing { .. } | Joined::Fetching { .. }
        )
    }

    /// The height a peer gave beside more work than this chain has, if one
    /// did.
    fn behind(&self) -> Option<u64> {
        self.claim
            .filter(|&(_, work)| work > self.work)
            .map(|(height, _)| height)
    }
}

/// Whether a wallet whose chain has held still for `still` can stop waiting.
fn settled(look: &Look, still: Duration) -> bool {
    look.peers > 0
        && look.height.is_some()
        && !look.joining()
        && look.behind().is_none()
        && still > SETTLED_FOR
}

/// What a wait that ran out came to, given how long the chain has held still
/// and whether it moved at all while it was watched.
fn ran_out(look: &Look, still: Duration, moved: bool) -> Waited {
    if look.peers == 0 {
        return Waited::Alone;
    }
    let recently = moved && still <= SETTLED_FOR;
    if look.height.is_none() || look.joining() || recently {
        return Waited::StillMoving;
    }
    match look.behind() {
        // A peer says more and the chain has not held still long enough to
        // say whether it is on its way.
        Some(_) if still <= SETTLED_FOR => Waited::StillMoving,
        Some(theirs) => Waited::Behind {
            ours: look.height,
            theirs,
        },
        None => Waited::Settled,
    }
}

/// Why no transfer could be drafted for a spend.
#[derive(Debug)]
enum NoDraft {
    /// The wallet holds the money, and holds it in more notes than one
    /// payment carries.
    SpreadTooThin {
        /// How many notes covering the amount would have taken.
        over: usize,
        /// What the most notes one payment carries come to, which is what the
        /// owner can actually send.
        reach: Amount,
    },
    /// The wallet does not hold the money at all.
    Short,
}

/// Picks at most `most` notes to cover `needed`, largest first so a spend uses
/// as few as it can and leaves as little dust behind.
///
/// Notes the nodes still hold come first whatever their size, because
/// spending one of those costs no proof: a wallet that reached for a fallen
/// note while a hot one would do would be paying bytes for nothing.
///
/// `most` is the network's own limit on how many notes one payment gathers,
/// and it had no counterpart here: this took notes until the amount was
/// covered and stopped at nothing. The only size guard downstream was on
/// bytes, and at a hundred and one bytes an input that one first fires at
/// 1 297 notes against a rule that refuses at 257, so a miner with 257 rewards
/// built, shuffled, signed and submitted a payment the network was always
/// going to turn away.
///
/// The second pass is what the cap costs and what it must not cost. Preferring
/// a hot note over a larger cold one saves bytes, and while there are notes to
/// spare that is free; at the cap it would be the wallet refusing a payment it
/// could make, because 256 hot pebbles may come to less than 256 cold ones. So
/// once cheap proofs no longer fit, value alone decides.
fn select(held: &[Held], needed: Amount, most: usize) -> Result<(Vec<Held>, Amount), NoDraft> {
    let mut by_proof = held.to_vec();
    by_proof.sort_by(|left, right| {
        left.is_cold()
            .cmp(&right.is_cold())
            .then_with(|| right.note.value.cmp(&left.note.value))
    });
    if let Some(enough) = take_until(&by_proof, needed, most) {
        return Ok(enough);
    }

    let mut by_value = held.to_vec();
    by_value.sort_by(|left, right| right.note.value.cmp(&left.note.value));
    if let Some(enough) = take_until(&by_value, needed, most) {
        return Ok(enough);
    }

    // Nothing within the cap reaches it. Whether that is too little money or
    // too many notes is the difference between the owner's mistake and the
    // network's rule, and they need telling apart: the same refusal for both
    // would have somebody with the money in hand reading that they do not have
    // it.
    let mut over = 0;
    let mut whole = Amount::ZERO;
    let mut reach = Amount::ZERO;
    for note in &by_value {
        let Some(more) = whole.checked_add(note.note.value) else {
            break;
        };
        whole = more;
        if over < most {
            reach = whole;
        }
        over = over.saturating_add(1);
        if whole >= needed {
            return Err(NoDraft::SpreadTooThin { over, reach });
        }
    }
    Err(NoDraft::Short)
}

/// Takes notes off an already ordered list until `needed` is covered, giving
/// up rather than gathering more than `most` of them.
fn take_until(sorted: &[Held], needed: Amount, most: usize) -> Option<(Vec<Held>, Amount)> {
    let mut chosen = Vec::new();
    let mut gathered = Amount::ZERO;
    for note in sorted {
        if gathered >= needed {
            break;
        }
        if chosen.len() >= most {
            return None;
        }
        gathered = gathered.checked_add(note.note.value)?;
        chosen.push(note.clone());
    }
    (gathered >= needed).then_some((chosen, gathered))
}

/// What notes falling out of the hot set before a block carries a spend can
/// add to the floor the pool asks of it again.
///
/// A spend is credited a place for every hot note it frees, against the
/// places its outputs take. A note that falls first frees nothing, so each can
/// add a place, and never more places than the outputs take: once they are
/// all paid for, a note falling changes nothing.
fn margin_of(freed: usize, outputs: usize) -> Amount {
    cairn_chain::fee_floor(freed.min(outputs).saturating_mul(cairn_chain::NOTE_WEIGHT))
}

/// The `cheapest` rate a pool of `count` transfers taking `bytes` holds, when
/// it is too full to take one more costing `cost` without dropping something
/// for it, and `None` when it has room.
fn crowded(count: usize, bytes: usize, cost: usize, cheapest: Option<u128>) -> Option<u128> {
    cairn_chain::must_make_room(count, bytes.saturating_add(cost))
        .then_some(cheapest)
        .flatten()
}

/// The fee a spend shaped like `draft` is quoted when none is named: the
/// floor and its margin, and past the cheapest rate a full pool holds.
fn asking(draft: &Draft, crowded: Option<u128>) -> Amount {
    let quoted = draft.floor.checked_add(draft.margin).unwrap_or(draft.floor);
    crowded.map_or(quoted, |rate| {
        quoted.max(cairn_chain::fee_to_outrank(rate, draft.weight))
    })
}

/// The most a spend pays to be carried before the wallet stops and asks.
///
/// The larger of two numbers, and both are needed. The amount being paid,
/// because a fee worth more than the payment is nearly always a decimal point
/// in the wrong place: someone meaning `0.00005` and typing `5`. And a wide
/// multiple of what the network actually asks, because on a payment of a few
/// pebbles the floor itself can come to more than the payment, and a wallet
/// that questioned its own quote would be teaching its owner to wave the
/// question away.
fn ceiling(amount: Amount, floor: Amount) -> Amount {
    let generous = Amount::from_pebbles(floor.as_pebbles().saturating_mul(STEEP_MULTIPLE))
        .unwrap_or(Amount::MAX_MONEY);
    amount.max(generous)
}

/// Puts `items` in an order nothing can be read from.
///
/// Drawn from the operating system rather than from anything this program
/// keeps, and a refusal is passed on rather than worked around: a spend that
/// went out in a predictable order would be one an observer reads the change
/// output off, which is the whole thing this is for.
fn shuffle<T>(items: &mut [T]) -> Result<(), WalletError> {
    let mut remaining = items.len();
    while remaining > 1 {
        let drawn = random_bytes::<8>().map_err(|_| WalletError::NoRandomness)?;
        let span = u64::try_from(remaining).unwrap_or(u64::MAX);
        // Taking a draw over the whole range modulo the span leaves the lowest
        // few values very slightly likelier, by about one part in 2^57 for the
        // handful of notes a transfer gathers. Nothing is read off that.
        let pick =
            usize::try_from(u64::from_le_bytes(drawn).checked_rem(span).unwrap_or(0)).unwrap_or(0);
        remaining = remaining.saturating_sub(1);
        items.swap(remaining, pick);
    }
    Ok(())
}

/// A refusal from the node, said to whoever is holding the money.
///
/// The types underneath print for whoever is debugging them: a note comes out
/// as a `Debug` struct thirty two bytes wide, and "unknown or already spent"
/// is said about a note this wallet spent itself a moment ago. Neither belongs
/// in front of somebody trying to pay for something, and in the one case that
/// happens most the fact that matters, that a second payment has to wait for a
/// block, is in neither of them.
fn said_plainly(refusal: &Refused) -> String {
    match refusal {
        Refused::OnProbation(probation) => format!(
            "this wallet's node has not finished checking the ledger it was handed, and it will \
             not carry a payment until it has. It has checked {} of the {} blocks above block \
             {}. Nothing was sent; leave the wallet open and try again when that line has gone.",
            probation.checked(),
            probation.owed(),
            probation.anchor
        ),
        Refused::Transfer(TransferError::UnknownNote(_) | TransferError::MissingProof { .. }) => {
            "one of the notes this payment is made of is not there any more. Almost always that \
             means a payment you have already made is still waiting for a block: until one \
             carries it, the notes it holds cannot be spent again. Nothing was sent. Wait a few \
             minutes and look at the balance before trying again."
                .to_owned()
        }
        Refused::Transfer(TransferError::FeeBelowFloor { floor, .. }) => format!(
            "the network asks {floor} to carry this payment and this one pays less, so nothing \
             was sent. Send it again paying that."
        ),
        Refused::Transfer(TransferError::TooLargeForABlock { .. }) => {
            "this payment gathers so many notes that no block would carry it. Nothing was sent. \
             Send a smaller amount, more than once: each one leaves fewer notes behind."
                .to_owned()
        }
        // The sibling of the case above, and it had no arm: the wallet's own
        // guard now refuses this before a transfer is built, so reaching here
        // means the node is holding the rule at a number this wallet was not
        // told about. Same advice, since the way out is the same.
        Refused::Transfer(TransferError::TooManyInputs { count, limit }) => format!(
            "this payment gathers {count} notes, and the network carries at most {limit} in one. \
             Nothing was sent. Send a smaller amount, more than once: the change comes back as a \
             single note, so each payment leaves the money in fewer pieces."
        ),
        // Three a wallet meets through no fault of its own. The payment is
        // drafted from the chain under one lock and handed over under
        // another, and a block landing in between can move the cold set a
        // proof was folded against, put a note back in the hot set, or undo
        // the block a reward came from. They fell through to the protocol's
        // words, which print a note for whoever is debugging it and say
        // nothing about what to do, in the one function written to say it.
        Refused::Transfer(
            TransferError::InvalidProof { .. }
            | TransferError::UnexpectedProof { .. }
            | TransferError::ImmatureCoinbase { .. },
        ) => "a block arrived while this payment was being built and changed what it has to \
              prove about the notes it spends. Nothing was sent: send it again, and it is built \
              from the chain as it stands now."
            .to_owned(),
        // A payment naming one note twice, which this wallet never builds. Its
        // own words because the protocol's print that note as a struct.
        Refused::Transfer(TransferError::DuplicateInput(_)) => {
            "this payment names one of its notes twice, which the network never carries. \
             Nothing was sent."
                .to_owned()
        }
        // Every refusal left carries numbers and amounts and never a note, so
        // the protocol's own words are what there is to say. A refusal that
        // does carry one has an arm above, and
        // `every_refusal_of_a_transfer_is_said_without_the_types_underneath`
        // asks each of them.
        other => format!("the network would not take this payment, and nothing was sent: {other}"),
    }
}

/// One reading of the money, and of what the payments this wallet is waiting
/// on need.
struct Reckoned {
    holdings: Holdings,
    waiting: Vec<Waiting>,
    /// Payments on the record whose notes are no longer this key's.
    gone: Vec<Hash32>,
    /// The notes waiting payments hold, with what it takes to spend each now.
    promised: BTreeMap<NoteId, Held>,
}

/// The notes promised to payments no block carries yet, the payments, and the
/// ones on this wallet's record whose notes are no longer this key's.
///
/// Two places a payment can be waiting, and both are read. This wallet's own
/// record comes first: it is what survives the process, and a payment on it is
/// waiting whether or not this node's pool holds it now, because a peer may
/// still. Then whatever else the pool holds that spends this key's notes,
/// which is how a payment made by another copy of this key, or before the
/// record existed, is still seen.
///
/// An input names a note and not its owner, so which pooled transfers are ours
/// is decided by which notes they reach for.
fn waiting_on(
    chain: &ChainStore,
    values: &BTreeMap<NoteId, Amount>,
    mine: PublicKey,
    handed: &[Handed],
) -> (BTreeSet<NoteId>, Vec<Waiting>, Vec<Hash32>) {
    let worth = |notes: &[NoteId]| {
        notes.iter().fold(Amount::ZERO, |sum, note_id| {
            values
                .get(note_id)
                .and_then(|value| sum.checked_add(*value))
                .unwrap_or(sum)
        })
    };
    let leaves = |transfer: &Transfer, gave: Amount| {
        let got = transfer
            .created_notes()
            .into_iter()
            .filter(|(_, note)| note.owner == mine)
            .fold(Amount::ZERO, |sum, (_, note)| {
                sum.checked_add(note.value).unwrap_or(sum)
            });
        gave.checked_sub(got).unwrap_or(Amount::ZERO)
    };

    let mut committed: BTreeSet<NoteId> = BTreeSet::new();
    let mut waiting: Vec<Waiting> = Vec::new();
    let mut gone: Vec<Hash32> = Vec::new();
    for one in handed {
        let id = one.id();
        let spends: Vec<NoteId> = one
            .transfer
            .inputs
            .iter()
            .map(|input| input.note_id)
            .collect();
        if !spends.iter().all(|note_id| values.contains_key(note_id)) {
            gone.push(id);
            continue;
        }
        let pooled = chain.pooled(&id).is_some();
        let gave = worth(&spends);
        committed.extend(spends);
        waiting.push(Waiting {
            id,
            amount: leaves(&one.transfer, gave),
            committed: gave,
            pooled,
            why: (!pooled).then(|| {
                one.refused
                    .as_ref()
                    .map_or_else(|| NOT_IN_THE_POOL.to_owned(), |(_, why)| why.clone())
            }),
            held_until: one.held_until(),
        });
    }
    for (id, transfer) in chain.pooled_transfers() {
        if waiting.iter().any(|one| one.id == *id) {
            continue;
        }
        let ours: Vec<NoteId> = transfer
            .inputs
            .iter()
            .map(|input| input.note_id)
            .filter(|note_id| values.contains_key(note_id))
            .collect();
        if ours.is_empty() {
            continue;
        }
        let gave = worth(&ours);
        committed.extend(ours);
        waiting.push(Waiting {
            id: *id,
            amount: leaves(transfer, gave),
            committed: gave,
            pooled: true,
            why: None,
            held_until: None,
        });
    }
    (committed, waiting, gone)
}

/// Whether an account reading from `next`, with nothing missed below
/// `missed_below`, has read every block from `made_at` to `tip`: the only
/// case in which a payment made at `made_at` that no block it read carried
/// was carried by none.
fn read_every_block_since(next: u64, missed_below: Option<u64>, made_at: u64, tip: u64) -> bool {
    next > tip && missed_below.is_none_or(|below| below <= made_at)
}

/// Whether the payments a wallet's node holds are due to be offered to its
/// peers again, given how many peers it has now, how many there were and
/// when, the last time they were offered.
///
/// A peer more than last time is the reason that matters, since nothing
/// gossips a pool and a peer that arrived afterwards was never told. Past
/// [`OFFER_PAUSE`] every peer is asked again, for the one that was offered it
/// and let it go. And nobody at all is nobody to offer anything to.
fn offer_due(peers: usize, last: (usize, Option<Instant>), now: Instant) -> bool {
    if peers == 0 {
        return false;
    }
    let (had, at) = last;
    peers > had || at.is_none_or(|at| at.checked_add(OFFER_PAUSE).is_none_or(|due| now >= due))
}

/// Writes down what this wallet's own node said when a payment was handed
/// back to it at `tip`: taken, or refused for a reason that is the payment's,
/// or neither.
fn note_the_answer(pending: &mut Pending, id: &Hash32, tip: u64, answer: &Result<bool, Refused>) {
    match answer {
        Ok(true) => {
            pending.taken_back(id);
        }
        Err(refusal) if refuses_the_payment(refusal) => {
            pending.refused(id, tip, &held_back_because(refusal));
        }
        // Already there, no room, or a node that carries nothing yet. None of
        // them is a refusal of the payment: see `refuses_the_payment`.
        Ok(false) | Err(_) => {}
    }
}

/// Whether a refusal from this wallet's own node is a refusal of the payment,
/// which starts the wait before its notes come back, rather than of the node.
///
/// A node that has not finished checking the ledger it was handed carries no
/// payment at all, and says so about every one. Read as a refusal of this one,
/// a wallet that restarted into a long check would let go of a payment its
/// peers may be carrying, and give its notes back to be spent again.
fn refuses_the_payment(refusal: &Refused) -> bool {
    !matches!(refusal, Refused::OnProbation(_))
}

/// Why this wallet's node will not take back a payment it already handed
/// over, said to whoever made it.
///
/// Not [`said_plainly`], whose words are for a payment being made and say
/// that nothing was sent and to send it again. This one was sent, may still be
/// held by a peer, and is still holding its notes; sending it again is the one
/// thing not to do.
fn held_back_because(refusal: &Refused) -> String {
    match refusal {
        Refused::Transfer(TransferError::FeeBelowFloor { fee, floor }) => format!(
            "it pays {fee} and the network now asks {floor} to carry it. A note it spends has \
             fallen out of the set every node keeps since it was made, and that makes it weigh \
             more"
        ),
        Refused::Transfer(
            TransferError::InvalidProof { .. }
            | TransferError::MissingProof { .. }
            | TransferError::UnexpectedProof { .. },
        ) => "a note it spends has moved in or out of the set every node keeps, and this wallet \
              cannot show where it sits now"
            .to_owned(),
        Refused::Transfer(TransferError::UnknownNote(_) | TransferError::DuplicateInput(_)) => {
            "a note it spends is not on the chain as this wallet's node has it".to_owned()
        }
        Refused::Transfer(TransferError::ImmatureCoinbase { matures_at, .. }) => format!(
            "a block reward it spends cannot move until block {matures_at} on the chain as it \
             stands"
        ),
        Refused::OnProbation(_) => "this wallet's node has not finished checking the ledger it \
             was handed, and carries no payment until it has"
            .to_owned(),
        other => format!("the network would not take it: {other}"),
    }
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{
        asking, ceiling, crowded, held_back_because, margin_of, offer_due, one_question, ran_out,
        read_every_block_since, said_plainly, select, settled, shuffle, still_outstanding,
        too_old_for_this_chain, Covered, Held, NoDraft, Outdated, Progress, Recovery, Waited,
        MAX_PROVEN, OFFER_PAUSE, SETTLED_FOR,
    };

    /// How many blocks an account has not read, when it has not read some.
    ///
    /// Both tests that asked were asked of an account at the tip, where the
    /// answer is nought, so an account that always said nought passed them,
    /// and so did one that said nought having read nothing at all. The page
    /// shows this number as the reason the list under it is short.
    #[test]
    fn an_account_says_how_many_blocks_it_has_not_read() {
        let covered = |through, tip| Covered {
            from: Some(0),
            through,
            missed_below: None,
            tip,
        };
        assert_eq!(covered(Some(7), Some(10)).behind(), 3);
        assert_eq!(
            covered(None, Some(10)).behind(),
            11,
            "an account that read nothing has every block from nought to read"
        );
        assert_eq!(covered(Some(10), Some(10)).behind(), 0);
        assert_eq!(
            covered(None, None).behind(),
            0,
            "and no chain is nothing to read"
        );
    }

    /// A bad address is answered as a bad address, in the same words by both
    /// faces.
    ///
    /// It was not. `WalletError::BadAddress` exists for this and was built
    /// nowhere: the web face answered `NothingToSend`, so somebody who
    /// mistyped a recipient was told "a transfer of nothing would only cost
    /// state", which is an answer about the amount to a fault in the address.
    /// The command line answered a bare `String`, which the note on
    /// `WalletError` forbids in its own first sentence. And the two parsers
    /// disagreed on whitespace, so a pasted address with a space on the end
    /// was taken by the form and refused by `send`.
    #[test]
    fn a_bad_address_is_answered_as_one_and_not_as_an_amount() {
        let error = super::parse_address("not an address").expect_err("this is not an address");
        assert!(
            matches!(error, super::WalletError::BadAddress(_, _)),
            "a fault in the address is answered as one, and this said {error}"
        );
        assert!(
            error.to_string().contains("not an address"),
            "and it quotes what was typed, so a person can see their own typo: {error}"
        );

        // The other way in, which the case above cannot reach: thirty two
        // bytes of good hexadecimal that are not a key anybody holds. Two
        // construction sites, and only one of them was covered until taking
        // the quoted text out of this one left the test green.
        let outside = "11".repeat(32);
        let error = super::parse_address(&outside).expect_err("not a usable key");
        assert!(
            matches!(error, super::WalletError::BadAddress(_, _)),
            "a point outside the prime order subgroup is a bad address, not \
             something else: {error}"
        );
        assert!(
            error.to_string().contains(&outside),
            "and this way in quotes what was typed too: {error}"
        );

        // A real address, and not any thirty two bytes of hexadecimal. Written
        // first with `"ab"` repeated, which is not a point anybody holds, so
        // both sides of the comparison below were refusals and the comparison
        // held whatever the trimming did. Caught by taking the trimming out
        // and watching this stay green.
        let real = cairn_primitives::hex::encode(
            &cairn_crypto::SecretKey::from_bytes(&[7u8; 32])
                .public_key()
                .to_bytes(),
        );
        assert!(
            super::parse_address(&real).is_ok(),
            "the fixture has to be an address, or the next line compares two \
             refusals"
        );
        assert!(
            super::parse_address(&format!("  {real}  ")).is_ok(),
            "what sits on either side of a pasted address is not something \
             the person typed on purpose, and the command line used to refuse \
             what the form took"
        );
    }
    use cairn_accumulator::ForestProof;
    use cairn_crypto::SecretKey;
    use cairn_ledger::note::{Note, NoteId};
    use cairn_ledger::validation::TransferError;
    use cairn_net::node::{
        Behind, Probation, Reading, Refused, Unread, Unweighable, Unwritten, Writing,
    };
    use cairn_net::Joined;
    use cairn_primitives::{Amount, Hash32};
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    fn cairn(text: &str) -> Amount {
        Amount::from_cairn(text).unwrap()
    }

    /// One note worth `value`, still held by the nodes or long since fallen.
    fn note(seed: u32, value: Amount, fallen: bool) -> Held {
        let owner = SecretKey::from_bytes(&[3; 32]).public_key();
        Held {
            id: NoteId::new(Hash32::ZERO, seed),
            note: Note::new(value, owner),
            fallen: fallen.then(|| {
                (
                    0,
                    ForestProof {
                        siblings: vec![Hash32::ZERO; 20],
                    },
                )
            }),
        }
    }

    /// Spending a note the nodes still hold costs no proof, so those come
    /// first whatever their size. That preference is free while there are
    /// notes to spare and is not free at the count the network carries: a
    /// wallet that filled a payment with hot dust rather than reach for the
    /// larger fallen notes beside it would be refusing a payment it could
    /// make, and the money is right there.
    #[test]
    fn once_the_count_binds_it_is_value_that_decides_and_not_cheap_proofs() {
        let mut held: Vec<Held> = (0..8).map(|i| note(i, cairn("1"), false)).collect();
        held.extend((8..12).map(|i| note(i, cairn("10"), true)));

        // Room to spare: the hot notes are enough on their own and cost no
        // proof, so they are what a spend reaches for.
        let (chosen, gathered) = select(&held, cairn("5"), 8).expect("eight hot notes cover five");
        assert_eq!(gathered, cairn("5"));
        assert!(
            chosen.iter().all(|one| !one.is_cold()),
            "five hot notes cover it without a single proof"
        );

        // Four notes only. Four hot ones come to four; four fallen ones come
        // to forty, and forty is what was asked for.
        let (chosen, gathered) = select(&held, cairn("40"), 4)
            .expect("four fallen tens come to forty, and the wallet holds four of them");
        assert_eq!(chosen.len(), 4);
        assert_eq!(gathered, cairn("40"));
        assert!(
            chosen.iter().all(Held::is_cold),
            "the largest four are the fallen ones"
        );

        // Past what any four notes reach, and the refusal has to say which
        // wall was hit: the money is there, and it is in too many pieces.
        let refused = select(&held, cairn("41"), 4);
        assert!(
            matches!(
                refused,
                Err(NoDraft::SpreadTooThin { over, reach })
                    if over == 5 && reach == cairn("40")
            ),
            "forty one out of forty eight held in twelve notes is neither short nor coverable \
             by four: {refused:?}"
        );

        // And too little money is still too little money.
        assert!(
            matches!(select(&held, cairn("49"), 12), Err(NoDraft::Short)),
            "forty eight is all there is"
        );
    }

    /// A fee larger than the payment is nearly always a decimal point in the
    /// wrong place, and a fee near what the network asks never is, however
    /// small the payment. Both have to be true of the ceiling or it refuses
    /// the wallet's own quote on a payment of a few pebbles.
    #[test]
    fn the_ceiling_on_a_fee_is_the_payment_or_a_wide_multiple_of_the_floor() {
        let floor = cairn("0.00007");
        assert_eq!(ceiling(cairn("1"), floor), cairn("1"));
        assert!(cairn("5") > ceiling(cairn("1"), floor), "five to send one");

        // A payment worth less than the fee the network itself asks. Refusing
        // this would be a wallet refusing the number it just quoted.
        let tiny = cairn("0.00001");
        assert!(floor <= ceiling(tiny, floor));
        assert!(
            cairn("0.005") <= ceiling(tiny, floor),
            "and there is room above it to pay to be carried sooner"
        );
    }

    /// The quote for a blank fee carries a place's worth over the floor for
    /// every place a note of the spend falling can add, and no more.
    ///
    /// It quoted the floor exactly, and the pool asks the floor again after
    /// every block: a note the payment spent falling out of the hot set made
    /// it weigh a place more, and every pool let it go.
    #[test]
    fn a_blank_fee_is_quoted_a_place_over_the_floor_for_each_note_that_can_fall() {
        let place = cairn_chain::fee_floor(cairn_chain::NOTE_WEIGHT);
        assert_eq!(
            margin_of(0, 2),
            Amount::ZERO,
            "nothing hot, nothing to fall"
        );
        assert_eq!(margin_of(1, 2), place);
        assert_eq!(margin_of(2, 2), place.checked_add(place).unwrap());
        assert_eq!(
            margin_of(5, 2),
            place.checked_add(place).unwrap(),
            "never more places than the outputs take"
        );

        let draft = super::Draft {
            spending: Vec::new(),
            change: Amount::ZERO,
            bytes: 150,
            floor: Amount::from_pebbles(1_500).unwrap(),
            weight: 150,
            margin: place,
        };
        assert_eq!(
            asking(&draft, None),
            Amount::from_pebbles(1_500)
                .unwrap()
                .checked_add(place)
                .unwrap(),
            "the quote is not the floor and its margin"
        );
        // A full pool whose cheapest pays far more per unit than this would.
        let dear = u128::from(u64::MAX >> 20);
        assert_eq!(
            asking(&draft, Some(dear)),
            cairn_chain::fee_to_outrank(dear, 150),
            "a quote into a full pool does not outrank the cheapest it holds"
        );
        assert_eq!(
            asking(&draft, Some(0)),
            asking(&draft, None),
            "a full pool of nothing dearer than this asks nothing more"
        );

        // A pool is crowded when one more would not fit, by count or by size,
        // and only then does its cheapest rate matter to a quote.
        let most = cairn_chain::MAX_POOLED;
        let size = cairn_chain::MAX_POOL_BYTES;
        assert_eq!(
            crowded(0, 0, 100, Some(7)),
            None,
            "an empty pool is not full"
        );
        assert_eq!(
            crowded(most - 1, 0, 100, Some(7)),
            None,
            "room for one more"
        );
        assert_eq!(crowded(most, 0, 100, Some(7)), Some(7), "full by count");
        assert_eq!(
            crowded(1, size - 100, 100, Some(7)),
            None,
            "exactly full fits"
        );
        assert_eq!(crowded(1, size - 99, 100, Some(7)), Some(7), "full by size");
        assert_eq!(
            crowded(most, 0, 100, None),
            None,
            "nothing held, nothing to beat"
        );
    }

    /// A `Debug` struct thirty two bytes wide used to go straight from the
    /// ledger's refusal into what the page showed, saying "already spent"
    /// about a note this wallet had spent itself half a minute earlier. The
    /// fact that mattered, that a second payment has to wait for a block, was
    /// nowhere in it.
    #[test]
    fn a_refusal_reaches_a_person_in_words() {
        let unknown = Refused::Transfer(TransferError::UnknownNote(NoteId::new(
            Hash32::from_bytes([9; 32]),
            0,
        )));
        let said = said_plainly(&unknown);
        assert!(!said.contains("NoteId"), "{said}");
        assert!(!said.contains("Hash32"), "{said}");
        assert!(!said.contains("already spent"), "{said}");
        assert!(said.contains("waiting for a block"), "{said}");
        assert!(said.contains("Nothing was sent"), "{said}");

        // A payment too large for a block had a hand-written answer and its
        // sibling, a payment gathering more notes than one carries, did not:
        // it fell through to the protocol's own words, which name a field and
        // say nothing about what to do next. The wallet now refuses this
        // before it builds anything, so getting here means the node holds the
        // rule at a number this wallet was not told, and the person on the
        // other end still needs the way out.
        let too_many = Refused::Transfer(TransferError::TooManyInputs {
            count: 257,
            limit: 256,
        });
        let said = said_plainly(&too_many);
        assert!(!said.contains("TooManyInputs"), "{said}");
        assert!(said.contains("257"), "{said}");
        assert!(said.contains("256"), "{said}");
        assert!(said.contains("Nothing was sent"), "{said}");
        assert!(said.contains("Send a smaller amount"), "{said}");
    }

    /// No refusal a transfer can meet reaches a person as a type printed for
    /// whoever is debugging it, and the three a block landing mid spend
    /// causes say that sending again is the answer.
    ///
    /// Five variants had words of their own and the rest fell through to the
    /// protocol's, which print a note as a `Debug` struct. The test above
    /// asked one of the five, so every one of the other twelve passed
    /// whatever it said, including the three a wallet meets through no fault
    /// of its own: the draft and the submission take the chain one after the
    /// other, and a block can land between them.
    #[test]
    fn every_refusal_of_a_transfer_is_said_without_the_types_underneath() {
        let note = NoteId::new(Hash32::from_bytes([9; 32]), 0);
        let fee = Amount::from_pebbles(10).unwrap();
        let every = [
            TransferError::UnsupportedVersion(9),
            TransferError::NoInputs,
            TransferError::NoOutputs,
            TransferError::TooManyInputs { count: 3, limit: 2 },
            TransferError::TooManyOutputs { count: 3, limit: 2 },
            TransferError::TooLargeForABlock { bytes: 3, limit: 2 },
            TransferError::FeeBelowFloor { fee, floor: fee },
            TransferError::DuplicateInput(note),
            TransferError::UnknownNote(note),
            TransferError::UnexpectedProof { note_id: note },
            TransferError::MissingProof { note_id: note },
            TransferError::InvalidProof { note_id: note },
            TransferError::ImmatureCoinbase {
                note_id: note,
                matures_at: 9,
            },
            TransferError::ZeroValueOutput { index: 0 },
            TransferError::ValueOverflow,
            TransferError::OutputsExceedInputs {
                available: fee,
                requested: fee,
            },
            TransferError::InvalidSignature { input_index: 0 },
        ];
        for refusal in every {
            let said = said_plainly(&Refused::Transfer(refusal.clone()));
            assert!(
                !said.contains("NoteId") && !said.contains("Hash32"),
                "{refusal:?} reached a person as the protocol prints it for debugging"
            );
            assert!(said.contains("othing was sent"), "{refusal:?}: {said}");
            assert!(
                super::refuses_the_payment(&Refused::Transfer(refusal.clone())),
                "{refusal:?} is not taken as a refusal of the payment"
            );
            // And said of a payment already handed over, which was sent and
            // must not be sent again.
            let held_back = held_back_because(&Refused::Transfer(refusal.clone()));
            assert!(
                !held_back.contains("NoteId") && !held_back.contains("Hash32"),
                "{refusal:?} reached a person as the protocol prints it for debugging"
            );
            assert!(
                !held_back.contains("othing was sent") && !held_back.contains("send it again"),
                "{refusal:?}, said of a payment already handed over, says to send it again"
            );
        }
        // A node still checking the ledger it was handed carries nothing at
        // all, which is not a refusal of any one payment.
        assert!(
            !super::refuses_the_payment(&Refused::OnProbation(Probation {
                anchor: 900,
                settles_at: 1000,
                reached: 940,
            })),
            "a node still checking its ledger was taken to refuse the payment itself"
        );
        for mid_spend in [
            TransferError::InvalidProof { note_id: note },
            TransferError::UnexpectedProof { note_id: note },
            TransferError::ImmatureCoinbase {
                note_id: note,
                matures_at: 9,
            },
        ] {
            let said = said_plainly(&Refused::Transfer(mid_spend.clone()));
            assert!(
                said.contains("send it again"),
                "{mid_spend:?}, which a block landing while the payment was built causes, \
                 did not say that sending again is the answer: {said}"
            );
        }
    }

    /// A payment no block this account read carried was carried by none only
    /// when the account read every block since the payment was made.
    ///
    /// Said otherwise, a payment carried in a block the account never read
    /// would be named as not carried, and its owner told to pay again what
    /// had been paid.
    #[test]
    fn a_payment_is_said_to_be_carried_by_no_block_only_when_every_block_was_read() {
        assert!(
            read_every_block_since(11, None, 5, 10),
            "read to the tip, nothing missed"
        );
        assert!(
            !read_every_block_since(10, None, 5, 10),
            "one block at the tip unread"
        );
        assert!(
            read_every_block_since(11, Some(5), 5, 10),
            "what was missed is from before the payment"
        );
        assert!(
            !read_every_block_since(11, Some(6), 5, 10),
            "what was missed reaches past the block the payment was made at"
        );
    }

    /// What this wallet's node says when a payment is handed back is written
    /// down as what it is: taken back, refused for the payment's own sake,
    /// or neither.
    ///
    /// A node still checking the ledger it was handed refuses every payment
    /// alike. Written down as a refusal of this one, it started the wait
    /// before the notes come back, and a wallet restarted into a long check
    /// let go of a payment its peers may be carrying. Nothing reached that
    /// branch, so it could have been either way round.
    #[test]
    fn what_the_node_says_of_a_payment_handed_back_is_written_down_as_what_it_is() {
        use crate::pending::{Handed, Pending};
        use cairn_ledger::transaction::{Input, Transfer};

        let to = SecretKey::generate().unwrap().public_key();
        let spends = NoteId::new(Hash32::from_bytes([2; 32]), 0);
        let one = Handed {
            transfer: Transfer::new(vec![Input::hot(spends)], vec![Note::new(cairn("1"), to)]),
            to,
            amount: cairn("1"),
            fee: cairn("0.001"),
            made_at: 10,
            refused: None,
            ended: None,
        };
        let id = one.id();
        let mut pending = Pending::default();
        pending.hand(one);
        let held = |pending: &Pending| pending.live().next().and_then(Handed::held_until);

        let checking = Err(Refused::OnProbation(Probation {
            anchor: 900,
            settles_at: 1000,
            reached: 940,
        }));
        super::note_the_answer(&mut pending, &id, 20, &checking);
        assert_eq!(
            held(&pending),
            None,
            "a node still checking was taken to refuse this payment"
        );
        super::note_the_answer(&mut pending, &id, 20, &Ok(false));
        assert_eq!(
            held(&pending),
            None,
            "no room was taken to refuse this payment"
        );

        let short = Err(Refused::Transfer(TransferError::FeeBelowFloor {
            fee: cairn("0.001"),
            floor: cairn("0.002"),
        }));
        super::note_the_answer(&mut pending, &id, 20, &short);
        assert!(
            held(&pending).is_some(),
            "a payment refused for its fee was not held as refused"
        );
        super::note_the_answer(&mut pending, &id, 21, &Ok(true));
        assert_eq!(
            held(&pending),
            None,
            "a payment taken back is still held as refused"
        );
    }

    /// A wallet that holds nothing names its account file when its account
    /// begins above the first block, and only then.
    ///
    /// Both faces sent a person restored from the key alone to look at the
    /// network or the height, where the missing money is not.
    #[test]
    fn a_wallet_holding_nothing_names_its_account_file_only_when_it_begins_late() {
        let covered = |from| Covered {
            from,
            through: Some(90),
            missed_below: None,
            tip: Some(90),
        };
        let late = super::nothing_here_yet(&covered(Some(70)));
        assert!(late.contains("begins at block 70"), "{late}");
        assert!(late.contains("history.dat"), "{late}");
        for whole in [Some(0), None] {
            let said = super::nothing_here_yet(&covered(whole));
            assert!(!said.contains("history.dat"), "{said}");
            assert!(said.starts_with("Nothing here yet."), "{said}");
        }
    }

    /// The wait for the chain ends only with a peer to ask, a chain held
    /// still, no ledger on its way and no peer saying it has more; and a wait
    /// that runs out says which of those it was short of.
    ///
    /// The one guard against answering before a chain arrived read "no
    /// height", which on both networks that exist is never true: their first
    /// block is in the program. Nothing asked what a ledger on its way or a
    /// peer ahead did to the wait, so a wallet that answered two seconds into
    /// a handover, from block nought, passed.
    #[test]
    fn the_wait_for_the_chain_ends_only_when_nothing_says_it_is_on_its_way() {
        let long = SETTLED_FOR + Duration::from_secs(1);
        let short = SETTLED_FOR;
        let calm = super::Look {
            height: Some(0),
            peers: 1,
            joining: Joined::No,
            work: 10,
            claim: Some((0, 10)),
        };
        assert!(
            settled(&calm, long),
            "a chain held still with a peer level with it"
        );
        assert!(
            !settled(&calm, short),
            "held still for no longer than the settle window"
        );
        let alone = super::Look { peers: 0, ..calm };
        assert!(!settled(&alone, long), "nobody to ask");
        assert_eq!(ran_out(&alone, long, false), Waited::Alone);
        let nothing = super::Look {
            height: None,
            ..calm
        };
        assert!(!settled(&nothing, long), "no chain at all");
        assert_eq!(ran_out(&nothing, long, false), Waited::StillMoving);
        for joining in [
            Joined::Weighing { held: 1, parts: 4 },
            Joined::Fetching { held: 1, parts: 4 },
        ] {
            let arriving = super::Look { joining, ..calm };
            assert!(
                !settled(&arriving, long),
                "a ledger on its way at block nought"
            );
            assert_eq!(ran_out(&arriving, long, false), Waited::StillMoving);
        }
        let done = super::Look {
            joining: Joined::Done,
            ..calm
        };
        assert!(
            settled(&done, long),
            "a join that is done is not one on its way"
        );
        let ahead = super::Look {
            claim: Some((90, 11)),
            ..calm
        };
        assert!(
            !settled(&ahead, long),
            "a peer says its chain has more work"
        );
        assert_eq!(
            ran_out(&ahead, long, false),
            Waited::Behind {
                ours: Some(0),
                theirs: 90
            },
            "held still below what a peer says is behind, and says so"
        );
        assert_eq!(
            ran_out(&ahead, short, false),
            Waited::StillMoving,
            "too soon to tell a chain on its way from a peer saying more than it sends"
        );
        assert_eq!(
            ran_out(&calm, short, true),
            Waited::StillMoving,
            "still landing blocks"
        );
        assert_eq!(ran_out(&calm, long, true), Waited::Settled);
        assert_eq!(
            ran_out(&calm, short, false),
            Waited::Settled,
            "never moved and nobody says more: nothing says it is behind"
        );
    }

    /// Waiting payments are offered again when a peer has arrived since the
    /// last time, or when a while has passed, and never to nobody.
    ///
    /// Nothing offered a pooled payment after the one broadcast when the pool
    /// took it, so a peer that arrived afterwards was never told of it.
    #[test]
    fn waiting_payments_are_offered_to_a_peer_that_arrived_since() {
        let then = Instant::now();
        let soon = then.checked_add(Duration::from_secs(1)).unwrap();
        let later = then.checked_add(OFFER_PAUSE).unwrap();
        assert!(
            offer_due(1, (0, None), then),
            "never offered, and a peer to offer to"
        );
        assert!(!offer_due(0, (0, None), then), "offered to nobody");
        assert!(!offer_due(0, (3, Some(then)), later), "offered to nobody");
        assert!(offer_due(2, (1, Some(then)), soon), "a peer arrived since");
        assert!(
            !offer_due(2, (2, Some(then)), soon),
            "offered again at once to the same peers"
        );
        assert!(
            !offer_due(1, (2, Some(then)), soon),
            "a peer leaving is no reason to offer"
        );
        assert!(
            offer_due(2, (2, Some(then)), later),
            "not offered again once the pause is over"
        );
    }

    /// A wallet too old for its chain used to be told to look at a height and
    /// a balance "from before that moment". It can now meet the verdict in the
    /// first ledger it is ever handed, where there is neither.
    #[test]
    fn a_wallet_that_never_had_a_chain_is_not_told_to_look_at_its_last_balance() {
        let outdated = Outdated {
            height: 900,
            required: 3,
            known: 2,
        };
        let following = too_old_for_this_chain(&outdated, true);
        assert!(following.contains("from before that moment"), "{following}");

        let never = too_old_for_this_chain(&outdated, false);
        assert!(!never.contains("from before that moment"), "{never}");
        assert!(never.contains("never got as far as a chain"), "{never}");
        assert!(
            never.contains("Install a newer wallet"),
            "and the way out is the same either way: {never}"
        );
    }

    /// The node reports three states in which a height and a balance say
    /// nothing, and the wallet showed none of them. Probation is the one that
    /// matters most: joining reports itself done throughout it, so a wallet
    /// just started shows a balance out of a ledger it has not checked.
    #[test]
    fn a_ledger_this_wallet_has_not_checked_is_said_to_be_one() {
        let healthy = healthy();
        assert!(healthy.warning().is_none(), "nothing to say about this one");

        let on_probation = Progress {
            probation: Some(Probation {
                anchor: 900,
                settles_at: 1000,
                reached: 940,
            }),
            ..healthy
        };
        let said = on_probation.warning().unwrap();
        assert!(said.contains("900"), "the warning does not name the anchor");
        assert!(
            said.contains("40 of the 100"),
            "the warning does not say how far the check has come"
        );
        assert!(
            said.contains("has not yet checked"),
            "the warning does not say the ledger is unchecked"
        );
    }

    /// A wallet whose node stopped over a full disk is not told the blocks
    /// were lost.
    ///
    /// The node stops at `MAX_BEHIND` blocks behind, inside the window its
    /// chain holds block bodies over, so when it stops it still holds every
    /// block it did not write. The line said they were "no longer anywhere
    /// this node can read them from". Nothing read it against the number, so a
    /// person was told of a loss that had not happened, as the reason for a
    /// stop that was a choice.
    #[test]
    fn a_node_stopped_over_its_disk_is_not_said_to_have_lost_the_blocks() {
        use cairn_net::node::{Unwritten, Writing, MAX_BEHIND};

        let stopped = Progress {
            unwritten: Some(Unwritten {
                what: Writing::Blocks,
                because: "no space left on device".to_owned(),
                reached: 1_200,
                written_through: Some(1_200 - MAX_BEHIND - 1),
                blocks: MAX_BEHIND + 1,
                within_reach: false,
            }),
            ..healthy()
        };
        let said = stopped.warning().expect("a person is told");
        assert!(
            !said.contains("no longer anywhere"),
            "a node that stopped {} blocks behind still held all of them, and the line \
             says they are gone",
            MAX_BEHIND + 1
        );
        assert!(
            said.contains("asks the network"),
            "and it does not say where a restart finds them"
        );
    }

    /// A node with nothing to report, for the states below to differ from.
    fn healthy() -> Progress {
        Progress {
            keeping_its_account: true,
            lost_its_account: None,
            unwritten: None,
            unread: None,
            clock_behind: None,
            unjudged: None,
            unweighable: None,
            height: Some(10),
            peers: 1,
            joining: Joined::Done,
            probation: None,
            outdated: None,
            stranded: None,
        }
    }

    /// The fourth state a height and a balance say nothing about, and the one
    /// the page positively contradicts.
    ///
    /// This wallet's list of payments is read one block at a time off the
    /// node's disk and cannot step over a block, so a block the disk will not
    /// give back stops the list there for good. The page goes on saying "still
    /// reading" about it, and the height beside it goes on climbing, because
    /// the chain is fine and only this one read is not. Nothing said so.
    #[test]
    fn a_disk_that_will_not_give_a_block_back_stops_the_list_and_now_says_so() {
        let stuck = Progress {
            unread: Some(Unread {
                what: Reading::Blocks,
                height: 4_312,
                because: "record 5 says it holds 244 bytes, the index gives it 184".to_owned(),
                refusals: 3,
            }),
            ..healthy()
        };
        let said = stuck.warning().expect("a person is told");
        assert!(said.contains("4312"), "it names the block: {said}");
        assert!(
            said.contains("the index gives it 184"),
            "in the words the store used, which is what tells damage from a full disk: {said}"
        );
        assert!(
            said.contains("still right"),
            "and says the amount is not what is wrong, because it is not: {said}"
        );
        assert!(
            said.contains("still reading"),
            "and answers the line on the page that says the opposite: {said}"
        );
    }

    /// A change output that is always last is one an observer picks out with
    /// certainty, whatever key it is paid to, which would leave the fresh key
    /// work worth very little. Two outputs, so a shuffle that does nothing
    /// fails this every time and a shuffle that works fails it about once in
    /// a hundred million runs.
    #[test]
    fn shuffling_moves_things() {
        let mut seen_first = false;
        let mut seen_second = false;
        for _ in 0..64 {
            let mut pair = ["recipient", "change"];
            shuffle(&mut pair).unwrap();
            if pair[0] == "change" {
                seen_first = true;
            } else {
                seen_second = true;
            }
        }
        assert!(seen_first && seen_second, "the change moved about");

        // And it keeps everything it was given, which is the half of this that
        // would lose money rather than privacy.
        let mut many: Vec<u32> = (0..64).collect();
        shuffle(&mut many).unwrap();
        many.sort_unstable();
        assert_eq!(many, (0..64).collect::<Vec<u32>>());
    }

    /// A place beyond the first question was never asked about, and what the
    /// wallet writes down has to say so.
    ///
    /// The set this feeds is read as "the places that were asked about and not
    /// answered for", and what it decides is whether asking again is worth
    /// anything. It used to be filled from every place the wallet wanted to
    /// ask about. With more stranded notes than one question carries, the
    /// places nobody had put a question about landed in a set meaning nobody
    /// could answer them, and the wallet then waited out its pause before
    /// asking.
    #[test]
    fn what_one_question_did_not_carry_is_not_a_place_that_went_unanswered() {
        let wanted: Vec<(u64, Hash32)> = (0..(MAX_PROVEN as u64 * 2))
            .map(|at| (at, Hash32::from_bytes([0; 32])))
            .collect();

        assert_eq!(
            one_question(&wanted).len(),
            MAX_PROVEN,
            "one message carries this many"
        );

        // Nobody answered, which is the case the pause is about. Handed the
        // whole of `wanted`, exactly as the wallet hands it, because the cut
        // belongs to the rule and not to its caller.
        let answered: BTreeMap<u64, ForestProof> = BTreeMap::new();
        let outstanding = still_outstanding(&wanted, &answered);

        assert_eq!(
            outstanding.len(),
            MAX_PROVEN,
            "every place that was asked about went unanswered, and all of them \
             belong here"
        );
        for at in 0..MAX_PROVEN as u64 {
            assert!(outstanding.contains(&at), "place {at} was asked about");
        }
        for at in MAX_PROVEN as u64..(MAX_PROVEN as u64 * 2) {
            assert!(
                !outstanding.contains(&at),
                "place {at} was never put to anybody, so calling it unanswered \
                 is what makes this wallet wait instead of ask"
            );
        }
    }

    /// A question that fits is not cut, and the answers that came back are not
    /// counted as outstanding.
    #[test]
    fn a_question_that_fits_is_asked_whole_and_what_came_back_is_settled() {
        let wanted: Vec<(u64, Hash32)> =
            (0..3).map(|at| (at, Hash32::from_bytes([0; 32]))).collect();
        assert_eq!(one_question(&wanted).len(), 3, "nothing was left behind");

        let mut answered: BTreeMap<u64, ForestProof> = BTreeMap::new();
        answered.insert(1, ForestProof::default());
        let outstanding = still_outstanding(&wanted, &answered);

        assert_eq!(outstanding.len(), 2);
        assert!(!outstanding.contains(&1), "that one came back");
    }

    /// The number said out loud, because "rebuilt 64 of 100" on its own reads
    /// as thirty six that were asked about and went unanswered.
    #[test]
    fn a_wallet_says_how_many_it_has_not_asked_about_yet() {
        let waiting = Recovery {
            stranded: 100,
            unplaceable: 0,
            asked: 2,
            archivists: 1,
            answered: 2,
            rebuilt: 64,
            refused: 0,
            not_yet_asked: 36,
        };
        let words = waiting.words().expect("a hundred notes are stuck");
        assert!(
            words.contains("36 of them have not been asked about yet"),
            "the ones nobody was asked about are named: {words}"
        );
        assert!(
            words.contains("comes back for the rest by itself"),
            "and what happens next is said rather than left to be worked out: \
             {words}"
        );

        // And a wallet whose whole question fit in one says nothing about it.
        let all_asked = Recovery {
            not_yet_asked: 0,
            ..waiting
        };
        let words = all_asked.words().expect("the notes are still stuck");
        assert!(
            !words.contains("have not been asked about yet"),
            "nothing was held back, so there is nothing to say: {words}"
        );
    }

    /// Which of the answers a person with stuck money is given, one state at
    /// a time.
    ///
    /// The tests that reach this through a running wallet each look for one
    /// phrase, and two of the answers share the phrase they look for: a
    /// wallet connected to nobody and a wallet connected to peers that keep
    /// no record both end in `--archive`. So telling somebody they are
    /// connected to nothing when they are connected to two peers passed, and
    /// so did telling them their money could move again only in part when all
    /// of it could, and naming "0 of them" as notes nothing can reach. Each
    /// state here is held to its own sentence and kept out of the others'.
    #[test]
    fn each_state_of_stuck_money_is_told_its_own_answer() {
        let stuck = Recovery {
            stranded: 3,
            asked: 2,
            archivists: 1,
            answered: 2,
            ..Recovery::default()
        };
        let cases = [
            (
                "every note rebuilt",
                Recovery {
                    rebuilt: 3,
                    ..stuck
                },
                "That money can move again",
                "still stuck",
            ),
            (
                "some notes rebuilt",
                Recovery {
                    rebuilt: 1,
                    ..stuck
                },
                "got fresh evidence for 1 of them",
                "can move again",
            ),
            (
                "nobody to ask",
                Recovery {
                    asked: 0,
                    archivists: 0,
                    answered: 0,
                    ..stuck
                },
                "not connected to anything at all",
                "none of the",
            ),
            (
                "peers, none of them keeping the record",
                Recovery {
                    archivists: 0,
                    ..stuck
                },
                "none of the 2 this wallet is connected to says it did",
                "not connected to anything",
            ),
            (
                "a peer keeping the record, and no answer from it",
                stuck,
                "It asked 1 machines that keep the whole record",
                "--archive",
            ),
        ];
        for (state, recovery, said, not_said) in cases {
            let words = recovery.words().expect("three notes are stuck");
            assert!(words.contains(said), "{state}: {words}");
            assert!(
                !words.contains(not_said),
                "{state} was told something only another state is: {words}"
            );
            assert!(
                !words.contains("cannot ask about at all"),
                "{state}: every note's place is known, so none is one nothing \
                 can reach: {words}"
            );
        }

        let one = Recovery {
            stranded: 1,
            ..stuck
        };
        let words = one.words().expect("one note is stuck");
        assert!(words.contains("holds one note it"), "{words}");
        let words = stuck.words().expect("three notes are stuck");
        assert!(words.contains("holds 3 notes it"), "{words}");
    }

    /// A refusal for want of money names the money that is there and cannot
    /// move, and says nothing about it when there is none.
    ///
    /// That clause is where a person learns the shortfall is money they hold
    /// and cannot reach yet, rather than money they lack. The tests that meet
    /// this refusal on a running wallet read its fields and never its words,
    /// so a refusal that dropped the clause, or said it about nought and not
    /// about thirty, passed.
    #[test]
    fn a_refusal_for_want_of_money_names_what_is_stranded_and_only_that() {
        let short = |stranded| {
            super::WalletError::NotEnough {
                needed: cairn("80"),
                have: cairn("50"),
                ripening: Amount::ZERO,
                waiting: Amount::ZERO,
                stranded,
            }
            .to_string()
        };

        let stuck = short(cairn("30"));
        assert!(
            stuck.contains("Another 30.00000000 CAIRN sits in notes this node cannot prove"),
            "thirty CAIRN the wallet holds and cannot move went unmentioned in the \
             refusal, so the person reads that they do not have it: {stuck}"
        );

        let none = short(Amount::ZERO);
        assert!(
            !none.contains("cannot prove"),
            "a wallet with nothing stranded was told about stranded money: {none}"
        );
        assert!(
            none.ends_with("more than the 50.00000000 CAIRN this wallet can spend"),
            "and the refusal is the plain one: {none}"
        );
    }

    /// A refusal for want of money names the rewards that cannot move yet,
    /// and says nothing about them when there are none.
    ///
    /// The clause beside it for stranded money was asked and this one was
    /// not, so a refusal that dropped the ripening money, the whole balance of
    /// a miner whose only money is a young reward, passed here.
    #[test]
    fn a_refusal_for_want_of_money_names_what_is_ripening_and_only_that() {
        let short = |ripening| {
            super::WalletError::NotEnough {
                needed: cairn("80"),
                have: cairn("0"),
                ripening,
                waiting: Amount::ZERO,
                stranded: Amount::ZERO,
            }
            .to_string()
        };
        let young = short(cairn("50"));
        assert!(
            young.contains("Another 50.00000000 CAIRN is in block rewards that cannot move"),
            "fifty CAIRN in a young reward went unmentioned in the refusal"
        );
        assert!(
            !short(Amount::ZERO).contains("block rewards"),
            "a wallet with no reward ripening was told about one"
        );
    }

    /// Notes the account has stopped answering for are counted and valued in
    /// words, and a wallet with none says nothing.
    ///
    /// This is the only place those notes reach a person, since they are kept
    /// out of every figure on purpose. Nothing read the sentence, so one that
    /// said nothing, or called one note "1 notes" and two notes "one note",
    /// passed.
    #[test]
    fn notes_the_account_stopped_answering_for_are_named_with_their_worth() {
        let owner = SecretKey::from_bytes(&[3; 32]).public_key();
        let lost = |seed: u32, value: &str| super::Unprovable {
            id: NoteId::new(Hash32::ZERO, seed),
            note: Note::new(cairn(value), owner),
            fell_at: None,
        };
        let holding = |unaccounted: Vec<super::Unprovable>| super::Holdings {
            spendable: Amount::ZERO,
            ripening: Amount::ZERO,
            ripe_at: None,
            waiting: Amount::ZERO,
            stranded: Amount::ZERO,
            unprovable: Vec::new(),
            unaccounted,
            notes: Vec::new(),
        };

        assert!(
            holding(Vec::new()).unaccounted_note().is_none(),
            "an account answering for everything it names has nothing to say"
        );

        let one = holding(vec![lost(0, "50")])
            .unaccounted_note()
            .expect("one note the account stopped answering for is said");
        assert!(
            one.contains("still names one note, worth 50.00000000 CAIRN"),
            "one note was not named as one note with its worth: {one}"
        );

        let two = holding(vec![lost(0, "50"), lost(1, "20")])
            .unaccounted_note()
            .expect("two of them are said");
        assert!(
            two.contains("still names 2 notes, worth 70.00000000 CAIRN"),
            "two notes were not counted as two, worth what they add up to: {two}"
        );
    }

    /// A slow clock is told in numbers, above the lines that call the balance
    /// right, and a refused first block is told as the certainty it is.
    ///
    /// Nothing read `Node::clock_behind` here, so a wallet refusing honest
    /// blocks for its clock said nothing at all, and with a full disk beside
    /// it said the balance was right for the chain as it stands.
    #[test]
    fn a_slow_clock_is_told_in_numbers_above_a_balance_called_right() {
        let behind = Behind {
            seconds: 9_000,
            drift: 7_200,
            blocks: 8,
            peers: 2,
            own_first_block: false,
        };
        let slow = Progress {
            clock_behind: Some(behind),
            ..healthy()
        };
        let said = slow.warning().expect("a person is told");
        assert!(
            said.contains("at least 1800 seconds slow"),
            "how far out the clock is, which is the gap less the drift, is not said"
        );
        assert!(
            said.contains("8 blocks from 2 different peers"),
            "the evidence is not said in numbers"
        );
        assert!(
            said.contains("payments made to you since will not appear"),
            "what it costs the person is not said"
        );

        let and_a_full_disk = Progress {
            unwritten: Some(Unwritten {
                what: Writing::Blocks,
                because: "no space left on device".to_owned(),
                reached: 1_200,
                written_through: Some(900),
                blocks: 300,
                within_reach: true,
            }),
            ..slow
        };
        let said = and_a_full_disk.warning().expect("a person is told");
        assert!(
            said.contains("clock"),
            "the line shown under a slow clock and a full disk says the balance is \
             right for the chain as it stands, which a slow clock makes untrue"
        );

        let before_the_opening = Progress {
            clock_behind: Some(Behind {
                own_first_block: true,
                ..behind
            }),
            ..healthy()
        };
        let said = before_the_opening.warning().expect("a person is told");
        assert!(
            said.contains("behind the day this network opened"),
            "a refused first block is told as a slow clock rather than as the \
             certainty it is"
        );
        assert!(
            !said.contains("reason to look"),
            "a certainty is hedged as a reason to look"
        );
    }

    /// A node nobody can show the chain to says what was tried and what it
    /// is doing instead.
    ///
    /// From the outside this looks like a wallet with no balance taking a
    /// long time, and the sentence is the difference. Nothing read it, so a
    /// wallet that said nothing at all, or a word nobody could act on, passed.
    #[test]
    fn a_node_nobody_could_show_the_chain_to_says_what_was_tried() {
        let waiting = Progress {
            unweighable: Some(Unweighable {
                because: "a run of 9000 headers is longer than this build takes".to_owned(),
                showings: 12,
                peers: 3,
                over: 240,
            }),
            ..healthy()
        };
        let said = waiting.warning().expect("a person is told");
        assert!(
            said.contains("12 showings from 3 different peers over 240 seconds"),
            "what was tried is not said in numbers"
        );
        assert!(
            said.contains("a run of 9000 headers is longer than this build takes"),
            "the refusal is not quoted, and it is what tells a chain this build \
             cannot weigh from somebody making one up"
        );
        assert!(
            said.contains("reading the chain block by block"),
            "and what the node does instead is not said"
        );
        assert!(
            said.contains("Leave it running"),
            "nor what the person should do, which is nothing"
        );
    }

    /// Each reason an account was not read back is told in its own words,
    /// inside the same frame.
    ///
    /// The reasons send a person to different places: a disk that changed a
    /// file is hardware to look at, and an older or newer version is not. The
    /// tests that reach this only asked that some warning came back, so a
    /// sentence that said nothing, or a word nobody could act on, passed.
    #[test]
    fn each_reason_an_account_was_not_read_back_is_told_its_own_way() {
        use crate::history::Discarded;

        let cases = [
            (Discarded::BeforeTheStamp, "This happens once."),
            (Discarded::DidNotVerify, "the disk changed it"),
            (Discarded::FromANewerVersion, "your disk is fine"),
            (Discarded::WouldNotOpen, "would not open"),
        ];
        for (why, own) in cases {
            let said = Progress {
                lost_its_account: Some(super::SetAside {
                    why,
                    kept_as: std::path::PathBuf::from("data/history.dat.unread-1"),
                }),
                ..healthy()
            }
            .warning()
            .expect("an account that was not read back is said");
            assert!(
                said.contains("did not read back the account it had written down"),
                "{why:?} was not said to be an account that did not read back"
            );
            assert!(said.contains(own), "{why:?} was not told its own reason");
            for (other, theirs) in cases {
                assert!(
                    other == why || !said.contains(theirs),
                    "{why:?} was told the reason for {other:?}"
                );
            }
            assert!(
                said.contains("the key file is not touched"),
                "{why:?} did not say the key is safe"
            );
            assert!(
                said.contains("data/history.dat.unread-1"),
                "{why:?} did not say where the account it could not read went"
            );
            assert!(
                !said.contains("becomes right"),
                "{why:?} promised a balance that is missing every note fallen before \
                 the oldest block the node holds"
            );
        }
    }

    /// A wallet on a directory of its own, with no chain and no peer.
    fn opened(name: &str) -> (super::Wallet, std::path::PathBuf) {
        let directory =
            std::env::temp_dir().join(format!("cairn-wallet-lib-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let key_file = directory.join("key");
        crate::keyfile::write(&key_file, &SecretKey::generate().unwrap()).unwrap();
        let (wallet, _) = super::Wallet::open(
            &key_file,
            cairn_ledger::validation::ConsensusParams::testnet(),
            &directory.join("data"),
        )
        .unwrap();
        (wallet, directory)
    }

    /// Leaves `lock` poisoned, the way a thread that panicked holding it does.
    fn poison<T: Send>(lock: &std::sync::Mutex<T>) {
        std::thread::scope(|scope| {
            let _ = scope
                .spawn(|| {
                    let _held = lock.lock();
                    std::panic::resume_unwind(Box::new("a thread panicked holding the lock"));
                })
                .join();
        });
        assert!(
            lock.is_poisoned(),
            "the lock is not poisoned, so the tests that use this ask nothing"
        );
    }

    /// A wallet that could not write its account down says so, after a thread
    /// panicked holding the answer as well as before.
    ///
    /// Every other lock in this crate, and in the node under it, is taken as
    /// it stands once a thread has panicked holding it, and the node says why
    /// at `Shared::outdated`: reading a poisoned lock with `.lock().ok()`
    /// answers nothing for ever. This one answered `true`, so the line above
    /// the money saying the account is no longer being written down went
    /// away for good. Nothing poisoned a lock in any test, so a wallet that
    /// answered a poisoned lock with a default passed.
    #[test]
    fn a_wallet_that_cannot_write_its_account_says_so_after_a_panic_held_the_answer() {
        let (wallet, directory) = opened("poisoned-said");
        *wallet.wrote_history.lock().unwrap() = false;
        poison(&wallet.wrote_history);

        let keeping = wallet.progress().keeping_its_account;
        wallet.shutdown();
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            !keeping,
            "a wallet that could not write its account down said it was keeping it, \
             because a thread had panicked holding the answer"
        );
    }

    /// Whether the account was written down is recorded after a thread
    /// panicked holding the record as well as before.
    ///
    /// It was recorded only when the lock was clean, so after a panic a save
    /// that failed left the wallet saying the last one had worked. Nothing
    /// poisoned a lock in any test, so a wallet that stopped recording passed.
    #[test]
    fn a_save_that_failed_is_recorded_after_a_panic_held_the_record() {
        use crate::history::History;

        let (mut wallet, directory) = opened("poisoned-recorded");
        // Nowhere a file can be written, so the save fails.
        wallet.history_file = directory.join("no-such-directory").join("history.dat");
        poison(&wallet.wrote_history);

        wallet.write_history(&History::new());
        let recorded = *wallet
            .wrote_history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        wallet.shutdown();
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            !recorded,
            "a save that failed was not recorded, because a thread had panicked \
             holding the record, and the wallet went on saying its account was written"
        );
    }

    /// Money the account recorded and the node cannot place is counted after
    /// a thread panicked holding the account as well as before.
    ///
    /// The account was read with a default in its place when its lock was
    /// poisoned, so every note it had recorded that the node has nothing to
    /// say about left the balance without a word: the balance going quietly
    /// down, which this crate has already said is the worse of the two ways
    /// to be wrong. Nothing poisoned a lock in any test, so a wallet that
    /// counted from an empty account after a panic passed.
    #[test]
    fn money_the_account_recorded_is_counted_after_a_panic_held_the_account() {
        use cairn_ledger::block::{Block, BlockHeader};
        use cairn_ledger::note::NetworkId;
        use cairn_ledger::transaction::CoinbaseTransaction;

        let (wallet, directory) = opened("poisoned-counted");
        let mine = wallet.address();
        let paid = cairn("50");
        // A block this wallet's node never saw, so the account holds a note
        // the node has nothing to say about.
        let block = Block {
            header: BlockHeader {
                version: 1,
                network: NetworkId::TESTNET,
                height: 0,
                previous: Hash32::ZERO,
                state_root: Hash32::ZERO,
                transactions_root: Hash32::ZERO,
                history: Hash32::ZERO,
                timestamp: 1_000,
                difficulty: 1,
                total_work: 0,
                nonce: 0,
            },
            coinbase: CoinbaseTransaction::new(0, vec![Note::new(paid, mine)]),
            transfers: Vec::new(),
        };
        wallet.history.lock().unwrap().take(&block, mine);
        poison(&wallet.history);

        let stranded = wallet.holdings().stranded;
        wallet.shutdown();
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(
            stranded, paid,
            "a note the account recorded and the node cannot place left the balance, \
             because a thread had panicked holding the account"
        );
    }

    /// A note the node answers for is taken off the list of ones the account
    /// stopped answering for, after a thread panicked holding the account as
    /// well as before.
    ///
    /// The marking was skipped when the lock was poisoned, so the note stayed
    /// on the list and the wallet went on saying it had stopped answering for
    /// money it could see. Nothing poisoned a lock in any test, so a wallet
    /// that skipped it passed.
    #[test]
    fn a_note_found_again_is_accounted_for_after_a_panic_held_the_account() {
        use cairn_ledger::transaction::CoinbaseTransaction;
        use cairn_ledger::validation::{assemble_block, mine_block, ConsensusParams};

        let (wallet, directory) = opened("poisoned-found");
        let mine = wallet.address();
        let params = ConsensusParams::testnet();
        let coinbase = CoinbaseTransaction::new(0, vec![Note::new(params.initial_reward, mine)]);
        let block = assemble_block(
            &cairn_ledger::LedgerState::new(),
            coinbase,
            Vec::new(),
            &params,
            1_600,
            0,
        )
        .unwrap();
        wallet
            .node()
            .submit_block(mine_block(block, 1 << 22).unwrap())
            .unwrap();
        assert_eq!(wallet.node().height(), Some(0), "the node took the block");
        wallet.follow_to_the_tip();
        {
            let mut history = wallet.history.lock().unwrap();
            // Past a block it will never read, which is what marks every note
            // held as one the account can no longer answer for.
            let next = history.next();
            history.skip_to(next + 1);
            assert_eq!(
                history.unaccounted().count(),
                1,
                "the note is not on the list, so this asks nothing"
            );
        }
        poison(&wallet.history);

        let _ = wallet.holdings();
        let left = wallet
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unaccounted()
            .count();
        wallet.shutdown();
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(
            left, 0,
            "a note the node holds stayed on the list of ones the account stopped \
             answering for, because a thread had panicked holding the account"
        );
    }
}

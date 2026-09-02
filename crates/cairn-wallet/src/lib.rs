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
pub mod page;
pub mod serve;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::history::{Discarded, History, Movement};
use cairn_accumulator::ForestProof;
use cairn_chain::Outdated;
use cairn_crypto::{random_bytes, PublicKey, SecretKey};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{Input, Transfer};
use cairn_ledger::validation::{ConsensusParams, TransferError};
use cairn_net::node::{Probation, Refused, Stranded, Unjudged, Unwritten};
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
        "{needed} is more than the {have} this wallet can spend{}{}",
        waiting_note(*waiting),
        stranded_note(*stranded)
    )]
    NotEnough {
        needed: Amount,
        have: Amount,
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

fn stranded_note(stranded: Amount) -> String {
    if stranded == Amount::ZERO {
        String::new()
    } else {
        format!(". Another {stranded} sits in notes this node cannot prove")
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
    /// will not let anybody spend twice. A wallet that went on counting it
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
    #[must_use]
    pub fn total(&self) -> Amount {
        self.spendable
            .checked_add(self.waiting)
            .and_then(|sum| sum.checked_add(self.stranded))
            .unwrap_or(self.spendable)
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
        if self.rebuilt > 0 && self.rebuilt >= self.stranded {
            return Some(format!(
                "Spending a note that has been put away needs a small piece of \
                 evidence that goes stale, and this wallet's own copy had gone \
                 stale for {notes}. It asked {} of the machines it is connected \
                 to, got fresh evidence back, and checked it against the chain it \
                 has verified itself. That money can move again.",
                self.asked
            ));
        }
        if self.rebuilt > 0 {
            return Some(format!(
                "Spending a note that has been put away needs a small piece of \
                 evidence that goes stale, and this wallet's own copy had gone \
                 stale for {notes}. It asked around and got fresh evidence for {} \
                 of them, checked against the chain it has verified itself. The \
                 rest is still stuck, and asking again later may find it.",
                self.rebuilt
            ));
        }
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
        if self.asked == 0 {
            return Some(format!(
                "This wallet holds {notes} it cannot spend yet. Spending a note \
                 that has been put away needs a small piece of evidence that goes \
                 stale, and this wallet's copy has. Rebuilding one takes a machine \
                 that kept the whole record, and this wallet is not connected to \
                 anything at all. Connect to a peer that was started with \
                 --archive, or start one yourself."
            ));
        }
        if self.archivists == 0 {
            return Some(format!(
                "This wallet holds {notes} it cannot spend yet. Spending a note \
                 that has been put away needs a small piece of evidence that goes \
                 stale, and this wallet's copy has. Rebuilding one takes a machine \
                 that kept the whole record, and none of the {} this wallet is \
                 connected to says it did. Connect to a peer started with \
                 --archive, or start one yourself.",
                self.asked
            ));
        }
        Some(format!(
            "This wallet holds {notes} it cannot spend yet. It asked {} machines \
             that keep the whole record, and none of them could say where these \
             notes sit. Asking again later may do better; so may a different peer.",
            self.archivists
        ))
    }
}

/// A payment this wallet handed over that no block carries yet.
///
/// A wallet that could not say this had only two things to tell its owner
/// about a payment, done and not done, and a payment spends most of its first
/// few minutes being neither.
#[derive(Clone, Copy, Debug)]
pub struct Waiting {
    pub id: Hash32,
    /// What leaves this key when a block carries it: what is being paid, and
    /// the fee with it.
    pub amount: Amount,
    /// What it holds meanwhile, which is more. The difference comes back as
    /// change, and comes back only when a block carries it.
    pub committed: Amount,
}

/// Where this wallet's node has got to.
#[derive(Clone, Debug)]
pub struct Progress {
    pub height: Option<u64>,
    pub peers: usize,
    pub joining: Joined,
    pub total_work: u128,
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
    /// Blocks the node met that this build has no rules to judge, if enough of
    /// them came from enough peers to mean anything.
    pub unjudged: Option<Unjudged>,
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
    /// was there and was not used.
    ///
    /// Set once at start and left set, because what it costs does not go away
    /// when the rescan catches up: the movements below where the reading
    /// restarts are gone whatever the height says afterwards.
    pub lost_its_account: Option<Discarded>,
}

/// The line for a wallet whose own account of what it was paid did not read
/// back.
///
/// Its own function because the three reasons need three different sentences
/// and the one thing they must not do is share a vague one: an operator told
/// their disk is suspect looks at hardware, and one told their wallet is a
/// version behind looks at the version.
fn lost_its_account(why: Discarded) -> String {
    let because = match why {
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
             one has no reader for. The file is whole and your disk is fine. Going \
             back to the newer version reads it again."
        }
    };
    format!(
        "This wallet did not read back the account it had written down. {because} It is \
         reading the chain again to rebuild it, so the balance beside this becomes right \
         on its own. What does not come back is the list of payments older than the \
         oldest block your node still holds. Nothing is lost on the chain and the key \
         file is not touched."
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
    /// Only one line is shown, so the order is a ranking. The ones that mean
    /// the numbers beside them are wrong or frozen come first; the account
    /// this wallet lost comes last, because the balance is right and becomes
    /// right again on its own, and what it costs is a record rather than
    /// money.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        if let Some(unwritten) = &self.unwritten {
            let kept = unwritten.written_through.map_or_else(
                || "nothing at all".to_owned(),
                |height| format!("block {height}"),
            );
            let lost = if unwritten.within_reach {
                "They can still reach it if the room comes back."
            } else {
                "They are no longer anywhere this node can read them from, so \
                 nothing done now will put them on the disk."
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
        if !self.keeping_its_account {
            return Some(
                "This wallet cannot write down its own account of what you have been \
                 paid. The balance beside this is still right, and it is being kept in \
                 memory only: if the wallet is closed it will have to read its way back \
                 through the chain, and anything older than the blocks your node still \
                 keeps will be gone. The usual cause is a disk with nothing left on it."
                    .to_owned(),
            );
        }
        if let Some(outdated) = self.outdated {
            return Some(format!(
                "This wallet is too old for the chain it is on. The rules from block {} need \
                 version {}, and this program knows only version {}. It stopped following the \
                 chain there on purpose, so the height and the balance shown are from before \
                 that moment and will not move again. Install a newer wallet and start it \
                 again: nothing on disk is lost, and the key file is not touched.",
                outdated.height, outdated.required, outdated.known
            ));
        }
        if let Some(stranded) = self.stranded {
            return Some(format!(
                "This wallet was handed the ledger at block {}, and had to check its own way to \
                 block {} before it could stand behind it. The blocks in between never arrived, \
                 and it holds nothing below block {}, so there is no other way to reach them. \
                 The balance shown is not one this wallet has checked. Delete this wallet's data \
                 directory and start it again from a peer you trust; the key file is a separate \
                 file and is not touched by that.",
                stranded.anchor, stranded.settles_at, stranded.anchor
            ));
        }
        if let Some(why) = self.lost_its_account {
            return Some(lost_its_account(why));
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
    /// Whether a peer took it. False means it is not spent: nobody has it.
    pub handed_on: bool,
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
const CATCH_UP_BATCH: u64 = 512;

/// How long the chain has to sit still, with somebody to ask, before catching
/// up counts as done.
const SETTLED_FOR: Duration = Duration::from_secs(2);

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
    /// Why the account on disk was not read back at start, if it was not.
    lost_its_account: Option<Discarded>,
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
        let (history, lost_its_account) = History::load(&history_file);
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
    pub fn floor_for(&self, recipient: PublicKey, amount: Amount) -> Amount {
        let holdings = self.holdings();
        let mut fee = Amount::ZERO;
        for _ in 0..QUOTE_ROUNDS {
            let Some(needed) = amount.checked_add(fee) else {
                return fee;
            };
            // Not enough to cover the amount and this fee together. Sending is
            // where that is said, with the numbers; quoting a larger fee here
            // would only make it worse.
            let Some(draft) = self.draft(&holdings, recipient, amount, needed) else {
                return fee;
            };
            if draft.floor <= fee {
                return fee;
            }
            fee = draft.floor;
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
    ) -> Option<Draft> {
        let (spending, gathered) = select(&holdings.notes, needed)?;
        let change = gathered.checked_sub(needed)?;
        let mut outputs = vec![Note::new(amount, recipient)];
        if change > Amount::ZERO {
            outputs.push(Note::new(change, self.address()));
        }
        let inputs = spending.iter().map(Held::as_input).collect();
        let transfer = Transfer::new(inputs, outputs);
        let bytes = transfer.encode().len();
        Some(Draft {
            floor: floor_of(&transfer, bytes, &spending),
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
            peers: self.node.peer_count(),
            joining: self.node.joining(),
            total_work: self.node.total_work(),
            probation: self.node.probation(),
            outdated: self.node.outdated(),
            stranded: self.node.stranded(),
            unwritten: self.node.unwritten(),
            unjudged: self.node.unjudged(),
            keeping_its_account: self.wrote_history.lock().map_or(true, |wrote| *wrote),
            lost_its_account: self.lost_its_account,
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
    pub fn catch_up(&self, patience: Duration) {
        let deadline = Instant::now()
            .checked_add(patience)
            .unwrap_or_else(Instant::now);
        let mut last = self.node.height();
        let mut still_since = Instant::now();

        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
            let height = self.node.height();
            if height != last {
                last = height;
                still_since = Instant::now();
                continue;
            }
            if height.is_none() {
                continue;
            }
            if self.node.peer_count() > 0 && still_since.elapsed() > SETTLED_FOR {
                return;
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
        if history.diverged(Some(tip), |height| {
            self.node.archived_at(height).map(|block| block.id())
        }) {
            history.forget();
            self.write_history(&history);
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
            self.write_history(&history);
        }
        drop(history);
        self.note_where_they_landed();
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
    /// The place is the half worth keeping. It is fixed the moment a note
    /// falls and never moves again, while the path up to it moves every time
    /// another note falls, which is why nobody keeps paths for strangers and
    /// why the place is what a wallet has to be able to name later.
    ///
    /// Walked rather than watched for, because there is nowhere to hang the
    /// watching: what the node knows is a map, and comparing it against this
    /// account is a pass over the wallet's own notes. Nothing is written
    /// unless something was learned.
    fn note_where_they_landed(&self) {
        let mine = self.address();
        let landed: Vec<(NoteId, u64)> = self.node.with_chain(|chain| {
            chain
                .state()
                .watched_notes()
                .filter(|(_, _, note)| note.owner == mine)
                .map(|(id, position, _)| (id, position))
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
        for (id, position) in landed {
            learned |= history.fell_at(id, position);
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
        while self.follow() > 0 {}
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
            tip,
        }
    }

    /// Everything this key owns, and what part of it cannot move.
    ///
    /// The confirmed ledger is only half the answer. What is waiting in the
    /// pool has not happened, but the notes it holds are promised, and money a
    /// wallet shows as spendable had better be money it can spend.
    #[must_use]
    pub fn holdings(&self) -> Holdings {
        self.reckon().0
    }

    /// The payments this wallet has handed over that no block carries yet.
    #[must_use]
    pub fn waiting(&self) -> Vec<Waiting> {
        self.reckon().1
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
        let places: BTreeSet<u64> = wanted.iter().map(|(at, _)| *at).collect();
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
            let same_question = places.is_subset(&last.unresolved);
            let better_now = self.node.archiving_peers() > last.report.archivists
                || (last.report.asked == 0 && self.node.peer_count() > 0);
            if paused && same_question && !better_now {
                return last.report;
            }
        }

        let unplaceable = holdings.unprovable.len().saturating_sub(wanted.len());
        let answer = self.node.recover_proofs(&wanted, RECOVERY_PATIENCE);

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
        };
        let mut last = self
            .last_recovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        last.unresolved = places
            .into_iter()
            .filter(|at| !answer.proofs.contains_key(at))
            .collect();
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
        if let Ok(mut wrote) = self.wrote_history.lock() {
            *wrote = kept;
        }
    }

    /// One reading of the chain answering both, since the pool decides what is
    /// spendable and the notes decide what the pool is holding.
    #[allow(clippy::too_many_lines)]
    fn reckon(&self) -> (Holdings, Vec<Waiting>) {
        let mine = self.address();
        // This wallet's own account of what it has been paid, which is what
        // lets it notice a note the node has stopped following, and where each
        // one landed, which is what lets it ask about one.
        let (recorded, landed): (BTreeMap<NoteId, Amount>, BTreeMap<NoteId, u64>) = self
            .history
            .lock()
            .map(|history| {
                let held: BTreeMap<NoteId, Amount> = history.held().collect();
                let landed = held
                    .keys()
                    .filter_map(|id| Some((*id, history.where_it_fell(id)?)))
                    .collect();
                (held, landed)
            })
            .unwrap_or_default();
        // Paths somebody else rebuilt for this wallet. Each is checked below
        // against the set as it stands rather than remembered as good, because
        // the set moves whenever a note falls and a path is worth exactly what
        // it is worth now.
        let rebuilt = self
            .rebuilt
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default();
        self.node.with_chain(|chain| {
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
            for (id, value) in &recorded {
                if seen.contains(id) {
                    continue;
                }
                let note = Note::new(*value, mine);
                match place(*id, note, None) {
                    Ok(one) => held.push(one),
                    Err(one) => unprovable.push(one),
                }
            }

            let values: BTreeMap<NoteId, Amount> = held
                .iter()
                .map(|one| (one.id, one.note.value))
                .chain(unprovable.iter().map(|one| (one.id, one.note.value)))
                .collect();

            // An input names a note and not its owner, so which pooled
            // transfers are ours is decided by which notes they reach for.
            let mut committed: BTreeSet<NoteId> = BTreeSet::new();
            let mut waiting: Vec<Waiting> = Vec::new();
            for (id, transfer) in chain.pooled_transfers() {
                let ours: Vec<NoteId> = transfer
                    .inputs
                    .iter()
                    .map(|input| input.note_id)
                    .filter(|note_id| values.contains_key(note_id))
                    .collect();
                if ours.is_empty() {
                    continue;
                }
                let gave = ours.iter().fold(Amount::ZERO, |sum, note_id| {
                    values
                        .get(note_id)
                        .and_then(|value| sum.checked_add(*value))
                        .unwrap_or(sum)
                });
                let got = transfer
                    .created_notes()
                    .into_iter()
                    .filter(|(_, note)| note.owner == mine)
                    .fold(Amount::ZERO, |sum, (_, note)| {
                        sum.checked_add(note.value).unwrap_or(sum)
                    });
                committed.extend(ours);
                waiting.push(Waiting {
                    id: *id,
                    amount: gave.checked_sub(got).unwrap_or(Amount::ZERO),
                    committed: gave,
                });
            }

            let mut notes = Vec::with_capacity(held.len());
            let mut spendable = Amount::ZERO;
            let mut promised = Amount::ZERO;
            let mut ripening = Amount::ZERO;
            let mut ripe_at: Option<u64> = None;
            for one in held {
                let value = one.note.value;
                if committed.contains(&one.id) {
                    promised = promised.checked_add(value).unwrap_or(promised);
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
                    notes,
                },
                waiting,
            )
        })
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

    fn spend(
        &self,
        recipient: PublicKey,
        amount: Amount,
        fee: Amount,
        meant: bool,
    ) -> Result<Sent, WalletError> {
        if amount == Amount::ZERO {
            return Err(WalletError::NothingToSend);
        }
        let needed = amount.checked_add(fee).ok_or(WalletError::TooLarge)?;

        let holdings = self.holdings();
        let short = || WalletError::NotEnough {
            needed,
            have: holdings.spendable,
            waiting: holdings.waiting,
            stranded: holdings.stranded,
        };
        let draft = self
            .draft(&holdings, recipient, amount, needed)
            .ok_or_else(short)?;

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
        if draft.bytes > self.params.max_block_bytes {
            return Err(WalletError::TooBulky {
                notes: draft.spending.len(),
                bytes: draft.bytes,
                limit: self.params.max_block_bytes,
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

        // Held open long enough for the transfer to leave. Reporting a spend
        // that reached nobody as done would be telling someone their money
        // moved when it did not.
        let handed_on = wait_until(Duration::from_secs(5), || self.node.peer_count() > 0);
        std::thread::sleep(Duration::from_millis(500));

        Ok(Sent {
            id,
            amount,
            fee,
            change: draft.change,
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

/// What the network asks to carry `transfer`.
fn floor_of(transfer: &Transfer, bytes: usize, spending: &[Held]) -> Amount {
    let freed = spending.iter().filter(|held| held.fallen.is_none()).count();
    cairn_chain::fee_floor(cairn_chain::transfer_weight(transfer, bytes, freed))
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
        other => format!("the network would not take this payment, and nothing was sent: {other}"),
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
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{ceiling, said_plainly, shuffle, Progress};
    use cairn_ledger::note::NoteId;
    use cairn_ledger::validation::TransferError;
    use cairn_net::node::{Probation, Refused};
    use cairn_net::Joined;
    use cairn_primitives::{Amount, Hash32};

    fn cairn(text: &str) -> Amount {
        Amount::from_cairn(text).unwrap()
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
    }

    /// The node reports three states in which a height and a balance say
    /// nothing, and the wallet showed none of them. Probation is the one that
    /// matters most: joining reports itself done throughout it, so a wallet
    /// just started shows a balance out of a ledger it has not checked.
    #[test]
    fn a_ledger_this_wallet_has_not_checked_is_said_to_be_one() {
        let healthy = Progress {
            keeping_its_account: true,
            lost_its_account: None,
            unwritten: None,
            unjudged: None,
            height: Some(10),
            peers: 1,
            joining: Joined::Done,
            total_work: 10,
            probation: None,
            outdated: None,
            stranded: None,
        };
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
        assert!(said.contains("900"), "{said}");
        assert!(said.contains("40 of the 100"), "{said}");
        assert!(said.contains("has not yet checked"), "{said}");
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
}

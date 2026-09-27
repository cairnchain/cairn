//! Payments this wallet handed over, written down until the chain settles
//! them.
//!
//! A transfer handed to the network waits in a pool until a miner carries it,
//! and the pool is memory in the process that made it. `cairn-wallet send` is
//! a process that hands a payment over and exits, so the next command, in a
//! new process, had no record that the payment existed: it counted the notes
//! the payment spends as spendable again, showed nothing waiting, and sent the
//! same payment a second time on the same notes. The page lives longer and met
//! the same silence another way: a pool lets a payment go when the chain moves
//! under it, a note it spends falling out of the hot set is enough, and
//! nothing said so. The waiting box went away and the balance went back up,
//! which is also what a payment that was carried looks like.
//!
//! So every payment the pool takes is written here, with everything it takes
//! to hand it over again, and kept until a block carries it or it is plainly
//! not going to be carried. It is this wallet's own record, beside its account
//! and written the same way: nothing in the protocol changes and no peer ever
//! sees it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use cairn_crypto::PublicKey;
use cairn_ledger::transaction::Transfer;
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::{hash, Domain, HASH_LEN};
use cairn_primitives::{Amount, Hash32};

/// What the record is called, inside the wallet's own directory.
pub(crate) const PENDING_FILE: &str = "pending.dat";

/// What the first bytes of the record say it is.
///
/// The stamp at the end is the account's own, `Domain::WalletHistory`, which
/// guards against a disk that changed under a file and not against anybody.
/// This is what keeps the two files apart: an account copied over this one
/// verifies and then fails here rather than being read as payments.
const MAGIC: &[u8; 16] = b"cairn pending v1";

/// Payments the record keeps.
///
/// Past this the oldest that is no longer waited on goes first, and only if
/// there is none does a payment still being waited on go. A wallet with this
/// many payments in flight at once is not one anybody runs by hand.
const MOST_KEPT: usize = 256;

/// Words kept about one payment, in bytes. What goes in is this wallet's own
/// sentences, so the bound only stops a changed file from asking for memory.
const MOST_WORDS: usize = 4096;

/// Blocks a payment this wallet's own node will not take back is still held
/// for, counted from the first block at which it would not.
///
/// A pool asks every transfer it holds again after every block, against rules
/// every node applies alike: what this node refuses on the chain as it stands,
/// a peer on the same chain has dropped too. The wait is for the peer that is
/// a block or two behind, and for this node being the one that is behind. Past
/// it the notes come back to the balance, and the payment is named as not
/// carried rather than left holding them for ever.
pub const HELD_AFTER_REFUSAL: u64 = 6;

/// Blocks a payment that was not carried is still named for, once it stopped
/// being waited on.
///
/// Long enough that somebody who looks at the wallet once a day reads it. A
/// command line that runs once and exits cannot say anything between two
/// runs, so the sentence has to still be there at the next one.
pub const NAMED_FOR: u64 = 144;

/// One payment this wallet handed over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Handed {
    /// The transfer as it was handed over, signed.
    ///
    /// What identifies a transfer, and what its signatures commit to, leave
    /// out how each note is shown to be spendable. So this is also what is
    /// handed over again once that evidence has gone stale, with fresher
    /// evidence in it and the same identifier.
    pub(crate) transfer: Transfer,
    /// Who it pays.
    pub(crate) to: PublicKey,
    /// What it pays them.
    pub(crate) amount: Amount,
    /// What it pays to be carried.
    pub(crate) fee: Amount,
    /// The height of this wallet's chain when it was handed over.
    pub(crate) made_at: u64,
    /// The first height at which this wallet's own node would not take it
    /// back, and what it said, if it would not.
    pub(crate) refused: Option<(u64, String)>,
    /// The height at which it stopped being waited on, and why, if it has.
    pub(crate) ended: Option<(u64, String)>,
}

impl Handed {
    pub(crate) fn id(&self) -> Hash32 {
        self.transfer.id()
    }

    /// The block from which its notes come back to the balance, if its own
    /// node has refused it.
    pub(crate) fn held_until(&self) -> Option<u64> {
        self.refused
            .as_ref()
            .map(|(since, _)| since.saturating_add(HELD_AFTER_REFUSAL))
    }
}

/// Words, as the record keeps them: whole characters, up to [`MOST_WORDS`]
/// bytes of them, so what is cut short still reads back.
fn encode_words(words: &str, out: &mut Vec<u8>) {
    let mut end = words.len().min(MOST_WORDS);
    while !words.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    words
        .as_bytes()
        .get(..end)
        .unwrap_or_default()
        .to_vec()
        .encode_to(out);
}

fn decode_words(reader: &mut Reader<'_>) -> Result<String, CodecError> {
    let bytes =
        cairn_primitives::codec::take_at_most::<u8>(reader, MOST_WORDS, "words about a payment")?;
    String::from_utf8(bytes).map_err(|_| CodecError::InvalidValue {
        type_name: "words about a payment",
    })
}

fn encode_moment(moment: Option<&(u64, String)>, out: &mut Vec<u8>) {
    match moment {
        None => 0u8.encode_to(out),
        Some((height, words)) => {
            1u8.encode_to(out);
            height.encode_to(out);
            encode_words(words, out);
        }
    }
}

fn decode_moment(reader: &mut Reader<'_>) -> Result<Option<(u64, String)>, CodecError> {
    match u8::decode_from(reader)? {
        0 => Ok(None),
        1 => Ok(Some((u64::decode_from(reader)?, decode_words(reader)?))),
        _ => Err(CodecError::InvalidValue {
            type_name: "a moment in a payment's life",
        }),
    }
}

impl Encode for Handed {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.transfer.encode_to(out);
        self.to.encode_to(out);
        self.amount.encode_to(out);
        self.fee.encode_to(out);
        self.made_at.encode_to(out);
        encode_moment(self.refused.as_ref(), out);
        encode_moment(self.ended.as_ref(), out);
    }
}

impl Decode for Handed {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            transfer: Transfer::decode_from(reader)?,
            to: PublicKey::decode_from(reader)?,
            amount: Amount::decode_from(reader)?,
            fee: Amount::decode_from(reader)?,
            made_at: u64::decode_from(reader)?,
            refused: decode_moment(reader)?,
            ended: decode_moment(reader)?,
        })
    }
}

/// Every payment this wallet is keeping a record of.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pending {
    handed: Vec<Handed>,
}

/// What became of a record that was there and could not be read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotReadBack {
    /// Moved out of the way under this name, where it can still be read.
    Moved(PathBuf),
    /// Left where it was, because it would not move. Nothing is written over
    /// it: the payments this wallet hands over from now on are kept in memory
    /// only.
    Stuck,
}

impl Pending {
    /// Payments still being waited on, oldest first.
    pub(crate) fn live(&self) -> impl Iterator<Item = &Handed> {
        self.handed.iter().filter(|one| one.ended.is_none())
    }

    /// Payments that stopped being waited on without a block carrying them,
    /// oldest first.
    pub(crate) fn ended(&self) -> impl Iterator<Item = &Handed> {
        self.handed.iter().filter(|one| one.ended.is_some())
    }

    fn find(&mut self, id: &Hash32) -> Option<&mut Handed> {
        self.handed.iter_mut().find(|one| one.id() == *id)
    }

    /// Writes down a payment the pool has just taken.
    pub(crate) fn hand(&mut self, handed: Handed) {
        let id = handed.id();
        self.handed.retain(|one| one.id() != id);
        self.handed.push(handed);
        while self.handed.len() > MOST_KEPT {
            let oldest = self
                .handed
                .iter()
                .position(|one| one.ended.is_some())
                .unwrap_or(0);
            self.handed.remove(oldest);
        }
    }

    /// Takes a payment off the record, because a block carried it or because
    /// nobody was ever offered it. Says whether it was there.
    pub(crate) fn settle(&mut self, id: &Hash32) -> bool {
        let before = self.handed.len();
        self.handed.retain(|one| one.id() != *id);
        self.handed.len() != before
    }

    /// Notes that this wallet's own node took a payment back. Says whether
    /// that changed anything.
    pub(crate) fn taken_back(&mut self, id: &Hash32) -> bool {
        self.find(id)
            .is_some_and(|one| one.refused.take().is_some())
    }

    /// Notes that this wallet's own node would not take a payment back, at
    /// `tip`, for `why`. The height is the first time it would not, which is
    /// what the wait before its notes come back is counted from. Says whether
    /// that changed anything.
    pub(crate) fn refused(&mut self, id: &Hash32, tip: u64, why: &str) -> bool {
        let Some(one) = self.find(id) else {
            return false;
        };
        let since = one.refused.as_ref().map_or(tip, |(since, _)| *since);
        let changed = one.refused.as_ref() != Some(&(since, why.to_owned()));
        one.refused = Some((since, why.to_owned()));
        changed
    }

    /// Stops waiting on a payment, at `tip`, for `why`. Its notes come back
    /// to the balance and it is named as not carried for [`NAMED_FOR`]
    /// blocks. Says whether that changed anything.
    pub(crate) fn end(&mut self, id: &Hash32, tip: u64, why: &str) -> bool {
        match self.find(id) {
            Some(one) if one.ended.is_none() => {
                one.ended = Some((tip, why.to_owned()));
                true
            }
            _ => false,
        }
    }

    /// Stops waiting on every payment refused for long enough, at `tip`, and
    /// forgets every one named for long enough. Says whether anything
    /// changed.
    pub(crate) fn age(&mut self, tip: u64) -> bool {
        let mut changed = false;
        for one in &mut self.handed {
            if one.ended.is_some() {
                continue;
            }
            let (Some(until), Some((_, why))) = (one.held_until(), one.refused.as_ref()) else {
                continue;
            };
            if tip >= until {
                one.ended = Some((tip, why.clone()));
                changed = true;
            }
        }
        let before = self.handed.len();
        self.handed.retain(|one| {
            one.ended
                .as_ref()
                .is_none_or(|(at, _)| tip < at.saturating_add(NAMED_FOR))
        });
        changed || self.handed.len() != before
    }

    /// Reads the record back from `path`, or starts empty.
    ///
    /// A record that is not there is a wallet that has handed nothing over.
    /// One that is there and does not read back is set aside rather than
    /// written over, and the caller is told where it went, because what it
    /// held was payments this wallet may still be waiting on.
    pub(crate) fn load(path: &Path) -> (Self, Option<NotReadBack>) {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (Self::default(), None)
            }
            Err(_) => return (Self::default(), Some(set_aside(path))),
        };
        match Self::verified(&bytes) {
            Some(pending) => (pending, None),
            None => (Self::default(), Some(set_aside(path))),
        }
    }

    fn verified(bytes: &[u8]) -> Option<Self> {
        let (body, stamp) = bytes.split_at_checked(bytes.len().checked_sub(HASH_LEN)?)?;
        if hash(Domain::WalletHistory, body).as_bytes() != stamp {
            return None;
        }
        let rest = body.strip_prefix(MAGIC.as_slice())?;
        Self::decode(rest).ok()
    }

    /// Writes it beside itself and moves it into place, as the account is
    /// written, so a wallet stopped partway keeps the record it had.
    pub(crate) fn save(&self, path: &Path) -> std::io::Result<()> {
        let partial = path.with_extension("part");
        let mut bytes = MAGIC.to_vec();
        self.encode_to(&mut bytes);
        let stamp = hash(Domain::WalletHistory, &bytes);
        bytes.extend_from_slice(stamp.as_bytes());
        // Made new, by the helper the account's partial file and the page's
        // link are made by: opened in place, a symbolic link planted at this
        // name would choose where the record goes, and empty it first.
        let written = crate::keyfile::create_anew(&partial).and_then(|mut file| {
            file.write_all(&bytes)?;
            file.sync_all()
        });
        if let Err(error) = written.and_then(|()| std::fs::rename(&partial, path)) {
            let _ = std::fs::remove_file(&partial);
            return Err(error);
        }
        if let Some(directory) = path.parent() {
            if let Ok(handle) = std::fs::File::open(directory) {
                let _ = handle.sync_all();
            }
        }
        Ok(())
    }
}

impl Encode for Pending {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.handed.encode_to(out);
    }
}

impl Decode for Pending {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            handed: cairn_primitives::codec::take_at_most(reader, MOST_KEPT, "payments")?,
        })
    }
}

/// Moves a record that did not read back to a name of its own, the first of
/// `pending.dat.unread`, `pending.dat.unread-1` and so on that is free.
fn set_aside(path: &Path) -> NotReadBack {
    for attempt in 0u32..64 {
        let name = if attempt == 0 {
            path.with_extension("dat.unread")
        } else {
            path.with_extension(format!("dat.unread-{attempt}"))
        };
        if name.exists() {
            continue;
        }
        return match std::fs::rename(path, &name) {
            Ok(()) => NotReadBack::Moved(name),
            Err(_) => NotReadBack::Stuck,
        };
    }
    NotReadBack::Stuck
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{Handed, NotReadBack, Pending, HELD_AFTER_REFUSAL, MOST_KEPT, NAMED_FOR};
    use cairn_crypto::SecretKey;
    use cairn_ledger::note::{Note, NoteId};
    use cairn_ledger::transaction::{Input, Transfer};
    use cairn_primitives::{Amount, Hash32};

    fn scratch(name: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "cairn-pending-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    /// Who the payments here pay: one key for the whole run, so the same
    /// seed makes the same payment twice.
    fn payee() -> cairn_crypto::PublicKey {
        static ONE: std::sync::OnceLock<cairn_crypto::PublicKey> = std::sync::OnceLock::new();
        *ONE.get_or_init(|| SecretKey::generate().unwrap().public_key())
    }

    fn handed(seed: u8, made_at: u64) -> Handed {
        let to = payee();
        let amount = Amount::from_pebbles(u64::from(seed) * 1_000).unwrap();
        let spends = NoteId::new(Hash32::from_bytes([seed; 32]), 0);
        Handed {
            transfer: Transfer::new(vec![Input::hot(spends)], vec![Note::new(amount, to)]),
            to,
            amount,
            fee: Amount::from_pebbles(7).unwrap(),
            made_at,
            refused: None,
            ended: None,
        }
    }

    /// What was written down reads back as it was, refusals and endings and
    /// all.
    ///
    /// This record is the whole of what survives the process that made a
    /// payment. A field written and not read back is a payment the next
    /// command knows only part of.
    #[test]
    fn the_record_reads_back_as_it_was_written() {
        let directory = scratch("round-trip");
        let path = directory.join(super::PENDING_FILE);
        let mut pending = Pending::default();
        pending.hand(handed(1, 10));
        pending.hand(handed(2, 11));
        pending.hand(handed(3, 12));
        assert!(pending.refused(&handed(2, 11).id(), 13, "it pays too little"));
        assert!(pending.end(&handed(3, 12).id(), 14, "its notes are gone"));
        pending.save(&path).unwrap();

        let (again, set_aside) = Pending::load(&path);
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(set_aside, None, "a record this wallet wrote was set aside");
        assert_eq!(
            again, pending,
            "the record did not read back as it was written"
        );
        assert_eq!(again.live().count(), 2);
        assert_eq!(again.ended().count(), 1);
    }

    /// Words longer than the record keeps are cut at a whole character, so
    /// the record still reads back.
    ///
    /// Cut at a byte, a sentence with a character of two bytes across the
    /// bound would be written as bytes that are not text, and the whole
    /// record, every payment in it, would be set aside at the next start.
    #[test]
    fn words_cut_short_are_cut_at_a_whole_character() {
        // Three bytes a character, so the bound falls inside one.
        let long = "\u{20ac}".repeat(super::MOST_WORDS);
        let mut bytes = Vec::new();
        super::encode_words(&long, &mut bytes);
        let back = super::decode_words(&mut cairn_primitives::codec::Reader::new(&bytes))
            .expect("words cut short did not read back");
        assert!(
            long.starts_with(&back),
            "what came back is not the start of what was said"
        );
        assert_eq!(
            back.len(),
            super::MOST_WORDS - super::MOST_WORDS % 3,
            "cut shorter than it had to be"
        );
        let mut short = Vec::new();
        super::encode_words("it pays too little", &mut short);
        assert_eq!(
            super::decode_words(&mut cairn_primitives::codec::Reader::new(&short)).unwrap(),
            "it pays too little"
        );
    }

    /// A record that is not there is no payments and nothing to set aside,
    /// and one that is there and will not open is set aside all the same.
    ///
    /// Read as the same thing, a record that could not be opened would be
    /// taken for a wallet that has handed nothing over, and written over at
    /// the next payment.
    #[test]
    fn a_record_that_is_not_there_is_nothing_and_one_that_will_not_open_is_set_aside() {
        let directory = scratch("not-there");
        let path = directory.join(super::PENDING_FILE);
        let (none, said) = Pending::load(&path);
        assert_eq!(
            (none, said),
            (Pending::default(), None),
            "nothing there was set aside"
        );

        // A directory where the record goes: there, and not a file to read.
        std::fs::create_dir(&path).unwrap();
        let (none, said) = Pending::load(&path);
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(none, Pending::default());
        assert_eq!(
            said,
            Some(NotReadBack::Moved(directory.join("pending.dat.unread"))),
            "a record that would not open was taken for no record at all"
        );
    }

    /// The record is written for its owner alone, and through nothing that
    /// stands at its partial file's name.
    ///
    /// A partial file left at a wider mode by a write that stopped would have
    /// carried that mode onto the record, and a symbolic link planted at the
    /// name would have chosen where the record went and emptied that file.
    #[cfg(unix)]
    #[test]
    fn the_record_is_written_for_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = scratch("mode");
        let path = directory.join(super::PENDING_FILE);
        // A partial record left by a write that stopped, at a wider mode: the
        // rename would carry that mode onto the record itself.
        let partial = path.with_extension("part");
        std::fs::write(&partial, b"left over").unwrap();
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut pending = Pending::default();
        pending.hand(handed(1, 10));
        pending.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;

        let elsewhere = directory.join("elsewhere");
        std::fs::write(&elsewhere, b"not the record").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &partial).unwrap();
        pending.save(&path).unwrap();
        let untouched = std::fs::read(&elsewhere).unwrap();
        let (again, _) = Pending::load(&path);
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(
            mode, 0o600,
            "the record of who this key paid is readable by others"
        );
        assert_eq!(
            untouched, b"not the record",
            "a link planted at the partial file's name took the record"
        );
        assert_eq!(
            again, pending,
            "the record written past the link did not read back"
        );
    }

    /// A record that does not read back is moved out of the way under a name
    /// of its own, and never written over.
    ///
    /// It holds payments this wallet may still be waiting on. Read as empty
    /// and written over at the next payment, those would be forgotten for
    /// good, which is the defect the record exists to end.
    #[test]
    fn a_record_that_does_not_read_back_is_set_aside_and_not_written_over() {
        let directory = scratch("set-aside");
        let path = directory.join(super::PENDING_FILE);
        let mut pending = Pending::default();
        pending.hand(handed(1, 10));
        pending.save(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x40;
        std::fs::write(&path, &bytes).unwrap();

        let (again, set_aside) = Pending::load(&path);
        let moved_to = directory.join("pending.dat.unread");
        let kept = std::fs::read(&moved_to).ok();
        let still_there = path.exists();
        let (_, second) = {
            std::fs::write(&path, &bytes).unwrap();
            Pending::load(&path)
        };
        let _ = std::fs::remove_dir_all(&directory);

        assert_eq!(
            again,
            Pending::default(),
            "a changed record was read as payments"
        );
        assert_eq!(set_aside, Some(NotReadBack::Moved(moved_to)));
        assert_eq!(
            kept,
            Some(bytes),
            "what was set aside is not the record as it was"
        );
        assert!(
            !still_there,
            "the record was left where the next save writes over it"
        );
        assert_eq!(
            second,
            Some(NotReadBack::Moved(directory.join("pending.dat.unread-1"))),
            "a second record set aside took the name of the first and wrote over it"
        );
    }

    /// A payment its node will not take back is held for a few blocks from the
    /// first refusal and then let go of, and named for a day after that.
    ///
    /// Nothing let a payment go, so its notes would have been held for ever;
    /// and nothing named one that had been let go of, so it would have
    /// vanished with its balance going back up, which is what a payment a
    /// block carried looks like too.
    #[test]
    fn a_refused_payment_is_held_for_a_while_then_named_for_a_while() {
        let mut pending = Pending::default();
        let one = handed(1, 10);
        let id = one.id();
        pending.hand(one);

        assert!(pending.refused(&id, 20, "it pays too little"));
        assert!(
            !pending.refused(&id, 22, "it pays too little"),
            "the same refusal said again is not a change"
        );
        let held = pending.live().next().unwrap().held_until();
        assert_eq!(
            held,
            Some(20 + HELD_AFTER_REFUSAL),
            "the wait is counted from the first refusal, not the last"
        );

        assert!(!pending.age(20 + HELD_AFTER_REFUSAL - 1));
        assert_eq!(pending.live().count(), 1, "let go of a block early");
        assert!(pending.age(20 + HELD_AFTER_REFUSAL));
        assert_eq!(pending.live().count(), 0, "held past the wait");
        let ended = pending.ended().next().unwrap().ended.clone();
        assert_eq!(
            ended,
            Some((20 + HELD_AFTER_REFUSAL, "it pays too little".to_owned())),
            "let go of without the reason it was refused for"
        );

        let over = 20 + HELD_AFTER_REFUSAL;
        assert!(!pending.age(over + NAMED_FOR - 1));
        assert_eq!(
            pending.ended().count(),
            1,
            "stopped naming it a block early"
        );
        assert!(pending.age(over + NAMED_FOR));
        assert_eq!(
            pending.ended().count(),
            0,
            "named past the day it is named for"
        );

        let mut taken = Pending::default();
        let two = handed(2, 10);
        taken.hand(two.clone());
        assert!(taken.refused(&two.id(), 20, "no"));
        assert!(taken.taken_back(&two.id()), "taken back is a change");
        assert!(!taken.taken_back(&two.id()), "and taken back twice is not");
        assert!(
            taken.refused(&two.id(), 30, "no"),
            "refused again after being taken back is a change"
        );
        assert_eq!(
            taken.live().next().unwrap().held_until(),
            Some(30 + HELD_AFTER_REFUSAL),
            "a refusal after being taken back starts the wait again"
        );
        assert!(
            !taken.age(20 + HELD_AFTER_REFUSAL),
            "and the old wait is gone"
        );
    }

    /// Settling takes one payment off the record, ending one names it, and
    /// neither touches another.
    #[test]
    fn settling_and_ending_touch_the_one_payment_named() {
        let mut pending = Pending::default();
        let (one, two) = (handed(1, 10), handed(2, 10));
        pending.hand(one.clone());
        pending.hand(two.clone());
        pending.hand(one.clone());
        assert_eq!(
            pending.live().count(),
            2,
            "a payment written down twice is there twice"
        );

        assert!(pending.end(&one.id(), 12, "gone"));
        assert!(!pending.end(&one.id(), 13, "gone again"), "ended twice");
        assert_eq!(
            pending.ended().next().unwrap().ended,
            Some((12, "gone".to_owned()))
        );
        assert!(
            !pending.refused(&handed(3, 1).id(), 12, "no"),
            "refused a stranger"
        );
        assert!(
            !pending.end(&handed(3, 1).id(), 12, "no"),
            "ended a stranger"
        );

        assert!(pending.settle(&two.id()));
        assert!(!pending.settle(&two.id()), "settled twice");
        assert_eq!(pending.live().count(), 0);
        assert_eq!(pending.ended().count(), 1, "settling one took the other");
    }

    /// Past the most it keeps, the record lets go of the oldest payment it has
    /// stopped waiting on before any it is still waiting on.
    #[test]
    fn a_full_record_lets_go_of_what_it_is_not_waiting_on_first() {
        let mut pending = Pending::default();
        let first = handed(1, 0);
        pending.hand(first.clone());
        let ended = handed(2, 0);
        pending.hand(ended.clone());
        assert!(pending.end(&ended.id(), 1, "gone"));
        for seed in 0..MOST_KEPT {
            let mut one = handed(3, 0);
            one.made_at = u64::try_from(seed).unwrap();
            one.transfer.outputs[0] = Note::new(
                Amount::from_pebbles(u64::try_from(seed).unwrap() + 1).unwrap(),
                one.to,
            );
            pending.hand(one);
            assert!(
                pending.handed.len() <= MOST_KEPT,
                "the record grew past its bound"
            );
        }
        assert_eq!(pending.handed.len(), MOST_KEPT);
        assert_eq!(
            pending.ended().count(),
            0,
            "a payment it had stopped waiting on outlived one it is waiting on"
        );
        assert!(
            pending.live().all(|one| one.id() != first.id()),
            "once nothing it had stopped waiting on was left, the oldest waiting went first"
        );
    }
}

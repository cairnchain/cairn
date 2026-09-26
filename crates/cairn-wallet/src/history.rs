//! What happened to this key, in the order it happened.
//!
//! The chain says what a key owns now. It does not say what it received in
//! March, and nothing in the protocol should: a history is one person's
//! account of their own money, useful to them and to nobody else, and putting
//! it in the ledger would be asking every node in the world to carry it.
//!
//! So the wallet keeps its own, by watching the blocks it validates go past.
//! It is not consensus, and the money does not depend on it: lose the file and
//! the money is exactly where it was. Finding it does. A note that has fallen
//! out of the set every node holds is spent with its place in the cold set,
//! that set carries no owner, and the place is written down here and nowhere
//! else. Reading the chain again rebuilds this account only as far back as the
//! blocks the node still holds, so this file is half of a wallet's backup, and
//! the key file is the other half.
//!
//! What it can say is bounded by what the wallet kept. A wallet that dropped
//! old blocks, or that was handed a ledger rather than reading its way to one,
//! has no way to know what happened before that, and says so rather than
//! showing a history that starts nowhere in particular.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use cairn_crypto::PublicKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::NoteId;
use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::{hash, Domain, HASH_LEN};
use cairn_primitives::{Amount, Hash32};

/// Movements kept. Past this the oldest are dropped, so a wallet running for
/// years does not turn its history into the cost it exists to avoid.
const MAX_MOVEMENTS: usize = 4096;

/// Undone movements kept. A reorganisation deep enough to undo more than this
/// is not something anybody has seen, and the record is worth having a bound
/// on all the same.
const MAX_UNDONE: usize = 256;

/// Which way money went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Paid to this key by somebody else.
    Received,
    /// Paid to this key by a block it mined.
    Mined,
    /// Paid by this key to somebody else.
    Sent,
}

impl Direction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Mined => "mined",
            Self::Sent => "sent",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Received => 0,
            Self::Mined => 1,
            Self::Sent => 2,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Received),
            1 => Some(Self::Mined),
            2 => Some(Self::Sent),
            _ => None,
        }
    }
}

/// One thing that happened to this key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Movement {
    pub height: u64,
    /// The block's own timestamp, which is what a chain has instead of a
    /// clock. Not the moment the wallet saw it.
    pub at: u64,
    pub direction: Direction,
    /// What this key gained or gave up, change already accounted for. A spend
    /// of 60 out of a note of 50 and a note of 20 shows as 60 and not as 70.
    pub amount: Amount,
    /// The transaction it happened in.
    pub id: Hash32,
}

impl Encode for Movement {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.height.encode_to(out);
        self.at.encode_to(out);
        self.direction.tag().encode_to(out);
        self.amount.encode_to(out);
        self.id.encode_to(out);
    }
}

impl Decode for Movement {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let height = u64::decode_from(reader)?;
        let at = u64::decode_from(reader)?;
        let direction =
            Direction::from_tag(u8::decode_from(reader)?).ok_or(CodecError::InvalidValue {
                type_name: "Direction",
            })?;
        Ok(Self {
            height,
            at,
            direction,
            amount: Amount::decode_from(reader)?,
            id: Hash32::decode_from(reader)?,
        })
    }
}

/// A note this key holds, for writing the history down.
///
/// A pair would do everywhere except on the wire, where a type of this
/// repository's own is what the codec knows how to carry.
#[derive(Clone, Copy, Debug)]
struct Owned {
    id: NoteId,
    value: Amount,
}

impl Encode for Owned {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.id.encode_to(out);
        self.value.encode_to(out);
    }
}

impl Decode for Owned {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            id: NoteId::decode_from(reader)?,
            value: Amount::decode_from(reader)?,
        })
    }
}

/// Where one of this key's notes landed when it fell, for writing down.
///
/// A pair would do everywhere except on the wire, like [`Owned`] above.
#[derive(Clone, Copy, Debug)]
struct Fell {
    id: NoteId,
    position: u64,
}

impl Encode for Fell {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.id.encode_to(out);
        self.position.encode_to(out);
    }
}

impl Decode for Fell {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            id: NoteId::decode_from(reader)?,
            position: u64::decode_from(reader)?,
        })
    }
}

/// The height of the block that paid one of this key's notes, for writing
/// down. A pair would do everywhere except on the wire, like the two above.
#[derive(Clone, Copy, Debug)]
struct PaidAt {
    id: NoteId,
    height: u64,
}

impl Encode for PaidAt {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.id.encode_to(out);
        self.height.encode_to(out);
    }
}

impl Decode for PaidAt {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            id: NoteId::decode_from(reader)?,
            height: u64::decode_from(reader)?,
        })
    }
}

/// This key's own account of its money.
#[derive(Clone, Debug, Default)]
pub struct History {
    /// Notes this key holds, so a spend can be told from a stranger's.
    ///
    /// Kept because an input names a note and not its owner: without knowing
    /// which notes are ours, a transfer spending one of them is
    /// indistinguishable from a transfer between two other people.
    held: BTreeMap<NoteId, Amount>,
    /// Where each of those notes landed when it fell out of the set every node
    /// keeps, for the ones that have.
    ///
    /// Written down while the node can still say, because the node will not
    /// always be able to. A place is fixed for as long as the block the note
    /// fell in stands; what moves is the path up to it, which changes every
    /// time another note falls and is nobody's to keep for ever. So the wallet
    /// keeps the half that lasts, and the half that does not can be asked for
    /// by anyone holding this.
    ///
    /// Without it there is nothing to ask about. A wallet that knows only that
    /// it owns a note knows the one thing an archivist cannot look up: the set
    /// is a list of hashes with no name attached, so a note has to be found by
    /// where it sits.
    fell: BTreeMap<NoteId, u64>,
    /// The height of the block that paid each of those notes, for the ones
    /// this account read the block for.
    ///
    /// What it is for is [`History::forget`]. Starting again is the whole
    /// answer to a reorganisation, and it has to throw away the map of which
    /// notes are this key's, because that map was built up as blocks went
    /// past and there is nothing to invert it with. What it must not throw
    /// away with it is a place, which is the one thing in this file the chain
    /// cannot give back: a place comes from the node's watch list, and a node
    /// restarted from a written ledger comes back without one.
    ///
    /// A note paid by a block deeper than any reorganisation this node will
    /// follow is a note no reorganisation can take away, so its place is kept.
    /// A note with no height here was never read in any block by this account:
    /// it came out of the window a handover carried, which sits below the
    /// anchor, so it is settled for the same reason.
    paid_at: BTreeMap<NoteId, u64>,
    /// The height below which this account's list of movements may be missing
    /// entries, because it was moved past blocks it could not read.
    ///
    /// `from` cannot carry this. It says the first height the account can
    /// answer for, and the note on it names exactly this failure: blocks that
    /// are not in the list "read as a stretch in which nothing happened to
    /// this key, which for a miner is plausible and false". That was answered
    /// where movements are dropped for age and nowhere else, so an account
    /// moved past a block kept the `from` it already had and went on saying it
    /// covered everything from there.
    ///
    /// Moving `from` forward instead would be the same lie the other way
    /// round: the blocks below the gap were read, and their movements are in
    /// the list. A gap is a third thing and needs a third number.
    ///
    /// The highest one, when there have been several. Everything below it may
    /// be short, which is the only claim one number can carry and is the
    /// conservative half of it.
    missed_below: Option<u64>,
    /// Notes this account held when it had to move past a block it could not
    /// read, and has therefore stopped answering for.
    ///
    /// A note leaves `held` when this account reads the block that spent it.
    /// When the node has let go of a block this account still needed, that
    /// reading never happens: the account moves to where the log now begins,
    /// and everything that became of this key in between is not in it. A note
    /// spent in that range stays in `held` for the life of the file, and what
    /// reads `held` reads it as what this key holds now.
    ///
    /// The account cannot work out which. A note that was spent and a note
    /// that fell out of the hot set are both simply gone from what the node
    /// can show, and the hot set is capped by size rather than by age, so
    /// there is no height at which either was due. What it can do is know
    /// that it does not know, which is what this is.
    ///
    /// Marked here a whole account at a time, because a gap is a fact about a
    /// range and not about a note. What is done with the mark is narrower, and
    /// `Wallet::reckon` decides it: a note this account watched fall has a
    /// place written down, and a place is evidence and is the only handle by
    /// which anyone could be asked about it, so that one is still counted. It
    /// is the notes with nothing to point at that stop being called this key's
    /// money.
    ///
    /// An entry leaves when the question is settled: the node still holds the
    /// note, or a block spends it, or the file is started over.
    unaccounted: BTreeSet<NoteId>,
    /// Newest last.
    movements: Vec<Movement>,
    /// What the account said before the chain changed under it, less whatever
    /// reading the chain again put back.
    ///
    /// Kept because forgetting is not the same as nothing having happened. A
    /// wallet that paid somebody, watched a block carry it, and then found
    /// itself on a branch where it never happened has to be able to say so:
    /// the money is back, and the person holding the wallet is the only one
    /// who can decide what that means for whoever was being paid. Emptying
    /// the history and saying nothing leaves them with neither the payment
    /// nor its undoing.
    ///
    /// Newest last, like the movements it was made from. An entry leaves as
    /// soon as a block is read that carries the same transaction, because
    /// then it was not undone after all, only moved.
    undone: Vec<Movement>,
    /// The next height to read.
    next: u64,
    /// The first height this history could see, so it never claims to cover
    /// what it never read.
    from: Option<u64>,
    /// The identifier of the newest block read.
    ///
    /// Kept so a branch that was undone can be noticed. A reorganisation
    /// replaces every block above the fork, so this one is enough to detect
    /// one: if it is still where it was, nothing below it moved either.
    last: Option<Hash32>,
}

/// Why a history file that was there was not used.
///
/// Whatever the reason, the wallet reads the chain again rather than trusting
/// it, and the file is moved aside rather than written over. The money is on
/// the chain either way. What the wallet loses until the file is back is the
/// list of movements below the height it restarts its reading at, and the
/// place of every note that fell out of the set every node holds before
/// then, which is money it cannot find without that place. That is worth a
/// line on the face rather than nothing at all: a wallet that quietly forgot
/// what it had shown yesterday is a wallet nobody can tell apart from one
/// that is wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discarded {
    /// Written by a release from before the stamp existed.
    ///
    /// Expected exactly once per wallet, and nobody's fault.
    BeforeTheStamp,
    /// Present, the right shape, and not the bytes that were written.
    DidNotVerify,
    /// Written by a wallet that knows more than this one.
    ///
    /// The stamp holds, so nothing changed the file. It carries fields this
    /// build has no reader for, which is what a downgrade looks like from
    /// here, and telling somebody their disk is suspect over it would send
    /// them looking at hardware that is fine.
    FromANewerVersion,
    /// There and would not open.
    ///
    /// The one case that is not about the bytes, because nothing here got to
    /// read any. A permission a restore left wrong, a disk that will not
    /// answer, a name taken by a directory. Said rather than passed over,
    /// since whatever it holds is worth having once the cause is mended.
    WouldNotOpen,
}

impl History {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Movements, newest first.
    pub fn movements(&self) -> impl Iterator<Item = &Movement> {
        self.movements.iter().rev()
    }

    /// What the chain took back and has not given again, newest first.
    pub fn undone(&self) -> impl Iterator<Item = &Movement> {
        self.undone.iter().rev()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.movements.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.movements.is_empty()
    }

    /// The next height this history has not read.
    #[must_use]
    pub const fn next(&self) -> u64 {
        self.next
    }

    /// The first height this account can still answer for, or `None` if it
    /// has seen nothing.
    ///
    /// Not simply the first height it read, which is what it used to answer.
    /// The two part company the moment the list is full: `record` drops the
    /// oldest movements past [`MAX_MOVEMENTS`] and used to leave the reading
    /// point where it was, so an account that had read four thousand two
    /// hundred blocks and kept the last four thousand and ninety six still
    /// said it reached block zero. A face prints this under the list as "as
    /// far back as block {from}: this wallet did not read what came before",
    /// so the blocks it dropped read as a stretch in which nothing happened to
    /// this key, which for a miner is plausible and false.
    ///
    /// Moved forward where the dropping happens rather than worked out here,
    /// because the oldest movement held is not the answer either: a wallet
    /// that read from block zero and was first paid at five hundred did read
    /// those five hundred blocks and found nothing in them, and saying it
    /// reached only five hundred would be the same lie the other way round.
    #[must_use]
    pub const fn from(&self) -> Option<u64> {
        self.from
    }

    /// Reads one block, in order, and records what it did to this key.
    ///
    /// Blocks have to arrive in order and without gaps, because which notes
    /// are ours is built up as they go past: a block read out of turn would
    /// spend notes this has not seen created and record a stranger's transfer
    /// as ours, or miss ours entirely.
    pub fn take(&mut self, block: &Block, mine: PublicKey) {
        if block.header.height != self.next {
            return;
        }
        self.next = self.next.saturating_add(1);
        self.last = Some(block.id());
        if self.from.is_none() {
            self.from = Some(block.header.height);
        }
        let at = block.header.timestamp;
        let height = block.header.height;

        // What a block paid its miner. Ours only if it names this key.
        let mined = block
            .coinbase
            .created_notes()
            .into_iter()
            .filter(|(_, note)| note.owner == mine)
            .fold(Amount::ZERO, |sum, (id, note)| {
                self.held.insert(id, note.value);
                self.paid_at.insert(id, height);
                sum.checked_add(note.value).unwrap_or(sum)
            });
        if mined > Amount::ZERO {
            self.record(Movement {
                height,
                at,
                direction: Direction::Mined,
                amount: mined,
                id: block.coinbase.id(),
            });
        }

        for transfer in &block.transfers {
            self.take_transfer(transfer, mine, height, at);
        }
    }

    fn take_transfer(
        &mut self,
        transfer: &cairn_ledger::transaction::Transfer,
        mine: PublicKey,
        height: u64,
        at: u64,
    ) {
        // What this key gave up: the notes of ours this transfer spent.
        let mut gave = Amount::ZERO;
        for input in &transfer.inputs {
            if let Some(value) = self.held.remove(&input.note_id) {
                self.fell.remove(&input.note_id);
                self.paid_at.remove(&input.note_id);
                self.unaccounted.remove(&input.note_id);
                gave = gave.checked_add(value).unwrap_or(gave);
            }
        }

        // What came back to it: outputs naming this key, which for a spend of
        // our own is the change.
        let mut got = Amount::ZERO;
        for (id, note) in transfer.created_notes() {
            if note.owner == mine {
                self.held.insert(id, note.value);
                self.paid_at.insert(id, height);
                got = got.checked_add(note.value).unwrap_or(got);
            }
        }

        if gave == Amount::ZERO && got == Amount::ZERO {
            return;
        }
        let id = transfer.id();
        // Net, so a spend shows what left rather than what was gathered. The
        // fee is part of what left: it is what was not paid to anyone here.
        if gave >= got {
            let amount = gave.checked_sub(got).unwrap_or(Amount::ZERO);
            if amount > Amount::ZERO {
                self.record(Movement {
                    height,
                    at,
                    direction: Direction::Sent,
                    amount,
                    id,
                });
            }
        } else {
            let amount = got.checked_sub(gave).unwrap_or(Amount::ZERO);
            self.record(Movement {
                height,
                at,
                direction: Direction::Received,
                amount,
                id,
            });
        }
    }

    /// Notes this key has been paid and has not spent, as this wallet's own
    /// record rather than the node's.
    ///
    /// The two can differ, and the difference is the point. A node follows the
    /// proof for a fallen note only while it has room, and past that ceiling
    /// it stops following the least valuable ones. Without a record of its
    /// own a wallet would simply stop seeing those notes, and money that
    /// quietly leaves a balance is the worst way to be told anything.
    pub fn held(&self) -> impl Iterator<Item = (NoteId, Amount)> + '_ {
        self.held.iter().map(|(id, value)| (*id, *value))
    }

    /// The height below which the list of movements may be missing entries.
    #[must_use]
    pub(crate) const fn missed_below(&self) -> Option<u64> {
        self.missed_below
    }

    /// Notes this account holds in name only, because it was moved past the
    /// blocks that would have said what became of them.
    pub fn unaccounted(&self) -> impl Iterator<Item = NoteId> + '_ {
        self.unaccounted.iter().copied()
    }

    /// Says the node still holds this note, which settles it.
    pub(crate) fn accounted_for(&mut self, id: &NoteId) -> bool {
        self.unaccounted.remove(id)
    }

    /// Writes down where a note landed, saying whether that was news.
    ///
    /// A note this account had not read the block for is taken up rather than
    /// refused, which it used to be. The reasoning for refusing was that a
    /// place written down for a note that was never this key's would be a
    /// claim about somebody else's money kept in this key's file, and the
    /// claim is not this file's to make either way: what calls this is the
    /// wallet reading its own node's ledger, filtered to notes naming this
    /// key, and that ledger is the same validated state the balance is read
    /// out of.
    ///
    /// What refusing cost was money. A wallet handed a ledger starts reading
    /// at the anchor, so the notes that fell in the sixty four blocks before
    /// it were never in any block this account saw. Its node knows them, from
    /// the window the handover carried, and stops knowing them the moment it
    /// starts again from a ledger of its own. With nothing written down here,
    /// the node was the only record, and on that restart the money left the
    /// balance without a word: not stranded, which is a thing a wallet can say
    /// and ask about, but gone.
    ///
    /// The newest answer stands. It used to be the first, on the reasoning
    /// that a place is fixed when the note falls and never moves, so a later
    /// answer could only be a second opinion about a settled fact. Fixed for
    /// as long as the block the note fell in stands, and no longer: a note
    /// falls when the hot set runs out of room, which can be long after the
    /// block that paid it, so a note paid below the reach of any
    /// reorganisation can still fall inside it, and [`History::forget`] keeps
    /// that note's place. The branch that wins can put it somewhere else. The
    /// account kept the losing branch's place while its own node named the
    /// right one, and once the node restarted and forgot, it asked archivists
    /// about somebody else's leaf and the money stayed stranded.
    ///
    /// What calls this is the wallet reading its own node's ledger, which is
    /// the chain as that node has checked it now, so a later answer is never
    /// a weaker one. `Wallet::reckon` already takes the node's word over the
    /// file's for the same reason.
    pub fn fell_at(&mut self, id: NoteId, value: Amount, position: u64) -> bool {
        self.held.entry(id).or_insert(value);
        self.fell.insert(id, position) != Some(position)
    }

    /// Where a note landed, if this account saw it land.
    #[must_use]
    pub fn where_it_fell(&self, id: &NoteId) -> Option<u64> {
        self.fell.get(id).copied()
    }

    fn record(&mut self, movement: Movement) {
        // A block carries it, so whatever branch it was read on before, it is
        // on this one now and was never undone.
        self.undone.retain(|held| held.id != movement.id);
        self.movements.push(movement);
        if self.movements.len() > MAX_MOVEMENTS {
            let over = self.movements.len().saturating_sub(MAX_MOVEMENTS);
            self.movements.drain(..over);
            // What was dropped is what this account can no longer answer for,
            // so how far back it reaches moves with it. Leaving the reading
            // point where it was is how a list that reached block 104 went on
            // saying it reached block 0.
            if let Some(oldest) = self.movements.first().map(|held| held.height) {
                self.from = Some(self.from.map_or(oldest, |began| began.max(oldest)));
            }
        }
    }

    /// Moves the reading point forward, for a wallet that cannot see what
    /// came before.
    ///
    /// A wallet handed a ledger, or one that dropped old blocks, has no way to
    /// read them and no way to guess. The history then begins where the wallet
    /// does, which it says rather than implying it covers everything.
    pub(crate) fn skip_to(&mut self, height: u64) {
        if height <= self.next {
            return;
        }
        // Everything this account holds now was held as of a block it will
        // never read, so from here it answers for none of it. Added to rather
        // than replaced: an account can be moved past a second gap before the
        // first one is settled.
        self.unaccounted.extend(self.held.keys().copied());
        // And the list below here may be short by whatever happened to this
        // key in the blocks being stepped over.
        self.missed_below = Some(
            self.missed_below
                .map_or(height, |already| already.max(height)),
        );
        self.next = height;
        // Nothing read is adjacent to what comes next, so there is no block to
        // compare against any more.
        self.last = None;
        if self.from.is_none() {
            self.from = Some(height);
        }
    }

    /// Whether the chain no longer holds the block this last read.
    ///
    /// `tip` is how far the chain reaches now and `chain` answers what block
    /// sits at a height. A reorganisation replaces every block above the fork
    /// it happened at, so asking about the newest one read is enough to
    /// notice: if that block is still there, no block below it moved.
    ///
    /// A height the wallet can no longer read is not a divergence. A node that
    /// dropped an old block has not changed its mind about it. A chain that no
    /// longer reaches that height is a different matter, and it is why the tip
    /// is asked for as well as the block: work decides which branch wins, not
    /// length, so the branch that won can end below the one it replaced. Read
    /// from the block alone that case answers "nothing there", which is
    /// indistinguishable from a block dropped for age and is the opposite of
    /// the truth.
    pub fn diverged(&self, tip: Option<u64>, chain: impl Fn(u64) -> Option<Hash32>) -> bool {
        let (Some(last), Some(newest)) = (self.last, self.next.checked_sub(1)) else {
            return false;
        };
        if matches!(tip, Some(reaches) if reaches < newest) {
            return true;
        }
        matches!(chain(newest), Some(now) if now != last)
    }

    /// Starts again from nothing, keeping what the branch that lost said.
    ///
    /// Starting again is the whole answer to a reorganisation, and dropping
    /// the movements above the fork is not. Which notes are this key's is
    /// built up as blocks go past, so a history that kept that map while
    /// forgetting some of the blocks that filled it would go on calling a
    /// stranger's transfer ours. There is nothing to invert it with, and
    /// reading the chain again is what the file exists to be cheaper than, not
    /// a thing that cannot be done.
    ///
    /// What is not thrown away is the account itself. It is set aside as
    /// undone, and every movement the chain still carries is taken back out of
    /// it as the blocks are read again, so what is left at the end is exactly
    /// what the chain took away.
    pub fn forget(&mut self, settled_below: Option<u64>) {
        let mut undone = std::mem::take(&mut self.undone);
        undone.append(&mut self.movements);
        let over = undone.len().saturating_sub(MAX_UNDONE);
        undone.drain(..over);

        // Everything above is thrown away for the reason the note above says.
        // What is kept is narrower than the account and wider than nothing: a
        // note that has fallen, whose place this file is the only record of,
        // and that was paid by a block no reorganisation this node will follow
        // can reach. Reading the chain again gives back everything else; it
        // cannot give back a place, because a place comes from a watch list a
        // node restarted from its own ledger no longer has.
        //
        // A note with no height was never read in any block by this account.
        // It came out of the window a handover carried, which sits below the
        // anchor, and is settled for the same reason.
        let settled = |id: &NoteId| match self.paid_at.get(id) {
            None => true,
            Some(paid_at) => matches!(settled_below, Some(line) if *paid_at < line),
        };
        let fell: BTreeMap<NoteId, u64> = std::mem::take(&mut self.fell)
            .into_iter()
            .filter(|(id, _)| settled(id))
            .collect();
        let held: BTreeMap<NoteId, Amount> = std::mem::take(&mut self.held)
            .into_iter()
            .filter(|(id, _)| fell.contains_key(id))
            .collect();
        let paid_at: BTreeMap<NoteId, u64> = std::mem::take(&mut self.paid_at)
            .into_iter()
            .filter(|(id, _)| fell.contains_key(id))
            .collect();

        *self = Self {
            held,
            fell,
            paid_at,
            undone,
            ..Self::default()
        };
    }

    /// Reads it back from `path`, or starts empty when there is nothing to
    /// read.
    ///
    /// A file that cannot be understood is not an error worth stopping for,
    /// and it is not one to write over either. This only reads: it says why
    /// a file was not used, and a caller that is going to save moves that
    /// file out of the way first, with [`History::set_aside`].
    #[must_use]
    pub fn load(path: &Path) -> (Self, Option<Discarded>) {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            // A file that is not there is a wallet that has never run, or one
            // restored from its key alone, and there is nothing in it to keep.
            // A file that is there and will not open is the opposite case,
            // and it took the same exit: empty account, nothing reported, and
            // the next save wrote over it, because a rename needs the
            // directory and not the file. Every variant below is worked out
            // from bytes, so they were only ever reached when there were
            // bytes, and this is the case where "worth looking into" is most
            // likely to be the right thing to say.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (Self::default(), None)
            }
            Err(_) => return (Self::default(), Some(Discarded::WouldNotOpen)),
        };
        if let Some(history) = Self::verified(&bytes) {
            return (history, None);
        }
        // Three ways a file can fail to be read back, and they are three
        // different pieces of news. Guessing wrong sends somebody looking at a
        // disk that is fine, or shrugging at one that is not.
        //
        // A file that is exactly a body, with nothing where the stamp goes, is
        // what the release before the stamp wrote: it happens once, to
        // everybody, on the day they update.
        //
        // A file whose stamp is over bytes this build cannot decode was
        // written by a wallet that knows more fields than this one. The stamp
        // holding is the whole of the evidence: nothing changed the file, it
        // is simply newer, which is what a downgrade looks like from here.
        //
        // Anything else is a file that was there and is not what was written.
        let why = if Self::decode(&bytes).is_ok() {
            Discarded::BeforeTheStamp
        } else if Self::stamped(&bytes) {
            Discarded::FromANewerVersion
        } else {
            Discarded::DidNotVerify
        };
        (Self::default(), Some(why))
    }

    /// The account in `bytes`, if the bytes are the ones that were written.
    ///
    /// A history that is short refuses to decode and costs a wallet a reread
    /// of the chain, which is the ordinary torn write and is handled. A
    /// history whose bytes changed without changing its length is a different
    /// thing: every field here is a fixed-width number or a hash, so almost
    /// any bytes decode into a plausible account. `Wallet::reckon` reads the
    /// notes out of this file and reports any the node does not know about as
    /// money whose proof cannot be produced, which is a real category, so a
    /// fabricated note is indistinguishable from a stranded one and the
    /// wallet shows money that does not exist.
    ///
    /// The stamp is not a defence against anybody: a file this wallet writes
    /// is a file whoever holds the machine can rewrite, stamp and all. It is
    /// a defence against a disk that changed under it, which is the failure
    /// this file actually meets, and it costs one hash of a few kilobytes at
    /// each start.
    /// Whether the last thirty two bytes are this build's stamp over the rest.
    ///
    /// Separate from decoding on purpose: a stamp that holds over bytes that
    /// will not decode says the file is whole and this build is behind it.
    fn stamped(bytes: &[u8]) -> bool {
        let Some(split) = bytes.len().checked_sub(HASH_LEN) else {
            return false;
        };
        let Some((body, stamp)) = bytes.split_at_checked(split) else {
            return false;
        };
        hash(Domain::WalletHistory, body).as_bytes() == stamp
    }

    fn verified(bytes: &[u8]) -> Option<Self> {
        let (body, stamp) = bytes.split_at_checked(bytes.len().checked_sub(HASH_LEN)?)?;
        if hash(Domain::WalletHistory, body).as_bytes() != stamp {
            return None;
        }
        Self::decode(body).ok()
    }

    /// Writes it beside itself and moves it into place, so a wallet stopped
    /// partway keeps the history it had rather than half of a new one.
    ///
    /// Synced before the move and the directory synced after it, because a
    /// rename covers a process that stops and not a machine that stops: a
    /// write returns when the bytes are in the page cache, so without this
    /// the file can come back present and short.
    ///
    /// The partial file is made new, private from the call that creates it,
    /// with whatever stood at its name taken away first; `keyfile::create_anew`
    /// says why. The key file has a paragraph on why it is `0600`, and this
    /// file needs the same one for a different reason: it holds no key, and it
    /// holds everything else, every note this key was paid, what each is
    /// worth, which of them are still held, and where each of the fallen ones
    /// sits. A save that fails takes its partial file away with it, so what is
    /// left is the account as it was and nothing beside it.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let partial = path.with_extension("part");
        let mut bytes = self.encode();
        bytes.extend_from_slice(hash(Domain::WalletHistory, &bytes).as_bytes());
        let moved = write_and_move(&partial, path, &bytes);
        if moved.is_err() {
            let _ = std::fs::remove_file(&partial);
        }
        moved?;
        // Best effort, where the key file's own directory sync is required. A
        // rename the machine loses leaves the account as an earlier save left
        // it, and the next start carries it forward by reading the blocks
        // since, which are the newest the node holds. A key file whose name is
        // lost is money nobody can reach; this is a few blocks read twice, and
        // saying so would be the line that tells a person this wallet cannot
        // keep its account, when it can.
        if let Some(directory) = path.parent() {
            if let Ok(handle) = std::fs::File::open(directory) {
                let _ = handle.sync_all();
            }
        }
        Ok(())
    }

    /// Moves a file that was not read back out of the way of the next save,
    /// to a name nothing writes to, and says where it went.
    ///
    /// A save renames a new account over `path`, and for a file that was not
    /// read that destroyed the only record of where this key's fallen notes
    /// sit: from a newer version the wallet had just called whole, from a disk
    /// it had just called worth looking into. So it is never written over.
    /// The name is `path` with `.unread-` and the first number nothing stands
    /// at, not even a link, so one set aside before keeps its own. Nothing
    /// else writes to the directory while its node holds the lock on it, so a
    /// name found free is still free when the rename lands; a name that cannot
    /// even be looked at is one the rename cannot reach either, and it fails
    /// there. The directory is synced after, because a move the machine loses
    /// puts the file back where the next save goes.
    pub fn set_aside(path: &Path) -> std::io::Result<PathBuf> {
        let name = path.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a file name")
        })?;
        for count in 1..=SET_ASIDE_NAMES {
            let mut aside = name.to_os_string();
            aside.push(format!(".unread-{count}"));
            let aside = path.with_file_name(aside);
            if std::fs::symlink_metadata(&aside).is_err() {
                std::fs::rename(path, &aside)?;
                crate::keyfile::sync_the_directory(&aside)?;
                return Ok(aside);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "every name an unread account is set aside under is taken",
        ))
    }
}

/// Names tried for an account set aside before giving up.
///
/// One is used each time a file does not read back, which is once per
/// upgrade across the stamp, once per downgrade, or once per disk fault. A
/// directory holding this many has something wrong with it that another name
/// would not help.
const SET_ASIDE_NAMES: u32 = 1000;

/// Writes `bytes` to `partial`, made new, and moves it onto `path`.
fn write_and_move(partial: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    {
        let mut file = crate::keyfile::create_anew(partial)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(partial, path)
}

impl Encode for History {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.next.encode_to(out);
        self.from.unwrap_or(u64::MAX).encode_to(out);
        self.movements.encode_to(out);
        self.last.unwrap_or(Hash32::ZERO).encode_to(out);
        let held: Vec<Owned> = self
            .held
            .iter()
            .map(|(id, value)| Owned {
                id: *id,
                value: *value,
            })
            .collect();
        held.encode_to(out);
        self.undone.encode_to(out);
        let fell: Vec<Fell> = self
            .fell
            .iter()
            .map(|(id, position)| Fell {
                id: *id,
                position: *position,
            })
            .collect();
        fell.encode_to(out);
        let paid_at: Vec<PaidAt> = self
            .paid_at
            .iter()
            .map(|(id, height)| PaidAt {
                id: *id,
                height: *height,
            })
            .collect();
        paid_at.encode_to(out);
        let unaccounted: Vec<NoteId> = self.unaccounted.iter().copied().collect();
        unaccounted.encode_to(out);
        // `u64::MAX` for "no gap", the way `from` is written above, so the
        // field is one fixed width whatever it holds.
        self.missed_below.unwrap_or(u64::MAX).encode_to(out);
    }
}

/// Whether a list names each note once and in the order a map writes them.
///
/// `held` and `fell` are `BTreeMap`s, so [`History::encode_to`] writes them in
/// key order and never writes one note twice. Reading them back into a map
/// without asking would lose an entry rather than refuse the file: two entries
/// for one note came back as the later of the two, silently, and `fell` is the
/// list that decides whether a fallen note can be spent at all. So a wallet
/// reported a balance that was neither what the file said nor an error.
///
/// The stamp on the file does not stand in the way of that, and cannot:
/// `History::save` appends `blake3(WalletHistory, bytes)`, which anybody who
/// can write the file can recompute. It is there to catch a write that was cut
/// short, not one that was meant.
fn each_note_once<T>(items: &[T], id: impl Fn(&T) -> NoteId) -> bool {
    items.windows(2).all(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_none_or(|(a, b)| id(a) < id(b))
    })
}

impl Decode for History {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let next = u64::decode_from(reader)?;
        let from = u64::decode_from(reader)?;
        let movements = Vec::<Movement>::decode_from(reader)?;
        let last = Hash32::decode_from(reader)?;
        let held = Vec::<Owned>::decode_from(reader)?;
        let undone = Vec::<Movement>::decode_from(reader)?;
        // Where fallen notes landed. A file written before this wallet learned
        // to keep places simply ends here, and is read rather than thrown
        // away: the account of what this key was paid is the expensive part
        // and the places are found again from the node as notes go past.
        let fell = if reader.remaining() > 0 {
            Vec::<Fell>::decode_from(reader)?
        } else {
            Vec::new()
        };
        // The heights those notes were paid at. A file written before this
        // wallet learned to keep them ends here, and is read rather than
        // thrown away: what a missing height means is a note this account
        // never read a block for, which is the settled case either way.
        let paid_at = if reader.remaining() > 0 {
            Vec::<PaidAt>::decode_from(reader)?
        } else {
            Vec::new()
        };
        // Notes the account stopped answering for. A file written before this
        // wallet learned to say so ends here, and is read rather than thrown
        // away.
        //
        // What that costs is worth stating exactly, because the obvious
        // sentence is wrong. It is not that such a wallet says so again the
        // next time it is moved past a block: `skip_to` is the only writer of
        // this set and it is reached only when the node's log begins above
        // where the account has read to, and an account caught up to the tip
        // is never below that again. There is no next time. A wallet that
        // carried the gap before this release goes on counting what it paid
        // away in it, for good, and nothing in the file records where the gap
        // was to rebuild the marks from.
        //
        // Read anyway, because the account of what this key was paid is the
        // expensive half and refusing the file would throw that away as well,
        // to fix nothing.
        let unaccounted = if reader.remaining() > 0 {
            Vec::<NoteId>::decode_from(reader)?
        } else {
            Vec::new()
        };
        // The height below which the list may be short. A file written before
        // this wallet learned to say so ends here, and is read: an account
        // that has never been moved past a block has nothing to put here, and
        // one that has cannot be told from it, which is a list that reads as
        // complete until the next gap opens. That is the same cost the
        // `unaccounted` list above carries and it is named there.
        let missed_below = if reader.remaining() > 0 {
            u64::decode_from(reader)?
        } else {
            u64::MAX
        };
        if !each_note_once(&held, |owned| owned.id)
            || !each_note_once(&fell, |fell| fell.id)
            || !each_note_once(&paid_at, |paid| paid.id)
            || !each_note_once(&unaccounted, |id| *id)
        {
            return Err(CodecError::InvalidValue {
                type_name: "History",
            });
        }
        Ok(Self {
            held: held.into_iter().map(|held| (held.id, held.value)).collect(),
            fell: fell
                .into_iter()
                .map(|fell| (fell.id, fell.position))
                .collect(),
            paid_at: paid_at
                .into_iter()
                .map(|paid| (paid.id, paid.height))
                .collect(),
            unaccounted: unaccounted.into_iter().collect(),
            missed_below: (missed_below != u64::MAX).then_some(missed_below),
            movements,
            next,
            from: (from != u64::MAX).then_some(from),
            last: (last != Hash32::ZERO).then_some(last),
            undone,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {

    /// What a movement is called, to the person and to the disk.
    ///
    /// Three words and three tags, and nothing held either. The words are what
    /// the page reads: it puts a minus sign in front of an amount when the
    /// movement's way is "sent", so renaming that one turns every payment made
    /// into a payment received on the screen. The tags are how a movement is
    /// written down, so dropping one turns every stored movement of that kind
    /// into a record the wallet reads back as nothing. `cargo mutants` did
    /// both with the suite green.
    #[test]
    fn a_movement_is_called_what_the_page_reads_and_stored_as_what_it_reads_back() {
        for direction in [Direction::Received, Direction::Mined, Direction::Sent] {
            assert_eq!(
                Direction::from_tag(direction.tag()),
                Some(direction),
                "{direction:?} does not read back as what it was written as"
            );
        }
        assert_eq!(Direction::from_tag(3), None, "a tag no direction has");

        assert_eq!(Direction::Received.as_str(), "received");
        assert_eq!(Direction::Mined.as_str(), "mined");
        assert_eq!(Direction::Sent.as_str(), "sent");

        // And the page is reading that word rather than one of its own.
        let page = include_str!("page.rs");
        assert!(
            page.contains(&format!("=== \"{}\"", Direction::Sent.as_str())),
            "the page no longer compares a movement's way against {:?}, so the \
             sign in front of an amount is decided by something else now",
            Direction::Sent.as_str()
        );
    }
    use super::*;
    use cairn_crypto::SecretKey;
    use cairn_ledger::block::BlockHeader;
    use cairn_ledger::note::{NetworkId, Note};
    use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};

    fn key(seed: u8) -> PublicKey {
        SecretKey::from_bytes(&[seed; 32]).public_key()
    }

    fn amount(text: &str) -> Amount {
        Amount::from_cairn(text).unwrap()
    }

    fn block(height: u64, to: PublicKey, transfers: Vec<Transfer>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                network: NetworkId::TESTNET,
                height,
                previous: Hash32::ZERO,
                state_root: Hash32::ZERO,
                transactions_root: Hash32::ZERO,
                history: Hash32::ZERO,
                timestamp: 1_000_u64.saturating_add(height),
                difficulty: 1,
                total_work: u128::from(height),
                nonce: 0,
            },
            coinbase: CoinbaseTransaction::new(height, vec![Note::new(amount("50"), to)]),
            transfers,
        }
    }

    /// What an account gives up on when it is moved past a block, and what it
    /// takes back when the note turns up again.
    #[test]
    fn moving_past_a_block_gives_up_on_what_was_held() {
        let mine = key(1);
        let mut history = History::new();
        history.take(&block(0, mine, Vec::new()), mine);
        history.take(&block(1, mine, Vec::new()), mine);
        let held: Vec<NoteId> = history.held().map(|(id, _)| id).collect();
        assert_eq!(held.len(), 2);
        assert_eq!(history.unaccounted().count(), 0, "nothing has been missed");

        history.skip_to(40);
        let given_up: Vec<NoteId> = history.unaccounted().collect();
        assert_eq!(
            given_up, held,
            "every note this account held was held as of a block it will never \
             read, so it answers for none of them"
        );

        // Found again, one at a time. The whole account is given up on at once
        // because a gap is a fact about a range; it is taken back a note at a
        // time because being found again is a fact about a note.
        assert!(history.accounted_for(&held[0]));
        assert!(!history.accounted_for(&held[0]), "and only once");
        assert_eq!(history.unaccounted().count(), 1);

        // And both survive the file, which is the whole point of writing them
        // down: the account is read back on a wallet that has been restarted,
        // and a gap it forgot would be a balance that came back wrong and a
        // list that came back looking complete.
        let bytes = history.encode();
        let read = History::decode_from(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            read.unaccounted().collect::<Vec<_>>(),
            vec![held[1]],
            "the file did not carry what the account had given up on"
        );
        assert_eq!(
            read.missed_below(),
            Some(40),
            "nor where its list stops being complete"
        );
    }

    /// A history with nothing in it says so, and one with a movement says
    /// that.
    ///
    /// The name clippy asks for beside `len`, which the page reads to decide
    /// whether to show a list or the sentence saying there is nothing yet. It
    /// could answer yes to a history holding movements, and the suite stayed
    /// green.
    #[test]
    fn a_history_is_empty_exactly_when_it_holds_no_movements() {
        let mine = key(1);
        let mut history = History::new();
        assert_eq!(history.len(), 0);
        assert!(history.is_empty(), "a history that has read nothing");

        history.take(&block(0, mine, Vec::new()), mine);
        assert_eq!(history.len(), 1);
        assert!(
            !history.is_empty(),
            "and one that has read a block paying this key"
        );
    }

    #[test]
    fn mining_a_block_is_money_arriving() {
        let mine = key(1);
        let mut history = History::new();
        history.take(&block(0, mine, Vec::new()), mine);
        history.take(&block(1, key(2), Vec::new()), mine);

        assert_eq!(history.len(), 1, "one of the two paid this key");
        let movement = history.movements().next().unwrap();
        assert_eq!(movement.direction, Direction::Mined);
        assert_eq!(movement.amount, amount("50"));
        assert_eq!(movement.height, 0);
        assert_eq!(history.next(), 2);
        assert_eq!(history.from(), Some(0));
    }

    /// A spend shows what left, not what was gathered. Gathering fifty to send
    /// twenty and keeping thirty is a movement of twenty.
    #[test]
    fn a_spend_is_recorded_net_of_its_change() {
        let mine = key(1);
        let them = key(2);
        let mut history = History::new();
        let first = block(0, mine, Vec::new());
        history.take(&first, mine);
        let held = first.coinbase.created_notes()[0].0;

        let transfer = Transfer::new(
            vec![Input::hot(held)],
            vec![Note::new(amount("20"), them), Note::new(amount("29"), mine)],
        );
        history.take(&block(1, them, vec![transfer]), mine);

        assert_eq!(history.len(), 2);
        let latest = history.movements().next().unwrap();
        assert_eq!(latest.direction, Direction::Sent);
        assert_eq!(
            latest.amount,
            amount("21"),
            "twenty to them and one to whoever carried it"
        );
    }

    /// A payment that takes a note whole, with nothing coming back to this
    /// key, is recorded as a payment of the whole note.
    ///
    /// No test read a spend with no change back out of the account, so a
    /// record that let one go by passed: the note left what the account holds
    /// and no line in the list said where it went.
    #[test]
    fn a_spend_with_no_change_is_recorded_whole() {
        let mine = key(1);
        let them = key(2);
        let mut history = History::new();
        let first = block(0, mine, Vec::new());
        history.take(&first, mine);
        let held = first.coinbase.created_notes()[0].0;

        let whole = Transfer::new(vec![Input::hot(held)], vec![Note::new(amount("49"), them)]);
        history.take(&block(1, them, vec![whole]), mine);

        assert_eq!(
            history.len(),
            2,
            "a payment of everything the note held left no line in the list"
        );
        let latest = history.movements().next().unwrap();
        assert_eq!(latest.direction, Direction::Sent);
        assert_eq!(
            latest.amount,
            amount("50"),
            "forty nine to them and one to whoever carried it"
        );
        assert_eq!(history.held().count(), 0, "and the note is no longer held");
    }

    /// A list that is exactly full still says how far back it reaches.
    ///
    /// Past `MAX_MOVEMENTS` the oldest are dropped and how far back the
    /// account reaches moves with them, because what was dropped is what it
    /// can no longer answer for. At exactly that many nothing is dropped, and
    /// nothing should move: `cargo mutants` could turn the comparison into
    /// `>=`, and then an account that had read every block from the first
    /// would say it only reaches back to its oldest payment, which is a
    /// sentence about somebody's money that is not true.
    #[test]
    fn a_list_that_is_exactly_full_still_reaches_back_to_where_it_began() {
        let mine = key(1);
        let them = key(2);
        let mut history = History::new();

        // The first block pays somebody else, so where this account begins
        // and where its oldest payment sits are different numbers.
        history.take(&block(0, them, Vec::new()), mine);
        assert_eq!(history.from(), Some(0), "it began at the first block");

        for height in 1..=MAX_MOVEMENTS as u64 {
            history.take(&block(height, mine, Vec::new()), mine);
        }
        assert_eq!(
            history.len(),
            MAX_MOVEMENTS,
            "exactly full, nothing dropped"
        );
        assert_eq!(
            history.from(),
            Some(0),
            "and it still reaches back to the block it began at"
        );

        // One more, and the oldest goes: what it can answer for moves with it.
        history.take(&block(MAX_MOVEMENTS as u64 + 1, mine, Vec::new()), mine);
        assert_eq!(history.len(), MAX_MOVEMENTS);
        assert_eq!(
            history.from(),
            Some(2),
            "the oldest payment it still holds is the one at height two"
        );
    }

    /// Money that went round and came back is not a payment.
    ///
    /// A transfer that spends this key's notes and pays the whole of them back
    /// to it moved nothing: the amount is nought, and a movement of nought in
    /// a list of payments is a line the person has to work out the meaning of.
    /// The comparison that drops it could be `>=` with the suite green, since
    /// nothing else in the workspace builds a transfer that gathers and
    /// returns exactly the same amount.
    #[test]
    fn money_that_went_round_and_came_back_is_not_a_payment() {
        let mine = key(1);
        let them = key(2);
        let mut history = History::new();
        let first = block(0, mine, Vec::new());
        history.take(&first, mine);
        let held = first.coinbase.created_notes()[0].0;
        assert_eq!(history.len(), 1, "the block that paid this key");

        // Gathered and handed straight back, whole: nothing left and nothing
        // arrived.
        let round_trip = Transfer::new(vec![Input::hot(held)], vec![Note::new(amount("50"), mine)]);
        history.take(&block(1, them, vec![round_trip]), mine);

        assert_eq!(
            history.len(),
            1,
            "a transfer that moved nothing left a line in the list: {:?}",
            history.movements().next()
        );
    }

    /// Being paid by a stranger is money arriving, and a transfer between two
    /// other people is nothing at all.
    #[test]
    fn what_happens_to_other_people_is_not_recorded() {
        let mine = key(1);
        let them = key(2);
        let mut history = History::new();

        let theirs = block(0, them, Vec::new());
        history.take(&theirs, mine);
        let their_note = theirs.coinbase.created_notes()[0].0;
        assert!(history.is_empty(), "a block that paid someone else");

        // They pay this key.
        let paying = Transfer::new(
            vec![Input::hot(their_note)],
            vec![Note::new(amount("12"), mine), Note::new(amount("38"), them)],
        );
        history.take(&block(1, them, vec![paying]), mine);
        assert_eq!(history.len(), 1);
        let movement = history.movements().next().unwrap();
        assert_eq!(movement.direction, Direction::Received);
        assert_eq!(movement.amount, amount("12"));

        // And a transfer that has nothing to do with this key.
        let elsewhere = Transfer::new(
            vec![Input::hot(NoteId::new(Hash32::from_bytes([3; 32]), 0))],
            vec![Note::new(amount("5"), key(3))],
        );
        history.take(&block(2, them, vec![elsewhere]), mine);
        assert_eq!(history.len(), 1, "nothing of ours happened");
    }

    /// Blocks out of order would spend notes this has not seen created, and
    /// record a stranger's transfer as ours.
    #[test]
    fn a_block_out_of_turn_is_not_taken() {
        let mine = key(1);
        let mut history = History::new();
        history.take(&block(5, mine, Vec::new()), mine);
        assert!(history.is_empty(), "the history starts at nought");
        assert_eq!(history.next(), 0);

        history.take(&block(0, mine, Vec::new()), mine);
        assert_eq!(history.len(), 1);
        history.take(&block(2, mine, Vec::new()), mine);
        assert_eq!(history.len(), 1, "one was skipped, so it is refused");
    }

    #[test]
    fn a_branch_that_was_undone_is_noticed_and_forgotten() {
        let mine = key(1);
        let mut history = History::new();
        let mut ids = Vec::new();
        for height in 0..5 {
            let block = block(height, mine, Vec::new());
            ids.push(block.id());
            history.take(&block, mine);
        }
        assert_eq!(history.len(), 5);

        // The chain still holds what was read: nothing moved.
        assert!(
            !history.diverged(Some(4), |height| usize::try_from(height)
                .ok()
                .and_then(|at| ids.get(at))
                .copied()),
            "every block is where it was read"
        );

        // A height the wallet can no longer read is not a branch being undone.
        assert!(
            !history.diverged(Some(4), |_| None),
            "a block that was dropped is not a block that changed"
        );

        // A chain that no longer reaches that height is, whatever it answers
        // about the block: work decides the branch, so the one that won can
        // end lower than the one it replaced.
        assert!(
            history.diverged(Some(2), |_| None),
            "the chain stops below what this read, so what it read is gone"
        );

        // The newest block is now a different one, which is what a
        // reorganisation leaves behind. The difference has to be in the
        // header, because that is what an identifier is taken over: two blocks
        // paying different people are the same block to this check unless
        // their headers differ, which on a real chain they always do.
        let mut rival = block(4, key(2), Vec::new());
        rival.header.nonce = 7;
        let elsewhere = rival.id();
        assert_ne!(elsewhere, ids[4], "the rival really is another block");
        assert!(
            history.diverged(Some(4), |height| if height == 4 {
                Some(elsewhere)
            } else {
                usize::try_from(height)
                    .ok()
                    .and_then(|at| ids.get(at))
                    .copied()
            }),
            "the block at the top is not the one that was read"
        );

        history.forget(None);
        assert_eq!(history.len(), 0, "and the whole account is read again");
        assert_eq!(history.next(), 0);
        assert_eq!(
            history.undone().count(),
            5,
            "while what it said before is kept, to be given back as the chain is read again"
        );
    }

    /// What the account keeps of a branch that lost, and what it drops.
    ///
    /// `MAX_UNDONE` is the bound, and nothing could fail on it: the tests
    /// around forgetting hold that what was undone is kept, at counts far
    /// under it, so the number could be five or five million and they would
    /// pass either way. It is the oldest that go, which is the half that
    /// decides whether a person reading their own account sees the payment
    /// they are looking for or the one before it.
    #[test]
    fn the_account_keeps_the_newest_undone_movements_and_no_more() {
        let mine = key(1);
        let mut history = History::new();
        // A literal, and not the constant plus something. Written in terms of
        // the constant this test moves with it, which is the defect it is here
        // to close: at five it would pass as readily as at two hundred and
        // fifty six, and five is not a record of a branch that lost.
        let over = 300usize;
        assert!(
            over > MAX_UNDONE,
            "this test reads {over} movements to watch {MAX_UNDONE} of them kept, and has to \
             read more than are kept"
        );
        for height in 0..over as u64 {
            history.take(&block(height, mine, Vec::new()), mine);
        }
        assert_eq!(history.len(), over, "every block paid this key");

        history.forget(None);

        assert_eq!(
            history.undone().count(),
            MAX_UNDONE,
            "the account kept every movement of a branch that lost"
        );
        let oldest = history.undone().map(|held| held.height).min();
        assert_eq!(
            oldest,
            Some((over - MAX_UNDONE) as u64),
            "the ones dropped were meant to be the oldest, and what is left \
             begins at the height after them"
        );
    }

    /// Forgetting keeps the place of a note no reorganisation can reach, and
    /// throws away the place of one it can.
    ///
    /// A place is the one thing in this file the chain cannot give back. It
    /// comes from the node's watch list, and a node restarted from a written
    /// ledger comes back without one, so after forgetting there is nothing
    /// anywhere that says where the note sits and the money cannot be moved.
    /// A note paid below the deepest switch this node will follow cannot be
    /// taken away by one, so keeping its place says nothing the chain could
    /// contradict.
    ///
    /// A note paid inside that reach is the case the rest of forgetting is
    /// for: the block that paid it may be gone, and keeping it would be this
    /// file going on calling somebody else's money ours.
    #[test]
    fn forgetting_keeps_the_place_of_a_note_that_is_settled_and_no_other() {
        let mine = key(1);
        let mut history = History::new();
        for height in 0..10 {
            history.take(&block(height, mine, Vec::new()), mine);
        }

        let settled = NoteId::new(block(2, mine, Vec::new()).coinbase.id(), 0);
        let inside_the_reach = NoteId::new(block(9, mine, Vec::new()).coinbase.id(), 0);
        assert!(history.fell_at(settled, amount("50"), 11));
        assert!(history.fell_at(inside_the_reach, amount("50"), 12));

        // The tip is 9 and this node follows a switch four deep, so anything
        // paid below height 6 is settled.
        history.forget(Some(6));

        assert_eq!(
            history.where_it_fell(&settled),
            Some(11),
            "the place of a note nothing can take away was thrown away with the rest"
        );
        assert_eq!(
            history.where_it_fell(&inside_the_reach),
            None,
            "the place of a note the switch may have taken was kept"
        );
        assert_eq!(
            history.held().count(),
            1,
            "and what the account still names is exactly the notes it kept a place for"
        );
    }

    /// Forgetting keeps the heights the places were judged by, so the next
    /// forgetting judges them the same way.
    ///
    /// What decides whether a place is kept is the height the note was paid
    /// at, against the line below which a switch can no longer reach. Those
    /// heights are rebuilt along with everything else, and `cargo mutants`
    /// could drop them from the rebuild: a note with no height counts as
    /// settled, so the second forgetting would keep every place the first one
    /// had kept, including the ones a switch can still take away.
    #[test]
    fn forgetting_twice_judges_the_same_places_the_same_way() {
        let mine = key(1);
        let mut history = History::new();
        for height in 0..10 {
            history.take(&block(height, mine, Vec::new()), mine);
        }

        let settled = NoteId::new(block(2, mine, Vec::new()).coinbase.id(), 0);
        let nearer = NoteId::new(block(5, mine, Vec::new()).coinbase.id(), 0);
        assert!(history.fell_at(settled, amount("50"), 11));
        assert!(history.fell_at(nearer, amount("50"), 12));

        // Below three is settled, so both places are kept the first time.
        history.forget(Some(6));
        assert_eq!(history.where_it_fell(&settled), Some(11));
        assert_eq!(history.where_it_fell(&nearer), Some(12));

        // And now the line moves back, as it does when a node restarts from a
        // ledger it was handed. The nearer note is no longer settled, so its
        // place goes; the older one stays.
        history.forget(Some(3));
        assert_eq!(
            history.where_it_fell(&settled),
            Some(11),
            "a note paid below the line keeps its place through both"
        );
        assert_eq!(
            history.where_it_fell(&nearer),
            None,
            "and one paid above it loses its place the moment the line passes \
             it, which takes the height it was paid at"
        );
    }

    /// And with no settled line at all, nothing is kept: a wallet that cannot
    /// say how deep the switch could have gone says nothing about any of them.
    #[test]
    fn forgetting_with_nothing_settled_keeps_no_place() {
        let mine = key(1);
        let mut history = History::new();
        history.take(&block(0, mine, Vec::new()), mine);
        let paid = NoteId::new(block(0, mine, Vec::new()).coinbase.id(), 0);
        assert!(history.fell_at(paid, amount("50"), 3));

        history.forget(None);

        assert_eq!(history.where_it_fell(&paid), None);
        assert_eq!(history.held().count(), 0);
    }

    /// Forgetting keeps the account, and reading the chain again takes back
    /// out of it everything the chain still carries. What is left is what was
    /// really undone.
    #[test]
    fn what_the_chain_gives_back_stops_being_undone() {
        let mine = key(1);
        let mut history = History::new();
        for height in 0..3 {
            history.take(&block(height, mine, Vec::new()), mine);
        }
        history.forget(None);
        assert_eq!(history.undone().count(), 3);

        // Two of the three blocks are on the branch that won.
        for height in 0..2 {
            history.take(&block(height, mine, Vec::new()), mine);
        }
        assert_eq!(history.len(), 2, "read again from the chain");
        assert_eq!(
            history.undone().count(),
            1,
            "and only the one the chain no longer carries is still undone"
        );
    }

    #[test]
    fn it_survives_being_written_down_and_read_back() {
        let mine = key(1);
        let mut history = History::new();
        let first = block(0, mine, Vec::new());
        history.take(&first, mine);
        let held = first.coinbase.created_notes()[0].0;
        history.take(
            &block(
                1,
                key(2),
                vec![Transfer::new(
                    vec![Input::hot(held)],
                    vec![Note::new(amount("10"), key(2))],
                )],
            ),
            mine,
        );

        let bytes = history.encode();
        let read = History::decode(&bytes).unwrap();
        assert_eq!(read.len(), history.len());
        assert_eq!(read.next(), history.next());
        assert_eq!(read.from(), history.from());
        assert_eq!(
            read.movements().next().unwrap(),
            history.movements().next().unwrap()
        );
        assert_eq!(read.encode(), bytes, "and the writing is canonical");
    }

    #[test]
    fn where_a_note_landed_is_written_down_and_read_back() {
        let mine = key(1);
        let mut history = History::new();
        history.take(&block(0, mine, Vec::new()), mine);
        let (id, _) = history.held().next().unwrap();

        assert_eq!(history.where_it_fell(&id), None, "it has not fallen yet");
        assert!(history.fell_at(id, amount("50"), 41));
        assert_eq!(history.where_it_fell(&id), Some(41));
        assert!(
            !history.fell_at(id, amount("50"), 41),
            "the same place again is not news, and news is what gets the file written"
        );
        assert!(
            history.fell_at(id, amount("50"), 9),
            "a branch that won put the note somewhere else, and that is news"
        );
        assert_eq!(history.where_it_fell(&id), Some(9));

        let read = History::decode(&history.encode()).unwrap();
        assert_eq!(read.where_it_fell(&id), Some(9));
        assert_eq!(read.encode(), history.encode());
    }

    /// A note the account never read the block for is taken up, place and all.
    ///
    /// The account is not the only thing that knows what this key owns. A
    /// wallet handed a ledger begins reading at the anchor, and its node comes
    /// out of that handover holding the notes that fell in the window below
    /// it. Written down here they survive the node starting again from a
    /// ledger of its own; refused, as they used to be, they were held in one
    /// place only and the money left the balance on that restart.
    #[test]
    fn a_note_the_account_never_read_a_block_for_is_taken_up_with_its_place() {
        let mine = key(1);
        let mut history = History::new();
        let unseen = NoteId::new(Hash32::from_bytes([9; 32]), 0);
        assert!(history.fell_at(unseen, amount("7"), 3));
        assert_eq!(history.where_it_fell(&unseen), Some(3));
        assert_eq!(
            history.held().find(|(id, _)| *id == unseen).map(|(_, v)| v),
            Some(amount("7")),
            "and it counts towards what this key holds, which is what makes it \
             money the wallet can name rather than a number in a map"
        );

        // And a note that is spent takes its place with it, so the account
        // never carries a handle to money it no longer holds.
        history.take(&block(0, mine, Vec::new()), mine);
        let (id, _) = history.held().find(|(id, _)| *id != unseen).unwrap();
        assert!(history.fell_at(id, amount("50"), 5));
        let spend = Transfer::new(vec![Input::hot(id)], vec![Note::new(amount("49"), key(2))]);
        history.take(&block(1, key(2), vec![spend]), mine);
        assert_eq!(history.where_it_fell(&id), None);
    }

    #[test]
    fn an_account_written_before_places_were_kept_is_still_read() {
        let mine = key(1);
        let mut history = History::new();
        history.take(&block(0, mine, Vec::new()), mine);

        // What the file looked like before: everything up to the undone list
        // and nothing after it.
        let mut older = Vec::new();
        history.next.encode_to(&mut older);
        history.from.unwrap_or(u64::MAX).encode_to(&mut older);
        history.movements.encode_to(&mut older);
        history.last.unwrap_or(Hash32::ZERO).encode_to(&mut older);
        let held: Vec<Owned> = history
            .held
            .iter()
            .map(|(id, value)| Owned {
                id: *id,
                value: *value,
            })
            .collect();
        held.encode_to(&mut older);
        history.undone.encode_to(&mut older);

        let read = History::decode(&older).unwrap();
        assert_eq!(read.len(), history.len());
        assert_eq!(read.held().count(), 1);
        assert_eq!(
            read.where_it_fell(&history.held().next().unwrap().0),
            None,
            "it knows nothing about places, and finds them again from the node"
        );
    }
}

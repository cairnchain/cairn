//! What happened to this key, in the order it happened.
//!
//! The chain says what a key owns now. It does not say what it received in
//! March, and nothing in the protocol should: a history is one person's
//! account of their own money, useful to them and to nobody else, and putting
//! it in the ledger would be asking every node in the world to carry it.
//!
//! So the wallet keeps its own, by watching the blocks it validates go past.
//! It is not consensus and nothing depends on it: lose the file and the money
//! is exactly where it was, and reading the chain again rebuilds it.
//!
//! What it can say is bounded by what the wallet kept. A wallet that dropped
//! old blocks, or that was handed a ledger rather than reading its way to one,
//! has no way to know what happened before that, and says so rather than
//! showing a history that starts nowhere in particular.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

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

/// This key's own account of its money.
#[derive(Clone, Debug, Default)]
pub struct History {
    /// Notes this key holds, so a spend can be told from a stranger's.
    ///
    /// Kept because an input names a note and not its owner: without knowing
    /// which notes are ours, a transfer spending one of them is
    /// indistinguishable from a transfer between two other people.
    held: BTreeMap<NoteId, Amount>,
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

    /// The first height it saw, or `None` if it has seen nothing.
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
                gave = gave.checked_add(value).unwrap_or(gave);
            }
        }

        // What came back to it: outputs naming this key, which for a spend of
        // our own is the change.
        let mut got = Amount::ZERO;
        for (id, note) in transfer.created_notes() {
            if note.owner == mine {
                self.held.insert(id, note.value);
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

    fn record(&mut self, movement: Movement) {
        // A block carries it, so whatever branch it was read on before, it is
        // on this one now and was never undone.
        self.undone.retain(|held| held.id != movement.id);
        self.movements.push(movement);
        if self.movements.len() > MAX_MOVEMENTS {
            let over = self.movements.len().saturating_sub(MAX_MOVEMENTS);
            self.movements.drain(..over);
        }
    }

    /// Moves the reading point forward, for a wallet that cannot see what
    /// came before.
    ///
    /// A wallet handed a ledger, or one that dropped old blocks, has no way to
    /// read them and no way to guess. The history then begins where the wallet
    /// does, which it says rather than implying it covers everything.
    pub fn skip_to(&mut self, height: u64) {
        if height <= self.next {
            return;
        }
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
    pub fn forget(&mut self) {
        let mut undone = std::mem::take(&mut self.undone);
        undone.append(&mut self.movements);
        let over = undone.len().saturating_sub(MAX_UNDONE);
        undone.drain(..over);
        *self = Self {
            undone,
            ..Self::default()
        };
    }

    /// Reads it back from `path`, or starts empty when there is nothing to
    /// read.
    ///
    /// A file that cannot be understood is not an error worth stopping for:
    /// this is one person's notes about their own money, and the chain can
    /// always be read again.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| Self::verified(&bytes))
            .unwrap_or_default()
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
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let partial = path.with_extension("part");
        let mut bytes = self.encode();
        bytes.extend_from_slice(hash(Domain::WalletHistory, &bytes).as_bytes());
        {
            let mut file = std::fs::File::create(&partial)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&partial, path)?;
        if let Some(directory) = path.parent() {
            if let Ok(handle) = std::fs::File::open(directory) {
                let _ = handle.sync_all();
            }
        }
        Ok(())
    }
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
    }
}

impl Decode for History {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let next = u64::decode_from(reader)?;
        let from = u64::decode_from(reader)?;
        let movements = Vec::<Movement>::decode_from(reader)?;
        let last = Hash32::decode_from(reader)?;
        let held = Vec::<Owned>::decode_from(reader)?;
        let undone = Vec::<Movement>::decode_from(reader)?;
        Ok(Self {
            held: held.into_iter().map(|held| (held.id, held.value)).collect(),
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

        history.forget();
        assert_eq!(history.len(), 0, "and the whole account is read again");
        assert_eq!(history.next(), 0);
        assert_eq!(
            history.undone().count(),
            5,
            "while what it said before is kept, to be given back as the chain is read again"
        );
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
        history.forget();
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
}

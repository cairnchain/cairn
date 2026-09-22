//! Consensus rules.
//!
//! Every rule here decides whether a block is valid. Two nodes that evaluate
//! any of them differently follow different chains, so nothing in this module
//! may depend on wall clock time, iteration order, or locale. The current time
//! is passed in rather than read.

use std::collections::{BTreeMap, BTreeSet};

use cairn_crypto::{PublicKey, Signature};
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

use crate::emission;

use crate::block::{Activation, Block, BlockHeader, BLOCK_VERSION};
use crate::note::{NetworkId, Note, NoteId};
use crate::pow::{median_time_past, meets_target, next_difficulty, work_of, MIN_DIFFICULTY};
use crate::state::{cold_leaf, BlockUndo, ColdSpend, LedgerState, StateTransition};
use crate::transaction::{
    CoinbaseTransaction, Input, Transfer, Witness, COINBASE_VERSION, MAX_COINBASE_EXTRA,
    TRANSFER_VERSION,
};

/// A reward written in pebbles, as an amount.
///
/// This used to map anything above the monetary ceiling to zero. Nothing was
/// wrong with the constants it was given, and that is the point: an edit that
/// pushed one over the ceiling would have compiled, shipped, and paid nobody,
/// with every node agreeing that nobody was owed anything. There is no amount
/// that stands in for one too large, so there is no fallback. Its only two
/// uses are the `const` items below, where this runs while the crate is being
/// built and a constant it cannot represent stops the build instead.
// A panic is denied across this workspace because a panic at run time is a
// node that stops. This one never reaches run time.
#[allow(clippy::panic)]
const fn reward_of(pebbles: u64) -> Amount {
    match Amount::from_pebbles(pebbles) {
        Some(amount) => amount,
        None => panic!("a block reward above the monetary ceiling would pay nobody"),
    }
}

const INITIAL_REWARD: Amount = reward_of(emission::INITIAL_REWARD_PEBBLES);
const TAIL_REWARD: Amount = reward_of(emission::TAIL_REWARD_PEBBLES);

/// How many notes stay in the hot set.
///
/// Chosen from a measurement rather than from a round number. A hot note costs
/// about 516 bytes across the three structures a node keeps for it, so this is
/// roughly 68 MB. It was 107 MB until a public key stopped being held as a
/// decoded curve point, which `cairn-ledger/examples/footprint.rs` measures.
///
/// The figure is set by the promise rather than by what a server could afford:
/// a phone has to be able to hold it, because a wallet that cannot verify for
/// itself is the centralisation this design exists to remove. Over half of
/// what is left is the tree that commits to the set, so a leaner tree is now
/// the single most valuable optimisation remaining, and it would buy room to
/// raise this.
const DEFAULT_HOT_CAPACITY: usize = 1 << 17;

/// Seconds a block is meant to take. Provisional.
const DEFAULT_TARGET_BLOCK_TIME: u64 = 60;

/// The difficulty [`ConsensusParams::mineable_network`] opens at.
///
/// Four thousand and ninety six hashes for a block, which is about a
/// millisecond on one core here, so a couple of hundred blocks is a fixture a
/// test can afford. What matters is that it is not the floor: the retarget can
/// fall six times from here before it reaches [`MIN_DIFFICULTY`], and it can
/// rise as far as a test is willing to pay for. A published network opens at
/// 2^23 or 2^27, where a test cannot afford a second block, and that is the
/// whole reason this number exists rather than one of those.
pub const MINEABLE_DIFFICULTY: u64 = 4_096;

/// Blocks a coinbase's notes must wait before anyone can spend them.
///
/// The reward is the one note in the chain that has no parent. Every other
/// note survives a reorganisation, because the transfer that made it can be
/// mined again on the branch that wins; a coinbase cannot, since it belongs to
/// one block and dies with it. So a miner paid at height N and spending at
/// N+1 hands its recipient money that a reorganisation removes and no honest
/// miner can put back. The recipient loses it and no rule was broken, which is
/// why nothing complains: the ledger stays right and the person does not.
///
/// The depth is the deepest reorganisation a node will accept, so a coinbase
/// becomes spendable exactly when its block can no longer be taken away. That
/// is a statement worth being able to make and it needs no number of its own
/// to justify: it is the number the rest of the design already runs on, and
/// the same one a handover is buried at. At a minute a block it is about
/// seventeen hours, which is close to what a Bitcoin miner already waits at a
/// hundred blocks of ten minutes.
///
/// Bitcoin waits a hundred blocks and Monero sixty, both of them far past
/// their own reorganisation depths. This one is exactly at it, which is the
/// most that can be argued for from the design rather than from custom.
///
/// A network that lowers this lowers its burial with it, and the depth a node
/// refuses to undo past follows the burial rather than this constant. That is
/// what keeps the claim true on such a network instead of leaving it a
/// sentence about the default: devnet settles at thirty two and undoes no
/// further, so a reward there is still spendable exactly when its block stops
/// being reachable.
pub const COINBASE_MATURITY: u64 = crate::handover::BURIAL;

/// Rules a node applies to every block it evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusParams {
    pub network: NetworkId,
    /// The block every chain on this network must start from.
    ///
    /// `None` means nothing is pinned, which is what tests and unnamed
    /// networks use. A live network always pins it: without that, a node
    /// starting fresh has to take whatever first block the peer it happens to
    /// ask hands it, which is the one piece of trust worth removing.
    pub genesis: Option<Hash32>,
    /// No block may be dated before this.
    ///
    /// Published ahead of a launch, it makes the opening moment the same for
    /// everyone. Whoever knew about the network first cannot have mined it
    /// quietly the week before, because every node refuses blocks dated
    /// earlier.
    pub opens_at: u64,
    /// What the first block pays. The schedule halves from here.
    pub initial_reward: Amount,
    /// What every block pays once halving would take it lower.
    pub tail_reward: Amount,
    /// Blocks between halvings.
    pub halving_interval: u64,
    /// Notes the hot set holds before the oldest start falling to the cold set.
    pub hot_capacity: usize,
    /// Notes one block may push from the hot set to the cold set.
    ///
    /// How fast the hot set turns over is a shared resource: every note pushed
    /// out is somebody's money now needing a proof to spend, and the pusher
    /// chooses who by choosing nothing, since it is always the oldest that
    /// falls. Fees make that churn cost something, but a fee is only a price,
    /// and a miner includes its own transfers for free. This is the bound that
    /// holds whatever anyone pays.
    ///
    /// The number is a judgement. Full blocks of ordinary payments push out
    /// about six hundred and eighty six notes each, so honest traffic never
    /// meets this; what meets it is a block stuffed with outputs, which could
    /// otherwise push out over three thousand. At this cap, emptying the whole
    /// tier takes at least a hundred and twenty eight blocks, about two hours,
    /// instead of forty three minutes. `cairn-ledger/examples/blocksize.rs`
    /// works both figures out from measured sizes.
    ///
    /// Those two sentences are about this number and [`Self::hot_capacity`]
    /// together, and only the public networks hold both: devnet takes the tier
    /// down and inherits this, so there the cap is larger than the tier and
    /// one block empties it. Said where devnet is built, and pinned for every
    /// network in `tests/network_rules.rs`.
    pub max_evictions_per_block: usize,
    /// Blocks a handed over ledger must sit below the tip it belongs to.
    ///
    /// See [`crate::handover::BURIAL`] for what it buys. Here because it is a
    /// consensus rule like any other: two nodes that disagreed about it would
    /// disagree about which handovers are worth taking.
    pub burial: u64,
    /// Blocks a coinbase's notes must wait before anyone can spend them.
    ///
    /// See [`COINBASE_MATURITY`]. Consensus in the strongest sense: the window
    /// of coinbases still waiting is in the state root, so two nodes with
    /// different depths do not merely disagree about one spend, they compute
    /// different roots for every block.
    ///
    /// Never *below* [`Self::burial`], or a reward would be spendable while
    /// the block that paid it can still be undone, which is the one thing the
    /// rule exists to prevent. Every network here sets the two equal.
    ///
    /// The direction is worth stating carefully because it was written down
    /// backwards once, and so was the check that was meant to hold it: a
    /// maturity of nought under a burial of a thousand read as sound, which is
    /// a reward spendable at once on a chain that undoes a thousand blocks.
    /// The depth a node refuses to undo past is the smaller of its build's
    /// window and this network's burial, so a maturity at or above the burial
    /// is at or above that depth whichever of the two is smaller. Above is the
    /// safe side; there is no ceiling here, only a floor.
    pub coinbase_maturity: u64,
    /// Seconds the retarget aims for between blocks.
    pub target_block_time: u64,
    /// Difficulty the first block carries, before any history exists.
    ///
    /// It should already take about the target block time on one ordinary
    /// machine. Anything less and the opening seconds are a race the rest of
    /// the world has not been told about yet.
    pub genesis_difficulty: u64,
    pub max_transfers_per_block: usize,
    pub max_inputs_per_transfer: usize,
    pub max_outputs_per_transfer: usize,
    pub max_coinbase_outputs: usize,
    /// Bytes a block may take once encoded.
    ///
    /// The counts above bound the shape of a block; this bounds the thing
    /// itself, which is what a peer has to carry, a node has to hold while it
    /// validates, and a disk has to keep. Without it those counts multiply out
    /// to a block far larger than any network would carry, and a miner could
    /// produce one that is valid and cannot be handed to anyone: it would
    /// follow a chain nobody else can follow, which is a fork with no attacker
    /// in it.
    ///
    /// It has to stay comfortably under what the wire carries, and it is the
    /// wire's business to be the larger of the two.
    ///
    /// It decides three things at once, which is why the number is small.
    /// A node holds the blocks it could still reorganise away, so this times
    /// the reorganisation depth is memory every node must have: a megabyte a
    /// block would be a gigabyte, and this project's whole claim is that a
    /// node stays affordable. It also decides how fast the hot set turns over,
    /// since every payment nets a note, and with it how long the grace on a
    /// fallen note really lasts. And it decides how many people can be paid in
    /// a minute, which is the only one of the three anybody asks about.
    pub max_block_bytes: usize,
    /// How far ahead of the receiving node's clock a timestamp may sit.
    pub max_timestamp_drift: u64,
    /// The rule changes this network has scheduled, oldest first.
    ///
    /// Consensus like every other field here, and for the same reason: two
    /// nodes with different schedules disagree about which blocks are valid
    /// while believing they are on the same chain. The first entry is what the
    /// network opened under, and it sits at height zero.
    ///
    /// Oldest first is consensus too, and that is easy to miss because it
    /// reads as tidiness. [`ConsensusParams::version_at`] walks the list
    /// backwards and takes the first entry at or below the height it is
    /// asked about, which is only the right answer for an ascending list. Two
    /// builds carrying the same three changes, one of them written out of
    /// order, put the same height under different rules and neither says a
    /// word. So `schedule_is_sound` checks the shape at build time rather
    /// than leaving it to whoever makes the next edit.
    pub activations: &'static [Activation],
}

/// The version every network here opened under.
///
/// Kept apart from [`BLOCK_VERSION`], which is the newest this build knows.
/// They are the same number today and mean different things, and the day they
/// stop being the same is the day confusing them costs a chain: one is a fact
/// about a network's past, the other is a fact about a binary's present.
const OPENING_VERSION: u16 = 1;

/// The schedule a network that has never changed a rule carries.
const OPENED: &[Activation] = &[Activation {
    height: 0,
    version: OPENING_VERSION,
}];

/// Whether a schedule is one [`ConsensusParams::version_at`] can read.
///
/// Ascending, starting at height zero, and never naming a version this build
/// has never heard of below one it has. Checked at build time for every
/// shipped network, because every one of these being wrong is a chain split
/// produced by an ordinary edit rather than by an attacker.
const fn schedule_is_sound(activations: &[Activation]) -> bool {
    let [opening, rest @ ..] = activations else {
        return false;
    };
    if opening.height != 0 {
        return false;
    }
    let mut below = opening;
    let mut rest = rest;
    while let [next, tail @ ..] = rest {
        if next.height <= below.height || next.version <= below.version {
            return false;
        }
        below = next;
        rest = tail;
    }
    true
}

const _: () = assert!(
    schedule_is_sound(OPENED),
    "a schedule has to start at height zero and rise"
);

/// The decoder refuses what no network would accept, and this is what says so.
///
/// [`MOST_INPUTS`] and the ceilings beside it let a frame be turned away for
/// the price of reading its declared length, instead of after every note in it
/// has been built and every public key in it decompressed. That is only sound
/// while they sit at or above what the rules allow. Every shipped network is
/// [`ConsensusParams::testnet`] with a few fields replaced, and none of the
/// replacements is one of these, so checking it covers all of them.
///
/// Raising a limit here without raising the ceiling would leave a transfer
/// that consensus accepts and the wire cannot carry: valid, unrelayable, and
/// silent. So it stops the build instead.
const _: () = {
    let rules = ConsensusParams::testnet();
    assert!(
        rules.max_inputs_per_transfer <= crate::transaction::MOST_INPUTS,
        "the decoder would refuse a transfer the rules allow"
    );
    assert!(
        rules.max_outputs_per_transfer <= crate::transaction::MOST_OUTPUTS,
        "the decoder would refuse a transfer the rules allow"
    );
    assert!(
        rules.max_coinbase_outputs <= crate::transaction::MOST_COINBASE_OUTPUTS,
        "the decoder would refuse a coinbase the rules allow"
    );
    assert!(
        rules.max_transfers_per_block <= crate::block::MOST_TRANSFERS,
        "the decoder would refuse a block the rules allow"
    );
};

impl ConsensusParams {
    /// The rules of a named network.
    ///
    /// Every field here is consensus: two nodes that disagree on any of them
    /// build different chains while believing they are on the same one. So the
    /// rules belong to the network and are chosen by naming it, never set one
    /// at a time by whoever starts the node.
    // The mainnet arm answers like the unknown one on purpose, and saying so
    // out loud is the point: it is a name that will mean something and does
    // not yet.
    #[allow(clippy::match_same_arms)]
    pub fn for_network(name: &str) -> Option<Self> {
        match name {
            // Not yet made. A network exists once its first block does, and
            // that block will be mined in the open on the day it is announced.
            "mainnet" => None,
            "testnet" | "testnet-6" => Some(Self {
                network: NetworkId::TESTNET_6,
                genesis: crate::genesis::pinned(NetworkId::TESTNET_6),
                opens_at: crate::genesis::opens_at(NetworkId::TESTNET_6),
                genesis_difficulty: 1 << 27,
                ..Self::testnet()
            }),
            // A throwaway network, so its hot set is small enough that notes
            // reach the cold set in seconds rather than months, and its first
            // block is found in seconds. Everything else is the same, which is
            // the point of having it.
            //
            // Everything else but one, and it is the one the small hot set
            // takes with it. `max_evictions_per_block` is written as a hundred
            // and twenty eighth of the *default* tier, so a tier of sixty four
            // inherits a cap sixteen times its own size and a single block
            // empties the whole thing, where on a public network the same
            // number buys a hundred and twenty eight blocks.
            //
            // Said rather than mended, because no number keeps the relation at
            // this size: a hundred and twenty eighth of sixty four is nought,
            // and a cap of one refuses an ordinary devnet payment, which
            // evicts two. So the one rule bounding how fast the hot set turns
            // over is the one rule a throwaway network does not rehearse.
            // `tests/network_rules.rs` writes down what each network's cap
            // actually buys, so that moving either number fails a test rather
            // than a network.
            "devnet" => Some(Self {
                network: NetworkId::DEVNET,
                genesis: crate::genesis::pinned(NetworkId::DEVNET),
                opens_at: crate::genesis::opens_at(NetworkId::DEVNET),
                genesis_difficulty: 1 << 23,
                target_block_time: 5,
                hot_capacity: 64,
                // A throwaway network reaches this in minutes rather than in
                // most of a day, which is the whole point of having one.
                burial: 32,
                // And for the same reason, and kept equal to the burial for
                // the same reason the two are equal everywhere else.
                coinbase_maturity: 32,
                ..Self::testnet()
            }),
            _ => None,
        }
    }

    /// The name [`Self::for_network`] would take to produce these rules.
    pub fn network_name(&self) -> &'static str {
        // One table, and it is `NetworkId::name`. This was a second copy
        // knowing two of the eight, so a node on a retired network called it
        // "unnamed" while the constant naming it sat unread two files away.
        // Mainnet is named here and is still not a network until it has a
        // first block; what says so is `for_network`, which refuses it.
        self.network.name().unwrap_or("unnamed")
    }

    /// The rule set, with nothing tying it to a live network.
    ///
    /// No pinned first block and a trivial opening difficulty, which is what
    /// tests want and what no public network should ever run. Public networks
    /// come from [`Self::for_network`].
    pub const fn testnet() -> Self {
        Self {
            network: NetworkId::TESTNET,
            genesis: None,
            opens_at: 0,
            initial_reward: INITIAL_REWARD,
            tail_reward: TAIL_REWARD,
            halving_interval: emission::HALVING_INTERVAL,
            hot_capacity: DEFAULT_HOT_CAPACITY,
            // A hundred and twenty eighth of the tier, so however the blocks
            // are stuffed, emptying it takes at least that many of them.
            max_evictions_per_block: DEFAULT_HOT_CAPACITY >> 7,
            burial: crate::handover::BURIAL,
            coinbase_maturity: COINBASE_MATURITY,
            target_block_time: DEFAULT_TARGET_BLOCK_TIME,
            genesis_difficulty: MIN_DIFFICULTY,
            max_transfers_per_block: 4096,
            max_inputs_per_transfer: 256,
            max_outputs_per_transfer: 256,
            max_coinbase_outputs: 16,
            max_block_bytes: 128 * 1024,
            max_timestamp_drift: 2 * 60 * 60,
            // Nothing has changed yet, so the schedule says only what the
            // network opened under. A rule that changes appends to this.
            activations: OPENED,
        }
    }

    /// The block version the rules require at `height`.
    ///
    /// The last activation at or below it, so a block is judged by the rules
    /// in force where it sits rather than by today's.
    /// The first height these rules would be judged under a version `known`
    /// cannot apply, and the version they would ask for.
    ///
    /// A node finds out it is too old by stopping: `version_at` reaches a
    /// version its build does not implement, `SoftwareTooOld` comes back for
    /// every block from that height on, and the node is off the chain. The
    /// height is knowable long before, because a rule change is announced by
    /// being put in this schedule; the only thing standing between an operator
    /// and that date is somebody saying it out loud.
    ///
    /// Nothing is fetched to answer this. The schedule is in the rules the
    /// node already runs, and a chain's own height is what turns it into a
    /// date. There is no feed to poll, no key to trust, and no way for anybody
    /// to bring the date forward by saying so. That is the whole reason this
    /// is the shape the answer takes rather than a check against a published
    /// list of releases: a release feed would put whoever serves it in a
    /// position to tell every node when to change its rules.
    ///
    /// `None` while the schedule asks for nothing this build lacks, which is
    /// every build up to date with the rules it ships under.
    #[must_use]
    pub fn leaves_behind(&self, known: u16) -> Option<Activation> {
        // The first, and `schedule_is_sound` is why first is the right one: a
        // schedule rises in both height and version, so the earliest entry
        // asking for more than `known` is also the lowest height that does.
        self.activations
            .iter()
            .find(|activation| activation.version > known)
            .copied()
    }

    pub fn version_at(&self, height: u64) -> u16 {
        self.activations
            .iter()
            .rev()
            .find(|activation| height >= activation.height)
            // Unreachable while the first entry sits at height zero, which
            // `schedule_is_sound` below stops the build without. It used to
            // answer with this build's own ceiling, which reads as harmless
            // only because that number and the opening version are the same
            // today: the release that raises it would have made every block
            // below the first entry require the new version, and the chain
            // would have stopped replaying from its own first block.
            .map_or(OPENING_VERSION, |activation| activation.version)
    }

    /// What a block at `height` pays whoever produced it.
    pub fn reward_at(&self, height: u64) -> Amount {
        emission::reward_at(
            height,
            self.halving_interval,
            self.initial_reward,
            self.tail_reward,
        )
    }

    /// The most money this network's schedule can have paid out by `height`.
    ///
    /// A ceiling on what any ledger at that height may hold, and the only
    /// thing about a ledger that follows from the rules rather than from a
    /// commitment its sender wrote. See [`emission::emitted_by`].
    pub fn emitted_by(&self, height: u64) -> Amount {
        emission::emitted_by(
            height,
            self.halving_interval,
            self.initial_reward,
            self.tail_reward,
        )
    }

    /// The same rules with a hot set small enough to exercise eviction.
    #[must_use]
    pub const fn with_hot_capacity(mut self, capacity: usize) -> Self {
        self.hot_capacity = capacity;
        self
    }

    /// The same, for how many notes one block may push out. For tests, which
    /// would otherwise have to fill blocks to the byte limit to reach it.
    #[must_use]
    pub const fn with_max_evictions(mut self, limit: usize) -> Self {
        self.max_evictions_per_block = limit;
        self
    }

    /// The same, for how deep a handed over ledger must sit. For tests, which
    /// would otherwise have to mine a thousand blocks to reach one.
    #[must_use]
    pub const fn with_burial(mut self, blocks: u64) -> Self {
        self.burial = blocks;
        self
    }

    /// The same, for how long a coinbase waits. For tests, which would
    /// otherwise have to mine a thousand blocks before they could spend
    /// anything at all.
    #[must_use]
    pub const fn with_coinbase_maturity(mut self, blocks: u64) -> Self {
        self.coinbase_maturity = blocks;
        self
    }

    /// The same, for how much a block carries. For tests, which would
    /// otherwise have to give a wallet a hundred and twenty eight kilobytes of
    /// notes to reach the rule that a spend can be too large for any block.
    ///
    /// The cap on a transfer's inputs and the cap on a block's bytes are not
    /// the same cap, and which one bites depends on what the notes carry: a
    /// hot input is bytes and a fallen one brings its own proof, which is
    /// kilobytes. Lowering this is how a test gets to ask about the second
    /// without building the first.
    #[must_use]
    pub const fn with_max_block_bytes(mut self, bytes: usize) -> Self {
        self.max_block_bytes = bytes;
        self
    }

    /// A public network's shape, opened at a difficulty a test can mine.
    ///
    /// [`Self::testnet`] opens at [`MIN_DIFFICULTY`], which is the floor, so a
    /// retarget that wants to lower the difficulty has nowhere to lower it to,
    /// and every fixture in this workspace spaced its blocks ten times the
    /// target apart, which is the direction that wants lowering. Instrumenting
    /// [`expected_difficulty`] over the whole suite produced five outcomes and
    /// not one of them was a block asked to carry a difficulty different from
    /// its parent's. Work was the height, everywhere, for the life of the
    /// project.
    ///
    /// Three defects lived in that gap and none of them could be reached from
    /// a fixture. A sweep in `cairn-chain` froze for the life of the node, but
    /// only when a switch applied two or more blocks than it undid, and where
    /// every block is worth one a rival wins by exactly one. The memory
    /// ceiling went unenforced on a chain younger than the reorganisation
    /// window. And the deepest switch the rules allow was refused on
    /// testnet-6, because every deep-switch fixture set a burial far under the
    /// constant.
    ///
    /// So this is not a fourth set of numbers nobody runs. It is
    /// [`Self::testnet`] with the opening difficulty lifted off the floor and
    /// the two depths set together, and `tests/network_rules.rs` compares it
    /// field by field against `testnet-6`: a rule that moves on a public
    /// network and not here fails a test rather than leaving the fixtures
    /// rehearsing a shape no network has.
    ///
    /// The burial is the caller's and the maturity follows it rather than
    /// being chosen beside it. That pairing is the half of the shape the
    /// fixtures were missing even where they raised the difficulty:
    /// `with_burial(8)` leaves the maturity at a thousand and twenty four,
    /// which is a combination no network ships, and it is what every
    /// deep-switch test in this workspace was built on.
    #[must_use]
    pub const fn mineable_network(burial: u64) -> Self {
        let mut params = Self::testnet();
        params.genesis_difficulty = MINEABLE_DIFFICULTY;
        params.burial = burial;
        params.coinbase_maturity = burial;
        params
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    #[error("transfer version {0} is not supported")]
    UnsupportedVersion(u16),
    #[error("a transfer must spend at least one note")]
    NoInputs,
    #[error("a transfer must create at least one note")]
    NoOutputs,
    #[error("transfer spends {count} notes, limit is {limit}")]
    TooManyInputs { count: usize, limit: usize },
    #[error("transfer creates {count} notes, limit is {limit}")]
    TooManyOutputs { count: usize, limit: usize },
    #[error("transfer takes {bytes} bytes, more than the {limit} a block carries")]
    TooLargeForABlock { bytes: usize, limit: usize },
    /// Raised by the pool, never by a block rule: what a block may carry is
    /// not priced, what a node will carry for a stranger is.
    #[error("transfer pays {fee}, below the {floor} its bytes and new notes ask")]
    FeeBelowFloor { fee: Amount, floor: Amount },
    #[error("note {0:?} is spent twice in the same transfer")]
    DuplicateInput(NoteId),
    #[error("note {0:?} is unknown or already spent")]
    UnknownNote(NoteId),
    #[error("note {note_id:?} is still in the hot set, so it takes no proof")]
    UnexpectedProof { note_id: NoteId },
    #[error(
        "note {note_id:?} is not in the hot set: either it fell and spending it \
         needs a proof, or it never existed. A node cannot tell the two apart, \
         because it holds neither the cold set nor a record of what was never in it"
    )]
    MissingProof { note_id: NoteId },
    #[error("the proof for note {note_id:?} does not match the cold commitment")]
    InvalidProof { note_id: NoteId },
    #[error(
        "note {note_id:?} was paid by a coinbase and cannot be spent before height \
         {matures_at}, because until then the block that paid it can still be undone"
    )]
    ImmatureCoinbase { note_id: NoteId, matures_at: u64 },
    #[error("output {index} carries no value")]
    ZeroValueOutput { index: usize },
    #[error("summing values overflowed the monetary ceiling")]
    ValueOverflow,
    #[error("transfer creates {requested} from {available}")]
    OutputsExceedInputs {
        available: Amount,
        requested: Amount,
    },
    #[error("signature on input {input_index} does not verify")]
    InvalidSignature { input_index: usize },
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error(
        "the rules at height {height} are block version {required}, and this software \
         knows only version {known}: it is too old to follow this chain"
    )]
    SoftwareTooOld {
        height: u64,
        required: u16,
        known: u16,
    },
    #[error("block version {0} is not supported")]
    UnsupportedVersion(u16),
    #[error(
        "the rules at height {height} are block version {required}, and this block \
         carries version {found}"
    )]
    WrongVersion {
        height: u64,
        found: u16,
        required: u16,
    },
    #[error("coinbase version {0} is not supported")]
    UnsupportedCoinbaseVersion(u16),
    #[error("block belongs to network {found}, this node follows {expected}")]
    WrongNetwork {
        expected: NetworkId,
        found: NetworkId,
    },
    #[error("expected height {expected}, block claims {found}")]
    WrongHeight { expected: u64, found: u64 },
    #[error("expected parent {expected}, block claims {found}")]
    WrongParent { expected: Hash32, found: Hash32 },
    #[error("the chain has reached the maximum representable height")]
    HeightOverflow,
    #[error("header is at height {header}, coinbase claims {coinbase}")]
    CoinbaseHeightMismatch { header: u64, coinbase: u64 },
    #[error("block carries {count} transfers, limit is {limit}")]
    TooManyTransfers { count: usize, limit: usize },
    #[error("block pushes {count} notes to the cold set, limit is {limit}")]
    TooManyEvictions { count: usize, limit: usize },
    #[error("block takes {bytes} bytes, limit is {limit}")]
    BlockTooLarge { bytes: usize, limit: usize },
    #[error("coinbase creates {count} notes, limit is {limit}")]
    TooManyCoinbaseOutputs { count: usize, limit: usize },
    #[error("coinbase output {index} carries no value")]
    ZeroValueCoinbaseOutput { index: usize },
    #[error("coinbase carries {size} extra bytes, limit is {MAX_COINBASE_EXTRA}")]
    CoinbaseExtraTooLarge { size: usize },
    #[error("coinbase claims {claimed}, only {allowed} is available")]
    CoinbaseOverpay { allowed: Amount, claimed: Amount },
    #[error("summing values overflowed the monetary ceiling")]
    ValueOverflow,
    /// The issued total cannot be moved the way this block moves it.
    ///
    /// Either the chain would have issued more money than an amount can hold,
    /// or this block destroys more in fees than the chain has ever issued. The
    /// second cannot happen to a ledger that adds up, which is why it is worth
    /// asking: the whole reason for keeping the total is to have somewhere a
    /// pebble from nowhere can show up as a number rather than as a state
    /// every node agrees on.
    #[error(
        "this block issues {minted} against {fees} in fees, which the total {supply} cannot take"
    )]
    SupplyDoesNotAddUp {
        supply: Amount,
        minted: Amount,
        fees: Amount,
    },
    #[error("timestamp {timestamp} is more than {drift} seconds ahead of this node")]
    TimestampTooFarAhead { timestamp: u64, drift: u64 },
    #[error("timestamp {found} is not past the median {median} of recent blocks")]
    TimestampNotAfterMedian { median: u64, found: u64 },
    #[error("block is dated {found}, before this network opened at {opens_at}")]
    BeforeTheNetworkOpened { opens_at: u64, found: u64 },
    #[error("this network starts at {expected}, block claims to start at {found}")]
    WrongGenesis { expected: Hash32, found: Hash32 },
    #[error("block claims difficulty {found}, the chain demands {expected}")]
    WrongDifficulty { expected: u64, found: u64 },
    #[error("block identifier does not meet the target for difficulty {difficulty}")]
    InsufficientWork { difficulty: u64 },
    #[error("header commits to transaction root {found}, body produces {expected}")]
    TransactionsRootMismatch { expected: Hash32, found: Hash32 },
    #[error("header commits to state root {found}, the block produces {expected}")]
    StateRootMismatch { expected: Hash32, found: Hash32 },
    /// The block cannot be applied to the set it was checked against.
    ///
    /// A note it spends is not where its proof said, so taking it out would
    /// take nothing out. The checks before this one already refuse that, so
    /// reaching here means this node disagrees with itself; it is not a thing
    /// a peer can cause, and it is refused rather than carried past.
    #[error("a note this block spends is not where its proof places it")]
    NoteNotWhereProved,
    #[error("header commits to history {found}, this chain's headers produce {expected}")]
    HistoryMismatch { expected: Hash32, found: Hash32 },
    #[error("header claims {found} total work, its parent and difficulty give {expected}")]
    WrongTotalWork { expected: u128, found: u128 },
    #[error("accumulated work would overflow")]
    WorkOverflow,
    #[error("transfer {index} is invalid")]
    InvalidTransfer {
        index: usize,
        #[source]
        source: TransferError,
    },
}

/// What a valid transfer contributes to the block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferOutcome {
    pub fee: Amount,
    pub spent_hot: Vec<NoteId>,
    pub spent_cold: Vec<ColdSpend>,
}

/// A signature found while validating, waiting to be checked.
///
/// Collected rather than checked where it is found, so that a whole block's
/// signatures are checked in one place, and a full block's worth is enough
/// work to be worth splitting across the cores the machine already has.
///
/// The position is carried so a failure names the same input the one-at-a-time
/// check would have named. Which of two bad signatures is reported changes
/// nothing any node agrees on, but a validator that names a different one on
/// every run is one nobody can debug.
struct Pending {
    owner: PublicKey,
    message: Hash32,
    signature: Signature,
    transfer: usize,
    input: usize,
}

impl Pending {
    fn holds(&self) -> bool {
        self.owner
            .verify(self.message.as_bytes(), &self.signature)
            .is_ok()
    }
}

/// Signatures below which splitting the work costs more than it saves.
const SPLIT_ABOVE: usize = 64;

/// Threads worth asking for. A validator is not the only thing on the machine.
const MOST_THREADS: usize = 8;

/// The one validation reached first, of two that do not hold.
fn earlier<'a>(held: Option<&'a Pending>, found: &'a Pending) -> &'a Pending {
    match held {
        Some(held) if (held.transfer, held.input) <= (found.transfer, found.input) => held,
        _ => found,
    }
}

/// Checks every signature collected, and names the first that does not hold.
///
/// First in the order validation reached them, whichever thread got there.
/// The check itself is pure (the same key, message and signature give the
/// same answer anywhere), so splitting it changes how long a block takes and
/// nothing about whether it is valid.
fn first_failure(pending: &[Pending]) -> Option<&Pending> {
    if pending.len() < SPLIT_ABOVE {
        return pending.iter().find(|found| !found.holds());
    }

    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .clamp(1, MOST_THREADS);
    let each = pending.len().div_ceil(threads).max(1);

    std::thread::scope(|scope| {
        let mut running = Vec::new();
        let mut worst: Option<&Pending> = None;
        for slice in pending.chunks(each) {
            // Asked for rather than taken. `Scope::spawn` panics when the
            // machine will not make a thread, and this is on the path that
            // decides whether a block is valid: a node that cannot have a
            // second thread would have stopped checking blocks altogether,
            // which is the one job it has, over a saving that is only ever
            // about how long the checking takes. Refused, the slice is checked
            // here instead, and the answer is the same answer.
            match std::thread::Builder::new()
                .name("cairn-verify".to_owned())
                .spawn_scoped(scope, move || slice.iter().find(|found| !found.holds()))
            {
                Ok(handle) => running.push(handle),
                Err(_) => {
                    if let Some(found) = slice.iter().find(|found| !found.holds()) {
                        worst = Some(earlier(worst, found));
                    }
                }
            }
        }

        for handle in running {
            // A thread that died took its answer with it, and the answer it
            // was carrying may have been "this block is invalid". Refusing the
            // block is the only safe reading of that, so the first signature
            // stands in for one that could not be checked.
            let Ok(found) = handle.join() else {
                return pending.first();
            };
            if let Some(found) = found {
                worst = Some(earlier(worst, found));
            }
        }
        worst
    })
}

/// Checks everything about a transfer that does not require the note set.
pub fn check_transfer_shape(
    transfer: &Transfer,
    params: &ConsensusParams,
) -> Result<(), TransferError> {
    if transfer.version != TRANSFER_VERSION {
        return Err(TransferError::UnsupportedVersion(transfer.version));
    }
    if transfer.inputs.is_empty() {
        return Err(TransferError::NoInputs);
    }
    if transfer.outputs.is_empty() {
        return Err(TransferError::NoOutputs);
    }
    if transfer.inputs.len() > params.max_inputs_per_transfer {
        return Err(TransferError::TooManyInputs {
            count: transfer.inputs.len(),
            limit: params.max_inputs_per_transfer,
        });
    }
    if transfer.outputs.len() > params.max_outputs_per_transfer {
        return Err(TransferError::TooManyOutputs {
            count: transfer.outputs.len(),
            limit: params.max_outputs_per_transfer,
        });
    }

    let mut seen = BTreeSet::new();
    for input in &transfer.inputs {
        if !seen.insert(input.note_id) {
            return Err(TransferError::DuplicateInput(input.note_id));
        }
    }

    // A note carrying no value costs permanent state and moves nothing. State
    // is the scarce resource in this design, so it is never free to consume.
    for (index, output) in transfer.outputs.iter().enumerate() {
        if output.value == Amount::ZERO {
            return Err(TransferError::ZeroValueOutput { index });
        }
    }

    transfer
        .total_output()
        .ok_or(TransferError::ValueOverflow)?;
    Ok(())
}

/// Finds the note an input spends, and what it takes to put it back.
///
/// The tier is not the spender's choice: a note is cold exactly when the hot
/// set does not hold it. A witness of the wrong kind is rejected rather than
/// ignored, so one spend has one encoding.
///
/// Cold proofs are checked against the commitment as it stood before the
/// block. Checking them against one that moves as the block is applied would
/// make a transfer's validity depend on where it sits in the block.
///
/// Maturity is asked first, and it is asked of the note's source rather than
/// of the note. Every note carries the identifier of the transaction that made
/// it, so an immature coinbase is recognised before anything has been said
/// about which tier its notes are in. That matters more than it looks: a hot
/// note carries the height it was made at and a cold note does not, so a rule
/// written against the tiers would have covered one and not the other, and
/// letting a note fall would have been a way to launder it. This asks a
/// question neither tier can answer differently.
///
/// The height it is asked at is read off the state rather than passed in. The
/// block a transfer can go into is the one after the tip and nothing else, so
/// there is nothing here for a caller to decide and no way for two callers to
/// decide it differently. That is not the reasoning that keeps the clock out
/// of this module: a clock is not in the state, and this is.
fn resolve_input(
    state: &LedgerState,
    input: &Input,
    spent_hot: &BTreeSet<NoteId>,
    spent_cold: &BTreeMap<NoteId, ColdSpend>,
) -> Result<(Note, Option<ColdSpend>), TransferError> {
    let id = input.note_id;
    if spent_hot.contains(&id) || spent_cold.contains_key(&id) {
        return Err(TransferError::UnknownNote(id));
    }
    if let Some(matures_at) = state.coinbase_matures_at(&id.source) {
        // A chain that has run out of heights has no next block to put this
        // in, and every coinbase still waiting matures above zero, so falling
        // back to zero refuses rather than waves through.
        if state.next_height().unwrap_or(0) < matures_at {
            return Err(TransferError::ImmatureCoinbase {
                note_id: id,
                matures_at,
            });
        }
    }

    match (state.hot_note(&id), &input.witness) {
        (Some(note), Witness::Hot) => Ok((note, None)),
        (Some(_), Witness::Cold(_)) => Err(TransferError::UnexpectedProof { note_id: id }),
        // A note that fell moments ago is still held by every node, along with
        // its proof, so spending it takes nothing extra from whoever wrote the
        // transfer. Without this the line between the tiers would be a cliff,
        // and a transfer would lose whenever a block landed while it was being
        // written.
        (None, Witness::Hot) => match state.within_grace(&id) {
            None => Err(TransferError::MissingProof { note_id: id }),
            Some((position, note)) => {
                let proof = state
                    .cold()
                    .proof_of(position)
                    .ok_or(TransferError::MissingProof { note_id: id })?;
                // Still checked: a note that fell within the window and has
                // since been spent is no longer there to find.
                if !state.cold().verify(position, cold_leaf(&id, &note), &proof) {
                    return Err(TransferError::UnknownNote(id));
                }
                let spend = ColdSpend {
                    id,
                    position,
                    note,
                    proof,
                };
                Ok((note, Some(spend)))
            }
        },
        (None, Witness::Cold(cold)) => {
            let leaf = cold_leaf(&id, &cold.note);
            if !state.cold().verify(cold.position, leaf, &cold.proof) {
                return Err(TransferError::InvalidProof { note_id: id });
            }
            let spend = ColdSpend {
                id,
                position: cold.position,
                note: cold.note,
                proof: cold.proof.clone(),
            };
            Ok((cold.note, Some(spend)))
        }
    }
}

/// Fully validates a transfer against the note set.
pub fn check_transfer(
    transfer: &Transfer,
    state: &LedgerState,
    spent_hot: &BTreeSet<NoteId>,
    spent_cold: &BTreeMap<NoteId, ColdSpend>,
    params: &ConsensusParams,
) -> Result<TransferOutcome, TransferError> {
    let mut pending = Vec::new();
    let outcome = resolve_transfer(
        transfer,
        0,
        state,
        spent_hot,
        spent_cold,
        params,
        Some(&mut pending),
    )?;
    if let Some(failed) = first_failure(&pending) {
        return Err(TransferError::InvalidSignature {
            input_index: failed.input,
        });
    }
    Ok(outcome)
}

/// Everything [`check_transfer`] decides except the signatures.
///
/// Only for a transfer whose signatures this node has already checked and
/// which it is asking about again because the chain moved. Anything arriving
/// from anywhere goes through [`check_transfer`].
///
/// What a signature covers is the network, the version, the transfer's own
/// identifier, the position of the input, and the value and owner of the note
/// being spent. Every one of those is settled by the transfer and by the
/// identifier of the note it names: a note identifier is the identifier of the
/// transaction that made the note together with a position in it, and that
/// identifier commits to the note. So the message a signature covers cannot be
/// moved by the chain, and one that held once holds for as long as the transfer
/// names the same notes.
///
/// What the chain does move is everything else: whether a note is still there,
/// whether it has been spent, which of the two sets it sits in, and what the
/// transfer is therefore worth. That is what this asks, and it is what a pool
/// has to ask again each time the branch it follows does.
///
/// The saving is not only the signature checks. Building the message costs an
/// encoding of the whole body and a hash of it, once, plus a hash an input, and
/// none of that is built here either.
pub fn check_transfer_again(
    transfer: &Transfer,
    state: &LedgerState,
    spent_hot: &BTreeSet<NoteId>,
    spent_cold: &BTreeMap<NoteId, ColdSpend>,
    params: &ConsensusParams,
) -> Result<TransferOutcome, TransferError> {
    resolve_transfer(transfer, 0, state, spent_hot, spent_cold, params, None)
}

/// The same, with the signatures written down instead of checked.
///
/// Everything else is decided here: the shape, where each note is, that it is
/// not already spent, and what it is worth. What is left over is the one part
/// that needs no state at all, and a block's worth of it is enough work to be
/// worth doing in one go.
fn resolve_transfer(
    transfer: &Transfer,
    position_in_block: usize,
    state: &LedgerState,
    spent_hot: &BTreeSet<NoteId>,
    spent_cold: &BTreeMap<NoteId, ColdSpend>,
    params: &ConsensusParams,
    mut pending: Option<&mut Vec<Pending>>,
) -> Result<TransferOutcome, TransferError> {
    check_transfer_shape(transfer, params)?;

    // Once, ahead of the loop, because it is the same value at every input and
    // it costs an encoding of the whole body and a hash of it. Asked for
    // inside the loop it made a transfer cost the square of its own size: a
    // full one was five megabytes hashed for thirty six kilobytes received,
    // and every byte of that was spent before the first signature was looked
    // at, so a transfer whose first signature is nonsense cost all of it.
    //
    // Not built at all when nobody is going to check a signature, which is a
    // transfer this node has already checked and is resolving again because
    // the state moved. That is the one cost here the state cannot change.
    let signing = pending.is_some().then(|| transfer.signing(params.network));

    let mut available = Amount::ZERO;
    let mut from_hot = Vec::new();
    let mut from_cold = Vec::new();

    for (index, input) in transfer.inputs.iter().enumerate() {
        let (spent, fallen) = resolve_input(state, input, spent_hot, spent_cold)?;

        let position = u32::try_from(index).unwrap_or(u32::MAX);
        if let (Some(collected), Some(signing)) = (pending.as_deref_mut(), signing.as_ref()) {
            collected.push(Pending {
                owner: spent.owner,
                message: signing.message(position, &spent),
                signature: input.signature,
                transfer: position_in_block,
                input: index,
            });
        }

        available = available
            .checked_add(spent.value)
            .ok_or(TransferError::ValueOverflow)?;
        match fallen {
            None => from_hot.push(input.note_id),
            Some(from_the_cold_set) => from_cold.push(from_the_cold_set),
        }
    }

    let requested = transfer
        .total_output()
        .ok_or(TransferError::ValueOverflow)?;
    let fee = available
        .checked_sub(requested)
        .ok_or(TransferError::OutputsExceedInputs {
            available,
            requested,
        })?;

    Ok(TransferOutcome {
        fee,
        spent_hot: from_hot,
        spent_cold: from_cold,
    })
}

/// What applying a block body does to the state, computed without mutation.
#[derive(Clone, Debug)]
pub struct BlockEffect {
    pub transition: StateTransition,
    pub total_fees: Amount,
    pub state_root: Hash32,
}

fn check_coinbase_shape(
    coinbase: &CoinbaseTransaction,
    params: &ConsensusParams,
) -> Result<(), BlockError> {
    if coinbase.version != COINBASE_VERSION {
        return Err(BlockError::UnsupportedCoinbaseVersion(coinbase.version));
    }
    if coinbase.extra.len() > MAX_COINBASE_EXTRA {
        return Err(BlockError::CoinbaseExtraTooLarge {
            size: coinbase.extra.len(),
        });
    }
    if coinbase.outputs.len() > params.max_coinbase_outputs {
        return Err(BlockError::TooManyCoinbaseOutputs {
            count: coinbase.outputs.len(),
            limit: params.max_coinbase_outputs,
        });
    }
    for (index, output) in coinbase.outputs.iter().enumerate() {
        if output.value == Amount::ZERO {
            return Err(BlockError::ZeroValueCoinbaseOutput { index });
        }
    }
    Ok(())
}

/// Validates a block body against `state` and reports its effect.
pub fn evaluate_block_body(
    state: &LedgerState,
    coinbase: &CoinbaseTransaction,
    transfers: &[Transfer],
    params: &ConsensusParams,
) -> Result<BlockEffect, BlockError> {
    check_coinbase_shape(coinbase, params)?;

    if transfers.len() > params.max_transfers_per_block {
        return Err(BlockError::TooManyTransfers {
            count: transfers.len(),
            limit: params.max_transfers_per_block,
        });
    }

    let height = state.next_height().ok_or(BlockError::HeightOverflow)?;
    let mut spent_hot: BTreeSet<NoteId> = BTreeSet::new();
    let mut spent_cold: BTreeMap<NoteId, ColdSpend> = BTreeMap::new();
    let mut created: Vec<(NoteId, Note)> = Vec::new();
    let mut total_fees = Amount::ZERO;

    // Collected across the whole block and checked once below, rather than one
    // at a time here. A full block carries over a thousand of them, every one
    // an elliptic curve verification, and that is the bulk of what the chain
    // lock is held for while a block is judged.
    let mut pending: Vec<Pending> = Vec::new();

    for (index, transfer) in transfers.iter().enumerate() {
        let outcome = resolve_transfer(
            transfer,
            index,
            state,
            &spent_hot,
            &spent_cold,
            params,
            Some(&mut pending),
        )
        .map_err(|source| BlockError::InvalidTransfer { index, source })?;

        spent_hot.extend(outcome.spent_hot);
        spent_cold.extend(
            outcome
                .spent_cold
                .into_iter()
                .map(|spend| (spend.id, spend)),
        );
        created.extend(transfer.created_notes());
        total_fees = total_fees
            .checked_add(outcome.fee)
            .ok_or(BlockError::ValueOverflow)?;
    }

    if let Some(failed) = first_failure(&pending) {
        return Err(BlockError::InvalidTransfer {
            index: failed.transfer,
            source: TransferError::InvalidSignature {
                input_index: failed.input,
            },
        });
    }

    // What the schedule pays at this height, plus what the transfers paid to
    // be carried.
    let allowed = params
        .reward_at(height)
        .checked_add(total_fees)
        .ok_or(BlockError::ValueOverflow)?;
    let claimed = coinbase.total_output().ok_or(BlockError::ValueOverflow)?;
    if claimed > allowed {
        return Err(BlockError::CoinbaseOverpay { allowed, claimed });
    }
    created.extend(coinbase.created_notes());

    let evicted = state.plan_evictions(&spent_hot, &created, params.hot_capacity);
    // Falling is what a full tier does to make room, so how many fall is
    // decided by what the block creates, and a block can be stuffed with
    // outputs for exactly that purpose. Fees put a price on it; this puts a
    // ceiling on it, because a miner pays no fee to itself.
    if evicted.len() > params.max_evictions_per_block {
        return Err(BlockError::TooManyEvictions {
            count: evicted.len(),
            limit: params.max_evictions_per_block,
        });
    }
    // The coinbase enters the maturity window by its own identifier, because
    // that is what every note it paid carries as the source half of its own.
    // One entry covers however many notes it paid, and a coinbase that paid
    // nobody takes no place at all: there is nothing waiting.
    let waiting = if coinbase.outputs.is_empty() {
        None
    } else {
        // A height whose maturity cannot be counted to is one no chain
        // reaches, and nothing above it could spend anything anyway.
        height
            .checked_add(params.coinbase_maturity)
            .map(|matures_at| (matures_at, coinbase.id()))
    };
    let transition = StateTransition {
        spent_hot: spent_hot.into_iter().collect(),
        spent_cold: spent_cold.into_values().collect(),
        created,
        evicted,
        coinbase: waiting,
        minted: claimed,
        fees: total_fees,
    };
    // Asked before the projection, so that a total that cannot be moved is
    // reported as what it is rather than as a block that produces no root.
    if state.supply_after(&transition).is_none() {
        return Err(BlockError::SupplyDoesNotAddUp {
            supply: state.supply(),
            minted: claimed,
            fees: total_fees,
        });
    }
    // A projection that cannot be made is a block that cannot be applied. It
    // means a note this block spends is not where its proof said, which the
    // checks above already refused, so reaching here is this node disagreeing
    // with itself, and the only safe answer is to refuse the block rather than
    // to carry on with a root that does not describe anything.
    let state_root = state
        .project(&transition, height)
        .ok_or(BlockError::NoteNotWhereProved)?;

    Ok(BlockEffect {
        transition,
        total_fees,
        state_root,
    })
}

/// The difficulty the next block must carry.
pub fn expected_difficulty(state: &LedgerState, params: &ConsensusParams) -> u64 {
    let recent = state.recent_headers();
    if recent.is_empty() {
        params.genesis_difficulty.max(MIN_DIFFICULTY)
    } else {
        next_difficulty(recent, params.target_block_time)
    }
}

/// Searches for a nonce that satisfies the block's difficulty.
///
/// Deliberately the naive loop. A real miner runs it across cores and rolls the
/// coinbase extra nonce once the nonce space is exhausted, but neither changes
/// what makes a block valid. Returns `None` if no nonce below `attempts` works.
pub fn mine_block(mut block: Block, attempts: u64) -> Option<Block> {
    for nonce in 0..attempts {
        block.header.nonce = nonce;
        if meets_target(&block.header.id(), block.header.difficulty) {
            return Some(block);
        }
    }
    None
}

/// Builds the block a producer would publish, with both roots filled in.
pub fn assemble_block(
    state: &LedgerState,
    coinbase: CoinbaseTransaction,
    transfers: Vec<Transfer>,
    params: &ConsensusParams,
    timestamp: u64,
    nonce: u64,
) -> Result<Block, BlockError> {
    let height = state.next_height().ok_or(BlockError::HeightOverflow)?;
    if coinbase.height != height {
        return Err(BlockError::CoinbaseHeightMismatch {
            header: height,
            coinbase: coinbase.height,
        });
    }

    let effect = evaluate_block_body(state, &coinbase, &transfers, params)?;
    let difficulty = expected_difficulty(state, params);
    let version = params.version_at(height);
    if version > BLOCK_VERSION {
        return Err(BlockError::SoftwareTooOld {
            height,
            required: version,
            known: BLOCK_VERSION,
        });
    }

    let header = BlockHeader {
        version,
        network: params.network,
        height,
        previous: state.expected_parent(),
        transactions_root: Hash32::ZERO,
        state_root: effect.state_root,
        history: state.history_root(),
        timestamp,
        difficulty,
        total_work: state
            .total_work()
            .checked_add(work_of(difficulty))
            .ok_or(BlockError::WorkOverflow)?,
        nonce,
    };
    let mut block = Block {
        header,
        coinbase,
        transfers,
    };
    block.header.transactions_root = block.transactions_root();
    Ok(block)
}

/// A block that was applied, and what it takes to apply or undo it again.
#[derive(Clone, Debug)]
pub struct ConnectedBlock {
    pub transition: StateTransition,
    pub undo: BlockUndo,
    pub total_fees: Amount,
}

/// Checks everything about a header that does not need the block body.
///
/// Split out from [`connect_block`] so that each half stays short enough to
/// hold in one reading, which matters more here than anywhere else in the
/// codebase: every line of it is a rule two nodes must agree on exactly.
fn check_header(
    state: &LedgerState,
    header: &BlockHeader,
    params: &ConsensusParams,
) -> Result<(), BlockError> {
    if header.network != params.network {
        return Err(BlockError::WrongNetwork {
            expected: params.network,
            found: header.network,
        });
    }

    // Nothing may predate the moment the network opened, which is what makes
    // the opening the same for everyone rather than for whoever knew first.
    if header.timestamp < params.opens_at {
        return Err(BlockError::BeforeTheNetworkOpened {
            opens_at: params.opens_at,
            found: header.timestamp,
        });
    }

    let expected_height = state.next_height().ok_or(BlockError::HeightOverflow)?;

    // Which rules judge this block is decided by where it sits, and where it
    // sits is decided by the state rather than by what the block says about
    // itself: its own claim about its height is checked further down, and a
    // block that lied about it would otherwise pick the rules it is judged by.
    let required = params.version_at(expected_height);
    if required > BLOCK_VERSION {
        // Not a bad block. A height whose rules this software does not have,
        // which is this software's problem and nobody else's.
        return Err(BlockError::SoftwareTooOld {
            height: expected_height,
            required,
            known: BLOCK_VERSION,
        });
    }
    if header.version > BLOCK_VERSION {
        // A version above anything this build knows is not a judgement about
        // the block, and it is not one this layer can make.
        //
        // Two wrong answers were tried here and both are worth writing down.
        // The first was to say nothing special: the refusal was remembered
        // against the block for good and the peer was banned for offering it,
        // so an un-updated node condemned the real chain and every honest
        // messenger, which is the opposite of what the machinery exists for.
        // The second was to answer that this node is too old, which stops it:
        // that made stopping a node something a stranger could ask for by
        // writing a number in a field, and on a chain at the difficulty floor
        // it costs nothing to ask.
        //
        // So the answer is the honest one, that this build cannot judge the
        // block, and it is no longer remembered, because it is a judgement
        // about the reader and an update reverses it. Deciding that a run of
        // these means the chain has moved rather than that somebody is
        // talking nonsense needs evidence from more than one block and more
        // than one peer, and that belongs where peers are counted.
        return Err(BlockError::UnsupportedVersion(header.version));
    }
    if header.version != required {
        // The other half, and the opposite answer. This build knows the
        // version the block carries and knows the rules where it sits, so it
        // can say the block is wrong rather than that it cannot tell. Both
        // used to come back as "cannot tell", which was wrong twice over: a
        // block from the abandoned side of a rule change was let through the
        // door meant for blocks nobody can judge yet, and a stranger could
        // make any node report itself out of date by writing a number in a
        // field, on a chain at the difficulty floor, for the price of one
        // hash.
        //
        // Remembered against the block, because this verdict is about the
        // block and no update reverses it. Not held against the peer: on the
        // day a rule changes, every node that has not updated sends these in
        // good faith, and they belong elsewhere rather than behaving badly.
        return Err(BlockError::WrongVersion {
            height: expected_height,
            found: header.version,
            required,
        });
    }

    if expected_height == 0 {
        if let Some(expected) = params.genesis {
            let found = header.id();
            if found != expected {
                return Err(BlockError::WrongGenesis { expected, found });
            }
        }
    }
    if header.height != expected_height {
        return Err(BlockError::WrongHeight {
            expected: expected_height,
            found: header.height,
        });
    }

    let expected_parent = state.expected_parent();
    if header.previous != expected_parent {
        return Err(BlockError::WrongParent {
            expected: expected_parent,
            found: header.previous,
        });
    }

    let demanded = expected_difficulty(state, params);
    if header.difficulty != demanded {
        return Err(BlockError::WrongDifficulty {
            expected: demanded,
            found: header.difficulty,
        });
    }

    check_header_commitments(state, header)
}

/// The two fields a newcomer relies on, and nothing else does.
fn check_header_commitments(state: &LedgerState, header: &BlockHeader) -> Result<(), BlockError> {
    // Both are one comparison, and both are what makes a header worth sampling
    // later. A header that misstates the work behind it, or the history it
    // follows, would let someone hand a newcomer a short chain wearing a long
    // one's numbers.
    let demanded_work = state
        .total_work()
        .checked_add(work_of(header.difficulty))
        .ok_or(BlockError::WorkOverflow)?;
    if header.total_work != demanded_work {
        return Err(BlockError::WrongTotalWork {
            expected: demanded_work,
            found: header.total_work,
        });
    }
    let demanded_history = state.history_root();
    if header.history != demanded_history {
        return Err(BlockError::HistoryMismatch {
            expected: demanded_history,
            found: header.history,
        });
    }
    Ok(())
}

/// Validates `block` against `state` and, if it holds, applies it.
///
/// `now` is the receiving node's clock, in seconds since the Unix epoch. On
/// failure the state is left untouched. Keep the returned value: undoing this
/// block later needs it.
pub fn connect_block(
    state: &mut LedgerState,
    block: &Block,
    params: &ConsensusParams,
    now: u64,
) -> Result<ConnectedBlock, BlockError> {
    let header = &block.header;
    check_header(state, header, params)?;

    // Cheap and decisive, so it runs before the body is looked at: a block
    // without work behind it costs an attacker nothing to send.
    if !meets_target(&header.id(), header.difficulty) {
        return Err(BlockError::InsufficientWork {
            difficulty: header.difficulty,
        });
    }

    // What a peer has to carry, a node has to hold while it validates, and a
    // disk has to keep. Checked once here, on the encoding a node received
    // rather than on a count of parts, because bytes are what the limit is
    // about and counting parts is how the two drifted apart.
    let bytes = block.encode().len();
    if bytes > params.max_block_bytes {
        return Err(BlockError::BlockTooLarge {
            bytes,
            limit: params.max_block_bytes,
        });
    }

    if header.timestamp > now.saturating_add(params.max_timestamp_drift) {
        return Err(BlockError::TimestampTooFarAhead {
            timestamp: header.timestamp,
            drift: params.max_timestamp_drift,
        });
    }
    // Measured against the median of recent blocks rather than the parent. A
    // miner writes its own timestamp, but it holds one vote in a median, so
    // backdating a block to claim an easier difficulty stops working.
    if let Some(median) = median_time_past(state.recent_headers()) {
        if header.timestamp <= median {
            return Err(BlockError::TimestampNotAfterMedian {
                median,
                found: header.timestamp,
            });
        }
    }

    if block.coinbase.height != header.height {
        return Err(BlockError::CoinbaseHeightMismatch {
            header: header.height,
            coinbase: block.coinbase.height,
        });
    }

    let computed_transactions_root = block.transactions_root();
    if header.transactions_root != computed_transactions_root {
        return Err(BlockError::TransactionsRootMismatch {
            expected: computed_transactions_root,
            found: header.transactions_root,
        });
    }

    let effect = evaluate_block_body(state, &block.coinbase, &block.transfers, params)?;
    if header.state_root != effect.state_root {
        return Err(BlockError::StateRootMismatch {
            expected: effect.state_root,
            found: header.state_root,
        });
    }

    // A refusal here is the node disagreeing with itself: this transition
    // projected against this same state a moment ago, and the root that came
    // out is the one checked just above. Nothing is applied when it happens,
    // so the block is refused like any other rather than the tip being
    // advanced over a state that is half a block old.
    let undo = state
        .commit(header, &effect.transition)
        .ok_or(BlockError::NoteNotWhereProved)?;
    Ok(ConnectedBlock {
        transition: effect.transition,
        undo,
        total_fees: effect.total_fees,
    })
}

/// Takes the tip block back out of the state.
///
/// `connected` has to be what [`connect_block`] returned for the block that is
/// currently the tip. Undoing anything else corrupts the state silently, which
/// is why the two travel together.
pub fn disconnect_block(state: &mut LedgerState, connected: &ConnectedBlock) {
    state.revert(&connected.transition, &connected.undo);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use cairn_crypto::SecretKey;

    /// A named network carries its own identity, and not the default's.
    ///
    /// The three fields that say which chain a node is on are written one
    /// arm at a time beside a `..Self::testnet()`, so a field dropped from an
    /// arm is not a compile error: it silently takes the default, which
    /// carries the unnamed network's number, no pinned first block and an
    /// opening moment of nought. `cargo mutants` dropped each of them in turn
    /// and the suite stayed green. A node started with `--network testnet-6`
    /// would then follow another network's number, take whatever first block
    /// it was handed, and accept blocks dated before the network opened.
    #[test]
    fn a_named_network_carries_its_own_identity() {
        let unnamed = ConsensusParams::testnet();
        for (name, id) in [
            ("testnet", NetworkId::TESTNET_6),
            ("testnet-6", NetworkId::TESTNET_6),
            ("devnet", NetworkId::DEVNET),
        ] {
            let params = ConsensusParams::for_network(name).expect("a network this build ships");
            // The number rather than the alias: `NetworkId::TESTNET` is
            // whichever test network is current, so an arm that took the
            // default would be right today and wrong on the day the alias
            // moves, which is the day a wrong number costs a chain.
            assert_eq!(params.network, id, "{name} is not on its own number");
            assert_eq!(
                params.genesis,
                crate::genesis::pinned(id),
                "{name} does not pin its own first block"
            );
            assert_eq!(
                params.genesis.is_some(),
                crate::genesis::block(id).is_some(),
                "{name} pins its first block exactly when it ships one"
            );
            assert_eq!(
                params.opens_at,
                crate::genesis::opens_at(id),
                "{name} does not open when its first block is dated"
            );
            assert_eq!(
                params.opens_at > unnamed.opens_at,
                crate::genesis::block(id).is_some(),
                "{name} opens when its first block is dated, and the unnamed \
                 network opens at nought"
            );
        }
        assert!(
            ConsensusParams::for_network("mainnet").is_none(),
            "a network exists once its first block does"
        );
        assert!(ConsensusParams::for_network("nowhere").is_none());
    }

    /// A schedule has to start at height zero and rise in both columns.
    ///
    /// The shipped schedules are put through this at build time, and that is
    /// all that ever ran it: a build-time assertion over correct input passes
    /// whatever the function says, so `cargo mutants` could replace the whole
    /// of it with `true`, and turn either comparison around, with nothing
    /// noticing. What it guards is a chain split produced by an ordinary edit,
    /// which is the one kind of break no attacker has to arrange.
    #[test]
    fn a_schedule_starts_at_zero_and_rises_in_both_columns() {
        let at = |height: u64, version: u16| Activation { height, version };

        assert!(
            schedule_is_sound(&[at(0, 1)]),
            "one opening rule is a schedule"
        );
        assert!(schedule_is_sound(&[at(0, 1), at(5, 2), at(9, 3)]));
        assert!(schedule_is_sound(OPENED), "and the one this build ships");

        assert!(!schedule_is_sound(&[]), "a schedule with no opening rule");
        assert!(
            !schedule_is_sound(&[at(1, 1)]),
            "a schedule that starts above the first block leaves it unruled"
        );
        assert!(
            !schedule_is_sound(&[at(0, 1), at(0, 2)]),
            "two rules at one height are two answers to one question"
        );
        assert!(
            !schedule_is_sound(&[at(0, 1), at(5, 2), at(4, 3)]),
            "heights that fall put a rule before the one it follows"
        );
        assert!(
            !schedule_is_sound(&[at(0, 2), at(5, 2)]),
            "a version that does not rise is an activation that activates nothing"
        );
        assert!(
            !schedule_is_sound(&[at(0, 2), at(5, 1)]),
            "a version that falls asks a build to forget rules it has"
        );
    }

    /// The schedule says when a build runs out, and both edges of that.
    ///
    /// `leaves_behind` is read by `cairnd` to tell an operator how long this
    /// build has. It was tested there and only there, so `cargo mutants`
    /// turned its `>` into `<` and into `>=` and this crate's own suite stayed
    /// green both times: a function whose behaviour only a dependent holds is
    /// a function relying on who happens to be built beside it, which is how
    /// the one guard on the hash counter came to live under another crate's
    /// feature flag.
    ///
    /// Both edges matter and they fail differently. Too eager and a build
    /// level with its schedule announces a deadline it does not have, which
    /// teaches an operator to ignore the line. Too slow and a build one
    /// version short says nothing at all, which is the whole defect this
    /// exists to close.
    #[test]
    fn the_schedule_says_when_a_build_runs_out_and_not_before() {
        const OPENS: Activation = Activation {
            height: 0,
            version: 3,
        };
        const CHANGES: Activation = Activation {
            height: 9_000,
            version: 4,
        };

        let mut rules = ConsensusParams::testnet();
        rules.activations = &[OPENS, CHANGES];

        // A build that has the later rules is not behind anything.
        assert_eq!(
            rules.leaves_behind(4),
            None,
            "a build level with the schedule"
        );
        assert_eq!(rules.leaves_behind(5), None, "and one ahead of it");

        // One short, and the answer is the entry that asks for more, not the
        // one it already satisfies.
        assert_eq!(
            rules.leaves_behind(3),
            Some(CHANGES),
            "a build one version short is behind at the height the change lands"
        );

        // Two short, and it is still the first entry it cannot apply rather
        // than the last one it can, because the first is where it stops.
        assert_eq!(
            rules.leaves_behind(2),
            Some(OPENS),
            "a build that cannot even open is behind from height nought"
        );
    }

    fn pending(seed: u8, transfer: usize, input: usize, good: bool) -> Pending {
        let key = SecretKey::from_bytes(&[seed | 1; 32]);
        let message = Hash32::from_bytes([seed; 32]);
        let signature = key.sign(message.as_bytes());
        Pending {
            owner: if good {
                key.public_key()
            } else {
                // A key that did not sign this: the signature is well formed
                // and does not hold, which is what a forged transfer looks
                // like and what a corrupted one looks like too.
                SecretKey::from_bytes(&[0xAB; 32]).public_key()
            },
            message,
            signature,
            transfer,
            input,
        }
    }

    /// The same answer above the threshold as below it.
    ///
    /// Past `SPLIT_ABOVE` the work is handed to several threads, and the one
    /// that finds a bad signature first is whichever was scheduled first. What
    /// is reported has to be the one validation reached first instead, or a
    /// node names a different input on every run and nobody can debug it. The
    /// verdict is the same either way; this is about the report.
    #[test]
    fn a_split_check_names_the_same_signature_a_whole_one_would() {
        for count in [4usize, SPLIT_ABOVE - 1, SPLIT_ABOVE, SPLIT_ABOVE * 4 + 3] {
            for bad_at in [0usize, 1, count / 2, count - 1] {
                let found: Vec<Pending> = (0..count)
                    .map(|index| {
                        let seed = u8::try_from(index % 251).unwrap();
                        pending(seed, index / 8, index, index != bad_at)
                    })
                    .collect();

                let failure = first_failure(&found).expect("one of them does not hold");
                assert_eq!(
                    (failure.transfer, failure.input),
                    (found[bad_at].transfer, found[bad_at].input),
                    "{count} signatures, the bad one at {bad_at}"
                );
            }
        }
    }

    /// And nothing is reported when every one of them holds, at any size.
    #[test]
    fn a_split_check_finds_nothing_wrong_with_signatures_that_hold() {
        for count in [1usize, SPLIT_ABOVE, SPLIT_ABOVE * 4 + 3] {
            let found: Vec<Pending> = (0..count)
                .map(|index| {
                    let seed = u8::try_from(index % 251).unwrap();
                    pending(seed, index / 8, index, true)
                })
                .collect();
            assert!(first_failure(&found).is_none(), "{count} good signatures");
        }
    }
}

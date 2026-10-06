//! A reorganisation storm, and whether every node comes out of it holding the
//! ledger a replay of the winning branch gives.
//!
//! The attack catalogue of 3 October rates one entry critical with no attacker
//! in it: I05, an undo that is not the exact inverse of the apply it undoes.
//! Two honest nodes that saw the same blocks in different orders would then
//! sit on the same tip with different ledgers, and nothing about either of
//! them would look wrong. Lab scenario R18 asks the question live, with two
//! mining groups on a link toggled for six hours. This asks it in one process,
//! deterministically, where a difference names the block it appeared at.
//!
//! What a switch has to put back is more than a root: the hot set and the
//! order it evicts in, the grace window and where each fallen note sits in it,
//! the cold set's roots and the paths a node keeps current under them, the
//! coinbases still maturing, the supply after the place price is burned, the
//! headers, and the undo record each block on the new branch leaves for the
//! next switch. `invariants.rs` undoes sequences block by block and walks one
//! losing branch back per sequence, at the ledger level and through no store;
//! `audit_a_reorganisation_is_the_inverse.rs` makes one switch through the
//! store over coinbase payments. None of them goes back and forth, reaches
//! every depth up to the limit, or runs with a place price, coinbases still
//! maturing, notes a block pushes into the cold set the moment it creates
//! them, and switches failing partway, all at once.
//!
//! So this grows a tree of competing branches on a common chain longer than
//! the grace window, deterministic from a seed, and feeds it to several stores
//! in different orders, plain and archiving. After every block a store takes,
//! its ledger is compared with the one a fresh node builds by replaying the
//! branch it now follows from the first block, field by field and as a whole.
//! After every switch, so is the ledger each undo record it holds would put
//! back, at every height down to the lowest fork; and a ledger beside it that
//! follows the same branch through `connect_block` and `disconnect_block` has
//! to have written, for every block it applied again, the same record byte
//! for byte as the replay did. Into the storm go switches that fail partway,
//! on a block deep in the new branch, and each must leave the store exactly as
//! it found it, pool and records included. At the end every store, whatever
//! order it was fed in, holds the same ledger.
//!
//! Two tests, both `cairn_fuzz` campaigns, so `CAIRN_FUZZ_SEED`,
//! `CAIRN_FUZZ_CASES` and `CAIRN_FUZZ_SECONDS` steer them. One walks every
//! depth from one to the undo limit, back and forth between two branches, in
//! every case. The other draws its trees and orders at random.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use cairn_accumulator::ForestProof;
use cairn_chain::{Accepted, ChainError, ChainStore, Located};
use cairn_crypto::{SecretKey, Signature};
use cairn_fuzz::{Campaign, Rng};
use cairn_ledger::block::{Block, BlockHeader, HeaderSummary};
use cairn_ledger::note::{Address, Note, NoteId};
use cairn_ledger::state::{HotEntry, Tip, GRACE_BLOCKS};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, check_transfer_again, connect_block, disconnect_block, ConnectedBlock,
    ConsensusParams, PLACE_PRICE,
};
use cairn_ledger::{LedgerState, Witness};
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
/// The spacing the difficulty rule aims for on the test network. Blocks dated
/// this far apart keep the difficulty at one, so a header costs nothing to
/// seal and the work behind a branch is its length.
const SPACING: u64 = 60;
/// Small, so the tier is full by the eighth block and every block after that
/// pushes notes into the cold set, inside whatever range a switch undoes.
const CAPACITY: usize = 8;
/// Room for a block to create more notes than the tier holds, so some of what
/// it creates falls in the block that created it.
const MOST_EVICTIONS: usize = 24;
/// A coinbase waits a few blocks, so the maturity window holds entries for a
/// switch to put back.
const MATURITY: u64 = 3;
/// The undo limit, which is the burial on a network that sets it below
/// `MAX_REORG_DEPTH`. Small, so every depth up to it is reached in seconds.
const LIMIT: u64 = 12;
/// Blocks in the common chain. Past the grace window by enough that the notes
/// that fell first have left it, so spending one takes a proof.
const PREFIX: u64 = GRACE_BLOCKS as u64 + 24;
/// How far below the common tip a branch may fork.
const FORK_SPREAD: u64 = 3;
/// Every note here belongs to one of these, so every note can be spent.
const OWNERS: usize = 5;
/// The owner every node is asked to follow, so the watched notes and their
/// paths are part of what a switch puts back.
const WATCHED: usize = OWNERS - 1;
/// The common chain is the same in every case. The branches are what the seed
/// varies.
const PREFIX_SEED: u64 = 0x0005_EED0_F2E0_0418;
/// Cases the storm runs in `cargo test`.
const QUICK: usize = 6;
/// Cases the depth sweep runs in `cargo test`. Each walks every depth.
const SWEEPS: usize = 3;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(CAPACITY)
        .with_max_evictions(MOST_EVICTIONS)
        .with_place_price(PLACE_PRICE)
        .with_coinbase_maturity(MATURITY)
        .with_burial(LIMIT)
}

/// The keys every note here belongs to, and the address of each.
struct Wallets {
    keys: Vec<SecretKey>,
    addresses: Vec<Address>,
}

fn wallets() -> &'static Wallets {
    static WALLETS: OnceLock<Wallets> = OnceLock::new();
    WALLETS.get_or_init(|| {
        let keys: Vec<SecretKey> = (1..=OWNERS as u8)
            .map(|seed| SecretKey::from_bytes(&[seed; 32]))
            .collect();
        let addresses = keys
            .iter()
            .map(|key| Address::from(key.public_key()))
            .collect();
        Wallets { keys, addresses }
    })
}

fn owner_of(note: &Note) -> &'static SecretKey {
    let wallets = wallets();
    let index = wallets
        .addresses
        .iter()
        .position(|address| *address == note.owner)
        .expect("every note here belongs to a wallet this file holds");
    &wallets.keys[index]
}

fn watched() -> Address {
    wallets().addresses[WATCHED]
}

fn pebbles(value: u64) -> Amount {
    Amount::from_pebbles(value).unwrap()
}

/// What one block does that a switch has to put back, counted so the run can
/// say what it reached.
#[derive(Clone, Copy, Debug, Default)]
struct Features {
    hot_spends: usize,
    /// Notes spent out of the cold set past the grace window, with a proof.
    cold_spends: usize,
    /// Notes spent out of the grace window by identifier alone.
    grace_spends: usize,
    /// The same, with a proof the spender brought.
    grace_proved: usize,
    /// Cold spends at the place beside another cold spend of the same block.
    adjacent_cold: usize,
    /// Notes spent out of the oldest block of a full grace window, so the
    /// block lifts them out of a landing it then ages off the window.
    grace_ageing: usize,
    /// Places paid for at the place price.
    places_paid: usize,
    evicted: usize,
    /// Notes the block created and pushed straight into the cold set.
    through: usize,
    coinbase_only: bool,
    pays_nobody: bool,
    /// Transfers another branch may carry too.
    shared: usize,
}

/// A wallet's view of one branch while it is being mined.
#[derive(Clone)]
struct Miner {
    /// What a fresh node holds once it has replayed the branch this far.
    plain: LedgerState,
    /// The same as an archivist holds it, which can say where any fallen note
    /// sits and prove it.
    archive: LedgerState,
    /// Notes this branch made fall and has not spent: what a wallet keeps of
    /// its own so that it can prove one later.
    fallen: BTreeMap<NoteId, Note>,
    /// Written into the nonce, so two branches building the same body on the
    /// same parent still build two blocks.
    tag: u64,
}

impl Miner {
    fn new() -> Self {
        let mut plain = LedgerState::new();
        let mut archive = LedgerState::archiving();
        plain.watch_owner(watched());
        archive.watch_owner(watched());
        Self {
            plain,
            archive,
            fallen: BTreeMap::new(),
            tag: 0,
        }
    }
}

/// One block of the tree, with the ledger a fresh node holds once it has
/// replayed the block's branch from the first block up to and including it.
struct Mined {
    block: Block,
    id: Hash32,
    parent: Hash32,
    height: u64,
    /// The record that replay wrote for this block.
    record: ConnectedBlock,
    after: Miner,
    features: Features,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tier {
    Hot,
    Grace(u64),
    Cold(u64),
}

#[derive(Clone, Copy)]
struct Spendable {
    id: NoteId,
    note: Note,
    tier: Tier,
}

impl Spendable {
    fn position(&self) -> u64 {
        match self.tier {
            Tier::Hot => u64::MAX,
            Tier::Grace(position) | Tier::Cold(position) => position,
        }
    }
}

/// What the branch can spend in the block at `height`, by tier: the hot set,
/// the grace window, the cold set past it, and the landing that ages off the
/// window in this very block when the window is full.
fn spendable(miner: &Miner, height: u64) -> [Vec<Spendable>; 4] {
    let state = &miner.archive;
    let mature = |id: &NoteId| {
        state
            .coinbase_matures_at(&id.source)
            .is_none_or(|at| height >= at)
    };
    let hot = state
        .hot_notes()
        .filter(|(id, _)| mature(id))
        .map(|(id, entry)| Spendable {
            id,
            note: entry.note,
            tier: Tier::Hot,
        })
        .collect();
    let window = state.grace_window();
    let ageing = match window.first() {
        Some(landing) if window.len() == GRACE_BLOCKS => landing.len(),
        _ => 0,
    };
    let grace: Vec<Spendable> = window
        .into_iter()
        .flatten()
        .map(|(id, position, note)| Spendable {
            id,
            note,
            tier: Tier::Grace(position),
        })
        .collect();
    let oldest = grace[..ageing]
        .iter()
        .filter(|spent| mature(&spent.id))
        .copied()
        .collect();
    let grace = grace
        .into_iter()
        .filter(|spent| mature(&spent.id))
        .collect();
    let mut cold: Vec<Spendable> = miner
        .fallen
        .iter()
        .filter(|(id, _)| state.within_grace(id).is_none() && mature(id))
        .filter_map(|(id, note)| {
            let position = state.cold().locate(id, note)?;
            Some(Spendable {
                id: *id,
                note: *note,
                tier: Tier::Cold(position),
            })
        })
        .collect();
    cold.sort_by_key(Spendable::position);
    [hot, grace, cold, oldest]
}

/// A cold note beside one already taken, so the proofs of one block share
/// siblings and an emptied leaf has a neighbour to disturb.
fn beside(cold: &[Spendable], picked: &[Spendable], used: &BTreeSet<NoteId>) -> Option<Spendable> {
    picked
        .iter()
        .filter(|taken| matches!(taken.tier, Tier::Cold(_)))
        .find_map(|taken| {
            cold.iter()
                .find(|other| {
                    !used.contains(&other.id) && other.position().abs_diff(taken.position()) == 1
                })
                .copied()
        })
}

/// One to three notes nobody in this block has spent yet, leaning on the hot
/// set but reaching the grace window and the cold set often.
fn pick_inputs(
    rng: &mut Rng,
    pools: &[Vec<Spendable>; 4],
    used: &mut BTreeSet<NoteId>,
) -> Vec<Spendable> {
    let wanted = 1 + rng.below(3);
    let mut picked: Vec<Spendable> = Vec::new();
    for _ in 0..wanted {
        let first = match rng.below(10) {
            0..=3 => 0,
            4..=6 => 1,
            _ => 2,
        };
        if first == 2 && rng.bool() {
            if let Some(next) = beside(&pools[2], &picked, used) {
                used.insert(next.id);
                picked.push(next);
                continue;
            }
        }
        // A third of the grace picks go to the landing this block ages off the
        // window, so the block lifts a note out of a landing it then drops.
        if first == 1 && rng.chance(3) {
            let free: Vec<Spendable> = pools[3]
                .iter()
                .filter(|candidate| !used.contains(&candidate.id))
                .copied()
                .collect();
            if let Some(chosen) = rng.pick(&free).copied() {
                used.insert(chosen.id);
                picked.push(chosen);
                continue;
            }
        }
        for offset in 0..3 {
            let free: Vec<Spendable> = pools[(first + offset) % 3]
                .iter()
                .filter(|candidate| !used.contains(&candidate.id))
                .copied()
                .collect();
            if let Some(chosen) = rng.pick(&free).copied() {
                used.insert(chosen.id);
                picked.push(chosen);
                break;
            }
        }
    }
    picked
}

fn proved(state: &LedgerState, spent: &Spendable, position: u64) -> Input {
    let proof = state
        .cold()
        .prove(position)
        .expect("an archivist proves any place it holds");
    Input::cold(spent.id, spent.note, position, proof)
}

/// A signed transfer of `inputs`, paying the place price for every place it
/// takes and now and then a little more, which the coinbase may keep. Returns
/// that little more beside it.
fn build_transfer(
    rng: &mut Rng,
    state: &LedgerState,
    params: &ConsensusParams,
    inputs: &[Spendable],
    room: usize,
) -> Option<(Transfer, u64)> {
    let freed = inputs
        .iter()
        .filter(|spent| spent.tier == Tier::Hot)
        .count();
    // Now and then more notes than the tier holds, so the block falls some of
    // its own.
    let wanted = if rng.chance(6) {
        CAPACITY + 1 + rng.below(4)
    } else {
        1 + rng.below(4)
    };
    let outputs = wanted.min(room);
    if outputs == 0 {
        return None;
    }
    let burn = PLACE_PRICE.as_pebbles() * outputs.saturating_sub(freed) as u64;
    let tip = if rng.bool() {
        0
    } else {
        rng.below(10_000) as u64
    };
    let total: u64 = inputs
        .iter()
        .map(|spent| spent.note.value.as_pebbles())
        .sum();
    let left = total.checked_sub(burn + tip)?;
    let count = outputs as u64;
    if left < count {
        return None;
    }
    let share = left / count;
    let notes = (0..count)
        .map(|index| {
            let value = if index + 1 == count {
                left - share * (count - 1)
            } else {
                share
            };
            Note::new(pebbles(value), wallets().addresses[rng.below(OWNERS)])
        })
        .collect();
    let spends = inputs
        .iter()
        .map(|spent| match spent.tier {
            Tier::Hot => Input::hot(spent.id),
            Tier::Grace(position) => {
                if rng.chance(3) {
                    proved(state, spent, position)
                } else {
                    Input::hot(spent.id)
                }
            }
            Tier::Cold(position) => proved(state, spent, position),
        })
        .collect();
    let mut transfer = Transfer::new(spends, notes);
    for (index, spent) in inputs.iter().enumerate() {
        transfer.sign_input(
            params.network,
            index as u32,
            &spent.note,
            owner_of(&spent.note),
        );
    }
    Some((transfer, tip))
}

#[derive(Clone, Copy)]
enum Pay {
    Nobody,
    One { claims: bool },
    Split(usize),
}

impl Pay {
    fn outputs(self) -> usize {
        match self {
            Self::Nobody => 0,
            Self::One { .. } => 1,
            Self::Split(count) => count,
        }
    }
}

fn coinbase(
    rng: &mut Rng,
    height: u64,
    params: &ConsensusParams,
    pay: Pay,
    kept: u64,
    tag: u64,
) -> CoinbaseTransaction {
    let reward = params.reward_at(height).as_pebbles();
    let outputs = match pay {
        Pay::Nobody => Vec::new(),
        Pay::One { claims } => {
            let payee = if rng.bool() { 0 } else { rng.below(OWNERS) };
            let value = reward + if claims { kept } else { 0 };
            vec![Note::new(pebbles(value), wallets().addresses[payee])]
        }
        Pay::Split(count) => {
            let total = reward + if rng.bool() { kept } else { 0 };
            let count = count as u64;
            let share = total / count;
            (0..count)
                .map(|index| {
                    let value = if index + 1 == count {
                        total - share * (count - 1)
                    } else {
                        share
                    };
                    Note::new(pebbles(value), wallets().addresses[rng.below(OWNERS)])
                })
                .collect()
        }
    };
    // Unmarked half the time, so two branches paying the same owner the same
    // amount at the same height pay it the same note.
    let extra = if rng.bool() {
        Vec::new()
    } else {
        tag.to_le_bytes().to_vec()
    };
    CoinbaseTransaction::with_extra(height, outputs, extra)
}

fn features_of(
    parent: &LedgerState,
    block: &Block,
    record: &ConnectedBlock,
    shared: &[Transfer],
) -> Features {
    let mut features = Features {
        evicted: record.transition.evicted.len(),
        coinbase_only: block.transfers.is_empty(),
        pays_nobody: block.coinbase.outputs.is_empty(),
        ..Features::default()
    };
    let window = parent.grace_window();
    let oldest: BTreeSet<NoteId> = match window.first() {
        Some(landing) if window.len() == GRACE_BLOCKS => {
            landing.iter().map(|(id, _, _)| *id).collect()
        }
        _ => BTreeSet::new(),
    };
    let mut cold_places = BTreeSet::new();
    for transfer in &block.transfers {
        if shared.iter().any(|other| other.id() == transfer.id()) {
            features.shared += 1;
        }
        let mut freed = 0;
        for input in &transfer.inputs {
            if parent.hot_note(&input.note_id).is_some() {
                features.hot_spends += 1;
                freed += 1;
            } else if parent.within_grace(&input.note_id).is_some() {
                features.grace_ageing += usize::from(oldest.contains(&input.note_id));
                if matches!(input.witness, Witness::Cold(_)) {
                    features.grace_proved += 1;
                } else {
                    features.grace_spends += 1;
                }
            } else {
                features.cold_spends += 1;
                if let Witness::Cold(cold) = &input.witness {
                    cold_places.insert(cold.position);
                }
            }
        }
        features.places_paid += transfer.outputs.len().saturating_sub(freed);
    }
    features.adjacent_cold = cold_places
        .iter()
        .filter(|place| cold_places.contains(&(**place + 1)))
        .count();
    let created: BTreeSet<NoteId> = record
        .transition
        .created
        .iter()
        .map(|(id, _)| *id)
        .collect();
    features.through = record
        .transition
        .evicted
        .iter()
        .filter(|(id, _)| created.contains(id))
        .count();
    features
}

/// Mines the next block of a branch, from what the branch can spend.
fn draw_block(
    miner: &mut Miner,
    rng: &mut Rng,
    params: &ConsensusParams,
    shared: &[Transfer],
) -> Mined {
    let height = miner.archive.next_height().unwrap();
    let pay = match rng.below(10) {
        0 => Pay::Nobody,
        1 | 2 => Pay::Split(2 + rng.below(3)),
        3 | 4 => Pay::One { claims: true },
        _ => Pay::One { claims: false },
    };
    // Whatever the block creates past the tier falls, so this bounds what it
    // creates by what may fall.
    let mut room = MOST_EVICTIONS - pay.outputs();
    let mut transfers = Vec::new();
    let mut kept = 0u64;
    // A quarter of the blocks carry the coinbase alone.
    if !rng.chance(4) {
        let mut used = BTreeSet::new();
        for transfer in shared {
            if !rng.chance(3)
                || transfer.outputs.len() > room
                || transfer
                    .inputs
                    .iter()
                    .any(|input| used.contains(&input.note_id))
            {
                continue;
            }
            let Ok(outcome) = check_transfer_again(
                transfer,
                &miner.archive,
                &BTreeSet::new(),
                &BTreeMap::new(),
                params,
            ) else {
                continue;
            };
            used.extend(transfer.inputs.iter().map(|input| input.note_id));
            room -= transfer.outputs.len();
            kept += outcome.fee.as_pebbles() - outcome.burn.as_pebbles();
            transfers.push(transfer.clone());
        }
        let pools = spendable(miner, height);
        for _ in 0..=rng.below(3) {
            let inputs = pick_inputs(rng, &pools, &mut used);
            if inputs.is_empty() {
                break;
            }
            if let Some((transfer, tip)) =
                build_transfer(rng, &miner.archive, params, &inputs, room)
            {
                room -= transfer.outputs.len();
                kept += tip;
                transfers.push(transfer);
            }
        }
    }
    let coinbase = coinbase(rng, height, params, pay, kept, miner.tag);
    let timestamp = 1_000 + SPACING * (height + 1);
    let block = assemble_block(
        &miner.archive,
        coinbase,
        transfers,
        params,
        timestamp,
        miner.tag,
    )
    .unwrap_or_else(|refused| {
        panic!("the generator built a block its own rules refuse, at height {height}: {refused}")
    });
    let parent = miner.plain.clone();
    let record = connect_block(&mut miner.plain, &block, params, NOW)
        .expect("a fresh node takes the block its branch was built for");
    connect_block(&mut miner.archive, &block, params, NOW).expect("and so does an archivist");
    assert_eq!(
        miner.plain.state_root(),
        miner.archive.state_root(),
        "the two kinds of node disagree on a block at height {height}"
    );
    for spend in &record.transition.spent_cold {
        miner.fallen.remove(&spend.id);
    }
    for (id, note) in &record.transition.evicted {
        miner.fallen.insert(*id, *note);
    }
    let features = features_of(&parent, &block, &record, shared);
    Mined {
        id: block.id(),
        parent: block.header.previous,
        height,
        block,
        record,
        after: miner.clone(),
        features,
    }
}

/// The common chain every tree grows on.
struct Prefix {
    blocks: Vec<Mined>,
    by_id: HashMap<Hash32, usize>,
}

fn prefix() -> &'static Prefix {
    static CHAIN: OnceLock<Prefix> = OnceLock::new();
    CHAIN.get_or_init(|| {
        let params = params();
        let mut rng = Rng::new(PREFIX_SEED);
        let mut miner = Miner::new();
        let blocks: Vec<Mined> = (0..PREFIX)
            .map(|_| draw_block(&mut miner, &mut rng, &params, &[]))
            .collect();
        let by_id = blocks
            .iter()
            .enumerate()
            .map(|(index, mined)| (mined.id, index))
            .collect();
        Prefix { blocks, by_id }
    })
}

/// Where a branch starts: a height of the common chain, or after so many
/// blocks of an earlier branch.
#[derive(Clone, Copy, Debug)]
enum Fork {
    Prefix(u64),
    Branch(usize, usize),
}

fn forked_at(forks: &[Fork], index: usize) -> u64 {
    match forks[index] {
        Fork::Prefix(height) => height,
        Fork::Branch(of, after) => forked_at(forks, of) + after as u64,
    }
}

/// Competing branches on the common chain, every block of them mined.
struct Tree {
    mined: HashMap<Hash32, Mined>,
    branches: Vec<Vec<Hash32>>,
    /// The lowest height a branch forks from. Nothing at or below it is ever
    /// undone.
    base: u64,
    /// The tip of the one heaviest branch, which every order ends on.
    winner: Hash32,
    /// Every block from the first one to that tip.
    winning: BTreeSet<Hash32>,
}

impl Tree {
    fn grow(specs: &[(Fork, usize)], rng: &mut Rng, params: &ConsensusParams) -> Self {
        let prefix = prefix();
        let base = specs
            .iter()
            .filter_map(|(fork, _)| match fork {
                Fork::Prefix(height) => Some(*height),
                Fork::Branch(..) => None,
            })
            .min()
            .unwrap();
        // A few transfers valid at the base, offered to every branch, so some
        // payments sit on both sides of a switch at different heights.
        let shared = draw_shared(&prefix.blocks[base as usize].after, rng, params);
        let mut tree = Self {
            mined: HashMap::new(),
            branches: Vec::new(),
            base,
            winner: Hash32::ZERO,
            winning: BTreeSet::new(),
        };
        for (index, (fork, length)) in specs.iter().enumerate() {
            let mut miner = match *fork {
                Fork::Prefix(height) => prefix.blocks[height as usize].after.clone(),
                Fork::Branch(of, after) => tree.mined[&tree.branches[of][after - 1]].after.clone(),
            };
            miner.tag = index as u64 + 1;
            let mut own = Vec::new();
            for _ in 0..*length {
                let built = draw_block(&mut miner, rng, params, &shared);
                own.push(built.id);
                tree.mined.insert(built.id, built);
            }
            tree.branches.push(own);
        }
        let tips: Vec<Hash32> = tree
            .branches
            .iter()
            .map(|own| *own.last().unwrap())
            .collect();
        let highest = tips.iter().map(|id| tree.get(id).height).max().unwrap();
        let winners: Vec<Hash32> = tips
            .into_iter()
            .filter(|id| tree.get(id).height == highest)
            .collect();
        assert_eq!(
            winners.len(),
            1,
            "a tree has one heaviest branch, so every order ends on it"
        );
        assert!(
            highest >= PREFIX,
            "a tree outweighs the common chain it grows on, which runs past its lowest fork"
        );
        tree.winner = winners[0];
        tree.winning = tree.path(tree.winner).into_iter().collect();
        tree
    }

    fn get(&self, id: &Hash32) -> &Mined {
        if let Some(mined) = self.mined.get(id) {
            return mined;
        }
        let prefix = prefix();
        &prefix.blocks[prefix.by_id[id]]
    }

    /// The blocks from the first one to `tip`, oldest first.
    fn path(&self, tip: Hash32) -> Vec<Hash32> {
        let mut path = Vec::new();
        let mut cursor = tip;
        loop {
            let mined = self.get(&cursor);
            path.push(cursor);
            if mined.height == 0 {
                break;
            }
            cursor = mined.parent;
        }
        path.reverse();
        path
    }

    /// The last block of the branch `id` is on, so one replay covers every
    /// tip of it.
    fn end_through(&self, id: Hash32) -> Hash32 {
        self.branches
            .iter()
            .find(|own| own.contains(&id))
            .map_or(id, |own| *own.last().unwrap())
    }

    /// Parents of branch blocks a broken switch can be built on, in a fixed
    /// order.
    fn parents(&self) -> Vec<Hash32> {
        let prefix = prefix();
        let mut parents: Vec<Hash32> = prefix.blocks[(self.base as usize)..]
            .iter()
            .map(|mined| mined.id)
            .collect();
        parents.extend(self.branches.iter().flatten().copied());
        parents
    }

    /// Notes created on more than one branch. A nested branch shares its
    /// parent's blocks below the fork, which are counted once.
    fn twins(&self) -> usize {
        let mut makers: BTreeMap<NoteId, BTreeSet<Hash32>> = BTreeMap::new();
        for id in self.branches.iter().flatten() {
            for (note, _) in &self.get(id).record.transition.created {
                makers.entry(*note).or_default().insert(*id);
            }
        }
        makers.values().filter(|blocks| blocks.len() > 1).count()
    }

    /// Notes two branches spend with different transfers.
    fn contested(&self) -> usize {
        let mut spenders: BTreeMap<NoteId, BTreeSet<Hash32>> = BTreeMap::new();
        for id in self.branches.iter().flatten() {
            for transfer in &self.get(id).block.transfers {
                for input in &transfer.inputs {
                    spenders
                        .entry(input.note_id)
                        .or_default()
                        .insert(transfer.id());
                }
            }
        }
        spenders
            .values()
            .filter(|transfers| transfers.len() > 1)
            .count()
    }
}

fn draw_shared(miner: &Miner, rng: &mut Rng, params: &ConsensusParams) -> Vec<Transfer> {
    let height = miner.archive.next_height().unwrap();
    let pools = spendable(miner, height);
    let mut used = BTreeSet::new();
    let mut shared = Vec::new();
    for _ in 0..2 + rng.below(2) {
        let inputs = pick_inputs(rng, &pools, &mut used);
        if inputs.is_empty() {
            break;
        }
        if let Some((transfer, _)) = build_transfer(rng, &miner.archive, params, &inputs, 6) {
            shared.push(transfer);
        }
    }
    shared
}

/// Two to three branches off the last few blocks of the common chain, now and
/// then one more off one of them, none reaching past what a switch may undo
/// from the lowest fork, and one of them strictly the longest, the common
/// chain included.
fn random_specs(rng: &mut Rng) -> Vec<(Fork, usize)> {
    let top = 2 + rng.below(2);
    let mut forks: Vec<Fork> = (0..top)
        .map(|_| Fork::Prefix(PREFIX - 1 - rng.below(FORK_SPREAD as usize) as u64))
        .collect();
    let base = (0..top)
        .map(|index| forked_at(&forks, index))
        .min()
        .unwrap();
    let cap = base + LIMIT + 1;
    let mut lengths: Vec<usize> = (0..top)
        .map(|index| 1 + rng.below((cap - forked_at(&forks, index)) as usize))
        .collect();
    if rng.bool() {
        let candidates: Vec<usize> = (0..top).filter(|&index| lengths[index] >= 2).collect();
        if let Some(&of) = rng.pick(&candidates) {
            let after = 1 + rng.below(lengths[of] - 1);
            let from = forked_at(&forks, of) + after as u64;
            forks.push(Fork::Branch(of, after));
            lengths.push(1 + rng.below((cap - from) as usize));
        }
    }
    loop {
        let tips: Vec<u64> = (0..forks.len())
            .map(|index| forked_at(&forks, index) + lengths[index] as u64)
            .collect();
        let highest = *tips.iter().max().unwrap();
        let tied: Vec<usize> = (0..tips.len())
            .filter(|&index| tips[index] == highest)
            .collect();
        // The common chain runs on past the lowest fork, so it is a branch
        // too, and one every store has taken first and keeps on a tie.
        if highest < PREFIX {
            lengths[tied[0]] += 1;
            continue;
        }
        if tied.len() == 1 {
            break;
        }
        if highest < cap {
            lengths[tied[0]] += 1;
            continue;
        }
        // Only a branch off a branch can be one block long at the cap, and it
        // is the last one and nothing forks from it.
        for &index in tied.iter().skip(1).rev() {
            if lengths[index] == 1 {
                forks.remove(index);
                lengths.remove(index);
            } else {
                lengths[index] -= 1;
            }
        }
    }
    forks.into_iter().zip(lengths).collect()
}

/// One thing done to a store: a block offered, or a switch built to fail on
/// a block above this one.
#[derive(Clone, Copy, Debug)]
enum Step {
    Deliver(Hash32),
    Break(Hash32),
}

fn prefix_steps() -> Vec<Step> {
    prefix()
        .blocks
        .iter()
        .map(|mined| Step::Deliver(mined.id))
        .collect()
}

/// Two branches, the one behind always given blocks until it is one ahead, so
/// each switch undoes one block more than the one before. With `breaks`, a
/// switch built to fail deep in the branch about to win goes in just before
/// each real one.
fn ping_pong(
    tree: &Tree,
    lead: usize,
    trail: usize,
    start: usize,
    mut breaks: Option<&mut Rng>,
) -> Vec<Step> {
    let mut steps = prefix_steps();
    let mut given = vec![0usize; tree.branches.len()];
    let mut give = |steps: &mut Vec<Step>, branch: usize, upto: usize| {
        let upto = upto.min(tree.branches[branch].len());
        while given[branch] < upto {
            steps.push(Step::Deliver(tree.branches[branch][given[branch]]));
            given[branch] += 1;
        }
        given[branch]
    };
    let (mut lead, mut trail) = (lead, trail);
    give(&mut steps, lead, start);
    let mut ahead = start.min(tree.branches[lead].len());
    loop {
        let target = ahead + 1;
        if target > tree.branches[trail].len() {
            give(&mut steps, trail, usize::MAX);
            give(&mut steps, lead, usize::MAX);
            break;
        }
        give(&mut steps, trail, ahead);
        if let Some(rng) = breaks.as_deref_mut() {
            // Above block `j` of the branch about to win, so the switch undoes
            // the branch followed, applies `j` blocks, and fails on the next.
            let j = rng.below(ahead + 1);
            let parent = if j == 0 {
                tree.get(&tree.branches[trail][0]).parent
            } else {
                tree.branches[trail][j - 1]
            };
            steps.push(Step::Break(parent));
        }
        ahead = give(&mut steps, trail, target);
        std::mem::swap(&mut lead, &mut trail);
    }
    steps
}

/// Whole branches one after the other, in the order given.
fn branch_after_branch(tree: &Tree, order: &[usize]) -> Vec<Step> {
    let mut steps = prefix_steps();
    for &branch in order {
        steps.extend(tree.branches[branch].iter().map(|id| Step::Deliver(*id)));
    }
    steps
}

/// Whether the next block of `branch` has a parent already given.
fn ready(tree: &Tree, given: &[usize], forks: &[Option<(usize, usize)>], branch: usize) -> bool {
    if given[branch] >= tree.branches[branch].len() {
        return false;
    }
    if given[branch] > 0 {
        return true;
    }
    forks[branch].is_none_or(|(of, after)| given[of] >= after)
}

/// Which branch, and after how many of its blocks, each branch forks from.
fn fork_points(tree: &Tree) -> Vec<Option<(usize, usize)>> {
    tree.branches
        .iter()
        .map(|own| {
            let parent = tree.get(&own[0]).parent;
            tree.branches.iter().enumerate().find_map(|(of, other)| {
                other
                    .iter()
                    .position(|id| *id == parent)
                    .map(|at| (of, at + 1))
            })
        })
        .collect()
}

/// Blocks one at a time from any branch whose next block has its parent.
fn scattered(tree: &Tree, rng: &mut Rng) -> Vec<Step> {
    let mut steps = prefix_steps();
    let forks = fork_points(tree);
    let mut given = vec![0usize; tree.branches.len()];
    loop {
        let open: Vec<usize> = (0..tree.branches.len())
            .filter(|&branch| ready(tree, &given, &forks, branch))
            .collect();
        let Some(&branch) = rng.pick(&open) else {
            break;
        };
        steps.push(Step::Deliver(tree.branches[branch][given[branch]]));
        given[branch] += 1;
    }
    steps
}

/// A branch other than the one leading, given blocks until it leads, over and
/// over, with switches built to fail thrown in just before the real ones.
fn storm(tree: &Tree, rng: &mut Rng) -> Vec<Step> {
    let mut steps = prefix_steps();
    let forks = fork_points(tree);
    let parents = tree.parents();
    let mut given = vec![0usize; tree.branches.len()];
    let mut height = PREFIX - 1;
    let mut leader: Option<usize> = None;
    loop {
        let open: Vec<usize> = (0..tree.branches.len())
            .filter(|&branch| ready(tree, &given, &forks, branch))
            .collect();
        let rivals: Vec<usize> = open
            .iter()
            .copied()
            .filter(|branch| Some(*branch) != leader)
            .collect();
        let Some(&branch) = rng.pick(if rivals.is_empty() { &open } else { &rivals }) else {
            break;
        };
        while given[branch] < tree.branches[branch].len() {
            let id = tree.branches[branch][given[branch]];
            let at = tree.get(&id).height;
            if at > height && rng.bool() {
                steps.push(Step::Break(*rng.pick(&parents).unwrap()));
            }
            steps.push(Step::Deliver(id));
            given[branch] += 1;
            if at > height {
                height = at;
                leader = Some(branch);
                break;
            }
            if rng.chance(8) {
                break;
            }
        }
    }
    steps
}

/// The store's branch followed at the ledger level, so the records a switch
/// leaves behind can be read and compared byte for byte.
struct Mirror {
    state: LedgerState,
    applied: Vec<(Hash32, ConnectedBlock)>,
}

impl Mirror {
    /// Starts at the tip of the common chain, with the records its replay
    /// wrote, which is where every store stands once it has taken it.
    fn new() -> Self {
        let prefix = prefix();
        Self {
            state: prefix.blocks.last().unwrap().after.plain.clone(),
            applied: prefix
                .blocks
                .iter()
                .map(|mined| (mined.id, mined.record.clone()))
                .collect(),
        }
    }

    fn follow(&mut self, store: &ChainStore, tree: &Tree, params: &ConsensusParams) {
        let height = store.height().unwrap();
        while let Some((id, _)) = self.applied.last() {
            let at = self.applied.len() as u64 - 1;
            if at <= height && store.id_at(at) == Some(*id) {
                break;
            }
            let (_, record) = self.applied.pop().unwrap();
            disconnect_block(&mut self.state, &record);
        }
        for at in self.applied.len() as u64..=height {
            let id = store.id_at(at).unwrap();
            let record = connect_block(&mut self.state, &tree.get(&id).block, params, NOW)
                .expect("the mirror takes every block the store took");
            self.applied.push((id, record));
        }
    }
}

struct Node {
    name: &'static str,
    store: ChainStore,
    archiving: bool,
    mirror: Option<Mirror>,
}

impl Node {
    fn new(name: &'static str, archiving: bool, params: ConsensusParams) -> Self {
        let mut store = if archiving {
            ChainStore::archiving(params)
        } else {
            ChainStore::new(params)
        };
        store.watch_owner(watched());
        Self {
            name,
            store,
            archiving,
            mirror: (!archiving).then(Mirror::new),
        }
    }
}

/// What the store says about its branch, apart from the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ChainFields {
    tip: Option<Hash32>,
    height: Option<u64>,
    total_work: u128,
    undo_records: usize,
    held_from: u64,
    branch_start: Option<u64>,
    held_ids: Vec<Hash32>,
    locator: Vec<Located>,
}

fn chain_fields(store: &ChainStore) -> ChainFields {
    ChainFields {
        tip: store.tip(),
        height: store.height(),
        total_work: store.total_work(),
        undo_records: store.undo_records(),
        held_from: store.held_from(),
        branch_start: store.branch_start(),
        held_ids: store.held_ids(),
        locator: store.locator(),
    }
}

/// Everything a ledger can be asked that does not depend on whether it keeps
/// the cold set's leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Common {
    tip: Option<Tip>,
    state_root: Hash32,
    history_root: Hash32,
    headers_committed: u64,
    headers_before_tip: Vec<u8>,
    recent: Vec<HeaderSummary>,
    hot_len: usize,
    hot: Vec<(NoteId, HotEntry)>,
    /// Every hot note, in the order the tier would let them fall.
    eviction_order: Vec<NoteId>,
    cold_roots: Vec<u8>,
    cold_len: u64,
    next_cold_position: u64,
    grace_root: Hash32,
    grace: Vec<Vec<(NoteId, u64, Note)>>,
    grace_len: usize,
    /// What the index beside the window answers for each note in it.
    grace_index: Vec<Option<(u64, Note)>>,
    maturing: Vec<(u64, Hash32)>,
    /// The same for the index beside the maturity window.
    maturing_index: Vec<Option<u64>>,
    supply: Amount,
    followed: Vec<(NoteId, u64, Note)>,
}

/// The paths a ledger proves places with: the ones a plain node keeps
/// current, or every place for an archivist, which builds them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Paths {
    kept: usize,
    proofs: Vec<(u64, ForestProof)>,
}

/// A ledger, as everything it can be asked and as the whole of its `Debug`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Print {
    common: Common,
    paths: Paths,
    whole: String,
}

fn print(state: &LedgerState) -> Print {
    let grace = state.grace_window();
    let grace_index = grace
        .iter()
        .flatten()
        .map(|(id, _, _)| state.within_grace(id))
        .collect();
    let maturing = state.maturing();
    let maturing_index = maturing
        .iter()
        .map(|(_, id)| state.coinbase_matures_at(id))
        .collect();
    let mut followed: Vec<_> = state.watched_notes().collect();
    followed.sort_by_key(|(id, _, _)| *id);
    let common = Common {
        tip: state.tip(),
        state_root: state.state_root(),
        history_root: state.history_root(),
        headers_committed: state.headers_committed(),
        headers_before_tip: state.headers_before_tip().encode(),
        recent: state.recent_headers().to_vec(),
        hot_len: state.hot_len(),
        hot: state.hot_notes().collect(),
        eviction_order: state
            .plan_evictions(&BTreeSet::new(), &[], 0)
            .into_iter()
            .map(|(id, _)| id)
            .collect(),
        cold_roots: state.cold_roots().encode(),
        cold_len: state.cold_len(),
        next_cold_position: state.next_cold_position(),
        grace_root: state.grace_root(),
        grace,
        grace_len: state.grace_len(),
        grace_index,
        maturing,
        maturing_index,
        supply: state.supply(),
        followed,
    };
    let paths = Paths {
        kept: state.watched_paths(),
        proofs: (0..state.next_cold_position())
            .filter_map(|position| Some((position, state.cold().proof_of(position)?)))
            .collect(),
    };
    Print {
        common,
        paths,
        whole: canonical_debug(state),
    }
}

/// Times [`canonical_debug`] dropped an empty row, so the run can say how
/// often an archivist held one.
static EMPTY_ROWS: AtomicUsize = AtomicUsize::new(0);

/// A ledger's `Debug`, with two things in an archivist's written the one way
/// they can be.
///
/// Everything else a ledger holds is ordered, so the rest of the text is
/// compared as it stands, which covers the indices beside the window, the
/// maturity list and the hot set that no accessor shows whole.
///
/// The first is the map an archivist finds a leaf through. It is a `HashMap`,
/// and two of those holding the same entries print them in different orders,
/// so its entries are sorted.
///
/// The second is the rows of inner nodes it keeps so a proof is one lookup a
/// level. A row is added when the leaf count first completes a node of that
/// height, and an undo that takes the count back below it empties the row
/// without dropping it, so an archivist that undid past a power of two holds
/// an empty row a replay never made. Nothing reads one: a node is looked up
/// in its row and an empty row answers as a missing one does, what an archive
/// says it holds adds up row lengths, and the next node of that height lands
/// in the row either way. So trailing empty rows are dropped before comparing,
/// and the difference is reported rather than taken for a divergence.
fn canonical_debug(state: &LedgerState) -> String {
    let mut text = format!("{state:?}");
    let rows = "inner: [";
    if let Some(start) = text.find(rows) {
        let open = start + rows.len();
        let close = open + text[open..].find(", standing: {").expect("the rows end") - 1;
        let whole = &text[open..close];
        let mut inside = whole;
        loop {
            if let Some(rest) = inside.strip_suffix(", []") {
                inside = rest;
            } else if inside == "[]" {
                inside = "";
            } else {
                break;
            }
        }
        if inside.len() != whole.len() {
            EMPTY_ROWS.fetch_add(1, Ordering::Relaxed);
        }
        text = format!("{}{inside}{}", &text[..open], &text[close..]);
    }
    let marker = "standing: {";
    let Some(start) = text.find(marker) else {
        return text;
    };
    let open = start + marker.len();
    let close = open + text[open..].find('}').expect("the map closes");
    let mut entries: Vec<&str> = text[open..close]
        .split(", ")
        .filter(|entry| !entry.is_empty())
        .collect();
    entries.sort_unstable();
    format!("{}{}{}", &text[..open], entries.join(", "), &text[close..])
}

/// Two texts that must be equal, and where they first part if not, so a
/// difference in a hundred kilobytes is readable.
fn same_text(found: &str, expected: &str, why: &str) {
    if found == expected {
        return;
    }
    let at = found
        .bytes()
        .zip(expected.bytes())
        .take_while(|(left, right)| left == right)
        .count();
    let from = at.saturating_sub(200);
    let window = |text: &str| -> String { text.chars().skip(from).take(500).collect() };
    let label: String = expected.chars().take(32).collect();
    panic!(
        "{why}\n  in {label:?}, from byte {from}\n  found    ...{}...\n  expected ...{}...",
        window(found),
        window(expected)
    );
}

fn same<T: PartialEq + std::fmt::Debug>(found: &T, expected: &T, why: &str) {
    if found != expected {
        same_text(&format!("{found:#?}"), &format!("{expected:#?}"), why);
        panic!("{why}: the two differ, though not in how they print");
    }
}

/// What the run reached, so a generator that stopped producing a case fails
/// rather than passes on less.
#[derive(Debug, Default)]
struct Reached {
    trees: usize,
    delivered: usize,
    /// Blocks refused as too far below the tip, or for a parent refused so.
    /// Only ever off the winning branch.
    turned_away: usize,
    /// Switches by how many blocks each undid.
    switches: BTreeMap<usize, usize>,
    undone: usize,
    reapplied: usize,
    evicted_in_range: usize,
    through_in_range: usize,
    cold_spends_in_range: usize,
    adjacent_cold_in_range: usize,
    grace_spends_in_range: usize,
    grace_ageing_in_range: usize,
    grace_proved_in_range: usize,
    places_paid_in_range: usize,
    coinbase_only_in_range: usize,
    pays_nobody_in_range: usize,
    shared_in_range: usize,
    contested: usize,
    /// Notes two branches both created, from the same coinbase or the same
    /// shared transfer, and then dealt with each in its own way.
    twins: usize,
    failed: usize,
    /// Failed switches that had applied at least one block of the new branch
    /// before reaching the bad one.
    failed_after_applying: usize,
    failed_depths: BTreeMap<u64, usize>,
    failed_kinds: BTreeMap<&'static str, usize>,
    undo_checks: usize,
    records_compared: usize,
    levelled: usize,
}

impl Reached {
    fn switched(&mut self, tree: &Tree, removed: &[Hash32], added: &[Hash32]) {
        *self.switches.entry(removed.len()).or_default() += 1;
        self.undone += removed.len();
        self.reapplied += added.len();
        for id in removed.iter().chain(added) {
            let features = tree.get(id).features;
            self.evicted_in_range += features.evicted;
            self.through_in_range += features.through;
            self.cold_spends_in_range += features.cold_spends;
            self.adjacent_cold_in_range += features.adjacent_cold;
            self.grace_spends_in_range += features.grace_spends;
            self.grace_ageing_in_range += features.grace_ageing;
            self.grace_proved_in_range += features.grace_proved;
            self.places_paid_in_range += features.places_paid;
            self.coinbase_only_in_range += usize::from(features.coinbase_only);
            self.pays_nobody_in_range += usize::from(features.pays_nobody);
            self.shared_in_range += features.shared;
        }
    }

    /// What every run of either test has to have reached.
    fn reached_every_kind(&self) {
        assert!(
            self.evicted_in_range > 0
                && self.through_in_range > 0
                && self.cold_spends_in_range > 0
                && self.grace_spends_in_range > 0
                && self.grace_proved_in_range > 0
                && self.places_paid_in_range > 0
                && self.coinbase_only_in_range > 0
                && self.pays_nobody_in_range > 0,
            "the switches undid and applied every kind of block: {self:#?}"
        );
        assert!(
            self.contested > 0 && self.twins > 0,
            "the branches spent some of the same notes differently, and created some of \
             the same notes: {self:#?}"
        );
        assert!(
            self.adjacent_cold_in_range > 0 && self.grace_ageing_in_range > 0,
            "blocks emptied neighbouring places, and spent notes out of a landing the \
             same block aged off the window: {self:#?}"
        );
        assert!(
            self.failed > 0 && self.failed_after_applying > 0,
            "switches failed, and some only after applying part of the new branch: {self:#?}"
        );
        assert!(
            self.undo_checks > 0 && self.records_compared > 0,
            "undo records were read back and compared: {self:#?}"
        );
    }
}

/// What a store holds, down to the ledger each of its undo records would put
/// back and the transfers waiting in its pool.
#[derive(Debug, PartialEq, Eq)]
struct Everything {
    chain: ChainFields,
    ledger: Print,
    pool: Vec<Hash32>,
    pool_bytes: usize,
    undone: Vec<Print>,
}

/// One tree fed to some stores, and the checks every step of that answers to.
struct Run<'t> {
    params: ConsensusParams,
    tree: &'t Tree,
    reached: &'t mut Reached,
    /// What a fresh store says about its branch at each block, filled one
    /// replayed branch at a time.
    fresh: HashMap<Hash32, ChainFields>,
    /// The ledger a replay to each block gives, for each kind of node. A
    /// replay does not change, so it is printed once.
    replays: HashMap<(Hash32, bool), Print>,
    label: String,
    /// Blocks this run made that no branch holds, counted so no two of them
    /// are ever the same block.
    made_up: u64,
}

impl<'t> Run<'t> {
    fn new(
        params: ConsensusParams,
        tree: &'t Tree,
        reached: &'t mut Reached,
        label: String,
    ) -> Self {
        reached.trees += 1;
        reached.contested += tree.contested();
        reached.twins += tree.twins();
        Self {
            params,
            tree,
            reached,
            fresh: HashMap::new(),
            replays: HashMap::new(),
            label,
            made_up: 0,
        }
    }

    fn play(&mut self, node: &mut Node, steps: &[Step], rng: &mut Rng) {
        for step in steps {
            match *step {
                Step::Deliver(id) => self.deliver(node, id),
                Step::Break(parent) => self.break_a_switch(node, parent, rng),
            }
        }
    }

    fn deliver(&mut self, node: &mut Node, id: Hash32) {
        let tree = self.tree;
        let mined = tree.get(&id);
        let before_tip = node.store.tip();
        let before_root = node.store.state().state_root();
        let outcome = node.store.add_block(mined.block.clone(), NOW);
        self.reached.delivered += 1;
        let why = format!(
            "{}: {} given the block at height {} ({id})",
            self.label, node.name, mined.height
        );
        match outcome {
            Ok(Accepted::Extended) => {
                assert_eq!(node.store.tip(), Some(id), "{why}: it extended elsewhere");
                if mined.height + 1 >= tree.base {
                    self.check_ledger(node, &why);
                }
            }
            Ok(Accepted::SideBranch) => {
                assert_eq!(
                    node.store.tip(),
                    before_tip,
                    "{why}: a side block moved the tip"
                );
                assert_eq!(
                    node.store.state().state_root(),
                    before_root,
                    "{why}: a side block moved the ledger"
                );
            }
            Ok(Accepted::Reorganised { removed, added }) => {
                assert_eq!(node.store.tip(), Some(id), "{why}: it switched elsewhere");
                self.reached.switched(tree, &removed, &added);
                let why = format!(
                    "{why}, which undid {} blocks and applied {}",
                    removed.len(),
                    added.len()
                );
                self.check_switch(node, &why);
            }
            Ok(Accepted::Duplicate) => panic!("{why}: offered once, taken as a duplicate"),
            Err(ChainError::TooOld { .. } | ChainError::UnknownParent(_))
                if !tree.winning.contains(&id) =>
            {
                self.reached.turned_away += 1;
                assert_eq!(
                    node.store.tip(),
                    before_tip,
                    "{why}: a refusal moved the tip"
                );
                assert_eq!(
                    node.store.state().state_root(),
                    before_root,
                    "{why}: a refusal moved the ledger"
                );
            }
            Err(refused) => panic!("{why}: refused, {refused}"),
        }
    }

    /// The ledger a fresh node of the given kind holds after replaying the
    /// branch to `id` from the first block.
    fn replay(&mut self, id: Hash32, archiving: bool) -> &Print {
        let tree = self.tree;
        self.replays.entry((id, archiving)).or_insert_with(|| {
            let after = &tree.get(&id).after;
            print(if archiving {
                &after.archive
            } else {
                &after.plain
            })
        })
    }

    /// The ledger is the one a fresh node of the same kind holds after
    /// replaying the branch from the first block.
    fn check_ledger(&mut self, node: &Node, why: &str) {
        let tip = node.store.tip().unwrap();
        let found = print(node.store.state());
        same(
            &found,
            self.replay(tip, node.archiving),
            &format!("{why}: the ledger is not the one a replay of its branch gives"),
        );
    }

    /// Everything after a switch: the ledger, what the store says about its
    /// branch, the ledger every undo record it holds would put back, and the
    /// records themselves.
    fn check_switch(&mut self, node: &mut Node, why: &str) {
        let tree = self.tree;
        self.check_ledger(node, why);
        let tip = node.store.tip().unwrap();
        let expected = self.fresh_fields(tip).clone();
        same(
            &chain_fields(&node.store),
            &expected,
            &format!("{why}: the store says something about its branch a fresh one does not"),
        );
        let height = node.store.height().unwrap();
        for at in tree.base - 1..height {
            let undone = node.store.ledger_at(at).unwrap_or_else(|| {
                panic!("{why}: no ledger at height {at}, so a record it needs is missing")
            });
            let id = node.store.id_at(at).unwrap();
            same(
                &print(&undone),
                self.replay(id, node.archiving),
                &format!(
                    "{why}: undoing its records down to height {at} lands somewhere a \
                     replay to that height does not"
                ),
            );
            self.reached.undo_checks += 1;
        }
        if let Some(mirror) = node.mirror.as_mut() {
            mirror.follow(&node.store, tree, &self.params);
            same(
                &print(&mirror.state),
                &print(node.store.state()),
                &format!("{why}: the ledger level mirror of its branch holds something else"),
            );
            for (id, record) in &mirror.applied {
                let mined = tree.get(id);
                if mined.height < tree.base {
                    continue;
                }
                same_text(
                    &format!("{record:?}"),
                    &format!("{:?}", mined.record),
                    &format!(
                        "{why}: the record for the block at height {} is not the one a \
                         replay wrote",
                        mined.height
                    ),
                );
                self.reached.records_compared += 1;
            }
        }
    }

    /// What a fresh store says about its branch once it has replayed it to
    /// `tip` from the first block.
    fn fresh_fields(&mut self, tip: Hash32) -> &ChainFields {
        if !self.fresh.contains_key(&tip) {
            let tree = self.tree;
            let end = tree.end_through(tip);
            let mut store = ChainStore::new(self.params);
            store.watch_owner(watched());
            for id in tree.path(end) {
                let mined = tree.get(&id);
                store
                    .add_block(mined.block.clone(), NOW)
                    .expect("a fresh store takes a branch given in order");
                if mined.height + 1 >= tree.base {
                    self.fresh.insert(id, chain_fields(&store));
                }
            }
            let found = print(store.state());
            same(
                &found,
                self.replay(end, false),
                "a fresh store's ledger is the one this file compares against",
            );
        }
        &self.fresh[&tip]
    }

    /// Everything a failed switch must leave as it was, the pool included.
    fn everything(&self, node: &Node) -> Everything {
        let height = node.store.height().unwrap();
        Everything {
            chain: chain_fields(&node.store),
            ledger: print(node.store.state()),
            pool: node.store.pooled_transfers().map(|(id, _)| *id).collect(),
            pool_bytes: node.store.pool_bytes(),
            undone: (self.tree.base - 1..height)
                .map(|at| print(&node.store.ledger_at(at).unwrap()))
                .collect(),
        }
    }

    /// A block that fails on application, built on `above`: an honest child
    /// of it with one thing broken, or a coinbase alone with a wrong root.
    fn broken_child(&mut self, above: &Mined, rng: &mut Rng) -> Block {
        let mut children: Vec<&Mined> = self
            .tree
            .mined
            .values()
            .filter(|mined| mined.parent == above.id)
            .collect();
        children.sort_by_key(|mined| mined.id);
        let mut block = if let Some(child) = rng.pick(&children) {
            child.block.clone()
        } else {
            let height = above.height + 1;
            let coinbase = CoinbaseTransaction::with_extra(
                height,
                vec![Note::new(
                    self.params.reward_at(height),
                    wallets().addresses[0],
                )],
                b"broken".to_vec(),
            );
            assemble_block(
                &above.after.archive,
                coinbase,
                Vec::new(),
                &self.params,
                1_000 + SPACING * (height + 1),
                0,
            )
            .expect("a coinbase alone is a valid block")
        };
        let mut kinds = vec!["state root", "coinbase overpays"];
        if !block.transfers.is_empty() {
            kinds.push("signature");
        }
        if block.transfers.iter().flat_map(|t| &t.inputs).any(|input| {
            matches!(&input.witness, Witness::Cold(cold) if !cold.proof.siblings.is_empty())
        }) {
            kinds.push("proof");
        }
        let kind = *rng.pick(&kinds).unwrap();
        match kind {
            "state root" => {
                let mut bytes = block.header.state_root.to_bytes();
                bytes[0] ^= 1;
                block.header.state_root = Hash32::from_bytes(bytes);
            }
            "coinbase overpays" => {
                let more = self.params.reward_at(block.header.height);
                match block.coinbase.outputs.first_mut() {
                    Some(first) => first.value = first.value.checked_add(more).unwrap(),
                    None => block.coinbase.outputs.push(Note::new(
                        more.checked_add(more).unwrap(),
                        wallets().addresses[0],
                    )),
                }
            }
            "signature" => {
                let at = rng.below(block.transfers.len());
                block.transfers[at].inputs[0].signature = Signature::from_bytes(&[7; 64]);
            }
            _ => {
                let cold = block
                    .transfers
                    .iter_mut()
                    .flat_map(|t| t.inputs.iter_mut())
                    .find_map(|input| match &mut input.witness {
                        Witness::Cold(cold) if !cold.proof.siblings.is_empty() => Some(cold),
                        _ => None,
                    })
                    .unwrap();
                let mut bytes = cold.proof.siblings[0].to_bytes();
                bytes[0] ^= 1;
                cold.proof.siblings[0] = Hash32::from_bytes(bytes);
            }
        }
        // The header names the body, so the door lets the block in and only
        // applying it finds what is wrong. The nonce makes it a block this
        // store has never refused, which the same break of the same child
        // would otherwise be the second time it was drawn.
        block.header.transactions_root = block.transactions_root();
        self.made_up += 1;
        block.header.nonce = u64::MAX - self.made_up;
        *self.reached.failed_kinds.entry(kind).or_default() += 1;
        block
    }

    /// A block nobody will ever apply, there to make a branch heavier.
    fn filler(&mut self, parent: &BlockHeader) -> Block {
        self.made_up += 1;
        let height = parent.height + 1;
        let mut block = Block {
            header: BlockHeader {
                previous: parent.id(),
                height,
                transactions_root: Hash32::ZERO,
                timestamp: parent.timestamp + SPACING,
                total_work: parent.total_work + u128::from(parent.difficulty),
                nonce: 0,
                ..*parent
            },
            coinbase: CoinbaseTransaction::with_extra(
                height,
                Vec::new(),
                self.made_up.to_le_bytes().to_vec(),
            ),
            transfers: Vec::new(),
        };
        block.header.transactions_root = block.transactions_root();
        block
    }

    /// A switch onto a branch through `parent` that fails on the block above
    /// it, after undoing the branch followed down to where they meet and
    /// applying every block of the new one up to `parent`. It has to leave the
    /// store exactly as it found it.
    fn break_a_switch(&mut self, node: &mut Node, parent: Hash32, rng: &mut Rng) {
        let tree = self.tree;
        let tip = node.store.height().unwrap();
        if !node.store.contains(&parent) {
            return;
        }
        let above = tree.get(&parent);
        let mut fork = above;
        while node.store.id_at(fork.height) != Some(fork.id) {
            fork = tree.get(&fork.parent);
        }
        let depth = tip - fork.height;
        if depth > LIMIT || above.height < tip.saturating_sub(LIMIT) {
            return;
        }
        let mut blocks = vec![self.broken_child(above, rng)];
        while blocks.last().unwrap().header.height <= tip {
            let header = blocks.last().unwrap().header;
            blocks.push(self.filler(&header));
        }
        let broken = blocks[0].id();
        let before = self.everything(node);
        let why = format!(
            "{}: {} given a branch through height {} that breaks at height {}, \
             {depth} below its tip",
            self.label,
            node.name,
            above.height,
            above.height + 1
        );
        let last = blocks.len() - 1;
        for (index, block) in blocks.into_iter().enumerate() {
            let outcome = node.store.add_block(block, NOW);
            if index < last {
                assert_eq!(
                    outcome,
                    Ok(Accepted::SideBranch),
                    "{why}: a block of it did not wait aside"
                );
                continue;
            }
            assert!(
                matches!(&outcome, Err(ChainError::InvalidBlock { id, .. }) if *id == broken),
                "{why}: the switch did not fail on the broken block: {outcome:?}"
            );
        }
        same(
            &self.everything(node),
            &before,
            &format!("{why}: the failed switch moved the store"),
        );
        self.reached.failed += 1;
        *self.reached.failed_depths.entry(depth).or_default() += 1;
        if above.height > fork.height {
            self.reached.failed_after_applying += 1;
        }
    }

    /// Every store is on the winning tip, holds what a replay gives, and
    /// holds what every other store holds, at the tip and at every height a
    /// record can take it back to.
    fn level(&mut self, nodes: &mut [Node]) {
        let tree = self.tree;
        for node in nodes.iter_mut() {
            assert_eq!(
                node.store.tip(),
                Some(tree.winner),
                "{}: {} ended on a block other than the heaviest",
                self.label,
                node.name
            );
            self.check_switch(node, &format!("{}: {} at the end", self.label, node.name));
        }
        let (first, rest) = nodes.split_first().unwrap();
        let height = first.store.height().unwrap();
        let first_print = print(first.store.state());
        for other in rest {
            let why = format!(
                "{}: {} and {} were given the same blocks in different orders",
                self.label, first.name, other.name
            );
            let other_print = print(other.store.state());
            same(
                &chain_fields(&other.store),
                &chain_fields(&first.store),
                &why,
            );
            same(&other_print.common, &first_print.common, &why);
            for at in tree.base - 1..height {
                same(
                    &print(&other.store.ledger_at(at).unwrap()).common,
                    &print(&first.store.ledger_at(at).unwrap()).common,
                    &format!("{why}, and undo to different ledgers at height {at}"),
                );
            }
            // An archivist proves every place and a plain node only those it
            // keeps paths for, so those two halves are compared within a kind.
            if first.archiving == other.archiving {
                same(&other_print, &first_print, &why);
            }
            self.reached.levelled += 1;
        }
    }
}

/// Every depth from one to the undo limit, back and forth between two
/// branches, each switch one block deeper than the last, with a switch that
/// fails partway before each real one. The same two branches go to an
/// archivist in another back and forth, and to two more stores whole and
/// scattered, and all four have to end holding the same ledger.
#[test]
fn every_depth_up_to_the_limit_back_and_forth() {
    let campaign = Campaign::named("chain: every depth back and forth");
    let params = params();
    assert_eq!(
        ChainStore::new(params).undo_limit(),
        LIMIT,
        "the rules this file sets are the undo limit it walks to"
    );
    let seed = campaign.seed();
    let mut reached = Reached::default();
    let ran = campaign.run(SWEEPS, |case, rng| {
        let tip = PREFIX - 1;
        let tree = Tree::grow(
            &[
                (Fork::Prefix(tip), LIMIT as usize + 1),
                (Fork::Prefix(tip), LIMIT as usize),
            ],
            rng,
            &params,
        );
        let label = format!("depth sweep, case {case} of seed {seed:#x}");
        let mut run = Run::new(params, &tree, &mut reached, label.clone());
        let mut nodes = vec![
            Node::new(
                "a plain node switching at every depth from one",
                false,
                params,
            ),
            Node::new(
                "an archivist switching at every depth from two",
                true,
                params,
            ),
            Node::new("a plain node given the losing branch first", false, params),
            Node::new("a plain node given the blocks scattered", false, params),
        ];
        let orders = [
            ping_pong(&tree, 0, 1, 1, Some(&mut *rng)),
            ping_pong(&tree, 1, 0, 2, Some(&mut *rng)),
            branch_after_branch(&tree, &[1, 0]),
            scattered(&tree, rng),
        ];
        let before = run.reached.switches.clone();
        run.play(&mut nodes[0], &orders[0], rng);
        for depth in 1..=LIMIT as usize {
            assert_eq!(
                run.reached.switches.get(&depth).copied().unwrap_or(0),
                before.get(&depth).copied().unwrap_or(0) + 1,
                "{label}: the first store switched once at each depth up to the limit, \
                 and not once at depth {depth}"
            );
        }
        for (node, steps) in nodes.iter_mut().zip(&orders).skip(1) {
            run.play(node, steps, rng);
        }
        run.level(&mut nodes);
    });
    eprintln!(
        "depth sweep reached {reached:#?}\nempty archivist rows dropped so far: {}",
        EMPTY_ROWS.load(Ordering::Relaxed)
    );
    assert_eq!(
        reached.switches.keys().copied().collect::<Vec<_>>(),
        (1..=LIMIT as usize).collect::<Vec<_>>(),
        "switches went to every depth up to the limit and no deeper"
    );
    // A replay of one case asks for fewer than this, and says nothing about
    // coverage.
    if ran.cases >= SWEEPS {
        reached.reached_every_kind();
        assert!(
            reached.failed_depths.keys().any(|depth| *depth == LIMIT),
            "a switch failed partway at the undo limit itself: {reached:#?}"
        );
    }
}

/// Random trees fed to a plain node and an archivist in two different storms
/// and to a third store scattered, with switches built to fail thrown in, all
/// checked against a replay at every step and against each other at the end.
#[test]
fn a_reorganisation_storm_leaves_every_node_with_the_ledger_a_replay_gives() {
    let campaign = Campaign::named("chain: reorganisation storm");
    let params = params();
    let seed = campaign.seed();
    let mut reached = Reached::default();
    let ran = campaign.run(QUICK, |case, rng| {
        let specs = random_specs(rng);
        let tree = Tree::grow(&specs, rng, &params);
        let mut run = Run::new(
            params,
            &tree,
            &mut reached,
            format!("case {case} of seed {seed:#x}, branches {specs:?}"),
        );
        let mut nodes = vec![
            Node::new("a plain node in a storm", false, params),
            Node::new("an archivist in another storm", true, params),
            Node::new("a plain node given the blocks scattered", false, params),
        ];
        let orders = [storm(&tree, rng), storm(&tree, rng), scattered(&tree, rng)];
        for (node, steps) in nodes.iter_mut().zip(&orders) {
            run.play(node, steps, rng);
        }
        run.level(&mut nodes);
    });
    eprintln!(
        "storm reached {reached:#?}\nempty archivist rows dropped so far: {}",
        EMPTY_ROWS.load(Ordering::Relaxed)
    );
    // A replay of one case asks for fewer than this, and says nothing about
    // coverage.
    if ran.cases >= QUICK {
        reached.reached_every_kind();
        assert!(
            reached.switches.len() >= 3,
            "the storms switched at several depths: {reached:#?}"
        );
    }
}

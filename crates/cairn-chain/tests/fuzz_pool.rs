//! The pool, under transfers and blocks interleaved at random.
//!
//! `tests/pool.rs` and the audits beside it each build the moment they ask
//! about: a replacement, a full pool, a note that falls under a pooled spend,
//! one reorganisation. The pool's life is those moments in any order, and
//! the testnet-8 attack catalogue names the gap (pool sequences under
//! evictions, staleness and replacement, F02, F03, G04, G05).
//!
//! Each case plays a chain forward on a hot set of twelve notes, so the notes
//! a pooled transfer spends fall out of the tier, through the grace window
//! and into the cold set while it waits, and between blocks it offers
//! transfers: valid ones from every tier, ones spending the oldest hot notes,
//! replacements that pay enough and ones that do not, ones under the floor or
//! under the burn of their places, forgeries, spends of notes already spent,
//! and transfers offered before. Blocks are built from the pool's own
//! selection, from transfers the pool refused, empty, or in a long quiet run;
//! some cases switch to a rival branch that carries double spends of what the
//! abandoned blocks carried, and some switch back.
//!
//! After every step, against the ledger the tip commits to as this file
//! builds it rather than against anything the pool says about itself:
//!
//! 1. No two pooled transfers spend the same note.
//! 2. Nothing pooled is invalid against the tip: each pooled transfer passes
//!    the consensus check, and the next block can carry it on its own.
//! 3. The pool's own bounds hold. Its count and its bytes are within
//!    `MAX_POOLED` and `MAX_POOL_BYTES`, its byte count is the sum of
//!    `pooled_cost`, its index of spent notes and its index by rate are the
//!    pool, and every transfer in it pays the pool's floor for the places it
//!    takes now and fits what a block has room for.
//! 4. What the pool offers a miner is a block: `selection` builds and
//!    connects, and the fees it claims are what the transfers it chose leave.
//! 5. A refused transfer changes nothing, and an accepted one displaces only
//!    what it conflicts with.
//! 6. After a switch, a transfer the abandoned blocks carried is back in the
//!    pool if the pool would take it: offering it again is answered as known
//!    or refused, never taken as new. And when the store switches back, the
//!    blocks it reconnects leave nothing in the pool that they spend, which
//!    is property 2 again on the reconnected tip.
//!
//! The pool is never filled to its ceiling here: four thousand pooled
//! transfers a case is more notes than a case can afford to make. The
//! ceilings are still checked at every step, and what happens at them is
//! `tests/pool.rs` and `audit_fee_market.rs`.
//!
//! A failing case is cut down to the shortest run of steps that still breaks
//! the same property and written under `target/fuzz/`, beside the record
//! `Campaign` keeps.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

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
use std::fmt::Write as _;
use std::path::PathBuf;

use cairn_chain::{
    fee_floor, must_make_room, places_taken, pooled_cost, Accepted, ChainStore, MAX_POOLED,
    MAX_POOL_BYTES,
};
use cairn_crypto::SecretKey;
use cairn_fuzz::{Campaign, Rng};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Address, Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, check_transfer, connect_block, ConsensusParams, PLACE_PRICE,
};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

/// Past every timestamp here, so the clock never stands between a block and
/// its verdict.
const NOW: u64 = 4_000_000_000;

/// Ten target block times, which keeps the difficulty on the floor: every
/// block is worth one, and a rival wins by being longer.
const SPACING: u64 = 600;

/// The blocks every case starts from a prefix of: past the twelve the hot
/// set holds and the sixty four the grace window keeps, so the oldest
/// rewards are in the cold set and spending them takes a proof.
const BASE: usize = 96;

const CAMPAIGN: &str = "chain: pool under sequences";

/// The rules: a hot set of twelve so notes fall within a few blocks, four
/// evictions a block, rewards spendable two blocks on, the place price a
/// public network charges, and a coinbase of one note so a block keeps room
/// for transfers that take places.
fn rules() -> ConsensusParams {
    let mut params = ConsensusParams::testnet()
        .with_hot_capacity(12)
        .with_max_evictions(4)
        .with_coinbase_maturity(2)
        .with_place_price(PLACE_PRICE);
    params.max_coinbase_outputs = 1;
    params
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// A block built here, and the ledger it leaves.
#[derive(Clone, Debug)]
struct Built {
    block: Block,
    parent: Option<Hash32>,
    after: LedgerState,
}

/// A note one of the four wallets owns.
#[derive(Clone, Copy, Debug)]
struct Owned {
    id: NoteId,
    note: Note,
    owner: u8,
}

/// Every block built in a case, on every branch, and every note they paid
/// to a wallet.
#[derive(Clone, Debug)]
struct World {
    params: ConsensusParams,
    built: HashMap<Hash32, Built>,
    genesis: Hash32,
    owned: Vec<Owned>,
    known_notes: BTreeSet<NoteId>,
    addresses: Vec<(Address, u8)>,
}

impl World {
    fn new() -> Self {
        let params = rules();
        let addresses = (1..=4)
            .map(|seed| (Address::from(wallet(seed).public_key()), seed))
            .collect();
        let mut world = Self {
            params,
            built: HashMap::new(),
            genesis: Hash32::ZERO,
            owned: Vec::new(),
            known_notes: BTreeSet::new(),
            addresses,
        };
        let first = world
            .assemble(
                &LedgerState::archiving(),
                1_000_000,
                Vec::new(),
                Amount::ZERO,
                0,
            )
            .unwrap();
        world.genesis = world.record(first, None);
        world
    }

    fn state(&self, id: &Hash32) -> &LedgerState {
        &self.built[id].after
    }

    /// The block after `state`, paying its reward and `claim` to a wallet.
    fn assemble(
        &self,
        state: &LedgerState,
        timestamp: u64,
        transfers: Vec<Transfer>,
        claim: Amount,
        salt: u64,
    ) -> Option<Block> {
        let height = state.next_height()?;
        let paid = self.params.reward_at(height).checked_add(claim)?;
        let coinbase = CoinbaseTransaction::with_extra(
            height,
            vec![Note::new(paid, wallet(1 + (height % 4) as u8).public_key())],
            salt.to_le_bytes().to_vec(),
        );
        // The difficulty is one, which every identifier meets.
        assemble_block(state, coinbase, transfers, &self.params, timestamp, 0).ok()
    }

    /// Files a block, and every note it pays a wallet.
    fn record(&mut self, block: Block, parent: Option<Hash32>) -> Hash32 {
        let id = block.id();
        let mut after = parent.map_or_else(LedgerState::archiving, |parent| {
            self.built[&parent].after.clone()
        });
        connect_block(&mut after, &block, &self.params, NOW).expect("a block built here is valid");
        let mut created = block.coinbase.created_notes();
        for transfer in &block.transfers {
            created.extend(transfer.created_notes());
        }
        for (note_id, note) in created {
            if let Some((_, owner)) = self.addresses.iter().find(|(at, _)| *at == note.owner) {
                if self.known_notes.insert(note_id) {
                    self.owned.push(Owned {
                        id: note_id,
                        note,
                        owner: *owner,
                    });
                }
            }
        }
        self.built.insert(
            id,
            Built {
                block,
                parent,
                after,
            },
        );
        id
    }

    /// Builds and files the block after `parent`.
    fn extend(
        &mut self,
        parent: Hash32,
        transfers: Vec<Transfer>,
        claim: Amount,
        salt: u64,
    ) -> Option<Hash32> {
        let built = &self.built[&parent];
        let timestamp = built.block.header.timestamp + SPACING;
        let block = self.assemble(&built.after, timestamp, transfers, claim, salt)?;
        Some(self.record(block, Some(parent)))
    }

    /// The same, keeping each candidate only if the block still builds with
    /// it.
    fn extend_with_what_fits(
        &mut self,
        parent: Hash32,
        candidates: Vec<Transfer>,
        salt: u64,
    ) -> Hash32 {
        let built = &self.built[&parent];
        let timestamp = built.block.header.timestamp + SPACING;
        let mut carried: Vec<Transfer> = Vec::new();
        for candidate in candidates {
            if carried.iter().any(|already| already.id() == candidate.id()) {
                continue;
            }
            let mut trying = carried.clone();
            trying.push(candidate);
            if self
                .assemble(&built.after, timestamp, trying.clone(), Amount::ZERO, salt)
                .is_some()
            {
                carried = trying;
            }
        }
        self.extend(parent, carried, Amount::ZERO, salt)
            .expect("the block was just built with these")
    }

    /// The block `depth` below `tip` on its branch.
    fn below(&self, tip: Hash32, depth: u64) -> Hash32 {
        let mut at = tip;
        for _ in 0..depth {
            at = self.built[&at].parent.unwrap_or(at);
        }
        at
    }
}

/// Where a note sits at a ledger, as far as spending it goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    /// In the hot set, created at this height: the lowest fall first.
    Hot(u64),
    /// Fallen within the grace window: a hot witness still spends it.
    Grace,
    /// In the cold set: spending it takes a proof.
    Cold,
}

/// A note a wallet holds at `state`, the input that spends it, and its tier.
fn spendable(world: &World, state: &LedgerState) -> Vec<(Owned, Input, Tier)> {
    let mut found = Vec::new();
    for owned in &world.owned {
        if let Some(entry) = state.hot_entry(&owned.id) {
            found.push((*owned, Input::hot(owned.id), Tier::Hot(entry.height)));
        } else if state.within_grace(&owned.id).is_some() {
            found.push((*owned, Input::hot(owned.id), Tier::Grace));
        } else if let Some(position) = state.cold().locate(&owned.id, &owned.note) {
            if let Some(proof) = state.cold().prove(position) {
                found.push((
                    *owned,
                    Input::cold(owned.id, owned.note, position, proof),
                    Tier::Cold,
                ));
            }
        }
    }
    found
}

/// How a transfer's fee is set against the floor its bytes and places owe.
#[derive(Clone, Copy, Debug)]
enum Fee {
    Above(u64),
    BelowTheFloor,
    BelowTheBurn,
    Exactly(u64),
}

/// A transfer spending `inputs` to `payees`, signed by `signer` when given
/// and by each note's owner otherwise.
fn spend(
    params: &ConsensusParams,
    inputs: &[(Owned, Input, Tier)],
    payees: &[u8],
    fee: Fee,
    signer: Option<u8>,
) -> Option<Transfer> {
    if inputs.is_empty() || payees.is_empty() {
        return None;
    }
    let total: u64 = inputs
        .iter()
        .map(|(owned, _, _)| owned.note.value.as_pebbles())
        .sum();
    let draft = Transfer::new(
        inputs.iter().map(|(_, input, _)| input.clone()).collect(),
        payees
            .iter()
            .map(|payee| Note::new(pebbles(1), wallet(*payee).public_key()))
            .collect(),
    );
    let bytes = draft.encode().len();
    let freed = inputs
        .iter()
        .filter(|(_, _, tier)| matches!(tier, Tier::Hot(_)))
        .count();
    let places = places_taken(&draft, freed);
    let floor = fee_floor(bytes, places, params).as_pebbles();
    let burn = params.burn_for(places)?.as_pebbles();
    let fee = match fee {
        Fee::Above(extra) => floor.checked_add(extra)?,
        Fee::BelowTheFloor => floor.checked_sub(1)?,
        Fee::BelowTheBurn => burn.checked_sub(1)?,
        Fee::Exactly(fee) => fee,
    };
    let shared = total.checked_sub(fee)?;
    let count = payees.len() as u64;
    if shared < count {
        return None;
    }
    let each = shared / count;
    let first = shared - each * (count - 1);
    let outputs = payees
        .iter()
        .enumerate()
        .map(|(index, payee)| {
            let value = if index == 0 { first } else { each };
            Note::new(pebbles(value), wallet(*payee).public_key())
        })
        .collect();
    let mut transfer = Transfer::new(draft.inputs, outputs);
    for (index, (owned, _, _)) in inputs.iter().enumerate() {
        transfer.sign_input(
            params.network,
            u32::try_from(index).unwrap(),
            &owned.note,
            &wallet(signer.unwrap_or(owned.owner)),
        );
    }
    Some(transfer)
}

/// What a fee drawn above the floor adds to it.
fn extra(rng: &mut Rng) -> u64 {
    *rng.pick(&[0, 1, 100, 10_000, 1_000_000, 50_000_000])
        .unwrap()
}

/// Who a transfer pays: one to three notes, and one time in four four or
/// five, which is more places than a block on a full tier has for transfers
/// once the notes it spends have fallen.
fn payees(rng: &mut Rng) -> Vec<u8> {
    let count = if rng.chance(4) {
        rng.between(4, 5)
    } else {
        rng.between(1, 3)
    };
    (0..count).map(|_| 1 + rng.below(4) as u8).collect()
}

/// One thing done to the store.
#[derive(Clone, Debug)]
enum Step {
    /// A transfer offered to the pool, and how it was made.
    Offer {
        transfer: Transfer,
        kind: &'static str,
    },
    /// A block of the world handed to the store.
    Deliver(Hash32),
}

/// A property that did not hold, and where.
#[derive(Clone, Debug)]
struct Failure {
    property: &'static str,
    step: usize,
    said: String,
}

/// What the runs saw, for the campaign to report and to hold a floor on.
#[derive(Debug, Default)]
struct Tally {
    offered: BTreeMap<&'static str, usize>,
    answers: BTreeMap<String, usize>,
    /// Accepted transfers that took the place of one or more pooled ones.
    replaced: usize,
    /// Pooled transfers a block let go of without carrying them.
    dropped_as_stale: usize,
    /// Transfers an abandoned block carried, found back in the pool.
    put_back: usize,
    /// Transfers an abandoned block carried, offered again after the switch.
    asked_again: usize,
    switches: usize,
    pooled_from: BTreeMap<&'static str, usize>,
    deepest_pool: usize,
}

/// The name of an answer, without what it carries.
fn kind_of<T: std::fmt::Debug, E: std::fmt::Debug>(answer: &Result<T, E>) -> String {
    let named = |said: String| {
        let end = said.find([' ', '(', '{']).unwrap_or(said.len());
        said[..end].to_owned()
    };
    match answer {
        Ok(value) => format!("Ok({})", named(format!("{value:?}"))),
        Err(refused) => named(format!("{refused:?}")),
    }
}

/// The pool, as it can be compared.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pool {
    transfers: BTreeMap<Hash32, Transfer>,
    bytes: usize,
}

fn pool_of(store: &ChainStore) -> Pool {
    Pool {
        transfers: store
            .pooled_transfers()
            .map(|(id, transfer)| (*id, transfer.clone()))
            .collect(),
        bytes: store.pool_bytes(),
    }
}

/// Properties 1 to 4, against the ledger the tip commits to.
fn check(
    world: &World,
    store: &ChainStore,
    step: usize,
    tally: &mut Option<&mut Tally>,
) -> Result<(), Failure> {
    let fail = |property: &'static str, said: String| Failure {
        property,
        step,
        said,
    };
    let params = &world.params;
    let Some(tip) = store.tip() else {
        if store.pool_len() > 0 {
            return Err(fail(
                "nothing pooled is invalid against the tip",
                format!("no chain, and {} transfers pooled", store.pool_len()),
            ));
        }
        return Ok(());
    };
    let Some(built) = world.built.get(&tip) else {
        return Err(fail(
            "the store follows a block built here",
            format!("the tip {tip:?} is no block this case built"),
        ));
    };
    let state = &built.after;
    if store.state().state_root() != state.state_root() {
        return Err(fail(
            "the store follows a block built here",
            "the store's ledger is not the one its tip commits to".to_owned(),
        ));
    }

    // 1. No note spoken for twice.
    let pooled: Vec<(Hash32, Transfer)> = store
        .pooled_transfers()
        .map(|(id, transfer)| (*id, transfer.clone()))
        .collect();
    let mut spoken: BTreeMap<NoteId, Hash32> = BTreeMap::new();
    for (id, transfer) in &pooled {
        if transfer.id() != *id {
            return Err(fail(
                "the pool's own bounds hold",
                format!(
                    "a transfer is filed under {id:?} and is {:?}",
                    transfer.id()
                ),
            ));
        }
        for input in &transfer.inputs {
            if let Some(other) = spoken.insert(input.note_id, *id) {
                return Err(fail(
                    "no two pooled transfers spend the same note",
                    format!(
                        "{:?} is spent by pooled {other:?} and by pooled {id:?}",
                        input.note_id
                    ),
                ));
            }
        }
    }

    // 3. The pool's own bounds and its indexes.
    let spenders: BTreeMap<NoteId, Hash32> = store
        .pooled_spenders()
        .map(|(note, id)| (*note, *id))
        .collect();
    if spenders != spoken {
        return Err(fail(
            "the pool's own bounds hold",
            format!(
                "the index of spent notes names {} notes and the pool spends {}",
                spenders.len(),
                spoken.len()
            ),
        ));
    }
    let rates: BTreeSet<(u128, Hash32)> = store.pooled_rates().map(|(id, at)| (at, *id)).collect();
    let index: BTreeSet<(u128, Hash32)> =
        store.pooled_by_rate().map(|(at, id)| (at, *id)).collect();
    if rates != index {
        return Err(fail(
            "the pool's own bounds hold",
            "the index by rate is not the pool's own rates".to_owned(),
        ));
    }
    let cost: usize = pooled
        .iter()
        .map(|(_, transfer)| pooled_cost(transfer.encode().len(), transfer.inputs.len()))
        .sum();
    if store.pool_len() > MAX_POOLED
        || store.pool_bytes() > MAX_POOL_BYTES
        || cost != store.pool_bytes()
        || pooled.len() != store.pool_len()
    {
        return Err(fail(
            "the pool's own bounds hold",
            format!(
                "{} pooled and {} bytes counted, against {MAX_POOLED} and {MAX_POOL_BYTES}, \
                 and the transfers held cost {cost}",
                store.pool_len(),
                store.pool_bytes()
            ),
        ));
    }

    // 2, and the rest of 3: each pooled transfer against the tip.
    let room = ChainStore::room_for_transfers(params.max_block_bytes);
    let places_left = store.places_for_transfers();
    let timestamp = built.block.header.timestamp + SPACING;
    let mut kept = BTreeMap::new();
    for (id, transfer) in &pooled {
        let outcome = check_transfer(transfer, state, &BTreeSet::new(), &BTreeMap::new(), params)
            .map_err(|refused| {
            fail(
                "nothing pooled is invalid against the tip",
                format!("pooled {id:?} is refused by consensus at the tip: {refused:?}"),
            )
        })?;
        if world
            .assemble(state, timestamp, vec![transfer.clone()], Amount::ZERO, 0)
            .is_none()
        {
            return Err(fail(
                "nothing pooled is invalid against the tip",
                format!("pooled {id:?} cannot be carried by the next block on its own"),
            ));
        }
        let bytes = transfer.encode().len();
        let places = places_taken(transfer, outcome.spent_hot.len());
        let floor = fee_floor(bytes, places, params);
        if outcome.fee < floor || places > places_left || bytes > room {
            return Err(fail(
                "the pool's own bounds hold",
                format!(
                    "pooled {id:?} pays {:?} against a floor of {floor:?} now, takes {places} \
                     places of {places_left} and {bytes} bytes of {room}",
                    outcome.fee
                ),
            ));
        }
        kept.insert(*id, outcome.fee.checked_sub(outcome.burn).unwrap());
        if let Some(tally) = tally {
            for input in &transfer.inputs {
                let from = if state.hot_note(&input.note_id).is_some() {
                    "the hot set"
                } else if state.within_grace(&input.note_id).is_some() {
                    "the grace window"
                } else {
                    "the cold set"
                };
                *tally.pooled_from.entry(from).or_default() += 1;
            }
            tally.deepest_pool = tally.deepest_pool.max(pooled.len());
        }
    }

    // 4. What a miner is offered builds, and claims what it leaves.
    let (chosen, fees) = store.selection(usize::MAX);
    let mut owed = Amount::ZERO;
    for transfer in &chosen {
        let Some(leaves) = kept.get(&transfer.id()) else {
            return Err(fail(
                "what the pool offers a miner is a block",
                format!("selection chose {:?}, which is not pooled", transfer.id()),
            ));
        };
        owed = owed.checked_add(*leaves).unwrap();
    }
    if owed != fees {
        return Err(fail(
            "what the pool offers a miner is a block",
            format!("selection claims {fees:?} for transfers that leave {owed:?}"),
        ));
    }
    let Some(block) = world.assemble(state, timestamp, chosen.clone(), fees, 0) else {
        return Err(fail(
            "what the pool offers a miner is a block",
            format!(
                "the {} transfers selection chose do not build a block",
                chosen.len()
            ),
        ));
    };
    let mut next = state.clone();
    if let Err(refused) = connect_block(&mut next, &block, params, NOW) {
        return Err(fail(
            "what the pool offers a miner is a block",
            format!("the block built from selection is refused: {refused:?}"),
        ));
    }
    Ok(())
}

/// Offers a transfer and holds property 5.
fn offer(
    world: &World,
    store: &mut ChainStore,
    step: usize,
    transfer: &Transfer,
    kind: &'static str,
    tally: &mut Option<&mut Tally>,
) -> Result<(), Failure> {
    let fail = |property: &'static str, said: String| Failure {
        property,
        step,
        said,
    };
    let before = pool_of(store);
    let answer = store.accept_transfer(transfer.clone());
    let after = pool_of(store);
    match &answer {
        Ok(true) => {
            let id = transfer.id();
            let added: Vec<&Hash32> = after
                .transfers
                .keys()
                .filter(|held| !before.transfers.contains_key(*held))
                .collect();
            if added != [&id] {
                return Err(fail(
                    "an accepted transfer displaces only what it conflicts with",
                    format!("{id:?} was accepted and the pool gained {added:?}"),
                ));
            }
            let spends: BTreeSet<NoteId> =
                transfer.inputs.iter().map(|input| input.note_id).collect();
            let full = must_make_room(
                before.transfers.len(),
                before.bytes + pooled_cost(transfer.encode().len(), transfer.inputs.len()),
            );
            let mut displaced = 0usize;
            for (gone, was) in &before.transfers {
                if after.transfers.contains_key(gone) {
                    continue;
                }
                displaced += 1;
                let conflicts = was
                    .inputs
                    .iter()
                    .any(|input| spends.contains(&input.note_id));
                if !conflicts && !full {
                    return Err(fail(
                        "an accepted transfer displaces only what it conflicts with",
                        format!(
                            "{id:?} was accepted into a pool with room and {gone:?}, which \
                             spends nothing it spends, went"
                        ),
                    ));
                }
            }
            if let Some(tally) = tally {
                if displaced > 0 {
                    tally.replaced += 1;
                }
            }
        }
        Ok(false) | Err(_) => {
            if after != before {
                return Err(fail(
                    "a refused transfer changes nothing",
                    format!("answered {answer:?}, and the pool moved"),
                ));
            }
        }
    }
    if let Some(tally) = tally {
        *tally.offered.entry(kind).or_default() += 1;
        *tally.answers.entry(kind_of(&answer)).or_default() += 1;
    }
    check(world, store, step, tally)
}

/// Hands a block over, and after a switch asks the pool again about what the
/// abandoned blocks carried (property 6).
fn deliver(
    world: &World,
    store: &mut ChainStore,
    step: usize,
    id: &Hash32,
    tally: &mut Option<&mut Tally>,
) -> Result<(), Failure> {
    let before = pool_of(store);
    let block = world.built[id].block.clone();
    let answer = store.add_block(block, NOW);
    if let Some(tally) = tally.as_deref_mut() {
        *tally.answers.entry(kind_of(&answer)).or_default() += 1;
    }
    let mut carried: BTreeSet<Hash32> = BTreeSet::new();
    match &answer {
        Ok(Accepted::Extended) => {
            carried.extend(world.built[id].block.transfers.iter().map(Transfer::id));
        }
        Ok(Accepted::Reorganised { removed, added }) => {
            for came in added {
                carried.extend(world.built[came].block.transfers.iter().map(Transfer::id));
            }
            if let Some(tally) = tally.as_deref_mut() {
                tally.switches += 1;
            }
            for gone in removed {
                for transfer in &world.built[gone].block.transfers {
                    if let Some(tally) = tally.as_deref_mut() {
                        tally.asked_again += 1;
                        if store.pooled(&transfer.id()).is_some() {
                            tally.put_back += 1;
                        }
                    }
                    let again = store.accept_transfer(transfer.clone());
                    if again == Ok(true) {
                        return Err(Failure {
                            property: "a transfer a switch undid is offered back to the pool",
                            step,
                            said: format!(
                                "{:?}, carried by {gone:?} which the switch undid, was not in \
                                 the pool afterwards and was taken when offered again",
                                transfer.id()
                            ),
                        });
                    }
                }
            }
        }
        _ => {}
    }
    if let Some(tally) = tally.as_deref_mut() {
        let after = pool_of(store);
        tally.dropped_as_stale += before
            .transfers
            .keys()
            .filter(|held| !after.transfers.contains_key(*held) && !carried.contains(*held))
            .count();
    }
    check(world, store, step, tally)
}

fn apply(
    world: &World,
    store: &mut ChainStore,
    step: usize,
    what: &Step,
    tally: &mut Option<&mut Tally>,
) -> Result<(), Failure> {
    match what {
        Step::Offer { transfer, kind } => offer(world, store, step, transfer, kind, tally),
        Step::Deliver(id) => deliver(world, store, step, id, tally),
    }
}

/// Runs a fixed sequence of steps against a fresh store.
fn replay(world: &World, steps: &[Step]) -> Result<(), Failure> {
    let mut store = ChainStore::archiving(world.params);
    for (at, what) in steps.iter().enumerate() {
        apply(world, &mut store, at, what, &mut None)?;
    }
    Ok(())
}

/// The shortest run of steps this reaches that still breaks `property`.
fn cut_down(world: &World, steps: &[Step], property: &'static str) -> Vec<Step> {
    let fails =
        |steps: &[Step]| replay(world, steps).is_err_and(|failure| failure.property == property);
    let mut best = steps.to_vec();
    let mut span = best.len().max(1);
    while span > 0 {
        let mut at = 0;
        while at < best.len() {
            let end = (at + span).min(best.len());
            let mut shorter = best[..at].to_vec();
            shorter.extend_from_slice(&best[end..]);
            if fails(&shorter) {
                best = shorter;
            } else {
                at += span;
            }
        }
        span /= 2;
    }
    best
}

/// Writes a cut-down failing sequence where the campaign keeps its failures.
fn keep(world: &World, steps: &[Step], failure: &Failure, seed: u64, case: usize) -> String {
    let mut record = String::new();
    let _ = writeln!(record, "campaign: {CAMPAIGN}");
    let _ = writeln!(record, "seed: {seed:#x}, case: {case}");
    let _ = writeln!(record, "property: {}", failure.property);
    let _ = writeln!(record, "at step: {}", failure.step);
    let _ = writeln!(record, "failed with: {}", failure.said);
    let _ = writeln!(record, "\nthe steps, cut down to {}:", steps.len());
    for (index, step) in steps.iter().enumerate() {
        match step {
            Step::Offer { transfer, kind } => {
                let _ = writeln!(
                    record,
                    "  {index}: offer {:?} ({kind}), spending {:?}, paying {:?}",
                    transfer.id(),
                    transfer
                        .inputs
                        .iter()
                        .map(|input| input.note_id)
                        .collect::<Vec<_>>(),
                    transfer
                        .outputs
                        .iter()
                        .map(|note| note.value.as_pebbles())
                        .collect::<Vec<_>>()
                );
            }
            Step::Deliver(id) => {
                let built = &world.built[id];
                let _ = writeln!(
                    record,
                    "  {index}: deliver {id:?}, height {}, on {:?}, carrying {:?}",
                    built.block.header.height,
                    built.parent,
                    built
                        .block
                        .transfers
                        .iter()
                        .map(Transfer::id)
                        .collect::<Vec<_>>()
                );
            }
        }
    }
    let folder: String = CAMPAIGN
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .join("target")
        .join("fuzz")
        .join(folder);
    let file = directory.join(format!("seed-{seed:x}-case-{case}-cut-down.txt"));
    let written = std::fs::create_dir_all(&directory)
        .and_then(|()| std::fs::write(&file, &record))
        .map_or_else(
            |error| format!("could not be written down: {error}"),
            |()| format!("kept in {}", file.display()),
        );
    eprintln!("{record}");
    written
}

/// One case being played: the world it builds as it goes, the store, and the
/// steps taken so far.
struct Play<'t> {
    world: World,
    store: ChainStore,
    steps: Vec<Step>,
    /// The tip the last switch left, which a later step may switch back to.
    left: Option<Hash32>,
    /// Transfers made so far, for offering again and for blocks to carry.
    made: Vec<Transfer>,
    tally: &'t mut Tally,
}

impl Play<'_> {
    fn tip(&self) -> Hash32 {
        self.store.tip().unwrap()
    }

    fn state(&self) -> LedgerState {
        self.world.state(&self.tip()).clone()
    }

    fn take(&mut self, step: Step) -> Result<(), Failure> {
        let at = self.steps.len();
        self.steps.push(step);
        let mut tally = Some(&mut *self.tally);
        apply(
            &self.world,
            &mut self.store,
            at,
            &self.steps[at],
            &mut tally,
        )
    }

    fn offer(&mut self, transfer: Transfer, kind: &'static str) -> Result<(), Failure> {
        self.made.push(transfer.clone());
        self.take(Step::Offer { transfer, kind })
    }

    /// Notes no pooled transfer spends yet.
    fn free(&self, state: &LedgerState) -> Vec<(Owned, Input, Tier)> {
        let spoken: BTreeSet<NoteId> = self
            .store
            .pooled_spenders()
            .map(|(note, _)| *note)
            .collect();
        spendable(&self.world, state)
            .into_iter()
            .filter(|(owned, _, _)| !spoken.contains(&owned.id))
            .collect()
    }

    /// One or two notes, leaning on the tier asked for.
    fn some_notes(
        rng: &mut Rng,
        from: &[(Owned, Input, Tier)],
        lean: Option<fn(&Tier) -> bool>,
    ) -> Vec<(Owned, Input, Tier)> {
        let leaning: Vec<&(Owned, Input, Tier)> = match lean {
            Some(lean) => from.iter().filter(|(_, _, tier)| lean(tier)).collect(),
            None => from.iter().collect(),
        };
        let pool = if leaning.is_empty() {
            from.iter().collect()
        } else {
            leaning
        };
        let mut chosen: Vec<(Owned, Input, Tier)> = Vec::new();
        for _ in 0..rng.between(1, 2) {
            if let Some(pick) = rng.pick(&pool) {
                if chosen.iter().all(|(owned, _, _)| owned.id != pick.0.id) {
                    chosen.push((*pick).clone());
                }
            }
        }
        chosen
    }

    fn offer_something(&mut self, rng: &mut Rng) -> Result<(), Failure> {
        let state = self.state();
        let params = self.world.params;
        let unspoken = self.free(&state);
        let made = match rng.below(12) {
            0..=3 => {
                let lean: Option<fn(&Tier) -> bool> = match rng.below(4) {
                    0 => Some(|tier| matches!(tier, Tier::Grace)),
                    1 => Some(|tier| matches!(tier, Tier::Cold)),
                    _ => None,
                };
                let notes = Self::some_notes(rng, &unspoken, lean);
                spend(&params, &notes, &payees(rng), Fee::Above(extra(rng)), None)
                    .map(|transfer| (transfer, "valid"))
            }
            4 | 5 => {
                // The oldest notes in the hot set, which the next blocks push
                // out first.
                let mut hot: Vec<&(Owned, Input, Tier)> = unspoken
                    .iter()
                    .filter(|(_, _, tier)| matches!(tier, Tier::Hot(_)))
                    .collect();
                hot.sort_by_key(|(owned, _, tier)| match tier {
                    Tier::Hot(height) => (*height, owned.id),
                    _ => (u64::MAX, owned.id),
                });
                let notes: Vec<(Owned, Input, Tier)> =
                    hot.into_iter().take(rng.between(1, 2)).cloned().collect();
                spend(
                    &params,
                    &notes,
                    &payees(rng),
                    Fee::Above(extra(rng) / 100),
                    None,
                )
                .map(|transfer| (transfer, "spending the oldest hot notes"))
            }
            6 | 7 => {
                // A note a pooled transfer already spends, with enough to take
                // its place or not.
                let pooled: Vec<Transfer> = self
                    .store
                    .pooled_transfers()
                    .map(|(_, t)| t.clone())
                    .collect();
                let everything = spendable(&self.world, &state);
                let Some(holder) = rng.pick(&pooled).cloned() else {
                    return Ok(());
                };
                let wanted = rng.pick(&holder.inputs).map(|input| input.note_id);
                let mut notes: Vec<(Owned, Input, Tier)> = everything
                    .iter()
                    .filter(|(owned, _, _)| Some(owned.id) == wanted)
                    .cloned()
                    .collect();
                if rng.bool() {
                    if let Some(more) = rng.pick(&unspoken) {
                        notes.push(more.clone());
                    }
                }
                let displaced: u64 =
                    check_transfer(&holder, &state, &BTreeSet::new(), &BTreeMap::new(), &params)
                        .map_or(0, |outcome| outcome.fee.as_pebbles());
                let (fee, kind) = if rng.bool() {
                    (
                        Fee::Above(displaced + extra(rng)),
                        "a replacement paying enough",
                    )
                } else {
                    (Fee::Above(displaced / 2), "a replacement paying too little")
                };
                spend(&params, &notes, &payees(rng), fee, None).map(|transfer| (transfer, kind))
            }
            8 => {
                let notes = Self::some_notes(rng, &unspoken, None);
                let (fee, kind) = if rng.bool() {
                    (Fee::BelowTheFloor, "a fee under the floor")
                } else {
                    (Fee::BelowTheBurn, "a fee under the burn of its places")
                };
                spend(&params, &notes, &payees(rng), fee, None).map(|transfer| (transfer, kind))
            }
            9 => {
                let notes = Self::some_notes(rng, &unspoken, None);
                match rng.below(3) {
                    0 => spend(&params, &notes, &payees(rng), Fee::Above(0), Some(4))
                        .map(|transfer| (transfer, "signed by a wallet that owns nothing here")),
                    1 => {
                        // Notes a wallet once held and the tip does not: spent,
                        // or on a branch the store has left.
                        let gone: Vec<(Owned, Input, Tier)> = self
                            .world
                            .owned
                            .iter()
                            .filter(|owned| {
                                state.hot_note(&owned.id).is_none()
                                    && state.within_grace(&owned.id).is_none()
                            })
                            .map(|owned| (*owned, Input::hot(owned.id), Tier::Hot(0)))
                            .collect();
                        let notes = Self::some_notes(rng, &gone, None);
                        spend(&params, &notes, &payees(rng), Fee::Above(extra(rng)), None)
                            .map(|transfer| (transfer, "spending a note the tip does not hold"))
                    }
                    _ => {
                        let total: u64 = notes
                            .iter()
                            .map(|(owned, _, _)| owned.note.value.as_pebbles())
                            .sum();
                        let mut transfer = spend(&params, &notes, &[1], Fee::Exactly(0), None);
                        if let Some(transfer) = transfer.as_mut() {
                            transfer.outputs[0] =
                                Note::new(pebbles(total + 1), wallet(1).public_key());
                            for (index, (owned, _, _)) in notes.iter().enumerate() {
                                transfer.sign_input(
                                    params.network,
                                    u32::try_from(index).unwrap(),
                                    &owned.note,
                                    &wallet(owned.owner),
                                );
                            }
                        }
                        transfer.map(|transfer| (transfer, "paying out more than it spends"))
                    }
                }
            }
            _ => rng
                .pick(&self.made)
                .cloned()
                .map(|transfer| (transfer, "offered before")),
        };
        match made {
            Some((transfer, kind)) => self.offer(transfer, kind),
            None => Ok(()),
        }
    }

    fn deliver(&mut self, id: Hash32) -> Result<(), Failure> {
        self.take(Step::Deliver(id))
    }

    fn mine_something(&mut self, rng: &mut Rng) -> Result<(), Failure> {
        let tip = self.tip();
        let salt = rng.edgy_u64();
        match rng.below(6) {
            0..=2 => {
                let (chosen, fees) = self.store.selection(usize::MAX);
                let next = self
                    .world
                    .extend(tip, chosen, fees, salt)
                    .or_else(|| self.world.extend(tip, Vec::new(), Amount::ZERO, salt))
                    .unwrap();
                self.deliver(next)
            }
            3 | 4 => {
                // Whatever was made lately, the pool's opinion aside: a
                // transfer under the pool's floor is still one a block may
                // carry, and the pool has to let go of what it conflicts with.
                let mut candidates: Vec<Transfer> =
                    self.made.iter().rev().take(12).cloned().collect();
                for _ in 0..candidates.len() / 2 {
                    let at = rng.below(candidates.len());
                    let with = rng.below(candidates.len());
                    candidates.swap(at, with);
                }
                let next = self.world.extend_with_what_fits(tip, candidates, salt);
                self.deliver(next)
            }
            _ => {
                let next = self
                    .world
                    .extend(tip, Vec::new(), Amount::ZERO, salt)
                    .unwrap();
                self.deliver(next)
            }
        }
    }

    /// A long run of empty blocks, which walks the notes pooled transfers
    /// spend out of the grace window and into the cold set.
    fn quiet(&mut self, rng: &mut Rng) -> Result<(), Failure> {
        for _ in 0..rng.between(4, 70) {
            let tip = self.tip();
            let next = self
                .world
                .extend(tip, Vec::new(), Amount::ZERO, rng.edgy_u64())
                .unwrap();
            self.deliver(next)?;
        }
        Ok(())
    }

    /// A rival branch from a few blocks down, one block longer, carrying a
    /// mix of what the abandoned blocks carried, double spends of it, and
    /// what the pool holds.
    fn switch(&mut self, rng: &mut Rng) -> Result<(), Failure> {
        let tip = self.tip();
        let height = self.store.height().unwrap();
        let depth = (rng.between(1, 3) as u64).min(height.saturating_sub(1));
        if depth == 0 {
            return Ok(());
        }
        let fork = self.world.below(tip, depth);
        let fork_state = self.world.state(&fork).clone();
        let params = self.world.params;
        let mut abandoned: Vec<Transfer> = Vec::new();
        let mut at = tip;
        while at != fork {
            abandoned.extend(self.world.built[&at].block.transfers.iter().cloned());
            at = self.world.built[&at].parent.unwrap();
        }
        let spendable_at_fork = spendable(&self.world, &fork_state);
        let mut doubles: Vec<Transfer> = Vec::new();
        for transfer in &abandoned {
            let Some(first) = transfer.inputs.first() else {
                continue;
            };
            let notes: Vec<(Owned, Input, Tier)> = spendable_at_fork
                .iter()
                .filter(|(owned, _, _)| owned.id == first.note_id)
                .cloned()
                .collect();
            if let Some(double) = spend(&params, &notes, &[4], Fee::Above(50), None) {
                doubles.push(double);
            }
        }
        let pooled: Vec<Transfer> = self
            .store
            .pooled_transfers()
            .map(|(_, t)| t.clone())
            .collect();
        let mut parent = fork;
        let mut rival = Vec::new();
        for _ in 0..=depth {
            let mut candidates: Vec<Transfer> = Vec::new();
            for source in [&abandoned, &doubles, &pooled] {
                for transfer in source {
                    if rng.chance(2) {
                        candidates.push(transfer.clone());
                    }
                }
            }
            for _ in 0..candidates.len() {
                let at = rng.below(candidates.len());
                let with = rng.below(candidates.len());
                candidates.swap(at, with);
            }
            candidates.truncate(6);
            parent = self
                .world
                .extend_with_what_fits(parent, candidates, rng.edgy_u64());
            rival.push(parent);
        }
        self.left = Some(tip);
        for id in rival {
            self.deliver(id)?;
        }
        Ok(())
    }

    /// Back to the branch the last switch left, made heavier again, which
    /// reconnects the blocks the switch disconnected.
    fn back(&mut self, rng: &mut Rng) -> Result<(), Failure> {
        let Some(left) = self.left.take() else {
            return Ok(());
        };
        let tip = self.tip();
        let have = self.world.built[&left].block.header.height;
        let need = self.store.height().unwrap() + 1;
        if need.saturating_sub(have) > 4 || self.store.is_active(&left) {
            return Ok(());
        }
        let mut parent = left;
        let mut back = Vec::new();
        while self.world.built[&parent].block.header.height < need {
            let pooled: Vec<Transfer> = self
                .store
                .pooled_transfers()
                .map(|(_, t)| t.clone())
                .collect();
            parent = self
                .world
                .extend_with_what_fits(parent, pooled, rng.edgy_u64());
            back.push(parent);
        }
        self.left = Some(tip);
        for id in back {
            self.deliver(id)?;
        }
        Ok(())
    }
}

/// The blocks every case starts from a prefix of.
fn base() -> (World, Vec<Hash32>) {
    let mut world = World::new();
    let mut chain = vec![world.genesis];
    let mut tip = world.genesis;
    for index in 1..BASE {
        tip = world
            .extend(tip, Vec::new(), Amount::ZERO, index as u64)
            .unwrap();
        chain.push(tip);
    }
    (world, chain)
}

/// The pool holds no conflict, nothing invalid against the tip, its own
/// bounds and floor, a selection that builds, refusals that move nothing,
/// and what a switch undid.
///
/// Nothing had interleaved offers with blocks connected and disconnected, so
/// a pool that kept a transfer whose note fell out of the grace window, or
/// whose places rose past what it paid, or that let a payment a switch undid
/// go missing, passed whenever it happened between two of the moments the
/// tests build.
#[test]
fn the_pool_holds_nothing_the_tip_refuses_whatever_order_things_arrive_in() {
    let campaign = Campaign::named(CAMPAIGN);
    let seed = campaign.seed();
    let (start, chain) = base();
    let mut tally = Tally::default();

    let ran = campaign.run(40, |case, rng| {
        let mut play = Play {
            world: start.clone(),
            store: ChainStore::archiving(start.params),
            steps: Vec::new(),
            left: None,
            made: Vec::new(),
            tally: &mut tally,
        };
        let prefix = rng.between(8, BASE);
        let mut result = Ok(());
        for id in &chain[..prefix] {
            result = result.and_then(|()| play.deliver(*id));
        }
        for _ in 0..rng.between(10, 60) {
            if result.is_err() {
                break;
            }
            result = match rng.below(40) {
                0 => play.quiet(rng),
                1..=3 => play.switch(rng),
                4 | 5 => play.back(rng),
                6..=16 => play.mine_something(rng),
                _ => play.offer_something(rng),
            };
        }
        if let Err(failure) = result {
            let world = play.world.clone();
            let steps = play.steps.clone();
            let shortest = cut_down(&world, &steps, failure.property);
            let again = replay(&world, &shortest).err().unwrap_or(failure.clone());
            let kept = keep(&world, &shortest, &again, seed, case);
            panic!(
                "case {case} of seed {seed:#x}: \"{}\" does not hold, at step {} ({}); cut \
                 down to {} steps, {kept}",
                failure.property,
                failure.step,
                failure.said,
                shortest.len()
            );
        }
    });

    eprintln!("{CAMPAIGN}: {tally:?}");
    assert!(ran.cases >= 20, "the campaign ran {} cases", ran.cases);
    for answer in [
        "Ok(true)",
        "Ok(false)",
        "FeeBelowFloor",
        "UnknownNote",
        "PlacesUnpaid",
    ] {
        assert!(
            tally.answers.get(answer).copied().unwrap_or(0) > 0,
            "the pool never answered {answer}: {:?}",
            tally.answers
        );
    }
    assert!(tally.replaced > 0, "no transfer took another's place");
    assert!(
        tally.dropped_as_stale > 0,
        "no block left a pooled transfer stale, so pruning was not asked"
    );
    assert!(tally.switches > 0, "no switch, so nothing was disconnected");
    assert!(
        tally.put_back > 0,
        "no transfer a switch undid came back to the pool"
    );
    for from in ["the hot set", "the grace window", "the cold set"] {
        assert!(
            tally.pooled_from.get(from).copied().unwrap_or(0) > 0,
            "nothing pooled ever spent from {from}: {:?}",
            tally.pooled_from
        );
    }
}

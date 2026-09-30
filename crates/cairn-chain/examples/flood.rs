//! What a flood of the hot set costs whoever floods it, and what it costs the
//! people it displaces.
//!
//! Every note a transfer adds to a full tier pushes the oldest untouched one
//! out, and its owner then spends it with a cold witness instead of a one-byte
//! hot tag. The place price is set so that pushing a note out costs the pusher
//! at least what that costs the owner: the extra bytes, at the pool's floor
//! rate. This measures the extra bytes, on a public network's rules, after a
//! flood that pushes a whole tier out, and prints the price they give.
//!
//! What it runs: sixteen honest keys and a flooder are paid in turn, a quiet
//! chain carries eight honest payments a block, and then the flooder fills and
//! flushes the tier through the pool, paying exactly the floor, as fast as a
//! miner's `selection` will take it. Before the flood each honest key prices a
//! payment from one of its oldest notes with a hot witness; after it, the same
//! payment from the same note with the cold witness its node kept current.
//! The median difference is `delta_w`, and the price is
//! `ceil(delta_w * MIN_FEE_PER_WEIGHT / 1000) * 1000` pebbles.
//!
//! Run with `cargo run --release -p cairn-chain --example flood`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::print_stdout
)]

use std::collections::{BTreeMap, BTreeSet};

use cairn_chain::{fee_floor, places_taken, ChainStore, MIN_FEE_PER_WEIGHT};
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, check_transfer, check_transfer_again, mine_block, ConsensusParams,
    TransferOutcome,
};
use cairn_primitives::amount::PEBBLES_PER_CAIRN;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

/// Honest keys, each watched by the node, so it keeps its fallen notes'
/// paths current the way a wallet's node does.
const HONEST: usize = 16;
/// Honest payments in every block, drawn round robin: a quiet chain.
const BACKGROUND: usize = 8;
/// Blocks of the quiet chain before the flood starts.
const QUIET: u64 = 16;
/// The burial, and so the maturity, of the rules measured on.
const BURIAL: u64 = 32;
/// What an honest payment pays its payee.
const PAID: u64 = PEBBLES_PER_CAIRN / 100;
/// The payment each honest key prices before and after the flood.
const MEASURED: u64 = PEBBLES_PER_CAIRN;
const ATTEMPTS: u64 = 1 << 26;
const SPACING: u64 = 60;

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).expect("an amount the ceiling holds")
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A one-input transfer from `spent` paying `outputs` and leaving `fee`, the
/// change going back to its owner as the last output.
fn spend(
    rules: &ConsensusParams,
    input: Input,
    spent: Note,
    owner: &SecretKey,
    paid: &[Note],
    fee: u64,
) -> Transfer {
    let given: u64 = paid.iter().map(|note| note.value.as_pebbles()).sum();
    let change = spent.value.as_pebbles() - given - fee;
    let mut outputs = paid.to_vec();
    outputs.push(Note::new(pebbles(change), owner.public_key()));
    let mut transfer = Transfer::new(vec![input], outputs);
    transfer.sign_input(rules.network, 0, &spent, owner);
    transfer
}

/// The same spend at the least fee the pool takes, with `margin` places over
/// it, worked out on the transfer it will be.
fn priced(
    rules: &ConsensusParams,
    input: &Input,
    spent: Note,
    owner: &SecretKey,
    paid: &[Note],
    freed: usize,
    margin: usize,
) -> Transfer {
    let probe = spend(rules, input.clone(), spent, owner, paid, 1);
    let floor = fee_floor(probe.encode().len(), places_taken(&probe, freed), rules);
    let extra = rules.burn_for(margin).expect("a small burn").as_pebbles();
    spend(
        rules,
        input.clone(),
        spent,
        owner,
        paid,
        floor.as_pebbles() + extra,
    )
}

/// What the store would judge a pooled transfer to pay against the tip, or
/// nothing if it no longer can.
fn outcome_of(store: &ChainStore, transfer: &Transfer) -> Option<TransferOutcome> {
    check_transfer_again(
        transfer,
        store.state(),
        &BTreeSet::new(),
        &BTreeMap::new(),
        store.params(),
    )
    .ok()
}

/// Mines the block `selection` offers, with its coinbase paying `to` the
/// reward and what the transfers leave their miner, and adds it.
fn mine(store: &mut ChainStore, clock: &mut u64, to: &SecretKey, outputs: usize) {
    let (chosen, kept) = store.selection(store.params().max_transfers_per_block);
    mine_these(store, clock, to, outputs, chosen, kept);
}

/// The same, for a selection taken earlier: a miner's template, which does
/// not change while it searches for a nonce.
fn mine_these(
    store: &mut ChainStore,
    clock: &mut u64,
    to: &SecretKey,
    outputs: usize,
    chosen: Vec<Transfer>,
    kept: Amount,
) {
    let rules = *store.params();
    let height = store.state().next_height().expect("a height");
    let total = rules.reward_at(height).checked_add(kept).expect("a sum");
    let each = total.as_pebbles() / outputs as u64;
    let first = total.as_pebbles() - each * (outputs as u64 - 1);
    let paid: Vec<Note> = (0..outputs)
        .map(|index| {
            let value = if index == 0 { first } else { each };
            Note::new(pebbles(value), to.public_key())
        })
        .collect();
    *clock += SPACING;
    let coinbase = CoinbaseTransaction::new(height, paid);
    let block = assemble_block(store.state(), coinbase, chosen, &rules, *clock, 0)
        .expect("the block selection offers is valid");
    let block = mine_block(block, ATTEMPTS).expect("a nonce at a mineable difficulty");
    store.add_block(block, *clock).expect("the block is taken");
}

/// A key's notes the harness may spend, oldest first.
#[derive(Default)]
struct Purse {
    notes: Vec<(NoteId, Note)>,
}

struct Honest {
    secret: SecretKey,
    /// The note measured before and after, set aside so nothing spends it.
    measured: Option<(NoteId, Note)>,
    /// The note its next background payment spends: its latest change.
    change: Option<(NoteId, Note)>,
    /// Its other notes, which the flood pushes out and which it then spends
    /// with a proof, one a block.
    rest: Vec<(NoteId, Note)>,
}

fn main() {
    let rules = ConsensusParams::mineable_network(BURIAL);
    let mut store = ChainStore::new(rules);
    let flooder = key(100);
    let payee = key(200);
    let miner = key(201);
    let mut honest: Vec<Honest> = Vec::new();
    for index in 0..HONEST {
        let secret = key(u8::try_from(index + 1).expect("a small index"));
        store.watch_owner(secret.public_key());
        honest.push(Honest {
            secret,
            measured: None,
            change: None,
            rest: Vec::new(),
        });
    }
    let mut purse = Purse::default();
    let mut clock = 1_000_000u64;

    // 1. Two rounds of rewards, each block's sixteen notes to one key in turn,
    //    then enough empty blocks that every one of them has matured.
    let round = HONEST as u64 + 1;
    let funding = 2 * round;
    for height in 0..funding {
        let turn = (height % round) as usize;
        let to = if turn == HONEST {
            &flooder
        } else {
            &honest[turn].secret
        };
        let before = store.state().next_height().unwrap();
        mine(&mut store, &mut clock, to, rules.max_coinbase_outputs);
        let block = store.block_at(before).expect("just added").clone();
        for (id, note) in block.coinbase.created_notes() {
            if turn == HONEST {
                purse.notes.push((id, note));
            } else if height < round && id.index == 0 {
                honest[turn].measured = Some((id, note));
            } else if id.index == 0 {
                honest[turn].change = Some((id, note));
            } else {
                honest[turn].rest.push((id, note));
            }
        }
    }
    while store.state().next_height().unwrap() < funding + BURIAL {
        mine(&mut store, &mut clock, &miner, 1);
    }

    // 2. A quiet chain: eight honest payments a block, each spending its
    //    key's latest change, paying a wallet's quote of the floor and a place
    //    over it for the note that could fall.
    let mut turn = 0usize;
    let mut background = |store: &mut ChainStore, honest: &mut Vec<Honest>| {
        for _ in 0..BACKGROUND {
            let one = &mut honest[turn % HONEST];
            turn += 1;
            let Some((id, note)) = one.change.take() else {
                continue;
            };
            let paid = [Note::new(pebbles(PAID), payee.public_key())];
            let transfer = priced(&rules, &Input::hot(id), note, &one.secret, &paid, 1, 1);
            let change = *transfer.outputs.last().unwrap();
            let change_id = NoteId::new(transfer.id(), 1);
            store
                .accept_transfer(transfer)
                .expect("an honest payment at the quote is pooled");
            one.change = Some((change_id, change));
        }
    };
    for _ in 0..QUIET {
        background(&mut store, &mut honest);
        mine(&mut store, &mut clock, &miner, 1);
    }

    // Each honest key prices its payment from its oldest note while the note
    // is hot, and does not send it.
    let measure = |store: &ChainStore, one: &Honest, input: Input| -> Transfer {
        let (id, note) = one.measured.expect("every key has its measured note");
        let paid = [Note::new(pebbles(MEASURED), payee.public_key())];
        let freed = usize::from(
            matches!(input.witness, cairn_ledger::transaction::Witness::Hot)
                && store.state().hot_note(&id).is_some(),
        );
        let transfer = priced(store.params(), &input, note, &one.secret, &paid, freed, 0);
        check_transfer(
            &transfer,
            store.state(),
            &BTreeSet::new(),
            &BTreeMap::new(),
            store.params(),
        )
        .expect("the measured payment is valid when it is priced");
        transfer
    };
    let before: Vec<usize> = honest
        .iter()
        .map(|one| {
            let (id, _) = one.measured.expect("every key has its measured note");
            assert!(store.state().hot_note(&id).is_some());
            measure(&store, one, Input::hot(id)).encode().len()
        })
        .collect();

    // 3. The flood.
    let flood_start = store.state().next_height().unwrap();
    println!(
        "A flood of the hot set on a public network's rules: a tier of {}, a cap of {}\n\
         evictions a block, {} bytes a block, {} pebbles destroyed a place.\n",
        rules.hot_capacity,
        rules.max_evictions_per_block,
        rules.max_block_bytes,
        rules.place_price.as_pebbles()
    );
    println!(
        "{:>6}  {:>7}  {:>8}  {:>7}  {:>9}  {:>12}  {:>11}",
        "height", "flood", "hot", "evicted", "landings", "burned", "byte fees"
    );
    let most_outputs = rules.max_outputs_per_transfer;
    let one_pebble = Note::new(pebbles(1), flooder.public_key());
    let flood_of = |outputs: usize, id: NoteId, note: Note| -> Transfer {
        let paid = vec![one_pebble; outputs - 1];
        priced(&rules, &Input::hot(id), note, &flooder, &paid, 1, 0)
    };
    let full_size = flood_of(most_outputs, purse.notes[0].0, purse.notes[0].1)
        .encode()
        .len();

    let mut filled_at: Option<u64> = None;
    let mut to_flush: BTreeSet<NoteId> = BTreeSet::new();
    // What the flood burned and paid in byte fees, filling the tier and then
    // flushing it. A live network's tier is already full, so the flush is
    // what pushing everybody out costs there.
    let (mut fill_burned, mut fill_kept) = (0u64, 0u64);
    let (mut flush_burned, mut flush_kept) = (0u64, 0u64);
    let mut flood_transfers = 0usize;
    let mut evicted_in_flush = 0usize;
    let mut landings: Vec<usize> = Vec::new();
    let mut evictions: Vec<usize> = Vec::new();
    let mut cold_pending: Option<cairn_primitives::Hash32> = None;
    let (mut cold_sent, mut cold_lost, mut cold_mined) = (0usize, 0usize, 0usize);
    let mut honest_cursor = 0usize;

    let flushed = loop {
        let height = store.state().next_height().unwrap();
        background(&mut store, &mut honest);

        // What the pool already holds takes its share of the block first:
        // the honest payments rank above the flood, as they pay more for what
        // they take.
        let state = store.state();
        let mut places = rules
            .hot_capacity
            .saturating_sub(state.hot_len())
            .saturating_add(rules.max_evictions_per_block)
            .saturating_sub(rules.max_coinbase_outputs);
        let mut room = ChainStore::room_for_transfers(rules.max_block_bytes);
        for (_, transfer) in store.pooled_transfers() {
            let freed = transfer
                .inputs
                .iter()
                .filter(|input| state.hot_note(&input.note_id).is_some())
                .count();
            places = places.saturating_sub(places_taken(transfer, freed));
            room = room.saturating_sub(transfer.encode().len());
        }
        // The flooder fills what is left, whole transfers first and the
        // remainder in one sized to it.
        let mut shapes = Vec::new();
        while places >= most_outputs - 1 && room >= full_size {
            shapes.push(most_outputs);
            places -= most_outputs - 1;
            room -= full_size;
        }
        if places >= 1 && room >= full_size && shapes.len() < purse.notes.len() {
            shapes.push(places + 1);
        }
        let mut flood_ids = BTreeSet::new();
        for outputs in shapes {
            let Some((id, note)) = purse.notes.first().copied() else {
                break;
            };
            purse.notes.remove(0);
            let transfer = flood_of(outputs, id, note);
            flood_ids.insert(transfer.id());
            store
                .accept_transfer(transfer)
                .expect("the flood pays exactly the floor and is pooled");
        }

        // What this block burns and keeps, read off the transfers against the
        // state they are judged on.
        let hot_before = store.state().hot_len();
        let supply_before = store.state().supply();
        let judged: Vec<(Transfer, TransferOutcome)> = store
            .pooled_transfers()
            .filter_map(|(_, transfer)| {
                outcome_of(&store, transfer).map(|outcome| (transfer.clone(), outcome))
            })
            .collect();
        let reward = rules.reward_at(height);

        // The miner's template is taken; an honest cold spend arrives after it,
        // and waits for the next block without being offered again.
        let (chosen, kept) = store.selection(rules.max_transfers_per_block);
        let chosen_ids: BTreeSet<_> = chosen.iter().map(Transfer::id).collect();
        let late = if filled_at.is_some() {
            cold_spend(&store, &mut honest, &mut honest_cursor, &payee)
        } else {
            None
        };
        if let Some(transfer) = &late {
            if store.accept_transfer(transfer.clone()) == Ok(true) {
                cold_sent += 1;
            }
        }
        mine_these(&mut store, &mut clock, &miner, 1, chosen, kept);
        let block = store.block_at(height).expect("just added").clone();
        assert_eq!(
            block
                .transfers
                .iter()
                .map(Transfer::id)
                .collect::<BTreeSet<_>>(),
            chosen_ids,
            "the block is the selection"
        );

        // The spend that arrived late last block either rode this one, or is
        // still waiting, or was let go of.
        if let Some(id) = cold_pending.take() {
            if chosen_ids.contains(&id) {
                cold_mined += 1;
            } else if store.pooled(&id).is_some() {
                cold_pending = Some(id);
            } else {
                cold_lost += 1;
            }
        }
        if let Some(transfer) = late {
            let id = transfer.id();
            if store.pooled(&id).is_some() {
                cold_pending = Some(id);
            } else {
                cold_lost += 1;
            }
        }

        let mut burned = 0u64;
        let mut fees = 0u64;
        let mut spent = 0usize;
        for (transfer, outcome) in &judged {
            if !chosen_ids.contains(&transfer.id()) {
                continue;
            }
            burned += outcome.burn.as_pebbles();
            fees += outcome.fee.as_pebbles();
            spent += outcome.spent_hot.len();
            if flood_ids.contains(&transfer.id()) {
                let (burned, kept) = if filled_at.is_some() {
                    (&mut flush_burned, &mut flush_kept)
                } else {
                    (&mut fill_burned, &mut fill_kept)
                };
                *burned += outcome.burn.as_pebbles();
                *kept += outcome.fee.as_pebbles() - outcome.burn.as_pebbles();
                flood_transfers += 1;
                let change = transfer.outputs.len() - 1;
                purse.notes.push((
                    NoteId::new(transfer.id(), u32::try_from(change).unwrap()),
                    transfer.outputs[change],
                ));
            }
        }
        assert_eq!(
            fees - burned,
            kept.as_pebbles(),
            "the miner kept the fees less the burn"
        );
        assert_eq!(
            store.state().supply().as_pebbles(),
            supply_before.as_pebbles() + reward.as_pebbles() - burned,
            "the supply fell by what the block burned"
        );
        // The flooder sized its transfers to the room the block had, so one
        // left behind is a flooder that miscounted, and the figures above
        // would be for a flood slower than the one it means to measure.
        for id in &flood_ids {
            if !chosen_ids.contains(id) {
                if let Some(transfer) = store.pooled(id) {
                    let spent = transfer.inputs[0].note_id;
                    panic!("the block left a flood transfer spending {spent:?} behind");
                }
            }
        }

        let created: usize = block
            .transfers
            .iter()
            .map(|transfer| transfer.outputs.len())
            .sum::<usize>()
            + block.coinbase.outputs.len();
        let hot_after = store.state().hot_len();
        let evicted = (hot_before + created).saturating_sub(spent + hot_after);
        let window = store.state().grace_window().len();

        if filled_at.is_none() && hot_after == rules.hot_capacity {
            filled_at = Some(height);
            to_flush = store.state().hot_notes().map(|(id, _)| id).collect();
        } else if filled_at.is_some() {
            evicted_in_flush += evicted;
            landings.push(window);
            evictions.push(evicted);
            let state = store.state();
            to_flush.retain(|id| state.hot_note(id).is_some());
        }

        if height % 8 == 0 || (filled_at.is_some() && to_flush.is_empty()) {
            println!(
                "{:>6}  {:>7}  {:>8}  {:>7}  {:>9}  {:>12}  {:>11}",
                height,
                height - flood_start,
                hot_after,
                evicted,
                window,
                burned,
                fees - burned
            );
        }
        if filled_at.is_some() && to_flush.is_empty() {
            break height;
        }
        assert!(height < flood_start + 1_000, "the flood never finished");
    };

    // 5. The same payments again, from the same notes, now with the cold
    //    witness each key's node kept.
    let after: Vec<usize> = honest
        .iter()
        .map(|one| {
            let state = store.state();
            let (id, note) = one.measured.expect("every key has its measured note");
            assert!(state.hot_note(&id).is_none(), "it fell");
            assert!(state.within_grace(&id).is_none(), "long ago");
            let position = state
                .watched_position(&id)
                .expect("a watched note's place is known");
            let proof = state.cold().proof_of(position).expect("its path is kept");
            let input = Input::cold(id, note, position, proof);
            measure(&store, one, input).encode().len()
        })
        .collect();
    let mut grown: Vec<usize> = before
        .iter()
        .zip(&after)
        .map(|(before, after)| after - before)
        .collect();
    grown.sort_unstable();
    let delta_w = grown[(grown.len() - 1) / 2];
    let price = (delta_w as u64 * MIN_FEE_PER_WEIGHT).div_ceil(1_000) * 1_000;

    let filled = filled_at.unwrap();
    let flush_blocks = flushed - filled;
    evictions.sort_unstable();
    landings.sort_unstable();
    println!();
    println!(
        "blocks to fill the tier        {}",
        filled - flood_start + 1
    );
    println!("blocks to flush it             {flush_blocks}");
    println!(
        "evictions a block, flushing    median {}, least {}, most {}",
        evictions[evictions.len() / 2],
        evictions[0],
        evictions[evictions.len() - 1]
    );
    println!(
        "grace window, flushing         median {} landings, least {}, most {}",
        landings[landings.len() / 2],
        landings[0],
        landings[landings.len() - 1]
    );
    let cairn = |pebbles: u64| pebbles as f64 / PEBBLES_PER_CAIRN as f64;
    println!("flood transfers                {flood_transfers}");
    println!(
        "filling, the flood burned      {:.4} CAIRN and paid {:.4} CAIRN of byte fees",
        cairn(fill_burned),
        cairn(fill_kept)
    );
    println!(
        "flushing, the flood burned     {:.4} CAIRN and paid {:.4} CAIRN of byte fees",
        cairn(flush_burned),
        cairn(flush_kept)
    );
    println!(
        "burned per displaced note      {} pebbles ({evicted_in_flush} notes pushed out during the flush)",
        flush_burned / evicted_in_flush.max(1) as u64
    );
    println!(
        "pooled cold spends             {cold_sent} sent, {cold_mined} carried, {cold_lost} let go of before a block carried them"
    );
    println!(
        "cold set at the end            {} notes",
        store.state().cold_len()
    );
    println!("payment before, per key        {before:?}");
    println!("payment after, per key         {after:?}");
    println!("delta_w                        {delta_w} bytes (median over {HONEST} keys)");
    println!(
        "place price                    ceil({delta_w} * {MIN_FEE_PER_WEIGHT} / 1000) * 1000 = {price} pebbles"
    );
}

/// An honest key's fallen note, spent with the proof its node holds now,
/// paying the floor and no more. `None` while no honest note has left the
/// grace window.
fn cold_spend(
    store: &ChainStore,
    honest: &mut [Honest],
    cursor: &mut usize,
    payee: &SecretKey,
) -> Option<Transfer> {
    let state = store.state();
    for _ in 0..honest.len() {
        let one = &mut honest[*cursor % HONEST];
        *cursor += 1;
        let at = one.rest.iter().position(|(id, _)| {
            state.hot_note(id).is_none()
                && state.within_grace(id).is_none()
                && state.watched_position(id).is_some()
        });
        let Some(at) = at else {
            continue;
        };
        let (id, note) = one.rest.remove(at);
        let position = state.watched_position(&id)?;
        let proof = state.cold().proof_of(position)?;
        let input = Input::cold(id, note, position, proof);
        let paid = [Note::new(pebbles(PAID), payee.public_key())];
        return Some(priced(
            store.params(),
            &input,
            note,
            &one.secret,
            &paid,
            0,
            0,
        ));
    }
    None
}

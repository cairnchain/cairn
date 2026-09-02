//! What a fee buys, what it costs to keep somebody out, and what a miner
//! gives up by following the order the pool suggests.
//!
//! The pool's ordering is local policy: a block is valid whatever order its
//! transfers were picked in, and a miner pays no fee to itself. So every
//! number here has to be read as what it costs a *stranger*, and separately as
//! what it costs the party writing the block, which is usually nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use cairn_chain::{
    fee_floor, transfer_weight, ChainStore, MAX_POOLED, MAX_POOL_BYTES, MIN_FEE_PER_WEIGHT,
    NOTE_WEIGHT,
};
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 20;
const PEBBLES_PER_CAIRN: u64 = 100_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// A chain paying `to` several notes a block, so a test has money to spend
/// without mining a block per note.
fn funded(count: usize, to: &SecretKey) -> (ChainStore, Vec<(NoteId, Note)>) {
    let params = params();
    let per_block = params.max_coinbase_outputs;
    let mut ledger = LedgerState::new();
    let mut store = ChainStore::new(params);
    let mut clock = 1_000_000u64;
    let mut notes = Vec::new();

    while notes.len() < count {
        let height = ledger.next_height().unwrap();
        let reward = params.reward_at(height).as_pebbles();
        let each = reward / per_block as u64;
        let first = reward - each * (per_block as u64 - 1);
        let outputs: Vec<Note> = (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(pebbles(value), to.public_key())
            })
            .collect();
        clock += 60;
        let coinbase = CoinbaseTransaction::new(height, outputs.clone());
        let block =
            assemble_block(&ledger, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut ledger, &block, &params, NOW).unwrap();
        store.add_block(block.clone(), NOW).unwrap();
        for (index, note) in outputs.into_iter().enumerate() {
            notes.push((NoteId::new(block.coinbase.id(), index as u32), note));
        }
    }
    (store, notes)
}

/// Spends one note into `count` notes, leaving `fee` behind.
fn split(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    count: usize,
    fee: Amount,
) -> Transfer {
    let shared = note.value.as_pebbles() - fee.as_pebbles();
    let each = shared / count as u64;
    let first = shared - each * (count as u64 - 1);
    let outputs: Vec<Note> = (0..count)
        .map(|index| {
            let value = if index == 0 { first } else { each };
            Note::new(pebbles(value), owner.public_key())
        })
        .collect();
    let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

/// The fee that puts a transfer at exactly `per_weight` pebbles a unit.
fn at_rate(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    count: usize,
    per_weight: u64,
) -> Transfer {
    // The weight does not depend on the fee, so one pass to measure and one to
    // build is enough.
    let probe = split(params, id, note, owner, count, pebbles(1));
    let weight = transfer_weight(&probe, probe.encode().len(), 1);
    split(
        params,
        id,
        note,
        owner,
        count,
        pebbles(weight as u64 * per_weight),
    )
}

// ---------------------------------------------------------------------------
// 1. What the fee market is worth against what a block pays.
// ---------------------------------------------------------------------------

/// A full block of ordinary payments at the floor is worth about a thousandth
/// of the block that carries it.
///
/// This is the frame for everything else in this file. `selection` orders by
/// fee per unit of weight, and a miner that threw the ordering away and filled
/// the block with its own traffic would forgo this much. At today's reward it
/// is not a number that changes anybody's behaviour, which means the pool's
/// ordering is followed because it is the default in the software and not
/// because it pays. It also means the fee floor deters nothing at all except
/// on a chain where the reward has halved into irrelevance.
#[test]
fn a_full_block_of_floor_paying_traffic_is_worth_a_thousandth_of_the_reward() {
    let params = ConsensusParams::testnet();
    // One in, two out: a payment and its change. Measured rather than guessed.
    let owner = wallet(1).public_key();
    let payment = Transfer::new(
        vec![Input::hot(NoteId::new(cairn_primitives::Hash32::ZERO, 0))],
        vec![
            Note::new(pebbles(1_000), owner),
            Note::new(pebbles(1_000), owner),
        ],
    );
    let bytes = payment.encode().len();
    let weight = transfer_weight(&payment, bytes, 1);
    let floor = fee_floor(weight);

    let per_block = params.max_block_bytes / bytes;
    let fees = floor.as_pebbles() * per_block as u64;
    let reward = params.reward_at(0).as_pebbles();

    println!("\n  an ordinary payment is {bytes} bytes and weighs {weight}");
    println!(
        "  its floor is {} pebbles, and {per_block} of them fill a block",
        floor.as_pebbles()
    );
    println!(
        "  a full block at the floor carries {fees} pebbles in fees against a\n  \
         reward of {reward}: {:.4} per cent of what the block pays\n",
        100.0 * fees as f64 / reward as f64
    );
    assert!(
        fees * 500 < reward,
        "fees are {fees} against a reward of {reward}"
    );
}

/// And what it would cost, at the floor, to push the whole hot set out.
///
/// The eviction cap says how fast. Nothing says how much altogether, and the
/// altogether is small: a fraction of one block's reward buys the tier, spread
/// over the hundred and twenty eight blocks the cap forces. A miner spending
/// its own blocks on it pays none of this.
#[test]
fn the_whole_hot_set_can_be_pushed_out_for_a_fraction_of_one_reward() {
    let params = ConsensusParams::testnet();
    let notes = params.hot_capacity as u64;
    // Each place taken is NOTE_WEIGHT of weight at the floor rate, plus the
    // bytes of the output itself, which an output of value and owner makes 40.
    let places = notes * NOTE_WEIGHT as u64 * MIN_FEE_PER_WEIGHT;
    let bytes = notes * 40 * MIN_FEE_PER_WEIGHT;
    let total = places + bytes;
    let reward = params.reward_at(0).as_pebbles();

    println!("\n  pushing every one of the {notes} hot notes out, paying the floor:");
    println!(
        "  {:.2} CAIRN for the places, {:.2} for the bytes, {:.2} altogether",
        places as f64 / PEBBLES_PER_CAIRN as f64,
        bytes as f64 / PEBBLES_PER_CAIRN as f64,
        total as f64 / PEBBLES_PER_CAIRN as f64
    );
    println!(
        "  against a block reward of {:.0} CAIRN, so the whole tier costs\n  \
         {:.2} of one block's pay, spread over the {} blocks the cap forces\n",
        reward as f64 / PEBBLES_PER_CAIRN as f64,
        total as f64 / reward as f64,
        params.hot_capacity.div_ceil(params.max_evictions_per_block)
    );
    assert!(total < reward, "{total} against a reward of {reward}");
}

// ---------------------------------------------------------------------------
// 2. A pool that is shut says nothing about being shut.
// ---------------------------------------------------------------------------

/// A transfer refused for want of room is reported exactly like one the node
/// already holds.
///
/// `accept_transfer` answers `Ok(false)` for "already here" and `Ok(false)`
/// for "the pool is full and you do not outbid the cheapest thing in it".
/// `cairn-net`'s `submit_transaction` passes that straight through and, for
/// the second case, does not relay: the sender is told nothing went wrong and
/// nothing was sent. There is no third answer to tell them apart, and a wallet
/// that shows "sent" on `Ok(false)` shows it for a payment no peer has heard
/// of.
///
/// The economics of the blockade itself are sound, which the next test
/// measures. This is about what the sender can find out.
#[test]
fn a_transfer_refused_for_want_of_room_looks_exactly_like_one_already_held() {
    let attacker = wallet(1);
    // Four hundred transfers of two hundred and fifty six outputs are about
    // ten kilobytes each, which fills most of the four megabyte pool, and a
    // tail of ordinary sized ones closes the last of it.
    let (mut store, mut purse) = funded(MAX_POOL_BYTES / 10_000 + 128, &attacker);
    let params = params();

    let mut spent = 0u64;
    let mut held = 0usize;
    let mut fill = |store: &mut ChainStore, purse: &mut Vec<(NoteId, Note)>, outputs: usize| {
        let (id, note) = purse.pop().expect("enough funding notes");
        let transfer = at_rate(
            &params,
            id,
            note,
            &attacker,
            outputs,
            MIN_FEE_PER_WEIGHT + 1,
        );
        let size = transfer.encode().len();
        let fee = note.value.as_pebbles() - transfer.total_output().unwrap().as_pebbles();
        if store.pool_bytes() + size > MAX_POOL_BYTES || store.pool_len() >= MAX_POOLED {
            return false;
        }
        assert_eq!(store.accept_transfer(transfer), Ok(true));
        spent += fee;
        held += 1;
        true
    };

    while fill(&mut store, &mut purse, params.max_outputs_per_transfer) {}
    // And now the last of the room, in payment sized pieces.
    while fill(&mut store, &mut purse, 2) {}

    let room = MAX_POOL_BYTES - store.pool_bytes();
    assert!(
        room < 200,
        "the pool should have no room left: {room} bytes"
    );

    // The victim's ordinary payment, paying the floor, on the same chain.
    let (id, note) = purse.pop().unwrap();
    let payment = at_rate(&params, id, note, &attacker, 2, MIN_FEE_PER_WEIGHT);
    let refused = store.accept_transfer(payment);
    assert_eq!(
        refused,
        Ok(false),
        "a full pool refuses by saying the transfer is not new"
    );

    // The very same answer for a transfer the pool really does hold.
    let already = store
        .pooled_transfers()
        .next()
        .map(|(_, transfer)| transfer.clone())
        .unwrap();
    assert_eq!(store.accept_transfer(already), Ok(false));

    // And a bump of one pebble a unit of weight gets straight in, which is
    // what makes this a report problem rather than a blockade.
    let (id, note) = purse.pop().unwrap();
    let better = at_rate(&params, id, note, &attacker, 2, MIN_FEE_PER_WEIGHT + 2);
    assert_eq!(store.accept_transfer(better), Ok(true));

    println!(
        "\n  {held} transfers and {} bytes closed the pool",
        store.pool_bytes()
    );
    println!(
        "  the blockade committed {:.2} CAIRN in fees to do it",
        spent as f64 / PEBBLES_PER_CAIRN as f64
    );
    println!("  a payment at the floor is answered Ok(false), which is also the");
    println!("  answer for a transfer the pool already holds. No error, no relay,");
    println!("  and nothing in the reply a sender could tell the two apart by.");
    println!("  Paying two pebbles a unit more gets in at once\n");
}

/// Holding the pool shut costs far more than slipping past it, which is the
/// property that makes the blockade unworkable rather than merely expensive.
///
/// The attacker buys pool room by the megabyte and the victim buys it by the
/// payment, so the same rate costs the two of them amounts three orders of
/// magnitude apart. The blockade also drains: `selection` takes the best rate
/// first whatever the absolute number is, so the attacker's own transfers are
/// mined a block's worth at a time and it pays for every one of them.
#[test]
fn the_pool_defends_itself_by_arithmetic() {
    let params = ConsensusParams::testnet();
    let owner = wallet(1).public_key();

    let payment = Transfer::new(
        vec![Input::hot(NoteId::new(cairn_primitives::Hash32::ZERO, 0))],
        vec![
            Note::new(pebbles(1_000), owner),
            Note::new(pebbles(1_000), owner),
        ],
    );
    let victim_weight = transfer_weight(&payment, payment.encode().len(), 1);

    // The blockade has to buy four megabytes of pool at the same rate. The
    // cheapest weight per byte is a transfer that frees as many places as it
    // takes, so bytes alone: four megabytes of weight.
    let blockade_weight = MAX_POOL_BYTES;
    let ratio = blockade_weight as f64 / victim_weight as f64;

    println!("\n  a payment weighs {victim_weight}; shutting the pool weighs at least");
    println!("  {blockade_weight}, which is {ratio:.0} times as much at any rate the");
    println!("  two are compared at. Outbidding the blockade costs the victim");
    println!("  {ratio:.0} times less than holding it, and the blockade is mined out");
    println!(
        "  at {} bytes a block, so it is re-bought about every {} blocks\n",
        params.max_block_bytes,
        MAX_POOL_BYTES / params.max_block_bytes
    );
    assert!(ratio > 1_000.0);
}

// ---------------------------------------------------------------------------
// 3. What the honest selection leaves on the table.
// ---------------------------------------------------------------------------

/// `selection` holds back the whole coinbase allowance whether or not the
/// coinbase uses it.
///
/// It subtracts `max_coinbase_outputs` from the places a block may take,
/// "because it is not known yet". A miner writing both halves knows: a
/// one-note coinbase leaves fifteen more places the rules would allow. It is
/// one and a half per cent of the eviction cap, so it changes no conclusion,
/// but it is one more place where the assembler is more careful than the rule
/// and the difference belongs to whoever is not using the assembler.
#[test]
fn the_assembler_reserves_places_a_hand_written_block_need_not() {
    let params = ConsensusParams::testnet();
    let reserved = params.max_coinbase_outputs;
    let cap = params.max_evictions_per_block;
    println!(
        "\n  selection allows {} net new notes a block; the rule allows {cap}",
        cap - reserved
    );
    println!(
        "  the difference is {reserved} places a block, {:.1} per cent of the cap\n",
        100.0 * reserved as f64 / cap as f64
    );
    assert_eq!(cap - reserved, 1_008);
}

/// The selection really does order by rate rather than by fee, and a miner
/// that reordered would be within the rules.
///
/// Recorded here because it is the hinge of the whole section: the ordering is
/// a default, not a rule, so the only thing that makes a miner follow it is
/// that it maximises the fee revenue, and the first test in this file says
/// what that revenue is worth.
#[test]
fn the_order_is_a_default_and_the_revenue_it_defends_is_small() {
    let attacker = wallet(1);
    let (mut store, purse) = funded(4, &attacker);
    let params = params();

    // A large transfer paying a big absolute fee at a poor rate, and a small
    // one paying less in total at a better rate.
    let (big_id, big_note) = purse[0];
    let big = at_rate(
        &params,
        big_id,
        big_note,
        &attacker,
        params.max_outputs_per_transfer,
        MIN_FEE_PER_WEIGHT + 1,
    );
    let (small_id, small_note) = purse[1];
    let small = at_rate(&params, small_id, small_note, &attacker, 2, 1_000);

    let big_fee = big_note.value.as_pebbles() - big.total_output().unwrap().as_pebbles();
    let small_fee = small_note.value.as_pebbles() - small.total_output().unwrap().as_pebbles();
    assert!(big_fee > small_fee, "the big one pays more in total");

    store.accept_transfer(big).unwrap();
    store.accept_transfer(small).unwrap();
    let (chosen, _) = store.selection(params.max_transfers_per_block);
    assert_eq!(chosen.len(), 2, "both fit in one block");
    assert_eq!(
        chosen[0].outputs.len(),
        2,
        "the better rate is reached for first, not the larger fee"
    );
    println!(
        "\n  the better rate is picked first ({small_fee} pebbles) over the larger\n  \
         fee ({big_fee} pebbles). Both are valid in either order; the rule\n  \
         has nothing to say about it\n"
    );
}

//! Transfers waiting for a block.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{
    fee_floor, transfer_weight, ChainStore, MAX_POOLED, MAX_POOL_BYTES, MIN_FEE_PER_WEIGHT,
    NOTE_WEIGHT,
};
use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, BlockError, ConsensusParams, TransferError,
};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Comfortably past the floor of an ordinary spend, for tests about something
/// other than the floor itself.
const PLAIN_FEE: u64 = 10_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// A chain of `count` blocks, and the coinbase note each one paid the miner.
fn funded(count: usize, miner: &SecretKey) -> (ChainStore, Vec<(NoteId, Note)>) {
    funded_under(params(), count, miner)
}

/// The same, under whatever rules the test needs.
fn funded_under(
    params: ConsensusParams,
    count: usize,
    miner: &SecretKey,
) -> (ChainStore, Vec<(NoteId, Note)>) {
    let mut ledger = LedgerState::new();
    let mut store = ChainStore::new(params);
    let mut clock = 1_000u64;
    let mut notes = Vec::new();

    for _ in 0..count {
        let height = ledger.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&ledger, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut ledger, &block, &params, NOW).unwrap();
        store.add_block(block.clone(), NOW).unwrap();
        notes.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(params.initial_reward, miner.public_key()),
        ));
    }
    (store, notes)
}

/// At least `count` spendable notes, paid out several to a block, so a test
/// can fill the pool without mining a block per transfer.
fn funded_widely(count: usize, miner: &SecretKey) -> (ChainStore, Vec<(NoteId, Note)>) {
    let params = params();
    let per_block = params.max_coinbase_outputs;
    let mut ledger = LedgerState::new();
    let mut store = ChainStore::new(params);
    let mut clock = 1_000u64;
    let mut notes = Vec::new();

    let each = params.initial_reward.as_pebbles() / per_block as u64;
    let first = params.initial_reward.as_pebbles() - each * (per_block as u64 - 1);

    while notes.len() < count {
        let outputs: Vec<Note> = (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(Amount::from_pebbles(value).unwrap(), miner.public_key())
            })
            .collect();

        let height = ledger.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(height, outputs.clone());
        let block =
            assemble_block(&ledger, coinbase, Vec::<Transfer>::new(), &params, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut ledger, &block, &params, NOW).unwrap();
        store.add_block(block.clone(), NOW).unwrap();

        for (index, note) in outputs.into_iter().enumerate() {
            let position = u32::try_from(index).unwrap();
            notes.push((NoteId::new(block.coinbase.id(), position), note));
        }
    }
    (store, notes)
}

/// Spends one note into `count` outputs, leaving `fee` behind.
fn splitting_spend(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    to: &SecretKey,
    count: usize,
    fee: Amount,
) -> Transfer {
    let shared = note.value.as_pebbles() - fee.as_pebbles();
    let each = shared / count as u64;
    let first = shared - each * (count as u64 - 1);
    let outputs: Vec<Note> = (0..count)
        .map(|index| {
            let value = if index == 0 { first } else { each };
            Note::new(Amount::from_pebbles(value).unwrap(), to.public_key())
        })
        .collect();
    let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

/// Spends one note into as many outputs as the rules allow, which is the
/// largest ordinary transfer there is.
fn wide_spend(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    to: &SecretKey,
    fee: Amount,
) -> Transfer {
    splitting_spend(
        params,
        id,
        note,
        owner,
        to,
        params.max_outputs_per_transfer,
        fee,
    )
}

/// Spends one note, paying `to` and leaving the rest as a fee.
fn spend(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    to: &SecretKey,
    fee: Amount,
) -> Transfer {
    let paid = note.value.checked_sub(fee).unwrap();
    let mut transfer = Transfer::new(vec![Input::hot(id)], vec![Note::new(paid, to.public_key())]);
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

#[test]
fn a_valid_transfer_is_taken_once() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(3, &miner);

    let transfer = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        pebbles(PLAIN_FEE),
    );
    assert_eq!(store.accept_transfer(transfer.clone()), Ok(true));
    assert_eq!(store.pool_len(), 1);
    assert_eq!(
        store.accept_transfer(transfer.clone()),
        Ok(false),
        "already held"
    );
    assert_eq!(store.pool_len(), 1);
    assert_eq!(store.pooled(&transfer.id()), Some(&transfer));
}

#[test]
fn a_transfer_the_chain_would_refuse_never_reaches_the_pool() {
    let params = params();
    let miner = wallet(1);
    let thief = wallet(9);
    let (mut store, notes) = funded(3, &miner);

    let stolen = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &thief,
        &thief,
        Amount::ZERO,
    );
    assert!(matches!(
        store.accept_transfer(stolen),
        Err(TransferError::InvalidSignature { .. })
    ));

    let invented = spend(
        &params,
        NoteId::new(notes[0].0.source, 7),
        notes[0].1,
        &miner,
        &wallet(2),
        Amount::ZERO,
    );
    assert!(store.accept_transfer(invented).is_err());
    assert_eq!(store.pool_len(), 0);
}

#[test]
fn two_transfers_spending_the_same_note_cannot_both_wait() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(3, &miner);

    let first = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        pebbles(PLAIN_FEE),
    );
    let second = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(3),
        pebbles(PLAIN_FEE),
    );

    assert_eq!(store.accept_transfer(first), Ok(true));
    assert!(matches!(
        store.accept_transfer(second),
        Err(TransferError::UnknownNote(_))
    ));
    assert_eq!(store.pool_len(), 1);
}

#[test]
fn a_selection_fits_together_and_carries_its_fees() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(5, &miner);

    let fee = Amount::from_cairn("0.5").unwrap();
    for (id, note) in notes.iter().take(3) {
        let transfer = spend(&params, *id, *note, &miner, &wallet(2), fee);
        assert_eq!(store.accept_transfer(transfer), Ok(true));
    }

    let (chosen, fees) = store.selection(10);
    assert_eq!(chosen.len(), 3);
    assert_eq!(fees, Amount::from_cairn("1.5").unwrap());

    let (fewer, _) = store.selection(2);
    assert_eq!(fewer.len(), 2, "the limit is respected");
}

#[test]
fn the_selection_is_the_same_on_every_node() {
    let params = params();
    let miner = wallet(1);
    let (mut forward, notes) = funded(5, &miner);
    let (mut backward, _) = funded(5, &miner);

    let transfers: Vec<Transfer> = notes
        .iter()
        .take(4)
        .map(|(id, note)| spend(&params, *id, *note, &miner, &wallet(2), pebbles(PLAIN_FEE)))
        .collect();

    for transfer in &transfers {
        forward.accept_transfer(transfer.clone()).unwrap();
    }
    for transfer in transfers.iter().rev() {
        backward.accept_transfer(transfer.clone()).unwrap();
    }

    let (left, _) = forward.selection(10);
    let (right, _) = backward.selection(10);
    assert_eq!(
        left, right,
        "arrival order must not decide what a block holds"
    );
}

#[test]
fn a_block_clears_what_it_carried_out_of_the_pool() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(4, &miner);

    let carried = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        pebbles(PLAIN_FEE),
    );
    let left_behind = spend(
        &params,
        notes[1].0,
        notes[1].1,
        &miner,
        &wallet(3),
        pebbles(PLAIN_FEE),
    );
    store.accept_transfer(carried.clone()).unwrap();
    store.accept_transfer(left_behind.clone()).unwrap();
    assert_eq!(store.pool_len(), 2);

    // Mine a block carrying only the first of them.
    let mut ledger = store.state().clone();
    let height = ledger.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block =
        assemble_block(&ledger, coinbase, vec![carried.clone()], &params, 5_000, 0).unwrap();
    let block = mine_block(block, ATTEMPTS).unwrap();
    connect_block(&mut ledger, &block, &params, NOW).unwrap();

    store.add_block(block, NOW).unwrap();

    assert_eq!(store.pooled(&carried.id()), None, "it is in a block now");
    assert_eq!(
        store.pooled(&left_behind.id()),
        Some(&left_behind),
        "this one still waits"
    );
    assert_eq!(store.pool_len(), 1);
}

/// A full pool that refuses everything is a pool anyone can close.
///
/// Filling it costs an attacker the floor on every place: transfers spending
/// notes back to itself, paying the least the pool will carry. Everyone who
/// wants to send anything is then behind them, for as long as the attacker
/// cares to keep it up. So the ceiling holds, and a transfer paying a better
/// rate than the least the pool already carries takes that one's place.
#[test]
fn a_full_pool_makes_room_for_whoever_pays_more() {
    let params = params();
    let attacker = wallet(1);
    let (mut store, notes) = funded_widely(MAX_POOLED + 2, &attacker);

    for (id, note) in notes.iter().take(MAX_POOLED) {
        let transfer = spend(
            &params,
            *id,
            *note,
            &attacker,
            &wallet(2),
            pebbles(PLAIN_FEE),
        );
        assert!(store.accept_transfer(transfer).unwrap());
    }
    assert_eq!(store.pool_len(), MAX_POOLED, "the ceiling is reached");

    // Another paying the same rate has nothing to offer and is turned away.
    let (id, note) = notes[MAX_POOLED];
    let matching = spend(&params, id, note, &attacker, &wallet(2), pebbles(PLAIN_FEE));
    assert!(
        !store.accept_transfer(matching).unwrap(),
        "nothing to displace"
    );
    assert_eq!(store.pool_len(), MAX_POOLED);

    // One that pays more gets in, and the pool stays at its ceiling.
    let (id, note) = notes[MAX_POOLED + 1];
    let paying = spend(
        &params,
        id,
        note,
        &attacker,
        &wallet(2),
        pebbles(PLAIN_FEE * 2),
    );
    let wanted = paying.id();
    assert!(store.accept_transfer(paying).unwrap(), "it pays more");
    assert_eq!(store.pool_len(), MAX_POOLED, "and took a place, not a seat");
    assert!(store.pooled(&wanted).is_some());
}

/// A fee that buys nothing is a fee nobody pays.
#[test]
fn a_miner_takes_the_best_paying_transfers_first() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded_widely(8, &miner);

    // Fees rising with the index, admitted in the opposite order so that no
    // ordering by arrival could produce this answer by accident.
    let mut expected: Vec<(u64, cairn_primitives::Hash32)> = Vec::new();
    for (index, (id, note)) in notes.iter().take(8).enumerate().rev() {
        let fee = (index as u64 + 1) * PLAIN_FEE;
        let transfer = spend(
            &params,
            *id,
            *note,
            &miner,
            &wallet(2),
            Amount::from_pebbles(fee).unwrap(),
        );
        expected.push((fee, transfer.id()));
        assert!(store.accept_transfer(transfer).unwrap());
    }
    expected.sort_by(|left, right| right.0.cmp(&left.0));

    let (chosen, fees) = store.selection(3);
    assert_eq!(chosen.len(), 3);
    let taken: Vec<cairn_primitives::Hash32> = chosen.iter().map(Transfer::id).collect();
    let best: Vec<cairn_primitives::Hash32> = expected.iter().take(3).map(|(_, id)| *id).collect();
    assert_eq!(taken, best, "the three best paying, in that order");
    let owed: u64 = expected.iter().take(3).map(|(fee, _)| fee).sum();
    assert_eq!(fees, Amount::from_pebbles(owed).unwrap());

    // And the whole pool still fits in a block that has room for it.
    let (all, _) = store.selection(64);
    assert_eq!(all.len(), 8);
}

/// A pool is bounded by what it weighs, not only by what it counts.
///
/// One transfer spending notes out of the cold set carries a proof for each,
/// and the rules allow two hundred and fifty six of them: half a megabyte in
/// a single transfer. Four thousand of those is two gigabytes of memory handed
/// to whoever cared to send them, without a rule being broken.
#[test]
fn the_pool_is_bounded_by_weight_as_well_as_by_count() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded_widely(64, &miner);

    // Transfers as large as the rules allow, which is what an attacker sends.
    let mut taken = 0usize;
    for (id, note) in &notes {
        let transfer = wide_spend(&params, *id, *note, &miner, &wallet(2), pebbles(2_000_000));
        if store.accept_transfer(transfer).is_err() {
            break;
        }
        taken = taken.saturating_add(1);
    }

    assert!(taken > 0, "some were taken");
    assert!(
        store.pool_bytes() <= MAX_POOL_BYTES,
        "the pool holds {} bytes, over the {MAX_POOL_BYTES} it may",
        store.pool_bytes()
    );
    assert!(
        store.pool_len() < MAX_POOLED,
        "and it filled up on weight long before it filled up on count"
    );
}

/// A transfer no block can carry is turned away rather than kept waiting.
///
/// The pool holds what is waiting for a block. A transfer too large for any
/// block is not waiting for one, it is waiting for one that cannot be built,
/// and it would sit there until something displaced it while whoever sent it
/// believed it was on its way. The refusal is what tells them otherwise.
#[test]
fn a_transfer_too_large_for_a_block_is_refused_outright() {
    let mut params = params();
    // Small enough that an ordinary wide spend passes it, so this test builds
    // a transfer rather than a megabyte.
    params.max_block_bytes = 4096;
    let owner = wallet(1);
    let (store, notes) = funded_widely(2, &owner);

    let (id, note) = notes[0];
    let wide = wide_spend(&params, id, note, &owner, &wallet(2), pebbles(2_000_000));
    let bytes = cairn_primitives::codec::Encode::encode(&wide).len();
    assert!(
        bytes > params.max_block_bytes,
        "the transfer has to be over it"
    );

    // The store built by `funded_widely` carries the ordinary rules, so it is
    // rebuilt here with the tighter limit in force.
    let mut tight = ChainStore::new(params);
    for height in 0.. {
        match store.block_at(height) {
            Some(block) => tight.add_block(block.clone(), NOW).unwrap(),
            None => break,
        };
    }

    match tight.accept_transfer(wide) {
        Err(TransferError::TooLargeForABlock { bytes: got, limit }) => {
            assert_eq!(got, bytes);
            assert_eq!(limit, params.max_block_bytes);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(tight.pool_len(), 0, "and nothing was kept");

    // One that fits is taken as before.
    let (id, note) = notes[1];
    let ordinary = spend(&params, id, note, &owner, &wallet(2), pebbles(PLAIN_FEE));
    assert!(tight.accept_transfer(ordinary).unwrap());
}

/// Nothing waits for a block for free any more.
///
/// Zero-fee transfers used to be pooled, and on a quiet chain they were also
/// mined, which made churning the hot set cost nothing exactly when notes stay
/// hot the longest. The refusal names the floor, so whoever set the fee learns
/// what to set instead.
#[test]
fn a_transfer_paying_less_than_the_floor_is_refused() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(3, &miner);

    let free = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        Amount::ZERO,
    );
    let floor = match store.accept_transfer(free) {
        Err(TransferError::FeeBelowFloor { fee, floor }) => {
            assert_eq!(fee, Amount::ZERO);
            floor
        }
        other => panic!("expected the floor to be named, got {other:?}"),
    };
    assert_eq!(store.pool_len(), 0, "and nothing was kept");

    // One pebble short is still short, and the floor itself is enough.
    let short_fee = floor.checked_sub(pebbles(1)).unwrap();
    let short = spend(
        &params,
        notes[0].0,
        notes[0].1,
        &miner,
        &wallet(2),
        short_fee,
    );
    assert!(matches!(
        store.accept_transfer(short),
        Err(TransferError::FeeBelowFloor { .. })
    ));
    let exact = spend(&params, notes[1].0, notes[1].1, &miner, &wallet(2), floor);
    assert_eq!(store.accept_transfer(exact), Ok(true));
}

/// The floor charges for places in the hot set, not only for bytes.
///
/// Every note a transfer creates beyond what it spends pushes somebody's
/// oldest note out of a full tier. Charged by bytes alone, an output is forty
/// bytes against a payment's two hundred, and churning the tier was several
/// times cheaper than the traffic it displaced.
#[test]
fn a_transfer_that_creates_many_notes_pays_for_the_places_it_takes() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded_widely(2, &miner);

    let (id, note) = notes[0];
    let wide = wide_spend(&params, id, note, &miner, &wallet(2), pebbles(1));
    let bytes = wide.encode().len();
    let places = wide.outputs.len() - wide.inputs.len();

    let floor = match store.accept_transfer(wide) {
        Err(TransferError::FeeBelowFloor { floor, .. }) => floor,
        other => panic!("expected the floor to be named, got {other:?}"),
    };

    // The floor is the bytes and every place, priced at the same rate. Bytes
    // alone would ask several times less.
    let expected = (bytes + places * NOTE_WEIGHT) as u64 * MIN_FEE_PER_WEIGHT;
    assert_eq!(floor, pebbles(expected));
    assert!(
        floor.as_pebbles() > (bytes as u64) * MIN_FEE_PER_WEIGHT * 4,
        "the places outweigh the bytes for a transfer shaped like this"
    );

    // Paying for what it takes, the same shape is carried.
    let (id, note) = notes[1];
    let paid = wide_spend(&params, id, note, &miner, &wallet(2), pebbles(expected));
    assert_eq!(store.accept_transfer(paid), Ok(true));
}

/// A block is filled by what a transfer pays for what it takes, not by the
/// largest fee.
///
/// Ordered by the fee alone, one wide transfer paying a single large fee
/// outbid a block's worth of payments each paying more for their room, and
/// churning the hot set was bought at a discount.
#[test]
fn a_block_is_filled_by_rate_and_not_by_the_largest_fee() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded_widely(5, &miner);

    // Pays more than every payment below put together, and less per unit of
    // what it takes than any of them.
    let (id, note) = notes[0];
    let wide = wide_spend(&params, id, note, &miner, &wallet(2), pebbles(2_000_000));
    let wide_id = wide.id();
    assert_eq!(store.accept_transfer(wide), Ok(true));

    let mut payments = Vec::new();
    for (id, note) in notes.iter().skip(1) {
        let transfer = spend(&params, *id, *note, &miner, &wallet(2), pebbles(100_000));
        payments.push(transfer.id());
        assert_eq!(store.accept_transfer(transfer), Ok(true));
    }

    let (chosen, _) = store.selection(payments.len());
    let taken: Vec<cairn_primitives::Hash32> = chosen.iter().map(Transfer::id).collect();
    assert_eq!(taken.len(), payments.len());
    assert!(
        !taken.contains(&wide_id),
        "the largest fee lost to the better rates"
    );
    for wanted in &payments {
        assert!(taken.contains(wanted));
    }
}

/// A pooled spend is replaced by one that pays for everything it displaces,
/// and the floor again on top.
///
/// The extra floor is what bounds the churn: re-announcing a spend costs its
/// sender every time, so the network cannot be made to relay endless copies
/// of one payment for one fee.
#[test]
fn a_conflicting_transfer_replaces_what_it_pays_for() {
    let params = params();
    let miner = wallet(1);
    let (mut store, notes) = funded(3, &miner);
    let (id, note) = notes[0];

    let first = spend(&params, id, note, &miner, &wallet(2), pebbles(PLAIN_FEE));
    let first_id = first.id();
    let floor = fee_floor(transfer_weight(&first, first.encode().len()));
    assert_eq!(store.accept_transfer(first), Ok(true));

    // Pays more, and not enough more: what it displaces plus the floor is the
    // price of the place, and one pebble short of it changes nothing.
    let asked = PLAIN_FEE + floor.as_pebbles();
    let short = spend(&params, id, note, &miner, &wallet(3), pebbles(asked - 1));
    assert!(matches!(
        store.accept_transfer(short),
        Err(TransferError::UnknownNote(_))
    ));
    assert!(store.pooled(&first_id).is_some(), "the first still waits");

    let enough = spend(&params, id, note, &miner, &wallet(3), pebbles(asked));
    let enough_id = enough.id();
    assert_eq!(store.accept_transfer(enough), Ok(true));
    assert_eq!(store.pool_len(), 1, "a replacement, not a second spend");
    assert!(store.pooled(&first_id).is_none());
    assert!(store.pooled(&enough_id).is_some());
}

/// What a miner selects never builds a block the rules refuse for pushing too
/// many notes out of the hot set.
///
/// The cap is consensus, so a selection ignoring it would mine blocks nobody
/// accepts. What does not fit this block waits in the pool for the next one,
/// which is the queue doing exactly what it is for.
#[test]
fn a_selection_leaves_out_what_would_push_out_too_many_notes() {
    let params = params().with_hot_capacity(64).with_max_evictions(8);
    let miner = wallet(1);
    let (mut store, notes) = funded_under(params, 20, &miner);

    // Each spends one note into eight, taking seven places in the hot set.
    for (id, note) in notes.iter().take(8) {
        let transfer =
            splitting_spend(&params, *id, *note, &miner, &wallet(2), 8, pebbles(100_000));
        assert_eq!(store.accept_transfer(transfer), Ok(true));
    }
    assert_eq!(store.pool_len(), 8);

    let (chosen, _) = store.selection(100);
    assert!(
        chosen.len() < 8,
        "the selection had to leave some for a later block"
    );
    assert!(!chosen.is_empty(), "and it did not leave everything");

    // What was chosen makes a block every node accepts.
    let mut ledger = store.state().clone();
    let height = ledger.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block = assemble_block(&ledger, coinbase, chosen, &params, NOW, 0).unwrap();
    let block = mine_block(block, ATTEMPTS).unwrap();
    connect_block(&mut ledger, &block, &params, NOW).unwrap();

    // And everything at once would not have: the cap the selection respects
    // is a rule, not a preference.
    let everything: Vec<Transfer> = store
        .pooled_transfers()
        .map(|(_, transfer)| transfer.clone())
        .collect();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    assert!(matches!(
        assemble_block(
            &store.state().clone(),
            coinbase,
            everything,
            &params,
            NOW,
            0
        ),
        Err(BlockError::TooManyEvictions { .. })
    ));
}

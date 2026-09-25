//! What a rewind's budget is spent on.
//!
//! A block coming off the branch takes its transfers with it, and `repool`
//! offers them back so that a reorganisation does not quietly cancel a payment
//! whose sender has already been told it was sent. It cannot offer everything:
//! a switch reaches `MAX_REORG_DEPTH` blocks and each of those may carry
//! thousands of transfers, so there has to be a bound.
//!
//! The bound was on offers, and it counted refusals. Two miners drawing on one
//! public pool build branches carrying mostly the same transfers, so on an
//! ordinary reorganisation most of what is offered back is refused for
//! spending notes the winning branch has already spent. That refusal is right
//! and it takes nothing, and four thousand of them spent the whole budget
//! before the walk reached the one transfer the winning branch did not carry.
//!
//! The give-away is the pool: it comes out of such a rewind empty. There was
//! never any pressure on it, only a count spent on answers that put nothing in
//! it. So the bound is on what the pool takes, which is the thing it has room
//! for, and a refusal is made cheap enough to be worth making: everything
//! offered here sat in a block this node validated, so its signatures have
//! been checked once already.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{Accepted, ChainStore, MAX_POOLED, MAX_POOL_BYTES};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const PLAIN_FEE: u64 = 10_000;

/// Comfortably past the budget, so the walk has to get through them to reach
/// the block below.
const SHARED: usize = MAX_POOLED + 64;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// A chain built block by block, with the ledger kept so a rival can fork from
/// a point this one has passed.
struct Source {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Source {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, outputs: Vec<Note>, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn split_reward(&self, to: &SecretKey) -> Vec<Note> {
        let per_block = self.params.max_coinbase_outputs;
        let each = self.params.initial_reward.as_pebbles() / per_block as u64;
        let first = self.params.initial_reward.as_pebbles() - each * (per_block as u64 - 1);
        (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(pebbles(value), to.public_key())
            })
            .collect()
    }
}

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

/// A payment the winning branch does not carry comes back, however much of
/// what it does carry had to be walked past to reach it.
#[test]
fn a_payment_under_a_branch_of_shared_transfers_still_comes_back() {
    let miner = wallet(1);
    let payee = wallet(2);
    let params = params();

    let mut source = Source::new();
    let mut store = ChainStore::new(params);

    // Notes for the shared transfers, and one more for the payment.
    let mut notes: Vec<(NoteId, Note)> = Vec::new();
    while notes.len() <= SHARED {
        let outputs = source.split_reward(&miner);
        let block = source.mine(outputs.clone(), Vec::new());
        store.add_block(block.clone(), NOW).unwrap();
        for (index, note) in outputs.into_iter().enumerate() {
            notes.push((
                NoteId::new(block.coinbase.id(), u32::try_from(index).unwrap()),
                note,
            ));
        }
    }

    // The fork point. Both branches see every funding block and nothing after.
    let mut rival = Source {
        params,
        state: source.state.clone(),
        clock: source.clock,
    };

    // The oldest undone block carries the payment, and only the payment. It is
    // the one thing neither branch shares, which is what makes it the one that
    // has to come back.
    let (id, note) = notes[SHARED];
    let payment = spend(&params, id, note, &miner, &payee, pebbles(PLAIN_FEE * 100));
    let paid = payment.id();
    let carried = source.mine(source.split_reward(&miner), vec![payment]);
    store.add_block(carried, NOW).unwrap();

    // Everything above it is carried by both branches, so every one of these
    // is offered back and rightly refused.
    let shared: Vec<Transfer> = notes
        .iter()
        .take(SHARED)
        .map(|(id, note)| spend(&params, *id, *note, &miner, &wallet(3), pebbles(PLAIN_FEE)))
        .collect();

    let per_block = params.max_block_bytes / 400;
    for lot in shared.chunks(per_block) {
        let block = source.mine(source.split_reward(&miner), lot.to_vec());
        store.add_block(block, NOW).unwrap();
    }

    // The rival carries the same transfers and then goes further, so it wins.
    let mut reorganised = false;
    for lot in shared.chunks(per_block) {
        let block = rival.mine(rival.split_reward(&miner), lot.to_vec());
        if matches!(
            store.add_block(block, NOW),
            Ok(Accepted::Reorganised { .. })
        ) {
            reorganised = true;
        }
    }
    for _ in 0..3 {
        let block = rival.mine(rival.split_reward(&miner), Vec::new());
        if matches!(
            store.add_block(block, NOW),
            Ok(Accepted::Reorganised { .. })
        ) {
            reorganised = true;
        }
    }
    assert!(reorganised, "the heavier branch was taken");

    assert!(
        store.pooled(&paid).is_some(),
        "a payment the winning branch never carried was thrown away, and the pool it \
         could not fit into holds {} of the {MAX_POOLED} it has room for. Nothing was \
         short of anything: the budget went on refusing transfers the winning branch \
         also carries, which is the right answer and takes no room at all",
        store.pool_len()
    );
}

/// Transfers the losing branch carries and the winning one does not, past
/// what the budget allows.
///
/// `ONLY_OURS` and not `SHARED`: the test above builds transfers both branches
/// carry, which is the case the budget must not be spent on and which this
/// file was written for. Those are turned away by `check_transfer_again`
/// before `asked` moves, so however many of them there are the budget is never
/// reached — which is why the fixture above crosses the number and still
/// cannot show what the number does.
const ONLY_OURS: usize = MAX_POOLED + 64;

/// The budget bounds the asking, and nothing held that.
///
/// `repool` is the one thing standing between a deep switch and a full check
/// of every transfer it undoes. `MAX_REORG_DEPTH` blocks of
/// `max_transfers_per_block` is four million of them, each an encoding, a hash
/// and an elliptic curve verification, and all of it under the chain lock.
/// The bound is `if asked >= MAX_POOLED { return; }`, and deleting it left the
/// whole suite green.
///
/// The pool's own size cannot show it: the pool is bounded on its own, so it
/// ends full either way. What the budget bounds is how many were *asked*, and
/// that is what `last_rewind_offered` reports.
///
/// So the losing branch here carries transfers the winning one does not, which
/// is the case that costs: each one passes the cheap refusals and reaches
/// `accept_transfer` in full. Past the budget by sixty four, so the stop is the
/// budget and not the end of the list.
#[test]
fn a_rewind_stops_asking_at_the_budget_and_not_at_the_end_of_what_it_undid() {
    let miner = wallet(1);
    let payee = wallet(2);
    let params = params();

    let mut source = Source::new();
    let mut store = ChainStore::new(params);

    let mut notes: Vec<(NoteId, Note)> = Vec::new();
    while notes.len() < ONLY_OURS {
        let outputs = source.split_reward(&miner);
        let block = source.mine(outputs.clone(), Vec::new());
        store.add_block(block.clone(), NOW).unwrap();
        for (index, note) in outputs.into_iter().enumerate() {
            notes.push((
                NoteId::new(block.coinbase.id(), u32::try_from(index).unwrap()),
                note,
            ));
        }
    }

    // Both branches see every funding block and nothing after, so every note
    // below exists on both and is spent on only one.
    let mut rival = Source {
        params,
        state: source.state.clone(),
        clock: source.clock,
    };

    // Rising fees, and that is the whole of what makes this measure the
    // budget. At one fee they all rate the same, so once the pool is full the
    // cheap refusal above `accept_transfer` turns every later one away without
    // spending the budget, and `asked` stops at `MAX_POOLED` because the pool
    // filled rather than because the bound bit. Deleting either half of the
    // budget then changes nothing and the test says so anyway. Rising, each
    // one outbids the pool's cheapest, so each is worth asking about and the
    // only thing that can stop the asking is the bound.
    let ours: Vec<Transfer> = notes
        .iter()
        .take(ONLY_OURS)
        .enumerate()
        .map(|(at, (id, note))| {
            let fee = PLAIN_FEE.saturating_add(at as u64);
            spend(&params, *id, *note, &miner, &payee, pebbles(fee))
        })
        .collect();

    let per_block = params.max_block_bytes / 400;
    let mut carried = 0usize;
    for lot in ours.chunks(per_block) {
        carried += lot.len();
        let block = source.mine(source.split_reward(&miner), lot.to_vec());
        store.add_block(block, NOW).unwrap();
    }
    assert_eq!(carried, ONLY_OURS, "the branch carries what it was given");

    // The rival carries none of them and wins on length alone, so every one of
    // the transfers above is undone and is still spendable.
    let mut reorganised = false;
    for _ in 0..(ours.len() / per_block + 4) {
        let block = rival.mine(rival.split_reward(&miner), Vec::new());
        if matches!(
            store.add_block(block, NOW),
            Ok(Accepted::Reorganised { .. })
        ) {
            reorganised = true;
        }
    }
    assert!(reorganised, "the heavier branch was taken");

    let offered = store.last_rewind_offered();
    assert_eq!(
        offered, MAX_POOLED,
        "a rewind undoing {ONLY_OURS} transfers the winning branch does not \
         carry asked about {offered} of them; the budget is {MAX_POOLED}"
    );
    assert!(
        carried > MAX_POOLED,
        "the branch that was undone carried {carried} transfers and the budget \
         is {MAX_POOLED}: with fewer, the stop above is the end of the list \
         rather than the bound"
    );
}

/// Transfers a rewind offers back in the shapes below, which pay the plain
/// fee and so rate below everything the pool is filled with.
const UNDONE: usize = 8;

/// A transfer paying one note out to as many as a transfer may name.
///
/// The shape that fills a pool by its bytes rather than by its count: one
/// input, the most outputs the rules allow, and a pool full of them holds a
/// tenth of the transfers `MAX_POOLED` has room for.
fn wide(params: &ConsensusParams, id: NoteId, note: Note, owner: &SecretKey, fee: u64) -> Transfer {
    let outputs = u64::try_from(params.max_outputs_per_transfer).unwrap();
    let paid = note.value.as_pebbles() - fee;
    let each = paid / outputs;
    let first = paid - each * (outputs - 1);
    let notes = (0..outputs)
        .map(|index| {
            let value = if index == 0 { first } else { each };
            Note::new(pebbles(value), wallet(5).public_key())
        })
        .collect();
    let mut transfer = Transfer::new(vec![Input::hot(id)], notes);
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

/// Funds a chain with at least `wanted` spendable notes and returns them.
fn funded(
    source: &mut Source,
    store: &mut ChainStore,
    owner: &SecretKey,
    wanted: usize,
) -> Vec<(NoteId, Note)> {
    let mut notes: Vec<(NoteId, Note)> = Vec::new();
    while notes.len() < wanted {
        let outputs = source.split_reward(owner);
        let block = source.mine(outputs.clone(), Vec::new());
        store.add_block(block.clone(), NOW).unwrap();
        for (index, note) in outputs.into_iter().enumerate() {
            notes.push((
                NoteId::new(block.coinbase.id(), u32::try_from(index).unwrap()),
                note,
            ));
        }
    }
    notes
}

/// Takes the heavier branch from `rival`, undoing what `source` added past
/// the fork.
fn switch_to_rival(rival: &mut Source, store: &mut ChainStore) {
    let mut reorganised = false;
    for _ in 0..2 {
        let block = rival.mine(rival.split_reward(&wallet(1)), Vec::new());
        if matches!(
            store.add_block(block, NOW),
            Ok(Accepted::Reorganised { .. })
        ) {
            reorganised = true;
        }
    }
    assert!(reorganised, "the heavier branch was taken");
}

/// A pool full by its bytes turns away what it cannot take without being
/// asked, the same as a pool full by its count.
///
/// `repool` settles cheaply the transfers a full pool could not take, so that
/// they do not spend the budget, which counts the times the pool is asked. It
/// decided "full" by the count alone, and the pool it stands in front of is
/// full by the count or by the bytes, whichever comes first: `must_make_room`
/// asks both. A pool of transfers paying out to hundreds of notes each is full
/// by its bytes at a tenth of its count, and in front of it every transfer a
/// rewind offered back was asked about and refused, a unit of the budget
/// each, which is the spending on refusals this file was written against, in
/// the one shape its fixtures did not build. Nothing asked it, because every
/// pool in them filled by its count.
#[test]
fn a_pool_full_by_its_bytes_is_not_asked_about_what_it_cannot_take() {
    let miner = wallet(1);
    let params = params();
    let mut source = Source::new();
    let mut store = ChainStore::new(params);

    // Enough notes for however many wide transfers fill the pool, the plain
    // ones that close the last gap, and the ones the rewind will offer back.
    let first = funded(&mut source, &mut store, &miner, 1);
    let (id, note) = first[0];
    let wide_bytes = wide(&params, id, note, &miner, 20_000_000).encode().len();
    let plain_bytes = spend(&params, id, note, &miner, &wallet(3), pebbles(PLAIN_FEE))
        .encode()
        .len();
    let wides = MAX_POOL_BYTES / wide_bytes + 1;
    let fillers = wide_bytes / plain_bytes + 2;
    let mut notes = funded(&mut source, &mut store, &miner, wides + fillers + UNDONE);
    notes.extend(first);

    let mut rival = Source {
        params,
        state: source.state.clone(),
        clock: source.clock,
    };

    // The block the rewind will undo, carrying plain payments the winning
    // branch does not.
    let undone: Vec<Transfer> = notes
        .drain(..UNDONE)
        .map(|(id, note)| spend(&params, id, note, &miner, &wallet(3), pebbles(PLAIN_FEE)))
        .collect();
    let carried = source.mine(source.split_reward(&miner), undone.clone());
    store.add_block(carried, NOW).unwrap();

    // Filled by its bytes: wide transfers until one does not fit, then plain
    // ones paying twice the plain fee until one of those does not either.
    // Each rates above the payments being undone, so a full pool cannot take
    // those.
    let mut left = notes.into_iter();
    for (id, note) in left.by_ref() {
        if !store
            .accept_transfer(wide(&params, id, note, &miner, 20_000_000))
            .unwrap()
        {
            break;
        }
    }
    for (id, note) in left.by_ref() {
        let filler = spend(
            &params,
            id,
            note,
            &miner,
            &wallet(4),
            pebbles(PLAIN_FEE * 2),
        );
        if !store.accept_transfer(filler).unwrap() {
            break;
        }
    }
    assert!(
        left.next().is_some(),
        "the notes ran out before the pool refused anything, so it is not full"
    );
    assert!(
        store.pool_len() < MAX_POOLED,
        "the pool holds {} transfers, so it filled by its count and this asks nothing new",
        store.pool_len()
    );

    switch_to_rival(&mut rival, &mut store);

    for payment in &undone {
        assert!(
            store.pooled(&payment.id()).is_none(),
            "a full pool took a payment rating below everything in it, so the rewind \
             offered back something it had room for"
        );
    }
    let offered = store.last_rewind_offered();
    assert_eq!(
        offered, 0,
        "a pool full by its bytes was asked about {offered} of the {UNDONE} transfers it \
         could not take, and each one spent a unit of the budget a pool full by its count \
         would have kept"
    );
}

/// A pool with room takes back a payment that rates below the cheapest thing
/// in it.
///
/// The other half of the test above. Turning a transfer away without asking
/// is right only when the pool is full; a pool with room takes whatever pays
/// its floor, however the rate compares, and a rewind that skipped it would be
/// cancelling a payment for being cheaper than a neighbour.
#[test]
fn a_pool_with_room_takes_back_a_payment_rating_below_its_cheapest() {
    let miner = wallet(1);
    let params = params();
    let mut source = Source::new();
    let mut store = ChainStore::new(params);

    let mut notes = funded(&mut source, &mut store, &miner, 2);
    let mut rival = Source {
        params,
        state: source.state.clone(),
        clock: source.clock,
    };

    let (id, note) = notes.pop().unwrap();
    let payment = spend(&params, id, note, &miner, &wallet(3), pebbles(PLAIN_FEE));
    let carried = source.mine(source.split_reward(&miner), vec![payment.clone()]);
    store.add_block(carried, NOW).unwrap();

    let (id, note) = notes.pop().unwrap();
    let dearer = spend(
        &params,
        id,
        note,
        &miner,
        &wallet(4),
        pebbles(PLAIN_FEE * 2),
    );
    assert!(store.accept_transfer(dearer).unwrap(), "the pool has room");

    switch_to_rival(&mut rival, &mut store);

    assert!(
        store.pooled(&payment.id()).is_some(),
        "a payment the winning branch never carried was not taken back into a pool with \
         room for it, because something already in it paid a better rate"
    );
    assert_eq!(
        store.last_rewind_offered(),
        1,
        "and the pool was asked once"
    );
}

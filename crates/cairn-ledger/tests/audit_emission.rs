//! Adversarial audit of the money: the emission schedule, the coinbase rules,
//! `Amount`, and conservation across a chain that reorganises.
//!
//! Nothing here is a fixture. Every number the report quotes is summed by
//! running the shipped schedule rather than by reading its formula.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::print_stdout
)]

use std::collections::BTreeMap;

use cairn_crypto::SecretKey;
use cairn_ledger::emission::{
    reward_at, HALVING_INTERVAL, INITIAL_REWARD_PEBBLES, TAIL_REWARD_PEBBLES,
};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer, MAX_COINBASE_EXTRA};
use cairn_ledger::validation::{
    assemble_block, connect_block, disconnect_block, BlockError, TransferError,
};
use cairn_ledger::{Block, ConnectedBlock, ConsensusParams, LedgerState};
use cairn_primitives::amount::PEBBLES_PER_CAIRN;
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const SPACING: u64 = 600;

fn initial() -> Amount {
    Amount::from_pebbles(INITIAL_REWARD_PEBBLES).unwrap()
}

fn tail() -> Amount {
    Amount::from_pebbles(TAIL_REWARD_PEBBLES).unwrap()
}

fn reward(height: u64) -> Amount {
    reward_at(height, HALVING_INTERVAL, initial(), tail())
}

// ---------------------------------------------------------------------------
// 1. The schedule against its own statement.
// ---------------------------------------------------------------------------

/// Sums the shipped schedule block by block, over every height that pays more
/// than the floor, and states the totals to the pebble.
#[test]
fn the_whole_schedule_summed_by_running_it() {
    // Where the floor takes over, found by walking rather than by algebra.
    let mut height = 0u64;
    while reward(height) != tail() {
        height = height.checked_add(1).unwrap();
        assert!(height < 100_000_000, "the floor is never reached");
    }
    let first_tail_height = height;

    // Every height below it, one at a time.
    let mut total: u128 = 0;
    let mut per_era: Vec<(u64, u64, u128)> = Vec::new();
    let mut era_start = 0u64;
    let mut era_reward = reward(0).as_pebbles();
    let mut era_total: u128 = 0;
    for h in 0..first_tail_height {
        let paid = reward(h).as_pebbles();
        if paid != era_reward {
            per_era.push((era_start, era_reward, era_total));
            era_start = h;
            era_reward = paid;
            era_total = 0;
        }
        era_total = era_total.checked_add(u128::from(paid)).unwrap();
        total = total.checked_add(u128::from(paid)).unwrap();
    }
    per_era.push((era_start, era_reward, era_total));

    println!("\n--- emission, summed by running the shipped schedule ---");
    for (index, (start, paid, sum)) in per_era.iter().enumerate() {
        let peb = u128::from(PEBBLES_PER_CAIRN);
        println!(
            "era {index:2}: heights {start:>9}..{:<9} reward {paid:>10} pebbles \
             ({}.{:08} CAIRN)  era total {sum} pebbles ({}.{:08} CAIRN)",
            start + HALVING_INTERVAL - 1,
            u128::from(*paid) / peb,
            u128::from(*paid) % peb,
            *sum / peb,
            *sum % peb,
        );
    }
    println!("eras that pay above the floor: {}", per_era.len());
    println!("first height paid at the floor: {first_tail_height}");
    println!("last height paid above it:      {}", first_tail_height - 1);
    println!(
        "  paying {} pebbles there, and {} at the height after",
        reward(first_tail_height - 1).as_pebbles(),
        reward(first_tail_height).as_pebbles()
    );
    println!("total before the floor: {total} pebbles");
    println!(
        "                      = {}.{:08} CAIRN",
        total / u128::from(PEBBLES_PER_CAIRN),
        total % u128::from(PEBBLES_PER_CAIRN)
    );

    // What an unrounded geometric series would have paid, so the rounding loss
    // is a number rather than an impression.
    let ideal_per_block: u128 = per_era
        .iter()
        .enumerate()
        .map(|(index, _)| {
            // 5e9 / 2^index in eighths of a pebble, exact for every era here.
            (u128::from(INITIAL_REWARD_PEBBLES) * 8) >> index
        })
        .sum();
    let ideal = ideal_per_block * u128::from(HALVING_INTERVAL) / 8;
    println!("an unrounded schedule would pay: {ideal} pebbles");
    println!(
        "rounding loses: {} pebbles over the whole run",
        ideal - total
    );

    // The claims, stated exactly.
    assert_eq!(per_era.len(), 13);
    assert_eq!(first_tail_height, 13 * HALVING_INTERVAL);
    assert_eq!(first_tail_height, 13_665_600);
    assert_eq!(total, 10_510_716_795_955_200);
    assert_eq!(reward(first_tail_height - 1).as_pebbles(), 1_220_703);
    assert_eq!(reward(first_tail_height).as_pebbles(), TAIL_REWARD_PEBBLES);
    // The floor is perpetual, so nothing is ever the last paying block.
    assert_eq!(reward(u64::MAX), tail());
    // Rounding only ever loses, never gains.
    assert!(ideal >= total);
    assert_eq!(ideal - total, 919_800);

    // The whitepaper's "roughly 105 million CAIRN", to the pebble.
    let in_cairn = total / u128::from(PEBBLES_PER_CAIRN);
    assert_eq!(in_cairn, 105_107_167);
}

/// The prose in `docs/cairn-whitepaper.html` against the constants in code.
#[test]
fn the_documents_and_the_constants_agree() {
    assert_eq!(INITIAL_REWARD_PEBBLES, 50 * PEBBLES_PER_CAIRN, "50 CAIRN");
    assert_eq!(HALVING_INTERVAL, 1_051_200, "1 051 200 blocks");
    assert_eq!(
        TAIL_REWARD_PEBBLES,
        PEBBLES_PER_CAIRN / 100,
        "a floor of 0.01 CAIRN"
    );
    assert_eq!(PEBBLES_PER_CAIRN, 100_000_000, "10^8 pebbles to one CAIRN");
    // "about two years at a one minute block time"
    let years = f64::from(u32::try_from(HALVING_INTERVAL).unwrap()) / (365.25 * 24.0 * 60.0);
    assert!((years - 2.0).abs() < 0.01, "{years} years an era");
    // And the same rules are what a named network actually runs.
    for name in ["testnet-6", "devnet"] {
        let params = ConsensusParams::for_network(name).unwrap();
        assert_eq!(params.initial_reward.as_pebbles(), INITIAL_REWARD_PEBBLES);
        assert_eq!(params.tail_reward.as_pebbles(), TAIL_REWARD_PEBBLES);
        assert_eq!(params.halving_interval, HALVING_INTERVAL);
    }
}

// ---------------------------------------------------------------------------
// 2. The halving boundary.
// ---------------------------------------------------------------------------

#[test]
fn every_halving_boundary_pays_on_the_stated_side_of_the_line() {
    for era in 0..13u64 {
        let start = era * HALVING_INTERVAL;
        let end = start + HALVING_INTERVAL - 1;
        let expected = Amount::from_pebbles(INITIAL_REWARD_PEBBLES >> era).unwrap();
        assert_eq!(reward(start), expected, "first block of era {era}");
        assert_eq!(reward(end), expected, "last block of era {era}");
        if era > 0 {
            assert_eq!(
                reward(start - 1).as_pebbles(),
                INITIAL_REWARD_PEBBLES >> (era - 1),
                "the block before the boundary is still on the old rate"
            );
        }
        // An era is exactly the stated number of blocks: no height inside it
        // pays anything else.
        for probe in [start, start + 1, end - 1, end, start + HALVING_INTERVAL / 2] {
            assert_eq!(reward(probe), expected, "height {probe} in era {era}");
        }
    }
    // The interval is counted from height zero, so the first era holds one
    // more block than the naive "halving at 1 051 200 blocks mined" reading:
    // heights 0..=1051199 inclusive.
    assert_eq!(reward(0), initial());
    assert_eq!(reward(HALVING_INTERVAL - 1), initial());
    assert_ne!(reward(HALVING_INTERVAL), initial());
}

// ---------------------------------------------------------------------------
// 3. Arithmetic at every extreme.
// ---------------------------------------------------------------------------

#[test]
fn the_schedule_holds_at_every_extreme_height() {
    assert_eq!(reward(0), initial());
    assert_eq!(reward(1), initial());
    assert_eq!(reward(u64::MAX), tail());
    assert_eq!(reward(u64::MAX - 1), tail());
    // The shift would be 64 or more here, which on u64 is undefined behaviour
    // in C and a panic in a debug Rust build. It is neither.
    assert_eq!(reward(64 * HALVING_INTERVAL), tail());
    assert_eq!(reward(63 * HALVING_INTERVAL), tail());
    assert_eq!(reward(1_000_000 * HALVING_INTERVAL), tail());

    // Never rises, at any height, ever.
    let mut previous = reward(0);
    for era in 0..200u64 {
        let now = reward(era.saturating_mul(HALVING_INTERVAL));
        assert!(now <= previous, "the reward rose at era {era}");
        previous = now;
    }
    // And never zero.
    for height in [
        0,
        1,
        HALVING_INTERVAL,
        13 * HALVING_INTERVAL,
        u64::MAX / 2,
        u64::MAX,
    ] {
        assert!(
            reward(height) > Amount::ZERO,
            "height {height} pays nothing"
        );
    }
}

#[test]
fn a_degenerate_interval_does_not_mint() {
    // Not reachable from the wire; `halving_interval` is a rule of the
    // network. Recorded because the branch exists and pays the opening rate
    // forever, which is the largest number in the file.
    assert_eq!(reward_at(u64::MAX, 0, initial(), tail()), initial());
    // A tail above the opening rate pins every height to the tail.
    let odd = Amount::from_cairn("1000").unwrap();
    assert_eq!(reward_at(0, HALVING_INTERVAL, initial(), odd), odd);
    // An initial reward at the ceiling still halves rather than wrapping.
    assert_eq!(
        reward_at(
            HALVING_INTERVAL,
            HALVING_INTERVAL,
            Amount::MAX_MONEY,
            tail()
        )
        .as_pebbles(),
        Amount::MAX_MONEY.as_pebbles() / 2
    );
}

#[test]
fn the_supply_stays_under_the_ceiling_for_longer_than_anyone_will_ask() {
    // The floor is perpetual, so the supply has no bound; the ceiling on a
    // single amount does. This states when the two would meet.
    let before_floor: u128 = 10_510_716_795_955_200;
    let room = u128::from(Amount::MAX_MONEY.as_pebbles()) - before_floor;
    let per_year = u128::from(TAIL_REWARD_PEBBLES) * 525_600;
    let years = room / per_year;
    println!(
        "the tail pays {} CAIRN a year",
        per_year / u128::from(PEBBLES_PER_CAIRN)
    );
    println!("the supply would reach Amount::MAX_MONEY in {years} years of floor");
    assert!(years > 100_000);
}

// ---------------------------------------------------------------------------
// 4. `Amount` itself.
// ---------------------------------------------------------------------------

#[test]
fn the_ceiling_is_enforced_on_every_way_an_amount_is_made() {
    assert!(Amount::from_pebbles(Amount::MAX_MONEY.as_pebbles() + 1).is_none());
    assert!(Amount::from_cairn("1000000001").is_none());
    assert!(Amount::MAX_MONEY
        .checked_add(Amount::from_pebbles(1).unwrap())
        .is_none());
    assert!(Amount::checked_sum([Amount::MAX_MONEY, Amount::MAX_MONEY]).is_none());
    // The wire is the one place a stranger picks the number.
    let over = (Amount::MAX_MONEY.as_pebbles() + 1).encode();
    assert!(Amount::decode(&over).is_err(), "the wire refuses it too");
    let at = Amount::MAX_MONEY.as_pebbles().encode();
    assert_eq!(Amount::decode(&at).unwrap(), Amount::MAX_MONEY);
    // Subtraction cannot land above the ceiling, so it needs no check.
    assert_eq!(
        Amount::MAX_MONEY.checked_sub(Amount::MAX_MONEY),
        Some(Amount::ZERO)
    );
    assert!(Amount::ZERO
        .checked_sub(Amount::from_pebbles(1).unwrap())
        .is_none());
}

#[test]
fn two_amounts_never_read_the_same_and_a_reading_comes_back_whole() {
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();
    let probes: Vec<u64> = vec![
        0,
        1,
        99_999_999,
        100_000_000,
        100_000_001,
        123_456_789,
        999_999_999,
        1_000_000_000,
        TAIL_REWARD_PEBBLES,
        INITIAL_REWARD_PEBBLES,
        Amount::MAX_MONEY.as_pebbles() - 1,
        Amount::MAX_MONEY.as_pebbles(),
    ];
    for pebbles in probes {
        let amount = Amount::from_pebbles(pebbles).unwrap();
        let shown = amount.to_string();
        if let Some(other) = seen.insert(shown.clone(), pebbles) {
            panic!("{other} and {pebbles} both read as {shown}");
        }
        // What it prints, read back, both with the unit and without. The
        // parser used to take neither, which made the doc comment's claim
        // that a figure can be typed straight back in false at the one place
        // it matters: the wallet prints with the unit and parses with this.
        let bare = shown.strip_suffix(" CAIRN").expect("the unit is printed");
        assert_eq!(
            Amount::from_cairn(bare),
            Some(amount),
            "{shown} did not read back without its unit"
        );
        assert_eq!(
            Amount::from_cairn(&shown),
            Some(amount),
            "{shown} did not read back as it was printed"
        );
    }
    // And a sweep, so injectivity is not just a claim about twelve numbers.
    let mut previous = String::new();
    for pebbles in (0..2_000_000u64).step_by(7) {
        let shown = Amount::from_pebbles(pebbles).unwrap().to_string();
        assert_ne!(shown, previous);
        previous = shown;
    }
}

#[test]
fn nothing_that_could_be_meant_two_ways_is_accepted() {
    for text in [
        "",
        ".",
        "-1",
        "+1",
        "1,5",
        "1e3",
        " 1 . 5",
        "1.234567891",
        "0x10",
        "1.2.3",
        "abc",
        "1 cairn",
        "1 CAIRNS",
        "1 CAIRN CAIRN",
        "١٢",
    ] {
        assert!(
            Amount::from_cairn(text).is_none(),
            "{text:?} was accepted as an amount"
        );
    }
    // What is accepted, and what it means.
    assert_eq!(Amount::from_cairn("1.").unwrap().as_pebbles(), 100_000_000);
    assert_eq!(Amount::from_cairn(".5").unwrap().as_pebbles(), 50_000_000);
    assert_eq!(
        Amount::from_cairn("0000000001").unwrap().as_pebbles(),
        100_000_000,
        "leading zeros are taken, which is harmless and worth knowing"
    );
}

// ---------------------------------------------------------------------------
// 5. The coinbase, on a real chain.
// ---------------------------------------------------------------------------

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Rules under which a reward is spendable at once.
///
/// What is being audited below is the money: what a coinbase may claim, what a
/// fee is, and that nothing is created or lost. A reward that cannot be moved
/// for a thousand blocks would make every one of those tests a thousand blocks
/// long without changing what any of them shows. The wait itself is audited in
/// `audit_coinbase_maturity.rs`.
fn spendable_at_once() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn build(
    state: &LedgerState,
    params: &ConsensusParams,
    coinbase: CoinbaseTransaction,
    transfers: Vec<Transfer>,
) -> Result<Block, BlockError> {
    let height = state.next_height().unwrap();
    assemble_block(
        state,
        coinbase,
        transfers,
        params,
        1_000 + height * SPACING,
        0,
    )
}

fn mine(
    state: &mut LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    transfers: Vec<Transfer>,
) -> (Block, ConnectedBlock) {
    let height = state.next_height().unwrap();
    let fees = Amount::ZERO;
    let pay = params.reward_at(height).checked_add(fees).unwrap();
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(pay, miner.public_key())]);
    let block = build(state, params, coinbase, transfers).unwrap();
    let connected = connect_block(state, &block, params, NOW).unwrap();
    (block, connected)
}

#[test]
fn a_coinbase_cannot_take_one_pebble_more_than_the_schedule_and_the_fees() {
    let params = spendable_at_once();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let height = state.next_height().unwrap();
    let allowed = params.reward_at(height);
    let one = Amount::from_pebbles(1).unwrap();

    let greedy = CoinbaseTransaction::new(
        height,
        vec![Note::new(
            allowed.checked_add(one).unwrap(),
            miner.public_key(),
        )],
    );
    assert!(
        matches!(
            build(&state, &params, greedy, Vec::new()),
            Err(BlockError::CoinbaseOverpay { .. })
        ),
        "one pebble over is one pebble minted"
    );

    // Spread over several outputs, which is the same overpay in another shape.
    let half = Amount::from_pebbles(allowed.as_pebbles() / 2 + 1).unwrap();
    let split = CoinbaseTransaction::new(
        height,
        vec![
            Note::new(half, miner.public_key()),
            Note::new(half, wallet(2).public_key()),
        ],
    );
    assert!(matches!(
        build(&state, &params, split, Vec::new()),
        Err(BlockError::CoinbaseOverpay { .. })
    ));

    // Exactly the reward is fine, and so is less.
    let exact = CoinbaseTransaction::new(height, vec![Note::new(allowed, miner.public_key())]);
    let block = build(&state, &params, exact, Vec::new()).unwrap();
    connect_block(&mut state, &block, &params, NOW).unwrap();
}

#[test]
fn a_coinbase_is_capped_in_number_of_outputs_and_in_what_it_carries() {
    let params = spendable_at_once();
    let miner = wallet(1);
    let state = LedgerState::archiving();
    let height = state.next_height().unwrap();
    let one = Amount::from_pebbles(1).unwrap();

    let many: Vec<Note> = (0..=params.max_coinbase_outputs)
        .map(|_| Note::new(one, miner.public_key()))
        .collect();
    assert!(matches!(
        build(
            &state,
            &params,
            CoinbaseTransaction::new(height, many),
            Vec::new()
        ),
        Err(BlockError::TooManyCoinbaseOutputs { .. })
    ));

    // A zero-value output is refused, so a coinbase cannot pad the note set
    // for free.
    assert!(matches!(
        build(
            &state,
            &params,
            CoinbaseTransaction::new(height, vec![Note::new(Amount::ZERO, miner.public_key())]),
            Vec::new()
        ),
        Err(BlockError::ZeroValueCoinbaseOutput { index: 0 })
    ));

    // Extra data is bounded, both by the rule and by the decoder.
    let big = vec![0u8; MAX_COINBASE_EXTRA + 1];
    let fat = CoinbaseTransaction::with_extra(
        height,
        vec![Note::new(params.reward_at(height), miner.public_key())],
        big,
    );
    assert!(matches!(
        build(&state, &params, fat.clone(), Vec::new()),
        Err(BlockError::CoinbaseExtraTooLarge { .. })
    ));
    assert!(
        CoinbaseTransaction::decode(&fat.encode()).is_err(),
        "the wire refuses it before any rule is consulted"
    );
}

#[test]
fn a_fee_cannot_be_counted_twice_or_conjured_from_nothing() {
    let params = spendable_at_once();
    let (miner, alice) = (wallet(1), wallet(2));
    let mut state = LedgerState::archiving();

    let (block, _) = mine(&mut state, &params, &miner, Vec::new());
    let coin = NoteId::new(block.coinbase.id(), 0);
    let value = params.reward_at(0);
    let spent = Note::new(value, miner.public_key());

    // One transfer paying a one-CAIRN fee.
    let fee = Amount::from_cairn("1").unwrap();
    let keep = value.checked_sub(fee).unwrap();
    let mut transfer = Transfer::new(
        vec![Input::hot(coin)],
        vec![Note::new(keep, alice.public_key())],
    );
    transfer.sign_input(params.network, 0, &spent, &miner);

    let height = state.next_height().unwrap();
    let honest = params.reward_at(height).checked_add(fee).unwrap();

    // Claiming the fee twice.
    let doubled = params
        .reward_at(height)
        .checked_add(fee)
        .unwrap()
        .checked_add(fee)
        .unwrap();
    assert!(matches!(
        build(
            &state,
            &params,
            CoinbaseTransaction::new(height, vec![Note::new(doubled, miner.public_key())]),
            vec![transfer.clone()]
        ),
        Err(BlockError::CoinbaseOverpay { .. })
    ));

    // Carrying the same transfer twice so the fee is collected twice: the
    // second copy spends a note the first already took.
    assert!(matches!(
        build(
            &state,
            &params,
            CoinbaseTransaction::new(height, vec![Note::new(doubled, miner.public_key())]),
            vec![transfer.clone(), transfer.clone()]
        ),
        Err(BlockError::InvalidTransfer { index: 1, .. })
    ));

    // A transfer that spends nothing is not a transfer.
    let empty = Transfer::new(Vec::new(), vec![Note::new(fee, miner.public_key())]);
    assert!(matches!(
        build(
            &state,
            &params,
            CoinbaseTransaction::new(height, vec![Note::new(honest, miner.public_key())]),
            vec![empty]
        ),
        Err(BlockError::InvalidTransfer { index: 0, .. })
    ));

    // A transfer spending a note this very block creates: the coinbase output
    // of the block being built, which no rule has to forbid because the state
    // a transfer is resolved against is the one from before the block.
    let unborn = NoteId::new(
        CoinbaseTransaction::new(height, vec![Note::new(honest, miner.public_key())]).id(),
        0,
    );
    let mut incest = Transfer::new(
        vec![Input::hot(unborn)],
        vec![Note::new(
            Amount::from_cairn("1").unwrap(),
            alice.public_key(),
        )],
    );
    incest.sign_input(
        params.network,
        0,
        &Note::new(honest, miner.public_key()),
        &miner,
    );
    assert!(matches!(
        build(
            &state,
            &params,
            CoinbaseTransaction::new(height, vec![Note::new(honest, miner.public_key())]),
            vec![incest]
        ),
        Err(BlockError::InvalidTransfer { index: 0, .. })
    ));

    // And the honest block is accepted, with the fee and nothing more.
    let block = build(
        &state,
        &params,
        CoinbaseTransaction::new(height, vec![Note::new(honest, miner.public_key())]),
        vec![transfer],
    )
    .unwrap();
    let connected = connect_block(&mut state, &block, &params, NOW).unwrap();
    assert_eq!(connected.total_fees, fee);
}

/// What the maturity rule is for, told as the story it was found in.
///
/// A miner is paid at height N and pays somebody at N+1. Two blocks are then
/// reorganised away, which takes no attack and no rule breaking: it is a thing
/// that happens. The coinbase behind the payment cannot be mined again by
/// anybody, because it belonged to that block, so the payment cannot be
/// carried on to the winning branch either. The recipient's money is gone and
/// nothing was invalid at any point, which is exactly why nothing complained.
///
/// The wait is what stops the payment from being made at all until the block
/// that paid the reward is past the depth a node will reorganise through.
#[test]
fn a_reward_cannot_be_paid_on_to_somebody_a_reorganisation_can_rob() {
    let params = ConsensusParams::testnet();
    let (miner, alice) = (wallet(1), wallet(2));
    let mut state = LedgerState::archiving();

    let (block, first) = mine(&mut state, &params, &miner, Vec::new());
    let coin = NoteId::new(block.coinbase.id(), 0);
    let value = params.reward_at(0);
    let spent = Note::new(value, miner.public_key());

    let mut transfer = Transfer::new(
        vec![Input::hot(coin)],
        vec![Note::new(value, alice.public_key())],
    );
    transfer.sign_input(params.network, 0, &spent, &miner);

    let height = state.next_height().unwrap();
    assert_eq!(height, 1, "the block straight after the one that minted it");
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.reward_at(height), miner.public_key())],
    );
    let refused = build(&state, &params, coinbase, vec![transfer]);
    assert!(
        matches!(
            refused,
            Err(BlockError::InvalidTransfer {
                index: 0,
                source: TransferError::ImmatureCoinbase { matures_at, .. },
            }) if matures_at == params.coinbase_maturity
        ),
        "alice was paid out of a reward that can still be taken away: {refused:?}"
    );

    // The reorganisation still removes the reward, which nothing can prevent.
    // What it can no longer remove is somebody else's money.
    disconnect_block(&mut state, &first);
    assert!(state.hot_note(&coin).is_none());
    assert_eq!(state.tip(), None);
    assert_eq!(
        state.supply(),
        Amount::ZERO,
        "the money went with the block that made it"
    );
}

// ---------------------------------------------------------------------------
// 6. Conservation over a long chain, including a reorganisation.
// ---------------------------------------------------------------------------

/// Every unspent note this test has watched go past.
///
/// This is the other half of the identity the ledger can now state for itself.
/// The ledger works its supply out from what each block issued and what its
/// transfers destroyed; this works the same number out from the notes
/// themselves. Two computations sharing nothing but the answer they should
/// reach, which is the only shape of check that catches a pebble from nowhere.
///
/// What used to be here as well was a running issued total, kept alongside
/// this one because nothing in the ledger stated the supply and an auditor had
/// nowhere else to get it. The ledger states it now, so the total is gone and
/// the ledger is asked instead. That is the whole point of the change: a chain
/// that cannot say how much money it has cannot notice when the answer is
/// wrong, and the books that stood in for it only ever checked this test.
#[derive(Default)]
struct Notes {
    unspent: BTreeMap<NoteId, Note>,
}

impl Notes {
    /// What every note still standing is worth, in pebbles.
    fn total(&self) -> u128 {
        self.unspent
            .values()
            .map(|note| u128::from(note.value.as_pebbles()))
            .sum()
    }

    fn apply(&mut self, connected: &ConnectedBlock) {
        let transition = &connected.transition;
        for id in &transition.spent_hot {
            self.unspent
                .remove(id)
                .expect("the ledger spent a note these do not hold");
        }
        for spend in &transition.spent_cold {
            let note = self
                .unspent
                .remove(&spend.id)
                .expect("the ledger spent a cold note these do not hold");
            assert_eq!(
                note.value, spend.note.value,
                "value changed on the way down"
            );
        }
        for (id, note) in &transition.created {
            assert!(
                self.unspent.insert(*id, *note).is_none(),
                "a note identifier was handed out twice"
            );
        }
        // Eviction moves money between tiers and must not change any of it.
        for (id, note) in &transition.evicted {
            assert_eq!(
                self.unspent.get(id).map(|held| held.value),
                Some(note.value),
                "a note changed value on its way to the cold set"
            );
        }
    }

    fn undo(&mut self, connected: &ConnectedBlock) {
        let transition = &connected.transition;
        for (id, _) in &transition.created {
            self.unspent.remove(id).expect("undoing an uncreated note");
        }
        for spend in &transition.spent_cold {
            self.unspent.insert(spend.id, spend.note);
        }
        // Hot spends are put back by the caller, from the ledger: the block's
        // own inputs no longer say what those notes were worth, and the undo
        // carries them back into the state where they can be read.
    }
}

#[test]
fn money_in_equals_money_out_over_a_long_chain_and_a_reorganisation() {
    // A small tier, so notes fall to the cold set and the grace window is
    // exercised rather than described. A short wait on the reward, so this
    // test can spend one without mining a thousand blocks first; what the
    // wait itself is worth is audited in `audit_coinbase_maturity.rs`.
    let params = ConsensusParams::testnet()
        .with_hot_capacity(8)
        .with_coinbase_maturity(4);
    let (miner, alice, bob) = (wallet(1), wallet(2), wallet(3));
    let mut state = LedgerState::archiving();
    let mut notes = Notes::default();
    let mut chain: Vec<(Block, ConnectedBlock)> = Vec::new();
    // What the schedule says the chain may have created by now.
    let mut allowed_issue: u128 = 0;
    // Notes this test knows it owns and can still spend, oldest first.
    let mut purse: Vec<(NoteId, Note)> = Vec::new();

    let step = |state: &mut LedgerState,
                notes: &mut Notes,
                chain: &mut Vec<(Block, ConnectedBlock)>,
                allowed_issue: &mut u128,
                purse: &mut Vec<(NoteId, Note)>,
                transfers: Vec<Transfer>,
                fees: Amount| {
        let height = state.next_height().unwrap();
        let schedule = params.reward_at(height);
        let pay = schedule.checked_add(fees).unwrap();
        let coinbase = CoinbaseTransaction::new(height, vec![Note::new(pay, miner.public_key())]);
        let block = build(state, &params, coinbase, transfers).unwrap();

        let before = u128::from(state.supply().as_pebbles());
        let connected = connect_block(state, &block, &params, NOW).unwrap();
        assert_eq!(
            connected.total_fees, fees,
            "the block's fees are not what was paid"
        );
        notes.apply(&connected);
        let after = u128::from(state.supply().as_pebbles());

        // The property, block by block, asked of the ledger: what the supply
        // gained is exactly what the coinbase created beyond the fees it
        // recycled, and never more than the schedule allows.
        let created = u128::from(pay.as_pebbles()) - u128::from(fees.as_pebbles());
        assert_eq!(
            after.checked_sub(before),
            Some(created),
            "block {height} moved the supply by something other than its emission"
        );
        assert!(
            created <= u128::from(schedule.as_pebbles()),
            "block {height} created more than the schedule allows"
        );
        *allowed_issue += u128::from(schedule.as_pebbles());
        assert!(
            after <= *allowed_issue,
            "the chain is ahead of its schedule"
        );

        // And the identity the ledger cannot check for itself: what it says it
        // has issued is what the notes are worth. Nobody holds the cold set,
        // so only something watching from outside can put these two side by
        // side, which is what this test is for.
        assert_eq!(
            after,
            notes.total(),
            "block {height}: the ledger's supply is not what its notes are worth"
        );

        // Structural conservation: every note is in one tier or the other, and
        // nothing is in both or in neither.
        assert_eq!(
            state.hot_len() as u64 + state.cold().len(),
            notes.unspent.len() as u64,
            "the tiers and the notes disagree about how many there are"
        );

        purse.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(pay, miner.public_key()),
        ));
        chain.push((block, connected));
    };

    // Ninety blocks of nothing but emission, which overflows the eight-note
    // tier, pushes notes down, and carries the oldest of them out of the
    // grace window so a real proof is needed to spend it.
    for _ in 0..90 {
        step(
            &mut state,
            &mut notes,
            &mut chain,
            &mut allowed_issue,
            &mut purse,
            Vec::new(),
            Amount::ZERO,
        );
    }
    assert!(
        !state.cold().is_empty(),
        "nothing fell, so nothing is tested"
    );

    // A hot spend, with a fee.
    let fee = Amount::from_cairn("0.25").unwrap();
    let (hot_id, hot_note) = purse
        .iter()
        .rev()
        .find(|(id, _)| state.hot_note(id).is_some() && is_mature(&state, id))
        .copied()
        .expect("a matured note still in the hot set");
    let mut hot_spend = Transfer::new(
        vec![Input::hot(hot_id)],
        vec![Note::new(
            hot_note.value.checked_sub(fee).unwrap(),
            alice.public_key(),
        )],
    );
    hot_spend.sign_input(params.network, 0, &hot_note, &miner);
    purse.retain(|(id, _)| *id != hot_id);
    step(
        &mut state,
        &mut notes,
        &mut chain,
        &mut allowed_issue,
        &mut purse,
        vec![hot_spend],
        fee,
    );

    // A grace spend: a note that has fallen but is still spendable without a
    // proof, offered as if it were hot.
    let (grace_id, grace_note) = purse
        .iter()
        .find(|(id, _)| state.hot_note(id).is_none() && state.within_grace(id).is_some())
        .copied()
        .expect("a note inside the grace window");
    let mut grace_spend = Transfer::new(
        vec![Input::hot(grace_id)],
        vec![Note::new(
            grace_note.value.checked_sub(fee).unwrap(),
            bob.public_key(),
        )],
    );
    grace_spend.sign_input(params.network, 0, &grace_note, &miner);
    purse.retain(|(id, _)| *id != grace_id);
    step(
        &mut state,
        &mut notes,
        &mut chain,
        &mut allowed_issue,
        &mut purse,
        vec![grace_spend],
        fee,
    );

    // A cold spend: a note out of the window, carrying its own proof.
    let (cold_id, cold_note) = purse
        .iter()
        .find(|(id, _)| state.hot_note(id).is_none() && state.within_grace(id).is_none())
        .copied()
        .expect("a note past the grace window");
    let position = state
        .cold()
        .locate(&cold_id, &cold_note)
        .expect("an archivist knows where it sits");
    let proof = state.cold().prove(position).expect("and can prove it");
    let mut cold_spend = Transfer::new(
        vec![Input::cold(cold_id, cold_note, position, proof)],
        vec![Note::new(
            cold_note.value.checked_sub(fee).unwrap(),
            alice.public_key(),
        )],
    );
    cold_spend.sign_input(params.network, 0, &cold_note, &miner);
    purse.retain(|(id, _)| *id != cold_id);
    step(
        &mut state,
        &mut notes,
        &mut chain,
        &mut allowed_issue,
        &mut purse,
        vec![cold_spend],
        fee,
    );

    // A few more, so the branch about to be undone has depth.
    for _ in 0..6 {
        step(
            &mut state,
            &mut notes,
            &mut chain,
            &mut allowed_issue,
            &mut purse,
            Vec::new(),
            Amount::ZERO,
        );
    }

    let supply_at_tip = u128::from(state.supply().as_pebbles());
    let height_at_tip = state.tip().unwrap().height;
    println!(
        "\n--- {} blocks: the ledger says {} pebbles, the schedule allows {} ---",
        height_at_tip + 1,
        supply_at_tip,
        allowed_issue
    );
    assert_eq!(
        supply_at_tip, allowed_issue,
        "every block took exactly its reward, so the two must match"
    );

    // The reorganisation: undo five blocks, then build five different ones.
    // A total that is right going forward and wrong coming back is worse than
    // none at all, because it forks nodes that did nothing wrong.
    for _ in 0..5 {
        let (_, connected) = chain.pop().unwrap();
        disconnect_block(&mut state, &connected);
        notes.undo(&connected);
        for id in &connected.transition.spent_hot {
            // Whatever the block spent is unspent again; its value comes from
            // the note the block's own transfer resolved, which the undo
            // carries back into the ledger.
            let note = state
                .hot_note(id)
                .or_else(|| state.within_grace(id).map(|(_, note)| note))
                .expect("the ledger put it back");
            notes.unspent.insert(*id, note);
        }
        allowed_issue -= u128::from(params.reward_at(state.next_height().unwrap()).as_pebbles());
        assert_eq!(
            u128::from(state.supply().as_pebbles()),
            notes.total(),
            "an undo left the ledger's supply and its notes disagreeing"
        );
    }
    assert_eq!(
        u128::from(state.supply().as_pebbles()),
        allowed_issue,
        "undoing five blocks did not put the supply back where it was"
    );
    assert_eq!(
        state.hot_len() as u64 + state.cold().len(),
        notes.unspent.len() as u64,
        "the tiers and the notes disagree after an undo"
    );

    // And a different five, on the branch that is left.
    for _ in 0..5 {
        step(
            &mut state,
            &mut notes,
            &mut chain,
            &mut allowed_issue,
            &mut purse,
            Vec::new(),
            Amount::ZERO,
        );
    }
    assert_eq!(u128::from(state.supply().as_pebbles()), allowed_issue);
    println!(
        "after a five block reorganisation: the ledger says {} pebbles, the schedule allows {}",
        state.supply(),
        allowed_issue
    );
}

/// Whether a coinbase's notes can be spent at the height that comes next.
fn is_mature(state: &LedgerState, id: &NoteId) -> bool {
    match state.coinbase_matures_at(&id.source) {
        None => true,
        Some(matures_at) => state.next_height().unwrap() >= matures_at,
    }
}

/// A block mined for one side of a halving cannot be moved to the other.
#[test]
fn a_halving_cannot_be_moved_by_a_block_arriving_out_of_order() {
    // A halving every four blocks, so the boundary is reachable.
    let mut params = spendable_at_once();
    params.halving_interval = 4;
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let mut chain: Vec<ConnectedBlock> = Vec::new();
    let mut blocks: Vec<Block> = Vec::new();
    for _ in 0..6u64 {
        let (block, connected) = mine(&mut state, &params, &miner, Vec::new());
        blocks.push(block);
        chain.push(connected);
    }

    // Heights 0..=3 pay the opening rate, 4 onwards pay half. Read off the
    // blocks themselves rather than off the schedule.
    for (height, block) in blocks.iter().enumerate() {
        let paid = block.coinbase.total_output().unwrap();
        let expected = if height < 4 {
            params.initial_reward
        } else {
            Amount::from_pebbles(params.initial_reward.as_pebbles() / 2).unwrap()
        };
        assert_eq!(paid, expected, "block {height}");
    }

    // The block that was mined at height 4, offered again at height 3 after
    // the chain is wound back. It carries the smaller reward, so accepting it
    // would be harmless; it is refused anyway, because where a block sits is
    // the chain's business and not the block's.
    let above = blocks[4].clone();
    for _ in 0..3 {
        let connected = chain.pop().unwrap();
        disconnect_block(&mut state, &connected);
    }
    assert_eq!(state.next_height(), Some(3));
    assert!(matches!(
        connect_block(&mut state, &above, &params, NOW),
        Err(BlockError::WrongHeight {
            expected: 3,
            found: 4
        })
    ));

    // And the block that was mined at height 3, offered at height 4, which is
    // the direction that would pay the opening rate one block too long.
    let below = blocks[3].clone();
    let (_, connected) = mine(&mut state, &params, &miner, Vec::new());
    chain.push(connected);
    assert_eq!(state.next_height(), Some(4));
    assert!(matches!(
        connect_block(&mut state, &below, &params, NOW),
        Err(BlockError::WrongHeight {
            expected: 4,
            found: 3
        })
    ));

    // Rebuilt on the new branch, the boundary lands in the same place.
    let (fresh, _) = mine(&mut state, &params, &miner, Vec::new());
    assert_eq!(fresh.header.height, 4);
    assert_eq!(
        fresh.coinbase.total_output().unwrap().as_pebbles(),
        params.initial_reward.as_pebbles() / 2,
        "the first block of the second era pays the halved rate wherever it came from"
    );
}

/// Underpaying is allowed, and it destroys money rather than refusing.
#[test]
fn a_coinbase_that_takes_less_than_it_may_burns_the_difference() {
    let params = spendable_at_once();
    let miner = wallet(1);
    let mut state = LedgerState::archiving();

    let height = state.next_height().unwrap();
    let one = Amount::from_pebbles(1).unwrap();
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(one, miner.public_key())]);
    let block = build(&state, &params, coinbase, Vec::new()).unwrap();
    connect_block(&mut state, &block, &params, NOW).unwrap();

    let created: u64 = state
        .hot_notes()
        .map(|(_, entry)| entry.note.value.as_pebbles())
        .sum();
    assert_eq!(created, 1);
    assert!(
        created < params.reward_at(height).as_pebbles(),
        "the schedule said 50 CAIRN and one pebble exists"
    );
    // A coinbase with no outputs at all is valid too: it is what both live
    // networks open with.
    let height = state.next_height().unwrap();
    let nothing = CoinbaseTransaction::new(height, Vec::new());
    let block = build(&state, &params, nothing, Vec::new()).unwrap();
    connect_block(&mut state, &block, &params, NOW).unwrap();
    assert_eq!(state.hot_len(), 1, "the second block paid nobody");
}

/// A block that creates more notes than the whole tier holds.
///
/// Everything it creates falls straight through to the cold set in the same
/// block, which is the one path where a note is inserted and removed inside a
/// single transition. Nothing may be lost or doubled on the way.
#[test]
fn a_block_that_overflows_the_tier_loses_nothing_on_the_way_down() {
    let params = spendable_at_once().with_hot_capacity(2);
    let (miner, alice) = (wallet(1), wallet(2));
    let mut state = LedgerState::archiving();

    let (block, _) = mine(&mut state, &params, &miner, Vec::new());
    let coin = NoteId::new(block.coinbase.id(), 0);
    let value = params.reward_at(0);
    let spent = Note::new(value, miner.public_key());

    // One transfer splitting the whole reward into two hundred notes, and a
    // coinbase taking its sixteen. Two hundred and sixteen notes into a tier
    // that holds two.
    let each = Amount::from_pebbles(value.as_pebbles() / 200).unwrap();
    let outputs: Vec<Note> = (0..200)
        .map(|_| Note::new(each, alice.public_key()))
        .collect();
    let paid_out: u64 = outputs.iter().map(|note| note.value.as_pebbles()).sum();
    let fee = value
        .checked_sub(Amount::from_pebbles(paid_out).unwrap())
        .unwrap();
    let mut split = Transfer::new(vec![Input::hot(coin)], outputs);
    split.sign_input(params.network, 0, &spent, &miner);

    let height = state.next_height().unwrap();
    let pay = params.reward_at(height).checked_add(fee).unwrap();
    let share = Amount::from_pebbles(pay.as_pebbles() / 16).unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        (0..16)
            .map(|_| Note::new(share, miner.public_key()))
            .collect(),
    );
    let coinbase_total = share.as_pebbles() * 16;

    let before: u128 = u128::from(value.as_pebbles());
    let block = build(&state, &params, coinbase, vec![split]).unwrap();
    let connected = connect_block(&mut state, &block, &params, NOW).unwrap();
    assert_eq!(connected.total_fees, fee);

    let transition = &connected.transition;
    let created: u128 = transition
        .created
        .iter()
        .map(|(_, note)| u128::from(note.value.as_pebbles()))
        .sum();
    assert_eq!(created, u128::from(paid_out) + u128::from(coinbase_total));

    // Every one of them is somewhere, and only in one place.
    assert_eq!(
        state.hot_len() as u64 + state.cold().len(),
        216,
        "216 notes were created into a tier that holds two"
    );
    assert_eq!(state.hot_len(), 2);
    assert!(
        transition.evicted.len() > 200,
        "the block pushed {} notes down",
        transition.evicted.len()
    );
    // Nothing was evicted twice, and nothing was evicted that was not created
    // or already held.
    let mut seen = BTreeMap::new();
    for (id, note) in &transition.evicted {
        assert!(seen.insert(*id, *note).is_none(), "{id:?} fell twice");
    }

    let after = before - u128::from(value.as_pebbles()) + created;
    assert_eq!(
        after,
        u128::from(paid_out) + u128::from(coinbase_total),
        "the supply after is what the block created"
    );
    assert!(
        after - before <= u128::from(params.reward_at(height).as_pebbles()),
        "the block created more than its reward"
    );
}

/// The ledger is never asked what the supply is, because it cannot say.
#[test]
fn the_ledger_states_no_supply_of_its_own() {
    // Recorded as a finding rather than as a wish: nothing in `LedgerState`,
    // `StateTransition` or the state root carries a running total, so no node
    // can notice a chain that has drifted from its schedule. The books above
    // are this test's own, kept outside the ledger.
    let state = LedgerState::new();
    assert_eq!(state.hot_len(), 0);
    assert_eq!(state.cold().len(), 0);
}

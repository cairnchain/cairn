//! What a block's producer is free to do, as opposed to what it is expected
//! to do.
//!
//! Every rule in this chain is enforced by validators and followed by miners
//! only where following pays. These tests are about the places the two come
//! apart: the coinbase a miner writes for itself, the transfers it carries for
//! free because the fee comes back to it, and the one shared resource a fee
//! was supposed to price.
//!
//! Nothing here is fixed by the tests. They record what the rules currently
//! allow so that a change to any of it is visible.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::next_difficulty;
use cairn_ledger::state::{GRACE_BLOCKS, GRACE_NOTES};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer, MAX_COINBASE_EXTRA};
use cairn_ledger::validation::{
    assemble_block, check_transfer, connect_block, mine_block, BlockError, ConsensusParams,
    TransferError,
};
use cairn_ledger::{Block, HeaderSummary, LedgerState};
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

use std::collections::{BTreeMap, BTreeSet};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 20;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// A chain whose blocks a test writes itself, so it can write ones no honest
/// miner would.
struct Bench {
    params: ConsensusParams,
    ledger: LedgerState,
    clock: u64,
}

impl Bench {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            ledger: LedgerState::new(),
            clock: 1_000_000,
        }
    }

    fn height(&self) -> u64 {
        self.ledger.next_height().unwrap()
    }

    /// Mines and applies a block carrying exactly what it is handed.
    fn mine(&mut self, coinbase: CoinbaseTransaction, transfers: Vec<Transfer>) -> Block {
        self.clock += 60;
        let block = assemble_block(
            &self.ledger,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .expect("the body should assemble");
        let block = mine_block(block, ATTEMPTS).expect("difficulty one takes the first nonce");
        connect_block(&mut self.ledger, &block, &self.params, NOW).expect("it should apply");
        block
    }

    /// The plainest block there is: the whole reward to one note, nothing else.
    fn plain(&mut self, to: &SecretKey) -> (NoteId, Note) {
        let height = self.height();
        let reward = self.params.reward_at(height);
        let note = Note::new(reward, to.public_key());
        let block = self.mine(CoinbaseTransaction::new(height, vec![note]), Vec::new());
        (NoteId::new(block.coinbase.id(), 0), note)
    }

    /// A block whose coinbase spreads the reward over `count` notes, which is
    /// how a test gets several spendable notes at once.
    fn spread(&mut self, to: &SecretKey, count: usize) -> Vec<(NoteId, Note)> {
        let height = self.height();
        let reward = self.params.reward_at(height).as_pebbles();
        let each = reward / count as u64;
        let first = reward - each * (count as u64 - 1);
        let outputs: Vec<Note> = (0..count)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(pebbles(value), to.public_key())
            })
            .collect();
        let block = self.mine(
            CoinbaseTransaction::new(height, outputs.clone()),
            Vec::new(),
        );
        outputs
            .into_iter()
            .enumerate()
            .map(|(index, note)| (NoteId::new(block.coinbase.id(), index as u32), note))
            .collect()
    }
}

/// Spends one note into `count` notes of the least value there is, leaving no
/// fee at all. The shape a miner reaches for when it wants places in the hot
/// set and is not paying for them.
fn stuffing(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    count: usize,
) -> Transfer {
    let value = note.value.as_pebbles();
    let each = 1u64;
    let first = value - each * (count as u64 - 1);
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

/// Whether a note can still be spent with nothing but its identifier.
fn spendable_without_a_proof(state: &LedgerState, params: &ConsensusParams, id: NoteId) -> bool {
    let transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(pebbles(1), wallet(0xEE).public_key())],
    );
    !matches!(
        check_transfer(&transfer, state, &BTreeSet::new(), &BTreeMap::new(), params,),
        Err(TransferError::MissingProof { .. })
    )
}

// ---------------------------------------------------------------------------
// 1. The fee floor is not a rule, and a miner never pays it.
// ---------------------------------------------------------------------------

/// A miner pays no fee for the transfers it puts in its own block.
///
/// The floor in `cairn-chain` is the price of being relayed and pooled by a
/// stranger. A miner assembling its own block reaches none of that code: it
/// hands `assemble_block` whatever it likes, and the only fee rule consensus
/// has is that the coinbase may not claim more than the reward plus the fees.
/// A transfer paying nothing satisfies it.
///
/// This is not a defect on its own. It is the reason every argument in this
/// file that starts "it would cost the attacker N pebbles" has to be read
/// twice: if the attacker is the miner, N is zero.
#[test]
fn a_miner_carries_its_own_transfers_for_nothing() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(0);
    let miner = wallet(1);
    let mut bench = Bench::new(params);
    let (id, note) = bench.plain(&miner);

    // Every pebble that went in comes back out: the fee is exactly zero, which
    // the pool would refuse and the block does not.
    let transfer = stuffing(&params, id, note, &miner, params.max_outputs_per_transfer);
    let paid = transfer.total_output().unwrap();
    assert_eq!(paid, note.value, "the transfer pays no fee at all");

    let height = bench.height();
    let reward = params.reward_at(height);
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(reward, miner.public_key())]);
    bench.mine(coinbase, vec![transfer]);

    println!(
        "\n  a zero fee transfer creating {} notes is a valid block body",
        params.max_outputs_per_transfer
    );
    println!("  the fee floor is cairn-chain policy and consensus has no floor at all\n");
}

// ---------------------------------------------------------------------------
// 2. The eviction cap prices the rate. Nobody prices the total.
// ---------------------------------------------------------------------------

/// A miner empties the hot set at the cap, block after block, for nothing.
///
/// The cap exists because "a miner includes its own transfers for free", which
/// the comment on `max_evictions_per_block` says out loud. What the cap buys
/// is time: it makes emptying the tier take `hot_capacity / cap` blocks. It
/// does not make it cost anything, and the arithmetic at the end of this test
/// is what those blocks come to on the live rules.
#[test]
fn emptying_the_hot_set_costs_a_miner_nothing_but_time() {
    // Small enough to run, shaped like the real thing: a tier, a cap that is a
    // fraction of it, and a coinbase allowance held back.
    let params = ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_hot_capacity(64)
        .with_max_evictions(8);
    let miner = wallet(1);
    let victim = wallet(2);

    let mut bench = Bench::new(params);
    // The victim's money, oldest in the tier, so it is what falls first.
    let victims = bench.spread(&victim, 16);
    // And enough of the miner's own to fill the rest and to spend from.
    let mut purse = Vec::new();
    for _ in 0..3 {
        purse.extend(bench.spread(&miner, 16));
    }
    assert_eq!(bench.ledger.hot_len(), 64, "the tier starts full");
    for (id, _) in &victims {
        assert!(bench.ledger.hot_note(id).is_some(), "the victim is hot");
    }

    // Now the attack, which is one ordinary looking block after another. Each
    // carries a single transfer of the miner's own, paying no fee, spending
    // one note and creating eight. Seven net places plus one for the coinbase
    // is the cap exactly.
    let mut blocks = 0usize;
    let mut spent_in_fees = 0u64;
    while victims
        .iter()
        .any(|(id, _)| bench.ledger.hot_note(id).is_some())
    {
        let (id, note) = purse.pop().expect("the miner has notes to spend");
        let transfer = stuffing(&params, id, note, &miner, 8);
        spent_in_fees += note.value.as_pebbles() - transfer.total_output().unwrap().as_pebbles();

        let height = bench.height();
        let reward = params.reward_at(height);
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(reward, miner.public_key())]);
        bench.mine(coinbase, vec![transfer]);
        blocks += 1;
        assert!(blocks < 100, "this should take a handful of blocks");
    }

    assert_eq!(spent_in_fees, 0, "the miner paid no fee to do any of this");
    println!("\n  a tier of {} notes, a cap of {} a block", 64, 8);
    println!("  every note the victim held was pushed to the cold set in {blocks} blocks,");
    println!("  and the miner paid {spent_in_fees} pebbles for it\n");

    // What the same thing comes to under the rules a public network runs.
    let live = ConsensusParams::testnet();
    let needed = live.hot_capacity.div_ceil(live.max_evictions_per_block);
    println!(
        "  on the live rules: {} notes in the tier, {} evictions a block,",
        live.hot_capacity, live.max_evictions_per_block
    );
    println!(
        "  so the whole tier goes cold in {needed} blocks, about {:.1} hours",
        needed as f64 * live.target_block_time as f64 / 3_600.0
    );
    assert_eq!(needed, 128);

    // And the honest comparison, which is what decides whether any of this
    // matters. A chain of full blocks of ordinary payments nets about six
    // hundred and eighty six new notes a block on its own, so the tier turns
    // over completely in about that many blocks with nobody attacking
    // anything. The cap is what keeps the two figures within striking
    // distance of each other, and it does: the attack buys an acceleration of
    // about half again, not an order of magnitude.
    let honest_per_block = live.max_block_bytes / 191;
    let honest_blocks = live.hot_capacity.div_ceil(honest_per_block);
    println!(
        "\n  against that: a full chain of ordinary payments nets {honest_per_block} notes a\n  \
         block on its own and empties the tier in {honest_blocks} blocks, {:.1} hours.\n  \
         So the cap holds the attack to {:.2} times what a busy honest chain\n  \
         already does. What the miner saves is the {:.2} CAIRN a block of fees\n  \
         that traffic would have paid, not the eviction itself\n",
        honest_blocks as f64 * live.target_block_time as f64 / 3_600.0,
        honest_blocks as f64 / needed as f64,
        honest_per_block as f64 * 7_030.0 / 100_000_000.0
    );
    assert!(
        honest_blocks < needed * 2,
        "{honest_blocks} against {needed}"
    );
}

/// The advertised grace of sixty four blocks is not what a victim gets.
///
/// A fallen note stays spendable with no proof for `GRACE_BLOCKS` blocks or
/// `GRACE_NOTES` notes, whichever runs out first. Under ordinary traffic the
/// block bound is the one that bites and sixty four blocks is the honest
/// figure. Under a block evicting at the cap, the note bound bites first, and
/// the number it gives is the one that matters to anybody trying to notice
/// their money has moved tier and do something about it.
#[test]
fn the_grace_a_victim_gets_is_eight_blocks_not_sixty_four() {
    let live = ConsensusParams::testnet();
    let under_attack = GRACE_NOTES / live.max_evictions_per_block;
    println!("\n  grace window: {GRACE_BLOCKS} blocks or {GRACE_NOTES} notes, whichever first");
    println!(
        "  at the eviction cap of {} a block that is {under_attack} blocks,",
        live.max_evictions_per_block
    );
    println!(
        "  which is {} minutes of warning, not {}\n",
        under_attack as u64 * live.target_block_time / 60,
        GRACE_BLOCKS as u64 * live.target_block_time / 60
    );
    assert_eq!(under_attack, 8);
    assert!(under_attack < GRACE_BLOCKS);
}

/// And once the grace is gone the note takes a proof nobody on an ordinary
/// node can make.
#[test]
fn a_note_past_its_grace_cannot_be_spent_without_a_proof() {
    let params = ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_hot_capacity(16)
        .with_max_evictions(64);
    let miner = wallet(1);
    let victim = wallet(2);
    let mut bench = Bench::new(params);

    let victims = bench.spread(&victim, 16);
    let target = victims[0].0;
    assert!(bench.ledger.hot_note(&target).is_some());

    // Push the tier over, which takes the victim's notes out of it.
    for _ in 0..2 {
        bench.spread(&miner, 16);
    }
    assert!(bench.ledger.hot_note(&target).is_none(), "it fell");
    assert!(
        spendable_without_a_proof(&bench.ledger, &params, target),
        "it is still inside the grace window"
    );

    // And now let the window age past it.
    for _ in 0..=GRACE_BLOCKS {
        bench.plain(&miner);
    }
    assert!(
        !spendable_without_a_proof(&bench.ledger, &params, target),
        "past the grace it takes a proof"
    );
    println!(
        "\n  {GRACE_BLOCKS} blocks after it fell, spending the note takes a cold proof,\n  \
         which only a node keeping the cold set can build\n"
    );
}

// ---------------------------------------------------------------------------
// 3. The coinbase, and every degree of freedom in it.
// ---------------------------------------------------------------------------

/// A coinbase that pays nobody is a valid block.
///
/// It burns the reward and the fees together. The question is whether burning
/// can ever be worth more than taking, and the answer is arithmetic: a burn of
/// R raises the value of every other pebble in proportion, so a holder of a
/// fraction f of the supply gains f*R and loses R. It pays only at f > 1.
#[test]
fn a_coinbase_that_pays_nobody_is_valid_and_simply_burns_the_block() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(0);
    let miner = wallet(1);
    let mut bench = Bench::new(params);
    bench.plain(&miner);

    let before = bench.ledger.supply();
    let height = bench.height();
    bench.mine(CoinbaseTransaction::new(height, Vec::new()), Vec::new());
    assert_eq!(
        bench.ledger.supply(),
        before,
        "an empty coinbase issued nothing"
    );

    // And half a reward is equally legal, burning the other half.
    let height = bench.height();
    let half = pebbles(params.reward_at(height).as_pebbles() / 2);
    bench.mine(
        CoinbaseTransaction::new(height, vec![Note::new(half, miner.public_key())]),
        Vec::new(),
    );
    assert_eq!(
        bench.ledger.supply().as_pebbles(),
        before.as_pebbles() + half.as_pebbles()
    );
    println!("\n  underpaying is legal at any fraction and the difference is destroyed\n");
}

/// The coinbase takes places in the hot set and is charged for none of them.
///
/// Sixteen notes a block, outside the weight that prices every other note, and
/// outside the fee floor because a miner does not pay itself. It is the one
/// way to consume the scarce resource of this design with no transfer at all.
/// Sixteen a block is slower than the eviction cap and it needs no funds, no
/// signatures and no transfer bytes.
#[test]
fn the_coinbase_takes_hot_places_and_pays_for_none_of_them() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(0);
    let miner = wallet(1);
    let mut bench = Bench::new(params);

    let before = bench.ledger.hot_len();
    bench.spread(&miner, params.max_coinbase_outputs);
    let added = bench.ledger.hot_len() - before;
    assert_eq!(added, params.max_coinbase_outputs);

    let live = ConsensusParams::testnet();
    let blocks = live.hot_capacity / live.max_coinbase_outputs;
    println!(
        "\n  a coinbase takes {} hot places a block and pays nothing for them",
        params.max_coinbase_outputs
    );
    println!(
        "  a miner holding every block turns the whole tier over in {blocks} blocks\n  \
         ({:.1} days) with no transfer at all\n",
        blocks as f64 * live.target_block_time as f64 / 86_400.0
    );
    assert_eq!(blocks, 8_192);
}

/// The extra field is committed to and is bounded, and it is the only place a
/// miner can write bytes that are not money.
#[test]
fn the_coinbase_extra_is_bounded_and_committed_to() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(0);
    let miner = wallet(1);
    let mut bench = Bench::new(params);
    bench.plain(&miner);

    let height = bench.height();
    let reward = params.reward_at(height);
    let note = Note::new(reward, miner.public_key());

    let plain = CoinbaseTransaction::new(height, vec![note]);
    let marked =
        CoinbaseTransaction::with_extra(height, vec![note], vec![0xAB; MAX_COINBASE_EXTRA]);
    assert_ne!(
        plain.id(),
        marked.id(),
        "the extra changes the coinbase identifier, so it is real search space"
    );

    // One byte past the limit and the block is refused.
    let over =
        CoinbaseTransaction::with_extra(height, vec![note], vec![0xAB; MAX_COINBASE_EXTRA + 1]);
    let built = assemble_block(
        &bench.ledger,
        over,
        Vec::new(),
        &params,
        bench.clock + 60,
        0,
    );
    assert!(matches!(
        built,
        Err(BlockError::CoinbaseExtraTooLarge { .. })
    ));

    bench.mine(marked, Vec::new());
    println!(
        "\n  {MAX_COINBASE_EXTRA} bytes a block of anything at all, plus {} owner fields\n  \
         of thirty two bytes each in the outputs: {} bytes a block of\n  \
         permanent state a miner writes and nobody prices\n",
        params.max_coinbase_outputs,
        MAX_COINBASE_EXTRA + params.max_coinbase_outputs * 32
    );
}

// ---------------------------------------------------------------------------
// 4. assemble_block will build a block its own node refuses.
// ---------------------------------------------------------------------------

/// `assemble_block` checks every rule about a block except how big it is.
///
/// The byte limit is checked in `connect_block` and nowhere else, so a miner
/// that hands `assemble_block` more than fits gets a block back, spends its
/// work on it, and is refused by every node including itself. It costs nobody
/// but the miner, and `cairn-chain`'s `selection` keeps the node's own miner
/// away from it, but the asymmetry is worth writing down: the assembler is not
/// a check on the assembler.
#[test]
fn assemble_block_hands_back_a_block_every_node_refuses() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(0);
    let miner = wallet(1);
    let mut bench = Bench::new(params);

    // Enough notes to spend into a block past the byte limit.
    let mut purse = Vec::new();
    while purse.len() < 64 {
        purse.extend(bench.spread(&miner, 16));
    }

    let mut transfers = Vec::new();
    let mut bytes = 0usize;
    while bytes <= params.max_block_bytes {
        let (id, note) = purse.pop().unwrap();
        let transfer = stuffing(&params, id, note, &miner, params.max_outputs_per_transfer);
        bytes += transfer.encode().len();
        transfers.push(transfer);
    }

    let height = bench.height();
    let reward = params.reward_at(height);
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(reward, miner.public_key())]);
    let block = assemble_block(
        &bench.ledger,
        coinbase,
        transfers,
        &params,
        bench.clock + 60,
        0,
    )
    .expect("assemble_block does not weigh the block it builds");
    let size = block.encode().len();
    assert!(size > params.max_block_bytes);

    let block = mine_block(block, ATTEMPTS).unwrap();
    let refused = connect_block(&mut bench.ledger, &block, &params, NOW);
    assert!(matches!(refused, Err(BlockError::BlockTooLarge { .. })));
    println!(
        "\n  assemble_block returned a {size} byte block against a {} byte limit,\n  \
         and connect_block refused it. The check lives on one side only\n",
        params.max_block_bytes
    );
}

// ---------------------------------------------------------------------------
// 5. The repaired retarget, read from the other direction.
// ---------------------------------------------------------------------------

/// Post dating the tip is a gift to whoever mines next, and the giver pays.
///
/// The repair made a timestamp thrown forward give itself back through the
/// blocks that follow. The question left over is the opposite one: does the
/// repair leave a miner better off for writing a late timestamp on the block
/// it has just found? It buys one block at a discount, and the discount goes
/// to whoever finds the next block, which is the post dater only in proportion
/// to its share. Two blocks later the window has taken it back.
#[test]
fn post_dating_the_tip_discounts_one_block_and_is_taken_back() {
    const TARGET: u64 = 60;
    const CEILING: u64 = 6 * TARGET;
    let start = 1_000_000u64;

    let honest: Vec<HeaderSummary> = (0..=90)
        .map(|index| HeaderSummary {
            height: index,
            timestamp: 1_000_000 + index * TARGET,
            difficulty: start,
        })
        .collect();
    let steady = next_difficulty(&honest, TARGET);

    // The tip, and only the tip, sits a full ceiling later than it should.
    let mut lied = honest.clone();
    lied[90].timestamp += CEILING - TARGET;
    let discounted = next_difficulty(&lied, TARGET);
    assert!(
        discounted < steady,
        "a late tip should read as a slow block: {discounted} against {steady}"
    );

    // And the honest block after it, dated by the wall clock, gives it back.
    let mut after_honest = honest.clone();
    after_honest.push(HeaderSummary {
        height: 91,
        timestamp: 1_000_000 + 91 * TARGET,
        difficulty: steady,
    });
    let mut after_lie = lied.clone();
    after_lie.push(HeaderSummary {
        height: 91,
        timestamp: 1_000_000 + 91 * TARGET,
        difficulty: discounted,
    });
    let recovered = next_difficulty(&after_lie, TARGET);
    let unlied = next_difficulty(&after_honest, TARGET);

    let discount = 100.0 * (1.0 - discounted as f64 / steady as f64);
    println!(
        "\n  one ceiling on the tip drops the next block's difficulty by {discount:.1} per cent"
    );
    println!("  and the block after that comes back to {recovered} against {unlied} honest");
    assert!(
        discount > 5.0 && discount < 15.0,
        "the one block discount is {discount:.3}"
    );
    // The give back is what stops it compounding: the window does not stay low.
    assert!(
        recovered as f64 >= unlied as f64 * 0.999,
        "the window did not take the lie back: {recovered} against {unlied}"
    );

    // And now the whole account. The pair of blocks, the lie and the honest
    // one that gives it back, sits at weights k and k+1 for every k as the
    // window slides, and costs the same three hundred weighted seconds at
    // every one of them. So the one block discount is followed by eighty nine
    // blocks each priced a little above honest, and the sum decides whether
    // the strategy pays.
    let mut gained = 1.0 - discounted as f64 / steady as f64;
    let mut window = lied.clone();
    let mut honest_window = honest.clone();
    let mut carried = discounted;
    let mut carried_honest = steady;
    for step in 1..90u64 {
        let stamp = 1_000_000 + (90 + step) * TARGET;
        window.push(HeaderSummary {
            height: 90 + step,
            timestamp: stamp,
            difficulty: carried,
        });
        honest_window.push(HeaderSummary {
            height: 90 + step,
            timestamp: stamp,
            difficulty: carried_honest,
        });
        carried = next_difficulty(&window, TARGET);
        carried_honest = next_difficulty(&honest_window, TARGET);
        gained += 1.0 - carried as f64 / carried_honest as f64;
    }

    println!(
        "  over the ninety blocks the window is wide, the lie is worth\n  \
         {gained:+.4} blocks of work against never having told it"
    );
    // Measured rather than assumed. The give back is real but the `average`
    // term in the retarget damps it: the discounted block drags the window's
    // mean difficulty down with it, so the correction lands at about a tenth
    // of the arithmetic on the weighted solve times alone. Ninety blocks give
    // back roughly a tenth of what one late timestamp took.
    assert!(
        gained > 0.0 && gained < 0.2,
        "the one shot gain measured {gained:+.4}"
    );
    println!(
        "  and the correction is damped: the window's mean difficulty falls with\n  \
         the discounted block, so ninety blocks give back about a tenth of it.\n  \
         Sustained, the feedback loop removes it: `the_saw_no_longer_pays_for_\n  \
         itself` measures the block time at the target and the difficulty at or\n  \
         above where it started, at every share up to 45 per cent. The discount\n  \
         also goes to whoever mines next, which is the post dater only in\n  \
         proportion to its share. cairn-node's miner never post dates\n"
    );
}

/// A miner started before the network opens mines blocks nobody will ever
/// take, and neither the assembler nor the miner says so.
///
/// `build` was taught to notice one way its own block would be refused, which
/// is a median that has outrun the drift. `opens_at` is the other, and it is
/// the one that bites at the only moment it can: the opening. Neither `build`
/// nor `assemble_block` reads it, so a node whose clock is behind, or that was
/// simply started early, assembles a valid looking block, spends its work on
/// it, submits it, is refused, and starts again. Nothing is logged, because
/// `run` drops the error from `submit_block` on the floor.
#[test]
fn nothing_stops_a_miner_dating_a_block_before_the_network_opened() {
    let mut params = ConsensusParams::testnet().with_coinbase_maturity(0);
    params.opens_at = 2_000_000;

    let miner = wallet(1);
    let mut ledger = LedgerState::new();
    let height = ledger.next_height().unwrap();
    let reward = params.reward_at(height);
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(reward, miner.public_key())]);

    // An hour before the opening, which is what a node started early has on
    // its clock.
    let early = params.opens_at - 3_600;
    let block = assemble_block(&ledger, coinbase, Vec::new(), &params, early, 0)
        .expect("the assembler does not read opens_at");
    let block = mine_block(block, ATTEMPTS).unwrap();
    let refused = connect_block(&mut ledger, &block, &params, NOW);
    assert!(
        matches!(refused, Err(BlockError::BeforeTheNetworkOpened { .. })),
        "got {refused:?}"
    );
    println!(
        "\n  a block dated an hour before the network opened assembles, mines, and\n  \
         is refused by every node including the one that made it. The guard\n  \
         added to `build` covers the median against the drift and not this\n"
    );
}

// ---------------------------------------------------------------------------
// 6. Which notes fall is a choice a miner can make for free.
// ---------------------------------------------------------------------------

/// A miner keeps its own money hot indefinitely while everyone else's falls.
///
/// The eviction order is by the height a note was made at, oldest first, and
/// spending a note makes a new one at the current height. A miner pays no fee
/// on its own transfers, so refreshing its whole holding costs it nothing but
/// block room, and it can do it every block. The comment on the eviction cap
/// says the pusher "chooses who by choosing nothing, since it is always the
/// oldest that falls". That is true of the notes it pushes out and not of its
/// own: it chooses itself out of the queue every time.
#[test]
fn a_miner_holds_its_own_money_at_the_front_of_the_queue_for_nothing() {
    let params = ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_hot_capacity(32)
        .with_max_evictions(1_024);
    let miner = wallet(1);
    let victim = wallet(2);
    let mut bench = Bench::new(params);

    let victims = bench.spread(&victim, 16);
    let mut mine = bench.spread(&miner, 16);
    assert_eq!(bench.ledger.hot_len(), 32, "the tier is full");

    // Every block, the miner spends all sixteen of its notes back to itself.
    // No new places are taken by that, so the only thing pushing anybody out
    // is the one note the coinbase pays.
    let mut fees = 0u64;
    for _ in 0..16 {
        let mut inputs = Vec::new();
        let mut value = 0u64;
        for (id, note) in &mine {
            inputs.push(Input::hot(*id));
            value += note.value.as_pebbles();
        }
        let each = value / 16;
        let first = value - each * 15;
        let outputs: Vec<Note> = (0..16)
            .map(|index| {
                let amount = if index == 0 { first } else { each };
                Note::new(pebbles(amount), miner.public_key())
            })
            .collect();
        let mut transfer = Transfer::new(inputs, outputs.clone());
        for (index, (_, note)) in mine.iter().enumerate() {
            transfer.sign_input(params.network, index as u32, note, &miner);
        }
        fees += value - transfer.total_output().unwrap().as_pebbles();

        let height = bench.height();
        let reward = params.reward_at(height);
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(reward, miner.public_key())]);
        bench.mine(coinbase, vec![transfer.clone()]);

        let id = transfer.id();
        mine = outputs
            .into_iter()
            .enumerate()
            .map(|(index, note)| (NoteId::new(id, index as u32), note))
            .collect();
    }

    assert_eq!(fees, 0, "the miner paid nothing to keep its place");
    let victim_hot = victims
        .iter()
        .filter(|(id, _)| bench.ledger.hot_note(id).is_some())
        .count();
    let miner_hot = mine
        .iter()
        .filter(|(id, _)| bench.ledger.hot_note(id).is_some())
        .count();
    assert_eq!(victim_hot, 0, "the victim's notes were all pushed out");
    assert_eq!(miner_hot, 16, "the miner's money never left the tier");
    println!(
        "\n  after sixteen blocks: {victim_hot} of the victim's sixteen notes are still\n  \
         hot, and {miner_hot} of the miner's. The miner paid {fees} pebbles\n"
    );
}

// ---------------------------------------------------------------------------
// 7. A block is not a sequence: nothing in it can spend what it made.
// ---------------------------------------------------------------------------

/// No transfer can spend a note another transfer in the same block created.
///
/// Every input is resolved against the state as it stood before the block, so
/// a chain of two spends needs two blocks. It is a deliberate rule and a
/// defensible one, since it makes a transfer's validity independent of where
/// it sits in the block. What it costs is child pays for parent: a payment
/// stuck at too low a rate cannot be rescued by whoever is waiting for it,
/// because the rescue would have to spend a note that is not there yet. The
/// only route is replacement, which needs the original signer and costs
/// everything it displaces plus the floor again.
#[test]
fn nothing_in_a_block_can_spend_what_the_block_itself_created() {
    let params = ConsensusParams::testnet().with_coinbase_maturity(0);
    let miner = wallet(1);
    let heir = wallet(3);
    let mut bench = Bench::new(params);
    let (id, note) = bench.plain(&miner);

    let mut first = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(note.value, miner.public_key())],
    );
    first.sign_input(params.network, 0, &note, &miner);

    let made = NoteId::new(first.id(), 0);
    let child_note = Note::new(note.value, miner.public_key());
    let mut second = Transfer::new(
        vec![Input::hot(made)],
        vec![Note::new(note.value, heir.public_key())],
    );
    second.sign_input(params.network, 0, &child_note, &miner);

    let height = bench.height();
    let reward = params.reward_at(height);
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(reward, miner.public_key())]);
    let built = assemble_block(
        &bench.ledger,
        coinbase,
        vec![first, second],
        &params,
        bench.clock + 60,
        0,
    );
    assert!(
        matches!(
            built,
            Err(BlockError::InvalidTransfer {
                index: 1,
                source: TransferError::MissingProof { .. }
            })
        ),
        "the child should be refused, got {built:?}"
    );
    println!(
        "\n  a block carrying a spend of its own output is refused, and the reason\n  \
         given is that the note takes a proof. There is no child pays for parent\n  \
         on this chain, so a stuck payment can only be replaced by its signer\n"
    );
}

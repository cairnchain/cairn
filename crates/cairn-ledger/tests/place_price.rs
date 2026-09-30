//! What a place in the hot set costs, and who pays it.
//!
//! Every note a transfer adds to a full tier pushes the oldest untouched one
//! out, and its owner then pays for a proof to spend it. The fee was the only
//! price on that, and a fee is paid to the block's miner, so a miner filling
//! its own blocks with outputs paid itself and flushed everybody's notes for
//! nothing. The price is now a rule: each place burns `place_price`, the fee
//! must cover the burn, and the coinbase cannot claim the burn back.
//!
//! The burn is a fee paid once, by whoever takes a place, when the transfer is
//! made. Nothing here charges a note for staying where it is.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::collections::{BTreeMap, BTreeSet};

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, check_transfer, connect_block, evaluate_block_body, BlockError,
    ConsensusParams, TransferError,
};
use cairn_ledger::{Block, LedgerState};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const TIER: usize = 64;
const PRICE: u64 = 6_000;

/// A small tier, a small cap and the price, with rewards spendable at once:
/// none of these tests is about the wait a reward normally takes.
fn rules() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(TIER)
        .with_max_evictions(8)
        .with_coinbase_maturity(0)
        .with_place_price(pebbles(PRICE))
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// A chain whose blocks a test writes itself, so it can write the ones a
/// miner would write for itself.
struct Bench {
    params: ConsensusParams,
    ledger: LedgerState,
    clock: u64,
}

impl Bench {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            ledger: LedgerState::archiving(),
            clock: 1_000_000,
        }
    }

    fn height(&self) -> u64 {
        self.ledger.next_height().unwrap()
    }

    fn assemble(
        &mut self,
        coinbase: CoinbaseTransaction,
        transfers: Vec<Transfer>,
    ) -> Result<Block, BlockError> {
        self.clock += 60;
        assemble_block(
            &self.ledger,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
    }

    fn mine(&mut self, coinbase: CoinbaseTransaction, transfers: Vec<Transfer>) -> Block {
        let block = self
            .assemble(coinbase, transfers)
            .expect("the body should assemble");
        connect_block(&mut self.ledger, &block, &self.params, NOW).expect("it should apply");
        block
    }

    /// A block whose coinbase spreads the reward over `count` notes.
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

    /// Fills the tier with notes paid to `to`, sixteen a block.
    fn fill(&mut self, to: &SecretKey) -> Vec<(NoteId, Note)> {
        let mut notes = Vec::new();
        while self.ledger.hot_len() < self.params.hot_capacity {
            notes.extend(self.spread(to, self.params.max_coinbase_outputs));
        }
        notes
    }

    /// The whole reward at this height, to one note.
    fn plain_coinbase(&self, to: &SecretKey, extra: u64) -> CoinbaseTransaction {
        let height = self.height();
        let claimed = self.params.reward_at(height).as_pebbles() + extra;
        CoinbaseTransaction::new(height, vec![Note::new(pebbles(claimed), to.public_key())])
    }
}

/// Spends `inputs` into `count` outputs, leaving exactly `fee` behind.
fn spend(
    params: &ConsensusParams,
    inputs: &[(NoteId, Note)],
    witnesses: Vec<Input>,
    owner: &SecretKey,
    count: usize,
    fee: u64,
) -> Transfer {
    let total: u64 = inputs.iter().map(|(_, note)| note.value.as_pebbles()).sum();
    let shared = total - fee;
    let each = shared / count as u64;
    let first = shared - each * (count as u64 - 1);
    let outputs: Vec<Note> = (0..count)
        .map(|index| {
            let value = if index == 0 { first } else { each };
            Note::new(pebbles(value), owner.public_key())
        })
        .collect();
    let mut transfer = Transfer::new(witnesses, outputs);
    for (index, (_, note)) in inputs.iter().enumerate() {
        transfer.sign_input(params.network, index as u32, note, owner);
    }
    transfer
}

/// The same, out of the hot set.
fn spend_hot(
    params: &ConsensusParams,
    inputs: &[(NoteId, Note)],
    owner: &SecretKey,
    count: usize,
    fee: u64,
) -> Transfer {
    let witnesses = inputs.iter().map(|(id, _)| Input::hot(*id)).collect();
    spend(params, inputs, witnesses, owner, count, fee)
}

fn check(bench: &Bench, transfer: &Transfer) -> Result<Amount, TransferError> {
    check_transfer(
        transfer,
        &bench.ledger,
        &BTreeSet::new(),
        &BTreeMap::new(),
        &bench.params,
    )
    .map(|outcome| outcome.fee)
}

/// A miner filling its own block with outputs pays for every place it takes.
///
/// The fee was the only price on a place, and the coinbase may claim every
/// fee in its block, so whatever a miner paid in its own block came back to
/// it: two transfers giving up nothing, each spending one note into four, sat
/// in a valid block beside a coinbase claiming the whole reward, and pushed
/// seven notes out of a full tier. Nothing asked a transfer to pay for the
/// places it took, so a miner flushed everybody's notes for free.
#[test]
fn a_miner_stuffing_its_own_block_pays_for_every_place() {
    let params = rules();
    let miner = wallet(1);
    let mut bench = Bench::new(params);
    let notes = bench.fill(&miner);
    assert_eq!(bench.ledger.hot_len(), TIER, "the tier is full");

    let stuffed: Vec<Transfer> = notes[..2]
        .iter()
        .map(|spent| spend_hot(&params, &[*spent], &miner, 4, 0))
        .collect();
    let coinbase = bench.plain_coinbase(&miner, 0);

    let judged = evaluate_block_body(&bench.ledger, &coinbase, &stuffed, &params);
    let burn = pebbles(3 * PRICE);
    assert!(
        matches!(
            judged,
            Err(BlockError::InvalidTransfer {
                index: 0,
                source: TransferError::PlacesUnpaid { places: 3, burn: named, fee },
            }) if named == burn && fee == Amount::ZERO
        ),
        "a miner's own transfers took three places each and paid for none of \
         them, and the block was {}",
        judged.map_or_else(|error| format!("refused as {error}"), |_| "valid".into())
    );
}

/// A place costs exactly the price, the fee pays it, and the coinbase cannot
/// take it back, so it leaves the supply.
///
/// Before the price there was nothing here to hold: a transfer's fee had no
/// floor in the rules, the coinbase could claim every pebble of it, and the
/// supply moved by exactly what the coinbase created.
#[test]
fn a_place_is_paid_once_and_destroyed() {
    let params = rules();
    let (miner, owner) = (wallet(1), wallet(2));
    let mut bench = Bench::new(params);
    let notes = bench.spread(&owner, 4);
    let spent = notes[0];

    // One hot input and three outputs: it gives one place back and takes
    // three, so it takes two.
    let exact = spend_hot(&params, &[spent], &owner, 3, 2 * PRICE);
    assert_eq!(
        check(&bench, &exact),
        Ok(pebbles(2 * PRICE)),
        "a transfer paying exactly the burn of its two places was refused"
    );
    let short = spend_hot(&params, &[spent], &owner, 3, 2 * PRICE - 1);
    assert_eq!(
        check(&bench, &short),
        Err(TransferError::PlacesUnpaid {
            places: 2,
            burn: pebbles(2 * PRICE),
            fee: pebbles(2 * PRICE - 1),
        }),
        "a transfer a pebble short of its burn was taken"
    );

    // The same spend with something over the burn, which the miner may keep.
    let tip = 1_234;
    let paying = spend_hot(&params, &[spent], &owner, 3, 2 * PRICE + tip);
    let before = bench.ledger.supply();
    let reward = params.reward_at(bench.height());

    let greedy = bench.plain_coinbase(&miner, tip + 1);
    let refused = bench.assemble(greedy, vec![paying.clone()]);
    assert!(
        matches!(
            refused,
            Err(BlockError::CoinbaseOverpay { allowed, claimed })
                if allowed.as_pebbles() == reward.as_pebbles() + tip
                    && claimed.as_pebbles() == reward.as_pebbles() + tip + 1
        ),
        "a coinbase claimed a pebble of the burn back and the block was {}",
        refused.map_or_else(|error| format!("refused as {error}"), |_| "valid".into())
    );

    let honest = bench.plain_coinbase(&miner, tip);
    bench.mine(honest, vec![paying]);
    assert_eq!(
        bench.ledger.supply().as_pebbles(),
        before.as_pebbles() + reward.as_pebbles() - 2 * PRICE,
        "the supply did not fall by the burn: the places were paid for with \
         money that is still somewhere"
    );
}

/// A note that has already fallen gives no place back when it is spent, so a
/// transfer spending one pays for all of its outputs.
///
/// Counting inputs instead of hot inputs would charge a transfer re-spending
/// fallen notes for the places it frees, which are none: its notes left the
/// tier already, and every output it makes is a note pushed out of it.
#[test]
fn a_note_that_already_fell_frees_no_place() {
    let params = rules();
    let (miner, owner) = (wallet(1), wallet(2));
    let mut bench = Bench::new(params);
    let notes = bench.fill(&owner);

    // Sixteen more notes push the sixteen oldest out, into the grace window.
    bench.spread(&miner, 8);
    bench.spread(&miner, 8);
    let fallen: Vec<(NoteId, Note)> = notes
        .iter()
        .copied()
        .filter(|(id, _)| bench.ledger.hot_note(id).is_none())
        .collect();
    assert!(fallen.len() >= 2, "notes fell out of the tier");
    let (graced, cold) = (fallen[0], fallen[1]);
    assert!(
        bench.ledger.within_grace(&graced.0).is_some(),
        "a note that fell a block ago is in the grace window"
    );

    // Spent with a plain hot tag, a grace note is charged for all three
    // outputs, not for two.
    let two = spend_hot(&params, &[graced], &owner, 3, 2 * PRICE);
    assert_eq!(
        check(&bench, &two),
        Err(TransferError::PlacesUnpaid {
            places: 3,
            burn: pebbles(3 * PRICE),
            fee: pebbles(2 * PRICE),
        }),
        "a note spent out of the grace window was credited with a place it \
         no longer held"
    );
    let three = spend_hot(&params, &[graced], &owner, 3, 3 * PRICE);
    assert_eq!(check(&bench, &three), Ok(pebbles(3 * PRICE)));

    // Out of the window, the same spend carries a proof, and still frees
    // nothing.
    for _ in 0..2 * cairn_ledger::state::GRACE_BLOCKS {
        if bench.ledger.within_grace(&cold.0).is_none() {
            break;
        }
        let coinbase = bench.plain_coinbase(&miner, 0);
        bench.mine(coinbase, Vec::new());
    }
    assert!(bench.ledger.within_grace(&cold.0).is_none());
    let position = bench.ledger.cold().locate(&cold.0, &cold.1).unwrap();
    let proof = bench.ledger.cold().prove(position).unwrap();
    let witness = || vec![Input::cold(cold.0, cold.1, position, proof.clone())];
    let two = spend(&params, &[cold], witness(), &owner, 3, 2 * PRICE);
    assert_eq!(
        check(&bench, &two),
        Err(TransferError::PlacesUnpaid {
            places: 3,
            burn: pebbles(3 * PRICE),
            fee: pebbles(2 * PRICE),
        }),
        "a note spent with a proof was credited with a place it no longer held"
    );
    let three = spend(&params, &[cold], witness(), &owner, 3, 3 * PRICE);
    assert_eq!(check(&bench, &three), Ok(pebbles(3 * PRICE)));
}

/// Taking no place costs nothing: a transfer that gives room back burns
/// nothing, and a coinbase's own notes burn nothing.
///
/// The price is on places taken, so it has to stop there. Charged on every
/// output, consolidating notes, which is what gives the tier room back, would
/// cost the price of the room it gives; charged on the coinbase, the reward
/// would shrink by the notes a miner pays itself in.
#[test]
fn giving_room_back_costs_nothing() {
    let params = rules();
    let (miner, owner) = (wallet(1), wallet(2));
    let mut bench = Bench::new(params);
    let notes = bench.spread(&owner, 4);

    let gathering = spend_hot(&params, &notes[..3], &owner, 1, 0);
    assert_eq!(
        check(&bench, &gathering),
        Ok(Amount::ZERO),
        "three notes gathered into one gave two places back and were charged"
    );
    let reward = params.reward_at(bench.height());
    let coinbase = CoinbaseTransaction::new(
        bench.height(),
        (0..params.max_coinbase_outputs)
            .map(|index| {
                let each = reward.as_pebbles() / params.max_coinbase_outputs as u64;
                let first = reward.as_pebbles() - each * (params.max_coinbase_outputs as u64 - 1);
                Note::new(
                    pebbles(if index == 0 { first } else { each }),
                    miner.public_key(),
                )
            })
            .collect(),
    );
    let before = bench.ledger.supply();
    bench.mine(coinbase, vec![gathering]);
    assert_eq!(
        bench.ledger.supply().as_pebbles(),
        before.as_pebbles() + reward.as_pebbles(),
        "a coinbase paying the whole reward over sixteen notes was charged for them"
    );
}

/// A burn too large for an amount is refused `ValueOverflow`, the refusal the
/// specification's *Places* now names for it.
///
/// Unreachable on any network shipped here: 6 000 pebbles times at most 256
/// places is nowhere near the ceiling. This asks a price no network here
/// uses, so the refusal is exercised at all rather than left as a code
/// reading nothing here demonstrates a consequence for.
#[test]
fn a_burn_too_large_for_an_amount_is_refused_value_overflow() {
    let params = rules().with_place_price(Amount::MAX_MONEY);
    let mut bench = Bench::new(params);
    let owner = wallet(2);
    let notes = bench.spread(&owner, 4);
    let spent = notes[0];

    // One hot input, three outputs: two places, and two times the maximum
    // amount overflows what an amount can hold.
    let transfer = spend_hot(&params, &[spent], &owner, 3, 0);
    assert_eq!(
        check(&bench, &transfer),
        Err(TransferError::ValueOverflow),
        "a burn that does not fit in an amount should be refused ValueOverflow, \
         which is what the specification now says it is"
    );
}

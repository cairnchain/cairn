//! A payment whose note somebody pays to push out of the hot set before a
//! block carries it.
//!
//! A payment is credited a place for every hot note it spends. A note that
//! falls before the block frees nothing, so the payment then owes the burn of
//! one place more than when it was signed, and the burn is a rule: short of
//! it, every block refuses the payment `PlacesUnpaid`. Anybody can make a note
//! fall by paying the place price for enough new places to push out
//! everything older, and the oldest notes, which are the savers', fall first.
//! The attack catalogue of 3 October files this as G04, beside G01 and G03,
//! and lab scenario R6 asks it of the wallet.
//!
//! The wallet's answer is the fee it quotes when none is named: the floor and
//! one place price over it for every place a falling note can add, and since
//! 8 October (04-F2) never less than what outranks filler that takes no place
//! and pays the floor, at what the payment weighs once those places are
//! taken. Nothing
//! asked whether that answer holds against a flush somebody pays for, all the
//! way to a block. These tests push the notes out the way an attacker would,
//! through the pool and an honest miner's choice, paying for every place and
//! outbidding the payment for the block's room, then follow the payment to
//! the block that carries it or to the line that says nothing will.
//!
//! What they found, on devnet's tier of sixty four and cap of thirty two:
//!
//! - At the quote, the payment stays in the pool across the flush and the
//!   next block carries it. Once its note has fallen it still pays more than
//!   it owes, and a pool still ranks it above filler at the floor: until
//!   04-F2 the margin was spent to the pebble, the payment then paid exactly
//!   its floor, and filler at the floor outranked it. A payment of two hot
//!   notes, both pushed out, is carried the same way.
//! - At the floor, which a person may name, the flush makes the payment one
//!   no block may carry. Nothing re-signs it. The wallet says why in words
//!   beside it, holds its notes for `HELD_AFTER_REFUSAL` blocks, then names
//!   it as not carried with its money back, and the payment sent again spends
//!   the same note, so the two can never both be carried.
//! - At the quote, but kept out of every block until its note leaves the
//!   grace window, the payment needs a proof. The wallet hands it back with
//!   one, the quote covers the proof's bytes here, and the first block the
//!   flush leaves alone carries it. Until 04-F2 the quote covered the place
//!   and not the proof's bytes, no pool took it, and the wallet went the
//!   floor's way.
//!
//! What a flush costs: the place price for every note ahead of the one it is
//! after and for that note, less one place each block's coinbase pushes out
//! for nothing. Here sixteen places, 96 000 pebbles destroyed, and more than
//! twice as much again to the miner to outbid the payment for the block's
//! places, which a miner flushing on its own account keeps. Keeping the payment out
//! until its note left the grace window took sixty five blocks of that, 1 040
//! places and 6 240 000 pebbles destroyed. At a public network's cap the
//! window is eight blocks of about a thousand places each.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::path::PathBuf;

use cairn_chain::{
    fee_floor, fee_to_outrank, places_taken, transfer_weight, ChainStore, FLOOR_RATE,
};
use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Address, Note, NoteId};
use cairn_ledger::state::GRACE_BLOCKS;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, BlockError, ConsensusParams, TransferError,
    PLACE_PRICE,
};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::pending::HELD_AFTER_REFUSAL;
use cairn_wallet::{Sent, Wallet};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Devnet's tier and eviction cap.
const TIER: usize = 64;
const CAP: usize = 32;

/// Devnet's tier and cap at the public place price, with rewards spendable
/// at once.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_hot_capacity(TIER)
        .with_max_evictions(CAP)
        .with_place_price(PLACE_PRICE)
}

/// What a block has for the places of transfers on a full tier: the cap less
/// the room a miner keeps for a whole coinbase.
fn places_a_block() -> usize {
    CAP - params().max_coinbase_outputs
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-pushed-out-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// Mines blocks on a private copy of the chain, which is also the rules'
/// verdict on every block before any node sees it.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    /// The next block, its reward shared evenly between `owners`, carrying
    /// `transfers`, or what the rules refused it for.
    fn mine(
        &mut self,
        owners: &[PublicKey],
        transfers: Vec<Transfer>,
    ) -> Result<Block, BlockError> {
        let height = self.state.next_height().unwrap();
        let reward = self.params.reward_at(height).as_pebbles();
        let count = owners.len() as u64;
        let each = reward / count;
        let first = reward - each * (count - 1);
        let outputs = owners
            .iter()
            .enumerate()
            .map(|(index, owner)| {
                let value = if index == 0 { first } else { each };
                Note::new(Amount::from_pebbles(value).unwrap(), *owner)
            })
            .collect();
        let clock = self.clock + 600;
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block = assemble_block(&self.state, coinbase, transfers, &self.params, clock, 0)?;
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW)?;
        self.clock = clock;
        Ok(block)
    }
}

/// Whoever pays to push notes out: a key holding hot notes, and what it has
/// spent doing so.
struct Flusher {
    secret: SecretKey,
    /// Its hot notes made after this wallet's, so that what it spends never
    /// moves this wallet's notes nearer the front.
    notes: Vec<(NoteId, Note)>,
    /// Places paid for, what their burn destroyed, and what went on top of
    /// the burn to the miners who carried them.
    places: usize,
    burned: u64,
    to_miners: u64,
}

impl Flusher {
    /// A transfer taking `places` new places in the hot set, paying their
    /// burn and the pool's floor, and when it is to `outbid` enough over that
    /// to rank above everything `chain` pools, so that an honest miner fills
    /// the block's places with it before anything else.
    ///
    /// Its largest note goes back to it whole and every other output is a
    /// pebble: a place costs the same whatever the note in it holds.
    fn pushing(&mut self, chain: &ChainStore, places: usize, outbid: bool) -> Transfer {
        let rules = params();
        // Its own notes fall too, and one that has fallen frees no place.
        self.notes
            .retain(|(id, _)| chain.state().hot_note(id).is_some());
        let largest = (0..self.notes.len())
            .max_by_key(|index| self.notes[*index].1.value)
            .expect("the flusher has run out of notes");
        let (id, note) = self.notes.swap_remove(largest);
        let owner = self.secret.public_key();
        let shaped = |fee: u64| {
            let dust = places as u64;
            let outputs = std::iter::once(note.value.as_pebbles() - fee - dust)
                .chain(std::iter::repeat_n(1, places))
                .map(|value| Note::new(Amount::from_pebbles(value).unwrap(), owner))
                .collect();
            let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
            transfer.sign_input(rules.network, 0, &note, &self.secret);
            transfer
        };
        let probe = shaped(0);
        let bytes = probe.encode().len();
        let weight = transfer_weight(&probe, bytes, 1);
        let floor = fee_floor(bytes, places_taken(&probe, 1), &rules);
        let burn = rules.burn_for(places).unwrap();
        let best = chain.pooled_by_rate().map(|(rate, _)| rate).max();
        let fee = match best {
            Some(best) if outbid => {
                floor.max(burn.checked_add(fee_to_outrank(best, weight)).unwrap())
            }
            _ => floor,
        };
        let transfer = shaped(fee.as_pebbles());
        assert_eq!(
            transfer.encode().len(),
            bytes,
            "fixture: the fee changed the size it was worked out on"
        );
        self.places += places;
        self.burned += burn.as_pebbles();
        // A flusher that mines its own block pays the rest of the fee to
        // itself.
        if outbid {
            self.to_miners += fee.as_pebbles() - burn.as_pebbles();
        }
        transfer
    }
}

/// A full tier of devnet's size, a wallet whose notes sit `older` places from
/// the front of it, and somebody holding the rest of it.
struct Scene {
    directory: PathBuf,
    wallet: Wallet,
    forge: Forge,
    flusher: Flusher,
    /// Who mines the honest blocks.
    miner: PublicKey,
    payee: PublicKey,
}

impl Scene {
    fn new(name: &str, older: usize, ours: usize) -> Self {
        let directory = scratch(name);
        let key_file = directory.join("key");
        let secret = SecretKey::from_bytes(&[3; 32]);
        cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
        let flusher = SecretKey::from_bytes(&[21; 32]);
        let them = flusher.public_key();

        let mut forge = Forge {
            params: params(),
            state: LedgerState::new(),
            clock: 1_000,
        };
        // Eviction goes by the height a note was made at, so the notes in the
        // first block are the first out, and this wallet's are next.
        let mut blocks = vec![
            forge.mine(&vec![them; older], Vec::new()).unwrap(),
            forge
                .mine(&vec![secret.public_key(); ours], Vec::new())
                .unwrap(),
        ];
        while forge.state.hot_len() < TIER {
            let room = (TIER - forge.state.hot_len()).min(params().max_coinbase_outputs);
            blocks.push(forge.mine(&vec![them; room], Vec::new()).unwrap());
        }
        assert_eq!(forge.state.hot_len(), TIER, "fixture: the tier is full");
        let notes = blocks[2..]
            .iter()
            .flat_map(|block| block.coinbase.created_notes())
            .filter(|(_, note)| note.owner == Address::from(them))
            .collect();

        let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
        for block in blocks {
            wallet.node().submit_block(block).unwrap();
        }
        wallet.follow_to_the_tip();

        Self {
            directory,
            wallet,
            forge,
            flusher: Flusher {
                secret: flusher,
                notes,
                places: 0,
                burned: 0,
                to_miners: 0,
            },
            miner: SecretKey::from_bytes(&[30; 32]).public_key(),
            payee: SecretKey::from_bytes(&[9; 32]).public_key(),
        }
    }

    fn pooled(&self, id: &Hash32) -> Option<Transfer> {
        self.wallet
            .node()
            .with_chain(|chain| chain.pooled(id).cloned())
    }

    /// The rate the pool itself ranks `id` at, which is what a miner walks.
    fn rate_of(&self, id: &Hash32) -> Option<u128> {
        self.wallet.node().with_chain(|chain| {
            chain
                .pooled_by_rate()
                .find(|(_, pooled)| *pooled == id)
                .map(|(rate, _)| rate)
        })
    }

    fn height(&self) -> u64 {
        self.wallet.progress().height.unwrap()
    }

    /// The block an honest miner builds from this pool, mined, checked by the
    /// rules, and handed to the wallet's node. Says what it carried.
    fn honest_block(&mut self) -> Vec<Transfer> {
        let chosen = self
            .wallet
            .node()
            .with_chain(|chain| chain.selection(self.forge.params.max_transfers_per_block).0);
        let block = self
            .forge
            .mine(&[self.miner], chosen.clone())
            .unwrap_or_else(|refused| {
                panic!("the rules refused a block an honest miner built from the pool: {refused}")
            });
        self.wallet.node().submit_block(block).unwrap();
        let them = Address::from(self.flusher.secret.public_key());
        for transfer in &chosen {
            if transfer.outputs.iter().all(|note| note.owner == them) {
                self.flusher.notes.extend(transfer.created_notes());
            }
        }
        chosen
    }

    /// One block of the flush: a transfer taking every place a block has for
    /// transfers, handed to the pool at a rate above everything in it, and
    /// the honest block that follows. Says what the block carried.
    fn flush_block(&mut self) -> Vec<Transfer> {
        let places = places_a_block();
        let flusher = &mut self.flusher;
        let push = self
            .wallet
            .node()
            .with_chain(|chain| flusher.pushing(chain, places, true));
        assert_eq!(
            self.wallet.node().submit_transaction(push.clone()).ok(),
            Some(true),
            "fixture: the pool refused the flusher's transfer"
        );
        let chosen = self.honest_block();
        assert!(
            chosen.iter().any(|transfer| transfer.id() == push.id()),
            "fixture: the honest block did not carry the flush"
        );
        chosen
    }

    /// One block of the flush mined by the flusher itself, carrying its own
    /// transfer and nothing from the pool: what a miner pushing notes out
    /// does, and what any block built before a payment reached its miner
    /// looks like.
    fn flush_block_of_its_own(&mut self) -> Vec<Transfer> {
        let places = places_a_block();
        let flusher = &mut self.flusher;
        let push = self
            .wallet
            .node()
            .with_chain(|chain| flusher.pushing(chain, places, false));
        let them = self.flusher.secret.public_key();
        let block = self
            .forge
            .mine(&[them], vec![push.clone()])
            .unwrap_or_else(|refused| panic!("fixture: the rules refused the flush: {refused}"));
        self.wallet.node().submit_block(block).unwrap();
        self.flusher.notes.extend(push.created_notes());
        vec![push]
    }

    fn hot(&self, notes: &[NoteId]) -> usize {
        self.wallet.node().with_chain(|chain| {
            notes
                .iter()
                .filter(|id| chain.state().hot_note(id).is_some())
                .count()
        })
    }

    fn within_grace(&self, notes: &[NoteId]) -> usize {
        self.wallet.node().with_chain(|chain| {
            notes
                .iter()
                .filter(|id| chain.state().within_grace(id).is_some())
                .count()
        })
    }

    /// The payments to the payee the chain holds, as notes in the hot set.
    fn paid_to_payee(&self) -> Vec<Amount> {
        let payee = Address::from(self.payee);
        self.wallet.node().with_chain(|chain| {
            chain
                .state()
                .hot_notes()
                .filter(|(_, entry)| entry.note.owner == payee)
                .map(|(_, entry)| entry.note.value)
                .collect()
        })
    }

    /// What the rules say of a block carrying `transfer` on the chain as it
    /// stands, asked of a copy so nothing is changed.
    fn would_a_block_carry(&self, transfer: &Transfer) -> Result<(), BlockError> {
        let mut copy = Forge {
            params: self.forge.params,
            state: self.forge.state.clone(),
            clock: self.forge.clock,
        };
        copy.mine(&[self.miner], vec![transfer.clone()]).map(|_| ())
    }

    fn finish(self) {
        self.wallet.shutdown();
        drop(self.wallet);
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn inputs_of(transfer: &Transfer) -> Vec<NoteId> {
    transfer.inputs.iter().map(|input| input.note_id).collect()
}

/// What one run of a flush against a payment at the quoted fee came to.
struct Measured {
    margin: Amount,
    places: usize,
    burned: u64,
    to_miners: u64,
    flush_blocks: usize,
}

/// A payment at the fee the wallet quotes, made of `ours` notes sitting
/// `older` places from the front of a full tier, pushed out by a flush that
/// outbids it for every block's places until all of them have fallen, and
/// then left alone for one honest block.
fn pushed_out_and_then_carried(
    name: &str,
    older: usize,
    ours: usize,
    amount: Amount,
    outbid: bool,
) -> Measured {
    let mut scene = Scene::new(name, older, ours);
    let payee = scene.payee;

    let fee = scene.wallet.fee_for(payee, amount);
    let floor = scene.wallet.floor_for(payee, amount);
    let margin = fee.checked_sub(floor).unwrap();
    let sent: Sent = scene.wallet.send(payee, amount, fee).unwrap();
    assert_eq!(
        sent.notes, ours,
        "fixture: the payment gathered other notes"
    );
    let made = scene.pooled(&sent.id).expect("the pool took the payment");
    let its_notes = inputs_of(&made);
    assert!(
        margin >= params().burn_for(ours.min(made.outputs.len())).unwrap(),
        "the quote is less than a place price over the floor for each hot note the payment \
         spends"
    );
    let bytes = made.encode().len();
    assert_eq!(
        fee,
        params()
            .burn_for(places_taken(&made, 0))
            .unwrap()
            .checked_add(fee_to_outrank(FLOOR_RATE, transfer_weight(&made, bytes, 0)))
            .unwrap(),
        "the quote is not what outranks filler at the floor once every note the payment \
         spends has fallen"
    );

    // Outbid for the block's places until every note it spends has fallen.
    let mut flush_blocks = 0;
    while scene.hot(&its_notes) > 0 {
        assert!(
            flush_blocks < 4,
            "fixture: the flush never reached the notes"
        );
        let chosen = if outbid {
            scene.flush_block()
        } else {
            scene.flush_block_of_its_own()
        };
        assert!(
            chosen.iter().all(|transfer| transfer.id() != sent.id),
            "fixture: the payment was carried before its notes fell"
        );
        flush_blocks += 1;
    }
    assert_eq!(
        scene.within_grace(&its_notes),
        ours,
        "fixture: the notes were meant to have only just fallen"
    );

    // Still waited on, and still in the pool, at a price that has moved.
    let waiting = scene.wallet.waiting();
    let ours_waiting = waiting.iter().find(|one| one.id == sent.id);
    assert!(
        ours_waiting.is_some_and(|one| one.pooled && one.why.is_none()),
        "a payment at the quoted fee was let go of by its node after a flush pushed its notes \
         out: {:?}",
        ours_waiting.and_then(|one| one.why.clone())
    );
    let held = scene
        .pooled(&sent.id)
        .expect("the pool let go of a payment paying the wallet's quote");
    let bytes = held.encode().len();
    // AUDIT, repaired (8 October, 04-F2): this said the price after the
    // flush was the quote to the pebble. A payment paying exactly its floor,
    // with places, is the one filler at the floor outranks, and that held
    // here only because nothing competed with it for the next block.
    assert!(
        fee > fee_floor(bytes, places_taken(&held, 0), &params()),
        "after the flush the payment pays no more than its floor"
    );
    let rate = scene
        .rate_of(&sent.id)
        .expect("the payment is not in the pool's own index");
    assert!(
        rate > FLOOR_RATE,
        "after the flush the pool ranks the payment at {rate}, no higher than filler that \
         takes no place and pays the floor, at {FLOOR_RATE}"
    );

    // The flush stops, and the next honest block carries it under the rules.
    let chosen = scene.honest_block();
    assert!(
        chosen.iter().any(|transfer| transfer.id() == sent.id),
        "the honest block after the flush did not carry the payment"
    );
    assert!(
        scene.wallet.waiting().is_empty() && scene.wallet.not_carried().is_empty(),
        "a carried payment is still listed as waiting, or as not carried"
    );
    assert_eq!(
        scene.paid_to_payee(),
        vec![amount],
        "the payee was not paid exactly once"
    );

    let measured = Measured {
        margin,
        places: scene.flusher.places,
        burned: scene.flusher.burned,
        to_miners: scene.flusher.to_miners,
        flush_blocks,
    };
    scene.finish();
    measured
}

/// Blocks go by until the wallet lets go of a payment its node refused at
/// `refused_at`, saying `why`, and the same payment is then sent again at the
/// quote and carried. Says what the quote came to.
///
/// What is held of every payment the wallet lets go of: it is named, with the
/// words it was refused in, its money comes back, and the payment sent again
/// spends one of its notes, so the two can never both be carried.
fn let_go_of_and_sent_again(
    scene: &mut Scene,
    (sent, made): (&Sent, &Transfer),
    why: &str,
    refused_at: u64,
    before: Amount,
) -> Amount {
    let mut ended_at = None;
    for _ in 0..HELD_AFTER_REFUSAL + 2 {
        scene.honest_block();
        // A face asks after the waiting payments first, which is what looks
        // after them.
        let _ = scene.wallet.waiting();
        if !scene.wallet.not_carried().is_empty() {
            ended_at = Some(scene.height());
            break;
        }
    }
    assert_eq!(
        ended_at,
        Some(refused_at + HELD_AFTER_REFUSAL),
        "the payment was not let go of at the block its notes were said to be held until"
    );
    let named = scene.wallet.not_carried();
    assert_eq!(
        named.iter().map(|one| one.id).collect::<Vec<_>>(),
        vec![sent.id],
        "the payment let go of is not named as not carried"
    );
    assert_eq!(
        named[0].why, why,
        "what was said when it was let go of changed"
    );
    assert!(
        named[0].notes_here,
        "its notes are not said to be this key's"
    );
    assert!(scene.wallet.waiting().is_empty());
    assert_eq!(
        scene.wallet.holdings().spendable,
        before,
        "the money of a payment not carried did not come back"
    );

    let payee = scene.payee;
    let quote = scene.wallet.fee_for(payee, sent.amount);
    let again = scene.wallet.send(payee, sent.amount, quote).unwrap();
    assert_eq!(
        inputs_of(&scene.pooled(&again.id).unwrap()),
        inputs_of(made),
        "the payment sent again does not spend the note of the one let go of"
    );
    assert_eq!(
        again.from_cold, 1,
        "fixture: the note was meant to be spent cold"
    );
    let chosen = scene.honest_block();
    assert!(
        chosen.iter().any(|transfer| transfer.id() == again.id),
        "the payment sent again at the quote was not carried"
    );
    assert!(
        scene.would_a_block_carry(made).is_err(),
        "the payment let go of can still be carried beside the one sent again"
    );
    assert_eq!(
        scene.paid_to_payee(),
        vec![sent.amount],
        "the payee was not paid exactly once"
    );
    quote
}

/// A payment at the quoted fee whose one note a paid flush pushes out is
/// still pooled, and the next block carries it.
///
/// Sixteen notes sit ahead of this wallet's. The flush block's coinbase
/// pushes one out for nothing, and the flush pays for the other sixteen
/// places, outbidding the payment for every place the block has.
#[test]
fn a_payment_at_the_quoted_fee_is_carried_after_a_paid_flush_pushes_its_note_out() {
    let measured = pushed_out_and_then_carried("one", 16, 1, cairn("10"), true);
    assert!(measured.margin > PLACE_PRICE);
    assert_eq!(measured.flush_blocks, 1);
    assert_eq!(measured.places, places_a_block());
    assert_eq!(
        measured.burned,
        PLACE_PRICE.as_pebbles() * places_a_block() as u64,
        "what the flush destroyed is not the place price for each place it took"
    );
    println!(
        "\n  one hot note: a margin of {} pebbles; the flush took {} places in {} block,\n  \
         destroyed {} pebbles and paid {} to the miner to outbid the payment\n",
        measured.margin.as_pebbles(),
        measured.places,
        measured.flush_blocks,
        measured.burned,
        measured.to_miners
    );
}

/// The same for a payment of two hot notes, both pushed out: the quote
/// carries a place for each, and needs both.
///
/// Such a payment takes no place in the tier, so no flush can outbid it for a
/// block's places, and an honest block carries it alongside the flush. What
/// pushes its notes out first is a block that leaves it out: a miner flushing
/// on its own account, or any block built before the payment reached it.
#[test]
fn a_payment_whose_two_notes_are_both_pushed_out_is_still_carried() {
    let measured = pushed_out_and_then_carried("two", 15, 2, cairn("30"), false);
    assert!(measured.margin > PLACE_PRICE.checked_add(PLACE_PRICE).unwrap());
    assert_eq!(measured.flush_blocks, 1);
    assert_eq!(
        measured.burned,
        PLACE_PRICE.as_pebbles() * places_a_block() as u64
    );
    println!(
        "\n  two hot notes: a margin of {} pebbles; a miner's own block took {} places\n  \
         and destroyed {} pebbles\n",
        measured.margin.as_pebbles(),
        measured.places,
        measured.burned
    );
}

/// A payment at the floor, which a person may name, becomes one no block may
/// carry once a flush pushes its note out, and the wallet says so.
///
/// The floor is the least a named fee may be and not the fee the wallet pays
/// when none is named, and this is why: the burn it owes moves by a place
/// when its note falls. Nothing re-signs it. It is named, held, let go of
/// and sent again by whoever holds the wallet.
#[test]
fn a_payment_at_the_floor_is_refused_by_the_rules_after_a_flush_and_the_wallet_says_so() {
    let mut scene = Scene::new("floor", 16, 1);
    let payee = scene.payee;
    let amount = cairn("10");
    let before = scene.wallet.holdings().spendable;

    let floor = scene.wallet.floor_for(payee, amount);
    let sent = scene.wallet.send(payee, amount, floor).unwrap();
    let made = scene.pooled(&sent.id).unwrap();
    let its_notes = inputs_of(&made);

    scene.flush_block();
    assert_eq!(scene.hot(&its_notes), 0, "fixture: the note did not fall");
    assert_eq!(scene.within_grace(&its_notes), 1);

    assert!(
        scene.pooled(&sent.id).is_none(),
        "a payment short of its burn is still pooled"
    );
    match scene.would_a_block_carry(&made) {
        Err(BlockError::InvalidTransfer {
            source: TransferError::PlacesUnpaid { places, burn, fee },
            ..
        }) => {
            assert_eq!(places, 2, "the fallen note still gives a place back");
            assert_eq!(burn, params().burn_for(2).unwrap());
            assert_eq!(fee, floor);
        }
        other => panic!(
            "a block carrying the payment at its old floor was not refused PlacesUnpaid: \
             {other:?}"
        ),
    }

    // The wallet hands it back, is refused, and says why in words.
    let refused_at = scene.height();
    let waiting = scene.wallet.waiting();
    let one = waiting
        .iter()
        .find(|one| one.id == sent.id)
        .expect("the payment the rules refuse is no longer listed as waiting");
    assert!(!one.pooled, "the payment is said to be held by its node");
    let why = one
        .why
        .clone()
        .expect("a payment its node refused does not say why");
    assert!(
        why.contains("no block may carry") && why.contains("fallen out"),
        "the refusal is not said plainly: {why}"
    );
    assert_eq!(
        one.held_until,
        Some(refused_at + HELD_AFTER_REFUSAL),
        "the block its notes come back at is not said"
    );
    assert!(
        scene.wallet.holdings().spendable < before,
        "the notes of a refused payment are not held while it is still waited on"
    );

    let quote = let_go_of_and_sent_again(&mut scene, (&sent, &made), &why, refused_at, before);
    println!(
        "\n  at the floor of {} pebbles: refused by the rules at block {refused_at}, let go of\n  \
         at block {}, sent again for {}\n",
        floor.as_pebbles(),
        refused_at + HELD_AFTER_REFUSAL,
        quote.as_pebbles()
    );
    scene.finish();
}

/// A payment at the quoted fee kept out of every block until its note leaves
/// the grace window, by a flush outbidding it for every block's places, is
/// handed back with its proof, still pooled, and carried by the first block
/// the flush leaves alone.
///
/// Past the window the note can only be spent with a proof, and the pool lets
/// go of the payment as it was made. The wallet hands it back with one, and
/// the quote now covers the proof's bytes here: it was asked to outbid filler
/// at the weight of the place a fall adds, 512 units at ten pebbles, which is
/// more than this proof's bytes at the same ten.
///
/// AUDIT, repaired (8 October, 04-F2): until then the quote paid the place
/// and not the proof's bytes, no pool took the payment with its proof, and
/// the wallet named it as not carried and gave its money back, the way of a
/// payment at the floor. Here that took sixty five blocks outbid; at a public
/// network's cap the note bound holds the window to eight.
#[test]
fn a_payment_kept_out_of_blocks_past_the_grace_window_is_handed_back_with_its_proof() {
    let mut scene = Scene::new("grace", 16, 1);
    let payee = scene.payee;
    let amount = cairn("10");

    let fee = scene.wallet.fee_for(payee, amount);
    let sent = scene.wallet.send(payee, amount, fee).unwrap();
    let made = scene.pooled(&sent.id).unwrap();
    let its_notes = inputs_of(&made);

    // Outbid for every block's places, block after block, with a look at the
    // wallet after each, as a face that redraws takes, until the note has left
    // the grace window.
    let sent_at = scene.height();
    let mut fell_at = None;
    let mut crowded = 0usize;
    while scene.hot(&its_notes) > 0 || scene.within_grace(&its_notes) > 0 {
        assert!(
            crowded < GRACE_BLOCKS + 8,
            "fixture: the note never left the grace window"
        );
        let chosen = scene.flush_block();
        assert!(
            chosen.iter().all(|transfer| transfer.id() != sent.id),
            "fixture: the payment was carried while it was outbid"
        );
        crowded += 1;
        if fell_at.is_none() && scene.hot(&its_notes) == 0 {
            fell_at = Some(scene.height());
        }
        let waiting = scene.wallet.waiting();
        assert!(
            waiting
                .iter()
                .any(|one| one.id == sent.id && (one.pooled || one.why.is_some())),
            "the payment stopped being listed as waiting while it was outbid"
        );
    }
    let fell_at = fell_at.unwrap();
    let left_at = scene.height();
    assert_eq!(
        fell_at,
        sent_at + 1,
        "fixture: the note fell later than the first block"
    );
    assert_eq!(left_at, fell_at + GRACE_BLOCKS as u64);

    // Handed back with its proof, and pooled again under the same name.
    let waiting = scene.wallet.waiting();
    let one = waiting.iter().find(|one| one.id == sent.id);
    assert!(
        one.is_some_and(|one| one.pooled && one.why.is_none()),
        "a payment at the quote whose note left the grace window was not handed back with \
         its proof: {:?}",
        one.and_then(|one| one.why.clone())
    );
    let proved = scene
        .pooled(&sent.id)
        .expect("the pool does not hold the payment the wallet says it holds");
    assert!(
        proved.encode().len() > made.encode().len(),
        "fixture: the payment the pool holds carries no proof"
    );
    let asked = fee_floor(proved.encode().len(), places_taken(&proved, 0), &params());
    assert!(
        fee >= asked,
        "the quote of {fee} does not reach the {asked} its proof's bytes ask"
    );
    let grew = proved.encode().len() - made.encode().len();
    let (places, burned, to_miners) = (
        scene.flusher.places,
        scene.flusher.burned,
        scene.flusher.to_miners,
    );
    assert_eq!(places, crowded * places_a_block());
    assert_eq!(burned, PLACE_PRICE.as_pebbles() * places as u64);

    // The flush stops, and the next honest block carries it.
    let chosen = scene.honest_block();
    assert!(
        chosen.iter().any(|transfer| transfer.id() == sent.id),
        "the honest block after the flush did not carry the payment with its proof"
    );
    assert!(
        scene.wallet.waiting().is_empty() && scene.wallet.not_carried().is_empty(),
        "a carried payment is still listed as waiting, or as not carried"
    );
    assert_eq!(
        scene.paid_to_payee(),
        vec![amount],
        "the payee was not paid exactly once"
    );
    println!(
        "\n  kept out until its note left the grace window: sent at block {sent_at}, fell at\n  \
         {fell_at}, out of the window at {left_at} after {crowded} blocks outbid. It pays {}\n  \
         and its proof of {grew} bytes asks {}. The flush took {places} places, destroyed\n  \
         {burned} pebbles and paid {to_miners} to miners. Carried by the next block\n",
        fee.as_pebbles(),
        asked.as_pebbles(),
    );
    scene.finish();
}

/// A payment quoted a blank fee while its note is hot, whose note falls out
/// of the hot set before a block carries it, still ranks above filler that
/// takes no place and pays the floor.
///
/// AUDIT, repaired (8 October, 04-F2). The quote was worked out at the
/// weight the payment has while its notes are hot. A note that falls adds a
/// place, and the place adds its burn, which the margin paid, and 512 to the
/// weight, which nothing paid: the pool ranked this one at 117 197 against
/// the floor rate's 655 360, so blocks kept full of filler at the floor never
/// carried it. What pushes the note out here is a block that leaves the
/// payment out, as any block built before the payment reached its miner does.
#[test]
fn a_blank_fee_still_outranks_floor_filler_after_the_note_it_spends_falls() {
    let mut scene = Scene::new("after-the-fall", 16, 1);
    let payee = scene.payee;
    let amount = cairn("1");

    let quote = scene.wallet.fee_for(payee, amount);
    let sent: Sent = scene.wallet.send(payee, amount, quote).unwrap();
    let made = scene.pooled(&sent.id).expect("the pool took the payment");
    let its_notes = inputs_of(&made);
    let hot_rate = scene
        .rate_of(&sent.id)
        .expect("the payment is not in the pool's own index");
    assert!(
        hot_rate > FLOOR_RATE,
        "the quote does not outrank filler at the floor even while its note is hot: \
         {hot_rate} against {FLOOR_RATE}"
    );

    let mut blocks = 0;
    while scene.hot(&its_notes) > 0 {
        assert!(blocks < 4, "fixture: the flush never reached the note");
        let chosen = scene.flush_block_of_its_own();
        assert!(
            chosen.iter().all(|transfer| transfer.id() != sent.id),
            "fixture: the payment was carried before its note fell"
        );
        blocks += 1;
    }
    assert_eq!(
        scene.within_grace(&its_notes),
        1,
        "fixture: the note was meant to have only just fallen"
    );
    let held = scene
        .pooled(&sent.id)
        .expect("the pool let go of a payment paying the wallet's quote");
    assert_eq!(places_taken(&held, 0), 2, "fixture: the fall added a place");
    let fallen_rate = scene
        .rate_of(&sent.id)
        .expect("the payment is not in the pool's own index");
    scene.finish();
    assert!(
        fallen_rate > FLOOR_RATE,
        "a payment quoted a blank fee of {quote}, whose note fell out of the hot set before a \
         block carried it, is ranked at {fallen_rate}, no higher than filler that takes no \
         place and pays the floor, at {FLOOR_RATE}: blocks kept full of such filler never \
         carry it"
    );
}

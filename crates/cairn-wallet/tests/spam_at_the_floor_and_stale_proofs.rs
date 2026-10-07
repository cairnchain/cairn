//! Spam at the floor and stale proofs, from the wallet's side.
//!
//! Lab scenarios R15, its wallet half, and R21 (attacks F01 and G05 of the 3
//! October catalogue). `cairn-chain/tests/spam_at_the_floor.rs` holds the
//! pool's half: a payment at twice its floor goes through blocks kept full at
//! the floor, and one at its floor does not. This asks what a wallet pays
//! when nobody names a fee, and whether that is carried, for a payment from a
//! hot note and for one from a note that has fallen out of the hot set; and,
//! for the second, what happens when somebody spends a note beside it in the
//! cold set every block, which makes its proof stale every block.
//!
//! The catalogue's defences are that an honest payer outbids filler at the
//! floor, and that a wallet hands a payment whose proof went stale back to
//! its pool with a fresh one. Its pass marks: carried within two blocks of
//! the spam (R15), and within five under the stale-making spends (R21).
//!
//! **What was found**, on a tier of 128, sixteen places a block and an eight
//! kibibyte block, which about forty transfers at the floor fill:
//!
//! ```text
//! note     spam          spends beside   fee paid, pebbles      carried   handed back
//! hot      every block   no              quote, 14 230          block 1   -
//! fallen   every block   no              quote, 16 670          never     none needed
//! fallen   three blocks  every block     floor, 16 670          block 4   3 of 3
//! fallen   every block   every block     quote, 16 670          never     8 of 8
//! fallen   every block   every block     twice floor, 33 340    block 1   -
//! ```
//!
//! The hot payment's floor is 8 230 pebbles, the fallen one's 16 670.
//!
//! The proofs are not what fails. A payment whose proof the attacker made
//! stale was let go of by the pool after every block and handed back with a
//! fresh one by the wallet's next look, every time, and carried by the first
//! block with room. What fails is the fee. A payment spending only fallen
//! notes frees no place, so the wallet's margin, a place's price for every
//! note that could still fall, is nought, and its quote is exactly the floor:
//! 16 670 pebbles here, of which 12 000 burn for its two places, leaving its
//! miner 4 670 for a weight of 1 491, about three pebbles a unit against the
//! filler's ten. The wallet outbids only a pool that is full, never one that
//! merely holds more than a block, so the payment waits for as long as
//! somebody pays ten pebbles a byte to keep blocks full: 0.78 CAIRN an hour
//! at testnet's block, all of it to the miners. A payment from a hot note
//! gets through only because its one place's price, 6 000 pebbles, happens to
//! be more than the 5 120 its place's weight is worth at ten a unit.
//!
//! The two failing tests here are R15's and R21's pass marks asked of the
//! fee a wallet pays when nobody names one; they fail for the one reason.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use cairn_accumulator::forest::tree_of;
use cairn_chain::{fee_floor, places_taken, ChainStore};
use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Address, Note, NoteId};
use cairn_ledger::state::GRACE_BLOCKS;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, ConsensusParams, PLACE_PRICE,
};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The hot set, small enough that filling it and pushing notes out of it
/// takes a handful of blocks.
const TIER: usize = 128;

/// A tier of [`TIER`], an eviction cap leaving a full tier's block sixteen
/// places for its transfers, the public place price, rewards spendable at
/// once, and an eight kibibyte block, which about forty transfers fill.
fn params() -> ConsensusParams {
    ConsensusParams {
        max_block_bytes: 8 * 1024,
        ..ConsensusParams::testnet()
            .with_coinbase_maturity(0)
            .with_hot_capacity(TIER)
            .with_max_evictions(32)
            .with_place_price(PLACE_PRICE)
    }
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-spam-stale-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// Mines blocks on a private ledger, which is also the rules' verdict on
/// every block before the wallet's node sees it. It follows the attacker's
/// notes into the cold set, so it can hand the attacker proofs.
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    /// The next block, its reward shared between `owners`, carrying
    /// `transfers`.
    fn mine(&mut self, owners: &[PublicKey], transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        let reward = self.params.reward_at(height).as_pebbles();
        let count = owners.len() as u64;
        let each = reward / count;
        let outputs = owners
            .iter()
            .enumerate()
            .map(|(at, owner)| {
                let value = if at == 0 {
                    reward - each * (count - 1)
                } else {
                    each
                };
                Note::new(Amount::from_pebbles(value).unwrap(), *owner)
            })
            .collect();
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
        .unwrap_or_else(|refused| panic!("the rules refused the block: {refused}"));
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }
}

/// One hot note spent whole back to its owner at exactly the pool's floor:
/// no place taken, so ten pebbles a unit of weight, the best rate the floor
/// buys.
fn filler(owner: &SecretKey, id: NoteId, note: Note) -> Transfer {
    let rules = params();
    let shaped = |fee: u64| {
        let back = Note::new(
            Amount::from_pebbles(note.value.as_pebbles() - fee).unwrap(),
            owner.public_key(),
        );
        let mut transfer = Transfer::new(vec![Input::hot(id)], vec![back]);
        transfer.sign_input(rules.network, 0, &note, owner);
        transfer
    };
    let probe = shaped(1);
    let floor = fee_floor(probe.encode().len(), places_taken(&probe, 1), &rules);
    shaped(floor.as_pebbles())
}

/// A wallet holding one note, and around it a filler holding most of a full
/// tier and an attacker holding fallen notes in the same tree of the cold
/// set as the wallet's, should it have fallen.
struct Scene {
    directory: PathBuf,
    wallet: Wallet,
    forge: Forge,
    filler: SecretKey,
    attacker: SecretKey,
    /// The attacker's fallen notes it has not spent yet.
    stash: Vec<(NoteId, Note)>,
    /// The wallet's one note.
    ours: NoteId,
    /// Who mines the honest blocks.
    miner: PublicKey,
    payee: PublicKey,
}

impl Scene {
    /// A wallet whose one note has `fallen` out of the hot set and out of
    /// the grace window, so that spending it takes a proof, or is still hot.
    fn new(name: &str, fallen: bool) -> Self {
        let directory = scratch(name);
        let key_file = directory.join("key");
        let secret = key(3);
        cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
        let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
        let filler = key(21);
        let attacker = key(22);
        let mut state = LedgerState::new();
        state.watch_owner(attacker.public_key());
        let mut forge = Forge {
            params: params(),
            state,
            clock: 1_000,
        };
        let ours = secret.public_key();
        let them = filler.public_key();
        let mut blocks = Vec::new();

        // The first block's notes are the first to fall, all in one block,
        // so they sit side by side in the cold set.
        let mut first = vec![attacker.public_key(); 15];
        if fallen {
            first.insert(7, ours);
        } else {
            first.push(attacker.public_key());
        }
        blocks.push(forge.mine(&first, Vec::new()));
        // The filler's notes fill the tier, and one block more pushes the
        // first block's out.
        while forge.state.hot_len() < TIER {
            blocks.push(forge.mine(&[them; 16], Vec::new()));
        }
        blocks.push(forge.mine(&[them; 16], Vec::new()));
        // Then out of the grace window, so that spending them takes a proof.
        for _ in 0..=GRACE_BLOCKS {
            blocks.push(forge.mine(&[them], Vec::new()));
        }
        if !fallen {
            blocks.push(forge.mine(&[ours], Vec::new()));
        }
        for block in blocks {
            wallet.node().submit_block(block).unwrap();
        }
        wallet.follow_to_the_tip();

        let stash: Vec<(NoteId, Note)> = forge
            .state
            .watched_notes()
            .map(|(id, _, note)| (id, note))
            .collect();
        assert_eq!(
            stash.len(),
            first.len() - usize::from(fallen),
            "fixture: the attacker's notes have fallen"
        );
        let held = wallet.holdings().notes;
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].is_cold(), fallen, "fixture: the wallet's note");
        if fallen {
            assert!(
                forge.state.within_grace(&held[0].id).is_none(),
                "fixture: the wallet's note is still in the grace window"
            );
        }

        Self {
            directory,
            wallet,
            forge,
            filler,
            attacker,
            stash,
            ours: held[0].id,
            miner: key(30).public_key(),
            payee: key(9).public_key(),
        }
    }

    fn pooled(&self, id: &Hash32) -> Option<Transfer> {
        self.wallet
            .node()
            .with_chain(|chain| chain.pooled(id).cloned())
    }

    /// Tops the pool up with floor-paying spends of the filler's hot notes
    /// until it holds a block's worth and one more, so the next block is full
    /// of them and, once the filler stops, the one after has room.
    fn top_up(&self) {
        let them = Address::from(self.filler.public_key());
        let room = ChainStore::room_for_transfers(params().max_block_bytes);
        let spends: Vec<Transfer> = self.wallet.node().with_chain(|chain| {
            let spoken_for: BTreeSet<NoteId> =
                chain.pooled_spenders().map(|(note, _)| *note).collect();
            let mut pooled: usize = chain
                .pooled_spenders()
                .filter_map(|(_, id)| chain.pooled(id))
                .filter(|transfer| transfer.outputs[0].owner == them)
                .map(|transfer| transfer.encode().len())
                .sum();
            let mut spends = Vec::new();
            for (id, entry) in chain.state().hot_notes() {
                if pooled > room {
                    break;
                }
                if entry.note.owner == them && !spoken_for.contains(&id) {
                    let spend = filler(&self.filler, id, entry.note);
                    pooled += spend.encode().len();
                    spends.push(spend);
                }
            }
            assert!(pooled > room, "fixture: the filler has run out of notes");
            spends
        });
        for spend in spends {
            assert_eq!(
                self.wallet.node().submit_transaction(spend).ok(),
                Some(true),
                "fixture: the pool refused the filler"
            );
        }
    }

    /// Hands the pool a spend of one of the attacker's fallen notes in the
    /// same tree of the cold set as `position`, at a rate above the filler,
    /// so the next block carries it and every proof in that tree goes stale.
    fn spend_beside(&mut self, position: u64) {
        let rules = params();
        let state = &self.forge.state;
        let leaves = state.cold_roots().leaves();
        let tree = tree_of(leaves, position).unwrap();
        let at = self
            .stash
            .iter()
            .position(|(id, _)| {
                let theirs = state.watched_position(id).unwrap();
                tree_of(leaves, theirs) == Some(tree)
            })
            .expect("fixture: the attacker has no note left beside the wallet's");
        let (id, note) = self.stash.swap_remove(at);
        let position = state.watched_position(&id).unwrap();
        let proof = state.cold().proof_of(position).unwrap();
        let attacker = &self.attacker;
        let shaped = |fee: u64| {
            let back = Note::new(
                Amount::from_pebbles(note.value.as_pebbles() - fee).unwrap(),
                attacker.public_key(),
            );
            let mut transfer = Transfer::new(
                vec![Input::cold(id, note, position, proof.clone())],
                vec![back],
            );
            transfer.sign_input(rules.network, 0, &note, attacker);
            transfer
        };
        let probe = shaped(1);
        let floor = fee_floor(probe.encode().len(), places_taken(&probe, 0), &rules);
        let spend = shaped(floor.as_pebbles() * 4);
        assert_eq!(
            self.wallet.node().submit_transaction(spend).ok(),
            Some(true),
            "fixture: the pool refused the attacker's cold spend"
        );
    }

    /// The block an honest miner builds from the pool, mined and handed to
    /// the wallet's node. Says what it carried.
    fn honest_block(&mut self) -> Vec<Hash32> {
        let chosen = self
            .wallet
            .node()
            .with_chain(|chain| chain.selection(self.forge.params.max_transfers_per_block).0);
        let block = self.forge.mine(&[self.miner], chosen.clone());
        self.wallet.node().submit_block(block).unwrap();
        chosen.iter().map(Transfer::id).collect()
    }

    /// Where the wallet's note sits in the cold set.
    fn position_of_ours(&self) -> u64 {
        self.wallet
            .node()
            .with_chain(|chain| chain.state().watched_position(&self.ours))
            .unwrap()
    }

    fn finish(self) {
        self.wallet.shutdown();
        drop(self.wallet);
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// What a run of blocks came to for one payment.
#[derive(Debug, Default)]
struct Followed {
    /// The block that carried it, counted from one.
    carried: Option<usize>,
    /// Blocks after which the pool had let it go and the wallet handed it
    /// back, with a proof other than the one it held.
    handed_back: usize,
    /// Blocks after which the pool did not hold it once the wallet had
    /// looked.
    missing: usize,
}

/// Sends `amount` at `fee`, then runs `blocks` honest blocks, the first
/// `spam` of them with the filler topping the pool up before each and, with
/// `stale`, the attacker spending a note beside the payment's. The wallet is
/// looked at after every block, as a face that redraws does.
fn follow(scene: &mut Scene, fee: Amount, blocks: usize, spam: usize, stale: bool) -> Followed {
    let sent = scene.wallet.send(scene.payee, cairn("1"), fee).unwrap();
    let mut followed = Followed::default();
    for number in 1..=blocks {
        if number <= spam {
            scene.top_up();
            if stale {
                let position = scene.position_of_ours();
                scene.spend_beside(position);
            }
        }
        let before = scene.pooled(&sent.id).map(|transfer| transfer.encode());
        let carried = scene.honest_block();
        if carried.contains(&sent.id) {
            followed.carried = Some(number);
            break;
        }
        let dropped = scene.pooled(&sent.id).is_none();
        let _ = scene.wallet.waiting();
        let after = scene.pooled(&sent.id).map(|transfer| transfer.encode());
        if dropped && after.is_some() && after != before {
            followed.handed_back += 1;
        }
        if after.is_none() {
            followed.missing += 1;
        }
    }
    followed
}

/// **A payment from a hot note, at the wallet's own quote, goes through
/// blocks kept full at the floor.**
///
/// The quote is the floor and a place's price over it, for the place the
/// note would stop freeing if it fell before a block. What a pool ranks is
/// what a fee leaves its miner per unit of weight, and that place's price,
/// 6 000 pebbles, is more than the 512 units of weight the place adds at ten
/// pebbles each: the quote ranks above filler at the floor, though the margin
/// is there for a falling note and not for this. Filler paying about 1.12
/// times its floor would outrank it.
#[test]
fn a_payment_from_a_hot_note_at_the_wallets_quote_goes_through_filler_at_the_floor() {
    let mut scene = Scene::new("hot", false);
    let fee = scene.wallet.fee_for(scene.payee, cairn("1"));
    let floor = scene.wallet.floor_for(scene.payee, cairn("1"));
    assert_eq!(
        fee.as_pebbles(),
        floor.as_pebbles() + PLACE_PRICE.as_pebbles()
    );
    let followed = follow(&mut scene, fee, 4, 4, false);
    println!("\n  a hot payment at the quote of {fee}: {followed:?}\n");
    assert_eq!(followed.carried, Some(1));
    scene.finish();
}

/// **A payment from a fallen note, at the wallet's own quote, is carried
/// within two blocks of filler at the floor.**
///
/// R15's pass mark, asked of the fee a wallet pays when nobody names one.
#[test]
fn a_payment_from_a_fallen_note_at_the_wallets_quote_goes_through_filler_at_the_floor() {
    let mut scene = Scene::new("cold", true);
    let fee = scene.wallet.fee_for(scene.payee, cairn("1"));
    let floor = scene.wallet.floor_for(scene.payee, cairn("1"));
    let followed = follow(&mut scene, fee, 6, 6, false);
    println!(
        "\n  a payment from a fallen note at the quote of {fee}, floor {floor}: {followed:?}\n"
    );
    scene.finish();
    assert!(
        followed.carried.is_some_and(|block| block <= 2),
        "a payment from a fallen note at the wallet's own quote of {fee}, the floor being \
         {floor}, waited behind filler at the floor: {followed:?}"
    );
}

/// **A payment from a fallen note whose proof is made stale every block is
/// handed back fresh every time, and carried once a block has room.**
///
/// R21's defence on its own: three blocks of filler with a spend beside the
/// payment's note in each, then a block with room. The payment pays its
/// floor, which a person may name, so that the filler holds it out of those
/// three blocks whatever the wallet would have quoted.
#[test]
fn a_payment_whose_proof_goes_stale_every_block_is_handed_back_every_time() {
    let mut scene = Scene::new("stale", true);
    let floor = scene.wallet.floor_for(scene.payee, cairn("1"));
    let followed = follow(&mut scene, floor, 6, 3, true);
    println!("\n  a payment from a fallen note under stale-making spends: {followed:?}\n");
    assert_eq!(followed.handed_back, 3, "{followed:?}");
    assert_eq!(followed.missing, 0, "{followed:?}");
    assert_eq!(followed.carried, Some(4), "{followed:?}");
    scene.finish();
}

/// **A payment from a fallen note at twice its floor is carried by the first
/// block, through filler at the floor and a spend beside it.**
///
/// The same attack as below, with the fee named: what R21 asks, held as soon
/// as the fee outranks the filler.
#[test]
fn a_payment_from_a_fallen_note_at_twice_its_floor_goes_through_spam_and_stale_proofs() {
    let mut scene = Scene::new("stale-spam-2x", true);
    let floor = scene.wallet.floor_for(scene.payee, cairn("1"));
    let fee = Amount::from_pebbles(floor.as_pebbles() * 2).unwrap();
    let followed = follow(&mut scene, fee, 3, 3, true);
    println!("\n  a payment from a fallen note at {fee}, twice its floor: {followed:?}\n");
    assert_eq!(followed.carried, Some(1), "{followed:?}");
    scene.finish();
}

/// **A payment from a fallen note, at the wallet's own quote, is carried
/// within five blocks of filler at the floor and a spend beside it in every
/// one.**
///
/// R21's pass mark, asked of the fee a wallet pays when nobody names one.
#[test]
fn a_payment_from_a_fallen_note_at_the_wallets_quote_is_carried_through_stale_proofs() {
    let mut scene = Scene::new("stale-spam", true);
    let fee = scene.wallet.fee_for(scene.payee, cairn("1"));
    let followed = follow(&mut scene, fee, 8, 8, true);
    println!("\n  a payment from a fallen note under spam and stale-making spends: {followed:?}\n");
    scene.finish();
    assert!(
        followed.carried.is_some_and(|block| block <= 5),
        "a payment from a fallen note at the wallet's own quote of {fee} waited past five \
         blocks of filler at the floor: {followed:?}"
    );
}

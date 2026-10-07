//! Block space bought at the floor, and what an ordinary payment then waits.
//!
//! Lab scenario R15 (attacks F01 and G12 of the 3 October catalogue). A
//! sender keeps every block full of transfers paying the least the pool
//! takes, and an ordinary payer arrives. The pool ranks by what a fee leaves
//! its miner per unit of weight, bytes plus 512 for every place in the hot
//! set, so the catalogue's defence is that an honest payer outbids; its pass
//! mark is a payment at twice its floor carried within two blocks.
//!
//! The floor is ten pebbles a byte, and the burn of the places, which a miner
//! cannot keep. So what a floor-paying transfer leaves its miner is ten
//! pebbles a byte whatever its shape, while its weight grows by 512 a place:
//! a transfer that takes no place, one spending a hot note back to its own
//! sender, ranks at exactly ten a unit of weight, and every transfer that
//! takes a place ranks below that at its own floor. A payment, which takes
//! one, is outranked at its floor by every byte of such filler, for as long
//! as somebody pays to send it.
//!
//! **Measured** on testnet rules with a quarter of its block and of its
//! eviction cap, and a full tier of 2 048 notes, so a block has 240 places
//! for its transfers and no room in the tier on top. Three payments, at one,
//! two and five times their floor, sent before the first block; then six
//! blocks of filler, or four of splits buying the places:
//!
//! ```text
//!                         carried by block    the spammer, a block
//!                         1x    2x    5x      paid        burned     places
//! filler, no place        none  1     1         317 505          0   0
//! splits, every place     1     1     1       1 347 202  1 260 000   120 240 240 240
//! ```
//!
//! A payment at twice its floor is carried by the first block, as the
//! catalogue asks, and at its floor by none while the filler lasts, for ten
//! pebbles a byte: 0.19 CAIRN an hour here, 0.78 at testnet's full block,
//! all of it to the miners. Buying every place instead, at the floor, delays
//! nobody: a payment at its floor ranks above the place buyer's own floor,
//! and its place comes out of the spammer's. Testnet's 1 008 places would
//! burn 6 048 000 pebbles a block, 3.6 CAIRN an hour.
//!
//! What a wallet pays when nobody names a fee, and whether that goes through,
//! is the wallet's half: `cairn-wallet/tests/spam_at_the_floor_and_stale_proofs.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;

use cairn_chain::{fee_floor, places_taken, ChainStore, MIN_FEE_PER_WEIGHT};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Address, Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, mine_block, ConsensusParams, PLACE_PRICE};
use cairn_ledger::TransferError;
use cairn_primitives::amount::PEBBLES_PER_CAIRN;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

const ATTEMPTS: u64 = 1 << 20;

/// Testnet's place price, with a tier small enough to fill, rewards
/// spendable at once, and a quarter of testnet's block and of its eviction
/// cap.
///
/// The quarter is for the suite's sake: filling a block is a signature a
/// transfer, and a full testnet block is seven hundred of them. The cap is
/// cut with the block so the two limits stand as they do on testnet, where a
/// full tier leaves a block 1 008 places, which outputs fill in about a third
/// of its bytes: here 240, in about a third of these. At the full 131 072
/// bytes the filler cost 1 300 215 pebbles a block, 0.78 CAIRN an hour of
/// sixty second blocks.
fn params() -> ConsensusParams {
    ConsensusParams {
        max_block_bytes: 32 * 1024,
        ..ConsensusParams::testnet()
            .with_coinbase_maturity(0)
            .with_place_price(PLACE_PRICE)
            .with_hot_capacity(2_048)
            .with_max_evictions(256)
    }
}

/// The outputs of each of the place buyer's splits: a hundred and twenty
/// places, so two of them take every place a full tier leaves a block.
const PLACE_BUYER_OUTPUTS: usize = 121;

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

fn cairn(pebbles: u64) -> f64 {
    pebbles as f64 / PEBBLES_PER_CAIRN as f64
}

/// One store, mined by a miner that takes what `selection` hands it, as
/// every node running this code does.
struct Chain {
    params: ConsensusParams,
    store: ChainStore,
    clock: u64,
    /// The seed of the key blocks are mined to.
    miner: u8,
}

impl Chain {
    fn new() -> Self {
        Self {
            params: params(),
            store: ChainStore::new(params()),
            clock: 1_000_000,
            miner: 99,
        }
    }

    fn now(&self) -> u64 {
        self.clock + 1
    }

    /// Mines `transfers` as they are, paying the coinbase to `to`.
    fn mine_these(&mut self, to: &SecretKey, transfers: Vec<Transfer>, fees: Amount) -> Block {
        let state = self.store.state();
        let height = state.next_height().unwrap();
        let reward = self.params.reward_at(height).checked_add(fees).unwrap();
        let outputs = (0..self.params.max_coinbase_outputs)
            .map(|at| {
                let share = reward.as_pebbles() / self.params.max_coinbase_outputs as u64;
                let value = if at == 0 {
                    reward.as_pebbles() - share * (self.params.max_coinbase_outputs as u64 - 1)
                } else {
                    share
                };
                Note::new(pebbles(value), to.public_key())
            })
            .collect();
        self.clock += 60;
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block =
            assemble_block(state, coinbase, transfers, &self.params, self.clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        self.store.add_block(block.clone(), self.now()).unwrap();
        block
    }

    /// Mines what the pool's own selection picks.
    fn mine_selection(&mut self) -> Block {
        let (transfers, fees) = self.store.selection(self.params.max_transfers_per_block);
        let miner = key(self.miner);
        self.mine_these(&miner, transfers, fees)
    }
}

/// Notes a block's coinbase paid `owner`.
fn paid(block: &Block, owner: &SecretKey) -> Vec<(NoteId, Note)> {
    block
        .coinbase
        .created_notes()
        .into_iter()
        .filter(|(_, note)| note.owner == Address::from(owner.public_key()))
        .collect()
}

/// Spends `note` into `outputs` notes back to its owner, leaving `fee`.
fn split(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    outputs: usize,
    fee: Amount,
) -> Transfer {
    let shared = note.value.as_pebbles() - fee.as_pebbles();
    let each = shared / outputs as u64;
    let notes = (0..outputs)
        .map(|at| {
            let value = if at == 0 {
                shared - each * (outputs as u64 - 1)
            } else {
                each
            };
            Note::new(pebbles(value), owner.public_key())
        })
        .collect();
    let mut transfer = Transfer::new(vec![Input::hot(id)], notes);
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

/// A transfer of one hot note into `outputs`, paying `times` its floor.
///
/// Built twice, because the fee is in the bytes it is charged on; the second
/// build is the size the first measured.
fn at_floor_times(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    outputs: usize,
    times: u64,
) -> Transfer {
    let probe = split(params, id, note, owner, outputs, pebbles(1));
    let floor = fee_floor(probe.encode().len(), places_taken(&probe, 1), params);
    split(
        params,
        id,
        note,
        owner,
        outputs,
        pebbles(floor.as_pebbles() * times),
    )
}

/// A payment of one hot note to somebody else, with change, at `times` its
/// floor: the shape almost every payment has.
fn payment(
    params: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    times: u64,
) -> Transfer {
    let build = |fee: u64| {
        let to_them = note.value.as_pebbles() / 2;
        let change = note.value.as_pebbles() - to_them - fee;
        let mut transfer = Transfer::new(
            vec![Input::hot(id)],
            vec![
                Note::new(pebbles(to_them), key(200).public_key()),
                Note::new(pebbles(change), owner.public_key()),
            ],
        );
        transfer.sign_input(params.network, 0, &note, owner);
        transfer
    };
    let probe = build(1);
    let floor = fee_floor(probe.encode().len(), places_taken(&probe, 1), params);
    build(floor.as_pebbles() * times)
}

fn fee_of(transfer: &Transfer, spent: &Note) -> u64 {
    spent.value.as_pebbles() - transfer.total_output().unwrap().as_pebbles()
}

/// The chain the spam and the payments run on, with a full tier: the spammer
/// holding `spam_notes` small hot notes and a coinbase's worth of large ones,
/// the payer `payer_notes`.
struct Funded {
    chain: Chain,
    small: Vec<(NoteId, Note)>,
    large: Vec<(NoteId, Note)>,
    purse: Vec<(NoteId, Note)>,
}

fn funded(spam_notes: usize, payer_notes: usize) -> Funded {
    let spammer = key(1);
    let payer = key(2);
    let mut chain = Chain::new();
    let params = chain.params;

    // Coinbases to the spammer, then as many of their notes as it takes
    // split in 256.
    let mut big = Vec::new();
    while big.len() * 256 < spam_notes {
        let block = chain.mine_these(&spammer, Vec::new(), Amount::ZERO);
        big.extend(paid(&block, &spammer));
    }
    big.truncate(spam_notes.div_ceil(256));
    let mut small = Vec::new();
    for chunk in big.chunks(3) {
        let splits: Vec<Transfer> = chunk
            .iter()
            .map(|(id, note)| at_floor_times(&params, *id, *note, &spammer, 256, 1))
            .collect();
        let block = chain.mine_these(&key(98), splits, Amount::ZERO);
        for transfer in &block.transfers {
            small.extend(transfer.created_notes());
        }
    }
    small.truncate(spam_notes);

    // A full tier, so a block has its eviction cap less the coinbase for the
    // places of its transfers and no room in the tier on top.
    while chain.store.state().hot_len() < params.hot_capacity {
        chain.mine_these(&key(97), Vec::new(), Amount::ZERO);
    }
    assert_eq!(
        chain.store.places_for_transfers(),
        params.max_evictions_per_block - params.max_coinbase_outputs
    );

    // After everything else, so the tier lets go of them last.
    let block = chain.mine_these(&spammer, Vec::new(), Amount::ZERO);
    let large = paid(&block, &spammer);
    let block = chain.mine_these(&payer, Vec::new(), Amount::ZERO);
    let mut purse = paid(&block, &payer);
    purse.truncate(payer_notes);
    Funded {
        chain,
        small,
        large,
        purse,
    }
}

/// What a run of blocks under spam came to.
#[derive(Debug)]
struct Watched {
    /// The block each payment was carried by, counted from one, if any.
    carried: Vec<Option<usize>>,
    /// What the spammer's transfers in those blocks paid, and burned.
    paid: u64,
    burned: u64,
    blocks: usize,
    /// Transfers the pool refused as needing more places than a block has.
    too_many_places: usize,
    /// The places the spammer's transfers took in each block.
    places: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spam {
    /// Hot notes spent back to the spammer, one in and one out: no place
    /// taken, so ten pebbles a unit of weight at the floor.
    Bytes,
    /// Hot notes split in [`PLACE_BUYER_OUTPUTS`] at the floor and the burn:
    /// every place the next block has.
    Places,
}

/// Keeps every block full of `spam` for `blocks` blocks, with `payments`
/// sent alongside the first.
fn under_spam(spam: Spam, blocks: usize, times: &[u64]) -> Watched {
    let spammer = key(1);
    let payer = key(2);
    let Funded {
        mut chain,
        small,
        large,
        purse,
    } = funded(600, times.len());
    let params = chain.params;
    let mut notes = match spam {
        Spam::Bytes => small,
        Spam::Places => large,
    };

    let payments: Vec<(Transfer, Note)> = purse
        .iter()
        .zip(times)
        .map(|((id, note), times)| (payment(&params, *id, *note, &payer, *times), *note))
        .collect();
    for (transfer, _) in &payments {
        assert_eq!(chain.store.accept_transfer(transfer.clone()), Ok(true));
    }
    let ids: Vec<Hash32> = payments.iter().map(|(transfer, _)| transfer.id()).collect();

    let mut watched = Watched {
        carried: vec![None; payments.len()],
        paid: 0,
        burned: 0,
        blocks,
        too_many_places: 0,
        places: Vec::new(),
    };
    let mut spending: std::collections::HashMap<Hash32, Note> = std::collections::HashMap::new();
    for number in 1..=blocks {
        // Top the pool up with what fills the next block and then some.
        let hot: BTreeSet<NoteId> = notes
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| chain.store.state().hot_note(id).is_some())
            .collect();
        let spoken_for: BTreeSet<NoteId> = chain
            .store
            .pooled_spenders()
            .map(|(note, _)| *note)
            .collect();
        for (id, note) in notes
            .iter()
            .filter(|(id, _)| hot.contains(id) && !spoken_for.contains(id))
        {
            // A split's own outputs are too small to pay another split's
            // burn, so only the notes it was funded with are split.
            if spam == Spam::Places && note.value.as_pebbles() < 100_000_000 {
                continue;
            }
            let transfer = match spam {
                Spam::Bytes => at_floor_times(&params, *id, *note, &spammer, 1, 1),
                Spam::Places => {
                    at_floor_times(&params, *id, *note, &spammer, PLACE_BUYER_OUTPUTS, 1)
                }
            };
            spending.insert(transfer.id(), *note);
            match chain.store.accept_transfer(transfer) {
                Ok(_) => {}
                Err(TransferError::TooManyPlacesForABlock { .. }) => watched.too_many_places += 1,
                Err(error) => panic!("the spam was refused: {error}"),
            }
        }

        let block = chain.mine_selection();
        let mut places = 0;
        for transfer in &block.transfers {
            if let Some(at) = ids.iter().position(|id| *id == transfer.id()) {
                watched.carried[at] = Some(number);
                continue;
            }
            let spent = spending[&transfer.id()];
            let fee = fee_of(transfer, &spent);
            // Every spam transfer spends one hot note.
            let taken = places_taken(transfer, 1);
            watched.paid += fee;
            watched.burned += params.burn_for(taken).unwrap().as_pebbles();
            places += taken;
            notes.extend(transfer.created_notes());
        }
        let spent: BTreeSet<NoteId> = block
            .transfers
            .iter()
            .flat_map(|transfer| transfer.inputs.iter().map(|input| input.note_id))
            .collect();
        notes.retain(|(id, _)| !spent.contains(id));
        watched.places.push(places);
    }
    watched
}

/// **A payment at twice its floor is carried by the next block through a
/// block kept full at the floor, and one at its floor is not carried at all.**
///
/// The catalogue's pass mark for R15, and the price of holding it: the
/// spammer pays ten pebbles a byte for every block, which goes to whoever
/// mines it, and burns nothing, since what it sends takes no place.
#[test]
fn a_payment_at_twice_its_floor_goes_through_filler_at_the_floor() {
    let watched = under_spam(Spam::Bytes, 6, &[1, 2, 5]);
    let per_block = watched.paid / watched.blocks as u64;
    println!(
        "\n  filler at the floor: payments at 1x, 2x and 5x their floor carried by blocks {:?}",
        watched.carried
    );
    println!(
        "  the spammer paid {per_block} pebbles a block ({:.4} CAIRN), burned {}, \
         {:.2} CAIRN an hour of sixty second blocks\n",
        cairn(per_block),
        watched.burned,
        cairn(per_block * 60)
    );
    assert_eq!(
        watched.carried[1],
        Some(1),
        "a payment at twice its floor waited behind filler paying the floor"
    );
    assert_eq!(watched.carried[2], Some(1));
    assert_eq!(
        watched.carried[0], None,
        "a payment at its floor ranks below filler at the floor, which takes no \
         place: the pool's order is by what a fee leaves per unit of weight"
    );
    assert_eq!(
        watched.burned, 0,
        "filler that takes no place burns nothing"
    );
    // Ten pebbles a byte of the room a block has for transfers, less what the
    // last transfer that would not fit leaves empty.
    let full = ChainStore::room_for_transfers(params().max_block_bytes) as u64 * MIN_FEE_PER_WEIGHT;
    assert!(
        per_block <= full && per_block * 100 > full * 95,
        "keeping a block full costs about ten pebbles a byte of it, {full}: {per_block}"
    );
}

/// **Buying every place at the floor holds up no payment.**
///
/// G12: a full tier leaves a block its eviction cap less the coinbase's
/// sixteen in new places, and a sender splitting notes at the floor and the
/// burn can ask for all of them, and gets them in every block nobody else
/// asks. It pays the burn on every one, and ranks below a payment at its own
/// floor, because a split's floor is mostly places the miner cannot keep and
/// its weight is mostly places: so the payments' places come out of the
/// spammer's, and the split that no longer fits waits.
#[test]
fn buying_every_place_at_the_floor_holds_up_no_payment() {
    let watched = under_spam(Spam::Places, 4, &[1, 2, 5]);
    let per_block = watched.paid / watched.blocks as u64;
    let burned = watched.burned / watched.blocks as u64;
    println!(
        "\n  places bought at the floor: payments at 1x, 2x and 5x their floor carried by blocks {:?}",
        watched.carried
    );
    println!(
        "  the spammer took {:?} places a block, paid {per_block} pebbles a block, of which \
         {burned} burned ({:.4} CAIRN a block)\n",
        watched.places,
        cairn(burned)
    );
    let every = params().max_evictions_per_block - params().max_coinbase_outputs;
    assert_eq!(watched.carried, vec![Some(1); 3]);
    assert_eq!(
        watched.too_many_places, 0,
        "no split of {PLACE_BUYER_OUTPUTS} outputs is past one block's places"
    );
    assert!(
        watched.places[1..].iter().all(|taken| *taken == every),
        "fixture: the spammer did not take every place of the blocks after the payments: {:?}",
        watched.places
    );
    assert!(
        watched.places[0] < every,
        "the payments were carried without taking any place the spammer asked for"
    );
}

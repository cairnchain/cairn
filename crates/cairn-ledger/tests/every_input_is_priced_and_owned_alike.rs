//! The three places a transfer is judged, the block, the pool's first look and
//! the pool's second look, agree on the price of its places and on whose key
//! may spend it, for every kind of input: a hot note, a note in the grace
//! window spent with the hot tag, the same note spent with its proof, and a
//! cold note past the window.
//!
//! For a note that has fallen, the comparison of the key an input carries with
//! the note's owner is the whole of what ties the two together: the signature
//! is verified under the input's own key, and the identifier leaves the key
//! out. Every test that asked `KeyNotOwner` spent a hot note, so a change that
//! asked it only of hot inputs would have let anyone spend any fallen note
//! with a key of their own, and passed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, BTreeSet};

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, check_transfer, check_transfer_again, connect_block, disconnect_block,
    evaluate_block_body, BlockError, ConsensusParams, TransferError,
};
use cairn_ledger::{Block, LedgerState};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const TIER: usize = 64;
const PRICE: u64 = 6_000;

fn rules() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(TIER)
        .with_max_evictions(8)
        .with_coinbase_maturity(0)
        .with_place_price(pebbles(PRICE))
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

fn count(many: usize) -> u64 {
    u64::try_from(many).unwrap()
}

/// A ledger that keeps the cold set, so a fallen note can be proven.
struct Bench {
    params: ConsensusParams,
    ledger: LedgerState,
    clock: u64,
}

impl Bench {
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

    /// A block paying its reward to `to` in `many` notes, and those notes.
    fn spread(&mut self, to: &SecretKey, many: usize) -> Vec<(NoteId, Note)> {
        let height = self.height();
        let reward = self.params.reward_at(height).as_pebbles();
        let each = reward / count(many);
        let first = reward - each * (count(many) - 1);
        let outputs: Vec<Note> = (0..many)
            .map(|at| Note::new(pebbles(if at == 0 { first } else { each }), to.public_key()))
            .collect();
        let block = self
            .assemble(
                CoinbaseTransaction::new(height, outputs.clone()),
                Vec::new(),
            )
            .unwrap();
        connect_block(&mut self.ledger, &block, &self.params, NOW).unwrap();
        (0u32..)
            .zip(outputs)
            .map(|(at, note)| (NoteId::new(block.coinbase.id(), at), note))
            .collect()
    }

    fn coinbase(&self, to: &SecretKey, claimed: u64) -> CoinbaseTransaction {
        CoinbaseTransaction::new(
            self.height(),
            vec![Note::new(pebbles(claimed), to.public_key())],
        )
    }
}

/// One input spending `spent` through `witness` into three outputs, `fee`
/// left behind, signed by `signer`, who need not be the owner.
fn spend(
    params: &ConsensusParams,
    spent: (NoteId, Note),
    witness: Input,
    signer: &SecretKey,
    fee: u64,
) -> Transfer {
    let shared = spent.1.value.as_pebbles() - fee;
    let each = shared / 3;
    let first = shared - 2 * each;
    let outputs = (0..3)
        .map(|at| {
            Note::new(
                pebbles(if at == 0 { first } else { each }),
                signer.public_key(),
            )
        })
        .collect();
    let mut transfer = Transfer::new(vec![witness], outputs);
    transfer.sign_input(params.network, 0, &spent.1, signer);
    transfer
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Valid { fee: Amount, burn: Amount },
    Refused(TransferError),
}

fn first_look(bench: &Bench, transfer: &Transfer) -> Verdict {
    let none = (BTreeSet::new(), BTreeMap::new());
    match check_transfer(transfer, &bench.ledger, &none.0, &none.1, &bench.params) {
        Ok(outcome) => Verdict::Valid {
            fee: outcome.fee,
            burn: outcome.burn,
        },
        Err(refusal) => Verdict::Refused(refusal),
    }
}

fn second_look(bench: &Bench, transfer: &Transfer) -> Verdict {
    let none = (BTreeSet::new(), BTreeMap::new());
    match check_transfer_again(transfer, &bench.ledger, &none.0, &none.1, &bench.params) {
        Ok(outcome) => Verdict::Valid {
            fee: outcome.fee,
            burn: outcome.burn,
        },
        Err(refusal) => Verdict::Refused(refusal),
    }
}

/// The block's verdict, with a coinbase claiming exactly what it may if the
/// transfer is what `expected` says.
fn in_a_block(
    bench: &Bench,
    miner: &SecretKey,
    transfer: &Transfer,
    expected: &Verdict,
) -> Verdict {
    let reward = bench.params.reward_at(bench.height()).as_pebbles();
    let claimable = match expected {
        Verdict::Valid { fee, burn } => fee.as_pebbles() - burn.as_pebbles(),
        Verdict::Refused(_) => 0,
    };
    let coinbase = bench.coinbase(miner, reward + claimable);
    match evaluate_block_body(
        &bench.ledger,
        &coinbase,
        std::slice::from_ref(transfer),
        &bench.params,
    ) {
        Ok(_) => match expected {
            Verdict::Valid { fee, burn } => Verdict::Valid {
                fee: *fee,
                burn: *burn,
            },
            Verdict::Refused(refusal) => {
                panic!("a block took a transfer the pool refuses as {refusal}")
            }
        },
        Err(BlockError::InvalidTransfer { index: 0, source }) => Verdict::Refused(source),
        Err(other) => {
            panic!("the block was refused for something other than its transfer: {other}")
        }
    }
}

/// Every kind of input pays for the places its transfer takes, and is spent
/// only by the key its note is paid to, on the block and on both of the
/// pool's looks.
///
/// The price is asked at exactly the burn and a pebble short. The key is
/// asked with a thief's own key and a signature that verifies under it, which
/// the block and the pool's first look refuse as `KeyNotOwner`; the second
/// look checks no key, by design, since everything it re-judges came in
/// through the first. Nothing asked the key of an input that was not hot, and
/// the price of a fallen one only through the first look.
#[test]
fn every_kind_of_input_is_priced_and_owned_the_same_on_every_path() {
    let params = rules();
    let (miner, owner, thief) = (key(1), key(2), key(3));
    let mut bench = Bench {
        params,
        ledger: LedgerState::archiving(),
        clock: 1_000_000,
    };

    // Fill the tier with the owner's notes, then push the oldest sixteen
    // into the grace window.
    let mut notes = Vec::new();
    while bench.ledger.hot_len() < TIER {
        notes.extend(bench.spread(&owner, params.max_coinbase_outputs));
    }
    bench.spread(&miner, 8);
    bench.spread(&miner, 8);
    let fallen: Vec<(NoteId, Note)> = notes
        .iter()
        .copied()
        .filter(|(id, _)| bench.ledger.hot_note(id).is_none())
        .collect();
    let hot = *notes
        .iter()
        .rev()
        .find(|(id, _)| bench.ledger.hot_note(id).is_some())
        .unwrap();
    let (graced, cold) = (fallen[0], fallen[1]);

    let (grace_position, _) = bench
        .ledger
        .within_grace(&graced.0)
        .expect("the premise: a note in the window");
    let grace_proof = bench.ledger.cold().prove(grace_position).unwrap();
    judge(
        &bench,
        &miner,
        &owner,
        &thief,
        vec![
            ("hot", hot, Input::hot(hot.0), 2),
            ("in the window, hot tag", graced, Input::hot(graced.0), 3),
            (
                "in the window, with its proof",
                graced,
                Input::cold(graced.0, graced.1, grace_position, grace_proof),
                3,
            ),
        ],
    );

    // The other fallen note walked out of the window, then spent cold.
    for _ in 0..2 * cairn_ledger::state::GRACE_BLOCKS {
        if bench.ledger.within_grace(&cold.0).is_none() {
            break;
        }
        let reward = bench.params.reward_at(bench.height()).as_pebbles();
        let coinbase = bench.coinbase(&miner, reward);
        let block = bench.assemble(coinbase, Vec::new()).unwrap();
        connect_block(&mut bench.ledger, &block, &bench.params, NOW).unwrap();
    }
    assert!(
        bench.ledger.within_grace(&cold.0).is_none(),
        "the premise: a note past the window"
    );
    let position = bench.ledger.cold().locate(&cold.0, &cold.1).unwrap();
    let proof = bench.ledger.cold().prove(position).unwrap();
    judge(
        &bench,
        &miner,
        &owner,
        &thief,
        vec![(
            "past the window",
            cold,
            Input::cold(cold.0, cold.1, position, proof),
            3,
        )],
    );
}

type Case = (&'static str, (NoteId, Note), Input, usize);

fn judge(bench: &Bench, miner: &SecretKey, owner: &SecretKey, thief: &SecretKey, cases: Vec<Case>) {
    let params = bench.params;
    for (kind, spent, witness, places) in cases {
        let burn = PRICE * count(places);
        for fee in [burn, burn - 1] {
            let transfer = spend(&params, spent, witness.clone(), owner, fee);
            let expected = if fee >= burn {
                Verdict::Valid {
                    fee: pebbles(fee),
                    burn: pebbles(burn),
                }
            } else {
                Verdict::Refused(TransferError::PlacesUnpaid {
                    places,
                    burn: pebbles(burn),
                    fee: pebbles(fee),
                })
            };
            assert_eq!(
                first_look(bench, &transfer),
                expected,
                "an input {kind} is priced otherwise by the pool's first look"
            );
            assert_eq!(
                second_look(bench, &transfer),
                expected,
                "an input {kind} is priced otherwise by the pool's second look"
            );
            assert_eq!(
                in_a_block(bench, miner, &transfer, &expected),
                expected,
                "an input {kind} is priced otherwise by the block"
            );
        }

        let stolen = spend(&params, spent, witness, thief, burn);
        let refused = Verdict::Refused(TransferError::KeyNotOwner { input_index: 0 });
        assert_eq!(
            first_look(bench, &stolen),
            refused,
            "a thief's own key spent an input {kind} past the pool's first look"
        );
        assert_eq!(
            in_a_block(bench, miner, &stolen, &refused),
            refused,
            "a thief's own key spent an input {kind} in a block"
        );
    }
}

/// A block that burns leaves the supply lower by the burn, a coinbase that
/// claims the burn back is refused, and undoing the block puts the supply
/// and the state root back where they were.
///
/// The burn lives only in the supply, so an undo that forgot it would leave
/// the supply short with every note restored, and nothing asked.
#[test]
fn a_block_that_burns_lowers_the_supply_by_the_burn_and_its_undo_restores_it() {
    let params = rules();
    let (miner, owner) = (key(1), key(2));
    let mut bench = Bench {
        params,
        ledger: LedgerState::archiving(),
        clock: 1_000_000,
    };
    bench.spread(&miner, 1);
    let fresh = bench.spread(&owner, 4)[0];
    let reward = bench.params.reward_at(bench.height()).as_pebbles();
    let paying = spend(&params, fresh, Input::hot(fresh.0), &owner, 2 * PRICE + 777);
    let supply = bench.ledger.supply();
    let root = bench.ledger.state_root();

    let greedy = bench.coinbase(&miner, reward + 777 + 1);
    assert!(
        matches!(
            bench.assemble(greedy, vec![paying.clone()]),
            Err(BlockError::CoinbaseOverpay { .. })
        ),
        "a coinbase claiming a pebble of the burn was taken"
    );
    let honest = bench.coinbase(&miner, reward + 777);
    let block = bench.assemble(honest, vec![paying]).unwrap();
    let connected = connect_block(&mut bench.ledger, &block, &bench.params, NOW).unwrap();
    assert_eq!(
        bench.ledger.supply().as_pebbles(),
        supply.as_pebbles() + reward - 2 * PRICE,
        "the supply did not fall by the burn"
    );
    disconnect_block(&mut bench.ledger, &connected);
    assert_eq!(bench.ledger.supply(), supply, "undo left the supply moved");
    assert_eq!(bench.ledger.state_root(), root, "undo left the root moved");
}

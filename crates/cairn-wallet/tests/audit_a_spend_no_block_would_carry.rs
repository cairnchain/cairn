//! A spend that gathers more notes than a block has room for.
//!
//! The rules cap a transfer at 256 inputs and a block at its byte limit, and
//! the two caps are not the same cap. A wallet whose money sits in many small
//! notes reaches the byte one first: each input carries a note identifier and
//! a signature, and a fallen note carries its own proof as well, which is
//! kilobytes rather than bytes.
//!
//! The wallet refuses such a spend itself rather than handing it to the
//! network and passing back the refusal. That is not politeness: the network's
//! answer names a rule nobody outside the protocol has heard of, and it comes
//! back after the person has been told their payment was sent.
//!
//! The guard had never been held by a test, because reaching it under the real
//! rules takes a wallet holding a hundred and twenty eight kilobytes of notes.
//! `with_max_block_bytes` brings it within reach, the way `with_burial` and
//! `with_coinbase_maturity` bring their own rules within reach.
//!
//! Then it was held by the wrong test. It asked whether the refusal named the
//! block's byte limit, which was the constant the guard was written against,
//! so the assertion and the code it checked were the same sentence twice. What
//! it never asked was the question the guard exists for: whether a miner would
//! carry the largest spend the wallet lets through. It would not. A block sets
//! aside room for its header and its coinbase, so what it carries in transfers
//! is that much less than how big it is, and every gather between the two was
//! accepted here, had its notes committed, was answered with "a block will
//! take a few minutes", and was then passed over by every miner that read the
//! pool. One more note adds about a hundred bytes and the gap was four
//! thousand, so the first gather to cross what a block carries was always
//! inside a whole block: the refusal could not fire on the spend it was
//! written for.
//!
//! The question is asked of the pool now, by the same call a miner makes.
//!
//! The gap is nine hundred and eight bytes rather than four thousand since
//! `accept_transfer` was made to read the same subtraction: a margin only a
//! miner reads may be generous, and one the pool reads may not, because a
//! margin larger than what it stands for is a band of transfers refused that
//! a block would have carried. Both tests below found that out for themselves
//! by saying their sweep no longer reached the guard, which is the whole
//! reason the sweep counts what it refused.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;
use cairn_wallet::{Wallet, WalletError};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Small enough that a spend gathering a few dozen ordinary notes passes what
/// a block of this size carries, and comfortably larger than the blocks this
/// test mines. It has to clear the room a block sets aside for everything that
/// is not a transfer, or there would be nothing a block could carry at all.
///
/// It was twelve kilobytes, which put the boundary at about eighty gathered
/// notes while this wallet holds ninety six. When the reserve went from four
/// thousand and ninety six bytes to the nine hundred and eight a block
/// actually spends, the boundary moved past everything the sweep could gather
/// and both tests here said so rather than passing. Five kilobytes puts it
/// back around forty, with the mined blocks of this chain at under nine
/// hundred, so neither end is near it.
const BLOCK_BYTES: usize = 5_120;

/// Blocks paying this key, several notes to a block.
const BLOCKS: usize = 6;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_max_block_bytes(BLOCK_BYTES)
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-bulky-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// A chain paying this key as many notes a block as a coinbase may carry.
fn a_chain(to: &SecretKey) -> (Vec<Block>, Amount) {
    let rules = params();
    let per_block = rules.max_coinbase_outputs;
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut blocks = Vec::new();
    let mut paid = Amount::ZERO;

    let each = rules.initial_reward.as_pebbles() / per_block as u64;
    let first = rules.initial_reward.as_pebbles() - each * (per_block as u64 - 1);

    for _ in 0..BLOCKS {
        let outputs: Vec<Note> = (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(Amount::from_pebbles(value).unwrap(), to.public_key())
            })
            .collect();
        for note in &outputs {
            paid = paid.checked_add(note.value).unwrap();
        }

        let height = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(height, outputs);
        let block =
            assemble_block(&state, coinbase, Vec::<Transfer>::new(), &rules, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &rules, NOW).unwrap();
        blocks.push(block);
    }
    (blocks, paid)
}

/// A spend no block would carry is refused here, with the numbers on it.
#[test]
fn a_spend_that_no_block_could_carry_is_refused_by_the_wallet() {
    let rules = params();
    let mine = SecretKey::from_bytes(&[3; 32]);
    let payee = SecretKey::from_bytes(&[9; 32]);
    let (chain, paid) = a_chain(&mine);

    let directory = scratch("no-room");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &mine).unwrap();

    let (wallet, _) = Wallet::open(&key_file, rules, &directory.join("data")).unwrap();
    for block in &chain {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    wallet.follow_to_the_tip();

    let holdings = wallet.holdings();
    assert!(
        holdings.notes.len() > 64,
        "this test needs a wallet holding many small notes, and it holds {}",
        holdings.notes.len()
    );
    assert!(
        holdings.notes.len() < rules.max_inputs_per_transfer,
        "and it needs the byte limit to be the one that bites, not the input \
         count: {} notes against a cap of {}",
        holdings.notes.len(),
        rules.max_inputs_per_transfer
    );

    // Nearly everything this key holds, which no one note can pay for, so the
    // spend has to gather most of them.
    let fee = Amount::from_pebbles(100_000).unwrap();
    let asking = paid
        .checked_sub(fee)
        .unwrap()
        .checked_sub(Amount::from_pebbles(1_000_000).unwrap())
        .unwrap();

    match wallet.send(payee.public_key(), asking, fee) {
        Err(WalletError::TooBulky {
            notes,
            bytes,
            limit,
        }) => {
            assert!(
                bytes > limit,
                "refused for being too large at {bytes} bytes against a limit of {limit}"
            );
            assert_eq!(
                limit,
                ChainStore::room_for_transfers(BLOCK_BYTES),
                "the limit named is what a block carries"
            );
            assert!(
                limit < BLOCK_BYTES,
                "this test proves nothing unless the two limits differ: a block of \
                 {BLOCK_BYTES} bytes carries {limit} of transfers"
            );
            assert!(
                notes > 1,
                "a refusal that names one note does not tell anybody why"
            );
            // The refusal has to be readable by whoever is holding the wallet,
            // because they are the only one who can do anything about it, and
            // what they can do is send it in pieces.
            let said = WalletError::TooBulky {
                notes,
                bytes,
                limit,
            }
            .to_string();
            assert!(said.contains("Send a smaller amount"), "{said}");
        }
        Err(other) => panic!("refused for the wrong reason: {other}"),
        Ok(_) => panic!(
            "a spend gathering {} notes was handed to the network, which will refuse it for \
             a rule the person holding this wallet has never heard of, after they were told \
             it had been sent",
            holdings.notes.len()
        ),
    }

    let _ = std::fs::remove_dir_all(&directory);
}

/// How many amounts the sweep below asks for, across everything the key holds.
const STEPS: usize = 10;

/// A fresh wallet holding an already mined chain.
fn a_wallet_holding(chain: &[Block], mine: &SecretKey, name: &str) -> (Wallet, PathBuf) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, mine).unwrap();
    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
    for block in chain {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    wallet.follow_to_the_tip();
    (wallet, directory)
}

/// Every spend this wallet accepts is one a miner would carry.
///
/// Asked of the pool by the same call a miner makes, rather than of a
/// constant. The defect was a band and not a point: spends under what a block
/// carries were accepted and carried, spends over a whole block were refused,
/// and everything between the two was accepted, had its notes committed, and
/// was never chosen by anybody. One reading taken anywhere outside that band
/// says nothing at all about it, which is why this sweeps.
#[test]
fn every_spend_the_wallet_accepts_is_one_a_block_would_carry() {
    let rules = params();
    let mine = SecretKey::from_bytes(&[3; 32]);
    let payee = SecretKey::from_bytes(&[9; 32]);
    let (chain, paid) = a_chain(&mine);

    let fee = Amount::from_pebbles(100_000).unwrap();
    let most = paid.checked_sub(fee).unwrap().as_pebbles();

    let mut accepted = 0usize;
    let mut refused = 0usize;
    let mut widest = 0usize;

    for step in 1..=STEPS {
        let asking = Amount::from_pebbles(most / STEPS as u64 * step as u64).unwrap();
        let (wallet, directory) = a_wallet_holding(&chain, &mine, &format!("carry-{step}"));

        let outcome = wallet.send(payee.public_key(), asking, fee);
        let chosen = wallet
            .node()
            .with_chain(|held| held.selection(rules.max_transfers_per_block).0);
        let _ = std::fs::remove_dir_all(&directory);

        match outcome {
            Ok(sent) => {
                accepted = accepted.saturating_add(1);
                widest = widest.max(sent.notes);
                assert!(
                    chosen.iter().any(|transfer| transfer.id() == sent.id),
                    "the wallet accepted a spend gathering {} notes, committed them, and told \
                     whoever sent it that a block would take a few minutes. No miner reading \
                     this pool chooses it: a block of {BLOCK_BYTES} bytes carries {} of \
                     transfers.",
                    sent.notes,
                    ChainStore::room_for_transfers(BLOCK_BYTES)
                );
            }
            Err(WalletError::TooBulky { .. }) => refused = refused.saturating_add(1),
            Err(other) => panic!("refused for the wrong reason: {other}"),
        }
    }

    assert!(
        accepted > 0,
        "the sweep never got a spend past the wallet, so it held nothing to a miner"
    );
    assert!(
        refused > 0,
        "the sweep never reached a spend too large to carry, so the guard under test was \
         never asked anything: the largest gather was {widest} notes"
    );
}

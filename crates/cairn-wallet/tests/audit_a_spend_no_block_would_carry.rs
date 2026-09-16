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

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

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

/// Small enough that a spend gathering a few dozen ordinary notes passes it,
/// and comfortably larger than the blocks this test mines.
const BLOCK_BYTES: usize = 4096;

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
    while wallet.follow() > 0 {}

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
            assert_eq!(limit, BLOCK_BYTES, "the limit named is the block's own");
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

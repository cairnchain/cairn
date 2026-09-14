//! A pool that would not take the transfer, and a wallet that said it had.
//!
//! `submit_transaction` answers `Ok(false)` for the two refusals that are not
//! failures: a pool already holding this identifier, and a full pool that
//! would rather keep what it has. Both leave nothing pooled and nothing
//! broadcast. Read as success, the wallet reports a payment the network never
//! took, and the note in `send` says what that costs: it is how somebody hands
//! over two things for one payment.
//!
//! The guard that reads the answer had no test. Deleted, the whole suite
//! passes: every test that reaches `send` reaches it with room in the pool, so
//! the answer is always true and the arm that reads it never runs.

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
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;
use cairn_wallet::{Wallet, WalletError};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Enough coinbase notes to fill the pool by count and a few over, paid
/// sixteen to a block.
///
/// By count rather than by size, because a pool full by size still has room
/// for something small and the wallet's own spend is the smallest thing there
/// is: one note in, one note and its change out. `MAX_POOLED` is 4096, and it
/// is what a newcomer has to outbid somebody to get past.
const FILLERS: usize = 4_160;
/// Outputs apiece. One, so that a filler is small and the pool fills by count
/// with room to spare in its four megabytes.
const SPREAD: usize = 1;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-refusal-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn pebbles(count: u64) -> Amount {
    Amount::from_pebbles(count).unwrap()
}

/// A chain paying `stranger` sixteen notes a block until there are `FILLERS`
/// of them, and then one block paying `mine`.
fn a_chain(
    stranger: &cairn_crypto::PublicKey,
    mine: &cairn_crypto::PublicKey,
) -> (Vec<Block>, Vec<(NoteId, Note)>) {
    let rules = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let per_block = rules.max_coinbase_outputs;
    let each = rules.initial_reward.as_pebbles() / per_block as u64;
    let first = rules.initial_reward.as_pebbles() - each * (per_block as u64 - 1);

    let mut blocks = Vec::new();
    let mut notes = Vec::new();
    let mine_one = |state: &mut LedgerState, clock: &mut u64, outputs: Vec<Note>| {
        let height = state.next_height().unwrap();
        *clock += 600;
        let coinbase = CoinbaseTransaction::new(height, outputs.clone());
        let block =
            assemble_block(state, coinbase, Vec::<Transfer>::new(), &rules, *clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(state, &block, &rules, NOW).unwrap();
        (block, outputs)
    };

    while notes.len() < FILLERS {
        let outputs: Vec<Note> = (0..per_block)
            .map(|index| {
                let value = if index == 0 { first } else { each };
                Note::new(Amount::from_pebbles(value).unwrap(), *stranger)
            })
            .collect();
        let (block, outputs) = mine_one(&mut state, &mut clock, outputs);
        for (index, note) in outputs.into_iter().enumerate() {
            notes.push((
                NoteId::new(block.coinbase.id(), u32::try_from(index).unwrap()),
                note,
            ));
        }
        blocks.push(block);
    }

    let (block, _) = mine_one(
        &mut state,
        &mut clock,
        vec![Note::new(rules.initial_reward, *mine)],
    );
    blocks.push(block);
    (blocks, notes)
}

/// One note spread over `SPREAD` outputs, paying `fee`.
fn a_wide_spend(
    rules: &ConsensusParams,
    id: NoteId,
    note: Note,
    owner: &SecretKey,
    to: &cairn_crypto::PublicKey,
    fee: Amount,
) -> Transfer {
    let shared = note.value.as_pebbles() - fee.as_pebbles();
    let each = shared / SPREAD as u64;
    let first = shared - each * (SPREAD as u64 - 1);
    let outputs: Vec<Note> = (0..SPREAD)
        .map(|index| {
            let value = if index == 0 { first } else { each };
            Note::new(Amount::from_pebbles(value).unwrap(), *to)
        })
        .collect();
    debug_assert_eq!(outputs.len(), SPREAD);
    let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
    transfer.sign_input(rules.network, 0, &note, owner);
    transfer
}

#[test]
fn a_pool_with_no_room_is_not_a_payment_the_network_took() {
    let directory = scratch("no-room");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[7; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");

    let stranger = SecretKey::from_bytes(&[8; 32]);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    let rules = params();
    let (chain, theirs) = a_chain(&stranger.public_key(), &secret.public_key());

    let (wallet, _) = Wallet::open(&key_file, rules, &data).unwrap();
    for block in chain {
        wallet.node().submit_block(block).unwrap();
    }
    while wallet.follow() > 0 {}
    assert!(
        wallet.holdings().spendable > Amount::ZERO,
        "the wallet was meant to have something to send"
    );

    // Strangers fill the pool, each paying far more than the floor, so what
    // the wallet offers below cannot buy anybody's place.
    let mut pooled = 0usize;
    let mut refused = false;
    for (id, note) in theirs {
        // Everything but a pebble an output, which is the best rate a note
        // this size can offer. What the wallet offers below is the floor, so
        // it cannot buy any of these places.
        let fee = pebbles(note.value.as_pebbles() - SPREAD as u64);
        let filler = a_wide_spend(&rules, id, note, &stranger, &recipient, fee);
        match wallet.node().submit_transaction(filler) {
            Ok(true) => pooled += 1,
            Ok(false) => {
                refused = true;
                break;
            }
            Err(_) => break,
        }
    }
    assert!(
        refused,
        "the pool took all {pooled} fillers and never filled, so this run measured nothing"
    );

    // And now the wallet's own, paying the least the rules allow, into a pool
    // that would rather keep what it has.
    let sent = wallet.send(recipient, pebbles(1), pebbles(1_000));
    match sent {
        Err(WalletError::NoRoom) => {}
        Err(WalletError::FeeTooLow { needed }) => {
            let sent = wallet.send(recipient, pebbles(1), needed);
            assert!(
                matches!(sent, Err(WalletError::NoRoom)),
                "a pool with no room answered {sent:?}, and the wallet has to say so rather than \
                 report a payment the network never took"
            );
        }
        other => panic!(
            "a pool with no room answered {other:?}, and the wallet has to say so rather than \
             report a payment the network never took"
        ),
    }

    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

//! The refusal this wallet gives before the network can.
//!
//! `spend` turns a fee under the floor away itself, with a paragraph saying
//! why: the network refuses it anyway, and a refusal fetched back from a pool
//! the sender cannot see is worse than one said here.
//!
//! Nothing measured it. Delete the guard and the suite passes, because the
//! node refuses too. What it refuses with is this:
//!
//! ```text
//! Err(Refused("the network asks 0.00007030 CAIRN to carry this payment and
//! this one pays less, so nothing was sent. Send it again paying that."))
//! ```
//!
//! Which is worth reading, because it weakens the comment's own account. The
//! node's words do carry the number. What the guard buys is narrower than
//! "the refusal comes back without the number", and still worth having: a
//! `FeeTooLow { needed }` is a refusal a program can act on where a sentence
//! is one only a person can read, and the wallet's own faces are programs. And
//! it is reached before the transfer is signed and before anything is handed
//! to the network, so a doomed payment costs neither signatures nor a round
//! trip.
//!
//! So what is asserted is which refusal comes back, and not merely that one
//! did. That is the only thing that tells the two apart.
//!
//! `TooBulky`, the other refusal `spend` gives for the same stated reason, is
//! **not held here**. It needs a draft past `max_block_bytes`, which is 128
//! kilobytes, and a transfer reaches that only through hundreds of fallen
//! notes each travelling with its own proof: the proofs are what make it
//! large, and they are only long once the cold set holds tens of thousands of
//! leaves. Holding it needs either that chain or a way to ask for a smaller
//! `max_block_bytes`, the way tests already ask for a smaller burial and a
//! smaller hot set.
//!
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

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-refusals-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

fn a_block_paying(state: &mut LedgerState, clock: &mut u64, to: &cairn_crypto::PublicKey) -> Block {
    let rules = params();
    let height = state.next_height().unwrap();
    *clock += 600;
    let coinbase = CoinbaseTransaction::new(height, vec![Note::new(rules.initial_reward, *to)]);
    let block = assemble_block(state, coinbase, Vec::<Transfer>::new(), &rules, *clock, 0).unwrap();
    let block = mine_block(block, ATTEMPTS).unwrap();
    connect_block(state, &block, &rules, NOW).unwrap();
    block
}

/// A wallet holding `blocks` rewards.
fn funded(name: &str, blocks: usize) -> (Wallet, PathBuf) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[6; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    for _ in 0..blocks {
        let block = a_block_paying(&mut state, &mut clock, &secret.public_key());
        wallet.node().submit_block(block).unwrap();
    }
    (wallet, directory)
}

/// A fee a pebble under what the network carries.
///
/// The wallet knows the floor: it prices the draft to work it out, and it
/// answers `floor_for` with it. So the refusal it gives names the number that
/// would have worked, where the node's is about a rule and a weight the sender
/// never saw.
#[test]
fn a_fee_under_the_floor_is_refused_with_the_floor() {
    let (wallet, directory) = funded("fee", 4);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    let amount = cairn("10");

    let floor = wallet.floor_for(recipient, amount);
    assert!(
        floor > Amount::ZERO,
        "the floor under this spend is nothing"
    );
    let under = Amount::from_pebbles(floor.as_pebbles() - 1).unwrap();

    let refused = wallet.send(recipient, amount, under);
    assert!(
        matches!(refused, Err(WalletError::FeeTooLow { needed }) if needed == floor),
        "a fee under the floor came back as something other than the floor: {refused:?}"
    );

    // And nothing was handed over on the way to saying so.
    assert!(
        wallet.waiting().is_empty(),
        "a transfer the wallet refused is waiting in its pool"
    );

    // The contrast, so this is a floor and not a wall: the floor itself is
    // taken.
    let sent = wallet.send(recipient, amount, floor);
    assert!(
        sent.is_ok(),
        "the floor the wallet quoted is not a fee it accepts: {sent:?}"
    );

    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

/// And the wallet's own quote is one it accepts at every size it quotes for.
///
/// Held beside the test above because a wallet that quoted a floor it would
/// then refuse would pass that one: the refusal would name a number, and the
/// number would be wrong.
#[test]
fn every_floor_the_wallet_quotes_is_a_fee_it_takes() {
    let (wallet, directory) = funded("quotes", 6);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    for whole in [1u64, 5, 25, 100] {
        let amount = Amount::from_cairn(&whole.to_string()).unwrap();
        let floor = wallet.floor_for(recipient, amount);
        let under = Amount::from_pebbles(floor.as_pebbles() - 1).unwrap();
        let refused = wallet.send(recipient, amount, under);
        assert!(
            matches!(refused, Err(WalletError::FeeTooLow { needed }) if needed == floor),
            "sending {amount} a pebble under its own quote was not refused for the quote: \
             {refused:?}"
        );
    }

    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

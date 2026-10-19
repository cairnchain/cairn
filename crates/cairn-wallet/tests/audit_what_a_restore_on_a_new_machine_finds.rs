//! What a wallet restored from its key alone, on a machine that never ran it,
//! finds of its money.
//!
//! The case a recovery phrase is for: the computer is gone, the twenty four
//! words are not, and the person types them into a wallet on a new machine.
//! What comes back from them is the key and nothing else. There is no
//! history.dat, because the account lived on the lost disk, and there is no
//! chain, because the new data directory is empty. The wallet joins the
//! network the way any newcomer does, and on a chain longer than
//! `JOIN_RATHER_THAN_READ` that means being handed a ledger rather than
//! reading every block.
//!
//! So the money falls into three parts, and these tests fix which of them
//! comes back. A note still in the set every node holds is in the ledger the
//! wallet was handed, filed under its owner, and comes back. A note that fell
//! inside the window a handed ledger carries comes back with its place,
//! because every node keeps those. A note that fell before that window sits in
//! the cold set as a hash with no owner attached, and the only record of where
//! it sits was the account on the lost disk: it does not come back, from this
//! wallet's own node or from anywhere it asks, an archivist included.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::sync::JOIN_RATHER_THAN_READ;
use cairn_net::Node;
use cairn_primitives::Amount;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The opening run, one block in three paying this key.
const DEEP: usize = 30;

/// Blocks to a stranger after it.
///
/// Far more than `cairn_ledger::state::GRACE_BLOCKS`, so that what the opening
/// run paid fell long before any window a ledger handed out at the end
/// carries. And enough to make the chain one a newcomer is handed a ledger
/// for rather than one it reads from the first block, which testnet-8 passed
/// in its first days.
const PAST_THE_WINDOW: usize = JOIN_RATHER_THAN_READ as usize + 100;

/// Blocks to a stranger after the one payment that falls inside the window:
/// enough for it to fall out of a hot set of four, and few enough, with the
/// burial on top, that it fell inside the last `GRACE_BLOCKS` below the
/// height the ledger a newcomer is handed was written at.
const AFTER_THE_WINDOW_PAYMENT: usize = 30;

/// Shallow wherever a number chosen for a live network would only cost mining,
/// and a hot set small enough that notes reach the cold set in a few blocks.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-new-machine-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(300);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, to: &cairn_crypto::PublicKey) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(self.params.initial_reward, *to)]);
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }
}

/// Ten payments deep in the cold set, one inside the window, one in the hot set.
fn a_chain_that_paid_this_key_in_all_three_places(mine: &cairn_crypto::PublicKey) -> Vec<Block> {
    let stranger = SecretKey::from_bytes(&[11; 32]).public_key();
    let mut forge = Forge::new();
    let mut blocks = Vec::new();
    for at in 0..DEEP {
        blocks.push(forge.mine(if at % 3 == 0 { mine } else { &stranger }));
    }
    for _ in 0..PAST_THE_WINDOW {
        blocks.push(forge.mine(&stranger));
    }
    blocks.push(forge.mine(mine));
    for _ in 0..AFTER_THE_WINDOW_PAYMENT {
        blocks.push(forge.mine(&stranger));
    }
    // And the last block pays this key, so its note is still in the hot set.
    blocks.push(forge.mine(mine));
    blocks
}

fn reward() -> Amount {
    params().initial_reward
}

fn times(amount: Amount, count: u64) -> Amount {
    Amount::from_pebbles(amount.as_pebbles() * count).unwrap()
}

/// **A wallet restored on a new machine finds what is in the hot set and in
/// the window, and nothing of what fell before it.**
///
/// The comparison is the same key on two machines. The first read every block
/// as it came and holds all twelve payments, the ten deep ones among them.
/// The second starts with the key and an empty data directory, joins the
/// network from a node that kept everything, an archivist, and is handed a
/// ledger, as a new machine on testnet-8 is. It finds two of the twelve: the
/// payment in the hot set and the one that fell inside the window. The ten
/// that fell before the window are still this key's and still unspent on the
/// chain, and nothing this wallet can do today names them.
#[test]
fn a_restore_on_a_new_machine_finds_the_hot_set_and_the_window_and_nothing_older() {
    let directory = scratch("three-places");
    std::fs::create_dir_all(&directory).unwrap();
    let secret = SecretKey::from_bytes(&[3; 32]);
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let blocks = a_chain_that_paid_this_key_in_all_three_places(&secret.public_key());
    let tip = (blocks.len() - 1) as u64;
    let deep_payments = DEEP.div_ceil(3) as u64;
    let window_payment_at = (DEEP + PAST_THE_WINDOW) as u64;

    // The machine that was lost: it read every block, and knows all of it.
    let whole = {
        let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("old")).unwrap();
        for block in &blocks {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        wallet.follow_to_the_tip();
        let total = wallet.holdings().total();
        wallet.shutdown();
        total
    };
    assert_eq!(
        whole,
        times(reward(), deep_payments + 2),
        "fixture: the machine that read every block holds every payment"
    );

    // Somebody who kept every block and every leaf of the cold set.
    let (keeper, _) =
        Node::open_archiving(params(), loopback(), directory.join("keeper")).unwrap();
    for block in &blocks {
        keeper.submit_block(block.clone()).unwrap();
    }

    // The new machine: the same key, an empty data directory, no account.
    let fresh = directory.join("fresh");
    let (wallet, _) = Wallet::open(&key_file, params(), &fresh).unwrap();
    assert!(!fresh.join("history.dat").exists(), "fixture: no account");
    assert!(wallet.reach(keeper.address()));
    wait_for("the new machine to reach the tip", || {
        wallet.node().height() == Some(tip)
    });
    wallet.follow_to_the_tip();
    // The first block this machine holds, which on a node handed a ledger is
    // the one after the height the ledger was written at.
    let first_held = wallet.node().blocks_from();
    assert!(
        first_held.is_some_and(|first| first > window_payment_at),
        "fixture: the new machine was handed a ledger written above every payment but the \
         last, as a newcomer on a long chain is, rather than reading from the first block \
         (its first block is {first_held:?})"
    );

    let holdings = wallet.holdings();
    let found = holdings.total();
    // Asked of the archivist as well, which is the only peer that could know.
    wait_for("the archivist to say what it keeps", || {
        wallet.node().archiving_peers() >= 1
    });
    let asked = wallet.recover_stranded();
    let after_asking = wallet.holdings().total();
    wallet.shutdown();
    keeper.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        found,
        times(reward(), 2),
        "a wallet restored on a new machine finds the note in the hot set and the one that \
         fell inside the window the handed ledger carries, and those two only"
    );
    assert_eq!(
        holdings.stranded,
        Amount::ZERO,
        "the two it finds it can spend: the window's places travel in the ledger"
    );
    assert_eq!(
        asked.stranded, 0,
        "the ten older payments are not even stranded, which is a state a wallet can ask \
         about: it does not know they exist"
    );
    assert_eq!(
        after_asking, found,
        "and an archivist connected and asked changes nothing, because it answers about a \
         place and the places were in the account on the lost disk"
    );
    assert_eq!(
        whole.as_pebbles() - found.as_pebbles(),
        times(reward(), deep_payments).as_pebbles(),
        "what is lost is exactly the payments that fell before the window"
    );
}

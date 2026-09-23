//! What starting over throws away that the chain cannot give back.
//!
//! `forget` is the whole of the wallet's answer to a reorganisation, and its
//! justification is this sentence: "reading the chain again is what the file
//! exists to be cheaper than, not a thing that cannot be done." True of the
//! movements, and true of `held` while the blocks are still on the disk. The
//! account keeps a third thing, `fell`: where each of this key's fallen notes
//! landed, "fixed the moment a note falls and never moves again", and the one
//! handle an archivist can be asked by. Its only source is the node's own
//! watch list, which a node restarted from a written ledger comes back
//! without. So on such a node the file is the only record of the places, and
//! `forget` wipes it and writes the wiped file to disk in the same call. And
//! on such a node the blocks below the ledger are not readable either, so
//! `held` is not rebuilt from them: the notes leave the account, and with it
//! the balance.
//!
//! The question `forget` answers is whether the account can be rebuilt from
//! the chain. The question the money needed answered is whether everything
//! the account holds can be. Two shapes of the ordinary restart are run: one
//! where the node wrote its ledger and stopped, which is what a machine that
//! stops between writing the ledger and trimming leaves, and one where it
//! trimmed the blocks below the ledger as well, which is what `trim_history`
//! does in one go.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::Amount;
use cairn_wallet::history::History;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Blocks read before the ledger is written down: heights `0..=LEDGER_AT`.
const LEDGER_AT: u64 = 90;
/// Blocks read after the restart, up to and including the one the
/// reorganisation will replace: heights `LEDGER_AT + 1..=REPLACED`.
const REPLACED: u64 = 98;

/// The recovery suite's own numbers, so this measures the same machinery.
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
        "cairn-forgetting-{name}-{}-{:?}",
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

fn catch_the_history_up(wallet: &Wallet) {
    wallet.follow_to_the_tip();
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

    fn fork(&self) -> Self {
        Self {
            params: self.params,
            state: self.state.clone(),
            clock: self.clock,
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
            Vec::<Transfer>::new(),
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

/// How many of the account's held notes carry a place, read off the file.
fn places_on_disk(data: &std::path::Path) -> (usize, usize) {
    let (history, why) = History::load(&data.join("history.dat"));
    assert_eq!(why, None, "the account read back");
    let held = history.held().count();
    let placed = history
        .held()
        .filter(|(id, _)| history.where_it_fell(id).is_some())
        .count();
    (held, placed)
}

fn one_block_reorganisation_after_a_restart(name: &str, trimmed: bool) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[3; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");
    let mine = secret.public_key();
    let stranger = SecretKey::from_bytes(&[11; 32]).public_key();
    let other = SecretKey::from_bytes(&[12; 32]).public_key();

    // The chain: every block pays this key up to the one that will be
    // replaced, so the account holds many fallen notes.
    let mut forge = Forge::new();
    let below: Vec<Block> = (0..=LEDGER_AT).map(|_| forge.mine(&mine)).collect();
    let above: Vec<Block> = (LEDGER_AT + 1..REPLACED)
        .map(|_| forge.mine(&mine))
        .collect();
    let mut rival = forge.fork();
    let a_top = forge.mine(&stranger);
    // Two blocks against one, paying somebody else so they are not the same
    // block: heavier, and a one block reorganisation at the tip.
    let b_top = rival.mine(&other);
    let b_next = rival.mine(&other);

    // Somebody who kept every leaf, to ask afterwards.
    let (keeper, _) = Node::open_archiving(params(), loopback(), directory.join("keeper")).unwrap();
    for block in below.iter().chain(&above) {
        keeper.submit_block(block.clone()).unwrap();
    }
    keeper.submit_block(a_top.clone()).unwrap();

    // Phase one: the wallet reads its way up, writes its ledger down, stops.
    {
        let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
        for block in &below {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        catch_the_history_up(&wallet);
        assert_eq!(
            wallet.holdings().stranded,
            Amount::ZERO,
            "while the node watched them fall, it can place every note"
        );
        assert!(wallet.node().write_ledger());
        if trimmed {
            wallet.node().keep_blocks(1);
            wait_for("the node to drop the blocks below its ledger", || {
                wallet.node().archived_at(0).is_none()
            });
        }
        wallet.shutdown();
    }

    // Phase two: the ordinary restart, from the ledger. The node no longer
    // watches the notes that fell below it; the account still says where
    // each of them landed.
    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    catch_the_history_up(&wallet);
    for block in &above {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    wallet.node().submit_block(a_top.clone()).unwrap();
    assert_eq!(wallet.progress().height, Some(REPLACED));

    let before = wallet.holdings();
    let places_before = before
        .unprovable
        .iter()
        .filter(|one| one.fell_at.is_some())
        .count();
    let (_, on_disk_before) = places_on_disk(&data);
    assert!(
        before.stranded > Amount::ZERO,
        "[{name}] the node cannot place these notes, which is the state this is about"
    );
    assert_eq!(
        places_before,
        before.unprovable.len(),
        "[{name}] and the account can ask about every one of them, which is what it is for"
    );

    // One block at the tip replaced by two. Depth one, and every note this
    // key holds fell far below it.
    keeper.submit_block(b_top.clone()).unwrap();
    keeper.submit_block(b_next.clone()).unwrap();
    wallet.node().submit_block(b_top).unwrap();
    wallet.node().submit_block(b_next).unwrap();
    assert_eq!(
        wallet.progress().height,
        Some(REPLACED + 1),
        "[{name}] the node reorganised onto the heavier branch"
    );

    let after = wallet.holdings();
    let places_after = after
        .unprovable
        .iter()
        .filter(|one| one.fell_at.is_some())
        .count();
    let (_, on_disk_after) = places_on_disk(&data);

    assert_eq!(
        after.total(),
        before.total(),
        "[{name}] a one block reorganisation took {} out of this wallet's balance",
        before
            .total()
            .checked_sub(after.total())
            .map_or_else(|| "(more than it had)".to_owned(), |gone| gone.to_string())
    );
    assert_eq!(
        places_after, places_before,
        "[{name}] it kept the notes and lost the places, which is the same thing as losing them: \
         a note nobody can be asked about is money that cannot be moved"
    );
    assert!(
        on_disk_after >= on_disk_before,
        "[{name}] the file went from {on_disk_before} places to {on_disk_after}"
    );

    // And the archivist, who could have answered for every one of them a
    // moment before the switch. It still can, which is what says the places
    // that were kept are the right ones and not merely some.
    assert!(wallet.reach(keeper.address()));
    wait_for("the archivist to say what it keeps", || {
        wallet.node().archiving_peers() >= 1
    });
    let asked = wallet.recover_stranded();
    assert_eq!(
        asked.rebuilt, places_before,
        "[{name}] asking an archivist brought back {} of the {places_before} notes it had a place \
         for",
        asked.rebuilt
    );
    let recovered = wallet.holdings();
    assert_eq!(
        recovered.stranded,
        Amount::ZERO,
        "[{name}] {} is still stranded after the archivist answered for all of it",
        recovered.stranded
    );
    assert_eq!(
        recovered.spendable,
        before.total(),
        "[{name}] the whole balance should be spendable again"
    );

    // And the account is still reading the chain, which is the other half of
    // what starting over used to cost.
    let movements_before = wallet.history().len();
    let paid_again = rival.mine(&mine);
    keeper.submit_block(paid_again.clone()).unwrap();
    wallet.node().submit_block(paid_again).unwrap();
    assert_eq!(
        wallet.history().len(),
        movements_before + 1,
        "[{name}] a block paying this key did not reach the account"
    );

    keeper.shutdown();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_one_block_reorganisation_after_a_restart_from_a_written_ledger() {
    one_block_reorganisation_after_a_restart("written", false);
}

#[test]
fn a_one_block_reorganisation_after_a_restart_from_a_trimmed_ledger() {
    one_block_reorganisation_after_a_restart("trimmed", true);
}

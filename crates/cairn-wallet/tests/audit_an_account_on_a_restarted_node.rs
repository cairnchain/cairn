//! An account on a node that wrote its ledger down and started again.
//!
//! That is the ordinary life of a node, and it cuts the block log to the
//! ledger's height: the account can no longer read the blocks below where the
//! log begins. What it knows of them is what it read before, and what it can
//! learn from the node's ledger now. Each test here is something the account
//! got wrong about the blocks it can no longer read.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::PathBuf;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::history::Direction;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Blocks paying this key before the ledger is written down.
const HEIGHT: u64 = 40;

/// A shallow burial so a ledger can be written after a few dozen blocks; the
/// hot set is left at its default so every reward stays hot.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

fn somebody(seed: u8) -> PublicKey {
    SecretKey::from_bytes(&[seed; 32]).public_key()
}

/// Mines blocks on a private ledger, paying whoever is named.
struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn fork(&self) -> Self {
        Self {
            state: self.state.clone(),
            clock: self.clock,
        }
    }

    fn mine(&mut self, to: &PublicKey, transfers: Vec<Transfer>) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, *to)]);
        let block =
            assemble_block(&self.state, coinbase, transfers, &params, self.clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }
}

/// A wallet that read `HEIGHT` blocks paying it, whose node then wrote its
/// ledger down and was started again.
struct Restarted {
    directory: PathBuf,
    forge: Forge,
    mine: PublicKey,
}

fn restarted(name: &str, keep_the_account: bool) -> (Restarted, Wallet) {
    let (chain, wallet) = reopened(name, keep_the_account);
    wallet.follow_to_the_tip();
    assert!(
        wallet.node().blocks_from() > Some(0),
        "a node that wrote its ledger and started again was meant to have cut its log"
    );
    assert_eq!(wallet.progress().height, Some(HEIGHT - 1));
    (chain, wallet)
}

/// The same, before the account has looked at anything.
fn reopened(name: &str, keep_the_account: bool) -> (Restarted, Wallet) {
    let directory = std::env::temp_dir().join(format!(
        "cairn-restarted-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[3; 32]);
    let mine = secret.public_key();
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");

    let mut forge = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    let blocks: Vec<Block> = (0..HEIGHT).map(|_| forge.mine(&mine, Vec::new())).collect();
    {
        let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
        for block in &blocks {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        assert_eq!(wallet.history().len() as u64, HEIGHT);
        assert!(wallet.node().write_ledger());
        wallet.shutdown();
    }
    if !keep_the_account {
        std::fs::remove_file(data.join("history.dat")).unwrap();
    }

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    (
        Restarted {
            directory,
            forge,
            mine,
        },
        wallet,
    )
}

fn pooled(wallet: &Wallet, id: &Hash32) -> Option<Transfer> {
    wallet.node().with_chain(|chain| chain.pooled(id).cloned())
}

/// A reorganisation on a restarted node takes back only what the chain took.
///
/// Starting again set every movement aside as undone and gave each one back
/// as a block carrying it was read again, and on a node whose log begins
/// above zero the blocks below it are never read again. So a switch that took
/// nothing of this key's away left every movement below the log's first block
/// on the list of what the chain took back, for good, under a sentence saying
/// whoever was being paid has not been paid. No test reorganised a wallet on a
/// restarted node, so an account that said that passed.
#[test]
fn a_reorganisation_on_a_restarted_node_takes_back_only_what_the_chain_took() {
    let (mut chain, wallet) = restarted("undone-below-the-log", true);

    for _ in 0..4 {
        let block = chain.forge.mine(&chain.mine, Vec::new());
        wallet.node().submit_block(block).unwrap();
    }
    let before = wallet.history();
    assert_eq!(before.len() as u64, HEIGHT + 4);

    // One block at the tip paying a stranger, read by the account, then
    // replaced by two paying somebody else.
    let mut rival = chain.forge.fork();
    wallet
        .node()
        .submit_block(chain.forge.mine(&somebody(11), Vec::new()))
        .unwrap();
    wallet.follow_to_the_tip();
    wallet
        .node()
        .submit_block(rival.mine(&somebody(12), Vec::new()))
        .unwrap();
    wallet
        .node()
        .submit_block(rival.mine(&somebody(12), Vec::new()))
        .unwrap();
    assert_eq!(wallet.progress().height, Some(HEIGHT + 5));

    let after = wallet.history();
    assert!(
        wallet.undone().is_empty(),
        "the block the chain took away paid a stranger, and the account says the chain took \
         back movements of this key's that every block still carries"
    );
    assert_eq!(
        after.len(),
        before.len(),
        "and the list of what happened lost the movements below where the node's log begins"
    );
    assert_eq!(
        wallet.history_covers().missed_below,
        None,
        "and says it could not read blocks it had read"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&chain.directory);
}

/// A payment from notes paid below where the log begins is recorded as what
/// left.
///
/// An account starting over on a restarted node begins where the log does and
/// never reads the blocks that paid the notes below it. Those notes are in the
/// ledger, so the balance counts them and a payment spends them; the account,
/// which tells this key's inputs from a stranger's by the notes it knows,
/// recorded the payment as the change coming back against the few notes it
/// did know. No test paid out of notes the account had not read the blocks
/// for, so an account that wrote down the wrong payment passed.
#[test]
fn a_payment_from_notes_paid_below_the_log_is_recorded_as_what_left() {
    let (mut chain, wallet) = restarted("below-the-log", false);
    let recipient = somebody(9);

    let known = wallet.history().len();
    assert_eq!(
        wallet.holdings().spendable,
        cairn("2000"),
        "forty rewards, all in the hot set and all counted"
    );

    let amount = cairn("1950");
    let fee = wallet.floor_for(recipient, amount);
    let sent = wallet.send(recipient, amount, fee).unwrap();
    assert!(
        sent.notes > known,
        "the payment gathers more notes than the account read the blocks for"
    );
    let transfer = pooled(&wallet, &sent.id).expect("in the pool");
    let block = chain.forge.mine(&somebody(7), vec![transfer]);
    wallet.node().submit_block(block).unwrap();

    let newest = wallet.history()[0];
    let left = amount.checked_add(fee).unwrap();
    assert_eq!(
        (newest.direction, newest.amount),
        (Direction::Sent, left),
        "this key paid the amount and the fee away in one transfer, and the account wrote \
         down something else: the change coming back against the notes it happened to know"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&chain.directory);
}

/// An account whose node cannot give back the first block of its log stops
/// there and says so, rather than going round for ever.
///
/// An account starting over asks for block zero, is told the log begins
/// further up, and moves there. When the block there will not read either,
/// the place the log begins is the place the account already stands, and
/// moving there again moves nothing. Nothing damaged the first block of a
/// log under an account, so a reading that went on asking passed.
#[test]
fn an_account_that_cannot_read_the_first_block_of_the_log_stops_there() {
    let (chain, wallet) = reopened("first-unreadable", false);
    let first = wallet.node().blocks_from().expect("the log holds blocks");
    assert!(
        first > 0,
        "a node that wrote its ledger was meant to have cut its log"
    );

    // The first record's header, past its length prefix, names its parent
    // from byte fourteen: a changed parent is a record the one after it no
    // longer names, which the store refuses.
    let log = chain.directory.join("data").join("blocks.log");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&log)
        .unwrap();
    let at = SeekFrom::Start(4 + 14);
    let mut byte = [0u8; 1];
    file.seek(at).unwrap();
    file.read_exact(&mut byte).unwrap();
    file.seek(at).unwrap();
    file.write_all(&[byte[0] ^ 0xFF]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(
        wallet.node().archived_at(first).is_none(),
        "the first block of the log still reads, so this asks nothing"
    );

    assert_eq!(wallet.follow(), 0, "a block that will not read was read");
    assert_eq!(wallet.follow(), 0);
    assert_eq!(
        wallet.history_covers().missed_below,
        Some(first),
        "the account moved to where the log begins and stands there"
    );
    assert!(
        wallet.progress().unread.is_some(),
        "and the refusal is said"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&chain.directory);
}

//! Where the account's reading and the chain part company, and what that costs.
//!
//! A reorganisation replaces every block above the fork it happened at. The
//! account notices one by comparing the newest block it read with what the
//! chain carries at that height, and what it has to do next depends entirely
//! on where the fork is: everything below it stands, everything above it is
//! undone. The account used to have no way to say where that was. It asked the
//! block log, which a node trims from the front, and on a divergence it threw
//! everything away and read the chain again from height zero, judging which
//! notes to keep by a line measured from the tip as it stood when it looked.
//!
//! Each test here is one way that went wrong on an ordinary chain: a one block
//! tie, a node that trimmed its log, a wallet that was not looking for a while.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;
use cairn_wallet::history::History;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A shallow burial so a ledger can be written after a few dozen blocks, and a
/// hot set of four so a note falls out of it four blocks after it is paid.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-left-the-chain-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
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

/// A wallet on a directory of its own, and the key it answers to. Opened
/// again on the same directory, it is the same wallet.
fn opened(directory: &Path, seed: u8) -> (Wallet, PublicKey) {
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[seed; 32]);
    if !key_file.exists() {
        cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    }
    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
    (wallet, secret.public_key())
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
    fn new() -> Self {
        Self {
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn fork(&self) -> Self {
        Self {
            state: self.state.clone(),
            clock: self.clock,
        }
    }

    fn mine(&mut self, to: &PublicKey) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, *to)]);
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }
}

fn heights(movements: &[cairn_wallet::history::Movement]) -> Vec<u64> {
    movements.iter().map(|movement| movement.height).collect()
}

/// A note the losing branch paid above the fork is not kept as money.
///
/// The account used to throw itself away on a divergence and keep only the
/// places of notes paid below a settled line, and it drew that line from the
/// tip as it stood when the wallet looked rather than from the tip the switch
/// happened at. A wallet that looked only after the winning branch had grown
/// further than a switch can reach found the losing branch's note below the
/// line, kept it with its place, and counted it as stranded money for good:
/// nothing on the winning branch spends a note it never paid. The existing
/// tests looked straight after the switch, where the two lines are the same
/// line, so an account that kept a note nobody paid passed.
#[test]
fn a_note_the_losing_branch_paid_above_the_fork_is_not_kept_as_money() {
    const FORK: u64 = 20;
    const LOSING: u64 = 6;
    const WINNING: u64 = 12;

    let directory = scratch("kept");
    let (wallet, mine) = opened(&directory, 3);
    let other = somebody(12);

    let mut forge = Forge::new();
    let common: Vec<Block> = (0..FORK).map(|_| forge.mine(&other)).collect();
    let mut rival = forge.fork();
    // The losing branch pays this key on its first block and runs on long
    // enough for that note to fall and be watched.
    let mut losing = vec![forge.mine(&mine)];
    losing.extend((1..LOSING).map(|_| forge.mine(&other)));
    let ours: NoteId = losing[0].coinbase.created_notes()[0].0;
    let winning: Vec<Block> = (0..WINNING).map(|_| rival.mine(&other)).collect();

    for block in common.iter().chain(&losing) {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    assert_eq!(
        wallet.holdings().total(),
        params().initial_reward,
        "on the losing branch this key holds the one reward"
    );
    let (written, _) = History::load(&directory.join("data").join("history.dat"));
    assert!(
        written.where_it_fell(&ours).is_some(),
        "the account wrote down where that note fell, which is what it used to keep"
    );

    // The switch, and then more chain than a switch can reach before the
    // wallet looks again.
    for block in &winning {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    assert_eq!(wallet.progress().height, Some(FORK + WINNING - 1));

    let after = wallet.holdings();
    assert_eq!(
        after.stranded,
        Amount::ZERO,
        "the winning branch never paid this key, and the account counts the note the losing \
         branch paid above the fork as stranded money that nothing will ever take out again"
    );
    assert_eq!(
        after.total(),
        Amount::ZERO,
        "this key owns nothing on the winning branch"
    );
    assert_eq!(
        heights(&wallet.undone()),
        vec![FORK],
        "and the one payment the switch took away is the one said to be taken back"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A one block reorganisation on a node that trimmed its log takes back the
/// one block it replaced, and nothing below it.
///
/// Starting again set every movement aside as undone and relied on reading
/// the chain again to give back each one a block still carried. A node that
/// has written its ledger cannot be read below it, so every movement below
/// where its log begins stayed on the list of what the chain took back, under
/// a sentence saying whoever was being paid has not been paid. No test
/// reorganised a wallet on a trimmed node, so an account that called its
/// whole past undone passed.
#[test]
fn a_one_block_reorganisation_on_a_trimmed_node_takes_back_only_the_block_it_replaced() {
    const LEDGER_AT: u64 = 90;

    let directory = scratch("trimmed");
    let (wallet, mine) = opened(&directory, 3);
    let other = somebody(12);

    let mut forge = Forge::new();
    let below: Vec<Block> = (0..=LEDGER_AT).map(|_| forge.mine(&mine)).collect();
    for block in &below {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    wallet.follow_to_the_tip();
    assert_eq!(wallet.history().len() as u64, LEDGER_AT + 1);

    assert!(wallet.node().write_ledger());
    wallet.node().keep_blocks(1);
    wait_for("the node to drop the blocks below its ledger", || {
        wallet.node().archived_at(0).is_none()
    });

    let mut rival = forge.fork();
    let replaced = forge.mine(&mine);
    wallet.node().submit_block(replaced).unwrap();
    wallet.follow_to_the_tip();
    assert_eq!(wallet.history().len() as u64, LEDGER_AT + 2);

    wallet.node().submit_block(rival.mine(&other)).unwrap();
    wallet.node().submit_block(rival.mine(&other)).unwrap();
    assert_eq!(wallet.progress().height, Some(LEDGER_AT + 2));

    let history = wallet.history();
    assert_eq!(
        heights(&wallet.undone()),
        vec![LEDGER_AT + 1],
        "a switch one block deep took back one payment, and the account lists every payment \
         below where the node's log begins as taken back too"
    );
    assert_eq!(
        history.len() as u64,
        LEDGER_AT + 1,
        "and every payment below the fork is still in the list of what happened"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A payment a reorganisation undid is taken back even once the node has
/// trimmed its log past it.
///
/// The account asked the block log whether the block it read last was still
/// there, and took a height the log no longer holds as a block nobody
/// changed. A block replaced and then trimmed away read that way, so the
/// payment it carried stayed in the list as having happened and its note
/// stayed in the account. Every test that reorganised a wallet looked before
/// the node trimmed, so an account that could not see a switch below the
/// log's first block passed.
#[test]
fn a_payment_undone_and_then_trimmed_away_is_still_taken_back() {
    const PAID_AT: u64 = 100;
    const GROWN_TO: u64 = 120;

    let directory = scratch("undone-and-trimmed");
    let (wallet, mine) = opened(&directory, 3);
    let other = somebody(12);

    let mut forge = Forge::new();
    let below: Vec<Block> = (0..PAID_AT).map(|_| forge.mine(&other)).collect();
    let mut rival = forge.fork();
    let paid = forge.mine(&mine);
    for block in below.iter().chain(std::iter::once(&paid)) {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    assert_eq!(heights(&wallet.history()), vec![PAID_AT]);

    // The wallet does not look again until the chain has switched, grown, and
    // the node has trimmed its log past the height it last read.
    for _ in PAID_AT..=GROWN_TO {
        wallet.node().submit_block(rival.mine(&other)).unwrap();
    }
    assert_eq!(wallet.progress().height, Some(GROWN_TO));
    assert!(wallet.node().write_ledger());
    wallet.node().keep_blocks(1);
    wait_for("the node to drop the block the account last read", || {
        wallet.node().archived_at(PAID_AT).is_none()
    });

    let history = wallet.history();
    assert!(
        history.iter().all(|movement| movement.height != PAID_AT),
        "the block that paid this key was undone, and the account still lists that payment \
         as having happened, because a block the log no longer holds was taken as a block \
         that did not change"
    );
    assert_eq!(
        heights(&wallet.undone()),
        vec![PAID_AT],
        "and it is the list of what the chain took back that names it"
    );
    assert_eq!(
        wallet.holdings().unaccounted.len(),
        0,
        "and the note it paid is not left in the account as one it lost track of"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A payment undone while the wallet was closed is taken back when it opens,
/// on a node that has since started again from a ledger past it.
///
/// Closed, the wallet's node is closed too, and it comes back from the
/// ledger it wrote: the chain in memory begins near that ledger, the block
/// log was trimmed to it, and the only record of which block the branch
/// carries at a height below it is the header log. The account asked the
/// block log, found nothing there, and kept the payment the switch had
/// undone as a payment that happened. No test closed a wallet across a
/// switch, so an account that could only see a switch the block log still
/// held passed.
#[test]
fn a_payment_undone_while_the_wallet_was_closed_is_taken_back_when_it_opens() {
    const PAID_AT: u64 = 100;
    // Far enough past it that a node started again from its ledger no longer
    // holds the height in memory: the ledger carries the headers a retarget
    // needs below its anchor, and no more.
    const GROWN_TO: u64 = 220;

    let directory = scratch("undone-while-closed");
    let other = somebody(12);
    let mut forge = Forge::new();
    let (paid, winning) = {
        let (wallet, mine) = opened(&directory, 3);
        let below: Vec<Block> = (0..PAID_AT).map(|_| forge.mine(&other)).collect();
        let mut rival = forge.fork();
        let paid = forge.mine(&mine);
        for block in below.iter().chain(std::iter::once(&paid)) {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        assert_eq!(heights(&wallet.history()), vec![PAID_AT]);
        let winning: Vec<Block> = (PAID_AT..=GROWN_TO).map(|_| rival.mine(&other)).collect();
        wallet.shutdown();
        (paid, winning)
    };

    // The node alone, under the wallet's directory, takes the switch and
    // writes its ledger down past the height the account last read.
    {
        let (node, _) = cairn_net::Node::open_watching(
            params(),
            "127.0.0.1:0".parse().unwrap(),
            directory.join("data"),
            &[],
        )
        .unwrap();
        for block in &winning {
            node.submit_block(block.clone()).unwrap();
        }
        assert_eq!(node.height(), Some(GROWN_TO));
        assert!(node.write_ledger());
        node.keep_blocks(1);
        wait_for("the node to drop the block the account last read", || {
            node.archived_at(PAID_AT).is_none()
        });
        node.shutdown();
    }

    let (wallet, _) = opened(&directory, 3);
    assert_eq!(wallet.progress().height, Some(GROWN_TO));
    assert!(
        wallet
            .node()
            .with_chain(|chain| chain.id_at(PAID_AT))
            .is_none(),
        "the chain in memory still names the height the account last read, so this asks \
         nothing of the header log"
    );
    assert_ne!(
        wallet.node().id_at(PAID_AT),
        Some(paid.id()),
        "the node still carries the block the switch replaced"
    );

    let history = wallet.history();
    assert!(
        history.iter().all(|movement| movement.height != PAID_AT),
        "the block that paid this key was undone while the wallet was closed, and the account \
         still lists that payment as having happened"
    );
    assert_eq!(heights(&wallet.undone()), vec![PAID_AT]);

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A switch one block deep reads back the blocks it applied and no others.
///
/// The account started again from height zero on every divergence and read
/// every block its node keeps, a gigabyte by default, and the page waited for
/// all of it before it counted a coin. Nothing counted what the account read
/// after a switch, so an account that read the whole chain again passed.
#[test]
fn a_one_block_switch_reads_back_only_the_blocks_it_applied() {
    const COMMON: u64 = 60;

    let directory = scratch("reread");
    let (wallet, mine) = opened(&directory, 4);

    let mut common = Forge::new();
    for _ in 0..COMMON {
        wallet.node().submit_block(common.mine(&mine)).unwrap();
    }
    assert_eq!(wallet.follow_to_the_tip() as u64, COMMON);

    let mut rival = common.fork();
    wallet.node().submit_block(common.mine(&mine)).unwrap();
    assert_eq!(wallet.follow_to_the_tip(), 1, "one block arrived, one read");

    let applied = [rival.mine(&somebody(9)), rival.mine(&somebody(9))];
    for block in &applied {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    assert_eq!(wallet.progress().height, Some(COMMON + 1));

    let read = wallet.follow_to_the_tip();
    assert_eq!(
        read,
        applied.len(),
        "a switch that undid one block and applied two made the account read that many \
         blocks off the disk again"
    );
    assert_eq!(wallet.history_covers().through, Some(COMMON + 1));
    assert_eq!(
        wallet.history().len() as u64,
        COMMON,
        "and the account is the one it would be having read the winning branch alone"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// An account level with the tip reads nothing off the disk to find that out.
///
/// Every look at the account asked whether it had diverged by reading the
/// newest block it had read back off the block log: a seek, a decode with one
/// key decompression per note, the transactions root hashed again and the
/// neighbour's header read, to compare thirty two bytes the chain holds in
/// memory. The page asks four times every two seconds. Nothing counted the
/// reads, so an account that went to the disk on every look passed. Here the
/// tip's record is damaged after the account has read it, which makes every
/// read of it a refusal the node counts.
#[test]
fn an_account_level_with_the_tip_reads_nothing_off_the_disk_to_say_so() {
    let directory = scratch("idle");
    let (wallet, mine) = opened(&directory, 5);

    let mut forge = Forge::new();
    for _ in 0..5 {
        wallet.node().submit_block(forge.mine(&mine)).unwrap();
    }
    assert_eq!(wallet.follow_to_the_tip(), 5);
    assert!(wallet.node().unread().is_none(), "nothing refused yet");

    // The last byte of the log is the last byte of the tip's record: the
    // count of its transfers, which no longer reads.
    let log = directory.join("data").join("blocks.log");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&log)
        .unwrap();
    let end = file.seek(SeekFrom::End(-1)).unwrap();
    let mut last = [0u8; 1];
    file.read_exact(&mut last).unwrap();
    file.seek(SeekFrom::Start(end)).unwrap();
    file.write_all(&[last[0] ^ 0xFF]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(
        wallet.node().archived_at(4).is_none() && wallet.node().unread().is_some(),
        "the damaged record is refused, or this test counts nothing"
    );
    let refused = wallet.node().unread().map_or(0, |unread| unread.refusals);

    // A page view, several times over.
    for _ in 0..3 {
        let _ = wallet.holdings();
        let _ = wallet.waiting();
        let _ = wallet.history();
        assert_eq!(wallet.follow_to_the_tip(), 0);
    }
    assert_eq!(
        wallet.node().unread().map_or(0, |unread| unread.refusals),
        refused,
        "an account with nothing new to read went to the disk to learn the tip's identifier"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

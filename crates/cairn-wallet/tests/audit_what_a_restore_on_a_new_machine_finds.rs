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
//!
//! Unless the wallet reads the chain again, from the first block, as the lost
//! machine did. That is `Wallet::recover`, `cairn-wallet recover`: its node is
//! never handed a ledger, asks peers that keep every block first, and writes
//! down where each of this key's notes fell as the block it fell in is
//! applied. The rest of this file holds what that finds and what it costs, and
//! what it does when it is interrupted, when nobody keeps the blocks, and when
//! the peer keeping them stops half way.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Keeps, Message, PROTOCOL_VERSION};
use cairn_net::node::READING_FROM_THE_FIRST;
use cairn_net::sync::JOIN_RATHER_THAN_READ;
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::Node;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::history::History;
use cairn_wallet::{ReadFromTheFirst, Wallet};

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
///
/// And a block may push out enough notes for its coinbase's sixteen places and
/// a payment's beside them, which a full tier of four leaves room for only
/// above that: the recovered money is spent at the end of a chain whose tier
/// is full.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(20)
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

    /// A forge standing where `blocks` leave the chain, to mine on top of it.
    fn over(blocks: &[Block]) -> Self {
        let mut forge = Self::new();
        for block in blocks {
            connect_block(&mut forge.state, block, &forge.params, NOW).unwrap();
            forge.clock = block.header.timestamp;
        }
        forge
    }

    fn mine(&mut self, to: &cairn_crypto::PublicKey) -> Block {
        self.mine_carrying(to, Vec::new())
    }

    fn mine_carrying(&mut self, to: &cairn_crypto::PublicKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(self.params.initial_reward, *to)]);
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
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

/// The key every test here is paid at.
fn the_key() -> SecretKey {
    SecretKey::from_bytes(&[3; 32])
}

/// The chain every test here reads, mined once for the whole file: twelve
/// hundred blocks at a cheap difficulty are still seconds of work.
fn the_chain() -> &'static [Block] {
    static CHAIN: OnceLock<Vec<Block>> = OnceLock::new();
    CHAIN.get_or_init(|| a_chain_that_paid_this_key_in_all_three_places(&the_key().public_key()))
}

/// How many of the twelve payments fell before the window.
fn deep_payments() -> u64 {
    DEEP.div_ceil(3) as u64
}

/// A directory of `name` holding the key file, and the key file's path.
fn a_key_on_a_new_machine(name: &str) -> (PathBuf, PathBuf) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &the_key()).unwrap();
    (directory, key_file)
}

/// Somebody who kept every block and every leaf of the cold set, holding the
/// whole chain.
fn an_archivist(directory: &Path) -> Node {
    let (keeper, _) = Node::open_archiving(params(), loopback(), directory).unwrap();
    for block in the_chain() {
        keeper.submit_block(block.clone()).unwrap();
    }
    keeper
}

/// How long a test gives a read that has stopped moving. Far longer than any
/// pause an honest read on the loopback makes.
const STILL_FOR: Duration = Duration::from_secs(60);

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
    let (directory, key_file) = a_key_on_a_new_machine("three-places");
    let blocks = the_chain();
    let tip = (blocks.len() - 1) as u64;
    let deep_payments = deep_payments();
    let window_payment_at = (DEEP + PAST_THE_WINDOW) as u64;

    // The machine that was lost: it read every block, and knows all of it.
    let whole = {
        let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("old")).unwrap();
        for block in blocks {
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
    let keeper = an_archivist(&directory.join("keeper"));

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

/// The notes `data`'s account holds, and how many of them it has a place for.
fn the_account_in(data: &Path) -> (usize, usize) {
    let (history, discarded) = History::load(&data.join("history.dat"));
    assert!(discarded.is_none(), "the account did not read back");
    let held: Vec<_> = history.held().collect();
    let placed = held
        .iter()
        .filter(|(id, _)| history.where_it_fell(id).is_some())
        .count();
    (held.len(), placed)
}

/// **A wallet recovered on a new machine finds all twelve payments, writes
/// down where each one that fell sits, and spends the oldest.**
///
/// The same machine as the finding above: the key, an empty data directory,
/// an archivist. Opened by `recover` rather than `open`, its node reads every
/// block from the first, and what was lost above is found. Every note that
/// fell, the ten deep ones and the one in the window, has its place in
/// history.dat, which is what lets the wallet spend it now and find it again
/// after a restart. And it spends: a payment of more than the two notes the
/// finding found reaches for the oldest, and a miner holding its own copy of
/// the chain carries it.
#[test]
fn a_recovery_on_a_new_machine_finds_every_payment_and_spends_the_oldest() {
    let (directory, key_file) = a_key_on_a_new_machine("recovered");
    let blocks = the_chain();
    let tip = (blocks.len() - 1) as u64;
    let keeper = an_archivist(&directory.join("keeper"));

    let fresh = directory.join("fresh");
    let (wallet, _) = Wallet::recover(&key_file, params(), &fresh).unwrap();
    assert!(wallet.reach(keeper.address()));
    let started = Instant::now();
    let read = wallet.read_from_the_first_block(STILL_FOR);
    let took = started.elapsed();
    let read_bytes = wallet.node().kept_bytes();
    let first_held = wallet.node().blocks_from();
    let finished = (
        wallet.node().reads_from_the_first_block(),
        fresh.join(READING_FROM_THE_FIRST).exists(),
    );
    let holdings = wallet.holdings();
    let covered = wallet.history_covers();
    let account = the_account_in(&fresh);

    // The oldest money moves: more than the two notes a plain restore finds.
    let stranger = SecretKey::from_bytes(&[11; 32]).public_key();
    let paying = times(reward(), 5);
    let fee = wallet.floor_for(stranger, paying);
    let sent = wallet.send(stranger, paying, fee);
    let carried: Vec<Transfer> = wallet.node().with_chain(|chain| {
        chain
            .pooled_transfers()
            .map(|(_, transfer)| transfer.clone())
            .collect()
    });
    wallet.shutdown();
    drop(wallet);
    keeper.shutdown();
    drop(keeper);
    let _ = std::fs::remove_dir_all(&directory);

    eprintln!(
        "a recovery read {} blocks from the first in {took:?}, holding {read_bytes} bytes of them",
        tip + 1
    );
    assert_eq!(read, ReadFromTheFirst::Reached, "the read reached the tip");
    assert_eq!(first_held, Some(0), "fixture: read from the first block");
    assert_eq!(
        holdings.total(),
        times(reward(), deep_payments() + 2),
        "a wallet recovered on a new machine finds every payment, the ten that fell before \
         the window among them"
    );
    assert_eq!(holdings.stranded, Amount::ZERO, "and can prove every one");
    assert_eq!(
        covered.from,
        Some(0),
        "its account reaches back to the first block"
    );
    assert_eq!(
        account,
        (12, deep_payments() as usize + 1),
        "history.dat holds the twelve notes, and a place for each of the eleven that fell: \
         the ten deep ones and the one in the window"
    );
    assert_eq!(
        finished,
        (false, false),
        "a recovery that reached the tip left its node, or its disk, reading from the first \
         block"
    );
    let sent = sent.expect("the recovered money could not be spent");
    assert!(
        sent.from_cold > 0,
        "the payment spent money that had fallen"
    );
    assert_eq!(carried.len(), 1, "the payment reached the pool");
    let mut forge = Forge::over(blocks);
    let miner = SecretKey::from_bytes(&[7; 32]).public_key();
    let block = forge.mine_carrying(&miner, carried);
    assert_eq!(
        block.transfers.len(),
        1,
        "a miner checking against its own copy of the chain carried the payment"
    );
}

/// **A recovery whose account copies nothing until the node has read the
/// whole chain loses no place.**
///
/// The wallet copies the places out of its node every round of its read, and
/// the node it copies from lets go of one only when more than `WATCHED_NOTES`
/// of this key's notes, each worth more, are fallen and unspent at once. So
/// how often the copies are made is no part of what can be lost, short of
/// that many notes paid to this one key, which is a flood aimed at it. Here
/// the copies are as rare as they can be: the node reads the whole chain
/// before the account copies anything at all, and the account comes out the
/// same as one copied all along.
#[test]
fn a_recovery_whose_account_copies_nothing_until_the_tip_loses_no_place() {
    let (directory, key_file) = a_key_on_a_new_machine("copied-late");
    let tip = (the_chain().len() - 1) as u64;
    let keeper = an_archivist(&directory.join("keeper"));
    let late = directory.join("late");
    let (wallet, _) = Wallet::recover(&key_file, params(), &late).unwrap();
    assert!(wallet.reach(keeper.address()));
    wait_for("the node to read the whole chain", || {
        wallet.node().height() == Some(tip)
    });
    let nothing_copied_yet = !late.join("history.dat").exists();
    let read = wallet.read_from_the_first_block(STILL_FOR);
    let total = wallet.holdings().total();
    let account = the_account_in(&late);
    wallet.shutdown();
    drop(wallet);
    keeper.shutdown();
    drop(keeper);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        nothing_copied_yet,
        "fixture: the account copied nothing during the read"
    );
    assert_eq!(read, ReadFromTheFirst::Reached);
    assert_eq!(
        (total, account),
        (
            times(reward(), deep_payments() + 2),
            (12, deep_payments() as usize + 1)
        ),
        "an account that copied the places only once the node had read the whole chain lost \
         some of them"
    );
}

/// **An interrupted recovery carries on reading from the first block,
/// whichever command starts the wallet again over its directory.**
///
/// The worst moment to stop is before the first block arrives: the node holds
/// nothing of its own then, and a node holding nothing on a chain this long is
/// handed a ledger. So it stops there, is opened again by an ordinary command
/// as `balance` would open it, and still reads from the first block; stopped
/// again half way and opened by `recover`, which takes the directory back, it
/// reads to the tip and finds everything.
#[test]
fn an_interrupted_recovery_carries_on_reading_from_the_first_block() {
    let (directory, key_file) = a_key_on_a_new_machine("interrupted");
    let keeper = an_archivist(&directory.join("keeper"));
    let fresh = directory.join("fresh");

    let (stopped_at_once, _) = Wallet::recover(&key_file, params(), &fresh).unwrap();
    stopped_at_once.shutdown();
    drop(stopped_at_once);

    let (opened_plainly, _) = Wallet::open(&key_file, params(), &fresh).unwrap();
    let still_reading = opened_plainly.node().reads_from_the_first_block();
    assert!(opened_plainly.reach(keeper.address()));
    wait_for("some of the chain to be read", || {
        opened_plainly
            .node()
            .height()
            .is_some_and(|height| height >= 100)
    });
    let first_held = opened_plainly.node().blocks_from();
    // And its account, read as far as the chain has come, is on the disk
    // beside the chain: what recover is about to be handed back.
    opened_plainly.follow();
    let account_written = fresh.join("history.dat").exists();
    opened_plainly.shutdown();
    drop(opened_plainly);

    assert!(account_written, "fixture: the account was written down");
    let (carried_on, _) = Wallet::recover(&key_file, params(), &fresh)
        .expect("recover refused the directory of the recovery it was to carry on");
    assert!(carried_on.reach(keeper.address()));
    let read = carried_on.read_from_the_first_block(STILL_FOR);
    let total = carried_on.holdings().total();
    let first_at_the_end = carried_on.node().blocks_from();
    carried_on.shutdown();
    drop(carried_on);
    keeper.shutdown();
    drop(keeper);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        still_reading,
        "a wallet opened over an interrupted recovery was not reading from the first block"
    );
    assert_eq!(
        first_held,
        Some(0),
        "a recovery stopped before its first block was handed a ledger when it started again"
    );
    assert_eq!(read, ReadFromTheFirst::Reached);
    assert_eq!(first_at_the_end, Some(0));
    assert_eq!(
        total,
        times(reward(), deep_payments() + 2),
        "a recovery carried on after two interruptions did not find every payment"
    );
}

/// **With no peer that keeps every block, the read stops and says so.**
///
/// The only peer reached keeps what its budget affords and has let go of the
/// chain's first blocks. Nothing it sends connects to the first block, so the
/// read stands still, and after the patience it is handed it stops and says
/// that no peer it reached keeps every block. What it found, nothing, is not
/// passed off as a balance.
#[test]
fn a_recovery_with_no_archivist_stops_and_says_so() {
    let (directory, key_file) = a_key_on_a_new_machine("no-archivist");
    let trimmed_directory = directory.join("trimmed");
    let (trimmed, _) = Node::open(params(), loopback(), &trimmed_directory).unwrap();
    for block in the_chain() {
        trimmed.submit_block(block.clone()).unwrap();
    }
    trimmed.keep_blocks(1);
    wait_for("the peer to let go of its first blocks", || {
        trimmed.blocks_from().unwrap_or(0) > 0
    });

    let fresh = directory.join("fresh");
    let (wallet, _) = Wallet::recover(&key_file, params(), &fresh).unwrap();
    assert!(wallet.reach(trimmed.address()));
    let patience = Duration::from_secs(5);
    let started = Instant::now();
    let read = wallet.read_from_the_first_block(patience);
    let took = started.elapsed();
    let still_reading = wallet.node().reads_from_the_first_block();
    wallet.shutdown();
    drop(wallet);
    trimmed.shutdown();
    drop(trimmed);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        matches!(read, ReadFromTheFirst::Stopped { archivists: 0, .. }),
        "a recovery with no archivist came to {read:?}"
    );
    assert!(
        took >= patience && took < patience * 4,
        "it stopped after {took:?}, given {patience:?}"
    );
    assert!(
        still_reading,
        "a read that stopped short no longer says it is reading from the first block, so the \
         next start over its directory could be handed a ledger"
    );
}

/// **`recover` starts only over a directory holding neither an account nor a
/// chain, and nothing it refuses is written to.**
#[test]
fn a_recovery_is_refused_over_a_directory_already_in_use() {
    let (directory, key_file) = a_key_on_a_new_machine("in-use");

    let with_an_account = directory.join("account");
    std::fs::create_dir_all(&with_an_account).unwrap();
    std::fs::write(with_an_account.join("history.dat"), b"").unwrap();
    let refused = Wallet::recover(&key_file, params(), &with_an_account).map(|(wallet, _)| {
        wallet.shutdown();
    });
    let marked = with_an_account.join(READING_FROM_THE_FIRST).exists();

    let with_a_chain = directory.join("chain");
    {
        let (wallet, _) = Wallet::open(&key_file, params(), &with_a_chain).unwrap();
        for block in &the_chain()[..3] {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        wait_for("the blocks to reach the disk", || {
            wallet.node().written_through() == Some(2)
        });
        wallet.shutdown();
    }
    let _ = std::fs::remove_file(with_a_chain.join("history.dat"));
    let chain_refused = Wallet::recover(&key_file, params(), &with_a_chain).map(|(wallet, _)| {
        wallet.shutdown();
    });

    let _ = std::fs::remove_dir_all(&directory);
    let refused = refused.expect_err("a recovery was started over a wallet's account");
    assert!(
        refused.to_string().contains("history.dat"),
        "the refusal does not name the account it found: {refused}"
    );
    assert!(!marked, "and the refusal wrote the marker anyway");
    assert!(
        chain_refused.is_err(),
        "a recovery was started over a directory holding a chain"
    );
}

/// A peer that says it keeps every block and claims the whole chain, and
/// sends the blocks below `serves` and then nothing more, while staying
/// connected. Dialled into `wallet`'s node.
fn an_archivist_that_stops_half_way(wallet: SocketAddr, serves: usize) -> TcpStream {
    let network = params().network;
    let blocks = the_chain();
    let tip = blocks.last().unwrap().header;
    let mut socket = TcpStream::connect(wallet).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let hello = Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network,
        genesis: params().genesis.unwrap_or(Hash32::ZERO),
        height: tip.height,
        total_work: tip.total_work,
        listen: 0,
        nonce: 0x0A5C_0001,
        keeps: Keeps {
            headers: true,
            cold_set: true,
        },
    });
    write_message(&mut socket, network, &hello).unwrap();
    let mut reading = socket.try_clone().unwrap();
    let mut answered: Option<Instant> = None;
    thread::spawn(move || loop {
        let message = match read_message(&mut reading, network, MAX_FRAME_BYTES) {
            Ok(Incoming::Message(message)) => message,
            Ok(Incoming::Quiet) => continue,
            Err(_) => return,
        };
        let answers = match message {
            Message::GetPeers => vec![Message::Peers(Vec::new())],
            Message::Ping(nonce) => vec![Message::Pong(nonce)],
            // No oftener than once a second, under the ceiling on messages a
            // node holds a peer to.
            Message::GetChain { .. }
                if answered.is_none_or(|at| at.elapsed() >= Duration::from_secs(1)) =>
            {
                answered = Some(Instant::now());
                vec![Message::Chain {
                    from: 0,
                    count: blocks.len() as u64,
                }]
            }
            Message::GetBlocks(heights) => heights
                .iter()
                .filter_map(|at| usize::try_from(*at).ok())
                .filter(|at| *at < serves)
                .filter_map(|at| blocks.get(at))
                .map(|block| Message::Block(Box::new(block.clone())))
                .collect(),
            _ => continue,
        };
        for answer in answers {
            if write_message(&mut reading, network, &answer).is_err() {
                return;
            }
        }
    });
    socket
}

/// **An archivist that stops sending half way is replaced, and the recovery
/// finds everything.**
///
/// The only peer at first says it keeps every block, is read from the first
/// block, and stops sending half way up the chain without hanging up. A
/// second archivist is reached once the read stands still there, and the
/// read carries on from it to the tip.
#[test]
fn a_recovery_whose_archivist_stops_half_way_carries_on_from_another() {
    let (directory, key_file) = a_key_on_a_new_machine("half-way");
    let half = the_chain().len() / 2;
    let fresh = directory.join("fresh");
    let (wallet, _) = Wallet::recover(&key_file, params(), &fresh).unwrap();
    let listening = SocketAddr::from((Ipv4Addr::LOCALHOST, wallet.node().address().port()));
    let quitter = an_archivist_that_stops_half_way(listening, half);
    wait_for("the read to reach where the first archivist stops", || {
        wallet.node().height() == Some(half as u64 - 1)
    });
    // Standing there, with blocks owed and none coming.
    thread::sleep(Duration::from_secs(2));
    let stood = wallet.node().height();

    let keeper = an_archivist(&directory.join("keeper"));
    assert!(wallet.reach(keeper.address()));
    let read = wallet.read_from_the_first_block(STILL_FOR);
    let total = wallet.holdings().total();
    let first_held = wallet.node().blocks_from();
    let _ = quitter.shutdown(std::net::Shutdown::Both);
    wallet.shutdown();
    drop(wallet);
    keeper.shutdown();
    drop(keeper);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        stood,
        Some(half as u64 - 1),
        "fixture: the first archivist stopped sending half way"
    );
    assert_eq!(read, ReadFromTheFirst::Reached);
    assert_eq!(first_held, Some(0));
    assert_eq!(
        total,
        times(reward(), deep_payments() + 2),
        "a recovery whose archivist stopped half way did not find every payment"
    );
}

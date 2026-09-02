//! Money a wallet can see and cannot move, and how it gets it back.
//!
//! A note that has fallen out of the set every node keeps can only be spent
//! alongside a path showing where it sits. The path changes every time another
//! note falls, so nobody keeps one for a stranger, and a wallet whose own node
//! has stopped keeping one is looking at money it cannot touch. Until now the
//! only thing it did about that was name a service and leave its owner to go
//! and find it.

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
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::Amount;
use cairn_wallet::{Wallet, WalletError};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Blocks mined before the money is looked at.
///
/// Long enough that some of this key's notes fell more than
/// `cairn_ledger::state::GRACE_BLOCKS` blocks below the point a written down
/// ledger is anchored at. Anything nearer than that travels in the ledger
/// itself, and the whole question here is what happens to the rest.
const BLOCKS: usize = 100;

/// Shallow wherever a test would otherwise have to mine its way through a
/// number chosen for a live network, and a hot set small enough that notes
/// reach the cold set in a few blocks rather than in months.
///
/// The maturity rule is turned off rather than shortened: on a network this
/// shallow a reward matures where the burial is, so a number in between would
/// be saying something the design does not say.
/// Nothing here is about maturity, and the money has to be reachable.
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
        "cairn-recovery-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

/// Mines blocks on a private ledger, paying whoever is named.
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

    fn mine(&mut self, to: &cairn_crypto::PublicKey, transfers: Vec<Transfer>) -> Block {
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

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// Reads its way to the end of the chain, which is what fills the wallet's own
/// account of what it was paid and where each note landed.
fn catch_the_history_up(wallet: &Wallet) {
    while wallet.follow() > 0 {}
}

/// A wallet holding money it cannot move, and somebody who could tell it how.
///
/// The way it gets there is ordinary and is nobody's fault: the node writes
/// its own ledger down, which is what keeps a node's disk from growing with
/// the chain, and starts again from that file. The ledger carries the chain
/// and not this machine's own notes about which owners it was following, so
/// every place this wallet's notes had landed goes with it.
struct Stuck {
    wallet: Wallet,
    keeper: Node,
    forge: Forge,
    secret: SecretKey,
    directory: PathBuf,
    /// What could be spent before any of this happened.
    was: Amount,
}

fn a_wallet_that_lost_its_record(name: &str) -> Stuck {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[3; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");

    let mut forge = Forge::new();
    let blocks: Vec<Block> = (0..BLOCKS)
        .map(|_| forge.mine(&secret.public_key(), Vec::new()))
        .collect();

    // A node that kept every leaf the cold set ever held. Nobody pays it to,
    // and the person who needs it is whoever lost their own path.
    let (keeper, _) = Node::open_archiving(params(), loopback(), directory.join("keeper")).unwrap();
    for block in &blocks {
        keeper.submit_block(block.clone()).unwrap();
    }

    let was = {
        let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
        for block in &blocks {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        catch_the_history_up(&wallet);

        let holdings = wallet.holdings();
        assert_eq!(
            holdings.stranded,
            Amount::ZERO,
            "while the node is the one that watched them fall, it can place \
             every one of them"
        );
        assert!(holdings.spendable > Amount::ZERO);
        assert!(
            wallet.node().write_ledger(),
            "the node wrote down the ledger it will start from next time"
        );
        holdings.spendable
    };

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    catch_the_history_up(&wallet);
    Stuck {
        wallet,
        keeper,
        forge,
        secret,
        directory,
        was,
    }
}

/// Puts a block on the chain both the wallet and the archivist follow.
fn one_more_block(stuck: &mut Stuck) {
    let block = stuck.forge.mine(&stuck.secret.public_key(), Vec::new());
    stuck.keeper.submit_block(block.clone()).unwrap();
    stuck.wallet.node().submit_block(block).unwrap();
}

/// **A wallet that lost its record gets its money back.**
///
/// The whole thing, from the money going out of reach to it being spent again.
/// What gets it back is one question to a node that kept the whole set, and
/// one check against the commitment this wallet's own node worked out from
/// blocks it validated itself. Nobody is trusted anywhere in it.
#[test]
fn a_wallet_that_lost_its_record_gets_its_money_back() {
    let mut stuck = a_wallet_that_lost_its_record("gets-it-back");
    let wallet = &stuck.wallet;
    assert_eq!(
        wallet.node().height(),
        Some((BLOCKS - 1) as u64),
        "it came back on the same chain"
    );
    assert!(
        wallet.progress().probation.is_none(),
        "and it validated its own way past the ledger it started from"
    );

    let waiting = wallet.holdings();
    assert!(
        waiting.stranded > Amount::ZERO,
        "money that cannot move: the wallet's own account still names these \
         notes and its node can no longer place them"
    );
    assert_eq!(
        waiting.spendable.checked_add(waiting.stranded).unwrap(),
        stuck.was,
        "none of it is lost, and none of it can be spent"
    );
    assert!(
        waiting.unprovable.iter().all(|one| one.fell_at.is_some()),
        "and the wallet wrote down where each of them landed while its node \
         could still say, which is the whole of what makes them askable about"
    );

    // Nobody to ask yet, and it says so rather than naming a service.
    let alone = wallet.recover_stranded();
    assert_eq!(alone.asked, 0);
    assert_eq!(alone.rebuilt, 0);
    let words = alone.words().expect("a wallet with stuck money says so");
    assert!(
        words.contains("--archive"),
        "and says what would fix it: {words}"
    );

    // Now it has somebody to ask.
    assert!(wallet.reach(stuck.keeper.address()));
    wait_for("the archivist to say what it keeps", || {
        wallet.node().archiving_peers() == 1
    });

    let recovery = wallet.recover_stranded();
    assert_eq!(
        recovery.archivists, 1,
        "it found the one node that can help"
    );
    assert_eq!(recovery.refused, 0, "nothing came back that did not fold");
    assert_eq!(
        recovery.rebuilt, recovery.stranded,
        "and every note it could ask about was placed"
    );

    let mended = wallet.holdings();
    assert_eq!(mended.stranded, Amount::ZERO, "nothing is stuck any more");
    assert_eq!(
        mended.spendable, stuck.was,
        "and the balance is what it was"
    );

    // And it is money, not a number: an amount that could not be reached while
    // the paths were missing is spent, and an independent miner that checks
    // the transfer against its own copy of the set carries it.
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    let beyond = waiting.spendable.checked_add(cairn("50")).unwrap();
    assert!(beyond <= mended.spendable);

    let fee = wallet.floor_for(recipient, beyond);
    let sent = wallet.send(recipient, beyond, fee).unwrap();
    assert!(
        sent.from_cold > 0,
        "the money that moved was money that had been put away"
    );

    let carried: Vec<Transfer> = wallet.node().with_chain(|chain| {
        chain
            .pooled_transfers()
            .map(|(_, transfer)| transfer.clone())
            .collect()
    });
    assert_eq!(carried.len(), 1, "the transfer reached the pool");
    let miner = SecretKey::from_bytes(&[7; 32]).public_key();
    let block = stuck.forge.mine(&miner, carried);
    assert_eq!(
        block.transfers.len(),
        1,
        "a miner holding its own copy of the set accepted the paths this \
         wallet was handed by a stranger"
    );
    stuck.wallet.node().submit_block(block).unwrap();

    stuck.keeper.shutdown();
    drop(stuck.wallet);
    let _ = std::fs::remove_dir_all(&stuck.directory);
}

/// **What could not be reached before is what could not be spent.**
///
/// The other half of the same story, said as a refusal. Before the paths come
/// back, a payment that needs the stuck money is turned away with the numbers
/// rather than being built and refused by the network, and the wallet's own
/// account of it names the money that is out of reach.
#[test]
fn a_payment_that_needs_the_stuck_money_is_refused_until_it_comes_back() {
    let stuck = a_wallet_that_lost_its_record("refused-until");
    let wallet = &stuck.wallet;
    let waiting = wallet.holdings();
    assert!(waiting.stranded > Amount::ZERO);

    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    let beyond = waiting.spendable.checked_add(cairn("50")).unwrap();
    match wallet.send(recipient, beyond, cairn("1")) {
        Err(WalletError::NotEnough { have, stranded, .. }) => {
            assert_eq!(have, waiting.spendable);
            assert_eq!(
                stranded, waiting.stranded,
                "and it says how much of the shortfall is money it holds and \
                 cannot reach, rather than only that there is not enough"
            );
        }
        other => panic!("a payment beyond what can be reached was not refused: {other:?}"),
    }

    assert!(wallet.reach(stuck.keeper.address()));
    wait_for("the archivist to say what it keeps", || {
        wallet.node().archiving_peers() == 1
    });
    assert!(wallet.recover_stranded().rebuilt > 0);

    let fee = wallet.floor_for(recipient, beyond);
    wallet
        .send(recipient, beyond, fee)
        .expect("the same payment goes through once the paths are back");

    stuck.keeper.shutdown();
    drop(stuck.wallet);
    let _ = std::fs::remove_dir_all(&stuck.directory);
}

/// **A path that has gone stale is not offered, and is asked for again.**
///
/// GUARD, and the reason a rebuilt path is not simply kept. A path folds from
/// the place a note sits up to a single value the whole set comes to, and that
/// value moves every time a note falls anywhere, so a path that was right a
/// minute ago can be wrong now. A wallet that went on offering one would be
/// building payments nobody will carry, and telling its owner they had money
/// to spend that the network will refuse.
///
/// So each one is checked again, against the set as it stands, every time the
/// money is counted, and the wallet asks again rather than waiting out the
/// pause that keeps a page from asking once a second.
#[test]
fn a_path_that_has_gone_stale_is_not_offered_and_is_asked_for_again() {
    let mut stuck = a_wallet_that_lost_its_record("gone-stale");
    assert!(stuck.wallet.reach(stuck.keeper.address()));
    wait_for("the archivist to say what it keeps", || {
        stuck.wallet.node().archiving_peers() == 1
    });
    assert!(stuck.wallet.recover_stranded().rebuilt > 0);
    assert_eq!(stuck.wallet.holdings().stranded, Amount::ZERO);

    // Blocks, until enough notes have fallen to change the shape of the set
    // under one of those paths. It takes a run of them rather than one,
    // because a place only moves when the trees around it merge.
    let mut blocks = 0;
    while stuck.wallet.holdings().stranded == Amount::ZERO && blocks < 64 {
        one_more_block(&mut stuck);
        blocks += 1;
    }
    let gone = stuck.wallet.holdings();
    assert!(
        gone.stranded > Amount::ZERO,
        "after {blocks} blocks no path had gone stale, so this test is no \
         longer testing what it says"
    );

    // And the pause that keeps a page from asking once a second does not hold
    // it back here, because this is not the same question as last time: it is
    // about a place that was answered for and has stopped being answerable.
    let again = stuck.wallet.recover_stranded();
    assert!(
        again.rebuilt > 0,
        "the wallet asked again at once rather than waiting"
    );
    assert_eq!(stuck.wallet.holdings().stranded, Amount::ZERO);

    stuck.keeper.shutdown();
    drop(stuck.wallet);
    let _ = std::fs::remove_dir_all(&stuck.directory);
}

//! What a wallet needs besides its key to move money that has fallen cold.
//!
//! A note that has left the set every node keeps can only be spent alongside a
//! path showing where it sits. The path goes stale and can be rebuilt on
//! request; the place it is a path to is fixed for good when the note falls,
//! and it is the only handle anybody has on that note. The set is a list of
//! hashes with no name attached to any of them, so nothing in it can be looked
//! up by the key that owns it: an archivist holding every leaf rebuilds a path
//! for a place it is told, and cannot find a place it is not told.
//!
//! So there are two records and not one. The key is what makes the money
//! spendable. The account beside it is what makes it reachable, and a restore
//! that carries the first without the second leaves money that is provably
//! owned and that nothing here can get to. These tests fix where that line
//! falls: what has to have been written down, what a stranger can be asked for
//! afterwards, and what nobody can supply at any price.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::Amount;
use cairn_wallet::{Recovery, Wallet};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The opening run of blocks, one in every [`EVERY`] of them paying this key.
///
/// Long enough that the notes it pays leave the hot set well below the point a
/// ledger written at the end of it is anchored at.
const PAID: usize = 120;

/// One block in this many pays this key, and the rest pay a stranger.
///
/// So that the notes this key ends up holding fit inside one question:
/// `cairn_net::message::MAX_PROVEN` places is what a single `GetProofs`
/// carries, and a wallet with more than that gets them back over several
/// rounds spaced by its own pause. That is real behaviour and is not what
/// these tests are about.
const EVERY: usize = 3;

/// Blocks mined to somebody else afterwards.
///
/// More than `cairn_ledger::state::GRACE_BLOCKS`, so that a ledger written at
/// the end of them carries a window reaching none of this key's notes. That
/// window is the only thing a node coming back from a written ledger can take
/// a fallen note up from.
const MOVED_ON: usize = 100;

/// Shallow wherever a number chosen for a live network would only cost mining,
/// and a hot set small enough that notes reach the cold set in a few blocks
/// rather than in months. The maturity rule is off because nothing here is
/// about maturity and the money has to be reachable.
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
        "cairn-key-alone-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// Waits for something to become true, or says what it was waiting for.
///
/// A minute, for the reason the recovery suite gives one: what is waited on is
/// milliseconds of work inside this process, and the deadline exists for the
/// case where it never happens at all. It costs no time when the condition is
/// met, so it measures the code and not the machine.
fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// Reads its way to the end of the chain, which is what fills the account.
fn catch_the_history_up(wallet: &Wallet) {
    while wallet.follow() > 0 {}
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

    fn mine_many(&mut self, count: usize, to: &cairn_crypto::PublicKey) -> Vec<Block> {
        (0..count).map(|_| self.mine(to)).collect()
    }
}

/// The chain everything here runs on, and the key it paid.
struct Chain {
    directory: PathBuf,
    key_file: PathBuf,
    data: PathBuf,
    /// Blocks paying this key, then blocks paying somebody else.
    paid: Vec<Block>,
    moved_on: Vec<Block>,
}

fn a_chain_that_paid_this_key(name: &str) -> Chain {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[3; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let stranger = SecretKey::from_bytes(&[11; 32]).public_key();
    let mine = secret.public_key();
    let mut forge = Forge::new();
    let paid: Vec<Block> = (0..PAID)
        .map(|at| {
            if at % EVERY == 0 {
                forge.mine(&mine)
            } else {
                forge.mine(&stranger)
            }
        })
        .collect();
    let moved_on = forge.mine_many(MOVED_ON, &stranger);
    let data = directory.join("data");
    Chain {
        directory,
        key_file,
        data,
        paid,
        moved_on,
    }
}

/// The wallet's own account of what it was paid, which lives beside the key.
fn account(data: &Path) -> PathBuf {
    data.join("history.dat")
}

/// Writes the ledger down and drops the blocks below it, which is the ordinary
/// life of a node rather than a fault.
///
/// Keeping every block for ever is the one thing this design exists not to do.
/// What the drop takes with it is every place this machine had written down
/// for a fallen note, because a place is a fact about this machine and a
/// ledger carries neither the asking nor the answer.
fn let_the_blocks_below_the_ledger_go(wallet: &Wallet, gone_by: u64) {
    assert!(wallet.node().write_ledger(), "the ledger went down first");
    wallet.node().keep_blocks(1);
    wait_for("the node to drop the blocks below its ledger", || {
        wallet.node().archived_at(gone_by).is_none()
    });
}

/// **A place only the node knew is written down, and outlives the node's own
/// memory of it.**
///
/// The shape a wallet meets by default rather than by misfortune. Its node
/// starts from a ledger, and a ledger carries the window of blocks below the
/// point it was written at, so the node knows where the notes in that window
/// fell while the wallet's own reading of the chain never saw the blocks that
/// paid them. The account used to refuse exactly those: a place for a note it
/// had not read a block for was treated as a claim about somebody else's
/// money.
///
/// So the node was the only record of them, and the next time it started from
/// a ledger of its own the window had moved past them and the record was gone.
/// The money did not become stranded, which is a state a wallet can name and
/// ask about. It left the balance.
#[test]
fn a_place_only_the_node_knew_is_written_down_and_outlives_it() {
    let chain = a_chain_that_paid_this_key("place-outlives-the-node");
    let top_of_the_paid_run = (PAID - 1) as u64;

    // A wallet that read every block it was paid in, wrote its ledger down,
    // and let the blocks below it go.
    {
        let (wallet, _) = Wallet::open(&chain.key_file, params(), &chain.data).unwrap();
        for block in &chain.paid {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        catch_the_history_up(&wallet);
        let_the_blocks_below_the_ledger_go(&wallet, 0);
        wallet.shutdown();
    }

    // And now the account goes: a disk that was replaced, a wallet started
    // against a directory it did not write, a restore from the key alone. What
    // is left is a node holding a ledger, and a key.
    std::fs::remove_file(account(&chain.data)).unwrap();

    let held = {
        let (wallet, _) = Wallet::open(&chain.key_file, params(), &chain.data).unwrap();
        catch_the_history_up(&wallet);
        assert!(
            wallet.node().archived_at(0).is_none(),
            "none of what follows came from reading the blocks: they are gone"
        );
        let holdings = wallet.holdings();
        assert!(
            holdings.total() > Amount::ZERO,
            "the window the ledger carried holds notes this key owns, and the \
             node took every one of them up"
        );
        assert_eq!(
            holdings.stranded,
            Amount::ZERO,
            "none of it is out of reach while the node is the one holding the \
             places"
        );

        // The chain moves on past that window, and the node writes a ledger
        // whose own window reaches none of these notes.
        for block in &chain.moved_on {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        catch_the_history_up(&wallet);
        let_the_blocks_below_the_ledger_go(&wallet, (PAID + 10) as u64);
        wallet.shutdown();
        holdings.total()
    };

    let (wallet, _) = Wallet::open(&chain.key_file, params(), &chain.data).unwrap();
    catch_the_history_up(&wallet);
    let after = wallet.holdings();
    assert_eq!(
        after.total(),
        held,
        "the same money, after a restart that took away every place the node \
         itself knew. Money that leaves a balance without a word is the worst \
         thing a wallet can tell anyone"
    );
    assert!(
        after.stranded > Amount::ZERO,
        "and it is named as money out of reach, which is what it is: the node \
         can no longer place any of it"
    );
    assert!(
        after.unprovable.iter().all(|one| one.fell_at.is_some()),
        "every note of it carrying the place it fell at, which is the whole of \
         what makes it askable about"
    );
    assert!(
        wallet.node().archived_at(top_of_the_paid_run).is_none(),
        "with nothing to read it back from: the blocks that paid this key are \
         long gone off this disk"
    );

    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&chain.directory);
}

/// **A restore that carries the key and not the account finds nothing at all.**
///
/// The boundary, and it is further out than "money that can be seen and not
/// moved". A node that has written its ledger down drops the blocks below it,
/// so a wallet starting there cannot read its way back to the payments it
/// received: the blocks are not on the disk and nothing on the network indexes
/// the chain by owner. What is left is the window the ledger carries, and
/// below that the wallet does not know it owns anything.
///
/// The money is still there and still this key's. Nothing here can name it, so
/// nothing here can ask about it either, and connecting to a machine that kept
/// every leaf of the cold set changes nothing: an archivist turns a place into
/// a path, and a place is exactly what was lost.
///
/// What the wallet does say is how far back its account reaches, which is the
/// one true thing it has: a face reading that can tell its owner the balance
/// is about a stretch of the chain rather than about their whole life.
#[test]
fn a_restore_from_the_key_alone_finds_nothing_and_says_how_far_back_it_looked() {
    let chain = a_chain_that_paid_this_key("key-alone");

    // A node that kept every leaf the cold set ever held. Nobody pays it to,
    // and the person who needs it is whoever lost their own path.
    let (keeper, _) =
        Node::open_archiving(params(), loopback(), chain.directory.join("keeper")).unwrap();
    for block in chain.paid.iter().chain(&chain.moved_on) {
        keeper.submit_block(block.clone()).unwrap();
    }

    let backup = chain.directory.join("account.backup");
    let whole = {
        let (wallet, _) = Wallet::open(&chain.key_file, params(), &chain.data).unwrap();
        for block in chain.paid.iter().chain(&chain.moved_on) {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        catch_the_history_up(&wallet);
        let holdings = wallet.holdings();
        assert!(holdings.total() > Amount::ZERO, "it was paid");
        assert!(wallet.node().write_ledger());
        wallet.shutdown();
        std::fs::copy(account(&chain.data), &backup).unwrap();
        holdings.total()
    };

    // The account goes, and the key stays. This is a restore from a written
    // down key, and it is the shape somebody who kept the one thing they were
    // told to keep will be in.
    std::fs::remove_file(account(&chain.data)).unwrap();

    {
        let (wallet, _) = Wallet::open(&chain.key_file, params(), &chain.data).unwrap();
        catch_the_history_up(&wallet);
        let holdings = wallet.holdings();
        assert_eq!(
            holdings.total(),
            Amount::ZERO,
            "not stranded, which is a state a wallet can name and ask about. \
             Absent: the blocks that paid this key are off the disk, and the \
             set they fell into is a list of hashes with no owner attached"
        );
        let covered = wallet.history_covers();
        assert!(
            covered.from.is_some_and(|from| from > 0),
            "and the wallet says how far back it looked rather than implying \
             it looked at everything: {covered:?}"
        );

        // The machine that keeps every leaf is connected, and it makes no
        // difference. It answers about a place, and there is no place here to
        // put to it.
        assert!(wallet.reach(keeper.address()));
        wait_for("the archivist to say what it keeps", || {
            wallet.node().archiving_peers() >= 1
        });
        let asked = wallet.recover_stranded();
        assert_eq!(
            asked.stranded, 0,
            "there is not even anything to call stranded"
        );
        assert!(
            asked.words().is_none(),
            "so there is nothing to say about it"
        );
        wallet.shutdown();
    }

    // And the other half of the same fact: the account is a file, and a
    // restore that carries it gets the money back. This is what a backup of a
    // wallet has to contain besides the key.
    std::fs::copy(&backup, account(&chain.data)).unwrap();
    let (wallet, _) = Wallet::open(&chain.key_file, params(), &chain.data).unwrap();
    catch_the_history_up(&wallet);
    let holdings = wallet.holdings();
    assert_eq!(
        holdings.total(),
        whole,
        "every note back, named out of the account rather than out of any \
         block: the blocks are gone"
    );
    assert!(
        holdings.stranded > Amount::ZERO,
        "and out of reach, because this node can place none of them"
    );
    assert!(
        holdings.unprovable.iter().all(|one| one.fell_at.is_some()),
        "each carrying the place the account wrote down while the node could \
         still say"
    );

    assert!(wallet.reach(keeper.address()));
    wait_for("the archivist to say what it keeps", || {
        wallet.node().archiving_peers() >= 1
    });
    let mended = wallet.recover_stranded();
    assert_eq!(
        mended.unplaceable, 0,
        "every one of them could be asked about"
    );
    assert_eq!(
        mended.rebuilt, mended.stranded,
        "and every one of them was answered for"
    );
    assert_eq!(
        wallet.holdings().stranded,
        Amount::ZERO,
        "so the money can move again"
    );

    keeper.shutdown();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&chain.directory);
}

/// **A wallet that can ask about some of its stuck money says so about the
/// rest.**
///
/// Every sentence a wallet has for stuck money ends in something worth doing:
/// wait, connect to an archivist, try another peer. None of them is true of a
/// note whose place was never written down, and a wallet holding both used to
/// print only the first kind. Somebody reading it would connect an archivist,
/// watch half the money come back, and go on waiting for the half that no
/// amount of waiting reaches.
#[test]
fn what_can_never_be_asked_about_is_not_reported_as_worth_waiting_for() {
    let both = Recovery {
        stranded: 4,
        unplaceable: 1,
        asked: 2,
        archivists: 1,
        answered: 2,
        rebuilt: 3,
        refused: 0,
    };
    let words = both.words().expect("four notes are stuck");
    assert!(
        words.contains("cannot ask about at all"),
        "the note nobody can be asked about is named: {words}"
    );
    assert!(
        words.contains("nothing here reaches them"),
        "and what that means is said rather than left to be worked out: {words}"
    );

    // The same shape with nobody connected. The advice to go and find an
    // archivist is still right about the three, and still not about the one.
    let alone = Recovery {
        stranded: 4,
        unplaceable: 1,
        asked: 0,
        archivists: 0,
        answered: 0,
        rebuilt: 0,
        refused: 0,
    };
    let words = alone.words().expect("four notes are stuck");
    assert!(
        words.contains("--archive"),
        "what would fix the three is still said: {words}"
    );
    assert!(
        words.contains("cannot ask about at all"),
        "and so is what will not fix the fourth: {words}"
    );

    // And when there is nothing else to say, it is said on its own rather
    // than twice.
    let none = Recovery {
        stranded: 2,
        unplaceable: 2,
        ..Recovery::default()
    };
    let words = none.words().expect("two notes are stuck");
    assert!(
        words.contains("cannot spend and cannot ask about"),
        "{words}"
    );
    assert!(
        !words.contains("--archive"),
        "nothing here would be fixed by connecting to one: {words}"
    );
}

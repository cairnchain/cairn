//! Where a note landed, when the block it fell in is undone.
//!
//! The account writes down where each of this key's fallen notes sits,
//! because a node restarted from a written ledger no longer knows, and a place
//! is the one handle an archivist can be asked by. It kept the first place it
//! was told, on the reasoning that a place is fixed the moment a note falls
//! and never moves.
//!
//! Fixed for as long as the block the note fell in stands, and no longer. A
//! note falls when the hot set runs out of room, which can be long after the
//! block that paid it, so a note paid below the reach of any reorganisation
//! can still fall inside it. Undoing a switch keeps the place of every note
//! paid at or below its fork, and the branch that wins can put the note
//! somewhere else: here,
//! by spending an older note the losing branch let fall first, so the note
//! falls one place earlier.
//!
//! The account then kept the losing branch's place with its own node naming
//! the right one. While the node ran nothing showed, because the node's word
//! is read first. Once it restarted from its ledger and forgot, the file was
//! the only record, and it named somebody else's leaf: an archivist asked
//! about it answered for that leaf, the answer did not fold, and the money was
//! stranded for good.

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

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::GRACE_BLOCKS;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::Amount;
use cairn_wallet::history::History;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The first height the two branches disagree about.
const FORK: u64 = 20;
/// Blocks on the branch that loses. Enough that the tip sits more than the
/// reach of a reorganisation above the block that paid this key's note, so
/// its place is kept however the account judges what a switch can reach, and
/// few enough to be undone.
const LOSING: u64 = 6;

/// A hot set of four, so a note falls four blocks after it is paid, and a
/// reorganisation reach of eight.
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
        "cairn-moved-place-{name}-{}-{:?}",
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

    fn fork(&self) -> Self {
        Self {
            params: self.params,
            state: self.state.clone(),
            clock: self.clock,
        }
    }

    fn mine_with(&mut self, to: &PublicKey, transfers: Vec<Transfer>) -> Block {
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

    fn mine(&mut self, to: &PublicKey) -> Block {
        self.mine_with(to, Vec::new())
    }
}

fn paid_by(block: &Block) -> (NoteId, Note) {
    block.coinbase.created_notes()[0]
}

fn watched_at(wallet: &Wallet, id: &NoteId) -> Option<u64> {
    wallet
        .node()
        .with_chain(|chain| chain.state().watched_position(id))
}

fn written_at(data: &std::path::Path, id: &NoteId) -> Option<u64> {
    let (history, why) = History::load(&data.join("history.dat"));
    assert_eq!(why, None, "the account read back");
    history.where_it_fell(id)
}

/// Two branches from one prefix, and a wallet that has read the one that will
/// lose.
struct Scene {
    directory: PathBuf,
    key_file: PathBuf,
    data: PathBuf,
    /// This key's note, paid three blocks below the fork.
    ours: NoteId,
    common: Vec<Block>,
    winning: Vec<Block>,
    /// The winning branch, to go on mining.
    rival: Forge,
    other: PublicKey,
}

impl Scene {
    fn new(name: &str) -> Self {
        let directory = scratch(name);
        std::fs::create_dir_all(&directory).unwrap();
        let key_file = directory.join("key");
        let secret = SecretKey::from_bytes(&[3; 32]);
        cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
        let data = directory.join("data");
        let mine = secret.public_key();
        let stranger_secret = SecretKey::from_bytes(&[11; 32]);
        let stranger = stranger_secret.public_key();
        let other = SecretKey::from_bytes(&[12; 32]).public_key();

        // Below the fork: the stranger is paid four blocks before it and this
        // key three, so when the branches part, the hot set holds the
        // stranger's note, then this key's, then two more.
        let mut forge = Forge::new();
        let common: Vec<Block> = (0..FORK)
            .map(|height| {
                let to = if height == FORK - 4 {
                    &stranger
                } else if height == FORK - 3 {
                    &mine
                } else {
                    &other
                };
                forge.mine(to)
            })
            .collect();
        let (older, older_note) = paid_by(&common[usize::try_from(FORK - 4).unwrap()]);
        let (ours, _) = paid_by(&common[usize::try_from(FORK - 3).unwrap()]);
        let mut rival = forge.fork();

        // The losing branch lets the stranger's note fall first and this key's
        // second.
        let losing: Vec<Block> = (0..LOSING).map(|_| forge.mine(&other)).collect();

        // The winning branch spends the stranger's note while it is still hot,
        // so this key's is the oldest left and falls first, one place earlier.
        // One block longer, so it outweighs the other.
        let mut spend = Transfer::new(vec![Input::hot(older)], vec![older_note]);
        spend.sign_input(params().network, 0, &older_note, &stranger_secret);
        let mut winning = vec![rival.mine_with(&other, vec![spend])];
        winning.extend((0..LOSING).map(|_| rival.mine(&other)));

        let scene = Self {
            directory,
            key_file,
            data,
            ours,
            common,
            winning,
            rival,
            other,
        };

        let (wallet, _) = Wallet::open(&scene.key_file, params(), &scene.data).unwrap();
        for block in scene.common.iter().chain(&losing) {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        wallet.follow_to_the_tip();
        let first = watched_at(&wallet, &scene.ours).expect("the note fell on the losing branch");
        assert_eq!(
            written_at(&scene.data, &scene.ours),
            Some(first),
            "the account wrote down where the note fell, which is what it is for"
        );
        wallet.shutdown();
        scene
    }

    fn open(&self) -> Wallet {
        Wallet::open(&self.key_file, params(), &self.data)
            .unwrap()
            .0
    }

    /// Hands the wallet the winning branch, and says where the note sat before.
    fn reorganise(&self, wallet: &Wallet) -> u64 {
        let first = written_at(&self.data, &self.ours).unwrap();
        for block in &self.winning {
            wallet.node().submit_block(block.clone()).unwrap();
        }
        assert_eq!(
            wallet.progress().height,
            Some(FORK + LOSING),
            "the node reorganised onto the heavier branch"
        );
        first
    }
}

/// The account writes down the place the winning branch gave a note, not the
/// one the branch it left gave it.
///
/// Nothing asked this. A note paid below the reach of any reorganisation that
/// fell inside it kept its place from the losing branch, while its own node
/// named another, and after a restart from a written ledger an archivist was
/// asked about somebody else's leaf and the money stayed stranded.
#[test]
fn a_place_a_reorganisation_moved_is_written_down_where_the_winning_branch_put_it() {
    let mut scene = Scene::new("moved");

    // Somebody who kept every leaf of the winning branch, to ask afterwards.
    let (keeper, _) =
        Node::open_archiving(params(), loopback(), scene.directory.join("keeper")).unwrap();
    for block in scene.common.iter().chain(&scene.winning) {
        keeper.submit_block(block.clone()).unwrap();
    }

    {
        let wallet = scene.open();
        let first = scene.reorganise(&wallet);
        wallet.follow_to_the_tip();
        let moved = watched_at(&wallet, &scene.ours).expect("the note fell on the winning branch");
        assert_ne!(
            moved, first,
            "the branches were meant to put the note at two different places"
        );
        assert_eq!(
            written_at(&scene.data, &scene.ours),
            Some(moved),
            "the account kept the place the losing branch gave the note, while its own node \
             named another"
        );

        // Far enough on that the note leaves the window a written ledger
        // carries, so the restart below leaves the file as the only record.
        let beyond = u64::try_from(GRACE_BLOCKS).unwrap() + 2;
        for _ in 0..beyond {
            let block = scene.rival.mine(&scene.other);
            keeper.submit_block(block.clone()).unwrap();
            wallet.node().submit_block(block).unwrap();
        }
        wallet.follow_to_the_tip();
        assert!(wallet.node().write_ledger(), "the node wrote its ledger");
        wallet.shutdown();
    }

    let wallet = scene.open();
    wallet.follow_to_the_tip();
    let before = wallet.holdings();
    assert!(
        before.unprovable.iter().any(|one| one.id == scene.ours),
        "the restarted node was meant to have forgotten where the note sits"
    );

    assert!(wallet.reach(keeper.address()));
    wait_for("the archivist to say what it keeps", || {
        wallet.node().archiving_peers() >= 1
    });
    let asked = wallet.recover_stranded();
    let after = wallet.holdings();
    assert_eq!(
        after.stranded,
        Amount::ZERO,
        "an archivist holding every leaf rebuilt {} of the stranded notes, and {} is still \
         stranded: the place asked about was the losing branch's",
        asked.rebuilt,
        after.stranded
    );
    assert!(
        after.notes.iter().any(|held| held.id == scene.ours),
        "the note was meant to be spendable again once the archivist answered"
    );

    keeper.shutdown();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&scene.directory);
}

/// The same correction when the wallet stops before reading the winning
/// branch, and its node starts again from a ledger written after the switch.
///
/// A restarted node does not remember where notes fell, except the ones that
/// fell recently enough to travel in the ledger itself, which it takes up
/// again for the owners it follows. That is the whole of what lets the
/// account learn the new place here: it reads the branch it missed, starts
/// over because the chain changed under it, keeps the old place because the
/// note was paid below the reach, and then has to hear its node's answer.
/// Nothing asked this, so an account that went on believing the losing branch
/// across a restart passed.
#[test]
fn a_place_a_reorganisation_moved_is_corrected_after_a_restart_that_still_remembers() {
    let scene = Scene::new("restarted");
    {
        let wallet = scene.open();
        let first = scene.reorganise(&wallet);
        assert_eq!(
            written_at(&scene.data, &scene.ours),
            Some(first),
            "the account was meant to stop before reading the winning branch"
        );
        assert!(wallet.node().write_ledger(), "the node wrote its ledger");
        wallet.shutdown();
    }

    let wallet = scene.open();
    wallet.follow_to_the_tip();
    let moved = watched_at(&wallet, &scene.ours)
        .expect("a note that fell this recently travels in the ledger, and is followed again");
    assert_eq!(
        written_at(&scene.data, &scene.ours),
        Some(moved),
        "the account kept the losing branch's place across a restart, while its node named \
         the winning one"
    );

    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&scene.directory);
}

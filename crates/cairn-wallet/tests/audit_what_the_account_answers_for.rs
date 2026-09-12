//! What this key's own account of itself is evidence of, and what it is not.
//!
//! The account beside the chain answers one question: what this key held as of
//! the last block the account read. Three places in this crate read it as the
//! answer to a different one.
//!
//! `Wallet::reckon` reads it as the answer to what this key holds now, and
//! reports every note in it the node cannot place as money out of reach. That
//! is the right reading of a note the node stopped following. It is the wrong
//! reading of a note a block carried away while the account was a block
//! behind, and the account is a block behind on every face in this crate: the
//! page counts the money before it reads the chain, the `balance` command does
//! the same, and `send` never reads the chain at all.
//!
//! `Covered::from` is read as how far back the list of movements goes. It is
//! the first height the account read, which is a different number once the
//! account has dropped the oldest of them for age.
//!
//! `History::load` reports why a file that was there was not used. A file that
//! cannot be read at all is not one of the three reasons, so it is reported as
//! no file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::history::History;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-wallet-account-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
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

    fn mine(&mut self, to: &PublicKey, transfers: Vec<Transfer>) -> Block {
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

/// A wallet holding `blocks` worth of rewards, and the forge that paid them.
fn funded(name: &str, seed: u8, blocks: usize) -> (Wallet, Forge, PathBuf) {
    let directory = scratch(name);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[seed; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
    let mut forge = Forge::new();
    for _ in 0..blocks {
        let block = forge.mine(&secret.public_key(), Vec::new());
        wallet.node().submit_block(block).unwrap();
    }
    (wallet, forge, directory)
}

/// **Money a block carried away is counted again as money out of reach.**
///
/// The account holds the notes this key was paid and had not spent as of the
/// last block it read. `Wallet::reckon` takes every note in it the node can
/// place in neither tier and calls it stranded: real money, owned, and
/// unspendable until somebody rebuilds a path to it. That is exactly what a
/// note the node stopped following is.
///
/// It is also exactly what a note that has been spent looks like, and the
/// account cannot tell the two apart until it has read the block that spent
/// it. Nothing in this crate reads that block before counting the money. The
/// page counts before it reads; `balance` counts before it reads; `send` reads
/// no block ever.
///
/// So on the block that carries a payment, this key's own wallet adds the
/// notes it just handed over back onto its total, in a category whose whole
/// meaning is that the money is still yours.
#[test]
fn a_note_a_block_carried_away_is_not_money_this_wallet_still_holds() {
    let (wallet, mut forge, directory) = funded("carried-away", 1, 4);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    // The account reads its way to the tip, which is the state every face
    // leaves it in and the state a restart loads it in.
    while wallet.follow() > 0 {}
    let before = wallet.holdings();
    assert_eq!(before.spendable, cairn("200"), "four blocks at fifty");
    assert_eq!(before.total(), cairn("200"));
    assert_eq!(before.stranded, Amount::ZERO);

    let fee = cairn("0.5");
    let sent = wallet.send(recipient, cairn("120"), fee).unwrap();
    assert_eq!(sent.notes, 3, "three fifties cover a hundred and twenty");

    // A miner takes it out of the pool and puts it in a block, which every
    // node checks the way this one does.
    let carried: Vec<Transfer> = wallet.node().with_chain(|chain| {
        chain
            .pooled_transfers()
            .map(|(_, transfer)| transfer.clone())
            .collect()
    });
    assert_eq!(carried.len(), 1);
    let miner = SecretKey::from_bytes(&[7; 32]).public_key();
    let block = forge.mine(&miner, carried);
    wallet.node().submit_block(block).unwrap();

    // The chain now says this key holds two hundred less a hundred and twenty
    // and less the half that carried it. Nothing else is true of it.
    let after = wallet.holdings();
    let left = cairn("200")
        .checked_sub(cairn("120"))
        .unwrap()
        .checked_sub(fee)
        .unwrap();
    assert_eq!(
        after.spendable, left,
        "the change came back and the fee did not"
    );
    assert_eq!(
        after.stranded,
        Amount::ZERO,
        "the three notes that paid for this are the recipient's. A wallet that \
         counts them as its own money in an awkward place is counting money \
         that is not there: {:?}",
        after
            .unprovable
            .iter()
            .map(|one| one.note.value.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        after.total(),
        left,
        "and the total is what is left, not what was there"
    );

    // What the wallet would go on to say about it, which is the half that
    // reaches a person: every one of these notes is unplaceable, so the
    // sentence is the one with nothing to try in it.
    let words = wallet.recover_stranded().words();
    assert!(
        words.is_none(),
        "nothing is out of reach, so there is nothing to say: {words:?}"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// **A page can be made to ask a stranger where this key's spent notes sit.**
///
/// The same defect, one step further on. A note that had fallen carries the
/// place it fell at in the account, so a note spent out of the cold set is not
/// merely counted as stranded: the wallet goes out and asks the network to
/// rebuild a path to it, once every fifteen seconds, for as long as the page
/// is open.
///
/// Kept to what can be checked without a network: that the wallet puts the
/// place of a spent note on the list of places it means to ask about.
#[test]
fn a_place_this_wallet_no_longer_owns_is_not_a_place_to_ask_about() {
    let (wallet, mut forge, directory) = funded("spent-cold", 2, 4);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    while wallet.follow() > 0 {}

    let fee = cairn("0.5");
    wallet.send(recipient, cairn("120"), fee).unwrap();
    let carried: Vec<Transfer> = wallet.node().with_chain(|chain| {
        chain
            .pooled_transfers()
            .map(|(_, transfer)| transfer.clone())
            .collect()
    });
    let miner = SecretKey::from_bytes(&[7; 32]).public_key();
    let block = forge.mine(&miner, carried);
    wallet.node().submit_block(block).unwrap();

    let after = wallet.holdings();
    assert!(
        after.unprovable.is_empty(),
        "a spent note is not a note whose path has to be rebuilt, and this \
         wallet has {} of them on its list",
        after.unprovable.len()
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

fn key(seed: u8) -> PublicKey {
    SecretKey::from_bytes(&[seed; 32]).public_key()
}

/// One block paying `to`, with no work done on it. `History::take` reads a
/// block rather than judging one, so nothing here has to be mined.
fn paying(height: u64, to: PublicKey) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            network: NetworkId::TESTNET,
            height,
            previous: Hash32::ZERO,
            state_root: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 1_000_u64.saturating_add(height),
            difficulty: 1,
            total_work: u128::from(height),
            nonce: 0,
        },
        coinbase: CoinbaseTransaction::new(height, vec![Note::new(cairn("50"), to)]),
        transfers: Vec::new(),
    }
}

/// **The block a list of payments begins at is not the block the account
/// began at.**
///
/// The account keeps the newest `MAX_MOVEMENTS` and drops the rest, which is
/// the bound that stops a wallet running for years turning its own record into
/// the cost the design exists to avoid. What it does not do is move the height
/// the account says it starts at.
///
/// So `Covered::from` goes on naming the first block ever read, and both faces
/// print it as the lower edge of the list they have just shown: "As far back
/// as block 0: this wallet did not read what came before." The first half is
/// true of the account and the second is true of the wallet, and neither is
/// the question somebody reading the list is asking, which is how far back the
/// list goes. Told it reaches block 0, they read an empty stretch as nothing
/// having happened.
#[test]
fn how_far_back_a_list_reaches_is_not_where_the_account_started() {
    let mine = key(1);
    let mut history = History::new();
    // Comfortably past the bound, one payment in each block.
    for height in 0..4_200u64 {
        history.take(&paying(height, mine), mine);
    }

    let movements: Vec<_> = history.movements().copied().collect();
    assert_eq!(
        movements.len(),
        4096,
        "the account holds what it undertakes to hold"
    );
    let oldest = movements.last().unwrap();
    assert_eq!(
        oldest.height, 104,
        "and the hundred and four below it are gone"
    );

    assert_eq!(
        history.from(),
        Some(oldest.height),
        "the number a face prints as the lower edge of this list has to be a \
         block the list reaches. It says {:?}, and the oldest payment in the \
         list is at block {}: everything between is shown as a stretch in \
         which nothing happened",
        history.from(),
        oldest.height
    );
}

/// **A file that cannot be read is reported as no file at all.**
///
/// `History::load` names why a file that was there was not used, and the
/// reason reaches a person: an operator told the bytes changed under it looks
/// at hardware, one told the file is from a newer build looks at the version.
/// The reasons are worked out from the bytes, so they are only reached when
/// there are bytes. A file that is there and will not open at all, which is
/// the case where "this is worth looking into" is likeliest to be right, takes
/// the same way out as a wallet that has never run: an empty account and
/// nothing said.
///
/// A directory where the file goes is one way in, and it is the portable one.
/// A file whose mode was widened and narrowed again by a restore is the way
/// this is actually met.
#[test]
fn a_file_that_will_not_open_is_not_the_same_as_no_file() {
    let directory = scratch("unreadable");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("history.dat");

    // Nothing is there, and nothing is the matter.
    let (empty, why) = History::load(&path);
    assert!(empty.is_empty() && why.is_none(), "a wallet that never ran");

    // Something is there and it cannot be read.
    std::fs::create_dir(&path).unwrap();
    assert!(
        std::fs::read(&path).is_err(),
        "the file this test is about is one that will not open"
    );
    let (loaded, why) = History::load(&path);
    assert!(loaded.is_empty(), "either way the chain is read again");
    assert!(
        why.is_some(),
        "and either way somebody has to be told, because what is lost is the \
         same: every payment older than the oldest block this node still \
         holds. This says nothing at all"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

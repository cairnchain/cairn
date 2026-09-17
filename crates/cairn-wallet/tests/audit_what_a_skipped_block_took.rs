//! What an account keeps of a block it was never able to read.
//!
//! An account reads the chain forward, block by block, and a note leaves
//! `held` when the account reads the block that spent it. When the node has
//! let go of a block the account still needs, the account cannot read it: it
//! moves to where the log now begins and carries on from there.
//!
//! Everything that happened to this key in between is then simply not in the
//! account. A note spent inside that range stays in `held` for the life of
//! the file, and `reckon` reads `held` as what this key holds now. The node
//! cannot place the note in either tier, because it is not in either tier, so
//! it is counted as money whose proof has to be rebuilt.
//!
//! The balance is then wrong, upwards, by everything this key paid away while
//! it was not reading, and wrong in the one way a balance must never be:
//! `stranded` means money that is yours and needs a path rebuilding, which is
//! a sentence about somebody else's money.
//!
//! What the account can and cannot say about it is the whole of the care this
//! needs. A note it watched fall has a place written down, and a place is both
//! evidence that this key held the note and the only handle by which anyone
//! could be asked about it. A note that was still hot has neither: nothing to
//! point at, and nothing anyone could be asked. Only the second stops being
//! counted, and the reason is next door in
//! `audit_what_forgetting_throws_away`, which holds that a one block
//! reorganisation must not take anything out of a balance. A node restarted
//! from its own written ledger walks past blocks it no longer holds as a
//! matter of course, so a rule that did not narrow here would stop every
//! wallet on one from counting its stranded money at all, which is the worse
//! of the two defects and the one this project has already named.
//!
//! The account cannot tell what happened in that range: a note that fell out
//! of the hot set and a note that was spent are both simply gone from it, and
//! the hot set is capped by size rather than by age, so neither is something
//! the account can work out for itself. What it can do is know that it does
//! not know, which is what this holds it to.

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
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;
use cairn_wallet::history::History;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// Blocks paying this key, before the one that spends from it.
const OURS: usize = 5;

/// The whole chain the node ends up holding. Well past the ledger's own
/// height, so writing one leaves the block at `OURS` below where the log
/// begins.
const HEIGHT: usize = 90;

const FEE: u64 = 10_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-skipped-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// A chain that pays this key `OURS` times, then spends the first of those
/// notes away to a stranger, then goes on without it.
fn a_chain(ours: &SecretKey, stranger: &SecretKey) -> (Vec<Block>, NoteId, Amount) {
    let rules = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    let mut blocks = Vec::new();
    let mut first: Option<(NoteId, Note)> = None;

    for height in 0..HEIGHT {
        let paid_to = if height < OURS { ours } else { stranger };
        let at = state.next_height().unwrap();
        clock += 600;
        let coinbase = CoinbaseTransaction::new(
            at,
            vec![Note::new(rules.initial_reward, paid_to.public_key())],
        );

        // The block at `OURS` carries the payment. It is an ordinary spend of
        // an ordinary note, and the only thing about it that matters here is
        // that the account will never get to read it.
        let transfers = match (height == OURS, first) {
            (true, Some((id, note))) => {
                let paid = note
                    .value
                    .checked_sub(Amount::from_pebbles(FEE).unwrap())
                    .unwrap();
                let mut transfer = Transfer::new(
                    vec![Input::hot(id)],
                    vec![Note::new(paid, stranger.public_key())],
                );
                transfer.sign_input(rules.network, 0, &note, ours);
                vec![transfer]
            }
            _ => Vec::new(),
        };

        let block = assemble_block(&state, coinbase, transfers, &rules, clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut state, &block, &rules, NOW).unwrap();
        if height == 0 {
            first = Some((
                NoteId::new(block.coinbase.id(), 0),
                Note::new(rules.initial_reward, ours.public_key()),
            ));
        }
        blocks.push(block);
    }

    let (id, note) = first.unwrap();
    (blocks, id, note.value)
}

/// The list of movements has a hole in it, and nothing about the list gives it
/// away.
///
/// The blocks on both sides were read and their movements are here; the ones
/// in between read as a stretch in which nothing happened to this key. That is
/// what the note on `History::from` says must never be allowed to happen, and
/// it was answered where movements are dropped for age and nowhere else.
fn the_hole_in_the_list_is_named(wallet: &Wallet) {
    let covers = wallet.history_covers();
    assert_eq!(
        covers.from,
        Some(0),
        "the account did read from the first block, and saying otherwise would be the same \
         untruth the other way round"
    );
    assert_eq!(
        covers.behind(),
        0,
        "and it is up to date, which is what makes the hole invisible"
    );
    let missed = covers.missed_below.expect(
        "a wallet moved past seventy blocks says its list covers everything from block zero \
         to the tip, and a miner reading it sees rewards, then nothing, then rewards, with \
         no line saying which blocks it could not read",
    );
    assert!(
        missed > OURS as u64,
        "and the height it names has to reach past the blocks it skipped: it says {missed}"
    );
}

/// An account cannot count as its own the notes it paid away while it was not
/// reading.
#[test]
fn a_note_spent_in_a_block_the_account_skipped_is_not_this_key_s_money() {
    let ours = SecretKey::from_bytes(&[3; 32]);
    let stranger = SecretKey::from_bytes(&[9; 32]);
    let (chain, spent, worth) = a_chain(&ours, &stranger);

    let directory = scratch("paid-away");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &ours).unwrap();
    let data = directory.join("data");

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    // Everything up to the payment, and nothing after it.
    for block in chain.iter().take(OURS) {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    while wallet.follow() > 0 {}
    let before = wallet.holdings();
    assert_eq!(
        before.stranded,
        Amount::ZERO,
        "nothing is stranded while the account is up to date"
    );
    assert!(
        before.spendable >= worth,
        "the note it is about to pay away"
    );

    // The rest of the chain arrives while the account is not reading, and the
    // node writes its ledger, which is what cuts the log. Opening it again is
    // the ordinary life of a node, and it is what leaves the block carrying
    // the payment below where the log begins.
    for block in chain.iter().skip(OURS) {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    assert!(wallet.node().write_ledger());
    drop(wallet);

    // The same account file, so what follows is what this wallet remembers.
    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    let readable_from = wallet.node().blocks_from().unwrap_or(0);
    assert!(
        readable_from > OURS as u64,
        "this test needs the block carrying the payment to be one the node has \
         let go of, and the log begins at {readable_from}"
    );
    while wallet.follow() > 0 {}

    let after = wallet.holdings();
    let counted_as_ours: Vec<NoteId> = after.unprovable.iter().map(|one| one.id).collect();
    assert!(
        !counted_as_ours.contains(&spent),
        "the note this key paid away is among the notes this wallet says are its \
         own and cannot be proved. That list is what `recover_stranded` works \
         from, and for any note in it that this account had watched fall it is \
         also what gets handed to an archivist"
    );
    assert_eq!(
        after.stranded,
        Amount::ZERO,
        "{worth} that this key paid away is counted back onto its own balance as \
         money whose proof needs rebuilding. The account never read the block \
         that spent it, so the note never left `held`, and a note the node can \
         place in neither tier is read as one that fell"
    );

    // The other half of the rule, and the one that would be the worse defect:
    // nothing that is still this key's money may be hidden by this. Four notes
    // were never touched, the node still holds every one of them, and the
    // balance is down by exactly what was paid away.
    assert_eq!(
        after.spendable,
        before.spendable.checked_sub(worth).unwrap(),
        "the balance is down by something other than the note that was spent"
    );
    assert_eq!(
        after.total(),
        before.total().checked_sub(worth).unwrap(),
        "the note is counted somewhere it should not be"
    );

    // And it says so, rather than going quiet about a note it used to name.
    assert!(
        after.unaccounted.iter().any(|one| one.id == spent),
        "the wallet dropped the note without saying it had stopped answering \
         for it, which is the same silence by a shorter road"
    );
    assert!(
        after.unaccounted_note().is_some(),
        "there is nothing to show whoever holds the wallet"
    );

    // Giving up is done a whole account at a time, because a gap is a fact
    // about a range. Taking it back is done a note at a time, as each one is
    // found again, and that has to reach the file: a note that was merely
    // still in the hot set when the gap opened would otherwise stay marked for
    // ever, and the day it fell out of reach for real it would be left out of
    // the balance instead of counted as stranded. A balance that goes quietly
    // down is the worse of the two defects, so the fix must not introduce it.
    let (account, _) = History::load(&data.join("history.dat"));
    let given_up: Vec<NoteId> = account.unaccounted().collect();
    assert_eq!(
        given_up,
        vec![spent],
        "the account is still giving up on notes the node has just shown it"
    );

    the_hole_in_the_list_is_named(&wallet);

    let _ = std::fs::remove_dir_all(&directory);
}

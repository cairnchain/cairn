//! A place this file got wrong, offered as a path.
//!
//! Three things can say where one of this key's fallen notes sits, and the
//! note in `reckon` sets out how far each is trusted. What the node says it is
//! watching is this node's own bookkeeping and is taken as it stands. What
//! somebody else rebuilt is folded before it is offered, twice over. And what
//! this wallet wrote down is "trusted about as far as the file it came out
//! of", so a path found through it is folded too.
//!
//! That last fold is a guard, and nothing measured it. Taken out, the whole
//! suite passes: every test that reaches the recorded place reaches it with a
//! place that is right, so the fold never has anything to refuse.
//!
//! A place can be wrong without anybody being dishonest. It is fixed for as
//! long as the block the note fell in stands, and a branch this wallet later
//! leaves can put a different note there; the node's newer answer is written
//! over it, but only while the node still knows, and a node restarted from
//! its ledger does not. And the file is one a person can edit.
//!
//! What the fold buys is that a wrong place costs nothing but a note the
//! wallet says it cannot move. Without it the wallet offers a path to somebody
//! else's leaf, which no node will take: the money looks spendable, every
//! spend of it is refused, and nothing says why.

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
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;
use cairn_wallet::history::History;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
/// Long enough that some of this key's notes fell more than
/// `cairn_ledger::state::GRACE_BLOCKS` blocks below where a written ledger is
/// anchored. Anything nearer travels in the ledger itself.
const BLOCKS: usize = 100;

/// A hot set small enough that notes reach the cold one in a few blocks.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(8)
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-wrong-place-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn a_chain(to: &cairn_crypto::PublicKey) -> Vec<Block> {
    let rules = params();
    let mut state = LedgerState::new();
    let mut clock = 1_000u64;
    (0..BLOCKS)
        .map(|_| {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase =
                CoinbaseTransaction::new(height, vec![Note::new(rules.initial_reward, *to)]);
            let block =
                assemble_block(&state, coinbase, Vec::<Transfer>::new(), &rules, clock, 0).unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &rules, NOW).unwrap();
            block
        })
        .collect()
}

/// Reads the chain, writes the ledger, and starts again from it, which is what
/// takes the places out of the node's own hands and leaves the file as the
/// only record.
fn a_wallet_whose_node_forgot_the_places(
    name: &str,
    plant: Option<(NoteId, Amount, u64)>,
) -> (Wallet, PathBuf) {
    let directory = scratch(name);
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[3; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");
    let blocks = a_chain(&secret.public_key());

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    for block in &blocks {
        wallet.node().submit_block(block.clone()).unwrap();
    }
    wallet.follow_to_the_tip();
    assert!(wallet.node().write_ledger(), "the node wrote its ledger");
    drop(wallet);

    // Written after the wallet has read everything and before it starts
    // again. Planted any earlier, the node's own answer is written over it as
    // the notes fall. After the restart the node no longer knows where the
    // planted note sits, so the file is the only record, which is where a
    // place from a branch the wallet left ends up.
    if let Some((id, value, position)) = plant {
        let path = data.join("history.dat");
        let (mut history, why) = History::load(&path);
        assert_eq!(why, None, "the account read back");
        assert!(history.fell_at(id, value, position));
        history.save(&path).unwrap();
    }

    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    wallet.follow_to_the_tip();
    (wallet, data)
}

#[test]
fn a_place_this_file_got_wrong_is_not_offered_as_a_path() {
    // An honest run first, for two things: what the wallet says when every
    // place it holds is its own, and a place that really is somebody's, so
    // that what is planted below is a real leaf rather than an empty one. A
    // position nothing sits at is refused by the accumulator before the fold
    // is reached, and a test built on one measures nothing.
    let (honest_total, honest_data, forgotten) = {
        let (wallet, data) = a_wallet_whose_node_forgot_the_places("honest", None);
        let holdings = wallet.holdings();
        assert!(
            holdings.stranded > Amount::ZERO,
            "the node was meant to have forgotten where these notes sit"
        );
        let total = holdings.total();
        let forgotten: Vec<NoteId> = holdings.unprovable.iter().map(|one| one.id).collect();
        drop(wallet);
        (total, data, forgotten)
    };

    let (account, why) = History::load(&honest_data.join("history.dat"));
    assert_eq!(why, None, "the account read back");
    let places: Vec<(NoteId, u64)> = account
        .held()
        .filter_map(|(id, _)| Some((id, account.where_it_fell(&id)?)))
        .collect();
    // The note wearing the wrong place has to be one the restarted node cannot
    // place, or the node's own word is read before the file's and the fold is
    // never reached. The place it wears has to be one the node still holds a
    // path to, or the accumulator refuses it before the fold.
    let (mine, _) = *places
        .iter()
        .find(|(id, _)| forgotten.contains(id))
        .expect("this chain was meant to leave a note the restarted node cannot place");
    let (_, somebody_elses) = *places
        .iter()
        .find(|(id, _)| !forgotten.contains(id))
        .expect("and one it still places, whose place is a real leaf with a path to it");
    let value = params().initial_reward;

    // One note, wearing another's place. Every byte of the file is the shape a
    // wallet writes; what is wrong is which leaf the place points at.
    let (planted, _) =
        a_wallet_whose_node_forgot_the_places("planted", Some((mine, value, somebody_elses)));
    let holdings = planted.holdings();

    assert_eq!(
        holdings.total(),
        honest_total,
        "planting a place changed what the wallet says it holds altogether"
    );
    assert!(
        !holdings.notes.iter().any(|held| held.id == mine),
        "a path was built from a place that is not this note's, and the wallet called the money \
         spendable: {} spendable against {} stranded",
        holdings.spendable,
        holdings.stranded
    );
    assert!(
        holdings.unprovable.iter().any(|one| one.id == mine),
        "the note was neither spendable nor named as one the wallet cannot move"
    );
}

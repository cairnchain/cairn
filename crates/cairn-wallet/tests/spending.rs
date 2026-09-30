//! What the wallet does with money.
//!
//! This is the part where a mistake costs somebody their coins rather than
//! their afternoon, so the tests here are about the money and not about the
//! plumbing: that a transfer the wallet signs is one the rules accept, that
//! what it says it holds is what it holds, that it refuses rather than
//! guesses, and that nothing goes missing between what is spent and what
//! comes back as change.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;
use cairn_wallet::{Wallet, WalletError};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    // These tests mine a block and spend its reward straight away, which the
    // maturity rule exists to stop. Shortened rather than worked around, so
    // the rule is still in force and still tested; the wallet's own maturity
    // handling is exercised in `a_reward_is_kept_out_of_what_can_be_spent`.
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-wallet-{name}-{}-{:?}",
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

    /// One block paying `to`, carrying `transfers`.
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

/// A wallet holding `blocks` worth of mining rewards, and the forge that paid
/// them, so a test can carry on mining onto the same chain.
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

/// What the network will carry for this spend, which is no longer nothing.
fn floor(wallet: &Wallet, to: PublicKey, amount: Amount) -> Amount {
    wallet.floor_for(to, amount)
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

/// The one that matters most: a transfer the wallet built and signed has to be
/// one the rules accept. A wallet that signs wrongly does not lose an
/// afternoon, it loses the money, and it would look like it had worked.
#[test]
fn a_transfer_the_wallet_signs_is_one_a_block_will_carry() {
    let (wallet, mut forge, directory) = funded("signs", 1, 4);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let before = wallet.holdings().spendable;
    assert_eq!(before, cairn("200"), "four blocks at fifty");

    let sent = wallet.send(recipient, cairn("120"), cairn("0.5")).unwrap();
    assert_eq!(sent.amount, cairn("120"));
    assert_eq!(sent.fee, cairn("0.5"));

    // Taken out of the wallet's own pool and put in a block by a miner who
    // checks it the way every node will.
    let carried: Vec<Transfer> = wallet.node().with_chain(|chain| {
        chain
            .pooled_transfers()
            .map(|(_, transfer)| transfer.clone())
            .collect()
    });
    assert_eq!(carried.len(), 1, "the transfer reached the pool");

    let miner = SecretKey::from_bytes(&[7; 32]).public_key();
    let block = forge.mine(&miner, carried);
    wallet.node().submit_block(block).unwrap();

    // What is left is what was there, less what was sent and what was paid to
    // carry it. Nothing is allowed to go missing in between.
    let after = wallet.holdings().spendable;
    assert_eq!(
        after,
        before
            .checked_sub(cairn("120"))
            .unwrap()
            .checked_sub(cairn("0.5"))
            .unwrap(),
        "the change came back and the fee did not"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// On a network that burns a price for every place in the hot set, a payment
/// at the wallet's floor is pooled and mined, and its blank quote carries that
/// price over the floor for the note that can fall.
///
/// The wallet priced a place at the pool's old weight, five hundred and twelve
/// bytes at ten pebbles, and knew nothing of a price the rules ask. Its floor
/// was below what every pool now refuses, so a payment at the floor it quoted
/// was turned away, and its margin for a falling note was below the burn that
/// note adds, so a payment quoted for exactly that case became one no block
/// may carry.
#[test]
fn a_payment_at_the_quote_is_pooled_and_mined_where_a_place_is_priced() {
    let price = cairn_ledger::validation::PLACE_PRICE;
    let rules = params().with_place_price(price);
    let directory = scratch("priced");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[31; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let (wallet, _) = Wallet::open(&key_file, rules, &directory.join("data")).unwrap();
    let mut forge = Forge {
        params: rules,
        state: LedgerState::new(),
        clock: 1_000,
    };
    for _ in 0..2 {
        let block = forge.mine(&secret.public_key(), Vec::new());
        wallet.node().submit_block(block).unwrap();
    }
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let least = wallet.floor_for(recipient, cairn("1"));
    let quoted = wallet.fee_for(recipient, cairn("1"));
    assert_eq!(
        quoted.checked_sub(least),
        Some(price),
        "the quote's margin for the one note that can fall is not the place price"
    );
    // What the confirmation says before paying: the burn of the one place the
    // payment takes, and nothing for a spend that cannot be drafted.
    assert_eq!(
        wallet.burn_of_the_fee(recipient, cairn("1"), least),
        Some(price),
        "the part of the fee said to be burned is not the price of the place the payment takes"
    );
    assert_eq!(
        wallet.burn_of_the_fee(recipient, Amount::ZERO, least),
        None,
        "a spend that cannot be drafted was said to burn something"
    );
    let sent = wallet
        .send(recipient, cairn("1"), least)
        .expect("a payment at the wallet's own floor was refused by its own pool");
    assert_eq!(sent.fee, least);

    // A miner takes it from the pool and claims what the rules let it keep.
    let (chosen, kept) = wallet
        .node()
        .with_chain(|chain| chain.selection(rules.max_transfers_per_block));
    assert_eq!(chosen.len(), 1, "the payment reached the pool");
    assert_eq!(
        kept.checked_add(price),
        Some(least),
        "the burn is the price"
    );
    let height = forge.state.next_height().unwrap();
    forge.clock += 600;
    let claimed = rules.reward_at(height).checked_add(kept).unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(
            claimed,
            SecretKey::from_bytes(&[7; 32]).public_key(),
        )],
    );
    let before = forge.state.supply();
    let block = assemble_block(&forge.state, coinbase, chosen, &rules, forge.clock, 0)
        .expect("a block carrying the payment and claiming what it may is valid");
    let block = mine_block(block, ATTEMPTS).unwrap();
    connect_block(&mut forge.state, &block, &rules, NOW).unwrap();
    wallet.node().submit_block(block).unwrap();
    assert_eq!(
        forge.state.supply().as_pebbles(),
        before.as_pebbles() + rules.reward_at(height).as_pebbles() - price.as_pebbles(),
        "the burn did not leave the supply"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A wallet that spends more than it has, or that quietly spends something it
/// cannot prove, is worse than one that refuses.
#[test]
fn spending_more_than_is_there_is_refused_and_says_so() {
    let (wallet, _forge, directory) = funded("short", 2, 2);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let error = wallet
        .send(
            recipient,
            cairn("500"),
            floor(&wallet, recipient, cairn("500")),
        )
        .unwrap_err();
    match error {
        WalletError::NotEnough { needed, have, .. } => {
            assert_eq!(needed, cairn("500"));
            assert_eq!(have, cairn("100"), "two blocks at fifty");
        }
        other => panic!("refused for the wrong reason: {other}"),
    }

    // And the fee counts towards it, which is where an off-by-one would sit:
    // exactly the balance is not enough once anything is paid to carry it.
    let error = wallet
        .send(recipient, cairn("100"), cairn("0.1"))
        .unwrap_err();
    assert!(
        matches!(error, WalletError::NotEnough { .. }),
        "the fee is part of what has to be covered"
    );

    // The balance less what the network asks to carry it does go through.
    // There is no sending all of it any more: a fee is part of the price.
    let paying = floor(&wallet, recipient, cairn("100"));
    let sending = cairn("100").checked_sub(paying).unwrap();
    assert!(wallet.send(recipient, sending, paying).is_ok());

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// Sending nothing costs the network a record of nothing happening.
#[test]
fn sending_nothing_is_refused() {
    let (wallet, _forge, directory) = funded("nothing", 3, 1);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    assert!(matches!(
        wallet.send(recipient, Amount::ZERO, Amount::ZERO),
        Err(WalletError::NothingToSend)
    ));

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A spend should gather as few notes as it can. Every note it takes is bytes
/// in the block and one more thing to sign, and a wallet that took ten fifties
/// to send sixty would be paying for eight of them for nothing.
#[test]
fn a_spend_takes_as_few_notes_as_it_can() {
    let (wallet, _forge, directory) = funded("fewest", 4, 6);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let paying = floor(&wallet, recipient, cairn("120"));
    let sent = wallet.send(recipient, cairn("120"), paying).unwrap();
    assert_eq!(
        sent.notes, 3,
        "three fifties cover a hundred and twenty, and two do not"
    );
    assert_eq!(
        sent.change,
        cairn("30").checked_sub(paying).unwrap(),
        "the change is what is left after the fee"
    );
    assert_eq!(
        sent.from_cold, 0,
        "nothing has fallen on a chain this short"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A payment that takes a note whole costs what a transfer with no change in it
/// costs, and that fee is taken.
///
/// With nothing to come back, the transfer has one output and the network asks
/// one output's worth. The one spend with no change the tests made paid a fee
/// the wallet had quoted itself, so a wallet that priced it with a second
/// output of nothing, which weighs as much as a real one, passed: its quote and
/// its check agreed with each other and not with the network, and it refused
/// the fee the network asks.
#[test]
fn a_payment_that_takes_a_note_whole_is_priced_without_change() {
    let (wallet, _forge, directory) = funded("whole", 12, 1);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let holdings = wallet.holdings();
    assert_eq!(holdings.notes.len(), 1, "one reward, in one note");
    let held = &holdings.notes[0];

    // What the network asks of one note spent into one output, worked out the
    // way the pool works it out, from the same public rules.
    let shape = Transfer::new(
        vec![Input::hot(held.id)],
        vec![Note::new(held.note.value, recipient)],
    );
    let bytes = shape.encode().len();
    let fee = cairn_chain::fee_floor(bytes, cairn_chain::places_taken(&shape, 1), wallet.params());
    let amount = held.note.value.checked_sub(fee).unwrap();

    let sent = wallet.send(recipient, amount, fee).expect(
        "the fee the network asks for this transfer was refused, so the wallet priced \
         a change output the transfer does not have",
    );
    assert_eq!(sent.change, Amount::ZERO, "nothing came back");
    assert_eq!(sent.fee, fee);
    assert_eq!(sent.notes, 1);

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// What a wallet reports has to be what it can actually move. The total it
/// holds and the part it can spend are two numbers, and folding them into one
/// would show a balance that quietly goes down.
#[test]
fn what_is_held_and_what_can_move_are_two_numbers() {
    let (wallet, _forge, directory) = funded("holdings", 5, 3);
    let holdings = wallet.holdings();

    assert_eq!(holdings.spendable, cairn("150"));
    assert_eq!(holdings.stranded, Amount::ZERO, "nothing has fallen yet");
    assert_eq!(holdings.total(), cairn("150"));
    assert_eq!(holdings.notes.len(), 3);
    assert!(
        holdings.notes.iter().all(|held| !held.is_cold()),
        "a young chain has evicted nothing"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// A wallet with no money at all must say so rather than fail in some other
/// way, because that is the state every wallet starts in.
#[test]
fn an_empty_wallet_holds_nothing_and_refuses_to_spend() {
    let directory = scratch("empty");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &SecretKey::from_bytes(&[6; 32])).unwrap();
    let (wallet, restored) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();

    assert_eq!(restored, 0, "nothing on disk to read back");
    let holdings = wallet.holdings();
    assert_eq!(holdings.spendable, Amount::ZERO);
    assert!(holdings.notes.is_empty());
    assert_eq!(wallet.progress().height, None, "no chain at all yet");

    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    assert!(matches!(
        wallet.send(recipient, cairn("1"), Amount::ZERO),
        Err(WalletError::NotEnough { .. })
    ));

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// The address is the one the key file names, and it is what a payer needs.
/// Getting this wrong sends money nowhere it can be recovered from.
#[test]
fn the_address_is_the_key_file_and_nothing_else() {
    let directory = scratch("address");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[8; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();

    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
    assert_eq!(wallet.address(), secret.public_key().into());
    assert_eq!(
        format!("{wallet:?}"),
        "Wallet(<key withheld>)",
        "and printing it says nothing about the key"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// The history is the wallet's own account of its money, and it has to survive
/// the wallet being closed. A wallet that rebuilt it from nothing every time
/// would lose everything older than the blocks it still keeps.
#[test]
fn the_history_is_written_down_and_read_back() {
    let directory = scratch("history");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[11; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let data = directory.join("data");

    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    let (wallet, _) = Wallet::open(&key_file, params(), &data).unwrap();
    let mut forge = Forge::new();
    for _ in 0..4 {
        let block = forge.mine(&secret.public_key(), Vec::new());
        wallet.node().submit_block(block).unwrap();
    }

    // Mined four times, then spent once, and the spend lands in a block.
    wallet.send(recipient, cairn("60"), cairn("1")).unwrap();
    let carried: Vec<Transfer> = wallet.node().with_chain(|chain| {
        chain
            .pooled_transfers()
            .map(|(_, transfer)| transfer.clone())
            .collect()
    });
    let block = forge.mine(&recipient, carried);
    wallet.node().submit_block(block).unwrap();

    let movements = wallet.history();
    assert_eq!(movements.len(), 5, "four mined and one sent");
    assert_eq!(
        movements[0].direction,
        cairn_wallet::history::Direction::Sent
    );
    assert_eq!(
        movements[0].amount,
        cairn("61"),
        "what left is what was sent and what was paid to carry it"
    );
    assert!(movements[1..]
        .iter()
        .all(|m| m.direction == cairn_wallet::history::Direction::Mined));
    assert_eq!(wallet.history_covers().from, Some(0));
    wallet.shutdown();
    drop(wallet);

    // Opened again, it remembers rather than starting over.
    let (again, _) = Wallet::open(&key_file, params(), &data).unwrap();
    let remembered = again.history();
    assert_eq!(remembered.len(), 5, "it was written down");
    assert_eq!(remembered[0].amount, cairn("61"));
    assert_eq!(remembered[0].id, movements[0].id, "the same transfer");
    assert_eq!(again.history_covers().from, Some(0));

    again.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// The network carries at most `max_inputs_per_transfer` notes in one payment,
/// and the wallet's only size guard was on bytes. At a hundred and one bytes a
/// note that one first fires at 1 297 notes, five times past the rule that
/// refuses at 257, so a miner with 257 rewards gathered them, shuffled them,
/// signed every one and handed the node a payment it was always going to turn
/// away. Nothing was lost but the answer was the raw protocol string, and the
/// wallet knew the number before it started.
#[test]
fn a_payment_gathering_more_notes_than_the_network_carries_is_refused_here() {
    let limit = params().max_inputs_per_transfer;
    let blocks = limit + 2;
    let (wallet, _forge, directory) = funded("toomanynotes", 11, blocks);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let reward = params().initial_reward;
    let holdings = wallet.holdings();
    assert_eq!(holdings.notes.len(), blocks, "one note per block mined");

    // More than the largest `limit` notes come to, so covering it needs one
    // note past what one payment carries.
    let reach = Amount::from_pebbles(reward.as_pebbles() * u64::try_from(limit).unwrap()).unwrap();
    let asking = Amount::from_pebbles(reach.as_pebbles() + 1).unwrap();
    assert!(asking <= holdings.spendable, "the money is all there");

    match wallet.send(recipient, asking, cairn("1")) {
        Err(WalletError::TooManyNotes {
            over,
            limit: told,
            reach: told_reach,
        }) => {
            assert_eq!(over, limit + 1, "one note past what a payment carries");
            assert_eq!(told, limit);
            assert_eq!(told_reach, reach, "what the owner can actually send");
        }
        other => panic!("a payment of {asking} should be refused for its note count: {other:?}"),
    }

    // And the wallet still makes the largest payment it can: the guard must
    // refuse what the network refuses and nothing else.
    let most = Amount::from_pebbles(reach.as_pebbles() - cairn("5").as_pebbles()).unwrap();
    let paying = floor(&wallet, recipient, most);
    let sent = wallet.send(recipient, most, paying).unwrap();
    assert_eq!(
        sent.notes, limit,
        "the largest payment there is gathers exactly what one carries"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

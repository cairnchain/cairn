//! What an adversarial audit found, kept as the shape of the repair.
//!
//! Each of these began as a probe that passed by demonstrating a defect. What
//! is left is the same situation set up the same way, asserting what the
//! wallet does now, with the account of what it used to do kept above it. A
//! defect nobody wrote down is a defect that comes back.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::path::PathBuf;
use std::time::Duration;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;
use cairn_wallet::{Wallet, WalletError};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-wallet-adv-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
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

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

fn pooled(wallet: &Wallet) -> Vec<Transfer> {
    wallet.node().with_chain(|chain| {
        chain
            .pooled_transfers()
            .map(|(_, transfer)| transfer.clone())
            .collect()
    })
}

/// A peer that answers the handshake and is asked for nothing else.
///
/// Sending holds itself open for up to five seconds waiting for somebody to
/// hand the transfer to, which is right and which makes a test that spends
/// more than twice spend all its time in that wait. This satisfies the wait
/// rather than skipping it.
struct Bystander(cairn_net::Node);

impl Bystander {
    fn beside(wallet: &Wallet) -> Self {
        let peer = cairn_net::Node::bind(params(), "127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(wallet.reach(peer.address()), "the peer is reachable");
        let mut waited = 0;
        while wallet.progress().peers == 0 && waited < 50 {
            std::thread::sleep(Duration::from_millis(100));
            waited += 1;
        }
        assert!(wallet.progress().peers > 0, "connected");
        Self(peer)
    }

    fn stop(self) {
        self.0.shutdown();
    }
}

/// CLAIM UNDER TEST: a wallet that says "sent" has sent something.
///
/// What used to happen: `holdings` read the confirmed ledger and knew nothing
/// of the pool, so a note handed to a transfer that was still waiting for a
/// block was counted as spendable and picked again. Sending the same payment
/// twice built the same bytes, so `accept_transfer` saw the identifier it
/// already held and returned `Ok(false)`, pooling nothing and broadcasting
/// nothing. `send` threw that boolean away and reported a spend. A person sent
/// once, saw a balance that had not moved, pressed Send again, and was told
/// twice that money had gone. A shopkeeper watching two green boxes hands over
/// two things.
#[test]
fn a_payment_waiting_for_a_block_is_out_of_what_can_be_spent() {
    let (wallet, _forge, directory) = funded("twice", 21, 4);
    let peer = Bystander::beside(&wallet);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let before = wallet.holdings().spendable;
    assert_eq!(before, cairn("200"));

    let fee = wallet.floor_for(recipient, cairn("10"));
    let first = wallet.send(recipient, cairn("10"), fee).unwrap();

    // The balance moves the moment the payment is handed over, which is the
    // whole of what stops the second press of Send.
    let after_first = wallet.holdings();
    assert_eq!(
        after_first.waiting,
        cairn("50"),
        "the note the payment is made of is spoken for"
    );
    assert_eq!(after_first.spendable, cairn("150"));
    assert_eq!(after_first.total(), before, "and none of it has gone yet");

    // And the wallet can say what it is waiting for, rather than leaving a
    // person to work out why the number changed.
    let waiting = wallet.waiting();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].id, first.id);
    assert_eq!(waiting[0].amount, cairn("10").checked_add(fee).unwrap());
    assert_eq!(waiting[0].committed, cairn("50"));

    // Pressing Send again is now a second payment and not a second report of
    // the first: it reaches for a note the first one did not take, so it is a
    // different transfer, and both are in the pool to be carried.
    let second = wallet.send(recipient, cairn("10"), fee).unwrap();
    assert_ne!(
        second.id, first.id,
        "a second payment is built out of notes the first did not touch"
    );
    let carried = pooled(&wallet);
    assert_eq!(
        carried.len(),
        2,
        "two payments reported, two payments exist"
    );
    assert_eq!(wallet.waiting().len(), 2);
    assert_eq!(wallet.holdings().spendable, cairn("100"));

    // What is left is a hundred, and asking for more than that is refused with
    // the waiting money named, because otherwise the refusal reads as money
    // gone missing.
    let error = wallet
        .send(recipient, cairn("150"), fee)
        .expect_err("a hundred is what is left");
    match error {
        WalletError::NotEnough { have, waiting, .. } => {
            assert_eq!(have, cairn("100"));
            assert_eq!(waiting, cairn("100"));
            assert!(error.to_string().contains("waiting for a block"), "{error}");
        }
        other => panic!("refused for the wrong reason: {other}"),
    }

    peer.stop();
    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: a second payment made before the first confirms is a
/// second payment, not a replacement of the first.
///
/// What used to happen: nothing told the second build that the first had
/// already spoken for a note, so the two reached for the same notes and the
/// pool had to decide between them.
#[test]
fn a_second_payment_before_a_block_reaches_for_other_notes() {
    let (wallet, _forge, directory) = funded("second", 22, 4);
    let peer = Bystander::beside(&wallet);
    let alice = SecretKey::from_bytes(&[9; 32]).public_key();
    let bob = SecretKey::from_bytes(&[10; 32]).public_key();

    let fee = wallet.floor_for(alice, cairn("10"));
    let first = wallet.send(alice, cairn("10"), fee).unwrap();
    assert_eq!(pooled(&wallet).len(), 1);

    // A larger second payment. It is quoted and built against what is left
    // rather than against the whole balance, so it neither displaces the first
    // nor collides with it.
    let second_fee = wallet.floor_for(bob, cairn("120"));
    let second = wallet.send(bob, cairn("120"), second_fee).unwrap();

    let now = pooled(&wallet);
    assert_eq!(now.len(), 2, "both are waiting to be carried");
    assert!(
        now.iter().any(|transfer| transfer.id() == first.id),
        "the first payment is untouched"
    );

    let mut taken: Vec<_> = now
        .iter()
        .flat_map(|transfer| transfer.inputs.iter().map(|input| input.note_id))
        .collect();
    let before_dedup = taken.len();
    taken.sort_unstable();
    taken.dedup();
    assert_eq!(
        taken.len(),
        before_dedup,
        "and no note is promised to both of them"
    );
    assert_eq!(second.amount, cairn("120"));

    peer.stop();
    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: a person who pays the fee the wallet quoted can send.
///
/// What used to happen: the quote priced a transfer covering the amount while
/// sending selected against the amount and the fee together. Where the fee
/// crossed a note boundary the real transfer gathered one more note, its floor
/// rose, and the wallet refused the number it had just given. It happened on
/// exactly the amounts that are a whole number of notes, which is to say the
/// round numbers people type.
#[test]
fn the_fee_the_wallet_quotes_is_one_it_accepts() {
    let (wallet, _forge, directory) = funded("quote", 23, 3);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    // 150 held, in three notes of 50. Ask for exactly two notes' worth: the
    // quote used to be priced against a two note transfer and the spend needed
    // three.
    let amount = cairn("100");
    let quoted = wallet.floor_for(recipient, amount);
    let sent = wallet
        .send(recipient, amount, quoted)
        .expect("the quoted fee goes through first time");
    assert_eq!(sent.fee, quoted);
    assert_eq!(
        sent.notes, 3,
        "three notes, which is what the quote was priced against"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: nothing links a wallet's notes on chain except the
/// addresses, which fresh keys per payment are meant to fix.
///
/// What used to happen: `send` built `[recipient, change]` and left it, so the
/// change was the last output every time and an observer picked it out with
/// certainty whatever key it was paid to. The inputs came out in selection
/// order, hot before cold and then largest first, which fingerprinted every
/// transfer this program built and resolved the change output on its own.
#[test]
fn the_change_does_not_sit_at_a_fixed_place() {
    let (wallet, mut forge, directory) = funded("shape", 24, 45);
    let peer = Bystander::beside(&wallet);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    let mine = wallet.address();

    let mut first = 0;
    let mut last = 0;
    for _ in 0..14 {
        let fee = wallet.floor_for(recipient, cairn("120"));
        let sent = wallet.send(recipient, cairn("120"), fee).unwrap();
        let transfer = pooled(&wallet)
            .into_iter()
            .find(|held| held.id() == sent.id)
            .expect("the payment reached the pool");
        assert_eq!(
            transfer.inputs.len(),
            3,
            "three notes cover a hundred and twenty"
        );
        assert_eq!(transfer.outputs.len(), 2, "one to them and the change back");
        match transfer.outputs.iter().position(|note| note.owner == mine) {
            Some(0) => first += 1,
            Some(1) => last += 1,
            other => panic!("the change is not among the outputs: {other:?}"),
        }
    }
    // Fourteen payments. A wallet that never shuffles puts the change last
    // fourteen times out of fourteen; one that does fails this about once in
    // eight thousand runs.
    assert!(
        first > 0 && last > 0,
        "the change moved about: {first} first, {last} last"
    );

    // And the shuffle did not make the transfer unsignable, which is the way
    // this repair could have cost money rather than saved privacy: what is
    // signed commits to the order, so the order has to be settled first.
    let one = pooled(&wallet).into_iter().next().unwrap();
    let miner = SecretKey::from_bytes(&[7; 32]).public_key();
    let block = forge.mine(&miner, vec![one.clone()]);
    wallet
        .node()
        .submit_block(block)
        .expect("a block carries what this wallet signed");
    assert!(
        !pooled(&wallet).iter().any(|held| held.id() == one.id()),
        "and it left the pool because a block took it"
    );

    peer.stop();
    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: a key file left half written is recoverable without
/// guessing.
///
/// What used to happen: writing said "already exists" and reading said "does
/// not hold 32 bytes of hexadecimal", and neither said the file was empty and
/// could go. Whoever hit it went round that loop with no way out of it.
#[test]
fn a_key_file_that_is_empty_says_to_delete_it() {
    let directory = scratch("halfkey");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("key");

    // What a torn write, a full disk or a crash between `create_new` and the
    // write leaves behind: the file exists and holds no key.
    std::fs::write(&path, "").unwrap();

    let written = cairn_wallet::keyfile::write(&path, &SecretKey::from_bytes(&[1; 32]))
        .expect_err("`new` still refuses to replace a file that is there");
    let read = cairn_wallet::keyfile::read(&path).expect_err("and it is not a key");
    for said in [&written, &read] {
        assert!(said.contains("empty"), "{said}");
        assert!(said.contains("Delete it"), "{said}");
        assert!(said.contains("nothing in it to lose"), "{said}");
    }

    // Once it is gone, making a key works, and what is written is on the disk
    // rather than on its way there.
    std::fs::remove_file(&path).unwrap();
    let secret = SecretKey::from_bytes(&[1; 32]);
    cairn_wallet::keyfile::write(&path, &secret).unwrap();
    assert_eq!(
        cairn_wallet::keyfile::read(&path).unwrap().to_bytes(),
        secret.to_bytes()
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: leaving the fee blank works. Both faces do exactly what
/// this does, `floor_for` then `send`, so whatever fails here is what a person
/// who typed nothing in the fee box sees.
///
/// What used to happen: swept over 1 to 190 CAIRN against four notes of 50,
/// three amounts quoted a fee the wallet then refused, and they were exactly
/// 50, 100 and 150.
#[test]
fn the_fee_the_wallet_works_out_for_itself_is_never_below_its_own_floor() {
    let (wallet, _forge, directory) = funded("blank", 25, 4);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let mut refused = Vec::new();
    for whole in 1..=190u64 {
        let amount = cairn(&whole.to_string());
        let quoted = wallet.floor_for(recipient, amount);
        if let Some(needed) = would_refuse(&wallet, recipient, amount, quoted) {
            refused.push((whole, quoted, needed));
        }
    }
    assert!(
        refused.is_empty(),
        "the wallet quoted fees it would then refuse: {refused:?}"
    );

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// Runs the same arithmetic `send` runs, without submitting anything, so the
/// sweep above does not fill a pool or wait on peers.
fn would_refuse(
    wallet: &Wallet,
    recipient: PublicKey,
    amount: Amount,
    fee: Amount,
) -> Option<Amount> {
    use cairn_ledger::transaction::Input;
    let needed = amount.checked_add(fee)?;
    let holdings = wallet.holdings();
    let mut sorted = holdings.notes.clone();
    sorted.sort_by(|left, right| {
        left.is_cold()
            .cmp(&right.is_cold())
            .then_with(|| right.note.value.cmp(&left.note.value))
    });
    let mut chosen = Vec::new();
    let mut gathered = Amount::ZERO;
    for held in sorted {
        if gathered >= needed {
            break;
        }
        gathered = gathered.checked_add(held.note.value)?;
        chosen.push(held);
    }
    if gathered < needed {
        return None;
    }
    let change = gathered.checked_sub(needed)?;
    let mut outputs = vec![Note::new(amount, recipient)];
    if change > Amount::ZERO {
        outputs.push(Note::new(change, wallet.address()));
    }
    let inputs = chosen
        .iter()
        .map(|held| match &held.fallen {
            None => Input::hot(held.id),
            Some((position, proof)) => Input::cold(held.id, held.note, *position, proof.clone()),
        })
        .collect();
    let transfer = Transfer::new(inputs, outputs);
    let bytes = cairn_primitives::codec::Encode::encode(&transfer).len();
    let freed = chosen.iter().filter(|held| held.fallen.is_none()).count();
    let floor = cairn_chain::fee_floor(cairn_chain::transfer_weight(&transfer, bytes, freed));
    (fee < floor).then_some(floor)
}

/// CLAIM UNDER TEST: the history a wallet shows is the history up to now.
///
/// What used to happen: `follow` read at most one batch of blocks per call and
/// `history()` called it once, while the first height read was never revised.
/// Six hundred blocks in, the balance was right and the list headed "what
/// happened, newest first" was eighty-eight blocks stale, with nothing
/// anywhere saying so.
#[test]
fn the_history_reads_its_way_to_the_tip_and_says_where_it_stopped() {
    let directory = scratch("batch");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[26; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();

    let mut forge = Forge::new();
    let blocks = 600usize;
    for _ in 0..blocks {
        let block = forge.mine(&secret.public_key(), Vec::new());
        wallet.node().submit_block(block).unwrap();
    }
    let top = blocks as u64 - 1;
    assert_eq!(wallet.progress().height, Some(top));

    // One look, as `cairn-wallet balance` takes and as the page's first tick
    // takes.
    let movements = wallet.history();
    assert_eq!(
        movements.len(),
        blocks,
        "every block paid this key, and every one of them is in the account"
    );
    assert_eq!(
        movements[0].height, top,
        "the newest thing it shows is the newest thing that happened"
    );

    let covered = wallet.history_covers();
    assert_eq!(covered.from, Some(0));
    assert_eq!(covered.through, Some(top));
    assert_eq!(covered.tip, Some(top));
    assert_eq!(covered.behind(), 0, "and it says it is not behind");

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: a payment that is undone by a reorganisation is something
/// the wallet tells its owner about.
///
/// What used to happen: `follow` noticed the divergence and called
/// `History::forget`, which resets the account deliberately and for good
/// reasons. The payment then existed nowhere: not in the history, not
/// anywhere. The money came back, the record of paying somebody disappeared,
/// and nothing said a payment had been undone.
#[test]
fn a_reorganisation_says_what_it_undid() {
    let directory = scratch("unsend");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[27; 32]);
    let mine = secret.public_key();
    let alice = SecretKey::from_bytes(&[9; 32]).public_key();
    let stranger = SecretKey::from_bytes(&[7; 32]).public_key();
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();

    // Four blocks paying this key, on a chain both branches will share.
    let mut common = Forge::new();
    for _ in 0..4 {
        let block = common.mine(&mine, Vec::new());
        wallet.node().submit_block(block).unwrap();
    }
    let before = wallet.holdings().spendable;

    // It pays Alice, and a block carries the payment.
    let fee = wallet.floor_for(alice, cairn("10"));
    let sent = wallet.send(alice, cairn("10"), fee).unwrap();
    let carried = pooled(&wallet);
    assert_eq!(carried.len(), 1);

    let mut branch_a = Forge {
        params: common.params,
        state: common.state.clone(),
        clock: common.clock,
    };
    let a4 = branch_a.mine(&stranger, carried.clone());
    wallet.node().submit_block(a4).unwrap();
    assert!(
        wallet
            .history()
            .iter()
            .any(|m| m.direction == cairn_wallet::history::Direction::Sent),
        "a block carried it, so paying her is what happened"
    );
    assert!(
        wallet.undone().is_empty(),
        "and nothing has been taken back"
    );

    // A heavier branch off the shared prefix that never carried the payment.
    let mut branch_b = Forge {
        params: common.params,
        state: common.state.clone(),
        clock: common.clock,
    };
    for _ in 0..3 {
        let block = branch_b.mine(&stranger, Vec::new());
        wallet.node().submit_block(block).unwrap();
    }
    assert_eq!(wallet.progress().height, Some(6), "it followed branch B");

    // The account says paying her was undone, and says it in the terms it was
    // recorded in rather than as a hole where a movement used to be.
    let told = wallet.history();
    assert!(
        !told
            .iter()
            .any(|m| m.direction == cairn_wallet::history::Direction::Sent),
        "no block carries it any more, so it is not in what happened: {told:?}"
    );
    let undone = wallet.undone();
    assert_eq!(undone.len(), 1, "and it is not simply gone: {undone:?}");
    assert_eq!(undone[0].direction, cairn_wallet::history::Direction::Sent);
    assert_eq!(undone[0].id, sent.id);
    assert_eq!(undone[0].amount, cairn("10").checked_add(fee).unwrap());
    assert_eq!(
        told.len(),
        4,
        "the four blocks that both branches share are still there"
    );

    // The chain puts the transfer back in the pool to be carried again, which
    // is `cairn-chain`'s half of this. The wallet's half is to stop counting
    // the notes it holds as spendable, and to be able to say it is waiting.
    let back = pooled(&wallet);
    assert!(
        back.iter().any(|transfer| transfer.id() == sent.id),
        "the payment is waiting to be carried again"
    );
    let holdings = wallet.holdings();
    assert_eq!(holdings.total(), before, "the money is all accounted for");
    assert_eq!(holdings.waiting, cairn("50"));
    assert_eq!(holdings.spendable, before.checked_sub(cairn("50")).unwrap());
    assert_eq!(wallet.waiting().len(), 1);

    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: `History::diverged` notices a branch that was undone.
///
/// What used to happen: it asked about one height, the newest block it had
/// read, and read `None` there as "the wallet cannot see that far" rather than
/// as "what I read is gone". Work decides which branch wins and not length, so
/// a branch that wins while ending lower answers `None` at that height, and
/// the wallet went on stacking the winning branch on top of the losing one.
#[test]
fn a_branch_that_wins_while_ending_lower_is_noticed() {
    use cairn_ledger::block::BlockHeader;
    use cairn_ledger::note::NetworkId;
    use cairn_primitives::Hash32;
    use cairn_wallet::history::History;

    let mine = SecretKey::from_bytes(&[28; 32]).public_key();
    let block = |height: u64, nonce: u64| Block {
        header: BlockHeader {
            version: 1,
            network: NetworkId::TESTNET,
            height,
            previous: Hash32::ZERO,
            state_root: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 1_000 + height,
            difficulty: 1,
            total_work: u128::from(height),
            nonce,
        },
        coinbase: CoinbaseTransaction::new(height, vec![Note::new(cairn("50"), mine)]),
        transfers: Vec::new(),
    };

    let mut history = History::new();
    let mut read = Vec::new();
    for height in 0..5 {
        let block = block(height, 0);
        read.push(block.id());
        history.take(&block, mine);
    }
    assert_eq!(history.len(), 5, "five payments to this key");
    assert_eq!(history.next(), 5);

    // The chain now ends at height 2, and every block on it above the fork is
    // a different one. Everything this history holds above height 2 describes
    // blocks nobody has.
    let rival: Vec<Hash32> = (0..3).map(|height| block(height, 9).id()).collect();
    assert_ne!(rival[2], read[2], "the branch really did change");

    assert!(
        history.diverged(Some(2), |height| {
            usize::try_from(height)
                .ok()
                .and_then(|at| rival.get(at))
                .copied()
        }),
        "the chain stops below what this read, so what it read is gone"
    );

    // And a block the wallet merely dropped for age is still not a divergence,
    // which is the case the old reading got right and is worth keeping.
    assert!(
        !history.diverged(Some(9), |_| None),
        "a block that was dropped is not a block that changed"
    );

    history.forget();
    assert_eq!(history.len(), 0);
    assert_eq!(
        history.undone().count(),
        5,
        "and what it said is kept, to be given back as the chain is read again"
    );
}

/// CLAIM UNDER TEST: `--wait <seconds>` is how long the wallet spends catching
/// up before it answers.
///
/// What used to happen: `catch_up` watched the height and gave up once it had
/// not moved for two seconds. A node being handed a ledger reports no height
/// at all until the whole of it has arrived, and `None` does not move either,
/// so a first `cairn-wallet balance` on a fresh install answered nought two
/// seconds into a thirty second wait. A hostile peer got that for free:
/// complete the handshake, send nothing.
#[test]
fn catching_up_waits_out_its_patience_while_no_chain_has_arrived() {
    use std::time::Instant;

    let directory = scratch("patience");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    cairn_wallet::keyfile::write(&key_file, &SecretKey::from_bytes(&[29; 32])).unwrap();
    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();

    // A peer that is reachable and has nothing to send, which is what a wallet
    // sees for the whole of a ledger handover and what a peer that answers the
    // handshake and then says nothing looks like.
    let peer = Bystander::beside(&wallet);
    assert_eq!(wallet.progress().height, None, "and no chain has arrived");

    let asked = Duration::from_secs(4);
    let started = Instant::now();
    wallet.catch_up(asked);
    let spent = started.elapsed();
    assert!(
        spent >= asked.checked_sub(Duration::from_millis(400)).unwrap(),
        "asked for {asked:?} of patience and spent {spent:?}"
    );

    peer.stop();
    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: nothing a browser can be made to do from another page
/// reaches this wallet.
///
/// This one found nothing, and it is kept for that reason: it knocks on the
/// real socket with the exact header shapes a browser sends, including the
/// ones the unit tests beside `serve.rs` do not cover. A lock that is right in
/// a function and wrong in the wiring is still an open door.
#[test]
fn what_a_page_somewhere_else_in_the_same_browser_gets() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let directory = scratch("knock");
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[30; 32]);
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();
    let mut forge = Forge::new();
    for _ in 0..2 {
        let block = forge.mine(&secret.public_key(), Vec::new());
        wallet.node().submit_block(block).unwrap();
    }

    let wallet = Arc::new(wallet);
    let (listener, opened) = cairn_wallet::serve::open(0).unwrap();
    let opened = Arc::new(opened);
    let alive = Arc::new(AtomicBool::new(true));
    let serving = Arc::clone(&wallet);
    let told = Arc::clone(&opened);
    let watching = Arc::clone(&alive);
    let thread =
        std::thread::spawn(move || cairn_wallet::serve::run(&serving, &listener, &told, &watching));

    let address = opened.address;
    let key = opened.secret.clone();
    let ask = |head: String, body: String| -> (u16, String) {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let request = if body.is_empty() {
            format!("{head}\r\nconnection: close\r\n\r\n")
        } else {
            format!(
                "{head}\r\ncontent-type: application/x-www-form-urlencoded\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        stream.write_all(request.as_bytes()).unwrap();
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        let status = answer
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        (status, answer)
    };

    let thief = SecretKey::from_bytes(&[99; 32]).public_key();
    let spend = format!("to={thief}&amount=1&fee=");

    // A form on a site the person happens to have open. A browser sends an
    // origin on every cross-site POST, form submissions included.
    let (status, _) = ask(
        format!(
            "POST /api/send HTTP/1.1\r\nhost: {address}\r\norigin: https://example.com\r\n\
             cookie: whatever"
        ),
        format!("k={key}&{spend}"),
    );
    assert_eq!(status, 403, "a cross-site form POST, with the secret right");

    // The same from a page opened off the disk, which sends `null`.
    let (status, _) = ask(
        format!("POST /api/send HTTP/1.1\r\nhost: {address}\r\norigin: null"),
        format!("k={key}&{spend}"),
    );
    assert_eq!(status, 403, "a POST from a file:// page");

    // And from something else the person is running on their own loopback,
    // which is same-site but not same-origin.
    let (status, _) = ask(
        format!("POST /api/send HTTP/1.1\r\nhost: {address}\r\norigin: http://127.0.0.1:1\r\n"),
        format!("k={key}&{spend}"),
    );
    assert_eq!(status, 403, "a POST from another loopback port");

    // A name someone else controls, pointed at this machine.
    let (status, _) = ask(
        format!(
            "POST /api/send HTTP/1.1\r\nhost: wallet.example.com:{}",
            address.port()
        ),
        format!("k={key}&{spend}"),
    );
    assert_eq!(status, 421, "a POST to a rebound name");

    // Nothing that changes anything can be reached by following a link, and
    // neither can anything that reads this wallet.
    let (status, body) = ask(
        format!("GET /api/send?k={key}&{spend} HTTP/1.1\r\nhost: {address}"),
        String::new(),
    );
    assert_eq!(status, 405, "{body}");
    let (status, body) = ask(
        format!("GET /api/quote?k={key}&{spend} HTTP/1.1\r\nhost: {address}"),
        String::new(),
    );
    assert_eq!(status, 405, "{body}");

    // What a spend is quoted at before it is made, which is where the fee is
    // said out loud for the first time.
    let (status, body) = ask(
        format!("POST /api/quote HTTP/1.1\r\nhost: {address}"),
        format!("k={key}&to={thief}&amount=1&fee="),
    );
    assert_eq!(status, 200);
    assert!(body.contains("\"fee\":\""), "{body}");
    assert!(body.contains("\"total\":\""), "{body}");

    // What the secret does and does not buy. Anything on this machine that
    // learns it can spend, origin or no origin: this is by design and it is
    // the whole of the lock.
    let (status, body) = ask(
        format!("POST /api/send HTTP/1.1\r\nhost: {address}"),
        format!("k={key}&{spend}"),
    );
    assert_eq!(status, 200);
    assert!(
        body.contains("\"fee\":\""),
        "and it says what it paid: {body}"
    );

    // And without it, nothing at all.
    let (status, _) = ask(
        format!("GET /api/state HTTP/1.1\r\nhost: {address}"),
        String::new(),
    );
    assert_eq!(status, 403);

    alive.store(false, Ordering::SeqCst);
    let _ = TcpStream::connect(address);
    let _ = thread.join();
    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: a wallet cannot be made to overpay a fee without saying
/// so.
///
/// What used to happen: there was a floor on the fee and no ceiling anywhere.
/// Someone meaning `0.00005` and typing `5`, which is one keystroke on a page
/// whose fee box is placeholdered `0.00`, paid five CAIRN to a miner and read
/// "Sent 1.00000000 CAIRN". The page's answer carried the amount, the change,
/// the notes and the identifier, and no fee at all.
#[test]
fn a_mistyped_fee_is_refused_and_the_fee_that_is_paid_is_shown() {
    let (wallet, _forge, directory) = funded("fatfinger", 31, 4);
    let peer = Bystander::beside(&wallet);
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let error = wallet
        .send(recipient, cairn("1"), cairn("5"))
        .expect_err("five CAIRN to carry a payment of one is not sent quietly");
    match error {
        WalletError::FeeOutOfProportion { fee, amount, floor } => {
            assert_eq!(fee, cairn("5"));
            assert_eq!(amount, cairn("1"));
            assert!(floor < cairn("1"), "what the network actually asks");
        }
        other => panic!("refused for the wrong reason: {other}"),
    }
    assert!(pooled(&wallet).is_empty(), "and nothing was sent");
    assert_eq!(wallet.holdings().spendable, cairn("200"));

    // The ceiling is one a person can step over, because paying over the odds
    // to be carried sooner is a thing people mean to do.
    let sent = wallet
        .send_over_the_odds(recipient, cairn("1"), cairn("5"))
        .expect("said again, it goes");
    assert_eq!(sent.fee, cairn("5"), "and the answer carries what it cost");
    assert_eq!(
        sent.change,
        cairn("44"),
        "fifty in, one out, five to whoever carries it"
    );

    // The fee reaching the page is checked where the page is spoken to, in
    // `tests/page.rs` and in the knock above.

    peer.stop();
    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

/// CLAIM UNDER TEST: a key file that anyone on the machine can read is not
/// quietly used.
///
/// What used to happen: reading never looked at the file's mode, so a 0644 key
/// file was used without a word. That is exactly what a restore from a backup,
/// a copy off a memory stick, or a `chmod` down a whole directory produces.
#[cfg(unix)]
#[test]
fn a_world_readable_key_file_is_refused_and_says_how_to_mend_it() {
    use std::os::unix::fs::PermissionsExt;

    let directory = scratch("mode");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("key");
    let secret = SecretKey::from_bytes(&[32; 32]);
    cairn_wallet::keyfile::write(&path, &secret).unwrap();
    assert!(
        cairn_wallet::keyfile::read(&path).is_ok(),
        "0600 as written"
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let said = cairn_wallet::keyfile::read(&path)
        .expect_err("a key other accounts can read is not used quietly");
    assert!(said.contains("0644"), "{said}");
    assert!(said.contains("chmod 600"), "{said}");

    // And the way out of it is the one command the message names.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        cairn_wallet::keyfile::read(&path).unwrap().to_bytes(),
        secret.to_bytes()
    );

    let _ = std::fs::remove_dir_all(&directory);
}

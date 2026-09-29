//! A payment from the moment it leaves to the moment the chain settles it.
//!
//! A transfer handed to the network waits in a pool until a miner carries it,
//! and the pool is memory in the process that made it. `cairn-wallet send` is
//! a process that hands a payment over and exits; the page is a process that
//! stays. Each test here follows one payment through one of the ways its life
//! can go, and asks whether what the wallet says about it at each step is
//! still true.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, mine_block, ConsensusParams, PLACE_PRICE,
};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::{Waited, Wallet};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

/// A hot set of four, so a note falls out of it a block after it is paid,
/// and a place priced as a public network prices it, so a note falling moves
/// what a payment owes: it frees no place any more, and the place it takes
/// instead burns the price.
fn small_hot_set() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
        .with_place_price(PLACE_PRICE)
}

/// A fee that pays the burn a payment owes once one of its notes has fallen,
/// and not the pool's floor: a payment its node lets go of that a block may
/// still carry.
fn short_of_the_floor_once_fallen(wallet: &Wallet) -> Amount {
    let floor = wallet.floor_for(recipient(), cairn("10"));
    Amount::from_pebbles(floor.as_pebbles() + PLACE_PRICE.as_pebbles() - 1).unwrap()
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-life-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// A liveness bound, set far past what a loaded machine needs, and not a
/// measurement: it costs nothing once the condition holds.
fn until(patience: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    ready()
}

/// Mines blocks on a private ledger, paying whoever is named.
#[derive(Clone)]
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
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

/// A wallet's key file and data directory, and the blocks that paid it.
struct Funded {
    directory: PathBuf,
    key_file: PathBuf,
    secret: SecretKey,
    params: ConsensusParams,
    forge: Forge,
    blocks: Vec<Block>,
}

impl Funded {
    fn data(&self) -> PathBuf {
        self.directory.join("data")
    }

    fn open(&self) -> Wallet {
        Wallet::open(&self.key_file, self.params, &self.data())
            .unwrap()
            .0
    }
}

/// A key nobody else holds.
fn somebody() -> PublicKey {
    SecretKey::generate().unwrap().public_key()
}

/// A wallet holding `rewards` block rewards.
fn funded(name: &str, rewards: usize, params: ConsensusParams) -> (Wallet, Funded) {
    let directory = scratch(name);
    let key_file = directory.join("key");
    let secret = SecretKey::generate().unwrap();
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let mut forge = Forge::new(params);
    let wallet = Wallet::open(&key_file, params, &directory.join("data"))
        .unwrap()
        .0;
    let mut blocks = Vec::new();
    for _ in 0..rewards {
        let block = forge.mine(&secret.public_key(), Vec::new());
        wallet.node().submit_block(block.clone()).unwrap();
        blocks.push(block);
    }
    (
        wallet,
        Funded {
            directory,
            key_file,
            secret,
            params,
            forge,
            blocks,
        },
    )
}

/// A node on the same chain as the wallet, introduced to it.
fn peer_beside(wallet: &Wallet, funded: &Funded) -> Node {
    let peer = Node::bind(funded.params, "127.0.0.1:0".parse().unwrap()).unwrap();
    for block in &funded.blocks {
        peer.submit_block(block.clone()).unwrap();
    }
    assert!(
        wallet.reach(peer.address()),
        "fixture: the peer is reachable"
    );
    assert!(
        until(Duration::from_secs(20), || wallet.progress().peers > 0),
        "fixture: the peer introduced itself"
    );
    peer
}

fn pooled(wallet: &Wallet, id: &Hash32) -> Option<Transfer> {
    wallet.node().with_chain(|chain| chain.pooled(id).cloned())
}

fn inputs_of(transfer: &Transfer) -> BTreeSet<NoteId> {
    transfer.inputs.iter().map(|input| input.note_id).collect()
}

/// Who every payment here pays: one key for the whole run, so a test that
/// pays twice pays the same person twice.
fn recipient() -> PublicKey {
    static ONE: std::sync::OnceLock<PublicKey> = std::sync::OnceLock::new();
    *ONE.get_or_init(somebody)
}

/// A payment one command handed over is still waiting in the next, holds
/// its notes out of the balance there, and a payment made there reaches for
/// other notes.
///
/// The pool it waited in was memory in the process that made it, and the
/// command line exits after every payment. Nothing asked what the next
/// command knew, so a wallet that forgot every payment it had made passed:
/// the next `balance` showed nothing waiting and the spent notes as
/// spendable, and the same payment sent again spent the same notes.
#[test]
fn a_payment_one_command_made_is_still_waiting_in_the_next() {
    let (wallet, funded) = funded("next-command", 3, params());
    let peer = peer_beside(&wallet, &funded);
    let amount = cairn("10");
    let fee = wallet.floor_for(recipient(), amount);

    let sent = wallet.send(recipient(), amount, fee).unwrap();
    assert!(sent.handed_on, "fixture: the peer beside it was offered it");
    assert!(
        !wallet.forget_if_unoffered(&sent),
        "a payment a peer was offered was forgotten as one nobody was offered"
    );
    let spendable = wallet.holdings().spendable;
    let its_notes = inputs_of(&pooled(&wallet, &sent.id).unwrap());
    wallet.shutdown();
    drop(wallet);
    peer.shutdown();

    // The next command: a new process, the same key file and directory.
    let again = funded.open();
    let waiting = again.waiting();
    let holdings = again.holdings();
    let second = again.send(recipient(), amount, fee);
    let reused = second
        .as_ref()
        .ok()
        .and_then(|sent| pooled(&again, &sent.id))
        .is_some_and(|transfer| !inputs_of(&transfer).is_disjoint(&its_notes));
    again.shutdown();
    drop(again);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert_eq!(
        waiting.iter().map(|one| one.id).collect::<Vec<_>>(),
        vec![sent.id],
        "the next command did not show the payment the last one handed over as waiting"
    );
    assert_eq!(
        holdings.spendable, spendable,
        "the next command counted the notes a waiting payment holds as spendable again"
    );
    // Sending again is a second payment, as it is in the process that made
    // the first (`adversarial.rs` holds that), and it has to be one: built
    // from notes the first does not spend, so the two are not one payment
    // the network decides between.
    assert!(second.is_ok(), "a second payment was refused");
    assert!(!reused, "the same notes were spent a second time");
}

/// A payment the pool let go of is still named, and its notes are still
/// held, until the chain settles what became of it.
///
/// The pool asks every transfer it holds again after every block, and a
/// payment paying exactly the floor is let go of the block after a note it
/// spends falls out of the hot set: the transfer frees one place fewer, and
/// the burn of the place it takes instead is more than it pays. Nothing asked what the wallet said then, so a wallet that
/// dropped the payment from every list passed, and its balance went back up
/// as if the money had never left, which is what a carried payment also looks
/// like until no `sent` line arrives.
#[test]
fn a_payment_the_pool_let_go_of_is_still_named() {
    let (wallet, mut funded) = funded("let-go", 4, small_hot_set());
    let stranger = somebody();
    let fee = wallet.floor_for(recipient(), cairn("10"));
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();
    assert_eq!(
        wallet.waiting().len(),
        1,
        "fixture: handed over and waiting"
    );

    let mut blocks = 0;
    while pooled(&wallet, &sent.id).is_some() && blocks < 12 {
        let block = funded.forge.mine(&stranger, Vec::new());
        wallet.node().submit_block(block).unwrap();
        blocks += 1;
    }
    assert!(
        pooled(&wallet, &sent.id).is_none(),
        "fixture: after {blocks} blocks the pool still holds the payment, so this test no \
         longer reaches what it is about"
    );

    let waiting = wallet.waiting();
    let holdings = wallet.holdings();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        waiting.iter().any(|one| one.id == sent.id),
        "the pool let the payment go and the wallet stopped naming it: no block carried it \
         and nothing says so"
    );
    assert!(
        holdings.waiting > Amount::ZERO,
        "the notes of a payment the pool let go of went straight back to the balance, \
         while a peer that still holds the payment could have it carried"
    );
}

/// A payment handed over while no peer was connected is offered to the
/// first peer that arrives, once the wallet is looked at again.
///
/// It was offered for five seconds, once, and nothing offered it again: no
/// message carries a pool. So the page said it was not sent and showed it
/// waiting for a block, with its notes held, until the wallet was closed.
#[test]
fn a_payment_nobody_was_offered_reaches_a_peer_that_arrives_later() {
    let (wallet, funded) = funded("nobody-offered", 4, params());
    let fee = wallet.floor_for(recipient(), cairn("10"));
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();
    assert!(
        !sent.handed_on,
        "fixture: no peer was connected, so nobody could have been offered it"
    );

    let peer = peer_beside(&wallet, &funded);
    // What the page does every two seconds.
    let reached = until(Duration::from_secs(20), || {
        let _ = wallet.waiting();
        peer.with_chain(|chain| chain.pooled(&sent.id).is_some())
    });
    peer.shutdown();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        reached,
        "a peer that arrived after the payment was handed over was never offered it, while \
         the wallet went on holding its notes for it"
    );
}

/// A refusal for want of money names the rewards that cannot move yet.
///
/// Its two sibling clauses name money held by a waiting payment and money in
/// notes nobody can prove. A miner whose only money was a young reward was
/// told the amount was more than the nought this wallet can spend, with
/// nothing about the fifty it holds, and nothing asked.
#[test]
fn a_refusal_for_want_of_money_names_the_rewards_that_are_ripening() {
    let (wallet, funded) = funded(
        "ripening",
        1,
        ConsensusParams::testnet().with_coinbase_maturity(10),
    );
    let holdings = wallet.holdings();
    assert!(
        holdings.ripening > Amount::ZERO && holdings.spendable == Amount::ZERO,
        "fixture: the only money is a reward that cannot move yet"
    );
    let refused = wallet.send(recipient(), cairn("10"), cairn("0.001"));
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    let said = refused.unwrap_err().to_string();
    assert!(
        said.contains(&holdings.ripening.to_string()),
        "a refusal for want of money said nothing about the reward the wallet holds and \
         cannot move yet"
    );
}

/// A payment spending a fallen note, whose proof went stale under it, is
/// handed back to the pool with a fresh one.
///
/// A proof folds up to what the whole cold set comes to, which changes every
/// time a note falls anywhere, and the pool checks every transfer it holds
/// again after every block. What identifies a transfer leaves its proofs out
/// so that it can be offered again with a fresher one, and nothing did: the
/// pool let the payment go and it stayed gone, with its sender told it was
/// waiting for a block.
#[test]
fn a_payment_whose_proof_went_stale_is_handed_back_with_a_fresh_one() {
    let (wallet, mut funded) = funded("stale-proof", 4, small_hot_set());
    let stranger = somebody();
    // Two blocks paying somebody else push this key's two oldest rewards out
    // of the hot set of four.
    for _ in 0..2 {
        let block = funded.forge.mine(&stranger, Vec::new());
        wallet.node().submit_block(block).unwrap();
    }
    assert_eq!(
        wallet
            .holdings()
            .notes
            .iter()
            .filter(|held| held.is_cold())
            .count(),
        2,
        "fixture: two of the four rewards have fallen and can be proved"
    );

    // More than the two hot rewards hold, so a fallen one goes with them, and
    // a fee well over the floor, so what moves under it is only the proof.
    let sent = wallet
        .send(recipient(), cairn("120"), cairn("0.01"))
        .unwrap();
    assert!(
        sent.from_cold > 0,
        "fixture: the payment spends a fallen note"
    );

    let mut blocks = 0;
    while pooled(&wallet, &sent.id).is_some() && blocks < 6 {
        let block = funded.forge.mine(&stranger, Vec::new());
        wallet.node().submit_block(block).unwrap();
        blocks += 1;
    }
    assert!(
        pooled(&wallet, &sent.id).is_none(),
        "fixture: after {blocks} blocks the pool still holds the payment, so its proof never \
         went stale and this test no longer reaches what it is about"
    );

    let waiting = wallet.waiting();
    let again = pooled(&wallet, &sent.id);
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        again.is_some(),
        "the pool let go of a payment whose proof went stale, and nothing handed it back \
         with a fresh one"
    );
    assert!(
        waiting.iter().any(|one| one.id == sent.id && one.pooled),
        "the payment handed back is not shown as held by this wallet's node"
    );
}

/// A payment its node will not take back holds its notes for a few blocks,
/// says why, and is then named as not carried with its money back in the
/// balance.
///
/// With nothing to end it, a payment the pool refused would hold its notes
/// for as long as the record lasts, and a payment nothing names looks
/// exactly like one a block carried.
#[test]
fn a_payment_its_node_will_not_take_back_is_named_as_not_carried() {
    let (wallet, mut funded) = funded("not-carried", 4, small_hot_set());
    let stranger = somebody();
    let before = wallet.holdings().spendable;
    let fee = wallet.floor_for(recipient(), cairn("10"));
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();

    let mut refused_at = None;
    for _ in 0..40 {
        let block = funded.forge.mine(&stranger, Vec::new());
        wallet.node().submit_block(block).unwrap();
        let waiting = wallet.waiting();
        if refused_at.is_none() {
            refused_at = waiting
                .iter()
                .find(|one| one.id == sent.id && !one.pooled)
                .and_then(|one| {
                    assert!(
                        one.why
                            .as_deref()
                            .is_some_and(|why| why.contains("now asks")),
                        "a payment its node refused does not say why"
                    );
                    one.held_until
                });
        }
        if !wallet.not_carried().is_empty() {
            break;
        }
    }
    let height = wallet.progress().height.unwrap();
    let not_carried = wallet.not_carried();
    let waiting = wallet.waiting();
    let holdings = wallet.holdings();

    // And the next start reads the same thing back.
    wallet.shutdown();
    drop(wallet);
    let again = funded.open();
    let named_again = again.not_carried();
    again.shutdown();
    drop(again);
    let _ = std::fs::remove_dir_all(&funded.directory);

    let until = refused_at.expect("the payment was never shown as refused by its node");
    assert_eq!(
        height, until,
        "the payment was let go of at a block other than the one it said its notes were held \
         until"
    );
    assert_eq!(
        not_carried.iter().map(|one| one.id).collect::<Vec<_>>(),
        vec![sent.id],
        "a payment let go of is not named as not carried"
    );
    assert_eq!(
        not_carried[0].amount,
        cairn("10").checked_add(fee).unwrap(),
        "a payment not carried is not named with what it would have taken"
    );
    assert!(
        waiting.iter().all(|one| one.id != sent.id),
        "a payment named as not carried is still listed as waiting"
    );
    assert_eq!(holdings.waiting, Amount::ZERO, "its notes are still held");
    assert!(
        holdings.spendable >= before,
        "the money of a payment that was not carried did not come back to the balance"
    );
    assert_eq!(
        named_again.iter().map(|one| one.id).collect::<Vec<_>>(),
        vec![sent.id],
        "the next start did not read back that the payment was not carried"
    );
    assert!(
        not_carried[0].notes_here,
        "the notes of a payment its node let go of are not said to be this key's"
    );
}

/// A payment a block carried is not named as waiting or as not carried, in
/// this run or the next.
///
/// The other half of the record: without it, every payment made would stay
/// listed as waiting, holding notes a block had already spent. It stays on the
/// record, marked with the block that carried it, until no switch can undo
/// that block: `a_payment_a_reorganisation_put_back_is_still_waiting_at_the_next_start`
/// holds why.
#[test]
fn a_payment_a_block_carried_is_neither_waiting_nor_named_as_not_carried() {
    let (wallet, mut funded) = funded("carried", 3, params());
    let miner = somebody();
    let fee = wallet.floor_for(recipient(), cairn("10"));
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();
    let transfer = pooled(&wallet, &sent.id).unwrap();
    let block = funded.forge.mine(&miner, vec![transfer]);
    wallet.node().submit_block(block).unwrap();

    let waiting = wallet.waiting();
    let not_carried = wallet.not_carried();
    wallet.shutdown();
    drop(wallet);
    let again = funded.open();
    // The block is on disk, so the next start has the chain it carried.
    let waiting_again = again.waiting();
    let not_carried_again = again.not_carried();
    again.shutdown();
    drop(again);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        waiting.is_empty(),
        "a carried payment is still listed as waiting"
    );
    assert!(
        not_carried.is_empty(),
        "a carried payment is named as not carried"
    );
    assert!(
        waiting_again.is_empty() && not_carried_again.is_empty(),
        "the next start still has the carried payment on its record"
    );
}

/// A payment paying what the wallet quotes for a blank fee is still in the
/// pool after the block a note it spends falls out of the hot set in.
///
/// The quote was the floor exactly, and the pool asks the floor again after
/// every block against a transfer that frees one place fewer once a note of
/// it has fallen. Nothing asked whether the quote survived that, so a wallet
/// whose every default payment was let go of the block after one of its notes
/// fell passed.
#[test]
fn the_fee_a_wallet_quotes_carries_a_payment_past_a_note_of_it_falling() {
    let (wallet, mut funded) = funded("quote-margin", 4, small_hot_set());
    let stranger = somebody();
    let fee = wallet.fee_for(recipient(), cairn("10"));
    assert!(
        fee > wallet.floor_for(recipient(), cairn("10")),
        "the quote for a blank fee is the floor exactly"
    );
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();
    let its_notes = inputs_of(&pooled(&wallet, &sent.id).unwrap());

    let hot = |wallet: &Wallet| {
        wallet.node().with_chain(|chain| {
            its_notes
                .iter()
                .filter(|note| chain.state().hot_note(note).is_some())
                .count()
        })
    };
    let mut blocks = 0;
    while hot(&wallet) == its_notes.len() && blocks < 8 {
        let block = funded.forge.mine(&stranger, Vec::new());
        wallet.node().submit_block(block).unwrap();
        blocks += 1;
    }
    let fell = hot(&wallet) < its_notes.len();
    let still = pooled(&wallet, &sent.id).is_some();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        fell,
        "fixture: no note the payment spends fell in {blocks} blocks"
    );
    assert!(
        still,
        "the pool let go of a payment paying the wallet's own quote the block a note of it \
         fell out of the hot set"
    );
}

/// An address a client can dial: a wallet's node listens on every interface
/// and reports a place rather than a machine, which Windows will not dial.
fn reachable(address: std::net::SocketAddr) -> std::net::SocketAddr {
    if address.ip().is_unspecified() {
        std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, address.port()))
    } else {
        address
    }
}

/// A wallet goes on waiting while a peer says its chain has more work than
/// the wallet's, and says so when its patience runs out.
///
/// The wait ended once the height had held still for two seconds with a
/// peer to ask, and on a network whose first block is in the program the
/// height holds still from the first moment of a join. The number that tells
/// a chain that stopped from a chain that is behind was in the handshake and
/// thrown away, and nothing asked about it, so a wallet that answered from
/// block nought while every peer was ahead passed.
#[test]
fn a_wallet_waits_while_a_peer_says_its_chain_has_more_work() {
    use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
    use cairn_net::wire::write_message;

    let (wallet, funded) = funded("claims-more", 2, params());
    // Introduces itself with far more work than there is, and sends nothing.
    let socket = std::net::TcpStream::connect(reachable(wallet.node().address())).unwrap();
    let claim = Message::Hello(Handshake {
        version: PROTOCOL_VERSION,
        network: funded.params.network,
        genesis: Hash32::ZERO,
        height: 1_000,
        total_work: u128::from(u64::MAX),
        listen: 0,
        nonce: 77,
        keeps: cairn_net::Keeps {
            headers: false,
            cold_set: false,
        },
    });
    write_message(&mut &socket, funded.params.network, &claim).unwrap();
    // Read what the node sends and answer nothing, so a full buffer never
    // ends the connection this is about.
    let mut reading = socket.try_clone().unwrap();
    std::thread::spawn(move || {
        let mut bin = [0u8; 4096];
        while let Ok(read) = std::io::Read::read(&mut reading, &mut bin) {
            if read == 0 {
                return;
            }
        }
    });
    assert!(
        until(Duration::from_secs(20), || wallet.progress().peers > 0),
        "fixture: the peer introduced itself"
    );

    let waited = wallet.catch_up(Duration::from_secs(4));
    drop(socket);
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert_eq!(
        waited,
        Waited::Behind {
            ours: Some(1),
            theirs: 1_000
        },
        "the wallet stopped waiting while a peer said its chain had more work, or did not \
         say so when it did stop"
    );
}

/// A payment named as not carried that a block carries after all, from a
/// peer that still held it, stops being named as not carried.
///
/// The floor a pool asks is its own policy and not a rule of the chain, so a
/// miner may carry what this wallet's node let go of. Named as not carried
/// beside a `sent` line for the same payment, it would tell its owner to pay
/// again what had been paid.
#[test]
fn a_payment_named_as_not_carried_that_a_block_carries_after_all_is_named_no_more() {
    let (wallet, mut funded) = funded("carried-after-all", 4, small_hot_set());
    let stranger = somebody();
    // Enough for the burn once a note of it has fallen, so a block may carry
    // it, and not for the floor, so its own node lets it go.
    let fee = short_of_the_floor_once_fallen(&wallet);
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();
    let transfer = pooled(&wallet, &sent.id).unwrap();

    let mut blocks = 0;
    while wallet.not_carried().is_empty() && blocks < 40 {
        let block = funded.forge.mine(&stranger, Vec::new());
        wallet.node().submit_block(block).unwrap();
        let _ = wallet.waiting();
        blocks += 1;
    }
    assert_eq!(
        wallet.not_carried().len(),
        1,
        "fixture: the payment was never named as not carried"
    );

    let block = funded.forge.mine(&stranger, vec![transfer]);
    wallet.node().submit_block(block).unwrap();
    let waiting = wallet.waiting();
    let named = wallet.not_carried();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        named.is_empty(),
        "a payment a block carried is still named as not carried"
    );
    assert!(waiting.is_empty(), "and is listed as waiting");
}

/// Asks a served wallet one question, the way its own page asks it, and
/// returns the body of the answer.
fn ask_the_page(opened: &cairn_wallet::serve::Opened, path: &str, body: &str) -> String {
    use std::io::{Read, Write};
    let host = opened.address.to_string();
    let mut stream = std::net::TcpStream::connect(opened.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let request = if body.is_empty() {
        format!(
            "GET {path}?k={} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n",
            opened.secret
        )
    } else {
        let body = format!("k={}&{body}", opened.secret);
        format!(
            "POST {path} HTTP/1.1\r\nhost: {host}\r\norigin: http://{host}\r\n\
             content-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        )
    };
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
        .split_once("\r\n\r\n")
        .map_or(String::new(), |(_, body)| body.to_owned())
}

/// The page is told what the command line is told: who a quote pays and
/// whether that is this wallet itself, how many peers a payment was written
/// to, which payments are waiting and whether this wallet's node holds each,
/// and which were not carried.
///
/// The page's script reads every one of these, and nothing in Rust asked
/// that the wallet sent them: a field the script reads and the answer lacks
/// is a sentence on the page with `undefined` in it.
#[test]
fn the_page_is_told_what_became_of_its_payments() {
    let (wallet, funded) = funded("page-told", 3, params());
    let wallet = std::sync::Arc::new(wallet);
    let (listener, opened) = cairn_wallet::serve::open(0).unwrap();
    let opened = std::sync::Arc::new(opened);
    let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let serving = {
        let (wallet, opened, alive) = (
            std::sync::Arc::clone(&wallet),
            std::sync::Arc::clone(&opened),
            std::sync::Arc::clone(&alive),
        );
        std::thread::spawn(move || cairn_wallet::serve::run(&wallet, &listener, &opened, &alive))
    };

    let to = cairn_ledger::note::Address::from(recipient()).to_text(params().network);
    let quote = ask_the_page(&opened, "/api/quote", &format!("to={to}&amount=10"));
    let own = wallet.address_text();
    let to_itself = ask_the_page(&opened, "/api/quote", &format!("to={own}&amount=10"));
    let sent = ask_the_page(
        &opened,
        "/api/send",
        &format!("to={to}&amount=10&fee=0.001"),
    );
    let state = ask_the_page(&opened, "/api/state", "");

    alive.store(false, std::sync::atomic::Ordering::SeqCst);
    let _ = std::net::TcpStream::connect(opened.address);
    let _ = serving.join();
    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        quote.contains(&format!("\"to\":\"{to}\"")) && quote.contains("\"toItself\":false"),
        "a quote does not say back who it pays"
    );
    assert!(
        to_itself.contains("\"toItself\":true"),
        "a quote to this wallet's own address does not say so"
    );
    assert!(
        sent.contains("\"sent\":true") && sent.contains("\"offered\":0"),
        "a payment sent does not say how many peers it was written to"
    );
    assert!(
        state.contains("\"pooled\":true") && state.contains("\"why\":null"),
        "a waiting payment is not said to be held by this wallet's node"
    );
    assert!(
        state.contains("\"nothingHere\":null"),
        "a wallet holding money is given words for holding nothing"
    );
    assert!(
        state.contains("\"notCarried\":[]") && state.contains("\"paymentsUnkept\":null"),
        "the payments not carried, and whether the record is kept, are not said"
    );
    assert!(
        state.contains("\"perhapsCarried\":[]")
            && state.contains("\"perhapsCarriedNote\":")
            && state.contains("\"notCarriedNote\":"),
        "the payments a block may have carried, and the words for each list, are not said"
    );
}

/// A payment whose notes another payment from the same key spent is named
/// as not carried, with the reason, and its record goes when nothing more
/// can be said of it.
///
/// Another copy of the key, or a payment made afresh from the same notes,
/// can spend them first, and then nothing will ever carry this one. It
/// vanished from the list of waiting payments without a word, which is also
/// what a carried payment looks like.
#[test]
fn a_payment_whose_notes_another_spent_is_named_as_not_carried() {
    use cairn_ledger::transaction::Input;

    let (wallet, mut funded) = funded("overtaken", 1, params());
    let owner = funded.secret.public_key();
    let fee = wallet.floor_for(recipient(), cairn("10"));
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();
    let first = pooled(&wallet, &sent.id).unwrap();

    // The same note, spent another way by the same key.
    let note = first.inputs[0].note_id;
    let other = somebody();
    let value = funded.params.initial_reward;
    let mut rival = Transfer::new(
        vec![Input::hot(note)],
        vec![Note::new(value.checked_sub(cairn("0.01")).unwrap(), other)],
    );
    rival.sign_input(
        funded.params.network,
        0,
        &Note::new(value, owner),
        &funded.secret,
    );
    let block = funded.forge.mine(&other, vec![rival]);
    wallet.node().submit_block(block).unwrap();

    let waiting = wallet.waiting();
    let named = wallet.not_carried();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        waiting.iter().all(|one| one.id != sent.id),
        "a payment whose notes another spent is still listed as waiting"
    );
    assert_eq!(
        named.iter().map(|one| one.id).collect::<Vec<_>>(),
        vec![sent.id],
        "a payment whose notes another spent is not named as not carried"
    );
    assert!(
        named[0]
            .why
            .contains("another payment from this key spent them"),
        "the reason a payment was not carried is not said"
    );
    let said = cairn_wallet::not_carried_note(&named).unwrap_or_default();
    assert!(
        !named[0].notes_here
            && said.contains("no longer this key's")
            && !said.contains("back in the balance above, and"),
        "a payment whose notes another payment spent is said to have its money back in the \
         balance: {said}"
    );
}

/// A payment nobody was offered is forgotten when the command line says it
/// was not sent, so the next run neither holds its notes nor hands it over.
///
/// The command line tells the person the money is still here and to run it
/// again. Kept on the record, the next start would hand this payment over as
/// well as the one sent again, and pay twice from two sets of notes.
#[test]
fn a_payment_nobody_was_offered_is_forgotten_when_the_command_says_so() {
    let (wallet, funded) = funded("forgotten-unoffered", 2, params());
    let fee = wallet.floor_for(recipient(), cairn("10"));
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();
    assert!(
        !sent.handed_on,
        "fixture: nobody was connected to offer it to"
    );
    let forgot = wallet.forget_if_unoffered(&sent);
    let again_forgot = wallet.forget_if_unoffered(&sent);
    wallet.shutdown();
    drop(wallet);

    let again = funded.open();
    let waiting = again.waiting();
    let holdings = again.holdings();
    again.shutdown();
    drop(again);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(forgot, "a payment nobody was offered was not forgotten");
    assert!(!again_forgot, "forgotten twice");
    assert!(waiting.is_empty(), "the next start still waits on it");
    assert_eq!(holdings.waiting, Amount::ZERO, "and still holds its notes");
}

/// A record of payments that does not read back is set aside, and the
/// wallet says so wherever it says what is waiting.
///
/// Read as no payments and written over at the next one, the payments it
/// held would be forgotten without a word, which is the defect the record
/// exists to end.
#[test]
fn a_record_of_payments_that_does_not_read_back_is_said() {
    let (wallet, funded) = funded("unkept", 1, params());
    assert_eq!(wallet.payments_unkept(), None, "fixture: nothing to say");
    wallet.shutdown();
    drop(wallet);
    std::fs::write(funded.data().join("pending.dat"), b"not a record").unwrap();

    let again = funded.open();
    let said = again.payments_unkept();
    again.shutdown();
    drop(again);
    let kept = std::fs::read(funded.data().join("pending.dat.unread")).ok();
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        said.is_some_and(|said| said.contains("pending.dat.unread")),
        "a record of payments that did not read back was passed over"
    );
    assert_eq!(
        kept.as_deref(),
        Some(b"not a record".as_slice()),
        "and was not kept"
    );
}

/// Of two payments waiting, the one its node will not take back is let go of
/// on its own, the look that lets go of it no longer lists it and writes it
/// down, and the other goes on waiting.
///
/// Every test here followed one payment, so a wallet that judged a payment by
/// whether some other payment was in the pool passed. And every test looked
/// again before closing the wallet, so one that wrote the record down only at
/// the look after a change passed too, while a command that exits after its
/// last look loses what that look learned.
#[test]
fn of_two_payments_the_one_not_taken_back_is_let_go_of_on_its_own() {
    let (wallet, mut funded) = funded("two-waiting", 4, small_hot_set());
    let stranger = somebody();
    let generous = wallet.send(somebody(), cairn("10"), cairn("0.01")).unwrap();
    let fee = wallet.floor_for(recipient(), cairn("10"));
    let exact = wallet.send(recipient(), cairn("10"), fee).unwrap();

    let mut let_go = None;
    for _ in 0..40 {
        let block = funded.forge.mine(&stranger, Vec::new());
        wallet.node().submit_block(block).unwrap();
        let waiting = wallet.waiting();
        if !wallet.not_carried().is_empty() {
            let_go = Some(waiting);
            break;
        }
    }
    let named = wallet.not_carried();
    // Closed straight after the look that let the payment go, as a command
    // that has answered is, and read back before anything looks again.
    wallet.shutdown();
    drop(wallet);
    let again = funded.open();
    let named_again = again.not_carried();
    let later = again.waiting();
    again.shutdown();
    drop(again);
    let _ = std::fs::remove_dir_all(&funded.directory);

    let waiting = let_go.expect("the payment paying exactly the floor was never let go of");
    assert_eq!(
        named_again.iter().map(|one| one.id).collect::<Vec<_>>(),
        vec![exact.id],
        "the look that let a payment go did not write it down, so the next start did not know"
    );
    assert_eq!(
        named.iter().map(|one| one.id).collect::<Vec<_>>(),
        vec![exact.id],
        "the payment its node would not take back is not the one named as not carried"
    );
    assert!(
        waiting.iter().all(|one| one.id != exact.id),
        "the look that let a payment go still listed it as waiting"
    );
    assert!(
        later.iter().any(|one| one.id == generous.id),
        "the payment its node still holds stopped being listed as waiting"
    );
}

/// A payment whose block a reorganisation undid, and which the chain put
/// back in the pool, is still waiting at the next start, with its notes held.
///
/// The record let go of a payment at the first block that carried it. A
/// switch that undoes that block puts the transfer back in the pool of every
/// node that saw it, this one's included, where the page showed it waiting;
/// nothing wrote it back onto the record, and the pool dies with the process.
/// Nothing asked what the next start knew after a switch, so a wallet whose
/// next command listed nothing waiting and counted the notes as spendable,
/// while peers could still hand the transfer to a miner, passed.
#[test]
fn a_payment_a_reorganisation_put_back_is_still_waiting_at_the_next_start() {
    let (wallet, mut funded) = funded("undone-and-pooled", 3, params());
    let stranger = somebody();
    // Where the two branches part.
    let mut rival = funded.forge.clone();
    let fee = wallet.floor_for(recipient(), cairn("10"));
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();
    let transfer = pooled(&wallet, &sent.id).unwrap();
    wallet
        .node()
        .submit_block(funded.forge.mine(&stranger, vec![transfer]))
        .unwrap();
    let once_carried = wallet.waiting();
    // A heavier branch without it.
    for _ in 0..2 {
        wallet
            .node()
            .submit_block(rival.mine(&stranger, Vec::new()))
            .unwrap();
    }
    let height = wallet.progress().height;
    let waiting_here = wallet.waiting();
    let undone = wallet.undone();
    wallet.shutdown();
    drop(wallet);

    // The next command: a new process on the same key and directory.
    let again = funded.open();
    let waiting_next = again.waiting();
    let holdings_next = again.holdings();
    again.shutdown();
    drop(again);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        once_carried.iter().all(|one| one.id != sent.id),
        "fixture: once a block carried it, the payment was not waiting"
    );
    assert_eq!(
        height,
        Some(4),
        "fixture: the node followed the heavier branch"
    );
    assert!(
        undone.iter().any(|one| one.id == sent.id),
        "fixture: the account lists the payment as taken back"
    );
    assert!(
        waiting_here
            .iter()
            .any(|one| one.id == sent.id && one.pooled),
        "fixture: the switch put the payment back in this process's pool"
    );
    assert!(
        waiting_next.iter().any(|one| one.id == sent.id),
        "a payment a reorganisation undid and the pool took back is not on the record: the \
         next start does not list it as waiting"
    );
    assert!(
        holdings_next.waiting > Amount::ZERO,
        "the next start counts the notes of a payment peers may still carry as spendable"
    );
}

/// A payment sent again after the wallet named the first as not carried
/// spends one of the first one's notes, so no block can carry both.
///
/// A payment its node would not take back is let go of after a few blocks
/// and its money comes back to the balance. What the node refused it over is
/// its pool's fee floor, which no block is held to, so the transfer as it was
/// made is still one a miner may carry. The payment made next reached for
/// other notes, and nothing asked whether the two could both be carried: a
/// block carrying both paid the recipient twice.
#[test]
fn a_payment_sent_again_after_one_was_let_go_of_cannot_be_carried_beside_it() {
    let (wallet, mut funded) = funded("sent-again", 4, small_hot_set());
    let stranger = somebody();
    // Enough for the burn once a note of it has fallen, and not for the
    // floor: the first payment is one a miner may still carry.
    let fee = short_of_the_floor_once_fallen(&wallet);
    let first = wallet.send(recipient(), cairn("10"), fee).unwrap();
    let as_made = pooled(&wallet, &first.id).unwrap();

    let mut blocks = 0;
    while wallet.not_carried().is_empty() && blocks < 40 {
        wallet
            .node()
            .submit_block(funded.forge.mine(&stranger, Vec::new()))
            .unwrap();
        let _ = wallet.waiting();
        blocks += 1;
    }
    let named = wallet.not_carried();
    // Somebody pays this wallet meanwhile, so it holds a note the first
    // payment does not spend.
    let owner = funded.secret.public_key();
    wallet
        .node()
        .submit_block(funded.forge.mine(&owner, Vec::new()))
        .unwrap();

    let fee_again = wallet.fee_for(recipient(), cairn("10"));
    let again = wallet.send(recipient(), cairn("10"), fee_again).unwrap();
    let sent_again = pooled(&wallet, &again.id).unwrap();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert_eq!(
        named.iter().map(|one| one.id).collect::<Vec<_>>(),
        vec![first.id],
        "fixture: after {blocks} blocks the first payment was named as not carried"
    );
    assert!(
        !inputs_of(&as_made).is_disjoint(&inputs_of(&sent_again)),
        "the payment sent again spends none of the notes of the one it replaces, which a block \
         may still carry: both can be carried and the recipient paid twice"
    );
}

/// A payment whose record cannot be written is not handed to anybody.
///
/// The pool passes a transfer to every connected peer the moment it takes it,
/// and the record was written after that. A record that would not write, on a
/// full disk or a directory the wallet cannot write to, was noted in memory
/// and the payment went on: a peer held it, the command line said "This
/// wallet has written it down", and the next start listed nothing waiting and
/// counted its notes as spendable. Nothing made the record refuse a write
/// during a payment.
#[test]
fn a_payment_the_record_cannot_keep_is_not_handed_to_anybody() {
    let (wallet, funded) = funded("unrecorded", 3, params());
    let peer = peer_beside(&wallet, &funded);
    // What a full disk, or a directory that is not writable, does to the
    // record: its partial file cannot be made.
    std::fs::create_dir_all(funded.data().join("pending.part").join("in-the-way")).unwrap();
    let before = wallet.holdings().spendable;
    let fee = wallet.fee_for(recipient(), cairn("10"));
    let sent = wallet.send(recipient(), cairn("10"), fee);
    let pooled_here = wallet.node().with_chain(cairn_chain::ChainStore::pool_len);
    let after = wallet.holdings().spendable;
    wallet.shutdown();
    drop(wallet);
    peer.shutdown();
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        matches!(sent, Err(cairn_wallet::WalletError::Unrecorded(_))),
        "a payment whose record could not be written was handed over, and the next start \
         would not know it is waiting"
    );
    assert_eq!(
        pooled_here, 0,
        "the pool, which passes a payment to every peer the moment it takes it, took it"
    );
    assert_eq!(after, before, "a payment nobody was handed holds notes");
}

/// A payment is not said to be written to a peer when the only thing
/// connected is a socket that never introduced itself.
///
/// A connection the wallet dialled is spoken to before its far end says a
/// word, and the count of queues that took the payment counted it. Both faces
/// said "Written to 1 peer" while no Cairn node had it. Every test that sent a
/// payment had a real peer beside it, or nobody.
#[test]
fn a_socket_that_never_introduced_itself_is_not_counted_as_a_peer_written_to() {
    let (wallet, funded) = funded("silent-socket", 3, params());
    // Accepts, holds each connection open, and never reads or says a word.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let held = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let holding = std::sync::Arc::clone(&held);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            holding.lock().unwrap().push(stream);
        }
    });
    assert!(wallet.reach(address), "fixture: the socket accepts");
    assert!(
        until(Duration::from_secs(20), || !held.lock().unwrap().is_empty()),
        "fixture: the wallet's connection reached the socket"
    );

    let fee = wallet.fee_for(recipient(), cairn("10"));
    let sent = wallet.send(recipient(), cairn("10"), fee).unwrap();
    wallet.shutdown();
    drop(wallet);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert_eq!(
        (sent.offered, sent.handed_on),
        (0, false),
        "a payment is said to be written to a peer, and the only thing connected is a socket \
         that never said a word"
    );
}

/// A payment of this key's that the pool holds and the record does not is
/// written down, so the next start lists it waiting, and it is named with
/// what it takes from this key when it is not carried.
///
/// Another copy of the key, or a record that lost it, leaves a payment this
/// process's pool holds and nothing wrote down: the run that saw it listed it
/// waiting, the next listed nothing and counted its notes as spendable while
/// peers could still carry it. Nothing handed a wallet's node a payment the
/// wallet had not made itself.
#[test]
fn a_payment_the_pool_holds_and_the_record_does_not_is_written_down() {
    use cairn_ledger::transaction::Input;

    let (wallet, mut funded) = funded("adopted", 2, params());
    let owner = funded.secret.public_key();
    let reward = funded.blocks[0].coinbase.created_notes()[0];
    let value = reward.1.value;
    let (paid, fee) = (cairn("10"), cairn("0.01"));
    let change = value.checked_sub(paid).unwrap().checked_sub(fee).unwrap();
    let signed = |outputs: Vec<Note>| {
        let mut transfer = Transfer::new(vec![Input::hot(reward.0)], outputs);
        transfer.sign_input(funded.params.network, 0, &reward.1, &funded.secret);
        transfer
    };
    // Made by another copy of this key, and handed to this wallet's node.
    let elsewhere = signed(vec![Note::new(paid, recipient()), Note::new(change, owner)]);
    assert!(
        matches!(
            wallet.node().submit_transaction(elsewhere.clone()),
            Ok(true)
        ),
        "fixture: the pool took it"
    );
    let _ = wallet.waiting();
    wallet.shutdown();
    drop(wallet);

    let again = funded.open();
    let waiting = again.waiting();
    // A third copy spends the same note, and a block carries that instead.
    let rival = signed(vec![Note::new(value.checked_sub(fee).unwrap(), somebody())]);
    again
        .node()
        .submit_block(funded.forge.mine(&somebody(), vec![rival]))
        .unwrap();
    let _ = again.waiting();
    let named = again.not_carried();
    again.shutdown();
    drop(again);
    let _ = std::fs::remove_dir_all(&funded.directory);

    assert!(
        waiting.iter().any(|one| one.id == elsewhere.id()),
        "a payment of this key's the pool held is not on the record: the next start does not \
         list it as waiting"
    );
    assert_eq!(
        named
            .iter()
            .map(|one| (one.id, one.amount))
            .collect::<Vec<_>>(),
        vec![(elsewhere.id(), paid.checked_add(fee).unwrap())],
        "a payment written down from the pool is not named with what it takes from this key"
    );
}

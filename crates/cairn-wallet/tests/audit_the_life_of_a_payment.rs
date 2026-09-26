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
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::{Waited, Wallet};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

/// A hot set of four, so a note falls out of it a block after it is paid.
fn small_hot_set() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_hot_capacity(4)
        .with_max_evictions(4)
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
/// spends falls out of the hot set: the transfer frees one place fewer and
/// weighs more. Nothing asked what the wallet said then, so a wallet that
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
}

/// A payment a block carried leaves the record, and is not named as waiting
/// or as not carried, in this run or the next.
///
/// The other half of the record: without it, every payment made would stay
/// listed as waiting, holding notes a block had already spent.
#[test]
fn a_payment_a_block_carried_leaves_the_record() {
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
        tip: Hash32::ZERO,
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
fn a_payment_named_as_not_carried_that_a_block_carries_after_all_leaves_the_record() {
    let (wallet, mut funded) = funded("carried-after-all", 4, small_hot_set());
    let stranger = somebody();
    let fee = wallet.floor_for(recipient(), cairn("10"));
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

    let to = recipient();
    let quote = ask_the_page(&opened, "/api/quote", &format!("to={to}&amount=10"));
    let own = wallet.address();
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

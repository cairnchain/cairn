//! A payment confirmed ten blocks deep, and then spent again on a heavier
//! branch: what the payee's wallet says before, while and after.
//!
//! R17 of the testnet-8 attack catalogue (A01). Whoever holds most of the work
//! rewrites recent history: the threat model's row for a majority miner says
//! so and defends nothing against it, and the specification calls a block
//! settled only at the burial, a thousand and twenty four blocks on the public
//! networks. So the payment is meant to be reversible here. What is measured
//! is what its payee is told: whether the wallet says in plain words that the
//! payment was taken back and the money is not there, whether that money is
//! ever counted twice, and whether anything had called the payment settled.
//!
//! "Ten blocks deep" is ten confirmations: the block carrying the payment and
//! nine above it. The attacker pays from a note it holds, mines in private a
//! branch from the block before the payment that spends the same note to
//! itself, and releases it eleven blocks long, one more than the honest
//! branch it replaces.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::pow::median_time_past;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, mine_block, ConsensusParams};
use cairn_net::Node;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::history::Direction;
use cairn_wallet::{serve, Wallet};

const ATTEMPTS: u64 = 1 << 22;

/// A liveness bound, far past what any of this takes on a loaded runner.
const PATIENCE: Duration = Duration::from_secs(180);

/// Confirmations the payee has seen when the other branch arrives.
const DEEP: usize = 10;

/// The public networks' burial and undo limit, so a reorganisation of eleven
/// is well inside what every node takes, as it would be on testnet-8. Rewards
/// spendable at once, so the attacker can be paid in the shared blocks.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("waited {PATIENCE:?} for {what}");
}

fn tip(node: &Node) -> Option<Hash32> {
    node.with_chain(cairn_chain::ChainStore::tip)
}

/// What the miner on `node` finds next, built as `cairnd --mine` builds it:
/// on the node's own chain, with what its pool selects, dated by the clock or
/// past the median of recent blocks, whichever is later.
fn mine_on(node: &Node, to: &PublicKey) -> Block {
    let params = params();
    let block = node.with_chain(|chain| {
        let state = chain.state();
        let height = state.next_height().unwrap();
        let earliest = median_time_past(state.recent_headers()).map_or(0, |median| median + 1);
        let (transfers, fees) = chain.selection(params.max_transfers_per_block);
        let reward = params.reward_at(height).checked_add(fees).unwrap();
        let coinbase = CoinbaseTransaction::new(height, vec![Note::new(reward, *to)]);
        assemble_block(state, coinbase, transfers, &params, now().max(earliest), 0).unwrap()
    });
    let block = mine_block(block, ATTEMPTS).unwrap();
    node.submit_block(block.clone()).unwrap();
    block
}

/// `amount` to `to` out of the note the coinbase of `from` paid `owner`, the
/// rest back to the owner less a fee well over the pool's floor.
fn pay(owner: &SecretKey, from: &Block, to: &PublicKey, amount: Amount) -> Transfer {
    let (id, held) = from.coinbase.created_notes()[0];
    let change = held
        .value
        .checked_sub(amount)
        .and_then(|left| left.checked_sub(Amount::from_pebbles(100_000).unwrap()))
        .unwrap();
    let mut transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![
            Note::new(amount, *to),
            Note::new(change, owner.public_key()),
        ],
    );
    transfer.sign_input(params().network, 0, &held, owner);
    transfer
}

fn get(address: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nhost: {address}\r\nconnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body)
        .to_owned()
}

/// How many times the payee's account lists the payment, as paid and as
/// taken back.
fn listed(wallet: &Wallet, id: &Hash32) -> (usize, usize) {
    let paid = wallet
        .history()
        .iter()
        .filter(|m| m.id == *id && m.direction == Direction::Received)
        .count();
    let taken_back = wallet.undone().iter().filter(|m| m.id == *id).count();
    (paid, taken_back)
}

/// **A payment ten blocks deep, spent again on a heavier branch, is said by
/// the payee's wallet to have been taken back, and is never counted twice.**
#[test]
fn a_payment_ten_blocks_deep_spent_again_on_a_heavier_branch_is_said_to_be_taken_back() {
    let directory = std::env::temp_dir().join(format!(
        "cairn-reversed-{}-{:?}",
        std::process::id(),
        thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let payee_key = key(21);
    let attacker = key(22);
    let honest_miner = key(23).public_key();
    let attacker_miner = key(24).public_key();

    // Five shared blocks, the first paying the attacker the note it will
    // spend twice. Every block sits on the difficulty floor, so the branch
    // with more blocks is the heavier.
    let honest = Node::bind(params(), loopback()).unwrap();
    let mut shared = vec![mine_on(&honest, &attacker.public_key())];
    for _ in 0..4 {
        shared.push(mine_on(&honest, &honest_miner));
    }
    let key_file = directory.join("payee.key");
    cairn_wallet::keyfile::write(&key_file, &payee_key).unwrap();
    let (payee, _) = Wallet::open(&key_file, params(), &directory.join("payee")).unwrap();
    let payee = Arc::new(payee);
    payee.node().connect(honest.address()).unwrap();
    wait_for("the payee's node to follow the honest node", || {
        tip(payee.node()) == tip(&honest)
    });

    // The attacker's private node holds the shared blocks and nothing else.
    let private = Node::bind(params(), loopback()).unwrap();
    for block in &shared {
        private.submit_block(block.clone()).unwrap();
    }

    // The payment, carried by the honest miner and buried under nine more.
    let payment = pay(&attacker, &shared[0], &payee_key.public_key(), cairn("10"));
    let again = pay(&attacker, &shared[0], &attacker_miner, cairn("10"));
    assert!(honest.submit_transaction(payment.clone()).unwrap());
    let carrying = mine_on(&honest, &honest_miner);
    assert!(carrying.transfers.iter().any(|t| t.id() == payment.id()));
    for _ in 1..DEEP {
        mine_on(&honest, &honest_miner);
    }
    wait_for("the payee to see the payment ten blocks deep", || {
        tip(payee.node()) == tip(&honest)
    });

    // In private, the same note spent to the attacker, and eleven blocks.
    assert!(private.submit_transaction(again.clone()).unwrap());
    let branch_first = mine_on(&private, &attacker_miner);
    assert!(branch_first.transfers.iter().any(|t| t.id() == again.id()));
    for _ in 0..DEEP {
        mine_on(&private, &attacker_miner);
    }
    let rewritten = tip(&private).unwrap();
    assert!(private.total_work() > honest.total_work());

    // The page, which is where a payee reads it.
    let (listener, opened) = serve::open(0).unwrap();
    let opened = Arc::new(opened);
    let alive = Arc::new(AtomicBool::new(true));
    let page = {
        let (serving, told, watching) =
            (Arc::clone(&payee), Arc::clone(&opened), Arc::clone(&alive));
        thread::spawn(move || serve::run(&serving, &listener, &told, &watching))
    };
    let state = || {
        get(
            opened.address,
            &format!("/api/state?k={}", opened.secret.as_str()),
        )
    };

    // Before.
    let paid_at = carrying.header.height;
    assert_eq!(listed(&payee, &payment.id()), (1, 0));
    assert_eq!(payee.holdings().total(), cairn("10"));
    assert_eq!(
        payee.progress().height,
        Some(paid_at + DEEP as u64 - 1),
        "fixture: the payment is not ten blocks deep"
    );
    let before = state();
    assert!(before.contains(&payment.id().to_string()));
    assert!(before.contains("\"warning\":null"));
    // A depth a person can work out from the heights on the page, and nothing
    // that calls the payment settled or final: the page has no word for how
    // deep a payment is.
    for word in ["settled", "final", "confirmed", "irreversible"] {
        assert!(
            !before.to_lowercase().contains(word),
            "the page says {word:?} of a payment ten blocks deep"
        );
    }

    // Released. While the payee's node takes the other branch, every reading
    // of the wallet lists the payment once, as paid or as taken back, and
    // never counts more than was paid.
    private.connect(honest.address()).unwrap();
    let deadline = Instant::now() + PATIENCE;
    loop {
        let (paid, taken_back) = listed(&payee, &payment.id());
        let total = payee.holdings().total();
        assert_eq!(
            paid + taken_back,
            1,
            "while the branch was being taken the payment was listed {paid} times as paid and \
             {taken_back} as taken back"
        );
        assert!(
            total <= cairn("10"),
            "while the branch was being taken the payee's balance read {total}"
        );
        if tip(payee.node()) == Some(rewritten) && taken_back == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "waited {PATIENCE:?} for the payee to take the heavier branch"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(tip(&honest), Some(rewritten));

    // After. The payee's account lists the payment once, as taken back, at
    // the height it had, and says in words that the money is gone with the
    // block that paid it.
    let undone = payee.undone();
    let reversed: Vec<_> = undone
        .iter()
        .filter(|m| m.id == payment.id())
        .copied()
        .collect();
    assert_eq!(reversed.len(), 1);
    assert_eq!(reversed[0].direction, Direction::Received);
    assert_eq!(reversed[0].amount, cairn("10"));
    assert_eq!(reversed[0].height, paid_at);
    assert_eq!(listed(&payee, &payment.id()), (0, 1));
    let waiting = payee.waiting();
    assert!(waiting.is_empty());
    let said = cairn_wallet::undone_note(&undone, &waiting).unwrap();
    assert_eq!(
        said,
        "What was paid to you is not in the balance any more: the block that paid it is gone.",
        "the payee is not told in plain words that the money left with the block"
    );
    assert_eq!(
        payee.holdings().total(),
        Amount::ZERO,
        "the payee's balance still counts a payment spent elsewhere on the branch that won"
    );
    // Spent elsewhere on the branch that won, so no pool holds it and no
    // block can carry it again.
    for node in [&honest, payee.node(), &private] {
        assert!(node.with_chain(|chain| chain.pooled(&payment.id()).is_none()));
    }
    let after = state();
    assert!(
        after.contains(&format!("\"undoneNote\":\"{said}\"")),
        "the page does not carry what the wallet says under what was taken back"
    );
    assert!(after.contains("\"undone\":[{"));
    assert!(after.contains("\"spendable\":\"0.00000000 CAIRN\""));
    assert!(after.contains("\"warning\":null"));

    alive.store(false, Ordering::SeqCst);
    let _ = TcpStream::connect(opened.address);
    let _ = page.join();
    payee.shutdown();
    honest.shutdown();
    private.shutdown();
    let _ = std::fs::remove_dir_all(&directory);
}

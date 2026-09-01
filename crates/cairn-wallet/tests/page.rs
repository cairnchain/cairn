//! The page, spoken to the way a browser speaks to it.
//!
//! The unit tests beside `serve.rs` check the four locks one at a time. These
//! run the real server on a real socket and knock: once as the wallet's own
//! page, and once for each way something else might try. A lock that is right
//! in a function and wrong in the wiring is still an open door.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cairn_crypto::SecretKey;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;
use cairn_wallet::serve::{self, Opened};
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// A wallet with four blocks of rewards, served on the loopback.
struct Running {
    wallet: Arc<Wallet>,
    opened: Arc<Opened>,
    alive: Arc<AtomicBool>,
    directory: PathBuf,
    thread: Option<thread::JoinHandle<()>>,
}

impl Running {
    fn start(name: &str, seed: u8, blocks: usize) -> Self {
        let params = ConsensusParams::testnet();
        let directory = std::env::temp_dir().join(format!(
            "cairn-page-{name}-{}-{:?}",
            std::process::id(),
            thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();

        let key_file = directory.join("key");
        let secret = SecretKey::from_bytes(&[seed; 32]);
        cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
        let (wallet, _) = Wallet::open(&key_file, params, &directory.join("data")).unwrap();

        let mut state = LedgerState::new();
        let mut clock = 1_000u64;
        for _ in 0..blocks {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, secret.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            wallet.node().submit_block(block).unwrap();
        }

        let wallet = Arc::new(wallet);
        let (listener, opened) = serve::open(0).unwrap();
        let opened = Arc::new(opened);
        let alive = Arc::new(AtomicBool::new(true));

        let serving = Arc::clone(&wallet);
        let told = Arc::clone(&opened);
        let watching = Arc::clone(&alive);
        let thread = thread::spawn(move || serve::run(&serving, &listener, &told, &watching));

        Self {
            wallet,
            opened,
            alive,
            directory,
            thread: Some(thread),
        }
    }

    /// One request, written out by hand so the headers are exactly what a
    /// caller would send rather than what a client library decides.
    fn ask(&self, head: &str, body: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(self.opened.address).unwrap();
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
        let body = answer.split_once("\r\n\r\n").map_or("", |(_, rest)| rest);
        (status, body.to_owned())
    }

    fn get(&self, path: &str, host: &str, origin: &str) -> (u16, String) {
        use std::fmt::Write as _;
        let mut head = format!("GET {path} HTTP/1.1\r\nhost: {host}");
        if !origin.is_empty() {
            let _ = write!(head, "\r\norigin: {origin}");
        }
        self.ask(&head, "")
    }

    fn secret(&self) -> &str {
        &self.opened.secret
    }

    fn host(&self) -> String {
        self.opened.address.to_string()
    }

    fn stop(mut self) {
        self.alive.store(false, Ordering::SeqCst);
        // One connection of our own, so the accept loop wakes and sees it.
        let _ = TcpStream::connect(self.opened.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.wallet.shutdown();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn the_page_answers_its_own_and_nothing_else() {
    let running = Running::start("locks", 1, 2);
    let host = running.host();
    let secret = running.secret().to_owned();

    // Its own page, navigated to: no origin, the loopback, the secret.
    let (status, body) = running.get(&format!("/?k={secret}"), &host, "");
    assert_eq!(status, 200);
    assert!(body.contains("Cairn wallet"), "the page came back");

    let (status, body) = running.get(&format!("/api/state?k={secret}"), &host, "");
    assert_eq!(status, 200);
    assert!(
        body.contains("\"spendable\":\"100.00000000 CAIRN\""),
        "{body}"
    );
    assert!(body.contains("\"network\":\"testnet-5\""), "{body}");

    // Without the secret, whoever is asking.
    assert_eq!(running.get("/api/state", &host, "").0, 403);
    assert_eq!(running.get("/api/state?k=wrong", &host, "").0, 403);
    assert_eq!(running.get(&format!("/?k={secret}x"), &host, "").0, 403);

    // A page somewhere else in the same browser, which is what all of this is
    // for: it can guess the port and it may even have the secret, and it is
    // still turned away by the origin it cannot forge.
    assert_eq!(
        running
            .get(
                &format!("/api/state?k={secret}"),
                &host,
                "https://example.com"
            )
            .0,
        403
    );

    // A name someone else controls, pointed at this machine. The browser would
    // consider that same-origin with the attacking page, so the host is what
    // has to refuse it.
    assert_eq!(
        running
            .get(&format!("/api/state?k={secret}"), "wallet.example.com", "")
            .0,
        421
    );

    // And nothing else is served at all.
    assert_eq!(
        running.get(&format!("/etc/passwd?k={secret}"), &host, "").0,
        404
    );

    running.stop();
}

/// The look and the script are the same bytes for everyone, so they are not
/// held behind the secret: putting it in the page is putting it in whatever
/// the browser caches.
#[test]
fn the_look_is_served_without_the_secret_and_says_nothing() {
    let running = Running::start("assets", 2, 1);
    let host = running.host();

    let (status, css) = running.get("/style.css", &host, "");
    assert_eq!(status, 200);
    assert!(css.contains("--held:"), "the palette came back");

    let (status, js) = running.get("/wallet.js", &host, "");
    assert_eq!(status, 200);
    assert!(js.contains("api/state"), "the script came back");
    assert!(
        !js.contains(running.secret()),
        "and it carries no secret: it reads one from the address it was opened at"
    );

    running.stop();
}

/// Spending through the page has to work, and has to arrive at the same place
/// spending through the library does.
#[test]
fn money_sent_from_the_page_leaves_the_wallet() {
    let running = Running::start("spend", 3, 4);
    let host = running.host();
    let secret = running.secret().to_owned();
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();

    let before = running.wallet.holdings().spendable;
    let head = format!("POST /api/send HTTP/1.1\r\nhost: {host}\r\norigin: http://{host}");
    // What the network will carry, which is no longer nothing.
    let floor = running
        .wallet
        .floor_for(recipient, Amount::from_cairn("60").unwrap());
    let floor = floor.to_string().replace(" CAIRN", "");
    let body = format!("k={secret}&to={recipient}&amount=60&fee={floor}");
    let (status, answer) = running.ask(&head, &body);
    assert_eq!(status, 200);
    assert!(answer.contains("\"sent\":true"), "{answer}");
    assert!(
        answer.contains("\"amount\":\"60.00000000 CAIRN\""),
        "{answer}"
    );
    // What the page was never told, and what a mistyped fee is paid out of.
    assert!(answer.contains("\"fee\":\""), "{answer}");

    // It is in the pool, which is where a spend goes before a block carries it.
    let pooled = running
        .wallet
        .node()
        .with_chain(cairn_chain::ChainStore::pool_len);
    assert_eq!(pooled, 1, "the transfer is with the network");

    // Nobody has been paid yet, and the notes the payment is made of are out
    // of what can be spent: the network will not carry them twice, so a wallet
    // that went on counting them would build a second payment nothing takes.
    let holdings = running.wallet.holdings();
    assert_eq!(holdings.waiting, Amount::from_cairn("100").unwrap());
    assert_eq!(
        holdings.spendable,
        before.checked_sub(holdings.waiting).unwrap(),
        "the two notes it gathered are spoken for"
    );
    assert_eq!(holdings.total(), before, "and none of it has gone anywhere");

    // What a person mistypes has to come back as something they can act on
    // rather than as a failure.
    let (status, answer) = running.ask(&head, &format!("k={secret}&to=nonsense&amount=1"));
    assert_eq!(status, 200);
    assert!(answer.contains("\"sent\":false"), "{answer}");
    assert!(answer.contains("64 hexadecimal"), "{answer}");

    let (status, answer) = running.ask(&head, &format!("k={secret}&to={recipient}&amount=99999"));
    assert!(answer.contains("\"sent\":false"), "{answer}");
    assert!(answer.contains("more than"), "{answer}");
    assert_eq!(status, 200);

    // A GET cannot spend, whatever it carries: money behind a link is money
    // behind something a page can be made to follow.
    assert_eq!(
        running
            .get(
                &format!("/api/send?k={secret}&to={recipient}&amount=1"),
                &host,
                ""
            )
            .0,
        405
    );

    running.stop();
}

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
        Self::start_with(
            name,
            seed,
            blocks,
            ConsensusParams::testnet().with_coinbase_maturity(0),
        )
    }

    /// The same, with the maturity rule left in force, so a test can serve a
    /// wallet whose whole balance is a reward that cannot move yet.
    fn start_with(name: &str, seed: u8, blocks: usize, params: ConsensusParams) -> Self {
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
    assert!(body.contains("\"network\":\"testnet-6\""), "{body}");

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
    // rather than as a failure, and in the reader's own words, which say what
    // is wrong with it: the command line's words for the same string.
    let (status, answer) = running.ask(&head, &format!("k={secret}&to=nonsense&amount=1"));
    assert_eq!(status, 200);
    assert!(answer.contains("\"sent\":false"), "{answer}");
    assert!(answer.contains("not 32 bytes of hexadecimal"), "{answer}");

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

/// A fee typed into the page is the fee it quotes, and a steep one is paid
/// once it is said again.
///
/// The only fee the page tests ever typed was the floor, which is also what a
/// blank box is filled with, so a page that threw away whatever was typed and
/// used the floor passed. So did a page that read the button saying "I mean
/// it" the wrong way round, since nothing ever pressed it.
#[test]
fn a_fee_typed_into_the_page_is_the_one_quoted_and_paid_once_said_again() {
    let running = Running::start("steep", 4, 2);
    let host = running.host();
    let secret = running.secret().to_owned();
    let recipient = SecretKey::from_bytes(&[9; 32]).public_key();
    let asked = format!("k={secret}&to={recipient}&amount=1&fee=5");

    let quote = format!("POST /api/quote HTTP/1.1\r\nhost: {host}\r\norigin: http://{host}");
    let (status, answer) = running.ask(&quote, &asked);
    assert_eq!(status, 200);
    assert!(
        answer.contains("\"fee\":\"5.00000000 CAIRN\""),
        "the fee typed is not the fee quoted, so the person is shown a number \
         other than the one they are about to pay: {answer}"
    );

    let send = format!("POST /api/send HTTP/1.1\r\nhost: {host}\r\norigin: http://{host}");
    let (status, answer) = running.ask(&send, &asked);
    assert_eq!(status, 200);
    assert!(
        answer.contains("\"sent\":false") && answer.contains("\"steep\":true"),
        "five CAIRN to carry one is asked about before it is paid: {answer}"
    );

    let (status, answer) = running.ask(&send, &format!("{asked}&anyway=1"));
    assert_eq!(status, 200);
    assert!(
        answer.contains("\"sent\":true"),
        "said again with the button the refusal puts up, the fee was still refused: {answer}"
    );
    assert!(
        answer.contains("\"fee\":\"5.00000000 CAIRN\""),
        "and what was paid is what was typed: {answer}"
    );

    running.stop();
}

/// A quote whose amount and fee together pass the ceiling on any sum is
/// refused, in the words sending the same pair is refused with.
///
/// The quote added the two and, where the sum failed, put the ceiling itself
/// in its place, so the page read "Sending 999999999 and paying 5 to carry
/// it, 1000000000 in all": a total that is not the sum of the two figures
/// beside it, for a payment `Wallet::send` turns away as too large. Nothing
/// asked for a quote past the ceiling, so a quote that answered a failed sum
/// with a real looking one passed.
#[test]
fn a_quote_past_the_ceiling_is_refused_as_sending_it_is_and_not_totalled() {
    let running = Running::start("ceiling", 10, 1);
    let host = running.host();
    let secret = running.secret().to_owned();
    let recipient = SecretKey::generate().unwrap().public_key();

    // One whole CAIRN under the ceiling, and a fee that takes the two past it.
    let most = Amount::MAX_MONEY.as_pebbles() / cairn_primitives::amount::PEBBLES_PER_CAIRN;
    let asked = format!("k={secret}&to={recipient}&amount={}&fee=5", most - 1);
    let refused = cairn_wallet::WalletError::TooLarge.to_string();

    let send = format!("POST /api/send HTTP/1.1\r\nhost: {host}\r\norigin: http://{host}");
    let (status, answer) = running.ask(&send, &asked);
    assert_eq!(status, 200);
    assert!(
        answer.contains("\"sent\":false") && answer.contains(&refused),
        "sending an amount and a fee past the ceiling is refused as too large: {answer}"
    );

    let quote = format!("POST /api/quote HTTP/1.1\r\nhost: {host}\r\norigin: http://{host}");
    let (status, answer) = running.ask(&quote, &asked);
    assert_eq!(status, 200);
    assert!(
        !answer.contains("\"quoted\":true"),
        "the quote gave a total for a payment sending refuses, and the total it \
         gave is the ceiling rather than the sum of the two figures beside it: {answer}"
    );
    assert!(
        answer.contains(&refused),
        "the quote refuses in the words sending uses, so the two faces of one \
         question give one answer: {answer}"
    );

    running.stop();
}

/// A quote for more than the wallet can spend is refused, in the words sending
/// it is refused with, and does not say the network asks nothing.
///
/// The fee a quote names is worked out from the transfer the wallet would
/// build, and for money it does not have there is no such transfer. That
/// answered nought, and the page read it as the network's price: "The network
/// asks 0.00000000 CAIRN", above a payment that sending then refused for want
/// of money. Nothing quoted more than the wallet held, so a quote that turned
/// "no transfer to price" into a price of nothing passed.
#[test]
fn a_quote_for_more_than_the_wallet_holds_is_refused_as_sending_it_is() {
    let running = Running::start("short", 11, 1);
    let host = running.host();
    let secret = running.secret().to_owned();
    let recipient = SecretKey::generate().unwrap().public_key();
    let held = running.wallet.holdings().spendable;
    assert!(
        held > Amount::ZERO,
        "the wallet has to hold something to be short of"
    );
    let asked = format!(
        "k={secret}&to={recipient}&amount={}",
        held.as_pebbles() / cairn_primitives::amount::PEBBLES_PER_CAIRN + 1
    );

    let send = format!("POST /api/send HTTP/1.1\r\nhost: {host}\r\norigin: http://{host}");
    let (status, refused) = running.ask(&send, &asked);
    assert_eq!(status, 200);
    assert!(
        refused.contains("\"sent\":false") && refused.contains("more than the"),
        "sending more than the wallet holds is refused for want of money: {refused}"
    );

    let quote = format!("POST /api/quote HTTP/1.1\r\nhost: {host}\r\norigin: http://{host}");
    let (status, answer) = running.ask(&quote, &asked);
    assert_eq!(status, 200);
    assert!(
        !answer.contains("\"floor\":\"0.00000000 CAIRN\""),
        "the quote said the network asks nothing to carry a payment the wallet cannot \
         make: {answer}"
    );
    assert_eq!(
        answer, refused,
        "the quote and the send are one question and gave two answers"
    );

    running.stop();
}

/// A wallet whose whole balance is a reward too young to move is not an empty
/// wallet, and the page must not call it one.
///
/// `held` counts the notes a spend can reach for, and that is nought here, for
/// a wallet holding a hundred and fifty CAIRN. The page read `held` to decide
/// whether there was anything at all and printed "Nothing here yet. If this
/// key should hold something, check the height above" in the line directly
/// above its own sentence naming the amount. The same nought stands for two
/// other states with money in them: every note promised to a payment waiting
/// for a block, and every note fallen where this node cannot place it.
#[test]
fn a_page_showing_a_young_reward_does_not_say_the_wallet_is_empty() {
    let running = Running::start_with(
        "ripening",
        8,
        3,
        ConsensusParams::testnet().with_coinbase_maturity(4),
    );
    let host = running.opened.address.to_string();
    let secret = running.opened.secret.clone();
    let (status, answer) = running.get(&format!("/api/state?k={secret}"), &host, "");
    assert_eq!(status, 200);

    assert!(
        answer.contains("\"held\":0"),
        "no note here can be spent yet: {answer}"
    );
    assert!(
        answer.contains("\"ripening\":\"150.00000000 CAIRN\""),
        "and the money is counted: {answer}"
    );
    assert!(
        answer.contains("\"anything\":true"),
        "so the page is told there is something here, which is what its \
         \"Nothing here yet\" line is decided by: {answer}"
    );

    let holdings = running.wallet.holdings();
    assert_eq!(
        holdings.total(),
        Amount::from_cairn("150").unwrap(),
        "everything this key owns includes what cannot move yet"
    );
    assert!(
        !holdings.empty_handed(),
        "a wallet with a hundred and fifty CAIRN in it is not empty-handed"
    );

    running.stop();
}

/// Every list the account cuts short says how many there were.
///
/// The rule is written beside the other face, at `main.rs`: a list that stops
/// short and does not say where it stopped is a list that has told somebody
/// something untrue about their own money. Four places ask how much of a list
/// to show. Three answered it and said so; the fourth showed a hundred of up
/// to `MAX_UNDONE` = 256 undone payments and said nothing, and the page renders
/// what it is given as a finished sentence ending "Whoever you were paying has
/// not been paid". A payment missing from that list reads as a payment that
/// went through.
///
/// Neither count had a test. `movements_held` was written correctly and was
/// held by nothing, which is why its twin could be missing without anybody
/// noticing: there was no test to extend.
///
/// This pins the fields and their values. It does not reach the truncating
/// branch, which would need a reorganisation undoing more than a hundred
/// payments; what it catches is the defect that was actually there, which is a
/// count that is not written at all.
#[test]
fn every_list_the_account_cuts_short_says_how_many_there_were() {
    let running = Running::start("counts", 6, 3);
    let host = running.host();
    let secret = running.secret().to_owned();

    let (status, body) = running.get(&format!("/api/state?k={secret}"), &host, "");
    assert_eq!(status, 200);

    // Three blocks of rewards, so three movements and nothing undone.
    assert!(
        body.contains("\"movements_held\":3"),
        "the account does not say how many movements it is holding: {body}"
    );
    assert!(
        body.contains("\"undone_held\":0"),
        "the account does not say how many undone payments it is holding, so a \
         page that shows a hundred of them cannot say it showed a hundred: {body}"
    );

    running.stop();
}

/// How many notes have fallen is said of every note, and not of the ones the
/// page happens to list.
///
/// The page lists the first two hundred of a wallet's notes and says above
/// them "N notes, F of them fallen to the cold set". N came from the account
/// and F was counted by the page over the list it had been handed, so past two
/// hundred F counted only the fallen notes among the ones listed, and the
/// listing puts the hot notes first: a wallet most of whose money needs a
/// proof to move was told that little of it did. The test of the lists that
/// are cut short pinned the counts the account sends, and this was not one of
/// them, so nothing asked it.
#[test]
fn the_count_of_fallen_notes_is_of_every_note_and_not_of_those_listed() {
    let params = ConsensusParams::testnet()
        .with_coinbase_maturity(0)
        .with_hot_capacity(16);
    let running = Running::start_with("fallen", 7, 230, params);
    let host = running.host();
    let secret = running.secret().to_owned();

    let (status, body) = running.get(&format!("/api/state?k={secret}"), &host, "");
    assert_eq!(status, 200);

    let holdings = running.wallet.holdings();
    let fallen = holdings.notes.iter().filter(|held| held.is_cold()).count();
    let listed = body.matches("\"source\":").count();
    let fallen_listed = body.matches("\"cold\":true").count();
    assert!(
        holdings.notes.len() > listed,
        "the wallet holds {} notes and the page listed {listed}, so this does not reach the cut",
        holdings.notes.len()
    );
    assert!(
        fallen > fallen_listed,
        "{fallen} notes have fallen and {fallen_listed} of them are listed, so a count over \
         the list and a count over the wallet agree here and this proves nothing"
    );

    assert!(
        body.contains(&format!("\"fallen\":{fallen}")),
        "the account does not say how many of its notes have fallen, so the page can only \
         count the {fallen_listed} it lists of the {fallen} there are"
    );

    let (status, js) = running.get("/wallet.js", &host, "");
    assert_eq!(status, 200);
    assert!(
        js.contains("state.fallen"),
        "the page does not read the account's count of fallen notes"
    );
    assert!(
        !js.contains("state.notes.filter"),
        "the page still counts fallen notes over the list it was handed, which stops at two \
         hundred"
    );

    running.stop();
}

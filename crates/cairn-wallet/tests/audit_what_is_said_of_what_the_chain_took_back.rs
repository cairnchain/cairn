//! What a wallet says under the list of movements the chain took back.
//!
//! Both faces closed that list with one sentence, "The money is back in the
//! balance above. Whoever you were paying has not been paid", whatever the
//! movements on it were. True of a payment out, which goes back to waiting
//! for a block. The opposite of true for a reward or a payment in, whose
//! money left the balance with the block that paid it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_wallet::history::Direction;
use cairn_wallet::serve;
use cairn_wallet::Wallet;

const NOW: u64 = 2_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn mine(&mut self, to: &PublicKey) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(params.initial_reward, *to)]);
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, 1 << 22).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }
}

fn get(address: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
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

/// A reward the chain took back is not said to be back in the balance, on the
/// page as in the library both faces read the sentence from.
///
/// The one test of the undone list undid a payment out, which is the one case
/// the fixed sentence is true of, so a page telling a miner that an orphaned
/// reward was back in the balance passed.
#[test]
fn a_reward_the_chain_took_back_is_not_said_to_be_back_in_the_balance() {
    let directory = std::env::temp_dir().join(format!(
        "cairn-took-back-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let key_file = directory.join("key");
    let secret = SecretKey::from_bytes(&[31; 32]);
    let mine = secret.public_key();
    let stranger = SecretKey::from_bytes(&[7; 32]).public_key();
    cairn_wallet::keyfile::write(&key_file, &secret).unwrap();
    let (wallet, _) = Wallet::open(&key_file, params(), &directory.join("data")).unwrap();

    // A first block paying this key, one more on a branch that will lose,
    // and a heavier branch paying a stranger.
    let mut common = Forge {
        state: LedgerState::new(),
        clock: 1_000,
    };
    wallet.node().submit_block(common.mine(&mine)).unwrap();
    let mut losing = Forge {
        state: common.state.clone(),
        clock: common.clock,
    };
    wallet.node().submit_block(losing.mine(&mine)).unwrap();
    assert_eq!(wallet.history().len(), 2);
    for _ in 0..3 {
        wallet.node().submit_block(common.mine(&stranger)).unwrap();
    }
    assert_eq!(wallet.progress().height, Some(3));
    wallet.follow_to_the_tip();
    let undone = wallet.undone();
    assert_eq!(undone.len(), 1);
    assert_eq!(undone[0].direction, Direction::Mined);

    let said = cairn_wallet::undone_note(&undone).expect("something is said under the list");
    assert!(
        !said.contains("back in the balance"),
        "a reward the chain took away is said to be back in the balance: {said}"
    );
    assert!(
        said.contains("not in the balance any more"),
        "and it is not said to have gone: {said}"
    );

    // The page, which is where most people read it.
    let wallet = Arc::new(wallet);
    let (listener, opened) = serve::open(0).unwrap();
    let opened = Arc::new(opened);
    let alive = Arc::new(AtomicBool::new(true));
    let serving = Arc::clone(&wallet);
    let told = Arc::clone(&opened);
    let watching = Arc::clone(&alive);
    let thread = std::thread::spawn(move || serve::run(&serving, &listener, &told, &watching));

    let script = get(opened.address, "/wallet.js");
    let state = get(
        opened.address,
        &format!("/api/state?k={}", opened.secret.as_str()),
    );

    alive.store(false, Ordering::SeqCst);
    let _ = TcpStream::connect(opened.address);
    let _ = thread.join();
    wallet.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        script.contains("api/state"),
        "the script was not served, so this reads nothing"
    );
    assert!(
        !script.contains("Whoever you were paying has not been paid"),
        "the page closes the list of what the chain took back with its own fixed sentence \
         rather than with what the wallet says of the movements on it"
    );
    assert!(
        state.contains(&format!("\"undoneNote\":\"{said}\"")),
        "the page is not handed what the wallet says under the list"
    );
}

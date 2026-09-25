//! What the command line says about a key nothing has happened to.
//!
//! The whole account of what happened, and of what the wallet did not read,
//! sat inside a test for the list of movements being non-empty. So a wallet
//! whose list was empty said none of it: not that it had read only the top of
//! the chain, not that there was a hole in the middle of what it read, not
//! that it was still reading, not even that there was nothing.
//!
//! What a person saw was four lines of address, notes, height and balance, and
//! then the end of the output. The conclusion anybody draws from that is that
//! nothing has ever happened to this key. A fresh account against a node
//! restored from a written ledger is the ordinary way to arrive there, and in
//! that case the wallet knows it read the last eight blocks of ninety and is
//! silent about the other eighty two.
//!
//! The web face prints all of it from the same `Covered`, and did before this
//! did. Nothing tested the command line at all.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("wallet-quiet-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn wallet(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args(arguments)
        .output()
        .expect("the wallet runs")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A key nothing has happened to is told so, rather than told nothing.
#[test]
fn a_wallet_that_read_no_movements_still_gives_an_account_of_itself() {
    let home = scratch("empty");
    let key = home.join("key");
    let made = wallet(&["new", key.to_str().unwrap()]);
    assert!(made.status.success(), "{}", said(&made));

    let shown = wallet(&[
        "balance",
        key.to_str().unwrap(),
        "--data",
        home.join("data").to_str().unwrap(),
        "--network",
        "devnet",
        // Nowhere, so this asks the command line and not the network.
        "--seed",
        "127.0.0.1:9",
        "--wait",
        "0",
    ]);
    let told = said(&shown);

    assert!(shown.status.success(), "{told}");
    assert!(
        told.contains("balance"),
        "this test is about what comes after the balance, and there is no balance: {told}"
    );
    assert!(
        told.contains("What happened"),
        "the wallet showed a balance and then stopped, which reads as `nothing has ever \
         happened to this key` whatever the wallet actually knows: {told}"
    );
    assert!(
        told.contains("Nothing yet"),
        "it opened an account of what happened and then said neither what did nor that \
         nothing did: {told}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

/// A payment the wallet cannot make is refused before a fee is named for it,
/// on the command line as on the page.
///
/// With no fee given, the command line fills in what the network asks, worked
/// out from the transfer the wallet would build. For money it does not have
/// there is no such transfer, and that answered nought: the command line
/// printed "fee 0.00000000 CAIRN to carry it", a fee the network never asks,
/// and only then the refusal for want of money. The page was corrected to
/// refuse such a quote in the words sending uses; this is the same question
/// on the other face, and nothing asked it here.
#[test]
fn a_payment_the_wallet_cannot_make_is_not_given_a_fee_of_nothing() {
    let home = scratch("short");
    let key = home.join("key");
    let made = wallet(&["new", key.to_str().unwrap()]);
    assert!(made.status.success(), "{}", said(&made));
    let payee = home.join("payee");
    let made = wallet(&["new", payee.to_str().unwrap()]);
    assert!(made.status.success(), "{}", said(&made));
    let shown = wallet(&["address", payee.to_str().unwrap()]);
    let to = said(&shown)
        .split_whitespace()
        .find(|word| word.len() == 64)
        .expect("the address command prints an address")
        .to_owned();

    let sent = wallet(&[
        "send",
        key.to_str().unwrap(),
        "--to",
        &to,
        "--amount",
        "1",
        "--data",
        home.join("data").to_str().unwrap(),
        "--network",
        "devnet",
        // Nowhere, so this asks the command line and not the network.
        "--seed",
        "127.0.0.1:9",
        "--wait",
        "0",
    ]);
    let told = said(&sent);

    assert!(
        !sent.status.success(),
        "a wallet holding nothing sent a payment: {told}"
    );
    assert!(
        told.contains("more than the"),
        "the refusal is for want of money: {told}"
    );
    assert!(
        !told.contains("fee       0.00000000 CAIRN"),
        "the command line named a fee of nothing for a payment the wallet cannot \
         make, which the network never asks: {told}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

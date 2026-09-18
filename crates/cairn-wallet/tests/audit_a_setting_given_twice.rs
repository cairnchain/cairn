//! A setting given twice, and which of the two spends the money.
//!
//! `Flags::value` returned the first of the values collected under a name and
//! dropped the rest without a word. Every money-bearing option on this command
//! line reads through it, so `--fee 5 --fee 0.00005` paid five CAIRN to carry
//! a payment its sender had priced at five thousandths of one, and said
//! nothing about the second figure it had also been given.
//!
//! Neither guard in the way of a ruinous fee is one this reaches. Both compare
//! the fee against the amount, and the amount is not what changed: five CAIRN
//! against a hundred is inside every proportion the wallet allows, so
//! `--fee-anyway` is never asked for and the payment goes.
//!
//! `cairnd` has refused a setting given twice since the day it was written,
//! under a comment saying that a setting silently ignored is how an operator
//! ends up running rules they did not choose. The wallet, where what is
//! dropped is somebody's money rather than a rule, did not.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("wallet-twice-{}-{name}", std::process::id()));
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

/// The same, with somewhere of its own to keep a chain.
///
/// Without it the wallet falls back to `cairn-wallet-data` beside whatever
/// directory the test happened to run in, and every test that reaches as far
/// as opening one waits on the same lock.
fn wallet_under(home: &str, arguments: &[&str]) -> Output {
    let data = scratch(home).join("data");
    let mut all: Vec<&str> = arguments.to_vec();
    let held = data.to_str().unwrap().to_owned();
    all.push("--data");
    all.push(&held);
    // Nowhere, on a network of its own. Every outcome in this file is decided
    // before a peer could matter, and a test that would reach the real network
    // if the thing it checks regressed is a test that reaches the real network
    // on the day it fails.
    if !arguments.contains(&"--seed") {
        all.push("--seed");
        all.push("127.0.0.1:9");
    }
    if !arguments.contains(&"--network") {
        all.push("--network");
        all.push("devnet");
    }
    if !arguments.contains(&"--wait") {
        all.push("--wait");
        all.push("0");
    }
    wallet(&all)
}

/// What it said, whichever channel it said it on.
fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A key file, so the refusal under test is the only reason to stop.
fn a_key(name: &str) -> PathBuf {
    let path = scratch(name).join("key");
    let made = wallet(&["new", path.to_str().unwrap()]);
    assert!(made.status.success(), "{}", said(&made));
    path
}

/// Two addresses that are both real, so a refusal can only be about being
/// handed two of them. Written out of a key rather than typed, because a
/// string of the right length is not a point on the curve and the wallet
/// refuses one of those for a reason of its own.
fn two_addresses(who: &str) -> (String, String) {
    (
        address_of(&format!("{who}-payee-one")),
        address_of(&format!("{who}-payee-two")),
    )
}

fn address_of(name: &str) -> String {
    let shown = wallet(&["address", a_key(name).to_str().unwrap()]);
    assert!(shown.status.success(), "{}", said(&shown));
    said(&shown)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
        .expect("the wallet prints the address it was asked for")
}

#[test]
fn a_fee_given_twice_is_refused_rather_than_charged() {
    let key = a_key("fee");
    let (somebody, _) = two_addresses("fee");
    let output = wallet_under(
        "fee-home",
        &[
            "send",
            key.to_str().unwrap(),
            "--to",
            &somebody,
            "--amount",
            "100",
            "--fee",
            "5",
            "--fee",
            "0.00005",
        ],
    );
    let told = said(&output);

    assert!(!output.status.success(), "it went through: {told}");
    assert!(told.contains("given twice"), "{told}");
    assert!(
        told.contains('5') && told.contains("0.00005"),
        "it did not say which two figures it was handed: {told}"
    );
    assert!(
        !told.contains("paying"),
        "it priced the payment before refusing it: {told}"
    );
}

#[test]
fn an_address_given_twice_is_refused_rather_than_paid() {
    let key = a_key("to");
    let (somebody, somebody_else) = two_addresses("to");
    let output = wallet_under(
        "to-home",
        &[
            "send",
            key.to_str().unwrap(),
            "--to",
            &somebody,
            "--to",
            &somebody_else,
            "--amount",
            "1",
        ],
    );
    let told = said(&output);

    assert!(!output.status.success(), "it went through: {told}");
    assert!(told.contains("given twice"), "{told}");
    assert!(
        told.contains(&somebody) && told.contains(&somebody_else),
        "it did not say which two it was handed: {told}"
    );
}

#[test]
fn an_amount_given_twice_is_refused_rather_than_sent() {
    let key = a_key("amount");
    let (somebody, _) = two_addresses("amount");
    let output = wallet_under(
        "amount-home",
        &[
            "send",
            key.to_str().unwrap(),
            "--to",
            &somebody,
            "--amount",
            "1",
            "--amount",
            "1000",
        ],
    );
    let told = said(&output);

    assert!(!output.status.success(), "it went through: {told}");
    assert!(told.contains("given twice"), "{told}");
}

/// Nothing is dropped, so there is nothing to say.
#[test]
fn the_same_value_twice_is_not_a_collision() {
    let key = a_key("same");
    let (somebody, _) = two_addresses("same");
    let output = wallet_under(
        "same-home",
        &[
            "send",
            key.to_str().unwrap(),
            "--to",
            &somebody,
            "--to",
            &somebody,
            "--amount",
            "1",
            "--amount",
            "1",
            "--network",
            "devnet",
            "--network",
            "devnet",
            // Somewhere that refuses at once, so this test waits on nothing: what
            // it is about is what was said before any of that was reached.
            "--seed",
            "127.0.0.1:9",
            "--wait",
            "0",
        ],
    );
    let told = said(&output);

    assert!(
        !told.contains("given twice"),
        "it refused a command line that drops nothing: {told}"
    );
}

/// `--seed` is a list rather than a setting, and every one of them is used.
#[test]
fn a_second_seed_is_another_peer_and_not_a_second_answer() {
    let key = a_key("seed");
    let output = wallet_under(
        "seed-home",
        &[
            "balance",
            key.to_str().unwrap(),
            "--network",
            "devnet",
            "--seed",
            "127.0.0.1:9",
            "--seed",
            "127.0.0.1:10",
            "--wait",
            "0",
        ],
    );
    let told = said(&output);

    assert!(
        !told.contains("given twice"),
        "it read a list of peers as a setting handed to it twice: {told}"
    );
}

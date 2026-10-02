//! The address `new` prints under the key it just made.
//!
//! Addresses became the hash of a key in 0.11, written with a network's
//! prefix, and `address` was taught to say so. `new` went on printing the key
//! itself, sixty four hexadecimal characters, on a line that still called it
//! the address: the first thing a person reads about a new wallet, and one a
//! payer's wallet refuses.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("wallet-new-address-{}-{name}", std::process::id()));
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

fn address_line(output: &Output) -> String {
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| {
            line.strip_prefix("address")
                .map(|rest| rest.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("`new` names an address: {}", said(output)))
}

#[test]
fn new_prints_the_address_that_address_prints() {
    let key = scratch("default").join("key");
    let made = wallet(&["new", key.to_str().unwrap()]);
    assert!(made.status.success(), "{}", said(&made));
    let shown = wallet(&["address", key.to_str().unwrap()]);
    assert!(shown.status.success(), "{}", said(&shown));

    let printed = address_line(&made);
    assert!(
        printed.starts_with("tcairn1"),
        "the address of a new key is written for the test network, not as its key: {printed}"
    );
    assert_eq!(printed, said(&shown).trim(), "`new` and `address` agree");
}

#[test]
fn new_writes_the_address_for_the_network_it_is_given() {
    let key = scratch("devnet").join("key");
    let made = wallet(&["new", key.to_str().unwrap(), "--network", "devnet"]);
    assert!(made.status.success(), "{}", said(&made));
    let shown = wallet(&["address", key.to_str().unwrap(), "--network", "devnet"]);
    assert!(shown.status.success(), "{}", said(&shown));

    let printed = address_line(&made);
    assert!(printed.starts_with("dcairn1"), "{printed}");
    assert_eq!(printed, said(&shown).trim());
}

#[test]
fn a_network_new_does_not_know_leaves_no_key_behind() {
    let key = scratch("nowhere").join("key");
    let made = wallet(&["new", key.to_str().unwrap(), "--network", "nowhere"]);
    assert!(!made.status.success(), "{}", said(&made));
    assert!(
        !key.exists(),
        "a key whose address could not be written is not made"
    );
}

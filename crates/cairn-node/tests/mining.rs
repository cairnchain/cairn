//! What `cairnd --mine` does before it has anybody to mine for.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

/// A node that was given somewhere to start does not mine before it has a
/// peer, and says it is waiting.
///
/// Run as the audit ran it: devnet, an empty directory, a seed that refuses
/// connections. Nothing asked this, so the node mined a chain of its own from
/// the first block and printed `mined` for every one of them, ninety eight in
/// twelve seconds with `peers 0` on every status line; past the depth a node
/// undoes, that chain can never rejoin the network, and the rewards it printed
/// were on a chain nobody else has.
#[test]
fn a_miner_given_somewhere_to_start_does_not_mine_before_it_has_a_peer() {
    let directory = std::env::temp_dir().join(format!("cairnd-mine-alone-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let key = cairn_crypto::SecretKey::generate().unwrap().public_key();
    let mut node = Command::new(env!("CARGO_BIN_EXE_cairnd"))
        .args([
            "--network",
            "devnet",
            "--data",
            &directory.to_string_lossy(),
            "--listen",
            "127.0.0.1:0",
            // A closed local port: somewhere to start that nobody answers at.
            "--seed",
            "127.0.0.1:9",
            "--mine",
            &cairn_primitives::hex::encode(key.as_bytes()),
            "--status",
            "1",
            "--run-for",
            "6",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("cairnd starts");

    let mut waited = false;
    let mut mined = Vec::new();
    for line in BufReader::new(node.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        // What the miner prints comes after the stamp.
        let said = line.split_once("] ").map_or("", |(_, said)| said);
        if said.starts_with("mining waits until this node has a peer") {
            waited = true;
        }
        if said.starts_with("mined") {
            mined.push(line);
        }
    }
    let status = node.wait().unwrap();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(status.success(), "the run ended on {status}");
    assert!(
        mined.is_empty(),
        "a node with no peer mined blocks nobody else will ever take: {mined:?}"
    );
    assert!(
        waited,
        "a node that will not mine without a peer did not say that is what it is waiting for"
    );
}

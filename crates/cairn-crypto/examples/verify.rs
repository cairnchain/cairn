//! What verifying a signature costs, which is what a node spends most of a
//! block on, and what merely reading a key costs, which is what a node spends
//! on a message before anything has judged it.
//!
//! Run with `cargo run --release -p cairn-crypto --example verify`.

#![allow(
    clippy::unwrap_used,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

use std::time::Instant;

use cairn_crypto::{PublicKey, SecretKey};

const ROUNDS: usize = 20_000;

/// Keys drawn from distinct seeds, so no cache or branch predictor answers the
/// same question twice.
fn a_key_each(count: usize) -> Vec<[u8; 32]> {
    (0..count)
        .map(|seed| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(seed as u64).to_le_bytes());
            SecretKey::from_bytes(&bytes).public_key().to_bytes()
        })
        .collect()
}

fn main() {
    let secret = SecretKey::from_bytes(&[3; 32]);
    let key = secret.public_key();
    let message = [7u8; 64];
    let signature = secret.sign(&message);

    let started = Instant::now();
    let mut good = 0usize;
    for _ in 0..ROUNDS {
        if key.verify(&message, &signature).is_ok() {
            good += 1;
        }
    }
    let taken = started.elapsed();
    assert_eq!(good, ROUNDS);
    let verification = taken.as_secs_f64() * 1e6 / ROUNDS as f64;

    println!("{ROUNDS} verifications in {taken:?}, {verification:.2} us each");

    // Reading a key is not verifying with it, and the two get confused because
    // the expensive half of a verification is the same decompression. Every
    // note on the wire carries a key and every one of them is decompressed
    // while the frame is being decoded, which is before any rule has looked at
    // the frame. So this is what a peer can make a node spend per forty bytes
    // it sends, and it is worth knowing on its own.
    let keys = a_key_each(ROUNDS);
    let started = Instant::now();
    let mut read = 0usize;
    for bytes in &keys {
        if PublicKey::from_bytes(bytes).is_ok() {
            read += 1;
        }
    }
    let taken = started.elapsed();
    assert_eq!(read, ROUNDS);
    let decoding = taken.as_secs_f64() * 1e6 / ROUNDS as f64;

    println!("{ROUNDS} key decodings in {taken:?}, {decoding:.2} us each");
    println!(
        "reading a key is {:.0}% of verifying with one",
        decoding / verification * 100.0
    );
    println!(
        "a public key is {} bytes in memory",
        core::mem::size_of::<cairn_crypto::PublicKey>()
    );
}

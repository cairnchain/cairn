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
    // the expensive half of a verification is the same decompression. While a
    // note carried its owner's key, every note on the wire was decompressed
    // while the frame was being decoded, before any rule had looked at the
    // frame, and this was what a peer could make a node spend per forty bytes
    // it sent. A note carries an address now, and a key is read only for the
    // input that spends a note, beside its verification: this is what that
    // input adds to it.
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

    // What an input costs a node: its key read with the refusals and its
    // signature verified under it. Asked as two steps the point is decoded
    // twice, since a key keeps its bytes and decodes them again to verify;
    // `verify_bytes` decodes it once for both.
    let bytes = key.to_bytes();
    let started = Instant::now();
    let mut apart = 0usize;
    for _ in 0..ROUNDS {
        if PublicKey::from_bytes(&bytes)
            .and_then(|read| read.verify(&message, &signature))
            .is_ok()
        {
            apart += 1;
        }
    }
    let two_steps = started.elapsed().as_secs_f64() * 1e6 / ROUNDS as f64;
    let started = Instant::now();
    let mut together = 0usize;
    for _ in 0..ROUNDS {
        if PublicKey::verify_bytes(&bytes, &message, &signature).is_ok() {
            together += 1;
        }
    }
    let one_pass = started.elapsed().as_secs_f64() * 1e6 / ROUNDS as f64;
    assert_eq!((apart, together), (ROUNDS, ROUNDS));
    println!(
        "an input, key read then verified: {two_steps:.2} us; in one decoding: {one_pass:.2} us"
    );
}

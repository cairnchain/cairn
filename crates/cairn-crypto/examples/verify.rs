//! What verifying a signature costs, which is what a node spends most of a
//! block on.
//!
//! Run with `cargo run --release -p cairn-crypto --example verify`.

#![allow(clippy::unwrap_used, clippy::cast_precision_loss)]

use std::time::Instant;

use cairn_crypto::SecretKey;

const ROUNDS: usize = 20_000;

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

    println!(
        "{ROUNDS} verifications in {taken:?}, {:.1} us each",
        taken.as_secs_f64() * 1e6 / ROUNDS as f64
    );
    println!(
        "a public key is {} bytes in memory",
        core::mem::size_of::<cairn_crypto::PublicKey>()
    );
}

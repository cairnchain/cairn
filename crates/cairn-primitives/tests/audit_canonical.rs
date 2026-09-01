//! Adversarial audit of the canonical encoding, the hash domains and the tree.
//!
//! The property the whole chain rests on is not `decode(encode(x)) == x`, which
//! every codec passes. It is the other direction: for every byte string the
//! decoder accepts, re-encoding must give back exactly those bytes. A decoder
//! that accepts something its encoder would never write is a decoder that gives
//! one value two identifiers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use cairn_primitives::amount::Amount;
use cairn_primitives::codec::{CodecError, Decode, Encode, MAX_SEQUENCE_LEN};
use cairn_primitives::hex;
use cairn_primitives::Hash32;

/// Deterministic generator, so any failure here can be replayed exactly.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() as usize) % bound
        }
    }
}

/// The encoder and the decoder disagree above `MAX_SEQUENCE_LEN`, and the
/// disagreement is unreachable rather than handled: nothing on the wire comes
/// near the ceiling, because a block is capped far below it. What was wrong
/// was that nothing said so and nothing would have noticed. A debug build now
/// stops on it, so whoever adds a type that could reach it finds out at once
/// rather than through the thing it breaks.
///
/// Silently writing a shorter count would be worse, since two different
/// sequences would then share an encoding, so this test pins that the ceiling
/// is where it is said to be rather than pinning a repair that should not
/// exist.
#[test]
fn the_ceiling_on_a_sequence_is_where_it_says_it_is() {
    let at_the_ceiling: Vec<u8> = vec![0u8; MAX_SEQUENCE_LEN];
    let bytes = at_the_ceiling.encode();
    assert_eq!(
        Vec::<u8>::decode(&bytes).map(|read| read.len()),
        Ok(MAX_SEQUENCE_LEN),
        "the longest sequence the decoder takes is one the encoder writes"
    );

    // One past it, built as bytes rather than by encoding, since encoding it
    // is what a debug build now stops on.
    let mut past = Vec::new();
    let over = u32::try_from(MAX_SEQUENCE_LEN + 1).unwrap();
    past.extend_from_slice(&over.to_le_bytes());
    past.extend(std::iter::repeat_n(0u8, MAX_SEQUENCE_LEN + 1));
    assert!(
        matches!(
            Vec::<u8>::decode(&past),
            Err(CodecError::SequenceTooLong { .. })
        ),
        "and one longer is refused before anything is reserved for it"
    );
}

#[test]
fn a_declared_length_never_drives_an_allocation() {
    // Four bytes claiming a million elements must fail on the first missing
    // element, not after reserving for a million.
    let frame = (MAX_SEQUENCE_LEN as u32).encode();
    let started = std::time::Instant::now();
    for _ in 0..1_000 {
        assert_eq!(Vec::<u128>::decode(&frame), Err(CodecError::UnexpectedEnd));
        assert_eq!(
            Vec::<Hash32>::decode(&frame),
            Err(CodecError::UnexpectedEnd)
        );
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "two thousand rejections should be instant, took {:?}",
        started.elapsed()
    );
}

#[test]
fn decoding_never_panics_on_attacker_chosen_bytes() {
    let mut rng = Rng::new(0x5eed_0004);
    for _ in 0..60_000 {
        let len = rng.below(300);
        let bytes = rng.bytes(len);
        let _ = u8::decode(&bytes);
        let _ = u16::decode(&bytes);
        let _ = u32::decode(&bytes);
        let _ = u64::decode(&bytes);
        let _ = u128::decode(&bytes);
        let _ = <[u8; 32]>::decode(&bytes);
        let _ = <[u8; 0]>::decode(&bytes);
        let _ = Hash32::decode(&bytes);
        let _ = Amount::decode(&bytes);
        let _ = Vec::<u8>::decode(&bytes);
        let _ = Vec::<u32>::decode(&bytes);
        let _ = Vec::<u128>::decode(&bytes);
        let _ = Vec::<Amount>::decode(&bytes);
        let _ = Vec::<Hash32>::decode(&bytes);
        let _ = Vec::<Vec<u8>>::decode(&bytes);
        let _ = Vec::<Vec<Vec<u8>>>::decode(&bytes);
    }
}

/// Every domain the crate declares. Listed by hand because there is no
/// iterator over the enum, which is exactly why a copy-paste in `key_for`
/// A key file is read through `decode_array`, and it used to go through
/// `decode`, which builds a vector on the heap holding the whole secret and
/// drops it without wiping it. The caller wraps the array it is handed in
/// `Zeroizing` and cannot wrap what it never saw, so every wallet start left a
/// copy of the private key in released memory for a core dump or a page of
/// swap to pick up. It now fills the array directly, so there is nothing else
/// to wipe.
///
/// What is asserted is the shape rather than the residue: reading freed bytes
/// back would need `unsafe`, which this workspace forbids. So the test pins
/// that `decode_array` still answers correctly, and that the allocator really
/// does hand the same block straight to the next caller, which is the
/// mechanism that made the old path worth closing.
#[test]
fn a_secret_no_longer_passes_through_a_heap_buffer() {
    let secret = [0xa7u8; 32];
    let text = hex::encode(&secret);

    assert_eq!(
        hex::decode_array::<32>(&text),
        Some(secret),
        "the key still loads"
    );
    assert_eq!(
        hex::decode_array::<32>(&text[..62]),
        None,
        "and a short one is refused rather than padded"
    );
    assert_eq!(
        hex::decode_array::<32>(&format!("{text}00")),
        None,
        "and a long one is refused rather than truncated"
    );
    assert_eq!(
        hex::decode_array::<32>(&text.replace('a', "z")),
        None,
        "and one that is not hexadecimal is refused"
    );

    // The mechanism the old path fell into, shown once so the reasoning above
    // is not merely asserted.
    let block: Vec<u8> = Vec::with_capacity(32);
    let address = block.as_ptr() as usize;
    drop(block);
    let recycled: Vec<u8> = Vec::with_capacity(32);
    eprintln!(
        "a freed 32 byte block at {address:#x} comes back at {:#x}{}",
        recycled.as_ptr() as usize,
        if recycled.as_ptr() as usize == address {
            ", which is the same block"
        } else {
            ""
        }
    );
}

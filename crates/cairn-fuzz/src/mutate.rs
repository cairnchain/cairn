//! Bending a byte string that was once valid.
//!
//! Uniformly random bytes reach the decoders that accept almost any prefix and
//! nothing else: a tag byte alone throws away seventeen eighteenths of them,
//! and a length prefix throws away almost all of the rest. Everything past the
//! first branch is only reachable from something that was well formed a moment
//! ago, which is what these operators produce.
//!
//! The operators are the ones that have historically found decoder defects,
//! and each is here for a shape of bug rather than for variety:
//!
//! - flipping a bit or setting a byte reaches a tag, an enum discriminant or a
//!   flag that was never meant to hold that value,
//! - writing an interesting integer over a four or eight byte window reaches
//!   the counts and lengths, which is where a sender gets to name a number
//!   this node will act on,
//! - truncating reaches every decoder that assumed more was coming,
//! - inserting, deleting and duplicating a run shifts every field after it,
//!   which turns one valid encoding into a stream of plausible misalignments,
//! - swapping two runs is the one that finds a decoder accepting a set in an
//!   order it does not itself produce,
//! - splicing two different valid messages together reaches the branches that
//!   only open once a header has been believed.

use crate::Rng;

/// Bytes worth writing where a byte is read.
pub const INTERESTING_U8: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x7f, 0x80, 0x81, 0xfe, 0xff];

/// Counts worth writing where a length is read.
///
/// `MAX_SEQUENCE_LEN` and the value just past it are here by name: that
/// boundary is checked in `cairn-primitives::codec` and again, differently, in
/// every decoder that caps a sequence of its own.
pub const INTERESTING_U32: &[u32] = &[
    0,
    1,
    2,
    63,
    64,
    65,
    255,
    256,
    257,
    4_095,
    4_096,
    4_097,
    8_191,
    8_192,
    8_193,
    0x000f_ffff,
    0x0010_0000,
    0x0010_0001,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_fffe,
    0xffff_ffff,
];

/// Values worth writing where a height, a position or a timestamp is read.
pub const INTERESTING_U64: &[u64] = &[
    0,
    1,
    2,
    63,
    64,
    1_023,
    1_024,
    1_025,
    0x0000_0000_ffff_ffff,
    0x0000_0001_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    u64::MAX.wrapping_sub(1),
    u64::MAX,
];

/// Bends `seed` into something near it, drawing other corpus entries from
/// `corpus` when it wants material to splice in.
///
/// Applies between one and four operators, because one is usually caught at
/// the field it lands on and four is usually caught at the first of them; the
/// interesting cases are in between, where the first bend is accepted and the
/// second is judged against it.
#[must_use]
pub fn mutate(rng: &mut Rng, seed: &[u8], corpus: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    let rounds = rng.between(1, 4);
    for _ in 0..rounds {
        bytes = one_operator(rng, bytes, corpus);
    }
    bytes
}

fn one_operator(rng: &mut Rng, bytes: Vec<u8>, corpus: &[Vec<u8>]) -> Vec<u8> {
    match rng.below(10) {
        0 => flip_a_bit(rng, bytes),
        1 => set_a_byte(rng, bytes),
        2 => write_a_count(rng, bytes),
        3 => write_a_wide_value(rng, bytes),
        4 => truncate(rng, bytes),
        5 => insert_a_run(rng, bytes),
        6 => delete_a_run(rng, bytes),
        7 => duplicate_a_run(rng, bytes),
        8 => swap_two_runs(rng, bytes),
        _ => splice_in(rng, bytes, corpus),
    }
}

fn flip_a_bit(rng: &mut Rng, mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    let at = rng.below(bytes.len());
    let bit = u32::try_from(rng.below(8)).unwrap_or(0);
    if let Some(byte) = bytes.get_mut(at) {
        *byte ^= 1u8.wrapping_shl(bit);
    }
    bytes
}

fn set_a_byte(rng: &mut Rng, mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    let at = rng.below(bytes.len());
    let value = rng.edgy_byte();
    if let Some(byte) = bytes.get_mut(at) {
        *byte = value;
    }
    bytes
}

/// Writes a chosen `u32` over a four byte window, which is where every length
/// prefix in this format sits.
fn write_a_count(rng: &mut Rng, mut bytes: Vec<u8>) -> Vec<u8> {
    let Some(last) = bytes.len().checked_sub(4) else {
        return bytes;
    };
    let at = rng.between(0, last);
    let value = rng.edgy_u32().to_le_bytes();
    if let Some(window) = bytes.get_mut(at..at.saturating_add(4)) {
        window.copy_from_slice(&value);
    }
    bytes
}

fn write_a_wide_value(rng: &mut Rng, mut bytes: Vec<u8>) -> Vec<u8> {
    let Some(last) = bytes.len().checked_sub(8) else {
        return bytes;
    };
    let at = rng.between(0, last);
    let value = rng.edgy_u64().to_le_bytes();
    if let Some(window) = bytes.get_mut(at..at.saturating_add(8)) {
        window.copy_from_slice(&value);
    }
    bytes
}

fn truncate(rng: &mut Rng, mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    let keep = rng.below(bytes.len());
    bytes.truncate(keep);
    bytes
}

fn insert_a_run(rng: &mut Rng, mut bytes: Vec<u8>) -> Vec<u8> {
    let at = rng.between(0, bytes.len());
    let len = rng.between(1, 16);
    let run = rng.bytes(len);
    let mut out = Vec::with_capacity(bytes.len().saturating_add(run.len()));
    let (head, tail) = bytes.split_at(at.min(bytes.len()));
    out.extend_from_slice(head);
    out.extend_from_slice(&run);
    out.extend_from_slice(tail);
    bytes = out;
    bytes
}

fn delete_a_run(rng: &mut Rng, bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    let at = rng.below(bytes.len());
    let len = rng.between(1, 16).min(bytes.len().saturating_sub(at));
    let end = at.saturating_add(len);
    let mut out = Vec::with_capacity(bytes.len().saturating_sub(len));
    if let Some(head) = bytes.get(..at) {
        out.extend_from_slice(head);
    }
    if let Some(tail) = bytes.get(end..) {
        out.extend_from_slice(tail);
    }
    out
}

fn duplicate_a_run(rng: &mut Rng, bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    let at = rng.below(bytes.len());
    let len = rng.between(1, 64).min(bytes.len().saturating_sub(at));
    let end = at.saturating_add(len);
    let Some(run) = bytes.get(at..end) else {
        return bytes;
    };
    let run = run.to_vec();
    let mut out = Vec::with_capacity(bytes.len().saturating_add(run.len()));
    if let Some(head) = bytes.get(..end) {
        out.extend_from_slice(head);
    }
    out.extend_from_slice(&run);
    if let Some(tail) = bytes.get(end..) {
        out.extend_from_slice(tail);
    }
    out
}

/// Exchanges two runs of the same length.
///
/// The one operator that keeps the length of the frame and the multiset of its
/// bytes, so a decoder that only checks totals sees nothing wrong. It is what
/// finds a structure whose encoder writes its parts in one order and whose
/// decoder accepts them in any.
fn swap_two_runs(rng: &mut Rng, mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() < 2 {
        return bytes;
    }
    let len = rng
        .between(1, 33)
        .min(bytes.len().checked_div(2).unwrap_or(0));
    if len == 0 {
        return bytes;
    }
    // Placed so the two windows cannot overlap. Overlapping ones would copy a
    // run over part of itself and invent bytes the frame never held, which is
    // a different operator wearing this one's name.
    let first = rng.between(0, bytes.len().saturating_sub(len.saturating_mul(2)));
    let second = rng.between(first.saturating_add(len), bytes.len().saturating_sub(len));
    let (Some(left), Some(right)) = (
        bytes
            .get(first..first.saturating_add(len))
            .map(<[u8]>::to_vec),
        bytes
            .get(second..second.saturating_add(len))
            .map(<[u8]>::to_vec),
    ) else {
        return bytes;
    };
    if let Some(window) = bytes.get_mut(first..first.saturating_add(len)) {
        window.copy_from_slice(&right);
    }
    if let Some(window) = bytes.get_mut(second..second.saturating_add(len)) {
        window.copy_from_slice(&left);
    }
    bytes
}

fn splice_in(rng: &mut Rng, bytes: Vec<u8>, corpus: &[Vec<u8>]) -> Vec<u8> {
    let Some(other) = rng.pick(corpus) else {
        return bytes;
    };
    splice(rng, &bytes, other)
}

/// Takes the front of `head` and the back of `tail`, cut at a point in each.
///
/// A frame that opens as one message and finishes as another. This is what
/// reaches a decoder's later branches carrying material it was never handed
/// alongside those branches before.
#[must_use]
pub fn splice(rng: &mut Rng, head: &[u8], tail: &[u8]) -> Vec<u8> {
    let cut = rng.between(0, head.len());
    let from = rng.between(0, tail.len());
    let mut out = Vec::with_capacity(head.len().saturating_add(tail.len()));
    if let Some(front) = head.get(..cut) {
        out.extend_from_slice(front);
    }
    if let Some(back) = tail.get(from..) {
        out.extend_from_slice(back);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Vec<Vec<u8>> {
        vec![vec![1, 2, 3, 4, 5, 6, 7, 8], vec![9; 32]]
    }

    #[test]
    fn every_operator_is_reached_and_none_of_them_panics() {
        let corpus = corpus();
        let mut rng = Rng::new(42);
        let mut lengths = std::collections::BTreeSet::new();
        for _ in 0..20_000 {
            let seed = rng.pick(&corpus).cloned().unwrap_or_default();
            let bent = mutate(&mut rng, &seed, &corpus);
            lengths.insert(bent.len());
        }
        assert!(
            lengths.len() > 8,
            "the operators only ever produced {} lengths",
            lengths.len()
        );
    }

    #[test]
    fn an_empty_seed_survives_every_operator() {
        let corpus = corpus();
        let mut rng = Rng::new(5);
        for _ in 0..5_000 {
            let _ = mutate(&mut rng, &[], &corpus);
        }
    }

    #[test]
    fn a_one_byte_seed_survives_every_operator() {
        let corpus = corpus();
        let mut rng = Rng::new(6);
        for _ in 0..5_000 {
            let _ = mutate(&mut rng, &[7], &corpus);
        }
    }

    #[test]
    fn swapping_runs_keeps_the_bytes_and_moves_them() {
        let mut rng = Rng::new(9);
        let start: Vec<u8> = (0..64).collect();
        let mut moved = 0usize;
        for _ in 0..1_000 {
            let after = swap_two_runs(&mut rng, start.clone());
            assert_eq!(after.len(), start.len());
            let mut mine = after.clone();
            let mut theirs = start.clone();
            mine.sort_unstable();
            theirs.sort_unstable();
            assert_eq!(mine, theirs, "a swap is not allowed to invent a byte");
            if after != start {
                moved = moved.saturating_add(1);
            }
        }
        assert!(moved > 500, "only {moved} of 1000 swaps moved anything");
    }
}

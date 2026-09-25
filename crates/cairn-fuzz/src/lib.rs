//! Randomised testing for the surfaces that read bytes from strangers.
//!
//! Every audit in this repository found what somebody thought to look for.
//! This is the other half: a generator that does not know what a decoder is
//! afraid of, run for long enough that not knowing stops mattering.
//!
//! # Why this and not a crate off the registry
//!
//! `proptest` and `quickcheck` were both considered and would have been legal:
//! a dev-dependency does not reach a shipped binary, and the release workflow
//! builds three programs by name. `cargo-fuzz` was not, because it needs a
//! nightly toolchain and `rust-toolchain.toml` pins a stable one, which is a
//! promise that anybody can reproduce this build.
//!
//! What a property crate sells is shrinking and strategy composition. Neither
//! is worth much here. Every input in this repository is a byte string, and
//! shrinking a byte string is [`shrink::smallest`] below, forty lines with no
//! generic machinery in it. Strategies would have had to be written by hand
//! for `Block`, `Handover`, `SampledStart` and the rest anyway, since none of
//! them derive anything, and a hand-written strategy is the same code as a
//! hand-written generator with an extra trait around it.
//!
//! What is bought by not taking the dependency is worth more than that. The
//! cases this suite runs are the same on every machine and in every year,
//! because the generator is written down here rather than being whatever
//! version of somebody's `rand` the lockfile resolved to; a failure is a seed
//! and a case number, and reproducing it needs nothing installed. And the
//! answer to "did anything that ships gain a dependency" is settled by reading
//! one empty `[dependencies]` section rather than by reading a tree.
//!
//! # How a campaign is run
//!
//! [`Campaign`] reads three environment variables and is otherwise
//! deterministic:
//!
//! - `CAIRN_FUZZ_SEED` picks the run. Absent, it is [`DEFAULT_SEED`], so the
//!   suite runs the same cases every time and a regression cannot hide behind
//!   a lucky seed.
//! - `CAIRN_FUZZ_CASES` replaces the small count each test asks for.
//! - `CAIRN_FUZZ_SECONDS` turns the count into a time budget and runs until it
//!   is spent. This is the long campaign, and it is out of `cargo test` by
//!   default for the same reason `CAIRN_AUDIT_FULL_DIR` keeps the full-disk
//!   tests out of it: a suite that takes minutes is a suite people stop
//!   running. `.github/workflows/fuzz.yml` runs it nightly on a seed that
//!   moves, because for a while nothing ran it at all: the two regressions
//!   pinned in the targets were both found by somebody typing the variable by
//!   hand, once, and nothing arranged for that to happen again.
//!
//! # What the campaigns reach, and what they do not
//!
//! Every campaign here has two arms: bytes built from nothing, and a corpus
//! entry with a few bytes changed. They do not reach the same depth and the
//! difference is worth stating, because for a long time one guard counted
//! both and a green result said "some input reached the decoder" while being
//! read as "both kinds do".
//!
//! **Bytes from nothing essentially never decode.** Measured over the default
//! seed: zero of 5 076 for `Message`, zero of 6 626 for a framed read, zero
//! of 9 838 for each accumulator decoder, zero of 20 000 for the sequence
//! decoders, of which 19 416 died on `SequenceTooLong`. Not one ever reached
//! the second element of any sequence. That arm now draws from
//! [`Rng::plausible_bytes`], which holds half its bytes at zero so a length
//! prefix is one a decoder acts on, and it still will not produce a whole
//! valid frame for a decoder that has to consume its buffer exactly. What it
//! measures is that garbage is refused rather than panicked on, which is
//! worth measuring and is not what it was being read as.
//!
//! **The mutation arm is what reaches**, and how far depends on how close the
//! corpus already is. The deepest target in the suite is the one that bends
//! three bytes of a real twelve kilobyte handover: 87 to 98 per cent of those
//! decode, and they go on into `handover::accept` and `check_start`.
//!
//! **What had no target at all** was named here so it would be a gap and not
//! an omission, and all four are closed: `cairn-http`'s request reader, the
//! most exposed parser here, by `fuzz_request`; `cairn-store`'s record
//! framing, which is what a rebuild reads, by `fuzz_record_framing`; the
//! address book's file reader by `fuzz_address_book`; and
//! `cairn-primitives`'s hexadecimal parser, behind every identifier in a URL
//! and the wallet's key file, by `fuzz_hex`. The list is kept as the record
//! of how it closed rather than deleted, because it went on being read as a
//! list of gaps for some time after it stopped being one, and a map of what
//! is not covered is read to decide where to spend an afternoon: a stale one
//! sends that afternoon to four places that already had campaigns, and away
//! from wherever the gap moved to. Anything added here should be added as a
//! gap and struck through the same way.
//!
//! There is still no corpus on disk: every campaign rebuilds its seeds in
//! process, so a case found today is not a case tomorrow's run starts from.
//!
//! Each case gets its own generator, seeded from the run seed and the case
//! number, so case 91 941 of a two-minute campaign is reachable in a
//! millisecond by asking for that one case.

mod arms;
mod campaign;
pub mod mutate;
mod shrink;

pub use arms::{Arms, Built};
pub use campaign::Campaign;
pub use mutate::mutate;
use mutate::{INTERESTING_U32, INTERESTING_U64, INTERESTING_U8};
pub use shrink::smallest;

/// A small, fast, fully specified generator.
///
/// `SplitMix64`. Chosen over the xorshift written in `cairn-net`'s own fuzz test
/// because every seed is a usable one, including zero, which matters when the
/// seed is derived from a case number.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next sixty four bits.
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ z.wrapping_shr(30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ z.wrapping_shr(27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ z.wrapping_shr(31)
    }

    fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64() & 0xffff_ffff).unwrap_or(u32::MAX)
    }

    pub fn byte(&mut self) -> u8 {
        u8::try_from(self.next_u64() & 0xff).unwrap_or(0)
    }

    /// A byte drawn from the values that sit on a boundary, half the time.
    ///
    /// Uniform bytes almost never produce `0x00` or `0xff` in a run of four,
    /// and a length prefix is exactly where those matter.
    fn edgy_byte(&mut self) -> u8 {
        if self.chance(2) {
            self.byte()
        } else {
            self.pick(INTERESTING_U8).copied().unwrap_or(0)
        }
    }

    /// Whether a one-in-`odds` draw came up. `odds` of zero never does.
    pub fn chance(&mut self, odds: u64) -> bool {
        odds != 0 && self.next_u64().checked_rem(odds) == Some(0)
    }

    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// A number below `limit`, or zero when `limit` is zero.
    pub fn below(&mut self, limit: usize) -> usize {
        let Ok(span) = u64::try_from(limit) else {
            return 0;
        };
        let Some(drawn) = self.next_u64().checked_rem(span) else {
            return 0;
        };
        usize::try_from(drawn).unwrap_or(0)
    }

    /// A number in `low..=high`, or `low` when the range is empty.
    pub fn between(&mut self, low: usize, high: usize) -> usize {
        let Some(span) = high.checked_sub(low) else {
            return low;
        };
        low.saturating_add(self.below(span.saturating_add(1)))
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.edgy_byte()).collect()
    }

    /// Bytes a decoder will act on rather than refuse at the first field.
    ///
    /// [`Rng::bytes`] draws from the values that sit on a boundary, which is
    /// the right thing for a scalar and the wrong thing for a frame. A
    /// sequence is written as a four byte count, and a count drawn this way
    /// is above `MAX_SEQUENCE_LEN` about ninety nine times in a hundred, so
    /// the decoder refuses on the first four bytes it reads and nothing
    /// behind them is ever looked at.
    ///
    /// Measured across every campaign in this workspace, over the default
    /// seed: the raw arm accepted nothing at all. Zero of 5 076 for
    /// `Message`, zero of 6 626 for a framed read, zero of 9 838 for each of
    /// the three accumulator decoders, zero of 20 000 for the sequence
    /// decoders, of which 19 416 died on `SequenceTooLong`. Not one random
    /// input ever reached the second element of any sequence. Every
    /// anti-vacuity guard those campaigns carry was satisfied by the mutation
    /// arm alone, so a green raw arm answered "does the length check refuse
    /// garbage" and was read as "does this decoder handle a hostile
    /// structure".
    ///
    /// Half the bytes here are zero, so a count read anywhere in the run is
    /// one a decoder acts on, and what follows it is reached. The other half
    /// is [`Rng::edgy_byte`], so the boundaries it was drawing are still
    /// drawn.
    pub fn plausible_bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len)
            .map(|_| if self.chance(2) { 0 } else { self.edgy_byte() })
            .collect()
    }

    /// One element of `from`, or nothing when it is empty.
    pub fn pick<'a, T>(&mut self, from: &'a [T]) -> Option<&'a T> {
        from.get(self.below(from.len()))
    }

    /// A `u64` that is either uniform or one a decoder is likely to care
    /// about.
    pub fn edgy_u64(&mut self) -> u64 {
        if self.chance(2) {
            self.next_u64()
        } else {
            self.pick(INTERESTING_U64).copied().unwrap_or(0)
        }
    }

    /// The same for a `u32`, which is what every length prefix is.
    pub fn edgy_u32(&mut self) -> u32 {
        if self.chance(2) {
            self.next_u32()
        } else {
            self.pick(INTERESTING_U32).copied().unwrap_or(0)
        }
    }

    /// Fills a fixed array, for the hashes and keys that make up most of what
    /// a decoder reads.
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for slot in &mut out {
            *slot = self.byte();
        }
        out
    }
}

/// Mixes a run seed and a case number into the seed for that one case.
///
/// So that a campaign of a hundred thousand cases can be re-entered at case
/// ninety thousand without running the eighty nine thousand before it, which
/// is what makes a failure worth reporting as a number.
#[must_use]
fn seed_for(run: u64, case: usize) -> u64 {
    let case = u64::try_from(case).unwrap_or(u64::MAX);
    let mut mixer = Rng::new(run ^ case.wrapping_mul(0xD1B5_4A32_D192_ED03));
    mixer.next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_run() {
        let first: Vec<u64> = (0..16).map(|_| Rng::new(7).next_u64()).collect();
        let again: Vec<u64> = (0..16).map(|_| Rng::new(7).next_u64()).collect();
        assert_eq!(first, again);
    }

    #[test]
    fn a_zero_seed_is_a_usable_one() {
        let mut rng = Rng::new(0);
        let drawn: Vec<u64> = (0..8).map(|_| rng.next_u64()).collect();
        assert!(drawn.iter().any(|value| *value != 0));
    }

    #[test]
    fn below_stays_below_and_covers_the_range() {
        let mut rng = Rng::new(1);
        let mut seen = [false; 8];
        for _ in 0..1_000 {
            let drawn = rng.below(8);
            assert!(drawn < 8);
            if let Some(slot) = seen.get_mut(drawn) {
                *slot = true;
            }
        }
        assert!(seen.iter().all(|hit| *hit), "the generator misses values");
    }

    #[test]
    fn below_zero_is_zero_rather_than_a_division_by_it() {
        assert_eq!(Rng::new(3).below(0), 0);
    }

    /// The generator is `SplitMix64`, value for value.
    ///
    /// A campaign reports a failure as a seed and a case number, and that pair
    /// has to replay the same case for whoever reads the report, next month as
    /// much as today. The tests above held that one build agrees with itself.
    /// Nothing held the algorithm, so a mixing step with `|` where it has `^`
    /// passed, and would have made every reported seed name a different case.
    /// These are the published reference values for seeds 0 and 1 234 567.
    #[test]
    fn the_generator_is_splitmix64_value_for_value() {
        let mut zero = Rng::new(0);
        assert_eq!(
            [zero.next_u64(), zero.next_u64(), zero.next_u64()],
            [
                0xe220_a839_7b1d_cdaf,
                0x6e78_9e6a_a1b9_65f4,
                0x06c4_5d18_8009_454f
            ]
        );
        let mut other = Rng::new(1_234_567);
        assert_eq!(
            [other.next_u64(), other.next_u64(), other.next_u64()],
            [
                0x599e_d017_fb08_fc85,
                0x2c73_f084_5854_0fa5,
                0x883e_bce5_a3f2_7c77
            ]
        );
    }

    /// Every way of drawing reaches across what it says it draws from.
    ///
    /// Nothing held these, so a `u32` that was always nought passed, as did a
    /// coin that always landed one way, "interesting" values that were only
    /// ever nought or one, arrays of one repeated byte, and case seeds that
    /// ignored the run they belong to. Each would have had every campaign
    /// testing a handful of inputs over and over and reporting it as
    /// thousands.
    #[test]
    fn every_way_of_drawing_reaches_across_its_range() {
        use std::collections::HashSet;
        let mut rng = Rng::new(42);

        let words: HashSet<u32> = (0..1_000).map(|_| rng.next_u32()).collect();
        assert!(words.len() > 990, "{} distinct u32 in 1000", words.len());

        let heads = (0..1_000).filter(|_| rng.bool()).count();
        assert!((400..600).contains(&heads), "{heads} heads in 1000 throws");

        let wide: HashSet<u64> = (0..1_000).map(|_| rng.edgy_u64()).collect();
        let narrow: HashSet<u32> = (0..1_000).map(|_| rng.edgy_u32()).collect();
        for (drawn, interesting, what) in [
            (
                wide.len(),
                INTERESTING_U64.iter().filter(|v| wide.contains(v)).count(),
                "u64",
            ),
            (
                narrow.len(),
                INTERESTING_U32
                    .iter()
                    .filter(|v| narrow.contains(v))
                    .count(),
                "u32",
            ),
        ] {
            assert!(drawn > 400, "only {drawn} distinct edgy {what} in 1000");
            assert!(
                interesting > 10,
                "only {interesting} of the edgy {what} values drawn"
            );
        }

        let tens = (0..10_000).filter(|_| rng.chance(10)).count();
        assert!(
            (800..1_200).contains(&tens),
            "{tens} in 10 000 draws came up one in ten"
        );

        let edgy: HashSet<u8> = (0..1_000).map(|_| rng.edgy_byte()).collect();
        assert!(edgy.len() > 100, "only {} distinct edgy bytes", edgy.len());
        assert!(
            INTERESTING_U8.iter().all(|byte| edgy.contains(byte)),
            "the boundary bytes are the point of this one"
        );
        for len in [0, 1, 37] {
            assert_eq!(rng.bytes(len).len(), len, "bytes asked for {len}");
            assert_eq!(
                rng.plausible_bytes(len).len(),
                len,
                "plausible asked for {len}"
            );
        }
        let plausible = rng.plausible_bytes(1_000);
        let zeros: usize = plausible.iter().map(|&byte| usize::from(byte == 0)).sum();
        assert!(
            (400..800).contains(&zeros),
            "{zeros} zeros in 1000 plausible bytes, which lean on nought by half"
        );

        let arrays: HashSet<[u8; 4]> = (0..100).map(|_| rng.array::<4>()).collect();
        assert!(arrays.len() > 95, "{} distinct arrays in 100", arrays.len());

        let seeds: HashSet<u64> = (0..1_000).map(|case| seed_for(7, case)).collect();
        assert_eq!(seeds.len(), 1_000, "two cases of one run share a seed");
        assert_ne!(
            seed_for(1, 5),
            seed_for(2, 5),
            "the same case of two runs is the same case"
        );
    }

    #[test]
    fn a_case_number_reaches_the_same_seed_twice() {
        assert_eq!(seed_for(11, 90_000), seed_for(11, 90_000));
        assert_ne!(seed_for(11, 90_000), seed_for(11, 90_001));
    }
}

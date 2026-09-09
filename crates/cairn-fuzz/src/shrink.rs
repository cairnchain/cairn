//! Cutting a failing input down to the part that fails.
//!
//! A campaign that reports "case 91 941 of seed 0xca12f0221d05 fails" has
//! found something and has not yet said what. What goes into a regression test
//! is the smallest byte string that still fails, because that is the one whose
//! bytes can be read.
//!
//! Greedy and deterministic: cut, and keep the cut if it still fails. It is
//! not the smallest input there is, only the smallest this reaches, and that
//! has been enough every time it has been used here.

/// The smallest input this can reach that still satisfies `fails`.
///
/// `fails` must be a decision about the bytes alone. A predicate that depends
/// on anything else will drive this somewhere arbitrary and the result will
/// not reproduce.
#[must_use]
pub fn smallest<F: Fn(&[u8]) -> bool>(input: &[u8], fails: F) -> Vec<u8> {
    let mut best = input.to_vec();
    if !fails(&best) {
        return best;
    }

    // Whole runs first, largest first, which takes a megabyte to a handful of
    // bytes in a few dozen tries when most of it is padding.
    let mut span = best.len();
    while span > 0 {
        let mut at = 0usize;
        while at < best.len() {
            let end = at.saturating_add(span).min(best.len());
            let mut shorter = Vec::with_capacity(best.len());
            if let Some(head) = best.get(..at) {
                shorter.extend_from_slice(head);
            }
            if let Some(tail) = best.get(end..) {
                shorter.extend_from_slice(tail);
            }
            if shorter.len() < best.len() && fails(&shorter) {
                best = shorter;
            } else {
                at = at.saturating_add(span);
            }
        }
        span = span.checked_div(2).unwrap_or(0);
    }

    // Then each byte down towards zero, so what is left reads as the thing it
    // is rather than as whatever the generator happened to draw. Halving is in
    // the list because a byte is often a count that has to stay above one: a
    // leaf count of twenty six will not go to zero and will go to three, and
    // the difference is a regression test whose numbers can be read.
    for at in 0..best.len() {
        loop {
            let Some(current) = best.get(at).copied() else {
                break;
            };
            let candidates = [0u8, 1, current.checked_div(2).unwrap_or(0)];
            let mut lowered = false;
            for candidate in candidates {
                if current <= candidate {
                    continue;
                }
                let mut lower = best.clone();
                if let Some(byte) = lower.get_mut(at) {
                    *byte = candidate;
                }
                if fails(&lower) {
                    best = lower;
                    lowered = true;
                    break;
                }
            }
            if !lowered {
                break;
            }
        }
    }

    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_is_cut_away() {
        let mut input = vec![0u8; 4_000];
        input.extend_from_slice(&[9, 9, 9]);
        input.extend_from_slice(&[0u8; 4_000]);
        let smaller = smallest(&input, |bytes| {
            bytes.windows(3).any(|window| window == [9, 9, 9])
        });
        assert_eq!(smaller, vec![9, 9, 9]);
    }

    #[test]
    fn a_byte_is_walked_down_to_the_smallest_that_still_fails() {
        let smaller = smallest(&[200, 200, 200], |bytes| bytes.len() == 3);
        assert_eq!(smaller, vec![0, 0, 0]);
    }

    #[test]
    fn an_input_that_does_not_fail_comes_back_untouched() {
        assert_eq!(smallest(&[1, 2, 3], |_| false), vec![1, 2, 3]);
    }

    #[test]
    fn an_empty_input_is_left_alone() {
        assert_eq!(smallest(&[], |_| true), Vec::<u8>::new());
    }
}

//! Reading and writing hexadecimal.
//!
//! Keys, identifiers and roots are all shown as hex, so a person typing one
//! back in needs it parsed. Lower case on the way out, either case accepted on
//! the way in, and no separators or prefixes so that what is printed is exactly
//! what can be pasted.

/// Renders bytes as lower case hexadecimal.
pub fn encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        text.push(digit(byte >> 4));
        text.push(digit(byte & 0x0f));
    }
    text
}

fn digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0'.saturating_add(nibble)),
        _ => char::from(b'a'.saturating_add(nibble.saturating_sub(10))),
    }
}

fn value(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character.saturating_sub(b'0')),
        b'a'..=b'f' => Some(character.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(character.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// Parses hexadecimal into bytes, returning `None` on anything unexpected.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len().saturating_div(2));
    for pair in bytes.chunks(2) {
        let [high, low] = pair else { return None };
        let high = value(*high)?;
        let low = value(*low)?;
        out.push(high.checked_shl(4).unwrap_or(0) | low);
    }
    Some(out)
}

/// Parses hexadecimal of exactly `N` bytes.
pub fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = decode(text)?;
    <[u8; N]>::try_from(bytes.as_slice()).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bytes_survive_a_round_trip() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(encode(&bytes), "000fa5ff");
        assert_eq!(decode("000fa5ff").unwrap(), bytes);
        assert_eq!(
            decode("000FA5FF").unwrap(),
            bytes,
            "either case is accepted"
        );
    }

    #[test]
    fn nothing_encodes_to_nothing() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn anything_unexpected_is_refused() {
        assert!(
            decode("abc").is_none(),
            "an odd length is not a byte string"
        );
        assert!(decode("zz").is_none());
        assert!(decode("0x1234").is_none(), "no prefixes");
        assert!(decode("12 34").is_none(), "no separators");
    }

    #[test]
    fn a_fixed_length_is_enforced() {
        assert!(decode_array::<2>("a1b2").is_some());
        assert!(decode_array::<3>("a1b2").is_none());
        assert!(decode_array::<1>("a1b2").is_none());
    }
}

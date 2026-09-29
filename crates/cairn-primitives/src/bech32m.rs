//! Bech32m, the text an address is written in.
//!
//! BIP 350's checksum over BIP 173's alphabet: a prefix naming what the string
//! is for, the separator `1`, the data in five-bit groups, and six characters
//! of checksum. The checksum is a BCH code that detects every error of up to
//! four characters in a string of up to 89, so a typo in an address is refused
//! rather than paid to. Hexadecimal detects none: about one in sixteen of the
//! 960 single-character typos of a hexadecimal key is another usable key.
//!
//! Written here rather than taken from a crate because it is small and a
//! reader of an address has to agree with every other reader about it. The
//! vectors BIP 350 publishes are held in `tests/bech32m.rs`.

/// The thirty two characters a five-bit group is written as, in order.
///
/// No `1`, `b`, `i` or `o`, the characters most easily read as another.
pub const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// What the checksum of a Bech32m string comes to, where Bech32's comes to 1.
///
/// The one difference between the two, and the reason for the second: with
/// the constant 1, a string ending in `p` could take or lose any number of `q`
/// before it and keep its checksum.
const BECH32M_CONSTANT: u32 = 0x2bc8_30a3;

/// The longest string a reader accepts, as BIP 173 sets it.
pub const MOST_CHARACTERS: usize = 90;

/// Characters of checksum at the end of every string.
const CHECKSUM_CHARACTERS: usize = 6;

/// Why a string is not Bech32m.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Bech32mError {
    #[error("it holds a character that is not printable ASCII")]
    NotPrintable,
    #[error("it mixes capital and small letters")]
    MixedCase,
    #[error("it is longer than the {MOST_CHARACTERS} characters an address can be")]
    TooLong,
    #[error("it has no `1` between its prefix and its data")]
    NoSeparator,
    #[error("it has nothing before the `1`")]
    EmptyPrefix,
    #[error("it is too short to carry a checksum")]
    TooShort,
    #[error("`{0}` is not a character an address is written with")]
    NotInAlphabet(char),
    #[error("its checksum does not match, so at least one character is wrong")]
    BadChecksum,
    #[error("its last character carries bits that should be zero")]
    NonZeroPadding,
    #[error("its last character carries no part of any byte")]
    ExtraPadding,
}

/// BIP 173's generator, run over five-bit values.
fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum: u32 = 1;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (bit, generator) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

/// The prefix as the checksum reads it: each character's high bits, a nought,
/// then each character's low five bits.
fn expanded(prefix: &[u8]) -> impl Iterator<Item = u8> + '_ {
    prefix
        .iter()
        .map(|character| character >> 5)
        .chain(std::iter::once(0))
        .chain(prefix.iter().map(|character| character & 31))
}

fn checksum_of(prefix: &[u8], groups: &[u8]) -> [u8; CHECKSUM_CHARACTERS] {
    let values = expanded(prefix)
        .chain(groups.iter().copied())
        .chain([0; CHECKSUM_CHARACTERS]);
    let remainder = polymod(values) ^ BECH32M_CONSTANT;
    let mut checksum = [0u8; CHECKSUM_CHARACTERS];
    for (index, slot) in checksum.iter_mut().enumerate() {
        let shift = u32::try_from(CHECKSUM_CHARACTERS.saturating_sub(index).saturating_sub(1))
            .unwrap_or(0)
            .saturating_mul(5);
        *slot = u8::try_from((remainder >> shift) & 31).unwrap_or(0);
    }
    checksum
}

fn character_of(group: u8) -> char {
    ALPHABET
        .get(usize::from(group & 31))
        .map_or('q', |character| char::from(*character))
}

/// Writes five-bit groups under `prefix`.
///
/// The prefix is taken as given and must already be what a reader accepts:
/// printable ASCII in small letters, one character or more, short enough that
/// the whole string stays within [`MOST_CHARACTERS`]. Every prefix this
/// workspace writes is a constant that is. A group is its low five bits.
pub fn encode_groups(prefix: &str, groups: &[u8]) -> String {
    let groups: Vec<u8> = groups.iter().map(|group| group & 31).collect();
    let checksum = checksum_of(prefix.as_bytes(), &groups);
    let mut text = String::with_capacity(
        prefix
            .len()
            .saturating_add(1)
            .saturating_add(groups.len())
            .saturating_add(CHECKSUM_CHARACTERS),
    );
    text.push_str(prefix);
    text.push('1');
    for group in groups.iter().chain(checksum.iter()) {
        text.push(character_of(*group));
    }
    text
}

/// Reads a string into its prefix, in small letters, and its five-bit groups,
/// checksum removed.
///
/// Refuses what BIP 350 refuses: a character outside printable ASCII, capital
/// and small letters mixed, more than [`MOST_CHARACTERS`], no separator, an
/// empty prefix, fewer than six characters after the separator, a character
/// outside [`ALPHABET`] after it, and a checksum that is not Bech32m's. A
/// string in capitals throughout is read as the same string in small letters,
/// which is what a QR code carries.
pub fn decode_groups(text: &str) -> Result<(String, Vec<u8>), Bech32mError> {
    let bytes = text.as_bytes();
    if bytes
        .iter()
        .any(|character| !(33..=126).contains(character))
    {
        return Err(Bech32mError::NotPrintable);
    }
    let has_small = bytes.iter().any(u8::is_ascii_lowercase);
    let has_capital = bytes.iter().any(u8::is_ascii_uppercase);
    if has_small && has_capital {
        return Err(Bech32mError::MixedCase);
    }
    if bytes.len() > MOST_CHARACTERS {
        return Err(Bech32mError::TooLong);
    }
    let text = text.to_ascii_lowercase();
    let Some((prefix, data)) = text.rsplit_once('1') else {
        return Err(Bech32mError::NoSeparator);
    };
    if prefix.is_empty() {
        return Err(Bech32mError::EmptyPrefix);
    }
    if data.len() < CHECKSUM_CHARACTERS {
        return Err(Bech32mError::TooShort);
    }
    let mut groups = Vec::with_capacity(data.len());
    for character in data.chars() {
        let group = ALPHABET
            .iter()
            .position(|known| char::from(*known) == character)
            .and_then(|found| u8::try_from(found).ok())
            .ok_or(Bech32mError::NotInAlphabet(character))?;
        groups.push(group);
    }
    if polymod(expanded(prefix.as_bytes()).chain(groups.iter().copied())) != BECH32M_CONSTANT {
        return Err(Bech32mError::BadChecksum);
    }
    groups.truncate(groups.len().saturating_sub(CHECKSUM_CHARACTERS));
    Ok((prefix.to_owned(), groups))
}

/// Writes bytes under `prefix`, eight bits at a time into five, the last group
/// filled out with zero bits.
///
/// The prefix is held to what [`encode_groups`] says.
pub fn encode(prefix: &str, bytes: &[u8]) -> String {
    let mut groups = Vec::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut held: u32 = 0;
    let mut bits: u32 = 0;
    for byte in bytes {
        held = ((held << 8) | u32::from(*byte)) & 0x0fff;
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            groups.push(u8::try_from((held >> bits) & 31).unwrap_or(0));
        }
    }
    if bits > 0 {
        groups.push(u8::try_from((held << 5_u32.saturating_sub(bits)) & 31).unwrap_or(0));
    }
    encode_groups(prefix, &groups)
}

/// Reads a string into its prefix and the bytes it carries.
///
/// Refuses everything [`decode_groups`] refuses, a last group whose spare
/// bits are not zero, and five spare bits or more, which is a group that
/// carries no part of any byte: those are strings [`encode`] never writes, so
/// one string has one reading.
pub fn decode(text: &str) -> Result<(String, Vec<u8>), Bech32mError> {
    let (prefix, groups) = decode_groups(text)?;
    let mut bytes = Vec::with_capacity(groups.len().saturating_mul(5).saturating_div(8));
    let mut held: u32 = 0;
    let mut bits: u32 = 0;
    for group in groups {
        held = ((held << 5) | u32::from(group)) & 0x0fff;
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            bytes.push(u8::try_from((held >> bits) & 0xff).unwrap_or(0));
        }
    }
    if bits >= 5 {
        return Err(Bech32mError::ExtraPadding);
    }
    let spare = 1_u32.checked_shl(bits).unwrap_or(0).wrapping_sub(1);
    if held & spare != 0 {
        return Err(Bech32mError::NonZeroPadding);
    }
    Ok((prefix, bytes))
}

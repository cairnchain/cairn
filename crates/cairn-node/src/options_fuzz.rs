//! The operator's own text, under a generator.
//!
//! `cairn.conf` is a file a person writes and a node reads on every start, and
//! no campaign had read one (33-I2). Neither had the size and the key a person
//! types, and both are read by more than one program: the explorer reads a
//! size with its own copy of the node's function, and the wallet reads the
//! same kind of key as an address. A copy is a second place a fact lives, and
//! the one that moves is never the copy, so these hold the copies together.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

use std::collections::BTreeMap;

use cairn_crypto::SecretKey;
use cairn_fuzz::{mutate, Campaign, Rng};

use super::{parse_config, parse_mining_address, parse_size, KNOWN, ONLY_ON_THE_COMMAND_LINE};

/// Settings a file may carry.
fn settable() -> Vec<&'static str> {
    KNOWN
        .iter()
        .copied()
        .filter(|name| {
            !ONLY_ON_THE_COMMAND_LINE
                .iter()
                .any(|(only, _)| only == name)
        })
        .collect()
}

/// A value as a person writes one: no comment mark, nothing on either side of
/// it, and sometimes an `=` of its own.
fn a_value(rng: &mut Rng) -> String {
    const ALPHABET: &[u8] = b"abcXYZ019.:/-_=[]@ ";
    let len = rng.between(1, 24);
    let mut value: String = (0..len)
        .map(|_| char::from(*rng.pick(ALPHABET).unwrap_or(&b'a')))
        .collect();
    value = value.trim().to_owned();
    if value.is_empty() {
        value.push('v');
    }
    value
}

/// Spaces and tabs, to go round the parts of a line.
fn padding(rng: &mut Rng) -> String {
    (0..rng.below(3))
        .map(|_| if rng.bool() { ' ' } else { '\t' })
        .collect()
}

/// What a file assembled here has to read as.
#[derive(Debug)]
enum Expected {
    /// Every setting, in the order written.
    Read(BTreeMap<String, Vec<String>>),
    /// Refused, for a line whose fault the message has to name.
    Refused(String),
}

/// One file of lines a person could write, and what it has to read as.
fn a_file(rng: &mut Rng) -> (String, Expected) {
    let names = settable();
    let mut text = String::new();
    let mut read: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut refused: Option<String> = None;
    for _ in 0..rng.between(0, 12) {
        let kind = rng.below(20);
        let line = match kind {
            0 => String::new(),
            1 => format!("{}# {}", padding(rng), a_value(rng)),
            // A setting nobody knows, which has to be refused by its name.
            2 => {
                let name = format!("x{}", a_value(rng).replace(['=', ' '], ""));
                refused.get_or_insert(name.clone());
                format!("{name} = {}", a_value(rng))
            }
            // A setting that is only a question about one run.
            3 => {
                let (name, _) = *rng.pick(&ONLY_ON_THE_COMMAND_LINE).unwrap();
                refused.get_or_insert(name.to_owned());
                format!("{name}={}", a_value(rng))
            }
            // A line that is not `key = value` at all.
            4 => {
                let words = a_value(rng).replace('=', "");
                let words = if words.trim().is_empty() {
                    "words".to_owned()
                } else {
                    words.trim().to_owned()
                };
                refused.get_or_insert(words.clone());
                words
            }
            _ => {
                let name = *rng.pick(&names).unwrap();
                let value = a_value(rng);
                if refused.is_none() {
                    read.entry(name.to_owned()).or_default().push(value.clone());
                }
                let comment = if rng.chance(3) {
                    format!(" # {}", a_value(rng))
                } else {
                    String::new()
                };
                format!(
                    "{}{name}{}={}{value}{}{comment}",
                    padding(rng),
                    padding(rng),
                    padding(rng),
                    padding(rng)
                )
            }
        };
        text.push_str(&line);
        text.push_str(if rng.chance(4) { "\r\n" } else { "\n" });
    }
    let expected = refused.map_or(Expected::Read(read), Expected::Refused);
    (text, expected)
}

/// A configuration file reads as written, or is refused, naming what was
/// wrong with the first line at fault.
///
/// Assembled from what a person writes: the settings a file may carry with
/// plain values, padding, comments, blank lines and both line endings, and
/// then the three faults, a name nobody knows, a name that only means
/// something on the command line, and a line that is not a setting. Beside
/// them, real files bent by every operator `cairn_fuzz` has, which only have
/// to be read or refused without the program falling over, and never read
/// as a setting this build does not have. Nothing had asked any of it of a
/// file the tests did not write by hand.
#[test]
fn a_configuration_file_reads_as_written_or_is_refused_at_its_fault() {
    let campaign = Campaign::named("node: cairn.conf");
    let seed = campaign.seed();
    let mut corpus = Vec::new();
    for case in 0..8 {
        corpus.push(a_file(&mut campaign.stream(case)).0.into_bytes());
    }
    let (mut read, mut refused, mut bent) = (0usize, 0usize, 0usize);

    let ran = campaign.run(20_000, |case, rng| {
        if rng.chance(4) {
            let from = rng.pick(&corpus).cloned().unwrap_or_default();
            let bytes = mutate(rng, &from, &corpus);
            let text = String::from_utf8_lossy(&bytes);
            if let Ok(given) = parse_config(&text) {
                for name in given.values.keys() {
                    assert!(
                        settable().contains(&name.as_str()),
                        "case {case} of seed {seed:#x}: a bent file was read as setting \
                         `{name}`, which a file may not carry"
                    );
                }
            }
            bent += 1;
            return;
        }
        let (text, expected) = a_file(rng);
        match (parse_config(&text), expected) {
            (Ok(given), Expected::Read(wanted)) => {
                assert_eq!(
                    given.values, wanted,
                    "case {case} of seed {seed:#x}: the file was not read as written:\n{text}"
                );
                read += 1;
            }
            (Err(said), Expected::Refused(fault)) => {
                assert!(
                    said.contains(&fault),
                    "case {case} of seed {seed:#x}: the file was refused without naming \
                     `{fault}`, the first line at fault: {said}\n{text}"
                );
                refused += 1;
            }
            (answer, expected) => panic!(
                "case {case} of seed {seed:#x}: the file was answered {answer:?} where it \
                 should have been {expected:?}:\n{text}"
            ),
        }
    });

    eprintln!("node: cairn.conf: {read} read as written, {refused} refused, {bent} bent");
    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    assert!(
        read > 0 && refused > 0 && bent > 0,
        "an arm of the campaign never ran"
    );
}

/// What `text` is as a size, worked out here: `all`, or whole digits and
/// then at most one of three units, in any case, with space around either,
/// and a number past `u64` being no size at all.
fn as_a_size(text: &str) -> Option<u64> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("all") {
        return Some(u64::MAX);
    }
    let lower = text.to_ascii_lowercase();
    let units = [("gb", 1_000_000_000u64), ("mb", 1_000_000), ("kb", 1_000)];
    let (digits, scale) = units
        .iter()
        .find_map(|(unit, scale)| lower.strip_suffix(unit).map(|rest| (rest, *scale)))
        .unwrap_or((lower.as_str(), 1));
    // A sign in front is what Rust's own reading of a number takes, and the
    // node reads the number that way.
    let digits = digits.trim();
    let unsigned = digits.strip_prefix('+').unwrap_or(digits);
    if unsigned.is_empty() || !unsigned.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits
        .parse::<u64>()
        .ok()
        .map(|count| count.saturating_mul(scale))
}

/// A size is its digits times its unit, and nothing else is a size.
///
/// Held against the arithmetic done here: whole digits, one of three units in
/// any case or none, padding, `all`, and the ways a person gets it wrong. The
/// only tests were a handful of named cases.
#[test]
fn a_size_is_its_digits_times_its_unit() {
    let campaign = Campaign::named("node: sizes");
    let seed = campaign.seed();
    let units: [(&str, u64); 7] = [
        ("", 1),
        ("kb", 1_000),
        ("KB", 1_000),
        ("mB", 1_000_000),
        ("MB", 1_000_000),
        ("gb", 1_000_000_000),
        ("GB", 1_000_000_000),
    ];
    let mut read = 0usize;
    let ran = campaign.run(20_000, |case, rng| {
        let (text, wanted) = match rng.below(6) {
            0 => ("aLl".to_owned(), Some(u64::MAX)),
            // Bytes nobody would type, which only have to be refused or read
            // the way the rule above reads them.
            1 => {
                let len = rng.below(8);
                let junk: String = rng
                    .plausible_bytes(len)
                    .into_iter()
                    .map(char::from)
                    .collect();
                let wanted = as_a_size(&junk);
                (junk, wanted)
            }
            // A unit with no number, or a number with a unit nobody uses.
            2 => {
                let (unit, _) = *rng.pick(&units).unwrap();
                let text = if rng.bool() {
                    unit.to_owned()
                } else {
                    format!("{}tb", rng.below(1_000))
                };
                let wanted = if text.is_empty() {
                    None
                } else {
                    as_a_size(&text)
                };
                (text, wanted)
            }
            _ => {
                let digits = rng.edgy_u64() >> rng.below(64);
                let (unit, scale) = *rng.pick(&units).unwrap();
                let text = format!(
                    "{}{digits}{}{unit}{}",
                    padding(rng),
                    padding(rng),
                    padding(rng)
                );
                (text, Some(digits.saturating_mul(scale)))
            }
        };
        let answer = parse_size(&text).ok();
        assert_eq!(
            answer, wanted,
            "case {case} of seed {seed:#x}: `{text}` was read as {answer:?}"
        );
        read += usize::from(answer.is_some());
    });
    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    assert!(read > 0, "no size was ever read");
}

/// The body of `fn name` in `source`, from its signature to the brace that
/// closes it at the start of a line.
fn body_of<'a>(source: &'a str, name: &str) -> &'a str {
    let signature = format!("fn {name}(");
    let start = source
        .find(&signature)
        .unwrap_or_else(|| panic!("no `{signature}` in the source"));
    let rest = &source[start..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("`{signature}` never closes"));
    &rest[..end]
}

/// The node and the explorer read a size with one function, written twice.
///
/// Both programs take `--keep` and must read `512MB` alike, and the two are
/// separate programs, so the function is copied rather than shared. Held here
/// as one function: the two bodies are the same text, but for the sentence
/// each prints and the name the explorer gives to keeping everything. Nothing
/// held the copies together, so either could change alone.
#[test]
fn the_node_and_the_explorer_read_a_size_with_one_function() {
    let ours = include_str!("options.rs");
    let theirs = include_str!("../../cairn-explorer/src/options.rs");
    assert!(
        theirs.contains("const KEEP_EVERYTHING: u64 = u64::MAX;"),
        "the explorer's word for keeping everything is no longer the node's"
    );
    let comparable = |body: &str| -> Vec<String> {
        body.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with(".map_err(|_| format!("))
            .map(|line| line.replace("KEEP_EVERYTHING", "u64::MAX"))
            .collect()
    };
    assert_eq!(
        comparable(body_of(ours, "parse_size")),
        comparable(body_of(theirs, "parse_size")),
        "the node and the explorer no longer read a size the same way"
    );
}

/// An address the node is told to mine to is read exactly as the wallet reads
/// one, for any text at all.
///
/// A person copies the address a wallet shows into `--mine`, and an address
/// the node accepted that the wallet would not show, or the other way round,
/// is a reward paid somewhere nobody can spend. The wallet trims what it is
/// handed, because an address arrives pasted, and the node reads what the
/// command line or the file already trimmed; beyond that they must agree.
/// Nothing held the two readings together.
///
/// Where they differ on purpose is a public key in the old form: the node
/// converts one to its address, for the release that changed the form, and
/// the wallet refuses to pay to one. So a string the node read as a key is
/// left out of the comparison, and everything else it read is held to the
/// wallet's reading.
#[test]
fn an_address_the_node_mines_to_is_an_address_the_wallet_reads() {
    let campaign = Campaign::named("node: addresses");
    let seed = campaign.seed();
    let network = cairn_ledger::note::NetworkId::TESTNET;
    let addresses: Vec<String> = (1..=4u8)
        .map(|n| {
            cairn_ledger::note::Address::from(SecretKey::from_bytes(&[n; 32]).public_key())
                .to_text(network)
        })
        .collect();
    let mut agreed_yes = 0usize;
    let ran = campaign.run(4_000, |case, rng| {
        let text = match rng.below(5) {
            0 => rng.pick(&addresses).cloned().unwrap_or_default(),
            1 => rng
                .pick(&addresses)
                .cloned()
                .unwrap_or_default()
                .to_uppercase(),
            2 => cairn_primitives::bech32m::encode("tcairn", &rng.array::<32>()),
            3 => {
                let from = rng
                    .pick(&addresses)
                    .cloned()
                    .unwrap_or_default()
                    .into_bytes();
                let corpus: Vec<Vec<u8>> = addresses
                    .iter()
                    .map(|address| address.clone().into_bytes())
                    .collect();
                String::from_utf8_lossy(&mutate(rng, &from, &corpus)).into_owned()
            }
            _ => {
                let len = rng.below(80);
                rng.plausible_bytes(len)
                    .into_iter()
                    .map(char::from)
                    .collect()
            }
        };
        let text = text.trim();
        let node = parse_mining_address(text, network)
            .ok()
            .filter(|to| !to.was_a_key)
            .map(|to| to.address);
        let wallet = cairn_wallet::parse_address(text, network).ok();
        assert_eq!(
            node, wallet,
            "case {case} of seed {seed:#x}: the node and the wallet read `{text}` differently"
        );
        agreed_yes += usize::from(node.is_some());
    });
    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    assert!(
        agreed_yes > 0,
        "no text was ever read as an address by either"
    );
}

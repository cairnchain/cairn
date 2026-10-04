//! Mints the first blocks of the current test network and of the devnet
//! again, and writes them into every place the repository pins them.
//!
//! Run with `cargo run --release -p cairn-ledger --example remint -- --opens-at
//! 2026-10-06T18:00:00Z`, from anywhere in the repository, on the code that is
//! about to ship. The opening is a time in UTC, written with its `Z`, and it
//! has to be ahead of this machine's clock. To change what a block says, name
//! the network and the new message after it: `... --opens-at
//! 2026-10-06T18:00:00Z testnet "..."`. Otherwise each block keeps the message
//! it carries.
//!
//! A published network's first block is dated at its opening, because the
//! retarget's schedule starts at that block's timestamp: every target time a
//! network opens after its first block is dated is a block asked less than the
//! network's real rate, down to the floor. And no node can run a network
//! before a build carrying its first block has been merged, released and
//! installed, so a block dated the moment it is minted opens that network late
//! by all of that. So the test network's block is dated at an opening
//! announced ahead, and minted before it: the release carries it, every server
//! is installed with it, and a node started early waits for the opening and
//! opens the chain by itself (`deploy/README.md` has the steps). The devnet's
//! is dated [`DEVNET_DATED_EARLY`] before the moment this runs rather than
//! before the opening: `cairn-net/tests/pinned_network.rs` mines forward from
//! it behind the wall clock, and the release's checks run that test before the
//! opening.
//!
//! Then it reads every file git tracks and replaces each trace of an old block
//! with the new one's: the bytes of the constant in `genesis.rs`, the
//! identifier in full and as the twelve characters and an ellipsis the
//! README's table shows, and the timestamp written plainly, with the
//! underscores Rust writes it with, and as the date and time a comment gives.
//! It says which files it rewrote and what it replaced in each, and which of
//! their lines still call a block provisional, since those are sentences for a
//! person to settle. A release refuses to go out while `genesis.rs` or the
//! README still says provisional (`.github/workflows/release.yml`).

#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cairn_ledger::block::Block;
use cairn_ledger::genesis::{when, DEVNET_DATED_EARLY};
use cairn_ledger::pow::meets_target;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer, MAX_COINBASE_EXTRA};
use cairn_ledger::validation::{assemble_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;

/// The networks this mints again, by the name `for_network` answers to, and
/// when each first block is dated.
const NETWORKS: [(&str, Dated); 2] = [
    ("testnet", Dated::AtTheOpening),
    ("devnet", Dated::Before(DEVNET_DATED_EARLY)),
];

/// When a first block is dated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dated {
    /// At the opening announced on the command line.
    AtTheOpening,
    /// This many seconds before the moment this runs.
    Before(u64),
}

impl Dated {
    /// The timestamp for a block minted at `now` for a network announced to
    /// open at `opening`.
    const fn at(self, opening: u64, now: u64) -> u64 {
        match self {
            Self::AtTheOpening => opening,
            Self::Before(early) => now.saturating_sub(early),
        }
    }
}

/// Where the constants holding the first blocks live, from the repository's
/// root.
const GENESIS: &str = "crates/cairn-ledger/src/genesis.rs";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(said) => {
            eprintln!("remint: {said}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| format!("cannot find the repository: {error}"))?;
    let minted_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the clock reads before 1970".to_owned())?
        .as_secs();
    let Asked { opening, messages } = asked(std::env::args().skip(1).collect(), minted_at)?;
    println!(
        "the test network opens on {}, {} from now",
        when(opening),
        span(opening - minted_at)
    );
    println!();

    let mut traces = Vec::new();
    let mut constants = Vec::new();
    for (name, dated) in NETWORKS {
        let params = ConsensusParams::for_network(name)
            .ok_or_else(|| format!("this build has no rules for `{name}`"))?;
        let network = params.network.name().ok_or("a network with no name")?;
        let old = cairn_ledger::genesis::block(params.network);
        let message = match messages
            .iter()
            .find(|(asked, _)| asked == name || asked == network)
        {
            Some((_, message)) => message.clone(),
            None => old
                .as_ref()
                .map(|block| String::from_utf8_lossy(&block.coinbase.extra).into_owned())
                .filter(|message| !message.is_empty())
                .ok_or_else(|| {
                    format!("{network} has no first block to take a message from: name one")
                })?,
        };
        let block = mint(params, dated.at(opening, minted_at), &message)?;
        println!(
            "{network:<10} {}  dated {} ({}), {message:?}",
            block.id(),
            block.header.timestamp,
            when(block.header.timestamp)
        );
        if let Some(old) = &old {
            traces.extend(traces_of(network, old, &block));
        }
        constants.push((
            constant_of(network),
            cairn_primitives::hex::encode(&block.encode()),
        ));
    }
    println!();

    let mut rewritten = Vec::new();
    for path in tracked(&root)? {
        let Ok(text) = std::fs::read_to_string(root.join(&path)) else {
            continue;
        };
        let (mut rewrite, mut counts) = replaced(&text, &traces);
        if path == Path::new(GENESIS) {
            for (constant, hex) in &constants {
                rewrite = with_constant(&rewrite, constant, hex)?;
                counts.push(format!("the bytes of {constant}"));
            }
        }
        if rewrite != text {
            std::fs::write(root.join(&path), &rewrite)
                .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
            println!("rewrote {}: {}", path.display(), counts.join(", "));
            rewritten.push((path, rewrite));
        }
    }
    if rewritten.is_empty() {
        return Err("nothing was rewritten".to_owned());
    }

    let mut settle = Vec::new();
    for (path, text) in &rewritten {
        for (number, line) in text.lines().enumerate() {
            if line.to_lowercase().contains("provisional") {
                settle.push(format!(
                    "  {}:{}: {}",
                    path.display(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }
    if !settle.is_empty() {
        println!();
        println!("still calling a block provisional, for a person to settle:");
        for line in settle {
            println!("{line}");
        }
    }
    Ok(())
}

/// What the command line asks for: the opening, and the messages given as
/// pairs of a network and what its first block should say.
#[derive(Debug, PartialEq, Eq)]
struct Asked {
    opening: u64,
    messages: Vec<(String, String)>,
}

/// Reads the command line, refusing an opening that is not ahead of `now`.
fn asked(arguments: Vec<String>, now: u64) -> Result<Asked, String> {
    const USAGE: &str = "name the opening, in UTC: `--opens-at 2026-10-06T18:00:00Z`, then any \
                         messages as a network and the message, in pairs";
    let mut opening = None;
    let mut rest = Vec::new();
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        if argument == "--opens-at" {
            let given = arguments.next().ok_or(USAGE)?;
            if opening.replace(utc(&given)?).is_some() {
                return Err("name the opening once".to_owned());
            }
        } else {
            rest.push(argument);
        }
    }
    let opening = opening.ok_or(USAGE)?;
    if opening <= now {
        return Err(format!(
            "the opening has to be ahead of this machine's clock, and {} was {} ago: the \
             test network's first block is dated at it, and a network that opens after its \
             first block is dated hands out a nearly free block for every minute of the gap",
            when(opening),
            span(now - opening)
        ));
    }
    if rest.len() % 2 != 0 {
        return Err(USAGE.to_owned());
    }
    Ok(Asked {
        opening,
        messages: rest
            .chunks(2)
            .map(|pair| (pair[0].clone(), pair[1].clone()))
            .collect(),
    })
}

/// A time written `2026-10-06T18:00:00Z` or `2026-10-06T18:00Z`, as seconds
/// since 1970. Only UTC, and only with its `Z`, so that nobody announces an
/// opening in the time of the machine they happen to be at.
fn utc(text: &str) -> Result<u64, String> {
    let refused = || format!("{text:?} is not a time in UTC like 2026-10-06T18:00:00Z");
    let body = text.strip_suffix('Z').ok_or_else(refused)?;
    let (date, time) = body.split_once('T').ok_or_else(refused)?;
    let number = |part: &str, digits: usize| {
        if part.len() == digits && part.bytes().all(|byte| byte.is_ascii_digit()) {
            part.parse::<u64>().map_err(|_| refused())
        } else {
            Err(refused())
        }
    };
    let date: Vec<&str> = date.split('-').collect();
    let time: Vec<&str> = time.split(':').collect();
    let (year, month, day) = match date[..] {
        [year, month, day] => (number(year, 4)?, number(month, 2)?, number(day, 2)?),
        _ => return Err(refused()),
    };
    let (hour, minute, second) = match time[..] {
        [hour, minute] => (number(hour, 2)?, number(minute, 2)?, 0),
        [hour, minute, second] => (number(hour, 2)?, number(minute, 2)?, number(second, 2)?),
        _ => return Err(refused()),
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if year < 1970
        || !(1..=12).contains(&month)
        || !(1..=days_in_month).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(refused());
    }
    // A civil date to days since 1970, after Howard Hinnant's
    // `days_from_civil`, the reverse of what `when` does.
    let year = year - u64::from(month <= 2);
    let era = year / 400;
    let year_of_era = year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// A length of time the way a person says one: `1 day, 4 hours and 5
/// minutes`, to the minute, or in seconds under one.
fn span(seconds: u64) -> String {
    let unit = |count: u64, name: &str| {
        let plural = if count == 1 { "" } else { "s" };
        format!("{count} {name}{plural}")
    };
    if seconds < 60 {
        return unit(seconds, "second");
    }
    let parts: Vec<String> = [
        (seconds / 86_400, "day"),
        (seconds % 86_400 / 3_600, "hour"),
        (seconds % 3_600 / 60, "minute"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, name)| unit(count, name))
    .collect();
    match parts.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => unit(0, "minute"),
    }
}

/// Mines a first block for `params` dated `timestamp` and saying `message`,
/// on every core there is.
fn mint(mut params: ConsensusParams, timestamp: u64, message: &str) -> Result<Block, String> {
    // The block being minted is the one that would be pinned, so nothing is
    // pinned while it is made.
    params.genesis = None;
    params.opens_at = 0;
    let extra = message.as_bytes().to_vec();
    if extra.len() > MAX_COINBASE_EXTRA {
        return Err(format!(
            "{message:?} is {} bytes, the limit is {MAX_COINBASE_EXTRA}",
            extra.len()
        ));
    }
    // A coinbase paying nobody: a network should not open with someone already
    // holding something.
    let coinbase = CoinbaseTransaction::with_extra(0, Vec::new(), extra);
    let mut block = assemble_block(
        &LedgerState::new(),
        coinbase,
        Vec::<Transfer>::new(),
        &params,
        timestamp,
        0,
    )
    .map_err(|error| format!("a first block is not valid: {error:?}"))?;

    let started = Instant::now();
    let found = Arc::new(AtomicBool::new(false));
    let nonce = Arc::new(Mutex::new(None));
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let stride = u64::try_from(cores).unwrap_or(1);
    let workers: Vec<_> = (0..stride)
        .map(|start| {
            let mut header = block.header;
            let found = Arc::clone(&found);
            let nonce = Arc::clone(&nonce);
            std::thread::spawn(move || {
                header.nonce = start;
                while !found.load(Ordering::Relaxed) {
                    if meets_target(&header.id(), header.difficulty) {
                        found.store(true, Ordering::Relaxed);
                        *nonce.lock().expect("no worker panics holding it") = Some(header.nonce);
                        return;
                    }
                    match header.nonce.checked_add(stride) {
                        Some(next) => header.nonce = next,
                        None => return,
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().map_err(|_| "a worker stopped".to_owned())?;
    }
    let nonce = nonce
        .lock()
        .expect("every worker is done")
        .ok_or("no nonce works for this block")?;
    block.header.nonce = nonce;
    if !meets_target(&block.id(), block.header.difficulty) {
        return Err("the nonce found does not meet the target".to_owned());
    }
    println!(
        "mined {} at difficulty {} in {:.1} s on {cores} cores",
        params.network,
        block.header.difficulty,
        started.elapsed().as_secs_f64()
    );
    Ok(block)
}

/// Each way the repository writes something about `old`, the first block of
/// `network`, beside how it writes the same thing about `new`.
fn traces_of(network: &str, old: &Block, new: &Block) -> Vec<Trace> {
    let (old_id, new_id) = (old.id().to_string(), new.id().to_string());
    let (old_time, new_time) = (old.header.timestamp, new.header.timestamp);
    let what = |thing: &str| format!("{network}'s {thing}");
    vec![
        Trace::word(what("identifier"), &old_id, &new_id),
        Trace {
            what: what("identifier shortened"),
            old: format!("{}...", &old_id[..12]),
            new: format!("{}...", &new_id[..12]),
            ends_a_word: false,
        },
        Trace::word(
            what("timestamp"),
            &old_time.to_string(),
            &new_time.to_string(),
        ),
        Trace::word(
            what("timestamp in Rust"),
            &underscored(old_time),
            &underscored(new_time),
        ),
        Trace::word(what("date"), &when(old_time), &when(new_time)),
    ]
}

/// A string to replace, and whether it has to stand as a word of its own,
/// so that a timestamp is not found inside a longer number or a run of
/// hexadecimal.
struct Trace {
    what: String,
    old: String,
    new: String,
    ends_a_word: bool,
}

impl Trace {
    fn word(what: String, old: &str, new: &str) -> Self {
        Self {
            what,
            old: old.to_owned(),
            new: new.to_owned(),
            ends_a_word: true,
        }
    }
}

/// `text` with every trace replaced at once, so that a value one trace writes
/// is never read again by another, and what was replaced.
fn replaced(text: &str, traces: &[Trace]) -> (String, Vec<String>) {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let mut out = String::with_capacity(text.len());
    let mut counts = vec![0usize; traces.len()];
    let mut rest = text;
    let mut before = None;
    'scan: while let Some(next) = rest.chars().next() {
        for (index, trace) in traces.iter().enumerate() {
            if trace.old == trace.new || !rest.starts_with(&trace.old) {
                continue;
            }
            let after = rest[trace.old.len()..].chars().next();
            if word(before) || (trace.ends_a_word && word(after)) {
                continue;
            }
            out.push_str(&trace.new);
            counts[index] += 1;
            before = trace.old.chars().last();
            rest = &rest[trace.old.len()..];
            continue 'scan;
        }
        out.push(next);
        before = Some(next);
        rest = &rest[next.len_utf8()..];
    }
    let said = traces
        .iter()
        .zip(counts)
        .filter(|(_, count)| *count > 0)
        .map(|(trace, count)| format!("{count} x {}", trace.what))
        .collect();
    (out, said)
}

/// `text` with the string constant `name` holding `value`.
fn with_constant(text: &str, name: &str, value: &str) -> Result<String, String> {
    let opening = format!("const {name}: &str = \"");
    let start = text
        .find(&opening)
        .map(|at| at + opening.len())
        .ok_or_else(|| format!("{GENESIS} has no {name}"))?;
    let length = text[start..]
        .find('"')
        .ok_or_else(|| format!("{name} in {GENESIS} is never closed"))?;
    Ok(format!(
        "{}{value}{}",
        &text[..start],
        &text[start + length..]
    ))
}

/// The constant in `genesis.rs` holding the first block of the network named
/// `network`: `testnet-8` is `TESTNET_8`.
fn constant_of(network: &str) -> String {
    network.to_uppercase().replace('-', "_")
}

/// Every file git tracks, from the repository's root.
fn tracked(root: &Path) -> Result<Vec<PathBuf>, String> {
    let listed = Command::new("git")
        .arg("ls-files")
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if !listed.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&listed.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(PathBuf::from)
        .collect())
}

/// A number the way Rust source writes a large one: `1_790_800_858`.
fn underscored(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push('_');
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_ledger::validation::{connect_block, expected_difficulty, BlockError};

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn an_opening_is_read_in_utc_and_written_back_the_same() {
        for (text, seconds) in [
            ("2026-10-06T18:00:00Z", 1_791_309_600),
            ("2026-10-06T18:00Z", 1_791_309_600),
            ("2000-02-29T00:00:00Z", 951_782_400),
            ("1970-01-01T00:00:00Z", 0),
            ("2100-03-01T23:59:59Z", 4_107_628_799),
        ] {
            assert_eq!(utc(text), Ok(seconds), "{text}");
        }
        assert_eq!(when(1_791_309_600), "6 October 2026 at 18:00:00 UTC");
    }

    #[test]
    fn a_time_that_is_not_plainly_utc_is_refused() {
        for text in [
            "2026-10-06T18:00:00",
            "2026-10-06T18:00:00+02:00",
            "2026-10-06 18:00:00Z",
            "2026-10-6T18:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-10-00T00:00:00Z",
            "2026-10-06T24:00:00Z",
            "2026-10-06T18:60:00Z",
            "2026-10-06T18:00:60Z",
            "1969-12-31T23:59:59Z",
            "2026-10-06T18Z",
            "2026-10-06T18:00:00:00Z",
            "+026-10-06T18:00:00Z",
            "1791309600",
        ] {
            assert!(utc(text).is_err(), "{text} was read as a time");
        }
        assert_eq!(utc("2024-02-29T12:00:00Z"), Ok(1_709_208_000));
    }

    #[test]
    fn the_opening_is_asked_for_and_has_to_be_ahead_of_the_clock() {
        let opening = 1_791_309_600;
        let given = asked(
            words("--opens-at 2026-10-06T18:00:00Z testnet hello"),
            opening - 1,
        )
        .unwrap();
        assert_eq!(given.opening, opening);
        assert_eq!(
            given.messages,
            vec![("testnet".to_owned(), "hello".to_owned())]
        );
        assert!(
            asked(words("testnet hello"), 0).is_err(),
            "no opening named"
        );
        assert!(
            asked(words("--opens-at"), 0).is_err(),
            "an opening with no time"
        );
        assert!(
            asked(words("--opens-at 2026-10-06T18:00Z testnet"), 0).is_err(),
            "a message with no network"
        );
        assert!(
            asked(
                words("--opens-at 2026-10-06T18:00Z --opens-at 2026-10-07T18:00Z"),
                0
            )
            .is_err(),
            "two openings"
        );
        let refused = asked(words("--opens-at 2026-10-06T18:00:00Z"), opening).unwrap_err();
        assert!(
            refused.contains("ahead of this machine's clock") && refused.contains("0 seconds ago"),
            "an opening at the moment this runs is not ahead of it: {refused}"
        );
        let refused = asked(words("--opens-at 2026-10-06T18:00:00Z"), opening + 3_660).unwrap_err();
        assert!(
            refused.contains("1 hour and 1 minute ago"),
            "a past opening says how long ago it was: {refused}"
        );
    }

    #[test]
    fn a_length_of_time_is_said_to_the_minute() {
        assert_eq!(span(0), "0 seconds");
        assert_eq!(span(1), "1 second");
        assert_eq!(span(59), "59 seconds");
        assert_eq!(span(60), "1 minute");
        assert_eq!(span(3_600), "1 hour");
        assert_eq!(span(3_660), "1 hour and 1 minute");
        assert_eq!(
            span(86_400 + 7_200 + 300 + 7),
            "1 day, 2 hours and 5 minutes"
        );
        assert_eq!(span(2 * 86_400 + 60), "2 days and 1 minute");
    }

    /// The test network's block is dated at the opening, and the devnet's
    /// [`DEVNET_DATED_EARLY`] before the moment this runs, which is behind
    /// the wall clock whatever day the release's checks run on.
    #[test]
    fn the_test_network_is_dated_at_its_opening_and_the_devnet_behind_the_clock() {
        let (now, opening) = (1_791_000_000, 1_791_309_600);
        let dated: Vec<(&str, u64)> = NETWORKS
            .iter()
            .map(|(name, dated)| (*name, dated.at(opening, now)))
            .collect();
        assert_eq!(
            dated,
            vec![("testnet", opening), ("devnet", now - DEVNET_DATED_EARLY)]
        );
    }

    /// A block minted for an opening carries it, and a node takes it once its
    /// clock is within the drift of it and asks the block after it the
    /// opening difficulty: the network opens on its schedule.
    #[test]
    fn a_block_minted_for_an_opening_is_dated_at_it_and_opens_on_schedule() {
        let opening = 1_791_309_600;
        let params = ConsensusParams {
            genesis_difficulty: 1 << 6,
            ..ConsensusParams::for_network("testnet").unwrap()
        };
        let block = mint(params, opening, "opens later").unwrap();
        assert_eq!(block.header.timestamp, opening);
        let rules = ConsensusParams {
            genesis: Some(block.id()),
            opens_at: block.header.timestamp,
            ..params
        };
        let drift = rules.max_timestamp_drift;
        let mut early = LedgerState::new();
        assert!(matches!(
            connect_block(&mut early, &block, &rules, opening - drift - 1),
            Err(BlockError::TimestampTooFarAhead { .. })
        ));
        let mut state = LedgerState::new();
        connect_block(&mut state, &block, &rules, opening - drift).unwrap();
        assert_eq!(expected_difficulty(&state, &rules), 1 << 6);
    }
}

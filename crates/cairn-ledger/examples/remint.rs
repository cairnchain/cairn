//! Mints the first blocks of the current test network and of the devnet
//! again, and writes them into every place the repository pins them.
//!
//! Run with `cargo run --release -p cairn-ledger --example remint`, from
//! anywhere in the repository, on the code that is about to ship. To change
//! what a block says, name the network and the new message after `--`:
//! `cargo run --release -p cairn-ledger --example remint -- testnet "..."`.
//! Otherwise each block keeps the message it carries.
//!
//! A published network's first block is minted at its opening, because the
//! retarget's schedule starts at that block's timestamp: every target time a
//! network opens after its first block is dated is a block asked less than
//! the network's real rate, down to the floor. So the blocks a restart is
//! written against are provisional, and this is what replaces them on the
//! day. The test network's block is dated the moment this runs, and the
//! devnet's [`DEVNET_DATED_EARLY`] before it, as early as
//! `cairn-net/tests/pinned_network.rs` needs and no earlier.
//!
//! Then it reads every file git tracks and replaces each trace of an old block
//! with the new one's: the bytes of the constant in `genesis.rs`, the
//! identifier in full and as the twelve characters and an ellipsis the
//! README's table shows, and the timestamp written plainly, with the
//! underscores Rust writes it with, and as the date and time a comment gives.
//! It says which files it rewrote and what it replaced in each, and which of
//! their lines still call a block provisional, since those are sentences for a
//! person to settle.

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
use cairn_ledger::genesis::DEVNET_DATED_EARLY;
use cairn_ledger::pow::meets_target;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer, MAX_COINBASE_EXTRA};
use cairn_ledger::validation::{assemble_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;

/// The networks this mints again, by the name `for_network` answers to, and
/// how long before the moment this runs each first block is dated.
const NETWORKS: [(&str, u64); 2] = [("testnet", 0), ("devnet", DEVNET_DATED_EARLY)];

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
    let messages = messages_given()?;
    let minted_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the clock reads before 1970".to_owned())?
        .as_secs();

    let mut traces = Vec::new();
    let mut constants = Vec::new();
    for (name, early) in NETWORKS {
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
        let block = mint(params, minted_at - early, &message)?;
        println!(
            "{network:<10} {}  dated {} ({}), {message:?}",
            block.id(),
            block.header.timestamp,
            when(block.header.timestamp)
        );
        if let Some(old) = &old {
            traces.extend(traces_of(old, &block));
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

/// The messages named on the command line, as pairs of a network and what
/// its first block should say.
fn messages_given() -> Result<Vec<(String, String)>, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() % 2 != 0 {
        return Err("give a message as a network and the message, in pairs".to_owned());
    }
    Ok(arguments
        .chunks(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect())
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

/// Each way the repository writes something about `old`, beside how it
/// writes the same thing about `new`.
fn traces_of(old: &Block, new: &Block) -> Vec<Trace> {
    let (old_id, new_id) = (old.id().to_string(), new.id().to_string());
    let (old_time, new_time) = (old.header.timestamp, new.header.timestamp);
    vec![
        Trace::word("an identifier", &old_id, &new_id),
        Trace {
            what: "a shortened identifier",
            old: format!("{}...", &old_id[..12]),
            new: format!("{}...", &new_id[..12]),
            ends_a_word: false,
        },
        Trace::word("a timestamp", &old_time.to_string(), &new_time.to_string()),
        Trace::word(
            "a timestamp",
            &underscored(old_time),
            &underscored(new_time),
        ),
        Trace::word("a date", &when(old_time), &when(new_time)),
    ]
}

/// A string to replace, and whether it has to stand as a word of its own,
/// so that a timestamp is not found inside a longer number or a run of
/// hexadecimal.
struct Trace {
    what: &'static str,
    old: String,
    new: String,
    ends_a_word: bool,
}

impl Trace {
    fn word(what: &'static str, old: &str, new: &str) -> Self {
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

/// A timestamp the way a comment here gives one: `30 September 2026 at
/// 20:40:58 UTC`.
fn when(timestamp: u64) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let days = timestamp / 86_400;
    let seconds = timestamp % 86_400;
    // Days since 1970 to a civil date, after Howard Hinnant's
    // `civil_from_days`, for dates after the epoch.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{day} {} {year} at {:02}:{:02}:{:02} UTC",
        MONTHS[usize::try_from(month - 1).unwrap_or(0)],
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    )
}

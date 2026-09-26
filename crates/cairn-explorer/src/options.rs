//! Reading what the operator asked for.
//!
//! Parsed by hand, like the node's, and for the same reason: the whole surface
//! is six settings, and an argument parser would be the largest thing in the
//! dependency tree of a program people are invited to read.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use cairn_ledger::validation::ConsensusParams;
use cairn_net::seeds;

/// Every name this program understands.
///
/// An unknown name stops it rather than being passed over, so an operator
/// never runs something other than what they wrote.
const KNOWN: [&str; 8] = [
    "data", "listen", "http", "seed", "network", "keep", "help", "check",
];
const DEFAULT_DATA: &str = "cairn-explorer-data";
const DEFAULT_LISTEN: &str = "0.0.0.0:9945";
const DEFAULT_HTTP: &str = "127.0.0.1:8080";

pub(crate) const HELP: &str = "\
cairn-explorer, a Cairn node that also serves a website

  --data <directory>     where the chain is kept
                         (default: cairn-explorer-data)
  --listen <address>     address to accept peer connections on
                         (default: 0.0.0.0:9945)
  --http <address>       address to serve the website on
                         (default: 127.0.0.1:8080)
  --seed <address>       a peer to start from; repeat for more. Without one,
                       the addresses written into the program are used
  --keep <size|all>      how much of the chain to keep on disk, in bytes, or
                         `all` (default: all). A plain node keeps a gigabyte
                         and drops the oldest blocks past it, because it does
                         not need them: it has the ledger they add up to. An
                         explorer does need them, and this is the one program
                         whose whole job is answering about every block ever,
                         so it keeps every block unless an operator says
                         otherwise. Below `all` the oldest blocks are let
                         go of: the index keeps what it read of them, a
                         restart reads only what is kept, and a page that
                         needs a block no longer kept says it is on the
                         chain and not kept here, rather than reporting a
                         shorter chain as the whole of it.
                         Accepts suffixes: 512MB, 8GB
  --check                work out what this explorer would do and print it,
                         then stop without starting anything. Exits with an
                         error if a setting is one this build does not
                         accept, which is how a script can find out that a
                         network it was told to use has been retired
  --network <name>       testnet-6 or devnet (default: testnet-6)
  --help                 print this and stop

The explorer always keeps the cold set, because answering questions about
notes that have fallen is the whole point of it. That is a cost which grows
with the chain, which is exactly what a plain node refuses to carry. The
index it builds on top grows faster still: 627 bytes for every note that has
ever existed, against 72 for every note that has fallen. Both are
reported live at /api/status.";

/// Everything the explorer needs to start.
#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub(crate) data: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) http: SocketAddr,
    pub(crate) seeds: Vec<SocketAddr>,
    /// The names those addresses came from, kept so the node can ask again if
    /// none of them resolved at the moment it started.
    pub(crate) seed_names: Vec<String>,
    pub(crate) params: ConsensusParams,
    /// Bytes of blocks to keep on disk, `u64::MAX` for every one of them.
    pub(crate) keep: u64,
    /// Whether the operator asked for the settings and nothing else.
    pub(crate) check: bool,
}

#[derive(Debug, Default)]
struct Given {
    values: BTreeMap<String, Vec<String>>,
}

impl Given {
    fn first(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    fn all(&self, name: &str) -> &[String] {
        self.values.get(name).map_or(&[], Vec::as_slice)
    }

    fn push(&mut self, name: &str, value: String) {
        self.values.entry(name.to_owned()).or_default().push(value);
    }

    fn has(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// Refuses a setting given twice with two different values.
    ///
    /// Only the first was ever read and the rest were dropped without a word,
    /// so `--network devnet --network testnet-6` ran on devnet and said nothing
    /// about the other. `cairnd` and the wallet refuse it, under the rule
    /// [`KNOWN`] states for a name this program does not know: what is passed
    /// over is how an operator runs something other than what they wrote.
    ///
    /// The same value twice drops nothing, so nothing is said. `seed` is a list
    /// rather than a setting, and every one of them is used.
    fn one_value_each(&self) -> Result<(), String> {
        for (name, values) in &self.values {
            if name == "seed" {
                continue;
            }
            let Some(first) = values.first() else {
                continue;
            };
            let Some(other) = values.iter().find(|value| *value != first) else {
                continue;
            };
            return Err(format!(
                "`--{name}` is given twice, as `{first}` and as `{other}`, and only the first \
                 would ever be used. Say which one you mean."
            ));
        }
        Ok(())
    }
}

fn parse_arguments(arguments: &[String]) -> Result<Given, String> {
    let mut given = Given::default();
    let mut index = 0usize;
    while let Some(argument) = arguments.get(index) {
        let Some(name) = argument.strip_prefix("--") else {
            return Err(format!(
                "unexpected argument `{argument}`, options start with `--`"
            ));
        };
        if !KNOWN.contains(&name) {
            return Err(format!("unknown option `--{name}`"));
        }
        index = index.saturating_add(1);
        if name == "help" || name == "check" {
            given.push(name, String::new());
            continue;
        }
        let Some(value) = arguments.get(index) else {
            return Err(format!("`--{name}` needs a value"));
        };
        // A value that begins with two dashes is a value the operator left
        // out. Taking it as one gave `--data --check` a chain directory called
        // `--check`, and swallowed the flag on the way past.
        if value.starts_with("--") {
            return Err(format!(
                "`--{name}` needs a value, and `{value}` is another option"
            ));
        }
        index = index.saturating_add(1);
        given.push(name, value.clone());
    }
    Ok(given)
}

pub(crate) fn resolve_options(arguments: &[String]) -> Result<Option<Options>, String> {
    let given = parse_arguments(arguments)?;
    if given.has("help") {
        return Ok(None);
    }
    given.one_value_each()?;

    let data = PathBuf::from(given.first("data").unwrap_or(DEFAULT_DATA));
    let listen = seeds::resolve_one(given.first("listen").unwrap_or(DEFAULT_LISTEN))?;
    let http = seeds::resolve_one(given.first("http").unwrap_or(DEFAULT_HTTP))?;

    let name = given.first("network").unwrap_or("testnet");
    let params = ConsensusParams::for_network(name).ok_or_else(|| {
        if name == "mainnet" {
            "mainnet does not exist yet: its first block has not been mined".to_owned()
        } else {
            format!("unknown network `{name}`, try testnet-6 or devnet")
        }
    })?;

    // After the network is settled: an explorer given no seed starts from the
    // ones written into the program, like every other node.
    let seed_names = seeds::names_for(given.all("seed"), params.network);
    let seeds = seeds::start_from(given.all("seed"), params.network)?;

    let keep = match given.first("keep") {
        None => KEEP_EVERYTHING,
        Some(text) => parse_size(text)?,
    };

    Ok(Some(Options {
        data,
        listen,
        http,
        seeds,
        seed_names,
        params,
        keep,
        check: given.has("check"),
    }))
}

/// What an explorer keeps unless it is told otherwise: all of it.
///
/// A node's default is a gigabyte, and it is right for a node: what it needs
/// is the ledger those blocks add up to, and it holds that. It keeps any
/// blocks at all as a service to peers a little behind. An explorer's whole
/// purpose is the opposite service, answering about every block ever, and it
/// reads its index by walking the chain from the first block up. Left on a
/// node's default it passed a gigabyte, dropped the oldest blocks, and then
/// the first reorganisation left it with an index it could not rebuild. The
/// index takes a shallow one back block by block now; one deeper than it keeps
/// the means for is still a rebuild, from the first block up.
pub(crate) const KEEP_EVERYTHING: u64 = u64::MAX;

/// A size as an operator writes one.
fn parse_size(text: &str) -> Result<u64, String> {
    let trimmed = text.trim();
    if trimmed.eq_ignore_ascii_case("all") {
        return Ok(KEEP_EVERYTHING);
    }
    let lower = trimmed.to_ascii_lowercase();
    let (digits, scale) = if let Some(rest) = lower.strip_suffix("gb") {
        (rest, 1_000_000_000u64)
    } else if let Some(rest) = lower.strip_suffix("mb") {
        (rest, 1_000_000)
    } else if let Some(rest) = lower.strip_suffix("kb") {
        (rest, 1_000)
    } else {
        (lower.as_str(), 1)
    };
    let count: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("`{text}` is not a size; try 8GB, 512MB, or all"))?;
    Ok(count.saturating_mul(scale))
}

/// A size as an operator would read it back.
pub(crate) fn size(bytes: u64) -> String {
    if bytes == KEEP_EVERYTHING {
        "every one ever accepted".to_owned()
    } else {
        format!("{}, older ones dropped", in_units(bytes))
    }
}

/// A number of bytes in the largest unit it fills.
fn in_units(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{} GB", bytes.saturating_div(1_000_000_000))
    } else if bytes >= 1_000_000 {
        format!("{} MB", bytes.saturating_div(1_000_000))
    } else {
        format!("{bytes} bytes")
    }
}

/// What this explorer keeps on disk, as its start says it: the budget, and
/// under a budget the floor the trim never cuts into.
///
/// The trim keeps the last [`ConsensusParams::burial`] blocks whatever it is
/// given, because the chain lets go of block bodies from memory on the promise
/// that the log still holds them. `cairnd` says so beside its own budget, after
/// `--keep 1MB` printed a megabyte and held a hundred and twenty eight times
/// that. This explorer trims through the same node and printed the megabyte
/// alone.
pub(crate) fn kept(keep: u64, params: &ConsensusParams) -> String {
    if keep == KEEP_EVERYTHING {
        return size(keep);
    }
    format!(
        "{}\n             never below the last {} blocks, whatever they weigh: up to {} on \
         this network",
        size(keep),
        params.burial,
        in_units(params.burial_bytes()),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        kept, parse_arguments, resolve_options, size, ConsensusParams, HELP, KEEP_EVERYTHING,
    };

    /// A size is said back the way an operator would write it.
    ///
    /// It is the line that tells somebody how much of the chain this explorer
    /// keeps, and nothing read it: saying every size in bytes passed, as did
    /// saying every one as a gigabyte count of nought.
    #[test]
    fn a_size_is_said_the_way_it_would_be_written() {
        assert_eq!(size(KEEP_EVERYTHING), "every one ever accepted");
        assert_eq!(size(8_000_000_000), "8 GB, older ones dropped");
        assert_eq!(size(1_000_000_000), "1 GB, older ones dropped");
        assert_eq!(size(999_999_999), "999 MB, older ones dropped");
        assert_eq!(size(1_000_000), "1 MB, older ones dropped");
        assert_eq!(size(999_999), "999999 bytes, older ones dropped");
    }

    /// Under a budget the explorer states the floor the trim never cuts into,
    /// and keeping everything it states none.
    ///
    /// Its start said the budget alone. Nothing asked it, so an explorer given
    /// a megabyte said it kept a megabyte on a network whose last blocks, the
    /// ones no budget drops, weigh several, which `cairnd` had stopped saying
    /// after the same figure misled its own operators.
    #[test]
    fn a_budget_is_said_with_the_floor_under_it() {
        let params = ConsensusParams::testnet()
            .with_burial(8)
            .with_max_block_bytes(1_000_000);
        let said = kept(1_000_000, &params);
        assert!(
            said.starts_with("1 MB, older ones dropped\n"),
            "the budget is not the first thing said: {said}"
        );
        assert!(
            said.contains(
                "never below the last 8 blocks, whatever they weigh: up to 8 MB on this network"
            ),
            "the floor under the budget is not said, or not as the rules make it: {said}"
        );
        assert_eq!(
            kept(KEEP_EVERYTHING, &params),
            "every one ever accepted",
            "an explorer that drops nothing states a floor under what it drops"
        );
    }

    fn arguments(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn an_unknown_option_stops_the_program() {
        let error = parse_arguments(&arguments(&["--rpc", "1"])).unwrap_err();
        assert!(error.contains("unknown option"), "{error}");
    }

    #[test]
    fn an_option_without_a_value_stops_the_program() {
        let error = parse_arguments(&arguments(&["--http"])).unwrap_err();
        assert!(error.contains("needs a value"), "{error}");
    }

    #[test]
    fn mainnet_is_refused_by_name() {
        let error = resolve_options(&arguments(&["--network", "mainnet"])).unwrap_err();
        assert!(error.contains("does not exist yet"), "{error}");
    }

    /// An explorer left on a node's block budget passes it, drops the oldest
    /// blocks, and then cannot rebuild its index after a reorganisation too
    /// deep to take back: it walks from the first block up, and the first
    /// block is the one it no longer has. So the default here is the opposite of
    /// the node's, and an operator who cannot afford it says so.
    #[test]
    fn an_explorer_keeps_every_block_unless_told_otherwise() {
        let options = resolve_options(&arguments(&[])).unwrap().unwrap();
        assert_eq!(options.keep, super::KEEP_EVERYTHING);

        let options = resolve_options(&arguments(&["--keep", "8GB"]))
            .unwrap()
            .unwrap();
        assert_eq!(options.keep, 8_000_000_000);

        let options = resolve_options(&arguments(&["--keep", "all"]))
            .unwrap()
            .unwrap();
        assert_eq!(options.keep, super::KEEP_EVERYTHING);

        let error = resolve_options(&arguments(&["--keep", "plenty"])).unwrap_err();
        assert!(error.contains("is not a size"), "{error}");
    }

    /// `--check` is a setting, so it is read off the settings.
    ///
    /// It used to be found by looking through the words the operator typed for
    /// one that read `--check`, which found it in the one place it was not:
    /// standing where another option's value belongs. `--data --check` printed
    /// the settings, stopped, and exited nought, having never started the site
    /// and never said why.
    #[test]
    fn a_flag_standing_where_a_value_belongs_is_not_the_flag() {
        let options = resolve_options(&arguments(&["--check"])).unwrap().unwrap();
        assert!(options.check, "asked for plainly");

        let error = resolve_options(&arguments(&["--data", "--check"])).unwrap_err();
        assert!(error.contains("another option"), "{error}");

        let options = resolve_options(&arguments(&["--data", "somewhere"]))
            .unwrap()
            .unwrap();
        assert!(!options.check, "and nothing here asked for it at all");
    }

    /// The help text quotes what one note costs the index. An operator sizes a
    /// machine off that figure, so it is held to the one the program reports.
    ///
    /// Both figures, which is the half this was missing. The same sentence
    /// names what a note that has ever existed costs the index and what a
    /// fallen one costs the cold set, and only the first was held: the second
    /// was spelled out in words, so no test could have found it and none
    /// looked. A rule applied to one of two numbers in one sentence is the
    /// shape this repository keeps finding, and it is worse here than usual,
    /// because both numbers are what an operator sizes a machine on.
    #[test]
    fn the_help_quotes_both_figures_the_program_reports() {
        let index = crate::index::BYTES_PER_NOTE.to_string();
        assert!(
            HELP.contains(&index),
            "the help says something other than {index} bytes a note for the index"
        );

        let cold = crate::api::COLD_BYTES_PER_NOTE.to_string();
        assert!(
            HELP.contains(&cold),
            "the help says something other than {cold} bytes a note for the cold set"
        );
    }

    /// A setting given twice with two different values stops the program, as
    /// it stops `cairnd` and the wallet, and the same value twice does not.
    ///
    /// Only the first value was ever read and the second was dropped without
    /// a word. Nothing asked this, so `--network devnet --network testnet-6`
    /// started an explorer on devnet that said nothing about the other name it
    /// was given, and so did a `--keep` given twice.
    #[test]
    fn a_setting_given_twice_as_two_values_stops_the_program() {
        let error = resolve_options(&arguments(&[
            "--network",
            "devnet",
            "--network",
            "testnet-6",
        ]))
        .unwrap_err();
        assert!(
            error.contains("given twice"),
            "a network named twice was taken as the first: {error}"
        );
        assert!(
            error.contains("devnet") && error.contains("testnet-6"),
            "the refusal does not say which two it was handed: {error}"
        );

        let error = resolve_options(&arguments(&["--keep", "1GB", "--keep", "all"])).unwrap_err();
        assert!(
            error.contains("given twice"),
            "a budget given twice was taken as the first: {error}"
        );

        assert!(
            resolve_options(&arguments(&["--network", "devnet", "--network", "devnet"])).is_ok(),
            "the same value twice drops nothing, and was refused"
        );
        assert!(
            resolve_options(&arguments(&[
                "--seed",
                "127.0.0.1:1",
                "--seed",
                "127.0.0.1:2"
            ]))
            .is_ok(),
            "a second seed is another peer, and was refused as a second answer"
        );
    }

    #[test]
    fn seeds_accumulate() {
        let given = parse_arguments(&arguments(&[
            "--seed",
            "127.0.0.1:1",
            "--seed",
            "127.0.0.1:2",
        ]))
        .unwrap_or_default();
        assert_eq!(given.all("seed").len(), 2);
    }
}

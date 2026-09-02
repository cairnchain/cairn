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
                         otherwise. Below `all` the index starts wherever the
                         oldest kept block is, and every page says so rather
                         than reporting a shorter chain as the whole of it.
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
index it builds on top grows faster still: about five hundred bytes for every
note that has ever existed, against seventy two for every note that has
fallen. Both are reported live at /api/status.";

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
/// the first reorganisation left it with an index it could not rebuild.
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
    } else if bytes >= 1_000_000_000 {
        format!(
            "{} GB, older ones dropped",
            bytes.saturating_div(1_000_000_000)
        )
    } else if bytes >= 1_000_000 {
        format!("{} MB, older ones dropped", bytes.saturating_div(1_000_000))
    } else {
        format!("{bytes} bytes, older ones dropped")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{parse_arguments, resolve_options};

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
    /// blocks, and then cannot rebuild its index after the next
    /// reorganisation: it walks from the first block up, and the first block
    /// is the one it no longer has. So the default here is the opposite of
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

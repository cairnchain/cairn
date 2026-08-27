//! Reading what the operator asked for.
//!
//! Settings come from the command line, and from a `cairn.conf` in the data
//! directory holding the same names as `key = value`. The command line wins,
//! so a running configuration can be overridden without editing a file.
//!
//! Parsed by hand rather than by a library: the whole surface is eight
//! settings, and a node people are asked to audit is better off without an
//! argument parser in its dependency tree.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use cairn_crypto::PublicKey;
use cairn_ledger::validation::ConsensusParams;

pub(crate) const CONFIG_FILE: &str = "cairn.conf";

/// Every name this node understands.
///
/// An unknown name stops the node rather than being passed over. A setting
/// that is silently ignored is how an operator ends up running rules they did
/// not choose, which on a chain means following a different one.
const KNOWN: [&str; 9] = [
    "data", "listen", "seed", "network", "mine", "status", "run-for", "archive", "help",
];
const DEFAULT_DATA: &str = "cairn-data";
const DEFAULT_LISTEN: &str = "0.0.0.0:9944";

pub(crate) const HELP: &str = "\
cairnd, a Cairn node

  --data <directory>     where the chain and the address book are kept
                         (default: cairn-data)
  --listen <address>     address to accept connections on
                         (default: 0.0.0.0:9944)
  --seed <address>       a peer to start from; repeat for more
  --network <name>       testnet-1 or devnet (default: testnet-1)
                         devnet has the same rules with a five second block
                         time and a tiny hot set, for one machine.
                         mainnet does not exist yet: a network exists once
                         its first block does, and that one will be mined in
                         the open on the day it is announced
  --mine <public key>    produce blocks, paying rewards to this key
  --archive              keep the cold set, so this node can rebuild a proof
                         for a wallet that lost its own. Costs a set that
                         grows; without it a node keeps sixty four hashes
  --status <seconds>     how often to print a status line (default: 10)
  --run-for <seconds>    stop after this long, for tests and demonstrations
  --help                 print this and stop

The same names work in <data>/cairn.conf as `key = value`. The command line
wins over the file.";

/// Everything a node needs to start.
#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub(crate) data: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) seeds: Vec<SocketAddr>,
    pub(crate) params: ConsensusParams,
    pub(crate) mine_to: Option<PublicKey>,
    pub(crate) status_period: u64,
    /// Stops the node after this long. A node is meant to run until it is
    /// stopped; this exists so a test or a demonstration can bound it.
    pub(crate) run_for: Option<u64>,
    /// Whether to keep the cold set and be able to prove things about it.
    pub(crate) archive: bool,
}

/// Named values, each of which may have been given more than once.
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

        if name == "help" || name == "archive" {
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

fn parse_config(text: &str) -> Result<Given, String> {
    let mut given = Given::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!("`{line}` is not a `key = value` line"));
        };
        let name = name.trim();
        if !KNOWN.contains(&name) {
            return Err(format!("unknown setting `{name}` in {CONFIG_FILE}"));
        }
        given.push(name, value.trim().to_owned());
    }
    Ok(given)
}

fn resolve(text: &str) -> Result<SocketAddr, String> {
    text.to_socket_addrs()
        .map_err(|error| format!("`{text}` is not an address: {error}"))?
        .next()
        .ok_or_else(|| format!("`{text}` resolved to nothing"))
}

/// Reads the command line, then the configuration file the command line points
/// at, and settles every setting.
pub(crate) fn resolve_options(arguments: &[String]) -> Result<Option<Options>, String> {
    let command_line = parse_arguments(arguments)?;
    if command_line.has("help") {
        return Ok(None);
    }

    let data = PathBuf::from(command_line.first("data").unwrap_or(DEFAULT_DATA));
    let file = std::fs::read_to_string(data.join(CONFIG_FILE)).unwrap_or_default();
    let config = parse_config(&file)?;

    let setting = |name: &str| -> Option<String> {
        command_line
            .first(name)
            .or_else(|| config.first(name))
            .map(str::to_owned)
    };

    let listen = resolve(&setting("listen").unwrap_or_else(|| DEFAULT_LISTEN.to_owned()))?;

    let mut seeds = Vec::new();
    for text in command_line.all("seed").iter().chain(config.all("seed")) {
        seeds.push(resolve(text)?);
    }

    let name = setting("network").unwrap_or_else(|| "testnet".to_owned());
    // Every consensus rule comes from the name, and none of them can be set
    // one at a time. Two nodes that differ on any of them would build
    // different chains while believing they were on the same network.
    let params = ConsensusParams::for_network(&name).ok_or_else(|| {
        if name == "mainnet" {
            "mainnet does not exist yet: its first block has not been mined".to_owned()
        } else {
            format!("unknown network `{name}`, try testnet-1 or devnet")
        }
    })?;

    let mine_to = match setting("mine") {
        None => None,
        Some(text) => Some(parse_key(&text)?),
    };

    let status_period = match setting("status") {
        None => 10,
        Some(text) => text
            .parse()
            .map_err(|_| format!("`{text}` is not a number of seconds"))?,
    };

    let run_for = match setting("run-for") {
        None => None,
        Some(text) => Some(
            text.parse()
                .map_err(|_| format!("`{text}` is not a number of seconds"))?,
        ),
    };

    let archive = command_line.has("archive") || config.has("archive");

    Ok(Some(Options {
        data,
        listen,
        seeds,
        params,
        mine_to,
        status_period,
        run_for,
        archive,
    }))
}

fn parse_key(text: &str) -> Result<PublicKey, String> {
    let bytes = cairn_primitives::hex::decode_array::<32>(text)
        .ok_or_else(|| format!("`{text}` is not 32 bytes of hexadecimal"))?;
    PublicKey::from_bytes(&bytes).map_err(|error| format!("that key is unusable: {error}"))
}

/// A one line summary of what the node is about to do.
pub(crate) fn describe(options: &Options) -> String {
    let mut text = String::new();
    let _ = writeln!(
        text,
        "network      {} ({:#010x})",
        options.params.network_name(),
        options.params.network.as_u32()
    );
    if let Some(genesis) = options.params.genesis {
        let _ = writeln!(text, "starts from  {genesis}");
        let _ = writeln!(text, "opened at    {}", options.params.opens_at);
    }
    let _ = writeln!(text, "data         {}", options.data.display());
    let _ = writeln!(text, "listen       {}", options.listen);
    let _ = writeln!(text, "block time   {} s", options.params.target_block_time);
    if options.seeds.is_empty() {
        let _ = writeln!(text, "seeds        none given");
    } else {
        for seed in &options.seeds {
            let _ = writeln!(text, "seed         {seed}");
        }
    }
    let _ = writeln!(
        text,
        "keeping      {}",
        if options.archive {
            "the whole cold set (archivist)"
        } else {
            "sixty four hashes"
        }
    );
    match options.mine_to {
        Some(key) => {
            let _ = writeln!(text, "mining       rewards to {key}");
        }
        None => {
            let _ = writeln!(text, "mining       off");
        }
    }
    text
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn defaults_apply_when_nothing_is_given() {
        let options = resolve_options(&[]).unwrap().unwrap();
        assert_eq!(options.data, PathBuf::from(DEFAULT_DATA));
        assert_eq!(options.listen.port(), 9_944);
        assert_eq!(options.params.network_name(), "testnet-1");
        assert_eq!(options.params.target_block_time, 60);
        assert!(options.mine_to.is_none());
        assert!(options.seeds.is_empty());
        assert!(
            !options.archive,
            "a node validates without archiving by default"
        );
    }

    #[test]
    fn help_stops_before_anything_else() {
        assert!(resolve_options(&args(&["--help"])).unwrap().is_none());
    }

    #[test]
    fn archiving_is_asked_for_and_takes_no_value() {
        let options = resolve_options(&args(&["--archive"])).unwrap().unwrap();
        assert!(options.archive);
        // It is a switch, so what follows it is not swallowed as its value.
        let options = resolve_options(&args(&["--archive", "--status", "3"]))
            .unwrap()
            .unwrap();
        assert!(options.archive);
        assert_eq!(options.status_period, 3);
    }

    #[test]
    fn seeds_accumulate() {
        let options = resolve_options(&args(&[
            "--seed",
            "127.0.0.1:1111",
            "--seed",
            "127.0.0.1:2222",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(options.seeds.len(), 2);
    }

    #[test]
    fn a_bad_value_is_reported_rather_than_guessed_at() {
        assert!(resolve_options(&args(&["--listen", "not an address"])).is_err());
        assert!(resolve_options(&args(&["--network", "moonnet"])).is_err());
        assert!(
            resolve_options(&args(&["--network", "mainnet"])).is_err(),
            "a network exists once its first block does"
        );
        assert!(resolve_options(&args(&["--mine", "abcd"])).is_err());
        assert!(
            resolve_options(&args(&["--listen"])).is_err(),
            "a value is missing"
        );
        assert!(
            resolve_options(&args(&["listen", "x"])).is_err(),
            "options start with --"
        );
    }

    #[test]
    fn a_mining_key_must_be_a_usable_key() {
        let secret = cairn_crypto::SecretKey::from_bytes(&[3; 32]);
        let text = secret.public_key().to_string();
        let options = resolve_options(&args(&["--mine", &text])).unwrap().unwrap();
        assert_eq!(options.mine_to, Some(secret.public_key()));

        let zeroes = "0".repeat(64);
        assert!(
            resolve_options(&args(&["--mine", &zeroes])).is_err(),
            "a weak key is refused"
        );
    }

    #[test]
    fn the_configuration_file_is_read_and_the_command_line_wins() {
        let directory = std::env::temp_dir().join(format!("cairn-options-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(CONFIG_FILE),
            "# a comment\nnetwork = devnet\nseed = 127.0.0.1:3333\nstatus = 3\n",
        )
        .unwrap();

        let data = directory.to_string_lossy().to_string();
        let options = resolve_options(&args(&["--data", &data])).unwrap().unwrap();
        assert_eq!(options.params.network_name(), "devnet");
        assert_eq!(options.params.target_block_time, 5);
        assert_eq!(options.seeds.len(), 1);
        assert_eq!(options.status_period, 3);

        let options = resolve_options(&args(&["--data", &data, "--network", "testnet-1"]))
            .unwrap()
            .unwrap();
        assert_eq!(
            options.params.network_name(),
            "testnet-1",
            "the command line wins"
        );
    }

    #[test]
    fn a_network_name_settles_every_rule_at_once() {
        // No single rule can be moved on its own, because a node that differed
        // on one would follow a chain of its own while believing otherwise.
        let testnet = resolve_options(&args(&["--network", "testnet"]))
            .unwrap()
            .unwrap();
        let devnet = resolve_options(&args(&["--network", "devnet"]))
            .unwrap()
            .unwrap();
        assert_ne!(testnet.params.network, devnet.params.network);
        assert_ne!(
            testnet.params.target_block_time,
            devnet.params.target_block_time
        );
        assert!(resolve_options(&args(&["--block-time", "5"])).is_err());
    }
}

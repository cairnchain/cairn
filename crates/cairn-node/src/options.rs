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
use std::net::SocketAddr;
use std::path::PathBuf;

use cairn_crypto::PublicKey;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::{seeds, KEEP_BLOCK_BYTES};

pub(crate) const CONFIG_FILE: &str = "cairn.conf";

/// Every name this node understands.
///
/// An unknown name stops the node rather than being passed over. A setting
/// that is silently ignored is how an operator ends up running rules they did
/// not choose, which on a chain means following a different one.
const KNOWN: [&str; 10] = [
    "data", "listen", "seed", "network", "mine", "status", "run-for", "archive", "keep", "help",
];
const DEFAULT_DATA: &str = "cairn-data";
const DEFAULT_LISTEN: &str = "0.0.0.0:9944";

pub(crate) const HELP: &str = "\
cairnd, a Cairn node

  --data <directory>     where the chain and the address book are kept
                         (default: cairn-data)
  --listen <address>     address to accept connections on
                         (default: 0.0.0.0:9944)
  --seed <address>       a peer to start from; repeat for more. Without
                         one, the addresses written into the program for
                         this network are used, which is why a node that
                         was just downloaded finds the network on its own
  --network <name>       testnet-3 or devnet (default: testnet-3)
                         devnet has the same rules with a five second block
                         time and a tiny hot set, for one machine.
                         mainnet does not exist yet: a network exists once
                         its first block does, and that one will be mined in
                         the open on the day it is announced
  --mine <public key>    produce blocks, paying rewards to this key
  --archive              keep the cold set, so this node can rebuild a proof
                         for a wallet that lost its own. Costs a set that
                         grows; without it a node keeps sixty four hashes
  --keep <size|all>      how much of the chain to keep on disk, in bytes, or
                         `all` to keep every block ever accepted (default:
                         1GB). A node does not need old blocks: it keeps the
                         ledger they add up to, and the headers apart from
                         them. They are kept for other people, so a peer a
                         little behind can read them rather than being handed
                         a whole ledger. Accepts suffixes: 512MB, 8GB
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
    /// Whether those seeds were named by the operator or read off the list
    /// written into the program.
    pub(crate) seeds_asked_for: bool,
    pub(crate) params: ConsensusParams,
    pub(crate) mine_to: Option<PublicKey>,
    pub(crate) status_period: u64,
    /// Stops the node after this long. A node is meant to run until it is
    /// stopped; this exists so a test or a demonstration can bound it.
    pub(crate) run_for: Option<u64>,
    /// Whether to keep the cold set and be able to prove things about it.
    pub(crate) archive: bool,
    /// Bytes of blocks to keep on disk. `u64::MAX` keeps everything.
    pub(crate) keep: u64,
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

    let listen =
        seeds::resolve_one(&setting("listen").unwrap_or_else(|| DEFAULT_LISTEN.to_owned()))?;

    let name = setting("network").unwrap_or_else(|| "testnet".to_owned());
    // Every consensus rule comes from the name, and none of them can be set
    // one at a time. Two nodes that differ on any of them would build
    // different chains while believing they were on the same network.
    let params = ConsensusParams::for_network(&name).ok_or_else(|| {
        if name == "mainnet" {
            "mainnet does not exist yet: its first block has not been mined".to_owned()
        } else {
            format!("unknown network `{name}`, try testnet-3 or devnet")
        }
    })?;

    // After the network is settled, because a node given no seed starts from
    // the ones written into the program for the network it is on.
    let asked: Vec<String> = command_line
        .all("seed")
        .iter()
        .chain(config.all("seed"))
        .cloned()
        .collect();
    let seeds_asked_for = !asked.is_empty();
    let seeds = seeds::start_from(&asked, params.network)?;

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

    let keep = match setting("keep") {
        None => KEEP_BLOCK_BYTES,
        Some(text) => parse_size(&text)?,
    };

    Ok(Some(Options {
        data,
        listen,
        seeds,
        seeds_asked_for,
        params,
        mine_to,
        status_period,
        run_for,
        archive,
        keep,
    }))
}

/// Reads a size in bytes, with the suffixes an operator would reach for.
///
/// `all` is spelled out rather than being a number, because a node keeping
/// every block is a decision and not a large setting.
fn parse_size(text: &str) -> Result<u64, String> {
    let trimmed = text.trim();
    if trimmed.eq_ignore_ascii_case("all") {
        return Ok(u64::MAX);
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
        .map_err(|_| format!("`{text}` is not a size; try 1GB, 512MB, or all"))?;
    Ok(count.saturating_mul(scale))
}

/// A size as an operator would read it back.
fn size(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{} GB", bytes / 1_000_000_000)
    } else if bytes >= 1_000_000 {
        format!("{} MB", bytes / 1_000_000)
    } else {
        format!("{bytes} bytes")
    }
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
        let _ = writeln!(
            text,
            "seeds        none, and none written in for this network"
        );
    } else {
        if !options.seeds_asked_for {
            let _ = writeln!(text, "seeds        written into the program, none given");
        }
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
    let _ = writeln!(
        text,
        "blocks       {}",
        if options.keep == u64::MAX {
            "every one ever accepted".to_owned()
        } else {
            format!("{} on disk, older ones dropped", size(options.keep))
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
        assert_eq!(options.params.network_name(), "testnet-3");
        assert_eq!(options.params.target_block_time, 60);
        assert!(options.mine_to.is_none());
        // A program somebody just downloaded finds the network on its own,
        // because it starts from the list written in for the network it chose.
        // Whether that list resolves is a question for a name server rather
        // than for a test, so what is held here is that nothing was asked for
        // and that there is something to fall back on.
        assert!(
            !options.seeds_asked_for,
            "no seed was named on the command line"
        );
        assert!(
            !seeds::written_in(options.params.network).is_empty(),
            "and the network it chose has somewhere to start"
        );
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

        let options = resolve_options(&args(&["--data", &data, "--network", "testnet-3"]))
            .unwrap()
            .unwrap();
        assert_eq!(
            options.params.network_name(),
            "testnet-3",
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

    #[test]
    fn a_size_is_read_the_way_an_operator_writes_one() {
        assert_eq!(parse_size("all").unwrap(), u64::MAX);
        assert_eq!(parse_size("ALL").unwrap(), u64::MAX);
        assert_eq!(parse_size("1GB").unwrap(), 1_000_000_000);
        assert_eq!(parse_size("512mb").unwrap(), 512_000_000);
        assert_eq!(parse_size(" 4 kb ").unwrap(), 4_000);
        assert_eq!(parse_size("2048").unwrap(), 2_048);
        assert!(parse_size("plenty").is_err());
        assert!(parse_size("").is_err());
    }

    /// A node that says nothing must not sign up for a disk that grows with
    /// the chain, which is the one thing this design exists not to do.
    #[test]
    fn how_much_of_the_chain_to_keep_has_a_default_and_can_be_set() {
        let options = resolve_options(&args(&[])).unwrap().unwrap();
        assert_eq!(options.keep, KEEP_BLOCK_BYTES);

        let options = resolve_options(&args(&["--keep", "all"])).unwrap().unwrap();
        assert_eq!(options.keep, u64::MAX, "and can be told to keep the lot");

        let options = resolve_options(&args(&["--archive"])).unwrap().unwrap();
        assert_eq!(
            options.keep, KEEP_BLOCK_BYTES,
            "archiving is about headers and fallen notes, not about blocks"
        );
    }
}

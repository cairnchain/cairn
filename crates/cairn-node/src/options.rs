//! Reading what the operator asked for.
//!
//! Settings come from the command line, and from a `cairn.conf` in the data
//! directory holding the same names as `key = value`. The command line wins,
//! so a running configuration can be overridden without editing a file.
//!
//! Parsed by hand rather than by a library: the whole surface is eight
//! settings, and a node people are asked to audit is better off without an
//! argument parser in its dependency tree.

use crate::Stopping;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use cairn_crypto::PublicKey;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::{seeds, KEEP_BLOCK_BYTES, NAME_LOOKUP_PERIOD};

pub(crate) const CONFIG_FILE: &str = "cairn.conf";

/// Every name this node understands.
///
/// An unknown name stops the node rather than being passed over. A setting
/// that is silently ignored is how an operator ends up running rules they did
/// not choose, which on a chain means following a different one.
const KNOWN: [&str; 11] = [
    "data", "listen", "seed", "network", "mine", "status", "run-for", "archive", "keep", "help",
    "check",
];

/// Names that are the command line's alone, and what to say when one turns up
/// in the file.
///
/// The rule above was applied to names this node does not understand and not
/// to names it understands and then never reads. `resolve_options` takes these
/// three from `command_line` and only from there, so a file carrying one was
/// validated, filed, and dropped without a word. `data = /mnt/chain` ran on
/// `cairn-data`; `check = yes` started a node, bound a port and wrote a
/// directory, which is the one thing `--check` exists so an operator can avoid.
///
/// Refused rather than honoured, because none of the three is a setting. `data`
/// cannot be one: it says where the file this line is in was looked for.
/// `help` and `check` are questions put to the program, answered once and not
/// carried from one run to the next.
const ONLY_ON_THE_COMMAND_LINE: [(&str, &str); 4] = [
    (
        "data",
        "names the directory this file was found in, so setting it here cannot \
         mean anything. Pass --data on the command line.",
    ),
    (
        "help",
        "is a question put to the program, not a setting. Pass --help on the \
         command line.",
    ),
    (
        "check",
        "asks what this node would do without starting one, which is a question \
         about a single run. Pass --check on the command line.",
    ),
    (
        "run-for",
        "stops the node after a while, which is a question about a single run \
         and not a setting a machine should carry across reboots. In a file it \
         is a node that goes down on its own and comes back under whatever \
         restarts it, for ever, and exits nought on the way out so nothing \
         reports a fault. Pass --run-for on the command line.",
    ),
];
const DEFAULT_DATA: &str = "cairn-data";

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
  --network <name>       testnet-6 or devnet (default: testnet-6)
                         devnet has the same rules with a five second block
                         time and a tiny hot set, for one machine.
                         mainnet does not exist yet: a network exists once
                         its first block does, and that one will be mined in
                         the open on the day it is announced
  --check                work out what this node would do and print it,
                         then stop without starting anything. Exits with an
                         error if a setting is one this build does not
                         accept, which is how a script can find out that a
                         network it was told to use has been retired
  --mine <public key>    produce blocks, paying rewards to this key
  --archive              keep the cold set, so this node can answer a wallet
                         that asks where one of its put-away notes sits and
                         cannot work it out for itself. Says so on the
                         handshake, so wallets can find this node. Costs a set
                         that grows with every note ever spent; without it a
                         node keeps sixty four hashes
  --keep <size|all>      how much of the chain to keep on disk, in bytes, or
                         `all` to keep every block ever accepted (default:
                         1GB). A node does not need old blocks: it keeps the
                         ledger they add up to, and the headers apart from
                         them. They are kept for other people, so a peer a
                         little behind can read them rather than being handed
                         a whole ledger. Accepts suffixes: 512MB, 8GB.
                         There is a floor under it that this setting cannot
                         lower: the blocks a reorganisation may still have to
                         read back are never dropped, however small a size is
                         asked for. `--check` prints what that floor comes to
                         on the chosen network
  --status <seconds>     how often to print a status line (default: 10)
  --run-for <seconds>    stop after this long, for tests and demonstrations.
                         The command line only: a node that stops itself on
                         every start is not a setting a machine should carry
                         across reboots
  --help                 print this and stop

The same names work in <data>/cairn.conf as `key = value`, apart from the four
that are questions about one run rather than settings: data, help, check and
run-for. The command line wins over the file.";

/// Everything a node needs to start.
#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub(crate) data: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) seeds: Vec<SocketAddr>,
    /// The names those addresses came from, kept so the node can ask again if
    /// none of them resolved at the moment it started.
    pub(crate) seed_names: Vec<String>,
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
    /// Print what this node would do and start nothing.
    ///
    /// A setting like every other one here, and read off the settings. It used
    /// to be found by looking through the words the operator typed for one
    /// that read `--check`, which finds it in the one place it is not: standing
    /// where another option's value belongs. `--data --check` then started a
    /// node in a directory called `--check`, or rather printed the settings,
    /// stopped, and exited nought without ever starting one. The explorer was
    /// mended for this and the node was not.
    pub(crate) check: bool,
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

    /// A yes or a no written in the file, or nothing where the setting is not
    /// there at all.
    ///
    /// On a command line `--archive` is the whole of what it says, so its
    /// presence is the answer. A file does not work that way: a file says
    /// `name = value`, and the value is the answer. Asking `has` of a file
    /// asks whether the word appeared, so `archive = no` turned archiving on
    /// and said nothing about it, which costs the operator a set that grows
    /// with every note ever spent for the rest of the node's life.
    ///
    /// Anything that is neither refuses the start rather than being guessed
    /// at, under the rule this file states above [`KNOWN`]: a setting silently
    /// ignored is how an operator ends up running rules they did not choose.
    fn says_yes(&self, name: &str, where_from: &str) -> Result<bool, String> {
        let Some(value) = self.first(name) else {
            return Ok(false);
        };
        match value.trim().to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" | "1" => Ok(true),
            "no" | "false" | "off" | "0" => Ok(false),
            other => Err(format!(
                "`{name} = {other}` {where_from} is neither yes nor no. Write `{name} = yes` \
                 or `{name} = no`."
            )),
        }
    }

    /// Refuses a setting given twice with two different values.
    ///
    /// The rule this file states above [`KNOWN`] is that a setting silently
    /// ignored is how an operator ends up running rules they did not choose,
    /// and on a chain that means following a different one. It was applied to
    /// a name this node does not know and not to a name it knows given twice,
    /// where exactly the same thing happens and the example in that sentence
    /// is the one it happens to: `--network devnet --network testnet-6` ran on
    /// devnet and said nothing about the other.
    ///
    /// Given twice with the same value, nothing is dropped and nothing is
    /// said. `seed` is a list rather than a setting and every one of them is
    /// used, so it is not asked about here.
    ///
    /// Asked of the command line and of the file separately, because the
    /// command line winning over the file is the rule and not a collision.
    fn one_value_each(&self, where_from: &str) -> Result<(), String> {
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
                "`{name}` is given twice {where_from}, as `{first}` and as `{other}`, and only \
                 the first would ever be used. Say which one you mean."
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

        if name == "help" || name == "archive" || name == "check" {
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
        if let Some((_, why)) = ONLY_ON_THE_COMMAND_LINE
            .iter()
            .find(|(only, _)| *only == name)
        {
            return Err(format!("`{name}` in {CONFIG_FILE} {why}"));
        }
        given.push(name, value.trim().to_owned());
    }
    Ok(given)
}

/// Reads the configuration file, and says nothing only when there is none.
///
/// No file is the ordinary case: a node that was never configured runs on its
/// defaults. A file that is there and cannot be read is the opposite case, and
/// treating the two alike is how an operator ends up watching a node report for
/// duty on settings it never saw. That is the same failure an unknown setting
/// name is refused for, one level up.
fn read_config(path: &std::path::Path) -> Result<String, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(format!(
            "{} is there and could not be read: {error}",
            path.display()
        )),
    }
}

/// Reads the command line, then the configuration file the command line points
/// at, and settles every setting.
pub(crate) fn resolve_options(arguments: &[String]) -> Result<Option<Options>, Stopping> {
    let misread = Stopping::Misread;
    let command_line = parse_arguments(arguments).map_err(misread)?;
    if command_line.has("help") {
        return Ok(None);
    }

    command_line
        .one_value_each("on the command line")
        .map_err(misread)?;

    let data = PathBuf::from(command_line.first("data").unwrap_or(DEFAULT_DATA));
    // Not a misreading. The file is there and the disk will not give it back,
    // which is the one thing the two arms of `read_config` exist to tell
    // apart, and it is about this moment rather than about anything typed.
    let file = read_config(&data.join(CONFIG_FILE)).map_err(Stopping::CouldNotStart)?;
    let config = parse_config(&file).map_err(misread)?;
    config
        .one_value_each(&format!("in {CONFIG_FILE}"))
        .map_err(misread)?;

    let setting = |name: &str| -> Option<String> {
        command_line
            .first(name)
            .or_else(|| config.first(name))
            .map(str::to_owned)
    };

    // Nor is this. A name that did not resolve at this instant is a resolver
    // that was not answering yet, which clears by itself, and telling an
    // operator to check what they typed sends them looking for nothing.
    // The default is built from `seeds::DEFAULT_PORT` rather than resolved
    // from a string. It was `"0.0.0.0:9944"` written here, which is a copy of
    // that constant, and the constant's own doc calls itself "the default port
    // a node listens on" while nothing read it: move it and this node went on
    // listening where the literal said.
    let listen = match setting("listen") {
        Some(text) => seeds::resolve_one(&text).map_err(Stopping::CouldNotStart)?,
        None => SocketAddr::from((Ipv4Addr::UNSPECIFIED, seeds::DEFAULT_PORT)),
    };

    let name = setting("network").unwrap_or_else(|| "testnet".to_owned());
    // Every consensus rule comes from the name, and none of them can be set
    // one at a time. Two nodes that differ on any of them would build
    // different chains while believing they were on the same network.
    let params = ConsensusParams::for_network(&name)
        .ok_or_else(|| {
            if name == "mainnet" {
                "mainnet does not exist yet: its first block has not been mined".to_owned()
            } else {
                format!("unknown network `{name}`, try testnet-6 or devnet")
            }
        })
        .map_err(misread)?;

    // After the network is settled, because a node given no seed starts from
    // the ones written into the program for the network it is on.
    let asked: Vec<String> = command_line
        .all("seed")
        .iter()
        .chain(config.all("seed"))
        .cloned()
        .collect();
    let seeds_asked_for = !asked.is_empty();
    let seed_names = seeds::names_for(&asked, params.network);
    // And nor is a seed the operator named whose name did not resolve. This is
    // the one a machine booting ahead of its resolver meets: without it the
    // node retries by itself, and with it the unit spends its five starts in
    // twenty five seconds and stays down.
    let seeds = seeds::start_from(&asked, params.network).map_err(Stopping::CouldNotStart)?;

    let mine_to = match setting("mine") {
        None => None,
        Some(text) => Some(parse_key(&text).map_err(misread)?),
    };

    let status_period = match setting("status") {
        None => 10,
        Some(text) => text
            .parse()
            .map_err(|_| misread(format!("`{text}` is not a number of seconds")))?,
    };

    let run_for = match setting("run-for") {
        None => None,
        Some(text) => Some(
            text.parse()
                .map_err(|_| misread(format!("`{text}` is not a number of seconds")))?,
        ),
    };

    // The command line carries the word alone and the file carries a value, so
    // the two are asked different questions. Asking the file whether the word
    // appeared made `archive = no` an instruction to archive.
    let archive = command_line.has("archive")
        || config
            .says_yes("archive", &format!("in {CONFIG_FILE}"))
            .map_err(misread)?;

    let keep = match setting("keep") {
        None => KEEP_BLOCK_BYTES,
        Some(text) => parse_size(&text).map_err(misread)?,
    };

    Ok(Some(Options {
        data,
        listen,
        seeds,
        seed_names,
        seeds_asked_for,
        params,
        mine_to,
        status_period,
        run_for,
        archive,
        keep,
        check: command_line.has("check"),
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
pub(crate) fn size(bytes: u64) -> String {
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
        if options.seed_names.is_empty() {
            let _ = writeln!(
                text,
                "seeds        none, and none written in for this network"
            );
        } else {
            // Not "none written in". The difference between having nowhere to
            // start and having somewhere this machine could not look up is the
            // whole diagnosis, and printing the first for the second sends an
            // operator reading source code instead of checking a resolver.
            let _ = writeln!(
                text,
                "seeds        {} did not resolve; asking again every {NAME_LOOKUP_PERIOD}s",
                options.seed_names.join(", ")
            );
        }
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
            "the whole cold set (archivist: this node answers wallets that \
             have lost their own path to a put-away note)"
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
    // The floor under that figure, said wherever the figure is said. The
    // budget is a preference and this is not: the chain lets go of block
    // bodies from memory in the belief the log still holds them, so the last
    // `burial` blocks are not the operator's to drop, and the trim never cuts
    // into them however small a size was asked for. Nothing stated it and
    // nothing reported it, so `--keep 1MB` printed "1 MB on disk, older ones
    // dropped" and held a hundred and twenty eight times that.
    if options.keep != u64::MAX {
        let _ = writeln!(
            text,
            "             never below the last {} blocks, whatever they weigh: \
             up to {} on this network",
            options.params.burial,
            // Read off the rules rather than worked out here, so the explorer,
            // which trims through the same node, states the same floor.
            size(options.params.burial_bytes()),
        );
        // And what dropping them costs somebody else, which is the half an
        // operator has no other way to learn. There are two ways onto this
        // chain: being handed a ledger, which needs headers and no body at
        // all, and reading it block by block, which needs every body. The
        // first is refused on a chain whose difficulty has fallen far enough,
        // and on that day the second is the only way in and it runs on blocks
        // that nobody is obliged to have kept. A node at any budget serves
        // newcomers perfectly well until then.
        let _ = writeln!(
            text,
            "             what is dropped cannot be served: a newcomer that \
             cannot be handed a ledger reads the chain block by block, from \
             whoever kept the blocks"
        );
    }
    match options.mine_to {
        Some(key) => {
            let _ = writeln!(text, "mining       rewards to {key}");
        }
        None => {
            let _ = writeln!(text, "mining       off");
        }
    }
    let _ = writeln!(text, "status       every {}s", options.status_period);
    // The one setting on this list that ends the run, and the summary went to
    // the end without mentioning it. An operator checking what their node
    // would do was shown everything except the thing that stops it.
    match options.run_for {
        Some(seconds) => {
            let _ = writeln!(
                text,
                "run-for      stops after {seconds}s and exits nought, which is not a fault \
                 anything downstream will report"
            );
        }
        None => {
            let _ = writeln!(text, "run-for      not set: runs until it is stopped");
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
        assert_eq!(options.params.network_name(), "testnet-6");
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

    /// The help quotes the address a node listens on without being told, and
    /// it is the address a node listens on without being told.
    ///
    /// Two places the port is written: `seeds::DEFAULT_PORT`, which the
    /// default is now built from, and this sentence, which has to be prose.
    /// Held together here, because the sentence is what an operator reads
    /// before deciding whether to open a firewall.
    #[test]
    fn the_help_quotes_the_address_a_node_actually_listens_on() {
        let listen = resolve_options(&args(&[]))
            .unwrap()
            .expect("no arguments still gives a configuration")
            .listen;
        assert_eq!(
            listen.port(),
            cairn_net::seeds::DEFAULT_PORT,
            "the default follows the constant"
        );
        assert!(
            HELP.contains(&listen.to_string()),
            "the help says something other than {listen}"
        );
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

    /// A file writes `key = value`, so the value is the answer.
    ///
    /// `has` asks whether the word appeared, which is the right question for a
    /// command line where `--archive` is the whole of what it says and the
    /// wrong one for a file. `archive = no` turned archiving on and said
    /// nothing, which costs the operator a set that grows with every note ever
    /// spent, for the life of the node.
    #[test]
    fn a_no_in_the_file_is_a_no() {
        let said = |line: &str| -> Result<bool, ()> {
            let directory = std::env::temp_dir().join(format!(
                "cairn-archive-{}-{}",
                std::process::id(),
                line.replace(['=', ' ', '\n'], "")
            ));
            let _ = std::fs::remove_dir_all(&directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(CONFIG_FILE), line).unwrap();
            let data = directory.to_string_lossy().to_string();
            let answer = resolve_options(&args(&["--data", &data]));
            let _ = std::fs::remove_dir_all(&directory);
            match answer {
                Ok(Some(options)) => Ok(options.archive),
                _ => Err(()),
            }
        };

        assert_eq!(said("archive = no\n"), Ok(false), "a no is a no");
        assert_eq!(said("archive = yes\n"), Ok(true));
        assert_eq!(said("archive = off\n"), Ok(false));
        assert_eq!(said("archive = true\n"), Ok(true));
        assert_eq!(said("\n"), Ok(false), "and unwritten is a no");
        assert_eq!(
            said("archive = maybe\n"),
            Err(()),
            "anything else refuses the start rather than being guessed at"
        );
    }

    /// `run-for` stops the node, so it is a question about one run.
    ///
    /// Left in the file it is a node that goes down on its own and comes back
    /// under whatever restarts it, for ever, exiting nought on the way out so
    /// nothing downstream reports a fault. `--check` never mentioned it
    /// either, so an operator asking what their node would do was shown
    /// everything except the thing that stops it.
    #[test]
    fn a_run_for_in_the_file_is_refused_and_a_summary_says_what_stops_the_node() {
        let directory = std::env::temp_dir().join(format!("cairn-runfor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(CONFIG_FILE), "run-for = 300\n").unwrap();
        let data = directory.to_string_lossy().to_string();

        let error = resolve_options(&args(&["--data", &data])).unwrap_err();
        let said = format!("{error:?}");
        assert!(
            said.contains("run-for"),
            "a node that stops itself every five minutes started without a word: {said}"
        );
        let _ = std::fs::remove_dir_all(&directory);

        let options = resolve_options(&args(&["--run-for", "300", "--status", "7"]))
            .unwrap()
            .unwrap();
        let summary = describe(&options);
        assert!(
            summary.contains("300"),
            "the summary went to the end without mentioning what stops the node: {summary}"
        );
        assert!(
            summary.contains("every 7s"),
            "nor how often it speaks: {summary}"
        );

        let quiet = resolve_options(&args(&[])).unwrap().unwrap();
        let summary = describe(&quiet);
        assert!(
            summary.contains("runs until it is stopped"),
            "and a node with no deadline says so, rather than leaving a reader to \
             notice a missing line: {summary}"
        );
    }

    /// Asking for mainnet is told that mainnet does not exist yet, and asking
    /// for a name nobody uses is told the name is unknown.
    ///
    /// Both were only held to be refusals, so a node that told the operator
    /// asking for mainnet that it had never heard of it, and told everyone
    /// else that mainnet has not been mined yet, passed.
    #[test]
    fn a_refused_network_is_told_why_it_was_refused() {
        let said = |name: &str| -> String {
            match resolve_options(&args(&["--network", name])) {
                Err(Stopping::Misread(said)) => said,
                Err(Stopping::CouldNotStart(said)) => format!("a failed start: {said}"),
                Ok(_) => "accepted".to_owned(),
            }
        };
        assert!(
            matches!(
                resolve_options(&args(&["--network", "mainnet"])),
                Err(Stopping::Misread(_))
            ),
            "a network name is a misread command line, not a failed start"
        );
        let mainnet = said("mainnet");
        assert!(
            mainnet.contains("does not exist yet"),
            "mainnet is not called an unknown name: {mainnet}"
        );
        let moonnet = said("moonnet");
        assert!(
            moonnet.contains("unknown network `moonnet`"),
            "a name nobody uses is called unknown: {moonnet}"
        );
        assert!(
            !moonnet.contains("does not exist yet"),
            "and is not told it has yet to be mined: {moonnet}"
        );
    }

    /// The summary says the seeds were written into the program only when
    /// nobody named any.
    ///
    /// Nothing read that line, so a summary that said "written into the
    /// program, none given" above the seeds an operator typed, and said
    /// nothing about where a node given none got its seeds from, passed.
    #[test]
    fn the_summary_says_where_the_seeds_came_from() {
        let mut options = resolve_options(&args(&["--seed", "127.0.0.1:1111"]))
            .unwrap()
            .unwrap();
        let summary = describe(&options);
        assert!(
            summary.contains("seed         127.0.0.1:1111"),
            "the seed named is listed: {summary}"
        );
        assert!(
            !summary.contains("written into the program"),
            "a seed the operator named is not called one written in: {summary}"
        );

        // The same addresses as a node that was given none would have them,
        // off the list written in for its network.
        options.seeds_asked_for = false;
        let summary = describe(&options);
        assert!(
            summary.contains("seeds        written into the program, none given"),
            "a node given no seed says where its seeds came from: {summary}"
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

        let options = resolve_options(&args(&["--data", &data, "--network", "testnet-6"]))
            .unwrap()
            .unwrap();
        assert_eq!(
            options.params.network_name(),
            "testnet-6",
            "the command line wins"
        );
    }

    /// The failure this exists for is silent: a node that starts, prints a
    /// summary, and follows rules the operator wrote down and never saw
    /// applied. A directory standing in for the file is used because it is
    /// unreadable for everybody, including whoever runs the tests as root.
    #[test]
    fn a_config_that_cannot_be_read_is_not_an_empty_one() {
        let directory =
            std::env::temp_dir().join(format!("cairn-unreadable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(directory.join(CONFIG_FILE)).unwrap();
        let data = directory.to_string_lossy().to_string();

        // And it is a node that could not start rather than a command line
        // that was misread, which is what decides whether whoever started this
        // node is shown the usage text and told to look for a typo. The file
        // being there and unreadable is about this disk at this moment.
        let error = resolve_options(&args(&["--data", &data])).unwrap_err();
        let said = match error {
            Stopping::CouldNotStart(said) => said,
            Stopping::Misread(said) => unreachable!(
                "a file the disk will not give back is not a misread command line: {said}"
            ),
        };
        assert!(
            said.contains(CONFIG_FILE),
            "the operator is told which file: {said}"
        );

        // Nothing there at all is the ordinary case, and carries on.
        std::fs::remove_dir(directory.join(CONFIG_FILE)).unwrap();
        assert!(resolve_options(&args(&["--data", &data])).is_ok());
        let _ = std::fs::remove_dir_all(&directory);
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

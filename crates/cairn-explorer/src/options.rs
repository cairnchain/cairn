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
  --keep <size|all>      read, and not a budget: an explorer keeps every
                         block whatever this says. A plain node keeps a
                         gigabyte and drops the oldest blocks past it,
                         because it does not need them: it has the ledger
                         they add up to. An explorer keeps the cold set,
                         which is built by reading every block from the
                         first at every start, and a directory whose blocks
                         do not begin at the first cannot build it, so the
                         explorer would not start there again. A size is
                         still read, so one that is not a size stops it.
                         Accepts suffixes: 512MB, 8GB
  --check                work out what this explorer would do and print it,
                         then stop without starting anything. Exits with an
                         error if a setting is one this build does not
                         accept, which is how a script can find out that a
                         network it was told to use has been retired
  --network <name>       testnet-7 or devnet (default: testnet-7)
  --help                 print this and stop

The explorer always keeps the cold set, because answering questions about
notes that have fallen is the whole point of it. That is a cost which grows
with the chain, which is exactly what a plain node refuses to carry. The
index it builds on top grows faster still: 627 bytes for every note that has
ever existed, against 104 for every note that has fallen and not been
spent. Both are reported live at /api/status.";

/// Everything the explorer needs to start.
#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub(crate) data: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) http: SocketAddr,
    /// What the seeds the operator named resolve to, and nothing when none
    /// was named: the ones written into the program are looked up at the
    /// start, and only when the node's own book cannot supply a peer.
    pub(crate) seeds: Vec<SocketAddr>,
    /// The names to start from, named or written in, kept so the node can ask
    /// again when its book has nobody to dial.
    pub(crate) seed_names: Vec<String>,
    /// Whether any seed was named, rather than read off the list written into
    /// the program.
    pub(crate) seeds_asked_for: bool,
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
    /// so `--network devnet --network testnet-7` ran on devnet and said nothing
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
            format!("unknown network `{name}`, try testnet-7 or devnet")
        }
    })?;

    // After the network is settled: an explorer given no seed starts from the
    // ones written into the program, like every other node. Only a seed named
    // is looked up here; the list written in is a question to whoever answers
    // for it, asked at the start and only when the node's own book cannot
    // supply a peer, as `cairnd` does.
    let seed_names = seeds::names_for(given.all("seed"), params.network);
    let seeds_asked_for = !given.all("seed").is_empty();
    let seeds = if seeds_asked_for {
        seeds::start_from(given.all("seed"), params.network)?
    } else {
        Vec::new()
    };

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
        seeds_asked_for,
        params,
        keep,
        check: given.has("check"),
    }))
}

/// What an explorer keeps, whatever it is told: all of it.
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
///
/// And its node archives, which settles it: the archive is built from every
/// block at every start, so an archiving node keeps them all whatever budget
/// it is handed (`Node::keep_blocks`). `--keep` below `all` was handed
/// through, trimmed, and left an explorer that could not start again.
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

/// What this explorer keeps on disk, as its start says it: every block, and
/// under a budget, that the budget is not one.
///
/// It printed the budget, with the floor the trim never cuts into under it,
/// and handed the budget to its node, which trimmed to it; the next start was
/// refused, since an archive is built from every block. The node keeps every
/// block now whatever it is handed, and this says that rather than a figure
/// nothing holds to.
pub(crate) fn kept(keep: u64) -> String {
    if keep == KEEP_EVERYTHING {
        return EVERY_BLOCK.to_owned();
    }
    format!(
        "{EVERY_BLOCK}, whatever --keep says\n             an explorer keeps the cold set, \
         built by reading every block from the first at every start, so {} is not a budget here",
        in_units(keep),
    )
}

/// What an explorer keeps, said the way its start says it.
const EVERY_BLOCK: &str = "every one ever accepted";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{kept, parse_arguments, resolve_options, HELP, KEEP_EVERYTHING};

    /// Under a budget the explorer says it keeps every block all the same, and
    /// that the budget is not one; keeping everything it says only that.
    ///
    /// It printed the budget, and the floor under it, as what it kept, and
    /// handed the budget to its node, which trimmed to it and was refused at
    /// the next start: an archive is built from every block. Nothing asked
    /// whether the line was true, so a line naming a size the node was about
    /// to trim to passed.
    #[test]
    fn a_budget_is_said_to_be_no_budget_for_an_explorer() {
        let said = kept(1_000_000);
        assert!(
            said.starts_with("every one ever accepted, whatever --keep says\n"),
            "an explorer given a budget does not say first that it keeps every block: {said}"
        );
        assert!(
            said.contains("so 1 MB is not a budget here"),
            "and does not say the budget it was given is not one: {said}"
        );
        assert!(
            !said.contains("dropped") && !said.contains("never below"),
            "an explorer given a budget says it drops blocks: {said}"
        );
        assert_eq!(
            kept(KEEP_EVERYTHING),
            "every one ever accepted",
            "an explorer given no budget speaks of one"
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
    /// the node's. A size given is still read, and one that is not a size
    /// stops the program, though the explorer keeps every block whatever it
    /// says: see `kept`.
    #[test]
    fn the_keep_setting_is_read_and_is_every_block_unless_given() {
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
    /// a word. Nothing asked this, so `--network devnet --network testnet-7`
    /// started an explorer on devnet that said nothing about the other name it
    /// was given, and so did a `--keep` given twice.
    #[test]
    fn a_setting_given_twice_as_two_values_stops_the_program() {
        let error = resolve_options(&arguments(&[
            "--network",
            "devnet",
            "--network",
            "testnet-7",
        ]))
        .unwrap_err();
        assert!(
            error.contains("given twice"),
            "a network named twice was taken as the first: {error}"
        );
        assert!(
            error.contains("devnet") && error.contains("testnet-7"),
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

    /// The seeds written into the program are not looked up when the settings
    /// are read, and a seed the operator named is.
    ///
    /// The explorer looked the list up at every start, whatever its node's own
    /// book held, as `cairnd` did. Nothing asked, so settings that looked the
    /// list up passed.
    #[test]
    fn the_written_in_seeds_are_not_looked_up_when_the_settings_are_read() {
        let options = resolve_options(&arguments(&[])).unwrap().unwrap();
        assert!(
            options.seeds.is_empty() && !options.seeds_asked_for,
            "the seeds written into the program were looked up with the settings"
        );
        assert!(
            !options.seed_names.is_empty(),
            "and their names are not kept for the start to ask with"
        );
        let named = resolve_options(&arguments(&["--seed", "127.0.0.1:1111"]))
            .unwrap()
            .unwrap();
        assert!(
            named.seeds_asked_for && named.seeds.len() == 1,
            "a seed the operator named was not read with the settings"
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

//! A Cairn wallet.
//!
//! The wallet is a node. It does not ask a server what it owns; it joins the
//! network, verifies the chain itself, and reads its own balance out of the
//! ledger it validated. That is the whole point of a chain whose state fits on
//! ordinary hardware, so it would be strange to build the wallet any other way.

use std::collections::BTreeMap;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::Amount;
use cairn_wallet::{keyfile, serve, Wallet};

const HELP: &str = "\
cairn-wallet, a Cairn wallet that is itself a node

  cairn-wallet new <key file>
      make a key and write it down

  cairn-wallet address <key file>
      print the public key to be paid at

  cairn-wallet balance <key file> [network options]
      join the network, verify the chain, and add up what this key holds

  cairn-wallet send <key file> --to <public key> --amount <cairn> [options]
      spend, and hand the transfer to the network

  cairn-wallet open <key file> [network options]
      open the wallet as a page on this machine, and print its address

Network options

  --data <directory>   where this wallet keeps its copy of the chain
                       (default: cairn-wallet-data, and it must not be the
                       same directory a node is using)
  --seed <address>     a peer to start from; repeat for more
  --network <name>     testnet-3 or devnet (default: testnet-3); it has to
                       be the same network the node is on
  --wait <seconds>     how long to spend catching up (default: 30)
  --fee <cairn>        what to pay to be carried (default: 0)

Options for `open`

  --port <number>      port to serve the page on (default: one the system
                       picks). It is served on 127.0.0.1 and nowhere else,
                       and the address carries a secret without which the
                       wallet answers nothing.";

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Err(message) = run(&arguments) {
        eprintln!("cairn-wallet: {message}");
        std::process::exit(2);
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
    let Some(command) = arguments.first() else {
        println!("{HELP}");
        return Ok(());
    };
    let rest = arguments.get(1..).unwrap_or_default();

    match command.as_str() {
        "help" | "--help" => {
            println!("{HELP}");
            Ok(())
        }
        "new" => make_key(rest),
        "address" => show_address(rest),
        "balance" => show_balance(rest),
        "send" => spend(rest),
        "open" => open_page(rest),
        other => Err(format!("unknown command `{other}`; try `help`")),
    }
}

/// A command line split into what came before the options and what came after.
#[derive(Debug, Default)]
struct Flags {
    loose: Vec<String>,
    named: BTreeMap<String, Vec<String>>,
}

impl Flags {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut flags = Self::default();
        let mut index = 0usize;
        while let Some(argument) = arguments.get(index) {
            index = index.saturating_add(1);
            let Some(name) = argument.strip_prefix("--") else {
                flags.loose.push(argument.clone());
                continue;
            };
            let Some(value) = arguments.get(index) else {
                return Err(format!("`--{name}` needs a value"));
            };
            index = index.saturating_add(1);
            flags
                .named
                .entry(name.to_owned())
                .or_default()
                .push(value.clone());
        }
        Ok(flags)
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.named
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    fn values(&self, name: &str) -> &[String] {
        self.named.get(name).map_or(&[], Vec::as_slice)
    }

    fn key_file(&self) -> Result<PathBuf, String> {
        self.loose
            .first()
            .map(PathBuf::from)
            .ok_or_else(|| "which key file? give its path".to_owned())
    }
}

fn make_key(arguments: &[String]) -> Result<(), String> {
    let flags = Flags::parse(arguments)?;
    let path = flags.key_file()?;

    let secret = SecretKey::generate().map_err(|error| format!("no entropy available: {error}"))?;
    keyfile::write(&path, &secret)?;

    println!("key written to {}", path.display());
    println!("address        {}", secret.public_key());
    println!();
    println!("That file is the only copy. Anyone holding it holds the money.");
    Ok(())
}

fn show_address(arguments: &[String]) -> Result<(), String> {
    let flags = Flags::parse(arguments)?;
    let secret = keyfile::read(&flags.key_file()?)?;
    println!("{}", secret.public_key());
    Ok(())
}

fn show_balance(arguments: &[String]) -> Result<(), String> {
    let flags = Flags::parse(arguments)?;
    let wallet = join(&flags)?;
    let holdings = wallet.holdings();
    let fallen = holdings.notes.iter().filter(|held| held.is_cold()).count();

    println!();
    println!("address   {}", wallet.address());
    println!(
        "height    {}",
        wallet
            .progress()
            .height
            .map_or_else(|| "-".to_owned(), |h| h.to_string())
    );
    println!(
        "notes     {} ({fallen} of them fallen to the cold set)",
        holdings.notes.len()
    );
    println!("balance   {}", holdings.spendable);
    if holdings.stranded > Amount::ZERO {
        println!();
        println!(
            "Another {} sits in notes this node cannot prove. They are",
            holdings.stranded
        );
        println!("yours and they are not lost, but spending one takes a proof, and");
        println!("rebuilding a proof takes an archivist. Ask one, or run this wallet");
        println!("against a node started with --archive.");
    }
    if holdings.notes.is_empty() {
        println!();
        println!("Nothing here yet. If this key should hold something, check that the");
        println!("wallet reached a peer and caught up to the height you expect.");
    }
    wallet.shutdown();
    Ok(())
}

fn spend(arguments: &[String]) -> Result<(), String> {
    let flags = Flags::parse(arguments)?;

    let recipient = flags
        .value("to")
        .ok_or_else(|| "who is being paid? use --to".to_owned())?;
    let recipient = parse_key(recipient)?;
    let amount = flags
        .value("amount")
        .ok_or_else(|| "how much? use --amount".to_owned())?;
    let amount = Amount::from_cairn(amount)
        .ok_or_else(|| format!("`{amount}` is not an amount of CAIRN"))?;
    let fee = match flags.value("fee") {
        None => Amount::ZERO,
        Some(text) => {
            Amount::from_cairn(text).ok_or_else(|| format!("`{text}` is not an amount"))?
        }
    };

    let wallet = join(&flags)?;
    let sent = wallet.send(recipient, amount, fee).map_err(|error| {
        wallet.shutdown();
        error.to_string()
    })?;

    println!();
    println!("sending   {} to {recipient}", sent.amount);
    println!("fee       {}", sent.fee);
    println!("change    {}", sent.change);
    println!(
        "from      {} note(s), {} of them out of the cold set",
        sent.notes, sent.from_cold
    );
    println!("transfer  {}", sent.id);
    wallet.shutdown();

    println!();
    if sent.handed_on {
        println!("Handed to the network. It is spent once a block carries it, and settled");
        println!("once enough work is piled on top of that block.");
    } else {
        println!("No peer took it: this wallet reached nobody. It is not spent.");
    }
    Ok(())
}

fn rules_of(flags: &Flags) -> Result<ConsensusParams, String> {
    let name = flags.value("network").unwrap_or("testnet-3");
    ConsensusParams::for_network(name).ok_or_else(|| {
        if name == "mainnet" {
            "mainnet does not exist yet: its first block has not been mined".to_owned()
        } else {
            format!("unknown network `{name}`, try testnet-3 or devnet")
        }
    })
}

/// Starts this wallet's own node and gives it time to catch up.
///
/// The node is told which owner to watch before it replays anything, because
/// where a note falls is learned as it falls. That is what lets this wallet
/// spend from the cold set without asking an archivist for anything.
/// Serves the wallet as a page on this machine, until it is stopped.
fn open_page(arguments: &[String]) -> Result<(), String> {
    let flags = Flags::parse(arguments)?;
    let port: u16 = match flags.value("port") {
        None => 0,
        Some(text) => text
            .parse()
            .map_err(|_| format!("`{text}` is not a port"))?,
    };

    let wallet = Arc::new(join(&flags)?);
    let (listener, opened) = serve::open(port)?;
    let opened = Arc::new(opened);
    let running = Arc::new(AtomicBool::new(true));

    println!();
    println!("address   {}", wallet.address());
    println!("open      {}", opened.url());
    println!();
    println!("That address carries a secret drawn for this run. Anyone with it can");
    println!("spend from this wallet, so it goes no further than your own browser,");
    println!("and it stops working the moment this command does.");
    println!();
    println!("Press Ctrl+C to close the wallet.");

    // Ctrl+C ends the process, as it does for the node and the explorer.
    // Nothing is lost by that: every block this wallet accepted was written
    // as it arrived, and a transfer it handed over is with the network rather
    // than here.
    serve::run(&wallet, &listener, &opened, &running);
    wallet.shutdown();
    Ok(())
}

/// Opens the wallet and brings it up to the chain the network is on.
fn join(flags: &Flags) -> Result<Wallet, String> {
    let params = rules_of(flags)?;
    let data = PathBuf::from(flags.value("data").unwrap_or("cairn-wallet-data"));
    let (wallet, blocks) =
        Wallet::open(&flags.key_file()?, params, &data).map_err(|error| error.to_string())?;

    let mut reached = 0usize;
    for seed in flags.values("seed") {
        let address = seed
            .to_socket_addrs()
            .map_err(|error| format!("`{seed}` is not an address: {error}"))?
            .next()
            .ok_or_else(|| format!("`{seed}` resolved to nothing"))?;
        if wallet.reach(address) {
            reached = reached.saturating_add(1);
        }
    }

    let patience: u64 = match flags.value("wait") {
        None => 30,
        Some(text) => text
            .parse()
            .map_err(|_| format!("`{text}` is not seconds"))?,
    };

    println!("wallet    {blocks} blocks on disk, {reached} seed(s) reached");
    print!("catching up");
    wallet.catch_up(Duration::from_secs(patience));
    println!();
    Ok(wallet)
}

fn parse_key(text: &str) -> Result<PublicKey, String> {
    let bytes = cairn_primitives::hex::decode_array::<32>(text)
        .ok_or_else(|| format!("`{text}` is not 32 bytes of hexadecimal"))?;
    PublicKey::from_bytes(&bytes).map_err(|error| format!("that key is unusable: {error}"))
}

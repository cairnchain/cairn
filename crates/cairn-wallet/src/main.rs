//! A Cairn wallet.
//!
//! The wallet is a node. It does not ask a server what it owns; it joins the
//! network, verifies the chain itself, and reads its own balance out of the
//! ledger it validated. That is the whole point of a chain whose state fits on
//! ordinary hardware, so it would be strange to build the wallet any other way.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::validation::ConsensusParams;
use cairn_net::seeds;
use cairn_primitives::Amount;
use cairn_wallet::{keyfile, serve, Wallet, WalletError};

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
  --seed <address>     a peer to start from; repeat for more. Without one,
                       the addresses written into the program are used
  --network <name>     testnet-6 or devnet (default: testnet-6); it has to
                       be the same network the node is on
  --wait <seconds>     how long to spend catching up (default: 30)
  --fee <cairn>        what to pay to be carried. Without one, the least
                       the network will carry, worked out from the transfer
  --fee-anyway         pay a fee out of all proportion to the amount. Without
                       this the wallet stops and asks, because a fee larger
                       than the payment is usually a decimal point in the
                       wrong place. Paying over the odds on purpose is what
                       this is for

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

/// Options that are the whole of what they say, with nothing after them.
const BARE: [&str; 1] = ["fee-anyway"];

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
            if BARE.contains(&name) {
                flags.named.entry(name.to_owned()).or_default();
                continue;
            }
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

    fn given(&self, name: &str) -> bool {
        self.named.contains_key(name)
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
    let progress = wallet.progress();
    // Before the money is counted, because this is what decides part of the
    // answer: a note whose path has been rebuilt is money that can move, and
    // one whose path nobody would rebuild is money that cannot.
    let recovery = wallet.recover_stranded();
    let holdings = wallet.holdings();
    let fallen = holdings.notes.iter().filter(|held| held.is_cold()).count();

    println!();
    println!("address   {}", wallet.address());
    println!(
        "height    {}",
        progress
            .height
            .map_or_else(|| "-".to_owned(), |h| h.to_string())
    );
    // Both of these are about what a spend can reach for, and both say so.
    // `Holdings::notes` holds only that, so an unqualified "notes 0" was a
    // false count for a wallet whose money is a young reward, or is promised to
    // a payment waiting for a block, or has fallen where this node cannot place
    // it. The lines further down name that money; this one now leaves room for
    // them rather than reading as the whole.
    println!(
        "notes     {} that can move now ({fallen} of them fallen to the cold set)",
        holdings.notes.len()
    );
    println!("balance   {}", holdings.spendable);

    // Before anything else about the money, because all three of these mean
    // the number above is not this wallet's own answer.
    if let Some(warning) = progress.warning() {
        println!();
        for line in wrapped(&warning) {
            println!("{line}");
        }
    }

    show_waiting(&wallet);
    show_undone(&wallet);

    if holdings.ripening > Amount::ZERO {
        println!();
        println!(
            "Another {} is in block rewards that cannot be spent yet.",
            holdings.ripening
        );
        match holdings.ripe_at {
            Some(at) => println!("The first of them moves at block {at}."),
            None => println!("They move once their blocks are settled."),
        }
        println!("A reward is the one kind of money whose existence depends on its");
        println!("block surviving, so the rules hold it still until nothing can undo it.");
    }

    if let Some(words) = recovery.words() {
        println!();
        if holdings.stranded > Amount::ZERO {
            println!(
                "Another {} is in notes that cannot move yet.",
                holdings.stranded
            );
        }
        for line in wrapped(&words) {
            println!("{line}");
        }
    }
    // Only when there is nothing at all. It used to be asked of the notes a
    // spend can reach for, which are empty for a wallet whose money is a young
    // reward, whose notes are promised to a payment waiting for a block, or
    // whose notes have fallen out of reach: this line then told somebody who
    // had just been shown their own balance that there was nothing here and
    // that they should go and check their connection.
    if holdings.empty_handed() {
        println!();
        println!("Nothing here yet. If this key should hold something, check that the");
        println!("wallet reached a peer and caught up to the height you expect.");
    }

    let movements = wallet.history();
    if !movements.is_empty() {
        println!();
        println!("What happened, newest first:");
        println!();
        for movement in movements.iter().take(MOVEMENTS_SHOWN) {
            println!(
                "  {:<9} {}{:<22} block {}",
                movement.direction.as_str(),
                if movement.direction == cairn_wallet::history::Direction::Sent {
                    "-"
                } else {
                    "+"
                },
                movement.amount.to_string(),
                movement.height,
            );
        }
        // A list that stops short and does not say where it stopped is a list
        // that has told somebody something untrue about their own money. It
        // stops at both ends: at the top when the wallet has not finished
        // reading the chain, and here when there is more than fits a screen.
        println!();
        if movements.len() > MOVEMENTS_SHOWN {
            println!(
                "Showing the newest {MOVEMENTS_SHOWN} of {}.",
                movements.len()
            );
        }
        let covered = wallet.history_covers();
        if let Some(from) = covered.from {
            if from > 0 {
                println!("As far back as block {from}: this wallet did not read what came before.");
            }
        }
        let behind = covered.behind();
        if behind > 0 {
            println!("Still reading: {behind} block(s) of the chain are not in this list yet.");
        }
    }
    wallet.shutdown();
    Ok(())
}

/// Movements printed. Past this a terminal is being filled rather than read,
/// and how many were left out is said instead.
const MOVEMENTS_SHOWN: usize = 20;

/// Payments handed over that no block carries yet.
///
/// The one thing somebody staring at a balance that has not moved needs told,
/// and the reason they do not press Send a second time.
fn show_waiting(wallet: &Wallet) {
    let payments = wallet.waiting();
    if payments.is_empty() {
        return;
    }
    println!();
    println!("Waiting for a block, so not paid to anybody yet:");
    println!();
    for payment in &payments {
        println!("  -{:<22} {}", payment.amount.to_string(), payment.id);
    }
    println!();
    println!("The notes they are made of are out of the balance above: the network will");
    println!("not carry them twice. A block takes a few minutes.");
}

/// What the chain took back.
///
/// A branch that lost takes its blocks with it, and this key's account of what
/// happened went with them. The money is back; whoever was being paid is not
/// paid, and only the person holding the wallet can do anything about that.
fn show_undone(wallet: &Wallet) {
    let undone = wallet.undone();
    if undone.is_empty() {
        return;
    }
    println!();
    println!("The chain changed and took these back:");
    println!();
    for movement in &undone {
        println!(
            "  {:<9} {:<22} block {}",
            movement.direction.as_str(),
            movement.amount.to_string(),
            movement.height,
        );
    }
    println!();
    println!("They were in this wallet's account of itself and the chain no longer");
    println!("carries them. The money is back in the balance above, and anyone who was");
    println!("being paid has not been paid.");
}

/// Breaks a sentence over lines a terminal holds.
///
/// The library says these things once, in prose, so that the page and this do
/// not drift apart. What is left here is the shape of a terminal.
fn wrapped(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len().saturating_add(word.len()) >= 76 {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
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
    let asked = match flags.value("fee") {
        None => None,
        Some(text) => {
            Some(Amount::from_cairn(text).ok_or_else(|| format!("`{text}` is not an amount"))?)
        }
    };

    let wallet = join(&flags)?;
    // Without one named, what the network asks for. Nothing is not an option
    // any more and defaulting to it would send transfers nobody carries.
    let fee = asked.unwrap_or_else(|| wallet.floor_for(recipient, amount));

    // Said before it is paid rather than only after. A fee is the one number
    // on this command line a person can get wrong by a factor of a hundred
    // thousand with one keystroke.
    println!();
    println!("paying    {amount} to {recipient}");
    println!("fee       {fee} to carry it");

    let outcome = if flags.given("fee-anyway") {
        wallet.send_over_the_odds(recipient, amount, fee)
    } else {
        wallet.send(recipient, amount, fee)
    };
    let sent = outcome.map_err(|error| {
        wallet.shutdown();
        match error {
            WalletError::FeeOutOfProportion { .. } => {
                format!("{error}\n\nIf you do mean it, send it again with --fee-anyway.")
            }
            other => other.to_string(),
        }
    })?;

    println!("change    {}", sent.change);
    println!(
        "from      {} note(s), {} of them out of the cold set",
        sent.notes, sent.from_cold
    );
    println!("transfer  {}", sent.id);
    wallet.shutdown();

    println!();
    if sent.handed_on {
        println!("Handed to the network, and waiting for a block. Nobody has been paid yet:");
        println!("that happens when a block carries it, which takes a few minutes, and it is");
        println!("settled once enough work is piled on top of that block. Until then this");
        println!("wallet's balance does not move and the notes it used cannot be spent again.");
    } else {
        println!("No peer took it: this wallet reached nobody. It is not sent and nobody has");
        println!("been paid.");
    }
    Ok(())
}

fn rules_of(flags: &Flags) -> Result<ConsensusParams, String> {
    let name = flags.value("network").unwrap_or("testnet-6");
    ConsensusParams::for_network(name).ok_or_else(|| {
        if name == "mainnet" {
            "mainnet does not exist yet: its first block has not been mined".to_owned()
        } else {
            format!("unknown network `{name}`, try testnet-6 or devnet")
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

    // As a node does: the names are kept, so a wallet opened on a machine
    // whose name server is not answering yet still joins once it is.
    wallet
        .node()
        .start_from_names(seeds::names_for(flags.values("seed"), params.network));

    let mut reached = 0usize;
    for address in seeds::start_from(flags.values("seed"), params.network)? {
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

    // A wallet with no chain has nothing to add up, and the balance it would
    // print is nought. Said here so it does not read as an empty key.
    let progress = wallet.progress();
    if progress.height.is_none() {
        println!();
        println!("No chain arrived in {patience} seconds, so there is nothing to read a balance");
        if progress.peers == 0 {
            println!("out of. This wallet reached no peer: check the network and the --seed");
            println!("addresses, and that this machine can make outgoing connections.");
        } else {
            println!("out of. This wallet is connected but nothing has been sent to it yet. A");
            println!("first start takes a while; try again with a longer --wait, or with a");
            println!("--seed you trust.");
        }
    }
    Ok(wallet)
}

fn parse_key(text: &str) -> Result<PublicKey, String> {
    let bytes = cairn_primitives::hex::decode_array::<32>(text)
        .ok_or_else(|| format!("`{text}` is not 32 bytes of hexadecimal"))?;
    PublicKey::from_bytes(&bytes).map_err(|error| format!("that key is unusable: {error}"))
}

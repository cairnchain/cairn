//! A Cairn wallet.
//!
//! The wallet is a node. It does not ask a server what it owns; it joins the
//! network, verifies the chain itself, and reads its own balance out of the
//! ledger it validated. That is the whole point of a chain whose state fits on
//! ordinary hardware, so it would be strange to build the wallet any other way.

use std::collections::BTreeMap;
use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use cairn_crypto::SecretKey;
use cairn_ledger::validation::ConsensusParams;
use cairn_net::seeds;
use cairn_primitives::Amount;
use cairn_wallet::history::{Direction, Movement};
use cairn_wallet::{keyfile, serve, Covered, Holdings, Wallet, WalletError};

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

  cairn-wallet backup <key file> --into <directory> [--data <directory>]
      copy the key file and this wallet's account, history.dat, into a
      directory of their own. A restore needs both: see below

Network options

  --data <directory>   where this wallet keeps its copy of the chain, and
                       history.dat, its own account of what this key was
                       paid, which is half of its backup (default:
                       cairn-wallet-data, and it must not be the same
                       directory a node is using)
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
                       wallet answers nothing.

Backing up

  A wallet is two files. The key file spends the money, and it is plain
  text with no passphrase: anyone who can read it, or a copy of it, holds
  the money. history.dat, in the --data directory, is this wallet's own
  account of what the key was paid, and the only record of where money
  that has fallen out of the set every node holds now sits. A restore from
  the key alone does not find that money, and nothing on the network can.
  `backup` copies the two together and never writes over a file. Take it
  again after the wallet has run, and restore by putting the key file back
  and history.dat back in the --data directory before the wallet starts.";

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
        "backup" => back_up(rest),
        other => Err(format!("unknown command `{other}`; try `help`")),
    }
}

/// Every option name this program reads.
///
/// An unknown name stops it rather than being passed over, as it stops
/// `cairnd` and the explorer. Taken and ignored, `--netwrok devnet` read a
/// balance on the default network and printed it as the answer, and `--fees`
/// paid the least the network carries instead of what its sender had priced.
const KNOWN: [&str; 10] = [
    "data",
    "seed",
    "network",
    "wait",
    "fee",
    "fee-anyway",
    "to",
    "amount",
    "port",
    "into",
];

/// Options that are the whole of what they say, with nothing after them.
const BARE: [&str; 1] = ["fee-anyway"];

/// Options that are a list rather than a setting, where every value is used.
const REPEATED: [&str; 1] = ["seed"];

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
                // Every command takes one key file and names everything else.
                // A second loose word was dropped, so `--fee-anyway 0.5`, from
                // somebody who read the flag as taking the fee, paid the least
                // the network carries and never mentioned the figure.
                if !flags.loose.is_empty() {
                    return Err(format!(
                        "unexpected argument `{argument}`: a command takes one key file, and \
                         everything else is named with `--`"
                    ));
                }
                flags.loose.push(argument.clone());
                continue;
            };
            if !KNOWN.contains(&name) {
                return Err(format!("unknown option `--{name}`; try `help`"));
            }
            if BARE.contains(&name) {
                flags.named.entry(name.to_owned()).or_default();
                continue;
            }
            let Some(value) = arguments.get(index) else {
                return Err(format!("`--{name}` needs a value"));
            };
            // A value that begins with two dashes is a value left out, as
            // `cairnd` and the explorer read it. Taken as one, `--data
            // --network devnet` kept a chain in a directory called `--network`
            // and joined the default network.
            if value.starts_with("--") {
                return Err(format!(
                    "`--{name}` needs a value, and `{value}` is another option"
                ));
            }
            index = index.saturating_add(1);
            flags
                .named
                .entry(name.to_owned())
                .or_default()
                .push(value.clone());
        }
        flags.one_value_each()?;
        Ok(flags)
    }

    fn given(&self, name: &str) -> bool {
        self.named.contains_key(name)
    }

    /// Refuses a setting given twice with two different values.
    ///
    /// Only the first was ever used and the rest were dropped without a word,
    /// which on this program means dropping money: `--fee 5 --fee 0.00005`
    /// paid five CAIRN to carry a payment its sender had priced at five
    /// thousandths of one, and neither the proportion guard nor `--fee-anyway`
    /// stands in the way, because both compare the fee against the amount and
    /// the amount was never the thing that changed. `--to` given twice pays
    /// the first address the same way.
    ///
    /// `cairnd` has refused this since the day it was written, under a comment
    /// saying that a setting silently ignored is how an operator ends up
    /// running rules they did not choose. The wallet, where what is dropped is
    /// somebody's money rather than a rule, did not.
    ///
    /// Given twice with the same value nothing is dropped, so nothing is said.
    /// `seed` is a list rather than a setting and every one of them is used.
    fn one_value_each(&self) -> Result<(), String> {
        for (name, values) in &self.named {
            if REPEATED.contains(&name.as_str()) {
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
    say(
        "Anyone holding that file holds the money: it is plain text with no passphrase, \
         so keep it where only you can read it.",
    );
    // It said "That file is the only copy", and a restore from it alone finds
    // nothing of the money that has fallen out of the set every node holds.
    say(
        "It is not all of this wallet. The first time the wallet runs it starts \
         history.dat in its data directory, its own account of what this key is paid, \
         and money that has fallen out of the set every node holds can only be found \
         again with that file. So a backup is both, taken again after the wallet has \
         run. This copies the two together, given the same --data as the wallet if it \
         runs with one:",
    );
    println!();
    println!(
        "  cairn-wallet backup {} --into <directory>",
        path.display()
    );
    if let Some(note) = keyfile::what_was_not_checked() {
        say(note);
    }
    Ok(())
}

/// Copies the key file and the account beside the chain into one directory.
fn back_up(arguments: &[String]) -> Result<(), String> {
    let flags = Flags::parse(arguments)?;
    let into = flags
        .value("into")
        .map(PathBuf::from)
        .ok_or_else(|| "where to? use --into <directory>".to_owned())?;
    let copies = keyfile::back_up(&flags.key_file()?, &data_directory(&flags), &into)?;

    println!("key       {}", copies.key.display());
    println!("account   {}", copies.account.display());
    say(
        "Those two files are this wallet. To restore it, put the key file back, and put \
         history.dat back in the wallet's --data directory before the wallet starts. The \
         account changes as the wallet reads the chain, and a note that falls out of the \
         set every node holds later is recorded only in a newer copy, so back up again \
         after the wallet has run.",
    );
    say(
        "The key file is plain text with no passphrase. Anyone who can read either copy of \
         it holds the money, so keep the backup where only you can reach it.",
    );
    if let Some(note) = keyfile::what_was_not_checked() {
        say(note);
    }
    Ok(())
}

fn show_address(arguments: &[String]) -> Result<(), String> {
    let flags = Flags::parse(arguments)?;
    let secret = keyfile::read(&flags.key_file()?)?;
    println!("{}", secret.public_key());
    Ok(())
}

/// What the list of movements does not cover, said under it.
///
/// Two different things, and the second is the one a reader cannot see for
/// themselves. Where the list begins is visible from the list. A gap in the
/// middle is not: the movements on both sides of it are there, and the blocks
/// inside it read as a stretch in which nothing happened to this key.
fn what_was_not_read(covered: &Covered, listed: usize) -> Vec<String> {
    // An empty list needs the same fact said the other way round. "As far back
    // as block N" beside no rows at all reads as a list, and what it is is the
    // absence of one over a stretch of chain this wallet never looked at.
    let mut lines = Vec::new();
    match (listed, covered.from) {
        (0, Some(from)) if from > 0 => lines.push(format!(
            "Nothing since block {from}, which is as far back as this wallet read."
        )),
        (0, _) => lines.push("Nothing yet.".to_owned()),
        (_, Some(from)) if from > 0 => lines.push(format!(
            "As far back as block {from}: this wallet did not read what came before."
        )),
        _ => {}
    }
    if let Some(missed) = covered.missed_below {
        lines.push(String::new());
        lines.extend(wrapped(&format!(
            "This wallet could not read every block up to {missed}, because the node had let \
             go of them by the time it looked. Anything that happened to this key in the ones \
             it missed is not in the list above. The balance is counted from the chain rather \
             than from the list, so it is right whatever the list is missing."
        )));
    }
    lines
}

/// Prints a paragraph on its own, wrapped to the width the rest of this uses.
fn say(text: &str) {
    println!();
    for line in wrapped(text) {
        println!("{line}");
    }
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

    for line in beside_the_balance(&holdings, recovery.words(), &wallet.history_covers()) {
        println!("{line}");
    }

    say_what_happened(&wallet);
    wallet.shutdown();
    Ok(())
}

/// The list of movements, and everything true about what is not in it.
///
/// All of this sat inside a test for the list being non-empty, so a wallet
/// whose list was empty said none of it: not that it had read only the top of
/// the chain, not that there was a hole in the middle of what it read, not
/// that it was still reading. What a person saw was four lines and no account
/// of anything, and the conclusion they draw from that is that nothing has
/// ever happened to this key. A fresh account against a node restored from a
/// written ledger is the ordinary way to arrive there: the wallet then knows
/// it read the last eight blocks of ninety and says nothing about the other
/// eighty two.
///
/// The web face says all of it, from the same `Covered`, and said so before
/// this did.
fn say_what_happened(wallet: &Wallet) {
    for line in what_happened(&wallet.history(), &wallet.history_covers()) {
        println!("{line}");
    }
}

/// The lines `say_what_happened` prints, from the movements and what they
/// cover.
fn what_happened(movements: &[Movement], covered: &Covered) -> Vec<String> {
    let mut lines = vec![
        String::new(),
        "What happened, newest first:".to_owned(),
        String::new(),
    ];
    for movement in movements.iter().take(MOVEMENTS_SHOWN) {
        lines.push(format!(
            "  {:<9} {}{:<22} block {}",
            movement.direction.as_str(),
            if movement.direction == Direction::Sent {
                "-"
            } else {
                "+"
            },
            movement.amount.to_string(),
            movement.height,
        ));
    }
    if !movements.is_empty() {
        lines.push(String::new());
    }

    // A list that stops short and does not say where it stopped is a list that
    // has told somebody something untrue about their own money. It stops at
    // both ends: at the top when the wallet has not finished reading the
    // chain, and at the bottom when there is more than fits a screen.
    lines.extend(what_was_not_read(covered, movements.len()));
    if movements.len() > MOVEMENTS_SHOWN {
        lines.push(format!(
            "Showing the newest {MOVEMENTS_SHOWN} of {}.",
            movements.len()
        ));
    }
    let behind = covered.behind();
    if behind > 0 {
        lines.push(format!(
            "Still reading: {behind} block(s) of the chain are not in this list yet."
        ));
    }
    lines
}

/// Everything `balance` says about money that is not on the balance line.
///
/// Rewards not ripe yet, notes this account no longer answers for, notes that
/// cannot move, and a wallet with nothing at all. Kept apart from the printing
/// so each can be held to when it is said: it all used to be printed in the
/// middle of reading the wallet, and not one of the four conditions was asked
/// of anything.
fn beside_the_balance(
    holdings: &Holdings,
    recovery: Option<String>,
    covered: &Covered,
) -> Vec<String> {
    let mut lines = Vec::new();
    if holdings.ripening > Amount::ZERO {
        lines.push(String::new());
        lines.push(format!(
            "Another {} is in block rewards that cannot be spent yet.",
            holdings.ripening
        ));
        lines.push(match holdings.ripe_at {
            Some(at) => format!("The first of them moves at block {at}."),
            None => "They move once their blocks are settled.".to_owned(),
        });
        lines.push("A reward is the one kind of money whose existence depends on its".to_owned());
        lines.push(
            "block surviving, so the rules hold it still until nothing can undo it.".to_owned(),
        );
    }

    if let Some(note) = holdings.unaccounted_note() {
        lines.push(String::new());
        lines.extend(wrapped(&note));
    }

    if let Some(words) = recovery {
        lines.push(String::new());
        if holdings.stranded > Amount::ZERO {
            lines.push(format!(
                "Another {} is in notes that cannot move yet.",
                holdings.stranded
            ));
        }
        lines.extend(wrapped(&words));
    }
    // Only when there is nothing at all. It used to be asked of the notes a
    // spend can reach for, which are empty for a wallet whose money is a young
    // reward, whose notes are promised to a payment waiting for a block, or
    // whose notes have fallen out of reach: this line then told somebody who
    // had just been shown their own balance that there was nothing here and
    // that they should go and check their connection.
    //
    // And when this wallet's account begins above the first block, the network
    // is not the only place to look. A restore from the key alone lands here:
    // the account starts where the node was handed the chain, and every note
    // that fell out of the set before that is missing, with nothing to name it
    // by. Sending that person to check their connection sends them the wrong
    // way.
    if holdings.empty_handed() {
        lines.push(String::new());
        match covered.from {
            Some(from) if from > 0 => lines.extend(wrapped(&format!(
                "Nothing here yet. This wallet's account of this key begins at block {from}. \
                 If this key was paid before that, money that has since fallen out of the set \
                 every node holds may be missing here, and only a history.dat that recorded it \
                 can find it: close the wallet, put a backup of that file in its data \
                 directory, and run this again. Otherwise, check that the wallet reached a \
                 peer and caught up to the height you expect."
            ))),
            _ => {
                lines.push(
                    "Nothing here yet. If this key should hold something, check that the"
                        .to_owned(),
                );
                lines.push(
                    "wallet reached a peer and caught up to the height you expect.".to_owned(),
                );
            }
        }
    }
    lines
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
    // The one reader, in the library, so this face and the web face answer the
    // same question about the same string. They did not: this one refused a
    // pasted address with a space on the end and the web face took it.
    let recipient = cairn_wallet::parse_address(recipient).map_err(|error| error.to_string())?;
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
    // Refused before a fee is named for it, as the page's quote is. For money
    // this wallet does not have there is no transfer to price, and the line
    // below used to name a fee of nothing for it.
    if let Some(error) = wallet.could_not_draft(recipient, amount, fee) {
        wallet.shutdown();
        return Err(error.to_string());
    }

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
    // A spend that reached nobody leaves by the failing door. It used to print
    // its own refusal and then exit nought, so a script that ran this and read
    // the code was told the payment had gone.
    if !sent.handed_on {
        return Err(format!(
            "no peer took it. This wallet offered the transfer to every peer it had \
             for five seconds and reached nobody, so it is not sent, nobody has been \
             paid, and the money is still here. Check the network and the --seed \
             addresses, then run this command again. The transfer that was drafted is \
             {}, and nothing on the chain carries it.",
            sent.id
        ));
    }
    println!("Handed to the network, and waiting for a block. Nobody has been paid yet:");
    println!("that happens when a block carries it, which takes a few minutes, and it is");
    println!("settled once enough work is piled on top of that block. Until then this");
    println!("wallet's balance does not move and the notes it used cannot be spent again.");
    Ok(())
}

/// Where this wallet keeps its copy of the chain, and now its link as well.
///
/// One function rather than the string written twice, because the second place
/// it was written would be the one that did not move.
fn data_directory(flags: &Flags) -> PathBuf {
    PathBuf::from(flags.value("data").unwrap_or("cairn-wallet-data"))
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

    let data = data_directory(&flags);
    let wallet = Arc::new(join(&flags)?);
    let (listener, opened) = serve::open(port)?;
    let opened = Arc::new(opened);
    let running = Arc::new(AtomicBool::new(true));

    // Where the link goes depends on what stdout is. See `Opened::hand_over`:
    // a terminal is the operator's own screen, and anything else is a file or
    // a journal that keeps a spending token longer than anyone means it to.
    let link = opened.hand_over(&data, std::io::stdout().is_terminal())?;

    println!();
    println!("address   {}", wallet.address());
    match &link {
        serve::Link::Shown(url) => println!("open      {url}"),
        serve::Link::Written(path) => println!("open      the address is in {}", path.display()),
    }
    println!();
    match &link {
        serve::Link::Shown(_) => {
            println!("That address carries a secret drawn for this run. Anyone with it can");
            println!("spend from this wallet, so it goes no further than your own browser,");
            println!("and it stops working the moment this command does.");
        }
        serve::Link::Written(_) => {
            println!("That address carries a secret drawn for this run, and anyone with it can");
            println!("spend from this wallet. This output is not a terminal, so it was written");
            println!("to a file only its owner can read rather than into whatever is reading");
            println!("this. It stops working the moment this command does.");
        }
    }
    println!();
    println!("Press Ctrl+C to close the wallet.");

    // Ctrl+C ends the process, as it does for the node and the explorer.
    // Nothing is lost by that: every block this wallet accepted was written
    // as it arrived, and a transfer it handed over is with the network rather
    // than here.
    serve::run(&wallet, &listener, &opened, &running);
    serve::Opened::let_the_link_go(&data);
    wallet.shutdown();
    Ok(())
}

/// Opens the wallet and brings it up to the chain the network is on.
fn join(flags: &Flags) -> Result<Wallet, String> {
    let params = rules_of(flags)?;
    let data = data_directory(flags);
    let (wallet, blocks) =
        Wallet::open(&flags.key_file()?, params, &data).map_err(|error| error.to_string())?;

    // Said here as well as where a key is made, because the machine a key file
    // is copied onto is not the one it was made on, and the one being warned
    // is whoever is about to use it.
    if let Some(note) = keyfile::what_was_not_checked() {
        say(note);
    }

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::{beside_the_balance, what_happened, what_was_not_read, wrapped, Flags};
    use super::{Amount, Covered, Direction, Holdings, Movement, MOVEMENTS_SHOWN};
    use cairn_primitives::Hash32;

    fn parsed(line: &[&str]) -> Flags {
        let arguments: Vec<String> = line.iter().map(|&word| word.to_owned()).collect();
        Flags::parse(&arguments).unwrap()
    }

    /// What a command was told is what it reads back.
    ///
    /// Nothing in this file had a test of its own, and the two that run the
    /// binary only reach the refusals. So reading every option as absent
    /// passed, as did reading `--fee-anyway` as always given or never given,
    /// and reading a list of seeds as empty.
    #[test]
    fn a_command_reads_back_what_it_was_given() {
        let flags = parsed(&[
            "key.json",
            "--to",
            "somebody",
            "--seed",
            "one.example:9333",
            "--seed",
            "two.example:9333",
            "--fee-anyway",
        ]);
        assert_eq!(flags.value("to"), Some("somebody"));
        assert_eq!(flags.value("amount"), None, "and nothing it was not told");
        assert!(flags.given("fee-anyway"));
        assert!(!flags.given("fee"), "an option not given is not given");
        assert_eq!(
            flags.values("seed"),
            ["one.example:9333", "two.example:9333"],
            "every seed, in order"
        );
        assert!(flags.values("amount").is_empty());
    }

    fn refused(line: &[&str]) -> String {
        let arguments: Vec<String> = line.iter().map(|&word| word.to_owned()).collect();
        Flags::parse(&arguments).unwrap_err()
    }

    /// An option name the wallet does not know stops it, as it stops `cairnd`
    /// and the explorer.
    ///
    /// Any `--name` at all was taken and the ones nothing reads were passed
    /// over. Nothing asked this, so `--netwrok devnet` read a balance on the
    /// default network and printed it as the answer, and `--fees 0.5` paid the
    /// least the network carries instead of what its sender had priced.
    #[test]
    fn an_option_the_wallet_does_not_know_stops_it() {
        let error = refused(&["key.json", "--netwrok", "devnet"]);
        assert!(
            error.contains("unknown option `--netwrok`"),
            "a misspelt network was passed over: {error}"
        );
        let error = refused(&["key.json", "--to", "somebody", "--fees", "0.5"]);
        assert!(
            error.contains("unknown option `--fees`"),
            "a misspelt fee was passed over: {error}"
        );
    }

    /// A value that is another option is refused rather than taken, as it is
    /// by `cairnd` and the explorer.
    ///
    /// Nothing asked this, so `--data --network devnet` kept a chain in a
    /// directory called `--network`, read `devnet` as a word nobody asked for,
    /// and joined the default network.
    #[test]
    fn an_option_standing_where_a_value_belongs_is_not_the_value() {
        let error = refused(&["key.json", "--data", "--network", "devnet"]);
        assert!(
            error.contains("`--data` needs a value, and `--network` is another option"),
            "an option was taken as the value of the one before it: {error}"
        );
    }

    /// A word past the key file that no option asked for stops the wallet
    /// rather than being dropped, as a loose word stops `cairnd` and the
    /// explorer.
    ///
    /// The first loose word is the key file and every one after it was
    /// dropped. Nothing asked this, so `--fee-anyway 0.5`, written by somebody
    /// who read the flag as taking the fee, paid the least the network carries
    /// and never mentioned the figure it had been handed.
    #[test]
    fn a_word_no_option_asked_for_stops_the_wallet() {
        let error = refused(&["key.json", "--fee-anyway", "0.5"]);
        assert!(
            error.contains("unexpected argument `0.5`"),
            "a word nothing reads was dropped: {error}"
        );
        let error = refused(&["one.json", "two.json"]);
        assert!(
            error.contains("unexpected argument `two.json`"),
            "a second key file was dropped in favour of the first: {error}"
        );
    }

    /// A paragraph comes out as lines no wider than the rest of the output,
    /// with every word in it, once, in order.
    ///
    /// Nothing read this either: it could answer nothing, one empty line or a
    /// word of its own choosing, break before every word, or never break.
    #[test]
    fn a_paragraph_is_wrapped_without_losing_a_word() {
        let text = "Spending a note that has been put away needs a small piece of evidence \
                    that goes stale, and this wallet's own copy had gone stale for three \
                    notes. It asked two of the machines it is connected to, got fresh \
                    evidence back, and checked it against the chain it has verified itself.";
        let lines = wrapped(text);
        assert!(lines.len() > 1, "a paragraph this long is more than a line");
        for line in &lines {
            assert!(line.len() < 76, "{line:?} is {} wide", line.len());
            assert!(!line.is_empty() && !line.starts_with(' ') && !line.ends_with(' '));
        }
        assert!(
            lines[0].len() > 60,
            "a line is filled before the next one starts: {lines:?}"
        );
        assert_eq!(
            lines.join(" "),
            text.split_whitespace().collect::<Vec<_>>().join(" "),
            "every word, once, in order"
        );

        assert!(wrapped("").is_empty(), "nothing to say is no lines");
        let long = "x".repeat(90);
        assert_eq!(
            wrapped(&format!("a {long} b")),
            ["a", long.as_str(), "b"],
            "a word wider than a line has a line of its own and is not cut"
        );
    }

    fn pebbles(count: u64) -> Amount {
        Amount::from_pebbles(count).unwrap()
    }

    /// A wallet holding something spendable and nothing else.
    fn holding() -> Holdings {
        Holdings {
            spendable: pebbles(5_000),
            ripening: Amount::ZERO,
            ripe_at: None,
            waiting: Amount::ZERO,
            stranded: Amount::ZERO,
            unprovable: Vec::new(),
            unaccounted: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn says(lines: &[String], words: &str) -> bool {
        lines.iter().any(|line| line.contains(words))
    }

    /// What `balance` says beside the number is said when it is so, and only
    /// then.
    ///
    /// All of it used to be printed in the middle of reading the wallet, so
    /// nothing could ask it anything: a wallet with rewards ripening passed
    /// with them unmentioned, one with none was told of nought in rewards,
    /// notes that could not move went unnamed, and a wallet holding money was
    /// free to be told it held nothing.
    #[test]
    fn what_is_beside_the_balance_is_said_when_it_is_so() {
        assert!(
            beside_the_balance(&holding(), None, &covered(0, 90, 90)).is_empty(),
            "money that can move and nothing else needs nothing said beside it"
        );

        let ripening = Holdings {
            ripening: pebbles(700),
            ripe_at: Some(120),
            ..holding()
        };
        let lines = beside_the_balance(&ripening, None, &covered(0, 90, 90));
        assert!(
            says(
                &lines,
                &format!("Another {} is in block rewards", pebbles(700))
            ),
            "{lines:?}"
        );
        assert!(
            says(&lines, "The first of them moves at block 120."),
            "{lines:?}"
        );
        let unsettled = Holdings {
            ripe_at: None,
            ..ripening
        };
        assert!(says(
            &beside_the_balance(&unsettled, None, &covered(0, 90, 90)),
            "They move once their blocks are settled."
        ));

        let stranded = Holdings {
            stranded: pebbles(300),
            ..holding()
        };
        let lines = beside_the_balance(
            &stranded,
            Some("Words about it.".to_owned()),
            &covered(0, 90, 90),
        );
        assert!(
            says(
                &lines,
                &format!("Another {} is in notes that cannot move yet.", pebbles(300))
            ),
            "{lines:?}"
        );
        assert!(says(&lines, "Words about it."), "{lines:?}");
        let lines = beside_the_balance(
            &holding(),
            Some("Words about it.".to_owned()),
            &covered(0, 90, 90),
        );
        assert!(
            !says(&lines, "cannot move yet"),
            "nothing stranded is nothing to count: {lines:?}"
        );

        let nothing = Holdings {
            spendable: Amount::ZERO,
            ..holding()
        };
        assert!(says(
            &beside_the_balance(&nothing, None, &covered(0, 90, 90)),
            "Nothing here yet."
        ));
        assert!(!says(
            &beside_the_balance(&holding(), None, &covered(0, 90, 90)),
            "Nothing here yet."
        ));
    }

    /// An empty wallet whose account begins above the first block names the
    /// account file, rather than only sending its owner to check the network.
    ///
    /// A restore from the key alone lands exactly here: nothing held, an
    /// account that begins where the node was handed the chain, and every
    /// note that fell out of the set before that missing. It was told to check
    /// that the wallet reached a peer. Nothing asked what an empty wallet says
    /// about where its account begins.
    #[test]
    fn an_empty_wallet_whose_account_begins_late_names_the_account_file() {
        let nothing = Holdings {
            spendable: Amount::ZERO,
            ..holding()
        };
        let late = beside_the_balance(&nothing, None, &covered(70, 90, 90)).join(" ");
        assert!(
            late.contains("block 70"),
            "the wallet does not say where its account begins"
        );
        assert!(
            late.contains("history.dat"),
            "the wallet does not name the file that finds money fallen before it"
        );
        let whole = beside_the_balance(&nothing, None, &covered(0, 90, 90)).join(" ");
        assert!(
            !whole.contains("history.dat"),
            "a wallet that read every block has missed nothing, and is sent looking \
             for a file it does not need"
        );
    }

    fn moved(height: u64, direction: Direction) -> Movement {
        Movement {
            height,
            at: 0,
            direction,
            amount: pebbles(50),
            id: Hash32::ZERO,
        }
    }

    fn covered(from: u64, through: u64, tip: u64) -> Covered {
        Covered {
            from: Some(from),
            through: Some(through),
            missed_below: None,
            tip: Some(tip),
        }
    }

    /// The list of movements says where it stops, at both ends.
    ///
    /// Nothing read it: a list cut at the screen's length without saying how
    /// many were left out passed, as did one that said it was cut when it was
    /// not, a wallet still reading that did not say so, and one that said so
    /// when it had finished.
    #[test]
    fn the_list_of_movements_says_where_it_stops() {
        let many: Vec<Movement> = (0..25)
            .map(|height| moved(height, Direction::Received))
            .collect();
        let lines = what_happened(&many, &covered(0, 24, 24));
        let rows = lines.iter().filter(|line| line.contains(" block ")).count();
        assert_eq!(rows, MOVEMENTS_SHOWN);
        assert!(says(&lines, "Showing the newest 20 of 25."), "{lines:?}");
        assert!(
            !says(&lines, "Still reading"),
            "it has read to the tip: {lines:?}"
        );

        let fits = &many[..MOVEMENTS_SHOWN];
        assert!(!says(
            &what_happened(fits, &covered(0, 24, 24)),
            "Showing the newest"
        ));

        let behind = what_happened(fits, &covered(0, 27, 30));
        assert!(says(&behind, "Still reading: 3 block(s)"), "{behind:?}");

        let sent = what_happened(&[moved(4, Direction::Sent)], &covered(0, 4, 4));
        assert!(
            sent[3].contains(" -"),
            "a payment out is written as one: {sent:?}"
        );
        assert_eq!(
            sent[4], "",
            "and the list is closed off from what follows it"
        );

        assert_eq!(
            what_happened(&[], &covered(0, 4, 4)),
            ["", "What happened, newest first:", "", "Nothing yet."],
            "an empty list says so and nothing more"
        );
    }

    /// Where the list begins, and the stretch it never read, are said.
    #[test]
    fn what_was_not_read_is_said() {
        assert_eq!(
            what_was_not_read(&covered(70, 90, 90), 0),
            ["Nothing since block 70, which is as far back as this wallet read."]
        );
        assert_eq!(what_was_not_read(&covered(0, 90, 90), 0), ["Nothing yet."]);
        assert_eq!(
            what_was_not_read(&covered(70, 90, 90), 3),
            ["As far back as block 70: this wallet did not read what came before."]
        );
        assert!(what_was_not_read(&covered(0, 90, 90), 3).is_empty());
        let holed = Covered {
            missed_below: Some(40),
            ..covered(0, 90, 90)
        };
        let lines = what_was_not_read(&holed, 3);
        assert!(
            says(&lines, "could not read every block up to 40"),
            "{lines:?}"
        );
    }
}

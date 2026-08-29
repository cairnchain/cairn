//! A Cairn wallet.
//!
//! The wallet is a node. It does not ask a server what it owns; it joins the
//! network, verifies the chain itself, and reads its own balance out of the
//! ledger it validated. That is the whole point of a chain whose state fits on
//! ordinary hardware, so it would be strange to build the wallet any other way.

mod keyfile;

use std::collections::BTreeMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cairn_accumulator::ForestProof;
use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{Input, Transfer};
use cairn_ledger::validation::ConsensusParams;
use cairn_net::Node;
use cairn_primitives::codec::Encode;
use cairn_primitives::Amount;

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

Network options

  --data <directory>   where this wallet keeps its copy of the chain
                       (default: cairn-wallet-data, and it must not be the
                       same directory a node is using)
  --seed <address>     a peer to start from; repeat for more
  --network <name>     testnet-2 or devnet (default: testnet-2); it has to
                       be the same network the node is on
  --wait <seconds>     how long to spend catching up (default: 30)
  --fee <cairn>        what to pay to be carried (default: 0)";

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
    let secret = keyfile::read(&flags.key_file()?)?;
    let mine = secret.public_key();
    let node = join(&flags, mine)?;
    let (held, stranded) = owned_notes(&node, mine);
    let total = Amount::checked_sum(held.iter().map(|owned| owned.note.value))
        .ok_or_else(|| "the notes held add up past the monetary ceiling".to_owned())?;
    let fallen = held.iter().filter(|owned| owned.fallen.is_some()).count();

    println!();
    println!("address   {mine}");
    println!(
        "height    {}",
        node.height()
            .map_or_else(|| "-".to_owned(), |h| h.to_string())
    );
    println!(
        "notes     {} ({fallen} of them fallen to the cold set)",
        held.len()
    );
    println!("balance   {total}");
    if stranded > Amount::ZERO {
        println!();
        println!("Another {stranded} sits in notes this node cannot prove. They are");
        println!("yours and they are not lost, but spending one takes a proof, and");
        println!("rebuilding a proof takes an archivist. Ask one, or run this wallet");
        println!("against a node started with --archive.");
    }
    if held.is_empty() {
        println!();
        println!("Nothing here yet. If this key should hold something, check that the");
        println!("wallet reached a peer and caught up to the height you expect.");
    }
    node.shutdown();
    Ok(())
}

fn spend(arguments: &[String]) -> Result<(), String> {
    let flags = Flags::parse(arguments)?;
    let secret = keyfile::read(&flags.key_file()?)?;

    let recipient = flags
        .value("to")
        .ok_or_else(|| "who is being paid? use --to".to_owned())?;
    let recipient = parse_key(recipient)?;
    let amount = flags
        .value("amount")
        .ok_or_else(|| "how much? use --amount".to_owned())?;
    let amount = Amount::from_cairn(amount)
        .ok_or_else(|| format!("`{amount}` is not an amount of CAIRN"))?;
    if amount == Amount::ZERO {
        return Err("a transfer of nothing would only cost state".to_owned());
    }
    let fee = match flags.value("fee") {
        None => Amount::ZERO,
        Some(text) => {
            Amount::from_cairn(text).ok_or_else(|| format!("`{text}` is not an amount"))?
        }
    };
    let needed = amount
        .checked_add(fee)
        .ok_or_else(|| "that total is too large".to_owned())?;

    let mine = secret.public_key();
    let node = join(&flags, mine)?;
    let (held, stranded) = owned_notes(&node, mine);

    let (spending, gathered) = select(&held, needed).map_err(|short| {
        if stranded > Amount::ZERO {
            format!("{short}. Another {stranded} sits in notes this node cannot prove")
        } else {
            short
        }
    })?;
    let change = gathered
        .checked_sub(needed)
        .ok_or_else(|| "not enough after all".to_owned())?;

    let mut outputs = vec![Note::new(amount, recipient)];
    if change > Amount::ZERO {
        outputs.push(Note::new(change, mine));
    }

    let rules = rules_of(&flags)?;
    let network = rules.network;
    let inputs = spending
        .iter()
        .map(|owned| match &owned.fallen {
            None => Input::hot(owned.id),
            Some((position, proof)) => Input::cold(owned.id, owned.note, *position, proof.clone()),
        })
        .collect();
    let mut transfer = Transfer::new(inputs, outputs);
    for (index, owned) in spending.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| "too many notes".to_owned())?;
        transfer.sign_input(network, index, &owned.note, &secret);
    }

    // A transfer no block can carry would be refused by the network, and it is
    // better to say so here than to have the refusal come back as a rule
    // nobody outside the protocol has heard of. It happens when a wallet holds
    // its money in many small fallen notes, each of which travels with its own
    // proof: sending less at a time, more than once, is the way through.
    let bulk = transfer.encode().len();
    if bulk > rules.max_block_bytes {
        return Err(format!(
            "this spend gathers {} notes and takes {bulk} bytes, more than the \
             {} a block carries. Send a smaller amount, more than once: each \
             one leaves fewer notes behind.",
            spending.len(),
            rules.max_block_bytes,
        ));
    }

    let id = transfer.id();
    node.submit_transaction(transfer)
        .map_err(|error| format!("the network would not take it: {error}"))?;

    println!();
    println!("sending   {amount} to {recipient}");
    println!("fee       {fee}");
    println!("change    {change}");
    let from_cold = spending
        .iter()
        .filter(|owned| owned.fallen.is_some())
        .count();
    println!(
        "from      {} note(s), {from_cold} of them out of the cold set",
        spending.len()
    );
    println!("transfer  {id}");

    // Hold the connection open long enough for the transfer to leave.
    let handed_on = wait_until(Duration::from_secs(5), || node.peer_count() > 0);
    thread::sleep(Duration::from_millis(500));
    node.shutdown();

    println!();
    if handed_on {
        println!("Handed to the network. It is spent once a block carries it, and settled");
        println!("once enough work is piled on top of that block.");
    } else {
        println!("No peer took it: this wallet reached nobody. It is not spent.");
    }
    Ok(())
}

/// One note this wallet owns, and what it takes to spend it.
#[derive(Clone, Debug)]
struct Owned {
    id: NoteId,
    note: Note,
    /// Where it fell and how to prove it, once it has fallen. The node was
    /// asked to watch this owner, so the proof it hands back is current.
    fallen: Option<(u64, ForestProof)>,
}

/// Everything this key owns: what the nodes still hold, and what has fallen.
/// What this key holds, and what it holds that cannot be spent right now.
///
/// The second is money, not a rounding error. A note that has fallen to the
/// cold set is spent by presenting a proof, and a wallet that cannot get one
/// holds something it cannot move until an archivist rebuilds it. Reporting
/// the total without it would show a balance that quietly went down, which is
/// the worst thing a wallet can tell anyone.
fn owned_notes(node: &Node, mine: PublicKey) -> (Vec<Owned>, Amount) {
    node.with_chain(|chain| {
        let state = chain.state();
        let mut owned: Vec<Owned> = state
            .hot_notes()
            .filter(|(_, entry)| entry.note.owner == mine)
            .map(|(id, entry)| Owned {
                id,
                note: entry.note,
                fallen: None,
            })
            .collect();

        let mut unprovable = Amount::ZERO;
        for (id, position, note) in state.watched_notes() {
            if note.owner != mine {
                continue;
            }
            match state.cold().proof_of(position) {
                Some(proof) => owned.push(Owned {
                    id,
                    note,
                    fallen: Some((position, proof)),
                }),
                None => unprovable = unprovable.checked_add(note.value).unwrap_or(unprovable),
            }
        }
        (owned, unprovable)
    })
}

/// Picks notes to cover `needed`, largest first so a spend uses as few as it
/// can and leaves as little dust behind.
fn select(held: &[Owned], needed: Amount) -> Result<(Vec<Owned>, Amount), String> {
    let mut sorted = held.to_vec();
    // Notes the nodes still hold come first, because spending one of those
    // costs no proof on the wire. Then the largest, so a spend uses as few
    // notes as it can and leaves as little dust behind.
    sorted.sort_by(|left, right| {
        left.fallen
            .is_some()
            .cmp(&right.fallen.is_some())
            .then(right.note.value.cmp(&left.note.value))
            .then(left.id.cmp(&right.id))
    });

    let mut chosen = Vec::new();
    let mut gathered = Amount::ZERO;
    for entry in sorted {
        if gathered >= needed {
            break;
        }
        gathered = gathered
            .checked_add(entry.note.value)
            .ok_or_else(|| "these notes add up past the ceiling".to_owned())?;
        chosen.push(entry);
    }

    if gathered < needed {
        return Err(format!(
            "this wallet holds {gathered}, which does not cover {needed}"
        ));
    }
    Ok((chosen, gathered))
}

fn rules_of(flags: &Flags) -> Result<ConsensusParams, String> {
    let name = flags.value("network").unwrap_or("testnet-2");
    ConsensusParams::for_network(name).ok_or_else(|| {
        if name == "mainnet" {
            "mainnet does not exist yet: its first block has not been mined".to_owned()
        } else {
            format!("unknown network `{name}`, try testnet-2 or devnet")
        }
    })
}

/// Starts this wallet's own node and gives it time to catch up.
///
/// The node is told which owner to watch before it replays anything, because
/// where a note falls is learned as it falls. That is what lets this wallet
/// spend from the cold set without asking an archivist for anything.
fn join(flags: &Flags, mine: PublicKey) -> Result<Node, String> {
    let params = rules_of(flags)?;

    let data = PathBuf::from(flags.value("data").unwrap_or("cairn-wallet-data"));
    let listen: SocketAddr = "0.0.0.0:0"
        .parse()
        .map_err(|_| "bad listen address".to_owned())?;
    let (node, restored) = Node::open_watching(params, listen, &data, &[mine])
        .map_err(|error| format!("could not start: {error}"))?;

    let mut reached = 0usize;
    for seed in flags.values("seed") {
        let address = seed
            .to_socket_addrs()
            .map_err(|error| format!("`{seed}` is not an address: {error}"))?
            .next()
            .ok_or_else(|| format!("`{seed}` resolved to nothing"))?;
        node.remember_seed(address);
        if node.connect(address).is_ok() {
            reached = reached.saturating_add(1);
        }
    }

    let patience: u64 = match flags.value("wait") {
        None => 30,
        Some(text) => text
            .parse()
            .map_err(|_| format!("`{text}` is not seconds"))?,
    };

    println!(
        "wallet    {} blocks on disk, {} seed(s) reached",
        restored.blocks, reached
    );
    print!("catching up");
    catch_up(&node, Duration::from_secs(patience));
    println!();
    Ok(node)
}

/// Waits until the chain stops moving, or until patience runs out.
fn catch_up(node: &Node, patience: Duration) {
    let deadline = Instant::now()
        .checked_add(patience)
        .unwrap_or_else(Instant::now);
    let mut last = node.height();
    let mut still_since = Instant::now();

    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(200));
        let height = node.height();
        if height == last {
            if node.peer_count() > 0 && still_since.elapsed() > Duration::from_secs(2) {
                return;
            }
        } else {
            last = height;
            still_since = Instant::now();
        }
    }
}

fn wait_until(patience: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = Instant::now()
        .checked_add(patience)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    ready()
}

fn parse_key(text: &str) -> Result<PublicKey, String> {
    let bytes = cairn_primitives::hex::decode_array::<32>(text)
        .ok_or_else(|| format!("`{text}` is not 32 bytes of hexadecimal"))?;
    PublicKey::from_bytes(&bytes).map_err(|error| format!("that key is unusable: {error}"))
}

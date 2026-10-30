//! `docs/cairn-integration.md`, held to the programs it describes.
//!
//! The guide is what an exchange reads before it writes a line of code
//! against Cairn, so a default it quotes that the program no longer has, a
//! flag it runs that the program refuses, or an endpoint it lists that answers
//! "no such endpoint" is a wrong instruction followed by somebody who trusted
//! it. Every figure it gives is worked out here from the code, or read out of
//! the text the program itself prints, and compared.
//!
//! The explorer is a binary with no library target, so its two modules are
//! included by path, as `answers.rs` does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    dead_code
)]

#[path = "../src/api.rs"]
mod api;
#[path = "../src/index.rs"]
mod index;

use std::collections::BTreeSet;
use std::net::SocketAddr;

use cairn_crypto::SecretKey;
use cairn_http::{Request, Response};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Address, NetworkId, Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::amount::PEBBLES_PER_CAIRN;
use cairn_primitives::hash::{hash, Domain};
use cairn_primitives::{hex, Amount, Hash32};

use api::Explorer;

const GUIDE: &str = include_str!("../../../docs/cairn-integration.md");
const SPECIFICATION: &str = include_str!("../../../docs/cairn-specification.md");
const THREAT_MODEL: &str = include_str!("../../../docs/cairn-threat-model.md");
const PAPER: &str = include_str!("../../../docs/cairn-whitepaper.html");
/// Where each program's `--help` is written, which is the text an operator
/// is shown and so the one the guide has to agree with.
const NODE_OPTIONS: &str = include_str!("../../cairn-node/src/options.rs");
const EXPLORER_OPTIONS: &str = include_str!("../src/options.rs");
const WALLET_MAIN: &str = include_str!("../../cairn-wallet/src/main.rs");
const EXPLORER_MAIN: &str = include_str!("../src/main.rs");
const API: &str = include_str!("../src/api.rs");
/// The case the guide sends a reader to for what a payee is told when a
/// payment is taken back. Included so that the file moving fails the build.
const REVERSED: &str =
    include_str!("../../cairn-wallet/tests/a_payment_reversed_ten_blocks_deep.rs");

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// The text with every run of white space made one space, so a phrase is
/// found wherever a line happened to wrap.
fn flowing(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn guide() -> String {
    flowing(GUIDE)
}

/// A number the way the documents write one in prose: 131 072.
fn spaced(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(' ');
        }
        out.push(digit);
    }
    out
}

fn says(phrase: &str) {
    assert!(
        guide().contains(phrase),
        "the guide no longer says `{phrase}`"
    );
}

/// The `--help` of the program a command line starts with.
fn help_of(program: &str) -> &'static str {
    let source = match program {
        "cairnd" => NODE_OPTIONS,
        "cairn-explorer" => EXPLORER_OPTIONS,
        "cairn-wallet" => WALLET_MAIN,
        other => panic!("the guide runs `{other}`, which is not one of the three programs"),
    };
    let start = source.find("HELP: &str = \"").expect("a help text");
    let rest = &source[start..];
    let end = rest.find("\";").expect("a closed help text");
    &rest[..end]
}

/// Every span of code in the guide, inline or fenced, one line at a time.
fn code_lines() -> Vec<String> {
    let mut lines = Vec::new();
    let mut fenced = false;
    for line in GUIDE.lines() {
        if line.starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            lines.push(line.trim().to_owned());
            continue;
        }
        let mut parts = line.split('`');
        parts.next();
        while let Some(code) = parts.next() {
            lines.push(code.to_owned());
            parts.next();
        }
    }
    lines
}

/// **Every default the guide quotes is the one the program prints in its
/// own help.**
#[test]
fn the_defaults_the_guide_quotes_are_the_ones_each_program_has() {
    for (program, in_help, in_guide) in [
        (
            "cairnd",
            "(default: 0.0.0.0:9944)",
            "<code>0.0.0.0:9944</code>",
        ),
        ("cairnd", "(default: cairn-data)", "<code>cairn-data</code>"),
        (
            "cairn-explorer",
            "(default: 0.0.0.0:9945)",
            "<code>0.0.0.0:9945</code>",
        ),
        (
            "cairn-explorer",
            "(default: 127.0.0.1:8080)",
            "<code>127.0.0.1:8080</code>",
        ),
        (
            "cairn-explorer",
            "(default: cairn-explorer-data)",
            "<code>cairn-explorer-data</code>",
        ),
        (
            "cairn-wallet",
            "(default: cairn-wallet-data,",
            "<code>cairn-wallet-data</code>",
        ),
        ("cairnd", "(default: 1GB)", "`1GB` by default"),
        (
            "cairn-explorer",
            "627 bytes for every note that has ever existed, against 104 for every note \
             that has fallen",
            "627 bytes for every note that has ever existed, against 104 for every note \
             that has fallen",
        ),
        (
            "cairnd",
            "about a hundred bytes each",
            "about a hundred bytes of memory for every such note",
        ),
        (
            "cairn-explorer",
            "An explorer keeps the cold set",
            "The explorer always keeps the cold set",
        ),
    ] {
        assert!(
            flowing(help_of(program)).contains(in_help),
            "`{program} --help` no longer says `{in_help}`"
        );
        says(in_guide);
    }
    // The node reads a file and the explorer does not, which is what the
    // guide says of each.
    assert!(NODE_OPTIONS.contains("const CONFIG_FILE: &str = \"cairn.conf\""));
    assert!(!EXPLORER_OPTIONS.contains("cairn.conf"));
    says("`cairnd` also reads `cairn.conf`");
    // And the server the API is on reads no body.
    assert!(EXPLORER_MAIN.contains("cairn_http::serve_without_bodies("));
    says("It answers `GET` and `HEAD` and reads no request body");
}

/// **Every command the guide runs, and every flag it names, is one the
/// program takes.**
///
/// A flag is checked against the help of the program on its line, and a
/// flag named alone in the prose against the help of any of the three.
#[test]
fn every_command_and_flag_the_guide_names_is_one_a_program_takes() {
    let programs = ["cairnd", "cairn-explorer", "cairn-wallet"];
    let mut commands = 0;
    for line in code_lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(first) = words.first() else {
            continue;
        };
        if programs.contains(first) {
            commands += 1;
            let help = help_of(first);
            if *first == "cairn-wallet" {
                if let Some(command) = words.get(1).filter(|word| !word.starts_with('-')) {
                    assert!(
                        help.contains(&format!("cairn-wallet {command} ")),
                        "the guide runs `cairn-wallet {command}`, which the wallet does not have"
                    );
                }
            }
            for flag in words.iter().filter(|word| word.starts_with("--")) {
                assert!(
                    help.contains(&format!("{flag} ")) || help.contains(&format!("{flag}\n")),
                    "the guide runs `{first} {flag}`, which `{first} --help` does not list: {line}"
                );
            }
        } else if first.starts_with("--") && words.len() <= 2 {
            assert!(
                programs
                    .iter()
                    .any(|program| help_of(program).contains(&format!("{first} "))),
                "the guide names `{first}`, which no program takes"
            );
        }
    }
    assert!(
        commands >= 4,
        "the guide runs {commands} commands; this test reads it wrongly"
    );
}

/// The endpoints `route` answers, read out of its source, each as the guide
/// writes it with whatever it is asked about left off.
fn routed() -> BTreeSet<String> {
    let start = API.find("fn route(").expect("the router");
    let body = &API[start..];
    let body = &body[..body.find("\n}\n").expect("the router ends")];
    let mut found = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Some((\"") {
            let name = rest.split('"').next().unwrap();
            found.insert(format!("/api/{name}/"));
        } else if let Some(rest) = line.strip_prefix('"') {
            let name = rest.split('"').next().unwrap();
            found.insert(format!("/api/{name}"));
        }
    }
    found
}

/// The endpoints the guide names, with what is filled in left off.
fn listed() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let text = GUIDE.replace("&lt;", "<").replace("&gt;", ">");
    for piece in text.split("/api/").skip(1) {
        let end = piece
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '/'))
            .unwrap_or(piece.len());
        let name = &piece[..end];
        if name.is_empty() {
            continue;
        }
        found.insert(format!("/api/{name}"));
    }
    found
}

/// **Every endpoint the guide lists is one the explorer routes, and every one
/// it routes is in the guide.**
///
/// And each is asked of a running explorer, with what the guide leaves to be
/// filled in filled in, so that a route spelled the same and answering "no
/// such endpoint" would be caught too.
#[test]
fn the_endpoints_the_guide_lists_are_the_ones_the_explorer_answers() {
    let routes = routed();
    let named = listed();
    assert!(routes.len() >= 13, "the router reads as {routes:?}");
    assert_eq!(
        named, routes,
        "the guide and the router disagree about what there is to ask"
    );

    let mut params = ConsensusParams::testnet();
    params.coinbase_maturity = 0;
    let miner = wallet(1);
    let mut forge = Forge::new(params);
    let blocks = forge.mine_many(&miner, 2);
    let explorer = explorer(params, &blocks);
    let coinbase = blocks[1].coinbase.id();
    let owner = Address::from(miner.public_key()).to_text(params.network);
    for endpoint in &named {
        let rest = endpoint.strip_prefix("/api/").unwrap();
        let asked = match rest {
            "block/" => "block/1".to_owned(),
            "tx/" => format!("tx/{coinbase}"),
            "address/" => format!("address/{owner}"),
            "note/" => format!("note/{coinbase}:0"),
            "search" => "search?q=1".to_owned(),
            other => other.to_owned(),
        };
        let answer = ask(&explorer, &asked);
        assert_eq!(
            answer.status,
            200,
            "{endpoint}, asked as /api/{asked}, answered {}",
            body(&answer)
        );
    }
    explorer.node().shutdown();
}

/// **The limits the guide gives a reader of the API are the ones the
/// explorer keeps.**
#[test]
fn the_api_limits_the_guide_gives_are_the_ones_the_explorer_keeps() {
    for (constant, phrase) in [
        ("const PAGE: usize = 25;", "25 by default and at most 128"),
        (
            "const MAX_PAGE: usize = 128;",
            "25 by default and at most 128",
        ),
        (
            "const ADDRESS_PAGE: usize = 100;",
            "at most 100 movements a page",
        ),
        (
            "const ADDRESS_SCAN: usize = 10_000;",
            "no more than the newest 10 000 notes",
        ),
    ] {
        assert!(
            API.contains(constant),
            "the explorer no longer has `{constant}`"
        );
        says(phrase);
    }
    assert!(API.contains("format!(\"{}:{}\", id.source, id.index)"));
    says("as `<transaction>:<index>`");
}

/// **The address vectors are the addresses the key makes, the table's
/// lengths are their lengths, and they are the specification's.**
#[test]
fn the_address_vectors_are_the_ones_the_key_makes() {
    let key = GUIDE
        .split("public key  ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    let key: [u8; 32] = hex::decode(key).unwrap().try_into().unwrap();
    let address = Address::of_ed25519(&key);
    for (network, prefix, length) in [
        (NetworkId::MAINNET, "cairn", 64),
        (NetworkId::TESTNET, "tcairn", 65),
        (NetworkId::DEVNET, "dcairn", 65),
    ] {
        assert_eq!(network.address_prefix(), prefix);
        let text = address.to_text(network);
        let line = format!("{prefix:<6}  {text}");
        assert!(GUIDE.contains(&line), "the guide lacks `{line}`");
        assert!(
            SPECIFICATION.contains(&line),
            "the specification lacks `{line}`"
        );
        assert_eq!(text.len(), length);
        says(&format!(
            "<td><code>{prefix}</code></td><td class=\"n\">{length}</td>"
        ));
        assert_eq!(Address::from_text(&text, network), Ok(address));
        assert_eq!(
            Address::from_text(&text.to_uppercase(), network),
            Ok(address),
            "the guide says capitals throughout are the same address"
        );
    }
    let bytes = hex::encode(address.as_bytes());
    let line = format!("address     {bytes}");
    assert!(GUIDE.contains(&line), "the guide lacks `{line}`");
}

/// The 32 bytes of the address in the vectors.
fn vector_address() -> Address {
    let key = "47da95e3585bde332648ce1bf660eb1d68bb4fd9a6b206f80996056edd78995c";
    Address::of_ed25519(&hex::decode(key).unwrap().try_into().unwrap())
}

/// **The bytes the guide says a transfer's identifier is taken over hash to
/// the identifier it gives, and that is the identifier the code computes for
/// the transfer it describes.**
#[test]
fn the_transfer_vector_is_the_identifier_the_code_computes() {
    let transfer = Transfer::new(
        vec![Input::hot(NoteId::new(Hash32::from_bytes([0; 32]), 0))],
        vec![Note::new(
            Amount::from_pebbles(PEBBLES_PER_CAIRN).unwrap(),
            vector_address(),
        )],
    );
    assert_eq!(transfer.version, 1, "the guide says version 1");

    let block = GUIDE
        .split("version     ")
        .nth(1)
        .expect("the guide's preimage")
        .split("```")
        .next()
        .unwrap();
    let mut preimage = String::new();
    let mut identifier = None;
    for line in std::iter::once(format!("version {block}"))
        .flat_map(|text| text.lines().map(str::to_owned).collect::<Vec<_>>())
    {
        let mut words = line.split_whitespace();
        let Some(label) = words.next() else {
            continue;
        };
        let hexes: String = words.collect();
        if label == "identifier" {
            identifier = Some(hexes);
        } else {
            preimage.push_str(&hexes);
        }
    }
    let hashed = hash(Domain::TransferId, &hex::decode(&preimage).unwrap());
    assert_eq!(
        hashed,
        transfer.id(),
        "the bytes the guide lists are not what the code hashes"
    );
    assert_eq!(
        identifier.as_deref(),
        Some(transfer.id().to_string().as_str()),
        "the guide gives the wrong identifier"
    );
    assert_eq!(
        Domain::TransferId.context(),
        "cairn v1 transfer id",
        "the transfer domain"
    );
}

/// **The confirmation policy is the depth the rules call settled, and the
/// time the guide gives it is that depth at the target block time.**
#[test]
fn the_confirmation_policy_is_the_depth_the_rules_settle_at() {
    let params = ConsensusParams::testnet();
    let depth = cairn_chain::MAX_REORG_DEPTH as u64;
    assert_eq!(depth, cairn_ledger::handover::BURIAL);
    assert_eq!(params.burial, depth);
    assert_eq!(params.coinbase_maturity, depth);
    says(&format!(
        "credit a deposit at {} confirmations",
        spaced(depth)
    ));
    says(&format!("The undo depth is {} blocks", spaced(depth)));
    says(&format!(
        "until the block that paid it is {} deep",
        spaced(depth)
    ));
    let seconds = depth * params.target_block_time;
    says(&format!(
        "{} h {:02} m",
        seconds / 3600,
        (seconds % 3600) / 60
    ));
    assert_eq!(params.target_block_time, 60, "the guide says one a minute");
    says("At one block a minute");
    // The row the guide sends a reader to.
    let model = flowing(THREAT_MODEL);
    assert!(model.contains("A miner who rents a majority while the chain is young"));
    assert!(model.contains("only more honest hash rate answers it"));
    // And the field it says a stranded node reports.
    assert!(API.contains("json.field_u64(\"outOfReach\", node.out_of_reach);"));
    says("`node.outOfReach`");
}

/// **The fee the guide says a node carries at least is the floor the pool
/// holds a transfer to.**
#[test]
fn the_fee_floor_the_guide_gives_is_the_one_a_node_holds_to() {
    let params = ConsensusParams::for_network("testnet-8").unwrap();
    assert_eq!(cairn_chain::MIN_FEE_PER_WEIGHT, 10);
    says("**ten pebbles for each byte**");
    let place = cairn_ledger::validation::PLACE_PRICE.as_pebbles();
    assert_eq!(params.place_price.as_pebbles(), place);
    says(&format!("**{} pebbles for each place**", spaced(place)));
    for (bytes, places) in [(223, 1), (300, 0), (500, 3)] {
        assert_eq!(
            cairn_chain::fee_floor(bytes, places, &params).as_pebbles(),
            10 * bytes as u64 + place * places as u64,
            "the floor is not the two parts the guide adds"
        );
    }
    says(&format!(
        "One CAIRN is {} pebbles",
        spaced(PEBBLES_PER_CAIRN)
    ));
}

/// **The schedule the guide gives an aggregator is the one the rules pay.**
#[test]
fn the_schedule_the_guide_gives_is_the_one_the_rules_pay() {
    let params = ConsensusParams::testnet();
    says(&format!(
        "The reward halves every {} blocks, from {} CAIRN, until halving would take it below {} CAIRN",
        spaced(params.halving_interval),
        params.initial_reward.as_pebbles() / PEBBLES_PER_CAIRN,
        "0.01"
    ));
    assert_eq!(params.tail_reward.as_pebbles(), PEBBLES_PER_CAIRN / 100);

    let floor_from = 13 * params.halving_interval;
    assert_eq!(params.reward_at(floor_from), params.tail_reward);
    assert!(params.reward_at(floor_from - 1) > params.tail_reward);
    let before = params.emitted_by(floor_from - 1);
    says(&format!(
        "<td><code>floorFrom</code></td><td class=\"n\">{floor_from}</td>"
    ));
    says(&format!(
        "<td><code>beforeTheFloor</code></td><td class=\"n\">{}</td>",
        before.in_cairn()
    ));
    says(&format!(
        "<td><code>floorPerBlock</code></td><td class=\"n\">{}</td>",
        params.tail_reward.in_cairn()
    ));

    let a_year = 525_600 * params.tail_reward.as_pebbles() / PEBBLES_PER_CAIRN;
    says(&format!("the floor adds {} CAIRN a year", spaced(a_year)));
    assert_eq!(
        Amount::MAX_MONEY.as_pebbles() / PEBBLES_PER_CAIRN,
        1_000_000_000
    );
    says("one billion CAIRN, is the most any amount can hold");
    let years = (Amount::MAX_MONEY.as_pebbles() - before.as_pebbles())
        / (525_600 * params.tail_reward.as_pebbles());
    let rounded = (years + 5_000) / 10_000 * 10_000;
    says(&format!("about {} years", spaced(rounded)));
    says(&format!(
        "a coinbase's notes wait {} blocks",
        spaced(params.coinbase_maturity)
    ));
}

/// **The hot set the guide sizes a node by is the figure the whitepaper
/// gives, which `published_figures.rs` holds to the code.**
#[test]
fn the_hot_set_the_guide_sizes_a_node_by_is_the_papers() {
    let key = "<span class=\"k\">Hot set at capacity</span><span class=\"v\">";
    let figure = PAPER
        .split_once(key)
        .unwrap()
        .1
        .split_once("</span>")
        .unwrap()
        .0;
    says(&format!("which is about {figure} at capacity"));
}

/// **The wallet facts the guide states are the wallet's.**
#[test]
fn what_the_guide_says_of_the_wallet_is_what_the_wallet_says() {
    let help = flowing(help_of("cairn-wallet"));
    assert!(help.contains("cairn-wallet backup <key file>"));
    assert!(help.contains("history.dat") && help.contains("pending.dat"));
    says("`cairn-wallet backup` copies all three");
    assert!(help.contains("--fee-anyway"));
    says("unless told `--fee-anyway`");
    assert_eq!(
        cairn_wallet::phrase::path(NetworkId::TESTNET),
        Ok([44, 1, 0, 0, 0])
    );
    assert_eq!(
        cairn_wallet::phrase::path(NetworkId::DEVNET),
        Ok([44, 1, 0, 0, 0])
    );
    says("`m/44'/1'/0'/0'/0'` on every test network");
    assert!(cairn_wallet::phrase::path(NetworkId::MAINNET).is_err());
    says("on mainnet a wallet makes no key from words at all");
    // The case the guide points at, and the field it reads.
    assert!(REVERSED.contains(r#"after.contains("\"undone\":[{")"#));
    says("`crates/cairn-wallet/tests/a_payment_reversed_ten_blocks_deep.rs`");
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Mines blocks on a private ledger, so a branch can be built to one side.
#[derive(Clone)]
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn carrying(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::with_extra(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
            miner.public_key().as_bytes()[..4].to_vec(),
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_many(&mut self, miner: &SecretKey, count: usize) -> Vec<Block> {
        (0..count)
            .map(|_| self.carrying(miner, Vec::new()))
            .collect()
    }
}

fn explorer(params: ConsensusParams, blocks: &[Block]) -> Explorer {
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let explorer = Explorer::new(Node::bind(params, address).expect("a node on a free port"));
    feed(&explorer, blocks);
    explorer
}

fn feed(explorer: &Explorer, blocks: &[Block]) {
    for block in blocks {
        explorer
            .node()
            .submit_block(block.clone())
            .expect("a block this node built the ledger for");
    }
    explorer.refresh();
}

fn ask(explorer: &Explorer, rest: &str) -> Response {
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    explorer
        .answer(&Request {
            path: format!("/api/{path}"),
            query: query.to_owned(),
            head_only: false,
            post: false,
            body: String::new(),
            host: String::new(),
            origin: String::new(),
        })
        .expect("an API route answered")
}

fn body(answer: &Response) -> String {
    String::from_utf8_lossy(&answer.body).into_owned()
}

/// **A transfer whose block a reorganisation undid is answered as back in
/// the pool, with no confirmations, which is what the guide tells an
/// integrator to look for.**
#[test]
fn a_transfer_its_block_lost_is_answered_as_back_in_the_pool() {
    let mut params = ConsensusParams::testnet();
    params.coinbase_maturity = 0;
    let miner = wallet(1);
    let rival = wallet(9);
    let mut base = Forge::new(params);
    let common = base.mine_many(&miner, 3);

    let paid = &common[0];
    let note = paid.coinbase.outputs[0];
    let half = Amount::from_pebbles(note.value.as_pebbles() / 2).unwrap();
    let mut payment = Transfer::new(
        vec![Input::hot(NoteId::new(paid.coinbase.id(), 0))],
        vec![Note::new(half, wallet(3).public_key())],
    );
    payment.sign_input(params.network, 0, &note, &miner);

    let mut honest = base.clone();
    let carried = vec![honest.carrying(&miner, vec![payment.clone()])];
    let mut heavier = base.clone();
    let replaced = heavier.mine_many(&rival, 2);

    let explorer = explorer(params, &common);
    feed(&explorer, &carried);
    let before = body(&ask(&explorer, &format!("tx/{}", payment.id())));
    assert!(before.contains("\"pooled\":false"), "{before}");
    assert!(before.contains("\"confirmations\":1"), "{before}");

    feed(&explorer, &replaced);
    assert_eq!(explorer.node().height(), Some(4), "the heavier branch won");
    let after = body(&ask(&explorer, &format!("tx/{}", payment.id())));
    assert!(after.contains("\"pooled\":true"), "{after}");
    assert!(after.contains("\"confirmations\":0"), "{after}");
    says("answers `\"pooled\":true` with `confirmations` 0");
    explorer.node().shutdown();
}

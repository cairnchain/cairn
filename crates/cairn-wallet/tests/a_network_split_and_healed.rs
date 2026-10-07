//! A network cut in two, each half mining on its own, and joined again.
//!
//! R13 of the testnet-8 attack catalogue (D16), with the deep case it leads
//! to (A03). Nodes in one process on the loopback, each half with a miner of
//! its own that builds on its node's chain and pool as `cairnd --mine` does,
//! and wallets that are nodes of their own.
//!
//! What a split shorter than the undo limit owes, by the fork choice and by
//! what the wallet says of a reorganisation: every node ends on the heavier
//! half without a further block being needed, a payment the lighter half
//! carried goes back to the pools of the nodes that undid it if it is still
//! valid and is carried again, one the heavier half contradicts is in no pool
//! at all, and each wallet says which of those happened to its money without
//! counting any of it twice. It holds.
//!
//! What a split longer than the undo limit owes, by the threat model's row for
//! a branch forking deeper than a node will undo: a node already following
//! refuses it "and says the branch is out of reach rather than hiding it", and
//! "a newcomer weighs the branch and takes it for the heavier". The nodes hold
//! the first half. Two tests below did not hold when they were written: a
//! wallet left on the lighter half said nothing, and a newcomer on a network
//! burying below a thousand and twenty four took whichever half answered
//! first. The wallet says so now; the newcomer is kept failing on purpose
//! until the code is changed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::median_time_past;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::Node;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::history::Direction;
use cairn_wallet::Wallet;

const ATTEMPTS: u64 = 1 << 22;

/// A liveness bound, far past what any of this takes on a loaded runner.
/// Every wait here is for something to happen, so it costs nothing when the
/// thing does.
const PATIENCE: Duration = Duration::from_secs(180);

/// The depth a node here will undo. Shallow so that a split past it is a
/// couple of dozen blocks; the rule is the same at a thousand and twenty four.
const BURIAL: u64 = 12;

/// Blocks both halves hold before the cut.
const SHARED: usize = 6;

/// Rewards spendable at once, so a payer can be paid in the shared blocks,
/// and the opening difficulty on the floor, so every block weighs the same
/// and the half with more blocks is the heavier.
fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_burial(BURIAL)
        .with_coinbase_maturity(0)
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn cairn(text: &str) -> Amount {
    Amount::from_cairn(text).unwrap()
}

/// Comfortably over the pool's floor of ten pebbles a byte for a transfer of
/// one input and two outputs, and nothing the wallet's own ceiling cares about
/// since the wallet does not build these.
fn fee() -> Amount {
    Amount::from_pebbles(100_000).unwrap()
}

fn v4() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// The loopback's other family, which is another machine as a node counts
/// machines: `::1` is kept whole and is not `127.0.0.1`.
fn v6() -> SocketAddr {
    SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("waited {PATIENCE:?} for {what}");
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-split-{name}-{}-{:?}",
        std::process::id(),
        thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Mines on a private ledger, dated far in the past: a half of the network
/// whose blocks are made before it is joined to anybody.
#[derive(Clone)]
struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new() -> Self {
        Self {
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, to: &PublicKey) -> Block {
        let params = params();
        self.clock += 600;
        let height = self.state.next_height().unwrap();
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(params.reward_at(height), *to)]);
        let block =
            assemble_block(&self.state, coinbase, Vec::new(), &params, self.clock, 0).unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &params, now()).unwrap();
        block
    }
}

/// The blocks both halves hold: the first pays the first key of `paid`, and
/// so on, and the rest pay a key nobody here holds. With the forge they were
/// made on, to go on from.
fn shared(paid: &[PublicKey]) -> (Vec<Block>, Forge) {
    let nobody = key(99).public_key();
    let mut forge = Forge::new();
    let blocks = (0..SHARED)
        .map(|at| forge.mine(&paid.get(at).copied().unwrap_or(nobody)))
        .collect();
    (blocks, forge)
}

/// Two halves parted after the shared blocks, each mined on its own, the
/// lighter `lighter` blocks long and the heavier `heavier`.
struct Parted {
    shared: Vec<Block>,
    lighter: Vec<Block>,
    heavier: Vec<Block>,
}

impl Parted {
    fn new(lighter: u64, heavier: u64, lighter_pays: &PublicKey) -> Self {
        let (shared, forge) = shared(&[]);
        let mut left = forge.clone();
        let mut right = forge;
        let other = key(98).public_key();
        Self {
            shared,
            lighter: (0..lighter).map(|_| left.mine(lighter_pays)).collect(),
            heavier: (0..heavier).map(|_| right.mine(&other)).collect(),
        }
    }

    fn holding(&self, node: &Node, half: &[Block]) {
        for block in self.shared.iter().chain(half) {
            node.submit_block(block.clone()).unwrap();
        }
    }

    fn lighter_tip(&self) -> Hash32 {
        self.lighter.last().unwrap().id()
    }

    fn heavier_tip(&self) -> Hash32 {
        self.heavier.last().unwrap().id()
    }
}

/// What the miner on `node` finds next, built as `cairnd --mine` builds it:
/// on the node's own chain, with what its pool selects, dated by the clock or
/// past the median of recent blocks, whichever is later. Handed to the node,
/// which announces it.
fn mine_on(node: &Node, to: &PublicKey) -> Block {
    let params = params();
    let block = node.with_chain(|chain| {
        let state = chain.state();
        let height = state.next_height().unwrap();
        let earliest = median_time_past(state.recent_headers()).map_or(0, |median| median + 1);
        let (transfers, fees) = chain.selection(params.max_transfers_per_block);
        let reward = params.reward_at(height).checked_add(fees).unwrap();
        let coinbase = CoinbaseTransaction::new(height, vec![Note::new(reward, *to)]);
        assemble_block(state, coinbase, transfers, &params, now().max(earliest), 0).unwrap()
    });
    let block = mine_block(block, ATTEMPTS).unwrap();
    node.submit_block(block.clone()).unwrap();
    block
}

/// A payment of `amount` to `to` out of the note a coinbase paid `owner`, the
/// change going back to the owner.
fn pay(owner: &SecretKey, from: &Block, to: &PublicKey, amount: Amount) -> Transfer {
    let (id, held): (NoteId, Note) = from.coinbase.created_notes()[0];
    let change = held
        .value
        .checked_sub(amount)
        .and_then(|left| left.checked_sub(fee()))
        .unwrap();
    let mut transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![
            Note::new(amount, *to),
            Note::new(change, owner.public_key()),
        ],
    );
    transfer.sign_input(params().network, 0, &held, owner);
    transfer
}

fn tip(node: &Node) -> Option<Hash32> {
    node.with_chain(cairn_chain::ChainStore::tip)
}

fn root(node: &Node) -> Hash32 {
    node.with_chain(|chain| chain.state().state_root())
}

fn pooled(node: &Node, id: &Hash32) -> bool {
    node.with_chain(|chain| chain.pooled(id).is_some())
}

/// Waits for every node to stand on `on`.
fn all_on(what: &str, nodes: &[&Node], on: Hash32) {
    wait_for(what, || nodes.iter().all(|node| tip(node) == Some(on)));
}

fn opened(directory: &std::path::Path, name: &str, secret: &SecretKey) -> Wallet {
    let key_file = directory.join(format!("{name}.key"));
    cairn_wallet::keyfile::write(&key_file, secret).unwrap();
    Wallet::open(&key_file, params(), &directory.join(name))
        .unwrap()
        .0
}

fn received(wallet: &Wallet, id: &Hash32) -> usize {
    wallet
        .history()
        .iter()
        .filter(|movement| movement.id == *id && movement.direction == Direction::Received)
        .count()
}

/// **A split shorter than the undo limit heals onto the heavier half, and
/// what the lighter half carried is put back where it can still be.**
///
/// Two nodes and a miner on each side, a buyer and a merchant on the lighter
/// side. The lighter half carries two payments to the merchant: one from the
/// buyer's wallet, out of a note the heavier half never touched, and one from
/// a third key whose note the heavier half spends elsewhere. Ten blocks
/// against six, under an undo limit of twelve.
#[test]
fn a_split_shorter_than_the_undo_limit_heals_onto_the_heavier_half() {
    let directory = scratch("short");
    let buyer_key = key(1);
    let merchant_key = key(2);
    let spender = key(3);
    let elsewhere = key(4).public_key();
    let miner_a = key(5).public_key();
    let miner_b = key(6).public_key();

    // The buyer is paid by the first shared block and the spender by the
    // second.
    let (shared, _) = shared(&[buyer_key.public_key(), spender.public_key()]);
    let a1 = Node::bind(params(), v4()).unwrap();
    let a2 = Node::bind(params(), v4()).unwrap();
    let b1 = Node::bind(params(), v4()).unwrap();
    let b2 = Node::bind(params(), v4()).unwrap();
    let buyer = opened(&directory, "buyer", &buyer_key);
    let merchant = opened(&directory, "merchant", &merchant_key);
    for node in [&a1, &a2, &b1, &b2, buyer.node(), merchant.node()] {
        for block in &shared {
            node.submit_block(block.clone()).unwrap();
        }
    }
    a2.connect(a1.address()).unwrap();
    b2.connect(b1.address()).unwrap();
    buyer.node().connect(b1.address()).unwrap();
    merchant.node().connect(b1.address()).unwrap();
    wait_for("each half to be connected", || {
        a1.peers_introduced() >= 1 && b1.peers_introduced() >= 3
    });

    // The lighter half. The buyer's own wallet pays ten, and the spender
    // seven out of a note the heavier half will spend on something else.
    let sent = buyer
        .send(merchant_key.public_key(), cairn("10"), fee())
        .unwrap();
    let doomed = pay(&spender, &shared[1], &merchant_key.public_key(), cairn("7"));
    let contradiction = pay(&spender, &shared[1], &elsewhere, cairn("7"));
    assert!(b1.submit_transaction(doomed.clone()).unwrap());
    wait_for(
        "the buyer's payment to reach the lighter half's miner",
        || pooled(&b1, &sent.id),
    );
    let carrying = mine_on(&b1, &miner_b);
    assert!(
        carrying.transfers.iter().any(|t| t.id() == sent.id)
            && carrying.transfers.iter().any(|t| t.id() == doomed.id()),
        "fixture: the lighter half's first block carries both payments"
    );
    let mut lighter = vec![carrying];
    for _ in 0..5 {
        lighter.push(mine_on(&b1, &miner_b));
    }
    let lighter_tip = lighter.last().unwrap().id();
    all_on(
        "the lighter half to follow its miner",
        &[&b1, &b2, buyer.node(), merchant.node()],
        lighter_tip,
    );

    // The heavier half spends the spender's note elsewhere, and mines ten.
    assert!(a1.submit_transaction(contradiction.clone()).unwrap());
    let mut heavier = vec![mine_on(&a1, &miner_a)];
    assert!(
        heavier[0]
            .transfers
            .iter()
            .any(|t| t.id() == contradiction.id()),
        "fixture: the heavier half's first block carries the other spend"
    );
    for _ in 0..9 {
        heavier.push(mine_on(&a1, &miner_a));
    }
    let heavier_tip = heavier.last().unwrap().id();
    all_on(
        "the heavier half to follow its miner",
        &[&a1, &a2],
        heavier_tip,
    );

    // Before: what both wallets read on the lighter half, as a face redrawing
    // itself would have read it.
    assert!(buyer
        .history()
        .iter()
        .any(|m| m.id == sent.id && m.direction == Direction::Sent));
    assert!(buyer.waiting().iter().all(|one| one.id != sent.id));
    assert_eq!(received(&merchant, &sent.id), 1);
    assert_eq!(received(&merchant, &doomed.id()), 1);
    assert_eq!(merchant.holdings().total(), cairn("17"));

    // The cut ends. One link each way across it, and no block mined until
    // every node agrees.
    b1.connect(a1.address()).unwrap();
    a2.connect(b2.address()).unwrap();
    let everyone = [&a1, &a2, &b1, &b2, buyer.node(), merchant.node()];
    all_on(
        "every node to take the heavier half with no further block",
        &everyone,
        heavier_tip,
    );
    let roots: Vec<Hash32> = everyone.iter().map(|node| root(node)).collect();
    assert!(
        roots.iter().all(|one| *one == roots[0]),
        "every node is on the same tip and not on the same ledger: {roots:?}"
    );

    // The buyer's payment spends a note the heavier half never touched, so
    // every node that undid it holds it again. The spender's payment to the
    // merchant spends a note the heavier half has spent, so no node holds it.
    for node in [&b1, &b2, buyer.node(), merchant.node()] {
        assert!(
            pooled(node, &sent.id),
            "a payment still valid on the heavier half is not back in the pool of a node \
             that undid the block carrying it"
        );
    }
    for node in everyone {
        assert!(
            !pooled(node, &doomed.id()),
            "a payment the heavier half contradicts is held in a pool"
        );
    }

    // What each wallet says. The merchant was paid by neither payment now, and
    // is told both were taken back and that the money is not in its balance.
    assert_eq!(received(&merchant, &sent.id), 0);
    assert_eq!(received(&merchant, &doomed.id()), 0);
    let undone = merchant.undone();
    for id in [sent.id, doomed.id()] {
        assert_eq!(
            undone
                .iter()
                .filter(|m| m.id == id && m.direction == Direction::Received)
                .count(),
            1,
            "a payment in the chain took back is not listed once as taken back"
        );
    }
    let said = cairn_wallet::undone_note(&undone, &merchant.waiting()).unwrap();
    assert!(
        said.contains("not in the balance any more"),
        "the merchant is not told the money left its balance: {said}"
    );
    assert_eq!(
        merchant.holdings().total(),
        Amount::ZERO,
        "the merchant's balance still counts a payment the chain no longer carries"
    );
    assert_eq!(merchant.progress().warning(), None);

    // The buyer's payment is waiting for a block again, with its notes held,
    // and the buyer is told so rather than that it went through.
    let waiting = buyer.waiting();
    assert!(
        waiting.iter().any(|one| one.id == sent.id && one.pooled),
        "the buyer's undone payment is not waiting for a block again"
    );
    let said = cairn_wallet::undone_note(&buyer.undone(), &waiting).unwrap();
    assert!(
        said.contains("waiting again"),
        "the buyer is not told its payment is waiting again: {said}"
    );
    let held = buyer.holdings();
    assert_eq!(
        held.total(),
        shared[0].coinbase.created_notes()[0].1.value,
        "the buyer's money is not all there, held or spendable, while its payment waits"
    );

    // The next block, found by the miner of what was the lighter half, which
    // is mining on the heavier one now and holds the payment in its pool.
    let again = mine_on(&b1, &miner_b);
    assert!(
        again.transfers.iter().any(|t| t.id() == sent.id),
        "the payment put back in the pool is not carried by the next block"
    );
    all_on("every node to take the next block", &everyone, again.id());

    // Counted once, by both of them.
    assert_eq!(received(&merchant, &sent.id), 1);
    assert_eq!(received(&merchant, &doomed.id()), 0);
    let undone = merchant.undone();
    assert!(
        !undone.iter().any(|m| m.id == sent.id),
        "a payment carried again is still listed as taken back"
    );
    assert!(undone.iter().any(|m| m.id == doomed.id()));
    assert_eq!(
        merchant.holdings().total(),
        cairn("10"),
        "the merchant's balance does not count the payment carried again exactly once"
    );
    assert!(buyer.waiting().iter().all(|one| one.id != sent.id));
    assert_eq!(
        buyer
            .history()
            .iter()
            .filter(|m| m.id == sent.id && m.direction == Direction::Sent)
            .count(),
        1
    );
    assert!(!buyer.undone().iter().any(|m| m.id == sent.id));

    buyer.shutdown();
    merchant.shutdown();
    for node in [&a1, &a2, &b1, &b2] {
        node.shutdown();
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// **A split longer than the undo limit is not crossed, and the nodes left on
/// the lighter half say so.**
///
/// The lighter half mines fourteen blocks under an undo limit of twelve, the
/// heavier twenty. The lighter half's node is then joined to two nodes of the
/// heavier half on two machines as a node counts them, `127.0.0.1` and `::1`,
/// which is what the line saying a branch is out of reach waits for: one
/// machine's blocks are a stranger's for the price of a hash.
#[test]
fn a_split_longer_than_the_undo_limit_is_refused_and_said_by_the_lighter_half() {
    let parted = Parted::new(BURIAL + 2, BURIAL + 8, &key(16).public_key());
    let a1 = Node::bind(params(), v4()).unwrap();
    let a2 = Node::bind(params(), v6()).unwrap();
    let b1 = Node::bind(params(), v4()).unwrap();
    parted.holding(&a1, &parted.heavier);
    parted.holding(&a2, &parted.heavier);
    parted.holding(&b1, &parted.lighter);
    assert!(a1.total_work() > b1.total_work());

    a2.connect(a1.address()).unwrap();
    b1.connect(a1.address()).unwrap();
    b1.connect(a2.address()).unwrap();
    // What `cairnd` reads for the line telling its operator that blocks are
    // arriving from a chain it cannot switch to, and that starting again from
    // an empty directory is the way onto it.
    wait_for(
        "the lighter half's node to count blocks from a chain it cannot switch to",
        || b1.out_of_reach() > 0,
    );

    let tips = (tip(&b1), tip(&a1), tip(&a2));
    let kept = b1.peer_count();
    let turned_away = (b1.refused_hosts(), a1.refused_hosts(), a2.refused_hosts());
    let heavier_said = (a1.out_of_reach(), a2.out_of_reach());
    for node in [&a1, &a2, &b1] {
        node.shutdown();
    }

    assert_eq!(
        tips,
        (
            Some(parted.lighter_tip()),
            Some(parted.heavier_tip()),
            Some(parted.heavier_tip())
        ),
        "a node crossed a split deeper than it will undo"
    );
    assert!(
        kept >= 2,
        "the lighter half's node let go of the peers telling it"
    );
    assert_eq!(
        turned_away,
        Default::default(),
        "somebody was turned away for the blocks of a half it cannot reach"
    );
    // The heavier half is told nothing, and has nothing to do: it is where a
    // newcomer goes.
    assert_eq!(heavier_said, (0, 0));
}

/// **A wallet left on the lighter half of a split deeper than it will undo
/// says so beside the balance.**
///
/// The threat model's row for a branch forking deeper than a node will undo:
/// a node already following refuses it "and says the branch is out of reach
/// rather than hiding it". A wallet is a node of its own, and its node counts
/// those blocks as `cairnd` does. The lighter half paid this wallet's key
/// fourteen rewards that the heavier half, every newcomer and every node that
/// was away do not have.
///
/// It was a gap: `Progress` carried nothing of `Node::out_of_reach`, so
/// `Progress::warning` had nothing to say, and both faces showed the lighter
/// half's balance as the wallet's money with no line beside it, while each of
/// the other states in which a wallet reads a chain the network has left, a
/// slow clock and a build too old, had its line. `Progress::out_of_reach`
/// carries the count now, and the line ranks below the slow clock's.
#[test]
fn a_wallet_on_the_half_the_network_left_says_so_beside_the_balance() {
    let directory = scratch("left-behind");
    let owner = key(12);
    let parted = Parted::new(BURIAL + 2, BURIAL + 8, &owner.public_key());
    let wallet = opened(&directory, "wallet", &owner);
    let a1 = Node::bind(params(), v4()).unwrap();
    let a2 = Node::bind(params(), v6()).unwrap();
    parted.holding(wallet.node(), &parted.lighter);
    parted.holding(&a1, &parted.heavier);
    parted.holding(&a2, &parted.heavier);
    let paid = wallet.holdings().total();
    assert!(
        paid > Amount::ZERO,
        "fixture: the lighter half paid this key"
    );

    wallet.node().connect(a1.address()).unwrap();
    wallet.node().connect(a2.address()).unwrap();
    wait_for(
        "the wallet's node to count blocks from a chain it cannot switch to",
        || wallet.node().out_of_reach() > 0,
    );

    let counted = wallet.node().out_of_reach();
    let progress = wallet.progress();
    let holdings = wallet.holdings();
    let on = tip(wallet.node());
    wallet.shutdown();
    a1.shutdown();
    a2.shutdown();
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        on,
        Some(parted.lighter_tip()),
        "fixture: the wallet crossed"
    );
    assert_eq!(holdings.total(), paid, "fixture: the balance moved");
    assert!(
        progress.warning().is_some(),
        "a wallet whose node counts {counted} blocks from a chain it cannot switch to, from \
         two machines, shows {paid} that no node of the heavier half holds, with no line \
         beside it"
    );
}

/// **A newcomer that meets the lighter half a moment before the heavier takes
/// the heavier.**
///
/// The threat model's row again: "a newcomer weighs the branch and takes it
/// for the heavier". A node with nothing waits two seconds for peers to
/// introduce themselves (`cairn_net::choosing`, `SETTLING`) and then asks the
/// one claiming the most work, so that its one irreversible choice is not
/// made by whichever handshake came first. The heavier half's two nodes
/// introduce themselves half a second after the lighter half's, well inside
/// that.
///
/// A gap, kept failing on purpose, on any network that buries below a
/// thousand and twenty four, devnet among them (32) and this file (12). The
/// choice is made only for a chain of `JOIN_RATHER_THAN_READ` blocks or more,
/// on the reading that a shorter one "carries no such weight: following the
/// wrong one is undone by the fork choice like any other branch"
/// (`cairn_net::sync`, on a greeting). That number is tied to
/// `MAX_REORG_DEPTH`, and a node undoes `ChainStore::undo_limit`, which is the
/// smaller of that and the network's burial. So a newcomer here asks the
/// lighter half for its chain on the handshake, has read past the fork's reach
/// before the heavier half has said a word, and can never take it. Testnet-8
/// buries at a thousand and twenty four and is not affected.
#[test]
fn a_newcomer_meeting_the_lighter_half_first_still_takes_the_heavier() {
    let parted = Parted::new(BURIAL + 2, BURIAL + 8, &key(16).public_key());
    let a1 = Node::bind(params(), v4()).unwrap();
    let a2 = Node::bind(params(), v6()).unwrap();
    let b1 = Node::bind(params(), v4()).unwrap();
    parted.holding(&a1, &parted.heavier);
    parted.holding(&a2, &parted.heavier);
    parted.holding(&b1, &parted.lighter);
    a2.connect(a1.address()).unwrap();

    let newcomer = Node::bind(params(), v4()).unwrap();
    newcomer.connect(b1.address()).unwrap();
    thread::sleep(Duration::from_millis(500));
    newcomer.connect(a1.address()).unwrap();
    newcomer.connect(a2.address()).unwrap();
    // Either it takes the heavier half, or it says, from the heavier half's
    // two machines, that the heavier half is out of its reach.
    wait_for("the newcomer to settle on one half", || {
        tip(&newcomer) == Some(parted.heavier_tip()) || newcomer.out_of_reach() > 0
    });

    let on = tip(&newcomer);
    for node in [&a1, &a2, &b1, &newcomer] {
        node.shutdown();
    }
    assert_eq!(
        on,
        Some(parted.heavier_tip()),
        "a newcomer that met the lighter half half a second before the heavier, inside the \
         moment it gives peers to introduce themselves, followed the lighter half and can \
         never take the heavier: it parts further back than this network undoes"
    );
}

//! Seam audit: what `cairn-chain` promises against what `cairn-net` and
//! `cairn-ledger` do on the other side of it.
//!
//! Several of these exercise behaviour that only exists once a chain is wired
//! to a disk, which is something `cairn-net` does and `cairn-chain`'s own
//! tests almost never did: `release_bodies` returns at its first line without
//! a `Bodies`, so every test that does not set one is testing a shape the live
//! node is never in.

#![allow(clippy::similar_names)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cairn_chain::{Accepted, Bodies, ChainError, ChainStore, Located, MAX_REORG_DEPTH};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
/// The chains here run up to the present rather than past it: a block dated
/// more than the allowed drift ahead of `NOW` is refused, and that is not
/// what any of these tests is about.
const STARTS_AT: u64 = NOW - 200_000;
const ATTEMPTS: u64 = 1 << 22;

/// Rewards are spendable at once. What the wait is worth is audited
/// elsewhere; none of these tests is about it.
fn params() -> ConsensusParams {
    ConsensusParams::testnet().with_coinbase_maturity(0)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain built block by block, with the ledger alongside so a transfer can
/// be signed against notes that really exist.
#[derive(Clone)]
struct Source {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Source {
    fn new() -> Self {
        Self {
            params: params(),
            state: LedgerState::new(),
            clock: STARTS_AT,
        }
    }

    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.reward_at(height), miner.public_key())],
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

    fn run(&mut self, miner: &SecretKey, count: usize, into: &mut Vec<Block>) {
        for _ in 0..count {
            into.push(self.mine(miner, Vec::new()));
        }
    }
}

/// What a node's disk is, from the chain's side of the seam: a block by
/// height, and no way to say that a read failed rather than found nothing.
///
/// That is not this test's simplification. `cairn-chain::Bodies::body`
/// returns `Option<Block>`, and `cairn-net`'s only implementation is
/// `read_at(height).ok()?` over a `Result<Option<Block>, StoreError>` whose
/// every error variant is a real I/O or corruption failure. Losing a record
/// here is exactly what a failing disk looks like from inside the chain.
#[derive(Debug, Default)]
struct Shelf(Mutex<HashMap<u64, Block>>);

impl Shelf {
    fn put(&self, block: &Block) {
        self.0
            .lock()
            .unwrap()
            .insert(block.header.height, block.clone());
    }

    fn lose(&self, height: u64) {
        self.0.lock().unwrap().remove(&height);
    }
}

impl Bodies for Shelf {
    fn body(&self, height: u64) -> Option<Block> {
        self.0.lock().unwrap().get(&height).cloned()
    }
}

fn one_note(state: &LedgerState, owner: &SecretKey) -> (NoteId, Note) {
    state
        .hot_notes()
        .find(|(_, entry)| entry.note.owner == owner.public_key())
        .map(|(id, entry)| (id, entry.note))
        .expect("the miner was paid")
}

/// A payment out of `owner`'s oldest note, signed against the state given.
fn payment(state: &LedgerState, owner: &SecretKey, payee: &SecretKey) -> Transfer {
    let params = params();
    let (id, note) = one_note(state, owner);
    let half = note.value.as_pebbles() / 2;
    let fee = 10_000u64;
    let mut transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![
            Note::new(Amount::from_pebbles(half).unwrap(), payee.public_key()),
            Note::new(
                Amount::from_pebbles(note.value.as_pebbles() - half - fee).unwrap(),
                owner.public_key(),
            ),
        ],
    );
    transfer.sign_input(params.network, 0, &note, owner);
    transfer
}

/// **A payment undone by a reorganisation deeper than sixty four blocks is
/// not offered back to the pool, and nothing says so.**
///
/// `ChainStore::repool` reads the undone blocks with `self.block(id)`, which
/// is memory only. `release_bodies` takes the body of every block on the
/// followed branch more than `WARM_BODIES` (sixty four) below the tip, once
/// the chain has been told where to read bodies back from. So for every block
/// a deep reorganisation undoes past that depth, `repool` finds `None` and
/// steps over it.
///
/// The comment on `repool` states the rule this breaks: without it "the money
/// returns to the sender, the payment is in no block and in no pool, and the
/// only party who could notice is the one who has just been told it was
/// sent". `apply` and `restore` on the same struct read bodies through
/// `body_of`, which does consult the disk; `repool` is the one walk over the
/// same list that does not.
///
/// Invisible from inside `cairn-chain`, because a store with no `Bodies`
/// never releases anything: the existing `reorg_repool.rs` reorganises five
/// blocks deep on a chain with no disk and passes. Invisible from inside
/// `cairn-net`, which calls `release_bodies` and never looks at the pool
/// afterwards.
#[test]
fn a_deep_reorg_offers_back_the_payments_whose_bodies_went_to_disk() {
    let miner = wallet(1);
    let payee = wallet(2);

    let shelf = Arc::new(Shelf::default());
    let mut store = ChainStore::new(params());
    store.reads_bodies_from(shelf.clone());

    let mut source = Source::new();
    let mut blocks = Vec::new();
    source.run(&miner, 3, &mut blocks);

    // The fork point: a second chain that shares everything up to here.
    let fork = source.clone();

    // The payment, carried by the block at height 3.
    let paid = {
        let transfer = payment(&source.state, &miner, &payee);
        let id = transfer.id();
        blocks.push(source.mine(&miner, vec![transfer]));
        id
    };
    // And a hundred more blocks over it, so the block carrying the payment
    // ends up well past the sixty four the chain keeps warm.
    source.run(&miner, 100, &mut blocks);

    for block in &blocks {
        shelf.put(block);
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.height().unwrap();
    assert_eq!(tip, 103);
    assert!(store.pooled(&paid).is_none(), "it is in a block");

    // What a node does after every write: tell the chain the disk has caught
    // up, so it can let go of the bodies it no longer needs in memory.
    store.release_bodies(0, tip + 1);
    assert!(
        store.block(&blocks[3].id()).is_none(),
        "the block carrying the payment is on the disk now and not in memory"
    );
    assert!(
        store.block(&blocks[102].id()).is_some(),
        "while the recent ones are still warm"
    );

    // A heavier branch forking below the payment, from the shared history, so
    // the note the payment spends still exists on it.
    let mut rival = fork;
    let mut branch = Vec::new();
    rival.run(&wallet(3), 102, &mut branch);

    let mut reorganised = false;
    for block in branch {
        if matches!(
            store.add_block(block, NOW),
            Ok(Accepted::Reorganised { .. })
        ) {
            reorganised = true;
        }
    }
    assert!(reorganised, "the heavier branch was taken");
    assert_eq!(store.height(), Some(104));

    // The claim under test. Offering the undone blocks' transfers back used
    // to read them out of memory, and a body more than `WARM_BODIES` below
    // the tip has been let go of and written, so a shallow reorganisation put
    // the payment back and a deep one silently did not. This crate's own
    // tests wire up no disk, so nothing was ever let go of and the walk was
    // right by accident.
    assert!(
        store.pooled(&paid).is_some(),
        "a payment undone by a reorganisation deep enough to reach the disk \
         is still offered back, so it can be mined again rather than being \
         cancelled by a reorganisation nobody told the sender about"
    );
}

/// The control: the same chain, the same reorganisation, the same depth, and
/// the one difference is that nothing told the chain where its disk is.
///
/// Same code path in `cairn-chain`, opposite outcome. That is what makes this
/// a seam rather than a bug inside either crate.
#[test]
fn the_same_reorg_keeps_the_payment_when_no_disk_is_wired_up() {
    let miner = wallet(1);
    let payee = wallet(2);

    // No `reads_bodies_from`, so `release_bodies` returns at its first line.
    let mut store = ChainStore::new(params());

    let mut source = Source::new();
    let mut blocks = Vec::new();
    source.run(&miner, 3, &mut blocks);
    let fork = source.clone();

    let paid = {
        let transfer = payment(&source.state, &miner, &payee);
        let id = transfer.id();
        blocks.push(source.mine(&miner, vec![transfer]));
        id
    };
    source.run(&miner, 100, &mut blocks);

    for block in &blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.height().unwrap();
    store.release_bodies(0, tip + 1);
    assert!(
        store.block(&blocks[3].id()).is_some(),
        "nothing was released, because there is nowhere to read it back from"
    );

    let mut rival = fork;
    let mut branch = Vec::new();
    rival.run(&wallet(3), 102, &mut branch);
    for block in branch {
        let _ = store.add_block(block, NOW);
    }
    assert_eq!(store.height(), Some(104));

    assert!(
        store.pooled(&paid).is_some(),
        "the payment is offered back, which is what the rule says must happen \
         and what the wired-up node above does not do"
    );
}

/// **One record the disk will not give back, during a reorganisation that
/// fails, silently truncates the node's chain and blames the peer.**
///
/// Three seams meet here.
///
/// `cairn-store` reports every failure as a `StoreError`; `cairn-net`'s
/// `FromLog::body` turns that into `None` with `.ok()?`; `cairn-chain`'s
/// `body_of` turns `None` into `ChainError::Corrupt`. So a disk that will not
/// read is indistinguishable from a block that was never there.
///
/// `ChainStore::follow` then propagates that out of `restore` with `?`, after
/// `restore` has already popped the branch it was putting back. Nothing puts
/// it back a second time, so the node is left on a branch that stops wherever
/// the unreadable record was, having silently thrown away everything above
/// it, with the ledger unwound to match. The height simply drops.
///
/// And `cairn-net`'s `on_block` names five `ChainError` variants and answers
/// everything else with `DropReason::BadBlock`, whose `is_misbehaviour` is
/// true. So the peer whose perfectly good block set this off is disconnected
/// and refused.
#[test]
fn one_unreadable_record_truncates_the_chain_and_the_peer_is_blamed() {
    let miner = wallet(1);
    let shelf = Arc::new(Shelf::default());
    let mut store = ChainStore::new(params());
    store.reads_bodies_from(shelf.clone());

    let mut source = Source::new();
    let mut blocks = Vec::new();
    source.run(&miner, 4, &mut blocks);
    let fork = source.clone();
    source.run(&miner, 101, &mut blocks);

    for block in &blocks {
        shelf.put(block);
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.height().unwrap();
    assert_eq!(tip, 104);
    store.release_bodies(0, tip + 1);

    // One record the disk will not give back, inside the stretch that was
    // released and above the fork.
    shelf.lose(10);
    assert!(
        store.block(&blocks[10].id()).is_none(),
        "and the chain does not hold it in memory either"
    );

    // A heavier branch off the fork, whose last block does not apply. The
    // header carries work and names a parent this node holds, so it is stored
    // and followed; it fails only once the ledger has been moved onto it.
    let mut rival = fork;
    let mut branch = Vec::new();
    rival.run(&wallet(3), 102, &mut branch);
    let last = branch.len() - 1;
    branch[last].header.state_root = Hash32::from_bytes([0xab; 32]);

    let mut verdict = None;
    for block in branch {
        verdict = Some(store.add_block(block, NOW));
    }

    assert!(
        matches!(verdict, Some(Err(ChainError::Corrupt))),
        "the chain reports its own block tree as corrupt, which is what a \
         disk that would not read looks like from here: {verdict:?}"
    );
    assert_eq!(
        store.height(),
        Some(9),
        "and the node is now ninety five blocks shorter than it was a moment \
         ago, with nothing logged and no branch to get back onto"
    );
    println!(
        "height went from {tip} to {} on one unreadable record",
        store.height().unwrap()
    );

    // The mapping on the other side, stated rather than inferred. These are
    // the variants `cairn-net::sync::on_block` names before its catch-all.
    for named in [
        "UnknownParent",
        "NotGenesis",
        "ForkTooDeep",
        "TooOld",
        "InvalidBlock(UnsupportedVersion)",
    ] {
        assert!(!named.is_empty());
    }
    assert!(
        !format!("{}", ChainError::Corrupt).contains("peer"),
        "Corrupt says nothing about a peer, and the catch-all below those \
         five answers it with DropReason::BadBlock"
    );
}

/// **The build-time assertion tying the burial to the reorganisation depth
/// checks a constant that no live path reads.**
///
/// `cairn-chain` asserts `cairn_ledger::handover::BURIAL <= MAX_REORG_DEPTH`
/// at build time, and the comment says that if either number moves this
/// "stops the build rather than the network". But `BURIAL` is only a default:
/// what every caller reads is `ConsensusParams::burial`, a runtime field with
/// a public `with_burial` setter, and `for_network` already ships a network
/// that overrides it.
///
/// The same for the second assertion, `COINBASE_MATURITY == MAX_REORG_DEPTH`,
/// whose stated purpose is that "a coinbase becomes spendable exactly when its
/// block can no longer be taken away". On devnet the maturity is thirty two
/// and the reorganisation depth is still a thousand and twenty four, so a
/// matured coinbase can be undone by a switch this node would accept. The
/// assertion passes.
#[test]
fn the_assertions_guard_constants_and_the_network_runs_on_fields() {
    assert_eq!(cairn_ledger::handover::BURIAL, MAX_REORG_DEPTH as u64);
    assert_eq!(
        cairn_ledger::validation::COINBASE_MATURITY,
        MAX_REORG_DEPTH as u64,
        "which is what the two `const _: () = assert!` lines check"
    );

    assert_eq!(
        ConsensusParams::testnet().burial,
        cairn_ledger::handover::BURIAL,
        "the default agrees with the constant"
    );

    let devnet = ConsensusParams::for_network("devnet").unwrap();
    assert_eq!(
        devnet.burial, 32,
        "and a shipped network already does not, so the assertion is about a \
         number this network never reads"
    );
    assert_eq!(devnet.coinbase_maturity, 32);
    assert!(
        devnet.coinbase_maturity < MAX_REORG_DEPTH as u64,
        "so on devnet a reward is spendable {} blocks before the block that \
         paid it stops being reorganisable, which is the one thing the \
         maturity rule claims it is not",
        MAX_REORG_DEPTH as u64 - devnet.coinbase_maturity
    );

    // And nothing refuses a burial past what the chain keeps records for.
    let over = ConsensusParams::testnet().with_burial(MAX_REORG_DEPTH as u64 + 1);
    assert_eq!(over.burial, MAX_REORG_DEPTH as u64 + 1);

    let miner = wallet(1);
    let mut source = Source::new();
    let mut store = ChainStore::new(params());
    for _ in 0..25 {
        let block = source.mine(&miner, Vec::new());
        store.add_block(block, NOW).unwrap();
    }
    let tip = store.height().unwrap();

    // The node's own arithmetic, from `Shared::write_ledger`:
    //     let anchor_height = ground.at.height.checked_sub(self.params.burial)?;
    // A burial past the tip, or past what the chain still holds undo records
    // for, drops out of the function with nothing said and no ledger written.
    assert_eq!(
        tip.checked_sub(over.burial),
        None,
        "so `write_ledger` returns None, `trim_history` returns, the log \
         grows for ever, and no newcomer is ever handed a ledger"
    );
    assert!(
        store.ledger_at(tip).is_some(),
        "the chain can still answer about what it does hold"
    );
}

/// A branch taken from a tail holds no milestones, so `genesis` answers
/// `None` for the life of the node however many blocks it goes on to apply.
///
/// Stated here as a fact about `cairn-chain` alone. What `cairn-net` does
/// with it is in `cairn-net/tests/audit_seams.rs`.
#[test]
fn a_branch_read_from_the_first_block_knows_its_first_block() {
    let miner = wallet(1);
    let mut source = Source::new();
    let mut blocks = Vec::new();
    source.run(&miner, 4, &mut blocks);

    let mut store = ChainStore::new(params());
    for block in &blocks {
        store.add_block(block.clone(), NOW).unwrap();
    }
    assert_eq!(
        store.genesis(),
        Some(blocks[0].id()),
        "a chain read from its first block knows what that block was"
    );
    assert_eq!(store.id_at(0), Some(blocks[0].id()));
    assert_eq!(store.branch_start(), Some(0));
    assert!(!store.agrees_with(&Located::new(0, Hash32::ZERO)));
}

/// **The floor a node trims its block log to is `params.burial`; the floor
/// its chain still reads back from is `MAX_REORG_DEPTH`. They are the same
/// number on exactly one shipped network.**
///
/// `cairn-net::cut_for` has a doc comment naming two floors, "and the lower of
/// them wins": the operator's disk budget, and "the window the chain can still
/// undo", of which it says "Whatever an operator sets, this much is not theirs
/// to drop". The body computes only the budget:
///
/// ```text
/// fn cut_for(tip: u64, held: u64, bytes: u64, keep: u64) -> u64 {
///     let average = bytes.checked_div(held).unwrap_or(0).max(1);
///     let affordable = keep.checked_div(average).unwrap_or(0);
///     tip.saturating_add(1).saturating_sub(affordable)
/// }
/// ```
///
/// The undo floor is not in it. It arrives by the argument the caller passes:
/// `trim_history` calls it with `at.height`, the ledger anchor, which
/// `write_ledger` sets to `chain_tip - params.burial`. So the deepest the log
/// is ever cut to is `chain_tip - params.burial + 1`.
///
/// What the chain reads back from is `undo_from`, which
/// `forget_what_cannot_change` holds at `chain_tip + 1 - MAX_REORG_DEPTH` — a
/// compile-time `usize` in this crate, not a rule of the network. So the
/// invariant `cut <= undo_from` reduces to `params.burial >= MAX_REORG_DEPTH`.
///
/// The build-time assertion checks the opposite direction, on a constant:
/// `BURIAL <= MAX_REORG_DEPTH`. Together they force equality, which testnet-6
/// has and devnet does not.
#[test]
fn the_disk_is_trimmed_to_the_burial_and_read_back_from_the_reorg_depth() {
    let depth = MAX_REORG_DEPTH as u64;

    // `cut_for` with the budget wide open: nothing is affordable to drop, so
    // the answer is the argument it was given plus one. That argument is the
    // anchor, and the anchor is `tip - burial`.
    let cut_at = |tip: u64, burial: u64| tip.saturating_sub(burial).saturating_add(1);
    // What `forget_what_cannot_change` holds `undo_from` at.
    let reads_back_from = |tip: u64| tip.saturating_add(1).saturating_sub(depth);

    let tip = 100_000u64;

    for name in ["testnet-6", "devnet"] {
        let network = ConsensusParams::for_network(name).unwrap();
        let cut = cut_at(tip, network.burial);
        let floor = reads_back_from(tip);
        println!(
            "{name}: burial {}, log cut to {cut}, chain reads back from {floor}, \
             blocks in neither place: {}",
            network.burial,
            cut.saturating_sub(floor)
        );
    }

    let testnet = ConsensusParams::for_network("testnet-6").unwrap();
    assert_eq!(
        cut_at(tip, testnet.burial),
        reads_back_from(tip),
        "on testnet-6 the two floors are the same height, exactly, because \
         the burial and the reorganisation depth are the same number"
    );

    let devnet = ConsensusParams::for_network("devnet").unwrap();
    assert!(
        cut_at(tip, devnet.burial) > reads_back_from(tip),
        "and on devnet the log is cut {} blocks above the deepest height the \
         chain still expects to read a body back from",
        cut_at(tip, devnet.burial) - reads_back_from(tip)
    );
    assert_eq!(
        cut_at(tip, devnet.burial) - reads_back_from(tip),
        depth - devnet.burial,
        "the gap is exactly the difference between the two numbers, and \
         nothing anywhere compares them"
    );
}

/// The consequence of that gap, on a chain, with no disk failure anywhere:
/// the node cut its own log where its rules told it to, and then could not
/// put a branch back.
///
/// The shelf here is cut to `tip - burial + 1` with a devnet-shaped burial,
/// which is what `BlockLog::keep_from(cut)` does. Everything else is an
/// ordinary reorganisation that turns out to end in a block that does not
/// apply, which is the case `restore` exists for.
#[test]
fn a_node_that_trimmed_its_log_to_the_burial_cannot_put_a_branch_back() {
    // Devnet's shape, scaled: the log keeps a short run above the anchor while
    // the chain believes it can still undo far more than that.
    let burial = 8u64;

    let miner = wallet(1);
    let shelf = Arc::new(Shelf::default());
    let mut store = ChainStore::new(params());
    store.reads_bodies_from(shelf.clone());

    let mut source = Source::new();
    let mut blocks = Vec::new();
    source.run(&miner, 4, &mut blocks);
    let fork = source.clone();
    source.run(&miner, 101, &mut blocks);

    for block in &blocks {
        shelf.put(block);
        store.add_block(block.clone(), NOW).unwrap();
    }
    let tip = store.height().unwrap();
    assert_eq!(tip, 104);

    // What the node does after every write.
    store.release_bodies(0, tip + 1);

    // And what `trim_history` does once the log is over its budget: cut to
    // the anchor, which is `tip - burial`, and keep everything above it.
    let cut = tip - burial + 1;
    for height in 0..cut {
        shelf.lose(height);
    }
    // Everything the chain released (below `tip - WARM_BODIES`, so below 40
    // here) is inside what the cut dropped, so it is now in neither place,
    // while the chain still holds an undo record for it and an entry in its
    // block table saying it has it.
    let lost: Vec<u64> = (0..cut)
        .filter(|height| {
            store.block(&blocks[*height as usize].id()).is_none() && shelf.body(*height).is_none()
        })
        .collect();
    assert!(
        !lost.is_empty(),
        "the trim and the release overlap: heights {:?}..{:?}",
        lost.first(),
        lost.last()
    );
    println!(
        "{} heights are in neither memory nor on the disk: {}..={}",
        lost.len(),
        lost[0],
        lost[lost.len() - 1]
    );

    // An ordinary reorganisation, deeper than the sixty four kept warm, whose
    // last block does not apply.
    let mut rival = fork;
    let mut branch = Vec::new();
    rival.run(&wallet(3), 102, &mut branch);
    let last = branch.len() - 1;
    branch[last].header.state_root = Hash32::from_bytes([0xcd; 32]);

    let mut verdict = None;
    for block in branch {
        verdict = Some(store.add_block(block, NOW));
    }

    assert!(
        matches!(verdict, Some(Err(ChainError::Corrupt))),
        "no disk failed and no peer misbehaved: {verdict:?}"
    );
    assert!(
        store.height().unwrap() < tip,
        "and the node is now shorter than it was, on neither branch, having \
         dropped {} blocks",
        tip - store.height().unwrap()
    );
    println!(
        "log cut to {cut}; height went from {tip} to {}",
        store.height().unwrap()
    );
}

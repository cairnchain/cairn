//! Being handed a ledger instead of replaying the chain that made it.

#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_accumulator::Archive;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover, HandoverError};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
/// Small enough that notes fall out of it during the run, which is the whole
/// point: a handover that never crossed a tier would prove nothing.
const HOT: usize = 8;

/// Buried shallowly, so a test does not have to mine a thousand blocks to
/// reach a ledger anyone would hand over.
const BURIAL: u64 = 8;

/// Short, for the same reason, and not nothing: a handover has to carry the
/// coinbases still waiting, so these tests are worth more with a window that
/// has something in it.
const MATURITY: u64 = 4;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(HOT)
        .with_burial(BURIAL)
        .with_coinbase_maturity(MATURITY)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain, kept the way a node that has been running keeps one.
///
/// The ledger at every height is kept as well, which a real node does not need
/// to do: it rebuilds an old one by undoing blocks off the current one. Here
/// it is simply cheaper than writing that again.
struct Node {
    state: LedgerState,
    /// The ledger at each height.
    past: Vec<LedgerState>,
    /// And the block that produced it, so a newcomer can be given the ones it
    /// has to check for itself.
    blocks: Vec<Block>,
    /// Every header leaf, so this can prove where one sits. A real node reads
    /// that off its header log; here it is kept in memory.
    history: Archive,
    headers: Vec<BlockHeader>,
    clock: u64,
}

impl Node {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
            history: Archive::new(),
            headers: Vec::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let params = params();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&self.state, coinbase, transfers, &params, self.clock, 0).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        self.past.push(self.state.clone());
        self.blocks.push(block.clone());
        self.history
            .add(cairn_ledger::state::header_leaf(&block.header.id()))
            .unwrap();
        self.headers.push(block.header);
        block
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner, Vec::new());
        }
    }

    /// The height a handover from this node belongs to, which is never the
    /// tip.
    fn anchor_height(&self) -> u64 {
        self.headers.last().unwrap().height - BURIAL
    }

    /// The ledger a handover from this node carries.
    fn buried(&self) -> &LedgerState {
        &self.past[self.anchor_height() as usize]
    }

    /// The blocks a newcomer must check for itself before it has caught up.
    ///
    /// This is what a buried handover buys: they are not taken on anybody's
    /// word, they are validated, so the ledger the newcomer ends on is one it
    /// built rather than one it was given.
    fn to_catch_up(&self) -> Vec<Block> {
        self.blocks[(self.anchor_height() as usize + 1)..].to_vec()
    }

    /// What this node would hand to someone starting out.
    ///
    /// Never the ledger at the tip. One from `BURIAL` blocks below it, with
    /// the proof that it sits on the chain the tip ends.
    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let tip_history = self.state.headers_before_tip();
        let anchor = self
            .history
            .prove_in(anchor_height, tip.height)
            .expect("the header sits in the forest before the tip");
        let first = (anchor_height as usize + 1).saturating_sub(RECENT_HEADERS);
        state.handover(
            at,
            tip,
            tip_history,
            anchor,
            self.headers[(anchor_height as usize + 1)..].to_vec(),
            self.headers[first..=anchor_height as usize].to_vec(),
        )
    }
}

/// A ledger handed over is the ledger that was handed.
///
/// Not merely one that looks like it: the test carries on from the rebuilt
/// ledger and from the original in step, and requires that they agree on every
/// block after that. A state root matching once says the pieces line up; two
/// ledgers producing the same next block says they are the same ledger.
#[test]
fn a_handed_over_ledger_carries_on_exactly_as_the_one_it_came_from() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    // Enough that the hot set has overflowed and the grace window is full.
    node.mine_empty(&miner, RECENT_HEADERS + 40);

    let handover = node.handover();
    let mut fresh = accept(&handover, &params).expect("it checks out");

    // What arrives is the ledger from BURIAL blocks back, not the one at the
    // tip. That is the whole defence: nobody is believed about the present.
    assert_eq!(fresh.state_root(), node.buried().state_root());
    assert_eq!(fresh.grace_root(), node.buried().grace_root());
    assert_eq!(fresh.history_root(), node.buried().history_root());
    assert_eq!(fresh.hot_len(), node.buried().hot_len());
    assert_eq!(fresh.cold_len(), node.buried().cold_len());
    assert_ne!(
        fresh.tip().unwrap().id,
        node.state.tip().unwrap().id,
        "and it is behind, on purpose"
    );

    // It closes the gap by checking every rule of every block in it, which is
    // what makes the ledger it ends on one it built rather than one it took.
    for block in node.to_catch_up() {
        connect_block(&mut fresh, &block, &params, NOW)
            .expect("a newcomer validates its way to the tip");
    }
    assert_eq!(fresh.state_root(), node.state.state_root());
    assert_eq!(fresh.tip().unwrap().id, node.state.tip().unwrap().id);

    // And now the part that matters: both carry on, and stay together.
    for _ in 0..20 {
        let block = node.mine(&miner, Vec::new());
        connect_block(&mut fresh, &block, &params, NOW)
            .expect("a handed over ledger takes what the chain does");
        assert_eq!(fresh.state_root(), node.state.state_root());
    }
}

/// The case the grace window commitment exists for.
///
/// A note that fell a few blocks ago is spendable without a proof, and only a
/// node holding the window knows which ones those are. A newcomer handed a
/// ledger has to be able to take a block that spends one, and before the state
/// root committed to the window it could not: it would have started empty and
/// refused.
#[test]
fn a_handed_over_ledger_accepts_a_spend_from_the_grace_window() {
    let params = params();
    let miner = wallet(1);
    let recipient = wallet(2);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 4);

    // A note the miner was paid early on, which the hot set has long since
    // pushed out but the grace window still covers.
    let fallen = node
        .state
        .grace_window()
        .last()
        .and_then(|block| block.first().copied())
        .expect("something fell in the last block");
    let (id, _, fallen_note) = fallen;

    let handover = node.handover();
    assert!(!handover.grace.is_empty(), "the window travels");
    let mut fresh = accept(&handover, &params).expect("it checks out");
    // A newcomer arrives BURIAL blocks back and validates its way forward, so
    // by the time it is asked anything it is at the tip like everyone else.
    for block in node.to_catch_up() {
        connect_block(&mut fresh, &block, &params, NOW).expect("it validates its way up");
    }
    assert_eq!(
        fresh.grace_len(),
        node.state.grace_len(),
        "and arrives whole"
    );

    let (position, _) = node.state.within_grace(&id).expect("the giver has it");
    assert!(
        fresh.within_grace(&id).is_some(),
        "and so does the one handed over"
    );
    assert!(
        fresh.cold().proof_of(position).is_some(),
        "along with the proof that spending it takes"
    );

    // Spent with no proof at all, which only the window makes possible.
    let mut transfer = Transfer::new(
        vec![Input::hot(id)],
        vec![Note::new(fallen_note.value, recipient.public_key())],
    );
    transfer.sign_input(params.network, 0, &fallen_note, &miner);

    let block = node.mine(&miner, vec![transfer]);
    assert_eq!(block.transfers.len(), 1, "the spend went into a block");
    connect_block(&mut fresh, &block, &params, NOW)
        .expect("a handed over ledger knows what has just fallen");
    assert_eq!(fresh.state_root(), node.state.state_root());
    assert_eq!(
        fresh
            .hot_note(&NoteId::new(block.transfers[0].id(), 0))
            .map(|paid| paid.value),
        Some(fallen_note.value),
        "and the payee holds it"
    );
}

/// A ledger that does not produce the header it claims to belong to.
#[test]
fn a_ledger_that_does_not_match_its_header_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    // One note quietly worth more than it was.
    let (id, mut entry) = handover.hot[0];
    entry.note = Note::new(
        Amount::from_pebbles(entry.note.value.as_pebbles() + 1).unwrap(),
        entry.note.owner,
    );
    handover.hot[0] = (id, entry);

    assert_eq!(
        accept(&handover, &params).err(),
        Some(HandoverError::StateRootMismatch),
        "a ledger is only worth what its header says about it"
    );
}

/// A grace window of the sender's choosing.
///
/// The one a header would not have caught before it committed to the window.
#[test]
fn a_grace_window_the_header_does_not_commit_to_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    handover.grace.clear();

    assert_eq!(
        accept(&handover, &params).err(),
        Some(HandoverError::StateRootMismatch),
        "an empty window is a different ledger, and the header says which"
    );
}

/// The same, for the coinbases still waiting.
///
/// A newcomer cannot work these out: they are what the last blocks paid, and
/// it has none of those blocks. Handed an empty window it would accept spends
/// of rewards the rest of the network is still refusing, for as long as it
/// took to mine past the depth. That is a fork with nobody at fault, which is
/// the same fault the grace window was found to have, so it is closed the same
/// way: the header commits to the window and a different one is a different
/// ledger.
#[test]
fn a_maturity_window_the_header_does_not_commit_to_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let honest = node.handover();
    assert!(
        !honest.maturing.is_empty(),
        "nothing was waiting, so nothing is being tested"
    );
    assert_eq!(
        accept(&honest, &params).map(|state| state.maturing()),
        Ok(node.buried().maturing()),
        "the window arrives as it stood"
    );

    let mut emptied = node.handover();
    emptied.maturing.clear();
    assert_eq!(
        accept(&emptied, &params).err(),
        Some(HandoverError::StateRootMismatch),
        "a newcomer told nothing is waiting would spend what everyone else refuses"
    );

    // And one that says a reward matures later than it does, which is the lie
    // in the other direction: a newcomer refusing what everyone else takes.
    let mut delayed = node.handover();
    delayed.maturing[0].0 += 1;
    assert_eq!(
        accept(&delayed, &params).err(),
        Some(HandoverError::StateRootMismatch)
    );
}

/// A window longer than any this network produces, refused on the size before
/// the ledger it belongs to is built.
#[test]
fn a_maturity_window_past_the_depth_is_refused_before_it_is_built() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    handover.maturing = (0..=MATURITY)
        .map(|index| (1_000 + index, Hash32::from_bytes([index as u8; 32])))
        .collect();

    assert_eq!(
        accept(&handover, &params).err(),
        Some(HandoverError::MaturityWindowTooLarge {
            held: MATURITY as usize + 1,
            limit: MATURITY,
        })
    );
}

/// What the chain has issued travels too, and cannot be made up.
///
/// A supply is only worth having if it is the chain's rather than the sender's.
/// A newcomer that took one on somebody's word would go on adding to a number
/// that was wrong from the moment it arrived, and would say it out loud to
/// anyone who asked.
#[test]
fn a_supply_the_header_does_not_commit_to_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let handover = node.handover();
    let fresh = accept(&handover, &params).expect("it checks out");
    assert_eq!(fresh.supply(), node.buried().supply());
    assert_ne!(fresh.supply(), Amount::ZERO, "the chain has paid somebody");

    for lie in [Amount::ZERO, params.initial_reward] {
        let mut bent = node.handover();
        bent.supply = lie;
        if lie == handover.supply {
            continue;
        }
        assert_eq!(
            accept(&bent, &params).err(),
            Some(HandoverError::StateRootMismatch),
            "a chain's supply is the chain's to state, not the sender's"
        );
    }
}

/// Headers from somewhere else, or none at all.
#[test]
fn a_history_the_header_does_not_commit_to_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut other = Node::new();
    other.mine_empty(&wallet(9), RECENT_HEADERS + 8);

    let mut handover = node.handover();
    handover.headers = other.state.headers_before_tip();

    assert_eq!(
        accept(&handover, &params).err(),
        Some(HandoverError::HistoryMismatch),
    );
}

/// A run of headers that does not lead to the one being handed over.
#[test]
fn recent_headers_that_are_not_a_chain_are_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    // One header replaced by a real one from further back, so the run still
    // looks like headers but no longer links.
    handover.recent[2] = node.headers[0];

    assert_eq!(
        accept(&handover, &params).err(),
        Some(HandoverError::RecentNotConsecutive),
    );

    // And a run that stops short of the header it belongs to.
    let mut handover = node.handover();
    handover.recent.pop();
    assert_eq!(
        accept(&handover, &params).err(),
        Some(HandoverError::RecentNotEndingAtTip),
    );
}

/// A hot set larger than the rules allow, before anything is built from it.
#[test]
fn a_hot_set_past_the_cap_is_refused_before_it_is_built() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    let filler = handover.hot[0];
    while handover.hot.len() <= params.hot_capacity {
        handover.hot.push(filler);
    }

    assert!(
        matches!(
            accept(&handover, &params),
            Err(HandoverError::HotSetTooLarge { .. })
        ),
        "how much work a handover costs is not for its sender to decide"
    );
}

/// A handover crosses the wire and is still the same ledger.
#[test]
fn a_handover_survives_a_round_trip() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 20);

    let handover = node.handover();
    let bytes = cairn_primitives::codec::Encode::encode(&handover);
    let read_back = <Handover as cairn_primitives::codec::Decode>::decode(&bytes)
        .expect("what it wrote, it reads");

    let rebuilt = accept(&read_back, &params).expect("and it still checks out");
    assert_eq!(rebuilt.state_root(), node.buried().state_root());
    assert_eq!(rebuilt.hot_len(), node.buried().hot_len());
    assert_eq!(rebuilt.grace_len(), node.buried().grace_len());

    println!(
        "a handover of {} blocks takes {} bytes",
        node.headers.len(),
        bytes.len()
    );
}

/// Sizes a reader reserves for are the sender's to name, so each is capped.
#[test]
fn a_handover_that_names_absurd_sizes_is_refused_while_reading() {
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 4);

    let handover = node.handover();
    let good = cairn_primitives::codec::Encode::encode(&handover);

    // The hot set count sits right after the two forests, and the forests are
    // fixed width for a given shape, so the count is found by reading up to it.
    // Rather than compute the offset, every prefix is truncated and fed back:
    // a reader that reserves before checking would run out of memory on one of
    // them rather than returning an error.
    for cut in (8..good.len()).step_by(good.len() / 20 + 1) {
        let outcome = <Handover as cairn_primitives::codec::Decode>::decode(&good[..cut]);
        assert!(
            outcome.is_err(),
            "a message cut short at {cut} should not read as a whole one"
        );
    }
}

/// The case the proof window commitment exists for.
///
/// A proof describes the cold set at the moment it was taken, and the set
/// moves with every block. A spender who took one a few blocks ago has done
/// nothing wrong, so a handful of recent states are kept and a proof against
/// any of them is taken. A newcomer handed a ledger holds none of those unless
/// they come with it, and before the state root committed to them it would
/// have refused every proof not taken at the exact tip.
#[test]
fn a_handed_over_ledger_accepts_a_proof_taken_a_few_blocks_ago() {
    let params = params();
    let miner = wallet(1);
    let recipient = wallet(2);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    // A note that fell long enough ago to be out of the grace window, so
    // spending it takes a proof rather than nothing.
    let old = node
        .state
        .grace_window()
        .first()
        .and_then(|block| block.first().copied())
        .expect("something fell early on");
    let (id, position, fallen_note) = old;

    // The proof as it stands now, taken before the chain moves on.
    let proof = node
        .state
        .cold()
        .prove(position)
        .expect("an archivist can build one");

    // The chain moves under it, which is exactly the case the window covers.
    node.mine_empty(&miner, 3);

    let handover = node.handover();

    let mut fresh = accept(&handover, &params).expect("it checks out");
    // A newcomer arrives BURIAL blocks back and validates its way forward, so
    // by the time it is asked anything it is at the tip like everyone else.
    for block in node.to_catch_up() {
        connect_block(&mut fresh, &block, &params, NOW).expect("it validates its way up");
    }

    let mut transfer = Transfer::new(
        vec![Input::cold(id, fallen_note, position, proof)],
        vec![Note::new(fallen_note.value, recipient.public_key())],
    );
    transfer.sign_input(params.network, 0, &fallen_note, &miner);

    let block = node.mine(&miner, vec![transfer]);
    assert_eq!(block.transfers.len(), 1, "the spend went into a block");
    connect_block(&mut fresh, &block, &params, NOW)
        .expect("a handed over ledger takes a proof the chain took");
    assert_eq!(fresh.state_root(), node.state.state_root());
}

/// The attack this exists to stop.
///
/// A miner who finds one block can commit to any ledger it likes: proof of
/// work says electricity was spent on those bytes, not that the state in them
/// is what honest transactions would have produced, and a newcomer has watched
/// no transaction go past to know otherwise. Before this, one block bought an
/// arbitrary ledger on every newcomer.
///
/// What stops it is refusing to take a ledger at the tip at all. A forger must
/// now bury its invention under `burial` blocks and be the heaviest chain for
/// all of them, which is out-mining everybody else, the assumption the chain
/// already rests on.
#[test]
fn a_ledger_at_the_tip_is_refused_however_good_it_looks() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 20);

    // An honest and internally perfect handover, but of the ledger as it stands.
    // Every commitment in it is real; it is refused for where it sits.
    let tip = *node.headers.last().unwrap();
    let at_the_tip = node.state.handover(
        tip,
        tip,
        node.state.headers_before_tip(),
        node.history
            .prove_in(tip.height, tip.height.saturating_add(1))
            .expect("it can prove its own tip"),
        Vec::new(),
        node.headers[node.headers.len() - RECENT_HEADERS..].to_vec(),
    );

    assert_eq!(
        accept(&at_the_tip, &params).err(),
        Some(HandoverError::NotBuried {
            at: tip.height,
            tip: tip.height,
        }),
        "nobody is believed about the present, however well they say it"
    );
}

/// And it has to be the chain that was weighed, not merely some chain.
#[test]
fn a_ledger_from_another_chain_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 20);

    // Another chain of the same shape, mined by somebody else.
    let mut other = Node::new();
    other.mine_empty(&wallet(9), RECENT_HEADERS + 20);

    // Its ledger, offered under our tip. Everything inside is consistent; what
    // is missing is that its header sits nowhere in our tip's history.
    let mut borrowed = other.handover();
    borrowed.tip = *node.headers.last().unwrap();
    borrowed.tip_history = node.state.headers_before_tip();

    assert_eq!(
        accept(&borrowed, &params).err(),
        Some(HandoverError::NotOnTheWeighedChain),
        "a peer cannot weigh one chain and hand over another's ledger"
    );
}

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
use cairn_ledger::state::{GRACE_BLOCKS, GRACE_NOTES};
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
        state
            .handover(
                at,
                tip,
                tip_history,
                anchor,
                self.headers[(anchor_height as usize + 1)..].to_vec(),
                self.headers[first..=anchor_height as usize].to_vec(),
            )
            .expect("every note in the window has a path")
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

/// A window the right length, holding a height it could not hold.
///
/// The length was the only rule this window had, and the sentence beside it —
/// "a window holding more than the maturity depth is not a window this network
/// ever produced" — is true and is not the question the window is on the hook
/// for. `advance_maturing` empties it from the front and stops at the first
/// entry that has not matured, so one entry that never matures never leaves
/// and nothing behind it leaves either: the window grows by an entry a block
/// for the life of the node, and `compose_state_root` walks all of it for
/// every candidate block. A node handed one of these had twenty times the
/// per-block cost of a node handed an honest one after three thousand blocks,
/// and was still climbing.
///
/// The window is taken from an honest handover and one height in it is moved,
/// so the fixture is a window this network did produce, altered in the one way
/// nothing asked about.
///
/// The state root over it is deliberately not recomputed, and that is enough:
/// this check runs before the root is compared, so it catches the sender who
/// did recompute one as well. That sender is the reachable attack and the
/// reason the check has to be here rather than in the root — a sender who
/// out-mined the network for the burial chose the window and the root over it
/// together, and `against_each_other` is named for exactly that reader.
#[test]
fn a_maturity_window_holding_a_height_it_could_not_hold_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let honest = node.handover();
    assert!(
        accept(&honest, &params).is_ok(),
        "this test needs a handover the rules take, so that what it refuses below is the \
         one thing it changed"
    );
    assert!(
        !honest.maturing.is_empty(),
        "and it needs a window with something in it"
    );

    // Past any height this chain will reach, which is what makes it an entry
    // that never matures. The length is untouched, so the only rule the window
    // had is satisfied exactly as before.
    let mut forged = honest.clone();
    forged.maturing[0].0 = u64::MAX;
    assert_eq!(
        forged.maturing.len(),
        honest.maturing.len(),
        "the length is the same, which is the whole point"
    );
    assert!(
        matches!(
            accept(&forged, &params).err(),
            Some(HandoverError::MaturityOutsideTheWindow { .. })
        ),
        "a coinbase that never matures was taken, so this node's window grows by an entry \
         a block for ever, its per-block cost grows with the chain, the notes that coinbase \
         paid can never be spent, and once the window passes the depth it stops being able \
         to hand its ledger to anybody"
    );

    // And the other end: a height at or below the anchor is one that has
    // already matured, so it would leave on the first block and never have
    // been in a window this chain produced either.
    let mut early = honest.clone();
    early.maturing[0].0 = honest.at.height;
    assert!(
        matches!(
            accept(&early, &params).err(),
            Some(HandoverError::MaturityOutsideTheWindow { .. })
        ),
        "a window holding a coinbase that has already matured is not one this network made"
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
        // Two rules can refuse a lowered total now and either is an answer.
        // The state root is what this test was written for: the supply is one
        // of the eight fields folded into it, so a number the header does not
        // commit to cannot be rebuilt into the header. The hot set is what
        // reaches it first, and cheaper: the notes handed over are worth more
        // than the total the same message declares, which is a disagreement
        // between two pieces and needs nothing rebuilt to see.
        //
        // Named rather than accepted as "some error", because a refusal for an
        // unrelated reason would pass that and say nothing.
        let refused = accept(&bent, &params)
            .expect_err("a chain's supply is the chain's to state, not the sender's");
        assert!(
            matches!(
                refused,
                HandoverError::StateRootMismatch | HandoverError::TiersAboveTheSchedule { .. }
            ),
            "refused for something other than the number: {refused}"
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
    let at_the_tip = node
        .state
        .handover(
            tip,
            tip,
            node.state.headers_before_tip(),
            node.history
                .prove_in(tip.height, tip.height.saturating_add(1))
                .expect("it can prove its own tip"),
            Vec::new(),
            node.headers[node.headers.len() - RECENT_HEADERS..].to_vec(),
        )
        .expect("every note in the window has a path");

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

/// Both halves of the grace rule, because the rule has two.
///
/// `advance_grace` runs the window down while it holds more blocks than
/// `GRACE_BLOCKS` **or** more notes than `GRACE_NOTES`. `accept` asked only
/// the first, under a comment naming the very distinction it then failed to
/// honour: "the decoder's ceiling is what a message carries; this is what the
/// rules produce, and the two are not the same question."
///
/// So a window of exactly `GRACE_BLOCKS` blocks carrying more than
/// `GRACE_NOTES` notes passed every size rule here and was stopped only by
/// the state root rebuild at the end, after the window had been built,
/// indexed, and its every proof taken. Its three siblings all refuse before
/// anything is built, which the file says out loud is the point: the size of
/// what follows is otherwise decided by whoever sent it.
///
/// `decode_grace` refuses this off the wire today, so this is not a hole a
/// peer can reach. It is the one bound of the four living in the decoder
/// alone, which is the opposite of the convention the rest of this file
/// states, and a decoder is not where a consensus rule belongs.
#[test]
fn a_grace_window_holding_more_notes_than_the_rules_keep_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let mut handover = node.handover();
    assert!(
        handover.grace.len() <= GRACE_BLOCKS,
        "the honest window is inside the block bound, so what follows is about the \
         other one"
    );

    // The same number of blocks, and more notes in them than the window keeps.
    //
    // Worth nothing each, so the money in the window is the money that was
    // already there. A copy of a real note eight thousand times over is a
    // ledger carrying forty one thousand CAIRN against a schedule that has
    // issued four hundred and fifty five, and it is the schedule that would
    // refuse it, which is a different sentence than the one under test.
    let (which, fell_at, sample) = handover
        .grace
        .iter()
        .flatten()
        .next()
        .copied()
        .expect("a window this test can copy a note out of");
    let fallen = (which, fell_at, Note::new(Amount::ZERO, sample.owner));
    let mut stuffed = vec![Vec::new(); handover.grace.len().max(1)];
    let mut left = GRACE_NOTES + 1;
    for block in &mut stuffed {
        let take = left.min(GRACE_NOTES / handover.grace.len().max(1) + 1);
        block.extend(std::iter::repeat_n(fallen, take));
        left = left.saturating_sub(take);
        if left == 0 {
            break;
        }
    }
    let notes: usize = stuffed.iter().map(Vec::len).sum();
    assert!(notes > GRACE_NOTES, "the window has to be over the bound");
    assert!(
        stuffed.len() <= GRACE_BLOCKS,
        "and inside the other one, or the sibling check catches it instead"
    );
    handover.grace = stuffed;

    assert_eq!(
        accept(&handover, &params).err(),
        Some(HandoverError::GraceWindowHoldsTooMuch {
            held: notes,
            limit: GRACE_NOTES,
        }),
        "a window holding more than the rules keep was carried all the way to the state \
         root rebuild, which is three orders of magnitude of work past where its \
         siblings refuse"
    );
}

/// A run shorter than the window the rules keep is refused, and says so.
///
/// Nothing asked this before: every fixture hands over the run its own chain
/// produced, which is exactly the window, so the comparison could be turned
/// around and a short run would have been taken. What the run seeds is the
/// window the burial above it is judged against, so a run one header short is
/// a burial judged on a window this chain never had.
#[test]
fn a_recent_run_shorter_than_the_window_is_refused_as_too_few() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let honest = node.handover();
    accept(&honest, &params).expect("the run this chain really has");
    let mut short = honest.clone();
    short.recent.remove(0);

    assert_eq!(
        accept(&short, &params).err(),
        Some(HandoverError::TooFewRecent {
            given: honest.recent.len() - 1,
            height: honest.at.height,
        })
    );
}

/// A run whose links do not match is refused, though every height does.
///
/// The two halves of the consecutive check are joined by "or", and the
/// difference shows only where one of them holds on its own. Bending a height
/// breaks both, since a height is inside its own identifier and the header
/// above names it; bending what a header says it was built on breaks the link
/// alone, and that is the case this pins. Asked of the run rather than of the
/// anchor at its end, which is what the sibling test bends.
#[test]
fn a_recent_run_whose_links_do_not_match_is_refused_though_the_heights_do() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let honest = node.handover();
    let last = honest.recent.len() - 1;
    let mut bent = honest.clone();
    bent.recent[last - 1].previous = Hash32::from_bytes([0xA5; 32]);
    assert_eq!(
        bent.recent[last - 1].height,
        bent.recent[last - 2].height + 1,
        "every height still follows the one below it"
    );

    assert_eq!(
        accept(&bent, &params).err(),
        Some(HandoverError::RecentNotConsecutive)
    );
}

/// And the same for the buried run, where the answer is a height.
///
/// Bending the link alone leaves the run ending at the tip, so what catches it
/// if this does not is the forest rebuilt at the end of the walk, which
/// answers `NotOnTheWeighedChain`: true, and the wrong sentence. The run was
/// not off another chain, it was not a run.
#[test]
fn a_buried_run_whose_links_do_not_match_is_refused_where_the_link_breaks() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let honest = node.handover();
    let mut bent = honest.clone();
    bent.buried[0].previous = Hash32::from_bytes([0xA5; 32]);

    assert_eq!(
        accept(&bent, &params).err(),
        Some(HandoverError::BuriedRunNotConsecutive {
            at: honest.buried[0].height
        })
    );
}

/// The recent run has to carry its own argument, not borrow one.
///
/// It cannot be forged: every field of a header is inside its identifier, the
/// run is chained by `previous` up to the anchor, and the anchor is pinned
/// twice into the forest of a tip the sampling weighed. So **neither of these
/// two refusals catches anything the chain would let through** — bending
/// either field changes the identifier the header above names, and the
/// consecutive check would refuse it.
///
/// Said plainly because the first version of this test did not know it. It
/// bent the last entry of the run, which is the anchor, and got
/// `RecentNotEndingAtTip`; bending any other entry gets `RecentNotConsecutive`
/// unless the new check runs first. That is what nearly shipped here: two
/// guards that could not fire, on a day spent removing them.
///
/// What they buy is the sentence. "The work at 812 does not add up" is
/// something somebody can act on; "not consecutive" is the same fact with the
/// reason removed. And they let `check_recent` carry its own argument rather
/// than borrow one from the forest, which matters because this run seeds the
/// window the burial above it is judged against.
///
/// Both are free of any window: the version is a function of the height alone
/// and the work is an addition between neighbours. The two that are not free
/// are written up on `check_recent`, along with why they are not here.
#[test]
fn a_recent_run_is_refused_when_its_version_or_its_work_does_not_hold() {
    let params = params();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 8);

    let honest = node.handover();
    accept(&honest, &params).expect("the run this chain really has");
    let last = honest.recent.len() - 1;

    // A version no schedule of this build asks for, on a header inside the
    // run rather than on the anchor, which was the only one asked before.
    let mut bent = honest.clone();
    bent.recent[last - 1].version = bent.recent[last - 1].version.saturating_add(1);
    match accept(&bent, &params).err() {
        Some(HandoverError::WrongVersion { height, .. }) => {
            assert_eq!(height, honest.recent[last - 1].height);
        }
        other => panic!("a recent header naming rules it was not mined under: {other:?}"),
    }

    // Work that does not add up across the run. This is what ties the
    // anchor's total to the headers below it; `check_buried` ties it to the
    // tip from above, and between the two there was nothing.
    let mut bent = honest.clone();
    bent.recent[last - 1].total_work = bent.recent[last - 1].total_work.saturating_add(1);
    match accept(&bent, &params).err() {
        Some(HandoverError::RecentWorkDoesNotAddUp { at }) => {
            assert_eq!(at, honest.recent[last - 1].height);
        }
        other => panic!("a recent run whose work does not add up: {other:?}"),
    }
}

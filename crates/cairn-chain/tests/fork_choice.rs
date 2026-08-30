//! Choosing between branches, and rebuilding the ledger when the choice moves.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::{Accepted, ChainError, ChainStore, MAX_REORG_DEPTH};
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// Produces blocks on a private copy of the ledger, so a branch can be built
/// without a node having to follow it.
#[derive(Clone)]
struct Branch {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Branch {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>, spacing: u64) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += spacing;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
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

    fn mine_empty(&mut self, miner: &SecretKey, count: usize, spacing: u64) -> Vec<Block> {
        (0..count)
            .map(|_| self.mine(miner, Vec::new(), spacing))
            .collect()
    }

    /// A second branch carrying on from where this one stands.
    fn fork(&self) -> Self {
        Self {
            params: self.params,
            state: self.state.clone(),
            clock: self.clock,
        }
    }
}

fn coinbase_note(block: &Block, params: &ConsensusParams, miner: &SecretKey) -> (NoteId, Note) {
    (
        NoteId::new(block.coinbase.id(), 0),
        Note::new(params.initial_reward, miner.public_key()),
    )
}

fn feed(store: &mut ChainStore, blocks: &[Block]) -> Vec<Accepted> {
    blocks
        .iter()
        .map(|block| store.add_block(block.clone(), NOW).unwrap())
        .collect()
}

#[test]
fn the_first_block_must_be_a_genesis() {
    let params = params();
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let blocks = branch.mine_empty(&miner, 2, 600);

    let mut store = ChainStore::new(params);
    assert_eq!(
        store.add_block(blocks[1].clone(), NOW),
        Err(ChainError::NotGenesis)
    );
    assert!(store.is_empty());
    assert_eq!(
        store.add_block(blocks[0].clone(), NOW),
        Ok(Accepted::Extended)
    );
}

#[test]
fn a_block_whose_parent_is_unknown_is_refused() {
    let params = params();
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let blocks = branch.mine_empty(&miner, 3, 600);

    let mut store = ChainStore::new(params);
    store.add_block(blocks[0].clone(), NOW).unwrap();
    assert_eq!(
        store.add_block(blocks[2].clone(), NOW),
        Err(ChainError::UnknownParent(blocks[1].id()))
    );
    assert_eq!(store.height(), Some(0));
}

#[test]
fn blocks_extend_the_chain_and_repeats_are_recognised() {
    let params = params();
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let blocks = branch.mine_empty(&miner, 5, 600);

    let mut store = ChainStore::new(params);
    assert_eq!(feed(&mut store, &blocks), vec![Accepted::Extended; 5]);
    assert_eq!(store.height(), Some(4));
    assert_eq!(store.tip(), Some(blocks[4].id()));
    assert_eq!(store.total_work(), 5);
    assert_eq!(
        store.add_block(blocks[2].clone(), NOW),
        Ok(Accepted::Duplicate)
    );
}

#[test]
fn a_block_carrying_no_work_never_reaches_memory() {
    let params = params();
    let miner = wallet(1);
    let mut branch = Branch::new(params);
    let genesis = branch.mine(&miner, Vec::new(), 600);

    let mut spoiled = genesis.clone();
    spoiled.header.difficulty = u64::MAX;

    let mut store = ChainStore::new(params);
    assert!(matches!(
        store.add_block(spoiled, NOW),
        Err(ChainError::NoWork { .. })
    ));
    assert!(
        store.is_empty(),
        "a block without work is not stored at all"
    );
}

#[test]
fn a_lighter_branch_is_recorded_without_being_followed() {
    let params = params();
    let miner = wallet(1);
    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 4, 600);

    let mut heavy = common.clone();
    let mut light = common.clone();
    let heavy_blocks = heavy.mine_empty(&miner, 3, 600);
    let light_blocks = light.mine_empty(&wallet(9), 1, 700);

    let mut store = ChainStore::new(params);
    feed(&mut store, &shared);
    feed(&mut store, &heavy_blocks);
    let tip = store.tip();

    assert_eq!(
        store.add_block(light_blocks[0].clone(), NOW),
        Ok(Accepted::SideBranch)
    );
    assert_eq!(store.tip(), tip, "the followed branch did not move");
    assert!(
        store.contains(&light_blocks[0].id()),
        "but the block is kept"
    );
    assert!(!store.is_active(&light_blocks[0].id()));
}

#[test]
fn an_equally_heavy_branch_does_not_displace_the_current_one() {
    let params = params();
    let miner = wallet(1);
    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 4, 600);

    let mut first = common.clone();
    let mut second = common.clone();
    let first_blocks = first.mine_empty(&miner, 2, 600);
    let second_blocks = second.mine_empty(&wallet(9), 2, 601);

    let mut store = ChainStore::new(params);
    feed(&mut store, &shared);
    feed(&mut store, &first_blocks);
    let tip = store.tip();

    let outcomes = feed(&mut store, &second_blocks);
    assert_eq!(outcomes, vec![Accepted::SideBranch; 2]);
    assert_eq!(
        store.tip(),
        tip,
        "equal work keeps the branch already followed"
    );
}

#[test]
fn a_heavier_branch_takes_over_and_undoes_what_the_other_did() {
    let params = params();
    let miner = wallet(1);
    let alice = wallet(2);

    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 12, 600);
    let (funded, funded_note) = coinbase_note(&shared[11], &params, &miner);

    // One branch pays alice. The other does nothing, but runs longer.
    let mut paying = common.clone();
    let mut quiet = common.clone();

    let mut payment = Transfer::new(
        vec![Input::hot(funded)],
        vec![Note::new(funded_note.value, alice.public_key())],
    );
    payment.sign_input(params.network, 0, &funded_note, &miner);
    let payment_id = payment.id();

    let mut paying_blocks = vec![paying.mine(&miner, vec![payment], 600)];
    paying_blocks.push(paying.mine(&miner, Vec::new(), 600));
    let quiet_blocks = quiet.mine_empty(&wallet(9), 4, 600);

    let mut store = ChainStore::new(params);
    feed(&mut store, &shared);
    feed(&mut store, &paying_blocks);

    let paid = NoteId::new(payment_id, 0);
    assert_eq!(
        store.state().hot_note(&paid),
        Some(Note::new(funded_note.value, alice.public_key())),
        "alice was paid on the branch the node follows"
    );
    assert_eq!(
        store.state().hot_note(&funded),
        None,
        "the source note was spent"
    );

    // The switch happens on the block that first outweighs the other branch,
    // not necessarily on the last one delivered.
    let outcomes = feed(&mut store, &quiet_blocks);
    let (removed, added) = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            Accepted::Reorganised { removed, added } => Some((removed.clone(), added.clone())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no reorganisation among {outcomes:?}"));

    assert_eq!(
        removed.len(),
        2,
        "both blocks of the abandoned branch came off"
    );
    assert_eq!(
        added.len(),
        3,
        "the branch was rebuilt up to the block that won"
    );
    assert_eq!(store.tip(), Some(quiet_blocks[3].id()));
    assert_eq!(
        store.state().hot_note(&paid),
        None,
        "the payment no longer happened"
    );
    assert_eq!(
        store.state().hot_note(&funded),
        Some(funded_note),
        "and the note it spent is unspent again"
    );
    assert!(
        store.contains(&paying_blocks[0].id()),
        "the abandoned blocks are still known"
    );
}

#[test]
fn a_branch_containing_a_bad_block_leaves_the_node_exactly_where_it_was() {
    let params = params();
    let miner = wallet(1);
    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 6, 600);

    let mut good = common.clone();
    let mut bad = common.clone();
    // The bad branch only outweighs the good one on its very last block, so
    // nothing switches until the block that cannot be applied.
    let good_blocks = good.mine_empty(&miner, 4, 600);
    let mut bad_blocks = bad.mine_empty(&wallet(9), 5, 600);

    // Break the last block of the heavier branch after it was built, so it is
    // only found out once the node tries to follow it.
    let broken = bad_blocks.last_mut().unwrap();
    broken.header.state_root = cairn_primitives::Hash32::ZERO;
    let broken = mine_block(broken.clone(), ATTEMPTS).unwrap();
    let last = bad_blocks.len() - 1;
    bad_blocks[last] = broken;

    let mut store = ChainStore::new(params);
    feed(&mut store, &shared);
    feed(&mut store, &good_blocks);

    let before = (
        store.tip(),
        store.state().state_root(),
        store.height(),
        store.total_work(),
    );

    for block in bad_blocks.iter().take(last) {
        assert_eq!(
            store.add_block(block.clone(), NOW),
            Ok(Accepted::SideBranch),
            "the lighter prefix must not displace anything"
        );
    }
    let outcome = store.add_block(bad_blocks[last].clone(), NOW);
    assert!(
        matches!(outcome, Err(ChainError::InvalidBlock { .. })),
        "got {outcome:?}"
    );

    assert_eq!(
        store.tip(),
        before.0,
        "the node is back on the branch it was following"
    );
    assert_eq!(store.state().state_root(), before.1);
    assert_eq!(store.height(), before.2);
    assert_eq!(store.total_work(), before.3);
}

#[test]
fn two_nodes_given_the_same_blocks_in_different_orders_agree() {
    let params = params();
    let miner = wallet(1);
    let mut common = Branch::new(params);
    let shared = common.mine_empty(&miner, 8, 600);

    let mut left = common.clone();
    let mut right = common.clone();
    let left_blocks = left.mine_empty(&miner, 2, 600);
    let right_blocks = right.mine_empty(&wallet(9), 5, 600);

    let mut first = ChainStore::new(params);
    feed(&mut first, &shared);
    feed(&mut first, &left_blocks);
    feed(&mut first, &right_blocks);

    let mut second = ChainStore::new(params);
    feed(&mut second, &shared);
    feed(&mut second, &right_blocks);
    feed(&mut second, &left_blocks);

    assert_eq!(first.tip(), second.tip(), "both settled on the same block");
    assert_eq!(first.state().state_root(), second.state().state_root());
    assert_eq!(first.total_work(), second.total_work());
    assert_eq!(
        first.len(),
        second.len(),
        "both kept every block they were given"
    );
    assert_eq!(
        first.tip(),
        Some(right_blocks[4].id()),
        "the heavier branch won"
    );
}

/// Undo records are what a reorganisation needs, and keeping one per block
/// ever applied is a cost that grows with the chain on a node whose whole
/// claim is that its cost does not.
#[test]
fn undo_records_do_not_pile_up_forever() {
    let miner = wallet(1);
    let mut branch = Branch::new(params());
    let blocks = branch.mine_empty(&miner, MAX_REORG_DEPTH + 200, 600);

    let mut store = ChainStore::new(params());
    feed(&mut store, &blocks);

    assert_eq!(store.height(), Some((MAX_REORG_DEPTH + 199) as u64));
    assert!(
        store.undo_records() <= MAX_REORG_DEPTH,
        "kept {} undo records, the limit is {MAX_REORG_DEPTH}",
        store.undo_records()
    );
}

/// A branch that forks deeper than this node could undo is refused at its
/// first block, not after its last.
///
/// The rule is that a block past [`MAX_REORG_DEPTH`] below the tip is settled.
/// A rival branch forking further back than that can never be followed, so
/// nothing it carries is worth holding: the refusal comes on the first block
/// of it, before a peer has made this node store a thousand more.
#[test]
fn a_branch_forking_deeper_than_the_limit_is_refused_at_once() {
    let miner = wallet(1);
    let rival = wallet(2);

    let mut shared = Branch::new(params());
    let genesis = shared.mine_empty(&miner, 1, 600);

    // Two branches from the same first block. The rival is heavier because it
    // is longer, and it forks further back than this node can undo.
    let mut ours = shared.fork();
    let ours_blocks = ours.mine_empty(&miner, MAX_REORG_DEPTH + 50, 600);
    let mut theirs = shared.fork();
    let theirs_blocks = theirs.mine_empty(&rival, MAX_REORG_DEPTH + 60, 600);

    let mut store = ChainStore::new(params());
    feed(&mut store, &genesis);
    feed(&mut store, &ours_blocks);

    // The first rival block sits below the floor, so it is turned away there
    // and every block built on it is then an orphan this node never sees a
    // parent for.
    let first = store.add_block(theirs_blocks[0].clone(), NOW);
    match first {
        Err(ChainError::TooOld { height, floor }) => {
            assert_eq!(height, 1);
            assert!(height < floor, "refused at height {height}, floor {floor}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    let held = store.len();
    for block in &theirs_blocks[1..] {
        assert!(
            store.add_block(block.clone(), NOW).is_err(),
            "a block whose parent was refused has nowhere to hang"
        );
    }
    assert_eq!(store.len(), held, "and none of them was kept");

    // And the node is exactly where it was.
    assert_eq!(store.height(), Some((MAX_REORG_DEPTH + 50) as u64));
}

/// The work the chain adds up for itself, and the work the tip's header
/// states, must be the same number.
///
/// Two independent counts of the same thing: one summed by the node as it
/// stores blocks, one written into each header and checked against its
/// parent's. They cannot drift apart without one of them being wrong, and a
/// newcomer who reads only the header is relying on the second.
#[test]
fn the_chain_and_its_headers_agree_on_the_work() {
    let miner = wallet(1);
    let mut branch = Branch::new(params());
    let blocks = branch.mine_empty(&miner, 12, 600);

    let mut store = ChainStore::new(params());
    for block in &blocks {
        store.add_block(block.clone(), NOW).unwrap();
        let stated = block.header.total_work;
        assert_eq!(
            store.total_work(),
            stated,
            "at height {} the chain and the header disagree",
            block.header.height
        );
    }

    // And the state carries the same figure, so a node restarted from its own
    // disk lands on it too.
    assert_eq!(store.state().total_work(), store.total_work());
}

/// Branches that can no longer be switched to are let go of.
///
/// A node keeps rival branches because one that loses today can win tomorrow,
/// and lets them go once they are too deep to switch to. What decides when to
/// look is how much it is holding, and that used to be compared against the
/// height of the chain, which was the same number back when a node kept every
/// block it had ever applied. Since it does not, a ceiling that grew with the
/// chain was one this never reached, and rival branches piled up with nothing
/// to clear them.
#[test]
fn rival_branches_do_not_pile_up_forever() {
    let miner = wallet(1);
    let rival = wallet(2);

    let mut shared = Branch::new(params());
    let common = shared.mine_empty(&miner, 8, 600);

    let mut store = ChainStore::new(params());
    feed(&mut store, &common);

    // The branch this node follows, run on past where the rivals will hang.
    let at_fork = shared.clone();
    let ours = shared.mine_empty(&miner, 6, 600);
    feed(&mut store, &ours);
    assert_eq!(store.height(), Some(13));

    // Rival branches from that fork, none of them heavy enough to win. Each is
    // a block a node has to hold in case its branch grows.
    let mut offered = 0usize;
    for seed in 0..24u8 {
        let mut side = at_fork.clone();
        for block in side.mine_empty(&wallet(seed.saturating_add(3)), 2, 600) {
            if store.add_block(block, NOW).is_ok() {
                offered = offered.saturating_add(1);
            }
        }
    }
    assert!(offered > 0, "the rivals were taken");
    assert_eq!(store.height(), Some(13), "and none of them won");

    // Now bury them: the followed branch runs past what a reorganisation can
    // reach back over, so nothing hanging off that fork can be switched to.
    let far = shared.mine_empty(&rival, MAX_REORG_DEPTH + 8, 600);
    feed(&mut store, &far);

    let held = store.len();
    assert!(
        held <= MAX_REORG_DEPTH + 4_096,
        "holding {held} blocks, which is more than the window and its branches"
    );
}

/// A count of blocks does not bound memory, because a block is not a fixed
/// size. What bounds it is the bytes, so the count of those has to follow
/// every block taken in and every block let go.
#[test]
fn what_is_held_is_counted_in_bytes_and_the_count_follows() {
    let miner = wallet(1);
    let mut shared = Branch::new(params());
    let mut store = ChainStore::new(params());

    assert_eq!(store.held_bytes(), 0, "nothing held, nothing counted");

    let blocks = shared.mine_empty(&miner, 12, 600);
    let sent: usize = blocks.iter().map(|block| block.encode().len()).sum();
    feed(&mut store, &blocks);
    assert_eq!(
        store.held_bytes(),
        sent,
        "the count is the blocks, not an estimate of them"
    );

    // The same block twice is one block, and must not be counted twice.
    let again = blocks.last().unwrap().clone();
    let _ = store.add_block(again, NOW);
    assert_eq!(store.held_bytes(), sent, "and a block seen twice is one");

    // Running past the window drops the oldest, and the count comes down with
    // them rather than standing still.
    let far = shared.mine_empty(&miner, MAX_REORG_DEPTH + 8, 600);
    feed(&mut store, &far);
    let counted: usize = store.held_bytes();
    assert!(
        counted < sent + far.iter().map(|block| block.encode().len()).sum::<usize>(),
        "blocks left memory and the count stayed behind"
    );
}

/// A node handed a ledger holds no block and is on a chain all the same. Every
/// question about whether it has one has to answer from the branch, or it
/// spends its life asking to be handed another.
#[test]
fn a_node_handed_a_ledger_knows_it_is_on_a_chain() {
    let miner = wallet(1);
    let mut shared = Branch::new(params());
    let blocks = shared.mine_empty(&miner, 6, 600);

    let mut source = ChainStore::new(params());
    feed(&mut source, &blocks);
    let recent: Vec<_> = blocks.iter().map(|block| block.header).collect();
    let state = source.state().clone();
    let work = source.total_work();

    let mut joined = ChainStore::new(params());
    assert!(joined.is_empty(), "it starts on nothing");
    joined.adopt(state, &recent).unwrap();

    assert!(!joined.is_empty(), "and it is on a chain, holding no block");
    assert_eq!(joined.len(), 0);
    assert_eq!(joined.held_bytes(), 0, "and counts none");
    assert_eq!(joined.height(), source.height());
    assert_eq!(
        joined.total_work(),
        work,
        "with the work behind it, or every branch would look heavier"
    );
}

/// The ceiling is the product of three numbers written in two files, which is
/// the shape of defect this exists to stop: raising the block size or the
/// reorganisation window silently raises what a node must hold.
#[test]
fn the_most_a_node_will_hold_stays_something_a_phone_has() {
    let ceiling = ChainStore::held_bytes_ceiling(&params());
    // Wire bytes, which is what can be counted here. A decoded block costs
    // about 1.4 times that, measured in `examples/window.rs`, so this ceiling
    // is roughly 235 MB of memory.
    assert!(
        ceiling <= 192 * 1024 * 1024,
        "a node may be made to hold {ceiling} bytes of blocks, and half again \
         that in memory, which is past what the promise that it runs on a \
         phone can carry"
    );
}

/// A node that has not updated must not mistake the network for a liar.
///
/// The block is well formed and every peer that has updated is sending it.
/// What is out of date is this node, and the two call for opposite reactions:
/// refusing the block as bad drops every updated peer and leaves this one
/// following whoever has not updated either. So the refusal is told apart, and
/// the node stops on it rather than banning its way onto a minority chain.
#[test]
fn a_block_from_rules_this_build_lacks_is_named_as_such_and_not_as_a_bad_block() {
    let miner = wallet(1);
    let plain = params();

    let mut branch = Branch::new(plain);
    let blocks = branch.mine_empty(&miner, 6, 600);

    // The same node, told that height five is judged by rules it does not have.
    let announced = ConsensusParams {
        activations: &[
            cairn_ledger::block::Activation {
                height: 0,
                version: cairn_ledger::block::BLOCK_VERSION,
            },
            cairn_ledger::block::Activation {
                height: 5,
                version: cairn_ledger::block::BLOCK_VERSION + 1,
            },
        ],
        ..plain
    };
    let mut store = ChainStore::new(announced);

    for block in &blocks[..5] {
        store
            .add_block(block.clone(), NOW)
            .expect("everything below the change is judged as it always was");
    }

    let refused = store.add_block(blocks[5].clone(), NOW).unwrap_err();
    let outdated = refused
        .outdated()
        .expect("named as rules this build lacks, not as a bad block");

    assert_eq!(outdated.height, 5);
    assert_eq!(outdated.required, cairn_ledger::block::BLOCK_VERSION + 1);
    assert_eq!(outdated.known, cairn_ledger::block::BLOCK_VERSION);

    // Offered again it is simply already known, which is the node declining to
    // judge twice rather than judging differently. What must not happen is
    // that the first refusal put it in the set of blocks known to be bad: a
    // block this software cannot judge becomes valid the moment the node is
    // updated, and remembering it as bad would outlive the update and come
    // back through `branch_to` as an ordinary refusal — the peer blamed for
    // this node being old. That the set is untouched is pinned by the unit
    // test on `branch_to` in the crate itself, where the set is reachable.
    assert_eq!(
        store.add_block(blocks[5].clone(), NOW),
        Ok(Accepted::Duplicate)
    );

    // And every ordinary refusal still says nothing of the sort.
    assert!(ChainError::NotGenesis.outdated().is_none());
    assert!(ChainError::Corrupt.outdated().is_none());
}

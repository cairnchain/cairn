//! What the index checks when it comes back, and what it does not.
//!
//! `Index::refresh` opens with one comparison and this sentence:
//!
//! > Only the last block has to be checked: everything under it was checked
//! > when it was read, and a branch that changed under one of them changed
//! > under this one too.
//!
//! True of a branch that changed before the last block was read. The walk
//! reads up to [`BATCH`] heights a turn and goes to the chain again for every
//! one of them, with nothing held in between: `Explorer::read_a_batch` takes
//! the chain, asks it two questions, gives it back, and only then starts
//! calling `held_at`, which takes it once per height. A switch landing inside
//! that turn changes the branch under heights the walk has already read, and
//! the walk goes on to read the heights above it off the branch that won. The
//! identifier the turn ends on is then the new branch's, so the comparison at
//! the top of the next turn agrees, and it agrees for ever: nothing looks at
//! anything below the last block again.
//!
//! What is left is an index whose bottom is one branch and whose top is
//! another. The blocks in the middle are on no branch this node or anybody
//! else follows, and they are what `/api/tx`, `/api/note` and `/api/address`
//! answer out of.
//!
//! The reader below is a faithful model of what the node hands the walk: the
//! chain is asked afresh for every height, and the switch lands between two
//! of those questions. Nothing here reaches past what one turn does.

#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    dead_code
)]

#[path = "../src/index.rs"]
mod index;

use std::cell::Cell;
use std::collections::HashMap;

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::{Amount, Hash32};

use index::{Head, Held, Index, Reading};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.coinbase_maturity = 0;
    params
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

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

    fn mine(&mut self, miner: &SecretKey) -> Block {
        self.carrying(miner, Vec::new())
    }

    fn mine_many(&mut self, miner: &SecretKey, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine(miner)).collect()
    }

    fn fork(&self) -> Self {
        self.clone()
    }
}

fn spend(
    params: &ConsensusParams,
    secret: &SecretKey,
    note: (NoteId, Note),
    to: PublicKey,
    amount: Amount,
) -> Transfer {
    let mut transfer = Transfer::new(vec![Input::hot(note.0)], vec![Note::new(amount, to)]);
    transfer.sign_input(params.network, 0, &note.1, secret);
    transfer
}

/// A branch, as the walk sees it: height to block, and the identifier it
/// carries at each height.
struct Branch {
    at: HashMap<u64, Block>,
}

impl Branch {
    fn of(runs: &[&[Block]]) -> Self {
        let mut at = HashMap::new();
        for run in runs {
            for block in *run {
                at.insert(block.header.height, block.clone());
            }
        }
        Self { at }
    }

    fn tip(&self) -> u64 {
        self.at.keys().copied().max().unwrap_or(0)
    }

    fn id_at(&self, height: u64) -> Option<Hash32> {
        self.at.get(&height).map(Block::id)
    }

    fn held(&self, height: u64) -> Held {
        match self.at.get(&height) {
            Some(block) => Held::Block(Box::new(block.clone())),
            None => Held::Waiting,
        }
    }
}

/// One turn of the walk, driven the way `Explorer::read_a_batch` drives it:
/// the head is two questions asked of the chain in one go, and the reader
/// goes back to the chain for every height on its own.
fn a_turn(index: &mut Index, chain: &Branch, block_at: impl Fn(u64) -> Held) -> Reading {
    let head = Head {
        tip: chain.tip(),
        at_last_read: index.covers().and_then(|(_, through)| chain.id_at(through)),
    };
    index.refresh(&head, block_at, |height| chain.id_at(height))
}

/// A switch that lands inside a turn is never noticed, and the index keeps
/// the branch that lost for as long as the process runs.
///
/// Three blocks are common. Branch A carries a transfer paying Alice at
/// height three and runs to height ten. Branch B carries a transfer paying
/// Bob at the same height and runs to height twelve, so B is the branch the
/// node ends up following and A is the branch nobody has.
///
/// The walk reads zero to six off A. The next turn takes its head off A,
/// which agrees, and then the switch lands: from height eight on, the chain
/// answers B. The turn ends on B's block at height ten, so the turn after it
/// compares B's identifier against B's identifier and agrees.
///
/// What the index is left holding: A's blocks at heights three to seven,
/// A's transfer to Alice at a height and a position, Alice paid, Bob not
/// paid, and the reward from block zero recorded as spent by a transfer that
/// is on no branch. Every one of those is what `/api/tx`, `/api/note` and
/// `/api/address` answer out of, under a `coverage` object that says the
/// index has read the chain whole.
#[test]
fn a_switch_inside_one_turn_leaves_the_index_on_the_branch_that_lost() {
    let params = params();
    let miner = wallet(1);
    let rival = wallet(9);
    let alice = wallet(3).public_key();
    let bob = wallet(4).public_key();

    let mut base = Forge::new(params);
    let common = base.mine_many(&miner, 3);
    let reward = (
        NoteId::new(common[0].coinbase.id(), 0),
        common[0].coinbase.outputs[0],
    );
    let half = Amount::from_pebbles(params.initial_reward.as_pebbles() / 2).unwrap();

    let mut forge_a = base.fork();
    let to_alice = spend(&params, &miner, reward, alice, half);
    let mut run_a = vec![forge_a.carrying(&miner, vec![to_alice.clone()])];
    run_a.extend(forge_a.mine_many(&miner, 7));

    let mut forge_b = base.fork();
    let to_bob = spend(&params, &miner, reward, bob, half);
    let mut run_b = vec![forge_b.carrying(&rival, vec![to_bob.clone()])];
    run_b.extend(forge_b.mine_many(&rival, 9));

    let branch_a = Branch::of(&[&common, &run_a]);
    let branch_b = Branch::of(&[&common, &run_b]);
    assert_eq!(branch_a.tip(), 10);
    assert_eq!(branch_b.tip(), 12);

    let mut walk = Index::new();

    // Turn one, with the chain nowhere near its tip yet: heights zero to six
    // off A. A real walk stops here on `BATCH`; this one stops because the
    // chain had not reached higher when the head was taken.
    let short = Branch::of(&[&common, &run_a[..4]]);
    assert_eq!(short.tip(), 6);
    while a_turn(&mut walk, &short, |height| short.held(height)) == Reading::More {}
    assert_eq!(walk.covers(), Some((0, 6)));

    // Turn two. The head is taken off A and agrees, which is what the check
    // at the top of `refresh` is for. Then the switch lands: from height
    // eight the chain answers B, because by the time the walk asks, B is what
    // the node follows.
    let switched = Cell::new(0usize);
    let head = Head {
        tip: branch_a.tip(),
        at_last_read: walk
            .covers()
            .and_then(|(_, through)| branch_a.id_at(through)),
    };
    // The third argument is the chain as it stands when the turn ends, which
    // is B: the switch landed inside the turn, so that is what a question put
    // to the chain after the walk is answered from.
    let reading = walk.refresh(
        &head,
        |height| {
            if height < 8 {
                branch_a.held(height)
            } else {
                switched.set(switched.get() + 1);
                branch_b.held(height)
            }
        },
        |height| branch_b.id_at(height),
    );
    assert_eq!(switched.get(), 3, "heights eight, nine and ten came off B");
    // The turn ran to the tip it was given, so it says so. What it does not
    // do any more is keep what it read: the check at the end asks the chain
    // about every height the turn relied on, and the ones it read off A
    // disagree.
    assert_eq!(reading, Reading::Done);
    assert_eq!(
        walk.covers(),
        None,
        "an index that read part of a turn off a branch that lost holds none of it"
    );

    // Every turn after it, on the branch the node now follows.
    for _ in 0..8 {
        while a_turn(&mut walk, &branch_b, |height| branch_b.held(height)) == Reading::More {}
    }
    assert_eq!(
        walk.covers(),
        Some((0, 12)),
        "the walk is level with the tip of the branch this node follows"
    );

    // What the site would now say. Each of these is a statement about a chain
    // nobody has, served with `coverage.whole` true.
    let stranded = walk.locate(&to_alice.id());
    let real = walk.locate(&to_bob.id());
    let held_by_alice = walk.owner(&alice).map(index::OwnerRecord::balance);
    let held_by_bob = walk.owner(&bob).map(index::OwnerRecord::balance);
    let spent_by = walk.note(&reward.0).and_then(|note| note.spent_by);
    println!("the transfer on the branch that lost is at {stranded:?}");
    println!("the transfer on the branch that won  is at {real:?}");
    println!("alice holds {held_by_alice:?}, bob holds {held_by_bob:?}");
    println!(
        "the reward from block zero was spent by {spent_by:?}; the branch this node \
         follows says it was spent by {}",
        to_bob.id()
    );

    assert_eq!(
        stranded, None,
        "a transfer that is on no branch is served at a height and a position"
    );
    assert!(
        real.is_some(),
        "and the transfer that is on the branch this node follows is not in the \
         index at all: `/api/tx` answers `no such transaction` about it, with \
         `coverage.whole` true"
    );
    assert_eq!(
        held_by_alice.unwrap_or(Amount::ZERO),
        Amount::ZERO,
        "alice was paid on the branch that lost and holds {half:?} on this page"
    );
    assert_eq!(
        held_by_bob,
        Some(half),
        "and bob, who was paid on the branch this node follows, holds nothing"
    );
    assert_eq!(
        spent_by,
        Some(to_bob.id()),
        "the reward is recorded as spent by the transfer on the branch that lost"
    );
}

/// The same hole reached the other way: the switch lands after the head is
/// taken and before the first height is read.
///
/// This is the narrowest version and the one a running site meets, because
/// `read_a_batch` gives the chain back after asking it two questions and
/// takes it again inside `held_at`. In between, a peer's block can win the
/// lock. The index here has read every block there is, which is where a site
/// sits almost all the time, so the fork is under the last block read by
/// definition, and the comparison at the top of the turn was made against the
/// branch that was about to lose.
#[test]
fn a_switch_between_the_head_and_the_first_height_is_never_noticed() {
    let params = params();
    let miner = wallet(1);
    let rival = wallet(9);
    let alice = wallet(3).public_key();
    let bob = wallet(4).public_key();

    let mut base = Forge::new(params);
    let common = base.mine_many(&miner, 3);
    let reward = (
        NoteId::new(common[0].coinbase.id(), 0),
        common[0].coinbase.outputs[0],
    );
    let half = Amount::from_pebbles(params.initial_reward.as_pebbles() / 2).unwrap();

    let mut forge_a = base.fork();
    let to_alice = spend(&params, &miner, reward, alice, half);
    let run_a = vec![forge_a.carrying(&miner, vec![to_alice.clone()])];

    let mut forge_b = base.fork();
    let to_bob = spend(&params, &miner, reward, bob, half);
    let mut run_b = vec![forge_b.carrying(&rival, vec![to_bob.clone()])];
    run_b.extend(forge_b.mine_many(&rival, 2));

    let branch_a = Branch::of(&[&common, &run_a]);
    let branch_b = Branch::of(&[&common, &run_b]);

    let mut walk = Index::new();
    while a_turn(&mut walk, &branch_a, |height| branch_a.held(height)) == Reading::More {}
    assert_eq!(walk.covers(), Some((0, 3)), "level with A's tip");

    // The head, taken with the chain in hand, on the branch that is about to
    // lose. It agrees, so nothing is thrown away.
    let head = Head {
        tip: branch_b.tip(),
        at_last_read: walk
            .covers()
            .and_then(|(_, through)| branch_a.id_at(through)),
    };
    // The chain is given back. The switch lands. Every height the walk now
    // asks for comes off B.
    while walk.refresh(
        &head,
        |height| branch_b.held(height),
        |height| branch_b.id_at(height),
    ) == Reading::More
    {}
    while a_turn(&mut walk, &branch_b, |height| branch_b.held(height)) == Reading::More {}

    assert_eq!(walk.covers(), Some((0, 5)));
    assert_eq!(
        walk.locate(&to_alice.id()),
        None,
        "one block of branch A is still in the index, and the transfer on it is \
         served at a height and a position on a branch nobody has. The whole of \
         what a switch this shallow costs is a comparison made one instant too \
         early."
    );
}

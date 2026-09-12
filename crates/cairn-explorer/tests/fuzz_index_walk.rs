//! The walk is a state machine over a branch that moves under it, and it had
//! no target.
//!
//! Every fuzz target in this workspace reads bytes. `Index::refresh` reads
//! something else: a `Head` taken from the chain at one instant and a run of
//! `Held` answers taken from it at later ones, and what makes it interesting
//! is exactly that those instants are not the same instant. It has one
//! invariant and it is worth a campaign of its own:
//!
//! > Everything the index holds came off the branch this node follows.
//!
//! The generator below draws a run of turns. Each turn takes its head off the
//! branch in force, then lets a switch land at a drawn height inside the
//! turn, which is what a peer's block does to a walk that has already given
//! the chain back. After the run, the branch is held still and the walk is
//! given twenty more turns to notice anything it missed. Then the invariant
//! is checked against the branch the node ended on.
//!
//! Blocks are built rather than mined. Nothing here goes near consensus: the
//! walk does not validate, and what is under test is which branch a block
//! came off, not whether it is a good one.
//!
//! A failure is a seed and a case number, the way the rest of the suite
//! reports one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::map_unwrap_or,
    dead_code
)]

#[path = "../src/index.rs"]
mod index;

use std::collections::HashMap;

use cairn_crypto::PublicKey;
use cairn_fuzz::{Campaign, Rng};
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::{Amount, Hash32};

use index::{Head, Held, Index, Reading};

/// Heights the two branches share.
const FORK: u64 = 4;
/// Heights each branch carries of its own.
const OWN: u64 = 10;

/// A key for `seed`, and never the key for another seed.
///
/// About half of all thirty two byte strings are not a point, so a derivation
/// that moves on to the next seed when one is refused hands two seeds the
/// same key half the time. This retries inside `seed`'s own stream instead.
/// The first version of this file did it the other way and two branches paid
/// the same address, which made the campaign below report a defect it had not
/// found.
fn key(seed: u64) -> PublicKey {
    let mut attempt = 0u64;
    loop {
        let mut bytes = [0u8; 32];
        let mut hasher =
            cairn_primitives::hash::Hasher::new(cairn_primitives::hash::Domain::NoteKey);
        hasher.update(&seed.to_le_bytes());
        hasher.update(&attempt.to_le_bytes());
        bytes.copy_from_slice(hasher.finalize().as_bytes());
        if let Ok(found) = PublicKey::from_bytes(&bytes) {
            return found;
        }
        attempt = attempt.saturating_add(1);
    }
}

fn finish(height: u64, coinbase: CoinbaseTransaction, transfers: Vec<Transfer>) -> Block {
    let params = ConsensusParams::testnet();
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            network: params.network,
            height,
            previous: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 1_000 + height,
            difficulty: 1,
            total_work: u128::from(height),
            nonce: height,
        },
        coinbase,
        transfers,
    };
    block.header.transactions_root = block.transactions_root();
    block
}

/// One branch: every height it carries, and what the site would be answering
/// about if this is the branch that wins.
struct Branch {
    at: HashMap<u64, Block>,
    /// The transfer each of this branch's own heights carries.
    transfers: Vec<Hash32>,
    payee: PublicKey,
}

impl Branch {
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

/// The common heights, then two branches that part at [`FORK`].
///
/// Each branch pays its own address out of the coinbase below it, so which
/// branch the index is holding is readable off one balance and off whether a
/// transfer is anywhere at all.
fn two_branches() -> (Branch, Branch) {
    let params = ConsensusParams::testnet();
    let half = Amount::from_pebbles(params.initial_reward.as_pebbles() / 2).unwrap();
    let common: Vec<Block> = (0..FORK)
        .map(|height| {
            let coinbase = CoinbaseTransaction::with_extra(
                height,
                vec![Note::new(params.initial_reward, key(0))],
                vec![0],
            );
            finish(height, coinbase, Vec::new())
        })
        .collect();

    let mut built = Vec::new();
    for tag in [1u8, 2u8] {
        let miner = key(u64::from(tag));
        let payee = key(u64::from(tag) + 100);
        let mut at: HashMap<u64, Block> = common
            .iter()
            .map(|block| (block.header.height, block.clone()))
            .collect();
        let mut transfers = Vec::new();
        let mut previous = common[common.len() - 1].coinbase.id();
        for step in 0..OWN {
            let height = FORK + step;
            let coinbase = CoinbaseTransaction::with_extra(
                height,
                vec![Note::new(params.initial_reward, miner)],
                vec![tag],
            );
            // Spends the coinbase of the height below, on this branch, so the
            // transfer is one no other branch could carry.
            let transfer = Transfer::new(
                vec![Input::hot(NoteId::new(previous, 0))],
                vec![Note::new(half, payee)],
            );
            transfers.push(transfer.id());
            previous = coinbase.id();
            at.insert(height, finish(height, coinbase, vec![transfer]));
        }
        built.push(Branch {
            at,
            transfers,
            payee,
        });
    }
    let second = built.pop().unwrap();
    let first = built.pop().unwrap();
    assert_ne!(
        first.payee, second.payee,
        "the two branches have to pay two different addresses or nothing below \
         reads anything"
    );
    assert!(
        first
            .transfers
            .iter()
            .all(|id| !second.transfers.contains(id)),
        "and carry two different sets of transfers"
    );
    (first, second)
}

/// One turn, driven the way `Explorer::read_a_batch` drives it: the head is
/// two questions asked of the chain in one go, and every height after that is
/// asked again, separately.
/// `head_from` is the branch the chain was on when the head was taken, and
/// `ends_on` the branch it is on when the turn finishes. They differ exactly
/// when a switch landed inside the turn, which is what this campaign is for.
fn turn(
    walk: &mut Index,
    head_from: &Branch,
    ends_on: &Branch,
    tip: u64,
    read: impl Fn(u64) -> Held,
) -> Reading {
    let head = Head {
        tip,
        at_last_read: walk
            .covers()
            .and_then(|(_, through)| head_from.id_at(through)),
    };
    walk.refresh(&head, read, |height| ends_on.id_at(height))
}

/// Nothing the index holds is off a branch this node has left.
#[test]
fn the_walk_never_settles_holding_a_branch_the_node_left() {
    let (first, second) = two_branches();
    let branches = [&first, &second];
    let campaign = Campaign::named("index walk");
    let mut switched = 0usize;
    let mut mixed = 0usize;

    let ran = campaign.run(4_000, |case, rng: &mut Rng| {
        let mut walk = Index::new();
        let mut following = 0usize;

        for _ in 0..rng.between(1, 8) {
            let from = branches[following];
            // A turn does not always run to the tip: the chain the head was
            // taken off may not have reached it yet.
            let tip = rng.below(usize::try_from(FORK + OWN).unwrap_or(1)) as u64;
            if rng.chance(2) {
                // A switch lands inside the turn, at a height drawn from the
                // whole run, so it lands above what the walk has read as
                // often as below it.
                let flip = rng.below(usize::try_from(FORK + OWN).unwrap_or(1)) as u64;
                let other = 1 - following;
                let served = branches[other];
                switched += 1;
                while turn(&mut walk, from, served, tip, |height| {
                    if height < flip {
                        from.held(height)
                    } else {
                        served.held(height)
                    }
                }) == Reading::More
                {}
                following = other;
            } else {
                while turn(&mut walk, from, from, tip, |height| from.held(height)) == Reading::More
                {
                }
            }
        }

        // The branch is held still, and the walk is given every chance to
        // notice. A site does this every five hundred milliseconds for as
        // long as it runs.
        let settled = branches[following];
        let left = branches[1 - following];
        for _ in 0..20 {
            while turn(&mut walk, settled, settled, settled.tip(), |height| {
                settled.held(height)
            }) == Reading::More
            {}
        }

        let Some((_, through)) = walk.covers() else {
            return;
        };

        // Every transfer the index can place is one the settled branch
        // carries at that height.
        for (step, id) in settled.transfers.iter().enumerate() {
            let height = FORK + step as u64;
            if height > through {
                continue;
            }
            assert_eq!(
                walk.locate(id).map(|at| at.height),
                Some(height),
                "case {case} of seed {:#x}: the index has read through {through} and \
                 cannot place the transfer the branch it follows carries at {height}",
                campaign.seed(),
            );
        }
        for (step, id) in left.transfers.iter().enumerate() {
            let height = FORK + step as u64;
            if settled.transfers.get(step) == Some(id) {
                continue;
            }
            if walk.locate(id).is_some() {
                mixed += 1;
            }
            assert_eq!(
                walk.locate(id),
                None,
                "case {case} of seed {:#x}: the index places a transfer from the \
                 branch this node left at height {height}, and has been given \
                 twenty turns on the branch it follows since. `Index::refresh` \
                 compares one identifier at the top of a turn and reads up to \
                 BATCH heights after it, so a switch that lands inside a turn \
                 leaves the bottom of the index on one branch and the top on \
                 another, and every turn after it agrees with itself.",
                campaign.seed(),
            );
        }
        // And the balances follow from that.
        let theirs = walk
            .owner(&left.payee)
            .map(index::OwnerRecord::balance)
            .unwrap_or(Amount::ZERO);
        assert_eq!(
            theirs,
            Amount::ZERO,
            "case {case} of seed {:#x}: an address paid only on the branch this \
             node left holds {theirs:?}",
            campaign.seed(),
        );
    });

    eprintln!(
        "{} of {} cases put a switch inside a turn; {mixed} left the index mixed",
        switched, ran.cases
    );
    assert!(
        switched > ran.cases / 4,
        "only {switched} of {} cases ever moved the branch, so this campaign is \
         not testing what it says it tests",
        ran.cases
    );
}

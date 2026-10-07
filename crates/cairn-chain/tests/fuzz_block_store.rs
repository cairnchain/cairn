//! The block store, handed one network's blocks in any order.
//!
//! Every test of `ChainStore` in this crate builds the sequence it means to
//! ask about: a rival one block heavier, a twin sent first, four thousand
//! side blocks off one parent. Each holds what it was written for, and none
//! of them asks what happens between those shapes, which is where a store
//! fed by strangers spends its life. The attack catalogue of the testnet-8
//! wave names this as the gap ("stateful `ChainStore::add_block` sequences")
//! and E05 as what it would find: a side store full of junk dropping honest
//! side blocks oldest first, so that a node on a losing branch never takes
//! the heavier one.
//!
//! Each case mints a small tree of honest blocks on one network, branches of
//! different spacing so that work and height part company, and beside them
//! blocks that are wrong in one way each: a difficulty the retarget does not
//! ask for, a total work that does not add up, a coinbase that pays itself
//! one pebble more, a twin with another body under the same identifier, a
//! timestamp at the median, a nonce that misses its target, a height one too
//! high, another network, and a block built on one of those. They are handed
//! to a fresh store shuffled, some withheld, some twice, often before their
//! parent; some cases add a flood of junk past the side store's ceiling, by
//! count or by bytes. Last, the heaviest honest branch is handed over once
//! more, in order from the first block.
//!
//! A flood comes at one of two prices. Free junk claims difficulty one
//! whatever its parent demands, which is what E05 was made of, and hangs just
//! under the store's tip, where E05 hangs it; the store refuses every block
//! of it at the door now, and the properties below hold it to refusing
//! without moving. Paid junk carries exactly what its parent demands, which
//! is the cheapest a place beside the branch can be had for, and is what
//! presses the side store's bounds. It hangs off the heaviest honest branch,
//! at or under where the store's branch leaves it, so that it weighs no more
//! than the first block of that branch the store lacks: a branch heavier than
//! those blocks displaces them by design, paying its parent's demand for
//! every block it holds, and the closing property below is about junk that
//! does not outweigh the branch it competes with.
//!
//! After every block it holds, against the tree as minted rather than
//! against anything the store reports about itself:
//!
//! 1. Nothing panics.
//! 2. The tip is an honest block, the ledger is the one that block commits
//!    to, and the branch the store calls active is that block's ancestry.
//! 3. No branch the store holds in full, every block of it valid, is one
//!    the fork choice takes over the branch it follows: more work, and at
//!    the followed tip's own height more than half that tip's difficulty
//!    more. Save one the store kept aside as a tie when it last weighed it,
//!    since a branch is weighed when a block of it arrives: the branch
//!    followed can grow past a tie's height by a block lighter than the
//!    tie's margin, and the tie stays aside until its next block comes.
//! 4. What the store keeps off its branch stays within `MAX_SIDE_BLOCKS` and
//!    `MAX_SIDE_BYTES`, counted here from the bodies it holds, and the count
//!    it keeps of its own bytes is that count.
//! 5. A refusal changes nothing it follows: the tip and the ledger are as
//!    they were, nothing valid is let go of, and the only block it may now
//!    hold that it did not is the one it refused. A body held under an
//!    identifier is never swapped for another.
//! 6. The same sequence handed to a second store gives the same answer and
//!    the same tip at every step.
//!
//! And once the heaviest honest branch has been handed over in order, the
//! store follows a branch it does not take over: that one, or one of its
//! height within half a block of it. That is the catalogue's own statement
//! of what E05 breaks, "an honest heavier branch delivered in order is
//! followed whatever else is interleaved", and the six above cannot see it:
//! a block dropped by the sweep is not held, so a branch missing it is not
//! one the store holds in full.
//!
//! During a flood the junk is checked a block at a time against the bounds
//! and the tip only, since counting thousands of held blocks after each of
//! thousands of arrivals is a square nobody would wait for; everything is
//! checked again once the flood has landed.
//!
//! A failing case is cut down before it is reported, step by step and flood
//! by flood, to the shortest sequence that still breaks the same property,
//! and that sequence is written beside the record `Campaign` keeps, under
//! `target/fuzz/`. A property that fails is reported, not loosened.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use cairn_chain::{
    Accepted, ChainError, ChainStore, HELD_OVERHEAD, MAX_SIDE_BLOCKS, MAX_SIDE_BYTES,
};
use cairn_crypto::SecretKey;
use cairn_fuzz::{Campaign, Rng};
use cairn_ledger::block::{Block, BlockHeader, BLOCK_VERSION};
use cairn_ledger::note::{NetworkId, Note, NoteId};
use cairn_ledger::pow::{median_time_past, meets_target, next_difficulty};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, expected_difficulty, mine_block, mine_header, ConsensusParams,
};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

/// When the network opens, and when its first block is dated.
const OPENS: u64 = 1_000_000;

/// The store's clock: past every timestamp minted here, so no honest block
/// is ever refused for being early and the one rule that reads the clock
/// does not stand between a block and its verdict.
const NOW: u64 = 4_000_000_000;

const ATTEMPTS: u64 = 1 << 28;

/// The opening difficulty of an ordinary case: off the floor, so a branch
/// spaced tightly asks more of each block and one spaced loosely less, and
/// cheap to mine.
const LIGHT: u64 = 16;

/// The opening difficulty of a case with a free flood.
///
/// A flood of junk claiming difficulty one weighs a unit a block. Hung off a
/// block a few honest blocks below the tip it is lighter than the tip only if
/// an honest block is worth more than the whole flood, which is the shape E05
/// describes and the one a real network is in. At `LIGHT` the flood would
/// outweigh the honest chain and be tried and refused instead, which is
/// another case and not that one; and the retarget could bring the honest
/// difficulty down to one, where the free junk would be paid junk.
///
/// A paid flood opens at `LIGHT`. Its junk costs what an honest block costs,
/// and at this difficulty four thousand of them would be thirty three million
/// hashes a flood.
const HEAVY: u64 = 8_192;

/// What one block of a fat flood is made to weigh.
const FAT_BYTES: usize = 512 * 1024;

fn rules(opening: u64) -> ConsensusParams {
    let mut params = ConsensusParams::testnet();
    params.opens_at = OPENS;
    params.genesis_difficulty = opening;
    params
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A block minted on the honest network, with the ledger it leaves behind.
#[derive(Clone, Debug)]
struct Honest {
    block: Block,
    parent: Option<usize>,
    after: LedgerState,
    work: u128,
}

/// How a block in a case's universe came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Minted on the network, by its index there.
    Honest(usize),
    /// Wrong in the way named.
    Malformed(&'static str),
}

/// One block a case can hand the store, and the honest block it was made
/// beside, which is where the shuffle tries to place it.
#[derive(Clone, Debug)]
struct Entry {
    block: Block,
    kind: Kind,
    near: usize,
}

/// Everything one case hands out.
#[derive(Clone, Debug)]
struct Network {
    params: ConsensusParams,
    honest: Vec<Honest>,
    /// The honest blocks first, at the same indices, then the malformed ones.
    universe: Vec<Entry>,
    honest_by_id: HashMap<Hash32, usize>,
    /// The honest block with the most work behind it, earliest minted on a
    /// tie.
    heaviest: usize,
}

/// Whether the fork choice takes a branch ending at `rival` over one ending
/// at `followed`: more work, and at the followed tip's own height more than
/// half its difficulty more.
///
/// Written out here rather than asked of the store, so that the store is held
/// to the rule and not to itself.
fn takes(rival: &BlockHeader, followed: &BlockHeader) -> bool {
    rival.total_work > followed.total_work
        && (rival.height != followed.height
            || rival.total_work - followed.total_work > u128::from(followed.difficulty) / 2)
}

/// Whether a branch ending at `rival` carries more work than one ending at
/// `followed` and is still a tie: the same height, within half the followed
/// tip's difficulty.
fn ties(rival: &BlockHeader, followed: &BlockHeader) -> bool {
    rival.total_work > followed.total_work && !takes(rival, followed)
}

impl Network {
    fn max_work(&self) -> u128 {
        self.honest[self.heaviest].work
    }

    /// The header of the honest block the store follows, if it follows one.
    fn followed(&self, store: &ChainStore) -> Option<&BlockHeader> {
        store
            .tip()
            .and_then(|tip| self.honest_by_id.get(&tip))
            .map(|index| &self.honest[*index].block.header)
    }

    /// Whether `body` is the honest block minted under `id`.
    fn is_valid(&self, id: &Hash32, body: &Block) -> bool {
        self.honest_by_id
            .get(id)
            .is_some_and(|index| self.honest[*index].block == *body)
    }

    /// The honest blocks from the first to `tip`, oldest first.
    fn ancestry(&self, tip: usize) -> Vec<usize> {
        let mut path = vec![tip];
        let mut at = tip;
        while let Some(parent) = self.honest[at].parent {
            path.push(parent);
            at = parent;
        }
        path.reverse();
        path
    }
}

/// Mints the next honest block on `state`.
fn mint(params: &ConsensusParams, state: &LedgerState, timestamp: u64, salt: u64) -> Block {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::with_extra(
        height,
        vec![Note::new(params.reward_at(height), wallet(1).public_key())],
        salt.to_le_bytes().to_vec(),
    );
    let block = assemble_block(state, coinbase, Vec::new(), params, timestamp, 0).unwrap();
    mine_block(block, ATTEMPTS).expect("a nonce at this difficulty")
}

/// The gap a branch leaves before its next block.
///
/// Tight ones climb the difficulty slowly, loose ones bring it down by up to
/// the clamp's quarter a block, so two branches of one height carry
/// different work.
fn gap(rng: &mut Rng) -> u64 {
    *rng.pick(&[1, 20, 59, 60, 61, 600, 3_600, 7_200, 14_400])
        .unwrap()
}

/// The honest tree: a first block, then each block on one already minted,
/// mostly the newest or one below it, sometimes anywhere.
fn honest_tree(rng: &mut Rng, params: &ConsensusParams, count: usize, salt: u64) -> Vec<Honest> {
    let genesis = mint(params, &LedgerState::new(), OPENS, salt);
    let mut after = LedgerState::new();
    connect_block(&mut after, &genesis, params, NOW).unwrap();
    let mut honest = vec![Honest {
        work: genesis.header.total_work,
        block: genesis,
        parent: None,
        after,
    }];
    while honest.len() < count {
        let newest = honest.len() - 1;
        let parent = if rng.chance(4) {
            rng.below(honest.len())
        } else {
            newest.saturating_sub(rng.below(2))
        };
        let timestamp = honest[parent].block.header.timestamp + gap(rng);
        let block = mint(
            params,
            &honest[parent].after,
            timestamp,
            salt ^ (honest.len() as u64) << 32,
        );
        let mut after = honest[parent].after.clone();
        connect_block(&mut after, &block, params, NOW).unwrap();
        honest.push(Honest {
            work: block.header.total_work,
            block,
            parent: Some(parent),
            after,
        });
    }
    honest
}

/// Turns the nonce until the header meets the difficulty it claims.
fn remine(header: BlockHeader) -> BlockHeader {
    mine_header(header, ATTEMPTS).expect("a nonce at the claimed difficulty")
}

/// A block made wrong in one way, beside an honest one.
fn malformed(
    rng: &mut Rng,
    params: &ConsensusParams,
    honest: &[Honest],
    built: &[Entry],
    salt: u64,
) -> Option<Entry> {
    let near = rng.below(honest.len());
    let original = &honest[near];
    let before = original
        .parent
        .map_or_else(LedgerState::new, |parent| honest[parent].after.clone());
    let parent_work = original.parent.map_or(0, |parent| honest[parent].work);
    let asked = expected_difficulty(&before, params);
    let mut block = original.block.clone();
    let kind = match rng.below(10) {
        0 => {
            let claimed = match rng.below(4) {
                0 => asked + 1,
                1 => asked * 2,
                2 => 1,
                _ => asked.saturating_sub(1).max(1),
            };
            if claimed == asked {
                return None;
            }
            block.header.difficulty = claimed;
            block.header.total_work = parent_work + u128::from(claimed);
            block.header = remine(block.header);
            "a difficulty the retarget does not ask for"
        }
        1 => {
            block.header.total_work += 1 + rng.below(3) as u128;
            block.header = remine(block.header);
            "a total work that does not add up"
        }
        2 => {
            let paid = block.coinbase.outputs[0];
            let more = Amount::from_pebbles(paid.value.as_pebbles() + 1).unwrap();
            block.coinbase.outputs[0] = Note::new(more, paid.owner);
            block.header.transactions_root = block.transactions_root();
            block.header = remine(block.header);
            "a coinbase paying itself a pebble more"
        }
        3 => {
            // The header untouched, so the identifier and the work are the
            // honest block's; the body is not the one the header names.
            block.coinbase =
                CoinbaseTransaction::with_extra(block.header.height, Vec::new(), vec![0xee; 8]);
            "a twin with another body"
        }
        4 => {
            let median = median_time_past(before.recent_headers())?;
            block.header.timestamp = median;
            block.header = remine(block.header);
            "a timestamp at the median"
        }
        5 => {
            if block.header.difficulty < 2 {
                return None;
            }
            let mut nonce = rng.edgy_u64();
            loop {
                block.header.nonce = nonce;
                if !meets_target(&block.id(), block.header.difficulty) {
                    break;
                }
                nonce = nonce.wrapping_add(1);
            }
            "a nonce that misses its target"
        }
        6 => {
            block.header.height += 1;
            block.header = remine(block.header);
            "a height one too high"
        }
        7 => {
            block.header.network = NetworkId::new(0x5eed_0001);
            block.header = remine(block.header);
            "another network"
        }
        _ => {
            // A block built on one of the above, as though it were sound.
            let wrong: Vec<&Entry> = built
                .iter()
                .filter(|entry| matches!(entry.kind, Kind::Malformed(_)))
                .collect();
            let under = rng.pick(&wrong)?;
            let parent = &under.block.header;
            let height = parent.height + 1;
            let mut child = Block {
                header: BlockHeader {
                    version: BLOCK_VERSION,
                    network: params.network,
                    height,
                    previous: under.block.id(),
                    transactions_root: Hash32::ZERO,
                    state_root: Hash32::ZERO,
                    history: Hash32::ZERO,
                    timestamp: parent.timestamp + 60,
                    difficulty: parent.difficulty,
                    total_work: parent.total_work + u128::from(parent.difficulty),
                    nonce: 0,
                },
                coinbase: CoinbaseTransaction::with_extra(
                    height,
                    vec![Note::new(params.reward_at(height), wallet(2).public_key())],
                    salt.to_le_bytes().to_vec(),
                ),
                transfers: Vec::new(),
            };
            child.header.transactions_root = child.transactions_root();
            child.header = remine(child.header);
            return Some(Entry {
                block: child,
                kind: Kind::Malformed("a block built on a malformed one"),
                near: under.near,
            });
        }
    };
    Some(Entry {
        block,
        kind: Kind::Malformed(kind),
        near,
    })
}

/// A case's network: the honest tree and what was made wrong beside it.
fn network(rng: &mut Rng, flood: Option<Price>, salt: u64) -> Network {
    let flooded = flood.is_some();
    let params = rules(if flood == Some(Price::Free) {
        HEAVY
    } else {
        LIGHT
    });
    let count = if flooded {
        rng.between(6, 16)
    } else {
        rng.between(2, 40)
    };
    let honest = honest_tree(rng, &params, count, salt);
    let mut universe: Vec<Entry> = honest
        .iter()
        .enumerate()
        .map(|(index, minted)| Entry {
            block: minted.block.clone(),
            kind: Kind::Honest(index),
            near: index,
        })
        .collect();
    let wanted = if flooded {
        rng.between(1, 5)
    } else {
        rng.between(0, count / 2 + 2)
    };
    for attempt in 0..wanted * 2 {
        if universe.len() >= honest.len() + wanted {
            break;
        }
        let salt = salt ^ 0xbad0_0000 ^ attempt as u64;
        if let Some(entry) = malformed(rng, &params, &honest, &universe, salt) {
            universe.push(entry);
        }
    }
    let honest_by_id = honest
        .iter()
        .enumerate()
        .map(|(index, minted)| (minted.block.id(), index))
        .collect();
    let heaviest = (0..honest.len())
        .max_by(|a, b| honest[*a].work.cmp(&honest[*b].work).then(b.cmp(a)))
        .unwrap();
    Network {
        params,
        honest,
        universe,
        honest_by_id,
        heaviest,
    }
}

/// How the junk of a flood hangs together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Each block on the one before, so the flood spans heights above where
    /// it hangs, which is how E05 places it.
    Chain,
    /// Every block on the same parent, at one height.
    Siblings,
    /// Siblings of half a megabyte, past the ceiling on bytes long before the
    /// one on count.
    Fat,
}

/// What a flood's junk pays for its place beside the branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Price {
    /// Difficulty one whatever its parent demands: E05's junk, refused at the
    /// door.
    Free,
    /// Exactly what its parent demands, which the door takes.
    Paid,
}

/// One thing handed to the store.
#[derive(Clone, Debug)]
enum Step {
    /// A block of the case's universe, by its place there.
    Offer(usize),
    /// Junk claiming the least work there is, hung off the block `depth`
    /// below the store's tip when the flood lands.
    ///
    /// Placed against the tip rather than against a block of the tree, so
    /// the flood hangs off something the store holds whatever the order
    /// before it: a block the store has not been handed refuses every block
    /// of the flood as a parent it has never seen, and that flood presses on
    /// nothing.
    ///
    /// Paid junk hangs no higher than where the store's branch leaves the
    /// heaviest honest one, so it hangs off that branch too. See the module
    /// documentation for why.
    Flood {
        depth: u64,
        count: usize,
        shape: Shape,
        price: Price,
        salt: u64,
    },
}

/// A block of junk: the least work there is, a root that matches its body,
/// and nothing else right about it.
fn junk(height: u64, previous: Hash32, nonce: u64, bytes: usize) -> Block {
    let owner = wallet(3);
    let value = Amount::from_pebbles(1).unwrap();
    let per = Note::new(value, owner.public_key()).encode().len();
    let transfers = if bytes == 0 {
        Vec::new()
    } else {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&nonce.to_le_bytes());
        vec![Transfer::new(
            vec![Input::hot(NoteId::new(Hash32::from_bytes(seed), 0))],
            (0..bytes / per)
                .map(|_| Note::new(value, owner.public_key()))
                .collect(),
        )]
    };
    let mut block = Block {
        header: BlockHeader {
            version: BLOCK_VERSION,
            network: NetworkId::TESTNET,
            height,
            previous,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: OPENS + height,
            difficulty: 1,
            total_work: 0,
            nonce,
        },
        coinbase: CoinbaseTransaction::new(height, Vec::new()),
        transfers,
    };
    block.header.transactions_root = block.transactions_root();
    block
}

/// A block of junk that pays for its place: the difficulty its parent
/// demands and the work behind it, dated a block after its parent so that a
/// chain of them keeps that difficulty, and nothing else right about it.
///
/// Its coinbase carries `nonce`, so blocks on one parent differ in body as
/// well as in the nonce the mining turns.
fn paid_junk(params: &ConsensusParams, parent: &BlockHeader, nonce: u64, bytes: usize) -> Block {
    let height = parent.height + 1;
    let mut block = junk(height, parent.id(), nonce, bytes);
    block.coinbase =
        CoinbaseTransaction::with_extra(height, Vec::new(), nonce.to_le_bytes().to_vec());
    block.header.timestamp = parent.timestamp + params.target_block_time;
    block.header.difficulty =
        next_difficulty(&parent.summary(), params.origin(), params.target_block_time);
    block.header.total_work = parent.total_work + u128::from(block.header.difficulty);
    block.header.transactions_root = block.transactions_root();
    block.header = remine(block.header);
    block
}

/// The heights of a case, in the order the store is handed them.
///
/// The universe in the order it was minted, each malformed block placed
/// after the honest block it was made beside; then neighbours swapped, a few
/// blocks moved anywhere, some withheld, some handed over twice, and maybe a
/// flood.
fn sequence(rng: &mut Rng, network: &Network, flood: Option<Price>) -> Vec<Step> {
    let honest = network.honest.len();
    let mut order: Vec<usize> = (0..honest).collect();
    for index in honest..network.universe.len() {
        let near = network.universe[index].near;
        let after = order.iter().position(|at| *at == near).unwrap_or(0);
        let at = rng.between(after + 1, order.len());
        order.insert(at, index);
    }
    for _ in 0..order.len() / 3 {
        let at = rng.below(order.len());
        let with = (at + 1 + rng.below(3)).min(order.len() - 1);
        order.swap(at, with);
    }
    for _ in 0..rng.below(3) {
        let from = rng.below(order.len());
        let moved = order.remove(from);
        let to = rng.below(order.len() + 1);
        order.insert(to, moved);
    }
    let withhold = rng.pick(&[0u64, 8, 4, 3]).copied().unwrap();
    order.retain(|_| !rng.chance(withhold));
    let mut steps: Vec<Step> = order.into_iter().map(Step::Offer).collect();
    for _ in 0..rng.below(steps.len() / 4 + 2) {
        if steps.is_empty() {
            break;
        }
        let from = rng.below(steps.len());
        let copy = steps[from].clone();
        let to = rng.between(from, steps.len());
        steps.insert(to, copy);
    }
    if let Some(price) = flood {
        // Off the tip's parent or close to it, which is where E05 hangs it:
        // the junk then sits above the heights an honest rival arrives at.
        let depth = rng.between(1, 3) as u64;
        let shape = *rng
            .pick(&[Shape::Chain, Shape::Chain, Shape::Siblings, Shape::Fat])
            .unwrap();
        let count = match shape {
            Shape::Fat => MAX_SIDE_BYTES / FAT_BYTES + rng.between(1, 8),
            _ => MAX_SIDE_BLOCKS + rng.between(1, 200),
        };
        let at = rng.between(steps.len() / 3, steps.len());
        steps.insert(
            at,
            Step::Flood {
                depth,
                count,
                shape,
                price,
                salt: rng.edgy_u64(),
            },
        );
    }
    steps
}

/// The steps that close every case: the heaviest honest branch, in order
/// from the first block.
fn in_order(network: &Network) -> Vec<Step> {
    network
        .ancestry(network.heaviest)
        .into_iter()
        .map(Step::Offer)
        .collect()
}

/// A property that did not hold, and where.
#[derive(Clone, Debug)]
struct Failure {
    property: &'static str,
    step: usize,
    said: String,
}

/// What a run saw, for the campaign to report and to hold a floor on.
#[derive(Debug, Default)]
struct Tally {
    answers: BTreeMap<String, usize>,
    malformed: BTreeMap<&'static str, usize>,
    floods: BTreeMap<String, usize>,
    /// Blocks after which the store held exactly as many side blocks as it
    /// may, or more than `MAX_SIDE_BYTES` less one fat block in bytes.
    at_the_ceiling: usize,
    /// Switches that left the node lower than it was: fewer, harder blocks.
    went_down: usize,
    /// Cases whose closing delivery moved the tip.
    closing_moved: usize,
    closing_moved_after_a_flood: usize,
    /// Honest blocks kept aside as a tie: heavier than the tip followed, at
    /// its height, by no more than half its difficulty.
    ties_kept: usize,
}

/// The name of an answer, without what it carries.
fn kind_of(answer: &Result<Accepted, ChainError>) -> String {
    let said = match answer {
        Ok(accepted) => format!("{accepted:?}"),
        Err(refused) => format!("{refused:?}"),
    };
    let end = said.find([' ', '(', '{']).unwrap_or(said.len());
    said[..end].to_owned()
}

/// The source of a body the store may hold, so it can be weighed without
/// encoding it again on every step.
#[derive(Clone, Copy, Debug)]
enum Source {
    Universe(usize),
    Junk(usize),
}

/// What the store holds, as this file counts it.
#[derive(Clone, Debug)]
struct Held {
    tip: Option<Hash32>,
    work: u128,
    state_root: Hash32,
    /// Every identifier held, and whether the body under it is valid.
    blocks: HashMap<Hash32, bool>,
}

/// One run of a sequence against a fresh store.
struct Run<'a> {
    network: &'a Network,
    store: ChainStore,
    junk: Vec<Block>,
    /// Every body handed over under each identifier, with its encoded size.
    known: HashMap<Hash32, Vec<(Source, usize)>>,
    /// Honest blocks the store kept aside, the last time it weighed them, as
    /// a tie with the branch it then followed. See property 3.
    tied: HashSet<Hash32>,
    trace: Vec<String>,
}

impl<'a> Run<'a> {
    fn new(network: &'a Network) -> Self {
        let mut known: HashMap<Hash32, Vec<(Source, usize)>> = HashMap::new();
        for (index, entry) in network.universe.iter().enumerate() {
            known
                .entry(entry.block.id())
                .or_default()
                .push((Source::Universe(index), entry.block.encode().len()));
        }
        Self {
            network,
            store: ChainStore::new(network.params),
            junk: Vec::new(),
            known,
            tied: HashSet::new(),
            trace: Vec::new(),
        }
    }

    fn body(&self, source: Source) -> &Block {
        match source {
            Source::Universe(index) => &self.network.universe[index].block,
            Source::Junk(index) => &self.junk[index],
        }
    }

    /// The encoded size of the body the store holds under `id`, and whether
    /// it is valid, or what is wrong with it.
    fn weigh(&self, id: &Hash32) -> Result<(usize, bool), String> {
        let held = self
            .store
            .block(id)
            .ok_or_else(|| format!("{id:?} is held with no body, and nothing here lets one go"))?;
        let candidates = self.known.get(id).map_or(&[][..], Vec::as_slice);
        let (_, size) = candidates
            .iter()
            .find(|(source, _)| self.body(*source) == held)
            .ok_or_else(|| format!("{id:?} is held under a body nobody handed over"))?;
        Ok((*size, self.network.is_valid(id, held)))
    }

    fn held(&self) -> Result<Held, String> {
        let mut blocks = HashMap::new();
        for id in self.known.keys() {
            if self.store.contains(id) {
                let (_, valid) = self.weigh(id)?;
                blocks.insert(*id, valid);
            }
        }
        if blocks.len() != self.store.len() {
            return Err(format!(
                "the store counts {} blocks and holds {} of those handed to it",
                self.store.len(),
                blocks.len()
            ));
        }
        Ok(Held {
            tip: self.store.tip(),
            work: self.store.total_work(),
            state_root: self.store.state().state_root(),
            blocks,
        })
    }

    /// Properties 2 to 4, against the tree as minted.
    fn check(&self, step: usize, tally: &mut Option<&mut Tally>) -> Result<(), Failure> {
        let fail = |property: &'static str, said: String| Failure {
            property,
            step,
            said,
        };
        let network = self.network;

        // 2. The tip, the ledger, and the branch called active.
        let Some(tip) = self.store.tip() else {
            // Counted rather than asked `is_empty`, which answers whether the
            // store follows a branch and not whether it holds anything.
            let held = self.store.len();
            if held > 0 {
                return Err(fail(
                    "the tip is an honest block",
                    format!("no tip, and {held} blocks held"),
                ));
            }
            return Ok(());
        };
        let Some(&at) = network.honest_by_id.get(&tip) else {
            return Err(fail(
                "the tip is an honest block",
                format!("the tip {tip:?} is no honest block"),
            ));
        };
        let minted = &network.honest[at];
        if self.store.block(&tip) != Some(&minted.block) {
            return Err(fail(
                "the tip is an honest block",
                format!("the tip {tip:?} is held under a body that is not its own"),
            ));
        }
        if self.store.total_work() != minted.work
            || self.store.state().state_root() != minted.after.state_root()
            || self.store.height() != Some(minted.block.header.height)
        {
            return Err(fail(
                "the ledger is the one the tip commits to",
                format!(
                    "the tip is honest block {at}, worth {} at height {}, and the store says \
                     {} at height {:?}",
                    minted.work,
                    minted.block.header.height,
                    self.store.total_work(),
                    self.store.height()
                ),
            ));
        }
        let path: BTreeSet<usize> = network.ancestry(at).into_iter().collect();
        for (index, other) in network.honest.iter().enumerate() {
            if self.store.is_active(&other.block.id()) != path.contains(&index) {
                return Err(fail(
                    "the active branch is the tip's ancestry",
                    format!(
                        "honest block {index} is {} by the store and {} by the tree",
                        if self.store.is_active(&other.block.id()) {
                            "active"
                        } else {
                            "not active"
                        },
                        if path.contains(&index) {
                            "on the tip's ancestry"
                        } else {
                            "off it"
                        }
                    ),
                ));
            }
        }

        // 3. No valid branch held in full is one the fork choice takes over
        // the one followed, save a tie kept aside at its last weighing.
        // Parents are minted before children, so one pass in that order
        // decides each.
        let mut whole = vec![false; network.honest.len()];
        for (index, other) in network.honest.iter().enumerate() {
            let id = other.block.id();
            let valid = self.store.contains(&id)
                && self
                    .weigh(&id)
                    .map_err(|said| fail("the store holds what it was handed", said))?
                    .1;
            whole[index] = valid
                && (self.store.is_active(&id) || other.parent.is_some_and(|parent| whole[parent]));
            if whole[index]
                && takes(&other.block.header, &minted.block.header)
                && !self.tied.contains(&id)
            {
                return Err(fail(
                    "no valid branch held in full is one the fork choice takes",
                    format!(
                        "honest block {index}, worth {} at height {}, is held with every block \
                         under it and every one valid, and the store follows honest block {at}, \
                         worth {} at height {} and difficulty {}",
                        other.work,
                        other.block.header.height,
                        minted.work,
                        minted.block.header.height,
                        minted.block.header.difficulty
                    ),
                ));
            }
        }

        // 4. What is kept off the branch, counted from the bodies.
        let mut side_blocks = 0usize;
        let mut side_bytes = 0usize;
        let mut all_bytes = 0usize;
        for id in self.known.keys() {
            if !self.store.contains(id) {
                continue;
            }
            let (size, _) = self
                .weigh(id)
                .map_err(|said| fail("the store holds what it was handed", said))?;
            let held = size + HELD_OVERHEAD;
            all_bytes += held;
            if !self.store.is_active(id) {
                side_blocks += 1;
                side_bytes += held;
            }
        }
        if side_blocks > MAX_SIDE_BLOCKS || side_bytes > MAX_SIDE_BYTES {
            return Err(fail(
                "the side store stays within its bounds",
                format!(
                    "{side_blocks} blocks and {side_bytes} bytes held off the branch, against \
                     {MAX_SIDE_BLOCKS} and {MAX_SIDE_BYTES}"
                ),
            ));
        }
        if all_bytes != self.store.held_bytes() {
            return Err(fail(
                "the side store stays within its bounds",
                format!(
                    "the store counts {} bytes held and its bodies come to {all_bytes}",
                    self.store.held_bytes()
                ),
            ));
        }
        if let Some(tally) = tally {
            if side_blocks == MAX_SIDE_BLOCKS || side_bytes > MAX_SIDE_BYTES - FAT_BYTES {
                tally.at_the_ceiling += 1;
            }
        }
        Ok(())
    }

    /// Property 5, and what each answer says it did.
    fn compare(
        &self,
        step: usize,
        offered: &Block,
        before: &Held,
        after: &Held,
        answer: &Result<Accepted, ChainError>,
    ) -> Result<(), Failure> {
        let fail = |property: &'static str, said: String| Failure {
            property,
            step,
            said,
        };
        let id = offered.id();
        for (held, valid) in &after.blocks {
            if let Some(was) = before.blocks.get(held) {
                if was != valid {
                    return Err(fail(
                        "a body held is never swapped for another",
                        format!("{held:?} was held valid={was} and is now held valid={valid}"),
                    ));
                }
            } else if *held != id {
                return Err(fail(
                    "a block is held only once it is handed over",
                    format!("{held:?} is newly held and the block handed over was {id:?}"),
                ));
            }
        }
        match answer {
            Err(refused) => {
                if after.tip != before.tip
                    || after.work != before.work
                    || after.state_root != before.state_root
                {
                    return Err(fail(
                        "a refusal changes nothing",
                        format!("refused as {refused:?}, and the tip or the ledger moved"),
                    ));
                }
                for (held, valid) in &before.blocks {
                    if *valid && !after.blocks.contains_key(held) {
                        return Err(fail(
                            "a refusal changes nothing",
                            format!("refused as {refused:?}, and the valid block {held:?} went"),
                        ));
                    }
                }
            }
            Ok(Accepted::Duplicate) => {
                if after.tip != before.tip || after.blocks.len() != before.blocks.len() {
                    return Err(fail(
                        "a duplicate changes nothing",
                        "a block answered as already held moved the tip or what is held".to_owned(),
                    ));
                }
            }
            Ok(Accepted::SideBranch) => {
                if after.tip != before.tip || after.state_root != before.state_root {
                    return Err(fail(
                        "a side block leaves the branch alone",
                        "a block filed aside moved the tip or the ledger".to_owned(),
                    ));
                }
            }
            Ok(Accepted::Extended | Accepted::Reorganised { .. }) => {
                if after.tip != Some(id) || after.work <= before.work {
                    return Err(fail(
                        "a switch lands on the block handed over",
                        format!(
                            "{answer:?}, with the tip at {:?} and the work gone from {} to {}",
                            after.tip, before.work, after.work
                        ),
                    ));
                }
                if let Ok(Accepted::Reorganised { removed, added }) = answer {
                    if added.last() != Some(&id)
                        || removed.iter().any(|gone| self.store.is_active(gone))
                        || added.iter().any(|came| !self.store.is_active(came))
                    {
                        return Err(fail(
                            "a switch lands on the block handed over",
                            format!("the switch reports {answer:?}, which is not what it did"),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Hands one block over and holds everything about what it did.
    fn offer(
        &mut self,
        step: usize,
        block: &Block,
        tally: &mut Option<&mut Tally>,
    ) -> Result<(), Failure> {
        let before = self.held().map_err(|said| Failure {
            property: "the store holds what it was handed",
            step,
            said,
        })?;
        let height_before = self.store.height();
        let followed_before = self.network.followed(&self.store).copied();
        let answer = self.store.add_block(block.clone(), NOW);
        let id = block.id();
        // Weighed by its header, so a twin offered under an honest identifier
        // weighs the honest block held under it.
        if matches!(answer, Ok(Accepted::SideBranch)) && self.network.honest_by_id.contains_key(&id)
        {
            if followed_before.is_some_and(|followed| ties(&block.header, &followed)) {
                self.tied.insert(id);
                if let Some(tally) = tally.as_deref_mut() {
                    tally.ties_kept += 1;
                }
            } else {
                self.tied.remove(&id);
            }
        }
        self.trace
            .push(format!("{answer:?} -> {:?}", self.store.tip()));
        let after = self.held().map_err(|said| Failure {
            property: "the store holds what it was handed",
            step,
            said,
        })?;
        self.compare(step, block, &before, &after, &answer)?;
        self.check(step, tally)?;
        if let Some(tally) = tally {
            *tally.answers.entry(kind_of(&answer)).or_default() += 1;
            if matches!(answer, Ok(Accepted::Reorganised { .. }))
                && self.store.height() < height_before
            {
                tally.went_down += 1;
            }
        }
        Ok(())
    }

    /// Hands over a flood, checking the bounds and the tip block by block,
    /// and everything once it has landed.
    #[allow(clippy::too_many_arguments)]
    fn flood(
        &mut self,
        step: usize,
        depth: u64,
        count: usize,
        shape: Shape,
        price: Price,
        salt: u64,
        tally: &mut Option<&mut Tally>,
    ) -> Result<(), Failure> {
        let fail = |property: &'static str, said: String| Failure {
            property,
            step,
            said,
        };
        let network = self.network;
        let Some(height) = self.store.height() else {
            if let Some(tally) = tally {
                *tally
                    .floods
                    .entry("nothing to hang off".to_owned())
                    .or_default() += 1;
            }
            return Ok(());
        };
        let mut at = height.saturating_sub(depth);
        if price == Price::Paid {
            // No higher than where the store's branch leaves the heaviest
            // honest one, which is the highest height the two share.
            let heaviest: BTreeSet<usize> =
                network.ancestry(network.heaviest).into_iter().collect();
            let shared = (0..=height)
                .rev()
                .find(|below| {
                    self.store
                        .id_at(*below)
                        .and_then(|id| network.honest_by_id.get(&id))
                        .is_some_and(|index| heaviest.contains(index))
                })
                .unwrap_or(0);
            at = at.min(shared);
        }
        let hung = self
            .store
            .id_at(at)
            .and_then(|id| network.honest_by_id.get(&id))
            .map(|index| &network.honest[*index].block)
            .ok_or_else(|| {
                fail(
                    "the active branch is the tip's ancestry",
                    format!("the store names no honest block {depth} below its tip"),
                )
            })?;
        let tip = self.store.tip();
        let work = self.store.total_work();
        let state_root = self.store.state().state_root();
        let mut on_branch = 0usize;
        let mut branch_bytes = 0usize;
        for (id, sizes) in &self.known {
            if self.store.is_active(id) {
                on_branch += 1;
                branch_bytes += sizes[0].1 + HELD_OVERHEAD;
            }
        }
        let params = network.params;
        let mut previous = hung.header;
        for index in 0..count {
            let nonce = salt.wrapping_add(index as u64);
            let (parent, bytes) = match shape {
                Shape::Chain => (previous, 0),
                Shape::Siblings => (hung.header, 0),
                Shape::Fat => (hung.header, FAT_BYTES),
            };
            let block = match price {
                Price::Free => junk(parent.height + 1, parent.id(), nonce, bytes),
                Price::Paid => paid_junk(&params, &parent, nonce, bytes),
            };
            let id = block.id();
            if shape == Shape::Chain {
                previous = block.header;
            }
            let size = block.encode().len();
            self.known
                .entry(id)
                .or_default()
                .push((Source::Junk(self.junk.len()), size));
            self.junk.push(block.clone());
            let answer = self.store.add_block(block, NOW);
            self.trace
                .push(format!("{} -> {:?}", kind_of(&answer), self.store.tip()));
            if let Some(tally) = tally {
                *tally
                    .answers
                    .entry(format!("{} (junk)", kind_of(&answer)))
                    .or_default() += 1;
            }
            if matches!(
                answer,
                Ok(Accepted::Extended | Accepted::Reorganised { .. })
            ) || self.store.tip() != tip
                || self.store.total_work() != work
                || self.store.state().state_root() != state_root
            {
                return Err(fail(
                    "a refusal changes nothing",
                    format!(
                        "junk block {index} of the flood was answered {answer:?} and the tip or \
                         the ledger moved"
                    ),
                ));
            }
            let side_blocks = self.store.len().saturating_sub(on_branch);
            let side_bytes = self.store.held_bytes().saturating_sub(branch_bytes);
            if side_blocks > MAX_SIDE_BLOCKS || side_bytes > MAX_SIDE_BYTES {
                return Err(fail(
                    "the side store stays within its bounds",
                    format!(
                        "after junk block {index} of the flood: {side_blocks} blocks and \
                         {side_bytes} bytes held off the branch"
                    ),
                ));
            }
            // Counted here as well as after the flood, since the sweep stops
            // an eighth under the ceiling, so a store that reached it during
            // the flood is seldom at it once the flood has landed.
            if let Some(tally) = tally {
                if side_blocks == MAX_SIDE_BLOCKS || side_bytes > MAX_SIDE_BYTES - FAT_BYTES {
                    tally.at_the_ceiling += 1;
                }
            }
        }
        if let Some(tally) = tally {
            *tally
                .floods
                .entry(format!("{shape:?} {price:?}"))
                .or_default() += 1;
        }
        self.check(step, tally)
    }

    fn step(
        &mut self,
        step: usize,
        what: &Step,
        tally: &mut Option<&mut Tally>,
    ) -> Result<(), Failure> {
        match what {
            Step::Offer(index) => {
                let entry = &self.network.universe[*index];
                if let (Some(tally), Kind::Malformed(kind)) = (tally.as_deref_mut(), entry.kind) {
                    *tally.malformed.entry(kind).or_default() += 1;
                }
                let block = entry.block.clone();
                self.offer(step, &block, tally)
            }
            Step::Flood {
                depth,
                count,
                shape,
                price,
                salt,
            } => self.flood(step, *depth, *count, *shape, *price, *salt, tally),
        }
    }
}

/// Runs a case: the sequence, then the heaviest honest branch in order, and
/// then whether the store follows a branch that heavy.
fn run(
    network: &Network,
    steps: &[Step],
    mut tally: Option<&mut Tally>,
) -> Result<Vec<String>, Failure> {
    let mut run = Run::new(network);
    for (at, what) in steps.iter().enumerate() {
        run.step(at, what, &mut tally)?;
    }
    let tip_before_closing = run.store.tip();
    let closing = in_order(network);
    for (offset, what) in closing.iter().enumerate() {
        run.step(steps.len() + offset, what, &mut tally)?;
    }
    let heaviest = &network.honest[network.heaviest].block.header;
    if network
        .followed(&run.store)
        .is_none_or(|followed| takes(heaviest, followed))
    {
        return Err(Failure {
            property: "an honest heavier branch delivered in order is followed",
            step: steps.len() + closing.len(),
            said: format!(
                "the heaviest honest branch, worth {} and ending at honest block {}, was handed \
                 over in order from its first block, and the store follows {:?}, worth {}",
                network.max_work(),
                network.heaviest,
                run.store
                    .tip()
                    .and_then(|tip| network.honest_by_id.get(&tip)),
                run.store.total_work()
            ),
        });
    }
    if let Some(tally) = tally {
        if run.store.tip() != tip_before_closing {
            tally.closing_moved += 1;
            if steps.iter().any(|step| matches!(step, Step::Flood { .. })) {
                tally.closing_moved_after_a_flood += 1;
            }
        }
    }
    Ok(run.trace)
}

/// Whether `steps` still breaks `property`, or gives two different runs
/// when `property` is the replay.
fn still_fails(network: &Network, steps: &[Step], property: &'static str) -> bool {
    if property == REPLAY {
        return match (run(network, steps, None), run(network, steps, None)) {
            (Ok(first), Ok(second)) => first != second,
            _ => false,
        };
    }
    run(network, steps, None).is_err_and(|failure| failure.property == property)
}

const REPLAY: &str = "the same sequence replayed gives the same tip";

/// The shortest sequence this reaches that still breaks `property`: runs cut
/// out largest first, then each flood made as small as it can be.
fn cut_down(network: &Network, steps: &[Step], property: &'static str) -> Vec<Step> {
    let mut best = steps.to_vec();
    let mut span = best.len().max(1);
    while span > 0 {
        let mut at = 0;
        while at < best.len() {
            let end = (at + span).min(best.len());
            let mut shorter = best[..at].to_vec();
            shorter.extend_from_slice(&best[end..]);
            if still_fails(network, &shorter, property) {
                best = shorter;
            } else {
                at += span;
            }
        }
        span /= 2;
    }
    // Each flood down to the fewest blocks that still break it, by halving
    // the gap between a count that does and one that does not.
    for index in 0..best.len() {
        let Step::Flood { count, .. } = best[index] else {
            continue;
        };
        let with = |fewer: usize| {
            let mut smaller = best.clone();
            if let Step::Flood { count, .. } = &mut smaller[index] {
                *count = fewer;
            }
            smaller
        };
        let (mut holds, mut breaks) = (0usize, count);
        while breaks - holds > 1 {
            let middle = holds + (breaks - holds) / 2;
            if still_fails(network, &with(middle), property) {
                breaks = middle;
            } else {
                holds = middle;
            }
        }
        best = with(breaks);
    }
    best
}

/// Writes a cut-down failing sequence where the campaign keeps its failures,
/// and says where.
fn keep(network: &Network, steps: &[Step], failure: &Failure, seed: u64, case: usize) -> String {
    let mut record = String::new();
    let _ = writeln!(record, "campaign: {CAMPAIGN}");
    let _ = writeln!(record, "seed: {seed:#x}, case: {case}");
    let _ = writeln!(record, "property: {}", failure.property);
    let _ = writeln!(record, "at step: {}", failure.step);
    let _ = writeln!(record, "failed with: {}", failure.said);
    let _ = writeln!(
        record,
        "\nthe network: opening difficulty {}, {} honest blocks, the heaviest is {} worth {}",
        network.params.genesis_difficulty,
        network.honest.len(),
        network.heaviest,
        network.max_work()
    );
    for (index, entry) in network.universe.iter().enumerate() {
        let header = &entry.block.header;
        let _ = writeln!(
            record,
            "  universe {index}: {:?}, height {}, difficulty {}, work {}, dated {}, id {:?}, \
             parent {:?}",
            entry.kind,
            header.height,
            header.difficulty,
            header.total_work,
            header.timestamp,
            entry.block.id(),
            header.previous
        );
    }
    let _ = writeln!(record, "\nthe sequence, cut down to {} steps:", steps.len());
    for (index, step) in steps.iter().enumerate() {
        let _ = writeln!(record, "  {index}: {step:?}");
    }
    let _ = writeln!(
        record,
        "  then the heaviest honest branch in order: {:?}",
        network.ancestry(network.heaviest)
    );
    let folder: String = CAMPAIGN
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .join("target")
        .join("fuzz")
        .join(folder);
    let file = directory.join(format!("seed-{seed:x}-case-{case}-cut-down.txt"));
    let written = std::fs::create_dir_all(&directory)
        .and_then(|()| std::fs::write(&file, &record))
        .map_or_else(
            |error| format!("could not be written down: {error}"),
            |()| format!("kept in {}", file.display()),
        );
    eprintln!("{record}");
    written
}

const CAMPAIGN: &str = "chain: block store under sequences";

/// The store follows the heaviest branch it holds in full, keeps what it
/// holds aside within its bounds, refuses without moving, answers the same
/// way twice, and takes an honest heavier branch handed to it in order.
///
/// Nothing had handed the store a sequence it was not built to expect, so a
/// fork choice that went wrong only between two of the shapes the tests in
/// this crate build, or a sweep that let an honest branch go and never took
/// it back, passed.
#[test]
fn the_block_store_follows_the_heaviest_valid_branch_whatever_order_it_hears_it_in() {
    let campaign = Campaign::named(CAMPAIGN);
    let seed = campaign.seed();
    let mut tally = Tally::default();

    let ran = campaign.run(160, |case, rng| {
        // One case in thirty two, and the first two, carry a flood: it is
        // what reaches the side store's ceiling, and it costs a second or so.
        // The first is paid and the second free, so a short run holds both.
        let flood = match case {
            0 => Some(Price::Paid),
            1 => Some(Price::Free),
            _ => rng
                .chance(32)
                .then(|| if rng.bool() { Price::Paid } else { Price::Free }),
        };
        let salt = rng.edgy_u64();
        let network = network(rng, flood, salt);
        let steps = sequence(rng, &network, flood);

        let first = run(&network, &steps, Some(&mut tally));
        let failure = match first {
            Err(failure) => Some(failure),
            Ok(trace) => match run(&network, &steps, None) {
                Ok(again) if again == trace => None,
                Ok(again) => {
                    let step = trace
                        .iter()
                        .zip(&again)
                        .position(|(one, two)| one != two)
                        .unwrap_or(trace.len().min(again.len()));
                    Some(Failure {
                        property: REPLAY,
                        step,
                        said: format!(
                            "the first run answered {:?} and the second {:?}",
                            trace.get(step),
                            again.get(step)
                        ),
                    })
                }
                Err(failure) => Some(Failure {
                    property: REPLAY,
                    step: failure.step,
                    said: format!("the first run held and the second failed: {failure:?}"),
                }),
            },
        };
        if let Some(failure) = failure {
            let shortest = cut_down(&network, &steps, failure.property);
            let again = run(&network, &shortest, None)
                .err()
                .unwrap_or(failure.clone());
            let kept = keep(&network, &shortest, &again, seed, case);
            panic!(
                "case {case} of seed {seed:#x}: \"{}\" does not hold, at step {} of {} \
                 handed over, the closing branch included ({}); cut down to {} steps, {kept}",
                failure.property,
                failure.step,
                steps.len() + in_order(&network).len(),
                failure.said,
                shortest.len()
            );
        }
    });

    eprintln!("{CAMPAIGN}: {tally:?}");
    assert!(ran.cases >= 50, "the campaign ran {} cases", ran.cases);
    for answer in [
        "Extended",
        "Reorganised",
        "SideBranch",
        "Duplicate",
        "UnknownParent",
        "NotGenesis",
        "BrokenHeight",
        "NoWork",
        "InvalidBlock",
        "KnownBad",
    ] {
        assert!(
            tally.answers.get(answer).copied().unwrap_or(0) > 0,
            "the store never answered {answer}, so that path was not asked: {:?}",
            tally.answers
        );
    }
    assert!(
        tally.went_down > 0,
        "no switch left the node lower, so work and height never parted company"
    );
    assert!(
        !tally.floods.is_empty() && tally.at_the_ceiling > 0,
        "no flood reached the side store's ceiling, so its bounds were never pressed: {:?}",
        tally.floods
    );
    for price in ["Free", "Paid"] {
        assert!(
            tally.floods.keys().any(|flood| flood.ends_with(price)),
            "no {price} flood landed, so that price was never asked: {:?}",
            tally.floods
        );
    }
    assert!(
        tally.closing_moved > 0,
        "the closing delivery never moved the tip, so it asked nothing"
    );
    assert!(
        tally.ties_kept > 0,
        "no honest block came within half a block of the tip at its height, so the \
         tie that makes was never asked"
    );
}
